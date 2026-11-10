/**
 * 卡C/T 假流验收（11-9 实机 fix §5.3 判定表 + §5.5 交付门 + §8 验收清单）——零 LLM。
 *
 * decideOutcome 纯判定逐行覆盖 + submit 交付回执（正常/去重/拒收/挂错 step）+
 * 真 runWorkerStep 假流（空结束/length/provider-aborted/部分交付后异常/本地取消/入口预 abort）。
 */
import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { decideOutcome, type OutcomeInput } from "../src/worker-outcome.js";
import { runWorkerStep, type RunWorkerStepResult } from "../src/agent.js";
import { createSubmitFactTool } from "../src/tools/submit.js";
import { loadTask } from "../src/task.js";
import { openDb, type NodeRow } from "../src/db.js";
import { getNode, initTask, submitFact, addStep } from "../src/graph.js";
import type { TaskJson } from "../src/task.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-outcome-"));
afterAll(() => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 句柄延迟释放——tmp 目录留给 OS */
	}
});

// ── §5.3 唯一判定表（纯函数逐行）──

function v(input: OutcomeInput): { outcome: string; reason: string } {
	const r = decideOutcome(input);
	return { outcome: r.outcome, reason: r.reason };
}

const base: OutcomeInput = {
	hasFinalAssistant: true,
	finalStopReason: "stop",
	deliveryCount: 0,
};

describe("卡C：唯一收尾判定表（§5.3 按顺序匹配）", () => {
	it("1 本地取消生效 → exhausted / step-timeout｜operator-stop；provider-aborted 不能覆盖", () => {
		expect(v({ ...base, localCancel: "step-timeout", finalStopReason: "aborted" })).toEqual({
			outcome: "exhausted",
			reason: "step-timeout",
		});
		expect(v({ ...base, localCancel: "operator-stop" })).toEqual({ outcome: "exhausted", reason: "operator-stop" });
		// 本地取消即使无交付也 exhausted（不降级 no-delivery）
		expect(v({ ...base, localCancel: "operator-stop", hasFinalAssistant: false })).toEqual({
			outcome: "exhausted",
			reason: "operator-stop",
		});
	});

	it("2 通道 error / worker 抛错 → blocked / channel-error｜worker-error（不被 no-delivery 覆盖）", () => {
		expect(v({ ...base, channelError: true })).toEqual({ outcome: "blocked", reason: "channel-error" });
		expect(v({ ...base, workerError: "BrowserPool 挂" })).toEqual({ outcome: "blocked", reason: "worker-error" });
		// 已有部分交付后 error：异常状态不变，不因 fact 改判 done
		expect(v({ ...base, channelError: true, deliveryCount: 2 })).toEqual({ outcome: "blocked", reason: "channel-error" });
	});

	it("3 无本地取消 + 最终 stopReason=aborted → incomplete / provider-aborted", () => {
		expect(v({ ...base, finalStopReason: "aborted" })).toEqual({ outcome: "incomplete", reason: "provider-aborted" });
	});

	it("4 最终 stopReason=length → incomplete / output-length（历史 length 后正常继续成功允许 done）", () => {
		expect(v({ ...base, finalStopReason: "length" })).toEqual({ outcome: "incomplete", reason: "output-length" });
		// 局部长度截断后 pi 正常继续并正常结束：只看最终消息，不因历史 length 永久判失败
		expect(v({ ...base, deliveryCount: 1 })).toEqual({ outcome: "done", reason: "delivered" });
	});

	it("5 无最终 assistant 消息 / stopReason 缺失或非正常 stop → incomplete / missing-final-message｜unexpected-stop", () => {
		expect(v({ ...base, hasFinalAssistant: false })).toEqual({ outcome: "incomplete", reason: "missing-final-message" });
		expect(v({ ...base, finalStopReason: undefined })).toEqual({ outcome: "incomplete", reason: "unexpected-stop" });
		expect(v({ ...base, finalStopReason: "content_filter" })).toEqual({ outcome: "incomplete", reason: "unexpected-stop" });
	});

	it("6 正常 stop 但无成功提交回执 → incomplete / no-delivery（有动作无交付不 done）", () => {
		expect(v(base)).toEqual({ outcome: "incomplete", reason: "no-delivery" });
	});

	it("7 正常 stop + ≥1 条合法交付 → done / delivered（dedup 返回也算交付）", () => {
		expect(v({ ...base, deliveryCount: 1 })).toEqual({ outcome: "done", reason: "delivered" });
		expect(v({ ...base, deliveryCount: 3 })).toEqual({ outcome: "done", reason: "delivered" });
	});
});

// ── submit 交付回执（§5.5：真实 submit 成功为准，含 dedup；挂错 step/拒收不算）──

function freshTask(prefix: string): { name: string; tdir: string; step: NodeRow } {
	const name = `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
	const tdir = join(dir, name);
	mkdirSync(tdir, { recursive: true });
	writeFileSync(
		join(tdir, "task.json"),
		JSON.stringify({
			name,
			goal: "确认至少一个越权读取",
			scope: { hosts: ["x.example.com"] },
			seed_steps: [{ summary: "探测首页鉴权面的种子方向" }],
		}),
	);
	const { task, dbPath } = loadTask(dir, name);
	const db = openDb(dbPath);
	const { stepIds } = initTask(db, task);
	return { name, tdir, step: getNode(db, name, stepIds[0])! };
}

describe("卡C：submit 交付回执（onDelivered 只记真实成功且挂对本 step）", () => {
	it("正常提交 → 交付 {fact, id, dedup:false}；去重提交 → {fact, 旧id, dedup:true}", () => {
		const t = freshTask("dlv");
		const db = openDb(join(t.tdir, "graph.db"));
		writeFileSync(join(t.tdir, "ev.txt"), "curl → 200");
		const got: Array<{ kind: string; id: number; dedup: boolean }> = [];
		const tool = createSubmitFactTool({
			db,
			taskId: t.name,
			taskDir: t.tdir,
			currentStepId: t.step.id,
			onDelivered: (r) => got.push(r),
		});
		tool.execute("t1", { step_id: t.step.id, summary: "首页无鉴权墙可直接访问", evidence: "ev.txt", confidence: "observed" });
		tool.execute("t2", { step_id: t.step.id, summary: "首页无鉴权墙可直接访问", evidence: "ev.txt", confidence: "observed" });
		expect(got).toHaveLength(2);
		expect(got[0]).toMatchObject({ kind: "fact", dedup: false });
		expect(got[1]).toMatchObject({ kind: "fact", dedup: true, id: got[0].id }); // dedup 返回旧 ID 也算交付
		db.close();
	});

	it("挂错 step → 不记交付（不能靠把提交挂错 step 满足交付门）", () => {
		const t = freshTask("dlv-wrong");
		const db = openDb(join(t.tdir, "graph.db"));
		writeFileSync(join(t.tdir, "ev.txt"), "curl → 200");
		const got: unknown[] = [];
		const tool = createSubmitFactTool({
			db,
			taskId: t.name,
			taskDir: t.tdir,
			currentStepId: t.step.id,
			onDelivered: (r) => got.push(r),
		});
		// 同 task 内另一条 step：提交真实成功入库，但挂错 step 不计入本 step 交付
		const wrong = addStep(db, t.name, [{ summary: "另一条挂错目标的 step" }]).accepted[0]!;
		tool.execute("t1", { step_id: wrong.id, summary: "挂错 step 的提交尝试记录", evidence: "ev.txt", confidence: "observed" });
		expect(got).toHaveLength(0);
		db.close();
	});

	it("拒收/抛错（证据不存在）→ 不记交付", async () => {
		const t = freshTask("dlv-rej");
		const db = openDb(join(t.tdir, "graph.db"));
		const got: unknown[] = [];
		const tool = createSubmitFactTool({
			db,
			taskId: t.name,
			taskDir: t.tdir,
			currentStepId: t.step.id,
			onDelivered: (r) => got.push(r),
		});
		await expect(
			tool.execute("t1", { step_id: t.step.id, summary: "证据缺失的提交会被打回", evidence: "nope.txt", confidence: "observed" }),
		).rejects.toThrow(/证据文件不存在/);
		expect(got).toHaveLength(0);
		db.close();
	});
});

// ── 真 runWorkerStep 假流（卡C/T 联动）──

/* eslint-disable @typescript-eslint/no-explicit-any */
const FAKE_MSG_BASE = {
	api: "openai-completions",
	provider: "fake",
	model: "fake-m",
	usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
	timestamp: Date.now(),
};

function fakeStream(finalMessage: any, events: any[]): StreamFn {
	return ((_model: unknown, _ctx: unknown, _opts: unknown) => ({
		result: async () => finalMessage,
		async *[Symbol.asyncIterator]() {
			for (const e of events) yield e;
		},
	})) as unknown as StreamFn;
}

function msg(text: string, stopReason: string, errorMessage?: string) {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		...FAKE_MSG_BASE,
		stopReason,
		...(errorMessage ? { errorMessage } : {}),
	};
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/** 跑一个真 worker step（无交付/按剧本预置交付），返回结果。 */
async function runScenario(name: string, streamFn: StreamFn, o?: { preAbort?: boolean; timeoutMs?: number; deliverFact?: boolean }) {
	const t = freshTask(name);
	const db = openDb(join(t.tdir, "graph.db"));
	if (o?.deliverFact) {
		writeFileSync(join(t.tdir, "ev.txt"), "curl → 200");
		submitFact(db, {
			taskId: t.name,
			taskDir: t.tdir,
			stepId: t.step.id,
			payload: { summary: "交付前的真实 fact", evidence: "ev.txt", confidence: "observed" },
		});
	}
	const abort = new AbortController();
	if (o?.preAbort) abort.abort();
	const result = await runWorkerStep({
		db,
		task: loadTask(dir, t.name).task,
		taskDir: t.tdir,
		step: t.step,
		secrets: { K: "x" },
		channel: { model: "fake-m", api: "openai", keyEnv: "K" },
		browser: false,
		timeoutMs: o?.timeoutMs ?? 5000,
		streamFn,
		abortSignal: abort.signal,
	});
	const state = (db.prepare("SELECT state FROM nodes WHERE id=?").get(t.step.id) as { state: string }).state;
	const payload = JSON.parse((db.prepare("SELECT payload FROM nodes WHERE id=?").get(t.step.id) as { payload: string }).payload) as {
		last_execution?: RunWorkerStepResult extends never ? never : { outcome: string; reason: string; delivery_refs: unknown[] };
	};
	db.close();
	return { result, state, lastExecution: payload.last_execution };
}

describe("卡C/T：真 runWorkerStep 假流收尾", () => {
	it("空结束（最终文本空、正常 stop、无交付）→ incomplete/no-delivery；非 done", async () => {
		const { result, state, lastExecution } = await runScenario("empty-end", fakeStream(msg("", "stop"), [{ type: "done", reason: "stop", message: msg("", "stop") }]));
		expect(result.outcome).toBe("incomplete");
		expect(result.reason).toBe("no-delivery");
		expect(result.finalText).toBe(""); // finalText=最后消息文本（空），不回填旧文本
		expect(state).toBe("incomplete");
		expect(lastExecution?.reason).toBe("no-delivery");
	});

	it("最终 stopReason=length → incomplete/output-length；部分交付后异常保留产出但不改判 done", async () => {
		const r1 = await runScenario("len-end", fakeStream(msg("写到一半被截断", "length"), [{ type: "done", reason: "length", message: msg("写到一半被截断", "length") }]));
		expect(r1.result.outcome).toBe("incomplete");
		expect(r1.result.reason).toBe("output-length");
		expect(r1.state).toBe("incomplete");

		// 已有 fact 后传输层异常：产出保留，状态 blocked（channel-error）
		const r2 = await runScenario("deliver-then-err", fakeStream(msg("", "error", "API error 502"), [{ type: "error", reason: "error", error: msg("", "error", "API error 502") }]), {
			deliverFact: true,
		});
		expect(r2.result.outcome).toBe("blocked");
		expect(r2.result.reason).toBe("channel-error");
		expect(r2.state).toBe("blocked");
	});

	it("无本地信号的上游 aborted → incomplete/provider-aborted（非 exhausted 非 done）", async () => {
		const { result, state } = await runScenario("upstream-abort", fakeStream(msg("", "aborted"), [{ type: "done", reason: "aborted", message: msg("", "aborted") }]));
		expect(result.outcome).toBe("incomplete");
		expect(result.reason).toBe("provider-aborted");
		expect(result.aborted).toBe(false); // 兼容字段：本地未取消
		expect(state).toBe("incomplete");
	});

	it("本地超时 → exhausted/step-timeout（本地取消原因先于上游 aborted，不误归 provider-aborted）", async () => {
		const t = freshTask("local-timeout");
		const db = openDb(join(t.tdir, "graph.db"));
		const hangStream: StreamFn = ((_m: unknown, _c: unknown, opts: any) => ({
			result: async () => msg("", "aborted"),
			async *[Symbol.asyncIterator]() {
				yield { type: "start", partial: msg("", "aborted") };
				await new Promise<void>((res) => {
					if (opts?.signal?.aborted) res();
					else opts?.signal?.addEventListener("abort", () => res(), { once: true });
				});
				yield { type: "done", reason: "aborted", message: msg("", "aborted") };
			},
		})) as unknown as StreamFn;
		const result = await runWorkerStep({
			db,
			task: loadTask(dir, t.name).task,
			taskDir: t.tdir,
			step: t.step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 200, // 内部 stepTimeout 先触发
			streamFn: hangStream,
		});
		expect(result.outcome).toBe("exhausted");
		expect(result.reason).toBe("step-timeout");
		const state = (db.prepare("SELECT state FROM nodes WHERE id=?").get(t.step.id) as { state: string }).state;
		expect(state).toBe("exhausted");
		db.close();
	});

	it("入口 signal 已 aborted → 不发模型请求，exhausted/operator-stop，无 worker 会话产出", async () => {
		const { result, state } = await runScenario("pre-abort", fakeStream(msg("不该被请求到", "stop"), []), { preAbort: true });
		expect(result.outcome).toBe("exhausted");
		expect(result.reason).toBe("operator-stop");
		expect(result.finalText).toBe("");
		expect(result.timing.worker_elapsed_ms).toBeLessThan(5000); // 立即返回，未挂起
		expect(state).toBe("exhausted");
	});

	it("外部 operator-stop → exhausted/operator-stop（原因可区分）", async () => {
		const t = freshTask("op-stop");
		const db = openDb(join(t.tdir, "graph.db"));
		const abort = new AbortController();
		const hangStream: StreamFn = ((_m: unknown, _c: unknown, opts: any) => ({
			result: async () => msg("", "aborted"),
			async *[Symbol.asyncIterator]() {
				yield { type: "start", partial: msg("", "aborted") };
				await new Promise<void>((res) => {
					if (opts?.signal?.aborted) res();
					else opts?.signal?.addEventListener("abort", () => res(), { once: true });
				});
			},
		})) as unknown as StreamFn;
		setTimeout(() => abort.abort(), 150);
		const result = await runWorkerStep({
			db,
			task: loadTask(dir, t.name).task,
			taskDir: t.tdir,
			step: t.step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 30_000,
			streamFn: hangStream,
			abortSignal: abort.signal,
		});
		expect(result.outcome).toBe("exhausted");
		expect(result.reason).toBe("operator-stop");
		db.close();
	});

	it("正常提交流（submit 工具在会话内真实执行）→ done/delivered + 计时三段可分辨", async () => {
		const t = freshTask("full-ok");
		const db = openDb(join(t.tdir, "graph.db"));
		writeFileSync(join(t.tdir, "ev.txt"), "curl → 200 越权");
		// 两轮假流：第一轮 assistant 发 submit_fact 工具调用（真实执行+guard 放行），第二轮正常收尾
		const toolCallMsg = {
			role: "assistant",
			content: [
				{ type: "toolCall", id: "tc-ok1", name: "submit_fact", arguments: { step_id: t.step.id, summary: "正常流真实交付的 fact", evidence: "ev.txt", confidence: "observed" } },
			],
			...FAKE_MSG_BASE,
			stopReason: "toolUse",
		};
		const finalMsg = msg("完成", "stop");
		let call = 0;
		const twoTurnStream: StreamFn = (() => {
			call += 1;
			const m = call === 1 ? toolCallMsg : finalMsg;
			return {
				result: async () => m,
				async *[Symbol.asyncIterator]() {
					yield { type: "done", reason: call === 1 ? "toolUse" : "stop", message: m };
				},
			};
		}) as unknown as StreamFn;
		const result = await runWorkerStep({
			db,
			task: loadTask(dir, t.name).task,
			taskDir: t.tdir,
			step: t.step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: twoTurnStream,
		});
		expect(result.outcome).toBe("done");
		expect(result.reason).toBe("delivered");
		expect(result.deliveries).toEqual([{ kind: "fact", id: expect.any(Number), dedup: false }]);
		expect(result.newFactIds).toEqual([result.deliveries[0]!.id]); // 新增语义不混入 dedup
		expect(result.stopReason).toBe("stop");
		const state = (db.prepare("SELECT state FROM nodes WHERE id=?").get(t.step.id) as { state: string }).state;
		expect(state).toBe("done");
		// last_execution 持久化可见
		const payload = JSON.parse((db.prepare("SELECT payload FROM nodes WHERE id=?").get(t.step.id) as { payload: string }).payload) as {
			last_execution?: { outcome: string; reason: string; delivery_refs: Array<{ id: number }> };
		};
		expect(payload.last_execution?.outcome).toBe("done");
		expect(payload.last_execution?.delivery_refs).toHaveLength(1);
		// 计时三段齐备
		expect(result.timing.queue_wait_ms).toBeGreaterThanOrEqual(0);
		expect(result.timing.worker_elapsed_ms).toBeGreaterThanOrEqual(0);
		expect(result.timing.cleanup_elapsed_ms).toBeGreaterThanOrEqual(0);
		// 会话结果 activity detail JSON 完整可解析（先限长再序列化）
		const row = db.prepare("SELECT detail FROM activity WHERE kind='result' AND tool='runWorkerStep' ORDER BY id DESC").get() as { detail: string };
		const parsed = JSON.parse(row.detail) as { outcome: string; reason: string; final_text: string };
		expect(parsed.outcome).toBe("done");
		expect(parsed.reason).toBe("delivered");
		db.close();
	});
});

// ── 卡A：call/result 分开计数 + 拦截/工具错误不重复统计 + token 不重复累计 ──

function guardBlockStream(): StreamFn {
	let call = 0;
	const toolCallMsg = {
		role: "assistant",
		content: [{ type: "toolCall", id: "tc-rm1", name: "Bash", arguments: { command: "rm -rf /tmp/x" } }],
		...FAKE_MSG_BASE,
		stopReason: "toolUse",
	};
	const finalMsg = msg("收到平台管控，转向", "stop");
	return (() => {
		call += 1;
		const m = call === 1 ? toolCallMsg : finalMsg;
		return {
			result: async () => m,
			async *[Symbol.asyncIterator]() {
				yield { type: "done", reason: call === 1 ? "toolUse" : "stop", message: m };
			},
		};
	}) as unknown as StreamFn;
}

describe("卡A：审计口径（call/result 分开，拦截与工具错误分账，token 只在会话结果一行）", () => {
	it("guard 拦截一次 Bash → call×1 + blocked×1（平台拒绝）+ tool error×1（执行结果账）三类分账，调用次数=1", async () => {
		const t = freshTask("audit-block");
		const db = openDb(join(t.tdir, "graph.db"));
		await runWorkerStep({
			db,
			task: loadTask(dir, t.name).task,
			taskDir: t.tdir,
			step: t.step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: guardBlockStream(),
		});
		const cnt = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
		// 调用次数只数 kind=tool_use 且 summary=call —— 不按 tool 列 COUNT(*)（76=38+38 口径错不再犯）
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE kind='tool_use' AND summary='call'")).toBe(1);
		// 平台拒绝：kind=tool_use + blocked: 前缀
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE kind='tool_use' AND summary LIKE 'blocked:%'")).toBe(1);
		// 执行结果错误：kind=result + tool error（guard 拦截在 pi 侧产生 isError 工具结果）
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE kind='result' AND summary='tool error'")).toBe(1);
		// toolCallId 关联：call/blocked/tool error 同一 ID
		const ids = db
			.prepare("SELECT detail FROM activity WHERE kind IN ('tool_use','result') AND (summary='call' OR summary LIKE 'blocked:%' OR summary='tool error')")
			.all() as Array<{ detail: string }>;
		const parsed = ids.map((r) => JSON.parse(r.detail) as { toolCallId: string });
		expect(new Set(parsed.map((p) => p.toolCallId))).toEqual(new Set(["tc-rm1"]));
		db.close();
	});

	it("正常 submit 成功 → call×1 + tool success×1 + submit_fact 结果账；token 只落在会话结果行", async () => {
		const t = freshTask("audit-ok");
		const db = openDb(join(t.tdir, "graph.db"));
		writeFileSync(join(t.tdir, "ev.txt"), "curl → 200 越权");
		let call = 0;
		const toolCallMsg = {
			role: "assistant",
			content: [
				{
					type: "toolCall",
					id: "tc-ok9",
					name: "submit_fact",
					arguments: { step_id: t.step.id, summary: "审计口径验证的交付事实", evidence: "ev.txt", confidence: "observed" },
				},
			],
			...FAKE_MSG_BASE,
			stopReason: "toolUse",
		};
		const finalMsg = msg("完成", "stop");
		const twoTurn: StreamFn = (() => {
			call += 1;
			const m = call === 1 ? toolCallMsg : finalMsg;
			return {
				result: async () => m,
				async *[Symbol.asyncIterator]() {
					yield { type: "done", reason: call === 1 ? "toolUse" : "stop", message: m };
				},
			};
		}) as unknown as StreamFn;
		await runWorkerStep({
			db,
			task: loadTask(dir, t.name).task,
			taskDir: t.tdir,
			step: t.step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: twoTurn,
		});
		const cnt = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE kind='tool_use' AND summary='call'")).toBe(1);
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE kind='result' AND summary='tool success'")).toBe(1);
		// submit_fact 结果账 ×2：graph 层入图账 + 卡A 工具执行结果账（tool success），均不计入 call
		expect(cnt("SELECT COUNT(*) AS n FROM activity WHERE tool='submit_fact' AND kind='result'")).toBe(2);
		// token 四列只在会话结果行（kind=result tool=runWorkerStep），工具结果账不重复累计
		const tokRows = db
			.prepare("SELECT tool, input_tokens, output_tokens FROM activity WHERE input_tokens + output_tokens + cache_read + cache_write > 0")
			.all() as Array<{ tool: string }>;
		expect(tokRows.map((r) => r.tool)).toEqual(["runWorkerStep"]);
		db.close();
	});
});
