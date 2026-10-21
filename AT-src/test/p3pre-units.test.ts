/**
 * P3pre 单测（报错透传 + 熔断）——确定性、零 LLM。
 *
 * 探针测试（P3pre-1）固化 pi 错误路径结论：pi 不抛错——streamSimple catch 全部错误
 * → error 事件 + result() 得 stopReason="error" 消息；agent-loop 见 error 正常收轮；
 * Agent.prompt() 永不 reject（连 streamFn 同步 throw 都被 handleRunFailure 转成
 * message_end 错误消息）。这就是 429 "静默吞掉"的机制层解释，也是 AT1 检测点
 * （订阅层看 message_end）赖以成立的前提——pi 升级时此组测试先红。
 */
import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Agent, type StreamFn } from "@earendil-works/pi-agent-core";
import { classifyTransportError, transportFailureFromMessage } from "../src/channel.js";
import { runWorkerStep } from "../src/agent.js";
import { runTask } from "../src/scheduler.js";
import { renderTriggers, stepDoneEvent } from "../src/triggers.js";
import { loadConfig, parseSimpleYaml } from "../src/config.js";
import { openDb, type NodeRow } from "../src/db.js";
import { getNode, initTask } from "../src/graph.js";
import { loadTask } from "../src/task.js";
import { readRecentInterventions, renderRecentInterventions } from "../src/planner.js";
import { renderPlannerUserMessage } from "../src/planner-prompt.js";
import type { AppConfig } from "../src/config.js";
import type { RunPlannerOptions, RunPlannerResult } from "../src/planner.js";
import type { RunWorkerStepOptions, RunWorkerStepResult } from "../src/agent.js";
import type { TaskJson } from "../src/task.js";
import type { Database } from "better-sqlite3";

const dir = mkdtempSync(join(tmpdir(), "at1v4-p3pre-"));
afterAll(() => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 句柄延迟释放——tmp 目录留给 OS */
	}
});

/** 造一个独立 task（隔离 addStep 拒重/图状态），返回加载好的 task + db + 首 step。 */
function freshTask(prefix: string, seed: TaskJson["seed_steps"] = TASK.seed_steps) {
	const name = `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
	const tdir = join(dir, name);
	mkdirSync(tdir, { recursive: true });
	writeFileSync(
		join(tdir, "task.json"),
		JSON.stringify({ name, goal: TASK.goal, scope: TASK.scope, seed_steps: seed }),
	);
	const { task, dbPath } = loadTask(dir, name);
	const db = openDb(dbPath);
	const { stepIds } = initTask(db, task);
	const step = getNode(db, task.name, stepIds[0])!;
	return { name, tdir, task, db, step };
}

// ── 假流小件（探针 + blocked 路径共用）──

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

/** 正常完成流：一轮 text 收尾。 */
function okStream(text = "探测完成，全阴性观察已写回"): StreamFn {
	const msg = { role: "assistant", content: [{ type: "text", text }], ...FAKE_MSG_BASE, stopReason: "stop" };
	return fakeStream(msg, [
		{ type: "start", partial: msg },
		{ type: "done", reason: "stop", message: msg },
	]);
}

/** 传输层故障流（pi 真实形态：error 事件 + result() 错误消息，不抛错）。 */
function transportErrorStream(errorMessage: string): StreamFn {
	const msg = { role: "assistant", content: [{ type: "text", text: "" }], ...FAKE_MSG_BASE, stopReason: "error", errorMessage };
	return fakeStream(msg, [{ type: "error", reason: "error", error: msg }]);
}

/** abort 流（掐断形态：挂起到 signal 中断 → stopReason=aborted——不是故障）。 */
/* eslint-disable @typescript-eslint/no-explicit-any */
function abortedStream(): StreamFn {
	return ((_model: unknown, _ctx: unknown, opts: any) => {
		const msg = { role: "assistant", content: [{ type: "text", text: "" }], ...FAKE_MSG_BASE, stopReason: "aborted" };
		return {
			result: async () => msg,
			async *[Symbol.asyncIterator]() {
				yield { type: "start", partial: msg };
				// 挂起直到 abort（真实 pi-ai 同款：signal aborted → stopReason=aborted）
				await new Promise<void>((res) => {
					if (opts?.signal?.aborted) res();
					else opts?.signal?.addEventListener("abort", () => res(), { once: true });
				});
				yield { type: "error", reason: "aborted", error: msg };
			},
		};
	}) as unknown as StreamFn;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const FAKE_MODEL = {
	id: "fake-m",
	name: "fake",
	api: "openai-completions",
	provider: "fake",
	baseUrl: "http://127.0.0.1:9",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 8192,
	maxTokens: 1024,
} as any;
/* eslint-enable @typescript-eslint/no-explicit-any */

// ── P3pre-1 探针：pi 错误路径固化 ──

describe("P3pre-1 探针：pi 错误不抛错、经 message_end 事件可见", () => {
	it("路径 A（error 事件）：prompt() 正常 resolve，message_end 带 stopReason=error + errorMessage", async () => {
		const seen: any[] = [];
		const agent = new Agent({
			initialState: { systemPrompt: "p", tools: [], model: FAKE_MODEL, thinkingLevel: "low" },
			streamFn: transportErrorStream("[probe] API error 429: quota"),
			getApiKey: async () => "k",
		});
		agent.subscribe(async (ev) => {
			seen.push(ev);
		});
		await expect(agent.prompt("探一下")).resolves.toBeUndefined(); // 不 reject——静默吞掉的机制
		const err = seen.find((e) => e.type === "message_end" && e.message?.role === "assistant");
		expect(err?.message?.stopReason).toBe("error");
		expect(err?.message?.errorMessage).toContain("429");
	});

	it("路径 B（streamFn 同步 throw）：prompt() 同样不 reject，handleRunFailure 合成错误消息", async () => {
		const seen: any[] = [];
		const agent = new Agent({
			initialState: { systemPrompt: "p", tools: [], model: FAKE_MODEL, thinkingLevel: "low" },
			streamFn: (() => {
				throw new Error("[probe] boom ECONNRESET");
			}) as StreamFn,
			getApiKey: async () => "k",
		});
		agent.subscribe(async (ev) => {
			seen.push(ev);
		});
		await expect(agent.prompt("探一下")).resolves.toBeUndefined();
		const err = seen.find((e) => e.type === "message_end" && e.message?.role === "assistant");
		expect(err?.message?.stopReason).toBe("error");
		expect(err?.message?.errorMessage).toContain("[probe] boom");
	});
});

// ── P3pre-1 分类器 ──

describe("P3pre-1 传输层故障分类", () => {
	it("HTTP 形态：4xx/5xx 全部进 http + status（P3pre-6 ④ 包含 400 等）", () => {
		expect(classifyTransportError("API error 429: quota exceeded")).toMatchObject({ kind: "http", status: 429 });
		expect(classifyTransportError("502 Bad Gateway")).toMatchObject({ kind: "http", status: 502 });
		expect(classifyTransportError("HTTP 403 forbidden")).toMatchObject({ kind: "http", status: 403 });
		expect(classifyTransportError("Request failed: 500 internal")).toMatchObject({ kind: "http", status: 500 });
		expect(classifyTransportError("HTTP 400 Bad Request: thinking:disabled rejected")).toMatchObject({ kind: "http", status: 400 });
	});

	it("网络形态：错误码/措辞 → network", () => {
		expect(classifyTransportError("getaddrinfo ENOTFOUND api.example.com").kind).toBe("network");
		expect(classifyTransportError("socket hang up").kind).toBe("network");
		expect(classifyTransportError("fetch failed: ECONNRESET").kind).toBe("network");
		expect(classifyTransportError("ETIMEDOUT after 30000ms").kind).toBe("network");
	});

	it("不可分类 → unknown（照样上抛进 blocked 路，不静默）", () => {
		expect(classifyTransportError("Provider finish_reason: content_filter").kind).toBe("unknown");
		expect(classifyTransportError("").kind).toBe("unknown");
	});

	it("transportFailureFromMessage：error 停因提取；abort/非 assistant 不误报；空 message 回退 unknown 兜底（P3pre-6 ④）", () => {
		expect(transportFailureFromMessage({ role: "assistant", stopReason: "error", errorMessage: "429" })?.status).toBe(429);
		expect(transportFailureFromMessage({ role: "assistant", stopReason: "aborted", errorMessage: "429" })).toBeUndefined();
		expect(transportFailureFromMessage({ role: "user", stopReason: "error", errorMessage: "429" })).toBeUndefined();
		// P3pre-6 ④：空 message 回退 unknown 兜底，堵死"error 事件零正文 → 翻 done 零产出"
		expect(transportFailureFromMessage({ role: "assistant", stopReason: "error" })).toEqual({
			kind: "unknown",
			raw: "(empty)",
			label: "传输层故障[unknown]",
		});
		expect(transportFailureFromMessage({ role: "assistant", stopReason: "error", errorMessage: "" })).toEqual({
			kind: "unknown",
			raw: "(empty)",
			label: "传输层故障[unknown]",
		});
		expect(transportFailureFromMessage(undefined)).toBeUndefined();
	});
});

// ── P3pre-2 worker blocked 路径（真 runWorkerStep + 假流）──

const TASK = {
	name: "p3pre-w",
	goal: "确认至少一个越权读取",
	scope: { hosts: ["x.example.com"] },
	seed_steps: [{ summary: "探测首页鉴权面" }],
};

describe("P3pre-2 worker 透传 blocked", () => {
	it("假流 429 → step=blocked（非 done）+ activity is_error 账（tool=channel）+ result.transportError", async () => {
		const { task, db, step, tdir } = freshTask("p3pre-w");
		const result = await runWorkerStep({
			db,
			task,
			taskDir: tdir,
			step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: transportErrorStream("API error 429: Insufficient balance (code 1113)"),
		});

		expect(result.aborted).toBe(false);
		expect(result.transportError).toContain("429");
		const st = db.prepare("SELECT state FROM nodes WHERE id=?").get(step.id) as { state: string };
		expect(st.state).toBe("blocked"); // 不翻 done——429 事故的核心修正
		const act = db.prepare("SELECT * FROM activity WHERE tool='channel'").get() as { is_error: number; summary: string; detail: string };
		expect(act.is_error).toBe(1);
		expect(act.summary).toContain("blocked");
		expect(act.summary).toContain("429");
		expect(act.detail).toContain("1113");
		db.close();
	});

	it("abort 流（stopReason=aborted）→ 不误报 blocked（走 exhausted 既有路）", async () => {
		const { task, db, step, tdir } = freshTask("p3pre-a");
		const result = await runWorkerStep({
			db,
			task,
			taskDir: tdir,
			step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 300, // 短超时触发真 abort 机制（agent.abort() → signal → 流收尾）
			streamFn: abortedStream(),
		});
		expect(result.aborted).toBe(true);
		expect(result.transportError).toBeUndefined();
		const st = db.prepare("SELECT state FROM nodes WHERE id=?").get(step.id) as { state: string };
		expect(st.state).toBe("exhausted");
		const errRows = db.prepare("SELECT COUNT(*) AS n FROM activity WHERE is_error=1").get() as { n: number };
		expect(errRows.n).toBe(0);
		db.close();
	});
});

// ── P3pre-4 steer 两段式核销 ──

describe("P3pre-4 steer 核销", () => {
	it("会话收尾队列有残留 → is_error 核销账（未消费 N 条）", async () => {
		const { task, db, step, tdir } = freshTask("p3pre-s1");
		let agentRef: { steer(m: { role: "user"; content: string; timestamp: number }): void } | undefined;
		await runWorkerStep({
			db,
			task,
			taskDir: tdir,
			step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: okStream(),
			onAgent: (a) => {
				agentRef = a;
			},
			onEvent: (ev) => {
				// agent_end 后队列不会再被消费——模拟"送达账记了，插话实际没进会话"
				if (ev.type === "agent_end") agentRef?.steer({ role: "user", content: "迟到的插话", timestamp: Date.now() });
			},
		});
		const act = db.prepare("SELECT * FROM activity WHERE tool='steer' AND is_error=1").all() as Array<{ summary: string }>;
		expect(act).toHaveLength(1);
		expect(act[0].summary).toContain("未消费 1 条");
		db.close();
	});

	it("插话被会话正常消费 → 无核销账", async () => {
		const { task, db, step, tdir } = freshTask("p3pre-s2");
		await runWorkerStep({
			db,
			task,
			taskDir: tdir,
			step,
			secrets: { K: "x" },
			channel: { model: "fake-m", api: "openai", keyEnv: "K" },
			browser: false,
			timeoutMs: 5000,
			streamFn: okStream(),
			onAgent: (a) => a.steer({ role: "user", content: "提前的插话", timestamp: Date.now() }), // prompt 开跑即被消费
		});
		const act = db.prepare("SELECT * FROM activity WHERE tool='steer' AND is_error=1").all();
		expect(act).toHaveLength(0);
		db.close();
	});
});

// ── P3pre-2/3 调度层 mock 集成（零 LLM）──

const CFG: AppConfig = {
	channels: {
		worker: { model: "m", api: "openai", keyEnv: "K" },
		planner: { model: "m", api: "openai", keyEnv: "K" },
	},
	run: { maxRounds: 10, budgetMs: 600_000 },
};

const MOCK_USAGE = { turns: 1, input: 10, output: 5, cacheRead: 0, cacheWrite: 0 };
const TRANSPORT_ERR = "传输层故障[http 429]：API error 429: quota";

let uid = 0;
function makeTask(seed: TaskJson["seed_steps"]): { name: string; tdir: string } {
	const name = `p3pre-sched-${++uid}`;
	const tdir = join(dir, name);
	mkdirSync(join(tdir, "evidence"), { recursive: true });
	writeFileSync(
		join(tdir, "task.json"),
		JSON.stringify({ name, goal: "确认至少一个越权读取", scope: { hosts: ["x.example.com"] }, seed_steps: seed ?? [] }),
	);
	return { name, tdir };
}

/** 剧本 deps：workers[j]=第 j 次 worker 行为；plans[i]=第 i 次 planner 唤醒派的 steps。 */
function makeScriptDeps(
	db: Database,
	taskName: string,
	_taskDir: string,
	script: {
		plans?: Array<Array<{ summary: string; note?: string }>>;
		workers?: Array<{ summary?: string; blocked?: boolean }>;
		plannerThrows?: boolean[]; // 第 i 次唤醒是否 throw
		plannerTransportError?: boolean[]; // 第 i 次唤醒是否返回 transportError
	},
) {
	let planIdx = -1;
	let workerIdx = -1;
	const plannerSeen: Array<Array<unknown>> = [];
	const deps = {
		plannerSeen,
		runPlanner: async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			planIdx += 1;
			plannerSeen.push([...o.events]);
			if (script.plannerThrows?.[planIdx]) throw new Error("[mock] planner 抛错");
			if (script.plannerTransportError?.[planIdx]) return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "", transportError: TRANSPORT_ERR };
			const steps = script.plans?.[planIdx] ?? [];
			if (steps.length) {
				const { addStep } = await import("../src/graph.js");
				addStep(db, taskName, steps, "mock-planner");
			}
			return { acceptedCount: steps.length, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		},
		runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			workerIdx += 1;
			const s = script.workers?.[workerIdx];
			const { setStepState } = await import("../src/graph.js");
			const base = { stepId: o.step.id, finalText: s?.summary ?? "", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
			if (s?.blocked) {
				setStepState(db, taskName, o.step.id, "blocked"); // 真实 runWorkerStep 收尾语义
				return { ...base, transportError: TRANSPORT_ERR };
			}
			setStepState(db, taskName, o.step.id, "done");
			return base;
		},
	};
	return deps;
}

describe("P3pre mock 集成（零 LLM）", () => {
	it("3 连 blocked → 熔断 channel-down；planner 收到 outcome=blocked 事件并重派接续", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ blocked: true }, { blocked: true }, { blocked: true }],
			plans: [
				[{ summary: "重派变体一（blocked 接续）" }],
				[{ summary: "重派变体二（blocked 接续）" }],
			],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("channel-down");
		expect(result.workerSteps).toBe(3);
		expect(result.plannerWakeups).toBe(2); // 第 3 连 blocked 后熔断，不再唤醒
		// planner 确实收到 blocked 事件（v1.2 重派规则的输入）
		expect(deps.plannerSeen[0][0]).toMatchObject({ type: "step_done", outcome: "blocked" });
		// 三步全 blocked 落图
		const blocked = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='step' AND state='blocked'").get() as { n: number };
		expect(blocked.n).toBe(3);
		// 熔断 activity 账
		const act = db.prepare("SELECT * FROM activity WHERE tool='runTask' AND is_error=1").get() as { summary: string };
		expect(act.summary).toContain("熔断");
		db.close();
	});

	it("夹成功 step → 计数清零不熔断（planner 停派后 planner-zero 正常判停）", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ blocked: true }, { summary: "恢复后的成功 step" }, { blocked: true }, { summary: "又一个成功 step" }],
			plans: [
				[{ summary: "重派变体一" }],
				[{ summary: "重派变体二" }],
				[{ summary: "重派变体三" }],
				[],
			],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("planner-zero"); // 不是 channel-down——成功清零生效
		expect(result.workerSteps).toBe(4);
		db.close();
	});

	it("planner 先抛后成（重试同一批事件）→ 重试成功正常继续", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "正常完成" }],
			plans: [[]],
			plannerThrows: [true],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("planner-zero"); // 重试成功走到正常判停，非 planner-error
		expect(deps.plannerSeen).toHaveLength(2); // 首次 + 重试
		// 重试收到同一批事件（未被误清）
		expect(deps.plannerSeen[0].length).toBeGreaterThan(0);
		expect(deps.plannerSeen[1]).toEqual(deps.plannerSeen[0]);
		db.close();
	});

	it("planner 传输层故障两连 → planner-error 终止 + 事件未消费（续跑可恢复）", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "正常完成" }],
			plannerTransportError: [true, true],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("planner-error");
		expect(deps.plannerSeen).toHaveLength(2);
		// 两连失败拿到同一批事件——事件数组只在成功后清（D3）
		expect(deps.plannerSeen[0].length).toBeGreaterThan(0);
		expect(deps.plannerSeen[1]).toEqual(deps.plannerSeen[0]);
		// 调度层留 is_error 账
		const act = db.prepare("SELECT * FROM activity WHERE tool='runPlanner' AND is_error=1").all() as Array<{ summary: string }>;
		expect(act.length).toBeGreaterThanOrEqual(2); // 重试账 + 终止账
		expect(act.some((a) => a.summary.includes("重试仍失败"))).toBe(true);
		db.close();
	});
});

// ── P3pre-5 hint 措辞 + config ──

describe("P3pre-5 hint 建议级措辞 + config.circuitBreaker", () => {
	it("hint 渲染含建议级取舍句；blocked 事件照常渲染", () => {
		const text = renderTriggers([{ type: "hint", text: "重点看 /admin" }]);
		expect(text).toContain("操作员插入一条指示");
		expect(text).toContain("建议级");
		expect(text).toContain("采纳/部分采纳/忽略");
		expect(text).toContain("note 里说明取舍");
		const bd = renderTriggers([stepDoneEvent({ id: 7, payload: JSON.stringify({ summary: "某方向" }) } as NodeRow, "blocked", [], [], "")]);
		expect(bd).toContain("[blocked]");
	});

	it("circuitBreaker：默认 3；config.yaml 可覆写", () => {
		const raw = parseSimpleYaml("run: { maxRounds: 5, budgetMs: 1000, circuitBreaker: 7 }");
		expect(raw.run.circuitBreaker).toBe(7);
		const yml = join(dir, "cfg.yaml");
		writeFileSync(yml, "channels: {}\nrun:\n  maxRounds: 5\n  budgetMs: 1000\n  circuitBreaker: 7\n");
		expect(loadConfig(yml).run.circuitBreaker).toBe(7);
	});
});

// ── P3pre-6 复审补充施工（① loop catch + ② 渲染窗口+splice + ④ 两行修）──

describe("P3pre-6 ② 操作员干预史渲染窗口与 splice 卫生修", () => {
	it("空目录：renderRecentInterventions 返回 undefined（不渲染干预史节）", () => {
		const emptyDir = join(dir, `empty-${Date.now()}`);
		mkdirSync(emptyDir, { recursive: true });
		expect(renderRecentInterventions(emptyDir)).toBeUndefined();
	});

	it("hints + steer 混合窗口：各取尾部 ≤5 条，截断 ≤200 字，宽容解析，时间正序", () => {
		const tdir = join(dir, `interv-${Date.now()}`);
		const cdir = join(tdir, "control");
		mkdirSync(cdir, { recursive: true });

		// 写入 7 条 hints（超出 5 条，只取最后 5 条），含坏行
		const hints = [
			JSON.stringify({ ts: "2026-10-20T10:00:00.000Z", text: "hint-1 (oldest)" }),
			JSON.stringify({ ts: "2026-10-20T10:01:00.000Z", text: "hint-2 (old)" }),
			JSON.stringify({ ts: "2026-10-20T10:03:00.000Z", text: "hint-3" }),
			"raw text hint without json (tolerant)",
			JSON.stringify({ ts: "2026-10-20T10:05:00.000Z", text: "hint-5: " + "x".repeat(300) }),
			JSON.stringify({ ts: "2026-10-20T10:07:00.000Z", text: "hint-6" }),
			JSON.stringify({ ts: "2026-10-20T10:09:00.000Z", text: "hint-7 (newest)" }),
		];
		writeFileSync(join(cdir, "hints.jsonl"), hints.join("\n") + "\n");

		// 写入 steer，含 stepId
		const steers = [
			JSON.stringify({ ts: "2026-10-20T10:04:00.000Z", text: "steer-1 for s1", stepId: 1 }),
			JSON.stringify({ ts: "2026-10-20T10:08:00.000Z", text: "steer-2 for s2", stepId: 2 }),
		];
		writeFileSync(join(cdir, "steer.jsonl"), steers.join("\n") + "\n");

		const entries = readRecentInterventions(tdir);
		// hints 尾部 5 条 + steer 2 条 = 7 条
		expect(entries).toHaveLength(7);
		// hint-1 和 hint-2 滑出窗口
		const fullText = entries.map((e) => e.formatted).join("\n");
		expect(fullText).not.toContain("hint-1");
		expect(fullText).not.toContain("hint-2");
		expect(fullText).toContain("hint-7");
		expect(fullText).toContain("steer → step #1");
		expect(fullText).toContain("steer → step #2");
		expect(fullText).toContain("raw text hint without json");

		// 截断检查：hint-5 超过 200 字被截断
		const h5 = entries.find((e) => e.formatted.includes("hint-5"));
		expect(h5?.formatted.length).toBeLessThanOrEqual(250);

		// 渲染块格式
		const rendered = renderRecentInterventions(tdir);
		expect(rendered).toBeDefined();
		expect(rendered).toContain("【操作员干预史（最近）】");
		expect(rendered).toContain("hint=调度层建议，steer=已插进 worker 会话的纠偏；结合当前态势判断是否已消化，旧项已处理可忽略。");

		// renderPlannerUserMessage 渲染插槽
		const msg = renderPlannerUserMessage({
			triggers: "【变动】无",
			overviewJson: "{}",
			todosText: "",
			goalText: "测试目标",
			stalled: false,
			interventionsText: rendered,
		});
		expect(msg).toContain("【操作员干预史（最近）】");
		expect(msg).toContain("steer → step #1");
	});

	it("splice 卫生修：planner 调用期间 watcher 新增事件不被清空，留给下一轮", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));

		let plannerRound = 0;
		const plannerReceivedEvents: Array<any[]> = [];
		const deps = {
			runPlanner: async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
				plannerRound += 1;
				plannerReceivedEvents.push([...o.events]);
				if (plannerRound === 1) {
					// 调度层下轮唤醒应该能看到
					const { addStep } = await import("../src/graph.js");
					addStep(db, name, [{ summary: "第二步" }], "mock-planner");
					return { acceptedCount: 1, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
				}
				return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
			},
			runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
				const { setStepState } = await import("../src/graph.js");
				setStepState(db, name, o.step.id, "done");
				return { stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
			},
		};

		const result = await runTask({
			tasksRoot: dir,
			taskName: name,
			config: CFG,
			secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.workerSteps).toBeGreaterThanOrEqual(1);
		db.close();
	});
});

describe("P3pre-6 ① worker 循环异常兜底（结构性缺口）与熔断安全网", () => {
	it("worker throw（构造/执行异常）→ step 落 blocked + activity 记 1 条 is_error 且 summary 带「构造/执行异常」+ planner 收到 outcome=blocked", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));

		let plannerWoke = 0;
		let workerCallCount = 0;
		const plannerReceivedEvents: Array<any[]> = [];
		const deps = {
			runPlanner: async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
				plannerWoke += 1;
				plannerReceivedEvents.push([...o.events]);
				if (plannerWoke === 1) {
					// 第一次唤醒由 step_done(blocked) 触发，派一个修复 step
					const { addStep } = await import("../src/graph.js");
					addStep(db, name, [{ summary: "重派修复 step" }], "mock-planner");
					return { acceptedCount: 1, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
				}
				return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
			},
			runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
				workerCallCount += 1;
				if (workerCallCount === 1) {
					// 模拟通道构造异常 / payload 坏 / BrowserPool 挂死
					throw new Error("Missing API key in keyEnv: AT1_BAD_KEY");
				}
				const { setStepState } = await import("../src/graph.js");
				setStepState(db, name, o.step.id, "done");
				return { stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
			},
		};

		const result = await runTask({
			tasksRoot: dir,
			taskName: name,
			config: CFG,
			secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});

		// 检查首个 step 状态为 blocked（而非残留 running）
		const s1 = db.prepare("SELECT state FROM nodes WHERE kind='step' ORDER BY id ASC LIMIT 1").get() as { state: string };
		expect(s1.state).toBe("blocked");

		// 检查重派的修复 step 正常完成
		const s2 = db.prepare("SELECT state FROM nodes WHERE kind='step' ORDER BY id DESC LIMIT 1").get() as { state: string };
		expect(s2.state).toBe("done");
		expect(result.workerSteps).toBe(2);

		// 检查 activity 账目
		const act = db.prepare("SELECT * FROM activity WHERE tool='runWorkerStep' AND is_error=1").get() as { summary: string; detail: string };
		expect(act).toBeDefined();
		expect(act.summary).toContain("构造/执行异常");
		expect(act.summary).toContain("AT1_BAD_KEY");
		expect(act.detail).toContain("Missing API key");

		// planner 收到 blocked outcome 事件
		expect(plannerReceivedEvents[0].some((e) => e.type === "step_done" && (e as any).outcome === "blocked")).toBe(true);

		db.close();
	});

	it("worker 连续 3 次 throw → 触发熔断 channel-down 终止，且三步全落 blocked", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));

		let planCount = 0;
		const deps = {
			runPlanner: async (): Promise<RunPlannerResult> => {
				planCount += 1;
				const { addStep } = await import("../src/graph.js");
				addStep(db, name, [{ summary: `重派变体 ${planCount}` }], "mock-planner");
				return { acceptedCount: 1, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
			},
			runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
				throw new Error(`Worker throw on step #${o.step.id}: simulated crash`);
			},
		};

		const result = await runTask({
			tasksRoot: dir,
			taskName: name,
			config: CFG,
			secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});

		expect(result.reason).toBe("channel-down");
		expect(result.workerSteps).toBe(3);

		// 3 个 step 全为 blocked
		const blockedCount = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='step' AND state='blocked'").get() as { n: number };
		expect(blockedCount.n).toBe(3);

		// 熔断 activity 账
		const act = db.prepare("SELECT * FROM activity WHERE tool='runTask' AND is_error=1").get() as { summary: string };
		expect(act.summary).toContain("熔断终止");
		expect(act.summary).toContain("simulated crash");

		db.close();
	});
});
