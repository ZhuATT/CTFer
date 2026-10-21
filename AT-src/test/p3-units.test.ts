/**
 * P3 单测（零 LLM）——admin CLI 核心（scope-add/reopen）+ currentGoal 多 goal +
 * list_facts q 过滤 + preflight 四项检查（streamFn/浏览器探测双注入）。
 */
import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import { currentGoal, initTask, submitFact } from "../src/graph.js";
import { openDb } from "../src/db.js";
import { loadTask, type TaskJson } from "../src/task.js";
import { openAssetsDb, resolveScopeHosts } from "../src/assets.js";
import { scopeAdd, reopenTask } from "../src/admin.js";
import { createPlannerTools } from "../src/planner.js";
import { runPreflight, renderPreflightReport, integrityCheck } from "../src/preflight.js";
import type { AppConfig } from "../src/config.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-p3units-"));
afterAll(() => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 句柄延迟释放——tmp 目录留给 OS */
	}
});

let uid = 0;

/** 造独立 task（可选 project——有则建 projects/<名>/assets.db 布局）。 */
function makeTask(opts: { project?: string; goal?: string; hosts?: string[] } = {}): {
	name: string;
	tdir: string;
	db: Database;
	assetsDb: Database | undefined;
	task: TaskJson;
} {
	const name = `p3u-${++uid}`;
	const tdir = join(dir, "tasks", name);
	mkdirSync(join(tdir, "evidence"), { recursive: true });
	const json = {
		name,
		...(opts.project ? { project: opts.project } : {}),
		goal: opts.goal ?? "确认目标站点至少一个越权读取点",
		scope: { hosts: opts.hosts ?? ["x.example.com"] },
		seed_steps: [{ summary: "种子 step：首探测方向" }],
	};
	writeFileSync(join(tdir, "task.json"), JSON.stringify(json));
	const { task, dbPath, assetsDbPath } = loadTask(join(dir, "tasks"), name);
	const db = openDb(dbPath);
	const assetsDb = assetsDbPath ? openAssetsDb(assetsDbPath) : undefined;
	return { name, tdir, db, assetsDb, task };
}

/** 带证据文件 + fact 的就绪图（goal + seed step + fact）。 */
function makeTaskWithFact(opts: Parameters<typeof makeTask>[0] & { summary?: string } = {}) {
	const t = makeTask(opts);
	const { stepIds } = initTask(t.db, t.task);
	writeFileSync(join(t.tdir, "ev.txt"), "curl → 200 越权");
	const r = submitFact(t.db, {
		taskId: t.name,
		taskDir: t.tdir,
		stepId: stepIds[0],
		payload: { summary: opts.summary ?? "首页接口 200 无鉴权墙", evidence: "ev.txt", confidence: "observed" },
	});
	return { ...t, factId: r.id };
}

// ── currentGoal 多 goal（D8 七处调用点共用的选取语义） ──

describe("currentGoal 多 goal 选取", () => {
	it("有 open 取最新 open；全终态取最新；多 goal 拓扑下不回退到第一条", () => {
		const t = makeTask();
		const { rootGoalId } = initTask(t.db, t.task);
		// 旧 goal 收尾 + 播种第二条（模拟 reopen 后形态）
		t.db.prepare("UPDATE nodes SET state='achieved' WHERE id=?").run(rootGoalId);
		const now = new Date().toISOString();
		const ins = t.db.prepare(
			"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES (?, 'goal', 'open', 'program', ?, ?, ?)",
		);
		const goal2 = Number(ins.run(t.name, JSON.stringify({ text: "第二个目标文本" }), now, now).lastInsertRowid);
		const goal3 = Number(ins.run(t.name, JSON.stringify({ text: "第三个目标文本" }), now, now).lastInsertRowid);

		expect(currentGoal(t.db, t.name)!.id).toBe(goal3); // 最新 open 优先
		t.db.prepare("UPDATE nodes SET state='closed' WHERE id=?").run(goal3);
		t.db.prepare("UPDATE nodes SET state='achieved' WHERE id=?").run(goal2);
		expect(currentGoal(t.db, t.name)!.id).toBe(goal3); // 无 open → 最新终态（不是第一条 root）
		t.db.close();
		t.assetsDb?.close();
	});
});

// ── list_facts q 过滤（P3-8 附带） ──

describe("planner list_facts q 过滤", () => {
	async function listFacts(db: Database, taskId: string, params: Record<string, unknown>): Promise<{ has_more: boolean; facts: Array<{ id: number; summary: string }> }> {
		const tools = createPlannerTools({ db, taskId, taskDir: dir });
		const tool = tools.find((t) => t.name === "list_facts")!;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const res = (await (tool as any).execute("1", params)) as { content: Array<{ text: string }> };
		return JSON.parse(res.content[0].text);
	}

	it("q 命中归一化包含匹配；不命中返回空数组", async () => {
		const t = makeTaskWithFact({ summary: "首页接口 200 无鉴权墙" });
		writeFileSync(join(t.tdir, "ev2.txt"), "x");
		submitFact(t.db, {
			taskId: t.name,
			taskDir: t.tdir,
			stepId: t.factId - 1,
			payload: { summary: "后台路径 /admin 鉴权缺失可未授权访问", evidence: "ev2.txt", confidence: "observed" },
		});

		const hit = await listFacts(t.db, t.name, { q: "鉴权" });
		expect(hit.facts).toHaveLength(2); // 两条 summary 都含"鉴权"
		const miss = await listFacts(t.db, t.name, { q: "不存在的关键词xyz" });
		expect(miss.facts).toHaveLength(0);
		expect(miss.has_more).toBe(false);
		const caseInsensitive = await listFacts(t.db, t.name, { q: "ADMIN" }); // 归一化含小写化
		expect(caseInsensitive.facts).toHaveLength(1);
		t.db.close();
		t.assetsDb?.close();
	});
});

// ── admin.scopeAdd（P3-7 CLI 核心） ──

describe("scope-add CLI 核心", () => {
	it("task.json 追加去重 + 资产表 origin=scope-add + 信号文件落位", () => {
		const t = makeTask({ project: "proj-a", hosts: ["a.example.com"] });
		resolveScopeHosts(t.assetsDb!, t.name, ["a.example.com"], "proj-a");

		// 大小写去重：A.example.com 与已有 a.example.com 同 host 跳过，只新增 b
		const r = scopeAdd(join(dir, "tasks"), t.name, ["b.example.com", "A.example.com", "a.example.com"]);
		expect(r.added).toEqual(["b.example.com"]);

		const onDisk = JSON.parse(readFileSync(join(t.tdir, "task.json"), "utf-8"));
		expect(onDisk.scope.hosts).toEqual(["a.example.com", "b.example.com"]);

		const rows = t.assetsDb!.prepare("SELECT origin FROM asset_tasks WHERE task_id=?").all(t.name) as Array<{ origin: string }>;
		expect(rows.filter((x) => x.origin === "scope-add")).toHaveLength(1); // 新增 host 补登记
		expect(existsSync(join(t.tdir, "control", "scope.changed"))).toBe(true);
		t.db.close();
		t.assetsDb!.close();
	});

	it("全幂等：重复 scope-add 同 host → added 空、不产生重复行", () => {
		const t = makeTask({ project: "proj-a", hosts: ["c.example.com"] });
		scopeAdd(join(dir, "tasks"), t.name, ["d.example.com"]);
		const r2 = scopeAdd(join(dir, "tasks"), t.name, ["d.example.com"]);
		expect(r2.added).toEqual([]);
		const rows = t.assetsDb!.prepare("SELECT origin FROM asset_tasks WHERE task_id=?").all(t.name) as Array<{ origin: string }>;
		expect(rows).toHaveLength(1); // 只有首次 scope-add 的 1 条
		t.db.close();
		t.assetsDb!.close();
	});
});

// ── reopenTask（P3-8 D8 CLI 核心） ──

describe("reopen CLI 核心", () => {
	it("goal open → 拒；终态 → 过（只改 task.json，不动图）", () => {
		const t = makeTaskWithFact({ goal: "第一个目标足够长了" });
		expect(() => reopenTask(join(dir, "tasks"), t.name, "还没跑完就想换目标")).toThrow(/open/);

		t.db.prepare("UPDATE nodes SET state='achieved' WHERE kind='goal'").run();
		const before = t.db.prepare("SELECT COUNT(*) AS n FROM nodes").get() as { n: number };
		const r = reopenTask(join(dir, "tasks"), t.name, "重开后的新目标文本");
		expect(r.task.goal).toBe("重开后的新目标文本");
		expect(r.prevGoalState).toBe("achieved");
		const after = t.db.prepare("SELECT COUNT(*) AS n FROM nodes").get() as { n: number };
		expect(after.n).toBe(before.n); // 图未被动过（播种归 initTask）
		t.db.close();
		t.assetsDb?.close();
	});

	it("图不存在（从未跑过）→ 允许直接改 goal", () => {
		const t = makeTask({ goal: "从未运行过的任务目标" });
		const r = reopenTask(join(dir, "tasks"), t.name, "改好了的全新目标文本");
		expect(r.task.goal).toBe("改好了的全新目标文本");
		expect(r.prevGoalState).toBeUndefined();
		t.db.close();
		t.assetsDb?.close();
	});

	it("重跑播种闭环：reopen 后 initTask 播种新 goal 并标 goalChanged", () => {
		const t = makeTaskWithFact({ goal: "待重开的目标文本" });
		t.db.prepare("UPDATE nodes SET state='closed' WHERE kind='goal'").run();
		reopenTask(join(dir, "tasks"), t.name, "重开播种的新目标文本");
		const { task } = loadTask(join(dir, "tasks"), t.name);
		const r = initTask(t.db, task);
		expect(r.goalChanged).toBe(true);
		expect(r.fresh).toBe(false);
		const newGoal = currentGoal(t.db, t.name)!;
		expect(newGoal.state).toBe("open");
		expect((JSON.parse(newGoal.payload) as { text: string }).text).toBe("重开播种的新目标文本");
		t.db.close();
		t.assetsDb?.close();
	});
});

// ── preflight（P3-10：streamFn / 浏览器探测双注入，零 LLM 零真 chrome） ──

const CFG_OK: AppConfig = {
	channels: {
		worker: { model: "m", api: "openai", keyEnv: "K" },
		planner: { model: "m", api: "openai", keyEnv: "K" },
	},
	run: { maxRounds: 5, budgetMs: 60_000 },
};
const SECRETS = { K: "test-key" };

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

function okStream(): StreamFn {
	const msg = { role: "assistant", content: [{ type: "text", text: "OK" }], ...FAKE_MSG_BASE, stopReason: "stop" };
	return fakeStream(msg, [{ type: "done", reason: "stop", message: msg }]);
}

function transportErrorStream(errorMessage: string): StreamFn {
	const msg = { role: "assistant", content: [{ type: "text", text: "" }], ...FAKE_MSG_BASE, stopReason: "error", errorMessage };
	return fakeStream(msg, [{ type: "error", reason: "error", error: msg }]);
}

/** 挂起流：直到 signal abort 才收尾（30s 硬超时路径的替身）。 */
function hangingStream(): StreamFn {
	return ((_model: unknown, _ctx: unknown, opts: any) => {
		const msg = { role: "assistant", content: [{ type: "text", text: "" }], ...FAKE_MSG_BASE, stopReason: "aborted" };
		return {
			result: async () => msg,
			async *[Symbol.asyncIterator]() {
				yield { type: "start", partial: msg };
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

describe("preflight A 通道构造（纯本地硬失败）", () => {
	it("keyEnv 缺失 → 对应通道硬失败 hardFailed=true；另一通道隔离不受影响", async () => {
		const cfg: AppConfig = {
			channels: {
				worker: { model: "m", api: "openai", keyEnv: "AT1_PREFLIGHT_MISSING_KEY_XYZ" },
				planner: { model: "m", api: "openai", keyEnv: "K" },
			},
			run: CFG_OK.run,
		};
		const r = await runPreflight({ config: cfg, secrets: SECRETS, streamFn: okStream() });
		const a1 = r.checks.find((c) => c.id === "A1")!;
		const a2 = r.checks.find((c) => c.id === "A2")!;
		expect(a1.status).toBe("fail");
		expect(a1.detail).toContain("AT1_PREFLIGHT_MISSING_KEY_XYZ");
		expect(a2.status).toBe("ok");
		expect(r.hardFailed).toBe(true);
	});
});

describe("preflight B 通道活性（生产同款 + 分档）", () => {
	it("正常回复 → ok，hardFailed=false", async () => {
		const r = await runPreflight({ config: CFG_OK, secrets: SECRETS, streamFn: okStream() });
		expect(r.checks.find((c) => c.id === "B1")!.status).toBe("ok");
		expect(r.checks.find((c) => c.id === "B2")!.status).toBe("ok");
		expect(r.hardFailed).toBe(false);
	});

	it("401 → 硬失败（确定性认证错误门口就挡）", async () => {
		const r = await runPreflight({ config: CFG_OK, secrets: SECRETS, streamFn: transportErrorStream("HTTP 401 Unauthorized") });
		expect(r.checks.find((c) => c.id === "B1")!.status).toBe("fail");
		expect(r.hardFailed).toBe(true);
	});

	it("429 / 5xx / network / unknown → 警告放行（交运行时熔断接力）", async () => {
		for (const errMsg of ["HTTP 429 Too Many Requests", "HTTP 503 Service Unavailable", "fetch failed"]) {
			const r = await runPreflight({ config: CFG_OK, secrets: SECRETS, streamFn: transportErrorStream(errMsg) });
			expect(r.checks.find((c) => c.id === "B1")!.status).toBe("warn");
			expect(r.hardFailed).toBe(false);
		}
	});

	it("30s 硬超时（测试 50ms 档）→ 警告放行，不重试", async () => {
		const r = await runPreflight({ config: CFG_OK, secrets: SECRETS, streamFn: hangingStream(), pingTimeoutMs: 50 });
		const b1 = r.checks.find((c) => c.id === "B1")!;
		expect(b1.status).toBe("warn");
		expect(b1.detail).toContain("硬超时");
		expect(b1.ms).toBeLessThan(5000);
	}, 10_000);
});

describe("preflight C 图完整性", () => {
	it("腊坏 open step 自动标 blocked + is_error 账；腊坏 fact 只警告；干净图 ok", () => {
		const t = makeTaskWithFact();
		// 干净 → ok
		const clean = integrityCheck(t.db, t.name);
		expect(clean.status).toBe("ok");
		// 塞一条腊坏 open step + 一条腊坏 fact
		const now = new Date().toISOString();
		t.db.prepare(
			"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES (?, 'step', 'open', 'planner', ?, ?, ?)",
		).run(t.name, "{broken-json!!", now, now);
		t.db.prepare(
			"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES (?, 'fact', 'confirmed', 'worker', ?, ?, ?)",
		).run(t.name, "not-json[[[", now, now);
		const r = integrityCheck(t.db, t.name);
		expect(r.status).toBe("warn");
		expect(r.detail).toContain("已标 blocked");
		const blocked = t.db.prepare("SELECT state FROM nodes WHERE payload='{broken-json!!'").get() as { state: string };
		expect(blocked.state).toBe("blocked");
		const act = t.db.prepare("SELECT * FROM activity WHERE tool='preflight' AND is_error=1").all() as Array<{ summary: string }>;
		expect(act.some((a) => a.summary.includes("腊坏"))).toBe(true);
		t.db.close();
		t.assetsDb?.close();
	});
});

describe("preflight D 浏览器池（探测注入）", () => {
	it("探测通过 → ok；探测失败 → 警告（不硬失败）；skipBrowser → skip", async () => {
		const okRun = await runPreflight({
			config: CFG_OK, secrets: SECRETS, streamFn: okStream(),
			taskDir: join(dir, "browser-t1"), probeBrowser: async () => ({ ok: true, detail: "启动→CDP 就绪→已关" }),
		});
		expect(okRun.checks.find((c) => c.id === "D")!.status).toBe("ok");
		expect(okRun.browserDegraded).toBe(false);

		const badRun = await runPreflight({
			config: CFG_OK, secrets: SECRETS, streamFn: okStream(),
			taskDir: join(dir, "browser-t2"), probeBrowser: async () => { throw new Error("Chrome 启动失败（3 次尝试）"); },
		});
		const d = badRun.checks.find((c) => c.id === "D")!;
		expect(d.status).toBe("warn"); // 拍板：失败=警告+人工选择降级
		expect(badRun.hardFailed).toBe(false);
		expect(badRun.browserDegraded).toBe(true);

		const skipRun = await runPreflight({
			config: CFG_OK, secrets: SECRETS, streamFn: okStream(), skipBrowser: true,
			taskDir: join(dir, "browser-t3"), probeBrowser: async () => ({ ok: true, detail: "不该被调用" }),
		});
		expect(skipRun.checks.find((c) => c.id === "D")!.status).toBe("skip");
	});
});

describe("preflight 汇总与渲染", () => {
	it("C/D 检查随 db/taskDir 注入出现；报告含 activity 落账 + Cairn 式表格", async () => {
		const t = makeTaskWithFact();
		const r = await runPreflight({
			config: CFG_OK, secrets: SECRETS, streamFn: okStream(),
			db: t.db, taskId: t.name, taskDir: t.tdir,
			probeBrowser: async () => ({ ok: true, detail: "真起真关替身" }),
		});
		expect(r.checks.map((c) => c.id)).toEqual(["A1", "A2", "B1", "B2", "C", "D"]);
		const act = t.db.prepare("SELECT * FROM activity WHERE tool='preflight' AND worker='preflight'").all() as Array<{ summary: string }>;
		expect(act.length).toBeGreaterThanOrEqual(1); // 汇总账落 DB（M5 查询用）
		const text = renderPreflightReport(r);
		expect(text).toContain("[+] A1");
		expect(text).toContain("结论");
		t.db.close();
		t.assetsDb?.close();
	});
});
