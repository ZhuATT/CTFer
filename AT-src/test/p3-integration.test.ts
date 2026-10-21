/**
 * P3 mock 集成（零 LLM）——验收清单 §3 后四格 + 双 task 一 project 全链剧本：
 * - 简报注入：双 task 夹具（unit）+ scheduler 首轮一次性注入（integration）
 * - scope.changed 信号 → Set 原位变更 + scope_changed 事件 + 信号删除
 * - reopen 闭环：goal-achieved → reopen → 重跑播种新 goal + goal_changed 事件
 * - 无 project 的 task（D6）：全链路不碰 assets.db，行为与 P2fix 一致
 * - 全链剧本：A 登记+带 endpoint facts → B 复用资产 + 简报 + list_assets 子集 + coverage 未测
 */
import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Database } from "better-sqlite3";
import { runTask } from "../src/scheduler.js";
import { openDb } from "../src/db.js";
import { openAssetsDb, resolveScopeHosts, registerAsset, listAssetsInScope } from "../src/assets.js";
import { buildProjectBriefing, renderProjectBriefing } from "../src/briefing.js";
import { initTask, submitFact, submitFinding, currentGoal, proveGoal, graphOverview } from "../src/graph.js";
import { loadTask, type TaskJson } from "../src/task.js";
import { reopenTask } from "../src/admin.js";
import type { AppConfig } from "../src/config.js";
import type { RunPlannerOptions, RunPlannerResult } from "../src/planner.js";
import type { RunWorkerStepOptions, RunWorkerStepResult } from "../src/agent.js";
import type { TriggerEvent } from "../src/triggers.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-p3int-"));
const TASKS_ROOT = join(dir, "tasks");
afterAll(() => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 句柄延迟释放——tmp 目录留给 OS */
	}
});

const CFG: AppConfig = {
	channels: {
		worker: { model: "m", api: "openai", keyEnv: "K" },
		planner: { model: "m", api: "openai", keyEnv: "K" },
	},
	run: { maxRounds: 10, budgetMs: 600_000 },
};
const MOCK_USAGE = { turns: 1, input: 10, output: 5, cacheRead: 0, cacheWrite: 0 };

let uid = 0;
let evCounter = 0;

interface MakeTaskOpts {
	project?: string;
	hosts: string[];
	goal?: string;
	steps?: number;
}

/** 造 task（写 task.json + evidence 目录），不 init——init 交给 runTask 或显式调用。 */
function makeTask(opts: MakeTaskOpts): { name: string; tdir: string; task: TaskJson } {
	const name = `p3i-${++uid}`;
	const tdir = join(TASKS_ROOT, name);
	mkdirSync(join(tdir, "evidence"), { recursive: true });
	const seed = Array.from({ length: opts.steps ?? 1 }, (_, i) => ({ summary: `种子方向${i + 1}：够长够具体的探测` }));
	writeFileSync(
		join(tdir, "task.json"),
		JSON.stringify({
			name,
			...(opts.project ? { project: opts.project } : {}),
			goal: opts.goal ?? "确认目标存在越权读取",
			scope: { hosts: opts.hosts },
			seed_steps: seed,
		}),
	);
	return { name, tdir, task: loadTask(TASKS_ROOT, name).task };
}

/** worker 剧本钩子里提交 fact 的便捷函数（evidence 现写现交，链路同生产 submitFact）。 */
function submitMockFact(o: RunWorkerStepOptions, summary: string, endpoint?: string, confidence: "observed" | "inferred" = "observed"): number {
	const evName = `ev-${++evCounter}.txt`;
	writeFileSync(join(o.taskDir, evName), `curl → 200（${summary}）`);
	return submitFact(o.db, {
		taskId: o.task.name,
		taskDir: o.taskDir,
		stepId: o.step.id,
		payload: { summary, evidence: evName, confidence, ...(endpoint ? { endpoint } : {}) },
		assetsDb: o.assetsDb,
	}).id;
}

/** worker 替身：按剧本逐次执行钩子（钩子里自行 submitFact/registerAsset），step 落 done。 */
function makeWorkerStub(script: Array<(o: RunWorkerStepOptions) => void>) {
	let idx = -1;
	return async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
		idx += 1;
		script[idx]?.(o);
		const { setStepState } = await import("../src/graph.js");
		setStepState(o.db, o.task.name, o.step.id, "done");
		return {
			stepId: o.step.id, finalText: "mock 完成", usage: MOCK_USAGE,
			facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: false,
		};
	};
}

interface PlannerObservation {
	events: TriggerEvent[];
	briefing?: string;
	assetsDb?: Database;
}

/** 空 planner 替身（可注入步进剧本 + 观察捕获 + 派 0 时自动 prove）。 */
function makePlannerStub(opts: {
	taskName: string;
	plans?: Array<Array<{ summary: string; note?: string }>>;
	seen?: PlannerObservation[];
	proveWithFactOnZero?: boolean;
}) {
	let planIdx = -1;
	return async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
		planIdx += 1;
		opts.seen?.push({ events: o.events, briefing: o.briefingText, assetsDb: o.assetsDb });
		const { addStep } = await import("../src/graph.js");
		const steps = opts.plans?.[planIdx] ?? [];
		if (steps.length) addStep(o.db, opts.taskName, steps, "mock-planner");
		if (opts.proveWithFactOnZero && steps.length === 0) {
			const goal = currentGoal(o.db, opts.taskName);
			const fact = o.db
				.prepare("SELECT id FROM nodes WHERE task_id=? AND kind='fact' ORDER BY id DESC LIMIT 1")
				.get(opts.taskName) as { id: number } | undefined;
			if (goal && fact && goal.state === "open") {
				proveGoal(o.db, { taskId: opts.taskName, goalId: goal.id, evidenceId: fact.id, reason: "mock：fact 证实达标" });
			}
		}
		return { acceptedCount: steps.length, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
	};
}

// ── 简报 unit（验收格 1：双 task 夹具 / inferred 不带 / cap 20 / 无前任无节） ──

describe("buildProjectBriefing（D4 边界）", () => {
	it("前任 findings 全量 + observed 锚定 facts；inferred 与未锚定不带；cap 20 id 倒序", () => {
		const proj = `proj-brief-${++uid}`;
		const a = makeTask({ project: proj, hosts: ["a.example.com", "shared.example.com"] });
		const b = makeTask({ project: proj, hosts: ["shared.example.com"] });

		// A 图：goal + step + 1 finding + 25 observed 锚定 facts + 1 inferred 锚定 + 1 observed 未锚定
		const aDb = openDb(join(a.tdir, "graph.db"));
		const assetsDb = openAssetsDb(join(dir, "projects", proj, "assets.db"));
		const { stepIds } = initTask(aDb, a.task);
		writeFileSync(join(a.tdir, "ev.txt"), "curl → 200 越权读取");
		submitFinding(aDb, {
			taskId: a.name, taskDir: a.tdir, stepId: stepIds[0],
			payload: {
				summary: "确认共享主机存在越权读取", vulnclass: "idor", severity: "high", poc: "curl /api/users 未授权返回列表",
				evidence: "ev.txt", endpoint: "shared.example.com/",
			},
			assetsDb,
		});
		const observedIds: number[] = [];
		for (let i = 1; i <= 25; i++) {
			writeFileSync(join(a.tdir, `ev-f${i}.txt`), `观察 ${i}`);
			observedIds.push(
				submitFact(aDb, {
					taskId: a.name, taskDir: a.tdir, stepId: stepIds[0],
					payload: { summary: `共享主机观察点${i}：返回未预期数据`, evidence: `ev-f${i}.txt`, confidence: "observed", endpoint: "shared.example.com/" },
					assetsDb,
				}).id,
			);
		}
		writeFileSync(join(a.tdir, "ev-inf.txt"), "推测");
		submitFact(aDb, {
			taskId: a.name, taskDir: a.tdir, stepId: stepIds[0],
			payload: { summary: "推测共享主机存在注入点未经证实", evidence: "ev-inf.txt", confidence: "inferred", endpoint: "shared.example.com/" },
			assetsDb,
		});
		writeFileSync(join(a.tdir, "ev-ua.txt"), "未锚定观察");
		submitFact(aDb, {
			taskId: a.name, taskDir: a.tdir, stepId: stepIds[0],
			payload: { summary: "与本 scope 无关的孤证观察记录", evidence: "ev-ua.txt", confidence: "observed", endpoint: "http://elsewhere.example.com/" },
			assetsDb,
		});

		// B 的 scope 登记（简报锚定查询的前提：B 在 asset_tasks 里拥有 shared.example.com）
		resolveScopeHosts(assetsDb, b.name, ["shared.example.com"], proj);

		const briefing = buildProjectBriefing(TASKS_ROOT, proj, b.name, assetsDb);
		expect(briefing).toBeDefined();
		expect(briefing!.sourceTasks).toContain(a.name);
		expect(briefing!.findings).toHaveLength(1); // findings 全量
		expect(briefing!.findings[0].summary).toContain("越权读取");
		expect(briefing!.facts).toHaveLength(20); // cap 20
		expect(briefing!.facts[0].id).toBe(observedIds[24]); // id 倒序（最新优先）
		expect(briefing!.facts.some((f) => f.summary.includes("推测"))).toBe(false); // inferred 不带
		expect(briefing!.facts.some((f) => f.summary.includes("孤证"))).toBe(false); // 未锚定不带

		const rendered = renderProjectBriefing(briefing);
		expect(rendered).toContain("【项目简报】");
		expect(rendered).toContain(`[来自 ${a.name}]`);
		expect(renderProjectBriefing(undefined)).toBeUndefined(); // 无内容不渲染空节
		aDb.close();
		assetsDb.close();
	});

	it("无前任（同 project 无其它 task）→ undefined（不渲染空节）", () => {
		const proj = `proj-empty-${++uid}`;
		const solo = makeTask({ project: proj, hosts: ["solo.example.com"] });
		const assets = openAssetsDb(join(dir, "projects", proj, "assets.db"));
		resolveScopeHosts(assets, solo.name, ["solo.example.com"], proj);
		expect(buildProjectBriefing(TASKS_ROOT, proj, solo.name, assets)).toBeUndefined();
		assets.close();
	});
});

// ── 全链剧本（mock 集成：双 task 一 project——资产复用 + 简报 + 子集视野 + coverage） ──

describe("双 task 一 project 全链剧本", () => {
	it("A 登记+锚定 → B 起跑：scope 命中复用不新建 + 简报首轮注入 + list_assets 子集 + coverage 指未测", async () => {
		const proj = `proj-full-${++uid}`;
		const a = makeTask({ project: proj, hosts: ["a.example.com", "shared.example.com"] });
		const b = makeTask({ project: proj, hosts: ["shared.example.com"] });
		const assetsDbPath = join(dir, "projects", proj, "assets.db");
		const countAssets = (db: Database) => (db.prepare("SELECT COUNT(*) AS n FROM assets").get() as { n: number }).n;

		// ── task A：worker 登记资产 + 提交带 endpoint 的 facts + finding ──
		const aWorkerStub = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			expect(o.assetsDb).toBeDefined();
			registerAsset(o.assetsDb!, o.task.name, { host: "internal.a.example.com", note: "内网资产线索" }, proj);
			submitMockFact(o, "共享主机首页可未授权访问", "shared.example.com/");
			submitMockFact(o, "秘密子域存在管理后台入口", "http://secret.a.example.com/x");
			submitMockFact(o, "推测共享主机存在注入点未经证实", "shared.example.com/", "inferred");
			writeFileSync(join(o.taskDir, "ev-find.txt"), "curl /api/users → 200 返回用户列表");
			submitFinding(o.db, {
				taskId: o.task.name, taskDir: o.taskDir, stepId: o.step.id,
				payload: {
					summary: "确认共享主机存在越权读取", vulnclass: "idor", severity: "high",
					poc: "curl /api/users 未授权返回列表", evidence: "ev-find.txt", endpoint: "shared.example.com/",
				},
				assetsDb: o.assetsDb,
			});
			const { setStepState } = await import("../src/graph.js");
			setStepState(o.db, o.task.name, o.step.id, "done");
			return { stepId: o.step.id, finalText: "A 完成", usage: MOCK_USAGE, facts: 3, findings: 1, newFactIds: [], newFindingIds: [], aborted: false };
		};
		const aResult = await runTask({
			tasksRoot: TASKS_ROOT, taskName: a.name, config: CFG, secrets: {},
			deps: { runWorkerStep: aWorkerStub, runPlanner: makePlannerStub({ taskName: a.name }) },
		});
		expect(aResult.reason).toBe("planner-zero");

		const assetsDb = openAssetsDb(assetsDbPath);
		expect(countAssets(assetsDb)).toBe(4); // a.example.com + shared.example.com（scope）+ internal（登记）+ secret 子域（锚点发现）

		// ── task B：复用 + 简报 + 视角隔离 ──
		const bPlannerSeen: PlannerObservation[] = [];
		const bWorkerSeen: RunWorkerStepOptions[] = [];
		let bAssetCountAtStart = -1;
		const bWorkerStub = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			bWorkerSeen.push(o);
			if (bAssetCountAtStart === -1) bAssetCountAtStart = countAssets(o.assetsDb!); // scope resolve 后、B 自己产出前
			submitMockFact(o, "共享主机 api 接口未授权返回列表", "http://shared.example.com/api");
			const { setStepState } = await import("../src/graph.js");
			setStepState(o.db, o.task.name, o.step.id, "done");
			return { stepId: o.step.id, finalText: "B 完成", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
		};
		const bPlannerStub = makePlannerStub({
			taskName: b.name,
			plans: [[{ summary: "沿共享主机 api 方向深挖越权", note: "依据项目简报" }], []],
			seen: bPlannerSeen,
		});
		const bResult = await runTask({
			tasksRoot: TASKS_ROOT, taskName: b.name, config: CFG, secrets: {},
			deps: { runWorkerStep: bWorkerStub, runPlanner: bPlannerStub },
		});
		expect(bResult.reason).toBe("planner-zero");

		// 复用：B 的 scope resolve 命中已有资产（不新建）——B 起跑时仍是 4 条
		expect(bAssetCountAtStart).toBe(4);
		expect(countAssets(assetsDb)).toBe(5); // B 的 /api 锚点发现 +1

		// 简报：首轮注入（含 A finding + observed 锚定 fact；inferred/未锚定不带），第二轮不带
		expect(bPlannerSeen.length).toBe(2);
		expect(bPlannerSeen[0].briefing).toBeDefined();
		expect(bPlannerSeen[0].briefing).toContain(`[来自 ${a.name}]`);
		expect(bPlannerSeen[0].briefing).toContain("确认共享主机存在越权读取");
		expect(bPlannerSeen[0].briefing).toContain("共享主机首页可未授权访问");
		expect(bPlannerSeen[0].briefing).not.toContain("未经证实"); // inferred 不带
		expect(bPlannerSeen[0].briefing).not.toContain("秘密子域"); // 锚不在 B scope 的 asset 不带
		expect(bPlannerSeen[1].briefing).toBeUndefined(); // 首轮一次性

		// 视角隔离：B 的 list_assets 只见子集（1 条）；anchor_count host 级只算 B 自己的锚
		// （P2 修法 A：B 锚的 /api 资产与 scope 裸 host 同 host → 计入；A 的锚不计入）
		// （scheduler 退出时已 close 自己的 assetsDb 句柄——run 后查询用自开句柄）
		const view = listAssetsInScope(assetsDb, b.name, {});
		expect(view.total).toBe(1);
		expect(view.assets[0].url).toBe("shared.example.com");
		expect(view.assets[0].anchor_count).toBe(1);

		// coverage：scope_total=1 / anchored=1（host 级：B 的 /api 锚覆盖裸 host 资产）/ untouched 空
		const bDb = openDb(join(b.tdir, "graph.db"));
		const overview = graphOverview(bDb, b.name, assetsDb);
		bDb.close();
		expect(overview.coverage).toBeDefined();
		expect(overview.coverage!.scope_total).toBe(1);
		expect(overview.coverage!.anchored).toBe(1);
		expect(overview.coverage!.untouched).toEqual([]);

		assetsDb.close();
	});
});

// ── scope.changed 信号（验收格 2：Set 原位变更 + 事件 + 信号删除） ──

describe("scope-add watcher 重载（P3-7）", () => {
	it("信号 → scopeSet 原位变更（guard 即刻生效）+ scope_changed 事件 + 资产补录 + 信号删除", async () => {
		const proj = `proj-scope-${++uid}`;
		const t = makeTask({ project: proj, hosts: ["a.example.com"], steps: 1 });

		const workerCalls: RunWorkerStepOptions[] = [];
		const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
		const workerStub = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			workerCalls.push(o);
			if (workerCalls.length === 1) {
				// 模拟操作员在跑途中 scope-add：改 task.json + 写信号（admin.scopeAdd 的两件事）
				const jsonPath = join(o.taskDir, "task.json");
				const meta = JSON.parse(readFileSync(jsonPath, "utf-8")) as { scope: { hosts: string[] } };
				meta.scope.hosts.push("b.example.com");
				writeFileSync(jsonPath, JSON.stringify(meta));
				mkdirSync(join(o.taskDir, "control"), { recursive: true });
				writeFileSync(join(o.taskDir, "control", "scope.changed"), JSON.stringify({ added: ["b.example.com"] }));
			}
			await sleep(120); // 给 watcher（10ms tick）留消费窗口
			submitMockFact(o, workerCalls.length === 1 ? "A 面探测观察记录" : "B 面接续观察记录");
			const { setStepState } = await import("../src/graph.js");
			setStepState(o.db, o.task.name, o.step.id, "done");
			return { stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
		};

		const plannerSeen: PlannerObservation[] = [];
		const plannerStub = makePlannerStub({
			taskName: t.name,
			plans: [[{ summary: "对新扩权 host 派探测方向", note: "scope_changed" }], []],
			seen: plannerSeen,
		});

		const result = await runTask({
			tasksRoot: TASKS_ROOT, taskName: t.name, config: CFG, secrets: {},
			watchIntervalMs: 10,
			deps: { runWorkerStep: workerStub, runPlanner: plannerStub },
		});
		expect(result.reason).toBe("planner-zero");

		// Set 原位变更：第二次 worker 领单时 scopeHosts 已含新 host（guard 同引用即刻生效）
		expect(workerCalls.length).toBe(2);
		const scopeAtSecond = workerCalls[1].scopeHosts as Set<string>;
		expect(scopeAtSecond.has("b.example.com")).toBe(true);

		// planner 收到 scope_changed 事件
		const ev = plannerSeen[0].events.find((e) => e.type === "scope_changed") as { added: string[] } | undefined;
		expect(ev?.added).toEqual(["b.example.com"]);

		// 资产补录 + 信号删除
		const assetsDb = openAssetsDb(join(dir, "projects", proj, "assets.db"));
		const assetRows = assetsDb.prepare("SELECT origin FROM asset_tasks WHERE task_id=?").all(t.name) as Array<{ origin: string }>;
		expect(assetRows.length).toBeGreaterThanOrEqual(2); // a（operator）+ b（watcher 补录）
		assetsDb.close();
		expect(existsSync(join(t.tdir, "control", "scope.changed"))).toBe(false);
	});
});

// ── reopen 闭环（验收格 3 后半：终态过 + 重跑播种新 goal + goal_changed 事件） ──

describe("reopen → 重跑播种闭环（P3-8 D8）", () => {
	it("goal-achieved 后 reopen 换目标：重跑 initTask 播种新 goal，planner 收 goal_changed", async () => {
		const t = makeTask({ hosts: ["reopen.example.com"], goal: "第一轮目标：确认首页可访问" });
		const db = openDb(join(t.tdir, "graph.db"));

		// ── 第一轮：跑到达标 ──
		const w1 = makeWorkerStub([(o) => void submitMockFact(o, "首页 200 可正常访问")]);
		const p1 = makePlannerStub({ taskName: t.name, plans: [[]], proveWithFactOnZero: true });
		const r1 = await runTask({ tasksRoot: TASKS_ROOT, taskName: t.name, config: CFG, secrets: {}, deps: { runWorkerStep: w1, runPlanner: p1 } });
		expect(r1.reason).toBe("goal-achieved");

		// ── reopen：终态 → 过（open 拒路径 unit 已盖，这里走通路径） ──
		const rr = reopenTask(TASKS_ROOT, t.name, "第二轮目标：拿下后台管理员权限");
		expect(rr.prevGoalState).toBe("achieved");

		// ── 第二轮：播种新 goal + goal_changed 事件 + 新 goal 被证明 ──
		const plannerSeen: PlannerObservation[] = [];
		const p2base = makePlannerStub({
			taskName: t.name,
			plans: [[{ summary: "探测后台登录面的新方向", note: "新目标首轮" }], []],
			proveWithFactOnZero: true,
		});
		const p2 = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			plannerSeen.push({ events: o.events, briefing: o.briefingText, assetsDb: o.assetsDb });
			return p2base(o);
		};
		const w2 = makeWorkerStub([(o) => void submitMockFact(o, "后台登录页存在弱口令提示")]);
		const r2 = await runTask({ tasksRoot: TASKS_ROOT, taskName: t.name, config: CFG, secrets: {}, deps: { runWorkerStep: w2, runPlanner: p2 } });
		expect(r2.reason).toBe("goal-achieved");

		const goalChangedEv = plannerSeen[0].events.find((e) => e.type === "goal_changed") as { text: string } | undefined;
		expect(goalChangedEv?.text).toBe("第二轮目标：拿下后台管理员权限");
		const goals = db.prepare("SELECT id, state, payload FROM nodes WHERE kind='goal' ORDER BY id").all() as Array<{ id: number; state: string; payload: string }>;
		expect(goals).toHaveLength(2);
		expect(goals[0].state).toBe("achieved"); // 旧 goal 保持终态
		expect((JSON.parse(goals[1].payload) as { text: string }).text).toContain("第二轮目标");
		expect(currentGoal(db, t.name)!.id).toBe(goals[1].id); // 七处调用点拿到的是新 goal
		db.close();
	});
});

// ── 无 project 兼容（验收格 4，D6：存量形态行为不变） ──

describe("无 project 的 task（D6 向后兼容）", () => {
	it("全链路不碰 assets.db：双替身收 assetsDb=undefined、无简报、projects/ 无新增", async () => {
		const t = makeTask({ hosts: ["legacy.example.com"] }); // 无 project 字段
		const projectsDir = join(dir, "projects");
		const projectsBefore = existsSync(projectsDir);
		const plannerSeen: PlannerObservation[] = [];
		const workerSeen: RunWorkerStepOptions[] = [];

		const plannerStub = makePlannerStub({
			taskName: t.name,
			plans: [[{ summary: "沿存量方向继续深探测", note: "D6" }], []],
		});
		const wrappedPlanner = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			plannerSeen.push({ events: o.events, briefing: o.briefingText, assetsDb: o.assetsDb });
			return plannerStub(o);
		};
		const workerStub = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			workerSeen.push(o);
			submitMockFact(o, "存量形态下的探测观察记录");
			const { setStepState } = await import("../src/graph.js");
			setStepState(o.db, o.task.name, o.step.id, "done");
			return { stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
		};

		const result = await runTask({
			tasksRoot: TASKS_ROOT, taskName: t.name, config: CFG, secrets: {},
			deps: { runWorkerStep: workerStub, runPlanner: wrappedPlanner },
		});
		expect(result.reason).toBe("planner-zero");

		// 全链路判空：worker/planner 双侧 assetsDb 均 undefined（工具不装配、不落锚、无 coverage/简报）
		expect(workerSeen.length).toBe(2);
		expect(workerSeen.every((o) => o.assetsDb === undefined)).toBe(true);
		expect(plannerSeen.every((p) => p.assetsDb === undefined)).toBe(true);
		expect(plannerSeen.every((p) => p.briefing === undefined)).toBe(true);
		// 行为与 P2fix 一致：scopeHosts 照传（Set），projects/ 落盘状态不变
		expect(workerSeen[0].scopeHosts).toBeInstanceOf(Set);
		expect(existsSync(projectsDir)).toBe(projectsBefore);
	});
});
