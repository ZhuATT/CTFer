import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Database } from "better-sqlite3";
import { runTask } from "../src/scheduler.js";
import { appendHint } from "../src/hints.js";
import { openDb } from "../src/db.js";
import type { AppConfig } from "../src/config.js";
import type { RunPlannerOptions, RunPlannerResult } from "../src/planner.js";
import type { RunWorkerStepOptions, RunWorkerStepResult } from "../src/agent.js";
import type { TaskJson } from "../src/task.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-sched-"));
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

let uid = 0;

function makeTask(seed: TaskJson["seed_steps"]): { name: string; tdir: string } {
	const name = `sched-${++uid}`;
	const tdir = join(dir, name);
	mkdirSync(join(tdir, "evidence"), { recursive: true });
	writeFileSync(
		join(tdir, "task.json"),
		JSON.stringify({ name, goal: "确认至少一个越权读取", scope: { hosts: ["x.example.com"] }, seed_steps: seed ?? [] }),
	);
	return { name, tdir };
}

const MOCK_USAGE = { turns: 1, input: 10, output: 5, cacheRead: 0, cacheWrite: 0 };

/** 剧本驱动：每幕 = [planner 派的 steps] / worker 产出的 fact 摘要（空=跳过 worker）。 */
interface ScriptDeps {
	runPlanner: (o: RunPlannerOptions) => Promise<RunPlannerResult>;
	runWorkerStep: (o: RunWorkerStepOptions) => Promise<RunWorkerStepResult>;
}

/** 剧本：plans[i]=第 i 次 planner 唤醒派的 steps；workers[j]=第 j 次 worker 执行的产出。 */
function makeScriptDeps(
	db: Database,
	taskName: string,
	taskDir: string,
	script: {
		plans?: Array<Array<{ summary: string; note?: string }>>;
		workers?: Array<{ summary?: string; aborted?: boolean }>;
	},
): ScriptDeps {
	let planIdx = -1;
	let workerIdx = -1;
	return {
		runPlanner: async (_o: RunPlannerOptions): Promise<RunPlannerResult> => {
			planIdx += 1;
			const { addStep } = await import("../src/graph.js");
			const steps = script.plans?.[planIdx] ?? [];
			if (steps.length) addStep(db, taskName, steps, "mock-planner");
			return { acceptedCount: steps.length, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		},
		runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			workerIdx += 1;
			const s = script.workers?.[workerIdx];
			if (s?.summary) {
				writeFileSync(join(taskDir, "ev.txt"), "curl → 200 越权");
				const { submitFact } = await import("../src/graph.js");
				const r = submitFact(db, {
					taskId: taskName,
					taskDir,
					stepId: o.step.id,
					payload: { summary: s.summary, evidence: "ev.txt", confidence: "observed" },
				});
				return {
					stepId: o.step.id, finalText: s.summary, usage: { ...MOCK_USAGE, turns: 2 },
					facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [], aborted: s.aborted ?? false,
				};
			}
			return {
				stepId: o.step.id, finalText: "", usage: MOCK_USAGE,
				facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: s?.aborted ?? false,
			};
		},
	};
}

describe("runTask mock 集成（零 LLM）", () => {
	it("剧本全循环：seed step → worker → planner 派新 → worker → goal 证明自停", async () => {
		const { name, tdir } = makeTask([{ summary: "探测首页鉴权面" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "首页 200 无鉴权墙" }, { summary: "已确认越权读取用户列表" }],
			plans: [[{ summary: "沿用户接口查越权读取", note: "依据首页无墙+接口列表" }], []],
		});

		// planner 派 0 时手工盖章（模拟真 planner 调 prove_goal）
		const { proveGoal } = await import("../src/graph.js");
		const origPlanner = deps.runPlanner;
		deps.runPlanner = async (o) => {
			const r = await origPlanner(o);
			if (r.acceptedCount === 0 && !goalProved(db)) {
				const goal = db.prepare("SELECT id FROM nodes WHERE kind='goal'").get() as { id: number };
				const fact = db.prepare("SELECT id FROM nodes WHERE kind='fact' ORDER BY id DESC LIMIT 1").get() as { id: number };
				proveGoal(db, { taskId: name, goalId: goal.id, evidenceId: fact.id, reason: "fact 证实" });
			}
			return r;
		};
		function goalProved(d: Database): boolean {
			const g = d.prepare("SELECT state FROM nodes WHERE kind='goal'").get() as { state: string };
			return g?.state === "achieved";
		}

		const result = await runTask({
			tasksRoot: dir,
			taskName: name,
			config: CFG,
			secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("goal-achieved");
		expect(result.workerSteps).toBe(2);
		expect(result.plannerWakeups).toBe(2);
		db.close();
	});

	it("planner 连续派 0 → planner-zero 判停（不空转）", async () => {
		const { name, tdir } = makeTask([{ summary: "看一眼首页" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "首页无信息" }],
			plans: [[]],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("planner-zero");
		expect(result.plannerWakeups).toBe(1); // 派 0 即停，不反复唤醒
		db.close();
	});

	it("CONTROL stop：轮边界优雅退出，已产出保留", async () => {
		const { name, tdir } = makeTask([{ summary: "第一件事" }, { summary: "第二件事" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "第一件完成" }, { summary: "第二件完成" }],
		});
		// worker 首步完成后置 stop 信号（模拟轮间 stop 请求）
		const origWorker = deps.runWorkerStep;
		let called = 0;
		deps.runWorkerStep = async (o) => {
			const r = await origWorker(o);
			called += 1;
			if (called === 1) {
				mkdirSync(join(tdir, "control"), { recursive: true });
				writeFileSync(join(tdir, "control", "stop"), "cmd=stop\n");
			}
			return r;
		};
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("control-stop");
		expect(result.workerSteps).toBe(1); // 第二轮边界退出，只跑了一步
		const facts = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='fact'").get() as { n: number };
		expect(facts.n).toBe(1); // 已产出保留
		db.close();
	});

	it("中断续跑：running 尸体被清扫 + planner 收到 resume/hint 触发并重派接续", async () => {
		const { name, tdir } = makeTask([{ summary: "探测面甲" }, { summary: "探测面乙" }]);
		const db = openDb(join(tdir, "graph.db"));
		// 预造"上次中断"现场：step 甲 done、step 乙 running 尸体、操作员插话
		const { initTask } = await import("../src/graph.js");
		const { TaskJson } = await import("../src/task.js");
		const { stepIds } = initTask(db, TaskJson.parse(JSON.parse(readFileSync(join(tdir, "task.json"), "utf-8"))));
		db.prepare("UPDATE nodes SET state='done' WHERE id=?").run(stepIds[0]);
		db.prepare("UPDATE nodes SET state='running' WHERE id=?").run(stepIds[1]);
		appendHint(tdir, "重点看 /user/profile 接口");

		const seen: Array<{ plannerEvents?: string[]; workerStepId?: number }> = [];
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "面乙接续补完" }],
			plans: [[{ summary: "接上次进度继续探测面乙", note: "exhausted 接续" }], []],
		});
		const origPlanner = deps.runPlanner;
		deps.runPlanner = async (o) => {
			seen.push({ plannerEvents: o.events.map((e) => e.type) });
			return origPlanner(o);
		};
		const origWorker = deps.runWorkerStep;
		deps.runWorkerStep = async (o) => {
			seen.push({ workerStepId: o.step.id });
			return origWorker(o);
		};

		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		// 启动清扫：尸体乙被置 exhausted（非 open）→ worker 领到的是 planner 重派的新 step
		const corpse = db.prepare("SELECT state FROM nodes WHERE id=?").get(stepIds[1]) as { state: string };
		expect(corpse.state).toBe("exhausted");
		const workerCall = seen.find((s) => s.workerStepId !== undefined);
		expect(workerCall?.workerStepId).toBeDefined();
		expect(workerCall!.workerStepId!).not.toBe(stepIds[1]); // 不是尸体本身——重派的新 step
		// planner 首次唤醒收到 resume + hint 触发
		const plannerCall = seen.find((s) => s.plannerEvents) as { plannerEvents: string[] } | undefined;
		expect(plannerCall).toBeTruthy();
		expect(plannerCall!.plannerEvents).toContain("resume");
		expect(plannerCall!.plannerEvents).toContain("hint");
		expect(result.reason).toBe("planner-zero"); // 第二次唤醒派 0 → 判停
		db.close();
	});
});
