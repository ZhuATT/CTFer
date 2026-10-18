import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
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
import type { TriggerEvent } from "../src/triggers.js";

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
			const { setStepState } = await import("../src/graph.js");
			if (s?.summary) {
				writeFileSync(join(taskDir, "ev.txt"), "curl → 200 越权");
				const { submitFact } = await import("../src/graph.js");
				const r = submitFact(db, {
					taskId: taskName,
					taskDir,
					stepId: o.step.id,
					payload: { summary: s.summary, evidence: "ev.txt", confidence: "observed" },
				});
				setStepState(db, taskName, o.step.id, s.aborted ? "exhausted" : "done"); // 真实 runWorkerStep 的收尾语义
				return {
					stepId: o.step.id, finalText: s.summary, usage: { ...MOCK_USAGE, turns: 2 },
					facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [], aborted: s.aborted ?? false,
				};
			}
			setStepState(db, taskName, o.step.id, s?.aborted ? "exhausted" : "done");
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

		const seen: Array<{ plannerEvents?: string[]; workerStepId?: number; workerChannel?: unknown }> = [];
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
			seen.push({ workerStepId: o.step.id, workerChannel: o.channel });
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
		// P2F-1：调度循环传整份通道配置
		expect(workerCall!.workerChannel).toBe(CFG.channels.worker);
		// planner 首次唤醒收到 resume + hint 触发
		const plannerCall = seen.find((s) => s.plannerEvents) as { plannerEvents: string[] } | undefined;
		expect(plannerCall).toBeTruthy();
		expect(plannerCall!.plannerEvents).toContain("resume");
		expect(plannerCall!.plannerEvents).toContain("hint");
		expect(result.reason).toBe("planner-zero"); // 第二次唤醒派 0 → 判停
		db.close();
	});
});

describe("p2fix mock 场景（零 LLM）", () => {
	it("P2F-6 事件驱动唤醒节奏：每个 step_done 唤醒一次；首轮空事件不唤醒", async () => {
		const { name, tdir } = makeTask([{ summary: "第一方向足够长" }, { summary: "第二方向足够长" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "第一方向探完无收获" }, { summary: "第二方向探完无收获" }],
			plans: [[], []], // planner 两轮都派 0（等价已覆盖）
		});
		const wakes: string[][] = [];
		const origPlanner = deps.runPlanner;
		deps.runPlanner = async (o) => {
			wakes.push(o.events.map((e) => e.type));
			return origPlanner(o);
		};
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		// 首轮空事件 + 有 open step → 直接 worker（plannerWakeups 从 0 开始计 step_done）
		expect(result.plannerWakeups).toBe(2);
		expect(result.workerSteps).toBe(2);
		expect(wakes[0]).toContain("step_done"); // 每次唤醒都消费 step_done 事件
		expect(result.reason).toBe("planner-zero"); // 派 0 且无 open → 判停
		db.close();
	});

	it("P2F-4 conclude 收尾循环：planner 探尽 conclude → reason=goal-closed", async () => {
		const { name, tdir } = makeTask([{ summary: "唯一方向足够长" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ summary: "方向探完，全阴性" }],
			plans: [[], []],
		});
		const origPlanner = deps.runPlanner;
		deps.runPlanner = async (o) => {
			const r = await origPlanner(o);
			// 模拟真 planner 判断探尽后调 conclude_task
			const { concludeGoal } = await import("../src/graph.js");
			const open = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='step' AND state IN ('open','running')").get() as { n: number }).n;
			if (r.acceptedCount === 0 && open === 0 && !goalIsClosed(db)) {
				concludeGoal(db, { taskId: name, reason: "全部方向探尽（#2 done 全阴性），再派无价值", sessionId: "mock" });
			}
			return r;
		};
		function goalIsClosed(d: Database): boolean {
			const g = d.prepare("SELECT state FROM nodes WHERE kind='goal'").get() as { state: string };
			return g?.state === "closed";
		}
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		expect(result.reason).toBe("goal-closed");
		const g = db.prepare("SELECT state FROM nodes WHERE kind='goal'").get() as { state: string };
		expect(g.state).toBe("closed");
		db.close();
	});

	it("P2F-5 stop watcher：在跑 step 秒级 abort 落 exhausted，reason=control-stop", async () => {
		const { name, tdir } = makeTask([{ summary: "长时间探测方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		// 替身 worker：挂起等 abortSignal（模拟在跑会话），收到 abort → 走优雅收尾（aborted=true）
		let abortSeen = false;
		const hangingWorker = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			await new Promise<void>((res) => {
				const t = setTimeout(res, 10_000);
				o.abortSignal?.addEventListener("abort", () => {
					abortSeen = true;
					clearTimeout(t);
					res();
				}, { once: true });
			});
			writeFileSync(join(tdir, "ev.txt"), "部分产出保留");
			const { submitFact, setStepState } = await import("../src/graph.js");
			const r = submitFact(db, {
				taskId: name, taskDir: tdir, stepId: o.step.id,
				payload: { summary: "被掐前已确认的部分产出", evidence: "ev.txt", confidence: "observed" },
			});
			setStepState(db, name, o.step.id, "exhausted"); // 真实 runWorkerStep 的收尾语义
			return { stepId: o.step.id, finalText: "被掐", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [], aborted: true };
		};
		const run = runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			watchIntervalMs: 20,
			deps: { runWorkerStep: hangingWorker, runPlanner: noopPlanner },
		});
		await sleep(80); // 让 worker 挂进在跑态
		mkdirSync(join(tdir, "control"), { recursive: true });
		writeFileSync(join(tdir, "control", "stop"), "cmd=stop\n");
		const result = await run;
		expect(abortSeen).toBe(true); // watcher 触发了 abort（替身断言）
		expect(result.reason).toBe("control-stop");
		const step = db.prepare("SELECT state FROM nodes WHERE kind='step'").get() as { state: string };
		expect(step.state).toBe("exhausted"); // 优雅收尾：非 running 尸体
		const fact = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='fact'").get() as { n: number };
		expect(fact.n).toBe(1); // 已产出保留
		db.close();
	});

	it("P2F-11 steer：在跑时送达（替身 steer spy），step_done 事件组含 steered；不在跑丢弃留账", async () => {
		const { name, tdir } = makeTask([{ summary: "被插话的 step 方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const steered: string[] = [];
		let stepIdSeen = 0;
		const steerableWorker = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			stepIdSeen = o.step.id;
			// 替身 agent：steer spy
			o.onAgent?.({ steer: (m) => steered.push(String((m as { content: string }).content)) });
			// 模拟操作员在 step 跑到一半时插话（写入 steer.jsonl，watcher 20ms 内收割）
			const { appendSteer } = await import("../src/steer.js");
			appendSteer(tdir, "插话：改试 X-Forwarded-For", o.step.id);
			await sleep(100); // 给 watcher 留出 tick
			writeFileSync(join(tdir, "ev.txt"), "curl → 200");
			const { submitFact } = await import("../src/graph.js");
			const r = submitFact(db, {
				taskId: name, taskDir: tdir, stepId: o.step.id,
				payload: { summary: "step 完成，吸收插话后确认", evidence: "ev.txt", confidence: "observed" },
			});
			return { stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [], aborted: false };
		};
		const plannerEventsSeen: TriggerEvent[][] = [];
		const plannerStub = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			plannerEventsSeen.push(o.events);
			return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		};
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			watchIntervalMs: 20,
			deps: { runWorkerStep: steerableWorker, runPlanner: plannerStub },
		});
		// 替身收到 steer 送达
		expect(steered).toHaveLength(1);
		expect(steered[0]).toContain("【操作员插话】");
		// planner 的 step_done 事件组里带 steered
		const group = plannerEventsSeen.find((evs) => evs.some((e) => e.type === "step_done"));
		expect(group?.some((e) => e.type === "steered" && e.stepId === stepIdSeen)).toBe(true);
		// activity 落账 operator/steer
		const act = db.prepare("SELECT * FROM activity WHERE tool='steer' AND worker='operator'").all() as Array<{ summary: string; is_error: number }>;
		expect(act.some((a) => a.summary.includes("送达") && !a.is_error)).toBe(true);
		expect(result.workerSteps).toBe(1);
		db.close();
	});

	it("P2F-11 steer 竞态兜底：目标已不在跑 → 丢弃 + is_error 留账，不进 planner", async () => {
		const { name, tdir } = makeTask([{ summary: "竞态场景的 step" }]);
		const db = openDb(join(tdir, "graph.db"));
		// 预埋一条针对不存在/不在跑 step 的 steer（watcher 每 tick 都会收割到）
		const { appendSteer } = await import("../src/steer.js");
		appendSteer(tdir, "给已死 step 的插话", 999);
		const plannerEventsSeen: TriggerEvent[][] = [];
		const plannerStub = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			plannerEventsSeen.push(o.events);
			return { acceptedCount: 1, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		};
		const oneShot = makeScriptDeps(db, name, tdir, { workers: [{ summary: "正常完成的结论" }] });
		// worker 挂 100ms——保证第一个 watcher tick（20ms）落在在跑窗口内（竞态收割路径）
		const origOneShot = oneShot.runWorkerStep;
		const slowWorker = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			const r = await origOneShot(o);
			await sleep(100);
			return r;
		};
		await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			watchIntervalMs: 20,
			deps: { runWorkerStep: slowWorker, runPlanner: plannerStub },
		});
		const act = db.prepare("SELECT * FROM activity WHERE tool='steer'").all() as Array<{ is_error: number; summary: string }>;
		expect(act).toHaveLength(1);
		expect(act[0].is_error).toBe(1);
		expect(act[0].summary).toContain("丢弃");
		expect(plannerEventsSeen.every((evs) => evs.every((e) => e.type !== "steered"))).toBe(true);
		db.close();
	});

	it("P2F-5 锁：runTask 正常退出删锁；在跑时二次 run 被拒", async () => {
		const { name, tdir } = makeTask([{ summary: "锁场景的 step" }]);
		const db = openDb(join(tdir, "graph.db"));
		// 手挂一个活锁（当前进程 pid）模拟另一实例在跑
		mkdirSync(join(tdir, "control"), { recursive: true });
		writeFileSync(join(tdir, "control", "run.lock"), JSON.stringify({ pid: process.pid, started: "x" }));
		await expect(
			runTask({ tasksRoot: dir, taskName: name, config: CFG, secrets: {}, deps: { runWorkerStep: noopWorker, runPlanner: noopPlanner } }),
		).rejects.toThrow(/拒绝双开/);
		// 清掉活锁 → 正常跑完 → 锁被释放
		rmSync(join(tdir, "control", "run.lock"), { force: true });
		const deps = makeScriptDeps(db, name, tdir, { workers: [{ summary: "正常跑完的结论" }], plans: [[]] });
		await runTask({ tasksRoot: dir, taskName: name, config: CFG, secrets: {}, deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner } });
		expect(existsSync(join(tdir, "control", "run.lock"))).toBe(false);
		db.close();
	});
});

// ── 共用小件 ──

/** 立即返回的替身 worker（锁测试用——不该被调用到）。 */
async function noopWorker(o: RunWorkerStepOptions): Promise<RunWorkerStepResult> {
	return { stepId: o.step.id, finalText: "", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [], aborted: false };
}

/** 空 planner 替身（不派任何东西）。 */
async function noopPlanner(_o: RunPlannerOptions): Promise<RunPlannerResult> {
	return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
