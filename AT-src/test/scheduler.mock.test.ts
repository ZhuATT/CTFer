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

/** 卡T：mock 计时（测试固定值；真 worker 用单调时钟实测）。 */
const MOCK_TIMING = {
	queue_wait_ms: 0,
	worker_elapsed_ms: 1,
	cleanup_elapsed_ms: 0,
	started_at_utc: "2026-11-09T00:00:00Z",
	returned_at_utc: "2026-11-09T00:00:01Z",
	cleanup_end_utc: "2026-11-09T00:00:01Z",
};

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
			const timing: RunWorkerStepResult["timing"] = {
				queue_wait_ms: 0, worker_elapsed_ms: 1, cleanup_elapsed_ms: 0,
				started_at_utc: "2026-11-09T00:00:00Z", returned_at_utc: "2026-11-09T00:00:01Z", cleanup_end_utc: "2026-11-09T00:00:01Z",
			};
			const { recordStepExecution } = await import("../src/graph.js");
			const recordLe = (oc: "done" | "exhausted" | "blocked" | "incomplete", rs: string, refs: Array<{ kind: "fact" | "finding"; id: number; dedup: boolean }>) =>
				recordStepExecution(db, taskName, o.step.id, {
					session_id: "mock", outcome: oc, reason: rs, delivery_refs: refs, timing,
					finished_at: "2026-11-09T00:00:01Z",
				});
			if (s?.blocked) {
				// 卡C：传输层故障 → blocked/channel-error（真实 runWorkerStep 收尾语义）
				setStepState(db, taskName, o.step.id, "blocked");
				recordLe("blocked", "channel-error", []);
				return {
					stepId: o.step.id, finalText: "", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [],
					outcome: "blocked", reason: "channel-error", deliveries: [], sessionId: "mock", timing,
					aborted: false, transportError: "传输层故障[http 503]：mock",
				};
			}
			if (s?.summary) {
				writeFileSync(join(taskDir, "ev.txt"), "curl → 200 越权");
				const { submitFact } = await import("../src/graph.js");
				const r = submitFact(db, {
					taskId: taskName,
					taskDir,
					stepId: o.step.id,
					payload: { summary: s.summary, evidence: "ev.txt", confidence: "observed" },
				});
				// 卡C：mock 与真实 worker 同语义——成功交付必须真实 submit，outcome done/delivered
				const outcome = s.aborted ? ("exhausted" as const) : ("done" as const);
				const reason = s.aborted ? "operator-stop" : "delivered";
				setStepState(db, taskName, o.step.id, outcome); // 真实 runWorkerStep 收尾语义
				recordLe(outcome, reason, [{ kind: "fact", id: r.id, dedup: false }]);
				return {
					stepId: o.step.id, finalText: s.summary, usage: { ...MOCK_USAGE, turns: 2 },
					facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [],
					outcome, reason, deliveries: [{ kind: "fact", id: r.id, dedup: false }], sessionId: "mock", timing,
					aborted: s.aborted ?? false,
				};
			}
			// 无交付的正常结束：incomplete/no-delivery（11-9 §5.3 判定表第 6 行）
			const outcome = s?.aborted ? ("exhausted" as const) : ("incomplete" as const);
			const reason = s?.aborted ? "operator-stop" : "no-delivery";
			setStepState(db, taskName, o.step.id, outcome);
			recordLe(outcome, reason, []);
			return {
				stepId: o.step.id, finalText: "", usage: MOCK_USAGE,
				facts: 0, findings: 0, newFactIds: [], newFindingIds: [],
				outcome, reason, deliveries: [], sessionId: "mock", timing,
				aborted: s?.aborted ?? false,
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
			return {
				stepId: o.step.id, finalText: "被掐", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [],
				outcome: "exhausted", reason: "operator-stop", deliveries: [{ kind: "fact", id: r.id, dedup: false }],
				sessionId: "mock", timing: MOCK_TIMING, aborted: true,
			};
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
			return {
				stepId: o.step.id, finalText: "完成", usage: MOCK_USAGE, facts: 1, findings: 0, newFactIds: [r.id], newFindingIds: [],
				outcome: "done", reason: "delivered", deliveries: [{ kind: "fact", id: r.id, dedup: false }],
				sessionId: "mock", timing: MOCK_TIMING, aborted: false,
			};
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
	return {
		stepId: o.step.id, finalText: "", usage: MOCK_USAGE, facts: 0, findings: 0, newFactIds: [], newFindingIds: [],
		outcome: "incomplete", reason: "no-delivery", deliveries: [], sessionId: "mock", timing: MOCK_TIMING, aborted: false,
	};
}

/** 空 planner 替身（不派任何东西）。 */
async function noopPlanner(_o: RunPlannerOptions): Promise<RunPlannerResult> {
	return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ── 卡S（11-9 §6.2/§6.1）：熔断分流 + incomplete 接续 + last_execution 可见 ──

describe("卡S：熔断分流与 incomplete 可见性（零 LLM）", () => {
	it("熔断分流：blocked→incomplete→blocked→incomplete→blocked 中间不因 incomplete 清零，第 3 个 blocked 熔断", async () => {
		const { name, tdir } = makeTask([{ summary: "初始方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{ blocked: true }, {}, { blocked: true }, {}, { blocked: true }],
			plans: [
				[{ summary: "blocked 后重派一" }],
				[{ summary: "incomplete 后接续一" }],
				[{ summary: "blocked 后重派二" }],
				[{ summary: "incomplete 后接续二" }],
				[], // 第 5 次唤醒派 0，worker 领上一条续接单 → 第 3 个 blocked 触发熔断
			],
		});
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: deps.runWorkerStep, runPlanner: deps.runPlanner },
		});
		// incomplete 不当「通道修复成功」清零，也不加计数——第 3 个 blocked 才到阈值 3
		expect(result.reason).toBe("channel-down");
		expect(result.workerSteps).toBe(5);
		const blocked = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='step' AND state='blocked'").get() as { n: number };
		expect(blocked.n).toBe(3);
		db.close();
	});

	it("incomplete 接续：事件带 reason/交付引用；planner 派血缘续接单（parent_ids 挂原 step）；原 step 保留 incomplete；last_execution 入 payload 且 overview/人读图可见", async () => {
		const { name, tdir } = makeTask([{ summary: "空结束的探测方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = makeScriptDeps(db, name, tdir, {
			workers: [{}], // 无交付空结束 → incomplete/no-delivery
			plans: [],
		});
		let originalStepId = 0;
		// planner 收到 incomplete 后派血缘续接单
		const plannerWithLineage = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			const evs = o.events;
			const sd = evs.find((e) => e.type === "step_done") as { outcome: string; reason: string; deliveries: unknown[] } | undefined;
			expect(sd?.outcome).toBe("incomplete");
			expect(sd?.reason).toBe("no-delivery");
			expect(sd?.deliveries).toEqual([]);
			const { addStep } = await import("../src/graph.js");
			addStep(db, name, [{ summary: "接续：补齐空结束 step 的交付缺口", parent_ids: [originalStepId] }], "mock-planner");
			return { acceptedCount: 1, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		};
		const wrappedWorker = async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
			if (originalStepId === 0) originalStepId = o.step.id; // 只捕获首个（原 step）；续接单不覆盖
			return deps.runWorkerStep(o);
		};
		let planCalled = 0;
		const oneWakePlanner = async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
			planCalled += 1;
			if (planCalled === 1) return plannerWithLineage(o);
			return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
		};
		const result = await runTask({
			tasksRoot: dir, taskName: name, config: CFG, secrets: {},
			deps: { runWorkerStep: wrappedWorker, runPlanner: oneWakePlanner },
		});
		expect(result.reason).toBe("planner-zero");
		// 原 step 保留 incomplete（不改成 open 重跑）
		const orig = db.prepare("SELECT state FROM nodes WHERE id=?").get(originalStepId) as { state: string };
		expect(orig.state).toBe("incomplete");
		// 续接单有 derives_from 血缘边
		const edge = db.prepare("SELECT * FROM edges WHERE src_id=? AND rel='derives_from'").get(originalStepId);
		expect(edge).toBeDefined();
		// last_execution 持久化（卡S/§6.1）
		const payload = JSON.parse((db.prepare("SELECT payload FROM nodes WHERE id=?").get(originalStepId) as { payload: string }).payload) as {
			last_execution?: { outcome: string; reason: string; session_id: string };
		};
		expect(payload.last_execution?.outcome).toBe("incomplete");
		expect(payload.last_execution?.reason).toBe("no-delivery");
		expect(payload.last_execution?.session_id).toContain("mock");
		// graphOverview / 人读图可见（卡S：人读面一致）
		const { graphOverview, renderOverviewText } = await import("../src/graph.js");
		const overview = graphOverview(db, name);
		const le = overview.steps.find((s) => s.id === originalStepId)?.last_execution;
		expect(le).toMatchObject({ outcome: "incomplete", reason: "no-delivery", deliveries: 0 });
		expect(renderOverviewText(db, name)).toContain("最近执行: incomplete/no-delivery");
		db.close();
	});
});

// ── R-A（11-9 §13.2）：scheduler 异常兜底补写 last_execution（重开库验证持久化） ──

describe("R-A：worker throw / 无 result 兜底持久化", () => {
	/** 断言兜底面（库状态/completed_at/事件/activity 关联/last_execution/overview），供重开库前后各跑一次。 */
	async function assertFallbackFace(db: Database, name: string, stepId: number, plannerEvents: Array<unknown[]>) {
		const { graphOverview, renderOverviewText } = await import("../src/graph.js");
		// 库状态 + completed_at（blocked 属收尾态）
		const row = db.prepare("SELECT state, completed_at FROM nodes WHERE id=?").get(stepId) as { state: string; completed_at: string | null };
		expect(row.state).toBe("blocked");
		expect(row.completed_at).toBeTruthy();
		// 事件 outcome/reason：planner 收到 blocked/worker-error，不被重算
		const all = plannerEvents.flat();
		const ev = all.find((e) => (e as { type: string }).type === "step_done") as { outcome: string; reason: string };
		expect(ev.outcome).toBe("blocked");
		expect(ev.reason).toBe("worker-error");
		// activity 兜底账：session_id 明确标识 scheduler-fallback，与 last_execution 同 ID
		const act = db.prepare("SELECT * FROM activity WHERE tool='runWorkerStep' AND is_error=1").get() as {
			session_id: string; node_id: number; summary: string;
		};
		expect(act.session_id).toMatch(/^scheduler-fallback-s\d+-\d+$/);
		expect(act.node_id).toBe(stepId);
		expect(act.summary).toContain("构造/执行异常");
		// last_execution：blocked/worker-error；不编造 stopReason/timing/交付
		const payload = JSON.parse((db.prepare("SELECT payload FROM nodes WHERE id=?").get(stepId) as { payload: string }).payload) as {
			last_execution?: { outcome: string; reason: string; session_id: string; stop_reason?: string; timing?: unknown; delivery_refs: unknown[] };
		};
		expect(payload.last_execution?.outcome).toBe("blocked");
		expect(payload.last_execution?.reason).toBe("worker-error");
		expect(payload.last_execution?.session_id).toBe(act.session_id); // 同一次兜底同关联 ID
		expect(payload.last_execution?.stop_reason).toBeUndefined(); // 无可靠 stopReason 就省略，不编造
		expect(payload.last_execution?.timing).toBeUndefined(); // 无真实计时就省略，不编 0 耗时
		expect(payload.last_execution?.delivery_refs).toEqual([]); // 兜底没拿到回执 ≠ 无已有 fact
		// overview / 人读图一致
		const le = graphOverview(db, name).steps.find((s) => s.id === stepId)?.last_execution;
		expect(le).toMatchObject({ outcome: "blocked", reason: "worker-error" });
		expect(renderOverviewText(db, name)).toContain("最近执行: blocked/worker-error");
	}

	it("worker throw → blocked/worker-error + last_execution 兜底落库；关闭重开数据库后仍可见（非仅内存）", async () => {
		const { name, tdir } = makeTask([{ summary: "异常兜底验证的方向" }]);
		const dbPath = join(tdir, "graph.db");
		const db = openDb(dbPath);
		const plannerEvents: Array<unknown[]> = [];
		const deps = {
			runPlanner: async (o: RunPlannerOptions): Promise<RunPlannerResult> => {
				plannerEvents.push([...o.events]);
				return { acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" };
			},
			runWorkerStep: async (): Promise<RunWorkerStepResult> => {
				throw new Error("[R-A] simulated construction crash");
			},
		};
		await runTask({ tasksRoot: dir, taskName: name, config: CFG, secrets: {}, deps });
		const stepId = (db.prepare("SELECT id FROM nodes WHERE kind='step' ORDER BY id LIMIT 1").get() as { id: number }).id;
		await assertFallbackFace(db, name, stepId, plannerEvents);
		db.close();

		// 关闭并重开数据库：last_execution/状态/审计均持久可见（不是仅内存）
		const db2 = openDb(dbPath);
		await assertFallbackFace(db2, name, stepId, plannerEvents);
		db2.close();
	});

	it("worker 返回 undefined（坏实现）→ 同兜底语义：blocked/worker-error + last_execution，不 done", async () => {
		const { name, tdir } = makeTask([{ summary: "无 result 替身的方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = {
			runPlanner: async (): Promise<RunPlannerResult> => ({ acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" }),
			// 测试强制模拟坏实现：正常类型下不可能返回 undefined（仅测试内绕过类型）
			runWorkerStep: (async (): Promise<RunWorkerStepResult> => undefined as unknown as RunWorkerStepResult) as typeof import("../src/agent.js").runWorkerStep,
		};
		await runTask({ tasksRoot: dir, taskName: name, config: CFG, secrets: {}, deps });
		const stepId = (db.prepare("SELECT id FROM nodes WHERE kind='step' ORDER BY id LIMIT 1").get() as { id: number }).id;
		const payload = JSON.parse((db.prepare("SELECT payload FROM nodes WHERE id=?").get(stepId) as { payload: string }).payload) as {
			last_execution?: { outcome: string; reason: string };
		};
		const state = (db.prepare("SELECT state FROM nodes WHERE id=?").get(stepId) as { state: string }).state;
		expect(state).toBe("blocked");
		expect(payload.last_execution?.outcome).toBe("blocked");
		expect(payload.last_execution?.reason).toBe("worker-error");
		db.close();
	});

	it("已有 fact 后 throw → 旧产出保留、仍 blocked 不算 done；delivery_refs=[] 不回滚已有提交", async () => {
		const { name, tdir } = makeTask([{ summary: "部分产出后异常的方向" }]);
		const db = openDb(join(tdir, "graph.db"));
		const deps = {
			runPlanner: async (): Promise<RunPlannerResult> => ({ acceptedCount: 0, rejectedCount: 0, proved: false, usage: MOCK_USAGE, finalText: "" }),
			runWorkerStep: async (o: RunWorkerStepOptions): Promise<RunWorkerStepResult> => {
				// 先真实提交一条 fact（部分产出），随后 worker 崩溃
				writeFileSync(join(tdir, "ev.txt"), "curl → 200 越权");
				const { submitFact } = await import("../src/graph.js");
				submitFact(db, {
					taskId: name, taskDir: tdir, stepId: o.step.id,
					payload: { summary: "异常前已确认的部分产出", evidence: "ev.txt", confidence: "observed" },
				});
				throw new Error("[R-A] crash after partial delivery");
			},
		};
		await runTask({ tasksRoot: dir, taskName: name, config: CFG, secrets: {}, deps });
		const stepId = (db.prepare("SELECT id FROM nodes WHERE kind='step' ORDER BY id LIMIT 1").get() as { id: number }).id;
		// 旧产出保留
		const fact = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='fact'").get() as { n: number };
		expect(fact.n).toBe(1);
		// 状态 blocked 非 done；last_execution 交付引用为空（兜底没拿到回执），但不删除已有 fact
		const row = db.prepare("SELECT state, payload FROM nodes WHERE id=?").get(stepId) as { state: string; payload: string };
		expect(row.state).toBe("blocked");
		const le = (JSON.parse(row.payload) as { last_execution?: { outcome: string; delivery_refs: unknown[] } }).last_execution;
		expect(le?.outcome).toBe("blocked");
		expect(le?.delivery_refs).toEqual([]);
		db.close();
	});
});
