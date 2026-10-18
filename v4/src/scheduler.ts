/**
 * runTask 调度循环（P2-3 / p2fix P2F-5/6/11）。
 *
 * 唤醒 = 方案 C 全面事件驱动（D6）：每轮收割事件（step_done/finding/hint/steered/resume）
 * 后，有新事件 → 先唤醒 planner 消费再领 step；空事件且有 open step → 直接 worker 不唤醒
 * （成本纪律）。planner-zero 判定保留：唤醒后仍无 open step 且 goal 未达 → 判停。
 *
 * 停止三层（D10）：①control/stop 信号文件（意图声明）②进程内 watcher 1.5s 盯盘 →
 * abort 当前会话（与 stepTimeout 同一条优雅收尾路：step 落 exhausted、产出保留）→
 * 循环以 control-stop 退出 ③run.lock pid 人工 kill（仅真僵死，不自动杀）。
 *
 * run.lock（D3）：启动互斥——活锁拒双开（tasklist 校验镜像名防 PID 回收误判）、
 * 死锁覆写接管、finally 删锁。
 *
 * steer（D11/P2F-11）：watcher 第二信号源——新 steer 行且目标在跑 → agent.steer() 送达
 * + steered 事件给 planner；目标不在跑（竞态）→ 丢弃 + activity 兜底。
 *
 * 中断 = SQLite 天然存活 + 启动清扫 running→exhausted；续跑 = 再敲 run（initTask 幂等）。
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import type { Database } from "better-sqlite3";
import { loadTask, type TaskJson } from "./task.js";
import { logActivity, openDb, type NodeRow } from "./db.js";
import { goalAchieved, goalClosed, initTask, setStepState } from "./graph.js";
import { runWorkerStep, type SteerableTarget } from "./agent.js";
import { runPlanner } from "./planner.js";
import { harvestHints } from "./hints.js";
import { harvestSteers, renderSteerMessage } from "./steer.js";
import { stepDoneEvent, type TriggerEvent } from "./triggers.js";
import { loadConfig, type AppConfig } from "./config.js";
import { loadSecrets, type Secrets } from "./secrets.js";

export interface RunTaskOptions {
	tasksRoot: string;
	taskName: string;
	config?: AppConfig;
	secrets?: Secrets;
	stepTimeoutMs?: number;
	plannerTimeoutMs?: number;
	/** watcher 轮询间隔（默认 1500ms；测试可调小）。 */
	watchIntervalMs?: number;
	onEvent?: (ev: TriggerEvent) => void;
	/** 测试钩子：替身 worker/planner（mock 集成用，零 LLM）。 */
	deps?: {
		runWorkerStep?: typeof runWorkerStep;
		runPlanner?: typeof runPlanner;
	};
}

export interface RunTaskResult {
	reason: "goal-achieved" | "goal-closed" | "control-stop" | "max-rounds" | "budget-exhausted" | "planner-zero";
	rounds: number;
	workerSteps: number;
	plannerWakeups: number;
}

/** 领下一条 step：priority desc, id asc（高价值链路优先）。 */
export function nextStep(db: Database, taskId: string): NodeRow | undefined {
	return db
		.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='step' AND state='open' ORDER BY priority DESC, id ASC LIMIT 1")
		.get(taskId) as NodeRow | undefined;
}

/** stop 信号文件：control/stop（施工卡的"task 目录 CONTROL 文件"落位到 control/
 * 目录下——Windows 大小写不敏感，与 hints 的 control/ 目录同名冲突，实抓修正）。 */
export function controlStopPath(taskDir: string): string {
	return join(taskDir, "control", "stop");
}

export function readControlStop(taskDir: string): boolean {
	const p = controlStopPath(taskDir);
	if (!existsSync(p)) return false;
	try {
		return readFileSync(p, "utf-8").trim().toLowerCase().includes("stop");
	} catch {
		return false;
	}
}

export function clearControl(taskDir: string): void {
	try {
		rmSync(controlStopPath(taskDir), { force: true });
	} catch {
		/* 无所谓 */
	}
}

// ── run.lock（p2fix P2F-5，D3：canary 实锤双开 38 秒重叠） ──

export function runLockPath(taskDir: string): string {
	return join(taskDir, "control", "run.lock");
}

/** pid 是否活着的 node 进程（锁校验用）。Windows 走 tasklist 校验镜像名——
 * 防 PID 回收误判（死进程 pid 被非 node 进程复用 ≠ 前一个 run 还活着）。 */
export function isNodePidAlive(pid: number): boolean {
	if (!Number.isFinite(pid) || pid <= 0) return false;
	try {
		if (process.platform === "win32") {
			const out = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, {
				encoding: "utf-8",
				timeout: 5000,
				windowsHide: true,
			});
			return /"?node\.exe"?/i.test(out);
		}
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

/** 取锁：活锁拒（报 pid）；死锁/损坏锁覆写接管。 */
export function acquireRunLock(taskDir: string): { pid: number; started: string } {
	const p = runLockPath(taskDir);
	mkdirSync(dirname(p), { recursive: true });
	if (existsSync(p)) {
		let prev: { pid?: number } = {};
		try {
			prev = JSON.parse(readFileSync(p, "utf-8")) as { pid?: number };
		} catch {
			/* 损坏锁 → 接管 */
		}
		const pid = Number(prev.pid);
		if (isNodePidAlive(pid)) {
			throw new Error(
				`已有运行中的调度进程 pid=${pid}，拒绝双开。` +
					`确认真僵死后：taskkill /PID ${pid} /T /F，然后重跑（锁会被接管）。`,
			);
		}
	}
	const lock = { pid: process.pid, started: new Date().toISOString() };
	writeFileSync(p, JSON.stringify(lock), "utf-8");
	return lock;
}

/** 释放锁：只删自己持有的（接管竞态保护——不误删后来者的锁）。 */
export function releaseRunLock(taskDir: string): void {
	const p = runLockPath(taskDir);
	try {
		const cur = JSON.parse(readFileSync(p, "utf-8")) as { pid?: number };
		if (Number(cur.pid) === process.pid) rmSync(p, { force: true });
	} catch {
		/* 锁不在了，无所谓 */
	}
}

// ── runTask ──

export async function runTask(opts: RunTaskOptions): Promise<RunTaskResult> {
	const { task, dir, dbPath } = loadTask(opts.tasksRoot, opts.taskName);
	const db: Database = openDb(dbPath);
	const cfg = opts.config ?? loadConfig();
	const deps = opts.deps ?? {};
	const doWorker = deps.runWorkerStep ?? runWorkerStep;
	const doPlanner = deps.runPlanner ?? runPlanner;
	const secrets = opts.secrets ?? loadSecrets();

	acquireRunLock(dir);
	const runAbort = new AbortController();
	let stopRequested = false;
	const watcher = setInterval(() => {
		try {
			if (!stopRequested && readControlStop(dir)) {
				stopRequested = true;
				runAbort.abort(); // D10：与 stepTimeout 同一条优雅收尾路
				return;
			}
			if (!stopRequested) deliverPendingSteers();
		} catch {
			/* watcher 单拍失败不带走循环 */
		}
	}, opts.watchIntervalMs ?? 1500);

	// steer 消费（P2F-11）：目标在跑 → agent.steer + steered 事件；不在跑 → 丢弃+兜底账
	let runningStepId: number | undefined;
	let currentAgent: SteerableTarget | undefined;
	function deliverPendingSteers(): void {
		for (const s of harvestSteers(dir)) {
			if (runningStepId !== undefined && s.stepId === runningStepId && currentAgent) {
				currentAgent.steer({ role: "user", content: renderSteerMessage(s.text), timestamp: Date.now() });
				events.push({ type: "steered", text: s.text, stepId: s.stepId });
				logActivity(db, {
					task_id: task.name,
					node_id: s.stepId,
					worker: "operator",
					kind: "result",
					tool: "steer",
					summary: `steer 送达在跑 step #${s.stepId}`,
					detail: s.text.slice(0, 1000),
				});
			} else {
				logActivity(db, {
					task_id: task.name,
					worker: "operator",
					kind: "result",
					tool: "steer",
					is_error: true,
					summary: `steer 目标 step #${s.stepId} 不在跑，已丢弃（调度层插话请用 hint）`,
					detail: s.text.slice(0, 500),
				});
			}
		}
	}

	let reason: RunTaskResult["reason"] = "max-rounds";
	let round = 0;
	let workerSteps = 0;
	let plannerWakeups = 0;
	const events: TriggerEvent[] = [];

	try {
		// 启动清扫（中断恢复语义）：v4 单进程，进程死 = 在跑全死，running 必是尸体
		db.prepare(
			"UPDATE nodes SET state='exhausted', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE task_id=? AND kind='step' AND state='running'",
		).run(task.name);

		const { stepIds: _stepIds, fresh } = initTask(db, task);
		// 老图续跑（initTask 未新建）且图上不止 goal → resume 触发
		if (!fresh) {
			const nodeCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=?").get(task.name) as { n: number }).n;
			if (nodeCount > 1) events.push({ type: "resume", nodeCount });
		}

		clearControl(dir);
		const startedAt = Date.now();

		while (true) {
			round += 1;
			// ── 终止检查（轮边界） ──
			if (goalAchieved(db, task.name)) {
				reason = "goal-achieved";
				break;
			}
			if (goalClosed(db, task.name)) {
				reason = "goal-closed";
				break;
			}
			if (stopRequested || readControlStop(dir)) {
				reason = "control-stop";
				break;
			}
			if (round > cfg.run.maxRounds) {
				reason = "max-rounds";
				break;
			}
			if (Date.now() - startedAt > cfg.run.budgetMs) {
				reason = "budget-exhausted";
				break;
			}

			// ── hints 收割（操作员调度层插话 → hint 触发） ──
			events.push(...harvestHints(dir));

			// ── 唤醒判定（方案 C，D6）：有新事件先让 planner 消费；空事件且有 open step 直接 worker ──
			let step = nextStep(db, task.name);
			if (events.length > 0 || !step) {
				plannerWakeups += 1;
				await doPlanner({
					db,
					task,
					taskDir: dir,
					events: [...events],
					channel: cfg.channels.planner,
					secrets,
					timeoutMs: opts.plannerTimeoutMs,
					abortSignal: runAbort.signal,
				});
				events.length = 0; // 触发已消费（steered 事件随本批进 planner）
				if (goalAchieved(db, task.name)) {
					reason = "goal-achieved";
					break;
				}
				if (goalClosed(db, task.name)) {
					reason = "goal-closed";
					break;
				}
				step = nextStep(db, task.name);
				if (!step) {
					// planner 派 0（认定已覆盖/等依赖）且无 open——goal 未达的派 0 = 判停
					reason = "planner-zero";
					break;
				}
				if (stopRequested) {
					// stop 在 planner 唤醒期间到达：不再开新活
					reason = "control-stop";
					break;
				}
			}

			// ── worker 领 step 干活 ──
			setStepState(db, task.name, step.id, "running");
			runningStepId = step.id;
			const result = await doWorker({
				db,
				task: task as TaskJson,
				taskDir: dir,
				step,
				secrets,
				channel: cfg.channels.worker,
				timeoutMs: opts.stepTimeoutMs,
				abortSignal: runAbort.signal,
				onAgent: (a) => {
					currentAgent = a;
				},
			});
			runningStepId = undefined;
			currentAgent = undefined;
			workerSteps += 1;
			const outcome = result.aborted ? "exhausted" : "done";
			events.push(
				stepDoneEvent(step, outcome, result.newFactIds, result.newFindingIds, result.finalText),
			);
			for (const fid of result.newFindingIds) {
				const f = db.prepare("SELECT payload FROM nodes WHERE task_id=? AND id=?").get(task.name, fid) as
					| { payload: string }
					| undefined;
				if (f) {
					const p = JSON.parse(f.payload) as { summary: string; severity?: string };
					events.push({ type: "finding", findingId: fid, severity: String(p.severity ?? "?"), summary: p.summary });
				}
			}
		}

		logActivity(db, {
			task_id: task.name,
			worker: "scheduler",
			kind: "result",
			tool: "runTask",
			summary: `run 结束：reason=${reason} rounds=${round} workerSteps=${workerSteps} plannerWakeups=${plannerWakeups}`,
		});
	} finally {
		clearInterval(watcher);
		releaseRunLock(dir);
		db.close();
	}
	return { reason, rounds: round, workerSteps, plannerWakeups };
}
