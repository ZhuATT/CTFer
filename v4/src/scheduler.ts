/**
 * runTask 调度循环（P2-3，D1 拍板：单 worker，停/断/续做扎实）。
 *
 * 循环：终止检查（goal 证 / CONTROL stop / maxRounds / budgetMs）→ hints 收割
 * → 无 open step 唤醒 planner（全新会话）→ worker 领 step（priority desc, id asc）
 * → runWorkerStep → 触发事件 → 下轮。
 *
 * 停止 = CONTROL 文件轮边界优雅退出；中断 = SQLite 天然存活（无需代码）+
 * 启动清扫 running→exhausted；续跑 = 再敲 run（initTask 幂等 + 图状态即进度）。
 * 成本纪律：step 全 open/running 时不唤醒 planner（没空位）。
 */
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { Database } from "better-sqlite3";
import { loadTask, type TaskJson } from "./task.js";
import { openDb, logActivity, type NodeRow } from "./db.js";
import { goalAchieved, initTask, setStepState } from "./graph.js";
import { runWorkerStep } from "./agent.js";
import { runPlanner } from "./planner.js";
import { harvestHints } from "./hints.js";
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
	onEvent?: (ev: TriggerEvent) => void;
	/** 测试钩子：替身 worker/planner（mock 集成用，零 LLM）。 */
	deps?: {
		runWorkerStep?: typeof runWorkerStep;
		runPlanner?: typeof runPlanner;
	};
}

export interface RunTaskResult {
	reason: "goal-achieved" | "control-stop" | "max-rounds" | "budget-exhausted" | "planner-zero" | "no-open-step";
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

export async function runTask(opts: RunTaskOptions): Promise<RunTaskResult> {
	const { task, dir, dbPath } = loadTask(opts.tasksRoot, opts.taskName);
	const db: Database = openDb(dbPath);
	const cfg = opts.config ?? loadConfig();
	const deps = opts.deps ?? {};
	const doWorker = deps.runWorkerStep ?? runWorkerStep;
	const doPlanner = deps.runPlanner ?? runPlanner;
	const secrets = opts.secrets ?? loadSecrets();

	// 启动清扫（中断恢复语义）：v4 单进程，进程死 = 在跑全死，running 必是尸体
	db.prepare("UPDATE nodes SET state='exhausted', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE task_id=? AND kind='step' AND state='running'").run(task.name);

	const { stepIds, fresh } = initTask(db, task);
	const events: TriggerEvent[] = [];
	// 老图续跑（initTask 未新建）且图上不止 goal → resume 触发
	if (!fresh) {
		const nodeCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=?").get(task.name) as { n: number }).n;
		if (nodeCount > 1) events.push({ type: "resume", nodeCount });
	}

	clearControl(dir);
	const startedAt = Date.now();
	let round = 0;
	let workerSteps = 0;
	let plannerWakeups = 0;
	let reason: RunTaskResult["reason"] = "max-rounds";

	while (true) {
		round += 1;
		// ── 终止检查（轮边界） ──
		if (goalAchieved(db, task.name)) {
			reason = "goal-achieved";
			break;
		}
		if (readControlStop(dir)) {
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

		// ── hints 收割（操作员插话 → hint 触发） ──
		events.push(...harvestHints(dir));

		// ── planner 唤醒判定：无 open step 才唤醒（没空位不唤醒——成本纪律） ──
		let step = nextStep(db, task.name);
		if (!step) {
			plannerWakeups += 1;
			await doPlanner({
				db,
				task,
				taskDir: dir,
				events: [...events],
				channel: cfg.channels.planner,
				secrets,
				timeoutMs: opts.plannerTimeoutMs,
			});
			events.length = 0; // 触发已消费
			if (goalAchieved(db, task.name)) {
				reason = "goal-achieved";
				break;
			}
			step = nextStep(db, task.name);
			if (!step) {
				// planner 派 0（认定已覆盖/等依赖）且无 open——goal 未达的派 0 = 判停
				reason = "planner-zero";
				break;
			}
		}

		// ── worker 领 step 干活 ──
		setStepState(db, task.name, step.id, "running");
		const result = await doWorker({
			db,
			task: task as TaskJson,
			taskDir: dir,
			step,
			secrets,
			mode: cfg.channels.worker.api,
			timeoutMs: opts.stepTimeoutMs,
		});
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
	db.close();
	return { reason, rounds: round, workerSteps, plannerWakeups };
}
