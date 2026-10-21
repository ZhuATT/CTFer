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
import { existsSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import type { Database } from "better-sqlite3";
import { loadTask, type TaskJson } from "./task.js";
import { logActivity, openDb, type NodeRow } from "./db.js";
import { goalAchieved, goalClosed, initTask, setStepState } from "./graph.js";
import { runWorkerStep, type SteerableTarget, type RunWorkerStepResult } from "./agent.js";
import { runPlanner } from "./planner.js";
import { harvestHints } from "./hints.js";
import { harvestSteers, renderSteerMessage } from "./steer.js";
import { stepDoneEvent, type TriggerEvent } from "./triggers.js";
import { loadConfig, type AppConfig } from "./config.js";
import { loadSecrets, type Secrets } from "./secrets.js";
import { openAssetsDb, resolveScopeHosts } from "./assets.js";
import { buildProjectBriefing, renderProjectBriefing } from "./briefing.js";

export interface RunTaskOptions {
	tasksRoot: string;
	taskName: string;
	config?: AppConfig;
	secrets?: Secrets;
	stepTimeoutMs?: number;
	plannerTimeoutMs?: number;
	/** watcher 轮询间隔（默认 1500ms；测试可调小）。 */
	watchIntervalMs?: number;
	/** P3-10：浏览器池降级开关（preflight D 失败 + 人工确认降级 → false——worker 不起浏览器）。缺省 true。 */
	browser?: boolean;
	onEvent?: (ev: TriggerEvent) => void;
	/** 测试钩子：替身 worker/planner（mock 集成用，零 LLM）。 */
	deps?: {
		runWorkerStep?: typeof runWorkerStep;
		runPlanner?: typeof runPlanner;
	};
}

export interface RunTaskResult {
	reason:
		| "goal-achieved"
		| "goal-closed"
		| "control-stop"
		| "max-rounds"
		| "budget-exhausted"
		| "planner-zero"
		| "channel-down"
		| "planner-error";
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
	const { task, dir, dbPath, assetsDbPath } = loadTask(opts.tasksRoot, opts.taskName);
	const db: Database = openDb(dbPath);
	let assetsDb: Database | undefined;
	if (assetsDbPath) {
		assetsDb = openAssetsDb(assetsDbPath);
	}
	const cfg = opts.config ?? loadConfig();
	const deps = opts.deps ?? {};
	const doWorker = deps.runWorkerStep ?? runWorkerStep;
	const doPlanner = deps.runPlanner ?? runPlanner;
	const secrets = opts.secrets ?? loadSecrets();

	acquireRunLock(dir);
	const runAbort = new AbortController();
	let stopRequested = false;
	const scopeSet = new Set<string>(task.scope.hosts.map((h) => h.toLowerCase()));

	// P3-2：资产库在场时初始化 scope 资产（origin=operator，幂等）
	if (assetsDb) {
		resolveScopeHosts(assetsDb, task.name, task.scope.hosts, task.project ?? "default");
	}

	const watcher = setInterval(() => {
		try {
			if (!stopRequested && readControlStop(dir)) {
				stopRequested = true;
				runAbort.abort(); // D10：与 stepTimeout 同一条优雅收尾路
				return;
			}
			if (!stopRequested) {
				deliverPendingSteers();
				checkScopeChanged();
			}
		} catch {
			/* watcher 单拍失败不带走循环 */
		}
	}, opts.watchIntervalMs ?? 1500);

	// P3-7：scope-add 扩权信号消费（control/scope.changed）
	function checkScopeChanged(): void {
		const sigPath = join(dir, "control", "scope.changed");
		if (!existsSync(sigPath)) return;
		try {
			const jsonPath = join(dir, "task.json");
			if (existsSync(jsonPath)) {
				const parsed = JSON.parse(readFileSync(jsonPath, "utf-8")) as { scope?: { hosts?: string[] } };
				const currentHosts = parsed.scope?.hosts ?? [];
				const added: string[] = [];
				for (const h of currentHosts) {
					const lower = h.toLowerCase();
					if (!scopeSet.has(lower)) {
						scopeSet.add(lower);
						added.push(h);
					}
				}
				if (assetsDb && added.length > 0) {
					resolveScopeHosts(assetsDb, task.name, added, task.project ?? "default");
				}
				if (added.length > 0) {
					events.push({ type: "scope_changed", added });
					logActivity(db, {
						task_id: task.name,
						worker: "operator",
						kind: "result",
						tool: "scope-add",
						summary: `操作员扩权：新增 ${added.join(", ")}`,
					});
				}
			}
		} finally {
			try {
				unlinkSync(sigPath);
			} catch {
				/* 忽略删信号文件异常 */
			}
		}
	}

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
	// P3pre-2 熔断计数：连续 blocked step 计数，成功 worker step 清零。
	// 注意 planner 唤醒成功**不**清零——分通道场景（planner 活着、worker 通道死）里
	// 若唤醒即清零，熔断永远到不了阈值，空泡烧轮数照旧；熔断语义 = 连续 3 个
	// worker step 没真正探成。阈值 cfg.run.circuitBreaker（默认 3）。
	let consecutiveBlocked = 0;
	const breakerThreshold = cfg.run.circuitBreaker ?? 3;

	try {
		// 启动清扫（中断恢复语义）：v4 单进程，进程死 = 在跑全死，running 必是尸体
		db.prepare(
			"UPDATE nodes SET state='exhausted', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE task_id=? AND kind='step' AND state='running'",
		).run(task.name);

		const { stepIds: _stepIds, fresh, goalChanged } = initTask(db, task);
		// P3-8：reopen 触发目标变更
		if (goalChanged) {
			events.push({ type: "goal_changed", action: "edited", text: task.goal });
		}
		// 老图续跑（initTask 未新建）且图上不止 goal → resume 触发
		if (!fresh) {
			const nodeCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=?").get(task.name) as { n: number }).n;
			if (nodeCount > 1) events.push({ type: "resume", nodeCount });
		}

		// P3-6：项目简报（fresh 且有 project 且 assetsDb 在场时首轮注入）
		let briefingText: string | undefined;
		if (fresh && task.project && assetsDb) {
			const briefing = buildProjectBriefing(opts.tasksRoot, task.project, task.name, assetsDb);
			briefingText = renderProjectBriefing(briefing);
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
				// P3pre-3（D3）：唤醒失败（抛错/传输层故障）→ 同一批事件重试 1 次 → 仍败终止。
				// 事件数组只在成功后清空——失败终止时事件未消费（进程死则丢内存 delta，
				// 但图上状态都在，续跑 resume 即恢复）。
				// P3pre-6 ② 卫生修（splice）：只消费当前快照前缀，await 期间 watcher 新推入事件留给下轮
				const snapshotLen = events.length;
				const snapshotEvents = events.slice(0, snapshotLen);
				let plannerFailure: string | undefined;
				try {
					const pr = await doPlanner({
						db,
						task,
						taskDir: dir,
						events: snapshotEvents,
						channel: cfg.channels.planner,
						secrets,
						timeoutMs: opts.plannerTimeoutMs,
						abortSignal: runAbort.signal,
						assetsDb,
						briefingText,
					});
					briefingText = undefined; // P3-6：首轮一次性注入，后续唤醒不带
					plannerFailure = pr.transportError;
				} catch (err) {
					plannerFailure = err instanceof Error ? err.message : String(err);
				}
				if (plannerFailure) {
					logActivity(db, {
						task_id: task.name,
						worker: "scheduler",
						kind: "result",
						tool: "runPlanner",
						is_error: true,
						summary: `planner 唤醒失败，重试 1 次：${plannerFailure.slice(0, 300)}`,
					});
					let retryFailure: string | undefined;
					try {
						const pr = await doPlanner({
							db,
							task,
							taskDir: dir,
							events: snapshotEvents,
							channel: cfg.channels.planner,
							secrets,
							timeoutMs: opts.plannerTimeoutMs,
							abortSignal: runAbort.signal,
							assetsDb,
						});
						retryFailure = pr.transportError;
					} catch (err) {
						retryFailure = err instanceof Error ? err.message : String(err);
					}
					if (retryFailure) {
						logActivity(db, {
							task_id: task.name,
							worker: "scheduler",
							kind: "result",
							tool: "runPlanner",
							is_error: true,
							summary: `planner 重试仍失败 → 终止（reason=planner-error），事件未消费续跑自动恢复：${retryFailure.slice(0, 300)}`,
						});
						reason = "planner-error";
						break;
					}
				}
				events.splice(0, snapshotLen); // 触发已消费（P3pre-6 ② 卫生修：只清前缀，保留 await 期间新到事件）
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
			let result: RunWorkerStepResult | undefined;
			let workerError: string | undefined;
			try {
				result = await doWorker({
					db,
					task: task as TaskJson,
					taskDir: dir,
					step,
					secrets,
					channel: cfg.channels.worker,
					timeoutMs: opts.stepTimeoutMs,
					abortSignal: runAbort.signal,
					assetsDb,
					browser: opts.browser,
					scopeHosts: scopeSet,
					onAgent: (a) => {
						currentAgent = a;
					},
				});
			} catch (err) {
				workerError = err instanceof Error ? err.message : String(err);
			} finally {
				runningStepId = undefined;
				currentAgent = undefined;
			}
			workerSteps += 1;

			// P3pre-6 ①：worker 构造/执行异常兜底（keyEnv 错、payload 坏、BrowserPool 挂等），step 落 blocked + 接熔断
			if (workerError || !result) {
				const rawErr = workerError ?? "未知 worker 异常";
				setStepState(db, task.name, step.id, "blocked");
				logActivity(db, {
					task_id: task.name,
					node_id: step.id,
					worker: "scheduler",
					kind: "result",
					tool: "runWorkerStep",
					is_error: true,
					summary: `step #${step.id} 构造/执行异常：${rawErr.slice(0, 300)}`,
					detail: rawErr.slice(0, 1000),
				});
				consecutiveBlocked += 1;
				events.push(stepDoneEvent(step, "blocked", [], [], ""));
				if (consecutiveBlocked >= breakerThreshold) {
					logActivity(db, {
						task_id: task.name,
						worker: "scheduler",
						kind: "result",
						tool: "runTask",
						is_error: true,
						summary: `熔断终止：连续 ${consecutiveBlocked} 个 step 传输层故障（threshold=${breakerThreshold}），最后：${rawErr.slice(0, 300)}`,
					});
					reason = "channel-down";
					break;
				}
				continue;
			}
			// P3pre-2 收尾三态：aborted→exhausted｜传输层故障→blocked｜else done
			const outcome = result.aborted ? "exhausted" : result.transportError ? "blocked" : "done";
			consecutiveBlocked = outcome === "blocked" ? consecutiveBlocked + 1 : 0;
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

			// P3pre-2 熔断（D2）：连续 blocked ≥ 阈值 → 终止防空泡烧轮数；修复通道后重跑即续
			if (consecutiveBlocked >= breakerThreshold) {
				logActivity(db, {
					task_id: task.name,
					worker: "scheduler",
					kind: "result",
					tool: "runTask",
					is_error: true,
					summary: `熔断终止：连续 ${consecutiveBlocked} 个 step 传输层故障（threshold=${breakerThreshold}），最后：${String(result.transportError).slice(0, 300)}`,
				});
				reason = "channel-down";
				break;
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
		assetsDb?.close();
	}
	return { reason, rounds: round, workerSteps, plannerWakeups };
}
