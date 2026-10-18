/**
 * CLI（P2-3/P2-6 / p2fix P2F-5/11）：
 *   node dist/index.js run <task>     跑一个 task（调度循环：planner↔worker 直至终止）
 *   node dist/index.js graph <task>   打印图（人读格式）
 *   node dist/index.js hint <task> "文本"   操作员插话（调度层，下轮 planner 唤醒时收割）
 *   node dist/index.js steer <task> "文本"  操作员插话（执行层，定向在跑 step，秒级送达）
 *   node dist/index.js stop <task>    请求停止（watcher 秒级 abort + 优雅收尾）
 *
 * flag：--step=N（首步指定）、--mode=anthropic、--no-browser、--max-rounds=N、--budget-min=N
 */
import { join, dirname } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadTask } from "./task.js";
import { openDb } from "./db.js";
import { initTask, renderOverviewText } from "./graph.js";
import { runTask, clearControl, runLockPath } from "./scheduler.js";
import { appendHint } from "./hints.js";
import { appendSteer, currentRunningStep } from "./steer.js";
import { loadConfig } from "./config.js";
import { loadSecrets } from "./secrets.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS_ROOT = join(HERE, "..", "tasks");

function parseArgs(argv: string[]): { cmd: string; task?: string; rest: string[]; flags: Record<string, string | boolean> } {
	const [cmd, task, ...rest] = argv;
	const flags: Record<string, string | boolean> = {};
	for (const a of rest) {
		if (a.startsWith("--")) {
			const eq = a.indexOf("=");
			if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
			else flags[a.slice(2)] = true;
		}
	}
	return { cmd, task, rest, flags };
}

async function main(): Promise<number> {
	const { cmd, task, rest, flags } = parseArgs(process.argv.slice(2));
	switch (cmd) {
		case "run": {
			if (!task) throw new Error("用法：node dist/index.js run <task> [--max-rounds=N] [--budget-min=N]");
			const cfg = loadConfig();
			if (typeof flags["max-rounds"] === "string") cfg.run.maxRounds = Number(flags["max-rounds"]);
			if (typeof flags["budget-min"] === "string") cfg.run.budgetMs = Number(flags["budget-min"]) * 60_000;
			const result = await runTask({
				tasksRoot: TASKS_ROOT,
				taskName: task,
				config: cfg,
				stepTimeoutMs: flags["step-timeout-min"] ? Number(flags["step-timeout-min"]) * 60_000 : undefined,
			});
			console.log(`\n[run] 结束：reason=${result.reason} rounds=${result.rounds} workerSteps=${result.workerSteps} plannerWakeups=${result.plannerWakeups}`);
			// 终态打印图
			const { task: t, dbPath } = loadTask(TASKS_ROOT, task);
			const db = openDb(dbPath);
			console.log(renderOverviewText(db, t.name));
			db.close();
			return result.reason === "goal-achieved" || result.reason === "goal-closed" || result.reason === "control-stop" ? 0 : 1;
		}
		case "graph": {
			if (!task) throw new Error("用法：node dist/index.js graph <task>");
			const { task: t, dbPath } = loadTask(TASKS_ROOT, task);
			const db = openDb(dbPath);
			console.log(renderOverviewText(db, t.name));
			db.close();
			return 0;
		}
		case "hint": {
			if (!task || rest.length === 0) throw new Error('用法：node dist/index.js hint <task> "指示文本"');
			const { dir } = loadTask(TASKS_ROOT, task);
			appendHint(dir, rest.filter((r) => !r.startsWith("--")).join(" "));
			console.log(`[hint] 已写入 control/hints.jsonl——下轮 planner 唤醒时收割`);
			return 0;
		}
		case "steer": {
			// P2F-11：执行层插话，显式定向——无在跑 step 拒绝（不自动转 hint）
			if (!task || rest.length === 0) throw new Error('用法：node dist/index.js steer <task> "插话文本"（默认定向当前在跑 step）');
			const { task: t, dir, dbPath } = loadTask(TASKS_ROOT, task);
			const text = rest.filter((r) => !r.startsWith("--")).join(" ");
			const db = openDb(dbPath);
			let stepId = flags["step"] !== undefined ? Number(flags["step"]) : NaN;
			const running = currentRunningStep(db, t.name);
			db.close();
			if (!Number.isFinite(stepId)) {
				if (!running) {
					console.error(`[steer] 拒绝：当前无在跑 step——对调度层插话请用 hint（node dist/index.js hint <task> "..."）`);
					return 1;
				}
				stepId = running.id;
			}
			appendSteer(dir, text, stepId);
			console.log(`[steer] 已定向 step #${stepId}——watcher 秒级送达；steered 事件将随 step_done 进 planner`);
			return 0;
		}
		case "stop": {
			if (!task) throw new Error("用法：node dist/index.js stop <task>");
			const { dir } = loadTask(TASKS_ROOT, task);
			const { writeFileSync, mkdirSync } = await import("node:fs");
			mkdirSync(join(dir, "control"), { recursive: true });
			writeFileSync(join(dir, "control", "stop"), "cmd=stop\n", "utf-8");
			console.log(`[stop] control/stop 已置——watcher 秒级 abort 当前会话并优雅收尾`);
			// D10 第三层兜底提示：锁 pid 人工 kill（仅真僵死；不自动杀）
			const lockP = runLockPath(dir);
			if (existsSync(lockP)) {
				try {
					const lock = JSON.parse(readFileSync(lockP, "utf-8")) as { pid?: number };
					console.log(`[stop] 运行锁 pid=${lock.pid}——若进程真僵死（stop 秒级无响应），人工执行：taskkill /PID ${lock.pid} /T /F`);
				} catch {
					/* 锁损坏——忽略 */
				}
			} else {
				console.log(`[stop] 无运行锁——当前无 runTask 在跑（stop 信号已留档，下次 run 启动时清除）`);
			}
			return 0;
		}
		case "reset-stop": {
			if (!task) throw new Error("用法：node dist/index.js reset-stop <task>");
			const { dir } = loadTask(TASKS_ROOT, task);
			clearControl(dir);
			console.log(`[reset-stop] CONTROL 已清`);
			return 0;
		}
		case "init": {
			if (!task) throw new Error("用法：node dist/index.js init <task>");
			const { task: t, dbPath } = loadTask(TASKS_ROOT, task);
			const db = openDb(dbPath);
			const r = initTask(db, t);
			console.log(`[init] root goal #${r.rootGoalId}，steps: ${r.stepIds.join(", ") || "(无 seed)"}`);
			db.close();
			return 0;
		}
		default:
			console.log(`AT1 v4（P2 调度 + p2fix 版）
用法：
  run <task>               调度循环：planner↔worker 事件驱动直至 goal 证明/收尾/预算/停止
  graph <task>             打印任务图（人读）
  hint <task> "文本"        调度层插话（经 planner 转译，影响未来 step）
  steer <task> "文本"       执行层插话（定向当前在跑 step，秒级送达 worker）
  stop <task>              秒级优雅停止（watcher abort）；reset-stop <task> 清除
  init <task>              只初始化图（不跑）
flag：--max-rounds=N --budget-min=N --step-timeout-min=N --mode=anthropic --no-browser
task 定义：tasks/<name>/task.json（goal + scope.hosts + seed_steps[仅测试夹具]）`);
			return 0;
	}
}

main()
	.then((code) => process.exit(code))
	.catch((err) => {
		console.error("[cli] 失败：", err instanceof Error ? err.stack ?? err.message : err);
		process.exit(2);
	});
