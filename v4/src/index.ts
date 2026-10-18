/**
 * CLI（P2-3/P2-6）：
 *   node dist/index.js run <task>     跑一个 task（调度循环：planner↔worker 直至终止）
 *   node dist/index.js graph <task>   打印图（人读格式）
 *   node dist/index.js hint <task> "文本"   操作员插话（下轮 planner 唤醒时收割）
 *   node dist/index.js stop <task>    请求停止（轮边界优雅退出）
 *
 * flag：--step=N（首步指定）、--mode=anthropic、--no-browser、--max-rounds=N、--budget-min=N
 */
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadTask } from "./task.js";
import { openDb } from "./db.js";
import { initTask, renderOverviewText } from "./graph.js";
import { runTask, clearControl } from "./scheduler.js";
import { appendHint } from "./hints.js";
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
			return result.reason === "goal-achieved" || result.reason === "control-stop" ? 0 : 1;
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
			if (!task || rest.length === 0) throw new Error("用法：node dist/index.js hint <task> \"指示文本\"");
			const { dir } = loadTask(TASKS_ROOT, task);
			appendHint(dir, rest.filter((r) => !r.startsWith("--")).join(" "));
			console.log(`[hint] 已写入 control/hints.jsonl——下轮 planner 唤醒时收割`);
			return 0;
		}
		case "stop": {
			if (!task) throw new Error("用法：node dist/index.js stop <task>");
			const { dir } = loadTask(TASKS_ROOT, task);
			const { writeFileSync, mkdirSync } = await import("node:fs");
			mkdirSync(join(dir, "control"), { recursive: true });
			writeFileSync(join(dir, "control", "stop"), "cmd=stop\n", "utf-8");
			console.log(`[stop] control/stop 已置——runTask 将在当前轮完成后优雅退出`);
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
			console.log(`AT1 v4（P2 调度版）
用法：
  run <task>               调度循环：planner↔worker 直至 goal 证明/预算/停止
  graph <task>             打印任务图（人读）
  hint <task> "文本"        操作员插话（经 planner 转译，不直接命令 worker）
  stop <task>              轮边界优雅停止；reset-stop <task> 清除
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
