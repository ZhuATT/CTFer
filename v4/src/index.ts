/**
 * CLI（P1-5）：
 *   node dist/index.js run <task>    跑一个 task（initTask 幂等 → 领第一条 open step → runWorkerStep）
 *   node dist/index.js graph <task>  打印图（人读格式，调试与验收用）
 *
 * 可选 flag：--step=N（指定 step）、--mode=anthropic、--no-browser、--timeout-ms=N
 */
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadTask } from "./task.js";
import { openDb } from "./db.js";
import { firstOpenStep, getNode, initTask, renderOverviewText } from "./graph.js";
import { runWorkerStep } from "./agent.js";
import { loadSecrets } from "./secrets.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS_ROOT = join(HERE, "..", "tasks");

function parseArgs(argv: string[]): { cmd: string; task?: string; flags: Record<string, string | boolean> } {
	const [cmd, task, ...rest] = argv;
	const flags: Record<string, string | boolean> = {};
	for (const a of rest) {
		if (a.startsWith("--")) {
			const eq = a.indexOf("=");
			if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
			else flags[a.slice(2)] = true;
		}
	}
	return { cmd, task, flags };
}

async function cmdRun(taskName: string, flags: Record<string, string | boolean>): Promise<number> {
	const { task, dir, dbPath } = loadTask(TASKS_ROOT, taskName);
	const db = openDb(dbPath);
	const { rootGoalId, stepIds } = initTask(db, task);
	console.log(`[run] task=${task.name} db=${dbPath}`);
	console.log(`[run] root goal #${rootGoalId}，steps: ${stepIds.join(", ") || "(无)"}`);

	const stepId = flags.step ? Number(flags.step) : undefined;
	const step = stepId ? getNode(db, task.name, stepId) : firstOpenStep(db, task.name);
	if (!step) throw new Error(stepId ? `step #${stepId} 不存在` : "没有 open 状态的 step 可领");
	if (step.kind !== "step") throw new Error(`#${stepId} 不是 step`);
	console.log(`[run] 领取 step #${step.id}: ${(JSON.parse(step.payload) as { summary: string }).summary}`);

	const result = await runWorkerStep({
		db,
		task,
		taskDir: dir,
		step,
		secrets: loadSecrets(),
		mode: flags.mode === "anthropic" ? "anthropic" : "openai",
		browser: !flags["no-browser"],
		timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
	});

	console.log("\n===== step 结果 =====");
	console.log(`[usage] 轮次=${result.usage.turns} input=${result.usage.input} output=${result.usage.output} cacheRead=${result.usage.cacheRead}`);
	console.log(`[graph] worker 产出：fact=${result.facts} finding=${result.findings}`);
	console.log(`[final] ${result.finalText.slice(0, 600) || "(无文本回复)"}`);
	console.log("\n" + renderOverviewText(db, task.name));
	db.close();
	return 0;
}

function cmdGraph(taskName: string): number {
	const { task, dbPath } = loadTask(TASKS_ROOT, taskName);
	const db = openDb(dbPath);
	console.log(renderOverviewText(db, task.name));
	db.close();
	return 0;
}

async function main(): Promise<number> {
	const { cmd, task, flags } = parseArgs(process.argv.slice(2));
	switch (cmd) {
		case "run": {
			if (!task) throw new Error("用法：node dist/index.js run <task> [--step=N] [--no-browser]");
			return cmdRun(task, flags);
		}
		case "graph": {
			if (!task) throw new Error("用法：node dist/index.js graph <task>");
			return cmdGraph(task);
		}
		default:
			console.log(`AT1 v4 worker
用法：
  node dist/index.js run <task>     跑一个 task（领 open step → 干活 → 写图）
  node dist/index.js graph <task>   打印任务图（人读）
flag：--step=N --mode=anthropic --no-browser --timeout-ms=N
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
