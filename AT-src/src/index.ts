/**
 * CLI（P2-3/P2-6 / p2fix P2F-5/11 / P3-7/8/10）：
 *   node dist/index.js run <task>     跑一个 task（先 preflight 门口体检 → 调度循环直至终止）
 *   node dist/index.js check [task]   前置健康检查 doctor（A/B 通道 + C 图 + D 浏览器；bare 输出进 CI）
 *   node dist/index.js graph <task>   打印图（人读格式）
 *   node dist/index.js scope-add <task> <host...>   运行时扩权（task.json+资产表+信号，watcher ≤1.5s 生效）
 *   node dist/index.js reopen <task> --goal "文本"  重开终态 task 换新目标（只改 task.json，重跑播种）
 *   node dist/index.js hint <task> "文本"   操作员插话（调度层，下轮 planner 唤醒时收割）
 *   node dist/index.js steer <task> "文本"  操作员插话（执行层，定向在跑 step，秒级送达）
 *   node dist/index.js stop <task>    请求停止（watcher 秒级 abort + 优雅收尾）
 *
 * flag：--step=N（首步指定）、--mode=anthropic、--no-browser、--max-rounds=N、--budget-min=N
 */
import { join, dirname } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { loadTask } from "./task.js";
import { openDb } from "./db.js";
import { initTask, renderOverviewText } from "./graph.js";
import { runTask, clearControl, runLockPath } from "./scheduler.js";
import { appendHint } from "./hints.js";
import { appendSteer, currentRunningStep } from "./steer.js";
import { scopeAdd, reopenTask } from "./admin.js";
import { runPreflight, renderPreflightReport } from "./preflight.js";
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

/** P3-10 D 检查失败后的人工降级确认（拍板：y/N，默认不启动——回车/N 都算拒）。 */
async function askDegradeNoBrowser(): Promise<boolean> {
	const rl = (await import("node:readline/promises")).createInterface({ input: process.stdin, output: process.stdout });
	try {
		const ans = (await rl.question("浏览器池不可用——是否降级为无浏览器模式继续 run？(y/N) ")).trim().toLowerCase();
		return ans === "y" || ans === "yes";
	} finally {
		rl.close();
	}
}

async function main(): Promise<number> {
	const { cmd, task, rest, flags } = parseArgs(process.argv.slice(2));
	switch (cmd) {
		case "run": {
			if (!task) throw new Error("用法：node dist/index.js run <task> [--max-rounds=N] [--budget-min=N] [--no-browser]");
			const cfg = loadConfig();
			if (typeof flags["max-rounds"] === "string") cfg.run.maxRounds = Number(flags["max-rounds"]);
			if (typeof flags["budget-min"] === "string") cfg.run.budgetMs = Number(flags["budget-min"]) * 60_000;
			const noBrowser = flags["no-browser"] === true;

			// P3-10：前置健康检查（拍板：CLI 层拦截，退出码 1——不进 runTask、不造 run reason，
			// run 还没开始没有 run 账目可写；C 图修复在检查内完成，activity 落 task 库）
			const loaded = loadTask(TASKS_ROOT, task);
			const secrets = loadSecrets();
			const db = openDb(loaded.dbPath);
			const pf = await runPreflight({
				config: cfg,
				secrets,
				db,
				taskId: loaded.task.name,
				taskDir: loaded.dir,
				skipBrowser: noBrowser,
			});
			console.log(renderPreflightReport(pf));
			if (pf.hardFailed) {
				db.close();
				return 1;
			}

			// D 浏览器失败（拍板：警告+人工选择降级——y/N 默认不启动；--no-browser 显式降级）
			let browser = true;
			if (pf.browserDegraded && !noBrowser) {
				const degrade = process.stdin.isTTY ? await askDegradeNoBrowser() : false;
				if (!degrade) {
					db.close();
					console.log(`[run] 浏览器不可用且未确认降级——不启动。显式降级：node dist/index.js run ${task} --no-browser`);
					return 1;
				}
				browser = false;
				console.log(`[run] 已确认降级：本次 run 无浏览器（worker 只能用 Bash 探测）`);
			}
			db.close();

			const result = await runTask({
				tasksRoot: TASKS_ROOT,
				taskName: task,
				config: cfg,
				browser,
				stepTimeoutMs: flags["step-timeout-min"] ? Number(flags["step-timeout-min"]) * 60_000 : undefined,
			});
			console.log(`\n[run] 结束：reason=${result.reason} rounds=${result.rounds} workerSteps=${result.workerSteps} plannerWakeups=${result.plannerWakeups}`);
			// P3pre：可靠性终局的人话提示——修复后重跑即续（initTask 幂等）
			if (result.reason === "channel-down") {
				console.log(`[run] 通道故障熔断——连续 step 传输层失败。检查配额/端点（config.yaml channels 段），修复后重跑即续。`);
			} else if (result.reason === "planner-error") {
				console.log(`[run] planner 唤醒失败（已重试 1 次）——检查通道后重跑即续，中断前进度不丢。`);
			}
			// 终态打印图
			const { task: t, dbPath } = loadTask(TASKS_ROOT, task);
			const endDb = openDb(dbPath);
			console.log(renderOverviewText(endDb, t.name));
			endDb.close();
			return result.reason === "goal-achieved" || result.reason === "goal-closed" || result.reason === "control-stop" ? 0 : 1;
		}
		case "check": {
			// P3-10：doctor——bare 输出可进 CI；带 task 加查 C 图完整性（activity 落账），D 用 task 目录
			const cfg = loadConfig();
			const secrets = loadSecrets();
			const noBrowser = flags["no-browser"] === true;
			let report;
			let opened: ReturnType<typeof openDb> | undefined;
			if (task) {
				const t = loadTask(TASKS_ROOT, task);
				opened = openDb(t.dbPath);
				report = await runPreflight({ config: cfg, secrets, db: opened, taskId: t.task.name, taskDir: t.dir, skipBrowser: noBrowser });
			} else {
				report = await runPreflight({ config: cfg, secrets, taskDir: join(tmpdir(), "at1-check-browser"), skipBrowser: noBrowser });
			}
			console.log(renderPreflightReport(report));
			opened?.close();
			return report.hardFailed ? 1 : 0;
		}
		case "scope-add": {
			// P3-7（D7）：运行时扩权——task.json + 资产表（origin=scope-add）+ 信号文件
			if (!task || rest.length === 0) throw new Error("用法：node dist/index.js scope-add <task> <host...>（可多个）");
			const hosts = rest.filter((r) => !r.startsWith("--"));
			const r = scopeAdd(TASKS_ROOT, task, hosts);
			console.log(`[scope-add] 已追加 ${r.added.length} 个 host：${r.added.join(", ") || "（全部已存在，幂等）"}`);
			console.log(`[scope-add] 信号已写 ${r.scopeChangedPath}——若在跑，watcher ≤1.5s 生效（guard 即刻放行 + planner 收 scope_changed）`);
			return 0;
		}
		case "reopen": {
			// P3-8（D8）：只改 task.json goal 文本；重跑时 initTask 播种新 goal + goal_changed
			if (!task) throw new Error('用法：node dist/index.js reopen <task> --goal "新目标文本"');
			const goalText = typeof flags["goal"] === "string" ? flags["goal"] : rest.filter((r) => !r.startsWith("--")).join(" ");
			if (!goalText.trim()) throw new Error('用法：node dist/index.js reopen <task> --goal "新目标文本"');
			const r = reopenTask(TASKS_ROOT, task, goalText);
			console.log(`[reopen] goal 文本已更新（task.json）`);
			console.log(`[reopen] 旧 goal：${r.oldGoal}`);
			console.log(`[reopen] 新 goal：${r.task.goal}${r.prevGoalState ? `（原 goal ${r.prevGoalState}）` : "（图尚不存在，直接生效）"}`);
			console.log(`[reopen] 重跑即生效：node dist/index.js run ${task}——initTask 将播种新 goal 并给 planner 发 goal_changed`);
			return 0;
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
			console.log(`AT1 v4（P3 资产登记表 + preflight 版）
用法：
  run <task>               调度循环：先 preflight 门口体检，planner↔worker 事件驱动直至终止
  check [task]             前置健康检查 doctor（A/B 通道活性 + C 图完整性 + D 浏览器池；bare 进 CI）
  graph <task>             打印任务图（人读）
  scope-add <task> <host...>  运行时扩权：task.json+资产表补登记+信号文件（watcher ≤1.5s 生效）
  reopen <task> --goal "文本"  重开已终态 task 换新目标（只改 task.json，重跑时播种新 goal）
  hint <task> "文本"        调度层插话（经 planner 转译，影响未来 step）
  steer <task> "文本"       执行层插话（定向当前在跑 step，秒级送达 worker）
  stop <task>              秒级优雅停止（watcher abort）；reset-stop <task> 清除
  init <task>              只初始化图（不跑）
flag：--max-rounds=N --budget-min=N --step-timeout-min=N --mode=anthropic --no-browser
task 定义：tasks/<name>/task.json（goal + scope.hosts + project[可选] + seed_steps[仅测试夹具]）`);
			return 0;
	}
}

main()
	.then((code) => process.exit(code))
	.catch((err) => {
		console.error("[cli] 失败：", err instanceof Error ? err.stack ?? err.message : err);
		process.exit(2);
	});
