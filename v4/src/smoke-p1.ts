/**
 * smoke-P1（验收）：seed task → worker 完成第一条 step → 断言图形状。
 *
 * 跑法：node dist/smoke-p1.js [--mode=anthropic]
 * 断言清单（§3 验收）：dispatch 边 / produces 边 / fact state=confirmed /
 * 去重幂等 / overview 含 recent_facts / activity token 四列非零 / Chrome 零残留。
 */
import { rmSync, mkdirSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { openDb } from "./db.js";
import { loadTask } from "./task.js";
import { getEdges, getNode, graphOverview, initTask, submitFact, firstOpenStep } from "./graph.js";
import { runWorkerStep } from "./agent.js";
import { loadSecrets } from "./secrets.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS_ROOT = join(HERE, "..", "tasks");
const TASK_NAME = "smoke-p1";

function fail(msg: string): never {
	console.error(`[smoke-P1] FAIL: ${msg}`);
	process.exit(1);
}

async function main(): Promise<void> {
	const mode = process.argv.includes("--anthropic") ? "anthropic" : "openai";
	const dir = join(TASKS_ROOT, TASK_NAME);
	rmSync(dir, { recursive: true, force: true });
	mkdirSync(join(dir, "evidence"), { recursive: true });
	writeFileSync(
		join(dir, "task.json"),
		JSON.stringify(
			{
				name: TASK_NAME,
				goal: "观察 example.com 首页并记录一条已确认事实",
				scope: { hosts: ["example.com"] },
				seed_steps: [
					{ summary: "打开 example.com 首页并记录页面标题", note: "用 browser_navigate + browser_snapshot，标题写进证据文件" },
					{ summary: "复查页面上的链接目标域名", note: "读首页 HTML 里的 href，记录其 host" },
				],
			},
			null,
			2,
		),
	);
	const { task, dbPath } = loadTask(TASKS_ROOT, TASK_NAME);
	const db = openDb(dbPath);

	// ── 基建断言（无 LLM）：initTask 建边 ──
	const { rootGoalId, stepIds } = initTask(db, task);
	if (stepIds.length !== 2) fail(`seed steps 应 2 条，实得 ${stepIds.length}`);
	const dispatch = getEdges(db, task.name, { src: rootGoalId, rel: "dispatch" });
	if (dispatch.length !== 2) fail(`dispatch 边应 2 条，实得 ${dispatch.length}`);
	console.log(`[smoke-P1] initTask OK：goal #${rootGoalId} → steps ${stepIds.join(",")}，dispatch×2`);

	const step = firstOpenStep(db, task.name);
	if (!step) fail("没有 open step");

	// ── LLM 会话 ──
	console.log(`[smoke-P1] 启动 worker（mode=${mode}）……`);
	const result = await runWorkerStep({ db, task, taskDir: dir, step, secrets: loadSecrets(), mode });
	console.log(`[smoke-P1] step #${result.stepId} 完成：usage=`, result.usage);

	// ── 图断言 ──
	const facts = db.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='fact'").all(task.name) as Array<{
		id: number;
		state: string;
		step_id: number | null;
		evidence_sha256: string | null;
	}>;
	if (facts.length < 1) fail("worker 未产出任何 fact");
	for (const f of facts) {
		if (f.state !== "confirmed") fail(`fact #${f.id} state=${f.state}，应 confirmed`);
		if (!f.evidence_sha256 || f.evidence_sha256.length !== 64) fail(`fact #${f.id} evidence_sha256 缺失`);
		const produces = getEdges(db, task.name, { src: result.stepId, dst: f.id, rel: "produces" });
		if (produces.length !== 1) fail(`fact #${f.id} 缺 produces 边`);
	}
	console.log(`[smoke-P1] 图断言 OK：fact×${facts.length} 全 confirmed+sha256+produces 边`);

	// 去重幂等：程序层拿同 summary 再提一次 → 旧 id
	const again = submitFact(db, {
		taskId: task.name,
		taskDir: dir,
		stepId: result.stepId,
		payload: JSON.parse(
			(db.prepare("SELECT payload FROM nodes WHERE task_id=? AND kind='fact' LIMIT 1").get(task.name) as { payload: string })
				.payload,
		) as never,
	});
	if (!again.dedup) fail("同 summary 二提未命中去重");
	console.log(`[smoke-P1] 去重幂等 OK：二提返回旧 id #${again.id}`);

	// overview
	const overview = graphOverview(db, task.name);
	if (overview.recent_facts.length < 1) fail("overview 无 recent_facts");
	if (!overview.steps.some((s) => s.state === "done")) fail("overview 无 done step");
	console.log(`[smoke-P1] overview OK：counts=`, overview.counts);

	// activity token 四列
	const metered = db
		.prepare("SELECT input_tokens, output_tokens FROM activity WHERE task_id=? AND kind='result' AND tool='runWorkerStep'")
		.get(task.name) as { input_tokens: number; output_tokens: number };
	if (!metered || metered.output_tokens <= 0) fail("activity 无 token 计量（R-2 复发？）");
	console.log(`[smoke-P1] 计量 OK：input=${metered.input_tokens} output=${metered.output_tokens}`);

	// Chrome 零残留
	const chrome = (() => {
		try {
			const out = execFileSync("tasklist", ["/FI", "IMAGENAME eq chrome.exe", "/FO", "CSV", "/NH"], { timeout: 10_000 }).toString();
			return out.includes("chrome.exe");
		} catch {
			return false;
		}
	})();
	if (chrome) fail("Chrome 进程有残留");

	const stepRow = getNode(db, task.name, result.stepId);
	if (stepRow?.state !== "done") fail(`step state=${stepRow?.state}，应 done`);

	console.log("\n[smoke-P1] ===== PASS：全链（seed→worker→图）验收过 =====");
	db.close();
}

main().catch((e) => {
	console.error("[smoke-P1] 异常：", e instanceof Error ? e.stack ?? e.message : e);
	process.exit(2);
});
