/**
 * 入口（P0-5 smoke）：node dist/index.js [--url=...] [--mode=openai|anthropic] [--block-test] [--keep-db]
 *
 * 无参数 = smoke-1（example.com，openai 形态）。
 * --block-test = smoke-2（诱导 test-block 触发闸机）。
 */
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdirSync, rmSync } from "node:fs";
import { loadSecrets } from "./secrets.js";
import { openDb } from "./db.js";
import { runWorker } from "./agent.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv: string[]): Record<string, string | boolean> {
	const out: Record<string, string | boolean> = {};
	for (const a of argv) {
		if (a.startsWith("--")) {
			const eq = a.indexOf("=");
			if (eq > 0) out[a.slice(2, eq)] = a.slice(eq + 1);
			else out[a.slice(2)] = true;
		}
	}
	return out;
}

async function main(): Promise<number> {
	const args = parseArgs(process.argv.slice(2));
	const targetUrl = String(args.url ?? "https://example.com");
	const mode = (args.mode === "anthropic" ? "anthropic" : "openai") as "openai" | "anthropic";
	const blockProbe = Boolean(args["block-test"]);

	const root = join(HERE, "..");
	const dbDir = join(root, ".at1");
	mkdirSync(dbDir, { recursive: true });
	const dbPath = join(dbDir, "smoke.db");
	if (!args["keep-db"]) {
		for (const suffix of ["", "-wal", "-shm"]) {
			try {
				rmSync(dbPath + suffix, { force: true });
			} catch {
				/* 无所谓 */
			}
		}
	}
	const db = openDb(dbPath);

	console.log(`[smoke] target=${targetUrl} mode=${mode} blockProbe=${blockProbe}`);
	console.log(`[smoke] db=${dbPath}`);

	const secrets = loadSecrets();
	const result = await runWorker({ db, secrets, root, targetUrl, mode, blockProbe });

	console.log("\n===== smoke 结果 =====");
	for (const u of result.usage) {
		console.log(
			`[usage] turn ${u.turn}: input=${u.input} output=${u.output} cacheRead=${u.cacheRead} cacheWrite=${u.cacheWrite} total=${u.totalTokens}`,
		);
	}
	const total = result.usage.reduce((s, u) => s + u.totalTokens, 0);
	console.log(`[usage] 轮次=${result.usage.length} 总token=${total}`);
	console.log(`[facts] nodes 表 fact 行数=${result.facts}`);
	console.log(`[guard] block 次数=${result.blockedCount}`);
	console.log(`[final] ${result.finalText.slice(0, 500) || "(无文本回复)"}`);

	const rows = db.prepare("SELECT id, payload FROM nodes WHERE kind='fact' ORDER BY created_at").all() as Array<{
		id: string;
		payload: string;
	}>;
	for (const r of rows) {
		console.log(`[fact] ${r.id}: ${r.payload}`);
	}

	if (blockProbe) {
		const ok = result.blockedCount >= 1;
		console.log(`\n[smoke-2] ${ok ? "PASS：闸机拦截生效且 worker 未崩" : "FAIL：没有 block 记录"}`);
		db.close();
		return ok ? 0 : 1;
	}
	const ok = result.facts >= 1 && result.usage.length >= 1;
	console.log(`\n[smoke-1] ${ok ? "PASS：navigate→snapshot→submit_fact 全链走通" : "FAIL：链路不完整"}`);
	db.close();
	return ok ? 0 : 1;
}

main()
	.then((code) => process.exit(code))
	.catch((err) => {
		console.error("[smoke] 失败：", err instanceof Error ? err.stack ?? err.message : err);
		process.exit(2);
	});
