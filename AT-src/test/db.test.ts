import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { openDb, logActivity } from "../src/db.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-db-"));
const db = openDb(join(dir, "t.db"));

beforeEach(() => {
	db.exec("DELETE FROM nodes; DELETE FROM edges; DELETE FROM activity;");
});

afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

describe("db v2 schema", () => {
	it("nodes/edges/activity 三表可写入（含 token 四列默认 0）", () => {
		db.prepare(
			"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES ('t1','goal','open','program','{}',?,?)",
		).run("2026-10-16T00:00:00Z", "2026-10-16T00:00:00Z");
		db.prepare("INSERT INTO edges (task_id, src_id, rel, dst_id, created_at) VALUES ('t1',1,'dispatch',2,?)").run(
			"2026-10-16T00:00:00Z",
		);
		// 复合主键幂等：重插不报错不重复
		db.prepare("INSERT OR IGNORE INTO edges (task_id, src_id, rel, dst_id, created_at) VALUES ('t1',1,'dispatch',2,?)").run(
			"2026-10-16T00:00:00Z",
		);
		const edges = db.prepare("SELECT COUNT(*) AS n FROM edges").get() as { n: number };
		expect(edges.n).toBe(1);
	});

	it("logActivity 记录 kind/tool/is_error/token 五列（prompt_tokens=input+cacheRead 合计）", () => {
		logActivity(db, {
			task_id: "t1",
			session_id: "s1",
			worker: "worker",
			kind: "result",
			tool: "runWorkerStep",
			summary: "done",
			tokens: { input: 100, output: 50, cacheRead: 7 },
		});
		const row = db.prepare("SELECT * FROM activity").get() as {
			input_tokens: number;
			output_tokens: number;
			cache_read: number;
			cache_write: number;
			prompt_tokens: number;
			is_error: number;
		};
		expect(row).toMatchObject({
			input_tokens: 100,
			output_tokens: 50,
			cache_read: 7,
			cache_write: 0,
			prompt_tokens: 107,
			is_error: 0,
		});
	});

	it("旧库迁移：openDb 幂等补 prompt_tokens 列并回填 input+cache_read 合计", () => {
		const mdir = mkdtempSync(join(tmpdir(), "at1v4-db-mig-"));
		const mpath = join(mdir, "old.db");
		// 手造 v2.1 之前的旧 schema（activity 无 prompt_tokens 列）
		const raw = new Database(mpath);
		raw.exec(`CREATE TABLE activity (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  task_id TEXT, node_id INTEGER, session_id TEXT, worker TEXT,
		  kind TEXT NOT NULL, tool TEXT, is_error INTEGER NOT NULL DEFAULT 0,
		  summary TEXT, detail TEXT,
		  input_tokens INTEGER NOT NULL DEFAULT 0,
		  output_tokens INTEGER NOT NULL DEFAULT 0,
		  cache_read INTEGER NOT NULL DEFAULT 0,
		  cache_write INTEGER NOT NULL DEFAULT 0,
		  created_at TEXT NOT NULL
		);`);
		raw
			.prepare("INSERT INTO activity (kind, input_tokens, cache_read, created_at) VALUES ('result', 6775, 7360, 'x')")
			.run();
		raw.close();

		const db2 = openDb(mpath); // 迁移：补列 + 回填
		const row = db2.prepare("SELECT prompt_tokens FROM activity").get() as { prompt_tokens: number };
		expect(row.prompt_tokens).toBe(6775 + 7360);
		db2.close();

		const db3 = openDb(mpath); // 幂等：二次打开不炸、值不被重置
		const again = db3.prepare("SELECT prompt_tokens FROM activity").get() as { prompt_tokens: number };
		expect(again.prompt_tokens).toBe(6775 + 7360);
		db3.close();
		rmSync(mdir, { recursive: true, force: true });
	});
});
