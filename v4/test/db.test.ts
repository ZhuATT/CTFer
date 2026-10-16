import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
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

	it("logActivity 记录 kind/tool/is_error/token 四列", () => {
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
			is_error: number;
		};
		expect(row).toMatchObject({ input_tokens: 100, output_tokens: 50, cache_read: 7, cache_write: 0, is_error: 0 });
	});
});
