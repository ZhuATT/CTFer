import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb, insertFact, logActivity, listFacts, type FactPayload } from "../src/db.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-db-"));
const db = openDb(join(dir, "t.db"));

beforeEach(() => {
	db.prepare("DELETE FROM nodes").run();
	db.prepare("DELETE FROM activity").run();
});

afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

describe("db", () => {
	it("insertFact 落一行 fact，payload JSON 往返一致，dedup 恒 false", () => {
		const payload: FactPayload = {
			summary: "example.com 首页标题为 Example Domain",
			evidence: "browser_navigate https://example.com → <title>Example Domain</title>",
			confidence: "observed",
		};
		const { id, dedup } = insertFact(db, payload, "worker");
		expect(dedup).toBe(false);
		expect(id).toMatch(/^[0-9a-f-]{36}$/);
		const rows = listFacts(db);
		expect(rows).toHaveLength(1);
		expect(rows[0].kind).toBe("fact");
		expect(rows[0].state).toBe("open");
		expect(rows[0].origin).toBe("worker");
		expect(JSON.parse(rows[0].payload)).toEqual(payload);
	});

	it("insertFact 两次生成不同 id（P0 不去重但 id 唯一）", () => {
		const p: FactPayload = { summary: "s 摘要", evidence: "e 证据", confidence: "inferred" };
		const a = insertFact(db, p, "worker");
		const b = insertFact(db, p, "worker");
		expect(a.id).not.toBe(b.id);
		expect(listFacts(db)).toHaveLength(2);
	});

	it("logActivity 记一行审计（call 与 block 各一条）", () => {
		logActivity(db, { session_id: "s1", tool: "browser_navigate", action: "call", params_digest: '{"url":"https://x"}' });
		logActivity(db, { session_id: "s1", tool: "submit_fact", action: "block", detail: "keyword=test-block" });
		const rows = db.prepare("SELECT * FROM activity ORDER BY id").all() as Array<{
			tool: string;
			action: string;
			session_id: string | null;
		}>;
		expect(rows).toHaveLength(2);
		expect(rows[0]).toMatchObject({ tool: "browser_navigate", action: "call", session_id: "s1" });
		expect(rows[1]).toMatchObject({ tool: "submit_fact", action: "block" });
	});
});
