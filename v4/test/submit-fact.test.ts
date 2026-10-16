import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { createSubmitFactTool } from "../src/tools/submit-fact.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-tool-"));
const db = openDb(join(dir, "t.db"));
const tool = createSubmitFactTool(db);

beforeEach(() => {
	db.prepare("DELETE FROM nodes").run();
});

afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

const good = {
	summary: "example.com 首页标题为 Example Domain",
	evidence: "browser_navigate https://example.com → <title>Example Domain</title>",
	confidence: "observed" as const,
};

describe("submit_fact 工具", () => {
	it("schema：name/parameters(description 里有微纪律)", () => {
		expect(tool.name).toBe("submit_fact");
		const params = tool.parameters as { properties: Record<string, { description?: string }> };
		expect(params.properties.summary).toBeTruthy();
		expect(params.properties.confidence).toBeTruthy();
		expect(tool.description).toContain("evidence");
		expect(tool.description).toContain("observed");
	});

	it("合法参数入库并回执 {id, dedup:false}", async () => {
		const res = await tool.execute("tc1", good);
		const structured = res.structuredContent as { id: string; dedup: boolean };
		expect(structured.dedup).toBe(false);
		expect(structured.id).toBeTruthy();
		expect((res.content[0] as { type: string }).type).toBe("text");
	});

	it("confidence 非法 → 抛错（模型收到错误回执）", async () => {
		await expect(tool.execute("tc2", { ...good, confidence: "guessed" })).rejects.toThrow(/不合规/);
	});

	it("evidence 缺失 → 抛错", async () => {
		await expect(tool.execute("tc3", { summary: good.summary, confidence: "observed" })).rejects.toThrow();
	});

	it("summary 过短 → 抛错", async () => {
		await expect(tool.execute("tc4", { ...good, summary: "短" })).rejects.toThrow();
	});
});
