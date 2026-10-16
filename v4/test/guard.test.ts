import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { createGuard } from "../src/guard.js";
import type { BeforeToolCallContext } from "@earendil-works/pi-agent-core";

const dir = mkdtempSync(join(tmpdir(), "at1v4-guard-"));
const db = openDb(join(dir, "t.db"));
const guard = createGuard(db, { sessionId: "test-session" });

beforeEach(() => {
	db.prepare("DELETE FROM activity").run();
});

afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

function ctxOf(toolName: string, args: unknown): BeforeToolCallContext {
	return {
		toolCall: { type: "toolCall", id: "tc1", name: toolName, arguments: args as never },
		args,
		assistantMessage: { role: "assistant", content: [], api: "openai-completions", provider: "bigmodel", model: "glm-5.3", usage: {} as never, stopReason: "toolUse", timestamp: 0 },
		context: { messages: [], tools: [] },
	} as unknown as BeforeToolCallContext;
}

describe("guard 闸机", () => {
	it("普通调用放行（返回 undefined）并落审计", async () => {
		const res = await guard(ctxOf("browser_navigate", { url: "https://example.com" }));
		expect(res).toBeUndefined();
		const rows = db.prepare("SELECT * FROM activity WHERE action='call'").all();
		expect(rows).toHaveLength(1);
	});

	it("submit_fact.summary 含 test-block → block，理由带平台管控语义", async () => {
		const res = await guard(ctxOf("submit_fact", { summary: "test-block 回归样例", evidence: "e → o", confidence: "observed" }));
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("平台管控");
		expect(res?.reason).toContain("test-block");
		expect(res?.reason).toContain("请勿尝试绕过");
		const blockRows = db.prepare("SELECT * FROM activity WHERE action='block'").all();
		expect(blockRows).toHaveLength(1);
	});

	it("submit_fact.summary 干净 → 放行", async () => {
		const res = await guard(ctxOf("submit_fact", { summary: "正常摘要无管控词", evidence: "e → o", confidence: "inferred" }));
		expect(res).toBeUndefined();
	});

	it("block 之外的关键词不影响", async () => {
		const res = await guard(ctxOf("submit_fact", { summary: "observed 块状布局", evidence: "e → o", confidence: "observed" }));
		expect(res).toBeUndefined();
	});
});
