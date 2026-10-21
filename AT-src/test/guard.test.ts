import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { createGuard, extractHosts } from "../src/guard.js";
import type { BeforeToolCallContext } from "@earendil-works/pi-agent-core";

const dir = mkdtempSync(join(tmpdir(), "at1v4-guard-"));
const db = openDb(join(dir, "t.db"));
const guard = createGuard(db, { taskId: "t1", sessionId: "s1", scopeHosts: ["target.example.com", "example.com"] });

beforeEach(() => {
	db.exec("DELETE FROM activity;");
});
afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

function ctxOf(toolName: string, args: unknown): BeforeToolCallContext {
	return {
		toolCall: { type: "toolCall", id: "tc1", name: toolName, arguments: args as never },
		args,
		assistantMessage: { role: "assistant", content: [] },
		context: { messages: [], tools: [] },
	} as unknown as BeforeToolCallContext;
}

describe("extractHosts", () => {
	it("抽显式 URL host，忽略裸域名", () => {
		expect(extractHosts("curl https://a.com/x && curl http://b.c:8080/y")).toEqual(["a.com", "b.c"]);
		expect(extractHosts("curl example.com")).toEqual([]); // 裸域名不做（死胡同教训）
	});
});

describe("guard 规则表", () => {
	it("browser_navigate 范围外 host → deny + 平台管控语义", async () => {
		const res = await guard(ctxOf("browser_navigate", { url: "https://evil.example.org/" }));
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("平台管控");
		expect(res?.reason).toContain("scope");
		expect(res?.reason).toContain("不要动手");
	});

	it("范围内 host → 放行", async () => {
		expect(await guard(ctxOf("browser_navigate", { url: "https://target.example.com/login" }))).toBeUndefined();
	});

	it("Bash 命令含范围外 URL → deny；纯本地命令放行", async () => {
		const blocked = await guard(ctxOf("Bash", { command: "curl -s https://other.invalid/ip" }));
		expect(blocked?.block).toBe(true);
		const ok = await guard(ctxOf("Bash", { command: "grep -r foo ./evidence" }));
		expect(ok).toBeUndefined();
	});

	it("破坏性命令 deny（rm -rf / mkfs / dd）", async () => {
		for (const cmd of ["rm -rf ./x", "dd if=/dev/zero of=/dev/sda", "mkfs.vfat /dev/sdb1"]) {
			const res = await guard(ctxOf("Bash", { command: cmd }));
			expect(res?.block, cmd).toBe(true);
			expect(res?.reason).toContain("破坏性命令");
		}
	});

	it("审计：call 与 blocked 都落 activity", async () => {
		await guard(ctxOf("browser_navigate", { url: "https://example.com/" }));
		await guard(ctxOf("browser_navigate", { url: "https://out.scope.example/x" }));
		const rows = db.prepare("SELECT * FROM activity ORDER BY id").all() as Array<{ kind: string; summary: string }>;
		expect(rows.filter((r) => r.summary === "call")).toHaveLength(2);
		expect(rows.filter((r) => r.summary!.startsWith("blocked:"))).toHaveLength(1);
	});
});
