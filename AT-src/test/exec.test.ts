import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createBashTool, createReadTool, createWriteTool, resolveInside } from "../src/tools/exec.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-exec-"));
afterAll(() => {
	rmSync(dir, { recursive: true, force: true });
});

describe("路径守卫", () => {
	it("task 目录内 → 绝对路径；../ 逃逸 → 拒", () => {
		expect(resolveInside(dir, "evidence/a.txt")).toContain("evidence");
		expect(() => resolveInside(dir, "../outside.txt")).toThrow(/逃逸/);
		expect(() => resolveInside(dir, "evidence/../../x")).toThrow(/逃逸/);
	});
});

describe("Read/Write 工具", () => {
	it("写→读往返；父目录自动创建", async () => {
		const write = createWriteTool(dir);
		const read = createReadTool(dir);
		const w = await write.execute("t1", { path: "evidence/sub/probe.txt", content: "curl → 200 OK" });
		expect((w.content[0] as { text: string }).text).toContain("probe.txt");
		const r = await read.execute("t2", { path: "evidence/sub/probe.txt" });
		expect((r.content[0] as { text: string }).text).toContain("200 OK");
		expect(readFileSync(join(dir, "evidence/sub/probe.txt"), "utf-8")).toContain("200");
	});

	it("Write 逃逸路径 → 抛错不落盘", async () => {
		const write = createWriteTool(dir);
		await expect(write.execute("t3", { path: "../evil.txt", content: "x" })).rejects.toThrow(/逃逸/);
	});
});

describe("Bash 工具", () => {
	it("bash -c 执行 + 输出返回", async () => {
		const bash = createBashTool(dir);
		const res = await bash.execute("t4", { command: "echo hello-from-worker | tr a-z A-Z" });
		expect((res.content[0] as { text: string }).text).toContain("HELLO-FROM-WORKER");
	});

	it("超时命令被杀（timeout_ms 下限验证）", async () => {
		const bash = createBashTool(dir);
		const res = await bash.execute("t5", { command: "sleep 5", timeout_ms: 1000 });
		expect((res.content[0] as { text: string }).text).toContain("timeout-killed");
	}, 15_000);
});
