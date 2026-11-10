import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { createGuard, extractHosts, parseUrlHosts, parseNavigateUrl } from "../src/guard.js";
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

describe("parseUrlHosts（G-B 标准 URL 解析）", () => {
	it("协议/host 大小写归一；端口不算 host；IPv6 剥外围方括号", () => {
		expect(parseUrlHosts("HTTPS://TARGET.Example.COM:8443/x").hosts).toEqual(["target.example.com"]);
		expect(parseUrlHosts("curl 'http://[::1]:9399/'").hosts).toEqual(["::1"]);
	});
	it("用户信息取 @ 后真实 host；引号不吃进 hostname", () => {
		expect(parseUrlHosts("curl https://user:pass@evil.example.org/").hosts).toEqual(["evil.example.org"]);
		expect(parseUrlHosts(`curl "https://a.example.com/path"`).hosts).toEqual(["a.example.com"]);
		expect(parseUrlHosts("curl 'https://b.example.com/'").hosts).toEqual(["b.example.com"]);
	});
	it("解析失败候选进 failed，不静默丢掉", () => {
		const out = parseUrlHosts("curl http://[bad");
		expect(out.hosts).toEqual([]);
		expect(out.failed).toHaveLength(1);
	});
});

describe("parseNavigateUrl（G-B browser_navigate url 校验）", () => {
	it("合法 http(s) → host；非法/非 http(s) → error", () => {
		expect(parseNavigateUrl("HTTPS://A.Example.COM/x")).toEqual({ host: "a.example.com" });
		expect(parseNavigateUrl("ftp://a.example.com/")?.error).toContain("http(s)");
		expect(parseNavigateUrl("not a url")?.error).toContain("无法解析");
		expect(parseNavigateUrl(123)?.error).toContain("非空字符串");
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

	it("G-A：破坏性回执含「保留已有文件 + 唯一临时文件名 + 禁替代删除」全链文本", async () => {
		const res = await guard(ctxOf("Bash", { command: "rm -f ./evidence/old.txt" }));
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("平台管控·非目标防御");
		expect(res?.reason).toContain("移除命令中的删除操作");
		expect(res?.reason).toContain("新的唯一文件名");
		expect(res?.reason).toContain("保留已有文件");
		expect(res?.reason).toContain("不得换用其他方式执行同一删除操作");
	});

	it("G-A：按真实 args.command 匹配——真实制表/换行/多行命令照样命中（JSON 转义不破规则）", async () => {
		for (const cmd of ["rm\t-rf /tmp/x", "echo hi\nrm -rf /tmp/x", "true && rm  ./x", "rm -f y\tz"]) {
			const res = await guard(ctxOf("Bash", { command: cmd }));
			expect(res?.block, JSON.stringify(cmd)).toBe(true);
		}
	});

	it("G-B：普通直接删除同样拒绝（rm 无参数 / rmdir / unlink）", async () => {
		for (const cmd of ["rm /tmp/f", "rm file1 file2", "rmdir /tmp/empty", "unlink ev-link"]) {
			const res = await guard(ctxOf("Bash", { command: cmd }));
			expect(res?.block, cmd).toBe(true);
			expect(res?.reason).toContain("破坏性命令");
		}
	});

	it("G-B：保守策略——仅展示/引号内出现危险文本也可能拒绝；普通命令不受影响", async () => {
		const echoed = await guard(ctxOf("Bash", { command: "echo 'rm -rf /'" }));
		expect(echoed?.block).toBe(true); // 不建纯文本例外，宁误拦不放松
		for (const cmd of ["echo hello world", "grep -r foo ./evidence", "mkdir -p a/b/c", "ls -la", "curl -s --help"]) {
			const res = await guard(ctxOf("Bash", { command: cmd }));
			expect(res, cmd).toBeUndefined();
		}
	});

	it("G-A：Bash.command 非字符串 → 参数校验拒绝（不走 String(object) 兑底，guard 异常不逃出）", async () => {
		const res = await guard(ctxOf("Bash", { command: { raw: "rm -rf /" } }));
		expect(res?.block).toBe(true);
		expect(res?.reason).toContain("必须是字符串");
		// 审计仍在：call + blocked: invalid-args
		const rows = db.prepare("SELECT summary FROM activity ORDER BY id DESC LIMIT 2").all() as Array<{ summary: string }>;
		expect(rows.map((r) => r.summary)).toEqual(["blocked: invalid-args", "call"]);
	});

	it("G-B URL scope：大小写/端口/用户信息/相似前缀/非法 URL 按标准解析精确匹配", async () => {
		// 范围内（协议大小写、端口不算 host）放行
		expect(await guard(ctxOf("Bash", { command: "curl HTTPS://TARGET.Example.COM:8443/api" }))).toBeUndefined();
		// 用户信息真实 host 范围外 → deny
		expect((await guard(ctxOf("Bash", { command: "curl https://user@evil.example.org/" })))?.block).toBe(true);
		// 相似前缀域名不匹配（target.example.com.evil.com ≠ target.example.com）
		expect((await guard(ctxOf("Bash", { command: "curl https://target.example.com.evil.com/" })))?.block).toBe(true);
		// 显式 http(s) 候选解析失败 → 拒绝并说明「URL 无法校验 scope」，不静默丢
		const bad = await guard(ctxOf("Bash", { command: "curl http://[bad" }));
		expect(bad?.block).toBe(true);
		expect(bad?.reason).toContain("URL 无法校验 scope");
		// 引号包裹的范围外 URL 照拦
		expect((await guard(ctxOf("Bash", { command: `curl "https://out.example.com/"` })))?.block).toBe(true);
		// IPv6：scope 外字面量（剥括号后比对）→ deny
		expect((await guard(ctxOf("Bash", { command: "curl http://[::1]:9399/" })))?.block).toBe(true);
	});

	it("G-B browser_navigate：非法/非 http(s) URL 拒绝；协议大小写兼容", async () => {
		expect((await guard(ctxOf("browser_navigate", { url: "ftp://target.example.com/" })))?.block).toBe(true);
		expect((await guard(ctxOf("browser_navigate", { url: "not a url" })))?.block).toBe(true);
		expect((await guard(ctxOf("browser_navigate", { url: 123 })))?.block).toBe(true);
		expect(await guard(ctxOf("browser_navigate", { url: "HTTPS://Target.Example.COM/Login" }))).toBeUndefined();
	});

	it("G-B：scope Set 热扩权原位生效（同引用语义不变）", async () => {
		const scopeSet = new Set(["a.example.com"]);
		const g = createGuard(db, { taskId: "t1", sessionId: "s1", scopeHosts: scopeSet });
		expect((await g(ctxOf("Bash", { command: "curl https://b.example.com/" })))?.block).toBe(true);
		scopeSet.add("b.example.com"); // scope-add 原位扩权
		expect(await g(ctxOf("Bash", { command: "curl https://b.example.com/" }))).toBeUndefined();
	});

	it("审计：call 与 blocked 都落 activity", async () => {
		await guard(ctxOf("browser_navigate", { url: "https://example.com/" }));
		await guard(ctxOf("browser_navigate", { url: "https://out.scope.example/x" }));
		const rows = db.prepare("SELECT * FROM activity ORDER BY id").all() as Array<{ kind: string; summary: string }>;
		expect(rows.filter((r) => r.summary === "call")).toHaveLength(2);
		expect(rows.filter((r) => r.summary!.startsWith("blocked:"))).toHaveLength(1);
	});
});

// ── 卡A：审计行结构（stepId 关联 + toolCallId/ruleId/receipt JSON，先限长再序列化）──

describe("卡A：guard 审计行（activity.node_id + JSON detail 可解析）", () => {
	it("call 与 blocked 走 node_id=stepId；detail JSON 含 toolCallId/ruleId/receipt，不追加命令原文", async () => {
		const g = createGuard(db, { taskId: "t1", sessionId: "s1", stepId: 42, scopeHosts: ["target.example.com"] });
		db.exec("DELETE FROM activity;");
		await g(ctxOf("Bash", { command: "rm -rf /tmp/x" }));
		const rows = db.prepare("SELECT * FROM activity ORDER BY id").all() as Array<{
			kind: string;
			node_id: number | null;
			summary: string;
			detail: string;
		}>;
		const call = rows.find((r) => r.summary === "call")!;
		const blocked = rows.find((r) => r.summary!.startsWith("blocked:")!)!;
		expect(call.node_id).toBe(42);
		expect(blocked.node_id).toBe(42);
		const callDetail = JSON.parse(call.detail) as { toolCallId: string; args: string };
		expect(callDetail.toolCallId).toBe("tc1");
		expect(callDetail.args).toContain("rm");
		const bDetail = JSON.parse(blocked.detail) as { toolCallId: string; ruleId: string; receipt: string };
		expect(bDetail.toolCallId).toBe("tc1"); // 与 call 同 ID 可关联
		expect(bDetail.ruleId).toBe("destructive-command");
		expect(bDetail.receipt).toContain("保留已有文件");
		expect(bDetail.receipt).not.toContain("/tmp/x"); // 平台回执是已知文案，不追加命令原文
	});
});
