import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import {
	executeKnowledgeSearch,
	formatSearchResults,
	createSearchKnowledgeTool,
	isKnowledgeReady,
	type KnowledgeEntry,
} from "../src/tools/knowledge.js";
import { buildKnowledge } from "../scripts/build-knowledge.mjs";

describe("知识库检索核心 executeKnowledgeSearch", () => {
	const mockCatalog: KnowledgeEntry[] = [
		{
			name: "offensive-idor",
			file: "knowledge/skills/offensive-idor.md",
			use_when: "在 Web 渗透测试中需要检测未授权访问与越权漏洞时阅读本篇。",
			triggers: ["IDOR", "BOLA", "越权", "水平越权", "垂直越权"],
			vulnclass: "越权",
			section_map: [
				{ heading: "Testing Methodology", what: "参数篡改与水平越权测试流程", line: 20 },
				{ heading: "Automated Scripts", what: "编写脚本自动化测试 IDOR", line: 50 },
			],
		},
		{
			name: "injection-sqli",
			file: "knowledge/skills/injection-sqli.md",
			use_when: "在渗透测试中评估 SQL 注入风险与执行时间盲注 payload 时阅读本篇。",
			triggers: ["SQL注入", "SQL injection", "SQLi", "时间盲注", "联合注入"],
			vulnclass: "SQL注入",
			section_map: [
				{ heading: "Time-Based Blind", what: "时间延迟函数与盲注检测", line: 35 },
			],
		},
		{
			name: "privesc-linux",
			file: "knowledge/skills/privesc-linux.md",
			use_when: "在获得 Linux 普通权限后需要本地提权与逃逸时阅读本篇。",
			triggers: ["提权", "Linux privesc", "SUID", "sudo", "内核漏洞"],
			vulnclass: "提权",
			section_map: [
				{ heading: "SUID Binaries", what: "利用 SUID 权限可执行文件提权", line: 15 },
			],
		},
	];

	it("中文 query 命中英文篇（triggers 跨语言词汇桥）", () => {
		const res = executeKnowledgeSearch("水平越权", mockCatalog);
		expect(res.isFallback).toBe(false);
		expect(res.results.length).toBeGreaterThan(0);
		expect(res.results[0].name).toBe("offensive-idor");
		expect(res.results[0].matchedTerms).toContain("水平越权");
	});

	it("英文 query 命中中文篇（反向对齐词汇桥）", () => {
		const res = executeKnowledgeSearch("SQL injection", mockCatalog);
		expect(res.isFallback).toBe(false);
		expect(res.results.length).toBeGreaterThan(0);
		expect(res.results[0].name).toBe("injection-sqli");
		expect(res.results[0].matchedTerms).toContain("sql");
	});

	it("多词计分排序：triggers (10) > use_when (3) > section (1)", () => {
		// 条目 A 在 section 命中 (1分)，条目 B 在 use_when 命中 (3分)，条目 C 在 triggers 命中 (10分)
		const rankingCatalog: KnowledgeEntry[] = [
			{
				name: "skill-section",
				file: "k/s/1.md",
				use_when: "完全不相关的描述",
				triggers: ["unrelated"],
				vulnclass: "其他",
				section_map: [{ heading: "TargetConcept Section", what: "细节", line: 10 }],
			},
			{
				name: "skill-usewhen",
				file: "k/s/2.md",
				use_when: "包含 TargetConcept 的适用场景描述",
				triggers: ["unrelated"],
				vulnclass: "其他",
				section_map: [{ heading: "Other", what: "细节", line: 10 }],
			},
			{
				name: "skill-trigger",
				file: "k/s/3.md",
				use_when: "完全不相关的描述",
				triggers: ["TargetConcept"],
				vulnclass: "其他",
				section_map: [{ heading: "Other", what: "细节", line: 10 }],
			},
		];

		const res = executeKnowledgeSearch("TargetConcept", rankingCatalog);
		expect(res.results.length).toBe(3);
		expect(res.results[0].name).toBe("skill-trigger");
		expect(res.results[1].name).toBe("skill-usewhen");
		expect(res.results[2].name).toBe("skill-section");
		expect(res.results[0].score).toBeGreaterThan(res.results[1].score);
		expect(res.results[1].score).toBeGreaterThan(res.results[2].score);
	});

	it("Top 5 截断：最多返回 5 篇", () => {
		const manyCatalog: KnowledgeEntry[] = Array.from({ length: 10 }, (_, i) => ({
			name: `skill-${i}`,
			file: `knowledge/skills/skill-${i}.md`,
			use_when: `适用场景 ${i}`,
			triggers: ["common-trigger", `unique-${i}`],
			vulnclass: "测试",
			section_map: [{ heading: "H", what: "W", line: 1 }],
		}));
		const res = executeKnowledgeSearch("common-trigger", manyCatalog);
		expect(res.results.length).toBe(5);
	});

	it("Layer 1 全 0 时触发 Layer 2 纯 Node 全文正文扫描兜底", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-k-scan-"));
		try {
			mkdirSync(join(tmp, "skills"), { recursive: true });
			writeFileSync(
				join(tmp, "skills", "test-obscure.md"),
				"# Title\nSome rare_payload_token_xyz in body.\n## Details\nPayload here.",
				"utf-8",
			);

			const emptyTrigCatalog: KnowledgeEntry[] = [
				{
					name: "test-obscure",
					file: "knowledge/skills/test-obscure.md",
					use_when: "普通测试",
					triggers: ["unrelated"],
					vulnclass: "其他",
					section_map: [{ heading: "Title", what: "W", line: 1 }],
				},
			];

			const res = executeKnowledgeSearch("rare_payload_token_xyz", emptyTrigCatalog, join(tmp, "skills"));
			expect(res.isFallback).toBe(true);
			expect(res.results.length).toBe(1);
			expect(res.results[0].name).toBe("test-obscure");
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("两层皆 0 命中落 activity 审计账本", async () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-k-act-"));
		const db = openDb(join(tmp, "test.db"));
		try {
			const tool = createSearchKnowledgeTool({
				db,
				taskId: "task-k1",
				sessionId: "sess-k1",
				stepId: 42,
				workerType: "worker",
				knowledgeDir: tmp, // 空目录，没有任何 catalog
			});

			const out = await tool.execute("call-1", { query: "completely_non_existent_exploit_target_999" });
			expect(out.content[0].text).toContain("未检索到");

			const logs = db.prepare("SELECT * FROM activity WHERE tool = 'search_knowledge'").all() as any[];
			expect(logs.length).toBe(1);
			expect(logs[0].summary).toContain("0命中: completely_non_existent_exploit_target_999");
			expect(logs[0].worker).toBe("worker");
			expect(logs[0].node_id).toBe(42);
		} finally {
			db.close();
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("formatSearchResults 控制输出在 60 行内并只给地图不给正文", () => {
		const res = executeKnowledgeSearch("越权", mockCatalog);
		const formatted = formatSearchResults("越权", res.results, false);
		const lineCount = formatted.split("\n").length;
		expect(lineCount).toBeLessThanOrEqual(60);
		expect(formatted).toContain("核心章节行号地图");
		expect(formatted).toContain("[L20]");
	});
});

describe("知识库构建器 buildKnowledge (零 LLM)", () => {
	it("正常构建：行号 100% 对账并生成 catalog.json", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-build-ok-"));
		try {
			const skillsDir = join(tmp, "knowledge", "skills");
			const cardsDir = join(tmp, "knowledge", "cards");
			mkdirSync(skillsDir, { recursive: true });
			mkdirSync(cardsDir, { recursive: true });

			const md = [
				"# 技能标题",
				"",
				"导言介绍",
				"",
				"## 侦察探测 (Recon)",
				"探测步骤...",
				"",
				"### 深入利用 (Deep Exploit)",
				"Payload 细节...",
			].join("\n");
			writeFileSync(join(skillsDir, "test-skill.md"), md, "utf-8");

			const card = {
				use_when: "在需要深入利用测试目标时阅读本篇。",
				triggers: ["深入利用", "Recon", "Deep Exploit"],
				vulnclass: "逻辑漏洞",
				section_map: [
					{ heading: "侦察探测 (Recon)", what: "前期资产识别" },
					{ heading: "深入利用 (Deep Exploit)", what: "攻击载荷执行" },
				],
			};
			writeFileSync(join(cardsDir, "test-skill.json"), JSON.stringify(card), "utf-8");

			const res = buildKnowledge(tmp);
			expect(res.count).toBe(1);
			expect(res.stale.length).toBe(0);

			const entry = res.catalog[0];
			expect(entry.name).toBe("test-skill");
			expect(entry.section_map[0].line).toBe(5); // ## 侦察探测 (Recon) 在第 5 行
			expect(entry.section_map[1].line).toBe(8); // ### 深入利用 (Deep Exploit) 在第 8 行
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("卡片缺失报错列出文件名", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-build-missing-"));
		try {
			const skillsDir = join(tmp, "knowledge", "skills");
			mkdirSync(skillsDir, { recursive: true });
			writeFileSync(join(skillsDir, "orphan.md"), "# Orphan", "utf-8");

			expect(() => buildKnowledge(tmp)).toThrowError(/orphan\.json.*卡片文件不存在/);
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("Schema 校验失败报错列出字段", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-build-bad-"));
		try {
			const skillsDir = join(tmp, "knowledge", "skills");
			const cardsDir = join(tmp, "knowledge", "cards");
			mkdirSync(skillsDir, { recursive: true });
			mkdirSync(cardsDir, { recursive: true });

			writeFileSync(join(skillsDir, "bad.md"), "# Bad", "utf-8");
			// triggers 必须是数组，这里给字符串
			writeFileSync(join(cardsDir, "bad.json"), JSON.stringify({ use_when: "short", triggers: "not-an-array" }), "utf-8");

			expect(() => buildKnowledge(tmp)).toThrowError(/bad\.json.*Schema 校验失败/);
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("mtime stale 报告：md 更新晚于 card 时列出 stale 清单", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-build-stale-"));
		try {
			const skillsDir = join(tmp, "knowledge", "skills");
			const cardsDir = join(tmp, "knowledge", "cards");
			mkdirSync(skillsDir, { recursive: true });
			mkdirSync(cardsDir, { recursive: true });

			writeFileSync(join(skillsDir, "stale-skill.md"), "# Heading\nContent", "utf-8");
			const card = {
				use_when: "测试 stale 场景的卡片描述。",
				triggers: ["stale"],
				vulnclass: "其他",
				section_map: [{ heading: "Heading", what: "说明" }],
			};
			writeFileSync(join(cardsDir, "stale-skill.json"), JSON.stringify(card), "utf-8");

			// 将 card 的 mtime 设为过去（10 秒前）
			const pastTime = (Date.now() - 10_000) / 1000;
			utimesSync(join(cardsDir, "stale-skill.json"), pastTime, pastTime);

			const res = buildKnowledge(tmp);
			expect(res.stale.length).toBe(1);
			expect(res.stale[0].name).toBe("stale-skill");
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("无 knowledge/catalog.json 时 isKnowledgeReady() 返回 false", () => {
		expect(isKnowledgeReady("/non/existent/path/catalog.json")).toBe(false);
	});
});
