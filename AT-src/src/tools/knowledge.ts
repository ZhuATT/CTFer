/**
 * search_knowledge 工具（K-4）
 *
 * 知识库章节地图检索工具：
 * - 双层检索：分词 → 卡片计分（triggers > use_when > section_map.what）取 top5；
 *   全 0 时纯 Node 全文扫描正文兜底；
 * - 快递单哲学：只给地图与行号，不给正文内容；worker 原生 Read(offset, limit) 精读；
 * - 两层皆 0 命中时落 activity 日志（tool=search_knowledge, summary="0命中: <query>"）；
 * - 条件装配：knowledge/catalog.json 存在才注册（agent.ts + planner.ts）。
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { logActivity } from "../db.js";

export interface KnowledgeEntry {
	name: string;
	file: string;
	use_when: string;
	triggers: string[];
	vulnclass: string;
	section_map: Array<{
		heading: string;
		what: string;
		line: number;
	}>;
}

export interface SearchKnowledgeOptions {
	db?: Database;
	taskId?: string;
	sessionId?: string;
	stepId?: number;
	workerType?: "worker" | "planner";
	knowledgeDir?: string; // 默认自动寻址 knowledge 目录
}

/** 分词：英文词（[a-zA-Z0-9_\-]+）+ 中文分词（连续汉字或二元词组） */
export function tokenizeQuery(query: string): string[] {
	const raw = query.toLowerCase().trim();
	const tokens = new Set<string>();

	// 1. 英文与数字标识符
	const enMatches = raw.match(/[a-z0-9_\-]+/g) ?? [];
	for (const m of enMatches) {
		if (m.length >= 2) tokens.add(m);
	}

	// 2. 中文连续串
	const cnMatches = raw.match(/[\u4e00-\u9fa5]+/g) ?? [];
	for (const m of cnMatches) {
		tokens.add(m);
		// 长度超过 2 时切出 bigram，提升召回率
		if (m.length > 2) {
			for (let i = 0; i <= m.length - 2; i++) {
				tokens.add(m.slice(i, i + 2));
			}
		}
	}

	return Array.from(tokens);
}

/** 双层检索逻辑实现，纯函数无副作用便于单测 */
export function executeKnowledgeSearch(
	query: string,
	catalog: KnowledgeEntry[],
	skillsDir?: string,
): {
	results: Array<{
		name: string;
		file: string;
		use_when: string;
		score: number;
		matchedTerms: string[];
		sections: Array<{ heading: string; what: string; line: number }>;
		isFallback?: boolean;
	}>;
	isFallback: boolean;
} {
	const tokens = tokenizeQuery(query);
	if (tokens.length === 0) {
		return { results: [], isFallback: false };
	}

	// ── Layer 1: 卡片计分 ──
	const scoredCards = [];
	for (const item of catalog) {
		let score = 0;
		const matched = new Set<string>();

		const triggers = (item.triggers ?? []).map((t) => t.toLowerCase());
		const useWhen = (item.use_when ?? "").toLowerCase();
		const sectionTexts = (item.section_map ?? []).map((s) => ({
			heading: s.heading,
			what: s.what,
			line: s.line,
			text: `${s.heading} ${s.what}`.toLowerCase(),
		}));

		for (const tok of tokens) {
			let tokMatched = false;
			// 1. triggers 权重最高: +10 分
			for (const trig of triggers) {
				if (trig.includes(tok) || tok.includes(trig)) {
					score += 10;
					tokMatched = true;
				}
			}
			// 2. use_when 权重次之: +3 分
			if (useWhen.includes(tok)) {
				score += 3;
				tokMatched = true;
			}
			// 3. section_map.what / heading: +1 分
			for (const sec of sectionTexts) {
				if (sec.text.includes(tok)) {
					score += 1;
					tokMatched = true;
				}
			}
			if (tokMatched) {
				matched.add(tok);
			}
		}

		if (score > 0) {
			scoredCards.push({
				name: item.name,
				file: item.file,
				use_when: item.use_when,
				score,
				matchedTerms: Array.from(matched),
				sections: item.section_map.slice(0, 8),
				isFallback: false,
			});
		}
	}

	if (scoredCards.length > 0) {
		scoredCards.sort((a, b) => b.score - a.score);
		return { results: scoredCards.slice(0, 5), isFallback: false };
	}

	// ── Layer 2: 全 0 时纯 Node 全文扫描正文兜底 ──
	if (!skillsDir || !existsSync(skillsDir)) {
		return { results: [], isFallback: false };
	}

	const fallbackMatches = [];
	try {
		const files = readdirSync(skillsDir).filter((f) => f.endsWith(".md"));
		for (const file of files) {
			const mdPath = join(skillsDir, file);
			const content = readFileSync(mdPath, "utf-8");
			const lowerContent = content.toLowerCase();

			let matchCount = 0;
			const matched = new Set<string>();
			for (const tok of tokens) {
				if (lowerContent.includes(tok)) {
					matchCount += 1;
					matched.add(tok);
				}
			}

			if (matchCount > 0) {
				const name = file.replace(/\.md$/, "");
				const catItem = catalog.find((c) => c.name === name);
				fallbackMatches.push({
					name,
					file: catItem ? catItem.file : `knowledge/skills/${file}`,
					use_when: catItem ? catItem.use_when : "全文扫描命中",
					score: matchCount,
					matchedTerms: Array.from(matched),
					sections: catItem ? catItem.section_map.slice(0, 5) : [],
					isFallback: true,
				});
			}
		}
	} catch {
		/* 尽力而为 */
	}

	fallbackMatches.sort((a, b) => b.score - a.score);
	return { results: fallbackMatches.slice(0, 5), isFallback: true };
}

/** 格式化检索结果输出，控制在 ~60 行内 */
export function formatSearchResults(
	query: string,
	results: ReturnType<typeof executeKnowledgeSearch>["results"],
	isFallback: boolean,
): string {
	if (results.length === 0) {
		return `未检索到与 "${query}" 相关的技能章节。建议更换关键词或技术概念重试。`;
	}

	const lines: string[] = [];
	lines.push(
		`针对 "${query}" 检索到 ${results.length} 篇相关技能地图${isFallback ? " (正文兜底扫描命中)" : ""}：`,
	);
	lines.push("（消费纪律：先查下方章节地图，再用原生 Read(offset, limit) 按行号精读，别凭记忆编造 payload）\n");

	for (let i = 0; i < results.length; i++) {
		const r = results[i];
		lines.push(`### ${i + 1}. ${r.name} [得分: ${r.score}] [命中: ${r.matchedTerms.join(", ")}]`);
		lines.push(`- 文件: ${r.file}`);
		lines.push(`- 适用场景: ${r.use_when}`);
		if (r.sections.length > 0) {
			lines.push("- 核心章节行号地图（请按需精读）：");
			for (const sec of r.sections.slice(0, 5)) {
				lines.push(`  - [L${sec.line}] ${sec.heading} — ${sec.what}`);
			}
		}
		lines.push("");
	}

	// 截断在 ~60 行内
	const finalLines = lines.slice(0, 60);
	return finalLines.join("\n").trim();
}

/** 判断知识库 catalog 是否就绪 */
export function isKnowledgeReady(customPath?: string): boolean {
	const p = customPath ?? resolve(process.cwd(), "knowledge", "catalog.json");
	return existsSync(p);
}

export function createSearchKnowledgeTool(opts: SearchKnowledgeOptions = {}): AgentTool<any> {
	const knowledgeDir = opts.knowledgeDir ?? resolve(process.cwd(), "knowledge");
	const catalogPath = join(knowledgeDir, "catalog.json");
	const skillsDir = join(knowledgeDir, "skills");

	let cachedCatalog: KnowledgeEntry[] | null = null;
	function getCatalog(): KnowledgeEntry[] {
		if (cachedCatalog) return cachedCatalog;
		try {
			if (existsSync(catalogPath)) {
				cachedCatalog = JSON.parse(readFileSync(catalogPath, "utf-8")) as KnowledgeEntry[];
				return cachedCatalog;
			}
		} catch {
			/* 容错 */
		}
		return [];
	}

	return {
		name: "search_knowledge",
		label: "Search Knowledge",
		description:
			"在通用渗透测试技能知识库中检索打法章节地图与行号。不熟的漏洞类/绕过手法/中间件打法，先查地图再按行号精读，别凭记忆编 payload。",
		parameters: Type.Object({
			query: Type.String({
				description: "检索关键词或概念（中英文均可，如 '时间盲注', 'IDOR', 'Docker 逃逸', 'Fastjson'）",
			}),
		}),
		execute: async (_id, params: any) => {
			const query = String(params?.query ?? "").trim();
			const catalog = getCatalog();

			const { results, isFallback } = executeKnowledgeSearch(query, catalog, skillsDir);
			const formatted = formatSearchResults(query, results, isFallback);

			// 两层皆 0 命中时，写入 activity 日志
			if (results.length === 0 && opts.db && opts.taskId) {
				logActivity(opts.db, {
					task_id: opts.taskId,
					node_id: opts.stepId,
					session_id: opts.sessionId,
					worker: opts.workerType ?? "worker",
					kind: "result",
					tool: "search_knowledge",
					is_error: false,
					summary: `0命中: ${query.slice(0, 80)}`,
					detail: `query=${query}`,
				});
			}

			return {
				content: [{ type: "text" as const, text: formatted }],
				details: null,
			};
		},
	};
}
