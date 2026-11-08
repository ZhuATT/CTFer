/**
 * build-knowledge.mjs — 知识库目录组装与行号对账（K-3）
 *
 * 职责（零 LLM）：
 * 1. zod 严格校验 cards/*.json 四字段
 * 2. 检查 skills/*.md 与 cards/*.json 的 mtime，输出 stale 报告
 * 3. 程序解析 md 标题行（1-based 行号），精准回填 section_map[].line
 * 4. 组装合成 knowledge/catalog.json（唯一真相源）
 */

import { readdirSync, readFileSync, writeFileSync, statSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = join(__dirname, "..");

export const CardSchema = z.object({
	use_when: z.string().min(5),
	triggers: z.array(z.string().min(1)).min(1),
	vulnclass: z.string().min(2),
	section_map: z.array(
		z.object({
			heading: z.string().min(1),
			what: z.string().min(1),
		}),
	),
});

/**
 * 从 markdown 正文中解析所有标题行及行号
 * 返回: Array<{ line: number, level: number, text: string }>
 */
export function extractHeadingsFromMd(mdContent) {
	const lines = mdContent.split(/\r?\n/);
	const headings = [];

	for (let i = 0; i < lines.length; i++) {
		const rawLine = lines[i];
		const trimmed = rawLine.trim();
		const match = /^(#{1,6})\s+(.+)$/.exec(trimmed);
		if (match) {
			const level = match[1].length;
			let text = match[2].trim();
			// 去除尾部可能存在的 # 号或 markdown 链接
			text = text.replace(/#+$/, "").trim();
			headings.push({
				line: i + 1, // 1-based 行号
				level,
				text,
				normText: normalizeHeading(text),
			});
		}
	}
	return headings;
}

function normalizeHeading(s) {
	return s
		.toLowerCase()
		.replace(/[#*_`~\[\]\(\)\-\—\:\/]/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

/**
 * 针对 section_map 中的 heading，在 md 标题列表中寻找最佳匹配行号。
 * 返回 { line, tier }（F-7a：五层各标 tier，非 exact 对齐收集进警告清单——
 * 规范化差异（em-dash/U+2011/LLM 改写编号）曾静默落错行 13 处被"100%对账"掩盖）。
 */
export function matchHeadingLine(heading, headings, mdContent) {
	if (!headings || headings.length === 0) return { line: 1, tier: "none" };

	const normTarget = normalizeHeading(heading);
	if (!normTarget) return { line: 1, tier: "none" };

	// 1. 精确规范化匹配
	for (const h of headings) {
		if (h.normText === normTarget) {
			return { line: h.line, tier: "exact" };
		}
	}

	// 2. 包含匹配 (target in title 或 title in target)
	let bestMatch = null;
	let maxScore = 0;

	const targetTokens = new Set(normTarget.split(" ").filter((w) => w.length > 1));

	for (const h of headings) {
		if (h.normText.includes(normTarget) || normTarget.includes(h.normText)) {
			return { line: h.line, tier: "contains" };
		}

		// 3. Token Jaccard 重叠度计分
		const hTokens = h.normText.split(" ").filter((w) => w.length > 1);
		let overlap = 0;
		for (const t of hTokens) {
			if (targetTokens.has(t)) overlap++;
		}
		if (overlap > maxScore) {
			maxScore = overlap;
			bestMatch = h.line;
		}
	}

	if (bestMatch && maxScore >= 1) {
		return { line: bestMatch, tier: "tokens" };
	}

	// 4. 兜底：正文文本搜索 heading
	const lines = mdContent.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].toLowerCase().includes(heading.toLowerCase().trim())) {
			return { line: i + 1, tier: "text" };
		}
	}

	return { line: 1, tier: "none" };
}

/**
 * 核心构建函数
 */
export function buildKnowledge(rootDir = DEFAULT_ROOT) {
	const skillsDir = join(rootDir, "knowledge", "skills");
	const cardsDir = join(rootDir, "knowledge", "cards");
	const catalogPath = join(rootDir, "knowledge", "catalog.json");

	if (!existsSync(skillsDir)) {
		throw new Error(`skills 目录不存在: ${skillsDir}`);
	}

	// F-7b：card→catalog stale 双保险——catalog 旧于任一 card = 有人改卡忘重组，运行时零告警用旧图
	const staleCatalog = [];
	if (existsSync(catalogPath)) {
		const catalogMtimeMs = statSync(catalogPath).mtimeMs;
		for (const f of readdirSync(cardsDir)) {
			if (!f.endsWith(".json")) continue;
			const m = statSync(join(cardsDir, f)).mtimeMs;
			if (m > catalogMtimeMs) {
				staleCatalog.push({ card: f, cardMtime: new Date(m).toISOString() });
			}
		}
	}

	const mdFiles = readdirSync(skillsDir)
		.filter((f) => f.endsWith(".md"))
		.sort();

	const errors = [];
	const staleList = [];
	const warnings = []; // F-7a：非精确对齐清单
	const catalog = [];

	for (const file of mdFiles) {
		const name = basename(file, ".md");
		const cardPath = join(cardsDir, `${name}.json`);
		const mdPath = join(skillsDir, file);

		// 1. 检查卡片存在性
		if (!existsSync(cardPath)) {
			errors.push({ file: `${name}.json`, error: "卡片文件不存在" });
			continue;
		}

		// 2. mtime 检查 (stale 报告)
		const mdStat = statSync(mdPath);
		const cardStat = statSync(cardPath);
		if (mdStat.mtimeMs > cardStat.mtimeMs) {
			staleList.push({
				name,
				mdMtime: mdStat.mtime.toISOString(),
				cardMtime: cardStat.mtime.toISOString(),
			});
		}

		// 3. 读取并 zod 校验卡片
		let rawCard;
		try {
			rawCard = JSON.parse(readFileSync(cardPath, "utf-8"));
		} catch (e) {
			errors.push({ file: `${name}.json`, error: `JSON 解析失败: ${e.message}` });
			continue;
		}

		const parsed = CardSchema.safeParse(rawCard);
		if (!parsed.success) {
			errors.push({
				file: `${name}.json`,
				error: `Schema 校验失败: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
			});
			continue;
		}

		const card = parsed.data;

		// 4. 解析 md 标题并回填行号
		const mdContent = readFileSync(mdPath, "utf-8");
		const headings = extractHeadingsFromMd(mdContent);

		const sectionMapWithLines = card.section_map.map((sec) => {
			const { line, tier } = matchHeadingLine(sec.heading, headings, mdContent);
			if (tier !== "exact") {
				warnings.push({ name, heading: sec.heading, line, tier });
			}
			return {
				heading: sec.heading,
				what: sec.what,
				line,
			};
		});

		catalog.push({
			name,
			file: `knowledge/skills/${file}`,
			use_when: card.use_when,
			triggers: card.triggers,
			vulnclass: card.vulnclass,
			section_map: sectionMapWithLines,
		});
	}

	if (errors.length > 0) {
		const msg = `知识库校验失败，发现 ${errors.length} 处错误:\n` + errors.map((e) => `  - [${e.file}] ${e.error}`).join("\n");
		const err = new Error(msg);
		err.errors = errors;
		err.stale = staleList;
		throw err;
	}

	// 写入 catalog.json
	writeFileSync(catalogPath, JSON.stringify(catalog, null, 2), "utf-8");

	return {
		catalog,
		count: catalog.length,
		stale: staleList,
		staleCatalog, // F-7b：catalog 旧于卡片的清单
		warnings, // F-7a：非精确对齐清单
	};
}

// CLI 执行入口
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	try {
		console.log("[K-3] 开始组装知识库 catalog.json...");
		const res = buildKnowledge(DEFAULT_ROOT);
		console.log(`✓ 构建成功！收录技能: ${res.count} 篇`);
		if (res.stale.length > 0) {
			console.warn(`! 发现 ${res.stale.length} 篇卡片过期 (md mtime 晚于卡片):`);
			for (const s of res.stale) {
				console.warn(`  - ${s.name}: md=${s.mdMtime}, card=${s.cardMtime}`);
			}
		} else {
			console.log("✓ 全部卡片与语料 mtime 对账一致 (零 stale)");
		}
		if (res.staleCatalog.length > 0) {
			console.warn(`! catalog 旧于 ${res.staleCatalog.length} 张卡片 (card mtime 晚于 catalog——改卡后需重组 catalog):`);
			for (const s of res.staleCatalog) {
				console.warn(`  - ${s.card}: card=${s.cardMtime}`);
			}
		}
		if (res.warnings.length > 0) {
			console.warn(`! ${res.warnings.length} 个 heading 非精确对齐 (tier 清单——错位会把精读窗口带偏):`);
			for (const w of res.warnings) {
				console.warn(`  - [${w.name}] "${w.heading}" → L${w.line} (${w.tier})`);
			}
		}
	} catch (e) {
		console.error("✗ 构建失败:\n", e.message);
		process.exit(1);
	}
}
