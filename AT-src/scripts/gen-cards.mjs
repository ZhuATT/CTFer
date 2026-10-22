/**
 * gen-cards.mjs — 知识库检索卡生成管线（K-2）
 *
 * 99 篇语料逐篇调用 LLM（glm-5.3）提取四字段检索卡：
 * - use_when: 中文一句话（做什么 + 何时读我）
 * - triggers: 10-20 个中英混合触发词（仅从正文提取，禁止幻觉）
 * - vulnclass: 漏洞大类（对齐受控词表）
 * - section_map: 章节地图（heading + what，行号由 build-knowledge.mjs 补齐）
 *
 * 特性：
 * - 断点续跑：已有 cards/<name>.json 默认跳过
 * - 失败重试 2 次（指数退避）
 * - 并发控制（默认 3）
 * - 10 条 smoke query 人工扫视
 */

import { readdirSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { Agent } from "@earendil-works/pi-agent-core";
import { createChannelFromConfig } from "../dist/channel.js";
import { loadSecrets } from "../dist/secrets.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, "..");
const SKILLS_DIR = join(ROOT_DIR, "knowledge", "skills");
const CARDS_DIR = join(ROOT_DIR, "knowledge", "cards");

mkdirSync(CARDS_DIR, { recursive: true });

const SMOKE_QUERIES = [
	"时间盲注 payload",
	"IDOR 水平越权检测",
	"kerberoasting golden ticket",
	"Fastjson 反序列化 gadget",
	"SSRF bypass cloud metadata",
	"Docker 容器逃逸 release_agent",
	"JWT 签名绕过 none 算法",
	"SSTI 模板注入 render",
	"Linux SUID 提权",
	"GraphQL introspection 泄露",
];

const SYSTEM_PROMPT = `你是一个网络安全知识库元数据专家。你的任务是根据提供的安全技能文档（Markdown 格式），为安全 Agent 检索系统生成高质量的检索卡（JSON 格式）。

【严格准则 (Rubric)】：
1. use_when: 必须是【中文一句话】，格式如「在[场景]下需要[做什么]时阅读本篇，重点涵盖[关键技术/工具]，区别于[差异角度]」。禁止空话套话，必须包含文档关键术语。
2. triggers: 必须是 10-20 个关键词的字符串数组，中英混合（英文文档必须补齐中文黑客实战称谓与漏洞别名，中文文档必须补齐英文术语），且必须仅从正文概念提取，严禁幻觉！
3. vulnclass: 漏洞大类，必须是单个中文大类字符串（如：越权、SQL注入、XSS、SSRF、RCE、未授权访问、信息泄露、逻辑漏洞、命令注入、反序列化、文件上传、XXE、SSTI、认证绕过、路径穿越、配置错误、中间件漏洞、密码学缺陷、网络与内网、提权、其他）。
4. section_map: 章节地图数组（提取正文 4-15 个核心技术章节）：
   [
     { "heading": "章节原文标题（去掉前缀 #）", "what": "中文一句话简述该节技术手法或操作" }
   ]
   无需计算行号，行号由后续程序自动补齐。

【范例格式】：
{
  "use_when": "在渗透测试中评估 Web 应用的 SQL 注入风险及探测盲注/WAF绕过时阅读本篇，涵盖报错、联合、布尔/时间盲注、带外通道及主流数据库针对性利用手法。",
  "triggers": [
    "SQL注入", "SQL injection", "SQLi", "报错注入", "联合查询注入",
    "UNION SELECT", "布尔盲注", "时间盲注", "time-based blind", "WAF绕过",
    "sqlmap", "二阶注入", "堆叠注入", "xp_cmdshell", "LOAD_FILE", "sleep"
  ],
  "vulnclass": "SQL注入",
  "section_map": [
    { "heading": "Detection", "what": "全输入入口基础注入探测字符与判断逻辑" },
    { "heading": "Time-Based Blind", "what": "基于时间的盲注探测手法与数据库延时函数" },
    { "heading": "WAF Bypass Techniques", "what": "大小写、注释混淆与编码绕过 WAF 过滤策略" }
  ]
}

只输出纯 JSON 对象，不要包裹在 \`\`\`json 代码块中，不要输出任何额外的解释文本。`;

function cleanJsonText(raw) {
	let text = raw.trim();
	// 匹配最外层的 { ... }
	const start = text.indexOf("{");
	const end = text.lastIndexOf("}");
	if (start !== -1 && end !== -1 && end > start) {
		text = text.slice(start, end + 1);
	}
	return text.trim();
}

function normalizeCardJson(data) {
	if (!data || typeof data !== "object") {
		throw new Error("Invalid card data: not an object");
	}

	// 1. use_when
	let useWhen = data.use_when;
	if (Array.isArray(useWhen)) useWhen = useWhen.join("，");
	if (typeof useWhen !== "string" || !useWhen.trim()) {
		throw new Error("Missing or empty use_when");
	}

	// 2. triggers
	let triggers = data.triggers;
	if (!Array.isArray(triggers)) {
		if (typeof triggers === "string") {
			triggers = triggers.split(/[,，、|]/).map((s) => s.trim());
		} else {
			triggers = [];
		}
	}
	triggers = triggers
		.map((t) => String(t).trim())
		.filter((t) => t.length > 0 && t.length < 50);
	if (triggers.length === 0) {
		throw new Error("Missing or empty triggers");
	}
	// 截取前 20 个
	if (triggers.length > 20) {
		triggers = triggers.slice(0, 20);
	}

	// 3. vulnclass
	let vulnclass = data.vulnclass;
	if (Array.isArray(vulnclass)) vulnclass = vulnclass[0];
	if (typeof vulnclass !== "string" || !vulnclass.trim()) {
		vulnclass = "其他";
	}
	vulnclass = vulnclass.trim();

	// 4. section_map
	let sectionMap = data.section_map;
	if (!Array.isArray(sectionMap)) {
		if (sectionMap && typeof sectionMap === "object") {
			// 对象转数组
			sectionMap = Object.entries(sectionMap).map(([k, v]) => ({
				heading: k,
				what: typeof v === "string" ? v : JSON.stringify(v),
			}));
		} else {
			sectionMap = [];
		}
	}
	sectionMap = sectionMap
		.filter((s) => s && (s.heading || s.title))
		.map((s) => ({
			heading: String(s.heading || s.title || "").trim(),
			what: String(s.what || s.description || s.summary || "").trim(),
		}));

	return {
		use_when: useWhen.trim(),
		triggers,
		vulnclass,
		section_map: sectionMap,
	};
}

async function callLlmForCard(channel, mdContent, maxRetries = 2) {
	let lastErr = null;
	for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
		try {
			const agent = new Agent({
				initialState: {
					systemPrompt: SYSTEM_PROMPT,
					tools: [],
					model: channel.model,
					thinkingLevel: channel.thinkingLevel,
				},
				streamFn: channel.streamFn,
				getApiKey: async () => channel.apiKey,
			});

			const texts = [];
			agent.subscribe((ev) => {
				if (ev.type === "message_end") {
					const msg = ev.message;
					if (msg?.role === "assistant" && Array.isArray(msg.content)) {
						const t = msg.content
							.filter((c) => c.type === "text" && c.text?.trim())
							.map((c) => c.text)
							.join("\n");
						if (t) texts.push(t);
					}
				}
			});

			// 语料前 30,000 字符已足够覆盖 TOC、各章节骨架及核心 payload
			const truncated = mdContent.slice(0, 30_000);
			await agent.prompt(`请阅读以下安全技能文档并输出检索卡 JSON：\n\n${truncated}`);

			const finalText = texts[texts.length - 1] || "";
			if (!finalText.trim()) {
				throw new Error("模型未返回任何文本内容");
			}

			const cleaned = cleanJsonText(finalText);
			const rawJson = JSON.parse(cleaned);
			const card = normalizeCardJson(rawJson);
			return card;
		} catch (err) {
			lastErr = err;
			console.warn(`  [重试 ${attempt}/${maxRetries + 1}] 失败: ${err instanceof Error ? err.message : String(err)}`);
			if (attempt <= maxRetries) {
				await new Promise((r) => setTimeout(r, 2000 * attempt));
			}
		}
	}
	throw lastErr;
}

async function asyncPool(limit, items, iteratorFn) {
	const ret = [];
	const executing = [];
	for (const item of items) {
		const p = Promise.resolve().then(() => iteratorFn(item));
		ret.push(p);
		if (limit <= items.length) {
			const e = p.then(() => executing.splice(executing.indexOf(e), 1));
			executing.push(e);
			if (executing.length >= limit) {
				await Promise.race(executing);
			}
		}
	}
	return Promise.all(ret);
}

async function main() {
	const args = process.argv.slice(2);
	const force = args.includes("--force");
	const concurrencyIdx = args.indexOf("--concurrency");
	const concurrency = concurrencyIdx !== -1 ? parseInt(args[concurrencyIdx + 1], 10) : 3;
	const fileIdx = args.indexOf("--file");
	const specificFile = fileIdx !== -1 ? args[fileIdx + 1] : null;

	console.log(`[K-2] 检索卡生成管线启动 (concurrency=${concurrency}, force=${force})`);

	const secrets = loadSecrets();
	const channel = createChannelFromConfig(
		{
			model: "glm-5.3",
			api: "anthropic",
			keyEnv: "AT1_API_KEY",
			baseUrl: "https://open.bigmodel.cn/api/anthropic",
			thinkingLevel: "low",
			contextWindow: 1_000_000,
			maxTokens: 8192,
		},
		secrets,
	);

	let mdFiles = readdirSync(SKILLS_DIR).filter((f) => f.endsWith(".md"));
	if (specificFile) {
		mdFiles = mdFiles.filter((f) => f === specificFile || f === `${specificFile}.md`);
	}
	mdFiles.sort();

	console.log(`目标技能文件数: ${mdFiles.length}`);

	const stats = { total: mdFiles.length, success: 0, skipped: 0, failed: [] };

	await asyncPool(concurrency, mdFiles, async (file) => {
		const name = basename(file, ".md");
		const cardPath = join(CARDS_DIR, `${name}.json`);

		if (!force && existsSync(cardPath)) {
			try {
				const existing = JSON.parse(readFileSync(cardPath, "utf-8"));
				if (existing.use_when && existing.triggers && Array.isArray(existing.triggers) && existing.triggers.length > 0) {
					stats.skipped += 1;
					process.stdout.write(".");
					return;
				}
			} catch {
				// corrupt, regenerate
			}
		}

		const mdPath = join(SKILLS_DIR, file);
		const mdContent = readFileSync(mdPath, "utf-8");

		console.log(`\n生成卡片: ${name}...`);
		try {
			const card = await callLlmForCard(channel, mdContent, 2);
			writeFileSync(cardPath, JSON.stringify(card, null, 2), "utf-8");
			stats.success += 1;
			console.log(`✓ 成功: ${name} [${card.vulnclass}] (triggers: ${card.triggers.length}, sections: ${card.section_map.length})`);
		} catch (err) {
			console.error(`✗ 失败: ${name} - ${err instanceof Error ? err.message : String(err)}`);
			stats.failed.push({ file, error: String(err) });
		}
	});

	console.log("\n=================== 统计报告 ===================");
	console.log(`总数: ${stats.total}`);
	console.log(`成功: ${stats.success}`);
	console.log(`跳过 (已存在): ${stats.skipped}`);
	console.log(`失败: ${stats.failed.length}`);
	if (stats.failed.length > 0) {
		console.log("失败清单:", JSON.stringify(stats.failed, null, 2));
	}
	console.log("================================================\n");

	runSmokeCheck();
}

function runSmokeCheck() {
	console.log("--- 10 条 Smoke Query 扫视 (人工快速复核) ---");
	const cardFiles = readdirSync(CARDS_DIR).filter((f) => f.endsWith(".json"));
	const cards = cardFiles.map((f) => {
		const name = basename(f, ".json");
		const data = JSON.parse(readFileSync(join(CARDS_DIR, f), "utf-8"));
		return { name, ...data };
	});

	for (const q of SMOKE_QUERIES) {
		const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
		const matches = [];

		for (const card of cards) {
			let score = 0;
			const triggers = (card.triggers || []).map((t) => String(t).toLowerCase());
			const useWhen = String(card.use_when || "").toLowerCase();
			const sections = (card.section_map || []).map((s) => `${s.heading} ${s.what}`.toLowerCase());

			for (const term of terms) {
				if (triggers.some((t) => t.includes(term))) score += 10;
				if (useWhen.includes(term)) score += 3;
				if (sections.some((s) => s.includes(term))) score += 1;
			}

			if (score > 0) {
				matches.push({ name: card.name, score, use_when: card.use_when });
			}
		}

		matches.sort((a, b) => b.score - a.score);
		const top = matches.slice(0, 2);
		console.log(`\nQuery: [${q}] -> 命中 ${matches.length} 篇`);
		if (top.length === 0) {
			console.log("  (未命中)");
		} else {
			for (const m of top) {
				console.log(`  - [得分 ${m.score}] ${m.name}: ${m.use_when}`);
			}
		}
	}
	console.log("\n--------------------------------------------");
}

main().catch((err) => {
	console.error("gen-cards 致命错误:", err);
	process.exit(1);
});
