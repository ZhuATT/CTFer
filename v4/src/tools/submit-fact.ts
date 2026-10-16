/**
 * submit_fact（P0-2）：worker 唯一写入口——把观察到的事实写进 nodes 表。
 *
 * description 即纪律载体（§4.4 模板精髓第一次落地）：evidence 必填
 * 「命令/动作 → 最能证明的输出」、confidence 枚举 observed/inferred。
 * 契约在应用层（桶四 #7）：JSON Schema 给模型，zod 在 execute 里二次校验。
 */
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { z } from "zod";
import { insertFact, type FactPayload } from "../db.js";

const FactArgs = z.object({
	summary: z.string().min(4).max(500),
	evidence: z.string().min(4).max(2000),
	confidence: z.enum(["observed", "inferred"]),
	tags: z.array(z.string().max(40)).max(10).optional(),
});

const PARAMETERS = Type.Object({
	summary: Type.String({
		description: "一句话事实：在哪看到了什么（≤200字）",
	}),
	evidence: Type.String({
		description: "一行可复核证据，格式「命令/动作 → 最能证明的输出片段」",
	}),
	confidence: Type.Union([Type.Literal("observed"), Type.Literal("inferred")], {
		description: "observed=工具输出直接证明；inferred=由观察推断",
	}),
	tags: Type.Optional(Type.Array(Type.String(), { description: "可选标签，如 [recon, auth]" })),
});

const OUTPUT_SCHEMA = Type.Object({
	id: Type.String(),
	dedup: Type.Boolean(),
});

export function createSubmitFactTool(db: Database): AgentTool<any> {
	return {
		name: "submit_fact",
		label: "Submit fact",
		description: [
			"把一条你亲眼确认过的事实写入知识库（SQLite nodes 表）。",
			"微纪律（违反会被打回）：",
			"- summary：一句话说清「在哪、看到了什么」，≤200字。",
			"- evidence：必填一行「命令/动作 → 最能证明该事实的输出片段」。",
			"  例：browser_navigate https://example.com → <title>Example Domain</title>。",
			"  没有可复核 evidence 的事实不收。",
			"- confidence：observed=工具输出直接证明；inferred=由观察推断得出。拿不准填 inferred，宁 observed 勿臆断。",
		].join("\n"),
		parameters: PARAMETERS,
		outputSchema: OUTPUT_SCHEMA,
		execute: async (_toolCallId, params) => {
			const parsed = FactArgs.safeParse(params);
			if (!parsed.success) {
				const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
				throw new Error(`submit_fact 参数不合规：${issues}`);
			}
			const payload: FactPayload = {
				summary: parsed.data.summary,
				evidence: parsed.data.evidence,
				confidence: parsed.data.confidence,
				...(parsed.data.tags ? { tags: parsed.data.tags } : {}),
			};
			const { id, dedup } = insertFact(db, payload, "worker");
			return {
				content: [{ type: "text", text: `已入库 fact ${id}（dedup=${dedup}）` }],
				details: { id, dedup },
				structuredContent: { id, dedup },
			};
		},
	};
}
