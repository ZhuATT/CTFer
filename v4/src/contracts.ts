/**
 * payload 契约（P1-0）——四种节点形状，照设计文档 §2.6「payload 四种形状」。
 *
 * 桶四 #7：契约放应用层（zod）不放 DDL——加枚举零迁移，进件时可报人话错误。
 * 这些形状同时是工具参数的 JSON Schema 来源（工具面用 Type 从 zod 形状手抄，
 * 校验以这里为准）。
 */
import { z } from "zod";

export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;

export const Confidence = z.enum(["observed", "inferred"]);
export type Confidence = z.infer<typeof Confidence>;

/** fact：一条一断言 + 证据指针（文件化，evidence/ 目录内相对路径）。 */
export const FactPayload = z.object({
	summary: z.string().min(4).max(500),
	detail: z.string().max(5000).optional(),
	evidence: z.string().min(3).max(500),
	confidence: Confidence,
	endpoint: z.string().max(500).optional(),
});
export type FactPayload = z.infer<typeof FactPayload>;

/** step：一句话方向 + 打法说明（planner 写；P1 由 seed 夹具/调用方给）。 */
export const StepPayload = z.object({
	summary: z.string().min(4).max(500),
	note: z.string().max(3000).optional(),
	asset_ids: z.array(z.number().int()).optional(),
	parent_ids: z.array(z.number().int()).optional(),
});
export type StepPayload = z.infer<typeof StepPayload>;

/** goal：可判定的完成标准（+可选量化条件）。 */
export const GoalPayload = z.object({
	text: z.string().min(4).max(1000),
	quantifier: z
		.object({ metric: z.string().min(1), target: z.number() })
		.nullish(),
});
export type GoalPayload = z.infer<typeof GoalPayload>;

/** finding：严门——poc/severity/vulnclass/evidence 全必填；retest 是回写区。
 * endpoint（p2fix P2F-2）：机器可解析端点，供 noreport 端点形状终审（.map 拒单）。 */
export const FindingPayload = z.object({
	summary: z.string().min(4).max(500),
	vulnclass: z.string().min(2).max(80),
	severity: Severity,
	poc: z.string().min(4).max(5000),
	report: z.string().max(20000).optional(),
	evidence: z.string().min(3).max(500),
	endpoint: z.string().max(500).optional(),
	retest: z
		.object({
			verdict: z.enum(["reproduced", "fixed", "inconclusive"]),
			at: z.string(),
			summary: z.string(),
		})
		.optional(),
});
export type FindingPayload = z.infer<typeof FindingPayload>;

/** summary 去重归一化：trim + 空白合一 + 小写。 */
export function normalizeSummary(s: string): string {
	return s.trim().replace(/\s+/g, " ").toLowerCase();
}
