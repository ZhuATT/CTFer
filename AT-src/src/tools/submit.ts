/**
 * submit 工具（P1-2）：worker 的图写入口——submit_fact v2 / submit_finding。
 *
 * 工具本体是薄壳：全部校验/去重/落边/哈希在 graph.ts（程序侧），工具描述
 * 承载微纪律（§4.4：纪律住工具描述）。step_id 必填=快递单哲学——程序见参数
 * 直接落 produces 边。
 */
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { submitFact, submitFinding } from "../graph.js";
import type { Confidence, Severity } from "../contracts.js";

export interface SubmitToolOptions {
	db: Database;
	taskId: string;
	taskDir: string;
	sessionId?: string;
	assetsDb?: Database;
}

function textResult(text: string) {
	return { content: [{ type: "text" as const, text }], details: null };
}

export function createSubmitFactTool(opts: SubmitToolOptions): AgentTool<any> {
	return {
		name: "submit_fact",
		label: "Submit fact",
		description: [
			"把一条你亲眼确认过的事实写进任务图（一条一断言）。微纪律（违反会被打回）：",
			"- step_id：你领到的 step 编号（user 消息里有），产出挂树全靠它；",
			"- summary：一句话断言「在哪、看到了什么」，只写增量、只写真实看到的；",
			"- evidence：证据文件相对路径（先用 Write 写进 evidence/<名>.txt，内容=一行命令 + 最能证明的一两行输出），没有可复核证据不收；",
			"- confidence：observed=工具输出直接证明；inferred=由观察推断。拿不准填 inferred；",
			"- 多个观察各自一条，别攒；瞥见别的线索也各成一条上抛，自己不动手。",
			"同一 summary 重复提交会返回已有 id（幂等，无害）。",
		].join("\n"),
		parameters: Type.Object({
			step_id: Type.Number({ description: "你领到的 step 编号" }),
			summary: Type.String({ description: "一句话断言：在哪、看到了什么" }),
			evidence: Type.String({ description: "证据文件相对路径（evidence/ 下）" }),
			confidence: Type.Union([Type.Literal("observed"), Type.Literal("inferred")], {
				description: "observed=直接看到；inferred=推断",
			}),
			detail: Type.Optional(Type.String({ description: "可选：对断言的拓展说明" })),
			endpoint: Type.Optional(Type.String({ description: "可选：机器可解析端点，如 /jsxsd/foo.do" })),
		}),
		outputSchema: Type.Object({ id: Type.Number(), dedup: Type.Boolean() }),
		execute: async (_id, params: any) => {
			const res = submitFact(opts.db, {
				taskId: opts.taskId,
				taskDir: opts.taskDir,
				stepId: Number(params?.step_id),
				sessionId: opts.sessionId,
				assetsDb: opts.assetsDb,
				payload: {
					summary: String(params?.summary ?? ""),
					evidence: String(params?.evidence ?? ""),
					confidence: params?.confidence as Confidence,
					...(params?.detail ? { detail: String(params.detail) } : {}),
					...(params?.endpoint ? { endpoint: String(params.endpoint) } : {}),
				},
			});
			const msg = res.dedup
				? `重复事实，返回已有 fact #${res.id}（幂等）`
				: `已入库 fact #${res.id}（produces 边已落）`;
			return { ...textResult(msg), structuredContent: { id: res.id, dedup: res.dedup } };
		},
	};
}

export function createSubmitFindingTool(opts: SubmitToolOptions): AgentTool<any> {
	return {
		name: "submit_finding",
		label: "Submit finding",
		description: [
			"上报漏洞候选（严门）。微纪律：",
			"- 真实触发过 + 可复现才报；CVE/指纹/漏洞库推断 ≠ 确认——那只是 inferred fact，用 submit_fact；",
			"- poc：最小复现命令（别人复制粘贴就能打中）；",
			"- evidence：证据文件相对路径（Write 进 evidence/，内容=请求/响应关键部分）；",
			"- vulnclass：漏洞类（越权/注入/未授权访问/信息泄露…）；severity：info/low/medium/high/critical 自评；",
			"- related_fact_ids：可选，支撑该漏洞的已有 fact 编号（血缘会连 proves 边）。",
			"severity 定级拿不准时，Read `standards/<目标厂商>.txt` 查该厂商评级细则（Grep 关键节，不全量读）；目标厂商不在列则按通用自评。",
			"提交后 state=reported，等待复测（P4），不要自己反复打同一洞。",
		].join("\n"),
		parameters: Type.Object({
			step_id: Type.Number({ description: "发现该漏洞时所在的 step 编号" }),
			summary: Type.String({ description: "一句话：什么漏洞在哪个点" }),
			vulnclass: Type.String({ description: "漏洞类，如 越权/SQLi/未授权访问" }),
			severity: Type.Union(
				[Type.Literal("info"), Type.Literal("low"), Type.Literal("medium"), Type.Literal("high"), Type.Literal("critical")],
				{ description: "严重度自评" },
			),
			poc: Type.String({ description: "最小复现命令" }),
			evidence: Type.String({ description: "证据文件相对路径（evidence/ 下）" }),
			report: Type.Optional(Type.String({ description: "可选：结构化报告正文" })),
			endpoint: Type.Optional(Type.String({ description: "可选：机器可解析端点，如 /static/app.js.map" })),
			related_fact_ids: Type.Optional(Type.Array(Type.Number(), { description: "支撑性 fact 编号列表" })),
		}),
		outputSchema: Type.Object({ id: Type.Number() }),
		execute: async (_id, params: any) => {
			const res = submitFinding(opts.db, {
				taskId: opts.taskId,
				taskDir: opts.taskDir,
				stepId: Number(params?.step_id),
				sessionId: opts.sessionId,
				assetsDb: opts.assetsDb,
				...(Array.isArray(params?.related_fact_ids) ? { relatedFactIds: params.related_fact_ids.map(Number) } : {}),
				payload: {
					summary: String(params?.summary ?? ""),
					vulnclass: String(params?.vulnclass ?? ""),
					severity: params?.severity as Severity,
					poc: String(params?.poc ?? ""),
					evidence: String(params?.evidence ?? ""),
					...(params?.report ? { report: String(params.report) } : {}),
					...(params?.endpoint ? { endpoint: String(params.endpoint) } : {}),
				},
			});
			return {
				...textResult(`finding #${res.id} 已入图（state=reported，等待复测）`),
				structuredContent: { id: res.id },
			};
		},
	};
}
