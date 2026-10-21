/**
 * 资产工具面（P3-4）：
 * - worker: register_asset（D3：只登记不浏览，发现不受 scope 限，但发现≠授权）
 * - planner: list_assets（scope 资产查询 + anchor_count 未测面导向）
 */
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { listAssetsInScope, registerAsset } from "../assets.js";

function textResult(text: string) {
	return { content: [{ type: "text" as const, text }], details: null };
}

export interface RegisterAssetToolOptions {
	assetsDb: Database;
	taskId: string;
	project?: string;
}

export function createRegisterAssetTool(opts: RegisterAssetToolOptions): AgentTool<any> {
	return {
		name: "register_asset",
		label: "Register asset",
		description: [
			"侦察发现的客观资产（子域/端口/端点；凭据线索写 note）——发现就登记，登记不受 scope 限制；",
			"但发现约束外新目标≠获得授权，动手与否由规划者/操作员决定。探索结论走 submit_fact，别串。",
		].join("\n"),
		parameters: Type.Object({
			host: Type.String({ description: "资产域名或 IP" }),
			type: Type.Optional(
				Type.Union([Type.Literal("subdomain"), Type.Literal("ip"), Type.Literal("endpoint")], {
					description: "资产类型（默认自动判断）",
				}),
			),
			port: Type.Optional(Type.Number({ description: "端口号" })),
			url: Type.Optional(Type.String({ description: "完整 URL 或端点路径" })),
			note: Type.Optional(Type.String({ description: "线索/凭据/上下文说明" })),
		}),
		outputSchema: Type.Object({ id: Type.Number(), created: Type.Boolean() }),
		execute: async (_id, params: any) => {
			const res = registerAsset(
				opts.assetsDb,
				opts.taskId,
				{
					host: String(params?.host ?? ""),
					...(params?.type ? { type: params.type } : {}),
					...(params?.port !== undefined ? { port: Number(params.port) } : {}),
					...(params?.url ? { url: String(params.url) } : {}),
					...(params?.note ? { note: String(params.note) } : {}),
				},
				opts.project ?? "default",
			);
			const msg = res.created
				? `已登记新资产 #${res.asset.id} [${res.asset.type}] ${res.asset.url}`
				: `已有资产 #${res.asset.id} [${res.asset.type}] ${res.asset.url}（幂等复用）`;
			return { ...textResult(msg), structuredContent: { id: res.asset.id, created: res.created } };
		},
	};
}

export interface ListAssetsToolOptions {
	assetsDb: Database;
	taskId: string;
}

export function createListAssetsTool(opts: ListAssetsToolOptions): AgentTool<any> {
	return {
		name: "list_assets",
		label: "List assets",
		description: [
			"查看当前 task scope 内的已知资产列表（分页 20，支持 host 模糊搜索 q）。",
			"回执包含每个资产的 anchor_count（被 fact 锚定的次数）。",
			"语义导读：anchor_count=0 的资产表示尚未被任何 fact 锚定，即未测面（untouched coverage）。",
		].join("\n"),
		parameters: Type.Object({
			page: Type.Optional(Type.Number({ description: "页码，从 1 起，默认 1" })),
			q: Type.Optional(Type.String({ description: "host 或 url 模糊搜索关键词" })),
		}),
		execute: async (_id, params: any) => {
			const page = Math.max(1, Number(params?.page) || 1);
			const q = params?.q ? String(params.q).trim() : undefined;
			const res = listAssetsInScope(opts.assetsDb, opts.taskId, { page, pageSize: 20, q });
			const formatted = {
				page: res.page,
				total: res.total,
				has_more: res.page * res.pageSize < res.total,
				assets: res.assets.map((a) => ({
					id: a.id,
					type: a.type,
					host: a.host,
					port: a.port,
					url: a.url,
					anchored_by_facts: a.anchor_count,
				})),
			};
			return textResult(JSON.stringify(formatted, null, 1));
		},
	};
}
