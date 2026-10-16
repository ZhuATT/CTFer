/**
 * guard 闸机（P0-3 最小版）：beforeToolCall 钩子。
 *
 * - 全量审计：每次工具调用落 activity 表（{ts,tool,action,params摘要}）。
 * - 假规则验证 block 通路：submit_fact 的 summary 含管控词则拒。
 * - block 消息用平台管控框架（§4.3）：「平台管控·非目标防御」+ 原因 + 正确做法
 *   ——第一天就养成正确语义，防 worker 把拦截当攻击目标。
 */
import type { Database } from "better-sqlite3";
import type { BeforeToolCallContext, BeforeToolCallResult } from "@earendil-works/pi-agent-core";
import { logActivity } from "./db.js";

export interface GuardOptions {
	sessionId?: string;
	/** 触发 block 的关键词（对 submit_fact.summary 生效）。默认 ["test-block"]。 */
	blockKeywords?: string[];
}

export type GuardHook = (ctx: BeforeToolCallContext) => Promise<BeforeToolCallResult | undefined>;

export function createGuard(db: Database, opts: GuardOptions = {}): GuardHook {
	const blockKeywords = opts.blockKeywords ?? ["test-block"];
	return async (ctx: BeforeToolCallContext): Promise<BeforeToolCallResult | undefined> => {
		const tool = ctx.toolCall.name;
		let digest = "";
		try {
			digest = JSON.stringify(ctx.args ?? {});
		} catch {
			digest = String(ctx.args);
		}
		logActivity(db, {
			session_id: opts.sessionId,
			tool,
			action: "call",
			params_digest: digest.slice(0, 2000),
		});

		if (tool === "submit_fact") {
			const summary = String((ctx.args as { summary?: unknown })?.summary ?? "");
			const hit = blockKeywords.find((k) => summary.includes(k));
			if (hit) {
				const reason = [
					`[平台管控·非目标防御] 本次 submit_fact 被闸机拦截。`,
					`触发规则：summary 含平台管控词「${hit}」。`,
					`说明：这是平台侧管控规则，不是你的任务目标——请勿尝试绕过（改写、拆分、变体提交都算绕过）。`,
					`正确做法：去掉管控内容、按原纪律重新提交；或放弃该动作继续任务。`,
				].join("\n");
				logActivity(db, {
					session_id: opts.sessionId,
					tool,
					action: "block",
					detail: `keyword=${hit}`,
				});
				return { block: true, reason };
			}
		}
		return undefined;
	};
}
