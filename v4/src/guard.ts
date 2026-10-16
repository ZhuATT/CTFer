/**
 * guard 闸机 v2（P1-3）——规则表最小版 + 全量审计。
 *
 * 规则数组 {priority, tool, test, message}，首命中生效；P1 内置两条真规则：
 * ①scope host 白名单：Bash 命令里的显式 URL + browser_navigate 的 url，
 *   host 不在 task.json scope.hosts → deny（平台管控框架消息）；
 * ②破坏性命令 deny：rm -rf / mkfs / dd if= / format 等自毁类。
 *
 * 历史教训（设计 §4.3）：逐命令 scope 强制是死胡同（guard 17 条 127.0.0.1 噪音、
 * ARTEX 删过更硬的 RoE）——host 抽取只认显式 URL（结构化位置），不做裸域名正则。
 * block 消息必须「平台管控·非目标防御」框架（§4.3 第 4 层）：裸 403 在渗透
 * agent 眼里 = WAF，明说是平台政策，agent 转向而非缠斗。
 */
import type { Database } from "better-sqlite3";
import type { BeforeToolCallContext, BeforeToolCallResult } from "@earendil-works/pi-agent-core";
import { logActivity } from "./db.js";

export interface GuardRuleContext {
	tool: string;
	args: Record<string, unknown>;
	digest: string;
}

export interface GuardRule {
	id: string;
	priority: number;
	/** 适用工具名；"*" = 全部。 */
	tools: string[];
	test: (ctx: GuardRuleContext) => { hit: boolean; detail?: string };
	message: (detail?: string) => string;
}

const PLATFORM_FRAMEWORK = (rule: string, detail: string | undefined, advice: string): string =>
	[
		`[平台管控·非目标防御] 本次工具调用被闸机拦截。`,
		`触发规则：${rule}${detail ? `（${detail}）` : ""}。`,
		`说明：这是平台侧管控规则，不是你的任务目标——请勿尝试绕过（改写、拆分、编码变体都算绕过）。`,
		`正确做法：${advice}`,
	].join("\n");

const URL_RX = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]*)(?::\d+)?/g;

/** 从文本抽显式 URL 的 host（小写）。只认结构化位置，不做裸域名猜测。 */
export function extractHosts(text: string): string[] {
	const out: string[] = [];
	for (const m of text.matchAll(URL_RX)) out.push(m[1].toLowerCase());
	return [...new Set(out)];
}

const DESTRUCTIVE_RX =
	/\b(rm\s+(-[a-z]*[rf][a-z]*\s+|--recursive)|mkfs(\.\w+)?\b|dd\s+if=|format\s+[a-zA-Z]:|shutdown\b|reboot\b|:\(\)\s*\{\s*:\|\|:\s*&\s*\}\s*;|del\s+\/[sq])/i;

export function builtinRules(scopeHosts: string[]): GuardRule[] {
	const hosts = new Set(scopeHosts.map((h) => h.toLowerCase()));
	return [
		{
			id: "scope-host-allowlist",
			priority: 10,
			tools: ["browser_navigate", "Bash"],
			test: ({ tool, args, digest }) => {
				let candidates: string[];
				if (tool === "browser_navigate") {
					candidates = extractHosts(String(args?.url ?? ""));
				} else {
					candidates = extractHosts(digest);
				}
				const offenders = candidates.filter((h) => !hosts.has(h));
				return { hit: offenders.length > 0, detail: `scope 外 host: ${offenders.join(", ")}` };
			},
			message: (detail) =>
				PLATFORM_FRAMEWORK(
					"scope host 白名单",
					detail,
					"只访问 task scope 内的 host；发现约束外新目标 ≠ 获得授权——把「范围外存在 X」作为一条 fact 上抛即可，不要动手。",
				),
		},
		{
			id: "destructive-command",
			priority: 20,
			tools: ["Bash"],
			test: ({ digest }) => {
				const m = DESTRUCTIVE_RX.exec(digest);
				return { hit: m !== null, detail: m ? `命中 ${m[0].trim()}` : undefined };
			},
			message: (detail) =>
				PLATFORM_FRAMEWORK(
					"破坏性命令禁令",
					detail,
					"删除/格式化/停服类命令不是渗透测试的手段；换非破坏性验证方式。",
				),
		},
	];
}

export interface GuardOptions {
	taskId?: string;
	sessionId?: string;
	scopeHosts: string[];
	/** 追加规则（测试/未来扩展用）。 */
	extraRules?: GuardRule[];
}

export type GuardHook = (ctx: BeforeToolCallContext) => Promise<BeforeToolCallResult | undefined>;

export function createGuard(db: Database, opts: GuardOptions): GuardHook {
	const rules = [...builtinRules(opts.scopeHosts), ...(opts.extraRules ?? [])].sort((a, b) => a.priority - b.priority);
	return async (ctx: BeforeToolCallContext): Promise<BeforeToolCallResult | undefined> => {
		const tool = ctx.toolCall.name;
		let digest = "";
		try {
			digest = JSON.stringify(ctx.args ?? {});
		} catch {
			digest = String(ctx.args);
		}
		const args = (ctx.args ?? {}) as Record<string, unknown>;
		logActivity(db, {
			task_id: opts.taskId,
			session_id: opts.sessionId,
			worker: "worker",
			kind: "tool_use",
			tool,
			summary: "call",
			detail: digest.slice(0, 2000),
		});

		for (const rule of rules) {
			if (!rule.tools.includes("*") && !rule.tools.includes(tool)) continue;
			const { hit, detail } = rule.test({ tool, args, digest });
			if (!hit) continue;
			logActivity(db, {
				task_id: opts.taskId,
				session_id: opts.sessionId,
				worker: "worker",
				kind: "tool_use",
				tool,
				is_error: true,
				summary: `blocked: ${rule.id}`,
				detail,
			});
			return { block: true, reason: rule.message(detail) };
		}
		return undefined;
	};
}
