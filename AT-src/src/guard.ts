/**
 * guard 闸机 v2（P1-3）——规则表最小版 + 全量审计。
 *
 * 规则数组 {priority, tool, test, message}，首命中生效；P1 内置两条真规则：
 * ①scope host 白名单：Bash 命令里的显式 URL + browser_navigate 的 url，
 *   host 不在 task.json scope.hosts → deny（平台管控框架消息）；
 * ②破坏性命令 deny：rm（含普通直接删/-f/-r/-rf/--recursive）/ rmdir / unlink / mkfs /
 *   dd if= / format 等自毁类——按真实 args.command 匹配（G-A）。
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

/** 从文本抽显式 URL 的 host（小写）。只认结构化位置，不做裸域名猜测。
 * 旧导出（兼容保留）：正则粗抽，不做标准 URL 校验——guard 内部判定走 parseUrlHosts。 */
export function extractHosts(text: string): string[] {
	const out: string[] = [];
	for (const m of text.matchAll(URL_RX)) out.push(m[1].toLowerCase());
	return [...new Set(out)];
}

// ── G-B：标准 URL 解析（11-9 实机 fix §3.3）──

/** 显式 http(s) 候选：排除空格/shell 引号/反引号/重定向符/反斜线；
 * 边界保守——引号内 URL 照抓（可能误拦，本批不建纯文本例外）。 */
const URL_CANDIDATE_RX = /https?:\/\/[^\s'"`<>\\]+/gi;

/** URL.hostname 对 IPv6 字面量保留外围方括号——统一剥掉，与 scope host 归一化一致。 */
function normalizeUrlHost(u: URL): string {
	let h = u.hostname.toLowerCase();
	if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
	return h;
}

export interface UrlParseOutcome {
	/** 解析成功的候选 → 标准化 hostname（小写、IPv6 去括号、端口不算 host）。 */
	hosts: string[];
	/** 显式 http(s) 候选但标准 URL 解析失败——guard 对此拒绝，不静默丢掉。 */
	failed: string[];
}

/** 从原始 Bash 命令文本抽显式 http(s) 候选并做标准 URL 解析。
 * 非解析器/非沙箱：模板字符串、编码变体、动态地址不在本批承诺范围。 */
export function parseUrlHosts(text: string): UrlParseOutcome {
	const hosts: string[] = [];
	const failed: string[] = [];
	for (const m of text.matchAll(URL_CANDIDATE_RX)) {
		try {
			hosts.push(normalizeUrlHost(new URL(m[0])));
		} catch {
			failed.push(m[0].slice(0, 200));
		}
	}
	return { hosts: [...new Set(hosts)], failed };
}

/** browser_navigate.url 解析：必须是字符串且为合法 http(s) URL；否则返回错误说明。 */
export function parseNavigateUrl(raw: unknown): { host?: string; error?: string } {
	if (typeof raw !== "string" || raw.trim() === "") return { error: "url 必须是非空字符串" };
	try {
		const u = new URL(raw);
		if (u.protocol !== "http:" && u.protocol !== "https:") {
			return { error: `仅允许 http(s) URL，收到协议 ${u.protocol}` };
		}
		return { host: normalizeUrlHost(u) };
	} catch {
		return { error: "URL 无法解析（不是合法 URL）" };
	}
}

// G-A/G-B：破坏性禁令按真实命令文本匹配（\s 覆盖真实空格/制表/换行）；
// 普通直接 rm/rmdir/unlink 一并拒绝（11-9 §3.3）；保守策略——命令文本任何位置出现
// 危险片段（含注释/引号内/纯展示）都可能命中，不建纯文本例外；非 shell 解析器。
const DESTRUCTIVE_RX =
	/\b(rm(\s|$)|rmdir(\s|$)|unlink(\s|$)|mkfs(\.\w+)?\b|dd\s+if=|format\s+[a-zA-Z]:|shutdown\b|reboot\b|:\(\)\s*\{\s*:\|\|:\s*&\s*\}\s*;|del\s+\/[sq])/i;

export function builtinRules(scopeHosts: string[] | Set<string>): GuardRule[] {
	// P3-4：传 Set 直接用引用不拷贝，供 scope-add 运行时扩权原位生效
	const hosts =
		scopeHosts instanceof Set
			? scopeHosts
			: new Set(scopeHosts.map((h) => h.toLowerCase()));
	return [
		{
			id: "scope-host-allowlist",
			priority: 10,
			tools: ["browser_navigate", "Bash"],
			test: ({ tool, args }) => {
				if (tool === "browser_navigate") {
					const nav = parseNavigateUrl(args?.url);
					if (nav.error) return { hit: true, detail: nav.error };
					const offender = nav.host && !hosts.has(nav.host) ? nav.host : undefined;
					return { hit: Boolean(offender), detail: offender ? `scope 外 host: ${offender}` : undefined };
				}
				// G-B：检查原始 Bash 命令字符串（不是 JSON digest）；候选解析失败 → 拒绝并说明
				const { hosts: parsed, failed } = parseUrlHosts(String(args?.command ?? ""));
				const offenders = parsed.filter((h) => !hosts.has(h));
				if (failed.length > 0) {
					return { hit: true, detail: `URL 无法校验 scope（解析失败）：${failed.join(", ")}` };
				}
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
			// G-A：检查真实 args.command（不是 JSON.stringify 后的 digest；digest 仅审计用）
			test: ({ args }) => {
				const cmd = args?.command;
				if (typeof cmd !== "string") return { hit: false };
				const m = DESTRUCTIVE_RX.exec(cmd);
				return { hit: m !== null, detail: m ? `命中 ${m[0].trim()}` : undefined };
			},
			message: (detail) =>
				PLATFORM_FRAMEWORK(
					"破坏性命令禁令",
					detail,
					// 11-9 §3.1 已同意回执文本：保留旧文件 + 唯一临时文件名 + 禁替代删除
					"移除命令中的删除操作；需要独立临时文件时使用新的唯一文件名，保留已有文件。不得换用其他方式执行同一删除操作。",
				),
		},
	];
}

/** 参数形态安全校验（fail-closed）：Bash.command 必须是字符串——不走 String(object) 兜底，
 * 不让对象形态参数伪装成有效命令逃过规则检查（11-9 §3.2）。 */
function paramShapeError(tool: string, args: Record<string, unknown>): string | undefined {
	if (tool === "Bash" && typeof args.command !== "string") {
		return `工具参数校验失败：Bash.command 必须是字符串（收到 ${typeof args.command}）——拒绝执行`;
	}
	return undefined;
}

export interface GuardOptions {
	taskId?: string;
	sessionId?: string;
	/** 卡A：当前 step 编号——审计行走 activity.node_id，与工具结果账可关联。 */
	stepId?: number;
	scopeHosts: string[] | Set<string>;
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
		const toolCallId = ctx.toolCall.id;
		// 卡A/§3.4：审计 detail 走 JSON（先限长文本字段再序列化，保证可解析）；call 与后续
		// blocked / tool_execution_end 靠 toolCallId 关联——统计口径：调用次数只数
		// kind=tool_use 且 summary=call，不按 tool 列 COUNT(*)，杜绝 call+result 翻倍口径。
		logActivity(db, {
			task_id: opts.taskId,
			...(opts.stepId !== undefined ? { node_id: opts.stepId } : {}),
			session_id: opts.sessionId,
			worker: "worker",
			kind: "tool_use",
			tool,
			summary: "call",
			detail: JSON.stringify({ toolCallId, args: digest.slice(0, 2000) }),
		});

		// G-A：参数形态先行（在校验前安全拒绝，规则执行不异常逃出）
		const shapeError = paramShapeError(tool, args);
		if (shapeError) {
			logActivity(db, {
				task_id: opts.taskId,
				...(opts.stepId !== undefined ? { node_id: opts.stepId } : {}),
				session_id: opts.sessionId,
				worker: "worker",
				kind: "tool_use",
				tool,
				is_error: true,
				summary: "blocked: invalid-args",
				detail: JSON.stringify({ toolCallId, ruleId: "invalid-args", receipt: shapeError.slice(0, 2000) }),
			});
			return { block: true, reason: PLATFORM_FRAMEWORK("工具参数校验", shapeError, "以正确参数形态重试。") };
		}

		for (const rule of rules) {
			if (!rule.tools.includes("*") && !rule.tools.includes(tool)) continue;
			let verdict: { hit: boolean; detail?: string };
			try {
				verdict = rule.test({ tool, args, digest });
			} catch (err) {
				// 规则执行异常按 fail-closed 处理：拒绝并留审计，不向 agent 逃出
				verdict = { hit: true, detail: `规则执行异常（安全拒绝）：${err instanceof Error ? err.message : String(err)}` };
			}
			if (!verdict.hit) continue;
			// 卡A：blocked 记 ruleId 与完整平台回执（已知平台文案，不追加命令原文）；
			// 与同次 tool_execution_end 的 error 结果账是两条账，统计按 toolCallId 关联去重
			const receipt = rule.message(verdict.detail);
			logActivity(db, {
				task_id: opts.taskId,
				...(opts.stepId !== undefined ? { node_id: opts.stepId } : {}),
				session_id: opts.sessionId,
				worker: "worker",
				kind: "tool_use",
				tool,
				is_error: true,
				summary: `blocked: ${rule.id}`,
				detail: JSON.stringify({ toolCallId, ruleId: rule.id, receipt, ...(verdict.detail ? { hit: verdict.detail } : {}) }),
			});
			return { block: true, reason: receipt };
		}
		return undefined;
	};
}
