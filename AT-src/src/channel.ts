/**
 * 模型通道（P2-5 配置化重构）——按 ChannelConfig 构造（worker/planner 各自独立）。
 *
 * - openai 形态：pi-ai openai-completions streamSimple → bigmodel /paas/v4
 *   （pi-ai detectCompat 对 open.bigmodel.cn 原生 zai 分支：max_tokens/zai thinking）
 * - anthropic 形态：anthropic-messages streamSimple → bigmodel /api/anthropic（备选，实测可用）
 *
 * 坑位存档：glm-5.3 拒绝 thinking:disabled（错误码 1210）——Agent 侧必须
 * thinkingLevel:"low"（发 {"type":"enabled"}）；{"type":"low"} 也 400，报错文案误导。
 */
import type { Model, SimpleStreamOptions, StreamFunction } from "@earendil-works/pi-ai";
import { streamSimple as openaiStreamSimple } from "@earendil-works/pi-ai/api/openai-completions";
import { streamSimple as anthropicStreamSimple } from "@earendil-works/pi-ai/api/anthropic-messages";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { secretOrEnv, type Secrets } from "./secrets.js";
import { resolveBaseUrl, type ChannelConfig } from "./config.js";

export type ChannelMode = "openai" | "anthropic";

export interface Channel {
	mode: ChannelMode;
	model: Model<any>;
	apiKey: string;
	streamFn: StreamFn;
}

// ── 传输层故障分类（P3pre-1，429 事故根治）──
//
// 探路结论（pi-agent-core/pi-ai 源码核实 + 假 streamFn 探针测试固化）：
// pi 不抛错——streamSimple catch 全部错误 → error 事件 + result() 得
// stopReason="error"+errorMessage 的消息；agent-loop 见 error 即收轮正常返回，
// Agent.prompt() 永不 reject。所以包装层抛 typed error 无处着落，检测点 = 订阅
// 事件流（message_end 且 stopReason="error"），本模块只出分类纯函数。
// abort 不是故障：pi-ai 与 handleRunFailure 都标 stopReason="aborted"，走既有 exhausted 路。

export type ChannelErrorKind = "http" | "network" | "unknown";

export interface ChannelTransportFailure {
	kind: ChannelErrorKind;
	/** HTTP 状态码（kind=http 时尽力提取，如 429/503）。 */
	status?: number;
	/** 原始错误消息。 */
	raw: string;
	/** 人读标签：`传输层故障[http 429]` / `传输层故障[network]`。 */
	label: string;
}

const NETWORK_PATTERNS = [
	"ENOTFOUND",
	"ECONNRESET",
	"ETIMEDOUT",
	"ECONNREFUSED",
	"EAI_AGAIN",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"ECONNABORTED",
	"EPIPE",
	"socket hang up",
	"fetch failed",
	"network error",
	"Failed to fetch",
];

/** 错误消息 → 故障形态：HTTP 状态（4xx/5xx）→ http；网络错误码 → network；其余 → unknown。 */
export function classifyTransportError(raw: string): ChannelTransportFailure {
	const text = raw ?? "";
	const statusMatch = /\b([45]\d{2})\b/.exec(text);
	if (statusMatch) {
		const status = Number(statusMatch[1]);
		return { kind: "http", status, raw: text, label: `传输层故障[http ${status}]` };
	}
	if (NETWORK_PATTERNS.some((p) => text.includes(p))) {
		return { kind: "network", raw: text, label: "传输层故障[network]" };
	}
	return { kind: "unknown", raw: text, label: "传输层故障[unknown]" };
}

/** pi Agent 事件里的 assistant 消息 → 传输层故障（非 assistant / 非 error 停因 / abort → undefined）。 */
export function transportFailureFromMessage(message: unknown): ChannelTransportFailure | undefined {
	const m = message as { role?: string; stopReason?: string; errorMessage?: string } | undefined;
	if (!m || m.role !== "assistant" || m.stopReason !== "error") return undefined;
	const text = m.errorMessage?.trim();
	if (!text) {
		return { kind: "unknown", raw: "(empty)", label: "传输层故障[unknown]" };
	}
	return classifyTransportError(text);
}

function makeModel(c: ChannelConfig): Model<any> {
	const api = c.api === "anthropic" ? "anthropic-messages" : "openai-completions";
	return {
		id: c.model,
		name: `${c.model} (bigmodel ${c.api})`,
		api,
		provider: c.api === "anthropic" ? "bigmodel-anthropic" : "bigmodel",
		baseUrl: resolveBaseUrl(c),
		reasoning: true,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 204_800,
		maxTokens: 131_072,
	} as Model<any>;
}

export function createChannelFromConfig(c: ChannelConfig, secrets?: Secrets): Channel {
	const apiKey = secretOrEnv(c.keyEnv, secrets);
	if (!apiKey) throw new Error(`缺少 key：环境变量 ${c.keyEnv}（或 .secrets.env 同名键）`);
	const streamFn: StreamFn =
		c.api === "anthropic"
			? (anthropicStreamSimple as StreamFunction<"anthropic-messages", SimpleStreamOptions> as StreamFn)
			: (openaiStreamSimple as StreamFunction<"openai-completions", SimpleStreamOptions> as StreamFn);
	return { mode: c.api, model: makeModel(c), apiKey, streamFn };
}

/** P1 兼容入口（runWorkerStep 单跑用）：mode + AT1_API_KEY。 */
export function createChannel(mode: ChannelMode, secrets?: Secrets): Channel {
	return createChannelFromConfig({ model: "glm-5.3", api: mode, keyEnv: "AT1_API_KEY" }, secrets);
}
