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
