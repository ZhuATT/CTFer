/**
 * 模型通道（P0-1）：bigmodel glm-5.3 双形态实测。
 *
 * - openai 形态：pi-ai openai-completions streamSimple → https://open.bigmodel.cn/api/paas/v4
 *   （pi-ai detectCompat 对 open.bigmodel.cn 有原生 zai 分支：max_tokens 字段/zai thinking 格式/关 reasoning effort）
 * - anthropic 形态：anthropic-messages streamSimple → https://open.bigmodel.cn/api/anthropic
 *
 * key 复用 Python 版同通道：.secrets.env 的 AT1_API_KEY（worker 通道）。
 * 模型项照 pi-ai 生成目录的 zai glm 条目形状手工填（P0 不接模型目录发现）。
 */
import type { Model, SimpleStreamOptions, StreamFunction } from "@earendil-works/pi-ai";
import { streamSimple as openaiStreamSimple } from "@earendil-works/pi-ai/api/openai-completions";
import { streamSimple as anthropicStreamSimple } from "@earendil-works/pi-ai/api/anthropic-messages";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { secretOrEnv, type Secrets } from "./secrets.js";

export type ChannelMode = "openai" | "anthropic";

const BIGMODEL_OPENAI_BASE = "https://open.bigmodel.cn/api/paas/v4";
const BIGMODEL_ANTHROPIC_BASE = "https://open.bigmodel.cn/api/anthropic";

/** openai 形态模型项（api/形状对齐 pi-ai providers/data/zai.json 的 glm 条目）。 */
export const BIGMODEL_GLM53_OPENAI: Model<"openai-completions"> = {
	id: "glm-5.3",
	name: "GLM-5.3 (bigmodel paas/v4)",
	api: "openai-completions",
	provider: "bigmodel",
	baseUrl: BIGMODEL_OPENAI_BASE,
	reasoning: true,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 204_800,
	maxTokens: 131_072,
};

/** anthropic 形态模型项。 */
export const BIGMODEL_GLM53_ANTHROPIC: Model<"anthropic-messages"> = {
	id: "glm-5.3",
	name: "GLM-5.3 (bigmodel anthropic)",
	api: "anthropic-messages",
	provider: "bigmodel-anthropic",
	baseUrl: BIGMODEL_ANTHROPIC_BASE,
	reasoning: true,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 204_800,
	maxTokens: 131_072,
};

export interface Channel {
	mode: ChannelMode;
	model: Model<any>;
	apiKey: string;
	streamFn: StreamFn;
}

export function createChannel(mode: ChannelMode, secrets?: Secrets): Channel {
	const apiKey = secretOrEnv("AT1_API_KEY", secrets);
	if (!apiKey) {
		throw new Error("缺少 bigmodel key：at1-github/.secrets.env 需有 AT1_API_KEY（或环境变量直接给）");
	}
	if (mode === "anthropic") {
		return { mode, model: BIGMODEL_GLM53_ANTHROPIC, apiKey, streamFn: anthropicStreamSimple as StreamFn };
	}
	return {
		mode,
		model: BIGMODEL_GLM53_OPENAI,
		apiKey,
		streamFn: openaiStreamSimple as StreamFunction<"openai-completions", SimpleStreamOptions> as StreamFn,
	};
}
