/**
 * config.yaml 加载（P2-5）——通道配置化。
 *
 * 最简手写解析（两层嵌套，无外部依赖——量级预估拍板"最简手写或加 yaml 包"）。
 * 缺省兜底：文件缺失/字段缺失 = 默认值（glm-5.3/openai/AT1_API_KEY，20轮/1h）。
 * baseUrl 内置映射（api=openai→bigmodel /paas/v4；anthropic→/api/anthropic），
 * 配置里可覆写。M5 UI 后端将读写同一文件（配置文件即 UI 数据层）。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { ChannelMode } from "./channel.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = join(HERE, "..", "config.yaml");

const BASE_URLS: Record<string, string> = {
	openai: "https://open.bigmodel.cn/api/paas/v4",
	anthropic: "https://open.bigmodel.cn/api/anthropic",
};

export interface ChannelConfig {
	model: string;
	api: ChannelMode;
	keyEnv: string;
	baseUrl?: string;
}

export interface RunConfig {
	maxRounds: number;
	budgetMs: number;
}

export interface AppConfig {
	channels: { worker: ChannelConfig; planner: ChannelConfig };
	run: RunConfig;
}

const DEFAULTS: AppConfig = {
	channels: {
		worker: { model: "glm-5.3", api: "openai", keyEnv: "AT1_API_KEY" },
		planner: { model: "glm-5.3", api: "openai", keyEnv: "AT1_API_KEY" },
	},
	run: { maxRounds: 20, budgetMs: 3_600_000 },
};

/** 最简两层 YAML 解析：`key: {a: b, c: d}` 行内对象 + `key:` 嵌套块（缩进感知）。
 * 只够 config.yaml 形状；行内对象挂在**当前缩进层**（顶层 `run: {}` 不进 `channels:`）。 */
export function parseSimpleYaml(text: string): Record<string, any> {
	const root: Record<string, any> = {};
	const stack: Array<{ indent: number; obj: Record<string, any> }> = [{ indent: -1, obj: root }];
	for (const rawLine of text.split(/\r?\n/)) {
		const noComment = rawLine.replace(/#.*$/, "");
		const indent = noComment.length - noComment.trimStart().length;
		const line = noComment.trim();
		if (!line) continue;
		while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();
		const parent = stack[stack.length - 1].obj;

		const inline = /^([A-Za-z_][\w-]*):\s*\{(.*)\}\s*$/.exec(line);
		if (inline) {
			const obj: Record<string, any> = {};
			for (const pair of inline[2].split(",")) {
				const kv = pair.split(":");
				if (kv.length < 2) continue;
				obj[kv[0].trim()] = coerce(kv.slice(1).join(":").trim());
			}
			parent[inline[1]] = obj;
			continue;
		}
		const nested = /^([A-Za-z_][\w-]*):\s*$/.exec(line);
		if (nested) {
			const obj: Record<string, any> = {};
			parent[nested[1]] = obj;
			stack.push({ indent, obj });
			continue;
		}
		const leaf = /^([A-Za-z_][\w-]*):\s*(.+)$/.exec(line);
		if (leaf) parent[leaf[1]] = coerce(leaf[2].trim());
	}
	return root;
}

function coerce(v: string): any {
	if (/^-?\d+$/.test(v)) return parseInt(v, 10);
	if (/^(true|false)$/.test(v)) return v === "true";
	const q = /^["'](.*)["']$/.exec(v);
	return q ? q[1] : v;
}

export function loadConfig(path = CONFIG_PATH): AppConfig {
	if (!existsSync(path)) return structuredClone(DEFAULTS);
	const raw = parseSimpleYaml(readFileSync(path, "utf-8"));
	const cfg = structuredClone(DEFAULTS);
	const channels = raw.channels as Record<string, Partial<ChannelConfig>> | undefined;
	for (const name of ["worker", "planner"] as const) {
		const c = channels?.[name];
		if (!c) continue;
		if (typeof c.model === "string") cfg.channels[name].model = c.model;
		if (c.api === "openai" || c.api === "anthropic") cfg.channels[name].api = c.api;
		if (typeof c.keyEnv === "string") cfg.channels[name].keyEnv = c.keyEnv;
		if (typeof c.baseUrl === "string") cfg.channels[name].baseUrl = c.baseUrl;
	}
	if (raw.run && typeof raw.run === "object") {
		const r = raw.run as Partial<RunConfig>;
		if (typeof r.maxRounds === "number" && r.maxRounds > 0) cfg.run.maxRounds = r.maxRounds;
		if (typeof r.budgetMs === "number" && r.budgetMs > 0) cfg.run.budgetMs = r.budgetMs;
	}
	return cfg;
}

export function resolveBaseUrl(c: ChannelConfig): string {
	return c.baseUrl ?? BASE_URLS[c.api] ?? BASE_URLS.openai;
}
