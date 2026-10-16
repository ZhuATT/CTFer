/**
 * .secrets.env 加载器（无依赖）。
 *
 * at1-github/.secrets.env 是 `export KEY=VAL` 行的 shell 片段（Python 版直接
 * source）。Node 侧这里做最简解析：仅识别 `export K=V` / `K=V`，值去掉成对
 * 引号；真实环境变量永远优先（允许临时覆盖）。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export type Secrets = Record<string, string>;

export function loadSecrets(path = join(REPO_ROOT, ".secrets.env")): Record<string, string> {
	if (!existsSync(path)) return {};
	const out: Record<string, string> = {};
	for (const rawLine of readFileSync(path, "utf-8").split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;
		const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
		if (!m) continue;
		let value = m[2].trim();
		if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
			value = value.slice(1, -1);
		}
		out[m[1]] = value;
	}
	return out;
}

/** secrets 值 + 真实 env 合并（env 优先），再取单个键。 */
export function secretOrEnv(key: string, secrets?: Record<string, string>): string | undefined {
	return process.env[key] ?? secrets?.[key] ?? undefined;
}
