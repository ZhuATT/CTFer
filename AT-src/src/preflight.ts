/**
 * 任务前置健康检查（P3-10，设计存档 P3-pre §8 末"D-2 拍板记录"）。
 *
 * 四项（参照 Cairn 分层骨架 + ARTEX 探测保真，不抄清单）：
 * - A 通道构造 ×2：createChannelFromConfig 纯本地（keyEnv 拼错/缺 key）→ **硬失败**；
 * - B 通道活性 ×2：生产同款 Agent+streamFn 发最小真实补全（30s 硬超时不重试、两通道
 *   并行逐项隔离）；401/403 → **硬失败**；429/5xx/network/超时/空回复 → 警告放行，
 *   交运行时熔断接力（P3pre 已建 planner-error 重试 + 3 连 blocked 熔断——
 *   两层分工：门口拦确定性错误、run 内数连续失败拦瞬时持续错误）；
 * - C 图完整性：payload 腊坏扫查 → 腊坏 open step 自动标 blocked + is_error 账
 *   （planner 见 blocked 重派绕开——ARTEX"失能不崩不占坑"），其余腊坏节点警告；
 * - D 浏览器池：真起真关；失败 = 警告 + 人工选择是否降级（CLI y/N 或 --no-browser）。
 *
 * 触发点（拍板）：`at1 run` 进循环前自动跑（CLI 层退出码 1，不进 runTask、不造 run
 * reason——run 还没开始，没有 run 账目可写）+ 独立 `at1 check`（doctor，bare 输出进 CI）。
 * 报告：Cairn 式表格打 stdout + 一条 activity（tool=preflight）落 DB 供 M5 查。
 *
 * 与 P3pre-6 分工：preflight 挡门口的常规构造失败，loop catch 接运行中的漏网 throw。
 * 测试：streamFn 注入零 LLM + 浏览器探测 deps 注入。
 */
import { Agent, type AgentEvent, type StreamFn } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import {
	classifyTransportError,
	createChannelFromConfig,
	transportFailureFromMessage,
	type Channel,
	type ChannelTransportFailure,
} from "./channel.js";
import type { AppConfig, ChannelConfig } from "./config.js";
import { logActivity } from "./db.js";
import { setStepState } from "./graph.js";
import { BrowserPool } from "./browser-pool.js";
import type { Secrets } from "./secrets.js";

export type PreflightStatus = "ok" | "warn" | "fail" | "skip";

export interface PreflightCheckResult {
	/** A1/A2=通道构造，B1/B2=通道活性，C=图完整性，D=浏览器池。 */
	id: string;
	name: string;
	status: PreflightStatus;
	detail: string;
	ms: number;
}

export interface PreflightReport {
	checks: PreflightCheckResult[];
	/** 有硬失败（A 构造失败 / B 401/403）→ run 不进循环，CLI 退出码 1。 */
	hardFailed: boolean;
	/** 浏览器池检查失败（D warn）——run 门外的降级交互用它判断。 */
	browserDegraded: boolean;
}

export interface PreflightOptions {
	config: AppConfig;
	secrets?: Secrets;
	/** task 图库（C 检查 + activity 落账）。无（check 不带 task）→ 跳过 C。 */
	db?: Database;
	taskId?: string;
	/** D 浏览器池 profile 根目录（真起真关）。无 → 跳过 D。 */
	taskDir?: string;
	/** B 活性检查的 streamFn 注入口（测试零 LLM；缺省 = 各通道生产同款）。 */
	streamFn?: StreamFn;
	/** D 浏览器探测注入（测试不真起 chrome；缺省 = BrowserPool 真起真关）。 */
	probeBrowser?: () => Promise<{ ok: boolean; detail: string }>;
	/** B 硬超时（默认 30_000ms；测试可调小）。 */
	pingTimeoutMs?: number;
	/** --no-browser：run 已决定不用浏览器 → D 跳过（skip 进报告留痕）。 */
	skipBrowser?: boolean;
}

const PING_TIMEOUT_MS = 30_000;

// ── A：通道构造（纯本地，零网络） ──

function constructionCheck(id: string, name: string, cfg: ChannelConfig, secrets?: Secrets): PreflightCheckResult {
	const t0 = Date.now();
	try {
		const ch = createChannelFromConfig(cfg, secrets);
		// 不回显 key 本体——只报来源与长度
		return {
			id,
			name,
			status: "ok",
			detail: `keyEnv=${cfg.keyEnv}（${ch.apiKey.length} 字符，api=${cfg.api}，model=${cfg.model}）`,
			ms: Date.now() - t0,
		};
	} catch (err) {
		return {
			id,
			name,
			status: "fail",
			detail: err instanceof Error ? err.message : String(err),
			ms: Date.now() - t0,
		};
	}
}

// ── B：通道活性（生产同款最小真实补全） ──

export interface PingOutcome {
	status: "ok" | "warn" | "fail";
	detail: string;
}

/** 最小补全探针（生产同款 Agent 包装 + 同款 message_end 检测——P3pre-2 同路）。
 * pi 探针结论：Agent.prompt 永不 reject，错误走 message_end(stopReason="error")。 */
export async function livePing(channel: Channel, timeoutMs = PING_TIMEOUT_MS): Promise<PingOutcome> {
	const agent = new Agent({
		initialState: {
			systemPrompt: "你是通道健康探针。无论收到什么都只回复：OK",
			tools: [],
			model: channel.model,
			thinkingLevel: "low", // glm-5.3 拒绝 thinking:disabled（channel.ts 坑位存档）
		},
		streamFn: channel.streamFn,
		getApiKey: async () => channel.apiKey,
	});

	let failure: ChannelTransportFailure | undefined;
	let text = "";
	const unsubscribe = agent.subscribe((ev: AgentEvent) => {
		if (ev.type !== "message_end") return;
		const msg = ev.message as { role?: string; content?: Array<{ type: string; text?: string }> };
		if (msg.role === "assistant" && Array.isArray(msg.content)) {
			text = msg.content
				.filter((c) => c.type === "text" && c.text?.trim())
				.map((c) => c.text)
				.join("\n")
				.trim();
		}
		failure = transportFailureFromMessage(ev.message) ?? failure;
	});

	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		agent.abort(); // 30s 硬超时：abort → stopReason=aborted（不算故障，走 timedOut 分支）
	}, timeoutMs);
	try {
		await agent.prompt("回复 OK");
	} catch (err) {
		// 理论不可达（pi 不抛）——兜底按故障分类，不静默
		failure = failure ?? classifyTransportError(err instanceof Error ? err.message : String(err));
	} finally {
		clearTimeout(timer);
		unsubscribe();
	}

	if (timedOut && !failure) {
		return { status: "warn", detail: `${timeoutMs}ms 硬超时（不重试——放行，交运行时熔断接力）` };
	}
	if (failure) {
		// ARTEX 失败二分：401/403 确定性认证失败 → 门口就挡；其余瞬时/瞬时态放行
		if (failure.kind === "http" && (failure.status === 401 || failure.status === 403)) {
			return { status: "fail", detail: `${failure.label}：${failure.raw.slice(0, 200)}——key 无效/无权限，修复后重跑` };
		}
		return { status: "warn", detail: `${failure.label}：${failure.raw.slice(0, 200)}——放行，交运行时熔断接力` };
	}
	if (!text) {
		// ARTEX：空回复也算失败（从严）——但连接通了，警告放行
		return { status: "warn", detail: "连接通但空回复（从严判）——放行，交运行时熔断接力" };
	}
	return { status: "ok", detail: `回复「${text.slice(0, 40)}」` };
}

async function livenessCheck(
	id: string,
	name: string,
	cfg: ChannelConfig,
	secrets: Secrets | undefined,
	opts: PreflightOptions,
): Promise<PreflightCheckResult> {
	const t0 = Date.now();
	try {
		const channel = createChannelFromConfig(cfg, secrets);
		if (opts.streamFn) channel.streamFn = opts.streamFn; // 测试注入口
		const ping = await livePing(channel, opts.pingTimeoutMs ?? PING_TIMEOUT_MS);
		return { id, name, status: ping.status, detail: ping.detail, ms: Date.now() - t0 };
	} catch (err) {
		return {
			id,
			name,
			status: "fail",
			detail: `通道构造失败：${err instanceof Error ? err.message : String(err)}`,
			ms: Date.now() - t0,
		};
	}
}

// ── C：图完整性（payload 腊坏扫查） ──

interface PayloadRow {
	id: number;
	kind: string;
	state: string;
	payload: string;
}

export function integrityCheck(db: Database, taskId: string): PreflightCheckResult {
	const t0 = Date.now();
	const rows = db.prepare("SELECT id, kind, state, payload FROM nodes WHERE task_id = ?").all(taskId) as PayloadRow[];
	const corrupt: string[] = [];
	const corruptOpenSteps: number[] = [];
	for (const r of rows) {
		try {
			JSON.parse(r.payload);
		} catch {
			corrupt.push(`#${r.id}(${r.kind}/${r.state})`);
			if (r.kind === "step" && r.state === "open") corruptOpenSteps.push(r.id);
		}
	}
	for (const id of corruptOpenSteps) {
		// 腊坏 open step → blocked（planner 见 blocked 重派绕开）+ is_error 账（原因留档）
		setStepState(db, taskId, id, "blocked");
		logActivity(db, {
			task_id: taskId,
			node_id: id,
			worker: "preflight",
			kind: "result",
			tool: "preflight",
			is_error: true,
			summary: `step #${id} payload 腊坏——preflight 自动标 blocked（planner 将重派绕开）`,
			detail: `payload 无法 JSON.parse（原始内容前 200 字）：${rows.find((r) => r.id === id)?.payload.slice(0, 200)}`,
		});
	}
	if (corrupt.length === 0) {
		return { id: "C", name: "图完整性", status: "ok", detail: `${rows.length} 节点 payload 全部可解析`, ms: Date.now() - t0 };
	}
	const fixed = corruptOpenSteps.length ? `，${corruptOpenSteps.length} 个腊坏 open step 已标 blocked` : "";
	return {
		id: "C",
		name: "图完整性",
		status: "warn",
		detail: `腊坏 ${corrupt.length} 条：${corrupt.join(" ")}${fixed}——run 继续`,
		ms: Date.now() - t0,
	};
}

// ── D：浏览器池（真起真关） ──

export async function realBrowserProbe(taskDir: string): Promise<{ ok: boolean; detail: string }> {
	const pool = await BrowserPool.start(taskDir);
	try {
		return { ok: true, detail: `启动→CDP 就绪 ${pool.endpoint}（pid ${pool.pid}）→ 已关` };
	} finally {
		await pool.shutdown();
	}
}

async function browserCheck(taskDir: string, opts: PreflightOptions): Promise<PreflightCheckResult> {
	const t0 = Date.now();
	if (opts.skipBrowser) {
		return { id: "D", name: "浏览器池", status: "skip", detail: "--no-browser——run 不用浏览器，跳过", ms: 0 };
	}
	try {
		const probe = opts.probeBrowser ?? (() => realBrowserProbe(taskDir));
		const r = await probe();
		return r.ok
			? { id: "D", name: "浏览器池", status: "ok", detail: r.detail, ms: Date.now() - t0 }
			: { id: "D", name: "浏览器池", status: "warn", detail: `${r.detail}——可 --no-browser 降级启动`, ms: Date.now() - t0 };
	} catch (err) {
		return {
			id: "D",
			name: "浏览器池",
			status: "warn", // 拍板：失败=警告+人工选择降级（不硬失败）
			detail: `${err instanceof Error ? err.message : String(err)}——可 --no-browser 降级启动`,
			ms: Date.now() - t0,
		};
	}
}

// ── 汇总 ──

export async function runPreflight(opts: PreflightOptions): Promise<PreflightReport> {
	const checks: PreflightCheckResult[] = [];
	const { config } = opts;

	// A 通道构造 ×2（纯本地；硬失败）
	checks.push(constructionCheck("A1", "worker 通道构造", config.channels.worker, opts.secrets));
	checks.push(constructionCheck("A2", "planner 通道构造", config.channels.planner, opts.secrets));

	// B 通道活性 ×2（并行逐项隔离——一路挂不带走另一路）
	const [b1, b2] = await Promise.all([
		livenessCheck("B1", "worker 通道活性", config.channels.worker, opts.secrets, opts),
		livenessCheck("B2", "planner 通道活性", config.channels.planner, opts.secrets, opts),
	]);
	checks.push(b1, b2);

	// C 图完整性（有 task 库才查）
	if (opts.db && opts.taskId) {
		checks.push(integrityCheck(opts.db, opts.taskId));
	}

	// D 浏览器池（有 taskDir 才真起；skipBrowser 留 skip 痕）
	if (opts.taskDir) {
		checks.push(await browserCheck(opts.taskDir, opts));
	}

	const hardFailed = checks.some((c) => c.status === "fail");
	const browserDegraded = checks.some((c) => c.id === "D" && c.status === "warn");

	// 一条 activity 落账（M5 查询用；check 不带 task 时无账可落）
	if (opts.db && opts.taskId) {
		logActivity(opts.db, {
			task_id: opts.taskId,
			worker: "preflight",
			kind: "result",
			tool: "preflight",
			is_error: hardFailed,
			summary: `preflight：${checks.filter((c) => c.status === "ok").length} ok / ${checks.filter((c) => c.status === "warn").length} warn / ${checks.filter((c) => c.status === "fail").length} fail（hardFailed=${hardFailed}）`,
			detail: checks.map((c) => `${c.id} ${c.status} ${c.detail}`).join("\n").slice(0, 1000),
		});
	}

	return { checks, hardFailed, browserDegraded };
}

/** Cairn 式表格（stdout / bare 进 CI）。 */
export function renderPreflightReport(report: PreflightReport): string {
	const lines: string[] = ["[preflight] 任务前置健康检查"];
	for (const c of report.checks) {
		const sym = c.status === "ok" ? "[+]" : c.status === "warn" ? "[!]" : c.status === "skip" ? "[ ]" : "[-]";
		lines.push(`${sym} ${c.id.padEnd(3)} ${c.name.padEnd(12)} ${c.status.padEnd(5)} ${String(c.ms).padStart(6)}ms  ${c.detail}`);
	}
	const failed = report.checks.filter((c) => c.status === "fail");
	const warns = report.checks.filter((c) => c.status === "warn");
	if (failed.length > 0) {
		lines.push(`结论：硬失败 ${failed.length} 项——不进循环，修复后重跑（中断前进度不丢）。`);
	} else if (warns.length > 0) {
		lines.push(`结论：通过（警告 ${warns.length} 项放行——运行时熔断接力）。`);
	} else {
		lines.push("结论：全部通过。");
	}
	return lines.join("\n");
}
