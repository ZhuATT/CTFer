/**
 * Agent 封装（P0-5）：pi loop + 事件消费 + 工具面 + guard 组装。
 *
 * 消费的都是 pi-agent-core 的 Agent：initialState 给 systemPrompt/tools/model，
 * streamFn 走 channel（bigmodel），beforeToolCall 挂 guard。
 * 事件流里顺带收每轮 usage（P1 activity 计量的数据源，验收项之一）。
 */
import { Agent, type AgentEvent, type AgentTool } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import { createChannel, type ChannelMode } from "./channel.js";
import { createGuard } from "./guard.js";
import { BrowserPool } from "./browser-pool.js";
import { BrowserSession, createNavigateTool, createSnapshotTool } from "./tools/browser.js";
import { createSubmitFactTool } from "./tools/submit-fact.js";
import type { Secrets } from "./secrets.js";

export const WORKER_SYSTEM_PROMPT = [
	"你是 AT1 渗透测试 worker（P0 冒烟）。",
	"纪律：",
	"- 只做被指示的事，不自由发挥扩大范围。",
	"- 一切结论必须有可复核证据（工具输出）；没有证据就回答「未观察到」。",
	"- 完成任务即停，不要追加多余动作。",
].join("\n");

export interface WorkerUsage {
	turn: number;
	model: string;
	input: number;
	output: number;
	cacheRead: number;
	cacheWrite: number;
	totalTokens: number;
}

export interface WorkerRunResult {
	usage: WorkerUsage[];
	facts: number;
	finalText: string;
	blockedCount: number;
}

export interface RunWorkerOptions {
	db: Database;
	secrets?: Secrets;
	root: string;
	targetUrl: string;
	mode?: ChannelMode;
	/** smoke-2 回归：诱导 summary 前缀 test-block 触发闸机。 */
	blockProbe?: boolean;
	timeoutMs?: number;
	onEvent?: (ev: AgentEvent) => void;
}

export function buildSmokePrompt(targetUrl: string, blockProbe: boolean): string {
	const lines = [
		`任务：用 browser_navigate 打开 ${targetUrl}，再用 browser_snapshot 观察页面内容。`,
		"然后调 submit_fact 记录一条你观察到的事实（evidence 填「导航 URL → 页面标题」）。",
		"完成即停。",
	];
	if (blockProbe) {
		lines.push(
			"回归测试要求：这次 submit_fact 的 summary 必须以「test-block 」开头（平台闸机回归用）。",
			"若提交被拦截：按拦截消息里的正确做法处理（去掉管控内容按原纪律重新提交一次），然后停止。",
		);
	}
	return lines.join("\n");
}

export async function runWorker(opts: RunWorkerOptions): Promise<WorkerRunResult> {
	const { db, root, targetUrl } = opts;
	const channel = createChannel(opts.mode ?? "openai", opts.secrets);
	const sessionId = `smoke-${Date.now()}`;

	const pool = await BrowserPool.start(root);
	const session = new BrowserSession(pool.endpoint);

	const usage: WorkerUsage[] = [];
	const texts: string[] = [];
	let turn = 0;
	let blockedCount = 0;

	const tools: AgentTool<any>[] = [
		createNavigateTool(session),
		createSnapshotTool(session),
		createSubmitFactTool(db),
	];

	const agent = new Agent({
		initialState: {
			systemPrompt: WORKER_SYSTEM_PROMPT,
			tools,
			model: channel.model,
			// glm-5.3 始终思考，bigmodel 拒绝 thinking:disabled（错误码 1210）。
			// low → pi 的 zai 格式发 {"type":"enabled"}，实测 200。
			thinkingLevel: "low",
		},
		streamFn: channel.streamFn,
		getApiKey: async () => channel.apiKey,
		beforeToolCall: createGuard(db, { sessionId }),
	});

	const unsubscribe = agent.subscribe(async (ev: AgentEvent) => {
		opts.onEvent?.(ev);
		if (ev.type === "turn_end") {
			turn += 1;
			const msg = ev.message as { usage?: Record<string, number>; model?: string };
			const u = msg.usage ?? {};
			usage.push({
				turn,
				model: msg.model ?? channel.model.id,
				input: u.input ?? 0,
				output: u.output ?? 0,
				cacheRead: u.cacheRead ?? 0,
				cacheWrite: u.cacheWrite ?? 0,
				totalTokens: u.totalTokens ?? 0,
			});
		} else if (ev.type === "message_end") {
			const msg = ev.message as { role?: string; content?: Array<{ type: string; text?: string }> };
			if (msg.role === "assistant" && Array.isArray(msg.content)) {
				const t = msg.content
					.filter((c) => c.type === "text" && c.text?.trim())
					.map((c) => c.text)
					.join("\n");
				if (t) texts.push(t);
			}
		}
	});

	const timeout = setTimeout(() => agent.abort(), opts.timeoutMs ?? 300_000);
	try {
		await agent.prompt(buildSmokePrompt(targetUrl, opts.blockProbe ?? false));
	} finally {
		clearTimeout(timeout);
		unsubscribe();
		await session.dispose();
		await pool.shutdown(); // 验收项：smoke 后 Chrome 死、无残留
	}

	const factsRow = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind = 'fact'").get() as { n: number };
	const blockRow = db
		.prepare("SELECT COUNT(*) AS n FROM activity WHERE session_id = ? AND action = 'block'")
		.get(sessionId) as { n: number };
	blockedCount = blockRow.n;

	return {
		usage,
		facts: factsRow.n,
		finalText: texts[texts.length - 1] ?? "",
		blockedCount,
	};
}
