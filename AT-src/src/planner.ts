/**
 * planner 会话（P2-1）——pi Agent 全新会话，与 worker 永不同会话（§3.1）。
 *
 * 工具面五个：add_step（批量≤4+D3 拒重）/ prove_goal（D7 校验）/ TodoWrite
 * （todos.json 跨唤醒）/ list_facts（分页20）/ node_detail。
 * 不做：kill_work/steer_work（单 worker 无在跑可杀）、list_assets（P3）、Bash（纯读图）。
 * usage 落 activity（worker="planner"）——计量分列（验收项）。
 */
import { Agent, type AgentEvent, type AgentTool, type StreamFn } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createChannelFromConfig, transportFailureFromMessage, type ChannelTransportFailure } from "./channel.js";
import type { ChannelConfig } from "./config.js";
import { addStep, concludeGoal, goalAchieved, goalClosed, getNode, graphOverview, proveGoal } from "./graph.js";
import { logActivity, type NodeRow } from "./db.js";
import { PLANNER_SYSTEM_PROMPT, renderPlannerUserMessage } from "./planner-prompt.js";
import { renderTriggers, type TriggerEvent } from "./triggers.js";
import type { Secrets } from "./secrets.js";
import { normalizeSummary } from "./contracts.js";
import { createListAssetsTool } from "./tools/assets.js";

const FACTS_PAGE = 20;
const TODO_MAX = 20;

// ── P3pre-6 ②：操作员干预史渲染窗口（常量化，未来可提升 config） ──
export const INTERVENTION_WINDOW = 5;
export const INTERVENTION_TEXT_LIMIT = 200;

export interface InterventionEntry {
	ts?: string;
	formatted: string;
}

/** 读 control/hints.jsonl 与 control/steer.jsonl 尾部 ≤5 条（每条截 ≤200 字，时间正序、不去重）。 */
export function readRecentInterventions(taskDir: string): InterventionEntry[] {
	const entries: InterventionEntry[] = [];

	// hints: control/hints.jsonl
	const hintsPath = join(taskDir, "control", "hints.jsonl");
	if (existsSync(hintsPath)) {
		try {
			const lines = readFileSync(hintsPath, "utf-8")
				.split(/\r?\n/)
				.filter((l) => l.trim())
				.slice(-INTERVENTION_WINDOW);
			for (const line of lines) {
				let ts: string | undefined;
				let text = line;
				try {
					const obj = JSON.parse(line) as { ts?: string; text?: string };
					if (typeof obj.text === "string" && obj.text.trim()) text = obj.text.trim();
					if (typeof obj.ts === "string" && obj.ts.trim()) ts = obj.ts.trim();
				} catch {
					// 宽容解析：坏行整行当文本（hints.ts:52-54 语义）
				}
				const truncated = text.slice(0, INTERVENTION_TEXT_LIMIT);
				const label = ts ? `[hint, ${ts}]` : `[hint]`;
				entries.push({ ts, formatted: `- ${label} ${truncated}` });
			}
		} catch {
			/* 读取失败忽略 */
		}
	}

	// steer: control/steer.jsonl
	const steerPath = join(taskDir, "control", "steer.jsonl");
	if (existsSync(steerPath)) {
		try {
			const lines = readFileSync(steerPath, "utf-8")
				.split(/\r?\n/)
				.filter((l) => l.trim())
				.slice(-INTERVENTION_WINDOW);
			for (const line of lines) {
				let ts: string | undefined;
				let stepId: number | undefined;
				let text = line;
				try {
					const obj = JSON.parse(line) as { ts?: string; text?: string; stepId?: number };
					if (typeof obj.text === "string" && obj.text.trim()) text = obj.text.trim();
					if (typeof obj.ts === "string" && obj.ts.trim()) ts = obj.ts.trim();
					if (Number.isFinite(obj.stepId)) stepId = Number(obj.stepId);
				} catch {
					// 宽容解析：坏行整行当文本
				}
				const truncated = text.slice(0, INTERVENTION_TEXT_LIMIT);
				const target = stepId !== undefined ? `→ step #${stepId}` : "";
				const meta = [target, ts].filter(Boolean).join(", ");
				const label = meta ? `[steer ${meta}]` : `[steer]`;
				entries.push({ ts, formatted: `- ${label} ${truncated}` });
			}
		} catch {
			/* 读取失败忽略 */
		}
	}

	// 时间正序、不去重
	entries.sort((a, b) => {
		if (a.ts && b.ts) return a.ts.localeCompare(b.ts);
		return 0;
	});

	return entries;
}

/** 格式化【操作员干预史（最近）】块；空窗口返回 undefined（不渲染）。 */
export function renderRecentInterventions(taskDir: string): string | undefined {
	const entries = readRecentInterventions(taskDir);
	if (entries.length === 0) return undefined;
	return [
		"【操作员干预史（最近）】",
		"hint=调度层建议，steer=已插进 worker 会话的纠偏；结合当前态势判断是否已消化，旧项已处理可忽略。",
		...entries.map((e) => e.formatted),
	].join("\n");
}

function textResult(text: string) {
	return { content: [{ type: "text" as const, text }], details: null };
}

// ── todos（跨唤醒共享串行链载体） ──

export interface TodoItem {
	text: string;
	done?: boolean;
}

export function readTodos(taskDir: string): TodoItem[] {
	try {
		const arr = JSON.parse(readFileSync(join(taskDir, "todos.json"), "utf-8")) as TodoItem[];
		return Array.isArray(arr) ? arr.slice(0, 100) : [];
	} catch {
		return [];
	}
}

function writeTodos(taskDir: string, todos: TodoItem[]): void {
	writeFileSync(join(taskDir, "todos.json"), JSON.stringify(todos.slice(0, TODO_MAX), null, 2), "utf-8");
}

export function renderTodos(todos: TodoItem[]): string {
	return todos.map((t, i) => `${i + 1}. ${t.done ? "[已完成]" : "[待办]"} ${t.text}`).join("\n");
}

// ── planner 工具面 ──

export interface PlannerToolOptions {
	db: Database;
	taskId: string;
	taskDir: string;
	sessionId?: string;
	assetsDb?: Database;
}

export function createPlannerTools(
	opts: PlannerToolOptions & { acceptedCounter?: { n: number }; rejectedCounter?: { n: number } },
): AgentTool<any>[] {
	const addStepTool: AgentTool<any> = {
		name: "add_step",
		label: "Add step",
		description: [
			"派 1-4 条新 step（一次批量，挑最高价值的）。step_id 由系统分配，dispatch 边程序自动落。",
			"note 必须写详细：为什么开（依据哪个 fact，引节点 id + 转述）、已知什么、下一步具体做什么。",
			"同义 open/running step 会被程序拒收（回执给理由）；换措辞重复生成已有 step 是严重错误。",
		].join("\n"),
		parameters: Type.Object({
			steps: Type.Array(
				Type.Object({
					summary: Type.String({ description: "一句话：测什么+为什么" }),
					note: Type.Optional(Type.String({ description: "详细上下文：依据/已知/下一步，引证节点 id" })),
					priority: Type.Optional(Type.Number({ description: "0-5，高价值链路优先被领，默认 0" })),
					parent_ids: Type.Optional(Type.Array(Type.Number(), { description: "由哪些节点推来（derives_from 血缘）" })),
				}),
				{ description: "1-4 条", minItems: 1, maxItems: 4 },
			),
		}),
		execute: async (_id, params: any) => {
			const steps = (params?.steps ?? []) as Array<{ summary: string; note?: string; priority?: number; parent_ids?: number[] }>;
			if (!Array.isArray(steps) || steps.length < 1) throw new Error("steps 必填（1-4 条）");
			const res = addStep(opts.db, opts.taskId, steps, opts.sessionId);
			if (opts.acceptedCounter) opts.acceptedCounter.n += res.accepted.length;
			if (opts.rejectedCounter) opts.rejectedCounter.n += res.rejected.length;
			const lines = [
				...res.accepted.map((a) => `已派 step #${a.id}: ${a.summary}`),
				...res.rejected.map((r) => `拒收: 「${r.summary}」——${r.reason}`),
			];
			return textResult(lines.join("\n") || "（无动作）");
		},
	};

	const concludeTaskTool: AgentTool<any> = {
		name: "conclude_task",
		label: "Conclude task",
		description: [
			"宣告任务收尾：确认方向已探尽或目标不可达时调用，reason 引 recent_done 的节点说明为何再派无价值。",
			"调用后调度循环以 goal-closed 终止。方向没探尽就调用是严重错误——该派就派。",
			"程序防线：图上还有 open/running step 时调用会被拒（无权宣判终局）；goal 已收尾/盖章后重复调用也拒。",
		].join("\n"),
		parameters: Type.Object({
			reason: Type.String({ description: "为何收尾（引 recent_done 的节点 id 说明为何再派无价值）" }),
		}),
		execute: async (_id, params: any) => {
			concludeGoal(opts.db, {
				taskId: opts.taskId,
				reason: String(params?.reason ?? ""),
				sessionId: opts.sessionId,
			});
			return textResult("任务已收尾（goal closed）——调度循环将以 goal-closed 终止。");
		},
	};

	const proveGoalTool: AgentTool<any> = {
		name: "prove_goal",
		label: "Prove goal",
		description: "判定目标达成。evidence_id 必须是真实支撑结论的 fact（挂空气证据会被程序拒）；含量化条件先核对态势实测值。盖章后调度循环终止。",
		parameters: Type.Object({
			goal_id: Type.Number({ description: "root goal 编号（态势里 goal.id）" }),
			evidence_id: Type.Number({ description: "支撑达成的 fact 编号" }),
			reason: Type.String({ description: "为何已达成（引证据说明）" }),
		}),
		execute: async (_id, params: any) => {
			proveGoal(opts.db, {
				taskId: opts.taskId,
				goalId: Number(params?.goal_id),
				evidenceId: Number(params?.evidence_id),
				reason: String(params?.reason ?? ""),
				sessionId: opts.sessionId,
			});
			return textResult(`goal #${params?.goal_id} 已盖章 achieved——调度将终止。`);
		},
	};

	const todoTool: AgentTool<any> = {
		name: "TodoWrite",
		label: "TodoWrite",
		description: "读写跨唤醒待办（串行利用链载体）：强依赖链记整条，本轮只派前置已满足的那步。全量覆写式——每次提交完整待办列表（≤20 条）。",
		parameters: Type.Object({
			todos: Type.Array(
				Type.Object({
					text: Type.String({ description: "待办内容（链上哪一步+依赖谁）" }),
					done: Type.Optional(Type.Boolean({ description: "已完成则标 true（会被清理）" })),
				}),
				{ maxItems: TODO_MAX },
			),
		}),
		execute: async (_id, params: any) => {
			const todos = (params?.todos ?? []) as TodoItem[];
			const kept = todos.filter((t) => typeof t?.text === "string" && t.text.trim() && !t.done).slice(0, TODO_MAX);
			writeTodos(opts.taskDir, kept);
			return textResult(`待办已写（${kept.length} 条待续）`);
		},
	};

	const listFactsTool: AgentTool<any> = {
		name: "list_facts",
		label: "List facts",
		description: "分页看全部 fact（最新在前，每页 20，支持 q 过滤 summary）。态势里的 recent_facts 只有 20 条，更多用本工具翻。",
		parameters: Type.Object({
			page: Type.Optional(Type.Number({ description: "页码，从 1 起，默认 1" })),
			q: Type.Optional(Type.String({ description: "fact 摘要关键词过滤" })),
		}),
		execute: async (_id, params: any) => {
			const page = Math.max(1, Number(params?.page) || 1);
			const q = params?.q ? String(params.q).trim() : undefined;
			if (q) {
				const allRows = opts.db
					.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='fact' ORDER BY id DESC")
					.all(opts.taskId) as NodeRow[];
				const qKey = normalizeSummary(q);
				const filtered = allRows.filter((r) => {
					const p = JSON.parse(r.payload) as { summary: string };
					return normalizeSummary(p.summary).includes(qKey);
				});
				const hasMore = filtered.length > page * FACTS_PAGE;
				const facts = filtered.slice((page - 1) * FACTS_PAGE, page * FACTS_PAGE).map((r) => {
					const p = JSON.parse(r.payload) as { summary: string; confidence: string };
					return { id: r.id, summary: p.summary, confidence: p.confidence, from_step: r.step_id };
				});
				return textResult(JSON.stringify({ page, has_more: hasMore, facts }, null, 1));
			}

			const rows = opts.db
				.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='fact' ORDER BY id DESC LIMIT ? OFFSET ?")
				.all(opts.taskId, FACTS_PAGE + 1, (page - 1) * FACTS_PAGE) as NodeRow[];
			const hasMore = rows.length > FACTS_PAGE;
			const facts = rows.slice(0, FACTS_PAGE).map((r) => {
				const p = JSON.parse(r.payload) as { summary: string; confidence: string };
				return { id: r.id, summary: p.summary, confidence: p.confidence, from_step: r.step_id };
			});
			return textResult(JSON.stringify({ page, has_more: hasMore, facts }, null, 1));
		},
	};

	const nodeDetailTool: AgentTool<any> = {
		name: "node_detail",
		label: "Node detail",
		description: "看某节点的完整 payload（evidence/详情）——列表只给摘要，采信前下钻看证据。",
		parameters: Type.Object({
			id: Type.Number({ description: "节点编号" }),
		}),
		execute: async (_id, params: any) => {
			const node = getNode(opts.db, opts.taskId, Number(params?.id));
			if (!node) throw new Error(`节点 #${params?.id} 不存在`);
			return textResult(`#${node.id} [${node.kind}/${node.state}] origin=${node.origin}\npayload: ${node.payload}`);
		},
	};

	const tools = [addStepTool, concludeTaskTool, proveGoalTool, todoTool, listFactsTool, nodeDetailTool];
	if (opts.assetsDb) {
		tools.push(createListAssetsTool({ assetsDb: opts.assetsDb, taskId: opts.taskId }));
	}
	return tools;
}

// ── runPlanner ──

export interface RunPlannerOptions {
	db: Database;
	task: { name: string };
	taskDir: string;
	events: TriggerEvent[];
	channel: ChannelConfig;
	secrets?: Secrets;
	timeoutMs?: number;
	/** 外部终止信号（p2fix P2F-5：stop watcher 与超时并联 abort）。 */
	abortSignal?: AbortSignal;
	onEvent?: (ev: AgentEvent) => void;
	/** streamFn 注入口（P3pre 测试用：假流验传输层故障路径；缺省用 channel 构造的）。 */
	streamFn?: StreamFn;
	/** 项目级资产库（P3-4/P3-5：在场时装配 list_assets + 态势 coverage 块）。 */
	assetsDb?: Database;
	/** 项目简报节（P3-6：首轮一次性注入前任 task 发现与实证观察）。 */
	briefingText?: string;
}

export interface RunPlannerResult {
	acceptedCount: number;
	rejectedCount: number;
	proved: boolean;
	usage: { turns: number; input: number; output: number; cacheRead: number };
	finalText: string;
	/** 传输层故障（P3pre-3：唤醒没真正发生——调度器据此重试/终止，事件不消费）。 */
	transportError?: string;
}

export async function runPlanner(opts: RunPlannerOptions): Promise<RunPlannerResult> {
	const { db, task, taskDir } = opts;
	const sessionId = `${task.name}-planner-${Date.now()}`;
	const channel = createChannelFromConfig(opts.channel, opts.secrets);

	// 收官判定（v1.2/方案 C 语义）：唤醒时图上无待办 step 即追加收官变体
	const openCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=? AND kind='step' AND state IN ('open','running')").get(task.name) as { n: number }).n;
	const stalled =
		openCount === 0 && !goalAchieved(db, task.name) && !goalClosed(db, task.name);

	const events = [...opts.events];
	if (stalled && !events.some((e) => e.type === "stall")) {
		events.push({ type: "stall" });
	}

	const overview = graphOverview(db, task.name, opts.assetsDb);
	const todos = readTodos(taskDir);
	const interventionsText = renderRecentInterventions(taskDir);
	const goalText = overview.goal ? `${overview.goal.text}（#${overview.goal.id}, ${overview.goal.state}）` : "（无）";

	const usage = { turns: 0, input: 0, output: 0, cacheRead: 0 };
	const texts: string[] = [];
	const acceptedCounter = { n: 0 };
	const rejectedCounter = { n: 0 };
	// P3pre-3：传输层故障检测（与 worker 同款——pi 不抛错，错误走 message_end 事件）
	let transportFailure: ChannelTransportFailure | undefined;

	const agent = new Agent({
		initialState: {
			systemPrompt: PLANNER_SYSTEM_PROMPT,
			tools: createPlannerTools({
				db,
				taskId: task.name,
				taskDir,
				sessionId,
				acceptedCounter,
				rejectedCounter,
				assetsDb: opts.assetsDb,
			}),
			model: channel.model,
			thinkingLevel: channel.thinkingLevel,
		},
		streamFn: opts.streamFn ?? channel.streamFn,
		getApiKey: async () => channel.apiKey,
	});

	const unsubscribe = agent.subscribe(async (ev: AgentEvent) => {
		opts.onEvent?.(ev);
		if (ev.type === "turn_end") {
			const u = (ev.message as { usage?: Record<string, number> }).usage ?? {};
			usage.turns += 1;
			usage.input += u.input ?? 0;
			usage.output += u.output ?? 0;
			usage.cacheRead += u.cacheRead ?? 0;
		} else if (ev.type === "message_end") {
			const msg = ev.message as { role?: string; content?: Array<{ type: string; text?: string }> };
			if (msg.role === "assistant" && Array.isArray(msg.content)) {
				const t = msg.content.filter((c) => c.type === "text" && c.text?.trim()).map((c) => c.text).join("\n");
				if (t) texts.push(t);
			}
			transportFailure = transportFailureFromMessage(ev.message) ?? transportFailure;
		}
	});

	const doAbort = () => agent.abort();
	const timeout = setTimeout(doAbort, opts.timeoutMs ?? 300_000);
	const onAbort = () => doAbort();
	opts.abortSignal?.addEventListener("abort", onAbort, { once: true });
	try {
		await agent.prompt(
			renderPlannerUserMessage({
				triggers: renderTriggers(events),
				interventionsText,
				briefingText: opts.briefingText,
				overviewJson: JSON.stringify(overview),
				todosText: renderTodos(todos),
				goalText,
				stalled,
			}),
		);
	} finally {
		clearTimeout(timeout);
		opts.abortSignal?.removeEventListener("abort", onAbort);
		unsubscribe();
		// usage 落账进 finally（P3pre-3：失败唤醒也记账——429 期间不再"派 0 条"无声无息）
		logActivity(db, {
			task_id: task.name,
			session_id: sessionId,
			worker: "planner",
			kind: "result",
			tool: "runPlanner",
			is_error: Boolean(transportFailure),
			summary: transportFailure
				? `planner 唤醒失败：${transportFailure.label}，events=${events.length} 未消费`
				: `planner 唤醒：events=${events.length} stalled=${stalled} 派${acceptedCounter.n}条拒${rejectedCounter.n}条`,
			detail: transportFailure ? transportFailure.raw.slice(0, 800) : (texts[texts.length - 1] ?? "").slice(0, 800),
			tokens: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead },
		});
	}

	return {
		acceptedCount: acceptedCounter.n,
		rejectedCount: rejectedCounter.n,
		proved: goalAchieved(db, task.name),
		usage,
		finalText: texts[texts.length - 1] ?? "",
		...(transportFailure ? { transportError: transportFailure.label + "：" + transportFailure.raw } : {}),
	};
}
