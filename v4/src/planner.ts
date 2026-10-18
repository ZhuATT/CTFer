/**
 * planner 会话（P2-1）——pi Agent 全新会话，与 worker 永不同会话（§3.1）。
 *
 * 工具面五个：add_step（批量≤4+D3 拒重）/ prove_goal（D7 校验）/ TodoWrite
 * （todos.json 跨唤醒）/ list_facts（分页20）/ node_detail。
 * 不做：kill_work/steer_work（单 worker 无在跑可杀）、list_assets（P3）、Bash（纯读图）。
 * usage 落 activity（worker="planner"）——计量分列（验收项）。
 */
import { Agent, type AgentEvent, type AgentTool } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import { Type } from "@earendil-works/pi-ai";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createChannelFromConfig } from "./channel.js";
import type { ChannelConfig } from "./config.js";
import { addStep, goalAchieved, getNode, graphOverview, proveGoal } from "./graph.js";
import { logActivity, type NodeRow } from "./db.js";
import { PLANNER_SYSTEM_PROMPT, renderPlannerUserMessage } from "./planner-prompt.js";
import { renderTriggers, type TriggerEvent } from "./triggers.js";
import type { Secrets } from "./secrets.js";

const FACTS_PAGE = 20;
const TODO_MAX = 20;

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
}

export function createPlannerTools(opts: PlannerToolOptions & { acceptedCounter?: { n: number } }): AgentTool<any>[] {
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
			const lines = [
				...res.accepted.map((a) => `已派 step #${a.id}: ${a.summary}`),
				...res.rejected.map((r) => `拒收: 「${r.summary}」——${r.reason}`),
			];
			return textResult(lines.join("\n") || "（无动作）");
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
		description: "分页看全部 fact（最新在前，每页 20）。态势里的 recent_facts 只有 20 条，更多用本工具翻。",
		parameters: Type.Object({
			page: Type.Optional(Type.Number({ description: "页码，从 1 起，默认 1" })),
		}),
		execute: async (_id, params: any) => {
			const page = Math.max(1, Number(params?.page) || 1);
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

	return [addStepTool, proveGoalTool, todoTool, listFactsTool, nodeDetailTool];
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
	onEvent?: (ev: AgentEvent) => void;
}

export interface RunPlannerResult {
	acceptedCount: number;
	rejectedCount: number;
	proved: boolean;
	usage: { turns: number; input: number; output: number; cacheRead: number };
	finalText: string;
}

export async function runPlanner(opts: RunPlannerOptions): Promise<RunPlannerResult> {
	const { db, task, taskDir } = opts;
	const sessionId = `${task.name}-planner-${Date.now()}`;
	const channel = createChannelFromConfig(opts.channel, opts.secrets);

	// 停摆判定：已有 done 产出 + 无 open + goal 未达
	const openCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=? AND kind='step' AND state IN ('open','running')").get(task.name) as { n: number }).n;
	const doneCount = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=? AND kind='step' AND state='done'").get(task.name) as { n: number }).n;
	const stalled = opts.events.some((e) => e.type === "stall") || (openCount === 0 && doneCount > 0 && !goalAchieved(db, task.name));

	const events = [...opts.events];
	if (openCount === 0 && doneCount > 0 && !goalAchieved(db, task.name) && !events.some((e) => e.type === "stall")) {
		events.push({ type: "stall" });
	}

	const overview = graphOverview(db, task.name);
	const todos = readTodos(taskDir);
	const goalText = overview.goal ? `${overview.goal.text}（#${overview.goal.id}, ${overview.goal.state}）` : "（无）";

	const usage = { turns: 0, input: 0, output: 0, cacheRead: 0 };
	const texts: string[] = [];
	const acceptedCounter = { n: 0 };

	const agent = new Agent({
		initialState: {
			systemPrompt: PLANNER_SYSTEM_PROMPT,
			tools: createPlannerTools({ db, taskId: task.name, taskDir, sessionId, acceptedCounter }),
			model: channel.model,
			thinkingLevel: "low",
		},
		streamFn: channel.streamFn,
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
		}
	});

	const timeout = setTimeout(() => agent.abort(), opts.timeoutMs ?? 300_000);
	try {
		await agent.prompt(
			renderPlannerUserMessage({
				triggers: renderTriggers(events),
				overviewJson: JSON.stringify(overview),
				todosText: renderTodos(todos),
				goalText,
				stalled,
			}),
		);
	} finally {
		clearTimeout(timeout);
		unsubscribe();
	}

	logActivity(db, {
		task_id: task.name,
		session_id: sessionId,
		worker: "planner",
		kind: "result",
		tool: "runPlanner",
		summary: `planner 唤醒：events=${events.length} stalled=${stalled} 派${acceptedCounter.n}条`,
		detail: (texts[texts.length - 1] ?? "").slice(0, 800),
		tokens: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead },
	});

	return {
		acceptedCount: acceptedCounter.n,
		rejectedCount: 0,
		proved: goalAchieved(db, task.name),
		usage,
		finalText: texts[texts.length - 1] ?? "",
	};
}
