/**
 * worker 会话基建（P1-4）——runWorkerStep：领一条 step 干活并写回图。
 *
 * 非调度（D2 拍板）：step 由调用方/测试夹具传入；P2 换 planner 供给，本接口不变。
 * user 首条 =【你领到的 step】+【全局态势】（graphOverview 渲染，态势预取省往返）。
 * 收尾 = usage 落 activity（token 四列，R-2 从根消解）+ step state→done。
 */
import { Agent, type AgentEvent, type AgentTool } from "@earendil-works/pi-agent-core";
import type { Database } from "better-sqlite3";
import { createChannel, type ChannelMode } from "./channel.js";
import { createGuard } from "./guard.js";
import { graphOverview, setStepState, type GraphOverview } from "./graph.js";
import type { NodeRow, } from "./db.js";
import { logActivity } from "./db.js";
import { createBashTool, createReadTool, createWriteTool } from "./tools/exec.js";
import { createSubmitFactTool, createSubmitFindingTool } from "./tools/submit.js";
import { BrowserSession, createNavigateTool, createSnapshotTool } from "./tools/browser.js";
import type { TaskJson } from "./task.js";
import type { Secrets } from "./secrets.js";
import { BrowserPool } from "./browser-pool.js";

export const WORKER_SYSTEM_PROMPT = [
	"你是 AT1 渗透测试 worker。领【一条 step】，唯一职责 = 完成 → 写回图 → 停止。",
	"边界红线：",
	"- 只做领到的这一条；瞥见别的线索 → 写成 fact 上抛（宁可多报让规划者判断，不要自己动手）；",
	"- 初次受阻 ≠ 探透：绕过手段走完再下结论；",
	"- 操作约束最高优先：每条命令执行前自检是否越界；发现约束外新目标 ≠ 获得授权，记 fact 跳过；",
	"- 一切结论必须有可复核证据；边发现边写回（别攒到结束丢掉）；完成即停。",
].join("\n");

export interface WorkerUsageTotals {
	turns: number;
	input: number;
	output: number;
	cacheRead: number;
	cacheWrite: number;
}

export interface RunWorkerStepResult {
	stepId: number;
	finalText: string;
	usage: WorkerUsageTotals;
	facts: number;
	findings: number;
	/** 本次会话新产出的 fact/finding 编号（P2 调度触发事件用）。 */
	newFactIds: number[];
	newFindingIds: number[];
	/** 会话被超时掐断（P2 置 step=exhausted，planner 重派"接上次继续"）。 */
	aborted: boolean;
}

export interface RunWorkerStepOptions {
	db: Database;
	task: TaskJson;
	taskDir: string;
	step: NodeRow;
	secrets?: Secrets;
	mode?: ChannelMode;
	browser?: boolean; // P1 默认开（smoke 要）；纯 bash task 可关
	timeoutMs?: number;
	onEvent?: (ev: AgentEvent) => void;
}

export function renderStepPrompt(step: NodeRow, overview: GraphOverview): string {
	const payload = JSON.parse(step.payload) as { summary: string; note?: string };
	return [
		`【你领到的 step】#${step.id}`,
		`目标：${payload.summary}`,
		...(payload.note ? [`上下文/打法：${payload.note}`] : []),
		"",
		"【全局态势】",
		JSON.stringify(overview),
		"",
		"完成定义：",
		"1. 用 Bash/浏览器对目标做该 step 描述的动作；",
		"2. 把关键证据用 Write 写进 evidence/<名字>.txt（一行命令 + 最能证明的输出）；",
		"3. submit_fact（step_id 填本 step 编号）写回结论；若确认漏洞则 submit_finding；",
		"4. 完成即停，不要领取或执行其他 step。",
	].join("\n");
}

export async function runWorkerStep(opts: RunWorkerStepOptions): Promise<RunWorkerStepResult> {
	const { db, task, taskDir, step } = opts;
	const channel = createChannel(opts.mode ?? "openai", opts.secrets);
	const sessionId = `${task.name}-worker-s${step.id}-${Date.now()}`;

	const overview = graphOverview(db, task.name);

	let pool: BrowserPool | undefined;
	if (opts.browser !== false) {
		pool = await BrowserPool.start(taskDir);
	}
	const browserSession = pool ? new BrowserSession(pool.endpoint) : undefined;

	const usage: WorkerUsageTotals = { turns: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
	const texts: string[] = [];

	const tools: AgentTool<any>[] = [
		createBashTool(taskDir),
		createReadTool(taskDir),
		createWriteTool(taskDir),
		...(browserSession ? [createNavigateTool(browserSession), createSnapshotTool(browserSession)] : []),
		createSubmitFactTool({ db, taskId: task.name, taskDir, sessionId }),
		createSubmitFindingTool({ db, taskId: task.name, taskDir, sessionId }),
	];

	const agent = new Agent({
		initialState: {
			systemPrompt: WORKER_SYSTEM_PROMPT,
			tools,
			model: channel.model,
			thinkingLevel: "low", // glm-5.3 始终思考，off 会发 thinking:disabled 被拒（1210）
		},
		streamFn: channel.streamFn,
		getApiKey: async () => channel.apiKey,
		beforeToolCall: createGuard(db, { taskId: task.name, sessionId, scopeHosts: task.scope.hosts }),
	});

	const unsubscribe = agent.subscribe(async (ev: AgentEvent) => {
		opts.onEvent?.(ev);
		if (ev.type === "turn_end") {
			const msg = ev.message as { usage?: Record<string, number> };
			const u = msg.usage ?? {};
			usage.turns += 1;
			usage.input += u.input ?? 0;
			usage.output += u.output ?? 0;
			usage.cacheRead += u.cacheRead ?? 0;
			usage.cacheWrite += u.cacheWrite ?? 0;
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

	let aborted = false;
	const timeout = setTimeout(() => {
		aborted = true;
		agent.abort();
	}, opts.timeoutMs ?? 600_000);
	try {
		await agent.prompt(renderStepPrompt(step, overview));
	} finally {
		clearTimeout(timeout);
		unsubscribe();
		if (browserSession) await browserSession.dispose();
		if (pool) await pool.shutdown();
	}

	// 收尾：计量落 activity（token 四列）+ step 状态（正常 done / 超时 exhausted）
	logActivity(db, {
		task_id: task.name,
		node_id: step.id,
		session_id: sessionId,
		worker: "worker",
		kind: "result",
		tool: "runWorkerStep",
		summary: `step #${step.id} ${aborted ? "超时掐断" : "完成"}，${usage.turns} 轮`,
		detail: (texts[texts.length - 1] ?? "").slice(0, 1000),
		tokens: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead, cacheWrite: usage.cacheWrite },
	});
	setStepState(db, task.name, step.id, aborted ? "exhausted" : "done");

	const newFactIds = idsBySession(db, sessionId, "fact");
	const newFindingIds = idsBySession(db, sessionId, "finding");
	const counts = db
		.prepare(
			"SELECT kind, COUNT(*) AS n FROM nodes WHERE task_id = ? AND origin = 'worker' GROUP BY kind",
		)
		.all(task.name) as Array<{ kind: string; n: number }>;

	return {
		stepId: step.id,
		finalText: texts[texts.length - 1] ?? "",
		usage,
		facts: counts.find((c) => c.kind === "fact")?.n ?? 0,
		findings: counts.find((c) => c.kind === "finding")?.n ?? 0,
		newFactIds,
		newFindingIds,
		aborted,
	};
}

function idsBySession(db: Database, sessionId: string, kind: string): number[] {
	return (
		db
			.prepare("SELECT id FROM nodes WHERE session_id = ? AND kind = ? ORDER BY id")
			.all(sessionId, kind) as Array<{ id: number }>
	).map((r) => r.id);
}
