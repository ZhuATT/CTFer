/**
 * worker 会话基建（P1-4 / p2fix P2F-1/7/8/11）——runWorkerStep：领一条 step 干活并写回图。
 *
 * 非调度（D2 拍板）：step 由调用方/测试夹具传入；P2 换 planner 供给，本接口不变。
 * 通道（P2F-1）：调度循环传整份 cfg.channels.worker；P1 兼容入口（单跑/测试）保留 mode。
 * user 首条 =【你领到的 step】+【任务态势】（p2fix 审7 精简版：goal+本 step 血缘 facts，
 * 全图 steps/findings 是 planner 的视野）+【standards 索引】（渐进披露）。
 * abort（P2F-5）：内部 stepTimeout 与外部 abortSignal（stop watcher）并联，同一条优雅收尾路。
 * steer（P2F-11）：onAgent 把会话暴露给调度器，【操作员插话】经 agent.steer() 送达。
 * 收尾 = usage 落 activity（token 四列，R-2 从根消解）+ step state→done/exhausted/blocked 三态。
 * 传输层故障（P3pre-2）：pi 不抛错（错误走 message_end 事件 stopReason="error"），订阅层检测
 *   → step 翻 blocked + activity 落 is_error 账，planner 按 v1.2 blocked 重派规则接续。
 * steer 核销（P3pre-4）：送达账是乐观的——会话收尾核对未消费队列，有残留落 is_error 账。
 */
import { Agent, type AgentEvent, type AgentTool, type StreamFn } from "@earendil-works/pi-agent-core";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Database } from "better-sqlite3";
import { createChannel, createChannelFromConfig, transportFailureFromMessage, type ChannelMode, type ChannelTransportFailure } from "./channel.js";
import type { ChannelConfig } from "./config.js";
import { createGuard } from "./guard.js";
import { setStepState, stepLineageView, type WorkerSituationalView } from "./graph.js";
import type { NodeRow } from "./db.js";
import { logActivity } from "./db.js";
import { createBashTool, createReadTool, createWriteTool } from "./tools/exec.js";
import { createSubmitFactTool, createSubmitFindingTool } from "./tools/submit.js";
import { createRegisterAssetTool } from "./tools/assets.js";
import { BrowserSession, createNavigateTool, createSnapshotTool } from "./tools/browser.js";
import type { TaskJson } from "./task.js";
import type { Secrets } from "./secrets.js";
import { BrowserPool } from "./browser-pool.js";

export const WORKER_SYSTEM_PROMPT = [
	// v2（2026-10-21 拍板，草案与块对照见 docs/PI-prompt.md §9.1）：
	// 增身份段/三层判读/探透标准/障碍分支/写操作纪律/防捏造句；红线与 steer 纪律保留。
	"你是授权渗透测试的执行专家——经验丰富的黑盒 web 渗透测试员，擅长在陌生目标上从蛛丝马迹推进到可证明的影响。你领【一条 step】，唯一职责 = 完成 → 写回图 → 停止。你的写回是整个系统对目标的唯一感知：规划者只能基于你写进图的东西思考，你落下的每条 fact 的质量决定全队的判断质量。",
	"",
	"【三层判读】（探索时这样看盘，写回前这样归类）：",
	"- 现象：报错、指纹、配置特征、响应异常——是路标不是发现；围绕它验证「能不能往前走」，别单独上报；",
	"- 中间能力：语法可控但还没拖到数据、守卫缺失但还没越过去、入口确认但还没打穿——这是有价值的 fact，如实进 submit_fact（confidence 按证据标）；",
	"- 成果：攻击者能做到本来不该做的事（读到他人数据 / 执行了不该执行的操作 / 拿到不该有的权限）——进 submit_finding。",
	"切分问句：「这是同一个『我能做到 X』吗？」——是→一条；否→各一条；链式影响按链的终点断成一条。嫌疑不是发现：触发不了就记 inferred fact 交规划者，别硬报。",
	"",
	"【探透的标准】：初次受阻 ≠ 死路。换编码 / 换方法 / 换参数 / 换路径，把合理绕过手段走完才可判「探不动」——每一步要有新意图，重复同一姿势不是探透是浪费。",
	"",
	"【障碍分支】（常见形态的下一步）：",
	"- 401/403：先查认证与身份（cookie/头/令牌对不对），再试越权变体（换 id、换方法、换路径写法）；",
	"- 404：端点大概率不存在——别原样重试，换相邻命名（复数/缩写/版本/前缀）；",
	"- 429/限速：立即降频或暂停该端点，换姿势硬冲没有意义；",
	"- 5xx/超时：可能是注入点或不稳定——重试一次，稳定复现就值得记录；",
	"- 拦截页/统一报错页（WAF 特征）：换编码与载荷形态，一次只变一个变量。",
	"",
	"【写操作纪律】：能用测试对象就不动真实对象；必须写时，写完用读接口回读验证值真的变了；删除/批量修改/不可逆操作不做——发现写入面即记 fact 上报，让系统决定。",
	"",
	"边界红线：",
	"- 只做领到的这一条；瞥见别的线索 → 写成 fact 上抛（宁可多报让规划者判断，不要自己动手）；",
	"- 操作约束最高优先：每条命令执行前自检是否越界；发现约束外新目标 ≠ 获得授权，记 fact 跳过；",
	"- 一切结论必须能指着工具输出里的原文行说话——引用不出的当作没见过；边发现边写回（别攒到结束丢掉）；完成即停。",
	"",
	"会话中可能出现【操作员插话】（steer）——那是情报补充或纠偏，不是新任务：完成当前 step，把相关观察落 fact 上抛，不自开新方向。",
].join("\n");

/** steer 目标接口（P2F-11）：worker 会话暴露给调度器 watcher 的最小插话面。 */
export interface SteerableTarget {
	steer(message: { role: "user"; content: string; timestamp: number }): void;
}

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
	/** 会话被掐断（超时/stop watcher——P2 置 step=exhausted，planner 重派「接上次继续」）。 */
	aborted: boolean;
	/** 传输层故障（P3pre-2：429/网络断连等——step=blocked，planner 直接重派）。 */
	transportError?: string;
}

export interface RunWorkerStepOptions {
	db: Database;
	task: TaskJson;
	taskDir: string;
	step: NodeRow;
	secrets?: Secrets;
	/** 完整通道配置（P2F-1：调度循环传 cfg.channels.worker）。 */
	channel?: ChannelConfig;
	/** P1 兼容入口（单跑/测试用）：mode + 默认 model/keyEnv。channel 优先。 */
	mode?: ChannelMode;
	browser?: boolean; // P1 默认开（smoke 要）；纯 bash task 可关
	timeoutMs?: number;
	/** 外部终止信号（P2F-5：stop watcher；与内部 timeout 并联，同落 exhausted）。 */
	abortSignal?: AbortSignal;
	/** 会话暴露（P2F-11）：调度器经此对在跑 step 送达操作员 steer。 */
	onAgent?: (agent: SteerableTarget) => void;
	onEvent?: (ev: AgentEvent) => void;
	/** streamFn 注入口（P3pre 测试用：假流验 blocked 路径；缺省用 channel 构造的）。 */
	streamFn?: StreamFn;
	/** 项目级资产库（P3-3/P3-4：在场时装配 register_asset + 机械落锚）。 */
	assetsDb?: Database;
	/** 动态 scope 白名单集合（P3-7：支持 scope-add 原位扩权）。 */
	scopeHosts?: string[] | Set<string>;
}

/** worker user 首条（p2fix 审7 精简态势版）。standardsIndex：standards/INDEX.md 内容
 * （P2F-8 渐进披露——索引坐 user 首条固定小开销，正文按需 Read/Grep）。 */
export function renderStepPrompt(step: NodeRow, situational: WorkerSituationalView, standardsIndex?: string): string {
	const payload = JSON.parse(step.payload) as { summary: string; note?: string };
	return [
		`【你领到的 step】#${step.id}`,
		`目标：${payload.summary}`,
		...(payload.note ? [`上下文/打法：${payload.note}`] : []),
		"",
		...(standardsIndex?.trim() ? ["【standards 索引】", standardsIndex.trim(), ""] : []),
		"【任务态势】",
		JSON.stringify(situational),
		"",
		"完成定义：",
		"1. 用 Bash/浏览器对目标做该 step 描述的动作；",
		"2. 把关键证据用 Write 写进 evidence/<名字>.txt（一行命令 + 最能证明的输出）；",
		"3. submit_fact（step_id 填本 step 编号）写回结论；若确认漏洞则 submit_finding；endpoint 参数写完整 host[:port]/路径 形态（锚定资产用），别写纯路径；",
		"3.5 若方向探不动/结果全阴性：这也是结论——submit_fact 落阴性观察（confidence=observed，summary 写明已试手段与结果），别空手收尾；",
		"4. 完成即停，不要领取或执行其他 step。",
		"",
		"开工按 step 方向查阅 standards/ 下相关手册（评级细则/方法论），有则先读相关节，没有就跳过。",
	].join("\n");
}

export async function runWorkerStep(opts: RunWorkerStepOptions): Promise<RunWorkerStepResult> {
	const { db, task, taskDir, step } = opts;
	// P2F-1：完整配置优先；无配置走 P1 兼容入口（单跑/测试）
	const channel = opts.channel
		? createChannelFromConfig(opts.channel, opts.secrets)
		: createChannel(opts.mode ?? "openai", opts.secrets);
	const sessionId = `${task.name}-worker-s${step.id}-${Date.now()}`;

	const situational = stepLineageView(db, task.name, step);
	const standardsIndex = readStandardsIndex(taskDir);

	const usage: WorkerUsageTotals = { turns: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
	const texts: string[] = [];
	// P3pre-2：传输层故障检测（pi 不抛错，错误以 message_end(stopReason="error") 过事件流）
	let transportFailure: ChannelTransportFailure | undefined;
	let pool: BrowserPool | undefined;
	let browserSession: BrowserSession | undefined;
	let agent: Agent | undefined;
	let unsubscribe: (() => void) | undefined;
	let timeout: NodeJS.Timeout | undefined;
	let onAbort: (() => void) | undefined;
	let aborted = false;

	try {
		// P3pre-6 ①：BrowserPool 挪进 try 防护，配合 finally shutdown 杜绝 zombie chrome
		if (opts.browser !== false) {
			pool = await BrowserPool.start(taskDir);
			browserSession = new BrowserSession(pool.endpoint);
		}

		const tools: AgentTool<any>[] = [
			createBashTool(taskDir),
			createReadTool(taskDir),
			createWriteTool(taskDir),
			...(browserSession ? [createNavigateTool(browserSession), createSnapshotTool(browserSession)] : []),
			createSubmitFactTool({ db, taskId: task.name, taskDir, sessionId, assetsDb: opts.assetsDb }),
			createSubmitFindingTool({ db, taskId: task.name, taskDir, sessionId, assetsDb: opts.assetsDb }),
			...(opts.assetsDb
				? [createRegisterAssetTool({ assetsDb: opts.assetsDb, taskId: task.name, project: task.project })]
				: []),
		];

		agent = new Agent({
			initialState: {
				systemPrompt: WORKER_SYSTEM_PROMPT,
				tools,
				model: channel.model,
				thinkingLevel: channel.thinkingLevel, // 通道级配置（config.yaml）；glm 系拒 thinking:disabled（1210 坑位见 channel.ts 头注）
			},
			streamFn: opts.streamFn ?? channel.streamFn,
			getApiKey: async () => channel.apiKey,
			beforeToolCall: createGuard(db, {
				taskId: task.name,
				sessionId,
				scopeHosts: opts.scopeHosts ?? task.scope.hosts,
			}),
		});
		opts.onAgent?.(agent);

		unsubscribe = agent.subscribe(async (ev: AgentEvent) => {
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
				transportFailure = transportFailureFromMessage(ev.message) ?? transportFailure;
			}
		});

		// 双 abort 并联（P2F-5）：内部 stepTimeout / 外部 stop watcher——同一条优雅收尾路
		const doAbort = () => {
			aborted = true;
			agent?.abort();
		};
		timeout = setTimeout(doAbort, opts.timeoutMs ?? 1_200_000); // 2026-10-21 拍板：step 超时默认 20min（原 10min 测试值）
		onAbort = () => doAbort();
		opts.abortSignal?.addEventListener("abort", onAbort, { once: true });

		await agent.prompt(renderStepPrompt(step, situational, standardsIndex));
	} finally {
		if (timeout) clearTimeout(timeout);
		if (onAbort) opts.abortSignal?.removeEventListener("abort", onAbort);
		// P3pre-4 steer 两段式核销：watcher 送达账是乐观的（agent.steer() 入队即记"送达"），
		// 会话收尾核对未消费队列——有残留 = 插话没真正进会话，落 is_error 账纠偏
		if (agent?.hasQueuedMessages()) {
			const pending = agent.peekQueuedMessages().length;
			logActivity(db, {
				task_id: task.name,
				node_id: step.id,
				session_id: sessionId,
				worker: "operator",
				kind: "result",
				tool: "steer",
				is_error: true,
				summary: `steer 发送失败：worker 已退出（未消费 ${pending} 条）`,
				detail: "steered 事件已保留，planner 侧兜底判断是否影响后续方向",
			});
		}
		unsubscribe?.();
		if (browserSession) await browserSession.dispose();
		if (pool) await pool.shutdown();
	}

	// 收尾：计量落 activity（token 四列）+ step 三态
	// （P3pre-2：aborted→exhausted｜传输层故障→blocked｜else done；blocked 走 v1.2 重派规则）
	const outcome = aborted ? "exhausted" : transportFailure ? "blocked" : "done";
	logActivity(db, {
		task_id: task.name,
		node_id: step.id,
		session_id: sessionId,
		worker: "worker",
		kind: "result",
		tool: transportFailure ? "channel" : "runWorkerStep",
		is_error: Boolean(transportFailure),
		summary: transportFailure
			? `step #${step.id} blocked：${transportFailure.label}，${usage.turns} 轮`
			: `step #${step.id} ${aborted ? "掐断（超时/stop）" : "完成"}，${usage.turns} 轮`,
		detail: transportFailure ? transportFailure.raw.slice(0, 1000) : (texts[texts.length - 1] ?? "").slice(0, 1000),
		tokens: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead, cacheWrite: usage.cacheWrite },
	});
	setStepState(db, task.name, step.id, outcome);

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
		...(transportFailure ? { transportError: transportFailure.label + "：" + transportFailure.raw } : {}),
	};
}

/** standards/INDEX.md 内容（P2F-8 渐进披露）；无 standards/ 返回 undefined。 */
export function readStandardsIndex(taskDir: string): string | undefined {
	try {
		return readFileSync(join(taskDir, "standards", "INDEX.md"), "utf-8");
	} catch {
		return undefined;
	}
}

function idsBySession(db: Database, sessionId: string, kind: string): number[] {
	return (
		db
			.prepare("SELECT id FROM nodes WHERE session_id = ? AND kind = ? ORDER BY id")
			.all(sessionId, kind) as Array<{ id: number }>
	).map((r) => r.id);
}
