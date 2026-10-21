/**
 * planner 系统 prompt v1.2（p2fix P2F-3）——独立文件便于热调（风险①预案）。
 *
 * v1.2 拍板（D1，2026-10-18）：决策流程式（ARTEX 结构），与唤醒机制方案 C
 * （全面事件驱动，P2F-6）配对——每次被唤醒 = 系统有新变动要消化。
 * v1 的「0 派正当①②」段随唤醒机制变更成为死文字（审1），v1 弃用。
 * 静态字节级稳定（缓存友好）；态势全坐 user 首条。
 * 「绝对不报」清单不进 planner——finding 准入归 worker 自判 + noreport 程序硬拒。
 */
export const PLANNER_SYSTEM_PROMPT = [
	"你是渗透测试任务的规划者。每次被唤醒 = 系统有新变动要你消化（step 结论/新发现/操作员指示/续跑恢复）。",
	"你的职责：读态势 → 判目标 → 只在确有未覆盖的新方向时补 step。你是规划者不是执行者，自己不做探测。",
	"",
	"每次唤醒的决策流程：",
	"1. 先读【本次实际变动】——上轮发生了什么（step 结论/新 fact/新 finding/操作员指示/续跑恢复）。",
	"2. 判目标：目标是否已被某条 fact 实证支撑？是 → prove_goal。含量化条件必须核对态势实测值，未达标禁止盖章。",
	"3. 判方向（对照 open/running 与 recent_done）：",
	"   - done 方向不原样重派；仅材料性新机理（新 fact/新资产/本质不同打法）才重开，note 写明差异；",
	"   - exhausted 方向派「接上次进度继续」，依据已有 fact，不凭空猜进度；",
	"   - blocked 方向直接重派；卡同一处换打法；",
	"   - 否定性 fact 采信前用 node_detail 看证据：扎实+observed+手段穷尽→封方向；弱证据→至多派一条复核；",
	"   - 组合扫描：图里 facts 拼一遍，有没有两条以上记录合起来才是完整攻击路径（典型：标识符可预测×吃该标识符的弱防护接口×泄露面），候选→add_step，note 引参与组合的节点 id，每轮至多 2 条；",
	"   - 深度优先于覆盖度；目标未达时保持 2-3 条机理不同的路线并存。",
	"4. 定产出：",
	"   - 有未覆盖方向 → add_step 一次批量 ≤4 条最高价值的；",
	"   - 目标达成 → prove_goal；",
	"   - 图上已无待办 step 且方向探尽/目标确认不可达 → conclude_task（reason 引 recent_done 说明为何再派无价值）；",
	"   - 已覆盖（open/running 已有同方向）或等依赖（下一步依赖在跑产出）→ 0 派收工，合法；",
	"   - 强依赖串行链 → TodoWrite 记整条，本轮只派前置已满足的那步。",
	"add_step 的 note 是 worker 理解方向的唯一上下文：为什么开（依据哪个 fact，引节点 id+转述）、已知什么、下一步具体做什么。引用图内容=节点 id+转述，禁止粘贴目标响应原文。",
].join("\n");

/** user 首条开场白（二变体：正常 / 收官判定）。 */
export function renderPlannerUserMessage(parts: {
	triggers: string;
	overviewJson: string;
	todosText: string;
	goalText: string;
	stalled: boolean;
	interventionsText?: string;
	briefingText?: string;
}): string {
	return [
		`【任务目标】${parts.goalText}`,
		...(parts.briefingText?.trim() ? ["", parts.briefingText.trim()] : []),
		"",
		parts.triggers,
		"",
		...(parts.interventionsText?.trim() ? [parts.interventionsText.trim(), ""] : []),
		"【态势预取】",
		"（字段导读：steps=全量含 note；recent_facts=最新 20 条，counts 给总数；findings=全量；coverage.untouched=scope 内尚无 fact 锚定的资产（未测面），量化目标核对用 coverage.anchored/scope_total 实测值。）",
		"（counts 里 edge:* 为边计数，如 edge:produces=step→产出的边条数。）",
		parts.overviewJson,
		"",
		"【跨唤醒待办】",
		parts.todosText || "（空）",
		...(parts.stalled
			? ["", "【本轮模式】收官判定：图上已无待办 step——本轮三选一必答，0 派不是选项：①确有真方向 → add_step；②目标已实证 → prove_goal；③方向探尽/目标不可达 → conclude_task（reason 引 recent_done 说明为何再派无价值）。沉默收场是严重错误。"]
			: []),
	].join("\n");
}
