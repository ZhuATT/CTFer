/**
 * worker 收尾唯一判定（11-9 实机 fix §5.3 判定表，卡C）。
 *
 * 已拍板（§5.2）：agent 收尾产出唯一权威 outcome/reason，scheduler 直接消费，
 * 不再用 aborted/transportError 自行重算另一套状态。本模块是纯函数——无 IO、
 * 无 pi 依赖，worker-outcome.test.ts 直接逐行覆盖判定表。
 */

export type WorkerOutcome = "done" | "exhausted" | "blocked" | "incomplete";

/** 本地取消首次生效原因（§4.2：首次生效后后来的 provider-aborted 不能覆盖）。 */
export type LocalCancelReason = "step-timeout" | "operator-stop";

/** 成功交付引用（§5.5：真实 submit 成功回执，含 dedup 返回的旧 ID）。 */
export interface DeliveryRef {
	kind: "fact" | "finding";
	id: number;
	/** true = 幂等去重返回的已有节点 ID（算一次合法提交，不算新增）。 */
	dedup: boolean;
}

/** 判定表输入（agent 从会话观测中收集后传入）。 */
export interface OutcomeInput {
	/** 本地取消生效（内部 step-timeout / 外部 operator-stop）。 */
	localCancel?: LocalCancelReason;
	/** worker 构造/执行抛错（无 result 时 scheduler 兜底，有 result 时按 blocked/worker-error）。 */
	workerError?: string;
	/** 既有通道 error 检测命中（transportFailureFromMessage）。 */
	channelError?: boolean;
	/** 是否存在最终 assistant 消息（message_end 落过——空文本也算存在）。 */
	hasFinalAssistant: boolean;
	/** 最终 assistant 消息的 stopReason（缺失 = undefined）。 */
	finalStopReason?: string;
	/** 本会话成功 submit 回执数（含 dedup）。 */
	deliveryCount: number;
}

export interface OutcomeVerdict {
	outcome: WorkerOutcome;
	reason: string;
}

/**
 * 唯一判定表（§5.3，按顺序匹配，首个命中生效）：
 * 1. 本地取消生效 → exhausted / step-timeout|operator-stop
 * 2. 既有通道 error 或 worker 抛错 → blocked / channel-error|worker-error
 * 3. 无本地取消、最终 stopReason=aborted → incomplete / provider-aborted
 * 4. 最终 stopReason=length → incomplete / output-length
 * 5. 无最终 assistant 消息或 stopReason 缺失/非正常 stop → incomplete / missing-final-message|unexpected-stop
 * 6. 正常 stop 但无成功提交回执 → incomplete / no-delivery
 * 7. 正常 stop 且 ≥1 条合法交付 → done / delivered
 *
 * 边界（§5.3）：局部长度截断后 pi 正常继续并结束的不因历史 length 判失败——
 * 本判定只看最终消息；通道 error 已明确时不被 no-delivery 覆盖（顺序保证）；
 * done 只证明最低交付，不证明派单全部答完。
 */
export function decideOutcome(input: OutcomeInput): OutcomeVerdict {
	if (input.localCancel) return { outcome: "exhausted", reason: input.localCancel };
	if (input.workerError) return { outcome: "blocked", reason: "worker-error" };
	if (input.channelError) return { outcome: "blocked", reason: "channel-error" };
	if (!input.hasFinalAssistant) return { outcome: "incomplete", reason: "missing-final-message" };
	const stop = input.finalStopReason;
	if (stop === "aborted") return { outcome: "incomplete", reason: "provider-aborted" };
	if (stop === "length") return { outcome: "incomplete", reason: "output-length" };
	if (stop !== "stop") return { outcome: "incomplete", reason: "unexpected-stop" };
	if (input.deliveryCount === 0) return { outcome: "incomplete", reason: "no-delivery" };
	return { outcome: "done", reason: "delivered" };
}

/** §4.1 最小计时字段（既有会话结果 JSON detail 内，不新增独立计时表）。 */
export interface StepTiming {
	/** worker 入口 UTC − step 建单时间（负数钳 0；含停机时长，非纯忙碌等待）。 */
	queue_wait_ms: number;
	/** worker 函数入口到 prompt 返回/抛错（单调时钟）。 */
	worker_elapsed_ms: number;
	/** finally 资源清理起止（单调时钟）。 */
	cleanup_elapsed_ms: number;
	/** worker 入口 UTC（对账用）。 */
	started_at_utc: string;
	/** prompt 返回/抛错 UTC。 */
	returned_at_utc: string;
	/** 清理结束 UTC。 */
	cleanup_end_utc: string;
}

/** §6.1 step 的 last_execution 元数据（每 step 只存最近一次；不新增 attempt 管理）。 */
export interface StepLastExecution {
	session_id: string;
	outcome: WorkerOutcome;
	reason: string;
	stop_reason?: string;
	delivery_refs: DeliveryRef[];
	timing?: StepTiming;
	finished_at: string;
}
