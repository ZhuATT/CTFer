/**
 * 触发事件与渲染（P2-0）——planner 唤醒输入的 delta 层。
 *
 * ARTEX planner.go 直译精简版：delta 优先（先看这里）再全局态势。
 * 渲染失败无 fallback 需求——纯字符串拼接，永不抛。
 * 卡S（11-9 §6.1）：step_done 携带结构化 reason 与交付引用，不沿用 400 字符结论裁切
 * 丢状态；outcome 并入 incomplete（§5.3 四态）。
 */
import type { NodeRow } from "./db.js";
import type { DeliveryRef, WorkerOutcome } from "./worker-outcome.js";

export type TriggerEvent =
	| {
			type: "step_done";
			stepId: number;
			summary: string;
			/** 唯一权威收尾判定（agent 产出，scheduler 原样透传——不重算）。 */
			outcome: WorkerOutcome;
			/** 判定原因（step-timeout/operator-stop/channel-error/provider-aborted/output-length/missing-final-message/unexpected-stop/no-delivery/delivered/worker-error）。 */
			reason: string;
			conclusion: string;
			newFactIds: number[];
			findingIds: number[];
			/** 成功交付引用（含 dedup；§5.5）。 */
			deliveries: DeliveryRef[];
	  }
	| { type: "finding"; findingId: number; severity: string; summary: string }
	| { type: "goal_changed"; action: "added" | "edited" | "deleted"; text: string }
	| { type: "hint"; text: string }
	| { type: "resume"; nodeCount: number }
	| { type: "steered"; text: string; stepId: number }
	| { type: "scope_changed"; added: string[] }
	| { type: "stall" };

export function renderTriggers(events: TriggerEvent[]): string {
	if (events.length === 0) {
		return "【本次实际变动】\n（无——心跳巡检轮：无新产出、无新指示。按态势判断是否有未覆盖方向。）";
	}
	const lines = ["【本次实际变动（先看这里）】"];
	for (const ev of events) {
		switch (ev.type) {
			case "step_done":
				lines.push(
					`- step #${ev.stepId} [${ev.outcome}/${ev.reason}]「${ev.summary}」${ev.conclusion ? `：${ev.conclusion}` : ""}` +
						(ev.newFactIds.length ? `（新 fact: ${ev.newFactIds.map((i) => `#${i}`).join(", ")}）` : "") +
						(ev.findingIds.length ? `（新 finding: ${ev.findingIds.map((i) => `#${i}`).join(", ")}）` : "") +
						(ev.deliveries.length
							? `（交付: ${ev.deliveries.map((d) => `${d.kind} #${d.id}${d.dedup ? " dedup" : ""}`).join(", ")}）`
							: ""),
				);
				break;
			case "finding":
				lines.push(`- 新 finding #${ev.findingId} [${ev.severity}] ${ev.summary}`);
				break;
			case "goal_changed":
				lines.push(`- 目标${ev.action === "added" ? "新增" : ev.action === "edited" ? "修改" : "删除"}：${ev.text}`);
				break;
			case "hint":
				lines.push(
					`- 操作员插入一条指示：「${ev.text}」——据此调整/补充方向` +
						`（建议级：结合态势判断采纳/部分采纳/忽略，派单时在 note 里说明取舍）`,
				);
				break;
			case "resume":
				lines.push(`- 续跑恢复：图上已有 ${ev.nodeCount} 个节点（历史进度见态势，别重复已完成的）`);
				break;
			case "steered":
				lines.push(`- 操作员曾对 step #${ev.stepId} 插话：「${ev.text}」——执行层已收到该插话，判断是否影响后续方向`);
				break;
			case "scope_changed":
				lines.push(`- 操作员扩权：新增 host ${ev.added.join(", ")}——现可派相关方向`);
				break;
			case "stall":
				lines.push("- 【接力唤醒】图上已无待办 step——本轮三选一：派真方向 / prove_goal / conclude_task（若确实都探尽了）");
				break;
		}
	}
	return lines.join("\n");
}

/** 从 worker 会话的产出行构造 step_done 触发（卡S：outcome/reason/交付引用结构化透传）。 */
export function stepDoneEvent(
	step: NodeRow,
	outcome: WorkerOutcome,
	reason: string,
	newFactIds: number[],
	findingIds: number[],
	deliveries: DeliveryRef[],
	conclusion: string,
): TriggerEvent {
	return {
		type: "step_done",
		stepId: step.id,
		summary: (JSON.parse(step.payload) as { summary: string }).summary,
		outcome,
		reason,
		conclusion: conclusion.slice(0, 400),
		newFactIds,
		findingIds,
		deliveries,
	};
}
