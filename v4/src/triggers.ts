/**
 * 触发事件与渲染（P2-0）——planner 唤醒输入的 delta 层。
 *
 * ARTEX planner.go 直译精简版：delta 优先（先看这里）再全局态势。
 * 渲染失败无 fallback 需求——纯字符串拼接，永不抛。
 */
import type { NodeRow } from "./db.js";

export type TriggerEvent =
	| {
			type: "step_done";
			stepId: number;
			summary: string;
			outcome: "done" | "exhausted" | "blocked";
			conclusion: string;
			newFactIds: number[];
			findingIds: number[];
	  }
	| { type: "finding"; findingId: number; severity: string; summary: string }
	| { type: "goal_changed"; action: "added" | "edited" | "deleted"; text: string }
	| { type: "hint"; text: string }
	| { type: "resume"; nodeCount: number }
	| { type: "steered"; text: string; stepId: number }
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
					`- step #${ev.stepId} [${ev.outcome}]「${ev.summary}」${ev.conclusion ? `：${ev.conclusion}` : ""}` +
						(ev.newFactIds.length ? `（新 fact: ${ev.newFactIds.map((i) => `#${i}`).join(", ")}）` : "") +
						(ev.findingIds.length ? `（新 finding: ${ev.findingIds.map((i) => `#${i}`).join(", ")}）` : ""),
				);
				break;
			case "finding":
				lines.push(`- 新 finding #${ev.findingId} [${ev.severity}] ${ev.summary}`);
				break;
			case "goal_changed":
				lines.push(`- 目标${ev.action === "added" ? "新增" : ev.action === "edited" ? "修改" : "删除"}：${ev.text}`);
				break;
			case "hint":
				lines.push(`- 操作员插入一条指示：「${ev.text}」——据此调整/补充方向`);
				break;
			case "resume":
				lines.push(`- 续跑恢复：图上已有 ${ev.nodeCount} 个节点（历史进度见态势，别重复已完成的）`);
				break;
			case "steered":
				lines.push(`- 操作员曾对 step #${ev.stepId} 插话：「${ev.text}」——执行层已收到该插话，判断是否影响后续方向`);
				break;
			case "stall":
				lines.push("- 【接力唤醒】图上已无待办 step——本轮三选一：派真方向 / prove_goal / conclude_task（若确实都探尽了）");
				break;
		}
	}
	return lines.join("\n");
}

/** 从 worker 会话的产出行构造 step_done 触发。 */
export function stepDoneEvent(step: NodeRow, outcome: "done" | "exhausted" | "blocked", newFactIds: number[], findingIds: number[], conclusion: string): TriggerEvent {
	return {
		type: "step_done",
		stepId: step.id,
		summary: (JSON.parse(step.payload) as { summary: string }).summary,
		outcome,
		conclusion: conclusion.slice(0, 400),
		newFactIds,
		findingIds,
	};
}
