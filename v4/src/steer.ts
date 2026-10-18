/**
 * steer 通道（p2fix P2F-11，D11 拍板：独立显式执行层通道，不是 hint 升级）。
 *
 * 语义分工：hint→planner=调度层（影响未来 step）；steer→当前 worker=执行层
 * （对在跑 step 补情报/纠偏，不影响调度）。操作员显式选择目标（不自动路由）。
 *
 * 写入侧：CLI `steer <task> "文本"`——默认定向当前唯一在跑 step；无在跑 step 拒绝
 * （提示改用 hint）。文件：control/steer.jsonl（追加式，带 ts + target stepId）。
 * 消费侧：scheduler watcher 轮询——目标在跑 → agent.steer() 送达 + steered 事件；
 * 目标已不在跑（竞态）→ 丢弃 + activity 兜底记录。
 */
import { existsSync, mkdirSync, appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Database } from "better-sqlite3";
import type { NodeRow } from "./db.js";

export interface SteerLine {
	ts: string;
	text: string;
	stepId: number;
}

function controlDir(taskDir: string): string {
	const d = join(taskDir, "control");
	mkdirSync(d, { recursive: true });
	return d;
}

/** 追加一条 steer（CLI 写入侧）。 */
export function appendSteer(taskDir: string, text: string, stepId: number): void {
	const line = JSON.stringify({ ts: new Date().toISOString(), text, stepId } satisfies SteerLine) + "\n";
	appendFileSync(join(controlDir(taskDir), "steer.jsonl"), line, "utf-8");
}

/** 读偏移（control/steer.offset）。 */
function readOffset(taskDir: string): number {
	try {
		return parseInt(readFileSync(join(controlDir(taskDir), "steer.offset"), "utf-8").trim(), 10) || 0;
	} catch {
		return 0;
	}
}

function writeOffset(taskDir: string, n: number): void {
	writeFileSync(join(controlDir(taskDir), "steer.offset"), String(n), "utf-8");
}

/** 收割新增 steer 行（推进偏移，幂等：无新行返回空）。坏行跳过不推进语义。 */
export function harvestSteers(taskDir: string): SteerLine[] {
	const p = join(controlDir(taskDir), "steer.jsonl");
	if (!existsSync(p)) return [];
	const all = readFileSync(p, "utf-8").split(/\r?\n/).filter((l) => l.trim());
	const offset = readOffset(taskDir);
	if (all.length <= offset) return [];
	const fresh = all.slice(offset);
	writeOffset(taskDir, all.length);
	const out: SteerLine[] = [];
	for (const line of fresh) {
		try {
			const obj = JSON.parse(line) as { ts?: string; text?: string; stepId?: number };
			if (obj.text?.trim() && Number.isFinite(obj.stepId)) {
				out.push({ ts: obj.ts ?? "", text: obj.text.trim().slice(0, 1000), stepId: Number(obj.stepId) });
			}
		} catch {
			/* 手写坏行丢弃——steer 是显式通道，宽容只给 hint */
		}
	}
	return out;
}

/** 当前在跑 step（CLI steer 定向 + watcher 目标校验用）。 */
export function currentRunningStep(db: Database, taskId: string): NodeRow | undefined {
	return db
		.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='step' AND state='running' ORDER BY id ASC LIMIT 1")
		.get(taskId) as NodeRow | undefined;
}

/** steer 送达消息模板（D11：情报补充/纠偏，不是新任务）。 */
export function renderSteerMessage(text: string): string {
	return `【操作员插话】${text}——情报补充/纠偏，不是新任务；完成当前 step，相关观察落 fact 上抛。`;
}
