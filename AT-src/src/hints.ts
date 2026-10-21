/**
 * hints message 通道（P2-6，D5 拍板：人不直接命令 worker，插话经 planner 转译）。
 *
 * 写入侧：CLI `hint <task> "文本"` / 手写文件——`control/hints.jsonl` 追加式带 ts。
 * 收割侧：planner 唤醒前按行数偏移读新增行（offset 存 `control/hints.offset`）——
 * 不重放已消费行。老 hints.jsonl 形态从 Python 版平移。
 */
import { existsSync, mkdirSync, appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { TriggerEvent } from "./triggers.js";

function controlDir(taskDir: string): string {
	const d = join(taskDir, "control");
	mkdirSync(d, { recursive: true });
	return d;
}

export function appendHint(taskDir: string, text: string): void {
	const line = JSON.stringify({ ts: new Date().toISOString(), text }) + "\n";
	appendFileSync(join(controlDir(taskDir), "hints.jsonl"), line, "utf-8");
}

/** 读偏移。 */
function readOffset(taskDir: string): number {
	const p = join(controlDir(taskDir), "hints.offset");
	try {
		return parseInt(readFileSync(p, "utf-8").trim(), 10) || 0;
	} catch {
		return 0;
	}
}

function writeOffset(taskDir: string, n: number): void {
	writeFileSync(join(controlDir(taskDir), "hints.offset"), String(n), "utf-8");
}

/** 收割新增 hints → hint 触发事件（推进偏移，幂等：无新行返回空）。 */
export function harvestHints(taskDir: string): TriggerEvent[] {
	const p = join(controlDir(taskDir), "hints.jsonl");
	if (!existsSync(p)) return [];
	const all = readFileSync(p, "utf-8").split(/\r?\n/).filter((l) => l.trim());
	const offset = readOffset(taskDir);
	if (all.length <= offset) return [];
	const fresh = all.slice(offset);
	writeOffset(taskDir, all.length);
	const events: TriggerEvent[] = [];
	for (const line of fresh) {
		try {
			const obj = JSON.parse(line) as { text?: string };
			if (obj.text?.trim()) events.push({ type: "hint", text: obj.text.trim().slice(0, 500) });
		} catch {
			// 手写容错：整行当文本
			events.push({ type: "hint", text: line.slice(0, 500) });
		}
	}
	return events;
}
