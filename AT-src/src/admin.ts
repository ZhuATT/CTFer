/**
 * 操作员管理操作（P3-7/P3-8）——CLI 子命令的可测核心（index.ts 只做参数接线）。
 *
 * scope-add（D7）：task.json scope.hosts 追加（去重）→ 有 project 则 assets.db 补
 * asset_tasks（origin=scope-add，幂等）→ 写 control/scope.changed（内容=新 host 快照）。
 * 在跑的 run 由进程内 watcher ≤1.5s 发现信号 → scopeSet 原位变更（guard 即刻生效）。
 *
 * reopen（D8）：只改 task.json goal 文本，**不开库写节点**——播种收敛进 initTask
 * （终态 goal + 文本变化 → 重跑时自动播种新 goal + goal_changed 事件）。
 * 现 goal open → 拒（先跑完或 conclude_task）；graph.db 不存在（从未跑过）→ 直接改。
 */
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { loadTask, type TaskJson } from "./task.js";
import { findOrCreateAsset, normalizeEndpoint, openAssetsDb } from "./assets.js";

export interface ScopeAddResult {
	task: TaskJson;
	taskDir: string;
	/** 本次实际追加的 host（去重后）。空数组 = 全部已存在（幂等；信号仍写，watcher 空转无害）。 */
	added: string[];
	scopeChangedPath: string;
}

/** scope-add 核心：扩 task.json 白名单 + 补资产登记（origin=scope-add）+ 写扩权信号（D7）。 */
export function scopeAdd(tasksRoot: string, taskName: string, hosts: string[]): ScopeAddResult {
	const candidates = hosts.map((h) => h.trim()).filter((h) => h.length > 0);
	if (candidates.length === 0) throw new Error("至少要给一个 host");

	const { task, dir, assetsDbPath } = loadTask(tasksRoot, taskName);

	// 追加（去重：host 小写比对——与 scheduler scopeSet 同款语义）
	const existingLower = new Set(task.scope.hosts.map((h) => h.toLowerCase()));
	const added: string[] = [];
	for (const h of candidates) {
		if (existingLower.has(h.toLowerCase())) continue;
		task.scope.hosts.push(h);
		existingLower.add(h.toLowerCase());
		added.push(h);
	}

	writeFileSync(join(dir, "task.json"), JSON.stringify(task, null, 2) + "\n", "utf-8");

	if (assetsDbPath && added.length > 0) {
		const assetsDb = openAssetsDb(assetsDbPath);
		try {
			const now = new Date().toISOString();
			const insert = assetsDb.prepare(
				"INSERT OR IGNORE INTO asset_tasks (asset_id, task_id, origin, created_at) VALUES (?, ?, 'scope-add', ?)",
			);
			for (const h of added) {
				const norm = normalizeEndpoint(h);
				const asset = findOrCreateAsset(assetsDb, {
					project: task.project ?? "default",
					type: norm.type,
					host: norm.host,
					port: norm.port,
					url: norm.url,
					taskName,
				});
				insert.run(asset.id, taskName, now);
			}
		} finally {
			assetsDb.close();
		}
	}

	// 扩权信号（内容=新 host 快照；watcher 只看存在性+重读 task.json，内容供人读审计）
	const controlDir = join(dir, "control");
	mkdirSync(controlDir, { recursive: true });
	const scopeChangedPath = join(controlDir, "scope.changed");
	writeFileSync(scopeChangedPath, JSON.stringify({ added, at: new Date().toISOString() }), "utf-8");

	return { task, taskDir: dir, added, scopeChangedPath };
}

export interface ReopenResult {
	task: TaskJson;
	taskDir: string;
	oldGoal: string;
	/** 原 goal 的终态（achieved/closed）；无图（从未跑过）为 undefined。 */
	prevGoalState?: string;
}

/** 只读打开图库看现 goal 状态（图不存在=从未跑过 → 允许直接改）。 */
function peekGoalState(dbPath: string, taskId: string): { state: string; text: string } | undefined {
	if (!existsSync(dbPath)) return undefined;
	const db = new Database(dbPath, { readonly: true });
	try {
		// 与 graph.currentGoal 同款查询（不引模块只为省一次开库——语义保持一致）
		const row =
			(db.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'goal' AND state = 'open' ORDER BY id DESC LIMIT 1").get(taskId) ??
				db.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'goal' ORDER BY id DESC LIMIT 1").get(taskId)) as
			| { state: string; payload: string }
			| undefined;
		if (!row) return undefined;
		const text = (JSON.parse(row.payload) as { text?: string }).text ?? "";
		return { state: row.state, text };
	} finally {
		db.close();
	}
}

/** reopen 核心：只改 task.json goal 文本（D8）。现 goal open → 拒；终态/无图 → 更新。 */
export function reopenTask(tasksRoot: string, taskName: string, goal: string): ReopenResult {
	const text = goal.trim();
	if (text.length < 4) throw new Error("goal 文本太短（≥4 字符）——写清楚要达成什么");

	const { task, dir, dbPath } = loadTask(tasksRoot, taskName);
	const oldGoal = task.goal;
	let prevGoalState: string | undefined;

	const goalState = peekGoalState(dbPath, task.name);
	if (goalState?.state === "open") {
		throw new Error(
			`goal 仍 open——先跑完（run）或让 planner conclude_task 收尾，再 reopen。` +
				`（reopen 的语义是"重开已终态的任务换新目标"；重跑即自动播种新 goal）`,
		);
	}
	prevGoalState = goalState?.state;

	task.goal = text;
	writeFileSync(join(dir, "task.json"), JSON.stringify(task, null, 2) + "\n", "utf-8");
	return { task, taskDir: dir, oldGoal, prevGoalState };
}
