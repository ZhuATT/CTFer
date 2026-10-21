/**
 * 项目简报（P3-6，D4 拍板）：
 * 跨 task 历史情报只读首轮注入——
 * - 来源：同 project 其它 tasks 的 graph.db（只读打开）；
 * - 范围：前任 findings 全量 + 锚定到本 task scope 资产的 observed facts（cap 20，id 倒序）；
 * - 纪律：inferred 不带、只读不写、每条标明来源 task、首轮一次性。
 */
import Database from "better-sqlite3";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { FindingPayload, FactPayload } from "./contracts.js";

export interface BriefingFinding {
	sourceTask: string;
	id: number;
	severity: string;
	summary: string;
	state: string;
}

export interface BriefingFact {
	sourceTask: string;
	id: number;
	summary: string;
}

export interface ProjectBriefing {
	sourceTasks: string[];
	findings: BriefingFinding[];
	facts: BriefingFact[];
	builtAt: string;
}

const BRIEFING_FACTS_CAP = 20;

/**
 * 构建同项目历史任务情报简报。
 * 无历史情报时返回 undefined（不渲染空节）。
 */
export function buildProjectBriefing(
	tasksRoot: string,
	project: string,
	selfTask: string,
	assetsDb: Database.Database,
): ProjectBriefing | undefined {
	if (!existsSync(tasksRoot)) return undefined;

	// 1. 查锚定到本 task scope 资产的 anchors（P2 修法 A：host 级匹配——前任锚落在同 host
	// 任意 port 形态资产上都算，scope 裸 host 与 endpoint host:port 不再分裂；port 精度保留在 assets 表）
	const anchorRows = assetsDb
		.prepare(
			`SELECT anc.task_id, anc.node_id
       FROM anchors anc
       JOIN assets aa ON aa.id = anc.asset_id
       WHERE anc.task_id != ?
         AND EXISTS (
           SELECT 1 FROM assets sa
           JOIN asset_tasks at ON at.asset_id = sa.id AND at.task_id = ?
           WHERE sa.host = aa.host
         )`,
		)
		.all(selfTask, selfTask) as Array<{ task_id: string; node_id: number }>;

	const anchoredFactsByTask = new Map<string, Set<number>>();
	for (const r of anchorRows) {
		let s = anchoredFactsByTask.get(r.task_id);
		if (!s) {
			s = new Set<number>();
			anchoredFactsByTask.set(r.task_id, s);
		}
		s.add(r.node_id);
	}

	// 2. 扫 tasksRoot 下同 project 任务
	const entries = readdirSync(tasksRoot, { withFileTypes: true });
	const sourceTasks: string[] = [];
	const findings: BriefingFinding[] = [];
	const facts: BriefingFact[] = [];

	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		const tName = entry.name;
		if (tName === selfTask) continue;

		const jsonPath = join(tasksRoot, tName, "task.json");
		const dbPath = join(tasksRoot, tName, "graph.db");
		if (!existsSync(jsonPath) || !existsSync(dbPath)) continue;

		try {
			const taskMeta = JSON.parse(readFileSync(jsonPath, "utf-8")) as { project?: string };
			if (taskMeta.project !== project) continue;

			sourceTasks.push(tName);
			const taskDb = new Database(dbPath, { readonly: true });
			try {
				// 前任 findings 全量
				const fRows = taskDb
					.prepare("SELECT id, payload, state FROM nodes WHERE kind = 'finding' ORDER BY id ASC")
					.all() as Array<{ id: number; payload: string; state: string }>;
				for (const r of fRows) {
					try {
						const p = JSON.parse(r.payload) as FindingPayload;
						findings.push({
							sourceTask: tName,
							id: r.id,
							severity: p.severity ?? "info",
							summary: p.summary,
							state: r.state,
						});
					} catch {
						/* 忽略损坏行 */
					}
				}

				// observed 且锚定到本 task scope 的 facts
				const targetNodeIds = anchoredFactsByTask.get(tName);
				if (targetNodeIds && targetNodeIds.size > 0) {
					const factRows = taskDb
						.prepare("SELECT id, payload FROM nodes WHERE kind = 'fact' ORDER BY id DESC")
						.all() as Array<{ id: number; payload: string }>;

					for (const r of factRows) {
						if (!targetNodeIds.has(r.id)) continue;
						try {
							const p = JSON.parse(r.payload) as FactPayload;
							if (p.confidence === "observed") {
								facts.push({
									sourceTask: tName,
									id: r.id,
									summary: p.summary,
								});
							}
						} catch {
							/* 忽略损坏行 */
						}
					}
				}
			} finally {
				taskDb.close();
			}
		} catch {
			/* 读取异常跳过此 task */
		}
	}

	if (findings.length === 0 && facts.length === 0) {
		return undefined;
	}

	// facts 截取前 20 条（cap 20，id 倒序已在查询保持）
	const cappedFacts = facts.slice(0, BRIEFING_FACTS_CAP);

	return {
		sourceTasks,
		findings,
		facts: cappedFacts,
		builtAt: new Date().toISOString(),
	};
}

/** 格式化项目简报为 prompt 字符串。 */
export function renderProjectBriefing(briefing: ProjectBriefing | undefined): string | undefined {
	if (!briefing || (briefing.findings.length === 0 && briefing.facts.length === 0)) {
		return undefined;
	}

	const lines = [
		"【项目简报】（前任 task 历史发现与本 scope 实证观察，首轮参考）：",
		...briefing.findings.map(
			(f) => `- [来自 ${f.sourceTask}] finding #${f.id} [${f.severity}] ${f.summary} (${f.state})`,
		),
		...briefing.facts.map((fc) => `- [来自 ${fc.sourceTask}] fact #${fc.id} ${fc.summary}`),
	];

	return lines.join("\n");
}
