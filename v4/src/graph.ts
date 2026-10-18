/**
 * 图操作层（P1-1）——worker 直提全链的程序侧：校验/去重/落边/态势渲染。
 *
 * 快递单哲学（§2.2 人话版）：边的原料不是 LLM 的自觉，是工具的必填参数——
 * submit_fact(step_id=42) 见参数直接落 produces 边，想漏都漏不了。
 * 进件检验非巡检（§2.3）：每次 submit 验这一条，脏数据门口被拒。
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";
import type { Database } from "better-sqlite3";
import {
	FactPayload,
	FindingPayload,
	GoalPayload,
	StepPayload,
	normalizeSummary,
	type FactPayload as FactPayloadT,
	type FindingPayload as FindingPayloadT,
} from "./contracts.js";
import { logActivity, nowIso, type EdgeRow, type NodeRow } from "./db.js";
import { noreportCheck } from "./noreport.js";
import type { TaskJson } from "./task.js";

// ── 基础 ──

export function getNode(db: Database, taskId: string, id: number): NodeRow | undefined {
	return db.prepare("SELECT * FROM nodes WHERE task_id = ? AND id = ?").get(taskId, id) as NodeRow | undefined;
}

export function getEdges(db: Database, taskId: string, opts?: { src?: number; dst?: number; rel?: string }): EdgeRow[] {
	const cond: string[] = ["task_id = ?"];
	const args: unknown[] = [taskId];
	if (opts?.src !== undefined) {
		cond.push("src_id = ?");
		args.push(opts.src);
	}
	if (opts?.dst !== undefined) {
		cond.push("dst_id = ?");
		args.push(opts.dst);
	}
	if (opts?.rel) {
		cond.push("rel = ?");
		args.push(opts.rel);
	}
	return db
		.prepare(`SELECT * FROM edges WHERE ${cond.join(" AND ")} ORDER BY created_at`)
		.all(...(args as never[])) as EdgeRow[];
}

function addEdge(db: Database, taskId: string, src: number, rel: string, dst: number, note?: string): void {
	if (src === dst) throw new Error(`自环边拒绝：${src} -${rel}-> ${dst}`);
	db.prepare(
		"INSERT OR IGNORE INTO edges (task_id, src_id, rel, dst_id, note, created_at) VALUES (?, ?, ?, ?, ?, ?)",
	).run(taskId, src, rel, dst, note ?? null, nowIso());
}

function parsePayload<T>(row: NodeRow): T {
	return JSON.parse(row.payload) as T;
}

// ── initTask ──

export interface InitTaskResult {
	rootGoalId: number;
	stepIds: number[];
	/** false=复用已有图（续跑），true=本次新建。 */
	fresh: boolean;
}

/** 建 root goal + seed steps（仅测试夹具，D2：生产 step 由 P2 planner 供给）+ dispatch 边。
 * 幂等：图已有节点则直接返回现有 root goal 与 steps，不重复播种（fresh=false）。 */
export function initTask(db: Database, task: TaskJson): InitTaskResult {
	const existing = db.prepare("SELECT id FROM nodes WHERE task_id = ? AND kind = 'goal' ORDER BY id LIMIT 1").get(
		task.name,
	) as { id: number } | undefined;
	if (existing) {
		const steps = db
			.prepare("SELECT id FROM nodes WHERE task_id = ? AND kind = 'step' ORDER BY id")
			.all(task.name) as Array<{ id: number }>;
		return { rootGoalId: existing.id, stepIds: steps.map((s) => s.id), fresh: false };
	}

	const now = nowIso();
	const goalPayload = GoalPayload.parse({ text: task.goal });
	const ins = db.prepare(
		"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES (?, 'goal', 'open', 'program', ?, ?, ?)",
	);
	const rootGoalId = Number(ins.run(task.name, JSON.stringify(goalPayload), now, now).lastInsertRowid);

	const stepIds: number[] = [];
	for (const seed of task.seed_steps ?? []) {
		const payload = StepPayload.parse(seed);
		const stepId = Number(
			db
				.prepare(
					"INSERT INTO nodes (task_id, kind, state, origin, payload, created_at, updated_at) VALUES (?, 'step', 'open', 'program', ?, ?, ?)",
				)
				.run(task.name, JSON.stringify(payload), now, now).lastInsertRowid,
		);
		addEdge(db, task.name, rootGoalId, "dispatch", stepId, "seed");
		stepIds.push(stepId);
	}
	return { rootGoalId, stepIds, fresh: true };
}

// ── 证据 ──

/** 证据文件校验：task 目录内、存在、非目录；返回内容 sha256（桶四 #5：进件算好落列，
 * 复测/翻案时验证"证据还是当初那份"）。 */
export function hashEvidence(taskDir: string, evidenceRel: string): string {
	const p = resolve(taskDir, evidenceRel);
	if (!p.startsWith(resolve(taskDir) + sep)) throw new Error(`证据路径逃逸 task 目录：${evidenceRel}`);
	if (!existsSync(p)) throw new Error(`证据文件不存在：${evidenceRel}（先用 Write 把证据写进 evidence/ 再提交）`);
	if (!statSync(p).isFile()) throw new Error(`证据必须是文件：${evidenceRel}`);
	return createHash("sha256").update(readFileSync(p)).digest("hex");
}

// ── submitFact ──

export interface SubmitFactArgs {
	taskId: string;
	taskDir: string;
	stepId: number;
	payload: FactPayloadT;
	sessionId?: string;
}

export interface SubmitResult {
	id: number;
	dedup: boolean;
}

export function submitFact(db: Database, args: SubmitFactArgs): SubmitResult {
	const { taskId, taskDir, stepId, sessionId } = args;
	const payload = FactPayload.parse(args.payload);
	const sha = hashEvidence(taskDir, payload.evidence);

	const step = getNode(db, taskId, stepId);
	if (!step || step.kind !== "step") throw new Error(`step #${stepId} 不存在（step_id 必填——产出挂树就靠它）`);

	// 去重：同 task 内 fact summary 归一化精确匹配 → 返回旧 id 幂等
	const facts = db.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'fact'").all(taskId) as NodeRow[];
	const key = normalizeSummary(payload.summary);
	const hit = facts.map(parsePayload<FactPayloadT>).findIndex((p) => normalizeSummary(p.summary) === key);
	if (hit >= 0) {
		return { id: facts[hit].id, dedup: true };
	}

	const now = nowIso();
	const id = Number(
		db
			.prepare(
				"INSERT INTO nodes (task_id, kind, state, origin, session_id, step_id, evidence_sha256, payload, created_at, updated_at, completed_at) VALUES (?, 'fact', 'confirmed', 'worker', ?, ?, ?, ?, ?, ?, ?)",
			)
			.run(taskId, sessionId ?? null, stepId, sha, JSON.stringify(payload), now, now, now).lastInsertRowid,
	);
	addEdge(db, taskId, stepId, "produces", id);
	logActivity(db, {
		task_id: taskId,
		node_id: id,
		session_id: sessionId,
		worker: "worker",
		kind: "result",
		tool: "submit_fact",
		summary: `fact #${id}: ${payload.summary.slice(0, 120)}`,
	});
	return { id, dedup: false };
}

// ── submitFinding ──

export interface SubmitFindingArgs {
	taskId: string;
	taskDir: string;
	stepId: number;
	payload: FindingPayloadT;
	relatedFactIds?: number[];
	sessionId?: string;
}

export function submitFinding(db: Database, args: SubmitFindingArgs): SubmitResult & { noreport?: { verdict: string; reason: string } } {
	const { taskId, taskDir, stepId, sessionId } = args;
	const payload = FindingPayload.parse(args.payload);
	const sha = hashEvidence(taskDir, payload.evidence);

	// noreport 前置（P2-4）：进件时跑，reject 硬拒不入图；suspect 放行但回执带公诉意见
	const evText = readFileSync(resolve(taskDir, payload.evidence), "utf-8").slice(0, 20_000);
	const nr = noreportCheck({ summary: payload.summary, evidence: evText, endpoint: "" });
	if (nr.verdict === "reject") {
		throw new Error(
			`[平台管控·不报表清单] 该 finding 被 noreport 预检拒绝：${nr.reason}。` +
				`现象是载体时，改报你用它找到的实际影响（作为 fact 或新 finding）；不要重复提交同类现象。`,
		);
	}

	const step = getNode(db, taskId, stepId);
	if (!step || step.kind !== "step") throw new Error(`step #${stepId} 不存在`);

	for (const fid of args.relatedFactIds ?? []) {
		const f = getNode(db, taskId, fid);
		if (!f || f.kind !== "fact") throw new Error(`related_fact_id #${fid} 不是 fact`);
	}

	const now = nowIso();
	const id = Number(
		db
			.prepare(
				"INSERT INTO nodes (task_id, kind, state, origin, session_id, step_id, evidence_sha256, payload, created_at, updated_at) VALUES (?, 'finding', 'reported', 'worker', ?, ?, ?, ?, ?, ?)",
			)
			.run(taskId, sessionId ?? null, stepId, sha, JSON.stringify(payload), now, now).lastInsertRowid,
	);
	addEdge(db, taskId, stepId, "produces", id, "finding");
	for (const fid of args.relatedFactIds ?? []) {
		addEdge(db, taskId, fid, "proves", id);
	}
	logActivity(db, {
		task_id: taskId,
		node_id: id,
		session_id: sessionId,
		worker: "worker",
		kind: "result",
		tool: "submit_finding",
		summary: `finding #${id} [${payload.severity}] ${payload.summary.slice(0, 120)}`,
	});
	const out: SubmitResult & { noreport?: { verdict: string; reason: string } } = { id, dedup: false };
	if (nr.verdict === "suspect") out.noreport = { verdict: "suspect", reason: nr.reason };
	return out;
}

// ── addStep（P2 planner 派活，D3 拒重兜底挂这里） ──

export interface AddStepInput {
	summary: string;
	note?: string;
	parent_ids?: number[];
	priority?: number;
}

export interface AddStepOutcome {
	accepted: Array<{ id: number; summary: string }>;
	rejected: Array<{ summary: string; reason: string }>;
}

/** 批量派 step（≤4 由工具面限制）：每条入库前查「同归一化 summary 已 open/running」→
 * 该条拒收回执，批量内其余照常（D3：程序精确硬拒零误伤，语义比对归 prompt）。 */
export function addStep(db: Database, taskId: string, steps: AddStepInput[], sessionId?: string): AddStepOutcome {
	if (steps.length > 4) throw new Error(`一次最多 4 条（收到 ${steps.length}）——挑最高价值的派`);
	const goal = db.prepare("SELECT id FROM nodes WHERE task_id = ? AND kind='goal' ORDER BY id LIMIT 1").get(taskId) as
		| { id: number }
		| undefined;
	if (!goal) throw new Error("task 无 root goal——先 initTask");
	const openSteps = db
		.prepare("SELECT payload FROM nodes WHERE task_id = ? AND kind='step' AND state IN ('open','running')")
		.all(taskId) as Array<{ payload: string }>;
	const openSummaries = new Set(
		openSteps.map((s) => normalizeSummary((JSON.parse(s.payload) as StepPayload).summary)),
	);

	const accepted: AddStepOutcome["accepted"] = [];
	const rejected: AddStepOutcome["rejected"] = [];
	for (const s of steps) {
		const payload = StepPayload.parse({ ...s, priority: undefined });
		const key = normalizeSummary(payload.summary);
		if (openSummaries.has(key)) {
			rejected.push({ summary: s.summary, reason: "已有 open/running step 同义（拒重兜底）" });
			continue;
		}
		const now = nowIso();
		const id = Number(
			db
				.prepare(
					// 9 列：task_id/kind/state/origin 字面量占 3 + 参数 6（含字面量占位共 9 项）
					"INSERT INTO nodes (task_id, kind, state, origin, session_id, priority, payload, created_at, updated_at) VALUES (?, 'step', 'open', 'planner', ?, ?, ?, ?, ?)",
				)
				.run(taskId, sessionId ?? null, Math.max(0, Math.min(5, s.priority ?? 0)), JSON.stringify(payload), now, now)
				.lastInsertRowid,
		);
		addEdge(db, taskId, goal.id, "dispatch", id, "planner");
		for (const pid of s.parent_ids ?? []) {
			const p = getNode(db, taskId, pid);
			if (!p) throw new Error(`parent_ids 里的 #${pid} 不存在（derives_from 边引用须存在）`);
			addEdge(db, taskId, pid, "derives_from", id, "planner 派生");
		}
		openSummaries.add(key); // 同批内互斥也生效
		accepted.push({ id, summary: payload.summary });
	}
	if (accepted.length) {
		logActivity(db, {
			task_id: taskId,
			session_id: sessionId,
			worker: "planner",
			kind: "result",
			tool: "add_step",
			summary: `派 ${accepted.length} 条 step${rejected.length ? `，拒 ${rejected.length} 条` : ""}`,
		});
	}
	return { accepted, rejected };
}

// ── proveGoal（D7：evidence 必须是图内 fact，防挂空气证据达标） ──

export interface ProveGoalArgs {
	taskId: string;
	goalId: number;
	evidenceId: number;
	reason: string;
	sessionId?: string;
}

export function proveGoal(db: Database, args: ProveGoalArgs): { achieved: true } {
	const goal = getNode(db, args.taskId, args.goalId);
	if (!goal || goal.kind !== "goal") throw new Error(`goal #${args.goalId} 不存在`);
	if (goal.state !== "open") throw new Error(`goal #${args.goalId} 已是 ${goal.state}，不能重复盖章`);
	const evidence = getNode(db, args.taskId, args.evidenceId);
	if (!evidence || evidence.kind !== "fact") {
		throw new Error(`evidence_id #${args.evidenceId} 必须是图内 fact（防挂空气证据达标）`);
	}
	if (!args.reason?.trim()) throw new Error("reason 必填——目标为何已达成");

	db.prepare("UPDATE nodes SET state='achieved', updated_at=?, completed_at=? WHERE id=?").run(
		nowIso(),
		nowIso(),
		args.goalId,
	);
	addEdge(db, args.taskId, args.evidenceId, "proves", args.goalId, args.reason.slice(0, 300));
	logActivity(db, {
		task_id: args.taskId,
		node_id: args.goalId,
		session_id: args.sessionId,
		worker: "planner",
		kind: "result",
		tool: "prove_goal",
		summary: `goal #${args.goalId} achieved（evidence=fact #${args.evidenceId}）`,
		detail: args.reason.slice(0, 1000),
	});
	return { achieved: true };
}

/** goal 是否已达成（runTask 终止检查用）。 */
export function goalAchieved(db: Database, taskId: string): boolean {
	const goal = db
		.prepare("SELECT state FROM nodes WHERE task_id = ? AND kind='goal' ORDER BY id LIMIT 1")
		.get(taskId) as { state: string } | undefined;
	return goal?.state === "achieved";
}

// ── step 生命周期（P1-4 收尾用） ──

export function setStepState(db: Database, taskId: string, stepId: number, state: string): void {
	const step = getNode(db, taskId, stepId);
	if (!step || step.kind !== "step") throw new Error(`step #${stepId} 不存在`);
	const done = ["done", "exhausted", "blocked", "cancelled"].includes(state);
	db.prepare("UPDATE nodes SET state = ?, updated_at = ?, completed_at = COALESCE(completed_at, ?) WHERE id = ?").run(
		state,
		nowIso(),
		done ? nowIso() : null,
		stepId,
	);
}

export function firstOpenStep(db: Database, taskId: string): NodeRow | undefined {
	return db
		.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'step' AND state = 'open' ORDER BY id LIMIT 1")
		.get(taskId) as NodeRow | undefined;
}

// ── graphOverview ──

export interface GraphOverview {
	goal: { id: number; text: string; state: string } | null;
	steps: Array<{ id: number; summary: string; note?: string; state: string }>;
	recent_facts: Array<{ id: number; summary: string; from_step: number | null; confidence: string; created_at: string }>;
	findings: Array<{ id: number; summary: string; severity: string; state: string }>;
	counts: Record<string, number>;
}

/** 态势视图（§2.4 消费闭环第一块）。P1 无资产表→无 coverage——worker/planner 同函数同视图。 */
export function graphOverview(db: Database, taskId: string): GraphOverview {
	const goalRow = db
		.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'goal' ORDER BY id LIMIT 1")
		.get(taskId) as NodeRow | undefined;
	const steps = db
		.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'step' ORDER BY id")
		.all(taskId) as NodeRow[];
	const facts = db
		.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'fact' ORDER BY id DESC LIMIT 20")
		.all(taskId) as NodeRow[];
	const findings = db
		.prepare("SELECT * FROM nodes WHERE task_id = ? AND kind = 'finding' ORDER BY id DESC")
		.all(taskId) as NodeRow[];
	const counts: Record<string, number> = {};
	for (const row of db
		.prepare("SELECT kind, COUNT(*) AS n FROM nodes WHERE task_id = ? GROUP BY kind")
		.all(taskId) as Array<{ kind: string; n: number }>) {
		counts[row.kind] = row.n;
	}
	for (const row of db.prepare("SELECT rel, COUNT(*) AS n FROM edges WHERE task_id = ? GROUP BY rel").all(taskId) as Array<{
		rel: string;
		n: number;
	}>) {
		counts[`edge:${row.rel}`] = row.n;
	}

	return {
		goal: goalRow ? { id: goalRow.id, text: parsePayload<GoalPayloadLike>(goalRow).text, state: goalRow.state } : null,
		steps: steps.map((s) => {
			const p = parsePayload<StepPayloadLike>(s);
			return { id: s.id, summary: p.summary, ...(p.note ? { note: p.note } : {}), state: s.state };
		}),
		recent_facts: facts.map((f) => {
			const p = parsePayload<FactPayloadT>(f);
			return { id: f.id, summary: p.summary, from_step: f.step_id, confidence: p.confidence, created_at: f.created_at };
		}),
		findings: findings.map((f) => {
			const p = parsePayload<FindingPayloadT>(f);
			return { id: f.id, summary: p.summary, severity: p.severity, state: f.state };
		}),
		counts,
	};
}

interface GoalPayloadLike {
	text: string;
}
interface StepPayloadLike {
	summary: string;
	note?: string;
}

// ── 渲染（graph 命令人读输出） ──

export function renderOverviewText(db: Database, taskId: string): string {
	const o = graphOverview(db, taskId);
	const lines: string[] = [];
	lines.push(`goal #${o.goal?.id} [${o.goal?.state}] ${o.goal?.text ?? "(无)"}`);
	lines.push("");
	lines.push("== steps ==");
	for (const s of o.steps) lines.push(`  #${s.id} [${s.state}] ${s.summary}`);
	lines.push("");
	lines.push(`== facts (${o.counts["fact"] ?? 0} 条，recent 20) ==`);
	for (const f of o.recent_facts) lines.push(`  #${f.id} (step#${f.from_step}, ${f.confidence}) ${f.summary}`);
	lines.push("");
	lines.push(`== findings (${o.counts["finding"] ?? 0}) ==`);
	for (const f of o.findings) lines.push(`  #${f.id} [${f.state}/${f.severity}] ${f.summary}`);
	lines.push("");
	const edgeEntries = Object.entries(o.counts).filter(([k]) => k.startsWith("edge:"));
	if (edgeEntries.length) lines.push(`== 边 == ${edgeEntries.map(([k, v]) => `${k.slice(5)}×${v}`).join(" ")}`);
	return lines.join("\n");
}
