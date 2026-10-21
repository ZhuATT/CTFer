/**
 * SQLite 持久层 v2（P1-0）——新图 schema，照设计文档 §2.5/§2.6。
 *
 * 结构拍板：
 * - 列=查询面（WHERE/ORDER BY 用），payload=内容面（模型读写 JSON）；
 * - DDL 不写 CHECK 枚举（桶四 #7：契约在应用层 zod，加枚举零迁移）；
 * - edges 复合主键 (task_id,src_id,rel,dst_id)——幂等免费（重插不重复）；
 * - activity 带 token 四列（input/output/cache_read/cache_write）——计量挂活动层，
 *   会话死了账还在（R-2 教训的反向应用）；
 * - 不设外键（SQLite 默认关+应用层管引用），id 用自增整数（边引用/人读友好）。
 *
 * P0 的 smoke.db（uuid 主键版）不迁移——测试产物，P1 task db 在 tasks/<name>/。
 */
import Database from "better-sqlite3";

export const NODE_KINDS = ["goal", "step", "fact", "finding"] as const;
export type NodeKind = (typeof NODE_KINDS)[number];

export const RELS = ["dispatch", "produces", "proves", "derives_from", "superseded"] as const;
export type Rel = (typeof RELS)[number];

export interface NodeRow {
	id: number;
	task_id: string;
	kind: NodeKind;
	state: string;
	origin: string;
	session_id: string | null;
	step_id: number | null;
	priority: number;
	evidence_sha256: string | null;
	payload: string;
	created_at: string;
	updated_at: string;
	completed_at: string | null;
}

export interface EdgeRow {
	task_id: string;
	src_id: number;
	rel: Rel;
	dst_id: number;
	note: string | null;
	created_at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  origin TEXT NOT NULL,
  session_id TEXT,
  step_id INTEGER,
  priority INTEGER NOT NULL DEFAULT 0,
  evidence_sha256 TEXT,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS edges (
  task_id TEXT NOT NULL,
  src_id INTEGER NOT NULL,
  rel TEXT NOT NULL,
  dst_id INTEGER NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (task_id, src_id, rel, dst_id)
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT,
  node_id INTEGER,
  session_id TEXT,
  worker TEXT,
  kind TEXT NOT NULL,
  tool TEXT,
  is_error INTEGER NOT NULL DEFAULT 0,
  summary TEXT,
  detail TEXT,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read INTEGER NOT NULL DEFAULT 0,
  cache_write INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_task_kind ON nodes(task_id, kind);
CREATE INDEX IF NOT EXISTS idx_nodes_task_state ON nodes(task_id, state);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(task_id, dst_id);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(task_id, src_id);
`;

export function openDb(path: string): Database.Database {
	const db = new Database(path);
	db.pragma("journal_mode = WAL");
	db.exec(SCHEMA);
	return db;
}

export function nowIso(): string {
	return `${new Date().toISOString().slice(0, 19)}Z`;
}

/** 活动记账（guard 审计 + 会话结果计量共用）。 */
export function logActivity(
	db: Database.Database,
	row: {
		task_id?: string;
		node_id?: number;
		session_id?: string;
		worker?: string;
		kind: "tool_use" | "result" | "text";
		tool?: string;
		is_error?: boolean;
		summary?: string;
		detail?: string;
		tokens?: { input?: number; output?: number; cacheRead?: number; cacheWrite?: number };
	},
): void {
	db.prepare(
		`INSERT INTO activity (task_id, node_id, session_id, worker, kind, tool, is_error, summary, detail,
		   input_tokens, output_tokens, cache_read, cache_write, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		row.task_id ?? null,
		row.node_id ?? null,
		row.session_id ?? null,
		row.worker ?? null,
		row.kind,
		row.tool ?? null,
		row.is_error ? 1 : 0,
		row.summary ?? null,
		row.detail ?? null,
		row.tokens?.input ?? 0,
		row.tokens?.output ?? 0,
		row.tokens?.cacheRead ?? 0,
		row.tokens?.cacheWrite ?? 0,
		nowIso(),
	);
}
