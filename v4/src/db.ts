/**
 * better-sqlite3 最简持久层（P0）。
 *
 * 表只做 P1 nodes schema 的最简子集 + guard 审计所需的 activity 表。
 * 契约在应用层（桶四 #7）：所有 payload 进库前由调用方（工具 execute 内
 * zod）校验，db 层不做约束，只做存储与查询。
 */
import Database from "better-sqlite3";
import { uuidv7 } from "@earendil-works/pi-ai";

export interface NodeRow {
	id: string;
	kind: string;
	state: string;
	origin: string;
	payload: string; // JSON 字符串
	created_at: string;
}

export interface ActivityRow {
	id: number;
	ts: string;
	session_id: string | null;
	tool: string;
	action: string; // 'call' | 'block' | 'error' | ...
	params_digest: string | null;
	detail: string | null;
}

export interface FactPayload {
	summary: string;
	evidence: string;
	confidence: "observed" | "inferred";
	tags?: string[];
	[key: string]: unknown;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  origin TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  session_id TEXT,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  params_digest TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
CREATE INDEX IF NOT EXISTS idx_activity_tool ON activity(tool);
`;

export function openDb(path: string): Database.Database {
	const db = new Database(path);
	db.pragma("journal_mode = WAL");
	db.exec(SCHEMA);
	return db;
}

/** 插入一条 fact 节点，返回生成的 id（P0 不去重，dedup 恒 false）。 */
export function insertFact(db: Database.Database, payload: FactPayload, origin: string): { id: string; dedup: boolean } {
	const id = uuidv7();
	const now = new Date();
	const createdAt = `${now.toISOString().slice(0, 19)}Z`;
	db.prepare(
		"INSERT INTO nodes (id, kind, state, origin, payload, created_at) VALUES (?, 'fact', 'open', ?, ?, ?)",
	).run(id, origin, JSON.stringify(payload), createdAt);
	return { id, dedup: false };
}

/** guard 审计日志：每次工具调用（含 block）记一行。 */
export function logActivity(
	db: Database.Database,
	row: {
		session_id?: string;
		tool: string;
		action: string;
		params_digest?: string;
		detail?: string;
	},
): void {
	const now = new Date();
	db.prepare(
		"INSERT INTO activity (ts, session_id, tool, action, params_digest, detail) VALUES (?, ?, ?, ?, ?, ?)",
	).run(`${now.toISOString().slice(0, 23)}Z`, row.session_id ?? null, row.tool, row.action, row.params_digest ?? null, row.detail ?? null);
}

export function listFacts(db: Database.Database): NodeRow[] {
	return db.prepare("SELECT * FROM nodes WHERE kind = 'fact' ORDER BY created_at").all() as NodeRow[];
}
