/**
 * 项目级资产登记表（P3-1，D1 拍板：独立 assets.db 资产图）。
 *
 * 目录：projects/<project>/assets.db
 * 三表结构：
 * - assets：客观资产全集（subdomain/ip/endpoint），跨 task 共享复用；
 * - asset_tasks：资产所有权/可见性（task 只能看到自己关联的资产）；
 * - anchors：机械锚点（fact/finding 关联到资产，跨库弱引用）。
 */
import Database from "better-sqlite3";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";
import { z } from "zod";

export const ASSET_TYPES = ["subdomain", "ip", "endpoint"] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export interface AssetRow {
	id: number;
	project_id: string;
	type: AssetType;
	host: string;
	port: number | null;
	url: string;
	payload: string;
	first_seen_task: string;
	created_at: string;
}

export interface AssetWithAnchorCount extends AssetRow {
	anchor_count: number;
}

export interface UntouchedAsset {
	id: number;
	type: AssetType;
	host: string;
	port: number | null;
	url: string;
}

export interface CoverageQueryResult {
	scope_total: number;
	anchored: number;
	untouched: UntouchedAsset[];
}

export interface NormalizedEndpoint {
	host: string;
	port: number | null;
	path: string;
	url: string;
	type: AssetType;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL,
  type TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER,
  url TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  first_seen_task TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_unique ON assets (host, IFNULL(port, 0), url);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets (project_id);

CREATE TABLE IF NOT EXISTS asset_tasks (
  asset_id INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (asset_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_tasks_task ON asset_tasks (task_id);

CREATE TABLE IF NOT EXISTS anchors (
  task_id TEXT NOT NULL,
  node_id INTEGER NOT NULL,
  asset_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (task_id, node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_anchors_asset ON anchors (asset_id);
CREATE INDEX IF NOT EXISTS idx_anchors_task ON anchors (task_id);
`;

/** 打开/初始化项目资产库（WAL 模式 + 三表 DDL）。 */
export function openAssetsDb(path: string): Database.Database {
	mkdirSync(dirname(path), { recursive: true });
	const db = new Database(path);
	db.pragma("journal_mode = WAL");
	db.pragma("busy_timeout = 5000");
	db.exec(SCHEMA);
	return db;
}

function isIpAddress(host: string): boolean {
	// IPv4 简明正则
	if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
		const parts = host.split(".").map(Number);
		return parts.every((p) => p >= 0 && p <= 255);
	}
	// IPv6
	if (host.includes(":")) return true;
	return false;
}

/**
 * 归一化 endpoint 字符串（D5 拍板）：
 * - host 小写；
 * - 协议默认端口补齐（http→80，https→443）；
 * - 剥离 query 与 fragment；
 * - 剥离尾部斜杠（除根路径 /）；
 * - 裸 host 支持（port=null，type=subdomain 或 ip）。
 */
export function normalizeEndpoint(raw: string): NormalizedEndpoint {
	const trimmed = raw.trim();
	if (!trimmed) {
		throw new Error("Endpoint 不能为空");
	}

	// 1. 带 http:// 或 https:// 协议头
	if (/^https?:\/\//i.test(trimmed)) {
		const u = new URL(trimmed);
		const host = u.hostname.toLowerCase();
		let port: number | null = u.port ? parseInt(u.port, 10) : null;
		if (port === null) {
			port = u.protocol === "https:" ? 443 : 80;
		}

		let path = u.pathname;
		if (path.length > 1 && path.endsWith("/")) {
			path = path.slice(0, -1);
		}

		const isDefaultPort = (u.protocol === "http:" && port === 80) || (u.protocol === "https:" && port === 443);
		const portPart = isDefaultPort ? "" : `:${port}`;
		const normalizedUrl = `${u.protocol}//${host}${portPart}${path === "/" ? "" : path}`;

		const type: AssetType = path && path !== "/" ? "endpoint" : isIpAddress(host) ? "ip" : "subdomain";
		return { host, port, path, url: normalizedUrl, type };
	}

	// 2. 无协议头，可能形如 host:port/path 或 host/path 或 host:port 或 bare host
	// 先切分路径
	const slashIdx = trimmed.indexOf("/");
	let hostPortPart = slashIdx >= 0 ? trimmed.slice(0, slashIdx) : trimmed;
	let pathPart = slashIdx >= 0 ? trimmed.slice(slashIdx) : "";

	// 剥离 query & fragment（若无协议时带有 ? 或 #）
	const queryIdx = pathPart.search(/[?#]/);
	if (queryIdx >= 0) {
		pathPart = pathPart.slice(0, queryIdx);
	}
	if (pathPart.length > 1 && pathPart.endsWith("/")) {
		pathPart = pathPart.slice(0, -1);
	}

	let host = hostPortPart.toLowerCase();
	let port: number | null = null;

	// 解析 host:port
	const colonMatch = /^([^:]+):(\d+)$/.exec(hostPortPart);
	if (colonMatch) {
		host = colonMatch[1].toLowerCase();
		port = parseInt(colonMatch[2], 10);
	}

	// P1 加固（实机测试计划 §1 P1）：纯路径形态（如 /jsxsd/foo.do）没有 host——
	// 抛错交 anchorFact 的 catch 静默吞掉（旁路不阻塞 fact 入图），而不是落 host="" 垃圾资产行
	if (!host) {
		throw new Error(`Endpoint 缺少 host（纯路径形态？）：${trimmed}`);
	}

	const isIp = isIpAddress(host);
	let type: AssetType;
	let normalizedUrl: string;

	if (pathPart && pathPart !== "/") {
		type = "endpoint";
		normalizedUrl = port !== null ? `${host}:${port}${pathPart}` : `${host}${pathPart}`;
	} else if (port !== null) {
		type = isIp ? "ip" : "endpoint";
		normalizedUrl = `${host}:${port}`;
	} else {
		type = isIp ? "ip" : "subdomain";
		normalizedUrl = host;
	}

	return {
		host,
		port,
		path: pathPart,
		url: normalizedUrl,
		type,
	};
}

export interface FindOrCreateAssetInput {
	project: string;
	type: AssetType;
	host: string;
	port: number | null;
	url: string;
	payload?: Record<string, unknown> | string;
	taskName: string;
}

/** 幂等查找或插入资产（D5 归一化 key: host + IFNULL(port, 0) + url）。 */
export function findOrCreateAsset(db: Database.Database, input: FindOrCreateAssetInput): AssetRow {
	const payloadStr =
		typeof input.payload === "string"
			? input.payload
			: JSON.stringify(input.payload ?? {});

	const existing = db
		.prepare("SELECT * FROM assets WHERE host = ? AND IFNULL(port, 0) = IFNULL(?, 0) AND url = ? LIMIT 1")
		.get(input.host, input.port, input.url) as AssetRow | undefined;

	if (existing) {
		return existing;
	}

	const now = new Date().toISOString();
	const res = db
		.prepare(
			"INSERT INTO assets (project_id, type, host, port, url, payload, first_seen_task, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		)
		.run(
			input.project,
			input.type,
			input.host,
			input.port,
			input.url,
			payloadStr,
			input.taskName,
			now,
		);

	return {
		id: Number(res.lastInsertRowid),
		project_id: input.project,
		type: input.type,
		host: input.host,
		port: input.port,
		url: input.url,
		payload: payloadStr,
		first_seen_task: input.taskName,
		created_at: now,
	};
}

export const RegisterAssetSchema = z.object({
	type: z.enum(ASSET_TYPES).optional(),
	host: z.string().min(1, "host 不能为空"),
	port: z.number().int().min(1).max(65535).optional(),
	url: z.string().optional(),
	note: z.string().optional(),
});

export type RegisterAssetInput = z.infer<typeof RegisterAssetSchema>;

/** 登记资产（worker register_asset 工具落点，支持 zod 契约校验与归一化）。 */
export function registerAsset(
	db: Database.Database,
	taskName: string,
	input: RegisterAssetInput,
	project = "default",
): { asset: AssetRow; created: boolean } {
	const parsed = RegisterAssetSchema.parse(input);

	let norm: NormalizedEndpoint;
	if (parsed.url?.trim()) {
		norm = normalizeEndpoint(parsed.url);
	} else if (parsed.port !== undefined) {
		norm = normalizeEndpoint(`${parsed.host}:${parsed.port}`);
	} else {
		norm = normalizeEndpoint(parsed.host);
	}

	const targetType = parsed.type ?? norm.type;
	const beforeCount = (db.prepare("SELECT COUNT(*) AS n FROM assets").get() as { n: number }).n;
	const asset = findOrCreateAsset(db, {
		project,
		type: targetType,
		host: norm.host,
		port: norm.port,
		url: norm.url,
		payload: parsed.note ? { note: parsed.note } : {},
		taskName,
	});
	const afterCount = (db.prepare("SELECT COUNT(*) AS n FROM assets").get() as { n: number }).n;

	// 记录任务所有权关系（origin=worker）
	db.prepare("INSERT OR IGNORE INTO asset_tasks (asset_id, task_id, origin, created_at) VALUES (?, ?, 'worker', ?)")
		.run(asset.id, taskName, new Date().toISOString());

	return { asset, created: afterCount > beforeCount };
}

/** 任务 scope 初始化：将 task.json 中 scope.hosts 登记到资产表与 asset_tasks 表中（origin=operator）。 */
export function resolveScopeHosts(
	db: Database.Database,
	taskName: string,
	hosts: string[],
	project = "default",
): AssetRow[] {
	const now = new Date().toISOString();
	const assets: AssetRow[] = [];
	const insertTask = db.prepare(
		"INSERT OR IGNORE INTO asset_tasks (asset_id, task_id, origin, created_at) VALUES (?, ?, 'operator', ?)",
	);

	for (const h of hosts) {
		if (!h.trim()) continue;
		const norm = normalizeEndpoint(h);
		const asset = findOrCreateAsset(db, {
			project,
			type: norm.type,
			host: norm.host,
			port: norm.port,
			url: norm.url,
			taskName,
		});
		insertTask.run(asset.id, taskName, now);
		assets.push(asset);
	}
	return assets;
}

/** 机械落锚（校验器5）：将 node（fact/finding）与资产关联。异常吞掉不挡主流程。 */
export function anchorFact(
	db: Database.Database,
	taskName: string,
	nodeId: number,
	endpoint: string,
	project = "default",
): { assetId: number; anchored: boolean } | undefined {
	try {
		const norm = normalizeEndpoint(endpoint);
		const asset = findOrCreateAsset(db, {
			project,
			type: norm.type,
			host: norm.host,
			port: norm.port,
			url: norm.url,
			taskName,
		});
		const res = db
			.prepare("INSERT OR IGNORE INTO anchors (task_id, node_id, asset_id, created_at) VALUES (?, ?, ?, ?)")
			.run(taskName, nodeId, asset.id, new Date().toISOString());
		return { assetId: asset.id, anchored: res.changes > 0 };
	} catch {
		return undefined;
	}
}

/** 查询本任务 scope 内可见资产（带本 task 锚计数，支持模糊搜索 q 和分页）。
 * P2 修法 A：anchor_count 按 **host 级**统计（本 task 在同 host 任意 port 资产上的锚都算）——
 * scope 裸 host（port=null）与 worker endpoint host:port 形态不再分裂；assets 表端口精度保留。 */
export function listAssetsInScope(
	db: Database.Database,
	taskName: string,
	opts?: { page?: number; pageSize?: number; q?: string },
): { total: number; page: number; pageSize: number; assets: AssetWithAnchorCount[] } {
	const page = Math.max(1, opts?.page ?? 1);
	const pageSize = Math.max(1, Math.min(100, opts?.pageSize ?? 20));
	const offset = (page - 1) * pageSize;
	const q = opts?.q?.trim().toLowerCase();

	const whereClause = q
		? "WHERE at.task_id = ? AND (LOWER(a.host) LIKE ? OR LOWER(a.url) LIKE ?)"
		: "WHERE at.task_id = ?";
	const countParams = q ? [taskName, `%${q}%`, `%${q}%`] : [taskName];

	const total = (
		db
			.prepare(
				`SELECT COUNT(DISTINCT a.id) AS n FROM assets a JOIN asset_tasks at ON at.asset_id = a.id ${whereClause}`,
			)
			.get(...countParams) as { n: number }
	).n;

	// 锚计数子查询：host 级匹配（锚落在本 task 关联资产的任意 port 形态上都算数）
	const selectParams = q
		? [taskName, taskName, `%${q}%`, `%${q}%`, pageSize, offset]
		: [taskName, taskName, pageSize, offset];

	const rows = db
		.prepare(
			`SELECT a.*, (
         SELECT COUNT(*) FROM anchors anc
         WHERE anc.task_id = ?
           AND anc.asset_id IN (SELECT a2.id FROM assets a2 WHERE a2.host = a.host)
       ) AS anchor_count
       FROM assets a
       JOIN asset_tasks at ON at.asset_id = a.id
       ${whereClause}
       ORDER BY a.id ASC
       LIMIT ? OFFSET ?`,
		)
		.all(...selectParams) as AssetWithAnchorCount[];

	return { total, page, pageSize, assets: rows };
}

/** 计算当前 task 的覆盖度（未测面 untouched 截取前 30 条）。
 * P2 修法 A：anchored 判定按 **host 级**——本 task 在同 host 任意 port 资产上有锚即算已测
 * （scope 裸 host 资产不再因 worker 提交 host:port 形态而恒 untouched）；他 task 的锚不计入。 */
export function coverageQuery(db: Database.Database, taskName: string): CoverageQueryResult {
	const rows = db
		.prepare(
			`SELECT a.id, a.type, a.host, a.port, a.url, (
         SELECT COUNT(*) FROM anchors anc
         WHERE anc.task_id = ?
           AND anc.asset_id IN (SELECT a2.id FROM assets a2 WHERE a2.host = a.host)
       ) AS anchor_count
       FROM assets a
       JOIN asset_tasks at ON at.asset_id = a.id AND at.task_id = ?
       ORDER BY a.id ASC`,
		)
		.all(taskName, taskName) as Array<{
		id: number;
		type: AssetType;
		host: string;
		port: number | null;
		url: string;
		anchor_count: number;
	}>;

	const scope_total = rows.length;
	const anchored = rows.filter((r) => r.anchor_count > 0).length;
	const untouched: UntouchedAsset[] = rows
		.filter((r) => r.anchor_count === 0)
		.slice(0, 30)
		.map((r) => ({ id: r.id, type: r.type, host: r.host, port: r.port, url: r.url }));

	return { scope_total, anchored, untouched };
}
