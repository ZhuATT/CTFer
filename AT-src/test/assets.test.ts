import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	anchorFact,
	coverageQuery,
	findOrCreateAsset,
	listAssetsInScope,
	normalizeEndpoint,
	openAssetsDb,
	registerAsset,
	resolveScopeHosts,
} from "../src/assets.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-assets-test-"));
afterAll(() => {
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 延迟释放 */
	}
});

describe("P3-1 assets.ts 基建", () => {
	describe("normalizeEndpoint", () => {
		it("大写 host 归一化为小写", () => {
			const res = normalizeEndpoint("https://EXAMPLE.COM/api");
			expect(res.host).toBe("example.com");
			expect(res.url).toBe("https://example.com/api");
		});

		it("默认端口补齐（http 补 80，https 补 443）", () => {
			const httpRes = normalizeEndpoint("http://target.com/test");
			expect(httpRes.port).toBe(80);
			expect(httpRes.url).toBe("http://target.com/test");

			const httpsRes = normalizeEndpoint("https://target.com/test");
			expect(httpsRes.port).toBe(443);
			expect(httpsRes.url).toBe("https://target.com/test");
		});

		it("显式非默认端口保留", () => {
			const res = normalizeEndpoint("http://target.com:8080/test");
			expect(res.port).toBe(8080);
			expect(res.url).toBe("http://target.com:8080/test");
		});

		it("尾斜杠剥离（根路径除外）", () => {
			const slashRes = normalizeEndpoint("https://target.com/admin/");
			expect(slashRes.path).toBe("/admin");
			expect(slashRes.url).toBe("https://target.com/admin");

			const rootRes = normalizeEndpoint("https://target.com/");
			expect(rootRes.path).toBe("/");
			expect(rootRes.url).toBe("https://target.com");
		});

		it("query 与 fragment 剥离", () => {
			const res = normalizeEndpoint("https://target.com/search?q=123&token=abc#section-1");
			expect(res.path).toBe("/search");
			expect(res.url).toBe("https://target.com/search");
		});

		it("裸 host 与带端口 IP", () => {
			const bare = normalizeEndpoint("sub.domain.com");
			expect(bare.host).toBe("sub.domain.com");
			expect(bare.port).toBeNull();
			expect(bare.type).toBe("subdomain");
			expect(bare.url).toBe("sub.domain.com");

			const ipPort = normalizeEndpoint("192.168.1.100:8443");
			expect(ipPort.host).toBe("192.168.1.100");
			expect(ipPort.port).toBe(8443);
			expect(ipPort.type).toBe("ip");
			expect(ipPort.url).toBe("192.168.1.100:8443");

			const bareIp = normalizeEndpoint("10.0.0.1");
			expect(bareIp.host).toBe("10.0.0.1");
			expect(bareIp.port).toBeNull();
			expect(bareIp.type).toBe("ip");
		});

		it("空输入抛错", () => {
			expect(() => normalizeEndpoint("   ")).toThrow("Endpoint 不能为空");
		});
	});

	describe("数据库操作与幂等性", () => {
		it("openAssetsDb 创建 WAL 模式与三张表", () => {
			const dbPath = join(dir, "test-p3-1.db");
			const db = openAssetsDb(dbPath);
			const tables = db
				.prepare("SELECT name FROM sqlite_master WHERE type='table'")
				.all() as Array<{ name: string }>;
			const names = tables.map((t) => t.name);
			expect(names).toContain("assets");
			expect(names).toContain("asset_tasks");
			expect(names).toContain("anchors");
			db.close();
		});

		it("findOrCreateAsset 幂等：同 endpoint 二次登记返回同 id，不产生重复行", () => {
			const dbPath = join(dir, "test-idemp.db");
			const db = openAssetsDb(dbPath);

			const a1 = findOrCreateAsset(db, {
				project: "proj1",
				type: "endpoint",
				host: "api.target.com",
				port: 443,
				url: "https://api.target.com/v1",
				taskName: "task-A",
			});

			const a2 = findOrCreateAsset(db, {
				project: "proj1",
				type: "endpoint",
				host: "api.target.com",
				port: 443,
				url: "https://api.target.com/v1",
				taskName: "task-B",
			});

			expect(a1.id).toBe(a2.id);
			const count = (db.prepare("SELECT COUNT(*) AS n FROM assets").get() as { n: number }).n;
			expect(count).toBe(1);
			db.close();
		});

		it("resolveScopeHosts 幂等入库，origin=operator", () => {
			const dbPath = join(dir, "test-scope.db");
			const db = openAssetsDb(dbPath);

			const list1 = resolveScopeHosts(db, "task-1", ["api.target.com", "login.target.com"], "proj1");
			expect(list1).toHaveLength(2);

			const list2 = resolveScopeHosts(db, "task-1", ["api.target.com", "new.target.com"], "proj1");
			expect(list2).toHaveLength(2);

			const total = (db.prepare("SELECT COUNT(*) AS n FROM assets").get() as { n: number }).n;
			expect(total).toBe(3); // api, login, new

			const taskRows = db
				.prepare("SELECT * FROM asset_tasks WHERE task_id='task-1'")
				.all() as Array<{ origin: string }>;
			expect(taskRows).toHaveLength(3);
			expect(taskRows.every((r) => r.origin === "operator")).toBe(true);

			db.close();
		});

		it("registerAsset 契约校验与登记（origin=worker）", () => {
			const dbPath = join(dir, "test-register.db");
			const db = openAssetsDb(dbPath);

			const r1 = registerAsset(db, "task-1", {
				host: "upload.target.com",
				port: 8080,
				note: "从 js 泄露中提取",
			});
			expect(r1.created).toBe(true);
			expect(r1.asset.host).toBe("upload.target.com");
			expect(r1.asset.port).toBe(8080);

			// 重复登记
			const r2 = registerAsset(db, "task-1", {
				host: "upload.target.com",
				port: 8080,
			});
			expect(r2.created).toBe(false);
			expect(r2.asset.id).toBe(r1.asset.id);

			db.close();
		});

		it("anchorFact 机械锚点：fact 关联资产；异常安全不抛出", () => {
			const dbPath = join(dir, "test-anchor.db");
			const db = openAssetsDb(dbPath);

			const res = anchorFact(db, "task-1", 101, "https://api.target.com/v1/user");
			expect(res?.anchored).toBe(true);
			expect(res?.assetId).toBeDefined();

			// 验证 anchors 表
			const row = db
				.prepare("SELECT * FROM anchors WHERE task_id='task-1' AND node_id=101")
				.get() as { asset_id: number };
			expect(row.asset_id).toBe(res?.assetId);

			// 坏输入不崩
			const badRes = anchorFact(db, "task-1", 102, "   ");
			expect(badRes).toBeUndefined();

			db.close();
		});
	});

	describe("listAssetsInScope 与 coverageQuery", () => {
		it("listAssetsInScope：仅可见当前 task 关联资产（越界不可见）+ 锚计数", () => {
			const dbPath = join(dir, "test-query.db");
			const db = openAssetsDb(dbPath);

			// Task A 关联 asset 1, 2
			resolveScopeHosts(db, "task-A", ["a.com", "b.com"], "proj");
			// Task B 关联 asset 2, 3
			resolveScopeHosts(db, "task-B", ["b.com", "c.com"], "proj");

			// Task A 锚定 b.com
			anchorFact(db, "task-A", 10, "b.com", "proj");

			// Task A 查：可见 a.com (anchor=0) 和 b.com (anchor=1)，不可见 c.com
			const resA = listAssetsInScope(db, "task-A");
			expect(resA.total).toBe(2);
			const hostsA = resA.assets.map((a) => a.host);
			expect(hostsA).toContain("a.com");
			expect(hostsA).toContain("b.com");
			expect(hostsA).not.toContain("c.com");
			const bInA = resA.assets.find((a) => a.host === "b.com");
			expect(bInA?.anchor_count).toBe(1);

			// Task B 查：可见 b.com 和 c.com，不可见 a.com。b.com 在 Task B 的锚为 0
			const resB = listAssetsInScope(db, "task-B");
			expect(resB.total).toBe(2);
			const hostsB = resB.assets.map((a) => a.host);
			expect(hostsB).toContain("b.com");
			expect(hostsB).toContain("c.com");
			expect(hostsB).not.toContain("a.com");
			const bInB = resB.assets.find((a) => a.host === "b.com");
			expect(bInB?.anchor_count).toBe(0); // 他 task 的锚不计入本 task

			// 模糊搜索 q
			const filtered = listAssetsInScope(db, "task-A", { q: "a." });
			expect(filtered.total).toBe(1);
			expect(filtered.assets[0].host).toBe("a.com");

			db.close();
		});

		it("coverageQuery：scope 资产与未测面统计（3 资产 1 锚 → untouched=2）", () => {
			const dbPath = join(dir, "test-cov.db");
			const db = openAssetsDb(dbPath);

			resolveScopeHosts(db, "task-X", ["x1.com", "x2.com", "x3.com"], "proj");
			anchorFact(db, "task-X", 1, "x2.com", "proj");

			const cov = coverageQuery(db, "task-X");
			expect(cov.scope_total).toBe(3);
			expect(cov.anchored).toBe(1);
			expect(cov.untouched).toHaveLength(2);
			const untouchedHosts = cov.untouched.map((u) => u.host);
			expect(untouchedHosts).toContain("x1.com");
			expect(untouchedHosts).toContain("x3.com");
			expect(untouchedHosts).not.toContain("x2.com");

			db.close();
		});
	});
});
