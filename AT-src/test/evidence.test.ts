import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { HarRecorder, HAR_MAX_BODY_SIZE } from "../src/har.js";
import { validateBaselineEvidence, submitFinding, getNode, initTask, submitFact } from "../src/graph.js";
import { openDb } from "../src/db.js";
import { createSubmitFindingTool } from "../src/tools/submit.js";
import type { TaskJson } from "../src/task.js";

describe("CDP HAR 硬捕获录制器 HarRecorder (E-1)", () => {
	it("替身事件注入 → flush 成合法 HAR 1.2 JSON 文件", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-har-test-"));
		const harPath = join(tmp, "traffic", "session-123.har");

		try {
			const recorder = new HarRecorder();

			// 1. 模拟请求发出事件
			recorder.recordCdpEvent("Network.requestWillBeSent", {
				requestId: "req-1",
				wallTime: 1700000000.123,
				timestamp: 100.5,
				request: {
					method: "POST",
					url: "http://target.example.com/api/login?ref=test",
					headers: { "Content-Type": "application/json", Authorization: "Bearer token-1" },
					postData: JSON.stringify({ user: "admin", pass: "123456" }),
				},
			});

			// 2. 模拟响应头到达
			recorder.recordCdpEvent("Network.responseReceived", {
				requestId: "req-1",
				timestamp: 100.8,
				response: {
					status: 200,
					statusText: "OK",
					protocol: "http/1.1",
					mimeType: "application/json",
					headers: { "Content-Type": "application/json", "Set-Cookie": "sess=abc" },
				},
			});

			// 3. 模拟获取响应体
			recorder.recordCdpEvent("Network.getResponseBodyResult", {
				requestId: "req-1",
				body: JSON.stringify({ success: true, token: "jwt-token-xyz" }),
				base64Encoded: false,
			});

			// 4. 模拟加载完成
			recorder.recordCdpEvent("Network.loadingFinished", {
				requestId: "req-1",
				timestamp: 100.9,
				encodedDataLength: 45,
			});

			// 5. flush 落盘
			recorder.flush(harPath);

			expect(existsSync(harPath)).toBe(true);
			const raw = readFileSync(harPath, "utf-8");
			const har = JSON.parse(raw);

			expect(har.log.version).toBe("1.2");
			expect(har.log.creator.name).toBe("AT1 CDP HAR Recorder");
			expect(har.log.entries).toHaveLength(1);

			const entry = har.log.entries[0];
			expect(entry.request.method).toBe("POST");
			expect(entry.request.url).toBe("http://target.example.com/api/login?ref=test");
			expect(entry.request.queryString).toEqual([{ name: "ref", value: "test" }]);
			expect(entry.request.postData.text).toContain("123456");
			expect(entry.response.status).toBe(200);
			expect(entry.response.content.text).toContain("jwt-token-xyz");
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("请求体与响应体超过 64KB 截断并在内容标记 [truncated at 64KB]", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-har-trunc-"));
		const harPath = join(tmp, "truncated.har");

		try {
			const recorder = new HarRecorder();
			const hugeBody = "X".repeat(HAR_MAX_BODY_SIZE + 5000);

			recorder.recordCdpEvent("Network.requestWillBeSent", {
				requestId: "req-huge",
				wallTime: 1700000000,
				timestamp: 10,
				request: {
					method: "POST",
					url: "http://target.example.com/upload",
					postData: hugeBody,
				},
			});

			recorder.recordCdpEvent("Network.getResponseBodyResult", {
				requestId: "req-huge",
				body: hugeBody,
			});

			recorder.recordCdpEvent("Network.loadingFinished", {
				requestId: "req-huge",
				timestamp: 12,
			});

			recorder.flush(harPath);
			const har = JSON.parse(readFileSync(harPath, "utf-8"));
			const entry = har.log.entries[0];

			expect(entry.request.postData.text).toContain("[truncated at 64KB]");
			expect(entry.request.postData.text.length).toBeLessThan(hugeBody.length);
			expect(entry.response.content.text).toContain("[truncated at 64KB]");
			expect(entry.response.content.text.length).toBeLessThan(hugeBody.length);
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("异常断开 finally 无论有无未完成请求均保证 flush 合法 HAR", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-har-finally-"));
		const harPath = join(tmp, "crashed.har");

		try {
			const recorder = new HarRecorder();

			// 只有发出的请求，由于异常断开未收到 responseReceived 或 loadingFinished
			recorder.recordCdpEvent("Network.requestWillBeSent", {
				requestId: "req-inflight",
				wallTime: 1700000000,
				timestamp: 10,
				request: { method: "GET", url: "http://target.example.com/hanging" },
			});

			// 模拟在 finally 中调用 flush
			try {
				throw new Error("Worker unexpected crash");
			} catch {
				// crash
			} finally {
				recorder.flush(harPath);
			}

			expect(existsSync(harPath)).toBe(true);
			const har = JSON.parse(readFileSync(harPath, "utf-8"));
			expect(har.log.version).toBe("1.2");
			expect(har.log.entries).toHaveLength(1);
			expect(har.log.entries[0].request.url).toBe("http://target.example.com/hanging");
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});
});

describe("baseline 对照严门 (E-2, 静态检查三规则)", () => {
	const tmp = mkdtempSync(join(tmpdir(), "at1-baseline-rules-"));

	it("规则 1：以 '不适用——' 开头且原因非空 → 成功通过并提取 baseline_note", () => {
		const res = validateBaselineEvidence(tmp, "不适用——纯只读单点接口无需对照");
		expect(res.ok).toBe(true);
		expect(res.note).toBe("纯只读单点接口无需对照");
	});

	it("规则 1 违规：'不适用——' 后面原因为空 → 打回", () => {
		expect(() => validateBaselineEvidence(tmp, "不适用——")).toThrowError(
			/必须填写具体原因.*收到了空的豁免原因/,
		);
		expect(() => validateBaselineEvidence(tmp, "不适用——   ")).toThrowError(
			/必须填写具体原因.*收到了空的豁免原因/,
		);
	});

	it("规则 2：按文件路径查存在性 → 文件存在通过", () => {
		const validFile = "evidence/baseline-order-401.txt";
		mkdirSync(join(tmp, "evidence"), { recursive: true });
		writeFileSync(join(tmp, validFile), "HTTP/1.1 401 Unauthorized\n未登录对照响应");

		const res = validateBaselineEvidence(tmp, validFile);
		expect(res.ok).toBe(true);
		expect(res.note).toBeUndefined();
	});

	it("规则 2 违规：对照证据文件不存在 → 人话打回指路", () => {
		const missingFile = "evidence/missing-baseline.txt";
		expect(() => validateBaselineEvidence(tmp, missingFile)).toThrowError(
			/对照证据文件不存在：evidence\/missing-baseline\.txt.*请先将对照证据写入该文件/,
		);
	});

	it("规则 3 违规：空串或纯空白乱填 → 打回", () => {
		expect(() => validateBaselineEvidence(tmp, "")).toThrowError(/baseline_evidence 必填，值二选一/);
		expect(() => validateBaselineEvidence(tmp, "   ")).toThrowError(/baseline_evidence 必填，值二选一/);
		expect(() => validateBaselineEvidence(tmp, undefined)).toThrowError(/baseline_evidence 必填，值二选一/);
	});
});

describe("submit_finding 严门回归与契约错误人话化", () => {
	const TASK: TaskJson = {
		name: "t-evidence",
		goal: "验 baseline 严门",
		scope: { hosts: ["target.example.com"] },
		seed_steps: [{ summary: "初始探测" }],
	};

	function writeEvidenceFile(baseDir: string, name: string, content = "GET / HTTP/1.1\n200 OK"): string {
		mkdirSync(join(baseDir, "evidence"), { recursive: true });
		const rel = join("evidence", name);
		writeFileSync(join(baseDir, rel), content, "utf-8");
		return rel;
	}

	it("submitFinding 传有效 baseline_evidence 时成功入图", () => {
		const dir = mkdtempSync(join(tmpdir(), "at1-finding-ok-"));
		const db = openDb(join(dir, "g.db"));
		try {
			const { stepIds } = initTask(db, TASK);
			const evidence = writeEvidenceFile(dir, "proof.txt", "GET /api/user/1002 → 200 (IDOR payload)");
			const fact = submitFact(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: { summary: "发现用户越权查看其他用户资料", evidence, confidence: "observed" },
			});

			const r = submitFinding(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				relatedFactIds: [fact.id],
				payload: {
					summary: "用户中心接口存在水平越权",
					vulnclass: "越权",
					severity: "high",
					poc: "curl -H 'Cookie: user=1001' https://target.example.com/api/user/1002",
					evidence,
					baseline_evidence: "不适用——已由 A/B 账号在 proof 中直接证明",
				},
			});

			const node = getNode(db, TASK.name, r.id)!;
			expect(node.state).toBe("reported");
			const parsedPayload = JSON.parse(node.payload);
			expect(parsedPayload.baseline_evidence).toBe("不适用——已由 A/B 账号在 proof 中直接证明");
			expect(parsedPayload.baseline_note).toBe("已由 A/B 账号在 proof 中直接证明");
		} finally {
			db.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("submit_finding 不带 baseline_evidence → 明确人话报错指引", async () => {
		const dir = mkdtempSync(join(tmpdir(), "at1-finding-legacy-"));
		const db = openDb(join(dir, "g.db"));
		try {
			const { stepIds } = initTask(db, TASK);
			writeEvidenceFile(dir, "proof.txt", "payload proof");

			const tool = createSubmitFindingTool({
				db,
				taskId: TASK.name,
				taskDir: dir,
				sessionId: "s1",
			});

			// 模拟遗留/存量调用（未传 baseline_evidence）
			await expect(
				tool.execute("call-legacy", {
					step_id: stepIds[0],
					summary: "未带 baseline 的漏洞提交",
					vulnclass: "越权",
					severity: "medium",
					poc: "curl /poc",
					evidence: "proof.txt",
				}),
			).rejects.toThrowError(/baseline_evidence 必填，值二选一/);
		} finally {
			db.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("F-10：路径型 baseline → payload 含 baseline_sha256（64位hex）；豁免型 → 无该键", () => {
		const dir = mkdtempSync(join(tmpdir(), "at1-finding-sha-"));
		const db = openDb(join(dir, "g.db"));
		try {
			const { stepIds } = initTask(db, TASK);
			const evidence = writeEvidenceFile(dir, "proof-sha.txt", "payload proof with hash");
			const baseline = writeEvidenceFile(dir, "baseline-sha.txt", "匿名对照请求 401 Unauthorized");

			const r1 = submitFinding(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: {
					summary: "路径型对照的越权漏洞可归因",
					vulnclass: "越权",
					severity: "high",
					poc: "curl -H 'Cookie: user=1001' https://target.example.com/api/user/1002",
					evidence,
					baseline_evidence: baseline,
				},
			});
			const p1 = JSON.parse(getNode(db, TASK.name, r1.id)!.payload);
			expect(p1.baseline_sha256).toMatch(/^[0-9a-f]{64}$/);

			const r2 = submitFinding(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: {
					summary: "豁免型对照的越权观察另一条",
					vulnclass: "越权",
					severity: "low",
					poc: "curl -H 'Cookie: user=1001' https://target.example.com/api/user/1003",
					evidence,
					baseline_evidence: "不适用——已由 proof 与 baseline-sha 双账号直接归因",
				},
			});
			const p2 = JSON.parse(getNode(db, TASK.name, r2.id)!.payload);
			expect(p2.baseline_sha256).toBeUndefined();
		} finally {
			db.close();
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("F-9 HAR 保真：extraInfo 头合并 + 重定向链分条", () => {
	function skeleton(rec: HarRecorder, id: string, url: string, headers: Record<string, string> = {}) {
		rec.recordCdpEvent("Network.requestWillBeSent", {
			requestId: id,
			wallTime: 1700000000.1,
			timestamp: 100.0,
			request: { method: "GET", url, headers },
		});
	}
	const names = (e: any) => Object.fromEntries((e.request?.headers ?? []).map((h) => [h.name.toLowerCase(), h.value]));
	const respNames = (e: any) => Object.fromEntries((e.response?.headers ?? []).map((h) => [h.name.toLowerCase(), h.value]));

	it("F-9a 骨架先到→extraInfo 后到：Cookie 进 requestHeaders，同名头被 extraInfo 覆盖，伪头剔除", () => {
		const rec = new HarRecorder();
		skeleton(rec, "r1", "http://t.example.com/a", { "User-Agent": "ua-1", Accept: "*/*" });
		rec.recordCdpEvent("Network.requestWillBeSentExtraInfo", {
			requestId: "r1",
			headers: { cookie: "foo=bar", "User-Agent": "ua-extra", ":method": "GET" },
		});
		rec.recordCdpEvent("Network.loadingFinished", { requestId: "r1", timestamp: 100.2 });
		const e = rec.buildHar().log.entries[0];
		const h = names(e);
		expect(h["cookie"]).toBe("foo=bar");
		expect(h["user-agent"]).toBe("ua-extra"); // extraInfo=网络层真实值，同名覆盖 base
		expect(h["accept"]).toBe("*/*"); // base 保留
		expect(h[":method"]).toBeUndefined(); // 伪头不进 HAR
	});

	it("F-9a extraInfo 先到→骨架后到（回捞路径）：同样合并成功", () => {
		const rec = new HarRecorder();
		rec.recordCdpEvent("Network.requestWillBeSentExtraInfo", { requestId: "r2", headers: { cookie: "sid=xyz" } });
		skeleton(rec, "r2", "http://t.example.com/b", { Host: "t.example.com" });
		rec.recordCdpEvent("Network.loadingFinished", { requestId: "r2", timestamp: 100.2 });
		const h = names(rec.buildHar().log.entries[0]);
		expect(h["cookie"]).toBe("sid=xyz");
		expect(h["host"]).toBe("t.example.com");
	});

	it("F-9a responseReceivedExtraInfo 的 Set-Cookie 进 responseHeaders", () => {
		const rec = new HarRecorder();
		skeleton(rec, "r3", "http://t.example.com/c");
		rec.recordCdpEvent("Network.responseReceived", {
			requestId: "r3",
			response: { status: 200, statusText: "OK", protocol: "http/1.1", mimeType: "text/plain", headers: { "Content-Type": "text/plain" } },
		});
		rec.recordCdpEvent("Network.responseReceivedExtraInfo", { requestId: "r3", headers: { "set-cookie": "k=v; Path=/" } });
		rec.recordCdpEvent("Network.loadingFinished", { requestId: "r3", timestamp: 100.2 });
		const h = respNames(rec.buildHar().log.entries[0]);
		expect(h["set-cookie"]).toBe("k=v; Path=/");
		expect(h["content-type"]).toBe("text/plain");
	});

	it("F-9a 孤儿 extraInfo：flush 不崩、不进产物", () => {
		const tmp = mkdtempSync(join(tmpdir(), "at1-har-orphan-"));
		const harPath = join(tmp, "t", "s.har");
		try {
			const rec = new HarRecorder();
			rec.recordCdpEvent("Network.requestWillBeSentExtraInfo", { requestId: "ghost", headers: { cookie: "x=y" } });
			rec.recordCdpEvent("Network.responseReceivedExtraInfo", { requestId: "ghost", headers: { "set-cookie": "a=b" } });
			expect(() => rec.flush(harPath)).not.toThrow();
			const har = JSON.parse(readFileSync(harPath, "utf-8"));
			expect(har.log.entries).toHaveLength(0);
		} finally {
			rmSync(tmp, { recursive: true, force: true });
		}
	});

	it("F-9b A(带Cookie)→302(redirectResponse)→B→200：恰好 2 条 entry，A=302+redirectURL+Cookie，B=200", () => {
		const rec = new HarRecorder();
		skeleton(rec, "rd", "http://t.example.com/login", { cookie: "prev=1" });
		// A 跳 extraInfo（byId 仍指 A → 合并进 A）
		rec.recordCdpEvent("Network.requestWillBeSentExtraInfo", { requestId: "rd", headers: { cookie: "user=a" } });
		// B 跳骨架带 redirectResponse（A 跳终态捎带）
		rec.recordCdpEvent("Network.requestWillBeSent", {
			requestId: "rd",
			wallTime: 1700000000.5,
			timestamp: 100.5,
			request: { method: "GET", url: "http://t.example.com/home", headers: {} },
			redirectResponse: {
				status: 302,
				statusText: "Found",
				protocol: "http/1.1",
				mimeType: "text/plain",
				headers: { Location: "/home", "Set-Cookie": "sess=s1" },
			},
		});
		rec.recordCdpEvent("Network.responseReceived", {
			requestId: "rd",
			response: { status: 200, statusText: "OK", protocol: "http/1.1", mimeType: "text/html", headers: { "Content-Type": "text/html" } },
		});
		rec.recordCdpEvent("Network.loadingFinished", { requestId: "rd", timestamp: 101.0 });
		const har = rec.buildHar();
		expect(har.log.entries).toHaveLength(2);
		const [a, b] = har.log.entries;
		expect(a.response.status).toBe(302);
		expect(a.response.redirectURL).toBe("/home");
		expect(names(a)["cookie"]).toBe("user=a"); // extraInfo 同名覆盖骨架值
		expect(respNames(a)["set-cookie"]).toBe("sess=s1");
		expect(names(b)["cookie"]).toBeUndefined(); // B 换新条目，A 的 extraInfo 不串
		expect(b.response.status).toBe(200);
	});

	it("F-9b 三跳链 A→B→C：3 条 entry 逐跳齐全", () => {
		const rec = new HarRecorder();
		skeleton(rec, "c3", "http://t.example.com/a");
		rec.recordCdpEvent("Network.requestWillBeSent", {
			requestId: "c3",
			wallTime: 1700000000.2,
			timestamp: 100.2,
			request: { method: "GET", url: "http://t.example.com/b", headers: {} },
			redirectResponse: { status: 301, statusText: "Moved", protocol: "http/1.1", mimeType: "text/plain", headers: { Location: "/b" } },
		});
		rec.recordCdpEvent("Network.requestWillBeSent", {
			requestId: "c3",
			wallTime: 1700000000.3,
			timestamp: 100.3,
			request: { method: "GET", url: "http://t.example.com/c", headers: {} },
			redirectResponse: { status: 302, statusText: "Found", protocol: "http/1.1", mimeType: "text/plain", headers: { Location: "/c" } },
		});
		rec.recordCdpEvent("Network.responseReceived", {
			requestId: "c3",
			response: { status: 200, statusText: "OK", protocol: "http/1.1", mimeType: "text/html", headers: {} },
		});
		rec.recordCdpEvent("Network.loadingFinished", { requestId: "c3", timestamp: 100.9 });
		const har = rec.buildHar();
		expect(har.log.entries).toHaveLength(3);
		expect(har.log.entries.map((e: any) => e.request.url)).toEqual([
			"http://t.example.com/a",
			"http://t.example.com/b",
			"http://t.example.com/c",
		]);
		expect(har.log.entries[0].response.status).toBe(301);
		expect(har.log.entries[0].response.redirectURL).toBe("/b");
		expect(har.log.entries[1].response.status).toBe(302);
		expect(har.log.entries[1].response.redirectURL).toBe("/c");
		expect(har.log.entries[2].response.status).toBe(200);
	});
});
