import { describe, expect, it } from "vitest";
import http from "node:http";
import { findExe, allocPort, probe } from "../src/browser-pool.js";

describe("browser-pool 基件", () => {
	it("findExe 找得到本机 Chrome/Edge", () => {
		const exe = findExe();
		expect(exe).toBeTruthy();
		expect(exe!.toLowerCase()).toMatch(/chrome|msedge/);
	});

	it("allocPort 返回空闲端口（数字，>0）", async () => {
		const p = await allocPort();
		expect(Number.isInteger(p)).toBe(true);
		expect(p).toBeGreaterThan(0);
		expect(p).toBeLessThanOrEqual(65535);
	});

	it("probe 死端口 → false（不抛）", async () => {
		expect(await probe(1, 500)).toBe(false); // port 1 几乎必无 CDP
	});

	it("probe 对 /json/version 200 的桩 → true", async () => {
		const srv = http.createServer((req, res) => {
			if (req.url === "/json/version") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end('{"Browser":"stub/1.0"}');
			} else {
				res.writeHead(404);
				res.end();
			}
		});
		await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
		const port = (srv.address() as { port: number }).port;
		expect(await probe(port)).toBe(true);
		await new Promise<void>((r) => srv.close(() => r()));
	});
});
