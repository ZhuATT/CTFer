/**
 * 浏览器池（P0-4）：src/browser.py 的 TS 直译。
 *
 * 保留：find_exe / alloc_port / launch(detached) / probe(/json/version) /
 * shutdown（杀树+删账）。记账走 <root>/.at1/browser.json（pid+port）——
 * P0 无孤儿复用：启动时见旧账且进程活着 → 先杀再拉新（P1 再补复用）。
 * 删掉（P0 用不到）：KEEP 留守语义、headless 比对、浏览器缺席降级（P0 强依赖）。
 *
 * Windows detached：node spawn({detached:true}) ≙ DETACHED_PROCESS（browser.py
 * 同款逻辑，jwzx 批已验证）。探活 fetch 直连——undici 默认不吃 HTTP_PROXY，
 * 无需 Python 版的 no-proxy opener。
 */
import { spawn, execFile } from "node:child_process";
import net from "node:net";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const CANDIDATES = [
	"D:\\chrome\\Chrome\\Application\\chrome.exe",
	"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
	"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
	"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
	"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
];

const CDP_WAIT_MS = 20_000; // 启动等 CDP 就绪 deadline（browser.py 同款）
const PROBE_TIMEOUT_MS = 2_000; // /json/version 探活超时
const PORT_RETRIES = 3; // bind-close-use 竞态兜底
const PROFILE_DIRNAME = "chrome-profile";

export function findExe(): string | null {
	const env = process.env.AT1_BROWSER_EXE?.trim();
	if (env) return existsSync(env) ? env : null;
	for (const c of candidates()) if (existsSync(c)) return c;
	return null;
}

function candidates(): string[] {
	const out = [...CANDIDATES];
	const la = process.env.LOCALAPPDATA;
	if (la) out.push(join(la, "Google", "Chrome", "Application", "chrome.exe"));
	return out;
}

export function allocPort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const srv = net.createServer();
		srv.unref();
		srv.on("error", reject);
		srv.listen(0, "127.0.0.1", () => {
			const { port } = srv.address() as net.AddressInfo;
			srv.close(() => resolve(port));
		});
	});
}

export async function probe(port: number, timeoutMs = PROBE_TIMEOUT_MS): Promise<boolean> {
	try {
		const res = await fetch(`http://127.0.0.1:${Math.floor(port)}/json/version`, {
			signal: AbortSignal.timeout(timeoutMs),
		});
		return res.ok;
	} catch {
		return false;
	}
}

export async function waitCdp(port: number, deadlineMs = CDP_WAIT_MS): Promise<boolean> {
	const end = Date.now() + deadlineMs;
	while (Date.now() < end) {
		if (await probe(port)) return true;
		await sleep(500);
	}
	return false;
}

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

function launch(port: number, profileDir: string, exe: string): number {
	mkdirSync(profileDir, { recursive: true });
	const child = spawn(
		exe,
		[
			`--remote-debugging-port=${port}`,
			`--user-data-dir=${profileDir}`,
			"--no-first-run",
			"--no-default-browser-check",
			"--disable-sync",
			"about:blank",
		],
		{ detached: true, stdio: "ignore", windowsHide: true },
	);
	child.unref(); // 不持有——Chrome 与本进程只有记账关系（browser.py 所有权设计的根）
	return child.pid ?? 0;
}

async function imageName(pid: number): Promise<string> {
	if (process.platform !== "win32") return "";
	try {
		const stdout = await new Promise<string>((resolve, reject) => {
			execFile("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], { timeout: 10_000 }, (err, out) =>
				err ? reject(err) : resolve(String(out)),
			);
		});
		const first = stdout.trim().split(/\r?\n/)[0] ?? "";
		return first.startsWith('"') ? first.split('","')[0].replace(/"/g, "").toLowerCase() : "";
	} catch {
		return "";
	}
}

async function pidAlive(pid: number): Promise<boolean> {
	if (!pid) return false;
	if (process.platform === "win32") return (await imageName(pid)) !== "";
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

/** 杀浏览器进程树（taskkill /T /F）。镜像名必须 chrome/msedge——pid 可能已被
 * OS 回收复用，裸 PID 杀树会误杀无辜（browser.py S2 同源守门）。 */
export async function killPid(pid: number): Promise<void> {
	if (!pid || !(await pidAlive(pid))) return;
	if (process.platform === "win32") {
		const img = await imageName(pid);
		if (!img.includes("chrome") && !img.includes("msedge")) return;
		try {
			await new Promise<void>((resolve) => {
				execFile("taskkill", ["/PID", String(pid), "/T", "/F"], { timeout: 10_000 }, () => resolve());
			});
		} catch {
			/* 尽力而为 */
		}
	} else {
		try {
			process.kill(pid, "SIGKILL");
		} catch {
			/* 已死 */
		}
	}
}

export interface BrowserState {
	pid: number;
	port: number;
}

export class BrowserPool {
	pid = 0;
	port = 0;

	private constructor(
		private readonly root: string,
		private readonly exe: string,
	) {}

	static statePath(root: string): string {
		return join(root, ".at1", "browser.json");
	}

	get profileDir(): string {
		return join(this.root, ".at1", PROFILE_DIRNAME);
	}

	get endpoint(): string {
		return `http://127.0.0.1:${this.port}`;
	}

	private writeState(): void {
		writeFileSync(
			BrowserPool.statePath(this.root),
			JSON.stringify({ pid: this.pid, port: this.port }, null, 2),
			"utf-8",
		);
	}

	private readState(): BrowserState | null {
		try {
			const d = JSON.parse(readFileSync(BrowserPool.statePath(this.root), "utf-8"));
			return d?.pid && d?.port ? { pid: Number(d.pid), port: Number(d.port) } : null;
		} catch {
			return null;
		}
	}

	/** 换口重试拉新；彻底失败抛错（P0 无降级路径，直接 fail-fast）。 */
	private async launchNew(): Promise<void> {
		let last = "";
		for (let i = 0; i < PORT_RETRIES; i++) {
			const port = await allocPort();
			let pid = 0;
			try {
				pid = launch(port, this.profileDir, this.exe);
			} catch (e) {
				last = `spawn-fail: ${e instanceof Error ? e.message : String(e)}`;
				continue;
			}
			this.port = port;
			this.pid = pid;
			if (await waitCdp(port)) {
				this.writeState();
				return;
			}
			last = `cdp-timeout port ${port}`;
			await killPid(pid); // 进程在但 CDP 没就绪 = 半死实例，清掉换口
		}
		throw new Error(`Chrome 启动失败（${PORT_RETRIES} 次尝试）：${last}`);
	}

	/** 开池：旧账里的实例活着也先杀（P0 无复用），再拉新。 */
	static async start(root: string): Promise<BrowserPool> {
		const exe = findExe();
		if (!exe) {
			throw new Error("找不到 Chrome/Edge 可执行文件（AT1_BROWSER_EXE 或默认候选路径）");
		}
		const pool = new BrowserPool(root, exe);
		const st = pool.readState();
		if (st) {
			await killPid(st.pid); // P0：不复用，先清场再拉新
		}
		try {
			await pool.launchNew();
			return pool;
		} catch (err) {
			await pool.shutdown();
			throw err;
		}
	}

	/** 探活自愈：假死/崩溃 → 杀旧拉新。 */
	async ensureAlive(): Promise<void> {
		if (this.pid && (await pidAlive(this.pid)) && (await probe(this.port))) return;
		if (this.pid) await killPid(this.pid);
		await this.launchNew();
	}

	/** 收尾：杀树 + 删账。P0 无 keep 语义——smoke 后必须无残留（验收项）。 */
	async shutdown(): Promise<void> {
		await killPid(this.pid);
		try {
			unlinkSync(BrowserPool.statePath(this.root));
		} catch {
			/* 已删 */
		}
		this.pid = 0;
		this.port = 0;
	}
}
