/**
 * browser 工具面（P0-4）：只做 browser_navigate + browser_snapshot 两个，
 * 包一层 playwright connectOverCDP 操作；其余工具面 P1 再扩。
 */
import { chromium, type Browser, type Page } from "playwright";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";

const SNAPSHOT_MAX_CHARS = 8000; // LLM-facing 截断，防大页面吃 token

/** CDP 附着会话：connectOverCDP 连池里的 Chrome，复用默认 context 的首个页面。 */
export class BrowserSession {
	private browser?: Browser;

	constructor(private readonly endpoint: string) {}

	async page(): Promise<Page> {
		if (!this.browser) {
			this.browser = await chromium.connectOverCDP(this.endpoint);
		}
		const ctx = this.browser.contexts()[0] ?? (await this.browser.newContext());
		return ctx.pages()[0] ?? (await ctx.newPage());
	}

	/** 只断连接不杀 Chrome——Chrome 归 browser-pool 管（所有权单一）。 */
	async dispose(): Promise<void> {
		try {
			await this.browser?.close();
		} catch {
			/* 已断 */
		}
		this.browser = undefined;
	}
}

function textResult(text: string) {
	return { content: [{ type: "text" as const, text }], details: null };
}

export function createNavigateTool(session: BrowserSession): AgentTool<any> {
	return {
		name: "browser_navigate",
		label: "Browser navigate",
		description: "用浏览器打开一个 URL，返回最终 URL 与页面标题。等待页面 load 完成。",
		parameters: Type.Object({
			url: Type.String({ description: "完整 URL（含 http:// 或 https://）" }),
		}),
		execute: async (_id, params: any) => {
			const url = String(params?.url ?? "").trim();
			if (!/^https?:\/\//i.test(url)) {
				throw new Error(`url 必须以 http:// 或 https:// 开头，收到：${url.slice(0, 100)}`);
			}
			const page = await session.page();
			await page.goto(url, { waitUntil: "load", timeout: 45_000 });
			const title = await page.title();
			return textResult(`final_url: ${page.url()}\ntitle: ${title}`);
		},
	};
}

export function createSnapshotTool(session: BrowserSession): AgentTool<any> {
	return {
		name: "browser_snapshot",
		label: "Browser snapshot",
		description:
			"对当前页面做可访问性快照（结构化文本：角色/名字/层级），用于观察页面内容与定位交互元素。导航后先调用本工具再下结论。",
		parameters: Type.Object({}),
		execute: async () => {
			const page = await session.page();
			let snapshot = "";
			try {
				snapshot = await page.locator("body").ariaSnapshot();
			} catch {
				snapshot = (await page.locator("body").innerText({ timeout: 10_000 })).slice(0, SNAPSHOT_MAX_CHARS);
			}
			const title = await page.title();
			const body = snapshot.slice(0, SNAPSHOT_MAX_CHARS);
			const trunc = snapshot.length > SNAPSHOT_MAX_CHARS ? `\n…（截断，原文 ${snapshot.length} 字符）` : "";
			return textResult(`url: ${page.url()}\ntitle: ${title}\n---\n${body}${trunc}`);
		},
	};
}
