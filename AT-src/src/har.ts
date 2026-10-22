/**
 * har.ts — CDP HAR 硬捕获录制器（E-1）
 *
 * 职责：
 * - 监听/注入 CDP Network 事件（requestWillBeSent, responseReceived, loadingFinished, loadingFailed）；
 * - 缓存请求/响应并在会话结束时 flush 成合法的 HAR 1.2 JSON 文件；
 * - 体积控制：请求与响应 body 超过 64KB 时硬截断，并追加 "[truncated at 64KB]" 标记；
 * - 纯旁路：异常断开走 finally flush，worker 零感知。
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const HAR_MAX_BODY_SIZE = 64 * 1024; // 64KB 截断阈值

export interface HarHeader {
	name: string;
	value: string;
}

export interface HarQueryParam {
	name: string;
	value: string;
}

export interface HarCookie {
	name: string;
	value: string;
}

interface InFlightEntry {
	requestId: string;
	startedDateTime: string;
	startWallTime: number;
	startTimestamp: number;
	endTimestamp?: number;
	method: string;
	url: string;
	requestHeaders: HarHeader[];
	queryString: HarQueryParam[];
	postDataText?: string;
	status: number;
	statusText: string;
	protocol: string;
	responseHeaders: HarHeader[];
	mimeType: string;
	responseBody?: string;
	responseSize: number;
	errorText?: string;
}

export class HarRecorder {
	private entries = new Map<string, InFlightEntry>();
	private completed: InFlightEntry[] = [];
	private flushed = false;

	onRequestWillBeSent(params: any): void {
		const reqId = String(params?.requestId ?? "");
		if (!reqId) return;

		const req = params.request ?? {};
		const wallTime = typeof params.wallTime === "number" ? params.wallTime : Date.now() / 1000;
		const startedDateTime = new Date(wallTime * 1000).toISOString();

		// 解析 query string
		const queryString: HarQueryParam[] = [];
		try {
			const u = new URL(req.url);
			u.searchParams.forEach((v, k) => {
				queryString.push({ name: k, value: v });
			});
		} catch {
			/* url 格式不规范时容错 */
		}

		// 解析 headers
		const requestHeaders: HarHeader[] = [];
		if (req.headers && typeof req.headers === "object") {
			for (const [k, v] of Object.entries(req.headers)) {
				requestHeaders.push({ name: k, value: String(v) });
			}
		}

		// 处理请求体 postData
		let postDataText: string | undefined;
		if (req.postData) {
			let text = String(req.postData);
			if (text.length > HAR_MAX_BODY_SIZE) {
				text = text.slice(0, HAR_MAX_BODY_SIZE) + "\n... [truncated at 64KB]";
			}
			postDataText = text;
		}

		const entry: InFlightEntry = {
			requestId: reqId,
			startedDateTime,
			startWallTime: wallTime,
			startTimestamp: Number(params.timestamp ?? 0),
			method: String(req.method ?? "GET"),
			url: String(req.url ?? ""),
			requestHeaders,
			queryString,
			postDataText,
			status: 0,
			statusText: "",
			protocol: "HTTP/1.1",
			responseHeaders: [],
			mimeType: "text/plain",
			responseSize: 0,
		};

		this.entries.set(reqId, entry);
	}

	onResponseReceived(params: any): void {
		const reqId = String(params?.requestId ?? "");
		const entry = this.entries.get(reqId);
		if (!entry) return;

		const resp = params.response ?? {};
		entry.status = Number(resp.status ?? 200);
		entry.statusText = String(resp.statusText ?? "OK");
		entry.protocol = String(resp.protocol ?? "HTTP/1.1");
		entry.mimeType = String(resp.mimeType ?? "text/plain");

		const responseHeaders: HarHeader[] = [];
		if (resp.headers && typeof resp.headers === "object") {
			for (const [k, v] of Object.entries(resp.headers)) {
				responseHeaders.push({ name: k, value: String(v) });
			}
		}
		entry.responseHeaders = responseHeaders;
	}

	onResponseBody(requestId: string, rawBody: string, _base64Encoded = false): void {
		const entry = this.entries.get(requestId);
		if (!entry) return;

		let body = String(rawBody ?? "");
		entry.responseSize = body.length;

		if (body.length > HAR_MAX_BODY_SIZE) {
			body = body.slice(0, HAR_MAX_BODY_SIZE) + "\n... [truncated at 64KB]";
		}
		entry.responseBody = body;
	}

	onLoadingFinished(params: any): void {
		const reqId = String(params?.requestId ?? "");
		const entry = this.entries.get(reqId);
		if (!entry) return;

		entry.endTimestamp = Number(params.timestamp ?? entry.startTimestamp);
		if (params.encodedDataLength && entry.responseSize === 0) {
			entry.responseSize = Number(params.encodedDataLength);
		}
		this.completed.push(entry);
		this.entries.delete(reqId);
	}

	onLoadingFailed(params: any): void {
		const reqId = String(params?.requestId ?? "");
		const entry = this.entries.get(reqId);
		if (!entry) return;

		entry.endTimestamp = Number(params.timestamp ?? entry.startTimestamp);
		entry.errorText = String(params.errorText ?? "Failed");
		this.completed.push(entry);
		this.entries.delete(reqId);
	}

	/** 替身事件注入统一入口 */
	recordCdpEvent(event: string, params: any): void {
		switch (event) {
			case "Network.requestWillBeSent":
				this.onRequestWillBeSent(params);
				break;
			case "Network.responseReceived":
				this.onResponseReceived(params);
				break;
			case "Network.loadingFinished":
				this.onLoadingFinished(params);
				break;
			case "Network.loadingFailed":
				this.onLoadingFailed(params);
				break;
			case "Network.getResponseBodyResult":
				this.onResponseBody(params.requestId, params.body, params.base64Encoded);
				break;
		}
	}

	/** 生成合法的 HAR 1.2 规范对象 */
	buildHar(): any {
		// 包括已完成的和尚未 loadingFinished 的在飞请求
		const allEntries = [...this.completed, ...Array.from(this.entries.values())];

		const harEntries = allEntries.map((e) => {
			const durationMs =
				e.endTimestamp && e.startTimestamp ? Math.max(0, Math.round((e.endTimestamp - e.startTimestamp) * 1000)) : 0;

			return {
				startedDateTime: e.startedDateTime,
				time: durationMs,
				request: {
					method: e.method,
					url: e.url,
					httpVersion: e.protocol,
					cookies: [] as HarCookie[],
					headers: e.requestHeaders,
					queryString: e.queryString,
					headersSize: -1,
					bodySize: e.postDataText ? e.postDataText.length : 0,
					...(e.postDataText
						? {
								postData: {
									mimeType:
										e.requestHeaders.find((h) => h.name.toLowerCase() === "content-type")?.value ?? "text/plain",
									text: e.postDataText,
								},
						  }
						: {}),
				},
				response: {
					status: e.status,
					statusText: e.statusText,
					httpVersion: e.protocol,
					cookies: [] as HarCookie[],
					headers: e.responseHeaders,
					content: {
						size: e.responseSize,
						mimeType: e.mimeType,
						text: e.responseBody ?? "",
					},
					redirectURL: "",
					headersSize: -1,
					bodySize: e.responseSize,
				},
				cache: {},
				timings: {
					send: 0,
					wait: durationMs,
					receive: 0,
				},
			};
		});

		return {
			log: {
				version: "1.2",
				creator: {
					name: "AT1 CDP HAR Recorder",
					version: "1.0.0",
				},
				pages: [],
				entries: harEntries,
			},
		};
	}

	/** 落盘 flush（幂等，保证异常断开也能写入） */
	flush(outputPath: string): void {
		if (this.flushed) return;
		this.flushed = true;
		try {
			mkdirSync(dirname(outputPath), { recursive: true });
			const harJson = JSON.stringify(this.buildHar(), null, 2);
			writeFileSync(outputPath, harJson, "utf-8");
		} catch (e) {
			/* 尽力而为，不破坏异常退出主链 */
			console.error(`HAR flush 失败: ${outputPath}`, e);
		}
	}
}
