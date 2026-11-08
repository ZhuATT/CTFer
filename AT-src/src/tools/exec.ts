/**
 * worker 基础工具（P1-2）：Bash / Read / Write——工作目录限制在 task 目录内。
 *
 * - Bash：bash -c（渗透命令需要 bash 语义），cwd=task 目录，超时+输出截断；
 * - Read/Write：路径守卫——resolve 后必须落在 task 目录内（防 ../ 逃逸），
 *   相对路径一律相对 task 根；证据文件约定放 evidence/。
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Type } from "@earendil-works/pi-ai";
import type { AgentTool } from "@earendil-works/pi-agent-core";

const BASH_TIMEOUT_MS_DEFAULT = 60_000;
const BASH_TIMEOUT_MS_MAX = 300_000;
const BASH_OUTPUT_MAX = 8_000; // LLM-facing 截断
const READ_MAX_BYTES = 64_000;

/** 知识库物理根：src/tools 与 dist/tools 同深度，../../ 均回 AT-src（F-2 同源） */
const KNOWLEDGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../knowledge");
const KNOWLEDGE_PREFIX = "knowledge/";

/** 路径守卫：相对 task 目录解析后必须仍在 task 目录内。返回绝对路径。 */
export function resolveInside(taskDir: string, relPath: string): string {
	if (typeof relPath !== "string" || relPath.trim() === "") throw new Error("path 必填");
	const abs = resolve(taskDir, relPath);
	if (abs !== taskDir && !abs.startsWith(taskDir + sep)) {
		throw new Error(`路径逃逸 task 目录（拒绝）：${relPath}`);
	}
	return abs;
}

/** 知识库路径解析（F-1）：剥 knowledge/ 前缀 → 对物理根解析 + 包含性校验，防 knowledge/../../ 逃逸。 */
function resolveKnowledgePath(p: string): string {
	const rest = p.slice(KNOWLEDGE_PREFIX.length);
	const abs = resolve(KNOWLEDGE_ROOT, rest);
	if (abs !== KNOWLEDGE_ROOT && !abs.startsWith(KNOWLEDGE_ROOT + sep)) {
		throw new Error(`知识库路径逃逸（拒绝）：${p}`);
	}
	return abs;
}

function textResult(text: string) {
	return { content: [{ type: "text" as const, text }], details: null };
}

export function createBashTool(taskDir: string): AgentTool<any> {
	return {
		name: "Bash",
		label: "Bash",
		description: [
			"在 task 工作目录内执行 bash 命令。curl 就绪（管道/grep 可用）；nmap/dig/nc 未预装——端口/服务探测用 curl 等价实现（如 `curl --connect-timeout 3 http://host:port/` 探活），确需 nmap 时提示平台安装。",
			"纪律：只做领到的 step 范围内的动作；scope 外 host 会被平台拦截；破坏性命令被禁止。",
			"超时默认 60s（参数可到 300s）；输出超 8000 字符截断。",
		].join("\n"),
		parameters: Type.Object({
			command: Type.String({ description: "要执行的 bash 命令" }),
			timeout_ms: Type.Optional(Type.Number({ description: "超时毫秒，默认 60000，上限 300000" })),
		}),
		execute: async (_id, params: any) => {
			const command = String(params?.command ?? "");
			if (!command.trim()) throw new Error("command 必填");
			const timeout = Math.min(Number(params?.timeout_ms) || BASH_TIMEOUT_MS_DEFAULT, BASH_TIMEOUT_MS_MAX);
			const { code, stdout, stderr, killed } = await new Promise<{
				code: number | null;
				stdout: string;
				stderr: string;
				killed: boolean;
			}>((res) => {
				const child = spawn("bash", ["-c", command], { cwd: taskDir, windowsHide: true });
				let out = "";
				let err = "";
				let wasKilled = false;
				const timer = setTimeout(() => {
					wasKilled = true;
					child.kill("SIGKILL");
				}, timeout);
				child.stdout.on("data", (d) => (out += String(d)));
				child.stderr.on("data", (d) => (err += String(d)));
				child.on("error", (e) => {
					clearTimeout(timer);
					res({ code: null, stdout: out, stderr: `${err}\nspawn-error: ${e.message}`, killed: wasKilled });
				});
				child.on("close", (c) => {
					clearTimeout(timer);
					res({ code: c, stdout: out, stderr: err, killed: wasKilled });
				});
			});
			const trunc = (s: string) =>
				s.length > BASH_OUTPUT_MAX ? `${s.slice(0, BASH_OUTPUT_MAX)}\n…（截断，原文 ${s.length} 字符）` : s;
			const parts = [`exit: ${killed ? "timeout-killed" : code ?? "error"}`];
			if (stdout.trim()) parts.push(`stdout:\n${trunc(stdout)}`);
			if (stderr.trim()) parts.push(`stderr:\n${trunc(stderr)}`);
			return textResult(parts.join("\n"));
		},
	};
}

export function createReadTool(taskDir: string): AgentTool<any> {
	return {
		name: "Read",
		label: "Read",
		description:
			"读文件。task 内相对路径（如 evidence/probe.txt）；知识库文件用 knowledge/ 前缀（如 knowledge/skills/ad-attacks.md）。默认整读（超 64KB 截断）；长文件给 offset/limit 按行窗口读（1-based 行号，输出带行号前缀，如 offset=412 limit=50）。",
		parameters: Type.Object({
			path: Type.String({ description: "task 目录内相对路径，或 knowledge/ 前缀的知识库路径" }),
			offset: Type.Optional(Type.Number({ description: "1-based 起始行号" })),
			limit: Type.Optional(Type.Number({ description: "读取行数，默认 100" })),
		}),
		execute: async (_id, params: any) => {
			const p = String(params?.path ?? "");
			// F-1 双根：knowledge/ 前缀 → 全局知识库物理根；否则 task 目录（Write/Bash 无 knowledge 分支=结构性只读）
			const abs = p.startsWith(KNOWLEDGE_PREFIX) ? resolveKnowledgePath(p) : resolveInside(taskDir, p);
			if (!existsSync(abs)) throw new Error(`文件不存在：${p}`);
			if (!statSync(abs).isFile()) throw new Error(`不是文件：${p}`);
			// 行窗口分支（offset 或 limit 任一给出）：整载切行，输出带行号前缀
			if (params?.offset !== undefined || params?.limit !== undefined) {
				const lines = readFileSync(abs, "utf-8").split(/\r?\n/);
				const total = lines.length;
				const start = Math.max(1, Number(params?.offset) || 1);
				const limit = Math.max(1, Number(params?.limit) || 100);
				if (start > total) throw new Error(`offset 超出文件末尾（共 ${total} 行）`);
				const end = Math.min(total, start + limit - 1);
				const body = lines
					.slice(start - 1, end)
					.map((line, i) => `L${start + i}| ${line}`)
					.join("\n");
				return textResult(`${p}: L${start}-L${end}（全文 ${total} 行）\n${body}`);
			}
			// 整读分支：64KB 截断现状不变（evidence 小文件场景）
			const buf = readFileSync(abs);
			const body = buf.length > READ_MAX_BYTES ? `${buf.subarray(0, READ_MAX_BYTES).toString("utf-8")}\n…（截断，共 ${buf.length} 字节）` : buf.toString("utf-8");
			return textResult(`${p} (${buf.length}B):\n${body}`);
		},
	};
}

export function createWriteTool(taskDir: string): AgentTool<any> {
	return {
		name: "Write",
		label: "Write",
		description:
			"写文件到 task 目录内（相对路径；父目录自动创建）。证据文件写 evidence/ 下——submit_fact/submit_finding 的 evidence 引用这些路径。",
		parameters: Type.Object({
			path: Type.String({ description: "task 目录内相对路径，建议 evidence/<名字>.txt" }),
			content: Type.String({ description: "文件内容" }),
		}),
		execute: async (_id, params: any) => {
			const abs = resolveInside(taskDir, String(params?.path ?? ""));
			const content = String(params?.content ?? "");
			mkdirSync(dirname(abs), { recursive: true });
			writeFileSync(abs, content, "utf-8");
			return textResult(`已写入 ${params?.path}（${Buffer.byteLength(content)}B）`);
		},
	};
}
