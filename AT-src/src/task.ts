/**
 * task 布局（P1-0 / p2fix P2F-8）：v4/tasks/<name>/ —— task.json + graph.db + evidence/ + standards/。
 *
 * task.json：goal 文本 + scope.hosts 白名单；seed_steps 仅测试夹具用（D2 拍板：
 * 生产留空——初始 step 是 P2 planner 的职责）。
 * standards/（D4）：agent 参考资料唯一目录，init 时从仓库 src标准/ 拷快照
 * （幂等——历史 task 保持创建时快照）；INDEX.md = 渐进披露索引。
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export const TaskJson = z.object({
	name: z.string().min(1).max(80),
	project: z.string().regex(/^[a-zA-Z0-9._-]+$/, "非法 project 名").optional(),
	goal: z.string().min(4),
	scope: z.object({ hosts: z.array(z.string().min(1)).min(1) }),
	seed_steps: z
		.array(
			z.object({
				summary: z.string().min(4),
				note: z.string().optional(),
			}),
		)
		.optional(),
});
export type TaskJson = z.infer<typeof TaskJson>;

export function projectDir(tasksRoot: string, project: string): string {
	if (!/^[a-zA-Z0-9._-]+$/.test(project)) throw new Error(`非法 project 名：${project}`);
	return resolve(tasksRoot, "..", "projects", project);
}

export function taskDir(tasksRoot: string, name: string): string {
	// 任务名做目录片段防逃逸
	if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error(`非法 task 名：${name}`);
	return resolve(tasksRoot, name);
}

export function loadTask(
	tasksRoot: string,
	name: string,
): { task: TaskJson; dir: string; dbPath: string; assetsDbPath?: string } {
	const dir = taskDir(tasksRoot, name);
	const jsonPath = join(dir, "task.json");
	if (!existsSync(jsonPath)) throw new Error(`task 不存在：${jsonPath}`);
	const parsed = TaskJson.safeParse(JSON.parse(readFileSync(jsonPath, "utf-8")));
	if (!parsed.success) {
		const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
		throw new Error(`task.json 不合规（${name}）：${issues}`);
	}
	mkdirSync(join(dir, "evidence"), { recursive: true });
	initStandards(dir);
	let assetsDbPath: string | undefined;
	if (parsed.data.project) {
		const pDir = projectDir(tasksRoot, parsed.data.project);
		mkdirSync(pDir, { recursive: true });
		assetsDbPath = join(pDir, "assets.db");
	}
	return { task: parsed.data, dir, dbPath: join(dir, "graph.db"), assetsDbPath };
}

// ── standards/（p2fix P2F-8，D4：agent 参考资料唯一目录） ──

const HERE = dirname(fileURLToPath(import.meta.url));
/** 源目录：仓库根 src标准/（src 与 dist 各上两级都落仓库根）。 */
const STANDARDS_SRC = join(HERE, "..", "..", "src标准");

/** 五份厂商评级细则（本批落 txt）。用户后续提供 skills 手册时拷入同目录并在
 * INDEX_LINES 挂一行——渐进披露索引的唯一登记处。 */
const STANDARDS_FILES: Array<{ file: string; desc: string }> = [
	{ file: "小米.txt", desc: "小米安全响应中心（MiSRC）漏洞评级细则——业务/公司/用户三类数据定级基准" },
	{ file: "美团.txt", desc: "美团安全应急响应中心（MTSRC）漏洞评分标准——严重/高危/中危/低危分级" },
	{ file: "腾讯.txt", desc: "腾讯安全应急响应中心（TSRC）漏洞处理和评分标准" },
	{ file: "菜鸟.txt", desc: "菜鸟安全响应中心漏洞评级细则——按严重等级分节" },
	{ file: "阿里云.txt", desc: "阿里云安全响应中心漏洞评级细则——按严重等级分节" },
];

/** init standards/：不存在 → 拷源文件 + 生成 INDEX.md；已存在 → 跳过（幂等，
 * 历史 task 保持创建时快照——源更新不回流旧任务）。源缺失时静默跳过（单测夹具无源）。 */
export function initStandards(taskDirPath: string, srcRoot = STANDARDS_SRC): void {
	const dst = join(taskDirPath, "standards");
	if (existsSync(dst)) return;
	mkdirSync(dst, { recursive: true }); // 先建目录——copyFileSync 不自动建父目录
	try {
		const indexLines: string[] = ["# standards 索引", ""];
		let copied = 0;
		for (const { file, desc } of STANDARDS_FILES) {
			const src = join(srcRoot, file);
			if (!existsSync(src)) continue;
			copyFileSync(src, join(dst, file));
			indexLines.push(`- ${file}——${desc}`);
			copied += 1;
		}
		if (copied === 0) {
			rmSync(dst, { recursive: true, force: true }); // 无源可拷——不落半空目录
			return;
		}
		indexLines.push("", "（severity 定级拿不准时按需 Read/Grep 对应手册，不全量读。）");
		writeFileSync(join(dst, "INDEX.md"), indexLines.join("\n") + "\n", "utf-8");
	} catch {
		/* standards 是参考件不是命脉——拷贝失败不挡 task 启动 */
	}
}
