/**
 * task 布局（P1-0）：v4/tasks/<name>/ —— task.json + graph.db + evidence/。
 *
 * task.json：goal 文本 + scope.hosts 白名单；seed_steps 仅测试夹具用（D2 拍板：
 * 生产留空——初始 step 是 P2 planner 的职责）。
 */
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";

export const TaskJson = z.object({
	name: z.string().min(1).max(80),
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

export function taskDir(tasksRoot: string, name: string): string {
	// 任务名做目录片段防逃逸
	if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error(`非法 task 名：${name}`);
	return resolve(tasksRoot, name);
}

export function loadTask(tasksRoot: string, name: string): { task: TaskJson; dir: string; dbPath: string } {
	const dir = taskDir(tasksRoot, name);
	const jsonPath = join(dir, "task.json");
	if (!existsSync(jsonPath)) throw new Error(`task 不存在：${jsonPath}`);
	const parsed = TaskJson.safeParse(JSON.parse(readFileSync(jsonPath, "utf-8")));
	if (!parsed.success) {
		const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
		throw new Error(`task.json 不合规（${name}）：${issues}`);
	}
	mkdirSync(join(dir, "evidence"), { recursive: true });
	return { task: parsed.data, dir, dbPath: join(dir, "graph.db") };
}
