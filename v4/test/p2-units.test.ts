import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { addStep, getNode, goalAchieved, initTask, proveGoal, submitFact } from "../src/graph.js";
import { renderTriggers, type TriggerEvent } from "../src/triggers.js";
import { noreportCheck } from "../src/noreport.js";
import { loadConfig, parseSimpleYaml } from "../src/config.js";
import { appendHint, harvestHints } from "../src/hints.js";
import { readControlStop, clearControl } from "../src/scheduler.js";
import { renderPlannerUserMessage, PLANNER_SYSTEM_PROMPT } from "../src/planner-prompt.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-p2-"));
const db = openDb(join(dir, "t.db"));
const TASK = {
	name: "t1",
	goal: "确认至少一个越权读取",
	scope: { hosts: ["x.example.com"] },
	seed_steps: [{ summary: "探测首页鉴权面" }],
};

beforeEach(() => {
	db.exec("DELETE FROM nodes; DELETE FROM edges; DELETE FROM activity;");
});
afterAll(() => {
	db.close();
	try {
		rmSync(dir, { recursive: true, force: true });
	} catch {
		/* Windows 句柄延迟释放——tmp 目录留给 OS */
	}
});

describe("renderTriggers（P2-0）", () => {
	it("六类事件各有形状；空=心跳巡检文案", () => {
		const events: TriggerEvent[] = [
			{ type: "step_done", stepId: 2, summary: "探测首页", outcome: "done", conclusion: "标题 Example", newFactIds: [4], findingIds: [] },
			{ type: "finding", findingId: 7, severity: "high", summary: "越权读取" },
			{ type: "goal_changed", action: "edited", text: "新目标" },
			{ type: "hint", text: "重点看 /user/profile" },
			{ type: "resume", nodeCount: 12 },
			{ type: "stall" },
		];
		const text = renderTriggers(events);
		expect(text).toContain("先看这里");
		expect(text).toContain("step #2 [done]");
		expect(text).toContain("新 fact: #4");
		expect(text).toContain("finding #7 [high]");
		expect(text).toContain("目标修改");
		expect(text).toContain("操作员插入一条指示");
		expect(text).toContain("续跑恢复");
		expect(text).toContain("停摆强制");
		expect(renderTriggers([])).toContain("心跳巡检");
	});

	it("开场白二变体：stalled 带硬提示", () => {
		const base = { triggers: "x", overviewJson: "{}", todosText: "", goalText: "g" };
		expect(renderPlannerUserMessage({ ...base, stalled: false })).not.toContain("停摆强制");
		expect(renderPlannerUserMessage({ ...base, stalled: true })).toContain("本轮必须产出至少 1 条");
		expect(PLANNER_SYSTEM_PROMPT).toContain("硬底线");
	});
});

describe("add_step 拒重（D3）", () => {
	it("同 summary open 二派被拒；批量内部分拒部分收；done 不触发拒", () => {
		initTask(db, TASK);
		const r1 = addStep(db, TASK.name, [{ summary: "探测 登录接口鉴权" }]);
		expect(r1.accepted).toHaveLength(1);
		const r2 = addStep(db, TASK.name, [
			{ summary: "  探测  登录接口鉴权  " }, // 归一化（trim+空白折叠+小写）后同 → 拒
			{ summary: "扫描目录列表页" }, // 新 → 收
		]);
		expect(r2.rejected).toHaveLength(1);
		expect(r2.accepted.map((a) => a.summary)).toEqual(["扫描目录列表页"]);

		// 把 r1 那条置 done 后，同 summary 可再派（done 不在拦截面）
		db.prepare("UPDATE nodes SET state='done' WHERE id=?").run(r1.accepted[0].id);
		const r3 = addStep(db, TASK.name, [{ summary: "探测 登录接口鉴权", note: "新机理：换 token 才有效" }]);
		expect(r3.rejected).toHaveLength(0);
		expect(r3.accepted).toHaveLength(1);
	});

	it(">4 条整批拒（工具面限额）；parent 不存在抛错", () => {
		initTask(db, TASK);
		expect(() => addStep(db, TASK.name, [1, 2, 3, 4, 5].map((i) => ({ summary: `方向${i}足够长` })))).toThrow(/最多 4 条/);
		expect(() => addStep(db, TASK.name, [{ summary: "带血缘的方向足够长", parent_ids: [999] }])).toThrow(/#999 不存在/);
	});
});

describe("prove_goal（D7）", () => {
	it("evidence 非 fact 拒 / goal 已 achieved 拒 / 合法路径 achieved+proves 边", () => {
		const { rootGoalId, stepIds } = initTask(db, TASK);
		writeFileSync(join(dir, "ev.txt"), "curl → 200");
		const fact = submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: { summary: "已确认越权读取用户列表", evidence: "ev.txt", confidence: "observed" },
		});
		expect(() =>
			proveGoal(db, { taskId: TASK.name, goalId: rootGoalId, evidenceId: stepIds[0], reason: "挂 step 当证据" }),
		).toThrow(/必须是图内 fact/);
		proveGoal(db, { taskId: TASK.name, goalId: rootGoalId, evidenceId: fact.id, reason: "fact 证实越权读取" });
		expect(goalAchieved(db, TASK.name)).toBe(true);
		expect(() =>
			proveGoal(db, { taskId: TASK.name, goalId: rootGoalId, evidenceId: fact.id, reason: "重复盖章" }),
		).toThrow(/已是 achieved/);
		const proves = db
			.prepare("SELECT * FROM edges WHERE task_id=? AND rel='proves' AND dst_id=?")
			.all(TASK.name, rootGoalId);
		expect(proves).toHaveLength(1);
	});
});

describe("noreport（P2-4）", () => {
	it(".map 端点 reject；凭证实害豁免放行；suspect 带公诉意见", () => {
		expect(noreportCheck({ summary: "发现 sourcemap 可下载", endpoint: "/static/app.js.map" }).verdict).toBe("reject");
		expect(noreportCheck({ summary: "裸 instance-id i-0abc1234def567890 可读", evidence: "metadata 内网" }).verdict).toBe("reject");
		expect(
			noreportCheck({ summary: "实例元数据里泄露凭证 sk-abcdefghijklmnopqrstuv", evidence: "凭证明文" }).verdict,
		).toBe("pass"); // 凭证形状 → 实害豁免
		const cors = noreportCheck({ summary: "CORS 配置为 *", evidence: "access-control-allow-origin: *" });
		expect(cors.verdict).toBe("suspect");
		expect(cors.reason).toContain("除非");
		expect(noreportCheck({ summary: "越权读取全部用户数据", evidence: "无特殊形状" }).verdict).toBe("pass");
	});
});

describe("config.yaml（P2-5）", () => {
	it("缺省/覆写/half 配置", () => {
		expect(loadConfig("/nonexistent.yaml").channels.planner.model).toBe("glm-5.3");
		const p = join(dir, "cfg.yaml");
		writeFileSync(p, "channels:\n  planner: { model: glm-5-max, api: anthropic }\nrun: { maxRounds: 5 }\n");
		const cfg = loadConfig(p);
		expect(cfg.channels.planner).toMatchObject({ model: "glm-5-max", api: "anthropic" });
		expect(cfg.channels.worker.model).toBe("glm-5.3"); // 未配置回落默认
		expect(cfg.run.maxRounds).toBe(5);
		expect(cfg.run.budgetMs).toBe(3_600_000);
	});

	it("parseSimpleYaml 行内对象+嵌套块+类型推定", () => {
		const y = parseSimpleYaml("channels:\n  worker: { model: m1, maxRounds: 7, flag: true }\nrun: { budgetMs: 60 }\n");
		expect(y.channels.worker).toEqual({ model: "m1", maxRounds: 7, flag: true });
		expect(y.run.budgetMs).toBe(60);
	});
});

describe("hints 收割偏移（P2-6）", () => {
	it("追加→收割→不重放；多条按序", () => {
		const tdir = join(dir, "hints-t");
		mkdirSync(tdir, { recursive: true });
		expect(harvestHints(tdir)).toHaveLength(0);
		appendHint(tdir, "第一条指示");
		appendHint(tdir, "第二条指示");
		const h1 = harvestHints(tdir);
		expect(h1.map((e) => (e as { text: string }).text)).toEqual(["第一条指示", "第二条指示"]);
		expect(harvestHints(tdir)).toHaveLength(0); // 偏移推进，不重放
		appendHint(tdir, "第三条");
		const h2 = harvestHints(tdir);
		expect(h2).toHaveLength(1);
	});
});

describe("CONTROL stop（P2-3）", () => {
	it("置位检出/清除后放行", () => {
		const tdir = join(dir, "ctl-t");
		mkdirSync(join(tdir, "control"), { recursive: true });
		expect(readControlStop(tdir)).toBe(false);
		writeFileSync(join(tdir, "control", "stop"), "cmd=stop\n");
		expect(readControlStop(tdir)).toBe(true);
		clearControl(tdir);
		expect(existsSync(join(tdir, "control", "stop"))).toBe(false);
	});
});

describe("启动清扫（P2-3）", () => {
	it("running→exhausted 语句语义（scheduler 进循环前执行，此处验证 SQL 效果）", () => {
		initTask(db, TASK);
		const { stepIds } = initTask(db, TASK);
		db.prepare("UPDATE nodes SET state='running' WHERE id=?").run(stepIds[0]);
		db.prepare(
			"UPDATE nodes SET state='exhausted', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE task_id=? AND kind='step' AND state='running'",
		).run(TASK.name);
		const row = getNode(db, TASK.name, stepIds[0])!;
		expect(row.state).toBe("exhausted");
		expect(row.completed_at).toBeNull(); // exhausted 不落 completed（接续跑语义）
	});
});
