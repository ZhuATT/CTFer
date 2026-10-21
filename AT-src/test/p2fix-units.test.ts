/**
 * p2fix 层1 单测（P2F-1/2/4/5/7/8/9/11）——确定性、零 LLM。
 * 存量 39 条在 p2-units/graph/exec 等文件；本文件只进 p2fix 新增。
 */
import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import { addStep, concludeGoal, getNode, goalClosed, initTask, stepLineageView, submitFact, submitFinding } from "../src/graph.js";
import { acquireRunLock, isNodePidAlive, releaseRunLock, runLockPath } from "../src/scheduler.js";
import { initStandards } from "../src/task.js";
import { appendSteer, currentRunningStep, harvestSteers, renderSteerMessage } from "../src/steer.js";
import { createChannelFromConfig } from "../src/channel.js";
import { createPlannerTools } from "../src/planner.js";
import { renderStepPrompt, WORKER_SYSTEM_PROMPT } from "../src/agent.js";
import { PLANNER_SYSTEM_PROMPT, renderPlannerUserMessage } from "../src/planner-prompt.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-p2fix-"));
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

// ── P2F-1 通道接 config ──

describe("P2F-1 通道配置生效", () => {
	it("createChannelFromConfig：model/keyEnv 跟随配置", () => {
		const ch = createChannelFromConfig({ model: "glm-5-max", api: "anthropic", keyEnv: "K_TEST" }, { K_TEST: "sk-xyz" });
		expect(ch.model.id).toBe("glm-5-max");
		expect(ch.model.api).toBe("anthropic-messages");
		expect(ch.apiKey).toBe("sk-xyz");
		expect(ch.mode).toBe("anthropic");
	});

	it("keyEnv 缺失 → 报人话错误", () => {
		expect(() => createChannelFromConfig({ model: "m", api: "openai", keyEnv: "NO_SUCH_KEY_ENV" }, {})).toThrow(/NO_SUCH_KEY_ENV/);
	});
});

// ── P2F-2 noreport endpoint 接通 ──

describe("P2F-2 noreport endpoint 接通", () => {
	it("summary 干净 + endpoint=.js.map → reject 硬拒不入图", () => {
		const { rootGoalId, stepIds } = initTask(db, TASK);
		writeFileSync(join(dir, "sm.txt"), "GET /static/app.js.map → 200 源码");
		expect(() =>
			submitFinding(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: {
					summary: "发现前端打包 sourcemap 文件可直接下载",
					vulnclass: "信息泄露",
					severity: "low",
					poc: "curl http://x.example.com/static/app.js.map",
					evidence: "sm.txt",
					endpoint: "/static/app.js.map",
				},
			}),
		).toThrow(/不报表清单.*sourcemap/);
		// 图上无 finding 落地
		const n = (db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE task_id=? AND kind='finding'").get(TASK.name) as { n: number }).n;
		expect(n).toBe(0);
		void rootGoalId;
	});

	it("豁免顺序不变：实害（凭证形状）先于端点终审", () => {
		const { stepIds } = initTask(db, TASK);
		writeFileSync(join(dir, "cred.txt"), "AKIAIOSFODNN7EXAMPLE 泄露在 sourcemap");
		const r = submitFinding(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: {
				summary: "sourcemap 中泄露 AWS 凭证",
				vulnclass: "凭证泄露",
				severity: "critical",
				poc: "curl http://x.example.com/static/app.js.map | grep AKIA",
				evidence: "cred.txt",
				endpoint: "/static/app.js.map",
			},
		});
		expect(r.id).toBeGreaterThan(0); // 实害豁免放行
	});

	it("无 endpoint 时行为不变（suspect 公诉路径）", () => {
		const { stepIds } = initTask(db, TASK);
		writeFileSync(join(dir, "cors.txt"), "access-control-allow-origin: *");
		const r = submitFinding(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: {
				summary: "CORS 配置为通配符",
				vulnclass: "配置",
				severity: "info",
				poc: "curl -H 'Origin: http://evil.com' http://x.example.com/",
				evidence: "cors.txt",
			},
		});
		expect(r.noreport?.verdict).toBe("suspect");
	});
});

// ── P2F-4 conclude_task 四态 ──

describe("P2F-4 concludeGoal", () => {
	it("合法收尾：无 open step + reason 非空 → closed + completed_at + activity；不落 proves 边", () => {
		const { stepIds } = initTask(db, TASK);
		db.prepare("UPDATE nodes SET state='done' WHERE id=?").run(stepIds[0]);
		concludeGoal(db, { taskId: TASK.name, reason: "方向探尽（见 recent_done #2），再派无价值", sessionId: "s1" });
		const goal = db.prepare("SELECT * FROM nodes WHERE task_id=? AND kind='goal'").get(TASK.name) as { state: string; completed_at: string | null };
		expect(goal.state).toBe("closed");
		expect(goal.completed_at).toBeTruthy();
		expect(goalClosed(db, TASK.name)).toBe(true);
		const proves = db.prepare("SELECT COUNT(*) AS n FROM edges WHERE task_id=? AND rel='proves'").get(TASK.name) as { n: number };
		expect(proves.n).toBe(0); // 收尾不是证明
		const act = db.prepare("SELECT * FROM activity WHERE tool='conclude_task'").get() as { detail: string };
		expect(act.detail).toContain("探尽");
	});

	it("有 open step → 拒（无权宣判终局）", () => {
		initTask(db, TASK); // seed step 保持 open
		expect(() => concludeGoal(db, { taskId: TASK.name, reason: "想收" })).toThrow(/无权宣判终局/);
	});

	it("有 running step → 同拒", () => {
		const { stepIds } = initTask(db, TASK);
		db.prepare("UPDATE nodes SET state='running' WHERE id=?").run(stepIds[0]);
		expect(() => concludeGoal(db, { taskId: TASK.name, reason: "想收" })).toThrow(/无权宣判终局/);
		db.prepare("UPDATE nodes SET state='open' WHERE id=?").run(stepIds[0]);
	});

	it("重复收尾拒 / 空 reason 拒", () => {
		const { stepIds } = initTask(db, TASK);
		db.prepare("UPDATE nodes SET state='done' WHERE id=?").run(stepIds[0]);
		concludeGoal(db, { taskId: TASK.name, reason: "第一次收尾" });
		expect(() => concludeGoal(db, { taskId: TASK.name, reason: "再来一次" })).toThrow(/不能重复收尾/);
		// 复位后空 reason 拒
		db.prepare("UPDATE nodes SET state='open' WHERE kind='goal'").run();
		expect(() => concludeGoal(db, { taskId: TASK.name, reason: "  " })).toThrow(/reason 必填/);
	});
});

// ── P2F-5 run.lock ──

describe("P2F-5 run.lock 三态", () => {
	it("isNodePidAlive：自身活 / 不存在 pid 死", () => {
		expect(isNodePidAlive(process.pid)).toBe(true);
		expect(isNodePidAlive(999_999_999)).toBe(false);
	});

	it("锁三态：活锁拒（报 pid）→ 死锁接管 → 释放删锁", () => {
		const tdir = join(dir, "lock-t");
		mkdirSync(join(tdir, "control"), { recursive: true });
		// ① 活锁（当前测试进程 pid 即 node.exe）→ 拒
		writeFileSync(runLockPath(tdir), JSON.stringify({ pid: process.pid, started: "x" }));
		expect(() => acquireRunLock(tdir)).toThrow(/拒绝双开/);
		expect(() => acquireRunLock(tdir)).toThrow(/pid=/); // 报错带 pid
		// ② 死锁 → 接管（覆写为己有）
		writeFileSync(runLockPath(tdir), JSON.stringify({ pid: 999_999_999, started: "x" }));
		const lock = acquireRunLock(tdir);
		expect(lock.pid).toBe(process.pid);
		// ③ 释放：锁删除；他人锁不误删
		releaseRunLock(tdir);
		expect(existsSync(runLockPath(tdir))).toBe(false);
		writeFileSync(runLockPath(tdir), JSON.stringify({ pid: 1, started: "x" })); // pid=1 非自己
		releaseRunLock(tdir);
		expect(existsSync(runLockPath(tdir))).toBe(true); // 没删别人的
		rmSync(runLockPath(tdir), { force: true });
	});
});

// ── P2F-7 精简态势 + 阴性句 ──

describe("P2F-7 worker 态势瘦身", () => {
	it("stepLineageView：只含血缘链 facts，不含全图 steps/findings 明细", () => {
		const { rootGoalId, stepIds } = initTask(db, TASK);
		const s1 = stepIds[0];
		writeFileSync(join(dir, "ev.txt"), "curl → 200");
		const f1 = submitFact(db, { taskId: TASK.name, taskDir: dir, stepId: s1, payload: { summary: "首页无鉴权墙直出用户列表", evidence: "ev.txt", confidence: "observed" } });
		const [s2] = addStep(db, TASK.name, [{ summary: "沿用户接口查越权读取", parent_ids: [f1.id] }]).accepted.map((a) => a.id);
		const f2 = submitFact(db, { taskId: TASK.name, taskDir: dir, stepId: s2, payload: { summary: "改 id 参数可读他人订单", evidence: "ev.txt", confidence: "observed" } });

		const view = stepLineageView(db, TASK.name, getNode(db, TASK.name, s2)!);
		expect(view.goal?.id).toBe(rootGoalId);
		expect(view.lineage_facts.map((f) => f.id)).toEqual([f1.id, f2.id]); // 血缘两跳都在
		expect(view.counts["fact"]).toBe(2);
		// 形状上没有全图字段
		expect(view).not.toHaveProperty("steps");
		expect(view).not.toHaveProperty("findings");

		// 无关分支的 fact 不进血缘：造第二个独立 step+fact
		const [s3] = addStep(db, TASK.name, [{ summary: "旁路方向独立探测一下" }]).accepted.map((a) => a.id);
		submitFact(db, { taskId: TASK.name, taskDir: dir, stepId: s3, payload: { summary: "旁路方向的独立观察记录", evidence: "ev.txt", confidence: "observed" } });
		const view2 = stepLineageView(db, TASK.name, getNode(db, TASK.name, s2)!);
		expect(view2.lineage_facts.map((f) => f.id)).toEqual([f1.id, f2.id]); // 不串
	});

	it("renderStepPrompt：精简态势 + 阴性句 + standards 索引节", () => {
		const { stepIds } = initTask(db, TASK);
		const step = getNode(db, TASK.name, stepIds[0])!;
		const view = stepLineageView(db, TASK.name, step);
		const withIdx = renderStepPrompt(step, view, "- 小米.txt——MiSRC 评级细则");
		expect(withIdx).toContain("【standards 索引】");
		expect(withIdx).toContain("MiSRC");
		const without = renderStepPrompt(step, view);
		expect(without).not.toContain("standards 索引");
		// 阴性出口句（审6）
		expect(without).toContain("结果全阴性");
		expect(without).toContain("别空手收尾");
		// 精简：不含 planner 视野的全量字段
		expect(without).not.toContain('"steps"');
		expect(without).not.toContain('"recent_facts"');
		expect(without).not.toContain('"findings"');
		// 开工引导句（P2F-8）
		expect(without).toContain("查阅 standards/");
	});

	it("worker 系统 prompt 含 steer 插话纪律句（P2F-11）", () => {
		expect(WORKER_SYSTEM_PROMPT).toContain("操作员插话");
		expect(WORKER_SYSTEM_PROMPT).toContain("不自开新方向");
	});
});

// ── P2F-8 standards/ 机制 ──

describe("P2F-8 initStandards", () => {
	it("拷贝 + INDEX.md 生成；幂等（二次不覆写）", () => {
		const src = join(dir, "std-src");
		mkdirSync(src, { recursive: true });
		writeFileSync(join(src, "小米.txt"), "小米评级细则内容");
		writeFileSync(join(src, "美团.txt"), "美团评级细则内容");
		const tdir = join(dir, "std-task");
		mkdirSync(tdir, { recursive: true });

		initStandards(tdir, src);
		expect(readFileSync(join(tdir, "standards", "小米.txt"), "utf-8")).toContain("小米评级细则");
		const idx = readFileSync(join(tdir, "standards", "INDEX.md"), "utf-8");
		expect(idx).toContain("小米.txt");
		expect(idx).toContain("美团.txt");

		// 幂等：改快照后二次 init 不覆写（历史 task 保持创建时快照）
		writeFileSync(join(tdir, "standards", "小米.txt"), "任务侧已修改");
		initStandards(tdir, src);
		expect(readFileSync(join(tdir, "standards", "小米.txt"), "utf-8")).toBe("任务侧已修改");
	});

	it("无源可拷 → 不落半空目录", () => {
		const tdir = join(dir, "std-empty");
		mkdirSync(tdir, { recursive: true });
		initStandards(tdir, join(dir, "no-such-src"));
		expect(existsSync(join(tdir, "standards"))).toBe(false);
	});
});

// ── P2F-9 rejectedCount ──

describe("P2F-9 rejectedCount 回填", () => {
	it("add_step 闭包计数器：拒收条数回传", async () => {
		initTask(db, TASK);
		const accepted = { n: 0 };
		const rejected = { n: 0 };
		const tools = createPlannerTools({ db, taskId: TASK.name, taskDir: dir, sessionId: "s", acceptedCounter: accepted, rejectedCounter: rejected });
		const addStepTool = tools.find((t) => t.name === "add_step")!;
		await addStepTool.execute!("1", { steps: [{ summary: "探测登录接口鉴权面" }] });
		expect(accepted.n).toBe(1);
		// 同义重派 → 拒（归一化精确匹配）
		await addStepTool.execute!("2", { steps: [{ summary: "探测登录接口鉴权面" }, { summary: "全新独立方向足够长" }] });
		expect(rejected.n).toBe(1);
		expect(accepted.n).toBe(2);
	});
});

// ── P2F-11 steer 通道（文件侧） ──

describe("P2F-11 steer 文件通道", () => {
	it("追加→收割→不重放；偏移独立于 hints", () => {
		const tdir = join(dir, "steer-t");
		mkdirSync(tdir, { recursive: true });
		expect(harvestSteers(tdir)).toHaveLength(0);
		appendSteer(tdir, "补一句：试试 XFF", 7);
		const got = harvestSteers(tdir);
		expect(got).toHaveLength(1);
		expect(got[0]).toMatchObject({ text: "补一句：试试 XFF", stepId: 7 });
		expect(harvestSteers(tdir)).toHaveLength(0); // 偏移推进
	});

	it("renderSteerMessage 模板：情报补充语义，非新任务", () => {
		const m = renderSteerMessage("试试 X-Forwarded-For");
		expect(m).toContain("【操作员插话】");
		expect(m).toContain("不是新任务");
	});

	it("currentRunningStep：running 有则取、无则 undefined", () => {
		const { stepIds } = initTask(db, TASK);
		expect(currentRunningStep(db, TASK.name)).toBeUndefined();
		db.prepare("UPDATE nodes SET state='running' WHERE id=?").run(stepIds[0]);
		expect(currentRunningStep(db, TASK.name)?.id).toBe(stepIds[0]);
	});
});

// ── prompt 快照（字节级关键词断言） ──

describe("p2fix prompt 快照", () => {
	it("planner v1.2 落位：决策流程式 + conclude 出口 + 方案 C 语义", () => {
		expect(PLANNER_SYSTEM_PROMPT).toContain("每次被唤醒 = 系统有新变动要你消化");
		expect(PLANNER_SYSTEM_PROMPT).toContain("4. 定产出");
		expect(PLANNER_SYSTEM_PROMPT).toContain("0 派收工，合法");
		expect(PLANNER_SYSTEM_PROMPT).toContain("组合扫描");
		// v1 死文字已删
		expect(PLANNER_SYSTEM_PROMPT).not.toContain("硬底线");
		expect(PLANNER_SYSTEM_PROMPT).not.toContain("停摆");
	});

	it("user 骨架：字段导读两行（审9）+ 收官判定变体", () => {
		const out = renderPlannerUserMessage({
			triggers: "t",
			overviewJson: "{}",
			todosText: "",
			goalText: "g",
			stalled: true,
		});
		expect(out).toContain("字段导读：steps=全量含 note");
		expect(out).toContain("edge:* 为边计数");
		expect(out).toContain("【本轮模式】收官判定：图上已无待办 step");
	});
});
