import { describe, expect, it, beforeEach, afterAll } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openDb } from "../src/db.js";
import {
	getEdges,
	getNode,
	graphOverview,
	hashEvidence,
	initTask,
	setStepState,
	submitFact,
	submitFinding,
} from "../src/graph.js";
import type { TaskJson } from "../src/task.js";

const dir = mkdtempSync(join(tmpdir(), "at1v4-graph-"));
const db = openDb(join(dir, "t.db"));
const TASK: TaskJson = {
	name: "t1",
	goal: "拿到一个可确认的未授权访问",
	scope: { hosts: ["target.example.com"] },
	seed_steps: [
		{ summary: "探测首页响应特征" },
		{ summary: "验证 GUID 可枚举性", note: "依据 F-012" },
	],
};

beforeEach(() => {
	db.exec("DELETE FROM nodes; DELETE FROM edges; DELETE FROM activity;");
});
afterAll(() => {
	db.close();
	rmSync(dir, { recursive: true, force: true });
});

function writeEvidence(name: string, content = "curl https://target.example.com → 200 OK"): string {
	writeFileSync(join(dir, name), content, "utf-8");
	return name;
}

describe("initTask", () => {
	it("建 root goal + seed steps + dispatch 边；幂等重跑不重复", () => {
		const a = initTask(db, TASK);
		expect(a.stepIds).toHaveLength(2);
		const dispatch = getEdges(db, TASK.name, { src: a.rootGoalId, rel: "dispatch" });
		expect(dispatch).toHaveLength(2);
		expect(dispatch.map((e) => e.dst_id).sort()).toEqual([...a.stepIds].sort());

		const b = initTask(db, TASK);
		expect(b.rootGoalId).toBe(a.rootGoalId);
		expect(b.stepIds).toHaveLength(2);
		const goals = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='goal'").get() as { n: number };
		expect(goals.n).toBe(1);
	});
});

describe("submitFact", () => {
	it("全链：校验→sha256 落列→confirmed→produces 边", () => {
		const { stepIds } = initTask(db, TASK);
		const evidence = writeEvidence("ev1.txt");
		const r = submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: { summary: "首页标题为 Example Domain", evidence, confidence: "observed" },
		});
		expect(r.dedup).toBe(false);
		const node = getNode(db, TASK.name, r.id)!;
		expect(node.kind).toBe("fact");
		expect(node.state).toBe("confirmed");
		expect(node.origin).toBe("worker");
		expect(node.evidence_sha256).toBe(hashEvidence(dir, evidence));
		expect(node.step_id).toBe(stepIds[0]);
		expect(getEdges(db, TASK.name, { src: stepIds[0], dst: r.id, rel: "produces" })).toHaveLength(1);
	});

	it("去重幂等：同 summary（大小写/空白差异）二提返回旧 id，不插新节点", () => {
		const { stepIds } = initTask(db, TASK);
		const evidence = writeEvidence("ev2.txt");
		const a = submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: { summary: "接口 /api/users 无鉴权", evidence, confidence: "observed" },
		});
		const b = submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[1],
			payload: { summary: "接口  /API/Users  无鉴权 ", evidence, confidence: "observed" },
		});
		expect(b.id).toBe(a.id);
		expect(b.dedup).toBe(true);
		const facts = db.prepare("SELECT COUNT(*) AS n FROM nodes WHERE kind='fact'").get() as { n: number };
		expect(facts.n).toBe(1);
	});

	it("evidence 文件不存在 → 拒；step 不存在 → 拒", () => {
		const { stepIds } = initTask(db, TASK);
		expect(() =>
			submitFact(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: { summary: "某事实摘要", evidence: "nope.txt", confidence: "observed" },
			}),
		).toThrow(/证据文件不存在/);
		expect(() =>
			submitFact(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: 999,
				payload: { summary: "某事实摘要", evidence: writeEvidence("ev3.txt"), confidence: "observed" },
			}),
		).toThrow(/step #999 不存在/);
	});
});

describe("submitFinding", () => {
	it("严门 schema → reported → produces + proves 边", () => {
		const { stepIds } = initTask(db, TASK);
		const evidence = writeEvidence("ev4.txt", "GET /admin → 200 user list");
		const fact = submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: { summary: "/admin 未登录可访问", evidence, confidence: "observed" },
		});
		const r = submitFinding(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			relatedFactIds: [fact.id],
			payload: {
				summary: "/admin 未授权访问",
				vulnclass: "越权",
				severity: "high",
				poc: "curl https://target.example.com/admin",
				evidence,
			},
		});
		const node = getNode(db, TASK.name, r.id)!;
		expect(node.state).toBe("reported");
		expect(getEdges(db, TASK.name, { src: stepIds[0], dst: r.id, rel: "produces" })).toHaveLength(1);
		expect(getEdges(db, TASK.name, { src: fact.id, dst: r.id, rel: "proves" })).toHaveLength(1);
	});

	it("缺 poc/severity 非法 → 拒", () => {
		const { stepIds } = initTask(db, TASK);
		const evidence = writeEvidence("ev5.txt");
		expect(() =>
			submitFinding(db, {
				taskId: TASK.name,
				taskDir: dir,
				stepId: stepIds[0],
				payload: { summary: "疑似注入", vulnclass: "SQLi", severity: "low" as never, poc: "", evidence },
			}),
		).toThrow();
	});
});

describe("graphOverview / step 状态", () => {
	it("渲染形状：goal/steps/recent_facts(带 from_step+confidence)/findings/counts", () => {
		const { stepIds, rootGoalId } = initTask(db, TASK);
		const evidence = writeEvidence("ev6.txt");
		submitFact(db, {
			taskId: TASK.name,
			taskDir: dir,
			stepId: stepIds[0],
			payload: { summary: "事实甲已确认可复现", evidence, confidence: "inferred" },
		});
		setStepState(db, TASK.name, stepIds[0], "done");
		const o = graphOverview(db, TASK.name);
		expect(o.goal).toMatchObject({ id: rootGoalId, state: "open" });
		expect(o.steps.find((s) => s.id === stepIds[0])?.state).toBe("done");
		expect(o.recent_facts[0]).toMatchObject({ confidence: "inferred", from_step: stepIds[0] });
		expect(o.counts["edge:dispatch"]).toBe(2);
		expect(o.counts["edge:produces"]).toBe(1);
		const done = getNode(db, TASK.name, stepIds[0])!;
		expect(done.completed_at).toBeTruthy();
	});
});
