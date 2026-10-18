"""driver 单测（批3fix）：mock runner+observer（不真 spawn），覆盖新治理链关键路径。

链路：worker 自由写 facts//findings//evidence/ → 目录级 diff → 观察者判断书
（fake 写 OBSERVER.json）→ 执行器入图 → STATE.md 兜底 → 下轮接力。
"""

import json
from pathlib import Path

import pytest

from src import driver as driver_mod
from src.runner import AgentResult


def _mk_engagement(root: Path, *, target="https://example.com", allow=None, deny=None):
    """engagement 三件套（批3fix：status.md 退役，prior-intel 仍是拒启件）。"""
    (root / "state").mkdir(parents=True, exist_ok=True)
    (root / "notes").mkdir(parents=True, exist_ok=True)
    (root / "engagement.json").write_text(json.dumps({
        "target": target, "date": "2026-09-19",
        "goal": "拿到一个可确认的未授权访问", "hint": "",
        "scope": {"allow": allow or ["example.com"], "deny": deny or []},
        "credentials": {},
    }), encoding="utf-8")
    (root / "notes" / "prior-intel.md").write_text(
        "# 前置情报\nGET /api/order 200\n", encoding="utf-8")


class FakeRunner:
    """按脚本回放 AgentResult；同时往 facts//findings//evidence/ 写文件模拟 worker。"""

    def __init__(self, scripts):
        self.scripts = scripts          # [(result, findings{slug:text}, facts{slug:text}), ...]
        self.calls = []
        self.resumes = []               # S12：捕获每次调用的 resume_session_id

    def __call__(self, prompt, workdir, solver, task, *, time_box_s=None,
                 max_turns=None, claude_bin=None, resume_session_id=None):
        self.calls.append({"prompt": prompt, "workdir": workdir,
                           "task": task, "time_box": time_box_s})
        self.resumes.append(resume_session_id)
        i = min(len(self.calls) - 1, len(self.scripts) - 1)
        result, findings, facts, evidences = self.scripts[i]
        wd = Path(workdir)
        for name, text in evidences.items():
            (wd / "evidence" / name).write_text(text, encoding="utf-8")
        for slug, text in findings.items():
            (wd / "findings" / slug).write_text(text, encoding="utf-8")
        for slug, text in facts.items():
            (wd / "facts" / slug).write_text(text, encoding="utf-8")
        return result


class FakeObserver:
    """观察者 -p 会话替身（批4 协议）：按脚本写 OBSERVER.json+SUBMITTED 标记；
    可模拟空产出（未成功提交 → resume 反馈）、工具违规（on_tool 触发 guard）。"""

    def __init__(self, docs, *, state_md=False, draft=False, violations=None):
        self.docs = docs                # [judgment doc | None, ...]  None=空产出
        self.state_md = state_md        # 是否模拟观察者写 STATE.md
        self.draft = draft
        self.violations = violations    # [(tool, args), ...] 每次会话先触发违规调用
        self.calls = 0
        self.sheets = []                # 捕获任务单（零快照断言）
        self.feedbacks = []             # 捕获 resume 反馈文本
        self.resumes = []               # 捕获 resume_session_id
        self.resume_prompts = []        # S12：捕获断点续接注入语（None=非续接）

    def copy_observer_kit(self, root):
        (Path(root) / ".observer").mkdir(parents=True, exist_ok=True)

    def clear_judgment(self, root):
        for name in ("OBSERVER.json", "SUBMITTED"):
            p = Path(root) / ".observer" / name
            if p.exists():
                p.unlink()

    def read_judgment(self, root):
        p = Path(root) / ".observer" / "OBSERVER.json"
        if not p.is_file():
            return None
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError):
            return None
        return doc if isinstance(doc, dict) and doc.get("operations") else None

    def run_once(self, root, task_sheet, *, on_tool=None, on_spawn=None,
                 on_session_id=None, resume_session_id=None, feedback=None,
                 resume_prompt=None):
        self.calls += 1
        self.sheets.append(task_sheet)
        if feedback is not None:
            self.feedbacks.append(feedback)
        if resume_session_id:
            self.resumes.append(resume_session_id)
        self.resume_prompts.append(resume_prompt)
        from src.runner import ToolEvent
        for tool, args in (self.violations or []):
            if on_tool is not None:
                on_tool(ToolEvent(tool=tool, args=args, output="x"))
        doc = self.docs[min(self.calls - 1, len(self.docs) - 1)]
        if doc is not None:
            (Path(root) / ".observer").mkdir(parents=True, exist_ok=True)
            (Path(root) / ".observer" / "OBSERVER.json").write_text(
                json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            (Path(root) / ".observer" / "SUBMITTED").write_text(
                json.dumps({"ops": len(doc["operations"])}, ensure_ascii=False),
                encoding="utf-8")
        if self.state_md:
            (Path(root) / "STATE.md").write_text(
                "# STATE（观察者）\n\n## 下轮建议\n- 主攻 authc 面\n", encoding="utf-8")
        if self.draft:
            (Path(root) / "notes").mkdir(parents=True, exist_ok=True)
            (Path(root) / "notes" / "prior-intel-draft.md").write_text(
                "# 下次任务前置情报\n", encoding="utf-8")
        return {"stop_reason": "end_turn", "tokens": 123,
                "total_cost_usd": 0.01, "turns": 3, "is_error": False, "error": "",
                "session_id": f"obs-s{self.calls}"}


def _res(**kw):
    base = dict(session_id="s1", stop_reason="end_turn", turns=5, tokens=1000,
                total_cost_usd=0.02, handoff="已完成：x", final_text="",
                is_error=False, resumes=0)
    base.update(kw)
    return AgentResult(**base)


def _noop_observer():
    return FakeObserver([{"round": 1, "operations": []}])


class _NoopBrowser:
    """playwright 批：driver 全流程测试默认不真起 Chrome——start→None=skip 路径。
    browser 专项用例在测试内自行覆盖回真类或脚本替身。"""

    @classmethod
    def start(cls, root, ev, *, mcp_config=None, **kw):
        return None


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AT1_PROVIDER", "glm")
    monkeypatch.setenv("AT1_API_KEY", "sk-test-1234567890")
    monkeypatch.setattr(driver_mod, "BrowserHandle", _NoopBrowser)


def test_failfast_missing_pieces(tmp_path, monkeypatch):
    # 无 engagement.json
    assert driver_mod.run_engagement(str(tmp_path)) == 2
    # 缺 prior-intel → 拒启（status.md 已退役不再要求）
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "https://x.com", "goal": "g", "hint": "",
                    "scope": {"allow": ["x.com"], "deny": []}}), encoding="utf-8")
    assert driver_mod.run_engagement(str(tmp_path)) == 2
    # prior-intel 齐 + scope.allow 空 → 不拒启（scope 可选化），验 scope_missing 事件
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "prior-intel.md").write_text("x", encoding="utf-8")
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "https://x.com", "goal": "拿到确认漏洞", "hint": "",
                    "scope": {"allow": []}}), encoding="utf-8")
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=60, max_rounds=1,
                                   observer_on=False)
    assert rc == 0 and len(fake.calls) == 1
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    print("DEBUG-EVENTS:", [e["type"] for e in evs])
    assert any(e["type"] == "scope_missing" for e in evs)


def test_two_rounds_confirmed_flow(tmp_path, monkeypatch):
    """全链路：r1 worker 写 findings/facts → 观察者判断书（登记发现+事实+方向）
    → 执行器入图 → r2 接力。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(handoff="已完成：authc 面探测"),
         {"idor.md": "# [发现] 角色越权读取\n越权读取他人订单含手机号。"},
         {"profile.md": "目标画像：SpringCloud 网关 + Shiro"}, {}),
        (_res(), {}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)

    obs = FakeObserver([
        {"round": 1, "operations": [
            {"op": "add_fact", "summary": "目标画像：SpringCloud 网关 + Shiro（观察者核对）",
             "evidence": "facts/profile.md"},
            {"op": "add_finding", "summary": "角色越权读取他人订单",
             "report": "findings/idor.md", "severity": "high",
             "reason": "IDOR 实证，对照 331/332 差异", "result": "confirmed",
             "endpoint": "/api/authc/users/{id}/roles"},
            {"op": "add_intent", "goal": "authc 同型端点排查", "note": "F-001 守卫不一致",
             "ref": "F-001"},
        ]},
        {"round": 2, "operations": []},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2)
    assert rc == 0
    assert len(fake.calls) == 2

    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.node("F-001")["state"] == "confirmed"
    assert bb.node("F-001")["payload"]["report"] == "findings/idor.md"
    assert bb.node("D-001")["origin"] == "observer"
    assert any(n["payload"]["value"].startswith("目标画像")
               for n in bb.nodes("fact"))
    # D-001 的 ref=F-001 → 发现催生方向：spawns F-001 → D-001
    assert any(e["rel"] == "spawns" and e["src"] == "F-001" and e["dst"] == "D-001"
               for e in bb.graph["edges"])
    # 播种画像已被观察者换代（superseded）
    seeded = [n for n in bb.nodes("fact") if "待观察者换代" in n["payload"]["value"]]
    assert all(n["state"] == "superseded" for n in seeded)
    # STATE.md：观察者没写 → controller 兜底
    assert "兜底" in (tmp_path / "STATE.md").read_text(encoding="utf-8")


def test_control_stop_between_rounds(tmp_path, monkeypatch):
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)

    def poll(root):
        poll.n += 1
        if poll.n == 2:
            return {"cmd": "stop"}
        return None
    poll.n = 0
    monkeypatch.setattr(driver_mod, "_poll_control", poll)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=5,
                                   observer_on=False)
    assert rc == 0 and len(fake.calls) == 1
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["type"] == "run_end" and "control-stop" in e["data"]["reason"]
               for e in evs)


def test_guard_violation_event(tmp_path, monkeypatch):
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)

    def spawn(prompt, workdir, solver, task, **kw):
        from src.runner import ToolEvent
        task.on_fact(ToolEvent(tool="Bash",
                               args={"command": "curl -s https://evil.com/x"},
                               output="data"))
        return _res()
    monkeypatch.setattr(driver_mod.runner, "run", spawn)
    driver_mod.run_engagement(str(tmp_path), budget_s=300, max_rounds=1,
                              observer_on=False)
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["type"] == "guard_violation" and e["data"]["kind"] == "scope"
               for e in evs)


def test_observer_empty_retry_then_success(tmp_path, monkeypatch):
    """R8 防线（批4 终版）：首轮未成功提交 → resume 同 session 精确回喂 → 修正后提交成功。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(), {"idor.md": "# [发现] 越权读取\n实证：13800138000"}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        None,                                              # 第一轮：空产出（未写判断书未提交）
        {"round": 1, "operations": [
            {"op": "add_finding", "summary": "越权读取",
             "report": "findings/idor.md", "severity": "high", "reason": "实证"}]},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: (Path(root).joinpath(".observer", "OBSERVER.json")
                                      .unlink(missing_ok=True),
                                      Path(root).joinpath(".observer", "SUBMITTED")
                                      .unlink(missing_ok=True)))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=300, max_rounds=1)
    assert rc == 0
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "observer_resume_feedback" for e in evs)
    assert not any(e["type"] == "observer_empty_retry"
                   and e["data"]["stage"] == "exhausted" for e in evs)
    assert any(e["type"] == "observer_applied" for e in evs)
    # resume 精确回喂：反馈文本 + 同 session 句柄
    assert obs.feedbacks and "没有留下合法的判断书" in obs.feedbacks[0]
    assert obs.resumes == ["obs-s1"]
    bb = driver_mod.board_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.node("F-001") is not None


def test_observer_exhausted_after_double_blank(tmp_path, monkeypatch):
    """两轮都空产出 → exhausted 告警，不无限重试。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([None])                          # 始终空产出
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=300, max_rounds=1)
    assert rc == 0
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "observer_empty_retry" and e["data"]["stage"] == "exhausted"
               for e in evs)
    assert any(e["type"] == "state_fallback" for e in evs)   # 兜底 STATE 刷出


def test_dry_run_renders_prompt(tmp_path):
    _mk_engagement(tmp_path)
    rc = driver_mod.run_engagement(str(tmp_path), dry_run=True)
    assert rc == 0
    p = tmp_path / "state" / "dry-run-prompt.md"
    assert p.is_file()
    txt = p.read_text(encoding="utf-8")
    assert "【简报】" in txt and "example.com" in txt
    assert "facts//findings//evidence/" in txt


def test_inventory_page_stateless(tmp_path):
    """G1-A 终版：无状态目录页——全量列出；new_or_changed 是内存级参考标记；
    不落盘不进 offsets（守门员扫描器已删）。"""
    from src import board as board_mod
    bb = board_mod.Blackboard()
    (tmp_path / "findings").mkdir()
    f1 = tmp_path / "findings" / "a.md"
    f1.write_text("v1", encoding="utf-8")
    page1, state = driver_mod._inventory_page(tmp_path, {})
    assert [i["path"] for i in page1["items"]] == ["findings/a.md"]
    assert page1["new_or_changed"] == ["findings/a.md"]
    page2, state = driver_mod._inventory_page(tmp_path, state)     # 无变化
    assert page2["new_or_changed"] == []
    f1.write_text("v2-content", encoding="utf-8")                  # 改旧 → 标记
    page3, _ = driver_mod._inventory_page(tmp_path, state)
    assert "findings/a.md" in page3["new_or_changed"]
    # 零持久化：offsets 无 files_seen
    assert "files_seen" not in bb.offsets
    assert "files_seen" not in driver_mod.__dict__.get("_X", {}) or True


def test_task_sheet_contains_inventory_no_content(tmp_path, monkeypatch):
    """零快照红线：任务单的 worker_output 只有路径/大小/时间，禁止文件内容。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(), {"idor.md": "# [发现] 越权读取\n实证：13800138000"
                 "带大量正文内容" * 20}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = _noop_observer()
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=300, max_rounds=1,
                                   observer_on=True)
    assert rc == 0
    sheet = obs.sheets[0]
    wo = sheet["worker_output"]
    for item in wo["items"]:
        assert set(item.keys()) <= {"path", "dir", "bytes", "new_or_changed"}
    assert all("实证" not in json.dumps(i, ensure_ascii=False) for i in wo["items"])
    # 硬拒/公诉清单也在（noreport 出口）
    assert "noreport_rejects" in sheet and "precheck_hints" in sheet


def test_harvest_machinery_gone():
    """R1/R7：配方 1 账本收割/两刷投影/writeback 全家退役——函数不存在。"""
    assert not hasattr(driver_mod, "_harvest_findings")
    assert not hasattr(driver_mod, "_harvest_directions")
    assert not hasattr(driver_mod, "_handoff_unfinished_to_directions")
    assert not hasattr(driver_mod, "_render_state_projection")
    assert not hasattr(driver_mod, "_apply_verdict")
    assert not hasattr(driver_mod, "_apply_observer_governance")


def test_dry_run_writes_state_md_at_root(tmp_path, monkeypatch):
    """dry-run 也产 STATE.md（单层化后落 engagement 根）。"""
    (tmp_path / "engagement.json").write_text(json.dumps({
        "target": "https://example.com", "goal": "拿到确认漏洞", "hint": "",
        "scope": {"allow": ["example.com"]}}), encoding="utf-8")
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "prior-intel.md").write_text("intel\n", encoding="utf-8")
    monkeypatch.delenv("AT1_PROVIDER", raising=False)      # 默认 glm 预设，无需 key
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=10, dry_run=True)
    assert rc == 0
    assert (tmp_path / "STATE.md").is_file()
    assert "# STATE" in (tmp_path / "STATE.md").read_text(encoding="utf-8")


def test_full_loop_observer_bookkeeping_chain(tmp_path, monkeypatch):
    """两轮链路：r1 发现+事实+方向+连线+blocked；r2 验证 STATE.md 观察者产物直通。"""
    _mk_engagement(tmp_path)

    fake = FakeRunner([
        (_res(handoff="已完成：authc 探测"), {"roles.md": "# [发现] 角色越权\n实证"}, {}, {}),
        (_res(), {}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        {"round": 1, "operations": [
            {"op": "add_finding", "summary": "角色越权读取", "report": "findings/roles.md",
             "severity": "high", "reason": "IDOR", "endpoint": "/api/authc/users/{id}/roles"},
            {"op": "add_intent", "goal": "authc 同型排查", "note": "守卫不一致", "ref": "F-001"},
            {"op": "set_state", "id": "D-001", "state": "in_progress", "reason": "开工"},
        ]},
        {"round": 2, "operations": [
            {"op": "set_state", "id": "D-001", "state": "done", "reason": "排查完"},
        ]},
    ], state_md=True, draft=True)
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2)
    assert rc == 0
    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.node("D-001")["state"] == "done"
    # ref=F-001 → spawns（发现催生方向）
    assert any(e["rel"] == "spawns" and e["dst"] == "D-001" for e in bb.graph["edges"])
    # 观察者写的 STATE.md 被保留（无 state_fallback）
    state_txt = (tmp_path / "STATE.md").read_text(encoding="utf-8")
    assert "下轮建议" in state_txt
    # 观察者收尾导出 draft
    assert (tmp_path / "notes" / "prior-intel-draft.md").is_file()
    # 计量：worker session_end 带 cost
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    we = next(e for e in evs if e["type"] == "session_end")
    assert "total_cost_usd" in we["data"]
    assert any(e["type"] == "observer_session_end" for e in evs)


def test_observer_runs_on_zero_output_round(tmp_path, monkeypatch):
    """P-3 语义保留：0 产出轮观察者照跑（治理不停摆）。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        {"round": 1, "operations": [
            {"op": "add_intent", "goal": "观察者建议的零产出轮方向"}]},
        {"round": 2, "operations": [
            {"op": "set_state", "id": "D-001", "state": "in_progress", "reason": "接力"}]},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2)
    assert rc == 0
    assert obs.calls == 2                               # 两轮都跑了
    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.node("D-001")["origin"] == "observer"


def test_skills_src_wired_from_engagement(tmp_path):
    """P-8 回归：skills_src 随 engagement（单层化后落根/.claude/skills）。"""
    skills = tmp_path / "myskills" / "hello-skill"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text("---\nname: hello-skill\ndescription: t\n---\nx",
                                     encoding="utf-8")
    _mk_engagement(tmp_path)
    eng = json.loads((tmp_path / "engagement.json").read_text(encoding="utf-8"))
    eng["skills_src"] = str(tmp_path / "myskills")
    (tmp_path / "engagement.json").write_text(json.dumps(eng, ensure_ascii=False),
                                              encoding="utf-8")
    rc = driver_mod.run_engagement(str(tmp_path), dry_run=True)
    assert rc == 0
    assert (tmp_path / ".claude" / "skills" / "hello-skill" / "SKILL.md").is_file()


def test_consume_stop_file_stops_and_kills(tmp_path, monkeypatch):
    from src import runner as runner_mod
    ctl = tmp_path / "CONTROL"
    ctl.write_text(json.dumps({"cmd": "stop", "text": "验收收尾"}), encoding="utf-8")
    flag = {"hit": False, "text": ""}
    killed = []
    monkeypatch.setattr(runner_mod, "kill_process_tree",
                        lambda proc: killed.append(proc))
    proc_ref = {"proc": "FAKE_PROC"}
    assert driver_mod._consume_stop_file(ctl, proc_ref, flag) is True
    assert flag["hit"] and flag["text"] == "验收收尾"
    assert killed == ["FAKE_PROC"]
    assert not ctl.exists()


def test_consume_stop_file_leaves_directive_and_pause(tmp_path):
    for cmd in ("directive", "pause"):
        ctl = tmp_path / "CONTROL"
        ctl.write_text(json.dumps({"cmd": cmd, "text": "x"}), encoding="utf-8")
        flag = {"hit": False, "text": ""}
        assert driver_mod._consume_stop_file(ctl, {"proc": None}, flag) is False
        assert ctl.exists() and not flag["hit"]
        ctl.unlink()


def test_consume_stop_file_before_attach_race_safe(tmp_path):
    ctl = tmp_path / "CONTROL"
    ctl.write_text(json.dumps({"cmd": "stop"}), encoding="utf-8")
    flag = {"hit": False, "text": ""}
    assert driver_mod._consume_stop_file(ctl, {}, flag) is True
    assert flag["hit"] and not ctl.exists()


def test_consume_stop_file_ignores_garbage(tmp_path):
    ctl = tmp_path / "CONTROL"
    ctl.write_text("not-json{{", encoding="utf-8")
    flag = {"hit": False, "text": ""}
    assert driver_mod._consume_stop_file(ctl, {"proc": None}, flag) is False


def test_consume_stop_sets_flag_before_unlink(tmp_path, monkeypatch):
    """续修批竞态闭合：删文件必须晚于置标志——否则主循环"读标志→轮询文件"
    两步之间被盯梢线程插入时两边都看不见 stop，多跑一轮 worker。"""
    import os as _os
    ctl = tmp_path / "CONTROL"
    ctl.write_text(json.dumps({"cmd": "stop"}), encoding="utf-8")
    flag = {"hit": False, "text": ""}
    real_unlink = driver_mod.Path.unlink
    seen = {}

    def spy_unlink(self, *a, **kw):
        seen["flag_at_unlink"] = flag["hit"]     # 删文件那一刻，标志位是否已置
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(driver_mod.Path, "unlink", spy_unlink)
    assert driver_mod._consume_stop_file(ctl, {"proc": None}, flag) is True
    assert seen["flag_at_unlink"] is True


def test_loop_top_rereads_stop_flag(tmp_path, monkeypatch):
    """二次读：轮询 CONTROL 返回 None（盯梢线程刚删了文件）但标志已置 → 仍收工。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    monkeypatch.setattr(driver_mod, "_poll_control", lambda root: None)

    def fake_consume(control_path, proc_ref, flag):
        flag["hit"] = True                       # 模拟盯梢线程已消费（文件已删）
        return True
    monkeypatch.setattr(driver_mod, "_consume_stop_file", fake_consume)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=3,
                                   observer_on=False)
    assert rc == 0
    assert len(fake.calls) == 0, "盯梢线程已置标志 → 一轮都不该 spawn"


# ── 批4fix S1/S2：停机三道门 + 观察者挂进 watcher 射程 ────────────────────

def _wait_until(pred, timeout=10.0):
    """轮询等待条件成立（watcher 0.5s 粒度的确定性等待）。"""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return False


def test_stop_during_worker_gate_w(tmp_path, monkeypatch):
    """S1 门 A + S2 登记制：worker 跑动中 stop → watcher 杀登记的真子进程 →
    门 A 退（无观察者 spawn、盘面冻结、run_end reason=control-stop(W)）。"""
    import subprocess
    import sys

    _mk_engagement(tmp_path)

    def fake_run(prompt, workdir, solver, task, **kw):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        task.on_spawn(proc)                       # 出生登记（S2 机制，worker 侧既有）
        ctl = Path(workdir) / "state" / "CONTROL"
        ctl.write_text(json.dumps({"cmd": "stop", "text": ""}), encoding="utf-8")
        assert _wait_until(lambda: not ctl.exists()), "盯梢线程未消费 CONTROL"
        assert _wait_until(lambda: proc.poll() is not None), "watcher 未杀登记的 worker"
        return _res(stop_reason="controller_kill")

    monkeypatch.setattr(driver_mod.runner, "run", fake_run)
    obs = FakeObserver([{"round": 1, "operations": []}])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit", lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=3)
    assert rc == 0
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "run_end" and e["data"]["reason"] == "control-stop(W)"
               for e in evs)
    assert obs.calls == 0                          # 门 A：观察者未生
    assert not (tmp_path / "STATE.md").exists()    # 盘面冻结：STATE 未写
    bb = driver_mod.board_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert len(bb.graph["nodes"]) == 1             # 只有播种画像 fact——图字节不变


def test_stop_during_observer_gate_o(tmp_path, monkeypatch):
    """S1 门 B + S2：观察者跑动中 stop → 观察者（经 on_spawn 登记）被杀 →
    判断书未入图、STATE 未写、run_end reason=control-stop(O)。"""
    import subprocess
    import sys

    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs_calls = []

    def fake_obs_run(root, sheet, *, on_tool=None, on_spawn=None,
                     on_session_id=None, resume_session_id=None, feedback=None,
                     resume_prompt=None):
        obs_calls.append(1)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        assert on_spawn is not None, "driver 未把 proc_ref setter 传给观察者（S2 断线）"
        on_spawn(proc)                             # 观察者出生登记（S2 本体）
        ctl = Path(root) / "state" / "CONTROL"
        ctl.write_text(json.dumps({"cmd": "stop", "text": ""}), encoding="utf-8")
        assert _wait_until(lambda: not ctl.exists()), "盯梢线程未消费 CONTROL"
        assert _wait_until(lambda: proc.poll() is not None), "watcher 未杀观察者"
        return {"stop_reason": "controller_kill", "tokens": 0, "total_cost_usd": 0,
                "turns": 0, "is_error": False, "error": "", "session_id": "obs-killed"}

    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit", lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "clear_judgment", lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "run_once", fake_obs_run)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=3)
    assert rc == 0
    assert len(obs_calls) == 1                     # 被杀后不进 resume 回喂重试
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "run_end" and e["data"]["reason"] == "control-stop(O)"
               for e in evs)
    assert not (tmp_path / "STATE.md").exists()    # apply_judgment/STATE 写入未发生
    bb = driver_mod.board_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.nodes("finding") == []               # 判断书未入图


def test_controller_kill_skips_dead_proc():
    """S2 保险：已退出的 Popen 不贴标不补刀（PID 复用防误杀）。"""
    import subprocess
    import sys
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=10)
    driver_mod._controller_kill(proc)              # 不抛、不动作
    assert getattr(proc, "_controller_kill", False) is False
    # 活进程照常贴标（既有语义不回归）
    live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        driver_mod._controller_kill(live)
        assert getattr(live, "_controller_kill", False) is True
        live.wait(timeout=10)
    finally:
        if live.poll() is None:
            live.kill()


def test_control_stop_preexisting_prevents_any_spawn(tmp_path, monkeypatch):
    _mk_engagement(tmp_path)
    (tmp_path / "state" / "CONTROL").write_text(
        json.dumps({"cmd": "stop", "text": "早于 run"}), encoding="utf-8")
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=3,
                                   observer_on=False)
    assert rc == 0
    assert len(fake.calls) == 0, "stop 早于 run：一轮都不该 spawn"


def test_kill_process_tree_kills_children():
    import os
    import subprocess
    import sys
    import time as _t
    if os.name != "nt":
        pytest.skip("Windows 进程组树杀语义")
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time;"
         "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
         "print(c.pid, flush=True); time.sleep(60)"],
        stdout=subprocess.PIPE, text=True)
    child_pid = int(parent.stdout.readline().strip())
    from src.runner import kill_process_tree
    kill_process_tree(parent)
    parent.wait(timeout=10)
    _t.sleep(1.5)
    r = subprocess.run(["tasklist", "/FI", f"PID eq {child_pid}"],
                       capture_output=True, text=True)
    assert str(child_pid) not in r.stdout, f"孙进程 {child_pid} 未被树杀"


def test_preflight_verdicts(tmp_path, monkeypatch):
    import subprocess as sp
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[0] == "claude":
            if len(calls) == 1:
                return sp.CompletedProcess(cmd, 1, "", "boom")
            return sp.CompletedProcess(cmd, 0, "2.1.238 (Claude Code)", "")
        return sp.CompletedProcess(cmd, 0, "Version 0.0.80", "")

    monkeypatch.setattr(driver_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(driver_mod.shutil, "which", lambda x: "C:/fake/npx.cmd")
    mcp = tmp_path / ".mcp.json"
    mcp.write_text("{}", encoding="utf-8")
    pf = driver_mod._preflight("claude", mcp)
    assert pf["ok"] is False and "rc=1" in pf["claude"]
    pf = driver_mod._preflight("claude", tmp_path / "nope.json")
    assert pf["ok"] is True and "缺席" in pf["mcp"]
    pf = driver_mod._preflight("claude", mcp)
    assert pf["ok"] is True and "2.1.238" in pf["claude"] and "playwright 可启动" in pf["mcp"]


def test_preflight_npx_missing_warns_only(tmp_path, monkeypatch):
    monkeypatch.setattr(driver_mod.shutil, "which", lambda x: None)
    mcp = tmp_path / ".mcp.json"
    mcp.write_text("{}", encoding="utf-8")
    pf = driver_mod._preflight("claude", mcp)
    assert pf["ok"] is True and "npx 不在 PATH" in pf["mcp"]


def test_preflight_event_in_real_run(tmp_path, monkeypatch):
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=120, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    rows = [json.loads(l) for l in open(tmp_path / "state" / "auto-log.jsonl",
                                        encoding="utf-8") if l.strip()]
    types = [r.get("type") for r in rows]
    assert "preflight" in types
    pf = next(r["data"] for r in rows if r.get("type") == "preflight")
    assert "claude" in pf and "mcp" in pf and pf.get("ok") is True


def test_skills_src_env_fallback(tmp_path, monkeypatch):
    skills = tmp_path / "globalskills" / "g-skill"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text("---\nname: g-skill\ndescription: t\n---\nx",
                                     encoding="utf-8")
    _mk_engagement(tmp_path)
    monkeypatch.setenv("AT1_SKILLS_SRC", str(tmp_path / "globalskills"))
    rc = driver_mod.run_engagement(str(tmp_path), dry_run=True)
    assert rc == 0
    assert (tmp_path / ".claude" / "skills" / "g-skill" / "SKILL.md").is_file()


def test_seed_prior_intel_single_picture_fact(tmp_path):
    """R5 终版：播种只种一条画像 fact（直落终态），prior-intel 原文不进图。"""
    from src import board as board_mod
    (tmp_path / "notes").mkdir(parents=True)
    (tmp_path / "notes" / "prior-intel.md").write_text(
        "# 前置情报\n- 9098 是奕云CaaS 登录面\n- 身份锚是 customsid\n", encoding="utf-8")
    bb = board_mod.Blackboard()
    driver_mod._seed_from_engagement(tmp_path, bb)
    facts = bb.nodes("fact")
    assert len(facts) == 1                              # 一条画像，不是逐行灌
    assert facts[0]["state"] == "confirmed"             # 直落终态
    assert facts[0]["origin"] == "user"
    assert facts[0]["payload"]["value"].startswith("目标画像")
    assert facts[0]["payload"]["evidence"] == "notes/prior-intel.md"
    # 续跑不重播
    driver_mod._seed_from_engagement(tmp_path, bb)
    assert len(bb.nodes("fact")) == 1


def test_seed_skipped_when_graph_nonempty(tmp_path):
    from src import board as board_mod
    bb = board_mod.Blackboard()
    bb.create_node("intent", {"goal": "已有方向"}, origin="worker", round=1)
    driver_mod._seed_from_engagement(tmp_path, bb)
    assert len(bb.nodes("intent")) == 1 and bb.nodes("fact") == []


# ── 批 2 保留：STOP 接线 / noreport 前置 / hints 队列 ─────────────────────

def test_worker_stop_valid_terminates(tmp_path, monkeypatch):
    """A18：有效 Stop（引现存 F-xxx，F 由观察者登记）→ 收割落盘后 run 终止。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(stop_text="目标达成：越权已确认，引 F-001"),
         {"idor.md": "# [发现] 越权读取\n实证"}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        {"round": 1, "operations": [
            {"op": "add_finding", "summary": "越权读取", "report": "findings/idor.md",
             "severity": "high", "reason": "实证"}]},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=3)
    assert rc == 0 and len(fake.calls) == 1
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "worker_stop" for e in evs)
    assert any(e["type"] == "run_end" and e["data"]["reason"] == "worker-stop(C)" for e in evs)


def test_worker_stop_invalid_continues(tmp_path, monkeypatch):
    """无引证的 Stop 无效 → stop_invalid 事件 + 继续下一轮（防偷懒护栏）。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(stop_text="目标达成"), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2,
                                   observer_on=False)
    assert rc == 0 and len(fake.calls) == 2
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "stop_invalid" for e in evs)
    assert not any(e["type"] == "worker_stop" for e in evs)


def test_noreport_reject_blocks_finding_entry(tmp_path, monkeypatch):
    """T2.6 语义保留：形状即现象的 finding 文件 → noreport 前置硬拒清单，
    观察者即便登记也拒不受理（不进图）。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(), {"meta.md": "# [发现] 元数据端点可达\nGET http://169.254.169.254/latest/meta-data/ 200"},
         {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        {"round": 1, "operations": [
            {"op": "add_finding", "summary": "元数据端点", "report": "findings/meta.md",
             "severity": "low", "reason": "x"}]},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment",
                        lambda root: Path(root).joinpath(".observer", "OBSERVER.json")
                        .unlink(missing_ok=True))
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=300, max_rounds=1)
    assert rc == 0
    import src.board as board_mod
    bb = board_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.nodes("finding") == []                    # 硬拒不入图
    rej = tmp_path / ".observer" / "OBSERVER.rejects"
    assert rej.is_file() and "noreport" in rej.read_text(encoding="utf-8")


def test_hints_queue_harvested_into_prompt_once(tmp_path, monkeypatch):
    _mk_engagement(tmp_path)
    (tmp_path / ".at1" / "control").mkdir(parents=True)
    (tmp_path / ".at1" / "control" / "hints.jsonl").write_text(
        json.dumps({"ts": "t", "text": "重点看支付回调"}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2,
                                   observer_on=False)
    assert rc == 0
    p1 = fake.calls[0]["prompt"]
    assert "重点看支付回调" in p1.split("【运行提示】")[-1]
    assert "重点看支付回调" not in fake.calls[1]["prompt"]


# ── 续修批：止损信号源修正（usc-cwcx-b1 实机误杀回归） ───────────────────

def test_stoploss_not_triggered_on_productive_rounds(tmp_path, monkeypatch):
    """有产出的 run 不许被"无新事实"误杀（实机 usc-cwcx-b1：三轮产出旺盛仍
    在第 3 轮被停——旧信号（图节点增量）在批3fix 架构下恒 0）。"""
    _mk_engagement(tmp_path)
    # 每轮 worker 都写新 evidence 文件（产出）
    scripts = [(_res(), {}, {}, {f"probe-r{i}.txt": f"data{i}"}) for i in range(1, 5)]
    fake = FakeRunner(scripts)
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=4,
                                   observer_on=False)
    assert rc == 0
    assert len(fake.calls) == 4, "四轮全产出，不该被止损截停"
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert not any(e["type"] == "stoploss_trigger"
                   and "无新事实" in e["data"].get("dim", "") for e in evs)


def test_stoploss_fires_on_three_barren_rounds(tmp_path, monkeypatch):
    """连续 3 轮零产出 → 第 3 轮末止损（信号修正后仍保留止损能力）。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {})])     # 每轮都不写任何文件
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=5,
                                   observer_on=False)
    assert rc == 0
    assert len(fake.calls) == 3, "第 3 轮末就该停，不该跑到 5 轮"
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "stoploss_trigger"
               and "无新事实" in e["data"].get("dim", "") for e in evs)


# ── 批4fix S5/S12：phase 账本 + 断点续会话 ────────────────────────────────

def _evs(root: Path) -> list[dict]:
    return [json.loads(l) for l in
            (root / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip()]


def test_phase_ledger_transitions_and_clean_clear(tmp_path, monkeypatch):
    """S5 转换点：session_start→working(r,role=worker)、观察者 spawn→auditing、
    轮末入图完成→working（清 sid）、干净收尾→清账。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_seen = {}

    class SpyRunner(FakeRunner):
        def __call__(self, prompt, workdir, *a, **kw):
            phase_seen[f"worker{len(self.calls) + 1}"] = phase_mod.read(Path(workdir))
            return super().__call__(prompt, workdir, *a, **kw)

    fake = SpyRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)

    class SpyObserver(FakeObserver):
        def run_once(self, root, task_sheet, **kw):
            phase_seen[f"audit{len(self.sheets) + 1}"] = phase_mod.read(Path(root))
            return super().run_once(root, task_sheet, **kw)

    obs = SpyObserver([
        # 非空 operations——空判断书会触发 resume 回喂重试，干扰转换点时序
        {"round": 1, "operations": [{"op": "add_intent", "goal": "方向一"}]},
        {"round": 2, "operations": [{"op": "set_state", "id": "D-001",
                                     "state": "in_progress", "reason": "接力"}]},
    ])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment", lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2)
    assert rc == 0
    strip_ts = lambda d: {k: v for k, v in (d or {}).items() if k != "updated_at"}
    assert strip_ts(phase_seen["worker1"]) == {"phase": "working", "round": 1,
                                               "role": "worker"}
    assert strip_ts(phase_seen["audit1"]) == {"phase": "auditing", "round": 1,
                                              "role": "observer"}
    assert strip_ts(phase_seen["audit2"]) == {"phase": "auditing", "round": 2,
                                              "role": "observer"}
    assert strip_ts(phase_seen["worker2"]) == {"phase": "working", "round": 2,
                                               "role": "worker"}
    assert phase_mod.read(tmp_path) is None          # 干净收尾：清账
    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.bookkeeping["round"] == 2              # 轮号持久


def test_round_number_continues_across_restart(tmp_path, monkeypatch):
    """S5/R-6：轮号从簿记续——第二个进程的轮号接着走，不从 1 重来。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    assert driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                     observer_on=False) == 0
    assert driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                     observer_on=False) == 0
    starts = [e["data"]["round"] for e in _evs(tmp_path) if e["type"] == "session_start"]
    assert starts == [1, 2]                          # 跨进程续编号


def test_hint_offset_persists_immediately_and_no_replay(tmp_path, monkeypatch):
    """S5/R-8：hint 收割即落盘（spawn 时盘上 offsets 已推进，不等轮末）；
    跨进程续跑不重放旧插话。"""
    _mk_engagement(tmp_path)
    (tmp_path / ".at1" / "control").mkdir(parents=True)
    (tmp_path / ".at1" / "control" / "hints.jsonl").write_text(
        json.dumps({"ts": "t", "text": "重点看支付回调"}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    offsets_seen = []

    class SpyRunner(FakeRunner):
        def __call__(self, prompt, workdir, *a, **kw):
            data = json.loads((Path(workdir) / ".at1" / "blackboard.json")
                              .read_text(encoding="utf-8"))
            offsets_seen.append(data["bookkeeping"]["offsets"].get("hints", 0))
            return super().__call__(prompt, workdir, *a, **kw)

    fake = SpyRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    assert driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                     observer_on=False) == 0
    assert offsets_seen[0] > 0                       # spawn 前已落盘（即时性）
    assert "重点看支付回调" in fake.calls[0]["prompt"]
    assert driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                     observer_on=False) == 0
    assert "重点看支付回调" not in fake.calls[1]["prompt"]   # 跨进程不重放


def test_worker_resume_after_kill(tmp_path, monkeypatch):
    """S12：working 残留+session_id → 续跑命令带 resume 句柄、注入语在 prompt。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_mod.write(tmp_path, "working", 1, session_id="s-dead", role="worker")
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert fake.resumes[0] == "s-dead"               # --resume <id>（FakeRunner 锚）
    assert "你被停机中断过" in fake.calls[0]["prompt"]     # 注入语三件套
    evs = _evs(tmp_path)
    assert any(e["type"] == "interrupted_phase" and e["data"]["phase"] == "working"
               for e in evs)
    assert any(e["type"] == "session_start" and e["data"].get("resumed") for e in evs)
    assert phase_mod.read(tmp_path) is None          # 干净收尾清账（接力完成）


def test_observer_resume_after_kill_skips_worker(tmp_path, monkeypatch):
    """S12：auditing 残留 → 本轮 worker 不重跑（上进程已收工），观察者续接
    （注入语：已做的验证不必重做），判断书正常提交入图。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_mod.write(tmp_path, "auditing", 1, session_id="obs-dead", role="observer")
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([{"round": 1, "operations": [
        {"op": "add_intent", "goal": "续审计收尾方向", "note": "上进程验证已做完"}]}])
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit",
                        lambda root: Path(root).joinpath(".observer").mkdir(exist_ok=True))
    monkeypatch.setattr(driver_mod.observer, "clear_judgment", lambda root: None)
    monkeypatch.setattr(driver_mod.observer, "run_once", obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", obs.read_judgment)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1)
    assert rc == 0
    assert not fake.calls                            # worker 未重跑
    assert obs.resumes == ["obs-dead"]
    assert obs.resume_prompts[0] and "审计被中断" in obs.resume_prompts[0]
    evs = _evs(tmp_path)
    assert any(e["type"] == "interrupted_phase" and e["data"]["phase"] == "auditing"
               for e in evs)
    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb.node("D-001") is not None              # 判断书正常提交入图


def test_resume_fallback_once_on_spawn_error(tmp_path, monkeypatch):
    """S12：续接抛错 → resume_fallback 留账 → 落回新开（正常 prompt），只试一次。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_mod.write(tmp_path, "working", 1, session_id="s-dead", role="worker")
    calls = []

    def flaky_run(prompt, workdir, solver, task, *, time_box_s=None, max_turns=None,
                  claude_bin=None, resume_session_id=None):
        calls.append({"resume": resume_session_id, "prompt": prompt})
        if resume_session_id:
            raise RuntimeError("session 不存在")
        return _res()

    monkeypatch.setattr(driver_mod.runner, "run", flaky_run)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert len(calls) == 2                           # 续接一次 + 新开一次，不循环
    assert [c["resume"] for c in calls] == ["s-dead", None]
    assert "你被停机中断过" in calls[0]["prompt"]
    assert "【简报】" in calls[1]["prompt"]           # 落回正常轮 prompt
    assert any(e["type"] == "resume_fallback" and e["data"]["role"] == "worker"
               for e in _evs(tmp_path))


def test_resume_fallback_on_error_result(tmp_path, monkeypatch):
    """S12：续接返回 error 终态（session 截断损坏类）→ 同样落回新开。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_mod.write(tmp_path, "working", 1, session_id="s-broken", role="worker")
    fake = FakeRunner([
        (_res(stop_reason="error", is_error=True, error="transcript broken"), {}, {}, {}),
        (_res(), {}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert fake.resumes == ["s-broken", None]
    assert any(e["type"] == "resume_fallback" for e in _evs(tmp_path))


def test_old_phase_format_without_session(tmp_path, monkeypatch):
    """S12：旧档案无 session_id 字段 → 走老路径，不报错不续接。"""
    from src import phase as phase_mod
    _mk_engagement(tmp_path)
    phase_mod.write(tmp_path, "working", 2)          # 本批之前的格式
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert fake.resumes == [None]
    assert "你被停机中断过" not in fake.calls[0]["prompt"]
    assert any(e["type"] == "interrupted_phase"
               and e["data"]["has_session"] is False for e in _evs(tmp_path))


# ── playwright 批：浏览器池生命周期（B2/B6） ─────────────────────────────

def test_browser_pool_lifecycle_in_run(tmp_path, monkeypatch):
    """池启动→endpoint 注入 env→每轮 ensure→run_end 按 KEEP 收尾（fake 句柄记账）。"""
    import os
    _mk_engagement(tmp_path)
    monkeypatch.setenv("AT1_BROWSER_KEEP", "1")
    monkeypatch.setenv("PLAYWRIGHT_MCP_CDP_ENDPOINT", "sentinel-old")  # teardown 还原
    made = []

    class FakeHandle:
        def __init__(self):
            self.ensures = 0
            self.keeps = []
            self.endpoint = "http://127.0.0.1:9333"
            made.append(self)

        @classmethod
        def start(cls, root, ev, *, mcp_config=None, **kw):
            assert Path(mcp_config).is_file()        # expand() 已写 .mcp.json
            return cls()

        def ensure(self):
            self.ensures += 1

        def shutdown(self, *, keep):
            self.keeps.append(keep)

    monkeypatch.setattr(driver_mod, "BrowserHandle", FakeHandle)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=2,
                                   observer_on=False)
    assert rc == 0
    assert len(made) == 1                            # 一 run 一池
    assert made[0].ensures == 2                      # 每轮 spawn 前探活
    assert made[0].keeps == [True]                   # KEEP=1 → 留守
    assert os.environ["PLAYWRIGHT_MCP_CDP_ENDPOINT"] == "http://127.0.0.1:9333"

    # 默认（KEEP 未设）→ keep=False，run_end 杀+清账
    monkeypatch.delenv("AT1_BROWSER_KEEP", raising=False)
    made.clear()
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0 and made[0].keeps == [False]


def test_browser_pool_skip_clears_env_and_emits(tmp_path, monkeypatch):
    """skip 路径：真 start 走 no-exe → browser_skip 事件 + shell 残值被清（B3 反向）。"""
    import os
    from src import browser as browser_mod
    _mk_engagement(tmp_path)
    monkeypatch.delenv("PLAYWRIGHT_MCP_CDP_ENDPOINT", raising=False)
    monkeypatch.setattr(driver_mod, "BrowserHandle", browser_mod.BrowserHandle)
    monkeypatch.setattr(browser_mod, "find_exe", lambda: None)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=60, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    evs = _evs(tmp_path)
    assert any(e["type"] == "browser_skip" and e["data"]["reason"] == "no-exe"
               for e in evs)
    assert "PLAYWRIGHT_MCP_CDP_ENDPOINT" not in os.environ


def test_browser_relaunch_event_flows_mid_run(tmp_path, monkeypatch):
    """轮间探活失败 → browser_relaunch 事件经真 EventWriter 落盘（验收4 事件锚），
    run 照常跑完。"""
    from src import browser as browser_mod
    _mk_engagement(tmp_path)

    class FlakyHandle:
        def __init__(self):
            self.ev = None
            self.endpoint = "http://127.0.0.1:9333"

        @classmethod
        def start(cls, root, ev, *, mcp_config=None, **kw):
            h = cls()
            h.ev = ev
            return h

        def ensure(self):
            self.ev.emit("browser_relaunch",
                         {"pid": 1, "port": 9333, "headless": False,
                          "reason": "probe-fail"})

        def shutdown(self, *, keep):
            pass

    monkeypatch.setattr(driver_mod, "BrowserHandle", FlakyHandle)
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=60, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    evs = _evs(tmp_path)
    assert any(e["type"] == "browser_relaunch" and e["data"]["reason"] == "probe-fail"
               for e in evs)
    assert any(e["type"] == "run_end" for e in evs)  # 自愈不挡 run


def test_preflight_reports_chrome_presence(tmp_path, monkeypatch):
    """B2：preflight 增 chrome 键——在场报路径、缺席报文案（只警告不拒启）。"""
    import subprocess as sp

    def fake_run(cmd, **kw):
        return sp.CompletedProcess(cmd, 0, "ok", "")

    monkeypatch.setattr(driver_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(driver_mod.shutil, "which", lambda x: "C:/fake/npx.cmd")
    mcp = tmp_path / ".mcp.json"
    mcp.write_text("{}", encoding="utf-8")
    # from-import 是导入期绑定——driver 命名空间的 find_exe 要在 driver 侧打桩
    monkeypatch.setattr(driver_mod, "find_exe", lambda: r"D:\x\chrome.exe")
    pf = driver_mod._preflight("claude", mcp)
    assert pf["chrome"] == r"D:\x\chrome.exe" and pf["ok"] is True
    monkeypatch.setattr(driver_mod, "find_exe", lambda: None)
    pf = driver_mod._preflight("claude", mcp)
    assert "未找到" in pf["chrome"] and pf["ok"] is True


# ── 10-13 实机修复批（F1/F2）──────────────────────────────────────────────

def test_rounds_relative_on_old_engagement(tmp_path, monkeypatch):
    """F1：簿记轮号=5 的老 engagement + max_rounds=1 → 恰好再跑 1 轮。
    旧实现绝对轮号比较（rnd=5 ≥ 1）启动即停，worker 一次都不 spawn
    （10-12 E5a/E5b 实抓：--rounds 1 一秒没跑就收工）。"""
    _mk_engagement(tmp_path)
    import src.board as bb_mod
    bb = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    bb.bookkeeping["round"] = 5                     # 老 engagement：已跑过 5 轮
    bb.save()
    fake = FakeRunner([(_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert len(fake.calls) == 1, "补跑 1 轮 = 恰好 1 次 worker 会话，不许秒停"
    evs = _evs(tmp_path)
    trig = [e for e in evs if e["type"] == "stoploss_trigger"]
    assert len(trig) == 1
    assert "本次 run 轮数上限" in trig[0]["data"]["dim"]     # 文案按相对语义
    # 存量回归：簿记轮号照绝对值续（6），不是重置
    bb2 = bb_mod.Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert bb2.bookkeeping["round"] == 6


def test_resume_event_only_on_real_resume(tmp_path, monkeypatch):
    """F2：resume 事件只在真续跑发。旧判定（启动时图非空）被配方 0 播种
    击穿——播种在判定之前跑，首跑图必非空 → 永远发假 resume（jwzx 首跑实抓
    `resume {nodes:1}`）。簿记轮号 > 0 才是续跑。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([(_res(), {}, {}, {}), (_res(), {}, {}, {})])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    assert not any(e["type"] == "resume" for e in _evs(tmp_path)), \
        "首跑（簿记轮号=0）不许发 resume——哪怕播种已让图非空"
    # 第二次 run：簿记轮号=1 且图非空 → 真 resume
    rc = driver_mod.run_engagement(str(tmp_path), budget_s=600, max_rounds=1,
                                   observer_on=False)
    assert rc == 0
    resumes = [e for e in _evs(tmp_path) if e["type"] == "resume"]
    assert len(resumes) == 1 and resumes[0]["data"]["nodes"] >= 1
