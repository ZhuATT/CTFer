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

    def __call__(self, prompt, workdir, solver, task, *, time_box_s=None,
                 max_turns=None, claude_bin=None):
        self.calls.append({"prompt": prompt, "workdir": workdir,
                           "task": task, "time_box": time_box_s})
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
    """观察者 -p 会话替身：按脚本写 OBSERVER.json；可模拟首轮空产出（测 R8 防线）。"""

    def __init__(self, docs, *, state_md=False, draft=False):
        self.docs = docs                # [judgment doc | None, ...]  None=空产出
        self.state_md = state_md        # 是否模拟观察者写 STATE.md
        self.draft = draft
        self.calls = 0

    def copy_observer_kit(self, root):
        (Path(root) / ".observer").mkdir(parents=True, exist_ok=True)

    def clear_judgment(self, root):
        p = Path(root) / ".observer" / "OBSERVER.json"
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

    def run_once(self, root, task_sheet):
        self.calls += 1
        doc = self.docs[min(self.calls - 1, len(self.docs) - 1)]
        if doc is not None:
            (Path(root) / ".observer").mkdir(parents=True, exist_ok=True)
            (Path(root) / ".observer" / "OBSERVER.json").write_text(
                json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        if self.state_md:
            (Path(root) / "STATE.md").write_text(
                "# STATE（观察者）\n\n## 下轮建议\n- 主攻 authc 面\n", encoding="utf-8")
        if self.draft:
            (Path(root) / "notes").mkdir(parents=True, exist_ok=True)
            (Path(root) / "notes" / "prior-intel-draft.md").write_text(
                "# 下次任务前置情报\n", encoding="utf-8")
        return {"stop_reason": "end_turn", "tokens": 123,
                "total_cost_usd": 0.01, "turns": 3, "is_error": False, "error": ""}


def _res(**kw):
    base = dict(session_id="s1", stop_reason="end_turn", turns=5, tokens=1000,
                total_cost_usd=0.02, handoff="已完成：x", final_text="",
                is_error=False, resumes=0)
    base.update(kw)
    return AgentResult(**base)


def _noop_observer():
    return FakeObserver([{"round": 1, "operations": []}])


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AT1_PROVIDER", "glm")
    monkeypatch.setenv("AT1_API_KEY", "sk-test-1234567890")


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
    """R8 防线：首轮空产出（观察者白跑）→ 重试一次 → 判断书到位 → 正常入图。"""
    _mk_engagement(tmp_path)
    fake = FakeRunner([
        (_res(), {"idor.md": "# [发现] 越权读取\n实证：13800138000"}, {}, {}),
    ])
    monkeypatch.setattr(driver_mod.runner, "run", fake)
    obs = FakeObserver([
        None,                                              # 第一轮：空产出
        {"round": 1, "operations": [
            {"op": "add_finding", "summary": "越权读取",
             "report": "findings/idor.md", "severity": "high", "reason": "实证"}]},
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
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    assert any(e["type"] == "observer_empty_retry" and e["data"]["stage"] == "retry"
               for e in evs)
    assert not any(e["type"] == "observer_empty_retry"
                   and e["data"]["stage"] == "exhausted" for e in evs)
    assert any(e["type"] == "observer_applied" for e in evs)
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


def test_dir_diff_new_and_changed(tmp_path):
    """目录级 diff：新文件入清单；指纹变化（改旧文件）也入清单；无变化不报。"""
    import os
    from src import board as board_mod
    bb = board_mod.Blackboard()
    f1 = tmp_path / "findings" / "a.md"
    f1.parent.mkdir(parents=True)
    f1.write_text("v1", encoding="utf-8")
    out1 = driver_mod._dir_diff(tmp_path, bb)
    assert [o["path"] for o in out1] == ["findings/a.md"]
    out2 = driver_mod._dir_diff(tmp_path, bb)               # 无变化
    assert out2 == []
    f1.write_text("v2-content", encoding="utf-8")           # 改旧文件 → 指纹变
    st = f1.stat()
    os.utime(f1, ns=(st.st_atime_ns + 10_000_000, st.st_mtime_ns + 10_000_000))
    (tmp_path / "facts").mkdir()
    (tmp_path / "facts" / "b.md").write_text("x", encoding="utf-8")
    out3 = driver_mod._dir_diff(tmp_path, bb)
    paths = {o["path"] for o in out3}
    assert paths == {"findings/a.md", "facts/b.md"}         # 改旧+新增都报
    flags = {o["path"]: o["changed"] for o in out3}
    assert flags["findings/a.md"] is True                   # 改过的标 changed
    assert flags["facts/b.md"] is False                     # 新文件非 changed


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
