"""观察者通道单测（批4 C6）：模型通道配置隔离 / submit CLI 两剧本 / guard role=observer。"""

import json
import os
from pathlib import Path

import pytest

from src.board import Blackboard
from src.observer import build_solver


# ── 模型通道（A23 双角色可配；批4 G5） ───────────────────────────────────

def test_build_solver_observer_overrides_and_restore(monkeypatch):
    """观察者通道可独立配置；用完还原，不污染 worker 的 AT1_*。"""
    monkeypatch.setenv("AT1_PROVIDER", "deepseek")           # worker 侧（假象）
    monkeypatch.setenv("AT1_API_KEY", "sk-worker-000")
    monkeypatch.setenv("AT1_OBSERVER_PROVIDER", "glm")
    monkeypatch.setenv("AT1_OBSERVER_API_KEY", "sk-observer-111")
    from src.observer import build_solver
    cfg = build_solver()
    assert cfg.provider == "glm"
    assert cfg.api_key == "sk-observer-111"
    assert os.environ["AT1_PROVIDER"] == "deepseek"          # 还原
    assert os.environ["AT1_API_KEY"] == "sk-worker-000"


def test_build_solver_llm_key_fallback(monkeypatch):
    """AT1_OBSERVER_API_KEY 缺席时用 LLM_API_KEY 兜底（deepseek 同 key 双通道）。"""
    monkeypatch.setenv("LLM_API_KEY", "sk-llm-222")
    monkeypatch.delenv("AT1_OBSERVER_API_KEY", raising=False)
    monkeypatch.delenv("AT1_API_KEY", raising=False)
    monkeypatch.delenv("AT1_PROVIDER", raising=False)
    from src.observer import build_solver
    cfg = build_solver()
    assert cfg.provider == "deepseek"
    assert cfg.api_key == "sk-llm-222"


# ── submit CLI（两剧本） ─────────────────────────────────────────────────

def _mk_obs_env(root: Path, *, noreport_rejects=(), judgment=None):
    (root / ".at1").mkdir(parents=True, exist_ok=True)
    (root / ".observer").mkdir(parents=True, exist_ok=True)
    bb = Blackboard(str(root / ".at1" / "blackboard.json"))
    bb.save()
    (root / ".observer" / "task.json").write_text(
        json.dumps({"noreport_rejects": list(noreport_rejects)}), encoding="utf-8")
    if judgment is not None:
        (root / ".observer" / "OBSERVER.json").write_text(
            json.dumps(judgment, ensure_ascii=False), encoding="utf-8")


def test_submit_accepts_valid_book(tmp_path):
    from src.submit import main
    _mk_obs_env(tmp_path, judgment={"round": 1, "operations": [
        {"op": "add_fact", "summary": "x", "evidence": "facts/x.md"}]})
    rc = main(str(tmp_path))
    assert rc == 0
    assert (tmp_path / ".observer" / "SUBMITTED").is_file()


def test_submit_rejects_illegal_op(tmp_path):
    from src.submit import main
    _mk_obs_env(tmp_path, judgment={"round": 1, "operations": [
        {"op": "set_state", "id": "D-001", "state": "blocked", "reason": ""}]})
    rc = main(str(tmp_path))
    assert rc == 1
    assert not (tmp_path / ".observer" / "SUBMITTED").exists()


def test_submit_idempotent_resubmit(tmp_path):
    """重放安全：同一判断书提交两次，图内不重复。"""
    from src.submit import main
    from src.board import Blackboard
    _mk_obs_env(tmp_path, judgment={"round": 1, "operations": [
        {"op": "add_fact", "summary": "x", "evidence": "facts/x.md"}]})
    assert main(str(tmp_path)) == 0
    bb1 = Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    n1 = len(bb1.graph["nodes"])
    assert main(str(tmp_path)) == 0                 # 二次提交仍成功（幂等吸收）
    bb2 = Blackboard(str(tmp_path / ".at1" / "blackboard.json"))
    assert len(bb2.graph["nodes"]) == n1            # 图不膨胀


# ── guard role=observer（driver 接线） ───────────────────────────────────

def test_observer_guard_violation_role(tmp_path, monkeypatch):
    """观察者工具调用过 guard：违规事件带 role=observer（只记不拦）。"""
    from src import driver as driver_mod
    from src.runner import AgentResult, ToolEvent

    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    (tmp_path / "notes").mkdir(parents=True, exist_ok=True)
    (tmp_path / "notes" / "prior-intel.md").write_text("x", encoding="utf-8")
    (tmp_path / "engagement.json").write_text(json.dumps({
        "target": "https://example.com", "goal": "g", "hint": "",
        "scope": {"allow": ["example.com"], "deny": []}}), encoding="utf-8")
    monkeypatch.setenv("AT1_PROVIDER", "glm")
    monkeypatch.setenv("AT1_API_KEY", "sk-test-000")

    class FakeRunner:
        def __call__(self, prompt, workdir, solver, task, **kw):
            return AgentResult(session_id="s", stop_reason="end_turn", turns=1,
                               tokens=1, handoff="", final_text="",
                               is_error=False, resumes=0, total_cost_usd=0.0)
    monkeypatch.setattr(driver_mod.runner, "run", FakeRunner())

    class FakeObs:
        calls = 0
        doc = {"round": 1, "operations": [
            {"op": "add_fact", "summary": "x", "evidence": "facts/x.md"}]}

        def copy_observer_kit(self, root):
            pass

        def clear_judgment(self, root):
            pass

        def read_judgment(self, root):
            return self.doc

        def submitted(self, root):
            return True

        def run_once(self, root, task_sheet, *, on_tool=None,
                     resume_session_id=None, feedback=None):
            FakeObs.calls += 1
            if on_tool is not None:
                on_tool(ToolEvent(tool="Write",
                                  args={"file_path": str(Path(root) / ".at1" / "x.json")},
                                  output=""))
            return {"stop_reason": "end_turn", "tokens": 5,
                    "total_cost_usd": 0.001, "turns": 1, "is_error": False,
                    "error": "", "session_id": "obs-s1"}

    fake_obs = FakeObs()
    monkeypatch.setattr(driver_mod.observer, "copy_observer_kit", fake_obs.copy_observer_kit)
    monkeypatch.setattr(driver_mod.observer, "clear_judgment", fake_obs.clear_judgment)
    monkeypatch.setattr(driver_mod.observer, "run_once", fake_obs.run_once)
    monkeypatch.setattr(driver_mod.observer, "read_judgment", fake_obs.read_judgment)
    monkeypatch.setattr(driver_mod.observer, "submitted", fake_obs.submitted)

    rc = driver_mod.run_engagement(str(tmp_path), budget_s=120, max_rounds=1)
    assert rc == 0
    evs = [json.loads(l) for l in
           (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip()]
    gv = [e for e in evs if e["type"] == "guard_violation" and e["data"].get("role") == "observer"]
    assert gv, "观察者越界写 .at1 必须产生 guard 事件（role=observer）"
    assert gv[0]["data"]["kind"] == "controller_zone"
