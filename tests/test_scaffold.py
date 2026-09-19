"""scaffold v3 单测：三槽渲染自簿记 / 播种规矩(§11) / 一致性锁 / workdir 展开。

T3.4 一致性锁（ARTEX/Cairn 之长取其锁）：汇编 §3.1/§3.2 定稿段与 scaffolding
落位文件**逐字一致**——漂移即红（改手册必须两边同 commit）。
"""

import json
from pathlib import Path

import pytest

from src import scaffold
from src.board import Blackboard

REPO = Path(__file__).resolve().parent.parent
_MANUAL_HEADER = ("### 3.1 WORKER-CLAUDE.md 全文(定稿 09-18,施工原样落位 scaffolding/;"
                  "渲染槽 {target}/{hint}/{env_bg})")
_FORMATS_HEADER = "### 3.2 FORMATS.md 全文(定稿 09-18,施工原样落位 scaffolding/)"


def _eng(**kw) -> dict:
    base = {"target": "https://example.com", "goal": "拿到一个可确认的未授权访问",
            "hint": "证书自签记得 -k",
            "scope": {"allow": ["example.com"], "deny": []}, "credentials": {}}
    base.update(kw)
    return base


# ── 一致性锁（T3.4） ──────────────────────────────────────────────────────

def _assembly_section(header: str) -> str:
    doc = (REPO / "docs" / "prompt-全文汇编.md").read_text(encoding="utf-8")
    lines = doc.split("\n")
    i = lines.index(header)
    j = i + 1
    while lines[j].strip() == "":
        j += 1
    assert lines[j] == "````markdown", f"汇编围栏形态漂移：{lines[j]!r}"
    k = j + 1
    out = []
    while lines[k] != "````":
        out.append(lines[k])
        k += 1
    return "\n".join(out)


def test_assembly_lock_manual():
    """锁③a：汇编 §3.1 定稿段 ↔ scaffolding/WORKER-CLAUDE.md 逐字一致。"""
    locked = _assembly_section(_MANUAL_HEADER)
    live = (REPO / "scaffolding" / "WORKER-CLAUDE.md").read_text(encoding="utf-8")
    assert locked == live


def test_assembly_lock_formats():
    """锁③b：汇编 §3.2 定稿段 ↔ scaffolding/FORMATS.md 逐字一致。"""
    locked = _assembly_section(_FORMATS_HEADER)
    live = (REPO / "scaffolding" / "FORMATS.md").read_text(encoding="utf-8")
    assert locked == live


def test_template_slots_exact():
    """锁①：模板三槽齐全；被裁的 v2 槽（allow/deny_list/mission/tools_root）不得复活。"""
    tmpl = (REPO / "scaffolding" / "WORKER-CLAUDE.md").read_text(encoding="utf-8")
    for slot in ("{target}", "{hint}", "{env_bg}"):
        assert slot in tmpl
    for dead in ("{allow}", "{deny_list}", "{mission}", "{tools_root}"):
        assert dead not in tmpl


# ── 播种（schema §11） ───────────────────────────────────────────────────

def test_seed_engagement_empty_fill_and_no_overwrite():
    """target/goal/hint 空则播；续跑已有值不覆盖；scope 每次覆盖。"""
    bb = Blackboard()
    scaffold.seed_engagement(_eng(goal="拿到域管", hint="证书自签"), bb)
    assert bb.bookkeeping["target"] == "https://example.com"
    assert bb.goal["text"] == "拿到域管"
    assert bb.bookkeeping["hint"] == "证书自签"
    # 续跑：goal-set 改过的目标 / 已有 hint 不被 engagement 冲掉
    bb.set_goal("新的完成标准", round=3)
    bb.bookkeeping["hint"] = "运行中改的指示"
    scaffold.seed_engagement(_eng(goal="旧目标", hint="旧指示"), bb)
    assert bb.goal["text"] == "新的完成标准"
    assert bb.bookkeeping["hint"] == "运行中改的指示"
    # scope：每次覆盖（边界以最新委托为准）
    bb.bookkeeping["scope"] = {"allow": ["old"]}
    scaffold.seed_engagement(_eng(scope={"allow": ["new"]}), bb)
    assert bb.bookkeeping["scope"]["allow"] == ["new"]


def test_load_engagement_requires_goal_and_hint(tmp_path):
    """§11 必填三件：target/goal 非空 + hint 字段在场——缺一拒启（hint 值可空串）。"""
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "x", "goal": "g"}), encoding="utf-8")           # 缺 hint
    with pytest.raises(ValueError, match="hint"):
        scaffold.load_engagement(tmp_path)
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "x", "hint": ""}), encoding="utf-8")            # 缺 goal
    with pytest.raises(ValueError, match="goal"):
        scaffold.load_engagement(tmp_path)
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "x", "goal": "g", "hint": ""}), encoding="utf-8")  # hint 空串合法
    assert scaffold.load_engagement(tmp_path)["target"] == "x"


# ── workdir 展开 ─────────────────────────────────────────────────────────

def test_expand_renders_from_bookkeeping(tmp_path):
    """槽值从黑板簿记取（运行时唯一真相），渲染产物零残留槽。"""
    bb = Blackboard()
    scaffold.seed_engagement(_eng(hint="证书自签记得 -k"), bb)
    wd = scaffold.expand(tmp_path, _eng(), bb)
    claude = (wd / "CLAUDE.md").read_text(encoding="utf-8")
    assert "https://example.com" in claude
    assert "证书自签记得 -k" in claude
    assert "Start-Process" in claude and "bg-*.log" in claude   # {env_bg} 注入
    for leftover in ("{target}", "{hint}", "{env_bg}", "{"):
        assert leftover not in claude               # 锁②：渲染零残留槽
    assert "旧 mission 字段已废" not in claude       # mission 字段废除


def test_expand_creates_full_workdir_v3(tmp_path):
    _mk = Blackboard()
    scaffold.seed_engagement(_eng(), _mk)
    wd = scaffold.expand(tmp_path, _eng(), _mk)
    for name in ("CLAUDE.md", "FORMATS.md", ".mcp.json", "FINDINGS", "FACTS",
                 "evidence", "reports", "src标准"):
        assert (wd / name).exists(), name
    assert not (wd / "DIRECTIONS").exists()         # A17③：写面退役，不预创建
    assert "FORMATS.md" in (wd / "FINDINGS").read_text(encoding="utf-8")
    assert "DIRECTIONS" not in (wd / "FINDINGS").read_text(encoding="utf-8")
    fmt = (wd / "FORMATS.md").read_text(encoding="utf-8")
    assert "derived_from|sources|yields" in fmt          # chain 三动词教学
    assert "不归你声明" in fmt                            # same_root 判重归观察者（禁令句在）


def test_expand_cleans_legacy_direactions(tmp_path):
    """旧 engagement 遗留 DIRECTIONS 文件——展开时清理（防误导新会话）。"""
    wd = tmp_path / ".auto"
    wd.mkdir(parents=True)
    (wd / "DIRECTIONS").write_text('{"id":"D-001","goal":"旧方向"}\n', encoding="utf-8")
    bb = Blackboard()
    scaffold.seed_engagement(_eng(), bb)
    scaffold.expand(tmp_path, _eng(), bb)
    assert not (wd / "DIRECTIONS").exists()


# ── fail-fast（§11：只剩 target） ────────────────────────────────────────

def test_load_engagement_failfast_target_only(tmp_path):
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "x", "goal": "g", "hint": ""}), encoding="utf-8")   # 无 scope/goal 外字段——不炸
    eng = scaffold.load_engagement(tmp_path)
    assert eng["target"] == "x"
    (tmp_path / "engagement.json").write_text(
        json.dumps({"mission": "没有 target"}), encoding="utf-8")
    with pytest.raises(ValueError):
        scaffold.load_engagement(tmp_path)


# ── 原有保留行为 ─────────────────────────────────────────────────────────

def test_expand_copies_skills_and_credentials(tmp_path):
    skills = tmp_path / "myskills" / "hello-skill"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").write_text("---\nname: hello-skill\ndescription: t\n---\nx",
                                     encoding="utf-8")
    (tmp_path / "cred.json").write_text("{}", encoding="utf-8")
    eng = _eng(credentials={"storage_state": "cred.json"})
    bb = Blackboard()
    scaffold.seed_engagement(eng, bb)
    wd = scaffold.expand(tmp_path, eng, bb, skills_src=str(tmp_path / "myskills"))
    assert (wd / ".claude" / "skills" / "hello-skill" / "SKILL.md").is_file()
    assert (wd / "storage-state.json").read_text(encoding="utf-8") == "{}"
