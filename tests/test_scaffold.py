"""scaffold 展开单测（P4.1）。"""

import json

from src.scaffold import expand, load_engagement


def _mk_engagement(root, *, deny=None, storage_state=None):
    (root / "engagement.json").write_text(json.dumps({
        "target": "https://example.com", "mission": "授权测试",
        "date": "2026-08-30",
        "scope": {"allow": ["example.com", "*.example.com"], "deny": deny or []},
        "credentials": ({"storage_state": storage_state} if storage_state else {}),
    }), encoding="utf-8")


def test_expand_creates_full_workdir(tmp_path):
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    assert (wd / "CLAUDE.md").is_file()          # 落位名是 CLAUDE.md（CLI 自动加载）
    assert (wd / ".mcp.json").is_file()
    assert (wd / "FINDINGS").is_file() and (wd / "FACTS").is_file()
    assert (wd / "evidence").is_dir()
    txt = (wd / "CLAUDE.md").read_text(encoding="utf-8")
    assert "https://example.com" in txt and "授权测试" in txt
    assert "example.com" in txt and "*.example.com" in txt


def test_expand_renders_deny_list(tmp_path):
    _mk_engagement(tmp_path, deny=["admin.example.com"])
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    txt = (wd / "CLAUDE.md").read_text(encoding="utf-8")
    assert "admin.example.com" in txt


def test_expand_idempotent_preserves_ledgers(tmp_path):
    """幂等：二次展开不覆盖已有 FINDINGS/evidence（发现即落盘保证）。"""
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    (wd / "FINDINGS").write_text('{"id":"F-001"}\n', encoding="utf-8")
    (wd / "evidence" / "x.md").write_text("ev", encoding="utf-8")
    expand(tmp_path, eng)
    assert '{"id":"F-001"}' in (wd / "FINDINGS").read_text(encoding="utf-8")
    assert (wd / "evidence" / "x.md").is_file()


def test_expand_copies_storage_state(tmp_path):
    ss = tmp_path / "storage-states" / "example.json"
    ss.parent.mkdir()
    ss.write_text('{"cookies":[]}', encoding="utf-8")
    _mk_engagement(tmp_path, storage_state="storage-states/example.json")
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    assert json.loads((wd / "storage-state.json").read_text(encoding="utf-8")) == {"cookies": []}


def test_expand_skills_optional(tmp_path):
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    src = tmp_path / "skills_src"
    (src / "api-all").mkdir(parents=True)
    (src / "api-all" / "SKILL.md").write_text("x", encoding="utf-8")
    wd = expand(tmp_path, eng, skills_src=src)
    assert (wd / ".claude" / "skills" / "api-all" / "SKILL.md").is_file()
    # 不给 skills_src → 不建目录，路由表降级
    e2 = tmp_path / "e2"
    e2.mkdir()
    _mk_engagement(e2)
    wd2 = expand(e2, load_engagement(e2))
    assert not (wd2 / ".claude").exists()


def test_load_engagement_fail_fast(tmp_path):
    # 缺文件
    try:
        load_engagement(tmp_path)
        assert False, "应拒启"
    except FileNotFoundError:
        pass
    # 缺 scope.allow
    (tmp_path / "engagement.json").write_text(
        json.dumps({"target": "https://x.com"}), encoding="utf-8")
    try:
        load_engagement(tmp_path)
        assert False, "应拒启"
    except ValueError as e:
        assert "allow" in str(e)
