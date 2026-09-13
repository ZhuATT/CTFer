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


# ── phase5 B2：三账本注释头 + 新契约文本 ─────────────────────────────────

def test_ledger_files_created_with_headers(tmp_path):
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    for name in ("FINDINGS", "FACTS", "DIRECTIONS"):
        p = wd / name
        assert p.is_file(), name
        txt = p.read_text(encoding="utf-8")
        assert txt.startswith("#"), f"{name} 缺注释头"
        assert "{" in txt          # 含 JSON 格式示例


def test_worker_contract_texts(tmp_path):
    """B2 契约断言：C-1 上报门槛 / 7-kind+confidence / DIRECTIONS 生命周期 / D 三条。"""
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    txt = (wd / "CLAUDE.md").read_text(encoding="utf-8")
    # C-1 上报硬门槛
    assert "真实触发过" in txt and "可复现证据" in txt
    assert "漏洞库推断" in txt and "inferred" in txt
    # FACTS：7 kind 菜单 + confidence 语义 + 否定门槛
    for k in ("endpoint", "credential", "kv_secret", "fingerprint",
              "identity_model", "business_context", "unclassified"):
        assert k in txt
    assert "observed" in txt and "inferred" in txt              # confidence 二值语义进纪律层
    assert "没穷尽手段" in txt                                   # 否定结论门槛
    # DIRECTIONS 契约：开工先读 + 生命周期 + 自主权话术
    assert "接手 open/blocked" in txt and "高于开新方向" in txt
    assert "in_progress" in txt and "blocked_reason" in txt
    assert "不是派工单" in txt                                   # 自主权（接单员化缓解 G-2）
    # D 三条
    assert "材料性新机理" in txt                                 # DEC-5 重开标准
    assert "不写 /tmp" in txt                                    # DEC-6
    assert "立刻写" in txt                                       # DEC-8 即时写
    # chain 契约（A-1）
    assert "derived_from" in txt and "same_root" in txt and "combines" in txt
    assert "F-xxx/D-xxx" in txt or "F-/D-" in txt.replace("只能指 F-/D-", "F-xxx/D-xxx")


def test_ledger_headers_idempotent(tmp_path):
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    (wd / "DIRECTIONS").write_text('{"id":"D-001","goal":"已有方向","status":"open","round":1}\n',
                                   encoding="utf-8")
    expand(tmp_path, eng)                                        # 二次展开
    t = (wd / "DIRECTIONS").read_text(encoding="utf-8")
    assert '{"id":"D-001"}' not in t and "已有方向" in t         # 已有内容不被注释头覆盖
    assert not t.startswith("#")                                 # 不重复盖头


def test_state_md_readonly_declared(tmp_path):
    """治理批#4：STATE.md 只读声明进纪律层。"""
    _mk_engagement(tmp_path)
    eng = load_engagement(tmp_path)
    wd = expand(tmp_path, eng)
    txt = (wd / "CLAUDE.md").read_text(encoding="utf-8")
    assert "STATE.md 是系统投影" in txt and "只读" in txt
