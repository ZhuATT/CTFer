"""writeback 单测（P4.6）：表尾追加幂等 / 深度刷新只升不降 / draft 生成 / 配方0 反向读。"""

from src.board import Blackboard
from src.writeback import (append_status_row, gen_prior_intel_draft,
                           parse_immune_from_status, parse_status_findings,
                           refresh_surface_depth)

_STATUS = """# Status

## 漏洞表
| ID | 等级 | 标题 | 证据 |
|---|---|---|---|
| F-old | 高 | 旧发现 | evidence/old.md (r1) |

## 攻击面
| 功能/端点 | 深度 | 测过什么 | 结论/免疫 |
|---|---|---|---|
| /api/login | seen | 首页发现 | - |
| /search | tested | 单引号探测 | 有报错 |

## 已确认非漏洞
- /api/login（authbypass——403，2026-08-24）
- /health 接口无需鉴权属设计内

## 阻断项
（无）
"""


def _status(tmp_path):
    p = tmp_path / "status.md"
    p.write_text(_STATUS, encoding="utf-8")
    return str(p)


def test_append_row_at_table_tail(tmp_path):
    p = _status(tmp_path)
    ok, why = append_status_row(p, {"id": "F-001", "severity": "high",
                                    "summary": "SQL注入", "evidence": "evidence/s.md",
                                    "round": 2})
    assert ok and why == "appended"
    txt = open(p, encoding="utf-8").read()
    # 新行在旧行之后、攻击面段之前（表尾）
    assert txt.index("F-old") < txt.index("F-001") < txt.index("## 攻击面")


def test_append_idempotent(tmp_path):
    p = _status(tmp_path)
    append_status_row(p, {"id": "F-001", "severity": "high", "summary": "x",
                          "evidence": "e.md", "round": 1})
    ok, why = append_status_row(p, {"id": "F-001", "severity": "high", "summary": "x",
                                    "evidence": "e.md", "round": 1})
    assert ok and why == "already-present"
    assert open(p, encoding="utf-8").read().count("F-001") == 1


def test_append_missing_anchor_fails_gracefully(tmp_path):
    p = tmp_path / "status.md"
    p.write_text("# 随便的文件没有锚点\n", encoding="utf-8")
    ok, why = append_status_row(str(p), {"id": "F-1", "summary": "", "evidence": ""})
    assert not ok and "锚点" in why


def test_refresh_depth_only_upgrades(tmp_path):
    p = _status(tmp_path)
    bb = Blackboard()
    f = bb.create_node("finding", {"summary": "sqli", "severity": "high"},
                       endpoint="/search", origin="worker", round=1)
    bb.update_node(f, state="confirmed")
    ok, why = refresh_surface_depth(p, bb)
    assert ok
    txt = open(p, encoding="utf-8").read()
    assert "| /search | deep |" in txt
    assert "| /api/login | seen |" in txt      # 未覆盖的不动

    # 降级保护：无 confirmed 时 deep 不退回 seen
    bb2 = Blackboard()
    refresh_surface_depth(p, bb2)
    assert "| /search | deep |" in open(p, encoding="utf-8").read()


def test_refresh_missing_anchor_tolerant(tmp_path):
    p = tmp_path / "status.md"
    p.write_text("no anchors\n", encoding="utf-8")
    ok, why = refresh_surface_depth(str(p), Blackboard())
    assert not ok and "宽容" in why


def test_draft_generation(tmp_path):
    bb = Blackboard()
    f = bb.create_node("finding", {"summary": "sqli", "severity": "high",
                                   "evidence": "evidence/s.md"},
                       endpoint="/search", origin="worker", round=1)
    bb.update_node(f, state="confirmed")
    bb.create_node("fact", {"value": "身份靠cookie派生", "evidence": "evidence/identity.md"},
                   origin="worker", round=1)                    # global 桶
    d = bb.create_node("intent", {"goal": "[已确认非漏洞] /api/login",
                                  "note": "403"}, endpoint="/api/login",
                       origin="user", round=0)
    bb.update_node(d, state="done")                             # → 阴性视图
    bb.create_node("fact", {"value": "线索"}, endpoint="/api/order",
                   origin="worker", round=1)                    # 未测面
    bb.add_intel("目标无 WAF", 1)
    bb.record_handoff("已完成：侦察；未竟：idor 面")
    out = gen_prior_intel_draft(str(tmp_path), bb, stop_reason="预算耗尽")
    txt = out.read_text(encoding="utf-8")
    assert "预算耗尽" in txt and "F-001" in txt and "身份靠cookie派生" in txt
    assert "/api/login" in txt and "/api/order" in txt and "未竟：idor 面" in txt
    assert "目标无 WAF" in txt


def test_parse_status_findings_seeds():
    """配方 0：漏洞表行 → finding 播种素材（人拍板,origin=user）。"""
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "status.md")
        open(p, "w", encoding="utf-8").write(_STATUS)
        rows = parse_status_findings(p)
        assert len(rows) == 1
        assert rows[0]["id"] == "F-old" and rows[0]["severity"] == "high"
        assert rows[0]["summary"] == "旧发现" and "old.md" in rows[0]["evidence"]


def test_parse_immune_seeds():
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "status.md")
        open(p, "w", encoding="utf-8").write(_STATUS)
        imm = parse_immune_from_status(p)
        eps = [i["endpoint"] for i in imm]
        assert "/api/login" in eps and "/health" in eps
        # 段外内容不进（漏洞表的 /api/login 是 seen 行——只解析列表行，表格行跳过）
        assert all(i["status"] for i in imm)


def test_promote_reports(tmp_path):
    """配方 2 报告晋升：confirmed 报告 .auto/reports → reports；dismissed 不升；幂等。"""
    from src.writeback import promote_reports
    auto = tmp_path / ".auto" / "reports"
    auto.mkdir(parents=True)
    (auto / "F-001.md").write_text("# 报告", encoding="utf-8")
    (auto / "F-002.md").write_text("# 被拒报告", encoding="utf-8")
    bb = Blackboard()
    f = bb.create_node("finding", {"summary": "s", "report": "reports/F-001.md"},
                       origin="worker", round=1, id="F-001")
    bb.update_node(f, state="confirmed")
    f2 = bb.create_node("finding", {"summary": "t", "report": "reports/F-002.md"},
                        origin="worker", round=1, id="F-002")
    bb.update_node(f2, state="dismissed")
    n = promote_reports(str(tmp_path), bb)
    assert n == 1
    assert (tmp_path / "reports" / "F-001.md").read_text(encoding="utf-8") == "# 报告"
    assert not (tmp_path / "reports" / "F-002.md").exists()
    assert promote_reports(str(tmp_path), bb) == 0          # 幂等


def test_sync_human_ledger_moves_and_dedups(tmp_path):
    """P-6：.auto/log.jsonl → state/log.jsonl 收尾搬运；去重追加幂等。"""
    from src.writeback import sync_human_ledger
    auto = tmp_path / ".auto"
    (tmp_path / "state").mkdir(parents=True)
    auto.mkdir()
    # 无源 → no ledger
    assert sync_human_ledger(str(tmp_path)) == (False, "no ledger")
    (auto / "log.jsonl").write_text(
        '{"ts":"t1","cmd":"curl /x","endpoint":"/x","result":"200"}\n'
        '{"ts":"t2","cmd":"curl /y","endpoint":"/y","result":"403"}\n', encoding="utf-8")
    ok, why = sync_human_ledger(str(tmp_path))
    assert ok and "appended 2" in why
    dst = (tmp_path / "state" / "log.jsonl").read_text(encoding="utf-8")
    assert '"cmd":"curl /x"' in dst and '"cmd":"curl /y"' in dst
    # 续跑：源文件长了一行，旧两行不重复
    (auto / "log.jsonl").write_text(
        '{"ts":"t1","cmd":"curl /x","endpoint":"/x","result":"200"}\n'
        '{"ts":"t2","cmd":"curl /y","endpoint":"/y","result":"403"}\n'
        '{"ts":"t3","cmd":"curl /z","endpoint":"/z","result":"500"}\n', encoding="utf-8")
    ok, why = sync_human_ledger(str(tmp_path))
    assert ok and "appended 1" in why
    dst = (tmp_path / "state" / "log.jsonl").read_text(encoding="utf-8")
    assert dst.count('"cmd":"curl /x"') == 1 and '"cmd":"curl /z"' in dst
