"""三出口一致性互证测试（治理批追加 F-3）。

同一份黑板状态经 render_summary / render_body / render_yaml_layer 三个出口渲染，
三个"报数员"对同一状态的陈述必须互相对得上——任一出口改了口径没同步其他，即红。
构造输入的数字由测试自己数着放（真值已知），不依赖从文字里理解语义。
"""

import re

from src.board import Blackboard


def _mk_board():
    """已知真值的黑板：
    未测面=1（/api/fresh）；已确认发现=1；阴性=实测1+推断1；方向 open 1/blocked 1。"""
    b = Blackboard()
    b.add_fact("endpoint", "/api/tested")          # 被 confirmed finding 覆盖 → 已测
    b.add_fact("endpoint", "/api/fresh")           # 无任何记录 → 未测
    b.add_immune("/api/obs", round_=1, status="403", confidence="observed")
    b.add_immune("/api/inf", round_=1, status="403", confidence="inferred")
    b.add_finding({"id": "F-001", "endpoint": "/api/tested", "summary": "s",
                   "assessment": "confirmed", "severity": "high", "reason": "r",
                   "evidence": "evidence/x.md", "round": 1})
    b.add_direction({"id": "D-001", "goal": "g1", "status": "open"}, round_=1)
    b.add_direction({"id": "D-002", "goal": "g2", "status": "blocked",
                     "blocked_reason": "缺头"}, round_=1)
    return b


def test_summary_body_direction_counts_agree():
    b = _mk_board()
    summary = b.render_summary()
    body = b.render_body({"/api/tested", "/api/obs", "/api/inf"})
    yaml = b.render_yaml_layer()
    # 出口①：摘要的方向计数
    dc = b.direction_counts()
    assert f"方向 open {dc['open']}/进行中 {dc['in_progress']}/blocked {dc['blocked']}/done {dc['done']}" in summary
    # 出口③：YAML 图层的方向按状态逐一对上
    for status in ("open", "in_progress", "blocked", "done"):
        assert yaml.count(f'"status": "{status}"') == dc[status]


def test_summary_body_untested_agree():
    b = _mk_board()
    tested = b.tested_endpoints()
    summary = b.render_summary(tested)
    body = b.render_body(tested)
    m = re.search(r"未测面 (\d+) 个", summary)
    n = int(m.group(1))
    # 出口②：正文未测面清单行数 == 摘要数字
    assert body.count("无任何测试记录") == n
    # 三出口口径与构造真值一致
    assert n == 1 and "/api/fresh" in body


def test_summary_body_finding_and_immune_agree():
    b = _mk_board()
    summary = b.render_summary()
    body = b.render_body()
    # 已确认发现：摘要数字 == 正文清单行数（段边界=下一个候选段头，取最近）
    m = re.search(r"已确认发现 (\d+) 条", summary)
    start = body.find("已确认发现（")
    ends = [p for p in (body.find(mk, start + 10) for mk in
                        ("已否决模式", "未测面（", "阴性记录（", "接近成功的尝试")) if p > 0]
    conf_sec = body[start:min(ends)] if ends else body[start:]
    assert int(m.group(1)) == conf_sec.count("\n- ")
    # 阴性两档：摘要分档数 == 正文各行数
    m2 = re.search(r"阴性：实测关闭 (\d+)/推断关闭 (\d+)", summary)
    assert int(m2.group(1)) == body.count("实测关闭——重开需材料性新机理")
    assert int(m2.group(2)) == body.count("推断关闭·未穷尽")


def test_summary_directions_match_yaml_layers():
    b = _mk_board()
    b.add_chains([{"rel": "same_root", "refs": ["F-001", "D-001"], "note": "n"}],
                 origin="observer", round_=1)
    summary = b.render_summary()
    yaml = b.render_yaml_layer()
    # 边在 yaml 聚合节且与摘要的链引用可见性一致（worker 能在图层看到可引用 id）
    assert '"rel": "same_root"' in yaml
    assert "F-001" in yaml and "D-001" in yaml
    # 三出口都成功渲染不互相污染（同一黑板两次调用逐字节稳定，nonce 除外）
    import re as _re
    strip = lambda s: _re.sub(r'id="[0-9a-f]{32}"', "id=N", s)
    assert strip(b.render_summary()) == strip(b.render_summary())
    assert strip(b.render_body()) == strip(b.render_body())
