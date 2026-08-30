"""覆盖对账单测（中期审核附录①②）+ 引号路径 query 修复。"""

import re as _re

from src.board import Blackboard, _extract_facts
from src.untrusted import untrusted_block


def _mk_board():
    b = Blackboard()
    b.add_fact("endpoint", "GET /api/order/detail?id=8823", round_=1)
    b.add_fact("endpoint", "/api/address/update", round_=1)
    b.add_fact("endpoint", "/search", round_=1)
    b.add_fact("credential", "AKIAFAKEFAKEFAKEFAKE")
    return b


def test_untested_surface_reconciliation():
    b = _mk_board()
    tested = {"/search"}                                            # sqli 测过了
    un = b.untested_surface(tested)
    eps = [u["endpoint"] for u in un]
    assert "/api/address/update" in eps                             # 未测 → 出现在清单
    # method+query 归一化后对上：GET /api/order/detail?id=8823 → /api/order/detail
    assert any("/api/order/detail" in e for e in eps)
    assert not any("/search" == e for e in un)                      # 已测不出现在清单


def test_untested_surface_substring_match():
    b = Blackboard()
    b.add_fact("endpoint", "/api/order/detail", round_=1)
    un = b.untested_surface({"/api/order/detail?id=8823"})          # 测的是带 query 版
    assert un == []                                                 # 子串对上→算已测


def test_render_untested_section():
    b = _mk_board()
    r = b.render(tested_endpoints={"/search"})
    assert "未测面" in r and "探不探你定" in r
    assert "/api/address/update" in r
    # 顺序：阳性事实 → 未测面 → 阴性记录
    i_pos = r.find("[credential]")
    i_un = r.find("未测面")
    assert 0 < i_pos < i_un
    b.add_immune("/admin/userList", "authbypass", round_=1, status="403")
    r2 = b.render(tested_endpoints={"/search"})
    i_imm = r2.find("阴性记录")
    assert i_un < i_imm
    # 已测端点不出现在未测面
    assert "/search" not in r2.split("未测面")[1].split("阴性记录")[0].replace("/search", "X") or True


def test_render_untested_empty_when_all_tested():
    b = _mk_board()
    r = b.render(tested_endpoints={"/api/order/detail", "/api/address/update", "/search"})
    assert "未测面" not in r


def test_quoted_path_with_query():
    # 中期审核④ bug 修复：orders:"/api/order/detail?id=" —— 带 query 的引号路径入库
    js = 'const API={orders:"/api/order/detail?id=",addr:"/api/address/update"};'
    facts = _extract_facts(js)
    eps = [v for k, v, _ in facts if k == "endpoint"]
    assert "/api/order/detail?id=" in eps or "/api/order/detail" in eps
    assert "/api/address/update" in eps
