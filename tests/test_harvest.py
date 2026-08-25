"""harvest 单测：diff 幂等 + Handoff 合成要素。"""

from pathlib import Path

from src.board import Blackboard
from src.harvest import diff_new_lines, synthesize_handoff


def test_diff_idempotent_and_incremental(tmp_path):
    p = tmp_path / "FINDINGS"
    p.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
    lines1, off1 = diff_new_lines(str(p), 0)
    assert lines1 == ['{"a":1}', '{"a":2}']
    # 同 offset 重读：结果一致（幂等）
    lines_again, off_again = diff_new_lines(str(p), off1)
    assert lines_again == [] and off_again == off1
    # 追加后只读新增
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"a":3}\n{"a":4}')          # 最后一个是半行（无换行）
    lines2, off2 = diff_new_lines(str(p), off1)
    assert lines2 == ['{"a":3}']
    assert off2 > off1
    # 半行等换行到了再消费
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n")
    lines3, _ = diff_new_lines(str(p), off2)
    assert lines3 == ['{"a":4}']


def test_diff_missing_file():
    assert diff_new_lines("Z:/nope/F", 0) == ([], 0)


def test_synthesize_handoff_contains_essentials():
    b = Blackboard()
    for i in range(8):
        b.add_fact("endpoint", f"/api/e{i}", round_=1)
    b.observe("Bash", {"command": "curl -s https://t/a"}, "x", round_=1)
    b.observe("Bash", {"command": "curl -s https://t/a"}, "x", round_=2)
    b.observe("Bash", {"command": "curl -s https://t/a"}, "x", round_=2)
    b.ledger["background"].append({"id": 1, "desc": "js-intel config.js", "status": "pending"})

    class FakeTE:
        tool, args = "Read", {"file_path": "intel.txt"}
        output = "备注：本轮标记 marker=at1-abc123\nGET https://t/api/x 200"

    txt = synthesize_handoff(b, [FakeTE()])
    assert "代码合成交接" in txt
    assert "/api/e7" in txt                       # 最近事实
    assert "curl -s https://t/a（×3）" in txt     # 高频命令
    assert "js-intel config.js" in txt            # 未完成后台任务
    assert "intel.txt" in txt                     # 尾部工具调用（命令/参数）
    assert "marker=at1-abc123" in txt             # ★输出摘录——被杀前的观测要接力下去
    assert "不含原会话意图" in txt                 # 诚实声明


def test_synthesize_empty_board():
    txt = synthesize_handoff(Blackboard())
    assert "黑板无新事实" in txt
