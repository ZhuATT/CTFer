"""harvest 单测（批3fix 后只剩 diff_new_lines——账本收割已死 R1，目录级 diff 在 driver）。"""

from src.harvest import diff_new_lines


def test_diff_new_lines_incremental(tmp_path):
    p = tmp_path / "hints.jsonl"
    off = 0
    p.write_text('{"text":"a"}\n{"text":"b"}\n', encoding="utf-8")
    lines, off = diff_new_lines(str(p), off)
    assert [l for l in lines if "a" in l] and len(lines) == 2
    # 追加一行 → 只读新增
    with p.open("a", encoding="utf-8") as f:
        f.write('{"text":"c"}\n')
    lines2, off2 = diff_new_lines(str(p), off)
    assert len(lines2) == 1 and "c" in lines2[0]
    assert off2 > off


def test_diff_new_lines_partial_line_held_back(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"a":1}\n{"b":', encoding="utf-8")
    lines, off = diff_new_lines(str(p), 0)
    assert len(lines) == 1                            # 半行留给下次
    lines2, _ = diff_new_lines(str(p), off)
    assert lines2 == []                               # 仍无完整行
    with p.open("a", encoding="utf-8") as f:
        f.write("2}\n")
    lines3, _ = diff_new_lines(str(p), off)
    assert len(lines3) == 1


def test_diff_new_lines_missing_file():
    assert diff_new_lines(str(tmp_path_none()), 0) == ([], 0)


def tmp_path_none():
    import tempfile
    return tempfile.mkdtemp() + "/nope.jsonl"
