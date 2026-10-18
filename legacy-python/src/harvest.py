"""AT1 harvest —— 追加式文件增量读取（批3fix 后唯一保留件）。

配方 1 账本收割已死（R1：大账本取消，目录级 diff 替代——driver._dir_diff）；
auto_link/账本翻译迁执行器（observer_harvest v2）。本模块只剩 diff_new_lines：
hints.jsonl 留言队列的按偏移增量读取（T2.8/A24）。
"""

from __future__ import annotations

import os


def diff_new_lines(path: str, offset: int = 0) -> tuple[list[str], int]:
    """从字节 offset 起读新增的完整行（不完整行留给下次）。返回 (行列表, 新 offset)。

    幂等：两次调用同一 offset 结果一致；文件不存在 → ([], offset)。
    """
    if not os.path.isfile(path):
        return [], offset
    size = os.path.getsize(path)
    if size <= offset:
        return [], offset
    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read()
    # 只消费到最后一个换行——半行（写入中）留给下一次
    last_nl = raw.rfind(b"\n")
    if last_nl < 0:
        return [], offset
    consumed = raw[:last_nl + 1]
    text = consumed.decode("utf-8", errors="replace")
    lines = [l.rstrip("\r") for l in text.split("\n")]     # Windows CRLF
    lines = [l for l in lines if l.strip()]
    return lines, offset + last_nl + 1
