"""CLI 子命令冒烟（P-2）：argparse → fn 的真实入口路径——P-1（watch 缺 import json）
能活着到真跑才炸，就是因为这里从没被测过。"""

import json
from pathlib import Path

from src.__main__ import main


def _mk_watch_target(tmp_path: Path) -> str:
    """watch 只要求 auto-log.jsonl 存在（不挑内容格式，坏行跳过）。"""
    log = tmp_path / "state" / "auto-log.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text(
        json.dumps({"ts": "2026-09-14T03:00:45Z", "round": 1, "type": "session_start",
                    "data": {"round": 1, "stage": "recon", "timebox": 1200}}) + "\n"
        + "not-json-garbage\n"                                  # 坏行必须被容忍
        + json.dumps({"ts": "2026-09-14T03:01:00Z", "round": 1, "type": "heartbeat",
                      "data": {"tool_calls": 25, "tokens": 10}}) + "\n",
        encoding="utf-8")
    return str(tmp_path)


def test_watch_once_replays_without_crash(tmp_path, capsys):
    """P-1 回归：watch --once --all 走完整 CLI 解析+渲染路径不崩。"""
    eng = _mk_watch_target(tmp_path)
    rc = main(["watch", eng, "--all", "--once"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "recon" in out and "心跳" in out               # 渲染映射真的跑了（事件 type → 呈现文案）


def test_watch_missing_log_fails_clean(tmp_path):
    rc = main(["watch", str(tmp_path), "--once"])          # 没 auto-log → rc=2，不抛
    assert rc == 2


def test_run_failfast_without_engagement(tmp_path):
    """run 子命令的拒启路径（不 spawn、不碰网络）。"""
    rc = main(["run", str(tmp_path)])
    assert rc == 2
