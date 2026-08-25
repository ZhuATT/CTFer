"""AT1 入口。Phase 1 只有 selftest（M1 验收 demo）；后续 phase 加 run/watch 等子命令。"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path


def cmd_selftest(args: argparse.Namespace) -> int:
    from . import events, runner
    from .providers import SolverConfig

    root = Path(tempfile.mkdtemp(prefix="at1-selftest-"))   # 英文路径，避开编码坑
    workdir = root / ".auto"          # worker 的世界（cwd）
    pilot = root / ".at1"           # 控制器区（worker 禁写；M4 起 guard 强制）
    state = root / "state"
    workdir.mkdir(parents=True)
    pilot.mkdir(parents=True)
    state.mkdir(parents=True)

    marker = "at1-" + secrets.token_hex(8)
    (workdir / "hello.txt").write_text(f"marker={marker}\n", encoding="utf-8")

    prompt = (
        "1. 读取当前目录下的 hello.txt。\n"
        "2. 把它的完整内容原样写入当前目录的 out.txt。\n"
        "3. 然后输出一行（原样包含标签）：\n"
        f"<Handoff>已完成：out.txt 写入成功，内容含 {marker}</Handoff>\n"
    )

    ev = events.EventWriter(str(state / "auto-log.jsonl"))

    def on_fact(t: runner.ToolEvent) -> None:
        ev.emit("fact_added", {"tool": t.tool, "out_head": t.output[:80]}, round_=1)

    def on_heartbeat(d: dict) -> None:
        ev.emit("heartbeat", d, round_=1)

    task = runner.AgentTask(on_fact=on_fact, on_heartbeat=on_heartbeat,
                            transcript_path=str(pilot / "transcript.jsonl"))

    os.environ.setdefault("AT1_PROVIDER", "glm")
    solver = SolverConfig.from_env()

    print(f"[selftest] root      = {root}")
    print(f"[selftest] solver    = {solver!r}")
    print(f"[selftest] marker    = {marker}")
    ev.emit("run_start", {"engagement": str(root), "mode": "selftest", "provider": solver.provider})
    ev.emit("session_start", {"round": 1}, round_=1)

    res = runner.run(prompt, str(workdir), solver, task,
                     time_box_s=240, max_turns=8)

    ev.emit("session_end", {
        "round": 1,
        "stop_reason": res.stop_reason,
        "turns": res.turns,
        "tokens": res.tokens,
        "session_id": res.session_id,          # 本地会话标识，非凭据，不脱敏（DoD 要求可见）
        "total_cost_usd": res.total_cost_usd,
        "resumes": res.resumes,
        "error": res.error,
    }, round_=1)
    ev.emit("run_end", {"reason": "selftest-done"}, round_=1)
    ev.close()

    out_txt = workdir / "out.txt"
    out_ok = out_txt.exists() and marker in out_txt.read_text(encoding="utf-8", errors="replace")

    transcript = pilot / "transcript.jsonl"
    t_lines = 0
    if transcript.exists():
        t_lines = sum(1 for _ in transcript.open(encoding="utf-8", errors="replace"))

    log_types: list[str] = []
    for line in (state / "auto-log.jsonl").open(encoding="utf-8"):
        try:
            import json as _json
            log_types.append(_json.loads(line).get("type", ""))
        except Exception:
            pass

    checks = [
        ("worker 完成任务（out.txt 含 marker）", out_ok, True),
        ("transcript.jsonl 存在且非空", t_lines > 0, True),
        ("session_id 捕获", bool(res.session_id), True),
        ("stop_reason ∈ {end_turn,max_turns,timeout}",
         res.stop_reason in ("end_turn", "max_turns", "timeout"), True),
        ("<Handoff> 收割且含 marker", marker in res.handoff, True),
        ("fact_added ≥ 1（on_fact 实时触发）", log_types.count("fact_added") >= 1, True),
        ("session_end 记录 cost/turns/tokens",
         res.total_cost_usd > 0 and res.turns > 0 and res.tokens > 0, True),
        ("heartbeat（≥25 次工具调用才触发，本用例可不触发）",
         log_types.count("heartbeat") >= 0, False),   # 记录性：单测里单独验证
    ]
    mandatory_fail = False
    print("\n[DoD]")
    for name, ok, mandatory in checks:
        mark = "PASS" if ok else ("FAIL" if mandatory else "n/a")
        if mandatory and not ok:
            mandatory_fail = True
        print(f"  [{mark}] {name}")

    print(f"\n[result] stop={res.stop_reason} turns={res.turns} tokens={res.tokens} "
          f"cost=${res.total_cost_usd:.4f} resumes={res.resumes} transcript_lines={t_lines}")
    if res.error:
        print(f"[result] error: {res.error}")

    if args.keep:
        print(f"[selftest] --keep：工作目录保留于 {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)
        print("[selftest] 临时目录已清理（--keep 可保留）")

    return 1 if mandatory_fail else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="at1", description="AT1 —— 黑盒自动化渗透框架")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_st = sub.add_parser("selftest", help="M1 验收：spawn 真 -p 会话跑最小闭环")
    p_st.add_argument("--dry-run", action="store_true",
                      help="（兼容占位：selftest 本身就是 dry-run 级最小任务）")
    p_st.add_argument("--provider", default=None, help="覆盖 AT1_PROVIDER")
    p_st.add_argument("--keep", action="store_true", help="保留临时工作目录")
    p_st.set_defaults(fn=cmd_selftest)

    args = ap.parse_args(argv)
    if getattr(args, "provider", None):
        os.environ["AT1_PROVIDER"] = args.provider
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
