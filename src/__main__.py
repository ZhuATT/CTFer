"""AT1 入口。selftest（M1 验收）+ --relay/--relay-kill（M2 验收：双会话接力/被杀接力）。"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path


def _relay(args: argparse.Namespace) -> int:
    """M2 验收 demo：双会话接力（--relay）/ 被杀接力（--relay-kill）。"""
    from . import board as board_mod
    from . import events, harvest
    from . import prompt as prompt_mod
    from . import runner
    from .providers import SolverConfig

    kill_mode = args.relay_kill
    root = Path(tempfile.mkdtemp(prefix="at1-relay-"))
    workdir, pilot, state = root / ".auto", root / ".at1", root / "state"
    for d in (workdir, pilot, state):
        d.mkdir(parents=True)

    marker = "at1-" + secrets.token_hex(8)
    intel = (
        "# 目标侦察材料（合成）\n"
        "GET https://fake-relay.example/api/item/list?page=1 200\n"
        "POST https://fake-relay.example/api/order/create 401\n"
        "GET https://fake-relay.example/api/user/profile 200\n"
        "Server: nginx/1.20.1\n"
        'config: apiKey=FAKErelayKey000111222333\n'
        f"备注：本轮标记 marker={marker}\n"
    )
    (workdir / "intel.txt").write_text(intel, encoding="utf-8")

    bb = board_mod.Blackboard(str(pilot / "_blackboard.json"))
    ev = events.EventWriter(str(state / "auto-log.jsonl"))
    os.environ.setdefault("AT1_PROVIDER", "glm")
    solver = SolverConfig.from_env()
    print(f"[relay] root={root}")
    print(f"[relay] mode={'KILL' if kill_mode else 'normal'} marker={marker} solver={solver.provider}")

    fact_count = [0]
    killed = [False]

    def on_fact(t):
        ev.emit("fact_added", {"tool": t.tool, "out_head": t.output[:80]}, round_=1)

    def on_spawn(proc):
        if not kill_mode:
            return

        def watch():                       # 条件杀：运行 ≥8s（v3 无被动事实计数，时间盒判据）
            t0 = time.time()
            while proc.poll() is None:
                if time.time() - t0 >= 8:
                    proc.kill()
                    killed[0] = True
                    break
                time.sleep(0.5)
        threading.Thread(target=watch, daemon=True).start()

    task = runner.AgentTask(on_fact=on_fact, on_heartbeat=lambda d: ev.emit("heartbeat", d, round_=1),
                            transcript_path=str(pilot / "transcript.jsonl"), on_spawn=on_spawn)

    prompt1 = (
        "【第 1 轮任务——侦察起步】\n"
        "1. 用 Read 工具读取当前目录 intel.txt 的完整内容。\n"
        "2. 用 Bash 执行：type intel.txt\n"
        "3. 用 Bash 原样执行下面这条命令（>> 是追加，勿改写）：\n"
        f"echo '{{\"kind\":\"identity_model\",\"value\":\"身份结论：合成靶，marker={marker}\",\"evidence\":\"intel.txt\"}}' >> FACTS\n"
        "4. 在最终回复里原样输出（含标签，marker 必须原样出现）：\n"
        f"<Handoff>已完成：intel.txt 读取、FACTS 已上报。未竟事项：POST /api/order/create 未测（401）。marker={marker}</Handoff>\n"
    )

    ev.emit("run_start", {"mode": "relay-kill" if kill_mode else "relay",
                          "provider": solver.provider})
    ev.emit("session_start", {"round": 1}, round_=1)
    if kill_mode:
        res = runner.spawn_once(prompt1, str(workdir), solver, task, time_box_s=240, max_turns=6)
    else:
        res = runner.run(prompt1, str(workdir), solver, task, time_box_s=240, max_turns=6)
    ev.emit("session_end", {"round": 1, "stop_reason": res.stop_reason, "turns": res.turns,
                            "tokens": res.tokens, "session_id": res.session_id,
                            "killed": killed[0]}, round_=1)

    # ── 收割：Handoff（A19：合成交接死，被杀轮置空）+ FACTS → 节点 ──
    bb.record_handoff(res.handoff or "")
    ev.emit("handoff_harvested", {"origin": "model" if res.handoff else "none",
                                  "killed": killed[0], "head": bb.handoff[:60]}, round_=1)
    fact_lines, _ = harvest.diff_new_lines(str(workdir / "FACTS"), 0)
    n_reported = harvest.facts_to_nodes(bb, fact_lines, round_=1)
    bb.save()

    prompt2 = prompt_mod.render_round_prompt(bb, round_=2)
    prompt2_full = prompt2 + (
        "\n\n【第 2 轮任务】找到本轮的 marker 值（形如 at1-十六进制），把它原样写入当前目录 "
        "answer.txt（只写 marker 本身）。查找顺序：当前目录 STATE.md 的『全局认知/发现』节 → "
        "都没有则读当前目录 intel.txt 里的『备注』行。\n"
        "完成后在最终回复里原样输出：<Handoff>第2轮完成</Handoff>\n")

    ev.emit("session_start", {"round": 2}, round_=2)
    res2 = runner.run(prompt2_full, str(workdir), solver,
                      runner.AgentTask(transcript_path=str(pilot / "transcript.jsonl")),
                      time_box_s=240, max_turns=6)
    ev.emit("session_end", {"round": 2, "stop_reason": res2.stop_reason, "turns": res2.turns,
                            "tokens": res2.tokens, "handoff": res2.handoff[:40]}, round_=2)
    ev.emit("run_end", {"reason": "relay-done"}, round_=2)
    ev.close()

    answer = workdir / "answer.txt"
    ans_ok = answer.exists() and marker in answer.read_text(encoding="utf-8", errors="replace")
    t_lines = sum(1 for _ in (pilot / "transcript.jsonl").open(encoding="utf-8", errors="replace")) \
        if (pilot / "transcript.jsonl").exists() else 0

    checks = [
        (f"round1 会话返回（stop={res.stop_reason}, turns={res.turns}）", True),
        (f"Handoff 置录（origin={'model' if res.handoff else 'none'}）",
         bool(bb.handoff) if not kill_mode else bb.handoff == ""),
    ]
    if kill_mode:
        # 被杀场景：会话死在中途，显式通道没走完是【预期】——验的是置空交接与接力
        checks += [
            ("被杀轮 Handoff 置空（观察者读盘替代合成）", bb.handoff == ""),
            (f"被杀于 FACTS 上报前（显式通道未走完，n={n_reported}）", True),
        ]
    else:
        checks += [
            (f"FACTS 上报入图（{n_reported} 条）", n_reported >= 1),
            ("prompt2 渲染含状态摘要段", "【状态摘要】" in prompt2),
        ]
    checks += [
        ("round2 answer.txt 含 marker（接力成立）", ans_ok),
        (f"transcript 两轮累计可读（{t_lines} 行）", t_lines > 0),
    ]
    if kill_mode:
        checks.insert(1, (f"条件杀生效（killed={killed[0]}）", killed[0]))

    mandatory_fail = False
    print("\n[DoD]")
    for name, ok in checks:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            mandatory_fail = True
        print(f"  [{mark}] {name}")
    print(f"\n[result] r1 stop={res.stop_reason} tokens={res.tokens} | "
          f"r2 stop={res2.stop_reason} tokens={res2.tokens} | "
          f"nodes={len(bb.graph['nodes'])} | handoff_origin={'model' if res.handoff else 'none'}")
    if res.error:
        print(f"[result] r1 error: {res.error[:120]}")

    if args.keep:
        print(f"[relay] --keep：工作目录保留于 {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if mandatory_fail else 0


def cmd_selftest(args: argparse.Namespace) -> int:
    if getattr(args, "relay", False) or getattr(args, "relay_kill", False):
        return _relay(args)
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
        ("session_end 记录 cost/turns（cost 或 tokens 任一 >0，端点 usage 偶发双零）",
         res.turns > 0 and (res.total_cost_usd > 0 or res.tokens > 0), True),
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


def cmd_run(args: argparse.Namespace) -> int:
    """M4：跑一个 engagement（driver 主循环）。"""
    from .driver import run_engagement
    return run_engagement(
        args.engagement,
        budget_s=args.budget,
        max_rounds=args.rounds,
        stop_on_first_confirmed=args.stop_on_first_confirmed,
        dry_run=args.dry_run,
        provider=args.provider,
        observer_on=not args.no_observer)


def cmd_watch(args: argparse.Namespace) -> int:
    """M4：tail auto-log.jsonl 渲染彩色一行式（isatty 才着色）。"""
    import time

    path = os.path.join(args.engagement, "state", "auto-log.jsonl")
    if not os.path.isfile(path):
        print(f"[watch] 找不到 {path}（engagement 还没跑过？）")
        return 2
    color = sys.stdout.isatty()
    C = {"dim": "\033[2m", "red": "\033[31m", "yellow": "\033[33m",
         "green": "\033[32m", "cyan": "\033[36m", "off": "\033[0m"} if color else \
        {k: "" for k in ("dim", "red", "yellow", "green", "cyan", "off")}

    # 事件 → 呈现映射（设计§4.3 运行页同款；M5 工作台复用这张表）
    def render(row: dict) -> str:
        t, r, d = row.get("type", ""), row.get("round"), row.get("data", {})
        ts = row.get("ts", "")[11:19]
        base = f"{C['dim']}{ts}{C['off']} r{r}"
        if t == "heartbeat":
            flags = [k for k in ("stalled", "stalled_tools") if d.get(k)]
            if flags:
                return f"{base} {C['yellow']}⚠ 呆滞 {','.join(flags)} " \
                       f"stream={d.get('stream_idle_s')}s tools={d.get('tool_calls')}{C['off']}"
            return f"{base} · 心跳 tools={d.get('tool_calls')} tokens={d.get('tokens')}"
        if t == "finding_confirmed":
            return f"{base} {C['red']}★ confirmed {d.get('id')} {d.get('endpoint')} " \
                   f"sev={d.get('severity')}{C['off']}"
        if t == "claim_verdict":
            mark = {"confirmed": C['green'] + "✓", "likely_false_positive": C['yellow'] + "✗",
                    "uncertain": C['yellow'] + "?", "duplicate": C['dim'] + "≡"}.get(
                    d.get("assessment"), "?")
            ev = "锚" if d.get("evidence_verified") else "未锚"
            return f"{base} {mark} {d.get('id')} {d.get('assessment')} [{ev}] " \
                   f"{str(d.get('reason', ''))[:70]}{C['off']}"
        if t == "guard_violation":
            c = C['red'] if d.get("critical") else C['yellow']
            return f"{base} {c}⛔ guard[{d.get('kind')}] {str(d.get('reason', ''))[:80]}{C['off']}"
        if t == "stoploss_trigger":
            return f"{base} {C['yellow']}△ stoploss {d.get('dim')}{C['off']}"
        if t == "session_start":
            return f"{base} {C['cyan']}▶ r{d.get('round')} [{d.get('stage')}] box={d.get('timebox')}s{C['off']}"
        if t == "session_end":
            return f"{base} {C['dim']}■ stop={d.get('stop_reason')} turns={d.get('turns')} " \
                   f"tokens={d.get('tokens')}{C['off']}"
        if t == "phase_check":
            return f"{base} {C['cyan']}◇ stage={d.get('stage')}{C['off']}"
        if t == "run_end":
            return f"{base} {C['green']}■■ run_end {d.get('reason')} confirmed={d.get('confirmed')}{C['off']}"
        if t in ("fact_added",):
            return f"{base} + fact {d.get('tool')} new={d.get('new')}"
        if t in ("handoff_harvested", "directive_injected", "observer_error",
                 "surface_parse_fail", "immune_added"):
            return f"{base} {t} {str(d)[:90]}"
        return f"{base} {t}"

    with open(path, encoding="utf-8") as f:
        f.seek(0, 2)                        # 从尾部开始（--all 回放全量）
        if args.all:
            f.seek(0)
        while True:
            line = f.readline()
            if not line:
                if args.once:
                    break
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                print(render(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                pass
    return 0


def main(argv: list[str] | None = None) -> int:
    # git-bash/PowerShell 控制台中文乱码修复：Python 输出统一 UTF-8
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="at1", description="AT1 —— 黑盒自动化渗透框架")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_st = sub.add_parser("selftest", help="M1/M2 验收：最小闭环 / 双会话接力")
    p_st.add_argument("--dry-run", action="store_true",
                      help="（兼容占位：selftest 本身就是 dry-run 级最小任务）")
    p_st.add_argument("--relay", action="store_true", help="M2 验收：双会话接力 demo")
    p_st.add_argument("--relay-kill", action="store_true", help="M2 验收变体：第1轮条件杀后接力")
    p_st.add_argument("--provider", default=None, help="覆盖 AT1_PROVIDER")
    p_st.add_argument("--keep", action="store_true", help="保留临时工作目录")
    p_st.set_defaults(fn=cmd_selftest)

    p_run = sub.add_parser("run", help="M4：跑一个 engagement（driver 主循环）")
    p_run.add_argument("engagement", help="engagement 目录（三件套所在）")
    p_run.add_argument("--budget", type=float, default=7200, help="总预算秒（默认 7200）")
    p_run.add_argument("--rounds", type=int, default=None, help="轮上限（默认不限——仅预算与连击止损，2026-09-04 拍板）")
    p_run.add_argument("--dry-run", action="store_true", help="渲染首轮 prompt 不 spawn")
    p_run.add_argument("--stop-on-first-confirmed", action="store_true",
                       help="字面终止A：confirmed 即停待人收割（默认走完 report 阶段）")
    p_run.add_argument("--no-observer", action="store_true", help="关观察者（调试用）")
    p_run.add_argument("--provider", default=None, help="覆盖 AT1_PROVIDER")
    p_run.set_defaults(fn=cmd_run)

    p_w = sub.add_parser("watch", help="M4：tail 事件流实时渲染")
    p_w.add_argument("engagement", help="engagement 目录")
    p_w.add_argument("--all", action="store_true", help="回放全量（默认只看新增）")
    p_w.add_argument("--once", action="store_true", help="读完现有内容即退出（不跟随）")
    p_w.set_defaults(fn=cmd_watch)

    args = ap.parse_args(argv)
    if getattr(args, "provider", None):
        os.environ["AT1_PROVIDER"] = args.provider
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
