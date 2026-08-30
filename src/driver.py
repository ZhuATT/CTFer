"""AT1 driver —— engagement 主循环（P4.5，设计§3.6，D3 拍板：提取 run_chain 泛化）。

run_chain.py 在 A4 验证过的循环（FINDINGS 兼容收割/lazy LLM/未测面传递/观察者
入板）原样迁入，叠加 M4 组件：scaffolding 展开 / guard 实时检测 / stoploss /
transcript 定点比对 / noreport 硬拒 / CONTROL 轮询 / 终止条件 / 协议文件写回。

终止语义（设计§3.6 + A4 实证微调）：
  A（confirmed）：不硬停——check_goal 已把阶段推进 report，worker 写报告轮
     之后 C 收工。A4 证明 confirmed 后的下一轮有链式价值（轮 1 SQL → 轮 2 XSS）。
     --stop-on-first-confirmed 可回到字面 A（立即停待人收割）。
  B（预算/stoploss）：立即停。
  C（TERMINAL_C）：goal 链走完（evidence + report.md），正常收工。
  D（CONTROL stop）：优雅停——已落盘 FINDINGS 照常收割。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import board as board_mod
from . import events as events_mod
from . import harvest
from . import prompt as prompt_mod
from . import runner
from . import scaffold, transcript_check, writeback
from .guard import Guard
from .noreport import check as noreport_check
from .observer import Observer
from .providers import SolverConfig, build_verifier_config
from .stoploss import Stoploss

TIMEBOX_LADDER = (600, 1200, 1800)      # 轮次时间盒阶梯（§7）
MAX_TURNS = 60


def _find_ledger(workdir: Path, base: str) -> Path:
    """FINDINGS/FACTS 文件名兼容（A4 教训：worker 偏好 .jsonl 变体）。"""
    for name in (base, base + ".jsonl", base + ".txt"):
        p = workdir / name
        if p.exists():
            return p
    return workdir / base


def _harvest_findings(workdir: Path, bb, round_no: int) -> list[dict]:
    """收割 FINDINGS 全部候选文件，按 ID 去重（不用字节 offset）。

    offset 方案在 worker 重写文件/换 .jsonl 变体时会丢行（P4.9 实测 F-004 丢失）。
    ID 去重对文件重写和名字变体都鲁棒：每轮全量解析，跳过已处理 ID。
    """
    seen = set(bb._offsets.get("findings_ids", []))
    new: list[dict] = []
    for name in ("FINDINGS", "FINDINGS.jsonl", "FINDINGS.txt"):
        p = workdir / name
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            f = _parse_finding(line)
            if f and f.get("id") not in seen:
                seen.add(f["id"])
                f["round"] = f.get("round", round_no)
                new.append(f)
    bb._offsets["findings_ids"] = sorted(seen)
    return new


def _parse_finding(line: str) -> dict | None:
    line = line.strip().lstrip("﻿").strip()
    if not line:
        return None
    try:
        d = json.loads(line)
        if isinstance(d, dict) and d.get("endpoint") and d.get("evidence"):
            return d
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _timebox(round_no: int) -> int:
    return TIMEBOX_LADDER[min(round_no - 1, len(TIMEBOX_LADDER) - 1)]


def _poll_control(engagement_root: Path) -> dict | None:
    """读后即删 state/CONTROL。返回 {cmd, text} 或 None。"""
    p = engagement_root / "state" / "CONTROL"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = {"cmd": "unknown"}
    try:
        p.unlink()
    except OSError:
        pass
    return data if isinstance(data, dict) else None


def run_engagement(engagement_root: str, *, budget_s: float = 7200,
                   max_rounds: int = 6, stop_on_first_confirmed: bool = False,
                   dry_run: bool = False, provider: str | None = None,
                   observer_on: bool = True) -> int:
    """跑一个 engagement。返回 0 正常 / 2 启动失败 / 1 异常。"""
    root = Path(engagement_root)

    # ── 启动 fail-fast：三件套 ──
    try:
        eng = scaffold.load_engagement(root)
    except (FileNotFoundError, ValueError) as e:
        print(f"[driver] 拒启：{e}")
        return 2
    for rel, what in (("state/status.md", "status.md"),
                      ("notes/prior-intel.md", "prior-intel.md")):
        p = root / rel
        if not p.is_file() or not p.read_text(encoding="utf-8").strip():
            print(f"[driver] 拒启：{what} 缺失或为空（{p}）")
            return 2

    if provider:
        os.environ["AT1_PROVIDER"] = provider
    solver = SolverConfig.from_env()

    # ── 环境就绪 ──
    pilot = root / ".at1"
    pilot.mkdir(exist_ok=True)
    (root / "state").mkdir(exist_ok=True)
    # worker 配置隔离：不读本机 ~/.claude/settings.json 的 env 覆盖（实测会劫持
    # 注入的 ANTHROPIC_BASE_URL）。指向控制器区空目录，worker 只吃注入配置。
    os.environ.setdefault("AT1_CLAUDE_CONFIG_DIR", str(pilot / "claude-config"))
    workdir = scaffold.expand(root, eng)
    bb = board_mod.Blackboard(str(pilot / "_blackboard.json"))
    ev = events_mod.EventWriter(str(root / "state" / "auto-log.jsonl"))
    guard = Guard.from_engagement(eng)
    sl = Stoploss(max_rounds=max_rounds)

    # 播种：prior-intel 喂语料 + status.md 阴性段 → immune
    intel_text = (root / "notes" / "prior-intel.md").read_text(encoding="utf-8")
    if bb.goal.get("stage") == "recon" and not bb.facts:
        bb.observe("Read", {"file_path": "notes/prior-intel.md"}, intel_text, round_=0)
    for imm in writeback.parse_immune_from_status(str(root / "state" / "status.md")):
        bb.add_immune(imm["endpoint"], status=imm.get("status", ""), round_=0)

    ev.emit("run_start", {"engagement": str(root), "target": eng.get("target"),
                          "provider": solver.provider, "budget_s": budget_s})
    print(f"[driver] engagement={root} target={eng.get('target')} solver={solver.provider}")

    # 观察者 lazy 通道
    _llm = None

    def get_chat():
        nonlocal _llm
        if _llm is None:
            from .llm import LLMClient
            _llm = LLMClient(build_verifier_config(solver))
        return lambda msgs: _llm.chat(msgs, temperature=0.0, max_tokens=1200,
                                      thinking=False).text

    tested: set[str] = set()
    for f in bb.findings:
        tested.add(str(f.get("endpoint", "")).split("?")[0])
    for i in bb.immune:
        tested.add(str(i.get("endpoint", "")).split("?")[0])

    stop_reason, exit_code = "budget", 0
    t0 = time.monotonic()
    directive_next: str | None = None
    had_confirmed_at_round: int | None = None

    def _brief(rnd_: int, box_: int, left_: float) -> str:
        return (f"\n\n【任务简报·第{rnd_}轮】目标 {eng.get('target')}（授权范围见 CLAUDE.md）。"
                f"身份：{'storage-state.json（已注入）' if (workdir / 'storage-state.json').exists() else '见 evidence/cookies.txt 或匿名'}。"
                f"剩余预算 {int(left_)}s，时间盒 {box_}s。"
                f"输出契约（FINDINGS/FACTS/evidence/Handoff）见 CLAUDE.md——发现即提交，验证是系统的事。")

    if dry_run:
        p = prompt_mod.render_round_prompt(bb, round_=1,
                                           tested_endpoints=(tested or None)) \
            + _brief(1, _timebox(1), budget_s)
        out = root / "state" / "dry-run-prompt.md"
        out.write_text(p, encoding="utf-8")
        print(f"[driver] dry-run：首轮 prompt 已渲染 → {out}（未 spawn）")
        ev.emit("run_end", {"reason": "dry-run"}, round_=0)
        return 0

    rnd = 0
    while True:
        rnd += 1
        # CONTROL 轮间轮询
        ctl = _poll_control(root)
        if ctl:
            cmd = ctl.get("cmd", "")
            if cmd == "stop":
                stop_reason, exit_code = "control-stop(D)", 0
                break
            if cmd == "pause":
                stop_reason, exit_code = "control-pause", 0
                break
            if cmd == "directive":
                directive_next = str(ctl.get("text", ""))[:500]
                ev.emit("directive_injected", {"head": directive_next[:60]}, round_=rnd)

        box = _timebox(rnd)
        budget_left = budget_s - (time.monotonic() - t0)
        if budget_left <= 0:
            stop_reason, exit_code = "budget(B)", 0
            break

        # ── 渲染 prompt ──
        stage = bb.goal.get("stage", "recon")
        prompt = prompt_mod.render_round_prompt(
            bb, directive=directive_next, round_=rnd,
            tested_endpoints=(tested if rnd > 1 else None)) \
            + _brief(rnd, box, budget_left)
        directive_next = None

        # ── spawn worker ──
        ev.emit("session_start", {"round": rnd, "stage": stage, "timebox": box}, round_=rnd)
        tool_tail: list = []
        proc_ref: dict = {}

        def on_fact(t, _r=rnd):
            n = bb.observe(t.tool, t.args, t.output, round_=_r)
            if n:
                ev.emit("fact_added", {"round": _r, "tool": t.tool, "new": n}, round_=_r)
            v = guard.check_tool(t.tool, t.args or {})
            if not v.ok:
                ev.emit("guard_violation", {"round": _r, "kind": v.kind,
                                            "tool": t.tool, "reason": v.reason[:200],
                                            "critical": v.kind == "self_destruct"}, round_=_r)
            tool_tail.append(t)
            if len(tool_tail) > 5:
                tool_tail.pop(0)

        def on_heartbeat(d, _r=rnd):
            ev.emit("heartbeat", {"round": _r, **d}, round_=_r)
            # 心跳点 CONTROL 轮询：stop → kill 当前 worker 走优雅停（设计§4.2）
            c = _poll_control(root)
            if c and c.get("cmd") == "stop" and proc_ref.get("proc") is not None:
                try:
                    proc_ref["proc"].kill()
                except Exception:
                    pass

        task = runner.AgentTask(on_fact=on_fact, on_heartbeat=on_heartbeat,
                                transcript_path=str(pilot / "transcript.jsonl"),
                                on_spawn=lambda proc: proc_ref.__setitem__("proc", proc))
        facts_before = len(bb.facts)
        res = runner.run(prompt, str(workdir), solver, task,
                         time_box_s=min(box, budget_left), max_turns=MAX_TURNS)
        ev.emit("session_end", {"round": rnd, "stop_reason": res.stop_reason,
                                "turns": res.turns, "tokens": res.tokens,
                                "resumes": res.resumes, "thinking_events": 0}, round_=rnd)
        print(f"[worker r{rnd}] stop={res.stop_reason} turns={res.turns} "
              f"tokens={res.tokens} facts={len(bb.facts)}")
        facts_delta = len(bb.facts) - facts_before
        sl.record_round(facts_delta=facts_delta,
                        session_ok=(res.stop_reason != "error"))

        # ── 收割 FINDINGS（ID 去重，鲁棒于文件重写/变体）/ FACTS（字节 offset）──
        new_findings = _harvest_findings(workdir, bb, rnd)
        facts_lines, foff = harvest.diff_new_lines(
            str(_find_ledger(workdir, "FACTS")), bb._offsets.get("facts", 0))
        bb._offsets["facts"] = foff
        if facts_lines:
            bb.ingest_facts(facts_lines, round_=rnd)

        verdicts: list[dict] = []
        if new_findings and observer_on:
            evidence_texts = {}
            for f in new_findings:
                ep = workdir / f.get("evidence", "")
                if ep.is_file():
                    evidence_texts[f["id"]] = ep.read_text(encoding="utf-8",
                                                            errors="replace")
            # transcript 定点比对（事实层锚定）→ evidence_verified
            tpath = str(pilot / "transcript.jsonl")
            for f in new_findings:
                f["evidence_verified"] = transcript_check.verify_evidence_in_transcript(
                    tpath, evidence_texts.get(f["id"], ""))

            bc_facts = bb.query("business_context")
            ob = Observer(chat_fn=get_chat(),
                          business_context=(bc_facts[0]["value"] if bc_facts else ""))
            try:
                result = ob.run(findings=new_findings,
                                evidence_texts=evidence_texts,
                                previous_confirmed=bb.confirmed_findings(),
                                board_summary=bb.render()[:2000],
                                handoff=res.handoff or "")
                verdicts = result["findings"]
                if result.get("session_intel"):
                    bb.update_session_intel(result["session_intel"])
            except Exception as e:                       # 观察者故障不阻塞收割
                ev.emit("observer_error", {"round": rnd, "error": str(e)[:200]}, round_=rnd)
                verdicts = [{**f, "assessment": "uncertain",
                             "reason": f"观察者故障：{str(e)[:100]}"} for f in new_findings]

            for f in verdicts:
                bb.add_finding(f)
                tested.add(str(f.get("endpoint", "")).split("?")[0])
                ev.emit("claim_verdict", {"round": rnd, "id": f.get("id"),
                                          "endpoint": f.get("endpoint"),
                                          "assessment": f.get("assessment"),
                                          "severity": f.get("severity"),
                                          "evidence_verified": f.get("evidence_verified"),
                                          "reason": str(f.get("reason", ""))[:150]},
                        round_=rnd)
                if f.get("assessment") == "confirmed":
                    ok, why = writeback.append_status_row(
                        str(root / "state" / "status.md"), f, round_no=rnd)
                    ev.emit("finding_confirmed", {"round": rnd, "id": f.get("id"),
                                                  "endpoint": f.get("endpoint"),
                                                  "severity": f.get("severity"),
                                                  "status_row": why}, round_=rnd)
            print(f"[观察者 r{rnd}] " + " | ".join(
                f"{f.get('id')}:{f.get('assessment')}" for f in verdicts) or "(无新发现)")

        # ── Handoff ──
        handoff = res.handoff or harvest.synthesize_handoff(bb, tool_tail)
        bb.record_handoff(handoff, "model" if res.handoff else "synthesized")
        ev.emit("handoff_harvested", {"round": rnd,
                                      "origin": bb.handoff_origin,
                                      "head": handoff[:60]}, round_=rnd)
        bb.save()

        # ── 终止判定 ──
        if stop_on_first_confirmed and bb.confirmed_findings():
            stop_reason, exit_code = "confirmed(A)", 0
            break
        if bb.confirmed_findings() and had_confirmed_at_round is None:
            had_confirmed_at_round = rnd
        go = bb.check_goal(str(root), round_no=rnd)
        ev.emit("phase_check", {"round": rnd, "stage": bb.goal.get("stage"),
                                "goal": go}, round_=rnd)
        if go == "TERMINAL_C":
            stop_reason, exit_code = "goal-complete(C)", 0
            break
        stop, why = sl.should_stop(rnd, budget_s - (time.monotonic() - t0))
        if stop:
            ev.emit("stoploss_trigger", {"round": rnd, "dim": why}, round_=rnd)
            stop_reason, exit_code = f"stoploss(B):{why}", 0
            break

    # ── 收尾 ──
    okr, whr = writeback.refresh_surface_depth(str(root / "state" / "status.md"), bb)
    if not okr:
        ev.emit("surface_parse_fail", {"reason": whr}, round_=rnd)
    writeback.gen_prior_intel_draft(str(root), bb, stop_reason=stop_reason)
    bb.save()
    ev.emit("run_end", {"reason": stop_reason, "rounds": rnd,
                        "confirmed": len(bb.confirmed_findings())}, round_=rnd)
    ev.close()
    print(f"[driver] 终止：{stop_reason}；轮次 {rnd}；confirmed {len(bb.confirmed_findings())}")
    return exit_code
