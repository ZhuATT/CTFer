# -*- coding: utf-8 -*-
"""canary-web 全链路编排（观察者架构版，phase3.5 §十-十一）。

流程：起靶 → 建 workdir（预创建 FINDINGS/FACTS）→ worker 真挖
→ 轮末收割 FINDINGS（兼容 .jsonl）→ 观察者评判 → findings 入板 → grade 对分。
用法：source .secrets.env && python canary-web/run_chain.py [--keep]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import board as board_mod                    # noqa: E402
from src import events, harvest, prompt as prompt_mod, runner  # noqa: E402
from src.llm import LLMClient                         # noqa: E402
from src.observer import Observer                     # noqa: E402
from src.providers import SolverConfig, build_verifier_config  # noqa: E402

PORT = 8790
TARGET = f"http://127.0.0.1:{PORT}"

CONTRACT = """
【输出契约——发现即提交，被杀也不丢】

⚠ 核心原则：提交是你的事，验证是系统的事。
你不需要"确定是漏洞"才交——你觉得可能是漏洞就交，系统会判断真假。
宁可多交（被系统标 likely_false 也不浪费），不要漏交。

【文件名——必须一字不差，无扩展名】
- 证据文件：evidence/ 目录下，文件名自定义（如 evidence/sql-test.md）
- 发现列表：当前目录下，文件名必须是 FINDINGS（不是 FINDINGS.jsonl）
- 事实列表：当前目录下，文件名必须是 FACTS（不是 FACTS.jsonl）

【什么时候写 FINDINGS】
你做了一次测试，看到了意料之外的结果 → 立刻做两件事：
1. 写一个证据文件（白话描述 + 请求和响应的关键原文粘贴）
2. 往 FINDINGS 文件末尾追加一行 JSON

不需要分类标签，不需要格式模板，不需要确认是漏洞。
侦察阶段发现的也可以交——不要等"准备好"。

【FINDINGS 每行长这样】
{"id":"F-001","endpoint":"/search","evidence":"evidence/sql-test.md","summary":"输入单引号返回SQL报错","round":1}

【FACTS 每行长这样】
{"kind":"business_context","value":"这是电商平台","evidence":"首页"}

【质量分层：现象不交 FINDINGS】
CORS/sourcemap/开放重定向/内网IP/版本指纹/安全头 → 写进 FACTS（kind 用 low_value_only），不写 FINDINGS。
Self-XSS（只有自己可见）→ 不交。其他所有"可能是个洞"的发现 → 交。

【双账号】cookies.txt 两行。身份实验用 A/B 对调。
【侦察额外】识别业务类型写 FACTS（kind 用 business_context）。
【会话结束】输出 <Handoff>已完成：…；未竟：…</Handoff>
"""


def _find_findings_file(workdir: Path) -> Path:
    """兼容 worker 可能加 .jsonl 后缀的情况。"""
    for name in ("FINDINGS", "FINDINGS.jsonl", "FINDINGS.txt"):
        p = workdir / name
        if p.exists():
            return p
    return workdir / "FINDINGS"


def _find_facts_file(workdir: Path) -> Path:
    for name in ("FACTS", "FACTS.jsonl", "FACTS.txt"):
        p = workdir / name
        if p.exists():
            return p
    return workdir / "FACTS"


def _parse_finding(line: str) -> dict | None:
    """简单 JSON 解析（新 4 字段格式，不需要旧 class 校验）。"""
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--timebox", type=int, default=900)
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    tgt = subprocess.Popen([sys.executable, str(Path(__file__).parent / "target.py")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    probe = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", TARGET],
                           capture_output=True, text=True)
    if probe.stdout.strip() != "200":
        tgt.kill()
        print(f"[abort] 靶子没起来（{probe.stdout.strip()}）")
        return 2

    root = Path(tempfile.mkdtemp(prefix="at1-canary-"))
    workdir, pilot, state = root / ".auto", root / ".at1", root / "state"
    for d in (workdir, pilot, state, workdir / "evidence"):
        d.mkdir(parents=True, exist_ok=True)
    (workdir / "cookies.txt").write_text(
        "userA_session=FAKE-sess-userA\nuserB_session=FAKE-sess-userB\n", encoding="utf-8")
    # 预创建空文件——worker 看到文件已存在就往里追加而不是创建 .jsonl
    (workdir / "FINDINGS").touch()
    (workdir / "FACTS").touch()

    bb = board_mod.Blackboard(str(pilot / "_blackboard.json"))
    ev = events.EventWriter(str(state / "auto-log.jsonl"))
    solver = SolverConfig.from_env()
    print(f"[canary] root={root}\n[canary] target={TARGET} solver={solver.provider}")

    # 观察者 LLM 客户端（lazy init——只有 FINDINGS 非空时才建）
    _llm_client = None
    def get_llm_chat():
        nonlocal _llm_client
        if _llm_client is None:
            cfg = build_verifier_config(SolverConfig.from_env())
            _llm_client = LLMClient(cfg)
        return lambda msgs: _llm_client.chat(
            msgs, temperature=0.0, max_tokens=1200, thinking=False).text

    tested = set()
    all_findings = []
    for rnd in range(1, args.rounds + 1):
        p = prompt_mod.render_round_prompt(bb, round_=rnd,
                                           tested_endpoints=(tested if rnd > 1 else None))
        task = (f"\n\n【任务简报·第{rnd}轮】本地授权测试靶 {TARGET}（你自己机器上的 Flask，随便打）。"
                f"双账号在 cookies.txt。目标：结果类发现（越权/注入/未授权访问）。\n"
                f"先侦察（浏览器或 curl），再做身份实验（A/B 对调），然后逐面深入。\n"
                + CONTRACT)
        ev.emit("session_start", {"round": rnd}, round_=rnd)
        task_obj = runner.AgentTask(
            on_fact=lambda t, _r=rnd: ev.emit(
                "fact_added", {"round": _r, "tool": t.tool,
                               "new": bb.observe(t.tool, t.args, t.output, round_=_r)}, round_=_r),
            on_heartbeat=lambda d, _r=rnd: ev.emit("heartbeat", {"round": _r, **d}, round_=_r),
            transcript_path=str(pilot / "transcript.jsonl"))
        res = runner.run(p + task, str(workdir), solver, task_obj,
                         time_box_s=args.timebox, max_turns=60)
        ev.emit("session_end", {"round": rnd, "stop_reason": res.stop_reason, "turns": res.turns,
                                "tokens": res.tokens}, round_=rnd)
        print(f"[worker r{rnd}] stop={res.stop_reason} turns={res.turns} tokens={res.tokens} "
              f"facts={len(bb.facts)} handoff={res.handoff[:60] if res.handoff else '(无)'}")

        # ── 轮末收割：FINDINGS（兼容 .jsonl）+ FACTS ──
        findings_path = _find_findings_file(workdir)
        fpath = str(findings_path)
        off = bb._offsets.get("findings", 0)
        lines, new_off = harvest.diff_new_lines(fpath, off)
        bb._offsets["findings"] = new_off

        facts_path = _find_facts_file(workdir)
        fact_lines, fact_off = harvest.diff_new_lines(str(facts_path),
                                                       bb._offsets.get("facts", 0))
        bb._offsets["facts"] = fact_off
        if fact_lines:
            bb.ingest_facts(fact_lines, round_=rnd)

        new_findings = []
        for ln in lines:
            f = _parse_finding(ln)
            if f:
                new_findings.append(f)
                tested.add(f.get("endpoint", "").split("?")[0])
                all_findings.append(f)

        # ── 观察者评判（新架构，替代旧 verify_claims） ──
        if new_findings:
            evidence_texts = {}
            for f in new_findings:
                ev_path = workdir / f.get("evidence", "")
                if ev_path.exists():
                    evidence_texts[f["id"]] = ev_path.read_text(encoding="utf-8", errors="replace")

            # business_context 从黑板取（worker 侦察时写入）
            bc_facts = bb.query("business_context")
            bc = bc_facts[0]["value"] if bc_facts else ""

            observer = Observer(chat_fn=get_llm_chat(), business_context=bc)
            result = observer.run(
                findings=new_findings,
                evidence_texts=evidence_texts,
                previous_confirmed=bb.confirmed_findings(),
                board_summary=bb.render()[:2000],
                handoff=res.handoff or "")

            # 观察者输出 → 黑板
            for f in result["findings"]:
                bb.add_finding(f)
                tested.add(f.get("endpoint", "").split("?")[0])
            if result.get("session_intel"):
                bb.update_session_intel(result["session_intel"])

            print(f"[观察者判定 r{rnd}]")
            for f in result["findings"]:
                print(f"  {f.get('id','?')} {f.get('assessment','?'):<10} "
                      f"sev={f.get('severity','?')} | {f.get('reason','')[:80]}")

        # 未测面预览
        un = bb.untested_surface(tested)
        if un and rnd < args.rounds:
            print(f"[未测面→r{rnd+1} prompt] {[u['endpoint'] for u in un]}")

    ev.emit("run_end", {"reason": "chain-done"}, round_=args.rounds)
    ev.close()

    # 输出新格式（assessment-based，非 class-based）
    out = {"findings": bb.findings, "session_intel": bb.session_intel}
    (root / "chain_result.json").write_text(json.dumps(out, ensure_ascii=False, indent=1),
                                            encoding="utf-8")

    print(f"\n[黑板 findings]")
    for f in bb.findings:
        print(f"  {f.get('id','?')} {f.get('assessment','?'):<10} "
              f"{f.get('endpoint','?')} sev={f.get('severity','?')}")

    tgt.kill()
    print(f"\n[result] chain_result.json 已写")
    if args.keep:
        print(f"[canary] --keep：现场保留 {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
