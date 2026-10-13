"""AT1 driver —— engagement 主循环（批3fix：Cairn 同构治理链，R1-R10 终版；
批4fix S1-S12：停机三道门/所有权锁/phase 账本/断点续会话）。

每轮：worker（自由写 facts//findings//evidence/，cwd=engagement 根）→ 目录级 diff 出
任务单 → 观察者 -p（读产出+读图+实测验证，终态写 .observer/OBSERVER.json，退出即提交）
→ 执行器（observer_harvest v2）逐条校验入图 → STATE.md（观察者产物，兜底极简计数）
→ 下轮 worker 优先读图、配合读 STATE.md。

【停机/续跑语义（2026-09-21 拍板，语义权威记录=docs/at1-v3批4fix-落地执行计划.md §0）】

节奏不变式（架构保证，任何中断点都塌缩回"上一个完整轮边界"）：
  - 图只在轮末入图时变（worker 产出即时落盘，但改图只发生在轮末）
  - 审计是无状态纯函数（读全部材料→一次判断书，无中间进度）
  - "永远新 worker 接"——不存在补跑，只有节奏重新开始

会话策略（S12）：能续则续，续不了则新开。被中断的 worker/观察者优先续接原会话
（--resume，保工作记忆与已做实验），续接失败落回新开；触发条件=phase.json 残留
（干净收尾清账；control-stop 有意留残留作续接触发器）。只试一次，永不循环。

停机三道门（S1，死因命名对齐 ARTEX 具名死因）：
  - control-stop(W)：killed in Worker phase——会话死、观察者未生，门 A 即退
  - control-stop(O)：killed in Observer phase——判断书未入图即作废，门 B 即退
  - control-stop(D)：detected at boundary——轮间/轮末盯梢到（P-11 既有）
  配套：S2 观察者出生登记 proc_ref（stop 杀当前活会话而非 worker 尸体）；
  S3 run.lock 所有权锁（单实例，进程死内核自动放锁）；S4 stop 返回时实例必已死。

保留的既有机械：preflight / CONTROL 盯梢（P-11）/ 判停三角（预算+人工停+worker
<Stop> 引证）/ stoploss 连击 / hints 队列 / 旧板归档 / noreport 检察官（硬拒清单
前置进任务单，执行器拒不受理）。
退役的旧链：配方 1 账本收割（harvest.finding/facts_to_nodes）、两刷投影
（_render_state_projection）、观察者 chat 通道（observer.Observer）、writeback 全家
（status.md/晋升/搬运/draft 代写）——见 docs/at1-v3批3-真轮待测试.md §13。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import board as board_mod
from . import events as events_mod
from . import harvest
from . import observer, observer_harvest
from . import phase as phase_mod
from . import prompt as prompt_mod
from . import runner
from . import scaffold
from .browser import BrowserHandle, find_exe
from .guard import Guard
from .noreport import check as noreport_check
from .providers import SolverConfig
from .stoploss import Stoploss

TIMEBOX_S = 1800                        # 单 worker 时间盒统一 30 分钟（09-19 拍板：取消阶梯）
MAX_TURNS = 60

# S12 断点续会话注入语（09-21 拍板：能续则续，续不了则新开）。
_WORKER_RESUME_PROMPT = (
    "你被停机中断过，继续收尾本轮。盘面（facts//findings//evidence/）与图只在上轮末"
    "更新过——本轮你已写盘的产出都在盘上。以下轮 CLAUDE.md/简报为准（scope 可能已变），"
    "凭证可能过期按手册自行恢复。")
_OBSERVER_RESUME_PROMPT = (
    "你的审计被中断过。已做的验证不必重做，继续完成判断书"
    "（.observer/OBSERVER.json）并运行任务单里的 submit_cmd 提交。")


def _timebox(round_no: int) -> int:
    """单 worker 时间盒（09-19 拍板：统一 30 分钟，取消阶梯）。round_no 保留兼容签名。"""
    return TIMEBOX_S


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


def _preflight(claude_bin: str, mcp_config: Path) -> dict:
    """启动预检（Cairn 式：把无声失败消灭在 spawn 前，2026-09-14）。

    - claude CLI 不可用 → ok=False（拒启——没有它一切免谈）
    - MCP 起不来 → 只警告不拒启（P-7 已有 curl 降级路径，浏览器缺席可活）
    纯函数（subprocess 可 monkeypatch），线程无关。
    """
    out = {"claude": "", "mcp": "", "chrome": "", "ok": True}
    try:
        r = subprocess.run([claude_bin, "--version"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=30)
        out["claude"] = ((r.stdout or r.stderr or "ok").strip()[:60])
        if r.returncode != 0:
            out["claude"] += f" (rc={r.returncode})"
            out["ok"] = False
    except Exception as e:
        out["claude"] = f"不可用：{str(e)[:80]}"
        out["ok"] = False
    # playwright 批 B2：chrome exe 在场检查（只警告不拒启——pool 缺席走 fallback）
    exe = find_exe()
    out["chrome"] = exe if exe else "未找到（浏览器池不启动，走 MCP fallback）"
    if not mcp_config.is_file():
        out["mcp"] = "无 .mcp.json（浏览器能力缺席，curl 起步）"
        return out
    npx = shutil.which("npx")     # Windows: npx 是 .cmd 垫片，裸名单 subprocess 找不到（WinError 2）
    if not npx:
        out["mcp"] = "npx 不在 PATH（降级 curl）"
        return out
    try:
        r = subprocess.run([npx, scaffold.MCP_PACKAGE, "--version"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=90)
        out["mcp"] = ("playwright 可启动（" + (r.stdout or "").strip()[:30] + "）"
                      if r.returncode == 0 else f"启动失败 rc={r.returncode}（降级 curl）")
    except Exception as e:
        out["mcp"] = f"检查失败：{str(e)[:80]}（降级 curl）"
    return out


def _controller_kill(proc) -> None:
    """P-11 v2：控制器击杀 = 打死因标签再杀进程树。标签让 runner 把这次死亡
    归为终态（controller_kill），续跑梯子不会把被杀会话当瞬态故障复活。
    S2 保险：已退出的进程不动作——死 worker 的 PID 被操作系统回收复用后，
    taskkill 按 PID 杀树会误杀无辜进程；登记簿上的尸体直接跳过。"""
    if proc is None:
        return
    try:
        alive = proc.poll() is None
    except Exception:
        alive = True            # 非 Popen（测试替身/未实现 poll）——按活者处理
    if not alive:
        return
    try:
        proc._controller_kill = True
    except Exception:
        pass
    runner.kill_process_tree(proc)


def _consume_stop_file(control_path: Path, proc_ref: dict, flag: dict) -> bool:
    """P-11 v2：peek CONTROL，仅 stop 即时消费——置标志 + 杀 worker 进程树。

    pause/directive 不动（留给轮界 poll，语义不变）。proc_ref 未挂上（worker 尚未
    spawn）也安全：只置标志，杀由盯梢线程的竞态防护循环补上（Cairn cancel-before-attach）。
    模块级纯函数——盯梢线程体与单测共用。
    """
    p = Path(control_path)
    if not p.is_file():
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return False
    if not isinstance(data, dict) or data.get("cmd") != "stop":
        return False
    # 置标志**先于**删文件（续修批实抓竞态）：主循环是"读标志 → 轮询文件"两步，
    # 若删文件先发生，中间被本线程插入就会出现两边都没看见 stop 的窗口 → 多跑一轮
    # worker（实机偶发复现于 test_control_stop_preexisting_prevents_any_spawn）。
    # 顺序反过来后：主循环读到标志 False ⇒ 删文件必未发生 ⇒ 轮询必能捞到。
    flag["hit"] = True
    flag["text"] = str(data.get("text", ""))[:200]
    try:
        p.unlink()
    except OSError:
        pass
    _controller_kill(proc_ref.get("proc"))
    return True


def _seed_from_engagement(root: Path, bb) -> None:
    """配方 0 播种（R5 终版，开跑前一次；图空才播——续跑不重播）：
    只种一条画像 fact（直落终态，观察者可经画像前缀规则换代）。
    prior-intel 原文不进图（真轮教训：35 条灌图）——worker/观察者按指针自读。
    status.md 漏洞表/非漏洞表播种已死（status.md 退役，R6/R7）。"""
    if bb.nodes("fact") or bb.nodes("intent") or bb.nodes("finding"):
        return
    pointer = root / "notes" / "prior-intel.md"
    if pointer.is_file() and pointer.read_text(encoding="utf-8").strip():
        bb.create_node("fact", {
            "value": "目标画像：（待观察者换代——操作员前置情报全文见 notes/prior-intel.md："
                     "身份/端点/侦察线索，开工先读它）",
            "evidence": "notes/prior-intel.md"},
            origin="user", round=0)


def _guide_from_state(root: Path) -> str:
    """【引导】来源（批3fix）：观察者写在 STATE.md 里的"## 下轮建议"节。
    机械抽取，不解释——内容由观察者负责（建议口吻，非指令）。"""
    p = root / "STATE.md"
    if not p.is_file():
        return ""
    return prompt_mod.extract_guide(p.read_text(encoding="utf-8", errors="replace"))


def _render_state_minimal(bb) -> str:
    """兜底极简 STATE（R6：观察者没写 STATE.md 时的占位——防 P-13 式静默失联）。
    计数行 + 待接方向 + 指路（全文读图本体）。"""
    n_nodes, n_edges = len(bb.graph["nodes"]), len(bb.graph["edges"])
    ic = bb.intent_counts()
    n_neg, n_un = len(bb.negative_view()), len(bb.untested_surface())
    parts = [f"# STATE｜节点{n_nodes} 边{n_edges}｜方向 open {ic['open']}/进行中 {ic['in_progress']}"
             f"/blocked {ic['blocked']}/done {ic['done']}"
             f"｜发现 确认{len(bb.confirmed_findings())}｜阴性{n_neg}｜未测面{n_un}",
             "（本轮观察者未更新 STATE——系统兜底计数。全文读 .at1/blackboard.json："
             "graph.nodes 看 fact/finding，bookkeeping 是系统字段。）"]
    pending = bb.active_intents()
    if pending:
        rows = [f"- [{d['id']}] ({d['state']}) {d['payload'].get('goal', '')}"
                f" — {d['payload'].get('note', '')}" for d in pending[:8]]
        parts.append("## 待接方向\n" + "\n".join(rows))
    return "\n\n".join(parts) + "\n"


def _inventory_page(root: Path, prev: dict) -> tuple[dict, dict]:
    """无状态目录页（批4 G1-A 终版）：facts//findings//evidence/ 全量盘点。
    纯现算零持久化——prev（上一轮清单指纹，内存级，重启清零）只用于
    new_or_changed 参考标记；标记不承担正确性责任，"哪些要审"由观察者对照图判断。"""
    items: list[dict] = []
    state: dict = {}
    for sub in ("facts", "findings", "evidence"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            st = p.stat()
            changed = prev.get(rel) != (st.st_mtime_ns, st.st_size)
            items.append({"path": rel, "dir": sub, "bytes": st.st_size,
                          "new_or_changed": changed})
            state[rel] = (st.st_mtime_ns, st.st_size)
    page = {"items": items,
            "new_or_changed": [i["path"] for i in items if i["new_or_changed"]]}
    return page, state


def _finding_summary_of(path: Path) -> str:
    """finding 文件的一句话定性：第一条非空非标记行（noreport 检察官的 summary 输入）。"""
    try:
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip().lstrip("#-*> ").strip()
            if s:
                return s[:300]
    except OSError:
        pass
    return path.stem


def _noreport_scan(root: Path, new_finding_paths: list[str]) -> tuple[list[str], list[dict]]:
    """noreport 检察官前置（T2.6 语义保留 + 批4 G2 公诉出口）：
    reject=形状即现象 → 硬拒清单（执行器对命中路径的 add_finding 拒不受理）；
    suspect=定性公诉意见 → 任务单 precheck_hints（提示观察者重点核实，非结论）。"""
    rejects: list[str] = []
    hints: list[dict] = []
    for rel in new_finding_paths:
        p = root / rel
        text = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        pre = noreport_check({"summary": _finding_summary_of(p), "endpoint": ""}, text)
        if pre["verdict"] == "reject":
            rejects.append(rel)
        elif pre["verdict"] == "suspect":
            hints.append({"path": rel,
                          "hint": f"疑似 {pre['category']}：{pre['reason']}"})
    return rejects, hints



def _observer_feedback(root: Path, bb, doc, noreport_rejects: list[str]) -> str:
    """resume 反馈文本（Cairn conclude-fallback）：把执行器校验的 rejects 精确回喂，
    观察者带完整上下文修正判断书后重新提交。"""
    if doc is None:
        return ("你退出时没有留下合法的判断书（.observer/OBSERVER.json 不存在/无法解析/"
                "operations 为空）。请按 .observer/INTERFACE.md 协议重新写判断书，"
                "运行任务单里的 submit_cmd 提交成功后退出。")
    check_bb = board_mod.Blackboard(str(root / ".at1" / "blackboard.json"))
    res_o = observer_harvest.apply_judgment(check_bb, doc, round=0, root=None,
                                            noreport_rejects=set(noreport_rejects))
    if res_o["rejects"]:
        det = "；".join(f"第{r.get('index', '?')}条 {r.get('error', '')}"
                        for r in res_o["rejects"][:5])
        return (f"你的判断书有 {len(res_o['rejects'])} 条未通过校验：{det}。"
                "请修正 .observer/OBSERVER.json 后重新运行 submit 命令提交。")
    return ("判断书校验通过但没有成功提交标记（SUBMITTED）——"
            "请运行任务单里的 submit_cmd 提交后退出。")


def run_engagement(engagement_root: str, *, budget_s: float | None = None,
                   max_rounds: int | None = None, stop_on_first_confirmed: bool = False,
                   dry_run: bool = False, provider: str | None = None,
                   observer_on: bool = True) -> int:
    """budget_s=None（默认）= 总预算不设——判停靠 worker Stop/人工 stop/止损；
    显式给 budget_s 则恢复预算兜底边。返回 0 正常 / 2 启动失败 / 1 异常。"""
    root = Path(engagement_root)

    # ── 启动 fail-fast ──
    try:
        eng = scaffold.load_engagement(root)
    except (FileNotFoundError, ValueError) as e:
        print(f"[driver] 拒启：{e}")
        return 2
    pointer = root / "notes" / "prior-intel.md"
    if not pointer.is_file() or not pointer.read_text(encoding="utf-8").strip():
        print(f"[driver] 拒启：notes/prior-intel.md 缺失或为空（{pointer}）")
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
    # U-1 同源：skills 供给也确定性化——engagement.json 显式值 > 全局默认(AT1_SKILLS_SRC) > 无
    skills_src = eng.get("skills_src") or os.getenv("AT1_SKILLS_SRC") or None
    bb = board_mod.Blackboard(str(pilot / "blackboard.json"))   # v3 容器（旧 _blackboard.json 遗形不读）
    scaffold.seed_engagement(eng, bb)               # §11 播种：target/goal/hint 空则播，scope 覆盖
    bb.save()          # S5/R-8：关键簿记（scope）播种即落盘——中断不丢授权边界
    workdir = scaffold.expand(root, eng, bb, skills_src=skills_src)   # 单层化：根=worker cwd
    ev = events_mod.EventWriter(str(root / "state" / "auto-log.jsonl"))
    scope_cfg = bb.bookkeeping.get("scope") or {}
    # S13：root=engagement 根——结构化路径走路径代数（worker cwd=根）
    guard = Guard.from_engagement({"scope": scope_cfg}, root=root)
    # F1（2026-10-13）：--rounds 是相对本次 run 的轮数——base_round 取启动时簿记
    # 轮号，Stoploss 内按差值判。老 engagement（簿记轮号=5）--rounds 1 = 再跑 1 轮。
    sl = Stoploss(max_rounds=max_rounds,
                  base_round=int(bb.bookkeeping.get("round", 0) or 0))

    # 配方 0 播种（R5）：画像 fact 一条 + 指针
    _seed_from_engagement(root, bb)

    ev.emit("run_start", {"engagement": str(root), "target": eng.get("target"),
                          "provider": solver.provider, "budget_s": budget_s})
    if bb.legacy_archived:
        ev.emit("board_legacy_archived", {"path": bb.legacy_archived})
        print(f"[driver] 旧板归档：{bb.legacy_archived}")
    if not scope_cfg.get("allow"):
        ev.emit("scope_missing", {"note": "无授权清单——guard 目标越界记录停用（禁区/自毁检测保留）"})
    # F2（2026-10-13）：resume 只在真续跑发。图非空不作数——配方 0 播种在本判定
    # 之前跑，首跑图必非空（jwzx 首跑实抓假 resume {nodes:1}）。簿记轮号跨 run
    # 持久：新 engagement 必为 0，真续跑必有轮号。
    if int(bb.bookkeeping.get("round", 0) or 0) > 0 and bb.graph["nodes"]:
        ev.emit("resume", {"nodes": len(bb.graph["nodes"]),
                           "confirmed": len(bb.confirmed_findings())})
    print(f"[driver] engagement={root} target={eng.get('target')} solver={solver.provider}")

    stop_reason, exit_code = "budget", 0
    t0 = time.monotonic()
    directive_next: str | None = None
    had_confirmed_at_round: int | None = None

    def _brief(rnd_: int, box_: int, left_: float | None) -> str:
        """简报正文（元信息；判层指路由 prompt.py 块壳统一加）。"""
        budget_txt = (f"剩余预算 {int(left_)}s，" if left_ is not None
                      else "总预算未设（判停靠 Stop/人工停），")
        return (f"目标 {eng.get('target')}（授权范围见 CLAUDE.md）。"
                f"身份：{'storage-state.json（已注入）' if (workdir / 'storage-state.json').exists() else '见 evidence/cookies.txt 或匿名'}。"
                f"{budget_txt}时间盒 {box_}s。")

    if dry_run:
        # 预览含留言但不消费偏移（真 run 的轮间收割才推进 offsets）
        hints_lines, _ = harvest.diff_new_lines(
            str(pilot / "control" / "hints.jsonl"), bb.offsets.get("hints", 0))
        hint_texts = []
        for ln in hints_lines:
            try:
                d_h = json.loads(ln)
            except (json.JSONDecodeError, ValueError):
                continue
            t_h = str(d_h.get("text", "")).strip()
            if t_h:
                hint_texts.append(t_h[:300])
        preview_directive = "；".join(hint_texts)[:800] or None
        p = prompt_mod.render_round_prompt(
            bb, directive=preview_directive, guide=_guide_from_state(root), round_=1,
            brief=_brief(1, _timebox(1), budget_s if budget_s is not None else None))
        out = root / "state" / "dry-run-prompt.md"
        out.write_text(p, encoding="utf-8")
        (workdir / "STATE.md").write_text(_render_state_minimal(bb), encoding="utf-8")
        bb.save()          # 落盘图（验收可查：播种画像 fact=1）
        print(f"[driver] dry-run：首轮 prompt → {out}；STATE.md → {workdir / 'STATE.md'}"
              f"；图 → {pilot / 'blackboard.json'}（未 spawn）")
        ev.emit("run_end", {"reason": "dry-run"}, round_=0)
        return 0

    # ── 启动预检（Cairn 式：把无声失败消灭在 spawn 前，2026-09-14）──
    pf = _preflight(os.getenv("AT1_CLAUDE_BIN", "claude"), workdir / ".mcp.json")
    ev.emit("preflight", {**pf})
    print(f"[driver] 预检：claude={pf['claude']} | mcp={pf['mcp']}")
    if not pf["ok"]:
        ev.emit("run_end", {"reason": "preflight-fail"}, round_=0)
        ev.close()
        print("[driver] 拒启：claude CLI 不可用")
        return 2

    # ── 浏览器池（playwright 批 B2）：driver 托管 engagement 专属 Chrome，MCP
    #    经 env 附着为客人；缺席/失败不拒启（与 preflight 哲学一致）。skip 路径
    #    主动清 env——防 shell 全局残值穿透给 worker（B3 反向）。 ──
    handle = BrowserHandle.start(root, ev, mcp_config=workdir / ".mcp.json")
    if handle is not None:
        os.environ["PLAYWRIGHT_MCP_CDP_ENDPOINT"] = handle.endpoint
    else:
        os.environ.pop("PLAYWRIGHT_MCP_CDP_ENDPOINT", None)

    # S5/R-6：轮号从簿记续（进程内从 0 起是"续跑轮号重置为 1"的根因）
    rnd = int(bb.bookkeeping.get("round", 0) or 0)
    # ── S12 接力触发：phase.json 残留=上次进程未走到干净收尾（stop/崩溃/断电
    #    一个条件全覆盖）。旧格式无 session_id → 走老路径，天然兼容。 ──
    interrupted: dict | None = phase_mod.read(root)
    if interrupted and interrupted.get("phase") not in ("working", "auditing"):
        interrupted = None                   # 未知 phase（损坏/老格式变种）→ 老路径
    if interrupted:
        ev.emit("interrupted_phase", {"phase": interrupted.get("phase"),
                                      "round": interrupted.get("round"),
                                      "has_session": bool(interrupted.get("session_id"))})
        print(f"[driver] 上次中断于 {interrupted.get('phase')} "
              f"r{interrupted.get('round')}——能续则续，续不了则新开")
    prev_inventory: dict = {}               # 目录页指纹（内存级；重启清零→首轮全标新增，无害）
    # ── P-11 v2（2026-09-14，参照 ARTEX具名取消/Cairn 即时杀）：盯梢线程 ──
    # 0.5s 轮询 CONTROL，看到 stop 立即杀 worker 进程树并置标志。
    # 停机语义 = drain（收割落盘可续跑），与 ARTEX/Cairn/hxbai 三家一致。
    stop_requested: dict = {"hit": False, "text": ""}
    watcher_stop = threading.Event()
    proc_ref: dict = {}

    def _control_watcher():
        while not watcher_stop.is_set():
            try:
                _consume_stop_file(root / "state" / "CONTROL",
                                   proc_ref, stop_requested)
            except Exception:
                pass
            if stop_requested["hit"]:
                # Cairn 式竞态防护：stop 时 worker 可能尚未 spawn/挂上 proc_ref——
                # 继续盯到出现为止补杀，防止"信号到早了"漏杀
                while not watcher_stop.is_set():
                    pr = proc_ref.get("proc")
                    if pr is not None:
                        if pr.poll() is None:
                            _controller_kill(pr)
                        break
                    time.sleep(0.2)
                return
            watcher_stop.wait(0.5)

    threading.Thread(target=_control_watcher, daemon=True, name="at1-control-watcher").start()

    try:
        while True:
            rnd += 1
            if stop_requested["hit"]:                # 盯梢线程在轮间消费了 stop
                stop_reason, exit_code = "control-stop(D)", 0
                break
            # CONTROL 轮间轮询（pause/directive 仍走这里；stop 已由盯梢线程即时消费）
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
            if stop_requested["hit"]:                # 二次读（续修批竞态闭合）：
                stop_reason, exit_code = "control-stop(D)", 0   # 盯梢线程可能在
                break                                           # 上次读标志之后才置位
            # ── 留言队列收割（T2.8/A24）：hints.jsonl 按偏移，追加式，进本轮【人工指示】 ──
            hints_lines, hoff = harvest.diff_new_lines(
                str(pilot / "control" / "hints.jsonl"), bb.offsets.get("hints", 0))
            if hints_lines:
                bb.offsets["hints"] = hoff
                texts = []
                for ln in hints_lines:
                    try:
                        d_h = json.loads(ln)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    t_h = str(d_h.get("text", "")).strip()
                    if t_h:
                        texts.append(t_h[:300])
                if texts:
                    extra = "；".join(texts)[:800]
                    directive_next = f"{directive_next}；{extra}" if directive_next else extra
                    ev.emit("hint_injected", {"round": rnd, "count": len(texts)}, round_=rnd)
                bb.save()          # S5/R-8：偏移推进即落盘——中断/续跑不重放旧插话

            box = _timebox(rnd)
            budget_left = (budget_s - (time.monotonic() - t0)) if budget_s is not None else float("inf")
            if budget_s is not None and budget_left <= 0:
                stop_reason, exit_code = "budget(B)", 0
                break

            # ── 轮间浏览器探活自愈（playwright 批 B2）：假死/崩溃 → 杀旧拉新，
            #    登录态从 profile 回；彻底起不来 handle 自行置 dead，不空转 ──
            if handle is not None:
                handle.ensure()

            # ── S12：auditing 残留 → 上进程本轮 worker 已收工（观察者 spawn 是其前提）
            #    ——跳过派工，观察者块里续接审计。观察者关用时放弃接力，轮次照走。 ──
            resume_audit_sid = ""
            if (interrupted is not None and interrupted.get("phase") == "auditing"
                    and interrupted.get("session_id")):
                if observer_on:
                    resume_audit_sid = interrupted["session_id"]
                interrupted = None                       # 接力只试一次（消费即不再来）
            res = None
            if not resume_audit_sid:
                # ── 渲染 prompt（三块终态：引导/运行提示/简报） ──
                # 引导来源=观察者写的 STATE.md "## 下轮建议"节（批3fix：guide 行退役）
                normal_prompt = prompt_mod.render_round_prompt(
                    bb, directive=directive_next, guide=_guide_from_state(root), round_=rnd,
                    brief=_brief(rnd, box, budget_left if budget_s is not None else None))
                directive_next = None
                # S12：working 残留 → 本轮 worker 会话=续接被杀会话（保工作记忆）
                resume_worker_sid = ""
                if (interrupted is not None and interrupted.get("phase") == "working"
                        and interrupted.get("session_id")):
                    resume_worker_sid = interrupted["session_id"]
                    interrupted = None                   # 接力只试一次
                prompt = _WORKER_RESUME_PROMPT if resume_worker_sid else normal_prompt

                # ── spawn worker ──
                ev.emit("session_start", {"round": rnd, "goal": bb.goal.get("text", "")[:40],
                                          "timebox": box,
                                          "resumed": bool(resume_worker_sid)}, round_=rnd)
                phase_mod.write(root, "working", rnd, role="worker")    # S5 转换点①
                nodes_before = len(bb.graph["nodes"])
                tx_path = pilot / "transcript.jsonl"

                def on_fact(t, _r=rnd):
                    v = guard.check_tool(t.tool, t.args or {}, role="worker")   # S10
                    if not v.ok:
                        ev.emit("guard_violation", {"round": _r, "kind": v.kind,
                                                    "tool": t.tool, "reason": v.reason[:200],
                                                    "critical": v.kind == "self_destruct"}, round_=_r)

                def on_heartbeat(d, _r=rnd):
                    # P-11 v2：CONTROL 消费已移交盯梢线程（0.5s 粒度）——心跳只报数
                    ev.emit("heartbeat", {"round": _r, **d}, round_=_r)

                def _phase_sid(sid, _r=rnd):
                    # S12：会话句柄捕获即落账本——被杀后续接才有 id 可续
                    phase_mod.write(root, "working", _r, session_id=sid, role="worker")

                task = runner.AgentTask(on_fact=on_fact, on_heartbeat=on_heartbeat,
                                        transcript_path=str(tx_path),
                                        on_spawn=lambda proc: proc_ref.__setitem__("proc", proc),
                                        on_session_id=_phase_sid)
                try:
                    res = runner.run(prompt, str(workdir), solver, task,
                                     time_box_s=min(box, budget_left), max_turns=MAX_TURNS,
                                     resume_session_id=resume_worker_sid or None)
                except Exception:
                    if not resume_worker_sid:
                        raise
                    res = None
                if resume_worker_sid and (res is None or res.is_error):
                    # S12：续接失败（session 不存在/截断损坏/报错）→ 落回新开——
                    # 只此一次，resume_fallback 留账，永不循环（区别于批3 P-11 复活梯子）
                    ev.emit("resume_fallback",
                            {"role": "worker", "session_id": resume_worker_sid,
                             "error": ((res.error if res is not None else "") or "spawn-fail")[:120]},
                            round_=rnd)
                    res = runner.run(normal_prompt, str(workdir), solver, task,
                                     time_box_s=min(box, budget_left), max_turns=MAX_TURNS,
                                     resume_session_id=None)
                ev.emit("session_end", {"round": rnd, "stop_reason": res.stop_reason,
                                        "turns": res.turns, "tokens": res.tokens,
                                        "total_cost_usd": round(res.total_cost_usd, 4),
                                        "resumes": res.resumes,
                                        "thinking_events": res.thinking_events}, round_=rnd)
                print(f"[worker r{rnd}] stop={res.stop_reason} turns={res.turns} "
                      f"tokens={res.tokens} nodes={len(bb.graph['nodes'])}")

                # ── S1 门 A（stop during worker）：会话已死、观察者未生——别生下一胎。
                #    盘面冻结在 worker 被杀瞬间：bb.save 后即退，目录页/审计全跳过。 ──
                if stop_requested["hit"]:
                    bb.save()
                    phase_mod.write(root, "working", rnd,            # S5 转换点④：stop 补一次
                                    session_id=res.session_id, role="worker")
                    stop_reason, exit_code = "control-stop(W)", 0
                    break

            # ── 无状态目录页（批4 G1-A）：全量盘点 worker 写盘面 → 观察者任务单 ──
            page, inv_state = _inventory_page(root, prev_inventory)
            prev_inventory = inv_state
            new_finding_paths = [p for p in page["new_or_changed"] if p.startswith("findings/")]
            noreport_rejects, precheck_hints = _noreport_scan(root, new_finding_paths)

            # ── Handoff（A19：读者=观察者，进任务单）。续审计轮无 worker 结果——
            #    handoff 保持上进程已录内容，不覆盖 ──
            if res is not None:
                bb.record_handoff(res.handoff or "")
                ev.emit("handoff_harvested", {"round": rnd,
                                              "origin": "model" if res.handoff else "none",
                                              "head": (res.handoff or "")[:60]}, round_=rnd)
                # 续修批实机修正（usc-cwcx-b1）：止损信号源换成本轮 worker 盘面
                # 新增/变更文件数——旧信号（图节点增量）在批3fix 架构下恒为 0
                #（worker 只写文件，图只在观察者轮末变，且发生在本记账之后），
                # 导致任何 run 必在第 3 轮被"无新事实"误杀，与产出无关。
                sl.record_round(facts_delta=len(page["new_or_changed"]),
                                session_ok=(res.stop_reason != "error"))

            # ── 观察者（F6）：-p 会话审计 → submit-judgment 提交 → 执行器入图。
            #    未成功提交 → resume 同 session 精确回喂一次（Cairn conclude-fallback）；仍失败 → 告警 ──
            if observer_on:
                observer.copy_observer_kit(root)
                observer.clear_judgment(root)
                state_md = root / "STATE.md"
                state_mtime_before = state_md.stat().st_mtime if state_md.is_file() else 0.0
                submit_cmd = f'"{sys.executable}" "{Path(__file__).resolve().parent.parent / "src" / "submit.py"}" "{root}"'
                sheet = {"round": rnd, "goal": bb.goal.get("text", ""),
                         "timebox": box,
                         "worker_output": page,
                         "noreport_rejects": noreport_rejects,
                         "precheck_hints": precheck_hints,
                         # 续审计轮 res=None——簿记 handoff 即上进程 worker 的遗留
                         "handoff": str(bb.bookkeeping.get("handoff", ""))[:500],
                         "graph_path": ".at1/blackboard.json",
                         "manual": ".observer/OBSERVER-MANUAL.md",
                         "interface": ".observer/INTERFACE.md",
                         "submit_cmd": submit_cmd}

                def on_tool(t, _r=rnd):
                    v = guard.check_tool(t.tool, t.args or {}, role="observer")   # S10
                    if not v.ok:
                        ev.emit("guard_violation", {"round": _r, "role": "observer",
                                                    "kind": v.kind, "tool": t.tool,
                                                    "reason": v.reason[:200],
                                                    "critical": v.kind == "self_destruct"},
                                round_=_r)

                phase_mod.write(root, "auditing", rnd, role="observer")   # S5 转换点②

                def _obs_sid(sid, _r=rnd):
                    phase_mod.write(root, "auditing", _r, session_id=sid, role="observer")

                res_o = observer.run_once(root, sheet, on_tool=on_tool,
                                          on_spawn=lambda proc: proc_ref.__setitem__("proc", proc),
                                          on_session_id=_obs_sid,
                                          resume_session_id=resume_audit_sid or None,
                                          resume_prompt=_OBSERVER_RESUME_PROMPT
                                          if resume_audit_sid else None)
                if resume_audit_sid and res_o.get("is_error"):
                    # S12：审计续接失败 → 新开=重新全量审计（审计无状态，最坏=现状）
                    ev.emit("resume_fallback", {"role": "observer",
                                                "session_id": resume_audit_sid,
                                                "error": (res_o.get("error") or "")[:120]},
                            round_=rnd)
                    res_o = observer.run_once(root, sheet, on_tool=on_tool,
                                              on_spawn=lambda proc: proc_ref.__setitem__("proc", proc),
                                              on_session_id=_obs_sid)
                ev.emit("observer_session_end",
                        {"round": rnd, "stage": "initial", **res_o}, round_=rnd)
                # ── S1 门 B（stop during observer）：观察者被杀 → 判断书未入图即作废
                #    （审计无状态全量，下轮盘点一起审）；不写 STATE，盘面冻结即退。
                #    .observer/ 草稿留下次审计开工时 clear_judgment 清。 ──
                if stop_requested["hit"]:
                    bb.save()
                    phase_mod.write(root, "auditing", rnd,            # S5 转换点④：stop 补一次
                                    session_id=res_o.get("session_id") or "", role="observer")
                    stop_reason, exit_code = "control-stop(O)", 0
                    break
                doc = observer.read_judgment(root)
                submitted = observer.submitted(root)
                if doc is None or not submitted:
                    # 未成功提交 → resume 同 session 精确回喂（Cairn conclude-fallback，一次机会）
                    feedback = _observer_feedback(root, bb, doc, noreport_rejects)
                    ev.emit("observer_resume_feedback",
                            {"round": rnd, "head": feedback[:80]}, round_=rnd)
                    res_o = observer.run_once(root, sheet, on_tool=on_tool,
                                              on_spawn=lambda proc: proc_ref.__setitem__("proc", proc),
                                              resume_session_id=res_o.get("session_id"),
                                              feedback=feedback)
                    ev.emit("observer_session_end",
                            {"round": rnd, "stage": "retry", **res_o}, round_=rnd)
                    doc = observer.read_judgment(root)
                    submitted = observer.submitted(root)
                    if doc is None or not submitted:
                        ev.emit("observer_empty_retry",
                                {"round": rnd, "stage": "exhausted"}, round_=rnd)
                if doc is not None and submitted:
                    res_a = observer_harvest.apply_judgment(
                        bb, doc, round=rnd, root=root,
                        noreport_rejects=set(noreport_rejects))
                    if res_a["rejects"]:
                        observer_harvest.write_rejects(root, res_a["rejects"], round=rnd)
                        ev.emit("observer_parse_fail",
                                {"round": rnd, "count": len(res_a["rejects"])}, round_=rnd)
                    ev.emit("observer_applied", {"round": rnd, **res_a["counts"]}, round_=rnd)
                    print(f"[观察者 r{rnd}] " + " | ".join(
                        f"{k}={v}" for k, v in res_a["counts"].items() if v))
                # STATE.md：观察者写了就用；没写 → 兜底极简计数（防 P-13 式静默失联）
                if not state_md.is_file() or state_md.stat().st_mtime <= state_mtime_before:
                    state_md.write_text(_render_state_minimal(bb), encoding="utf-8")
                    ev.emit("state_fallback", {"round": rnd}, round_=rnd)
            else:
                (root / "STATE.md").write_text(_render_state_minimal(bb), encoding="utf-8")

            bb.bookkeeping["round"] = rnd               # S5：轮号持久——续跑接着编号
            phase_mod.write(root, "working", rnd)       # S5 转换点③：入图完成→下轮 working（清 sid）

            # ── worker Stop 终判（A18 判停三角第三边；drain——上方已落盘） ──
            if res is not None and res.stop_text:
                parsed_stop = bb.validate_stop_content(res.stop_text)
                if parsed_stop is not None:
                    stop_reason, exit_code = "worker-stop(C)", 0
                    ev.emit("worker_stop", {"round": rnd, "kind": parsed_stop["kind"],
                                            "refs": parsed_stop["refs"],
                                            "head": parsed_stop["reason"][:80]}, round_=rnd)
                    break
                ev.emit("stop_invalid", {"round": rnd, "head": res.stop_text[:60]}, round_=rnd)

            # ── 终止判定（判停三角：预算+人工停；其余两边已接） ──
            if stop_on_first_confirmed and bb.confirmed_findings():
                stop_reason, exit_code = "confirmed(A)", 0
                break
            if bb.confirmed_findings() and had_confirmed_at_round is None:
                had_confirmed_at_round = rnd
            ev.emit("phase_check", {"round": rnd, "goal": bb.goal.get("text", "")[:40]},
                    round_=rnd)
            stop, why = sl.should_stop(
                rnd, (budget_s - (time.monotonic() - t0)) if budget_s is not None else float("inf"))
            if stop:
                ev.emit("stoploss_trigger", {"round": rnd, "dim": why}, round_=rnd)
                stop_reason, exit_code = f"stoploss(B):{why}", 0
                break
            if stop_requested["hit"]:                # P-11 v2：轮中被喊停，收割完即收工
                stop_reason, exit_code = "control-stop(D)", 0
                break

    finally:
        # playwright 批 B2：Chrome 收尾——KEEP=1 留守（browser.json 供下次
        # 复用）、KEEP=0 杀+清账。stop/budget/worker-stop/异常路径全收得到。
        if handle is not None:
            handle.shutdown(keep=os.getenv("AT1_BROWSER_KEEP") == "1")

    # ── 收尾（批3fix：writeback 全家退役——draft 归观察者，board 落盘即真相） ──
    watcher_stop.set()                           # 收盯梢线程
    bb.save()
    # S12：control-stop 留账本残留（=续接触发器：被杀会话能续则续）；
    # 其余（budget/stoploss/worker-stop/pause）=干净收尾，清账防误触发。
    if not stop_reason.startswith("control-stop"):
        phase_mod.clear(root)
    ev.emit("run_end", {"reason": stop_reason, "rounds": rnd,
                        "confirmed": len(bb.confirmed_findings()),
                        "stop_text": stop_requested.get("text", "")}, round_=rnd)
    ev.close()
    print(f"[driver] 终止：{stop_reason}；轮次 {rnd}；confirmed {len(bb.confirmed_findings())}")
    return exit_code
