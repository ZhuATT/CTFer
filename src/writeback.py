"""AT1 writeback —— engagement 协议文件写回（P4.6，设计§2.2）。

机器只做三种写：
  ① status.md 漏洞表**表尾**追加行（confirmed 时；不整文件重写）
  ② status.md 攻击面段深度列刷新（confirmed→deep / tentative→tested / 事实→seen）
  ③ 收尾生成 notes/prior-intel-draft.md（跨 run 接力的机器半边）

宽容模式：段落锚点缺失/解析失败 → 跳过 + 返回失败原因（driver 记
surface_parse_fail 事件），绝不因格式问题丢数据或中断 run。
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_ANCHORS = ("## 漏洞表", "## 攻击面", "## 已确认非漏洞", "## 阻断项")
_SEV_ZH = {"high": "高", "medium": "中", "low": "低"}


def _read(p) -> str:
    return Path(p).read_text(encoding="utf-8") if Path(p).is_file() else ""


# ── ① 漏洞表表尾追加 ─────────────────────────────────────────────────────

def append_status_row(status_path: str, finding: dict, round_no: int = 0) -> tuple[bool, str]:
    """confirmed finding → 漏洞表表尾一行。返回 (ok, 原因)。"""
    path = Path(status_path)
    text = _read(path)
    if "## 漏洞表" not in text:
        # 宽容：无锚点 → 建骨架（首次 confirmed 时文件可能只有空段）
        if not text:
            text = "# Engagement Status\n\n## 漏洞表\n| ID | 等级 | 标题 | 证据 |\n|---|---|---|---|\n\n" \
                   "## 攻击面\n| 功能/端点 | 深度 | 测过什么 | 结论/免疫 |\n|---|---|---|---|\n\n" \
                   "## 已确认非漏洞\n\n## 阻断项\n"
        else:
            return False, "status.md 缺锚点 ## 漏洞表"

    fid = finding.get("id", "?")
    if fid in text:                        # 幂等：同 ID 已在表里不重复追加
        return True, "already-present"
    sev = _SEV_ZH.get(str(finding.get("severity", "")), str(finding.get("severity") or "?"))
    row = (f"| {fid} | {sev} | {str(finding.get('summary', ''))[:120]} "
           f"| {finding.get('evidence', '')} (r{finding.get('round', round_no)}) |")

    lines = text.splitlines()
    out: list[str] = []
    in_vuln = False
    inserted = False
    for i, ln in enumerate(lines):
        if ln.strip().startswith("##"):
            if in_vuln and not inserted:   # 段结束还没插 → 插在段尾空行前
                out.append(row)
                inserted = True
            in_vuln = ln.strip() == "## 漏洞表"
        elif in_vuln and ln.strip().startswith("|") and not inserted:
            # 表尾 = 最后一个表格行：先看下一行还是不是表
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if not nxt.startswith("|"):
                out.append(ln)
                out.append(row)
                inserted = True
                continue
        out.append(ln)
    if not inserted:                       # 段内无表 → 补表头+行
        out = lines + ["| ID | 等级 | 标题 | 证据 |", "|---|---|---|---|", row]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return True, "appended"


# ── ② 攻击面深度刷新 ─────────────────────────────────────────────────────

def _ep_key(endpoint: str) -> str:
    return (endpoint or "").split("?")[0].strip().rstrip("/").lower()


def refresh_surface_depth(status_path: str, board) -> tuple[bool, str]:
    """攻击面段深度列：confirmed 覆盖→deep / uncertain→tested / 事实→seen。
    深度只升不降（deep 不被 seen 覆盖）。"""
    path = Path(status_path)
    text = _read(path)
    if "## 攻击面" not in text:
        return False, "status.md 缺锚点 ## 攻击面（宽容跳过）"

    deep_eps = {_ep_key(f.get("endpoint", "")) for f in board.confirmed_findings()}
    tested_eps = {_ep_key(f.get("endpoint", ""))
                  for f in board.findings if f.get("assessment") in ("uncertain", "duplicate")}
    seen_eps = {_ep_key(f.get("value", "").lstrip("GET POST PUT DELETE PATCH "))
                for f in board.query("endpoint")}
    seen_eps.discard("")

    lines = text.splitlines()
    out: list[str] = []
    in_surface = False
    changed = 0
    for ln in lines:
        s = ln.strip()
        if s.startswith("##"):
            in_surface = s == "## 攻击面"
            out.append(ln)
            continue
        if in_surface and s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if len(cells) >= 2 and cells[1] in ("seen", "tested", "deep"):
                ep = _ep_key(cells[0])
                target = ("deep" if ep in deep_eps else
                          "tested" if ep in tested_eps else
                          "seen" if ep in seen_eps else cells[1])
                rank = {"seen": 0, "tested": 1, "deep": 2}
                if rank.get(target, 0) > rank.get(cells[1], 0):
                    cells[1] = target
                    changed += 1
                out.append("| " + " | ".join(cells) + " |")
                continue
        out.append(ln)
    if changed:
        path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return True, f"refreshed {changed}"


# ── ③ prior-intel-draft 生成 ─────────────────────────────────────────────

def gen_prior_intel_draft(engagement_root: str, board, stop_reason: str = "") -> Path:
    """收尾生成 notes/prior-intel-draft.md（续跑表单预填素材）。"""
    parts = ["# 下次任务前置情报（机器生成，人确认后合并）", ""]
    if stop_reason:
        parts.append(f"- 上次终止：{stop_reason}")
    cf = board.confirmed_findings()
    if cf:
        parts.append("## 已确认发现")
        parts += [f"- {f.get('id')} {_ep_key(f.get('endpoint',''))}：{f.get('summary','')}"
                  f"（{f.get('severity','?')}）" for f in cf]
    for f in board.query("identity_model"):
        parts += ["", "## 身份模型结论", f"- {f['value']}"]
    if board.immune:
        parts += ["", "## 免疫清单（阴性记录）"]
        parts += [f"- {i.get('endpoint')}（{i.get('status') or '?'}）" for i in board.immune]
    si = board.session_intel or {}
    if si.get("coverage_gaps"):
        parts += ["", "## 未测面/覆盖缺口"] + [f"- {g}" for g in si["coverage_gaps"]]
    if si.get("effective_patterns"):
        parts += ["", "## 有效模式"] + [f"- {p}" for p in si["effective_patterns"]]
    if si.get("intel_summary"):
        parts += ["", "## 情报摘要", si["intel_summary"]]
    parts += ["", "## 待跟进", f"- 交接：{(board.handoff or '（无）')[:400]}"]

    out = Path(engagement_root) / "notes" / "prior-intel-draft.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return out


# ── ④ 启动反向读：已确认非漏洞 → immune 播种 ────────────────────────────

_EP_RX = re.compile(r"(/[A-Za-z0-9_/.{}\-]{2,80})")


def parse_immune_from_status(status_path: str) -> list[dict]:
    """读"## 已确认非漏洞"段，提取端点形状 → immune 记录（driver 启动播种）。"""
    text = _read(status_path)
    if "## 已确认非漏洞" not in text:
        return []
    out: list[dict] = []
    in_seg = False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("##"):
            if in_seg:
                break
            in_seg = s == "## 已确认非漏洞"
            continue
        if in_seg and s and not s.startswith("|"):
            for m in _EP_RX.findall(s):
                ep = m.rstrip("。，,；;)）").rstrip("/")
                if ep and not any(i["endpoint"] == ep for i in out):
                    out.append({"endpoint": ep, "status": s[:60], "since_round": 0})
    return out
