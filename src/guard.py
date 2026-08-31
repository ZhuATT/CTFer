"""AT1 guard —— scope 拦截 + 控制器区禁写 + 自毁检测（P4.2，设计§3.7）。

机制诚实：worker 跑 --dangerously-skip-permissions，guard 没有 OS 层强制力。
拦截的三层实现：
  ① 教育层：deny 列表 + 控制器区禁令渲染进 CLAUDE.md（scaffold 已做）
  ② 实时检测：driver 挂进 runner on_fact——每个工具调用到达即判，
     命中 → guard_violation 事件（越界记录在案，回放/审计可见）
  ③ 高危自毁：同路检测（黑名单命令特征），事件标 critical

设计 §2.3 不变量：transcript/黑板是门 3 物理锚，worker 写控制器区 = 伪造证据，
所以控制器区写检测是唯一"该硬"的判定——命中即记高危（不可降级为提示）。
scope 拦截宽松取向：URL 解析失败的命令放行（误拦正常工作流比漏拦更伤）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

# 控制器区/协议文件区（对 workdir 而言）。worker cwd = workdir，碰这些路径
# （相对或经 ../ 回溯）都是越权。evidence/ 不在禁区——那是 worker 的合法
# 写入目录（workdir/evidence）。
# 匹配用非锚定搜索（命令文本里路径在中间）；URL 先剥掉再查（url 路径 /state/ 不是禁区）。
_ZONE_PATH_RX = re.compile(
    r"(?:\.\./)*(?:\.at1|state|notes)/|_(?:blackboard|transcript)\.(?:json|jsonl|bak|tmp)",
    re.IGNORECASE)
_URL_STRIP_RX = re.compile(r"https?://\S+", re.IGNORECASE)

# 自毁特征（Windows + Unix 双形态；命中记 critical 事件）
_SELF_DESTRUCT_RX = re.compile(
    r"\brm\s+-rf\s+[/~.]|del\s+/[sq]|format\s+[a-z]:|mkfs|"
    r">\s*/dev/sda|remove-item\s+-recurse|rd\s+/s|"
    r"find\s+.*-delete\s+/\*|shutdown|/etc/passwd\s*<<", re.IGNORECASE)

_WRITE_TOOL_HINT_RX = re.compile(r">>|>\s*\S|\btouch\b|\btee\b|\bmv\b|\bcp\b|"
                                 r"\brm\b|\bdel\b|\bwrite|\bsave|\bcreate\b|"
                                 r"\bnew-file\b|\bedit\b|"
                                 r"add-content|set-content|out-file|"
                                 r"copy-item|move-item|remove-item", re.IGNORECASE)


@dataclass
class GuardVerdict:
    ok: bool
    kind: str = ""          # scope / controller_zone / self_destruct / ""
    reason: str = ""


class Guard:
    """消费 engagement scope，判定工具调用是否越界。无副作用纯判定。"""

    def __init__(self, allow: list[str], deny: list[str]):
        self.allow = [str(a).lower().lstrip("*.").lstrip(".") for a in allow if a]
        self.deny = [str(d).lower().lstrip("*.").lstrip(".") for d in deny if d]

    # ── scope ────────────────────────────────────────────────────────────

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urlsplit(url).hostname or "").lower()
        except ValueError:
            return ""

    def _host_allowed(self, host: str) -> bool:
        if not host:
            return True                     # 解析不出主机（本地文件/相对路径）→ 放行
        for d in self.deny:
            if host == d or host.endswith("." + d):
                return False
        return not self.allow or any(
            host == a or host.endswith("." + a) for a in self.allow)

    def check_url(self, url: str) -> GuardVerdict:
        host = self._host_of(url)
        if not host:
            return GuardVerdict(True)     # 本地文件/相对路径 → 放行（宽松取向）
        for d in self.deny:
            if host == d or host.endswith("." + d):
                return GuardVerdict(False, "scope",
                                    f"deny 命中：{host} ∈ deny[{d}]")
        if self.allow and not any(host == a or host.endswith("." + a) for a in self.allow):
            return GuardVerdict(False, "scope", f"allow 外目标：{host}")
        return GuardVerdict(True)

    # ── 工具调用综合判定（on_fact 挂点） ─────────────────────────────────

    def check_tool(self, tool: str, args: dict) -> GuardVerdict:
        """URL 类参数走 scope；Bash/PowerShell 命令查自毁 + 控制器区写；写类工具查路径。

        Windows worker 实测用 PowerShell 工具（P4.9 事件流 tool:PowerShell）——
        命令类检查必须覆盖，否则自毁/禁区检测在 Windows 上形同虚设。
        """
        # ① 自毁（最高优先级，critical）
        if tool in ("Bash", "Execute", "PowerShell", "Shell"):
            cmd = str((args or {}).get("command", "") or (args or {}).get("script", ""))
            if _SELF_DESTRUCT_RX.search(cmd):
                return GuardVerdict(False, "self_destruct", f"高危命令特征：{cmd[:120]}")
            # 禁区查命令文本（URL 剥掉——url 路径段 /state/ 不是禁区）
            cmd_sanitized = _URL_STRIP_RX.sub(" ", cmd)
            if _ZONE_PATH_RX.search(cmd_sanitized) and _WRITE_TOOL_HINT_RX.search(cmd_sanitized):
                return GuardVerdict(False, "controller_zone",
                                    f"疑似写控制器区/协议文件：{cmd[:120]}")
            # 命令里的 curl/wget URL 走 scope
            for m in _URL_STRIP_RX.finditer(cmd):
                v = self.check_url(m.group(0))
                if not v.ok:
                    return v
        # ② URL 类参数（MCP playwright / WebFetch 的 url 参数）
        for key in ("url", "target", "endpoint"):
            u = str((args or {}).get(key, "") or "")
            if u.startswith(("http://", "https://")):
                v = self.check_url(u)
                if not v.ok:
                    return v
        # ③ 写文件类工具的路径参数（路径即整串，反斜杠归一）
        if tool in ("Write", "Edit", "NotebookEdit"):
            p = str((args or {}).get("file_path", "") or (args or {}).get("path", ""))
            if _ZONE_PATH_RX.search(p.replace("\\", "/")):
                return GuardVerdict(False, "controller_zone", f"写禁区路径：{p[:120]}")
        return GuardVerdict(True)

    @staticmethod
    def from_engagement(engagement: dict) -> "Guard":
        scope = engagement.get("scope", {}) or {}
        return Guard(scope.get("allow") or [], scope.get("deny") or [])
