"""AT1 guard —— scope 越界记录 + 控制器区禁写检测 + 自毁检测（P4.2，设计§3.7）。

机制诚实：worker 跑 --dangerously-skip-permissions，guard 没有 OS 层强制力
——**只记录不阻断**（P-9 拍板：guard 是摄像头不是闸门；2026-10-13 措辞对齐，
勿再写"拦下/照拦"）。
记录的三层实现：
  ① 教育层：deny 列表 + 控制器区禁令渲染进 CLAUDE.md（scaffold 已做）
  ② 实时检测：driver 挂进 runner on_fact——每个工具调用到达即判，
     命中 → guard_violation 事件（越界记录在案，回放/审计可见）
  ③ 高危自毁：同路检测（黑名单命令特征），事件标 critical

设计 §2.3 不变量：transcript/黑板是门 3 物理锚，worker 写控制器区 = 伪造证据，
所以控制器区写检测是唯一"该硬"的判定——命中即记高危（不可降级为提示）。
scope 记录宽松取向：URL 解析失败的命令不记（误记正常工作流比漏记更伤）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

# 控制器区/协议文件区（对 workdir 而言）。worker cwd = workdir，碰这些路径
# （相对或经 ../ 回溯）都是越权。evidence/ 不在禁区——那是 worker 的合法
# 写入目录（workdir/evidence）。
# 匹配用非锚定搜索（命令文本里路径在中间）；URL 先剥掉再查（url 路径 /state/ 不是禁区）。
# 分隔符 [/\\] 双形态（P-5，2026-09-14 真实 run 实锤：PowerShell
# [IO.File]::AppendAllLines("..\state\log.jsonl",...) 反斜杠写穿禁区 0 告警——
# 我们的运行平台就是 Windows，正则只认 / 等于对常态失明）。
# $ 终止（批4fix S7/R-5，2026-09-21 实机实锤：PowerShell 变量拼接 URL
# "https://myportal.usc.edu.cn$u" —— \S+ 不认 $ 是终止符，整串当 URL 抓出
# hostname 带变量名 → scope 误记连吃 5 次。host 永在 URL 中任何 $ 之前
# （$ 合法出现在 path/query，不合法出现在 netloc 尾部粘连处），截断不影响判定）。
# 禁区（批3fix R3 终版）：.at1/.observer/state/notes 禁写；.at1 与 notes 对 worker
# 可读（读检测不存在——guard 只判写）。.observer 是观察者工作台，worker 完全禁入。
_ZONE_PATH_RX = re.compile(
    r"(?:\.\.[/\\])*(?:\.at1|\.observer|state|notes)[/\\]"
    r"|_(?:blackboard|transcript|interface_log)\.(?:json|jsonl|bak|tmp)"
    r"|OBSERVER\.(?:json|rejects)",
    re.IGNORECASE)
# 观察者自家可写集（S10/R-4）：观察者角色对这些路径的写放行——与 observer.py
# 手册声明的可写面一致（OBSERVER.json/STATE.md/prior-intel-draft/.observer/ 草稿）。
# worker 对它们照旧记账（禁入纪律一寸不让）。
# 不锚定（实机批4fix 演练抓的 bug：绝对路径 D:\...\eng\.observer\x 的 .observer
# 前面是 / 或 \，前缀类接不住）——豁免判定只在 zone 命中后才跑，宽于 zone 的
# 部分是死支，不会放过任何 zone 外的东西。
_OBSERVER_WRITABLE_RX = re.compile(
    r"\.observer[/\\][^\s\"']*"
    r"|\.observer(?=[\s\"']|$)"
    r"|STATE\.md(?=[\s\"']|$)"
    r"|notes[/\\]prior-intel-draft\.md(?=[\s\"']|$)",
    re.IGNORECASE)
_URL_STRIP_RX = re.compile(r"https?://[^\s$]+", re.IGNORECASE)

# ── S13 结构化路径代数（续修批，2026-09-21）────────────────────────────────
# 病根="枚举形态"：靠想象 worker 会怎么写路径，一种补一条正则（P-1 引号分号/
# P-5 反斜杠/S7 的 $/4fix 的 +& 四刀同族，军备竞赛追不完）。结构化参数
# （Write/Edit 的 file_path）本来就有干净路径串——用 resolve()+前缀比较判定
# 归属：绝对/相对/../混合分隔符/8.3 短名/UNC 全由构造保证，不枚举。
# 禁区判定=正则 ∪ 代数（只增不漏，保高召回）；豁免判定=代数（精确，治病灶）。
_ZONE_DIRS = (".at1", ".observer", "state", "notes")
_ZONE_FILE_RX = re.compile(
    r"^_(?:blackboard|transcript|interface_log)\.(?:json|jsonl|bak|tmp)$"
    r"|^OBSERVER\.(?:json|rejects)$", re.IGNORECASE)
# 命令文本用（S14）：归一化后按 token 取禁区委照——带捕获，豁免要看全 token。
_ZONE_TEXT_RX = re.compile(
    r"(?:\.at1|\.observer|state|notes)/[^\s;|&]*"
    r"|_(?:blackboard|transcript|interface_log)\.[a-z]+"
    r"|OBSERVER\.(?:json|rejects)",
    re.IGNORECASE)
# 嵌套检查专用（豁免 token 内部再扫）：只认目录级引用与下划线私有文件——
# 不含裸 OBSERVER.json（那是观察者自己的判断书名，`.observer/OBSERVER.json`
# 正是它的合法产物，误当禁区委照会把自家工作台判成越界）。
_ZONE_NESTED_RX = re.compile(
    r"(?:\.at1|\.observer|state|notes)/"
    r"|_(?:blackboard|transcript|interface_log)\.[a-z]+",
    re.IGNORECASE)


def _normalize_cmd(cmd: str) -> str:
    """S14：命令文本归一化——URL 剥掉 → 分隔符统一 / → 引号统一空格。

    禁区判定与豁免判定**共用这一个形态**（P-1① 的真正根因就是两侧各认一套
    正则、形态认知不一致）。绝对路径 D:\\x\\.at1\\b 归一化后含 /.at1/ ✓。
    """
    s = _URL_STRIP_RX.sub(" ", cmd or "")
    return re.sub(r"[\"']", " ", s.replace("\\", "/"))


def _observer_writable_token(tok: str) -> bool:
    """S14：归一化文本里的禁区委照——是否落在观察者自家可写集内。

    嵌套禁区引用一律不放行（续修批实测抓的真洞：`.observer/../.at1/x.json`
    在整串匹配下被 `.observer[/\\][^\\s]*` 一口吞掉 → 逃过禁区判定。规则收紧为
    "token 内除自家工作台外不得再夹任何**目录级**禁区委照"）。
    嵌套检查只看目录级引用（`.at1/`…）与下划线私有文件——**不含裸
    `OBSERVER.json`**：那是观察者自己的判断书文件名，正是它的合法产物。
    """
    t = (tok or "").lower()
    if t == ".observer":
        rest = ""
    elif t.startswith(".observer/"):
        rest = t[len(".observer/"):]
    elif t.startswith("notes/prior-intel-draft.md"):
        rest = t[len("notes/prior-intel-draft.md"):]
    else:
        return False
    return not _ZONE_NESTED_RX.search(rest)


def _text_zone_refs(raw: str) -> list[str]:
    """把一段文本（路径或命令）归一化后取出全部禁区委照。"""
    return _ZONE_TEXT_RX.findall(_normalize_cmd(raw))

# 自毁特征（Windows + Unix 双形态；命中记 critical 事件）
_SELF_DESTRUCT_RX = re.compile(
    r"\brm\s+-rf\s+[/~.]|del\s+/[sq]|format\s+[a-z]:|mkfs|"
    r">\s*/dev/sda|remove-item\s+-recurse|rd\s+/s|"
    r"find\s+.*-delete\s+/\*|shutdown|/etc/passwd\s*<<", re.IGNORECASE)

# 写动词启发式（S10/R-4 收紧）：只认词边界真写动词——裸 \bwrite 把
# Write-Output/Write-Host（往屏幕打印）当写文件，观察者 42 条违规全是这类噪声。
# .NET 静态写方法：只认 appendall/writeall 动词本身——裸 [io.file] 前缀把
# ReadAllText 这类读方法也标了（批4fix 实机演练抓的第三形态：观察者纯读
# .observer 工作台被误报；P-5 的 AppendAllLines 由 appendall 独自覆盖）。
_WRITE_TOOL_HINT_RX = re.compile(
    r">>|>\s*\S"                                   # 重定向
    r"|\btouch\b|\btee\b|\bmv\b|\bcp\b|\brm\b|\bdel\b"
    r"|add-content|set-content|out-file|new-item"
    r"|copy-item|move-item|remove-item"
    r"|\bnew-file\b"
    r"|\bcurl(?:\.exe)?\b[^|;&]*\s-[oT]\b"         # curl 下载/上传落盘
    r"|appendall(?:lines|text)|writeall(?:text|lines|bytes)",
    re.IGNORECASE)


@dataclass
class GuardVerdict:
    ok: bool
    kind: str = ""          # scope / controller_zone / self_destruct / ""
    reason: str = ""


class Guard:
    """消费 engagement scope，判定工具调用是否越界。无副作用纯判定。"""

    def __init__(self, allow: list[str], deny: list[str], root=None):
        self.allow = [str(a).lower().lstrip("*.").lstrip(".") for a in allow if a]
        self.deny = [str(d).lower().lstrip("*.").lstrip(".") for d in deny if d]
        # S13：engagement 根（worker cwd=根）——路径代数判定的锚点。
        # 缺省 None = 老行为（单测/旧调用路径），代数分支自动跳过。
        try:
            self.root = Path(root).resolve() if root else None
        except (OSError, ValueError):
            self.root = None

    # ── S13 路径代数（结构化参数用；纯判定无副作用）───────────────────────

    def _resolve_target(self, p: str):
        """相对路径按 root 解析 → resolve（吃掉 .. / 软链 / 8.3 短名）。失败返回 None。"""
        if not p:
            return None
        try:
            t = Path(str(p))
            if not t.is_absolute():
                if self.root is None:
                    return None
                t = self.root / t
            return t.resolve()
        except (OSError, ValueError, RuntimeError):
            return None

    def _path_in_zone(self, target) -> bool:
        """目标是否落在控制器区（代数：前缀比较）。root 缺省→False（走正则）。"""
        if target is None or self.root is None:
            return False
        for d in _ZONE_DIRS:
            z = (self.root / d).resolve()
            if target == z or z in target.parents:
                return True
        if target.parent == self.root and _ZONE_FILE_RX.match(target.name):
            return True
        return False

    def _path_observer_writable(self, target) -> bool:
        """观察者自家可写集（代数；与 observer.py 手册声明的可写面一致）。"""
        if target is None or self.root is None:
            return False
        obs = (self.root / ".observer").resolve()
        if target == obs or obs in target.parents:
            return True
        if target == (self.root / "STATE.md").resolve():
            return True
        if target == (self.root / "notes" / "prior-intel-draft.md").resolve():
            return True
        return False

    # ── scope ────────────────────────────────────────────────────────────

    @staticmethod
    def _host_of(url: str) -> str:
        s = str(url or "")
        host = ""
        try:
            host = urlsplit(s).hostname or ""
        except ValueError:
            # 续修批实测抓的**真绕过**：urlsplit 对畸形 netloc（`evil.com[x]` →
            # "Invalid IPv6 URL"）直接抛。旧代码 except→""，而空 host 的语义是
            # "本地文件/相对路径 → 放行"（宽松取向）——于是给主机后面挂一对
            # 方括号就能让任何越界 URL 免检。兜底手工解 netloc（去 userinfo/端口），
            # 让畸形主机名照常进 scope 判定；真·无主机（本地路径）不受影响。
            m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/?#]*)", s)
            if m:
                netloc = m.group(1)
                if "@" in netloc:
                    netloc = netloc.rsplit("@", 1)[1]
                host = netloc.split(":")[0]
        host = host.lower()
        # P1（批3fix）：剥掉命令串粘连的标点尾巴（实测 PowerShell 命令
        # "https://h.example';" → hostname 带引号分号 → scope 误报 12 次/轮）。
        # $（S7/R-5）与 +&|（批4fix 实机：拼接算子/命令边界粘连，如
        # "https://x"&echo hi 的 hostname 是 x"&echo）同族；{}[]（S16，P-2：
        # PowerShell 双引号内子表达式 "…{$x}…" 形态）同族。
        # 截断式清洗：RFC 1123 主机名只含字母/数字/连字符/点——host 串里
        # 一旦出现 junk 字符（引号/拼接符/花括号/空白），其后全不属主机名。
        # （注意类里不能有点——那会截断每一个正常域名。）
        return re.split(r"[\"'&|+;,，。（）$\[\]{}\s]", host, maxsplit=1)[0].strip(".:")

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

    def check_tool(self, tool: str, args: dict, role: str = "worker") -> GuardVerdict:
        """URL 类参数走 scope；Bash/PowerShell 命令查自毁 + 控制器区写；写类工具查路径。

        Windows worker 实测用 PowerShell 工具（P4.9 事件流 tool:PowerShell）——
        命令类检查必须覆盖，否则自毁/禁区检测在 Windows 上形同虚设。
        role（S10/R-4）："worker"（默认）=禁区一寸不让；"observer"=对自家可写集
        （.observer/、STATE.md、notes/prior-intel-draft.md）豁免，出可写集照记。
        """
        # ① 自毁（最高优先级，critical——角色不豁免）
        if tool in ("Bash", "Execute", "PowerShell", "Shell"):
            cmd = str((args or {}).get("command", "") or (args or {}).get("script", ""))
            if _SELF_DESTRUCT_RX.search(cmd):
                return GuardVerdict(False, "self_destruct", f"高危命令特征：{cmd[:120]}")
            # 禁区查命令文本（S14：先归一化，再按 token 取照——禁区侧与豁免侧
            # 共用同一形态；URL 剥掉的语义不变：url 路径段 /state/ 不是禁区）
            norm = _normalize_cmd(cmd)
            zone_tokens = _ZONE_TEXT_RX.findall(norm)
            if zone_tokens and role == "observer":
                # S10/S14：观察者豁免——剔除自家可写集 token 后仍有剩余才违规
                zone_tokens = [t for t in zone_tokens if not _observer_writable_token(t)]
            if zone_tokens and _WRITE_TOOL_HINT_RX.search(norm):
                return GuardVerdict(False, "controller_zone",
                                    f"疑似写控制器区/协议文件：{cmd[:120]}")
            # 命令里的 curl/wget URL 走 scope（匹配尾巴带引号/分号先剥——P1；
            # $ 与 +&| 的清洗已统一收进 _host_of 的截断式清洗——09-21 拍板：
            # 活字符清洗留一处实现，rstrip 只管正则放行的引号分号尾巴）
            for m in _URL_STRIP_RX.finditer(cmd):
                v = self.check_url(m.group(0).rstrip("\"';,，。)）]"))
                if not v.ok:
                    return v
        # ② URL 类参数（MCP playwright / WebFetch 的 url 参数）
        for key in ("url", "target", "endpoint"):
            u = str((args or {}).get(key, "") or "")
            if u.startswith(("http://", "https://")):
                v = self.check_url(u)
                if not v.ok:
                    return v
        # ③ 写文件类工具的路径参数（S13：结构化路径走代数，正则只作兜底并集）
        if tool in ("Write", "Edit", "NotebookEdit"):
            p = str((args or {}).get("file_path", "") or (args or {}).get("path", ""))
            target = self._resolve_target(p)
            in_zone = _ZONE_PATH_RX.search(p.replace("\\", "/")) or self._path_in_zone(target)
            if in_zone:
                # 豁免：代数（精确——绝对路径/短名/软链主防线）∪ token 判
                # （兜底；**逐个 token 全部可写才放行**——嵌套禁区引用一律记违规，
                # 整串正则会被 `.observer/../.at1/x` 吞吃，实测真洞）
                refs = _text_zone_refs(p)
                writable = (self._path_observer_writable(target)
                            or (bool(refs) and all(_observer_writable_token(t) for t in refs)))
                if role == "observer" and writable:
                    pass                    # 观察者写自己工作台（S10 豁免）
                else:
                    return GuardVerdict(False, "controller_zone", f"写禁区路径：{p[:120]}")
        return GuardVerdict(True)

    @staticmethod
    def from_engagement(engagement: dict, root=None) -> "Guard":
        scope = engagement.get("scope", {}) or {}
        return Guard(scope.get("allow") or [], scope.get("deny") or [], root=root)
