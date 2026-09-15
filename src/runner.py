"""AT1 runner —— 进程桥（vendor 自 hxbai ccrunner.py，按 phase1 P1.3 清单改造）。

与 hxbai 的结构差异：
- communicate()（收完再算）→ 读流线程（实时）：on_fact / 心跳 / transcript 增量落盘
  都发生在会话进行中；kill 后 transcript 留有已发生部分（设计§3.1）
- 解析器独立成 StreamParser（可单测：喂合成流，不依赖真进程）
- session_id 捕获（system/init 事件）+ run() 断点续跑（--resume，仅异常终态续，
  max_turns/timeout 是终态不续——续了等于放大时间盒）
- Handoff 从最后一条消息【向前】扫（dcr 教训：agent 先吐标签再说 "Done!"）
- 删 flag/CTF 机制；环境消毒键名 AT1_*；CLAUDECODE=""（阻断嵌套检测）+ IS_SANDBOX=1
  （允许 bypassPermissions 生效）——dcr 同款两个 load-bearing 值
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .providers import SolverConfig

_HANDOFF_RX = re.compile(r"<Handoff>(.*?)</Handoff>", re.IGNORECASE | re.DOTALL)
_FINAL_RX = re.compile(r"<FinalAnswer>(.*?)</FinalAnswer>", re.IGNORECASE | re.DOTALL)

# thinking 进度事件短路（phase3.5 §六：实测 98.8% 流量是 system/thinking_tokens，
# 每条 json.loads + flush 是 I/O 洪水根因）。标记用正则匹配原始行——JSON 字符串
# 内的引号必被转义，未转义的 "subtype":"thinking_tokens" 只可能出现在结构层，
# 不会误伤 tool_result 文本里恰好含这段文字的内容。
_THINKING_RX = re.compile(r'"subtype"\s*:\s*"thinking_tokens"')
_THINK_DELTA_RX = re.compile(r'"estimated_tokens_delta"\s*:\s*(\d+)')
_THINKING_TOTAL_RX = re.compile(r'"estimated_tokens"\s*:\s*(\d+)')
THINKING_SAMPLE_EVERY = 100      # 进度事件采样写盘：每 100 条留 1 条

MAX_TOOL_CHARS = 20_000          # 单条 tool_result 喂给 on_fact 的截断长度
HEARTBEAT_EVERY = 25             # 每 N 次 tool_result 一次心跳（设计§3.1）
# 双阈值呆滞告警（实测 glm 有两种呆滞形态，单阈值抓不全）：
STALL_WARN_S = float(os.getenv("AT1_STALL_WARN_S", "120"))       # 流级：无任何输出（网络挂死）
STALL_TOOL_WARN_S = float(os.getenv("AT1_STALL_TOOL_WARN_S", "600"))  # 工具级：流活着但无 tool_result（thinking 马拉松）
MAX_RESUMES = 20                 # 每会话续跑上限（设计§3.1）
RESUME_BACKOFF_CAP_S = 300.0     # 退避封顶


def _stall_flags(stream_idle_s: float, tool_idle_s: float | None) -> dict:
    """呆滞判定（纯函数，可单测）。两级独立：流级抓网络挂死，工具级抓
    thinking-only 呆滞（实测：16k 行 thinking 增量、零工具调用——流级监控对它无效）。"""
    flags: dict = {}
    if stream_idle_s >= STALL_WARN_S:
        flags["stalled"] = True
    if tool_idle_s is not None and tool_idle_s >= STALL_TOOL_WARN_S:
        flags["stalled_tools"] = True
    return flags
_RESUME_PROMPT = "继续上次中断的任务，从中断处接着做。"


def extract_handoff(text: str) -> str:
    m = _HANDOFF_RX.search(text or "")
    return m.group(1).strip() if m else ""


def extract_final_answer(text: str) -> str:
    m = _FINAL_RX.search(text or "")
    return m.group(1).strip() if m else ""


@dataclass
class ToolEvent:
    """一次配对完成的工具调用：名字 + 参数 + 输出摘要。"""
    tool: str
    args: dict
    output: str


@dataclass
class AgentTask:
    """driver 挂进 runner 的回调集（M2 起接线 board/CONTROL）。"""
    on_fact: Optional[Callable[[ToolEvent], None]] = None
    on_heartbeat: Optional[Callable[[dict], None]] = None
    transcript_path: Optional[str] = None   # 增量追加的原始流落盘位置（.at1/transcript.jsonl）
    on_spawn: Optional[Callable[[object], None]] = None   # Popen 后回调（杀进程演示/CONTROL 用）


@dataclass
class AgentResult:
    session_id: str = ""
    stop_reason: str = ""        # end_turn / max_turns / timeout / error
    turns: int = 0
    tokens: int = 0
    total_cost_usd: float = 0.0
    handoff: str = ""
    final_text: str = ""
    final_answer: str = ""
    is_error: bool = False
    error: str = ""
    resumes: int = 0
    thinking_events: int = 0     # thinking 进度事件计数（短路不写盘，遥测用）


def _tool_result_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(content)


class StreamParser:
    """逐行解析 stream-json，transcript 按 I/O 分级写（phase3.5 §六）：
    init/result/tool_result 逐条 flush（不能丢）；assistant 常规写（量小，
    过滤洪水后 flush 开销可忽略）；thinking 进度只计数 + 1/100 采样；
    遥测/非 JSON 行不写。

    实测依据（CLI v2.1.238）：init 事件 = 首条 JSON 行，带 session_id；
    result 事件带 num_turns/stop_reason/usage/total_cost_usd；
    system/thinking_tokens 占流量的 98.8%（flash thinking 洪水根因）。
    """

    def __init__(self, task: AgentTask | None = None):
        self.task = task or AgentTask()
        self.session_id = ""
        self.stop_reason = ""
        self.turns = 0
        self.tokens = 0
        self.total_cost_usd = 0.0
        self.is_error = False
        self.final_text = ""
        self.pending: dict[str, tuple[str, dict]] = {}
        self.assistant_texts: list[str] = []
        self.tool_events: list[ToolEvent] = []
        self.tool_count = 0
        self.last_tool_ts: float = 0.0     # 最近一次 tool_result 的时刻（工具级呆滞判据）
        self.raw_lines = 0
        self.thinking_events = 0           # thinking 进度事件计数（短路，不解析）
        self.thinking_tokens_est = 0       # 估算 thinking token 总量（正则抽 delta 累加）
        self._tf = None
        if self.task.transcript_path:
            os.makedirs(os.path.dirname(self.task.transcript_path) or ".", exist_ok=True)
            self._tf = open(self.task.transcript_path, "a", encoding="utf-8")

    # ── 流处理 ────────────────────────────────────────────────────────────

    def feed_line(self, raw: str) -> None:
        self.raw_lines += 1
        line = raw.strip()
        # ① thinking 进度短路：只计数 + 正则抽 token 估算，不 json.loads；
        #    每 THINKING_SAMPLE_EVERY 条采样写盘 1 条（丢了无所谓）
        if _THINKING_RX.search(line):
            self.thinking_events += 1
            m = _THINK_DELTA_RX.search(line) or _THINKING_TOTAL_RX.search(line)
            if m:
                self.thinking_tokens_est += int(m.group(1))
            if (self._tf is not None
                    and self.thinking_events % THINKING_SAMPLE_EVERY == 0):
                self._tf.write(raw if raw.endswith("\n") else raw + "\n")
                self._tf.flush()
            return
        # ② 非 JSON 行（stdin 警告、[claude-code:…] 遥测前缀）：不写 transcript
        if not line or not line.startswith("{"):
            return
        try:
            ev = json.loads(line)
        except Exception:
            return
        if not isinstance(ev, dict):
            return
        # ③ 通过过滤的 JSON 事件照写 transcript + flush（kill 后磁盘留有已写部分）
        if self._tf is not None:
            self._tf.write(raw if raw.endswith("\n") else raw + "\n")
            self._tf.flush()

        etype = ev.get("type")
        if etype == "system" and ev.get("subtype") == "init":
            self.session_id = ev.get("session_id") or ""

        elif etype == "assistant":
            try:
                u = (ev.get("message", {}) or {}).get("usage") or {}
                if isinstance(u, dict):
                    self.tokens += sum(int(u.get(k, 0) or 0) for k in
                                       ("input_tokens", "output_tokens",
                                        "cache_creation_input_tokens", "cache_read_input_tokens"))
            except Exception:
                pass
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    txt = block.get("text", "")
                    if txt:
                        self.assistant_texts.append(txt)
                elif block.get("type") == "tool_use":
                    self.pending[block.get("id", "")] = (block.get("name", ""), block.get("input", {}) or {})

        elif etype == "user":
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                name, args = self.pending.pop(block.get("tool_use_id", ""), ("tool", {}))
                output = _tool_result_text(block.get("content"))[:MAX_TOOL_CHARS]
                if not output:
                    continue
                te = ToolEvent(tool=name, args=args, output=output)
                self.tool_events.append(te)
                self.tool_count += 1
                self.last_tool_ts = time.time()
                if self.task.on_fact is not None:
                    try:
                        self.task.on_fact(te)
                    except Exception:
                        pass
                if self.task.on_heartbeat is not None and self.tool_count % HEARTBEAT_EVERY == 0:
                    try:
                        self.task.on_heartbeat({
                            "tool_calls": self.tool_count,
                            "tokens": self.tokens,
                            "assistant_msgs": len(self.assistant_texts),
                            "thinking_events": self.thinking_events,
                            "thinking_tokens_est": self.thinking_tokens_est,
                        })
                    except Exception:
                        pass

        elif etype == "result":
            self.final_text = ev.get("result", "") or ""
            self.turns = int(ev.get("num_turns", 0) or 0)
            try:
                self.total_cost_usd = float(ev.get("total_cost_usd", 0) or 0)
            except (TypeError, ValueError):
                self.total_cost_usd = 0.0
            # 实测（glm 端点）：逐 assistant 事件的 usage 全为 0，真实总量在
            # result 事件的 usage 块——两处都累加，谁有算谁
            try:
                u = ev.get("usage") or {}
                if isinstance(u, dict):
                    self.tokens += sum(int(u.get(k, 0) or 0) for k in
                                       ("input_tokens", "output_tokens",
                                        "cache_creation_input_tokens", "cache_read_input_tokens"))
            except Exception:
                pass
            subtype = str(ev.get("subtype", "") or "")
            if "max_turns" in subtype:
                self.stop_reason = "max_turns"
            elif ev.get("is_error") or subtype not in ("", "success"):
                self.stop_reason = "error"
                self.is_error = True
            else:
                self.stop_reason = ev.get("stop_reason") or "end_turn"

    def close(self) -> None:
        if self._tf is not None:
            self._tf.close()

    # ── 收割 ──────────────────────────────────────────────────────────────

    def harvest_handoff(self) -> str:
        """从后向前扫：final_text（result 的最后叙述）→ 逆序的 assistant 文本块。
        dcr 教训：agent 常先吐 <Handoff> 再说 "Done!"，取末条会只拿到散文。"""
        for text in [self.final_text] + list(reversed(self.assistant_texts)):
            h = extract_handoff(text)
            if h:
                return h
        return ""

    def to_result(self, resumes: int = 0) -> AgentResult:
        res = AgentResult(
            session_id=self.session_id,
            stop_reason=self.stop_reason or ("error" if self.is_error else ""),
            turns=self.turns,
            tokens=self.tokens,
            total_cost_usd=self.total_cost_usd,
            handoff=self.harvest_handoff(),
            final_text=self.final_text,
            final_answer=extract_final_answer(self.final_text),
            is_error=self.is_error,
            resumes=resumes,
            thinking_events=self.thinking_events,
        )
        return res


# ──────────────────────────────────────────────────────────────────────────────
# 子进程 spawn（单次）与 run（含续跑）
# ──────────────────────────────────────────────────────────────────────────────

def _sanitize_env(solver: SolverConfig) -> dict:
    """环境消毒（设计§3.1）：worker 拿不到控制器内部状态。

    - 控制器私有变量（AT1_*）与 verifier key（LLM_*）永远剥掉
    - benchmark 遗留变量剥掉
    - ANTHROPIC_*：仅当 solver 自带凭证时才剥（随后由 anthropic_env 重新注入
      自己的）；solver 无凭证时保留本机配置——selftest 零配置可跑
    - AT1_CLAUDE_CONFIG_DIR（控制器指定）：worker 的 claude CLI 用它做
      CLAUDE_CONFIG_DIR 隔离——不读本机 ~/.claude/settings.json 的 env 覆盖
      （实测：settings env 优先于进程 env，会把注入的 ANTHROPIC_BASE_URL 拉回
      本机配置，worker 打错通道）。隔离后 worker 只吃注入的 ANTHROPIC_*。
    """
    env = dict(os.environ)
    claude_cfg_dir = env.pop("AT1_CLAUDE_CONFIG_DIR", None)
    for k in list(env):
        if (k.startswith("AT1_") or k.startswith("LLM_")
                or k in ("SOLVER_API_KEY", "BENCHMARK_TOKEN", "BENCHMARK_BASE_URL", "LLM_PROFILE")):
            env.pop(k, None)
    if solver.has_own_credentials:
        for k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
                  "ANTHROPIC_MODEL"):
            env.pop(k, None)
    env.update(solver.anthropic_env())
    if claude_cfg_dir:
        try:
            os.makedirs(claude_cfg_dir, exist_ok=True)
        except OSError:
            pass
        env["CLAUDE_CONFIG_DIR"] = claude_cfg_dir
    env["CLAUDECODE"] = ""    # 阻断 CLI 嵌套会话检测（dcr load-bearing #1）
    env["IS_SANDBOX"] = "1"   # 允许 bypassPermissions 生效（dcr load-bearing #2）
    return env


def kill_process_tree(proc) -> None:
    """杀 worker 整棵进程树（P-11 v2，参照 Cairn _terminate：先宽限后强杀）。

    claude CLI 底下挂着 npx MCP、浏览器子进程——单 proc.kill() 会留孤儿树。
    Windows 用 taskkill /T（进程组语义）；POSIX 退化 proc.kill()。
    """
    if proc is None or proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=10)
            return
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass


def _build_argv(claude_bin: str, solver: SolverConfig, max_turns: int,
                resume_session_id: str | None,
                mcp_config: str | None = None) -> list[str]:
    argv = [
        claude_bin, "-p",
        "--output-format", "stream-json",
        "--verbose",                      # 实测：-p + stream-json 必需
        "--dangerously-skip-permissions",
        "--max-turns", str(max_turns),
        "--model", solver.model,
    ]
    if mcp_config:
        # U-1（2026-09-14）：MCP 世界只认 scaffold 写的 .auto/.mcp.json——
        # 关掉父目录链/用户级的继承通道（实验证实 CLI 会逐级合并祖先 .mcp.json，
        # worker 能力随目录地理漂移：usc-fresh 捡到 tavily、usc-jiuye 干净）
        argv += ["--strict-mcp-config", "--mcp-config", mcp_config]
    if resume_session_id:
        argv += ["--resume", resume_session_id]
    return argv


def spawn_once(
    prompt: str,
    workdir: str,
    solver: SolverConfig,
    task: AgentTask | None = None,
    *,
    time_box_s: float | None = None,
    max_turns: int | None = None,
    claude_bin: str | None = None,
    resume_session_id: str | None = None,
) -> AgentResult:
    """spawn 一个 -p 会话并实时收割到自然结束。返回 AgentResult（不含续跑逻辑）。"""
    task = task or AgentTask()
    binary = claude_bin or os.getenv("AT1_CLAUDE_BIN", "claude")
    mt = max_turns if max_turns is not None else solver.max_turns
    box = time_box_s if time_box_s is not None else solver.session_seconds
    os.makedirs(workdir, exist_ok=True)

    # U-1：MCP 唯一来源=workdir 的 .mcp.json（scaffold 每次确定性重写）；文件缺失则
    # 不加 strict（自测/旧路径无此文件，行为不变）
    local_mcp = os.path.join(workdir, ".mcp.json")
    argv = _build_argv(binary, solver, mt, resume_session_id,
                       mcp_config=local_mcp if os.path.isfile(local_mcp) else None)
    env = _sanitize_env(solver)
    parser = StreamParser(task)

    try:
        proc = subprocess.Popen(
            argv, cwd=workdir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, errors="replace",
        )
    except FileNotFoundError as e:
        parser.close()
        return AgentResult(stop_reason="error", is_error=True,
                           error=f"claude CLI not found ({binary}): {e}")
    except Exception as e:
        parser.close()
        return AgentResult(stop_reason="error", is_error=True,
                           error=f"failed to launch claude: {e}")

    if task.on_spawn is not None:
        try:
            task.on_spawn(proc)
        except Exception:
            pass

    stderr_tail: list[str] = []
    stall = {"last_ts": time.time()}

    def _drain_stderr():
        try:
            for line in proc.stderr:
                stderr_tail.append(line)
                if len(stderr_tail) > 200:
                    stderr_tail.pop(0)
        except Exception:
            pass

    def _read_stdout():
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                stall["last_ts"] = time.time()
                parser.feed_line(line)
        except Exception:
            pass

    def _stall_watch():
        """双阈值呆滞告警，只告警不杀（设计§4.2）。发完各自重置计时防刷屏。"""
        while proc.poll() is None:
            time.sleep(10)
            now = time.time()
            stream_idle = now - stall["last_ts"]
            tool_idle = (now - parser.last_tool_ts) if parser.last_tool_ts else None
            flags = _stall_flags(stream_idle, tool_idle)
            if flags and task.on_heartbeat is not None:
                try:
                    task.on_heartbeat({**flags,
                                       "stream_idle_s": round(stream_idle, 1),
                                       "tool_idle_s": round(tool_idle, 1) if tool_idle else None,
                                       "tool_calls": parser.tool_count,
                                       "tokens": parser.tokens,
                                       "thinking_events": parser.thinking_events,
                                       "thinking_tokens_est": parser.thinking_tokens_est})
                except Exception:
                    pass
            if "stalled" in flags:
                stall["last_ts"] = now            # 流级节流
            if "stalled_tools" in flags:
                parser.last_tool_ts = now         # 工具级节流

    t_out = threading.Thread(target=_read_stdout, daemon=True)
    t_err = threading.Thread(target=_drain_stderr, daemon=True)
    t_stall = threading.Thread(target=_stall_watch, daemon=True)
    t_out.start()
    t_err.start()
    t_stall.start()

    # prompt 经 stdin 一次喂入并立即关闭（实测：CLI 等 stdin ~3s）
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
    except Exception:
        pass

    timed_out = False
    try:
        proc.wait(timeout=box)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=15)
        except Exception:
            pass
    t_out.join(timeout=10)
    t_err.join(timeout=5)
    parser.close()

    res = parser.to_result()
    if getattr(proc, "_controller_kill", False):
        # P-11 v2：控制器击杀（watcher 秒停）=【终态】不是错误——会话即死不复活
        #（ARTEX/Cairn/hxbai 三家同款语义；续跑 = 新 worker 从盘上状态接力，run 层面的事）
        res.stop_reason = "controller_kill"
    elif timed_out:
        # 时间盒耗尽是【终态】不是错误：走 Handoff 收割（可能没有 → M2 代码合成兜底）
        res.stop_reason = "timeout"
    elif not parser.turns and proc.returncode not in (0, None):
        # 没撑到 result 事件就非零退出 = 异常终态（续跑候选）
        res.is_error = True
        res.stop_reason = "error"
        res.error = f"process exited rc={proc.returncode}; stderr tail: {''.join(stderr_tail[-5:])[:400]}"
    elif not parser.stop_reason and not timed_out:
        res.stop_reason = "end_turn"
    if stderr_tail and res.is_error and not res.error:
        res.error = f"stderr tail: {''.join(stderr_tail[-5:])[:400]}"
    return res


def run(
    prompt: str,
    workdir: str,
    solver: SolverConfig,
    task: AgentTask | None = None,
    *,
    time_box_s: float | None = None,
    max_turns: int | None = None,
    claude_bin: str | None = None,
) -> AgentResult:
    """带断点续跑的完整执行（设计§3.1）：

    - 异常终态（error，如 API 429/5xx 中断）→ 指数退避后 --resume <session_id> 续跑
    - max_turns / timeout 是终态，不续（续了等于放大时间盒）
    - 每 task.transcript_path 是追加式的：续跑的流接在同一个 transcript 后
    """
    resume_id: str | None = None
    cur_prompt = prompt
    attempt = 0
    while True:
        res = spawn_once(cur_prompt, workdir, solver, task,
                         time_box_s=time_box_s, max_turns=max_turns,
                         claude_bin=claude_bin, resume_session_id=resume_id)
        # 正常终态（含时间盒耗尽/控制器击杀 controller_kill）→ 直接返回
        if not res.is_error:
            res.resumes = attempt          # 计数记在返回的这份上，不是被丢弃的错误份上
            return res
        # 异常：能续（有 session_id + 未超续跑上限）才续
        if not res.session_id or attempt >= MAX_RESUMES:
            res.resumes = attempt
            return res
        attempt += 1
        resume_id = res.session_id
        cur_prompt = _RESUME_PROMPT
        time.sleep(min(2.0 ** attempt, RESUME_BACKOFF_CAP_S))
