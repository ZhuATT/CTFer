"""AT1 browser —— driver 托管的每 engagement 独立 Chrome（playwright 批 B1）。

根因（docs/playwright升级计划.md §0）：-p 模型下挂在 MCP 进程树上的状态活不过
一轮。浏览器所有权挪给 driver（唯一活过整个 engagement 的进程）：detached 拉
Chrome（engagement 专属 user-data-dir），状态落 .at1/browser.json（pid+port
记账），假死/崩溃轮间探活自愈；MCP 经 PLAYWRIGHT_MCP_CDP_ENDPOINT 附着为客人，
轮末杀 worker 树天然够不着它。

语义拍板（2026-10-12，§6.5）：有头默认（AT1_BROWSER_HEADLESS=1 才 headless）；
复用时 headless 与当前 flag 不一致 → flag 优先杀旧重起（丢页面态不丢 cookie）；
relaunch 前必须先杀旧进程（假死实例占着 profile 锁，不杀新实例起不来——R1）。
本模块不 import events——ev 回调由 driver 注入，保持纯函数可测；真 Emitter
冒烟（EVENT_TYPES 登记缺失防护，R8）在 test_browser.py。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

# 浏览器候选（js-intel 同源 D:\chrome 优先；LOCALAPPDATA 兜底；Edge 同协议垫底）
_CANDIDATES = (
    r"D:\chrome\Chrome\Application\chrome.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)

CDP_WAIT_S = 20.0        # 启动等 CDP 就绪 deadline（dual-slot 同款）
PROBE_TIMEOUT_S = 2.0    # /json/version 探活超时
PORT_RETRIES = 3         # bind-close-use 竞态兜底：探活失败换口重试
PROFILE_DIRNAME = "chrome-profile"          # driver 托管 profile（相对 .at1/）
FALLBACK_DIRNAME = "chrome-profile-fallback"  # MCP fallback profile（scaffold B4 渲染）


def find_exe() -> str | None:
    """AT1_BROWSER_EXE 显式设置即权威——文件缺失返回 None（走 MCP fallback，
    不悄悄换默认浏览器：验收10 的语义）；未设置按候选序列找；找不到 None（不抛）。"""
    env = os.getenv("AT1_BROWSER_EXE", "").strip()
    if env:
        return env if Path(env).is_file() else None
    for c in _candidates():
        if c.is_file():
            return str(c)
    return None


def _candidates() -> list[Path]:
    out = [Path(c) for c in _CANDIDATES if c]
    la = os.environ.get("LOCALAPPDATA")
    if la:
        out.append(Path(la) / "Google" / "Chrome" / "Application" / "chrome.exe")
    return out


def alloc_port() -> int:
    """向 OS 要一个空闲 TCP 端口。bind(:0) 后关闭——close 到 Chrome bind 之间有
    竞态窗口（单机低并发可接受），探活失败由调用方换口重试。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# 直连 opener——不吃机器代理配置（HTTP_PROXY 无 no_proxy 时 127.0.0.1 会被
# 劫去代理，探活全部假阴）
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe(port: int, timeout: float = PROBE_TIMEOUT_S) -> bool:
    """CDP 探活：/json/version 2s 内 200 = 活着。假死实例不应答 = 判死。"""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{int(port)}/json/version")
        with _NO_PROXY_OPENER.open(req, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def wait_cdp(port: int, deadline_s: float = CDP_WAIT_S) -> bool:
    """轮询等 CDP 就绪。"""
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if probe(port):
            return True
        time.sleep(0.5)
    return False


def launch(port: int, profile_dir, exe: str, headless: bool = False):
    """detached 拉 Chrome，返回 Popen 句柄但**不持有**——Chrome 从此与 driver
    只有记账关系（pid+port），杀 worker 树天然够不着它（所有权设计的根）。"""
    profile_dir = Path(profile_dir)
    profile_dir.mkdir(parents=True, exist_ok=True)
    cmd = [exe, f"--remote-debugging-port={port}", f"--user-data-dir={profile_dir}",
           "--no-first-run", "--no-default-browser-check", "--disable-sync"]
    if headless:
        cmd.append("--headless=new")
    cmd.append("about:blank")
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, creationflags=flags,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _image_name(pid: int) -> str:
    """按 PID 查进程镜像名（Windows tasklist；查不到/非 Windows = ""）。"""
    if os.name != "nt":
        return ""
    try:
        r = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}",
                            "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return ""
    first = (r.stdout or "").strip().splitlines()
    if first and first[0].startswith('"'):
        return first[0].split('","')[0].strip('"').lower()
    return ""


def _pid_alive(pid) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        return _image_name(pid) != ""       # tasklist 查无此 PID = 已死
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def kill_pid(pid) -> None:
    """杀旧浏览器进程树（taskkill /T /F）。守门：镜像名必须 chrome/msedge——
    browser.json 里的 pid 可能已被 OS 回收复用，按裸 PID 杀树会误杀无辜
    （S2 同源教训）；无关进程复用了这个 PID 就不动。"""
    if not pid or not _pid_alive(pid):
        return
    if os.name == "nt":
        img = _image_name(int(pid))
        if "chrome" not in img and "msedge" not in img:
            return
        try:
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
    else:
        try:
            os.kill(int(pid), 9)
        except OSError:
            pass


class BrowserHandle:
    """run 级常驻 Chrome 的记账+自愈。跨进程唯一状态 = .at1/browser.json；

    - start()：run 启动开池——孤儿实例活着且 headless 说法一致 → 复用；
      否则先杀旧进程再拉新（R1 profile 锁 / §6.5-2 flag 优先）
    - ensure()：每轮 spawn 前探活，失败同款「先杀旧再拉新」
    - shutdown(keep)：run_end 收尾——keep=1 留守（browser.json 供下次复用），
      keep=0 杀树+删账
    """

    def __init__(self, root, ev, exe: str, port: int = 0, pid: int = 0,
                 headless: bool = False):
        self.root = Path(root)
        self.ev = ev
        self.exe = exe
        self.port = int(port)
        self.pid = int(pid)
        self.headless = bool(headless)
        self.dead = False    # relaunch 彻底失败置位——后续 ensure 不再空转

    @property
    def state_path(self) -> Path:
        return self.root / ".at1" / "browser.json"

    @property
    def profile_dir(self) -> Path:
        return self.root / ".at1" / PROFILE_DIRNAME

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # ── 状态文件 ──
    def _write_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({
            "pid": self.pid, "port": self.port, "headless": self.headless,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, ensure_ascii=False), encoding="utf-8")

    def _read_state(self) -> dict | None:
        try:
            d = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if isinstance(d, dict) and d.get("pid") and d.get("port"):
            return d
        return None

    def _emit(self, type_: str, reason: str) -> None:
        self.ev.emit(type_, {"pid": self.pid, "port": self.port,
                             "headless": self.headless, "reason": reason})

    # ── 拉新（换口重试） ──
    def _launch_new(self, event: str, reason: str) -> bool:
        last = ""
        for _ in range(PORT_RETRIES):
            port = alloc_port()
            try:
                proc = launch(port, self.profile_dir, self.exe, self.headless)
            except OSError as e:
                last = f"popen-fail: {str(e)[:80]}"
                continue
            self.port, self.pid = port, proc.pid
            if wait_cdp(port):
                self._write_state()
                self._emit(event, reason)
                return True
            last = f"cdp-timeout port {port}"
            kill_pid(proc.pid)       # 进程在但 CDP 没就绪 = 半死实例，清掉换口
        self.dead = True
        self._emit("browser_exit", f"launch-failed ({last})")
        return False

    # ── 生命周期三拍 ──
    @classmethod
    def start(cls, root, ev, *, mcp_config=None,
              headless: bool | None = None) -> "BrowserHandle | None":
        """run 启动开池。skip：无 .mcp.json（浏览器能力缺席）或无 chrome exe
        → browser_skip + None，不拒启（MCP fallback / curl 降级可活）。"""
        if mcp_config is None or not Path(mcp_config).is_file():
            ev.emit("browser_skip", {"reason": "no-mcp-config"})
            return None
        exe = find_exe()
        if exe is None:
            ev.emit("browser_skip", {"reason": "no-exe"})
            return None
        if headless is None:
            headless = os.getenv("AT1_BROWSER_HEADLESS", "0") == "1"
        h = cls(root, ev, exe, headless=headless)
        st = h._read_state()
        if (st and _pid_alive(st.get("pid")) and probe(int(st["port"]))
                and bool(st.get("headless")) == headless):
            h.pid, h.port = int(st["pid"]), int(st["port"])
            h._emit("browser_reuse", "orphan-alive")
            return h
        # 不可复用（死了/假死/headless 说法变了）：先杀旧再拉新
        if st:
            kill_pid(st.get("pid"))
        h._launch_new("browser_start", "orphan-dead" if st else "fresh")
        return None if h.dead else h

    def ensure(self) -> None:
        """每轮 spawn 前探活自愈：probe 失败（假死/崩溃）→ 杀旧拉新，登录态从
        profile 回（活页面态丢）。彻底起不来 → dead 置位，本轮起 worker 走
        curl 降级，不每轮空转重试。"""
        if self.dead:
            return
        if self.pid and _pid_alive(self.pid) and probe(self.port):
            return
        if self.pid:
            kill_pid(self.pid)
        self._launch_new("browser_relaunch", "probe-fail")

    def shutdown(self, keep: bool) -> None:
        """run_end 收尾。keep=1：只留 browser.json 供下次复用（Chrome 留守）；
        keep=0：taskkill 树 + 删 browser.json。"""
        if keep:
            return
        kill_pid(self.pid)
        try:
            self.state_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._emit("browser_exit", "shutdown")
