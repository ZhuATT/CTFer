"""browser 单测（playwright 批 B1/B6）：全 mock 不真起 Chrome。

覆盖：find_exe 语义（env 权威/候选序列，验收10）/ alloc_port / probe（本地 mock
http）/ browser.json 读写与孤儿复用判定 / start-ensure-shutdown 状态迁移（R1
先杀旧再拉新的顺序、§6.5-2 headless flag 优先、launch 失败降级）/ kill_pid 镜像
守门 / 真 Emitter 冒烟（R8：EVENT_TYPES 登记缺失，纯 mock 假 ev 测不出来）。
"""

import json
import os
import socket
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from src import browser


class Rec:
    """事件记录器（ev 回调替身）。"""

    def __init__(self):
        self.rows = []

    def emit(self, t, d=None, round_=None):
        self.rows.append((t, dict(d or {})))

    def types(self):
        return [t for t, _ in self.rows]


def _patch_mocks(monkeypatch, *, alive=True, probe=True, wait=True):
    """launch/wait_cdp/probe/_pid_alive/kill_pid/alloc_port 全替身；
    launch 每次给新 pid，alloc_port 每次给新端口。返回 (launches, kills) 捕获列表。"""
    state = {"seq": 0}
    launches, kills = [], []

    def fake_launch(port, profile_dir, exe, headless=False):
        state["seq"] += 1
        launches.append({"port": port, "pid": 1000 + state["seq"],
                         "headless": headless, "profile": str(profile_dir)})
        return types.SimpleNamespace(pid=1000 + state["seq"])

    monkeypatch.setattr(browser, "launch", fake_launch)
    monkeypatch.setattr(browser, "wait_cdp", lambda port, deadline_s=None: wait)
    monkeypatch.setattr(browser, "probe", lambda port, timeout=None: probe)
    monkeypatch.setattr(browser, "_pid_alive", lambda pid: bool(pid) and alive)
    monkeypatch.setattr(browser, "kill_pid", lambda pid: kills.append(pid))
    monkeypatch.setattr(browser, "alloc_port", lambda: 9000 + state["seq"] + 1)
    return launches, kills


def _mk_mcp(tmp_path) -> Path:
    p = tmp_path / ".mcp.json"
    p.write_text("{}", encoding="utf-8")
    return p


def _mk_orphan_state(tmp_path, pid=777, port=9222, headless=False):
    (tmp_path / ".at1").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".at1" / "browser.json").write_text(json.dumps(
        {"pid": pid, "port": port, "headless": headless, "started_at": "x"}),
        encoding="utf-8")


# ── find_exe（验收10：env 显式设置即权威） ────────────────────────────────

def test_find_exe_env_authoritative(monkeypatch, tmp_path):
    monkeypatch.setenv("AT1_BROWSER_EXE", str(tmp_path / "nope.exe"))
    assert browser.find_exe() is None                # env 指错 → None（不换默认）
    real = tmp_path / "chrome.exe"
    real.write_bytes(b"x")
    monkeypatch.setenv("AT1_BROWSER_EXE", str(real))
    assert browser.find_exe() == str(real)
    monkeypatch.delenv("AT1_BROWSER_EXE", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)  # 隔离本机装机
    c1 = tmp_path / "cand" / "chrome.exe"
    c1.parent.mkdir(parents=True)
    c1.write_bytes(b"x")
    monkeypatch.setattr(browser, "_CANDIDATES", (str(c1),))
    assert browser.find_exe() == str(c1)
    monkeypatch.setattr(browser, "_CANDIDATES", ())
    assert browser.find_exe() is None


def test_alloc_port_bindable():
    p = browser.alloc_port()
    with socket.socket() as s:
        s.bind(("127.0.0.1", p))                     # 拿到的端口此刻可 bind


def test_probe_against_local_mock_http():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert browser.probe(srv.server_address[1]) is True
        assert browser.probe(browser.alloc_port()) is False   # 没人听的端口
    finally:
        srv.shutdown()


# ── 状态文件 ─────────────────────────────────────────────────────────────

def test_state_roundtrip_and_corruption(tmp_path):
    h = browser.BrowserHandle(tmp_path, Rec(), "exe", port=9333, pid=111)
    assert h._read_state() is None                   # 无文件=无账
    h._write_state()
    st = h._read_state()
    assert st["pid"] == 111 and st["port"] == 9333 and st["headless"] is False
    h.state_path.write_text("{broken", encoding="utf-8")
    assert h._read_state() is None                   # 坏文件=无账（不抛）


# ── start() 状态迁移 ─────────────────────────────────────────────────────

def test_start_skip_no_mcp_and_no_exe(tmp_path, monkeypatch):
    ev = Rec()
    _patch_mocks(monkeypatch)
    assert browser.BrowserHandle.start(tmp_path, ev, mcp_config=None) is None
    assert ev.rows[0] == ("browser_skip", {"reason": "no-mcp-config"})
    monkeypatch.setattr(browser, "find_exe", lambda: None)
    assert browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path)) is None
    assert ev.rows[1] == ("browser_skip", {"reason": "no-exe"})


def test_start_fresh_launches_and_writes_state(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch)
    h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path))
    assert h is not None and h.port == 9001 and h.pid == 1001
    assert ev.types() == ["browser_start"]
    st = json.loads((tmp_path / ".at1" / "browser.json").read_text(encoding="utf-8"))
    assert st["pid"] == 1001 and st["port"] == 9001
    assert launches[0]["profile"] == str(tmp_path / ".at1" / "chrome-profile")


def test_start_reuses_orphan_without_touching_it(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch)
    _mk_orphan_state(tmp_path, pid=777, port=9222)
    h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path))
    assert h is not None and h.pid == 777 and h.port == 9222
    assert ev.types() == ["browser_reuse"]
    assert launches == [] and kills == []            # 复用：旧实例分文不动


def test_start_headless_mismatch_flag_wins(tmp_path, monkeypatch):
    """§6.5-2：记账 headless 与当前 flag 不一致 → flag 优先，杀旧按新 flag 重起。"""
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch)
    _mk_orphan_state(tmp_path, pid=777, headless=False)
    monkeypatch.setenv("AT1_BROWSER_HEADLESS", "1")
    h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path))
    assert h is not None and h.headless is True and h.pid == 1001
    assert kills == [777]                            # 先杀旧
    assert launches[0]["headless"] is True
    assert ev.types() == ["browser_start"]


def test_start_dead_orphan_kills_before_relaunch(tmp_path, monkeypatch):
    """R1：不可复用时先杀旧进程再拉新（顺序锚——假死实例占 profile 锁）。"""
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch, alive=False)
    _mk_orphan_state(tmp_path, pid=777)
    h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path))
    assert h is not None and ev.types() == ["browser_start"]
    assert kills[0] == 777                           # 杀旧先于 launch
    assert len(launches) == 1


def test_start_launch_failure_retries_then_degrades(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch, wait=False)   # CDP 永不就绪
    h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=_mk_mcp(tmp_path))
    assert h is None                                 # 不拒启：降级 None
    assert len(launches) == browser.PORT_RETRIES     # 换口重试 3 次
    assert ev.types()[-1] == "browser_exit"
    assert "launch-failed" in ev.rows[-1][1]["reason"]


# ── ensure() 轮间探活 ────────────────────────────────────────────────────

def test_ensure_noop_when_alive(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch)
    h = browser.BrowserHandle(tmp_path, ev, "exe", port=9333, pid=111)
    h.ensure()
    assert launches == [] and kills == [] and ev.rows == []


def test_ensure_relaunches_with_kill_first(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch, probe=False)
    h = browser.BrowserHandle(tmp_path, ev, "exe", port=9333, pid=111)
    h.ensure()
    assert kills == [111]                            # 先杀旧
    assert len(launches) == 1
    assert ev.types() == ["browser_relaunch"]
    assert ev.rows[0][1]["reason"] == "probe-fail"


def test_ensure_dead_is_noop(tmp_path, monkeypatch):
    ev = Rec()
    launches, kills = _patch_mocks(monkeypatch, probe=False)
    h = browser.BrowserHandle(tmp_path, ev, "exe", port=9333, pid=111)
    h.dead = True
    h.ensure()
    assert launches == [] and ev.rows == []          # 不每轮空转重试


# ── shutdown(keep) ───────────────────────────────────────────────────────

def test_shutdown_keep_leaves_everything(tmp_path, monkeypatch):
    ev = Rec()
    kills = _patch_mocks(monkeypatch)[1]
    h = browser.BrowserHandle(tmp_path, ev, "exe", port=9333, pid=111)
    h._write_state()
    h.shutdown(keep=True)
    assert kills == [] and h.state_path.is_file() and ev.rows == []


def test_shutdown_no_keep_kills_and_clears(tmp_path, monkeypatch):
    ev = Rec()
    kills = _patch_mocks(monkeypatch)[1]
    h = browser.BrowserHandle(tmp_path, ev, "exe", port=9333, pid=111)
    h._write_state()
    h.shutdown(keep=False)
    assert kills == [111]
    assert not h.state_path.exists()
    assert ev.types() == ["browser_exit"] and ev.rows[0][1]["reason"] == "shutdown"


# ── kill_pid 镜像守门（pid 回收复用防护，S2 同源） ────────────────────────

@pytest.mark.skipif(os.name != "nt", reason="tasklist 镜像守门是 Windows 分支")
def test_kill_pid_refuses_non_browser_image(monkeypatch):
    calls = []
    monkeypatch.setattr(browser, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(browser, "_image_name", lambda pid: "explorer.exe")
    monkeypatch.setattr(browser.subprocess, "run", lambda *a, **k: calls.append(a))
    browser.kill_pid(4242)
    assert calls == []                               # pid 被无关进程复用 → 不动
    monkeypatch.setattr(browser, "_image_name", lambda pid: "chrome.exe")
    browser.kill_pid(4242)
    assert calls                                     # chrome 镜像 → 动手


# ── 真 Emitter 冒烟（R8：EVENT_TYPES 登记缺失，假 ev 测不出来） ──────────

_BROWSER_EVENTS = ("browser_start", "browser_reuse", "browser_relaunch",
                   "browser_skip", "browser_exit")


def test_real_emitter_accepts_all_browser_events(tmp_path):
    from src.events import EVENT_TYPES, EventWriter
    for t in _BROWSER_EVENTS:
        assert t in EVENT_TYPES
    ev = EventWriter(str(tmp_path / "auto-log.jsonl"))
    try:
        for t in _BROWSER_EVENTS:
            ev.emit(t, {"pid": 1, "port": 2, "headless": False, "reason": "smoke"})
    finally:
        ev.close()
    rows = [json.loads(l) for l in (tmp_path / "auto-log.jsonl")
            .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert [r["type"] for r in rows] == list(_BROWSER_EVENTS)


def test_start_skip_through_real_emitter(tmp_path):
    """start→emit→EventWriter 全真链（skip 路径最短真冒烟）。"""
    from src.events import EventWriter
    ev = EventWriter(str(tmp_path / "auto-log.jsonl"))
    try:
        h = browser.BrowserHandle.start(tmp_path, ev, mcp_config=None)
    finally:
        ev.close()
    assert h is None
    rows = [json.loads(l) for l in (tmp_path / "auto-log.jsonl")
            .read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows[0]["type"] == "browser_skip"
