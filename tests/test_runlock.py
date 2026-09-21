"""runlock/phase 单测（批4fix S3/S4/S5）：

S3 run.lock：内核级所有权锁——双抢必有一败、进程死锁自动放（无死锁残尸）。
S4 stop 等死：cmd_stop 返回时刻 ≥ 持锁进程死亡时刻；超时报警；无实例幂等。
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SRC = str(REPO / "src")


def _spawn_holder(tmp_path: Path, code: str) -> tuple[subprocess.Popen, int]:
    """真子进程里抢锁（锁是进程级的——单测进程内自抢自放测不出内核语义）。

    返回 (Popen, 真解释器 PID)——Windows venv python.exe 是转发器，Popen.pid
    是启动器，干活的解释器是它的子进程（锁信息里记的是真解释器）。"""
    code = ("import os\n" + code.replace(
        "print('LOCKED', flush=True)",
        "print('LOCKED', os.getpid(), flush=True)"))
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=str(REPO), stdout=subprocess.PIPE, text=True)
    line = proc.stdout.readline().split()
    assert line[0] == "LOCKED"
    return proc, int(line[1])


def _kill_tree(pid: int) -> None:
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                   capture_output=True, timeout=10)


# ── S3：所有权锁 ──────────────────────────────────────────────────────────

def test_acquire_writes_info_and_release(tmp_path):
    from src import runlock
    h = runlock.acquire(tmp_path)
    assert h is not None
    info = runlock.read_info(tmp_path)
    assert info and info["pid"] == os.getpid() and "started_at" in info
    runlock.release(h)
    # 残文件仍在（内容保留）但锁已放——不影响下次抢
    assert runlock.acquire(tmp_path) is not None


def test_double_acquire_second_rejected(tmp_path):
    from src import runlock
    h = runlock.acquire(tmp_path)
    assert h is not None
    try:
        assert runlock.acquire(tmp_path) is None     # 双 run：第二个拒
        info = runlock.read_info(tmp_path)
        assert info["pid"] == os.getpid()            # 现持者信息未被输家毁掉
    finally:
        runlock.release(h)


def test_read_info_garbage_or_missing(tmp_path):
    from src import runlock
    assert runlock.read_info(tmp_path) is None       # 无文件
    p = runlock.lock_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("not-json{{", encoding="utf-8")
    assert runlock.read_info(tmp_path) is None


def test_holder_death_releases_lock(tmp_path):
    """S3 核心性质：持锁进程被杀（模拟崩溃）→ 内核自动放锁，锁可抢。"""
    from src import runlock
    proc, real_pid = _spawn_holder(tmp_path, (
        "import sys, time\n"
        "sys.path.insert(0, r'%s')\n"
        "from src import runlock\n"
        "h = runlock.acquire(r'%s')\n"
        "assert h is not None, '子进程抢锁失败'\n"
        "print('LOCKED', flush=True)\n"
        "time.sleep(60)\n" % (SRC, tmp_path)))
    try:
        assert runlock.acquire(tmp_path) is None     # 锁在别人手里
        _kill_tree(real_pid)                          # 模拟崩溃（杀真解释器树）
        proc.wait(timeout=10)
        time.sleep(0.3)                               # 内核收尾句柄
        h = runlock.acquire(tmp_path)
        assert h is not None, "持锁进程死后锁未释放（出现死锁残尸）"
        runlock.release(h)
    finally:
        _kill_tree(real_pid)


# ── S4：stop 等进程死透才返回 ─────────────────────────────────────────────

def test_stop_returns_only_after_instance_dead(tmp_path, capsys):
    """真子进程持锁慢退出：stop 返回时进程必已死（新契约本体）。"""
    from src.__main__ import main
    proc, real_pid = _spawn_holder(tmp_path, (
        "import sys, time\n"
        "sys.path.insert(0, r'%s')\n"
        "from src import runlock\n"
        "import pathlib\n"
        "h = runlock.acquire(r'%s')\n"
        "assert h is not None\n"
        "print('LOCKED', flush=True)\n"
        # 等 stop 写下 CONTROL → 模拟"收尾 1s"→ 退出放锁
        "ctl = pathlib.Path(r'%s') / 'state' / 'CONTROL'\n"
        "t0 = time.time()\n"
        "while not ctl.exists() and time.time() - t0 < 15:\n"
        "    time.sleep(0.1)\n"
        "time.sleep(1.0)\n" % (SRC, tmp_path, tmp_path)))
    try:
        rc = main(["stop", str(tmp_path)])
        assert rc == 0
        assert proc.poll() is not None, "stop 返回时实例还活着（契约破坏）"
        out = capsys.readouterr().out
        assert "实例已退出" in out
        proc.wait(timeout=10)
    finally:
        _kill_tree(real_pid)


def test_stop_timeout_warns_not_kill(tmp_path, monkeypatch, capsys):
    """超时路径：大声报警带 PID（锁信息里的真解释器）+ 非零退出——不偷偷强杀。"""
    from src.__main__ import main
    monkeypatch.setenv("AT1_STOP_WAIT_S", "1")
    proc, real_pid = _spawn_holder(tmp_path, (
        "import sys, time\n"
        "sys.path.insert(0, r'%s')\n"
        "from src import runlock\n"
        "h = runlock.acquire(r'%s')\n"
        "assert h is not None\n"
        "print('LOCKED', flush=True)\n"
        "time.sleep(60)\n" % (SRC, tmp_path)))       # 装死不理 CONTROL
    try:
        rc = main(["stop", str(tmp_path)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "未退出" in out and str(real_pid) in out
        assert proc.poll() is None                    # 报警路径没有替用户强杀
    finally:
        _kill_tree(real_pid)
        proc.wait(timeout=10)


def test_stop_without_instance_idempotent(tmp_path, capsys):
    """无实例幂等：首次试探即抢到锁 → 立即返回；CONTROL 照写（早于 run 语义不变）。"""
    from src.__main__ import main
    t0 = time.time()
    rc = main(["stop", str(tmp_path)])
    assert rc == 0
    assert time.time() - t0 < 5                       # 不等待
    assert "没有在跑的实例" in capsys.readouterr().out
    assert (tmp_path / "state" / "CONTROL").is_file()


def test_stop_reports_frozen_phase(tmp_path, capsys):
    """stop 成功报文从 phase.json 读冻结点（等待过的实例；S5 联动）。"""
    from src import phase as phase_mod
    from src.__main__ import main
    phase_mod.write(tmp_path, "auditing", 3)
    proc, real_pid = _spawn_holder(tmp_path, (
        "import sys, time\n"
        "sys.path.insert(0, r'%s')\n"
        "from src import runlock\n"
        "import pathlib\n"
        "h = runlock.acquire(r'%s')\n"
        "assert h is not None\n"
        "print('LOCKED', flush=True)\n"
        "ctl = pathlib.Path(r'%s') / 'state' / 'CONTROL'\n"
        "t0 = time.time()\n"
        "while not ctl.exists() and time.time() - t0 < 15:\n"
        "    time.sleep(0.1)\n"
        "time.sleep(0.6)\n" % (SRC, tmp_path, tmp_path)))
    try:
        rc = main(["stop", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "实例已退出" in out and "auditing r3" in out
        proc.wait(timeout=10)
    finally:
        _kill_tree(real_pid)


# ── CLI 接线：cmd_run 抢锁 ────────────────────────────────────────────────

def test_cmd_run_rejected_when_lock_held(tmp_path, capsys):
    from src import runlock
    from src.__main__ import main
    lock = runlock.acquire(tmp_path)
    assert lock is not None
    try:
        rc = main(["run", str(tmp_path)])             # engagement 无效也不该走到那
        assert rc == 2
        out = capsys.readouterr().out
        assert "已有实例" in out and str(os.getpid()) in out
    finally:
        runlock.release(lock)


def test_cmd_run_proceeds_when_lock_free(tmp_path, capsys):
    """锁空闲 → cmd_run 走进 run_engagement（无 engagement.json 拒启，非锁拒启）。"""
    from src.__main__ import main
    rc = main(["run", str(tmp_path)])
    assert rc == 2
    out = capsys.readouterr().out
    assert "已有实例" not in out
    assert "拒启" in out
