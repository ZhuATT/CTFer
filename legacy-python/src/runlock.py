"""AT1 runlock —— engagement 所有权锁（批4fix S3）。

语义拍板（§0 所有权）：任何时刻一个 engagement 只有一个活实例。ARTEX/Cairn
靠"服务器天然单例"，CLI 形态没有服务器——锁文件外置同等约束。

关键性质：**锁的存在性=内核管的**。持锁进程死（被杀/崩溃/正常退出）内核自动
放锁——不存在"死锁残尸"；文件存在但无锁=上次异常退出的残文件，直接覆盖即可，
不构成阻塞。Windows `msvcrt.locking(LK_NBLCK)` / POSIX `fcntl.flock(NB)`。

stop 探活复用同一把锁（S4）：抢到=持锁进程已死，零探活代码、绕开 Windows
PID 回收复用陷阱。锁=未来 M5 server 的所有权凭证（本批产物按"会被 server
收编"的形状做）。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# 锁字节放 4096 而非 0：Windows msvcrt.locking 是字节区间锁，被锁字节连本进程
# 其他句柄都读不了——持有者信息写在文件头，锁字节必须落在信息区之外
#（锁区间允许超出 EOF；POSIX flock 锁整文件、读写不受影响，两平台行为归一）。
_LOCK_OFFSET = 4096


def lock_path(root) -> Path:
    return Path(root) / ".at1" / "run.lock"


def acquire(root) -> "object | None":
    """抢内核级独占锁。抢到→返回文件句柄（持有到 release/进程死）；抢不到→None。

    抢到后截断写入持有者信息 {pid, started_at, cmd}（拒启报错/stop 超时报警
    都从这里读）。输家绝不写文件——现持者信息保持完整。
    """
    lock_file = lock_path(root)
    try:
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        # O_RDWR|O_CREAT 不截断——输家打开不能毁掉现持者的信息
        fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o644)
        f = os.fdopen(fd, "r+", encoding="utf-8")
    except OSError:
        return None
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(_LOCK_OFFSET)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ValueError):
        f.close()
        return None
    try:
        f.seek(0)
        f.truncate()
        f.write(json.dumps({"pid": os.getpid(), "started_at": _now_iso(),
                            "cmd": " ".join(sys.argv)}, ensure_ascii=False))
        f.flush()
    except OSError:
        pass
    return f


def release(f) -> None:
    """放锁（显式 unlock 后关句柄；进程死时内核兜底放锁）。"""
    if f is None:
        return
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(_LOCK_OFFSET)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except (OSError, ValueError):
        pass
    try:
        f.close()
    except OSError:
        pass


def read_info(root) -> dict | None:
    """读锁文件里的持有者信息（抢不到锁时供报错/报警）。坏文件→None。"""
    try:
        doc = json.loads(lock_path(root).read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None
