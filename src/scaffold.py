"""AT1 scaffold —— workdir 模板展开（v3）。

<engagement>/.auto/ 展开：CLAUDE.md（WORKER-CLAUDE.md 渲染，槽值从黑板簿记取——
运行时唯一真相=bookkeeping，engagement.json 只是 CLI 时代的播种源之一，M5 前端
表单写簿记走同一条路）+ FORMATS.md（每轮重写防篡改）+ .mcp.json + FINDINGS/FACTS
预创建（指路头）+ evidence/ + reports/ + src标准/。

播种（schema §11）：target/goal/hint 空则播进 bookkeeping（续跑不覆盖）；
scope 每次覆盖（边界以最新委托为准）。mission 字段已废（09-19：与图重合）。
DIRECTIONS 写面退役（A17③）：不预创建、遗留旧文件清理。

文本定稿=prompt-全文汇编.md §3.1/§3.2；本模块与汇编的一致性由 test_scaffold 锁定。
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

_TEMPLATE_DIR = Path(__file__).parent.parent / "scaffolding"
_STANDARDS_DIR = Path(__file__).parent.parent / "src标准"

# {env_bg} 渲染内容（汇编 §3.3；A21 可插拔——WSL/容器化时换 Cairn 同款 tmux 条款）
_ENV_BG = (
    "长任务（扫描/爆破/大文件下载）脱离启动：PowerShell Start-Process（不是 Start-Job——"
    "它随会话死）；输出重定向到当前目录 bg-*.log，首行记命令与启动时间；"
    "交接必提在跑的后台任务（文件名+在干什么）。轮末系统会扫 bg-*.log 遗留并提醒下轮。"
)

# 账本指路头（幂等：只在文件不存在时写入；格式细节在 FORMATS.md，头只指路）
_LEDGER_HEADERS = {
    "FINDINGS": "# 每行一条发现（JSONL，append-only）——格式/三层判层正反例/报告要求：写盘前必读同目录 FORMATS.md。\n",
    "FACTS": "# 每行一条知识（JSONL，append-only，只写对攻击真有效的线索）——格式与不写清单：见 FORMATS.md。\n",
}


def seed_engagement(eng: dict, bb) -> None:
    """engagement.json → bookkeeping 播种（schema §11）。

    target/goal/hint 空则播（续跑不覆盖——goal-set 改过的目标不被 engagement 冲掉）；
    scope 每次覆盖（授权边界以最新委托为准）。mission 字段已废，不读。"""
    bk = bb.bookkeeping
    if not bk.get("target"):
        bk["target"] = str(eng.get("target", "")).strip()
    if not bb.goal.get("text") and eng.get("goal"):
        bb.set_goal(str(eng["goal"]).strip(), round=0)
    if not bk.get("hint"):
        bk["hint"] = str(eng.get("hint", "")).strip()
    bk["scope"] = dict(eng.get("scope") or {})


def _render_worker_claude(bb) -> str:
    """WORKER-CLAUDE.md 模板 + 黑板簿记 → 纪律层文本。

    显式 replace 不用 str.format——模板含 JSON 示例（单大括号）与 {env_bg} 等
    自定义槽，replace 对内容零约束。"""
    tmpl = (_TEMPLATE_DIR / "WORKER-CLAUDE.md").read_text(encoding="utf-8")
    bk = bb.bookkeeping
    for k, v in {
        "{target}": str(bk.get("target") or "(未提供——见任务简报)"),
        "{hint}": str(bk.get("hint") or "（无）"),
        "{env_bg}": _ENV_BG,
    }.items():
        tmpl = tmpl.replace(k, v)
    return tmpl


def expand(engagement_root: str | os.PathLike, eng: dict, bb, *,
           skills_src: str | os.PathLike | None = None) -> Path:
    """展开 workdir（<engagement>/.auto/）。返回 workdir 路径。bb 必传——
    槽值从黑板簿记取（运行时唯一真相），调用方须先 seed_engagement。"""
    workdir = Path(engagement_root) / ".auto"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "evidence").mkdir(exist_ok=True)
    (workdir / "reports").mkdir(exist_ok=True)

    # 纪律层（每轮重写）+ 格式层（每轮重写防篡改）+ MCP
    (workdir / "CLAUDE.md").write_text(_render_worker_claude(bb), encoding="utf-8")
    (workdir / "FORMATS.md").write_text(
        (_TEMPLATE_DIR / "FORMATS.md").read_text(encoding="utf-8"), encoding="utf-8")
    shutil.copyfile(_TEMPLATE_DIR / ".mcp.json", workdir / ".mcp.json")

    # A17③：DIRECTIONS 写面退役——不预创建；旧 engagement 遗留文件清理（防误导新会话）
    legacy = workdir / "DIRECTIONS"
    if legacy.exists():
        legacy.unlink()

    # 账本：预创建指路头（幂等）
    for name, header in _LEDGER_HEADERS.items():
        p = workdir / name
        if not p.exists():
            p.write_text(header, encoding="utf-8")

    # src标准（判定标尺库，设计§6.5：worker 写报告自愿参照）——资料地图指针的实体
    if _STANDARDS_DIR.is_dir():
        dst = workdir / "src标准"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(_STANDARDS_DIR, dst)

    # 身份注入：engagement.json credentials.storage_state → workdir/storage-state.json
    cred = eng.get("credentials", {}) or {}
    src_state = cred.get("storage_state")
    if src_state:
        p = Path(src_state)
        if not p.is_absolute():
            p = Path(engagement_root) / p
        if p.is_file():
            shutil.copyfile(p, workdir / "storage-state.json")

    # 可选：skills 预复制
    if skills_src and Path(skills_src).is_dir():
        dst = workdir / ".claude" / "skills"
        if not dst.exists():
            shutil.copytree(skills_src, dst)
    return workdir


class EngagementError(ValueError):
    """engagement.json 校验失败。field=问题字段名——M5 前端表单校验直接映射
    （拒启原因要在 UI 上体现，用户要求 09-19）；CLI 时代继承 ValueError 兼容现有捕获。"""

    def __init__(self, field: str, msg: str):
        super().__init__(msg)
        self.field = field


def load_engagement(engagement_root: str | os.PathLike) -> dict:
    """读并校验 engagement.json（§11）。
    fail-fast：target/goal 非空必填；hint 字段必填（值可空串=无指示）。
    scope/skills_src/credentials 可选（scope 缺→guard 目标拦截停用+警告）。"""
    path = Path(engagement_root) / "engagement.json"
    if not path.is_file():
        raise EngagementError("engagement", f"缺 engagement.json：{path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise EngagementError("engagement", f"engagement.json 不是合法 JSON：{e}") from e
    if not str(data.get("target", "")).strip():
        raise EngagementError("target", "engagement.json 缺 target（打谁）")
    if not str(data.get("goal", "")).strip():
        raise EngagementError("goal", "engagement.json 缺 goal（完成标准，一句可判定的话——<Stop> 达成锚点）")
    if "hint" not in data:
        raise EngagementError("hint", "engagement.json 缺 hint 字段（无指示可填空串）")
    return data
