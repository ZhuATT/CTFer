"""AT1 scaffold —— workdir 模板展开（P4.1，设计§2.3）。

<sengagement>/.auto/ 展开：CLAUDE.md（常驻纪律层，由模板 WORKER-CLAUDE.md 渲染）
+ .mcp.json（Playwright → 本地 chrome）+ FINDINGS/FACTS 预创建空文件 + evidence/。

文件名决策：模板叫 WORKER-CLAUDE.md，落位成 CLAUDE.md——Claude Code CLI 对
cwd 的 CLAUDE.md 有自动加载机制（进 system prompt 基线），纪律层靠机制保证
被读，不依赖 worker 自觉"开工先读 WORKER-CLAUDE.md"。

幂等：重复展开不覆盖已有 FINDINGS/FACTS/evidence（发现即落盘的物理保证）；
CLAUDE.md/.mcp.json 每次重写（纪律层随 engagement 配置，内容确定性）。
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

_TEMPLATE_DIR = Path(__file__).parent.parent / "scaffolding"


def _render_worker_claude(engagement: dict) -> str:
    """WORKER-CLAUDE.md 模板 + engagement 字段 → 纪律层文本。

    用显式 replace 不用 str.format——模板含 JSON 示例（单大括号），
    format 会被当成占位符炸掉；replace 对模板内容零约束。
    """
    tmpl = (_TEMPLATE_DIR / "WORKER-CLAUDE.md").read_text(encoding="utf-8")
    scope = engagement.get("scope", {}) or {}
    allow = scope.get("allow") or [engagement.get("target", "")]
    deny = scope.get("deny") or []
    subs = {
        "{target}": str(engagement.get("target", "(未提供——见任务简报)")),
        "{mission}": str(engagement.get("mission", "(见任务简报)")),
        "{allow}": "\n  - ".join(str(a) for a in allow),
        "{deny_list}": ("\n  - ".join(str(d) for d in deny) if deny
                        else "（无显式 deny——allow 之外一律不打）"),
    }
    for k, v in subs.items():
        tmpl = tmpl.replace(k, v)
    return tmpl


def expand(engagement_root: str | os.PathLike, engagement: dict, *,
           skills_src: str | os.PathLike | None = None) -> Path:
    """展开 workdir（<engagement>/.auto/）。返回 workdir 路径。

    skills_src 给定时复制整个 skills 目录到 workdir/.claude/skills/
    （信号路由表的物理依赖；不给则路由表降级为"按经验行事"，不阻塞）。
    """
    workdir = Path(engagement_root) / ".auto"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "evidence").mkdir(exist_ok=True)

    # 纪律层 + MCP：确定性重写
    (workdir / "CLAUDE.md").write_text(
        _render_worker_claude(engagement), encoding="utf-8")
    shutil.copyfile(_TEMPLATE_DIR / ".mcp.json", workdir / ".mcp.json")

    # 账本：预创建空文件（实测教训：不预创建 worker 会建 .jsonl 变体名）
    for name in ("FINDINGS", "FACTS"):
        (workdir / name).touch(exist_ok=True)

    # 身份注入：engagement.json credentials.storage_state → workdir/storage-state.json
    cred = engagement.get("credentials", {}) or {}
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


def load_engagement(engagement_root: str | os.PathLike) -> dict:
    """读并校验 engagement.json（fail-fast：scope.allow 非空 + target 存在）。"""
    path = Path(engagement_root) / "engagement.json"
    if not path.is_file():
        raise FileNotFoundError(f"缺 engagement.json：{path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"engagement.json 不是合法 JSON：{e}") from e
    if not data.get("target"):
        raise ValueError("engagement.json 缺 target")
    allow = (data.get("scope") or {}).get("allow")
    if not allow or not isinstance(allow, list):
        raise ValueError("engagement.json 缺 scope.allow（非空列表是 fail-fast 条件）")
    return data
