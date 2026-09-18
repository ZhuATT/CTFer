"""AT1 prompt —— 每轮 stdin 渲染（批 1 残版；三块终态=引导/运行提示/简报，T4.1/P4）。

v3 已砍：序言(A6)/阶段手册(A12)/指令(A15)/plan_directive(A15)/交接段(A19——
Handoff 住 STATE.md 不进 stdin)/重复命令告警(A20)/后台任务块(A21)。
保留：紧凑摘要（board.summarize，四视图现算）/路由提示（全图 fact 值扫描，S4——
不再按 kind=fingerprint 查）/人工指示。防注入唯一战线=STATE.md（A19/A20）。
"""

from __future__ import annotations

from typing import Optional

# 路由提示（A7/S4：燃料=全图 fact 值扫描；命中措辞 T4.2 改直接指令式）
_HINT_ROUTES = (
    ("spring|java|tomcat|jboss", "Java 系中间件 → 加载 injection-sqli / injection-deser skill"),
    ("php", "PHP → 加载 crypto-attacks（松散比较）/ injection-xss skill"),
    ("node|express", "Node → 加载 injection-deser（原型污染）/ api-all skill"),
    ("nginx", "nginx 反代 → 加载 web-advanced（缓存/绕过）skill"),
    ("asp|\\.net|iis", ".NET → 加载 injection-deser（ViewState）/ auth-token skill"),
)

_SEGMENT_MARKS = ("【状态摘要】", "【提示】", "【人工指示】")


def render_round_prompt(board, directive: Optional[str] = None, *, round_: int = 0) -> str:
    """批 1 残版：摘要 + 路由提示 + 人工指示。确定性：同黑板两次调用逐字节相同。"""
    segs: list[str] = []
    segs.append(board.summarize(round_=round_))
    fp_text = " ".join(board.fact_values()).lower()
    hints = [txt for pat, txt in _HINT_ROUTES
             if any(k.lower() in fp_text for k in pat.split("|"))]
    segs.append("\n".join(f"- {h}" for h in hints) if hints else "（暂无路由提示）")
    segs.append(directive if directive else "（无）")
    return "\n\n".join(f"{mark}\n{seg}" for mark, seg in zip(_SEGMENT_MARKS, segs))
