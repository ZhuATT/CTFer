"""AT1 prompt —— 阶段手册 + 每轮 prompt 渲染（纯 Python 确定性拼接，无 LLM）。

设计§3.5：9 段固定顺序组装；同一黑板状态渲染结果逐字节相同。
注意：recon 手册全文为 DRAFT——按用户要求需过目后才算定稿（落码仅为 relay demo 可跑）。
"""

from __future__ import annotations

from typing import Optional

PREAMBLE = """【方法论序言——固定不变】
你在执行一次授权黑盒渗透测试。方法论：现象是路标，结果是终点——只追求结果类发现
（越权/注入/RCE/凭证泄露），现象类信号（CORS/sourcemap/指纹/裸 instance-id）记录
后当侦察弹药继续深挖，不作为发现提交。没有可复现 PoC 的东西不存在。
每轮你都是全新会话：黑板状态和上一轮交接在下方，这是你对任务的全部记忆来源。"""

MANUALS: dict[str, str] = {
    "recon": """【阶段手册① 侦察拓面】
铁律：不做浏览器侦察，不准开始 curl。
目标：攻击面摸清并沉淀进黑板（端点/指纹自动入库；结论写 FACTS）。

操作序列（按序执行）：
1. 浏览器侦察四步（Playwright MCP）：
   browser_navigate → 目标 URL
   browser_snapshot → 页面结构
   browser_network_requests(filter:"/api|xhr|fetch/") → 真实 API
   browser_click 有目的地点击功能区 → 再捕获一轮
2. JS 蒸馏（js-intel，本地 Chrome，无需 playwright install）：
   node D:/Downloads/hacker/script/js-intel/src/index.js --url <URL> --storage-state storage-state.json
   产物 out/<host>-<时间戳>.md：端点→漏洞类路由、密钥、sink——读完把要点写进 FACTS
3. 资产分诊（端点 >20 时）：按指纹分组 → 每组测一个代表 → 挑 3-8 个高价值
   （有身份语义 / 有对象 ID 参数 / 可写操作）；CDN、静态资源、文档域名跳过
4. 记账：每个功能面在 status.md 攻击面表加一行（| 端点 | seen | 测过什么 |）；
   每次主动测试往 state/log.jsonl 追加一行 {ts,cmd,endpoint,result摘要}

实战纪律：
- 同一方向连续 5 次失败 → 切换方向，不死磕
- cookie 统一存 evidence/cookies.txt，命令里引用文件，不裸拼长串
- 动手前先看状态区的"已免疫勿重测"；同一命令不跑第三遍
- 现象（CORS/sourcemap/指纹）只记录当弹药，继续挖到结果类发现
出口判据见指令行——达标即进下一阶段，不恋战。""",

    "identity": """【阶段手册② 身份模型】
目标：搞清"服务端到底认谁"。结论必须写成 FACTS 行：
{"kind":"identity_model","value":"…","evidence":"…"}（engagement 级唯一，重报覆盖）。

三条路依次做实验（每条都把完整请求响应落进 evidence/）：
1. cookie 摘除：逐个摘掉 httpOnly cookie 重放同一请求，看登录态变化
   → 掉登录态的那个就是身份派生源
2. 客户端身份注入对调：请求里的 userId / X-User-Id / spidertoken 类字段，
   把 A 的值换成 B 的重放 → 服务端认了 = 注入可越权；忽略 = 摆设（也是重要结论）
3. 签名/token 强制性：摘掉签名头或签名参数重放
   → 还能成功 = 签名非强制（风控软校验的常见形态）

若【上一轮交接】或前置情报里带有平台形态参考，优先按它设计实验
（参考是假设不是答案，三个实验仍要做全）。
出口：黑板出现 identity_model（含三项实验结论）→ 进 exploit。""",

    "exploit": """【阶段手册③ 越权闭环——提纲占位，M3 前定稿】
对象枚举 → 身份对调（marker 取自 marker_source）→ 响应 diff → 写操作必须读回。
每候选当场落 evidence/ + FINDINGS 行（含 distinct_from）。""",

    "report": """【阶段手册④ 报告产出——提纲占位，M4 前定稿】
同根因合并；evidence 四段模板（请求/响应/佐证/来源命令）；阴性结论写
status.md"已确认非漏洞"段；产出 report.md 草稿。""",
}

# 第 8 段 hints：指纹关键词 → skill 路由行（设计§3.5.2 第 5 段路由表的渲染子集）
_HINT_ROUTES = (
    ("spring|java|tomcat|jboss", "Java 系中间件 → 路由表 injection-sqli / injection-deser 行"),
    ("php", "PHP → 路由表 crypto-attacks（松散比较）/ injection-xss 行"),
    ("node|express", "Node → 路由表 injection-deser（原型污染）/ api-all 行"),
    ("nginx", "nginx 反代 → 路由表 web-advanced（缓存/绕过）行"),
    ("asp|\.net|iis", ".NET → 路由表 injection-deser（ViewState）/ auth-token 行"),
)

_SEGMENT_MARKS = ("【序言】", "【阶段手册】", "【指令】", "【状态】",
                  "【上一轮交接】", "【重复命令告警】", "【后台任务】", "【提示】", "【人工指示】")


def render_round_prompt(board, directive: Optional[str] = None, *, round_: int = 0) -> str:
    """9 段固定顺序。确定性：同黑板两次调用逐字节相同（nonce 例外——untrusted 防注入需随机）。"""
    segs: list[str] = []
    segs.append(PREAMBLE)
    segs.append(MANUALS.get(board.goal.get("stage", "recon"), MANUALS["recon"]))
    segs.append(board.plan_directive(round_=round_))
    segs.append(board.render())
    segs.append(board.handoff if board.handoff else "（首轮，无上一轮交接）")
    tried = sorted(board.ledger.get("tried", {}).items(), key=lambda x: -x[1])
    hot = [(c, n) for c, n in tried if n >= 3][:5]
    segs.append("\n".join(f"- {c[:100]}（已 ×{n}，勿重跑）" for c, n in hot)
                if hot else "（无高频重复命令）")
    bg = board.ledger.get("background", [])
    segs.append("\n".join(f"- #{b.get('id')} {b.get('desc','')} [{b.get('status','?')}]"
                          for b in bg) if bg else "（无后台任务）")
    fp_text = " ".join(f["value"] for f in board.query("fingerprint"))
    hints = [txt for pat, txt in _HINT_ROUTES
             if pat.split("|")[0].lower() in fp_text.lower()
             or any(k.lower() in fp_text.lower() for k in pat.split("|"))]
    segs.append("\n".join(f"- {h}" for h in hints) if hints else "（暂无路由提示）")
    segs.append(directive if directive else "（无）")
    return "\n\n".join(f"{mark}\n{seg}" for mark, seg in zip(_SEGMENT_MARKS, segs))
