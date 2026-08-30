"""AT1 prompt —— 阶段手册 + 每轮 prompt 渲染（纯 Python 确定性拼接，无 LLM）。

设计§3.5：9 段固定顺序组装；同一黑板状态渲染结果逐字节相同。
四份手册 M4 定稿（P4.7）：recon 经 A4 实战验证；identity/exploit/report 按
观察者架构新契约写全（利用标注段/白话 evidence/4 字段 FINDINGS）。
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
额外任务：识别目标业务类型（电商/社交/SaaS/内部系统），写一条
{"kind":"business_context","value":"这是XX平台，XX行为是正常业务","evidence":"..."} 进 FACTS。

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
- 动手前先看状态区的阴性记录与已否决模式，规划时跳过已试过的同姿势（换姿势不受限）；同一命令不跑第三遍
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

    "exploit": """【阶段手册③ 深挖闭环】
目标：把疑似变成确认的结果类发现（越权/注入/未授权访问/凭证泄露）。

怎么选方向——看状态区三个标记段：
- "已确认发现"：同端点同根因**勿重交**（系统会判 duplicate）
- "未测面"+"观察者建议"：地图上有路没探过的，优先挑有身份语义/对象 ID 参数/可写操作的
- "阴性记录"+"已否决模式"：同姿势已试过是关的，换姿势/新线索不受限

攻击闭环四步（每候选跑全）：
1. 对象枚举：相邻 ID/时间戳/UUID 的可预测性——连续取 3 个样本看规律
2. 身份对调：A 的身份访问 B 的对象（A/B 凭证见 evidence/cookies.txt），
   marker 从 B 的正常响应取（手机号/用户名等），换 A 凭证重放看 marker 是否还在
3. 响应 diff：两次响应逐字段比——差异字段才是发现，相同部分不算
4. 写操作必须读回：改完立刻用读接口复查值真的变了，才算写入成立

每发现当场两件事（不等会话结束）：
- evidence/ 白话文件（请求响应关键原文，别编造别省略关键行）
- FINDINGS 追加一行（4 字段）

纪律：同一方向连续 5 次失败换方向；低价值现象是路标不是终点，
同一根因换个输入形状 often 出真结果。""",

    "report": """【阶段手册④ 报告产出】
目标：把黑板上的确认结果整理成 report.md 草稿（写到本目录上一级的 report.md，
即 <engagement>/report.md——用绝对路径或 ../report.md）。

取数三源（都在 prompt 状态区，不要凭记忆编）：
1. "已确认发现"段 → 报告主体
2. "阴性记录"+"已否决模式"段 → "已确认非漏洞"章节（有价值的阴性结论）
3. FACTS 里的身份模型/业务上下文 → 测试方法章节

每条报告项的结构（同根因合并成一条，不拆水）：
- 标题：一句话说清影响（攻击者能做什么）
- 等级：高（凭证/PII组合/写入）/ 中（单字段PII）/ 低（非敏感状态）
- 端点与复现步骤：完整请求（含凭证位置说明）+ 响应关键行 + evidence 文件引用
- 影响：能拿到的具体数据/能执行的具体操作

阴性结论写成"已确认非漏洞"：endpoint + 为什么不是（403/设计内/影响归零）+ 测过的姿势。

格式要求：Markdown；开头一页摘要（发现数/等级分布/覆盖度）；
不虚报没确认的东西；草稿状态标注"待人复核"。""",
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


def render_round_prompt(board, directive: Optional[str] = None, *, round_: int = 0,
                        tested_endpoints: set | None = None) -> str:
    """9 段固定顺序。确定性：同黑板两次调用逐字节相同（nonce 例外——untrusted 防注入需随机）。
    tested_endpoints 传入时 → board.render 在状态区后插入"未测面"段（覆盖对账，中期审核①②）。"""
    segs: list[str] = []
    segs.append(PREAMBLE)
    segs.append(MANUALS.get(board.goal.get("stage", "recon"), MANUALS["recon"]))
    segs.append(board.plan_directive(round_=round_))
    segs.append(board.render(tested_endpoints=tested_endpoints))
    relay = board.handoff if board.handoff else "（首轮，无上一轮交接）"
    intel = board.intel_summary()
    if intel:
        relay += f"\n\n[观察者情报] {intel}"
    segs.append(relay)
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
