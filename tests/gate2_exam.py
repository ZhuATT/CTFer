# -*- coding: utf-8 -*-
"""门 2 全科考试（live）：11 类 × 拒/放两题，3 票多数决。考题源自四家 SRC 判读标准。

用法：source .secrets.env && python tests/gate2_exam.py
不是 pytest 用例——需要真 LLM，手动跑。结果回写 phase3-验证.md。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.providers import SolverConfig, build_verifier_config  # noqa: E402
from src.llm import LLMClient  # noqa: E402
from src.verify import Claim, gate2  # noqa: E402

M = "13800000000"   # 万能 marker（各案证据内自洽使用）
MS = "## 响应\nuserB 资料快照（admin 导出）：uid=20001，姓名张三，手机 " + M


def _c(klass, **kw):
    base = dict(id="X", klass=klass, endpoint="/api/x", marker=M,
                marker_source="evidence/b.md", evidence="evidence/a.md",
                as_identity="userA(uid=100)", owner_identity="userB(uid=20001)",
                distinct_from="exam")
    base.update(kw)
    return Claim(**base)


REQ = 'curl -s -H "Cookie: sid=A" https://t.example/api/order/detail?id=8823'

CASES = [
    # ── idor_read ──
    ("idor_read 放", "pass", _c("idor_read"),
     "## 请求\n" + REQ + "\n\n## 响应\nHTTP/1.1 200\n\n"
     '{"buyer":"userC","name":"张三","phone":"' + M + '","addr":"北京朝阳区xx路1号"}\n\n'
     "## 佐证\nA=uid100 普通用户；id=8822 是 A 自己的单，id=8823 返回上述 C 的单（姓名+手机+地址），id 连续可遍历"),
    ("idor_read 拒", "rejected", _c("idor_read"),
     "## 请求\n" + REQ + "\n\n## 响应\nHTTP/1.1 200\n\n"
     '{"success":true,"msg":"查询成功","trace_id":"a1b2"}\n\n'
     "## 佐证\n该接口无登录态校验，任何人查任何 id 都返回同样的成功状态，响应不含任何用户数据"),
    # ── idor_write ──
    ("idor_write 放", "pass", _c("idor_write", expect='"code":0'),
     "## 请求\nPOST /api/address/update  {\"addrId\":501,\"addr\":\"攻击者地址\"}（Cookie sid=A）\n\n"
     "## 响应\nHTTP/1.1 200\n\n{\"code\":0}\n\n"
     "## 佐证\n读回验证：GET /api/address/501 → 收货地址已变为攻击者地址，addrId=501 属于 userB（admin 导出对账）"),
    ("idor_write 拒", "rejected", _c("idor_write", expect='"code":0'),
     "## 请求\nPOST /api/draft/save  {\"draftId\":9,\"content\":\"x\"}（Cookie sid=A）\n\n"
     "## 响应\nHTTP/1.1 200\n\n{\"code\":0}\n\n"
     "## 佐证\n读回：draftId=9 为公共协作草稿，任何登录用户均可在产品说明中查到的共享编辑区"),
    # ── authbypass ──
    ("authbypass 放", "pass", _c("authbypass", marker="AT1BANNER"),
     "## 请求\nPOST /admin/config/update  {\"siteBanner\":\"AT1BANNER\"}（Cookie sid=A，普通用户）\n\n"
     "## 响应\nHTTP/1.1 200\n\n{\"code\":0,\"affected\":\"全站首页横幅已更新为 AT1BANNER\"}\n\n"
     "## 佐证\n读回：GET / → 首页横幅渲染为 AT1BANNER；角色表导出：userA=普通用户，无 admin 角色，"
     "/admin/* 设计上仅管理员可达"),
    ("authbypass 拒", "rejected", _c("authbypass"),
     "## 请求\nGET /admin/about  (Cookie sid=A，普通用户)\n\n"
     "## 响应\nHTTP/1.1 200\n\n{\"about_text\":\"本平台成立于2015年…\"}\n\n"
     "## 佐证\n/about 同时挂在公开路由 /about 下，任何游客可访问，无敏感操作"),
    # ── infoleak ──
    ("infoleak 放", "pass", _c("infoleak", marker="AKIAFAKEFAKEFAKEFAKE"),
     "## 请求\nGET /static/config.js\n\n## 响应\n200\n\n"
     'const cfg={accessKey:"AKIAFAKEFAKEFAKEFAKE",secretKey:"FAKEsecret8888888888888888",bucket:"prod-media"}'),
    ("infoleak 拒", "rejected", _c("infoleak", marker="phpinfo()"),
     "## 请求\nGET /debug/phpinfo.php\n\n## 响应\n200\n\n"
     "phpinfo() 输出页：PHP Version 8.1.2 /Loaded Modules/Environment 变量列表（无任何密钥字段）"),
    # ── sqli_error ──
    ("sqli_error 放", "pass", _c("sqli_error"),
     "## 请求\nGET /search?q=1' UNION SELECT name,phone FROM users--\n\n"
     "## 响应\nSQL syntax error debug 页 + 回显两列数据：张三 / 138****0000、李四 / 139****1111"),
    ("sqli_error 拒", "rejected", _c("sqli_error"),
     "## 请求\nGET /search?q=1' 与 GET /search?q=1 对照\n\n"
     "## 响应\n两个请求返回完全相同的 You have an error in your SQL syntax 报错页"
     "（该接口对任何参数都报同样错误，报错与注入输入无关，无数据通路）"),
    # ── sqli_diff ──
    ("sqli_diff 放", "pass", _c("sqli_diff"),
     "## 请求\n"
     "[baseline] GET /item?id=1 → 200\n"
     "[attack ] GET /item?id=1'+AND+1%3D2-- → 200（同一 id，仅追加布尔载荷）\n"
     "## 响应\n"
     "[baseline] 页面含 2 条商品卡片：\"Item-A\",\"Item-B\"（响应片段：[\"Item-A\",\"Item-B\"]）\n"
     "[attack ] 同一页面仅 1 条：[\"Item-A\"]（Item-B 消失——1=2 为假致后行被过滤）\n"
     "## 佐证\n各复测两轮结果相同；交换载荷 1%3D1--+-- 后恢复 2 条（差异随布尔表达式翻转，稳定可归因注入）"),
    ("sqli_diff 拒", "rejected", _c("sqli_diff"),
     "## 请求\nGET /item?id=1 与 id=1'（各一次）\n\n"
     "## 响应\n[baseline] 耗时 320ms；[attack] 耗时 401ms（单次 81ms 差异，未复测）"),
    # ── ssrf ──
    ("ssrf 放", "pass", _c("ssrf", marker="oob-9f8e"),
     "## 请求\nPOST /webhook {\"url\":\"http://oob-9f8e.example/\"} → 改 http://10.2.3.4:8080/\n\n"
     "## 响应\nOOB hit: oob-9f8e.example 收到回连；随后 http://10.2.3.4:8080/ 经响应差异探测到"
     " Jenkins（X-Jenkins: 2.4xx header 回显在错误页）"),
    ("ssrf 拒", "rejected", _c("ssrf", marker="oob-77aa"),
     "## 请求\nPOST /webhook {\"url\":\"http://oob-77aa.example/\"}\n\n"
     "## 响应\nOOB hit: oob-77aa.example 收到回连；但改测 http://10.2.3.4:8080 与 file:///etc/passwd "
     "均超时无响应，内网完全过滤，无任何内网信息"),
    # ── xxe ──
    ("xxe 放", "pass", _c("xxe"),
     "## 请求\nPOST /import XML 含外部实体指向 OOB 平台\n\n"
     "## 响应\nOOB 平台记录收到：root:x:0:0:root:/root:/bin/bash（/etc/passwd 首行外带成功）"),
    ("xxe 拒", "rejected", _c("xxe"),
     "## 请求\nPOST /import XML 含内部实体 &xxe;\n\n"
     "## 响应\n回显 'xxe' 字面量与本地 DTD 文件名（ISOpub），无任何敏感内容外带或读取"),
    # ── lfi ──
    ("lfi 放", "pass", _c("lfi"),
     "## 请求\nGET /download?file=../../../../etc/passwd\n\n"
     "## 响应\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin…"),
    ("lfi 拒", "rejected", _c("lfi"),
     "## 请求\nGET /download?file=public/README.md\n\n"
     "## 响应\n# README\n本项目的公开说明文档…（产品首页即有此文件链接）"),
    # ── xss ──
    ("xss 放", "pass", _c("xss", marker="<img src=x onerror=at1xss>"),
     "## 请求\n商品评论提交 <img src=x onerror=at1xss>\n\n"
     "## 响应\n商品详情页（全站日活页面）渲染该评论，任意访客打开即触发 at1xss（无交互存储型）"),
    ("xss 拒", "rejected", _c("xss", marker="<svg/onload=at1xss>"),
     "## 请求\n个人资料页昵称改为 <svg/onload=at1xss>\n\n"
     "## 响应\npayload 存储并反射，但该昵称仅在自己个人资料页渲染（self），其他用户不可见"),
    # ── logic_race ──
    ("logic_race 放", "pass", _c("logic_race"),
     "## 请求\n并发 100 线程领取同一张限领 1 次的 5 元无门槛券\n\n"
     "## 响应\nbefore: 券余量 1000/已领0；after: 同一账号成功到账 23 张券（限领 1 被绕过），"
     "复测 3 次均可复现"),
    ("logic_race 拒", "rejected", _c("logic_race"),
     "## 请求\n并发重复领取新用户注册红包（拉新活动）\n\n"
     "## 响应\nbefore: 红包 0 张；after: 同账号到账 3 个 1 元拉新红包（活动规则为拉新专用，不可提现不可转赠）"),
]


def main() -> int:
    cfg = build_verifier_config(SolverConfig.from_env())
    client = LLMClient(cfg)
    chat = lambda msgs: client.chat(msgs, temperature=0.0, max_tokens=900, thinking=False).text

    ok_n = fail_n = 0
    fails = []
    for i, (name, expect, claim, ev) in enumerate(CASES, 1):
        claim.id = f"E{i:02d}"
        v = gate2(claim, ev, MS, llm_chat=chat)          # 默认 3 票
        good = v.verdict == expect
        if good:
            ok_n += 1
        else:
            fail_n += 1
            fails.append((name, expect, v.verdict, v.reasons[0][:120]))
        print(f"[{'OK ' if good else 'FAIL'}] {i:02d} {name:<18} → {v.verdict}"
              f"{'' if good else f'（期望 {expect}）'}")
        if not good:
            print(f"       {v.reasons[0][:160]}")

    print(f"\n总分 {ok_n}/{len(CASES)}" + (f"，挂 {fail_n} 题" if fail_n else "，全科通过"))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
