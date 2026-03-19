---
name: wooyun-legacy
description: >-
  WooYun business logic vulnerability methodology — 22,132 real cases across 6 domains (authentication bypass, authorization bypass, payment tampering, information disclosure, logic flaws, misconfiguration) and 33 vulnerability classes.
  Use for ANY security testing, auditing, or code review of web apps, APIs, or business systems — even without explicit "security" keywords.
  Triggers: penetration testing, security audit, vulnerability, bug bounty, payment security, IDOR, password reset, weak credentials, unauthorized access, race condition, parameter tampering, code review, 渗透测试, 安全审计, 漏洞挖掘, 支付安全, 越权, 逻辑漏洞, 业务安全, SRC, 代码审计.
  Also triggers on implicit intent: "test this endpoint", "find bugs", "can I bypass this", "帮我测测这个接口", "这个参数能不能改", "帮我找bug".
---

# WooYun 业务逻辑漏洞方法论

> 22,132 个真实漏洞案例 · 6 个领域 · 33 类漏洞

**Extended trigger keywords (not in description due to length limits):**
Implicit black-box testing: "看看这个功能有没有问题"、"这个流程有漏洞吗"、"怎么绕过这个限制"、"订单/支付/退款流程测试"、"这个系统安全吗"、"接口有没有风险"、"check this API"、"is this flow secure"、"review this for issues".
Tools & techniques: 抓包分析、Burp Suite、拦截请求、修改参数、重放攻击、并发测试、遍历ID、爆破、薅羊毛、刷单、套利、风控绕过、短信轰炸、接口滥用、未授权接口、任意文件、数据泄露、信息收集、子域名、目录扫描、指纹识别、intercept、replay、fuzz、enumerate、brute force、rate limiting bypass、coupon abuse.

业务逻辑漏洞无法通过扫描器发现。它们存在于开发者的本意与应用实际允许的行为之间的空隙中。本方法论教会你像编写代码的开发者一样思考，像滥用应用的用户一样发起攻击。

**数据基础：** WooYun（2010-2016），中国最大的漏洞披露平台。

## 漏洞严重性优先级

测试应优先考虑高危漏洞类别。下表按 WooYun 数据集中高危发现的比例排序——百分比越高，代表关键影响的可能性越大。

| 排名 | 漏洞类别 | 案例数 | 高危占比 | 领域 |
|------|---------|-------|---------|------|
| 1 | 密码重置 | 777 | 88.0% | 认证 |
| 2 | 任意账号 | 220 | 86.4% | 授权 |
| 3 | 提现 | 59 | 83.1% | 金融 |
| 4 | 金额篡改 | 176 | 83.0% | 金融 |
| 5 | 余额篡改 | 113 | 77.9% | 金融 |
| 6 | 任意用户注册 | 24 | 75.0% | 授权 |
| 7 | 逻辑漏洞 | 266 | 74.8% | 逻辑流 |
| 8 | 订单篡改 | 1,227 | 74.2% | 金融 |
| 9 | 价格篡改 | 70 | 74.3% | 金融 |
| 10 | 配置不当 | 1,796 | 72.6% | 配置 |
| 11 | 任意操作 | 40 | 72.5% | 授权 |
| 12 | 支付绕过 | 1,056 | 68.7% | 金融 |
| 13 | 设计缺陷 | 1,391 | 65.3% | 逻辑流 |
| 14 | 信息泄露 | 4,858 | 64.7% | 信息 |
| 15 | 越权 | 1,705 | 62.3% | 授权 |
| 16 | 弱口令 | 7,513 | 58.2% | 认证 |

## 四阶段方法

每个阶段都建立在前一阶段的基础上。跳过任何阶段会导致浅层测试，无法发现扫描器无法找到的逻辑漏洞。

### 第一阶段：业务流程映射

在测试任何端点之前，理解应用做了什么，以及资金、数据和权限如何在其中流动。

1. **理解业务**
   - 这个应用做什么？（电商、银行、社交、SaaS）
   - 主要参与者是谁？（匿名用户、普通用户、管理员、商户、API 客户端）
   - 收入模式是什么？（资金如何流动？）
   - 哪些数据敏感？（个人信息、财务数据、医疗数据、凭证）

2. **映射用户旅程**
   - 注册 → 登录 → 核心操作 → 登出
   - 购买 → 支付 → 履行 → 退款
   - 密码重置 → 验证 → 新密码
   - 管理员 → 用户管理 → 权限分配

3. **识别状态转移**
   ```
   对每个业务流程：
     - 列出所有状态（待审、活跃、已支付、已发货、已退款）
     - 列出所有有效转移（待审→已支付、已支付→已发货）
     - 问题：能否强制执行无效转移？（待审→已发货）
     - 问题：能否反向转移？（已支付→待审）
   ```

4. **映射信任边界**
   - 客户端 vs 服务器：哪些验证仅在客户端进行？
   - 用户 vs 管理员：什么分隔了权限级别？
   - 租户 vs 租户：什么防止跨租户访问？
   - 内部 vs 外部：哪些假设了受信任的内部来源？

### 第二阶段：假设形成

使用下面的参考文件形成特定领域的假设。每个领域文件包含详细的攻击模式矩阵、测试清单和防御模式，这些都源自数千个真实的 WooYun 案例。

**第一层：领域参考（方法论 + 攻击模式矩阵）** — 优先加载

| 领域 | 参考文件 | 案例数 |
|------|---------|-------|
| 认证绕过、凭证缺陷 | [authentication-domain.md](references/authentication-domain.md) | 8,846 |
| 权限绕过、IDOR、权限提升、任意操作 | [authorization-domain.md](references/authorization-domain.md) | 6,838 |
| 支付、订单、余额、价格篡改 | [financial-domain.md](references/financial-domain.md) | 2,919 |
| 个人信息泄露、凭证泄露、调试信息 | [information-domain.md](references/information-domain.md) | 6,446 |
| 状态机滥用、竞态条件、流程绕过 | [logic-flow-domain.md](references/logic-flow-domain.md) | 1,679 |
| 配置不当、默认设置、加固缺陷 | [configuration-domain.md](references/configuration-domain.md) | 1,796 |

**第二层：深度分析手册（技术细节 + 根因分析）** — 需要深入某个技术领域时加载

| 技术领域 | 知识文件 | 内容 |
|---------|---------|------|
| 命令执行 | [command-execution.md](../../knowledge/command-execution.md) | 系统命令注入、代码注入、表达式注入的完整攻击链 |
| 文件遍历 | [file-traversal.md](../../knowledge/file-traversal.md) | 路径穿越、任意文件读取/下载的绕过技术 |
| 文件上传 | [file-upload.md](../../knowledge/file-upload.md) | 上传绕过（类型、后缀、内容检测）的 Payload 矩阵 |
| 信息泄露 | [info-disclosure.md](../../knowledge/info-disclosure.md) | 敏感信息暴露路径、调试接口、配置文件泄露 |
| 逻辑缺陷 | [logic-flaws.md](../../knowledge/logic-flaws.md) | 密码重置、支付绕过、验证码绕过的根因矩阵 |
| SQL 注入 | [sql-injection.md](../../knowledge/sql-injection.md) | 注入类型分类、WAF 绕过、盲注技巧 |
| 未授权访问 | [unauthorized-access.md](../../knowledge/unauthorized-access.md) | 未授权接口发现、权限校验缺失模式 |
| XSS | [xss.md](../../knowledge/xss.md) | 存储型/反射型/DOM XSS 的输入点和绕过 |

**第三层：漏洞案例库（真实案例标题 + 高频 Payload）** — 需要引用具体案例或 Payload 模式时加载

| 漏洞类型 | 案例文件 | 用途 |
|---------|---------|------|
| SQL 注入 | [sql-injection.md](../../categories/sql-injection.md) | 15 个典型案例 + 高频注入 Payload |
| 命令执行 | [command-execution.md](../../categories/command-execution.md) | 15 个典型案例 + 命令执行 Payload |
| 未授权访问 | [unauthorized-access.md](../../categories/unauthorized-access.md) | 15 个典型案例 + 越权模式 |
| 弱口令 | [weak-password.md](../../categories/weak-password.md) | 15 个典型案例 + 高频弱口令 |
| 信息泄露 | [info-disclosure.md](../../categories/info-disclosure.md) | 15 个典型案例 + 泄露路径 |
| XSS | [xss.md](../../categories/xss.md) | 9 个典型案例 + XSS Payload |
| 配置不当 | [misconfig.md](../../categories/misconfig.md) | 15 个典型案例 + 错误配置模式 |
| 逻辑缺陷 | [logic-flaws.md](../../categories/logic-flaws.md) | 15 个典型案例 + 逻辑绕过 |
| 文件上传 | [file-upload.md](../../categories/file-upload.md) | 11 个典型案例 + 上传绕过 Payload |
| SSRF | [ssrf.md](../../categories/ssrf.md) | SSRF 攻击模式 |
| CSRF | [csrf.md](../../categories/csrf.md) | CSRF 利用模式 |
| 文件遍历 | [file-traversal.md](../../categories/file-traversal.md) | 5 个典型案例 + 遍历 Payload |
| RCE | [rce.md](../../categories/rce.md) | 3 个典型案例 + RCE 链 |
| XXE | [xxe.md](../../categories/xxe.md) | XXE 注入模式 |
| 其他 | [other.md](../../categories/other.md) | 13 个典型案例 |

> **渐进加载规则：** 先读第一层（领域参考）确定测试方向，再按需读第二层（深度分析）获取技术细节，最后在需要引用具体案例或 Payload 时才读第三层（案例库）。不要一次性加载所有文件。

**对每个领域，使用以下结构形成假设：**

```
假设：[业务流程 X] 容易受到 [攻击模式 Y] 的攻击
原因：[来自侦查的证据——参数可见、缺乏服务器验证、ID 可预测]
WooYun 模式：[与领域参考中匹配的模式]
影响：[业务影响——财务损失、数据泄露、账户接管]
测试：[具体的手动测试步骤]
```

### 第三阶段：针对性手动测试

业务逻辑需要手动测试，因为漏洞存在于应用如何解释业务规则的方式中，而不是扫描器可以匹配的技术特征。

1. **准备测试账号**
   - 至少 2 个相同权限级别的账号（用于水平测试）
   - 至少每个权限级别 1 个账号（用于垂直测试）
   - 记录所有会话令牌、Cookie、ID

2. **执行最小化测试**
   - 拦截特定请求（Burp/mitmproxy）
   - 仅修改要测试的参数
   - 观察：服务器是否验证？状态是否改变？
   - 记录确切的请求/响应对

3. **根据业务规则分析**
   - 应用是否在服务器端实施业务规则？
   - 状态转移是否可以被强制无序执行？
   - 是否可以访问/修改另一个用户的资源？
   - 财务价值是否可以被篡改？

4. **如果确认 → 第四阶段** · 如果否定 → 下一个假设 · 如果不确定 → 改变方法

### 第四阶段：影响评估与文档化

证明业务影响，而不仅仅是技术绕过。

```
## 发现：[标题]
- 严重级别：[严重/高/中/低]
- 领域：[认证/授权/金融/信息/逻辑/配置]
- WooYun 模式：[此发现匹配的历史模式]
- 业务影响：[财务损失、受影响用户数、数据范围]
- 重现步骤：
  1. [确切的步骤与请求/响应]
  2. [...]
- 补救：[服务器端修复，不是客户端创可贴]
```

## 真实案例

这些案例说明为什么业务逻辑测试很重要——每一个都代表 WooYun 研究者发现的真实漏洞：

| 案例 | 领域 | 影响 |
|------|------|------|
| 北京现代某平台越权遍历几百万身份证件/行驶证件 | 授权 | 通过顺序文件 ID 泄露数百万身份证件 |
| M1905电影网 2588元套餐漏洞只需5毛 | 金融 | 通过后端自批准绕过实现 5000 倍价格差异 |
| TCL统一认证平台可重置所有用户密码 | 认证 | 跨 N+ 个业务系统的完整账户接管 |
| 微糖主站SQL注入影响860W+患者/46W+医生 | 信息 | 860 万患者记录、46 万医生记录 |
| 中国铁通计费系统GetShell+生成充值卡 | 金融 | 任意充值卡生成 + 客户数据泄露 |
| 百合网某APP设计缺陷影响100W+女性手机号 | 逻辑流 | 100 万+ 电话号码通过设计缺陷泄露 |

## 需要避免的思维陷阱

测试业务逻辑时，要警惕这些导致浅层测试的常见理性化表现：

| 陷阱 | 现实 |
|------|------|
| "扫描器可以覆盖业务逻辑" | 扫描器找到的是特征，不是逻辑漏洞。没有扫描器能发现"订单状态可以跳过支付"。 |
| "我测试了主流程，它是安全的" | 22,132 个案例证明：逻辑漏洞存在于边界情况。 |
| "只需改价格为 0.01" | 那只是一个测试。WooYun 数据显示 17+ 种支付攻击模式。 |
| "IDOR 很简单，只需改 ID" | IDOR 有编码绕过、参数污染、JSON 嵌套。简单改 ID 只占案例的 30%。 |
| "前端验证了，就没问题" | 68.7% 的支付漏洞存在是因为验证仅在客户端。 |
| "管理员面板需要不同的凭证" | 58.2% 的未授权访问 = 完全没有身份验证的管理后台。 |

## 快速参考

| 阶段 | 关键活动 | 门槛标准 |
|------|---------|---------|
| **1. 映射** | 业务流程、状态机、信任边界 | 完整流程图已记录 |
| **2. 假设** | 基于 WooYun 模式的特定领域理论 | ≥5 个按影响排序的假设 |
| **3. 测试** | 手动拦截、单参数、精确观察 | 每个假设有证据支持或反驳 |
| **4. 报告** | 业务影响、重现步骤、补救措施 | 带有 WooYun 模式分类的发现 |

<!-- 数据源：WooYun 漏洞数据库（2016年7月）· 方法论 v2.0 -->
