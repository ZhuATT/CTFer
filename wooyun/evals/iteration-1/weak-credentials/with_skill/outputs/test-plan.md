# 政府内部管理系统弱口令与默认口令专项检测方案

> 基于 WooYun 22,132 个真实漏洞案例 | 认证领域 8,846 例 | 配置领域 1,796 例

---

## 一、项目背景与检测范围

### 1.1 背景

政府内部管理系统（OA、邮件、VPN、堡垒机、数据库管理等）由不同厂商在不同年代部署，存在以下系统性风险：

- 厂商交付时使用默认凭证，运维人员未修改
- 历史遗留系统缺乏密码策略强制执行
- 多系统独立认证，缺乏统一身份管理
- 运维人员为便利设置弱口令

### 1.2 WooYun 数据支撑

| 指标 | 数据 |
|------|------|
| 弱口令/默认口令案例总数 | **7,513 例**（占 WooYun 全部案例的 **34%**） |
| 弱口令案例中高危占比 | **58.2%** |
| 配置不当（含默认凭证）案例 | **1,796 例**，高危占比 **72.6%** |
| 认证领域总案例 | **8,846 例**（占所有发现的 40%） |

**核心结论：** WooYun 数据集中超过三分之一的漏洞归因于弱密码或默认密码。这不是边缘问题，而是最普遍的安全风险。

### 1.3 检测范围

| 系统类别 | 典型目标 | 风险等级 |
|---------|---------|---------|
| OA 系统 | 致远 OA、泛微 OA、通达 OA、万户 OA、蓝凌 OA | 高 |
| 邮件系统 | Coremail、Exchange、Zimbra、Postfix+Roundcube | 高 |
| VPN 网关 | 深信服 VPN、Array VPN、Pulse Secure、OpenVPN | 严重 |
| 堡垒机 | 齐治堡垒机、JumpServer、行云管家 | 严重 |
| 数据库管理 | phpMyAdmin、Navicat Web、DBeaver、数据库直连 | 严重 |
| 运维监控 | Zabbix、Grafana、Nagios、Prometheus | 高 |
| 中间件管理 | Tomcat Manager、WebLogic Console、JBoss | 高 |
| 网络设备 | 路由器、交换机、防火墙 Web 管理界面 | 高 |

---

## 二、默认口令字典来源与构建

### 2.1 WooYun 高频默认凭证数据库

以下数据直接来自 WooYun 1,796 个配置不当案例的统计分析：

| 服务/系统 | 默认凭证 | WooYun 出现频率 |
|-----------|---------|--------------|
| Tomcat Manager | tomcat/tomcat, admin/admin | 极高 |
| JBoss 控制台 | admin/admin, jboss/jboss | 极高 |
| WebLogic | weblogic/weblogic1 | 高 |
| Jenkins | （默认无认证） | 极高 |
| Zabbix | Admin/zabbix | 高 |
| phpMyAdmin | root/（空密码） | 极高 |
| MongoDB | （默认无认证） | 高 |
| Redis | （默认无认证） | 极高 |
| Elasticsearch | （默认无认证） | 高 |
| Docker Remote API | （默认无认证） | 高 |
| Grafana | admin/admin | 高 |
| RabbitMQ | guest/guest | 高 |
| ActiveMQ | admin/admin | 高 |
| Nacos | nacos/nacos | 高 |
| Spring Boot Actuator | （默认无认证） | 极高 |
| Hadoop YARN | （默认无认证） | 高 |

### 2.2 政府/企业场景专用字典构建策略

根据 WooYun 认证领域方法论，字典构建需覆盖四个阶段：

#### 阶段 1：厂商默认凭证

```
# OA 系统
system/system, admin/admin, audit/audit
致远: seeyon/seeyon1, A8/seeyon123456, yyoa/seeyon
泛微: sysadmin/1, admin/weaver@2001
通达: admin/（空密码）, admin/td3200

# 邮件系统
Coremail: admin/coremail, admin/admin
Exchange: administrator/P@ssw0rd
Zimbra: admin/zimbra

# VPN
深信服: admin/admin, dlanrecover/（空密码）
Array: admin/admin, array/admin

# 堡垒机
齐治: admin/admin, shterm/shterm
JumpServer: admin/admin, admin/ChangeMe

# 数据库管理工具
phpMyAdmin: root/（空密码）, root/root, root/123456

# 网络设备
H3C: admin/admin, admin/h3capadmin
华为: admin/Admin@123, admin/admin
锐捷: admin/admin, admin/ruijie
思科: cisco/cisco, admin/admin
```

#### 阶段 2：社会工程学密码（政府场景特化）

```
# 组织相关
[单位简称]@123, [单位简称]123, [单位简称]2024, [单位简称]2025
[城市拼音]@123, [城市拼音]2024
gov123, gov@123, gov123456

# 运维习惯
P@ssw0rd, p@ssword, Passw0rd!, Admin@123, Admin123!
qwer1234, 1qaz2wsx, 1qaz@WSX, !QAZ2wsx
root123, root@123, test123, test@123

# 手机号模式（中国系统极为常见）
1[3-9]xxxxxxxxx（11位手机号直接作为密码）
```

#### 阶段 3：中国 Top 100 弱口令

```
123456, a123456, 123456789, password, 12345678
111111, 123123, abc123, 1234567, 000000
a123456789, 1234567890, woaini1314, qq123456, abc123456
iloveyou, 123321, qwerty, 147258369, 123456a
a12345678, 987654321, zxcvbnm, asd123456, aa123456
q123456, 1q2w3e4r, 123456abc, abcd1234, 110110
woaini, 11111111, 5201314, aini1314, wang1234
...
```

#### 阶段 4：行业特定默认密码

```
# 政务行业
zwfw@123（政务服务）, egov123, digital@gov
oa123456, oa@123, mail@123

# 医疗行业（如涉及卫健委系统）
his@123, pacs@123, lis@123

# 教育行业（如涉及教育局系统）
edu@123, school@123
```

### 2.3 字典来源汇总

| 来源 | 说明 | 获取方式 |
|------|------|---------|
| WooYun 漏洞库统计 | 7,513 个弱口令案例提炼的高频密码 | 本方案已内置 |
| SecLists (Daniel Miessler) | 全球最全的安全测试字典集合 | `github.com/danielmiessler/SecLists/Passwords/` |
| 弱口令实验室（weakpass.com） | 多国语言弱口令库，含中文特化 | weakpass.com |
| DefaultCreds-cheat-sheet | 厂商默认凭证速查表 | `github.com/ihebski/DefaultCreds-cheat-sheet` |
| CISA Known Default Credentials | 美国 CISA 维护的已知默认凭证列表 | cisa.gov |
| 厂商官方文档 | 每个目标系统的安装手册/运维手册 | 逐一查阅 |
| Changeme | 默认凭证自动检测工具内置库 | `github.com/ztgrace/changeme` |
| 国内安全社区积累 | 先知、补天、CNVD 历史漏洞中的默认口令 | 手动整理 |

---

## 三、检测工具矩阵

### 3.1 核心工具

| 工具 | 用途 | 适用场景 | 备注 |
|------|------|---------|------|
| **Hydra** | 多协议在线口令爆破 | SSH、FTP、RDP、HTTP-Form、SMTP、POP3、IMAP、MySQL、MSSQL、VNC | 支持 50+ 协议，政府场景首选 |
| **Medusa** | 并行在线口令爆破 | 与 Hydra 类似，稳定性更好 | 模块化设计，适合长时间运行 |
| **Ncrack** | 高速网络认证破解 | SSH、RDP、FTP、Telnet、HTTP(S) | Nmap 团队出品，与 Nmap 联动好 |
| **Burp Suite** | Web 表单口令爆破 | OA、邮件 Webmail、管理后台 | Intruder 模块，处理 CSRF Token/验证码场景 |
| **超级弱口令检测工具** | Windows 图形化弱口令检测 | 综合场景，操作简单 | 国产工具，支持多协议，界面友好 |
| **fscan** | 内网综合扫描+弱口令检测 | 内网快速扫描 | 国产工具，一键扫描常见服务弱口令 |
| **Nmap NSE Scripts** | 服务发现+默认口令检测 | 大范围资产识别 | `--script=default-credentials,brute` |

### 3.2 专项工具

| 工具 | 专项用途 |
|------|---------|
| **SNETCracker** | 超级弱口令检查工具，支持 SSH/RDP/MySQL/MSSQL/FTP 等 |
| **DefaultCreds-cheat-sheet + changeme** | 自动匹配服务指纹并尝试默认凭证 |
| **CrackMapExec (NetExec)** | Windows 域环境 SMB/WinRM/LDAP/MSSQL 弱口令 |
| **Patator** | 模块化爆破框架，支持自定义协议和复杂认证流程 |
| **John the Ripper / Hashcat** | 离线密码哈希破解（获取到数据库/配置文件后） |
| **RouterSploit** | 路由器/IoT 设备默认口令检测 |
| **ssh-audit** | SSH 服务配置审计（含弱密码策略检查） |

### 3.3 辅助工具

| 工具 | 用途 |
|------|------|
| **Nmap** | 资产发现、端口扫描、服务指纹识别 |
| **Masscan** | 大规模端口快速扫描 |
| **EHole (棱洞)** | 红队资产指纹识别，快速定位 OA/VPN/堡垒机 |
| **Goby** | 资产测绘+漏洞扫描+弱口令检测一体化 |

---

## 四、检测流程

### 4.1 四阶段检测流程

```
阶段 1：资产测绘与服务识别
    │
    ├── Nmap/Masscan 全端口扫描 → 识别所有开放服务
    ├── EHole/Goby 指纹识别 → 定位 OA/VPN/堡垒机/数据库管理等系统
    ├── 手动确认管理界面 URL 和登录入口
    └── 输出：《资产清单与服务列表》
    │
阶段 2：默认凭证检测（零风险，优先执行）
    │
    ├── 按 WooYun 高频默认凭证列表逐一尝试
    ├── 检查无认证暴露的管理界面（Jenkins、Redis、MongoDB、ES、Spring Actuator 等）
    ├── 检查空密码/匿名访问
    └── 输出：《默认凭证发现清单》
    │
阶段 3：弱口令爆破（需授权，控制频率）
    │
    ├── 构建针对性字典（组织名、域名、运维习惯）
    ├── Web 系统：Burp Suite Intruder（处理验证码/CSRF）
    ├── 网络服务：Hydra/Medusa（SSH、RDP、FTP、数据库）
    ├── 域环境：CrackMapExec（SMB/LDAP）
    ├── 严格控制：线程数 ≤ 5，请求间隔 ≥ 1s，避免锁定账户
    └── 输出：《弱口令发现清单》
    │
阶段 4：密码策略审计
    │
    ├── 检查各系统密码复杂度策略配置
    ├── 检查账户锁定策略
    ├── 检查密码有效期策略
    ├── 检查默认密码强制修改机制
    └── 输出：《密码策略审计报告》
```

### 4.2 WooYun 案例参考：验证码/防暴力破解绕过

在阶段 3 中，若遇到验证码或账户锁定机制，参考 WooYun 384 个验证码绕过案例：

| 绕过技术 | 测试方法 | 成功率 |
|---------|---------|--------|
| 移除验证码参数 | 从请求中删除 captcha/verifycode 字段 | 高 |
| 验证码重用 | 同一会话中多次提交同一验证码值 | 极高 |
| IP 轮换绕过锁定 | 修改 X-Forwarded-For / X-Real-IP 头 | 中等 |
| 客户端验证码校验 | 验证码仅在 JavaScript 中验证，后端不校验 | 高 |
| 短信验证码无过期 | 旧验证码长时间有效，可暴力破解 | 中等 |

---

## 五、自动化脚本思路

### 5.1 总体架构

```
weak-cred-scanner/
├── config/
│   ├── targets.yaml          # 目标资产清单
│   ├── credentials/
│   │   ├── default_creds.yaml    # 按服务分类的默认凭证
│   │   ├── weak_passwords.txt    # 通用弱口令字典
│   │   ├── gov_passwords.txt     # 政府场景特化字典
│   │   └── custom_passwords.txt  # 项目定制字典
│   └── settings.yaml         # 全局配置（线程、间隔、超时）
├── scanners/
│   ├── web_form_scanner.py   # Web 表单登录检测
│   ├── service_scanner.py    # 网络服务弱口令检测（调用 Hydra）
│   ├── db_scanner.py         # 数据库默认口令检测
│   ├── noauth_scanner.py     # 无认证服务检测
│   └── device_scanner.py     # 网络设备默认口令检测
├── utils/
│   ├── fingerprint.py        # 服务指纹识别
│   ├── dict_generator.py     # 动态字典生成器
│   ├── rate_limiter.py       # 请求频率控制
│   └── reporter.py           # 报告生成器
├── reports/
│   └── (自动生成)
└── main.py                   # 主入口
```

### 5.2 核心模块伪代码

#### 主调度器

```python
# main.py - 主调度逻辑
def main():
    # 1. 加载目标资产
    targets = load_targets("config/targets.yaml")

    # 2. 服务指纹识别（调用 Nmap）
    for target in targets:
        target.services = fingerprint(target.ip, target.ports)

    # 3. 按服务类型分派检测器
    findings = []
    for target in targets:
        for service in target.services:
            # 阶段 2：默认凭证（优先）
            creds = get_default_creds(service.name, service.version)
            result = try_default_creds(target, service, creds)
            if result.success:
                findings.append(result)
                continue  # 已发现默认口令，无需继续爆破

            # 无认证检测
            if service.name in NO_AUTH_SERVICES:
                result = check_no_auth(target, service)
                if result.success:
                    findings.append(result)
                    continue

            # 阶段 3：弱口令检测（受控）
            passwords = generate_dict(target, service)
            result = brute_force(target, service, passwords,
                                 threads=3, delay=1.0, max_attempts=50)
            findings.extend(result)

    # 4. 生成报告
    generate_report(findings, template="gov_audit")
```

#### 动态字典生成器

```python
# utils/dict_generator.py
def generate_dict(target, service):
    """根据目标信息动态生成针对性字典"""
    passwords = set()

    # 基础弱口令
    passwords.update(load_file("config/credentials/weak_passwords.txt"))

    # 厂商默认凭证
    vendor_creds = VENDOR_DEFAULT_CREDS.get(service.fingerprint, [])
    passwords.update(vendor_creds)

    # 社会工程学密码（基于目标组织信息）
    org_name = target.organization  # 如 "某某市住建局"
    pinyin = to_pinyin(org_name)    # zjj, zhujj, zhujjj
    for suffix in ["123", "@123", "2024", "2025", "!@#", "888"]:
        passwords.add(f"{pinyin}{suffix}")

    # 域名衍生
    if target.domain:
        base = target.domain.split(".")[0]
        for suffix in ["123", "@123", "Admin", "admin"]:
            passwords.add(f"{base}{suffix}")

    # 手机号模式（仅用于已知用户名场景）
    # 不生成，但在字典中包含常见手机号前缀模式

    return list(passwords)
```

#### Web 表单检测器

```python
# scanners/web_form_scanner.py
def scan_web_form(target_url, usernames, passwords):
    """
    处理 Web 登录表单的弱口令检测
    - 自动识别登录表单字段
    - 处理 CSRF Token
    - 处理验证码（尝试绕过）
    - 基于响应差异判断成功/失败
    """
    session = requests.Session()

    # 1. 获取登录页面，提取表单结构
    form = parse_login_form(session.get(target_url))

    # 2. 检测验证码
    if form.has_captcha:
        # 尝试绕过：移除验证码参数
        bypass_result = try_without_captcha(session, form, "admin", "admin")
        if bypass_result.captcha_required:
            # 尝试绕过：重用验证码
            bypass_result = try_reuse_captcha(session, form, "admin", "admin")
            if bypass_result.captcha_required:
                log.warning(f"[{target_url}] 验证码无法绕过，需手动测试")
                return []

    # 3. 基线：记录失败登录的响应特征
    baseline = login_attempt(session, form, "nonexist_user_xyzzy", "wrong_pass")

    # 4. 遍历凭证组合
    findings = []
    for username in usernames:
        for password in passwords:
            resp = login_attempt(session, form, username, password)
            if is_success(resp, baseline):
                findings.append(Finding(
                    target=target_url, username=username,
                    password=password, severity="CRITICAL"
                ))
                break  # 该用户已发现弱口令，跳到下一个
            rate_limit_wait()  # 频率控制

    return findings
```

#### 无认证服务检测器

```python
# scanners/noauth_scanner.py
# 基于 WooYun 配置域数据：这些服务默认无认证，出现频率极高

NO_AUTH_CHECKS = {
    "redis":         {"port": 6379, "probe": "INFO\r\n", "match": "redis_version"},
    "mongodb":       {"port": 27017, "probe": None, "method": "pymongo_connect"},
    "elasticsearch": {"port": 9200, "probe": "GET /", "match": '"cluster_name"'},
    "jenkins":       {"port": 8080, "probe": "GET /", "match": "Dashboard [Jenkins]"},
    "docker_api":    {"port": 2375, "probe": "GET /version", "match": '"ApiVersion"'},
    "spring_actuator": {"port": 8080, "probe": "GET /actuator", "match": '"_links"'},
    "hadoop_yarn":   {"port": 8088, "probe": "GET /ws/v1/cluster", "match": '"clusterInfo"'},
}

def check_no_auth(target, service):
    """检测服务是否存在未授权访问"""
    check = NO_AUTH_CHECKS.get(service.name)
    if not check:
        return None

    try:
        response = probe_service(target.ip, check["port"], check["probe"])
        if check["match"] in response:
            return Finding(
                target=f"{target.ip}:{check['port']}",
                service=service.name,
                issue="未授权访问（无需任何凭证）",
                severity="CRITICAL",
                wooyun_ref="配置域 - 默认无认证服务"
            )
    except Exception:
        pass
    return None
```

### 5.3 安全控制要点

```yaml
# config/settings.yaml
safety:
  max_threads: 3                # 单目标最大并发线程
  request_delay_ms: 1000        # 请求间隔（毫秒）
  max_attempts_per_user: 50     # 单用户最大尝试次数（防锁定）
  lockout_detection: true       # 检测到锁定立即停止
  lockout_indicators:           # 锁定特征关键词
    - "账号已锁定"
    - "account locked"
    - "too many attempts"
    - "请稍后再试"
  whitelist_hours: "09:00-17:00"  # 仅在工作时间检测
  notification_on_critical: true  # 发现严重问题立即通知
```

---

## 六、WooYun 典型案例参考

### 6.1 政府/企事业单位弱口令案例

以下案例来自 WooYun 数据库，展示弱口令在真实攻击中的严重后果：

| 案例 | 漏洞类型 | 影响 | 教训 |
|------|---------|------|------|
| 云南农村信用社智慧农信微信管理平台 | 默认凭证 | 银行平台被完全控制 | 金融系统使用默认口令 |
| 华夏航空准备网 | 默认凭证 | 航空安全系统沦陷 | 关键基础设施默认口令 |
| ChinaCache 某系统 JBoss 配置不当导致 Getshell | 默认凭证+暴露管理界面 | JBoss 管理控制台被利用，获得服务器权限 | 中间件默认口令 |
| DaoCloud 弱口令+Docker Remote API 未授权 | 弱口令+无认证 | 容器逃逸，主机被控 | 运维工具弱口令链式利用 |
| 飞特物流某系统后台登录绕过 | 弱口令+SQL注入 | 1000万+用户、银行卡、身份证照片泄露 | 弱口令作为突破口进一步渗透 |
| 复星保德信某系统配置不当 GetShell | 配置不当+默认凭证 | 大量保险保单信息泄露（姓名/身份证/地址） | 保险行业默认配置 |
| 同程旅游某系统配置不当任意文件上传 getshell | 配置不当 | 通过文件上传获得 root 权限 | 管理后台弱口令进入后上传 WebShell |

### 6.2 关键统计

- **WooYun 弱口令 Top 3 受灾行业：** 政府/事业单位、教育、医疗
- **默认口令存活率：** 在 WooYun 配置域 1,796 个案例中，超过 60% 的系统使用厂商出厂默认凭证
- **攻击链放大效应：** 弱口令本身危害可能为"高"，但作为攻击链入口（弱口令 → 后台 → 上传 WebShell → 服务器权限 → 内网渗透），最终危害通常为"严重"
- **WooYun 铁律：** "在任何其他身份认证测试之前，先测试默认凭证。WooYun 所有案例中 34% 属于弱密码/默认密码。"

---

## 七、检测报告模板

### 7.1 封面

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           XX 市 XX 局内部管理系统                              ║
║         弱口令与默认口令专项安全检测报告                          ║
║                                                              ║
║  项目编号：XXXX-XXXX-XXX                                      ║
║  检测单位：XXXXXXXXXX                                         ║
║  报告日期：2026 年 XX 月 XX 日                                 ║
║  密级标识：【机密】                                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

### 7.2 报告正文结构

```
1. 概述
   1.1 项目背景
   1.2 检测范围
   1.3 检测依据（GB/T 22239 等保、GB/T 28448 测评要求）
   1.4 检测时间与方式
   1.5 检测团队

2. 检测方法
   2.1 资产识别方法
   2.2 默认口令检测方法
   2.3 弱口令检测方法
   2.4 密码策略审计方法
   2.5 工具与字典说明

3. 检测结果汇总
   3.1 统计概览（饼图/柱状图）
       - 发现弱口令/默认口令总数
       - 按系统类型分布
       - 按严重性分布
       - 按口令类型分布（默认口令 / 弱口令 / 空口令 / 无认证）
   3.2 风险等级分布表

4. 详细发现
   [每个发现使用以下模板]

   ┌────────────────────────────────────────────────────────┐
   │ 发现编号：WC-001                                        │
   │ 严重级别：【严重】/【高】/【中】/【低】                     │
   │ 系统名称：XX OA 系统                                     │
   │ 系统地址：http://10.x.x.x:8080                         │
   │ 发现类型：默认口令 / 弱口令 / 空口令 / 未授权访问            │
   │ 涉及账号：admin                                         │
   │ 口令内容：admin123（脱敏处理：adm***23）                   │
   │ 业务影响：管理员权限，可访问全部 XX 条公文/XX 个用户信息       │
   │ WooYun 历史模式：配置域-默认凭证（WooYun 出现频率：极高）     │
   │ 重现步骤：                                               │
   │   1. 访问 http://10.x.x.x:8080/login                   │
   │   2. 输入用户名 admin，密码 admin123                      │
   │   3. 成功登录管理后台                                      │
   │ 证据截图：[附图编号]                                       │
   │ 修复建议：                                               │
   │   - 立即修改为强密码（≥12位，含大小写+数字+特殊字符）         │
   │   - 启用首次登录强制改密                                    │
   │   - 配置账户锁定策略（5次失败后锁定15分钟）                   │
   │   - 部署多因素认证（MFA）                                  │
   └────────────────────────────────────────────────────────┘

5. 密码策略审计结果
   5.1 各系统密码策略配置对比表
   5.2 与等保 2.0 要求的差距分析

6. 风险分析
   6.1 弱口令作为攻击链入口的风险（参考 WooYun 案例）
   6.2 内网横向移动风险
   6.3 数据泄露风险评估

7. 整改建议
   7.1 紧急措施（24小时内）
       - 立即修改所有已发现的默认口令和弱口令
       - 关闭或限制无认证暴露的管理界面
   7.2 短期措施（1周内）
       - 全系统强制密码复杂度策略
       - 配置账户锁定与登录失败告警
       - 管理界面限制为内网/VPN 访问
   7.3 中期措施（1个月内）
       - 部署统一身份认证（SSO）
       - 关键系统启用多因素认证
       - 建立定期弱口令扫描机制
   7.4 长期措施（持续）
       - 密码策略纳入安全基线
       - 新系统上线前强制默认口令检测
       - 定期安全意识培训

8. 附录
   8.1 检测工具清单
   8.2 检测字典说明
   8.3 证据截图（脱敏）
   8.4 等保 2.0 身份鉴别相关条款对照
```

### 7.3 严重性定级标准

| 级别 | 定义 | 弱口令场景示例 |
|------|------|-------------|
| **严重** | 可直接导致核心系统沦陷或大规模数据泄露 | 堡垒机/VPN/域控默认口令、数据库 root 空密码 |
| **高** | 可获取敏感数据或重要系统管理权限 | OA 管理员弱口令、邮件系统默认口令 |
| **中** | 可获取部分系统功能或非敏感数据 | 监控系统弱口令、普通用户弱口令 |
| **低** | 影响有限，但违反安全最佳实践 | 测试环境弱口令、非生产系统默认口令 |

---

## 八、合规对照

### 8.1 等保 2.0（GB/T 22239-2019）身份鉴别要求

| 等保条款 | 要求 | 检测关联 |
|---------|------|---------|
| 8.1.4.1 a) | 对登录的用户进行身份标识和鉴别 | 检测无认证暴露的管理界面 |
| 8.1.4.1 b) | 身份标识具有唯一性 | 检测共享账号/通用账号 |
| 8.1.4.1 c) | 具有登录失败处理功能 | 检测账户锁定策略是否生效 |
| 8.1.4.1 d) | 远程管理时防窃听 | 检测明文传输凭证的系统 |
| 8.1.4.1 e) | 口令复杂度要求 | 检测密码策略配置 |
| 8.1.4.1 f) | 初始口令/默认口令强制修改 | 检测默认口令存活情况 |

---

## 九、注意事项

### 9.1 法律合规

- **必须持有甲方签署的书面授权书**，明确检测范围、时间、方式
- 检测过程中发现的所有凭证信息需严格保密
- 报告中口令内容必须脱敏处理
- 检测完成后删除本地存储的所有凭证信息

### 9.2 安全控制

- 在非业务高峰期（如夜间或周末）执行爆破类检测
- 严格控制并发数和请求频率，避免触发账户锁定
- 实时监控目标系统运行状态，发现异常立即停止
- 与甲方运维团队保持实时沟通通道
- 对堡垒机、数据库等关键系统采用手动逐一尝试方式，禁止自动化批量爆破

### 9.3 WooYun 方法论提醒

> "在任何其他身份认证测试之前，先测试默认凭证。"
> -- WooYun 认证领域铁律

执行顺序铁律：**默认凭证 → 空口令 → 无认证服务 → 弱口令爆破**。这个顺序基于 WooYun 7,513 个弱口令案例的统计规律：大部分系统在第一步就会被攻破，无需进入爆破阶段。

---

*本方案基于 WooYun 漏洞数据库（2010-2016）22,132 个真实案例，其中认证领域 8,846 例、配置领域 1,796 例。方法论版本 v2.0。*
