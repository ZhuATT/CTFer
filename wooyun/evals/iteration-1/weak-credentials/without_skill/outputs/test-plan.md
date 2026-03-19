# 政府内部系统弱口令与默认口令专项检测方案

## 一、项目概述

### 1.1 检测目标

针对政府单位内部管理系统进行弱口令与默认口令专项安全评估，覆盖以下系统类型：

| 系统类型 | 典型产品 | 风险等级 |
|---------|---------|---------|
| OA 办公系统 | 致远 A6/A8、泛微 E-Cology、通达 OA、华天动力、蓝凌 | 高 |
| 邮件系统 | Coremail、Exchange、Zimbra、Winmail | 高 |
| VPN 网关 | 深信服 SSL VPN、Sangfor VPN、华为 USG、锐捷 | 极高 |
| 堡垒机 | 齐治、JumpServer、帕拉迪、绿盟 | 极高 |
| 数据库管理 | phpMyAdmin、Navicat Web、DBeaver、DBMS 自带管理口 | 极高 |
| 网络设备 | 交换机、路由器、防火墙管理口 | 高 |
| 中间件/运维 | Tomcat Manager、WebLogic Console、Zabbix、Grafana | 高 |

### 1.2 检测范围与授权

- **必须获取**：甲方书面授权书（盖章）、IP/URL 资产清单、检测时间窗口确认
- **检测约束**：仅在授权范围内进行，不进行暴力破解（仅测试弱口令/默认口令组合），不造成业务中断
- **锁定策略**：检测前确认各系统账号锁定策略，控制尝试次数，避免触发锁定

---

## 二、默认口令字典来源

### 2.1 公开字典资源

| 来源 | 地址/路径 | 说明 |
|------|----------|------|
| **SecLists** | `github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials` | 业界最全默认凭据集，含路由器、摄像头、Web 应用等 |
| **DefaultCreds-cheat-sheet** | `github.com/ihebski/DefaultCreds-cheat-sheet` | 按厂商/产品分类的默认口令速查表，含 Python 查询工具 |
| **CISA Known Default Passwords** | CISA 官方发布 | 美国网络安全局维护的已知默认口令列表 |
| **RouterPasswords** | `routerpasswords.com` | 网络设备默认口令数据库 |
| **Kali 自带字典** | `/usr/share/wordlists/` | 含 `rockyou.txt`、`common-passwords.txt` 等 |
| **fuzzdb** | `github.com/fuzzdb-project/fuzzdb/tree/master/wordlists-user-passwd` | 渗透测试用弱口令字典 |
| **WooYun 历史漏洞库** | 乌云镜像/本地存档 | 大量国产系统默认口令实际案例 |

### 2.2 国产系统专用默认口令整理

需要针对政府常用产品手工整理，以下为高频默认口令：

#### OA 系统

```
# 致远 OA (Seeyon)
system / system
audit-admin / seeyon123456
group-admin / 123456
seeyon / 123456
A8 / seeyon

# 泛微 OA (E-Cology)
sysadmin / 1
admin / admin
SecurityAdmin / SecurityAdmin@123

# 通达 OA
admin / (空密码)
admin / admin00

# 蓝凌 OA
admin / admin
```

#### VPN 设备

```
# 深信服 SSL VPN
admin / admin
Admin / Admin123

# 华为 USG 防火墙
admin / Admin@123
admin / Huawei@123

# 锐捷设备
admin / admin
admin / ruijie
```

#### 堡垒机

```
# 齐治堡垒机
admin / admin123
shterm / shterm

# JumpServer
admin / admin
admin / ChangeMe

# 帕拉迪堡垒机
admin / admin
```

#### 数据库

```
# MySQL
root / (空密码)
root / root
root / 123456
root / mysql

# SQL Server
sa / (空密码)
sa / sa
sa / 123456

# Oracle
sys / change_on_install
system / manager
scott / tiger

# PostgreSQL
postgres / postgres
postgres / 123456

# Redis
(无认证)
(密码) 123456 / redis / foobared
```

#### 中间件与运维工具

```
# Tomcat Manager
tomcat / tomcat
admin / admin
manager / manager

# WebLogic
weblogic / weblogic
weblogic / weblogic123

# Zabbix
Admin / zabbix

# Grafana
admin / admin
```

#### 网络设备通用

```
admin / admin
admin / 123456
admin / password
cisco / cisco
enable / (空)
```

### 2.3 自建字典策略

除默认口令外，还需检测以下弱口令模式：

1. **Top 弱口令**：`123456`、`admin`、`password`、`12345678`、`abc123`、`000000`、`1qaz2wsx`、`qwerty`
2. **单位相关**：单位名拼音 + 常见后缀（如 `zwfwzx@123`、`govunit2024`）
3. **用户名=密码**：`zhangsan/zhangsan`、`admin/admin`
4. **用户名+简单变换**：`zhangsan123`、`zhangsan@123`、`Zhangsan1!`
5. **年份/季度组合**：`Unit@2025`、`Admin2025!`、`P@ssw0rd2025`
6. **键盘序列**：`1qaz2wsx`、`qwer1234`、`!QAZ2wsx`
7. **手机号码**：常见 11 位手机号（如果能获取用户手机号列表）

---

## 三、检测工具矩阵

### 3.1 核心工具

| 工具 | 用途 | 协议/场景 | 备注 |
|------|------|----------|------|
| **Hydra** | 网络服务暴力检测 | SSH, FTP, RDP, SMB, MySQL, MSSQL, POP3, IMAP, HTTP-Form, VNC 等 | 支持并发控制、代理 |
| **Medusa** | 并行网络登录检测 | SSH, FTP, HTTP, MySQL, MSSQL, SMB, VNC 等 | 模块化，线程稳定 |
| **Ncrack** | 高速网络认证破解 | SSH, RDP, FTP, HTTP, Telnet 等 | Nmap 团队出品 |
| **CrackMapExec (NetExec)** | Windows/AD 域环境 | SMB, WinRM, MSSQL, LDAP, RDP | 检测域弱口令首选 |
| **超级弱口令检查工具** | 国产图形化工具 | SSH, RDP, MySQL, MSSQL, FTP, SMB 等 | 中文界面，适合国内环境 |
| **Fscan** | 内网综合扫描 | 端口扫描 + 弱口令检测一体化 | Go 编写，单文件，内网神器 |
| **SNETCracker** | 国产弱口令审计 | SSH, RDP, MySQL, FTP, SMB, Redis, MongoDB 等 | Windows GUI，操作简便 |

### 3.2 Web 应用专用

| 工具 | 用途 |
|------|------|
| **Burp Suite (Intruder)** | HTTP 表单弱口令检测，支持 Cookie/Token 处理 |
| **PKAV HTTP Fuzzer** | 国产 HTTP 弱口令工具，支持验证码识别接口 |
| **自定义 Python 脚本** | 针对特定 OA/VPN 登录接口编写（见第四节） |

### 3.3 数据库专用

| 工具 | 用途 |
|------|------|
| **DBPwAudit** | 数据库口令审计（MySQL, MSSQL, Oracle） |
| **odat** | Oracle 数据库攻击工具，含默认口令检测模块 |
| **redis-cli** | Redis 未授权访问及弱口令检测 |

### 3.4 辅助工具

| 工具 | 用途 |
|------|------|
| **Nmap** | 端口发现与服务识别（前置步骤） |
| **Masscan** | 大规模端口快速扫描 |
| **EHole (棱洞)** | 指纹识别，快速识别资产对应的产品/厂商 |
| **TideFinger** | 国产 Web 指纹识别 |

---

## 四、自动化脚本思路

### 4.1 整体架构

```
┌─────────────────────────────────────────────┐
│              弱口令检测自动化框架              │
├─────────────┬───────────┬───────────────────┤
│  Phase 1    │  Phase 2  │     Phase 3       │
│  资产发现    │  指纹识别  │   弱口令检测       │
│  Nmap/      │  EHole/   │   Hydra/自定义     │
│  Masscan    │  指纹库   │   脚本/Fscan      │
├─────────────┴───────────┴───────────────────┤
│              Phase 4: 结果汇总与报告生成       │
└─────────────────────────────────────────────┘
```

### 4.2 Phase 1：资产发现与端口扫描

```python
#!/usr/bin/env python3
"""
Phase 1: 基于授权 IP 列表进行端口扫描，识别开放服务
"""
import subprocess
import json
import csv

def scan_targets(ip_file, output_dir):
    """
    对授权 IP 列表执行端口扫描
    """
    # 常见管理服务端口
    target_ports = [
        22,     # SSH
        23,     # Telnet
        80,     # HTTP
        443,    # HTTPS
        1433,   # MSSQL
        1521,   # Oracle
        3306,   # MySQL
        3389,   # RDP
        5432,   # PostgreSQL
        5900,   # VNC
        6379,   # Redis
        8080,   # HTTP-Alt / Tomcat
        8443,   # HTTPS-Alt
        8888,   # 管理口常见端口
        9090,   # WebLogic / 管理控制台
        27017,  # MongoDB
    ]
    ports_str = ",".join(str(p) for p in target_ports)

    cmd = [
        "nmap", "-sV", "-sC",
        "-p", ports_str,
        "-iL", ip_file,
        "-oA", f"{output_dir}/scan_result",
        "--open",
        "-T3",  # 控制扫描速度，避免影响业务
    ]
    subprocess.run(cmd, check=True)

def parse_nmap_results(xml_file):
    """
    解析 Nmap XML 输出，提取 IP:Port:Service 映射
    返回: [{"ip": "x.x.x.x", "port": 22, "service": "ssh", "product": "OpenSSH"}, ...]
    """
    import xml.etree.ElementTree as ET
    tree = ET.parse(xml_file)
    results = []
    for host in tree.findall(".//host"):
        ip = host.find(".//address[@addrtype='ipv4']").get("addr")
        for port in host.findall(".//port"):
            state = port.find("state").get("state")
            if state == "open":
                service = port.find("service")
                results.append({
                    "ip": ip,
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "product": service.get("product", "") if service is not None else "",
                })
    return results
```

### 4.3 Phase 2：指纹识别与字典匹配

```python
#!/usr/bin/env python3
"""
Phase 2: 根据服务指纹匹配对应的默认口令字典
"""

# 服务→字典映射规则
SERVICE_DICT_MAP = {
    "ssh":       ["dict/ssh_default.txt", "dict/common_weak.txt"],
    "ftp":       ["dict/ftp_default.txt", "dict/common_weak.txt"],
    "rdp":       ["dict/rdp_default.txt", "dict/common_weak.txt"],
    "mysql":     ["dict/mysql_default.txt"],
    "mssql":     ["dict/mssql_default.txt"],
    "oracle":    ["dict/oracle_default.txt"],
    "redis":     ["dict/redis_default.txt"],
    "mongodb":   ["dict/mongodb_default.txt"],
    "vnc":       ["dict/vnc_default.txt"],
    "telnet":    ["dict/telnet_default.txt", "dict/network_device_default.txt"],
}

# Web 产品指纹→字典映射
WEB_PRODUCT_DICT_MAP = {
    "seeyon":      "dict/web/seeyon_default.txt",
    "ecology":     "dict/web/weaver_default.txt",
    "tongda":      "dict/web/tongda_default.txt",
    "coremail":    "dict/web/coremail_default.txt",
    "tomcat":      "dict/web/tomcat_default.txt",
    "weblogic":    "dict/web/weblogic_default.txt",
    "zabbix":      "dict/web/zabbix_default.txt",
    "grafana":     "dict/web/grafana_default.txt",
    "jumpserver":  "dict/web/jumpserver_default.txt",
    "sangfor":     "dict/web/sangfor_default.txt",
    "phpmyadmin":  "dict/web/phpmyadmin_default.txt",
}

def match_dict(service_info):
    """
    根据扫描结果匹配合适的字典文件
    """
    service = service_info["service"].lower()
    product = service_info.get("product", "").lower()

    dicts = []

    # 服务级匹配
    if service in SERVICE_DICT_MAP:
        dicts.extend(SERVICE_DICT_MAP[service])

    # Web 产品级匹配（HTTP/HTTPS 服务需要进一步指纹识别）
    if service in ("http", "https", "http-proxy"):
        for keyword, dict_file in WEB_PRODUCT_DICT_MAP.items():
            if keyword in product:
                dicts.append(dict_file)
        if not dicts:
            dicts.append("dict/web/generic_web_default.txt")

    return dicts
```

### 4.4 Phase 3：弱口令检测执行

```python
#!/usr/bin/env python3
"""
Phase 3: 调度弱口令检测任务
"""
import subprocess
import time
import logging

logger = logging.getLogger("weak_pwd_checker")

# 全局速率控制：避免触发账号锁定
MAX_ATTEMPTS_PER_ACCOUNT = 3   # 每账号最大尝试次数
REQUEST_INTERVAL = 2            # 每次尝试间隔（秒）
MAX_THREADS = 4                 # 并发线程数

def check_network_service(target_ip, port, service, user_file, pass_file):
    """
    使用 Hydra 检测网络服务弱口令
    """
    service_map = {
        "ssh": "ssh",
        "ftp": "ftp",
        "rdp": "rdp",
        "mysql": "mysql",
        "mssql": "mssql",
        "vnc": "vnc",
        "telnet": "telnet",
        "smb": "smb",
        "redis": "redis",
    }

    hydra_service = service_map.get(service)
    if not hydra_service:
        logger.warning(f"不支持的服务类型: {service}")
        return None

    cmd = [
        "hydra",
        "-L", user_file,          # 用户名字典
        "-P", pass_file,          # 密码字典
        "-s", str(port),          # 端口
        "-t", str(MAX_THREADS),   # 线程数
        "-W", str(REQUEST_INTERVAL),  # 等待间隔
        "-f",                     # 找到第一个有效凭据即停止
        "-o", f"results/{target_ip}_{port}_{service}.txt",
        f"{target_ip}",
        hydra_service,
    ]

    logger.info(f"检测 {target_ip}:{port} ({service})")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return parse_hydra_output(result.stdout)


def check_web_login(url, product_type, dict_file):
    """
    使用 requests 检测 Web 应用默认口令
    支持处理验证码、CSRF Token 等
    """
    import requests

    results = []
    session = requests.Session()
    session.verify = False

    # 加载字典：格式 username:password
    with open(dict_file) as f:
        creds = [line.strip().split(":", 1) for line in f if ":" in line]

    for username, password in creds:
        try:
            # 1. 获取登录页面（取 CSRF Token / Cookie）
            login_page = session.get(url, timeout=10)

            # 2. 根据产品类型构造登录请求
            login_data = build_login_request(product_type, username, password, login_page)

            # 3. 发送登录请求
            resp = session.post(
                login_data["url"],
                data=login_data["data"],
                headers=login_data.get("headers", {}),
                timeout=10,
                allow_redirects=False,
            )

            # 4. 判断登录结果
            if is_login_success(product_type, resp):
                results.append({
                    "url": url,
                    "username": username,
                    "password": password,
                    "product": product_type,
                })
                logger.warning(f"[!] 发现弱口令: {url} -> {username}:{password}")

            time.sleep(REQUEST_INTERVAL)

        except Exception as e:
            logger.error(f"检测异常 {url}: {e}")

    return results


def build_login_request(product_type, username, password, login_page):
    """
    根据不同产品构造登录请求
    这里需要针对每种产品单独适配
    """
    from bs4 import BeautifulSoup
    import re

    # 通用 CSRF Token 提取
    soup = BeautifulSoup(login_page.text, "html.parser")
    csrf_token = ""
    csrf_input = soup.find("input", {"name": re.compile(r"csrf|token|_token", re.I)})
    if csrf_input:
        csrf_token = csrf_input.get("value", "")

    # 按产品类型分发
    if product_type == "seeyon":
        return {
            "url": login_page.url.rsplit("/", 1)[0] + "/seeyon/rest/authentication/ucpcLogin",
            "data": {"login_username": username, "login_password": password},
        }
    elif product_type == "ecology":
        return {
            "url": login_page.url.rsplit("/", 1)[0] + "/ecology/login/checkLogin.jsp",
            "data": {"loginid": username, "userpassword": password, "csrf": csrf_token},
        }
    elif product_type == "tongda":
        import hashlib
        pwd_md5 = hashlib.md5(password.encode()).hexdigest()
        return {
            "url": login_page.url.rsplit("/", 1)[0] + "/logincheck.php",
            "data": {"UNAME": username, "PASSWORD": pwd_md5},
        }
    # ... 其他产品适配 ...
    else:
        # 通用表单提交
        form = soup.find("form")
        action = form.get("action", "") if form else ""
        inputs = {}
        if form:
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                if "user" in name.lower():
                    inputs[name] = username
                elif "pass" in name.lower() or "pwd" in name.lower():
                    inputs[name] = password
                elif inp.get("value"):
                    inputs[name] = inp["value"]
        return {"url": action or login_page.url, "data": inputs}


def is_login_success(product_type, response):
    """
    判断登录是否成功（需要根据产品适配）
    """
    # 通用判断逻辑
    fail_keywords = ["失败", "错误", "error", "fail", "invalid", "incorrect", "wrong"]

    # 302 跳转通常表示登录成功
    if response.status_code in (301, 302):
        location = response.headers.get("Location", "").lower()
        if "login" not in location and "error" not in location:
            return True

    # 200 响应中不含失败关键词
    if response.status_code == 200:
        body = response.text.lower()
        if not any(kw in body for kw in fail_keywords):
            # 还需检查是否有成功标识
            success_keywords = ["成功", "welcome", "dashboard", "index", "main", "home"]
            if any(kw in body for kw in success_keywords):
                return True

    return False
```

### 4.5 Phase 4：结果汇总

```python
#!/usr/bin/env python3
"""
Phase 4: 汇总所有检测结果，生成报告数据
"""
import json
import csv
from datetime import datetime

def aggregate_results(result_dir):
    """
    汇总所有检测结果
    """
    findings = []

    # 遍历所有结果文件
    # ... 解析 Hydra 输出、Web 检测输出 ...

    # 按风险等级排序
    risk_order = {"极高": 0, "高": 1, "中": 2, "低": 3}
    findings.sort(key=lambda x: risk_order.get(x.get("risk", "中"), 2))

    return findings

def calculate_risk(finding):
    """
    风险评级逻辑
    """
    service = finding.get("service", "")
    password = finding.get("password", "")

    # 堡垒机/VPN/数据库默认口令 → 极高
    if service in ("jumpserver", "shterm", "vpn", "mysql", "mssql", "oracle", "redis"):
        return "极高"
    # 空密码 → 极高
    if not password or password == "(空)":
        return "极高"
    # OA/邮件系统默认口令 → 高
    if service in ("seeyon", "ecology", "tongda", "coremail", "exchange"):
        return "高"
    # 通用弱口令（如 123456）→ 高
    if password in ("123456", "admin", "password", "root"):
        return "高"
    return "中"

def export_csv(findings, output_file):
    """
    导出 CSV 格式结果
    """
    fieldnames = ["序号", "IP地址", "端口", "服务/系统", "用户名", "密码", "风险等级", "发现时间"]
    with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, finding in enumerate(findings, 1):
            writer.writerow({
                "序号": i,
                "IP地址": finding["ip"],
                "端口": finding["port"],
                "服务/系统": finding["service"],
                "用户名": finding["username"],
                "密码": finding["password"],
                "风险等级": finding["risk"],
                "发现时间": finding.get("timestamp", datetime.now().isoformat()),
            })
```

### 4.6 一键运行脚本

```bash
#!/bin/bash
# weak_pwd_audit.sh — 弱口令检测主控脚本
# 用法: ./weak_pwd_audit.sh <授权IP列表文件>

set -euo pipefail

IP_FILE="${1:?用法: $0 <ip_list.txt>}"
WORK_DIR="./audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORK_DIR"/{scan,results,report}

echo "[*] Phase 1: 端口扫描..."
nmap -sV -p 22,23,80,443,1433,1521,3306,3389,5432,5900,6379,8080,8443,9090,27017 \
     -iL "$IP_FILE" -oA "$WORK_DIR/scan/nmap_result" --open -T3

echo "[*] Phase 2: 指纹识别..."
# 可选: 调用 EHole 识别 Web 产品
# ./EHole finger -l "$IP_FILE" -json "$WORK_DIR/scan/finger.json"

echo "[*] Phase 3: 弱口令检测..."
# 网络服务批量检测 (Fscan 一体化)
./fscan -hf "$IP_FILE" -pwdf dict/common_weak.txt -o "$WORK_DIR/results/fscan_result.txt" -t 4 -time 2

# 或分服务调用 Hydra
while IFS=, read -r ip port service; do
    case "$service" in
        ssh|ftp|rdp|mysql|mssql|vnc|telnet|redis)
            hydra -L "dict/${service}_users.txt" -P "dict/${service}_default.txt" \
                  -s "$port" -t 4 -W 2 -f \
                  -o "$WORK_DIR/results/${ip}_${port}.txt" \
                  "$ip" "$service" || true
            ;;
    esac
done < "$WORK_DIR/scan/service_list.csv"

echo "[*] Phase 4: 生成报告..."
python3 generate_report.py "$WORK_DIR/results/" "$WORK_DIR/report/"

echo "[+] 检测完成，报告位于: $WORK_DIR/report/"
```

---

## 五、检测流程与注意事项

### 5.1 标准作业流程

```
1. 前期准备（1-2天）
   ├── 获取书面授权
   ├── 收集资产清单（IP、URL、系统名称、负责人）
   ├── 确认各系统账号锁定策略
   ├── 准备检测环境（工具部署、字典整理）
   └── 与甲方确认检测时间窗口（建议非工作时间）

2. 资产梳理（0.5天）
   ├── 端口扫描确认开放服务
   ├── Web 指纹识别确认产品类型
   └── 整理 IP:端口:服务:产品 映射表

3. 字典适配（0.5天）
   ├── 根据产品类型匹配默认口令字典
   ├── 补充单位相关弱口令（单位名拼音等）
   └── 确认每个目标的尝试次数上限

4. 检测执行（1-3天）
   ├── 网络服务弱口令检测（SSH/RDP/DB等）
   ├── Web 应用默认口令检测（OA/VPN/邮件等）
   ├── 网络设备管理口检测
   └── 实时记录发现结果

5. 结果验证（0.5天）
   ├── 人工确认每一条弱口令发现（排除误报）
   ├── 评估每条发现的实际风险
   └── 截图取证

6. 报告编写（1天）
   └── 按模板输出检测报告
```

### 5.2 安全注意事项

1. **速率控制**：每个账号最多尝试 3 次，间隔不低于 2 秒，避免触发账号锁定
2. **时间窗口**：核心业务系统建议在非工作时间（如 22:00-06:00）检测
3. **应急联系**：检测期间保持与甲方运维人员通信畅通，出现异常立即停止
4. **日志记录**：所有检测操作必须有完整日志（时间、目标、操作、结果）
5. **数据安全**：发现的弱口令信息加密存储，报告仅传递给授权接收人
6. **不做后渗透**：发现弱口令后仅验证可登录，不进行任何后续操作（不读数据、不提权）

---

## 六、报告模板

### 6.1 报告结构

```
封面
  - 报告名称：XX单位内部系统弱口令专项安全检测报告
  - 委托单位
  - 检测单位
  - 报告日期
  - 密级标识：机密

一、项目概述
  1.1 检测背景与目的
  1.2 检测依据（等保标准、授权书编号）
  1.3 检测范围（IP 段、系统清单）
  1.4 检测时间
  1.5 检测团队

二、检测方法
  2.1 检测思路
  2.2 使用工具
  2.3 检测策略（字典来源、速率控制）

三、检测结果总览
  3.1 统计概览
      - 检测系统总数
      - 存在弱口令系统数
      - 弱口令发现总数
      - 按风险等级分布饼图
      - 按系统类型分布柱状图

  3.2 风险统计表
      | 风险等级 | 数量 | 占比 |
      |---------|------|------|
      | 极高    |      |      |
      | 高      |      |      |
      | 中      |      |      |

四、详细发现（按风险等级排列）

  [编号] VULN-2025-001
  ┌──────────────────────────────────────────────┐
  │ 风险等级：极高                                 │
  │ 系统名称：XX堡垒机                             │
  │ 访问地址：https://10.x.x.x:443                │
  │ 系统类型：堡垒机 (齐治)                         │
  │ 弱口令账户：admin / admin123                   │
  │ 账户权限：系统管理员                            │
  │ 发现时间：2025-xx-xx xx:xx                     │
  │ 风险描述：                                     │
  │   堡垒机使用出厂默认口令，攻击者可直接登录       │
  │   管理后台，获取所有受管服务器的访问权限，        │
  │   导致内网全面沦陷。                            │
  │ 影响范围：                                     │
  │   通过堡垒机可访问 XX 台内网服务器               │
  │ 修复建议：                                     │
  │   1. 立即修改为强密码（≥12位，含大小写+数字+特殊）│
  │   2. 启用双因素认证（MFA）                      │
  │   3. 限制管理口访问源 IP                        │
  │ 验证截图：[附截图]                              │
  └──────────────────────────────────────────────┘

  （重复以上格式列出所有发现）

五、整体风险评估
  5.1 总体安全态势评价
  5.2 主要风险点归纳
  5.3 横向对比分析（哪类系统问题最严重）

六、整改建议
  6.1 紧急修复项（24小时内）
      - 所有"极高"风险项立即修改密码
      - 对外暴露的弱口令服务立即断网处理
  6.2 短期改进项（1周内）
      - 部署统一密码策略（最小长度、复杂度、过期时间）
      - 所有管理后台启用 MFA
      - 清理默认账号/测试账号
  6.3 长期建设项（1-3个月）
      - 建设统一身份认证平台（SSO + LDAP）
      - 部署特权账号管理系统（PAM）
      - 建立定期弱口令巡检机制
      - 制定口令管理制度并纳入安全考核

七、参考标准
  - GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求
  - GB/T 25070-2019 信息安全技术 网络安全等级保护安全设计技术要求
  - GB/T 39786-2021 信息安全技术 信息系统密码应用基本要求

附录
  A. 授权书（扫描件）
  B. 检测资产完整清单
  C. 工具版本与配置参数
  D. 密码强度评估标准
```

### 6.2 密码强度评估标准（附录 D 参考）

| 等级 | 标准 | 示例 |
|------|------|------|
| 极弱 | 空密码 / 与用户名相同 / Top10 弱口令 | `(空)`、`admin`、`123456` |
| 弱 | 纯数字或纯字母，长度 < 8 | `abc123`、`test`、`888888` |
| 中 | 长度 ≥ 8 但模式可预测 | `Admin@123`、`Password1!` |
| 强 | 长度 ≥ 12，含大小写 + 数字 + 特殊字符，无字典词 | `kT9#mP2x$vR5` |

### 6.3 合规映射

| 等保条款 | 要求 | 对应检测项 |
|---------|------|-----------|
| 8.1.4.1 身份鉴别 (a) | 应对登录的用户进行身份标识和鉴别 | 检测空密码、匿名访问 |
| 8.1.4.1 身份鉴别 (b) | 身份标识应具有唯一性 | 检测共享账号 |
| 8.1.4.1 身份鉴别 (c) | 应提供登录失败处理功能 | 验证账号锁定策略是否生效 |
| 8.1.4.1 身份鉴别 (d) | 口令复杂度要求 | 弱口令/默认口令检测核心项 |
| 8.1.4.1 身份鉴别 (e) | 应采用两种或以上鉴别技术 | 检测关键系统是否有 MFA |

---

## 七、工具部署快速参考

### 7.1 Hydra 安装

```bash
# macOS
brew install hydra

# Ubuntu/Debian
apt-get install -y hydra

# CentOS/RHEL
yum install -y hydra
```

### 7.2 Fscan（推荐内网使用）

```bash
# 下载
wget https://github.com/shadow1ng/fscan/releases/latest/download/fscan_amd64
chmod +x fscan_amd64

# 弱口令检测
./fscan_amd64 -h 10.0.0.0/24 -pwdf weak_pass.txt -o result.txt
```

### 7.3 CrackMapExec / NetExec（域环境）

```bash
# 安装
pip3 install crackmapexec

# SMB 弱口令检测
crackmapexec smb 10.0.0.0/24 -u users.txt -p passwords.txt --continue-on-success

# RDP 弱口令检测
crackmapexec rdp 10.0.0.0/24 -u admin -p passwords.txt
```

### 7.4 字典文件结构建议

```
dict/
├── common_weak.txt          # 通用 Top 1000 弱口令
├── ssh_users.txt            # SSH 常见用户名 (root, admin, ubuntu...)
├── ssh_default.txt          # SSH 默认口令
├── rdp_default.txt          # RDP 默认口令
├── mysql_default.txt        # MySQL 默认口令
├── mssql_default.txt        # MSSQL 默认口令
├── oracle_default.txt       # Oracle 默认口令
├── redis_default.txt        # Redis 默认口令
├── network_device_default.txt  # 网络设备默认口令
├── web/
│   ├── seeyon_default.txt   # 致远 OA
│   ├── weaver_default.txt   # 泛微 OA
│   ├── tongda_default.txt   # 通达 OA
│   ├── coremail_default.txt # Coremail 邮件
│   ├── sangfor_default.txt  # 深信服 VPN
│   ├── tomcat_default.txt   # Tomcat
│   ├── weblogic_default.txt # WebLogic
│   ├── zabbix_default.txt   # Zabbix
│   ├── grafana_default.txt  # Grafana
│   └── jumpserver_default.txt # JumpServer
└── custom/
    ├── unit_related.txt     # 单位相关口令（需现场生成）
    └── username_as_pwd.txt  # 用户名=密码组合
```

---

## 八、Checklist（检测执行清单）

| 序号 | 检查项 | 完成 |
|------|--------|------|
| 1 | 获取书面授权并确认 IP 范围 | [ ] |
| 2 | 确认各系统账号锁定策略 | [ ] |
| 3 | 确认检测时间窗口 | [ ] |
| 4 | 部署检测工具并验证可用 | [ ] |
| 5 | 整理目标产品对应的默认口令字典 | [ ] |
| 6 | 生成单位相关弱口令字典 | [ ] |
| 7 | 端口扫描与服务识别 | [ ] |
| 8 | Web 应用指纹识别 | [ ] |
| 9 | 网络服务弱口令检测（SSH/RDP/DB/Redis 等） | [ ] |
| 10 | Web 管理后台默认口令检测 | [ ] |
| 11 | VPN 网关弱口令检测 | [ ] |
| 12 | 堡垒机弱口令检测 | [ ] |
| 13 | 网络设备管理口弱口令检测 | [ ] |
| 14 | 结果人工验证与截图取证 | [ ] |
| 15 | 编写检测报告 | [ ] |
| 16 | 报告评审与交付 | [ ] |
| 17 | 删除本地检测数据与凭据 | [ ] |
