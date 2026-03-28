---
name: recon
description: CTF 初始侦察与信息收集。解题第一步，用于发现攻击面、识别技术栈、寻找潜在漏洞点。
allowed-tools: Bash, Read, Write
---

# CTF 初始侦察指南

当你收到一个目标地址但不知道是什么漏洞时，按照本指南进行系统化的初始侦察。

---

## Phase 1: 基础信息收集（必须执行）

### 1.1 HTTP 基础探测

```python
import requests

url = "http://target.com"

# 获取基础响应
resp = requests.get(url, timeout=10)
print(f"Status: {resp.status_code}")
print(f"Server: {resp.headers.get('Server', 'Unknown')}")
print(f"X-Powered-By: {resp.headers.get('X-Powered-By', 'Unknown')}")
print(f"Content-Type: {resp.headers.get('Content-Type', '')}")
print(f"Set-Cookie: {resp.headers.get('Set-Cookie', 'None')}")

# 检查响应内容特征
if "PHP" in resp.text or "php" in resp.text:
    print("[+] 可能是 PHP 应用")
if "Django" in resp.text or "csrfmiddlewaretoken" in resp.text:
    print("[+] 可能是 Django 应用")
if "Flask" in resp.text or "Werkzeug" in resp.text:
    print("[+] 可能是 Flask 应用")
if "Express" in resp.text or "Node.js" in resp.text:
    print("[+] 可能是 Node.js/Express 应用")
if "ASP.NET" in resp.text or "__VIEWSTATE" in resp.text:
    print("[+] 可能是 ASP.NET 应用")
```

### 1.2 检查关键文件

```bash
# robots.txt
curl -s http://target.com/robots.txt

# sitemap.xml
curl -s http://target.com/sitemap.xml

# 常见敏感文件
curl -s http://target.com/.git/config
curl -s http://target.com/.env
curl -s http://target.com/backup.zip
curl -s http://target.com/config.php.bak
curl -s http://target.com/web.config
curl -s http://target.com/package.json
```

---

## Phase 2: 技术栈识别

### 2.1 Cookie 分析

| Cookie 名称 | 技术栈 |
|------------|--------|
| PHPSESSID | PHP |
| JSESSIONID | Java (Tomcat/Jetty) |
| sessionid | Django |
| connect.sid | Express/Node.js |
| ASP.NET_SessionId | ASP.NET |
| laravel_session | Laravel |

### 2.2 错误页面特征

```python
# 故意触发错误，观察特征
import requests

# 404 测试
resp_404 = requests.get("http://target.com/this_page_not_exists")
print(f"404 页面特征: {resp_404.text[:500]}")

# 500 测试（尝试异常输入）
resp_500 = requests.get("http://target.com/?test=<script>alert(1)</script>")
if resp_500.status_code == 500:
    print("[+] 可能对特殊字符敏感")
```

---

## Phase 3: 目录与端点发现

### 3.1 常见路径扫描

```bash
# 使用 dirsearch（快速）
dirsearch -u http://target.com -e php,html,js,txt -q

# 或使用 gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -q

# 常见管理后台路径
/admin
/admin.php
/login
/login.php
/wp-admin
/manager
/console
/dashboard
/api
/api/v1
/swagger
```

### 3.2 API 端点探测

```python
import requests

base = "http://target.com"

# 常见 API 路径
api_paths = [
    "/api", "/api/v1", "/api/v2",
    "/graphql", "/graphiql",
    "/swagger", "/swagger-ui", "/api-docs",
    "/rest", "/rest/v1"
]

for path in api_paths:
    resp = requests.get(base + path)
    if resp.status_code == 200:
        print(f"[+] 发现 API: {path}")
        print(f"    内容: {resp.text[:200]}")
```

---

## Phase 4: 参数发现

### 4.1 URL 参数分析

观察目标 URL 是否包含参数：
- `?id=1` → 可能是 SQL 注入点
- `?page=about` → 可能是文件包含
- `?url=http://...` → 可能是 SSRF
- `?cmd=ls` → 可能是命令注入

### 4.2 表单发现

```python
from bs4 import BeautifulSoup
import requests

resp = requests.get("http://target.com")
soup = BeautifulSoup(resp.text, 'html.parser')

forms = soup.find_all('form')
for i, form in enumerate(forms):
    print(f"\n[Form {i+1}]")
    print(f"Action: {form.get('action', 'self')}")
    print(f"Method: {form.get('method', 'GET')}")

    inputs = form.find_all('input')
    for inp in inputs:
        name = inp.get('name', 'unnamed')
        type_ = inp.get('type', 'text')
        print(f"  - {name} ({type_})")
```

---

## Phase 5: 漏洞线索识别

### 5.1 输入点识别

以下特征提示可能存在漏洞：

| 特征 | 可能的漏洞 |
|------|-----------|
| 搜索框 | SQL 注入、XSS、命令注入 |
| 文件上传 | 文件上传漏洞、RCE |
| URL 参数 | SQL 注入、LFI/RFI、SSRF、IDOR |
| Cookie | 认证绕过、反序列化 |
| Header 回显 | HTTP 头注入、XSS |
| 模板渲染 | SSTI |

### 5.2 错误信息分析

```python
# 测试各种注入
import requests

test_payloads = {
    "sql": ["'", "\"", "1' OR '1'='1", "1 AND 1=2"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "lfi": ["../../../etc/passwd", "....//....//etc/passwd"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "cmd": ["; ls", "| whoami", "&& cat /etc/passwd"]
}

for vuln_type, payloads in test_payloads.items():
    print(f"\n测试 {vuln_type}:")
    for payload in payloads:
        # 根据实际情况构造请求
        resp = requests.get(f"http://target.com/?test={payload}")
        if "error" in resp.text.lower() or resp.status_code == 500:
            print(f"  [!] {payload} 触发异常，可能存在 {vuln_type}")
```

---

## Phase 6: 侦察结果分析

完成侦察后，整理以下信息：

```markdown
## 侦察报告模板

### 基础信息
- **目标**: http://target.com
- **技术栈**: PHP/Apache (根据 Server 头和 Cookie)
- **框架**: Laravel (根据 laravel_session cookie)

### 发现的端点
- /login - 登录页面
- /admin - 管理后台
- /api/v1/users - API 接口

### 输入点
- GET 参数: id, page, search
- POST 表单: 登录表单 (username, password)
- Cookie: session_id

### 潜在漏洞线索
1. **SQL 注入**: id 参数可能是数字型注入点
2. **认证绕过**: 登录页面可能存在逻辑漏洞
3. **IDOR**: /api/v1/users?id=1 可能可以遍历

### 下一步建议
加载对应漏洞类型的 Skill 进行深入测试
```

---

## 快速决策流程

```
发现登录页面 → 尝试: SQL注入、认证绕过、暴力破解
发现搜索功能 → 尝试: SQL注入、XSS、命令注入
发现文件上传 → 尝试: 文件上传漏洞、RCE
发现 URL 参数 → 尝试: SQL注入、LFI/RFI、SSRF
发现模板渲染 → 尝试: SSTI
发现 API 接口 → 尝试: IDOR、认证绕过、注入
```

---

## 最佳实践

1. **先侦察，后攻击**：不要一上来就盲注，先了解目标
2. **记录所有发现**：IP、端口、技术栈、端点、参数
3. **从简单到复杂**：先测试明显的注入点
4. **注意 WAF**：如果请求被拦截，尝试绕过
5. **保存证据**：截图、保存响应，便于分析
