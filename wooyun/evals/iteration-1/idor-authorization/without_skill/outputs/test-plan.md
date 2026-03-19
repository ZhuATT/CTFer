# 多租户 SaaS 平台越权访问测试计划

## 1. 测试范围与目标

### 1.1 测试目标

验证多租户 SaaS 平台在以下三个维度的访问控制是否健全：

| 维度 | 威胁模型 | 核心问题 |
|------|---------|---------|
| 水平越权 (IDOR) | 同权限用户 A 访问用户 B 的资源 | 资源标识符是否被正确鉴权？ |
| 垂直越权 | 低权限用户执行高权限操作 | 角色权限边界是否严格？ |
| 未授权访问 | 未登录/无凭证用户访问受保护资源 | 认证机制是否全覆盖？ |

### 1.2 测试范围

- 所有 REST API 端点（CRUD 操作）
- 跨租户数据隔离
- 文件/对象存储访问
- 批量操作接口
- 导出/报表接口
- WebSocket 连接（如有）
- GraphQL 查询（如有）

### 1.3 前置条件

准备以下测试账号（最少）：

| 账号编号 | 角色 | 租户 | 用途 |
|---------|------|------|------|
| A1 | 超级管理员 | 租户 A | 垂直越权基准 |
| A2 | 普通管理员 | 租户 A | 垂直越权测试 |
| A3 | 普通用户 | 租户 A | 水平越权 + 垂直越权 |
| A4 | 只读用户 | 租户 A | 垂直越权测试 |
| B1 | 普通管理员 | 租户 B | 跨租户越权 |
| B2 | 普通用户 | 租户 B | 跨租户水平越权 |
| -- | (无凭证) | -- | 未授权访问测试 |

---

## 2. 水平越权 (IDOR) 测试

### 2.1 测试原理

IDOR (Insecure Direct Object Reference) 的核心是：攻击者通过篡改请求中的资源标识符（ID、UUID、文件名等），访问不属于自己的资源。

### 2.2 测试用例矩阵

#### TC-IDOR-001: 基于路径参数的 IDOR

**目标**: 所有 `/{resource}/{id}` 形式的端点

```
步骤:
1. 用账号 A3 创建资源，记录资源 ID（假设为 res_123）
2. 用账号 B2 的 Token 发送请求:
   GET /api/v1/orders/res_123
   Authorization: Bearer <B2_token>
3. 验证响应

预期: 403 Forbidden 或 404 Not Found
失败标志: 200 OK 且返回了 A3 的数据
```

**覆盖端点清单**（逐一测试）：

```
GET    /api/v1/users/{userId}
GET    /api/v1/users/{userId}/profile
PUT    /api/v1/users/{userId}
DELETE /api/v1/users/{userId}
GET    /api/v1/orders/{orderId}
PUT    /api/v1/orders/{orderId}
GET    /api/v1/invoices/{invoiceId}
GET    /api/v1/projects/{projectId}
GET    /api/v1/documents/{docId}
GET    /api/v1/reports/{reportId}
GET    /api/v1/organizations/{orgId}/members
...（根据实际 API 补充）
```

#### TC-IDOR-002: 基于查询参数的 IDOR

```
步骤:
1. 用 A3 的 Token 发送:
   GET /api/v1/messages?user_id=<B2_user_id>
2. 用 A3 的 Token 发送:
   GET /api/v1/audit-logs?tenant_id=<tenant_B_id>

预期: 返回空集或 403，不返回 B2 的数据
失败标志: 返回了其他用户/租户的数据
```

#### TC-IDOR-003: 基于请求体参数的 IDOR

```
步骤:
1. 用 A3 的 Token 发送:
   PUT /api/v1/profile
   {
     "user_id": "<B2_user_id>",
     "email": "attacker@evil.com"
   }
2. 检查 B2 的 profile 是否被修改

预期: 服务端忽略 user_id 参数或返回 403
失败标志: B2 的 email 被修改
```

#### TC-IDOR-004: 基于文件/对象引用的 IDOR

```
步骤:
1. 用 A3 上传文件，获取文件 URL/Key:
   POST /api/v1/files/upload → 返回 file_key: "abc123.pdf"
2. 用 B2 的 Token 访问:
   GET /api/v1/files/abc123.pdf
3. 尝试直接访问存储 URL（如 S3 pre-signed URL 泄露）

预期: 403 或 404
失败标志: B2 能下载 A3 的文件
```

#### TC-IDOR-005: 批量操作中的 IDOR

```
步骤:
1. 用 A3 的 Token 发送批量操作:
   POST /api/v1/orders/batch-delete
   {
     "ids": ["own_order_1", "B2_order_1", "B2_order_2"]
   }

预期: 只删除 own_order_1，其余返回错误或被忽略
失败标志: B2 的订单被删除
```

#### TC-IDOR-006: ID 可预测性测试

```
步骤:
1. 连续创建 3 个资源，记录 ID
2. 分析 ID 模式:
   - 自增整数 (1001, 1002, 1003) → 高风险
   - 短序列 UUID → 中风险
   - UUIDv4 → 低风险（但仍需鉴权）
3. 如果 ID 可预测，尝试枚举:
   for id in range(1000, 1010):
     GET /api/v1/resources/{id}

预期: 即使 ID 可猜测，鉴权也应阻止访问
失败标志: 能通过枚举获取他人数据
```

#### TC-IDOR-007: 跨租户 IDOR（多租户核心）

```
步骤:
1. 用 A3 的 Token，替换请求中所有租户标识:
   GET /api/v1/tenants/<tenant_B_id>/users
   GET /api/v1/tenants/<tenant_B_id>/settings
   GET /api/v1/tenants/<tenant_B_id>/billing
2. 检查是否存在隐含的租户上下文（Header/Cookie/Token 中的 tenant_id）:
   - 修改 X-Tenant-ID header
   - 修改 JWT 中的 tenant claim（如果 JWT 未加密仅签名，不应生效）

预期: 所有跨租户请求返回 403
失败标志: 返回了租户 B 的任何数据
```

#### TC-IDOR-008: 关联资源的间接 IDOR

```
步骤:
1. A3 创建一个项目 proj_A
2. B2 创建一个项目 proj_B，其下有任务 task_B1
3. 用 A3 的 Token:
   GET /api/v1/projects/proj_B/tasks/task_B1
   POST /api/v1/projects/proj_A/tasks
   {
     "parent_project": "proj_B"  // 尝试跨项目关联
   }

预期: 拒绝跨项目/跨租户的关联操作
```

### 2.3 IDOR 测试自动化脚本模板

```python
#!/usr/bin/env python3
"""IDOR 自动化测试脚本模板"""

import requests
import json
from dataclasses import dataclass

@dataclass
class TestAccount:
    name: str
    token: str
    tenant_id: str
    user_id: str

# === 配置 ===
BASE_URL = "https://api.your-saas.com"

VICTIM = TestAccount(
    name="victim_A3",
    token="Bearer eyJ...",
    tenant_id="tenant_a_id",
    user_id="user_a3_id"
)

ATTACKER = TestAccount(
    name="attacker_B2",
    token="Bearer eyJ...",
    tenant_id="tenant_b_id",
    user_id="user_b2_id"
)

# === IDOR 端点列表 ===
IDOR_ENDPOINTS = [
    {"method": "GET",    "path": "/api/v1/users/{user_id}"},
    {"method": "GET",    "path": "/api/v1/users/{user_id}/profile"},
    {"method": "PUT",    "path": "/api/v1/users/{user_id}", "body": {"name": "hacked"}},
    {"method": "DELETE", "path": "/api/v1/users/{user_id}"},
    {"method": "GET",    "path": "/api/v1/orders/{order_id}"},
    {"method": "GET",    "path": "/api/v1/tenants/{tenant_id}/settings"},
    # ... 添加所有端点
]

def test_idor(endpoint, victim: TestAccount, attacker: TestAccount):
    """用 attacker 的 token 访问 victim 的资源"""
    path = endpoint["path"].format(
        user_id=victim.user_id,
        tenant_id=victim.tenant_id,
        order_id="victim_order_id",  # 替换为实际 ID
    )
    url = f"{BASE_URL}{path}"
    headers = {"Authorization": attacker.token, "Content-Type": "application/json"}

    method = endpoint["method"]
    body = endpoint.get("body")

    resp = getattr(requests, method.lower())(url, headers=headers, json=body)

    status = "PASS" if resp.status_code in (403, 404, 401) else "FAIL"
    print(f"[{status}] {method} {path} → {resp.status_code}")

    if status == "FAIL":
        print(f"  !!! 越权成功，响应: {resp.text[:200]}")

    return status

# === 执行 ===
if __name__ == "__main__":
    results = {"PASS": 0, "FAIL": 0}
    for ep in IDOR_ENDPOINTS:
        result = test_idor(ep, VICTIM, ATTACKER)
        results[result] += 1

    print(f"\n=== 结果汇总 ===")
    print(f"通过: {results['PASS']}, 失败: {results['FAIL']}")
```

---

## 3. 垂直越权（权限提升）测试

### 3.1 测试原理

低权限角色尝试执行高权限角色才能进行的操作。关注点：角色继承、API 端点权限校验、功能级访问控制。

### 3.2 权限矩阵（测试前先建立）

先确认系统的权限模型，建立如下矩阵：

| API 端点 | 超级管理员 | 管理员 | 普通用户 | 只读用户 | 未登录 |
|---------|:---------:|:-----:|:------:|:------:|:-----:|
| GET /api/v1/users | Y | Y | N | N | N |
| POST /api/v1/users | Y | Y | N | N | N |
| DELETE /api/v1/users/{id} | Y | N | N | N | N |
| GET /api/v1/settings | Y | Y | Y | Y | N |
| PUT /api/v1/settings | Y | Y | N | N | N |
| GET /api/v1/admin/dashboard | Y | N | N | N | N |
| POST /api/v1/roles | Y | N | N | N | N |
| GET /api/v1/billing | Y | Y | N | N | N |
| POST /api/v1/export/all-data | Y | N | N | N | N |
| DELETE /api/v1/tenants/{id} | Y | N | N | N | N |

### 3.3 测试用例

#### TC-VERT-001: 普通用户访问管理员端点

```
步骤:
1. 用 A3（普通用户）的 Token 逐一请求管理员端点:
   GET    /api/v1/admin/dashboard
   GET    /api/v1/admin/users
   POST   /api/v1/admin/users
   DELETE /api/v1/admin/users/{userId}
   PUT    /api/v1/admin/settings
   GET    /api/v1/admin/audit-logs
   POST   /api/v1/admin/export

预期: 全部返回 403 Forbidden
失败标志: 任何一个返回 200/201
```

#### TC-VERT-002: 只读用户执行写操作

```
步骤:
1. 用 A4（只读用户）的 Token:
   POST   /api/v1/orders       {"item": "test"}
   PUT    /api/v1/orders/{id}   {"status": "cancelled"}
   DELETE /api/v1/orders/{id}
   POST   /api/v1/documents    {"title": "test"}
   PUT    /api/v1/profile      {"name": "hacked"}

预期: 全部返回 403
失败标志: 写操作成功执行
```

#### TC-VERT-003: 自我提权——角色篡改

```
步骤:
1. 用 A3 的 Token 修改自己的角色:
   PUT /api/v1/users/A3_id
   {
     "role": "admin"
   }
2. 用 A3 的 Token 给自己添加权限:
   POST /api/v1/users/A3_id/roles
   {
     "roles": ["admin", "super_admin"]
   }
3. 用 A3 的 Token 创建高权限 API Key:
   POST /api/v1/api-keys
   {
     "permissions": ["*"],
     "role": "admin"
   }

预期: 全部被拒绝（403）
失败标志: 角色或权限被修改
```

#### TC-VERT-004: 管理员越权为超级管理员

```
步骤:
1. 用 A2（普通管理员）的 Token:
   DELETE /api/v1/tenants/tenant_a_id     (删除租户)
   PUT    /api/v1/system/config            (修改系统配置)
   GET    /api/v1/system/all-tenants       (查看所有租户)
   POST   /api/v1/super-admin/impersonate  (模拟其他用户)
   PUT    /api/v1/users/A1_id/role         (修改超级管理员)

预期: 全部返回 403
失败标志: 任何操作成功
```

#### TC-VERT-005: HTTP 方法覆盖绕过

```
步骤:
1. 对只允许 GET 的端点尝试其他方法:
   PUT    /api/v1/readonly-resource/{id}
   DELETE /api/v1/readonly-resource/{id}
   PATCH  /api/v1/readonly-resource/{id}

2. 尝试方法覆盖:
   POST /api/v1/admin/users
   X-HTTP-Method-Override: DELETE

   POST /api/v1/admin/users
   X-HTTP-Method: PUT

   GET /api/v1/admin/users?_method=DELETE

预期: 非授权方法返回 405 或 403
失败标志: 通过方法覆盖成功执行了未授权操作
```

#### TC-VERT-006: 参数级权限绕过

```
步骤:
1. 普通用户修改请求体中的隐藏/管理员字段:
   POST /api/v1/orders
   {
     "item": "product_1",
     "price": 0.01,              // 尝试篡改价格
     "discount": 99,             // 尝试设置折扣
     "is_admin_order": true,     // 尝试管理员标记
     "bypass_approval": true     // 尝试绕过审批
   }

2. 用户注册时注入角色:
   POST /api/v1/register
   {
     "email": "new@test.com",
     "password": "pass123",
     "role": "admin",            // 注入角色
     "tenant_id": "target_tenant" // 注入租户
   }

预期: 服务端忽略这些字段或明确拒绝
失败标志: 非授权字段被接受并生效
```

#### TC-VERT-007: JWT/Token 篡改

```
步骤:
1. 解码当前 JWT（base64），修改 payload:
   - 修改 "role": "user" → "role": "admin"
   - 修改 "tenant_id": "a" → "tenant_id": "b"
   - 修改 "user_id" 为其他用户
   - 不修改签名，直接发送

2. 尝试 None 算法攻击:
   - 将 JWT header 的 alg 改为 "none"
   - 移除签名部分

3. 尝试弱密钥签名:
   - 用常见弱密钥（"secret", "123456", "password"）重新签名

4. 尝试过期 Token:
   - 使用已过期的 Token 访问

预期: 全部返回 401 Unauthorized
失败标志: 篡改后的 Token 被接受
```

#### TC-VERT-008: 多租户角色隔离

```
步骤:
1. B1 是租户 B 的管理员
2. 用 B1 的 Token 尝试管理租户 A 的资源:
   GET    /api/v1/tenants/tenant_a/users
   POST   /api/v1/tenants/tenant_a/users
   PUT    /api/v1/tenants/tenant_a/settings
   DELETE /api/v1/tenants/tenant_a/projects/{id}

预期: B1 的管理员权限仅在租户 B 内有效，对租户 A 返回 403
失败标志: B1 能管理租户 A
```

### 3.4 垂直越权自动化脚本模板

```python
#!/usr/bin/env python3
"""垂直越权自动化测试"""

import requests

BASE_URL = "https://api.your-saas.com"

TOKENS = {
    "super_admin": "Bearer eyJ...",
    "admin":       "Bearer eyJ...",
    "user":        "Bearer eyJ...",
    "readonly":    "Bearer eyJ...",
}

# 权限矩阵: (method, path, allowed_roles)
PERMISSION_MATRIX = [
    ("GET",    "/api/v1/admin/dashboard",      ["super_admin"]),
    ("GET",    "/api/v1/admin/users",           ["super_admin", "admin"]),
    ("POST",   "/api/v1/admin/users",           ["super_admin", "admin"]),
    ("DELETE", "/api/v1/admin/users/test_id",   ["super_admin"]),
    ("PUT",    "/api/v1/settings",              ["super_admin", "admin"]),
    ("GET",    "/api/v1/orders",                ["super_admin", "admin", "user"]),
    ("POST",   "/api/v1/orders",                ["super_admin", "admin", "user"]),
    ("GET",    "/api/v1/reports/export",         ["super_admin", "admin"]),
    ("DELETE", "/api/v1/tenants/test_tenant",   ["super_admin"]),
    ("POST",   "/api/v1/roles",                 ["super_admin"]),
    # ... 补充所有端点
]

def test_vertical_escalation():
    results = {"PASS": 0, "FAIL": 0}

    for method, path, allowed_roles in PERMISSION_MATRIX:
        for role, token in TOKENS.items():
            url = f"{BASE_URL}{path}"
            headers = {"Authorization": token}
            resp = getattr(requests, method.lower())(url, headers=headers)

            if role in allowed_roles:
                expected = "ALLOWED"
                passed = resp.status_code in (200, 201, 204)
            else:
                expected = "DENIED"
                passed = resp.status_code in (401, 403, 404)

            status = "PASS" if passed else "FAIL"
            results[status] += 1

            if not passed:
                print(f"[FAIL] {role:12s} {method:6s} {path:40s} "
                      f"→ {resp.status_code} (expected {expected})")

    print(f"\n=== 结果 === PASS: {results['PASS']}, FAIL: {results['FAIL']}")

if __name__ == "__main__":
    test_vertical_escalation()
```

---

## 4. 未授权访问测试

### 4.1 测试原理

验证所有需要认证的端点在缺少有效凭证时是否正确拒绝访问。

### 4.2 测试用例

#### TC-UNAUTH-001: 无 Token 访问

```
步骤:
1. 对所有 API 端点发送请求，不携带 Authorization header:
   GET  /api/v1/users
   GET  /api/v1/orders
   GET  /api/v1/admin/dashboard
   POST /api/v1/orders  {"item": "test"}
   PUT  /api/v1/profile {"name": "test"}

预期: 全部返回 401 Unauthorized
失败标志: 任何端点返回 200/201 且包含业务数据
```

**豁免白名单**（这些端点应该允许匿名访问）：

```
POST /api/v1/auth/login
POST /api/v1/auth/register
POST /api/v1/auth/forgot-password
GET  /api/v1/health
GET  /api/v1/public/*
```

#### TC-UNAUTH-002: 无效 Token 访问

```
步骤:
1. 使用各种无效 Token:
   Authorization: Bearer invalid_token_string
   Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9.invalid
   Authorization: Bearer null
   Authorization: Bearer undefined
   Authorization: Bearer ""
   Authorization: Basic dGVzdDp0ZXN0  (错误的认证类型)
   Authorization: bearer <valid_token>  (小写 bearer)

预期: 全部返回 401
失败标志: 任何请求被接受
```

#### TC-UNAUTH-003: 过期/吊销 Token

```
步骤:
1. 获取有效 Token
2. 调用登出接口:
   POST /api/v1/auth/logout
3. 用已登出的 Token 继续访问:
   GET /api/v1/users/me
4. 用已过期的 Token（手动修改 exp 或等待过期）访问

预期: 返回 401
失败标志: 已登出/过期的 Token 仍然有效
```

#### TC-UNAUTH-004: API 端点发现

```
步骤:
1. 尝试常见的未保护端点:
   GET /api/v1/swagger.json
   GET /api/v1/openapi.json
   GET /api/docs
   GET /api/v1/graphql  (GraphQL introspection)
   GET /api/v1/debug
   GET /api/v1/metrics
   GET /api/v1/actuator
   GET /api/v1/actuator/env
   GET /api/v1/internal/*
   GET /.env
   GET /config
   GET /api/v1/test

预期: 生产环境下调试/文档端点应被禁用或需要认证
失败标志: 暴露了内部 API 结构、环境变量或调试信息
```

#### TC-UNAUTH-005: CORS 配置测试

```
步骤:
1. 发送预检请求:
   OPTIONS /api/v1/users
   Origin: https://evil-site.com

2. 检查响应头:
   Access-Control-Allow-Origin: *              → 高风险
   Access-Control-Allow-Origin: https://evil.com → 高风险
   Access-Control-Allow-Credentials: true       → 与 * 组合是严重漏洞

预期: CORS 只允许已知的前端域名
失败标志: 允许任意 Origin 且带 Credentials
```

#### TC-UNAUTH-006: 认证绕过技巧

```
步骤:
1. 路径遍历绕过:
   GET /api/v1/public/../admin/dashboard
   GET /api/v1/./admin/users
   GET /api//v1//admin//users
   GET /api/v1/admin/users/..;/public  (Tomcat 特有)

2. 大小写绕过:
   GET /api/v1/ADMIN/dashboard
   GET /api/v1/Admin/Users

3. URL 编码绕过:
   GET /api/v1/%61dmin/dashboard      (a → %61)
   GET /api/v1/admin%2Fusers          (/ → %2F)
   GET /api/v1/admin/dashboard%00     (null byte)

4. HTTP 版本降级:
   发送 HTTP/1.0 请求（某些中间件可能不检查认证）

5. 请求走私:
   Transfer-Encoding: chunked + Content-Length 不一致

预期: 全部被正确拒绝
失败标志: 通过编码/路径技巧绕过了认证检查
```

#### TC-UNAUTH-007: 静态资源与上传文件

```
步骤:
1. 通过已知或猜测的路径直接访问:
   GET /uploads/user_avatar_A3.jpg
   GET /static/exports/report_20240101.pdf
   GET /api/v1/files/download?path=../../etc/passwd

预期: 私有文件需要认证，路径遍历被阻止
失败标志: 可以匿名下载用户上传的私有文件
```

### 4.3 未授权访问自动化脚本模板

```python
#!/usr/bin/env python3
"""未授权访问扫描器"""

import requests

BASE_URL = "https://api.your-saas.com"

# 需要认证的端点（从 API 文档/路由扫描中获取）
PROTECTED_ENDPOINTS = [
    ("GET",    "/api/v1/users"),
    ("GET",    "/api/v1/users/me"),
    ("GET",    "/api/v1/orders"),
    ("POST",   "/api/v1/orders"),
    ("GET",    "/api/v1/admin/dashboard"),
    ("GET",    "/api/v1/settings"),
    ("GET",    "/api/v1/billing"),
    ("GET",    "/api/v1/reports"),
    # ... 所有端点
]

# 不需要认证的端点（白名单验证）
PUBLIC_ENDPOINTS = [
    ("POST",   "/api/v1/auth/login"),
    ("POST",   "/api/v1/auth/register"),
    ("GET",    "/api/v1/health"),
]

# 敏感端点（不应暴露）
SENSITIVE_ENDPOINTS = [
    ("GET",    "/api/docs"),
    ("GET",    "/api/v1/swagger.json"),
    ("GET",    "/api/v1/openapi.json"),
    ("GET",    "/debug"),
    ("GET",    "/metrics"),
    ("GET",    "/api/v1/actuator"),
    ("GET",    "/api/v1/actuator/env"),
    ("GET",    "/.env"),
    ("GET",    "/api/v1/graphql"),  # introspection
]

INVALID_TOKENS = [
    None,                          # 无 header
    "invalid_token",               # 随机字符串
    "null",                        # null 字符串
    "",                            # 空字符串
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ0ZXN0IjoidGVzdCJ9.",  # alg:none
]

def test_no_auth():
    """测试无认证访问受保护端点"""
    print("=== 测试 1: 无 Token 访问受保护端点 ===")
    fails = 0
    for method, path in PROTECTED_ENDPOINTS:
        url = f"{BASE_URL}{path}"
        resp = getattr(requests, method.lower())(url)
        if resp.status_code not in (401, 403):
            print(f"[FAIL] {method} {path} → {resp.status_code}")
            fails += 1
    print(f"失败: {fails}/{len(PROTECTED_ENDPOINTS)}\n")

def test_invalid_tokens():
    """测试无效 Token"""
    print("=== 测试 2: 无效 Token ===")
    fails = 0
    test_path = "/api/v1/users/me"  # 用一个代表性端点
    for token in INVALID_TOKENS:
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(f"{BASE_URL}{test_path}", headers=headers)
        if resp.status_code not in (401, 403):
            print(f"[FAIL] Token='{token}' → {resp.status_code}")
            fails += 1
    print(f"失败: {fails}/{len(INVALID_TOKENS)}\n")

def test_sensitive_exposure():
    """测试敏感端点暴露"""
    print("=== 测试 3: 敏感端点暴露 ===")
    for method, path in SENSITIVE_ENDPOINTS:
        url = f"{BASE_URL}{path}"
        resp = getattr(requests, method.lower())(url)
        if resp.status_code == 200:
            print(f"[WARN] {path} 可公开访问! Content-Type: {resp.headers.get('Content-Type')}")

if __name__ == "__main__":
    test_no_auth()
    test_invalid_tokens()
    test_sensitive_exposure()
```

---

## 5. 多租户专项测试

### 5.1 租户隔离验证

#### TC-TENANT-001: 数据库层隔离

```
步骤:
1. 租户 A 创建 100 条记录
2. 租户 B 查询列表:
   GET /api/v1/orders?page=1&size=1000
3. 检查返回数据中是否包含租户 A 的记录

预期: 租户 B 的查询绝不返回租户 A 的数据
失败标志: 列表中出现了其他租户的数据
```

#### TC-TENANT-002: 搜索/过滤器隔离

```
步骤:
1. 租户 A 创建标题为 "IDOR_TEST_MARKER" 的资源
2. 租户 B 搜索:
   GET /api/v1/search?q=IDOR_TEST_MARKER
   GET /api/v1/orders?filter=title:IDOR_TEST_MARKER

预期: 租户 B 搜不到该资源
失败标志: 搜索结果泄露了跨租户数据
```

#### TC-TENANT-003: 聚合/统计数据隔离

```
步骤:
1. 用租户 B 的 Token 访问统计接口:
   GET /api/v1/dashboard/stats
   GET /api/v1/analytics/overview
2. 检查返回的数字是否只反映租户 B 的数据
   （可通过已知数据量验证）

预期: 统计数据仅包含当前租户的数据
失败标志: 统计数字包含了其他租户的数据
```

#### TC-TENANT-004: 租户上下文切换

```
步骤:
1. 用户同时属于多个租户时:
   GET /api/v1/orders
   X-Tenant-ID: tenant_a

   GET /api/v1/orders
   X-Tenant-ID: tenant_b

2. 尝试切换到不属于自己的租户:
   GET /api/v1/orders
   X-Tenant-ID: tenant_c  (用户不属于此租户)

预期: 只能访问自己所属租户的数据
失败标志: 能切换到任意租户
```

---

## 6. 测试执行流程

### 6.1 端点收集

在正式测试前，先完整收集所有 API 端点：

```bash
# 方法 1: 从 OpenAPI/Swagger 文档提取
curl -s https://api.your-saas.com/api/docs/swagger.json | \
  jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | "\(.key | ascii_upcase) \($path)"'

# 方法 2: 从前端 JS 中提取
# 下载前端打包文件，grep API 路径
curl -s https://app.your-saas.com/main.js | grep -oP '/api/v[0-9]+/[a-zA-Z0-9/_-]+' | sort -u

# 方法 3: 从服务端代码提取 (如有代码访问权)
grep -rn '@(Get|Post|Put|Delete|Patch)Mapping\|@RequestMapping\|router\.\(get\|post\|put\|delete\)' src/ --include="*.java" --include="*.ts" --include="*.py"

# 方法 4: 流量抓包
# 用 mitmproxy/Burp Suite 代理正常使用应用，收集所有 API 调用
```

### 6.2 执行顺序

```
Phase 1: 侦察 (Day 1)
├── 收集所有 API 端点
├── 建立权限矩阵
├── 准备测试账号
└── 配置测试环境

Phase 2: 未授权访问 (Day 2)
├── TC-UNAUTH-001 ~ 007
├── 标记所有不需要认证即可访问的端点
└── 验证白名单端点的合理性

Phase 3: 水平越权 IDOR (Day 3-4)
├── TC-IDOR-001 ~ 008
├── 同租户内用户间的 IDOR
├── 跨租户 IDOR
└── 批量操作 IDOR

Phase 4: 垂直越权 (Day 5-6)
├── TC-VERT-001 ~ 008
├── 权限矩阵全量验证
├── Token 篡改测试
└── 参数注入测试

Phase 5: 多租户专项 (Day 7)
├── TC-TENANT-001 ~ 004
├── 数据隔离验证
└── 搜索/聚合泄露

Phase 6: 报告与复测 (Day 8)
├── 汇总所有发现
├── 评估风险等级
└── 修复后复测
```

---

## 7. 报告模板

### 7.1 漏洞报告格式

每个发现的漏洞按以下格式记录：

```
### [CRITICAL/HIGH/MEDIUM/LOW] 漏洞标题

**漏洞类型**: 水平越权 / 垂直越权 / 未授权访问
**影响端点**: `GET /api/v1/orders/{orderId}`
**CVSS 评分**: 8.6 (High)

**描述**:
用户 A 可以通过修改 URL 中的 orderId 参数访问用户 B 的订单数据，
服务端未验证请求者是否为资源所有者。

**复现步骤**:
1. 用用户 A 的 Token 发送请求
2. 将 orderId 替换为用户 B 的订单 ID
3. 观察返回了用户 B 的订单详情

**请求**:
GET /api/v1/orders/order_B_12345
Authorization: Bearer <user_A_token>

**响应**:
HTTP/1.1 200 OK
{
  "order_id": "order_B_12345",
  "user_id": "user_B",
  "items": [...]
}

**影响范围**:
- 任何认证用户可读取任意用户的订单数据
- 涉及 PII（个人信息）泄露
- 影响所有租户

**修复建议**:
1. 在数据访问层添加所有者验证: `WHERE order_id = ? AND user_id = ?`
2. 使用不可预测的 UUID 替代自增 ID（纵深防御，非主要修复）
3. 添加请求日志审计

**修复优先级**: P0 — 立即修复
```

### 7.2 风险评级标准

| 等级 | 定义 | 示例 |
|------|------|------|
| CRITICAL | 大规模数据泄露/跨租户全面突破 | 跨租户管理员接管、批量数据导出无鉴权 |
| HIGH | 单一敏感资源越权访问 | IDOR 读取他人订单、垂直提权至管理员 |
| MEDIUM | 有限信息泄露或受限写操作 | 只读 IDOR（非敏感数据）、部分管理功能暴露 |
| LOW | 信息收集类、理论风险 | API 文档暴露、错误信息泄露内部路径 |

---

## 8. 常用工具清单

| 工具 | 用途 | 类型 |
|------|------|------|
| Burp Suite Pro | 手动测试 + 自动扫描 | 代理/扫描器 |
| OWASP ZAP | 自动化安全扫描 | 开源扫描器 |
| Postman/Insomnia | API 请求构造 | API 客户端 |
| jwt.io / jwt_tool | JWT 分析与篡改 | JWT 工具 |
| ffuf / dirsearch | 端点发现与模糊测试 | 目录爆破 |
| mitmproxy | 流量拦截与修改 | 代理 |
| Autorize (Burp 插件) | 自动化越权检测 | Burp 插件 |
| AuthMatrix (Burp 插件) | 权限矩阵自动验证 | Burp 插件 |
| Python requests | 自定义测试脚本 | 脚本 |
| nuclei | 基于模板的漏洞扫描 | 扫描器 |

### Burp Suite Autorize 插件使用方法

```
1. 安装 Autorize 插件
2. 配置低权限用户的 Cookie/Token
3. 以高权限用户正常浏览应用
4. Autorize 自动用低权限 Token 重放每个请求
5. 对比响应差异，标记潜在越权点
```

---

## 9. 检查清单 (Checklist)

### 水平越权 (IDOR)

- [ ] 所有 CRUD 端点的路径参数 ID 已测试
- [ ] 所有查询参数中的 ID/引用已测试
- [ ] 请求体中的 ID 字段已测试（Mass Assignment）
- [ ] 文件上传/下载端点已测试
- [ ] 批量操作接口已测试
- [ ] ID 可预测性已评估
- [ ] 跨租户资源引用已测试
- [ ] 关联资源的间接引用已测试
- [ ] GraphQL 查询中的 ID 参数已测试（如适用）
- [ ] WebSocket 消息中的 ID 已测试（如适用）

### 垂直越权

- [ ] 权限矩阵已建立并全量验证
- [ ] 每个角色对每个端点的访问已验证
- [ ] 自我提权（修改 role 字段）已测试
- [ ] HTTP 方法覆盖已测试
- [ ] 管理员端点对普通用户的防护已测试
- [ ] 只读用户的写操作已测试
- [ ] JWT/Token 篡改已测试
- [ ] 参数级权限绕过已测试（隐藏字段注入）
- [ ] 跨租户角色隔离已测试

### 未授权访问

- [ ] 所有端点无 Token 访问已测试
- [ ] 无效/过期/吊销 Token 已测试
- [ ] 公开端点白名单已审查
- [ ] 敏感端点暴露已检查（swagger, debug, metrics）
- [ ] CORS 配置已验证
- [ ] 路径遍历/编码绕过已测试
- [ ] 静态资源/上传文件的访问控制已测试
- [ ] 认证类型混淆已测试（Bearer vs Basic）

### 多租户

- [ ] 列表查询的租户隔离已验证
- [ ] 搜索功能的租户隔离已验证
- [ ] 聚合/统计数据的租户隔离已验证
- [ ] 租户切换功能的安全性已验证
- [ ] 共享资源的访问控制已验证

---

## 10. 修复建议总则

### 架构层面

1. **统一鉴权中间件**: 所有 API 请求必须经过统一的认证和授权中间件，不允许端点自行实现鉴权
2. **资源归属校验**: 数据访问层强制绑定当前用户/租户，SQL 查询自动附加 `tenant_id = ?` 条件
3. **最小权限原则**: 默认拒绝，显式授权。新端点未配置权限时应默认 403
4. **不可预测标识符**: 使用 UUIDv4 作为资源 ID（纵深防御，非替代鉴权）

### 代码层面

```python
# 反例 — 仅凭 ID 查询，无归属校验
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str):
    return db.query("SELECT * FROM orders WHERE id = ?", order_id)

# 正例 — 强制校验资源归属
@app.get("/api/v1/orders/{order_id}")
@require_auth
def get_order(order_id: str, current_user: User):
    order = db.query(
        "SELECT * FROM orders WHERE id = ? AND tenant_id = ?",
        order_id, current_user.tenant_id
    )
    if not order:
        raise HTTPException(404)
    if order.user_id != current_user.id and not current_user.has_role("admin"):
        raise HTTPException(403)
    return order
```

### 测试层面

1. **CI/CD 集成**: 将权限矩阵测试集成到 CI 流水线，每次部署自动验证
2. **回归测试**: 每个越权漏洞修复后，将其测试用例加入回归测试套件
3. **定期审计**: 每季度执行一次完整的越权访问测试
