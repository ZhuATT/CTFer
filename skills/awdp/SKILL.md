# AWDP 攻防赛制知识库

## 赛制概述
- **AWDP** = Attack With Defense Plus，攻防兼备
- 两个板块：**Break**（攻击自己的题）+ **Fix**（修复主办方的攻击）
- 通俗讲：**CTF + 反CTF**
- **核心技巧**：Fix一般比Break容易，优先修复

## 常见漏洞修复手段

| 漏洞类型 | 修复方法 |
|---------|---------|
| SQL注入 | addslashes()、**预处理（推荐）** |
| 文件上传 | 白名单后缀、内容WAF、MIME验证、二次处理 |
| SSTI | WAF（只过滤`{`不行） |
| 原型链污染 | 注释污染代码、扩充黑名单 |
| 代码审计/RCE | WAF、注释漏洞代码 |
| Java反序列化 | 上调库版本、黑名单类 |
| 源码泄露 | 删除www.zip/.git等 |

## PHP WAF 示例

### RCE WAF
```php
function wafrce($str){
    return !preg_match("/openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|scandir|assert|pcntl_exec|fwrite|curl|system|eval|flag|passthru|exec|chroot|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore/i", $str);
}
```

### SQL注入 WAF
```php
function wafsqli($str){
    return !preg_match("/select|and|\*|\x09|\x0a|\x0b|\x0c|\x0d|\xa0|\x00|\x26|\x7c|or|into|from|where|join|sleexml|extractvalue|+|regex|copy|read|file|create|grand|dir|insert|link|server|drop|=|>|<|;|\"|\'|\^|\|/i", $str);
}
```

### 通用WAF（放漏洞点前）
```php
$str1 ="";
foreach ($_POST as $key => $value) {
    $str1.=$key;
    $str1.=$value;
}
$str2 ="";
foreach ($_GET as $key => $value) {
    $str2.=$key;
    $str2.=$value;
}
if (preg_match("/system|tail|flag|\'|\"|\<|\{|\}|exec|base64|phpinfo|<\?|\"/i", $str1)||preg_match("/system|tail|flag|\'|\"|\<|\{|\}|exec|base64|phpinfo|<\?|\"/i", $str2)) {
    die('no!');
}
```

### ThinkPHP框架防护（放public/index.php最前）
```php
foreach($_REQUEST as $key=>$value) {
    $_POST[$key] = preg_replace("/construct|get|call_user_func|load|invokefunction|Session|phpinfo|param1|Runtime|assert|input|dump|checkcode|union|select|updatexml|@/i",'',$value);
    $_GET[$key] = preg_replace("/construct|get|call_user_func|load|invokefunction|Session|phpinfo|param1|Runtime|assert|input|dump|checkcode|union|select|updatexml|@/i",'',$value);
}
```

## Python WAF 示例

```python
black_list = ["{{","}}", "'", '"', '_', '[','.','%','+','|','(',')', '{','}','\\','/']
for tmp in black_list:
    if tmp in v:
        raise ValueError("note cannot contain a special character")
```

## 文件上传修复

```php
// 1. 生成随机文件名
$new_filename = bin2hex(random_bytes(16)) . '.png';
$upload_path = '/var/www/uploads/';

// 2. 验证文件内容确实是PNG
$image_info = getimagesize($_FILES['myfile']['tmp_name']);
if ($image_info === false || $image_info[2] !== IMAGETYPE_PNG) {
    die('文件不是有效的PNG图片');
}

// 3. 移动文件到安全目录
if (move_uploaded_file($_FILES['myfile']['tmp_name'], $upload_path . $new_filename)) {
    echo '文件上传成功';
}
```

## Java反序列化修复

```java
public class NewObjectInputStream extends ObjectInputStream {
    private static final Set<String> BLACKLISTED_CLASSES = new HashSet();
    static {
        BLACKLISTED_CLASSES.add("java.lang.Runtime");
        BLACKLISTED_CLASSES.add("java.lang.ProcessBuilder");
        BLACKLISTED_CLASSES.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (BLACKLISTED_CLASSES.contains(desc.getName())) {
            throw new SecurityException("");
        }
        return super.resolveClass(desc);
    }
}
```

## Patch包格式

### PHP
```sh
#!/bin/bash
cp /index.php /var/www/html/index.php
```

### Python
```sh
#!/bin/sh
cp /app.py /app/app.py
ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9
cd /app && nohup python app.py >> /opt/app.log 2>&1 &
```

### Nodejs
```sh
#!/bin/sh
cp server.js /app/server.js
ps -ef | grep node | grep -v grep | awk '{print $2}' | xargs kill -9
cd /app && nohup node server.js >> /opt/aa.log 2>&1 &
```

### 打包
```sh
tar -zcvf patch.tar.gz main.py patch.sh
```

## 实战经典案例

### 1. 粗心的程序员（源码泄露+逻辑漏洞）
- **漏洞**：www.zip源码泄露 + 用户输入写入.php文件（RCE）
- **攻击**：`?>`截断 + 写入webshell
- **修复**：
```php
// 对username和$p加WAF
if (preg_match("/\?|\<\?|php|:/i",$username)){ die(""); }
if (preg_match("/\?|php|:|system|cat|flaaaaaag|\*|eval|php/i",$p)){ die(""); }
```

### 2. submit（文件上传绕过）
- **绕过**：`<script language="php">`标签绕过正则 + MIME修改 + 短标签
- **修复**：白名单+内容WAF+`getimagesize()`验证

### 3. Polluted（SSTI+原型链污染）
- **攻击**：Unicode转义绕过下划线过滤（`\u005f__class__`）
- **修复**：扩充黑名单 + ban掉adminer用户名

### 4. BabyMemo（Session伪造）
- **攻击**：利用备份功能伪造session文件，`admin|b:1`提权
- **修复**：ban掉`sess`用户名

### 5. fuzee_rce（科学计数法+自增RCE）
- **攻击**：GET传`?w1key=1e9`绕过数值检查，POST用自增写马
- **修复**：WAF增加更多字符过滤（`%`, `_`, `$`等）

### 6. Oh! My PDF（JWT伪造+WeasyPrint）
- **攻击**：空密钥伪造JWT → WeasyPrint的`<link>`标签SSRF读flag
- **修复**：验证JWT签名、禁止加载HTML文件

### 7. ezSSTI
- **攻击**：fenjing生成绕过WAF的SSTI payload
- **修复**：过滤更多字符包括单引号、`{`、数字等

### 8. easyupload（Apache解析漏洞）
- **攻击**：文件名`shell.php.txt`利用Apache解析漏洞
- **修复**：黑名单变白名单 + 限制只能有一个点号

## 注意事项

1. **WAF语法要准**：本地先测试，语法错误会导致服务异常（被判宕机）
2. **优先Fix**：修复比攻击容易，Check通过率更高
3. **断网环境**：Java可直接升版本，Python可用vps开http服务
4. **检测状态**：通过/未通过/服务异常（过滤太严格会异常）
5. **白名单优于黑名单**：尽量用白名单，安全性更高

## 参考资料
- CISCN 2024 AWDP 赛题
- 羊城杯2023 AWDP
- 楚慧杯2024