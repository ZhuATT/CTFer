
## Content-Type 欺骗绕过

### 核心 bypass
通过伪造图片 Content-Type 绕过 PHP 后端基于 $_FILES['file']['type'] 的文件类型校验

### payload
python requests 上传时指定 Content-Type: image/png

### 原理分析
- PHP 后端使用 $_FILES['file']['type'] 获取客户端提交的 Content-Type，该值可被客户端伪造
- 服务器仅校验 Content-Type 而不校验文件内容或扩展名
- 攻击者上传恶意文件但伪装 Content-Type 为图片类型即可绕过

### 失败方法
- 直接上传 .php → 前端JS扩展名校验拦截
- webshell 命令执行 → 未成功返回结果

### 适用场景
- 后端使用 $_FILES['file']['type'] 做类型校验
- 前端仅做扩展名检查
- 黑名单扩展名但未校验 Content-Type

### 案例
| 日期 | 靶机 | 成功方法 | Flag |
|------|------|---------|------|
| 2026-03-29 | 356987df-612d-4633-bafe-5a7bbf42b41d.challenge.ctf.show | Content-Type 欺骗绕过 | ctfshow{1984f157-5812-4953-9585-9d2240f61a72} |
## .htaccess AddType 绕过上传限制

### 核心 bypass
通过上传 .htaccess 文件使用 AddType 指令将图片扩展名映射为 PHP 代码执行

### payload
AddType application/x-httpd-php .jpg

### 原理分析
- Apache 允许 .htaccess 覆盖主配置文件中的 MIME 类型设置
- AddType 指令可改变文件扩展名到 MIME 类型的映射关系
- 将 .jpg 文件映射为 application/x-httpd-php 后，服务器会把 jpg 文件当作 PHP 解析
- 绕过前端 JS 扩展名校验（仅检查是否为图片扩展名）
- 后端仅检查 Content-Type 而不验证 .htaccess 文件内容

### 失败方法
- .htaccess 绕过 → 表述过于宽泛，需明确具体指令
- Content-Type: image/jpeg 绕过扩展名检查 → 只能绕过 Content-Type 校验，文件仍以图片处理
- .phtml 扩展名上传 → 服务器作为静态文件处理，不执行 PHP 代码
- .php5 扩展名上传 → 同 .phtml，服务器未配置解析

### 适用场景
- Apache 服务器配置
- 上传目录可被访问且解析
- 前端限制上传扩展名（白名单）
- 后端未过滤 .htaccess 文件内容
- 服务器未禁用 .htaccess 覆盖功能

### 案例
| 日期 | 靶机 | 成功方法 | Flag |
|------|------|---------|------|
| 2026-03-30 | b304df13-1c3f-495a-9414-59f8b0100201.challenge.ctf.show | .htaccess AddType 绕过 | ctfshow{b0cfcc89-0eae-4eb5-bb1e-88a9c2332b6d} |