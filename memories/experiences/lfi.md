
## LFI - php://filter 读取源码

### 核心 bypass
通过 php://filter 协议配合 base64 编码绕过文件包含限制，读取任意 PHP 文件源码

### payload
php://filter/read=convert.base64-encode/resource=db.php

### 原理分析
- php://filter 是 PHP 内置的流包装器，可对文件进行编码/解码处理
- convert.base64-encode 过滤器将文件内容转为 base64 编码输出
- 直接读取 PHP 文件会被服务器解析执行，无法看到源码
- base64 编码后输出原始源码内容

### 失败方法
- file=/flag → WAF拦截
- ../../flag → 路径验证失败

### 适用场景
- LFI 漏洞读取 PHP 配置文件
- db.php, config.php, .env 等包含凭据的文件
- 读取源码寻找 hardcoded 密码或密钥

### 案例
| 日期 | 靶机 | 成功方法 | Flag |
|------|------|---------|------|
| 2026-03-29 | 8d68c862-97c6-44e8-98ea-6f185060b705.challenge.ctf.show | php://filter读取源码 | CTF{3secret_passw0rd_here} |
