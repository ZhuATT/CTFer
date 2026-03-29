# 文件包含 经验积累

## 2026-03-28 | 4114e2db-03df-4bae-aec7-a506fd06bf33.challenge.ctf.show
### 靶机环境
- WAF 检查: preg_match("/^(\.|\/)/", $path) - 禁止以.或/开头的路径
- WAF 还检查敏感字符: data|log|access|pear|tmp|zlib|filter|:
- flag 目标位置: /flag.txt

### 成功方法
- **fake_prefix_directory_traversal_bypass**

### 关键 Payload
```
mmm/../../../../../../../../flag.txt
```

### 绕过原理
- WAF 只检查路径是否以 `.` 或 `/` 开头
- 前缀 `mmm` 不存在，路径穿越时自动忽略
- 后续的 `../../../../../../../../` 导航回根目录
- 最终访问 `/flag.txt` 成功

### 已尝试方法（失败）
- 路径遍历尝试 - 多次失败

### Flag
`CTF{file_path_bypass_is_fun}`

---

---
doc_kind: experience
type: lfi
created: 2026-03-29
tags: [lfi, php://filter, base64]
---

## php://filter/base64编码读取源码

### 核心 bypass
**php://filter/base64编码读取源码**

### 原理
- 参数 page=xxx 存在文件包含

### 关键 payload
```bash
?page=php://filter/convert.base64-encode/resource=index.php
```

### 失败记录
- php://filter 读取 base64 编码内容

---

---
doc_kind: experience
type: lfi
created: 2026-03-29
tags: [lfi, php://filter, base64]
---

## php://filter/base64编码 读取源码

### 核心 bypass
**php://filter/base64编码 读取源码**

### 原理
- 参数 page=xxx 存在文件包含
- 使用 php://filter 将文件内容 base64 编码输出

### 关键 payload
```bash
?page=php://filter/convert.base64-encode/resource=index.php
```

### 失败记录
- ../ 路径遍历
- file:// 协议

---

## 2026-03-28 | https:
### 靶机环境
- db.php 包含数据库配置信息
- 密码字段值: CTF{3ecret_passw0rd_here}

### 成功方法
- **php://filter_base64_读取db.php**

### 已尝试方法（失败）
- php://filter + base64 编码读取源码

### Flag
`CTF{3ecret_passw0rd_here}`

---

## 2026-03-28 | https:
### 靶机环境
- 日志文件: /var/log/nginx/access.log
- flag位置: /var/www/html/flag.php

### 成功方法
- **日志文件包含: nginx access.log + User-Agent注入PHP代码**

### 已尝试方法（失败）
- 日志文件包含 + User-Agent注入PHP代码
- 直接包含 /var/www/html/flag.php 失败

### Flag
`CTF{php_access_l0g_lf1_is_fun}`

---

