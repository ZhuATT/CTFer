# Tomcat + MySQL + Redis + Nginx 配置安全检查清单

> 适用场景：接手无文档的老项目，阿里云 ECS 部署，逐项排查默认配置风险。
> 检查方式：每项给出**检查命令**和**预期安全状态**，不符合则需整改。

---

## 一、操作系统与 ECS 基础

### 1.1 SSH 安全

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 1 | 禁止 root 直接登录 | `grep "^PermitRootLogin" /etc/ssh/sshd_config` | `PermitRootLogin no` |
| 2 | 禁止密码登录，仅允许密钥 | `grep "^PasswordAuthentication" /etc/ssh/sshd_config` | `PasswordAuthentication no` |
| 3 | SSH 端口是否改为非 22 | `grep "^Port" /etc/ssh/sshd_config` | 非 22 端口（如 2222） |
| 4 | 空闲超时断开 | `grep "ClientAliveInterval" /etc/ssh/sshd_config` | 设置合理值（如 300） |
| 5 | 最大认证尝试次数 | `grep "MaxAuthTries" /etc/ssh/sshd_config` | `MaxAuthTries 3` |

### 1.2 系统用户与权限

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 6 | 各服务是否以独立非 root 用户运行 | `ps aux \| grep -E "(java\|mysql\|redis\|nginx)" \| awk '{print $1}'` | 分别为 tomcat/mysql/redis/nginx 等非 root 用户 |
| 7 | 是否存在空密码账户 | `awk -F: '($2 == "") {print $1}' /etc/shadow` | 无输出 |
| 8 | sudo 权限是否收紧 | `cat /etc/sudoers.d/*; grep -v "^#" /etc/sudoers \| grep -v "^$"` | 仅必要用户有 sudo，且限制具体命令 |

### 1.3 防火墙与安全组

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 9 | iptables/firewalld 是否启用 | `systemctl status firewalld; iptables -L -n` | 防火墙处于 active 状态，有规则 |
| 10 | 阿里云安全组规则 | 阿里云控制台 > ECS > 安全组 > 查看规则 | 仅开放 80/443/SSH 端口，来源 IP 限制 |
| 11 | MySQL 端口(3306)是否对外暴露 | `iptables -L -n \| grep 3306; ss -tlnp \| grep 3306` | 3306 仅监听 127.0.0.1，安全组不开放 |
| 12 | Redis 端口(6379)是否对外暴露 | `ss -tlnp \| grep 6379` | 6379 仅监听 127.0.0.1，安全组不开放 |
| 13 | Tomcat 管理端口(8080/8443)是否对外暴露 | `ss -tlnp \| grep -E "8080\|8443"` | 仅监听 127.0.0.1（由 Nginx 反代），安全组不开放 |

### 1.4 系统更新与内核

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 14 | 系统是否有未修复的安全补丁 | `yum check-update --security` 或 `apt list --upgradable` | 无高危安全更新待安装 |
| 15 | 内核版本是否过旧 | `uname -r` | 无已知高危漏洞的内核版本 |

---

## 二、Nginx 安全配置

### 2.1 信息泄露

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 16 | 隐藏 Nginx 版本号 | `grep "server_tokens" /etc/nginx/nginx.conf` | `server_tokens off;` |
| 17 | 响应头中是否泄露版本 | `curl -sI http://localhost \| grep Server` | `Server: nginx`（无版本号） |
| 18 | 移除 X-Powered-By 等多余头 | `curl -sI http://localhost \| grep -iE "x-powered-by\|x-aspnet"` | 无输出 |

### 2.2 HTTPS 与证书

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 19 | 是否启用 HTTPS | `grep -r "ssl_certificate" /etc/nginx/` | 存在 SSL 证书配置 |
| 20 | 是否强制 HTTP 跳转 HTTPS | `grep -rA3 "listen 80" /etc/nginx/conf.d/` | 含 `return 301 https://` |
| 21 | SSL 协议版本 | `grep "ssl_protocols" /etc/nginx/nginx.conf` | `TLSv1.2 TLSv1.3`（禁用 TLSv1.0/1.1） |
| 22 | SSL 加密套件 | `grep "ssl_ciphers" /etc/nginx/nginx.conf` | 使用强加密套件，禁用 RC4/DES/3DES/MD5 |
| 23 | HSTS 头 | `grep "Strict-Transport-Security" /etc/nginx/` -r` | `max-age=31536000; includeSubDomains` |
| 24 | 证书是否即将过期 | `echo \| openssl s_client -connect localhost:443 2>/dev/null \| openssl x509 -noout -dates` | 有效期 > 30 天 |

### 2.3 安全头

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 25 | X-Frame-Options | `curl -sI https://localhost \| grep -i x-frame` | `DENY` 或 `SAMEORIGIN` |
| 26 | X-Content-Type-Options | `curl -sI https://localhost \| grep -i x-content-type` | `nosniff` |
| 27 | X-XSS-Protection | `curl -sI https://localhost \| grep -i x-xss` | `1; mode=block` |
| 28 | Content-Security-Policy | `curl -sI https://localhost \| grep -i content-security` | 存在合理 CSP 策略 |
| 29 | Referrer-Policy | `curl -sI https://localhost \| grep -i referrer` | `strict-origin-when-cross-origin` 或更严格 |

### 2.4 访问控制与限流

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 30 | 禁止目录列表 | `grep "autoindex" /etc/nginx/ -r` | `autoindex off;` 或无此指令（默认 off） |
| 31 | 敏感路径访问控制 | `grep -rE "location.*(admin\|manager\|status\|\.git\|\.env\|\.svn)" /etc/nginx/` | 敏感路径有 `deny all` 或 IP 白名单 |
| 32 | 请求体大小限制 | `grep "client_max_body_size" /etc/nginx/nginx.conf` | 设置合理值（如 10m），非默认 1m 也非无限制 |
| 33 | 连接数/请求速率限制 | `grep -rE "limit_req_zone\|limit_conn_zone" /etc/nginx/` | 存在限流配置 |
| 34 | 反向代理超时设置 | `grep -rE "proxy_connect_timeout\|proxy_read_timeout" /etc/nginx/` | 设置合理超时（如 60s），避免默认无限等待 |

### 2.5 日志

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 35 | 访问日志是否开启 | `grep "access_log" /etc/nginx/nginx.conf` | `access_log` 指向有效路径，非 off |
| 36 | 错误日志是否开启 | `grep "error_log" /etc/nginx/nginx.conf` | `error_log` 指向有效路径，级别为 warn 或 error |
| 37 | 日志文件权限 | `ls -la /var/log/nginx/` | 权限 640 或更严格，属主为 nginx/root |

---

## 三、Tomcat 安全配置

### 3.1 默认凭据与管理页面

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 38 | 是否存在默认管理用户 | `cat $CATALINA_HOME/conf/tomcat-users.xml \| grep -v "<!--"` | 无默认用户（admin/tomcat/manager），或文件为空注释 |
| 39 | Manager App 是否可访问 | `curl -s http://localhost:8080/manager/html -o /dev/null -w "%{http_code}"` | 404 或 403（应删除或限制访问） |
| 40 | Host Manager 是否可访问 | `curl -s http://localhost:8080/host-manager/html -o /dev/null -w "%{http_code}"` | 404 或 403 |
| 41 | 默认示例应用是否删除 | `ls $CATALINA_HOME/webapps/ \| grep -E "examples\|docs\|ROOT"` | 无 examples、docs 目录；ROOT 为业务应用或已删除 |

### 3.2 信息泄露

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 42 | 隐藏 Tomcat 版本号 | `grep "server=" $CATALINA_HOME/conf/server.xml` | Connector 中含 `server=""`（自定义值或空） |
| 43 | 自定义错误页面 | `grep "<error-page>" $CATALINA_HOME/conf/web.xml` | 定义了 404/500 等错误页面，不暴露堆栈 |
| 44 | 禁止目录列表 | `grep "listings" $CATALINA_HOME/conf/web.xml` | `<param-value>false</param-value>` |
| 45 | X-Powered-By 头 | `grep "xpoweredBy" $CATALINA_HOME/conf/server.xml` | `xpoweredBy="false"` 或无此属性（默认 false） |

### 3.3 连接器安全

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 46 | AJP 连接器是否禁用或设密钥 | `grep -i "AJP" $CATALINA_HOME/conf/server.xml \| grep -v "<!--"` | AJP 连接器已注释/删除，或设置了 `secret`/`requiredSecret` |
| 47 | Shutdown 端口 | `grep "shutdown=" $CATALINA_HOME/conf/server.xml` | 端口改为 -1（禁用），或改为非默认 8005 且 shutdown 字符串已更改 |
| 48 | Connector 绑定地址 | `grep "address=" $CATALINA_HOME/conf/server.xml` | 8080 绑定 `127.0.0.1`（Nginx 反代场景） |
| 49 | maxPostSize 限制 | `grep "maxPostSize" $CATALINA_HOME/conf/server.xml` | 设置合理值（如 2097152 = 2MB） |

### 3.4 会话与 Cookie

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 50 | Cookie HttpOnly | `grep "httpOnly" $CATALINA_HOME/conf/context.xml` | `useHttpOnly="true"` |
| 51 | Cookie Secure 标志 | `grep -i "secure" $CATALINA_HOME/conf/web.xml` | `<secure>true</secure>`（HTTPS 场景） |
| 52 | Session 超时 | `grep "session-timeout" $CATALINA_HOME/conf/web.xml` | 合理值（如 30 分钟），非默认无限 |
| 53 | JSESSIONID 不出现在 URL | `grep "tracking-mode" $CATALINA_HOME/conf/web.xml` | `<tracking-mode>COOKIE</tracking-mode>` |

### 3.5 JVM 与运行安全

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 54 | Tomcat 运行用户 | `ps aux \| grep java \| grep -v grep \| awk '{print $1}'` | 非 root 用户 |
| 55 | CATALINA_HOME 目录权限 | `ls -la $CATALINA_HOME/` | conf/ 目录权限 700，属主为 tomcat 用户 |
| 56 | 日志目录权限 | `ls -la $CATALINA_HOME/logs/` | 权限 750 或更严格 |
| 57 | JMX 远程是否开放 | `ps aux \| grep java \| grep -o "jmxremote[^ ]*"` | 未启用远程 JMX，或设置了认证和 SSL |
| 58 | Debug 模式是否关闭 | `ps aux \| grep java \| grep "agentlib:jdwp"` | 无输出（生产不开 debug 端口） |

### 3.6 Tomcat 版本

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 59 | Tomcat 版本是否过旧 | `$CATALINA_HOME/bin/version.sh 2>/dev/null \|\| java -cp $CATALINA_HOME/lib/catalina.jar org.apache.catalina.util.ServerInfo` | 当前大版本的最新安全补丁版本 |

---

## 四、MySQL 安全配置

### 4.1 认证与用户

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 60 | root 是否有密码 | `mysql -u root -e "SELECT 1" 2>&1` | 报错 `Access denied`（有密码保护） |
| 61 | 是否存在匿名用户 | `mysql -e "SELECT user,host FROM mysql.user WHERE user=''"` | 无结果 |
| 62 | 是否存在空密码用户 | `mysql -e "SELECT user,host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL"` | 无结果 |
| 63 | root 是否限制远程登录 | `mysql -e "SELECT user,host FROM mysql.user WHERE user='root'"` | host 仅为 localhost/127.0.0.1 |
| 64 | 是否删除 test 数据库 | `mysql -e "SHOW DATABASES LIKE 'test'"` | 无结果 |
| 65 | 业务账号权限最小化 | `mysql -e "SHOW GRANTS FOR 'appuser'@'localhost'"` | 仅授予业务所需的最小权限，无 GRANT OPTION |
| 66 | 是否运行过 mysql_secure_installation | 综合检查上述 60-64 | 全部通过 |

### 4.2 网络与监听

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 67 | 绑定地址 | `grep "bind-address" /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null` | `bind-address = 127.0.0.1` |
| 68 | skip-networking（如不需要远程） | `grep "skip-networking" /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null` | 如果仅本机应用访问，建议启用 |
| 69 | 端口是否为默认 3306 | `grep "port" /etc/my.cnf \| head -1` | 建议更改为非默认端口（纵深防御） |

### 4.3 文件与权限

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 70 | local-infile 是否禁用 | `mysql -e "SHOW VARIABLES LIKE 'local_infile'"` | `OFF` |
| 71 | symbolic-links 是否禁用 | `mysql -e "SHOW VARIABLES LIKE 'symbolic_links'"` 或 `grep "symbolic-links" /etc/my.cnf` | `skip-symbolic-links` 或值为 `OFF` |
| 72 | secure_file_priv 是否设置 | `mysql -e "SHOW VARIABLES LIKE 'secure_file_priv'"` | 设置为特定目录或 NULL（禁止 LOAD DATA OUTFILE） |
| 73 | 数据目录权限 | `ls -la /var/lib/mysql/` | 属主 mysql:mysql，权限 750 |
| 74 | 配置文件权限 | `ls -la /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null` | 权限 640 或更严格 |

### 4.4 日志与审计

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 75 | 错误日志是否开启 | `mysql -e "SHOW VARIABLES LIKE 'log_error'"` | 有有效路径 |
| 76 | 慢查询日志 | `mysql -e "SHOW VARIABLES LIKE 'slow_query_log'"` | `ON`（生产环境建议开启） |
| 77 | 通用查询日志（生产关闭） | `mysql -e "SHOW VARIABLES LIKE 'general_log'"` | `OFF`（生产不开，性能影响大且可能记录敏感数据） |
| 78 | 二进制日志 | `mysql -e "SHOW VARIABLES LIKE 'log_bin'"` | `ON`（用于恢复和审计） |

### 4.5 其他

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 79 | MySQL 版本 | `mysql --version` | 无已知高危 CVE 的版本 |
| 80 | 密码策略（5.7+） | `mysql -e "SHOW VARIABLES LIKE 'validate_password%'"` | 启用密码验证插件，策略 MEDIUM 或以上 |

---

## 五、Redis 安全配置

### 5.1 认证与访问

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 81 | 是否设置了密码 | `grep "^requirepass" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | `requirepass <强密码>`（非空、非 foobared） |
| 82 | 绑定地址 | `grep "^bind" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | `bind 127.0.0.1`（不绑定 0.0.0.0） |
| 83 | protected-mode | `grep "^protected-mode" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | `protected-mode yes` |
| 84 | 是否以 root 运行 | `ps aux \| grep redis-server \| grep -v grep \| awk '{print $1}'` | 非 root（如 redis 用户） |

### 5.2 危险命令

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 85 | 禁用/重命名危险命令 | `grep -E "^rename-command" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 至少重命名以下命令：`FLUSHALL`、`FLUSHDB`、`CONFIG`、`KEYS`、`DEBUG`、`EVAL` |
| 86 | CONFIG 命令是否可远程执行 | `redis-cli -a <password> CONFIG GET dir 2>/dev/null` | 被拒绝或已重命名 |

### 5.3 持久化与文件

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 87 | RDB/AOF 文件目录权限 | `ls -la $(grep "^dir" /etc/redis/redis.conf \| awk '{print $2}')` | 属主 redis，权限 750 |
| 88 | 日志文件 | `grep "^logfile" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 指向有效路径，非空 |

### 5.4 版本与网络

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 89 | Redis 版本 | `redis-server --version` | >= 6.0（支持 ACL），无已知高危 CVE |
| 90 | 最大内存限制 | `grep "^maxmemory" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 设置了上限（防止 OOM） |
| 91 | 超时断开空闲连接 | `grep "^timeout" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 设置合理值（如 300） |

---

## 六、应用层安全（通用检查）

### 6.1 敏感信息

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 92 | 配置文件中是否有明文密码 | `grep -rn -iE "(password\|passwd\|secret\|api.key)\s*=" /path/to/app/conf/ \| head -20` | 密码使用加密存储或环境变量注入，非明文 |
| 93 | 数据库连接串是否加密 | 检查应用的 `application.properties` / `server.xml` 的 DataSource | 使用 Jasypt 加密或环境变量 |
| 94 | .git 目录是否暴露在 Web 根目录 | `ls -la /path/to/webroot/.git 2>/dev/null` | 不存在，或 Nginx 已拦截 |
| 95 | 备份文件是否暴露 | `find /path/to/webroot -name "*.bak" -o -name "*.sql" -o -name "*.tar.gz" -o -name "*.zip" 2>/dev/null` | 无备份文件在 Web 可访问目录 |

### 6.2 日志安全

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 96 | 日志中是否记录敏感信息 | `grep -rn -iE "(password\|token\|secret\|credit.card)" /path/to/app/logs/ \| head -10` | 无敏感信息输出到日志 |
| 97 | 日志是否有轮转机制 | `ls /etc/logrotate.d/ \| grep -iE "nginx\|tomcat\|mysql\|redis"` | 存在对应的 logrotate 配置 |

---

## 七、定时任务与后门排查

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 98 | 可疑 crontab | `for u in $(cut -f1 -d: /etc/passwd); do echo "==$u=="; crontab -u $u -l 2>/dev/null; done` | 无可疑的下载/反弹 shell 任务 |
| 99 | 可疑开机启动项 | `systemctl list-unit-files --state=enabled` | 无不认识的服务 |
| 100 | 可疑网络连接 | `ss -tlnp; ss -tnp \| grep ESTABLISHED` | 无连接到可疑外部 IP/端口（如 IRC 6667、反弹 shell） |
| 101 | 异常 SUID 文件 | `find / -perm -4000 -type f 2>/dev/null` | 仅系统标准 SUID 文件（passwd, sudo, ping 等） |
| 102 | /tmp 目录可疑文件 | `ls -la /tmp/ /var/tmp/ /dev/shm/` | 无可疑脚本或二进制文件 |
| 103 | authorized_keys 是否被篡改 | `find /root /home -name "authorized_keys" -exec md5sum {} \;` | 仅包含已知的公钥 |

---

## 八、备份与恢复

| # | 检查项 | 检查命令 | 安全状态 |
|---|--------|----------|----------|
| 104 | MySQL 是否有定期备份 | `crontab -l \| grep -i "mysqldump\|xtrabackup"` | 存在定期备份计划 |
| 105 | 备份文件是否加密存储 | `file /path/to/backup/*.sql*` | 使用 gpg 加密或存储在加密卷 |
| 106 | 备份是否有异地副本 | 检查是否有 OSS/S3 同步脚本 | 至少一份异地备份 |
| 107 | ECS 快照策略 | 阿里云控制台 > ECS > 快照策略 | 开启自动快照，保留 >= 7 天 |

---

## 九、阿里云特定检查

| # | 检查项 | 检查方式 | 安全状态 |
|---|--------|----------|----------|
| 108 | RAM 子账号权限 | 阿里云控制台 > RAM > 用户 | 遵循最小权限原则，无全权限子账号 |
| 109 | AccessKey 泄露检查 | `grep -rn "LTAI" /path/to/app/ 2>/dev/null` | 代码/配置中无硬编码 AK |
| 110 | 安骑士/云安全中心 | 阿里云控制台 > 云安全中心 | 已安装且无未处理告警 |
| 111 | ECS 实例元数据访问限制 | `curl -s --connect-timeout 2 http://100.100.100.200/latest/meta-data/` | 应用内部不应能随意访问（防 SSRF） |

---

## 检查优先级建议

**P0 - 立即修复（可被直接利用）：**
- Redis 无密码 + 绑定 0.0.0.0（#81, #82）— 可直接写 crontab 反弹 shell
- MySQL root 无密码或允许远程登录（#60, #63, #67）
- Tomcat Manager 使用默认凭据可访问（#38, #39）
- AJP 连接器开放（Ghostcat 漏洞）（#46）
- SSH root 密码登录（#1, #2）

**P1 - 尽快修复（扩大攻击面）：**
- 服务以 root 运行（#6, #54, #84）
- 安全组过度开放（#10, #11, #12, #13）
- 敏感路径/默认应用未移除（#31, #41）
- .git / 备份文件暴露（#94, #95）
- 代码中硬编码 AK（#109）

**P2 - 计划修复（纵深防御）：**
- HTTPS 配置加固（#19-#24）
- 安全响应头（#25-#29）
- 版本信息泄露（#16, #42）
- 日志与审计完善（#75-#78, #96-#97）
- 备份策略（#104-#107）

---

## 快速一键扫描脚本

将以下脚本保存为 `quick-check.sh`，在 ECS 上以 root 执行，快速获取关键风险点：

```bash
#!/bin/bash
echo "====== 快速安全检查 ======"

echo -e "\n[1] SSH 配置"
grep -E "^(PermitRootLogin|PasswordAuthentication|Port)" /etc/ssh/sshd_config 2>/dev/null

echo -e "\n[2] 服务运行用户"
ps aux | grep -E "(java|mysql|redis|nginx)" | grep -v grep | awk '{print $1, $11}' | sort -u

echo -e "\n[3] 监听端口"
ss -tlnp | grep -E "(3306|6379|8080|8443|8005|22)"

echo -e "\n[4] Redis 密码"
grep "^requirepass" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null || echo "警告: 未找到 requirepass 配置！"

echo -e "\n[5] Redis 绑定地址"
grep "^bind" /etc/redis/redis.conf /etc/redis.conf 2>/dev/null

echo -e "\n[6] MySQL 绑定地址"
grep "bind-address" /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null

echo -e "\n[7] Tomcat AJP"
grep -i "AJP" $CATALINA_HOME/conf/server.xml 2>/dev/null | grep -v "<!--"

echo -e "\n[8] Tomcat Manager 用户"
grep -v "<!--" $CATALINA_HOME/conf/tomcat-users.xml 2>/dev/null | grep -i "user "

echo -e "\n[9] Nginx server_tokens"
grep "server_tokens" /etc/nginx/nginx.conf 2>/dev/null

echo -e "\n[10] 可疑 crontab"
for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null | grep -v "^#" | grep -v "^$"; done

echo -e "\n[11] SUID 文件"
find / -perm -4000 -type f 2>/dev/null | grep -v -E "/(sudo|passwd|ping|mount|umount|su|chfn|chsh|newgrp|gpasswd|pkexec)"

echo -e "\n[12] 安全组（需在阿里云控制台确认）"
echo "请手动检查安全组规则：仅开放 80/443/SSH"

echo -e "\n====== 检查完毕 ======"
```

---

> **使用建议**：逐节检查，优先处理 P0 级问题。每修复一项，在对应行标注 `[已修复] + 日期`，作为整改记录留档。
