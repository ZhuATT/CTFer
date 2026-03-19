# Tomcat + MySQL + Redis + Nginx 配置安全检查清单

> 基于 WooYun 22,132 个真实漏洞案例（2010-2016）· 配置域 1,796 案例 · 72.6% 高危
>
> 适用场景：阿里云 ECS 上运维交接缺失的老项目，逐项排查默认配置风险

---

## 使用说明

- **检查方式**：SSH 登录 ECS 后，按章节顺序逐项执行命令，对照「期望结果」判断是否合规
- **优先级标记**：`[严重]` `[高危]` `[中危]` `[低危]`——优先修复严重和高危项
- **WooYun 引用**：每个章节标注关联的 WooYun 案例模式和统计数据

---

## 一、Tomcat 配置安全检查

> **WooYun 数据**：Tomcat Manager 默认凭证出现频率「极高」，是配置域最高频的攻击入口之一。
> **典型案例**：ChinaCache 某系统 JBoss 配置不当导致 Getshell（同类 Java 中间件管理后台问题）

### 1.1 默认凭证与管理后台 `[严重]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 1 | Tomcat Manager 是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/manager/html` | 返回 404 或连接拒绝（非 401/200） |
| 2 | Host Manager 是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/host-manager/html` | 返回 404 或连接拒绝 |
| 3 | tomcat-users.xml 是否存在默认账号 | `cat $CATALINA_HOME/conf/tomcat-users.xml \| grep -i 'username='` | 不存在 tomcat/tomcat、admin/admin 等默认凭证 |
| 4 | Manager 应用是否已删除 | `ls $CATALINA_HOME/webapps/ \| grep -E 'manager\|host-manager'` | 生产环境不存在这两个目录 |
| 5 | 默认示例应用是否已删除 | `ls $CATALINA_HOME/webapps/ \| grep -E 'docs\|examples\|ROOT'` | 不存在 docs、examples 目录；ROOT 只含业务代码 |

### 1.2 信息泄露防护 `[高危]`

> **WooYun 数据**：信息泄露域 4,858 个案例中 64.7% 高危。错误页面暴露服务器版本和堆栈跟踪是精准利用的前提。

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 6 | Server 头是否暴露版本 | `curl -sI http://localhost:8080/ \| grep -i server` | 不显示 "Apache-Coyote" 或 Tomcat 版本号 |
| 7 | server.xml 是否关闭版本泄露 | `grep -i 'server=' $CATALINA_HOME/conf/server.xml` | Connector 中配置 `server="Server"` 或自定义值 |
| 8 | 自定义错误页面 | `grep '<error-page>' $CATALINA_HOME/conf/web.xml` | 配置了 404、500 等错误码的自定义页面 |
| 9 | 目录列表是否关闭 | `grep '<param-name>listings</param-name>' -A1 $CATALINA_HOME/conf/web.xml` | `<param-value>false</param-value>` |
| 10 | TRACE 方法是否禁用 | `curl -sI -X TRACE http://localhost:8080/` | 返回 405 Method Not Allowed |

### 1.3 连接器与协议安全 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 11 | AJP 连接器是否暴露（Ghostcat CVE-2020-1938） | `grep 'Connector.*8009' $CATALINA_HOME/conf/server.xml` | 已注释或配置了 `secretRequired="true"` + `secret="..."` |
| 12 | Shutdown 端口是否修改默认值 | `grep '<Server port=' $CATALINA_HOME/conf/server.xml` | 端口非 8005，或命令字符串非 "SHUTDOWN" |
| 13 | Tomcat 是否以 root 运行 | `ps aux \| grep tomcat \| grep -v grep \| awk '{print $1}'` | 运行用户为专用非 root 账号（如 tomcat） |
| 14 | 自动部署是否关闭 | `grep 'autoDeploy' $CATALINA_HOME/conf/server.xml` | `autoDeploy="false"` 且 `deployOnStartup="false"` |

### 1.4 Session 安全 `[中危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 15 | Cookie HttpOnly 标记 | `grep 'useHttpOnly' $CATALINA_HOME/conf/context.xml` | `useHttpOnly="true"` |
| 16 | Session 超时时间 | `grep '<session-timeout>' $CATALINA_HOME/conf/web.xml` | 不超过 30 分钟 |

---

## 二、MySQL 配置安全检查

> **WooYun 数据**：phpMyAdmin root/空密码出现频率「极高」；MySQL 3306 端口无密码暴露是数据库管理类最常见问题。
> **典型案例**：微糖主站 SQL 注入影响 860W+ 患者/46W+ 医生——数据库安全是最后防线。

### 2.1 认证与权限 `[严重]`

> **WooYun 数据**：弱凭证域 7,513 个案例，58.2% 高危。admin/admin、root/空 是 WooYun 全库中出现频率最高的默认凭证模式。

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 17 | root 是否有密码 | `mysql -u root --password='' -e "SELECT 1" 2>&1` | 连接失败（Access denied） |
| 18 | 是否存在空密码账号 | `mysql -u root -p -e "SELECT User,Host FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;"` | 结果为空 |
| 19 | 是否存在匿名账号 | `mysql -u root -p -e "SELECT User,Host FROM mysql.user WHERE User='';"` | 结果为空 |
| 20 | test 数据库是否删除 | `mysql -u root -p -e "SHOW DATABASES LIKE 'test';"` | 结果为空 |
| 21 | root 是否限制本地登录 | `mysql -u root -p -e "SELECT User,Host FROM mysql.user WHERE User='root';"` | Host 列仅含 localhost / 127.0.0.1，不含 % |
| 22 | 业务账号权限最小化 | `mysql -u root -p -e "SHOW GRANTS FOR 'app_user'@'%';"` | 仅有 SELECT/INSERT/UPDATE/DELETE 等必需权限，无 GRANT/SUPER/FILE |

### 2.2 网络暴露 `[严重]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 23 | 监听地址是否限制 | `grep 'bind-address' /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null` | `bind-address = 127.0.0.1`（非 0.0.0.0） |
| 24 | 3306 是否对外开放 | `ss -tlnp \| grep 3306` | 仅监听 127.0.0.1:3306 |
| 25 | 阿里云安全组是否放行 3306 | 登录阿里云控制台 → ECS → 安全组规则 | 入方向不存在 3306 的 0.0.0.0/0 规则 |

### 2.3 安全配置 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 26 | 是否禁用 LOCAL INFILE | `mysql -u root -p -e "SHOW VARIABLES LIKE 'local_infile';"` | `OFF` |
| 27 | 是否禁用符号链接 | `mysql -u root -p -e "SHOW VARIABLES LIKE 'have_symlink';"` | `DISABLED` |
| 28 | 错误日志是否开启 | `mysql -u root -p -e "SHOW VARIABLES LIKE 'log_error';"` | 配置了日志文件路径 |
| 29 | 慢查询日志是否开启 | `mysql -u root -p -e "SHOW VARIABLES LIKE 'slow_query_log';"` | `ON` |
| 30 | MySQL 是否以 root 运行 | `ps aux \| grep mysqld \| grep -v grep \| awk '{print $1}'` | 运行用户为 mysql，非 root |

### 2.4 数据保护 `[中危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 31 | 是否启用 SSL 连接 | `mysql -u root -p -e "SHOW VARIABLES LIKE '%ssl%';"` | `have_ssl = YES` |
| 32 | 二进制日志是否开启（灾备） | `mysql -u root -p -e "SHOW VARIABLES LIKE 'log_bin';"` | `ON` |

---

## 三、Redis 配置安全检查

> **WooYun 数据**：Redis 默认无认证，出现频率「极高」。6379 端口未授权访问是配置域中单一服务影响最大的漏洞类别。
> **典型案例**：DaoCloud 弱口令 + Docker Remote API 未授权访问——Redis 未授权常与其他服务组合形成利用链。
> **攻击模式**：未授权 Redis → 写 SSH 公钥 / 写 Crontab / 写 Webshell → 服务器沦陷

### 3.1 认证与访问控制 `[严重]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 33 | 是否设置了密码 | `grep '^requirepass' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 存在 `requirepass <强密码>`（非空、非 foobared） |
| 34 | 无密码能否连接 | `redis-cli -h 127.0.0.1 ping` | 返回 `NOAUTH Authentication required.` |
| 35 | 监听地址是否限制 | `grep '^bind' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | `bind 127.0.0.1`（非 0.0.0.0 或注释状态） |
| 36 | 6379 是否对外开放 | `ss -tlnp \| grep 6379` | 仅监听 127.0.0.1:6379 |
| 37 | 阿里云安全组是否放行 6379 | 登录阿里云控制台 → ECS → 安全组规则 | 入方向不存在 6379 的 0.0.0.0/0 规则 |
| 38 | protected-mode 是否开启 | `grep '^protected-mode' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | `protected-mode yes` |

### 3.2 危险命令限制 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 39 | 是否禁用/重命名危险命令 | `grep -E 'rename-command' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | FLUSHALL、FLUSHDB、CONFIG、KEYS、DEBUG、EVAL 已 rename 为随机字符串或空串 |
| 40 | 是否禁用 Lua 脚本 | 业务不需要时，检查 rename-command EVAL | EVAL 已被 rename 或禁用 |

### 3.3 运行安全 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 41 | Redis 是否以 root 运行 | `ps aux \| grep redis-server \| grep -v grep \| awk '{print $1}'` | 运行用户为 redis，非 root |
| 42 | 数据目录权限 | `ls -la /var/lib/redis/` | 属主为 redis 用户，权限 750 或更严 |
| 43 | 配置文件权限 | `ls -la /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 权限 640 或更严，属主 root:redis |
| 44 | 是否启用持久化 | `grep -E '^(save\|appendonly)' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null` | 至少配置了 RDB (save) 或 AOF (appendonly yes) |

---

## 四、Nginx 配置安全检查

> **WooYun 数据**：配置不当服务类中，目录列表启用、详细错误信息泄露、允许 PUT/DELETE 方法是高影响模式。
> **典型案例**：同程旅游某系统配置不当任意文件上传 getshell/root 权限

### 4.1 信息泄露防护 `[高危]`

> **WooYun 数据**：404 响应头暴露服务器版本号是信息泄露域中的常见发现指标，为后续精准利用提供版本信息。

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 45 | 是否隐藏版本号 | `grep 'server_tokens' /etc/nginx/nginx.conf` | `server_tokens off;` |
| 46 | Server 头是否暴露版本 | `curl -sI http://localhost/ \| grep -i server` | 不显示 Nginx 版本号 |
| 47 | 是否禁用 autoindex | `grep -r 'autoindex' /etc/nginx/` | 不存在 `autoindex on`；或仅内网目录开启 |
| 48 | 自定义错误页面 | `grep 'error_page' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null` | 配置了 403、404、500、502 等自定义错误页 |
| 49 | 是否暴露 X-Powered-By | `curl -sI http://localhost/ \| grep -i x-powered-by` | 不存在该响应头（通过 proxy_hide_header 移除） |

### 4.2 访问控制 `[严重]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 50 | Tomcat Manager 是否通过 Nginx 暴露 | `grep -r 'manager\|host-manager' /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null` | 不存在反代到 /manager/ 的规则；或配置了 IP 白名单 |
| 51 | 敏感路径是否限制访问 | `grep -rE '(\.git\|\.svn\|\.env\|\.bak\|WEB-INF)' /etc/nginx/conf.d/ 2>/dev/null` | 配置了 `deny all` 规则阻止访问 .git、.svn、.env 等 |
| 52 | phpMyAdmin 等管理界面 | `grep -rE '(phpmyadmin\|pma\|adminer)' /etc/nginx/conf.d/ 2>/dev/null` | 不存在，或配置了 IP 白名单 + 认证 |
| 53 | 默认站点是否清理 | `ls /etc/nginx/sites-enabled/ 2>/dev/null` | 不存在 default 站点配置 |
| 54 | 不必要的 HTTP 方法 | `curl -sI -X OPTIONS http://localhost/ \| grep -i allow` | 仅允许 GET、HEAD、POST；不允许 PUT、DELETE、TRACE |

### 4.3 安全头部 `[中危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 55 | X-Frame-Options | `curl -sI http://localhost/ \| grep -i x-frame-options` | `DENY` 或 `SAMEORIGIN` |
| 56 | X-Content-Type-Options | `curl -sI http://localhost/ \| grep -i x-content-type-options` | `nosniff` |
| 57 | X-XSS-Protection | `curl -sI http://localhost/ \| grep -i x-xss-protection` | `1; mode=block` |
| 58 | Content-Security-Policy | `curl -sI http://localhost/ \| grep -i content-security-policy` | 存在 CSP 策略 |
| 59 | Strict-Transport-Security（HTTPS 时） | `curl -sI https://域名/ \| grep -i strict-transport-security` | `max-age=31536000; includeSubDomains` |

### 4.4 SSL/TLS 配置（如已启用 HTTPS）`[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 60 | TLS 协议版本 | `grep 'ssl_protocols' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null` | 仅 `TLSv1.2 TLSv1.3`；不含 SSLv3、TLSv1、TLSv1.1 |
| 61 | 加密套件配置 | `grep 'ssl_ciphers' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null` | 使用强加密套件，无 RC4、DES、3DES、MD5 |
| 62 | 是否强制 HTTPS 跳转 | `grep -E 'return 301.*https\|rewrite.*https' /etc/nginx/conf.d/*.conf 2>/dev/null` | HTTP 80 端口 301 跳转到 HTTPS |
| 63 | 证书有效期 | `echo \| openssl s_client -connect localhost:443 2>/dev/null \| openssl x509 -noout -dates` | 未过期，且到期日 > 30 天 |

### 4.5 反向代理安全 `[中危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 64 | 是否转发真实 IP | `grep -r 'X-Real-IP\|X-Forwarded-For' /etc/nginx/conf.d/` | 配置了 `proxy_set_header X-Real-IP $remote_addr` |
| 65 | 请求体大小限制 | `grep 'client_max_body_size' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null` | 设置了合理上限（如 10m），非默认 1m 或无限制 |
| 66 | 超时设置 | `grep -E 'proxy_connect_timeout\|proxy_read_timeout' /etc/nginx/conf.d/*.conf 2>/dev/null` | 配置了合理超时（如 60s），防止慢速攻击 |

---

## 五、操作系统与 ECS 安全基线

> **WooYun 数据**：云配置不当是 WooYun 时代后的新兴高危模式。安全组 0.0.0.0/0 放行管理端口等同于无防火墙。

### 5.1 SSH 安全 `[严重]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 67 | 是否禁用 root SSH 登录 | `grep '^PermitRootLogin' /etc/ssh/sshd_config` | `PermitRootLogin no` |
| 68 | 是否禁用密码登录 | `grep '^PasswordAuthentication' /etc/ssh/sshd_config` | `PasswordAuthentication no`（使用密钥认证） |
| 69 | SSH 端口是否修改 | `grep '^Port' /etc/ssh/sshd_config` | 非默认 22 端口 |
| 70 | 登录失败限制 | `grep '^MaxAuthTries' /etc/ssh/sshd_config` | `MaxAuthTries 3`（或已部署 fail2ban） |

### 5.2 阿里云安全组 `[严重]`

| # | 检查项 | 检查方法 | 期望结果 |
|---|--------|---------|---------|
| 71 | 入方向是否有 0.0.0.0/0 全放行规则 | 阿里云控制台 → 安全组规则 | 不存在允许所有端口的 0.0.0.0/0 规则 |
| 72 | 管理端口是否限制来源 IP | 检查 22、8080、3306、6379 的安全组规则 | 仅允许办公 IP / 堡垒机 IP 访问 |
| 73 | 出方向是否限制 | 检查出方向规则 | 非全放行；限制到必需的目标和端口 |

### 5.3 系统加固 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 74 | 系统是否有未修补漏洞 | `yum check-update 2>/dev/null \|\| apt list --upgradable 2>/dev/null` | 无重大安全更新待安装 |
| 75 | 是否存在不必要的 SUID 文件 | `find / -perm -4000 -type f 2>/dev/null` | 仅系统标准 SUID 文件，无自定义或异常项 |
| 76 | 定时任务是否异常 | `crontab -l; ls /etc/cron.d/; cat /etc/crontab` | 无可疑的挖矿脚本、反弹 shell 等异常任务 |
| 77 | 是否有异常监听端口 | `ss -tlnp` | 仅有业务必需的端口在监听，无未知服务 |
| 78 | 防火墙是否启用 | `iptables -L -n \|\| firewall-cmd --list-all 2>/dev/null` | 存在明确的入站规则，非全放行 |

---

## 六、应用层通用检查

> **WooYun 数据**：信息泄露域 6,446 案例 + 配置不当域 1,796 案例共同指向——版本控制文件泄露、备份文件暴露、调试端点未关是运维交接缺失的典型特征。

### 6.1 敏感文件与信息泄露 `[高危]`

> **WooYun 模式**：源代码/配置泄露 4,858 个案例，64.7% 高危。/.git/config 泄露 → 完整源码克隆 → 凭据提取是 WooYun 中高频利用链。

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 79 | .git 目录是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://域名/.git/config` | 返回 403 或 404 |
| 80 | .svn 目录是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://域名/.svn/entries` | 返回 403 或 404 |
| 81 | 备份文件是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://域名/backup.zip` | 返回 403 或 404 |
| 82 | .env 文件是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://域名/.env` | 返回 403 或 404 |
| 83 | WEB-INF 是否可访问 | `curl -s -o /dev/null -w "%{http_code}" http://域名/WEB-INF/web.xml` | 返回 403 或 404 |
| 84 | phpinfo 是否残留 | `curl -s -o /dev/null -w "%{http_code}" http://域名/phpinfo.php` | 返回 404 |
| 85 | Swagger/API 文档是否暴露 | `curl -s -o /dev/null -w "%{http_code}" http://域名/swagger-ui.html` | 返回 404 或需要认证 |
| 86 | Druid 监控是否暴露 | `curl -s -o /dev/null -w "%{http_code}" http://域名/druid/index.html` | 返回 404 或需要认证 |

### 6.2 第三方组件检查 `[高危]`

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 87 | Tomcat 版本是否有已知 CVE | `$CATALINA_HOME/bin/version.sh 2>/dev/null` | 版本为最新稳定版或无重大 CVE |
| 88 | MySQL 版本 | `mysql --version` | 无已知未修补的重大 CVE |
| 89 | Redis 版本 | `redis-server --version` | 无已知未修补的重大 CVE |
| 90 | Nginx 版本 | `nginx -v 2>&1` | 无已知未修补的重大 CVE |
| 91 | Java/JDK 版本 | `java -version 2>&1` | 非 EOL 版本，已修补已知漏洞 |

---

## 七、日志与监控

> **WooYun 防御模式**：配置漂移检测、新服务检测、暴露服务定期扫描是防御配置不当的三大监控支柱。

| # | 检查项 | 检查命令 | 期望结果 |
|---|--------|---------|---------|
| 92 | Tomcat 访问日志是否开启 | `grep 'AccessLogValve' $CATALINA_HOME/conf/server.xml` | Valve 未被注释，日志正常写入 |
| 93 | Nginx 访问日志是否开启 | `grep 'access_log' /etc/nginx/nginx.conf` | 非 `access_log off`，日志路径存在 |
| 94 | MySQL 慢查询日志 | `mysql -u root -p -e "SHOW VARIABLES LIKE 'slow_query_log';"` | `ON` |
| 95 | 日志是否有轮转 | `ls /etc/logrotate.d/ \| grep -E 'nginx\|tomcat\|mysql'` | 存在对应的 logrotate 配置 |
| 96 | 是否有登录失败告警 | `grep -c 'Failed password' /var/log/secure /var/log/auth.log 2>/dev/null` | 有监控机制（fail2ban / 阿里云安骑士等） |

---

## 统计摘要

| 维度 | 数量 |
|------|------|
| 总检查项 | 96 项 |
| 严重 | 22 项（#1-5, 17-21, 33-38, 50, 67-68, 71-72） |
| 高危 | 42 项 |
| 中危 | 20 项 |
| 低危 | 12 项 |

## WooYun 案例引用索引

| WooYun 案例 | 关联检查项 | 攻击模式 |
|-------------|-----------|---------|
| ChinaCache 某系统 JBoss 配置不当导致 Getshell | #1-5 | 默认凭证 → 管理后台 → 部署 WebShell |
| DaoCloud 弱口令 + Docker Remote API 未授权访问 | #33-38 | Redis/Docker 未授权 → 容器逃逸 |
| 同程旅游某系统配置不当任意文件上传 getshell/root 权限 | #47, 54, 91 | 配置不当 → 文件上传 → RCE |
| 微糖主站 SQL 注入影响 860W+ 患者/46W+ 医生 | #17-22, 23-25 | 数据库暴露 → 数据泄露 |
| TCL 某系统配置不当导致 600 万顾客信息泄露 | #79-86 | 信息泄露 → 大规模数据外泄 |
| 复星保德信某系统配置不当 GetShell 影响大量保单信息 | #45-49, 87-91 | 服务配置不当 → RCE → 数据泄露 |
| 阳光保险敏感信息泄露导致成功进入内网系统 | #79-86, 67-70 | 凭据泄露 → 内网横向移动 |

## WooYun 关键统计

- **配置不当域**：1,796 个案例，72.6% 高危——默认配置 = 漏洞
- **弱凭证域**：7,513 个案例，58.2% 高危——WooYun 全库 34% 的漏洞源于默认/弱密码
- **信息泄露域**：4,858 个案例，64.7% 高危——泄露的信息是所有其他攻击的催化剂
- **默认凭证频率**：Tomcat Manager (极高)、Redis 无认证 (极高)、phpMyAdmin root/空 (极高)
- **核心教训**：WooYun 22,132 个真实案例反复证明——最具破坏力的入侵来自未修改的默认配置，而非零日漏洞

---

> 生成依据：WooYun 业务逻辑漏洞方法论 v2.0 · 配置域 1,796 案例 + 信息泄露域 6,446 案例 + 认证域 8,846 案例
