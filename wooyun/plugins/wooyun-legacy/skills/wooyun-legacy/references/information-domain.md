# 信息泄露领域

## 概述

信息泄露是催化剂。6,446 个 WooYun 案例证明：暴露的信息能够启动所有其他攻击类型——泄露的凭据导致账户接管，泄露的架构导致精准利用。

**核心原则：** 应用程序暴露的任何超出用户需求的信息都是漏洞。调试信息、堆栈跟踪、内部 IP、API 密钥、源代码——每一项都是攻击面倍增器。

## 攻击模式矩阵

### 源代码/配置泄露（4,858 个案例，64.7% 高危）

**系统性发现检查清单：**

```
1. 版本控制泄露
   - [ ] /.git/config → 通过 GitHack/git-dumper 克隆
   - [ ] /.svn/entries → SVN 仓库暴露
   - [ ] /.hg/ → Mercurial 仓库
   - [ ] /.bzr/ → Bazaar 仓库
   - [ ] /CVS/Root → CVS 仓库

2. 备份文件
   - [ ] /backup.zip, /backup.tar.gz, /backup.sql
   - [ ] /db.sql, /database.sql, /dump.sql
   - [ ] /web.rar, /www.zip, /site.tar.gz
   - [ ] /[域名].zip, /[域名].sql
   - [ ] /*.bak, /*.old, /*.orig, /*.swp
   - [ ] /WEB-INF/web.xml (Java)
   - [ ] /config.php.bak, /settings.py.bak

3. 调试/测试端点
   - [ ] ?debug=true, ?debug=1, ?test=1
   - [ ] /debug, /test, /phpinfo.php
   - [ ] /actuator (Spring Boot), /metrics, /health, /env
   - [ ] /trace, /dump, /heapdump
   - [ ] /__debug__/ (Django 调试工具栏)
   - [ ] /console (Rails 控制台, H2 控制台)
   - [ ] /swagger-ui.html, /api-docs, /openapi.json

4. 错误信息
   - [ ] 触发 500 错误 → 包含文件路径的堆栈跟踪
   - [ ] 无效输入 → 包含查询结构的数据库错误
   - [ ] 缺少参数 → 包含类名的框架错误
   - [ ] 404 响应头中暴露服务器版本
```

### 敏感数据泄露（1,588 个案例，62.8% 高危）

**个人信息泄露模式：**

| 泄露向量 | 泄露内容 | 测试方法 |
|---------|---------|---------|
| API 过度获取 | 完整用户对象（密码哈希、邮箱、电话、ID） | 对比 API 响应与 UI 显示 |
| 日志文件可访问 | 用户活动、查询、凭据 | /logs/, /log/, /access.log |
| 错误信息 | 数据库结构、文件路径、内部 IP | 通过畸形输入触发错误 |
| 客户端存储 | localStorage/sessionStorage 中的令牌、个人信息 | 浏览器开发者工具检查 |
| URL 参数 | Referer 头中的会话令牌、用户 ID | 检查 GET 参数中是否有敏感数据 |
| 缓存响应 | CDN/代理缓存中的其他用户数据 | Cache-Control 头测试 |
| 导出功能 | 未授权的批量数据导出 | 测试 /export、/download、/report 端点 |

**关键发现指标：**
- API 响应字段数 > UI 可见字段数
- 生产环境中的详细错误消息
- 暴露版本的服务器头（X-Powered-By、Server）
- HTML/JS 中暴露内部信息的注释
- 客户端 JavaScript 中的凭据

### 目录/文件枚举

**高收益路径（来自 WooYun 统计）：**

```
# 管理
/admin/            /manage/           /backend/
/administrator/    /system/           /console/

# 配置
/config/           /conf/             /settings/
/.env              /wp-config.php     /application.yml

# 数据
/upload/           /uploads/          /files/
/data/             /export/           /tmp/

# 监控
/status/           /server-status     /server-info
/monitoring/       /metrics/          /grafana/

# 文档
/api/docs          /swagger/          /redoc/
/readme.md         /README.txt        /CHANGELOG
```

## 真实案例

| 案例 | 子域 | 影响 |
|------|------|------|
| 丁丁租房邮箱泄露导致600+人信息泄露 | 个人信息泄露 | 通过邮箱暴露 600+ 用户记录 |
| 映客多个数据库服务器沦陷 | 源代码/配置 | 多个数据库服务器被攻破 |
| 新网命令执行导致45万用户信息泄露 | 源代码/配置 | 通过远程代码执行泄露 45 万用户记录 |
| 阳光保险敏感信息泄露导致成功进入内网系统（直登多台运维主机） | 个人信息泄露 | 通过泄露的凭据进行内网枢纽 |
| 传化集团邮件系统内部敏感信息泄露 | 个人信息泄露 | 内部邮件系统暴露 |
| TCL某系统配置不当导致600万顾客姓名/手机/家庭住址泄露 | 个人信息泄露 | 600 万客户个人信息 |
| 百姓大药房漏洞危及2000W个人详细信息（姓名/身份证/手机号/住址） | 个人信息泄露 | 2000 万个人信息记录 |

## 防御模式

### 代码层面
- **最小化响应：** 仅返回客户端需要的字段，不返回完整数据库对象
- **错误处理：** 生产环境仅显示通用错误消息，详细信息仅在开发环境
- **凭据管理：** 使用环境变量或密钥库，绝不在代码/配置文件中
- **日志脱敏：** 在日志中掩盖个人信息（邮箱示例：`a***@example.com`）

### 架构层面
- **强制执行 .gitignore：** 配置文件、.env、凭据绝不在仓库中
- **WAF 规则：** 阻止访问 /.git、/.svn、/.env、/backup*
- **响应头加固：** 删除 Server、X-Powered-By、X-AspNet-Version
- **CDN 配置：** 不缓存已认证的响应

### 监控
- **敏感路径访问：** 外部 IP 访问 /.git、/.env、/admin 时告警
- **批量数据访问：** 大型 API 响应或高频数据请求时告警
- **错误率监控：** 500 错误激增 = 可能的侦察
- **凭据泄露扫描：** 监控 GitHub/GitLab/Pastebin 上泄露的凭据
