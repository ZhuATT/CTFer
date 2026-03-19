# Java Spring Boot 信息泄露全面排查清单与测试方案

> 基于 WooYun 方法论 | 数据来源：22,132 个真实漏洞案例 | 信息泄露领域：6,446 案例，64.7% 高危

---

## 一、背景与范围

**触发场景：** 项目曾被报告 Spring Boot Actuator 端点暴露，领导要求上线前全面排查信息泄露风险。

**方法论基础：** WooYun 数据集中信息泄露（4,858 + 1,588 案例）是所有攻击的催化剂——泄露的信息能启动账户接管、内网渗透、精准利用等后续攻击链。Actuator 暴露只是冰山一角，必须系统性排查。

**WooYun 统计警示：**
- 信息泄露案例总数：6,446 个，其中 64.7% 为高危
- 配置不当案例总数：1,796 个，其中 72.6% 为高危
- Spring Boot Actuator 默认无认证的出现频率：**极高**

---

## 二、四阶段方法论概述

| 阶段 | 关键活动 | 门槛标准 |
|------|---------|---------|
| 1. 映射 | 梳理所有暴露面：端点、文件、响应头、错误页面 | 完整资产清单已建立 |
| 2. 假设 | 基于 WooYun 模式形成信息泄露假设 | >=10 个按影响排序的假设 |
| 3. 测试 | 逐项手动验证，记录请求/响应 | 每个假设有证据支持或反驳 |
| 4. 报告 | 业务影响评估、修复建议 | 每个发现附 WooYun 模式分类 |

---

## 三、排查清单（共 8 大类、42 个检查项）

### 第 1 类：Spring Boot Actuator 端点暴露 [严重]

**WooYun 模式：** 配置不当 / 暴露的管理界面（1,796 案例，72.6% 高危）
**WooYun 案例参考：** Spring Boot Actuator 默认无认证，出现频率"极高"，与 JBoss/Tomcat 管理控制台暴露同类

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 1.1 | `/actuator` 主端点是否可未授权访问 | 严重 | `curl -s https://target/actuator` |
| 1.2 | `/actuator/env` 环境变量泄露 | 严重 | 检查响应是否包含数据库密码、API Key、密钥等 |
| 1.3 | `/actuator/heapdump` 堆内存转储 | 严重 | 下载 heapdump，用 `jhat` 或 Eclipse MAT 分析，搜索密码、密钥、会话令牌 |
| 1.4 | `/actuator/configprops` 配置属性 | 高 | 检查数据源密码、第三方服务凭据 |
| 1.5 | `/actuator/mappings` 路由映射 | 高 | 暴露所有 API 端点，含内部/管理接口 |
| 1.6 | `/actuator/beans` Bean 列表 | 中 | 暴露应用架构、组件列表 |
| 1.7 | `/actuator/trace` 或 `/actuator/httptrace` | 严重 | 暴露最近请求历史，可能含 Cookie、Authorization 头 |
| 1.8 | `/actuator/logfile` 日志文件 | 高 | 日志中可能含用户数据、SQL 语句、异常堆栈 |
| 1.9 | `/actuator/shutdown` 关闭端点 | 严重 | POST 请求可直接关闭应用（DoS） |
| 1.10 | `/actuator/jolokia` JMX 暴露 | 严重 | 可通过 JMX 执行任意代码（RCE） |

**测试脚本：**
```bash
# 批量探测 Actuator 端点
ENDPOINTS="actuator actuator/env actuator/heapdump actuator/configprops \
actuator/mappings actuator/beans actuator/httptrace actuator/logfile \
actuator/shutdown actuator/jolokia actuator/info actuator/health \
actuator/metrics actuator/conditions actuator/scheduledtasks \
actuator/threaddump actuator/caches actuator/flyway actuator/liquibase"

for ep in $ENDPOINTS; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target/$ep")
  echo "$ep -> HTTP $STATUS"
done
```

**注意路径变体：** 同时测试以下路径前缀：
- `/actuator/xxx`（Spring Boot 2.x 默认）
- `/xxx`（Spring Boot 1.x 默认，如 `/env`、`/trace`、`/dump`）
- `/manage/xxx`（自定义 management context-path）
- `/admin/actuator/xxx`（自定义前缀）

---

### 第 2 类：API 响应过度暴露 [高危]

**WooYun 模式：** 敏感数据泄露 / API 过度获取（1,588 案例，62.8% 高危）
**WooYun 案例参考：**
- 丁丁租房邮箱泄露导致 600+ 人信息泄露
- TCL 某系统配置不当导致 600 万顾客姓名/手机/家庭住址泄露
- 百姓大药房漏洞危及 2000W 个人详细信息

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 2.1 | API 响应是否返回了 UI 不展示的多余字段 | 高 | 对比 API JSON 响应字段数与前端页面展示字段数 |
| 2.2 | 用户信息接口是否返回密码哈希 | 严重 | 检查 `/api/user/info`、`/api/profile` 等响应 |
| 2.3 | 列表接口是否返回完整对象而非摘要 | 高 | 检查分页列表 API 是否包含手机号、邮箱、身份证等 |
| 2.4 | 用户搜索接口是否可遍历 | 高 | 尝试 `/api/users?page=1&size=9999` 或遍历 ID |
| 2.5 | 导出/下载功能是否有权限控制 | 严重 | 测试 `/export`、`/download`、`/report` 端点 |
| 2.6 | 序列化配置是否排除了敏感字段 | 高 | 检查 Jackson `@JsonIgnore` 是否正确标注 |

**关键指标：** API 响应字段数 > UI 可见字段数 = 存在过度暴露

---

### 第 3 类：错误信息与异常处理 [高危]

**WooYun 模式：** 源代码/配置泄露 — 错误信息（4,858 案例）
**WooYun 案例参考：** 映客多个数据库服务器因错误信息暴露内部架构后沦陷

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 3.1 | 500 错误是否返回完整堆栈跟踪 | 高 | 发送畸形请求触发异常，观察响应体 |
| 3.2 | 数据库错误是否暴露 SQL 语句和表结构 | 高 | 发送非法参数（单引号、超长字符串），检查错误详情 |
| 3.3 | 404 页面是否暴露框架和版本信息 | 中 | 访问不存在的路径，检查 Whitelabel Error Page |
| 3.4 | 参数校验错误是否暴露内部类名 | 中 | 发送类型不匹配的参数，检查 `MethodArgumentNotValidException` 详情 |
| 3.5 | `spring.mvc.throw-exception-if-no-handler-found` 配置 | 中 | 检查是否开启，结合全局异常处理器 |

**测试方法：**
```
# 触发各类错误
1. 发送空 JSON 体到需要参数的 POST 接口
2. 发送超大数值到数字字段（如 id=99999999999999999）
3. 发送特殊字符到字符串字段（如 name=<script>、name='OR 1=1）
4. 请求不存在的端点（如 /api/v99/nonexistent）
5. 发送错误的 Content-Type（如 text/plain 到期望 JSON 的接口）
```

---

### 第 4 类：版本控制与备份文件泄露 [严重]

**WooYun 模式：** 源代码/配置泄露 — 版本控制泄露（4,858 案例，64.7% 高危）
**WooYun 案例参考：** 新网命令执行导致 45 万用户信息泄露（源代码/配置类）

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 4.1 | `/.git/config` Git 仓库泄露 | 严重 | 如可访问，用 GitHack/git-dumper 克隆完整源码 |
| 4.2 | `/.svn/entries` SVN 仓库泄露 | 严重 | 检查 HTTP 200 响应 |
| 4.3 | `/WEB-INF/web.xml` Java 配置泄露 | 严重 | 暴露 Servlet 映射、Filter 链、安全配置 |
| 4.4 | `/WEB-INF/classes/application.yml` | 严重 | 暴露数据库连接、Redis 密码等全部配置 |
| 4.5 | 备份文件探测 | 高 | 检查 `/backup.zip`、`/backup.sql`、`/[域名].zip` 等 |
| 4.6 | `.bak`、`.old`、`.swp` 文件 | 高 | 检查 `/application.yml.bak`、`/config.properties.old` |
| 4.7 | `/src/main/resources/application.yml` | 高 | 直接访问源码路径 |

**批量探测脚本：**
```bash
PATHS=".git/config .git/HEAD .svn/entries .svn/wc.db \
WEB-INF/web.xml WEB-INF/classes/application.yml \
WEB-INF/classes/application.properties \
WEB-INF/classes/bootstrap.yml \
backup.zip backup.sql db.sql database.sql \
application.yml.bak application.properties.bak .env"

for p in $PATHS; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target/$p")
  [ "$STATUS" != "404" ] && echo "[!] $p -> HTTP $STATUS"
done
```

---

### 第 5 类：HTTP 响应头信息泄露 [中危]

**WooYun 模式：** 敏感数据泄露 — 关键发现指标
**防御参考：** WooYun 方法论明确要求"删除 Server、X-Powered-By、X-AspNet-Version"

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 5.1 | `Server` 头暴露 Web 服务器版本 | 中 | `curl -I https://target/` 检查响应头 |
| 5.2 | `X-Powered-By` 暴露框架信息 | 中 | 同上 |
| 5.3 | `X-Application-Context` 暴露 Spring 应用信息 | 中 | Spring Boot 1.x 默认开启 |
| 5.4 | 自定义错误头暴露内部信息 | 低 | 检查所有非标准响应头 |
| 5.5 | 缺少安全响应头 | 中 | 检查 `X-Content-Type-Options`、`X-Frame-Options`、`Strict-Transport-Security`、`Content-Security-Policy` |
| 5.6 | `Cache-Control` 缺失导致敏感页面被缓存 | 高 | 已认证页面是否设置 `no-store` |

---

### 第 6 类：Swagger/API 文档暴露 [高危]

**WooYun 模式：** 源代码/配置泄露 — 调试/测试端点

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 6.1 | `/swagger-ui.html` 或 `/swagger-ui/index.html` | 高 | 暴露全部 API 定义、参数、模型 |
| 6.2 | `/v2/api-docs` 或 `/v3/api-docs` | 高 | 原始 OpenAPI JSON/YAML |
| 6.3 | `/api-docs` | 高 | 同上 |
| 6.4 | `/doc.html`（Knife4j） | 高 | 国产项目高频使用的增强 Swagger |
| 6.5 | `/druid/index.html`（Druid 监控） | 严重 | 暴露 SQL 执行日志、连接池状态、慢查询 |
| 6.6 | `/h2-console`（H2 数据库控制台） | 严重 | 可直接执行 SQL，内存数据库常用于开发 |

**探测脚本：**
```bash
DOC_PATHS="swagger-ui.html swagger-ui/index.html v2/api-docs v3/api-docs \
api-docs doc.html druid/index.html druid/login.html h2-console \
graphql graphiql"

for p in $DOC_PATHS; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target/$p")
  [ "$STATUS" != "404" ] && echo "[!] $p -> HTTP $STATUS"
done
```

---

### 第 7 类：日志与调试信息泄露 [高危]

**WooYun 模式：** 敏感数据泄露 — 日志文件可访问（1,588 案例）
**WooYun 案例参考：** 阳光保险敏感信息泄露导致成功进入内网系统（直登多台运维主机）

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 7.1 | `/logs/`、`/log/` 目录是否可访问 | 严重 | 检查目录列表是否启用 |
| 7.2 | `/access.log`、`/error.log` 日志文件直接可下载 | 高 | 直接 URL 访问 |
| 7.3 | 日志中是否记录了明文密码 | 严重 | 代码审计：检查登录接口日志是否记录 password 参数 |
| 7.4 | 日志中是否记录了完整请求体 | 高 | 检查 `CommonsRequestLoggingFilter` 配置 |
| 7.5 | 日志中是否记录了用户敏感信息（手机、身份证） | 高 | 代码审计：搜索 `log.info`/`log.debug` 中拼接的用户数据 |
| 7.6 | 生产环境日志级别是否为 DEBUG | 高 | 检查 `application.yml` 中 `logging.level` 配置 |

---

### 第 8 类：客户端与前端信息泄露 [中危]

**WooYun 模式：** 敏感数据泄露 — 客户端存储 / HTML/JS 注释

| 编号 | 检查项 | 风险等级 | 测试方法 |
|------|--------|---------|---------|
| 8.1 | HTML 注释中是否包含内部信息 | 低 | 查看页面源代码，搜索 `<!-- -->` |
| 8.2 | JavaScript 中是否硬编码 API Key/密钥 | 严重 | 搜索 JS 文件中的 `apiKey`、`secret`、`password`、`token` |
| 8.3 | 前端 JS 是否包含完整 Source Map | 高 | 检查 `.map` 文件是否可访问，可还原源码 |
| 8.4 | localStorage/sessionStorage 是否存储敏感信息 | 中 | 浏览器 DevTools 检查 |
| 8.5 | URL 中是否传递敏感参数（GET 请求） | 高 | 检查会话令牌、用户 ID 是否在 URL 参数中（Referer 泄露风险） |
| 8.6 | CORS 配置是否为通配符 `*` | 高 | 检查 `Access-Control-Allow-Origin` 响应头 |

---

## 四、Spring Boot 专项深度排查

### 4.1 配置文件安全审计

```yaml
# application.yml / application.properties 中必须检查的配置项

# 1. Actuator 安全
management:
  endpoints:
    web:
      exposure:
        include: health,info    # 只暴露必要端点，绝不能是 "*"
  endpoint:
    shutdown:
      enabled: false            # 禁止远程关闭
    env:
      enabled: false            # 禁止环境变量暴露
    heapdump:
      enabled: false            # 禁止堆转储
  server:
    port: -1                    # 最佳实践：管理端口不对外，或绑定内网地址

# 2. 错误处理
server:
  error:
    include-stacktrace: never   # 绝不返回堆栈跟踪
    include-message: never      # 不返回原始错误消息
    include-binding-errors: never
    include-exception: false
    whitelabel:
      enabled: false            # 禁用默认错误页面

# 3. Swagger（生产环境）
springfox:
  documentation:
    enabled: false              # 生产环境禁用
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false

# 4. H2 控制台
spring:
  h2:
    console:
      enabled: false            # 生产环境必须禁用

# 5. Druid 监控
spring:
  datasource:
    druid:
      stat-view-servlet:
        enabled: false          # 或设置强密码 + IP 白名单
```

### 4.2 代码级检查清单

| 检查项 | 搜索模式 | 说明 |
|--------|---------|------|
| 全局异常处理器 | `@ControllerAdvice` / `@ExceptionHandler` | 确认存在且不返回堆栈信息 |
| Jackson 序列化排除 | `@JsonIgnore` / `@JsonProperty(access=WRITE_ONLY)` | 密码、密钥字段必须标注 |
| 日志脱敏 | `log.info` / `log.debug` + 用户数据 | 确认敏感字段已脱敏 |
| 硬编码凭据 | `password =` / `secret =` / `apiKey =` | 搜索源码中的硬编码密钥 |
| Spring Security 配置 | `WebSecurityConfigurerAdapter` / `SecurityFilterChain` | 检查 Actuator 端点是否纳入鉴权 |
| CORS 配置 | `@CrossOrigin` / `CorsConfiguration` | 检查是否限制了允许的 Origin |
| 文件上传路径 | `MultipartFile` + 存储路径 | 上传文件是否在 Web 可访问目录 |

---

## 五、测试执行方案

### 5.1 测试环境准备

| 项目 | 要求 |
|------|------|
| 测试账号 | 至少 2 个普通用户 + 1 个管理员（用于越权对比） |
| 工具 | Burp Suite / mitmproxy（请求拦截）、curl（端点探测）、Eclipse MAT（heapdump 分析） |
| 网络 | 从外网视角测试（模拟攻击者）+ 内网视角（检查内部暴露） |
| 代码 | 源码访问权限（配合白盒审计） |

### 5.2 测试执行顺序

按 WooYun 高危占比排序，优先测试影响最大的类别：

```
阶段 1 — 快速扫描（30 分钟）
├── 1.1-1.10  Actuator 端点批量探测
├── 4.1-4.7   版本控制/备份文件探测
├── 6.1-6.6   Swagger/Druid/H2 探测
└── 输出：暴露面清单

阶段 2 — 深度验证（2-4 小时）
├── 对阶段 1 发现的暴露端点逐一深入分析
├── 2.1-2.6   API 响应字段审计（抓包对比 UI）
├── 3.1-3.5   错误处理测试（构造畸形请求）
└── 输出：确认的漏洞列表

阶段 3 — 代码审计（2-4 小时）
├── 7.1-7.6   日志配置与内容审计
├── 4.2 代码级安全检查
├── application.yml 安全配置审计
└── 输出：代码层面风险清单

阶段 4 — 前端与综合（1-2 小时）
├── 8.1-8.6   前端信息泄露检查
├── 5.1-5.6   响应头安全检查
├── 跨类别关联分析
└── 输出：完整排查报告
```

### 5.3 假设驱动测试模板

对每个发现的问题，按以下结构记录：

```
假设：[业务流程 X] 存在 [信息泄露类型 Y] 风险
原因：[具体证据——可访问的端点、响应中的多余字段、错误中的堆栈]
WooYun 模式：[匹配的 WooYun 模式名称]
影响：[业务影响——数据泄露范围、可能的攻击链]
测试步骤：
  1. [具体请求]
  2. [预期 vs 实际结果]
修复建议：[服务器端修复，不是前端掩盖]
```

---

## 六、WooYun 真实案例警示

以下案例说明信息泄露的真实后果，每个都是 WooYun 研究者发现的真实漏洞：

| 案例 | 泄露类型 | 影响规模 | 教训 |
|------|---------|---------|------|
| TCL 某系统配置不当导致 600 万顾客信息泄露 | 个人信息泄露 | 600 万客户姓名/手机/住址 | 配置不当 = 大规模数据泄露 |
| 百姓大药房漏洞危及 2000W 个人信息 | 个人信息泄露 | 2000 万条（姓名/身份证/手机/住址） | API 未做权限控制和字段过滤 |
| 映客多个数据库服务器沦陷 | 源代码/配置泄露 | 多台数据库服务器 | 错误信息暴露架构 → 精准攻击 |
| 新网命令执行导致 45 万用户信息泄露 | 源代码/配置泄露 | 45 万用户记录 | 配置文件泄露 → RCE → 数据库 |
| 阳光保险敏感信息泄露导致进入内网 | 凭据泄露 | 多台运维主机 | 信息泄露 → 内网枢纽攻击 |
| 丁丁租房邮箱泄露 | 个人信息泄露 | 600+ 用户 | API 过度返回字段 |
| 传化集团邮件系统内部敏感信息泄露 | 内部系统暴露 | 整个邮件系统 | 管理界面未做访问控制 |
| 微糖主站 SQL 注入影响 860W 患者/46W 医生 | 错误信息 → SQL 注入 | 860 万患者 + 46 万医生 | 错误信息暴露数据库结构 → 注入 |
| ChinaCache JBoss 配置不当导致 Getshell | 暴露管理界面 | 服务器 root 权限 | 管理控制台默认凭证 |
| DaoCloud 弱口令 + Docker Remote API 未授权 | 默认凭证 | 容器逃逸 | 默认配置 = 零成本入侵 |

**关键统计：**
- WooYun 6,446 个信息泄露案例中，64.7% 被评为高危
- 配置不当 1,796 个案例中，72.6% 为高危
- Spring Boot Actuator 未授权访问在 WooYun 出现频率为"极高"
- API 过度暴露是个人信息泄露的首要向量

---

## 七、修复优先级矩阵

| 优先级 | 风险项 | 修复措施 | SLA |
|--------|--------|---------|-----|
| P0 (立即) | Actuator 敏感端点暴露 | 关闭或加鉴权，仅保留 `/health` 和 `/info` | 上线前必须完成 |
| P0 (立即) | heapdump/env 可访问 | `management.endpoint.*.enabled: false` | 上线前必须完成 |
| P0 (立即) | Swagger/Druid/H2 生产环境暴露 | 通过 Profile 禁用或加鉴权 | 上线前必须完成 |
| P0 (立即) | .git/备份文件可访问 | Nginx/网关层 deny 规则 | 上线前必须完成 |
| P1 (24h) | API 返回密码哈希/多余字段 | `@JsonIgnore` + DTO 模式 | 24 小时内 |
| P1 (24h) | 生产环境返回堆栈跟踪 | 全局异常处理器 + `include-stacktrace: never` | 24 小时内 |
| P1 (24h) | 日志中记录明文密码 | 日志脱敏框架（如 Logback MaskingPattern） | 24 小时内 |
| P2 (1周) | 响应头暴露版本信息 | 移除 `Server`、`X-Powered-By` 头 | 1 周内 |
| P2 (1周) | CORS 配置为通配符 | 限制为具体域名 | 1 周内 |
| P2 (1周) | 前端 Source Map 可访问 | 生产构建禁用 source map 或限制访问 | 1 周内 |
| P3 (持续) | 安全响应头缺失 | 添加 CSP、HSTS、X-Content-Type-Options | 持续优化 |
| P3 (持续) | 日志级别过低（DEBUG） | 生产环境设为 WARN/ERROR | 持续优化 |

---

## 八、持续防护建议

### 架构层面
1. **Actuator 端点绑定内网端口：** `management.server.port=8081` + 防火墙仅允许内网访问
2. **Spring Security 拦截管理端点：** 所有 `/actuator/**` 路径要求管理员角色
3. **WAF 规则：** 阻止外部访问 `/.git`、`/.svn`、`/.env`、`/backup*`、`/WEB-INF/*`
4. **CDN 配置：** 不缓存已认证的响应（`Cache-Control: no-store`）
5. **反向代理层过滤：** Nginx 移除 `Server`、`X-Powered-By` 等信息头

### 监控层面
1. **敏感路径访问告警：** 外部 IP 访问 `/actuator`、`/.git`、`/.env`、`/admin` 时触发告警
2. **批量数据访问告警：** 大型 API 响应或高频数据请求时告警
3. **500 错误率监控：** 异常激增可能意味着攻击者在进行侦察
4. **凭据泄露扫描：** 定期在 GitHub/GitLab/Pastebin 上搜索项目关键词

### 开发规范
1. **DTO 模式强制：** 所有 API 接口使用 DTO 返回，禁止直接返回 Entity
2. **全局异常处理器：** `@ControllerAdvice` 统一处理，生产环境仅返回错误码
3. **Profile 隔离：** Swagger/Druid/H2 仅在 `dev`/`test` Profile 下启用
4. **代码审查 Checklist：** PR 审查时必须检查信息泄露项（日志、响应字段、错误处理）

---

> 本方案基于 WooYun 业务逻辑漏洞方法论 v2.0，数据来源为 WooYun 漏洞数据库（2010-2016）22,132 个真实案例中的信息泄露领域 6,446 个案例及配置不当领域 1,796 个案例。
