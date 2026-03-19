# Java Spring Boot 信息泄露全面排查清单与测试方案

## 一、排查范围总览

| 风险域 | 风险等级 | 排查重点 |
|--------|---------|---------|
| Actuator 端点暴露 | 高危 | 健康检查、环境变量、配置属性、堆转储 |
| 错误处理与异常信息 | 高危 | 堆栈跟踪、SQL 错误、框架版本号 |
| 配置文件与敏感数据 | 高危 | 数据库密码、API Key、密钥硬编码 |
| HTTP 响应头 | 中危 | Server 头、X-Powered-By、框架指纹 |
| API 响应数据 | 高危 | 过度返回字段、用户隐私数据 |
| 静态资源与目录遍历 | 中危 | .git 目录、备份文件、源码泄露 |
| 日志输出 | 中危 | 敏感数据写入日志、日志文件对外可访问 |
| Swagger/OpenAPI 文档 | 中危 | 接口文档暴露、调试端点 |
| Spring DevTools | 高危 | 远程调试、自动重载端点 |
| 数据库与中间件控制台 | 高危 | H2 Console、Druid Monitor、Redis 未授权 |

---

## 二、逐项排查清单与测试方案

### 2.1 Spring Boot Actuator 端点暴露

**背景**：这是上次被报告的漏洞类型，是 Spring Boot 最高频的信息泄露问题。

#### 排查清单

- [ ] 检查 `application.yml` / `application.properties` 中 `management.endpoints.web.exposure.include` 配置
- [ ] 检查 `management.server.port` 是否与主服务端口分离
- [ ] 检查 `management.endpoints.web.base-path` 是否修改了默认路径 `/actuator`
- [ ] 检查各端点是否配置了独立的安全认证
- [ ] 检查自定义 Actuator 端点是否存在

#### 高危端点清单

| 端点 | 泄露内容 | 风险等级 |
|------|---------|---------|
| `/actuator/env` | 环境变量、数据库连接串、API Key | 高危 |
| `/actuator/configprops` | 所有配置属性及值 | 高危 |
| `/actuator/heapdump` | JVM 堆转储（可提取密码、密钥、Session） | 高危 |
| `/actuator/threaddump` | 线程信息、内部类名 | 中危 |
| `/actuator/mappings` | 所有 URL 映射及控制器方法 | 中危 |
| `/actuator/beans` | 所有 Spring Bean 及依赖关系 | 中危 |
| `/actuator/conditions` | 自动配置条件评估结果 | 低危 |
| `/actuator/health` | 数据库、Redis、MQ 等组件连接状态及版本 | 中危 |
| `/actuator/info` | 应用信息（Git commit、构建版本） | 低危 |
| `/actuator/metrics` | JVM 内存、CPU、请求计数等运行指标 | 低危 |
| `/actuator/loggers` | 日志级别配置（POST 可动态修改） | 中危 |
| `/actuator/scheduledtasks` | 定时任务列表 | 低危 |
| `/actuator/httptrace` / `/actuator/httpexchanges` | 最近 HTTP 请求含 Header（可能含 Token） | 高危 |
| `/actuator/shutdown` | 关闭应用（默认关闭，但需确认） | 高危 |
| `/actuator/jolokia` | JMX MBean 操作（可 RCE） | 高危 |
| `/actuator/prometheus` | Prometheus 指标数据 | 低危 |

#### 测试方案

```bash
# 1. 基础探测 — 检查默认路径
BASE_URL="http://target:8080"
ENDPOINTS=(
  "/actuator"
  "/actuator/env"
  "/actuator/configprops"
  "/actuator/heapdump"
  "/actuator/threaddump"
  "/actuator/mappings"
  "/actuator/beans"
  "/actuator/conditions"
  "/actuator/health"
  "/actuator/info"
  "/actuator/metrics"
  "/actuator/loggers"
  "/actuator/scheduledtasks"
  "/actuator/httptrace"
  "/actuator/httpexchanges"
  "/actuator/shutdown"
  "/actuator/jolokia"
  "/actuator/prometheus"
  "/actuator/caches"
  "/actuator/flyway"
  "/actuator/liquibase"
  "/actuator/sessions"
  "/actuator/startup"
  "/actuator/quartz"
  "/actuator/integrationgraph"
  "/actuator/sbom"
)

for ep in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${ep}")
  echo "[${STATUS}] ${ep}"
done

# 2. 变体路径探测（绕过路径过滤）
VARIANTS=(
  "/actuator"
  "/Actuator"
  "/ACTUATOR"
  "/%61ctuator"        # URL 编码
  "/actuator/"
  "/actuator;.js"      # Tomcat 路径参数绕过
  "/actuator%00"       # 空字节截断
  "//actuator"
  "/./actuator"
  "/manage"            # 旧版 Spring Boot 1.x 路径
  "/admin"
  "/monitor"
)

for v in "${VARIANTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${v}/env")
  echo "[${STATUS}] ${v}/env"
done

# 3. 自定义管理端口探测
for PORT in 8081 8443 9090 9091 8180 18080; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://target:${PORT}/actuator")
  echo "[${STATUS}] Port ${PORT} /actuator"
done

# 4. heapdump 分析（如可下载）
curl -s -o heapdump "${BASE_URL}/actuator/heapdump"
# 使用 Eclipse MAT 或 jhat 分析
# 或使用 JDumpSpider 自动提取敏感信息：
# java -jar JDumpSpider.jar heapdump
```

#### 安全加固建议

```yaml
# application.yml 推荐配置
management:
  endpoints:
    web:
      exposure:
        include: health,info    # 仅暴露必要端点
        # include: "*"          # 绝对禁止
  endpoint:
    health:
      show-details: never       # 不显示组件详情
    env:
      enabled: false
    heapdump:
      enabled: false
    threaddump:
      enabled: false
    configprops:
      enabled: false
    mappings:
      enabled: false
    beans:
      enabled: false
    shutdown:
      enabled: false
  server:
    port: 19090                 # 管理端口与主服务分离，仅内网可访问
```

---

### 2.2 错误处理与异常信息泄露

#### 排查清单

- [ ] 检查是否存在全局异常处理器（`@ControllerAdvice` / `@RestControllerAdvice`）
- [ ] 检查 `server.error.include-stacktrace` 配置值
- [ ] 检查 `server.error.include-message` 配置值
- [ ] 检查 `server.error.include-binding-errors` 配置值
- [ ] 检查 `server.error.include-exception` 配置值
- [ ] 检查 Whitelabel Error Page 是否禁用
- [ ] 检查自定义 ErrorController 的实现
- [ ] 检查 SQL 异常是否被直接返回给前端
- [ ] 检查 MyBatis / Hibernate 错误是否泄露表名、字段名

#### 测试方案

```bash
# 1. 触发 404 — 检查默认错误页
curl -v "${BASE_URL}/nonexistent_path_xyz"

# 2. 触发 500 — 参数类型错误
curl -v "${BASE_URL}/api/users/abc"          # 预期 int 传 string
curl -v "${BASE_URL}/api/users/-1"           # 边界值
curl -v "${BASE_URL}/api/users/99999999999"  # 超大数

# 3. 触发 SQL 错误
curl -v "${BASE_URL}/api/users?id=1'"                    # SQL 注入探测
curl -v "${BASE_URL}/api/search?q=test' OR '1'='1"

# 4. 触发参数校验错误
curl -X POST "${BASE_URL}/api/users" \
  -H "Content-Type: application/json" \
  -d '{"email": "not-an-email", "age": -1}'

# 5. 触发请求体格式错误
curl -X POST "${BASE_URL}/api/users" \
  -H "Content-Type: application/json" \
  -d '{"malformed json'

# 6. 触发 405 Method Not Allowed
curl -X DELETE "${BASE_URL}/api/users"

# 7. Content-Type 不匹配
curl -X POST "${BASE_URL}/api/users" \
  -H "Content-Type: application/xml" \
  -d '<test>123</test>'
```

**判定标准**：响应中不应包含以下任何内容：
- Java 包名（`com.xxx.xxx`、`org.springframework`）
- 堆栈跟踪（`at java.lang.`、`.java:123`）
- SQL 语句或表名
- 框架版本号
- 服务器内部路径（`/home/app/`、`/opt/xxx/`）
- 异常类名（`NullPointerException`、`SQLException`）

#### 安全加固建议

```yaml
# application.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
    include-exception: false
    whitelabel:
      enabled: false
```

```java
// 全局异常处理器
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e) {
        log.error("Internal error", e);  // 日志记录完整信息
        return ResponseEntity.status(500)
            .body(new ErrorResponse("INTERNAL_ERROR", "服务器内部错误"));  // 脱敏返回
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException e) {
        return ResponseEntity.status(400)
            .body(new ErrorResponse("VALIDATION_ERROR", "参数校验失败"));
    }
}
```

---

### 2.3 配置文件与敏感数据泄露

#### 排查清单

- [ ] `application.yml` / `application.properties` 中是否硬编码数据库密码
- [ ] 是否使用了配置加密（Jasypt / Spring Cloud Config 加密）
- [ ] `bootstrap.yml` 是否包含敏感信息
- [ ] 多环境配置文件（`application-dev.yml`、`application-prod.yml`）是否都做了脱敏
- [ ] 是否存在 `.env` 文件被打包到制品中
- [ ] Git 仓库历史中是否有敏感信息（即使当前已删除）
- [ ] `pom.xml` / `build.gradle` 中是否有私有仓库凭据
- [ ] Docker 镜像中是否包含配置文件明文
- [ ] Kubernetes ConfigMap / Secret 是否正确使用

#### 测试方案

```bash
# 1. 代码仓库敏感信息扫描（使用 trufflehog 或 gitleaks）
gitleaks detect --source=. --report-format=json --report-path=gitleaks-report.json

# 2. 关键词搜索
grep -rn "password\s*=" src/ --include="*.yml" --include="*.yaml" --include="*.properties" --include="*.xml"
grep -rn "secret\s*=" src/ --include="*.yml" --include="*.yaml" --include="*.properties"
grep -rn "api[_-]key\s*=" src/ --include="*.yml" --include="*.yaml" --include="*.properties"
grep -rn "jdbc:" src/ --include="*.yml" --include="*.yaml" --include="*.properties" --include="*.xml"
grep -rn "aws_access_key\|aws_secret" src/
grep -rn "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" src/

# 3. 打包产物检查（解压 JAR/WAR）
jar -tf target/app.jar | grep -E "(\.yml|\.yaml|\.properties|\.xml|\.env|\.key|\.pem)"
# 解压后检查配置文件内容
jar -xf target/app.jar BOOT-INF/classes/application.yml
cat BOOT-INF/classes/application.yml | grep -i "password\|secret\|key\|token"

# 4. Docker 镜像层分析
docker history --no-trunc app:latest
docker save app:latest | tar -xf - -C /tmp/image-layers/
# 逐层检查是否有敏感文件
find /tmp/image-layers/ -name "*.yml" -o -name "*.properties" -o -name "*.env" | xargs grep -l "password"
```

---

### 2.4 HTTP 响应头信息泄露

#### 排查清单

- [ ] `Server` 响应头是否暴露服务器类型和版本（如 `Apache-Coyote/1.1`）
- [ ] `X-Powered-By` 头是否暴露框架信息
- [ ] `X-Application-Context` 头是否暴露应用名和 Profile
- [ ] 是否缺少安全响应头（`X-Content-Type-Options`、`X-Frame-Options`、`Strict-Transport-Security`）
- [ ] CORS 配置是否过于宽松（`Access-Control-Allow-Origin: *`）
- [ ] `Set-Cookie` 是否缺少 `HttpOnly`、`Secure`、`SameSite` 标志

#### 测试方案

```bash
# 1. 检查所有响应头
curl -sI "${BASE_URL}/api/health" | head -30

# 2. 检查敏感头
curl -sI "${BASE_URL}/" | grep -iE "^(server|x-powered-by|x-application-context|x-aspnet)"

# 3. CORS 检查
curl -sI -H "Origin: https://evil.com" "${BASE_URL}/api/users" | grep -i "access-control"

# 4. Cookie 安全标志检查
curl -sI "${BASE_URL}/login" | grep -i "set-cookie"
# 确认包含: HttpOnly; Secure; SameSite=Lax (或 Strict)

# 5. 安全头检查
curl -sI "${BASE_URL}/" | grep -iE "^(x-content-type|x-frame|strict-transport|content-security-policy|x-xss)"
```

#### 安全加固建议

```yaml
# application.yml — 隐藏 Server 头
server:
  server-header: ""             # 清空 Server 头
```

```java
// Spring Security 配置
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .frameOptions(f -> f.deny())
        .xssProtection(x -> x.disable())  // 现代浏览器已内置
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(h -> h
            .includeSubDomains(true)
            .maxAgeInSeconds(31536000))
    );
    return http.build();
}
```

---

### 2.5 API 响应数据过度暴露

#### 排查清单

- [ ] 用户相关接口是否返回了密码哈希、盐值
- [ ] 列表接口是否返回了不必要的敏感字段（手机号、身份证、银行卡）
- [ ] 是否使用了 `@JsonIgnore` / DTO 模式控制输出字段
- [ ] 分页接口是否允许一次性查询全部数据（如 `pageSize=999999`）
- [ ] 接口是否存在水平越权（通过改 ID 访问他人数据）
- [ ] 枚举接口是否可遍历（如递增 ID 遍历所有用户）
- [ ] GraphQL 接口是否允许内省（Introspection）

#### 测试方案

```bash
# 1. 检查用户接口返回字段
curl -s "${BASE_URL}/api/users/1" | python3 -m json.tool
# 检查是否包含: password, salt, idCard, bankCard, phone 等敏感字段

# 2. 检查列表接口
curl -s "${BASE_URL}/api/users?page=1&size=10" | python3 -m json.tool
# 确认返回字段与单个查询一致，不多出字段

# 3. 大页面测试
curl -s "${BASE_URL}/api/users?page=1&size=999999" | wc -c
# 应有页面大小上限

# 4. 水平越权测试（用 A 用户 Token 访问 B 用户数据）
curl -s -H "Authorization: Bearer ${TOKEN_A}" "${BASE_URL}/api/users/2"

# 5. ID 枚举遍历
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/users/${i}")
  echo "[${STATUS}] user/${i}"
done

# 6. GraphQL 内省检查
curl -X POST "${BASE_URL}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'
```

---

### 2.6 静态资源与目录遍历

#### 排查清单

- [ ] `.git` 目录是否可通过 Web 访问
- [ ] 是否存在备份文件（`.bak`、`.swp`、`.old`、`~`）
- [ ] 是否存在源码文件可直接访问（`.java`、`.class`）
- [ ] 是否启用了目录列表功能
- [ ] `robots.txt` 是否暴露了敏感路径
- [ ] `sitemap.xml` 是否包含管理后台路径
- [ ] `crossdomain.xml` / `clientaccesspolicy.xml` 是否存在且配置过宽

#### 测试方案

```bash
# 1. 敏感文件探测
SENSITIVE_FILES=(
  "/.git/HEAD"
  "/.git/config"
  "/.gitignore"
  "/.env"
  "/.env.local"
  "/.env.production"
  "/WEB-INF/web.xml"
  "/WEB-INF/classes/application.yml"
  "/WEB-INF/classes/application.properties"
  "/robots.txt"
  "/sitemap.xml"
  "/crossdomain.xml"
  "/swagger-ui.html"
  "/swagger-ui/index.html"
  "/v2/api-docs"
  "/v3/api-docs"
  "/druid/index.html"
  "/h2-console"
  "/favicon.ico"
  "/backup.sql"
  "/dump.sql"
  "/application.yml"
  "/application.properties"
  "/.DS_Store"
  "/Thumbs.db"
)

for f in "${SENSITIVE_FILES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${f}")
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ]; then
    echo "[FOUND ${STATUS}] ${f}"
  fi
done

# 2. 目录遍历测试
curl -s "${BASE_URL}/static/"
curl -s "${BASE_URL}/resources/"
curl -s "${BASE_URL}/public/"
curl -s "${BASE_URL}/uploads/"

# 3. 路径穿越测试
curl -s "${BASE_URL}/static/../../etc/passwd"
curl -s "${BASE_URL}/static/..%2F..%2Fetc%2Fpasswd"
curl -s "${BASE_URL}/static/....//....//etc/passwd"
```

---

### 2.7 日志信息泄露

#### 排查清单

- [ ] 日志中是否打印了用户密码、Token、Session ID
- [ ] 日志中是否打印了完整的请求/响应体（含敏感数据）
- [ ] 日志文件是否可通过 Web 访问（如 `/logs/`、`/log/`）
- [ ] 日志级别在生产环境是否设置为 `INFO` 或以上（不应为 `DEBUG`/`TRACE`）
- [ ] 是否使用了日志脱敏组件
- [ ] 日志是否输出到 stdout 后被收集系统暴露

#### 测试方案

```bash
# 1. 日志文件探测
LOG_PATHS=(
  "/logs/"
  "/log/"
  "/logs/spring.log"
  "/logs/app.log"
  "/logs/error.log"
  "/log/spring.log"
  "/output.log"
  "/nohup.out"
)

for p in "${LOG_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${p}")
  if [ "$STATUS" == "200" ]; then
    echo "[EXPOSED] ${p}"
  fi
done

# 2. 代码审计 — 搜索日志中的敏感信息输出
grep -rn "log\.\(info\|debug\|warn\|error\)" src/ --include="*.java" | \
  grep -iE "(password|token|secret|credential|session|cookie|authorization)"

# 3. 检查生产环境日志级别配置
grep -rn "logging.level" src/ --include="*.yml" --include="*.properties"
```

---

### 2.8 Swagger / OpenAPI 文档暴露

#### 排查清单

- [ ] Swagger UI 是否在生产环境可访问
- [ ] OpenAPI JSON/YAML 端点是否暴露
- [ ] Knife4j（增强 Swagger）是否在生产环境可访问
- [ ] 是否通过 Profile 控制 Swagger 仅在开发环境启用

#### 测试方案

```bash
# Swagger / OpenAPI 端点探测
SWAGGER_PATHS=(
  "/swagger-ui.html"
  "/swagger-ui/"
  "/swagger-ui/index.html"
  "/swagger-resources"
  "/swagger-resources/configuration/ui"
  "/v2/api-docs"
  "/v3/api-docs"
  "/v3/api-docs.yaml"
  "/doc.html"                    # Knife4j
  "/webjars/springfox-swagger-ui/"
  "/api-docs"
  "/api/swagger.json"
  "/api/v1/swagger.json"
)

for p in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${p}")
  if [ "$STATUS" == "200" ]; then
    echo "[EXPOSED] ${p}"
  fi
done
```

#### 安全加固建议

```java
// 通过 Profile 控制，仅 dev/test 环境启用
@Configuration
@Profile({"dev", "test"})
public class SwaggerConfig {
    // Swagger 配置
}
```

```yaml
# application-prod.yml — 生产环境关闭
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false
```

---

### 2.9 Spring DevTools 泄露

#### 排查清单

- [ ] `spring-boot-devtools` 依赖是否在生产包中（应为 `optional` + `provided` scope）
- [ ] 远程调试端口是否暴露（`spring.devtools.remote.secret`）
- [ ] LiveReload 端口（35729）是否开放
- [ ] 远程重启端点 `/.~~spring-boot!~/restart` 是否可访问

#### 测试方案

```bash
# 1. 检查 DevTools 远程端点
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.~~spring-boot!~/restart"

# 2. 检查 LiveReload 端口
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://target:35729/"

# 3. 代码审计 — pom.xml 检查
grep -A5 "spring-boot-devtools" pom.xml
# 确认 scope 为 runtime + optional=true
```

---

### 2.10 数据库与中间件控制台

#### 排查清单

- [ ] H2 Console 是否在生产环境启用（`spring.h2.console.enabled`）
- [ ] Druid 监控页面是否可未授权访问（`/druid/index.html`）
- [ ] Redis 是否设置了密码且不暴露在公网
- [ ] RabbitMQ / Kafka 管理界面是否有认证
- [ ] Elasticsearch `_cat`、`_cluster` 端点是否暴露
- [ ] Nacos / Apollo / Spring Cloud Config 控制台是否有认证

#### 测试方案

```bash
# 1. H2 Console
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/h2-console"
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/h2-console/"

# 2. Druid Monitor
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/druid/index.html"
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/druid/login.html"
curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/druid/api.html"
# 默认用户名/密码尝试：admin/admin, druid/druid

# 3. 注册中心 / 配置中心
curl -s -o /dev/null -w "%{http_code}" "http://target:8848/nacos/"
curl -s -o /dev/null -w "%{http_code}" "http://target:8070/"  # Apollo
curl -s "http://target:8848/nacos/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=100"

# 4. Elasticsearch
curl -s "http://target:9200/"
curl -s "http://target:9200/_cat/indices"
curl -s "http://target:9200/_cluster/health"
```

---

### 2.11 Spring Security 配置缺陷

#### 排查清单

- [ ] 是否存在认证绕过路径（`permitAll()` 配置的路径是否合理）
- [ ] Session 是否使用安全配置（超时、固定攻击防护）
- [ ] CSRF 保护是否合理启用/关闭
- [ ] 密码是否使用 BCrypt 等安全算法（而非 MD5/SHA1）
- [ ] Token（JWT）是否暴露了不必要的 Claim（用户角色、权限列表）
- [ ] JWT Secret 是否硬编码在代码中

#### 测试方案

```bash
# 1. JWT Token 解码检查（不需要密钥就能读 payload）
# 获取一个 token 后
echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# 检查 payload 中是否包含敏感信息

# 2. 代码审计 — 搜索硬编码密钥
grep -rn "jwt\.\(secret\|key\)" src/ --include="*.yml" --include="*.properties" --include="*.java"
grep -rn "SecretKeySpec\|signing[Kk]ey\|\.signWith" src/ --include="*.java"

# 3. 检查 permitAll 路径
grep -rn "permitAll\|anonymous" src/ --include="*.java"
```

---

### 2.12 依赖组件版本泄露

#### 排查清单

- [ ] 是否使用了已知有信息泄露漏洞的 Spring Boot 版本
- [ ] Jackson、Fastjson 等序列化库版本是否安全
- [ ] 第三方依赖是否有已知 CVE

#### 测试方案

```bash
# 1. 依赖漏洞扫描
mvn org.owasp:dependency-check-maven:check
# 或
./gradlew dependencyCheckAnalyze

# 2. Spring Boot 版本确认
grep "spring-boot" pom.xml | head -5
# 对照已知漏洞列表：https://spring.io/security

# 3. 响应中框架指纹识别
curl -sI "${BASE_URL}/" | grep -iE "server|x-powered|x-application"
curl -s "${BASE_URL}/error" | grep -i "whitelabel\|spring\|tomcat"
```

---

## 三、自动化扫描工具推荐

| 工具 | 用途 | 命令/链接 |
|------|------|----------|
| **nuclei** | Actuator + 通用漏洞模板扫描 | `nuclei -u http://target -t spring/` |
| **SpringBoot-Scan** | Spring Boot 专项扫描 | GitHub: AabyssZG/SpringBoot-Scan |
| **gitleaks** | Git 仓库敏感信息泄露 | `gitleaks detect --source .` |
| **trufflehog** | Git 历史凭据搜索 | `trufflehog git file://.` |
| **OWASP ZAP** | Web 安全综合扫描 | 含信息泄露检测规则 |
| **dependency-check** | 依赖 CVE 检测 | Maven/Gradle 插件 |
| **JDumpSpider** | heapdump 自动提取敏感信息 | GitHub: whwlsfb/JDumpSpider |
| **pspy** | 进程监控（检查启动参数是否含密码） | GitHub: DominicBreuker/pspy |

---

## 四、排查执行计划

### 第一阶段：高优先级（立即执行，1-2 天）

| 序号 | 任务 | 风险等级 | 负责 |
|------|------|---------|------|
| 1 | Actuator 端点全量扫描 + 封堵 | 高危 | 安全/运维 |
| 2 | 错误页面信息泄露检查 + 全局异常处理器审查 | 高危 | 开发 |
| 3 | 配置文件敏感信息扫描（含 Git 历史） | 高危 | 安全 |
| 4 | Swagger / H2 Console / Druid 生产环境关闭确认 | 高危 | 运维 |
| 5 | DevTools 依赖检查 | 高危 | 开发 |

### 第二阶段：中优先级（3-5 天内）

| 序号 | 任务 | 风险等级 | 负责 |
|------|------|---------|------|
| 6 | HTTP 响应头安全审计 | 中危 | 开发 |
| 7 | API 响应字段过度暴露检查 | 中危 | 开发 |
| 8 | 日志敏感信息审计 | 中危 | 开发 |
| 9 | 静态资源与敏感文件路径扫描 | 中危 | 安全/运维 |
| 10 | JWT Token Payload 审查 | 中危 | 开发 |

### 第三阶段：持续改进（1-2 周）

| 序号 | 任务 | 风险等级 | 负责 |
|------|------|---------|------|
| 11 | 依赖组件 CVE 扫描 | 中危 | 开发 |
| 12 | Docker 镜像安全审计 | 中危 | 运维 |
| 13 | CI/CD 流水线集成安全扫描 | 低危 | DevOps |
| 14 | 建立安全基线和定期巡检机制 | 低危 | 安全 |

---

## 五、验收标准

所有排查项通过后，应满足以下条件：

1. **Actuator**：仅 `/actuator/health`（`show-details: never`）和 `/actuator/info`（无敏感信息）对外开放
2. **错误响应**：所有异常返回统一格式，不含堆栈、SQL、类名、路径
3. **配置文件**：零硬编码密码/密钥，全部通过环境变量或加密配置注入
4. **响应头**：无 Server 版本、无 X-Powered-By、包含全部安全头
5. **API 响应**：使用 DTO 模式，敏感字段（手机号、身份证等）脱敏返回
6. **文档/控制台**：Swagger、H2 Console、Druid Monitor 生产环境完全关闭
7. **日志**：不记录密码、Token、完整银行卡号等敏感数据
8. **依赖**：无高危 CVE 未修复，DevTools 不在生产构建中
9. **Git 仓库**：无历史敏感信息泄露（已通过 BFG / filter-branch 清理）
10. **自动化**：CI/CD 集成了 gitleaks + dependency-check，增量检测
