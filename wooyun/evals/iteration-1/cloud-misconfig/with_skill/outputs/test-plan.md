# 云原生环境配置安全检查清单

> 阿里云 ACK (Kubernetes) + 微服务架构迁移专项安全评估
>
> 方法论基础：WooYun 22,132 真实漏洞案例 -- 配置域 1,796 例（72.6% 高危）

---

## 一、总体风险判断

传统部署迁移到云原生架构，攻击面发生结构性变化：

| 维度 | 传统部署 | 云原生架构 | 新增风险 |
|------|---------|-----------|---------|
| 网络边界 | 明确的 DMZ/防火墙 | 扁平化 Pod 网络，东西向流量激增 | 横向移动成本极低 |
| 身份认证 | 主机级 SSH + 应用层认证 | ServiceAccount + RBAC + mTLS | 凭据类型爆炸式增长 |
| 配置管理 | 手动运维，配置集中 | YAML 声明式，配置分散在数百个资源中 | 配置漂移、Secret 泄露 |
| 暴露面 | IP + 端口 | NodePort/LoadBalancer/Ingress/API Server | 管理面暴露风险倍增 |
| 供应链 | RPM/DEB 包 | 容器镜像（基础镜像 + 多层依赖） | 镜像投毒、CVE 传播 |

**WooYun 历史教训：** 配置域 1,796 个案例中，最高频的致命模式是「默认凭证 + 暴露管理界面」。在云原生环境中，这个模式映射为：Kubernetes Dashboard 未授权访问、Docker Remote API 暴露、etcd 未加密通信等。

---

## 二、Kubernetes 集群安全检查

### 2.1 API Server 加固

| # | 检查项 | 风险等级 | 检查方法 | WooYun 关联模式 |
|---|--------|---------|---------|----------------|
| K-01 | API Server 是否暴露在公网 | 严重 | `kubectl cluster-info`；检查 ALB/SLB 绑定的 EIP | WooYun 模式：暴露的管理界面（Jenkins/JBoss 控制台直接暴露公网，类比 API Server 暴露） |
| K-02 | 匿名认证是否禁用 | 严重 | 检查 `--anonymous-auth=false` | 案例参考：「DaoCloud弱口令+docker remote API未授权访问」-- Docker API 无认证导致容器逃逸 |
| K-03 | RBAC 是否启用（非 ABAC） | 高 | `kubectl api-versions \| grep rbac` | 默认凭证模式的延伸：无 RBAC = 所有 SA 等同管理员 |
| K-04 | Admission Controller 是否配置 | 高 | 检查 `--enable-admission-plugins` 是否包含 PodSecurity、NodeRestriction | 缺少准入控制 = 允许特权容器部署 |
| K-05 | Audit Log 是否启用 | 高 | 检查 `--audit-policy-file` 和 `--audit-log-path` | WooYun 模式：缺乏监控导致入侵长期未发现 |
| K-06 | etcd 通信是否加密 + 认证 | 严重 | 检查 etcd 是否启用 `--client-cert-auth` 和 TLS | etcd 存储所有集群 Secret，未加密 = 全量凭据泄露 |

### 2.2 RBAC 与权限控制

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| K-07 | 是否存在 cluster-admin 绑定到非必要 ServiceAccount | 严重 | `kubectl get clusterrolebindings -o json \| jq '.items[] \| select(.roleRef.name=="cluster-admin")'` |
| K-08 | default ServiceAccount 是否自动挂载 Token | 高 | 检查 Pod spec 中 `automountServiceAccountToken` 是否为 false |
| K-09 | 是否存在通配符权限（`*` verbs 或 `*` resources） | 高 | 审计所有 ClusterRole/Role 中的通配符规则 |
| K-10 | 各命名空间是否有独立的 ServiceAccount | 中 | `kubectl get sa --all-namespaces`，检查是否都在使用 default SA |

**WooYun 案例映射：** WooYun 配置域中「通配符权限（Action: "\*", Resource: "\*"）」被列为云 IAM 高危配置不当模式。K8s RBAC 中的 `*` 通配符与 AWS/阿里云 IAM 的 `Action: "*"` 本质相同 -- 违反最小权限原则。

### 2.3 网络策略

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| K-11 | 是否定义了 NetworkPolicy | 高 | `kubectl get networkpolicy --all-namespaces`（空 = 所有 Pod 互通） |
| K-12 | 是否实施 deny-all 默认策略 | 高 | 检查是否有 `podSelector: {}` + 空 ingress 的默认拒绝策略 |
| K-13 | 管理命名空间（kube-system）是否与业务隔离 | 高 | 检查 kube-system 的 NetworkPolicy 是否限制业务 Pod 访问 |
| K-14 | Pod 是否能直接访问云 Metadata API（169.254.169.254） | 严重 | 从 Pod 内 `curl http://169.254.169.254/latest/meta-data/`；检查 IMDS 防护 |

**WooYun 案例映射：** 配置域明确列出「IMDS v1 可访问（无需令牌）」为云配置高危项。在 ACK 中，若未限制 Pod 访问 Metadata API，攻击者可通过 SSRF 或容器逃逸获取 RAM 角色临时凭据，等同于「Webhook SSRF 访问内网」模式。

### 2.4 Pod 安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| K-15 | 是否存在特权容器（privileged: true） | 严重 | `kubectl get pods --all-namespaces -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true) \| .metadata.name'` |
| K-16 | 是否以 root 运行容器 | 高 | 检查 `runAsNonRoot: true` 和 `runAsUser` 配置 |
| K-17 | 是否挂载了宿主机路径（hostPath） | 严重 | 审查所有 volume 中的 hostPath 挂载 |
| K-18 | 是否挂载了 Docker Socket | 严重 | 检查是否有 `/var/run/docker.sock` 挂载 |
| K-19 | 是否限制了 Linux Capabilities | 高 | 检查 securityContext 中是否有 `drop: ["ALL"]` + 按需 add |
| K-20 | 是否设置了资源限制（CPU/Memory Limits） | 中 | 检查所有 Deployment 的 resources.limits 是否设置 |
| K-21 | 是否启用了只读根文件系统 | 中 | 检查 `readOnlyRootFilesystem: true` |

### 2.5 Secret 管理

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| K-22 | Secret 是否以明文存储在 etcd | 严重 | 检查 `--encryption-provider-config` 是否配置 |
| K-23 | Secret 是否通过环境变量注入（而非 volume） | 中 | 环境变量会出现在 `/proc/1/environ`，被日志/coredump 泄露 |
| K-24 | 是否使用外部密钥管理（阿里云 KMS / External Secrets） | 高 | 检查是否集成 KMS Provider 或 External Secrets Operator |
| K-25 | Git 仓库中是否存在明文 Secret YAML | 严重 | 在代码仓库中搜索 `kind: Secret` 文件中的 base64 编码值 |

**WooYun 案例映射：** 信息泄露域 4,858 个案例中，「源代码/配置泄露」占最大比例。Git 仓库中的明文 Secret YAML（base64 不是加密）等同于 WooYun 中「/.git/config 暴露导致全量源码泄露」模式 -- 一旦仓库泄露，所有 Secret 即刻失效。

### 2.6 Kubernetes Dashboard 与管理组件

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| K-26 | Kubernetes Dashboard 是否安装 | 高 | `kubectl get deploy -n kubernetes-dashboard` |
| K-27 | Dashboard 是否启用了 skip 登录 | 严重 | 检查 Dashboard 部署参数中是否有 `--enable-skip-login` |
| K-28 | Dashboard ServiceAccount 权限是否过大 | 严重 | 检查 Dashboard SA 绑定的 ClusterRole |
| K-29 | Dashboard 是否暴露在公网（NodePort/LoadBalancer） | 严重 | `kubectl get svc -n kubernetes-dashboard` |

**WooYun 直接案例：** 配置域默认凭证表中明确记录「Kubernetes Dashboard（令牌绕过）」为中等频率出现的配置不当。案例「DaoCloud弱口令+docker remote API未授权访问」直接展示了容器管理界面暴露导致容器逃逸的完整攻击链。

---

## 三、Docker 镜像安全检查

### 3.1 基础镜像安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| D-01 | 基础镜像是否来自可信源（官方 / 企业 ACR） | 高 | 审查所有 Dockerfile 的 FROM 指令 |
| D-02 | 基础镜像是否使用固定 tag（非 latest） | 高 | Dockerfile 中是否为 `FROM image:latest` |
| D-03 | 基础镜像是否为最小化（alpine / distroless / scratch） | 中 | 检查镜像中是否包含 shell、包管理器等非必要工具 |
| D-04 | 基础镜像是否存在已知 CVE | 高 | 使用 Trivy/Grype 扫描：`trivy image <image>` |

### 3.2 构建安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| D-05 | Dockerfile 中是否有硬编码凭据 | 严重 | 搜索 ENV/ARG 中的密码、API Key、Token |
| D-06 | 是否使用多阶段构建（避免泄露构建工具和源码） | 中 | 检查 Dockerfile 是否有 `FROM ... AS builder` 模式 |
| D-07 | 是否以非 root 用户运行（USER 指令） | 高 | 检查 Dockerfile 最后是否有 `USER nonroot` |
| D-08 | 是否存在 .dockerignore 排除敏感文件 | 高 | 检查 .dockerignore 是否排除 .git、.env、*.key 等 |
| D-09 | 镜像层是否泄露中间凭据 | 严重 | `docker history <image>` 检查是否有 secret 残留在某一层 |

**WooYun 案例映射：** 信息泄露域中「版本控制泄露（/.git/config）」和「备份文件泄露」模式在容器场景下映射为：未使用 .dockerignore 导致 .git 目录、配置文件被打包进镜像。攻击者拉取镜像后即可获取完整源码和凭据。

### 3.3 镜像仓库安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| D-10 | ACR（容器镜像服务）是否启用公网访问控制 | 高 | 阿里云控制台检查 ACR 实例的网络访问策略 |
| D-11 | 镜像拉取是否强制使用 imagePullSecrets | 高 | 检查 Pod spec 中是否配置 imagePullSecrets |
| D-12 | 是否启用镜像签名验证（Notation / Cosign） | 中 | 检查是否部署签名验证 Admission Webhook |
| D-13 | 是否配置镜像漏洞自动扫描 | 高 | ACR 安全扫描功能是否启用 |
| D-14 | 是否限制只能拉取指定仓库的镜像 | 中 | 检查 OPA/Kyverno 策略是否限制 image registry |

### 3.4 运行时安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| D-15 | 容器运行时是否为安全版本（containerd/CRI-O） | 高 | `kubectl get nodes -o wide` 查看 Container Runtime |
| D-16 | 是否启用 Seccomp Profile | 中 | 检查 Pod annotation 或 securityContext 中的 seccompProfile |
| D-17 | 是否启用 AppArmor / SELinux | 中 | 检查节点级安全模块配置 |
| D-18 | 是否存在容器逃逸路径 | 严重 | 综合检查：privileged + hostPID + hostNetwork + hostPath + docker.sock |

---

## 四、Service Mesh 安全检查（Istio / ASM）

### 4.1 mTLS 配置

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| SM-01 | 是否启用 STRICT mTLS（非 PERMISSIVE） | 严重 | `kubectl get peerauthentication --all-namespaces`；PERMISSIVE 模式允许明文通信 |
| SM-02 | 是否有命名空间级别的 mTLS 覆盖 | 高 | 检查各命名空间是否有覆盖全局 STRICT 为 PERMISSIVE 的配置 |
| SM-03 | 证书轮换是否正常工作 | 高 | 检查 Citadel/istiod 的证书有效期和自动轮换配置 |

### 4.2 授权策略

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| SM-04 | 是否定义了 AuthorizationPolicy | 高 | `kubectl get authorizationpolicy --all-namespaces`（空 = 所有服务互通） |
| SM-05 | 是否存在 allow-all 策略 | 严重 | 检查是否有 `action: ALLOW` + 空 rules 的策略 |
| SM-06 | 敏感服务是否有细粒度的访问控制 | 高 | 数据库代理、支付服务等是否限制了调用源 |
| SM-07 | 是否限制了 egress 流量 | 中 | 检查 ServiceEntry 和 Sidecar 的 egress 配置 |

**WooYun 案例映射：** 授权域中「越权访问」（1,705 例，62.3% 高危）的核心模式是「缺乏服务端鉴权，信任客户端身份」。在 Service Mesh 场景下，缺少 AuthorizationPolicy 等同于：任何被攻陷的 Pod 都能调用集群内任意服务，横向移动零成本。

### 4.3 Sidecar 注入与网格完整性

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| SM-08 | 是否所有业务 Pod 都注入了 Sidecar | 高 | `kubectl get pods --all-namespaces -o json \| jq '.items[] \| select(.spec.containers \| length == 1) \| .metadata.name'` |
| SM-09 | 是否有 Pod 通过 annotation 跳过注入 | 高 | 搜索 `sidecar.istio.io/inject: "false"` |
| SM-10 | Envoy 管理端口（15000/15004）是否暴露 | 高 | 检查 Envoy admin 接口是否可被非 localhost 访问 |

---

## 五、API 网关安全检查

### 5.1 认证与鉴权

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| GW-01 | 所有 API 路由是否都配置了认证 | 严重 | 逐一检查网关路由配置，识别未绑定认证插件的路由 |
| GW-02 | JWT 验证是否在网关层执行 | 高 | 检查网关是否配置 JWT 验证插件 + 密钥来源 |
| GW-03 | 是否存在绕过网关直接访问后端服务的路径 | 严重 | 检查后端 Service 类型是否为 ClusterIP（非 NodePort/LoadBalancer） |
| GW-04 | API Key / OAuth Token 是否在网关层校验 | 高 | 测试无 Token 请求是否被拒绝 |

**WooYun 直接案例：** 案例「ChinaCache某系统JBoss配置不当导致Getshell」的核心问题是管理控制台直接暴露且使用默认凭证。在微服务架构中，若后端服务通过 NodePort 暴露而非仅通过网关路由，等同于绕过了所有网关层安全策略。

### 5.2 流量控制

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| GW-05 | 是否配置了限流（Rate Limiting） | 高 | 检查网关的限流插件配置 |
| GW-06 | 是否配置了请求体大小限制 | 中 | 检查 `client_max_body_size` 或等效配置 |
| GW-07 | 是否启用了 WAF 防护 | 中 | 检查阿里云 WAF 是否接入网关 |
| GW-08 | 是否配置了 IP 黑/白名单 | 中 | 管理 API 是否限制来源 IP |

### 5.3 信息泄露防护

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| GW-09 | 响应头是否泄露后端信息 | 中 | 检查 Server、X-Powered-By、X-Real-Server 等头 |
| GW-10 | 错误响应是否泄露内部拓扑 | 高 | 发送畸形请求，检查 502/503 响应中是否暴露内部服务名/IP |
| GW-11 | Swagger/OpenAPI 文档是否暴露在生产环境 | 高 | 访问 `/swagger-ui.html`、`/api-docs`、`/openapi.json` |
| GW-12 | 调试端点是否可从外部访问 | 严重 | 检查 `/actuator`、`/debug`、`/metrics` 是否通过网关暴露 |

**WooYun 案例映射：** 信息泄露域中「调试/测试端点」是高频泄露向量。案例中 Spring Boot Actuator（默认无认证，极高频率出现）在微服务中被大量使用。若 `/actuator/env`（泄露环境变量含数据库密码）和 `/actuator/heapdump`（泄露内存中的凭据）通过网关暴露到公网，将直接导致全量凭据泄露。

### 5.4 CORS 与跨域

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| GW-13 | CORS 是否使用通配符 `*` | 高 | 检查 Access-Control-Allow-Origin 配置 |
| GW-14 | CORS 是否允许携带凭据（credentials: true + 通配符） | 严重 | 两者同时存在 = 任意站点窃取用户数据 |
| GW-15 | 是否对预检请求有合理缓存 | 低 | 检查 Access-Control-Max-Age 设置 |

---

## 六、对象存储（OSS）安全检查

### 6.1 Bucket 访问控制

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| OSS-01 | 是否存在公开读/写的 Bucket | 严重 | `aliyun oss ls` + 逐一检查 Bucket ACL 和 Bucket Policy |
| OSS-02 | Bucket Policy 是否存在 `Principal: "*"` | 严重 | 审查所有 Bucket Policy JSON |
| OSS-03 | 是否使用 STS 临时凭据（而非永久 AK/SK） | 高 | 检查应用代码中 OSS 客户端的初始化方式 |
| OSS-04 | 上传路径是否可预测/可枚举 | 高 | 检查文件命名策略是否使用 UUID/随机字符串 |

**WooYun 直接映射：** 配置域「云配置不当」模式中明确列出「OSS（阿里云）存储桶 ACL 配置不当」。同时，案例「同程旅游某系统配置不当任意文件上传getshell/root权限」展示了上传功能配置不当如何导致 RCE -- 在 OSS 场景下虽不直接 RCE，但公开写的 Bucket 可被投毒植入恶意文件，若结合 CDN 分发则影响所有用户。

### 6.2 数据保护

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| OSS-05 | 敏感数据 Bucket 是否启用服务端加密（SSE-KMS） | 高 | 检查 Bucket 加密配置 |
| OSS-06 | 是否启用版本控制（防误删/勒索） | 中 | 检查 Bucket 版本控制状态 |
| OSS-07 | 是否配置了生命周期策略（日志/临时文件自动清理） | 中 | 检查 Lifecycle 规则 |
| OSS-08 | 签名 URL 的有效期是否合理（< 1 小时） | 高 | 审查代码中 `generate_presigned_url` 的 expires 参数 |
| OSS-09 | 是否配置了防盗链（Referer 白名单） | 中 | 检查 Bucket Referer 配置 |

### 6.3 日志与监控

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| OSS-10 | 是否启用 OSS 访问日志 | 高 | 检查 Bucket Logging 配置 |
| OSS-11 | 是否对异常访问模式告警（批量下载/扫描） | 中 | 检查 SLS/CloudMonitor 告警规则 |

---

## 七、阿里云 RAM（IAM）安全检查

### 7.1 账号与权限

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| IAM-01 | 根账号是否启用 MFA | 严重 | 控制台检查根账号安全设置 |
| IAM-02 | 是否存在通配符权限策略（`Action: "*"`, `Resource: "*"`） | 严重 | 审查所有自定义 Policy |
| IAM-03 | RAM 用户是否使用独立 AK/SK（非根账号） | 严重 | 检查根账号是否创建了 AccessKey |
| IAM-04 | 长期未使用的 AK/SK 是否清理 | 高 | 检查 AccessKey 最后使用时间 |
| IAM-05 | 跨账号角色信任策略是否过于宽松 | 高 | 审查 AssumeRole 信任策略中的 Principal |
| IAM-06 | 服务账户 AK/SK 是否硬编码在代码/镜像中 | 严重 | 代码库和镜像层搜索 LTAI 开头的字符串 |

**WooYun 案例映射：** 配置域明确列出「通配符权限（Action: "\*", Resource: "\*"）」和「服务账户密钥暴露在代码/配置中」为云 IAM 高危模式。案例「阳光保险敏感信息泄露导致成功进入内网系统（直登多台运维主机）」展示了凭据泄露如何导致横向移动 -- 在云环境中，泄露的 AK/SK 等同于拿到了对应 RAM 用户的全部权限。

---

## 八、CI/CD 流水线安全检查

### 8.1 构建环境

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| CI-01 | CI/CD 工具（Jenkins/GitLab Runner）是否暴露在公网 | 严重 | 检查 CI 服务的网络暴露面 |
| CI-02 | CI/CD 凭据是否使用 Secret 管理（非明文） | 严重 | 审查 Pipeline 配置中的凭据引用方式 |
| CI-03 | 构建节点是否与生产环境网络隔离 | 高 | 检查 CI Runner 的网络拓扑 |
| CI-04 | 是否对合入主干的代码强制 Code Review | 中 | 检查分支保护规则 |
| CI-05 | 是否集成 SAST/SCA 扫描 | 中 | 检查 Pipeline 中是否有安全扫描步骤 |

**WooYun 直接案例：** 配置域默认凭证表中 Jenkins（默认无认证，极高频率）位列榜首。案例「ChinaCache某系统JBoss配置不当导致Getshell」的模式完全适用于 Jenkins：暴露管理控制台 + 默认/弱凭证 = 通过 Script Console 直接 RCE。

### 8.2 供应链安全

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| CI-06 | 依赖包是否有漏洞扫描 | 高 | 检查是否集成 Snyk/Trivy/Grype 等 SCA 工具 |
| CI-07 | 是否使用私有依赖代理（防依赖混淆攻击） | 中 | 检查 npm/pip/maven 是否配置私有 registry 优先 |
| CI-08 | 镜像是否在推送前进行漏洞扫描 | 高 | 检查 Pipeline 中 image push 前是否有扫描步骤 |

---

## 九、日志、监控与应急响应

### 9.1 日志收集

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| LOG-01 | 集群审计日志是否接入 SLS | 高 | 检查 ACK 审计日志配置 |
| LOG-02 | 应用日志是否集中收集 | 中 | 检查 DaemonSet 日志采集器（Logtail/Filebeat） |
| LOG-03 | 日志中是否脱敏（不含密码、Token、身份证号） | 高 | 抽样检查日志内容 |
| LOG-04 | 日志保留期限是否满足合规要求（>=180 天） | 中 | 检查 SLS Logstore 保留策略 |

### 9.2 安全告警

| # | 检查项 | 风险等级 | 检查方法 |
|---|--------|---------|---------|
| LOG-05 | 是否启用阿里云安全中心（云安全） | 高 | 检查安全中心 Agent 部署状态 |
| LOG-06 | K8s 异常行为检测是否启用 | 高 | 检查是否部署 Falco 或使用 ACK 安全能力 |
| LOG-07 | 是否有容器逃逸检测 | 严重 | 检查运行时安全策略和告警规则 |
| LOG-08 | 安全事件应急响应流程是否定义 | 中 | 检查是否有文档化的 IR 流程 |

---

## 十、检查执行优先级

基于 WooYun 72.6% 高危率的配置域数据和云原生特有风险，建议按以下优先级执行：

### P0 -- 立即检查（攻破即全盘沦陷）

| 检查项 | 理由 |
|--------|------|
| K-01 API Server 公网暴露 | 等同于把数据库管理界面挂公网，WooYun 默认凭证模式 |
| K-14 Pod 访问 Metadata API | IMDS 凭据泄露 = RAM 角色权限全丢 |
| K-22 Secret 明文存储 etcd | 等同于配置文件中的明文密码 |
| K-25 Git 中的明文 Secret | WooYun .git 泄露模式的 K8s 版本 |
| OSS-01 公开读写 Bucket | WooYun 云配置不当模式，直接数据泄露 |
| IAM-02 通配符 RAM 权限 | WooYun IAM 通配符权限模式 |
| D-18 容器逃逸路径 | privileged + hostPath + docker.sock 三件套 |

### P1 -- 48 小时内完成（可被利用进行横向移动）

| 检查项 | 理由 |
|--------|------|
| K-07 cluster-admin 过度授权 | 一个 Pod 沦陷 = 集群管理员 |
| K-11 缺少 NetworkPolicy | 横向移动零成本 |
| SM-01 mTLS 非 STRICT | 中间人攻击 / 流量窃听 |
| GW-03 后端服务绕过网关可达 | 绕过所有认证 / WAF |
| CI-01 Jenkins 暴露公网 | WooYun Jenkins 默认无认证 → RCE |
| GW-12 Actuator 公网可达 | 凭据泄露 + 内存转储 |

### P2 -- 一周内完成（纵深防御层）

所有中等风险项 + 监控告警体系建设。

---

## 附录 A：WooYun 案例与云原生风险映射总表

| WooYun 原始模式 | 案例数 | 云原生等效风险 | 本清单对应检查项 |
|----------------|-------|--------------|----------------|
| 默认凭证（Tomcat/JBoss/Jenkins/Redis/MongoDB） | 极高频 | K8s Dashboard skip login、Grafana admin/admin、etcd 无认证 | K-27, K-06 |
| Docker Remote API 未授权 | 高频 | 容器运行时 API 暴露、特权容器逃逸 | D-18, K-15, K-18 |
| 管理界面暴露公网 | 极高频 | API Server/Dashboard/Jenkins/Actuator 公网可达 | K-01, K-29, CI-01, GW-12 |
| 源代码/配置泄露（.git/.svn/备份文件） | 4,858 例 | Git 中明文 Secret、Dockerfile 硬编码凭据、镜像层残留 | K-25, D-05, D-08, D-09 |
| CORS 通配符 | 高频 | API 网关 CORS 配置不当 | GW-13, GW-14 |
| 调试端点暴露（Actuator/phpinfo/debug） | 极高频 | Spring Boot Actuator 通过网关暴露 | GW-11, GW-12 |
| 通配符 IAM 权限 | 高频 | RAM `Action: "*"` + K8s RBAC `*` verbs | IAM-02, K-09 |
| 云存储 ACL 配置不当 | 高频 | OSS Bucket 公开读/写 | OSS-01, OSS-02 |
| SSRF → 内网访问 | 高频 | Pod SSRF → Metadata API → RAM 临时凭据 | K-14 |
| 个人信息泄露（API 过度获取/日志可访问） | 1,588 例 | 日志未脱敏、API 响应过度返回 | LOG-03, GW-10 |

---

## 附录 B：自动化检查工具推荐

| 工具 | 用途 | 集成方式 |
|------|------|---------|
| **kube-bench** | CIS Kubernetes Benchmark 合规检查 | 部署为 Job，定期运行 |
| **kube-hunter** | K8s 渗透测试（发现暴露面） | 从集群外部和内部分别运行 |
| **Trivy** | 镜像 CVE + K8s 配置审计 + Secret 扫描 | CI Pipeline + Operator 模式 |
| **Falco** | 运行时异常行为检测（容器逃逸、异常进程） | DaemonSet 部署 |
| **OPA/Kyverno** | Policy as Code（准入控制） | Admission Webhook |
| **kubeaudit** | K8s 资源安全审计 | 定期扫描 + CI 集成 |
| **Prowler** | 阿里云安全配置审计（类 AWS ScoutSuite） | 定期运行，输出报告 |

---

## 附录 C：核心原则（源自 WooYun 1,796 个配置不当案例）

1. **每个服务的默认配置都是为便利而非安全设计的** -- 如果没有明确加固，就存在漏洞
2. **管理界面 + 默认凭证 = 远程代码执行** -- 这在 WooYun 时代是 Tomcat/JBoss/Jenkins，在云原生时代是 Dashboard/etcd/Envoy Admin
3. **凭据不属于代码仓库** -- 无论是 .env 文件还是 K8s Secret YAML，base64 不是加密
4. **网络隔离是最有效的配置安全措施** -- 管理界面仅限内网访问，这一条能消除 50% 以上的配置类漏洞
5. **最小权限不是建议，是底线** -- RBAC 通配符、RAM `Action: "*"`、privileged 容器，每一个都是攻击者的提权跳板
