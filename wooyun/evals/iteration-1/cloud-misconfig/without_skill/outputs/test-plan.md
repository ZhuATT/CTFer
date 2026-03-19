# 云原生环境配置安全检查清单

> 适用场景：传统业务迁移至阿里云 ACK（Kubernetes）+ 微服务架构
> 覆盖范围：K8s 集群、Docker 镜像、Service Mesh、API 网关、OSS 对象存储、CI/CD、日志审计

---

## 一、Kubernetes 集群安全

### 1.1 集群访问控制

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| API Server 是否暴露公网 | 严重 | `kubectl cluster-info`；ACK 控制台查看集群访问模式 | 仅内网访问，或通过 SLB + IP 白名单限制 |
| API Server 匿名访问是否关闭 | 严重 | `kubectl auth can-i --list --as=system:anonymous` | 匿名用户无任何权限 |
| 是否启用 RBAC | 严重 | `kubectl api-versions \| grep rbac` | 存在 `rbac.authorization.k8s.io/v1` |
| 是否存在 cluster-admin 滥用 | 高 | `kubectl get clusterrolebindings -o json \| jq '.items[] \| select(.roleRef.name=="cluster-admin") \| .subjects'` | 仅限管理员 SA 和必要组件绑定 |
| kubeconfig 文件权限 | 高 | 检查所有运维人员本地 `~/.kube/config` 权限及分发方式 | 600 权限，禁止明文共享，使用 RAM 子账号 + kubeconfig 生成 |
| 是否启用审计日志 | 高 | ACK 控制台 → 集群管理 → 日志审计 | 已开启，审计日志投递至 SLS |
| Dashboard 是否暴露 | 严重 | `kubectl get svc -n kubernetes-dashboard` | 不存在或仅 ClusterIP，禁止 NodePort/LoadBalancer |
| etcd 是否加密存储 | 高 | ACK 托管版默认加密；自建集群检查 `--encryption-provider-config` | Secret 数据静态加密 |

### 1.2 Pod 安全策略

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否使用 Pod Security Standards (PSS) | 严重 | `kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}: {.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}{end}'` | 生产 namespace 设置为 `restricted` 或 `baseline` |
| 容器是否以 root 运行 | 严重 | `kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: runAsUser={.spec.containers[*].securityContext.runAsUser}{"\n"}{end}'` | 所有业务容器 `runAsNonRoot: true`，指定非零 UID |
| 是否启用特权容器 | 严重 | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true) \| .metadata.name'` | 无特权容器（仅允许基础设施组件例外） |
| 是否挂载 hostPath | 高 | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.volumes[]?.hostPath != null) \| "\(.metadata.namespace)/\(.metadata.name)"'` | 业务 Pod 不挂载 hostPath |
| 是否限制 capabilities | 高 | 检查 `securityContext.capabilities.drop` | 所有容器 `drop: ["ALL"]`，仅按需 add |
| 是否设置 readOnlyRootFilesystem | 中 | 检查 Pod spec | 建议启用，需写入的目录用 emptyDir/volume 挂载 |
| 是否限制 hostNetwork/hostPID/hostIPC | 严重 | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostNetwork==true or .spec.hostPID==true or .spec.hostIPC==true)'` | 业务 Pod 不使用 host 命名空间 |
| 是否配置 seccomp profile | 中 | 检查 `securityContext.seccompProfile` | 设置为 `RuntimeDefault` 或自定义 profile |

### 1.3 网络策略

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否启用 NetworkPolicy | 高 | `kubectl get networkpolicy -A` | 每个业务 namespace 至少有默认拒绝策略 |
| 默认拒绝入站流量 | 高 | 检查是否存在 `default-deny-ingress` 策略 | 存在，所有入站需显式放行 |
| 默认拒绝出站流量 | 中 | 检查是否存在 `default-deny-egress` 策略 | 存在，DNS (53) 和必要外部服务显式放行 |
| 跨 namespace 访问是否受控 | 高 | 检查 NetworkPolicy 的 `namespaceSelector` | 仅允许必要的跨 namespace 通信 |
| CNI 插件是否支持 NetworkPolicy | 高 | ACK 集群 CNI 类型（Terway/Flannel） | 使用 Terway 网络插件（原生支持 NetworkPolicy） |

### 1.4 资源与隔离

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否设置 Resource Limits/Requests | 高 | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].resources.limits == null)'` | 所有容器设置 CPU/Memory limits |
| 是否配置 LimitRange | 中 | `kubectl get limitrange -A` | 每个 namespace 配置默认限制 |
| 是否配置 ResourceQuota | 中 | `kubectl get resourcequota -A` | 生产 namespace 配置配额上限 |
| namespace 隔离 | 高 | `kubectl get ns` | 按业务/环境/团队划分 namespace，非 default 部署 |
| 节点池隔离 | 中 | ACK 控制台 → 节点池 | 关键业务使用独立节点池 + 污点(Taint) 调度 |

---

## 二、Docker 镜像安全

### 2.1 镜像来源与构建

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 基础镜像是否来源可信 | 严重 | 审查所有 Dockerfile 的 FROM 指令 | 使用阿里云 ACR 官方镜像或内部基础镜像，禁止 `latest` tag |
| 基础镜像是否最小化 | 高 | 检查基础镜像类型 | 使用 `alpine`/`distroless`/`slim` 变体，非完整 OS 镜像 |
| 是否使用多阶段构建 | 中 | 审查 Dockerfile | 编译工具链不进入最终镜像 |
| 是否固定镜像版本 | 高 | 检查 FROM 和依赖版本 | 使用确定的 tag + digest（如 `nginx:1.25.3@sha256:...`） |
| 构建时是否泄露敏感信息 | 严重 | 审查 Dockerfile 中的 COPY/ADD/ENV/ARG | 无密钥、证书、配置文件硬编码；使用 BuildKit `--secret` |
| .dockerignore 是否完善 | 中 | 检查项目根目录 `.dockerignore` | 排除 `.git`、`.env`、`node_modules`、密钥文件等 |

### 2.2 镜像扫描与准入

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| ACR 镜像漏洞扫描 | 严重 | 阿里云容器镜像服务 → 安全扫描 | 所有镜像无 Critical/High CVE，定期扫描 |
| 是否启用镜像签名 | 高 | ACR 企业版 → 内容信任 | 启用 Cosign/Notation 签名，部署前验证 |
| 集群镜像准入控制 | 严重 | 检查 ACK 镜像准入配置或 OPA/Kyverno 策略 | 仅允许从指定 ACR 仓库拉取镜像 |
| 镜像仓库访问权限 | 高 | ACR → 访问控制 | 最小权限原则，开发/生产环境隔离仓库 |
| 是否使用 root 用户运行 | 严重 | Dockerfile 中检查 USER 指令 | 存在 `USER nonroot` 或数字 UID |

### 2.3 运行时安全

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 容器运行时版本 | 高 | `kubectl get nodes -o wide`（CONTAINER-RUNTIME 列） | containerd >= 1.7，无已知 CVE |
| 是否启用运行时安全监控 | 高 | 检查是否部署云安全中心容器安全或 Falco | 异常行为（反弹 shell、异常进程）实时告警 |
| 容器文件系统完整性 | 中 | 检查 `readOnlyRootFilesystem` + 运行时监控 | 运行时文件变更可检测 |

---

## 三、Service Mesh 安全（Istio/ASM）

### 3.1 mTLS 与流量加密

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否全局启用 mTLS STRICT 模式 | 严重 | `kubectl get peerauthentication -A` | 存在 mesh 级别 `STRICT` 模式策略 |
| 是否存在 PERMISSIVE 模式服务 | 高 | `kubectl get peerauthentication -A -o yaml \| grep -A5 mtls` | 无长期 PERMISSIVE 配置（仅迁移过渡期允许） |
| 证书轮换周期 | 中 | 检查 Istio/ASM 证书配置 | 证书有效期 <= 24h，自动轮换 |
| 外部流量入口 TLS | 严重 | `kubectl get gateway -A -o yaml` | Ingress Gateway 强制 TLS 1.2+，配置有效证书 |

### 3.2 授权策略

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否配置 AuthorizationPolicy | 严重 | `kubectl get authorizationpolicy -A` | 每个服务有显式授权策略，默认拒绝 |
| 是否存在 allow-all 策略 | 严重 | 审查所有 AuthorizationPolicy 的 rules | 无 `action: ALLOW` + 空 rules（等同 allow-all） |
| 服务间调用是否基于身份验证 | 高 | 检查 `principals`/`namespaces` 字段 | 基于 ServiceAccount 身份做细粒度授权 |
| 外部请求 JWT 验证 | 高 | `kubectl get requestauthentication -A` | 外部 API 请求强制 JWT 验证，配置 issuer 和 jwksUri |

### 3.3 Sidecar 配置

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| Sidecar 注入是否全覆盖 | 高 | `kubectl get ns -L istio-injection` | 所有业务 namespace 标记 `istio-injection=enabled` |
| 是否限制 Sidecar 出站范围 | 中 | `kubectl get sidecar -A` | 配置 `egress.hosts` 限制可访问的外部服务 |
| Envoy 管理端口是否暴露 | 高 | 检查 15000/15004 端口可达性 | 仅 localhost 访问，不可从集群外到达 |

---

## 四、API 网关安全

### 4.1 认证与鉴权

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 所有 API 是否强制认证 | 严重 | 审查网关路由配置 | 除健康检查外所有路由需认证（OAuth2/JWT/API Key） |
| JWT 密钥管理 | 严重 | 检查 JWT signing key 存储位置 | 存储在 KMS/Secret Manager，非环境变量或配置文件 |
| API Key 轮换机制 | 高 | 检查 Key 管理策略 | 支持多 Key 共存，定期轮换，可即时吊销 |
| 是否实施 RBAC/ABAC | 高 | 审查授权策略配置 | 不同角色/租户访问不同 API 子集 |

### 4.2 流量防护

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否配置限流（Rate Limiting） | 高 | 检查网关限流策略 | 按用户/IP/API 粒度限流，防止资源耗尽 |
| 是否启用 WAF | 高 | 阿里云 WAF → 防护配置 | 绑定网关 SLB，启用 SQL 注入/XSS/RCE 防护规则 |
| 请求体大小限制 | 中 | 检查网关 `client_max_body_size` 或等价配置 | 限制合理大小（如 10MB），防止大包攻击 |
| 是否过滤敏感 Header | 中 | 检查网关 header 处理规则 | 移除/不转发 `X-Forwarded-For` 伪造、内部 header |
| CORS 配置 | 中 | 检查 `Access-Control-Allow-Origin` | 非 `*`，白名单指定允许的域名 |
| 超时与重试策略 | 中 | 检查网关全局/路由级别超时 | 连接超时 <= 5s，请求超时 <= 30s，重试 <= 3 次 |

### 4.3 TLS 配置

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 最低 TLS 版本 | 高 | `nmap --script ssl-enum-ciphers -p 443 <gateway-domain>` | TLS >= 1.2，禁用 SSLv3/TLS 1.0/1.1 |
| 证书有效性 | 严重 | `echo \| openssl s_client -connect <domain>:443 2>/dev/null \| openssl x509 -dates` | 证书未过期，自动续期配置正常 |
| HSTS 头 | 中 | `curl -I https://<domain>` | 返回 `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| HTTP 自动跳转 HTTPS | 高 | `curl -I http://<domain>` | 301/308 跳转至 HTTPS |

---

## 五、对象存储（OSS）安全

### 5.1 Bucket 访问控制

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| Bucket 是否公开可读 | 严重 | `aliyun oss stat oss://<bucket>` 或控制台检查 ACL | ACL 为 `private`，非 `public-read`/`public-read-write` |
| Bucket Policy 是否过于宽泛 | 严重 | 控制台 → Bucket → 权限管理 → Bucket Policy | 无 `"Effect": "Allow", "Principal": "*"` 的策略 |
| 是否启用服务端加密（SSE） | 高 | `aliyun oss bucket-encryption --method get --bucket <bucket>` | 启用 SSE-KMS 或 SSE-OSS |
| 跨域（CORS）配置 | 中 | 控制台 → Bucket → 跨域设置 | `AllowedOrigin` 非 `*`，限定业务域名 |
| Referer 防盗链 | 中 | 控制台 → Bucket → 防盗链 | 配置 Referer 白名单，禁止空 Referer |
| 是否开启版本控制 | 中 | 控制台 → Bucket → 版本控制 | 重要数据 Bucket 启用版本控制 |
| 是否配置生命周期策略 | 低 | 控制台 → Bucket → 生命周期 | 临时文件自动过期删除，历史版本定期清理 |

### 5.2 访问日志与监控

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 是否开启访问日志 | 高 | 控制台 → Bucket → 日志管理 | 启用，日志存储到独立的日志 Bucket |
| 异常访问告警 | 中 | 云监控 → OSS 监控 | 配置异常下载量/请求量告警 |
| STS 临时凭证访问 | 高 | 审查应用代码中 OSS 客户端初始化方式 | 使用 STS AssumeRole 临时凭证，非长期 AK/SK |

### 5.3 数据安全

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 传输加密 | 高 | 检查 OSS endpoint 协议 | 强制使用 HTTPS endpoint |
| 敏感数据分类存储 | 高 | 审查 Bucket 规划 | PII/金融数据独立 Bucket，加强访问控制 |
| 是否存在敏感文件泄露 | 严重 | 枚举 Bucket 文件（如 `.env`、`backup.sql`、密钥文件） | 无配置文件、备份、密钥等敏感数据 |

---

## 六、Secrets 管理

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| K8s Secret 是否加密存储 | 高 | ACK 控制台 → Secret 加密 | 启用 KMS 加密 etcd 中的 Secret |
| 是否使用外部 Secret 管理 | 高 | 检查是否集成阿里云 KMS/凭据管家 | 敏感凭据通过 External Secrets Operator 或 CSI Secret Store 注入 |
| Secret 是否以环境变量注入 | 中 | 检查 Pod spec | 优先 volume mount 而非 env（env 可能被日志/core dump 泄露） |
| Secret 访问是否有 RBAC 限制 | 高 | `kubectl auth can-i get secrets -A --as=<sa>` | 仅授权的 ServiceAccount 可访问对应 namespace 的 Secret |
| 是否存在硬编码凭据 | 严重 | 代码仓库扫描（git-secrets/trufflehog） | 无密码、Token、AK/SK 硬编码在代码或配置中 |
| 镜像中是否包含凭据 | 严重 | `docker history --no-trunc <image>` 审查层 | 无 layer 包含密钥文件或敏感环境变量 |

---

## 七、CI/CD 流水线安全

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 流水线凭据管理 | 严重 | 检查 CI/CD 变量配置 | 使用 protected/masked 变量，非明文 |
| 构建环境隔离 | 高 | 检查 Runner/Agent 配置 | 每次构建使用独立容器，构建后销毁 |
| 制品完整性 | 高 | 检查是否签名制品 | 镜像 push 后签名，部署前验证 |
| 部署权限最小化 | 严重 | 检查 CI/CD 使用的 K8s 凭据 | ServiceAccount 仅有目标 namespace 的 deployment 更新权限 |
| 分支保护 | 高 | 代码仓库设置 | main/master 分支需 Code Review + CI 通过才能合并 |
| 依赖安全扫描 | 高 | 检查流水线步骤 | 集成 SCA 工具（如 Trivy/Snyk）扫描依赖漏洞 |
| SAST 静态分析 | 中 | 检查流水线步骤 | 集成代码安全扫描（SonarQube/Semgrep） |

---

## 八、日志与审计

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| K8s 审计日志 | 高 | ACK 控制台 → 日志中心 | 开启，投递至 SLS，保留 >= 180 天 |
| 应用日志集中采集 | 中 | 检查日志采集组件（Logtail/Fluent Bit） | 所有业务容器日志采集至 SLS/ES |
| 日志中是否脱敏 | 高 | 抽样检查日志内容 | 无密码、Token、身份证、手机号等明文 |
| 告警规则覆盖 | 高 | SLS → 告警配置 | 覆盖：异常登录、权限变更、Pod CrashLoop、镜像拉取失败 |
| 操作审计（ActionTrail） | 高 | 阿里云控制台 → ActionTrail | 开启，记录所有 API 调用（特别是 RAM/KMS/ACK 操作） |
| 日志存储访问控制 | 高 | SLS Project 权限设置 | 日志 Project 仅安全/运维团队有读权限，应用无删除权限 |

---

## 九、RAM 与身份管理（阿里云层面）

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| 主账号是否日常使用 | 严重 | 审查登录记录 | 主账号仅用于账单/顶层管理，日常用 RAM 子账号 |
| RAM 用户 MFA | 严重 | RAM 控制台 → 用户管理 | 所有控制台登录用户启用 MFA |
| AK/SK 使用审计 | 严重 | RAM → 用户 → AccessKey 管理 | 禁止主账号 AK，子账号 AK 定期轮换（90 天） |
| RAM 角色最小权限 | 高 | 检查 RAM Policy 内容 | 无 `"Action": "*"` 或 `"Resource": "*"` 的自定义策略 |
| 跨服务访问使用 RAM 角色 | 高 | 检查 ECS/容器使用 Instance RAM Role | 应用通过实例角色获取临时凭证，非静态 AK/SK |
| 闲置账号清理 | 中 | RAM → 用户列表 → 最后登录时间 | 90 天未使用的账号禁用或删除 |

---

## 十、网络安全

| 检查项 | 风险等级 | 检查方法 | 预期结果 |
|--------|---------|---------|---------|
| VPC 网络规划 | 高 | VPC 控制台 | 生产/测试/开发环境独立 VPC 或独立 VSwitch |
| 安全组规则 | 严重 | ECS/ACK 节点安全组 | 无 `0.0.0.0/0` 入站规则（22/3389/全端口），最小化开放 |
| SLB 暴露面 | 高 | SLB 列表 → 监听配置 | 仅暴露 80/443，后端端口不直接暴露 |
| 集群节点公网 IP | 高 | ACK 节点列表 | Worker 节点无公网 EIP，通过 NAT 网关出站 |
| DNS 安全 | 中 | 域名解析记录审查 | 无废弃解析记录（悬挂 DNS），内部服务使用 PrivateZone |
| 出站流量管控 | 高 | NAT 网关 + 安全组出方向规则 | 限制出站目标，禁止随意访问外网 |

---

## 检查执行建议

### 优先级排序

1. **P0（立即修复）**：所有标记为「严重」的项 — 直接暴露攻击面或导致数据泄露
2. **P1（1 周内修复）**：所有标记为「高」的项 — 纵深防御缺失，被利用后影响重大
3. **P2（1 月内修复）**：所有标记为「中/低」的项 — 加固项，提升整体安全水位

### 自动化工具推荐

| 工具 | 用途 | 部署方式 |
|------|------|---------|
| **kube-bench** | CIS Kubernetes Benchmark 自动检查 | DaemonSet 或 Job |
| **Trivy** | 镜像漏洞 + K8s 配置扫描 | CI/CD 集成 + Operator |
| **Kyverno / OPA Gatekeeper** | K8s 策略即代码，准入控制 | Admission Webhook |
| **Falco** | 运行时威胁检测 | DaemonSet |
| **kubeaudit** | K8s 安全审计 | CLI 扫描 |
| **cloud_enum / ossutil** | OSS Bucket 枚举与权限检测 | 手动/定期脚本 |
| **阿里云安全中心** | 全栈安全监控（主机+容器+云服务） | SaaS，ACK 集成 |

### 定期复查节奏

- **每日**：运行时告警检查、Pod 异常状态巡检
- **每周**：镜像漏洞扫描结果复核、安全组变更审计
- **每月**：RAM 权限审计、Secret 轮换状态检查、OSS Bucket 权限复查
- **每季度**：全量安全配置基线扫描（kube-bench + Trivy）、渗透测试
