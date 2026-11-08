---
name: recon-methodology
description: >-
  Reconnaissance and methodology. Covers the master routing skill (phenomenon-to-skill mapping), cognitive testing framework (black-box pentest thinking discipline), and recon methodology (asset discovery/fingerprinting/endpoint inventory/Java middleware matrix). Load at engagement start to establish testing approach and route to deeper skills.
---

<!-- src: hacker/.claude/skills/recon-methodology/SKILL.md -->

# Reconnaissance & Methodology

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Master Router (hack) |
| 2 | Recon Methodology |

---
# Part 1: Master Router


# HACKING SKILLS / HackSkills

## Overview

This is a top-level routing skill for **bug bounty, web security, API security, and authorized penetration testing**.

Its core role is not to replace all specialized techniques, but to help the agent:

1. First determine the testing phase (Recon / Validation / Privilege Escalation / Chain building)
2. Then select the correct vulnerability category
3. Avoid relying only on baseline model memory; prefer structured methodology
4. Prioritize boundary conditions AI often misses but that matter in real engagements

## Trust Model

- This knowledge base emphasizes content safety and auditability.
- Use this only within **authorized targets**, **legitimate research**, **defensive validation**, and **bug-bounty-approved rules**.
- Do not use these techniques for unauthorized attacks.

## When to Use This Skill

Use this skill first in the following scenarios:

- You just received a new bug bounty target and do not know where to start
- You need to decide whether to load XSS / SQLi / SSRF / IDOR / JWT / API tracks first
- You want the agent to perform Web/API security testing with a more stable methodology
- You need to route scattered findings to the right attack surface
- You want AI to miss fewer critical test points in security work

## Operating Model

### Step 1: Start with Recon and context validation

Collect first:

- Target type: classic web, REST API, mobile backend, admin panel, payment flow, file upload, GraphQL
- Identity and permission model: anonymous, regular user, admin, multi-tenant
- Input locations: URL, query parameters, JSON, headers, cookies, filenames, imported files, templates, reflection points
- Output locations: HTML, attributes, JS, PDF, email, logs, background tasks, mobile endpoints

### Step 2: Route by observed behavior

| Signal | Priority direction |
|---|---|
| Input reflects into HTML / JS | XSS / SSTI |
| Server actively fetches URL / hostname | SSRF |
| Accepts XML / Office / SVG | XXE |
| Path, filename, or download endpoint is controllable | Path Traversal / LFI |
| Many object IDs appear in APIs | IDOR / BOLA / BFLA |
| Login, reset password, 2FA, sessions | Auth Bypass / JWT / OAuth |
| Multi-step transactions, coupons, pricing, inventory | Business Logic |
| MongoDB / JSON query syntax exposure | NoSQL Injection |
| CLI tools, image processing, importers | Command Injection |
| HTTP parsing anomalies / front-back framing mismatch | Request Smuggling |
| Node.js JSON handling / controllable `__proto__` | Prototype Pollution |
| PHP weak comparison / 0e hash / loose conditions | Type Juggling |
| Repeated parameter names / WAF-app parsing mismatch | HTTP Parameter Pollution |
| One-time operations (coupon/inventory/reset) | Race Condition |
| XML/XSLT template processing | XSLT Injection |
| Accessible .git/.svn/.env paths | Insecure SCM |
| CSV/Excel export features | CSV Formula Injection |
| WebSocket protocol upgrades | WebSocket Security |
| Internal package names / supply-chain inventory | Dependency Confusion |

### Step 3: Use the most likely-hit testing order

1. Recon / Methodology
2. API Security / Auth / IDOR
3. XSS / SQLi / SSRF / SSTI / XXE
4. Business Logic / Race Condition
5. Chained exploits and privilege-escalation paths

## Core Skill Map

If you have the full repository, prioritize using these topic documents together:

**注入**
- [XSS / CSV Formula](../injection-xss/SKILL.md)
- [SQLi / NoSQLi](../injection-sqli/SKILL.md)
- [SSRF](../injection-ssrf/SKILL.md)
- [SSTI / EL / JNDI / XSLT / CMDi](../injection-server/SKILL.md)
- [Smuggling / H2 / CRLF / HPP / Email Header](../injection-protocol/SKILL.md)
- [Deserialization / Prototype Pollution / Ghost Bits / XXE / LFI](../injection-deser/SKILL.md)

**认证授权**
- [JWT / OAuth / SAML / Auth Bypass](../auth-token/SKILL.md)
- [IDOR / CORS / CSRF / 403 Bypass](../auth-access/SKILL.md)
- [API Security / GraphQL](../api-all/SKILL.md)

**业务/逻辑**
- [Business Logic / Race Condition](../logic-race/SKILL.md)

**高级 Web**
- [WAF / Cache / Host / DNS / Takeover / Upload](../web-advanced/SKILL.md)

**提权/移动**
- [Linux / Container / K8s](../privesc-linux/SKILL.md)
- [Windows / Lateral / AV Evasion](../privesc-windows/SKILL.md)
- [Active Directory](../ad-attacks/SKILL.md)
- [macOS](../macos-all/SKILL.md)
- [Android / iOS](../mobile-all/SKILL.md)

**基础设施**
- [Tunneling / Dep Confusion / Insecure SCM / WebSocket / Reverse Shell](../infra-network/SKILL.md)

**Pwn**
- [Stack / ROP](../pwn-stack/SKILL.md)
- [Heap](../pwn-heap/SKILL.md)
- [Kernel](../pwn-kernel/SKILL.md)
- [Misc / Sandbox / Browser](../pwn-misc/SKILL.md)

**其他**
- [Crypto / Type Juggling](../crypto-attacks/SKILL.md)
- [Reverse Engineering](../re-all/SKILL.md)
- [Forensics](../forensics-all/SKILL.md)

**未实现（Phase 2 遗留）**
- Blockchain, AI Security, CMDi 完整 playbook, File Upload 完整 playbook — 待补

Previously separate mini skills such as payload-selection and brute-selection were merged back into their main skills to avoid router overload and selection noise.

## High-Value Expert Intuitions

These are points many baseline models miss, but they are frequently effective in real bug bounty work:

1. **The same filtering logic is often reused across multiple pages**: if one point is bypassable, similar pages usually are too.
2. **Parameter names are an attack surface too**: WAFs often inspect values but not names.
3. **Second-order vulnerabilities are common**: safe at storage time does not mean safe when later read into a dangerous context.
4. **BOLA is fundamentally 'authenticated but unauthorized'**: replaying with account A/B switching is critical.
5. **Older API versions are most likely to miss patches**: fixing v2 does not mean v1 was retired.
6. **Business-logic vulnerabilities often bring highest impact**: scanners miss them and they persist longer.
7. **Race conditions should prioritize one-time actions**: coupon redemption, claims, resets, invites, trials, inventory deduction.
8. **For JWT attacks, check key and algorithm context first**: do not blindly spray payloads; verify `alg`, `kid`, JWKS, and key source first.

## Suggested Prompts

Use this skill as a router to make the agent clarify phase and goal first:

- "First, plan the testing route for this target using bug bounty methodology.
- "This is a REST API; prioritize BOLA, BFLA, Mass Assignment, and JWT angles.
- "This parameter triggers server-side requests; list key validation points from an SSRF perspective.
- "This feature is a payment/coupon/inventory flow; prioritize business logic and race-condition analysis.
- "I only see login and password-reset flows; analyze via Auth Bypass + OAuth/JWT + CSRF.

## Installation Notes

Recommended skill name:

- `hack`

Recommended search keywords:

- `HackSkills`
- `HACKING SKILLS`
- `bug bounty`
- `bug bounty hunter`

## Guidelines

- Prioritize routing by target type and observed behavior, not random payload enumeration.
- When payloads are needed, prefer quick-start / first-pass samples in the corresponding main skill instead of adding another intermediate router.
- Prioritize reusable filters, shared components, and cross-page reproduction paths.
- Confirm authentication, authorization, and version boundaries before deeper exploitation.
- Preserve explainable, auditable, reproducible testing processes.
- When full repository context is available, return to topic documents for finer exploitation details.


---
# Part 2: Recon & Methodology


# SKILL: Recon and Methodology — Expert Bug Bounty Playbook

> **AI LOAD INSTRUCTION**: Systematic recon and bug-finding methodology from top bug hunters. Covers subdomain enumeration, endpoint discovery, tech fingerprinting, and the hunter's mental model for finding bugs that others miss. Key insight: most high-severity bugs are found through systematic coverage, not just clever payloads.


## 1. RECON HIERARCHY

```
Target Selection
└── Scope Definition (in-scope assets)
    └── Asset Discovery (subdomains, IPs, domains)
        └── Tech Fingerprinting (what's running)
            └── Endpoint Discovery (attack surface)
                └── Vulnerability Testing (per vulnerability type)
```

---

## 2. SUBDOMAIN ENUMERATION (CRITICAL FIRST STEP)

### Passive (no DNS queries to target)
```bash
# Subfinder (aggregates multiple sources):
subfinder -d target.com -o subdomains.txt

# Amass passive:
amass enum -passive -d target.com

# Certsh (certificate transparency):
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails API, Shodan:
# Web: https://securitytrails.com/list/apex_domain/target.com
```

### Active (DNS brute force + resolution)
```bash
# Massdns + wordlist:
massdns -r /path/to/resolvers.txt -t A -o S -w output.txt \
  <(cat wordlist.txt | sed 's/$/.target.com/')

# ffuf for subdomain brute:
ffuf -w subdomains-wordlist.txt -u https://FUZZ.target.com \
  -mc 200,301,302,403 -H "Host: FUZZ.target.com"

# DNSx for bulk resolution:
cat subdomains.txt | dnsx -a -resp -o resolved.txt

# Recommended wordlist: SecLists/Discovery/DNS/
```

### Virtual Host Discovery
```bash
# ffuf vhost mode:
ffuf -w wordlist.txt -u https://target.com \
  -H "Host: FUZZ.target.com" -mc 200,301,403

# gobuster vhost:
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## 3. SERVICE AND PORT DISCOVERY

```bash
# Fast port scan (common ports):
nmap -T4 -F target.com -oN ports.txt

# Comprehensive scan on resolved subdomains:
cat resolved_ips.txt | nmap -iL - --open -p 80,443,8080,8443,8888,3000,5000 -oG scan.txt

# httpx for HTTP probing:
cat subdomains.txt | httpx -title -tech-detect -status-code -o live_hosts.txt

# masscan for speed on large IP ranges:
masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=1000
```

---

## 4. WEB TECHNOLOGY FINGERPRINTING

```bash
# Wappalyzer (browser extension) or:
whatweb https://target.com

# httpx with tech detection:
httpx -u https://target.com -tech-detect

# Check headers manually:
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|cf-ray"

# Fingerprint from:
- Server header: nginx/1.18, Apache/2.4, IIS/10.0
- X-Powered-By: PHP/7.4, ASP.NET
- Cookies: PHPSESSID (PHP), JSESSIONID (Java), _rails_session (Rails)
- HTML comments: <!-- Drupal 9 -->
- Meta generator: <meta name="generator" content="WordPress 6.2">
- JS framework files: /static/js/angular.min.js
```

---

## 5. ENDPOINT DISCOVERY

### Directory Brute Force
```bash
# ffuf (fastest):
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302,403 -t 50 -o dirs.txt

# Gobuster:
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,json

# feroxbuster (recursive):
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt -r
```

### Parameter Discovery
```bash
# Arjun (hidden parameter finder):
arjun -u https://target.com/api/endpoint

# x8:
x8 -u https://target.com/api/endpoint -w params-wordlist.txt
```

### JavaScript Source Mining
```bash
# Extract endpoints from JS files:
gau target.com | grep '\.js$' | httpx -mc 200 | xargs -I{} curl -s {} | \
  grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u

# LinkFinder:
python3 linkfinder.py -i https://target.com -d -o output.html

# GetAllURLs (gau):
gau target.com | sort -u > all_urls.txt

# Wayback URLs:
waybackurls target.com | sort -u > wayback_urls.txt
```

### API Endpoint Discovery
```bash
# Common API paths:
ffuf -u https://target.com/FUZZ -w /SecLists/Discovery/Web-Content/api/api-endpoints.txt

# Swagger/OpenAPI:
test: /swagger.json /api-docs /openapi.json /v2/api-docs /.well-known/ /docs/

# GraphQL:
test: /graphql /gql /v1/graphql /api/graphql
```

---

## 6. SOURCE CODE RECON

### GitHub / GitLab Exposure
```bash
# trufflehog (secret scanner in git history):
trufflehog git https://github.com/target-org/target-repo

# gitleaks:
gitleaks detect --source /path/to/cloned/repo

# Manual GitHub search:
# site:github.com "target.com" "api_key" OR "secret" OR "password"
# site:github.com "target.com" ".env" OR "config.php" OR "db_password"

# GitHub dorks:
# "target.com" extension:env
# "target.com" filename:*.config password
# org:target-org secret OR password OR apikey
```

### Exposed Environment Files
```
# Check common paths:
https://target.com/.env
https://target.com/.git/config
https://target.com/config.json
https://target.com/config.yaml
https://target.com/credentials.json
https://target.com/secrets.json
https://target.com/wp-config.php
https://target.com/backup.sql
https://target.com/backup.zip
```

---

## 7. ZSEANO'S TESTING METHODOLOGY

### Core Philosophy
1. **Go deep on one program** rather than spread across many — learn the application thoroughly
2. **Build a profile of the company** — tech stack, developers, processes
3. **Look where others don't** — check error pages, admin paths, old versions, mobile API
4. **Follow the filter** — if input is filtered somewhere, that functionality exists and may be bypassed

### Testing Sequence (One Page / Feature)
```
For each input point:
1. Non-malicious HTML tags (<h2>, <img>) → are they reflected?
2. Incomplete tags → what happens? (<iframe src=//evil.com )
3. Encoding tests → %0d, %0a, %09, <%00
4. Observe the OUTPUT too (not just response) — where does your input appear?
5. Test same input in ALL similarly-structured pages (shared code → shared vuln)
6. Check if the same parameter exists in mobile/API endpoint (less protected)
```

### Parameter Insights
```
- Each parameter tells a story: "what does this do server-side?"
- Filename → OS interaction → Path Traversal / CMDi
- URL/location → HTTP fetch → SSRF
- Template/HTML parameter → render function → SSTI
- XML field → parser → XXE
- SQL filter → query → SQLi
- User-content → storage → Stored XSS
```

---

## 8. BUG BOUNTY PROGRAM TRIAGE (WHERE TO SPEND TIME)

### High-Value Target Selection
```
✓ Programs with large scope (*.target.com)
✓ Programs that pay for P2/P3 (not just RCE)
✓ Programs with recent tech changes (migrations = new bugs)
✓ Programs with active development (new features = new attack surface)
× Avoid: frozen/old codebases with well-known CVEs (already claimed)
× Avoid: strict programs with narrow scope (less surface)
```

### High-Value Feature Focus (by bug probability)
```
Priority 1: Authentication, password reset, 2FA → account takeover
Priority 2: File upload, profile edit, API endpoints → stored XSS, IDOR
Priority 3: Admin panels, user management → BFLA, privilege escalation
Priority 4: Payment flows, subscription → business logic
Priority 5: Import/export, template rendering → XXE, SSTI
```

---

## 9. NUCLEI TEMPLATES (AUTOMATED SCANNING)

```bash
# Run all on target:
nuclei -u https://target.com -t /nuclei-templates/ -o nuclei-results.txt

# Specific categories:
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# On subdomain list:
cat subdomains.txt | nuclei -t exposures/ -t misconfiguration/ -o exposed.txt
```

---

## 10. COMMON MISCONFIGURATIONS (QUICK WINS)

```
□ CORS: Access-Control-Allow-Origin: * with credentials → CSRF + data theft
□ S3 bucket public: curl https://target.s3.amazonaws.com/
□ Directory listing: response contains "Index of /"
□ .git exposed: curl https://target.com/.git/config
□ .env exposed: curl https://target.com/.env
□ Debug mode: stack traces in production (source code exposure)
□ Default credentials: admin:admin, admin:password on admin panels
□ phpinfo.php: curl https://target.com/phpinfo.php
□ Backup files: config.bak, database.sql.gz, app.zip
□ GraphQL introspection enabled: POST /graphql {"query":"{__schema{types{name}}}"}
□ Admin panels: /admin /manager /console /phpmyadmin /wp-admin
```

---

## 11. QUICK REFERENCE TOOLS

| Category | Tool |
|---|---|
| Subdomain enum | subfinder, amass, massdns |
| Port scan | nmap, masscan |
| HTTP probe | httpx |
| Dir brute | ffuf, feroxbuster, gobuster |
| JS mining | LinkFinder, gau, waybackurls |
| Secret scan | trufflehog, gitleaks |
| Parameter fuzz | arjun, x8 |
| Vuln scan | nuclei |
| Proxy/intercept | Burp Suite Pro |
| JWT attacks | jwt_tool |
| SQLi | sqlmap |
| XSS | dalfox, XSStrike |
| SSRF | SSRFmap, Gopherus |

---

## 12. JAVA MIDDLEWARE FINGERPRINT MATRIX

| Middleware | Detection Path | Key Indicators |
|---|---|---|
| Apache Tomcat | `/manager/html`, `/manager/status` | Default creds: `tomcat:tomcat`, `admin:admin` |
| JBoss / WildFly | `/jmx-console/`, `/web-console/` | JMX MBean access, WAR deployment |
| WebLogic | `/console/`, `/wls-wsat/` | T3 protocol on 7001/7002, IIOP |
| Spring Boot Actuator | `/actuator/`, `/actuator/env`, `/actuator/heapdump` | JSON endpoint listing, heap dump contains secrets |
| Spring Boot (alt paths) | `/actuator/jolokia`, `/actuator/gateway/routes` | Jolokia JMX bridge, Gateway route injection |
| Jenkins | `/script`, `/manage` | Groovy console, API token in cookie |
| GlassFish | `/common/`, `/theme/` | Admin on 4848, default empty password |
| Jetty | `/jolokia/` | JMX access |
| Resin | `/resin-admin/` | Admin panel |

### Spring Boot Actuator Exploitation Priority

```
/actuator/env          → Leak environment variables (DB creds, API keys)
/actuator/heapdump     → Download JVM heap → search for passwords in memory
/actuator/jolokia      → JMX → possible RCE via MBean manipulation
/actuator/gateway/routes → Spring Cloud Gateway → SpEL injection (CVE-2022-22947)
/actuator/configprops  → All configuration properties
/actuator/mappings     → All URL mappings (hidden endpoints)
/actuator/beans        → All Spring beans
/actuator/shutdown     → POST to shutdown application (DoS)
```

---

## 13. INFORMATION LEAK DETECTION CHECKLIST

### Version Control & Backup Leaks

```
/.git/HEAD                    → Git repository exposed
/.svn/entries                 → SVN metadata
/.svn/wc.db                   → SVN SQLite database
/.hg/requires                 → Mercurial
/.bzr/README                  → Bazaar
/.DS_Store                    → macOS directory listing
```

### Backup File Patterns

```
/backup.zip    /backup.tar.gz    /backup.sql
/wwwroot.rar   /www.zip          /web.zip
/db.sql        /database.sql     /dump.sql
/config.php.bak    /config.php~    /config.php.swp
/.config.php.swp   /wp-config.php.bak
/.env          /.env.bak         /.env.production
```

### API Documentation & Debug

```
/swagger-ui.html              → Swagger/OpenAPI
/swagger-ui/                  → Swagger UI
/api-docs                     → API documentation
/graphql                      → GraphQL playground
/graphiql                     → GraphQL IDE
/debug/                       → Debug endpoints
/phpinfo.php                  → PHP configuration
/server-status                → Apache status
/server-info                  → Apache info
/nginx_status                 → Nginx status
```

### Cloud & Infrastructure

```
/.aws/credentials             → AWS credentials
/.docker/config.json          → Docker registry auth
/robots.txt                   → Disallowed paths (hint list)
/sitemap.xml                  → Full URL listing
/crossdomain.xml              → Flash cross-domain policy
/.well-known/                 → Various well-known URIs
```

---

## 浏览器侦察四步（Playwright MCP——headless 会话必读）

**第 0 步（P-7 实测教训，2026-09-14）：先调 WaitForMcpServers 工具（timeout 填 30000）。**
headless（`-p`）模式里 MCP 服务器是异步启动的，CLI 不等——浏览器工具（browser_*）
要等它返回 ready 才出现在工具列表里。不调这一步，你会"看不到浏览器工具"而误判
无浏览器能力。返回失败/超时 → 本轮无浏览器，直接 curl 起步，别卡死在这一步。

浏览器侦察四步（第 0 步通过后按序执行）：

1. `browser_navigate` → 目标 URL
2. `browser_snapshot` → 页面结构
3. `browser_network_requests(filter:"/api|xhr|fetch/")` → 真实 API 清单
4. `browser_click` 有目的地点击功能区 → 再捕获一轮

JS 蒸馏：拿到 JS 资源后用 js-intel（本地 Chrome，无需 playwright install；
工具路径见环境说明/CLAUDE.md 渲染槽）——产物是端点→漏洞类路由、密钥、sink
的情报简报，读完把要点记进账本。

## 资产分诊（端点 >20 时）

按指纹分组 → 每组测一个代表 → 挑 3-8 个高价值目标：
- 有身份语义（登录/注册/个人中心）
- 有对象 ID 参数（?id=/detail/update 形态）
- 可写操作（POST/PUT/DELETE 面）
CDN、静态资源、文档域名跳过（w3.org/schema.org/jsdelivr/npm 类噪声域不算目标端点）。

## 收尾画像（每轮收尾义务）

冷启动轮（图里还没有画像时）生产一条**目标画像**，措辞不含任何阶段词，格式为一条
紧凑事实：`目标画像：<业务形态/技术栈/身份模型一句话>`。
前缀 `目标画像：` 全图唯一——更新时追加新版（旧版由观察者标 superseded），不改写旧条。
画像用途：接力封面页（下一会话第一眼）+ 观察者判案标尺（业务语境判断）。
