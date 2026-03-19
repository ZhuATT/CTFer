# WooYun Legacy

[![Website](https://img.shields.io/badge/Website-wooyun.tanweagent.com-000?style=flat-square)](https://wooyun.tanweagent.com/en.html) [![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey?style=flat-square)](LICENSE)

[中文](README.md) | **English**

> Back your AI security reports with real-world case studies and hard data

**WooYun Legacy** is a [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin built on 22,132 business logic vulnerability cases collected by WooYun (2010–2016). It injects **real company case references**, **quantitative statistics**, and **data-driven test prioritization** into Claude's security testing output.

### What It Does / Doesn't Do

**What it does:** Transforms Claude's security reports from "you should test for payment tampering" into "WooYun payment bypass: 1,056 cases, 68.7% rated high-severity — M1905 movie site's ¥2,588 subscription was purchased for ¥0.50." Case citations, statistics, and prioritization make reports more convincing to stakeholders.

**What it doesn't do:** Claude already knows business logic security testing methodology — `amount=0.01`, IDOR enumeration, state machine step-skipping — these test techniques work without the plugin. The plugin doesn't teach new penetration techniques; it adds **data ammunition** to existing capabilities.

> **Data Vintage:** Knowledge distilled from WooYun public data (2010–2016). Coverage of modern stacks (cloud-native, GraphQL, Serverless) is limited. But business logic attack patterns are more stable than tech stacks — "modify the amount parameter to see if the server validates it" works the same in 2012 and 2026.

## Installation

Two installation modes: **Lite Install** (Marketplace, recommended) and **Full Install** (clone the entire repo).

### Difference Between the Two Modes

| | Lite Install (Marketplace) | Full Install (git clone) |
|---|---|---|
| **Size** | ~432KB | ~71MB |
| **Layer 1: Domain References** (references/) | 6 methodology files | 6 methodology files |
| **Layer 2: Deep Analysis** (knowledge/) | 8 technical manuals (complete) | 8 technical manuals (complete) |
| **Layer 3: Case Database** (categories/) | 15 condensed indexes (60KB) | 15 complete case databases (71MB raw data) |
| **Condensed vs Complete** | Each category retains top 15 case titles + frequent parameters + attack pattern distribution + 10 payload fragments | All 22,132 cases with full titles, classifications, severity, company info |
| **Industry Pentest Examples** (examples/) | Not included | Telecom & banking penetration methodologies |
| **Evaluation Benchmarks** (evals/) | Not included | 12 controlled A/B test datasets |
| **Best for** | Day-to-day security testing, report writing, bug bounty | Full case retrieval, deep data analysis, custom development |

> **Bottom line:** For most users, the Lite Install covers all core plugin capabilities (methodology + statistics + case references + prioritization). Full Install is for those who need to search the complete case database or do custom analysis on the raw data.

### Option 1: Lite Install (Marketplace, Recommended)

```bash
# 1. Add the Marketplace
claude plugin marketplace add tanweai/wooyun-legacy

# 2. Install the plugin
claude plugin install wooyun-legacy@tanweai-security
```

Or inside the Claude Code interactive interface:

```
/plugin marketplace add tanweai/wooyun-legacy
/plugin install wooyun-legacy@tanweai-security
```

Once installed, Claude Code will automatically load the plugin when it detects security-related tasks.

### Option 2: Full Install (Complete Case Database)

Clone the full repository to get the 71MB raw case data + industry pentest examples + evaluation data:

```bash
# Clone the complete repository
git clone https://github.com/tanweai/wooyun-legacy.git

# Method A: Single-session load
claude --plugin-dir ./wooyun-legacy/plugins/wooyun-legacy

# Method B: Persistent install to Claude Code
# Copy the plugin directory to the plugin cache
cp -r ./wooyun-legacy/plugins/wooyun-legacy ~/.claude-personal/plugins/cache/wooyun-legacy
```

After a full install, the root-level `categories/`, `knowledge/`, `examples/`, and `evals/` directories are available as supplementary reference materials.

### Option 3: Team Configuration

Add to your project's `.claude/settings.json` so team members are automatically prompted to install:

```json
{
  "extraKnownMarketplaces": {
    "tanweai-security": {
      "source": {
        "source": "github",
        "repo": "tanweai/wooyun-legacy"
      }
    }
  },
  "enabledPlugins": {
    "wooyun-legacy@tanweai-security": true
  }
}
```

### Verify Installation

In Claude Code, type:

```
/skills
```

You should see `wooyun-legacy` in the skill list. Or simply ask a security testing question and observe whether Claude references real WooYun cases.

### Update & Uninstall

```bash
# Update marketplace and plugin (Lite Install)
claude plugin marketplace update tanweai-security
claude plugin update wooyun-legacy@tanweai-security

# Update Full Install
cd wooyun-legacy && git pull

# Uninstall plugin
claude plugin uninstall wooyun-legacy

# Remove marketplace
claude plugin marketplace remove tanweai-security
```

## Quick Start

No configuration needed after installation. The plugin automatically activates when you ask security testing questions.

### First Use

Try these prompts:

```
Help me test the payment security of this e-commerce platform. It has a shopping cart, Alipay/WeChat Pay, order management, and a refund flow.
```

```
I need to do authorization testing on this SaaS platform — IDOR, vertical privilege escalation, and unauthorized access.
```

```
Audit this order API code for business logic vulnerabilities.
```

Claude will automatically load the WooYun methodology and output structured test plans with real case references, quantitative statistics, and step-by-step testing procedures.

### Auto-Triggering

The plugin activates not only on explicit security keywords but also on **implicit black-box testing intent**:

**Explicit security keywords:**

| Chinese | English |
|------|------|
| 渗透测试、安全审计、漏洞挖掘 | penetration testing, security audit |
| 支付安全、金额篡改、订单篡改 | payment security, price tampering |
| 越权、IDOR、未授权访问 | authorization bypass, IDOR |
| 密码重置、弱口令、验证码绕过 | password reset, weak credentials |
| 逻辑漏洞、业务安全、竞态条件 | business logic, race condition |
| SRC 漏洞、代码审计安全性 | bug bounty, code review security |

**Implicit black-box testing scenarios (triggers without saying "security"):**

| What the user says | Plugin interprets as |
|---------|-----------|
| "Help me test this endpoint" | API black-box security testing |
| "Check if this feature has issues" | Business logic vulnerability review |
| "Can I change this parameter?" | Parameter tampering test |
| "How to bypass this restriction" | Business rule bypass |
| "Order/payment/refund flow testing" | Financial logic security test |
| "Find bugs" | Vulnerability hunting |

**Tool & technique keywords:**

Packet capture, Burp Suite, intercept requests, modify parameters, replay attacks, concurrency testing, ID enumeration, brute force, coupon abuse, arbitrage, rate limiting bypass, SMS bombing, API abuse, fuzz, enumerate

## What the Plugin Actually Adds

Let's be honest: Claude's security testing capabilities are already strong. In 12 controlled evaluations, Claude without the plugin passed **98% of domain-specific assertions** (47/48). Test techniques, attack patterns, remediation advice — these don't need the plugin.

The plugin adds what isn't in Claude's training data:

| Dimension | Without Plugin | With Plugin | Why It Matters |
|------|--------|--------|-----------|
| Case References | "Consider testing payment tampering" | "M1905 movie site's ¥2,588 subscription was bought for ¥0.50" | Stakeholders take notice when they see real company names |
| Statistics | "Risk is relatively high" | "Payment bypass: 1,056 cases, 68.7% high-severity" | Quantitative data gives prioritization a factual basis |
| Classification | Generic OWASP taxonomy | WooYun's "Arbitrary X" taxonomy (arbitrary account/view/modify/delete/operation) | Aligns with Chinese security community conventions |
| Prioritization | Experience-based judgment | Ranked by high-severity ratio (password reset 88% > payment bypass 68.7% > weak passwords 58.2%) | When time is limited, data tells you what to test first |
| Business Scenarios | Generic web scenarios | Alipay/WeChat callbacks, government OA, telecom BOSS systems | Real targets for Chinese SRC and enterprise testing |

**What it doesn't add:** Attack techniques (`amount=0.01`, IDOR enumeration, state machine step-skipping), test procedures, remediation advice — Claude already knows these.

## Use Cases

### Scenario 1: E-commerce Payment Security Testing

> **You say:** I'm doing a security audit on an e-commerce platform with a shopping cart, online payments (Alipay/WeChat Pay), order management, and refund flow. Help me create a security test plan for the payment and order flow.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude outputs a structured test plan including:

**Order State Machine Illegal Transition Detection (WooYun order tampering: 1,227 cases, 74.2% high-severity):**

| Illegal Transition | Attack Intent | Risk Level |
|---------|---------|---------|
| Pending Payment → Paid | Skip payment step | Critical |
| Pending Payment → Completed | Bypass payment and logistics entirely | Critical |
| Shipped → Refunded | Refund after receiving goods | High |
| Completed → Refunding | Trigger refund after confirming receipt | High |
| Refunded → Refunded | Duplicate refund | Critical |

**Each test point includes specific steps and real case references:**

> **WooYun Pattern:** "M1905 movie site's ¥2,588 subscription for just ¥0.50" — client-submitted price was trusted by the server directly.
>
> **Test Steps:**
> 1. Place a normal order (e.g., total ¥299), proceed to payment page
> 2. Intercept the "initiate payment" request
> 3. Modify the amount parameter: `amount=0.01` / `amount=0` / `amount=-1`
> 4. Observe whether the payment page shows the tampered amount

**Appendix includes quantitative statistics:** Payment bypass 1,056 cases (68.7% high-severity), order tampering 1,227 cases (74.2% high-severity), amount tampering 176 cases (83.0% high-severity)

</details>

---

### Scenario 2: SaaS Platform Authorization Testing

> **You say:** Our company has a multi-tenant SaaS platform with REST APIs. I need a complete test plan for authorization bypass — IDOR, vertical privilege escalation, and unauthorized access.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

**WooYun's unique "Arbitrary X" taxonomy (529 cases):**

| Subcategory | Cases | High-Severity % | Test Focus |
|--------|--------|----------|---------|
| Arbitrary Account Operation | 220 | 86.4% | Modify others' phone/email/password |
| Arbitrary View | 145 | 62.1% | Enumerate others' orders/info/records |
| Arbitrary Modify | 89 | 74.2% | Tamper with others' profiles/configs |
| Arbitrary Delete | 35 | 71.4% | Delete others' data/files |
| Arbitrary Operation | 40 | 72.5% | Execute sensitive operations on behalf of others |

**IDOR testing isn't just "change the ID":**

| Technique | Description |
|------|------|
| Direct ID replacement | Most basic, ~30% of cases |
| ID encoding bypass | Base64/Hex encoded IDs: decode → modify → re-encode |
| Parameter pollution | `?id=me&id=1002` |
| JSON nested tampering | `{"user": {"id": 1002}}` |
| Batch operation endpoints | `{"ids": [1001, 1002, 1003]}` |
| GraphQL authorization bypass | `node(id: "other-user-id")` |

</details>

---

### Scenario 3: Code Security Audit

> **You say:** Audit this e-commerce order API code and find all business logic vulnerabilities.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude audits using a four-phase methodology, outputting a structured report:

```
Vulnerability 1: Amount can be tampered to negative — no coupon discount cap
├── Severity: Critical
├── Domain: Financial — Amount Tampering (176 cases, 83.0% high-severity)
├── Code Location: total_price -= coupon.discount_amount (no floor check)
├── Business Impact: Attacker can make total_price negative
└── Fix: total_price = max(total_price, 0.01)

Vulnerability 2: Coupon has no ownership check — any user can reuse
├── Severity: High
├── Domain: Authorization — Arbitrary Operation (40 cases, 72.5% high-severity)
└── Fix: Add AND user_id = current_user.id condition

Vulnerability 3: Quantity parameter has no range validation — negative/zero/extreme values
├── ...(9 vulnerabilities found in total)
```

</details>

---

### Scenario 4: SRC Bug Bounty Hunter

> **You say:** I'm a bug bounty hunter targeting a large internet company. I have two days. Help me create a vulnerability hunting plan.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude prioritizes by time and high-severity rate:

**Day 1 — High-Severity Speed Run:**

| Priority | Target | WooYun High-Severity % | Time |
|--------|------|--------------|------|
| P0 | Payment amount tampering | 83.0% | 2h |
| P0 | Password reset logic | 88.0% | 2h |
| P1 | IDOR enumeration | 62.3% | 3h |
| P1 | Unauthenticated admin panel | 58.2% | 1h |

**Day 2 — Deep Dive:**

| Priority | Target | WooYun High-Severity % | Time |
|--------|------|--------------|------|
| P1 | Race condition / double-spend | 74.8% | 3h |
| P2 | CAPTCHA bypass | — | 2h |
| P2 | Information disclosure scan | 64.7% | 2h |

</details>

---

### Scenario 5: Race Condition Focused Testing

> **You say:** Test a ticketing system for race condition vulnerabilities. It has ticket purchasing, payment, and refund features. Include test scripts.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude outputs a test plan with Python concurrency scripts:

```python
import asyncio, aiohttp

async def race_buy_ticket(session, url, ticket_id, token):
    payload = {"ticket_id": ticket_id, "quantity": 1}
    headers = {"Authorization": f"Bearer {token}"}
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "https://target.com/api/ticket/buy"
    async with aiohttp.ClientSession() as session:
        # 50 concurrent requests for the same ticket
        tasks = [race_buy_ticket(session, url, "TICKET-001", token)
                 for _ in range(50)]
        results = await asyncio.gather(*tasks)
        success = [r for r in results if r.get("status") == "success"]
        print(f"Successful purchases: {len(success)} (expected: 1)")
```

Also includes state machine illegal transitions, TOCTOU race tests — each backed by WooYun cases.

</details>

---

### Scenario 6: Writing Security Reports for Stakeholders

> **You say:** I just finished testing an e-commerce system and found three vulnerabilities: payment amount can be changed, IDOR can enumerate orders, and the admin panel has no authentication. Help me write a convincing report for management.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude's reports use WooYun data to back every vulnerability with evidence instead of vague "please fix" recommendations:

```
## Vulnerability 1: Payment Amount Not Validated Server-Side

Severity: Critical
Business Impact: Attacker can change any product price to ¥0.01 and complete payment

Industry Reference:
  WooYun has 1,056 payment bypass vulnerabilities, 68.7% rated high-severity.
  Notable case: M1905 movie site's ¥2,588 subscription was purchased for ¥0.50
  due to the same class of vulnerability.
  This vulnerability's technical characteristics match WooYun's 176 amount
  tampering cases (83.0% high-severity) exactly.

Remediation:
  All price calculations must be performed server-side. Client-submitted
  price parameters should only be used for display purposes.
  ……
```

**Why this beats a generic report:** Executives don't understand what `amount=0.01` means, but "same vulnerability that cost M1905 ¥2,588" — that they understand. Numbers and cases are the language for persuading non-technical decision-makers.

</details>

---

### Scenario 7: Test Prioritization Under Time Pressure

> **You say:** Client gave me two days to test a B2B platform with tons of features (user management, orders, payments, invoicing, approval workflows, report exports). I can't test everything. Help me prioritize by risk.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude ranks by WooYun high-severity percentages — not "gut feeling" but data:

```
Two-Day Test Plan (Ranked by WooYun High-Severity %)

Day 1 — Must Test (High-Severity % >75%)
┌──────────────────────┬─────────┬────────────┬──────┐
│ Test Item            │ Sev. %  │ WooYun Cases│ Time │
├──────────────────────┼─────────┼────────────┼──────┤
│ Payment tampering    │ 83.0%   │ 176        │ 2h   │
│ Balance/withdrawal   │ 77.9%   │ 113        │ 1.5h │
│ Approval flow bypass │ 74.8%   │ 266(logic) │ 2h   │
│ Order state tampering│ 74.2%   │ 1,227      │ 2h   │
└──────────────────────┴─────────┴────────────┴──────┘

Day 2 — Should Test (High-Severity % 50-75%)
┌──────────────────────┬─────────┬────────────┬──────┐
│ Test Item            │ Sev. %  │ WooYun Cases│ Time │
├──────────────────────┼─────────┼────────────┼──────┤
│ Report export authz  │ 64.7%   │ 4,858(info)│ 2h   │
│ IDOR enumeration     │ 62.3%   │ 1,705      │ 3h   │
│ Invoice API abuse    │ 62.3%   │ (authz)    │ 1.5h │
└──────────────────────┴─────────┴────────────┴──────┘

If time runs out, cut Day 2. Day 1's four items cover the highest-risk attack surfaces.
```

**Without the plugin:** Claude can still list priorities, but the ranking is based on "general experience." With the plugin, every priority has hundreds to thousands of cases as statistical backing — useful when explaining "why test this first" to clients.

</details>

---

### Scenario 8: China-Specific Business Security Testing

> **You say:** Help me test a government services platform with unified identity auth, administrative approval, license/certificate lookup, online payment, integrated with Alipay and WeChat Pay.

<details>
<summary><b>Click to expand Claude's response (excerpt)</b></summary>

Claude provides China government system-specific test focus areas using WooYun data:

**Government System Weak Password Patterns (WooYun weak passwords: 7,513 cases, 58.2% high-severity):**

High-frequency weak passwords in WooYun government system data:
- Admin panels: `admin/admin123`, `admin/888888`
- Business systems: `employee_id/employee_id`, `pinyin_name/123456`
- Databases: `sa/empty`, `root/root`
- Operations interfaces: `test/test`, `tomcat/tomcat`

**Alipay/WeChat Callback Parameter Testing:**

| Test Point | Attack Method | WooYun Reference |
|--------|---------|------------|
| Callback notification forgery | Craft POST request to notify_url without signature verification | Payment bypass 1,056 cases |
| trade_status tampering | Change WAIT_BUYER_PAY to TRADE_SUCCESS | Order tampering 1,227 cases |
| out_trade_no enumeration | Modify merchant order number to view others' payment records | Authorization bypass 1,705 cases |
| total_amount tampering | Callback amount doesn't match actual payment amount | Amount tampering 176 cases |

</details>

---

### More Use Cases

| Scenario | Example Prompt | Plugin's Added Value |
|------|---------|------------------|
| Password Reset Security | "Test the password reset feature for security" | 777 cases + 88% high-severity rate |
| Weak Password Detection | "Run weak password checks on these government systems" | Industry-specific high-frequency password patterns |
| CAPTCHA Bypass | "Test this fintech app's CAPTCHA security" | CAPTCHA bypass case taxonomy (echo/brute/reuse/expiry) |
| Information Disclosure | "Audit this Spring Boot system for info leaks" | 4,858 info disclosure cases with taxonomy |
| Configuration Hardening | "Check Tomcat + MySQL + Redis + Nginx configuration security" | 1,796 misconfiguration cases, 72.6% high-severity |
| Cloud Security | "Create an Alibaba Cloud/AWS security checklist" | China-specific cloud misconfiguration patterns |
| Banking App Assessment | "Business logic security assessment for a mobile banking app" | Financial domain: 2,919 cases attack pattern matrix |
| Security Training | "Prepare a payment security training for the dev team" | Real cases are more educational than abstract theory |
| Compliance Audit | "How to test business logic for compliance audits" | Map WooYun data to compliance requirements |

## Knowledge Coverage

### Three-Layer Progressive Knowledge System

The plugin uses a three-layer progressive loading architecture — loads on demand, not all at once:

```
Layer 1: Domain References (references/)       ← Loaded first on trigger
  6 domain files · Methodology + attack pattern matrix + test checklists

Layer 2: Deep Analysis (knowledge/)             ← Loaded when technical details needed
  8 technical files · Root cause analysis + payload matrices + WAF bypass

Layer 3: Case Database (categories/)            ← Loaded when citing cases or payloads
  15 category files · Real case titles + frequent parameters + attack pattern distribution
```

### 6 Domains · 33 Vulnerability Classes

| Domain | Cases | Representative Vulnerability Types |
|------|-------|-------------|
| **Authentication Bypass** | 8,846 | Password reset (88% high-sev), weak passwords, CAPTCHA bypass, session fixation |
| **Authorization Bypass** | 6,838 | IDOR, vertical privilege escalation, arbitrary account/operation/view/modify/delete |
| **Financial Security** | 2,919 | Payment bypass (68.7% high-sev), amount tampering, order tampering, balance manipulation |
| **Information Disclosure** | 6,446 | PII leaks, credential exposure, debug info, API documentation exposure |
| **Logic Flaws** | 1,679 | State machine abuse, race conditions, flow bypass, design flaws |
| **Misconfiguration** | 1,796 | Default credentials, component exposure, hardening gaps, cloud misconfig |

### Vulnerability Severity Ranking (by High-Severity %)

| Rank | Vulnerability Type | Cases | High-Severity % |
|------|---------|-------|---------|
| 1 | Password Reset | 777 | 88.0% |
| 2 | Arbitrary Account | 220 | 86.4% |
| 3 | Withdrawal Exploit | 59 | 83.1% |
| 4 | Amount Tampering | 176 | 83.0% |
| 5 | Balance Tampering | 113 | 77.9% |
| 6 | Logic Flaw | 266 | 74.8% |
| 7 | Order Tampering | 1,227 | 74.2% |
| 8 | Misconfiguration | 1,796 | 72.6% |
| 9 | Payment Bypass | 1,056 | 68.7% |
| 10 | Information Disclosure | 4,858 | 64.7% |
| 11 | Authorization Bypass | 1,705 | 62.3% |
| 12 | Weak Passwords | 7,513 | 58.2% |

### Four-Phase Methodology

```
Phase 1: Business Flow Mapping
  └─ Understand the business → Map user journeys → Identify state transitions → Map trust boundaries

Phase 2: Hypothesis Formation
  └─ Based on 6 domain reference files, form "[Flow X] may be vulnerable to [Attack Y]" hypotheses

Phase 3: Targeted Manual Testing
  └─ Prepare multi-role accounts → Intercept requests → Single-parameter modification → Observe server behavior

Phase 4: Impact Assessment & Documentation
  └─ Prove business impact → Match WooYun patterns → Output actionable remediation
```

## Evaluation Benchmarks

12 full-domain controlled evaluations (with_skill vs without_skill), covering all 6 domains:

| Metric | With Skill | Without Skill | Difference |
|------|-----------|---------------|------|
| **Assertion Pass Rate** | 100% (72/72) | 64.6% (47/72) | **+54.8%** |
| Avg. Latency | 222s | 164s | +35% |
| Avg. Tokens | 41K | 28K | +46% |

**Breakdown:**

| Assertion Category | With Skill | Without Skill |
|---------|-----------|---------------|
| WooYun Case References | 12/12 (100%) | 0/12 (0%) |
| WooYun Statistics | 12/12 (100%) | 0/12 (0%) |
| Domain-Specific Assertions | 48/48 (100%) | 47/48 (98%) |

Conclusion: The plugin's core value is injecting real WooYun historical data (company cases + quantitative statistics + unique taxonomy), not general security knowledge.

> Full evaluation data available in the [`evals/`](evals/) directory

## Industry Penetration Playbooks

The `examples/` directory contains industry-specific penetration methodologies generated from WooYun data:

<details>
<summary><b>Telecom Penetration</b> — Weak passwords, authorization bypass, value-added service platforms, NMS, shell access paths</summary>

- **Weak Passwords:** Network devices admin/admin, BOSS systems employee_id/employee_id, databases sa/empty
- **Authorization Bypass:** Phone number enumeration for user info, plans/billing/call records
- **High-Value Attack Surfaces:** Value-added service platforms (SP→SMS Gateway→BOSS), NMS (Huawei U2000), IoT SIM card platforms
- **Shell Access Paths:** Struts2/WebLogic RCE → VPN exploits → Supply chain (outsourced vendors) → Lateral movement to BOSS/AAA

See [`examples/telecom-penetration.md`](examples/telecom-penetration.md)

</details>

<details>
<summary><b>Banking Penetration</b> — Payment vulnerabilities, mobile banking apps, verification bypass, penetration paths</summary>

- **Financial Vulnerabilities:** Password reset (88% high-sev), withdrawal bypass (83.1%), amount tampering (83.0%), payment bypass (68.7%)
- **Banking-Specific Surfaces:** Mobile banking (SSL Pinning bypass), online banking (ActiveX/front-end encryption), third-party payment APIs
- **Verification Bypass:** SMS OTP (brute force/concurrency/reuse), facial recognition (photo/hook), transaction signatures (hardcoded keys)
- **Penetration Paths:** External Web → Mobile → Supply chain → Core banking/credit/risk control

See [`examples/bank-penetration.md`](examples/bank-penetration.md)

</details>

## Project Structure

```
wooyun-legacy/                              # Marketplace repository
├── .claude-plugin/
│   └── marketplace.json                    # Marketplace manifest (tanweai-security)
├── plugins/
│   └── wooyun-legacy/                      # Plugin directory (copied to cache on install)
│       ├── .claude-plugin/
│       │   └── plugin.json                 # Plugin manifest
│       ├── skills/
│       │   └── wooyun-legacy/
│       │       ├── SKILL.md                # Main skill — methodology entry + 3-layer reference index
│       │       └── references/             # Layer 1: 6 domain references
│       │           ├── authentication-domain.md
│       │           ├── authorization-domain.md
│       │           ├── financial-domain.md
│       │           ├── information-domain.md
│       │           ├── logic-flow-domain.md
│       │           └── configuration-domain.md
│       ├── knowledge/                      # Layer 2: 8 deep analysis manuals
│       │   ├── command-execution.md        #   Command injection full attack chain
│       │   ├── sql-injection.md            #   SQL injection + WAF bypass
│       │   ├── file-upload.md              #   Upload bypass payload matrix
│       │   ├── xss.md                      #   XSS input points and bypass
│       │   └── ...                         #   (8 technical files total)
│       └── categories/                     # Layer 3: 15 vulnerability case indexes
│           ├── sql-injection.md            #   Example cases + frequent payloads
│           ├── unauthorized-access.md      #   Authorization cases + attack patterns
│           ├── weak-password.md            #   Weak password cases + frequent passwords
│           └── ...                         #   (15 category files total)
├── categories/                             # Full vulnerability case database (71MB)
├── knowledge/                              # Full knowledge methodology
├── evals/                                  # Evaluation benchmark data
├── examples/                               # Industry penetration playbooks
├── LICENSE                                 # CC BY-NC-SA 4.0
└── README.md
```

## System Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI (requires Claude Pro / Max / Team / Enterprise subscription)
- No other external dependencies

## Data Source

- **WooYun** (乌云): China's largest vulnerability disclosure platform (2010–2016), 88,636 total vulnerabilities collected
- This plugin focuses on **22,132 business logic vulnerabilities** across e-commerce, finance, social media, government, telecom, cloud services, and more
- All case data, statistical ratios, and high-severity percentages are derived from structured analysis of the original vulnerability database

## Contributing

Contributions welcome! Here's how to participate:

1. **Report Issues:** File bugs or suggestions in [Issues](https://github.com/tanweai/wooyun-legacy/issues)
2. **Submit Cases:** Add new vulnerability cases or attack patterns to the relevant domain reference files
3. **Improve Methodology:** Optimize test procedures or hypothesis formation strategies in SKILL.md
4. **Add Industry Examples:** Create new industry penetration methodologies in `examples/`

Before submitting a PR, please ensure:
- No unredacted real vulnerability details (URLs, IPs, credentials)
- Case references maintain the "company name + vulnerability type" format without exposing specific exploitation details
- Follow the existing file structure and naming conventions

## License

[CC BY-NC-SA 4.0](LICENSE) — Attribution-NonCommercial-ShareAlike

- Free to use for security research, education, and authorized testing
- Commercial use prohibited (separate licensing required)
- Derivative works must be released under the same license

## Disclaimer

**This plugin is intended solely for security research, education, and authorized penetration testing.**

It is strictly prohibited to use this plugin for unauthorized penetration testing or any illegal activities. Users assume full legal responsibility for any misuse. WooYun case references include only company names and vulnerability type descriptions — no directly exploitable vulnerability details are included.

## Community

<p align="center">
  <img src="wechat-group.jpg" width="300" alt="WeChat Group: Tanwei Security">
</p>

<p align="center">
  <b>Scan to join the Tanwei Security community group</b><br>
  <sub>Discuss the intersection of AI and security</sub>
</p>

> If the QR code has expired, follow the WeChat public account "探微杜渐人工智能" for the latest group QR code

## Tribute

In honor of WooYun and the white-hat hackers of that era.

---

*A product of Tanwei Security Lab*
