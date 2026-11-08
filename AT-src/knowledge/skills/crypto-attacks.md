---
name: crypto-attacks
description: >-
  Cryptography attacks complete playbook. Covers RSA (Wiener/Coppersmith/Hastad/Bleichenbacher/CRT fault/common factor/partial key), symmetric (CBC padding oracle/ECB cut-paste/bit-flip/stream key reuse/LFSR), lattice (LLL/BKZ/HNP/knapsack/Coppersmith multivariate), hash (length extension/MD5-SHA1 collision/HMAC timing/0e magic), classical (frequency analysis/Vigenere/Kasiski/XOR), and PHP/JS type juggling weak comparison (0e magic hash collision, in_array loose, strcmp array bypass). Load for any crypto CTF challenge, real-world cryptographic weakness, or loose-comparison auth bypass.
---

<!-- src: hacker/.claude/skills/crypto-attacks/SKILL.md -->

# Cryptography Attacks — Complete Playbook

## Internal Navigation

| Section | Content |
|---|---|
| Part 1 | RSA Attack Techniques |
| Part 2 | RSA Attack Catalog (Detailed) |
| Part 3 | Symmetric Cipher Attacks |
| Part 4 | Block Cipher Attacks (Scripts) |
| Part 5 | Lattice Crypto Attacks |
| Part 6 | Hash Attack Techniques |
| Part 7 | Classical Cipher Analysis |
| Part 8 | Type Juggling & Weak Comparison |

---

# Part 1: RSA Attack Techniques


# SKILL: RSA Attack Techniques — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert RSA attack techniques for CTF and authorized security assessments. Covers factorization attacks, small exponent exploits, lattice-based approaches (Wiener/Boneh-Durfee/Coppersmith), broadcast attacks, common modulus, padding oracles, and fault attacks. Base models often suggest attacks that don't match the given parameters or miss the correct attack selection based on what's known.

## 0. RELATED ROUTING

- [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md) for deep lattice theory behind Coppersmith/Boneh-Durfee
- [hash-attack-techniques](../hash-attack-techniques/SKILL.md) when RSA signature forgery involves hash weaknesses
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) when RSA protects a symmetric key (hybrid encryption)

### Advanced Reference

Also load [RSA_ATTACK_CATALOG.md](./RSA_ATTACK_CATALOG.md) when you need:
- Detailed SageMath/Python implementation for each attack
- Step-by-step mathematical derivation
- Edge cases and failure conditions per attack

### Quick attack selection

| Given / Observable | Attack | Tool |
|---|---|---|
| Small n (< 512 bits) | Direct factorization | factordb, yafu, msieve |
| e = 3, small message | Cube root | gmpy2.iroot |
| Multiple (n, c) same small e | Hastad broadcast | CRT + iroot |
| Very large e or very small d | Wiener / Boneh-Durfee | SageMath, RsaCtfTool |
| Partial p knowledge | Coppersmith small roots | SageMath |
| Same n, different e | Common modulus | Extended GCD |
| Multiple n values | Batch GCD (shared factor) | Python/SageMath |
| Padding error oracle | Bleichenbacher | Custom script |
| LSB parity oracle | LSB oracle attack | Custom script |
| Fault in CRT computation | RSA-CRT fault | Single faulty signature |


## 1. FACTORIZATION ATTACKS

### 1.1 Direct Factorization (Small n)

```python
from sympy import factorint

n = 0x...  # small modulus
factors = factorint(n)
p, q = list(factors.keys())
```

**When**: n < ~512 bits, or known to be in factordb.

### 1.2 Fermat's Factorization

Works when p and q are close together: |p - q| is small.

```python
from gmpy2 import isqrt, is_square

def fermat_factor(n):
    a = isqrt(n) + 1
    while True:
        b2 = a * a - n
        if is_square(b2):
            b = isqrt(b2)
            return (a + b, a - b)
        a += 1
```

### 1.3 Pollard's p-1

Works when p-1 has only small prime factors (B-smooth).

```python
from gmpy2 import gcd

def pollard_p1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
    d = gcd(a - 1, n)
    if 1 < d < n:
        return d
    return None
```

### 1.4 Batch GCD (Multiple n share a factor)

```python
from math import gcd
from functools import reduce

def batch_gcd(moduli):
    """Find shared factors among multiple RSA moduli."""
    product = reduce(lambda a, b: a * b, moduli)
    results = {}
    for i, n in enumerate(moduli):
        remainder = product // n
        g = gcd(n, remainder)
        if g != 1 and g != n:
            results[i] = (g, n // g)
    return results
```

---

## 2. SMALL EXPONENT ATTACKS

### 2.1 Cube Root Attack (e = 3, small m)

If m^e < n (no modular reduction occurred), simply take the e-th root.

```python
from gmpy2 import iroot

c = 0x...  # ciphertext
e = 3
m, exact = iroot(c, e)
if exact:
    print(f"Plaintext: {bytes.fromhex(hex(m)[2:])}")
```

### 2.2 Hastad Broadcast Attack

Same message encrypted with same small e under different moduli (n₁, n₂, ..., nₑ).

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot

# e = 3, three ciphertexts under three different n
n_list = [n1, n2, n3]
c_list = [c1, c2, c3]

# CRT: find x such that x ≡ ci (mod ni) for all i
r, M = crt(n_list, c_list)
m, exact = iroot(r, 3)
assert exact
```

### 2.3 Related Message Attack (Franklin-Reiter)

Two messages related by a known linear function: m₂ = a·m₁ + b. Same n and e.

```python
# SageMath
def franklin_reiter(n, e, c1, c2, a, b):
    R.<x> = PolynomialRing(Zmod(n))
    f1 = x^e - c1
    f2 = (a*x + b)^e - c2
    return Integer(n - gcd(f1, f2).coefficients()[0])
```

---

## 3. LARGE e / SMALL d ATTACKS

### 3.1 Wiener's Attack (Continued Fractions)

When d < n^(1/4) / 3, the continued fraction expansion of e/n reveals d.

```python
def wiener_attack(e, n):
    """Recover d when d is small via continued fractions."""
    cf = continued_fraction(e, n)
    convergents = get_convergents(cf)

    for k, d in convergents:
        if k == 0:
            continue
        phi_candidate = (e * d - 1) // k
        # phi(n) = n - p - q + 1 → p + q = n - phi + 1
        s = n - phi_candidate + 1
        # p, q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            from gmpy2 import isqrt, is_square
            if is_square(discriminant):
                return d
    return None

def continued_fraction(a, b):
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf

def get_convergents(cf):
    convergents = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        convergents.append((h_curr, k_curr))
    return convergents
```

### 3.2 Boneh-Durfee Attack (Lattice-Based)

Extends Wiener: works when d < n^0.292. Uses lattice reduction (LLL/BKZ).

**Use SageMath implementation** — see [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md) for theory.

---

## 4. COPPERSMITH'S METHOD

### 4.1 Stereotyped Message

Known portion of plaintext, unknown part is small.

```python
# SageMath
n = ...
e = 3
c = ...
known_prefix = b"flag{" + b"\x00" * 27  # known prefix, unknown suffix
known_int = int.from_bytes(known_prefix, 'big')

R.<x> = PolynomialRing(Zmod(n))
f = (known_int + x)^e - c
roots = f.small_roots(X=2^(27*8), beta=1.0)
if roots:
    m = known_int + int(roots[0])
    print(bytes.fromhex(hex(m)[2:]))
```

### 4.2 Partial Key Exposure

Known MSB or LSB of p → recover full p via Coppersmith.

```python
# SageMath — known MSB of p
p_msb = ...  # known upper bits of p
R.<x> = PolynomialRing(Zmod(n))
f = p_msb + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5)
if roots:
    p = p_msb + int(roots[0])
    q = n // p
```

---

## 5. COMMON MODULUS ATTACK

Two ciphertexts of same message under same n but different e₁, e₂ where gcd(e₁, e₂) = 1.

```python
from gmpy2 import gcd, invert

def common_modulus(n, e1, e2, c1, c2):
    """Recover m when same message encrypted with two different e under same n."""
    assert gcd(e1, e2) == 1
    _, s1, s2 = extended_gcd(e1, e2)  # s1*e1 + s2*e2 = 1

    if s1 < 0:
        c1 = invert(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = invert(c2, n)
        s2 = -s2

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x
```

---

## 6. ORACLE ATTACKS

### 6.1 LSB Oracle (Parity Oracle)

An oracle reveals whether decrypted message is even or odd.

```python
from gmpy2 import mpz

def lsb_oracle_attack(n, e, c, oracle_func):
    """Decrypt using LSB (parity) oracle. oracle_func(c) returns m%2."""
    from fractions import Fraction
    lo, hi = Fraction(0), Fraction(n)

    for _ in range(n.bit_length()):
        c = (c * pow(2, e, n)) % n  # multiply plaintext by 2
        if oracle_func(c) == 0:
            hi = (lo + hi) / 2
        else:
            lo = (lo + hi) / 2

    return int(hi)
```

### 6.2 Bleichenbacher (PKCS#1 v1.5 Padding Oracle)

Given a padding validity oracle (valid/invalid PKCS#1 v1.5), iteratively narrow down the plaintext range.

**Complexity**: O(2^16) oracle queries per byte on average.

**Target**: TLS implementations returning different errors for valid/invalid padding.

### 6.3 Manger's Attack (PKCS#1 OAEP)

Similar to Bleichenbacher but for OAEP padding. Exploits oracle that distinguishes whether the first byte after unpadding is 0x00.

---

## 7. RSA-CRT FAULT ATTACK

If RSA-CRT signing produces a faulty signature (fault in one CRT half):

```python
def rsa_crt_fault(n, e, correct_sig, faulty_sig, msg):
    """Factor n from one correct and one faulty CRT signature."""
    from math import gcd
    diff = pow(correct_sig, e, n) - pow(faulty_sig, e, n)
    p = gcd(diff % n, n)
    if 1 < p < n:
        q = n // p
        return p, q
    return None

# Even simpler: only faulty signature needed if message is known
def rsa_crt_fault_simple(n, e, faulty_sig, msg):
    p = gcd(pow(faulty_sig, e, n) - msg, n)
    if 1 < p < n:
        return p, n // p
    return None
```

---

## 8. DECISION TREE

```
RSA challenge — what information do you have?
│
├─ Have n and it's small (< 512 bits)?
│  └─ Factor directly: factordb.com → yafu → msieve
│
├─ Have multiple n values?
│  └─ Batch GCD — shared factors?
│     ├─ Yes → factor all that share factors
│     └─ No → analyze each n individually
│
├─ Know e?
│  ├─ e = 3 (or small)?
│  │  ├─ Single ciphertext, small message → cube root
│  │  ├─ Multiple ciphertexts, different n → Hastad broadcast
│  │  ├─ Two related messages → Franklin-Reiter
│  │  └─ Partial plaintext known → Coppersmith
│  │
│  ├─ e is very large?
│  │  └─ d is likely small → Wiener → Boneh-Durfee
│  │
│  └─ Same n, two different e values?
│     └─ Common modulus attack (Bezout coefficients)
│
├─ Know partial factorization info?
│  ├─ Know some bits of p → Coppersmith partial key
│  ├─ p-1 is B-smooth → Pollard p-1
│  └─ p ≈ q (close primes) → Fermat factorization
│
├─ Have an oracle?
│  ├─ Parity oracle (LSB) → LSB oracle attack
│  ├─ Padding validity oracle (PKCS#1 v1.5) → Bleichenbacher
│  └─ OAEP oracle → Manger's attack
│
├─ Have faulty signature?
│  └─ RSA-CRT fault → factor n from faulty sig
│
├─ Know e·d relationship?
│  └─ e·d ≡ 1 mod φ(n) → factor n from (e,d,n)
│
└─ None of the above?
   ├─ Check factordb for known factorization
   ├─ Try Pollard rho for medium-size n
   ├─ Look for implementation flaws (weak PRNG for key generation)
   └─ Consider side-channel if physical access available
```

---

## 9. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| **RsaCtfTool** | Automated RSA attack suite | `python3 RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc` |
| **SageMath** | Mathematical computation | Coppersmith, lattice attacks, polynomial arithmetic |
| **factordb.com** | Online factor database | Check if n is already factored |
| **yafu** | Fast factorization (SIQS/GNFS) | `yafu "factor(n)"` |
| **msieve** | GNFS factorization | Large n factorization |
| **gmpy2** | Fast Python integer library | `iroot`, `invert`, `gcd` |
| **pycryptodome** | RSA primitives | Key construction from factors |

### RsaCtfTool Quick Commands

```bash
# From public key
python3 RsaCtfTool.py --publickey pub.pem -n --private

# From parameters
python3 RsaCtfTool.py -n $N -e $E --uncipher $C

# Try all attacks
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc --attack all
```

### Decrypt After Factoring

```python
from Crypto.PublicKey import RSA
from gmpy2 import invert

p, q = ...  # factored
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = int(invert(e, phi))

c = ...  # ciphertext as integer
m = pow(c, d, n)
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(plaintext)
```


---

# Part 2: RSA Attack Catalog


## 1. FACTORIZATION METHODS — DETAILED

### 1.1 Trial Division

```python
def trial_division(n, limit=10**6):
    """Factor n by trial division up to limit."""
    factors = []
    d = 2
    while d * d <= n and d <= limit:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors
```

### 1.2 Pollard's Rho

```python
from math import gcd
from random import randint

def pollard_rho(n):
    """Pollard's rho factorization."""
    if n % 2 == 0:
        return 2
    x = randint(2, n - 1)
    y = x
    c = randint(1, n - 1)
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    return d if d != n else None
```

### 1.3 Williams' p+1

Works when p+1 is smooth (complement to Pollard's p-1).

```python
def williams_pp1(n, B=10**6):
    """Williams p+1 factorization."""
    from sympy import nextprime
    
    for A in range(3, 20):
        v = A
        p = 2
        while p < B:
            e = 1
            pe = p
            while pe * p <= B:
                pe *= p
                e += 1
            # Lucas chain multiplication
            v = lucas_chain(v, pe, n)
            p = nextprime(p)
        
        g = gcd(v - 2, n)
        if 1 < g < n:
            return g
    return None
```

### 1.4 Quadratic Sieve (Concept)

For n in range 10^30 to 10^100. Use yafu or msieve for implementation.

```
Algorithm outline:
1. Choose factor base of small primes
2. Sieve for B-smooth values of Q(x) = (x + ⌈√n⌉)² - n
3. Collect enough smooth relations (≥ factor base size + 1)
4. Linear algebra over GF(2) to find subset product = perfect square
5. Compute gcd(x² - y², n) to find factor
```


## 2. SMALL EXPONENT ATTACKS — DETAILED

### 2.1 Cube Root with Padding Search

When m^e slightly exceeds n (wraps around a few times):

```python
from gmpy2 import iroot, mpz

def cube_root_with_wrap(c, e, n, max_k=10000):
    """Try c + k*n for small k, check if perfect e-th root."""
    for k in range(max_k):
        m, exact = iroot(mpz(c + k * n), e)
        if exact:
            return int(m)
    return None
```

### 2.2 Hastad with Linear Padding

When messages have linear padding: mᵢ = a·m + bᵢ (different padding per recipient).

```python
# SageMath
def hastad_linear_padding(n_list, c_list, e, a_list, b_list):
    """Hastad attack with linear padding: m_i = a_i * m + b_i."""
    assert len(n_list) == e
    
    # Build polynomial for CRT
    N = product(n_list)
    R.<x> = PolynomialRing(Zmod(N))
    
    g = 0
    for i in range(e):
        Ni = N // n_list[i]
        ti = inverse_mod(Ni, n_list[i])
        fi = (a_list[i] * x + b_list[i])^e - c_list[i]
        g += fi * Ni * ti
    
    g = g.monic()
    roots = g.small_roots()
    if roots:
        return int(roots[0])
    return None
```

### 2.3 Coppersmith's Short Pad Attack

Two encryptions of same message with different short random padding (r₁, r₂):

```python
# SageMath
def short_pad_attack(n, e, c1, c2, pad_bits):
    """Recover message when same message has short random padding."""
    R.<x, y> = PolynomialRing(Zmod(n))
    
    # m1 = m * 2^pad_bits + r1, m2 = m * 2^pad_bits + r2
    # Let y = r1 - r2 (difference of padding)
    g1 = x^e - c1
    g2 = (x + y)^e - c2
    
    # Resultant eliminates x, leaving univariate in y
    res = g1.resultant(g2, x)
    
    Ry.<yy> = PolynomialRing(Zmod(n))
    res_uni = Ry(res.polynomial(y))
    roots = res_uni.small_roots(X=2^pad_bits)
    
    if roots:
        diff = int(roots[0])
        # Now solve for x with known y = diff
        # ...
```

---

## 3. WIENER'S ATTACK — COMPLETE IMPLEMENTATION

```python
def wiener_full(e, n):
    """Full Wiener's attack implementation with validation."""
    from gmpy2 import isqrt, is_square, mpz
    
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    
    # Generate convergents
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    
    for a_i in cf:
        p_prev, p_curr = p_curr, a_i * p_curr + p_prev
        q_prev, q_curr = q_curr, a_i * q_curr + q_prev
        
        k, d = p_curr, q_curr
        
        if k == 0:
            continue
        
        # Check if (e*d - 1) / k is integer (= phi(n))
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        
        # p + q = n - phi + 1
        # p * q = n
        s = n - phi + 1
        discriminant = mpz(s * s - 4 * n)
        
        if discriminant < 0:
            continue
        
        if is_square(discriminant):
            sqrt_disc = isqrt(discriminant)
            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2
            if p * q == n:
                return d, int(p), int(q)
    
    return None
```

---

## 4. BONEH-DURFEE — SAGE IMPLEMENTATION

```python
# SageMath
def boneh_durfee(n, e, delta=0.292, m=4):
    """
    Boneh-Durfee attack for small d: d < n^delta.
    Based on: e*d = 1 + k*(n+1-p-q) = 1 + k*(n+1-s) where s = p+q.
    Rewrite: 1 + k*(n+1) ≡ k*s (mod e)
    """
    A = Integer((n + 1) // 2)
    P.<x, y> = PolynomialRing(ZZ)
    f = 1 + x * (A + y)
    
    X = Integer(2 * floor(n^delta))
    Y = Integer(floor(n^0.5))
    
    # Build lattice for Coppersmith-type method
    t = m + 1
    shifts = []
    
    for k in range(m + 1):
        for i in range(m - k + 1):
            g = x^i * f^k * e^(m - k)
            shifts.append(g)
    
    for k in range(1, t + 1):
        for i in range(k):
            g = y^i * f^k * e^(m - k)  
            shifts.append(g)
    
    # Construct lattice matrix and apply LLL
    # ... (full lattice construction omitted for brevity)
    # Use standard Coppersmith multivariate implementation
    
    # After LLL: extract small root (x0, y0)
    # k = x0, s = 2*(A + y0)
    # p = (s + sqrt(s^2 - 4n)) / 2
```

---

## 5. LSB ORACLE ATTACK — COMPLETE

```python
from gmpy2 import mpz, invert
from decimal import Decimal, getcontext

def lsb_oracle_full(n, e, c, oracle):
    """
    Full LSB oracle attack.
    oracle(c) → returns LSB of decrypt(c), i.e., m mod 2.
    """
    getcontext().prec = n.bit_length() + 100
    
    lo = Decimal(0)
    hi = Decimal(n)
    
    two_e = pow(2, e, n)
    multiplier = mpz(1)
    
    for i in range(n.bit_length()):
        multiplier = (multiplier * two_e) % n
        test_c = (c * multiplier) % n
        
        lsb = oracle(int(test_c))
        
        mid = (lo + hi) / 2
        if lsb == 0:
            hi = mid
        else:
            lo = mid
    
    return int(hi)
```

---

## 6. BLEICHENBACHER ATTACK — ALGORITHM OUTLINE

```
Input: oracle O(c) = 1 if PKCS-conformant, 0 otherwise
       n, e (public key), c₀ (target ciphertext)

Step 1: Blinding
  Find s₀ such that O(c₀ · s₀ᵉ mod n) = 1
  Set c ← c₀ · s₀ᵉ mod n

Step 2a: Starting search
  Find smallest s₁ ≥ ⌈n/(3B)⌉ such that O(c · s₁ᵉ mod n) = 1
  where B = 2^(8*(k-2)), k = byte length of n

Step 2b: Searching with one interval
  If M = {[a, b]}, find smallest s ≥ 2(b·sᵢ₋₁ - 2B)/n
  such that O(c · sᵉ mod n) = 1

Step 3: Narrowing intervals
  For each (s, [a,b]) in M × {s}:
    r_min = ⌈(a·s - 3B + 1) / n⌉
    r_max = ⌊(b·s - 2B) / n⌋
    For r in [r_min, r_max]:
      Update interval: [max(a, ⌈(2B + r·n)/s⌉), min(b, ⌊(3B - 1 + r·n)/s⌋)]

Step 4: Check
  If M = {[a, a]}: m = a (done!)
  Else: go to Step 2
```

---

## 7. RSA-CRT FAULT — MATHEMATICAL DERIVATION

```
RSA-CRT computation:
  sp = m^d mod p     (computed correctly)
  sq = m^d mod q     (fault injected here → s̃q ≠ sq)
  
  Correct: s = CRT(sp, sq) = sp + p · (((sq - sp) · p⁻¹) mod q)
  Faulty:  s̃ = CRT(sp, s̃q) = sp + p · (((s̃q - sp) · p⁻¹) mod q)

Verification:
  s^e ≡ m (mod p)   ← correct (sp was correct)
  s̃^e ≡ m (mod p)   ← correct (sp was correct)
  
  s^e ≡ m (mod q)   ← correct
  s̃^e ≢ m (mod q)   ← wrong (s̃q was faulty)

Therefore:
  s̃^e - m ≡ 0 (mod p)   but   s̃^e - m ≢ 0 (mod q)
  
  ⟹ gcd(s̃^e - m, n) = p
```

```python
from math import gcd

def rsa_crt_factor(n, e, m, faulty_sig):
    """Factor n from a single faulty CRT signature."""
    diff = (pow(faulty_sig, e, n) - m) % n
    p = gcd(diff, n)
    if 1 < p < n:
        return p, n // p
    return None
```

---

## 8. MULTI-PRIME RSA

When n = p · q · r (three or more primes):

```python
from sympy import factorint
from functools import reduce

def multi_prime_decrypt(n, e, c):
    factors = factorint(n)
    primes = list(factors.keys())
    
    # Euler's totient for multi-prime
    phi = reduce(lambda a, p: a * (p - 1), primes, 1)
    
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return m
```

---

## 9. KNOWN e·d → FACTOR n

```python
from random import randint
from math import gcd

def factor_from_ed(n, e, d):
    """Factor n given e and d such that e·d ≡ 1 (mod φ(n))."""
    k = e * d - 1
    
    while True:
        g = randint(2, n - 2)
        t = k
        
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)
            
            if x > 1 and gcd(x - 1, n) > 1:
                p = gcd(x - 1, n)
                if p != n:
                    return p, n // p
```

---

## 10. ATTACK CONDITIONS SUMMARY

| Attack | Condition | Complexity | Success Rate |
|---|---|---|---|
| Factordb | n is known composite | O(1) lookup | Depends on database |
| Trial division | n has small factor | O(√n) worst case | Good for n < 2^64 |
| Pollard rho | n has factor < n^(1/4) | O(n^(1/4)) | Probabilistic |
| Pollard p-1 | p-1 is B-smooth | O(B log B) | Depends on smoothness |
| Fermat | \|p-q\| < n^(1/4) | O(n^(1/4) / \|p-q\|) | Good when p ≈ q |
| Cube root | m < n^(1/e) | O(1) | Deterministic |
| Hastad | e copies, e different n | O(e log n) | Deterministic |
| Wiener | d < n^(1/4)/3 | O(log n) | Deterministic |
| Boneh-Durfee | d < n^0.292 | Polynomial | High |
| Coppersmith | Small unknown portion | Polynomial | Depends on bounds |
| Common modulus | Same n, gcd(e₁,e₂)=1 | O(log n) | Deterministic |
| Batch GCD | Shared factor among n's | O(n log² n) | Depends on key gen |
| LSB oracle | Parity oracle access | O(log n) queries | Deterministic |
| Bleichenbacher | PKCS#1 padding oracle | O(2^20) queries avg | High |
| CRT fault | Single faulty signature | O(1) | Deterministic |


---

# Part 3: Symmetric Cipher Attacks


# SKILL: Symmetric Cipher Attacks — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for attacking symmetric encryption in CTF and authorized testing. Covers CBC padding oracle, CBC bit flipping, ECB detection and exploitation, stream cipher key reuse, LFSR/LCG state recovery, RC4 biases, and meet-in-the-middle attacks. Base models often confuse ECB and CBC attack strategies or fail to set up byte-at-a-time ECB decryption correctly.

## 0. RELATED ROUTING

- [rsa-attack-techniques](../rsa-attack-techniques/SKILL.md) when symmetric key is protected by RSA
- [hash-attack-techniques](../hash-attack-techniques/SKILL.md) when HMAC or hash-based authentication is involved
- [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md) for LCG/LFSR state recovery via lattice methods

### Advanced Reference

Also load [BLOCK_CIPHER_ATTACKS.md](./BLOCK_CIPHER_ATTACKS.md) when you need:
- Detailed attack scripts with full Python implementations
- Step-by-step byte-at-a-time ECB walkthrough
- PadBuster usage and custom padding oracle scripts
- LCG/LFSR recovery implementation

### Quick attack selection

| Observable Behavior | Likely Weakness | Attack |
|---|---|---|
| Same plaintext → same ciphertext (block-aligned) | ECB mode | Cut-and-paste / byte-at-a-time |
| Padding error distinguishable | CBC padding oracle | Decrypt without key |
| Can modify ciphertext, affects next block | CBC mode, no integrity check | Bit flipping |
| Key reused with XOR/stream cipher | Two-time pad | XOR ciphertexts together |
| Predictable PRNG output | LCG or LFSR | State recovery |
| Double encryption used | 2DES-like | Meet in the middle |


## 1. PADDING ORACLE ATTACK (CBC MODE)

### 1.1 Mechanism

CBC decryption: `P_i = D_K(C_i) ⊕ C_{i-1}`

If the server reveals whether padding is valid (PKCS#7), we can decrypt any block by manipulating the previous ciphertext block.

### 1.2 Attack Steps

```
Target: decrypt block C_i (with unknown plaintext P_i)

For byte position b = 15 down to 0 (last byte first):
  padding_value = 16 - b
  
  For guess = 0x00 to 0xFF:
    Construct modified C'_{i-1}:
      - Bytes 0..b-1: original C_{i-1} bytes
      - Byte b: guess
      - Bytes b+1..15: calculated to produce correct padding
    
    Send (C'_{i-1} || C_i) to oracle
    
    If oracle says "valid padding":
      intermediate_byte[b] = guess ⊕ padding_value
      plaintext_byte[b] = intermediate_byte[b] ⊕ original_C_{i-1}[b]
```

### 1.3 Python Implementation

```python
def padding_oracle_attack(ciphertext, block_size, oracle):
    """
    oracle(ct) returns True if padding is valid, False otherwise.
    ciphertext includes IV as first block.
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b""

    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = [0] * block_size
        decrypted = [0] * block_size

        for byte_pos in range(block_size - 1, -1, -1):
            padding_val = block_size - byte_pos

            for guess in range(256):
                modified = bytearray(block_size)
                modified[byte_pos] = guess

                for j in range(byte_pos + 1, block_size):
                    modified[j] = intermediate[j] ^ padding_val

                test_ct = bytes(modified) + curr_block
                if oracle(test_ct):
                    if byte_pos == block_size - 1:
                        # Verify it's not a false positive (padding 0x02 0x02)
                        check = bytearray(modified)
                        check[byte_pos - 1] ^= 1
                        if not oracle(bytes(check) + curr_block):
                            continue

                    intermediate[byte_pos] = guess ^ padding_val
                    decrypted[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                    break

        plaintext += bytes(decrypted)

    return plaintext
```

### 1.4 Tools

```bash
# PadBuster
padbuster http://target/decrypt?ct= CIPHERTEXT_HEX 16 -encoding 0
padbuster http://target/decrypt?ct= CIPHERTEXT_HEX 16 -encoding 0 -plaintext "admin=true"
```

---

## 2. CBC BIT FLIPPING

### 2.1 Concept

Flipping bit at position j in C_{i-1} flips the same bit at position j in P_i (and corrupts all of P_{i-1}).

```
Original:  P_i[j] = D_K(C_i)[j] ⊕ C_{i-1}[j]
Modified:  P'_i[j] = D_K(C_i)[j] ⊕ C'_{i-1}[j]
                    = P_i[j] ⊕ (C_{i-1}[j] ⊕ C'_{i-1}[j])
```

### 2.2 Practical Example

```python
def cbc_bitflip(ciphertext, block_size, target_byte_pos, old_value, new_value):
    """
    Flip byte in plaintext block N+1 by modifying ciphertext block N.
    target_byte_pos: absolute position in plaintext (0-indexed)
    """
    ct = bytearray(ciphertext)
    block_num = target_byte_pos // block_size
    byte_in_block = target_byte_pos % block_size

    # Modify previous block (block_num - 1) to flip target byte
    modify_pos = (block_num - 1) * block_size + byte_in_block

    # XOR to cancel old value and set new value
    ct[modify_pos] ^= old_value ^ new_value
    return bytes(ct)

# Example: flip "admin=0" to "admin=1"
# If "admin=0" is at byte position 22 (block 1, byte 6):
modified_ct = cbc_bitflip(ciphertext, 16, 22, ord('0'), ord('1'))
```

---

## 3. ECB MODE ATTACKS

### 3.1 Detection

```python
def detect_ecb(ciphertext, block_size=16):
    """ECB produces identical blocks for identical plaintext blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# Force detection: send repeated plaintext
test_input = b"A" * 48  # at least 3 blocks of identical data
# If response has repeated blocks → ECB
```

### 3.2 ECB Cut-and-Paste

Reorder ciphertext blocks to create new valid plaintexts.

```
Original blocks:
  Block 0: "email=foo@bar.c"
  Block 1: "om&role=user&uid"
  Block 2: "=10\x0d\x0d\x0d..."

Attack: craft input so "admin" + padding lands in its own block,
then swap it in place of "user" block.

Step 1: Send email that aligns "admin" + PKCS7 to a block:
  email = "foo@bar.coadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
  → Block 1 encrypts "admin\x0b\x0b..."  (save this block)

Step 2: Send email that puts "role=" at end of block:
  email = "foo@bar.co"
  → Block 2 = "=user&uid=10..."  (but we replace this)

Step 3: Replace last block with saved "admin\x0b..." block
```

### 3.3 Byte-at-a-Time ECB Decryption

Decrypt unknown appended secret one byte at a time.

```python
def ecb_byte_at_a_time(encrypt_oracle, block_size=16):
    """
    encrypt_oracle(input_bytes) = AES_ECB(input || unknown_secret)
    Returns the unknown_secret.
    """
    secret = b""
    secret_len = len(encrypt_oracle(b"")) 

    for i in range(secret_len):
        block_num = i // block_size
        pad_len = block_size - 1 - (i % block_size)
        padding = b"A" * pad_len

        # Build lookup table
        target_ct = encrypt_oracle(padding)
        target_block = target_ct[block_num * block_size:(block_num + 1) * block_size]

        for byte_val in range(256):
            test_input = padding + secret + bytes([byte_val])
            test_ct = encrypt_oracle(test_input)
            test_block = test_ct[block_num * block_size:(block_num + 1) * block_size]

            if test_block == target_block:
                secret += bytes([byte_val])
                break

    return secret
```

---

## 4. STREAM CIPHER ATTACKS

### 4.1 Known Plaintext / Key Reuse (Two-Time Pad)

```python
def two_time_pad(c1, c2, known_crib=None):
    """
    c1 = m1 ⊕ K, c2 = m2 ⊕ K (same key K)
    c1 ⊕ c2 = m1 ⊕ m2 (key cancels)
    """
    xored = bytes(a ^ b for a, b in zip(c1, c2))

    if known_crib:
        results = []
        for offset in range(len(xored) - len(known_crib) + 1):
            candidate = bytes(
                xored[offset + i] ^ known_crib[i] for i in range(len(known_crib))
            )
            if all(0x20 <= b <= 0x7e for b in candidate):
                results.append((offset, candidate))
        return results
    return xored
```

### 4.2 Single-Byte XOR Brute Force

```python
def single_byte_xor_crack(ciphertext):
    """Brute force single-byte XOR key using frequency analysis."""
    english_freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    }
    best_score, best_key, best_plaintext = 0, 0, b""

    for key in range(256):
        plaintext = bytes(b ^ key for b in ciphertext)
        score = sum(
            english_freq.get(chr(b).lower(), 0)
            for b in plaintext if 0x20 <= b <= 0x7e
        )
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext
```

### 4.3 Repeating-Key XOR (Kasiski-like)

```python
def repeating_xor_crack(ciphertext, max_keylen=40):
    """Crack repeating-key XOR using Hamming distance for key length."""
    def hamming(a, b):
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

    # Find key length
    scores = []
    for kl in range(2, max_keylen + 1):
        blocks = [ciphertext[i:i+kl] for i in range(0, len(ciphertext) - kl, kl)]
        if len(blocks) < 4:
            continue
        dist = sum(hamming(blocks[i], blocks[i+1]) for i in range(min(3, len(blocks)-1)))
        normalized = dist / (min(3, len(blocks)-1) * kl)
        scores.append((normalized, kl))

    best_keylen = sorted(scores)[0][1]

    # Crack each position with single-byte XOR
    key = b""
    for i in range(best_keylen):
        column = bytes(ciphertext[j] for j in range(i, len(ciphertext), best_keylen))
        k, _ = single_byte_xor_crack(column)
        key += bytes([k])

    return key
```

### 4.4 LFSR State Recovery (Berlekamp-Massey)

```python
def berlekamp_massey_gf2(output_bits):
    """Recover LFSR feedback polynomial from output sequence over GF(2)."""
    n = len(output_bits)
    C = [0] * (n + 1)
    B = [0] * (n + 1)
    C[0] = B[0] = 1
    L = 0
    m = 1
    b = 1

    for N in range(n):
        d = output_bits[N]
        for i in range(1, L + 1):
            d ^= C[i] & output_bits[N - i]

        if d == 0:
            m += 1
        elif 2 * L <= N:
            T = C[:]
            for i in range(m, n + 1):
                C[i] ^= B[i - m]
            L = N + 1 - L
            B = T
            b = d
            m = 1
        else:
            for i in range(m, n + 1):
                C[i] ^= B[i - m]
            m += 1

    return C[:L + 1], L
```

### 4.5 RC4 Biases

| Bias | Description | Exploitation |
|---|---|---|
| Initial byte bias | P(K[0] = 0) ≈ 2/256 (double normal) | Statistical plaintext recovery for first bytes |
| Fluhrer-Mantin-Shamir | Weak key scheduling with IV | WEP attack (historical) |
| NOMORE attack | Long-term biases in keystream | TLS/RC4 plaintext recovery (2^24-2^26 ciphertexts) |
| Invariance weakness | Key-dependent biases throughout stream | Statistical attack on many encryptions |

---

## 5. MEET-IN-THE-MIDDLE

### 5.1 Double Encryption Attack

```
Double encryption: C = E_K2(E_K1(P))
Brute force: 2^(2n) expected
MITM:        2^(n+1) + storage for 2^n entries

Attack:
1. Encrypt P with all possible K1 → store (E_K1(P), K1) in table
2. Decrypt C with all possible K2 → check if D_K2(C) matches any entry
3. Match found → (K1, K2) recovered
```

```python
from itertools import product

def meet_in_the_middle(encrypt, decrypt, plaintext, ciphertext, keyspace_bits):
    """MITM attack on double encryption."""
    # Phase 1: build encryption table
    enc_table = {}
    for k1 in range(2**keyspace_bits):
        intermediate = encrypt(plaintext, k1)
        enc_table[intermediate] = k1

    # Phase 2: decrypt and look up
    for k2 in range(2**keyspace_bits):
        intermediate = decrypt(ciphertext, k2)
        if intermediate in enc_table:
            k1 = enc_table[intermediate]
            return k1, k2

    return None
```

---

## 6. DECISION TREE

```
Symmetric cipher challenge — what can you observe?
│
├─ Can you detect the mode?
│  ├─ Repeated input → repeated output blocks?
│  │  └─ Yes → ECB mode
│  │     ├─ Can control prefix → byte-at-a-time decryption
│  │     ├─ Can reorder blocks → cut-and-paste
│  │     └─ Can detect block boundaries → block alignment oracle
│  │
│  ├─ Error message differs for bad padding?
│  │  └─ Yes → Padding oracle (CBC)
│  │     └─ PadBuster or custom script
│  │
│  └─ Can modify ciphertext and observe effect?
│     └─ Next-block plaintext changes → CBC bit flipping
│
├─ Stream cipher or XOR?
│  ├─ Key reused on different messages?
│  │  └─ XOR ciphertexts → crib drag
│  │
│  ├─ Known plaintext-ciphertext pair?
│  │  └─ Recover keystream directly
│  │
│  ├─ Single-byte XOR key?
│  │  └─ Brute force 256 keys with frequency analysis
│  │
│  ├─ Repeating-key XOR?
│  │  └─ Hamming distance → key length → per-position crack
│  │
│  └─ LFSR-based?
│     └─ Berlekamp-Massey for state/polynomial recovery
│
├─ PRNG-based cipher?
│  ├─ LCG → truncated output lattice attack
│  ├─ Mersenne Twister → 624 outputs → full state recovery
│  └─ Custom PRNG → analyze period and state size
│
├─ Double / triple encryption?
│  └─ Meet-in-the-middle
│
└─ RC4 specifically?
   ├─ Single encryption → initial byte bias
   ├─ Many encryptions same key → statistical attack
   └─ IV prepended to key → FMS attack (WEP-like)
```

---

## 7. TOOLS

| Tool | Purpose |
|---|---|
| **PadBuster** | Automated padding oracle exploitation |
| **xortool** | Repeating-key XOR analysis (key length detection + cracking) |
| **CyberChef** | Quick XOR, encoding, block cipher operations |
| **SageMath** | LFSR/LCG analysis, lattice-based recovery |
| **pycryptodome** | AES/DES implementation for testing |
| **hashcat** | Brute force symmetric keys (GPU-accelerated) |
| **Custom Python** | All attacks above implementable in pure Python |


---

# Part 4: Block Cipher Attacks


## 1. PADDING ORACLE — FULL WALKTHROUGH

### 1.1 PKCS#7 Padding Review

```
Block size: 16 bytes
Data "HELLO" (5 bytes) → padded to 16 bytes:
  48 45 4C 4C 4F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B
  
Valid padding examples (last byte determines):
  ...01           → 1 byte of padding
  ...02 02        → 2 bytes of padding
  ...03 03 03     → 3 bytes of padding
  ...10 10 10 ... → 16 bytes (full block of padding)

Invalid:
  ...03 03 04     → last byte says 4, but 3rd-from-end ≠ 04
  ...00           → 0x00 is never valid PKCS#7
```

### 1.2 Attack Internals — Byte-by-Byte Decryption

```
Target: decrypt P[15] (last byte of target block)

CBC decryption internals:
  I[15] = AES_DEC(C_target)[15]    (intermediate value, unknown)
  P[15] = I[15] ⊕ C_prev[15]       (plaintext = intermediate ⊕ prev ciphertext)

Attack for padding 0x01 (valid when last plaintext byte = 0x01):
  We send: C'_prev || C_target
  Where C'_prev[15] = guess

  Server computes: P'[15] = I[15] ⊕ guess
  If P'[15] == 0x01, padding is valid!
  
  Therefore: I[15] = guess ⊕ 0x01
  And: P[15] = I[15] ⊕ original_C_prev[15]

Next: decrypt P[14] (need padding = 0x02 0x02):
  Set C'_prev[15] = I[15] ⊕ 0x02   (forces P'[15] = 0x02)
  Brute force C'_prev[14] until P'[14] = 0x02

Continue until all 16 bytes recovered.
```

### 1.3 Handling False Positives

```python
def is_real_padding(oracle, modified_block, target_block, byte_pos, block_size):
    """
    When cracking the last byte, padding 0x02 0x02 can give false positive.
    Verify by flipping the penultimate byte — if still valid, it was 0x01.
    """
    if byte_pos != block_size - 1:
        return True

    check = bytearray(modified_block)
    check[byte_pos - 1] ^= 1  # flip adjacent byte
    return oracle(bytes(check) + target_block)
```

### 1.4 Encryption via Padding Oracle (CBC-R)

A padding oracle can also encrypt arbitrary plaintext without the key:

```python
def padding_oracle_encrypt(plaintext, block_size, oracle):
    """Encrypt arbitrary plaintext using padding oracle (CBC-R technique)."""
    # Pad plaintext
    pad_len = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([pad_len] * pad_len)
    pt_blocks = [padded[i:i+block_size] for i in range(0, len(padded), block_size)]

    # Start with random last ciphertext block
    import os
    ct_blocks = [os.urandom(block_size)]

    # Work backwards
    for pt_block in reversed(pt_blocks):
        # Use padding oracle to find intermediate values for ct_blocks[0]
        intermediate = decrypt_block_intermediate(ct_blocks[0], block_size, oracle)
        # Previous CT block = intermediate ⊕ desired plaintext
        prev_ct = bytes(i ^ p for i, p in zip(intermediate, pt_block))
        ct_blocks.insert(0, prev_ct)

    return b"".join(ct_blocks)  # first block is IV
```


## 2. CBC BIT FLIPPING — ADVANCED SCENARIOS

### 2.1 Multi-Byte Flip

```python
def cbc_multibyte_flip(ciphertext, block_size, changes):
    """
    changes: list of (absolute_position, old_byte, new_byte)
    All changes must be in the SAME target block.
    """
    ct = bytearray(ciphertext)

    for pos, old, new in changes:
        target_block = pos // block_size
        byte_in_block = pos % block_size
        prev_block_pos = (target_block - 1) * block_size + byte_in_block
        ct[prev_block_pos] ^= old ^ new

    return bytes(ct)

# Example: change ";admin=false;" to ";admin=true;x"
changes = [
    (32 + 7, ord('f'), ord('t')),   # f → t
    (32 + 8, ord('a'), ord('r')),   # a → r
    (32 + 9, ord('l'), ord('u')),   # l → u
    (32 + 10, ord('s'), ord('e')),  # s → e
    (32 + 11, ord('e'), ord(';')),  # e → ;
    (32 + 12, ord(';'), ord('x')),  # ; → x (pad)
]
```

### 2.2 Dealing with Corrupted Block

The previous block gets corrupted. Strategies:
- If corrupted block is IV: server may not validate IV content
- If corrupted block is a "don't care" field: acceptable corruption
- Two-block technique: use padding oracle to fix the corrupted block

---

## 3. ECB BYTE-AT-A-TIME — COMPLETE WALKTHROUGH

### Step-by-Step Example

```
Server: encrypt(user_input || secret)
Block size: 16
Secret: "FLAG{example}"

Round 1: Find block size
  Send "A", "AA", "AAA", ...
  Watch ciphertext length — when it jumps by 16, block size = 16

Round 2: Confirm ECB
  Send "A" * 32 → check for repeated blocks

Round 3: Decrypt byte 0
  Send "A" * 15 (pad to align secret[0] at end of block 0)
  
  Ciphertext block 0 = E("AAAAAAAAAAAAAAA" + secret[0])
  
  Build table:
    E("AAAAAAAAAAAAAAA" + chr(0))  → block_0_0
    E("AAAAAAAAAAAAAAA" + chr(1))  → block_0_1
    ...
    E("AAAAAAAAAAAAAAA" + "F")     → block_0_70  ← matches!
  
  secret[0] = "F"

Round 4: Decrypt byte 1
  Send "A" * 14
  
  Ciphertext block 0 = E("AAAAAAAAAAAAAA" + "F" + secret[1])
  
  Build table with known prefix "AAAAAAAAAAAAAAAF":
    E("AAAAAAAAAAAAAA" + "F" + chr(0))  → ...
    E("AAAAAAAAAAAAAA" + "F" + "L")     → matches!
  
  secret[1] = "L"

Continue until all bytes recovered.
```

### 3.1 Handling Prefix

If server adds unknown prefix: `encrypt(prefix || user_input || secret)`

```python
def find_prefix_length(encrypt_oracle, block_size):
    """Determine length of unknown prefix."""
    # Find which block the prefix ends in
    base = encrypt_oracle(b"")
    for i in range(1, block_size + 1):
        test = encrypt_oracle(b"A" * i)
        # Find first block that differs from base
        for b in range(len(base) // block_size):
            base_block = base[b*block_size:(b+1)*block_size]
            test_block = test[b*block_size:(b+1)*block_size]
            if base_block != test_block:
                # Prefix ends in block b
                # Now find exact byte offset within block
                for j in range(1, block_size + 1):
                    t1 = encrypt_oracle(b"A" * j)
                    t2 = encrypt_oracle(b"B" * j)
                    if (t1[b*block_size:(b+1)*block_size] !=
                        t2[b*block_size:(b+1)*block_size]):
                        continue
                    return b * block_size + (block_size - j)
    return 0
```

---

## 4. LCG STATE RECOVERY

### 4.1 Known Outputs (Full)

```python
def recover_lcg_full(outputs, modulus):
    """Recover LCG parameters a, b from full consecutive outputs.
    LCG: x_{n+1} = a * x_n + b (mod m)
    """
    # From three consecutive outputs x0, x1, x2:
    x0, x1, x2 = outputs[0], outputs[1], outputs[2]

    # x1 = a*x0 + b (mod m)
    # x2 = a*x1 + b (mod m)
    # x2 - x1 = a*(x1 - x0) (mod m)

    a = ((x2 - x1) * pow(x1 - x0, -1, modulus)) % modulus
    b = (x1 - a * x0) % modulus
    return a, b
```

### 4.2 Truncated Outputs (Lattice-Based)

When only upper bits of each output are known:

```python
# SageMath
def recover_lcg_truncated(known_upper_bits, modulus, a, b, unknown_bits):
    """
    Recover full LCG state from truncated outputs.
    Uses CVP on a lattice.
    """
    n = len(known_upper_bits)
    B = 2^unknown_bits  # bound on unknown part

    # Build lattice
    M = matrix(ZZ, n+1, n+1)
    for i in range(n):
        M[i, i] = modulus
    # Last row encodes the recurrence
    for i in range(n):
        M[n, i] = (a^i) % modulus
    M[n, n] = B

    # LLL reduction
    L = M.LLL()
    # Extract short vector → recover unknown bits
```

---

## 5. MERSENNE TWISTER STATE RECOVERY

```python
def untemper(y):
    """Reverse MT19937 tempering to recover internal state."""
    # Undo: y ^= y >> 18
    y ^= y >> 18

    # Undo: y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000

    # Undo: y ^= (y << 7) & 0x9D2C5680 (need multiple steps)
    y ^= (y <<  7) & 0x9D2C5680
    y ^= (y << 14) & 0x9D2C5680
    y ^= (y << 21) & 0x9D2C5680
    y ^= (y << 28) & 0x9D2C5680

    # Undo: y ^= y >> 11 (need two steps)
    y ^= (y >> 11)
    y ^= (y >> 22)

    return y & 0xFFFFFFFF

def clone_mt(outputs_624):
    """Clone MT19937 state from 624 consecutive outputs."""
    assert len(outputs_624) == 624
    state = [untemper(o) for o in outputs_624]
    # Now state[] is the internal state array
    # Can predict all future outputs
    return state
```

---

## 6. AES KEY SCHEDULE WEAKNESS EXPLOITATION

### 6.1 Related-Key Attack Setup

```python
from Crypto.Cipher import AES

def related_key_test(key1, key2, plaintext):
    """Demonstrate related-key distinguisher."""
    c1 = AES.new(key1, AES.MODE_ECB).encrypt(plaintext)
    c2 = AES.new(key2, AES.MODE_ECB).encrypt(plaintext)

    # In AES-256, related keys with specific XOR differences
    # can produce predictable ciphertext relationships
    return c1, c2
```

---

## 7. GCM NONCE REUSE

### 7.1 Authentication Key Recovery

When AES-GCM nonce is reused with two different messages:

```
Given: (C1, T1, AAD1) and (C2, T2, AAD2) under same (K, nonce)

The authentication tags are:
  T1 = GHASH_H(AAD1, C1) ⊕ E_K(nonce||1)
  T2 = GHASH_H(AAD2, C2) ⊕ E_K(nonce||1)

Therefore:
  T1 ⊕ T2 = GHASH_H(AAD1, C1) ⊕ GHASH_H(AAD2, C2)

GHASH is polynomial evaluation over GF(2^128):
  GHASH_H(A, C) = A_n * H^(n+1) + ... + C_m * H^2 + len_block * H

T1 ⊕ T2 gives a polynomial equation in H (the auth key).
Factor the polynomial over GF(2^128) to find H.
With H known: forge tags for arbitrary messages.
```

```python
# SageMath
def gcm_nonce_reuse_recover_H(aad1, c1, t1, aad2, c2, t2):
    """Recover GHASH authentication key H from nonce reuse."""
    F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)

    def bytes_to_gf(b):
        return F(Integer(int.from_bytes(b, 'big')).bits())

    # Build GHASH polynomials and find roots of their difference
    # ... (polynomial construction in GF(2^128))
    # Factor to find H
```

---

## 8. PRACTICAL TIPS

| Scenario | Common Mistake | Correct Approach |
|---|---|---|
| Padding oracle timing | Not accounting for network jitter | Use statistical threshold (multiple requests per guess) |
| ECB byte-at-a-time | Wrong block alignment with prefix | Measure prefix length first, add compensating padding |
| CBC bit flip | Forgetting IV is block -1 | If flipping block 0 content, modify IV bytes |
| XOR key reuse | Trying all cribs simultaneously | Start with high-frequency English words, drag incrementally |
| LFSR recovery | Too few output bits | Need at least 2×LFSR_length bits for Berlekamp-Massey |
| MT clone | Non-consecutive outputs | Must be exactly 624 consecutive outputs, no gaps |


---

# Part 5: Lattice Crypto Attacks


# SKILL: Lattice-Based Cryptanalysis — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert lattice techniques for CTF and cryptanalysis. Covers LLL/BKZ reduction, Coppersmith's method (univariate and multivariate), Hidden Number Problem for DSA/ECDSA nonce recovery, knapsack attacks, and NTRU analysis. Base models often fail to construct the correct attack lattice (wrong dimensions, missing scaling factors) or misapply Coppersmith bounds.

## 0. RELATED ROUTING

- [rsa-attack-techniques](../rsa-attack-techniques/SKILL.md) for RSA-specific attacks that use lattice methods (Coppersmith, Boneh-Durfee)
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) for LCG state recovery via lattice
- [classical-cipher-analysis](../classical-cipher-analysis/SKILL.md) when lattice methods apply to classical cipher analysis

### Quick application guide

| Problem Type | Lattice Technique | Key Parameter |
|---|---|---|
| RSA small roots | Coppersmith (LLL on polynomial lattice) | Root bound X < N^(1/e) |
| RSA small d | Boneh-Durfee (multivariate Coppersmith) | d < N^0.292 |
| DSA/ECDSA nonce bias | Hidden Number Problem → CVP | Bias bits known |
| Knapsack cipher | Low-density lattice attack | Density < 0.9408 |
| LCG truncated output | CVP on recurrence lattice | Unknown bits per output |
| Subset sum | LLL reduction on knapsack lattice | Element size vs count |
| NTRU key recovery | Lattice reduction on NTRU lattice | Dimension and key size |


## 1. LATTICE FUNDAMENTALS

### 1.1 Definitions

A **lattice** L is the set of all integer linear combinations of basis vectors:

```
L = { a₁·b₁ + a₂·b₂ + ... + aₙ·bₙ | aᵢ ∈ ℤ }
```

where b₁, ..., bₙ are linearly independent vectors in ℝᵐ.

**Key problems**:
- **SVP** (Shortest Vector Problem): Find the shortest non-zero vector in L
- **CVP** (Closest Vector Problem): Given target t, find v ∈ L closest to t
- **SVP is NP-hard** in general, but LLL finds an approximately short vector in polynomial time

### 1.2 Lattice Quality Metrics

```
Determinant: det(L) = |det(B)| where B is the basis matrix
Gaussian heuristic: shortest vector ≈ √(n/(2πe)) · det(L)^(1/n)
```

---

## 2. LLL ALGORITHM

### 2.1 What LLL Does

Takes a lattice basis B and produces a **reduced basis** B' where:
- Vectors are nearly orthogonal
- First vector is approximately short (within 2^((n-1)/2) factor of SVP)
- Runs in polynomial time: O(n^5 · d · log³ B) where d = dimension, B = max entry size

### 2.2 SageMath Usage

```python
# SageMath
M = matrix(ZZ, [
    [1, 0, 0, large_value_1],
    [0, 1, 0, large_value_2],
    [0, 0, 1, large_value_3],
    [0, 0, 0, modulus],
])

L = M.LLL()
# Short vectors in L reveal the solution
short_vector = L[0]  # first row is typically shortest
```

### 2.3 Python (fpylll)

```python
from fpylll import IntegerMatrix, LLL

n = 4
A = IntegerMatrix(n, n)
# Fill matrix A...
A[0] = (1, 0, 0, large_value_1)
A[1] = (0, 1, 0, large_value_2)
A[2] = (0, 0, 1, large_value_3)
A[3] = (0, 0, 0, modulus)

LLL.reduction(A)
print(A[0])  # shortest vector
```

---

## 3. BKZ (BLOCK KORKINE-ZOLOTAREV)

### 3.1 Comparison with LLL

| Property | LLL | BKZ-β |
|---|---|---|
| Quality | 2^((n-1)/2) approximation | 2^(n/(β-1)) approximation |
| Speed | Polynomial | Exponential in β |
| Block size | Fixed (2) | Configurable β |
| Best for | Quick reduction | High-quality reduction |

### 3.2 Usage

```python
# SageMath
M = matrix(ZZ, [...])
L = M.BKZ(block_size=20)  # β = 20

# fpylll
from fpylll import BKZ
BKZ.reduction(A, BKZ.Param(block_size=20))
```

Rule of thumb: start with LLL, increase to BKZ if needed. BKZ block size 20-40 is usually sufficient for CTF.

---

## 4. COPPERSMITH'S METHOD

### 4.1 Univariate Case

Given f(x) ≡ 0 (mod N) with small root |x₀| < X, find x₀.

**Bound**: X < N^(1/d) where d = degree of f.

```python
# SageMath — built-in small_roots
N = ...
R.<x> = PolynomialRing(Zmod(N))
f = x^3 + a*x^2 + b*x + c  # known polynomial
roots = f.small_roots(X=2^100, beta=1.0, epsilon=1/30)
```

**Parameters**:
- `X`: upper bound on the root
- `beta`: N = p^beta (beta=1.0 for modular root of N itself; beta=0.5 for root mod unknown factor p ≈ √N)
- `epsilon`: smaller = better results but slower (try 1/30 to 1/100)

### 4.2 Stereotyped Message Attack (RSA)

```python
# SageMath
n, e, c = ...  # RSA parameters
known_msb = ...  # known upper portion of message

R.<x> = PolynomialRing(Zmod(n))
f = (known_msb + x)^e - c

# x represents the unknown lower bits
X = 2^(unknown_bit_count)
roots = f.small_roots(X=X, beta=1.0)
if roots:
    m = known_msb + int(roots[0])
```

### 4.3 Partial Key Exposure (Factor p)

Known MSBs of p: `p = p_known + x` where x is small.

```python
# SageMath
n = ...
p_known = ...  # known upper bits of p

R.<x> = PolynomialRing(Zmod(n))
f = p_known + x
roots = f.small_roots(X=2^unknown_bits, beta=0.5)
# beta=0.5 because p ≈ √n
if roots:
    p = p_known + int(roots[0])
    q = n // p
```

### 4.4 Multivariate Coppersmith (Howgrave-Graham)

For f(x, y) ≡ 0 (mod N):
- No polynomial-time algorithm guaranteed
- Heuristic methods work in practice
- Used in Boneh-Durfee for RSA small d

```python
# SageMath — Boneh-Durfee
# e*d ≡ 1 (mod phi) where phi = (p-1)(q-1)
# Rewrite: e*d = 1 + k*((n+1) - (p+q))
# Let x = k, y = (p+q), both small relative to n

R.<x, y> = PolynomialRing(ZZ)
A = (n + 1) // 2
f = 1 + x * (A + y)  # mod e

# Build shift polynomials and construct lattice
# Apply LLL to find small (x₀, y₀)
```

---

## 5. HIDDEN NUMBER PROBLEM (HNP) — DSA/ECDSA NONCE RECOVERY

### 5.1 Problem Statement

Given: signatures (rᵢ, sᵢ) where nonces kᵢ have known bias (leaked MSBs or LSBs).

DSA equation: `s = k⁻¹(H(m) + xr) mod q`

Rearranged: `k = s⁻¹(H(m) + xr) mod q`

If partial bits of k are known: reduces to CVP on a lattice.

### 5.2 Attack Setup

```python
# SageMath
def ecdsa_nonce_attack(signatures, q, known_bits, bit_position='msb'):
    """
    signatures: list of (r, s, hash, known_nonce_bits)
    q: curve order
    known_bits: number of known bits per nonce
    """
    n = len(signatures)

    # Build lattice
    B = 2^(q.nbits() - known_bits)  # bound on unknown part
    M = matrix(QQ, n + 2, n + 2)

    for i in range(n):
        r_i, s_i, h_i, a_i = signatures[i]
        t_i = Integer(inverse_mod(s_i, q) * r_i % q)
        u_i = Integer(inverse_mod(s_i, q) * h_i % q)

        M[i, i] = q
        M[n, i] = t_i
        M[n+1, i] = u_i - a_i  # a_i = known nonce bits

    M[n, n] = B / q
    M[n+1, n+1] = B

    # LLL reduction
    L = M.LLL()

    # Find row containing the private key x
    for row in L:
        x_candidate = Integer(row[n] * q / B) % q
        # Verify x_candidate against one signature
        if verify_private_key(x_candidate, signatures[0], q):
            return x_candidate

    return None
```

### 5.3 Practical Nonce Bias Sources

| Source | Leaked Bits | Required Signatures |
|---|---|---|
| MSB bias (always 0) | 1 bit | ~100 signatures |
| k generated with wrong length | Variable | ~50 signatures |
| Timing side channel | 1-4 bits | 20-100 signatures |
| Insecure PRNG | Many | Few |
| Reused nonce (k₁ = k₂) | All | 2 signatures |

For **reused nonce** (simplest case):

```python
def ecdsa_reused_nonce(r, s1, s2, h1, h2, q):
    """Recover private key when nonce k is reused."""
    # s1 - s2 = k⁻¹(h1 - h2) mod q  (since r is same)
    k = ((h1 - h2) * inverse_mod(s1 - s2, q)) % q
    x = ((s1 * k - h1) * inverse_mod(r, q)) % q
    return x, k
```

---

## 6. KNAPSACK / SUBSET SUM ATTACKS

### 6.1 Low-Density Attack

Knapsack: given weights a₁,...,aₙ and target S, find x₁,...,xₙ ∈ {0,1} such that Σxᵢaᵢ = S.

**Density** d = n / max(log₂ aᵢ). If d < 0.9408, lattice attack works.

```python
# SageMath
def knapsack_lattice(weights, target):
    """Solve subset sum via LLL lattice attack."""
    n = len(weights)

    # Build lattice (Lagarias-Odlyzko style)
    N = ceil(sqrt(n) / 2)  # scaling factor
    M = matrix(ZZ, n + 1, n + 1)

    for i in range(n):
        M[i, i] = 1
        M[i, n] = N * weights[i]
    M[n, n] = N * target

    # Alternative: CJLOSS embedding
    M2 = matrix(ZZ, n + 1, n + 2)
    for i in range(n):
        M2[i, i] = 1
        M2[i, n + 1] = N * weights[i]
    M2[n, n] = 1
    M2[n, n + 1] = N * (-target)

    L = M2.LLL()

    # Look for short vector with entries in {0, 1, -1}
    for row in L:
        if all(v in (0, 1) for v in row[:n]):
            solution = list(row[:n])
            if sum(solution[i] * weights[i] for i in range(n)) == target:
                return solution

    return None
```

---

## 7. NTRU CRYPTANALYSIS

### 7.1 NTRU Lattice

```python
# SageMath
def ntru_lattice_attack(h, q, N):
    """
    Construct NTRU lattice for key recovery.
    h = public key polynomial (mod q)
    q = modulus
    N = dimension
    """
    # NTRU lattice:
    # | qI  0 |
    # | H   I |
    # where H is the circulant matrix of h

    H = matrix(ZZ, N, N)
    for i in range(N):
        for j in range(N):
            H[i, j] = h[(j - i) % N]

    M = block_matrix([
        [q * identity_matrix(N), zero_matrix(N)],
        [H, identity_matrix(N)]
    ])

    L = M.LLL()

    # Short vector in reduced basis = (f, g) private key
    for row in L:
        f = vector(row[:N])
        g = vector(row[N:])
        if f.norm() < q and g.norm() < q:
            return f, g

    return None
```

---

## 8. CONSTRUCTING ATTACK LATTICES — METHODOLOGY

### 8.1 General Recipe

```
1. Express the cryptographic problem as:
   "Find small x such that f(x) ≡ 0 (mod N)"
   or "Find x close to target t in some lattice L"

2. Choose lattice type:
   ├─ Polynomial lattice → Coppersmith-style
   ├─ Modular lattice → HNP-style CVP
   └─ Knapsack lattice → subset sum / CJLOSS

3. Determine dimensions:
   └─ More dimensions = better approximation but slower

4. Set scaling factors:
   └─ Balance the rows so short vector has roughly equal entries
   └─ Common: multiply by N/X where X is the root bound

5. Apply reduction:
   ├─ LLL first (fast, usually sufficient)
   └─ BKZ if LLL fails (increase block size: 20, 30, 40)

6. Extract solution:
   └─ Check reduced basis rows for valid solutions
```

### 8.2 Embedding Technique (CVP → SVP)

Transform CVP into SVP by embedding the target into the lattice:

```python
# SageMath
def cvp_to_svp(basis_matrix, target, scale=1):
    """Convert CVP to SVP via Kannan's embedding."""
    n = basis_matrix.nrows()
    m = basis_matrix.ncols()

    # Augment matrix
    M = matrix(ZZ, n + 1, m + 1)
    for i in range(n):
        for j in range(m):
            M[i, j] = basis_matrix[i, j]
        M[i, m] = 0

    for j in range(m):
        M[n, j] = target[j]
    M[n, m] = scale  # scaling factor (try 1, then adjust)

    L = M.LLL()

    # Look for row with last entry = ±scale
    for row in L:
        if abs(row[m]) == scale:
            return vector(target) - vector(row[:m]) * (row[m] // abs(row[m]))

    return None
```

### 8.3 Dimension Selection Guide

| Problem | Typical Dimension | Notes |
|---|---|---|
| Coppersmith univariate (degree d) | d × m where m ≈ 1/ε | Larger m = smaller root bound |
| HNP with n signatures | n + 2 | n ≥ known_bits_ratio × q_bits |
| Knapsack with n weights | n + 1 or n + 2 | Depends on density |
| LCG with n outputs | n + 1 | More outputs = easier |
| Boneh-Durfee | (m+1)(m+2)/2 | m = parameter depth |

---

## 9. DECISION TREE

```
Lattice approach needed — which construction?
│
├─ RSA-related?
│  ├─ Small unknown part of message → Coppersmith univariate
│  │  └─ Check: unknown_bits < n_bits / e
│  ├─ Partial factor knowledge → Coppersmith mod p
│  │  └─ Use beta=0.5, X=2^unknown_bits
│  ├─ Small private exponent d → Boneh-Durfee
│  │  └─ Check: d < N^0.292
│  └─ Multiple related equations → multivariate Coppersmith
│
├─ DSA/ECDSA-related?
│  ├─ Reused nonce → direct algebraic recovery (no lattice needed)
│  ├─ Partial nonce leakage → HNP → CVP lattice
│  │  └─ Need enough signatures: n ≥ q_bits / leaked_bits
│  └─ Nonce bias → statistical HNP → larger lattice
│
├─ Knapsack / subset sum?
│  ├─ Low density (d < 0.9408) → CJLOSS lattice attack
│  ├─ High density → lattice attack unlikely to work
│  └─ Super-increasing → greedy algorithm (no lattice needed)
│
├─ LCG / PRNG?
│  ├─ Full outputs known → algebraic recovery (no lattice)
│  ├─ Truncated outputs → CVP on recurrence lattice
│  └─ Unknown modulus → use GCD of output differences
│
├─ NTRU?
│  └─ Build circulant lattice → LLL/BKZ for short key vector
│
└─ Custom problem?
   ├─ Express as "find small root of polynomial mod N" → Coppersmith
   ├─ Express as "find lattice point close to target" → CVP
   ├─ Express as "find short vector in lattice" → SVP / LLL
   └─ If none fit → probably not a lattice problem
```

---

## 10. COMMON PITFALLS

| Pitfall | Symptom | Fix |
|---|---|---|
| Root bound too large | `small_roots()` returns empty | Reduce X, increase epsilon, verify bound satisfies Coppersmith criterion |
| Wrong scaling | LLL finds irrelevant short vector | Scale columns so target vector has balanced entries |
| Insufficient dimension | Solution not in reduced basis | Increase m parameter (more shift polynomials) |
| Wrong beta | Coppersmith doesn't find factor | beta=0.5 for half-size factor, beta=1.0 for full modulus |
| Too few signatures (HNP) | Lattice attack fails | Collect more signatures with nonce bias |
| BKZ block size too small | Solution not short enough | Increase block size (try 25, 30, 40) |
| Integer overflow | SageMath crashes | Use ZZ ring explicitly, avoid mixing QQ and ZZ |


---

# Part 6: Hash Attack Techniques


# SKILL: Hash Attack Techniques — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert hash attack techniques for CTF and security assessments. Covers length extension attacks, MD5/SHA1 collision generation, meet-in-the-middle hash attacks, HMAC timing side channels, birthday attacks, and proof-of-work solving. Base models often incorrectly apply length extension to HMAC or SHA-3, or fail to distinguish between identical-prefix and chosen-prefix collisions.

## 0. RELATED ROUTING

- [rsa-attack-techniques](../rsa-attack-techniques/SKILL.md) when hash weaknesses affect RSA signature schemes
- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) when hash is used in key derivation
- [classical-cipher-analysis](../classical-cipher-analysis/SKILL.md) when analyzing hash-like constructions in classical ciphers

### Quick attack selection

| Scenario | Attack | Tool |
|---|---|---|
| `H(secret \|\| msg)` known, extend message | Length extension | HashPump, hash_extender |
| Need two files with same MD5 | Identical-prefix collision | fastcoll |
| Need specific MD5 prefix match | Chosen-prefix collision | hashclash |
| Byte-by-byte HMAC comparison | Timing attack | Custom script |
| Find any collision | Birthday attack | O(2^(n/2)) |
| Proof of work: find hash with leading zeros | Brute force | hashcat, Python |


## 1. LENGTH EXTENSION ATTACK

### 1.1 Vulnerable vs Non-Vulnerable

| Hash | Vulnerable | Why |
|---|---|---|
| MD5 | Yes | Merkle-Damgard construction |
| SHA-1 | Yes | Merkle-Damgard construction |
| SHA-256 | Yes | Merkle-Damgard construction |
| SHA-512 | Yes | Merkle-Damgard construction |
| SHA-3 / Keccak | No | Sponge construction |
| HMAC-* | No | Double hashing prevents extension |
| SHA-256 truncated | No (if truncated) | Missing internal state bits |
| BLAKE2 | No | Different construction |

### 1.2 Attack Mechanism

```
Given:   MAC = H(secret || original_message)
Known:   original_message, len(secret), MAC value
Compute: H(secret || original_message || padding || extension)
         WITHOUT knowing the secret!

How: The MAC value IS the internal hash state after processing
     (secret || original_message || padding).
     Initialize hash with this state, continue hashing extension.
```

### 1.3 Padding Calculation (MD5/SHA)

```python
def md5_padding(message_len_bytes):
    """Calculate MD5/SHA padding for given message length."""
    bit_len = message_len_bytes * 8

    # Pad with 0x80 + zeros until length ≡ 56 (mod 64)
    padding = b'\x80'
    padding += b'\x00' * ((55 - message_len_bytes) % 64)

    # Append original length as 64-bit little-endian (MD5)
    # or big-endian (SHA)
    padding += bit_len.to_bytes(8, 'little')  # MD5
    # padding += bit_len.to_bytes(8, 'big')    # SHA

    return padding
```

### 1.4 Tool Usage

```bash
# HashPump
hashpump -s "known_mac_hex" \
         -d "original_data" \
         -k 16 \            # secret length
         -a "extension_data"

# Output: new_mac, new_data (original + padding + extension)

# hash_extender
hash_extender --data "original" \
              --secret 16 \
              --append "extension" \
              --signature "known_mac_hex" \
              --format md5
```

### 1.5 Python Implementation

```python
import struct

def md5_extend(original_mac, original_data_len, secret_len, extension):
    """
    Perform MD5 length extension attack.
    original_mac: hex string of H(secret || original_data)
    """
    # Parse MAC into MD5 internal state (4 × 32-bit words, little-endian)
    h = struct.unpack('<4I', bytes.fromhex(original_mac))

    # Calculate total length after padding
    total_original = secret_len + original_data_len
    padding = md5_padding(total_original)
    forged_len = total_original + len(padding) + len(extension)

    # Continue MD5 from saved state with extension
    # (requires MD5 implementation that accepts initial state)
    from hashlib import md5
    # Most stdlib md5 doesn't expose state setting
    # Use: hlextend library or custom MD5

    import hlextend
    sha = hlextend.new('md5')
    new_hash = sha.extend(extension, original_data, secret_len,
                          original_mac)
    new_data = sha.payload  # includes original + padding + extension

    return new_hash, new_data
```

---

## 2. MD5 COLLISION ATTACKS

### 2.1 Identical-Prefix Collision (fastcoll)

Two messages with same prefix but different content, producing identical MD5.

```bash
# Generate collision pair
fastcoll -p prefix_file -o collision1.bin collision2.bin

# Result: MD5(collision1.bin) == MD5(collision2.bin)
# Files differ in exactly 128 bytes (two MD5 blocks)
```

### 2.2 Chosen-Prefix Collision (hashclash)

Two messages with different chosen prefixes, appended with computed suffixes to collide.

```bash
# hashclash (Marc Stevens)
./hashclash prefix1.bin prefix2.bin

# Result: MD5(prefix1 || suffix1) == MD5(prefix2 || suffix2)
```

### 2.3 UniColl (Single-Block Near-Collision)

Produces two messages differing in a single byte within one MD5 block, with same hash.

```
Application: forge two PDF/PE files with same MD5
  - File 1: benign content
  - File 2: malicious content
  - Same MD5 hash
```

### 2.4 Collision Applications

| Application | Technique | Impact |
|---|---|---|
| Certificate forgery | Chosen-prefix | Rogue CA certificate (proven in 2008) |
| Binary substitution | Identical-prefix + conditional | Two executables, same MD5, different behavior |
| PDF collision | UniColl | Two PDFs showing different content |
| Git commit collision | Chosen-prefix (SHAttered for SHA1) | Two commits with same hash |
| CTF: bypass MD5 check | fastcoll | Two different inputs accepted as same |

### 2.5 CTF MD5 Collision Tricks

```php
// PHP: md5($_GET['a']) == md5($_GET['b']) && $_GET['a'] != $_GET['b']

// Method 1: Array trick (not real collision)
?a[]=1&b[]=2  // md5(array) returns NULL, NULL == NULL

// Method 2: Real collision (fastcoll output, URL-encoded binary)
?a=<collision1_urlencoded>&b=<collision2_urlencoded>

// Method 3: 0e magic hashes (loose comparison ==)
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")   = "0e830400451993494058024219903391"
// PHP: "0e..." == "0e..." is TRUE (both evaluate to 0 as floats)
```

---

## 3. SHA-1 COLLISION

### 3.1 SHAttered Attack (2017)

First practical SHA-1 collision: two PDF files with same SHA-1.

- Complexity: ~2^63 SHA-1 computations
- Cost: ~$110K on GPU clusters (2017 prices)
- Tool: shattered.io provides the collision PDFs

### 3.2 SHA-1 Chosen-Prefix Collision (2020)

- Complexity: ~2^63.4 computations
- Practical for attacking PGP/GnuPG key servers
- Demonstrates SHA-1 is broken for collision resistance

### 3.3 Impact

```
SHA-1 should NOT be used for:
  ✗ Digital signatures
  ✗ Certificate fingerprints
  ✗ Git commit integrity (migration to SHA-256 in progress)
  ✗ Deduplication based on hash

SHA-1 is still OK for:
  ✓ HMAC-SHA1 (collision resistance not required)
  ✓ HKDF-SHA1 (PRF security suffices)
  ✓ Non-adversarial checksums
```

---

## 4. BIRTHDAY ATTACK

### 4.1 Generic Birthday Bound

```
For n-bit hash: expected collisions after ~2^(n/2) hashes

Hash     Bits    Birthday bound
MD5      128     2^64
SHA-1    160     2^80
SHA-256  256     2^128

CTF application: if hash is truncated to k bits,
collision in ~2^(k/2) attempts
```

### 4.2 Birthday Attack Implementation

```python
import hashlib
import os

def birthday_attack(hash_func, output_bits, max_attempts=2**28):
    """Find collision for truncated hash."""
    mask = (1 << output_bits) - 1
    seen = {}

    for _ in range(max_attempts):
        msg = os.urandom(16)
        h = int(hash_func(msg).hexdigest(), 16) & mask

        if h in seen and seen[h] != msg:
            return seen[h], msg  # collision!
        seen[h] = msg

    return None

# Example: find collision for first 32 bits of SHA-256
result = birthday_attack(hashlib.sha256, 32)
```

---

## 5. HMAC TIMING ATTACK

### 5.1 Vulnerable Comparison

```python
# VULNERABLE: early-exit string comparison
def verify_hmac(received, expected):
    return received == expected  # Python == compares left to right

# The comparison may short-circuit on first differing byte,
# leaking timing information
```

### 5.2 Attack Strategy

```python
import requests
import time

def hmac_timing_attack(url, data, hmac_len=32):
    """Byte-by-byte HMAC recovery via timing."""
    known = ""

    for pos in range(hmac_len * 2):  # hex chars
        best_char = ""
        best_time = 0

        for c in "0123456789abcdef":
            candidate = known + c + "0" * (hmac_len * 2 - len(known) - 1)
            times = []

            for _ in range(50):  # multiple samples for accuracy
                start = time.perf_counter_ns()
                requests.get(url, params={**data, "mac": candidate})
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)

            avg_time = sorted(times)[len(times)//2]  # median
            if avg_time > best_time:
                best_time = avg_time
                best_char = c

        known += best_char
        print(f"Position {pos}: {known}")

    return known
```

### 5.3 Constant-Time Comparison (Defense)

```python
import hmac

# SECURE: constant-time comparison
def verify_hmac_secure(received, expected):
    return hmac.compare_digest(received, expected)
```

---

## 6. MEET-IN-THE-MIDDLE (HASH)

### 6.1 Concept

Split hash computation into two halves, precompute one, match against the other.

```
Hash computation: H = f(g(x₁), h(x₂))

Precompute: table[g(x₁)] = x₁  for all x₁ in space₁
Search:     for each x₂ in space₂:
              if h(x₂) in table:
                found! (x₁, x₂)

Time:  O(2^(n/2)) instead of O(2^n)
Space: O(2^(n/2))
```

---

## 7. HASH PROOF-OF-WORK

### 7.1 Common CTF PoW Formats

```python
# Format 1: Find x such that SHA256(prefix + x) starts with N zero bits
import hashlib

def solve_pow_prefix(prefix, zero_bits):
    target = '0' * (zero_bits // 4)
    i = 0
    while True:
        candidate = prefix + str(i)
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h.startswith(target):
            return str(i)
        i += 1

# Format 2: Find x such that SHA256(x) ends with specific suffix
def solve_pow_suffix(suffix_hex, hash_func=hashlib.sha256):
    i = 0
    while True:
        h = hash_func(str(i).encode()).hexdigest()
        if h.endswith(suffix_hex):
            return str(i)
        i += 1
```

### 7.2 GPU-Accelerated PoW

```bash
# hashcat for SHA256 PoW
hashcat -a 3 -m 1400 --hex-charset \
  "0000000000000000000000000000000000000000000000000000000000000000:prefix" \
  "?a?a?a?a?a?a?a?a"
```

---

## 8. RAINBOW TABLES & SALTING

### 8.1 Rainbow Table Attack

```
Precomputed chain: password → hash → reduce → password₂ → hash₂ → ...
Lookup: given hash h, check if h appears in any chain
Time-memory tradeoff: less space than full table, more time than direct lookup
```

### 8.2 Salt Defeats Rainbow Tables

```
Without salt: H(password) — same password always produces same hash
With salt:    H(salt || password) — different salt per user

Rainbow tables are password-specific, not (salt+password)-specific
Each unique salt requires a separate table → infeasible
```

### 8.3 Modern Password Hashing

| Algorithm | Salt | Iterations | Memory-Hard | Recommended |
|---|---|---|---|---|
| MD5 | No | 1 | No | Never |
| SHA-256 | No | 1 | No | Never for passwords |
| bcrypt | Yes | Configurable | No | Yes |
| scrypt | Yes | Configurable | Yes | Yes |
| Argon2 | Yes | Configurable | Yes | Best choice |
| PBKDF2 | Yes | Configurable | No | Acceptable |

---

## 9. DECISION TREE

```
Hash-related challenge — what's the scenario?
│
├─ Have H(secret || message), need to extend?
│  ├─ Hash is MD5/SHA1/SHA256/SHA512?
│  │  └─ Yes → Length extension attack
│  │     └─ Need: MAC value, original message, secret length
│  │        └─ Tool: HashPump or hash_extender
│  │
│  └─ Hash is SHA3/HMAC/BLAKE2?
│     └─ Length extension doesn't work
│        └─ Look for other vulnerabilities
│
├─ Need two inputs with same hash?
│  ├─ MD5?
│  │  ├─ Same prefix → fastcoll (seconds)
│  │  ├─ Different prefixes → hashclash (hours)
│  │  └─ CTF PHP loose comparison → 0e magic hashes
│  │
│  ├─ SHA-1?
│  │  └─ SHAttered (expensive, use precomputed if possible)
│  │
│  └─ SHA-256+?
│     └─ No practical collision attack
│        └─ Look for logic flaws instead
│
├─ Need to forge HMAC?
│  ├─ Timing side channel available?
│  │  └─ Byte-by-byte timing attack
│  │
│  ├─ Key is short/weak?
│  │  └─ Brute force key with hashcat
│  │
│  └─ No weakness?
│     └─ HMAC is secure — look elsewhere
│
├─ Hash is truncated (short output)?
│  └─ Birthday attack — collision in 2^(bits/2)
│
├─ Proof of work?
│  └─ Brute force with parallel computation
│     ├─ Python multiprocessing for < 28 bits
│     ├─ hashcat/GPU for > 28 bits
│     └─ Optimize: pre-increment string, avoid re-encoding
│
└─ Password hash cracking?
   ├─ No salt → rainbow tables (pre-computed)
   ├─ Known salt → hashcat / John the Ripper
   └─ Memory-hard (Argon2/scrypt) → limited by memory, slow brute force
```

---

## 10. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| **HashPump** | Length extension attack | `hashpump -s MAC -d data -k secret_len -a extension` |
| **hash_extender** | Length extension (multiple algorithms) | `hash_extender --data D --secret L --append E --sig MAC` |
| **fastcoll** | MD5 identical-prefix collision | `fastcoll -p prefix -o out1 out2` |
| **hashclash** | MD5 chosen-prefix collision | `hashclash prefix1 prefix2` |
| **hashcat** | Password/hash cracking (GPU) | `hashcat -m MODE -a ATTACK hash wordlist` |
| **John the Ripper** | Password cracking (CPU/GPU) | `john --wordlist=rockyou.txt hashes.txt` |
| **CyberChef** | Quick hash computation and encoding | Web-based |


---

# Part 7: Classical Cipher Analysis


# SKILL: Classical Cipher Analysis — Expert Cryptanalysis Playbook

> **AI LOAD INSTRUCTION**: Expert classical cipher identification and breaking techniques for CTF. Covers cipher identification methodology (frequency analysis, IC, Kasiski), monoalphabetic substitution, Caesar/ROT, Vigenere, Enigma, affine, Hill, transposition ciphers, Bacon/Polybius/Playfair, and XOR ciphers. Base models often skip the identification step and jump to the wrong cipher type, or fail to recognize encoded (base64/hex) ciphertext that needs decoding before analysis.

## 0. RELATED ROUTING

- [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) when dealing with modern symmetric ciphers (AES/DES) rather than classical
- [hash-attack-techniques](../hash-attack-techniques/SKILL.md) when the challenge involves hash-based constructions
- [lattice-crypto-attacks](../lattice-crypto-attacks/SKILL.md) when knapsack-based ciphers are encountered

### Quick identification guide

| Observation | Likely Cipher | First Action |
|---|---|---|
| All uppercase letters, uneven frequency | Monoalphabetic substitution | Frequency analysis |
| All uppercase, flat frequency distribution | Polyalphabetic (Vigenere) | IC + Kasiski |
| Only A-Z shifted uniformly | Caesar/ROT | Brute force 25 shifts |
| Base64 alphabet (A-Za-z0-9+/=) | Base64 encoded (decode first) | Base64 decode |
| Hex string (0-9a-f) | Hex encoded (decode first) | Hex decode |
| Binary (0s and 1s) | Binary encoded | Convert to ASCII |
| Dots and dashes | Morse code | Morse decode |
| Raised/normal text pattern | Bacon cipher | Map to A/B, decode |
| 2-digit number pairs (11-55) | Polybius square | Grid lookup |
| Text appears scrambled (right letters, wrong order) | Transposition | Anagram analysis |
| Non-printable bytes XOR-like | XOR cipher | Single/repeating key XOR analysis |


## 1. CIPHER IDENTIFICATION METHODOLOGY

### 1.1 Step 1: Character Set Analysis

```python
def analyze_charset(ciphertext):
    """Identify encoding/cipher by character set."""
    chars = set(ciphertext.strip())

    if chars <= set('01 \n'):
        return "Binary encoding"
    if chars <= set('.-/ \n'):
        return "Morse code"
    if chars <= set('0123456789abcdef \n'):
        return "Hex encoding"
    if chars <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n'):
        if '=' in ciphertext or len(ciphertext) % 4 == 0:
            return "Base64 encoding"
    if chars <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZ \n'):
        return "Uppercase only — classical cipher"
    if all(c in '12345' for c in ciphertext.replace(' ', '').replace('\n', '')):
        return "Polybius square (digits 1-5)"

    return "Mixed charset — needs further analysis"
```

### 1.2 Step 2: Frequency Analysis

```python
from collections import Counter

def frequency_analysis(text):
    """Compute letter frequency distribution."""
    text = text.upper()
    letters = [c for c in text if c.isalpha()]
    total = len(letters)
    freq = Counter(letters)

    print("Letter frequencies:")
    for letter, count in freq.most_common():
        pct = count / total * 100
        bar = '#' * int(pct)
        print(f"  {letter}: {pct:5.1f}% {bar}")

    return freq

# English letter frequency (for comparison):
# E T A O I N S H R D L C U M W F G Y P B V K J X Q Z
# 12.7 9.1 8.2 7.5 7.0 6.7 6.3 6.1 6.0 4.3 4.0 2.8 ...
```

### 1.3 Step 3: Index of Coincidence (IC)

```python
def index_of_coincidence(text):
    """
    IC ≈ 0.065 → English / monoalphabetic substitution
    IC ≈ 0.038 → random / polyalphabetic cipher
    """
    text = [c for c in text.upper() if c.isalpha()]
    N = len(text)
    freq = Counter(text)

    ic = sum(f * (f - 1) for f in freq.values()) / (N * (N - 1))
    return ic

# Interpretation:
# IC > 0.060 → monoalphabetic (Caesar, simple substitution, Playfair)
# IC ≈ 0.045-0.055 → polyalphabetic with short key (Vigenere key < 10)
# IC ≈ 0.038-0.042 → polyalphabetic with long key or random
```

### 1.4 Step 4: Kasiski Examination (for Polyalphabetic)

```python
from math import gcd
from functools import reduce

def kasiski(ciphertext, min_len=3):
    """Find repeated sequences and their distances → key length."""
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    distances = []

    for length in range(min_len, min(20, len(text) // 3)):
        for i in range(len(text) - length):
            seq = text[i:i+length]
            j = text.find(seq, i + 1)
            while j != -1:
                distances.append(j - i)
                j = text.find(seq, j + 1)

    if not distances:
        return None

    # Key length is likely GCD of common distances
    common_gcds = Counter()
    for d in distances:
        for factor in range(2, min(d + 1, 30)):
            if d % factor == 0:
                common_gcds[factor] += 1

    print("Likely key lengths (by frequency):")
    for length, count in common_gcds.most_common(5):
        print(f"  Key length {length}: {count} occurrences")

    return common_gcds.most_common(1)[0][0]
```

---

## 2. MONOALPHABETIC SUBSTITUTION

### 2.1 Frequency Analysis Attack

```python
def solve_substitution(ciphertext, interactive=False):
    """Solve monoalphabetic substitution via frequency analysis."""
    freq = frequency_analysis(ciphertext)

    # English frequency order
    eng_order = "ETAOINSRHLDCUMWFGYPBVKJXQZ"
    cipher_order = ''.join(c for c, _ in freq.most_common())

    # Initial mapping (frequency-based guess)
    mapping = {}
    for i, c in enumerate(cipher_order):
        if i < len(eng_order):
            mapping[c] = eng_order[i]

    # Apply mapping
    result = ""
    for c in ciphertext.upper():
        result += mapping.get(c, c)

    return result, mapping

# Better approach: use automated solvers
# quipqiup.com — online substitution solver
# dcode.fr/monoalphabetic-substitution — with word pattern matching
```

### 2.2 Known Plaintext (Crib Dragging)

If part of the plaintext is known (e.g., "flag{" prefix):

```python
def crib_drag_substitution(ciphertext, known_plain, known_cipher):
    """Build partial mapping from known plaintext-ciphertext pair."""
    mapping = {}
    for p, c in zip(known_plain.upper(), known_cipher.upper()):
        mapping[c] = p

    # Apply partial mapping
    result = ""
    for c in ciphertext.upper():
        result += mapping.get(c, '?')

    return result, mapping
```

---

## 3. CAESAR / ROT CIPHERS

### 3.1 Brute Force

```python
def caesar_bruteforce(ciphertext):
    """Try all 25 shifts, score by English frequency."""
    results = []
    for shift in range(26):
        decrypted = ""
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decrypted += chr((ord(c) - base - shift) % 26 + base)
            else:
                decrypted += c

        # Chi-squared scoring against English frequency
        score = chi_squared_score(decrypted)
        results.append((shift, score, decrypted))

    results.sort(key=lambda x: x[1])
    return results[0]  # best match

def chi_squared_score(text):
    """Lower score = closer to English."""
    expected = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
        'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
        'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
        'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
        'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1,
    }
    text = text.upper()
    letters = [c for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return float('inf')

    freq = Counter(letters)
    score = sum(
        (freq.get(c, 0) / total * 100 - expected.get(c, 0)) ** 2 / max(expected.get(c, 0.1), 0.1)
        for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    )
    return score
```

### 3.2 ROT13 and ROT47

```python
import codecs

# ROT13 (letters only)
rot13 = codecs.decode(ciphertext, 'rot_13')

# ROT47 (ASCII 33-126)
def rot47(text):
    return ''.join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in text
    )
```

---

## 4. VIGENERE CIPHER

### 4.1 Full Attack Workflow

```
Step 1: Confirm polyalphabetic (IC ≈ 0.04-0.05)
Step 2: Find key length (Kasiski + IC per period)
Step 3: For each key position, solve as single Caesar cipher
Step 4: Assemble key → decrypt
```

### 4.2 IC-Based Key Length Detection

```python
def find_vigenere_key_length(ciphertext, max_key=20):
    """Use IC to find Vigenere key length."""
    text = [c for c in ciphertext.upper() if c.isalpha()]
    results = []

    for kl in range(1, max_key + 1):
        # Split text into kl columns
        columns = [[] for _ in range(kl)]
        for i, c in enumerate(text):
            columns[i % kl].append(c)

        # Average IC across columns
        avg_ic = sum(
            index_of_coincidence(''.join(col)) for col in columns
        ) / kl

        results.append((kl, avg_ic))
        print(f"  Key length {kl:2d}: IC = {avg_ic:.4f}")

    # Key length with IC closest to 0.065
    best = max(results, key=lambda x: x[1])
    return best[0]
```

### 4.3 Per-Position Frequency Attack

```python
def crack_vigenere(ciphertext, key_length):
    """Crack Vigenere given known key length."""
    text = [c for c in ciphertext.upper() if c.isalpha()]
    key = ""

    for pos in range(key_length):
        column = ''.join(text[i] for i in range(pos, len(text), key_length))
        # Solve as Caesar cipher
        shift, score, _ = caesar_bruteforce(column)
        key += chr(shift + ord('A'))

    # Decrypt
    plaintext = ""
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % key_length]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            plaintext += chr((ord(c) - base - shift) % 26 + base)
            ki += 1
        else:
            plaintext += c

    return key, plaintext
```

---

## 5. AFFINE CIPHER

### 5.1 Definition

`E(x) = (a·x + b) mod 26` where gcd(a, 26) = 1.

Valid a values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25 (12 values).

### 5.2 Brute Force (312 combinations)

```python
def crack_affine(ciphertext):
    """Brute force affine cipher: 12 × 26 = 312 combinations."""
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]

    for a in valid_a:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            plaintext = ""
            for c in ciphertext.upper():
                if c.isalpha():
                    y = ord(c) - ord('A')
                    x = (a_inv * (y - b)) % 26
                    plaintext += chr(x + ord('A'))
                else:
                    plaintext += c

            score = chi_squared_score(plaintext)
            if score < 50:  # reasonable English
                print(f"a={a}, b={b}: {plaintext[:50]}...")
```

### 5.3 Known Plaintext

```python
def affine_from_known(plain1, cipher1, plain2, cipher2):
    """Recover (a, b) from two known plaintext-ciphertext pairs."""
    p1, c1 = ord(plain1) - ord('A'), ord(cipher1) - ord('A')
    p2, c2 = ord(plain2) - ord('A'), ord(cipher2) - ord('A')

    # c1 = a*p1 + b, c2 = a*p2 + b
    # c1 - c2 = a*(p1 - p2) mod 26
    diff_p = (p1 - p2) % 26
    diff_c = (c1 - c2) % 26

    if gcd(diff_p, 26) != 1:
        return None

    a = (diff_c * pow(diff_p, -1, 26)) % 26
    b = (c1 - a * p1) % 26
    return a, b
```

---

## 6. HILL CIPHER

Matrix-based cipher: `C = K · P mod 26` where K is an n×n key matrix.

### 6.1 Known-Plaintext Attack

```python
import numpy as np

def crack_hill(known_plain, known_cipher, n=2):
    """Recover Hill cipher key from known plaintext-ciphertext (mod 26)."""
    # Convert to numbers
    P = [ord(c) - ord('A') for c in known_plain.upper()]
    C = [ord(c) - ord('A') for c in known_cipher.upper()]

    # Build matrices (need at least n pairs of n-grams)
    P_matrix = np.array(P[:n*n]).reshape(n, n).T
    C_matrix = np.array(C[:n*n]).reshape(n, n).T

    # K = C · P⁻¹ mod 26
    # Need modular matrix inverse
    from sympy import Matrix
    P_mat = Matrix(P_matrix.tolist())
    C_mat = Matrix(C_matrix.tolist())

    P_inv = P_mat.inv_mod(26)
    K = (C_mat * P_inv) % 26

    return K
```

---

## 7. TRANSPOSITION CIPHERS

### 7.1 Rail Fence

```python
def rail_fence_decrypt(ciphertext, rails):
    """Decrypt rail fence cipher."""
    n = len(ciphertext)
    # Build the zigzag pattern
    pattern = []
    for i in range(n):
        row = 0
        cycle = 2 * (rails - 1)
        pos = i % cycle
        row = pos if pos < rails else cycle - pos
        pattern.append((row, i))

    pattern.sort()

    # Fill in characters
    result = [''] * n
    ci = 0
    for _, orig_pos in pattern:
        result[orig_pos] = ciphertext[ci]
        ci += 1

    return ''.join(result)

# Brute force all rail counts
for rails in range(2, 20):
    print(f"Rails {rails}: {rail_fence_decrypt(ct, rails)[:50]}")
```

### 7.2 Columnar Transposition

```python
def columnar_decrypt(ciphertext, key):
    """Decrypt columnar transposition given key word."""
    n_cols = len(key)
    n_rows = -(-len(ciphertext) // n_cols)  # ceiling division

    # Determine column order from key
    order = sorted(range(n_cols), key=lambda i: key[i])

    # Calculate column lengths (some may be shorter)
    full_cols = len(ciphertext) % n_cols
    if full_cols == 0:
        full_cols = n_cols

    # Split ciphertext into columns (in key order)
    columns = [''] * n_cols
    pos = 0
    for col_idx in order:
        col_len = n_rows if col_idx < full_cols else n_rows - 1
        columns[col_idx] = ciphertext[pos:pos + col_len]
        pos += col_len

    # Read off row by row
    plaintext = ''
    for row in range(n_rows):
        for col in range(n_cols):
            if row < len(columns[col]):
                plaintext += columns[col][row]

    return plaintext
```

---

## 8. XOR CIPHER

### 8.1 Single-Byte XOR

See [symmetric-cipher-attacks](../symmetric-cipher-attacks/SKILL.md) Section 4.2 for full implementation.

### 8.2 Multi-Byte XOR (xortool)

```bash
# Automatic key length detection and cracking
xortool ciphertext.bin -l 5        # try key length 5
xortool ciphertext.bin -b          # brute force key length
xortool ciphertext.bin -c 20       # assume most common char is space (0x20)
```

### 8.3 Known Plaintext XOR

```python
def xor_known_plaintext(ciphertext, known_plain, offset=0):
    """Recover XOR key from known plaintext at given offset."""
    key_fragment = bytes(
        c ^ p for c, p in zip(ciphertext[offset:], known_plain)
    )
    print(f"Key fragment: {key_fragment}")

    # If repeating key, infer full key from fragment
    return key_fragment
```

---

## 9. SPECIAL CIPHERS

### 9.1 Bacon Cipher

Binary encoding using two typefaces (A=normal, B=bold/italic).

```python
BACON = {
    'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
    'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
    'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
    'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P',
    'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
    'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
    'BAAAA': 'Y', 'BAAAB': 'Z',
}

def decode_bacon(text):
    """Decode Bacon cipher: uppercase=B, lowercase=A (or similar mapping)."""
    binary = ''.join('B' if c.isupper() else 'A' for c in text if c.isalpha())
    result = ''
    for i in range(0, len(binary) - 4, 5):
        chunk = binary[i:i+5]
        result += BACON.get(chunk, '?')
    return result
```

### 9.2 Polybius Square

```
    1 2 3 4 5
  ┌──────────
1 │ A B C D E
2 │ F G H I/J K
3 │ L M N O P
4 │ Q R S T U
5 │ V W X Y Z

"HELLO" = "23 15 31 31 34"
```

### 9.3 Playfair

5×5 grid cipher encrypting digraphs.

```
Key: "MONARCHY" → grid:
  M O N A R
  C H Y B D
  E F G I/J K
  L P Q S T
  U V W X Z

Rules:
  Same row → shift right: HE → FE → "GF"
  Same col → shift down
  Rectangle → swap columns
```

---

## 10. DECISION TREE

```
Unknown ciphertext — how to identify and break?
│
├─ Step 1: Check encoding
│  ├─ Base64 alphabet with padding? → Decode first, then re-analyze
│  ├─ Hex string? → Convert to bytes, re-analyze
│  ├─ Binary (01)? → Convert to ASCII
│  ├─ Morse (.-/)? → Decode Morse
│  └─ Printable text? → Continue to Step 2
│
├─ Step 2: Character set
│  ├─ Only letters (A-Z)?
│  │  ├─ Compute IC
│  │  │  ├─ IC ≈ 0.065 → Monoalphabetic
│  │  │  │  ├─ Uniform shift in freq? → Caesar → brute force 25
│  │  │  │  ├─ Random-looking mapping? → Simple substitution → frequency analysis
│  │  │  │  └─ Digraph patterns? → Playfair → digraph analysis
│  │  │  │
│  │  │  ├─ IC ≈ 0.04-0.05 → Polyalphabetic
│  │  │  │  ├─ Kasiski → find key length
│  │  │  │  └─ Per-position frequency → crack Vigenere
│  │  │  │
│  │  │  └─ IC ≈ 0.038 → Very long key or one-time pad
│  │  │     └─ Look for key reuse or weak key generation
│  │  │
│  │  └─ Letters appear scrambled (right freq, wrong order)?
│  │     └─ Transposition
│  │        ├─ Rail fence → brute force rail count
│  │        └─ Columnar → try common key lengths
│  │
│  ├─ Numbers (digit pairs)?
│  │  ├─ Pairs in range 11-55 → Polybius square
│  │  └─ Numbers mod 26 → numeric substitution
│  │
│  ├─ Mixed case with pattern?
│  │  └─ Upper/lower encodes binary → Bacon cipher
│  │
│  └─ Non-printable bytes?
│     └─ XOR cipher
│        ├─ Single-byte key → brute force 256
│        ├─ Repeating key → xortool / Hamming distance
│        └─ Known plaintext → direct key recovery
│
└─ Step 3: Apply specific attack
   ├─ Substitution → quipqiup.com / frequency analysis
   ├─ Caesar → dcode.fr / brute force
   ├─ Vigenere → Kasiski + per-column Caesar
   ├─ Affine → brute force 312 combinations
   ├─ Hill → known-plaintext matrix attack
   ├─ Transposition → pattern analysis + brute force
   └─ XOR → xortool / crib dragging
```

---

## 11. TOOLS

| Tool | Purpose | URL/Usage |
|---|---|---|
| **CyberChef** | Universal encoding/cipher Swiss army knife | gchq.github.io/CyberChef |
| **dcode.fr** | 200+ cipher solvers online | dcode.fr |
| **quipqiup** | Automated substitution cipher solver | quipqiup.com |
| **xortool** | XOR cipher analysis and cracking | `pip install xortool` |
| **RsaCtfTool** | RSA + some classical cipher support | GitHub |
| **Ciphey** | Automated cipher detection and decryption | `pip install ciphey` |
| **hashID** | Identify hash types | `pip install hashid` |
| **Python** | Custom frequency analysis and scripting | All attacks above |

### CyberChef Recipes (Common)

```
ROT13:               ROT13
Caesar brute force:   ROT13 (with offset slider)
Base64 decode:        From Base64
Hex decode:           From Hex
XOR:                  XOR (key as hex/utf8)
Vigenere:             Vigenère Decode
Morse:                From Morse Code
```

---

# Part 8: Type Juggling & Weak Comparison

Type juggling is the abuse of dynamic-typing language comparison semantics to make two values that *look* different compare as equal. PHP is the canonical victim; JavaScript and Python have related but weaker forms. It sits in this file because the most common-juggling primitive — `0e...` magic hashes — is a property of the hash function output combined with the language's `==` operator, and modern auth systems still ship vulnerable comparison code.

## 1. Non-Obvious Techniques

### 1.1 PHP `==` is transitive through type coercion

```php
"0e12345" == 0           // true  (numeric string → int)
"0e12345" == "0e99999"   // true  (both parse as scientific 0)
"abc"      == 0          // true  in PHP < 8.0 (non-numeric string → 0)
null       == false      // true
false      == ""         // true
```

Any auth path that uses `==` on user input vs. a stored hash/token is a candidate. `===` blocks all of these; strict comparison is the only safe form.

### 1.2 Magic-hash collision table

Any MD5/SHA1 hash whose hex form is `0e[0-9]+` is parsed as `0 × 10^N = 0`. Two such hashes are `==` equal regardless of inputs.

Known plaintexts producing `0e`-prefix MD5:
| Plaintext | MD5 |
|---|---|
| `240610708` | `0e462097431906509019562988736854` |
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `aabg7XSs` | `0e087386482136013740957780965295` |
| `aabC9RqS` | `0e041022518697231910737266493374` |
| `0e1137126905` | produces another `0e...` md5 |

For SHA1: `aaroZmOk`, `aaK1STfY`, `aaO8zCCZF` → all produce `0e[0-9]+` SHA1 hashes.

Exploit pattern:
```php
if (md5($_GET['a']) == md5($_GET['b'])) { ... }
// ?a=240610708&b=QNKCDZO  → both hashes start with 0e, comparison is true
```

### 1.3 In_array / array_search with default loose comparison
```php
in_array('abc', [0]);              // true  in PHP < 8.0
array_search('abc', ['0' => 1]);   // 0  (non-strict)
```
Whenever an allow-list check uses `in_array` without `$strict = true`, the user input `"abc"` matches the integer `0` in the list.

### 1.4 Switch juggling
```php
switch($x) {
  case 0:   echo "zero"; break;
  case "a": echo "a";     break;
}
// $x = "abc" → matches case 0 (PHP < 8.0)
```

### 1.5 JSON `true` / non-empty array
```php
if ($json == true) ...   // any non-empty array or string passes
```
Frameworks that compare API responses with `==` instead of `===` are vulnerable to `{"authenticated": "1"}` vs `{"authenticated": 1}` vs `{"authenticated": true}`.

### 1.6 strcmp bypass
```php
if (strcmp($_GET['pw'], $stored) === 0) ...
// ?pw[]=  → strcmp returns NULL (error), NULL === 0 is false, but strcmp != 0 also false
// Older PHP: strcmp returns NULL, and NULL == 0 is true  → bypass
```
Send password as array `pw[]=anything`; strcmp errors to NULL, and `NULL === 0` is `false` in strict code but `NULL == 0` is `true` in loose code.

## 2. JavaScript equivalents

JS `==` is similarly loose but with different rules:
```js
0 == ""           // true
0 == "0"          // true
"" == "0"         // false (asymmetric!)
null == undefined // true
"1" == true       // true
```
Token comparison: `if (userToken == expectedToken)` where `expectedToken` is `"0e12345"` and user supplies `0` (number) → match.

## 3. Realistic auth-bypass scenarios

1. **API key/token check using `==`**: supply `0`, `false`, `null`, or `""` against a stored value starting with `0e` or `0`.
2. **HMAC verification with `==`**: timing-attack fix is `===` or `hash_equals`; both also fix juggling. Any codebase using `==` is suspect.
3. **Password hash comparison**: rare in modern code (password_hash/password_verify are strict) but seen in legacy / framework-less code.
4. **Cookie/session token** parsed from JSON and compared with `==`.
5. **CTF: loose comparison puzzles**: classic warm-up — give two values producing equal `0e` hashes.

## 4. Detection

- Read source (white-box): grep for `==` near `md5(`, `sha1(`, `hash(`, `password`, `token`, `auth`, `secret`, `key`, `hmac`.
- Black-box: supply `0`, `0e1`, `true`, `false`, `null`, `[]` (array), `""` to any token-style field; watch for unexpected `200`/`success`.
- Response divergence: sending `{"key":"abc"}` vs `{"key":0}` vs `{"key":true}` should produce identical errors in safe code; divergence indicates comparison is type-sensitive.

## 5. Defense

- Always use `===` for secret comparison.
- Use `hash_equals($known, $user)` (constant-time + strict).
- Type-tighten inputs at the boundary: `if (!is_string($x)) die();`
- PHP 8.0+ removed most string/int juggling edge cases — upgrade.
- ESLint: `eqeqeq` rule forces `===` in JS.

## 6. Common AI blind spots

1. **`hash_equals` is both timing-safe AND juggling-safe.** Use it as the universal fix; do not recommend `===` alone — a strict string compare is still timing-leaky.
2. **0e magic hashes are about the *hash output*, not the input.** You cannot craft inputs to *make* a hash start with `0e`; you can only use known plaintexts. Keep a list.
3. **PHP 8.0 changed the rules.** Pre-8.0 `"abc" == 0` is `true`; post-8.0 it is `false`. Always fingerprint PHP version before declaring type juggling exploitable.
4. **strcmp with array argument is PHP-only.** Other languages throw; only PHP silently returns NULL and the loose comparison saves the day for the attacker.
5. **`in_array` defaults to loose.** Most static analyzers don't flag it. Manual review is the only reliable detector.
