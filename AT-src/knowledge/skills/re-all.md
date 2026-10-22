---
name: re-all
description: >-
  Reverse engineering complete playbook. Covers anti-debugging (PEB/ptrace/timing/signal tricks with bypass), code obfuscation (CFF/movfuscator/API hashing/anti-disassembly), symbolic execution (angr/Z3/Unicorn with cookbook patterns), and custom VM/bytecode reverse (dispatcher identification/Sleigh modules/maze solving). Load for CTF reversing or protected binary analysis.
---

# Reverse Engineering — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Anti-Debugging Techniques |
| 2 | Anti-Debug Matrix |
| 3 | Code Obfuscation & Deobfuscation |
| 4 | Symbolic Execution Tools |
| 5 | angr Cookbook |
| 6 | VM & Bytecode Reverse |

---
# Part 1: Anti-Debugging Techniques


# SKILL: Anti-Debugging Techniques — Detection & Bypass Playbook

> **AI LOAD INSTRUCTION**: Expert anti-debug techniques across Linux and Windows. Covers ptrace, PEB flags, NtQueryInformationProcess, timing attacks, signal-based detection, TLS callbacks, VEH tricks, and all corresponding bypass methods. Base models often miss the distinction between user-mode and kernel-mode detection and the correct patching strategy for each.

## 0. RELATED ROUTING

- [code-obfuscation-deobfuscation](../code-obfuscation-deobfuscation/SKILL.md) when the binary also uses control flow flattening, VM protection, or string encryption
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) when the anti-debug sits inside a custom VM dispatcher
- [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) when you want to symbolically skip anti-debug checks entirely

### Advanced Reference

Also load [ANTI_DEBUG_MATRIX.md](./ANTI_DEBUG_MATRIX.md) when you need:
- Complete cross-reference matrix of technique × OS × detection method × bypass method
- Per-technique reliability ratings and false-positive notes
- Tool compatibility chart (GDB, x64dbg, WinDbg, Frida, ScyllaHide)

### Quick bypass picks

| Detection Class | First Bypass | Backup |
|---|---|---|
| ptrace-based (Linux) | `LD_PRELOAD` hook `ptrace()` → return 0 | Kernel module to hide tracer |
| PEB.BeingDebugged (Windows) | Patch PEB byte at `fs:[0x30]+0x2` | ScyllaHide auto-patch |
| Timing check (rdtsc) | Conditional BP after rdtsc, fix registers | Frida hook `rdtsc` return |
| IsDebuggerPresent | NOP the call / hook return 0 | x64dbg built-in hide |
| INT 2D / UD2 exception | Set VEH to handle gracefully | TitanHide driver |


## 1. LINUX ANTI-DEBUG TECHNIQUES

### 1.1 ptrace(PTRACE_TRACEME)

The classic self-attach: a process calls `ptrace(PTRACE_TRACEME, 0, 0, 0)`. If a debugger is already attached, the call fails (returns -1).

```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    exit(1); // debugger detected
}
```

**Bypass methods**:

| Method | How |
|---|---|
| `LD_PRELOAD` shim | Compile shared lib: `long ptrace(int r, ...) { return 0; }` and set `LD_PRELOAD` |
| Binary patch | NOP the `ptrace` call or patch return value check |
| GDB catch | `catch syscall ptrace` → modify `$rax` to 0 on return |
| Kernel module | Hook `sys_ptrace` to allow multiple tracers |

### 1.2 /proc/self/status — TracerPid

```c
FILE *f = fopen("/proc/self/status", "r");
// parse TracerPid: if non-zero → debugger attached
```

**Bypass**: Mount a FUSE filesystem over `/proc/self`, or `LD_PRELOAD` hook `fopen`/`fread` to filter `TracerPid` to 0.

### 1.3 Timing Checks (rdtsc / clock_gettime)

Measures elapsed time between two points; debugger single-stepping causes noticeable delay.

```asm
rdtsc
mov ebx, eax       ; save low 32 bits
; ... protected code ...
rdtsc
sub eax, ebx
cmp eax, 0x1000    ; threshold
ja  debugger_detected
```

**Bypass**: Set hardware breakpoint after second `rdtsc`, modify `eax` to pass the comparison. Or use Frida to replace the timing function.

### 1.4 Signal-Based Detection (SIGTRAP)

```c
volatile int caught = 0;
void handler(int sig) { caught = 1; }
signal(SIGTRAP, handler);
raise(SIGTRAP);
if (!caught) exit(1); // debugger swallowed the signal
```

When a debugger is attached, `SIGTRAP` is consumed by the debugger rather than delivered to the handler. **Bypass**: In GDB, use `handle SIGTRAP nostop pass` to forward the signal.

### 1.5 /proc/self/maps & LD_PRELOAD Detection

Checks for injected libraries or memory regions characteristic of debuggers/instrumentation.

```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(buf, sizeof(buf), f)) {
    if (strstr(buf, "frida") || strstr(buf, "LD_PRELOAD"))
        exit(1);
}
```

**Bypass**: Hook `fopen("/proc/self/maps")` to return a filtered version, or rename Frida's agent library.

### 1.6 Environment Variable Checks

Some protections check for `LD_PRELOAD`, `LINES`, `COLUMNS` (set by GDB's terminal), or debugger-specific env vars.

**Bypass**: Unset suspicious env vars before launch, or hook `getenv()`.

---

## 2. WINDOWS ANTI-DEBUG TECHNIQUES

### 2.1 IsDebuggerPresent / CheckRemoteDebuggerPresent

```c
if (IsDebuggerPresent()) ExitProcess(1);

BOOL debugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
if (debugged) ExitProcess(1);
```

**Bypass**: Hook `kernel32!IsDebuggerPresent` to return 0, or patch PEB directly.

### 2.2 PEB Flags

| Field | Offset (x64) | Debugged Value | Normal Value |
|---|---|---|---|
| `BeingDebugged` | `PEB+0x02` | 1 | 0 |
| `NtGlobalFlag` | `PEB+0xBC` | `0x70` (FLG_HEAP_*) | 0 |
| `ProcessHeap.Flags` | Heap+0x40 | `0x40000062` | `0x00000002` |
| `ProcessHeap.ForceFlags` | Heap+0x44 | `0x40000060` | 0 |

```asm
mov rax, gs:[0x60]    ; PEB
movzx eax, byte [rax+0x02]  ; BeingDebugged
test eax, eax
jnz debugger_detected
```

**Bypass**: Zero all four fields. ScyllaHide does this automatically.

### 2.3 NtQueryInformationProcess

| InfoClass | Value | Debugged Return |
|---|---|---|
| `ProcessDebugPort` | 0x07 | Non-zero port |
| `ProcessDebugObjectHandle` | 0x1E | Valid handle |
| `ProcessDebugFlags` | 0x1F | 0 (inverted!) |

**Bypass**: Hook `ntdll!NtQueryInformationProcess` to return clean values per info class.

### 2.4 Hardware Breakpoint Detection

```c
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
    ExitProcess(1);
```

**Bypass**: Hook `GetThreadContext` to zero DR0–DR3, or use `NtSetInformationThread(ThreadHideFromDebugger)` preemptively (ironically, the anti-debug technique itself).

### 2.5 INT 2D / INT 3 / UD2 Exception Tricks

`INT 2D` is the kernel debug service interrupt. Without a debugger, it raises `STATUS_BREAKPOINT`; with a debugger, behavior differs (byte skipping).

```asm
xor eax, eax
int 2dh
nop          ; debugger may skip this byte
; ... divergent execution path ...
```

**Bypass**: Handle in VEH or patch the interrupt instruction.

### 2.6 TLS Callbacks

TLS callbacks execute before `main()` / `WinMain()`. Anti-debug checks placed here run before the debugger's initial break.

**Bypass**: In x64dbg, set "Break on TLS Callbacks" option. In WinDbg, use `sxe ld` to break on module load.

### 2.7 NtSetInformationThread(ThreadHideFromDebugger)

```c
NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
```

After this call, the thread becomes invisible to the debugger — breakpoints and single-stepping stop working silently.

**Bypass**: Hook `NtSetInformationThread` to NOP when `ThreadInfoClass == 0x11`.

### 2.8 VEH-Based Detection

Registers a Vectored Exception Handler that checks `EXCEPTION_RECORD` for debugger-specific behavior (single-step flag, guard page violations with debugger semantics).

**Bypass**: Understand the VEH logic and ensure the exception chain behaves identically to non-debugged execution.

---

## 3. ADVANCED MULTI-LAYER TECHNIQUES

### 3.1 Self-Debugging (fork + ptrace)

The process forks a child that attaches to the parent via ptrace. If an external debugger is already attached, the child's ptrace fails.

```c
pid_t child = fork();
if (child == 0) {
    if (ptrace(PTRACE_ATTACH, getppid(), 0, 0) == -1)
        kill(getppid(), SIGKILL);
    else
        ptrace(PTRACE_DETACH, getppid(), 0, 0);
    _exit(0);
}
wait(NULL);
```

**Bypass**: Patch the `fork()` return or kill/detach the watchdog child.

### 3.2 Multi-Process Debugging Detection

Parent and child cooperatively check each other's debug state, creating a mutual-watch pattern.

**Bypass**: Attach to both processes (GDB `follow-fork-mode`, or two debugger instances).

### 3.3 Timing-Based with Multiple Checkpoints

Distributes timing checks across multiple functions, comparing cumulative drift. Single patches fail because the total still exceeds threshold.

**Bypass**: Frida `Interceptor.replace` all timing sources (`rdtsc`, `clock_gettime`, `QueryPerformanceCounter`) to return controlled values.

### 3.4 Nanomite / INT3 Patching

Original conditional jumps are replaced with `INT3` (0xCC). A parent debugger process handles each `INT3`, evaluates the condition, and sets the child's EIP accordingly.

**Bypass**: Reconstruct the original jump table by tracing all `INT3` handlers, then patch the binary.

---

## 4. COUNTERMEASURE TOOLS

| Tool | Platform | Capability |
|---|---|---|
| **ScyllaHide** | Windows (x64dbg/IDA/OllyDbg) | Auto-patches PEB, hooks NtQuery*, hides threads, fixes timing |
| **TitanHide** | Windows (kernel driver) | Kernel-level hiding for all user-mode checks |
| **Frida** | Cross-platform | Script-based hooking of any function, timing spoofing |
| **LD_PRELOAD shims** | Linux | Replace ptrace, getenv, fopen at load time |
| **GDB scripts** | Linux | `catch syscall`, conditional BP, register fixup |
| **Qiling** | Cross-platform | Full-system emulation, bypass all hardware checks |

---

## 5. SYSTEMATIC BYPASS METHODOLOGY

```
Step 1: Static analysis — identify anti-debug calls
  └─ Search for: ptrace, IsDebuggerPresent, NtQuery, rdtsc,
     GetTickCount, SIGTRAP, INT 2D, TLS directory entries

Step 2: Classify each check
  ├─ API-based → hook or patch the call
  ├─ Flag-based → patch PEB/proc fields
  ├─ Timing-based → spoof time source
  ├─ Exception-based → forward/handle exception correctly
  └─ Multi-process → handle both processes

Step 3: Apply bypass (order matters)
  1. Load ScyllaHide / set LD_PRELOAD (covers 80% of checks)
  2. Handle TLS callbacks (break before main)
  3. Patch remaining custom checks (Frida or binary patch)
  4. Verify: run with breakpoints, confirm no premature exit

Step 4: Validate bypass completeness
  └─ Set BP on ExitProcess/exit/_exit — if hit unexpectedly,
     a check was missed → trace back from exit call
```

---

## 6. DECISION TREE

```
Binary exits/crashes under debugger?
│
├─ Crashes immediately before main?
│  └─ TLS callback anti-debug
│     └─ Enable TLS callback breaking in debugger
│
├─ Crashes at startup?
│  ├─ Linux: check for ptrace(TRACEME)
│  │  └─ LD_PRELOAD hook or NOP patch
│  └─ Windows: check IsDebuggerPresent / PEB
│     └─ ScyllaHide or manual PEB patch
│
├─ Crashes after some execution?
│  ├─ Consistent crash point → API-based check
│  │  ├─ NtQueryInformationProcess → hook return values
│  │  ├─ /proc/self/status → filter TracerPid
│  │  └─ Hardware BP detection → hook GetThreadContext
│  │
│  ├─ Variable crash point → timing-based check
│  │  └─ Hook rdtsc / QueryPerformanceCounter
│  │
│  └─ Crash on breakpoint hit → exception-based check
│     ├─ INT 2D / INT 3 trick → handle in VEH
│     └─ SIGTRAP handler → GDB: handle SIGTRAP pass
│
├─ Debugger loses control silently?
│  └─ ThreadHideFromDebugger
│     └─ Hook NtSetInformationThread
│
├─ Child process detects and kills parent?
│  └─ Self-debugging (fork+ptrace)
│     └─ Patch fork() or handle both processes
│
└─ All basic bypasses applied but still detected?
   └─ Multi-layer / custom checks
      ├─ Use Frida for comprehensive API hooking
      ├─ Full emulation with Qiling
      └─ Trace all calls to exit/abort to find remaining checks
```

---

## 7. CTF & REAL-WORLD PATTERNS

### Common CTF Anti-Debug Patterns

| Pattern | Frequency | Quick Bypass |
|---|---|---|
| Single `ptrace(TRACEME)` | Very common | `LD_PRELOAD` one-liner |
| `IsDebuggerPresent` + `NtGlobalFlag` | Common | ScyllaHide |
| rdtsc timing in loop | Moderate | Patch comparison threshold |
| signal(SIGTRAP) + raise | Moderate | GDB signal forwarding |
| fork + ptrace watchdog | Rare but tricky | Kill child or patch fork |
| Nanomite INT3 replacement | Rare (advanced) | Reconstruct jump table |

### Real-World Protections

| Protector | Primary Anti-Debug | Recommended Tool |
|---|---|---|
| VMProtect | PEB + timing + driver-level | TitanHide + ScyllaHide |
| Themida | Multi-layer PEB + SEH + timing | ScyllaHide + manual patches |
| Enigma Protector | IsDebuggerPresent + CRC checks | x64dbg + ScyllaHide |
| UPX (custom) | Usually none (just packing) | Standard unpack |
| Custom (malware) | Varies widely | Frida + Qiling for analysis |

---

## 8. QUICK REFERENCE — BYPASS CHEAT SHEET

### Linux One-Liners

```bash
# LD_PRELOAD anti-ptrace
echo 'long ptrace(int r, ...) { return 0; }' > /tmp/ap.c
gcc -shared -o /tmp/ap.so /tmp/ap.c
LD_PRELOAD=/tmp/ap.so ./target

# GDB: catch and bypass ptrace
(gdb) catch syscall ptrace
(gdb) commands
> set $rax = 0
> continue
> end
```

### Frida Anti-Debug Bypass (Cross-Platform)

```javascript
// Hook IsDebuggerPresent (Windows)
Interceptor.replace(
  Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
  new NativeCallback(() => 0, 'int', [])
);

// Hook ptrace (Linux)
Interceptor.replace(
  Module.getExportByName(null, 'ptrace'),
  new NativeCallback(() => 0, 'long', ['int', 'int', 'pointer', 'pointer'])
);

// Timing spoof
Interceptor.attach(Module.getExportByName(null, 'clock_gettime'), {
  onLeave(retval) {
    // manipulate timespec to hide debugger delay
  }
});
```

### x64dbg ScyllaHide Quick Setup

1. Plugins → ScyllaHide → Options
2. Check: PEB BeingDebugged, NtGlobalFlag, HeapFlags
3. Check: NtQueryInformationProcess (all classes)
4. Check: NtSetInformationThread (HideFromDebugger)
5. Check: GetTickCount, QueryPerformanceCounter
6. Apply → restart debugging session


---
# Part 2: Anti-Debug Matrix


## 1. LINUX ANTI-DEBUG MATRIX

| # | Technique | Detection Method | Reliability | Bypass Method | Bypass Tool | False Positives |
|---|---|---|---|---|---|---|
| L1 | `ptrace(PTRACE_TRACEME)` | Self-attach; fails if already traced | High | `LD_PRELOAD` shim, NOP patch, GDB `catch syscall` | GDB, gcc | None — definitive |
| L2 | `/proc/self/status` TracerPid | Read TracerPid field; non-zero = traced | High | Hook `fopen`/`fread`, FUSE mount, patch string | Frida, LD_PRELOAD | Container environments may show artifacts |
| L3 | `/proc/self/maps` scanning | Search for debugger/instrumentation libraries | Medium | Filter maps output via hook, rename agent libs | Frida (rename gadget.so) | Security tools may trigger |
| L4 | `rdtsc` timing | Measure cycle count delta between two points | Medium | Fix registers at BP, hook timing source | GDB scripts, Frida | High CPU load can cause false positives |
| L5 | `clock_gettime` timing | Similar to rdtsc but via syscall | Medium | Hook `clock_gettime`, return controlled values | Frida, LD_PRELOAD | System load variation |
| L6 | `SIGTRAP` handler | Install handler, raise SIGTRAP; debugger swallows it | High | GDB: `handle SIGTRAP nostop pass` | GDB | None |
| L7 | `SIGSTOP`/`SIGCONT` self-send | Send SIGSTOP to self, measure if debugger intervenes | Low | Forward signals properly | GDB signal handling | Rare |
| L8 | Fork + ptrace watchdog | Child attaches to parent; fails if debugger present | High | Kill child, patch fork, dual-attach | GDB (follow-fork-mode) | None |
| L9 | `LD_PRELOAD` env check | `getenv("LD_PRELOAD")` | Low | Unset env var, hook `getenv` | Shell, Frida | Legitimate LD_PRELOAD usage |
| L10 | Parent PID check | `getppid()` — expect init/shell, not debugger | Low | Run from shell normally, hook `getppid` | Frida | Terminal multiplexers |
| L11 | `/proc/self/exe` readlink | Check if binary path matches expected | Low | Symlink or hook `readlink` | Shell | Custom install paths |
| L12 | Breakpoint scanning (0xCC) | Scan `.text` for `INT3` bytes | Medium | Use hardware breakpoints only | x86 HW BP (DR0-DR3) | Legitimate 0xCC in data |
| L13 | `prctl(PR_SET_DUMPABLE, 0)` | Prevent ptrace attach after start | Medium | Hook `prctl`, keep dumpable | LD_PRELOAD, Frida | None |
| L14 | `personality(ADDR_NO_RANDOMIZE)` | Detect if ASLR disabled (common debugger setting) | Low | Keep ASLR enabled while debugging | GDB (don't disable ASLR) | Manual ASLR disable |


## 2. WINDOWS ANTI-DEBUG MATRIX

| # | Technique | Detection Method | Reliability | Bypass Method | Bypass Tool | False Positives |
|---|---|---|---|---|---|---|
| W1 | `IsDebuggerPresent` | Reads `PEB.BeingDebugged` | High | Patch PEB byte, hook API | ScyllaHide, x64dbg | None |
| W2 | `CheckRemoteDebuggerPresent` | Calls `NtQueryInformationProcess(DebugPort)` | High | Hook underlying NtQIP | ScyllaHide | None |
| W3 | PEB.BeingDebugged | Direct PEB read (no API call) | High | Zero the byte at PEB+0x02 | ScyllaHide, manual patch | None |
| W4 | PEB.NtGlobalFlag (0x70) | Check for `FLG_HEAP_ENABLE_*` flags | High | Zero PEB+0xBC | ScyllaHide | None |
| W5 | Heap flags | `ProcessHeap.Flags` / `ForceFlags` | High | Patch heap header | ScyllaHide | None |
| W6 | `NtQueryInformationProcess` DebugPort | InfoClass 0x07 → non-zero if debugged | High | Hook NtQIP, return 0 | ScyllaHide, Frida | None |
| W7 | `NtQueryInformationProcess` DebugObjectHandle | InfoClass 0x1E → valid handle if debugged | High | Hook NtQIP, return error | ScyllaHide | None |
| W8 | `NtQueryInformationProcess` DebugFlags | InfoClass 0x1F → 0 if debugged (inverted!) | High | Hook NtQIP, return 1 | ScyllaHide | None |
| W9 | `OutputDebugString` timing | Measure time for ODS call (faster with debugger) | Medium | Hook ODS or fix timing | Frida | System load |
| W10 | INT 2D | Kernel debug interrupt; byte-skip behavior differs | High | Handle in VEH, NOP patch | ScyllaHide, manual | None |
| W11 | INT 3 (0xCC) | Breakpoint instruction behavior | Medium | Single-step past, VEH | Debugger built-in | None |
| W12 | UD2 (#UD exception) | Invalid opcode exception handling differs | Medium | Handle in VEH | Manual | None |
| W13 | TLS callbacks | Code runs before entry point | High | Break on TLS callback | x64dbg option, WinDbg | None |
| W14 | `NtSetInformationThread` HideFromDebugger | Thread becomes invisible to debugger | High | Hook NtSIT, NOP the call | ScyllaHide | None |
| W15 | DR register check | `GetThreadContext` reads DR0-DR3 | High | Hook GTC, zero DRx | ScyllaHide | None |
| W16 | `NtQuerySystemInformation` SystemKernelDebuggerInformation | Detects kernel debugger | High (kernel) | TitanHide (kernel driver) | TitanHide | None |
| W17 | VEH chain inspection | Walk VEH list for debugger-installed handlers | Low | Don't install VEH from debugger | Manual | Security software VEHs |
| W18 | `CloseHandle(invalid)` | With debugger: raises exception; without: returns error | Medium | Handle exception in VEH | ScyllaHide | None |
| W19 | `NtClose(invalid)` | Same as CloseHandle trick at NT level | Medium | Hook NtClose | ScyllaHide | None |
| W20 | SEH-based detection | Install SEH, trigger exception, check handler invocation | Medium | Ensure correct SEH dispatch | Debugger settings | None |
| W21 | `QueryPerformanceCounter` timing | Measure ticks between two points | Medium | Hook QPC, spoof delta | ScyllaHide, Frida | System load |
| W22 | `GetTickCount` / `GetTickCount64` timing | Millisecond-level timing check | Medium | Hook and spoof | ScyllaHide | System load |
| W23 | `RDTSC` instruction | Direct CPU timestamp counter | Medium | Patch comparison or hook via VEH on #UD | Frida (replace block) | CPU frequency changes |
| W24 | Parent process check | `NtQueryInformationProcess` → check parent is explorer.exe | Low | Spoof parent PID or hook | Frida | Non-standard launchers |
| W25 | Window class enumeration | `FindWindow("OLLYDBG")`, `FindWindow("x64dbg")` | Low | Rename debugger window class | Debugger plugin | None |
| W26 | Process enumeration | Enumerate processes for known debugger names | Low | Rename debugger executable | Shell | None |
| W27 | CRC / integrity check | Hash `.text` section, compare against stored value | Medium | Patch stored hash or hook CRC function | Manual, Frida | Legitimate code updates |
| W28 | `BlockInput(TRUE)` | Lock keyboard/mouse during sensitive operations | Low | Hook `BlockInput` | ScyllaHide | None |

---

## 3. TOOL COMPATIBILITY MATRIX

| Technique | GDB | x64dbg + ScyllaHide | WinDbg | IDA Remote | Frida | Qiling |
|---|---|---|---|---|---|---|
| ptrace self-attach | `catch syscall` | N/A | N/A | N/A | Hook | Emulate |
| /proc/self/status | Manual hook | N/A | N/A | N/A | Hook fopen | Emulate |
| PEB.BeingDebugged | N/A | Auto-patch | Manual | Plugin | Hook | Emulate |
| NtGlobalFlag | N/A | Auto-patch | Manual | Plugin | Hook | Emulate |
| NtQueryInformationProcess | N/A | Auto-hook | Manual | Plugin | Hook | Emulate |
| IsDebuggerPresent | N/A | Auto-hook | `eb kernel32!IsDebuggerPresent` | Plugin | Hook | Emulate |
| rdtsc timing | Register fixup | Spoof QPC | Manual | N/A | Replace block | Emulate |
| INT 2D / INT 3 | Handle signal | VEH/auto | Handle exception | N/A | Replace insn | Emulate |
| TLS callback | `starti` | Break on TLS | `sxe ld` | Break on entry | Early inject | Emulate |
| ThreadHideFromDebugger | N/A | Auto-NOP | Manual | Plugin | Hook NtSIT | Emulate |
| DR register check | N/A | Auto-zero DRx | Manual | N/A | Hook GTC | Emulate |
| fork+ptrace watchdog | follow-fork-mode | N/A | N/A | N/A | Hook fork | Emulate both |
| SIGTRAP handler | `handle pass` | N/A | N/A | N/A | Hook signal | Emulate |
| Breakpoint scan (0xCC) | Use HW BP | Use HW BP | Use HW BP | N/A | No BP needed | Emulate |

---

## 4. BYPASS PRIORITY CHECKLIST

Apply bypasses in this order for maximum coverage with minimum effort:

```
Phase 1 — Automated tools (covers ~80%)
├─ Windows: Load ScyllaHide with all options checked
├─ Linux: Set LD_PRELOAD with ptrace + timing shims
└─ Verify: program runs past initial checks

Phase 2 — TLS / early execution (covers +10%)
├─ Break on TLS callbacks or _init functions
└─ Patch any pre-main checks found

Phase 3 — Custom checks (covers +8%)
├─ Trace exit/abort calls → backtrack to find check
├─ Frida hook remaining detection functions
└─ Patch binary for persistent bypass

Phase 4 — Multi-process / kernel (covers +2%)
├─ Handle fork+ptrace with dual-process debugging
├─ TitanHide for kernel-level debugger detection
└─ Qiling full emulation for heavily protected targets
```

---

## 5. DETECTION RELIABILITY RATING GUIDE

| Rating | Meaning | Example |
|---|---|---|
| **High** | Definitive detection, no false positives | PEB.BeingDebugged, ptrace self-attach |
| **Medium** | Reliable but environment-sensitive | Timing checks (CPU load affects), breakpoint scanning |
| **Low** | Easily spoofed or many false positives | Process name enumeration, window class search, env var check |


---
# Part 3: Code Obfuscation & Deobfuscation


# SKILL: Code Obfuscation & Deobfuscation — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for identifying, classifying, and defeating code obfuscation in native binaries. Covers junk code, opaque predicates, SMC, control flow flattening, movfuscator, VM protectors (VMProtect/Themida/Code Virtualizer), string encryption, import hiding, and anti-disassembly tricks. Base models often conflate packing with obfuscation and miss the distinction between static and dynamic deobfuscation strategies.

## 0. RELATED ROUTING

- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) when the obfuscated binary also has anti-debug layers
- [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) when using angr/Z3 for automated deobfuscation
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) for deep VM protector bytecode analysis

### Quick identification picks

| Symptom in IDA/Ghidra | Likely Obfuscation | Start With |
|---|---|---|
| Flat CFG, single giant switch | Control flow flattening | Symbolic execution to recover CFG |
| Only `mov` instructions | movfuscator | demovfuscation / trace-based lifting |
| pushad/pushfd → VM entry | VM protector | Handler table extraction |
| XOR loop before code execution | SMC / string encryption | Dynamic analysis, breakpoint after decode |
| Impossible conditions (opaque predicates) | Junk code insertion | Pattern-based removal |
| All strings unreadable | String encryption | Hook decryption routine, or emulate |
| No imports in IAT | Import hiding | Trace GetProcAddress / hash resolution |


## 1. JUNK CODE & OPAQUE PREDICATES

### 1.1 Junk Code Insertion

Dead code that never affects program output, added to increase analysis time.

**Identification**:
- Instructions that write to registers/memory never read afterward
- Function calls whose return values are discarded and have no side effects
- Loops with invariant bounds that compute unused results

**Removal strategy**:
1. Compute def-use chains (IDA/Ghidra data flow analysis)
2. Mark instructions with no downstream use as dead
3. Verify removal doesn't change program behavior (trace comparison)

### 1.2 Opaque Predicates

Conditional branches where the condition is always true or always false, but this is non-obvious.

| Type | Example | Always Evaluates To |
|---|---|---|
| Arithmetic | `x² ≥ 0` | True |
| Number theory | `x*(x+1) % 2 == 0` | True (product of consecutive ints) |
| Pointer-based | `ptr == ptr` after aliasing | True |
| Hash-based | `CRC32(constant) == known_value` | True |

**Deobfuscation**:
- Abstract interpretation: prove the condition is constant
- Symbolic execution: Z3 proves `∀x: predicate(x) = True`
- Pattern matching: recognize known opaque predicate families
- Dynamic: trace and observe the branch is never taken / always taken

```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver()
s.add(x * (x + 1) % 2 != 0)
print(s.check())  # unsat → always true
```

---

## 2. SELF-MODIFYING CODE (SMC)

Runtime code patching: encrypted code is decrypted just before execution.

### 2.1 XOR Decryption Loop (Most Common)

```asm
lea esi, [encrypted_code]
mov ecx, code_length
mov al, xor_key
decrypt_loop:
    xor byte [esi], al
    inc esi
    loop decrypt_loop
    jmp encrypted_code  ; now decrypted
```

### 2.2 Analysis Strategy

```
1. Identify the decryption routine (look for XOR/ADD/SUB in loops writing to .text)
2. Set breakpoint AFTER the loop completes
3. At breakpoint: dump the decrypted memory region
4. Re-analyze the dumped code in IDA/Ghidra
5. For multi-layer: repeat for each decryption stage
```

### 2.3 Automated Unpacking via Emulation

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, binary_code)
mu.emu_start(decrypt_entry, decrypt_end)
decrypted = mu.mem_read(code_start, code_length)
```

---

## 3. CONTROL FLOW FLATTENING (CFF)

### 3.1 Structure

Original sequential blocks are transformed into a dispatcher loop:

```
Original:      A → B → C → D

Flattened:     ┌──────────────────┐
               │   dispatcher     │
               │   switch(state)  │◄─────┐
               ├──────────────────┤      │
               │ case 1: block A  │──────┤
               │ case 2: block B  │──────┤
               │ case 3: block C  │──────┤
               │ case 4: block D  │──────┘
               └──────────────────┘
```

Each block sets `state = next_state` before jumping back to the dispatcher.

### 3.2 Recovery Techniques

| Technique | Tool | Effectiveness |
|---|---|---|
| Symbolic execution | angr, Triton, miasm | High — traces all state transitions |
| Trace-based recovery | Pin/DynamoRIO trace → reconstruct CFG | Medium — covers executed paths only |
| Pattern matching | Custom IDA/Ghidra script | Medium — works for known flatteners |
| D-810 (IDA plugin) | IDA Pro | High — specifically designed for CFF |

### 3.3 Symbolic Deflattening (angr approach)

```python
import angr, claripy

proj = angr.Project('./obfuscated')
cfg = proj.analyses.CFGFast()

# Find dispatcher block (highest in-degree basic block)
dispatcher = max(cfg.graph.nodes(), key=lambda n: cfg.graph.in_degree(n))

# For each case block, symbolically determine successor
for block in case_blocks:
    state = proj.factory.blank_state(addr=block.addr)
    # ... solve state variable to find real successor
```

---

## 4. MOVFUSCATOR

### 4.1 Concept

All computation reduced to `mov` instructions only (Turing-complete via memory-mapped computation tables). Created by Christopher Domas.

### 4.2 Identification

- Function contains only `mov` instructions (no add, sub, xor, jmp, call)
- Large lookup tables in data section
- Memory-mapped flag registers

### 4.3 Demovfuscation

| Approach | Description |
|---|---|
| demovfuscator (tool) | Static analysis, recovers original operations from mov patterns |
| Trace + taint analysis | Run with Pin/DynamoRIO, taint inputs, observe computation |
| Symbolic execution | Treat entire function as constraint system |

---

## 5. VM PROTECTION (VMProtect / Themida / Code Virtualizer)

### 5.1 VM Architecture

```
Protected code → bytecode compiler → custom bytecode
Runtime: VM entry (pushad/pushfd) → fetch → decode → execute → VM exit (popad/popfd)
```

### 5.2 VM Entry Point Identification

```asm
; Typical VMProtect entry
pushad                    ; save all registers
pushfd                    ; save flags
mov ebp, esp              ; VM stack frame
sub esp, VM_LOCALS_SIZE   ; allocate VM context
mov esi, bytecode_addr    ; bytecode instruction pointer
jmp vm_dispatcher         ; enter VM loop
```

### 5.3 Handler Table Extraction

```
1. Find dispatcher (large switch or indirect jump via table)
2. Each case/entry = one VM handler (implements one VM opcode)
3. Map handler addresses to operations by analyzing each handler:
   - Handler reads operand from bytecode stream (esi)
   - Performs operation on VM registers/stack
   - Advances bytecode pointer
   - Returns to dispatcher
```

### 5.4 Devirtualization Approaches

| Method | Description | Tool |
|---|---|---|
| Manual handler mapping | Reverse each handler, build ISA spec | IDA + scripting |
| Trace recording | Record all handler executions, reconstruct program | REVEN, Pin |
| Symbolic lifting | Symbolically execute handlers, lift to IR | Triton, miasm |
| Pattern matching | Match handler patterns to known VM families | Custom scripts |

### 5.5 VMProtect Specifics

- Uses opaque predicates in dispatcher
- Handler mutation: same opcode, different handler code per build
- Multiple VM layers (VM inside VM)
- Integrates anti-debug and integrity checks

---

## 6. STRING ENCRYPTION

### 6.1 Common Patterns

| Pattern | Example | Recovery |
|---|---|---|
| XOR loop | `for (i=0; i<len; i++) s[i] ^= key;` | Hook or emulate XOR function |
| Stack strings | `mov [esp+0], 'H'; mov [esp+1], 'e'; ...` | IDA FLIRT / Ghidra script to reassemble |
| RC4 encrypted | Encrypted blob + RC4 key in binary | Extract key, decrypt offline |
| AES encrypted | Encrypted blob + AES key derived at runtime | Hook after decryption |
| Custom encoding | Base64 + XOR + reverse | Trace the decode function, replicate |

### 6.2 Automated String Decryption

```python
# Ghidra script: find XOR decryption calls, emulate them
from ghidra.program.model.symbol import SourceType

decrypt_func = getFunction("decrypt_string")
refs = getReferencesTo(decrypt_func.getEntryPoint())

for ref in refs:
    call_addr = ref.getFromAddress()
    # extract arguments (encrypted buffer ptr, key, length)
    # emulate decryption, add comment with plaintext
```

---

## 7. IMPORT HIDING

### 7.1 GetProcAddress + Hash Lookup

```c
FARPROC resolve(DWORD hash) {
    // Walk PEB → LDR → InMemoryOrderModuleList
    // For each DLL, walk export table
    // Hash each export name, compare with target hash
    // Return matching function pointer
}
```

### 7.2 Recovery

1. Identify the hash algorithm (common: CRC32, djb2, ROR13+ADD)
2. Compute hashes for all known API names
3. Build hash → API name lookup table
4. Annotate resolved calls in IDA/Ghidra

### 7.3 Common Hash Algorithms

| Name | Algorithm | Used By |
|---|---|---|
| ROR13 | `hash = (hash >> 13 \| hash << 19) + char` | Metasploit shellcode |
| djb2 | `hash = hash * 33 + char` | Various malware |
| CRC32 | Standard CRC32 of function name | Sophisticated packers |
| FNV-1a | `hash = (hash ^ char) * 0x01000193` | Modern malware |

---

## 8. ANTI-DISASSEMBLY TRICKS

### 8.1 Techniques

| Trick | Mechanism | Fix |
|---|---|---|
| Overlapping instructions | `jmp $+2; db 0xE8` (fake call prefix) | Manual re-analysis from correct offset |
| Misaligned jumps | Jump into middle of multi-byte instruction | Force IDA to re-analyze at target |
| Conditional jump pair | `jz $+5; jnz $+3` (always jumps, confuses linear disasm) | Convert to unconditional jmp |
| Return address manipulation | `push addr; ret` instead of `jmp addr` | Recognize push+ret as jump |
| Exception-based flow | Trigger exception, real code in handler | Analyze exception handler chain |
| Call + add [esp] | `call $+5; add [esp], N; ret` (computed jump) | Calculate actual target |

### 8.2 IDA Fixes

```
Right-click → Undefine (U)
Right-click → Code (C) at correct offset
Edit → Patch → Assemble (for permanent fix)
```

---

## 9. DECISION TREE

```
Obfuscated binary — how to approach?
│
├─ Can you run it?
│  ├─ Yes → Dynamic analysis first
│  │  ├─ Set BP on interesting APIs (file, network, crypto)
│  │  ├─ Trace execution to understand real behavior
│  │  └─ Dump decrypted code/strings at runtime
│  │
│  └─ No (embedded/firmware/exotic arch) → Static only
│     └─ Identify obfuscation type from patterns below
│
├─ What does the code look like?
│  │
│  ├─ Giant flat switch/dispatcher loop?
│  │  ├─ State variable drives control flow → CFF
│  │  │  └─ Use D-810 or symbolic deflattening
│  │  └─ Bytecode fetch-decode-execute → VM protection
│  │     └─ Extract handlers, build disassembler
│  │
│  ├─ Only mov instructions?
│  │  └─ movfuscator → demovfuscator tool
│  │
│  ├─ XOR/ADD loop writing to .text section?
│  │  └─ SMC → breakpoint after decode, dump
│  │
│  ├─ Impossible conditions in branches?
│  │  └─ Opaque predicates → Z3 proving or pattern removal
│  │
│  ├─ Disassembly looks wrong / functions overlap?
│  │  └─ Anti-disassembly → manual re-analysis at correct offsets
│  │
│  ├─ No readable strings?
│  │  └─ String encryption → hook decrypt function or emulate
│  │
│  ├─ No imports in IAT?
│  │  └─ Import hiding → identify hash, build lookup table
│  │
│  └─ pushad/pushfd → complex code → popad/popfd?
│     └─ VM protector entry/exit → full VM analysis
│
└─ What tool to use?
   ├─ Known protector (VMProtect/Themida) → specific deprotection guide
   ├─ Custom obfuscation → combine: IDA scripting + Triton + manual
   ├─ CTF challenge → angr symbolic execution often fastest
   └─ Malware analysis → dynamic (debugger + API monitor) first
```

---

## 10. TOOLBOX

| Tool | Purpose | Best For |
|---|---|---|
| IDA Pro + Hex-Rays | Disassembly, decompilation, scripting | All-around analysis |
| Ghidra | Free alternative with scripting (Java/Python) | Budget-friendly RE |
| D-810 (IDA plugin) | Automated CFF deflattening | OLLVM-style obfuscation |
| miasm | IR-based analysis framework | Symbolic deobfuscation |
| Triton | Dynamic symbolic execution | Opaque predicate solving, CFF |
| REVEN | Full-system trace recording and replay | VM protector analysis |
| demovfuscator | movfuscator reversal | mov-only binaries |
| x64dbg + plugins | Dynamic analysis with scripting | Windows RE |
| Unicorn Engine | CPU emulation | SMC unpacking, shellcode |
| Capstone | Disassembly library | Custom tooling |
| IDA FLIRT | Function signature matching | Identify library code in stripped binaries |
| Binary Ninja | Alternative disassembler with MLIL/HLIL | Automated analysis |


---
# Part 4: Symbolic Execution Tools


# SKILL: Symbolic Execution Tools — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert symbolic execution techniques using angr, Z3, and Unicorn Engine. Covers CTF challenge automation, constraint solving patterns, function hooking, SimProcedure replacement, and emulation-based unpacking. Base models often produce broken angr scripts due to incorrect state initialization or missing hooks for libc functions.

## 0. RELATED ROUTING

- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) when anti-debug checks need to be symbolically bypassed
- [code-obfuscation-deobfuscation](../code-obfuscation-deobfuscation/SKILL.md) when using symbolic execution for deobfuscation
- [vm-and-bytecode-reverse](../vm-and-bytecode-reverse/SKILL.md) when applying angr to custom VM challenges

### Advanced Reference

Also load [ANGR_COOKBOOK.md](./ANGR_COOKBOOK.md) when you need:
- 15+ ready-to-use angr script patterns for common CTF challenges
- Hook templates for scanf, printf, malloc, strcmp
- Symbolic file input, stdin, argv patterns
- Optimization tricks for path explosion management

### When to use which tool

| Scenario | Best Tool | Why |
|---|---|---|
| Pure math / equation system | Z3 | Direct constraint solving, no binary needed |
| Binary with control flow | angr | Explores paths, manages constraints automatically |
| Emulate specific code region | Unicorn | Fast, no symbolic overhead, good for unpacking |
| Complex binary + custom VM | angr + Unicorn (combo) | angr for control flow, Unicorn for VM handlers |
| Kernel / firmware code | Qiling | Full system emulation with OS awareness |


## 1. ANGR — CORE CONCEPTS

### 1.1 Pipeline

```
Project(binary)
  → Factory.entry_state() / blank_state(addr=)
    → SimulationManager(state)
      → explore(find=target, avoid=bad)
        → found[0].solver.eval(symbolic_var)
```

### 1.2 Essential Setup

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

# Entry state: start from program entry point
state = proj.factory.entry_state()

# Blank state: start from arbitrary address
state = proj.factory.blank_state(addr=0x401000)

# Full init state: with command-line args
state = proj.factory.full_init_state(args=['./challenge', arg1_sym])

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    found = simgr.found[0]
    solution = found.solver.eval(symbolic_input, cast_to=bytes)
    print(f"Solution: {solution}")
```

### 1.3 Symbolic Variables (claripy)

```python
# Bitvector (fixed-size integer)
sym_input = claripy.BVS("input", 64)        # 64-bit symbolic
sym_byte = claripy.BVS("byte", 8)           # 8-bit symbolic
sym_buf = claripy.BVS("buffer", 8 * 32)     # 32-byte buffer

# Concrete bitvector
concrete = claripy.BVV(0x41, 8)             # concrete value 0x41

# Constraints
state.solver.add(sym_input > 0)
state.solver.add(sym_input < 100)
state.solver.add(sym_byte >= 0x20)           # printable ASCII
state.solver.add(sym_byte <= 0x7e)

# Evaluate
value = state.solver.eval(sym_input)
all_values = state.solver.eval_upto(sym_input, 10)  # up to 10 solutions
```

### 1.4 Symbolic stdin

```python
flag_len = 32
sym_stdin = claripy.BVS("stdin", 8 * flag_len)

state = proj.factory.entry_state(stdin=sym_stdin)

# Constrain to printable ASCII
for i in range(flag_len):
    byte = sym_stdin.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)
```

### 1.5 Hooking Functions

```python
# Hook by address (skip N bytes of original code)
@proj.hook(0x401100, length=5)
def skip_check(state):
    state.regs.eax = 1  # force success

# SimProcedure: replace library function
class MyStrcmp(angr.SimProcedure):
    def run(self, s1, s2):
        return claripy.If(
            self.state.memory.load(s1, 32) == self.state.memory.load(s2, 32),
            claripy.BVV(0, 32),
            claripy.BVV(1, 32)
        )

proj.hook_symbol('strcmp', MyStrcmp())

# Hook common problematic functions
proj.hook_symbol('printf', angr.SIM_PROCEDURES['libc']['printf']())
proj.hook_symbol('scanf', angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())
```

### 1.6 Memory Operations

```python
# Read memory (symbolic-aware)
data = state.memory.load(addr, size)          # returns BV
data_concrete = state.solver.eval(data, cast_to=bytes)

# Write memory
state.memory.store(addr, claripy.BVV(0x41, 8))
state.memory.store(addr, sym_buf)

# Read/write registers
rax = state.regs.rax
state.regs.rdi = claripy.BVV(0x1000, 64)
```

---

## 2. Z3 CONSTRAINT SOLVING

### 2.1 Core API

```python
from z3 import *

# Sorts
x = BitVec('x', 32)    # 32-bit bitvector
y = Int('y')             # arbitrary precision integer
b = Bool('b')            # boolean

# Solver
s = Solver()
s.add(x + y == 42)
s.add(x > 0)
s.add(y > 0)

if s.check() == sat:
    m = s.model()
    print(f"x = {m[x]}, y = {m[y]}")
```

### 2.2 Common CTF Patterns

```python
# Serial key validation: each char satisfies constraints
key = [BitVec(f'k{i}', 8) for i in range(16)]
s = Solver()
for k in key:
    s.add(k >= 0x30, k <= 0x7a)  # alphanumeric-ish

# XOR key recovery
plaintext = b"known_plaintext"
ciphertext = b"\x12\x34..."
key_byte = BitVec('key', 8)
s = Solver()
for p, c in zip(plaintext, ciphertext):
    s.add(p ^ key_byte == c)

# System of linear equations (modular)
a, b, c = BitVecs('a b c', 32)
s = Solver()
s.add(3*a + 5*b + 7*c == 0x12345678)
s.add(2*a + 4*b + 6*c == 0xDEADBEEF)
s.add(a ^ b ^ c == 0xCAFEBABE)
```

### 2.3 Optimization

```python
from z3 import Optimize

opt = Optimize()
x = BitVec('x', 32)
opt.add(x > 0)
opt.add(x < 1000)
opt.minimize(x)  # find smallest satisfying value
opt.check()
print(opt.model())
```

---

## 3. UNICORN ENGINE — CODE EMULATION

### 3.1 Basic Setup

```python
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

mu = Uc(UC_ARCH_X86, UC_MODE_64)

CODE_ADDR = 0x400000
STACK_ADDR = 0x7fff0000
STACK_SIZE = 0x10000

mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(CODE_ADDR, code_bytes)
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x1000)
mu.reg_write(UC_X86_REG_RBP, STACK_ADDR + STACK_SIZE - 0x1000)

mu.emu_start(CODE_ADDR, CODE_ADDR + len(code_bytes))

result = mu.reg_read(UC_X86_REG_RAX)
```

### 3.2 Hooking Memory & Instructions

```python
# Hook memory access
def hook_mem(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f"Write {value:#x} to {address:#x}")
    elif access == UC_MEM_READ:
        print(f"Read from {address:#x}")

mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

# Hook specific instruction (for tracing)
def hook_code(uc, address, size, user_data):
    code = uc.mem_read(address, size)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in md.disasm(bytes(code), address):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

### 3.3 Use Cases

| Use Case | Approach |
|---|---|
| Unpack shellcode | Map shellcode, emulate, dump decoded payload |
| Decrypt strings | Emulate decryption function with controlled inputs |
| Brute-force short keys | Loop emulation with different key inputs |
| Analyze obfuscated function | Emulate function, observe register/memory state |
| Firmware code emulation | Map firmware memory layout, emulate routines |

---

## 4. ANGR EXPLORATION STRATEGIES

### 4.1 find/avoid

```python
simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),   # stdout contains "Correct"
    avoid=lambda s: b"Wrong" in s.posix.dumps(1)      # avoid "Wrong" output
)
```

### 4.2 Managing Path Explosion

| Strategy | Implementation |
|---|---|
| Constrain input space | Add constraints (printable, length limits) |
| Avoid dead-end paths | Use `avoid=` for known failure addresses |
| Hook complex functions | Replace with simplified SimProcedure |
| Limit loop iterations | `state.options.add(angr.options.LAZY_SOLVES)` |
| Use veritesting | `simgr.explore(..., technique=angr.exploration_techniques.Veritesting())` |
| DFS instead of BFS | `simgr.use_technique(angr.exploration_techniques.DFS())` |
| Timeout per path | `simgr.explore(..., num_find=1)` + timeout wrapper |

### 4.3 Concrete + Symbolic Hybrid

```python
state = proj.factory.entry_state(
    add_options={angr.options.UNICORN}  # use Unicorn for concrete regions
)
```

This dramatically speeds up execution: concrete code runs natively via Unicorn, switching to symbolic only when symbolic variables are involved.

---

## 5. PRACTICAL WORKFLOW

### 5.1 CTF Binary Solving Workflow

```
1. Static analysis: identify input method, success/fail conditions
   └─ Find "Correct" / "Wrong" strings → get their xref addresses

2. Choose tool:
   ├─ Pure math (no binary needed) → Z3
   ├─ Small binary, clear success/fail → angr explore
   └─ Specific function to emulate → Unicorn

3. Set up symbolic input:
   ├─ stdin → claripy.BVS + entry_state(stdin=)
   ├─ argv → full_init_state(args=[...])
   ├─ file input → SimFile
   └─ specific memory → state.memory.store(addr, sym)

4. Hook problematic functions:
   ├─ printf/puts → SimProcedure or no-op
   ├─ scanf → custom handler
   ├─ time/random → return concrete value
   └─ anti-debug → skip entirely

5. Explore and extract:
   └─ simgr.explore(find=, avoid=) → solver.eval()
```

---

## 6. DECISION TREE

```
Need to solve a reversing challenge?
│
├─ Is the challenge pure math / equations?
│  └─ Yes → Z3
│     ├─ Linear equations → BitVec + Solver
│     ├─ Modular arithmetic → BitVec (natural mod 2^n)
│     ├─ Boolean logic → Bool + Solver
│     └─ Optimization → Optimize + minimize/maximize
│
├─ Is it a compiled binary with clear success/fail?
│  └─ Yes → angr
│     ├─ Input via stdin → symbolic stdin
│     ├─ Input via argv → full_init_state with symbolic args
│     ├─ Input via file → SimFile
│     ├─ Path explosion → add constraints, avoid paths, hook loops
│     └─ Complex library calls → hook with SimProcedure
│
├─ Need to emulate a specific function/region?
│  └─ Yes → Unicorn Engine
│     ├─ Decryption routine → map code + data, emulate, read result
│     ├─ Shellcode analysis → map shellcode, hook syscalls
│     └─ Key schedule → emulate with different inputs
│
├─ Need to analyze firmware / exotic arch?
│  └─ Yes → Qiling (full system emulation with OS support)
│
├─ Binary has VM protection?
│  └─ angr for handler analysis + Z3 for bytecode constraints
│
└─ None of the above working?
   ├─ Combine: Unicorn for concrete regions + Z3 for constraints
   ├─ Manual reverse engineering with debugger
   └─ Side-channel approach (timing, power analysis for hardware)
```

---

## 7. COMMON PITFALLS & FIXES

| Problem | Cause | Fix |
|---|---|---|
| angr hangs forever | Path explosion in loops | Add `avoid=` for loop-back edges, or hook the loop |
| Z3 returns `unknown` | Non-linear constraints too complex | Simplify, split into sub-problems, use `set_param("timeout", 5000)` |
| Unicorn crashes on syscall | Syscall not handled | Hook syscall interrupt, handle or skip |
| angr wrong result | Incorrect state initialization | Verify initial memory layout matches actual binary |
| Symbolic memory too large | Unbounded symbolic reads | Concretize array indices where possible |
| SimProcedure wrong types | Argument type mismatch | Check calling convention (cdecl vs fastcall) |
| angr can't load binary | Missing libraries | Use `auto_load_libs=False` + hook needed symbols |

---

## 8. TOOL VERSIONS & INSTALLATION

```bash
# angr (Python 3.8+)
pip install angr

# Z3
pip install z3-solver

# Unicorn Engine
pip install unicorn

# Capstone (disassembly, pairs with Unicorn)
pip install capstone

# Keystone (assembly)
pip install keystone-engine
```


---
# Part 5: angr Cookbook


## Recipe 1: Basic find/avoid by Address

**Scenario**: Binary prints "Correct" at 0x401234, "Wrong" at 0x401300. Input via stdin.

```python
import angr

proj = angr.Project('./challenge', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].posix.dumps(0))  # fd 0 = stdin
```


## Recipe 2: Find by stdout Content

**Scenario**: Success/failure messages not at fixed addresses (PIE binary or indirect calls).

```python
import angr

proj = angr.Project('./challenge', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

simgr.explore(
    find=lambda s: b"Correct" in s.posix.dumps(1),
    avoid=lambda s: b"Wrong" in s.posix.dumps(1)
)

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

---

## Recipe 3: Symbolic stdin with Printable Constraint

**Scenario**: Flag is 32 printable characters read via scanf/fgets.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

FLAG_LEN = 32
flag = claripy.BVS("flag", 8 * FLAG_LEN)

state = proj.factory.entry_state(stdin=flag)

for i in range(FLAG_LEN):
    byte = flag.get_byte(i)
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    solution = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print(f"Flag: {solution}")
```

---

## Recipe 4: Symbolic argv

**Scenario**: Binary takes flag as command-line argument `./challenge FLAG`.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

flag = claripy.BVS("flag", 8 * 32)
state = proj.factory.full_init_state(
    args=['./challenge', flag],
    add_options=angr.options.unicorn
)

for i in range(32):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20, b <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Recipe 5: Symbolic File Input

**Scenario**: Binary reads flag from a file.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

flag = claripy.BVS("flag", 8 * 64)
sim_file = angr.SimFile("flag.txt", content=flag)

state = proj.factory.entry_state(fs={'/tmp/flag.txt': sim_file})

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Recipe 6: Hook scanf

**Scenario**: Custom scanf that angr's default SimProcedure handles incorrectly.

```python
import angr
import claripy

class MyScanf(angr.SimProcedure):
    def run(self, fmt, ptr):
        buf = claripy.BVS("scanf_input", 8 * 32)
        self.state.memory.store(ptr, buf)
        self.state.globals['scanf_buf'] = buf
        return 1

proj = angr.Project('./challenge', auto_load_libs=False)
proj.hook_symbol('__isoc99_scanf', MyScanf())

state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    found = simgr.found[0]
    buf = found.globals['scanf_buf']
    print(found.solver.eval(buf, cast_to=bytes))
```

---

## Recipe 7: Hook strcmp to Leak Expected Value

**Scenario**: Binary compares input against computed value. Hook strcmp to extract the expected string.

```python
import angr
import claripy

class LeakStrcmp(angr.SimProcedure):
    def run(self, s1, s2):
        # Read both strings up to null
        str1 = self.state.memory.load(s1, 64)
        str2 = self.state.memory.load(s2, 64)
        self.state.globals['cmp_s1'] = s1
        self.state.globals['cmp_s2'] = s2
        return claripy.If(str1 == str2, claripy.BVV(0, 32), claripy.BVV(1, 32))

proj = angr.Project('./challenge', auto_load_libs=False)
proj.hook_symbol('strcmp', LeakStrcmp())

state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234)

if simgr.found:
    found = simgr.found[0]
    s2_addr = found.solver.eval(found.globals['cmp_s2'])
    expected = found.memory.load(s2_addr, 32)
    print(found.solver.eval(expected, cast_to=bytes))
```

---

## Recipe 8: Start from Specific Function (skip initialization)

**Scenario**: Large binary, but the check function is known. Skip everything before it.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

CHECK_FUNC = 0x401500
BUF_ADDR = 0x600000

flag = claripy.BVS("flag", 8 * 32)

state = proj.factory.blank_state(addr=CHECK_FUNC)
state.memory.store(BUF_ADDR, flag)
state.regs.rdi = BUF_ADDR  # first arg = buffer pointer (System V ABI)
state.regs.rsi = 32         # second arg = length

state.stack_push(0xDEADBEEF)  # fake return address

simgr = proj.factory.simulation_manager(state)
simgr.explore(
    find=lambda s: b"OK" in s.posix.dumps(1),
    avoid=lambda s: b"FAIL" in s.posix.dumps(1)
)

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Recipe 9: Veritesting (Merge Paths at Branches)

**Scenario**: Path explosion due to many conditional branches (e.g., per-character check).

```python
import angr

proj = angr.Project('./challenge', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

simgr.use_technique(angr.exploration_techniques.Veritesting())
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

---

## Recipe 10: Unicorn Concrete Execution Speedup

**Scenario**: Most code is concrete (no symbolic data), only small portion needs symbolic reasoning.

```python
import angr

proj = angr.Project('./challenge', auto_load_libs=False)
state = proj.factory.entry_state(
    add_options=angr.options.unicorn  # enable Unicorn backend
)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

---

## Recipe 11: Multi-Stage Binary (Sequential Checks)

**Scenario**: Binary has multiple stages, each validating part of the flag.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

stages = [
    {"find": 0x401100, "avoid": [0x401150]},
    {"find": 0x401200, "avoid": [0x401250]},
    {"find": 0x401300, "avoid": [0x401350]},
]

flag = claripy.BVS("flag", 8 * 48)
state = proj.factory.entry_state(stdin=flag)

for i, stage in enumerate(stages):
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=stage["find"], avoid=stage["avoid"])
    if simgr.found:
        state = simgr.found[0]
        partial = state.solver.eval(flag, cast_to=bytes)
        print(f"Stage {i+1}: {partial}")
    else:
        print(f"Stage {i+1} failed")
        break
```

---

## Recipe 12: Constrain Flag Format (CTF{...})

**Scenario**: Flag format is known: `flag{...}` with alphanumeric content.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

FLAG_LEN = 40
flag = claripy.BVS("flag", 8 * FLAG_LEN)
state = proj.factory.entry_state(stdin=flag)

prefix = b"flag{"
for i, c in enumerate(prefix):
    state.solver.add(flag.get_byte(i) == c)
state.solver.add(flag.get_byte(FLAG_LEN - 1) == ord('}'))

for i in range(len(prefix), FLAG_LEN - 1):
    b = flag.get_byte(i)
    state.solver.add(
        claripy.Or(
            claripy.And(b >= ord('0'), b <= ord('9')),
            claripy.And(b >= ord('a'), b <= ord('z')),
            claripy.And(b >= ord('A'), b <= ord('Z')),
            b == ord('_'), b == ord('-')
        )
    )

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300])

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Recipe 13: Replace rand() with Concrete Value

**Scenario**: Binary uses `rand()` making execution non-deterministic.

```python
import angr

class ConcreteRand(angr.SimProcedure):
    def run(self):
        return 42  # deterministic

proj = angr.Project('./challenge', auto_load_libs=False)
proj.hook_symbol('rand', ConcreteRand())
proj.hook_symbol('srand', angr.SIM_PROCEDURES['libc']['srand']())

state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234)

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

---

## Recipe 14: Timeout + DFS for Deep Binaries

**Scenario**: Binary has deep execution path, BFS runs out of memory.

```python
import angr
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("angr timed out")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(300)  # 5-minute timeout

proj = angr.Project('./challenge', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

simgr.use_technique(angr.exploration_techniques.DFS())

try:
    simgr.explore(find=0x401234, avoid=[0x401300])
    if simgr.found:
        print(simgr.found[0].posix.dumps(0))
except TimeoutError:
    print("Timed out — try narrowing search space")
```

---

## Recipe 15: Symbolic Memory at Global Buffer

**Scenario**: Input is read into a global buffer at a known address, but through a complex path.

```python
import angr
import claripy

proj = angr.Project('./challenge', auto_load_libs=False)

GLOBAL_BUF = 0x604080
CHECK_START = 0x401200
FLAG_LEN = 24

flag = claripy.BVS("flag", 8 * FLAG_LEN)
state = proj.factory.blank_state(addr=CHECK_START)
state.memory.store(GLOBAL_BUF, flag)

for i in range(FLAG_LEN):
    b = flag.get_byte(i)
    state.solver.add(b >= 0x20, b <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401300, avoid=[0x401400])

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Adaptation Checklist

When adapting any recipe to your specific challenge:

1. **Update addresses**: `find=`, `avoid=`, function addresses, buffer addresses
2. **Match input method**: stdin, argv, file, or memory — use the right recipe
3. **Set correct flag length**: Too short = can't find solution; too long = slow
4. **Add format constraints**: Known prefix, charset, null terminator
5. **Hook problematic functions**: Any function causing path explosion or crashes
6. **Choose exploration technique**: BFS (default) for short paths, DFS for deep, Veritesting for branchy
7. **Enable Unicorn**: `add_options=angr.options.unicorn` for speed on mostly-concrete paths
8. **Check architecture**: Ensure `auto_load_libs=False` doesn't break needed functionality


---
# Part 6: VM & Bytecode Reverse


# SKILL: VM & Bytecode Reverse Engineering — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert techniques for reversing custom virtual machines and bytecode interpreters. Covers dispatcher identification, opcode mapping, custom ISA reconstruction, disassembler/decompiler writing, maze challenges, and real-world VM protector analysis. Base models often fail to recognize the fetch-decode-execute pattern or attempt to analyze VM bytecode as native code.

## 0. RELATED ROUTING

- [code-obfuscation-deobfuscation](../code-obfuscation-deobfuscation/SKILL.md) when the VM is a commercial protector (VMProtect/Themida)
- [symbolic-execution-tools](../symbolic-execution-tools/SKILL.md) when using angr to solve VM-based challenges
- [anti-debugging-techniques](../anti-debugging-techniques/SKILL.md) when the VM includes anti-debug checks

### Quick identification

| Binary Pattern | Likely VM Type | Start With |
|---|---|---|
| `while(1) { switch(bytecode[pc]) }` | Switch-based dispatcher | Map each case to an operation |
| Indirect jump via table `jmp [table + opcode*8]` | Table-based dispatcher | Dump jump table, analyze handlers |
| Nested if-else chain on byte value | If-chain dispatcher | Same as switch, just different syntax |
| Stack push/pop dominant operations | Stack-based VM | Identify push, pop, arithmetic ops |
| `reg[X] = ...` array operations | Register-based VM | Map register indices to operations |
| 2D grid + direction input | Maze challenge | Extract grid, apply BFS/DFS |


## 1. CUSTOM VM IDENTIFICATION

### 1.1 Structural Indicators

```
VM Architecture Components:
┌─────────────────────────────────┐
│  Bytecode Program (data section)│
├─────────────────────────────────┤
│  Program Counter (pc/ip)        │
│  Register File / Stack          │
│  Memory / Data Area             │
├─────────────────────────────────┤
│  Dispatcher Loop                │
│  ├─ Fetch: opcode = code[pc]    │
│  ├─ Decode: lookup handler      │
│  └─ Execute: run handler        │
└─────────────────────────────────┘
```

### 1.2 IDA/Ghidra Signatures

**Switch dispatcher** (most common in CTF):
```c
while (running) {
    unsigned char op = bytecode[pc++];
    switch (op) {
        case 0x00: /* nop */       break;
        case 0x01: /* push imm */  stack[sp++] = bytecode[pc++]; break;
        case 0x02: /* add */       stack[sp-2] += stack[sp-1]; sp--; break;
        // ...
        case 0xFF: /* halt */      running = 0; break;
    }
}
```

**Table dispatcher** (more optimized):
```c
typedef void (*handler_t)(vm_ctx_t*);
handler_t handlers[256] = { handle_nop, handle_push, handle_add, ... };

while (running) {
    handlers[bytecode[pc++]](&ctx);
}
```

---

## 2. ANALYSIS METHODOLOGY

### Step 1: Find the Dispatcher

Look for:
- Large switch statement (many cases) in a loop
- Array of function pointers indexed by a byte from a data buffer
- Single function with high cyclomatic complexity
- Cross-references to a data buffer read byte-by-byte

### Step 2: Map Opcodes to Operations

For each case/handler, determine:

| Property | How to Identify |
|---|---|
| Opcode value | Case number or table index |
| Operation type | Register/stack modifications |
| Operand count | How many bytes consumed after opcode |
| Operand type | Immediate value, register index, or memory address |
| Side effects | Output, memory write, flag modification |

### Step 3: Extract Bytecode Program

```python
# Typical extraction from binary
import struct

with open('challenge', 'rb') as f:
    f.seek(bytecode_offset)
    bytecode = f.read(bytecode_length)

# Or from IDA:
# bytecode = idc.get_bytes(bytecode_addr, bytecode_len)
```

### Step 4: Write Custom Disassembler

```python
OPCODES = {
    0x00: ("nop",  0),    # (mnemonic, operand_bytes)
    0x01: ("push", 1),    # push immediate byte
    0x02: ("pop",  0),
    0x03: ("add",  0),
    0x04: ("sub",  0),
    0x05: ("xor",  0),
    0x06: ("cmp",  0),
    0x07: ("jmp",  2),    # jump to 16-bit address
    0x08: ("je",   2),
    0x09: ("jne",  2),
    0x0A: ("mov",  2),    # mov reg, imm
    0x0B: ("load", 1),    # load from memory[operand]
    0x0C: ("store",1),    # store to memory[operand]
    0x0D: ("print",0),
    0x0E: ("read", 0),    # read input
    0xFF: ("halt", 0),
}

def disassemble(bytecode):
    pc = 0
    while pc < len(bytecode):
        op = bytecode[pc]
        if op not in OPCODES:
            print(f"  {pc:04x}: UNKNOWN {op:#04x}")
            pc += 1
            continue

        mnemonic, operand_size = OPCODES[op]
        operands = bytecode[pc+1:pc+1+operand_size]
        operand_str = ' '.join(f'{b:#04x}' for b in operands)
        print(f"  {pc:04x}: {mnemonic:8s} {operand_str}")
        pc += 1 + operand_size

disassemble(bytecode)
```

### Step 5: Analyze Disassembled Program

With the custom disassembly, apply standard reverse engineering:
- Identify input reading (read opcode)
- Trace data flow from input to comparison
- Determine success/failure conditions
- Extract the check logic (often XOR/ADD transformations of input compared against constants)

---

## 3. COMMON VM PATTERNS IN CTF

### 3.1 Stack-Based VM

Operations work on a stack (like JVM or Python bytecode).

| Opcode | Operation | Stack Effect |
|---|---|---|
| PUSH imm | Push immediate value | [...] → [..., imm] |
| POP | Discard top | [..., a] → [...] |
| ADD | Add top two | [..., a, b] → [..., a+b] |
| SUB | Subtract | [..., a, b] → [..., a-b] |
| MUL | Multiply | [..., a, b] → [..., a*b] |
| XOR | Bitwise XOR | [..., a, b] → [..., a^b] |
| CMP | Compare | [..., a, b] → [..., (a==b)] |
| JMP addr | Unconditional jump | no change |
| JZ addr | Jump if top is zero | [..., a] → [...] |
| PRINT | Output top as char | [..., a] → [...] |
| READ | Read char to stack | [...] → [..., input] |
| HALT | Stop execution | - |

### 3.2 Register-Based VM

Operations use register indices (like x86, ARM).

| Opcode | Format | Operation |
|---|---|---|
| MOV r, imm | `0x01 RR II II` | reg[R] = imm16 |
| MOV r1, r2 | `0x02 R1 R2` | reg[R1] = reg[R2] |
| ADD r1, r2 | `0x03 R1 R2` | reg[R1] += reg[R2] |
| SUB r1, r2 | `0x04 R1 R2` | reg[R1] -= reg[R2] |
| XOR r1, r2 | `0x05 R1 R2` | reg[R1] ^= reg[R2] |
| CMP r1, r2 | `0x06 R1 R2` | flags = compare(r1, r2) |
| JMP addr | `0x07 AA AA` | pc = addr |
| JE addr | `0x08 AA AA` | if equal: pc = addr |
| LOAD r, [addr] | `0x09 RR AA` | reg[R] = mem[addr] |
| STORE [addr], r | `0x0A AA RR` | mem[addr] = reg[R] |
| SYSCALL | `0x0B` | I/O operation based on reg[0] |
| HALT | `0xFF` | stop |

### 3.3 Brainfuck-like / Esoteric VMs

| BF Command | VM Equivalent | Description |
|---|---|---|
| `>` | INC ptr | Move data pointer right |
| `<` | DEC ptr | Move data pointer left |
| `+` | INC [ptr] | Increment byte at pointer |
| `-` | DEC [ptr] | Decrement byte at pointer |
| `.` | OUTPUT [ptr] | Output byte at pointer |
| `,` | INPUT [ptr] | Input byte to pointer |
| `[` | JZ forward | Jump past `]` if byte is zero |
| `]` | JNZ back | Jump back to `[` if byte is nonzero |

---

## 4. MAZE CHALLENGES

### 4.1 Identification

- Binary reads directional input (WASD, arrow keys, UDLR)
- 2D array in data section (walls, paths, start, end)
- Position tracking with x,y coordinates
- Win condition at specific coordinates

### 4.2 Map Extraction

```python
# Extract maze grid from binary data section
MAZE_ADDR = 0x601060
WIDTH = 20
HEIGHT = 15

# From binary dump:
maze = []
for row in range(HEIGHT):
    line = ""
    for col in range(WIDTH):
        cell = bytecode[MAZE_ADDR + row * WIDTH + col - base_addr]
        if cell == 0: line += "."    # path
        elif cell == 1: line += "#"  # wall
        elif cell == 2: line += "S"  # start
        elif cell == 3: line += "E"  # end
        else: line += "?"
    maze.append(line)
    print(line)
```

### 4.3 Automated Solving

```python
from collections import deque

def solve_maze(maze, start, end):
    """BFS solver returns direction string."""
    rows, cols = len(maze), len(maze[0])
    directions = {'U': (-1, 0), 'D': (1, 0), 'L': (0, -1), 'R': (0, 1)}
    queue = deque([(start, "")])
    visited = {start}

    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == end:
            return path

        for name, (dr, dc) in directions.items():
            nr, nc = r + dr, c + dc
            if (0 <= nr < rows and 0 <= nc < cols and
                maze[nr][nc] != '#' and (nr, nc) not in visited):
                visited.add((nr, nc))
                queue.append(((nr, nc), path + name))

    return None

# Find start and end positions
for r, row in enumerate(maze):
    for c, cell in enumerate(row):
        if cell == 'S': start = (r, c)
        if cell == 'E': end = (r, c)

solution = solve_maze(maze, start, end)
print(f"Path: {solution}")
```

### 4.4 Direction Encoding

Different challenges encode directions differently:

| Encoding | Up | Down | Left | Right |
|---|---|---|---|---|
| WASD | W | S | A | D |
| UDLR | U | D | L | R |
| Arrow keys | ↑ (0x48) | ↓ (0x50) | ← (0x4B) | → (0x4D) |
| Numbers | 1 | 2 | 3 | 4 |
| Hex opcodes | 0x01 | 0x02 | 0x03 | 0x04 |

---

## 5. REAL-WORLD VM PROTECTORS

### 5.1 VMProtect Analysis Approach

```
1. Find VM entry: search for pushad/pushfd sequence
2. Identify VM context structure (registers, flags, bytecode pointer)
3. Locate handler table (often obfuscated with opaque predicates)
4. For each handler:
   a. Remove junk code / opaque predicates
   b. Identify the core operation
   c. Document handler semantics
5. Trace bytecode execution (instruction-level trace)
6. Reconstruct original code from trace
```

### 5.2 Tigress Obfuscator

Academic VM obfuscator with configurable protection layers.

| Feature | Approach |
|---|---|
| Single-dispatch VM | Standard handler extraction |
| Split handlers | Handlers spread across multiple functions |
| Nested VMs | Outer VM handler invokes inner VM |
| Encrypted bytecode | Dynamic decryption before each fetch |
| Polymorphic handlers | Different code for same operation on each build |

### 5.3 Common VM Protector Patterns

| Protector | Dispatcher Style | Difficulty |
|---|---|---|
| VMProtect | Table + opaque predicates | High |
| Themida (Code Virtualizer) | CISC-like, large handler set | High |
| Tigress | Configurable, academic | Medium-High |
| Custom CTF VM | Simple switch | Low-Medium |
| Movfuscator | All-mov computation | Medium |

---

## 6. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| IDA Pro | Identify dispatcher, reverse handlers | F5 decompile, xref analysis |
| Ghidra | Free alternative with Sleigh processor modules | Write custom processor for VM ISA |
| angr | Symbolic execution through VM | Treat entire VM as constraint system |
| Pin / DynamoRIO | Dynamic instrumentation for tracing | Record opcode handler execution sequence |
| REVEN | Full-system trace recording | Replay and analyze VM execution |
| Unicorn | Emulate VM execution | Fast handler emulation |
| Miasm | IR-based analysis | Lift VM handlers to IR for analysis |
| Custom Python | Write disassembler/decompiler | Per-challenge custom tooling |

### Ghidra Sleigh Processor Module

For recurring VM architectures, write a Sleigh processor specification:

```
define space ram      type=ram_space      size=2  default;
define space register type=register_space  size=1;

define register offset=0 size=1 [ R0 R1 R2 R3 FLAGS PC SP ];

define token opcode(8)
    op = (0,7)
;

:NOP    is op=0x00 { }
:PUSH   imm is op=0x01; imm { SP = SP - 1; *[ram]:1 SP = imm; }
:POP    is op=0x02 { SP = SP + 1; }
:ADD    is op=0x03 { local a = *[ram]:1 (SP+1); *[ram]:1 (SP+1) = a + *[ram]:1 SP; SP = SP + 1; }
```

---

## 7. DECISION TREE

```
Binary contains custom bytecode interpreter?
│
├─ Can you identify the dispatcher?
│  ├─ Yes (switch/table/if-chain)
│  │  ├─ Few opcodes (< 20) → Simple CTF VM
│  │  │  ├─ Stack-based → map push/pop/arithmetic ops
│  │  │  ├─ Register-based → map mov/add/cmp ops
│  │  │  └─ Write disassembler → analyze program → solve
│  │  │
│  │  └─ Many opcodes (50+) → Commercial protector
│  │     ├─ Known protector → use specific deprotection tools
│  │     └─ Custom → trace execution, pattern-match handlers
│  │
│  └─ No clear dispatcher
│     ├─ All-mov instructions → movfuscator
│     ├─ Encrypted bytecode → find decryption, dump after decode
│     └─ Split/distributed handlers → trace execution to find them
│
├─ Is it a maze challenge?
│  ├─ Extract grid from data section
│  ├─ Identify direction encoding
│  ├─ BFS/DFS to find shortest path
│  └─ Convert path to expected input format
│
├─ Is there input validation in VM?
│  ├─ Small input space → brute-force via Unicorn emulation
│  ├─ Known format → constrained angr solve
│  └─ Complex check → write disassembler, analyze check logic
│
└─ Multiple VM layers (VM in VM)?
   ├─ Analyze outer VM first
   ├─ Extract inner bytecode
   ├─ Repeat analysis for inner VM
   └─ Consider: symbolic execution may handle nested VMs directly
```

---

## 8. CTF SOLVING WORKFLOW

```
1. Run the binary — understand I/O behavior
   └─ What input does it expect? What output on success/failure?

2. Open in IDA/Ghidra — find the main loop
   └─ Look for while/for loop with switch or indirect jump

3. Identify VM components:
   ├─ Bytecode location (where is the program data?)
   ├─ PC/IP variable (how is current position tracked?)
   ├─ Registers/stack (where is VM state stored?)
   └─ I/O handlers (which opcodes read input / write output?)

4. Map all opcodes (create the ISA specification)
   └─ For each case/handler: opcode number, operation, operands

5. Write disassembler in Python
   └─ Output readable assembly for the bytecode

6. Analyze the disassembled program:
   ├─ Find input reading
   ├─ Trace transformations applied to input
   ├─ Find comparison against expected values
   └─ Reverse the transformation to find valid input

7. Solve:
   ├─ If simple transforms (XOR, ADD) → reverse manually
   ├─ If complex → feed to Z3 as constraints
   └─ If maze → extract grid, run pathfinding
```
