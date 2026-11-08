---
name: forensics-all
description: >-
  Digital forensics complete playbook. Covers memory forensics (Volatility 2/3 with DKOM/injection/rootkit detection), steganography (PNG CRC/LSB/spectrograms/zero-width Unicode/polyglots), and traffic analysis (Wireshark filters/TLS decryption/DNS tunneling/USB HID/PCAP repair). Load for CTF forensics challenges or incident response analysis.
---

<!-- src: hacker/.claude/skills/forensics-all/SKILL.md -->

# Digital Forensics — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Memory Forensics (Volatility) |
| 2 | Volatility Cheatsheet |
| 3 | Steganography Techniques |
| 4 | Stego Tools Guide |
| 5 | Traffic Analysis & PCAP |

---
# Part 1: Memory Forensics


# SKILL: Memory Forensics — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert memory forensics techniques using Volatility 2 and 3. Covers memory acquisition, OS identification, process analysis (hidden process detection), network connections, DLL/module analysis, code injection detection (malfind), credential extraction, file carving, registry analysis, and timeline generation. Base models miss the Vol2/Vol3 command differences, malware indicator patterns, and Linux-specific memory analysis.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [traffic-analysis-pcap](../traffic-analysis-pcap/SKILL.md) for correlating network artifacts with memory findings
- [steganography-techniques](../steganography-techniques/SKILL.md) if hidden data suspected in extracted files
- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) for understanding post-exploitation artifacts in memory

### Quick Reference

Also load [VOLATILITY_CHEATSHEET.md](./VOLATILITY_CHEATSHEET.md) when you need:
- Vol2 vs Vol3 command comparison table
- Common plugin sequences for specific investigation types


## 1. MEMORY ACQUISITION

### Linux

```bash
# LiME (Linux Memory Extractor) — kernel module
insmod lime.ko "path=/tmp/mem.lime format=lime"

# /proc/kcore (if available)
dd if=/proc/kcore of=/tmp/mem.raw bs=1M

# AVML (Microsoft's open-source)
./avml /tmp/mem.lime
```

### Windows

```bash
# WinPmem
winpmem_mini_x64.exe memdump.raw

# FTK Imager (GUI) — capture memory to file

# DumpIt (single-click memory dump)
DumpIt.exe

# Comae (MagnetRAM)
MagnetRAMCapture.exe /output memdump.raw
```

### Virtual Machines

```bash
# VMware: .vmem file in VM directory (suspend VM first)
# VirtualBox: VBoxManage debugvm "VM_NAME" dumpvmcore --filename mem.raw
# KVM/QEMU: virsh dump DOMAIN memdump --memory-only
# Hyper-V: checkpoint VM → inspect .bin files
```

---

## 2. VOLATILITY 2 vs 3

| Concept | Volatility 2 | Volatility 3 |
|---|---|---|
| Profile system | `--profile=Win10x64_19041` | Auto-detected (symbol tables) |
| Image info | `imageinfo` | `windows.info` / `linux.info` |
| Process list | `pslist` | `windows.pslist` |
| Network | `netscan` / `connections` | `windows.netscan` / `windows.netstat` |
| DLLs | `dlllist` | `windows.dlllist` |
| Injection | `malfind` | `windows.malfind` |
| Hashes | `hashdump` | `windows.hashdump` |
| Files | `filescan` | `windows.filescan` |
| Registry | `hivelist` / `printkey` | `windows.registry.hivelist` / `windows.registry.printkey` |
| Install | `pip2 install volatility` | `pip3 install volatility3` |

---

## 3. ANALYSIS METHODOLOGY

### Step 1: Identify OS

```bash
# Vol2
vol.py -f mem.raw imageinfo
vol.py -f mem.raw kdbgscan

# Vol3
vol -f mem.raw windows.info
vol -f mem.raw banners.Banners
```

### Step 2: Process Listing — Hidden Process Detection

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE pslist       # EPROCESS linked list
vol.py -f mem.raw --profile=PROFILE psscan       # pool tag scan (finds unlinked)
vol.py -f mem.raw --profile=PROFILE pstree       # parent-child hierarchy

# Vol3
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan
vol -f mem.raw windows.pstree
```

**Red flags**: Process in `psscan` but not `pslist` = DKOM (Direct Kernel Object Manipulation) hiding.

### Step 3: Network Connections

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE netscan      # TCP/UDP endpoints
vol.py -f mem.raw --profile=PROFILE connections   # XP/2003 only
vol.py -f mem.raw --profile=PROFILE connscan      # closed connections

# Vol3
vol -f mem.raw windows.netscan
vol -f mem.raw windows.netstat
```

### Step 4: DLL / Module Analysis

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE dlllist -p PID
vol.py -f mem.raw --profile=PROFILE ldrmodules -p PID   # find unlinked DLLs

# Vol3
vol -f mem.raw windows.dlllist --pid PID
```

**Red flags**: DLL in `dlllist` but `False` in all three `ldrmodules` columns = reflective DLL injection.

### Step 5: Code Injection Detection (Malfind)

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE malfind -p PID
vol.py -f mem.raw --profile=PROFILE malfind -D /tmp/dump/   # dump injected sections

# Vol3
vol -f mem.raw windows.malfind --pid PID
```

**What malfind detects**: Memory regions with `PAGE_EXECUTE_READWRITE` that don't map to a file on disk — classic shellcode/injection indicator.

### Step 6: Credential Extraction

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE hashdump      # SAM hashes
vol.py -f mem.raw --profile=PROFILE lsadump       # LSA secrets
vol.py -f mem.raw --profile=PROFILE cachedump     # domain cached creds
vol.py -f mem.raw --profile=PROFILE mimikatz      # (plugin) plaintext creds

# Vol3
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.cachedump
```

### Step 7: File Extraction

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE filescan | grep -i "password\|secret\|flag"
vol.py -f mem.raw --profile=PROFILE dumpfiles -Q OFFSET -D /tmp/dump/

# Vol3
vol -f mem.raw windows.filescan
vol -f mem.raw windows.dumpfiles --virtaddr OFFSET
```

### Step 8: Registry Analysis

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE hivelist
vol.py -f mem.raw --profile=PROFILE printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
vol.py -f mem.raw --profile=PROFILE userassist    # program execution evidence

# Vol3
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Step 9: Command History

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE cmdscan       # cmd.exe history
vol.py -f mem.raw --profile=PROFILE consoles       # full console output

# Vol3
vol -f mem.raw windows.cmdline
```

### Step 10: Timeline Generation

```bash
# Vol2
vol.py -f mem.raw --profile=PROFILE timeliner --output=body --output-file=timeline.body
mactime -b timeline.body -d > timeline.csv

# Vol3
vol -f mem.raw timeliner.Timeliner
```

---

## 4. LINUX MEMORY ANALYSIS

```bash
# Vol2 (requires Linux profile)
vol.py -f mem.lime --profile=LinuxProfile linux_pslist
vol.py -f mem.lime --profile=LinuxProfile linux_pstree
vol.py -f mem.lime --profile=LinuxProfile linux_netstat
vol.py -f mem.lime --profile=LinuxProfile linux_bash        # bash history
vol.py -f mem.lime --profile=LinuxProfile linux_enumerate_files
vol.py -f mem.lime --profile=LinuxProfile linux_proc_maps -p PID
vol.py -f mem.lime --profile=LinuxProfile linux_malfind

# Vol3
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash
vol -f mem.lime linux.check_afinfo     # rootkit detection
vol -f mem.lime linux.check_syscall    # syscall hooking
vol -f mem.lime linux.tty_check        # TTY hooking
```

### Building Linux Profiles (Vol2)

```bash
cd volatility/tools/linux
make
# Creates module.dwarf + System.map → zip as profile
zip LinuxProfile.zip module.dwarf /boot/System.map-$(uname -r)
# Place in volatility/plugins/overlays/linux/
```

---

## 5. MALWARE INDICATORS IN MEMORY

| Indicator | Detection Method | What It Means |
|---|---|---|
| Process in psscan but not pslist | Compare pslist vs psscan | DKOM — process hiding |
| Unexpected parent-child | pstree analysis | e.g., svchost spawned by cmd.exe |
| MZ header in non-image memory | malfind | Reflective DLL / PE injection |
| RWX memory without backing file | malfind | Shellcode injection |
| DLL unlinked from all PEB lists | ldrmodules (all False) | Stealth DLL loading |
| svchost.exe not child of services.exe | pstree | Fake svchost (malware) |
| Unusual network connections | netscan + PID correlation | C2 communication |
| Hooking in SSDT/IDT | ssdt / idt plugins | Rootkit |
| Modified kernel objects | linux_check_syscall | Linux rootkit |

### Normal Parent-Child Relationships (Windows)

```
System (4)
└── smss.exe
    └── csrss.exe
    └── wininit.exe
        └── services.exe
            └── svchost.exe (multiple)
            └── spoolsv.exe
        └── lsass.exe
    └── winlogon.exe
        └── explorer.exe
            └── user applications
```

---

## 6. DECISION TREE

```
Memory dump acquired — need to analyze
│
├── What OS?
│   ├── Windows → vol imageinfo / windows.info (§3 Step 1)
│   └── Linux → build profile or use Vol3 auto-detect (§4)
│
├── Malware investigation?
│   ├── Check processes: pslist vs psscan (hidden?) (§3 Step 2)
│   ├── Check parent-child: pstree (suspicious spawning?) (§5)
│   ├── Check injections: malfind (RWX memory?) (§3 Step 5)
│   ├── Check DLLs: ldrmodules (unlinked?) (§3 Step 4)
│   ├── Check network: netscan (C2 connections?) (§3 Step 3)
│   └── Extract suspicious files: dumpfiles (§3 Step 7)
│
├── Credential recovery?
│   ├── SAM hashes → hashdump (§3 Step 6)
│   ├── LSA secrets → lsadump (§3 Step 6)
│   ├── Cached domain creds → cachedump (§3 Step 6)
│   └── Plaintext passwords → mimikatz plugin (§3 Step 6)
│
├── Incident timeline?
│   ├── timeliner for comprehensive timeline (§3 Step 10)
│   ├── cmdscan / consoles for command history (§3 Step 9)
│   ├── userassist for program execution (§3 Step 8)
│   └── Cross-reference with PCAP timeline (→ traffic-analysis-pcap)
│
├── CTF / flag hunting?
│   ├── filescan + grep for flag patterns (§3 Step 7)
│   ├── cmdscan for typed flags/passwords (§3 Step 9)
│   ├── Clipboard: clipboard plugin
│   ├── Screenshots: screenshot plugin
│   └── Environment vars: envars plugin
│
└── Linux-specific?
    ├── linux_bash for shell history (§4)
    ├── linux_check_syscall for rootkit (§4)
    └── linux_netstat for connections (§4)
```


---
# Part 2: Volatility Cheatsheet


# VOLATILITY CHEATSHEET — Vol2 / Vol3 Command Reference

> Supplementary reference for [memory-forensics-volatility](./SKILL.md). Quick-access command tables.


## 1. COMMAND COMPARISON TABLE

### System Information

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| OS identification | `imageinfo` | `windows.info` |
| Kernel debug scan | `kdbgscan` | (auto) |
| OS banners | `imageinfo` | `banners.Banners` |

### Process Analysis

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| Process list (linked) | `pslist` | `windows.pslist` |
| Process list (scan) | `psscan` | `windows.psscan` |
| Process tree | `pstree` | `windows.pstree` |
| Process command line | `cmdline` | `windows.cmdline` |
| Process environment | `envars` | `windows.envars` |
| Process handles | `handles` | `windows.handles` |
| Process privileges | `privs` | `windows.privileges` |
| Process SIDs | `getsids` | `windows.getsids` |

### Memory / DLL

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| Loaded DLLs | `dlllist` | `windows.dlllist` |
| Unlinked DLL detection | `ldrmodules` | `windows.ldrmodules` |
| Code injection | `malfind` | `windows.malfind` |
| VAD tree | `vadinfo` | `windows.vadinfo` |
| Dump process memory | `memdump -p PID` | `windows.memmap --dump --pid PID` |
| Dump DLLs | `dlldump -p PID` | `windows.dlllist --pid PID --dump` |

### Network

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| All connections (Vista+) | `netscan` | `windows.netscan` |
| Active connections (XP) | `connections` | N/A |
| Listening sockets (XP) | `sockets` | N/A |
| Connection scan (XP) | `connscan` | N/A |
| Net stats | N/A | `windows.netstat` |

### Credentials

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| SAM hashes | `hashdump` | `windows.hashdump` |
| LSA secrets | `lsadump` | `windows.lsadump` |
| Cached creds | `cachedump` | `windows.cachedump` |
| Mimikatz | `mimikatz` (plugin) | N/A (use hashdump/lsadump) |

### File System

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| File scan | `filescan` | `windows.filescan` |
| File dump | `dumpfiles -Q OFFSET` | `windows.dumpfiles --virtaddr ADDR` |
| MFT analysis | `mftparser` | `windows.mftscan` |

### Registry

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| List hives | `hivelist` | `windows.registry.hivelist` |
| Print key | `printkey -K "path"` | `windows.registry.printkey --key "path"` |
| User assist | `userassist` | `windows.registry.userassist` |
| Shimcache | `shimcache` | N/A (third-party) |

### History / User Activity

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| CMD history | `cmdscan` | `windows.cmdline` |
| Console output | `consoles` | `windows.consoles` |
| Clipboard | `clipboard` | `windows.clipboard` |
| Screenshots | `screenshot` | N/A |
| IE history | `iehistory` | N/A |

### Rootkit / Hooking

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| SSDT hooks | `ssdt` | `windows.ssdt` |
| IDT hooks | `idt` | N/A |
| Driver scan | `driverscan` | `windows.driverscan` |
| Kernel modules | `modules` | `windows.modules` |
| Moddump | `modscan` | `windows.modscan` |
| Callbacks | `callbacks` | `windows.callbacks` |

### Timeline

| Purpose | Volatility 2 | Volatility 3 |
|---|---|---|
| Generate timeline | `timeliner` | `timeliner.Timeliner` |

---

## 2. COMMON INVESTIGATION SEQUENCES

### Malware Triage (Quick)

```bash
# Vol3
vol -f mem.raw windows.info
vol -f mem.raw windows.pstree
vol -f mem.raw windows.malfind
vol -f mem.raw windows.netscan
```

### Full Malware Investigation

```bash
# Vol3
vol -f mem.raw windows.info
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan         # compare with pslist
vol -f mem.raw windows.pstree         # check parent-child
vol -f mem.raw windows.cmdline        # command lines
vol -f mem.raw windows.netscan        # C2 connections
vol -f mem.raw windows.malfind        # code injection
vol -f mem.raw windows.dlllist --pid SUSPICIOUS_PID
vol -f mem.raw windows.handles --pid SUSPICIOUS_PID
vol -f mem.raw windows.filescan | grep -i "suspicious_name"
vol -f mem.raw windows.dumpfiles --virtaddr OFFSET
```

### Credential Extraction

```bash
# Vol3
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.cachedump
```

### Incident Response Timeline

```bash
# Vol3
vol -f mem.raw windows.info
vol -f mem.raw timeliner.Timeliner
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.registry.userassist
vol -f mem.raw windows.netscan
vol -f mem.raw windows.filescan
```

### CTF Challenge

```bash
# Vol3
vol -f mem.raw windows.info           # or banners.Banners
vol -f mem.raw windows.filescan | grep -iE "flag|secret|password|key"
vol -f mem.raw windows.cmdline        # look for typed commands
vol -f mem.raw windows.pslist         # find interesting processes
vol -f mem.raw windows.netscan        # find interesting connections
vol -f mem.raw windows.dumpfiles --virtaddr OFFSET  # extract files
vol -f mem.raw windows.hashdump       # extract hashes
```

### Linux Rootkit Detection

```bash
# Vol3
vol -f mem.lime linux.pslist
vol -f mem.lime linux.check_syscall
vol -f mem.lime linux.check_afinfo
vol -f mem.lime linux.tty_check
vol -f mem.lime linux.bash
vol -f mem.lime linux.elfs            # find injected ELFs
```

---

## 3. PROFILE MANAGEMENT (Vol2)

```bash
# List available profiles
vol.py --info | grep -i "Profile"

# Common Windows profiles
Win7SP1x64, Win10x64_19041, Win10x64_17763, WinXPSP3x86, Win2016x64_14393

# Determine correct profile
vol.py -f mem.raw imageinfo
# Use "Suggested Profile(s)" from output

# Custom Linux profile
# On target system:
cd volatility/tools/linux && make
zip profile.zip module.dwarf /boot/System.map-$(uname -r)
cp profile.zip volatility/plugins/overlays/linux/
```

---

## 4. USEFUL GREP PATTERNS

```bash
# Find interesting files
vol -f mem.raw windows.filescan | grep -iE '\.(txt|doc|xls|pdf|kdbx|key|pem|conf|ini|bat|ps1)$'

# Find web-related files
vol -f mem.raw windows.filescan | grep -iE '\.(php|asp|jsp|html)$'

# Find executables in unusual locations
vol -f mem.raw windows.filescan | grep -iE '\\(temp|tmp|appdata|downloads)\\.*\.exe'

# Network connections to external IPs
vol -f mem.raw windows.netscan | grep -v "127.0.0.1\|0.0.0.0\|::1\|::"
```


---
# Part 3: Steganography Techniques


# SKILL: Steganography Techniques — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert steganography detection and extraction techniques. Covers image steganography (LSB, PNG chunk hiding, JPEG DCT, EXIF metadata, dimension tricks, palette manipulation), audio steganography (spectrogram, LSB, DTMF, morse), file steganography (polyglots, binwalk, NTFS ADS, steghide), and text steganography (whitespace, zero-width Unicode, homoglyphs). Base models miss the systematic file-type-based analysis approach and tool-specific extraction workflows.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [traffic-analysis-pcap](../traffic-analysis-pcap/SKILL.md) for extracting files from network captures before stego analysis
- [memory-forensics-volatility](../memory-forensics-volatility/SKILL.md) for extracting files from memory dumps
- [classical-cipher-analysis](../classical-cipher-analysis/SKILL.md) if extracted hidden data is further encrypted/encoded

### Tool Reference

Also load [STEGO_TOOLS_GUIDE.md](./STEGO_TOOLS_GUIDE.md) when you need:
- Tool installation instructions and dependencies
- Detailed command reference for each stego tool
- Workflow patterns for specific file types


## 1. IMAGE STEGANOGRAPHY

### LSB (Least Significant Bit)

LSB embeds data in the least significant bits of pixel color channels.

```bash
# zsteg — LSB analysis for PNG/BMP
zsteg image.png                       # auto-detect all LSB patterns
zsteg image.png -a                    # try all known methods
zsteg image.png -b 1                  # extract bit plane 1
zsteg image.png -E "b1,rgb,lsb,xy"   # specific extraction pattern

# StegSolve (Java GUI)
java -jar StegSolve.jar
# Navigate color planes: Red 0, Green 0, Blue 0 → look for hidden image/text
# Data Extractor: specify bit planes + byte order

# stegoveritas — comprehensive automated analysis
stegoveritas image.png
# Runs: exiftool, binwalk, zsteg, foremost, color plane extraction
```

### PNG Specific

```bash
# pngcheck — validate structure, find hidden chunks
pngcheck -v image.png

# Hidden chunks: tEXt, zTXt (compressed text), iTXt (international text)
# Custom/private chunks may contain hidden data

# CRC vs dimensions trick
# If CRC doesn't match declared dimensions → image was cropped
# Fix: brute-force correct width/height → reveals hidden rows/columns
python3 -c "
import struct, zlib
with open('image.png','rb') as f:
    data = f.read()
# Check IHDR CRC at offset 29
ihdr = data[12:29]
for h in range(1,2000):
    for w in range(1,2000):
        new_ihdr = struct.pack('>II',w,h) + ihdr[8:]
        if zlib.crc32(b'IHDR'+new_ihdr) & 0xffffffff == struct.unpack('>I',data[29:33])[0]:
            print(f'Width: {w}, Height: {h}')
"

# APNG (animated PNG) — hidden frames
# Use apngdis to extract all frames: apngdis image.png
```

### JPEG Specific

```bash
# steghide — embed/extract from JPEG (DCT coefficient modification)
steghide extract -sf image.jpg                 # extract (no passphrase)
steghide extract -sf image.jpg -p PASSWORD     # extract with passphrase
steghide info image.jpg                        # check if data is embedded

# stegcracker — brute force steghide passphrase
stegcracker image.jpg wordlist.txt

# jsteg — JPEG LSB steganography
jsteg reveal image.jpg output.txt

# JPEG structure analysis
exiftool -v3 image.jpg       # verbose metadata + structure
jpegdump image.jpg           # raw JPEG marker analysis
```

### EXIF Metadata

```bash
# exiftool — comprehensive metadata extraction
exiftool image.jpg
exiftool -b -ThumbnailImage image.jpg > thumb.jpg   # extract thumbnail
exiftool -all= image.jpg                             # strip all metadata

# Hidden data in EXIF fields (comment, artist, copyright, etc.)
exiftool -Comment image.jpg
exiftool -UserComment image.jpg
strings image.jpg | grep -i "flag\|key\|secret"
```

### Palette-Based (GIF)

```bash
# GIF color table manipulation — data in color palette order
gifsicle -I image.gif                    # info
gifsicle --color-info image.gif          # palette details
# Check for animation frames: convert -coalesce image.gif frame_%d.png
```

---

## 2. AUDIO STEGANOGRAPHY

### Spectrogram Analysis

```bash
# Sonic Visualiser — best for spectrogram viewing
# Layer → Add Spectrogram → look for visual patterns (text/images)

# Audacity
# Analyze → Plot Spectrum
# Select audio → change view to Spectrogram

# sox for command-line spectrogram generation
sox audio.wav -n spectrogram -o spectro.png
```

### Audio LSB

```bash
# DeepSound — hide/extract files in audio (Windows)
# GUI tool: open audio file → extract hidden files

# WavSteg — LSB in WAV files
python3 WavSteg.py -r -i audio.wav -o output.txt -n 1   # extract 1 LSB
python3 WavSteg.py -r -i audio.wav -o output.txt -n 2   # extract 2 LSBs
```

### DTMF / Morse Code

```bash
# DTMF decoder (phone tones)
multimon-ng -t wav -a DTMF audio.wav

# Morse code
# Audacity → visual inspection of on/off pattern
# Online decoder or manual: .- = A, -... = B, etc.

# SSTV (Slow-Scan Television) — image in audio
qsstv                    # GUI decoder
# Or: RX-SSTV (Windows)
```

### WAV Header Manipulation

```bash
# Check for data appended after WAV audio data
# WAV data chunk size vs actual file size
python3 -c "
import wave
w = wave.open('audio.wav','rb')
print(f'Frames: {w.getnframes()}, Channels: {w.getnchannels()}, Width: {w.getsampwidth()}')
expected = w.getnframes() * w.getnchannels() * w.getsampwidth() + 44  # 44 = WAV header
import os
actual = os.path.getsize('audio.wav')
if actual > expected:
    print(f'Extra data: {actual - expected} bytes appended')
"
```

---

## 3. FILE STEGANOGRAPHY

### Polyglot Files

A single file that is valid in two or more formats simultaneously.

```bash
# Detection: check file with multiple tools
file suspicious_file
xxd suspicious_file | head          # check magic bytes
binwalk suspicious_file             # find embedded files

# Common polyglots: PDF+ZIP, JPEG+ZIP, JPEG+RAR, PNG+ZIP
# Try unzip on image files:
unzip image.jpg -d extracted/
7z x image.jpg -oextracted/
```

### Appended / Embedded Data

```bash
# binwalk — scan for embedded files and data
binwalk image.png                   # scan
binwalk -e image.png                # extract embedded files
binwalk --dd='.*' image.png         # extract everything

# foremost — file carving
foremost -i suspicious_file -o output_dir/

# dd — manual extraction
# If binwalk shows embedded ZIP at offset 0x1234:
dd if=suspicious_file bs=1 skip=$((0x1234)) of=extracted.zip
```

### NTFS Alternate Data Streams (ADS)

```cmd
:: List ADS (Windows)
dir /r file.txt
Get-Item file.txt -Stream *

:: Read hidden stream
more < file.txt:hidden_stream
Get-Content file.txt -Stream hidden_stream

:: Create ADS (for testing)
echo "hidden data" > file.txt:secret
```

### Steghide Brute Force

```bash
# stegcracker — wordlist attack on steghide passphrase
stegcracker image.jpg /usr/share/wordlists/rockyou.txt

# stegseek — faster alternative
stegseek image.jpg /usr/share/wordlists/rockyou.txt
# stegseek is ~10000x faster than stegcracker
```

---

## 4. TEXT STEGANOGRAPHY

### Whitespace Encoding

```bash
# Tabs and spaces encode binary (tab=1, space=0 or vice versa)
# stegsnow — whitespace steganography
stegsnow -C message.txt                # extract hidden message
stegsnow -C -p PASSWORD message.txt    # extract with password

# Manual detection:
cat -A file.txt | head     # show tabs (^I) and line endings ($)
xxd file.txt | grep "09 20\|20 09"    # look for tab/space patterns
```

### Zero-Width Characters

```bash
# Unicode invisible characters used for encoding:
# U+200B (Zero-Width Space), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM)

# Detection:
python3 -c "
text = open('message.txt','r').read()
hidden = [c for c in text if ord(c) in [0x200b, 0x200c, 0x200d, 0xfeff]]
print(f'Found {len(hidden)} zero-width characters')
binary = ''.join('0' if ord(c)==0x200b else '1' for c in hidden)
# Convert binary to ASCII
"

# Online tools: holloway.nz/steg, Unicode Steganography decoders
```

### Homoglyph Substitution

```bash
# Visually identical characters from different Unicode blocks
# e.g., Latin 'a' (U+0061) vs Cyrillic 'а' (U+0430)

# Detection:
python3 -c "
text = open('message.txt','r').read()
for i, c in enumerate(text):
    if ord(c) > 127:
        print(f'Position {i}: char={c} ord={ord(c)} name={__import__(\"unicodedata\").name(c,\"?\")}')
"
```

---

## 5. DECISION TREE

```
Suspect hidden data — what file type?
│
├── Image (PNG/BMP)?
│   ├── Check metadata: exiftool (§1 EXIF)
│   ├── Check structure: pngcheck, binwalk (§1 PNG)
│   ├── LSB analysis: zsteg, StegSolve (§1 LSB)
│   ├── Check dimensions vs CRC: height/width brute force (§1 PNG)
│   ├── Check for appended data: binwalk -e (§3)
│   └── Try as polyglot: unzip/7z (§3)
│
├── Image (JPEG)?
│   ├── Check metadata: exiftool (§1 EXIF)
│   ├── Try steghide: steghide extract (§1 JPEG)
│   │   └── Password protected? → stegseek brute force (§3)
│   ├── Try jsteg: jsteg reveal (§1 JPEG)
│   ├── Check for appended data: binwalk -e (§3)
│   └── Check thumbnail: exiftool -b -ThumbnailImage (§1 EXIF)
│
├── Image (GIF)?
│   ├── Check frames: extract all animation frames (§1 Palette)
│   ├── Check palette: gifsicle --color-info (§1 Palette)
│   └── Check for appended data: binwalk -e (§3)
│
├── Audio (WAV/MP3/FLAC)?
│   ├── Spectrogram: Sonic Visualiser / Audacity (§2)
│   ├── LSB: WavSteg (§2)
│   ├── DTMF tones: multimon-ng (§2)
│   ├── Morse code: manual or decoder (§2)
│   ├── SSTV: qsstv (§2)
│   └── Check file size vs expected: header analysis (§2)
│
├── Text file?
│   ├── Check whitespace: cat -A, stegsnow (§4)
│   ├── Check zero-width chars: Unicode analysis (§4)
│   ├── Check homoglyphs: non-ASCII detection (§4)
│   └── Check encoding: multiple base decodings
│
├── Any file type?
│   ├── strings: strings -n 8 file | grep -i "flag\|key\|pass"
│   ├── binwalk: binwalk -e file (embedded files) (§3)
│   ├── file: file suspicious_file (true type)
│   ├── xxd: check magic bytes, compare headers
│   └── NTFS? → check ADS: dir /r (§3)
│
└── Password/passphrase needed?
    ├── steghide → stegseek / stegcracker (§3)
    ├── Check challenge description for hints
    └── Try common passwords: password, file name, challenge name
```


---
# Part 4: Stego Tools Guide


# STEGANOGRAPHY TOOLS GUIDE

> Supplementary reference for [steganography-techniques](./SKILL.md). Installation and detailed usage for each tool.


## 1. MULTI-PURPOSE TOOLS

### stegoveritas

Automated steganography analysis — runs multiple tools in one pass.

```bash
# Install
pip3 install stegoveritas
stegoveritas_install_deps

# Usage — full automated analysis
stegoveritas image.png
# Runs: exiftool, binwalk, zsteg, foremost, trailing data check
# Extracts: color planes, LSB data, embedded files
# Output: results/ directory with all findings

stegoveritas image.png -meta         # metadata only
stegoveritas image.png -imageTransform   # color plane extraction only
stegoveritas image.png -extractLSB   # LSB extraction only
```

### binwalk

Firmware/file analysis and extraction.

```bash
# Install
sudo apt install binwalk
# or: pip3 install binwalk

# Scan for embedded files
binwalk file.png

# Extract embedded files
binwalk -e file.png                  # extract known types
binwalk --dd='.*' file.png           # extract everything
binwalk -Me file.png                 # recursive extraction

# Entropy analysis (detect encrypted/compressed regions)
binwalk -E file.png
```

### foremost

File carving tool — recovers files from raw data.

```bash
# Install
sudo apt install foremost

# Carve files
foremost -i suspicious_file -o output_dir/
foremost -t all -i disk_image.raw -o carved/

# Specific file types
foremost -t pdf,jpg,zip -i data.bin -o output/
```

---

## 2. IMAGE TOOLS

### zsteg

PNG/BMP LSB steganography detector.

```bash
# Install
gem install zsteg

# Auto-detect all LSB patterns
zsteg image.png

# Verbose scan with all methods
zsteg image.png -a

# Specific extraction
zsteg image.png -b 1                        # bit plane 1
zsteg image.png -E "b1,rgb,lsb,xy"          # specific pattern
zsteg image.png -E "b1,r,lsb,xy"            # red channel only
zsteg image.png -E "b2,bgr,msb,yx"          # MSB, BGR order

# Extract to file
zsteg image.png -E "b1,rgb,lsb,xy" > extracted.bin
```

### StegSolve

Java GUI for visual bit plane analysis.

```bash
# Install
wget http://www.caesum.com/handbook/Stegsolve.jar

# Run
java -jar Stegsolve.jar

# Key features:
# Analyse → File Format: check headers and structure
# Analyse → Data Extract: specify bit planes to extract
# Arrow keys: cycle through color planes (R0-R7, G0-G7, B0-B7, Alpha)
# XOR/AND/OR with second image for comparison
```

### steghide

JPEG/WAV/BMP/AU steganography with encryption.

```bash
# Install
sudo apt install steghide

# Check if data is embedded
steghide info image.jpg

# Extract (no password)
steghide extract -sf image.jpg

# Extract with password
steghide extract -sf image.jpg -p "password"

# Embed data (for testing)
steghide embed -cf cover.jpg -ef secret.txt -p "password"
```

### stegseek

Fast steghide passphrase cracker (~10000x faster than stegcracker).

```bash
# Install
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_amd64.deb
sudo dpkg -i stegseek_amd64.deb

# Crack passphrase
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# Seed crack (try without wordlist)
stegseek --seed image.jpg
```

### jsteg

JPEG LSB steganography.

```bash
# Install
go install github.com/lukechampine/jsteg@latest

# Extract
jsteg reveal image.jpg

# Embed (for testing)
jsteg hide cover.jpg secret.txt output.jpg
```

### pngcheck

PNG structure validator.

```bash
# Install
sudo apt install pngcheck

# Validate and show chunk info
pngcheck -v image.png

# Show text chunks
pngcheck -t image.png

# Full verbose with data
pngcheck -vtp7f image.png
```

### exiftool

Metadata extraction and manipulation.

```bash
# Install
sudo apt install libimage-exiftool-perl

# All metadata
exiftool image.jpg

# Specific fields
exiftool -Comment image.jpg
exiftool -UserComment image.jpg
exiftool -GPSLatitude -GPSLongitude image.jpg

# Extract thumbnail
exiftool -b -ThumbnailImage image.jpg > thumbnail.jpg

# Verbose structure
exiftool -v3 image.jpg

# Strip all metadata
exiftool -all= image.jpg
```

---

## 3. AUDIO TOOLS

### Sonic Visualiser

Best spectrogram viewer for stego analysis.

```bash
# Install
sudo apt install sonic-visualiser

# Usage:
# 1. Open audio file
# 2. Layer → Add Spectrogram
# 3. Adjust: Window=4096, Overlap=87.5%, Scale=dBV
# 4. Look for patterns (text, QR codes, images in frequency domain)
```

### multimon-ng

Decoder for DTMF, POCSAG, and other digital modes.

```bash
# Install
sudo apt install multimon-ng

# DTMF decode
multimon-ng -t wav -a DTMF audio.wav

# Multiple decoders
multimon-ng -t wav -a DTMF -a MORSE_CW audio.wav

# From raw audio input
sox audio.wav -t raw -r 22050 -e signed -b 16 -c 1 - | multimon-ng -t raw -
```

### DeepSound

Audio steganography tool (Windows).

```bash
# GUI application — Windows only
# 1. Open carrier audio file
# 2. Click "Extract Secret Files"
# 3. Enter password if prompted

# Alternative for Linux: use WavSteg for WAV LSB analysis
```

---

## 4. TEXT TOOLS

### stegsnow

Whitespace steganography in text files.

```bash
# Install
sudo apt install stegsnow

# Extract hidden message
stegsnow -C message.txt

# Extract with password
stegsnow -C -p "password" message.txt

# Embed (for testing)
stegsnow -C -m "hidden message" -p "password" cover.txt stego.txt
```

---

## 5. RECOMMENDED ANALYSIS WORKFLOW

### Quick Triage (Any File)

```bash
file suspicious_file
exiftool suspicious_file
strings -n 8 suspicious_file | head -50
binwalk suspicious_file
xxd suspicious_file | head -20
```

### Image Deep Analysis

```bash
exiftool -v3 image.*
pngcheck -v image.png         # if PNG
steghide info image.jpg       # if JPEG
zsteg -a image.png            # if PNG/BMP
stegoveritas image.*          # comprehensive automated scan
binwalk -e image.*            # embedded file extraction
```

### Audio Deep Analysis

```bash
exiftool audio.*
file audio.*
sox audio.wav -n spectrogram -o spectro.png
multimon-ng -t wav -a DTMF audio.wav
# Open in Sonic Visualiser for spectrogram inspection
# Check file size vs expected duration
```

### Password Recovery for Steghide

```bash
# Fast: stegseek
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# Slow fallback: stegcracker
stegcracker image.jpg /usr/share/wordlists/rockyou.txt

# Manual: try common passwords
for p in password flag secret admin test ""; do
    steghide extract -sf image.jpg -p "$p" 2>/dev/null && echo "Password: '$p'" && break
done
```


---
# Part 5: Traffic Analysis & PCAP


# SKILL: Traffic Analysis & PCAP — Expert Analysis Playbook

> **AI LOAD INSTRUCTION**: Expert traffic analysis and PCAP forensics techniques. Covers PCAP repair, Wireshark essential filters, protocol-specific analysis (HTTP, HTTPS/TLS, DNS, FTP, SMTP, USB HID, WiFi, ICMP), data extraction (file carving, credential harvesting, covert channels), NetworkMiner, and tshark CLI analysis. Base models miss USB keyboard decode patterns, DNS tunneling detection heuristics, and TLS decryption workflows.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [memory-forensics-volatility](../memory-forensics-volatility/SKILL.md) for correlating memory artifacts with network traffic
- [steganography-techniques](../steganography-techniques/SKILL.md) for analyzing files extracted from traffic captures
- [network-protocol-attacks](../network-protocol-attacks/SKILL.md) for understanding attack patterns visible in captures
- [reverse-shell-techniques](../reverse-shell-techniques/SKILL.md) for identifying shell traffic in captures


## 1. PCAP REPAIR

```bash
pcapfix corrupted.pcap -o fixed.pcap           # repair corrupted PCAP
# Magic bytes: d4c3b2a1=pcap(LE), a1b2c3d4=pcap(BE), 0a0d0d0a=pcapng
editcap -F pcap capture.pcapng capture.pcap    # convert pcapng→pcap
mergecap -w merged.pcap file1.pcap file2.pcap  # merge captures
```

---

## 2. WIRESHARK ESSENTIAL FILTERS

### IP / Host Filters

```
ip.addr == 10.0.0.1                  # source or destination
ip.src == 10.0.0.1                   # source only
ip.dst == 10.0.0.1                   # destination only
ip.addr == 10.0.0.0/24              # subnet
!(ip.addr == 10.0.0.1)              # exclude host
```

### Protocol Filters

```
http                                  # all HTTP
dns                                   # all DNS
tcp                                   # all TCP
ftp                                   # all FTP
smtp                                  # all SMTP
tls                                   # all TLS/SSL
icmp                                  # all ICMP
arp                                   # all ARP
```

### TCP / Stream

```
tcp.stream eq 5                       # follow specific TCP stream
tcp.port == 80                        # traffic on port 80
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN packets (connection starts)
tcp.analysis.retransmission           # retransmitted packets
tcp.len > 0                           # packets with payload
```

### HTTP

```
http.request.method == "POST"         # POST requests
http.request.method == "GET"          # GET requests
http.response.code == 200             # successful responses
http.response.code >= 400             # error responses
http.request.uri contains "login"     # URI contains string
http.host contains "target.com"       # specific host
http.content_type contains "json"     # JSON responses
http.cookie contains "session"        # session cookies
http.request.full_uri                 # show full URIs (column)
```

### DNS

```
dns.qry.name contains "evil.com"     # specific domain queries
dns.qry.type == 1                    # A records
dns.qry.type == 28                   # AAAA records
dns.qry.type == 16                   # TXT records
dns.flags.response == 1              # DNS responses only
dns.resp.len > 100                   # large DNS responses
```

### TLS

```
tls.handshake.type == 1              # Client Hello
tls.handshake.type == 2              # Server Hello
tls.handshake.extensions.server_name  # SNI (hostname)
tls.handshake.type == 11             # Certificate
```

### Content Search

```
frame contains "password"             # search in raw bytes
frame contains "flag{"                # CTF flag pattern
tcp contains "admin"                  # search in TCP payload
```

---

## 3. PROTOCOL ANALYSIS

### HTTP — Follow Stream & Extract

```
Right-click packet → Follow → TCP Stream
# Shows full HTTP request/response conversation

# File extraction:
# File → Export Objects → HTTP → Save All

# Useful filters for credential hunting:
http.request.method == "POST" && frame contains "password"
http.request.method == "POST" && frame contains "login"
http.authbasic                        # Basic auth (base64 encoded)
```

### HTTPS / TLS Decryption

```bash
# Method 1: SSLKEYLOGFILE (pre-master secrets from browser)
# Set environment variable BEFORE opening browser:
export SSLKEYLOGFILE=/tmp/sslkeys.log
firefox https://target.com

# Wireshark: Edit → Preferences → Protocols → TLS
# → (Pre)-Master-Secret log filename: /tmp/sslkeys.log

# Method 2: Server private key (for RSA key exchange only)
# Wireshark: Edit → Preferences → Protocols → TLS → RSA keys list
# → Add: IP, Port, Protocol, Key file (.pem)
```

### DNS — Tunneling Detection

```bash
# Indicators of DNS tunneling:
# 1. Unusually long subdomain names (>30 chars)
# 2. High volume of TXT record queries/responses
# 3. Consistent query patterns to same domain
# 4. Base32/Base64-like subdomain strings
# 5. High query frequency from single host

# Wireshark filter for suspicious DNS:
dns.qry.name.len > 50                # long query names
dns.qry.type == 16                   # TXT records (common for tunneling)
dns.resp.len > 512                   # large DNS responses

# tshark extraction:
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name
```

### FTP — Credential & File Extraction

```bash
# FTP credentials (plaintext)
# Filter: ftp.request.command == "USER" || ftp.request.command == "PASS"

# FTP file transfer reconstruction:
# FTP uses separate data channel (usually port 20 or dynamic)
# Follow TCP stream of data connection to extract file

# tshark:
tshark -r capture.pcap -Y "ftp.request.command==USER || ftp.request.command==PASS" -T fields -e ftp.request.arg
```

### SMTP — Email Content Extraction

```bash
# Follow TCP stream → MAIL FROM/RCPT TO/DATA sections
# Attachments: base64 in MIME → decode Content-Transfer-Encoding blocks
# Filters:
smtp.req.command == "AUTH"            # authentication (often base64)
smtp contains "Content-Disposition: attachment"   # attachments
```

### USB — Keyboard HID Capture Decode

```bash
# USB HID keyboard traffic: interrupt transfers with 8-byte data
# Filter: usb.transfer_type == 0x01

# Extract keystrokes:
tshark -r usb.pcap -Y "usb.capdata && usb.data_len == 8" -T fields -e usb.capdata > keystrokes.txt

# HID keycode layout: byte[0]=modifier, byte[2]=keycode
# 0x04=a..0x1d=z, 0x1e=1..0x27=0, 0x28=Enter, 0x2c=Space
# Use Python/online HID decoder to convert keycodes → text
```

### WiFi — WPA Handshake

```bash
# Capture: airodump-ng --bssid AP_MAC -w capture wlan0mon
# Convert + crack: hcxpcapngtool -o hash.hc22000 capture.pcap
hashcat -m 22000 hash.hc22000 wordlist.txt
# Deauth detection: wlan.fc.type_subtype == 0x0c
```

### ICMP — Data Exfiltration

```bash
# ICMP payload analysis
# Normal ping: 32 or 64 bytes of pattern data
# Exfiltration: meaningful data in ICMP payload

# Filter:
icmp && data.len > 48                 # unusual ICMP payload size
icmp.type == 8                        # echo requests

# Extract ICMP payloads:
tshark -r capture.pcap -Y "icmp.type==8" -T fields -e data.data
```

---

## 4. DATA EXTRACTION

### File Carving

```bash
# Wireshark: File → Export Objects
# Supported: HTTP, SMB, TFTP, IMF (email), DICOM

# Manual from reassembled stream:
# Follow TCP Stream → Show as Raw → Save As

# binwalk on exported stream data
binwalk -e exported_stream.bin
foremost -i exported_stream.bin -o carved/
```

### Credential Harvesting

```bash
# Plaintext: ftp || telnet || http.authbasic || smtp || pop || imap
# NTLM: ntlmssp.auth.username → extract challenge/response from NTLMSSP messages
# Hash format: user::domain:challenge:NTProofStr:blob → hashcat -m 5600
```

### Covert Channel Detection

Indicators: DNS with long subdomains, ICMP with large payloads, HTTP with encoded headers, regular beacon intervals (C2). Use `tshark -q -z io,stat,1` and `-z conv,tcp` for statistical anomaly detection.

---

## 5. NETWORKMINER

```bash
# Automated PCAP analysis: sudo apt install networkminer
# Open PCAP → auto-extracts: Files, Images, Credentials, Sessions, DNS
# Files tab: carved from HTTP/SMB/FTP | Credentials tab: plaintext creds
```

---

## 6. TSHARK COMMAND-LINE ANALYSIS

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data
tshark -r capture.pcap -q -z io,stat,1                # I/O graph
tshark -r capture.pcap -q -z conv,tcp                  # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip              # IP endpoints
tshark -r capture.pcap -q -z io,phs                    # protocol hierarchy
tshark -r capture.pcap -q -z follow,tcp,ascii,0        # follow stream 0
tshark -r capture.pcap --export-objects http,/tmp/exported/
```

---

## 7. DECISION TREE

```
PCAP file for analysis
│
├── File won't open?
│   ├── Check magic bytes: xxd | head (§1)
│   ├── Repair: pcapfix (§1)
│   └── Convert: editcap pcapng→pcap (§1)
│
├── What's in the capture? (Quick overview)
│   ├── tshark -q -z io,phs (protocol hierarchy) (§6)
│   ├── tshark -q -z conv,tcp (conversations) (§6)
│   └── tshark -q -z endpoints,ip (endpoints) (§6)
│
├── HTTP traffic?
│   ├── Export objects: File → Export Objects → HTTP (§4)
│   ├── Credential hunt: POST + password/login filters (§3)
│   ├── Follow streams: interesting request/response pairs (§3)
│   └── Encrypted (HTTPS)? → need SSLKEYLOGFILE or RSA key (§3)
│
├── DNS traffic?
│   ├── Long subdomains? → DNS tunneling (§3)
│   ├── High TXT record volume? → DNS exfiltration (§3)
│   ├── Extract all queries: tshark -Y dns -T fields -e dns.qry.name (§6)
│   └── DNS rebinding? → check for alternating A record responses
│
├── FTP / Telnet / SMTP?
│   ├── Extract credentials (plaintext) (§3)
│   ├── Reconstruct file transfers (follow data stream) (§3)
│   └── Email content and attachments (base64 decode) (§3)
│
├── USB traffic?
│   ├── Keyboard HID → decode keystrokes (§3)
│   ├── Storage → extract transferred files
│   └── Check transfer_type and data_len fields
│
├── WiFi traffic?
│   ├── WPA handshake → crack with hashcat (§3)
│   ├── Deauth frames → detect attack (§3)
│   └── Probe requests → device fingerprinting
│
├── ICMP traffic?
│   ├── Large/variable payloads → data exfiltration (§3)
│   ├── Regular pattern → ICMP tunnel (§3)
│   └── Extract payloads: tshark -Y icmp -T fields -e data.data
│
├── Suspicious patterns?
│   ├── Regular beacon interval → C2 communication (§4)
│   ├── Unusual port/protocol combos → covert channel (§4)
│   ├── High volume to single external IP → data exfil (§4)
│   └── Encrypted traffic without SNI → suspicious tunnel
│
└── Need automated extraction?
    ├── NetworkMiner for files/creds/images (§5)
    ├── tshark --export-objects for HTTP/SMB files (§6)
    └── binwalk/foremost on exported streams (§4)
```
