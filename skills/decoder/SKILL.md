# Decoder 工具使用文档

## 概述

Decoder 是 CTF Toolkit 内置的编码/解码工具，支持多种常见编码格式的自动检测、解码和编码。

## 决策策略

### 三层推理
- **fact**: 直接观察到的字符集（ASCII/UTF-8/特殊字符）
- **hypothesis**: 猜测编码类型（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先自动检测，再针对性解码。解码最短探针顺序：
1. 自动检测编码类型 → 确认是什么编码
2. 基础解码（Base64/Hex/URL）→ 确认内容
3. 层层递进解码 → 直到明文

### 切换规则
解码无果时：
- 尝试多种编码组合（Base64 + URL）
- 尝试大小端转换
- 尝试压缩后编码（gzip + Base64）
- 尝试其他编码（Unicode/Morse/Base58）

## 支持的编码类型

| 编码类型 | 说明 | 示例 |
|---------|------|------|
| `base64` | Base64 编码 | `SGVsbG8=` |
| `base32` | Base32 编码 | `JBSWY3DPEHPK3PXQ` |
| `url` | URL 编码 | `hello%20world` |
| `hex` | Hex 十六进制 | `48656c6c6f` |
| `unicode` | Unicode 转义 | `\u0048\u0065` |
| `html` | HTML 实体 | `&#72;&#101;` |
| `ascii85` | Ascii85 编码 | `87cURD]j7Bo` |

## 基本使用

### 自动解码（推荐）

```python
from toolkit import decoder

# 自动检测编码并解码
result = decoder.auto_decode("SGVsbG8gQ1RGIQ==")
print(result.result)  # Hello CTF!

# 检查是否包含 flag
if result.has_flag:
    print(f"发现 flag: {result.flag}")
```

### 指定编码解码

```python
from toolkit.decoder import decode

# 指定 Base64 解码
result = decode("SGVsbG8=", encoding="base64")
print(result.result)  # Hello

# 指定 URL 解码
result = decode("hello%20world", encoding="url")
print(result.result)  # hello world

# 指定 Hex 解码
result = decode("48656c6c6f", encoding="hex")
print(result.result)  # Hello
```

### 编码

```python
from toolkit.decoder import encode

# Base64 编码
result = encode("Hello CTF!", encoding="base64")
print(result.result)  # SGVsbG8gQ1RGIQ==

# URL 编码
result = encode("hello world!", encoding="url")
print(result.result)  # hello%20world%21

# Hex 编码
result = encode("Hello", encoding="hex")
print(result.result)  # 48656c6c6f
```

## 高级功能

### 多层嵌套解码

自动处理多层编码：

```python
from toolkit.decoder import auto_decode

# 多层编码：base64(url_encode(data))
nested = "RmxhZyU3QmN0ZiU3RA=="  # base64("Flag%7Bctf%7D")
result = auto_decode(nested)
print(result.result)   # Flag{ctf}
print(result.steps)    # [{'encoding': 'base64', 'result': 'Flag%7Bctf%7D'},
                       #  {'encoding': 'url', 'result': 'Flag{ctf}'}]
```

### 编码类型检测

```python
from toolkit.decoder import detect_encoding

# 检测可能的编码类型
results = detect_encoding("SGVsbG8gQ1RGIQ==")
# [('base64', 0.9)]

# 返回列表包含 (编码类型, 置信度) 元组
for encoding, confidence in results:
    print(f"{encoding}: {confidence}")
```

### 获取支持的编码列表

```python
from toolkit.decoder import supported_encodings

encodings = supported_encodings()
# ['base64', 'base32', 'url', 'hex', 'unicode', 'html', 'ascii85']
```

## 快速解码方法

提供便捷的特定编码解码方法：

```python
from toolkit import decoder

# Base64
r = decoder.base64("SGVsbG8=")

# URL
r = decoder.url("hello%20world")

# Hex
r = decoder.hex("48656c6c6f")

# Unicode
r = decoder.unicode("\\u0048\\u0065")

# HTML
r = decoder.html("&#72;&#101;")

# Ascii85
r = decoder.ascii85("87cURD]j7Bo")

# Base32
r = decoder.base32("JBSWY3DPEHPK3PXQ")
```

## 结果对象

`DecodeResult` 对象包含以下属性：

| 属性 | 类型 | 说明 |
|-----|------|------|
| `success` | bool | 是否成功 |
| `result` | str | 解码/编码结果 |
| `encoding` | str | 使用的编码类型 |
| `steps` | List[Dict] | 解码步骤（多层解码时） |
| `error` | str | 错误信息（失败时） |
| `has_flag` | bool | 检查是否包含 flag |
| `flag` | str | 提取 flag 字符串 |

```python
result = decoder.auto_decode("ZmxhZyU3QjEyMyU3RA==")

if result.success:
    print(f"结果: {result.result}")
    print(f"编码类型: {result.encoding}")
    if result.has_flag:
        print(f"提取到 flag: {result.flag}")  # flag{123}
```

## CTF 应用场景

### 解码 Web 响应中的编码字符串

```python
# 从 HTTP 响应中获取编码字符串
encoded = "ZmxhZyU3QjEyMyU3RA=="  # 从页面源码中提取

# 尝试解码
result = decoder.auto_decode(encoded)
if result.success:
    print(f"解码结果: {result.result}")
```

### 处理多层编码的 flag

```python
# 常见的 CTF 多层编码
encoded_data = "RmxhZyU3QmN0ZiU3RA=="

result = decoder.auto_decode(encoded_data, max_iterations=10)
if result.success:
    print(f"最终: {result.result}")
    for step in result.steps:
        print(f"  -> {step['encoding']}: {step['result']}")
```

### 批量解码尝试

```python
encoded_strings = [
    "SGVsbG8=",
    "68656c6c6f",
    "hello%20world",
]

for s in encoded_strings:
    result = decoder.auto_decode(s)
    if result.success:
        print(f"{s} -> {result.result} ({result.encoding})")
```

## 注意事项

1. **自动检测准确率**: 自动检测基于数据特征，可能有误判，不确定时建议指定编码类型
2. **嵌套层数限制**: 默认最多 10 层解码，可通过 `max_iterations` 参数调整
3. **编码错误处理**: 解码失败返回 `success=False`，可通过 `result.error` 获取错误信息
4. **字符编码**: 处理非 ASCII 字符时可能出现问题，工具主要设计用于 CTF 中的 ASCII flag
