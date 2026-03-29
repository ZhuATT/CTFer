# Windows 终端编码处理实用技能

## 决策策略

### 使用场景
当遇到 `'gbk' codec can't encode character` 错误时，使用本工具。

### 最短探针原则
先检测编码，再安全输出。编码修复最短探针顺序：
1. `detect_terminal_encoding()` → 确认终端类型
2. `safe_print(text)` → 安全输出
3. 避免直接 `print()` 字符串

### 切换规则
安全输出仍失败时：
- 使用 `encode_for_terminal()` 手动编码
- 尝试设置 `PYTHONIOENCODING=utf-8`
- 使用 `sys.stdout.buffer.write()` 绕过

## Overview

Windows下Python终端经常遇到GBK编码错误（如`'gbk' codec can't encode character`）。
这个模块提供安全的打印和字符串处理方法，避免编码问题。

## 提供功能
- `safe_print(text)` - 安全打印，自动处理编码
- `encode_for_terminal(text)` - 将文本转为终端可安全显示
- `detect_terminal_encoding()` - 检测终端编码

## 快速使用

```python
from skills.encoding_fix import safe_print, encode_for_terminal

# 安全打印（自动处理GBK错误）
safe_print("[OK] 完成 - Success")  # 不会出错

# 处理中文输出
safe_print(f"扫描完成：发现{count}个路径")  # 正常显示

# 编码文本供外部使用
encoded = encode_for_terminal(some_unicode_text)
```

## 详细用法

### safe_print(text, newline=True, encoding=None)
安全打印文本，自动根据终端编码处理。

**参数：**
- `text`: 要打印的文本（可以是包含Unicode的字符串）
- `newline`: 是否在末尾添加换行（默认True）
- `encoding`: 指定编码，默认自动检测

**示例：**
```python
# 正常打印（可能包含特殊字符）
safe_print("✓ 指纹识别完成")  # 会转为 [OK] 指纹...
safe_print("→ 开始扫描...")    # 会转为 -> 开始扫描...

# 批量打印列表
for item in results:
    safe_print(f"  - {item}")
```

### encode_for_terminal(text, fallback='ignore')
将Unicode文本转为终端可安全显示的字符串。

**处理规则：**
- ✓ → [OK]
- × → [X]
- → → ->
- 💡 → [Tip]
- ⚠️ → [Warn]

**示例：**
```python
# 替换特殊Unicode字符
safe = encode_for_terminal("[✓] 完成", to_ascii=True)  # [OK]完成
safe = encode_for_terminal("[✓] 完成", to_ascii=False) # 保持原样或 '?'
```

### detect_terminal_encoding()
检测当前终端编码，返回如'utf-8', 'gbk', 'cp1252'等。

**示例：**
```python
encoding = detect_terminal_encoding()
print(f"终端编码: {encoding}")
```

## 集成到项目中

**常见使用场景：**

```python
# 在Agent输出中使用
class MyAgent(BaseAgent):
    async def execute(self, target, **kwargs):
        from skills.encoding_fix import safe_print

        # 使用safe_print代替print
        safe_print(f"[{self.agent_type}] 开始...")

        # ...

        safe_print("[OK] 完成")

# 在tools.py中使用
from skills.encoding_fix import encode_for_terminal

# 返回给AI之前处理
result_summary = encode_for_terminal(raw_output)
```
