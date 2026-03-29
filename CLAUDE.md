# CTF Agent - Claude Code 直接模式解题代理

> 当用户提供 URL 时，**立即自动执行**解题流程，无需额外确认。

---

## 解题流程（强制执行）

用户给出 URL 后，**立即自动执行**：

```
1. curl 访问目标 → 观察页面结构
2. 识别题型（rce/sqli/auth/lfi/xss/upload）
3. 【自动获取知识】立即执行：
   C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import get_all_type_knowledge; print(get_all_type_knowledge('题型'))"
   - 自动检索：skills/ + memories/ + wooyun/knowledge/ + wooyun_cases/
   - 返回格式化知识，直接作为解题上下文
4. 【基于知识制定攻击计划】根据返回的知识确定攻击方法
5. 使用辅助工具（dirsearch/sqlmap）
6. 构造 payload，执行攻击
7. 识别 flag → 输出 FLAG{...}
8. 【自动保存经验】set_flag('FLAG{...}', '成功方法', '关键payload')
```

**强制规则**：
- 步骤 3 必须立即执行，不得跳过
- 步骤 4 必须基于步骤 3 的知识制定计划，不得盲试
- 失败 3 次后重新执行步骤 3 获取新知识

---

## 攻击前检查清单

解题前必须完成：

- [x] curl 目标页面，观察结构
- [x] 识别题型
- [x] 执行 `get_all_type_knowledge('题型')` 获取知识
- [x] 基于知识制定攻击计划
- [ ] 执行攻击

---

## 【强制】失败记录指令

**目标**：确保每次失败的尝试都被记录到 `failures.json`，供 Hook 检测阈值。

### 手动记录（LLM 自觉）
当 curl/sqlmap 等工具**命令成功但攻击无效**时（如 SQL 注入无效果、LFI payload 无回显），LLM 必须：

```python
record_failed('方法名', '失败原因', '使用的 payload')
```

### 检查方法是否已失败
```python
is_method_failed('http://target.com', 'sqlmap')  # 返回 True/False
```

### 强制重查触发
当 `failures.json` 中同一目标的方法数 ≥3 时，Hook 会注入**强制重查消息**，要求你：
1. 调用 `get_all_type_knowledge('题型')` 重新获取知识
2. 查看 `memories/experiences/` 中的历史经验
3. **禁止重复已失败的方法**

---

## 失败触发知识查询

**【重要】失败 3 次后，Hook 会强制提示重新查询知识**

当你尝试 3 次都失败时：
```
1. 查看当前状态：C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.state_manager import get_context_summary; print(get_context_summary())"
2. 重新获取知识：C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import get_all_type_knowledge; print(get_all_type_knowledge('题型'))"
3. 基于新知识制定新攻击计划
4. 继续尝试
```

**不要重复尝试同样的方法**——失败后换思路。

---

## 题型识别

根据挑战描述和文件类型识别 web 漏洞类型：

**关键词识别：**
- "XSS", "SQL", "injection", "cookie", "JWT" → XSS/SQLi
- "upload", "file inclusion", "LFI", "RFI" → 文件上传/包含
- "SSTI", "template" → SSTI
- "auth", "bypass", "login", "password" → 认证绕过
- "RCE", "command", "exec", "code execution" → RCE
- "SSRF", "curl", "file_get_contents" → SSRF

**文件类型识别：**
- Web URL 或 HTML/JS/PHP 源码 → web
- URL 路径包含 `/admin`, `/login`, `/api` → 认证相关

---

## 失败转向（Pivot When Stuck）

**失败 3 次后必须执行以下步骤：**

1. **重新审视假设** - 这个漏洞类型真的正确吗？
2. **尝试不同技术** - 很多挑战混合多种漏洞
3. **检查遗漏** - 隐藏文件、响应头、源码注释
4. **检查边界情况** - 编码问题、竞争条件

**常见多类型组合：**
- Web + Auth: JWT 伪造、session 利用
- Web + File: 文件上传 + 代码执行

---

## 快速检索命令

```bash
# 获取指定题型全部知识（自动检索以下4个来源）
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import get_all_type_knowledge; print(get_all_type_knowledge('rce'))"

# 知识来源：
# 1. skills/rce/SKILL.md - 技能知识
# 2. memories/experiences/rce.md - 成功经验
# 3. wooyun/knowledge/command-execution.md - WooYun 技术手册
# 4. wooyun/plugins/wooyun-legacy/categories/ - WooYun 精简案例库

# RAG 关键词检索
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import search_knowledge; print(search_knowledge('phpinfo', top_k=5))"

# 检查失败方法
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.failure_tracker import is_method_failed; print(is_method_failed('http://target.com', 'system'))"
```

---

## 强制知识检查 Hook

**【系统机制】PreToolUse Hook 自动检查**

当你执行 `curl`、`sqlmap`、`dirsearch` 等攻击工具时，系统会自动检查：

1. **是否有未过期的知识查询标记**（`workspace/.knowledge_checked`）
2. 如果没有，会注入提醒让你先查询知识

**正确的解题流程**：
```
1. curl 目标页面
2. 识别题型
3. Read skills/<type>/SKILL.md
4. RAG 检索：C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import search_knowledge..."
5. Read memories/experiences/<type>.md
6. 【标记】C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe mark_knowledge_checked.py  ← 必须！
7. 执行攻击工具（curl/sqlmap/dirsearch）
```

**为什么需要手动标记？**
- Hook 在攻击工具执行前检查，无法自动知道知识查询何时完成
- 标记脚本创建 `workspace/.knowledge_checked` 文件
- 文件超过 30 分钟自动过期，需要重新标记

---

---

## 技能知识（skills/）

解题前必须加载：

```
skills/rce/SKILL.md           - RCE 命令注入绕过
skills/sqli/SKILL.md         - SQL 注入 bypass
skills/auth-bypass/SKILL.md   - 认证绕过
skills/file-inclusion/SKILL.md - 文件包含 LFI
skills/xss/SKILL.md           - XSS 绕过
skills/upload/SKILL.md         - 文件上传绕过
skills/deserialization/SKILL.md - 反序列化
skills/ssrf/SKILL.md          - SSRF
skills/ssti/SKILL.md          - 模板注入
```

---

## 工具用法

### curl（直接调用）
```
curl -s -k http://target.com
```

### sqlmap（通过 Python 模块）
```python
from tools.sqlmap_tool import scan, deep_scan

# 普通扫描
result = scan("http://target.com/?id=1")

# 深度扫描
result = deep_scan("http://target.com/?id=1")
```

### dirsearch（通过 Python 模块）
```python
from tools.dirsearch_tool import scan, quick_scan

# 扫描
result = scan("http://target.com")

# 快速扫描
result = quick_scan("http://target.com")
```

### 解析输出
```python
from tools.output_parser import parse_curl, parse_sqlmap, parse_dirsearch
```

---

## RAG 知识库类别

| category | 题型 |
|----------|------|
| command-execution | rce |
| sql-injection | sqli |
| file-traversal | lfi |
| file-upload | upload |
| xss | xss |
| unauthorized-access | auth |
| logic-flaws | auth |
| info-disclosure | recon |

---

## 状态管理

```python
# 初始化并记录状态
from core.state_manager import init_state, add_finding, add_method, add_reasoning, add_failed_pattern, add_suggested_bypass, set_flag, record_failed, get_context_summary
init_state('http://target.com', 'rce')

# 记录每个动作和发现
add_finding('disable_functions=exec,system')
add_reasoning('curl homepage', '发现 PHPinfo 页面')
add_reasoning('test system()', '被 disable_functions 拦截')

# 记录失败特征和建议
add_failed_pattern('disable_functions')
add_suggested_bypass('copy() 文件写入', 'copy 函数未被禁用')

# 记录方法
add_method('system')
add_method('exec')

# 设置 flag（自动保存经验）
# 第二个参数为成功方法，第三个参数为关键 payload（会保存到经验中）
set_flag('FLAG{...}', 'path_traversal_bypass', 'mmm/../../../../../../../../flag.txt')

# 获取完整状态摘要（重要！）
print(get_context_summary())

# 记录失败尝试（自动写入 failures.json）
record_failed('system', 'disabled by disable_functions', 'system("id")')
record_failed('copy', 'file not found', 'copy("/tmp/a","/var/www/html/b.php")')

# 检查失败
is_method_failed('http://target.com', 'system')  # True

# 保存成功经验（自动用当前状态，已被 set_flag 替代）
# 现在 set_flag('FLAG{...}', 'method') 会自动保存，无需单独调用
# 但 save_experience_auto 仍可用于手动保存
from core.state_manager import save_experience_auto
save_experience_auto('copy')  # 传入成功的方法名
```

---

## 约束

- **【强制】所有 Python 命令必须使用虚拟环境**：
  ```
  C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe
  ```
  禁止使用裸 `python`、`python3` 命令，所有 Python 调用必须带完整路径
- 解题时联网请求用 `curl`（需要精确控制），其他场景可用 WebFetch/WebSearch
- 发现 flag 后调用 `set_flag('FLAG{...}', 'method', 'payload')` 自动保存经验（payload 会写入经验文件）
- **先查知识再动手**，不要盲试
- 每次尝试前检查失败记录
- 执行完每个步骤后主动推进，不要等待用户指令
