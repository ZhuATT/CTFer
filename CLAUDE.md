# CTF Agent - Claude Code 直接模式解题代理

> 当用户提供 URL 时，**立即自动执行**解题流程，无需额外确认。

---

## 解题流程（强制执行）

用户给出 URL 后，**立即**按顺序执行每一步：

```
1. curl 访问目标 → 观察页面结构
2. 识别题型（rce/sqli/auth/lfi/xss/upload）
3. 【必须】加载技能知识：Read skills/<type>/SKILL.md
4. 【必须】RAG 检索wooyun知识库
5. 【必须】参考历史经验：Read memories/experiences/<type>.md
6. 使用辅助工具（dirsearch/sqlmap）
7. 构造 payload，执行攻击
8. 识别 flag → 输出 FLAG{...}
9. 【必须】保存经验：from core.state_manager import save_experience_auto; save_experience_auto('成功方法')
```

**关键**：不要盲试！每次构造 payload 前，必须先完成 3-5 步知识准备。

---

## 攻击前检查清单

每次尝试攻击前，确认已完成：

- [ ] **skills/<type>/SKILL.md** - 阅读题型技能知识
- [ ] **RAG 检索** - 查询类似题目的解法
- [ ] **memories/experiences/** - 查看历史经验
- [ ] **失败记录** - 检查该方法是否已失败过

没完成检查清单就盲目尝试是**无效的**。

---

## 失败触发知识查询

**【重要】失败 3 次后，必须重新查询知识**

当你尝试 3 次都失败时：
```
1. 查看当前状态：python -c "from core.state_manager import get_context_summary; print(get_context_summary())"
2. RAG 检索：python -c "from core.rag_knowledge import search_knowledge; print(search_knowledge('失败关键词', category='题型', top_k=5))"
3. 分析 suggested_bypass 建议
4. 基于新知识制定新攻击计划
5. 继续尝试
```

**不要重复尝试同样的方法**——失败后换思路。

---

## 快速检索命令

```bash
# RAG 统一检索（搜索所有知识库）
python -c "from core.rag_knowledge import search_knowledge; print(search_knowledge('rce', top_k=5))"

# 读取技能知识
Read skills/rce/SKILL.md

# 读取历史经验
Read memories/experiences/rce.md

# 检查失败方法
python -c "from core.failure_tracker import is_method_failed; print(is_method_failed('http://target.com', 'copy'))"

# 标记知识已查询
python mark_knowledge_checked.py
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
4. RAG 检索：python -c "from core.rag_knowledge import search_knowledge..."
5. Read memories/experiences/<type>.md
6. 【标记】python mark_knowledge_checked.py  ← 必须！
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
from core.state_manager import init_state, add_finding, add_method, add_reasoning, add_failed_pattern, add_suggested_bypass, set_flag, get_context_summary
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
set_flag('FLAG{...}', 'ctfshow_1024')  # 第二个参数为成功方法，会自动保存经验

# 获取完整状态摘要（重要！）
print(get_context_summary())

# 检查失败
from core.failure_tracker import is_method_failed, record_failure
record_failure('http://target.com', 'system', 'disabled', 'rce')
is_method_failed('http://target.com', 'system')  # True

# 保存成功经验（自动用当前状态，已被 set_flag 替代）
# 现在 set_flag('FLAG{...}', 'method') 会自动保存，无需单独调用
# 但 save_experience_auto 仍可用于手动保存
from core.state_manager import save_experience_auto
save_experience_auto('copy')  # 传入成功的方法名
```

---

## 约束

- 联网请求用 `curl`，不用 WebFetch/WebSearch
- 发现 flag 后调用 `set_flag('FLAG{...}', 'method')` 自动保存经验
- **先查知识再动手**，不要盲试
- 每次尝试前检查失败记录
- 执行完每个步骤后主动推进，不要等待用户指令
