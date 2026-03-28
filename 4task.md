# CTF Agent 优化计划

> 基于实际解题测试发现的问题，制定优化方案。

---

## 问题总结

| 问题 | 表现 |
|------|------|
| LLM 不主动查知识 | 失败后盲目重试，不按流程先查再试 |
| RAG 检索不实用 | 返回结果与 CTFshow 题目不匹配 |
| 缺乏主动探索 | 只测主页面，不主动扫描其他端点 |
| 状态没有持续更新 | 只在最后 set_flag()，过程无记录 |

---

## 解决方案

### Phase 1: 状态管理增强 ✅ 已完成

**目标**：增强状态持久化，支持推理历史记录

**修改文件**：`core/state_manager.py`

**新增 API**：
```python
add_reasoning(action, finding)     # 记录推理链
add_failed_pattern(pattern)          # 记录失败特征
add_suggested_bypass(method, reason) # 记录建议的 bypass 方法
get_context_summary()                 # 获取供 LLM 使用的完整状态摘要
```

**测试验证**：
```bash
python -c "from core.state_manager import init_state, add_finding, add_reasoning, add_suggested_bypass, get_context_summary; init_state('http://test.com', 'auth'); add_finding('Cookie: ro1e=guest'); add_reasoning('curl homepage', '发现 Admin Login'); add_suggested_bypass('修改 Cookie', '需要登录后修改'); print(get_context_summary())"
```
✅ 通过

**新状态结构**：
```json
{
  "target": "url",
  "type": "auth",
  "step": 5,
  "findings": ["Cookie: ro1e=guest", "Login form at /check.php"],
  "methods_tried": ["cookie_ro1e_admin", "sql_injection", "default_creds"],
  "failed_patterns": ["Admin Login", "Invalid credentials"],
  "suggested_bypass": ["Modify ro1e=admin after login"],
  "reasoning_chain": [
    {"step": 1, "action": "curl homepage", "finding": "Admin Login form"},
    {"step": 2, "action": "test guest/guest", "finding": "Login success, cookie ro1e=guest"},
    {"step": 3, "action": "set ro1e=admin", "finding": "Still Admin Login page"},
    {"step": 4, "action": "access /check.php with admin cookie", "finding": "Flag found!"}
  ],
  "flag": "FLAG{cookie_injection_is_fun}"
}
```

**新增 API**：
```python
add_reasoning(action, finding)     # 记录推理链
add_failed_pattern(pattern)          # 记录失败特征
add_suggested_bypass(method)        # 记录建议的 bypass 方法
get_state_summary()                  # 获取状态摘要（供 LLM 上下文使用）
```

---

### Phase 2: 失败触发 RAG ✅ 已完成

**目标**：失败 N 次后强制触发 RAG 检索

**修改文件**：
- `CLAUDE.md` - 新增"失败触发知识查询"章节
- `core/failure_tracker.py` - 新增 `should_trigger_rag()` 函数

**新增 API**：
```python
from core.failure_tracker import should_trigger_rag, get_failure_count
should_trigger_rag('http://target.com')  # True if 失败 >= 3
get_failure_count('http://target.com')    # 返回失败数量
```

**测试验证**：
```bash
python -c "from core.failure_tracker import record_failure, should_trigger_rag; \
  record_failure('http://test.com', 'm1', 'r'); \
  record_failure('http://test.com', 'm2', 'r'); \
  print(should_trigger_rag('http://test.com'))"  # False
```
✅ 通过（2次失败不触发，3次触发）

---

### Phase 2.5: 强制知识检查 Hook ✅ 新完成

**目标**：解决"LLM 不主动查知识"——通过 PreToolUse Hook 强制验证

**修改文件**：
- `.claude/settings.json` - 添加 PreToolUse Hook 配置（Python）
- `.claude/hooks/check_knowledge_hook.py` - Hook 检查脚本（跨平台）
- `mark_knowledge_checked.py` - 标记脚本
- `CLAUDE.md` - 新增"强制知识检查 Hook"章节

**工作原理**：
```
Bash 执行 curl/sqlmap/dirsearch
         ↓
PreToolUse Hook 触发
         ↓
检查 workspace/.knowledge_checked 是否存在且未过期（30分钟）
         ↓
不存在 → 注入提醒，要求先查询知识
过期 → 注入提醒，建议重新标记
存在且有效 → 放行
```

**测试验证**：
```bash
# 无 marker 时执行 curl → 返回提醒 JSON
echo '{"tool_input": {"command": "curl -s https://example.com"}}' | python .claude/hooks/check_knowledge_hook.py
# → {"continue": true, "hookSpecificOutput": {...}, "systemMessage": "请先查询知识！"}

# 标记后执行 curl → 返回 {} 放行
python mark_knowledge_checked.py && echo '{"tool_input": {"command": "curl -s https://example.com"}}' | python .claude/hooks/check_knowledge_hook.py
# → {}

# 非工具命令 → 返回 {} 放行
echo '{"tool_input": {"command": "ls -la"}}' | python .claude/hooks/check_knowledge_hook.py
# → {}
```
✅ 通过

---

### Phase 3: 自动目录扫描触发

**目标**：404 响应时自动触发 dirsearch

**修改文件**：`tools/dirsearch_tool.py`

**新增逻辑**：
```python
def auto_scan_on_404(response_text: str, url: str) -> bool:
    """检测到 404 时自动扫描"""
    if "404" in response_text or "Not Found" in response_text:
        print("[!] 404 detected, running dirsearch...")
        run_dirsearch(url)
        return True
    return False
```

**触发条件**：
- curl 返回 404
- 页面包含 "Not Found"
- 连续 3 个页面返回类似内容

---

### Phase 4: 多级检索增强

**目标**：按优先级检索不同知识库

**修改文件**：`core/rag_knowledge.py`

**检索优先级**：
1. `memories/experiences/<type>.md` - 历史成功经验（最高）
2. `wooyun/knowledge/` - WooYun 真实漏洞库
3. `skills/<type>/SKILL.md` - 题型技能知识

**新增 API**：
```python
search_knowledge_multi(query, challenge_type, top_k=5)
# 返回带优先级标记的结果
```

**结果过滤**：
```python
def filter_by_challenge_type(results, challenge_type):
    """根据题型过滤结果"""
    # 例如 auth 题目只看 unauthorized-access 和 logic-flaws
```

---

## 实施顺序

| 阶段 | 任务 | 状态 |
|------|------|------|
| Phase 1 | 状态管理增强 | ✅ 已完成 |
| Phase 2 | 失败触发 RAG | ✅ 已完成 |
| Phase 2.5 | 强制知识检查 Hook | ✅ 已完成 |
| Phase 3 | 自动目录扫描 | 待实施 |
| Phase 4 | 多级检索增强 | 待实施 |

---

## 预期效果

| 阶段 | 效果 |
|------|------|
| Phase 1 | LLM 可随时查看当前状态和推理历史，避免重复失败 |
| Phase 2 | 失败后自动检索知识，换思路而不是盲试 |
| Phase 3 | 自动发现隐藏端点（如 /check.php） |
| Phase 4 | 检索结果更精准，减少无关信息干扰 |

---

## 核心改进思路

**从"人工驱动"改为"事件驱动"**：

```
用户给题目
    ↓
LLM 开始解题
    ↓
失败 3 次 → 自动触发 RAG 检索
    ↓
404 响应 → 自动触发 dirsearch
    ↓
发现新端点 → 继续测试
    ↓
成功 → 保存经验到 memories/
```

---

## 备注

- 工具调用混乱问题暂不修复，留到最后统一处理
- 优化过程中持续测试，确保每阶段都能正常工作
