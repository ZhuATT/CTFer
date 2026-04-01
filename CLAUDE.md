# CTF Agent - Claude Code 直接模式解题代理

> 当用户提供 URL 时，**立即自动执行**解题流程，无需额外确认。

---

## 解题流程（强制执行）

用户给出 URL 后，**立即自动执行**：

```
1. curl 访问目标 → 观察页面结构
2. 识别题型（rce/sqli/auth/lfi/xss/upload/ssti/ssrf/deserialization）
3. 【必须】初始化状态：
   C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.state_manager import init_state; init_state('URL', '题型')"
4. 【自动获取知识】立即执行：
   C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import get_all_type_knowledge; print(get_all_type_knowledge('题型'))"
5. 【基于知识制定攻击计划】声明假设 → 进入 Exploit 阶段
6. 执行攻击（curl/sqlmap/dirsearch）
7. 识别 flag → set_flag('FLAG{...}', '方法名', 'payload')
```

**强制规则**：
- 步骤 3、4 必须立即执行，不得跳过
- 步骤 5 必须基于步骤 4 的知识制定计划
- **Hook 会自动拦截未声明假设的攻击行为**

---

## 阶段化攻击流程

```
Recon ────► Identify ────► Exploit ────► Flag
(侦察)      (识别)       (攻击)       (拿旗)
```

| 阶段 | 职责 | 预算 | 门口条件 |
|------|------|------|----------|
| Recon | 信息收集 | 10 步 | - |
| Identify | 漏洞识别 + 假设声明 | 15 步 | ≥2 发现 |
| Exploit | 攻击执行 | 20 步 | 假设已声明 |
| Flag | 验证 + 保存 | - | 找到 Flag |

**阶段门口（PhaseGate）**：
- Recon → Identify：需要 ≥2 个发现
- Identify → Exploit：需要声明假设
- Exploit → Flag：需要找到 flag

---

## Hook 自动检查机制

**PreToolUse Hook（check_knowledge_hook.py）自动检查**：

| 检查项 | 条件 | 动作 |
|--------|------|------|
| 假设声明 | Identify/Exploit 未声明 | **拦截** |
| 方法失败 | 方法在 failures.json | 警告 + 替代建议 |
| 预算耗尽 | step_count ≥ budget | 警告 |
| 工具白名单 | 工具不在允许列表 | **拦截** |
| 语义循环 | 同一动作 ≥3 次 | 警告 |
| 失败阈值 | 同一目标 ≥3 次失败 | 强制重查 |
| 签名循环 | 相同命令 ≥5 次 | **拦截** |

**PostToolUse Hook（save_command_hook.py）自动处理**：
- `add_method()` — 记录已使用方法
- `increment_step()` — 更新阶段步数
- `record_failure()` — 失败时写入 failures.json

**所有检查和记录已自动化，LLM 无需手动调用。**

---

## 顾问审查（Advisor）

每 3 步自动触发，或在关键节点主动调用：

```python
from core.advisor import review, ask

# 初始审查
review("initial")

# 定期审查
review("periodic")

# 阶段转换审查
review("phase_transition", question="从 identify 转到 exploit 是否合理？")

# 失败后审查
review("post_failure")

# 主动提问
ask("目标有 WAF，如何绕过？")
```

**输出格式**：
```json
{
  "verdict": "proceed | pause | pivot",
  "reasoning": "分析理由",
  "suggestions": ["建议1", "建议2"],
  "priority": 1-3
}
```

---

## 循环检测（LoopDetector）

签名级重复检测，区分"真正循环"和"合理重试"：

- 签名格式：`tool_name:args_json[:500]`
- 滑动窗口：12 次
- 阈值：≥3 次警告，≥5 次中断

**自动触发**，无需手动调用。

---

## RAG v2.0 知识检索 + 自动联网

**知识来源（5 个）**：
1. `memories/experiences/*.md` — 成功经验（含 frontmatter 元数据）
2. `skills/*/SKILL.md` — 题型技能知识
3. `knowledge_base/wooyun/` — WooYun 技术手册
4. `knowledge_base/h-pentest/` — H-Pentest 攻击库
5. `knowledge_base/PayloadsAllTheThings/*/README.md` — PATT

**检索流程**：BM25 多源检索 → RRF 融合 → 综合评分排序 → 格式化输出

**持久化索引**：`rag_index/manifest.json` + `rag_index/kb_store.json`

```bash
# 获取题型全部知识
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import get_all_type_knowledge; print(get_all_type_knowledge('rce'))"

# 关键词检索
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import search_knowledge; print(search_knowledge('disable_functions bypass', top_k=5))"

# 重建索引
C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe -c "from core.rag_knowledge import build_rag_index; build_rag_index(force_rebuild=True)"
```

### 自动联网规则

**触发条件（满足任一即自动联网）**：
1. 知识库检索结果为空或相关性很低（< 0.3）
2. 遇到知识库中没有的漏洞/CVE/Payload
3. 需要查询特定技术的最新解决方案
4. 目标使用了知识库中没有记录的框架/中间件
5. 攻击失败后需要查找替代方案

**自动联网流程**：
```
知识库检索 → 结果不足 → 自动调用 /web-fetch 搜索 → 整合结果继续攻击
```

**联网优先级**：
1. `/web-fetch search <技术关键词>` — playwright/Tavily 搜索解决方案
2. `/web-fetch <相关 POC/Writeup URL>` — curl -k 抓取文章（CTF 目标）
3. 优先使用 curl -k（跳过 SSL），复杂页面用 playwright

---

## 状态管理 API

```python
from core.state_manager import (
    init_state, add_finding, add_method, add_reasoning,
    set_hypothesis, set_flag, get_context_summary,
    record_failed, is_method_failed
)

# 初始化
init_state('http://target.com', 'rce')

# 记录发现
add_finding('发现 admin.php 登录页面')
add_finding('SQL 注入点在 id 参数')

# 声明假设
set_hypothesis('SQL 注入绕过 auth 获取 admin 权限', status='verified')

# 设置 flag（自动保存经验）
set_flag('FLAG{...}', 'sql_union_bypass', 'id=0 UNION SELECT...')

# 检查失败方法
is_method_failed('http://target.com', 'sqlmap')  # True/False

# 获取状态摘要
print(get_context_summary())
```

---

## 失败处理

Hook 已自动处理失败记录，**无需手动调用 `record_failed()`**。

**失败转向（失败 3 次后）**：
1. 调用 `get_all_type_knowledge('题型')` 重新获取知识
2. 查看 `memories/experiences/` 中的历史经验
3. 尝试完全不同的攻击向量

---

## 题型识别

| 关键词 | 题型 |
|--------|------|
| "RCE", "command", "exec", "code execution" | rce |
| "SQL", "injection", "sqli" | sqli |
| "LFI", "RFI", "file inclusion", "file_get_contents" | lfi |
| "upload", "file upload" | upload |
| "XSS", "script", "alert" | xss |
| "auth", "bypass", "login", "JWT", "cookie" | auth |
| "SSTI", "template", "jinja" | ssti |
| "SSRF", "file_get_contents", "curl" | ssrf |
| "serialize", "unserialize", "pickle", "phar" | deserialization |

---

## MCP 工具（已配置）

Claude Code 已配置以下 MCP 服务器，可直接调用：

| 工具 | 用途 | 使用场景 |
|------|------|----------|
| **fetch** | 网页抓取 | SSL 证书不稳定的站点慎用 |
| **chrome-devtools** | Chrome 开发者工具 | 浏览器环境 |
| **playwright** | 浏览器自动化 | 搜索、复杂表单交互、截图 |
| **Tavily** | 智能搜索 | 深度技术搜索 |

**调用方式**：直接使用 `fetch`、`playwright`、`Tavily`、`chrome-devtools` 或 `curl` 工具，Claude Code 会自动识别。

---

## 工具用法

### curl（直接调用）
```
curl -s -k http://target.com
curl -s -k "http://target.com/?id=1 UNION SELECT 1,2,3"
```

### sqlmap
```python
from tools.sqlmap_tool import scan, deep_scan
result = scan("http://target.com/?id=1")
result = deep_scan("http://target.com/?id=1")
```

### dirsearch
```python
from tools.dirsearch_tool import scan, quick_scan
result = scan("http://target.com")
result = quick_scan("http://target.com")
```

### /web-fetch（slash command）
```
/web-fetch https://example.com       # 抓取网页
/web-fetch search Python 教程         # 搜索
```

### 解析输出
```python
from tools.output_parser import parse_curl, parse_sqlmap, parse_dirsearch
```

---

## 技能知识（skills/）

```
skills/rce/SKILL.md               - RCE 命令注入绕过
skills/sqli/SKILL.md             - SQL 注入 bypass
skills/auth-bypass/SKILL.md       - 认证绕过
skills/file-inclusion/SKILL.md   - 文件包含 LFI/RFI
skills/upload/SKILL.md           - 文件上传绕过
skills/xss/SKILL.md              - XSS 绕过
skills/deserialization/SKILL.md   - 反序列化
skills/ssrf/SKILL.md             - SSRF
skills/ssti/SKILL.md             - 模板注入
skills/recon/SKILL.md            - 信息收集
skills/awdp/SKILL.md             - AWDP 模式
skills/decoder/SKILL.md          - 编码绕过
```

---

## 约束

- **【强制】所有 Python 命令必须使用虚拟环境**：
  ```
  C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe
  ```
- 解题时联网请求用 `curl -k`，其他场景用 playwright/Tavily
- **先查知识再动手**，不要盲试
- 执行完每个步骤后主动推进，不要等待用户指令
- 发现 flag 后调用 `set_flag()` 自动保存经验
