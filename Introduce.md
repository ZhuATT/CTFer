# CTF Agent 完整运行流程

> 本文档详细描述 CTF Agent 从接收题目到解题完成的全流程架构。

---

## 一、系统架构总览

```
用户输入 URL
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  1. 解题流程触发                                          │
│     - curl 访问目标 → 识别题型                            │
│     - init_state() 初始化状态                            │
│     - get_all_type_knowledge() 获取知识                    │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  2. 知识系统 (RAG)                                       │
│     skills/<type>/SKILL.md     ← 技能知识（人工编写）      │
│     memories/experiences/<>.md  ← 成功经验（自动积累）     │
│     wooyun/knowledge/         ← WooYun 漏洞库            │
│     wooyun/plugins/.../       ← 精简案例库               │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  3. 攻击执行                                            │
│     - curl / sqlmap / dirsearch                         │
│     - Hook 检查知识标记                                  │
│     - FailureTracker 记录失败                            │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  4. 状态持久化                                          │
│     workspace/state.json      ← 当前解题状态               │
│     workspace/failures.json   ← 失败记录                 │
│     workspace/.knowledge_log  ← 知识调用日志              │
│     workspace/.knowledge_checked ← 知识检查标记           │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  5. 经验保存                                            │
│     set_flag() → 自动保存经验到 memories/experiences/    │
└─────────────────────────────────────────────────────────┘
```

---

## 二、目录结构

```
CTFagent/
├── CLAUDE.md                    ← 项目说明（给 LLM 看的指令）
├── Introduce.md                  ← 本文档
│
├── .claude/
│   ├── settings.json            ← Claude Code 配置（Hook/权限）
│   └── hooks/
│       └── check_knowledge_hook.py  ← PreToolUse Hook
│
├── core/                        ← 核心模块
│   ├── state_manager.py         ← 解题状态管理
│   ├── rag_knowledge.py         ← RAG 知识检索
│   ├── skill_loader.py          ← Skill 加载器
│   ├── experience_manager.py    ← 经验保存管理
│   ├── failure_tracker.py       ← 失败追踪
│   └── loop_detector.py         ← 循环检测（签名级）
│
├── skills/                      ← 技能知识（人工维护）
│   ├── rce/SKILL.md
│   ├── sqli/SKILL.md
│   ├── lfi/SKILL.md
│   ├── xss/SKILL.md
│   ├── auth-bypass/SKILL.md
│   ├── file-inclusion/SKILL.md
│   ├── upload/SKILL.md
│   ├── ssrf/SKILL.md
│   ├── ssti/SKILL.md
│   ├── deserialization/SKILL.md
│   ├── recon/SKILL.md
│   ├── awdp/SKILL.md
│   ├── decoder/SKILL.md
│   ├── encoding_fix/SKILL.md
│   └── encoding_fix/__init__.py  ← 编码修复
│
├── memories/                    ← 经验积累
│   └── experiences/             ← 成功经验（按题型索引）
│       ├── _index.md
│       ├── rce.md
│       ├── sqli.md
│       ├── lfi.md
│       └── ...
│
├── wooyun/                      ← WooYun 漏洞库
│   ├── knowledge/               ← 技术手册
│   ├── categories/             ← 案例分类
│   ├── examples/               ← 渗透示例
│   └── plugins/
│       └── wooyun-legacy/      ← 精简版
│           ├── categories/     ← 精简案例库
│           └── skills/
│
├── tools/                       ← 工具封装
│   ├── curl_tool.py
│   ├── sqlmap_tool.py
│   ├── dirsearch_tool.py
│   ├── output_parser.py
│   ├── sqlmap/                  ← sqlmap 源码
│   └── dirsearch/               ← dirsearch 源码
│
└── workspace/                   ← 工作目录（解题状态）
    ├── state.json               ← 当前状态
    ├── failures.json            ← 失败记录
    ├── .loop_state.json        ← 循环检测状态（跨进程）
    ├── .knowledge_checked       ← 知识已检查标记
    ├── .knowledge_log           ← 知识调用日志
    └── traces/                  ← （可选）操作轨迹
```

---

## 三、核心组件详解

### 3.1 Hook 机制（check_knowledge_hook.py）

**位置**: `.claude/hooks/check_knowledge_hook.py`

**触发时机**: 每次执行 Bash 工具之前（PreToolUse）

**配置来源**: `.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "python.exe .claude/hooks/check_knowledge_hook.py",
        "timeout": 10
      }]
    }]
  }
}
```

**检查逻辑**:
1. 读取 `workspace/state.json` → 获取当前靶机、题型、已尝试方法
2. 读取 `workspace/failures.json` → 获取失败记录
3. 扫描 `skills/`、`memories/experiences/` → 获取可用知识文件列表
4. 根据状态生成建议（新手引导/继续攻击/任务完成）

**返回结构**:
```python
{
    "continue": True,  # 不阻止执行，提供上下文
    "hookSpecificOutput": {
        "additionalContext": "【当前状态】\n- 靶机: ...\n- 题型: ..."
    }
}
```

**关键设计原则**: Hook 只提供上下文，不强制阻断。LLM 根据上下文自主决策下一步。

---

### 3.2 状态管理（state_manager.py）

**状态文件**: `workspace/state.json`

**核心结构**:
```json
{
  "target": "https://challenge.ctf.show/",
  "type": "lfi",
  "step": 0,
  "findings": [
    "日志文件: /var/log/nginx/access.log",
    "flag位置: /var/www/html/flag.php"
  ],
  "methods_tried": [
    "日志文件包含 + User-Agent注入PHP代码"
  ],
  "failed_patterns": [],
  "suggested_bypass": [],
  "reasoning_chain": [
    {"step": 1, "action": "curl homepage", "finding": "发现 LFI 参数 page="}
  ],
  "flag": "CTF{...}",
  "created_at": "2026-03-28T19:26:14",
  "updated_at": "2026-03-28T19:26:14"
}
```

**核心 API**:
```python
init_state(target, challenge_type)     # 初始化新题目
add_finding(finding)                  # 添加发现
add_method(method)                    # 记录已尝试方法
add_reasoning(action, finding)        # 添加推理链
add_failed_pattern(pattern)           # 记录失败特征
add_suggested_bypass(method, reason)  # 添加建议 bypass
set_flag(flag, method_succeeded)      # 设置 flag → 自动保存经验
get_context_summary()                  # 获取完整状态摘要
```

---

### 3.3 RAG 知识检索（rag_knowledge.py）

**搜索来源（按优先级）**:
1. `memories/experiences/<type>.md` — 历史成功经验（最高）
2. `skills/<type>/SKILL.md` — 题型技能知识
3. `wooyun/knowledge/<category>.md` — WooYun 技术手册
4. `wooyun/plugins/wooyun-legacy/categories/` — WooYun 精简案例库

**检索流程**:
```
用户查询 → 同义词扩展 → 中文分词 (jieba) → TF-IDF 余弦相似度 → 返回 top_k 结果
```

**题型 → 类别映射**:
| 题型 | WooYun 类别 |
|------|------------|
| rce | command-execution |
| sqli | sql-injection |
| lfi | file-traversal |
| upload | file-upload |
| xss | xss |
| auth | unauthorized-access |
| ssrf | ssrf |
| ssti | ssti |

**核心 API**:
```python
get_all_type_knowledge(challenge_type)  # 获取题型全部知识
search_knowledge(query, category, top_k)  # RAG 检索
format_knowledge_results(results)      # 格式化输出
```

---

### 3.4 经验管理（experience_manager.py）

**保存时机**: `set_flag(flag, method_succeeded)` 被调用时自动保存

**保存位置**: `memories/experiences/<type>.md`

**智能保存**: 使用 LLM 自动生成高质量经验
- 自动判断是否与已有经验重复
- 自动生成标准化 Markdown 格式
- 自动提取相关标签

**经验格式**:
```markdown
## [LFI 通过 php://filter 读取敏感文件]

### 核心 bypass
**[利用 php://filter 协议配合 base64 编码绕过文件包含限制读取源码]**

### 原理分析
- PHP 的 `php://filter` 协议允许在文件包含前对内容进行过滤处理
- `convert.base64-encode` 过滤器会对文件内容进行 Base64 编码
- 由于文件被包含时会执行 PHP 代码，直接访问会得到执行结果而非源码
- 使用 Base64 编码后，源码被编码成字符串，从而绕过执行直接获取原始内容
- db.php 等配置文件通常包含数据库凭证等敏感信息

### 关键 Payload
```php
php://filter/read=convert.base64-encode/resource=db.php
```

### 失败记录
- 直接包含 db.php：返回空或执行结果，无法获取源码

### 适用场景
- LFI 题型中需要读取 PHP 源码
- 文件包含点无法直接 RCE 时获取配置文件
- 目标存在 db.php、config.php、conn.php 等数据库配置文件的场景

---
doc_kind: experience
type: lfi
created: 2026-03-29
tags: [lfi, php://filter, base64-encode]
---
```

**LLM 配置**: 通过 `config.json` 配置
```json
{
  "llm": {
    "api_url": "https://mydamoxing.cn",
    "api_key": "sk-xxx",
    "model": "MiniMax-M2.7-highspeed",
    "provider": "claude"
  }
}
```

**核心 API**:
```python
save_experience_with_llm(...)  # LLM 智能保存
save_experience(...)           # 普通保存（兼容）
```

---

### 3.5 失败追踪（failure_tracker.py）

**状态文件**: `workspace/failures.json`

**记录结构**:
```json
[
  {
    "target": "http://target.com",
    "method": "system",
    "reason": "disabled by disable_functions",
    "payload": "system('id')",
    "category": "rce",
    "created_at": "2026-03-28T19:00:00"
  }
]
```

**核心 API**:
```python
record_failure(target, method, reason, payload, category)  # 记录失败
is_method_failed(target, method)  # 检查方法是否已失败
should_trigger_rag(target)  # 失败≥3次时触发 RAG 重查
```

---

### 3.6 Skill 加载器（skill_loader.py）

**职责**: 根据题型映射到正确的 skill 目录

**题型映射表**:
```python
TAXONOMY_SKILL_MAP = {
    "rce": "rce",
    "command_injection": "rce",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "lfi": "file-inclusion",
    "file_inclusion": "file-inclusion",
    "auth": "auth-bypass",
    "auth_bypass": "auth-bypass",
    ...
}
```

---

### 3.7 编码修复（encoding_fix）

**问题**: Windows Git Bash/MSYS2 环境下 `sys.stdout.encoding` 返回 `gbk`，但终端实际支持 UTF-8

**解决方案**:
```python
detect_terminal_encoding()  # 检测 MSYS2 环境
encode_for_terminal(text)   # MSYS2 下返回 UTF-8 bytes
safe_print(text)            # 安全输出，自动处理编码
```

---

### 3.8 循环检测（loop_detector.py）

**文件**: `core/loop_detector.py`

**问题**: 简单的"失败3次就提示"无法区分真正的循环和合理的重试。例如：
- `curl /?page=1` 失败 → `curl /?page=2` 失败 → `curl /?page=1` 再执行 → 前两次参数不同，第三次的签名和第一次相同
- 用"失败次数"判断会把第三次的重试当成正常（因为是第2次失败），但实际上签名完全相同，是真正的循环

**解决方案**: 签名级循环检测

**签名格式**: `tool_name:args_json[:500]`

**检测逻辑**:
```
滑动窗口（12次）→ 统计相同签名出现次数
- ≥3次 → warn 警告
- ≥5次 → break 中断
```

**核心 API**:
```python
from core.loop_detector import check_loop, LOOP_WARNING_MESSAGE, LOOP_BREAK_MESSAGE

# 检查命令是否循环
result = check_loop('curl', '-s http://target.com')
# 返回: None / "warn" / "break"
```

**与 Hook 集成**: `check_knowledge_hook.py` 在每次 Bash 命令前调用 `check_loop()`，并将警告信息注入 `additionalContext`

**持久化**: 状态保存到 `workspace/.loop_state.json`，支持跨进程检测

**优势对比**:
| 机制 | 防止什么 |
|------|---------|
| 失败次数判断 | 同一方法失败N次后提示 |
| Hook: check_command_for_failed_methods | 命令包含已失败方法名 |
| **LoopDetector** | **完全相同命令（签名级）重复执行** |

---

## 四、解题完整流程

```
┌──────────────────────────────────────────────────────────────┐
│  Step 0: 用户输入                                              │
│  题目: https://challenge.ctf.show/                             │
│  hint: 日志文件包含                                            │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 1: 初始化状态                                           │
│  init_state(url, 'lfi')                                       │
│  → 创建 workspace/state.json                                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 2: curl 访问目标                                        │
│  curl -s -k https://challenge.ctf.show/                      │
│  → 观察页面结构，识别漏洞类型（LFI）                           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 3: 获取知识（强制）                                      │
│  get_all_type_knowledge('lfi')                                 │
│  → RAG 检索 4 个来源                                          │
│  → 格式化输出作为解题上下文                                    │
│  → 写入 .knowledge_log 供 Hook 验证                           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 4: 基于知识制定攻击计划                                  │
│  根据返回的知识：                                              │
│  - skills/file-inclusion/SKILL.md → 日志文件包含方法          │
│  - memories/experiences/lfi.md → 历史成功经验                 │
│  - wooyun/knowledge/file-traversal.md → 类似题目              │
│  → 确定攻击向量：nginx access.log + User-Agent 注入           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 5: 执行攻击                                             │
│  a) curl 目标页面，尝试 LFI                                   │
│  b) Hook 检查：.knowledge_checked 存在，放行                   │
│  c) 失败 → record_failure()                                   │
│  d) 失败 3 次 → should_trigger_rag() → 重新获取知识           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 6: 识别 Flag                                           │
│  curl '...include=/var/log/nginx/access.log'                  │
│  User-Agent: <?php system($_GET['cmd']); ?>                   │
│  → 写入日志 → 包含日志 → RCE 成功                             │
│  → cat /var/www/html/flag.php → CTF{...}                     │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 7: 保存结果                                             │
│  set_flag('CTF{...}', 'nginx_log_ua_injection')               │
│  → 写入 state.json (flag 字段)                                │
│  → 自动调用 save_experience() → memories/experiences/lfi.md   │
│  → 更新 memories/experiences/_index.md                       │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  完成                                                         │
│  输出: FLAG{php_access_l0g_lf1_is_fun}                        │
└──────────────────────────────────────────────────────────────┘
```

---

## 五、Hook 检查流程（细节）

```
用户执行 Bash 命令
        │
        ▼
┌───────────────────────────────────────────┐
│ PreToolUse Hook 触发                       │
│ C:/Users/Administrator/Envs/CTFagent/Scripts/python.exe check_knowledge_hook.py            │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│ 读取 workspace/state.json                  │
│ - 有状态 → 提取 target/type/flag          │
│ - 无状态 → 返回空上下文（不阻断）           │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│ 读取 workspace/failures.json               │
│ - 提取最近 5 条失败记录                    │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│ 扫描可用知识文件                           │
│ - skills/*/SKILL.md                       │
│ - memories/experiences/*.md               │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│ 生成上下文建议                             │
│ - 无状态 → "请先用 curl 访问目标"          │
│ - 有状态无 flag → "Flag 未找到，继续尝试"  │
│ - 已找到 flag → "任务完成"                 │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│ 返回 additionalContext                    │
│ {                                          │
│   "continue": True,                       │
│   "additionalContext": "【当前状态】..."    │
│ }                                          │
└───────────────────────────────────────────┘
        │
        ▼
    LLM 自主决策下一步
```

---

## 六、知识流转示意

```
                    ┌─────────────────┐
                    │   用户输入 URL   │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │ get_all_type_knowledge('lfi')│
              └──────────────┬───────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ skills/lfi/   │  │ memories/       │  │ wooyun/knowledge/│
│ SKILL.md      │  │ experiences/    │  │ file-traversal.md│
│               │  │ lfi.md          │  │                  │
│ - LFI 方法    │  │ - 历史成功经验  │  │ - 类似题目案例   │
│ - Payload     │  │ - 成功方法      │  │ - WooYun 漏洞库  │
│ - bypass 技巧 │  │ - Flag 位置    │  │                  │
└───────────────┘  └─────────────────┘  └──────────────────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │ RAG 检索结果
                             ▼
              ┌──────────────────────────────┐
              │ format_knowledge_results()   │
              │ 格式化输出 → LLM 上下文        │
              └──────────────────────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │ LLM 基于知识制定攻击计划       │
              └──────────────────────────────┘
```

---

## 七、文件用途速查表

| 文件/目录 | 用途 | 生命周期 |
|-----------|------|---------|
| `workspace/state.json` | 当前解题状态 | 题目开始时创建，flag 找到后保留 |
| `workspace/failures.json` | 失败方法记录 | 题目开始时创建/覆写 |
| `workspace/.knowledge_checked` | 知识已检查标记 | 标记后 30 分钟过期 |
| `workspace/.knowledge_log` | 知识调用日志 | 每次调用追加 |
| `memories/experiences/<type>.md` | 成功经验（按题型） | 永久积累 |
| `skills/<type>/SKILL.md` | 技能知识（人工维护） | 手动更新 |
| `wooyun/knowledge/` | WooYun 技术手册 | 外部导入 |
| `wooyun/plugins/wooyun-legacy/` | 精简案例库 | 外部导入 |

---

## 八、题型支持矩阵

| 题型 | Skill | Experience | WooYun 类别 | 典型攻击方法 |
|------|-------|------------|-------------|-------------|
| RCE | rce | rce | command-execution | 命令注入、代码执行、模板注入 |
| SQLi | sqli | sqli | sql-injection | Union、盲注、报错注入 |
| LFI | file-inclusion | lfi | file-traversal | 日志包含、session 包含 |
| Upload | upload | file_upload | file-upload | 图片马、双扩展名、.htaccess |
| XSS | xss | - | xss | 弹窗、cookie 窃取、钓鱼 |
| Auth | auth-bypass | php-bypass | unauthorized-access | JWT 伪造、session 劫持 |
| SSRF | ssrf | - | ssrf | URL 读取、端口扫描 |
| SSTI | ssti | - | - | Jinja2/Twig 模板注入 |
| Deserialize | deserialization | - | - | 反序列化 payload |

---

## 九、编码问题处理

Windows MSYS2 环境下的特殊处理：

```python
# 检测逻辑
msystem = os.environ.get('MSYSTEM', '')
if 'MINGW' in msystem or 'MSYS' in msystem:
    return 'utf-8'  # 实际终端支持 UTF-8

# sys.stdout.encoding 可能返回 'gbk'（误判）
# 但 stdout.buffer 支持 UTF-8

# 解决方案：safe_print()
if needs_utf8_buffer:
    sys.stdout.buffer.write(encoded_utf8)  # 直接写 buffer
else:
    sys.stdout.write(safe_text)  # 正常输出
```



---

## 十、已升级功能

### 1. LoopDetector 签名级循环检测

**文件**: `core/loop_detector.py`

通过追踪工具调用签名（tool_name + args），检测重复执行：
- 签名格式：`tool_name:args_json[:500]`
- warn_threshold=3，break_threshold=5
- 状态持久化到 `workspace/.loop_state.json`

**Hook 集成**: `check_knowledge_hook.py` 在每次 Bash 命令前调用，警告信息注入 `additionalContext`

### 2. Skills 决策策略

每个 SKILL.md 顶部添加三层推理框架：

```markdown
## 决策策略

### 三层推理
- **fact**: 直接观察到的行为
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击

### 切换规则
探针无效果时，换方向重新分析
```

### 3. LLM 智能经验保存

**文件**: `core/llm_client.py`, `core/experience_manager.py`

使用 LLM 自动生成高质量经验：

**特性**:
- **智能去重**: 判断新技术/相同技术/相同 flag
- **高质量格式**: 自动生成标准 Markdown，包含原理分析、Payload、适用场景
- **自动标签**: 根据解题信息提取相关标签

**配置** (`config.json`):
```json
{
  "llm": {
    "api_url": "https://mydamoxing.cn",
    "api_key": "sk-xxx",
    "model": "MiniMax-M2.7-highspeed",
    "provider": "claude"
  }
}
```

**API**:
```python
from core.llm_client import configure, call_llm, is_configured
from core.experience_manager import save_experience_with_llm

# 初始化
configure(api_url, api_key, model)

# 保存经验
result = save_experience_with_llm(
    target="https://example.com",
    challenge_type="lfi",
    flag="CTF{...}",
    method_succeeded="php://filter读取db.php",
    payload_context="..."
)
```

