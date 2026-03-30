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
│     skills/<type>/SKILL.md     ← 技能知识（优化精简）       │
│     memories/experiences/<>.md  ← 成功经验（自动积累）     │
│     wooyun/                  ← 原材料库（不参与 RAG）     │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  3. 攻击执行                                            │
│     - curl / sqlmap / dirsearch                         │
│     - FailureTracker 记录失败                            │
└─────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  4. 状态持久化                                          │
│     workspace/state.json      ← 当前解题状态               │
│     workspace/failures.json   ← 失败记录                 │
│     workspace/.knowledge_log  ← 知识调用日志              │
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
│   └── settings.json            ← Claude Code 配置（Hook/权限）

├── core/                        ← 核心模块
│   ├── state_manager.py         ← 解题状态管理
│   ├── rag_knowledge.py       ← RAG 知识检索（experiences + skills）
│   ├── skill_loader.py          ← Skill 加载器
│   ├── experience_manager.py    ← 经验保存管理
│   ├── failure_tracker.py       ← 失败追踪
│   ├── loop_detector.py         ← 循环检测（签名级）
│   └── llm_client.py           ← LLM 客户端（经验智能保存）

├── skills/                      ← 技能知识（优化精简）
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
├── wooyun/                      ← 原材料库（不参与 RAG）
│   ├── knowledge/               ← 技术手册
│   ├── categories/             ← 案例分类
│   ├── examples/              ← 渗透示例
│   └── plugins/
│       └── wooyun-legacy/     ← 精简版（原材料）
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

### 3.1 Hook 机制（已移除）

**状态**: check_knowledge_hook.py 已删除

**替代机制**:

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

### 3.2 RAG 知识检索（rag_knowledge.py）

**检索来源（按优先级）**:
1. `memories/experiences/<type>.md` — 历史成功经验（最高）
2. `skills/<type>/SKILL.md` — 题型技能知识
3. ~~wooyun/knowledge/<category>.md~~ — **已移除，不参与 RAG**
4. ~~wooyun/plugins/wooyun-legacy/categories/~~ — **已移除，不参与 RAG**

**wooyun 新定位**: 作为"原材料库"，按需提炼到 experiences/skills，不直接参与 RAG 检索

**检索流程**:
```
用户查询 → 同义词扩展 → 中文分词 (jieba) → TF-IDF 余弦相似度 → sort_by_type_priority() → 返回 top_k 结果
```

**sort_by_type_priority() 排序逻辑**:
```
1. experiences 同题型（最高）
2. skills 同题型
3. experiences 跨题型
4. skills 跨题型
```

**题型 → 类别映射**:
| 题型 | 映射类别 |
|------|---------|
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
│  → RAG 检索 experiences + skills（wooyun 已移出）            │
│  → 格式化输出作为解题上下文                                    │
│  → 写入 .knowledge_log                                       │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 4: 基于知识制定攻击计划                                  │
│  根据返回的知识：                                              │
│  - skills/file-inclusion/SKILL.md → 日志文件包含方法          │
│  - memories/experiences/lfi.md → 历史成功经验                 │
│  → 确定攻击向量：nginx access.log + User-Agent 注入           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  Step 5: 执行攻击                                             │
│  a) curl 目标页面，尝试 LFI                                   │
│  b) 失败 → record_failure()                                   │
│  c) 失败 3 次 → 重新获取知识                                 │
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

## 五、知识流转示意

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
        ┌────────────────────┴────────────────────┐
        │                                         │
        ▼                                         ▼
┌───────────────┐                       ┌─────────────────┐
│ skills/lfi/   │                       │ memories/       │
│ SKILL.md      │                       │ experiences/    │
│               │                       │ lfi.md          │
│ - LFI 方法    │                       │ - 历史成功经验  │
│ - Payload     │                       │ - 成功方法      │
│ - bypass 技巧 │                       │ - Flag 位置    │
└───────────────┘                       └─────────────────┘
        │                                         │
        └────────────────────┬────────────────────┘
                             │ sort_by_type_priority()
                             ▼
              ┌──────────────────────────────┐
              │ format_structured_output()    │
              │ 格式化输出 → LLM 上下文       │
              └──────────────────────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │ LLM 基于知识制定攻击计划       │
              └──────────────────────────────┘

【wooyun 定位调整】
wooyun/ 现作为"原材料库"，不参与 RAG 检索
按需提炼 → experiences/ 或 skills/
```

---

## 七、文件用途速查表

| 文件/目录 | 用途 | 生命周期 |
|-----------|------|----------|
| `workspace/state.json` | 当前解题状态 | 题目开始时创建，flag 找到后保留 |
| `workspace/failures.json` | 失败方法记录 | 题目开始时创建/覆写 |
| `workspace/.knowledge_checked` | 知识已检查标记 | 标记后 30 分钟过期 |
| `workspace/.knowledge_log` | 知识调用日志 | 每次调用追加 |
| `memories/experiences/<type>.md` | 成功经验（按题型） | 永久积累 |
| `skills/<type>/SKILL.md` | 技能知识（优化精简） | 手动更新 |
| `wooyun/` | 原材料库（不参与 RAG） | 按需提炼 |

---

## 八、题型支持矩阵

| 题型 | Skill | Experience | 典型攻击方法 |
|------|-------|------------|--------------|
| RCE | rce | rce | 命令注入、代码执行、模板注入 |
| SQLi | sqli | sqli | Union、盲注、报错注入 |
| LFI | file-inclusion | lfi | 日志包含、session 包含 |
| Upload | upload | file_upload | 图片马、双扩展名、.htaccess |
| XSS | xss | - | 弹窗、cookie 窃取、钓鱼 |
| Auth | auth-bypass | php-bypass | JWT 伪造、session 劫持 |
| SSRF | ssrf | - | URL 读取、端口扫描 |
| SSTI | ssti | - | Jinja2/Twig 模板注入 |
| Deserialize | deserialization | - | 反序列化 payload |

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

### 1. RAG 知识检索优化

**wooyun 移出 RAG**: 作为"原材料库"，不参与日常 RAG 检索

**检索来源调整**:
- `memories/experiences/<type>.md` — 历史成功经验（最高）
- `skills/<type>/SKILL.md` — 题型技能知识

**sort_by_type_priority()**: 确保同题型 experiences/skills 优先排序

### 2. Skills 格式优化

**优化内容**:
- 移除 frontmatter (`---name/description/allowed-tools---`)
- 移除 `来自外部导入内容` 标记和章节
- 保留核心方法论结构
- 保留代码块/payloads
- 保留绕过技术

**已优化文件**: rce, sqli, file-inclusion, upload, auth-bypass, ssrf, xss, ssti, deserialization, recon, web-recon

### 3. LoopDetector 签名级循环检测

**文件**: `core/loop_detector.py`

通过追踪工具调用签名（tool_name + args），检测重复执行：
- 签名格式：`tool_name:args_json[:500]`
- warn_threshold=3，break_threshold=5
- 状态持久化到 `workspace/.loop_state.json`

### 4. LLM 智能经验保存

**文件**: `core/llm_client.py`, `core/experience_manager.py`

使用 LLM 自动生成高质量经验：

**特性**:
- **智能去重**: 判断新技术/相同技术/相同 flag
- **高质量格式**: 自动生成标准 Markdown，包含原理分析、Payload、适用场景
- **自动标签**: 根据解题信息提取相关标签

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

