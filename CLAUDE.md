# CTF Agent - Claude Code 直接模式解题指南

> 在 Claude Code 中，用户提供 URL/hint/source code 后，直接调用工具解题。
> `ctf_direct/` 是工具库，不是独立 Agent。

---

## 默认解题流程

用户提供靶机 URL 后，Claude Code 直接执行以下流程：

```
1. curl 访问目标 → 观察页面结构
2. 识别题型（rce/sqli/auth/lfi/xss/upload）
3. 加载技能知识：ctf_direct/skills/<type>/SKILL.md
4. 构造 payload，执行攻击
5. 识别 flag → 输出 FLAG{...}
```

**禁止**：不要先跑 `python ctf_direct/main.py`，那是一个独立的 Python 程序。

---

## 可用工具

直接在 Claude Code 中调用：

| 工具 | 用途 | 用法 |
|------|------|------|
| `curl` | HTTP 请求 | 直接在终端执行 `curl <url>` |
| `execute_python` | Python 代码执行 | 直接在终端执行 `python -c "..."` |
| `dirsearch` | 目录扫描 | 通过 `ctf_direct/tools/dirsearch_tool.py` |
| `sqlmap` | SQL 注入检测 | 通过 `ctf_direct/tools/sqlmap_tool.py` |

---

## 技能知识（ctf_direct/skills/）

解题前加载对应题型的 SKILL.md：

```
ctf_direct/skills/rce/SKILL.md       - RCE 命令注入绕过
ctf_direct/skills/sqli/SKILL.md      - SQL 注入 bypass
ctf_direct/skills/auth/SKILL.md      - 认证绕过
ctf_direct/skills/lfi/SKILL.md       - 文件包含 LFI
ctf_direct/skills/xss/SKILL.md       - XSS 绕过
ctf_direct/skills/upload/SKILL.md     - 文件上传绕过
```

加载方式：`Read` 工具读取对应文件

---

## 经验知识（ctf_direct/memories/experiences/）

```
ctf_direct/memories/experiences/rce.md      - 历史 RCE 题目解法
ctf_direct/memories/experiences/sqli.md    - 历史 SQLi 题目解法
ctf_direct/memories/experiences/*.md        - 其他题型
```

---

## RAG 知识检索

```
ctf_direct/core/rag_knowledge.py
```

用法：
```python
from ctf_direct.core.rag_knowledge import search_knowledge
results = search_knowledge("sql injection bypass", category="sqli", top_k=3)
```

---

## 独立执行模式（不使用）

`ctf_direct/main.py` 是一个独立的 Python 推理循环程序，**不在 Claude Code 直接模式中使用**。

它的存在是为了在没有 Claude Code 的环境下也能运行 CTF 解题。

---

## 约束

- 联网请求用 `curl`，不要用 `WebFetch`/`WebSearch`
- 解题时直接调用工具，不要先初始化 Python 程序
- 发现 flag 输出 `FLAG{...}` 格式
