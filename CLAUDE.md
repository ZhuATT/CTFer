# CTF Agent - 项目指令

## 项目概述

全自动CTF解题Agent，Claude自主解题直到获得flag。

**核心特点**：
- Claude作为大脑，自主决策解题流程
- 双记忆系统：短期记忆(单题) + 长期记忆(跨题经验)
- Windows本地执行(CTFagent虚拟环境)
- 全自动解题：用户给题目→Agent解题→遇到困难才求助

## 执行环境

| 环境 | 路径 |
|------|------|
| Python | `C:\Users\Administrator\Envs\CTFagent\Scripts\python.exe` |

**重要**：所有Python命令必须使用CTFagent虚拟环境

## 核心文件

| 文件 | 用途 |
|------|------|
| `tools.py` | 主入口：执行工具 + 记忆系统 |
| `short_memory.py` | 短期记忆：防重复、追踪状态 |
| `long_memory.py` | 长期记忆自动检索系统 |
| `long_memory/experiences/` | 手动经验(用户提供) |
| `long_memory/auto_experiences/` | 自动经验(AI保存) |
| `long_memory/cve_pocs/` | CVE POC库(用户提供) |
| `skills/` | 漏洞知识库(SKILL.md) |
| `toolkit/` | 工具封装(sqlmap,dirsearch,fenjing) |

## 快速开始

```python
# 1. 初始化题目
from tools import init_problem
init_problem(
    target_url="http://target.com/test.php?id=1",
    description="SQL注入测试",
    hint="使用union select"
)

# 2. Agent自动解题...
# 3. flag获取后自动保存经验
```

## 核心API

### 记忆系统
```python
from tools import *

reset_memory()           # 重置短期记忆
get_memory()             # 获取ShortMemory实例
get_memory_summary()     # 获取解题状态摘要
has_tried(tool, target)  # 检查是否已尝试
check_flag()             # 检查是否获得flag(自动保存经验)
```

### 长期记忆
```python
load_long_memory("experiences", "sqli")  # 加载经验
save_long_memory("experiences", "name", content)  # 保存
list_long_memory()  # 列出所有记忆
```

### 执行工具
```python
execute_command("nmap -sV target.com", timeout=120)  # Shell命令
execute_python_poc("print('test')", timeout=30)  # Python POC
sqlmap_scan_url("http://target/?id=1")  # SQLMap扫描
quick_dir_scan("http://target/")  # 目录扫描
extract_flags(text)  # 提取flag
```

### RAG 漏洞知识库检索
```python
# 解题过程中主动检索知识（推荐）
retrieve_rag_knowledge(
    query="如何绕过WAF",        # 当前问题
    vuln_type="sqli",           # 漏洞类型
    attempted_methods=["union select"]  # 已尝试的方法
)

# 获取当前题目可用的所有资源
get_available_resources()  # 返回 POC列表、经验、WooYun知识
```
**说明**：- init_problem() 初始化时会自动加载资源- 解题过程中遇到困难可调用 retrieve_rag_knowledge() 主动检索- WooYun 知识库包含 979 条真实漏洞案例

### SSTI工具
```python
fenjing_generate_payload("id")  # 生成绕过WAF的SSTI payload
fenjing_crack_form(url, inputs="name", command="id")  # 攻击表单
fenjing_scan(url)  # 扫描SSTI漏洞
```

## 自动识别类型

支持：`sqli`, `xss`, `lfi`, `rce`, `ssrf`, `upload`, `auth`, `deserialization`, `awdp`

init_problem() 会自动识别并加载对应POC/经验

## Skills知识库

位置: `skills/<type>/SKILL.md`

可用: sqli, xss, rce, file-inclusion, ssrf, auth-bypass, web-recon, decoder, deserialization, ssti, upload, **awdp**

## 用户偏好

1. **全自动解题** - Agent自动识别类型并加载POC/经验，Claude自主解题直到拿到flag
2. **遇到困难才求助** - 关键攻击被阻断、工具配置问题、3种方法失败、需特殊POC时求助
3. **POC由用户提供** - cve_pocs/目录中的POC由用户放入
4. **经验自动保存** - 解题成功后自动保存到auto_experiences/
5. **Windows本地** - CTFagent虚拟环境，无Docker/Kali

## ⚠️ Claude Code 解题入口约束（必须遵守）

**当用户在 Claude Code 中提供题目 URL / hint / description / source code 请求解题时，必须默认走项目级唯一主链入口，不得绕过。**

### 默认入口
```python
from orchestrator import orchestrate_challenge

result = orchestrate_challenge(
    url="http://target.com",
    hint="...",
    description="..."
)
```

或使用 CLI：
```bash
python main.py --url "http://target.com" --hint "..." --description "..."
```

### 角色分工
- **Claude Code**：交互层 / HITL / 控制面
- **orchestrator**：项目级唯一执行入口
- **AutoAgent.run_main_loop()**：主链内部自动解题循环

### 禁止行为
- ❌ 用户一给题目就直接从零散 `tools.py` 工具开始攻击
- ❌ 把 `AutoAgent.solve_challenge()` 作为 Claude Code 默认入口
- ❌ 绕过 orchestrator，自己临时拼接“初始化 → 攻击”流程

### 允许例外
仅在以下场景允许绕过主链：
- 调试主链本身
- 编写/修复单元测试
- 修复 `orchestrator.py`、`main.py`、`agent_core.py` 的底层问题

## ⚠️ 强制解题流程（必须遵守）

**在开始攻击前，必须按顺序执行：**

### 第1步：初始化并识别类型
```python
from tools import init_problem, get_available_resources
result = init_problem(target_url="...", description="...")
```

### 第2步：检索知识库（强制）
**识别到类型后，必须立即读取对应的SKILL.md：**
```python
# 方法1：使用get_available_resources获取所有资源
resources = get_available_resources()

# 方法2：直接读取skills知识库
from tools import load_long_memory
skill = load_long_memory("skills", "sqli")  # 替换sqli为实际类型
print(skill)
```

### 第3步：遇到困难时主动检索
```python
# 当常规方法失败时，主动检索知识
retrieve_rag_knowledge(
    query="如何绕过select过滤",
    vuln_type="sqli",
    attempted_methods=["union select", "报错注入"]
)
```

**禁止行为**：
- ❌ 不检索知识就直接开始攻击
- ❌ 忽略init_problem()返回的资源信息
- ❌ 遇到困难不主动检索知识库

## 注意事项

1. 短期记忆在会话中持续，题目结束自动清除
2. 工具执行自动记录到短期记忆，防重复
3. CVE POC需放入 `long_memory/cve_pocs/<type>/`
4. POC索引在 `long_memory/cve_pocs/cve_index.json`
5. 编码问题：使用ASCII安全字符，避免中文Unicode