# CTF Agent

全自动CTF解题Agent，Claude作为决策大脑，自主识别漏洞类型并执行攻击直到获得flag。

## 核心特性

- **全自动解题**: Claude自主决策解题流程，无需人工干预直到成功或明确失败
- **双记忆系统**:
  - 短期记忆：单题目内防重复、追踪解题状态
  - 长期记忆：跨题目积累经验，自动检索和应用历史POC
- **智能知识库**: 集成WooYun真实漏洞案例，RAG检索辅助决策
- **多Agent协作**: 侦察Agent、分析Agent、攻击Agent分工配合
- **AWD攻防支持**: 支持Attack/Defense双模式，自动代码审计和漏洞修复

## 支持的漏洞类型

| 类型 | 说明 | 检测方式 |
|------|------|----------|
| `sqli` | SQL注入 | sqlmap扫描 + 手工注入 |
| `lfi` | 本地文件包含 | 路径遍历测试 |
| `rce` | 远程代码执行 | 命令执行检测 |
| `ssrf` | 服务端请求伪造 | 内网探测、协议测试 |
| `xss` | 跨站脚本攻击 | 反射型/DOM型检测 |
| `upload` | 文件上传漏洞 | 后缀绕过、内容检测 |
| `auth` | 认证绕过/越权 | 会话测试、逻辑绕过 |
| `deserialization` | 反序列化漏洞 | PHP/Java/Python |
| `ssti` | 模板注入 | SSTI payload生成 |
| `xxe` | XML外部实体 | DTD注入测试 |
| `awdp` | AWD攻防模式 | 代码审计+自动修复 |

## 快速开始

### 环境配置

**必需环境:**
- Python 3.8+
- Windows本地执行环境
- CTFagent虚拟环境

**配置虚拟环境:**
```bash
# 使用mkvirtualenv创建虚拟环境
mkvirtualenv CTFagent

# 激活环境
workon CTFagent

# 安装依赖
pip install requests beautifulsoup4
```

### 基础使用

```python
from tools import init_problem, check_flag

# 1. 初始化题目
init_problem(
    target_url="http://target.com/test.php?id=1",
    description="存在SQL注入漏洞的登录页面",
    hint="尝试使用union select绕过登录"
)

# 2. Agent自动识别类型并加载相关POC/经验

# 3. 获取解题状态
from tools import get_memory_summary
print(get_memory_summary())

# 4. 检查是否获得flag
flag = check_flag()  # 获得flag后自动保存经验
```

### 自动化解题模式

```python
from agent_core import AutoAgent

# 全自动解题
agent = AutoAgent(max_steps=20)
result = agent.solve_challenge(
    url="http://target.com/vuln.php",
    hint="文件包含漏洞",
    description="可以控制文件包含路径"
)

if result["success"]:
    print(f"[*] Flag: {result['flag']}")
    print(f"[*] 用时: {result['steps']} 步")
```

## 项目结构

```
CTF_agent/
├── tools.py                 # 核心工具入口（自动记忆集成）
├── short_memory.py          # 短期记忆系统（单题防重复）
├── long_memory.py           # 长期记忆自动检索系统
├── agent_core.py            # 自动化解题Agent核心
├── config.json              # 工具配置和虚拟环境路径
│
├── long_memory/             # 长期记忆数据目录
│   ├── experiences/         # 手动经验（用户提供）
│   ├── auto_experiences/      # 自动经验（AI解题后保存）
│   │   ├── exp_index.json     # 经验索引
│   │   └── sqli/              # 按类型分类
│   └── cve_pocs/              # CVE POC库
│       ├── cve_index.json     # CVE元数据索引
│       └── sqli/              # 按类型分类
│
├── skills/                  # 漏洞知识库（SKILL.md）
│   ├── sqli/
│   ├── lfi/
│   ├── rce/
│   ├── xss/
│   ├── ssrf/
│   ├── upload/
│   ├── auth-bypass/
│   ├── deserialization/
│   ├── ssti/
│   └── awdp/
│
├── toolkit/                 # 工具封装层
│   ├── sqlmap.py            # SQLMap集成
│   ├── dirsearch.py         # 目录扫描集成
│   └── fenjing/             # SSTI工具
│
├── agents/                  # 多Agent系统
│   ├── coordination.py      # Agent协调器
│   └── recon/               # 侦察Agent
│
├── wooyun/                  # WooYun知识库
│   └── plugins/
│
└── workspace/               # 临时工作目录（自动清理）
```

## 核心API详解

### 记忆系统

```python
from tools import *

# 重置短期记忆（开始新题目时调用）
reset_memory()

# 获取记忆实例
memory = get_memory()

# 获取解题状态摘要
print(get_memory_summary())

# 检查是否已尝试过
if not has_tried("sqlmap", target_url):
    # 执行sqlmap扫描
    pass

# 检查是否获得flag（成功后自动保存经验）
flag = check_flag()
```

### 执行工具

```python
from tools import *

# 执行shell命令（自动防重复）
result = execute_command("nmap -sV target.com", timeout=120)

# 执行Python POC（自动防重复）
poc_code = """
import requests
resp = requests.get('http://target.com/?id=1\'')
print(resp.text)
"""
result = execute_python_poc(poc_code, timeout=30)

# SQLMap扫描
result = sqlmap_scan_url("http://target.com/?id=1")

# 目录扫描
result = quick_dir_scan("http://target.com/")

# HTTP请求
result = http_get("http://target.com/")
result = http_post("http://target.com/login", data={"user": "admin"})
```

### 长期记忆

```python
from tools import load_long_memory, save_long_memory

# 加载某种类型的经验
sqli_skill = load_long_memory("skills", "sqli")
print(sqli_skill)

# 保存新经验
save_long_memory("experiences", "my_sqli_exp", "绕过WAF的技巧...")
```

### RAG知识检索

```python
from tools import retrieve_rag_knowledge

# 遇到困难时主动检索知识
result = retrieve_rag_knowledge(
    query="如何绕过select过滤",
    vuln_type="sqli",
    attempted_methods=["union select", "报错注入"]
)

# 查看建议做法
print(result["suggested_approach"])
```

### SSTI工具

```python
from tools import *

# 生成绕过WAF的SSTI payload
result = fenjing_generate_payload(command="id")
print(result["payload"])

# 自动攻击表单
result = fenjing_crack_form(
    url="http://target.com/search",
    inputs="name",
    command="cat /flag"
)
```

## AWD攻防模式

```python
from tools import init_awd, switch_awd_phase, analyze_code

# 初始化AWD题目
init_awd(
    target_url="http://10.0.0.1/",
    target_code="<?php ...",  # 待分析的源码
    description="AWD攻防赛"
)

# 切换到防御阶段
switch_awd_phase("defense")

# 自动代码审计
vulns = analyze_code(php_code)
for vuln in vulns["vulnerabilities"]:
    print(f"发现 {vuln['type']} 在 {vuln['location']}")
    print(f"修复建议: {vuln['fix_suggestion']}")

# 获取修补点摘要
print(get_patch_summary())
```

## 配置说明

编辑 `config.json` 配置工具和路径：

```json
{
  "venv": {
    "name": "CTFagent",
    "path": "C:\\Users\\Administrator\\Envs\\CTFagent",
    "python_path": "C:\\Users\\Administrator\\Envs\\CTFagent\\Scripts\\python.exe"
  },
  "tools": {
    "sqlmap": { "enabled": true, "path": "sqlmap/sqlmap.py" },
    "dirsearch": { "enabled": true, "path": "dirsearch/dirsearch.py" },
    "decoder": { "enabled": true, "internal": true }
  }
}
```

## 解题流程

```
用户提供题目URL+描述
         ↓
init_problem() 初始化
         ↓
自动识别题目类型 → 加载相关POC/经验/SKILL.md
         ↓
Agent自主决策 → 执行工具 → 检查结果
         ↓
    获得flag? ──┬── 是 → 自动保存经验
         │      └── 否 → 继续尝试
         ↓
步数超限/明确失败 → 向用户求助
```

## 命令速查表

| 命令 | 功能 |
|------|------|
| `from tools import *` | 导入所有工具 |
| `init_problem(url, desc, hint)` | 初始化题目 |
| `reset_memory()` | 重置短期记忆 |
| `get_memory_summary()` | 获取解题摘要 |
| `check_flag()` | 检查flag并保存经验 |
| `execute_command(cmd)` | 执行shell命令 |
| `execute_python_poc(code)` | 执行Python POC |
| `sqlmap_scan_url(url)` | SQLMap扫描 |
| `quick_dir_scan(url)` | 快速目录扫描 |
| `extract_flags(text)` | 提取flag |
| `retrieve_rag_knowledge(...)` | 检索知识库 |

## 注意事项

1. **必须使用CTFagent虚拟环境** - 所有Python命令在虚拟环境中执行
2. **自动防重复** - 相同工具和参数会自动跳过
3. **自动保存经验** - 解题成功后自动保存到`auto_experiences/`
4. **编码安全** - 使用ASCII安全字符，避免中文Unicode问题
5. **清理工作区** - 解题成功后自动清理`workspace/`临时文件

## License

MIT
