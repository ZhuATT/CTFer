# CTF Agent 优化方案

## 借鉴 BUUCTF_Agent 的核心改进

### 1. 检查点机制 (Checkpoint)

**场景**: Claude Code 对话可能中断，需要支持从断点恢复

```python
# checkpoint.py - 新增
class CheckpointManager:
    """解题状态检查点管理"""

    def save(self, problem_id: str, memory: Memory, current_step: int)
    def load(self, problem_id: str) -> Optional[Dict]
    def list_checkpoints() -> List[Dict]  # 列出所有可恢复的检查点
```

**Claude 交互集成**:
```
用户: "继续上次的题目"
Claude: 检测到检查点 "web-challenge-001", 已执行 15 步, 最后操作: SQL注入测试
      是否恢复? (y/n)
```

---

### 2. 智能记忆压缩

**当前问题**: `memory.py` 只是简单截断旧记录

**改进**: 借鉴 BUUCTF_Agent 的 LLM 压缩

```python
# memory.py - 增强
class Memory:
    def __init__(self, max_history=20, compression_threshold=10):
        self.history: List[Step]           # 详细历史
        self.compressed_blocks: List[Dict] # LLM 压缩后的记忆块
        self.key_facts: KeyFacts           # 结构化事实

    def compress_memory(self):
        """调用 LLM 智能压缩历史"""
        prompt = """
        压缩以下 CTF 解题历史，提取：
        1. 关键发现（IP、端口、端点、漏洞线索）
        2. 已尝试但失败的方法
        3. 当前状态评估
        4. 下一步建议

        返回 JSON: {"key_findings": [], "failed_attempts": [], "status": "", "suggestions": []}
        """
```

---

### 3. 工具封装系统 (Toolkit)

**目标**: 像 Skill 一样方便调用 sqlmap、fengjing、dirsearch

```
toolkit/
├── __init__.py
├── base.py          # ToolBase 抽象类
├── registry.py      # 工具注册与发现
├── sqlmap.py        # SQLMap 封装
├── fengjing.py      # 指纹识别
├── dirsearch.py     # 目录扫描
└── nmap.py          # 端口扫描
```

**使用方式**:
```python
from toolkit import sqlmap, fengjing, dirsearch

# 方式1: 简单调用
result = sqlmap.scan("http://target.com/page.php?id=1", level=3)

# 方式2: 高级配置
scanner = sqlmap.SQLMap(
    url="http://target.com/page.php?id=1",
    level=5,
    risk=3,
    tamper="space2comment",
    threads=10
)
result = scanner.run()

# 方式3: Claude 直接调用 (通过 tools.py 集成)
execute_tool("sqlmap", url="http://target.com/page.php?id=1", level=3)
```

---

### 4. 配置分离

**当前**: 配置硬编码在 `core/constants.py`

**改进**: `config.json` + 环境变量覆盖

```json
{
    "memory": {
        "max_history": 20,
        "compression_threshold": 10,
        "auto_compress": true
    },
    "tools": {
        "docker": {
            "container": "kali-sandbox",
            "timeout": 120
        },
        "microsandbox": {
            "name": "ctf-sandbox",
            "timeout": 60
        }
    },
    "checkpoints": {
        "enabled": true,
        "auto_save_interval": 5,
        "directory": "./checkpoints"
    },
    "llm": {
        "compression_model": "gpt-4o-mini",
        "analysis_model": "claude-sonnet"
    }
}
```

---

### 5. 反思机制 (Reflection)

**场景**: 连续失败时，让 Claude 重新思考策略

```python
# 新增 reflection.py
class ReflectionEngine:
    """失败时重新评估策略"""

    def should_reflect(self, memory: Memory) -> bool:
        """检查是否需要反思"""
        # 条件1: 同一方法失败 3 次
        # 条件2: 连续 5 步无进展
        # 条件3: 用户主动要求
        pass

    def reflect(self, memory: Memory) -> Dict:
        """生成新的攻击策略"""
        prompt = """
        基于以下失败历史，重新评估攻击策略：
        - 已尝试的方法及失败原因
        - 可能遗漏的攻击面
        - 新的攻击思路

        返回: {"new_strategy": "", "priority": [], "reasoning": ""}
        """
```

---

### 6. 增强的记忆摘要

**当前**: 简单的文本列表

**改进**: 结构化输出 + 关键发现高亮

```python
def get_summary(self, format="claude") -> str:
    """为 Claude 优化的记忆摘要"""

    if format == "claude":
        return """
        📊 关键发现
        ├── 目标: 192.168.1.10:80
        ├── 技术栈: Apache, PHP, MySQL
        ├── 端点: /login, /admin, /api/users
        └── 疑似漏洞: SQL注入 (login 页面)

        ⚠️ 失败尝试 (避免重复)
        ├── 目录爆破 (gobuster) - 未发现隐藏目录
        └── 简单单引号注入 - 被 WAF 拦截

        💡 建议下一步
        1. 尝试 SQLMap 的 tamper 脚本绕过 WAF
        2. 检查 /api/users 的 IDOR 漏洞
        3. 查看 admin 页面是否存在默认凭证

        📜 最近 3 步
        ...
        """
```

---

## 实施优先级

| 优先级 | 功能 | 工作量 | 影响 |
|--------|------|--------|------|
| P0 | 工具封装 (Toolkit) | 中 | 大幅提升使用便利性 |
| P1 | 检查点机制 | 中 | 支持长任务断点恢复 |
| P2 | 智能记忆压缩 | 中 | 解决长对话上下文问题 |
| P3 | 配置分离 | 低 | 提升可维护性 |
| P4 | 反思机制 | 高 | 提升解题成功率 |

---

## 与 Claude Code 的集成点

### 1. 检查点恢复
```
用户: @ctf-agent 继续解题
Claude: 🔍 发现 2 个检查点:
       1. [web-2024-03-15] SQL注入测试 - 第 12 步
       2. [pwn-2024-03-14] 栈溢出分析 - 第 8 步
       选择要恢复的检查点 (1/2/n):
```

### 2. 工具调用
```
用户: 用 sqlmap 扫描这个注入点
Claude: 🚀 启动 SQLMap 扫描
       URL: http://target.com/page.php?id=1
       参数: --level=3 --batch

       [执行中...]

       ✅ 扫描完成
       发现: MySQL 5.7, 可 UNION 注入
       建议: 使用 --dump 获取数据
```

### 3. 记忆查询
```
用户: 我之前发现了什么？
Claude: 📊 当前题目关键信息:
       - 目标: http://192.168.1.10
       - 开放端口: 80, 3306
       - 发现端点: /login, /admin
       - 已尝试: 目录爆破 (无果), SQL注入 (进行中)
       - 失败记录: 简单密码爆破失败 3 次
```
