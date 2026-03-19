# BUUCTF_Agent 架构参考文档

## 项目概述

BUUCTF_Agent 是一个功能完整的 CTF 自动化解题 Agent，采用**配置驱动 + 插件化工具**架构，支持本地/MCP 工具混合、RAG 知识检索、检查点恢复等高级特性。

---

## 核心架构设计

### 1. 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│  Workflow (工作流编排)                                       │
│  - 题目预处理 (summary_problem)                              │
│  - 检查点管理 (CheckpointManager)                            │
│  - Flag 提交确认 (confirm_flag_callback)                     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  SolveAgent (核心解题引擎)                                   │
│  - 主循环: think → execute → analyze → memory               │
│  - 自动/手动模式切换                                         │
│  - 反思机制 (reflection)                                     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  Tools (工具层)                                              │
│  - BaseTool 抽象接口                                         │
│  - 本地工具 (Python/SSH) - 全量注入                          │
│  - MCP 工具 - RAG 检索注入                                   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  Memory + RAG (记忆与知识)                                   │
│  - 分层记忆: 详细历史 + 压缩记忆 + 关键事实                   │
│  - 知识库: 工具用法、解题模式                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 关键设计亮点

### 1. 工具系统设计

#### BaseTool 抽象接口
```python
class BaseTool(ABC):
    @abstractmethod
    def execute(self, *args, **kwargs) -> str:
        """执行工具操作"""
        pass

    @property
    @abstractmethod
    def function_config(self) -> Dict:
        """返回工具的函数调用配置 (OpenAI Function Calling 格式)"""
        pass
```

#### 本地工具 vs MCP 工具区分策略
| 类型 | 加载方式 | 使用场景 |
|------|----------|----------|
| 本地工具 | 全量注入 Prompt | Python执行、SSH命令等核心工具 |
| MCP 工具 | RAG 检索注入 | 外部服务、可选工具 |

**RAG 工具检索实现**:
- 工具描述向量化缓存 (`tool_embeddings_cache.json`)
- 余弦相似度匹配
- 动态 Top-K 选择

```python
def recommend_tools(self, query: str, top_k: int = 3) -> List[Dict]:
    # 本地工具全量返回 + MCP 工具相似度检索
    query_embedding = self._get_embedding(query)
    # ... 相似度计算
    return self.local_function_configs + top_mcp_tools
```

---

### 2. 记忆系统设计

#### 三层记忆架构

```python
class Memory:
    def __init__(self, max_steps=15, compression_threshold=7):
        self.history: List[Dict]           # 详细历史记录
        self.compressed_memory: List[Dict] # LLM 压缩后的记忆块
        self.key_facts: Dict[str, str]     # 结构化关键事实
        self.failed_attempts: Dict[str, int]  # 失败次数追踪
```

#### 自动记忆压缩
- 触发条件: 历史步骤数 >= compression_threshold
- 压缩方式: 调用 LLM 提取关键发现、失败尝试、当前状态、建议步骤
- 保留策略: 压缩后保留最近 4 步详细记录

```python
def compress_memory(self) -> None:
    prompt = """
    你是一个CTF解题助手，需要压缩解题历史记录...
    返回JSON格式: {
        "key_findings": [...],
        "failed_attempts": [...],
        "current_status": "...",
        "next_steps": [...]
    }
    """
    # ... 调用 LLM 压缩
```

---

### 3. 主循环设计

#### SolveAgent.solve() 核心循环

```python
def solve(self, resume_step: int = 0) -> str:
    while True:
        step_count += 1

        # 1. 生成下一步 (思考 + 工具调用规划)
        think, tool_calls = self.next_instruction()

        # 2. 手动模式确认
        if not self.auto_mode:
            approved, (think, tool_calls) = self.manual_approval_step(...)

        # 3. 记录计划
        self.memory.add_planned_step(step_count, think, tool_calls)

        # 4. 执行所有工具
        for tool_call in tool_calls:
            result = self.tools[tool_name].execute(tool_name, arguments)

        # 5. LLM 分析输出
        analysis = self.analyzer.analyze_step_output(...)

        # 6. 检查 Flag
        if analysis.get("flag_found"):
            if self.confirm_flag_callback(flag):
                return flag

        # 7. 更新记忆 & 保存检查点
        self.memory.update_step(step_count, {...})
        self.checkpoint_manager.save(...)

        # 8. 检查终止条件
        if analysis.get("terminate"):
            break
```

#### 反思机制 (Reflection)
当用户在手动模式提供反馈时，Agent 可以重新思考:
```python
def reflection(self, think: str, feedback: str) -> Tuple[str, List[Dict]]:
    # 基于原计划和用户反馈，重新生成思考内容和工具调用
    prompt = template.render(
        original_purpose=think,
        feedback=feedback,
        ...
    )
```

---

### 4. 检查点恢复机制

#### CheckpointManager
```python
class CheckpointManager:
    def save(self, problem, step_count, auto_mode, memory_data):
        # 保存到 checkpoints/{problem_hash}.json

    def load_any(self) -> Optional[Dict]:
        # 列出所有检查点，让用户选择恢复

    def restore_from_checkpoint(self, data: dict) -> int:
        self.memory.restore_from_dict(data["memory"])
        return data["step_count"]  # 返回恢复后的步骤数
```

---

### 5. 工具输出处理

#### 多工具输出摘要
当多个工具同时执行时，使用 LLM 总结输出:
```python
@staticmethod
def output_summary(tool_results: List[Dict], think: str, tool_output: str) -> str:
    if len(tool_output) <= 1024:
        return tool_output  # 短输出直接返回

    prompt = f"""
    你是一个CTF解题助手，总结多个工具执行后的输出。
    要求：
    1. 保留关键信息（路径、端点、漏洞线索）
    2. 移除冗余信息（重复日志、调试信息）
    3. 说明多个工具输出之间的关联

    执行思路: {think}
    工具调用详情: {tool_details}
    合并原始输出: {combined_output}
    """
```

---

### 6. 配置驱动设计

#### config.json 结构
```json
{
    "llm": {
        "analyzer": {...},      // 分析模型
        "solve_agent": {...},   // 解题模型
        "embedding": {...},     // 向量模型
        "pre_processor": {...}  // 预处理模型
    },
    "tool_config": {
        "ssh_shell": {"host": "...", "port": 22, ...},
        "python": {"remote": true, "ssh": {...}}
    },
    "mcp_server": {
        "server_name": {"url": "...", "tools": [...]}
    },
    "max_history_steps": 10,
    "compression_threshold": 5
}
```

---

## 可借鉴的设计模式

### 1. 工具自动发现与加载
```python
def load_tools(self) -> Tuple[Dict, List]:
    # 1. 扫描 ctf_tool/ 目录
    # 2. 自动导入继承 BaseTool 的类
    # 3. 提取 function_config
    # 4. 支持配置参数注入
```

### 2. 向量缓存机制
- 工具描述变更检测 (MD5 hash)
- 本地缓存避免重复 Embedding
- 自动更新策略

### 3. 用户交互抽象
```python
class UserInterface(ABC):
    @abstractmethod
    def select_mode(self) -> bool: ...  # 自动/手动

    @abstractmethod
    def manual_approval_step(self, think, tool_calls) -> Tuple[bool, Any]: ...

    @abstractmethod
    def confirm_resume(self) -> bool: ...
```
支持命令行和 WebUI 两种实现

### 4. 平台抽象层
```python
class QuestionInputer(ABC):    # 题目获取
class FlagSubmitter(ABC):      # Flag 提交

# 支持文件输入、BUUCTF API、手动输入等多种方式
```

---

## 与当前项目的对比建议

| 特性 | BUUCTF_Agent | 当前项目 | 建议 |
|------|-------------|----------|------|
| 工具系统 | BaseTool + 自动发现 | 函数式工具 | 可引入 BaseTool 接口 |
| 记忆压缩 | LLM 自动压缩 | 简单截断 | 引入压缩机制 |
| 工具检索 | RAG 向量检索 | 直接调用 | 工具多时可引入 RAG |
| 检查点 | 完整支持 | 无 | 高优先级实现 |
| MCP 支持 | 完整支持 | 无 | 可选增强 |
| 配置驱动 | config.json | 代码配置 | 可引入配置分离 |

---

## 核心文件参考

| 文件 | 职责 | 可借鉴内容 |
|------|------|-----------|
| `agent/solve_agent.py` | 主解题循环 | 循环设计、反思机制 |
| `agent/memory.py` | 记忆管理 | 三层记忆、压缩策略 |
| `ctf_tool/base_tool.py` | 工具接口 | 抽象设计 |
| `ctf_tool/python.py` | Python执行 | 本地/远程执行 |
| `utils/tools.py` | 工具管理 | 自动发现、RAG检索 |
| `agent/checkpoint.py` | 检查点 | 保存/恢复机制 |
| `rag/knowledge_base.py` | 知识库 | RAG 封装 |
