# CTF Agent 修复计划

> **核心原则**：框架是用来加强 LLM 能力的，而不是限制 LLM 的思考能力。
> LLM 负责决策，框架负责执行并提供结构化的上下文信息。

---

## P0 - LLM 决策质量差（持续选择 recon）

### 问题描述
连续多步 AI 都选择 recon，没有基于 `taxonomy_tags` (rce/auth) 选择攻击动作。

### 根本原因
**不是 LLM 决策质量问题，而是信息断裂**：
- `recon` 执行后，结果没有结构化回填到 `memory.target`
- LLM 每次决策时看不到靶机的端点/参数/forms 信息
- LLM 在"信息真空"中决策，只能重复选择 recon 尝试获取更多信息

### 已完成的修复

**修复 1: `execute_python_poc` 路径 bug**（已完成）
- 根因：`Path(__file__).parent` 在某些情况下解析为相对路径，导致 `workspace` 计算错误
- 修复：`Path(__file__).resolve()` 确保绝对路径
- 验证：真实靶机测试确认 POC 能正确执行

**修复 2: JavaScript 路由端点提取**（已完成）
- 新增：`_execute_recon_action()` 中使用 `app.(get|post|...)(path)` 模式提取 JS 中的路由
- 效果：`/flag` 端点被正确识别并添加到 `known_endpoints`

**修复 3: href 链接提取**（已完成）
- 确认：代码中已有 `self.memory.add_endpoint(discovered)` 调用，会正确写入

### 验证结果

**真实靶机测试** (`https://c89304fc-a944-4e7b-909e-f32f3f5d2999.challenge.ctf.show/`):
- Step 1: recon 执行后，`known_endpoints=['.../', '.../flag']` ✅
- Step 2: AI 决策能看到已发现的端点，选择 dirscan 继续探测 ✅
- 端点正确传递到 LLM 决策上下文 ✅

---

## P0.5 - 重构：消除硬编码决策规则，确立 LLM 决策优先

### 状态：✅ 已完成

### 完成内容
- `_decide_next_action()` 深处 3 处 auth 硬编码分支已移除（lines 4181-4190, 4203-4212, 4242-4251）
- LLM 决策优先，框架只做 graph-informed 兜底

### 保留内容
- `_build_decision_context()` 中的 auth/sqli/ua 信号注入（正常上下文提供）
- 循环检测逻辑 `low_yield_probe_loop`、`dir_scan_stuck_loop` 等（通用安全约束）

### 问题描述
虽然 LLM 决策已放在 `_decide_next_action()` 最前面（lines 3602-3608），但当 LLM 返回 None 或框架不认可时，大量硬编码 fallback 规则（lines 3610-3792+）会强制覆盖，实质上是**框架在做决策而非 LLM**。

### 根本原因
**硬编码 if/else 规则代替了 LLM 的判断**：
- auth 类型：lines 3639-3733 包含 6 个硬编码分支（weak-creds, endpoint-enum, auth-sqli 等）
- sqli 类型：lines 3765-3786 强制先 sqlmap 再 dirscan
- 通用 fallback：lines 3735-3737 graph_action 覆盖 LLM
- dirscan 重复检测：lines 3788-3792 硬编码判断逻辑

### 参考框架架构

**1. H-Pentest 多 LLM 协作模式**
```
StrategicSupervisor（战略级）
  - 基于 preprocessing 结果生成初始测试计划
  - 不直接执行，只做高层次规划

Worker（执行级）
  - 快速决策，基于当前上下文
  - 接受 Strategic 的 plan 和 Meta 的 insights

MetaSupervisor（元认知级）
  - 每 N 轮生成一次 insights
  - 注入到 Worker 的 context 中

PayloadMaster（payload 指导）
  - 提供绕过方案，不做决策
```

**2. ctfSolver Master 协调模式**
```
FlagHunter.hunt() 主循环：
  - explorer_page()：页面探索（异步）
  - detect_page()：漏洞检测
  - poc_scan() / llm_scan()：调用 Scanner/Flagger

Master LLM（master.py）
  - 接收：请求/响应 + tool_chain + desc
  - 输出：绕过方案（XML 格式 tool 调用）
  - 核心：人类推理专家，专注于 payload 绕过
```

### 重构方案

**原则：LLM 是决策者，框架是执行器和上下文提供者**

#### 改动 1：移除硬编码 fallback 规则
将以下硬编码分支改为 LLM 可见的上下文信号：

| 原硬编码规则 | 改为 LLM 可见的上下文信号 |
|-------------|------------------------|
| auth weak-creds/brute | `auth_state = {"stage": "weak-creds", "attempts": [...]}` |
| auth endpoint-enum | `needs_endpoint_discovery = true` |
| sqli 强制先 sqlmap | `sqli_confidence = 0.7, suggested_tool = "sqlmap"` |
| graph_action 强制覆盖 | 移除，改为 LLM 可读的 `graph_signals` |

#### 改动 2：重构 `_build_decision_prompt()`
让 prompt 包含**可执行的选项**而非让框架强制决策：

```python
# 原来的问题：hard-coded if/else 规则直接决定动作
# 修复后：所有动作选项都交给 LLM 选择

prompt += f"""
## 当前解题状态
- 题型: {problem_type}
- 已识别标签: {tags_str}
- 漏洞类型: {vuln_tags}

## 靶机信息
- 已发现端点: {endpoints_str}
- 已发现参数: {params_str}
- 已有攻击线索: {findings}

## 建议动作（供 LLM 参考，LLM 可自由选择）
{self._get_suggested_actions(context)}
"""

def _get_suggested_actions(self, context):
    """生成建议动作列表，让 LLM 参考而非强制执行"""
    suggestions = []

    if context.get("auth_state", {}).get("stage") == "weak-creds":
        suggestions.append({
            "tool": "python_poc",
            "target": "login_endpoint",
            "params": {"type": "brute_force"},
            "reason": "检测到登录入口，可尝试弱口令暴力破解"
        })

    if context.get("sqli_confidence", 0) > 0.5:
        suggestions.append({
            "tool": "sqlmap",
            "target": context.get("sqli_target", ""),
            "params": {"batch": True},
            "reason": "SQL注入置信度高，建议使用 sqlmap 验证"
        })

    # ... 其他建议

    return suggestions
```

#### 改动 3：LLM 决策拥有最高优先级
```python
def _decide_next_action(self) -> Dict[str, Any]:
    # 1. LLM 决策（永远优先）
    ai_decision = self._try_ai_decision()
    if ai_decision is not None:
        action = self._build_action_from_ai_decision(ai_decision)
        if action is not None:
            return action  # 直接返回，不再走硬编码规则

    # 2. AttackPlan（来自 Strategic Supervisor 的计划）
    if self.attack_plan:
        next_step = self.attack_plan.get_next_step()
        if next_step:
            return self._build_action_from_plan_step(next_step)

    # 3. 框架兜底：recon（只有当没有任何上下文时才执行）
    if not self.memory.steps:
        return self._build_action("recon", target=self.target_url, ...)

    # 4. 最终兜底：返回 recon 但标记"需要人工介入"
    return self._build_action("recon", target=self.target_url,
                              metadata={"needs_human_guidance": True})
```

### 关键代码位置
- `agent_core.py:3593-3610`: LLM 决策入口（已正确）
- `agent_core.py:3610-3792`: 硬编码 fallback 规则（需重构）
- `agent_core.py:1135-1231`: `_build_decision_prompt()`（需增强）

### 验证方式
1. 运行 `python main.py --url <rce靶机>`
2. 观察 Step 2+ 的决策日志：不再出现硬编码的 auth/sqli/ua 规则覆盖
3. LLM 应基于 `known_endpoints` 和 `taxonomy_tags` 自主选择攻击动作

---

## P0.6 - 重构：Skills/Memory/RAG 与 AI 决策协调

### 问题描述
1. **RAG 与决策循环隔离**：RAG 只在 help 阈值触发时运行，LLM 决策时看不到历史类似题目的解法
2. **资源加载无优先级**：skills + experiences + RAG 全部塞进 resource_summary，没有指导 LLM 优先关注哪些
3. **缺少上下文压缩**：所有上下文直接拼接，超 token 限制后无法处理

### 参考框架架构

**H-Pentest Context Manager**
```
- 基于 tiktoken 的 token 计数
- 优先级压缩：low-priority 资源 → LLM 总结 → 保留关键信息
- 保留：system prompts + 最近的 steps + 高优先级 findings
```

**H-Pentest Multi-LLM Context 注入**
```
StrategicSupervisor 生成 plan ──► Worker context
MetaSupervisor 生成 insights ──► Worker context（每3轮）
PayloadMaster 提供 guidance ──► Worker context
```

### 重构方案

#### 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                    LLM 决策层 (Worker)                          │
│  - 基于压缩后的完整上下文做决策                                   │
│  - 决策权重：taxonomy_signals > planner_signals > resources     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│              Decision Context Builder                            │
│                                                              │
│  1. taxonomy_signals ──► 漏洞类型 + 标签                       │
│  2. planner_signals ──► known_endpoints, parameters, state    │
│  3. Skills ────────────► 针对性技术知识 (按 taxonomy 选取)      │
│  4. Long Memory ───────► 历史类似题目解法 (按 taxonomy 选取)    │
│  5. RAG ──────────────► WooYun 相似 writeup (每次决策前运行)  │
│                                                              │
│  输出：结构化 Context，标注优先级                              │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│              Context Manager (新增)                            │
│                                                              │
│  - 基于 tiktoken token 计数                                   │
│  - 优先级压缩：low-priority 资源 → LLM 总结 → 保留关键信息   │
│  - 保留：system prompts + 最近的 steps + 高优先级 findings     │
└───────────────────────────────────────────────────────────────┘
```

#### 改动 1：RAG 每次决策前运行

```python
# agent_core.py _decide_next_action() 中

def _decide_next_action(self) -> Dict[str, Any]:
    # === 新增：每次决策前先做 RAG ===
    rag_result = self._get_rag_knowledge_for_decision()
    context = self._build_decision_context(rag_knowledge=rag_result)

    # 1. LLM 决策（永远优先）
    ai_decision = self._try_ai_decision(context)
    if ai_decision is not None:
        action = self._build_action_from_ai_decision(ai_decision)
        if action is not None:
            return action

    # ... 后续 fallback ...

def _get_rag_knowledge_for_decision(self):
    """每次决策前从 RAG 获取相似题目知识"""
    if not self.memory.steps:
        return None  # 第一步没有足够上下文，不做 RAG

    rag_result = retrieve_rag_knowledge(
        query=f"{self.target_type} {' '.join(self.taxonomy_tags)}",
        vuln_type=self.target_type,
        target_url=self.target_url,
        top_k=3,
    )
    return rag_result
```

#### 改动 2：按 taxonomy 优先级选取资源

```python
# taxonomy_priority 定义
TAXONOMY_RESOURCE_PRIORITY = {
    "rce": ["skills/rce", "long_memory/pocs", "rag/command_injection"],
    "sqli": ["skills/sqli", "long_memory/pocs", "rag/sql_injection"],
    "xss": ["skills/xss", "long_memory/pocs", "rag/xss"],
    "auth": ["skills/auth", "long_memory/experiences", "rag/auth_bypass"],
}

def _build_decision_context(self, rag_knowledge=None):
    """构建决策上下文，按优先级组织"""

    # 优先级 1: taxonomy_signals
    canonical = self._get_canonical_type()
    resource_priority = TAXONOMY_RESOURCE_PRIORITY.get(canonical, ["skills/general"])

    # 优先级 2: planner_signals
    planner_signals = self.graph_manager.planner_signals()

    # 优先级 3: 针对性 resources
    resources = self._get_prioritized_resources(resource_priority)

    # 优先级 4: RAG 知识
    if rag_knowledge:
        resources["rag_knowledge"] = rag_knowledge

    return {
        "taxonomy_signals": self.taxonomy_signals,
        "planner_signals": planner_signals,
        "resources": resources,
    }
```

#### 改动 3：新增 CTFContextManager

```python
# context_manager.py（新增文件）

import tiktoken
from typing import Dict, Any

class CTFContextManager:
    """CTF 专用上下文管理器"""

    def __init__(self, max_tokens: int = 8000):
        self.max_tokens = max_tokens
        try:
            self.encoding = tiktoken.get_encoding("cl100k_base")
        except:
            self.encoding = None

    def count_tokens(self, text: str) -> int:
        if not self.encoding:
            return len(text) // 4
        return len(self.encoding.encode(text))

    def compress_context(self, context: Dict[str, Any], target_tokens: int = None) -> Dict[str, Any]:
        """压缩上下文，保留关键信息"""
        if target_tokens is None:
            target_tokens = int(self.max_tokens * 0.8)

        current_tokens = self.count_tokens(str(context))
        if current_tokens <= target_tokens:
            return context

        compressed = context.copy()

        # 压缩 resources（低优先级资源 LLM 总结）
        if "resources" in context:
            compressed["resources"] = self._compress_resources(context["resources"])

        # 压缩 history（只保留最近 5 步）
        if "action_history" in context:
            compressed["action_history"] = context["action_history"][-5:]

        return compressed

    def _compress_resources(self, resources: Dict) -> Dict:
        """压缩资源部分"""
        priority_resources = ["skill", "rag_knowledge", "taxonomy_signals"]
        result = {k: v for k, v in resources.items() if k in priority_resources}

        low_priority = ["experiences", "pocs", "tips"]
        for key in low_priority:
            if key in resources and resources[key]:
                result[key] = f"[已压缩，共 {len(resources[key])} 条经验]"

        return result
```

### 关键代码位置

| 改动 | 文件 | 位置 |
|------|------|------|
| RAG 每次决策前运行 | `agent_core.py` | `_decide_next_action()` |
| 按 taxonomy 优先级选取资源 | `agent_core.py` | `_build_decision_context()` |
| 新增 CTFContextManager | `context_manager.py` | 新文件 |

### 与现有代码的衔接

```
现有流程：
init_problem() ──► resource_bundle ──► memory ──► build_advisor_context() ──► LLM

优化后：
init_problem() ──► resource_bundle ──► memory
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
              taxonomy_signals              Decision Context Builder
                    │                               │
              planner_signals                         │
                    │                               │
              _get_rag_knowledge() ──► Context Manager ──► LLM
```

---

## P0.7 - 重构：Skills/记忆/RAG 与 AI 决策协调

### 状态：✅ 已完成实现

### 问题描述
1. **资源无优先级**：skills + experiences + WooYun 全部平铺塞进 resource_summary
2. **RAG 只在 help 时运行**：LLM 决策时看不到相似题目知识
3. **无 taxonomy 筛选**：所有类型的资源都加载，不管题型
4. **ContextManager 未完全集成**：已创建但资源选择未接入

### 参考框架架构

**1. H-Pentest Multi-LLM Context 注入**
```
StrategicSupervisor（生成计划）──► Worker Context
MetaSupervisor（每3轮洞察）────► Worker Context
PayloadMaster（payload 指导）──► Worker Context
```

**2. BUUCTF Agent 记忆分类**
```
MemorySystem: 存储具体步骤/观察/结论
KnowledgeBase: 存储通用 CTF 知识/工具用法
```

**3. H-Pentest Context Manager**
```
compress_messages(): system + recent + LLM总结middle
smart_compress(): 基于优先级的压缩
prioritize_messages(): 内容重要性排序
```

### 最优方案架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    init_problem()                               │
│                         │                                        │
│    ┌───────────────────┼───────────────────┐                    │
│    │                   │                   │                    │
│    v                   v                   v                    │
│ taxonomy_profile   skill_content    resource_bundle             │
│    │                   │                   │                    │
│    │                   │                   ├── experiences      │
│    │                   │                   ├── pocs             │
│    │                   │                   └── wooyun_knowledge│
│    │                   │                                            │
└────│───────────────────│────────────────────────────────────────┘
     │                   │
     ▼                   ▼
┌─────────────────────────────────────────────────────────────────┐
│              _decide_next_action()                              │
│                         │                                        │
│    ┌───────────────────┴───────────────────┐                    │
│    │                                       │                    │
│    v                                       v                    │
│ _get_rag_knowledge()              _build_decision_context()      │
│ (每次决策前运行)                         │                       │
│                                           │                       │
│                    ┌────────────────────┼────────────────────┐│
│                    │                    │                       ││
│                    v                    v                       v│
│              taxonomy_signals    planner_signals    skill (按taxonomy)│
│                    │                    │                       ││
│                    │                    │            rag_knowledge│
│                    │                    │            (每次更新)   ││
│                    │                    │                       ││
│                    └────────────────────┴───────────────────────┘│
│                                       │                          │
│                                       ▼                          │
│                        CTFContextManager.compress_context()       │
│                                       │                          │
│                    ┌──────────────────┴──────────────────┐      │
│                    │                                     │      │
│                    v                                     v      │
│         保留: taxonomy_signals,             压缩: experiences    │
│               planner_signals,                   pocs            │
│               skill,                              tips           │
│               rag_knowledge                                           │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                              [压缩后的完整上下文]
                              进入 LLM 决策 prompt
```

### 改动 1：按 taxonomy 优先级选取资源

```python
# taxonomy 与资源优先级映射
TAXONOMY_RESOURCE_PRIORITY = {
    "rce": {
        "skill": "skills/rce",
        "long_memory": "experiences",  # RCE 相关经验
        "rag_query": "rce command injection bypass",
    },
    "sqli": {
        "skill": "skills/sqli",
        "long_memory": "experiences",
        "rag_query": "sql injection bypass filter",
    },
    "xss": {
        "skill": "skills/xss",
        "long_memory": "experiences",
        "rag_query": "xss bypass filter",
    },
    "auth": {
        "skill": "skills/auth",
        "long_memory": "experiences",
        "rag_query": "auth bypass credential",
    },
    "lfi": {
        "skill": "skills/lfi",
        "long_memory": "experiences",
        "rag_query": "local file inclusion bypass",
    },
}

def _get_prioritized_resources(self, problem_type: str) -> Dict[str, Any]:
    """按 taxonomy 优先级获取资源"""
    priority = TAXONOMY_RESOURCE_PRIORITY.get(problem_type, {})

    resources = {}

    # 1. Skill（优先级最高）
    if "skill" in priority:
        skill_name = priority["skill"].split("/")[1]
        resources["skill"] = self._load_skill(skill_name)

    # 2. Long Memory experiences（按 taxonomy 筛选）
    if "long_memory" in priority:
        experiences = self._filter_experiences_by_type(priority["long_memory"])
        resources["experiences"] = experiences

    return resources

def _filter_experiences_by_type(self, exp_type: str) -> List[Dict]:
    """从 long_memory 中筛选特定类型的经验"""
    loaded_resources = self.init_result.get("loaded_resources", {})
    resource_bundle = loaded_resources.get("resource_bundle", {})
    all_experiences = resource_bundle.get("experiences", [])

    # 简单关键词匹配
    filtered = [
        exp for exp in all_experiences
        if exp_type.lower() in str(exp.get("method", "")).lower()
        or exp_type.lower() in str(exp.get("title", "")).lower()
    ]
    return filtered[:5]  # 最多5条
```

### 改动 2：RAG 每次决策前运行

```python
def _get_rag_knowledge_for_decision(self) -> Optional[Dict[str, Any]]:
    """每次决策前从 RAG 获取相似题目知识"""
    # 第一步和类型未知时不运行
    if not self.memory.steps or not self.target_type:
        return None

    # 获取 taxonomy 对应的 RAG 查询
    priority = TAXONOMY_RESOURCE_PRIORITY.get(self.target_type, {})
    rag_query = priority.get("rag_query", self.target_type)

    # 获取已尝试的方法
    graph_signals = self.graph_manager.planner_signals()
    attempted = list(graph_signals.get("failed_tools") or [])

    rag_result = retrieve_rag_knowledge(
        query=rag_query,
        vuln_type=self.target_type,
        target_url=self.target_url,
        attempted_methods=attempted,
        top_k=5,
    )

    if rag_result and (rag_result.get("retrieved_knowledge") or rag_result.get("suggested_approach")):
        return rag_result
    return None
```

### 改动 3：重构 `_build_decision_context()` 按优先级组织

```python
def _build_decision_context(self, rag_knowledge: Optional[Dict] = None) -> Dict[str, Any]:
    """按优先级构建决策上下文"""

    # === 优先级 1: taxonomy_signals（漏洞类型决定攻击方向）===
    taxonomy_signals = self._get_taxonomy_signals()

    # === 优先级 2: planner_signals（已知端点、参数、状态）===
    planner_signals = self.graph_manager.planner_signals()

    # === 优先级 3: Skill（按 taxonomy 选取）===
    skill_content = self._get_prioritized_skill()

    # === 优先级 4: RAG 知识（每次决策前更新）===
    if rag_knowledge:
        rag_summary = self._summarize_rag_result(rag_knowledge)
    else:
        rag_summary = None

    # === 优先级 5: Long Memory experiences（按 taxonomy 筛选）===
    experiences = self._get_prioritized_experiences()

    # === 构建上下文 ===
    context = {
        # 优先级 1-2
        "taxonomy_signals": taxonomy_signals,
        "planner_signals": planner_signals,

        # 优先级 3-5
        "skill": skill_content,
        "rag_summary": rag_summary,
        "experiences": experiences,

        # 其他上下文
        "known_endpoints": planner_signals.get("known_endpoints", []),
        "known_parameters": planner_signals.get("known_parameters", []),
        # ...
    }

    return context
```

### 改动 4：CTFContextManager 集成

```python
def _try_ai_decision(self) -> Optional[Dict[str, Any]]:
    """尝试 AI 决策"""

    # === 1. 每次决策前 RAG ===
    rag_knowledge = self._get_rag_knowledge_for_decision()

    # === 2. 构建决策上下文（按优先级）===
    context = self._build_decision_context(rag_knowledge=rag_knowledge)

    # === 3. 上下文压缩 ===
    compressed_context = self.context_manager.compress_context(context)

    # === 4. AI 决策 ===
    return self._ai_decide(compressed_context)
```

### 改动 5：Prompt 按优先级展示资源

```python
def _build_decision_prompt(self, context: Dict[str, Any]) -> str:
    """构建 AI 决策 prompt"""

    # === 按优先级展示 ===
    prompt = f"""## 任务
你是一个 CTF Web 解题助手。你的目标是通过分析当前情况，决定下一步应该做什么。

## 目标信息
- 题型: {context.get('problem_type')}
- 漏洞类型: {context.get('taxonomy_signals', {}).get('vulnerability_tags', [])}

## 靶机已探测到的信息
- 已发现端点: {endpoints_str}
- 已发现参数: {params_str}

## 上下文摘要（按优先级排序）

### 1. 针对性技能知识（最高优先级）
{context.get('skill', '暂无')}

### 2. 相似题目参考（RAG）
{context.get('rag_summary', '暂无')}

### 3. 相关历史经验
{context.get('experiences', '暂无')}

### 4. 已发现的线索
{findings}

### 5. 历史动作
{history}

### 6. 失败分析
{failures}

## 可用工具
{tool_desc}

## 决策要求
1. 优先利用针对性技能知识和 RAG 相似题目
2. 不要重复已失败的尝试
3. 如果一个方向连续失败，应该换方向

## 输出格式
{{"tool": "工具名称", "target": "具体目标", "reason": "决策理由"}}
"""
    return prompt
```

### 与现有代码的衔接

```
现有流程：
init_problem() ──► resource_bundle ──► memory ──► build_advisor_context() ──► LLM

优化后：
init_problem()
    │
    ├── taxonomy_profile ──► taxonomy_signals
    │
    ├── skill_content (按 taxonomy 选取)
    │
    └── resource_bundle ──► experiences (按 taxonomy 筛选)
              │
              v
    _decide_next_action()
        │
        ├── _get_rag_knowledge_for_decision() (每次决策前)
        │
        ├── _build_decision_context() (按优先级组织)
        │
        ├── CTFContextManager.compress_context()
        │
        └── _build_decision_prompt() (按优先级展示)
```

### 关键代码位置

| 改动 | 文件 | 位置 |
|------|------|------|
| taxonomy 资源优先级映射 | agent_core.py | 新增常量 |
| `_get_prioritized_resources()` | agent_core.py | 新增方法 |
| `_get_prioritized_skill()` | agent_core.py | 新增方法 |
| `_get_prioritized_experiences()` | agent_core.py | 新增方法 |
| `_get_rag_knowledge_for_decision()` | agent_core.py | 已存在，需增强 |
| `_build_decision_context()` | agent_core.py | 已有，需重构 |
| `_build_decision_prompt()` | agent_core.py | 已有，需按优先级展示 |
| CTFContextManager | context_manager.py | 已存在，需集成 |

---

## P0.7 - Skills/记忆/RAG 与 AI 决策协调（按 taxonomy 优先级）

### 状态：✅ 已完成实现

### 核心改动
1. `TAXONOMY_RESOURCE_PRIORITY` 常量：定义 rce/sqli/xss/auth/lfi 等题型的资源优先级映射
2. `_get_prioritized_skill()`：按 taxonomy 选取针对性 skill
3. `_get_prioritized_experiences()`：按 taxonomy 筛选相关经验
4. `_get_canonical_type()`：获取 canonical problem type
5. `_build_decision_context()`：接入优先级资源选取
6. `_build_decision_prompt()`：按优先级展示资源（skill → experiences → RAG → findings）

---

## P0.8 - 重构：消除 auth/sqli/ua 硬编码分支，转为 LLM 可见上下文信号

### 状态：✅ 主要完成（待回归测试验证）

### 核心改动

**第一阶段（✅ 已完成）**：
1. `_get_auth_signals()` - auth 题型结构化信号
2. `_get_sqli_signals()` - sqli 题型结构化信号
3. `_get_ua_bypass_signals()` - ua_bypass 题型结构化信号
4. `_build_decision_context()` 已注入 signals
5. `_build_decision_prompt()` 已添加信号展示区块

**第二阶段（✅ 已完成）**：
6. 移除 `_decide_next_action()` 中的 auth/sqli/ua 硬编码 if/else 分支
7. LLM 决策成为唯一主路径，框架只做 graph-informed 兜底

### 剩余循环检测逻辑（保留原因）
`low_yield_probe_loop`、`dir_scan_stuck_loop` 等循环检测逻辑保留，因为这些是**通用安全约束**，不是题型特判。

---

## P0.9 - 修复：recon 结果中 typed_findings 未写入 key_findings

### 问题描述
`summarize_generic_recon_findings()` 返回的 `typed_findings`（如 `source_leak:highlight_file`）没有被写入 `step.key_findings`，导致 `_refresh_graph_state()` → `planner_signals()` 无法获取这些信息。

### 根因
`_execute_recon_action()` 只提取了 `findings` 列表，没有提取 `typed_findings`。

### 修复
在 `_execute_recon_action()` 中，将 `typed_findings` 也写入 `key_findings`：
```python
typed_findings = list(generic_summary.get("typed_findings") or [])
for tf in typed_findings:
    kind = tf.get("kind", "")
    value = tf.get("value", "")
    if kind and value:
        findings.append(f"{kind}:{value}")
```

### 状态：✅ 已完成

### 参考框架架构

**H-Pentest Strategic Supervisor 模式**：
```
StrategicSupervisor → 注入结构化上下文（phase plans, task priorities）
                    → NOT 直接命令（specific tools, payloads）

Worker → 接收上下文，自主决策
       → 可选择遵循或忽略 supervisor 建议
```

**核心原则**：
- **框架提供信息，不做决策**：endpoints、parameters、state signals 都要作为 LLM 可见上下文
- **LLM 拥有完整自主权**：基于上下文自己决定下一步
- **硬编码规则转为结构化信号**：把 if/else 分支改为 LLM 可读的 `auth_state`、`sqli_confidence` 等字段

### 问题代码位置
`agent_core.py:3867-4070`：
```python
# 问题：硬编码判断替代了 LLM 决策
if self.target_type == "auth":
    auth_state = self._auth_progress_state()
    auth_stage = auth_state.get("stage") or "weak-creds"

    if auth_stage == "weak-creds" and not has_successful_poc:
        return poc_action  # 框架强制执行，没有给 LLM 选择权
```

### 重构方案

#### 改动 1：将 auth 硬编码分支转为上下文信号

**原硬编码逻辑**：
```python
if auth_stage == "weak-creds" and not has_successful_poc:
    return poc_action
if auth_stage == "endpoint-enum":
    return recon_action
if auth_stage == "auth-sqli":
    return sqlmap_action
```

**重构后：LLM 可见的上下文信号**：
```python
# 在 _build_decision_context() 中添加：
if self.target_type == "auth":
    auth_state = self._auth_progress_state()
    context["auth_signals"] = {
        "stage": auth_state.get("stage", "unknown"),
        "has_login_endpoint": bool(login_endpoints),
        "has_login_params": bool(login_params),
        "has_successful_poc": has_successful_poc,
        "login_endpoint": login_endpoints[0] if login_endpoints else None,
        "login_params": [param_u, param_p],
        "suggested_approach": _get_auth_suggested_approach(auth_state),
    }
```

**Prompt 中的呈现方式**：
```
### Auth 攻击状态
- 当前阶段: {auth_signals.stage}（weak-creds / endpoint-enum / auth-sqli）
- 登录端点: {auth_signals.login_endpoint}
- 登录参数: {auth_signals.login_params}
- 已成功 POC: {auth_signals.has_successful_poc}
- 建议方向: {auth_signals.suggested_approach}

基于以上信息，你认为下一步应该做什么？
```

#### 改动 2：将 sqli 硬编码分支转为上下文信号

**原硬编码逻辑**：
```python
if self.target_type == "sqli":
    if not any(s.tool == "sqlmap" for s in steps):
        return sqlmap_action
    if any(s.tool == "sqlmap" and not s.success for s in steps[-2:]):
        return dir_scan_action
```

**重构后**：
```python
# 在 _build_decision_context() 中添加：
if self.target_type == "sqli":
    context["sqli_signals"] = {
        "sqlmap_attempted": any(s.tool == "sqlmap" for s in steps),
        "sqlmap_success": any(s.tool == "sqlmap" and s.success for s in steps),
        "sqlmap_recently_failed": any(s.tool == "sqlmap" and not s.success for s in steps[-2:]),
        "sqli_confidence": self._estimate_sqli_confidence(),
        "suggested_tool": "sqlmap" if not any(s.tool == "sqlmap" for s in steps) else "dirsearch",
    }
```

#### 改动 3：UA bypass 硬编码转为上下文信号

**原硬编码逻辑**：
```python
if self.target_type == "ua_bypass":
    if not any(s.tool in {"ua_test", "python_poc"} ...):
        return ua_test_action
    if "301" in str(last_step.result) or "302" in str(last_step.result):
        return follow_redirect_action
```

**重构后**：
```python
if self.target_type == "ua_bypass":
    context["ua_bypass_signals"] = {
        "ua_test_attempted": any(s.tool in {"ua_test", "python_poc"} and "Mobile" in str(s.result) for s in steps),
        "last_response_code": self._get_last_response_code(),
        "redirect_target": self._extract_redirect(last_step.result) if last_step else None,
    }
```

### 实施步骤

1. **提取信号函数**：从 `_decide_next_action()` 中提取 auth/sqli/ua 状态计算逻辑
2. **修改 `_build_decision_context()`**：将计算好的信号注入 context
3. **修改 `_build_decision_prompt()`**：添加各题型的上下文信号区块
4. **保留 LLM 决策入口**：确保 `_try_ai_decision()` 能接收这些信号
5. **移除硬编码分支**：删除 `_decide_next_action()` 中的 if/else 分支
6. **保留安全约束**：max_steps、max_failures 等约束仍由框架执行

### 关键代码位置

| 改动 | 文件 | 位置 |
|------|------|------|
| 提取 auth 信号 | agent_core.py | 新增 `_get_auth_signals()` |
| 提取 sqli 信号 | agent_core.py | 新增 `_get_sqli_signals()` |
| 提取 ua bypass 信号 | agent_core.py | 新增 `_get_ua_bypass_signals()` |
| 修改 `_build_decision_context()` | agent_core.py | 注入各类 signals |
| 修改 `_build_decision_prompt()` | agent_core.py | 添加 signals 展示 |
| 移除硬编码分支 | agent_core.py | 删除 lines 3867-4070 中的 if/else |

### 验证方式
1. 运行 auth 类型靶机，观察 LLM 是否能基于 `auth_signals` 自主选择攻击路径
2. 运行 sqli 类型靶机，观察 LLM 是否能自主决定 sqlmap/dirscan 顺序
3. 确认硬编码分支被移除后，系统仍能正常工作

---

## P0.9 - 修复：taxonomy 检测后 skill_names 未更新 + recon findings 未注册 family

### 状态：✅ 已完成

### 问题描述
1. taxonomy 检测到 `rce` 类型后，`skill_names` 没有同步更新，导致 `_resolve_skill_resources` 找不到 `skills/rce/SKILL.md`
2. recon 执行后发现 `source_leak:highlight_file`，但没有注册为 attempted family，导致 help gate 被 `missing_families:source_leak` 阻塞

### 根因分析
1. `tools.py:461`: `build_taxonomy_profile` 后更新了 `canonical_problem_type` 但没有更新 `skill_names`
2. `agent_core.py`: recon 执行后只调用了 `memory.add_step()`，没有主动注册 finding family

### 修复内容

**修复 1: `tools.py:461-462`**
```python
# taxonomy 检测到类型后，同步更新 skill_names
taxonomy_profile["canonical_problem_type"] = tag
taxonomy_profile["skill_names"] = canonical_skill_names(tag)
```

**修复 2: `agent_core.py:3329-3349`** (in `_execute_recon_action`)
```python
# recon 执行后，主动注册 finding family
finding_kinds = set()
for f in findings:
    if isinstance(f, str) and ":" in f:
        kind = f.split(":", 1)[0].strip()
        finding_kinds.add(kind)
    elif isinstance(f, dict):
        kind = str(f.get("kind", "")).strip()
        if kind:
            finding_kinds.add(kind)
for kind in finding_kinds:
    self.memory.note_attempted_family(kind)

# 标记 skill 资源已被使用
if self.init_result.get("skill_content") or getattr(self.agent_context, "skill_content", ""):
    self.memory.note_resource_source_used("skill")
```

### 验证结果
- Step 1: recon 发现 `source_leak:highlight_file` → 正确注册 family
- Step 2: help gate 不再被 `missing_families:source_leak` 阻塞
- Step 3-9: 能正常推进到 source_analysis、dir_scan 等攻击动作

---

## P1 - 已完成的修复

| 修复项 | 状态 | 关键代码 |
|--------|------|---------|
| P1-3 分类结果脱节 | ✅ 已完成 | `tools.py:451-463` taxonomy 标签 fallback |
| P2-6 异常处理日志 | ✅ 已完成 | `tools.py:_call_llm_chat()` logging |
| P1-4 历史记忆未消费 | ✅ 已有架构 | `resource_bundle.experiences` 已暴露到 prompt |

---

## P2 - 优化项

### LLM provider 配置文档
- **问题**：使用者不清楚如何配置不同的 LLM API
- **修复**：在 config.json 中添加注释说明 provider 选项

---

## 重构进度映射

| 重构文档章节 | 对应修复项 | 状态 |
|-------------|-----------|------|
| 第1节 "题型识别过度依赖 heuristic" | P1-3 分类脱节 | ✅ 已完成 |
| 第2节 "工具执行不可预测" | P0 recon 回填 | ✅ 已完成 |
| 第3节 "P3: planner 深度消费" | P0.5 硬编码规则重构 | ✅ 已完成 |
| 第4节 "Skills/Memory/RAG 协调" | P0.6 Skills/Memory/RAG 重构 | ✅ 已完成 |
| 第5节 "P0.9: skill_names 未更新" | P0.9 taxonomy + recon findings 修复 | ✅ 已完成 |
