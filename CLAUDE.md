# CTF Agent - 项目指令

## 项目目标
- 这是一个全自动 CTF Web 解题 Agent。
- 默认工作方式：自动识别题型、加载知识与经验、沿唯一主链执行，受阻后再求助。

## 当前最重要的默认约束

### 1. 主链入口唯一
当用户在 Claude Code 里提供 URL / hint / description / source code 请求解题时，默认只能走项目级主链：

```python
from orchestrator import orchestrate_challenge

result = orchestrate_challenge(
    url="http://target.com",
    hint="...",
    description="...",
)
```

或：

```bash
python main.py --url "http://target.com" --hint "..." --description "..."
```

**禁止默认绕过主链**：
- 不要直接从零散 `tools.py` 工具开始攻击
- 不要把 `AutoAgent.solve_challenge()` 当作 Claude Code 默认入口
- 不要自己临时拼接“初始化 -> 攻击”流程

**仅以下场景允许绕过**：
- 调试主链本身
- 编写/修复单元测试
- 修复 `orchestrator.py` / `main.py` / `agent_core.py` 底层问题

### 2. 强制执行顺序
1. 先初始化题目：`init_problem(...)`
2. 题型识别默认遵循：**LLM 优先、heuristic 兜底**；不要再把少量关键词匹配当作主判断器
3. 识别题型后，先消费统一资源：`get_available_resources()` / `loaded_resources["resource_bundle"]`，再使用对应 `skills/<type>/SKILL.md`、长期记忆、WooYun / RAG
4. 再进入主循环：`Advisor -> Planner -> Executor -> ToolNode`
5. 常规方法受阻后，先主动检索：`retrieve_rag_knowledge(...)`
6. 仍无法继续时，再 `help`
7. 获得人工提示后，必须沿同一 agent / memory / route trace 执行 `resume`

### 3. Python 运行时唯一真值源
全项目只允许一个 Python 解释器来源：

- `config.json["venv"]["python_path"]`

**禁止**：
- 硬编码 Python 路径
- 使用 `sys.executable` 充当项目工具解释器
- 使用 `workon CTFagent && ...` 之类包装
- 在 `tools.py` / `toolkit/*` / `utils/*` 各自维护一套解释器选择逻辑

### 4. 工具成功语义必须一致
- `tool_node.success` 必须与该动作对应的 memory step success 对齐
- 失败统计优先基于 `action_id`
- 动作元信息默认保持统一：`action_id` / `action_type` / `expected_tool` / `canonical_tool`

### 5. 当前阶段优先级
进行主链 / P2 / P3 相关修改时，先看根目录文档：

- `CHYing_参考重构方案.md`

它是当前主链重构路线与阶段进度的对齐基准。

按当前状态：
- P2-Beta：已完成
- P2-Gamma：核心已完成
- 已新增：初始化分类漂移第一轮修复、可降级的 LLM-first 分类入口、统一 `resource_bundle`、标准化 advisor context
- 下一重点：继续收敛 `long_memory.py` / `skills/skill_loader.py` 的独立识别逻辑，并让 planner 更深消费 `classification_*`、`resource_summary`、`shared_findings`

### 6. 联网默认规则
- 需要联网抓网页或搜索时，默认走自定义 `/web-fetch`
- 不使用内置 `WebFetch` / `WebSearch`

## 当前架构要求（新增）
- 初始化分类结果应优先信任 `init_problem()` 返回的结构化字段：
  - `problem_type`
  - `classification_confidence`
  - `classification_source`
  - `classification_evidence`
  - `classification_reasoning`
- `hint` 只能在**低置信初始化结果**下做兜底增强，不能默认降级覆盖初始化分类。
- 资源消费统一通过 `loaded_resources["resource_bundle"]` / `get_available_resources()` 暴露的标准化视图；不要在新代码里再各自拼一套 skill / long memory / WooYun 结构。
- `build_advisor_context()` 已暴露 `canonical_problem_type`、`taxonomy_signals`、`resource_summary`、`classification_*`；后续 planner / reflector / policy 优先消费这些标准化字段。
- 后续优化默认优先做：
  1. 主链稳定性与语义一致性
  2. LLM 分类与资源链路收敛
  3. graph / planner 对标准化上下文的深消费
- 默认不要为了某个题目继续在 `agent_core.py` / `tools.py` 堆单题关键词或单题策略特判。

## 用户工作流偏好
- 全自动解题，遇到困难再求助
- 用户提供 POC；Agent 负责识别、检索、使用
- 成功经验自动沉淀到长期记忆
- 运行环境是 Windows 本地 `CTFagent`，不默认用 Docker / Kali

## 关键文件
- `orchestrator.py`：项目级唯一执行入口
- `main.py`：CLI 主入口
- `agent_core.py`：主循环、规划、执行、求助、resume
- `tools.py`：初始化、工具封装、记忆接入
- `short_memory.py`：短期记忆、动作失败统计、help/resume 记录
- `toolkit/base.py`：共享 runtime
- `CHYing_参考重构方案.md`：主链重构路线与阶段进度
