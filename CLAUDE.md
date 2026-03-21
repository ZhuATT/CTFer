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
2. 识别题型后，先消费知识资源：`get_available_resources()`、`skills/<type>/SKILL.md`、长期记忆、WooYun
3. 再进入主循环：`Advisor -> Planner -> Executor -> ToolNode`
4. 常规方法受阻后，先主动检索：`retrieve_rag_knowledge(...)`
5. 仍无法继续时，再 `help`
6. 获得人工提示后，必须沿同一 agent / memory / route trace 执行 `resume`

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
- 下一重点：P3 `graph_manager.py` / PoG / `GraphOp` / `shared_findings`

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
