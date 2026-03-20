# CTF Agent 记忆索引

## 项目定位
- CTF Web 解题 Agent，目标是：用户提供题目信息后，Agent 自动识别类型、加载知识与经验、沿唯一主链执行，遇到困难再向人求助。
- Claude Code 是当前 HITL / 交互控制面；不需要单独 UI 才能完成人工协作。

## 强约束
- 在 Claude Code 中，只要用户给出 URL / hint / description / source code 请求解题，默认入口必须走：
  - `orchestrator.orchestrate_challenge(...)`，或
  - `python main.py ...`
- 不要默认绕过 orchestrator 直接拼接 `tools.py` 工作流。
- 仅在以下场景允许绕过主链：调试主链本身、修测试、修 `orchestrator.py` / `main.py` / `agent_core.py` 底层问题。
- 所有 Python 执行都必须使用 `C:\Users\Administrator\Envs\CTFagent\Scripts\python.exe`。

## 当前稳定认知
- P0 已完成：`main.py` + `orchestrator.py` 已形成项目级唯一主链入口。
- P1 第一版已完成：`agent_core.py` 已收敛统一动作结构、`plan_next_action()`、`action_handlers` dispatch table 与 canonical tool 映射。
- `_should_ask_for_help()` 已与真实工具名对齐，减少 planner 动作名与 memory 记账名漂移。
- 求助后，Agent 应基于真人提示继续沿主链解题。

## 关键文件
- `orchestrator.py`：项目级唯一执行入口与结构化状态容器。
- `main.py`：CLI 入口，默认进入 orchestrator。
- `agent_core.py`：主循环、规划、执行、求助判定。
- `tools.py`：初始化、工具封装、资源加载、短期记忆接入。
- `short_memory.py`：短期记忆、上下文、失败统计。
- `long_memory.py`：长期记忆与资源检索。
- `CHYing_参考重构方案.md`：重构计划与阶段进度。

## 用户工作流偏好
- 全自动解题，遇到困难再求助。
- 用户提供 POC；Agent 负责自动识别、检索和使用。
- 成功经验应沉淀到长期记忆。
- 可以参考 `References/` 中其他 Agent 架构，但默认落地仍以当前项目主链为准。

## 仍未完成的关键缺口
- `ShortMemory` 失败统计还未完全切到 `ActionSchema.id` 驱动。
- `graph_manager.py` / PoG / `GraphOp` / `shared_findings` 尚未落地。
- 工具执行环境与成功语义还未完全统一，`tools.py`、`toolkit/base.py`、`toolkit/fenjing.py` 仍有多套逻辑。

## 详细记忆
- [`main_chain_progress.md`](./main_chain_progress.md)：主链重构进度与当前阶段状态
- [`buuctf_agent_reference.md`](./buuctf_agent_reference.md)：外部参考架构对本项目的可复用启发
- [`deserialization.md`](./deserialization.md)：本项目内反序列化题型的高价值识别要点

## 使用提醒
- 记忆文件用于快速建立上下文，不代表实时代码状态；涉及细节时仍需回到代码验证。
