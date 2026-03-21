# 主链重构进度

## 目标
把初始化、知识加载、规划、执行、记忆、主动检索、求助/恢复统一到一条可审计、可恢复、可扩展的项目级主链里。

## 规范执行顺序（口径对齐）
> 以下顺序来源于 `CLAUDE.md`，描述的是项目要求的主链规范；它不等同于所有细节都已在代码里 100% hard gate。

1. 通过 `python main.py ...` 或 `orchestrator.orchestrate_challenge(...)` 进入项目级唯一主链。
2. `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` → `tools.init_problem(...)` 完成初始化、类型识别与上下文写入。
3. 识别题型后，必须先消费知识资源：`get_available_resources()` / 对应 `skills/<type>/SKILL.md` / 长期记忆 / WooYun。
4. 再进入 `Advisor → Planner → Executor → ToolNode` 主循环。
5. 常规方法受阻时，先主动做 `retrieve_rag_knowledge(...)` 这类知识检索，而不是直接求助。
6. 仍无法继续时，进入 `help`；拿到人工提示后，通过 `resume` 沿同一 agent / memory / route trace 继续。

## 已完成

### P0：唯一主链入口
- `main.py` 已作为项目级 CLI 入口，默认转发到 `orchestrator.main()`。
- `orchestrator.py` 已提供 `CTFOrchestrator` / `orchestrate_challenge()`。
- `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` 已统一接入 `tools.init_problem()`。
- `init_problem()` 已在初始化阶段加载题型、技能、长期记忆资源与 WooYun 参考，并写入 `AgentContext`。

### P1：Planner / Executor 契约第一版
- `agent_core.py` 已具备统一动作结构：`{id, type, target, description, intent, expected_tool, params}`。
- 已落地 `plan_next_action()` 与 `action_handlers` dispatch table。
- `attack_step` 已能映射到真实工具语义，帮助执行与求助判定对齐。
- `_should_ask_for_help()` 已按真实工具名统计失败趋势。
- 异常写入短期记忆时已带 `action_id` / `action_type` 元数据。

### P2-Alpha：help / resume continuity
- `OrchestratorState` 已包含：`messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request`。
- 已具备 `Advisor → Planner → Executor → ToolNode → help / resume` 的第一版事件流。
- `orchestrator.resume()`、`AutoAgent.resume_with_guidance()`、`ShortMemory.help_history / human_guidance / resume_count` 已打通。
- `test_orchestrator_resume.py` 已覆盖 help → resume continuity 回归。

## 当前约束
- Claude Code 是当前 HITL / 控制面。
- 不需要先做独立 UI；用户提示本身就是人工介入入口。
- 求助后应继续沿主链求解，而不是切回零散手工流程。
- 规范上要求“主动 RAG 检索先于 help”，但这条 gate 仍需继续向代码判定层收敛。

## 未完成

### P2-Beta：失败统计升级
- 让 `ShortMemory` 在保留旧签名兼容层的同时，稳定支持 `action_id` 级失败统计。
- 让 replanning、重复失败判定、help escalation 优先消费动作级失败信息。
- 补齐 P2-Beta 回归测试，确认不会破坏现有 help / resume continuity。

### P2-Gamma：工具执行统一
- 统一工具执行环境与成功语义。
- 收敛 `tools.py`、`toolkit/base.py`、`toolkit/fenjing.py` 的多头运行逻辑。
- 逐步收敛到 `config.json["venv"]["python_path"]` 作为唯一解释器来源。

### P3：图结构增强
- 落地 `graph_manager.py`。
- 引入 PoG / `GraphOp` / `shared_findings`。
- 为后续 Reflector / 因果图 / HITL 审批流预留接口。

## 最近已完成交付
- `9387fd0` `feat: 收敛主链入口与动作分发`
- `3473d43` `docs: 更新主链约束与重构进度`
- `914bb11` `chore: 清理冗余测试与遗留文件`
