# 主链重构进度

## 目标
把初始化、知识加载、规划、执行、记忆、求助统一到一条可审计、可恢复、可扩展的项目级主链里。

## 已完成

### P0：唯一主链入口
- `main.py` 已作为项目级 CLI 入口，默认转发到 `orchestrator.main()`。
- `orchestrator.py` 已提供 `CTFOrchestrator` / `orchestrate_challenge()`。
- `AutoAgent.initialize_challenge()` 与 `AutoAgent.run_main_loop()` 已被 orchestrator 串成统一入口。

### P1：Planner / Executor 契约第一版
- `agent_core.py` 已具备统一动作结构：`{id, type, target, description, intent, expected_tool, params}`。
- 已落地 `plan_next_action()` 与 `action_handlers` dispatch table。
- `attack_step` 已能映射到真实工具语义，帮助执行与求助判定对齐。
- `_should_ask_for_help()` 已按真实工具名统计失败趋势。
- 异常写入短期记忆时已带 `action_id` / `action_type` 元数据。

### 状态层骨架
- `OrchestratorState` 已包含：`messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request`。
- 已具备 Advisor → Planner → Executor → ToolNode → help 的第一版事件流。

## 当前约束
- Claude Code 是当前 HITL / 控制面。
- 不需要先做独立 UI；用户提示本身就是人工介入入口。
- 求助后应继续沿主链求解，而不是切回零散手工流程。

## 未完成

### P2
- 统一工具执行环境与成功语义。
- 升级 `ShortMemory`，拆出更清晰的 execution log / evidence / shared findings 语义。
- 让失败统计更稳定地挂到 `action_id` 维度。

### P3
- 落地 `graph_manager.py`。
- 引入 PoG / `GraphOp` / `shared_findings`。
- 为后续 Reflector / 因果图 / HITL 审批流预留接口。

## 最近已完成交付
- `9387fd0` `feat: 收敛主链入口与动作分发`
- `3473d43` `docs: 更新主链约束与重构进度`
- `914bb11` `chore: 清理冗余测试与遗留文件`
