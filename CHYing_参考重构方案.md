# CHYing 参考重构方案

## 0. 当前落地进度（基于当前代码静态检查）
> 说明：以下勾选基于当前仓库实现与定向测试核对；P2-Alpha help/resume continuity 已完成并通过 `test_orchestrator_resume.py`。

- [x] `AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，主入口不再绕过知识加载链路（`agent_core.py:344-363`）
- [x] `AgentContext` 已落到 `ShortMemory.context`，并与 `target.url/problem_type` 同步（`short_memory.py:66-79`，`short_memory.py:269-329`）
- [x] `get_agent_context()` / `reset_memory()` / `init_problem()` 已形成 P0 基础上下文管道（`tools.py:68-79`）
- [x] `min_steps_before_help` help guardrail 已实现（`agent_core.py`）
- [x] CLI / orchestrator 级“唯一主循环”已落地：`main.py` 默认进入 `orchestrator.main()`，由 `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` 统一接入 `init_problem()`，再由 `CTFOrchestrator.run()` → `AutoAgent.run_main_loop()` 驱动主链
- [x] `ActionSchema` / dispatch table 已落地第一版：已具备统一 `action = {id, type, target, description, intent, expected_tool, params}` 结构、`plan_next_action()` 规范化出口、`action_handlers` 分发表，以及 `attack_step` → 实际工具名的 canonical 映射
- [x] `orchestrator.py` / 结构化 `agent_state` 已落地第一版：已具备 `messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request` 等状态字段，并能记录 Advisor / Planner / Executor / ToolNode / help / resume 事件
- [x] P2-Alpha 已完成：`needs_help` 已成为可恢复暂停态，`orchestrator.resume()` + `AutoAgent.resume_with_guidance()` + `ShortMemory.help_history/human_guidance/resume_count` 已打通同链路恢复
- [x] 定向回归已补齐：`test_orchestrator_resume.py` 覆盖 help → resume continuity，以及 `ShortMemory.add_patch()` / `get_patch_summary()` 回归
- [x] 进度文档口径已对齐：规范执行顺序明确为 `orchestrator/main -> initialize_challenge -> init_problem -> 先消费知识资源 -> Advisor/Planner/Executor/ToolNode -> 受阻后主动 RAG -> help/resume`，并明确区分“规范顺序”与“当前代码已完全强制实现”
- [ ] `graph_manager.py` / PoG / `GraphOp` / `shared_findings` 尚未落地
- [x] P2-Beta 已完成：`ShortMemory` 已支持 `action_id` 级失败聚合、`latest_step_for_action()` 查询，`_should_ask_for_help()` / replanning / skip 判定已优先消费动作级失败信息，并补齐 `test_failure_statistics.py` 回归
- [x] P2-Gamma 核心已完成：`config.json["venv"]["python_path"]` 已成为唯一 Python 真值源，`tools.py` / `toolkit/base.py` / `utils/python_runner.py` / `toolkit/fenjing.py` 已收敛到 shared runtime，`tool_node.success` 已与 memory step success 对齐，并补齐定向 runtime 回归测试

## 1. 背景与目标
- [x] 入口断层的第一步已修补：`AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，技能、长期记忆与 WooYun 可在主入口初始化阶段装载。
- [x] Planner/Executor 契约已收敛到第一版：`_build_action()` / `plan_next_action()` / `action_handlers` 已统一动作结构，`attack_step` / `recon` / `ua_test` / `sqlmap_scan` / `dir_scan` 等动作均可落到 executor；`_should_ask_for_help()` 与异常路径记忆也已对齐 canonical tool 名称。
- [x] help-resume continuity 已打通：Agent 触发求助后，可在不重新初始化题目、不重置短期记忆的前提下，基于人工提示继续沿同一主链运行。
- [ ] 类型体系与记忆链路仍漂移：短期记忆仍以粗粒度去重为主，长期记忆、技能与 RAG 之间还没有统一 taxonomy 与保存闭环。
- [ ] 工具环境仍多头管理：`toolkit/base.py` 已读取 `config.json["venv"]["python_path"]`，但 `tools.py` 与 `toolkit/fenjing.py` 仍存在硬编码 Python 路径、`sys.executable` 等并存逻辑。

**目标**：先完成唯一主链 + help/resume continuity + 结构化状态闭环，再进入失败统计精细化、工具执行统一、PoG / 图结构增强。

## 1.5 强制执行顺序口径（与 `CLAUDE.md` 对齐）
> 本节描述的是项目要求的规范顺序，不等同于所有环节都已在代码中 100% hard gate；当前已落地的是 orchestrator / `init_problem()` / 主循环 / help-resume 骨架，主动 RAG → help 的判定顺序仍需继续收敛。

1. `python main.py ...` / `orchestrator.orchestrate_challenge(...)` 进入项目级唯一主链。
2. `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` → `tools.init_problem(...)` 完成初始化、类型识别与上下文写入。
3. 识别题型后，必须先消费知识资源：`get_available_resources()`、对应 `skills/<type>/SKILL.md`、长期记忆经验 / POC、WooYun 参考。
4. 再进入 `Advisor -> Planner -> Executor -> ToolNode` 主循环。
5. 常规方法受阻后，应先调用 `retrieve_rag_knowledge(...)` 等主动检索链路补知识，而不是直接求助。
6. 仍无法继续时，再进入 `help`；拿到人工提示后，通过 `resume` 沿同一 agent / memory / route trace 继续。

## 2. “唯一真链路”缺口定位
1. [x] **入口断层**：`main.py` 现已默认进入 `orchestrator.main()`，并由 orchestrator 统一驱动初始化与唯一主循环，项目级入口骨架已打通。
2. [x] **动作语义第一版已收敛**：Planner 现通过统一动作字典输出，Executor 通过 `action_handlers` / canonical tool 映射统一执行；`_should_ask_for_help()` 与异常路径记录也已改用实际工具名。
3. [x] **help 后中断重开**：这一缺口已补齐。`needs_help` 不再是终态，而是可恢复暂停态；恢复后保持同一 agent、同一 memory、同一条 route trace 继续运行。
4. [ ] **知识与记忆断链**：skills、`long_memory/experiences`、`auto_experiences`、WooYun 皆存在，但没有共享分类或统一加载/保存回路。
5. [ ] **工具执行不可预测**：`execute_python_poc`、`toolkit/base.py`、`fenjing` 仍各自维护环境逻辑，成功语义也未统一。
6. [ ] **短期记忆精度不足**：失败统计与重复尝试判定还未完全升级到 `action_id` 粒度。

## 3. 当前优先级判断
- 当前最大断点已经不是“求助后无法继续”，而是：
  1. `ShortMemory` 失败统计还未完全切到 `action_id`
  2. 工具执行环境与成功语义仍不统一
  3. 图结构抽象尚未引入
- 因此下一阶段顺序保持：
  1. **P2-Beta：失败统计切到 `action_id` 优先**
  2. **P2-Gamma：统一工具执行环境与 success 语义**
  3. **P3：再进入 `graph_manager.py` / PoG / `GraphOp` / `shared_findings`**

## 3.5 工具执行统一方案（P2-Gamma 细化）
- **唯一 Python 执行入口**：全项目只保留一个 Python runtime / runner，唯一真值源来自 `config.json["venv"]["python_path"]`。业务层、planner、`tools.py`、`toolkit/*` 都不再自己决定解释器，也不再依赖 `workon CTFagent`、硬编码路径或 `sys.executable`。
- **统一调用面**：主链只感知 `action -> tool_name -> tool params -> ToolResult`。`agent_core.py` 的 `action_handlers` 负责把动作路由到统一工具入口；真正的进程创建、cwd、timeout、环境变量、stdout/stderr 收集都下沉到 runtime / runner。
- **统一结果结构**：所有外部工具返回统一 `ToolResult` / 标准字典，至少包含：`success`、`exit_code`、`stdout`、`stderr`、`command`、`tool_name`、`artifacts`、`parsed`。`success` 不再由各调用方各自猜测，统一由适配器或结果规范给出，供 ToolNode、memory logging、help 判定共用。
- **README 驱动封装**：用户只需要把工具放到 `tools_source/<tool_name>/` 目录，并提供 README。接入流程按四步走：
  1. 读取 `tools_source/<tool_name>/README.md`，确认官方推荐入口（例如 `python tool.py`、`python -m module`、独立二进制、依赖要求、典型参数、输出格式）；
  2. 在 `config.json["tools"]` 中登记元信息（path、timeout、enabled、entry_mode、module/script/binary、默认参数、README 路径）；
  3. 在 `toolkit/` 下新增对应适配器，负责 `_build_command()`、`_check_success()`、`parse_output()`，必要时定义 `artifacts` 提取规则；
  4. 通过统一 `run_tool()` / runtime 暴露给 `tools.py` 与主链 action handler 使用。
- **工具分类约束**：
  - Python CLI 工具：统一走 `python_path + script/module`；
  - 非 Python 二进制工具：允许作为例外类型接入，但仍必须走同一个 runtime / runner，由适配器声明 `entry_mode="binary"`；
  - 源码 import 型工具（如当前 `toolkit/fenjing.py` 的 `sys.path` 注入）应逐步迁移到 README 明确的 CLI / module 调用方式，避免业务层直接 import 第三方源码。
- **与现状的衔接**：
  - `toolkit/base.py` 是当前最接近目标的雏形，应继续收敛成统一 runner，而不是再在 `tools.py` 新增一套执行逻辑；
  - `tools.py.execute_command()` / `execute_python_poc()` 后续应改为调用统一 runtime；
  - `toolkit/fenjing.py` 需要从“直接 import 源码”迁移到受控适配器；
  - `toolkit/__init__.py::run_tool()` 适合作为统一调度入口保留并扩展。
- **落地顺序**：
  1. 先抽出 runtime / runner，并让 `tools.py` 与 `toolkit/base.py` 共用同一解释器来源；
  2. 再统一 `ToolResult` / success 语义；
  3. 再逐个把 sqlmap / dirsearch / fenjing 等现有工具迁移到 README 驱动适配器；
  4. 最后补工具注册表、自动发现与更细粒度的 artifacts/parsed 解析。

## 4. 分阶段落地清单
1. **统一入口（P0）**
   - [x] `AutoAgent.solve_challenge()` 强制调用 `tools.init_problem()`，并将 `problem_type/skill_content/loaded_resources` 写入强化版短期记忆 / `AgentContext` 供全局引用。
   - [x] CLI / orchestrator 主循环已接收 `init_problem()` 返回值，形成项目级知识优先入口。
   - [x] 进度文档已同步主链规范顺序：`orchestrator/main -> initialize_challenge -> init_problem -> 先消费知识资源 -> 主循环 -> 主动 RAG -> help/resume`。

2. **收敛 Action Schema（P1）**
   - [x] 已定义统一动作结构：`{id, type, target, description, intent, expected_tool, params}`；planner 通过 `plan_next_action()` 输出标准动作，executor 通过 `action_handlers` dispatch table 调用工具。
   - [~] `_should_ask_for_help()` 已与 canonical tool 名称对齐，异常路径已补 `action_id/action_type` 元数据；但 `ShortMemory` 底层失败计数仍以签名为主，尚未完全切到 `ActionSchema.id`。

3. **主链恢复闭环（P2-Alpha）**
   - [x] `orchestrator.py` 已补齐 resume 相关状态字段，并新增 `resume(human_guidance)`。
   - [x] `AutoAgent` 已支持基于人工提示恢复，同链路继续，不重新初始化。
   - [x] `AgentContext` / `ShortMemory` 已记录 `human_guidance`、`help_history`、`resume_count`。
   - [x] `build_advisor_context()` 已显式暴露人工提示与历史求助信息。
   - [x] 已新增 `test_orchestrator_resume.py` 并通过定向回归。

4. **失败统计升级（P2-Beta）**
   - [ ] 让 `_should_ask_for_help()`、重复尝试判定、失败趋势统计更多基于动作级别而不是粗粒度签名。
   - [ ] 优先让 `ShortMemory` 支持 `action_id` 主键化失败记录。

5. **工具执行 & 成功语义统一（P2-Gamma）**
   - [ ] `toolkit/base.py` 统一成为唯一 Python 执行出口；清理硬编码路径、`sys.executable` 等多头环境逻辑。
   - [ ] 收敛工具返回结构与 success 语义，让 ToolNode / memory logging / help 判定共用同一套标准。

6. **PoG / 因果图增强（P3）**
   - [ ] 引入 `graph_manager.py` 维护 DAG + 因果图：节点结构 `{id, type, state, parent_ids, action_schema}`，边结构 `{from, to, condition}`。
   - [ ] Planner 产出 `GraphOp`，Executor 完成为节点写入 `state`，Reflector 根据失败原因触发重新规划。
   - [ ] 将短期记忆的执行日志 / 证据沉淀到 `shared_findings`。

## 5. 当前结论
- `main.py` / `orchestrator.py` / `agent_core.py` 已形成项目级唯一主链。
- help-resume continuity 已不再是阻塞项。
- 下一步不应立刻跳去 GraphManager，而应先完成 `action_id` 级失败统计与工具执行统一。
