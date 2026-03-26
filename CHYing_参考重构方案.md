# CHYing 参考重构方案

## 0. 当前落地进度（基于当前代码静态检查）
> 说明：以下勾选基于当前仓库实现与定向验证核对；P2-Alpha help/resume continuity、RAG-before-help 最小 hard gate、本轮 P3-Alpha 最小闭环与 P3-Beta 候选排序小切片已完成针对性验证。最近新增的一轮工作已把 graph-driven reflector / replan policy 向前推进：`graph_manager.py` 已能暴露 `finding_lineages` / `blocked_findings` / `finding_failure_counts` / `finding_attempt_counts`，`agent_core.py` 已把部分 candidate generation 收敛到 finding-family 驱动，并补了 low-yield probe loop 抑制；对应回归已扩到 `tests/test_graph_reflector.py` 与 `tests/test_orchestrator_graph_state.py`。

- [x] `AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，主入口不再绕过知识加载链路（`agent_core.py:344-363`）
- [x] `AgentContext` 已落到 `ShortMemory.context`，并与 `target.url/problem_type` 同步（`short_memory.py:66-79`，`short_memory.py:269-329`）
- [x] `get_agent_context()` / `reset_memory()` / `init_problem()` 已形成 P0 基础上下文管道（`tools.py:68-79`）
- [x] `min_steps_before_help` help guardrail 已实现（`agent_core.py`）
- [x] CLI / orchestrator 级“唯一主循环”已落地：`main.py` 默认进入 `orchestrator.main()`，由 `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` 统一接入 `init_problem()`，再由 `CTFOrchestrator.run()` → `AutoAgent.run_main_loop()` 驱动主链
- [x] `ActionSchema` / dispatch table 已落地第一版：已具备统一 `action = {id, type, target, description, intent, expected_tool, params}` 结构、`plan_next_action()` 规范化出口、`action_handlers` 分发表，以及 `attack_step` → 实际工具名的 canonical 映射
- [x] `orchestrator.py` / 结构化 `agent_state` 已落地第一版：已具备 `messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request` 等状态字段，并能记录 Advisor / Planner / Executor / ToolNode / help / resume 事件
- [x] P2-Alpha 已完成：`needs_help` 已成为可恢复暂停态，`orchestrator.resume()` + `AutoAgent.resume_with_guidance()` + `ShortMemory.help_history/human_guidance/resume_count` 已打通同链路恢复
- [x] 恢复连续性相关的定向验证已完成：help → resume continuity 与 `ShortMemory.add_patch()` / `get_patch_summary()` 链路均已核对
- [x] 进度文档口径已对齐：规范执行顺序明确为 `orchestrator/main -> initialize_challenge -> init_problem -> 先消费知识资源 -> Advisor/Planner/Executor/ToolNode -> 受阻后主动 RAG -> help/resume`，并明确区分“规范顺序”与“当前代码已完全强制实现”
- [~] P3-Alpha 最小闭环已落地：`graph_manager.py` 已提供 `planner_signals()` 等 graph-derived signals，`agent_core.py` 已通过 `_build_graph_informed_action()` 消费 guidance / endpoint / parameter / repeated action failure，并已完成最小 graph/planner 行为验证；最近又补入了 `finding_lineages` / `blocked_findings` / `finding_failure_counts` / `finding_attempt_counts`、finding-lineage replan metadata、以及低收益 probe loop 抑制，但完整 PoG / Reflector / 因果图增强仍未完成
- [x] P3-Beta 小切片已落地：graph-informed replan candidates 已接入确定性排序，`_collect_graph_informed_actions()` 会统一经过 `_rank_graph_informed_candidates()`，`selected_alternative`、`_build_graph_informed_action()` 与 `plan_next_action()` 已共享同一排序结果，不再依赖候选生成顺序
- [x] P2-Beta 已完成：`ShortMemory` 已支持 `action_id` 级失败聚合、`latest_step_for_action()` 查询，`_should_ask_for_help()` / replanning / skip 判定已优先消费动作级失败信息，相关失败统计与 skip 行为已完成定向验证
- [x] P2-Gamma 核心已完成：`config.json["venv"]["python_path"]` 已成为唯一 Python 真值源，`tools.py` / `toolkit/base.py` / `utils/python_runner.py` / `toolkit/fenjing.py` 已收敛到 shared runtime，`tool_node.success` 已与 memory step success 对齐，并完成 shared runtime / success 语义相关定向验证
- [x] 本轮定向验证已完成：graph/planner 最小闭环、help/resume continuity、RAG-before-help 最小 hard gate 与 shared runtime 核心语义均已核对
- [x] RAG-before-help 最小 hard gate 已落地：`agent_core.py::maybe_request_help()` 命中 help 阈值后，会先执行一次 `retrieve_rag_knowledge(...)`，并把 `rag_query/rag_summary/rag_suggested_approach` 写入 `ShortMemory.context` 供下一轮 planner 消费；仅在同一失败窗口再次命中时才真正进入 help
- [x] RAG-before-help 自动化回归已补齐：`tests/test_rag_before_help.py` 已覆盖“首次命中先 RAG、同窗口二次命中再 help、resume 后重置 RAG gate”三段行为
- [x] `init_problem()` 已收敛出结构化分类结果：当前已返回 `problem_type`、`classification_confidence`、`classification_source`、`classification_evidence`、`classification_reasoning`，并继续向 `AgentContext` / `loaded_resources` 传递
- [x] 初始化分类漂移已完成第一轮修复：`phpinfo()` / 信息泄露优先级已上提，`initialize_challenge()` 中 hint 仅在低置信初始化结果下做兜底增强，不再默认降级覆盖
- [x] 已接入可降级的 LLM-first 分类入口：`tools.py` 现已先尝试 `_classify_problem_with_llm(...)`，仅在模型不可用 / 出错 / 低置信时退回 heuristic
- [x] resource bundle 已完成第一轮统一：`tools.py` 已新增 `_resolve_skill_resources()`、`_resolve_long_memory_resources()`、`_resolve_wooyun_resources()`、`_assemble_resource_bundle()`，并让 `init_problem()` / `get_available_resources()` 统一消费同一套资源装配结果
- [x] `build_advisor_context()` 已暴露标准化资源视图：包含 `canonical_problem_type`、`classification_*` 字段、`taxonomy_signals` 与更明确的 `resource_summary`
- [x] **auth 执行流 drift 修复已完成（2026-03-26）**：
  - `tactic_family` / `resource_source` 元数据保留：`agent_core.py` 的 `_action_candidate_summary()` (line 852) 与 `_build_action_from_candidate()` (line 1016) 现已保留和恢复这两个字段
  - `auth-sqli` 阶段门槛收紧：`_auth_progress_state()` (line 2671) 的 `structured_auth_signal` 判断已收紧（必须有 `endpoint_enum_confirmed` 或确认的 endpoint + 多参数），`_required_tactic_families()` (line 1732) 的 auth-sqli 现只在 `endpoint_enum_confirmed` 为 true 时加入
  - auth 目标避免退化到 dir_scan：`low_yield_probe_loop` 分支 (line 3015) 与通用失败处理 (line 2987) 中的 auth 目标优先返回 `recon` + `auth-recover` 而非 `dir_scan`
  - 回归测试已补齐：`tests/test_auth_replan_degradation.py` 新增 6 个测试用例覆盖 metadata 保留、auth-sqli 门控、dir_scan 退化防护


## 1. 背景与目标
- [x] 入口断层的第一步已修补：`AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，技能、长期记忆与 WooYun 可在主入口初始化阶段装载。
- [x] Planner/Executor 契约已收敛到第一版：`_build_action()` / `plan_next_action()` / `action_handlers` 已统一动作结构，`attack_step` / `recon` / `ua_test` / `sqlmap_scan` / `dir_scan` 等动作均可落到 executor；`_should_ask_for_help()` 与异常路径记忆也已对齐 canonical tool 名称。
- [x] help-resume continuity 已打通：Agent 触发求助后，可在不重新初始化题目、不重置短期记忆的前提下，基于人工提示继续沿同一主链运行。
- [~] **题型识别仍过度依赖 heuristic / keyword match**：当前已接入可降级的 LLM-first 分类入口，`init_problem()` 会优先尝试 `_classify_problem_with_llm(...)`，仅在模型不可用 / 出错 / 低置信时退回 heuristic；但统一模型调用层、分类结果在更多模块的深度消费、以及 `long_memory.py` / `skills/skill_loader.py` 中残留的独立识别逻辑仍未完全收敛。
- [~] **知识与记忆断链**：第一轮 `resource_bundle` 已统一到 `tools.py`，`init_problem()` / `get_available_resources()` / `build_advisor_context()` 已共享 taxonomy + resource summary；但 `long_memory.py`、`skills/skill_loader.py`、WooYun / RAG 与 planner policy 之间仍未完全形成统一保存/回灌闭环。
- [~] **工具环境统一已完成核心阶段**：`config.json["venv"]["python_path"]` 已成为唯一真值源，但 README 驱动适配器化、逐工具迁移与更细粒度 `artifacts/parsed` 解析仍未完全收口。

**目标**：在不回退 P0-P2 稳定性的前提下，继续把 P3 从“最小 graph 读写闭环”推进到“主链稳定 + LLM 优先题型识别 + 统一资源消费链 + 更强的 PoG / 因果图 / Reflector / RAG-before-help 闭环”。

## 1.5 强制执行顺序口径（与 `CLAUDE.md` 对齐）
> 本节描述的是项目要求的规范顺序，不等同于所有环节都已在代码中 100% hard gate；当前已落地的是 orchestrator / `init_problem()` / 主循环 / help-resume 骨架，以及“同一失败窗口内先主动 RAG、再进入 help”的最小 gate，taxonomy / 长期记忆 / 更深的 RAG 闭环仍需继续收敛。

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
4. [x] **RAG-before-help 最小硬门已补齐**：`maybe_request_help()` 命中 help 阈值后，现会先执行一次 `retrieve_rag_knowledge(...)`，把结果写回 `AgentContext` / `ShortMemory.context` 并暴露到 `build_advisor_context()`；同一失败窗口再次命中时才真正求助，`resume` 后会重置当前窗口的 RAG gate。
5. [ ] **知识与记忆断链**：skills、`long_memory/experiences`、`auto_experiences`、WooYun 皆存在，但没有共享分类或统一加载/保存回路。
6. [x] **工具执行不可预测（核心）**：shared runtime / `ToolResult` / success 语义已完成核心收敛，但 README 驱动适配器化与逐工具迁移仍可继续完善。
7. [x] **短期记忆精度不足（核心）**：失败统计、skip 与重试判定已优先升级到 `action_id` 粒度。
- [~] **图结构能力已具备最小读写闭环**：`graph_manager.py`、`GraphOp`、checkpoint、`shared_findings`、`planner_signals()` 与 graph-driven replanning 已接入主链；最近已新增 finding-lineage 摘要、blocked lineage / avoid lineage、以及低收益 probe loop suppression，但完整 PoG、Reflector、因果边消费与图驱动深度重规划还未完成。

## 3. 当前优先级判断
- 当前最大断点已经从“help 后无法继续”转向“P3 已具备最小闭环，但 LLM 分类、统一 resource bundle 与 planner 深度消费还未完全收口”。
- 现阶段判断：
  1. `ShortMemory` 失败统计已切到 `action_id` 优先
  2. 工具执行环境与成功语义已完成核心收敛
  3. P3-Alpha 最小闭环已完成：planner 已能消费 guidance / endpoint / parameter / repeated-failure signals
  4. graph-driven reflector 已有第一批 branch-level signals：`finding_lineages`、`blocked_findings`、`finding_failure_counts`、`finding_attempt_counts`
  5. `_collect_graph_informed_actions()` 已开始从 challenge-specific 分支收敛到 finding-family 驱动，低收益 probe loop 已纳入统一 suppression
  6. 初始化分类漂移已完成第一轮修复，且已具备可降级的 LLM-first 分类入口
  7. `resource_bundle` 与 `build_advisor_context()` 已完成第一轮标准化，但尚未完全渗透到所有资源入口与 planner policy
  8. **auth 执行流 drift 已完成修复**：tactic_family/resource_source metadata 保留、auth-sqli 门控收紧、auth 目标避免退化到 dir_scan 均已完成并补齐回归测试
- 因此下一阶段顺序调整为：
  1. **Phase 2-C：继续收敛 `long_memory.py` / `skills/skill_loader.py` 的独立识别逻辑，统一到分类结果与 resource bundle**
  2. **P3-Gamma：让 Planner / Reflector 更系统地消费 `classification_*`、`resource_summary`、`graph_state` / `shared_findings` / `planner_signals()`**
  3. **工具结构化输出：把 `parsed/artifacts` 真正提升为 planner 一等输入**

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
   - [x] `_should_ask_for_help()`、异常路径记忆与 executor 日志已与 canonical tool 名称、`action_id/action_type` 元信息对齐；动作失败聚合已由 `ShortMemory` 升级到 `action_id` 优先。

3. **主链恢复闭环（P2-Alpha）**
   - [x] `orchestrator.py` 已补齐 resume 相关状态字段，并新增 `resume(human_guidance)`。
   - [x] `AutoAgent` 已支持基于人工提示恢复，同链路继续，不重新初始化。
   - [x] `AgentContext` / `ShortMemory` 已记录 `human_guidance`、`help_history`、`resume_count`。
   - [x] `build_advisor_context()` 已显式暴露人工提示与历史求助信息。
   - [x] 已完成 help/resume continuity 与 `ShortMemory.add_patch()` / `get_patch_summary()` 相关链路核对。

4. **失败统计升级（P2-Beta）**
   - [x] `_should_ask_for_help()`、重复尝试判定、失败趋势统计已优先消费动作级别信息。
   - [x] `ShortMemory` 已支持 `action_id` 主键化失败记录，并完成 `latest_step_for_action()` / `should_skip_action()` 等核心失败统计行为核对。

5. **工具执行 & 成功语义统一（P2-Gamma）**
   - [x] `toolkit/base.py` 已成为唯一 Python 执行出口的核心收敛点；硬编码路径、`sys.executable` 等多头环境逻辑已收敛到 shared runtime / `config.json["venv"]["python_path"]`。
   - [x] 工具返回结构与 success 语义已基本收敛，ToolNode / memory logging / help 判定共享同一套成功语义。

6. **PoG / 因果图增强（P3）**
   - [x] 已引入 `graph_manager.py` 维护 Shadow Graph Layer：包含 `GraphNode` / `GraphEdge` / `GraphOp` / `SharedFinding`，并可输出 `planner_signals()` / `snapshot()` / `summary()`。
   - [x] RAG-before-help 最小 hard gate 已补齐：`agent_core.py::maybe_request_help()` 达到 help 阈值时会先调用 `retrieve_rag_knowledge(...)`，把 `rag_query`、`rag_summary`、`rag_suggested_approach` 写入 `ShortMemory.context` 并暴露给 `build_advisor_context()`；仅在同一失败窗口再次命中时才真正进入 help。
   - [x] `short_memory.py` 已承载最小 RAG gate 状态，并在 `apply_human_guidance()` / resume 后清理当前窗口状态，确保恢复后可以重新经历一次“先 RAG、再 help”的决策阶段。
   - [x] 已新增自动化回归 `tests/test_rag_before_help.py`，覆盖“首次命中先 RAG、同窗口二次命中再 help、resume 后 gate reset”。
   - [~] Planner 产出的 action 已附带 `graph_op`，Executor / ToolNode / help / resume 已能回写节点状态与 checkpoint；`_build_graph_informed_action()` 已能消费 guidance / endpoint / parameter / repeated failure，`graph_manager.py` 已新增 `finding_lineages` / `blocked_findings` / `finding_failure_counts` / `finding_attempt_counts`，`agent_core.py` 已接入 finding-lineage replan metadata、guidance-family candidate 生成与 low-yield probe loop 抑制；但完整 PoG / Reflector 驱动重规划仍未落地。
   - [~] `shared_findings` 已从短期记忆、help_history、human_guidance、target facts 中提取并注入 `AgentContext` / `OrchestratorState`，且 `OrchestratorState` 已额外暴露 `replan_reason` / `blocked_findings` / `selected_alternative`；但更强的因果图、共享发现消费链路与主动 RAG 联动仍待继续增强。

## 5.6 下一阶段架构原则（本轮新增）
- [x] **先修框架可运行性，再增强能力**：主链稳定运行、初始化分类不漂移、planner/executor/memory/help 语义一致，优先级高于继续补单题利用链。
- [x] **题型识别由 LLM 优先负责**：`tools.py` 已具备可降级的 `_classify_problem_with_llm(...)`，初始化阶段会优先尝试模型分类，仅在模型不可用 / 低置信时退回 heuristic。
- [x] **识别题型后统一消费资源**：`resource_bundle` 第一轮统一已完成，`init_problem()`、`get_available_resources()`、`build_advisor_context()` 已共享同一套 taxonomy + resource summary。
- [~] **避免在 `agent_core.py` / `tools.py` 中继续堆单题特判**：当前路线已切到分类结果、resource bundle、finding family、normalized context 驱动；但仍需继续清理其他模块中的残留特判与独立识别逻辑。
- [x] **保持现有主链优势**：即 `orchestrator/main -> init_problem -> 先消费资源 -> Advisor/Planner/Executor/ToolNode -> RAG-before-help -> help/resume`，本轮新增改动均未绕开该主链。

- [~] **统一高价值侦察信号抽取层**：已完成第一批通用 taxonomy 与传播链路，`ShortMemory.add_step()` → `GraphManager.refresh_shared_findings()` → `planner_signals()` 已能稳定传播 `repo_exposure`、`backup_file`、`sensitive_file`、`debug_page`、`source_leak`、`shell_artifact`、`info_leak`、`parameter`、`endpoint`；但尚未与 long memory / skills / RAG 形成统一保存与回灌闭环。
- [~] **补 `recon -> exploit-family` 的通用阶段切换**：`_build_verification_action_from_finding()`、`_collect_graph_informed_actions()` 与 lineage-aware ranking 已接入第一版 finding-family 驱动，且 guidance 已开始走统一 family 入口；但仍有剩余 challenge-specific 分支需要继续压缩，尚未形成更完整的 PoG/Reflector policy。
- [~] **增强定向验证动作生成，而不是增强单题 payload**：当前已能围绕 `priority_findings` / `verification_hints` / `blocked_findings` 生成 finding-backed candidate，并把 `verification_family` / `source_finding_kind/value` 带入 replan 与排序；但更系统的相邻路径验证、lineage 切换与 family 级 alternative policy 仍可继续增强。
- [~] **继续抑制低收益循环动作**：已不再只抑制最小 `dir_scan` 熔断；finding-lineage suppression、blocked lineage、avoid lineage 与 `low_yield_probe_loop` 已落地到 replan payload / candidate ranking / `_decide_next_action()`，但对更多轻量 fallback 形态的统一判定仍可继续推广。**本轮已增强 auth 目标的低收益循环抑制**：auth 目标在 `low_yield_probe_loop` 与通用失败分支中不再退化到 `dir_scan`，而是优先返回 `recon` + `auth-recover`。
- [ ] **把工具结构化输出真正接入规划闭环**：P2-Gamma 已修正 success 契约，但下一步重点仍应是让工具 `parsed/artifacts` 成为 Planner 的一等输入，使”工具发现 -> memory -> graph -> planner -> 下一步动作”形成稳定闭环，而不是只修日志或记账语义。
- [x] **优先优化框架流程，不优先优化单题利用链**：本轮新增工作已持续按 graph-driven replanning、finding taxonomy、finding-family candidate 与低收益 suppression 推进，没有再回退到单题特判路线。本轮 auth drift 修复也是框架级改进，不针对单题。

- [x] `main.py` / `orchestrator.py` / `agent_core.py` 已形成项目级唯一主链。
- [x] help-resume continuity 已不再是阻塞项。
- [x] P2-Beta / P2-Gamma 核心能力已落地，当前不应再把它们当作下一阶段阻塞项。
- [x] RAG-before-help 最小 hard gate 已落地，并已有 `tests/test_rag_before_help.py` 自动化回归覆盖。
- [~] P3-Alpha 最小闭环已完成：graph 写路径、planner 读路径与最小 graph/planner 回归已打通；本轮已补齐 auth stage progression 与 metadata 保留修复。
- [x] 当前定向验证已完成：graph/planner 最小闭环、help/resume continuity、RAG-before-help 最小 hard gate、shared runtime 核心语义均已核对。
- 下一步应继续补齐 P3-Beta / P3-Gamma 以及 taxonomy / 长期记忆闭环，而不是回退到已完成的 P2 事项。

---

## 6. Planner 重构：AI 决策 + 框架辅助检索模式

### 6.1 当前问题

**现状**：
- `agent_core.py` 中有大量硬编码的 if/else 规则：
  - `if auth_stage == "weak-creds": ...`
  - `if auth_stage == "endpoint-enum": ...`
  - `if auth_stage == "auth-sqli": ...`
  - `if low_yield_probe_loop: return dir_scan`
  - `if repeated_dir_scan_without_new_findings: ...`
- AI 只在 `Advisor` 环节参与决策，但动作选择已经被规则写死了
- 框架强制决定了"下一步应该做什么"，而不是"AI 决定下一步做什么"

**问题**：
- 规则永远写不完：新增一个题型就要加一套 if/else
- AI 能力被浪费：大模型可以理解上下文并做出智能决策，但没有被利用
- 维护困难：每个规则都是特判，越积越多

### 6.2 目标架构

**核心理念**：
- **AI 是决策主体**：把完整上下文给 AI，让 AI 决定下一步
- **框架是辅助**：
  - 构建上下文（memory、graph、skills、RAG、resources）
  - 执行工具
  - 存储记忆
  - 不硬编码动作选择

**工作流程**：
```
框架构建上下文 → AI 决策 → 框架执行 → 记忆沉淀 → 循环
```

### 6.2.1 框架 vs AI 的边界

**框架的优势（应该保留）**：
| 能力 | 说明 |
|------|------|
| 记忆存储 | 存储和检索历史步骤、失败次数、flag 候选 |
| 工具执行 | 安全地执行外部工具（dirsearch、sqlmap 等） |
| 结构化提取 | 从非结构化文本中提取 endpoints、parameters、findings |
| 状态跟踪 | 跟踪失败次数、轮次、已尝试的工具 |
| 安全 guardrails | 限制危险操作（如无限制的暴力破解） |

**AI 的优势（应该发挥）**：
| 能力 | 说明 |
|------|------|
| 语义理解 | 理解"这个登录页面可能有弱口令"、"这个参数可能有注入" |
| 推理能力 | 从少量线索推理出潜在攻击路径 |
| 适应性 | 处理规则未覆盖的新情况 |
| 创造力 | 组合不同的攻击思路 |

**关键原则**：
- 框架不决定"做什么"，只提供"有什么"
- AI 基于框架提供的信息决定"做什么"
- 框架的规则应该是"安全约束"，不是"动作选择"

### 6.3 具体改动

#### 6.3.1 构建 AI 友好的上下文

**当前已有（需要整合）**：
- `ShortMemory.steps`：历史步骤
- `ShortMemory.target`：目标信息（endpoints、parameters）
- `graph_manager.planner_signals()`：图信号（priority_findings、blocked_findings、failed_tools）
- `AgentContext`：问题类型、skill、rag_summary、loaded_resources

**需要新增**：
- `action_history_summary`：用自然语言描述已尝试的动作和结果
- `finding_summary`：用自然语言描述已发现的高价值线索
- `failure_summary`：用自然语言描述失败原因和模式
- `available_tools`：当前可用的工具列表
- `resource_summary`：当前加载的技能和资源

#### 6.3.2 重构 Planner 决策点

**当前代码结构**：
```python
def _decide_next_action():
    if self.target_type == "auth":
        auth_state = self._auth_progress_state()
        if auth_stage == "weak-creds" and not has_successful_poc:
            return poc_action
        if auth_stage == "endpoint-enum":
            return recon_action
        if auth_stage == "auth-sqli":
            return sqlmap_action
    # ... 更多 if/else
```

**目标代码结构**：
```python
def _decide_next_action():
    context = self._build_decision_context()
    decision = self._ai_decide(context)
    return self._build_action_from_decision(decision)
```

#### 6.3.3 AI 决策 Prompt 设计

**输入**：
```
## 当前目标
- URL: {target_url}
- 题型: {problem_type}
- 描述: {description}

## 已发现线索
{findings_summary}

## 历史动作
{action_history_summary}

## 失败模式
{failure_summary}

## 可用资源
{resource_summary}

## 可用工具
{available_tools}

## 问题
基于以上信息，你认为下一步应该做什么？请选择：
1. 工具名称（如 dirsearch、recon、sqlmap）
2. 目标（如具体 URL 或参数）
3. 理由（为什么选择这个动作）

请用 JSON 格式返回：
{{"tool": "...", "target": "...", "reason": "..."}}
```

#### 6.3.4 框架辅助检索能力

**在 AI 决策前，框架可以做**：
- 把相关技能（skill）提取出来，放到上下文中
- 把长期记忆中的相关经验提取出来
- 把 RAG 中的相关知识提取出来

**AI 不需要知道具体怎么实现**，只需要知道"有什么资源可用"。

### 6.4 实施步骤

#### Phase 1: 搭建上下文构建层
1. 新增 `_build_decision_context()` 方法
2. 整合现有的 memory、graph、resources 到统一上下文
3. 测试上下文构建是否完整

#### Phase 2: 搭建 AI 决策层
1. 新增 `_ai_decide()` 方法，调用 LLM 做决策
2. 设计 prompt，让 AI 理解上下文并做出合理决策
3. 处理 AI 返回的决策，转成 action

#### Phase 3: 移除硬编码规则
1. 逐步移除 `_decide_next_action()` 中的 if/else
2. 保留必要的 fallback（如初始动作）
3. 验证 AI 决策的效果

#### Phase 4: 优化和迭代
1. 收集 AI 决策案例，分析问题
2. 优化 prompt，提高决策质量
3. 添加约束，防止 AI 做出危险决策

### 6.5 预期收益

- **减少代码量**：移除大量 if/else 规则
- **提高泛化能力**：AI 可以处理规则未覆盖的情况
- **更好利用 AI 能力**：让大模型的推理能力发挥作用
- **更容易维护**：新增题型不需要加规则，只需要提供相关资源

### 6.6 风险和缓解

| 风险 | 缓解 |
|------|------|
| AI 决策质量不稳定 | 提供足够的上下文和约束 |
| AI 可能做出危险决策 | 保留框架级别的安全检查 |
| 增加 token 消耗 | 优化 prompt，控制上下文长度 |

### 6.7 AI 决策 Prompt 改进版

**核心原则**：
- AI 需要知道"已尝试过什么"（避免重复）
- AI 需要知道"已发现什么"（利用线索）
- AI 需要知道"有什么资源可用"（借助外力）
- AI 需要给出"决策理由"（便于调试和理解）

**完整 Prompt 结构**：
```
## 任务
你是一个 CTF 解题助手。你的目标是通过分析当前情况，决定下一步应该做什么。

## 目标信息
- URL: {target_url}
- 题型: {problem_type} (如 auth, sqli, xss, lfi 等)
- 提示: {hint}

## 上下文摘要

### 已发现的线索（由框架从历史步骤中提取）
{findings_summary}

### 历史动作（由框架从历史步骤中提取）
{action_history_summary}

### 失败分析（由框架从失败步骤中提取）
{failure_summary}

### 已加载的资源
{resource_summary}

## 可用工具
- recon: 信息收集（访问页面、提取链接、参数）
- dirsearch: 目录扫描
- sqlmap: SQL 注入检测
- python_poc: 执行自定义 POC
- source_analysis: 源码分析
- 其他工具...

## 决策要求

1. **分析当前情况**：基于上述上下文，理解目标的当前状态
2. **选择下一步动作**：
   - 工具名称（如 recon, dirsearch, sqlmap, python_poc）
   - 目标（如具体 URL、参数、目标）
   - 具体参数（如扫描深度、payload 类型）
3. **给出理由**：解释为什么选择这个动作
4. **考虑约束**：
   - 不要重复已失败的尝试
   - 利用已发现的线索
   - 结合可用资源

## 输出格式
请用 JSON 格式返回你的决策：
{
  "tool": "工具名称",
  "target": "具体目标",
  "params": {"参数": "值"},
  "reason": "决策理由（50字以内）"
}
```

### 6.8 框架安全约束设计

**需要保留的硬编码约束**（不是动作选择，而是安全限制）：

| 约束 | 说明 |
|------|------|
| max_steps | 最多执行步数 |
| max_failures_per_action | 单个动作最大失败次数 |
| rate_limit | 请求频率限制 |
| dangerous_tools | 危险工具的使用限制（如 sqlmap 的 --risk 参数） |
| timeout | 单个工具的最大执行时间 |

**约束的实现方式**：
```python
def _ai_decide(context):
    decision = llm.decide(context)

    # 安全检查
    if decision["tool"] == "sqlmap" and decision["params"].get("risk", 1) > 2:
        decision["params"]["risk"] = 2  # 降级

    if self._exceeds_rate_limit(decision):
        raise RateLimitError()

    return decision
```

### 6.9 迁移策略

**渐进式迁移**：
1. **保留现有框架逻辑**，新增 AI 决策作为 fallback
2. **AB 测试**：同一目标同时跑旧逻辑和新逻辑，对比效果
3. **逐步替换**：从简单的题型开始，用 AI 决策替换硬编码逻辑

**迁移顺序建议**：
1. 先迁移 `auth` 类型（当前问题最多）
2. 再迁移 `sqli` 类型
3. 最后迁移其他类型

### 6.10 效果评估

**如何评估 AI 决策的效果**：
- 是否比硬编码逻辑更好地利用线索
- 是否能处理未预见的情况
- token 消耗是否在可接受范围
- 决策质量是否稳定

---

## 7. 框架级改进：AI 驱动的上下文 + 记忆增强

### 7.1 现有组件整合

**已实现的组件**：
| 组件 | 现状 | 改进方向 |
|------|------|----------|
| ShortMemory | 存储步骤、失败统计 | 增加失败分析、语义摘要 |
| graph_manager | 维护 shared_findings、planner_signals | 增加线索价值评估、优先级排序 |
| AgentContext | 存储问题类型、skill、rag_summary | 融入攻击策略层级 |
| skills | 提供题型知识 | 融入工具语义库 |
| long_memory | 提供历史经验 | 融入自我反思机制 |

### 7.2 失败分析层（改进 ShortMemory）

**状态**：✅ 已实现（在 `_summarize_failures` 方法中）

**当前问题**：只记录"失败"，不记录"为什么失败"

**改进方案**：
```python
class ShortMemory:
    def add_step(self, ..., key_findings=None, failure_analysis=None):
        # failure_analysis: 框架自动提取的失败原因
        # - "无注入点"
        # - "密码错误"
        # - "权限不足"
        # - "页面无变化"

    def get_failure_summary(self) -> str:
        # 生成自然语言形式的失败摘要
        # "已尝试 3 次弱口令爆破，均失败，错误信息为'密码错误'"
```

**框架应该做的**：
1. 从工具输出中提取关键错误信息
2. 归类失败类型（无反馈、错误反馈、异常）
3. 生成 AI 可读的失败摘要

### 7.3 攻击策略层级（新增）

**状态**：✅ 部分实现（AI 决策 prompt 中包含策略思考引导）

**当前问题**：AI 只知道"下一步做什么"，不知道"整体策略"

**改进方案**：

```
## 攻击策略（由 AI 根据上下文决定）

### 阶段 1：信息收集
任务：了解目标的基本情况
- 需要的信息：页面结构、端点、参数、技术栈
- 可用动作：recon, dirsearch, source_analysis

### 阶段 2：漏洞发现
任务：基于收集的信息，发现潜在漏洞
- 需要的信息：可测试的端点、参数、认证点
- 可用动作：参数测试, 注入检测, 弱口令测试

### 阶段 3：漏洞利用
任务：利用发现的漏洞获取 flag
- 需要的信息：已确认的漏洞点
- 可用动作：sqlmap, 爆破, POC 执行

AI 决策时应该思考：
- 当前在哪个阶段？
- 这个阶段需要什么信息？
- 现有信息够不够进入下一阶段？
```

### 7.4 线索价值评估（改进 graph_manager）

**状态**：⏳ 待实现（当前使用 `priority_findings`）

**当前问题**：所有发现平铺，AI 不知道哪些重要

**改进方案**：
```python
class GraphManager:
    def evaluate_finding_value(self, finding: dict) -> float:
        # 评估线索价值
        # - 来源可靠性 (dirscan: 0.8, recon: 0.6)
        # - 内容相关性 (与问题类型的关联)
        # - 可利用性 (是否能直接用来攻击)
        return score

    def get_priority_findings(self) -> list:
        # 返回排序后的高价值线索
        # 而不是所有平铺的 findings
```

### 7.5 上下文压缩机制（新增）

**状态**：⏳ 待实现

**问题**：上下文随步数增长，token 消耗增加

**改进方案**：
```python
def compress_context(context: dict, max_tokens: int) -> dict:
    """
    压缩策略：
    - 早期步骤：只保留关键结论
    - 失败步骤：只保留失败原因
    - 有效步骤：完整保留
    """

    # 示例：
    # 原始："访问 index.php，响应 200，页面包含 1234 行 HTML..."
    # 压缩："已确认 index.php 可访问，返回登录页面"
```

### 7.6 工具语义库（新增）

**状态**：✅ 已实现（在 `_get_available_tools` 方法中）

**问题**：AI 不知道每个工具适合什么场景

**改进方案**：
```python
TOOL_SEMANTICS = {
    "recon": {
        "适用": "需要了解目标页面内容",
        "输出": "页面结构、链接、参数、form",
        "局限": "只能访问已知页面",
        "成本": "低",
    },
    "dirsearch": {
        "适用": "需要发现隐藏页面或目录",
        "输出": "目录、文件列表",
        "局限": "需要猜测路径字典",
        "成本": "中",
    },
    "sqlmap": {
        "适用": "已确认存在 SQL 注入的参数",
        "输出": "数据库信息、数据",
        "局限": "需要已知注入点",
        "成本": "高",
    },
    # ...
}
```

**AI 决策时应该理解**：
- 不是"找不到路就 dirsearch"
- 而是"需要发现更多页面时用 dirsearch"

### 7.7 自我反思机制（新增）

**状态**：✅ 已实现（在 `_should_self_reflect` 和 `_do_self_reflect` 方法中）
- 触发条件：连续3次失败、最近5步无新发现、工具选择陷入循环

**问题**：AI 不会从失败中学习，重复尝试相同策略

**改进方案**：
```python
class SelfReflection:
    TRIGGERS = [
        "连续 3 次同类动作失败",
        "超过 5 步没有新发现",
        "工具选择陷入循环",
    ]

    def should_reflect(self, memory: ShortMemory) -> bool:
        # 检查是否触发反思条件

    def reflect(self, context: dict) -> str:
        # 反思内容：
        # 1. 到目前为止尝试了哪些方法？
        # 2. 为什么这些方法失败了？
        # 3. 是否有遗漏的攻击面？
        # 4. 应该尝试什么新方向？
```

**触发条件**：
- 连续 3 次同类动作失败
- 超过 5 步没有新发现
- 工具选择陷入循环

### 7.8 Hint 融入决策（改进 init_problem）

**状态**：✅ 已实现（在 `_interpret_hint` 方法中）

**当前问题**：hint 没有被融入 AI 决策上下文

**改进方案**：
```python
def _build_decision_context(self) -> dict:
    # 确保 hint 被正确融入
    context = {
        ...
        "hint": self.agent_context.hint or "无",
        "hint_interpretation": self._interpret_hint(
            self.agent_context.hint,
            self.agent_context.problem_type
        ),
        ...
    }

def _interpret_hint(self, hint: str, problem_type: str) -> str:
    """将 hint 转化为 AI 可理解的策略建议"""
    # "好像没有" → "常见的弱口令可能不行，需要尝试其他攻击面"
    # "admin" → "可能存在 admin 相关路径或用户"
```

### 7.9 完整架构图

```
┌─────────────────────────────────────────────────────────────┐
│                      框架层                                 │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ ShortMemory  │  │ GraphManager │  │ AgentContext │     │
│  │ - 步骤存储   │  │ - 线索管理   │  │ - 问题类型   │     │
│  │ - 失败分析   │  │ - 价值评估   │  │ - skill     │     │
│  │ - 上下文压缩 │  │ - 优先级排序 │  │ - rag       │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  ┌──────────────────────────────────────────────────┐     │
│  │              上下文构建器                          │     │
│  │ - 失败摘要生成                                    │     │
│  │ - 线索摘要生成                                    │     │
│  │ - 攻击策略推断                                    │     │
│  │ - Hint 解读                                       │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      AI 决策层                               │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────┐     │
│  │              AI 决策 Prompt                       │     │
│  │ - 当前目标                                        │     │
│  │ - 已发现线索（优先级排序）                        │     │
│  │ - 历史动作 + 失败分析                             │     │
│  │ - 攻击策略层级                                    │     │
│  │ - 工具语义库                                      │     │
│  │ - 自我反思（触发时）                              │     │
│  └──────────────────────────────────────────────────┘     │
│                              │                             │
│                              ▼                             │
│  ┌──────────────────────────────────────────────────┐     │
│  │              决策输出                             │     │
│  │ - tool: 工具名称                                  │     │
│  │ - target: 目标                                    │     │
│  │ - params: 参数                                    │     │
│  │ - reason: 理由                                    │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      执行层                                  │
├─────────────────────────────────────────────────────────────┤
│  - 工具执行                                               │
│  - 结果解析                                               │
│  - 记忆沉淀                                               │
│  - 安全约束检查                                           │
└─────────────────────────────────────────────────────────────┘
```

### 7.10 实施优先级

| 优先级 | 改进项 | 状态 |
|--------|--------|------|
| P0 | 上下文构建器 | ✅ 已完成 |
| P1 | 失败分析层 | ✅ 已完成 |
| P2 | 攻击策略层级 | ✅ 已完成（prompt 引导） |
| P3 | 线索价值评估 | ⏳ 待实现 |
| P4 | 工具语义库 | ✅ 已完成 |
| P5 | 自我反思机制 | ✅ 已完成 |
| P6 | 上下文压缩 | ⏳ 待实现 |
| P7 | Hint 融入 | ✅ 已完成 |

