# CHYing 参考重构方案

## 0. 当前落地进度（基于当前代码静态检查）
> 说明：以下勾选基于当前仓库实现与 `py_compile` 静态核对；本文尚未执行完整运行时验证。

- [x] `AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，主入口不再绕过知识加载链路（`agent_core.py:344-363`）
- [x] `AgentContext` 已落到 `ShortMemory.context`，并与 `target.url/problem_type` 同步（`short_memory.py:66-75`，`short_memory.py:233-246`）
- [x] `get_agent_context()` / `reset_memory()` / `init_problem()` 已形成 P0 基础上下文管道（`tools.py:68-79`）
- [x] `min_steps_before_help` help guardrail 已实现（`agent_core.py:321-355,1237-1309`）
- [x] CLI / orchestrator 级“唯一主循环”已落地：`main.py` 默认进入 `orchestrator.main()`，由 `CTFOrchestrator.initialize_challenge()` → `AutoAgent.initialize_challenge()` 统一接入 `init_problem()`，再由 `CTFOrchestrator.run()` → `AutoAgent.run_main_loop()` 驱动主链（`main.py:1-8`，`orchestrator.py:140-229`，`agent_core.py:363-395,801-929`）
- [x] `ActionSchema` / dispatch table 已落地第一版：已具备统一 `action = {id, type, target, description, intent, expected_tool, params}` 结构、`plan_next_action()` 规范化出口、`action_handlers` 分发表，以及 `attack_step` → 实际工具名的 canonical 映射（`agent_core.py:321-349,470-565,1035-1159`）
- [x] `orchestrator.py` / 结构化 `agent_state` 已落地第一版：已具备 `messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request` 等状态字段，并能记录 Advisor / Planner / Executor / ToolNode / help 事件（`orchestrator.py:31-207`）
- [ ] `graph_manager.py` / PoG / `GraphOp` / `shared_findings` 尚未落地
- [ ] 工具执行环境与成功语义尚未统一（`tools.py`、`toolkit/base.py`、`toolkit/fenjing.py` 仍并存多套路径与判定逻辑）

## 1. 背景与目标
- [x] 入口断层的第一步已修补：`AutoAgent.solve_challenge()` 已接入 `tools.init_problem()`，技能、长期记忆与 WooYun 可在主入口初始化阶段装载（`agent_core.py:344-363`；`tools.py:79-216`）。
- [x] Planner/Executor 契约已收敛到第一版：`_build_action()` / `plan_next_action()` / `action_handlers` 已统一动作结构，`attack_step` / `recon` / `ua_test` / `sqlmap_scan` / `dir_scan` 等动作均可落到 executor；`_should_ask_for_help()` 与异常路径记忆也已对齐 canonical tool 名称（`agent_core.py:470-565,665-769,1035-1159,1237-1309`）。
- [ ] 类型体系与记忆链路仍漂移：短期记忆仍以粗粒度去重为主，长期记忆、技能与 RAG 之间还没有统一 taxonomy 与保存闭环（`架构审计报告.md:353-409, 495-538`）。
- [ ] 工具环境仍多头管理：`toolkit/base.py` 已读取 `config.json["venv"]["python_path"]`，但 `tools.py` 与 `toolkit/fenjing.py` 仍存在 `workon`、硬编码 Python 路径、`sys.executable` 等并存逻辑（`tools.py:648,705-757`；`toolkit/base.py:63,151-181`；`toolkit/fenjing.py`）。

**目标**：结合 CHYing LangGraph 三层架构与 LuaN1aoAgent 的 P-E-R / PoG 设计，打通初始化→知识加载→规划→执行→记忆→比赛 API / HITL 的唯一主链，并给出分阶段的可复现重构蓝图。

## 2. “唯一真链路”缺口定位
1. [x] **入口断层**：`AutoAgent.solve_challenge()` 已调用 `init_problem()`；`main.py` 现已默认进入 `orchestrator.main()`，并由 orchestrator 统一驱动初始化与唯一主循环，项目级入口骨架已打通（`main.py:1-8`；`orchestrator.py:140-229`；`agent_core.py:349-380,464-583`）。
2. [x] **动作语义第一版已收敛**：Planner 现通过 `ActionSchema` 风格动作字典输出，Executor 通过 `action_handlers` / `plan_next_action()` / canonical tool 映射统一执行；`attack_step` 的常见分支已可落地，`_should_ask_for_help()` 与异常路径记录也已改用实际工具名（`agent_core.py:470-565,665-769,1035-1159,1237-1309`）。
3. [ ] **知识与记忆断链**：skills、`long_memory/experiences`、`auto_experiences`、WooYun 皆存在，但没有共享分类或统一加载/保存回路（`架构审计报告.md:64-379`）。
4. [ ] **工具执行不可预测**：`execute_python_poc` 仍硬编码解释器，`toolkit/base.py` 与 `fenjing` 仍各自维护环境逻辑，成功语义也未统一（`tools.py:705-757`；`toolkit/base.py:63,108`）。
5. [ ] **短期记忆精度不足**：结果截断、去重忽略 header/cookie、flag 正则覆盖不足，使失败统计与求助判断仍可能失真（`架构审计报告.md:495-538`）。

## 3. CHYing 架构可复用模式
| 能力 | 参考文件 | 可借鉴点 |
| --- | --- | --- |
| 三层 LangGraph | `References/CHYing-agent-main/chying_agent/graph.py:1-745` | Advisor → Main Planner → 执行层（PoC/Docker） → ToolNode → 状态回写，确保规划与执行解耦，并通过 `pending_task` / `pending_flag` 实现显式路由。 |
| 结构化状态 | `References/CHYing-agent-main/chying_agent/state.py:17-174` | TypedDict + `compress_messages` 控制消息体积，`pending_task/pending_flag/consecutive_failures` 让路由有据可循。 |
| Recon 自动化 | `References/CHYing-agent-main/chying_agent/utils/recon.py:1-225` | 调用前自动收集表单、headers、title，带日志与 LLM 可读格式，可替换当前 ad-hoc `execute_python_poc` 的侦察手段。 |
| 比赛 API 守护 | `References/CHYing-agent-main/chying_agent/tools/competition_api_tools.py:11-512` | 带重试、速率限制、格式校验的 `submit_flag` / hint 工具，确保 FLAG 提交与提示请求稳定可追踪。 |
| 工具路由与记忆 | `graph.py:134-213`、`tool_node`、`route_after_*` | 统一工具执行入口，成功/失败写入状态层，便于触发 advisor / 求助逻辑。 |

## 4. LuaN1aoAgent 启发
1. **P-E-R 认知协作**：Planner 负责图编辑 + 并行调度，Executor 专注子任务工具调用并带上下文压缩，Reflector 负责失败归因与终止控制，避免单 Agent “人格分裂”（`References/LuaN1aoAgent-main/README.md:71-144`）。
2. **因果图谱驱动**：Evidence → Hypothesis → Vulnerability → Exploit 的显式链路，强制“证据先行”“置信度量化”，可解决当前 planner 盲猜、重复无效尝试的问题（`References/LuaN1aoAgent-main/README.md:99-128`）。
3. **Plan-on-Graph (PoG)**：Planner 输出 DAG 图编辑指令（`ADD_NODE/UPDATE_NODE/DEPRECATE_NODE`），实时插入 WAF 绕过、端口分支，拓扑排序自动识别可并行任务（`References/LuaN1aoAgent-main/README.md:129-158`）。
4. **工具/MCP 与共享公告板**：统一的 MCP Tool Server、共享 `shared_findings` 公告板、任务图 + 因果图双图持久化，支撑跨节点知识同步（`References/LuaN1aoAgent-main/README.md:159-410`）。
5. **HITL 与 Web UI**：Web Dashboard + SQLite 持久化 + HITL 审批/任务注入，给“遇到困难才求助”提供可视化入口（`References/LuaN1aoAgent-main/README.md:178-215`）。
6. **Benchmark 佐证**：PoG + 因果图 + Reflector 带来的 90.4% 成功率与低成本（`References/LuaN1aoAgent-main/xbow-benchmark-results/README.md:1-96`）。

**对当前 Agent 的直接指引**：
- 需要一个 `GraphManager` 将 planner 输出与执行节点绑定，同时提供 `shared_findings`（可由短期记忆升级而来）。
- 短期记忆应拆成“执行日志 + 因果证据”，Reflector 逻辑可复用 `_should_ask_for_help()` 的触发条件。
- 工具调用层需统一入口（可借 CHYing ToolNode），并为 PoG 节点附带 `expected_tool` / `success_criteria`。

## 5. ctfSolver ClaudeCode 原生 Agent 模式
1. **ClaudeCode 作为“超通用”大脑**：`flaghunter.py` 将 explorer / scanner / solutioner / executor / actioner 等子 Agent 串成单体 `FlagHunter`，每个任务都会创建 `tasks/<task_id>` 目录并落地页面/漏洞/POC 记录（`References/ctfSolver-master/agent/flaghunter.py:25-425`）。这套流程默认由 ClaudeCode 统一思考和提示，真实执行仍通过 CLI 进程完成，证明“ClaudeCode 中枢 + 外部执行器”完全可行。
2. **任务注册与心跳守护**：`AgentManager` 负责注册、心跳、任务轮询、状态/flag/消息上报，并将页面、漏洞、summary 通过 REST API 写入后端（`agent/utils/agent_manager.py:26-567`）。这一基建示范了如何在不引入 LangGraph 的前提下，靠 ClaudeCode + HTTP API + sqlite/Redis 即可支撑长期运行。
3. **统一知识/工具加载**：`agent/config/config.py:24-160` 把 API key、POC、payload、knowledge、addons 的入口都集中管理，并提供 `get_knowledge()` / `get_payload()` 等接口，可被 MCP 工具或 Pydantic-based Agent 直接引用，避免多套配置漂移。
4. **HITL 友好事件流**：FlagHunter 把探索/扫描/漏洞进度实时写入任务消息队列，并允许前端（`server/backend` + `server/frontend`）展示或注入任务（`flaghunter.py:56-425`）。这与期望的 ClaudeCode HITL 模式一致，可作为“人工在 ClaudeCode 里掌控、CLI 负责跑”的落地蓝本。

> **启示**：长期形态不必盲目重建 LangGraph；可以借 ctfSolver 思路，把 ClaudeCode 打造成 MCP 友好的“控制面”，并把 orchestrator（注册、心跳、任务分发、日志上传）抽象成服务。PoG / 因果图也可套在这个架构上：GraphManager 负责写入共享数据库，由 ClaudeCode / Web 前端读取审批，CLI 工作者只需消费结构化行动指令。

## 6. 分阶段落地清单
1. **统一入口（P0）**
   - [x] `AutoAgent.solve_challenge()` 强制调用 `tools.init_problem()`，并将 `problem_type/skill_content/loaded_resources` 写入强化版短期记忆 / `AgentContext` 供全局引用。
   - [x] CLI / orchestrator 主循环已接收 `init_problem()` 返回值，形成项目级知识优先入口（`orchestrator.py:140-229`，`main.py:1-8`）。

2. **收敛 Action Schema（P1）**
   - [x] 已定义 `ActionSchema` 风格统一动作结构：`{id, type, target, description, intent, expected_tool, params}`；planner 通过 `plan_next_action()` 输出标准动作，executor 通过 `action_handlers` dispatch table 调用工具（`agent_core.py:339-349,470-565,1035-1159`）。
   - [~] `_should_ask_for_help()` 已与 canonical tool 名称对齐，异常路径已补 `action_id/action_type` 元数据；但 `ShortMemory` 底层失败计数仍以签名为主，尚未完全切到 `ActionSchema.id`（`agent_core.py:880-889,1237-1309`；`short_memory.py:96-147`）。

3. **统一 taxonomy 与资源链（P1）**
   - [ ] 将 `tools.py` 中现有 `type_keywords` 提升为 canonical taxonomy，统一映射 `skills/<type>`、`long_memory/*/<type>`、RAG query 参数。
   - [ ] 将 `long_memory.auto_identify_and_load()` 收敛为 `{type, skills, experiences, pocs, rag_snippets}` 统一结构，并记录来源元数据。

4. **Orchestrator / State 重构（P2）**
   - [x] 新建 `orchestrator.py`，引入 `Advisor → Planner → Executor → ToolNode` 四段式路由骨架，状态结构第一版已具备 `messages`、`pending_task`、`pending_flag`、`consecutive_failures`、`route_trace`、`help_request`（`orchestrator.py:31-207`）。
   - [~] Advisor / Planner / Executor / ToolNode 事件链已可用，且 P1 dispatch 已并入 `AutoAgent` 主循环；但尚未拆成独立 `Action DAG` / `GraphManager`，ToolNode 仍是轻量事件层而非独立执行网关（`agent_core.py:397-405,801-929`）。

5. **工具执行 & 竞赛 API 统一（P2）**
   - [ ] `toolkit/base.py` 统一成为唯一 Python 执行出口；清理 `workon`、硬编码路径、`sys.executable` 等多头环境逻辑。
   - [ ] 参考 CHYing `competition_api_tools` 的重试/审计思路，保留日志、速率限制与格式校验，用于**辅助人工提交 flag**：由短期记忆 / 状态层生成待提交草稿与失败计数，但真正的 flag 仍由操作者手动提交至赛事平台。

6. **短期记忆 → 认知状态升级（P2）**
   - [ ] 在当前 `ShortMemory + AgentContext` 的基础上，拆分为 `{execution_log, causal_evidence, shared_findings}`，保留原有去重函数但增加 header/cookie/payload 维度。
   - [ ] 每条记录附带 `action_id` 与 `confidence`，为后续 PoG / Reflector 提供输入。

7. **PoG / 因果图增强（P3）**
   - [ ] 引入 `graph_manager.py` 维护 DAG + 因果图：节点结构 `{id, type, state, parent_ids, action_schema}`，边结构 `{from, to, condition}`。
   - [ ] Planner 产出 `GraphOp`（借鉴 LuaN1ao `ADD_NODE/UPDATE_NODE/DEPRECATE_NODE`），Executor 完成为节点写入 `state`，Reflector 根据失败原因触发 `Hard Veto` / 重新规划。
   - [ ] 将短期记忆的 `causal_evidence` 同步至图节点，供 `query_causal_graph` 工具查询。

8. **HITL / ClaudeCode 协作（P3）**
   - [ ] 在 ClaudeCode 会话中提供“暂停审批”接口；若需 Web UI，再对接现有 CLI 或提示卡式审批流。

## 7. Plan-on-Graph 采纳建议
1. **前置条件**
   - [ ] Action Schema、统一工具入口、短期记忆升级为图节点附带的 `execution_log`。
   - [ ] State 层必须能保存 DAG 与节点状态，且具备并行队列 / 步数限制控制。

2. **落地路线**
   - [ ] **P3-Alpha**：在现有 planner 内部引入简化版 DAG（只记录串行步骤），利用 `GraphOp` 取代当前 `_decide_next_action()` 的纯文字输出。
   - [ ] **P3-Beta**：实现 `graph_manager.py` + `shared_findings`，支持 `ADD_NODE`、`MARK_FAILED`、`SPLIT_BRANCH`，与短期记忆互通。
   - [ ] **P4**：接入 `Reflector` 级别的失败模式分析与 `Hard Veto`，让 DAG 节点具备 `confidence` 与 `replan_reason` 字段。

3. **收益/风险评估**
   - 收益：避免重复动作、可视化依赖、可自动并行化 Recon / PoC、便于 HITL 审批。
   - 风险：实现成本高、需要额外存储；建议先在 ClaudeCode 会话中以 JSON DAG 打印 / 审批，验证 schema 后再引入持久化。

## 8. ClaudeCode 原生交互 vs `main.py` CLI
| 形式 | 优势 | 风险/适用场景 |
| --- | --- | --- |
| **ClaudeCode 原生** | 天然具备提示上下文、可直接调用 `tools.py` API、便于用户在 Chat 中 HITL 干预，与项目“Claude 作为大脑”定位一致（`CLAUDE.md:4-159`）。 | 需要保证所有 Python 命令都走 CTFagent 虚拟环境；若需大批量工具执行，ClaudeCode 会话可能受限于权限，需要配合统一工具网关。 |
| **`main.py` CLI** | 运行稳定、适合长期比赛模式，与 CHYing / LuaN1ao 的 CLI/Web Server 相似；易于脚本化（`References/CHYing-agent-main/CLAUDE.md:21-39`、`References/LuaN1aoAgent-main/README.md:246-345`）。 | 当前仓库主分支尚未提供项目级 `main.py` / orchestrator 入口；CLI 形态需在主链稳定后再补。 |

**建议**：
- **短期**：优先在 ClaudeCode 会话内调试新的 orchestrator / PoG 结构，因其可直接观察状态、手动介入、快速修复。
- **中期**：待唯一主链稳定后，提供 `main.py --mode orchestrator`，内部同样走 `init_problem()` → Orchestrator → PoG 的流程，方便在比赛环境长跑。
- **长期**：仿 LuaN1ao，将 ClaudeCode 作为 HITL / 控制面，CLI 进程作为执行面，通过共享数据库或消息队列同步。

## 9. 下一步行动清单
- [x] 先补齐 P0 剩余缺口：新增项目级 CLI / orchestrator 主循环，并统一接入 `init_problem()` 返回值。
- [x] 紧接着落地 P1：定义 `ActionSchema` 与 dispatch table，先把 planner / executor 契约收敛。
- [ ] 评估当前 `ShortMemory` 与未来 `shared_findings` 的数据结构，为 PoG / 因果图准备输入。
- [ ] 设计 `GraphOp` JSON schema，并在 ClaudeCode 会话里进行 HITL 审批演练。
- [ ] 统一工具出口与比赛 API，让 ClaudeCode / CLI 两种运行方式共享同一 orchestrator 主链。
