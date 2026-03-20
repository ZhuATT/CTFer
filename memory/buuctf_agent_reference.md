# 外部参考架构要点

## 作用
记录外部 Agent 项目中，已经证明对当前 CTF Agent 有参考价值的架构模式；只保留对本项目落地真正有帮助的结论。

## CHYing 可复用点
- 三层编排思路清晰：Advisor → Main Planner → 执行层 / ToolNode。
- 结构化状态有助于审计与恢复：`pending_task`、`pending_flag`、`consecutive_failures`、路由事件。
- 比赛 API 与工具调用应有统一入口、重试、日志和速率控制。

## LuaN1ao / BUUCTF 类参考可复用点
- P-E-R 分工有助于避免单 Agent 在规划、执行、反思之间语义混乱。
- PoG（Plan-on-Graph）适合替代纯线性计划，后续可用于并行化与分支重规划。
- Evidence → Hypothesis → Vulnerability → Exploit 的因果链有助于降低盲猜与重复尝试。
- Reflector / veto 机制适合沉淀到当前项目的求助与重规划逻辑里。
- `shared_findings` 公告板适合升级当前 `ShortMemory`。

## ctfSolver 类参考可复用点
- Claude Code / 通用大模型适合作为控制面；外部执行器负责工具与长流程。
- 任务状态、消息流、心跳、结果上报可以独立于具体推理框架存在。
- 不必为了长期形态强行上 LangGraph；先把当前 orchestrator 主链稳定更重要。

## 对当前项目的直接结论
- 先稳住唯一主链，再做 PoG、GraphManager、Reflector。
- 先统一动作语义与工具语义，再扩展图结构。
- 当前阶段最重要的是：可审计、可恢复、可求助，而不是追求复杂框架外观。
