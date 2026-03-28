# CTF Agent 升级方案

> 基于 References/ 中参考项目的架构分析，结合当前 `ctf_direct` 框架的实际情况，制定分阶段升级计划。

---

## 1. 当前框架状态

**已实现：**
- 直接模式 LLM 推理循环
- 流式 tool calling 支持
- 6 个工具注册（curl, execute_python, dirsearch, sqlmap 等）
- RAG 知识检索
- Skill 知识加载
- 文件状态持久化

**局限性：**
- 单一推理模式，无规划能力
- 无因果推理，所有决策依赖 LLM 自行推理
- 无上下文压缩，长对话会 token 溢出
- 无多阶段攻击链规划
- 无失败模式学习

---

## 2. 参考项目架构分析

### H-Pentest（已克隆）

**架构：** Multi-Agent Supervisor 架构
```
StrategicSupervisor（战略规划） → 生成初始测试计划
MetaSupervisor（元监督） → 每3轮生成洞察
Worker（执行层） → ReAct 循环
PayloadMaster（载荷指导） → 每3轮提供攻击指导
```

**启发点：**
- 分离战略决策和执行
- 元认知层周期性注入洞察
- 基于 tiktoken 的上下文压缩

### LuaN1aoAgent（已克隆）

**架构：** Dual-Graph Reasoning（P-E-R 框架）
```
Planner（规划器） → 维护 Task DAG，管理任务依赖
Executor（执行器） → 工具调用，上下文压缩
Reflector（反思器） → 审计结果，Hark Veto 剪枝无效路径
```

**启发点：**
- Task Graph（DAG）管理多阶段攻击
- Causal Graph 证据驱动推理，避免 LLM 幻觉
- 失败模式 L1-L4 分析

### ctfSolver（已克隆）

**架构：** Master/Worker + Hybrid Scanning
```
Explorer → 页面探索，JS分析，路径发现
Scanner → POC扫描 + LLM扫描 并行
Solutioner → 生成绕过/payload策略
Executor → 工具分发
```

**启发点：**
- POC + LLM 混合扫描
- ThreadPoolExecutor 并行测试多解
- XML 格式工具调用

---

## 3. 升级方案（分阶段）

### Phase 1：增量优化（不改变核心架构）✅ 主要完成

**目标：** 提升现有直接模式的解题能力

#### 1.1 上下文压缩 ✅ 已完成
- 参考 H-Pentest 的 `ContextManager`
- 基于字符的 token 计数（不依赖 tiktoken）
- 保留：system prompt + 最近 N 步 + 高优先级 findings
- 实现：`ctf_direct/core/context_manager.py`

#### 1.2 Hybrid POC + LLM 扫描 ✅ 已完成
- 参考 ctfSolver 的 `poc_scan + llm_scan`
- 先用已知 POC 快速检测（连续 2 次无新发现时触发）
- POC 未命中时继续正常推理流程
- ThreadPoolExecutor 并行测试（最多 10 个 POC）
- 实现：`ctf_direct/core/poc_scanner.py` + `reasoner.py` 的 `_try_poc_scan()`
- 命中结果写入 `findings.json`（kind: poc_hit）

#### 1.3 失败模式学习 ✅ 已完成
- 参考 LuaN1aoAgent 的 L1-L4 失败分析
- 记录失败原因，避免重复
- 实现：标记 failed_tool + failed_reason
- 位置：`reasoner.py` 的 `_record_failure()` + `_analyze_failure_reason()`

#### 1.4 工具调用格式标准化 ✅ 不需要
- 当前 OpenAI function calling 已足够
- 不需要 XML 格式

---

### Phase 2：推理增强（引入规划层）

**目标：** 超越直接模式，增加因果推理能力

#### 2.1 Task Graph（任务图） ❌ 暂不实现
- 参考 LuaN1aoAgent 的 Dynamic Task Graph
- DAG 管理多阶段攻击
- 复杂度高，当前题目标签化已足够

#### 2.2 Causal Graph（因果图） ❌ 暂不实现
- 参考 LuaN1aoAgent 的 Cognitive Causal Graph
- Evidence-Hypothesis-Exploit 链
- 需要大量重构

#### 2.3 P-E-R 框架 ❌ 暂不实现
- Planner-Executor-Reflector 分离
- 复杂度高，Phase 1 优先

---

### Phase 3：多 Agent 协作（可选）

**目标：** 引入 Supervisor 层

#### 3.1 Strategic Supervisor ✅ 已实现
- 初始测试计划生成
- 基于 skill + RAG 生成攻击路径建议（真实加载 SKILL.md 内容提取）
- 非强制，LLM 可忽略
- 实现：`reasoner.py` 的 `_generate_strategic_plan()` + `_extract_from_skill()` + `prompt_builder.py` 的 `_build_attack_plan_section()`
- 效果：推理循环第一步就注入题型相关的攻击步骤建议和 POC 候选
- 机制：
  1. 加载对应题型的 SKILL.md 内容
  2. 通过 `_extract_from_skill()` 提取攻击向量和 POC
  3. 结合 RAG 检索结果补充 rag_insights
  4. 如 skill 文件不存在，降级到 hardcoded fallback 步骤

#### 3.2 Meta Supervisor ❌ 暂不需要
- 每 N 轮生成洞察
- 当前 max_steps 限制已足够

#### 3.3 Payload Master ❌ 暂不需要
- Payload 进化指导
- 当前 skill 内容已足够

---

## 4. 推荐实施方案

### 近期（1-2周）：Phase 1 增量优化

| 任务 | 描述 | 优先级 | 工作量 |
|------|------|--------|--------|
| **1.1 上下文压缩** | tiktoken token 计数 + 压缩逻辑 | P0 | 中 |
| **1.2 Hybrid POC+LLM** | 并行 POC 扫描 + LLM 生成解法 | P1 | 小 |
| **1.3 失败模式记录** | 标记 failed_tool + reason | P1 | 小 |

### 中期（1个月）：Phase 2 规划增强

| 任务 | 描述 | 优先级 | 工作量 |
|------|------|--------|--------|
| **2.1 攻击计划生成** | 基于 skill 生成候选攻击路径 | P1 | 中 |
| **2.2 上下文感知决策** | 根据已尝试方法调整决策 | P2 | 中 |

### 长期（如有需要）：Phase 3

| 任务 | 描述 | 优先级 | 工作量 |
|------|------|--------|--------|
| **3.1 Strategic Supervisor** | 战略规划层 | P2 | 大 |
| **3.2 多轮反思机制** | Reflector 审计结果 | P3 | 大 |

---

## 5. 清理与维护

### 已清理项

#### wooyun skill 移除 ✅ 已完成
- **问题**：`ctf_direct/skills/wooyun/SKILL.md` 引用已删除的 `wooyun_rag.py`，属于孤立文件
- **操作**：删除 `ctf_direct/skills/wooyun/` 目录
- **原因**：wooyun RAG 已由 `rag_knowledge.py` 实现，原 skill 文件已过时

---

## 6. 不做约束

基于当前框架的简洁性和实际需求，以下**暂不实现**：

- ❌ **Dual-Graph Reasoning**（复杂度高，当前题目标签化已足够）
- ❌ **P-E-R 框架**（需要大量重构）
- ❌ **多 Agent 协作**（当前单 Agent 足够）
- ❌ **完整的 Meta Supervisor**（max_steps 已足够）
- ❌ **Payload Master**（skill 内容已足够）

---

## 7. 架构演进路线

```
当前架构：
Strategic Supervisor → LLM 推理 → 工具执行 → 上下文压缩 → Hybrid POC+LLM

Phase 1 增量优化后（已实现）：
Strategic Supervisor → LLM 推理 → 上下文压缩 → 失败模式记录 → Hybrid POC+LLM

Phase 2 规划增强后（暂不实现）：
Strategic Supervisor → LLM 推理 → 工具执行 → 上下文压缩 → Hybrid POC+LLM
                       ↑                    ↑
                  Task Graph          Causal Graph
```

---

## 8. 参考文件

- H-Pentest: `References/H-Pentest-main/backend/agent/core/context_manager.py`
- LuaN1aoAgent: `References/LuaN1aoAgent-main/core/planner.py`, `core/executor.py`, `core/reflector.py`
- ctfSolver: `References/ctfSolver-master/agent/agents/master.py`, `flaghunter.py`
