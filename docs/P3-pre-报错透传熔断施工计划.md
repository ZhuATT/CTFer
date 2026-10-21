# P3-pre 施工计划：LLM 报错透传与熔断（v4 第四阶段前置小批）

> **定位**：429 事故的根治批——LLM 传输层错误不再被静默吞掉，step 如实翻 **blocked**；连续故障**熔断**终止防空泡烧轮数；planner 唤醒失败有处理；steer 送达补核销；hint 措辞补句。**可靠性债与 P3 资产特性无关，独立小批先行、独立验收、独立 commit。**
> **事故回顾**（`p2fix-验收记录.md` 途中事故节）：bigmodel 429（code 1113）期间，planner 每次唤醒被静默吞掉、账面显示"派 0 条"（极迷惑，一度误判为 prompt 问题）；5 个 worker step"完成但零产出"。切 Coding Plan 端点后 planner 第一件事就是识别出 5 个空洞任务重建链——判断在线，错在错误没透传。
> **上游设计**：`图与基底重构设计.md` 头部决议 ⑫；ARTEX 语义参照=**LLM 错误 → step=blocked**（"传输层故障导致这条意图基本没真正探成"）。
> **基线**：`31f1a05`（P2fix）。
> **状态**：✅ 全部竣工（2026-10-19 首批竣工详见 §7；2026-10-20 P3pre-6 小卡竣工详见 §8.1，验收 88/88 全绿，tsc 干净）。preflight 健康检查设计定形、施工移交 P3 正式批 P3-10。

---

## 0. 决策点（2026-10-19 拍板）

| # | 决策 | 内容 |
|---|---|---|
| D1 | 错误分类二分 | **传输层故障**（HTTP 429/5xx、网络断连、超时）→ step=blocked + activity 落 is_error；工具执行错误不在本批范围（工具回执已自含纠错）。v1.2 prompt 已有"blocked → 直接重派"规则，**零 prompt 改动**，重派链自动接上 |
| D2 | 熔断 | 同一 run 内**连续 3 个**传输层故障 step（中间无任何成功会话）→ 终止 run，`reason=channel-down`。阈值可配（config `run.circuitBreaker`，默认 3）。防"429 死亡期空泡烧轮数"——修复方式=操作员换通道（config.yaml 一行）后重跑续接 |
| D3 | planner 唤醒失败 | 重试 1 次；仍败 → 终止 `reason=planner-error`（事件未消费不丢，续跑自动恢复）。**事件数组只在 planner 成功后才清空**（现状代码无条件清，须改） |
| D4 | steer 两段式核销 | watcher 送达账是乐观的——step 会话收尾时核对未消费队列，有残留 → is_error 账"发送失败：worker 已退出"；steered 事件保留（planner 侧兜底） |
| D5 | hint 建议级措辞 | 渲染文案补句："建议级：结合态势判断采纳/部分采纳/忽略，派单时在 note 里说明取舍"——忽略有留痕，复盘可区分"想过不采"和"没看见" |

## 1. 现状与注入点（代码落点，2026-10-19 核对）

- `agent.ts` `runWorkerStep`：`agent.prompt()` 的流错误现状被 pi 会话内部吞掉（429 实证：会话"正常"结束零产出 → step 翻 **done**——错误路径完全不可见）。
- `agent.ts:203`：`setStepState(db, task.name, step.id, aborted ? "exhausted" : "done")`——收尾二态，须扩三态。
- `scheduler.ts:313`：`const outcome = result.aborted ? "exhausted" : "done"`——同上。
- `scheduler.ts:272`：`events.length = 0` 在 `await doPlanner` 之后**无条件**执行——planner 抛错时事件会被误清（D3 修改点）。
- `scheduler.ts:53`：`RunTaskResult["reason"]` 联合类型须增 `"channel-down" | "planner-error"`。
- `channel.ts`：streamFn 构造处——包装层挂这里（分类后抛 typed error）。

## 2. 施工卡

### P3pre-1 探路 + streamFn 包装（小卡，**本批第一步**）

- **探路**（10 行探针脚本，不进主干）：对 pi-agent-core 注入错误流（假 streamFn throw 429），确认错误传播路径——`agent.prompt()` reject？`subscribe` 出错误事件？还是静默？**429 的"静默吞掉"具体在哪一层，本卡落点随之定**（P0-1 同款先探后打）。
- **包装**：`channel.ts` 增 `wrapStreamFn(streamFn)`——catch 错误 → 分类：HTTP 429/5xx/401/403（配额/网关）、`ENOTFOUND`/`ECONNRESET`/`ETIMEDOUT`（网络）、 AbortError（放过，走既有 abort 路）→ `throw new ChannelTransportError(kind, status, 原始消息)`；不可分类的包装为 `ChannelTransportError("unknown")` 照样上抛。
- 单测：假 streamFn 分别抛各形态 → wrapper 分类正确；abort 不误报。

### P3pre-2 worker 透传 → blocked + 熔断（中卡）

- `agent.ts`：`runWorkerStep` 捕获 `ChannelTransportError` → 不再走 done 收尾；`RunWorkerStepResult` 增 `transportError?: string`；activity 落 `is_error` 账（kind=result / tool=channel / summary=`传输层故障：429 quota` / detail=原始错误——**M5 UI 直接查 is_error 行渲染**）；step 收尾三态：`aborted→exhausted｜transportError→blocked｜else→done`。
- `scheduler.ts`：outcome 三态；`stepDoneEvent` 带 `outcome=blocked`（triggers 渲染进 delta——v1.2 prompt 的 blocked 重派规则消费）；**熔断计数器** `consecutiveTransportErrors`（blocked 累加、任何成功 step/planner 唤醒清零）≥3 → `reason="channel-down"` break；CLI `run` 退出码：channel-down → 1 并打印"通道故障熔断——检查配额/端点（config.yaml），修复后重跑即续"。
- 单测：抛 429 → blocked（非 done）+is_error 账+事件 outcome；3 连 blocked → channel-down；中间夹一个成功 step → 计数清零不熔断。

### P3pre-3 planner 失败处理（小卡）

- `scheduler.ts`：doPlanner 调用包 try/catch——失败 → activity 落账 → **同一批事件重试 1 次** → 仍败 → `reason="planner-error"` break（退出码 1）；成功才 `events.length = 0`。
- `planner.ts`：runPlanner 的 usage 落账挪进 finally（失败唤醒也记账）。
- 单测：mock planner 剧本=先抛后成（重试成功正常继续）/连抛两次（planner-error 终止+事件未丢——续跑场景断言 resume 恢复）。

### P3pre-4 steer 两段式核销（小卡）

- `agent.ts`：会话收尾处（unsubscribe 前）检查 agent 未消费队列（pi API 面 P3pre-1 探路时一并确认：有 `hasQueuedMessages` 用之；无则用"送达时间戳 vs 最后 turn_end 时间"粗判）→ 有残留 → activity 落 `is_error`："steer 发送失败：worker 已退出（未消费 N 条）"。
- `scheduler.ts`：steered 事件保留不动（planner 兜底语义不变）。
- 单测：steer 送达后立即结束会话 → 核销 is_error 账；正常消费 → 无 is_error。

### P3pre-5 hint 措辞 + 验收杂项（小卡）

- `triggers.ts`：hint 事件渲染文案补 D5 句。
- canary 搭车项：真机收 **hint 采纳分支样本**（p2fix 遗留——只验过"忽略"分支）。

## 3. 验收清单

**确定性单测（零 LLM）**：
- [x] wrapper 分类：429/5xx/网络错/abort 四形态（✅ 2026-10-19，含 unknown 兜底 + abort 不误报双测）
- [x] worker 抛 429 → step=blocked + activity is_error + 事件 outcome=blocked（**不翻 done**）
- [x] 熔断：3 连 blocked → channel-down；夹成功 step 清零
- [x] planner 重试 1 次成功 → 继续；两败 → planner-error + 事件保留
- [x] steer 未消费 → is_error 核销账
- [x] hint 渲染含建议级措辞

**mock 集成（零 LLM）**：deps 注入抛错 worker/planner 剧本跑 runTask 全循环——blocked → 重派接续 → 熔断终止三段。（✅ 2026-10-19，4 条剧本全过）

**canary 真机（LLM，搭车跑）**：

> ⚠️ **注（2026-10-20 复审，D-6 拍板 C）——执行下列剧本前先读**：
> ① "跑批中途把 keyEnv 指向坏 key"**机制上不成立**：secrets/config 均为进程启动快照（`scheduler.ts:164,168`），换 key 必须杀进程重启——"中途"只能做成"跑批间"；
> ② **单通道坏 key 触发不了 channel-down**：planner 永远先醒（fresh 图无 open step / 续跑必有 resume 事件），坏 key 会先走 planner-error 终止——要观察 blocked→重派→熔断链，须**分通道配**（worker 坏 key + planner 好 key）；
> ③ 坏 key 必须是**垃圾值**而非缺失——缺失在通道构造处 throw（`channel.ts:103`），worker 侧暂无兜底（P3pre-6 缺口）会裸崩；**本剧本建议排在 P3pre-6 落地后执行**；
> ④ hint 采纳分支样本已明确延后（2026-10-20 拍板"先不做"）。

- [ ] 跑批中途把 keyEnv 指向坏 key（或等真实 429）→ 观察 step 翻 blocked + planner 重派 → 持续故障熔断终止 + 提示文案 → 换回好 key 重跑续接不丢进度
- [ ] hint 采纳分支样本：跑批中插方向 hint → planner 派对应 step（note 说明取舍）

## 4. 风险与预案

| # | 风险 | 预案 |
|---|---|---|
| ① | pi 错误面探明结果与预期不符（错误只能从事件流观察 / 完全不可观察） | P3pre-1 先探；完全不可观察时退路=wrapper 内直接 reject + prompt() 外层 catch（包装点在我们就行的 streamFn 上，主动权在我们手里） |
| ② | 熔断阈值 3 不合适（429 恢复窗口长短不一） | config 可覆写；真机观察后调 |
| ③ | planner 重试期间事件重复消费 | 事件数组只在成功后清（D3）；重试用同一引用不重建 |
| ④ | blocked 重派风暴（通道恢复后一次性重派过多） | 单 planner 既有批量 ≤4 纪律约束；v1.2 重派规则本就含"blocked→直接重派"，无需新纪律 |

## 5. 明确不做（边界）

- **工具结果归因分类**（设计 §4.1 校验器 7：HTTP 403/429→blocked 只计数进态势喂 planner）——那是 postToolUse 挂钩点、看的是**工具结果**，与本批的 LLM 传输层（流层）是两回事，不混批（P4 议）；
- ask 审批/规则表扩容（P4）；UI 显示（M5——本批只保证 activity 有 is_error 账可查）；worker 会话内重试（blocked→planner 重派已是最优路径，会话内重试反而烧上下文）。

## 6. 量级预估

~250-350 行 TS（wrapper ~60 / agent 收尾三态+核销 ~80 / scheduler 熔断+planner 重试 ~80 / planner 落账+文案 ~30）+ ~180 行测试。零新依赖。**预估半天到一天施工。**

## 7. 竣工记录

**竣工 2026-10-19。验收：83/83 全绿（存量 67 + 新增 16），`tsc` build 干净。**

### 7.1 探路结论（P3pre-1，落点变更依据）

静态读穿 pi-agent-core/pi-ai 源码 + 假流探针测试固化（`test/p3pre-units.test.ts` 探针组）：

1. pi-ai `streamSimple` **catch 全部错误**（fetch 失败/HTTP 错/解析错）→ 推 `{type:"error"}` 事件，`result()` 解析为 `stopReason:"error"` + `errorMessage` 的 AssistantMessage，**从不 throw/reject**；
2. agent-loop 见 `stopReason==="error"` → 发 `message_end`(错误消息) → `turn_end` → `agent_end`，**正常 return**；
3. `Agent.prompt()` 因此**永不 reject**——连 streamFn 同步 throw 都被 `handleRunFailure` 转成同样的错误消息事件；
4. abort 可区分：pi-ai 与 handleRunFailure 都标 `stopReason:"aborted"`。

**429 "静默吞掉"的机制层解释**：错误一直是可见的（message_end 事件），但 AT1 的订阅处理器只看 turn_end 计量和 assistant 正文，错误消息零正文零 usage → "正常结束零产出"。**落点变更**：施工卡原案 `wrapStreamFn` 抛错式包装不必要（throw 出去也会被 handleRunFailure 转回 message_end，白多一层二次合成）→ 改为 `channel.ts` 纯分类函数 `classifyTransportError` / `transportFailureFromMessage` + 订阅层检测。探针固化为常驻回归测试（pi 升级先红这里）。

### 7.2 与施工卡的偏差

| # | 偏差 | 理由 |
|---|---|---|
| ① | `wrapStreamFn` 抛错包装 → 分类纯函数 + 订阅检测 | §7.1 探路结论 |
| ② | **熔断计数清零语义收紧**：只清零于成功 worker step；**planner 唤醒成功不清零**（施工卡 D2 原文"任何成功 step/planner 唤醒清零"） | 分通道场景（planner 通道活着、worker 通道死）若唤醒即清零，blocked(1)→清零→blocked(1) 循环，熔断永远到不了阈值成死代码，空泡烧轮数照旧；与验收项"3 连 blocked → channel-down"也矛盾（mock 里 planner 每次成功重派）。blocked step 后必有 planner 唤醒（事件驱动），清零即无连击 |
| ③ | planner 失败双通道检测：`RunPlannerResult.transportError`（返回值）+ 调度层 try/catch（真抛错） | 探路证实 runPlanner 不会因 429 抛错——"派 0 条"假象正是它正常 return 造成的，只做 try/catch 拦不住 |
| ④ | `RunWorkerStepOptions/RunPlannerOptions` 增 `streamFn?` 测试注入口 | blocked 路径零 LLM 验收需要假流注入（deps 注入模式同款） |
| ⑤ | planner usage 落账挪进 finally 时顺带 is_error 化 | 失败唤醒账面直接可见故障形态（M5 可查） |

### 7.3 施工明细

- `channel.ts`：`ChannelTransportFailure`/`classifyTransportError`（http[401/403/408/429/5xx]/network[ENOTFOUND 等 13 型]/unknown 三态）+ `transportFailureFromMessage`；
- `agent.ts`：订阅检测 → `RunWorkerStepResult.transportError`；收尾三态 aborted→exhausted｜transport→blocked｜else done；blocked 账 `tool=channel`+`is_error=1`（summary 带 label+轮数，detail=原始错误）；steer 核销在 finally（unsubscribe 前）`hasQueuedMessages()` → `未消费 N 条` is_error 账；
- `planner.ts`：同款检测 → `RunPlannerResult.transportError`；usage 落账进 finally（is_error 化）；
- `scheduler.ts`：reason += `channel-down`/`planner-error`；planner 唤醒失败→activity 留账→同批事件重试 1 次→仍败 `planner-error` break（事件不清）；`events.length=0` 仅成功后；`consecutiveBlocked` 熔断 ≥`cfg.run.circuitBreaker`（默认 3）→ `channel-down` + is_error 账；
- `config.ts`/`config.default.yaml`：`run.circuitBreaker`（可选，默认 3，yaml 覆写）；
- `index.ts`：channel-down/planner-error 人话提示（退出码既有逻辑已为 1）；
- `triggers.ts`：hint 渲染补建议级取舍句（前缀不变，p2-units 旧断言兼容）。

### 7.4 验收清单核对

确定性单测（零 LLM）全过：wrapper 分类四形态 ✓；worker 抛 429 → blocked + is_error + 事件 outcome=blocked（不翻 done）✓；熔断 3 连 → channel-down ✓ 夹成功清零 ✓；planner 先抛后成重试成功 ✓ 两败 planner-error + 事件保留 ✓；steer 残留核销 ✓ 正常消费无账 ✓；hint 建议级措辞 ✓；mock 集成 blocked→重派接续→熔断终止三段 ✓。

**canary 真机（LLM，搭车跑，未执行）**：坏 key 注入观察 blocked+重派+熔断续接；hint 采纳分支样本（p2fix 遗留）。

### 7.5 量级实际

src 净 +229/-38 行（`--stat` 分文件为增删合计：channel 58 / agent 50 / planner 39 / scheduler 103 / config+index+triggers 16 / config.default.yaml 1）+ 测试 486 行（`test/p3pre-units.test.ts`，16 条 it）。零新依赖。

---

## 8. 复审补充问题与 P3pre-6 施工（2026-10-20，竣工 88/88 全绿）

> 背景：canary 方案讨论中对竣工代码做了全量复核（channel/agent/planner/scheduler 逐行 + index/config 落地核对）。结果 = **2 个真问题（①②）+ 1 个语义盲区（③）+ 2 个边角（④）+ 1 项阴性确认（⑤）**。①②③ 建议合并成一张 **P3pre-6** 小卡施工；④ 建议记录不修；⑤ 无需动作。**拍板后再动工。**
>
> 2026-10-20 二轮讨论：**② 修法定形**（渲染窗口 + splice，明确**不做图节点**、不动 schema）；文末新增**拍板待决清单**——新会话动工前逐项过一遍。
>
> 2026-10-20 三轮拍板：**D-1 = 维持现状**（③ 降级为已知边界）；**D-4 = 修**；**D-2 = 研究中**——参照 `lernproject/Cairn-main` 与 `lernproject/ARTEX-new` 的任务前置健康检查设计，结合 AT1 架构再定 ① 的 catch 处理。
>
> 2026-10-20 四轮拍板（D-2 落锤，研究结论见本节末"D-2 拍板记录"）：① 兜底**回归原案**留 P3pre-6；**preflight 任务前置健康检查设计定形、施工挪 P3 正式批（P3-10）**；at1 check 子命令含在内；浏览器失败=警告+人工选择降级；D-5 归档重排 = "P3pre-6 小卡 + preflight 移交 P3"。

### ① worker 调用无兜底 catch——结构性缺口（建议 P3pre-6 主体）

**位置**：
- `scheduler.ts:358`——循环内 `await doWorker({...})` **没有 try/catch**；
- `agent.ts:191`——runWorkerStep 的 try/finally 只包 `agent.prompt()`，**构造段全部裸露**：
  - `channel.ts:103`——keyEnv 名拼错/缺 key，通道构造即 throw；
  - `agent.ts:123`——`stepLineageView` 内 `JSON.parse(step.payload)`，payload 腊坏直接 throw；
  - `agent.ts:128`——`BrowserPool.start` 在 try **之外**，半启动的 chrome 可能泄漏成 zombie 进程。

**根因**：D1 的"pi 不抛错"推理只覆盖了**流层**（prompt 永不 reject），没覆盖**构造层**（通道构造/图读取/浏览器池启动都会抛）。不对称点：planner 侧对称位置 P3pre-3 刚加了 try/catch，worker 侧没有。

**影响**：上述任一 throw = 裸崩整个 runTask——finally 只清 watcher/锁/db，`reason` 不落、activity 无账、CLI 抛栈退出；BrowserPool 半启动场景还可能残留 chrome 进程。keyEnv 手滑拼错一次就踩。

**修复计划（~20 行 + 2 测试）**：
- scheduler 循环内 `doWorker` 包 try/catch：catch → step 落 **blocked** + activity is_error 账（summary=构造/执行异常，detail=原始错误）+ 计入 `consecutiveBlocked` → 接既有熔断路（payload 腊坏类不可恢复错误会 3 连后 channel-down 终止，账面带真实原因，不再是裸崩）；
- agent.ts：`BrowserPool.start` 挪进 try 防护（或独立 catch + shutdown 兜底），杜绝 zombie。

> **注（2026-10-20，D-2 四轮拍板落锤）**：catch 后处理**回归原案**——blocked + is_error 账（detail 载真实原因）+ 计入熔断，作为 run 内**安全网**保留（preflight 挡住常规构造失败后，它只接漏网：运行中新出现的腊坏 fact、db 异常等意外 throw）。**前置健康检查（preflight）另立设计、施工挪 P3 正式批 P3-10**——设计提案与本轮研究结论存档于本节末"D-2 拍板记录"。

### ② operator 干预（hint/steer）planner 不可见 + steer 事件竞态误清（存量问题；修法 2026-10-20 定形）

**需求实锚**：planner 能看到之前人类发过的 steer/hint，且留有记录。复核结论：**"留存"半件已成立**——`control/hints.jsonl` / `control/steer.jsonl` 均追加式、永不删行、带 ts（steer 还带目标 stepId），只推进 offset。缺的是**planner 可见性**，叠加一个事件竞态：

- **可见性缺失**：planner 视野 = 当轮一次性 events（`renderTriggers` 渲染，planner 成功消费即清）——工具面五个（add_step/conclude/prove/TodoWrite/list_facts/node_detail）没有一个能查"操作员说过什么"，态势区也没有干预史；
- **竞态**（原 ② 条目）：`scheduler.ts:333`（成功后 `events.length = 0`）× watcher `deliverPendingSteers`（`scheduler.ts:180/193`）交错——planner `await` 期间（10s~300s 窗口）watcher 推入的 steered 事件不在前置快照里（`scheduler.ts:285`），成功后 `length=0` 把这批**从未被消费的 steered** 一并清掉。

**影响**：steer 消息本身已进 worker 会话（乐观送达成立），但 planner 侧兜底语义永久丢失——后续唤醒不知道操作员插过话，复盘无法区分"planner 见过没理"和"根本没送到 planner"；hint 同理只闪现一次。

**修复计划（~20 行 + 1-2 测试，2026-10-20 讨论定形）**：
- **主修——渲染窗口**：`planner.ts` runPlanner（已持有 taskDir）读 `control/hints.jsonl` 尾部 ≤5 条 + `control/steer.jsonl` 尾部 ≤5 条（每条截 ~200 字，带 ts；steer 标"→ step #N"；**解析宽容同 harvest——坏行整行当文本，`hints.ts:52-54` 语义，别裸 JSON.parse**），拼 **【操作员干预史（最近）】** 块传 `renderPlannerUserMessage` 新字段，**每次唤醒固定渲染**；措辞一句："hint=调度层建议，steer=已插进 worker 会话的纠偏；结合当前态势判断是否已消化，旧项已处理可忽略"。效果链：每轮必见 → pi 会话 transcript 可查 → "见过没理"从此可区分；steered 事件被竞态吃掉也会在下一轮从窗口看到；旧项自然滑出窗口，全文永远在 jsonl，复盘直接看文件。
- **卫生修——splice**：planner 调用前记 `snapshotLen = events.length`；成功后 `events.splice(0, snapshotLen)` 代替 `events.length = 0`——只清已消费前缀，窗口内新到事件留给下一轮唤醒（P3pre-3 重试路径同快照语义，不受影响）。

**已否决路线存档**（防止后续会话重新争论）：hint/steer 落**图节点**（kind="hint"，同序列编号+血缘）——架构上更统一（编号引用、note 引证机械可查），但动图 invariant（nextStep/拒重/proveGoal 过滤审计、resume nodeCount 边界），本需求不需要这重量；activity 落账渲染——给 planner 开第二视野（activity 行），不如直接渲染原始 jsonl 贴近其现有消费方式。

**已知代价**：每唤醒 prompt +200~400 token（典型一句话级干预；最坏 5+5 条全部顶满 200 字 ≈ 1000-1500 token——固定窗口买确定性）；同 hint 重复曝光靠 ts + 措辞缓解，真出现重复派单再上"已消化水位线"（第一版不上）；窗口外更早干预 planner 不可见（文件里有，暂不做翻页工具）。

### ③ 熔断盲区：挂死型故障永不触发（✅ 已拍板 2026-10-20：维持现状，降级为已知边界）

**位置**：`scheduler.ts:376`——`consecutiveBlocked = outcome === "blocked" ? consecutiveBlocked + 1 : 0`。

**问题**：**exhausted（超时）也清零计数**。通道挂死（连接 hang 到 stepTimeout、不发 error 事件）表现为 exhausted → 计数永远归零 → 熔断形同虚设。

**影响**：挂死型通道故障烧的是 timeout（默认 10min）× 轮数的空泡——恰是 P3pre 想防的"空泡烧轮数"的另一面：快速报错型防住了，慢速挂死型没防住。

**拍板记录（2026-10-20，D-1 选 B）**：**维持现状——exhausted 照样归零，不修**。理由：① 默认 10min 超时是测试值，实战/实际使用会设远大于此，"连续超时凑够熔断条件"的场景概率极低；② 超时被杀时 worker 本身是正常工作的（通道未必死），归零语义成立；③ 挂死/超时类问题靠这个计数器本来就解决不了——**后续另想方案**（候选：缩短超时 + 心跳/流式活性检测，P4+ 议）。本节降级为**已知边界**，仅记录。

### ④ 分类与检测边角（cosmetic，✅ 已拍板 2026-10-20：修，归 P3pre-6）

| 位置 | 边角 | 影响 |
|---|---|---|
| `channel.ts:67` | 状态码正则只认 401/403/408/429/5xx——**400 不在内**（正是 1210 thinking:disabled 老坑的 HTTP 形态，复发会标 `[unknown]`）；反向：报错文本中任意三位数（如 "503 tokens"）可能误标 `[http 503]` | 仅 label 变粗/误标，blocked 判定（stopReason=error）不受影响 |
| `channel.ts:81` | 要求 `errorMessage` 非空才判传输故障——若 pi 未来发出 stopReason=error 但空 message 的事件，会翻 done 零产出（原事故形态残留） | 探针结论 pi 必填 errorMessage，当前不可达；防线差一行 |

**修复计划（已拍板修，各 1 行 + 单测断言）**：正则放宽为 `\b[45]\d{2}\b`（400 等全部 4xx 进 http 分类）；空 message 回退 `{kind:"unknown", raw:"(empty)"}` 照判故障（堵死"error 事件零正文 → 翻 done 零产出"的理论回归路）。

### ⑤ 阴性确认（复核过，无需修）

- planner 半程派单后传输故障：已派 steps 落在 DB，重试唤醒被 add_step **程序级拒重护栏**（`planner.ts:71` 同义 open/running 拒收）拦住重复派单；失败唤醒 usage 已进 finally 账——无重复派单、无无声失败；
- `index.ts:55-57` channel-down/planner-error 人话提示、`config.ts:110` circuitBreaker 解析均已落地；
- 事件只在 planner 成功后清、重试用同批引用——与 D3 决议一致。

### 拍板待决清单（新会话动工前逐项过，2026-10-20）

| # | 事项 | 选项 | 当前倾向 |
|---|---|---|---|
| D-1 | **③ 熔断清零语义** | ✅ 2026-10-20 拍板：**B 维持现状**。理由：默认 10min 超时是测试值、实战远大于此，连续超时凑满熔断条件的概率极低；超时被杀时 worker 本身正常工作；超时类问题计数器解决不了，**后续另想方案**（P4+ 议）。③ 降级为已知边界记录 |
| D-2 | **① 构造层异常的 reason 归属 / 前置健康检查** | ✅ 2026-10-20 拍板：① 兜底**回归原案**（blocked + is_error + 计熔断，留 P3pre-6 作安全网）；**preflight 健康检查设计定形、施工挪 P3 正式批 P3-10**（at1 check 子命令 + 浏览器失败人工选择降级均含在内，见本节末拍板记录） | 已定 |
| D-3 | ② 渲染窗口参数 | ✅ 2026-10-20 拍板：**按默认——尾部各 5 条 × 截 200 字**；写死为模块常量（`FACTS_PAGE` 同款先例，如 `INTERVENTION_WINDOW` / `INTERVENTION_TEXT_LIMIT`）；空窗口不渲染该节、时间正序、不去重。**升级路径已留**：常量 → 需要时提升为 config 字段（`circuitBreaker` 同款一行接线，`config.ts:110` 模式）→ M5 UI 设置页本来就是读写 config.yaml，字段进了 config 前端调节免费得——写死不堵路，提升是机械动作 | 已定 |
| D-4 | ④ 两处 1 行修（正则放宽 `\b[45]\d{2}\b` / 空 message 兜底） | ✅ 2026-10-20 拍板：**修**（归 P3pre-6，含单测断言） | 已定 |
| D-5 | P3pre-6 归档形状 | ✅ 2026-10-20 定形：**P3pre-6 小卡** = ① loop catch + BrowserPool 挪 try + ④ 两行修 + ② 渲染窗口+splice（~60 行）；**preflight 移交 P3 正式批 P3-10**（原"一张卡"案作废——健康检查进来后量级超小卡） | 已定 |
| D-6 | §3/§7.4 canary 清单措辞已过时（"中途换 key"机制上不成立——secrets/config 均为进程启动快照，换 key 必须杀进程重启；且单通道坏 key 只会触发 planner-error，channel-down 需分通道构造） | ✅ 2026-10-20 拍板：**C 最小注记**——§3 canary 清单上方已加现实约束注记（①中途换 key 不成立 ②channel-down 须分通道 ③坏 key 须垃圾值+建议排在 P3pre-6 后 ④hint 项延后），清单原文保留不修史；修正后的剧本协议在 P3-10 验收里落地 | 已定 |

### D-2 拍板记录：preflight 任务前置健康检查设计（2026-10-20 定形，**施工挪 P3 正式批 P3-10**）

**参照研究结论**（2026-10-20，两份完整调查由子代理产出，源码行号可复查）：

- **Cairn-main**（同域：LLM 渗透调度，黑板架构）——贡献**分层骨架 + 报告形态**：配置加载时结构校验（`dispatcher/config.py:259-272` env 键强制）→ 启动时活性探测（`runtime/startup_healthcheck.py`，ThreadPool 并行、逐项防崩）→ 每任务前复检（可配三模式）→ 运行中心跳租约。探测=**真实最小请求**（`workers/health.py:17-36` http_ping，max_tokens=10 的 "ping"——一次覆盖可达+key 有效+模型名可调）。失败分档：全挂才 fail fast，部分挂降级继续；doctor 模式（`--startup-healthcheck-only`）不受配置开关控制、bare 日志可进 CI。
- **ARTEX-new**（同域：AI 渗透平台，planner/worker/意图）——贡献**探测保真 + 失败分档 + 降级不崩**：`TestConnection`（`agent/provider.go:457-501`）镜像生产参数（thinking/流式/自定义头）、空回复也算失败、wire 报文留档、30s 硬超时**不叠重试**；失败二分 hard（401/402/403/404 确定性，首次即熔断）vs soft（429/5xx/网络，连错 3 次才熔断，`llmpool/health.go:21-38`）；quota 判定从严（普通 429 明确排除在"换通道"外——瞬时抖动不得误升级，`provider.go:289-323`）；失能任务标结构化 blocked_reason 排队不占坑（`server/goals.go:253-279`）。

**AT1 设计（新 `src/preflight.ts`，两个触发点：`at1 run` 进循环前自动跑 + 独立 `at1 check` 子命令——check 已拍板要）**：

| 检查项 | 抓什么（对应 §8① 裸奔点） | 怎么查 | 失败行为（拍板） |
|---|---|---|---|
| A 通道构造 ×2 | keyEnv 拼错/缺 key（`channel.ts:103`） | 纯本地调 `createChannelFromConfig`，零网络 | **硬失败**，进循环前退出 |
| B 通道活性 ×2 | key 失效、endpoint 挂、模型名错 | 生产同款 streamFn+model+key 发最小真实补全（"回复 OK"；30s 硬超时、不重试；两通道并行、逐项隔离） | 按 `classifyTransportError` 分档：**401/403 → 硬失败**；**429/5xx/network → 警告放行**，交运行时熔断接力（soft 兜底机制 = P3pre 已建的 planner-error 重试路 + 3 连 blocked 熔断，两层分工：门口拦确定性错误、run 内数连续失败拦瞬时持续错误） |
| C 图完整性 | payload 腊坏（`agent.ts:123`） | 扫 nodes 表 parse 全部 step/fact/finding payload | 腊坏 **open step 自动标 blocked + is_error 账**（note 写明损坏原因），run 继续——planner 见 blocked 重派绕开（对应 ARTEX"失能不崩不占坑"） |
| D 浏览器池 | chrome 起不来/zombie（`agent.ts:128`） | 真起一个池开 about:blank 即关 | ✅ 拍板（推翻原"硬失败"推荐）：**警告 + 人工选择是否降级无浏览器启动**——当前 CLI 形态 = 交互确认（y/N，默认不启动）或 `--no-browser` 显式参数；M5 UI 到位后加前端选择框 |

- 报告：Cairn 式表格打 stdout（`[+]/[-]` + 耗时 + HTTP 码/原因）+ 一条 activity（tool=preflight）落 DB 供 M5 查；
- 退出码：**推荐 CLI 层直接退出码 1、不进 runTask、不造 run reason**（run 还没开始，没有 run 账目可写——"失败记在门口"而非"记在 run 的账上"）；P3 施工时终定；
- 测试：streamFn 注入零 LLM（P3pre 偏差④同款）+ 浏览器探测 deps 注入，~150 行；
- **不抄清单**（scope 纪律）：心跳租约（AT1 单进程不需要）、冷却阶梯熔断（与既有 consecutiveBlocked 重叠）、每任务前复检（成本高，通道瞬时故障交给运行时熔断）、自更新回滚（不适用）；
- 与 P3pre-6 的关系：preflight 挡**常规**构造失败（门口），P3pre-6 的 loop catch 接**漏网**（运行中意外 throw）——两层防御，缺一不可。

---

### 8.1 P3pre-6 竣工记录（2026-10-20）

**验收：88/88 全绿（存量 83 + 新增 5），`tsc` build 干净（0 error 0 warning）。**

#### 落点明细

1. **④ 边角修复（`channel.ts`）**：
   - 状态码正则放宽为 `\b([45]\d{2})\b`（400 等全部 4xx 进 http 分类，包含 glm 1210 thinking 报错形态）；
   - `transportFailureFromMessage` 空 message 回退 `{ kind: "unknown", raw: "(empty)", label: "传输层故障[unknown]" }` 照判故障（堵死"error 事件零正文 → 翻 done 零产出"的理论回归路）。

2. **① 构造层防僵尸与循环异常兜底（`browser-pool.ts` + `agent.ts` + `scheduler.ts`）**：
   - `browser-pool.ts:start`：内部 `launchNew` catch 兜底，失败时执行 `await pool.shutdown()` 保证状态清理；
   - `agent.ts:runWorkerStep`：`BrowserPool.start` 与 `BrowserSession` 挪进 `try` 防护，`finally` 保证 `await browserSession?.dispose()` 与 `await pool?.shutdown()`，杜绝 zombie chrome 泄漏；
   - `scheduler.ts`：
     - 循环内 `await doWorker({...})` 包裹 `try/catch/finally`（`finally` 清 `runningStepId` 和 `currentAgent`）；
     - catch 异常 → step 落 **blocked**（非残留 running）+ activity 记 `is_error: true` 账（summary 带 `step #${step.id} 构造/执行异常：...`，detail 记录原始错误）；
     - `consecutiveBlocked` 累加 + 产生 `stepDoneEvent(step, "blocked", [], [], "")`；
     - 达到熔断阈值（默认 3）→ `reason = "channel-down"` 退出循环，未达则 `continue` 留给 planner 事件驱动重派。

3. **② 操作员干预史渲染窗口与 splice 卫生修（`planner.ts` + `planner-prompt.ts` + `scheduler.ts`）**：
   - `planner.ts`：
     - 常量化：`INTERVENTION_WINDOW = 5`，`INTERVENTION_TEXT_LIMIT = 200`；
     - 实现 `readRecentInterventions` / `renderRecentInterventions`：读取 `control/hints.jsonl`（尾部 ≤5 条）与 `control/steer.jsonl`（尾部 ≤5 条，标 `→ step #N`）；宽容解析（坏行整行当文本，同 hints.ts 宽容语义），每条截 ≤200 字，按 ISO 时间戳时间正序排序；
     - 拼出 `【操作员干预史（最近）】` 块，带措辞句："hint=调度层建议，steer=已插进 worker 会话的纠偏；结合当前态势判断是否已消化，旧项已处理可忽略。"；空窗口返回 `undefined`（不渲染）；
   - `planner-prompt.ts`：`renderPlannerUserMessage` 增 `interventionsText?: string` 参数，在 triggers 与态势预取之间固定渲染；
   - `scheduler.ts`（splice 卫生修）：planner 唤醒前记录 `const snapshotLen = events.length;`，传给 planner 快照前缀 `events.slice(0, snapshotLen)`；planner 成功唤醒后执行 `events.splice(0, snapshotLen)`，保护在 planner await 期间由 watcher 推入的新事件（如 `steered`）留存给下轮消费。

4. **单测覆盖（`test/p3pre-units.test.ts`）**：
   - HTTP 400 与全部 4xx/5xx 分类断言；
   - 空 message 错误回退 unknown 兜底断言；
   - 干预史渲染窗口：空目录不渲染、hints+steer 混合读取（尾部截取、200 字截断、坏行宽容、时间正序、措辞核验）；
   - splice 卫生修：planner 执行期间 watcher 新增事件保留验证；
   - worker 循环异常兜底：worker throw 抛错 → step 翻 blocked + activity is_error 账（含构造/执行异常） + planner 收到 blocked outcome 事件并重派成功；
   - worker 连续 3 次 throw → 触发熔断 `channel-down` 终止，3 步全落 blocked。

