# P2fix 施工计划：验收修复批（v4）

> **定位**：P2 验收（2026-10-18）抓出的问题 + prompt 拍板项 + 唤醒机制升级（方案 C）的集中修复批。
> **上游**：验收问题 #1/#2/#3/#5/#6（代码）+ 审1/2/3/6/8/9（prompt，全文见 `prompt-全文汇编-v4.md`）+ Cairn/ARTEX 收官机制调研（§6）。
> **基线**：P2 全部未提交（HEAD=`b43fb46`，P2 改动在工作区）。**建议提交顺序：P2 原样先 commit → 本批单独 commit**（回滚粒度干净）。
> **状态**：🚧 施工中（2026-10-18 开工）——P2F-1~P2F-11 全部落码；**层1 67/67 绿、层2 H1-H4 全过、层3 Run A 回归五项+剧本B 过**；层3 剧本A（goal-closed）跑到 canary-p2fix-b step #46 处**操作员暂停**（conclude 尾巴未触发，图现场保留可续跑）。验收详情见 `docs/p2fix-验收记录.md`。通道备注：验收途中 bigmodel /paas/v4 资源包余额耗尽（429 code 1113），已切 GLM Coding Plan `/api/anthropic`（`v4/config.yaml`）。未 commit，等竣工一并提交。

---

## 0. 决策点

**已拍板（2026-10-18）**：

| # | 决策 |
|---|---|
| D1 | planner prompt = v1.2（决策流程式，ARTEX 结构），与唤醒机制方案 C 配对；v1 弃用 |
| D2 | conclude_task 进本批；防线：工具执行时校验 openCount==0——还有待办 step 无权宣判终局（依据 §6：Cairn/ARTEX 均不给模型无条件弃守权） |
| D3 | run.lock 启动互斥（canary 实锤双开：03:16:37-03:17:15 两 worker 会话重叠 38 秒） |
| D4 | **`standards/` = agent 参考资料唯一目录**：能给 agent 参考的信息都放这里（src标准 五份厂商评级细则先落；用户 skills 手册后续提供时拷入同目录）；initTask 快照式拷贝；prompt 引导行挂触发条件不挂"必读" |
| D5 | 代码修复五件：worker 通道接 config / noreport endpoint / worker 阴性出口句 / Bash 措辞（nmap 已核实未装，仅 curl）/ 小项清账 |
| D6 | **唤醒机制 = 方案 C 全面事件驱动**：每次收割到新事件（step_done/finding/hint/resume）即唤醒 planner。事件源存档：step 唯一生产者是 planner 本人，无"新 step 唤醒"事件；fact 归入 step_done 批次。成本已知情（每 step 一次唤醒 ≈5k in/3k out）。**本大阶段不做多 worker**（用户声明） |
| D7 | **前端 UI 需求登记（M5）**：goal 重开（reopen）/ stop / hint 插话 / steer 插话（**带 worker 选择 + 显示其在跑 step**，单 worker 时期列表恒为一项，接口按多 worker 形状设计）/ config 编辑，后续都要在 UI 上直接操作——本批只做 CLI/文件形态，接口设计预留 |
| D8 | **不上目标分解器**：大目标的分解交给 planner 的 step 边探边做（延迟/自适应分解）；ARTEX 分解器批判存档见 §6.4。偷走的唯一纪律：goal 尽量写成可验证结果（建任务时引导，不做机制） |
| D9 | **reopen 语义（Q2 拍板）**：图不变；reopen 必须填**新 goal** → goal 节点 state closed→open + text 更新 + 发 `goal_changed(edited)` 触发（预留事件首次启用），原图全保留接着跑（历史 facts=新 goal 的先验）。入口 M5 UI / P3 CLI |
| D10 | **停止三层（Q4 拍板，对照见 §6.5）**：①stop 信号文件（意图声明）②**进程内 watcher：1-2s 盯 control/stop → 对当前 Agent 调 .abort()——与超时同路的优雅收尾，秒级响应**③锁 pid 打印人工 kill 兜底（仅真僵死）。不自动杀 |
| D11 | **steer 通道（2026-10-18 拍板，独立显式通道，不是 hint 升级）**：两块干净语义——hint→planner=调度层（拨方向/情报/禁令，影响未来 step）；steer→当前 worker=执行层（对在跑 step 补情报/纠偏，不影响调度）。**发送时选择目标 worker 并显示其在跑 step**（单 worker 恒一项，接口按多 worker 形状）。不搞自动路由（操作员显式选择）。技术依据：pi Agent 原生 `steer(message)` |

**待拍板**：无——全部拍板，等开工指令。

---

## 1. 施工卡

### P2F-1 worker 通道接 config.yaml（验收#1）

- `scheduler.ts`：`runWorkerStep` 调用处传整份 `channel: cfg.channels.worker`（替换只传 `mode`）。
- `agent.ts`：`RunWorkerStepOptions` 加 `channel?: ChannelConfig`；内部 `opts.channel ? createChannelFromConfig(...) : createChannel(mode)`——P1 兼容入口保留（单跑/测试用）。
- 验收：单测——mock config 换 `model/keyEnv`，断言构造的 model.id 与取 key 跟随配置。

### P2F-2 noreport endpoint 接通（验收#5）

- `graph.ts` submitFinding：`endpoint: ""` → `endpoint: payload.endpoint ?? ""`（一行）。
- 验收：单测——summary 干净 + `endpoint=/static/app.js.map` → reject(sourcemap)；豁免顺序不变。

### P2F-3 planner prompt v1.2（审1/2/3 + 审9）

- `planner-prompt.ts` 替换全文（与方案 C 唤醒配对）：

```
你是渗透测试任务的规划者。每次被唤醒 = 系统有新变动要你消化（step 结论/新发现/操作员指示/续跑恢复）。
你的职责：读态势 → 判目标 → 只在确有未覆盖的新方向时补 step。你是规划者不是执行者，自己不做探测。

每次唤醒的决策流程：
1. 先读【本次实际变动】——上轮发生了什么（step 结论/新 fact/新 finding/操作员指示/续跑恢复）。
2. 判目标：目标是否已被某条 fact 实证支撑？是 → prove_goal。含量化条件必须核对态势实测值，未达标禁止盖章。
3. 判方向（对照 open/running 与 recent_done）：
   - done 方向不原样重派；仅材料性新机理（新 fact/新资产/本质不同打法）才重开，note 写明差异；
   - exhausted 方向派「接上次进度继续」，依据已有 fact，不凭空猜进度；
   - blocked 方向直接重派；卡同一处换打法；
   - 否定性 fact 采信前用 node_detail 看证据：扎实+observed+手段穷尽→封方向；弱证据→至多派一条复核；
   - 组合扫描：图里 facts 拼一遍，有没有两条以上记录合起来才是完整攻击路径（典型：标识符可预测×吃该标识符的弱防护接口×泄露面），候选→add_step，note 引参与组合的节点 id，每轮至多 2 条；
   - 深度优先于覆盖度；目标未达时保持 2-3 条机理不同的路线并存。
4. 定产出：
   - 有未覆盖方向 → add_step 一次批量 ≤4 条最高价值的；
   - 目标达成 → prove_goal；
   - 图上已无待办 step 且方向探尽/目标确认不可达 → conclude_task（reason 引 recent_done 说明为何再派无价值）；
   - 已覆盖（open/running 已有同方向）或等依赖（下一步依赖在跑产出）→ 0 派收工，合法；
   - 强依赖串行链 → TodoWrite 记整条，本轮只派前置已满足的那步。
add_step 的 note 是 worker 理解方向的唯一上下文：为什么开（依据哪个 fact，引节点 id+转述）、已知什么、下一步具体做什么。引用图内容=节点 id+转述，禁止粘贴目标响应原文。
```

- 收官判定变体（唤醒时图上无待办 step 则追加）：`【本轮模式】收官判定：图上已无待办 step——本轮三选一：派真方向 / prove_goal / conclude_task（若确实都探尽了）。`
- 审9 顺手：user 骨架【态势预取】下加两行字段导读（steps=全量含 note / recent_facts=最新 20+counts 总数 / findings=全量 / counts 里 edge:* 为边计数）。
- 依赖：P2F-4（conclude_task 工具先落）。
- 验收：canary 复跑（§3）。

### P2F-4 conclude_task 出口（审2）

- `graph.ts`：`concludeGoal(db, {taskId, reason, sessionId})`——**前置校验 openCount==0**（回执说明"还有待办 step，无权宣判终局"）；goal 必须 open（重复盖章拒）；reason 非空（≤1000 截断落 detail）；state→`closed` + completed_at；logActivity（tool="conclude_task"）。不加 proves 边（收尾不是证明）。
- `planner.ts`：concludeTaskTool；描述注明程序防线。
- `scheduler.ts`：终止检查加 goalClosed → `reason: "goal-closed"`；reason 联合类型加 `"goal-closed"`、删无路径的 `"no-open-step"`。
- `index.ts`：goal-closed 退出码 0。
- 语义边界：conclude_task = **任务级**收尾（所有方向探尽，一次性，goal 翻 closed）；单条攻击路径的放弃**不需要它**——planner 不往那个方向派 step 即可（封方向，日常隐式判断）。
- 对 worker 影响：零。
- 重跑语义按 D9（reopen=新 goal+原图续跑）；入口 M5 UI / P3 CLI，本批不做。
- 验收：单测——合法收尾 / 有 open step 拒 / 重复拒 / 空 reason 拒；mock 场景——conclude 收尾循环。

### P2F-5 run.lock 互斥 + 停止 watcher（验收#3，D10）

- **锁**：`<task>/control/run.lock`，JSON `{pid, started}`。`runTask` 入口：锁存在 && pid 活（tasklist 校验镜像名 node.exe，防 PID 回收误判）→ 抛错"已有运行中的调度进程 pid=N，拒绝双开"；pid 死 → 覆写接管。释放：`finally` 删锁。
- **stop watcher（主菜）**：runTask 统一持有一个 AbortController，runWorkerStep / runPlanner 的会话 abort 接到它上（与各自 timeout abort 并联）；1-2s 定时器盯 `control/stop`，发现 → abort 当前会话 → 走与 stepTimeout 完全相同的优雅收尾（step 落 exhausted、已产出保留）→ 循环以 control-stop 退出。停止响应从"最长一个 step（~9min）"降到秒级。
- `stop` 命令：写信号文件 + 打印锁 pid（人工 `taskkill /PID N /T /F` 兜底，仅真僵死；不自动杀）。
- 验收：单测——锁三态（活拒/死接管/收尾删）/ watcher 触发 abort（替身断言）/ 优雅退出 reason=control-stop。

### P2F-6 唤醒机制方案 C：全面事件驱动（D6）

- `scheduler.ts` 循环改：每轮收割事件后，**有新事件（step_done/finding/hint/resume）→ 先唤醒 planner（消费事件）再领 step**；空事件且有 open step → 直接 worker 不唤醒。
- planner-zero 判定保留：唤醒后仍无 open step 且 goal 未达 → 判停。
- **hint 介入程度（语义存档）**：建议级（advisory）非指令级——hint 是给 planner 的输入不是命令，planner 可采纳（派对应方向 step）/部分采纳/判断无关而忽略；人不直接命令 worker（D5），不改 goal（那是 reopen/D9），不打断在跑 step（那是 stop/D10）。时效（方案 C 后）：当前 step 跑完的下一次唤醒即消费。**执行层实时介入走 steer（D11/P2F-11）**；ARTEX 式 planner 级 steer_work/kill_work 仍 P3 再议。
- 验收：mock 场景——每个 step_done 后 planner 被唤醒（计数断言）；hint 到达下一轮即进 planner；空事件轮不唤醒。

### P2F-7 worker prompt 微调 + 态势瘦身（审6/8/7）

- `agent.ts` renderStepPrompt 完成定义第 3 步后追加阴性句（全文=汇编 §五拟新增）。
- `tools/exec.ts` Bash 描述改："curl 就绪（管道/grep 可用）；nmap/dig/nc 未预装——端口探测用 curl 等价实现（如 `curl --connect-timeout` 探活），确需 nmap 时提示平台安装"。
- **审7（本批做）**：renderStepPrompt 的【全局态势】改精简版——goal + 本 step 血缘 facts（parent_ids 链上 fact 摘要）+ counts 总数；不含全图 steps/findings 明细（那是 planner 的视野）。planner 侧 overview 不动。
- 验收：单测——精简态势渲染只含血缘；prompt 快照含阴性句。

### P2F-8 standards/ 参考目录机制（D4）

- **`<task>/standards/` = agent 参考资料唯一目录**。本批落 `src标准/` 五份厂商评级 txt（小米/美团/腾讯/菜鸟/阿里云）；用户后续提供 skills 手册时拷入同目录（源路径待提供，卡内留钩子）。
- `initTask`：standards/ 不存在 → 拷贝 + 生成 `standards/INDEX.md`（每份手册一行：文件名+一句话描述，取自首行或手写）；已存在跳过（幂等，历史 task 保持创建时快照）。
- **渐进披露（复刻 skill 的"只加载 description"特性）**：renderStepPrompt 的 user 首条加【standards 索引】节——注入 INDEX.md 内容（几行，固定小开销）；正文按需 Read/Grep（用一次付一次）。system 保持字节级稳定，索引坐 user 首条。
- 两处引导行（挂触发条件，不挂"必读"）：
  - `submit_finding` 描述末尾："severity 定级拿不准时，Read `standards/<目标厂商>.txt` 查该厂商评级细则（Grep 关键节，不全量读）；目标厂商不在列则按通用自评。"（全文=汇编 §六拟新增）
  - renderStepPrompt 开工句："开工按 step 方向查阅 `standards/` 下相关手册（评级细则/方法论），有则先读相关节，没有就跳过。"
- worker 的 Read 已锚定 taskDir，目录自然可读，无额外代码。
- 验收：单测——initTask 落 standards/ 五文件；二次 init 不覆写。

### P2F-9 小项清账（验收#6）

- `planner.ts`：add_step 闭包加 rejectedCounter 回填 `RunPlannerResult.rejectedCount`；logActivity summary 带"拒N条"。
- 删 `RunTaskResult.reason` 的 `"no-open-step"`（P2F-4 一并）。
- `goal_changed` 类型保留，标注 P3 由 CLI goal 命令发射。
- 验收：39 存量全绿 + rejectedCount 单测。

### P2F-11 steer 通道（D11）

- **写入侧**：CLI `steer <task> [--step <id>] "文本"`——默认定向当前唯一在跑 step；**无在跑 step 时拒绝**并提示改用 hint（显式选择原则，不自动转 hint）。UI（M5）= worker 列表 + 各自在跑 step 显示 + 输入框。文件：`control/steer.jsonl`（追加式，带 ts + target stepId）。
- **消费侧**：D10 的 watcher 加第二信号源——读到新 steer 行且目标 step 正在跑 → 对当前 Agent 调 `steer()`，消息模板：`【操作员插话】{text}——情报补充/纠偏，不是新任务；完成当前 step，相关观察落 fact 上抛。`目标不在跑（刚完成）→ 丢弃 + activity 记录（UI 下单时即知在跑，此为竞态兜底）。
- **worker prompt 插话纪律**（拟新增句见汇编 §四）：接受插话为上下文补充，不弃当前 step、不自开新方向。
- **planner 可见性（防盲区）**：新 trigger 事件 `steered{text, stepId}`——step 收尾时与 step_done 一起渲染给 planner（"操作员曾对 step #N 插话：…"），调度权威不破。
- **落账**：activity worker="operator" tool="steer"。
- **安全面不变**：steer 是消息非工具调用，guard 照拦所有 Bash/browser。
- 验收：单测——在跑时 steer 触发 agent.steer（替身断言）/ 无在跑拒 / steered 事件渲染；mock 场景——steer 后 step_done 事件组含 steered。

### P2F-10 文档回写

- `P2-planner调度施工计划.md` §7 两处更正：①"中断续跑"实况=双开重叠（甲从未死，03:07:58-03:17:15 连续 22 条记录为证）+ s7 实为自身超时掐断（~9m17s）；②"step 超时未真实验证"撤遗留守真。
- 本文档竣工后回写状态。

---

## 2. 量级预估

~420-530 行 TS（C 唤醒/锁+watcher/conclude/通道/瘦身/standards/steer/清账）+ prompt 两文件 + ~280 行测试。无新依赖。

## 3. 验收方案（四层，层间门禁——风险结构：这批大半是行为变更，核心危险是"老能力悄悄回退"）

**层1 确定性单测 + mock（零 LLM，机器判）**

- 存量 39 条全绿（回归保护——不动语义的卡不许顺手改坏）。
- 新增 ~15 条：P2F-1 通道配置生效 / P2F-2 `.map` reject / P2F-4 conclude 四态 / P2F-5 锁三态+watcher abort / P2F-6 每 step_done 唤醒+空轮不唤醒 / P2F-7 精简态势+阴性句快照 / P2F-8 拷贝幂等+索引生成 / P2F-9 rejectedCount / P2F-11 steer 触发+拒绝+事件渲染。
- prompt 快照字节级断言：v1.2 落位 / 阴性句 / 插话纪律句 / 收官判定变体 / standards 索引节。
- mock +3 场景：conclude 收尾（reason=goal-closed）/ 事件驱动唤醒节奏 / steer 后 steered 事件组。
- **门禁：100% 绿才进层2。**

**层2 故障注入手测（本批特色——修的全是故障路径，单测覆盖不了时序）**

| # | 场景 | 判据 | 取证 |
|---|---|---|---|
| H1 | 双终端同 task 双开 | 第二个 run 被锁拒并报 pid | 终端输出 |
| H2 | 跑批中 stop | 当前 step 秒级 abort 落 exhausted，reason=control-stop | activity + step 状态 |
| H3 | 跑批中 steer | worker 下一轮收到【操作员插话】，step_done 事件组含 steered | activity（operator/steer 行）+ 触发渲染 |
| H4 | 杀进程重跑（锁接管） | 残留锁被接管，清扫正常，续跑不回退 | session_id 时间线 |

- 可用 mock worker 快验机制；H2/H3 各抽一次真 LLM。
- **验收即取证**（P2 教训制度化）：canary"中断续跑"的叙述与实际（双开）有出入，事后靠 activity 复盘才发现——本批起每项验收**当场**留存 task 原始数据 + session_id 时间线，不凭事后回忆。
- **门禁：全过才进层3。**

**层3 canary 真靶回归（真 LLM）——行为变更不回退是核心判据**

- **回归五项**（P2 原验收重跑）：链式分步派 / 不重派 / goal 自停 / 中断续跑 / 计量分列。
- **新剧本 A（goal-closed）**：不可达 goal（"拿到 RCE shell"——canary 无此洞）→ planner 探尽后 conclude 收尾，reason=goal-closed，**无凑数 step**（人工判最后两轮派单是否真方向——审2 的直接验收点）。
- **新剧本 B（介入时效）**：跑批中插 hint（下一轮 planner 消费）+ 真跑 H3 steer——顺带补掉 P2 遗留的"hint 真 LLM 验证"。
- 量化门禁：打穿 ≥3/4（P2 基线 3）、干扰 0 误报（基线 0）；noreport 程序层拒单在 activity 可查。
- **自带对照**：canary-p2（v1 行为基线，随 P2 commit 保护）vs 新 task canary-p2fix——对比 step 数 / 唤醒数 / token / 0 派率，机制变更的副作用看得见。
- **门禁：回归五项不回退 + 两剧本过；任何回退 → 修 → 从层1 重跑全链路（回归是全链路性质，不许只补测）。**

**层4 汇总与回写**

- 验收记录落档（P2 惯例）：各层结果 + 证据指针。
- P2F-10 文档回写同步执行；本施工单状态改竣工。

**顺序纪律**：先 commit P2（基线与对照数据入库）→ 开工 fix → 层1 → 层2 → 层3 → 层4。

**canary 复跑（真 LLM，建议）**：v1.2 全链路不回退（链式派/不重派/prove_goal 自停）；goal-closed 场景（不可达 goal → 探尽后 conclude，无凑数 step）；hint 到达下一轮即消费；双开防御手测（锁活二次 run 被拒）。

## 4. 明确不做（本批边界）

planner 失败重试 / planner-error reason（用户统一调默认设置时一并）；list_facts q 过滤（P3 资产表）；goal_changed 发射（P3 CLI）；reopen 命令（M5 UI，D7 登记）；kill/steer、多 worker（本大阶段不做）；retester/ask（P4）。

## 5. 拍板记录

Q2（closed 后重跑）→ D9：reopen=新 goal+原图续跑。Q4（stop 杀锁）→ D10：三层停止，不自动杀。Q5（目录名）→ D4：standards/。**全部拍板完毕。**

## 6. 参考系调研：任务如何收官（Cairn vs ARTEX vs AT1 现状，2026-10-18）

**Cairn（`dispatcher/prompts/default/reason.md`）**：单一大 goal + reason 阶段每轮判"facts 是否满足 Goal"——满足 → `{"complete": {"from": [fact_ids], "description": 论证}}`（即 prove_goal，from 必须引 Valid facts）；不满足 → 派 intents。硬规则"Open Intents 为空必须派"。**无放弃出口**，探不尽靠外部预算/容器停。

**ARTEX（`agent/goals.go` + `planner.go` + `db/exploration.go`）**：
- **目标分解器是 LLM 阶段，不是静态脚本**——goals-decomposer 系统提示词（拆分原则：目标=最终可交付结果、侦察/步骤/验证禁止列为子目标、独立交付物分别列出、严禁臆造）驱动一次 LLM 调用输出 GoalSpec 列表；**LLM 不可用/零输出时回退规则拆分**（代码注释原话："the caller then falls back to a rule-based split so goal nodes always exist"）。
- 收官：planner 逐个 prove_goal（state→met），DB `COUNT(*) FILTER (WHERE state='met')` 聚合，**全部 met = 系统自动判任务完成**——收官完全由逐个 prove_goal 驱动。
- goal 状态只有 open/met，**无 abandoned/failed**；探不尽由任务 deadline（taskclock）夹逼，wrapup prompt 明言"本轮步数耗尽≠任务终止"。

**AT1 v4 现状（P2 已实现 + p2fix 增量）**：
- **goal 节点**：单数，initTask 从 task.json 人写的 goal 建 root goal（无分解器；ARTEX 式多 goal 分解可作为 P3 可选——在 initTask 后插一个 LLM 阶段，canary 的"确认至少一个越权读取"这类单一可验证目标目前够用）。
- **结束触发 = goal 节点状态，不是边**：`prove_goal(goal_id, evidence_id, reason)` 把 goal.state 翻成 achieved 并落一条 `proves` 边（evidence fact → goal）；scheduler 每轮边界查 goal 状态 → 退出（reason=goal-achieved）。p2fix 后加 `conclude_task` → state=closed（**不落 proves 边**——收尾不是证明）→ reason=goal-closed。
- **边的角色 = 账本，状态 = 开关**：proves（fact→goal/finding，证据血缘，审计"谁证明了谁"）、dispatch（goal→step，谁派的）、produces（step→fact/finding，谁产出）、derives_from（上游→新 step，派生依据）。边不参与结束判定，但 prove_goal 的 D7 校验（evidence 必须是图内 fact）靠图结构把关"空气证据"。（dispatch 在单 planner 单 goal 的今天只有审计价值、近乎常数列——留：成本≈0 每步一条 INSERT，多 goal/多 planner 一来立刻有用。）
- 结束触发器全景（p2fix 后五条）：prove_goal（达成）/ conclude_task（探尽，仅空位）/ maxRounds / budget / control-stop。

### 6.4 ARTEX 目标分解器批判（D8 决议存档：不学）

**精妙处**（知道它好在哪，才谈得上不学什么）：
1. **可验证性锚定**——goal=可独立验证的交付物，prove_goal 判定机械化（`COUNT FILTER state='met'`），收官零主观判断；
2. **防目标漂移**——goal 建任务时钉死，planner 中途挪不了门柱（想收场只能真证明）；
3. **与资产/覆盖度耦合**——goal 挂资产、覆盖度分母由此而来（AT1 无资产层，这三分之一价值天然用不上）。

**对我们的场景是过度设计**："对目标做已授权渗透测试"这类模糊 goal，分解器只能发明量化代理（"发现≥N个洞"）——虚假精度，未必是操作员真实意图；真实的测什么/测多深取决于踩点后才知道的地形。AT1 拍板：**延迟/自适应分解**——planner 用 step 边探边分解（与 Cairn 搜索哲学一致）。代价：模糊 goal 下 prove_goal 判定变软（"测完了没有"是 planner 判断）——由 conclude_task（探尽收尾，D2 防线）+ 预算兜底承接。偷走的唯一纪律：goal 尽量写成可验证结果（建任务时引导文案，不做机制）。

### 6.5 停止机制对照（D10 依据）

- **Cairn**（`dispatcher/runtime/cancellation.py`）：协作式取消——线程锁 + 一次性 reason + **attach_process（当前执行单元句柄挂在取消器上）**，cancel 即时传导到在跑进程；heartbeat 线程监健康；容器层 `cleanup_stopped` 硬清理兜底。
- **ARTEX**：两层——server `StopTask(taskID)` ctx 取消贯穿全任务 goroutine；planner 手握 **kill_work**（停单条在跑意图，标 stopped 不自动重领，先 `get_worker_output` 看它在干嘛再决定）+ steer_work 纠偏——多 worker 世界的设计。
- **AT1（pi L1）**：比 Cairn 还直接——scheduler 与 worker/planner 会话**同进程**，Agent 自带 `.abort()`（优雅中止，与 stepTimeout 同一条路，canary 已实证 s7 路径：abort 后正常落 exhausted+保留产出）。拍板三层：stop 文件（意图）→ **进程内 watcher 调 abort（秒级优雅停，主菜）** → 锁 pid 人工 kill（真僵死兜底）。kill_work 类单意图止损：P3 多 worker 再议。

---

## 7. 竣工记录（2026-10-18 施工暂停点）——逐卡落点与验证

> 实现了什么（本节，逐卡落点+偏离）／验证了什么（`docs/p2fix-验收记录.md`，四层证据）。
> 状态：11 卡全落码；层1 67/67 绿、层2 H1-H4 全过、层3 Run A 回归+剧本B 过；剧本A 暂停在 canary-p2fix-b step#46（续跑命令见验收记录 §3）。未 commit。

### P2F-1 worker 通道接 config.yaml → ✅ `scheduler.ts`（runWorkerStep 调用传 `channel: cfg.channels.worker`）+ `agent.ts`

- `RunWorkerStepOptions` 加 `channel?: ChannelConfig`；内部 `opts.channel ? createChannelFromConfig(...) : createChannel(mode)`（P1 兼容入口保留）。
- 验证：单测（createChannelFromConfig 跟随 model/keyEnv/api + keyEnv 缺失报人话错）+ mock 断言调度传整份配置 + Run A 真机跑通。

### P2F-2 noreport endpoint 接通 → ✅ `graph.ts:submitFinding` + 偏离：contracts.ts + tools/submit.ts

- 卡内"一行"实为三处：**FindingPayload 契约原本无 endpoint 字段**——加了 `endpoint` 契约 + submit_finding 工具参数 + execute 透传，`endpoint: payload.endpoint ?? ""` 才有源头。验证：单测（干净 summary+`.js.map` endpoint → reject 硬拒不入图；凭证实害豁免先于端点终审——豁免顺序不变）。

### P2F-3 planner prompt v1.2 → ✅ `planner-prompt.ts` 全文替换 + `planner.ts`（stalled 判定改 v1.2 语义）+ `triggers.ts`（stall 渲染改"接力唤醒"）

- 系统词=卡内 v1.2 决策流程式全文；收官判定变体挂 user 尾（`stalled = open==0 && !achieved && !closed`，不再要求 done>0——bootstrap 空图也适用三选一）；审9 字段导读两行坐【态势预取】下。
- **验收中一次收紧**：变体从"三选一"改"三选一必答，0 派不是选项"（起因=429 事故误判为模型不 conclude；收紧本身语义更严，保留）。
- 验证：prompt 字节级快照断言（v1.2 落位/旧死文字已删/变体/导读）+ Run A/Run B 真机行为。

### P2F-4 conclude_task 出口 → ✅ `graph.ts:concludeGoal/goalClosed` + `planner.ts:concludeTaskTool` + `scheduler.ts`（goal-closed 终止）+ `index.ts`（exit 0）

- 程序防线按卡：goal 必须 open（重复拒）/ openCount>0 拒（"无权宣判终局"）/ reason 非空 / state→closed+completed_at / logActivity(tool=conclude_task) / **不落 proves 边**。reason ≤1000 截断落 detail。
- 验证：单测四态 + mock conclude 收尾循环（reason=goal-closed）。真模型触发=剧本A 暂停项。

### P2F-5 run.lock 互斥 + stop watcher → ✅ `scheduler.ts`（acquireRunLock/releaseRunLock/isNodePidAlive + watcher interval）+ `agent.ts`/`planner.ts`（abortSignal 并联）+ `index.ts`（stop 打印锁 pid）

- 锁：`control/run.lock` JSON{pid,started}；活锁拒（tasklist 校验镜像名 node.exe 防 PID 回收误判）/死锁覆写接管/finally 释放（只删自己的——接管竞态保护）。
- watcher：1.5s tick（`watchIntervalMs` 测试钩子可调）盯 control/stop → AbortController 统一 abort worker/planner 会话（与各自 timeout 并联，同一条 exhausted 优雅收尾）→ 循环 reason=control-stop；planner 唤醒期间 stop 到达则不再开新活。
- 验证：层2 H1（真双终端拒+报 pid）/H2（5 秒收尾）/H4（杀进程死锁接管+尸体清扫）全真机；单测锁三态+watcher 替身断言。

### P2F-6 唤醒机制方案 C → ✅ `scheduler.ts` 循环重写

- 每轮收割事件后：有事件（step_done/finding/hint/steered/resume）→ 先唤醒 planner 消费再领 step；空事件且有 open step → 直接 worker；唤醒后无 open 且 goal 未达 → planner-zero 判停（保留）。终止检查增 goal-closed。
- 验证：mock 唤醒节奏（每 step_done 一次/空轮不唤醒）+ Run A 真机（2 step 2 唤醒）+ 剧本B（4 事件单次唤醒全消费）。

### P2F-7 worker prompt 微调 + 态势瘦身 → ✅ `agent.ts:renderStepPrompt` 重写 + `graph.ts:stepLineageView`（新）+ `tools/exec.ts`（Bash 描述）

- 阴性出口句（3.5 步）按汇编 §五逐字；Bash 描述改"curl 就绪（nmap/dig/nc 未预装，curl 等价探活）"按审8；审7 瘦身=worker 态势改 `stepLineageView`（goal+derives_from 血缘 facts+本 step 直产 facts+counts），planner 侧 graphOverview 不动。
- 验证：单测（血缘只含链上/旁支不串/形状无全图字段/阴性句快照）。

### P2F-8 standards/ 参考目录 → ✅ `task.ts:initStandards` + `agent.ts:readStandardsIndex` + `tools/submit.ts`（submit_finding 定级引导行）——偏离：挂 loadTask 不挂 initTask

- 卡写"initTask 拷贝"，但 initTask 无 taskDir 参数；落 `initStandards()`（先建目录拷五 txt+手写 INDEX.md 一行一册；零拷贝回滚不落半空；已存在跳过=历史 task 快照幂等）挂 **loadTask**（所有 CLI/run 公共入口，语义等价"init 时落位"）。
- 验证：单测（拷贝+INDEX 生成+二次不覆写+无源不落目录）+ Run A 真机（standards/ 五文件落 task）。
- **实抓真 bug**：初版先 copyFileSync 后 mkdir，ENOENT 被 try/catch 吞→standards 整体不落地。修：先建目录。

### P2F-9 小项清账 → ✅ `planner.ts`（rejectedCounter 回填+logActivity"派N条拒M条"）+ `scheduler.ts`（删 "no-open-step"）+ `triggers.ts`（goal_changed 保留，P3 CLI 发射）

- 验证：单测（闭包计数器拒收回填）+ 39 存量回归全绿。

### P2F-11 steer 通道 → ✅ `steer.ts`（新：appendSteer/harvestSteers/currentRunningStep/renderSteerMessage）+ `scheduler.ts`（watcher 第二信号源+送达/竞态丢弃留账）+ `triggers.ts`（steered 事件）+ `agent.ts`（SteerableTarget.onAgent+插话纪律句）+ `index.ts`（CLI steer，无在跑拒）

- 写入侧：`control/steer.jsonl` 追加带 ts+stepId，偏移收割；无在跑 step 显式拒绝提示改 hint（不自动转）。
- 消费侧：watcher tick 读新行→目标在跑→`agent.steer({role:"user",...})` 送达（消息模板按卡）+ events.push(steered) 给 planner + activity operator/steer；目标不在跑→丢弃+is_error 留账。
- 验证：层2 H3 真机（送达 5s 内+worker 吸收产出 fact+steered 进下一轮 planner 事件组）+ 单测（收割偏移/模板/currentRunningStep/竞态丢弃）+ mock 送达替身断言。

### P2F-10 文档回写 → ✅（暂停点版本）

- `P2-planner调度施工计划.md` §7 三处更正：①中断续跑实况=双开重叠（甲从未死，03:07:58-03:17:15 连续 22 条 activity 为证）+s7 实为自身超时掐断（~9m17s）；②"step 超时未真实验证"撤遗留守真（p2fix #23/#24 真机补验）；③hint 真 LLM 行补验勾销（Run A 4 事件批）。
- 本施工单：状态行更新至暂停点+本节竣工记录。
- 验收记录：`docs/p2fix-验收记录.md`（四层证据/对照基线/遗留清单/器械环境）。

### 验收中环境事故与器械记录（存档）

- **bigmodel /paas/v4 余额耗尽（429 code 1113）**：症状=runPlanner 吞错显"派0条"极易误判为模型不 conclude；5 个 worker step"完成却零产出"。切 GLM Coding Plan `/api/anthropic`（`v4/config.yaml`；`/api/coding/paas/v4` 实测可用备选）后全链恢复。由此新增遗留：**LLM 报错透传/零产出标记**（见验收记录 §5.1）。
- git-bash curl 中文 payload 按 GBK 发送（0xbb）→ 远端 UTF-8 解析报错；连通性测试用 ASCII。
- 靶场启动：`"C:\Program Files\python\python.exe" canary-web/target.py`（默认 python 无 flask）。
