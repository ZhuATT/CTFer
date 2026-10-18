# P2 施工计划：planner 与调度循环（v4 第三阶段）

> **定位**：给系统装上"脑子"——planner 会话 + 单 worker 同步调度循环 + 触发渲染 + 停/断/续 + message 通道 + 通道配置化。**P0 验证了 worker 能干活，P1 验证了产出变成正确的图，P2 验证"派活-干活-再派活"的调度正循环。**
> **上游设计**：`图与基底重构设计.md` §3（角色与调度）/§3.3（planner 实现·重派规则·复核）/§3.4（续跑三场景）/§4.6（prompt 层）。
> **基线**：P1 已推送（`b43fb46`）。代码布局：v4 主干 + `legacy-python/`（v3 冻结归档，2026-10-17 完成分离）。
> **状态**：**✅ P2 竣工（2026-10-17）**——P2-0~P2-7 全落地：39 单测绿 + mock 集成 4 场景过 + canary-web 真 LLM 验收 5/6 过（goal-achieved 自然停机）。逐卡详情见 §7 竣工记录。

---

## 0. 决策点（全部已拍板，2026-10-16/17）

| # | 决策 | 内容 |
|---|---|---|
| D1 | 单 worker，但**停/断/续做扎实** | 砍的只是并发机械（kill 在跑的/防抖/抢占）；停止（CONTROL）/中断（启动清扫）/续跑（幂等 initTask）为显式交付 |
| D2 | 通道配置化 | `v4/config.yaml`：worker/planner 各自 model/api/baseUrl/keyEnv——独立可配，为以后模型对照实验留口；M5 UI 读写同一文件（配置文件即 UI 数据层） |
| D3 | 程序兜底拒重 | add_step 入库前查"同归一化 summary 已 open"→拒收回执（刷卡机保险丝，防 planner 重复派活；ARTEX 纯靠 prompt 比对） |
| D4 | 验收靶 | 免费级=`canary-web`（本地 Flask:8790，4 真洞+7 干扰+双账号，legacy .venv 起）→ 真实级=用户届时提供 |
| D5 | message 通道 | 老 hints.jsonl 形态保留：task 目录 `control/hints.jsonl` → planner 唤醒时收割 → 渲染进【本次实际变动】；**人不直接命令 worker**，插话经 planner 转译（调度职责归 planner） |
| D6 | 组合扫描/负向复核 = planner prompt 研判规则 | 不做单独机制（派复核 step 就是一次普通 add_step）——jwzx 教训沉淀为 prompt 纪律 |
| D7 | 拒重之外的 prove_goal 兜底 | evidence_id 必填且必须是图内存在的 fact（防"挂空气证据"达标） |

## 1. P2 调度全景（一段话）

```
runTask(task)：initTask（幂等）→ 启动清扫（running→exhausted）→ loop {
  终止检查：goal 已证 / 预算尽 / 轮上限 / CONTROL stop 文件 → 优雅收尾退出
  hints 收割：control/hints.jsonl 新行 → 待渲染触发
  无 open step → 唤醒 planner（全新会话）：
      user 首条 = 开场白（有变动/停摆强制 二变体）
              + 【本次实际变动】（上轮 delta：step 结论+新 fact ids / finding / goal 变更 / hint）
              + 【态势预取】（graphOverview，recent_facts 截 20）
              + 【跨唤醒待办】（todos.json 渲染）
      工具面：add_step（≤4/批，拒重兜底）/ prove_goal（evidence 校验）/ TodoWrite / list_facts / node_detail
      产物：0..N 条新 step（多数唤醒 0 是正常）或 prove_goal
  worker：领第一条 open step（priority desc, id asc）→ runWorkerStep（P1 全套复用）
      → 完成（done/exhausted/blocked）→ 产生下轮触发
}
```

**成本纪律**（P2 起成本主项=planner 唤醒×态势大小）：step 全 open/running 时**不唤醒**（没空位）；态势预取截断（recent_facts 20 条+计数并排"看到 N/总共 M"防误判）。

## 2. 施工卡

### P2-0 触发事件与渲染（小卡）

- `TriggerEvent` 类型：`step_done{stepId, 结论摘要, newFactIds[], findingIds[]}` / `finding{findingId, severity, 摘要}` / `goal_added|goal_edited|goal_deleted{文本}` / `hint{text}` / `resume{节点数}` / `stall{}`（停摆强制变体）。
- `renderTriggers(events)`：拼【本次触发本轮的实际变动（先看这里）】——ARTEX `planner.go` 直译精简版。
- 触发来源接线：runTask 循环内 worker 收尾产出 step_done/finding；启动时图非空产 resume；hints 收割产 hint；无 open step 且 goal 未达标置 stall。

### P2-1 planner.ts 会话（中卡）

- `runPlanner(db, task, events, todos)`：pi Agent 全新会话（与 worker 永不同会话），`thinkingLevel:"low"`（glm 坑位），usage 落 activity（worker="planner"）。
- 工具面五个：
  - `add_step`（批量 intents 数组 ≤4：summary 必填/note/parent_ids 可选/priority 可选默认 0）——**D3 拒重兜底挂这里**；
  - `prove_goal(goal_id, evidence_id, reason)`——**D7 校验**：goal 存在且 open、evidence_id 是图内 fact、reason 非空 → goal state=achieved + 落 proves 边；
  - `TodoWrite`（读写 task 目录 `todos.json`——跨唤醒共享串行链载体）；
  - `list_facts`（分页 20，q 过滤可选——最简版：无 q）；
  - `node_detail(id)`（完整 payload）。
- **不做**：kill_work/steer_work（单 worker 无在跑可杀）、list_assets（P3）。

### P2-2 planner prompt v1（灵魂卡——调度哲学全量）

> **参考来源三股**（2026-10-17 补记）：①ARTEX `planner.go`（调度哲学主体）；②**v3 观察者手册**（`legacy-python/scaffolding/OBSERVER-MANUAL.md`）——"下轮建议"写法（主攻+备选+自由探索、建议口吻）直接吸收进 step note 结构，方向截断纪律同源；③v3 第零步"绝对不报"清单**不进 planner**（finding 准入归 worker 自判+P2-4 noreport 程序硬拒，分工见 §0/D6）。

静态 system（每轮字节级相同，缓存友好）+ user 首条动态。system 内容骨架（照设计 §3.3 + ARTEX planner.go 蒸馏）：

```
身份：规划者，被频繁唤醒。职责=读态势→判目标→只在确有未覆盖新方向时补 step。
  你是规划者不是执行者：本轮产物只能是【说清 step】或【判定目标】。

硬底线（最高优先）：目标未达且无 open/running step → 本轮必须产出 ≥1 条。
0 派正当理由：①已覆盖（open/running 已有同方向）②等依赖（下一步依赖在跑产出）。
  确有未覆盖新方向就该派，0 派不是偷懒默认。

重派规则（对 recent_done 的 step）：
  done=正常跑完 → 不原样重派；仅材料性新机理（新 fact/资产/本质不同打法）才重派，note 写差异
  exhausted=预算掐断 → 派"接上次进度继续"（依据=worker 结论与已有 fact，不凭空猜进度）
  blocked=外部故障没跑成 → 直接重派同方向；卡同一处→换打法
深度优先于覆盖度：发现高价值入口往深打穿，不为拉平铺广。
路线多样性：目标未达时保持 2-3 条机理不同的路线并存，某条交出逼近证据再集中。

负向 fact 复核：否定性观察是 worker 的观察非定论——采信前 node_detail 看 evidence：
  扎实+observed+手段穷尽→封方向；缺失/只探一次/inferred→按尚未探明处理，
  派一条复核 step（同一否定方向至多复核一次——复核过又在 recent_done 里就尊重结论）。

组合扫描：把图里 facts 当拼图再扫一遍——有没有两条以上记录拼起来才是完整攻击路径？
  典型形态：标识符可预测 × 吃该标识符的弱防护接口 × 泄露面。发现候选→add_step，
  note 写明链路并引参与组合的节点 id（不引证的方向不作数）。每轮最多 2 条。

串行利用链：强依赖链不要一次并行下发——用 TodoWrite 记整条链，本轮只派前置已满足的那步，
  待办会在下次唤醒时带回来。"同一件事"别拆两条。

prove_goal 纪律：目标含量化条件时必须核对态势实测值（findings 计数等），未达标禁止盖章。

提交：add_step 一次批量 ≤4 条最高价值的；summary=一句话（测什么+为什么）。
```

worker prompt 微调（P1 版加一句）："只做领到的 step；瞥见 step 外的线索→fact 的 summary 里点一句上抛，不动手"（P1 已有，复核确认）。

### P2-3 runTask 循环 + 停/断/续（中卡）

- `runTask(opts)`：§1 全景的循环实现；`maxRounds`/`budgetMs` 终止参数。
- **停止**：每轮边界检查 task 目录 `CONTROL` 文件（cmd=stop）→ 当轮 worker 已完成的产出保留，优雅退出（exit reason=control-stop）。
- **中断**：无需代码——SQLite 落盘天然存活；**启动清扫**：runTask 进入时 `UPDATE nodes SET state='exhausted' WHERE kind='step' AND state='running'`（v4 设计 §3.4 拍板）。
- **续跑**：`run <task>` 再敲即续（initTask 幂等 + 图状态即进度）。
- CLI：`run` 命令接 runTask（P1 的单发 runWorkerStep 保留为内部函数）。

### P2-4 程序兜底（小卡）

- **拒重**（D3）：add_step 每条入库前查 `kind='step' AND state IN ('open','running')` 且归一化 summary 相同 → 该条拒收，回执 `{rejected: "已有 open step #N 同义"}`（批量内其余照常）。**归一化规格（2026-10-17 定）**：trim+连续空白折叠+小写——**精确匹配不做语义相似**（保险丝定位：误伤阻断正活不可接受，漏放只浪费一轮且有第二道兜）；哈希仅可选加速（sha256 存列打索引）非判断依据，判断=归一化串相等，与 P1 fact 去重同套。**三道防线分工**：程序精确硬拒（零误伤）→ prompt 语义比对（"换措辞重复生成已有 step 是严重错误"）→ 范围限缩（只查 open/running，done 重派是 planner 合法自由）。升级后手（先不做）：漏放高频时改 token 重叠**警告回执**（不硬拦，判断还 planner）。
- **prove_goal 校验**（D7）：见 P2-1。
- **noreport 前置（2026-10-17 补卡——原设计 §4.1#6 漏排，用户抓出）**：submit_finding 进件时跑 noreport 检查（`legacy-python/src/noreport.py` 130 行 TS 平移：reject=形状即现象硬拒清单（.map/裸 instance-id/169.254/版本指纹类）；suspect=公诉意见回执提示复核；**实害豁免**：summary 声明影响/证据含凭证形状/手机号 → 放行）。reject 的回执给模型可读理由（哪类现象+“现象是载体时改报实际影响”）。
- 三处兜底的回执都设计成**模型可读的纠错信息**（指出冲突项 id / 违规类别），planner/worker 能自愈。

### P2-5 config.yaml 通道配置（小卡）

```yaml
# v4/config.yaml
channels:
  worker:  { model: glm-5.3, api: openai, keyEnv: AT1_API_KEY }   # baseUrl 内置映射，可覆写
  planner: { model: glm-5.3, api: openai, keyEnv: AT1_API_KEY }
run: { maxRounds: 20, budgetMs: 3600000 }   # 可选覆写
```
- loader ~50 行（缺省值兜底：文件缺失=全默认）；channel.ts 改为按名取配置；M5 UI 后端将读写此文件。

### P2-6 hints message 通道（小卡）

- 写入侧：`v4 hint <task> "文本"` CLI（或直接手写文件）；文件=`control/hints.jsonl`（追加式带 ts）。
- 收割侧：planner 唤醒前读新增行（按行数偏移记在 todos.json 旁或独立 offset 文件）→ 生成 hint 触发事件 → 渲染进【本次实际变动】（"操作员插入一条指示：…——据此调整/补充方向"）。
- 不直接命令 worker（D5）。

### P2-7 测试与验收

## 3. 验收清单

**确定性单测（零 LLM）**：
- [ ] renderTriggers 六类事件形状；开场白二变体（有变动/停摆）
- [ ] add_step 拒重：同 summary open 二派被拒、批量内部分拒部分收、done/exhausted 不触发拒（只拦 open/running）
- [ ] prove_goal：evidence 非 fact 拒 / goal 已 achieved 拒 / 合法路径落 achieved+proves 边
- [ ] noreport：`.map` 泄露类 finding 被 reject / 凭证实害豁免放行 / suspect 回执带复核提示
- [ ] 启动清扫：running→exhausted；CONTROL stop：轮边界优雅退出
- [ ] config.yaml loader 缺省/覆写/half 配置
- [ ] hints 收割偏移：不重放已消费行

**mock 集成（零 LLM）**：假 planner（脚本替身按剧本 add_step/prove_goal）驱动 runTask 全循环——派活→假 worker→触发→终止条件。

**canary-web 真验收（LLM，本地靶）**：
- [ ] 链式任务分步派：goal 设计成两步依赖（step2 需 step1 的 fact），断言 planner **先派 1 后派 2**，不并行下发
- [ ] 不重派：canary 打过一轮后重启 task，已 done 方向不原样重派
- [ ] goal 证明自停：可达成的 goal（如"确认至少一个越权读取"）→ prove_goal 后循环终止
- [ ] 中断续跑：跑两轮 Ctrl-C → 再 run → 从 open step 继续 + planner 不重复派已完成方向
- [ ] hint 生效：跑批中插入"重点看 /user/profile 接口"→ 下次唤醒后出现对应方向
- [ ] 计量：planner/worker 的 activity token 分列可见

**真实环境**：用户届时提供目标后按 canary 同清单跑（proxy env 注意事项沿用）。

## 4. 风险与预案

| # | 风险 | 预案 |
|---|---|---|
| ① | planner prompt 需要多轮调教（判断密集区，一版不会完美） | 预期 2-3 轮迭代：canary 验收暴露问题→改 prompt 重跑；prompt 独立成文件便于热调 |
| ② | glm-5.3 planner 判断力不足（重派/复核判断走样） | config.yaml 切换更强模型对照（D2 的口子就是为这留的）；判定标准=canary 四条真验收 |
| ③ | planner 态势超预算（fact 多后预取膨胀） | recent_facts 已截 20+计数并排；超了再收紧渲染字段 |
| ④ | canary-web 环境依赖（flask） | legacy .venv 直接起（`python target.py`），起不来再排查 |
| ⑤ | worker 干超 step 范围（单 step 会话膨胀） | timebox（runWorkerStep 传 timeout）+ 边界红线 prompt；实抓再收敛 |

## 5. 明确不做（边界）

并发 worker/kill/steer（P2 后按需再议）；资产表/list_assets/覆盖度（P3）；retester/ask 审批/规则表扩容（P4）；skills/MCP/watch UI；**量化 goal 的程序侧核对**（coverage P3 才有数据，P2 靠 prompt 纪律）；planner 的 Bash 探测豁免（ARTEX 有"开局 ≤3 次只读探测"条款——我们 planner 纯读图，不给 Bash，先看纯读图够不够，不够 P2.5 再议）。

## 6. 量级预估

~600-800 行 TS（planner.ts/runTask/触发渲染/兜底/config/hints）+ planner prompt ~1.5k 字 + ~400 行测试。无新依赖（yaml 用最简手写解析或加 `yaml` 一个包）。

## 7. 竣工记录（2026-10-17）——逐卡验收详情

### P2-5 config.yaml 通道配置 → ✅ `src/config.ts` + `config.default.yaml` + `channel.ts` 重构

- 手写两层 YAML 解析（缩进感知栈式，零依赖）；缺省兜底全默认；baseUrl 内置映射（openai→/paas/v4，anthropic→/api/anthropic）可覆写。
- channel.ts 重构为 `createChannelFromConfig(ChannelConfig)`——worker/planner 各自独立 model/api/keyEnv。
- **实抓坑**：初版解析器行内对象总是挂到上一个嵌套块（缩进不感知），顶层 `run: {}` 被塞进 `channels:` 里——单测抓住，重写为缩进栈式。
- 验收：`test/p2-units.test.ts` 缺省/覆写/half 配置/类型推定 2 条 ✓。

### P2-4 程序兜底三件 → ✅ `src/noreport.ts`（新）+ `graph.ts` addStep/proveGoal/submitFinding 接线

- **noreport TS 平移**：legacy-python/src/noreport.py 130 行逐正则平移（reject 形状即现象 3 类 / suspect 定性公诉 5 类 / 实害豁免门 0：IMPACT_RX+凭证形状+手机号）。**平移笔误实抓**：Python `(?<![无没])凭证` 的 lookbehind 被误写成空分支 hack——JS 原生支持 lookbehind，直接平移。
- **submit_finding 接线**：进件读证据文本（截 20KB）跑 noreport；reject 硬拒+模型可读回执（「现象是载体时改报实际影响」）；suspect 放行+公诉意见带回执。
- **add_step 拒重（D3）**：归一化精确匹配只查 open/running；批量内部分拒部分收（同批互斥也生效）；done/exhausted 不在拦截面。
- **prove_goal（D7）**：goal open + evidence 必须是图内 fact + reason 非空 → achieved + proves 边；重复盖章拒。
- **实抓坑**：addStep 的 INSERT 占位符数两次数错（5→7→6），better-sqlite3 "10 values for 9 columns" 单测直接抓出。
- 验收：拒重 2 条 / prove_goal 1 条 / noreport 三态 1 条 ✓。

### P2-0 触发事件与渲染 → ✅ `src/triggers.ts`

- TriggerEvent 六类 + renderTriggers（delta 优先「先看这里」）+ stepDoneEvent 构造器。空事件=心跳巡检文案。
- 验收：六类形状+二变体 2 条 ✓。

### P2-6 hints 通道 → ✅ `src/hints.ts` + CLI `hint` 命令

- `control/hints.jsonl` 追加式 + `control/hints.offset` 偏移收割（不重放）；容错解析（手写坏 JSON 整行当文本）。
- 验收：追加→收割→不重放→增量 ✓。

### P2-1/P2-2 planner 会话+prompt → ✅ `src/planner.ts` + `src/planner-prompt.ts`（灵魂卡）

- 五工具：add_step（批量≤4+拒重回执）/ prove_goal / TodoWrite（todos.json 全量覆写）/ list_facts（分页 20）/ node_detail。无 Bash（纯读图，§5 拍板）。
- prompt v1 独立文件（热调），吸收 v3 观察者手册 note 写法（为什么开/已知什么/下一步+引证 id+转述，禁贴原文）。
- **实现坑实抓**：acceptedCount 初版用 before/after 计数（两个都在 prompt 后调用恒 0）——改为 add_step 工具闭包计数器。
- usage 落 activity（worker="planner"）——计量分列 ✓（canary 实测：planner in=14965/out=9062，worker in=73455/out=52205）。

### P2-3 runTask 循环 + 停/断/续 → ✅ `src/scheduler.ts` + `agent.ts` 增强 + CLI

- 循环：终止检查（goal/stop/maxRounds/budget）→ hints → 无 open 唤醒 planner → worker 领 step（priority desc, id asc）→ step_done/finding 触发事件。
- 启动清扫 running→exhausted；CONTROL stop 轮边界优雅退出；runWorkerStep 返回值增强（newFactIds/newFindingIds/aborted→exhausted）。
- **实抓坑（Windows 大小写）**：施工卡的「task 目录 CONTROL 文件」与 hints 的 `control/` 目录在 Windows 大小写不敏感文件系统上**同名冲突**（writeFileSync 打到目录上 EISDIR）——stop 信号改落 `control/stop`。
- CLI：run（接 runTask）/ graph / hint / stop / reset-stop / init。
- 验收：mock 集成 4 场景（goal 证明自停 / planner-zero 判停 / CONTROL stop 轮边界 / 中断续跑尸体清扫+resume+hint 触发）✓。

### P2-7 测试与 canary 验收 → ✅ 39 单测 + mock 4 场景 + canary 真验收 5/6

**确定性测试**：39/39 绿（7 文件；P1 存量 24 + P2 新增 15）。mock 集成零 LLM 4 场景全过。

**canary-web 真 LLM 验收（glm-5.3，本地靶 :8790，两段 run）**：

| 验收项 | 结果 |
|---|---|
| 链式分步派 | ✅ seed 侦察 step → planner 基于侦察 facts 派 4 条攻击线（#7 IDOR/#8 会话伪造/#9 垂直越权写/#10 内部接口），不并行下发整链；planner 产出含路线/机理/血缘表 |
| 不重派 | ✅ 第二次 run planner 收 resume+stall 触发后**派 0 条**（done 方向未重派），直接复核盖章 |
| goal 证明自停 | ✅ `reason=goal-achieved`，goal #1 achieved（evidence=fact #20，proves 边落图） |
| 中断续跑 | ✅ ~~真实中断（进程被杀）后重跑~~ **p2fix 更正（P2F-10）：验收当时的"中断"实况是双开重叠——甲进程从未死（03:07:58-03:17:15 连续 22 条 activity 为证），第二个 run 才是引发重叠的元凶；s7 实为自身 step 超时掐断（~9m17s），非进程级中断恢复**。真实"杀进程→重跑"路径于 p2fix 层2 H4 补真机验证：taskkill 后残留锁被接管、running 尸体清扫 exhausted、resume 触发重派接续 ✓ |
| 计量分列 | ✅ planner in=14965/out=9062，worker in=73455/out=52205（activity 四列） |
| hint 生效（真 LLM） | ⏳ ~~未跑~~ → **p2fix Run A 已补真机验证**：跑批中插 hint，下一轮 planner 唤醒 4 事件批（step_done+finding+steered+hint）一次全消费 ✓ |

**战果（图上真实产出）**：15 facts 全 confirmed + 2 findings（#18 authbypass 高危：/admin/config/update 零鉴权写；#23 /internal/status 未授权读 medium）——canary 4 真洞中 worker 实际打穿 3 个（authbypass/内部接口/SQL LIKE 枚举线索），干扰项 0 误报（CORS/sourcemap/版本指纹全部只落 fact 不落 finding，noreport+worker 自判双闸生效）。边计数：dispatch×5 / produces×17 / proves×11 / derives_from×7。

### 遗留与预案触发情况

- planner prompt v1 首跑即达标（风险①预期的 2-3 轮调教暂未触发；重派/复核/组合判断需更多靶次样本）。
- step 超时 8 分钟掐断路径未在真 LLM 下验证（canary 中断是进程级被杀——恰好走了启动清扫路径）。
- hint 真 LLM 转译顺延下轮跑靶；CONTROL stop 真实验证同（mock 已过）。

### 测试运行结果与迭代记录（如实存档）

**终态**：单测 **39/39 绿**（7 文件：P1 存量 24 + P2 新增 15，`npx vitest --run`）；mock 集成 4 场景全过；canary 真 LLM 验收 5/6（表见上）。**迭代过程 4 轮**，首轮 24/39，各轮修复如下——

**第 1 轮暴露（9 失败）——三个真 bug**：
1. **`parseSimpleYaml` 行内对象挂错层级**（源码 bug）：初版用单一 `current` 指针，行内对象 `run: {maxRounds: 5}` 被塞进上一个嵌套块 `channels:` 里——顶层键与嵌套键无缩进区分。重写为缩进感知栈式解析。测试抓法：`loadConfig` 断言 `cfg.run.maxRounds === 5` 得 20。
2. **`addStep` INSERT 占位符数错**（源码 bug）：9 列写成 10 值（初版 5 个 `?` 传 6 参，第一次修又改成 7 个 `?`），better-sqlite3 报 `10 values for 9 columns`。教训：**带字面量混写的 INSERT 必须数 ? 与参数个数一一对应**，现已加行内注释锚定。
3. **mock 剧本模型错位**（测试设计 bug）：初版单 `act` 指针按 planner 调用递增，worker 与 planner 共读同一格——时序对不上，goal/fact 查询落空。重写为 `plans[]`（按 planner 唤醒序）/`workers[]`（按 worker 执行序）双独立指针。

**第 2 轮暴露（5 失败）——一个真 bug + 环境坑**：
4. **resume 触发条件恒假**（源码 bug，最有价值的一个）：初版判定 `stepIds.length === 0 && nodeCount > 1`——但 initTask 幂等分支返回**现有** steps，`stepIds.length` 恒 >0，**续跑时 planner 永远收不到 resume 触发**。修：initTask 返回值加 `fresh: boolean`，scheduler 判 `!fresh && nodeCount > 1`。若没被 mock 抓到，中断续跑的 planner 引导就是哑的。
5. **Windows 句柄 EPERM**（环境坑）：mock 测试 afterAll `rmSync` 临时目录报 `EPERM: Permission denied`——SQLite WAL 文件句柄在 Windows 上延迟释放。规避：afterAll 的 rmSync 包 try-catch（tmp 目录留给 OS 清理）。

**第 3 轮暴露（2 失败）——测试数据语义错**：
6. **中文空格归一化语义**（测试数据 bug）：拒重测试用「探测  登录接口  鉴权」期待与「探测登录接口鉴权」归一化相等——但空白折叠后前者仍是「探测 登录接口 鉴权」（中文无词间空格，折叠不消空格）。改用折叠后确实一致的串（「探测 登录接口鉴权」vs「  探测  登录接口鉴权  」）。
7. **测试查错行**：置 done 时 `ORDER BY id LIMIT 1` 拿到的是 seed step 而非被测的 planner step——改用 `r1.accepted[0].id` 精确定位。

**第 4 轮：39/39 全绿**，此后未再破。

**canary 实操教训（非代码 bug）**：
- **旧 dist 乌龙**：第一次 canary run 跑的是 P1 构建产物（P2 改完源码没 `npm run build`），planner 根本没参与，输出格式是 P1 的——靠输出格式对不上发现。**纪律：改完源码必须 build 再跑真验收**（`npm test` 不受影响，vitest 走源码）。
- **超时未掐观察**：#7 step running 超 8 分钟未被 `--step-timeout-min=8` 掐断——事后确认是 600s 命令行超时把整个进程迁后台时杀掉（非超时机制失效，pi 的 signal 透传已核实 ：371/:380）。~~超时掐断→exhausted 路径本身留待下次真跑验证~~ **→ p2fix 已真机验证（canary-p2fix-b B3/B5）：#23/#24 撞 6 分钟 step 超时 → abort → exhausted → planner 派「接续」step，产出保留，语义全对 ✓**
