# AT1 v3 施工计划(总纲:图与黑板 v3 + Prompt v3 合并)

> **依据**:`图与黑板v3设计.md`(定稿+§五 A17 修订)/`at1-黑板schema.md` v3.0(S1-S7 已落文)/`prompt-全文汇编.md`(v3 定稿,A1-A22)/`中期真实环境测试文档.md`(P-1~P-11 修复史与实机教训)。
> **代码基线**:commit `22ff975`(U-1),219 测试绿,19 模块 4637 行。
> **原则**:直接 v3 大版本无过渡步(Q-7);文件存储不上 SQL(触发条件挂起);**测试红线=每阶段完成时全绿**;git 管回滚。
> **进度(09-18)**:**批 1 已 commit(`45d7491`);批 2 已竣工并 commit 推送**——批 1=P0 全部+P1 全部+T2.1/T2.5;批 2=P2 全部余量(T2.2 STOP 接线/T2.3 七类行/T2.4 六节投影+两刷/T2.6 noreport/T2.7 events/T2.8 hints+CLI),223 测试全绿,dry-run CLI 全链路目检过;执行细节=`at1-v3批2-收割投影终态落地计划.md`+`at1-v3批2-施工执行单.md`。下一批=批 3(P3 worker 模板+P4 stdin 三块终态,prompt 在此合龙)。

---

## 执行协议(新会话开工前必读——本计划由独立会话执行,不依赖任何讨论记忆)

**开工引导序列**(新会话第一件事,按序读):
1. `prompt-全文汇编.md` §一~§四——终态架构/stdin 三块/worker 骨架/观察者骨架(语义权威)
2. `at1-黑板schema.md` v3.0——字段契约(结构权威;含 goal/guide/Stop/七类行)
3. `图与黑板v3设计.md` §五 A17 修订块 + §六——观察者/报告制度
4. 回到本计划执行。**冲突裁决序:schema > 汇编 > 设计文档 > 本计划**

**施工纪律**:
- 每完成一个 P 阶段 = 一次 commit(中文描述,列 T 编号);**commit 前全量测试绿**(基线 219,只增不减)
- 任务完成后在本文件该行验收列尾追加 `✅MM-DD`;计划未覆盖的决策点 → **标 UED 停下问用户,不擅自拍板**
- 不做过渡兼容(Q-7);删代码以 T1.6/T6.1 清单兜底
- 首件 = T1.1(图容器+迁移脚本+活契约);P0(skill 迁移)可并行插空

**UED 清单(开工时需用户裁决)**:
- dry-run 目标(P6 才需要,用户届时给)
- ~~v2→v3 迁移脚本~~ **已裁(09-18):不做内容迁移——每个 run 新开 v3 空板,旧板文件读到即归档改名(.v2-legacy.json);先验知识一律走配方 0 播种;T1.1/T1.4 相应验收同步作废(详见 at1-v3批1-图核心落地计划.md §三)**
- ~~poison_probe 归宿~~ **已裁(09-18):删除,到时按 v3 观察者形态写新探针**;~~中期文档改动归属~~ **已确认:保留原样,不随施工 commit**

---

## 〇、代码现状全景 → v3 命运(模块映射,函数级锚点)

| 模块(行数) | v2 现状(关键函数:行) | v3 命运 |
|---|---|---|
| **board.py** (961) | 黑板类:facts/findings/directions/immune/chains/session_intel 混存;被动抽取 `_extract_facts:124`;事实衰减 `verify_facts_against_transcript:610`;stage 机 `check_goal:568/_advance:604`;渲染 `render:745/render_summary:834/render_yaml_layer:857/plan_directive:922/intel_summary:917` | **核心重写**:graph{nodes,edges}+bookkeeping 两节;三原子操作+六不变量+去重/重编号;四派生视图(阴性/端点/谱系/未测面);goal 字段;Stop-TERMINAL;STATE.md v3 渲染器。**删**:被动抽取/衰减/immune 存储/session_intel/stage 机/全部旧渲染 |
| **driver.py** (642) | 收割 `_harvest_findings:52/_harvest_directions:193`;方向升格 `_handoff_unfinished_to_directions:215`;投影 `_render_state_projection:235`;观察者治理 `_apply_observer_governance:251`;控制 `_poll_control/_controller_kill/_consume_stop_file`;预检 `_preflight:121`;简报 `_brief:365` | **改造**:配方1 对齐(报告指针/声明边);`_harvest_directions`/`_handoff_unfinished_to_directions` **删**(A17③/A19);投影重写为 STATE.md v3;治理重写为配方2 七类行收割;**保留** preflight/控制停机(P-11 语义)+新增 Stop 收割/一键续跑/guide 注入;简报尾巴改写 |
| **runner.py** (549) | `spawn_once:373/kill_process_tree:331/StreamParser:119`;`extract_handoff:60`;续跑梯子/死因标签/stall 检测 | **保留**(P-11 停机语义实机终验过);小改:Stop 标记抽取(与 Handoff 同路径) |
| **observer.py** (306) | JUDGE/SESSION chat 双通道(`JUDGE_PROMPT/SESSION_PROMPT`);无工具 | **重写**:chat 退役(P-13 根除);-p 同构 spawn(全能力,.observer 工作台);OBSERVER 七类行输出;防注入声明/四步框架迁观察手册 |
| **writeback.py** (217) | 漏洞表 `append_status_row:28`;攻击面 `refresh_surface_depth:79`;`gen_prior_intel_draft:125`;台账搬运 `sync_human_ledger:166`(P-6);`parse_immune_from_status:197` | **改造**:三件+ledger_synced 保留;immune 解析改配方0 播种;新增报告晋升(.auto\reports→reports\) |
| **transcript_check.py** (210) | C-5 双向对账(喂 judge 的 anchor_note/事实衰减抽验) | **删除**(已裁 09-18,A23):消费者全死,A17 实测重放替代字节对账 |
| **prompt.py** (161) | 九段装配 `render_round_prompt:133`;`PREAMBLE/MANUALS/_HINT_ROUTES/_SEGMENT_MARKS` | **重写**:三块装配(引导/运行提示/简报);路由三信号(全图 fact 值扫描/覆盖缺口/图空);旧九段全删 |
| **scaffold.py** (127) | `_render_worker_claude:50/expand:72`;现渲染 {allow}/{deny_list}/{mission} 槽(:58-64)+内嵌 DIRECTIONS 教学文本(:43) | **重写渲染层**:新槽{target}/{hint}/{tools_root}/{env_bg};FORMATS.md/OBSERVER-MANUAL.md;reports\ 与 .observer\ 目录;私有区路径对齐;**fail-fast scope.allow 校验保留(A1 澄清,见 guard 行)** |
| **guard.py** (135) | 控制器区录像(P-5 修复后 Windows 双形态);**scope 拦截消费 engagement.json 的 scope.allow/deny(guard.py:61)** | **保留**;⚠ **A1 只砍 CLAUDE.md 渲染槽——scope 数据与 fail-fast 校验(scaffold:126)是 guard 的燃料,保留勿删** |
| **noreport.py** (125) | `check:81` 代码预检(现象类硬否决) | **保留**;接入 verdict 前置(硬拒条目收割器直接 dismissed) |
| **events.py** (93) | EventWriter/redact | **扩展**:stop/resume/guide_injected/observer_parse_fail 事件 |
| **harvest.py** (70) | 代码合成交接合成 | **重写**:合成交接机制死(A19);收敛为配方1 辅助 |
| **stoploss.py** (49) | 止损 | **保留原样** |
| **untrusted.py** (36) | nonce 包裹 | **保留**(A20 升级路径,本阶段不用) |
| **llm.py+providers.py** (484) | 双通道(worker=glm/bigmodel,观察者=deepseek/官方) | **保留+角色模型配置化**(A23:worker=glm-5.3-flash,观察者=glm-5.3,同 baseurl/AK;双角色 model/baseurl/ak 可配——配置文件先行,控制台将来可改) |
| **__main__.py** (424) | relay/selftest/run/watch CLI | **微调+控制面子命令**(A24):`goal --set`/`hint`/`stop`(resume=run);M5 UI 将来调同一批函数 |
| **json_utils.py** (42) | parse_llm_json 三层剥取 | **保留** |
| **blackboard.schema.json**(根目录) | v2 活契约:required 全是死结构(facts/immune/session_intel/verified);配 test_schema_contract 契约测试(结构真相双件套) | **随 T1.1 同步重写 v3**(graph/bookkeeping)——漏改=契约说谎+测试整片红 |
| **tests/**(23 文件 3417 行) | 一半在测将死结构(stage 机/九段/摘要/方向账本/transcript_check) | 精确处置=**11 改 / 1 删 / 9 保留 + poison_probe 待裁**,清单见 T6.2 |
| **tests/poison_probe.py** | 红队探针:伪造注入 evidence→真调 judge_finding 断言判定跟技术内容走 | **删除**(已裁 09-18:靶随 chat 通道退役;v3 跑顺后按新观察者形态写新探针) |

---

## 一、决策覆盖对照(每个拍板 → 施工任务)

| 决策 | 任务 |
|---|---|
| A1 砍槽+铁律 | T3.1 |
| A2/A3/A4/A5 三层契约+示例废+改向+兜底删 | T3.1/T3.2 |
| A6 砍序言 | T3.1/T4.1 |
| A7 砍路由表 | T4.2 |
| A8 FORMATS.md | T3.2/T3.3 |
| A10 v3§6.2 修订 | 文档已落,无施工 |
| A11 依赖=blocked+可检验条件(记账人=观察者) | T5.1 |
| A12 砍 stage/手册/门控 | T1.5/T1.6/T4.1 + P0 全部 |
| A13 fact 准入+fingerprint 回图 | T1.2/T4.2 |
| A14 目标画像 | T0.3/T3.2/T5.1 |
| A15 砍指令段+冷启动+术语清扫 | T4.1/T3.1/T6.1 |
| A16 砍摘要+计数行+开工序列 | T2.4/T3.1 |
| A17 观察者升格+DIRECTIONS 退役+goal | T2.3/T2.4/T5.1/T5.2/T1.5 |
| A18 探透/自由/Stop/探索义务 | T3.1/T1.5 |
| A19 Handoff 改道+合成交接死+引导写作规矩 | T2.2/T2.4/T4.1/T5.1 |
| A20 防注入本阶段不做 | (untrusted.py 保留即可) |
| A21 长任务三层+{env_bg} | T3.1/T5.1 |
| A22 description 条款 | T0.4 |
| S4 路由燃料/T6 goal/T7 配方 | T4.2/T1.5/T2.2/T2.3 |

**消解项核对**:Q1-Q5/N1/N2 均已被上述任务吸收,无独立施工;N3 告警撤出=T4.1(装配时自然消失)+ledger 数据留观察者;N3-2 运行提示形态=T4.1。

---

## 二、依赖图

```
P0 skill 迁移(独立,可先行) ─────────────────────────────┐
P1 图核心(board) → P2 收割投影(driver/harvest/writeback) → P5 观察者 → P6 终验
P3 worker 模板(纯文本,与 P1 并行) → P4 stdin(prompt.py,依赖 P3 模板+P1 结构) ─┘
```

关键路径:**P1→P2→P5→P6**;测试随各阶段写(T6.2 汇总),每阶段完成=全绿。

---

## 三、任务明细

### P0 skill 迁移(4 件,砍手册前置——不迁移=丢知识)

| # | 任务 | 文件 | 验收 | 决策 |
|---|---|---|---|---|
| T0.1 | 加"身份诊断三实验"节:cookie 摘除/身份注入对调/签名强制性+三场判例(携程/千问/听悟) | `.claude/skills/auth-token/SKILL.md` | 节+判例在;description 不动 ✅09-18 | A12 迁移/N5 |
| T0.2 | 加 IDOR 必做闭环(双账号/对象枚举/身份对调/响应 diff/写读回)+攻击四步 | `.claude/skills/auth-access/SKILL.md` | 五步+四步在 ✅09-18 | A12/N5 |
| T0.3 | 补:浏览器四步侦察/资产分诊/**WaitForMcpServers 第 0 步(P-7 实测教训,随手册①迁移不得丢)**/收尾画像行(冷启动措辞) | `.claude/skills/recon-methodology/SKILL.md` | 四件全在;画像行含前缀教学 ✅09-18(附带:P-7 回归测试由 skip 转真跑) | A12/A14/P-7 |
| T0.4 | 产出规范加 description 触发式守门条款 | `.claude/skills/distill-report/SKILL.md` | "Load when 收尾"一句在 ✅09-18 | A22 |

### P1 图核心(board.py,6 件)

| # | 任务 | 锚点 | 验收 | 决策 |
|---|---|---|---|---|
| T1.1 | blackboard.json v3 容器(graph/bookkeeping)+~~v2→v3 迁移脚本~~ **已裁(09-18):不做内容迁移——旧板归档改名空板新开,知识走配方 0 播种**+**活契约同步**:`blackboard.schema.json` v3 重写(v2 契约 required 里全是死结构:facts/immune/session_intel/verified)+`test_schema_contract.py` 契约测试同步(结构真相双件套锁死新容器) | `_load:200/save:235` 重写 | 旧板归档单测;免疫→阴性视图公式核对(合成 v3 夹具);新契约+正反例测试绿 ✅09-18 | §三/S 系列 |
| T1.2 | 节点模型:三 kind payload/状态机/公共 7 字段;三原子操作(controller 独占);六不变量;去重键;id 重编号 | 替换 add_fact/add_finding/add_direction/merge_directions | schema §2/§3 契约测试全过 ✅09-18 | schema |
| T1.3 | 边模型:六动词+方向约定+origin+兜底(声明优先,endpoint 兜底) | 替换 add_chains | 兜底单测 ✅09-18(兜底落 harvest.auto_link) | schema §4 |
| T1.4 | 四派生视图(零存储现算):阴性/端点分组/谱系/未测面 | 新函数 | 四视图单测(合成 v3 夹具;~~usc 数据回放~~已裁 09-18 随迁移取消) ✅09-18 | §三 |
| T1.5 | goal 字段(text/updated_round,**goal-set CLI 可改**,A24)+check_goal 重写:删 stage 机,TERMINAL=预算耗尽/人工停/**有效 Stop**(达成须引 F-xxx) | `check_goal:568/_advance:604` 重写 | Stop 解析单测(无引证=无效);O-4 随灭 ✅09-18(goal-set CLI 壳随批 2) | S5/S6/A18/A24 |
| T1.6 | 删除执行:被动抽取 `_extract_facts:124`/`observe/ingest_facts` 抽取路径/事实衰减 `verify_facts_against_transcript:610`/immune 存储 `add_immune:343`/`update_session_intel:373`/旧渲染全家(render:745/render_summary:834/render_yaml_layer:857/plan_directive:922/intel_summary:917) | 见左 | 术语清扫零残留(T6.1 联动) ✅09-18(board.py 零残留;src 全局死引用零) | 报废清单/A15/A16 |

### P2 收割投影写回(7 件)

| # | 任务 | 锚点 | 验收 | 决策 |
|---|---|---|---|---|
| T2.1 | 配方0 播种:prior-intel/status.md 漏洞表→节点(confirmed,origin=user);`parse_immune_from_status` 改播种 | writeback:197 | usc-fresh 播种回放 ✅09-18 批1(三源播种落地:情报行/漏洞表/非漏洞表→done intent;"usc-fresh 播种回放"项随迁移裁取消) | schema §6 |
| T2.2 | 配方1 轮末收割:FINDINGS(报告指针+chain 声明边+endpoint 兜底 yields)/FACTS(evidence 透传)/**HANDOFF→bookkeeping(读者=观察者)/STOP 抽取→TERMINAL**;DIRECTIONS 行废;**harvest.py 合成交接机制删(A19——观察者自己读磁盘)** | `_harvest_findings:52` 改;`_harvest_directions:193/_handoff_unfinished_to_directions:215` 删;harvest.py 合成函数删 | usc 增量账本收割回放;被杀轮不产合成 Handoff ✅09-18(收割半随批1;STOP 接线随批2;usc 真账本回放真跑) | S7/A19 |
| T2.3 | 配方2 观察者收割:七类行(verdict[noreport 前置]/edge[same_root 正主 dismiss/supersedes 状态迁移]/comment/intent[spawns]/intel/**guide→下一轮注入队列**);报告晋升;非法行隔离区 | `_apply_observer_governance:251` 重写 | 七类行单测+隔离区事件 ✅09-18(observer_harvest.py+10 测;driver 钩子 P5 激活;晋升函数就绪激活等批3) | S7/A17 |
| T2.4 | STATE.md v3 渲染:**头部第一行=计数行**;六节(任务概要含 goal/方向谱系/阴性/端点分组/全局认知含画像/Handoff 原文+报告索引);方向 cap+溢出行;一轮两刷(收割后/观察者后) | `_render_state_projection:235` 重写 | schema §8 对照;usc 渲染目检 ✅09-18(计数行+八节+两刷;刷1 为 P5 预铺) | A16/S6/A19 |
| T2.5 | writeback:三件保留;immune→阴性视图化;报告晋升 .auto\reports→reports\;ledger_synced 保留 | writeback.py 改造 | usc 收尾三件+晋升 e2e ✅09-18 批1(三件+阴性视图化/global 桶认知;报告晋升依赖配方2,随批 2/P5) | §七 |
| T2.6 | noreport 接入:硬拒条目 verdict 不受理,收割器直接 dismissed | harvest/driver | 现象类样本走 dismissed ✅09-18(收割时建节点即 dismissed+事件+剔除观察者输入) | 拍板(代码检察官) |
| T2.7 | events 扩展:stop/resume/guide_injected/observer_parse_fail | events.py | watch 回放可见 ✅09-18(白名单注册 10 新类型+watch 分支) | §七 |
| T2.8 | **留言队列**(A24):`.at1/control/hints.jsonl` 追加式(带 ts);driver 按偏移收割(同三账本 offsets 模式)→下轮【运行提示】人工指示项;CLI `hint` 子命令 | driver/prompt 装配 | 队列收割单测(追加→下轮必达→偏移推进) ✅09-18(hints+CLI 四壳;【运行提示】终态措辞随批3) | A24 |

### P3 worker 模板(3 件,可与 P1 并行)

| # | 任务 | 文件 | 验收 | 决策 |
|---|---|---|---|---|
| T3.1 | WORKER-CLAUDE.md 六节:身份开工({target}/{hint},铁律,Read STATE.md 第一件事,图空冷启动,**{env_bg} 长任务纪律**)/判层契约(**A2 三层+A4"宁可多开方向不轻交发现"+A5 无兜底**+画像指引)/写盘义务(FORMATS 必读+log.jsonl 记账[P-6 纪律保留])/干活规则(探透判定+自由条款+探索义务三出口+**<Stop> 信号格式**)/台账纪律/写操作约束;**{tools_root} 环境槽**(js-intel 路径) | `scaffolding/WORKER-CLAUDE.md` | 渲染产物无 v2 残留词;六节齐 | A1-A6/A15/A16/A18/A21 |
| T3.2 | FORMATS.md:FINDINGS/FACTS 行格式(A2 三层正反例:报错→方向/语法可控→T/拖出数据→F)/报告模板(单洞+链式八段)/画像纪律(前缀唯一/追加不换写);**无 DIRECTIONS 节** | `scaffolding/FORMATS.md`(新) | 示例全合 A2 判层 | A2/A8/A10/A14 |
| T3.3 | scaffold 扩展:双手册+FORMATS 每轮重写(防篡改)/reports\ 与 .observer\ 目录/私有区路径对齐 v3/新槽渲染/**engagement.json 字段映射**:goal 初值(→bookkeeping.goal 播种)+hint 字段(→{hint} 槽);**scope.allow/deny 保留(guard 燃料)仅停 prompt 渲染**;fail-fast 校验保留 | `src/scaffold.py` | dry-run 渲染产物检查;guard 用旧 engagement 照常工作 | A1/A8/A17/A24 |

### P4 stdin 装配(3 件)

| # | 任务 | 锚点 | 验收 | 决策 |
|---|---|---|---|---|
| T4.1 | render_round_prompt 三块化:【引导】(guide 注入)/【运行提示】(人工指示独占,空则消失)/简报;删 PREAMBLE/MANUALS/九段标记/plan_directive/render_summary 调用/重复告警段 | `prompt.py` 重写 | 渲染恰三块;空态块消失 | A6/A12/A15/A16/A19/A20 |
| T4.2 | 路由三信号:燃料=**全图 fact 值扫描**(替代 query("fingerprint"))/覆盖缺口(未测面含对象级端点→auth-access)/图空(facts 空→recon-methodology);措辞直接指令式 | `_HINT_ROUTES` 重写 | 三信号单测(usc 指纹回放命中) | A7/A13/S4/N5 |
| T4.3 | 简报尾巴:判层指引(CLAUDE.md/FORMATS 指路),去"发现即提交" | `_brief:365` | 渲染检查 | A4 |

### P5 观察者(3 件)

| # | 任务 | 锚点 | 验收 | 决策 |
|---|---|---|---|---|
| T5.1 | OBSERVER-MANUAL:质检(纸面+**实测重放**)/记账纪律(A11:blocked+可检验条件/瞥见立向/画像换代 supersedes+缺档审计)/引导写法(guide:主攻+备选+自由探索;**节点 id+转述禁贴原文**)/提新思路/红线(不杀/不中途/不判停/非强制;高危不做等作业纪律继承)/长任务扫尾(bg-*.log)/判定方法论(第零步+四步+src标准 路由) | `scaffolding/OBSERVER-MANUAL.md`(新) | 红线逐条在;方法论继承 v2 原文 | A11/A17/A18/A19/A21/§六 |
| T5.2 | observer.py 重写:chat 双通道退役;-p 同构 spawn(复用 runner 通道,全能力,`.observer\` 工作台);OBSERVER 七类行输出;0-finding 轮照跑(P-3 语义保留);**观察者 stdin 形态=最小任务单**(轮次+新发现/新报告索引+读 STATE.md 投影指引——细节它自己读,不喂快照,P-13 铁律);**角色模型配置化**(A23:双角色 model/baseurl/ak 可配,默认 worker=glm-5.3-flash/观察者=glm-5.3 同 bigmodel;配置文件→控制台) | observer.py 重写 | 七类行解析单测;双角色配置生效单测;观察者 stdin 零快照检查;真通道冒烟 | A17/A23/S7/P-13 |
| T5.3 | ~~transcript_check 处置~~ **已裁(09-18,A23):整文件删除**——消费者全死,A17 实测重放替代字节对账;引用点清理由 T6.1 清扫覆盖 | transcript_check.py | 删除后全绿 | A23 |

### P6 清扫测试实机(4 件)

| # | 任务 | 验收 |
|---|---|---|
| T6.1 | 术语清扫:src+scaffold 全量 grep `tentative/阶段=/出口判据/实测·推断关闭/unclassified/plan_directive/session_intel/immune(存储义)` | 零残留 |
| T6.2 | tests 全量(21 个测试文件):**11 改**=test_board(38 测→节点/边/三原子/六不变量/四视图/goal/Stop)/test_schema_contract(活契约 v3)/test_driver(25 测→配方0-2/Stop/续跑/hint 队列)/test_observer+test_observer_layer(→七类行/-p 同构)/test_prompt(→三块+路由三信号)/test_harvest(→合成交接死)/test_writeback(→晋升/视图化)/test_render_consistency(→STATE.md v3)/test_scaffold(→新槽/FORMATS/engagement 映射)/test_untested(**部分改**:normalize/query 段保留,_extract_facts 对账段随 T1.6 死)/test_events(→新事件);**2 删**=test_transcript_check(随模块 A23)+poison_probe(已裁 09-18);**9 保留**=test_guard/test_noreport/test_stoploss/test_cli/test_runner/test_json_utils/test_untrusted/test_providers/fixtures | 全绿(基线 219 起,只增不减) |
| T6.3 | dry-run 实机验收(usc 复测或新目标),清单:①stdin 恰三块零目标原文 ②STATE.md 计数行+六节 ③guide 注入开场块 ④Handoff 进 STATE.md 不进 stdin ⑤Stop 全流程(伪造→停机→一键续跑)⑥三账本收割+报告晋升 ⑦路由三信号命中 ⑧画像产出+supersedes ⑨bg-*.log 三层链路 ⑩guard 仍录像(P-5 形态)⑪P-11 停机语义仍立 ⑫P-6 台账搬运仍走 | 十二项全过 |
| T6.4 | 中期问题登记回填:P-3(观察者每轮,重验证输出质量)/P-4(阴性→视图化后 worker 防重复实效)/O-2(skills 三信号后是否真触发)/O-5(衰减已删,关闭)/P-10(简报轮次)/P-12(usage) | 回填中期文档 |

---

## 四、实机教训约束(从中期真实环境测试文档带入,施工不得违背)

1. **P-7**:WaitForMcpServers 教学必须随手册①迁入 recon-methodology(T0.3),丢了浏览器侦察就废;
2. **P-6**:log.jsonl 当前目录记账 + sync_human_ledger 收尾搬运保留——worker 世界无穿区合法理由;
3. **P-11**:停机语义(杀 worker/盘上全留/续跑=新会话)实机终验过,Stop/续跑沿用该地基;
4. **中期结论"worker 纪律立得住"(glm-flash 0 垃圾 FINDINGS)**——新契约(A2 三层)可教,但正反例必须显式(T3.2);
5. **未锻炼机制清单**(chains 图/观察者输出质量/skills 触发/TERMINAL_C/stoploss)= v3 首跑观察重点(T6.4 回填);
6. **O-4**(stage 落盘滞后)随 stage 机死自动消灭。

## 五、风险与对策

| 风险 | 对策 |
|---|---|
| board.py 961 行核心重写,量最大 | schema 契约即规格(T1.2/T1.3 逐条对 schema);合成 v3 夹具(旧板回放已裁 09-18);每阶段全绿红线 |
| 无过渡步一次切换 | 基线 22ff975 可回滚;T6.3 十二项不过不投产 |
| 观察者全能力(执行+网络)越界 | 手册红线+首跑人审 guide 行与命令日志 |
| 引导 prompt 质量决定轮效率 | T5.1 给 guide 形态模板;首跑对照 usc 旧摘要评估信息量 |
| Stop 懒停 | 引证护栏(无 F-xxx 无效)+一键续跑;首跑审停机理由 |
| 路由扫描面变宽误报 | T4.2 单测用 usc 指纹回放;必要时收窄到 fact value 字段 |
| 双通道成本(观察者 -p 全能力轮轮跑) | 时间盒给观察者;0-finding 轮 guide/intel 兜底 |

## 六、交付物

worker:新 CLAUDE.md/FORMATS.md/三块 stdin;观察者:OBSERVER-MANUAL/七类行/-p 同构;图:nodes-edges 容器/迁移脚本/四视图/Stop-TERMINAL/goal;投影:STATE.md v3 一轮两刷;写回:晋升+视图化;skills:四迁移件;测试:全量绿+十二项 dry-run 记录+中期回填。

**开工顺序**:T0(P0)与 T1.1-T1.2(P1)并行起步;首件交付=图容器+活契约(一切的地基;~~迁移脚本~~已裁 09-18)。
