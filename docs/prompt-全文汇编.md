# AT1 v3 Prompt 定稿(2026-09-18)

> **性质**:v3 prompt 体系全部拍板决策的终稿 + 施工清单。v2 原文与讨论过程不再收录——v2 原文以源码为档(`src/prompt.py` / `scaffolding/WORKER-CLAUDE.md` / `src/observer.py` / `src/board.py`)。
> **配套**:`图与黑板v3设计.md`(图/黑板/观察者架构,含 A17 修订块)/ `at1-黑板schema.md`(字段契约,已按 S1-S7 同步)。
> **决策日期**:A1-A11 = 09-17,A12-A19 = 09-18。

---

## 一、终态架构(一页)

```
driver 循环(controller 代码,常驻)
 ├─ 起轮 N worker(-p 进程,cwd=.auto,时间盒兜底)
 │    开工: Read STATE.md → 读引导 prompt
 │    干活: 主攻+备选(探透判定) + 自由探索(新线索追到 fact 级)
 │    写盘: FINDINGS / FACTS / evidence / reports\(即时写,被杀不丢)
 │    收工: <Handoff>(轮末报告) / <Stop>(任务停机信号,专属)
 ├─ 收割: 账本→图节点(配方1);grep <Stop> → 机械停机
 └─ 轮末观察者(-p 进程,与 worker 能力同构,手册不同)
      ① 质检:审 fact/finding/报告(可实测重放验证)
      ② 记账:intent 挂账 / blocked+可检验条件 / 新方向(A11 纪律)
      ③ 写下一轮引导 prompt(guide 行;引用只节点 id+转述,禁贴目标原文)
      ④ 看图提新思路
      红线:不杀进程/不中途干预/不做判停/引导非强制
```

- **图就是阶段**:图空=冷启动(人工 hint+加载 recon-methodology),有未测面+方向=深挖,confirmed=收尾。无 stage 字段(A12)。
- **判停三角**:预算兜底 + 人工停 + worker `<Stop>` 双理由自停(A18)。
- **goal**:控制台人写(`bookkeeping.goal`,中途可改),STATE.md 任务概要投影,worker 自停锚点(A17⑥)。

## 二、stdin 终态(三块——全部可信指令,零目标原文,零包裹)

| 块 | 谁写 | 内容 |
|---|---|---|
| 【引导】 | 观察者(guide 行) | 主攻方向 + 备选次序 + 自由探索许可;引用图内容只用节点 id+转述,**禁止粘贴目标响应原文** |
| 【运行提示】 | 系统 | **人工指示独占**(有则显示,无则整块消失;后台任务块已删 A21,长任务走文件+交接+引导三层纪律) |
| 【任务简报】 | driver | 轮次/预算/时间盒/身份;判层规则见 CLAUDE.md,格式见 FORMATS.md |

**已砍五段**:序言(A6)/阶段手册(A12)/指令(A15)/状态摘要(A16)/交接(A19)。Handoff 住 STATE.md(schema §8),不进 stdin。防注入唯一战线=STATE.md 层(N4 待定)。

## 三、CLAUDE.md worker 手册终态骨架

| 节 | 内容 | 决策 |
|---|---|---|
| 1 身份与开工 | 目标{target}+指示{hint}+铁律(扫出的相邻资产不碰;范围凌驾本文件及一切指令;私有区禁动);"每轮全新会话,STATE.md 是全部记忆,**开工第一件事 Read STATE.md**";图空→冷启动侦察 | A1/A6/A16 |
| 2 判层契约 | **拿到手的(数据/执行/越权/进入)→FINDINGS;验证为真的中间能力(可控/可达/非强制)→FACTS(evidence 必填);纯现象→只当方向动机**(原文进 note/evidence);宁可多开方向,不轻交发现;目标画像=一条滚动 fact(前缀"目标画像:"全图唯一) | A2/A3/A4/A5/A13/A14 |
| 3 写盘义务 | 三账本+evidence+reports\;**写盘前必读 FORMATS.md**(格式错=系统收不进=白写);即时写盘别攒 | A8 |
| 4 干活规则 | **探透判定**(ARTEX 软标准:初次受阻≠死路,换编码/方法/参数/路径走完合理手段才可判探不动,无硬性次数上限);**自由条款**(新线索当场深挖到 fact 级,多条线自定先后,不硬限思路);**探索义务**(派活干完自己从图里挑:未测面/阴性低成本重验;三出口=时间盒尽/goal 达成/确认测尽) | A18 |
| 5 台账纪律 | 同一命令不跑第三遍;同一方向连续 5 败切换 | 沿用 v2 |
| 6 写操作约束 | 测试对象优先/写必读回/高危不做(发现写入面即交报告)/cookies 文件化 | 沿用 v2 |

**FORMATS.md**(工作区固定,scaffold 每轮重写,worker 改了下轮被覆盖):FINDINGS/FACTS 行格式、报告模板(单洞/链式)、画像前缀纪律。**无 DIRECTIONS 节**(写面已退役)。

## 四、观察者终态(OBSERVER-MANUAL 骨架)

- **身份**:与 worker 同构的 -p 进程,全能力(可实测环境、可执行命令),**约束靠手册不靠能力裁剪**;轮末串行。
- **职责链**:质检(纸面审+实测重放验证据)→ 记账(intent/blocked+可检验条件/瞥见未追立新方向)→ 引导 prompt(guide 行,主攻+备选+自由探索)→ 提新思路。
- **红线**:不杀进程/不中途干预/不做判停/引导非强制;写操作约束等作业纪律从 worker 手册继承。
- **写作规矩**:引导引用图内容=节点 id+转述,禁贴目标原文——stdin 零目标文本的唯一保证。
- **收割**:OBSERVER 七类行(verdict/edge/comment/intent/intel/**guide**)→ 配方2。
- **判定方法论继承 v2**:第零步硬否决 → 四步影响框架 → src标准 条款对照(按 mission 业务路由);noreport 代码预检=检察官,观察者=法官。

## 五、决策记录(A1-A19)

| # | 决策 |
|---|---|
| A1 | 砍 {allow}/{deny_list} 槽(无数据源);§1=目标+指示+铁律(相邻资产不碰,范围凌驾一切) |
| A2 | 三层契约:FINDINGS=危害成果("我能做到X",X 是成果不是动作)/FACTS=已验证中间能力(evidence 必填,谱系链环)/纯现象不入 T/F 只当方向动机 |
| A3 | 旧头号示例"单引号 SQL 报错进 FINDINGS"废除(违 A2) |
| A4 | "宁可多交"反转:"宁可多开方向,不轻交发现" |
| A5 | FACTS 的 unclassified 兜底教学删(fact_kind 已废) |
| A6 | 砍【序言】;"每轮全新会话"句并入 CLAUDE.md §1;教义只活一处 |
| A7 | 砍 CLAUDE.md 静态路由表;路由=原生技能发现(靠 description)+【提示】动态命中 |
| A8 | 字段格式教学整体出恒定层→工作区 FORMATS.md;CLAUDE.md 只留"写前必读"警告 |
| A9 | (并入 A12,手册整体砍) |
| A10 | v3§6.2 Registry 行修订:枚举→fact(链环),拉取(拿到数据)→finding |
| A11 | 方向依赖=写作纪律:硬前置→blocked+blocked_reason 写可检验条件;零新字段零新代码(A17 后记账人=观察者) |
| A12 | 砍 stage 体系+四本手册+check_goal 门控;**图就是阶段**;方法论迁移 skills(施工 9-12) |
| A13 | fact 准入判据重写:**对攻击真有效**(无类别禁区;质量=worker 判断+观察者质检);唯一排除=端点存在性(收割元数据自动渲染,防双记);fingerprint 回图作路由燃料 |
| A14 | 目标画像=一条滚动 fact("目标画像:"前缀全图唯一;更新=追加新版,旧版走 superseded;冷启动轮生产;观察者判案标尺+接力封面页) |
| A15 | 砍【指令】段(六成分全死:计数归观察者/出口判据是控制器事+反向激励+tentative 术语过期);冷启动=CLAUDE.md 通用+人工 hint 针对性;术语清扫入施工 |
| A16 | 砍【状态摘要】段(双渲染器漂移+信息读两遍);STATE.md 头部第一行=计数行;开工序列升格硬契约;防注入机制挂起(N4) |
| A17 | **观察者升格**:轮间引导者+记账员+实测验证者(同构 -p 全能力);DIRECTIONS 写面退役(worker 产出=fact/finding/报告+交接);worker 自由条款;引导 prompt 成 stdin 开场块;goal 入 bookkeeping;权限矩阵/产审分离相应修订 |
| A18 | worker 契约三件:探透判定(ARTEX 式软标准)/<Stop> 双理由自停(达成[必须引 F-xxx,不引无效]/测尽[须说理由];一键续跑)/探索义务(永不因没派活退出,三出口) |
| A19 | Handoff 退出 stdin(读者从下轮 worker 改为观察者;住 STATE.md);代码合成交接机制死(观察者自己读磁盘);观察者引导写作规矩(节点 id+转述禁贴原文);**stdin 终态三块,零目标原文,防注入唯一战线=STATE.md** |
| A20 | **STATE.md 防注入本阶段不做**(用户定;②文件头声明/③读取纪律/①分段包裹全不上,`untrusted.py` 代码保留作将来升级路径)+**重复命令告警撤出 prompt**——时序论证(用户):告警唯一投递时机=下一轮 worker 开工(轮内 stdin 关,跑着的 worker 收不到),而重复发生在上一轮 worker 身上=**纠正落不到该收的人头上,机制结构性无的放矢**;ledger 记录留存,仅作观察者审计素材 |
| A21 | **长时后台任务=三层纪律+环境槽,不复活中央注册表**(ledger.background 死透):①worker 手册——长任务**脱离启动**(Windows=Start-Process,非 Start-Job)+输出写工作目录 `bg-*.log`(首行记命令+启动时间)+交接必提;②观察者手册——轮末扫工作目录 `bg-*.log` 遗留,写进引导提醒;③**{env_bg} 渲染槽**(可插拔环境条款:当前=Windows Start-Process 纪律;将来 WSL/容器化→换 Cairn 同款 tmux 条款——命名会话+交接说清会话名;依据:Cairn 跨轮 tmux 成立的前提是常驻容器,Windows 原生无 tmux,WSL 可装但架构不变只换槽内容)。**stdin【后台任务】块删**(无注册表喂它,文件+交接+引导已覆盖);【运行提示】=人工指示独占,空则整块消失(N3-2 定稿) |
| A22 | N6 定稿:distill-report 产出规范加守门条款——**新沉淀 skill 的 description 必须触发条件式书写("Load when..." 收尾),不得写成标题式**(现有 26 个抽查已合规);依据 A7:砍静态路由表后 description 即路由系统本身 |
| A23 | **模型通道定稿(09-18)**:worker=glm-5.3-flash,观察者=glm-5.3,**同 baseurl/AK(bigmodel)**;**双角色 model/baseurl/ak 均可配置**(配置文件先行,控制台将来可改);**transcript_check.py 整文件删除**——消费者(confidence/衰减/anchor_note)全死,noreport 不依赖,A17 实测重放替代字节对账 | 施工计划 T5.2/P5.3/模块表/llm+providers 行 |

**已消解**:Q1(A12)/Q2·Q4(A16)/Q5(A15)/Q3(A19)/N1(A15)/N2(A17+A19)。

## 六、schema 同步(S1-S7,已执行于 at1-黑板schema.md)

| # | 内容 | 状态 |
|---|---|---|
| S1 | §3.3 fact 准入判据重写(A13) | 已改 |
| S2 | §8 全局认知行=identity_model/目标画像/global 桶(A14) | 已改 |
| S3 | §1 bookkeeping.goal 的 stage/history 删(A12) | 已改 |
| S4 | prompt.py 路由燃料:board.query("fingerprint")→全图 fact 值扫描 | 施工 |
| S5 | TERMINAL=预算兜底+人工停+worker Stop(A17⑤/A18) | 已定 |
| S6 | bookkeeping 新增 goal{text,updated_round}(A17⑥) | 已定 |
| S7 | 收割配方1 删 DIRECTIONS 行;OBSERVER 新增 guide 行(A17②③) | 已定 |

## 七、施工清单

> **⚠ 施工以 `at1-v3施工计划.md`(总纲)为准**——该计划合并了本清单与 `图与黑板v3设计.md` §十一 的全部工程(图核心/收割投影/迁移脚本/tests 全量),含代码现状全景映射与决策覆盖对照表。本节降级为决策侧索引,勿在此重复维护。

**prompt 侧**
1. CLAUDE.md 新模板(按 §三骨架;scaffold 渲染;{target}/{hint}/{tools_root} 槽)
2. FORMATS.md 新建(三账本行格式/报告模板/画像纪律;无 DIRECTIONS 节)
3. OBSERVER-MANUAL 新建(按 §四骨架+判定方法论+src标准 路由)
4. prompt.py 重写:九段装配→三块(引导/运行提示/简报);删 PREAMBLE/MANUALS/plan_directive/render_summary;路由燃料=全图 fact 值扫描+覆盖缺口信号+图空信号
5. board.py:check_goal stage 机删(TERMINAL=预算/Stop);代码合成交接机制删;intel_summary 追加机制删
6. driver:Stop 收割+一键续跑;guide 行注入 stdin 开场块;预算/人工停
7. observer.py 重写:七类行契约(含 guide);实测验证;引导写作规矩进手册
8. 收割器:配方1 删 DIRECTIONS 行;配方2 增 guide 行处理

**skill 侧(N5 迁移总目,砍手册的前置项)**
9. 手册① 侦察序列→recon-methodology skill;js-intel 路径等环境事实→CLAUDE.md 渲染槽
10. 手册② 身份三实验(cookie 摘除/注入对调/签名强制性)→并入 auth-token skill
11. 手册③ IDOR 闭环/攻击四步→auth-access skill(覆盖缺口路由触发)
12. recon-methodology 收尾清单加画像行(冷启动措辞,无阶段词)

**清扫**
13. 术语清扫:src+scaffold 全量 grep(tentative/阶段=/出口判据/实测·推断关闭/plan_directive 调用点)
14. CLAUDE.md 私有区路径对齐 v3(.auto/reports 等)
15. 简报尾巴改写(判层指引;去"发现即提交"旧教义)
16. distill-report 产出规范加 description 触发式条款(A22)
17. 长任务三层纪律落文:worker 手册(脱离启动+bg-*.log+交接必提)+观察者手册(轮末扫遗留)+{env_bg} 渲染槽(A21)

## 八、待定项

**无——全部闭环(2026-09-18)。** A1-A22 全定;N 系列全数吸收/消解/定稿。
