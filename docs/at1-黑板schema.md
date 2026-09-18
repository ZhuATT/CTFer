# AT1 共享黑板 Schema v3.0(定稿候选)

> **性质**:黑板与图的**完整字段契约**。v3.0 是大版本——图从"黑板的装饰字段"升格为协作面本体,黑板分裂为**写入面(日志,不变)**与**协作面(图,重构)**。
> **设计论证**:`图与黑板v3设计.md`(四家参考对比 + 多轮讨论记录)。
> **状态**:定稿候选。拍板 1/2 已定,字段经消费者审计(28→23,砍 6:confidence/source/verified/primary/killed/created_at)。**定稿后写施工计划,未动代码。**

---

## 0. 设计原则(五条,字段取舍全从这里推导)

1. **两层分家**:写入面(日志)= worker 的 append-only 账本,worker 只写这层;图(协作面)= 知识的唯一事实源,controller 从日志蒸馏。worker 永不直接写图。
2. **判断权与记录权分离**:关系的判断权在 **worker 声明**(写入时它知道上下文)与**观察者**(全局审视)手里;controller 是记录员 + 机械兜底(endpoint 匹配),不做语义判断。
3. **每个字段必须有一个实名消费者**。答不出"谁读它"的字段不进 schema(v3 审计砍 6:confidence/source/verified/primary/killed/created_at)。
4. **节点不删、边不删**:一切消亡都是状态(superseded/dismissed/killed),历史完整,当前态靠视图。
5. **单向阀不变**:worker 永不碰 `.at1/`(graph 所在地),只写 workdir 账本;一切消费读投影(STATE.md)。

---

## 1. 顶层结构总览

```json
// .at1/blackboard.json —— 唯一源文件,两节分立
{
  "graph": {
    "nodes": [ {intent | finding | fact} ... ],
    "edges": [ {src, rel, dst, origin, note, round} ... ]
  },
  "bookkeeping": {
    "offsets":   { "facts": n, "findings": n, … },   // 账本收割偏移(directions 已废 A17③;hints 等自由扩展,批2 起)
    // stage/history 已废(2026-09-17,A12:阶段体系退役,"图就是阶段")
    "goal":      { "text": "…", "updated_round": n },  // 任务级 goal(S6):人写/控制台中途可改;worker <Stop> 自停锚点
    "handoff":   "上一轮 worker 交接叙事",
    "config":    { … },                                // 自由扩展;endpoint_n 随 stage 机死无消费者(A12)
    "intel":     [ { "round": n, "text": "证词" } ],   // 观察者证词(按轮)
    "guide":     { "round": n, "text": "下一轮引导全文" }  // A17 guide 行收割落点(批2 落 blackboard.schema.json)
  }
}
```

**v2 → v3 容器映射**:

| v2 | v3 去向 |
|---|---|
| facts[](kind:value 扁平账) | nodes[kind=fact](获得 id/状态/可连边) |
| findings[] | nodes[kind=finding] |
| directions[] | nodes[kind=intent] |
| immune[](存储) | **删除** → 阴性视图(派生,§5) |
| chains[](边库) | edges[](动词词表更新,§4) |
| session_intel(观察者输出存储) | **删除** → OBSERVER 直接收割成节点/边/comment |
| verified(影子计数) | **删除**(check_goal 已随 stage 机死,T1.5;判停三角=预算/人工停/worker Stop) |
| ledger.tried/background(分母流水) | **删除**——分母知识不进图,进投影"端点分组"节(controller 从收割元数据渲染) |
| handoff / goal / config / offsets | bookkeeping 节 |

**报废清单**:被动抽取的四套 kind 正则(_CRED_RXS/_FP_HDR_RX/_KV_RX 等)——fact_kind 取消后无消费者;机械窗口衰减——过期检验移交观察者语义质检(§6 配方 C)。

---

## 2. 节点公共字段(全部 kind 共有,7 个)

| 字段 | 类型 | 谁写 | 谁读 | 语义 | 备注 |
|---|---|---|---|---|---|
| id | str "D-001"/"F-001"/"T-001" | controller(create_node 时按 kind 发) | 全部 | 类型前缀可读;边端点;去重键 | worker 账本自报 id 冲突 → 重编号 `F-R{round}-{orig}`(v2 机制沿用) |
| kind | str ∈ intent/finding/fact | controller | 状态机分发/渲染/视图 | 节点种类 | |
| state | str(kind 各自状态机,§3) | controller(按账本/观察者判定迁移) | 判停/视图/渲染 | 生命周期 | 迁移规则见 §3 各表 |
| endpoint | str(host[:port][/path]) 或 "global" | controller(worker 账本带则透传) | 端点视图/yields·derived_from 兜底匹配 | **一等锚定键**——"这个端点上发生过什么" | 无端点知识标 "global" 旁挂 |
| origin | str ∈ worker/controller/observer/user | controller(按产出源设) | 渲染(观察者建议标签)/G-1 上限/审计 | 谁产出这个节点 | **吸收 v2 intent.source**(重复字段,已砍) |
| round | int | controller | 事实新鲜度显示/writeback 表行/审计 | 产生轮次 | 衰减窗口维度的残留消费(§6 配方 C 后仅剩显示+审计) |
| updated_at | str | controller | M5 显示/调试 | 最后变更时间 | 唯一时间戳(created_at 已砍:round+updated_at 足够) |

**节点不删**:一切消亡都是状态迁移。

---

## 3. 三种 kind 的 payload 与状态机

### 3.1 intent(方向,接力的一等公民)——payload 4 字段

| 字段 | 类型 | 谁写 | 谁读 | 语义 |
|---|---|---|---|---|
| goal | str | worker / 观察者 | 渲染主体/判停 | 方向要达成什么 |
| note | str | worker(接力笔记)/ 观察者 | 下一轮 worker | 工作笔记:"干到哪/下一步/依赖谁" |
| comment | str | controller(代写观察者 comment 行) | 下一轮 worker(STATE.md comment 列) | 观察者批注——P-3 介入通道 |
| blocked_reason | str | worker / 观察者 | 渲染/state=blocked 时必填 | 卡住的機理 |

**状态机**:`open → in_progress → done / blocked`;`killed` 状态已砍(YAGNI,U-5 落地时再加)。

**状态迁移谁触发**:
- open → in_progress:worker 账本声明(接手)
- → done / blocked:worker 账本声明
- 批注(comment):controller 代写观察者
- 阴性判定:**不存储**——done 且 yields 边为空 = 阴性(派生视图公式,§5)

### 3.2 finding(发现)——payload 5 字段

**定义(2026-09-16 拍板)**:finding = **一条被验证的攻击断言**("攻击者可以做到 X"),X 是成果不是动作。切分问句:"这是同一个'我能做到 X'吗?" 链完整性检验:"删掉中间任何一步,断言还成立吗?"(不成立=同一条链;成立=独立 finding)。链式 finding 按链的终点定级。
**产审分离**:worker 写报告(总结验证 + 串 fact 成链,`.auto\reports\`),观察者**审报告**(准确性/业务语境/src标准 对照)——干活的和审查的不能是同一上下文。

| 字段 | 类型 | 谁写 | 谁读 | 语义 |
|---|---|---|---|---|
| summary | str | worker(报告标题行) | 渲染/M5/漏洞表 | 发现一句话 |
| **report** | str | **worker** | **观察者(审查输入)/人工/对账** | 报告指针(`reports/F-xxx.md` 单洞 或 `reports/chain-xxx.md` 链式)——finding 阶段的交付物:漏洞描述/触发条件/攻击动机/实际影响/业务语境判断(对照 src标准)/链路(谱系引用)/严重度评级(引标准原文)/复现要点(引 evidence) |
| evidence | str | worker | **观察者判定输入/对账** | 证据文件路径(evidence/ 下,原始实现记录) |
| severity | str ∈ high/medium/low/none | controller(代写观察者审查) | 漏洞表/M5 | 严重度——**观察者按 src标准 条款核定**(worker 可自评,最终以审查为准) |
| reason | str | controller(代写观察者审查) | 漏洞表/审计 | **审查意见**(含标准条款依据)——非 worker 论证(论证在报告里) |

**状态机**:`proposed → confirmed / dismissed`。

**状态迁移谁触发**:
- proposed:收割时初始态(worker 交了报告,待审)
- → confirmed / dismissed:**仅观察者审查报告后**(§6 配方 C)——controller/worker 不可迁移;**已 confirmed 不可翻案**(历史修正走 superseded/人工)
- dismissed 的两种含义(由 reason 区分):判假(无威胁/业务语境不构成,如"批量读公开评价——信息本身公开可见")/ 判重(并入正主,配 same_root 边,§4 正主规则)
- **报告晋升**:confirmed 的报告由 controller 从 `.auto\reports\` 晋升人工面 `reports\`(人/M5 消费);dismissed 报告留观察者工作台审计

**v3 砍**:`confidence`——与 state 重复(发现的真伪由状态机回答,衰减不作用于发现);v2 本无此字段,v3 草稿误带,审计砍。

### 3.3 fact(事实/线索)——payload 2 字段

| 字段 | 类型 | 谁写 | 谁读 | 语义 |
|---|---|---|---|---|
| value | str | worker | 渲染主键/端点分组 | **可利用的漏洞线索或信息**,紧凑一句话 |
| evidence | str | worker | 观察者质检输入/追溯 | 细节指针(evidence/ 文件或命令输出) |

**状态机**:`proposed → confirmed / dismissed`;`confirmed → superseded`。

**状态迁移谁触发**:
- proposed:收割时初始态(worker 写入的线索,未质检)
- → confirmed / dismissed:**仅观察者轮末质检**(§6 配方 C)——质检员角色:真线索转 confirmed,叙事垃圾/错误线索 dismissed(用户拍板:质量关卡从写入时挪到审查时)
- confirmed → superseded:收割到矛盾新事实 + 观察者 supersedes 判定(旧事实不删,标被取代)
- confirmed → dismissed(过时):观察者质检判"已过时且无替代"(无替代时直接 dismissed + reason,替代存在时走 superseded)

**v3 砍**:
- `fact_kind`(七种分类)——用户拍板取消分类本体;七种词表退役存档:v2 §2.1.1。
- ~~背景知识(fingerprint/端点存在性/业务上下文)不进图~~ → **准入判据重写(2026-09-17,A13)**:fact = **对攻击真有效的知识**——可利用线索/攻击方向/影响打法定型的认知(身份模型/WAF 指纹/目标画像均入图);**无类别禁区**,质量由两道已有闸把守(worker 写入判断 + 观察者轮末质检 dismissed)。**唯一排除:端点存在性**——收割元数据自动渲染端点分组视图,手写=双记(防重复,非类别禁令)。废除依据:原枚举与设计文档 §四"business_context 旁挂 global"同日自相矛盾,且断绝 skill 路由的指纹燃料(fingerprint 回图,路由改扫全图 fact 值)。
- `confidence`(observed/inferred)——worker 自报标签砍(最终裁判是观察者,自我申报无必要);机械窗口衰减砍(34/74 窗口偏差,实机证伪);过期检验移交观察者质检(上文)。**v2 的衰减货币退役**;v2 凭证冻结/结论跳过等例外规则随机械衰减一并退役。

---

## 4. 边(关系,记录员模型)

| 字段 | 类型 | 谁写 | 语义 |
|---|---|---|---|
| src / dst | 节点 id | controller(按判定记录) | 关系两端 |
| rel | str,六动词 | — | 关系类型(下表) |
| origin | str(worker/observer/controller) | controller(按判定源设) | 谁决定的这条关系 |
| note | str(可选) | 决定者 | 语境 |
| round | int | controller | 建边轮次 |

**边不删、不重写**;same_root/supersedes 的"方向即语义"约定见下表。

### 4.1 六动词表

| rel | 语义 | 方向约定 | **谁决定**(判断) | controller |
|---|---|---|---|---|
| `sources` | 线索支撑方向(依据/弹药) | T/F → intent | worker 写线索时声明"指向 D-xxx" / 观察者补线 / controller endpoint 兜底(无人声明时) | 记录员 |
| `yields` | 方向产出了发现/事实 | intent → F/T | worker 交产出时声明 / 观察者补判 | 记录员;无人声明时 endpoint 兜底 |
| `derived_from` | 本节点派生自某节点(因果谱系) | 新 → 旧 | worker 声明优先 / 观察者补非显然者 | 记录员;同上兜底 |
| `spawns` | 节点催生了新方向 | F/T → intent | **观察者/用户** | 记录员 |
| `same_root` | 同根因(**正主 = dst**) | 非正主 → 正主 | **观察者**(连线时标注正主;缺失回退先到优先) | 记录员 + 机械 dismiss 非正主 |
| `supersedes` | 新事实取代旧事实 | 新 → 旧 | **观察者** | 记录员 |

**拒绝泛化 `related`**(Cairn/ARTEX 同款立场):"有关联"是零信息量关系——任何两节点都能扯上关系。关联的三种真实形态:共同支撑(sources)、因果谱系(derived_from)、同端点共位(端点分组隐式表达,不需要边)。

---

## 5. 派生视图(零存储,查询时现算)

| 视图 | 公式 | 消费者 |
|---|---|---|
| **阴性视图** | `intent.state=done 且 yields 边为空` ∪ `finding.state=dismissed`(已裁 09-18:判掉的全部印——判假/判重/硬拒都是"别再交同样姿势"的阴性知识;原"reason 含攻击路径"过滤语义不明,废除) | 下一轮 worker("别再试")/ 观察者(immune_reviews 替代:建议 retest 只针对 confirmed 态的推断项) |
| **端点视图** | group by endpoint | 谱系渲染/观察者同端点历史语境/未测面统计 |
| **谱系视图** | 每节点 parentsOf(指入边源)+ yieldsOf(指出边目标) | STATE.md 谱系节/观察者投影/M5 |
| **未测面视图** | 出现过的 endpoint − 有 intent/finding 覆盖的 endpoint | prompt 摘要(路标)/判停分母 |

> **注(09-18,已拍板)**:阴性视图公式修订为 `finding.state=dismissed`(全部印),原"reason 含攻击路径"过滤废除——见上表。批 1 实现与本公式一致。

---

## 6. 写图操作(三原子操作 + 三配方 + 六不变量)

### 6.1 原子操作(controller 独占调用权)

```python
create_node(kind, payload, endpoint, origin, round) -> id   # 按 kind 发 id
update_node(id, state=?, payload_patch=?, comment=?)        # 状态迁移/批注
add_edge(src, rel, dst, origin, note=?, round)              # 建边((src,rel,dst) 去重)
```

**谁调用**:仅 controller。worker/观察者通过账本/OBSERVER 间接表达意愿,controller 代写。

### 6.2 三配方(写图时机)

**配方 0:run 启动播种**(开跑前一次)
| 来源 | 操作 |
|---|---|
| prior-intel 情报条目(人写知识行:prose 行或 JSON 节点) | create_node(fact, confirmed, origin=user) |
| status.md 漏洞表(人拍板) | create_node(finding, confirmed, origin=user) |

**配方 1:轮末收割**(worker 日志蒸馏,每轮一次)
| 账本 | 操作 |
|---|---|
| FINDINGS 新行 | create_node(finding, proposed) → report 指针透传 payload → worker chain 声明照抄 add_edge → 无人声明则 endpoint 兜底 yields |
| FACTS 新行 | create_node(fact, proposed) → evidence 透传 → worker chain 声明照抄 |
| ~~DIRECTIONS 新行/变更~~ | **已废(A17③)**:worker 不再写方向账本,intent 由观察者 intent 行经配方2 创建 |
| HANDOFF / STOP 抽取 | `<Handoff>` → bookkeeping.handoff(读者=观察者,A19);grep `<Stop>`(达成须引 F-xxx,不引无效)→ TERMINAL(A18) |

**配方 2:观察者收割**(OBSERVER 判断书 → 图,观察者会话后一次;verdict = 对 worker 报告的审查结论)
| OBSERVER 行 | 操作 |
|---|---|
| verdict | update_node(finding: proposed→confirmed/dismissed + severity/reason)——severity/reason 为**审查意见**(对照 src标准),worker 论证在报告 |
| edge(same_root) | add_edge + update_node(非正主 → dismissed,"并入正主") |
| edge(supersedes) | update_node(旧 fact → superseded) + add_edge |
| comment | update_node(intent.comment) |
| intent | create_node(intent, open, origin=observer) + add_edge(spawns) |
| intel | bookkeeping.intel 追加 |
| **报告晋升** | confirmed 的报告由 controller 从 `.auto\reports\` 晋升人工面 `reports\` |

**0-finding 轮**:配方 2 只跑 intel/comment/intent 行——观察者每轮必跑(轮间质检不与发现死绑)。

### 6.3 六不变量(违反即 bug)

1. worker/观察者永不直接调用三操作——只通过账本/OBSERVER 间接表达,controller 代写(每次写带 round+origin,可审计)
2. 节点不删、边不删——一切消亡都是状态
3. 观察者 verdict 仅作用于 **proposed**——confirmed 不可被 LLM 翻案(历史修正走 superseded/人工)
4. 兜底只在无人声明时——声明的关系永远优先于 endpoint 机械匹配
5. 去重:node 按 (kind, endpoint, 归一化内容);edge 按 (src, rel, dst)
6. worker 自报 id 与图冲突 → 重编号 `F-R{round}-{orig}`

---

## 7. OBSERVER 行契约(Q-2 定稿)

观察者输出 `.observer/OBSERVER`,JSONL,**七类行**(A17/A19 增 guide);controller 收割器机械执行,格式非法行进隔离区并记 `observer_parse_fail` 事件。**verdict = 对 worker 报告的审查结论**(产审分离:worker 写报告,观察者审查;判定材料 = 报告 + evidence + 图投影 + src标准 按业务路由)。

```json
{"t":"verdict", "id":"F-002", "state":"confirmed", "severity":"high", "reason":"_catalog 匿名可达,按通用 SRC 标准=高危;业务语境无减损"}
{"t":"verdict", "id":"F-003", "state":"dismissed", "reason":"批量读公开评价——信息本身公开可见,按 XX 标准 X 条不构成漏洞"}
{"t":"edge",    "rel":"same_root",  "src":"F-004", "dst":"F-002", "primary":"F-002", "note":"同端点同根因"}
{"t":"edge",    "rel":"supersedes", "src":"T-009", "dst":"T-003", "note":"9月实测取代4月情报"}
{"t":"comment", "id":"D-002", "text":"已blocked两轮无新机理,建议转向"}
{"t":"intent",  "goal":"拉取 k8s 基建镜像层挖凭证", "endpoint":"...:5000", "note":"从 F-001 延伸", "from":"F-001"}
{"t":"intel",   "text":"5000 的 Registry 是全局最大突破口"}
{"t":"guide",   "text":"主攻 /user/findpwd 验证码复用验证(T-012);备选:附件面(D-008);自由探索照常——新线索追到 fact 级"}
```

- `primary` 字段:正主 id(拍板2=B);收割器校验 primary ∈ {src,dst},缺失/非法 → 回退先到优先(confirmed 最早者)。
- `intent.from`:spawns 边的源节点(可选;缺省无 spawns 边)。
- `intel` 必填:缺失 → 收割器记警告事件(不阻塞,但质检报告可见)。
- `guide` 行(A17):下一轮 worker 的引导 prompt 全文,controller 机械注入 stdin 开场块;**引用图内容只节点 id+转述,禁贴目标响应原文(A19——stdin 零目标文本的保证)**;形态=主攻+备选次序+自由探索许可。
- noreport 硬拒条目:verdict 不受理(维持 v2 代码检察官原则),收割器直接 dismissed。
- **src标准 路由**:观察手册规定"按 mission 业务类型选标准文件 + Grep 关键节",不全量读;覆盖不到的业务退化到四步影响框架(有则参照,无则不拒判)。

---

## 8. 投影 STATE.md(唯一投影,一轮两刷)

| 节 | 内容 | 数据源 |
|---|---|---|
| 任务概要 | **goal 文本(S6)** + mission 精要 + 人类已确认发现(漏洞表) | bookkeeping.goal + engagement.json + status.md |
| 方向谱系 | 每方向:状态 + parentsOf + yieldsOf + comment(观察者批注列) | 谱系视图 |
| 阴性视图 | 两列表:死因(done 无产出 reason / dismissed reason)| 阴性视图 |
| 端点分组 | group by endpoint:该端点上的方向/发现/事实一览 | 端点视图 |
| 全局认知 | identity_model / **目标画像**(前缀"目标画像:"全图唯一,更新=追加新版+旧版走 supersedes,A14) / global 桶 | nodes(endpoint=global) |
| worker 本轮报告 | Handoff 原文 | bookkeeping.handoff |

- **双读者**:worker(执行手册:重点读方向谱系+阴性)/ 观察者(观察手册:重点读新发现+谱系连线)——各手册写明重点节。
- **一轮两刷**:配方 1 后刷第一版(观察者读,含 proposed 态新发现)→ 配方 2 后刷第二版(下一轮 worker 读,含 verdict/批注)。
- **防注入**:~~六节全部 untrusted nonce 包裹(v2 机制沿用)~~ **已裁 A20(09-18):本阶段不包裹,`untrusted.py` 保留作升级路径**。
- **不受目录地理影响**:投影从 blackboard.json 渲染,来源唯一。

---

## 9. v2→v3 概念映射速查

| v2 概念 | v3 归宿 |
|---|---|
| facts 账本(分母+结论) | 写入面不变;图侧 = fact 节点(可利用线索)+ 投影端点分组节(背景) |
| immune 阴性清单 | 阴性视图(派生) |
| chains 边库 | edges[](动词表更新:same_root/supersedes/derived_from 保留,+sources/yields/spawns) |
| confidence(observed/inferred) | 删除(worker 自报砍 + 机械衰减砍)→ 过期检验 = 观察者质检 |
| session_intel | OBSERVER 直接收割 |
| 被动抽取四正则 | 报废(分母知识进投影端点分组节) |
| verified 影子计数 | 删除(check_goal 直数) |
| intent.source | node.origin 吸收 |
| 试探性 STATE.md 渲染 | 谱系渲染(§8) |

---

## 10. SQL 触发条件(挂起,非本 schema 范围)

存储保持文件(blackboard.json)。以下任一条件发生 → 图与 runs 入 SQLite(nodes/edges/runs/events 四表,ARTEX/Cairn 同构):多 run 真并行 / M5 出现文件扫不动的跨 run 查询 / 单图节点数大到 JSON 全量加载卡顿。
