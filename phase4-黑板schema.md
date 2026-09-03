# AT1 共享黑板 Schema 定稿（v2，串行 worker 架构）

> **性质**：黑板的形式/字段/内容的**完整契约**——先定稿，后施工。吸收决策板 D1/D2/D3/D5 与 DEC-2/3/8/9 的全部讨论结论。
> **架构前提**：串行单 worker 轮次接力（每轮一个全新 `-p` 会话）。v2 并发（scheduler）时的升级路径见 §9。
> **日期**：2026-08-31。拍板后本文档晋升为 `docs/at1-黑板schema.md`（正式契约），phase4 执行文档引用它。

---

## 0. 设计原则（五条，字段的取舍全从这里推导）

1. **三层分离**：分母层（被动抽取的形状，"有什么"）/ 结论层（worker 显式上报的语义，"什么是真的"）/ **方向层（新增，"正在做什么/没做完什么"）**。图适合结论层和方向层，不适合分母层——分母是噪声索引，不是知识。
2. **每个字段必须有一个机械消费者**。没有消费者的字段是死重（v1 审计：conf 半死、provenance 全死）。接线或废弃，二选一。
3. **worker 写语义，控制器写 bookkeeping**。worker 交 kind/value/confidence（它刚做完实验，分类在信息最全处）；id/round/provenance/ts 由控制器补。
4. **接力信息在过程中落盘**（发现即落盘的推广）：方向对象工作中途就写文件，被时间盒杀死也不丢——Handoff 从"唯一接力棒"降级为"叙事补充"。
5. **单向阀不变**：worker 永远不碰 `.at1/`（黑板原始区），只写 workdir 文件；控制器收割入板；worker 读到的永远是渲染投影（prompt 状态区 / STATE.md）。

---

## 1. 顶层结构总览

```json
{
  "facts":         {"<kind>:<value>": {fact…}},     // 分母层 + 结论层（扁平 dict，保持）
  "findings":      [{finding…}],                      // 观察者标注后的发现
  "immune":        [{immune…}],                       // 阴性记录（含置信度）
  "directions":    [{direction…}],                    // ★新增：方向（接力的一等公民）
  "session_intel": {…},                               // 观察者会话观察
  "handoff":       "叙事文本（降级）",
  "goal":          {"stage": "…", "history": […]},
  "ledger":        {"tried": {…}, "background": […]},
  "verified":      {"confirmed": n, "tentative": n},  // 派生计数（影子，保留）
  "config":        {"endpoint_n": 15},
  "offsets":       {…}                                // 收割记账
}
```

---

## 2. 逐对象 Schema

### 2.1 facts（分母层 + 结论层，扁平 dict 保持）

**键**：`"<kind>:<value.lower()[:120]>"`（去重键，同键高置信覆盖——保持现状）

| 字段 | 类型 | 谁写 | 谁读 | 语义 | 状态 |
|---|---|---|---|---|---|
| kind | str ∈ KINDS | worker（显式）/ 控制器（被动） | 全部机械消费者 | 路由键（§2.1.1） | 保留 |
| value | str | 同上 | 全部 | 事实内容 | 保留 |
| confidence | **"observed" \| "inferred"** | worker（显式事实）；被动抽取固定 "observed"（直接看到） | `render`（阴性分档）、DEC-3 决策 | observed=直接看到；inferred=推断。**否定结论默认 inferred**，穷尽手段才 observed | ★新增（替代 conf 的决策职责） |
| conf | float | **控制器派生**（observed→0.9，inferred→0.5，被动→0.7） | render/query 排序 | 纯排序权重，**不再是决策输入** | 降级为派生字段 |
| provenance | str | 控制器（"round{n} {tool}: {cmd}" 或 FACTS 的 evidence 字段） | `verify_fact`（重验，v2 接线）；追溯审计 | 这条事实从哪来 | 接线（D3） |
| round | int | 控制器 | untested 显示"第几轮发现"；时间线 | 产生轮次 | 保留 |
| ts | str | 控制器 | — | 时间戳 | 保留（bookkeeping） |

#### 2.1.1 KINDS 菜单 v2（7 个，D1 精化①）

| kind | 层 | 语义 | 主要写者 | 主要消费者 |
|---|---|---|---|---|
| `endpoint` | 分母 | 端点形状 | **被动抽取**（显式也可） | untested 分母、check_goal 计数 |
| `credential` | 分母 | 凭证形状（AKIA/sk-/JWT/PEM） | 被动抽取 | noreport 实害豁免、渲染 |
| `kv_secret` | 分母 | KV 秘密形状 | 被动抽取 | 渲染 |
| `fingerprint` | 分母 | 中间件指纹 | 被动抽取 | hints 路由 |
| `identity_model` | **结论** | 身份模型结论（engagement 级唯一，重报覆盖） | **worker 显式** | check_goal（identity→exploit 出口） |
| `business_context` | **结论** | 业务上下文 | **worker 显式** | 观察者 prompt（设计内行为判断） |
| `unclassified` | 结论兜底 | ★新增：worker 拿不准 kind 时的落点；**未知 kind 映射到此，不静默丢弃**（D1 精化②） | worker | 渲染（低优先级）、人工复核 |

**D2 定位声明**：分母层四类 = 覆盖度分母 + 盲区兜底（"worker 忘了报的，被动不丢"），**不承担语义权威**；语义结论只认显式层。被动抽取的 conf 恒 0.7、confidence 恒 observed。

### 2.2 findings（一处保持 + chain 边字段）

| 字段 | 类型 | 谁写 | 语义 |
|---|---|---|---|
| id | str | worker（冲突时控制器重编号 `F-R{r}-{orig}`） | 发现标识 |
| endpoint / summary | str | worker | 定位 + 一句话定性 |
| evidence | str | worker（相对 workdir 路径） | 证据文件引用 |
| round | int | worker/控制器 | 提交轮次 |
| **chain** | {rel, refs[], note} 可选 | **worker**（发现时最知关联） | **结构化图边**（★2026-09-03 升级，见下） |
| assessment | confirmed/likely_false_positive/uncertain/duplicate | **观察者**（noreport 终审类为控制器） | 判定 |
| severity | high/medium/low/null | 观察者 | 严重度 |
| reason | str | 观察者/控制器（硬拒格式"硬拒·{cat}：…"） | 判定理由（writeback 硬拒清单按此前缀识别） |
| evidence_verified | bool | **控制器**（transcript_check） | 证据锚定 |

**chain 边规格**（ARTEX 边模型适配——worker 传引用，系统拥有词汇表）：

```json
"chain": {"rel": "derived_from", "refs": ["F-001"], "note": "SQL调试页反射，同根因"}
"chain": {"rel": "combines", "refs": ["F-002", "D-003"], "note": "SSRF+redis凭证=可组合RCE路径，值得试"}
```
- **rel ∈ 系统固定枚举**（worker 不发明边类型）：`derived_from`（派生）/ `combines`（可组合）/ `same_root`（同根因）
- **refs = id 数组**（F-xxx / D-xxx）——机器直接连节点（M5 前端画边零解析），多父可表达
- **note** = 自然语言细节，worker/人读，画边忽略
- **ingest 校验**（控制器执行）：rel ∉ 枚举 → 降级 note-only（refs 丢弃）；refs 悬空 → 保留，渲染标"（悬空引用）"
- FACTS 行同样支持可选 chain 字段（同规格）

**不变量**：同 id 覆盖（观察者重评更新）；硬拒不可被会话级翻案（方案 A）；chain 随 finding 原样透传观察者不删改。

### 2.3 immune（阴性记录，DEC-3 接线）

| 字段 | 类型 | 谁写 | 语义 | 状态 |
|---|---|---|---|---|
| endpoint | str | 控制器（403 检测）/ status.md 反向读 | 关了的口子 | 保留 |
| status | str | 同上 | 结果标记（403/设计内…） | 保留 |
| since_round | int | 控制器 | 轮次 | 保留 |
| confidence | "observed"\|"inferred" | worker（经 FACTS）/ 控制器默认 | **实测关闭 vs 推断关闭** | ★新增 |

**渲染语义（DEC-3 落点）**：observed → "实测关闭（重开需材料性新机理）"；inferred → "推断关闭·未穷尽（可低成本重验）"——弱化阻断力，解"轻率否定焊死路线"。

### 2.4 directions（★新增：方向层，D5 轻量版）

**为什么**：Handoff 是有损接力，被杀场景（代码合成兜底）连"我本想干什么"都没有——A4/P4.9 漏 idor 的第三层病灶。方向对象让"进行中的工作"成为过程中落盘的一等公民。

| 字段 | 类型 | 谁写 | 语义 |
|---|---|---|---|
| id | str | worker（D-001…；冲突重编号同 findings 规则） | 方向标识 |
| goal | str | worker / 观察者（suggestions 入列，source=observer） | 一句话目标（"用 A/B 对调验证 /api/order/detail idor 读"） |
| endpoint | str，可选 | worker | 关联端点——**计入 tested 集合**（修"探过没留痕迹"缺口） |
| status | open / in_progress / blocked / done | **worker**（编辑 DIRECTIONS 文件更新） | 生命周期 |
| note | str | worker | 接力上下文：测到哪 / 卡在哪 / 下一步具体做什么（"已拿双账号；B 的订单 id=8823，换 A cookie 重放看手机号"） |
| blocked_reason | str（blocked 时） | worker | 卡住原因（配合 DEC-5 重开标准："新材料出现才重开"） |
| source | worker / observer | 写入者 | 来源 |
| round | int | 控制器 | 创建/最后更新轮次 |

**生命周期**：worker 开工先读 open/blocked 方向 → 接着干（in_progress）→ done（写结论进 FACTS/FINDINGS）或 blocked（写 reason）。观察者每轮的 suggestions 自动追加 source=observer 的 open 方向。**整表替换语义**：DIRECTIONS 文件是 worker 眼中的当前状态，driver 轮末全量合并（worker 文件的 status 优先；observer 方向不被 worker 碰则保留）。

**渲染位置**：指令行计数（"未测面 7 个；进行中方向 2 个"）+ STATE.md 全文置顶——和 DEC-2 配套构成双重欠账。

### 2.5 session_intel / handoff / goal / ledger / verified / config / offsets

| 对象 | 变化 |
|---|---|
| session_intel | **观察者 v2（决策 G，09-03）**——输出契约随图扩展，原五字段基础上：① 加 **`chains: [{rel, refs, note}]`**（与 worker 的 chain 同形状；duplicate 判定顺产 same_root 边）② 加 **`direction_comments`**（方向治理，原 suggestions 并入：带 id=对既有方向批注"已blocked两轮建议转向"；带 goal=建议新方向）③ 加 **`immune_reviews`**（否定复核，DEC-3 闭环：endorse→confidence 升 observed；retest→自动开 open direction）。**输入扩展**：session prompt 加 directions 全表+已有 chains。**原则不变**：无工具/轮间/建议不指挥/不关闭方向（关闭权在 worker） |
| handoff | **降级**：只写叙事总结（已完成概览/关键判断），"未竟"段废弃（directions 接管）；旧格式"未竟"段 driver best-effort 提为 directions；被杀时合成兜底照旧（它的缺陷由 directions 补） |
| goal | 不变（stage/history + 轮次兜底已在 `71d3b91`） |
| ledger | 不变（tried 计数 / background） |
| verified | 保持派生影子（由 findings 计数） |
| offsets | 保持（findings_ids_map / facts / directions 合并态） |

---

## 3. 生产端契约（worker 写什么文件、什么格式、什么纪律）

### 3.1 FINDINGS（不变 + DEC-4 纪律）

```json
{"id":"F-001","endpoint":"/search","evidence":"evidence/sql-test.md","summary":"单引号返回SQL报错","round":1,"chain":{"rel":"derived_from","refs":["F-004"],"note":"同调试页"}}
```
纪律（DEC-4 上报门槛）：只有**真实触发过**、拿到可复现证据才写；版本/CVE 匹配、"看起来可注入"、漏洞库推断**不算**——触发不了的嫌疑写 FACTS（confidence=inferred）。

### 3.2 FACTS（D1-B 契约）

```json
{"kind":"identity_model","value":"身份靠 httpOnly cticket 派生，客户端 userId 注入被忽略","confidence":"observed","evidence":"evidence/identity-tests.md"}
{"kind":"business_context","value":"电商平台，订单手机号是敏感数据","confidence":"observed","evidence":"首页"}
{"kind":"unclassified","value":"https://cdn.example.com/config.json 里有内部端点列表","confidence":"inferred","evidence":"curl 输出"}
```
纪律：
- kind 从 7 个菜单选，**拿不准用 unclassified**（不许发明新 kind；未知 kind 控制器映射到 unclassified，不丢弃）
- **增量纪律**（ARTEX/Cairn 双印证）：写之前扫一眼状态区/STATE.md 已有事实，只写新结论，不换措辞重记
- **否定结论门槛**（DEC-3）：手段没穷尽（换编码/参数/路径/方法）一律 confidence=inferred；宁可 inferred 让系统复核，不用轻率 observed 焊死路线
- **即时写**（DEC-8）：得出结论立刻写，别攒到会话末——被杀即丢

### 3.3 DIRECTIONS（★新增）

```json
{"id":"D-001","goal":"验证 /api/order/detail idor 读","endpoint":"/api/order/detail","status":"in_progress","note":"双账号已拿到(cookies.txt)；B 的订单 id=8823；下一步：换 A 的 cookie 重放看手机号是否还在","round":1}
{"id":"D-002","goal":"admin 面写入验证读回","endpoint":"/admin/config/update","status":"blocked","blocked_reason":"写接口需要 X-CSRF 头，未找到获取方式","round":2}
```
纪律：
- 开工先读：**接手上轮 open/blocked 的方向**（这是你的首要工作——接力第一优先级，高于开新方向）
- 开始一个方向前写一行 status=in_progress；做完改 done（结论另写 FACTS/FINDINGS）；卡住改 blocked + reason
- blocked 的重开标准（DEC-5）：只有材料性新机理（新发现/新入口/新参数/明显不同构造）才重开，note 里说清"这次和上次不同在哪"
- 文件小，重写整文件更新状态即可

### 3.4 其它 workdir 文件（不变）

evidence/（白话+请求响应原文；中间产物一律写 workdir 不写 /tmp——DEC-6）、cookies.txt、`../state/log.jsonl` 记账。

---

## 4. 消费端契约（谁读什么）

| 消费者 | 读 | 用途 |
|---|---|---|
| `check_goal` | facts(kind=endpoint/fingerprint/identity_model 计数)、findings(assessment) | 阶段推进 + 轮次兜底（不变量⑦） |
| `untested_surface` | facts(endpoint) − **tested 集合** | DEC-2 计数 + STATE.md 清单。**tested 集合 v2 = findings 端点 ∪ immune 端点 ∪ directions 关联端点**（修"探过没留痕迹"缺口） |
| `render` / STATE.md 投影 | facts（按层分优先级：结论层 > 分母层）、immune（按 confidence 分档）、directions（置顶 open/in_progress/blocked）、findings 标注、session_intel | DEC-9：摘要进 prompt，全文进 `.auto/STATE.md` |
| `plan_directive` | untested 计数、directions open 计数 | DEC-2："未测面 N 个；进行中方向 M 个（目标：清零/完成）" |
| 观察者 | business_context、findings、evidence、黑板摘要 | 判定 + suggestions → directions |
| `noreport` | finding + evidence | reject/suspect/pass（不变量⑨） |
| `transcript_check` | evidence 锚点 | evidence_verified |
| `writeback` | confirmed findings、immune | status.md 表尾追加 / prior-intel-draft（含硬拒清单） |
| `verify_fact`（v2 接线） | provenance | 事实重验/追溯 |

---

## 5. 渲染优先级 v2（三层替代原单列表）

```
① 方向层（置顶）：open/in_progress/blocked directions + 关联段（chains）—— 接力第一优先
② 结论层：identity_model > business_context > findings 标注 > 阴性记录（observed 在前，inferred 弱化）
③ 分母层：credential > kv_secret > endpoint > fingerprint（cap 裁剪只发生在这层）
```

### 5.1 STATE.md 投影格式（E-1 细化：图层 YAML + 其余 markdown）

**三视图模型**（同一份图的三个视图）：`DIRECTIONS 文件` = worker 眼中的图（自己维护的工作状态）；`STATE.md` = 系统投影的图（driver 每轮覆盖写）；`_blackboard.json` = 存储的图（M5 前端读它画图）。

```
STATE.md 结构:
  ## 方向与图（YAML 块）—— 图层用 YAML（Cairn 式，id 可见/边自然表达）
  ```yaml
  directions:
    - {id: D-001, status: in_progress, endpoint: /api/order/detail, goal: 验证idor读}
    - {id: D-002, status: blocked, endpoint: /admin/config/update, blocked: 需X-CSRF头}
  findings:
    - {id: F-001, sev: high, endpoint: /search, chain: "derived_from F-004 (调试页反射)"}
  chains:
    - {rel: combines, refs: [F-002, D-003], note: SSRF+redis凭证=RCE路径}
  ```
  ## 阴性记录 / 事实清单 / 观察者建议（markdown，保持现状 + confidence 分档）
```

为什么图层 YAML、分母层不进 YAML：① chain 引用契约要求 worker **看到** F-xxx/D-xxx（YAML 里 id 是一等列）；② 引用/边在 YAML 自然表达；③ 图层小（策展层）不膨胀，分母层（endpoint×50）进 YAML 是灾难。nonce 包裹策略与现 markdown 段一致。

---

## 6. v1 → v2 迁移

| 项 | 迁移规则 |
|---|---|
| conf float | 保留字段，语义降级为派生排序权重；加载时无 confidence 的旧事实按 conf≥0.8→observed、否则→inferred 推断 |
| 免疫记录 | 无 confidence 的旧记录 → inferred（保守：可重验） |
| directions | 空表起步；首轮 CLAUDE.md 教学后 worker 自然开始写 |
| KINDS | 加 unclassified；旧板无需动（无该 kind 的 facts 就是不存在） |
| handoff | 旧格式仍可解析（"未竟"段若有，driver 尝试提为 directions——best effort，不强求） |

---

## 7. 本定稿吸收的决策映射

| 决策 | 落在 |
|---|---|
| D1（B+三精化） | §2.1.1 菜单 + §3.2 契约 + ingest 映射 |
| D2（被动=分母） | §2.1.1 分层声明 |
| D3（字段接线） | §2.1 confidence/provenance + §2.3 + §4 消费表 |
| D5 轻量版（directions） | §2.4 + §3.3 |
| chain 结构化边（09-03 升级） | §2.2 + §2.5 + §5.1 |
| DEC-2/3/4/5/6/8 | §3.1/3.2/3.3 纪律 + §4 |
| DEC-9（STATE.md） | §4 渲染行 |

---

## 8. 明确不进 v2（推迟/不做，防过度设计）

| 项 | 理由 | 归宿 |
|---|---|---|
| from_/derived_from 边（图结构） | provenance 字段已覆盖追溯；边是查询增强 | v2 图化（§9） |
| domain→site→endpoint 层级 | 子串匹配缺陷用 directions.endpoint + 精确归一化缓解 | v2 图化 |
| facts 加 id | 无边就不需要节点 id（键即身份） | v2 图化 |
| KINDS 扩 subdomain/service/port | 分母层 endpoint 够用 | 需要时再加（走 unclassified 过渡） |
| conf 由 worker 写浮点 | 人因风险（worker 乱填），改 confidence 二值枚举 | 已定：枚举 |

---

## 9. 图的第一消费者：M5 前端图视图（2026-09-03 用户需求）+ v2 并发升级路径

**M5 图视图**（前端控制台必须有，参照 ARTEX"探索链路"力导向图）：

| 图要素 | 数据（v2 schema 已齐） |
|---|---|
| 节点 | findings（id + severity 着色）、directions（id + status 着色：open/blocked/done）、endpoint facts（未测面暗色） |
| 边 | **chain 的 rel 为边类型（分色：derived_from/combines/same_root）、refs 为边两端**；direction.endpoint 为节点→资产锚 |
| 数据通道 | 工作台直接读 `_blackboard.json`（JSON 原生），与 YAML 图层共用同一节点/边模型 |

**A 块落地后数据即齐，M5 不需要等 v2 全图化。**

**v2 并发升级路径**（scheduler 触发时的迁移预告）：

directions 天然前向兼容：并发时代它升级为可认领 intent（加 claim/heartbeat/concluded 字段——Cairn 模式）；facts/findings 加 id 与边表（**chain 结构 → exploration_edges 同款 (src, rel, dst) 表，机械迁移**；provenance → 来源边）；分母层保持扁平索引不图化。**现在做的所有字段都为此留了门。**

---

*拍板位：本 schema 整体一份契约（决策板 A-F 是其决策摘要），确认或逐节批注。确认后：①晋升 docs/ 正式契约 ②phase4 决策板 A/B 块随之关闭 ③按执行计划一批落地（CLAUDE.md/ingest/board/directions/chain/渲染/测试）。*
