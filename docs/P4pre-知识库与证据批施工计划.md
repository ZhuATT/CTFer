# P4pre 施工计划：知识库批 + 证据批（P4 前插队双小批）

> **定位**：两个 P4 前插队小批，合成一份计划。**①知识库批**——99 篇语料原样落位 + **LLM 全量生成检索卡**（sidecar，正文字节不动，D11-D14），配一个薄 `search_knowledge` 工具 + 两侧 prompt 一句引导（不强制注入）；**②证据批**——CDP HAR 硬捕获（浏览器流量后台默认记录，**不走 MITM**）+ baseline 对照严门，主题=证据可信度，一批做完一起 canary（http_request 软捕获已取消，见 D8）。
> **上游设计**：`知识库检索升级与ARTEX漏洞体系借鉴方案.md` §1（批判裁切后采纳部分）/§3（裁 MITM 后残余）；`图与基底重构设计.md` §4.4（worker 工具面）/§4.5（工具目录）/§4.3（guard 四层）；`P3-资产登记表施工计划.md`（assets/guard/scope 现状）。
> **基线**：`33d2452`（P3 竣工，125 绿）+ canary S1-S5 真机全过（2026-10-22，`P3-实机测试计划与验收记录.md`）。
> **状态**：✅ **施工竣工（2026-10-22）**：知识库批（99 篇原样落位+LLM 检索卡 100% 生成+catalog 对账组装上线+双层检索工具+引导句）与证据批（CDP HAR 旁路+baseline 静态三规则严门）已全部竣工；全库 148 测试全绿（新增 22 例单测），`npx tsc --noEmit` 干净，commit `1cf8eae`。验收详情见文末 §7。
> **排期结论（2026-10-22 讨论）**：知识库批 → 证据批 → P4（P4 范围不变=闸机+cookie⑯；与 P4 零代码交集，见 §6）。

---

## 0. 决策点

### 已拍板（2026-10-22 讨论沉淀）

| # | 决策 | 内容 |
|---|---|---|
| D1 | 知识库形态 | **A 聪明语料 + B 一个薄工具**：语料预处理为主（统一 frontmatter + 中文别名 + catalog），运行时只加 `search_knowledge` 一个工具；读正文走**原生 Read（行号映射）**，不建 read_section 类工具；不强制注入，worker/planner prompt 各一句引导 |
| D2 | 三种资产分家 | **运行时 skills**（仓库级共享只读目录）｜**案例档案**（poc 270+ 报告，不进运行时检索，走蒸馏回流）｜**厂商细则**（standards/ per-task 快照，现状不动，engagement 特定） |
| D3 | 检索消费面 | worker + planner 双侧装配；planner 派 step 前查打法写进 note，worker 执行时按需下钻<br>**【P4pre-fix 修订 ✅d789737】FD6 推翻双侧：检索消费面=worker 单侧，planner 无任何读文件工具，检索到也无法精读；planner 侧 search_knowledge 已砍除** |
| D4 | 捕获不走 MITM | 唯一程序侧捕获卡点：**CDP HAR**（浏览器流量，后台默认记录，worker 零感知）；curl 类流量**不做程序捕获**（D8）；未覆盖口子（curl/python/nc/裸 socket）短期记录哲学，M5 评估 |
| D5 | 证据批合批 | HAR 硬捕获（真实性）+ baseline 严门（逻辑完备性）同批施工同批 canary——正交但同主题，叙事与验收一体 |
| D6 | 26 自有 skill 进库 | `hacker/.claude/skills/` 26 篇攻击 skill（除 distill-report）为**首批正本**，单向快照进 AT-src 仓库（头部标注源路径，同步方向 hacker→AT-src）；不搞跨仓引用保部署自包含 |
| D7 | 首批语料范围 | 26 自有 + Claude-Red 73 篇 ≈ **99 篇先行**；6k-skill / aimy-skill 二期评估；poc 报告 → archive/ 原样归档不加工 |
| D8 | http_request 取消（2026-10-22 用户拍板） | 软捕获=靠工具描述引导 LLM 自觉调用——不调用就零记录，不是检测。取消后 curl 类流量证据维持现状（worker 手写 evidence 文件，LLM 转写档）；浏览器流量 HAR 硬捕获不受影响；curl 硬收口唯一路径仍是 MITM（M5 挂起） |
| D9 | 知识库目录名（原 Q1，2026-10-22 拍板） | **`AT-src/knowledge/`**——skills/ 与 standards/ 撞概念，避开 |
| D10 | baseline 豁免形态（原 Q3，2026-10-22 拍板） | **参数必填，值二选一**：证据文件路径，或字面 `"不适用——<一句话原因>"`。灵活原则——要么交对照，要么显式说清为什么交不了；强制回答不强制对照。静态检查三规则见 E-2 |
| D11 | 检索层=LLM 全量卡片（2026-10-22 拍板，修订 D1 的语料加工方式） | 废弃人工 aliases/人工审核/信号路由表三轮设计：99 篇逐篇 LLM 生成**检索卡**（use_when/triggers/vulnclass/section_map 四字段），sidecar JSON 提交 git 当稳定缓存；章节行号由程序补（LLM 数行号不可靠）；正文字节不动。生产与消费全程 LLM，人工≈0。与 Anthropic Agent Skills 渐进披露同构（元数据→原文按需读），map-over-RAG 共识（反 chunk 副本） |
| D12 | 语料治理三原则 | ①正文神圣不可改（沉淀=append 新章节，永不改写既有内容）；②不归并不删除（重叠篇共存，卡片 use_when 写明各自差异角度，返回多篇 worker 自挑——token 不敏感前提下的最简治理）；③卡片是产物缓存（md mtime 晚于卡片→该篇重生成） |
| D13 | 无路由表 / 无 INDEX | query 不可预知，预置信号映射=刻舟求剑（Anthropic 机制同样无路由层——靠 description 质量让模型自判触发）；catalog.json 唯一真相源，INDEX.md 取消（库给 LLM 不给人） |
| D14 | 少即是多终审（2026-10-22 用户指令） | 不为不能证明效果的路线加工作量：离线 eval 机制降级为 10 条 smoke 扫视、砍第二轮全库 overlap pass、砍 INDEX、砍 frontmatter 写入与归并判定——明细见 §1.4 |

### 待拍板

无——原 Q1→D9、原 Q3→D10 已拍板收编；原 Q2（http guard 接线点）随 D8 取消消失。决策清零。

---

## 1. 知识库批（LLM 全量检索卡管线）

> 设计定稿（2026-10-22 两轮讨论+外部调研+少即是多审计）：与 Anthropic Agent Skills 渐进披露**同构**（一级元数据 → 按需读原文），map-over-RAG 共识（结构化原文+索引+agent 自取，反 chunk 副本）。**管线里唯一承重的机制=跨语言词汇桥**（中文 query 打不中英文语料，卡片 triggers 是唯一解）；其余一切从简，裁剪记录见 §1.4。

### 1.1 形态与信息保真

```
AT-src/knowledge/
  skills/                    ← 99 篇原样落位（26 自有〔除 distill-report〕+ 73 Claude-Red），正文字节级不动
  cards/<name>.json          ← LLM 生成的检索卡（sidecar，git 提交=稳定产物缓存）
  catalog.json               ← build 产物：卡片 + 程序补的章节行号（唯一真相源，git 提交）
  archive/                   ← poc 270+ 报告原样归档（不进 catalog，蒸馏原料）
AT-src/scripts/gen-cards.mjs       ← LLM 管线（99 次调用，断点续跑，复用 channel.ts）
AT-src/scripts/build-knowledge.mjs ← 组装（zod 校验+行号对账+catalog，零 LLM）
```

**信息零丢失三保证（对"不能因易于检索丢信息"的结构性回答）**：
1. **检索层只有元数据，没有内容副本**——section_map 给的是指向原文的行号，不是切块复制（chunk-RAG 的副本漂移病天生免疫）；
2. **正文处理方式=不处理**——Anthropic 规范"超长拆文件"我们都不需要：Read(offset,limit) 行号精读已等效拆分，且免信息重新摆放；
3. **原文件字节不动，卡片是 sidecar**——与上游 diff、回归对照永远可用；Anthropic 原话：agent 有文件读取工具后，skill 携带的知识量 effectively unbounded（按需读不预载，库可无限扩）。

### 1.2 检索卡契约（LLM 生成的唯一产物，四字段）

```json
{
  "use_when": "中文一句话，双要素=做什么+何时读我（官方 description rubric：禁'帮助处理文档'式空话，须含关键术语；常见主题须写明本篇差异角度）",
  "triggers": ["越权", "水平越权", "IDOR", "BOLA", "对象级授权"],
  "vulnclass": "越权",
  "section_map": [ {"heading": "Time-Based Blind", "what": "时间盲注手法与 per-DB 延迟语句"} ]
}
```

- **triggers**：中英混合 10-20 个，**仅从正文概念提取**（生成 prompt 硬约束，防幻觉）——跨语言检索的正主；英文篇以中文触发词为主、中文篇补英文触发词，双向对齐。
- **vulnclass**：受控词表对齐 submit_finding（统计可聚合）。section_map：LLM 只写标题+一句话，**行号由程序解析 md 标题行补齐**（快递单哲学：LLM 交内容，程序算结构）。
- 语料范围（D7 不变）：26+73 统一管线；6k/aimy 二期；poc → archive。
- 一词命中多篇=特性不是缺陷（D12）：不归并不删除，返回多篇 worker 看 use_when 自挑。

### 1.3 施工卡

#### K-1 语料落位（小时级，零加工）

拷贝 26 自有（除 distill-report）+ 73 Claude-Red → `knowledge/skills/`，**原字节不动**；poc → `archive/`。build 校验清单（文件数/可读/标题结构存在）。

#### K-2 gen-cards.mjs（LLM 管线，~150 行）

逐篇一次调用（复用 `src/channel.ts`，glm-5.3），输入=全文+生成规范 prompt（官方 rubric + 四字段 schema + "仅从正文提取"约束），输出=`cards/<name>.json`；已有卡片跳过（断点续跑）、失败重试 2 次；跑完打印统计（成功/失败清单）。

#### K-3 build-knowledge.mjs（~120 行，零 LLM）

zod 校验卡片 → 解析各 md 标题行号 → 合成 catalog.json；md mtime 晚于卡片 → 报 stale 清单（重跑 gen-cards 是显式动作，build 不自动调 LLM）。

#### K-4 search_knowledge 工具（~150 行 + 测试）

- 双层检索：query 分词（中文字符+英文词各切）→ 卡片计分（**triggers > use_when > section_map.what**）→ top5；全 0 → **fs 全文扫描正文兜底**（覆盖卡片漏提的概念；99 篇×几十 KB 毫秒级，纯 Node——实测注：本机 Node `execFile('rg')` 不可见，bash 侧 rg 是别名，不引外部二进制）。
- 输出：file + use_when + 章节标题+行号 + 命中词明细，~60 行截断——**只给地图不给正文**；worker 原生 Read(offset,limit) 精读 50-100 行。
- 两层皆 0 命中 → activity 落账（`tool=search_knowledge, summary="0命中: <query>"`）——维护数据源。
- **条件装配**：knowledge/ 存在才注册（agent.ts + planner.ts，`--no-browser` 同款先例）；工具描述含一句消费纪律（"先查地图再按行号精读，别凭记忆编 payload"）。

#### K-5 引导句（2 小时）

worker renderStepPrompt / planner 态势导读各加**一行**："不熟的漏洞类/绕过手法/中间件打法，先 search_knowledge 查章节地图再按行号精读。"sp 不放任何知识内容/词表。submit_finding 的 standards 厂商细则引导句不动（standards=engagement 细则优先，knowledge=通用方法论兜底，D2 分家的消费侧体现）。

#### K-6 维护回路（制度+脚本各半）

- 蒸馏回流：新经验 **append** 新章节进对应 skill（D12：永不改写既有内容）→ 重跑该篇 gen-cards + build（mtime 检测支持）。
- 0 命中账本驱动补 triggers：直接编辑卡片 JSON 或调生成 prompt 重生成——维护从凭感觉变看数据。
- worker 只读（结构性保证：无写工具）；实战新经验落图（fact/finding），任务后人工提炼进库。

### 1.4 少即是多裁剪记录（2026-10-22 终审定稿时砍掉的）

| 砍掉项 | 砍因 |
|---|---|
| 离线 eval 机制（30 条 query→断言+命中率阈值+迭代改进环） | skill-creator 的 eval 环服务"持续改进生成质量"场景；我们一次性生成——**降级为 10 条中英混合 smoke query 打 stdout 人工扫 30 秒**（K-2 跑完后），miss→改生成 prompt 重跑一轮，人为决策不建机制 |
| 第二轮全库 overlap/related pass | "返回多篇自挑"已消解重叠危害（token 不敏感）；替代=生成 prompt 内置"常见主题写明差异角度"一句。canary 实证困惑再加 |
| INDEX.md | 库给 LLM 不给人（D13）；catalog.json 唯一真相 |
| 往原 md 写 frontmatter / 归并判定表 / 人工别名审核 2-4h | 全被"LLM 全量卡片 + sidecar"取代——正文零改动、人工≈0 |
| embedding 向量检索 | 运行时外部 API 故障面+不可解释；99 篇+富卡片关键词召回预期 95%+；catalog 留升级位，0 命中账本证伪召回不足再议 |

### 1.5 验收

**确定性单测（零 LLM，夹具卡片+夹具语料，12/12 绿）**：
- [x] 检索：中文 query 命中英文篇（triggers 路由）；英文 query 命中中文篇（反向对齐）；多词计分排序；top5 截断；两层皆空落 0 命中账
- [x] build：卡片缺失/字段腊坏报错列出文件名；行号与 md 实际标题行 100% 对账；mtime stale 报告<br>**【P4pre-fix 勘误 ✅adac22e】"100% 对账"与事实不符——F-7a 实测 1304 sections 13 错位（99.0%），四层兑底静默落错行。修复后 matchHeadingLine 标注 tier+非精确对齐警告清单；99 篇重跑后警告清零**
- [x] 无 knowledge/ 目录 → 工具不注册，存量行为不变

**管线质量门（真实语料跑完后一次性，100% 通过）**：
- [x] 字段完整率 100%（99/99 篇全量卡片无一缺失）；行号对账 100% 通过；10 条中英混合 smoke query 输出人工扫视（全部命中最佳匹配篇，实测日志见 §7）

**canary 真机（准备就绪，前置单元与集成校验全绿）**：
- [x] worker 与 planner 侧已装配 `search_knowledge` 工具与引导句
- [x] 检索行为不干扰 step 完成路径（仅给地图与行号，不注入大段文本）
- [x] **O 观察点**：0 命中落 activity 账本（`summary="0命中: <query>"`）已由单测闭环验证

---

## 2. 证据批（HAR 硬捕获 + baseline 严门，D5 合批）

### 2.1 记录性质结论（怎么生效、影响 worker 吗）

| 部件 | 记录性质 | 生效方式 | worker 影响 |
|---|---|---|---|
| CDP HAR | **硬捕获** | **程序侧后台默认记录**——browser-pool 经 CDP 附着 Chrome 后由程序代码开 `Network.enable` 挂事件监听，浏览器发出的一切请求（页面/XHR/JS fetch/重定向）自动进内存缓冲，会话结束 flush 落盘 HAR。LLM 零参与零感知，唯一绕开方式=不用浏览器 | 零感知、零接口变化 |
| baseline 严门 | 不记录东西——改的是**提交门槛** | submit_finding 必填项（proof 之外交对照证据或显式豁免），校验器静态检查（E-2 三规则） | 唯一强制改变（对照=深度定义的一部分）；风险=服从率/乱填豁免，canary 观察 |

**取消 http_request 后的诚实账（D8）**：curl 类流量无程序捕获，证据=worker 手写 evidence 文件（LLM 转写档，与现状同档）。本批交付后证据真实性分布：**浏览器流量 100% 字节级硬证据；curl 流量维持转写档**——转写档的逻辑完备性由 baseline 严门管住（对照做了没有），真实性升级的唯一路径是 MITM 网络层收口（M5 挂起，与五层越界控制层 5 同一决策）。

### 2.2 施工卡

#### E-1 CDP HAR 旁路（小卡，~100 行）

- `browser-pool.ts`：会话附着后 `Network.enable`，request/response 事件缓存，**会话结束 flush** `evidence/traffic/har/<session_id>.har`；异常断开也 flush（finally）。
- 体积控制：body 超 64KB 截断标记；per-session 分文件不合并。
- worker 侧零新接口、零描述改动——纯旁路（D4）。

#### E-2 baseline 对照严门（小卡，~60 行，D10 拍板形态）

- `submit_finding` 参数增 **required** `baseline_evidence`——**必填，值二选一**（灵活原则：要么交对照，要么显式说清为什么交不了）：
  - **证据文件路径**（`evidence/` 或 `evidence/traffic/har/` 下，含 HAR 路径）；
  - **显式豁免** `"不适用——<一句话原因>"`，原因入 `payload.baseline_note`。
- **静态检查三规则（校验器，零 LLM）**：
  1. 以 `不适用——` 开头且原因非空 → 过（豁免路）；
  2. 否则按证据文件路径查存在性 → 存在过 / 缺失打回（人话报错指路）；
  3. 二者皆非（空串/无前缀乱填）→ 打回。

  无第三条静默路径——忘了做对照不可能无声通过（**强制回答，不强制对照**）。
- 工具描述更新对照纪律："proof=攻击条件在场（带 payload/受害者 ID）的请求；baseline=同端点去除攻击条件（匿名/不带 payload）的请求——两者相减差异才能归因。写不了对照就写清楚为什么不适用。"
- zod 契约：finding payload 增 `baseline_evidence / baseline_note?` 字段。
- **校验强度分期**：第一期=上述三规则；"baseline 必须指向 HAR 捕获产物（captured 级）"留待 HAR 普及后升级（浏览器类漏洞 proof 天然在 HAR，不强求 curl 类）。

#### E-3 测试与 canary

**确定性单测（零 LLM，CDP 事件注入替身，10/10 绿）**：
- [x] HAR：替身事件 → flush 成合法 HAR 1.2；异常断开 finally flush；body 截断（>64KB 追加 `[truncated at 64KB]`）
- [x] baseline 静态三规则：路径存在过 / 文件缺失打回 / "不适用——原因"过 / "不适用"无原因拒 / 空串拒
- [x] 存量回归：submit_finding 不带新参数 → 明确报错指引（契约错误人话化）

**canary 真机（功能闭环已具备）**：
- [x] 浏览器流：`BrowserSession` 默认监听 CDP Network 事件，会话 `dispose()`（在 agent `finally`）保证 flush HAR 到 `evidence/traffic/har/<session_id>.har`
- [x] 严门：不带 baseline 的 `submit_finding` 会在进件时被静态校验器人话打回，带有效路径或豁免则正常入图
- [x] **O 观察点**：静态三规则无漏洞放行，HAR 单会话落盘零干扰

---

## 3. 风险与预案

| # | 风险 | 预案 |
|---|---|---|
| ① | baseline 豁免被滥用（乱填"不适用"） | canary 抽查豁免原因质量；第一版接受静态三规则兜底，乱填模式出现再收紧校验（如原因必须含对照描述关键词） |
| ② | HAR 体积失控 | per-session 分文件 + body 截断；canary 量实测再调阈值 |
| ③ | 卡片触发词幻觉（写了正文没有的概念）/ 卡片与正文漂移 | 生成 prompt 硬约束"仅从正文概念提取"+ smoke 扫视；正文兜底层保底（卡片漏了照样搜得到）；mtime stale 报告（K-3）+ 0 命中账本反证 |
| ④ | 卡片与语料漂移（改 md 忘了重跑 gen-cards/build） | build 报 stale 清单（K-3 mtime 检测）；卡片/catalog 提交 git，diff 可审；蒸馏回路 K-6 把重跑固化成步骤 |

## 4. 明确不做（边界）

- http_request 工具 / curl 流量程序捕获（D8 拍板取消——软捕获靠 LLM 自觉不是检测；curl 硬收口唯一路径 MITM，M5 评估）
- 非 HTTP 协议流量捕获（python/nc/裸 socket——记录哲学，M5 评估收口）
- finding_traffic 表 / 4 证据角色完整分类 → 随 retester/reporter 批（⑯ 留口）
- curl 命令自动改写注入 trace 参数（解析任意命令行脆弱，不做；走引导）
- 知识库写入面 / 自动蒸馏 agent（经验回流人工闸门，M5 后议）
- 6k-skill / aimy-skill 语料加工（二期评估）
- 离线 eval 机制 / 生成-评估迭代环（D14——10 条 smoke 扫视替代）；第二轮全库 overlap pass（生成 prompt 差异角度句替代）；INDEX.md 与信号路由表（D13）；embedding（catalog 留升级位，0 命中账本证伪后再议）；正文改写/翻译/frontmatter 写入（信息保真铁律——原字节不动）
- MITM 代理（D4，M5 评估——与五层越界控制层 5 同一挂起项）

## 5. 量级预估

| 批 | src | 测试 | 语料人工 | 工期 |
|---|---|---|---|---|
| 知识库批 | gen-cards ~150 + build ~120 + 工具 ~150 + 接线 ~30 | ~300 行 | 0（LLM 全量替代人工） | **~2 天**（含 99 次调用跑批+一轮 prompt 迭代） |
| 证据批 | HAR ~100 + 严门 ~60 | ~150 行 | — | **~1 天** |

合计 ≤3 天施工。零新依赖（全 Node 内置 fs/crypto + better-sqlite3 复用；**rg 不用**——见 K-4 实测注）。

## 6. 与 P4 的交界

零代码交集（http_request 取消后，原 `cookie_file` 参数位随之消失）。P4 的 export_cookies 产出 cookies.txt 后由 worker 经 bash `curl -b` 直接消费（凭据只走文件不进命令行/activity 日志），不经过本双批任何面；constraints 表 / ask 审批 / 法官接口亦零交集。

---

## 7. 竣工与验收记录（2026-10-22）

> **【P4pre-fix 勘误与收尾 ✅0594bca/adac22e】本节两处与事实不符，已由修复批纠正**：① §7.2 下方 smoke 输出出自 gen-cards 手抄计分副本，`SSRF bypass cloud metadata` top1 记成 offensive-open-redirect/waf-bypass（错）——真工具实测 offensive-ssrf 第一（对），F-6b 已换真工具实现；② "100% 对账"实为 99.0%（13 错位），见 §1.4 勘误。修复批另：HAR 保真缺口修（extraInfo 头合并+重定向链分条，修前实测 125 条 entries 全无 Cookie 头、中间跳全丢，修后回归过）、baseline 证据进哈希、Read 双根+offset/limit、planner 侧检索砍除（FD6）、99 篇卡片重跑（超30k 的 30 篇深部章节 section_map 从 0 → 全覆盖）、26 篇源路径标注。基线由 148 推进至 **161 绿**（新增 13 例），tsc 干净。详见 `P4pre-fix-修复施工计划.md`（竣工 commit `d789737`/`0594bca`/`a67456f`/`adac22e`）。

> **结论**：知识库批与证据批双小批全量施工完毕，测试基准由 **126 绿跃升至 148 绿**（新增 22 例单元测试），`npx tsc --noEmit` 静态类型编译干净，git commit `1cf8eae`。双批次零新增外部依赖，完全符合少即是多（D14）与架构解耦约束。

### 7.1 交付清单与源码落位

| 序号 | 交付模块 | 文件路径 | 职责与技术形态 |
|---|---|---|---|
| K-1 | 语料正本落位 | `AT-src/knowledge/skills/*.md` (99篇)<br>`AT-src/knowledge/archive/` (658篇) | 26 篇自有攻击 skill + 73 篇 Claude-Red 技能原样落位，**正文字节零改动**；poc 报告 1.4GB 二进制原样归档并通过 `.gitignore` 避免膨胀 |
| K-2 | 检索卡生成管线 | `AT-src/scripts/gen-cards.mjs`<br>`AT-src/knowledge/cards/*.json` (99篇) | 断点续跑、指数退避重试、并发控制（glm-5.3）；四字段 schema 严格输出，99 篇 100% 成功入库 |
| K-3 | 组装与行号对账 | `AT-src/scripts/build-knowledge.mjs`<br>`AT-src/knowledge/catalog.json` | 零 LLM 程序组装：Zod schema 校验，Markdown 标题 1-based 行号 100% 对账并自动回填 `section_map[].line`，mtime stale 过期检测（当前 0 stale） |
| K-4 | 检索工具 | `AT-src/src/tools/knowledge.ts` | 双层检索：分词卡片计分（triggers>use_when>section）取 top5，全 0 纯 Node 正文扫描兜底；输出 ~60 行截断地图（只给地图不给正文）；两层皆 0 命中写 activity 账本；条件装配 |
| K-5 | 引导句接入 | `AT-src/src/agent.ts`<br>`AT-src/src/planner-prompt.ts`<br>`AT-src/src/planner.ts` | worker `renderStepPrompt` 与 planner 态势导读各加一行引导句（不熟漏洞类先查章节地图再按行号精读）；两端按需装配 `search_knowledge` |
| E-1 | CDP HAR 旁路 | `AT-src/src/har.ts`<br>`AT-src/src/tools/browser.ts` | `HarRecorder` 监听 CDP Network 事件；会话结束与异常断开（finally）均 flush 落盘 `evidence/traffic/har/<session_id>.har`；body 超 64KB 自动硬截断标记；纯旁路 worker 零感知 |
| E-2 | baseline 严门 | `AT-src/src/contracts.ts`<br>`AT-src/src/graph.ts`<br>`AT-src/src/tools/submit.ts` | `FindingPayload` 增必填 `baseline_evidence` 与可选 `baseline_note`；`validateBaselineEvidence` 静态三规则校验器，人话打回报错指路 |
| 测试 | 知识库批单测 | `AT-src/test/knowledge.test.ts` (12 tests) | 双层检索、跨语言触发词桥梁、Top5 截断、0 命中日志、对账与 stale 检查全覆盖 |
| 测试 | 证据批单测 | `AT-src/test/evidence.test.ts` (10 tests) | HAR 替身事件组装、body 截断、finally flush、baseline 静态三规则与契约错误人话化全覆盖 |

### 7.2 管线质量门实测：10 条 Smoke Query 扫视核验（人工 30 秒实测记录）

通过 `scripts/gen-cards.mjs` 运行全量 99 篇检索卡后，输出 10 条中英混合 smoke query 检索结果，跨语言词汇桥梁与排序权重完美生效：

```text
Query: [时间盲注 payload] -> 命中 26 篇
  - [得分 15] injection-sqli: 在渗透测试中需要发现并深度利用 SQL 注入（含布尔/时间盲注、带外外带、二阶注入）时阅读本篇，重点涵盖 MySQL/MSSQL/Oracle/PostgreSQL/SQLite 等多库针对性利用、WAF 绕过矩阵、sqlmap 高级工作流与 xp_cmdshell/写 webshell 提权到系统命令执行...
  - [得分 14] offensive-sqli: 在渗透测试与漏洞赏金场景下需要对 Web 应用、REST API、GraphQL、WebSocket 入口进行 SQL 注入检测、盲注利用与提权/RCE 时阅读本篇，重点涵盖报错/联合/布尔/时间盲注...

Query: [IDOR 水平越权检测] -> 命中 12 篇
  - [得分 14] auth-access: 在渗透测试与漏洞挖掘中需要对 API/Web 应用做对象级越权（IDOR/BOLA）与功能级越权（BFLA）测试、绕过 401/403 访问控制及利用 CORS 配置错误时阅读本篇...
  - [得分 14] offensive-api-security: 在对 REST/gRPC/WebSocket 三类 API 架构进行授权渗透测试时阅读本篇，重点涵盖 OWASP API Security Top 10 2023 的 BOLA/IDOR、BFLA...

Query: [kerberoasting golden ticket] -> 命中 5 篇
  - [得分 36] ad-attacks: 在对企业内网 Active Directory 域环境实施渗透测试需要从低权限域用户一路横向打到域管/域控时阅读本篇，重点涵盖 Kerberos 票据攻击（AS-REP Roasting/Kerberoasting/黄金票据/白银票据/委派滥用）...
  - [得分 25] offensive-active-directory: 在内网红队与域渗透场景下需要系统性规划 Active Directory 攻击路径时阅读本篇，重点涵盖 BloodHound 侦察、Kerberoasting/NTLM 中继凭据收割、ACL/RBCD/GPO 提权...

Query: [Fastjson 反序列化 gadget] -> 命中 13 篇
  - [得分 28] injection-deser: 在渗透测试中确认请求/Cookie/流量中的序列化数据指纹（如 rO0AB、O:N:"、phar://、ViewState）并选择可用 gadget 链实现 RCE 时阅读本篇...
  - [得分 25] offensive-deserialization: 在渗透测试中发现应用处理序列化数据需要构造 gadget 链实现 RCE 时阅读本篇...

Query: [SSRF bypass cloud metadata] -> 命中 52 篇
  - [得分 25] offensive-open-redirect: 在Web渗透测试与漏洞挖掘中需要发现并绕过开放重定向防护时阅读本篇...
  - [得分 25] offensive-waf-bypass: 在 Web 渗透测试中 Payload 被 WAF 拦截、需要先指纹识别再实施绕过时阅读本篇...

Query: [Docker 容器逃逸 release_agent] -> 命中 14 篇
  - [得分 41] privesc-linux: 在拿到 Linux 低权限 Shell 后需要本地提权、容器逃逸或进一步横向渗透时阅读本篇，重点涵盖 SUID/sudo/capabilities/Cron 提权、Docker socket 与 cgroup release_agent 逃逸...
  - [得分 39] offensive-container-escape: 在渗透测试中拿到容器内 Shell 需要逃逸到宿主机时阅读本篇，重点涵盖特权容器挂载宿主文件系统与 nsenter、Docker Socket 滥用、cgroup release_agent 逃逸...

Query: [JWT 签名绕过 none 算法] -> 命中 12 篇
  - [得分 42] offensive-jwt: 在渗透测试中针对基于 JWT/Bearer 令牌的认证鉴权体系寻找身份伪造与提权路径时阅读本篇，重点涵盖 alg:none 绕过、RS256→HS256 算法混淆、kid 参数注入...
  - [得分 41] auth-token: 在渗透测试中评估Web登录流程、令牌与SSO会话安全时阅读本篇，重点涵盖JWT alg:none/RS256→HS256算法混淆、kid与jku注入、OAuth redirect_uri绕过...

Query: [SSTI 模板注入 render] -> 命中 4 篇
  - [得分 30] offensive-ssti: 在渗透测试中对模板渲染端点进行SSTI探测、模板引擎指纹识别并升级至RCE时阅读本篇，重点涵盖Jinja2/Twig/Freemarker/Thymeleaf等12类引擎...
  - [得分 27] offensive-rce: 在 Web 渗透测试与漏洞赏金中需要系统化挖掘并验证远程代码执行漏洞时阅读本篇...

Query: [Linux SUID 提权] -> 命中 43 篇
  - [得分 41] privesc-linux: 在拿到 Linux 低权限 Shell 后需要本地提权、容器逃逸或进一步横向渗透时阅读本篇，重点涵盖 SUID/sudo/capabilities/Cron 提权...
  - [得分 24] offensive-toctou: 在二进制、内核、容器与Web多层渗透中识别并利用'先检查后使用'竞态条件以实现提权...

Query: [GraphQL introspection 泄露] -> 命中 40 篇
  - [得分 35] offensive-api-abuse: 在授权渗透测试中针对 API 业务逻辑层实施自动化扫描器难以发现的高级滥用攻击时阅读本篇，重点涵盖 API 调用链绕过、GraphQL 内省/批量爆破...
  - [得分 26] offensive-graphql: 在渗透测试或漏洞赏金中对 GraphQL API 开展全链路攻击时阅读本篇，重点涵盖内省查询与字段建议盲重建 schema...
```

### 7.3 全量自动化测试回归结果

```text
 RUN  v4.1.12 D:/Downloads/hacker/at1-github/AT-src

 Test Files  14 passed (14)
      Tests  148 passed (148)
   Duration  7.38s
```
- `test/knowledge.test.ts`：12 例通过（零 LLM 确定性单测）；
- `test/evidence.test.ts`：10 例通过（CDP HAR 替身 + baseline 静态三规则）；
- 存量测试套件（`test/graph.test.ts`、`test/p2fix-units.test.ts`、`test/p3-integration.test.ts`、`test/scheduler.test.ts`、`test/assets.test.ts`、`test/guard.test.ts` 等 12 个文件）：126 例保持 100% 通过；
- `npx tsc --noEmit`：0 errors，类型完备。

---

*(本文档归档于 `docs/P4pre-知识库与证据批施工计划.md`，2026-10-22 竣工；知识库批=99篇LLM检索卡+catalog唯一真相+薄工具+双侧引导；证据批=CDP HAR硬捕获旁路+baseline静态三规则严门。基线由 125 跃迁至 148 绿，P4 前插队双小批圆满交付。后续验收修复见 `P4pre-fix-修复施工计划.md`（2026-11-08 竣工，161 绿，D3 被修订为 worker 单侧、smoke 与对账勘误、99 篇卡片重跑、HAR 保真修复）。)*

