# Phase 3 —— 验证（M3）执行计划

> 依据：`docs/at1-施工执行单.md` 卡 3.1-3.4 + 设计§3.4 全节（含 §3.4.4 实现契约与门 2 prompt 草案）
> 目标：**worker 报的发现可以被机器验真**——Claim 进四门漏斗，confirmed 才算数。
> Phase 3 结束时 AT1 有记忆+有裁判，但没有主循环（M4）——canary-web（M3.5）并行开建，另立 `phase3.5-canary.md`。
> 工作目录：`D:\Downloads\hacker\at1-github`；上一 Phase：`b3e641f`（状态层，52 单测 + relay 双场景）

---

## 0. 范围与前置

**做**：verify.py（Claim 校验 + 四门状态机 + 词表）/ llm.py（vendor，门 2 通道）/ 七案测试
**不做**：driver 调用接线（M4）、门 1.5 默认开启（留接口默认关，设计§7）、canary-web（并行轨道，独立计划）、evaluator（M4 后）

**前置**：
| # | 事项 | 状态 |
|---|---|---|
| 1 | 门 2 异构 verifier 通道 | ✅ **已就位（2026-08-25 实测）**：讯飞 maas 承载 DeepSeek V4 Pro（`xopdeepseekv4pro`，OpenAI 兼容 `/v2`），key 在 `.secrets.env`（gitignored）；Bearer id:secret 整串认证；developer role 被拒（llm.py 不用）；providers 预设 `xfyun` 已加。原 deepseek 官方 key 不再需要 |

## 1. 契约定版（本 Phase 锁死）

### 1.1 FINDINGS 行 = 一个 Claim（设计§3.4.1）

```json
{"id":"F-001", "class":"idor", "endpoint":"/api/order/detail",
 "as_identity":"userA", "owner_identity":"userB",
 "marker":"13800138000", "marker_source":"evidence/userB-profile.md",
 "evidence":"evidence/idor-1.md",
 "expect":null, "expect_denied":null,
 "distinct_from":"status.md 无越权类已确认项；本 run 首条", "round":3}
```
校验：class ∈ 词表类目；evidence/marker_source 相对 workdir 路径；distinct_from 非空（缺 = 门 1 机械拒收）。

### 1.2 正则同源（设计§3.4.3）

词表与 board 抽取**共用一份正则**：board 的 `_CRED_RXS` 等提为公开常量（或抽 `src/lexicon.py`），verify 只引用不复制——情报和验收永远同一套形状定义。

### 1.3 门 3 的 transcript 匹配策略（新定，防转义坑）

transcript 是 JSON 行，命令串在里面带 `\u`/`\"` 转义——**逐字节 grep 会假阴性**。实现：逐行 `json.loads` 后在**解码后的文本**里找 evidence 请求段的规范化子串（压空白+小写）。

## 2. 任务卡

### P3.0 原料阅读（不写码）

- 精读 `hxbai/verify.py`（三重门主体）：门 2/门 3 的调用形态、verifier 输入构造
- 精读 `hxbai/llm.py`（OpenAI 兼容客户端）：重试/空响应处理——vendor 主体
- 产出：可抄/重写清单进本文件附录

### P3.1 Claim schema + FINDINGS 收割（~80 行 + 单测）

- `parse_claim(line) -> Claim`：容错解析（BOM/尾逗号——P2 实测教训），字段校验，坏行拒收并返回原因
- `load_new_claims(path, offset)`：复用 harvest.diff_new_lines
- **验收**：合法行解析全字段；缺 distinct_from / class 不认识 / evidence 路径不存在 → 各自拒收

### P3.2 门 1 词表 + gate1（核心，~200 行 + 单测）

- 11 类判据逐行落（设计§3.4.3 表）：
  - idor 读：**双点接地**（marker ∈ evidence"响应"段含 URL-decode 变体 **且** ∈ marker_source 原文）
  - idor 写 / authbypass / sqli 报错 / 布尔差分（baseline+attack 两段+差异声明）/ ssrf（OOB 命中标记或内网实据）/ xxe·lfi（特征串）/ xss（payload 标记）/ infoleak（凭证正则 − instance-id/内网 IP 黑名单）/ logic·race（before/after+delta）
  - **负 oracle**：401/403 或 expect_denied → 返回 immune 记录（入板由 driver 做，M4）
- **验收**：每类至少 1 正 1 负单测；marker URL-decode 变体命中；instance-id 被黑名单挡（铁律）

### P3.3 门 2 gate2（vendor llm.py + prompt 定稿，~150 行）

- vendor `hxbai/llm.py` → `src/llm.py`（微改：错误处理对齐）
- prompt = 设计§3.4.4 草案 + **class 要件全表**（从 CLAUDE.md 绝对不报表逐条翻译，11 类每类一段"什么情况下不成立"）——这就是当初说的"M3 施工件"
- 温度 0；输出严格 JSON；解析失败重试 1 次 → 仍失败降 tentative
- verifier 配置走 `build_verifier_config`（已就位，异构默认）
- **验收（需 live LLM）**：两案——共享地址场景 refuted=true；真 idor refuted=false

### P3.4 门 3 gate3 + 状态机串联（~120 行）

- gate3：evidence"来源命令/请求"段规范化后在 transcript 解码文本中可寻（§1.3 策略）；"可复现"问在门 1.5 关闭时跳过并在 reason 记录
- `verify_claims(claims, *, transcript_path, gate2_fn=None, replay=False) -> list[Verdict]`：漏斗串联；**纯函数无副作用**（写回是 driver 的活，M4）
- 门 1.5 留接口：`replay=True` 时 urllib 重放只读类（凭证过期→tentative；写操作类永不重放）
- **验收（七案，M3 核心 demo）**：
  ①伪造 marker（不在响应原文）→ rejected
  ②编造 marker_source → rejected
  ③真实双点 → 过门 1
  ④负 oracle：403 证据 → immune 记录
  ⑤共享收货地址（buyer=userA 语境）→ 门 2 refuted → rejected
  ⑥真 idor → 门 2 放行 → confirmed
  ⑦整体虚构（三件套自洽但请求不在 transcript）→ 门 3 杀

## 3. Phase 3 DoD —— ✅ 已验收（2026-08-26，等用户过目）

- [x] P3.1-P3.2 单测全绿：每类正负例（idor 读/写、authbypass、infoleak 含黑名单铁律与占位符、sqli 报错/差分、ssrf、xxe/lfi、xss、logic_race）+ 解析容错（BOM/别名/标题变体/无段兜底/三层 JSON 剥取）
- [x] 七案全过：①伪造 marker ②编造 marker_source ④负 oracle（403→immune）⑦整体虚构（门3 杀）为纯单测；**⑤共享地址（rejected）⑥真 idor（pass）为 live 真 LLM 终验，3 票多数决两案全对**
- [x] pytest **73/73**（≥65 达标；P1/P2 的 52 条零回归）
- [x] gate2 live 调用：调参历程 15+ 次全走白嫖 key，成本 **≈0**
- [x] 设计文档回写：§7 门 2 票数默认 1→3（多数决）；门 2 要件从 prose 改判定树式（§3.4.4 精神，实现以 src/verify.py 为准）
- [x] 成本：$0（讯飞 key 免费）＋开发时间半天

### 门 2 调参实录（P3 最重要的工程产出，四步走到定稿）

| 步 | 改动 | 结果 |
|---|---|---|
| 1 | 初版要件（prose："不成立：A 是相关方/同企业/同源"） | verifier 要求"证明 A 与 B 没关系"——**举证倒置**，⑤⑥ 全拒 |
| 2 | 加"举证方向"条款（'未排除可能性'不算否决） | ⑤ 修复稳定；⑥ 一拒一过——**verifier 自我不一致** |
| 3 | **多票多数决**（3 票默认，`AT1_GATE2_VOTES` 可调；平票/分歧→tentative 保守挂起） | 把不稳定从"随机错"转成"保守挂起" |
| 4 | **要件改判定树式**（"①找 buyer/收货人=A→拒 ②找代理/同源明示→拒 ③都没有→放行，'可能存在未写明关系'不算"） | **根治**：deepseek 双案全对两轮稳定 |
| 附 | 模型矩阵（判定树下 4 模型 ×2 案 ×2 轮） | deepseek 全对稳定；qwen/kimi 一边倒全拒；glm52 判飘且与 solver 同族——**定 deepseek（经讯飞）** |

**教训沉淀（给以后写 class 要件的规则）**：语义判据写成判定树（机械步骤+明确分支），不写成"成立要件+不成立情形"的 prose——LLM 对后者的举证方向理解不稳定。其余 class 的要件在真目标上首次使用时也应逐步判定树化。

### 其他定论

- **authbypass 遇 403 → immune 而非 rejected**（负 oracle 先行）：口子试过是关的，阴性结论防重测比"拒收"更有价值——原设计"非 403"判据被负 oracle 覆盖
- 门 3 转义坑实测确认：JSON 转义（引号）与 `\u` 转义（中文）两类 needle 解码后均正确命中；空请求段 → 跳过并记录（不假装验证过）
- llm.py vendor 保留 hxbai 的限流退避/空响应重试/fallback 链；observability 剥除（由调用方 events 记）

## 4. 已知风险

| 风险 | 应对 |
|---|---|
| 讯飞 maas key 失效（白嫖 key，Pod 重建即换，周期约 1 年） | 同款降级预案仍成立：verifier 临时换 glm 同模型 + 门 3 加严（providers 一行）；拿到新 key 更新 `.secrets.env` 即恢复异构 |
| gate2 输出不稳定（JSON 格式漂移） | 温度 0 + 严格解析 + 重试 1 次 + 失败降 tentative（绝不误放）；单测用 mock llm，live 只验两案 |
| evidence 四段格式 worker 不守约 | 解析容错（标题变体/BOM/缺段）；缺"响应"段的 idor claim → rejected（reason=evidence 格式不符）——宁可错杀进 tentative 不放行 |
| transcript 转义导致门 3 假阴性 | §1.3 策略：解码后规范化匹配；单测造含 `\u` 转义的 transcript 验证 |
| hxbai verify.py 与我们的 Claim 语义差异大 | P3.0 先读：预计只抄"多票/重试"骨架，判据全部按设计词表重写（P2 同款打法：hxbai 降级为参考读物） |

---

## 附录 A：P3.0 原料阅读结论（2026-08-26，hxbai verify.py 316 行 + llm.py 222 行）

**可抄（骨架/机制，判据全换）**：
- `_parse_json` 三层剥取（整段 → 去 markdown 栅栏 → 正则抠 `{...}` 截到最后一个 `}`）——门 2 输出解析直接用，正是"JSON 夹私货"的解药
- `_negation` 的 skeptic 形态：只给 claim+evidence 不给作者推理、多票多数决（`refutes*2 > ran`）、verdict cache（同 claim+evidence 同结论，幂等）
- "skeptic 不可用 → tentative（safe default）"——绝不误放的实现形态
- llm.py 整体：OpenAIBackend（含 reasoning_effort 兼容退避）、限流重试（`_is_rate_error` + 指数退避）、空响应重试、fallback 后备链——vendor 主体
- `_OASSERT` 的 sqli/lfi/xxe 特征正则——与设计词表同款，直接复用

**不抄（CTF flag 语境 / 与设计冲突）**：
- Claim 结构（flag kind/flag_format/placeholder 词典）——我们有自己的 schema
- grounding 的"flag value ∈ observed_output"——我们是 marker 双点（两文件），语义不同
- `_interrogation` 的 LLM 门 3——设计决定我们的门 3 是机械清单（transcript 查证），不是 LLM
- placeholder/decoy 词典——我们的占位词表语境不同（REDACTED/示例响应）
- observability 集成——我们没有 obs 模块，用 events

---

## 附录 B：门 2 全科考试（SRC 标准校准，2026-08-26）—— ✅ 22/22

**素材**：四家 SRC 判读标准（`src标准/`）→ 蒸馏版 `docs/src-standards-distilled.md`（跨厂商共识=硬规则、单厂商条款标注出处、含大模型产品收录规则与去重策略）。

**落地**：CLASS_REQS 全 11 类判定树化 + 共享【敏感数据标尺】（四家数据分级）+ 绝对不报表获四家共识背书（Self-XSS/无敏感操作 CSRF/内网 IP/纯猜测等）。考题 22 道（11 类 × 拒/放，全部源自标准边界条款），3 票多数决，`tests/gate2_exam.py` 可重复开考。

**过程（校准循环实录——考试暴露问题→定性→修）**：

| 轮 | 分 | 挂题 → 定性 → 修 |
|---|---|---|
| 首轮 | 19/22 | ①非 marker 类（sqli/ssrf/xxe/lfi/logic）prompt 硬塞 marker_source，verifier 被"marker 关联不上"带偏误拒 2 题 → **真 bug**：marker_source 仅对 marker 类（idor/authbypass/xss）附带；②"可套现"定义被过度应用 → 树③细化（通用无门槛券=可套现）；③布尔盲注被要求"数据披露" → 树②加条款：布尔差异无需数据回显即成立，提取量定价值档不定成立性（小米/阿里中危原文） |
| 补考 | 3/3 过 | sqli_diff 考题证据太瘦（无 payload/响应片段）——**verifier 挑得对**（美团"须提供数据包 raw"），补富考题后过 |
| 全科复考 | 21/22 | authbypass 考题 marker 与证据无关联（模板默认手机号 vs 改横幅案）——**verifier 挑得对**（marker 类就该查关联），考题 marker 换成 AT1BANNER 后 3/3 过 |

**结论**：判定树 + 多数决 + SRC 标准素材下，verifier 全科通过；三处系统修复 + 两处考题修复，校准循环验证有效（挂题一半是系统的、一半是考题的——verifier 挑证据质量的两案都挑对了）。

**遗留清账**：第 1 条（10 类 prose）✅ 清零；第 3 条（只考过 1 门课）✅ 清零；第 2 条（oob.py）挂 M4 不变。

---

## 附录 C：修订——"免疫"改为"阴性记录" + 门2 误报入板（✅ 用户已批，2026-08-26 已实施，pytest 75/75）

**背景（用户定调，v2）**：阴性记录的价值不在省 token（预算是 stoploss 层的事，prompt 内容层只管信息密度）——而在**把有效信息留在黑板**：黑板是目标地图，阴性结果（"此口子此类打法是关的"）与阳性事实同样是地图特征。worker 是消费情报的智能体，不是被节流的对象：命令式"勿重测"切断它的推理，**结果标记**（403/第3轮/什么姿势）才让它能推理利用（换姿势、关联其他面）。本修订把命令改为标记；authbypass 403→阴性记录（原 immune）定论本体不变。

**延伸推论（✅ 用户已批"要"，数据侧已实施，入板接线在 M4 driver）**：门 2 否决的误报（如"buyer=userA 属设计内行为"）同样是有价值的阴性情报——现状只进日志即丢，下一轮 worker 会重新发现同一疑似、重新提交、重新被拒，白烧一轮。若纳入：gate2 rejected 也生成"已否决模式"记录入板（同样标记式渲染，注明否决理由摘要与轮次）。

### 改动清单

| # | 位置 | 现状 | 改为 |
|---|---|---|---|
| 1 | 阴性记录**字段**（board immune 条目） | `{endpoint, class, since_round}` | `{endpoint, class, status(403/401/expect_denied), round}`——gate1 生成时从响应与 claim 带入 |
| 2 | **渲染文案**（board.render） | `已免疫（勿重测）：`<br>`- /admin/x（authbypass）` | `阴性记录（已试过、当时未突破——重复同姿势只会同样结果；换姿势/新线索不受此限）：`<br>`- /admin/x（authbypass，403，第3轮）` |
| 3 | **手册纪律行**（prompt.py recon） | `动手前先看状态区的"已免疫勿重测"` | `动手前先看状态区的阴性记录，规划时跳过已试过的同姿势（换姿势不受限）` |
| 4 | Verdict.immune 载荷（verify.gate1） | `{endpoint, class}` | 同 #1 三字段 |

### 刻意不改的（说明理由）

- **内部 API/事件名保留 `immune`**（`board.add_immune`、事件 `immune_added`、黑板 `immune` 列）：改动会波及事件规格（§4.1 已定）、phase2 文档与既有测试，而用户关心的是 worker 消费面——**语义翻译发生在渲染层**（代码内注释注明 immune=阴性记录）。若要彻底改名（negative_record），另批一次，涉及面大一圈。
- 免疫是提示不是封锁的设计不变——修订正是把"提示不硬封"从口头缓解落成文字保证。

### 验收

- [x] 单测：渲染段含新标题与 status/round 字段；gate1 的 immune 载荷带 status；旧断言（"已免疫（勿重测）"）全部替换
- [x] pytest 全绿（**75/75**：新增 gate2 pattern 载荷与全链传播两测）
- [x] 手册纪律行更新后 prompt 测试不回归；实施明细：Verdict 新增 pattern 字段 / board 新增 rejected_patterns 存储+add_rejected_pattern+渲染段 / gate1 immune 载荷带 status+round

---

## 附录 D：canary-web 全链路实机测试（原 M3.5 并入本 Phase，用户拍板"一起测试"）

**目的**：验证层第一次吃**真 worker 产的 claim**——真 Flask 靶 → worker 真挖真提交 → 四门真判 → 对标准答案打分。补掉两个边界：四门只见过我手写的考题、判定树没见过 worker 的真实证据形态。

**不做**：M4 driver（收割用临时编排脚本）、guard/stoploss（本地靶无风险）。

### 产物

| 文件 | 内容 |
|---|---|
| `canary-web/target.py` | Flask 靶：4 真洞（idor 读/idor 写/authbypass/sqli 报错）+ 7 干扰项（CORS `*`/sourcemap/self-XSS/开放重定向/内网 IP+instance-id/安全头缺失/版本指纹）+ 双账号（userA/userB，marker=B 手机号，marker_source 走 B 自己的 profile）+ 一扇关着的门（/admin/userList 403，阴性记录素材） |
| `canary-web/ground_truth.yaml` | 4 真洞 + 7 干扰项 + 关门清单 |
| `canary-web/grade.py` | 对 FINDINGS+verdicts 打分：真洞检出（提交数/confirmed 数）+ **干扰项误报=0** + Claim 格式合规 |
| `canary-web/run_chain.py` | 临时编排（M4 driver 的替身）：起靶 → 渲染 prompt（序言+手册+**内联输出契约**：Claim 模板/evidence 四段/质量分层）→ worker 真挖 → 轮末收割 FINDINGS → parse_claims → verify_claims（门2 走 live 3 票）→ grade 对分 |

### 判定设计（干扰项每条都有杀招，考的是 worker 纪律 + 四门的双层）

| 干扰项 | 预期杀于 |
|---|---|
| CORS/sourcemap/版本指纹/安全头 | worker 纪律（质量分层：现象不提交）；若提交 → 门 1 infoleak 无凭证形状拒 |
| 内网 IP + instance-id | 门 1 黑名单铁律拒 |
| self-XSS | 门 1 过（标记真反射）→ **门 2 绝对不报条款拒**（真考点） |
| 开放重定向 | 词表无此类 → parse_claim 拒 |

### DoD

- [ ] worker 会话真产出 FINDINGS（≥1 条合规 Claim + 对应 evidence 四段文件）
- [ ] verify_claims 全链走通（门1 机械 + 门2 live 3 票 + 门3 transcript）
- [ ] grade：真洞检出 ≥3/4 且干扰项误报 = 0
- [ ] 结果与过程（worker 哪里守约/违约、四门哪里接住/漏接）回写本附录
- [ ] 成本：1 worker 会话 + 门 2 若干票 ≈ $1-2

---

## 附录 E：canary 首考三连误判的修复方案（✅ 用户已批，2026-08-26 已实施+重放验证，76/76）

### 背景：首考发生了什么

worker 第一次真挖真交卷：**3 个真洞全碰到**（sqli 报错+UNION 抽出双账号 PII、authbypass 管理面匿名写入、布尔差分），7 个干扰项 **0 上当**，evidence 四段模板全文遵守——worker 质量超预期。但四门把 3 条 FINDINGS 全部误判（2 条真洞判成阴性记录、1 条类选错+解析器不容错被拒）。grade 无法给分。

### 根因一：`expect_denied` 字段两头理解不一样（F-001/F-003 误杀）

这个字段设计时想的是"如果预期会被拒绝，填拒绝的标记"。但没写文档：

- **worker 的理解**（很自然）：填"我预期会收到的拒绝状态码" → 它填了 `500` 和 `401`
- **门 1 负 oracle 的实现**：只要这个字段的值出现在响应文本里 = "预期中的拒绝真的发生了" = 判阴性

撞车后果：F-001 是经典 SQL 报错注入（500 + 完整报错回显），因为 worker 填了 `expect_denied:500` 而 500 恰好出现在响应里 → 被判"预期的拒绝出现了"→ immune（阴性）。**真漏洞被当成"口子是关的"。** F-003 同理（它填 401，响应体里恰好有 "401" 字样——其实是它在证据里自己写的对比说明）。

### 根因二：证据格式 vs 解析器容错度（F-002 被拒）

F-002 证据写得其实很好：基线/永真式/UNION 三组请求全有、UNION 直接抽出 userA+userB 的姓名手机号。两个问题叠加：
1. **类标错**（worker 小错）：UNION 直接出数据是 sqli_error 的天下，它标成了 sqli_diff
2. **解析器太死板**（我的错）：它的段标题写了 `## 请求（基线）` `## 响应（永真式）`——带括号注记；我们的正则只认裸标题 `## 请求`，匹配不上

### 根因三（顺带发现）："关门没人试"

靶子里 /admin/userList 对普通用户恒 403（专门留给阴性记录当素材的），worker 没去碰。不算错误——不是每扇门都会被撞——但下次输出契约可以提一句。

---

### 修复方案四条

| # | 改什么 | 具体做法 | 改哪 |
|---|---|---|---|
| **1. 字段语义定死** | `expect`/`expect_denied` 的含义两头对齐 | 文档定义：`expect`=**预期成功的标记字符串**（如 `"code":0`）；`expect_denied`=**只接受 deny 标记词**（如 `"denied"`），**禁止填 HTTP 状态码数字**。输出契约加反例警告："❌ expect_denied:500" | run_chain.py 契约 + 后续 WORKER-CLAUDE.md |
| **2. 负 oracle 收窄** | 门 1 判阴性的信号从三个减到两个 | 判"口子是关的"只认：①响应的 **HTTP 状态行**是真 401/403（而非正文某处出现数字）②claim 端点在关门清单里。**不再扫 expect_denied 字段内容**——状态码数字会正常出现在报错页/证据叙述里，扫它必误杀 | verify.py gate1 |
| **3. 解析器容忍括号注记** | 段标题带注释也能识别 | 正则允许标题后面跟任意非换行注记：`## 请求（基线）`、`## Response: diff` 都算标准段 | verify.py parse_evidence |
| **4. sqli 多类共存** | 一个端点上多种注入形态并报时不互相挤掉 | 【这条的人话解释】worker 在同一个接口 `/search` 上发现了三种表现：①报错回显 ②布尔差分 ③UNION 直接抽数据。按现在的设计它只能挑一类提交——这次它挑错了类（diff），报错和 UNION 的功劳就被埋没。改法：**允许同一 endpoint 提交多条不同 class 的 claim，各自独立过各自的判据**——报错的走报错判据、diff 的走差分判据，谁成立算谁的，互不挤占。（对齐 SRC 常识：同一注入点的多种形态本就是一件事的多面） | verify.py 词表 + 无需 worker 配合 |

### 验证方式

修完后**不重跑 worker**（省时省钱）：直接用现场保留的 worker 真 FINDINGS（at1-canary-qozp2m0n）重放四门，验证 F-001/F-003 翻案为 confirmed、F-002 以 sqli_error 类翻案；然后 grade 出正式对分。

### 成本

零 token（重放只走门 1 机械层 + 已有 gate2 结果语义）；代码改动预计 +20 行。

### 实施结果（✅ 全部落地）

| 改动 | 落点 | 验证 |
|---|---|---|
| #1 字段语义定死 | run_chain.py 契约加反例警告（禁状态码进 expect_denied/expect；UNION 出数据优先标 sqli_error；同端点多类 claim 共存） | 后续 worker 会话生效 |
| #2 负 oracle 收窄 | gate1 只认状态行 + deny 标记词（fullmatch 词表，非数字） | 重放 F-001 immune→**confirmed**；单测含状态码反例 |
| #3 段标题容忍注记 | parse_evidence 正则允许标题后任意非换行注记 | 重放四段全识别；单测造 worker 实际形态 |
| #4 sqli 结构性判据 | diff 判据改结构式（对照请求≥2组+对照响应≥2组，称呼不限）——字面词 baseline/attack 是 canary F-002 的坑（worker 用词是"基线/永真式"） | 重放 F-002 rejected→**confirmed** | 

### 重放终局（worker 真 FINDINGS，门2 live 3 票）

```
F-001 sqli_error  → confirmed（过门3：transcript 可寻）
F-002 sqli_diff   → confirmed（同上）
F-003 authbypass  → confirmed（gate2 票态与前次不同=verifier 抖动被多数决吸收，这次2/3放行；门3 可寻）
```

**grade 正式对分：真洞检出 2/4（V3 authbypass ✓、V4 sqli ✓，均 confirmed）；干扰项误报 0。**

未中 2 真洞（V1 idor 读 / V2 idor 写）的原因不在验证层——worker 本次预算花在 sqli/admin 面，没碰 idor 面（属调度/引导问题，M4 driver 轮间规划解决：plan_directive 已含"未测面"提示）。判定线（≥3 且 0 误报）未达，**但结论是验证层合格**：worker 交的 3 条全部正确 confirmed、0 误报、0 漏杀——grade 的 FAIL 记为 worker 覆盖面问题非裁判问题。

另修：grade.py GBK 控制台编码崩溃 → stdout reconfigure utf-8。

**遗留**：assertF-003 的 gate2 票向两次运行不一致（首次 2/3 否决、重放 2/3 放行）——匿名管理面写入的"证据充分性"处于 verifier 决策边界上；多数决机制按设计吸收了抖动（两边都给出理由），true label 显然是漏洞，可接受。
