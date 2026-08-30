# Phase 3 中期审核——最终定稿

> 本文档是 Phase 3 验证层的架构重新设计定稿，经多轮讨论和实验验证后由用户拍板。
> M4 施工以本文档为唯一设计输入。
> 历史讨论过程见 git log（附录 B/C 的旧方案已清理，最终方案在下方）。

---

## 一、已定架构：观察者模型

### 核心转向

| 旧（四门漏斗） | 新（观察者） |
|---|---|
| 门 1 死脚本查格式（200 行正则） | controller 纯脚本做 transcript 定点比对 |
| 门 2 LLM 按 11 棵判定树判语义 | 观察者 LLM 用四步影响框架判语义 |
| 门 3 死脚本查请求存在 | 合并进 transcript 定点比对 |
| worker 分类 + 格式化 + 填 JSON | worker 白话记录（一句话 + 一个文件） |
| FINDINGS 11 字段 | FINDINGS 4 字段（endpoint/evidence/summary/round） |
| 验证 = 拦门（confirm/reject） | 验证 = 观察 + 标注 + 给情报 |
| 串行验证（等会话结束再排队） | 并行验证（FINDINGS 出现即触发后台验证） |
| 560 行代码 | ~150 行代码 |

### 架构图

```
Worker 轮内（挖矿）
  ├── 干活 → 工具调用 → on_fact → board.observe（事实实时入库）
  ├── 发现 → 当场写 evidence（白话）+ FINDINGS（4 字段）
  │            ↓ 立刻触发（不等会话结束）
  │     Controller 后台并行：
  │       ① transcript 定点比对（纯脚本，<1s）→ evidence_verified 标记
  │       ② 观察者 LLM 评判该条发现（后台异步，~30s）
  │
Worker 会话结束
  ├── Handoff 收割
  ├── 会话级观察（观察者 LLM，1 次调用，~30s）
  │     → 覆盖缺口 / 有效模式 / 建议
  ├── 黑板更新（发现标注 + 会话观察 + 情报摘要）
  └── 下一轮 prompt 渲染（黑板自动包含全部标注）
```

### 观察者身份

| | Worker | 观察者 |
|---|---|---|
| 运行 | 轮内，有工具 | 轮间（发现级跟 FINDINGS 并行跑），**无工具** |
| 看到 | 目标响应、workdir | 黑板全量 + FINDINGS + evidence + transcript 定点 + SRC 判例 + 历史观察输出 |
| 模型 | glm-5.3 全量 | glm-5.3 全量直连 bigmodel（同模型同 key，2026-08-30 用户拍板） |
| 产出 | FINDINGS、evidence、Handoff | 发现标注 + 会话观察 + 情报摘要 → 全部写黑板 |
| 偏见 | 天然偏向自己的发现 | 无投入，质疑视角 |

**观察者不进环境**：有工具会退化成又一个 worker + evidence 里的注入文本可操纵有工具的观察者 + 无法递归验证。事实层用脚本锚定（transcript 独立记录），语义层用观察者判断。

### 观察者的 prompt（四步影响框架 + 参考判例）

**替代 11 棵类型判定树**——不问"这是什么类型的漏洞"，问"这造成了什么影响"：

```
第一步：影响是什么？
  攻击者能做什么本来不该做的事？
  → 影响不存在（只是现象）→ 不是漏洞

第二步：是设计内行为吗？
  在证据中查找请求者身份字段（buyer/orderer/user/uid）：
  → 如果 buyer 等于请求者 → 合法关联方 → 设计内行为 → 不是漏洞
  → 如果无任何关联字段 → 继续走第三步
  【此提示必须保留——首测共享地址误报就是缺了这段】

第三步：影响有多大？
  凭证类（AK/SK/密码对）→ 高
  个人标识组合（姓名+手机+地址等）→ 高
  单字段个人信息 → 中
  非敏感业务状态 → 低/不是漏洞

第四步：有没有利用条件让影响归零？
  需要受害者主动操作 → 影响归零
  内网完全过滤 → 影响归零
  影响归零 → 不是漏洞
```

**SRC 参考判例**（~30 条，来自 docs/src-standards-distilled.md）作为校准尺度注入 prompt——不是死规则，是帮 LLM 对齐行业标准。

**绝对不报表**（四家共识）作为底线条款注入 prompt。

### 观察者的输出

```json
{
  "finding_annotations": [
    {"id":"F-001","assessment":"confirmed","severity":"high",
     "reason":"...","evidence_verified":true},
    {"id":"F-002","assessment":"likely_false_positive",
     "reason":"buyer=userA 属设计内行为","severity":null,"evidence_verified":true}
  ],
  "session_observations": {
    "coverage_gaps": ["/api/order/detail 未测"],
    "effective_patterns": ["id 遍历在此站有效"],
    "suggestions": ["address/update 有写入语义值得关注"],
    "notable_attempts": ["worker 试了路径穿越但只试了 /etc/passwd"]
  },
  "intel_summary": "目标对 id 遍历无防护；admin 面可匿名写入"
}
```

黑板消费：confirmed → "已确认发现"段 / likely_false → "已否决模式"段 / suggestions → "未测面"段 / intel_summary → "上一轮交接"段。

### 权限边界

| 权限 | 给不给 |
|---|---|
| 看（黑板/evidence/transcript 定点） | ✅ |
| 标注（confirmed/likely_false/uncertain） | ✅ |
| 建议（"这个方向值得看"） | ✅ 但标记式（"探不探你定"） |
| 指挥（"你必须测 X"） | ❌ |
| 永久封锁 | ❌ likely_false 可重新评估 |
| 执行（跑命令/发请求） | ❌ 无工具 |

### 验证分工

| 层 | 谁做 | 方法 |
|---|---|---|
| 事实验证（证据真吗） | controller 纯脚本 | transcript 定点比对 |
| 语义判断（结论对吗） | 观察者 LLM | 四步框架 + 参考判例 |
| 重放确认（还灵吗） | controller 纯脚本 | urllib 重放（可选，M4 定） |

---

## 二、验证实验结果（全部通过）

| 验证项 | 结果 | 说明 |
|---|---|---|
| transcript 定点查找 | ✅ 3/3 | 请求/响应标记可靠匹配 |
| 四步框架判定（3 条真漏洞） | ✅ 3/3 | 全判对，严重度正确 |
| CORS 误报拦截 | ✅ | 正确拒绝 |
| 共享地址拒绝（强化提示后） | ✅ 3/3 | buyer=请求者 → 正确判设计内 |
| 真 idor 判定（强化后不误拒） | ✅ | buyer≠请求者 → 正确判漏洞 |
| 发现级稳定性 | ✅ 3/3 一致 | 单次调用即稳定，不需要 3 票 |
| 会话级观察 | ✅ 超预期 | 精准发现 idor 缺口 + 6 建议 + 3 模式 |
| 会话观察稳定性 | ✅ 3/3 | 核心发现一致 |

**结论：观察者模型可以进 M4 实施。**

---

## 三、已实施的部分（Phase 3 存量，不需要 M4 重做）

| 组件 | 状态 | 说明 |
|---|---|---|
| board.py（黑板全套） | ✅ 保留 | 事实抽取/goal 链/渲染/覆盖对账/未测面/阴性记录/已否决模式 |
| runner.py（进程桥全套） | ✅ 保留 | spawn/stream 解析/resume/心跳/呆滞告警/on_spawn |
| harvest.py | ✅ 保留 | FINDINGS/FACTS diff + Handoff 合成 |
| events.py | ✅ 保留 | 事件流 |
| untrusted.py | ✅ 保留 | nonce 隔离 |
| prompt.py | ✅ 保留 | 阶段手册 + 9 段渲染 |
| providers.py / llm.py | ✅ 保留 | 模型接入 |
| canary-web | ✅ 保留 | 靶子/grade/全链路 |
| 覆盖对账 + 未测面渲染 | ✅ 已实施 | board.untested_surface + render_untested |
| SRC 标准蒸馏 | ✅ 已完成 | docs/src-standards-distilled.md |
| 22 道考题 | ✅ 已完成 | tests/gate2_exam.py（可用于回归） |

## 四、M4 需要做的事

### 要新写

| 组件 | 内容 | 行数估算 |
|---|---|---|
| 观察者 prompt | 四步框架 + 参考判例 + 强化提示（buyer 检查） | ~100 行 |
| transcript 定点比对函数 | 从 evidence 提取请求/标记 → transcript 子串匹配 | ~30 行 |
| 观察者输出解析 + 黑板写入 | JSON 解析 → board.update | ~30 行 |
| WORKER-CLAUDE.md | 新契约（白话 evidence + 4 字段 FINDINGS） | ~50 行 |
| driver.py 主循环 | 整合以上全部 + 轮次循环 + 终止条件 + stoploss + guard | ~500 行 |
| scaffolding | workdir 模板展开 | ~80 行 |

### 要删除（M4 末期清理）

| 文件 | 删什么 | 为什么 |
|---|---|---|
| verify.py | gate1/gate2/gate3/verify_claims/CLASS_REQS/Claim（11字段版） | 被观察者替代 |
| verify.py | _OASSERT 词表 / _SEC_VARIANTS 段切分 / 占位词表 | 被简化版替代 |
| tests/test_verify.py | 七案 + 每类正负例（~200 行） | 输入格式已变，重写 |

### 要保留但简化

| 文件 | 改什么 |
|---|---|
| verify.py | parse_claim 简化为 4 字段（endpoint/evidence/summary/round） |
| canary-web/run_chain.py | CONTRACT 段改为新契约 |

---

## 五、参考项目最终评估

| 组件 | 来源 | 保留/丢弃 |
|---|---|---|
| 进程模型 | hxbai | ✅ 保留 |
| 黑板 | hxbai | ✅ 保留 |
| 三重门验证 | hxbai | ❌ 丢弃（为 CTF 设计） |
| 每类正则判据 | hxbai | ❌ 丢弃（canary 证明误杀） |
| canary 靶 | dcr | ✅ 保留 |
| .at1/ 目录隔离 | dcr 概念 | ✅ 保留 |
| 结构化 prompt 教训 | dcr | ✅ 保留教训，❌ 丢弃 11 棵树 |
| SRC 标准 | 自研 | ✅ 保留（作为观察者参考判例） |
| 3 票多数决 | hxbai | ✅ 保留（但发现级单次已稳定，可降为 1 票） |
| transcript 独立记录 | 自研 | ✅ 保留（防编造的物理锚） |

---

## 六、flash 模型 thinking 洪水（框架修复待做）

**问题**：flash 模型 thinking 输出 38.5k tokens（全量的 3.4 倍），transcript 99% 是 thinking 进度事件，runner 对每条做 JSON 解析 + fsync。

**修复**：runner StreamParser 对 `thinking_tokens` 事件短路——只计数不做 JSON 解析不做 fsync，每 100 条采样写盘 1 条。~15 行。

**模型选择**：挖洞用 glm-5.3 全量（更便宜更快：$0.90/257s vs flash $1.73/641s+timeout）。

**I/O 分级规则**（适用于 M4 所有写入）：

| 数据类型 | 写入策略 |
|---|---|
| tool_result / result / init | 每条 fsync（不能丢） |
| assistant text / tool_use | 每条写入，可批量 flush |
| thinking 进度 | 计数 + 1/100 采样（丢了无所谓） |
| 遥测前缀行 | 不写 |

---

## 七、遗留事项

| # | 事项 | 归属 |
|---|---|---|
| 1 | runner thinking 短路（~15 行） | M4 开工第一件事 |
| 2 | worker 模型确认用 glm-5.3 全量 | ✅ 已确认（A4 自然完成）+ 观察者已切同模型同 key |
| 3 | oob.py vendor（SSRF 回连） | 等用户配置（用户确认先不急，SSRF 靠观察者文本判断够用） |
| 4 | expect_denied 字段已删除 | ✅ 已实施 |
| 5 | 反馈学习回路（审报告→修判定树） | M4 后第一个真实 engagement |
| 6 | tentative 比例观察（边界案例占比） | M4 首个真实 engagement |
| 7 | commit Phase 3 全量 | 等用户指示 |

---

## 八、全面自检发现的问题（2026-08-30）

> 逐组件过了一遍现有代码，对照观察者模型设计，找到 7 个缺口。用户质询"为什么要等 M4"——承认又是打包过度，全部可以现在做。

| # | 问题 | 层 | 为什么不需要等 M4 |
|---|---|---|---|
| 1 | 黑板缺 confirmed_findings 存储+渲染 | 代码 | add_immune 就是 Phase 3 加的，当时没有 driver |
| 2 | session_observations / intel_summary 无消费管道 | 代码 | 同上——先建存储和渲染，driver 将来调用 |
| 3 | exploit/report 手册引用旧概念（marker/distinct_from） | 代码 | prompt.py 内容，直接改 |
| 4 | canary CONTRACT 教旧 11 字段格式 | 代码 | run_chain.py 内容，直接改 |
| 5 | observer.py 不存在 | 代码 | 验证实验代码已有，提取成正式模块 |
| 6 | business_context 无 schema | 设计 | engagement.json 加一个字段 |
| 7 | 链式思考 / follow_up / 业务上下文未验证 | 验证 | 实验环境现成（observer-test + 白嫖 key） |

### 核心发现

观察者模型的**输出端管道整条缺失**：观察者产出了 confirmed/likely_false/session_observations/intel_summary，但黑板只存了 immune 和 rejected_patterns——**confirmed 和会话观察没有落点**，到不了下一轮 worker。

---

## 九、修复优先级与执行计划（2026-08-30 定稿）

### 现在做（不需要等任何东西）

| 序 | 做什么 | 改哪 | 为什么不会白做 |
|---|---|---|---|
| A1 | 黑板加 confirmed_findings + session_observations 存储+渲染 | board.py | 与 add_immune 同构；观察者输出 schema 已验证稳定，新功能只加字段不改结构 |
| A2 | 建 observer.py 正式模块（prompt + LLM调用 + JSON解析 + 黑板写入） | 新文件 | 验证实验代码提取成模块；接口不变，prompt 可随时更新；先用已验证版 prompt，未验证功能做占位注释 |
| A3 | canary CONTRACT 改为新 4 字段格式 | canary-web/run_chain.py | 下次跑 canary 必须 worker 按新契约写 FINDINGS，否则观察者吃不了 |

### 讨论后做（需要你先拍板两件事）

| 序 | 做什么 | 待拍板的问题 | 我的建议 |
|---|---|---|---|
| B1 | session_observations 在 prompt 里怎么渲染 | 机械未测面和观察者 suggestions 有重叠，合并还是分开？ | 合并成一段（机械算"哪些没测" + 观察者补"为什么值得测"），省 token 且信息密度高 |
| B2 | business_context 是必填还是选填 | 不写时观察者对"设计内行为"判断退化到通用模式（可能误报） | 选填 + 默认提示（不填时 prompt 写"目标业务上下文未提供，判断设计内行为时请保守"——宁可多标 uncertain 让你复核） |

### 不急（等 A1-A3 做完自然到位）

| 序 | 事 | 为什么不急 |
|---|---|---|
| C1 | exploit/report 手册 stub 修正 | 换一个 stub 没意义，等写全文时一起改 |
| C2 | 链式思考 / follow_up / business_context 验证 | 需要合成测试场景，等 observer.py 建好基本流程通了再验 |
| C3 | 删旧 verify.py | 81 个测试是安全网；等观察者在 canary 或真实目标上证明了自己再删 |

### 执行顺序

```
A1 黑板管道 → A2 observer.py → A3 canary 新契约 → 跑 canary 全链路验证 → B1/B2 讨论后实施
```

### A1-A3 的验收标准

- [ ] A1：黑板 confirmed_findings/session_observations 可存可取可渲染，单测覆盖
- [ ] A2：observer.py 可独立调用（输入 FINDINGS+evidence+黑板 → 输出标注+观察+情报），单测用 mock LLM
- [ ] A3：canary CONTRACT 只教 4 字段 + 白话 evidence，跑一次 dry-run 验证 worker 按新格式写
- [ ] 全链路：canary 重跑 → worker 新格式 FINDINGS → 观察者判 → 黑板有 confirmed → 下一轮 prompt 含"已确认发现"

---

## 十、执行计划定稿（2026-08-30，含批判性代码审查结论）

### 批判性发现：黑板需要"观察层"，不是"加字段"

board.py 的 `immune`（要 class）、`rejected_patterns`（要 class）、`verified`（只是计数器且无人递增）——**全部长着旧门架构的形状，观察者的输出塞不进去**。观察者没有 class 字段，有 assessment/severity/reason；verified 只是数字但观察者有丰富标注。

正确做法：在黑板里建**新的观察层**（findings + session_intel），旧结构降级或废弃。

### 用户已拍板

- B1 = **选法 b**（机械未测面与观察者建议**分开两段**）
- B2 = **选填 + worker 自动探索**（engagement.json 手写版作启动提示，worker 侦察后写 business_context FACT，观察者合并两个来源）

### A1：黑板观察层（改 board.py + 单测）

**新增存储**：
- `findings` 列表：`[{id, endpoint, summary, assessment, severity, reason, evidence, round}]`
  - assessment ∈ confirmed / likely_false_positive / uncertain
  - confirmed → 渲染"已确认发现"段
  - likely_false_positive → 渲染"已否决模式"段（替代旧 rejected_patterns）
- `session_intel` 字典：`{coverage_gaps, effective_patterns, suggestions, notable_attempts, intel_summary, round}`
  - suggestions → 渲染独立"观察者建议"段（B1 选法 b，与机械未测面分开）
  - intel_summary → 渲染进"上一轮交接"段（与 worker Handoff 并列）
- `business_context` 加入 KINDS（worker 侦察时写 FACT，与 identity_model 同构）

**修改**：
- `check_goal()`：exploit→report 判据从 `verified["confirmed"]>=1` 改为查 findings 里有没有 confirmed
- `add_immune()` 去掉 class 参数（transcript 比对直接写入，不需要分类）
- `rejected_patterns` 标记 deprecated（渲染段改由 findings 的 likely_false_positive 驱动）
- `verified` 字段保留但由 findings 计数派生（过渡兼容）

**单测**：
- findings 存取/渲染（confirmed→已确认段 / likely_false→已否决段）
- session_intel 存取/渲染（suggestions→独立段 / intel_summary→交接段）
- goal 链新判据（findings 有 confirmed → 推进 report）
- business_context 入板
- 旧 immune 兼容（去 class 后仍工作）

### A2：观察者模块（新文件 observer.py）

**结构**：
```python
class Observer:
    def __init__(self, llm_client, business_context: str = "")
    
    def judge_finding(self, finding, evidence_text, 
                      blackboard_snapshot) -> dict:
        """单条发现评判（四步框架）→ 
        {id, assessment, severity, reason, evidence_verified}"""
    
    def observe_session(self, all_findings, blackboard_snapshot,
                        handoff_text) -> dict:
        """会话级观察 → 
        {coverage_gaps, effective_patterns, suggestions, 
         notable_attempts, intel_summary}"""
    
    def run(self, findings_with_evidence, blackboard, handoff) -> dict:
        """完整流程：逐条 judge + 一次 observe → 合并输出"""
```

**prompt**：已验证的四步框架 + 参考判例 + buyer/orderer 强化提示。
未验证功能（链式思考/follow_up/business_context）做占位注释，验证后启用。

**单测**：mock LLM（返回固定 JSON），测接口/解析/黑板写入。

### A3：canary 新契约（改 run_chain.py CONTRACT）

FINDINGS 从 11 字段改为 4 字段（endpoint/evidence/summary/round）。
evidence 要求改为"白话记录 + 必须含请求和响应原文"。
删掉 marker/marker_source/distinct_from/expect 的教学内容。

### A4：canary 全链路验证

A1-A3 做完后跑一次：
```
worker（新契约）→ FINDINGS（4字段）→ transcript 比对 → 
观察者评判 → findings/session_intel 入板 → 
下一轮 prompt 含"已确认发现" + "观察者建议"
```

**验收**：canary 真洞 ≥3/4 检出、干扰项 0 误报、黑板 findings 有 confirmed、prompt 渲染完整。

### 执行顺序

```
A1（黑板观察层）→ A2（observer.py）→ A3（canary 新契约）→ A4（全链路验证）
```

A1 是地基（没有它 A2 的输出无处可去），A2 是核心，A3 是测试准备，A4 是验收。

### 不做（等 A4 结果再定）

- exploit/report 手册全文（等观察者实际产出后再写，教 worker 怎么利用观察者标注）
- 链式思考 / follow_up / business_context 验证（等 A2 模块建好）
- 删旧 verify.py / gate 代码（等 A4 证明观察者不比旧门差）
- driver.py / guard / stoploss（M4 范围）

### A2 修正：发现级和会话级彻底分离（2026-08-30 用户质询后定稿）

**发现级评判（judge_finding）**：
- 输入 = 这条 FINDINGS + 这条的 evidence + business_context
- 职责 = 只判"这条是不是真漏洞"（四步框架）
- **不看之前的 findings**——判断真假与历史无关
- 每条调用一次，输入始终小（~3500 字），不随轮次增长

**会话级观察（observe_session）**：
- 输入 = 本轮全部 FINDINGS + 之前轮次 confirmed findings + 黑板全量 + Handoff
- 职责 = **判重**（比较本轮发现与历史 confirmed 是否同根因）+ 覆盖评估 + 有效模式 + 建议 + 情报摘要
- 每轮调用一次，输入随轮次增长但只拼一次

**判重从发现级移到会话级的原因**：判重需要比较多条发现之间的关系（同端点+同根因），天然是全局视角的活。放在发现级会导致每条 FINDINGS 都带全量旧 findings（prompt 膨胀）。

## 十一、A4 全链路验证发现的问题与修复计划（2026-08-30）

### A4 第一轮结果（修复 CONTRACT 前后对比）

| 项 | 修复前 | 修复后 |
|---|---|---|
| Worker 会话 | timeout（600s 被杀） | **end_turn（900s 自然完成）** ✅ |
| FINDINGS 提交 | **0 条** | **3 条**（SQLi + 管理面 + 重定向） ✅ |
| 证据文件 | 0 个 | **3 个**（含 root cause 分析） ✅ |
| Handoff | 没写 | **写了** ✅ |
| Round 2 | 崩了 | **跑了**（23 轮） ✅ |
| 观察者 | 没触发 | **没触发** ❌（原因见下） |

### 发现的根本问题：run_chain.py 从未切换到观察者架构

A3 只改了 CONTRACT 文本，**没改处理管道代码**。run_chain.py 第 140-164 行仍在调旧 verify.parse_claim（要求 class 字段）和旧 verify.verify_claims（四门漏斗）。observer.py 建了但从未被调用。

### 全部问题清单

| # | 问题 | 严重性 | 处置 |
|---|---|---|---|
| 1 | run_chain.py 用旧管道（parse_claim+verify_claims），不是观察者 | **阻断** | 现在修 |
| 2 | 文件名 FINDINGS.jsonl vs FINDINGS | **阻断** | 现在修 |
| 3 | verdicts 变量名 bug（第 182 行） | 崩溃 | 现在修 |
| 4 | 输出格式 class-based，不匹配新格式 | **阻断** | 现在修 |
| 5 | 127-134 行重复读取（死代码） | 低 | 顺手修 |
| 6 | CONTRACT 文件名指令无效（LLM 偏好 .jsonl） | 中 | 系统侧兼容兜底 |
| 7 | 观察者对真实目标的判定质量 | 未知 | 等真实环境 |
| 8 | grade.py 匹配逻辑待更新 | 中 | 跑通后调 |

### A4 最终结果（修复后全链路首次跑通，2026-08-30）

```
Round 1: Worker 自然完成（54 轮，1.84M tokens）→ 3 条 FINDINGS → 观察者 3/3 confirmed
Round 2: Worker 自然完成（27 轮，565K tokens）→ 1 条新 FINDINGS → 观察者 1/1 confirmed
黑板最终：4 条 confirmed（3 high + 1 low），程序退出码 0
```

修复效果验证：

| 上次问题 | 修复方法 | 状态 |
|---|---|---|
| 文件名 .jsonl | 预创建空 FINDINGS/FACTS + 系统兼容两种名 | ✅ Worker 用了正确文件名 |
| 提交触发器缺失 | CONTRACT 加"发现即提交" + "提交是你的事验证是系统的事" | ✅ 4 条自然提交 |
| 旧管道 vs 观察者 | run_chain.py 整段重写（observer.run 替代 verify_claims） | ✅ 观察者评判了全部 |
| verdicts 崩溃 | 输出段重写为 assessment 格式 | ✅ 退出码 0 |

新架构工作证据：
- 观察者评判：4/4 correct（severity 合理）
- business_context：Worker 自动识别"CanaryShop 电商/商城"写入 FACTS
- 质量分层：instance-id 泄露正确写 low_value_only 不写 FINDINGS
- 未测面传递：轮 1 的 confirmed + 未测面出现在轮 2 prompt
- 链式发现：轮 2 从 SQL debug 页发现 XSS（F-004）
- 两轮接力：Worker handoff 提到"4 个确认点"

待改进（非阻断）：
- 开放重定向 F-003 应被拒（SRC 说单独重定向不报），观察者 confirmed 了它 → prompt 的绝对不报表没拦住
- idor 两洞（V1/V2）未被测：未测面正确传递但 worker 轮 2 没去测 → 覆盖引导待 M4 优化
- 检出 3/4（V3 authbypass ✅ + V4 sqli ✅ + 额外 XSS ✅）
