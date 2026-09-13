# AT1 Phase 5.5 图字段治理批（字段设计 / 图利用 / worker 用法 + 活契约落地）—— ✅ 已竣工（2026-09-04）

> **状态**：五项全部施工完成并回执（5 commits，190 测试绿）。本文档转**竣工档案**，不再更新；开放项的家 = `phase5-问题登记与决策.md`。
> **回执**：#1 chains 常设边库 ✓（含一次性迁移）｜#2 verify_fact 接线 ✓（**施工补强：轮窗记账**——transcript 跨轮追加使整卷检查空转，语义诚实定为"最近仍在观测"+对称自愈）｜#3 combines ⚡ ✓｜#4 STATE.md 只读句 ✓｜#5 blackboard.schema.json ✓（190 绿，满配快照一次过）。
> **日期**：2026-09-04。上游：`at1-黑板schema.md`（v2.1.1，语义参照）｜`phase5-后期fix.md`（残留清单）。
> **治理定调（用户拍板）**：结构真相 = `src/board.py` + `blackboard.schema.json` 双件套（同步由测试锁）；`docs/at1-黑板schema.md` = **施工参照文档**（语义/理由/迁移规则），历史化，不再追字段机械同步。
> **回复方式**："五项全做 / 砍 X / 某项方案改"。

---

## 0. 总览

| # | 项 | 性质 | 成本 | 依赖 |
|---|---|---|---|---|
| 1 | 常设 chains 列表修"边蒸发" bug | **bug 修复** | ~30min | — |
| 2 | verify_fact 接线（transcript 复现抽验） | 死字段激活 | ~40min | 复用 C-5 hay 基建 |
| 3 | combines 组合路径显式浮现 | 图利用增值 | ~20min | #1 |
| 4 | CLAUDE.md：STATE.md 只读声明 | 契约清晰度 | ~5min | — |
| 5 | blackboard.schema.json + 契约测试 | 活契约落地 | ~1h | #1（schema 含修好的结构） |

全做 ≈ 3h。顺序 1→2→3→4→5，每项独立 commit。

---

## 1. 病灶修复：观察者的边会蒸发（bug 级）

**病灶**：`update_session_intel` 每轮**整体覆盖** dict；B4 把观察者产的 chains 存进了 `session_intel.chains`，`_all_chains()` 从那里读。时间线：

```
轮 N 结束 → 观察者判重产出 same_root 边 → session_intel → 渲染 ✓
轮 N+1 结束 → 观察者再跑 → update_session_intel 整体覆盖 → 轮 N 的边【无声消失】
```

worker 下轮看不到上轮的关联（接力有损），M5 画的图不完整。违反 schema §2.5"判重顺产 same_root 边"的本意——边应是**黑板一等公民**，不是会话临时产物。

**修法**：
- 黑板新增常设 **`self.chains: list[dict]`**：`add_chains(items, origin)` 入口——逐条 `normalize_chain` 校验 + 按 `(rel, frozenset(refs))` 去重 + origin 记录（worker/observer）+ 进 save/load 快照
- `_apply_observer_governance`（driver）：session_intel 里的 chains 改走 `add_chains(origin="observer")`，不再依赖 session_intel 存续
- `_all_chains()` / `render_yaml_layer` 改读常设列表（findings/directions/facts 挂载的 chain 照旧聚合）
- schema 语义（md 参照）：chains 从"session_intel 子字段"改记为"黑板顶层一等对象"

**验收（测试 ~4）**：①轮 N 入边→轮 N+1 覆盖 session_intel→边仍在；②去重（同 rel+refs 不重复入列）；③非法 rel 降级 note-only 与 worker chain 同规；④持久化 roundtrip。

## 2. 死字段激活：verify_fact 接线（provenance 的消费者）

**病灶（两层）**：
1. `verify_fact` 全仓零调用（grep 仅 pycache）；`provenance` 字段因此是死重——与当初被审计处死的 conf 同罪，躲在"v2 接线"名义下。
2. **功能缺口**：事实不会衰老——轮 1 抽取的 observed 事实到轮 5 仍以最高置信渲染，哪怕目标已改版/凭证已轮换/端点已下线。confidence 是决策货币却永不衰减。

**修法（零网络、复用 C-5 hay 基建；语义 = "最近仍在观测"而非"仍然为真"）**：
- **轮窗记账**：`offsets["transcript_rounds"]` 记每轮 transcript 起始字节偏移——transcript 是跨轮追加的，整卷查"出现过"对被动事实永远为真（它本来就是从流里抽的，检查会空转）；**只验最近一轮窗口内是否再现**
- 对象筛选：仅**被动抽取类**（provenance 以 `round` 开头）；显式结论类（identity_model 等 prose）不检——结论不该要求在流里逐字出现；**凭证 provenance 照旧冻结**（会话守卫语义不变）
- 判定（对称自愈）：最近窗口内 value 可寻 → 保持/恢复 observed；不可寻 → observed 降 inferred（不删除）；`fact["last_verified_round"]=N` 防重复验
- 语义诚实声明：机械验不了"仍然为真"（那要重放，已冻结）——能机械验的是"最近还在观测"。最近没再见到 → 缓降一位（渲染排序轻降，无硬伤害）

**接线点**：driver 轮末（STATE.md 投影前）；`verify_fact` 旧 `run` 回调签名连同其从未存在的调用方一起退役 → `verify_fact_against_transcript(bb, hay_pair, round_no)`。

**验收（测试 ~5）**：①最近窗口内再现→保持 observed；②窗口内不可寻→observed 降 inferred；③凭证 provenance 冻结；④显式结论类跳过；⑤降级后下轮窗口再现→恢复 observed（自愈）。

## 3. 图利用：组合路径显式浮现

**动机**：`rel=combines` 且 refs 指向 **open/blocked 方向**的边 = "SSRF+redis 凭证可组合成 RCE 路径"这类**待试攻击链**——exploit 阶段最值钱的信号，现在埋在边列表里与其他边无差别。

**修法**：`_render_chains_block` / `render_yaml_layer` 中，combines 边若 refs 含 `in_progress/open/blocked` 方向 → 渲染加前缀 **"⚡组合路径待试"**（yaml 加 `hot: true`）；STATE.md 该段排方向层之后紧邻位置不变（已在关联段）。

**验收（测试 ~2）**：①combines+活方向 → 带 ⚡/hot 标记；②combines 指向 done 方向或纯 findings 边 → 无标记。

## 4. 契约清晰度：STATE.md 只读声明

**修法**：WORKER-CLAUDE.md §3 末尾追加一句：
> **STATE.md 是系统投影（每轮覆盖写，只读）**——你对图的写面只有 DIRECTIONS/FINDINGS/FACTS（evidence/ 佐证）。改 STATE.md 的内容下轮会被系统重写，白费力气。

**验收**：test_scaffold 契约文本断言 +1。

## 5. 活契约落地：blackboard.schema.json + 永久契约测试

**治理结构（用户定调）**：

| 文件 | 角色 | 同步机制 |
|---|---|---|
| `src/board.py` | 结构与行为的**执行真相** | ←→ schema.json 双向，测试锁 |
| `blackboard.schema.json`（根目录） | 结构的**机器契约**（JSON Schema draft 2020-12） | 契约测试：满配黑板快照 validate |
| `docs/at1-黑板schema.md` | 语义/理由/迁移规则的**施工参照**（历史化） | 不再追字段机械同步 |

**schema 范围**：
- **严格**：facts（kind 7 枚举/confidence 2 枚举/无 conf 禁选 `not.required`/chain 形态 refs pattern `^[FD]-`）、immune（4 字段）、findings（id/assessment 4 枚举/evidence_verified/param_verified·response_verified 可选）、directions（status 4 枚举/id `^D-`/source 2 枚举/comment 必有）、**chains（新顶层一等对象）**
- **宽松**：offsets/ledger/config/session_intel（`additionalProperties: true`——观察者输出逐字段容错风格，校严打架）
- 顶层 required 快照九键 + chains

**契约测试**（`tests/test_schema_contract.py`）：构造满配黑板（每对象每枚举值各一）→ save → `jsonschema.validate`；**负例三个**：fact 带 conf → 红；direction status=archived → 红；chain rel=invented → 红。依赖 `jsonschema`（纯 Python，venv 安装）。

**验收**：正例过/三负例红；`pip show jsonschema` 在 venv；schema 文件含第 1 项修好的 chains 结构。

---

## 不做（本轮边界）

- 图投影格式（nodes/edges）——M5 触发
- fact→fact 边——v2 图化
- worker 用法的进一步设计——写 5 面/读 2 面结构无病灶，三个开放问题（摘要够不够/漏写率/接方向率）全部等真实环境数据，已挂验收指标

## 依赖与风险

| 项 | 风险 | 缓解 |
|---|---|---|
| #1 chains 一等化 | session_intel.chains 旧数据迁移 | `_load` 时迁移进常设列表（一次性） |
| #2 verify_fact 改签名 | 外部调用方（已查实为零） | grep 复核 |
| #5 jsonschema 依赖 | venv 安装失败 | 备选手写 80 行校验器（不推荐） |

---

*拍板位：五项全做（推荐）？或砍/改某项。拍后顺序 1→2→3→4→5，每项独立 commit，全量 pytest 绿收口。*
