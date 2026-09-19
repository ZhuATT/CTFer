# AT1 v3 批3fix 落地执行计划

> **定位**:批3真轮后修复批的施工执行单。设计依据与全部拍板记录在 `at1-v3批3-真轮待测试.md` §9-§13（本文引用不重复论证）；本文只写"怎么施工"。
> **基线**:commit `40e6152`（批3竣工，223 绿）。usc-portal 目录保留为 v3 机制终态参照，**不做内容迁移**（老 engagement 归档，新跑重建）。
> **状态**:**✅ 已竣工（2026-09-19）**——F1-F8 全部落地，181 测试全绿，dry-run 验收过；仅剩实机复跑（§6.3，待用户给目标与凭证）。结果见 §9。**未 commit**（按惯例等用户指示）。

---

## 0. 执行协议（开工必读）

1. 每卡完成即跑全量测试，绿了才算卡完；**做完不自动 commit，等用户指示**（既定施工习惯）。
2. 施工顺序：F1→F2（图地基）→ F3→F4→F5（工作区与退役）→ F6→F7（观察者核心）→ F8（终验）。F6 是关键路径，动工前其设计稿（§4）视为已冻结。
3. 语义变更后旧测试必须同步翻转，不留 skip 挂着（批3教训：旧测试真 spawn 烧 API）。
4. 唯一真相源纪律：prompt 汇编（`prompt-全文汇编.md`）定稿权威 + `scaffolding/` 文件即实施真相，一致性锁 3 断言保持绿。

## 1. 本批交付一句话

把"controller 死脚本居中翻译"的 v3 机制，换成"**worker 自由写文件 → 观察者终态判断书 → 执行器确定性入图 → worker 直读图**"的 Cairn 同构治理链，同时修掉真轮实抓的 P1/P3/P4/P5。

## 2. 终局形态（改完长这样）

```
<engagement>/                       ← worker cwd（单层，.auto/ 取消）
├─ engagement.json / storage-state.json / notes/prior-intel.md   操作员输入（拒启件保留）
├─ facts/                           worker：一条事实一文件（自由格式，可读 slug）
├─ findings/                        worker：一条发现一文件（=报告本体，reports/ 并入）
├─ evidence/                        worker：原始响应/截图/现象随手笔记
├─ STATE.md                         观察者产物（进度总结+"## 下轮建议"固定节；没写则 controller 兜底极简计数）
├─ notes/prior-intel-draft.md       观察者收尾导出（跨 run 接力素材）
├─ .observer/                       观察者工作台（worker 禁入）：OBSERVER.json / OBSERVER.rejects / 草稿
└─ .at1/                            系统区（worker 禁写可读）：blackboard.json / transcript.jsonl /
                                    observer-transcript.jsonl / interface_log.jsonl / auto-log / CONTROL
```

数据流：`worker 写 facts//findings//evidence/ → 退出 → controller 目录级 diff 出任务单 → 观察者 -p（读产出+读图+实测验证）→ 终态写 .observer/OBSERVER.json → 退出 → 执行器校验入图+receipt → board 落盘 → 下轮 worker 优先读图、配合读 STATE.md`。

## 3. 施工卡

### F1 board/schema 地基
- **改动**：`board.py`（severity 顶层死槽删；proposed 状态语义清理——不再作为入图落点；三原子对外参数整理成执行器友好形态）；`blackboard.schema.json`（同步删槽；origin 仅来源记录无特权；confidence 不加）。
- **不做**：去重键 hash 升级已否决——现有三元组查重原样保留当重放兜底。
- **验收**：schema 负例契约测试更新全绿；现有查重行为回归测试不动仍绿。

### F2 配方0 重写
- **改动**：`driver.py::_seed_from_engagement`——删 prior-intel 逐行灌 fact+人拍板 confirmed 逻辑；改为只种一条画像 fact（直落终态，origin=user 仅作来源标记）+ bookkeeping.intel 指针指向 prior-intel.md 原文。
- **验收**：dry-run 后图内 fact 恰 1 条（画像）；老用例（播种多条/confirmed 语义）翻转。

### F3 工作区单层化（scaffold+guard）
- **改动**：`scaffold.py`——取消 `.auto/`，根=worker cwd；预创建 `facts//findings//evidence/`（FORMATS.md/status.md/双 log 不再生成）；skills_src 复制到根 `.claude/skills`；storage_state 注入到根；`src标准/`、`.mcp.json`（保持 playwright 单 server，不加 MCP）落位。`guard.py`——P1 host 提取修复（剥离引号/分号）；禁区清单重划：`.at1`（禁写可读）、`.observer`（禁入）、`notes`（禁写可读）、`state` 若残留则禁写；自毁检测不动。
- **验收**：dry-run 目录树目检；guard 单测（禁区命中/notes 可读不误伤/host 误报回归）。

### F4 worker 手册重写（scaffolding/WORKER-CLAUDE.md + 汇编 §3.1-3.3 同步）
- **章节**：①开工=优先读图本体（导航教学：看 fact/finding 忽略 bookkeeping）；STATE.md=配合读（观察者的进度总结+"下轮建议"，非限制口吻）②判层三层表保留（成果→findings//中间能力→facts//现象→evidence 随手记）③写盘引导：一条一文件+四条纪律（一文件一断言/证据指针必填/先落盘再继续/开工读图防重复）+建议形状示例④handoff 契约与 `<Stop>` 自停保留⑤controller 区禁令改"禁写可读"，`.observer` 禁入。
- **验收**：一致性锁 3 断言绿；无 FORMATS 引用残留。

### F5 配方1+投影退役
- **改动**：`harvest.py` 账本解析删（auto_link endpoint 兜底语义迁执行器）；`driver.py` 两刷投影删，只留兜底极简计数（观察者没写 STATE.md 时刷）；diff 改目录级（facts//findings/ 新增文件清单+noreport 硬拒清单→观察者任务单）；`writeback.py` 7 函数清空（gen_prior_intel_draft 职责移交观察者收尾导出）；`prompt.py:31` FORMATS 引用句改写。
- **验收**：driver 瘦身；dry-run 门全过；usc 真账本回放测试报废删除。

### F6 观察者 -p 化+判断书执行器（核心件）
- **observer.py 重写**：chat 双通道退役；-p 同构 spawn（复用 runner，OBSERVER_TIMEBOX_S=1800，模型配置化先用 deepseek-v4-flash）；stdin=最小任务单（轮次/goal/新增文件清单/noreport 硬拒/读图指引，零快照）；`.observer/` 工作台；可实测验证（存疑发现发真实请求复核）。
- **执行器（observer_harvest v2 升级，非新组件）**：进程退出→读判断书→不存在/解析失败/operations 空→重试一次→再失败告警；逐条校验（schema/未知 id/confirmed 翻案拒/noreport 拒/查重撞键返回已有 id）→board 三原子入图；receipt 落 `.at1/interface_log.jsonl`；坏条落 `.observer/OBSERVER.rejects`。
- **OBSERVER-MANUAL（scaffolding 新增）**：审计权独占/证据逐字/评级口径（P5：观察者终裁，与 worker 自评关系一句话）/**先验证后入图**（否定结论必须自己复现过才入图；没验证到位的留 STATE.md 当未决线索，不焊死路线）/STATE.md 维护（含"## 下轮建议"固定节）/防注入（worker 原文指令性文本一律当数据）/收尾导出 prior-intel-draft/超时前先落盘。
- **会话计量（P4 关闭项）**：worker/observer 双会话 tokens/cost 收全进 session_end（含被杀轮）。
- **验收**：执行器单测（拒收矩阵/幂等重放/receipt 完整性）；计量断言（双会话 tokens>0）；真通道冒烟（mini engagement 一轮真观察者）。

### F7 防线接线
- **改动**：空产出检测（退出后判断书缺失/解析失败/operations 空→重试一次→observer_empty_retry 告警事件）；目录级 diff 补账（观察者失败轮的文件下轮仍在清单）；新事件注册 events 白名单（新增 observer_empty_retry 等，删 ledger_synced/reports_promoted/surface_parse_fail）；watch 分支扩展。
- **验收**：故障注入单测（观察者空产出/判断书损坏/重试后成功三剧本）。

### F8 测试翻转+终验
- **改动**：翻转/报废用例清单见 §5；产出**新版验收清单**（§6.3 草案转正）；dry-run 门全过；清扫类：`transcript_check.py` 删除（A23 已裁，消费者全死）。
- **终验**：usc-portal 复跑对照（新 engagement 重建），按 §6.3 逐项打勾。

## 4. 关键设计稿（F6 动工前视为冻结）

### 4.1 判断书 schema 草案
**权威协议 = `contracts/OBSERVER-INTERFACE.md`**（判断书五操作+任务单 schema+校验规则+写入纪律 R9，随执行器同 commit 演进）；图存储形态权威 = `contracts/blackboard.schema.json`（已从仓库根迁入，test_schema_contract 引用同步改，6/6 绿）。下例仅为速览：
```json
{
  "round": 2,
  "operations": [
    {"op": "add_fact", "summary": "…", "evidence": "facts/auth-session-anchor.md",
     "endpoint": "/api/upp/…", "ref": "D-001"},
    {"op": "add_finding", "summary": "…", "report": "findings/authc-idor.md",
     "severity": "high", "reason": "…", "result": "confirmed",
     "endpoint": "/api/authc/users/{id}/roles", "ref": "T-030"},
    {"op": "add_intent", "goal": "…", "note": "…", "ref": "T-038"},
    {"op": "set_state", "id": "D-003", "state": "blocked", "reason": "…可检验条件…"},
    {"op": "add_edge", "src": "T-030", "rel": "yields", "dst": "F-001", "note": "组合逻辑…"}
  ]
}
```

### 4.2 观察者任务单 schema（stdin，零快照）
```json
{"round": 2, "goal": "…", "timebox": 1800,
 "new_outputs": [{"path": "facts/xxx.md"}, {"path": "findings/yyy.md"}],
 "noreport_rejects": ["/api/upp/…"],
 "graph_path": ".at1/blackboard.json",
 "manual": ".observer/INTERFACE.md"}
```

### 4.3 执行器流程（伪代码级）
```
on observer_exit:
  doc = read(.observer/OBSERVER.json)
  if not exists or parse_fail or operations empty:
      retry_once(); on fail → emit(observer_empty_retry, warn); return
  for op in doc.operations:
      err = validate(op)            # schema/未知 id/翻案/noreport/查重
      if err: rejects.append(op, err); continue
      board.apply(op)               # 三原子；receipt → .at1/interface_log.jsonl
  board.save()
```

### 4.4 手册大纲
- worker（F4）：见 §3-F4 章节。
- OBSERVER-MANUAL（F6）：定位职权（唯一审计者/写图唯一通道/无杀无判停）→ 开工序列（任务单→读产出→读图→逐份审计）→ 五纪律（证据逐字/判层核对/增量写/防注入/评级口径）→ STATE.md 写法（进度总结口吻+"## 下轮建议"固定节）→ 收尾（draft 导出/超时前落盘）。

## 5. 测试计划

- **报废**：配方1 收割解析类、两刷投影类、FORMATS 渲染类、账本格式类、人拍板播种类、promote/ledger 类、usc 真账本回放。
- **翻转**：配方0（fact=1）、dry-run 断言、guard 禁区清单+教育层、scaffold 目录树、一致性锁。
- **新写**：执行器拒收矩阵/幂等重放/receipt、防线三剧本故障注入、观察者 spawn（时间盒/模型可配）、目录 diff 清单、一致性锁新版。
- **估算**：报废/翻转 60-80 条，新写 40-60 条，净值 ±10%，先降后回。

## 6. 验收

### 6.1 卡级验收
每卡"验收"栏逐条过；全量测试绿。

### 6.2 dry-run 门
目录树正确（无 .auto/，有 facts//findings//evidence/）；图内 fact 恰 1（画像）；prompt 三块终态；无 FORMATS/status.md 生成。

### 6.3 复跑对照验收（新版十点，usc-portal 重建跑）
1. worker 开工首工具=读图本体 ｜ 2. facts//findings/ 一条一文件、指针齐 ｜ 3. 播种仅画像 1 条 ｜ 4. 观察者判断书五操作合法、执行器入图、receipt/rejects 可查 ｜ 5. STATE.md 观察者产出（含下轮建议节）、【引导】块抽取正常 ｜ 6. 防线故障注入恢复轮 ｜ 7. `<Stop>` 引证护栏 ｜ 8. 发现全链：worker 文件→判断书→图→F-id ｜ 9. 计量收全（tokens/cost，P4 关闭）｜ 10. 无 DIRECTIONS/账本/FORMATS 死信。

## 7. 风险与回退

| 风险 | 对策 |
|---|---|
| 观察者语义审计质量不足（deepseek-v4-flash） | 模型配置化，切 glm-5.3 只改配置；复跑对照出质量/成本数据 |
| 观察者单点（空产出/呆滞） | R8 防线（重试+告警+补账）；时间盒 1800s 强杀 |
| worker 摆放乱（prompt 约束失守） | 观察者全量扫描兜底，不丢只乱；真轮看整洁度再调手册 |
| 判断书 schema 设计缺陷 | §4.1 冻结后施工；执行器 rejects 留痕可迭代 |
| 回退 | git 基线 40e6152，每卡一 commit 可回滚；usc-portal 参照目录全程不动 |

## 8. 明确不做（本批边界）

MCP（已弃案）/ engagement 树 git 化（已弃案）/ confidence 字段（用户暂缓待议）/ 内容迁移（老 engagement 归档）/ M5 工作台 / oob.py / cas 与外链系统测试。

## 9. 施工结果（2026-09-19 执行完毕，除实机复跑）

**状态：F1-F8 全部落地，181 测试全绿，dry-run 验收过。实机复跑（§6.3）按用户指示未做。**

| 卡 | 结果 |
|---|---|
| F1 | board.py：proposed 消亡（finding 仅 confirmed/dismissed；fact confirmed/dismissed/superseded）；finding 终态写死不可迁移；create_node 支持显式 state 直落终态；schema 同步 + 新增 proposed 消亡负例 |
| F2 | `_seed_from_engagement` 重写：只种一条画像 fact（直落终态）+ 指针；prior-intel 逐行灌图与 status.md 播种全删 |
| F3 | scaffold 单层化（根=worker cwd；facts//findings//evidence/ 预创建；FORMATS/status.md/账本不再生成）；guard：P1 host 尾巴剥离修复 + 禁区加 `.observer`/`interface_log`/`OBSERVER.*` |
| F4 | WORKER-CLAUDE.md 重写（优先读图/STATE 配合读/文件夹写盘/四纪律/判层语义保留/禁写可读）；汇编 §3.1 同步（逐字锁过） |
| F5 | harvest 瘦身至 diff_new_lines（hints 用）；writeback.py 与 transcript_check.py 删除；driver 两刷投影/配方1 全删 |
| F6 | **observer.py 重写**（-p 同构 spawn/`.observer/` 工作台/任务单/判断书读取/模型配置化）；**observer_harvest v2 执行器**（五操作/拒收矩阵/幂等/ref 连线语义表/receipts/rejects/画像换代）；OBSERVER-MANUAL 新增；会话计量（P4 关闭） |
| F7 | 空产出重试一次 + `observer_empty_retry`（retry/exhausted 两阶段）+ `state_fallback` 兜底 + 目录级 diff（纳秒指纹）+ events 白名单增删 + watch 渲染器扩展 |
| F8 | 测试翻转：181 绿（原 223 → 删除 writeback/transcript_check/observer chat 通道相关死用例，新写执行器/防线/单层化/新链路用例）；dry-run 门全过 |

**执行中发现并修正的实现问题**（非测试问题）：
1. 执行器 `applied` 计数把幂等撞键的 existing 也算进去了 → 拆分真落笔计数。
2. `_ref_edge` 语义映射初版把"方向→事实"错判成 derived_from → 按 schema §4.1 定为 yields（并补全六动词映射表）。
3. 目录级 diff 秒级 mtime 同秒改写会漏 → 改纳秒+尺寸指纹。
4. dry-run 分支未落盘图（验收查不到播种结果）→ 补 `bb.save()`。

**目录终态**（dry-run 实测）：`.at1/ CLAUDE.md STATE.md engagement.json evidence/ facts/ findings/ notes/ src标准/ state/ .mcp.json`——无 .auto/、无 FORMATS.md、无 status.md、无账本。
