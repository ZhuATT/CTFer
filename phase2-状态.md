# Phase 2 —— 状态（M2）执行计划

> 依据：`docs/at1-施工执行单.md` 卡 2.1-2.3 + 设计§3.3（board）/§3.5（prompt）/§2.3（workdir 契约）
> 目标：**跨轮状态成立**——会话 1 干的活（事实/台账/交接）出现在会话 2 的 prompt 里；会话被杀，接力不断。
> Phase 2 结束时 AT1 有了记忆，但还没有验证（M3）和主循环（M4）。
> 工作目录：`D:\Downloads\hacker\at1-github`；上一 Phase：`9850aa0`（骨架，pytest 25/25）

---

## 0. 范围

**做**：board.py（黑板四函数）/ harvest.py（收割 diff + Handoff 代码合成）/ prompt.py（渲染管线 + recon 手册全文）/ relay demo（selftest 新子命令）
**不做**：verify 与 Claim 门（M3）、driver 主循环与 CONTROL（M4）、WORKER-CLAUDE.md 与 scaffolding 展开（M4，M2 demo 的 prompt 直接内联指示）、canary-web（M3.5）、stoploss/guard（M4）

**结构变化**：新增 `src/harvest.py`（设计§2.1 树没有的模块——FINDINGS/FACTS diff 与 Handoff 合成放这，board.py 保持纯状态职责；完成后回写设计文档模块表）。

## 1. 数据契约定版（本 Phase 锁死，M3/M4 直接消费）

### 1.1 黑板 schema（`.at1/_blackboard.json`，设计§3.3）

```json
{"facts":    [{"kind":"endpoint", "value":"GET /api/order/detail", "provenance":"curl -s ...",
               "ts":"2026-08-25T10:00:00Z", "conf":0.9, "round":3}],
 "immune":   [{"endpoint":"/api/login", "class":"authbypass", "since_round":2}],
 "handoff":  "上一轮 <Handoff> 文本（或代码合成文本，带 origin 字段区分）",
 "handoff_origin": "model | synthesized",
 "goal":     {"stage":"recon|identity|exploit|report", "history":["recon"]},
 "ledger":   {"tried": {"<归一化命令>": 3}, "background": [{"id":1,"desc":"js-intel config.js","status":"done"}]},
 "verified": {"confirmed": 0, "tentative": 0},
 "config":   {"endpoint_n": 15}}
```

### 1.2 事实两入口

- **自动抽取**（`board.observe(tool_event)`）：endpoint / credential / kv_secret / fingerprint 四类，正则从 hxbai blackboard.py 移植改 Web 化
- **显式上报**（workdir `FACTS` 文件，每行一 JSON）：`{"kind":"identity_model","value":"身份由 httpOnly cticket 派生","evidence":"..."}` 等结论类

### 1.3 渲染段格式（prompt 第 4 段 Graph State 的固定形状）

- 事实按 kind 分组，每组**上限 12 行**，超出显示"…余 N 条"；整段**总预算 ≤4000 字符**，超限按优先级裁（immune > credential > identity_model > endpoint > fingerprint，低优先级只留计数行）——两道闸 M2 第一天就上，不留到 M4
- 免疫段独立小节，附"勿重测"
- 全部目标衍生文本走 `untrusted_block()` 包裹

## 2. 任务卡

### P2.0 原料阅读（不写码）

- 精读 `hxbai/blackboard.py`（371 行）：事实抽取正则、去重键、observe 管线——抄正则改语义，不抄 CTF 特有逻辑
- 泛读 `hxbai/taskprompt.py`（424 行）：段落组装顺序、Graph State 渲染形态——P2.3 的参考
- 产出：把可用正则/不可用部分列进本文件附录（施工时对照）

### P2.1 board.py（核心，~250 行 + 单测）

- `Blackboard(path)`：load/save JSON——save 走**临时文件 + fsync + rename** 原子替换，覆写前留 `.bak`，加载时主文件损坏自动回退（"唯一事实源"的崩溃保险）；observe 批量后 save
- `observe(tool_event, round_)`：四类抽取**按设计§3.3 事实类型表从零写**（hxbai 只作参考读物），去重键：endpoint=method+path / credential=值哈希 / kv_secret=key 名 / fingerprint=名
- `ingest_facts(lines, round_)`：FACTS 显式行入库（identity_model 等，engagement 级唯一）
- `check_goal()`：设计§3.3 伪代码逐行落（count/exists；N 从 config.endpoint_n）
- `verify_fact(fact)`：会话守卫——provenance 匹配凭证特征（`cookie|token|authorization|session`，i）→ 跳过重放、conf 冻结
- `render()`：§1.3 格式（组内 12 行 + 总预算 4000 字符两道闸）+ 免疫段；`plan_directive()` 一行（阶段+出口+轮次）
- **验收（单测）**：**对 tests/fixtures/ 的真实语料**（每类 ≥3 份真形状样本）抽取正确；10 条假 tool_result 去重入库；喂到 15 条 endpoint 断言 stage→identity；带 cookie 的 provenance 走 verify_fact 断言不重放且 conf 不降；同黑板两次 render 逐字节相同；render 输出被 untrusted 包裹（含恶意 `</untrusted_data` 的 fact 值被消毒）；**预算闸**：灌 200 条事实断言 render ≤4000 字符且 credential/immune 未被裁；**bak 回退**：写坏主文件后 load 回退到 .bak

### P2.2 harvest.py（~120 行 + 单测）

- `diff_new_lines(path, offset) -> (lines, new_offset)`：FINDINGS/FACTS 轮末增量读取（offset 记在黑板 ledger 或独立状态文件）
- `synthesize_handoff(board, tool_events_tail) -> str`：被杀会话的代码合成兜底——从 ledger.tried 高频命令 + 最近 facts + 未完成的后台任务拼一段降级交接文本（`handoff_origin="synthesized"`）
- **验收（单测）**：两次 diff 不重读不漏读（append 后 offset 前移）；synth 输出含最近事实与后台任务摘要

### P2.3 prompt.py（~200 行 + 单测）

- `PREAMBLE` 常量（方法论序言：现象是路标结果是终点 / 发现即落盘 / 输出契约摘要）
- 四份阶段手册：**recon 全文**（浏览器侦察协议/js-intel/资产分诊细则，从设计§3.5.3 展开成操作级文案）；identity/exploit/report 三份先写提纲占位（M3/M4 补全文——各自 phase 开工时写）
- `render_round_prompt(board, directive=None) -> str`：9 段固定顺序（序言/手册/plan_directive/Graph State/接力块/tried 告警/台账/hints/directive）；接力块=黑板 handoff 字段渲染；tried 告警=ledger 里 count≥3 的命令
- **验收（单测）**：9 段顺序与分隔标记固定；确定性（同黑板两次渲染逐字节相同）；tried≥3 的命令出现在第 6 段；directive=None 时第 9 段为空

### P2.4 relay demo（`python -m src selftest --relay`）+ Phase 验收

流程（真 -p 会话 ×2）：

```
round 1: 临时 engagement 目录（.auto workdir / .at1 控制器区 / state）
  prompt1 = 序言 + 临时任务指示（创建 notes.txt 写指定 marker；
           执行 2-3 条会产生事实的命令；追加一行 FACTS；输出 <Handoff>…</Handoff>）
  → runner.run → on_fact → board.observe 实时入库
  → 会话结束：Handoff 收割（模型版）入黑板
round 2: prompt2 = render_round_prompt(board)
  → 断言 prompt2 第 4 段含 round1 事实、第 5 段含 round1 Handoff
  → spawn round 2，任务="根据状态回答上轮 marker 与未竟事项，写入 answer.txt"
  → 断言 answer.txt 正确 = 接力成立
kill 组（同流程变体）：round 1 spawn 后**条件杀**（on_fact ≥1 条事实 且 已运行 ≥8s，两条件同时满足才杀）
  → synthesize_handoff 生成交接 → prompt2 含合成段（origin=synthesized）
  → round 2 照常接力 = 被杀不断
```

**Phase 2 完成定义（DoD）**：

- [ ] board 单测全绿（P2.1 六条验收）
- [ ] harvest 单测全绿（diff 幂等 / synth 含要素）
- [ ] prompt 单测全绿（顺序/确定性/tried/directive）
- [ ] relay demo：round2 answer.txt 正确；prompt2 的事实/接力/台账段现场断言
- [ ] kill demo：强杀后接力不断，auto-log 记 handoff_harvested(origin=synthesized)
- [ ] pytest 全绿（Phase 1 的 25 条不回归）
- [ ] 成本：两轮真会话 ≈ $0.7-1.0
- [ ] 设计文档回写：模块表加 harvest.py；§3.3/§3.5 与实现的差异清单（若有）

## 3. 节奏与纪律

- commit：每张卡一 commit（等用户指示统一提交或随卡提交，沿用 Phase 1 习惯——**做完不自动推远程**）
- 施工冲突 → 先改设计文档再继续
- P2.0 的正则移植结论写进本文件附录，M3 写词表时复用

## 4. 已知风险（已附强化改进，标 ★ 的是比常规应对多走的一步）

| 风险 | 应对 + ★改进 |
|---|---|
| hxbai 正则是 CTF 题解语境（flag/端口扫），Web 事实抽取可能要大改 | P2.0 先读后定，业务语义全部重写。★**不走 vendor-改的路子，直接按设计§3.3 事实类型表从零写**，hxbai 降级为"参考读物"；★配套**真实语料夹具**：从已测过的目标形态（memory 里的 ctrip/qianwen/tingwu 响应特征）整理每类 ≥3 份真实形状的 tool_result 样本进 tests/fixtures/，抽取单测对着真语料跑，不对合成数据自嗨 |
| Graph State 随事实增长撑爆 prompt | §1.3 每组 12 行上限。★再加**总预算**：Graph State 整段 ≤4000 字符，超了按优先级裁（immune > credential > identity_model > endpoint > fingerprint，低优先级只留计数行）；★tried 告警同样封顶（按重复次数取 top-5）——两处膨胀源都上闸 |
| live kill 演示的时序 flaky（杀早了什么都没干） | ★把"定时杀"改成**条件杀**：on_fact 观察到 ≥1 条事实**且**已运行 ≥8s 才杀（两个条件都满足）——从"赌时间"变成"等状态"，flaky 基本消除；断言仍只验"合成 Handoff 存在 + round2 接力成功" |
| worker 不按指示输出 `<Handoff>` / 不写 FACTS | prompt1 给逐字模板；★**断言不依赖 worker 自觉**：prompt2 的事实断言全部走 observe 自动抽取（prompt1 让 worker 跑几条输出含 URL/头域的命令，endpoint/fingerprint 自然入库，与它写不写 FACTS 无关）；★Handoff 缺失本身就是生产路径的**双路收割演练**——模型版没有就落代码合成版，demo 反而多验了一条真实链路 |
| 双会话成本 ~$1/次 demo | 单元层覆盖逻辑，demo 按需跑。★round1/round2 同一次 selftest 调用内完成（省一次进程启动）；round1 max_turns 压到 6 |
| Windows 文件句柄 / 黑板损坏 | 原子写（临时文件 + rename）。★rename 前 fsync（防断电半写）；★**留 .bak**：每次覆写前把上一份好黑板拷成 `_blackboard.json.bak`，加载时主文件损坏自动回退 .bak——"唯一事实源"值得这个保险 |
