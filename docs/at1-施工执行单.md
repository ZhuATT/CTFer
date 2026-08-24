# AT1 施工执行单（v1.0）

> **两份文档的分工**：`at1-执行开发计划.md`（设计 v2.3，已冻结）= 系统是什么，施工有疑问先查它对应节；本文档 = 按什么顺序写、每步怎么验收。
> **纪律**：不动 hxbai/aiscan 源文件（vendor 拷贝）；每个施工卡的验收通过才进下一张卡；施工中发现设计冲突 → 先改设计文档再继续。
> 文中"设计§x.y"均指 `at1-执行开发计划.md` 的章节。

---

## 0. 开工前置（M1 动工前逐项勾掉）

| # | 事项 | 状态 | 说明 |
|---|---|---|---|
| 1 | **hxbai 源码路径** | ✅ **已解决** | `D:\Downloads\hacker\lernproject\hxbai-main\hxbai\`——vendor 来源九文件齐备（ccrunner/blackboard/verify/stoploss/llm/oob/task/scheduler/longtask_guard/config 合计 2067 行，与计划预估一致）；`drivers/benchmark_driver.py`（1608 行）确认存在且不拷贝 |
| 2 | claude CLI headless 验证 | ✅ 跑通（CLI v2.1.238） | 实测四事实已入库：① `-p`+stream-json 必须加 `--verbose`；② 输出流**混有非 JSON 行**（stdin 警告、`[claude-code:…]` 遥测行）→ runner 逐行 try json.loads 跳过失败行、按 type/subtype 匹配；③ init/result 事件均带 `session_id`，result 另带 num_turns/stop_reason/usage/total_cost_usd；④ prompt 经 stdin 喂入后即关闭（CLI 等 stdin ~3s）；单次 headless 固定开销 ~25k input tokens（系统提示+工具定义），预算按此估 |
| 3 | Python 环境 | ✅ | `.venv` 已建于 at1-github（Python 3.13.11 / pip 25.3）；无重依赖（标准库 + 门1.5 用 urllib） |
| 4 | solver 模型 env | ✅ | 默认 glm，现有 CC 配置直接复用（providers.anthropic_env()） |
| 5 | deepseek key | ⬜ 可延到 M3 | 门 2 verifier 用；没有 → 按设计§7 换异构方案，先记着不阻塞 M1/M2 |

---

## 1. 施工总顺序

```
M1 骨架（providers → events → runner）
   ↓
M2 状态（untrusted → board → 收割 → prompt 骨架）
   ↓                          ↘（并行）
M4 闭环（driver/guard/stoploss/进出/watch）    M3 裁决（verify 全链）
   ↑ 需要 M3+M3.5 完成 ↙                        ↘ M3.5 canary-web（与 M2 起即可并行）
   ↓
M5 工作台
```

---

## 2. M1 骨架

### 卡 1.1 `at1/providers.py`
- **来源**：vendor hxbai config.py，删 `_to_gateway` + `SOLVER_GATEWAY`，预设表加自定义位
- **设计§**：3.2（双通道/env 清单）
- **验收**：`anthropic_env()` 返回的 dict 注入后 `claude -p` 能跑通；打印 env 无明文 key

### 卡 1.2 `at1/events.py`
- **来源**：新写（事件类型抄设计§4.1 表）
- **关键点**：只追加 writer；`_redact(data)` 脱敏 cookie/key/token 字段再落盘
- **验收**：写 3 条假事件 → `jq -c .state/auto-log.jsonl` 逐行可解析，含 secret 的字段显示为 `***`

### 卡 1.3 `at1/runner.py` + `at1/untrusted.py`
- **来源**：runner vendor hxbai ccrunner.py（删 tsec；消毒键名换 `AT1_*`）；untrusted 移植 dcr-harness 37 行（设计§2.1 已列出处）
- **改动点**（设计§3.1 全表）：
  1. `init` 事件抓 `session_id` 落盘
  2. 原始流逐消息追加落 `<engagement>/.at1/transcript.jsonl`（注意：控制器区，不是 workdir）
  3. resume：异常退出退避后 `--resume <session_id>`，≤20 次；max-turns 终态不 resume
  4. 心跳：每 25 次 tool_result → `heartbeat` 事件 + 回调 `on_heartbeat`（CONTROL 轮询挂这）
  5. 收割：从最后一条 assistant 消息**向前扫** `<Handoff>`
- **验收（M1 总 demo，可复制）**：
  ```powershell
  # dry-run：让一个 -p 会话读指定文件写一行结果
  python -m at1 selftest --dry-run
  # 通过标准：stream-json 被逐行解析；auto-log.jsonl 有 run_start/session_start/fact_added/session_end；
  # transcript.jsonl 存在且含完整消息流；<Handoff> 正则提取出文本；Ctrl+C 杀掉后 transcript 仍可读
  ```

---

## 3. M2 状态

### 卡 2.1 `at1/board.py`
- **来源**：vendor hxbai blackboard.py，按设计§3.3 重写为四函数（observe / check_goal / verify_fact / render）
- **关键点**：
  - 数据模型照设计§3.3 JSON 示例（facts/immune/handoff/goal/ledger）
  - 事实两入口：observe 正则抽（endpoint/credential/kv_secret/fingerprint）+ FACTS 文件 diff（identity_model）
  - check_goal 照设计§3.3 伪代码（count/exists/文件存在，无文本匹配）；N 从 engagement.json 读默认 15
  - render 出口一律走 untrusted 包裹；免疫段单独渲染
- **验收**：单测——喂 10 条假 tool_result，断言 facts 入库去重；喂到 15 条 endpoint 断言 stage 变 identity；带 cookie 的 provenance 走 verify_fact 断言不重放

### 卡 2.2 收割：FINDINGS / FACTS / Handoff 双路
- **关键点**：driver 侧 diff 函数（记录上次偏移）；Handoff 模型版（runner 扫标签）+ 代码合成版（被杀时从 ledger+facts 拼）
- **验收**：模拟被杀会话（kill -9 一个真 `-p`）→ 代码合成 Handoff 生成，下一轮 prompt 含它

### 卡 2.3 `at1/prompt.py` 骨架
- **关键点**：设计§3.5——序言常量 + 四手册占位（M2 只写 recon 全文，其余三份写提纲）+ `render_round_prompt(board, directives)` 按 9 段顺序拼
- **验收（M2 总 demo）**：双会话接力——会话 1（真 `-p`）发现的事实+台账出现在会话 2 的 prompt 第 4/5/6 段里；渲染是确定性的（同黑板两次渲染逐字节相同）

---

## 4. M3 裁决（可与 M3.5 并行）

### 卡 3.1 Claim schema + FINDINGS 契约
- 设计§3.4.1 JSON；WORKER-CLAUDE.md 输出契约段同步写（引用 evidence 四段模板）

### 卡 3.2 门 1 词表 + `gate1`
- **关键点**：11 行词表照设计§3.4.3；正则与 board 抽取共用一份常量模块（同源复用）；distinct_from 缺失机械拒收；负 oracle → immune 入板
- **验收（三案测试，M3 核心 demo）**：
  ```powershell
  python -m pytest tests/test_gate1.py -v
  # ①伪造证据（marker 不在 evidence 原文）→ rejected
  # ②编造 marker_source（文件不存在/无 marker）→ rejected
  # ③真实双点 → 过门1
  # ④负 oracle：403 响应 → immune 事实入板
  ```

### 卡 3.3 门 2 `gate2`（llm.py vendor）
- **关键点**：prompt 用设计§3.4.4 草案；补 class 成立要件全表（从 CLAUDE.md 绝对不报表逐条翻译，11 类每类一段"什么情况下不成立"）；温度 0；输出严格 JSON 解析失败 → 重试 1 次 → 降 tentative
- **验收**：三案加两案——⑤"共享收货地址"证据（造一份 buyer=userA 的响应）→ refuted=true；⑥真 idor → refuted=false

### 卡 3.4 门 3 `gate3` + 状态机串联
- **关键点**：transcript 逐字查找（设计§3.4.4 机械实现）；门1.5 留接口默认关；verify 纯函数无副作用（写回在 driver）
- **验收**：全链——⑦整体虚构案（三件套自洽但请求不在 transcript）→ 门 3 杀

---

## 5. M3.5 canary-web（与 M2 起并行，独立目录 `script/at1/canary-web/`）

### 卡 5.1 Flask 靶
- 设计§6.3：4 真洞（idor 读/idor 写/水平越权/sqli 报错）+ 7 干扰项；两个测试账号 + 有 marker 的数据；绑 127.0.0.1；数据生成固定 seed

### 卡 5.2 `ground_truth.yaml` + `grade.py`
- **验收**：`grade.py` 对空输出打 0 检出 0 误报；对一份手工正确答案打满分；单行摘要输出（回归可比）

---

## 6. M4 闭环

### 卡 6.1 `at1/guard.py`
- **来源**：vendor hxbai longtask_guard 判定正则；deny 模板 Windows 化
- **新增**：scope 拦截（消费 engagement.json allow/deny）+ **控制器区禁写**（`.at1/**`、`state/**`）
- **验收**：worker 会话里 curl scope 外域名被 deny 且收到教学提示；写 `.at1/x` 被 deny

### 卡 6.2 `at1/stoploss.py` + `at1/driver.py`
- stoploss 四维照设计§7 默认（3/预算/3/3）；driver 主循环照设计§3.6 伪代码逐行落（fail-fast → 轮次循环 → 终止三条件 → 收尾）；evidence 直写 engagement；surface 深度刷新 + prior-intel-draft 生成
- **验收（M4 核心 demo）**：
  ```powershell
  # ① canary-web 全量回归
  python -m at1 run <canary-engagement> --budget 1800
  python canary-web/grade.py <结果>          # 真洞 4/4 检出 + 干扰项误报=0
  # ② 协议文件正确性：status.md 锚点追加、攻击面深度刷新、prior-intel-draft 生成
  # ③ CONTROL：stop/pause/directive 三命令各验一次
  # ④ fail-fast：删掉 engagement.json → 拒绝启动
  ```

### 卡 6.3 `at1 watch`
- tail auto-log 彩色一行式（isatty 着色）——这份"事件→呈现"映射 M5 直接复用

---

## 7. M5 工作台

- 照设计§4.3 四页规格：布置（表单→编译三件套+骨架→spawn）/ 运行（SSE + 三态灯 + 三档告警 + 三动作）/ 结果 / 续跑（draft 预填）
- FastAPI + 单页前端，绑 127.0.0.1:8787；控制器是子进程，工作台崩溃不影响 run
- **验收**：从工作台布置 canary-web 任务跑到出报告**全程不碰终端**；confirmed 时浏览器通知弹出

---

## 8. 里程碑验收一览（全过 = v1 交付）

| M | 验收 demo | 依赖 |
|---|---|---|
| M1 | dry-run：spawn/解析/事件落盘/Handoff 提取/kill 后可读 | 前置全勾 |
| M2 | 双会话接力 + 被杀代码合成 Handoff | M1 |
| M3 | 七案测试全过（含整体虚构案） | M1，可与 M2 并行 |
| M3.5 | grade.py 空跑 0/0、手答满分 | 无（M2 起并行） |
| M4 | canary 回归 4/4+0 误报 → 三件套读写/CONTROL/fail-fast/watch | M2+M3+M3.5 |
| M5 | 工作台全程不碰终端 | M4 |

## 9. 施工决策路由（遇到问题查哪）

| 遇到 | 查设计§ |
|---|---|
| 这字段/文件谁写谁读 | 2.2 权限表 / 2.3 不变量 |
| 某门怎么判、输入输出 | 3.4 全节 + 3.4.4 契约 |
| prompt 怎么拼 | 3.5（含 9 段顺序与示例） |
| 阶段/终止谁判定 | 3.3 check_goal + 3.6（driver 查盘，worker 零权重） |
| 防注入/防篡改 | 3.3 渲染安全 + 2.3 控制器区 + 5 防线表 |
| 参数默认值要调 | 7 默认参数表 |
| 某功能 v1 做不做 | 8 推迟清单 |
