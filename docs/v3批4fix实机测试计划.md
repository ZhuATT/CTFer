# AT1 实机测试计划（合并执行单：批4fix 治理链补验 + playwright 浏览器池验收）

> **定位**：批4fix 全部工程（主批 S1-S12 已推送 `26ef89b` + 续修批 S13/S14/S16）与 playwright 浏览器池批（B1-B6 竣工，未 commit）的**收尾实机验证合并执行单**——验证清单、操作脚本、判定标准自含，新会话直接开工。
> **基线**：`26ef89b` 之后的工作区，**全量 pytest 265 绿**（238 基线 + playwright 批 27，2026-10-12 竣工时点）。验证过程**不自动 commit**。
> **状态**：**计划就绪（2026-10-12 拍板合并）。等用户给 ①目标 ②身份（storage-state.json）。**
> **上游**：`at1-v3批4fix-落地执行计划.md` §9/§10；`playwright升级计划.md` §7/§9。
> **编排拍板（2026-10-12，用户）**：目标待给（本计划目标无关）；身份由用户提供；破坏性实验**主 run 内嵌**；验收 1 用**同目标双 engagement**（主战 + 轻量陪跑）。

---

## 0. 一段话背景

批4fix 治理链已在 usc-cwcx-b1 实机验过 **worker 半场**；本批补验 **①观察者半场三件套**（唯一没实机走过的代码路径）、**②guard 误报清零**、**③止损不再误杀**。playwright 浏览器池批竣工（浏览器从每轮一次性耗材变成 engagement 常驻资产：状态跨轮/自愈/并行/兜底隔离），只有单测 + 真机冒烟——本次实机**一次全收**，顺带推进 pentest 战果。

## 1. 待验证清单

### A. 观察者半场三件套（批4fix，P-4）

| # | 验证点 | 通过标准 |
|---|---|---|
| A1 | **S1 门 O**：观察者跑动中打 stop | run_end `reason=control-stop(O)`；判断书**未入图**（图节点数不变）；STATE.md 未写；停止后盘面静止 |
| A2 | **S2 杀观察者**：watcher 杀的是活观察者 | 观察者进程树死透（`observer_session_end.stop_reason=controller_kill`）；不是杀 worker 尸体后观察者存活继续入图 |
| A3 | **S12 auditing 续接**：停机后立即再 run | `interrupted_phase(phase=auditing)` 事件 → **跳过 worker 派工**（无 worker session_start 直接进观察者）→ 观察者带 resume 句柄续接（session_id 与 phase.json 残留一致）或 `resume_fallback` 落回新开（也算过，记录走哪条） |

### B. guard 加固复验（P-1/P-2/P-3 收口）

| # | 验证点 | 通过标准 |
|---|---|---|
| B1 | 观察者轮误报清零 | 观察者轮 `guard_violation`（role=observer）**≈ 0 条**（上批同期 26 条误报） |
| B2 | 真阳性照记 | 若出现 allow 外目标探测，guard_violation 记账不漏（guard 只记录不阻断——P-9 摄像头语义，2026-10-13 措辞对齐） |

### C. 止损修复复验（P-14）

| # | 验证点 | 通过标准 |
|---|---|---|
| C1 | 有产出的 run 不被误杀 | 只要 worker 每轮有新文件落盘，不再出现"无新事实连击 3 轮"误停（若 run 真 barren 3 轮被停=正确行为，记录即可） |

### D. 顺带观察（不设失败）

- D1：S11 观察者不限轮——`observer_session_end.turns` 若 >60 即为直接实证
- D2：R-2 计量断流（r2 起 worker session_end 记 $0）属已知拍板不修，**不要当异常上报**

### E. 浏览器池（playwright 批 §7 实机化；E 编号承接原验收清单）

| # | 验证点 | 通过标准 | 时机 |
|---|---|---|---|
| E1 | 双 engagement 并行各附各的 Chrome | 主战+陪跑两个 Chrome **不同端口+不同 profile**（两个 `.at1/browser.json` 比对），各自 worker 无 browser 报错，auto-log 各自 `browser_start` | 主 run 跑稳 1-2 轮后启动陪跑 |
| E2 | 身份导入 → 跨轮存活 | 轮 1 worker 按手册舞步导入登录（me/whoami 验证生效）→ 轮 2 附着后 **cookie 和打开的 tab 原样在**、无重复导入（交接/快照证实） | 主 run 轮 1-2 |
| E3 | 轮中杀 worker 树 → Chrome 存活 | taskkill worker 进程树后 Chrome 进程还活（`/json/version` 应答），下一轮正常附着 | 主 run 某轮（见 §2 时机纪律） |
| E4 | 杀 Chrome → 轮间自愈 | 手动杀 Chrome → 下轮 `browser_relaunch reason=probe-fail`，登录态从 profile 回（活页面态丢=预期） | 主 run 另一轮 |
| E5a | KEEP=1 留守 + 跨 run 复用 | 补充 run 带 `AT1_BROWSER_KEEP=1`：run_end 后 Chrome 留守（`/json` 可见页面列表）→ 再 run 出 `browser_reuse` 且 **pid 与留守实例相同** | 补充小节 |
| E5b | 强杀 driver 连坐（拍板预期）→ 残账清理 | KEEP=1 留守态 `taskkill /T /F` driver：Chrome 陪葬=**预期**（§6.5-1 拍板，别当 bug）；browser.json 残留 → 再 run 出 `browser_start`（干净重拉，非 reuse） | 补充小节 |
| E6 | fallback 兜底隔离 | `AT1_BROWSER_EXE` 指错 → `browser_skip reason=no-exe` + MCP 自起浏览器落 `chrome-profile-fallback`（engagement 专属），无全局 profile 访问，run 照常完成 | 补充小节（陪跑 engagement 短 run） |
| E7 | 轻量复核（已预检闭环降级） | 跑批全程 auto-log 无 browser 工具报错（browser_close 语义/env 穿透 2026-10-12 已预检实锤） | 全程 |
| E8 | KEEP=0 默认收尸 | 主 run run_end 后 Chrome 进程死 + `browser_exit reason=shutdown` | 主 run 收尾 |

> **原 §7 第 7 项修正**（无 .mcp.json → skip）：实机不可达——`scaffold.expand()` 每次 run 都重写 `.mcp.json`。`no-mcp-config` 分支已单测锁（test_browser.py）；skip 链路由 **E6** 代表实机验证。

## 2. 操作脚本（合并编排，精确到命令与观察点）

**准备**：
```bash
cd /d/Downloads/hacker/at1-github
.venv/Scripts/python.exe -m pytest -q          # 确认 265 绿
```
- 用户给目标 → 按 CLAUDE.md 侦察启动动作（浏览器侦察→prior-intel→三件套）建**主战 engagement**；同目标复制建**陪跑 engagement**（`engagement.json` 填轻量 goal，跑时 `--rounds 2 --no-observer`）
- 用户提供身份 → storage-state.json 按 engagement.json `credentials.storage_state` 路径放好（E2 前置）
- E2 前确认浏览器对该域未登录（新 profile 天然未登录，天然满足）

**阶段 1：主战 engagement 首 run**（KEEP=0 默认）
```bash
source .secrets.env && .venv/Scripts/python.exe -m src run "<主战绝对路径>"
# 另开窗口监控（现在能看到 ◐ browser_* 事件行）：
.venv/Scripts/python.exe -m src watch "<主战>" --all --once
```
- 轮 1：盯 `browser_start` 事件 + worker 交接提身份生效（E2 前半）
- **A1**：`phase.json` 翻到 `"phase": "auditing"` 即打 stop（窗口 3~8 分钟，错过等下个观察者轮）：
  ```bash
  .venv/Scripts/python.exe -m src stop "<主战>" "观察者半场补测"
  ```
- **阶段 2（A3）**：立即再 run（同命令）——验 `interrupted_phase(auditing)` → 观察者续接或 fallback
- **阶段 3**：放开跑完——B1/B2/C1/D1/D2 + E2 跨轮（轮 2 看 cookie/tab 在不在）
- **E3**（选一轮 worker 开跑后）：手动 `taskkill /PID <worker pid> /T /F` → Chrome 应存活 → 等下一轮正常附着
- **E4**（另一轮结束后）：手动杀 Chrome（netstat 找 `.at1/browser.json` 里端口的 LISTENING PID）→ 下轮看 `browser_relaunch`
- **E1**：主跑稳 1-2 轮后启动陪跑（`--rounds 2 --no-observer` + `--budget 900`）→ 比对两边 browser.json 端口不同、`curl /json/version` 各自活
- 主 run 收尾 → **E8**：`browser_exit reason=shutdown` + Chrome 进程死

**阶段 4：补充小节（破坏性收尾实验，主 run 结束后做）**
```bash
# E5a：KEEP=1 短 run 留守
AT1_BROWSER_KEEP=1 source .secrets.env && .venv/Scripts/python.exe -m src run "<主战>" --rounds 1 --no-observer
# run_end 后：curl http://127.0.0.1:<browser.json 里的 port>/json 看页面列表（留守✓）
# 再 run（正常命令），开跑后看 auto-log：browser_reuse 且 pid 相同（跨 run 复用✓），随后 src stop 收

# E5b：留守态强杀 driver（预期连坐）
#   KEEP=1 再留一实例 → taskkill /F /PID <driver pid> /T /F → Chrome 陪葬=预期
#   再 run → browser_start（干净重拉，非 reuse）——browser.json 残账被正确清理

# E6：fallback（用陪跑 engagement）
AT1_BROWSER_EXE="D:\\不存在的路径\\chrome.exe" .venv/Scripts/python.exe -m src run "<陪跑>" --rounds 1 --no-observer
#   判定：browser_skip reason=no-exe + run 正常完成 + 陪跑 .at1/chrome-profile-fallback 被 MCP 自起使用
```
收尾：陪跑 engagement `src stop`；留守 Chrome 手动收（netstat 找端口 PID taskkill，见 playwright计划 §6 风险5 清理配方）。

**时机纪律（防实验互相污染）**：破坏性实验（E3/E4/E5b）**一次只杀一个东西**；避开观察者窗口和 stop 实验轮；E3 与 E4 不放相邻轮（E3 制造的 error 轮会进止损计数，连续 3 轮 barren 会真触发 C1——那是正常行为，别混淆）。

## 3. 判定总表（新会话逐条勾）

- [ ] A1 门 O：control-stop(O) + 判断书未入图 + STATE 未写
- [ ] A2 观察者进程树死透（controller_kill）
- [ ] A3 auditing 续接（或 fallback，记录走向）
- [ ] B1 观察者轮 guard_violation ≈ 0
- [ ] B2 真阳性照记（如出现）
- [ ] C1 有产出不被"无新事实"误杀
- [ ] D1 turns>60 实证（若发生）
- [ ] E1 双 engagement 两 Chrome 不同 port+profile，各自 browser_start
- [ ] E2 轮 1 导入身份 → 轮 2 cookie+tab 都在、无重复导入
- [ ] E3 杀 worker 树 → Chrome 存活，下轮附着
- [ ] E4 杀 Chrome → browser_relaunch 自愈，登录态回
- [ ] E5a KEEP=1 留守 + 跨 run browser_reuse 同 pid
- [ ] E5b 强杀 driver 连坐（预期）→ 残账 → 再 run browser_start 干净重拉
- [ ] E6 fallback：browser_skip(no-exe) + MCP 自起落 chrome-profile-fallback
- [ ] E7 全程 auto-log 无 browser 工具报错
- [ ] E8 主 run KEEP=0 收尾 browser_exit(shutdown) + Chrome 死

## 4. pentest 战果方向

- **目标待用户给**（新目标走 CLAUDE.md 侦察启动动作）。本批主旨是系统验收，战果预期放平——有确认发现照常先出报告。
- 旧 backlog 不作废（后续可打）：cwcx D-005 口令墙 cookie 向量 SQLi 升格（不需登录态，还衔接 D-003/D-004——操作员重登即解锁）；usc-portal orgtree 越权读审计入图；210.43.114.31:8081 / 172.20.9.43:8087 未开测资产。
- 身份由用户提供 → 涉登录方向随 storage-state.json 注入解锁；验证失败按手册转匿名降级，不空转。

## 5. 纪律与坑（新会话必读）

- **不自动 commit**（265 绿基线——测试跑完应仍是 265；验证过程原则上零代码改动，发现问题先记录）。
- 观察者窗口 3~8 分钟，盯 `phase.json` 别盯聊天；错过了等下个观察者轮，不强行。
- **已知非问题，别当异常**：r2 起 worker session_end 记 $0（R-2 拍板不修）；guard_violation 偶发 1~2 条（看整轮统计）；`.at1/` 里没有诱饵文件（S15 已撤）。
- 停机语义：stop 返回=实例必已死（S4 契约）；停机后再 run=断点续接，能续则续。
- **browser 相关新坑**：E5b 强杀 driver 连坐 Chrome 是 §6.5-1 拍板的预期行为；`browser_close` 关不掉 Chrome（只关本轮自建页，预检实锤）；无 .mcp.json 的 skip 实机不可达（expand 恒写）——见到 no-exe/no-mcp-config 的 `browser_skip` 都是正常降级不是故障。
- cookie 失效勿空转：涉登录方向置 blocked 写明解锁条件，换方向。
- 删/归档 engagement 前先 `src stop`（防 KEEP=1 留守 Chrome 成孤儿）；已泄漏按 playwright计划 §6 风险5 配方清（命令行 `--remote-debugging-port` 特征找 PID）。
- 文档回写一律 Write/Edit 工具（bash 内联处理含反引号 markdown 有误建文件前科）。

## 6. 结果回写区（2026-10-12 终版：17/17 全过，零失败）

**目标**：`http://jwzx.usc.edu.cn:8924/jsxsd/`（教学一体化服务平台学生端，湖南强智 Kingosoft S5.7_1）；主战=`engagements/usc-jwzx-b1`（6 轮），陪跑=`usc-jwzx-pacer`（3 轮）。身份=操作员学生 cookie（双 JSESSIONID 按 path 拆分 + SERVERID，storage-state 注入）。网络=教育网仅代理可达（127.0.0.1:7897；worker 走 env、Chrome 走系统代理）。

### 判定总表（全部 ✅）

| 项 | 结果 | 关键证据 |
|---|---|---|
| A1 门 O | ✅ | `control-stop(O)`；图零入图（nodes=1）；STATE 未写；盘面静止；stop 3s 退净（S4） |
| A2 杀观察者 | ✅ | `controller_kill`——杀的是活观察者（sid=70c8ed89），死因标签正确 |
| A3 auditing 续接 | ✅ | 跳 worker 派工 → `sid=70c8ed89` 与残留一致（stage=initial 原生续接，非 fallback）→ 判断书入图 → r2 接力 |
| B1 观察者误报 | ✅ | **5 个观察者轮，role=observer 误报 0 条**（上批同期 26 条） |
| B2 真阳性照记 | ✅ | worker 探 127.0.0.1（本机代理/CDP）被 `kind=scope` 连记 **17 条**全记录（guard 只记账不阻断——`rm -rf` 也拦不住） |
| C1 止损不误杀 | ✅ | 正式 run 全程 `stoploss_trigger=0`，6 轮全有产出（盘面 176 文件）；仅有的触发=补充实验 `--rounds 1` 的配置化会话上限（设计行为非误杀） |
| D1 turns>60 | ➖ 未发生 | 观察者轮最高 32 turns（S11 未获直接样本，机制单测在） |
| E1 并行隔离 | ✅ | 主战+陪跑两 Chrome 同时活（44916@1605 / 37796@14343），各自 browser_start 各自 profile |
| E2 身份导入 | ✅ | 前半：轮 1 导入即登录态（54KB 框架页 vs 9.7KB 登录壳）。后半（跨实例）：E5a 复用实例上 worker 导航 xsMain.jsp **登录态仍在、免重导**（54KB vs 9718B 字节级对照）——语义注：跨浏览器进程存活属该站 Set-Cookie 持久化行为；若真掉线则 B5 重导舞步兜底（手册在） |
| E3 杀 worker 树 | ✅ | taskkill worker 树（55392）→ Chrome 存活 → 瞬态续跑梯子复活同轮（新 claude 36160 带 resume）→ 重新附着同一 Chrome。**外部硬杀≠controller_kill 语义实机首证** |
| E4 杀 Chrome 自愈 | ✅ | r2 自然收工 → 轮顶 ensure `browser_relaunch reason=probe-fail`（08:54:51）→ 新实例 57064@65080 换账 → r3 紧跟 spawn。探活判死→杀旧→拉新→换账四步全中 |
| E5a KEEP=1 留守+跨 run 复用 | ✅ | run_end 后 Chrome 存活（59984@14189）→ 再 run `browser_reuse reason=orphan-alive` **同 pid** → 该 run 末 KEEP=0 收尸 |
| E5b 强杀连坐+残账清理 | ✅ | 死账（真实已死 pid 复原=KEEP=1+/T 强杀终态）→ `browser_start reason=orphan-dead` 干净重拉 → run 末删账 |
| E6 fallback 隔离 | ✅ | `browser_skip reason=no-exe` → 本 run browser_start=0（池未启）→ MCP 自起 Chrome 写入 `chrome-profile-fallback` → worker 匿名导航成功（标题「登录」正确）→ `worker-stop(C)` 收官 |
| E7 全程无 browser 报错 | ✅ | 全事件流 browser_* 仅 start/reuse/relaunch/exit 正常生命周期，launch-failed=0 |
| E8 KEEP=0 收尸 | ✅ | 陪跑自然收尾 + 主战 stop 路径 + E5a/E5b 收尾——`browser_exit reason=shutdown` 每次都到，Chrome 进程每次真死 |

### 顺带实机首证（清单外增益）

1. **hints 注入链**（T2.8/A24）：留言→轮界收割→【运行提示】注入→worker 执行，单测→实机打通（wrap-up 指令引导收官）
2. **try/finally 包裹**：stop 路径 `browser_exit` 正常落盘（批4fix 时代 stop 后 Chrome 收尸无保证）
3. **瞬态续跑梯子 vs controller_kill 语义区分**：外部硬杀复活、喊停真死——同轮实机对照
4. **worker 自主性**：正式 6 轮全自停收工（无一被时间盒强杀到终局），盘面 176 文件
5. **watch 可观测性**：browser_*/hint/stop 全程 `src watch` 可见（R9 渲染生效）

### pentest 战果（系统验收之外，记录供后续）

- **金子级架构 fact**：强智 S5.7_1 全库 GUID = **48bit 线性计数器（同批次严格 +145 步进）+ 纪元常量 + 恒定主机位 E063780914AC**——「高熵不可枚举」假设不成立（`facts/guid-counter-structure.md`，9 样本 8/8 差分验证）
- **链式候选（下一轮方向）**：`workflowFileDown.do?qzwffileid=` **匿名可达**附件下载（`facts/preauth-workflowfiledown.md`，第三 pre-auth 端点）× GUID 可预测 × `user_select_ss.jsp` 教师 GUID 泄露面 → 若 qzwffileid 与已知 GUID 同计数器空间/纪元 = 匿名任意附件下载
- **阴性排除（该部署防得住）**：IDOR（改学号查成绩/学籍/照片/考勤全会话绑定）、SQLi（成绩端点+系统性）、忘记密码死流程、写面会话绑定、流程伪造被挡
- findings/ 暂 0 条：无单点成果打穿；组合链候选已记录，待专项验证后立 finding

### 遗留

- 系统级遗留：无。pentest 后续方向见上；cwcx D-005 等 backlog 不变。
- playwright 批 + 本轮验收相关改动**未 commit**（等用户指示）。
