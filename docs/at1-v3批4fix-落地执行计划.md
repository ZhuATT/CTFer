# AT1 v3 批4fix 落地执行计划（G7 实抓缺陷修复：R-1/R-3~R-8）

> **定位**：G7 实机复跑（`at1-v3批4-实机复跑测试.md` §9）实抓问题的修复批。本批修 R-1/R-3/R-4/R-5/R-6/R-7（R-8 由 S5 收口）；**R-2 用户拍板不修**（计量是账目问题，读 0 不影响运行）；M5 server、观察者迭代留批5/路线图。
> **基线**：`1f478ed`（批4 竣工 + 交接单，188 测试绿）。
> **状态**:**全批竣工（2026-09-21）——主批 S1-S12（§1）已施工并经实机演练验收（§9.4，含战果 F-001），已 commit+push（`5ae69a2`+`26ef89b`）；续修批 S13/S14/S16（§10，guard 静态检测加固）已施工，S15 tripwire 经讨论撤销（09-22 拍板：现阶段不考虑反注入场景），全量 pytest 237 绿，未 commit。**
> **读法**：主批成果看 §9；**全部问题按发现顺序统一登记在 §9.5（P-1~P-14，含状态）**；续修批（本批最后一段）看 §10（快览 §10.1 / 施工结果 §10.5）。
> **参考调研**：ARTEX（`lernproject/ARTEX-main`，settle 收尾时序/gate-first/具名死因/控制态即时落库）、Cairn（`lernproject/Cairn-main`，cancel-before-attach/取消=贴字条/被取消回合作废不补跑/单管家）、deadend（单进程架构无双跑问题，无可抄机制）、hxbai（反面教材：kill 了事）。

---

## 快览：每张卡一句话（人话版）

| 卡 | 问题哪来的 | 造成了什么 | 怎么修 |
|---|---|---|---|
| **S1** | stop 的老设计只杀 worker，主程序杀完人之后不知道自己该死 | 你按了 stop，程序还接着跑观察者、改图 | 程序在三个关键位置（worker 干完、观察者干完、每轮开头）先看一眼"收到 stop 没"，收到立刻收摊退出 |
| **S2** | 代码只登记了 worker 的进程号，观察者的没登记 | 观察者跑到一半按 stop，没人杀得掉它 | 观察者出生时也把进程号报给监管线程，stop 一到照杀 |
| **S3** | run 就是个普通命令，谁都能多敲一遍，没有"这任务已经有主"的概念（参考项目靠服务器天然单例，我们没有） | 两个程序能同时跑同一个任务目录，互相踩 | 开跑先抢操作系统级文件锁，抢不到就拒启并报出谁在跑；进程死了内核自动放锁，不留死结 |
| **S4** | stop 命令写完停止文件就立刻返回，但程序实际还要几秒才真退出 | stop 一返回你就 run，撞上没退干净的老程序——实机双管道就是这么来的 | stop 之后盯着锁轮询，锁一空=老程序真死了，这才返回；最多等 30 秒，超时报警 |
| **S5** | 轮次编号、"哪条插话读过了"记在内存里，轮末才写盘 | 程序中途死这些就丢——续跑轮号从 1 重来、旧插话重放 | 记一个小账本文件，每跨一步马上写盘；轮号跟着账本走，重启接着编号 |
| **S6** | stop/续跑的语义这次讨论才定稿 | 不写下来，下次还要重新吵一遍 | 把定稿语义（节奏不变式 + "能续则续，续不了则新开"）写进代码注释和本文档 |
| **S7** | guard 从命令里抽 URL 的正则不认识 `$`，把 PowerShell 变量名一起吞进主机名 | worker 正常命令被误判"越界"连拦 5 次，白干 | 正则和两处清洗字符集补上 `$`，碰到就停 |
| **S8** | ~~已撤~~（R-2 用户拍板不修，见 §4） | — | — |
| **S9** | 启动 claude 子进程时没指定编码（hxbai 骨架带来的老毛病），中文 Windows 按 GBK 解 UTF-8 | 交接内容中文变乱码（"已完成"变"宸插畬鎴"） | 加一行 `encoding="utf-8"`，再顺着乱码传播路径排查其他没指定编码的读取点 |
| **S10** | guard 没有角色概念，worker 的禁区规则原样套在观察者自己头上；"Write-Output"（往屏幕打印）被当成写文件 | 观察者干本职工作被记 40 多条违规全是噪声，真信号被淹没 | guard 加角色参数：观察者写自己工作台放行；打印不算写；worker 的规则一寸不让 |
| **S11** | 观察者轮数上限设了 60，但它做的实测验证实验很费轮次 | 第 2 轮观察者干到 61 轮被强停（万幸判断书已写完），烧了 4.67 刀 | **轮次上限取消**（默认不传 `--max-turns`，环境变量仍可主动设限）；成本控制交给时间盒这道硬闸；手册加一句"超过 5 分钟的实验先记账再跑" |
| **S12** | "续跑"现在是新开会话，被杀会话脑子里的计划（worker 的下一步打算、观察者已做的验证实验）全丢 | 续跑后要么重做实验（观察者）、要么丢工作记忆（worker） | 续跑时先试**续接原会话**（机制批4 已造好，观察者回喂在用）：phase 账本存 session_id，能续则续、续不上落回新开；每会话只给一次续接机会 |

---

## 执行协议（新会话开工入口，本文档自含）

1. **读序**：本文档自含——快览表（每卡人话）→ §0 语义拍板 → §1 施工卡 → §2 顺序 → §3 测试 → §4 边界。背景证据按需读 `at1-v3批4-实机复跑测试.md` §9（R-1~R-8 实抓记录），不读也能施工。
2. **纪律**：每卡完成跑全量 pytest（基线 188 绿，只增不减）；**不自动 commit/push**（分组建议见 §2，push 等用户）；文档一律 Write/Edit 工具（bash 内联处理含反引号 markdown 有误建文件事故）；S11 触发汇编↔scaffolding 双写（test_scaffold 一致性锁必须保持绿）；**语义争议一律回到 §0 拍板记录，不重新发明**。
3. **施工顺序**：S7 → S1 → S2 → S3 → S4 → S5 → S12 → S9 → S10 → S11 → S6（S8 已撤销不动）。
4. **终验**：全量绿 + 实机演练——usc-portal-b4 续收 drill：`run` → worker 中途 `stop` → 确认秒退+图冻结+stop 返回时进程已死 → 立即 `run` → 确认干净接力（轮号续接/hint 不重放/断点续会话生效或 fallback）；顺带 F-01（orgtree finding）被观察者审计入图、cwcx+210.43.114.31+172.20.9.43 三新资产开测。
5. **关键事实速查**（动工前已知，勿重复调研）：`runner.Result.session_id` 现成（runner.py:96，init 事件捕获）；`AgentTask.on_spawn` 现成（runner.py:91，run 在 L431 回调）；`OBSERVER_MAX_TURNS` env 化现成（observer.py:20）；`cmd_stop` 现状=写 CONTROL 即 return（__main__.py:324-331）；guard URL 正则 `https?://\S+`（guard.py:36）；worker Popen 缺 encoding（runner.py:420，hxbai 骨架遗传）；轮号是进程内变量从 0 起（driver.py:358）。

---

## 0. 事故复述与语义拍板

**事故**（2026-09-20 实机，auto-log 06:29 段）：操作员 `stop` → watcher 杀 worker 树 → **driver 不退，继续补跑该轮观察者**；操作员 30 秒后 `run` 续跑 → 新旧两套 driver+claude 并发同一 engagement（实抓 4 python + 2 claude）。且无任何机制防双跑。

**语义拍板**（用户定，参考项目背书）：

- **stop** = 杀当前会话（worker 或观察者）+ **进程立即退出**；图与盘面冻结在被杀瞬间，一个字不动。
- **续跑（run）** = 新进程，从节奏**开头**重新开始。**没有"补跑"概念，只有"节奏重新开始"**。会话策略（S12 追加，用户拍板）：**能续则续，续不了则新开**——被中断的 worker/观察者优先续接原会话（保留工作记忆与已做实验），续接失败落回新开；无论哪种，节奏与图语义不变。
- **上轮观察者没干完怎么办**：观察者的活是"算"出来的（读全部材料→结尾一次交判断书），中间没有可保存进度；被杀=本次审计未发生，材料全在盘上，下轮结束的无状态全量盘点一起审。**"永远新 worker 接"是架构不变式**，不是简化——图只在轮末入图时变 + worker 产出即时落盘 + 审计是无状态纯函数，三条保证任何中断点都塌缩回"上一个完整轮边界"。
- **所有权**：任何时刻一个 engagement 只有一个活实例。ARTEX/Cairn 靠"服务器天然单例"，我们靠锁文件外置同等约束。

**与 M5 的关系**：锁=未来 server 的所有权凭证；phase 账本=未来状态机的崩溃恢复日志；CLI=未来薄客户端。本批全部产物按"会被 server 收编"的形状做。心跳/健康/重连/恢复四件套我们已背本地版（内核进程语义+呆滞双阈值+preflight），分布式税按路线图进阶档逐项缴，不预支。

---

## 1. 施工卡

### S1 停机字条三道门（核心）

**改**：`src/driver.py`。watcher 置位的 `flag`（`_consume_stop_file`，L110-132）现在只在循环顶（L389-393）被看。补两道门：

1. **门 A**：`runner.run()` 返回 + `session_end` 事件之后、目录页/观察者块（L456 起）之前——`flag["hit"]` 为真则 `bb.save()` → `run_end(reason="control-stop(W)")` → break。（W=killed in Worker phase）
2. **门 B**：`observer.run_once()` 返回 + `observer_session_end` 事件之后、`apply_judgment`/STATE 写入之前——同上，`reason="control-stop(O)"`。（O=killed in Observer phase；判断书未入图即作废，`.observer/` 草稿留下次审计开工时 `clear_judgment` 清）

循环顶的门（已有）保留，reason 仍是 `control-stop(D)`（D=detected at boundary）。三个死因名对齐 ARTEX 具名死因思想，事件账目可分辩。

**验收**：stop during worker → 无观察者 spawn、图字节不变、run_end 带 reason；stop during observer → `apply_judgment` 未调用、STATE.md 未写。

### S2 观察者挂进 watcher 射程

**机制现状（登记簿杀人）**：监视线程杀的是 `proc_ref` 登记簿上的进程。worker 出生时经 `on_spawn` 回调登记（runner 现成机制，runner.py:91/431）；**观察者出生时没登记**——stop 到达时登记簿上躺着的是 worker 的尸体。

**事故推演（观察者跑动中按 stop）**：监视线程对尸体补刀 → 观察者毫发无伤继续跑完实验（实测 r2 观察者 7.5 分钟/$4.67）→ 判断书写完 → **入图改图** → 直到下一圈开头才看到标志退出。三条全违反拍板语义（杀当前会话/进程即退/盘面冻结）。

**附带埋伏**：死 worker 的 PID 被操作系统回收复用后，taskkill 按 PID 杀树会误杀无辜进程。低概率、极难排查，同根因一并堵。

**改**：
1. `src/observer.py` `run_once`（L100）签名加 `on_spawn=None`，透传给它内部构造的 `AgentTask`（字段现成，零 runner 改动）；**retry 路径（resume feedback 那次调用）同样传**
2. driver 观察者块传入与 worker 相同的 `proc_ref` setter——登记簿上永远躺着当前活着的会话
3. `_controller_kill` 补一行保险：`proc.poll() is not None`（已退出）跳过杀，杜绝 PID 复用误杀

**修后推演**：stop → 0.5s 内观察者全家被杀 → `run_once` 返回（被杀态）→ 撞 S1 门 B → 不入图不写 STATE → `bb.save` → 退出。盘面精确冻结在按下 stop 的一刻。

**与 S1 的分工**：S1 管"阶段之间"（worker 死了、观察者没生——别生下一胎直接退）；S2 管"阶段进行中"（谁在跑杀谁）。合起来才是完整的 stop。

**验收**：观察者跑动中写 CONTROL → 观察者进程树被杀（FakeRunner 的 on_spawn 挂真子进程验证）、门 B 生效不入图；`_controller_kill` 对已退出 Popen 不动作（PID 复用夹具）。

### S3 run.lock：engagement 所有权锁

**改**：新增 `src/runlock.py`（~60 行）：
- `acquire(root)`：打开/创建 `.at1/run.lock`，Windows `msvcrt.locking(LK_NBLCK)` / POSIX `fcntl.flock(NB)` 抢**内核级**锁；抢到→截断写入 `{pid, started_at, cmd}`，返回句柄；抢不到→返回 None（读出现有内容供报错）。
- `release(handle)` / `read_info(path)`。
- 关键性质：**锁的存在性=内核管的**，持锁进程死（含被杀/崩溃）内核自动放锁——不存在"死锁残尸"。文件存在但无锁=上次异常退出的残文件，直接覆盖即可，不构成阻塞。
- `cmd_run`（`__main__.py`）preflight 通过后 acquire；失败→`[run] 拒启：engagement 已有实例（PID x，自 yyyy-mm-dd hh:mm）`→非零退出。句柄随进程生命周期持有，finally 里 release。

`.at1/` 是控制器区，guard 本就禁 worker 写，位置天然安全。

**验收**：双 run 并发→第二个拒启带 PID；模拟崩溃（进程被杀）→锁自动可抢。

### S4 stop 等进程死透才返回

**现状毛病（时间线）**：

```
敲 stop → 写 CONTROL → 命令返回                        ← 0.1 秒，"停止"完成？
   run 程序：watcher 每 0.5s 才看一次 → 杀 worker 树（几秒）→ 主线程收尾退出 ← 2~10 秒后才真死
```

stop 在第 2 步就返回，程序第 5 步才死——中间 2~10 秒是"你以为死了其实还活着"的窗口。**实机双管道事故就是这个窗口里的 run 撞上的。**

**改**：`src/__main__.py` `cmd_stop`（L324-331，现为写完 CONTROL 立即 return）：
1. 写 CONTROL（原样）
2. **不返回，轮询 `runlock.acquire()`**（非阻塞，0.5s 间隔，上限 30s）——抢到=持锁进程已死（内核保证：进程死锁必放，无第三种状态）；抢到后立即 release
3. 30s 超时 → 大声报警 `[stop] ⚠ 实例（PID x）30s 未退出，仍在收尾——可 taskkill /F /PID x 强清`，非零退出码。**不偷偷强杀**——卡住的原因值得人看一眼
4. 成功 → `[stop] 实例已退出，盘面冻结于 <phase>`（从 phase.json 读，见 S5）

**三个设计点**：① 抢锁当死亡信号——锁是内核管的，存活判定 100% 可靠，零探活代码；② 不用 PID 直接等——Windows PID 会回收复用，可能等错对象，锁探测完全绕开；③ 超时报警不装死——系统不替用户做主强杀。

**新契约一句话：stop 命令返回的那一刻，保证该 engagement 无任何活进程。**

**白赚的幂等行为**：没程序在跑时敲 stop → 首次试探就抢到锁 → 立即返回"没有在跑的实例"；连敲两次 stop → 都写同一 CONTROL（幂等）都正常返回，无害。

**事故回放验证**：有了 S1+S4，当时的操作序列下 stop 会等老进程真死（配合 S1，杀完 worker 几秒内退）才返回，30 秒后的 run 起点干净；就算老程序卡死 30 秒，run 也被 S3 锁拒启。**双管道两个方向都堵死。**

**验收**：真子进程慢退出场景，stop 的返回时刻晚于进程死亡时刻；超时路径有报警；无实例时幂等返回。

### S5 phase 账本 + 控制状态即时落盘（收 R-6）

**改**：
- **`.at1/phase.json`**：`{"phase": "working"|"auditing", "round": N, "updated_at": iso}`。写入点=每个阶段转换：session_start→working、观察者 spawn→auditing、轮末入图完成→working（下轮）、stop 退出路径→补一次。进程启动时若已存在→`ev.emit("interrupted_phase", ...)` 记一笔"上次中断于 auditing r3"再覆盖——中断可诊断，不再靠猜。
- **轮号续接**：`rnd` 从 `bookkeeping["round"]` 续（当前是进程内变量从 0 起，driver.py:358——续跑轮号重置为 1 的根因）。每轮入图时 `bk["round"]=rnd` 随 bb.save 持久。
- **hint 偏移即时落盘**：循环顶收割完 hint（消费 offsets）立即 `bb.save()`（现在只在轮末 L557 存——续跑重放旧插话的根因）。scope 播种后同样补一次 save（**R-8 由此收口**：关键簿记变更即落盘原则落地）。
- **verify_fact 轮窗专项复核**：轮号续接后 offsets 窗口是否仍对齐（测试锚定：跨进程续跑后轮窗抽验不串号）。

**验收**：续跑后轮号接着走、旧 hint 不重放、phase.json 五个转换点全部留痕、中断可从 phase.json 读出。

### S6 不变式落档

**改**：`src/driver.py` 模块 docstring 写入停机/续跑语义（节奏不变式："图只在轮末变、审计全量、中断塌缩到完整边界" + 会话策略："**能续则续，续不了则新开**"（S12）+ 三死因命名）；本文档即语义权威记录。不加测试（纯文档），但 S1/S5/S12 的行为测试即其锚。

### S7 guard `$` 终止符（R-5）

**病灶**（实机 06:11-06:14，worker 连吃 5 次 scope 误拦）：worker 写 PowerShell 变量拼接 URL：

```powershell
$u = "/api/xxx"
curl.exe ... "https://myportal.usc.edu.cn$u"     # ← 域名和 $u 粘连
```

`src/guard.py:36` 的 `_URL_STRIP_RX = re.compile(r"https?://\S+")` 把 `https://myportal.usc.edu.cn$u` 整串当 URL 抓出来（`\S+` 不认 `$` 是终止符），`urlsplit().hostname` 吐出 `myportal.usc.edu.cn$u`，后缀匹配 allow 失败 → `allow 外目标` 误拦。与批3fix P-1（引号分号尾巴）、P-5（反斜杠双缝）同族：**主机名解析的终止字符集不全**，第三刀。

**改**（三处，belt + 裤带 + 背带）：
1. `guard.py:36`：`r"https?://[^\s$]+"`——匹配在 `$` 处截断
2. `check_url` 调用点的 `.rstrip("\"';,，。)）]")` 补 `$`
3. `_host_of` 的 `.strip("'\";:,.()（）")` 补 `$`

**零误伤论证**：host 永远位于 URL 中任何 `$` 之前（`$` 合法出现在 path/query，不合法出现在 netloc 尾部粘连处）；scope 只看 hostname，截断匹配损失的只是 path 段文本——所以截断不影响任何合法判定。OData 类真带 `$` 的 path（`/api/$batch`）host 不受影响。

**验收**（guard 单测新增）：
- `curl "https://myportal.usc.edu.cn$u"` → 放行（host=`myportal.usc.edu.cn`）——实机事故回归锚
- `https://myportal.usc.edu.cn/api/x` 等常规 URL 判定不变
- `https://host/api/$batch`（真 `$` 在 path）→ host 仍=`host`
- deny 表在 `$` 粘连场景下仍命中
- P-1 老案例（`https://h.example';`）不回归

### S8 worker 计量断流（R-2）——**已撤销，不修**

**用户拍板（2026-09-21）**：计量提取不出来没关系，不影响架构跑起来。session_end 记 0 只是账目难看，轮次/成本核算不依赖它。留档：r1 正常（53t/2.55M/$2.49）、r2 起 0 的现象与 `usc-portal-b4/.at1/transcript.jsonl` 里的真实事件都在，将来要做成本核算时再启用诊断（方法已写在 git 历史的本卡：r1/r2 事件逐字段对比→补解析分支→真实行夹具）。

### S9 stdout 编码修复（R-3）

**病灶**：`src/runner.py:420` `subprocess.Popen(..., text=True, bufsize=1, errors="replace")`——**没指定 encoding**，Windows 中文环境 text 模式按 locale（GBK）解码 claude 的 UTF-8 stdout。hxbai 骨架同款（ccrunner.py `text=True, bufsize=1`），骨架遗传 bug。auto-log 里 handoff head 的 mojibake（"宸插畬鎴愶細"="已完成："的 UTF-8 被当 GBK 解）即此来源候选。

**改**：
1. Popen 补 `encoding="utf-8"`（stdout/stderr 一处搞定）
2. **诊断定位**：拿 r1 transcript 里 worker 最终消息原文 vs auto-log 的 head 对比——若 transcript 干净而 head 坏，再排查 transcript **读回**路径是否有 `open()` 缺 encoding 的点（候选：从 transcript 文件提取 handoff 的读取处）；若 transcript 本身坏则是上游。两处都修到夹具过为止。

**验收**：夹具子进程输出 UTF-8 中文 → 提取的 handoff 中文原样；auto-log 中文事件不再 mojibake。

### S10 guard 观察者角色豁免（R-4）

**现象**：42 条 guard 事件绝大多数是噪声——观察者写**自己工作台**（`.observer/`）、纯读命令（`Get-Content`/`node -e readFileSync`）全被"疑似写控制器区"标记；观察者写白名单产物 `notes/prior-intel-draft.md` 也标。根因：`check_tool` 无角色概念，worker 的禁区规则原样套在观察者头上；写动词启发式把 `Write-Output`（控制台打印）当写文件。

**改**（`src/guard.py` + driver 两个挂点）：
1. `check_tool(tool, args, role="worker")` 加角色参数；**observer 角色对自家可写集豁免**：`.observer/`、`STATE.md`、`notes/prior-intel-draft.md`（与 observer.py 手册声明的可写面一致）
2. 命令文本写动词启发式收紧为词边界真写动词（`Set-Content|Out-File|New-Item|Add-Content|Remove-Item|curl -o/-T|>` 重定向…），排除 `Write-Output`/`Write-Host`
3. driver 两个 on_fact 挂点分别传 `role="worker"` / `role="observer"`（事件里的 role 字段已经有了，判定侧补齐）
4. **worker 侧行为一寸不让**：worker 写 `.observer/` 照旧拦截（禁入纪律）

**验收**：auto-log 里五类真实误报形态做回归夹具（观察者写 `.observer/`×3、观察者纯读×2 → 全放行）；worker 写 `.observer/` 仍拦。

### S11 观察者取消轮次上限（R-7，用户拍板：不设限）

**现状**：`OBSERVER_MAX_TURNS` 常量+env 化已存在（observer.py:20，默认 60），`runner._build_argv` 把 `--max-turns` 硬拼进命令行（runner.py:377）。r2 观察者 61 turns 跑满被截停（判断书仍完整受理=防线工作），耗时大头是 liveness 类长实验。

**改**（用户拍板：观察者**不限制轮次**）：
1. `OBSERVER_MAX_TURNS` 默认 60 → **0**，语义=不限制：`runner.run`/`_build_argv` 对 `max_turns` 为 0/None 时**不拼 `--max-turns` 参数**（claude 自身无轮数硬限）
2. **成本兜底边界说清**：轮次不设限后，观察者的成本硬闸=时间盒（`OBSERVER_TIMEBOX_S` 默认 1800s，已有），超时照杀、盘上草稿全留——失控半径从"60 轮"变成"30 分钟"，可接受
3. env 覆盖保留：想设限仍可 `AT1_OBSERVER_MAX_TURNS=100`（非 0 即按老逻辑拼参数）
4. OBSERVER-MANUAL.md 加实验预算指引一句：超过 5 分钟的实测实验（liveness/延时重放类），先在判断书里把方向记成 intent 再跑，跑不完留给下轮——**汇编双写**（执行协议规则 4，test_scaffold 一致性锁保持绿）

**验收**：默认配置下 spawn 的观察者命令行**不含** `--max-turns`（单测断言 argv）；设 env 时参数照拼；一致性锁 3 断言绿。

### S12 断点续会话（用户追加：观察者断观察者接、worker 断 worker 接）

**依据**：机制全部现成——`runner.Result.session_id`（runner.py:96，init 事件捕获）+ `run()` 断点续跑（`--resume`，runner 文档字符串明确设计意图="仅异常终态续"）+ 观察者空判断回喂路径现役在用。本卡零新机制，只把"被杀"正式归类为 runner 预留的"异常终态"。

**改**：
1. **phase.json 加字段**（扩展 S5）：`{"phase", "round", "session_id", "role", "updated_at"}`——两侧 session_id 均现成（runner.Result），spawn 时写入
2. **触发条件 = phase.json 残留**（上次进程未走到干净收尾）——一个条件天然覆盖 stop/崩溃/TaskStop/断电，不用按死法写分支。**天然排除时间盒杀 worker**：时间盒是设计好的轮出口且进程不退出、轮照常走观察者——若时间盒也续，worker 永远赖着不走，轮节奏即毁。此边界写死
3. **启动接力路径**（driver，seed 之后、正常派工之前）：phase.json 残留 → 读 phase+session_id → **尝试续接（只一次）**：
   - `phase=working` → `runner.run(resume_session_id=…)`，注入语三件套："你被停机中断过，继续收尾本轮；盘面/图只在上轮末更新过；**以下轮 CLAUDE.md/简报为准（scope 可能已变）**，凭证可能过期按手册自行恢复"
   - `phase=auditing` → `observer.run_once(resume_session_id=…)`，注入："审计被中断，已做的验证不必重做，继续完成判断书并 submit"
   - 续接失败（session 不存在/截断损坏/报错）→ `resume_fallback` 事件 → 落回老路径（新开 worker/重新全量审计）。**永不循环**——与批3 P-11 复活梯子的三点区别：只在 operator 主动 run 时发生 / 只试一次 / 每步事件留账
4. **语义对齐（S6 措辞）**：节奏不变式不动（图只在轮末变、审计无状态全量、中断塌缩到完整边界）——S12 只是"塌缩后那个会话"从"新开"升级为"尽量续接"；最坏情况=现状，不存在更坏。观察者审计即使新开也依然正确（全量盘点不依赖记忆）
5. 旧档案无 session_id 字段（本批之前）→ 直接走老路径，天然兼容

**风险与对策**：被杀会话 transcript 截断，`--resume` 加载截断 jsonl 理论可行（append-only）未实测——"只试一次+fallback"因此是必须的保险而非优雅。续接不产生新成本类（每轮本就重喂全部上下文），省的是观察者重做实验与 worker 工作记忆。

**账本归属与 M5 去向（09-21 讨论定稿）**：账本唯一写者=当前 `run` 进程（worker/观察者是 guard 禁区、CLI 只发指令、run.lock 保证独占——文件本身无需锁）。M5 大进程（把整个 run 收编的常驻 server：控制面 API + 内存状态机 + spawn 一次性会话）落地后，写它的手和写点纪律**原样平移**，账本从"状态唯一载体"降级为"大进程的崩溃恢复日志"——大进程也是进程也会死，"从哪接着来"的记忆只有账本承载。不会被黑板吞（治理所有权分离：图归观察者管辖、账本是控制器私有运行态），不换 SQLite（多任务并行的进阶档税；单任务下 JSON 人眼可读依旧最优）。

**验收**：
- worker 会话被杀 → 续跑时命令行带 `--resume <id>`、注入语在 prompt 里、续接成功完成本轮（FakeRunner 锚）
- 观察者被杀 → 续接后不再重跑已完成的验证（以会话上下文存在为断言）、判断书正常提交
- 续接失败（FakeRunner 抛错）→ 落回新开、`resume_fallback` 事件留痕、只试一次不循环
- phase.json 无 session_id 的旧格式 → 走老路径不报错

---

## 2. 施工顺序与依赖

```
S1（门）──┐
S2（射程）─┴─→ 语义闭环（R-1 本体）
S3（锁）──→ S4（stop 等待）──→ 操作层闭环
S5（账本）──→ S12（断点续会话，依赖账本里的 session_id）──→ R-6 闭环 + 接力升级（R-8 一并收口）
S7（guard $）─┐
S9（编码）────┼─→ 小件包（各自独立，实机证据齐全）
S10（角色）───┤
S11（轮数）───┘
S6 收尾
```

每卡完成跑全量测试；不自动 commit。建议三个 commit：**R-1 本体（S1-S4）/ R-6+接力（S5+S12）/ 小件包（S7+S9+S10+S11）**——或一次性，动工前问。

## 3. 测试计划

- 新增行为测试（沿用现有 FakeRunner/FakeObserver 替身模式）：
  - stop during worker：无观察者 spawn、run_end reason=control-stop(W)、图不变
  - stop during observer：观察者被杀（on_spawn 挂真 Popen 验证树杀）、apply_judgment 未调用
  - 双 run：第二个拒启含 PID；无锁残文件可正常启动
  - stop 等待：返回时刻≥进程死亡时刻；超时报警路径
  - phase.json 转换点留痕；续跑轮号续接；hint 偏移跨进程不重放
  - S12：被杀 worker 续接（--resume + 注入语）、被杀观察者续接（不重做已做验证）、续接失败落回新开只试一次、旧格式无 session_id 兼容
  - guard `$` 粘连五例（S7 验收清单）+ P-1 老案例回归
  - S9：UTF-8 中文经 stdout→handoff 提取全链路不坏
  - S10：auto-log 五类真实误报形态放行 + worker 写 `.observer/` 仍拦
  - S11：默认 argv 不含 `--max-turns`；env 设限时照拼；汇编↔scaffolding 一致性锁绿
- 全量 pytest 绿（188 基线 + 新增）
- **实机演练**（G 级验收）：usc-portal-b4 续收——run → worker 中途 stop → 确认秒退+图冻结 → 立刻 run → 确认干净接力（轮号续、无 hint 重放）；顺带 F-01（orgtree finding）被下轮观察者审计入图，三个新资产开测。

## 4. 明确不做（本批）

| 项 | 去向 |
|---|---|
| **R-2 worker 计量断流** | **用户拍板不修（2026-09-21）**——账目问题非架构问题，session_end 记 0 不影响运行；将来要成本核算再启用诊断（方法留档 S8 卡） |
| M5 server（daemon/UI） | 路线图 M5；本批产物为其地基（锁=所有权、phase=恢复日志、CLI=薄客户端） |
| 观察者迭代（判定质量精进、G-4 清单） | **批5 本职**——批4fix 收完缺陷，批5 回归观察者与下一轮实机复跑验收 |
| audit-first 续跑策略（续跑先补审计） | 不做，"永远新 worker 接"是不变式；phase.json 留了将来加开关的余地 |
| 心跳/健康/重连的分布式版 | 路线图进阶档（远程访问/多任务并行时逐项缴税） |
| commit / push | 全部等用户指示 |

---

## 9. 施工结果（回写区）

**施工完成（2026-09-21）。全量 pytest 222 绿（基线 188 + 新增 34）。未 commit。**

### 9.0 各卡落点

| 卡 | 落点 | 测试锚 |
|---|---|---|
| S7 | `guard.py`：`_URL_STRIP_RX`→`[^\s$]+`、`_host_of` strip 补 `$`；**rstrip 未补 $（见 9.1 拍板）** | test_guard 5 例（$u 粘连/常规不变/path $batch/deny 命中/P-1 回归） |
| S1 | `driver.py` 门 A（worker 后，W）/ 门 B（observer_session_end 后，O）；循环顶既有门（D）保留 | test_stop_during_worker_gate_w / gate_o |
| S2 | `observer.py` run_once 加 `on_spawn` 透传；driver 观察者两处调用（initial/retry）挂 proc_ref setter；`_controller_kill` 已退出跳过（非 Popen 按活者处理） | gate_w/gate_o 内真子进程树杀断言 + test_controller_kill_skips_dead_proc |
| S3 | 新增 `src/runlock.py`（msvcrt/flock 内核锁；**锁字节在 offset 4096**——Windows msvcrt 是字节区间锁，锁 offset 0 连本进程其他句柄都读不了持有者信息）；cmd_run 抢锁拒启 | test_runlock 5 例（双抢/崩溃放锁/残文件幂等） |
| S4 | `cmd_stop` 重写：写 CONTROL 后轮询锁（0.5s 间隔，`AT1_STOP_WAIT_S` 可调默认 30s）——抢到=实例必死；超时报警非零退出不强杀；无实例幂等 | test_stop_returns_only_after_instance_dead / timeout_warns / idempotent / frozen_phase |
| S5 | 新增 `src/phase.py`（.at1/phase.json 账本）；driver 转换点①session_start→working ②观察者 spawn→auditing ③轮末→working(清 sid) ④门A/门B stop 补一次；`bk["round"]` 持久（board.py `_load`/`__init__` 补键）；hint 偏移收割即落盘；scope 播种即落盘（R-8 收口）；启动读残留→`interrupted_phase` 事件 | test_phase_ledger_transitions_and_clean_clear / round_number_continues_across_restart / hint_offset_persists_immediately_and_no_replay |
| S12 | runner `AgentTask.on_session_id` 回调（init 事件即回调——spawn 中途落账本，Result.session_id 要等会死才拿到）；phase.json 存 session_id/role；working 残留→worker 续接（注入语三件套）；auditing 残留→跳过本轮 worker 派工、观察者续接（`resume_prompt` 注入语）；失败（抛错/is_error）→`resume_fallback` 事件→落回新开，只试一次；干净收尾清账（control-stop 有意留残留=触发器）；旧格式无 session_id 天然兼容 | test_worker_resume_after_kill / observer_resume_after_kill_skips_worker / resume_fallback_once_on_spawn_error / on_error_result / old_phase_format_without_session |
| S9 | `runner.py` Popen 补 `encoding="utf-8"`；preflight 两处 subprocess.run 补 encoding；全仓读点排查：其余 open/read_text 全带 encoding（harvest.py rb=二进制、runlock fdopen 已带），mojibake 唯一来源即 Popen | test_popen_decodes_utf8_chinese_end_to_end（真子进程 UTF-8 流→handoff 原样 + encoding 参数在场的回归锚） |
| S10 | `guard.py` `check_tool(tool, args, role="worker")`；观察者豁免自家可写集（`.observer/`、STATE.md、notes/prior-intel-draft.md——剥掉可写集残留再查禁区，出界照拦）；写动词启发式收紧（删裸 `\bwrite`/\bsave/\bcreate\b/\bedit\b，补 new-item/curl -o/-T；Write-Output/Write-Host 不再匹配）；worker 侧默认 role 一寸不让 | test_observer_own_workspace_exempt（五类实抓形态）/ observer_outside_own_workspace_still_flagged / worker_observer_zone_still_blocked / write_verb_heuristic_tightened |
| S11 | `OBSERVER_MAX_TURNS` 默认 60→0（env 覆盖保留）；`_build_argv` 对 0/None 不拼 `--max-turns`；OBSERVER-MANUAL 加实验预算一句（**汇编↔scaffolding 双写**，一致性锁绿） | test_build_argv_max_turns_zero_means_unlimited / observer_max_turns_default_unlimited / env_override |
| S6 | driver 模块 docstring 落档：节奏不变式/会话策略/三死因命名（本计划 §0 为语义权威） | S1/S5/S12 行为测试即其锚 |

### 9.1 偏离拍板记录（施工中经用户确认）

- **S7 改法 2（调用点 rstrip 补 `$`）砍掉**：正则改后匹配串永不含 `$`，rstrip 的 `$` 一次都摸不到=纯死代码（P-1 的 `';` 在 rstrip 是活的——正则放行引号分号；性质不同）。用户拍板：砍改法 2，留改法 1（正则=真修复）+ 改法 3（`_host_of` strip=护直连 url 参数入口）。
- **S3 锁字节 offset 4096**：计划未预见的 Windows 细节——msvcrt.locking 是字节区间锁，锁 offset 0 会把持有者信息一起锁死（本进程其他句柄都读不了，read_info 全 None）。信息区在文件头、锁字节放 4096（区间允许超 EOF），POSIX flock 锁整文件不受影响，两平台行为归一。
- **S12 会话句柄需要新回调**：计划的"runner.Result.session_id 现成"只在会话结束后成立；spawn 中途被杀时要落账本必须有 init 事件即回调——`AgentTask.on_session_id` 三行新增，runner 改动最小化。
- **schema 契约同步**：`contracts/blackboard.schema.json` bookkeeping.properties 补 `round`（integer，不进 required——旧档案兼容）。

### 9.2 测试替身连带改动

- FakeRunner `__call__` 补 `resume_session_id` 捕获；FakeObserver `run_once` 补 `on_spawn`/`on_session_id`/`resume_prompt`；test_observer_channel 的 FakeObs 同步签名。

### 9.3 遗留与去向

| 项 | 去向 |
|---|---|
| ~~实机演练~~ → **已完成**（见 §9.4），usc-portal-b4 的 F-01 入图改在新靶 usc-cwcx-b1 完成（用户换目标） | — |
| commit / push | **已完成**（2026-09-21：G7 遗留文档 `5ae69a2` + 批4fix `26ef89b`，已推送 origin/main） |
| verify_fact 轮窗专项复核 | 机制本体已随批3fix 配方 1 退役（events.py 仅存登记）——落地为两条测试锚：hint 偏移跨进程不重放 + 轮号续接 |
| 观察者迭代（判定质量精进、G-4 清单）、M5 server | 批5 / 路线图（§4 不变） |

### 9.4 实机演练记录（2026-09-21，新靶 usc-cwcx-b1=cwcx.usc.edu.cn 智慧财务管理平台）

> 用户换新目标（usc-portal-b4 三新资产之一），小目标=LoginSSO 签名 SSO + 收费查询面。
> 共 2 个 run 进程 / 3 轮 / 总成本 $11.15，stoploss 收尾（该收尾后被判为误杀，见 §9.5 P-14），**confirmed=1（F-001）**。
> 演练中暴露的问题全部统一登记在 §9.5（P-1~P-10），此处不重复。

**批4fix 验收点实机结果**：

| 验收点 | 结果 |
|---|---|
| S1 门 W（worker 阶段 stop） | ✅ stop 发出→1.6s 返回，run_end=control-stop(W)，无观察者 spawn，STATE 未写，stop 后盘面静止 |
| S4 stop 等死透 | ✅ 报文"实例已退出（等了 1s），盘面冻结于 working r1"——返回时刻=进程死亡时刻 |
| S3 双开拒启 | ✅ 实例运行中第二个 run 拒启带 PID+启动时间，原实例无损 |
| S5 phase 账本 | ✅ working/auditing 转换、on_session_id spawn 中途落账、干净收尾清账（stoploss 后 phase.json 消失）、run.lock 残文件无害 |
| S12 worker 续接 | ✅ working 残留→interrupted_phase(has_session=True)→resumed=True→**同 session_id 续上、零 fallback**——真 --resume 吃下被 taskkill 杀断的会话 |
| S12 时间盒边界 | ✅ r2 worker 时间盒被杀→进程不退出→轮照走观察者→不触发续接（设计边界实机成立） |
| S9 中文编码 | ✅ 三轮 handoff 中文逐字正常（auto-log 与 transcript 对照），R-3 mojibake 根治 |
| R-2 计量断流 | 按 S8 拍板不修——r2 worker session_end 记 $0/0 turns，现象与上批一致，运行不受影响 |
| S1 门 O + S2 杀观察者 + S12 auditing 续接 | **未实机验**（P-4）——单测已覆盖；下个 engagement 盯 `phase.json` 转 `auditing` 打 stop 一次补齐 |
| S11 观察者不限轮 | argv 无 --max-turns 已单测锚定；实机 r3 观察者 53 turns 未越旧限 60，未构成直接观察（P-5） |

**战果摘要**（详情见 engagement 盘面）：F-001=`/cw/Cwzccx_dz.asp`+`/cw/Cwzccx_th.asp` 双页完全无鉴权，匿名拉全校已到账明细 203 笔 ¥2271 万（含军工课题经费关联）+退回明细 532 笔（个人实名）。LoginSSO mac 结论：确定性可重放、只绑 username、不绑 sj/ts/appId（盐未破不立 finding）。r3 末 AC cookie/h5token 双死（worker 正确置 blocked 不空转，见 P-10）——**下次续跑前需操作员重新登录刷新 storage-state.json**。

### 9.5 问题登记总表（实机暴露 + 续修批施工中暴露，按发现顺序，一处说完）

> 状态口径：✅已修（含回归锚）｜☑已结案（含拍板）｜⏳待办。正向确认（P-9/P-10）一并登记防散失。

| # | 问题 | 根因 | 处置 | 状态 |
|---|---|---|---|---|
| P-1 | guard 误报 26/28 条：①绝对路径写自家工作台被拦（19 条）；②`[System.IO.File]::ReadAllText` 读被当写；③拼接符粘连（`"https://x"+$p`、`curl "https://x"&echo hi`）。其中①②是 S10 施工 bug | 单测夹具全是相对路径理想形态，实机形态一个没盖住；豁免正则与禁区正则各认一套形态 | 当日修：截断式可写集 + 删裸 `[io.file]` 前缀 + `_host_of` 截断式清洗；续修批 S13/S14 进一步换成**路径代数 + 归一化 token 判**（§10）。另加**对账锁** `test_observer_writable_set_contract`：手册可写面声明钉成用例，手册↔guard 漂移即红 | ✅已修（三实机形态原样入库 test_guard.py；237 绿） |
| P-2 | scope 误报：host 解析成 `{`（1 条，r2 worker） | PowerShell 子表达式 `"…{$x}…"` 形态，截断类没含 `{}` | S16：截断类补 `{}[]` | ✅已修（test_host_braces_truncated_p2） |
| P-3 | guard 修复下个进程才生效，演练中 r2/r3 旧 guard 继续误报 22 条 | 进程级快照（代码在进程里的自然语义） | ☑已结案（用户拍板）：接受该语义——guard 是记录员不拦人，代价只是日志脏；"换规则立即生效"= stop→run，S12 断点续会把重启成本压到≈0；**不建"补判"回放工具** | ☑结案 |
| P-4 | 观察者半场三件套未实机验（S1 门 O / S2 杀观察者 / S12 auditing 续接） | 两次都错过观察者窗口（3~8 分钟难掐；r3 观察者跑完即 stoploss 收尾） | 单测已覆盖；**待补测**：下个 engagement 盯 `phase.json` 转 `auditing` 打一次 stop，三件套全覆盖 | ⏳待办  **补测执行单=`v3批4fix实机测试计划.md`（2026-09-22 已写，等用户给目标）** |
| P-5 | S11"不限轮"无直接实机观察（r3 观察者 53 turns < 旧限 60） | 未被自然越过 | argv 无 `--max-turns` 已单测锚定；遇长审计自然越过即为实机证 | ☑结案（低价值） |
| P-6 | 观察者成本逐轮上涨（$1.23→$1.69→$2.84，r3 达 10.7M tokens 超同轮 worker） | 无状态全量审计固有成本：图和产出越大重读越多 | 批5 本职：任务单分诊（只深审 new_or_changed）、验证结论复用（G-4 清单） | ⏳批5 ；**用户拍板（09-22）：审计贵是设计使然，接受——优化杠杆在 worker 写的质量，不急** |
| P-7 | cookie 死亡恢复是人工舞步（重登→抠 cookie→写 storage-state→重启） | 登录态在 storage-state 而非活浏览器 | **playwright 升级批正解**：持久 profile + KEEP=1，人工登录一次跨轮跨 run 存活 | ⏳playwright 批 ；**用户拍板（09-22）：留到 playwright 批一起做** |
| P-8 | R-2 计量断流复现（r2 worker session_end 记 $0/0 turns） | S8 墓碑卡已录的诊断项 | 按拍板不修，现象稳定不影响运行 | ☑结案（拍板） |
| P-9 | （正向）scope 真阳性工作正常 | — | r2 worker 探测厂商域名 `www.wangcai.cc` 被正确拦（allow 外）——28 条里唯一真阳性 | ☑确认 |
| P-10 | （正向，2026-09-22 部分更正）记账纪律成立；~~判停~~一条移 P-14 | — | ①画像换代链完整（T-001→T-002→T-007→T-010）；②cookie 死后 D-003/D-004 置 blocked **已逐条核实**：blocked_reason 带可检验解锁条件，且是观察者重放 ssoLogin 确认 cookie 真死才记账（先验证后入图），r3 交接"门检确认双死，未空转"，同轮仍产出 SQLi fact+四条阴性；③判断书三轮零 rejects | ☑确认 |
| P-11 | **scope 可被 `[]` 整对绕过（真绕过，非误报）**：`urlsplit("https://evil.com[x]")` 抛 Invalid IPv6 → 旧代码 except→空 host→按"本地路径"放行，任何越界 URL 挂 `[]` 即免检（含元数据端点形态） | 续修批 S16 测试 `[]` 截断时抓到 | S16 一并修：except 分支兜底手工解 netloc 再进同一截断清洗；本地路径宽松语义不变（阴性对照锚定） | ✅已修（test_malformed_netloc_scope_bypass_fixed） |
| P-12 | **观察者豁免正则吞并嵌套禁区引用（真漏判）**：`.observer/../.at1/x.json` 被 `\.observer[/\\][^\s]*` 一口吞掉→逃过禁区判定 | 整串贪婪匹配能跨 `..`；"宽于 zone 是死支"的假设错误 | 续修批 S13/S14 修：豁免改**逐 token 全可写才放行** + 嵌套目录级引用检查（裸 `OBSERVER.json` 不算禁区委照——那是观察者自己的判断书名） | ✅已修（test_path_algebra_dotdot_and_mixed_separators） |
| P-13 | **stop 竞态窗口（R-1 同族，产品代码）**：`_consume_stop_file` 原顺序「删 CONTROL→置标志」与主循环「读标志→轮询文件」交错时，两边都不见 stop→多跑一轮 worker | 测试偶发失败（3 轮 1 次）刨根，不是测试脆弱 | 续修批修两道：①置标志先于删文件；②主循环 `_poll_control` 后二次读标志。各配确定性单测 | ✅已修（test_consume_stop_sets_flag_before_unlink / test_loop_top_rereads_stop_flag） |
| P-14 | **止损信号源断裂（真 bug，实机误杀）**：run 第 3 轮被"无新事实连击 3 轮"停，但三轮观察者入图 7/5/8 操作、产出旺盛 | `facts_delta` 用图节点增量；批3fix 架构下 worker 只写文件、图只在观察者轮末变（发生在 record_round 之后）→ 恒 0 → 任何 run 必在第 3 轮被误杀。旧架构轮内收割入图时该信号有意义，收割退役时没重接。usc-cwcx-b1 是第一个自然跑到第 3 轮的 run 才暴露；发现于用户对 P-10 的核查质询 | 2026-09-22 修：信号源换成本轮 worker 盘面新增/变更文件数（`page["new_or_changed"]`）；补两条回归（有产出 4 轮不触发 / 零产出第 3 轮触发）；stoploss.py docstring 记录语义变更 | ✅已修（test_stoploss_not_triggered_on_productive_rounds / test_stoploss_fires_on_three_barren_rounds） |

---

## 10. 续修批：guard 静态检测加固（S13-S16，2026-09-21 用户拍板）

> **定位**：§9.5 的 P-1/P-2 病灶治理。用户拍板：**不引入 LLM 参与检测**，只把静态检测做到最好。
> **基线**：`26ef89b` 之后（225 测试绿，含 S7/S10 的三条实机形态修复）。
> **状态**：**已竣工（2026-09-21；P-14 止损修复 09-22 补入）——S13/S14/S16 落地 + 施工中连带修 P-11/P-12/P-13；S15 tripwire 撤销（09-22 拍板：现阶段不考虑目标反注入 agent 场景，效果层不做）。全量 237 测试绿；未 commit（见 §10.5）。**

### 10.0 认知拍板（决定了这批长什么样）

**旧做法的病根 = 枚举形态**：靠人想象"worker 会怎么写这个路径/这个 URL"，一种形态补一条正则。实机四刀同族（P-1 引号分号 / P-5 反斜杠 / S7 的 `$` / 4fix 的 `+&`）全是这个病——**军备竞赛，永远追不完**。

**静态能打的最优解只有两条**（都不靠枚举）：

1. **能拿到结构化数据的地方，别用正则**——`Write`/`Edit` 的 `file_path` 是干净字符串，用**路径代数**（`Path.resolve()` + 前缀比较）判定归属，绝对/相对/`..`/混合分隔符/8.3 短名/UNC 全由构造保证。
2. **拿不到结构化的地方（命令文本），先归一化再匹配**——分隔符统一、引号统一，**禁区判定与豁免判定共用同一个归一化后的形态**（P-1① 的真正根因就是两侧各用一套正则、形态认知不一致）。

**效果层兜底（S15 tripwire）——已撤销（09-22 拍板）**：曾加 `.at1/` 诱饵+基线哈希+尺寸单调作为漏报检测器。撤销理由：①诱饵文件在 `.at1/` 里有被 worker 误读的风险；②黑板/转录是自愈资产（控制器内存覆盖、续接有 fallback），篡改检测价值有限；③现阶段不考虑目标反注入 agent 的场景（用户拍板）。文本层被绕过=静默漏记，接受。

### 10.1 快览（人话版）

| 卡 | 问题哪来的 | 造成了什么 | 怎么修 |
|---|---|---|---|
| **S13** | 路径判定靠正则猜形态 | 绝对路径/混合分隔符/短名形态漏判误判 | 结构化路径改用**路径代数**（resolve + 前缀比较）：禁区判定"正则 ∪ 代数"（只增不漏），**豁免判定用代数**（精确，治 P-1①） |
| **S14** | 禁区正则与豁免正则各认一套形态 | 两侧认知不一致 → 自家工作台被误判禁区 | 命令文本**先归一化**（分隔符→`/`、引号→空格），两侧共用同一形态；按**token**判定而不是整串正则 |
| ~~**S15**~~ | 文本层被绕过时无声无息 | 真被改了控制器区也查不出来 | **已撤销（09-22 拍板，见 §10.0）**——现阶段不考虑反注入场景，效果层不做 |
| **S16** | P-2 残留 + 房内清理 | 花括号形态 host 误判 | `_host_of` 截断类补 `{}[]`；顺手清理已死的正则分支 |

### 10.2 施工卡

**S13 结构化路径代数（治 P-1①）**

- `Guard.__init__(allow, deny, root=None)`；`from_engagement(engagement, root=None)`；driver 传 engagement 根。
- `_resolve_target(p)`：相对路径按 root 解析 → `Path.resolve()`（吃掉 `..`/软链/短名）；失败返回 None（回退正则）。
- `_path_in_zone(target)`：与 `root/{.at1,.observer,state,notes}` 前缀比较 + 根目录下 `_blackboard/_transcript/_interface_log/OBSERVER.*` 文件名。
- `_path_observer_writable(target)`：`root/.observer/**`、`root/STATE.md`、`root/notes/prior-intel-draft.md`。
- **判定合并**：禁区 = 模糊正则 **∪** 代数（保高召回，不丢任何既有拦截）；豁免 = 代数 **∪** 已修的 token 正则（保精确，治误报）。
- **验收**：绝对路径写自家工作台放行；绝对路径写 `.at1/` 仍拦；`notes/../.at1/x` 仍拦；root 缺省（单测旧路径）行为不回归。

**S14 命令文本先归一化再匹配（治误报残留）**

- `_normalize_cmd(cmd)`：URL 剥离 → 分隔符 `\`→`/` → 引号→空格。
- `_ZONE_TEXT_RX` 改为**带 token 捕获**（`.at1/...`、`notes/...`、`_blackboard.json`…）。
- 判定：归一化文本上取 zone tokens；observer 角色过滤掉自家可写 token；剩余非空且命中写动词 → 违规。
- **验收**：五类实机形态（绝对路径、反斜杠、读方法、拼接符、纯读）全放行；真越界形态（`>> ../state/x`、`Set-Content .at1/x`）仍拦。

**S15 `.at1/` tripwire——已撤销（09-22 拍板）**，以下为原设计存档：

- `arm()`：`.at1/` 放两枚随机内容诱饵（`.tp-<hex>.dat`）+ 建基线。
- `rebaseline()`：driver 每次 `bb.save()` 后调用——刷 `blackboard.json` 哈希基线（控制器合法写）。
- `check()`：诱饵丢失/内容变 → 违规；`blackboard.json` 哈希 ≠ 基线 → 违规；`transcript.jsonl` 尺寸 < 历史最大值 → 违规。已报项去重不刷屏。
- driver：watcher 线程每 ~5s 跑一次 `check()`，命中 emit `zone_tamper`（新事件类型，critical）；收尾再跑一次终检。
- **诚实边界**：只守 `.at1/`（`.observer/` 是观察者合法工作台、`notes/` 有合法产物，不能放诱饵）；两次 check 之间"截断+立刻补回更大"的理论窗口盖不住（~5s 粒度）。
- **验收**：改写诱饵/篡改黑板/截断 transcript 三种篡改各自被抓；无篡改时零误报。

**S16 收尾补漏**

- `_host_of` 截断类补 `{}[]`（治 P-2）；`_WRITE_TOOL_HINT_RX` 已删的裸 `[io.file]` 分支确认无残留引用。
- **验收**：`{}` 形态 host 解析正确；既有 URL 用例不回归。

### 10.3 测试与顺序

- 新 `tests/test_tripwire.py`；`test_guard.py` 补 S13/S14 案例（**夹具取自 usc-cwcx-b1 auto-log 的实机事件流**——§9.5 P-1 的教训落地）。
- 顺序：S16 → S13 → S14 → S15 → 全量 pytest（225 基线只增不减）。
- 不自动 commit。

### 10.4 明确不做

| 项 | 去向 |
|---|---|
| LLM 复核/打标 | **用户拍板不做**（不引 LLM 参与检测） |
| 观察者 triage guard 事件为机制 | 不做（同上；事件本就在 auto-log，人/观察者照旧能看，只是不新增机制） |
| 全目录 watchdog（抓任意进程写禁区） | 不做——区分控制器自身合法写需要排除表，脆（排除表漂移=误报 critical） |
| 权限收权（ACL/job object 沙箱） | M5/沙箱化路线，不预支 |
| 命令文本层继续追新形态 | **冻结**——S14 归一化后不再枚举形态；文本层被绕过=静默漏记，**接受**（S15 已撤，无效果层兜底） |
| S15 效果层 tripwire（诱饵/基线哈希/尺寸单调） | **已撤销（09-22 拍板）**——现阶段不考虑目标反注入 agent 场景；黑板篡改架构自愈（控制器内存覆盖）、transcript 截断有续接 fallback |

### 10.5 施工结果（回写区）

**施工完成（2026-09-21）；P-14 止损修复 09-22 补入；S15 tripwire 09-22 撤销。全量 pytest 237 绿。未 commit——等用户指示。**

施工中新抓的 P-11/P-12/P-13 三个问题已统一登记进 §9.5 问题总表（含根因/修法/回归锚），此处不重复。

| 卡 | 落点 | 测试锚 |
|---|---|---|
| S13 | `guard.py`：`Guard.__init__(allow, deny, root=None)` / `from_engagement(..., root=None)`（driver 传 engagement 根）；`_resolve_target`（相对路径按 root 解析 + `resolve()`）、`_path_in_zone`、`_path_observer_writable` 三个代数方法；判定合并 = 禁区「正则 ∪ 代数」（只增不漏）+ 豁免「代数 ∪ token 判」 | test_path_algebra_absolute_forms / dotdot_and_mixed_separators / without_root_keeps_legacy |
| S14 | `_normalize_cmd`（URL 剥 → 分隔符 `/` → 引号空格）+ `_ZONE_TEXT_RX`（带 token 捕获）+ `_observer_writable_token`；`check_tool` 命令分支改 token 判定，禁区侧与豁免侧共用同一归一化形态 | test_norm_cmd_unifies_forms / text_zone_token_observer_exempt_forms（五类实机原形）/ text_zone_token_still_blocks_worker_and_out_of_scope |
| ~~S15~~ | **已撤销（09-22 拍板）**——`src/tripwire.py`/`tests/test_tripwire.py` 删除，driver 6 处引用与 `zone_tamper`/`tripwire_armed` 事件注销 | — |
| S16 | `_host_of` 截断类补 `{}[]`（P-2 收口）；施工中连带抓出 P-11 绕过一并修 | test_host_braces_truncated_p2 / test_malformed_netloc_scope_bypass_fixed |
| P-13 | driver：`_consume_stop_file` 置标志先于删文件 + 主循环二次读标志 | test_consume_stop_sets_flag_before_unlink / test_loop_top_rereads_stop_flag |
| P-14 | driver：止损信号源换 `page["new_or_changed"]`；stoploss.py docstring 记录语义变更 | test_stoploss_not_triggered_on_productive_rounds / test_stoploss_fires_on_three_barren_rounds |

**诚实边界（本批交付后仍存在的）**：

- **文本层被绕过=静默漏记，无效果层兜底**（S15 已撤）： exotic 写法真写了 `.at1/` 不会被告警，靠控制器内存覆盖自愈 + 审计对账。
- **代数只在 root 在场时生效**：root 缺省（旧调用路径/单测）退回正则，行为不回归但不享代数精度。
