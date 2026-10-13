# AT1 Playwright 升级计划（Browser Pool：driver 托管每 engagement 独立浏览器）

> **定位**：修 `-p` 模型下 playwright MCP 的两个根因——**多 claude -p 进程抢全局共享 profile**（轮间/resume/并行 engagement/操作员交互会话四个时机都撞，撞了还静默降级 curl）与**浏览器状态活不过一轮**（`taskkill /T` 连坐，profile 只能回 cookie 回不了活页面态，还跨目标串味）。方案 = **driver 托管浏览器池**：借 dual-slot 三件套（detached 脱离进程树 / CDP 附着代替 MCP 自有 / PID 记录+探活自愈），弃其双槽共享仲裁（AT1 的 driver 是单点权威，engagement 与浏览器一对一，锁都多余）。
> **基线**：批4fix + 续修批竣工（238 测试绿，未 commit）。
> **状态**：**施工竣工（2026-10-12，B1-B6 六卡全落地，265 绿=238 基线+27 新增，未 commit 等指示）。剩余：§7 实机验收清单未跑（与批4fix 实机测试合并，见 §9）。早前拍板：有头默认；run_end 默认杀 Chrome、`AT1_BROWSER_KEEP=1` 留；身份导入写进 WORKER-CLAUDE.md。**
> **参考**：`lernproject/6k-skill/clown-src-6k-skill/bin/playwright-dual-slot.mjs`（Grok 生态的 Playwright MCP 双槽启动器——本文三件套的出处）。

---

## 快览：每张卡一句话（人话版）

| 卡 | 问题哪来的 | 造成了什么 | 怎么修 |
|---|---|---|---|
| **B1** | 浏览器现在归 MCP 所有：MCP 起它、MCP 死它死，而 MCP 每轮都换人 | 轮间冷启、登录态/页面态反复丢、强杀留脏 profile | 新建 `browser.py`：driver 直接 detached 拉 Chrome（独立 user-data-dir），状态落 `.at1/browser.json`，崩了自己拉起来 |
| **B2** | driver 只管 worker 进程树，浏览器在视野外 | Chrome 假死没人知道；engagement 结束没人收尸 | driver 集成池生命周期：start / 每轮 ensure（探活+自愈）/ finally 按 KEEP 收尾，全程进事件流 |
| **B3** | 正向：消毒规则未来收紧会误伤附着通道（现状其实透传——剥除规则只匹配 `AT1_*`/`LLM_*`/benchmark 变量）；反向：shell 全局残留的 endpoint 会在托管失败时穿透给 worker | 残值穿透 = 静默降级换个入口复发（MCP 附着死端点 → worker 降级 curl） | `_sanitize_env` 白名单放行（防收紧）+ driver 托管失败/skip 路径主动 pop（防残值）——双向 |
| **B4** | `.mcp.json` 模板没传 `--user-data-dir`，MCP fallback 自起浏览器时落全局共享 profile | driver 托管失败时回退路径仍然互撞+串味 | 模板加占位符，`expand()` 渲染每 engagement 绝对路径——**任何路径都不再碰全局 profile** |
| **B5** | 简报说「storage-state.json（已注入）」但全库没有任何导入机制，worker 全靠现场发挥 | 首轮身份建立不稳定，每轮可能浪费轮次重摸 | WORKER-CLAUDE.md 新增「身份导入」节：首轮经 `browser_run_code_unsafe` → `context.addCookies()` 导入（httpOnly 只有这条路进得去），profile 记住后不再导 |
| **B6** | 新增机制无测试 | 回归风险 | `test_browser.py` + `test_driver.py` 补池生命周期用例 |

### 2026-10-12 评审修订对照（每条：问题是什么 → 怎么解）

动工前评审抓出 10 个问题（首轮 7 + 二次复查 3，逐条人话对照）——细节散在下面各卡和 §6.5，看这张表就够：

| # | 问题是什么 | 怎么解 | 落点 |
|---|---|---|---|
| R1 | **relaunch 不杀旧进程**：假死的 Chrome 进程还活着、占着 profile 锁，直接拉新实例会起不来——「假死自愈」反而自己卡死 | relaunch 前先 `taskkill` 旧 pid、等它死透，再拉新的 | B1 状态机 + 验收 |
| R2 | **全局残值从后门回来**：手动测试常在 shell 里 export 过 CDP endpoint；一旦 driver 托管失败走降级，worker 会继承这个死值 → MCP 附着死端点 → 又静默降级 curl（正是本批要消灭的失败模式，换个入口复发）。另：原 B3 的前提写错了——消毒规则根本不剥这个变量，正向透传现状就通，白名单只是防御 | 双向消毒：①driver 托管失败/skip 时主动 pop 残值（治真问题）；②`_sanitize_env` 白名单放行（防未来收紧误伤） | B2 第 1 条 + B3 |
| R3 | **KEEP=1 紧急收尾没着落**：run 卡死超 30s 后 stop 提示人工 `taskkill` 强杀 driver，`/T` 这刀连坐 Chrome——KEEP=1 想留的现场没了，且原计划只说"注意"没有卡承接 | 拍板**接受连坐、不改代码**（都卡到要人工强杀了，现场多半本来就是坏的）；文档写明边界：KEEP=1 只在正常 stop / driver 体面退出时成立 | §6 风险2 + §6.5-1 |
| R4 | **headless 说法不一致**：上轮有头 + KEEP=1 留了实例，这轮设 `AT1_BROWSER_HEADLESS=1`，现状写法会静默复用有头实例（flag 白设） | 拍板 **flag 优先**：headless 不匹配就杀旧按新 flag 重起——改 flag 是明确表态（比如挂机过夜不想弹窗），丢页面态不丢 cookie | B1 状态机 + 验收 / §6.5-2 |
| R5 | **browser_close"待实测"其实能先查证**：Playwright 官方文档已写明 connected browser 的 close 是「断开连接，进程不死」，MCP 工具描述也只是"Close the page" | **✅ 已预检闭环（2026-10-12）**：桌面查 0.0.83 源码 + 实机各一次——只关本轮自建页、进程不死、旧标签存活；详见 §6 风险1 | §6 风险1 + 验收 8 |
| R6 | **基线数字过期**：计划写 222 绿，续修批后实为 238 绿 | 全文刷成 238；playwright 落地后，实机测试计划里的「238 绿」也要跟着刷（两份文档数字连动） | 文档头 + B6 |
| R7 | **版本漂移**：`@playwright/mcp@latest` 浮动，而本批开始全靠「env var 穿透」和「close 不断连」两个行为吃饭，哪天 npx 拉到新版本悄悄改了语义，故障就是静默降级 curl，排查要命 | 拍板**钉死固定版本**：模板与 preflight 用同一常量；代价只是偶尔手动升级。**✅ 钉版确定 = 0.0.83**（2026-10-12 预检时 npm latest 恰为此版=缓存版，零行为变化；env var 支持与 close 语义均已在此版实测） | B2 第 5 条 + B4 / §6.5-3 |
| R8 | **新事件没登记白名单 = 一 emit 就崩**：events.py 的 EVENT_TYPES 是 frozenset 白名单，未登记类型 emit 直接 ValueError（events.py:97）；B1/B2 要发 5 个 browser 事件，计划原稿没写登记这步；且纯 mock 假 ev 的单测**测不出来** | B1 明写「五类型登记进 EVENT_TYPES」+ 验收加一条：真 Emitter 发一次 browser_start 不炸 | B1 + B6 |
| R9 | **watch 看不见细节**：`src watch` 对未知事件只打裸类型名（有兜底不崩），browser_start 出来就一行光秃秃的 `browser_start`，pid/port 瞎 | `_fmt_event` 补一行渲染，顺路的事 | B2 第 6 条 |
| R10 | **删 engagement 不 stop → Chrome 孤儿**：目录一删 browser.json 跟着没，活着的 Chrome（KEEP=1 必留）没人收尸，占端口占内存 | 操作纪律：删/归档前先 `src stop`；已泄漏的 netstat 找端口 PID 手动杀。不改代码 | §6 风险5 |

---

## 0. 根因复述与语义拍板（已定稿，施工不重新议）

**根因一句话**：`-p` 模型下，任何挂在 MCP 进程树上的状态活不过一轮。想要浏览器状态跨轮、跨 resume、跨并行 engagement，唯一办法是把所有权挪出 MCP 进程树——driver 是唯一活过整个 engagement 生命周期的进程，浏览器托管给它。

**「抢 profile」在 AT1 里的四个发生时机**（都已被现状命中）：

1. 轮间：每轮新 `claude -p` → 新 MCP → 与上一轮残留的 Chrome/锁竞争；
2. 轮内 resume（`runner.run` 续跑循环，runner.py:554）：新 MCP 起浏览器时上一个可能没死透；
3. 并行 engagement（双管道）：两个 driver 的 worker 共用同一个固定 profile，第二个起不来；
4. 操作员交互会话（全局挂 playwright MCP）与 AT1 同机并行。

撞了之后是**静默的**：browser 工具报错 → worker 按 P-7 降级 curl，操作员以为它在挖，浏览器通道整轮是死的（preflight 只查 `npx --version`，探不到）。

**「丢登录态」的精确机制**：默认 persistent profile 在磁盘上，cookie 轮间其实留着——但这是因祸得福（所有进程共享同一个 profile）。真正损失：① 活浏览器（tab/页面内存态/JS 会话）随 `taskkill /T /F` 全走；② `/F` 强杀不走优雅关闭，profile 写一半有损坏风险；③ 跨目标串味——engagement A 的 cookie jar 和指纹出现在 B 的浏览器里，测试被污染。

**语义拍板（用户 2026-09-21 定）**：

- **有头默认**（`AT1_BROWSER_HEADLESS=0`）：渗透场景有头更贴近真人、少一类 headless 指纹；要干净改 env，不做代码分支。
- **run_end 默认杀 Chrome**（`AT1_BROWSER_KEEP=0`）：资源干净；`=1` 留守——调试接上去看现场，driver 崩后续跑时页面态还在。
- **身份导入写进 WORKER-CLAUDE.md**（worker 侧导入，driver 端 CDP 注 cookie 留作后续，v0 不做）。
- 浏览器缺席**不拒启**（与现 preflight 哲学一致：curl 降级路径可活；pool 起不来只警告+不注入 env，MCP fallback 走 B4 的隔离 profile）。

补拍三条（2026-10-12，同效力，详释见 §6.5）：**KEEP=1 紧急强杀连坐属预期**（不改代码）；**headless 说法不一致时 flag 优先、杀旧重起**；**@playwright/mcp 钉死固定版本**。

---

## 1. 架构

```
现在：
  每轮 claude -p ─▶ npx @playwright/mcp（无 --user-data-dir）
                    └▶ MCP 自起 Chrome（全局共享 profile）
  轮末/stop ─▶ taskkill /T /F ─▶ claude→npx→Chrome 整棵树死

目标：
  run_engagement 启动
    └▶ driver（B1/B2）：找 exe → 挑空闲端口 → detached 拉 Chrome
       （--remote-debugging-port --user-data-dir=<engagement>/.at1/chrome-profile）
       → 等 CDP 就绪 → PLAYWRIGHT_MCP_CDP_ENDPOINT 注入 os.environ
  每轮 spawn 前（B2）：pool.ensure() —— probe /json/version，死了就重启
  每轮 claude -p ─▶ MCP 读 env 附着 CDP（不拥有浏览器，轮末死不掉它）
  run_end（B2）：KEEP=0 → 杀 Chrome + 删 browser.json；KEEP=1 → 留守供复用
```

**自愈链（任何一层死了都有兜底）**：

| 故障 | 兜底 |
|---|---|
| Chrome 崩 | 轮间 ensure 探活重启，cookie 从 profile 回 |
| worker 调 `browser_close` 误杀 | 同上（语义见 §6 风险 1） |
| driver 崩 | Chrome 孤儿存活，新 driver 读 `.at1/browser.json`（pid+port）探活复用 |
| driver 托管整体失败 | 不注入 env → MCP fallback 自起，落 B4 渲染的 engagement 专属 profile（仍隔离） |
| 无 `.mcp.json` 的 engagement | pool 不启动，行为与现在完全一致 |

---

## 2. 关键事实速查（动工前已知，勿重复调研）

- 模板拷贝点：`scaffold.expand()` → `shutil.copyfile(_TEMPLATE_DIR / ".mcp.json", workdir / ".mcp.json")`（scaffold.py:74）。
- MCP 唯一来源：`runner._build_argv` 加 `--strict-mcp-config --mcp-config <workdir>/.mcp.json`（runner.py:380-384）；模板现状 = `npx @playwright/mcp@latest --executable-path D:\chrome\Chrome\Application\chrome.exe`。
- 环境消毒：`runner._sanitize_env`（runner.py:314-345）剥 `AT1_*`/`LLM_*`；`AT1_CLAUDE_CONFIG_DIR` 的「先 pop 再回注」特例在 L327/L337-342——B3 照抄这个模式。
- env 注入口：driver 已用 `os.environ.setdefault("AT1_CLAUDE_CONFIG_DIR", ...)`（driver.py:283）——B2 注 endpoint 用同一位置同一手法（worker 和 observer 子进程都继承）。
- 杀树：`runner.kill_process_tree` = Windows `taskkill /PID /T /F`（runner.py:348-366）——detached Chrome 不在 worker 树内，天然够不着。
- preflight：`driver._preflight`（driver.py:64-96），MCP 检查现状只跑 `npx @playwright/mcp@latest --version`。
- @playwright/mcp 官方（2026-09 已核对 README）：**每个 CLI flag 都有对应环境变量**（`--cdp-endpoint` ↔ `PLAYWRIGHT_MCP_CDP_ENDPOINT`）；默认 persistent profile 是固定共享路径，官方明示「concurrent MCP clients sharing the same workspace will conflict」；`--user-data-dir` 可覆盖。
- httpOnly cookie 无法经 `document.cookie` 写入，唯一导入路径 = Playwright API `context.addCookies()`，对应 MCP 工具 `browser_run_code_unsafe`（函数签名拿到 `page`，`page.context().addCookies([...])`）。
- Chrome exe：`D:\chrome\Chrome\Application\chrome.exe`（js-intel 同源）；candidates 兜底照抄 dual-slot（Program Files / LOCALAPPDATA / Edge）。
- detached 启动（Windows）：`subprocess.Popen(creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP, stdout=DEVNULL, stderr=DEVNULL)`；Chrome 参数照抄 dual-slot：`--remote-debugging-port=<port> --user-data-dir=<dir> --no-first-run --no-default-browser-check --disable-sync about:blank`。
- CDP 探活：GET `http://127.0.0.1:<port>/json/version`，2s 超时；启动等待 deadline 20s（dual-slot 同款）。

---

## 3. 施工卡

### B1 `src/browser.py` 新建（~150 行）

**内容**：`BrowserHandle` 类 + 模块级工具函数。

- `find_exe()`：`AT1_BROWSER_EXE` env > `D:\chrome\...` > Program Files / LOCALAPPDATA / Edge candidates（dual-slot 抄袭）；找不到返回 None（不抛）。
- `alloc_port()`：`socket.bind(("127.0.0.1", 0))` 拿空闲端口；起 Chrome 后探活失败换口重试，最多 3 次（bind-close-use 之间有竞态窗口，单机低并发可接受）。
- `launch(port, profile_dir, headless)`：detached Popen（参数见 §2）；**返回 Popen 句柄但不持有**——Chrome 从此与 driver 无进程关系，只靠 port+pid 记账。
- `probe(port) -> bool`：`/json/version` 探活。
- `wait_cdp(port, deadline_s=20)`：轮询直到就绪。
- `BrowserHandle` 状态机：`start()`（读 `.at1/browser.json`——pid 活且 CDP 通且 headless 与本次 flag 一致 → 复用 emit browser_reuse；**flag 优先**：headless 说法不一致就杀旧按新 flag 重起，丢页面态不丢 cookie，见 §6.5-2；其余不一致**先 `taskkill /PID <旧pid> /T /F` 清掉旧进程**再重新 launch——假死 Chrome 占着 user-data-dir 锁，不杀旧进程新实例起不来，这正是 relaunch 的头号场景）/ `ensure()`（探活，失败走同款「先杀旧再拉新」relaunch emit browser_relaunch）/ `shutdown(keep)`（keep=1 只留 browser.json 供下次复用；keep=0 `taskkill /PID <pid> /T /F` + 删 browser.json）。
- 状态文件：`.at1/browser.json` = `{"pid", "port", "headless", "started_at"}`。
- 事件：browser_start / browser_reuse / browser_relaunch / browser_exit，带 `{"pid", "port", "headless", "reason"}`——由 driver 传 `ev` 回调注入，browser.py 自身不 import events（保持纯函数可测）。
- **事件类型必须登记进 `events.py::EVENT_TYPES`**（R8）：白名单是 frozenset，emit 未登记类型**直接 ValueError**（events.py:97）——browser_start/reuse/relaunch/exit/skip 五个全要登记，否则 driver 第一次 emit 当场崩。

**验收**：单测全 mock（不真起 Chrome）下 start/ensure/shutdown 状态迁移正确；browser.json 读写与孤儿复用判定正确；relaunch 分支断言「杀旧进程先于新 launch」；复用分支断言 headless 不匹配 → 走杀旧重起而非复用；**用真 `events.Emitter` 发一次 browser_start 不炸**（纯 mock 的假 ev 测不出 EVENT_TYPES 登记缺失——T2.7 的坑专防这一手）。

### B2 `src/driver.py` 集成（~40 行）

1. preflight（L349）之后：`handle = BrowserHandle.start(root, ev)`——`.mcp.json` 不存在或 `find_exe()` 为 None → 不启动，只 emit `browser_skip`，且 `os.environ.pop("PLAYWRIGHT_MCP_CDP_ENDPOINT", None)`（防 shell 全局残值穿透给 worker，见 B3 反向）。
2. 成功 → `os.environ["PLAYWRIGHT_MCP_CDP_ENDPOINT"] = f"http://127.0.0.1:{port}"`（driver.py:283 同位置风格；observer 子进程同样继承）。
3. 每轮 spawn 前（L439 渲染 prompt 附近）：`handle.ensure()`。
4. `finally`（L580 收尾区）：`handle.shutdown(keep=os.getenv("AT1_BROWSER_KEEP") == "1")`，且 try/finally 包住主循环保证 stop/budget/异常路径都收得到。
5. `_preflight` 增加 chrome exe 存在检查（复用 `find_exe`；缺失只警告文案，不拒启）；MCP 版本探测从 `@latest`（driver.py:119）改成与 B4 模板同一固定版本常量。
6. `__main__._fmt_event` 给 browser_* 五个事件补一行渲染（R9）：现状兜底只打裸类型名（__main__.py:462 `return f"{base} {t}"`，不崩但 pid/port 看不见）——一行 `f"{base} ◐ browser_start pid={d.get('pid')} port={d.get('port')} …"` 级别的事，顺路做。

**验收**：monkeypatch 下 driver 全流程事件序列正确；`.mcp.json` 缺失 engagement 走 browser_skip 且 run 正常完成。

### B3 `src/runner.py::_sanitize_env` 附着通道双向消毒

> 现状澄清（2026-10-12 评审）：`_sanitize_env`（runner.py:336-340）只剥 `AT1_*`/`LLM_*`/三个 benchmark 变量，`PLAYWRIGHT_MCP_CDP_ENDPOINT` 本就不匹配剥除规则——正向透传现状已成立。本卡是**防御性白名单**（防未来收紧消毒误伤）+ **反向防全局残值**。
>
> 威胁模型拍板（2026-10-13，F4 措辞对齐）：消毒防的是**凭证与控制器变量误传**（`AT1_*`/`LLM_*`/API key），不是"worker 拿不到控制器内部状态"——B3 白名单放行 `PLAYWRIGHT_MCP_CDP_ENDPOINT` 后，浏览器附着通道是**有意共享**（worker 的正当工具）。威胁模型 = worker 可全权操作本 engagement 浏览器（同信任域，拍板接受：worker 本就有完整浏览器操作权限，白名单未新增能力）。

- 正向：照 `AT1_CLAUDE_CONFIG_DIR` 模式（L327 pop → L342 回注）：`endpoint = env.pop("PLAYWRIGHT_MCP_CDP_ENDPOINT", None)`，清洗后 `if endpoint: env["PLAYWRIGHT_MCP_CDP_ENDPOINT"] = endpoint`。
- 反向（真正的新增价值）：机器全局 shell 残留过该变量（手动测试常见）时，driver 托管失败/browser_skip 不注入 → worker 继承残值 → MCP 附着死端点又静默降级。配套 B2：托管成功才由 driver 注入，**browser_skip / 托管失败路径 driver 主动 `os.environ.pop`**——残值在源头清掉，B3 的保留逻辑只保留 driver 注入的值。

**验收**：单测断言消毒后 env 里 endpoint 保留、其余 AT1_* 仍剥净；B2 侧断言 skip 路径下 endpoint 不出现在 spawn env。

### B4 `scaffold.py` + `scaffolding/.mcp.json` 兜底隔离

- 模板 `.mcp.json`：保留 `--executable-path`（fallback 自起时用），追加 `--user-data-dir`, `{{BROWSER_PROFILE_DIR}}` 占位符。
- 版本钉死（§6.5-3）：**钉 0.0.83**（2026-10-12 预检时 npm latest 恰为此版，env var 支持与 browser_close 语义均已在此版实测过）；模板与 B2 的 preflight 探测用同一常量。
- `expand()`：`shutil.copyfile` 改为读模板 → 替换占位符为**绝对路径** `<engagement>/.at1/chrome-profile-fallback` → 写入。（占位符未替换的模板拷贝禁止落盘——测试锁一行断言。）
- driver 托管模式下这两个 flag 被 CDP 附着忽略，无副作用。

**验收**：渲染产物含本 engagement 路径、不含占位符；test_scaffold 一致性锁保持绿。

### B5 `scaffolding/WORKER-CLAUDE.md` 身份导入节

新增一节（放 §1 开工之后）：

- 触发条件：简报说 `storage-state.json（已注入）` 且当前浏览器对目标域未登录。
- 步骤：`browser_navigate` 目标域任意页 → 读 `storage-state.json`（Playwright storage state 格式：`cookies[]` + `origins[].localStorage`）→ `browser_run_code_unsafe` 执行 `page.context().addCookies(<cookies>)`（localStorage 按 origin 同法）→ 重新 navigate 刷新会话 → 打一个 me/whoami 类接口验证身份生效。
- 纪律：**只在 profile 未登录时做**（profile 记住后不再导）；验证失败重试 1 次，仍失败转匿名/curl 降级，并在交接里记一句「身份导入失败」，不空转。

**验收**：文档评审通过即可（无代码）；汇编↔scaffolding 双写一致性锁（若本文件在汇编射程内）保持绿。

### B6 测试

- `tests/test_browser.py`：find_exe candidates / alloc_port 返回可用端口 / probe 对本地 mock http server / browser.json 读写与孤儿复用判定 / shutdown keep 两分支（mock taskkill）。
- `tests/test_driver.py` 补：pool 启动→env 注入→spawn env 断言（monkeypatch Popen capture）；无 chrome → browser_skip 照常跑；ensure 在 Chrome 探活失败时 relaunch 一次。
- **基线 238 绿（续修批后），只增不减**；每卡完成跑全量 pytest。

---

## 4. 配置位

| env | 默认 | 说明 |
|---|---|---|
| `AT1_BROWSER_EXE` | `D:\chrome\Chrome\Application\chrome.exe` | 浏览器可执行；缺失只降级不拒启 |
| `AT1_BROWSER_HEADLESS` | `0`（有头，已拍板） | `=1` headless |
| `AT1_BROWSER_KEEP` | `0`（run_end 杀，已拍板） | `=1` 留守：调试手动 attach / driver 崩后续跑复用页面态 |
| `PLAYWRIGHT_MCP_CDP_ENDPOINT` | driver 注入 | MCP 附着通道；不暴露给用户配，托管失败/skip 时不注入且主动清残留（见 B3 反向） |

## 5. 施工顺序

**B1 → B3 → B4 → B2 → B5 → B6**（B3/B4 小且独立先行；B2 依赖 B1；B5 纯文档随时插；B6 随卡写、末卡兜底核对）。每卡完成跑全量 pytest。不自动 commit/push（文档用 Write/Edit 工具）。

## 6. 已知风险

1. **`browser_close` 语义——已实锤（2026-10-12 预检，无需再测）**。桌面查证（0.0.83 源码）：工具只 `page.close()` 关当前页，不碰 browser/context；就算走到 `Browser.close()`，CDP 附着下也只是关 WebSocket 断开连接（进程不死）。实机复测：worker 调 browser_close 后 Chrome 进程存活、CDP 照常应答、**上一轮开的标签原样还在**（它只关本轮 MCP 自建的那个页）——顺带预验证了验收 2 的「轮间 tab 存活」。唯一尾巴：若关的是浏览器里**最后一个**页，Chrome 按「无窗即退」常规退出——轮间 ensure 杀旧拉新兜底，cookie 从 profile 回。
2. **对 driver 进程 `taskkill /T` 会连坐 Chrome**（detached 只断控制台/进程组，父子关系还在——Chrome 的爹仍是 driver）：正常 stop 不走这条（协作式，driver 体面退场自己收 Chrome）。已拍板（§6.5-1）：紧急人工强杀的连坐属预期，不改代码；KEEP=1 的「留现场」只在 driver 体面退出（含异常走 finally）时成立，紧急 taskkill 场景别当 bug。
3. **env 穿透——已实锤（2026-10-12 预检），渲染退路作废**。实测：起带调试端口的 Chrome，`PLAYWRIGHT_MCP_CDP_ENDPOINT` 只走 env（`.mcp.json` 里无端点信息），`claude -p --strict-mcp-config` + 0.0.83 → MCP 附着成功，导航的页面落在我们那个 Chrome 里（/json 可见 example.com）。顺带证实 CDP 附着模式下模板里的 `--executable-path` 被忽略（没有第二辆 Chrome 被拉起）。验收第 9 项降级为实机轻量复核。
4. **端口 bind-close-use 竞态窗口**：单机低并发可接受，探活失败换口重试 3 次兜底。
5. **engagement 目录不经 stop 直接删除 → Chrome 孤儿（R10）**：browser.json（唯一记账，pid+port）随目录一起没了，留下的活 Chrome 没人收尸（占端口占内存，KEEP=1 留守 + 直接删目录时发生）。只在绕过正常流程时出现（KEEP=0 默认 run 末即收、正常 stop 也收）。**预防**：删/归档 engagement 前先 `src stop`。**事后清理**（browser.json 没了不知道端口，netstat 法不可用——按命令行特征识别，我们的 Chrome 带 `--remote-debugging-port`，普通 Chrome 没有）：
   ```powershell
   Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" |
     Where-Object { $_.CommandLine -match 'remote-debugging-port' } |
     Select-Object ProcessId, CommandLine
   taskkill /PID <查到的PID> /T /F
   ```
   不改代码（为罕见误操作加全局登记簿不值）。
6. **Chrome 轮内死亡不自愈（确认接受）**：探活在轮间，轮内死了 = 当轮浏览器通道废、worker 降级 curl，下轮 ensure 复活。轮内自愈要教 worker「browser 报错先重试」或 attach 重试，收益低不做。死亡本身是尾部风险（目标页有毒 JS / 内存泄漏 / 机器睡眠 / worker 关掉最后一张页→无窗即退），多数 run 一辈子碰不上。

## 6.5 补拍三条（2026-10-12，已定稿）

1. **KEEP=1 紧急收尾 = 接受连坐，写明边界**。正常 stop 是 driver 自己体面退场，Chrome 按 KEEP 处置，这条路 KEEP=1 好使；但 run 卡死超 30s 后 stop 会提示人工 `taskkill /F /PID <driver>` 强清（__main__.py:375），`/T` 这刀下去 Chrome 陪葬，想留的现场没了。拍板：**不为紧急路径改代码**——都卡到要人工强杀了，现场多半本来就是坏的，不值得为它改杀树逻辑、留一堆孤儿 worker。文档写明边界（§6 风险2），遇到别当 bug。
2. **headless 说法不一致时，听 flag 的，杀旧重起**。上轮有头 + KEEP=1 留了实例，本轮设 `AT1_BROWSER_HEADLESS=1`——把旧的杀掉按新的重起。改 flag 是明确表态（比如挂机过夜不想弹窗），旧实例打开的页面丢就丢，cookie 在 profile 里登录态还在。实现：start() 复用分支多比一个字段。
3. **@playwright/mcp 钉死固定版本**。不再 `@latest` 漂着。这批全靠「环境变量穿透」和「close 不断连」两个行为吃饭，版本一漂就是静默降级 curl，排查要命；代价只是偶尔手动升级。**已钉 0.0.83（2026-10-12 预检：当时 npm latest 恰为此版，两个行为都在此版实测过）。**

## 7. 验收清单（实机）

1. 双 engagement 并行跑：各起各的 Chrome（不同 port+profile），worker 侧无 browser 报错，auto-log 各自 browser_start。
2. 轮 1 经 B5 导入身份登录 → 轮 2 附着后 cookie **和打开的 tab** 原样在。
3. 轮中手动 taskkill worker 进程树 → Chrome 存活，下轮正常附着。
4. 手动杀 Chrome → 下轮 ensure 自动重启且登录态在（emit browser_relaunch）。
5. 杀 driver → 重启 run → 复用孤儿 Chrome（browser.json 路径）。
6. `AT1_BROWSER_KEEP=1` → run_end 后 Chrome 留守，手动 `http://127.0.0.1:<port>/json` 能看到页面列表。
7. 无 `.mcp.json` engagement → browser_skip，行为与现在一致（curl 起步）。
8. ~~worker 侧实测 `browser_close`~~ 已预检闭环（2026-10-12：只关本轮自建页、进程不死、旧标签存活）——实机跑批时看 auto-log 无 browser 报错即可。
9. ~~env 穿透~~ 已预检闭环（2026-10-12：附着成功 + `--executable-path` 被忽略均实测）；实机验收 1（双 engagement 并行各附各的）天然复核一遍。
10. fallback 路径：故意改错 `AT1_BROWSER_EXE` → MCP 自起浏览器落在 engagement 专属 profile，无共享 profile 访问。

## 8. 边界（本批不做）

- 双槽/多槽共享仲裁（AT1 无对等窗口场景）；单 engagement 内多 worker 并发浏览器（现在也没有）。
- driver 端 CDP 直接注 cookie（v0 身份导入走 worker 侧 B5；driver 端注入留后续批次）。
- guard / prompt / observer 协议任何改动（observer 经 env 继承自动获得附着能力，零改动）。
- 端口范围/浏览器参数配置化（不加用不到的旋钮）；M5 server 化收编（沿批4fix §0 既定路线，本批产物按可收编形状做：状态落 `.at1/browser.json`、生命周期全事件流）。

用户确认不需要（2026-10-12）：单轮多 tab A/B 对比；双身份并发在线（串行测试——先 A 后 B，prompt 引导可解）；CDP 指纹/stealth 层；127.0.0.1 调试端口本机敞口（单人 pentest 机）。

资源模型澄清（2026-10-12）：Chrome 生命周期 = **run 级**——轮间保活是特性（状态跨轮），run_end 默认杀（KEEP=0）。成本 = 每个正在跑的 run 一个实例，跑完就没；观察者轮/curl 轮期间闲着也留着属设计使然。常规 1~2 个并行 engagement 无感，等于多开一两个浏览器窗口。

## 9. 施工记录（2026-10-12）

**六卡全落地，265 绿（238 基线 + 27 新增：browser 18 / driver 4 / runner 3 / scaffold 2），零回归，未 commit。**

| 卡 | 落点 | 要点/偏离 |
|---|---|---|
| B1 | `src/browser.py` 新建（~290 行）+ events.py 登记 5 类型 | find_exe 的 `AT1_BROWSER_EXE` **显式设置即权威**（指错→None 走 fallback，保验收10）；kill_pid 带**镜像名守门**（pid 回收复用后不是 chrome/msedge 不动手，S2 同源）；probe 用无代理 opener（HTTP_PROXY 劫持 127.0.0.1 探活的坑提前拆）；`_launch_new` 失败 emit browser_exit + dead 置位（不每轮空转） |
| B3 | runner.py `_sanitize_env` pop→回注 | 照计划，防御性白名单 |
| B4 | scaffold.py `MCP_PACKAGE`/`FALLBACK_PROFILE_DIRNAME` 常量 + expand() 渲染 + 模板钉 0.0.83 | 渲染用 **as_posix**（Windows 反斜杠是非法 JSON 转义）；测试锁：模板版本字面量↔常量同源 + 未替换占位符禁止落盘 + 产物合法 JSON |
| B2 | driver.py：preflight 加 chrome 键 + 池启动/skip 清 env + 每轮 ensure + **主循环 try/finally 包裹**（重缩进 285 行，脚本机械完成）+ `__main__._fmt_event` browser_* 渲染 | npx 探测版本从 `@latest` 换 `scaffold.MCP_PACKAGE`（实跑输出 `Version 0.0.83` 确认钉版生效） |
| B5 | scaffolding/WORKER-CLAUDE.md §1 末 + prompt-全文汇编.md §3.1 **双写同文** | 一致性锁 ③a 保持绿 |
| B6 | test_browser.py 新建 18 条 + test_driver 4 + test_runner 3 + test_scaffold 2 | 测试隔离：test_driver autouse 桩 `_NoopBrowser`（driver 全流程测试不真起 Chrome）；新测试踩坑两条已修（漏建 engagement 三件套 / from-import 绑定要在 driver 侧打桩） |

**真机冒烟（非测试件，一次性脚本跑完即删）**：真 exe 拉起 → CDP 探活 ✓ → 二次 start 复用同 pid（browser_reuse）✓ → 活实例 ensure 零动作 ✓ → shutdown(keep=0) Chrome 真死 + browser.json 删除 ✓ → 事件流 start/reuse/exit 全落盘 ✓。

**剩余**：§7 实机验收清单 10 项未跑——与 `v3批4fix实机测试计划.md` 的实机验证合并执行（该文档的「238 绿」断言按 R6 约定刷新为 265 绿）。
