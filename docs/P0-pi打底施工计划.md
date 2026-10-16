# P0 施工计划：pi 打底（v4 第一阶段）

> **定位**：v4 重构第一阶段——Node 工程 + pi agent loop 跑通。**只打地基，不盖楼**：不含 planner/事件流/资产表/skills，全部留给 P1+。
> **上游设计**：`图与基底重构设计.md`（§5 pi 基底 / §6 全 Node / §8 迁移路径）。
> **本轮拍板引用（2026-10-16）**：老图不迁移（v4 只管新 task）；Cairn_Y 合并降级（跑靶后对照）；**单 worker**（并行推迟，P0-P2 全程单 worker）。
> **状态**：**✅ P0 竣工（2026-10-16）**——六张施工卡全落地，验收 5/6 过（smoke-3 jwzx 可选项未跑，需代理 env）。关键实测结论见文末「竣工记录」。

---

## 0. P0 要达成的一句话

一个 Node 进程里，pi worker 会话拿到三个能力（bigmodel 通道 + 浏览器 + submit_fact 工具），在无人工干预下自主完成：**打开浏览器访问靶站 → 观察到内容 → 调 submit_fact 把观察写进 SQLite**。全链走通即 P0 验收。

## 1. 施工卡

### P0-0 工程骨架

- **位置**：`at1-github/v4/`（与 Python `src/` 并存；Python 版冻结只读，v4 是唯一主干）。
- **形态**：单包 TypeScript 工程（不上 monorepo，P0 无需）：`package.json` + `tsconfig.json`（ESM、Node ≥20）+ `vitest`。
- **依赖**：`playwright`（库形态，不用 @playwright/test）、`better-sqlite3`、pi 的消费（见风险①：优先 npm workspace/file 依赖 `lernproject/pi-main` 的 `@earendil-works/pi-ai`+`packages/agent`，装不上则 vendor 所需包）。
- **目录草案**：
  ```
  v4/
    src/
      index.ts          # 入口：跑 smoke
      agent.ts          # Agent 封装：pi loop + 事件消费
      tools/            # 工具面
        submit-fact.ts
        browser.ts
      browser-pool.ts   # browser.py 的 TS 移植
      guard.ts          # beforeToolCall 闸机（最小）
      db.ts             # better-sqlite3 最简 nodes 表
    test/
  ```

### P0-1 pi loop hello + bigmodel 通道

- `new Agent(options)`（`packages/agent/src/agent.ts:188`）+ `agent.prompt(input)` 跑通最小会话：固定 systemPrompt（"你是测试 worker"）+ 一条用户指令，消费事件流打印。
- **模型通道**（风险②，实测二选一）：
  - a) `packages/ai` 的 anthropic 形态 provider + 模型项 baseUrl 覆写 → bigmodel 的 Anthropic 兼容端点（`open.bigmodel.cn/api/anthropic`，key 在 `.secrets.env`——与现 Python 版同通道）；
  - b) openai 形态 → bigmodel `/paas/v4`（OpenAI 兼容）。
- **顺手记录**（P1 要用）：事件流里的 usage 字段位置与结构（input/output/cacheRead/cacheWrite）——activity 计量列的数据源。

### P0-2 submit_fact 最简工具

- 按 `AgentTool` 接口实现（`types.ts:466`）：`name/description/parameters`(JSON Schema) + `execute(toolCallId, params, signal)`。
- **description 里写微纪律**（§4.4 模板精髓的第一次落地）：evidence 必填一行"命令+最能证明的输出"、confidence 枚举 observed/inferred——工具描述即纪律载体。
- `db.ts`：better-sqlite3 建 P1 nodes 表的**最简子集**（`id/kind/state/origin/payload/created_at`），execute 里 insert，zod 校验参数（桶四 #7：契约在应用层）。
- 回执：`{id, dedup:false}`（去重 P1 再做，P0 只插）。

### P0-3 guard 闸机最小版

- `beforeToolCall` 钩子（`BeforeToolCallResult{block, reason}`，`types.ts:66`）：
  - 全量审计日志（每次工具调用记 `{ts,tool,action,params摘要}` 落 SQLite activity 表最简子集）；
  - 一条假规则验证 block：如"submit_fact 的 summary 含 'test-block' 则拒"；
  - **block 消息用平台管控框架**（§4.3：「平台管控·非目标防御」+ 原因——第一天就养成正确语义，防 worker 绕拦）。

### P0-4 浏览器池 TS 移植

- `browser-pool.ts`：`browser.py` 直译——find_exe/alloc_port/launch(detached)/probe(/json/version)/shutdown，**删掉**：KEEP/headless 比对、孤儿复用（P0 用不到，P1 补）。
- 附着方式升级：`playwright.chromium.connectOverCDP(endpoint)` 库直连（比 MCP 附着稳，池逻辑不变）。
- `tools/browser.ts`：P0 只做 **browser_navigate + browser_snapshot** 两个工具（包一层 playwright page 操作），其余工具面 P1 扩。

### P0-5 smoke 组装（= P0 验收）

```
prompt（worker 短模板 v0，~10 行）:
  你是渗透测试 worker。用 browser_navigate 打开 <靶站>，browser_snapshot 观察内容，
  然后调 submit_fact 记录一条你观察到的事实（evidence 填导航 URL+页面标题）。
  完成即停。
靶站：example.com（无副作用）——跑通后可换 jwzx 登录页再跑一遍（带代理 env）
```

## 2. 验收清单

- [x] `v4/` 工程 `npm test` 绿（单测：db 插入/工具 schema 校验/闸机 block/池 probe）——16/16
- [x] smoke-1（example.com）：无人工干预，模型自主依次调 navigate → snapshot → submit_fact；SQLite nodes 表出现一行 fact，payload 含页面真实标题
- [x] smoke-2（假规则）：诱导 summary 含 test-block → 工具被 block，模型收到平台管控消息且不崩（转向或放弃）——实测模型读到「不得绕过」后去词重提，语义正确
- [ ] smoke-3（jwzx 匿名页，可选）：带代理 env 复跑 smoke-1，验证网络环境兼容（**未跑**，需代理 env）
- [x] 成本可见：事件流 usage 打印每轮 token 数（为 P1 activity 计量备料）
- [x] 浏览器收尾干净：smoke 后 Chrome 进程死、无残留（tasklist 零 chrome.exe，browser.json 已删）

## 3. 竣工记录（2026-10-16）

**通道实测结论（风险②收尾）**：bigmodel glm-5.3 双形态全通——openai 形态（`/paas/v4`，主选）与 anthropic 形态（`/api/anthropic`，备选验证可用）都能流式 + tool call 全链跑通。主选 openai：Python 版同通道、pi-ai `detectCompat` 对 `open.bigmodel.cn` 有原生 zai 分支。

**坑：glm-5.3 拒绝关闭思考**（错误码 1210「该模型始终思考，不支持关闭思考」）。pi 的 zai thinking 格式在 `thinkingLevel=off` 时发 `thinking:{type:"disabled"}` 直接 400。解法：`thinkingLevel: "low"` → pi 发 `{"type":"enabled"}`（实测 200；`{"type":"low"}` 也 400——type 只认 enabled/disabled，报错文案误导）。curl 直测：不带 thinking 参数也 200 且照样吐 reasoning_content。

**usage 结构（P1 activity 计量数据源）**：assistant message.usage = `{input, output, cacheRead, cacheWrite, totalTokens, cost{...}}`；openai 形态多一个 `reasoning` 字段，anthropic 形态多 `cacheWrite1h`。bigmodel 有 prompt cache（cacheRead 实测 640→1408 递增）。

**pi 消费方式（风险①收尾）**：file 依赖 `lernproject/pi-main/packages/{agent,ai}`，pi-main 内先 `npm install` + 逐包 build（telemetry → ai `build:offline`（需先 `hydrate-model-data` 生成 `src/providers/data/*.json`）→ agent）。v4 侧普通 npm install 即可解析。未走 vendor。

**其余实测**：
- `Agent` 构造：`initialState{systemPrompt,tools,model,thinkingLevel}` + `streamFn`（直接传 pi-ai 各 api 的 `streamSimple`）+ `getApiKey` 回调 + `beforeToolCall` 钩子，与施工卡行号锚点一致。
- block 语义：`BeforeToolCallResult{block:true, reason}` → reason 原样进 tool error result，模型读得到。
- Chrome detached：node `spawn({detached:true, windowsHide:true, stdio:"ignore"})` + `unref()` ≙ Python 版同款，杀树用 `taskkill /T /F` 带镜像名守门。
- playwright `connectOverCDP` 附着稳定；`page.locator("body").ariaSnapshot()` 做 snapshot 工具。
- npm 会拦 install scripts（警告但 better-sqlite3 prebuild 正常落地）。

**已知留账（P1 处理）**：node 侧直用 pi-agent-core 而非官方 SDK（`createAgentSession` 带全套 coding-agent 运行时，P0 不要）；官方文档在 `lernproject/pi-main/packages/coding-agent/docs/`（线上 https://pi.dev/docs/latest，40 页一致），P1+ 查 sessions/compaction/extensions 先看这里。

**独立复核（2026-10-16，另一会话真跑验证）**：`npm test` 16/16 + tsc 干净；smoke-1 真跑 PASS（4 轮 4548 token，evidence 精确遵守「动作→输出」纪律，confidence=observed，自发带 tags）；smoke-2 真跑 PASS **且超预期**——worker 被拦后未尝试绕拦，读拦截消息的「正确做法」去词自纠重提（**§4.3 平台管控框架首次真模型实证**）；两次 smoke 后 debug Chrome=0 零残留；`v4/.gitignore` 覆盖 node_modules/.at1/dist，19 个入库文件全净。

**P1 schema 对齐清单（P0 最简子集的已知偏差，P1 建表时修）**：①fact 节点 state 落 `'open'`——设计应为 `confirmed`（§2.6 状态机）；②nodes 无 `task_id` 列；③insertFact 无去重（P1 实现去重 key+幂等回执）；④`debug-probe.ts` 为通道调试遗物（保留复用）。

## 4. 风险与待实测（P0 内解决，不外溢）

| # | 风险 | 处置 |
|---|---|---|
| ① | pi 消费方式（pi-main 是 monorepo，无发布包名） | 优先 file/workspace 依赖实测；不行则 vendor `packages/agent`+`pi-ai` 进 v4（ licences Apache/MIT 类，注意保留版权头） |
| ② | bigmodel 对接走 anthropic 还是 openai 形态 | P0-1 双试，选流式+tool call 都正常的那个；记录配置进 `.secrets.env` 新段 |
| ③ | pi 事件流/工具协议细节与预期不符（AgentToolResult 结构等） | 以 `packages/agent/src/types.ts` 实测为准，施工卡中的行号引用即锚点 |
| ④ | Windows detached Chrome（browser.py 经验平移：DETACHED_PROCESS 标志） | 直译即可，jwzx 批已验证同款逻辑 |

## 5. P0 明确不做（边界）

- 不做 planner/事件驱动调度（P2）；不做 nodes 完整 schema/去重/落边（P1）；不做资产表（P3）；不做 retester/规则表全量（P4）；不做 MCP/skills/watch/CLI/多 task——**P0 的一切只为验证"地基能站人"**。
