---
title: "深度解读 Pi Agent：86.5K Star 的极简主义 AI Agent 框架"
source: "https://zhuanlan.zhihu.com/p/2070260828587161111"
author:
  - "[[山风]]"
published:
created: 2026-09-04
description: "本文内容较多，建议直接丢给AI进行总结。一、一句话说清楚 Pi Agent 是什么 Pi Agent（项目名 earendil-works/pi）是一个开源的、MIT 协议的生产级 AI Agent 运行时 SDK，由 Mario Zechner（@badlogic）创建并主导…"
tags:
  - "clippings"
---
[收录于 · AI相关知识](https://www.zhihu.com/column/c_2070260459027146341)

6 人赞同了该文章

> 本文内容较多，建议直接丢给AI进行总结。

## 一、一句话说清楚 Pi Agent 是什么

**Pi Agent** （项目名 `earendil-works/pi` ）是一个开源的、MIT 协议的生产级 AI Agent **运行时 SDK** ，由 Mario Zechner（@badlogic）创建并主导维护。它的定位很清晰—— **Claude Code 给你一个现成的 AI 助手，Pi 则给你一套构建 AI 助手的底层引擎和积木** 。

通俗来说，Pi Agent 是以极简架构为核心、可高度自定义的本地终端 AI 智能体的运行框架。

截至目前（2026 年 8 月），GitHub Star 数 **86,500+** ，Fork **10,700+** ，累计提交 **5,585 次** ，社区活跃度极高。

---

### 二、设计哲学：激进的极简主义

Pi 的设计哲学可以用一句话概括：

> **“The philosophy is radical minimalism: no MCP, no plan mode, no sub-agents by default.”** （没有MCP，没有计划模式，默认情况下没有子代理）

这不是工程能力的缺失，而是 **刻意的设计选择** 。Mario 创建 Pi 的起因，就是对现有编码 Agent 的不满：

- ❌ **隐藏的上下文注入** — 你不知道系统在提示词里塞了什么
- ❌ **版本间行为变化** — 升级后 agent 行为不可预期
- ❌ **工具描述吞噬巨量Token** — MCP 方式在用户输入前就烧掉 13,000+ 的Token

所以 Pi 的核心设计原则非常明确：

| 原则 | 含义 |
| --- | --- |
| 显式上下文控制 | LLM 上下文的每一个方面都可控制、可检查、可序列化 |
| 渐进式披露 | 工具按需加载，而不是启动时全量注入 |
| 做少不做多 | 不确定的功能宁可没有，也不做半成品 |
| CLI 优先 | 一切从命令行出发，TUI/Web UI 是锦上添花 |
| 透明 > 便利 | 宁可让用户多写两行，也不隐藏关键行为 |

---

### 三、架构剖析：严格分层的三层七包

Pi 采用了 **构建时强制的严格分层架构** ，每一层都可以独立使用：

```
┌──────────────────────────────────────────────────┐
│           应用层 (Application Layer)              │
│  ┌────────────────────────────────────────────┐  │
│  │  @earendil-works/pi-coding-agent           │  │
│  │  编码 Agent CLI/SDK                         │  │
│  │  · 会话管理  · 工具注册  · 项目上下文           │  │
│  │  · 扩展系统  · 技能路由  · 护栏/自审查          │  │
│  └────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────┤
│            核心层 (Core Layer)                    │
│  ┌────────────────────────────────────────────┐  │
│  │  @earendil-works/pi-agent-core             │  │
│  │  Agent 运行时                               │  │
│  │  · Agent Loop  · 工具执行  · 状态机          │  │
│  │  · 事件流    · 消息系统  · TypeBox 校验       │  │
│  └────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────┤
│           基础层 (Foundation Layer)               │
│  ┌────────────────────────────────────────────┐  │
│  │  @earendil-works/pi-ai                     │  │
│  │  统一 LLM API 基座                          │  │
│  │  · 20+ 提供商 · 上下文序列化 · Token 追踪     │  │
│  │  · 思维链支持 · 跨提供商切换                  │  │
│  └────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────┤
│            UI 层 & 辅助层                         │
│  ┌──────────────────┐  ┌──────────────────────┐  │
│  │  pi-tui          │  │  pi-web-ui           │  │
│  │  终端 UI 库      │  │  Web UI 组件          │  │
│  │  差分渲染/编辑器 │  │  聊天面板/Artifact      │  │
│  └──────────────────┘  └──────────────────────┘  │
│  ┌──────────────────┐  ┌──────────────────────┐  │
│  │  pi-mom          │  │  pi-pods             │  │
│  │  Slack 机器人    │  │  GPU Pod 管理器      │  │
│  └──────────────────┘  └──────────────────────┘  │
│  ┌──────────────────────────────────────────┐    │
│  │  pi-telemetry                            │    │
│  │  厂商无关的可观测性合约 + 参考适配器      │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### 3.1 基础层：pi-ai 统一多提供商 LLM API

这是 Pi 的根基。它抽象了 **20+ LLM 提供商** ：

- **商业版** ：Anthropic (Claude)、OpenAI (GPT)、Google (Gemini)、xAI (Grok)
- **免费版** ： [Groq](https://zhida.zhihu.com/search?content_id=281018992&content_type=Article&match_order=1&q=Groq&zhida_source=entity) (免费 tier)、Gemini (免费 tier)、OpenRouter (免费 tier)、GLM/Z.ai (免费 tier)、EURI (免费)
- **本地版** ：Ollama、vLLM、任何 OpenAI 兼容端点

一个特别强的能力是 **跨提供商上下文无缝切换，** Claude 的思维链（ `<thinking>` 标签）会以文本形式传递给 GPT/Gemini，实现跨模型对话延续。这在统一 API 设计中非常罕见。

### 3.2 核心层：pi-agent-core Agent 运行时

这是 Agent 的”大脑”，包含：

- **Agent Loop** ：可靠的 LLM 运行循环（模型调用 → 停止判断 → 错误处理）
- **工具执行管道** ：五步管道（定义 → 注册 → 拦截 → 执行 → 回收）
- **消息系统** ：内部 7 种自由表达，对外翻译为 OpenAI/Anthropic 等标准 Message 格式
- **事件驱动架构** ：同步屏障 + 发布订阅机制
- **TypeBox Schema 校验** ：工具参数全类型安全，自动校验

### 3.3 应用层：pi-coding-agent — 编码 Agent CLI

这是用户直接交互的层，提供：

- 交互式 REPL 环境
- 内置工具集： `read` 、 `bash` 、 `edit` 、 `write` 、 `glob` 、 `grep` 、 `notebook` 、 `task` 、 `web_search` 、 `web_fetch` 等
- 会话管理：保存、恢复、分叉
- 扩展与技能系统
- 护栏与自审查机制

---

### 四、核心能力详解

### 4.1 持久记忆

Agent 会将项目相关的事实保存到 `.pi/memory.md` ，跨会话自动加载。这意味着你今天和 Pi 讨论的设计决策，明天的会话里它还记得。

```
# .pi/memory.md 在后续会话中自动注入到上下文
pi "继续昨天的工作，完善用户登录模块"
```

### 4.2 🔍 自审查（Self-Review）

`--reflect` 标志触发一个有界的自审查 pass：Agent 完成工作后会重新检查输出，发现并修复真实问题后再提交最终结果。

```
pi --reflect "重构 utils.py，保持行为一致"
```

### 4.3 🛡️ 护栏系统（Guardrails）

默认开启，无需配置：

- **密钥泄露防护** ：阻止 API Key、Token 等敏感信息泄露
- **高危命令确认** ： `rm -rf` 等破坏性命令会触发二次确认
- **密钥自动脱敏** ：输出前自动遮挡密钥
- **提示注入检测** ：标记不可信的工具输出

### 4.4 📋 实时计划（Live Todos）

Agent 可以通过 `update_plan` 声明执行计划，用户会看到实时清单：

```
⬜ 分析现有代码结构        (pending)
⏳ 重构用户模块            (in_progress)
⬜ 更新单元测试            (pending)
✅ 代码格式化              (completed)
```

### 4.5 容错与弹性

- **智能重试** ：429 / 5xx / timeout 自动重试，最多 5 次，带随机抖动退避
- **上下文压缩** ：长会话自动裁剪历史，适配上下文窗口限制
- **会话序列化** ：完整上下文可序列化为 JSON，支持存储、迁移和”时光旅行调试”

### 4.6 🐳 容器化安全

Pi 默认以用户进程权限运行，不内置权限系统。需要强隔离时有三种方案：

| 方案 | 说明 |
| --- | --- |
| [Gondolin](https://zhida.zhihu.com/search?content_id=281018992&content_type=Article&match_order=1&q=Gondolin&zhida_source=entity) 扩展 | Host 运行 Pi + 认证，工具调用路由进本地 Linux 微 VM |
| Plain Docker | 整个 Pi 进程运行在 Docker 容器内 |
| OpenShell | 整进程运行在策略控制的沙箱中 |

### 4.7 📦 数据与文档工具

内建工具不仅仅是代码编辑，还覆盖了更广的工程场景：

- `analyze_data` — CSV/Excel 数据分析
- `make_slides` — PPTX 幻灯片生成
- `ingest` — 文档知识库摄入
- 项目 ZIP 上传（含 zip-slip 防护）

### 4.8 🔌 技能与扩展系统

通过 `SKILL.md` 文件注入提示词即可扩展能力。 `pi-mcp-adapter` 扩展可选接入 MCP 生态（GitHub、Postgres、Slack、Filesystem 等），但不作为核心内置。

```
pi install npm:pi-agents    # 安装通用 agent 编排扩展
pi install npm:pi-mcp-adapter  # 安装 MCP 适配器
```

---

### 五、Pi Agents：代数式工作流编排

这是 Pi 生态中最有设计感的模块—— **用代数表达式树来编排 Agent 工作流** 。

### 5.1 九种节点类型

| 节点 | 语义 | 用法 |
| --- | --- | --- |
| agent | 唯一叶子节点，运行一个委托 agent | {type: "agent", task: "..." } |
| sequence | 顺序执行，返回最后一步的值 | 串联多个步骤 |
| parallel | 并发运行命名分支，可选 reducer 合并 | mode: all\\\|any\\\|{quorum: n} |
| map | 按运行时数组逐元素扇出 | 对列表每一项执行相同操作 |
| loop | 有界 do-until，至少执行一次 | 条件匹配或达 max 时停止 |
| while | 有界预检查折叠 | 条件满足才执行 body |
| switch | 按序匹配谓词路由 | 必有 else，永不悬空 |
| value | 纯数据叶子，模板插值 | 不产生 agent |
| workflow | 按名内联调用已保存工作流 | 带循环检测 |

### 5.2 显式数据流

**规则很简单：数据只通过显式引用流动，没有隐式共享状态。**

```
flow:
  type: sequence
  steps:
    - type: agent
      as: finder           # ← 命名为 finder
      task: "找到所有需要重构的文件"
    - type: agent
      task: "对 {finder.files} 进行安全检查"  # ← 显式引用 finder 的输出
```

这种设计让复杂工作流 **可预测、可调试、可序列化** ，而不是 LLM 黑箱。

### 5.3 四种触发方式

1. **根模型触发** ：Agent 自主判断何时调用 `workflow` 工具
2. **用户斜杠命令** ： `/review` 、 `/review-fix` 等
3. **事件钩子** ： `on: [turn_end]` + debounce
4. **RPC 调用** ：通过事件总线远程启停

### 5.4 多层预算控制

| 预算 | 默认值 | 作用 |
| --- | --- | --- |
| maxAgents | 50 | 总 agent 执行数上限 |
| maxParallelism | 8 | 全局并发数 |
| maxIterations | 10 | 每个 loop/while 上限 |
| maxDepth | 5 | agent 嵌套深度 |
| maxTurns | 250 | 单个 agent 轮次 |
| maxTokens | 无 | Token 上限 |
| maxCost | 无 | USD 花费上限 |

---

### 六、供应链安全：业内最严谨之一

Pi 在依赖管理上的做法堪称教科书级别：

- **直接依赖精确锁定版本** （ `save-exact=true` ）
- **`min-release-age=2`** ：不解析发布不到 2 天的新包（防投毒）
- **`npm-shrinkwrap.json`** ：发布包锁定所有传递依赖
- **显式白名单** ：依赖生命周期脚本逐项审批
- **CI 定时审计** ： `npm audit --omit=dev` + `npm audit signatures --omit=dev`
- **Pre-commit 钩子** ：阻止意外的 lockfile 变更

---

### 七、与主流框架的定位对比

| 维度 | Pi Agent | LangChain/LangGraph | CrewAI | OpenAI Agents SDK | Claude Code |
| --- | --- | --- | --- | --- | --- |
| 定位 | Agent 运行时基座 | 通用编排框架 | 角色协作框架 | OpenAI 原生 SDK | 开箱即用产品 |
| 多 Agent | ❌ 默认不支持 | ✅ 图编排 | ✅ 角色模型 | ✅ Handoff | ❌ 单 Agent |
| MCP | ⚠️ 可选扩展 | ✅ 成熟集成 | ✅ 支持 | ✅ 支持 | ✅ 原生支持 |
| 跨提供商 | ✅ 20+ 原生 | ⚠️ 适配器 | ⚠️ 适配器 | ❌ OpenAI 优先 | ❌ Anthropic |
| 上下文控制 | ✅ 核心卖点 | ⚠️ 一般 | ⚠️ 框架管理 | ⚠️ 框架管理 | ❌ 黑箱 |
| 学习曲线 | 中等 | 陡峭 | 平缓 | 平缓 | 极低 |
| 社区规模 | 中等 | 极大 | 大 | 大 | 大 |
| 供应链安全 | ✅ 行业标杆 | ⚠️ 一般 | ⚠️ 一般 | ✅ 良好 | N/A |

### Pi 的差异化优势

1. **上下文透明** ：在”上下文工程”这个维度上，Pi 做到了业内最精细的控制
2. **跨提供商连续性** ：Claude → GPT → Gemini 无缝切换，保留思维链，独此一家
3. **供应链安全** ：依赖治理水平远超同类开源项目
4. **代数式编排** ：Agent 工作流的表达式树模型非常有设计感

### Pi 的明确短板

1. **不做多 Agent** （设计决策，非能力缺失）
2. **不做 MCP** （核心不内置，但可通过扩展接入）
3. **不做自动记忆** （无向量库，需手动管理）
4. **社区相对小** （单人维护为主）
5. **文档不够体系化** （以 README 和博客为主）

---

### 八、创建者：Mario Zechner 是谁？

很多人在 Pi Agent 和 OpenClaw 之间产生混淆——因为两个项目都是奥地利人创建的。但 **这是两位完全不同的开发者** ：

| 维度 | Mario Zechner（@badlogic） | Peter Steinberger |
| --- | --- | --- |
| 身份 | 软件工程师、开源作者、技术书籍作者 | 连续创业者、前 PSPDFKit 创始人 |
| 代表作 | libGDX（23K Star）、Pi Agent（86.5K Star） | PSPDFKit（装机 10 亿+）、OpenClaw（247K Star） |
| 背景 | 格拉茨工业大学软件工程学士；Know-Center 研究员；旧金山手游创业公司技术负责人 | PSPDFKit 经营 13 年，以超 1 亿美元退出；经历 3 年职业倦怠后重返 |
| 著作 | 《Beginning Android Games》（Apress 出版） | 无 |
| 擅长领域 | 游戏引擎、编译器、虚拟机、NLP、信息可视化 | PDF 引擎、移动 SDK、产品商业化 |
| 设计风格 | 极简主义、强观点、透明优先、做少不做多 | 快速原型、产品思维、社区驱动 |
| 近况 | 持续维护 Pi Agent 及相关项目 | 2026 年 2 月加入 OpenAI 负责下一代个人 Agent |
| GitHub | [github.com/badlogic](https://link.zhihu.com/?target=http%3A//github.com/badlogic) | [github.com/steipete](https://link.zhihu.com/?target=http%3A//github.com/steipete) |

Mario Zechner 从 12 岁开始编程，有超过 20 年的软件工程经验。除了 libGDX 和 Pi Agent，他还创建了 RoboVM 调试器、奥地利超市比价网站 [heisse-preise.io](https://link.zhihu.com/?target=http%3A//heisse-preise.io) 、复古渲染教程系列 r96、DOS 风格汇编编程环境 ulang 等项目。他的技术广度（从游戏引擎底层到 LLM Agent 运行时）在开源社区非常罕见。

> **关键澄清** ：OpenClaw 的运行时底层使用了 Pi Agent，但 OpenClaw 是 Peter Steinberger 的产品，Pi Agent 是 Mario Zechner 的框架。两人的关系是：一个造运行时，一个用这个运行时造产品（有些自媒体会将这些搞混，在此特别备注一下）。

---

### 九、Pi Agent 能做什么？—— 打造自己的 Claude Code / Codex / WorkBuddy

这是 Pi Agent 最核心最有价值的东西： **Claude Code / Codex / WorkBuddy 是成品 App，Pi 则是你用来组装这些 App 的底层引擎和乐高积木** 。Pi 提供完整的三层 SDK，可以基于它构建任何形态的编码助手产品。

### 9.1 用代码说话：30 行实现一个最简编码 Agent

```
import { Agent } from "@earendil-works/pi-agent-core";
import { getModel } from "@earendil-works/pi-ai";
import { Type } from "@sinclair/typebox";

// 1. 定义工具
const readFileTool = {
  name: "read_file",
  label: "Read File",
  description: "Read a file's contents",
  parameters: Type.Object({
    path: Type.String({ description: "File path" })
  }),
  execute: async (toolCallId, params, signal, onUpdate) => {
    const content = await fs.readFile(params.path, "utf-8");
    return {
      content: [{ type: "text", text: content }],
      details: { size: content.length }
    };
  },
};

// 2. 创建 Agent
const agent = new Agent({
  initialState: {
    systemPrompt: "You are a coding assistant. Use tools to help the user.",
    model: getModel("anthropic", "claude-sonnet-4-20250514"),
    thinkingLevel: "medium",
    tools: [readFileTool, writeFileTool, bashTool, grepTool, globTool],
    messages: []
  }
});

// 3. 订阅事件流 —— 任意 UI 自由渲染
agent.subscribe((event) => {
  if (event.type === "message_update" && 
      event.assistantMessageEvent.type === "text_delta") {
    process.stdout.write(event.assistantMessageEvent.delta); // 流式输出
  }
  if (event.type === "tool_execution_start") {
    console.log(\`\n🔧 ${event.toolCall.name} ...\`);
  }
});

// 4. 运行
await agent.prompt("找出项目中所有未使用的 import 并删除");
```

**这就是一个最简版「Claude Code 内核」。** 剩下的 UI、权限、工作流都是你围绕它构建的「壳」。

### 9.2 Pi SDK 的产品化分层模型

```
┌──────────────────────────────────────────────────────────────┐
│  你构建的产品层                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ 自定义 UI │ │ 自定义工具│ │ 自定义护栏│ │ 自定义工作流  │  │
│  │ TUI/Web/  │ │ 部署/数据库│ │ 企业安全 │ │ 代码审查/重构 │  │
│  │ IDE 插件  │ │ API/业务  │ │ 审计策略 │ │ CI/CD 集成   │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
├──────────────────────────────────────────────────────────────┤
│  Pi SDK 层                                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  pi-agent-core — Agent 运行时                        │   │
│  │  · Agent Loop（自动重试/错误恢复）                    │   │
│  │  · 事件流（text_delta / tool_start / tool_end 等）   │   │
│  │  · TypeBox 类型安全工具校验                          │   │
│  │  · 会话管理 + 上下文序列化                           │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  pi-ai — 统一 LLM API 基座                          │   │
│  │  · 20+ 提供商 / 跨提供商切换 / 思维链传递            │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 9.3 Pi SDK vs Claude Agent SDK vs 从零自研

| 维度 | Pi Agent SDK | Claude Agent SDK | 从零自研 |
| --- | --- | --- | --- |
| Agent Loop | ✅ 开箱即用（状态机、重试、错误恢复） | ✅ 开箱即用 | ❌ 需自建 |
| 工具系统 | ✅ TypeBox 类型安全校验管道 | ✅ 框架内置 | ❌ 需自建校验 |
| 事件流 | ✅ 细粒度事件（text\_delta / tool\_start / tool\_end） | ✅ 框架内置 | ❌ 需自建 SSE/WS |
| 多提供商 | ✅ 20+ 原生支持，跨提供商无缝切换 | ❌ 仅 Anthropic | ⚠️ 需逐一适配 |
| 上下文序列化 | ✅ JSON 完整序列化（时光旅行调试） | ⚠️ 框架管理 | ❌ 需自建 |
| 护栏系统 | ✅ 默认开启（密钥泄露/注入检测） | ⚠️ 需自行配置 | ❌ 需自建 |
| 供应链安全 | ✅ 依赖精确锁定 + 定期审计 | ✅ Anthropic 背书 | ⚠️ 取决于实践 |
| 自定义 UI | ✅ 完全自由（TUI/Web/IDE 任选） | ⚠️ 受限于 SDK | ✅ 完全自由 |
| 模型自由 | ✅ 任意提供商自由切换 | ❌ 锁定 Anthropic | ✅ 但需自建抽象层 |
| 许可证 | MIT（完全自由商用） | 闭源 SDK | 无限制 |

### 9.4 已有产品案例：别人已经用 Pi SDK 造了什么

**① One Code — 把 Claude Code 完整体验搬到 Pi 上**

```
pi install npm:one-code-extension
```

给 Pi 加上了：子 Agent、Ultracode 工作流、Skills 系统、MCP 协议、Plan Mode、Hooks、权限系统、项目记忆、`.claude/` 配置完全兼容。本质是 **用 Pi 的运行时，跑 Claude Code 的全部功能，模型任选** 。

**② Claude-Pi-Bridge — 异构模型混合编排**

```
Claude Code（项目经理/编排层）
    ├── Pi Agent #1（Groq + Llama 3.3 70B）→ 代码生成
    ├── Pi Agent #2（Anthropic + Claude Sonnet）→ 代码审查
    └── Pi Agent #3（OpenRouter + DeepSeek V3）→ 测试生成
```

Claude Code 作为「项目经理」，通过 MCP 协议并行派发任务给多只 Pi Agent，每只跑在不同模型/提供商上，实现成本与能力的混合调度。

**③ OpenClaw（247K Star）**

底层运行时使用的就是 Pi Agent。这是 Pi 作为产品底座最有说服力的案例——247K Star 的产品就是最好的「可行性证明」。

**④ Vercel AI SDK 的 Harness Adapter**

Vercel 官方提供了 `@ai-sdk/harness-pi` ，将 Pi 作为标准化 Harness Agent 接口，与 Claude Code、Codex、DeepAgents、OpenCode、Grok Build 并列为官方支持的 Agent Harness。

**⑤ Edge-Pi**

基于 Vercel AI SDK 重新实现的 Pi 核心逻辑，定位为 Claude Agent SDK 的开源替代品。

---

### 个人评价

Pi Agent 是我见过设计哲学最自洽的 AI Agent 框架。

它不自称”通用框架”，而是老老实实做一个 **编码 Agent 的运行时底座** 。在”什么都想做”的 Agent 框架军备竞赛中，Pi 选择了反向操作—— **通过不做什么来定义自己** 。不内置 MCP、不支持子 Agent、不做自动记忆，每个”缺失”背后都是一个深思熟虑的立场。

这种克制在今天的 AI 工具生态里非常罕见，也恰恰是 Pi 最大的价值——它让你真正 **理解并掌控 Agent 的每一个字节的上下文** ，而不是信任一个黑箱。

如果你是一个想深入理解 AI Agent 运行机制的工程师，读 Pi 的源码会非常有价值。

**参考来源：**

- [Pi 官方文档](https://link.zhihu.com/?target=https%3A//pi.dev/docs/latest)
- [earendil-works/pi GitHub](https://link.zhihu.com/?target=https%3A//github.com/earendil-works/pi)
- [framework-analysis: Pi 框架深度分析](https://link.zhihu.com/?target=https%3A//github.com/larsderidder/framework-analysis/blob/main/tier-2/pi.md)
- [The Best AI Agent Frameworks for 2026 — Signadot](https://link.zhihu.com/?target=https%3A//www.signadot.com/blog/the-best-ai-agent-frameworks-for-2026/)
- [State of AI Agents — March 2026](https://link.zhihu.com/?target=https%3A//github.com/zzhiyuann/state-of-ai-agents)
- [JamJet: AI Agents Need Their Spring Moment](https://link.zhihu.com/?target=https%3A//jamjet.dev/blog/jamjet-java-ai-ecosystem/)
- [Pi Agent Extensions Guide — AI Builder Club](https://link.zhihu.com/?target=https%3A//www.aibuilderclub.com/blog/pi-agent-extensions-guide)
- [Vercel AI SDK Harness Adapters (Claude Code, Codex, Pi)](https://link.zhihu.com/?target=https%3A//deepwiki.com/vercel/ai/5.2-harness-adapters)
- [Who Is Peter Steinberger? — Inbounter](https://link.zhihu.com/?target=https%3A//inbounter.com/blog/who-is-peter-steinberger-openclaw)
- [OpenAI Hires OpenClaw Creator — PCMag](https://link.zhihu.com/?target=https%3A//uk.pcmag.com/ai/163182/creator-of-viral-ai-tool-openclaw-joins-openai)
- [Mario Zechner CV](https://link.zhihu.com/?target=http%3A//www.apistudios.com/hosted/marzec/badlogic/downloads/Zechner%2520Mario%2520-%2520Curriculum%2520Vitae.pdf)

还没有人送礼物，鼓励一下作者吧

编辑于 2026-08-10 21:57・上海

赞同 6