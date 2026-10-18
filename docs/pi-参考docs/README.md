# Pi Agent 官方中文参考文档体系

> **版本来源**：Pi Coding Agent (pi-main 源码库最新版)  
> **整理时间**：2026-10-17  
> **整理方式**：完整保留并收录官方全部 42 篇参考文档（与官网 https://pi.dev/docs/latest 100% 对齐），按 5 大核心板块结构化归类，内部相对超链接与图片已完全修复打通，0 坏链，附带完整官方示例代码库 `examples/`。

---

## 架构概览与核心设计

Pi 是一个**极简主义、高性能、终端优先（Terminal-First）且完全可编程**的 AI Coding Agent。其核心架构具有以下标志性特点：

1. **极轻量内核，无冗余封装**：不同于层层嵌套的重型 Agent 框架，Pi 的核心代码高度凝聚，启动极快，内存占用极低。
2. **状态机与循环机制 (Agent Loop)**：以严格且透明的事件循环驱动工具调用、流式思考（Thinking/Reasoning）与上下文管理。
3. **基于 JSONL 的无限分支会话树 (Session Tree)**：会话持久化为易于解析和恢复的 JSONL 格式，天然支持任意历史分叉（Forking）、回溯与合并。
4. **智能上下文压缩 (Auto-Compaction & Branch Summaries)**：提供精细的自动压缩算法与分支摘要，保障在长周期编码任务中始终保留核心记忆与关键变更。
5. **全方位可扩展与无头集成**：
   - **Extensions 插件系统**：在交互终端内自定义工具、UI 浮层、状态栏与事件钩子；
   - **Pi SDK**：直接在 Node/TypeScript 代码中以原生 API 操控 Agent 会话；
   - **RPC & JSON 事件流**：提供无头守护进程模式，方便跨语言服务、IDE 插件或 Web 客户端无缝对接。

---

## 五大板块分类导航

```
pi-参考docs/
├── 01-入门与架构/          # 入门概览、快速开始、底层原理与工作机制
├── 02-运行与环境指南/      # 终端使用、多平台适配、本地模型与安全配置
├── 03-定制与配置指南/      # 配置层级、Prompt 模板、Skills 技能系统、MCP 集成
├── 04-二次开发与集成/      # Extensions 插件、自定义 Provider、TUI 组件与 SDK
├── 05-参考手册与底层规范/  # CLI 参数、Settings Schema、RPC 协议、数据结构与会话格式
├── 06-社区实践与进阶配置/  # 火炬树进阶指南、DeepakNess 实战长文、生产级配置模板
├── examples/               # 官方完整示例代码库 (40+ Extensions 范例、14 个渐进式 SDK 范例)
├── images/                 # 官方文档所有图元资源
└── docs.json               # 官方文档元数据与导航路由定义
```

---

### 板块 01：入门与架构 (Get Started)
👉 **[进入板块详细说明与导读](./01-入门与架构/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **Pi 概览** | [index.md](./01-入门与架构/index.md) | 设计理念、核心功能矩阵、官方架构全景 |
| **快速入门** | [quickstart.md](./01-入门与架构/quickstart.md) | 安装、鉴权配置、首次运行与交互模式基础 |
| **工作机制** | [how-pi-works.md](./01-入门与架构/how-pi-works.md) | Agent 会话循环、上下文组装、工具调用流水线与状态流转 |

---

### 板块 02：运行与环境指南 (Guides - Run Pi)
👉 **[进入板块详细说明与导读](./02-运行与环境指南/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **终端日常使用** | [usage.md](./02-运行与环境指南/usage.md) | 多行编辑、思考展示、状态栏指示器交互 |
| **模型选择与配置** | [models.md](./02-运行与环境指南/models.md) | 主模型、思考模型、分类模型与视觉模型配置 |
| **会话与上下文管理** | [sessions.md](./02-运行与环境指南/sessions.md) | 会话分支树、回溯、分支切换、导出与继续 |
| **安全与权限机制** | [security.md](./02-运行与环境指南/security.md) | 项目信任机制（Trust Manager）、破坏性操作拦截与路径防护 |
| **容器化与沙箱隔离** | [containerization.md](./02-运行与环境指南/containerization.md) | Docker 与无特权容器隔离运行方案 |
| **本地模型 llama.cpp** | [llama-cpp.md](./02-运行与环境指南/llama-cpp.md) | llama.cpp 部署对接、本地 GGUF 离线推理 |
| **NVIDIA RTX 显卡优化** | [nvidia-rtx-llama-cpp.md](./02-运行与环境指南/nvidia-rtx-llama-cpp.md) | 针对 GeForce RTX 平台的专有加速配置 |
| **终端与字体配置** | [terminal-setup.md](./02-运行与环境指南/terminal-setup.md) | Nerd Fonts 字体、真彩色显示、中英文对齐与排版优化 |
| **Shell 别名与快捷指令** | [shell-aliases.md](./02-运行与环境指南/shell-aliases.md) | Bash / Zsh / Fish 下的高频工作流别名 |
| **tmux 集成** | [tmux.md](./02-运行与环境指南/tmux.md) | tmux 多窗格布局、键位防冲突与持久化挂起 |
| **Windows 平台运行** | [windows.md](./02-运行与环境指南/windows.md) | Windows Terminal、PowerShell 与 WSL2 环境适配 |
| **Android Termux 运行** | [termux.md](./02-运行与环境指南/termux.md) | 移动端 Android Termux 完整部署与运行 |

---

### 板块 03：定制与配置指南 (Guides - Customize Pi)
👉 **[进入板块详细说明与导读](./03-定制与配置指南/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **全局与项目配置** | [configuration.md](./03-定制与配置指南/configuration.md) | `~/.pi/config` 与 `.pi/` 优先级与配置体系 |
| **提示词模板** | [prompt-templates.md](./03-定制与配置指南/prompt-templates.md) | 系统提示词模版定制、动态变量注入 |
| **Skills 技能系统** | [skills.md](./03-定制与配置指南/skills.md) | 声明式领域技能定义、按需激活、规则包隔离 |
| **UI 主题定制** | [themes.md](./03-定制与配置指南/themes.md) | 终端色彩主题定义、Syntax 高亮样式修改 |
| **Pi 软件包体系** | [packages.md](./03-定制与配置指南/packages.md) | 打包分发技能与扩展的 npm / git 封装机制 |
| **MCP 协议集成** | [mcp.md](./03-定制与配置指南/mcp.md) | Model Context Protocol 服务器连接、工具权限与暴露控制 |

---

### 板块 04：二次开发与集成 (Guides - Build on Pi)
👉 **[进入板块详细说明与导读](./04-二次开发与集成/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **Extension 扩展开发** | [extensions.md](./04-二次开发与集成/extensions.md) | 扩展生命周期 Hooks、输入拦截、自定义工具注入 |
| **自定义 Provider** | [custom-provider.md](./04-二次开发与集成/custom-provider.md) | 接入自定义大模型、实现私有 API 认证与流式协议 |
| **虚拟模型路由** | [virtual-models.md](./04-二次开发与集成/virtual-models.md) | 智能模型分流、成本/速率路由与自动容灾降级 |
| **终端 UI 组件开发** | [tui.md](./04-二次开发与集成/tui.md) | 基于 Blessed 构建终端交互组件、自定义浮层与状态栏 |
| **CLI 进程管道集成** | [cli-integration.md](./04-二次开发与集成/cli-integration.md) | 标准输入输出管道、子进程调度与批处理自动化 |
| **Pi SDK 核心开发** | [sdk.md](./04-二次开发与集成/sdk.md) | 编程式操控 `AgentSession`、生命周期事件订阅与执行控制 |

---

### 板块 05：参考手册与底层规范 (Reference)
👉 **[进入板块详细说明与导读](./05-参考手册与底层规范/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **CLI 命令行全量参数** | [cli.md](./05-参考手册与底层规范/cli.md) | 全量命令行选项（Flags）、参数与子命令速查 |
| **Codemode 模式规范** | [codemode.md](./05-参考手册与底层规范/codemode.md) | 纯代码模式的运行规范、上下文约束与行为准则 |
| **斜杠命令全集** | [slash-commands.md](./05-参考手册与底层规范/slash-commands.md) | `/help`, `/model`, `/compact`, `/tree` 等所有命令列表 |
| **Settings 配置项规范** | [settings.md](./05-参考手册与底层规范/settings.md) | 全局配置项字段列表、类型定义与默认值 Schema |
| **Models 模型配置规范** | [models-configuration.md](./05-参考手册与底层规范/models-configuration.md) | `models.json` 模型与 Provider 配置全量字段、API 兼容性表格与 Schema 字典 |
| **环境变量清单** | [environment-variables.md](./05-参考手册与底层规范/environment-variables.md) | 控制 Pi 运行行为的所有环境变量完整速查 |
| **快捷键映射速查** | [keybindings.md](./05-参考手册与底层规范/keybindings.md) | 快捷键配置规范、自定义快捷键与跨平台按键码 |
| **内置 Provider 规范** | [providers.md](./05-参考手册与底层规范/providers.md) | 官方支持的模型列表、Provider 参数规范 |
| **会话存储格式 (JSONL)** | [session-format.md](./05-参考手册与底层规范/session-format.md) | JSONL 文件底层结构、Entry 节点定义、树状 parentId 关系 |
| **上下文压缩算法** | [compaction.md](./05-参考手册与底层规范/compaction.md) | Auto-compaction 压缩策略、分支总结生成与扩展 |
| **JSON 事件流协议** | [json.md](./05-参考手册与底层规范/json.md) | Streaming JSON 输出规范、事件类型与前端解析协议 |
| **RPC 协议总规范** | [rpc.md](./05-参考手册与底层规范/rpc.md) | 基于 Stdio 的 JSON-RPC 2.0 规范与双向通信机制 |
| **RPC 命令参考手册** | [rpc-commands.md](./05-参考手册与底层规范/rpc-commands.md) | RPC 全量方法、入参报文与出参格式字典 |
| **RPC 扩展界面协议** | [rpc-extension-ui.md](./05-参考手册与底层规范/rpc-extension-ui.md) | RPC 模式下的扩展 UI 广播与交互事件规范 |
| **内部消息类型定义** | [message-types.md](./05-参考手册与底层规范/message-types.md) | `UserMessage`, `AssistantMessage`, `ToolCall` 严格类型定义 |

---

### 板块 06：社区实践与进阶配置 (Community Best Practices)
👉 **[进入板块详细说明与导读](./06-社区实践与进阶配置/README.md)**

| 文档 | 链接 | 核心内容 |
|:---|:---|:---|
| **Pi Agent 配置进阶实战指南** | [pi-agent-configuration-guide.md](./06-社区实践与进阶配置/pi-agent-configuration-guide.md) | 火炬树深度好文：5 层配置体系、settings.json 关键字段、models.json 自定义模型接入（Ollama/OpenRouter/代理）、Thinking 预算与生产模板 |
| **配置并日常使用 Pi 终端 Agent** | [deepakness-pi-agent-setup.md](./06-社区实践与进阶配置/deepakness-pi-agent-setup.md) | DeepakNess 实战长文：Pi + DeepSeek 主力工作流、极简底栏扩展、跨模型视觉接力、会话树导航、$1 抓取 28.5 万 URL 战绩 |
| **菜鸟教程：Pi Agent 中文入门实战指南** | [菜鸟教程分册目录](./06-社区实践与进阶配置/菜鸟教程-Pi-Agent中文入门实战教程/README.md) | 菜鸟教程 (RUNOOB.COM) 精华汇编（五大高密度板块）：从概念认知、DeepSeek 接入、会话分支树、自定义工具开发（TypeBox 实战）到国内网络避坑排查 |

---

## 示例代码库索引 (Examples)

在 [`examples/`](./examples/) 目录中包含了丰富的官方工程级参考范例：

- **SDK 实战案例 (`examples/sdk/`)**：
  - `01-minimal.ts`: 最小化 SDK 启动与单轮对话
  - `02-custom-model.ts`: 动态配置模型与推理参数
  - `03-custom-prompt.ts`: 自定义 System Prompt 与上下文
  - `04-skills.ts`: 编程式加载与注入 Skills
  - `05-tools.ts`: 注册自定义工具与函数调用
  - `06-extensions.ts`: 加载与执行 Extension 扩展
  - `07-context-files.ts`: 上下文文件预加载与管理
  - `08-prompt-templates.ts`: 模版加载与参数替换
  - `09-api-keys-and-oauth.ts`: 多 Provider 鉴权与 OAuth 状态管理
  - `10-settings.ts`: 编程式读取与修改全局 Settings
  - `11-sessions.ts`: 深度操作会话树（创建、分支、合并、遍历）
  - `12-full-control.ts`: 完整自定义事件循环接管
  - `13-session-runtime.ts`: 无头运行时深度集成
  - `14-codemode-mcp.ts`: 结合 MCP 工具的 Codemode 代码生成模式
- **Extensions 扩展范例 (`examples/extensions/`)**：
  - 核心工作流：`plan-mode/` (规划模式)、`git-checkpoint.ts` (自动 Git 检查点)、`custom-compaction.ts` (自定义压缩算法)、`dynamic-tools.ts` (动态工具注入)
  - 交互界面定制：`modal-editor.ts` (弹窗编辑器)、`custom-footer.ts` (自定义底栏)、`status-line.ts` (状态指示线)
  - 趣味与游戏演示：`doom-overlay/` (终端内嵌运行经典 Doom 毁灭战士)、`snake.ts` (贪吃蛇)、`space-invaders.ts` (太空侵略者)
- **RPC 范例**：
  - `rpc-client.ts`: 基于 Node.js 的无头 RPC 客户端实现
  - `rpc-extension-ui.ts`: 远程 RPC 客户端处理交互式扩展 UI 协议范例

---

## 社区精选深度实战指南

- 🎓 **[菜鸟教程：Pi Agent 中文入门与实战指南（五大精选板块）](./06-社区实践与进阶配置/菜鸟教程-Pi-Agent中文入门实战教程/README.md)**  
  *国内最全、最易上手的保姆级入门课程。摒弃碎片化小文件，深度整合为 5 篇大板块专篇：涵盖核心概念与 DeepSeek 极速接入、交互会话与 `/tree` 会话树、提示词模板与 Skills 规范、自定义工具开发（TypeBox 实战）及国内网络与环境避坑排查。*
- 📖 **[Pi Agent 配置进阶：AGENTS.md、模型切换与 Thinking Level 实战指南](./06-社区实践与进阶配置/pi-agent-configuration-guide.md)**  
  *国内火炬树（TorchTree）技术专栏深度实操。系统拆解了 Pi 的全局/项目配置层级、多 Provider 凭据管理、Thinking Level 适用场景矩阵、上下文自动压缩与会话树管理，并附带一套经过工程验证的开箱即用完整配置模板。*
- 📖 **[实战案例：配置并日常使用 Pi 终端编程 Agent](./06-社区实践与进阶配置/deepakness-pi-agent-setup.md)**  
  *海外一线全栈开发者 DeepakNess 的生产级长文实录。详细记载了如何将 Pi 与 DeepSeek 打造为个人主力日常编程工具（Daily Driver）、极简底栏插件定制、跨模型视觉接力（Vision Handoff）、会话树导航技巧，以及单次任务以 $1 美元超低成本抓取 28.5 万个 URL 的真实案例。*

---

## 常用开发工作流速查卡

### 1. 编程方式调用 Pi SDK 最小示例
```typescript
import { AgentSession } from "@earendil-works/pi-coding-agent";

async function main() {
  const session = new AgentSession({
    cwd: process.cwd(),
    model: "anthropic/claude-3-7-sonnet-20250219"
  });

  await session.init();

  session.events.on("assistant-chunk", (chunk) => {
    process.stdout.write(chunk.delta);
  });

  await session.prompt("分析当前目录下的代码结构并输出摘要");
}

main();
```

### 2. 编写一个最小 Extension 工具
```typescript
import { ExtensionContext } from "@earendil-works/pi-coding-agent";

export default function myExtension(context: ExtensionContext) {
  context.registerTool({
    name: "ping",
    description: "测试连通性",
    parameters: { type: "object", properties: { host: { type: "string" } } },
    execute: async (args) => {
      return { stdout: `Pong from ${args.host}` };
    }
  });
}
```

---

## 质量保证与维护说明
- 全量 42 篇官方文档与在线官网 `https://pi.dev/docs/latest` 及源码库保持 100% 内容一致与最新特性同步；
- 文档内部互相引用的相对链接（共 400+ 处）已按板块路径全部重写校准，确保在 GitHub 网页、VSCode、Obsidian 等 Markdown 环境下均可一键精准跳转；
- 图片引用已做双重兼容保障；
- 示例代码保持完整 TypeScript 语法高亮与可读性。
