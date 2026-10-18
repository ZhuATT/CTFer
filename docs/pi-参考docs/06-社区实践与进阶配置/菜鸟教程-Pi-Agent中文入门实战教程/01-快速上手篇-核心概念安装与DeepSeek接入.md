# 模块一：快速上手篇 —— 核心概念、安装配置与 DeepSeek 极速接入

> **本篇定位**：本篇系统讲解 Pi Agent 的核心定位、四种运行模式、Node.js 22+ 环境准备、认证体系配置以及国内高性价比模型 DeepSeek 的极速接入与首次对话验证。  
> **来源**：菜鸟教程 (RUNOOB.COM) Pi Agent 系列课程精华汇编  

---

## 📑 章节目录导航

- [一、教程导读与学习前置](#一教程导读与学习前置)
- [二、Pi Agent 简介与核心理念](#二Pi-Agent-简介与核心理念)
- [三、核心概念与四大运行模式](#三核心概念与四大运行模式)
- [四、环境准备与 Pi 安装](#四环境准备与-Pi-安装)
- [五、认证体系与模型配置 (auth.json)](#五认证体系与模型配置-authjson)
- [六、国内首选：接入 DeepSeek 全流程](#六国内首选接入-DeepSeek-全流程)
- [七、首次对话与代码协同验证](#七首次对话与代码协同验证)

---

## 一、教程导读与学习前置

### 什么是 Pi Agent？

Pi Agent 是一种面向开发者的 AI Agent 框架，它将大语言模型、工具调用、任务规划和执行能力结合起来。

传统 AI 聊天机器人只能回答问题，而 Agent 可以理解目标，并主动调用工具完成任务。

- 让 AI 从「回答问题」升级为「执行任务」
- 支持调用外部工具、API、数据库和系统能力
- 可以构建个人 AI 助手、自动化机器人和智能工作流
- 帮助开发者快速学习 AI Agent 开发模式

### 谁适合阅读本教程？

本教程适合希望学习 AI Agent 开发的开发者。

- 想学习大语言模型应用开发的新手
- 希望掌握 AI Agent 工作原理的程序员
- 想使用 AI 自动化日常工作的开发者
- 希望开发个人 AI 助手、智能机器人或自动化工具的人员
- 希望从传统软件开发进入 AI 应用开发领域的人

### 学习本教程前你需要了解

学习本教程前，你需要了解一些基础编程知识以及人工智能基础概念。

- Python 基础：变量、函数、类、模块导入
- 基础 Web 知识：HTTP 请求、API 调用、JSON 数据格式
- 了解大语言模型（LLM）基本概念，例如 ChatGPT、Claude、Gemini 等
- 了解命令行工具和开发环境配置
- 了解 Git 基础操作（推荐）

### Pi Agent 可以做什么？

- 创建个人 AI 助手
- 自动执行重复性任务
- 调用搜索、数据库、文件等外部工具
- 构建企业智能客服系统
- 开发 AI 自动化工作流
- 结合大语言模型打造智能应用

### Pi Agent 学习路线

- 了解 Agent 基础概念
- 学习模型调用和 Prompt 设计
- 掌握 Tool Calling 工具调用
- 开发多步骤任务 Agent
- 构建完整 AI 应用

### 参考文档

- Pi Agent 官网：[https://pi.dev/](https://pi.dev/)
- Pi Agent Github 地址：[https://github.com/earendil-works/pi](https://github.com/earendil-works/pi)
- Pi Agent 官方文档：[https://pi.dev/docs/latest](https://pi.dev/docs/latest)

---

---

## 二、Pi Agent 简介与核心理念

Pi Agent（全称 Pi Coding Agent，下文简称 Pi）是一个极简的终端 AI 编程助手，在命令行界面中通过自然语言对话帮你完成编码任务。

Pi Agent 由 earendil-works 团队开发，核心代码保持精简，同时通过可扩展的插件体系支持各种工作流。

Pi 是一个运行在终端里的 AI 编码 Agent，类似于 Claude Code、OpenAI Codex CLI 这类工具。

Pi 的官方理念是："There are many agent harnesses but this one is yours"（Agent 工具很多，但这个是你自己的）。

### 什么是 Pi Agent

Pi Agent 是一个运行在终端（Terminal）中的编程助手。

你可以在项目目录中启动它，用自然语言描述需求，它会读取你的代码、执行命令、修改文件，像一个协作开发者一样工作。

它的核心设计原则是：核心保持最小化，工作流相关的功能通过 Extensions（扩展）、Skills（技能）、Prompt Templates（提示词模板）和 Themes（主题）来实现，而不是内置到核心中。

### Pi Agent 与其他工具的区别

Pi Agent 的定位与以下工具类似但又有所不同：

| 对比维度 | Pi Agent | Claude Code | GitHub Copilot / Codex CLI |
| --- | --- | --- | --- |
| 运行方式 | 终端 TUI | 终端 TUI | 终端 TUI |
| 核心大小 | 极简，无内置 MCP/子代理等 | 功能较多（Hook、MCP、子代理等） | 中等 |
| 扩展方式 | TypeScript 扩展 + Skills + 包 | Hook + MCP 服务器 + Skills | Skills + MCP |
| 支持的 AI 提供商 | 30+ 提供商（订阅 + API Key） | Anthropic API 为主 | GitHub Copilot / OpenAI |
| 会话管理 | 树状分支，支持 fork/clone | 线性 + 分支恢复 | 基本会话管理 |
| 包生态系统 | 有（npm/git 分发包） | 无内置包管理 | Skills 仓库 |
| 本地模型支持 | 内置 llama.cpp 支持 | 以内置云提供商为主 | 以内置云提供商为主 |

### 核心特性一览

Pi Agent 的核心特性覆盖运行模式、提供商接入、内置工具、扩展体系和主题定制，足以支撑日常的终端编程工作。

| 特性 | 说明 |
| --- | --- |
| 多模式运行 | 交互模式、Print 模式（-p）、JSON 模式、RPC 模式 |
| 丰富的 AI 提供商 | 支持 Anthropic、OpenAI、Google Gemini、DeepSeek、Groq、xAI、Mistral 等 30+ 提供商 |
| 内置编程工具 | 默认启用 read（读文件）、write（写文件）、edit（编辑文件）、bash（执行命令）四种内置工具，grep、find、ls 为只读工具，可选开启 |
| TypeScript 扩展 | 自定义工具、事件钩子、命令注册、UI 交互 |
| Skills 系统 | 兼容 Agent Skills 标准，按需加载专业能力 |
| 树状会话 | 支持分支、克隆与废弃分支摘要，轻松探索不同方案 |
| 提示词模板 | 可复用的 Markdown 提示词，支持参数替换 |
| 主题定制 | 51 个颜色令牌，支持暗色/亮色主题和自定义配色 |
| 包管理 | 通过 npm/git 安装和分享扩展、技能、模板和主题 |
| 本地模型 | 内置 llama.cpp 路由器支持，可直接管理本地模型 |

### 适用场景

Pi Agent 适合以下使用场景：

| 场景 | 说明 |
| --- | --- |
| 终端编码任务 | 在终端中快速完成代码修改和工程任务 |
| 多模型协作 | 通过 Ctrl+P 切换，在同一会话中使用多个 AI 模型 |
| 自定义工具扩展 | 开发团队用 TypeScript 编写自己的工具、命令和 UI 组件 |
| 方案探索 | 借助会话树状分支，同时保留多条实现思路 |
| 自动化任务 | 在容器或沙盒中运行无界面的自动化任务 |
| 团队共享配置 | 通过包系统在团队间分享扩展、技能、模板和主题 |

### 设计哲学

Pi Agent 的核心理念是：不做大而全，而是提供可组合的基础能力。

它的创作者认为，过多的内置功能会让工具变得臃肿且难以维护。

因此 Pi Agent 将核心限定在最小的可用范围内，其余能力交由扩展系统完成。

这种设计的好处包括：

| 好处 | 说明 |
| --- | --- |
| 维护成本低 | 核心代码量小，更容易理解和维护 |
| 按需安装 | 你只安装真正需要的功能，界面保持干净 |
| 扩展门槛低 | 一个 TypeScript 文件就能写出可用的扩展 |
| 社区共建 | 社区可以自由贡献和分享扩展包 |

---

---

## 三、核心概念与四大运行模式

在正式使用 Pi Agent 之前，先了解它的核心概念和工作方式，能帮助你更快上手。

### 一句话理解 Pi Agent

Pi Agent 是一个运行在终端里的 AI 编程助手。

启动后你会看到类似聊天软件的界面，输入自然语言需求，AI 就能读取你的代码、执行命令、修改文件。

### 四种运行模式

Pi Agent 支持四种运行模式，适应不同场景：

| 模式 | 命令 | 说明 | 适用场景 |
| --- | --- | --- | --- |
| 交互模式 | pi（默认） | 终端 TUI 界面，实时对话，支持所有功能 | 日常开发、交互式编程 |
| Print 模式 | pi -p "提示词" | 一次性问答，输出结果后退出 | 脚本集成、快速查询 |
| JSON 模式 | pi --mode json | 所有事件以 JSON 行输出，适合程序解析 | 工具链集成、数据分析 |
| RPC 模式 | pi --mode rpc | 通过 stdin/stdout 的 JSONL 协议集成 | 进程间通信、编辑器插件 |

交互模式直接启动，进入 TUI 界面：

```
$ pi

Pi Agent 0.1.x  |  ~/projects/runoob-demo

claude-sonnet-4  |  上下文 2%  |  $0.0000

>
```

Print 模式回答完就退出，适合放进脚本：

```typescript
$ pi -p "总结这个项目"

这是一个 TypeScript 命令行工具，核心逻辑位于 src/ 目录，包含会话管理、工具调度和扩展加载三个模块。

Tokens: 1.2k 输入 / 320 输出  |  费用 $0.0081
```

JSON 模式把每个事件输出为一行 JSON，方便程序解析：

```
$ pi --mode json -p "总结这个项目"

{"type":"session","id":"a1b2c3d4"}

{"type":"message_start","role":"assistant"}

{"type":"message_end","usage":{"input":1200,"output":320}}
```

RPC 模式通过 stdin/stdout 收发 JSONL 消息，供编辑器插件调用：

```
$ pi --mode rpc

{"id":1,"method":"prompt","params":{"message":"列出 src 目录"}}

{"id":1,"result":{"state":"idle","messages":2}}
```

作为初学者，你大部分时间都在交互模式下工作。

当你熟练后，Print 模式可以用于脚本自动化。

### 内置工具

Pi Agent 启动后会默认给予 AI 下面四种内置工具，另有 grep、find、ls 三个只读工具可选开启：

| 工具名 | 功能 | 示例 | 默认状态 |
| --- | --- | --- | --- |
| read | 读取文件内容 | AI 读取 src/main.ts 理解代码逻辑 | 默认启用 |
| write | 创建或覆盖文件 | AI 创建新文件或重写整个文件 | 默认启用 |
| edit | 精确替换文件中的内容 | AI 修改函数中的某几行代码 | 默认启用 |
| bash | 执行 shell 命令 | AI 运行测试、安装依赖、执行 lint | 默认启用 |
| grep | 在文件中搜索文本 | AI 搜索某个函数在哪些文件中被调用 | 可选开启 |
| find | 按名称搜索文件 | AI 找出所有名为 *.test.ts 的文件 | 可选开启 |
| ls | 列出目录内容 | AI 查看目录结构定位模块 | 可选开启 |

三个只读工具通过--tools参数手动开启，例如pi --tools read,grep,find,ls。

### 扩展体系

Pi Agent 通过以下五种方式扩展功能：

| 扩展方式 | 文件格式 | 用途 | 难度 |
| --- | --- | --- | --- |
| Extensions（扩展） | TypeScript（.ts） | 注册自定义工具、事件监听、命令、UI 组件 | 需要编程 |
| Skills（技能） | Markdown（SKILL.md） | 提供专业领域的工作流指令和脚本 | 会写 Markdown 即可 |
| Prompt Templates（提示词模板） | Markdown（.md） | 可复用的提示词，支持参数 | 最简单 |
| Themes（主题） | JSON（.json） | 自定义终端界面配色 | 简单 |
| Packages（包） | npm/git 项目 | 打包和分享以上四种资源 | 按需 |

### 文件加载顺序

Pi Agent 启动时会自动加载项目指令文件，让你可以约定 AI 的行为规范：

| 级别 | 路径 | 作用范围 | 优先级 |
| --- | --- | --- | --- |
| 全局配置 | ~/.pi/agent/AGENTS.md | 所有项目 | 最低，作为通用基线 |
| 项目配置 | 项目目录及父目录中的 AGENTS.md 或 CLAUDE.md | 当前项目 | 最高，可覆盖全局指令 |

项目级的配置会从父目录向上遍历加载，最终和当前目录的配置合并。

### 会话与分支

Pi Agent 的会话系统是其最独特的特性之一。

每次对话会自动保存为一个会话文件，存放在~/.pi/agent/sessions/中。

会话内部是树状结构：你可以在任意历史节点「分叉」出新的探索方向，而不会丢失之前的对话。

这在你需要试验不同的实现方案时非常有用——每条思路都可以独立保留、随时回溯。

---

---

## 四、环境准备与 Pi 安装

本章介绍如何在不同平台上安装 Pi Agent，并完成基础环境配置。

### 环境要求

在安装 Pi Agent 之前，请确保你的系统满足以下要求：

| 依赖项 | 最低版本 | 说明 |
| --- | --- | --- |
| Node.js | 建议 18 LTS 或更高 | Pi Agent 基于 Node.js 运行，需要支持现代 JavaScript 特性的运行环境 |
| npm | 随 Node.js 自带 | 用于安装 Pi Agent 和扩展包 |
| 终端 | 支持 True Color | 推荐 iTerm2（macOS）、Windows Terminal、Kitty、WezTerm |

检查 Node.js 是否已安装：

```bash
node --version
```

输出类似：

```
v20.11.0
```

查看 npm 是否同步安装（安装 Node.js 会自带）：

```bash
npm --version
```

输出类似：

```
10.2.4
```

### 安装

#### 方式一：npm 全局安装

这是最通用、最简单的安装方式，适用于 macOS、Linux 和 Windows：

```
# 全局安装 Pi Agent

# --ignore-scripts 禁用依赖包的生命周期脚本，提高安装安全性

npm install -g --ignore-scripts @earendil-works/pi-coding-agent
```

安装完成后验证版本:

```bash
pi --version
```

安装完成后，pi命令就可以在终端中直接使用了。

#### 方式二：curl 一键脚本

在 Linux 或 macOS 上，也可以使用官方安装脚本：

```
# 使用 curl 下载并执行安装脚本

curl -fsSL https://pi.dev/install.sh | sh
```

这个脚本会自动检测你的系统并完成安装，本质也是通过 npm 全局安装。

#### 方式三：其他包管理器

如果你使用 pnpm、Yarn 或 Bun，也可以用对应的命令安装：

```
# 使用 pnpm 安装

pnpm add -g @earendil-works/pi-coding-agent



# 使用 Yarn 安装

yarn global add @earendil-works/pi-coding-agent



# 使用 Bun 安装

bun install -g @earendil-works/pi-coding-agent
```

### 卸载方法

卸载 Pi Agent 时，请使用与你安装时相同的包管理器：

```
# npm 或 curl 安装的用 npm 卸载

npm uninstall -g @earendil-works/pi-coding-agent



# pnpm 安装的

pnpm remove -g @earendil-works/pi-coding-agent



# Yarn 安装的

yarn global remove @earendil-works/pi-coding-agent



# Bun 安装的

bun uninstall -g @earendil-works/pi-coding-agent
```

### 终端建议

Pi Agent 使用 24 位 RGB 色彩渲染终端界面，推荐使用以下终端以获得最佳体验：

| 平台 | 推荐终端 | 说明 |
| --- | --- | --- |
| macOS | iTerm2、Kitty、Warp | 原生支持 True Color，内嵌图片显示效果好 |
| Windows | Windows Terminal、WezTerm | Windows Terminal 是官方推荐的现代终端 |
| Linux | Kitty、WezTerm、Alacritty | 都支持 True Color 和 GPU 加速 |

检查你的终端是否支持 True Color：

```
$ echo $COLORTERM

truecolor
```

如果输出是truecolor或24bit，说明你的终端支持完整的色彩渲染。

### 首次运行

安装完成后，进入一个项目目录并启动 Pi Agent：

```
$ cd /path/to/your-project

$ pi
```

首次启动时，你会看到 Pi Agent 的欢迎界面。

此时还没有配置 AI 提供商，你需要先完成认证——这将在下一章详细说明。

### 更新 Pi Agent

保持 Pi Agent 更新到最新版本：

```
# 仅更新 Pi Agent 本身

pi update --self



# 更新 Pi Agent 和所有已安装的扩展包

pi update --all



# 更新模型目录（获取最新的可用模型列表）

pi update --models
```

使用--self --force可以强制重装 Pi Agent，即使当前已是最新版本：

```
$ pi update --self --force
```

需要注意，通过 install.sh 等安装脚本托管的安装不支持--force。

这类托管安装需要修复时，重新运行一次安装脚本即可。

---

---

## 五、认证体系与模型配置 (auth.json)

Pi Agent 支持两种认证方式：订阅登录和 API Key。本章详细介绍如何配置，让 Pi Agent 连接到 AI 模型。

### 认证方式概览

| 认证方式 | 操作方法 | 适用场景 |
| --- | --- | --- |
| 订阅登录（OAuth） | 启动 pi 后执行 /login | 已有 Claude Pro/Max、ChatGPT Plus/Pro、GitHub Copilot 等订阅 |
| API Key 环境变量 | 设置环境变量后启动 pi | 有 API Key，希望持久化到 shell 配置 |
| API Key 凭证文件 | 通过 /login 选择 API Key 提供商存储 | 有 API Key，希望 Pi Agent 统一管理 |

### 方式一：订阅登录（推荐）

如果你已经订阅了 Claude Pro/Max、ChatGPT Plus/Pro 或 GitHub Copilot，这是最便捷的方式。

启动 Pi Agent 后，输入以下命令：

```
/login
```

然后在出现的菜单中选择你的订阅提供商：

| 提供商 | 要求 | 说明 |
| --- | --- | --- |
| Claude Pro/Max | Anthropic 订阅账号 | 使用额外用量计费，不占用计划额度 |
| ChatGPT Plus/Pro (Codex) | OpenAI Plus 或 Pro 订阅 | OpenAI 官方认可的 Codex for OSS |
| GitHub Copilot | GitHub Copilot 订阅 | 支持 github.com 和企业服务器 |
| xAI (Grok) | X Premium 订阅 | 使用 Grok 模型 |
| OpenRouter | OpenRouter 账户 | OAuth 创建 API Key，从余额扣费 |

完成登录后，凭证会存储在~/.pi/agent/auth.json中，之后启动 Pi Agent 会自动使用。

如需退出登录，使用：

```
/logout
```

### 方式二：API Key 环境变量

如果你有 API Key，可以在启动 Pi Agent 前设置环境变量：

```
# 设置 Anthropic API Key

export ANTHROPIC_API_KEY=sk-ant-api03-your-key-here



# 启动 Pi Agent

pi
```

Pi Agent 支持以下主要提供商的 API Key 环境变量：

| 提供商 | 环境变量 | auth.json 键名 |
| --- | --- | --- |
| Anthropic | ANTHROPIC_API_KEY | anthropic |
| OpenAI | OPENAI_API_KEY | openai |
| Google Gemini | GEMINI_API_KEY | google |
| DeepSeek | DEEPSEEK_API_KEY | deepseek |
| Groq | GROQ_API_KEY | groq |
| Mistral | MISTRAL_API_KEY | mistral |
| xAI | XAI_API_KEY | xai |
| OpenRouter | OPENROUTER_API_KEY | openrouter |

#### 配置 DeepSeek 供应商

Pi 通过 models.json 支持自定义供应商，配置文件地址：

- Linux / macOS：~/.pi/agent/models.json
- Windows：%USERPROFILE%\.pi\agent\models.json

先在 DeepSeek 开放平台获取  API Key：[https://platform.deepseek.com/api_keys](https://platform.deepseek.com/api_keys)。

```json
{

  "providers": {

    "deepseek": {

      "baseUrl": "https://api.deepseek.com",

      "api": "openai-completions",

      "apiKey": "$DEEPSEEK_API_KEY",

      "models": [

        {

          "id": "deepseek-v4-pro",

          "name": "DeepSeek V4 Pro",

          "contextWindow": 1000000,

          "maxTokens": 384000,

          "input": ["text"],

          "reasoning": true,

          "cost": {

            "input": 1.74,

            "output": 3.48,

            "cacheRead": 0.145,

            "cacheWrite": 0

          },

          "compat": {

            "requiresReasoningContentOnAssistantMessages": true,

            "thinkingFormat": "deepseek",

            "reasoningEffortMap": {

              "minimal": "high",

              "low": "high",

              "medium": "high",

              "high": "high",

              "xhigh": "max"

            }

          }

        },

        {

          "id": "deepseek-v4-flash",

          "name": "DeepSeek V4 Flash",

          "contextWindow": 1000000,

          "maxTokens": 384000,

          "input": ["text"],

          "reasoning": true,

          "cost": {

            "input": 0.14,

            "output": 0.28,

            "cacheRead": 0.028,

            "cacheWrite": 0

          },

          "compat": {

            "requiresReasoningContentOnAssistantMessages": true,

            "thinkingFormat": "deepseek",

            "reasoningEffortMap": {

              "minimal": "high",

              "low": "high",

              "medium": "high",

              "high": "high",

              "xhigh": "max"

            }

          }

        }

      ]

    }

  }

}
```

设置环境变量：

Linux / Mac 用户：

```bash
export DEEPSEEK_API_KEY="<你的 DeepSeek API Key>"
```

Windows 用户：

```
$env:DEEPSEEK_API_KEY="<你的 DeepSeek API Key>"
```

进入项目目录并执行 pi 命令：

```
cd /path/to/my-project

pi
```

### 方式三：API Key 凭证文件

你也可以通过 /login 命令，选择 API Key 提供商来存储凭证。

存储位置为~/.pi/agent/auth.json，格式如下：

```json
{

  "anthropic": { "type": "api_key", "key": "sk-ant-api03-your-key" },

  "openai": { "type": "api_key", "key": "sk-your-openai-key" },

  "deepseek": { "type": "api_key", "key": "sk-your-deepseek-key" }

}
```

凭证文件会自动设置为0600权限（仅用户可读写），安全性有基本保障。

### 凭证解析顺序

当 Pi Agent 需要获取 API Key 时，按以下优先级查找：

- CLI 参数 --api-key（最高优先级）
- auth.json 文件中的凭证
- 环境变量
- models.json 中自定义提供商的 Key

也就是说，如果你同时设置了环境变量和 auth.json，auth.json 中的值会优先生效。

### auth.json 高级功能

auth.json 不仅支持存储明文 Key，还支持以下高级用法：

#### 从命令行获取 Key

使用!前缀执行命令来获取 Key，适合从密码管理器读取：

```json
{

  "anthropic": {

    "type": "api_key",

    "key": "!security find-generic-password -ws 'anthropic-api-key'"

  },

  "openai": {

    "type": "api_key",

    "key": "!op read 'op://vault/item/credential'"

  }

}
```

上例展示了从 macOS Keychain 和 1Password CLI 获取 Key 的方式。

#### 环境变量插值

使用$前缀引用环境变量：

```json
{

  "anthropic": {

    "type": "api_key",

    "key": "$MY_ANTHROPIC_KEY"

  }

}
```

### 切换模型

配置好认证后，你可以随时切换使用的 AI 模型：

交互模式中使用/model命令或按Ctrl+L打开模型选择器。

使用Ctrl+P/Shift+Ctrl+P在已配置的模型间循环切换。

命令行方式指定模型：

```
# 指定提供商和模型

$ pi --provider anthropic --model claude-sonnet-4-20250514



# 使用 provider/model 格式

$ pi --model openai/gpt-4o "帮我重构这段代码"



# 指定推理等级（thinking level）

$ pi --model sonnet:high "解决这个复杂问题"
```

| 推理等级 | 说明 | 适用场景 |
| --- | --- | --- |
| off | 不显示推理过程 | 简单问答、代码格式化 |
| minimal | 最少推理 | 基础编码任务 |
| low | 低度推理 | 一般编程问题 |
| medium | 中度推理（默认推荐） | 日常开发任务 |
| high | 高度推理 | 复杂架构设计、调试 |
| xhigh | 超高度推理 | 困难算法问题 |
| max | 最大推理 | 极复杂逻辑分析 |

编辑器的边框颜色会随推理等级变化，让你直观地看到当前推理深度。

---

---

## 六、国内首选：接入 DeepSeek 全流程

DeepSeek 提供 OpenAI 兼容接口，可以复用 Pi 现成的 OpenAI 适配层，无需为 DeepSeek 单独开发适配器。

接入的核心工作只有两件：在 models.json 中声明供应商与模型参数，通过环境变量提供 API Key。

整体架构如下图所示：

### 安装 Pi

Pi 依赖 Node.js 运行环境，安装前请先确认 Node.js 已就绪。

#### 安装 Node.js

从 Node.js 官网下载对应系统的安装包，使用默认选项安装即可。

#### 安装 Pi CLI

在终端通过 npm 全局安装：

```bash
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
```

Linux 和 macOS 用户也可以使用官方安装脚本一键安装：

```bash
curl -fsSL https://pi.dev/install.sh | sh
```

#### 验证安装

执行以下命令，能正常打印出版本号即表示安装成功：

```bash
pi --version
```

输出类似：

```
0.83.0
```

### 配置 DeepSeek 供应商

Pi 通过 models.json 定义自定义模型供应商，本节把 DeepSeek 以 OpenAI 兼容接口的形式接入。

#### 配置文件路径

不同操作系统的配置路径不同，请按系统对号入座：

| 操作系统 | 配置文件路径 |
| --- | --- |
| Linux / macOS | ~/.pi/agent/models.json |
| Windows | %USERPROFILE%\.pi\agent\models.json |

#### 编写 models.json

把以下内容写入配置文件：

```json
{

  "providers": {

    "deepseek": {

      "baseUrl": "https://api.deepseek.com",

      "api": "openai-completions",

      "apiKey": "$DEEPSEEK_API_KEY",

      "models": [

        {

          "id": "deepseek-v4-pro",

          "name": "DeepSeek V4 Pro",

          "contextWindow": 1000000,

          "maxTokens": 384000,

          "input": ["text"],

          "reasoning": true,

          "cost": {

            "input": 1.74,

            "output": 3.48,

            "cacheRead": 0.145,

            "cacheWrite": 0

          },

          "compat": {

            "requiresReasoningContentOnAssistantMessages": true,

            "thinkingFormat": "deepseek",

            "reasoningEffortMap": {

              "minimal": "high",

              "low": "high",

              "medium": "high",

              "high": "high",

              "xhigh": "max"

            }

          }

        },

        {

          "id": "deepseek-v4-flash",

          "name": "DeepSeek V4 Flash",

          "contextWindow": 1000000,

          "maxTokens": 384000,

          "input": ["text"],

          "reasoning": true,

          "cost": {

            "input": 0.14,

            "output": 0.28,

            "cacheRead": 0.028,

            "cacheWrite": 0

          },

          "compat": {

            "requiresReasoningContentOnAssistantMessages": true,

            "thinkingFormat": "deepseek",

            "reasoningEffortMap": {

              "minimal": "high",

              "low": "high",

              "medium": "high",

              "high": "high",

              "xhigh": "max"

            }

          }

        }

      ]

    }

  }

}
```

#### 配置项解析

下面对 models.json 中用到的主要字段逐一说明：

| 字段 | 类型 | 是否必填 | 说明 | 默认值 |
| --- | --- | --- | --- | --- |
| baseUrl | string | 必填 | DeepSeek 的 OpenAI 兼容接口地址 | https://api.deepseek.com |
| api | string | 必填 | 对接协议，声明使用 OpenAI Completions 兼容协议 | openai-completions |
| apiKey | string | 必填 | 从同名环境变量读取密钥，无需把 Key 明文写进配置文件 | $DEEPSEEK_API_KEY |
| contextWindow | number | 必填 | 上下文窗口大小（tokens） | 1000000 |
| maxTokens | number | 必填 | 单次最大输出长度（tokens） | 384000 |
| reasoning | boolean | 可选 | 声明模型支持思维链（推理）能力 | true |
| cost | object | 可选 | 记录输入/输出/缓存命中等单价，用于 Pi 界面估算花费 | — |
| requiresReasoning ContentOnAssistantMessages | boolean | 推荐 | 多轮对话中 assistant 消息需要保留 reasoning_content 字段，否则可能出现兼容性问题 | true |
| thinkingFormat | string | 推荐 | 按 DeepSeek 特有的思维内容格式解析、展示推理过程 | deepseek |
| reasoningEffortMap | object | 推荐 | 把 Pi 的推理强度档位映射到 DeepSeek 实际支持的档位 | — |

#### 模型选择

配置声明了两个 DeepSeek 模型，主要区别如下：

| 模型 | 上下文窗口 | 最大输出 | 输入单价 | 输出单价 | 缓存命中单价 | 适用场景 |
| --- | --- | --- | --- | --- | --- | --- |
| deepseek-v4-pro | 1,000,000 | 384,000 | 1.74 | 3.48 | 0.145 | 推理能力更强，适合复杂任务 |
| deepseek-v4-flash | 1,000,000 | 384,000 | 0.14 | 0.28 | 0.028 | 响应更快、成本更低 |

单价单位为每百万 tokens（美元）。

#### 获取并设置 API Key

先在 DeepSeek 开放平台申请 API Key：[https://platform.deepseek.com/api_keys](https://platform.deepseek.com/api_keys)。

Linux / macOS 在终端导出环境变量：

```bash
export DEEPSEEK_API_KEY="你的 DeepSeek API Key"
```

Windows（PowerShell）设置方式：

```
$env:DEEPSEEK_API_KEY="你的 DeepSeek API Key"
```

建议把导出命令写入 shell 配置（如 ~/.bashrc、~/.zshrc 或 PowerShell Profile），避免每次开新终端都重新设置。

### 运行与测试

配置完成后，就可以启动 Pi 并切换到 DeepSeek 模型。

#### 启动 Pi

进入项目目录:

```
cd ~/runoob-test/
```

直接执行 pi 命令：

```
pi
```

#### 切换到 DeepSeek 模型

进入交互界面后，按以下步骤切换：

- 输入/model打开模型选择器。
- 选择 deepseek 供应商，选择 DeepSeek-V4-Pro 或 DeepSeek-V4-Flash。
- 接下来询问当前模型

切换完成后，就可以直接在这个极简终端框架里开始编码了。

#### 建议的测试步骤

按下面的清单逐项验证接入是否完整可用：

| 测试项 | 操作方法 | 预期结果 |
| --- | --- | --- |
| 鉴权与连通性 | 发送一句话，例如「你好，请介绍一下 runoob 学习平台」 | 正常拿到回复，无 401 / 403 类鉴权报错，说明 apiKey、baseUrl 配置正确 |
| 推理能力 | 问一个需要多步推理的问题，比如让它先分析再给方案 | 输出可见的思维过程，说明 thinkingFormat 与 reasoning 生效 |
| 多轮工具调用 | 让 Pi 连续调用工具完成读文件、跑命令、改代码、验证结果 | 多轮对话稳定，不因 reasoning_content 丢失而报错 |
| 推理强度切换 | 在 /model 中从 medium 切到 xhigh | 行为符合 reasoningEffortMap 映射，xhigh 对应 DeepSeek 的 max |
| 成本核算 | 跑几轮真实任务后查看花费统计 | 界面统计与 cost 字段设置的单价相符 |

其中「多轮工具调用」是验证 requiresReasoningContentOnAssistantMessages 配置是否正确的关键场景。

### 常见问题排查

接入过程中遇到问题，可对照下面的清单快速定位。

#### 模型选择器里看不到 DeepSeek

检查 models.json 路径是否正确，Windows 与 Linux / macOS 的路径不同。

同时确认 JSON 格式没有语法错误，比如多余的逗号、未闭合的引号。

#### 鉴权失败

确认 DEEPSEEK_API_KEY 环境变量已经正确设置。

注意：执行 pi 命令的终端会话，必须与设置环境变量的会话是同一个。

#### 多轮工具调用报错

优先检查 requiresReasoningContentOnAssistantMessages 与 thinkingFormat 是否已按上文配置齐全。

#### 需要更多自定义能力

可以参考[Pi 官方 models 文档](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent/docs/models.md)，了解更完整的配置项。

---

---

## 七、首次对话与代码协同验证

完成了安装和认证配置后，本章带你进行第一次完整的对话体验。

你会熟悉界面布局和基本操作。

### 启动 Pi Agent

进入你的项目目录，启动 Pi Agent：

```
$ cd ~/projects/runoob-demo

$ pi
```

你会看到终端中出现 Pi Agent 的交互界面。

界面分为四个主要区域：

| 区域 | 位置 | 显示内容 |
| --- | --- | --- |
| 启动头部 | 顶部 | 快捷键提示、已加载的上下文文件、提示词模板、Skills、扩展 |
| 消息区域 | 中部 | 用户消息、AI 回复、工具调用详情、通知和错误 |
| 编辑区 | 底部输入行 | 你的输入位置，边框颜色表示当前推理等级 |
| 底部状态栏 | 最下方 | 工作目录、会话名、token/缓存用量、上下文用量、费用、当前模型名（总额包含 AI 回复、工具上报用量和摘要生成消耗） |

### 第一个任务

进入界面后，输入你的第一个需求并回车：

```
帮我总结一下这个项目的结构和主要功能
```

Pi Agent 会使用内置工具读取你的项目文件，分析代码结构，然后返回总结。

你可以在消息区域看到 AI 正在执行的操作——包括它调用了哪些工具、读取了哪些文件。

一次完整对话的输出类似：

```typescript
> read README.md（1.2k 字符）

> read src/main.ts（3.4k 字符）



这是一个基于 TypeScript 的终端编程助手，主要功能分为会话管理、工具调度和扩展加载三部分。

Tokens: 2.4k 输入 / 410 输出  |  费用 $0.0152
```

Pi Agent 默认提供 read、write、edit、bash 四种内置工具，完整说明见《核心概念速览》一章。

### 引用文件

你可以在对话中引用特定文件，有两种方式：

#### 方式一：@ 语法（编辑器内搜索）

在编辑区输入@，会自动弹出项目文件的模糊搜索：

```
@src/app.ts 解释这个文件的功能
```

#### 方式二：命令行参数

启动时直接传入文件引用：

```
$ pi @README.md "总结一下这个文档"

$ pi @src/app.ts @src/app.test.ts "对比这两个文件"
```

也可以引用图片文件：

```
$ pi -p @screenshot.png "这张截图里显示了什么"
```

### 粘贴图片

Pi Agent 支持在对话中发送图片，不同平台操作方式略有差异。

| 平台 | 操作 | 说明 |
| --- | --- | --- |
| macOS / Linux | Ctrl+V | 粘贴剪贴板中的图片 |
| Windows | Alt+V | 粘贴剪贴板中的图片 |
| 支持的终端 | 拖拽图片到终端窗口 | 以文件方式传入对话 |

### 在对话中执行命令

你可以直接从编辑区执行 shell 命令，无需退出 Pi Agent：

```
!npm run lint

!git diff
```

以!开头的命令会被执行，且输出结果会自动发送给 AI 查看。

执行!npm run lint的结果类似：

```
> pi-agent@1.0.0 lint

> eslint .

0 errors, 0 warnings
```

以!!开头的命令也会执行，但不会将输出发送给 AI：

```
!!echo "这只在本地显示"

这只在本地显示
```

### 多行输入与外部编辑器

大段文本可以用多行输入或外部编辑器书写，下面是相关快捷键。

| 操作 | 快捷键 |
| --- | --- |
| 插入换行 | Shift+Enter（Windows Terminal 用 Ctrl+Enter） |
| 打开外部编辑器 | Ctrl+G |

当你需要输入大段文本时，按Ctrl+G会打开系统默认编辑器（如 nano、vim 或 VS Code），编辑完成保存后内容会自动填入 Pi Agent 的编辑区。

### 消息队列

Pi Agent 允许在 AI 正在工作时发送消息，而不需要等待它完成：

| 快捷键 | 行为 | 说明 |
| --- | --- | --- |
| Enter | 发送 steering 消息 | 在当前工具执行完毕后立即发送给 AI |
| Alt+Enter | 发送 follow-up 消息 | 等 AI 完成所有工作后再发送 |
| Escape | 取消已排队消息 | 将排队中的消息恢复到编辑区 |
| Alt+Up | 取回排队消息 | 将已排队的消息取回编辑区修改 |

### 非交互模式

除了交互对话，你也可以用以下方式快速使用 Pi Agent：

```
# 一次性问答，输出后退出
pi -p "总结一下这个代码库"

# 管道输入：将文件内容传给 AI
cat README.md | pi -p "总结这段文字"

# 带图片的一次性问答
pi -p @screenshot.png "这张图里有什么"

# 命名会话（方便之后继续）
pi --name "代码审查" -p "审查 src/ 目录下的代码"

# 只读模式（不允许修改文件）
pi --tools read,grep,find,ls -p "审查代码不修改"
```

Print 模式（-p）非常适合集成到脚本和 CI 流程中。

### 创建项目指令文件

为了让 AI 更好地理解你的项目，建议创建 AGENTS.md 文件。

把下面的内容保存为 Markdown 文件，文件路径为项目根目录/AGENTS.md：

```
# 项目指令


- 代码修改后运行 `npm run check`

- 不要直接在本地执行生产环境迁移

- 回复保持简洁，不要过多解释

- 使用 TypeScript 严格模式编写代码

- 遵循项目现有的代码风格
```

Pi Agent 会在启动时自动加载这个文件。

同时也会加载来自~/.pi/agent/AGENTS.md的全局指令和父目录中的指令文件。

更新 AGENTS.md 后，使用/reload命令即可热重载，无需重启。

### 界面一览

以下是 Pi Agent 交互模式的主要快捷键速查：

| 操作 | 快捷键 | 说明 |
| --- | --- | --- |
| 提交输入 | Enter | 发送当前编辑区内容，AI 工作时进入消息队列（见消息队列） |
| 模型选择 | Ctrl+L | 打开模型选择器 |
| 切换模型 | Ctrl+P / Shift+Ctrl+P | 向前/向后循环切换模型 |
| 推理等级 | Shift+Tab | 循环切换推理等级 |
| 展开/折叠工具输出 | Ctrl+O | 切换工具调用结果的显示 |
| 展开/折叠推理过程 | Ctrl+T | 切换 AI 推理过程的显示 |
| 中断操作 | Escape | 取消当前 AI 操作（见消息队列） |
| 清空编辑区 | Ctrl+C | 清空当前编辑区内容 |
| 复制 AI 最后一条回复 | Ctrl+X | 复制回复内容到剪贴板 |
| 路径自动补全 | Tab | 补全文件路径 |
| 退出程序 | Ctrl+D | 编辑区为空时退出程序 |
| 退出程序（直接） | /quit | 立即退出 |

---

---

