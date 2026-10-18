# 实战案例：配置并日常使用 Pi 终端编程 Agent

> **原文标题**：[Setting Up and Using the Pi Coding Agent](https://deepakness.com/blog/pi-agent-setup/)  
> **作者**：DeepakNess  
> **发布日期**：2026 年 5 月 29 日（更新于 2026 年 8 月 14 日）  
> **阅读时间**：约 13 分钟（2,478 字）  
> **标签**：`pi-agent` · `ai` · `coding` · `deepseek`  
> **导读说明**：本文来自海外一线全栈开发者 DeepakNess。作者曾重度使用 Cursor、OpenAI Codex、Claude Code 与 Grok Build，但最终将 **Pi 搭配 DeepSeek** 作为其每天主力驱动工具（Daily Driver）。本文详细记录了他的安装步骤、大模型分工配置、自定义扩展、提示词工程及一线实操踩坑心得。

---

## 引言

我使用 AI 辅助编程工具已经有相当长一段时间了。之前我一直使用 Cursor 和 OpenAI Codex 作为主项目的开发主力，但目前我的日常技术栈发生了一些变化：**Pi 搭配 DeepSeek 成了我的主力工具**，遇到某些复杂高难度任务时使用 Grok Build，而前端设计与 UI 交互工作主要交给 Claude Code。

几个月前（2026 年 5 月），我偶然发现了 **Pi** —— 一款开源的终端编程 Agent（Terminal Coding Agent）。它的内核极其精简小巧，并没有像其他工具那样把所有功能一股脑默认打包塞给用户，而是允许你通过扩展（Extensions）和软件包（Packages）按需添加所需功能。我非常赞同这一设计哲学，于是决定上手配置一番，看看它能否融入我的工作流。

虽然我目前仍在不断寻找最完美的平衡点，但 **Pi 已经稳固地成为了我日常不可或缺的核心工具**。在这篇文章中，我将分享我是如何安装它、我的具体配置方案是什么样的，以及我迄今为止最真实的实战体验。

---

## 什么是 Pi？

Pi 是由 **Mario Zechner** 创建的开源终端编程 Agent。它直接在终端命令行中运行，默认仅为 AI 模型提供 4 个最纯粹的基础工具来操作你的代码库：
- `read`（读取文件）
- `write`（写入/创建文件）
- `edit`（精确替换代码行）
- `bash`（执行命令行命令）

**Pi 没有强行内置 Plan 模式，没有强制的 Sub-agents 机制，没有默认捆绑的 MCP，更没有任何恼人弹窗来反复确认权限。** 相反，你可以通过扩展、技能（Skills）和包管理系统按需组装这些能力。这种设计让 Pi 的核心保持了极度的轻巧与灵活性，完全由你自己量身构建想要的工作流。

Pi 支持与市面上绝大多数 AI 供应商无缝协作 —— 包括 Anthropic、OpenAI、DeepSeek、Google Gemini、Groq、xAI、OpenRouter、Kimi 等等，几乎涵盖了你所知道的每一个主流 Provider。你可以直接使用 API 密钥，也可以通过已有订阅直接授权登录。

---

## 我如何将 Pi 与其他工具配合使用

目前在实际工作中，我针对不同类型的工作使用不同的工具：

- **日常主力（日常大部分工作）**：使用 **Pi 搭配 DeepSeek 模型**
- **高复杂度任务**：使用 **Grok Build**
- **前端页面与 UI 还原**：主要使用 **Claude Code**

我也曾长期在主项目中使用 Cursor 和 OpenAI Codex。它们依然是我 AI 编程旅程中的一部分，也是非常成熟的工具，只不过目前已经不是我最常开启的软件了。

**Pi 之所以成为我日常主力驱动工具，核心原因在于它速度极快、极度轻量，而且我可以使用更便宜的大模型，完全不必担心烧光昂贵的闭源订阅配额。**

> **💡 一个真实战绩案例**：  
> 我最近使用 Pi 搭配 **DeepSeek v4 Flash** 模型，从一个目标网站上抓取了整整 **28.5 万个 URL**。整个任务在后台连续跑了大约 1.5 个小时，通过 DeepSeek 官方 API 结账，**总共仅仅花掉了 1 美元**！在整个长任务运行过程中，我使用 `pi-codex-goal` 扩展来追踪状态，中途没有任何崩溃或报错。

---

## 安装 Pi

安装极其简单，仅需终端一行命令：

```bash
curl -fsSL https://pi.dev/install.sh | sh
```

安装完成后，在终端直接输入 `pi` 即可启动。不过在正式使用前，你需要先配置好模型供应商（Provider）。

---

## 将 OpenCode Go 配置为 Provider

Pi 内置了极其实用的 `/login` 命令，让任何 Provider 的授权接入都变得非常轻而易举。因为我自己订阅了 OpenCode Go 服务，所以我直接用订阅账号授权登录，省去了手动管理 API 密钥的麻烦。步骤如下：

1. 打开终端输入 `pi` 启动；
2. 在输入框输入 `/login`，并在弹出的列表中选择 **OpenCode Go**；
3. 使用已有订阅完成网页授权登录。

大功告成！登录之后，输入 `/model` 即可挑选想用的模型 —— 我默认选择了 **`deepseek-v4-pro`**，并将思考级别（Thinking）设置为 **`max`**。

在早些时候，我是按用量付费（Pay-as-you-go）通过 DeepSeek 官方 API 调用的，至今我还保留着那个官方 API Key 作为灾备兜底。现在 OpenCode Go 订阅已经能覆盖我绝大部分日常调用。

我之所以默认开到 `max thinking`，是因为我希望模型在实际动手修改代码之前，先进行充分且深度的逻辑推理。而在处理轻量级任务（比如前面提到的 URL 批量抓取）时，我会切到速度更快、价格也更低廉的 `deepseek-v4-flash` 模型。

* 快捷键速查：
  * 按 `Ctrl + L`：打开模型选择器；
  * 按 `Ctrl + P`：在常用关注模型（Scoped Models）列表中快速轮替循环；
  * 按 `Shift + Tab`：直接切换思考深度（Low / Medium / High / Max）。

对于复杂的疑难杂症，我还会使用 Grok 4.6，具体见下一节的模型阵容。

---

## 我的大模型阵容清单

我在 Pi 中启用了多款模型，并在实际任务中根据需求随时切换：

| 模型名称 (Model) | 我的主要用途 | 运行来源 |
|:---|:---|:---|
| **DeepSeek v4 Pro** | **绝大部分日常开发任务的默认首选** | 通过 OpenCode Go 订阅运行 |
| **DeepSeek v4 Flash** | **轻量级、高重复度任务**（如大规模爬取、批量重命名/重构），极速且极其便宜 | 通过 OpenCode Go 或 DeepSeek API |
| **Grok 4.6** | **高复杂度、架构级攻坚任务** | 通过 SuperGrok 套餐运行 |
| **GPT-5.6 Luna** | **作为视觉辅助模型**（配合 `pi-vision-handoff` 扩展） | 通过 Codex 免费配额或 OpenCode Go |

模型切换是瞬间完成的 —— `Ctrl + L` 唤起全量选择器，`Ctrl + P` 在核心池中秒级循环。

---

## 交互界面与自定义极简底栏 (Minimal Footer)

打开 Pi，界面呈现出极简纯粹的 Terminal 风格：底部是输入编辑器，中间是对话交互区，底栏（Footer）则展示当前工作路径、Git 分支、当前模型、思考级别以及上下文窗口（Context Window）的消耗情况。

刚上手不久，我就针对**底栏**做了一次个性化改造。Pi 官方默认底栏展示的信息对我来说略显繁复，有些数据我平时并不关注。因此，**我直接在 Pi 会话中让 Pi 自己帮我写了一个极简底栏扩展**！

我把我的诉求告诉了它：只要当前文件夹名、带脏标记（Dirty Marker）的 Git 分支、模型名称、思考级别、一个可选的目标展示位、以及一个紧凑的上下文进度条。Pi 很快为我生成了一个完整的 TypeScript 扩展文件。

该扩展保存在本地目录：
```
~/.pi/agent/extensions/minimal-footer.ts
```
Pi 每次启动时都会自动加载该目录下的插件。我也把这份源码放到了 GitHub Gist 上 —— 只要把它丢进扩展目录并重启 Pi 即可生效。虽然这是一个很小的改动，但它让整个工具的使用体验瞬间变得非常亲切，在这个过程中我也深入理解了 Pi Extensions 的运行机制。

最近我还加上了另一个非常有趣的小插件 —— **Whimsical working messages（趣味思考提示语）**，该扩展基于著名开源作者 Armin Ronacher 的创意改造而成。我为其定制了更多炫酷的色彩高亮、装饰符号，并且在 Pi 思考或执行耗时任务时，状态栏每隔 2 秒会自动轮换一句趣味俏皮的状态提示。该文件保存在 `~/.pi/agent/extensions/whimsical.ts`。

---

## 我安装的核心扩展包 (Packages)

Pi 的 Packages 可以是打包了扩展、技能（Skills）、提示词和主题的 npm 或 git 仓库。通过执行 `pi install <package>` 即可完成安装。本着“少即是多”的原则，我日常只保留了两个最重要的扩展包：

### 1. `pi-web-access`（联网与文档检索）

这个扩展赋予了 Pi 检索互联网、抓取网页正文、提取 YouTube 视频字幕以及深入探索 GitHub 开源仓库的能力。
安装命令：
```bash
pi install npm:pi-web-access
```

该工具开箱即用，默认集成 Exa 搜索引擎（甚至无需自己配置 API Key）。当然如果你追求更强的控制力，也可以配置 Perplexity、Exa 或 Gemini 的 API Key。我通过创建 `~/.pi/web-search.json` 配置文件将其锁定为默认使用 Exa：

```json
{
  "provider": "exa",
  "allowBrowserCookies": false,
  "summaryModel": "opencode-go/deepseek-v4-flash",
  "workflow": "none",
  "curatorTimeoutSeconds": 20
}
```

有了这个扩展，Pi 可以直接搜索最新网络技术资讯、阅读官方在线文档、理解 YouTube 教程内容、克隆并阅读 GitHub 仓库代码 —— **所有操作全都在终端内部闭环完成，完全无需切换浏览器**。

### 2. `pi-vision-handoff`（跨模型视觉接力）

DeepSeek 本身是一个纯文本/推理模型，无法直接识别图片。为了解决这一痛点，我安装了 `pi-vision-handoff` 扩展包：
```bash
pi install npm:pi-vision-handoff
```

它的工作逻辑非常精妙：**当你在终端粘贴或传入图片时，它先调用专门的视觉模型把图片内容转录为详细的文字描述，然后再将这份文字描述转交给非视觉模型（如 DeepSeek）继续执行编程任务。**

我通过 Codex 免费计划将 GPT-5.6 Luna 设置为视觉转接模型（免费额度非常充裕），也可以通过 OpenCode Go 运行。每当我把一张屏幕截图或设计图粘贴进 Pi，Luna 会秒级完成视觉解析，随后 DeepSeek 接管并依据该说明精准写出前端代码。

这种转接机制是**完全与 Provider 解耦的**。你可以通过 `/vision-handoff` 选择任意具备视觉能力的模型，然后你所喜爱的所有纯文本模型瞬间就都获得了“看懂图片”的能力。扩展还会对相同图片的分析结果做本地缓存，并批量合并请求，避免重复截图消耗多余 Token。

> *注：我还尝试过用于长线目标追踪的 `pi-codex-goal`、终端内嵌浏览器的 `pi-agent-browser-native` 以及接入 Cursor 订阅的 `pi-cursor-sdk`，但为了保持极简，目前日常已精简卸载。*

---

## 项目指令规范：AGENTS.md 与 APPEND_SYSTEM.md

Pi 提供了两层让模型遵循项目规范与行为习惯的机制：针对项目上下文的 `AGENTS.md`，以及针对全局通用行为规范的 `APPEND_SYSTEM.md`。

### 1. `AGENTS.md`（项目技术栈与上下文）

Pi 在启动时会自动寻找 `AGENTS.md` 文件并将其注入到系统提示词中。它的检索是分层级冒泡的：
1. 全局配置：`~/.pi/agent/AGENTS.md`
2. 逐级向上查找父目录中的 `AGENTS.md`
3. 当前工作目录下的 `AGENTS.md`

所有层级的规则会拼接生效。我的全局 `~/.pi/agent/AGENTS.md` 写得非常克制：

```markdown
# Global Pi Instructions

- Projects commonly use Laravel (PHP/Inertia/React), Next.js
  (TypeScript/Tailwind), or Astro. Check the project-root AGENTS.md for
  stack-specific rules – if none exists, ask.
```

这里面最关键的是 **“if none exists, ask”（若未检测到规则，请先主动询问）**。这有效防止了当我在一个普通的静态 HTML/CSS/JS 目录工作时，Agent 自作聪明强行引入庞大的现代前端全家桶。

对于具体的项目，通常由框架脚手架（例如 Laravel Boost）自动在项目根目录生成专有 `AGENTS.md`，精确锁定依赖库版本和编码规范，几乎不需要手工编写。

### 2. `APPEND_SYSTEM.md`（全局行为与输出准则）

`AGENTS.md` 是与具体项目绑定的，但有些规则无论在什么技术栈下都必须严格遵守。这就是 `APPEND_SYSTEM.md` 的用武之地。它存放在：
```
~/.pi/agent/APPEND_SYSTEM.md
```
它会被直接追加到系统底层提示词末尾，这意味着它拥有比普通 `AGENTS.md` **更高的优先级和执行权威**。

以下是我的完整配置规则：

```markdown
- If the default provider doesn't have vision capabilities, use
  pi-vision-handoff for images.
- Read relevant local files first when the answer is available in the
  codebase. If not, research online via pi-web-access. Before making a
  big change based on online research findings, confirm with me first.
- Explain risky file edits and destructive commands before executing.
- Write simply. Avoid AI-slop language – no flowery adjectives,
  unnecessary adverbs, or overly formal phrasing.
- Use en dashes (–) not em dashes (—).
```

核心细则解读：
- **视觉动态适配**：不硬编码具体厂商，只要当前默认模型无 Vision 能力就自动调起 handoff。
- **本地优先策略**：本地已有代码能回答的，严禁盲目联网搜索；确需联网时使用 `pi-web-access`，且基于搜索结果做重大重构前必须与我确认。
- **高危操作防线**：在执行破坏性命令或修改关键配置前，必须先做出合理解释。
- **拒绝 AI 假大空黑话（No AI-slop）**：禁止华丽冗余的形容词、毫无必要的副词或过度官僚化的客套话，行文必须干脆直接。

---

## 常用快捷键与命令速查

Pi 拥有完善的快捷键体系，以下是我每天使用频率最高的一组：

### 核心快捷键
| 快捷键 | 作用说明 |
|:---|:---|
| **`Ctrl + L`** | 打开大模型选择器（快速搜寻并切换模型） |
| **`Ctrl + P`** | 在关注的常用模型列表（Scoped Models）中快速循环轮替 |
| **`Shift + Tab`** | 切换模型的思考等级（None / Low / Medium / High / Max） |
| **`Ctrl + C` (连按两次)** | 退出 Pi |
| **`Escape`** | 取消或强行中止当前正在执行的动作 |
| **`Enter`** | **发送转向指令（Steering Message）**：在模型工作时直接打断插队 |
| **`Alt + Enter`** | **发送排队后续指令（Follow-up Message）**：排队等当前工作做完再交付 |

> **🔥 实操技巧：区分 Enter 与 Alt+Enter**  
> 一开始可能需要习惯一下：如果你发现 Pi 在执行 bash 或编辑文件时方向走偏了，立刻打字敲 **`Enter`**，这会立即入队一条转向指令，在当前命令执行完的瞬间直接纠偏；如果你只是想给它留个话等它把当前活干完再做，那就按 **`Alt + Enter`**（macOS 上为 `Option + Enter`）。

### 高频斜杠命令
在输入框输入 `/` 即可触发：
- `/model`：切换模型（记不住快捷键时的备选）；
- `/settings`：调整思考等级、主题和其他运行参数；
- `/resume`：从历史会话列表中挑选并恢复以往会话；
- `/new`：开启全新的纯净会话；
- `/tree`：**以可视化树状图查看会话历史，并自由跳跃到任意历史分支**；
- `/compact`：手动压缩过长的会话历史，腾出上下文窗口；
- `/session`：查看当前会话的详细开销（输入/输出 Token 统计与实际花费账单）。

其中 **`/tree`** 是极其震撼的功能。它把整场对话像 Git commit log 一样变成了一棵交互式树状图。如果你尝试了方案 A 发现走不通，无需重新开新对话或大段复制提示词，直接在树状图里选到分叉前的节点一键回滚，就能基于原有状态尝试方案 B。

---

## 使用 Pi 的实操心得

1. **长会话与上下文管理**：
   长周期编程任务一定会消耗上下文空间。Pi 内置了自动压缩算法（Auto-compaction），当上下文快满时会自动在后台总结老旧交互。你也可以随时使用 `/compact` 手动触发。此外，我特别喜欢在终端中直接运行：
   ```bash
   pi --continue
   ```
   它会自动秒级打开你在当前仓库/目录下最后一次进行的对话，无缝接着干活。
2. **实时纠偏机制（Steering System）**：
   当 Pi 正在噼里啪啦连续跑 bash 命令或修改文件时，随时敲字按 `Enter`，转向消息会直接插到下一步。再也不需要干看着 AI 往错误的方向一路狂奔。
3. **海纳百川的 Provider 生态**：
   不管 OpenAI、Cursor、OpenRouter、xAI、Claude 还是本地 Ollama，只要有 API，在 Pi 里全都能跑。

---

## 我为什么如此偏爱 Pi？

在使用 Pi 数月之后，有几个特点深深打动了我：
* **极其轻巧与迅速**：纯粹的终端交互，零 Electron 开销，UI 没有一丁点卡顿与掉帧。
* **高自由度定制**：我让 Pi 给自己写出了最合心意的底栏，按需安装了极简的两个包，其余部分干干净净。
* **支持任意供应商**：大部分时间我通过 OpenCode Go 跑极具性价比的 DeepSeek，需要换模型时按一个快捷键就能切换。在这个过程中你还能真正看清 Agent 是如何调用 bash 和编辑代码的，而不是被封装在一个黑盒里。
* **会话树机制无与伦比**：分支化对话、随时检出回溯到任意节点的能力，一旦用惯就再也回不去传统线性聊天的工具了。
* **彻底开源（MIT 协议）**：没有任何商业公司能突然决定削减我什么功能，或者强行变更订阅收费策略。
* **上下文压缩省心稳定**：后台默默搞定上下文修剪，又快又好。

---

## 最终总结

目前我的生产力组合非常清晰：
- **核心主力（Daily Driver）**：Pi 搭配 DeepSeek 处理绝大部分编码需求；
- **疑难大件**：Grok Build（通过 SuperGrok）；
- **前端 UI 攻坚**：Claude Code。

但毫无疑问，**Pi 已经稳稳坐牢了我日常开发核心工具的头把交椅**。它速度飞快、费用极低（配合 DeepSeek 简直是杀手级组合），再加上几个精挑细选的扩展包，整体体验坚如磐石。

当前我的常驻配置清单：
- **模型默认**：DeepSeek v4 Pro + `max thinking`（通过 OpenCode Go）
- **轻量任务**：DeepSeek v4 Flash
- **攻坚任务**：Grok 4.6
- **核心扩展**：
  - `pi-web-access`（联网与文档抓取）
  - `pi-vision-handoff`（GPT-5.6 Luna 视觉接力）
- **配置文件**：
  - `~/.pi/agent/APPEND_SYSTEM.md`（行为规范与去 AI 黑话）
  - `~/.pi/agent/extensions/minimal-footer.ts`（自制极简底栏）
  - `~/.pi/agent/extensions/whimsical.ts`（动态趣味工作状态）

**我的核心建议是：越简单的配置，效果往往越好。**  
如果你熟悉终端命令行，并且喜欢这种“极简、纯粹、高度可编程”的 Agent 理念，强烈建议尝试一下 Pi —— 从最基础的配置起步，随着真实痛点的出现，再逐步为其添砖加瓦。
