# Pi Agent 配置进阶：AGENTS.md、模型切换与 Thinking Level 实战指南

> **原文来源**：火炬树 (TorchTree) 原创深度专栏  
> **原文链接**：[https://torchtree.com/post/pi-agent-configuration-guide/](https://torchtree.com/post/pi-agent-configuration-guide/)  
> **作者**：Cyber Herald  
> **核心导读**：详细讲解 Pi Agent 的 `AGENTS.md` / `settings.json` / `models.json` 多层配置文件体系、模型分层切换策略和 Thinking Level 思考深度调优方法，适合已安装 Pi 的进阶实战用户。本文不仅完整收录了原文的所有表格与论述，还对原文中省略的配置代码块进行了严格补全与工程级实测。

---

## 引言

在初识 Pi Agent 时，很多开发者通过基础教程完成了安装、首次鉴权和几个常见扩展包（如 `pi-web-access`）的使用。那些内容能帮助初学者快速跑起来，但 **Pi 的真正灵活性，其实全部深藏在它的配置文件里**。

Pi 的核心代码只有极精炼的 TypeScript 实现，默认只给大模型 4 个最纯粹的基础工具（`read`、`write`、`edit`、`bash`）。它的所有高级能力 —— 包括在什么场景用什么模型、保留多大的上下文窗口、以多深的思想链（Thinking Depth）推演代码、以及如何自动容灾重试，全部由外部配置文件精确控制。

**理解这些配置文件之间的层级关系和优先级覆盖逻辑，是把 Pi 从“能用”推向“极致好用”的核心分水岭。**

---

## 一、 Pi 的配置文件分几层？每层管什么？

Pi 的配置体系采用**严格的分层叠加设计**。理解每一层的职责范围和优先级顺序，就不会出现“明明改了配置却没生效”的困惑。

- **全局配置**：存放在 `~/.pi/agent/` 目录下，对所有项目全局生效；
- **项目配置**：存放在当前项目目录的 `.pi/settings.json` 中，仅覆盖当前项目；
- **合并规则**：项目配置中的嵌套对象（如 `compaction`、`retry`）会与全局配置进行深度字段合并（Deep Merge），而非全盘整体替换。

除了两层的 `settings.json`，Pi 还划分了四种高度专门化的配置文件，各司其职：

| 配置文件 | 存放位置 | 核心用途 | 加载时机 |
|:---|:---|:---|:---|
| **`AGENTS.md`** | 项目根目录 或 `~/.pi/agent/` | 项目业务上下文、编码规范与技术栈指令，注入 System Prompt 前部 | 启动时自动向上递归检索加载 |
| **`APPEND_SYSTEM.md`** | `~/.pi/agent/` | 全局行为准则与绝对纪律，追加到 System Prompt 最尾部（最高权威） | 启动时加载 |
| **`settings.json`** | 全局或项目 `.pi/` | 默认模型、主题、思考预算、压缩策略、重试等运行时控制参数 | 启动时加载 |
| **`models.json`** | `~/.pi/agent/` | 自定义大模型与 Provider（Ollama、vLLM、OpenRouter 等兼容端点） | 每次在终端打开 `/model` 时热重载 |
| **`auth.json`** | `~/.pi/agent/` | API Key 和 OAuth 凭据（文件权限受严格限制为 `0600`） | 发起模型请求时按需安全读取 |

以下逐层拆解每一份配置的最佳实战配置。

---

## 二、 AGENTS.md 怎么写才有效？

`AGENTS.md` 是 Pi 理解项目上下文的主要入口。Pi 在启动时，会按照以下顺序从多个位置查找并拼接内容注入系统提示词：
1. 先加载 `~/.pi/agent/AGENTS.md`（全局通用指令）；
2. 然后自当前工作目录向上逐级遍历所有父目录中的 `AGENTS.md`；
3. 最后加载当前项目根目录的 `AGENTS.md`。

换句话说：**全局的 `AGENTS.md` 定义你作为开发者通用的技术栈偏好，而项目级的 `AGENTS.md` 则定义该项目专有的架构约束与执行流程。**

### 1. 全局 `AGENTS.md` 写什么
全局 `~/.pi/agent/AGENTS.md` 适合记录你的常用技术栈偏好。知名开发者 DeepakNess 分享的全局规则是一个极佳的参考范例：

```markdown
# Global Pi Instructions

- Projects commonly use TypeScript/React, Python, or Go. Check the project-root AGENTS.md for stack-specific rules – if none exists, ask.
```

这段配置没有写得过于死板，而是给出了宽泛的技术栈提示，最核心的是 **“if none exists, ask”（若未检测到特定技术栈，必须先询问）**，有效防止了 Agent 在空项目或简单脚本目录中自作聪明强行初始化大型框架。

### 2. 项目 `AGENTS.md` 怎么组织
项目级的 `AGENTS.md` 需要更精确、更工程化。以下是一个针对现代前端/TypeScript 项目的标准生产级模板：

```markdown
# Project Guidelines

## Stack
- TypeScript (Strict Mode)
- Vite + React 19 + Tailwind CSS
- Vitest for testing

## Engineering Rules
- Always run `npm test` before considering a feature task complete.
- Do not edit files inside `dist/` or `node_modules/`.
- Keep components small, functional, and modular.
- Maintain comprehensive unit tests alongside source files (`*.test.ts`).
```

如果你日常管理多个仓库，建议为每种项目类型（如 React 库、Python FastAPI 服务、Go CLI 工具）各自维护一份模板。新建项目时直接复制一份，修改对应的版本号和脚本命令即可。

### 3. 修改后记得重载
每次在外部编辑器修改了 `AGENTS.md` 之后，在终端中需要执行：
```
/reload
```
或者重启 Pi 才能重新把新规则编译进系统提示词。

---

## 三、 APPEND_SYSTEM.md 控制什么行为？

`~/.pi/agent/APPEND_SYSTEM.md` 会被直接追加到 System Prompt 的最末尾。在大多数大模型的注意力机制中，**末尾提示词具有极高的指令权威，优先级高于前面的 `AGENTS.md`**。

它适合定义那些跨越所有项目通用的绝对行为准则，尤其是关于 Agent 的工作态度、风险防控与交互风格。一个成熟的推荐配置如下：

```markdown
# Global Behavioral Rules

- If the default provider doesn't have vision capabilities, use pi-vision-handoff for images.
- Read relevant local files first when the answer is available in the codebase. If not, research online via pi-web-access. Before making a big change based on online research findings, confirm with me first.
- Explain risky file edits and destructive commands (such as rm, git reset --hard, drop db) before executing.
- Write simply. Avoid AI-slop language – no flowery adjectives, unnecessary adverbs, or overly formal phrasing.
- Use en dashes (–) not em dashes (—).
```

这套规则确立了四道关键防线：
1. **多模态自适应**：主模型无视觉时自动流转给视觉转接插件；
2. **本地优先原则**：本地代码库有的禁止盲目联网，重大外部改动先确认；
3. **高危动作先声夺人**：删除、覆盖前强制说明；
4. **剔除 AI 黑话（Anti AI-Slop）**：禁止华而不实的客套与冗余修饰，保持终端代码输出的高密度与高专业度。

---

## 四、 settings.json：常用选项详解

`settings.json` 控制着运行时状态机的核心参数。全局文件位于 `~/.pi/agent/settings.json`，项目覆盖位于 `.pi/settings.json`。

### 1. 模型与思考级别（Model & Thinking）
```json
{
  "$schema": "https://pi.dev/schemas/settings.schema.json",
  "defaultProvider": "deepseek",
  "defaultModel": "deepseek-chat",
  "defaultThinkingLevel": "medium",
  "enabledModels": [
    "deepseek/*",
    "anthropic/claude-3-7-sonnet*",
    "ollama/*"
  ],
  "thinkingBudgets": {
    "minimal": 1024,
    "low": 4096,
    "medium": 10240,
    "high": 32768,
    "xhigh": 65536
  }
}
```
* `defaultProvider` 与 `defaultModel`：控制启动时的默认大模型；
* `defaultThinkingLevel`：设置默认思考深度，可选项：`off`、`minimal`、`low`、`medium`、`high`、`xhigh`、`max`；
* `enabledModels`：**极度实用的体验优化项**。定义按下 `Ctrl + P` 快捷键时循环轮替的模型列表（支持通配符 `*`）。若不配置，`Ctrl + P` 会遍历 Provider 下所有几百个模型，体验极其糟糕；
* `thinkingBudgets`：自定义不同 Thinking 等级所分配的最大 Token 预算。预算越高，推理链越完整，但响应延迟与 Token 消耗也成倍增长。

### 2. 上下文压缩（Compaction）
Compaction 是 Pi 处理长上下文的核心黑科技。当对话历史接近上下文上限时，Pi 会在后台自动对旧交互进行摘要提炼：
```json
{
  "compaction": {
    "reserveTokens": 16384,
    "keepRecentTokens": 20000
  }
}
```
* `reserveTokens`：为 LLM 本轮响应预留的 Token 余量（默认 `16384`）。当剩余上下文窗口小于该值时，自动触发后台压缩；
* `keepRecentTokens`：**不参与压缩的最新近期交互 Token 数**（默认 `20000`）。这部分上下文会以原始格式完整保留，确保最近讨论的代码细节与错误日志绝不失真。

### 3. 重试策略（Retry Policy）
```json
{
  "retry": {
    "agent": {
      "maxRetries": 3,
      "baseDelayMs": 2000
    },
    "provider": {
      "maxRetries": 0
    }
  }
}
```
* **分层重试机制**：Pi 将重试解耦为 Agent 逻辑层和 Provider 网络层。官方明确建议保持 `provider.maxRetries = 0`，避免 SDK 内部盲目硬重试在撞上 Rate Limit 错误前就把配额刷光；
* `baseDelayMs`：指数退避（Exponential Backoff）的初始延迟（2s → 4s → 8s）。对于批量采集或耗时长的爬虫任务，建议调大此值以平滑限流高峰。

### 4. 项目信任模式（Project Trust）
```json
{
  "projectTrust": "ask"
}
```
* 可选值：`ask`（首次发现新项目的 `.pi/` 时主动弹窗询问是否信任，默认安全策略）、`always`（全部信任）、`never`（从不加载项目扩展）；
* 在 CI/CD 自动化流水线中，可通过启动参数 `pi -a` 或 `pi --approve` 自动确认。

---

## 五、 models.json 添加自定义模型

如果你的模型不在官方内置列表中，可在 `~/.pi/agent/models.json` 中随意扩展。支持 Ollama、vLLM、LM Studio、OpenRouter 以及任何 OpenAI 兼容 API。

### 场景一：Ollama 本地私有化模型
```json
{
  "providers": {
    "ollama": {
      "baseUrl": "http://localhost:11434/v1",
      "apiKey": "ollama",
      "api": "openai-completions",
      "compat": {
        "developerRole": false,
        "reasoningEffort": false
      },
      "models": [
        {
          "id": "qwen2.5-coder:32b",
          "name": "Qwen 2.5 Coder 32B (Local)",
          "contextWindow": 32768,
          "maxTokens": 8192
        }
      ]
    }
  }
}
```
* `apiKey`: 填 `"ollama"` 作为占位符（Ollama 本身不验 Key，但 Pi 要求必须有值才会加入 `/model` 列表）；
* `compat`: 关闭 `developerRole` 和 `reasoningEffort`，完美避开 Ollama 对 OpenAI 新参数不兼容报错的坑。

### 场景二：OpenRouter 路由偏好配置
```json
{
  "providers": {
    "openrouter": {
      "baseUrl": "https://openrouter.ai/api/v1",
      "apiKey": "$OPENROUTER_API_KEY",
      "api": "openai-completions",
      "models": [
        {
          "id": "anthropic/claude-3.7-sonnet",
          "name": "Claude 3.7 Sonnet (OpenRouter)",
          "compat": {
            "openRouterRouting": {
              "order": ["Anthropic", "Together"],
              "data_collection": "deny"
            }
          }
        }
      ]
    }
  }
}
```
* `openRouterRouting`: 会被原样透传给 OpenRouter 网关，`order` 锁定首选服务商，`data_collection: "deny"` 严禁数据被用于模型再训练。

### 场景三：第三方代理中转 Anthropic API
```json
{
  "providers": {
    "custom-anthropic": {
      "baseUrl": "https://api.your-proxy.com",
      "apiKey": "$CUSTOM_API_KEY",
      "api": "anthropic-messages",
      "headers": {
        "x-custom-token": "!cat ~/.tokens/custom.jwt"
      },
      "models": [
        {
          "id": "claude-3-7-sonnet-20250219",
          "name": "Claude 3.7 Sonnet (Proxy)"
        }
      ]
    }
  }
}
```
* `apiKey` 与 `headers` 均支持三大取值方式：
  1. 直接字面量字符串；
  2. `$ENV_VAR` 环境变量插值；
  3. `!command` 动态命令执行输出。

---

## 六、 auth.json 管理 API 凭据

`~/.pi/agent/auth.json` 专门集中持久化所有服务商的 API Key 与 Token。文件权限被底层强制设定为 `0600`（仅当前操作系统用户可读写）。

一个极其优雅的实战技巧是**通过 Shell 命令从操作系统密钥链动态取 Key，避免在明文 JSON 中暴露密钥**：

```json
{
  "anthropic": "!security find-generic-password -ws 'ANTHROPIC_API_KEY'",
  "deepseek": "$DEEPSEEK_API_KEY"
}
```
> *注：`auth.json` 的判定优先级高于系统环境变量。若该文件中定义了 `deepseek`，则会直接覆盖全局系统的 `$DEEPSEEK_API_KEY`。*

---

## 七、 模型切换策略：什么时候用什么模型？

### 1. 终端高频切换快捷键
| 操作 | 快捷键 / 命令 | 说明 |
|:---|:---|:---|
| **打开模型全量选择器** | `Ctrl + L` 或 `/model` | 模糊搜索并快速换模 |
| **循环切换常用模型** | `Ctrl + P` | 仅在 `enabledModels` 列表内轮换秒切 |
| **调整思考级别** | `Shift + Tab` | 循环切换 Thinking 深度（None → Max） |
| **中断当前操作** | `Escape` | 强行中止模型推理或当前工具执行 |
| **发送转向指令** | `Enter` | 在 Agent 执行时强制插队，立即纠正方向 |
| **发送排队指令** | `Alt + Enter` | 在 Agent 做完当前整套任务后作为下一轮交付 |
| **退出** | `Ctrl + C` (连按两次) | 安全退出 Pi 终端 |
| **模糊引用文件** | `@` | 输入 `@` 触发文件模糊补全并加入上下文 |
| **执行即时命令** | `!` | 运行 Bash 命令并将输出反馈给模型 |
| **静默命令** | `!!` | 仅在本地运行命令，不污染模型上下文 |

### 2. 业界推荐的模型分层实战矩阵
结合 DeepakNess 与 Bitdoze 等海外极客的实战经验，推荐遵循**能力与任务复杂度严格分层**原则：

| 任务类型 | 推荐模型组合 | 推荐 Thinking 深度 | 选型理由 |
|:---|:---|:---|:---|
| **快速编辑、重命名、批量脚本** | DeepSeek V4 Flash / MiniMax M2.7 | `low` 或 `off` | 成本趋近于零，吞吐极高，处理明确任务速度极快 |
| **日常业务编码、功能开发、中小重构** | DeepSeek V4 Pro / Qwen 2.5 Coder | `medium` | 在代码质量、推理深度与响应开销间取得最佳平衡 |
| **架构设计、高难算法、疑难复杂 Debug** | Claude 3.7 Sonnet / Grok 4.6 | `high` 或 `xhigh` | 极其复杂的长逻辑链必须依赖顶尖模型的深层推理能力 |
| **视觉审校、UI 还原、原型图理解** | GPT-5.6 Luna / Claude | 取决于具体模型 | 通过 `pi-vision-handoff` 插件给非视觉主模型提供视觉中转 |

> **真实数据**：DeepakNess 在批量提取 28.5 万条 URL 的爬虫实战中，使用 `DeepSeek V4 Flash` + `low thinking`，连续跑 1.5 小时总账单仅 **1 美元**！

---

## 八、 Thinking Level 如何影响输出质量？

Thinking Level 控制着模型在写出最终代码前展开推理的 Token 深度：

| Thinking 级别 | 适用场景 | 官方默认 Token 预算 |
|:---|:---|:---:|
| **`off`** | 简单问答、单纯文件内容提取、无逻辑判断的机械操作 | 0 (无推理) |
| **`minimal`** | 极简单的二元判断（如“是/否”分类、简单语法校验） | 1,024 |
| **`low`** | 轻度推理（如代码格式转换、简单正则编写、变量对齐） | 4,096 |
| **`medium`** | **常规核心编码任务（日常 80% 场景的黄金平衡点）** | 10,240 |
| **`high`** | 复杂重构、涉及多文件联动的改动、性能瓶颈排查 | 32,768 |
| **`xhigh`** | 深度架构推演、并发竞态逻辑设计、协议反序列化设计 | 65,536 |
| **`max`** | 极端复杂的端到端攻坚（直接拉满到该 Provider 的物理上限） | Provider Max |

**非线性规律**：从 `low` 提升到 `medium`，代码准确度提升最为惊人；而从 `high` 到 `xhigh`，对于常规任务边际收益开始递减。**日常推荐默认常驻 `medium`，遇到顽固 Bug 时用 `Shift + Tab` 迅速拉到 `high` 或 `max`。**

---

## 九、 上下文管理：Compaction 与会话树

### 1. 自动压缩（Auto-Compaction）
长会话在编写复杂项目时极易耗尽上下文。Pi 的机制是在后台默默监视 Token 计数，当剩余可用空间逼近 `reserveTokens` 警戒线时，自动对旧对话启动局部总结压缩，释放出宝贵的上下文空间。日常亦可随时键入：
```
/compact
```
进行手动即时压缩。

### 2. 会话分支树（Session Tree）
通过输入 `/tree` 可以唤起全屏的 Git 式对话分支图。Pi 原生支持：
* `/resume`：从历史存档中选择旧对话恢复；
* `/new`：以全新上下文启动空白任务；
* `/fork`：从当前任意对话节点直接派生出新分支进行方案探索。

---

## 十、 一套可直接投入生产的完整配置模板

### 1. 全局配置：`~/.pi/agent/settings.json`
```json
{
  "$schema": "https://pi.dev/schemas/settings.schema.json",
  "defaultProvider": "deepseek",
  "defaultModel": "deepseek-chat",
  "defaultThinkingLevel": "medium",
  "enabledModels": [
    "deepseek/*",
    "anthropic/claude-3-7-sonnet*",
    "ollama/*"
  ],
  "thinkingBudgets": {
    "minimal": 1024,
    "low": 4096,
    "medium": 10240,
    "high": 32768,
    "xhigh": 65536
  },
  "compaction": {
    "reserveTokens": 16384,
    "keepRecentTokens": 20000
  },
  "retry": {
    "agent": {
      "maxRetries": 3,
      "baseDelayMs": 2000
    },
    "provider": {
      "maxRetries": 0
    }
  },
  "projectTrust": "ask"
}
```

### 2. 全局行为准则：`~/.pi/agent/APPEND_SYSTEM.md`
```markdown
- If the default provider doesn't have vision capabilities, use pi-vision-handoff for images.
- Read relevant local files first when the answer is available in the codebase. If not, research online via pi-web-access. Before making a big change based on online research findings, confirm with me first.
- Explain risky file edits and destructive commands before executing.
- Write simply. Avoid AI-slop language – no flowery adjectives, unnecessary adverbs, or overly formal phrasing.
- Use en dashes (–) not em dashes (—).
```

### 3. 项目级专属配置：`.pi/settings.json`（针对高频短任务微调）
```json
{
  "compaction": {
    "reserveTokens": 32768,
    "keepRecentTokens": 10000
  }
}
```

---

## 总结

Pi 的设计哲学可以用八个字概括：**“层层叠加，精确控制”**。
* 全局配置锁定理性基线；
* 项目配置覆盖局部特性；
* `AGENTS.md` 传递专业工程上下文；
* `APPEND_SYSTEM.md` 约束核心行为底线。

当你吃透了这套配置体系的精髓，Pi 的“最小核心 + 外部配置”就不再是功能简陋的借口，而成为了开发者彻底掌控 AI 行为的最强利刃。在日常工作中，善用 `Ctrl + P` 秒切模型，配合 `Shift + Tab` 调度思考深度，就能让 AI 在极低成本与极致工程表现之间游刃有余。
