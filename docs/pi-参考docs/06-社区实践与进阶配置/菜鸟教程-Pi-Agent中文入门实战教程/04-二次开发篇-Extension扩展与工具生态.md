# 模块四：二次开发篇 —— Extension 扩展开发、自定义工具与生态集成

> **本篇定位**：本篇是针对开发者的进阶实战指南，涵盖 Extension 插件生命周期、自定义工具开发 (pi.registerTool + TypeBox)、事件总线系统、斜杠命令与快捷键注册、Pi Packages 包生态、跨平台部署与 llama.cpp 本地私有化模型集成。  
> **来源**：菜鸟教程 (RUNOOB.COM) Pi Agent 系列课程精华汇编  

---

## 📑 章节目录导航

- [一、Extension 扩展系统架构原理](#一Extension-扩展系统架构原理)
- [二、实战：开发自定义工具 (TypeBox 严格校验)](#二实战开发自定义工具-TypeBox-严格校验)
- [三、事件总线与生命周期交互钩子](#三事件总线与生命周期交互钩子)
- [四、注册自定义斜杠命令与快捷键](#四注册自定义斜杠命令与快捷键)
- [五、Pi Packages 软件包管理与分发](#五Pi-Packages-软件包管理与分发)
- [六、多平台部署要点 (Linux/macOS/Windows/Docker)](#六多平台部署要点-Linux/macOS/Windows/Docker)
- [七、本地私有化模型：对接 llama.cpp (GGUF)](#七本地私有化模型对接-llamacpp-GGUF)

---

## 一、Extension 扩展系统架构原理

Extensions（扩展）是 Pi Agent 最强大的定制方式——你可以用 TypeScript 编写自定义工具、命令和事件监听器。

### 什么是 Extension

Extension 是一个 TypeScript 模块，它可以做下面这些事。

| 能力 | 说明 | 典型用途 |
| --- | --- | --- |
| 注册 自定义工具 | 为 AI 增加可调用的新功能 | 查询内部系统、读写数据库、封装第三方 API |
| 注册 自定义命令 | 用户通过 /命令名 调用 | 封装常用提示词、一键执行固定流程 |
| 监听 生命周期事件 | 在 AI 工作的各个阶段插入逻辑 | 拦截危险命令、注入上下文、记录审计日志 |
| 注册 键盘快捷键 | 在终端界面中绑定按键 | 快速切换面板、触发高频操作 |
| 展示 自定义 UI | 在终端中渲染交互界面 | 进度条、列表、确认弹窗等组件 |

### 第一个 Extension：Hello World

下面这个扩展一次性演示了事件监听、工具注册和命令注册三种能力。

```typescript
// 文件路径：~/.pi/agent/extensions/my-extension.ts
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export default function (pi: ExtensionAPI) {
  // 在会话启动时触发
  pi.on("session_start", async (_event, ctx) => {
    ctx.ui.notify("我的扩展已加载！", "info");
  });

  // 拦截危险命令
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "bash"
        && event.input.command?.includes("rm -rf")) {
      const ok = await ctx.ui.confirm("危险操作！", "确认执行 rm -rf？");
      if (!ok) return { block: true, reason: "用户阻止" };
    }
  });

  // 注册一个自定义工具
  pi.registerTool({
    name: "greet",
    label: "打招呼",
    description: "向指定的人打招呼",
    parameters: Type.Object({
      name: Type.String({ description: "要打招呼的人名" }),
    }),
    async execute(toolCallId, params) {
      return {
        content: [{ type: "text", text: `你好，${params.name}！` }],
        details: {},
      };
    },
  });

  // 注册一个自定义命令
  pi.registerCommand("hello", {
    description: "向世界问好",
    handler: async (args, ctx) => {
      ctx.ui.notify(`你好 ${args || "世界"}！`, "info");
    },
  });
}
```

第 13 行的事件判断用了最简单的event.toolName写法，也可以用类型守卫把 event 收窄成具体事件类型，见《事件系统》一章。

用 pi -e 参数启动 Pi Agent，即可加载这个扩展进行测试：

```
$ pi -e ~/.pi/agent/extensions/my-extension.ts

Loading extension: /Users/runoob/.pi/agent/extensions/my-extension.ts

my-extension 加载成功（1 个工具、1 个命令）

我的扩展已加载！
```

最后一行就是 session_start 事件里 ctx.ui.notify 弹出的通知，说明扩展已经生效。

### 扩展的加载位置

Pi Agent 会在固定的几个目录中自动发现扩展，也可以显式指定路径。

| 位置 | 作用范围 | 说明 |
| --- | --- | --- |
| ~/.pi/agent/extensions/*.ts | 全局 | 对所有项目生效，自动发现 |
| ~/.pi/agent/extensions/*/index.ts | 全局 | 子目录中有 index.ts 的扩展 |
| .pi/extensions/*.ts | 项目 | 仅当前项目，需项目信任 |
| .pi/extensions/*/index.ts | 项目 | 项目子目录扩展 |

除了命令行参数，也可以在 settings.json 的 extensions 字段中写入路径数组，目录路径会按扩展目录规则展开。

```json
{

  "extensions": [

    "/Users/runoob/.pi/agent/extensions/quick-notify.ts",

    "/Users/runoob/.pi/agent/extensions/team-tools"

  ]

}
```

第一个元素是单文件扩展，第二个是目录扩展，实际使用时替换成你自己的扩展位置即可。

### Extension 文件结构

Extension 可以是单个 .ts 文件，也可以是一个带入口文件的目录。

#### 单文件扩展

最简单的形式，适合小型扩展：

```
~/.pi/agent/extensions/

└── my-extension.ts
```

#### 目录扩展（含 index.ts）

适合多文件扩展：

```
~/.pi/agent/extensions/

└── my-extension/

    ├── index.ts        # 入口文件（导出默认函数）

    ├── tools.ts        # 辅助模块

    └── utils.ts        # 工具函数
```

#### 带依赖的扩展

适合需要 npm 包的大型扩展：

```
~/.pi/agent/extensions/

└── my-extension/

    ├── package.json    # 声明依赖和入口

    ├── node_modules/   # npm install 后生成

    └── src/

        └── index.ts
```

### 扩展的加载机制

扩展通过[jiti](https://github.com/unjs/jiti)加载，TypeScript 代码无需编译即可直接运行。

如果你的工厂函数返回 Promise，Pi Agent 会在继续启动流程之前等待它完成。

这意味着你可以在扩展初始化时做异步操作，比如获取远程配置。

### 可用 Import 包

这些包由 Pi Agent 内置提供，扩展中可以直接 import。

| 包名 | 用途 |
| --- | --- |
| @earendil-works/pi-coding-agent | 扩展类型（ExtensionAPI、ExtensionContext 和各种事件类型） |
| typebox | 工具参数的 Schema 定义 |
| @earendil-works/pi-ai | AI 工具（如 StringEnum，用于 Google 兼容的枚举） |
| @earendil-works/pi-tui | TUI 组件，用于自定义渲染 |

这些内置核心包由 Pi 自身提供，列为 peerDependencies 即可，不要打包进你的扩展。

自有运行时依赖则必须写进 package.json 的 dependencies 字段。

Pi 安装扩展包时默认执行生产安装（npm install --omit=dev），devDependencies 在运行时不可用。

其他 npm 包也可以使用——在扩展目录中添加 package.json 并运行 npm install 即可。

### 开发提示

这几条经验能帮你少走弯路，尤其是加载方式的选择。

| 做法 | 原因 |
| --- | --- |
| 把扩展放在 ~/.pi/agent/extensions/ 目录中 | 支持 /reload 热重载，修改后无需重启会话 |
| pi -e ./path.ts 仅用于临时测试 | 长期使用应把扩展放入 ~/.pi/agent/extensions/ 目录，由 Pi Agent 自动发现 |
| 不要在扩展工厂函数中启动后台资源 | 进程、socket、文件监听器、定时器等应在 session_start 事件中启动 |
| 在 session_shutdown 事件中清理会话级资源 | 避免切换会话后残留句柄与监听器 |

### 进一步集成

除了编写扩展，官方还提供两条编程接入路线。

Node 或 TypeScript 项目可以直接使用@earendil-works/pi-coding-agent导出的 SDK：用 createAgentSession 创建会话、subscribe 订阅事件、prompt 发送消息。

这种方式与 Pi 同进程运行，类型定义完整。

跨语言调用或需要进程隔离时，改用pi --mode rpc，通过 JSONL 协议与 Pi 进程通信。

两条路线与扩展共用同一套事件模型，选哪条主要看你是否需要独立进程。

---

---

## 二、实战：开发自定义工具 (TypeBox 严格校验)

通过 Extension 注册自定义工具，让 AI 能够调用你编写的函数来完成特定任务。

### 工具注册基础

使用pi.registerTool()注册一个 AI 可调用的工具：

```typescript
// 文件路径：~/.pi/agent/extensions/todo-tool.ts
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";

// 定义待办事项列表（内存存储）
let todos: string[] = [];

export default function (pi: ExtensionAPI) {
  // 启动时从会话中恢复状态
  pi.on("session_start", async (_event, ctx) => {
    todos = [];
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type === "message"
          && entry.message.role === "toolResult"
          && entry.message.toolName === "todo") {
        todos = entry.message.details?.todos ?? [];
      }
    }
  });

  pi.registerTool({
    name: "todo",
    label: "待办事项",
    description: "管理项目的待办事项列表",
    // 简短描述，显示在系统提示词的 Available tools 区域
    promptSnippet: "管理项目待办事项：list 列表、add 添加、done 完成",
    // 使用指南，追加到系统提示词的 Guidelines 区域
    promptGuidelines: [
      "使用 todo 工具进行任务规划，不要直接编辑待办文件",
    ],
    parameters: Type.Object({
      // StringEnum 确保与 Google API 兼容
      action: StringEnum(["list", "add", "done"] as const),
      text: Type.Optional(Type.String({
        description: "添加时：事项描述。完成时：事项编号或描述"
      })),
    }),
    // 兼容旧参数格式
    prepareArguments(args) {
      if (!args || typeof args !== "object") return args;
      const input = args as { action?: string; oldAction?: string };
      // 将旧字段映射到新字段
      if (typeof input.oldAction === "string"
          && input.action === undefined) {
        return { ...input, action: input.oldAction };
      }
      return args;
    },
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      if (signal?.aborted) {
        return {
          content: [{ type: "text", text: "操作已取消" }]
        };
      }

      // 发送进度更新
      onUpdate?.({
        content: [{ type: "text", text: `正在处理: ${params.action}` }],
      });

      switch (params.action) {
        case "list":
          return {
            content: [{
              type: "text",
              text: todos.length === 0
                ? "待办列表为空"
                : todos.map((t, i) => `${i + 1}. ${t}`).join("\n"),
            }],
            details: { todos: [...todos] },
          };
        case "add":
          if (!params.text) {
            throw new Error("add 操作需要 text 参数");
          }
          todos.push(params.text);
          // 第 5 个参数 ctx 是扩展上下文，这里用它向终端弹一条通知
          ctx.ui.notify(`待办已新增：${params.text}`, "info");
          return {
            content: [{
              type: "text",
              text: `已添加: ${params.text}（共 ${todos.length} 项）`,
            }],
            details: { todos: [...todos] },
          };
        case "done":
          if (!params.text) {
            throw new Error("done 操作需要 text 参数");
          }
          const idx = todos.findIndex(
            t => t.includes(params.text!)
          );
          if (idx === -1) {
            return {
              content: [{
                type: "text",
                text: `未找到匹配项: ${params.text}`
              }],
              details: { todos: [...todos] },
            };
          }
          const removed = todos.splice(idx, 1)[0];
          return {
            content: [{
              type: "text",
              text: `已完成: ${removed}（剩余 ${todos.length} 项）`,
            }],
            details: { todos: [...todos] },
          };
        default:
          throw new Error("未知操作");
      }
    },
  });
}
```

注册完成后，AI 会根据 description 和 promptSnippet 自主决定何时调用 todo 工具。

例如用户说"帮我把写周报加进待办"，AI 会发起下面这次调用：

```
tool_call: todo

{

  "action": "add",

  "text": "写周报"

}
```

execute 执行后，返回给 AI 的文本如下：

```
待办已新增：写周报（共 1 项）
```

AI 拿到这个结果后，会用自然语言向用户确认，例如"已把「写周报」加入待办列表，目前共 1 项"。

除了从 toolResult 的 details 重建状态，跨重启持久化还有另一条路：pi.appendEntry()。

它把自定义条目直接写进会话文件，配合pi.registerEntryRenderer()还能在对话记录里渲染出来。

自定义条目不会进入 LLM 上下文，因此不占用 token。

但它们会随会话一起保存，并且在 /tree 分支中保留。

### 工具定义详解

registerTool 的配置对象包含以下字段，其中 name、parameters 和 execute 是核心。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| name | string | 是 | 工具的唯一标识，AI 通过此名称调用 |
| label | string | 是 | 工具显示名 |
| description | string | 是 | 工具功能描述，AI 据此判断何时使用 |
| parameters | TypeBox Schema | 是 | 工具参数的类型定义 |
| promptSnippet | string | 否 | 在 Available tools 区域的单行简介 |
| promptGuidelines | string[] | 否 | 追加到系统提示 Guidelines 区域的指南 |
| prepareArguments | function | 否 | 在 Schema 验证前转换参数，用于兼容旧格式 |
| execute | async function | 是 | 工具的实际执行逻辑 |

### execute 函数详解

execute 函数接收以下参数：

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| toolCallId | string | 工具调用的唯一 ID |
| params | 泛型 T | 经过 Schema 验证的参数对象 |
| signal | AbortSignal \| undefined | 取消信号，用户按 Escape 时触发 |
| onUpdate | function | 发送进度更新的回调 |
| ctx | ExtensionContext | 扩展上下文，提供 UI、会话等能力 |

返回值格式：

```
// 文件路径：~/.pi/agent/extensions/todo-tool.ts（execute 函数的返回值）
return {
  // 发送给 LLM 的内容（必需）
  content: [{ type: "text", text: "操作完成" }],

  // 自定义详情数据，用于状态重建和渲染（可选）
  details: { result: "..." },

  // 嵌套 LLM 调用的用量统计（可选）
  usage: nestedModelUsage,

  // 终止标记：当同一批次所有工具都返回 terminate 时
  // 跳过后续的 LLM 调用（可选）
  terminate: true,
};
```

### StringEnum 与类型安全

使用StringEnum而不是 Type.Union/Type.Literal 来定义枚举参数：

```python
// 文件路径：~/.pi/agent/extensions/todo-tool.ts（parameters 字段）
import { StringEnum } from "@earendil-works/pi-ai";

// 正确：Google API 兼容
parameters: Type.Object({
  action: StringEnum(["list", "add", "done"] as const),
})

// 错误：Google API 不兼容
parameters: Type.Object({
  action: Type.Union([
    Type.Literal("list"),
    Type.Literal("add"),
    Type.Literal("done"),
  ]),
})
```

### 文件修改安全队列

如果你的工具会修改文件，使用withFileMutationQueue()参与文件修改队列：

```python
// 文件路径：~/.pi/agent/extensions/note-edit.ts
import { withFileMutationQueue } from "@earendil-works/pi-coding-agent";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

// 以下片段位于 registerTool 的 execute 函数内
async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
  // 将路径解析为绝对路径
  const absolutePath = resolve(ctx.cwd, params.path);

  return withFileMutationQueue(absolutePath, async () => {
    // 确保目录存在
    await mkdir(dirname(absolutePath), { recursive: true });
    // 读取当前内容
    const current = await readFile(absolutePath, "utf8");
    // 应用修改
    const next = current.replace(params.oldText, params.newText);
    // 写回文件
    await writeFile(absolutePath, next, "utf8");

    return {
      content: [{ type: "text", text: `已更新 ${params.path}` }],
      details: {},
    };
  });
}
```

文件修改队列确保同一文件的并发修改不会互相覆盖——当内置 edit 工具和你的自定义工具同时修改同一个文件时，它们会排队执行。

### 输出截断

工具输出必须截断，避免撑满 LLM 上下文窗口。内置限制为 50KB（约 1 万 token）和 2000 行：

```
// 文件路径：~/.pi/agent/extensions/read-log.ts
import {
  truncateHead,
  formatSize,
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
} from "@earendil-works/pi-coding-agent";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

// 以下片段位于 registerTool 的 execute 函数内
async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
  // 读取一个真实文件，得到待返回的文本
  const output = await readFile(resolve(ctx.cwd, params.file), "utf8");

  // 保留开头部分（适合文件读取、搜索结果）
  const truncation = truncateHead(output, {
    maxLines: DEFAULT_MAX_LINES,
    maxBytes: DEFAULT_MAX_BYTES,
  });

  let result = truncation.content;

  // 被截断时追加一行说明，让 AI 知道内容不完整
  if (truncation.truncated) {
    result += `\n\n[输出已截断：${truncation.outputLines}/`;
    result += `${truncation.totalLines} 行`;
    result += `（${formatSize(truncation.outputBytes)}/`;
    result += `${formatSize(truncation.totalBytes)}）]`;
  }

  return {
    content: [{ type: "text", text: result }],
  };
}
```

对一个超过限制的大日志文件，工具的返回文本末尾会带上截断说明：

```json
[2026-08-31 10:02:11] server started on port 3000

[2026-08-31 10:02:12] GET / 200 12ms

[2026-08-31 10:02:12] GET /static/app.js 200 4ms

...



[输出已截断：2000/8642 行（49.9KB/210.3KB）]
```

### 覆盖内置工具

你可以通过注册同名工具来覆盖内置工具（read、bash、powershell、edit、write、grep、find、ls）。

```
$ pi -e ./tool-override.ts
```

下面用 registerTool 覆盖内置的 read 工具，为每次文件读取加一条日志：

```typescript
// 文件路径：~/.pi/agent/extensions/read-logger.ts
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export default function (pi: ExtensionAPI) {
  // 与内置工具同名即可覆盖，这里只给 read 增加日志
  pi.registerTool({
    name: "read",
    label: "读取文件",
    description: "读取文件内容，并在终端记录访问日志",
    parameters: Type.Object({
      path: Type.String({ description: "要读取的文件路径" }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const absolutePath = resolve(ctx.cwd, params.path);
      const text = await readFile(absolutePath, "utf8");
      // 额外能力：记录一次访问日志
      console.log(`[read] ${params.path}（${text.length} 字符）`);
      // 返回结构与内置 read 保持一致
      return {
        content: [{ type: "text", text }],
      };
    },
  });
}
```

加载这个扩展后，AI 每次读文件都会在终端打印一行 [read] 日志。

覆盖时，渲染器（renderCall/renderResult）会按槽位继承——如果你省略了 renderCall，内置的 renderCall 仍会使用。

这让你可以在不重写 UI 的情况下为内置工具添加日志或权限控制。

但对于 promptSnippet 和 promptGuidelines，它们不会从内置工具继承，需要显式定义。

还有一个更隐蔽的约束：你的实现必须与内置工具的结果形状完全一致，包括 details 字段。

以 read 为例，入参需要支持 offset 和 limit 两个可选参数，这样 AI 按分页方式读取大文件时才能拿到预期内容。

返回值中的 details 也必须与内置 read 的 ReadToolDetails 形状一致，否则 UI 渲染会缺信息，会话的状态跟踪也会受影响。

上面这个日志扩展示例只做演示，正式覆盖内置 read 时请按内置实现补全参数与 details。

---

---

## 三、事件总线与生命周期交互钩子

事件系统是扩展的核心机制。

通过监听生命周期事件，你可以在 AI 工作的各个阶段插入自定义逻辑。

### 生命周期全景

以下是 Pi Agent 从启动到退出过程中触发的所有事件：

每个 turn 内部，context、provider、tool 三类事件按序触发，有工具调用时循环多轮。

虚线部分表示该阶段可被多个事件多次触发。

input、before_agent_start、resources_discover、agent_settled 等其余事件的触发时机见下方全事件速查表。

### 核心事件详解

这一节挑选使用频率最高的 5 个事件，说明它们的触发时机和返回值约定。

#### input — 输入拦截

在用户输入被处理之前触发，可以转换、拦截或直接处理输入：

```
// 文件路径：~/.pi/agent/extensions/quick-input.ts
// 以下片段位于扩展工厂函数体内
pi.on("input", async (event, ctx) => {
  // event.text - 原始输入文本
  // event.images - 附带的图片
  // event.source - "interactive" | "rpc" | "extension"

  // 转换输入：在输入前添加指令
  if (event.text.startsWith("?quick ")) {
    return {
      action: "transform",
      text: `简短回复：${event.text.slice(7)}`
    };
  }

  // 直接处理：不经过 LLM 直接响应
  if (event.text === "ping") {
    ctx.ui.notify("pong", "info");
    return { action: "handled" };
  }

  // 跳过扩展注入的消息
  if (event.source === "extension") {
    return { action: "continue" };
  }

  return { action: "continue" };  // 默认：正常处理
});
```

| action 值 | 效果 |
| --- | --- |
| "continue" | 不改变输入，继续正常处理流程 |
| "transform" | 修改输入后继续处理，多个 handler 的转换会链式叠加 |
| "handled" | 完全接管，跳过 LLM 调用（第一个返回此值的 handler 生效） |

两种典型写法的实际效果如下。

输入?quick hello world时，实际发给 LLM 的文本已被改写：

```
简短回复：hello world
```

输入ping时不会调用 LLM，终端里只弹出一条通知：

```
pong
```

#### tool_call — 工具调用拦截

在工具执行之前触发，可以修改参数或阻止执行：

```python
// 文件路径：~/.pi/agent/extensions/guard-bash.ts
// import 写在模块顶层，下面的 pi.on 片段位于扩展工厂函数体内
// isToolCallEventType 是类型守卫，需从官方包导入
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

pi.on("tool_call", async (event, ctx) => {
  // 拦截危险 bash 命令
  if (isToolCallEventType("bash", event)) {
    // event.input 是 { command: string; timeout?: number }
    const dangerous = ["rm -rf /", "mkfs.", "dd if=", "> /dev/sda"];
    // 先判断是否危险，再决定是否放行
    if (dangerous.some(cmd =>
        event.input.command.includes(cmd))) {
      return { block: true, reason: "危险命令已被阻止" };
    }
    // 判断通过后才追加环境变量加载
    event.input.command = `source ~/.profile\n${event.input.command}`;
  }

  // 记录所有文件读取操作
  if (isToolCallEventType("read", event)) {
    // event.input 是 { path: string; offset?: number; limit?: number }
    ctx.ui.notify(`读取文件: ${event.input.path}`, "info");
  }
});
```

若 AI 试图执行rm -rf /，工具不会运行，终端中会显示阻断原因：

```
危险命令已被阻止
```

event.input是可变的——你修改它会直接影响工具执行。

#### tool_result — 修改工具结果

在工具执行完成后触发，可以修改返回给 LLM 的结果：

```
// 文件路径：~/.pi/agent/extensions/read-linenum.ts
// 以下片段位于扩展工厂函数体内
pi.on("tool_result", async (event, ctx) => {
  // event.toolName - 工具名
  // event.content - 返回给 LLM 的内容
  // event.details - 详情数据
  // event.isError - 是否为错误

  // 例如：对 read 结果添加行号
  if (event.toolName === "read" && !event.isError) {
    const lines = event.content
      .filter(c => c.type === "text")
      .map(c => c.text)
      .join("\n")
      .split("\n")
      .map((line, i) => `${i + 1}: ${line}`)
      .join("\n");

    return {
      content: [{ type: "text", text: lines }],
    };
  }
});
```

原本两行的文件内容，交给 LLM 时会变成带行号的形式：

```python
1: import { readFile } from "node:fs/promises";

2: export async function load() {
```

#### context — 修改 LLM 上下文

在每次 LLM 调用之前触发，可以过滤或修改消息：

```
// 文件路径：~/.pi/agent/extensions/context-filter.ts
// 以下片段位于扩展工厂函数体内
pi.on("context", async (event, ctx) => {
  // event.messages - 当前上下文消息的深拷贝，可安全修改

  // 过滤掉特定类型的消息
  const filtered = event.messages.filter(m => {
    // 移除自定义类型为 "debug" 的消息
    if (m.type === "custom" && m.customType === "debug") {
      return false;
    }
    return true;
  });

  return { messages: filtered };
});
```

#### before_agent_start — 注入消息

在 AI 开始处理用户输入之前触发，可以注入额外消息或修改系统提示词：

```
// 文件路径：~/.pi/agent/extensions/context-inject.ts
// 以下片段位于扩展工厂函数体内
pi.on("before_agent_start", async (event, ctx) => {
  // event.prompt - 用户的提示文本
  // event.systemPrompt - 当前配置的系统提示词

  return {
    // 注入一条持久化消息（存入会话，发送给 LLM）
    message: {
      customType: "my-context",
      content: `当前时间是 ${new Date().toISOString()}`,
      display: true,
    },
    // 追加到系统提示词
    systemPrompt: event.systemPrompt
      + "\n\n请在所有回复中使用中文。",
  };
});
```

### 全事件速查表


| 事件 | 触发时机 | 是否可修改 | 是否可阻断 |
| --- | --- | --- | --- |
| project_trust | 加载项目资源之前，确认是否信任当前项目 | 否 | 是（拒绝则不加载项目扩展） |
| session_start | 会话启动或恢复时 | 否 | 否 |
| resources_discover | session_start 之后触发（startup/reload 时） | 是（仅可追加 Skill、提示词模板、主题路径，不能增删扩展） | 否 |
| input | 用户输入被处理之前 | 是（可转换输入） | 是（handled 接管） |
| before_agent_start | AI 开始处理用户输入之前 | 是（可注入消息、改系统提示词） | 否 |
| agent_start | agent 循环开始时 | 否 | 否 |
| message_start / message_update | 消息生成期间（message_update 为助手流式增量） | 否 | 否 |
| message_end | 用户、助手、toolResult 消息定稿时 | 是（可返回 { message } 替换最终消息，role 必须一致） | 否 |
| turn_start | 每个轮次开始时 | 否 | 否 |
| context | 每次 LLM 调用之前 | 是（可过滤消息） | 否 |
| before_provider_headers | 发送 HTTP 请求头之前 | 是（可增改请求头） | 否 |
| before_provider_request | 请求体发给模型之前 | 是（返回非 undefined 值是替换整个请求 payload，而非中止请求） | 否 |
| after_provider_response | 收到 HTTP 响应之后，流式 body 尚未消费 | 否（仅可读取 status/headers 做观测） | 否 |
| tool_execution_start | 工具开始执行时 | 否 | 否 |
| tool_call | 工具执行之前 | 是（event.input 可变） | 是（block: true） |
| tool_execution_update | 工具执行中产生进度时 | 否 | 否 |
| tool_result | 工具执行完成后 | 是（可改返回内容） | 否 |
| tool_execution_end | 工具执行结束时 | 否 | 否 |
| turn_end | 每个轮次结束时 | 否 | 否 |
| agent_end | agent 循环结束时 | 否 | 否 |
| agent_settled | 一轮交互完全平息之后 | 否 | 否 |
| session_before_switch | /new 或 /resume 执行之前 | 否 | 是（返回 { cancel: true }） |
| session_before_fork | /fork 或 /clone 执行之前 | 否 | 是（返回 { cancel: true }） |
| session_before_compact | 压缩执行之前（手动 /compact、阈值、上下文溢出） | 是（可自定义压缩摘要） | 是（返回 { cancel: true }） |
| session_shutdown | 会话销毁前触发，退出、/new、/resume、/fork、/reload 都会触发（reason 为 quit/reload/new/resume/fork） | 否 | 否 |

### 事件处理要点

写事件 handler 时，下面这几点决定了代码是否健壮。

| 方法 | 作用 |
| --- | --- |
| 多个扩展监听同一事件 | 按扩展加载顺序依次执行，前一个的返回值会影响后续 handler |
| 返回 { block: true, reason: "..." } | 阻止该操作，reason 会展示给用户和 AI |
| 返回 { cancel: true } | 取消会话切换等操作 |
| 使用 ctx.signal | 在异步操作中响应取消信号，用户按 Escape 时中止 |
| 使用 ctx.ui 系列方法 | 与用户交互，如 notify、confirm、select 等 |
| 用 ctx.hasUI 守卫对话框调用 | Print/JSON/RPC 模式下对话框类方法不可用或为空操作，先判断再调用 |
| 用 ctx.mode === "tui" 守卫 TUI 专属 API | custom()、组件工厂、终端输入等只在交互模式有效 |

---

---

## 四、注册自定义斜杠命令与快捷键

通过扩展注册自定义命令、键盘快捷键和 CLI 标志，让 Pi Agent 更好地适应你的工作流。

### 注册自定义命令

使用pi.registerCommand()注册用户可通过 / 调用的命令。

下面的扩展同时演示了基础命令和带参数自动补全的命令：

```
// 文件路径：~/.pi/agent/extensions/stats-command.ts

// 基础命令
pi.registerCommand("stats", {
  description: "显示当前会话的统计信息", // 必填，显示在 / 自动补全列表中
  handler: async (args, ctx) => {
    const count = ctx.sessionManager.getEntries().length;
    ctx.ui.notify(`共 ${count} 条消息`, "info");
  }
});

// 带参数自动补全的命令
pi.registerCommand("deploy", {
  description: "部署到指定环境",
  // 定义参数自动补全，prefix 是用户已输入的参数前缀
  getArgumentCompletions: (prefix) => {
    const envs = ["dev", "staging", "prod"];
    const items = envs
      .filter(e => e.startsWith(prefix))
      .map(e => ({ value: e, label: e }));
    return items.length > 0 ? items : null; // 无匹配时返回 null
  },
  handler: async (args, ctx) => {
    if (!args) {
      ctx.ui.notify("用法: /deploy <环境名>", "warning");
      return;
    }
    ctx.ui.notify(`正在部署到 ${args} 环境...`, "info");
  },
});
```

保存后执行 /reload 加载扩展，在编辑区输入 /stats 即可看到效果：

```
/stats

共 42 条消息
```

### 扩展主动发消息

除了被动响应命令和事件，扩展还可以主动驱动对话。

pi.sendMessage(message, deliverAs?)用于注入自定义消息，pi.sendUserMessage(text, deliverAs?)则模拟一条用户输入。

deliverAs 有三个取值：steer 是默认值，把消息插入当前轮；followUp 在本轮结束后追加；nextTurn 开启新一轮（仅 sendMessage 支持）。

sendUserMessage 总是会触发一轮回复，因为它对 AI 来说就是一次真实的用户发言。

流式输出期间调用这两个方法时，必须显式给出 deliverAs，否则会直接抛错。

```
// 文件路径：~/.pi/agent/extensions/follow-up.ts
// 以下片段位于扩展工厂函数体内

// 模拟用户补充要求：等当前所有工具执行完再追加
pi.sendUserMessage("部署完成后请顺手检查生产环境日志", {
  deliverAs: "followUp",
});

// 只往上下文里塞参考信息，不模拟用户发言
pi.sendMessage({
  customType: "deploy-context",
  content: "当前部署目标是 production",
  display: true,
}, {
  deliverAs: "steer", // 默认值，插入当前轮
});
```

sendMessage 还支持 triggerTurn: true，在 agent 空闲时立即触发一次 LLM 响应。

两者的选择标准很简单：想让 AI 真正接话就用 sendUserMessage，只想提供参考信息就用 sendMessage。

### 命令上下文（ExtensionCommandContext）

命令的 handler 接收的是ExtensionCommandContext，它继承自 ExtensionContext。

在普通上下文的基础上，它额外提供以下方法：

| 方法 | 说明 |
| --- | --- |
| ctx.getSystemPromptOptions() | 读取构建系统提示词的基础输入（contextFiles、skills 等），仅命令上下文可用 |
| ctx.waitForIdle() | 等待 AI 完全空闲（包括重试、压缩、跟进消息全部完成） |
| ctx.newSession(options) | 创建新会话，可指定父会话和初始化逻辑 |
| ctx.fork(entryId, options) | 从指定条目分叉出新会话 |
| ctx.navigateTree(targetId, options) | 导航到会话树中的指定位置 |
| ctx.switchSession(sessionPath, options) | 切换到另一个会话文件 |
| ctx.reload() | 执行与 /reload 相同的热重载流程 |

下面的命令把当前项目的所有会话列成选择列表，选中后直接切换过去：

```python
// 文件路径：~/.pi/agent/extensions/switch-session.ts
import { SessionManager } from "@earendil-works/pi-coding-agent";

pi.registerCommand("switch", {
  description: "切换到另一个会话",
  handler: async (args, ctx) => {
    // 列出当前项目的所有会话
    const sessions = await SessionManager.list(ctx.cwd);
    if (sessions.length === 0) {
      ctx.ui.notify("没有可用的会话", "warning");
      return;
    }

    // 弹出选择列表
    const choice = await ctx.ui.select(
      "选择要切换的会话：",
      sessions.map(s => s.file),
    );

    if (choice) {
      // 切换到选中的会话
      await ctx.switchSession(choice, {
        withSession: async (ctx) => {
          ctx.ui.notify("已切换会话", "info");
        },
      });
    }
  },
});
```

```
/switch

┌ 选择要切换的会话：

│ > ~/.pi/agent/sessions/my-project/abc123.jsonl

│   ~/.pi/agent/sessions/my-project/def456.jsonl

└

已切换会话
```

### 注册快捷键

使用pi.registerShortcut()注册自定义键盘快捷键。

下面把「切换 Plan 模式」绑到一个尚无内置占用的组合键上：

```
// 文件路径：~/.pi/agent/extensions/plan-shortcut.ts

pi.registerShortcut("ctrl+shift+g", {
  description: "切换 Plan 模式",
  handler: async (ctx) => {
    ctx.ui.notify("已切换 Plan 模式！", "info");
  },
});
```

启动后按下组合键即可触发：

```
已切换 Plan 模式！
```

快捷键格式为修饰键+按键，例如 ctrl+shift+g、alt+x 等。

### 注册 CLI 标志

使用pi.registerFlag()为 pi 命令添加自定义 CLI 参数。

下面的例子注册一个 --plan 布尔标志，用于让 AI 先出计划再动手：

```
// 文件路径：~/.pi/agent/extensions/plan-flag.ts

pi.registerFlag("plan", {
  description: "以 Plan 模式启动",
  type: "boolean",
  default: false,
});

// 在扩展代码中检查标志值
// 注意：pi.getFlag() 要等到命令行参数解析完成后才有值，
// 因此建议把判断放进事件回调里，而不是写在扩展模块顶层。
// 模块顶层求值发生在扩展加载阶段，此时读到的永远是默认值 false。
pi.on("before_agent_start", async (event, ctx) => {
  if (!pi.getFlag("plan")) return; // 未启用 --plan 则不做任何修改
  return {
    systemPrompt: event.systemPrompt
      + "\n\nPlan Mode：先提出计划，经用户确认后再执行。",
  };
});
```

使用方式：

```
$ pi --plan "帮我实现用户认证功能"
```

### 扩展间通信

使用pi.events在扩展之间共享事件。

发送方不需要知道谁在监听，监听方也不需要知道事件从哪里来：

```
// 文件路径：~/.pi/agent/extensions/deploy-events.ts

// 扩展 A：发送事件
pi.events.emit("deploy:completed", {
  env: "production",
  timestamp: Date.now(),
});

// 扩展 B：监听事件（通常写在另一个扩展文件里）
pi.events.on("deploy:completed", (data) => {
  console.log(`部署完成：${data.env}`);
});
```

### 获取已注册的命令

使用pi.getCommands()获取当前会话中所有可用的命令。

下面的例子注册一个 /my-commands 命令，用来列出所有由扩展注册的命令：

```
// 文件路径：~/.pi/agent/extensions/list-commands.ts

pi.registerCommand("my-commands", {
  description: "列出扩展注册的所有命令",
  handler: async (args, ctx) => {
    const commands = pi.getCommands();

    // 按来源分类
    const extCommands = commands.filter(
      c => c.source === "extension"
    );
    const templates = commands.filter(
      c => c.source === "prompt"
    );
    const skills = commands.filter(
      c => c.source === "skill"
    );

    // 把结果展示出来，避免只计算不输出
    ctx.ui.notify(
      `扩展命令 ${extCommands.length} 个：`
        + extCommands.map(c => "/" + c.name).join("、"),
      "info"
    );
    console.table(commands);
  },
});
```

```
/my-commands

扩展命令 2 个：/stats、/deploy
```

每个命令条目包含以下字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| name | string | 命令名，在编辑区以 /name 的形式调用 |
| description | string | 命令描述，显示在自动补全列表中 |
| source | string | 来源类型：extension、prompt、skill 等 |
| sourceInfo | object | 详细的来源元数据，例如注册它的扩展路径 |

### 动态工具管理

运行时管理工具的启用和禁用。

典型用途是临时关掉写操作工具，让 AI 在一次任务里只能读不能改：

```
// 文件路径：~/.pi/agent/extensions/manage-tools.ts

// 获取当前启用的工具列表
const active = pi.getActiveTools();
// 例如：["read", "bash", "edit", "write"]

// 获取所有已注册工具的元数据
const all = pi.getAllTools();

// 筛选内置工具
const builtinTools = all.filter(
  t => t.sourceInfo.source === "builtin"
);

// 筛选扩展注册的工具
const extTools = all.filter(
  t => t.sourceInfo.source !== "builtin"
    && t.sourceInfo.source !== "sdk"
);

// 动态启用自定义工具（保留现有工具）
pi.setActiveTools([...new Set([...active, "my_tool"])]);

// 切换到只读模式：只保留读取类工具，
// 不包含 bash / edit / write，AI 在此状态下无法执行命令或改动文件
pi.setActiveTools(["read", "grep", "find", "ls"]);
```

传入 setActiveTools 的变更必须是增量的（additive），在同一次调用中移除当前已激活的工具会失去延迟加载优化。

另外，激活带 promptSnippet 或 promptGuidelines 的工具会重建系统提示词，即使模型支持延迟加载，也可能使缓存的提示词前缀失效。

---

---

## 五、Pi Packages 软件包管理与分发

Pi Packages(包) 允许你将 Extensions、Skills、提示词模板和主题打包，通过 npm 或 git 进行分发和安装。

### 包管理命令

所有包操作都通过 pi 命令完成，无需手动编辑 settings.json。

| 命令 | 功能 | 示例 |
| --- | --- | --- |
| pi install <source> | 安装包，-l 参数安装为项目级 | pi install npm:@runoob/pi-todo-kit |
| pi remove <source> | 移除包 | pi remove npm:@runoob/pi-todo-kit |
| pi uninstall <source> | 同 remove | pi uninstall npm:@runoob/pi-todo-kit |
| pi list | 列出已安装的包 | pi list |
| pi update --all | 更新 Pi Agent 和所有包 | pi update --all |
| pi update --extensions | 仅更新已安装的包（不含 Pi Agent 本体） | pi update --extensions |
| pi update <source> | 更新指定包 | pi update npm:@runoob/pi-todo-kit |

使用示例：

```
# 安装 npm 包

$ pi install npm:@runoob/pi-todo-kit@1.0.0



# 安装 git 包

$ pi install git:github.com/runoob/pi-todo-kit@v1



# 安装本地包

$ pi install ./packages/pi-todo-kit

$ pi install ~/projects/pi-share-kit



# 安装为项目级（写入 .pi/settings.json）

$ pi install -l npm:@runoob/pi-todo-kit



# 临时试用包（不安装到配置中）

$ pi -e npm:@runoob/pi-todo-kit

$ pi -e git:github.com/runoob/pi-todo-kit
```

安装输出大致如下（示意），其中 extensions 和 skills 的数量取决于包的 pi 字段：

```
$ pi install npm:@runoob/pi-todo-kit

Resolving @runoob/pi-todo-kit@1.2.0

Downloading @runoob/pi-todo-kit (12.4 kB)

Running npm install in ~/.pi/agent/npm/@runoob/pi-todo-kit

Installed @runoob/pi-todo-kit@1.2.0

  extensions: 2

  skills:     1

  prompts:    3

Saved to ~/.pi/agent/settings.json
```

上述包名与版本都是示意值，实际使用时替换成你要安装的包即可。

### 包来源

Pi Agent 支持三种包来源，安装行为和缓存位置各不相同。

#### npm 包

npm 是推荐的包分发方式：

```bash
pi install npm:@scope/pkg@1.2.3

pi install npm:pkg
```

带版本号的 npm 包会被锁定，pi update 不会自动升级它们。

包安装位置：全局在~/.pi/agent/npm/，项目级在.pi/npm/。

#### Git 包

支持 HTTPS 和 SSH 协议：

```
# HTTPS

pi install https://github.com/user/repo@v1



# SSH（git@host:path 需要 git: 前缀）

pi install git:git@github.com:user/repo@v1



# SSH 协议

pi install ssh://git@github.com/user/repo@v1
```

Git 包的 ref 会被锁定，pi update 不会自动移动到新 ref。

克隆位置：全局在~/.pi/agent/git/，项目级在.pi/git/。

#### 本地路径

指向本地文件系统路径，不会复制文件：

```bash
pi install /Users/runoob/.pi/agent/packages/my-kit

pi install ./packages/my-kit
```

### 创建 Pi 包

在 package.json 中添加pi字段：

```json
{

  "name": "@runoob/pi-todo-kit",

  "keywords": ["pi-package"],

  "pi": {

    "extensions": ["./extensions"],

    "skills": ["./skills"],

    "prompts": ["./prompts"],

    "themes": ["./themes"],

    "video": "https://example.com/demo.mp4",

    "image": "https://example.com/screenshot.png"

  }

}
```

如果没有pi字段，Pi Agent 会自动从约定的目录中发现资源：

| 约定目录 | 加载内容 |
| --- | --- |
| extensions/ | 加载其中的 .ts 和 .js 文件 |
| skills/ | 递归查找包含 SKILL.md 的文件夹，同时把顶层的 .md 文件作为独立 Skill 加载 |
| prompts/ | 加载其中的 .md 模板文件 |
| themes/ | 加载其中的 .json 主题文件 |

### 包过滤

安装包时可以精确控制加载哪些资源，避免一次性带入全部内容。

下面的 packages 数组写入~/.pi/agent/settings.json（全局生效）或.pi/settings.json（仅当前项目生效）。

用 pi install -l 安装的包就是写进了项目的 .pi/settings.json，两种方式最终都落在同一份配置里。

数组条目支持两种写法：字符串形式加载该包的全部资源，对象形式按资源类型逐项过滤。

```json
{

  "packages": [

    "npm:simple-pkg",

    {

      "source": "npm:@runoob/pi-todo-kit",

      "extensions": ["extensions/*.ts", "!extensions/legacy.ts"],

      "skills": ["skills/brave-search"],

      "prompts": [],

      "themes": ["+themes/legacy.json"]

    }

  ]

}
```

官方文档中 skills 过滤既有按包内路径的写法，也有按技能名的写法，实际以所装包的说明为准。

过滤规则如下：

| 语法 | 含义 | 示例 |
| --- | --- | --- |
| 省略某个键 | 加载该类型的所有资源 | 不写 skills 键 = 加载全部 Skill |
| 设为 [] | 不加载该类型的任何资源 | "prompts": [] |
| !pattern | 排除匹配的资源 | "!extensions/legacy.ts" |
| +path | 强制包含指定路径 | "+themes/legacy.json" |
| -path | 强制排除指定路径 | "-skills/internal" |

### 依赖管理

Pi Agent 会为每个已安装的 npm/git 包执行npm install，自动安装依赖。

随包分发的本地依赖可用bundledDependencies打包。

以下核心包由 Pi Agent 自身提供，应列为peerDependencies，不要在包中重复打包：

| 包名 | 说明 |
| --- | --- |
| @earendil-works/pi-ai | AI 工具和类型 |
| @earendil-works/pi-agent-core | 代理核心 |
| @earendil-works/pi-coding-agent | Pi Agent 主包 |
| @earendil-works/pi-tui | TUI 组件 |
| typebox | 参数 Schema 定义 |

### pi config 管理资源

使用pi config交互式地启用或禁用已安装包的扩展、Skills、模板和主题：

```
# 编辑全局配置

$ pi config



# 编辑项目配置

$ pi config -l
```

Tab 键在全局和项目模式之间切换。

### 作用域与去重

同一个包可以同时出现在全局和项目配置中。

如果项目条目存在，它优先于全局条目。

例外是项目条目设置autoload: false时，不再整体覆盖，而是作为增量叠加到全局条目上。

包的身份由以下方式确定，Pi Agent 以此判断两条配置是否指向同一个包：

| 来源 | 身份标识 |
| --- | --- |
| npm 包 | 包名（如 @runoob/pi-todo-kit） |
| git 包 | 仓库 URL（不含 ref） |
| 本地路径 | 解析后的绝对路径 |

---

---

## 六、多平台部署要点 (Linux/macOS/Windows/Docker)

Pi Agent 支持在 Windows、macOS、Linux 和 Android（Termux）上运行。

本章介绍各平台的配置要点。

### macOS 配置

macOS 是 Pi Agent 的一等支持平台，大部分功能开箱即用。

#### 推荐终端

| 终端 | 安装方式 | 推荐理由 |
| --- | --- | --- |
| iTerm2 | brew install --cask iterm2 | 原生 True Color 支持，图片显示效果好，功能丰富 |
| Kitty | brew install --cask kitty | GPU 加速渲染，速度快 |
| Warp | brew install --cask warp | 现代化终端，AI 功能集成 |

#### 验证 True Color 支持

```
$ echo $COLORTERM

truecolor
```

#### Shell 别名

Pi Agent 在非交互模式下运行 bash（即bash -c）时，默认不会自动展开你的 Shell 别名。

核心机制：让 Pi 识别 Shell 别名若要在 Pi 中使用自定义别名，需将以下配置写入 ~/.pi/agent/settings.json（或 ~/.atomic/agent/settings.json）中，令其在启动时主动加载你的 Shell 配置文件（如 ~/.zshrc 或 ~/.bashrc）：

```json
{

  "shellCommandPrefix": "shopt -s expand_aliases\neval \"$(grep '^alias ' ~/.zshrc)\""

}
```

注意：请把路径 ~/.zshrc 改成你实际使用的 Shell 配置文件路径。

### Windows 配置

Windows 上可以通过原生终端或 WSL2 运行 Pi Agent，关键是选对终端并处理快捷键冲突。

#### 推荐安装方式

在 Windows 上推荐使用Windows Terminal配合 WSL2 或直接使用 Node.js。

#### 安装 Git for Windows

Pi 在 Windows 上默认使用 Git Bash 执行命令。

启动时会按顺序查找，其中就包括默认路径C:\Program Files\Git\bin\bash.exe。

如果没有安装 Git for Windows，启动时会找不到 bash，直接安装 Git for Windows 即可解决。

如果不想用 Git Bash，也可以通过shellPath配置指定其他 bash，或通过defaultTools改用 PowerShell 工具。

#### 安装 Node.js

从[nodejs.org](https://nodejs.org/)下载安装包，或使用 winget：

```
# PowerShell

> winget install OpenJS.NodeJS.LTS
```

#### 安装 Pi Agent

在 Windows Terminal 的 PowerShell 或 CMD 中执行：

```
# PowerShell

> npm install -g --ignore-scripts @earendil-works/pi-coding-agent
```

#### Windows 特有快捷键

| 功能 | Windows 快捷键 | macOS/Linux 快捷键 |
| --- | --- | --- |
| 粘贴图片 | Alt+V | Ctrl+V |
| 多行输入 | Ctrl+Enter | Shift+Enter |
| 发送跟进消息 | Ctrl+Q（发送）、Alt+Q（取回） | Alt+Enter |

Windows 默认用 Ctrl+Q 发送跟进消息、Alt+Q 取回排队消息，无需重映射。

想改用 Alt+Enter 才需要配置。

#### 挂起行为

Windows 原生终端不支持 Unix 的作业控制。

原生 Windows 上 Ctrl+Z 被绑定为编辑撤销，挂起需自行绑定一个快捷键。

WSL 下用 Alt+Z 挂起，Ctrl+Z 仍可挂起进程，配合 fg 恢复正常可用。

### Termux（Android）配置

Pi Agent 可以在 Android 设备上通过 Termux 运行。

#### 安装步骤

先安装 Termux 本体，请从 F-Droid 获取最新版安装包，再在 Termux 中执行下面的命令。

```
# 1. 更新包并安装 Node.js 和 termux-api 命令行工具
pkg update && pkg upgrade
pkg install nodejs termux-api

# 2. 安装 Pi Agent
npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# 3. 验证安装
pi --version

# 4. 首次使用共享存储前，先执行一次以授权访问下载目录等路径
termux-setup-storage
```

除了 Termux 本体，还需要在手机上安装 Termux:API 应用。

这个应用同样可以从 F-Droid 获取，剪贴板等设备集成能力都依赖它。

只安装 termux-api 命令行包而不装 Termux:API 应用，相关命令不会生效。

#### 注意事项

Termux 环境与常规 Linux 有差异，下面几点需要留意。

| 项目 | 说明 |
| --- | --- |
| 存储路径 | Termux 的存储访问路径与常规 Linux 不同，使用 ~/storage/shared/ 访问共享存储，首次使用前先执行 termux-setup-storage |
| 图片显示 | 部分终端的图片显示功能可能受限 |
| 剪贴板 | Termux 剪贴板集成仅支持文本，图片粘贴不可用 |
| 输入体验 | 建议使用蓝牙键盘或 OTG 键盘以获得更好的编辑体验 |

### tmux 集成

Pi Agent 可以在 tmux 会话中正常工作。

#### 优势

把 Pi Agent 放进 tmux，主要为了获得持久化和多窗口能力。

| 优势 | 说明 |
| --- | --- |
| 会话持久化 | 即使 SSH 断开，Pi Agent 仍在后台运行 |
| 多窗口布局 | 一个窗口运行 Pi Agent，另一个窗口查看代码 |
| 远程开发 | SSH 到服务器后使用 Pi Agent |

#### 推荐配置

在 ~/.tmux.conf 中添加：

```
# 文件路径：~/.tmux.conf
# 确保 True Color 支持
set -g default-terminal "tmux-256color"
set -ag terminal-overrides ",*:Tc"

# 开启扩展键上报并以 CSI-u 格式转发组合键
# 缺了这两行，tmux 里 Shift+Enter 会退化成普通回车
set -g extended-keys on
set -g extended-keys-format csi-u

# 增大回滚缓冲区（查看大量 AI 输出时有用）
set -g history-limit 50000
```

其中 extended-keys 两行是关键配置，作用是让 Shift+Enter、Ctrl+Enter 等组合键正确传入 pi。

extended-keys-format csi-u 需要 tmux 3.5 或更高版本，可用tmux -V查看版本。

```
$ tmux -V

tmux 3.5a
```

### 终端设置优化

无论使用哪个终端，下面几项设置都会直接影响 Pi Agent 的显示效果。

| 设置项 | 建议值 | 说明 |
| --- | --- | --- |
| True Color | 启用 | 确保终端支持 24 位色彩 |
| 字体 | 等宽字体（如 JetBrains Mono、Fira Code） | 确保代码对齐和特殊字符显示 |
| 回滚缓冲区 | 至少 10000 行 | 查看大量 AI 输出和历史消息 |
| VS Code 终端 | 设置 minimumContrastRatio 为 1 | 确保主题颜色准确渲染 |

#### VS Code 集成终端配置

在 VS Code 的 settings.json 中添加以下配置，文件路径为~/Library/Application Support/Code/User/settings.json（macOS）：

```json
{

  "terminal.integrated.minimumContrastRatio": 1,

  "terminal.integrated.fontFamily": "JetBrains Mono",

  "terminal.integrated.fontSize": 13

}
```

### Shell 别名建议

以下是一套完整的 Pi Agent 别名，各平台通用，可添加到 ~/.zshrc、~/.bashrc 或等效的 shell 配置文件中：

```
# 文件路径：~/.zshrc（bash 用户为 ~/.bashrc）
# Pi Agent 常用别名
alias pin='pi --name'           # 命名会话启动
alias pic='pi -c'               # 继续最近会话
alias pir='pi -r'               # 恢复历史会话
alias piq='pi -p'               # 快速一次性问答
alias pip='pi --print'          # Print 模式（同 -p）
alias pif='pi --fork'           # 分叉会话
alias pii='pi --no-session'     # 临时模式（不保存）
alias piro='pi --tools read,grep,find,ls'  # 只读模式
alias pirev='pi -p "审查暂存的代码变更（git diff --cached）"'
```

如果你使用 fish shell，将 alias 改为 abbr 或使用 fish 的 alias 语法。

```
# fish shell 使用 abbr 定义缩写

abbr -a pic pi -c
```

---

---

## 七、本地私有化模型：对接 llama.cpp (GGUF)

Pi Agent 内置了对 llama.cpp 的支持，让你可以在本地运行开源大模型，无需云端 API。

### 什么是 llama.cpp

llama.cpp 是一个高性能的 LLM 推理引擎，可以在消费级硬件上运行开源大语言模型。

它支持 CPU 推理（通过量化技术大幅降低内存需求）和 GPU 加速（CUDA、Metal、Vulkan 等）。

Pi Agent 通过llama.cpp 路由器服务器与本地模型通信。

### 配置 llama.cpp

配置分三步：先启动 llama-server 路由器，再注册 llama.cpp 提供商，最后加载并选择模型。

#### 启动 llama-server 路由器

不带-m或--model参数启动 llama-server，就会进入路由器模式。

一旦传了模型参数，llama-server 会进入单模型模式，不再扫描模型目录。

路由器会按需加载或卸载--models-dir目录下的 GGUF 模型，常用参数有 --models-dir（模型目录）、--no-models-autoload（关闭自动加载）、--jinja（启用对话模板与工具调用支持）、-ngl（卸载到 GPU 的层数）和 -c 32768（每个模型的上下文窗口）。

```
llama-server \

  --models-dir ~/models \

  --no-models-autoload \

  --jinja \

  --host 127.0.0.1 \

  --port 8080 \

  -ngl 999 \

  -c 32768
```

启动后可以用 /health 与 /models 两个接口自检路由器是否可达、模型是否被发现。

#### 登录 llama.cpp

在 Pi Agent 交互模式中：

```
/login llama.cpp
```

此步仅注册本地提供商，无需账号鉴权，但需要填写路由器地址（默认 http://127.0.0.1:8080）。

执行后 Pi 会要求填写路由器 URL 与可选的 API Key，本地服务通常把 API Key 留空即可。

#### 管理本地模型

使用/llama命令打开模型管理菜单：

```
/llama
```

在菜单中选中一个未加载的模型并回车，就会把它加载进内存。

选中一个已加载的模型并回车，则会把它卸载。

选择菜单项Download model...可以搜索 Hugging Face 并下载新模型，加载或下载过程中按 Escape 可确认取消。

菜单始终显示路由器当前的真实状态，而只有已加载的模型才会出现在 /model 选择器里。

#### 切换到本地模型

使用/model命令选择已加载的本地模型。

快捷键方面，Ctrl+L 打开模型选择器，Ctrl+P 在模型间循环切换。

### 推荐的开源模型

以下是一些适合本地运行的开源编码模型：

| 模型 | 参数量 | 最低显存/内存 | 适用场景 |
| --- | --- | --- | --- |
| Qwen 2.5 Coder | 7B / 14B / 32B | 8G / 16G / 32G | 通用编码、多语言 |
| DeepSeek Coder V2 | 16B / 236B | 16G / 128G+ | 复杂编程任务 |
| CodeLlama | 7B / 13B / 34B | 8G / 16G / 32G | 代码补全、通用编码 |
| Mistral | 7B | 8G | 轻量级编码助手 |

### 模型存储

模型目录由 llama-server 启动参数--models-dir决定（如 ~/models），模型下载也由 llama.cpp 服务端执行。

模型文件通常较大（几 GB 到几十 GB），请确保该目录有足够的磁盘空间。

### 自定义 llama.cpp 服务器

如果你的 llama.cpp 服务器运行在非默认端口或远程机器上，有两种接入方式。

零代码方式是设置环境变量LLAMA_BASE_URL与LLAMA_API_KEY指向自定义 llama.cpp 服务器，无需写扩展，也不用 /login。

```bash
export LLAMA_BASE_URL=http://192.168.1.20:8080

export LLAMA_API_KEY=optional-secret

pi
```

若服务器启用了 API Key，llama-server 启动时要带上相同的 --api-key 值，并保留 --host 127.0.0.1 以限制本机访问。

只需接入 OpenAI 兼容 API 时，models.json 方式更简单，见《接入 DeepSeek》一章；需要完整控制请求流程时才用扩展方式。

在扩展中注册 llama.cpp 提供商：

```
// 文件路径：~/.pi/agent/extensions/llamacpp-provider.ts
pi.registerProvider("llama.cpp", {
  name: "本地 llama.cpp",
  baseUrl: "http://localhost:8080/v1",
  apiKey: "local",
  api: "openai-completions",
  // 动态发现已加载的模型
  async refreshModels({ signal }) {
    const response = await fetch(
      "http://localhost:8080/v1/models",
      { signal }
    );
    const { data } = await response.json();
    return data.map(({ id }) => ({
      id,
      name: id,
      reasoning: false,
      input: ["text"],
      cost: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
      },
      contextWindow: 128000,
      maxTokens: 16384,
    }));
  },
});
```

这个动态发现模式让 Pi Agent 能实时获取 llama.cpp 服务器上当前已加载的模型列表。

把文件保存到 ~/.pi/agent/extensions/ 目录并重启 Pi Agent，扩展会自动加载并注册这个提供商。

生效后打开 /model 选择器，就能看到 llama.cpp 服务器上当前已加载的模型并直接对话。

### 本地模型的局限性

使用本地模型时需要注意以下几点：

- 工具调用能力：部分开源模型的工具调用（tool calling）能力较弱，可能无法正确使用 Pi Agent 的内置工具
- 推理速度：在没有 GPU 加速的情况下，推理速度可能较慢
- 上下文长度：本地模型的有效上下文窗口通常小于云端模型
- 推理等级：非推理型模型始终以 off 运行，无法使用推理等级功能

工具调用能力弱时，最常见的表现是模型把工具调用当成文字输出，而不是真正触发工具。

```python
> 查看 src/index.ts 的内容



好的，下面是 src/index.ts 的内容：

import { createAgent } from "pi";

export const agent = createAgent();

...
```

消息区域没有出现工具调用卡片，说明模型并没有真正调用 read 工具，而是在自己编造文件内容。

遇到这种情况可以换用工具调用支持更好的模型，或者把任务拆成更小的步骤。

---

---

