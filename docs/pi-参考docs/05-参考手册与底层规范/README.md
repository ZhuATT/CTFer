# 板块 05：参考手册与底层规范 (Reference)

本板块是 Pi Agent 的权威底层技术参考手册，涵盖 CLI 参数规范、配置文件 Schema、会话存储格式、通信协议与数据结构定义。

---

## 包含文档清单

| 序号 | 官方文件名 | 中文标题 | 核心内容概述 |
|:---:|:---|:---|:---|
| 01 | [cli.md](cli.md) | **CLI 命令行参数全集 (CLI)** | 完整命令行选项、标志位（Flags）、子命令与参数速查手册。 |
| 02 | [codemode.md](codemode.md) | **Codemode 模式规范 (Codemode)** | 代码编写专用模式规范、上下文隔离与代码生成约束。 |
| 03 | [slash-commands.md](slash-commands.md) | **斜杠命令全集 (Slash Commands)** | 内置斜杠命令清单（`/help`, `/model`, `/compact`, `/tree` 等）及其语法。 |
| 04 | [settings.md](settings.md) | **Settings 配置规范 (Settings)** | 全局配置项字段列表、类型约束、默认值与配置 Schema。 |
| 05 | [models-configuration.md](models-configuration.md) | **Models 配置规范 (Models Configuration)** | `models.json` 模型与 Provider 配置全量字段、API 兼容性表格与 Schema 字典。 |
| 06 | [environment-variables.md](environment-variables.md) | **环境变量清单 (Environment Variables)** | 控制 Pi 运行行为的所有环境变量及其生效说明。 |
| 07 | [keybindings.md](keybindings.md) | **键盘快捷键映射 (Keybindings)** | 快捷键配置定义、按键绑定语法、跨平台键位与冲突处理。 |
| 08 | [providers.md](providers.md) | **模型 Provider 规范 (Providers)** | 官方内置 Provider（Anthropic, OpenAI, DeepSeek 等）及模型名称对应表。 |
| 09 | [session-format.md](session-format.md) | **会话文件存储格式 (Session Format)** | JSONL 会话持久化结构、Entry 节点定义、树状 parentId 关系机制。 |
| 10 | [compaction.md](compaction.md) | **上下文压缩与总结算法 (Compaction)** | 自动压缩触发策略、分支总结生成、保留关键上下文算法与扩展。 |
| 11 | [json.md](json.md) | **JSON 事件流协议 (JSON Event Stream)** | 流式标准输出中的逐行 JSON 事件格式与报文解析。 |
| 12 | [rpc.md](rpc.md) | **RPC 协议总规范 (RPC Protocol)** | 基于 Stdio 的 JSON-RPC 通信规范、连接生命周期与请求应答机制。 |
| 13 | [rpc-commands.md](rpc-commands.md) | **RPC 命令手册 (RPC Commands)** | 全量 RPC 方法、输入参数、返回值与错误码字典。 |
| 14 | [rpc-extension-ui.md](rpc-extension-ui.md) | **RPC 扩展界面协议 (RPC Extension UI)** | RPC 模式下的自定义扩展 UI 协议、交互式提示与前端渲染规范。 |
| 15 | [message-types.md](message-types.md) | **核心消息类型定义 (Message Types)** | 内部数据结构 `UserMessage`, `AssistantMessage`, `ToolCall`, `ToolResult` 规范。 |

---

## 核心协议速览

### 1. 会话持久化格式 (JSONL)
每一个 session 文件包含逐行追加的 JSON 数据，主要节点包括：
- `session_start`：会话元数据（ID、时间戳、工作目录、根分支）；
- `message`：用户或模型的消息；
- `tool_call` 与 `tool_result`：工具执行记录与返回结果；
- `compaction`：会话上下文压缩事件及生成的摘要；
- `branch_summary`：分支合并或分支切出时的总结节点。

### 2. JSON-RPC 与无头模式
通过 `pi --rpc` 启动守护进程，外部宿主环境可通过 Stdio 管道使用标准的 JSON-RPC 发送命令，例如：
- `prompt`：发起一轮交互提示；
- `get_state`：获取当前上下文、模型与工具列表；
- `abort`：中断正在执行的生成或工具调用；
- `switch_session`：切换或分叉会话。

---

## 快速导航
- 返回 [文档总目录](../README.md)
- 上一步：[04-二次开发与集成](../04-二次开发与集成/README.md)
