# 板块 04：二次开发与集成 (Guides - Build on Pi)

本板块是面向高级开发者与系统集成的核心指南，详细阐述 Extension 插件系统、自定义 Provider、虚拟模型路由、终端 UI 组件、CLI 进程管道与 Pi SDK。

---

## 包含文档清单

| 序号 | 官方文件名 | 中文标题 | 核心内容概述 |
|:---:|:---|:---|:---|
| 01 | [extensions.md](extensions.md) | **Extension 扩展开发 (Extensions)** | 扩展生命周期、事件钩子（Hooks）、自定义工具定义、拦截与修改输入输出。 |
| 02 | [custom-provider.md](custom-provider.md) | **自定义 Provider (Custom Provider)** | 对接第三方 LLM API、实现自定义鉴权、模型格式转换与流式响应处理。 |
| 03 | [virtual-models.md](virtual-models.md) | **虚拟模型路由 (Virtual Models)** | 构建智能路由规则、成本与速率智能分流、主备模型自动降级（Fallback）。 |
| 04 | [tui.md](tui.md) | **终端 UI 组件开发 (TUI Components)** | 自定义终端渲染组件、Overlay 浮层弹窗、状态栏扩展与交互控件。 |
| 05 | [cli-integration.md](cli-integration.md) | **CLI 命令行进程集成 (CLI Integration)** | 管道流式输入输出、子进程通信、无头自动化脚本与批处理任务。 |
| 06 | [sdk.md](sdk.md) | **Pi SDK 核心开发指南 (Pi SDK)** | `@earendil-works/pi-coding-agent` SDK API、编程式操控 AgentSession、事件监听。 |

---

## 关键集成模式对比

| 集成模式 | 适用场景 | 交互机制 | 典型案例 |
|:---|:---|:---|:---|
| **Extension 插件** | 增强终端交互、添加本地工具 | 进程内 Hook、事件总线 | Plan 模式、Git 自动检查点、自定义工具 |
| **Pi SDK** | 嵌入已有 Node/TypeScript 服务端 | 强类型接口、直接操控 Session 运行时 | Web 后端、工作流编排引擎、CI/CD 自动化 |
| **CLI 管道 / RPC** | 跨语言外部调用 (Python/Go/Rust) | JSON-RPC 2.0 / 逐行 JSONL 事件流 | 外部 IDE 插件、无头执行代理、自动化评估 |

---

## 官方示例代码库
在 [`../examples/`](../examples/) 目录下提供了大量高质量官方示例：
- [`../examples/extensions/`](../examples/extensions/)：包含 Plan 模式、自定义工具、状态栏、Doom 终端小游戏等 40+ 插件范例；
- [`../examples/sdk/`](../examples/sdk/)：从 01 到 14 渐进式 SDK 实战（从最小启动到完整控制流与 Codemode MCP）。

---

## 快速导航
- 返回 [文档总目录](../README.md)
- 上一步：[03-定制与配置指南](../03-定制与配置指南/README.md)
- 下一步：[05-参考手册与底层规范](../05-参考手册与底层规范/README.md)
