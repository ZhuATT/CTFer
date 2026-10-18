# 板块 06：社区实践与进阶配置 (Community Best Practices)

本板块汇聚全球与国内一线全栈极客在生产环境中重度使用 Pi 的实战经验、深度配置模型与最佳工程实践。

---

## 包含文档清单

| 序号 | 文件名 | 标题与作者 | 核心内容概述 |
|:---:|:---|:---|:---|
| 01 | [pi-agent-configuration-guide.md](pi-agent-configuration-guide.md) | **Pi Agent 配置进阶：AGENTS.md、模型切换与 Thinking Level 实战指南**<br>*（火炬树 / Cyber Herald）* | 深入剖析 Pi 的 5 层配置体系、`settings.json` 高阶字段（压缩、重试、预算）、`models.json` 自定义模型（Ollama/OpenRouter/代理）、Thinking 深度调优及可直接投产的完整配置模板。 |
| 02 | [deepakness-pi-agent-setup.md](deepakness-pi-agent-setup.md) | **实战案例：配置并日常使用 Pi 终端编程 Agent**<br>*（DeepakNess 深度长文全译）* | 揭秘如何将 Pi 搭配 DeepSeek 打造为主力开发工具（Daily Driver）、自制极简底栏插件（Minimal Footer）、跨模型视觉接力（Vision Handoff）、以及以 $1 美元完成 28.5 万 URL 批量任务的真实案例。 |
| 03 | [菜鸟教程-Pi-Agent中文入门实战教程/](./菜鸟教程-Pi-Agent中文入门实战教程/README.md) | **菜鸟教程：Pi Agent 中文入门与实战指南（五大精选板块）**<br>*（RUNOOB.COM 全量整合）* | 专为国内开发者打造的保姆级入门教材。已摒弃碎片化小文件，深度整合为 **5 篇高信息密度专篇**：涵盖核心概念与 DeepSeek 极速接入、交互会话与 `/tree` 会话树、提示词模板与 Skills 规范、自定义工具开发（TypeBox 实战）及国内网络与环境避坑手册。 |

---

## 核心实战经验速览

### 1. 配置层级与优先级法则
Pi 的配置文件采用层层叠加设计，优先级自高到低严格执行：
```
1. APPEND_SYSTEM.md (~/.pi/agent/APPEND_SYSTEM.md) —— 追加到 System Prompt 最末尾，具有最高权威
2. 项目级 .pi/settings.json                         —— 覆盖当前项目的运行参数（深度对象合并）
3. 项目级 AGENTS.md (./AGENTS.md)                  —— 当前项目技术栈规范与业务上下文
4. 父级目录递归 AGENTS.md                           —— 向上冒泡继承通用架构规则
5. 全局 AGENTS.md (~/.pi/agent/AGENTS.md)          —— 开发者通用的技术栈偏好（兜底）
6. 全局 settings.json (~/.pi/agent/settings.json)  —— 全局基础设置
```

### 2. 性价比与能力分层模型矩阵
综合社区最佳实践，建议建立分层调用机制：
- **微任务 / 批量脚本**：`DeepSeek V4 Flash` / `MiniMax M2.7`，Thinking 设为 `low` 或 `off`，极致节省 Token；
- **主力日常编码**：`DeepSeek V4 Pro` / `Qwen 2.5 Coder`，Thinking 设为 `medium`（80% 场景的黄金平衡点）；
- **复杂疑难 Debug / 架构设计**：`Claude 3.7 Sonnet` / `Grok 4.6`，Thinking 设为 `high` 或 `max`；
- **视觉多模态**：通过 `pi-vision-handoff` 插件，让任何纯文本模型通过轻量视觉模型接力读图。

---

## 快速导航
- 返回 [文档总目录](../README.md)
- 上一步：[05-参考手册与底层规范](../05-参考手册与底层规范/README.md)
