# 板块 03：定制与配置指南 (Guides - Customize Pi)

本板块介绍如何深度定制 Pi，包括全局与项目级配置、提示词模板、Skills 技能机制、UI 主题、Pi 软件包以及 MCP 服务器连接。

---

## 包含文档清单

| 序号 | 官方文件名 | 中文标题 | 核心内容概述 |
|:---:|:---|:---|:---|
| 01 | [configuration.md](configuration.md) | **配置系统 (Configuration)** | 配置层级结构、全局配置 `~/.pi/config` 与项目配置 `.pi/` 的合并策略。 |
| 02 | [prompt-templates.md](prompt-templates.md) | **提示词模板 (Prompt Templates)** | 提示词模版定义、系统提示词覆盖、动态占位符注入与多场景定制。 |
| 03 | [skills.md](skills.md) | **Skills 技能系统 (Skills)** | 声明式技能定义、按条件动态激活技能、注入领域专项规则与知识库。 |
| 04 | [themes.md](themes.md) | **主题与视觉定制 (Themes)** | 定制终端配色方案、语法高亮主题、状态指示器颜色与图标定制。 |
| 05 | [packages.md](packages.md) | **Pi 软件包体系 (Pi Packages)** | 跨项目共享与分发扩展、技能与主题的 npm / git 封装包机制。 |
| 06 | [mcp.md](mcp.md) | **MCP 协议与服务连接 (MCP)** | Model Context Protocol 服务器集成、外部工具动态发现、权限与曝光控制。 |

---

## 核心机制详解

### 1. 提示词与技能注入机制
- **Prompt Templates**：允许针对不同任务类型（如 `review`, `refactor`, `explain`）定义预设模版；
- **Skills**：将专业知识（如特定框架规范、渗透测试攻击链、测试编写标准）封装在 Markdown 文件中，并在 Agent 判定需要时动态加载到当前上下文中，避免无谓占用上下文窗口。

### 2. MCP (Model Context Protocol)
通过集成 MCP，Pi 可以直接桥接外部生态系统（如 PostgreSQL 数据库、GitHub API、外部爬虫或自定义服务端）：
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed"]
    }
  }
}
```

---

## 快速导航
- 返回 [文档总目录](../README.md)
- 上一步：[02-运行与环境指南](../02-运行与环境指南/README.md)
- 下一步：[04-二次开发与集成](../04-二次开发与集成/README.md)
