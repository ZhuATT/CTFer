# 板块 02：运行与环境指南 (Guides - Run Pi)

本板块深入讲解 Pi 在各种终端、操作系统、隔离沙箱以及本地模型环境下的运行与配置方案。

---

## 包含文档清单

| 序号 | 官方文件名 | 中文标题 | 核心内容概述 |
|:---:|:---|:---|:---|
| 01 | [usage.md](usage.md) | **终端使用指南 (Usage)** | 交互式终端日常使用、多行编辑、状态栏指示器、思考过程折叠与展开。 |
| 02 | [models.md](models.md) | **模型选择与配置 (Models)** | 切换主模型、思考模型、分类器模型、图像模型，配置上下文长度与推理参数。 |
| 03 | [sessions.md](sessions.md) | **会话与上下文管理 (Sessions)** | 会话历史回溯、树状分支导航、分支克隆、会话导出与恢复。 |
| 04 | [security.md](security.md) | **安全与权限机制 (Security)** | 项目信任机制（Trust Manager）、敏感操作二次确认、路径访问防护策略。 |
| 05 | [containerization.md](containerization.md) | **容器化与沙箱隔离 (Containerization)** | Docker 与容器内运行方案、无特权环境限制、文件系统挂载与网络隔离。 |
| 06 | [llama-cpp.md](llama-cpp.md) | **本地模型 llama.cpp (llama.cpp)** | llama.cpp 部署对接、GGUF 本地推理、完全离线私有化运行。 |
| 07 | [nvidia-rtx-llama-cpp.md](nvidia-rtx-llama-cpp.md) | **NVIDIA RTX 显卡优化 (RTX Acceleration)** | 专为 NVIDIA GeForce RTX 优化的 llama.cpp 加速部署指南。 |
| 08 | [terminal-setup.md](terminal-setup.md) | **终端环境与字体配置 (Terminal Setup)** | 解决中文对齐、真彩色支持、Nerd Fonts 字体安装、终端重绘优化。 |
| 09 | [shell-aliases.md](shell-aliases.md) | **Shell 别名与快捷命令 (Shell Aliases)** | Bash / Zsh / Fish 下的常用 alias 配置与工作流提效脚本。 |
| 10 | [tmux.md](tmux.md) | **tmux 集成与多窗格 (tmux)** | tmux 环境下的快捷键防冲突配置、窗格拆分与后台会话持久化。 |
| 11 | [windows.md](windows.md) | **Windows 平台运行指南 (Windows)** | Windows Terminal、PowerShell、CMD 以及 WSL2 环境适配说明。 |
| 12 | [termux.md](termux.md) | **Android Termux 运行 (Termux)** | 在 Android 设备上通过 Termux 部署和运行 Pi 的完整指南。 |

---

## 典型使用场景速查

### 1. 切换与选择模型
```bash
# 启动时指定模型
pi --model anthropic/claude-3-7-sonnet-20250219

# 交互界面中切换
/model deepseek/deepseek-chat
```

### 2. 会话分支与树状回溯
在交互界面中按下快捷键或使用 `/tree` 查看当前会话分支树，支持在任意历史节点分叉尝试不同代码实现，而无需丢失原有进度。

### 3. 项目信任机制
初次在未知项目目录下启动时，Pi 会提示确认是否信任该项目。信任后才会允许自动执行项目内的扩展与配置文件。

---

## 快速导航
- 返回 [文档总目录](../README.md)
- 上一步：[01-入门与架构](../01-入门与架构/README.md)
- 下一步：[03-定制与配置指南](../03-定制与配置指南/README.md)
