# Hooks 使用说明

## 文件说明

| 文件 | 用途 |
|------|------|
| `check_knowledge_hook.py` | PreToolUse Hook - 检查假设声明、预算、阶段等 |
| `save_command_hook.py` | PostToolUse Hook - 自动保存命令结果 |
| `check_knowledge_hook.sh` | Bash 备用版本 |

## 配置方法

### 1. Claude Code 配置

在 Claude Code 的 `settings.json` 中添加：

```json
{
  "hooks": {
    "PreToolUse": {
      "command": "python hooks/check_knowledge_hook.py"
    },
    "PostToolUse": {
      "command": "python hooks/save_command_hook.py"
    }
  }
}
```



## Hook 功能

### check_knowledge_hook.py

- **假设声明检查**: Identify/Exploit 阶段必须声明假设
- **预算检查**: 每阶段有步数限制（Recon 10步, Identify 15步, Exploit 20步）
- **阶段工具白名单**: 限制各阶段可用工具
- **循环检测**: 防止重复执行相同命令

### save_command_hook.py

- 自动记录每次命令的输入、输出、返回码
- 供下次 PreToolUse 读取并注入上下文





依赖 `core/` 目录下的模块（state_manager.py, phase_gate.py 等）

工作目录需要 `workspace/` 文件夹存放状态文件
