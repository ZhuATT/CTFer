# CTFer

> 基于 Claude Code 的自动化 CTF Web 安全解题框架。

## 项目概述

CTFer是一个基于claudecode的直接模式解题框架，全自动解题，以ClaudeCode作为主agent，解题过程中能在终端中与agent交互。

## 基于 Claude Code的局限

以claudecode作为主agent，最大的问题是攻击过程一长，AI不会严格按照框架设计的流程解题，利用工具和知识，重复的去尝试相同的几种方法，所以在关键节点引入独立视角审查，减少主 Agent 陷入思维定式和幻觉。受限于 Claude Code 的 API 和工具集，灵活性不如 LangGraph 的图编排，状态管理也需自己实现。但是可以直接利用 Claude Code 内置强大的上下文窗口管理和工具调用机制。

目录结构

```
D:/CC_CTFer/
├── CLAUDE.md              ← LLM 指令（解题流程规范）
├── config.json            ← 配置文件
│
├── core/                  ← 核心模块
│   ├── state_manager.py   # 状态管理
│   ├── rag_knowledge.py   # RAG v2.0 检索
│   ├── experience_manager.py # 经验管理
│   ├── failure_tracker.py # 失败追踪
│   ├── loop_detector.py   # 循环检测
│   ├── phase_gate.py      # 阶段门口
│   ├── advisor.py         # 顾问审查
│   ├── llm_client.py     # LLM 客户端
│   └── skill_loader.py    # Skill 加载
│
├── skills/                ← 技能知识库 (14 个题型)
│   └── <type>/SKILL.md
│
├── memories/             ← 经验积累
│   └── experiences/      # 成功经验 (6 个题型)
│       └── *.md
│
├── knowledge_base/        ← 外部知识库
│   ├── wooyun/           # WooYun 技术手册
│   ├── h-pentest/        # H-Pentest 攻击库
│   └── PayloadsAllTheThings/ # PATT
│
├── rag_index/             ← RAG v2.0 持久化索引
│   ├── manifest.json
│   └── kb_store.json
│
├── tools/                 ← 工具封装
│   ├── curl_tool.py
│   ├── sqlmap_tool.py
│   ├── dirsearch_tool.py
│   └── output_parser.py
│
├── workspace/             ← 工作目录
│   ├── state.json         # 当前状态
│   ├── failures.json     # 失败记录
│   └── advisor/           # 顾问建议
│
└── .claude/              ← Claude Code 配置
    ├── settings.json      # Hook 配置
    └── hooks/
        ├── check_knowledge_hook.py  # PreToolUse
        └── save_command_hook.py    # PostToolUse
```

| 特性                  | 说明                                           |
| --------------------- | ---------------------------------------------- |
| **RAG v2.0 知识检索** | BM25 + RRF 融合，持久化索引，增量更新          |
| **阶段化攻击流程**    | Recon → Identify → Exploit → Flag              |
| **Hook 自动检查**     | 假设声明、方法失败、预算、语义循环等多维度检查 |
| **失败追踪**          | 自动记录失败方法，避免重复尝试                 |
| **经验积累**          | 自动保存成功经验到 experiences/                |

## 阶段化攻击流程

```
Recon ────► Identify ────► Exploit ────► Flag
(侦察)        (识别)         (攻击)      
```

## Hook 自动检查机制

针对主agent的幻觉和丢失上下文问题，使用Claude Code简洁的hook机制
 settings.json 配置即可生效
 并且在关键节点引入独立视角审查，减少主 Agent 陷入思维定式和幻觉
 参考 CHYing-agent 的双 Agent 架构（顾问 + 主攻手），将当前项目中的"隐性顾问"显式化，同时整合现有的 `get_context_summary_intelligent` 和 `analyze_failure_with_llm`，形成统一的建议层

| 检查项     | 触发条件                | 动作     |
| ---------- | ----------------------- | -------- |
| 假设声明   | Identify/Exploit 未声明 | **拦截** |
| 方法失败   | 方法在 failures.json    | 警告     |
| 预算耗尽   | step_count ≥ budget     | 警告     |
| 工具白名单 | 工具不在允许列表        | **拦截** |
| 语义循环   | 同一动作家族 ≥3 次      | 警告     |
| 失败阈值   | 同一目标 ≥3 次失败      | 强制重查 |
| 签名循环   | 相同签名 ≥5 次          | **拦截** |

### PostToolUse 自动记录

攻击完成后自动：

1. `add_method()` — 记录已使用方法
2. `increment_step()` — 更新阶段步数
3. `record_failure()` — 失败时自动写入 failures.json

### 顾问审查时机

| 时机              | 触发方式      | 调用函数                             | 说明                        |
| ----------------- | ------------- | ------------------------------------ | --------------------------- |
| 任务开始          | Hook 自动     | `advisor.review("initial")`          | 第一次工具执行时触发        |
| 连续失败 3/6/9 次 | Hook 自动     | `advisor.review("post_failure")`     | PostToolUse 检测失败次数    |
| 定期（每5次尝试） | Hook 自动     | `advisor.review("periodic")`         | PostToolUse 更新 step_count |
| 阶段转换          | 主 Agent 调用 | `advisor.review("phase_transition")` | `try_set_phase()` 前调用    |
| 主动求助          | 主 Agent 调用 | `advisor.ask(question)`              | 任何时候可调用              |

## 使用

### 克隆仓库

```
git clone https://github.com/ZhuATT/CTFer.git
```

### 虚拟环境

 创建虚拟环境，这样更加轻量化

- Python 3.10+

```
你的python解释器路径   -m venv C:\Users\Administrator\Envs\CTFagent
目前只用到了Python 标准库，后续配置的工具的依赖再根据需要下载
```

### 配置API

适配openai和Anthropic

```
编辑config.example.json
重命名为config.json
```

### CLAUDE.md

CLAUDE.md 是 Claude Code 的系统级项目指令文件，每次对话开始时都会自动加载到上下文中
 这个文件在这个模式下一定程度影响解题的流程。仓库中的为示例，可以按照需要自己修改

### Hooks 使用

在 Claude Code 的 `settings.json` 中添加

```
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

## 下一步计划

重构工具系统，现有工具封装太过简易，无统一管理，没有参数说明、返回值格式、示例

RAG知识库升级    Dense Embedding   Cross-encoder Rerank，让顾问按需加载漏洞知识库，不是一次性塞给主 Agent

优化经验保存机制，保存解题记录，构建一个反思系统

支持多 Agent 协作...



## 参考项目

[hexian2001/H-Pentest: 🔐 H-Pentest v2.0 🥷 AI-Powered Penetration Testing Platform](https://github.com/hexian2001/H-Pentest)

https://github.com/MuWinds/BUUCTF_Agent

https://github.com/SanMuzZzZz/LuaN1aoAgent

https://github.com/yhy0/CHYing-agent
