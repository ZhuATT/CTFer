# Changelog

本文件记录 **LuaN1aoAgent** 的所有重要变更，遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 规范。

---

## [Unreleased]

_下一版本的变更将在此处汇总。_

---

## [0.6.0] — 2026-03-09

### 修复
- **core**: 修复 `rich` 库因解析特殊字符（如 `[/]`）而导致崩溃的问题 (`bf51e6f`)

---

## [0.5.0] — 2026-03-08

### 新增
- **core**: 添加工具超时配置、共享公告板（Shared Bulletin Board）功能及活跃假设支持 (`42975d5`)
- **rag**: 添加重叠块（Chunk Overlap）功能，提升检索召回率 (`6d38528`)

### 优化
- **arch/prompts/docs**: 整体架构、提示词与 README 全面优化 (`c2bfe38`)

---

## [0.4.0] — 2026-03-07

### 新增
- **prompts**: 更新提示词内容 (`6e69331`)
- **prompts/core**: 添加 CTF 特化优化与关注点，更新相关模板内容，优化节点类型和执行原则描述 (`cf9a4a9`)
- **core**: 添加子任务 ID 支持，优化因果图命令处理和节点更新时间逻辑 (`402c87f`)
- **web**: 更新审计状态显示逻辑，优化状态颜色处理，支持更多状态值 (`362a7b9`)
- **core/web**: 更新任务状态管理，添加新的审计状态和配置选项，优化前端显示和后端逻辑 (`7a741a1`)

---

## [0.3.0] — 2026-03-06

### 修复
- **agent**: 优化进程终止逻辑，添加任务状态管理，更新前端任务状态显示 (`7843018`)

---

## [0.2.0] — 2026-02-28

### 新增
- **prompts/core**: 添加 Executor 与 Planner 模板，包含详细 Schema 和渗透测试工作流原则 (`fd682fb`)

### 修复
- **data**: 修复数据 Bug (`cc575f4`, `d9cb922`)

### 文档
- **readme**: 修复 Showcase 链接格式 (`1c296ae`, `6a49a5d`)

---

## [0.1.0] — 2026-02-26

### 新增
- **core/tools**: 增强工具链、资源治理与认知推理框架 (`3a590bc`)

---

## [0.0.9] — 2026-01-15

### 修复
- **rag**: 修复相对导入失败时的路径查找问题 (`9b14ad2`)
- **tools**: 修复 `LLMClient` 导入失败的兼容性问题（双重修复提交） (`6a1d068`, `cd4ac83`)

---

## [0.0.8] — 2026-01-13

### 新增
- **web**: 添加左右侧边栏折叠功能 (`8328ee6`)

### 修复
- **web**: 修复 LLM 返回内容包含 HTML 标签导致的 XSS 问题（来自 PR #1） (`a1cf830`)

---

## [0.0.7] — 2026-01-12

### 修复
- **app**: 支持折叠根节点及执行链节点 (`7ee7cee`)

### 文档
- **readme**: 更新安装步骤并移除过时链接 (`b9cf3dc`)

---

## [0.0.6] — 2026-01-08

### 新增
- **server**: 添加操作日志记录功能 (`a365535`)
- **agent**: 增加会话状态更新和错误处理 (`3c90d22`)
- **model**: 添加会话自定义排序字段 (`b280775`)

### 构建
- 添加项目依赖声明 (`f5de209`)

---

## [0.0.5] — 2026-01-06

### 新增
- **web**: 优化任务管理与渲染，支持任务重命名和排序 (`8959f8e`)

---

## [0.0.4] — 2025-12-28

### 文档
- **readme**: 添加 demo 演示视频 (`2921236`, `9f15750`)

---

## [0.0.3] — 2025-12-25

### 新增
- **graph**: 优化占位节点及阶段切换逻辑 (`f7a66fe`)
- **ui**: 统一替换确认弹窗为通用模态框组件 (`30385ca`)
- **database**: 添加原子写入图数据支持 (`ed01082`)

### 样式
- **web**: 优化首页标题名称 (`fe45fa5`)

---

## [0.0.2] — 2025-12-24

### 新增
- **ops**: 实现任务列表拖拽排序功能 (`5706730`)
- **graph/ui**: 添加用户展开节点管理、折叠功能，支持双击切换子任务折叠状态 (`8993ec6`, `e399c9b`)
- **graph**: 根据节点数量调整过渡动画时间，优化图形渲染体验 (`cc7b51b`)
- **graph**: 添加渲染任务 ID 记录以检测竞争条件，优化渲染逻辑 (`8032e69`)
- **agent**: 优化成功节点标记逻辑，支持从子任务中获取关键成功步骤并更新反思器输出模式 (`99d7fe6`)
- **agent**: 更新成功节点标记逻辑，支持从 Planner 指定的节点获取目标达成信息，并优化前端日志输出 (`fb82011`)
- **agent**: 在数据库中创建会话记录以支持前端任务刷新，优化任务列表加载逻辑 (`43c4e57`)
- **agent**: 标记成功子任务节点并优化成功路径高亮逻辑 (`2623a5c`)
- **ui**: 添加并优化新建任务弹窗 (`7721349`)

### 重构
- **core**: 实现子任务执行链持久化机制 (`3a65744`)

---

## [0.0.1] — 2025-12-17

### 新增
- **graph**: 添加证据强度分类与更新逻辑以优化因果推理；更新失败模式渲染以支持竞争假设消解；反思器增加证据强度智能判断原则 (`4b8a11c`)
- **executor**: 添加失败模式渲染功能以增强提示信息 (`22d113e`)
- **reflector**: 添加拒绝节点逻辑以优化因果图谱管理 (`2fb8485`)

---

## [0.0.0] — 2025-12-09 ~ 2025-12-13

> 项目初始建设阶段，核心图引擎、Web UI、Agent 执行框架基础搭建。

### 新增
- **core**: 添加 MCP 服务器管理功能并完善任务完成图状态更新 (`ee0cd7e`)
- **planner**: 增加分支再生计划的人机协同审核与依赖修正机制 (`ffae7ae`)
- **core**: 增加节点完成时间戳支持与高亮逻辑优化 (`f5933ba`)
- **graph**: 实现全局任务完成状态及成功路径高亮 (`5269517`)
- **ui**: 添加并显示任务阶段横幅提示 (`f021008`)
- **exec**: 优化执行路径高亮与界面国际化支持 (`b39909c`)
- **graph**: 根据节点类型动态调整节点尺寸，优化当前执行路径高亮样式 (`b265c58`)
- **graph**: 增加当前执行路径高亮显示功能，优化节点和连线样式 (`5140dbd`)
- **graph**: 优化节点类型处理与详情面板显示 (`a0e161f`)
- **executor**: 优化任务状态管理与前端节点渲染 (`1fd5cc7`)
- **agent**: 支持通过 Web UI 传入操作 ID 以统一任务标识 (`6712f49`)
- **intervention**: 增强人工干预请求处理，集成数据库支持 (`32b511f`)
- **web**: 支持通过环境变量配置 Web 服务主机地址 (`9e8efb2`)

### 重构
- **web**: 支持任务删除及优化任务状态展示 (`0d6179e`)

### 修复
- **agent**: 修复异步调用及事件处理逻辑 (`ad659ec`)
- **agent**: 规范审计状态处理逻辑 (`6557fa8`)
- **planner**: 防止将已完成任务状态误改为废弃 (`e0be529`)
- **executor**: 确保 `step_id` 全局唯一，避免节点冲突 (`2831a96`)
- **web**: 修复 Agent 日志空白及状态横幅显示异常问题 (`3d2a049`)

### 文档
- **readme**: 添加腾讯云黑客松徽标 (`6dc257a`)

---

[Unreleased]: https://github.com/SanMuzZzZz/LuaN1aoAgent/compare/HEAD...HEAD
[0.6.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/bf51e6f
[0.5.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/42975d5
[0.4.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/362a7b9
[0.3.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/7843018
[0.2.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/fd682fb
[0.1.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/3a590bc
[0.0.9]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/9b14ad2
[0.0.8]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/8328ee6
[0.0.7]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/7ee7cee
[0.0.6]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/3c90d22
[0.0.5]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/8959f8e
[0.0.4]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/2921236
[0.0.3]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/30385ca
[0.0.2]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/8032e69
[0.0.1]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/4b8a11c
[0.0.0]: https://github.com/SanMuzZzZz/LuaN1aoAgent/commits/1fd5cc7
