# CTF Agent Memory Index

## 项目进度

| 阶段 | 任务 | 状态 |
|------|------|------|
| P1 | 失败模式记录 | ✅ 完成 |
| P2 | RAG 增强 | ✅ 完成 |
| P3 | 解题状态持久化 | ✅ 完成 |
| P4 | 工具输出解析 | ✅ 完成 |
| P5 | 成功路径记忆 | ✅ 完成 |

## 文件说明

- `MEMORY.md` - 本索引文件
- `main_chain_progress.md` - 主链进度追踪
- `optimization_plan.md` - 优化计划
- `buuctf_agent_reference.md` - BUUCTF 参考
- `deserialization.md` - 反序列化知识

## 组件清单

| 组件 | 文件 | 功能 |
|------|------|------|
| 失败追踪 | `core/failure_tracker.py` | 记录失败方法，避免重复 |
| RAG 检索 | `core/rag_knowledge.py` | wooyun 知识库检索 |
| 状态持久化 | `core/state_manager.py` | 解题状态保存/恢复 |
| 输出解析 | `tools/output_parser.py` | curl/sqlmap/dirsearch 解析 |
| 经验记忆 | `core/experience_manager.py` | 成功经验积累 |
