# Framework Bug Fix Checklist

基于 `Ez_bypass` 这次联调测试，当前优先修复项只聚焦**框架 bug / 语义一致性问题**，不做该题型的定向能力增强。

## P0：先修会直接导致错误结果或运行异常的问题

- [x] 修正 flag 命中即成功的误判逻辑
  - 问题：`agent_core.py` 当前只要 `extract_flags(result)` 命中，就会直接返回成功。
  - 暴露现象：页面里的占位 flag / 示例 flag / 干扰文本可能导致主链提前结束。
  - 修复目标：把“命中文本中的 flag 样式字符串”和“确认本轮动作真实成功拿到 flag”解耦，避免伪阳性终止。
  - 相关位置：`agent_core.py:1762-1777`

- [x] 修正 `memory.target.add_flag(...)` 的错误调用
  - 问题：`TargetInfo` 没有 `add_flag()` 方法，真实接口在 `ShortMemory.add_flag()`。
  - 风险：对应路径一旦命中会直接抛异常。
  - 修复目标：统一改为通过 `memory.add_flag(...)` 记账，并检查同类错误调用。
  - 相关位置：`tools.py:1365-1368`，`short_memory.py:296-299`

## P1：修语义漂移，避免不同模块行为不一致

- [x] 统一全项目 flag 提取规则
  - 问题：`tools.py::extract_flags()` 与 `short_memory.py::_extract_from_step()` 的 regex 覆盖范围不一致。
  - 暴露现象：有的 flag 格式能触发主链成功，但不会被 memory 自动沉淀；不同路径识别结果不一致。
  - 修复目标：统一到单一 flag 提取入口，避免 success 判定、memory 记账、工具返回各自维护一套 regex。
  - 相关位置：`tools.py:1179-1193`，`short_memory.py:485-488`

- [x] 统一“发现 flag”与“动作成功”之间的判定语义
  - 问题：当前 success、memory 记账、auto-save 之间仍偏向文本命中驱动，缺少统一语义。
  - 风险：主链 success、tool success、memory flag、经验保存可能出现不一致。
  - 修复目标：明确一套共享语义，保证 `tool_node.success`、memory step success、最终 solve success 对齐。
  - 相关位置：`agent_core.py` 主循环成功出口、`tools.py` 各工具返回结构、`short_memory.py` 记账逻辑

## P2：修可观测性和契约问题，避免误导调试

- [x] 检查并修正经验自动保存返回值契约
  - 问题：运行日志里出现过“已自动保存: None”，但 `long_memory.auto_save_experience()` 的接口语义看起来应返回可读结果。
  - 风险：保存可能成功但日志误导，也可能底层确实返回契约不稳定。
  - 修复目标：明确 `auto_save_experience()` / `save_experience()` 的返回值协议，并让日志输出可判读。
  - 相关位置：`long_memory.py:405-418`，`agent_core.py` 自动保存经验调用链

- [x] 为本次暴露的 bug 补最小回归测试
  - 目标：不要只修代码，要让问题进入自动化回归面。
  - 建议至少覆盖：
    - 占位 / 伪 flag 不应直接判定 solve success
    - `memory.add_flag(...)` 路径可正常工作
    - 统一 regex 后，主链与 memory 对同一 flag 文本识别一致
    - auto-save 返回值 / 日志语义稳定
  - 相关位置：`tests/` 下新增或扩展现有回归测试文件

## 本轮新增待修项（基于后续联调补充）

### P0：先修会直接污染动作成功语义、导致主链卡住的问题

- [ ] 修正重复 PoC skip 与当前 action success 解析脱节
  - 问题：`execute_python_poc()` 命中 `memory.has_tried()` / `memory.should_skip()` 时会直接返回 `[Skip] ...`，但不会为当前 action 写入新的 memory step；`run_main_loop()` 随后仍通过 `_latest_memory_step_for_action()` / `_resolve_action_success()` 解析 success，可能继承旧 step 的状态。
  - 暴露现象：重复 recon / 重复 PoC 被跳过时，`tool_node.success`、失败统计与 replanning 触发条件可能被旧结果污染，主链容易卡在 recon 循环。
  - 修复目标：保证 skip 也是当前 action 的显式结果并进入 memory / graph，避免旧 step success 泄漏到本轮动作。
  - 相关位置：`tools.py:701-789`，`agent_core.py:783-793`，`agent_core.py:1671-1763`

### P1：修 planner 与 guidance 之间的动作化断层

- [ ] 修正人工 guidance 已入 memory / advisor context，但未有效转成后续动作
  - 问题：`resume_with_guidance()` 与 `build_advisor_context()` 已保存并暴露 `human_guidance`，但 `_collect_graph_informed_actions()` 当前仅对 `cookie`、`ua` / `user-agent` / `mobile` 做少量硬编码候选。
  - 暴露现象：即使人工已明确给出参数名、请求方法、源码泄露、sink 类型或 payload 方向，planner 仍可能继续输出 `recon`。
  - 修复目标：补齐从 guidance / shared findings 到候选 action 的通用映射，至少让高价值提示能驱动动作类型切换，而不是只记录不消费。
  - 相关位置：`agent_core.py:552-593`，`agent_core.py:614-656`，`agent_core.py:1011-1101`

- [ ] 修正高价值发现无法触发从 recon 到 exploit-family 的通用切换
  - 问题：当前 `_decide_next_action()` 在无 attack plan / 无特定类型命中时，主要只会在 `recon` 与 `dir_scan` 之间回退；即使已确认参数入口、源码泄露、可疑 sink 等强利用信号，也缺少通用“进入利用阶段”的桥接。
  - 暴露现象：主链在同一目标上长时间重复轻量侦察，无法利用已发现证据推进。
  - 修复目标：把高价值 shared findings / source analysis / recent confirmed signals 纳入下一步动作决策，避免 recon starvation。
  - 相关位置：`agent_core.py:1011-1217`，`agent_core.py:1998-2114`

### P2：修初始化与执行阶段的网络访问契约不一致

- [ ] 统一初始化探测与运行阶段的 TLS 校验策略
  - 问题：`init_problem()` 使用默认 `requests.get()` 校验证书，而 recon / ua_test 等运行阶段请求使用 `verify=False`。
  - 暴露现象：HTTPS 目标可能在初始化阶段报证书错误、导致类型识别 / 资源加载退化，但进入主循环后又能访问，形成前后语义不一致。
  - 修复目标：统一初始化与执行阶段的网络访问契约，至少保证类型识别、资源加载与主循环对同一目标的可达性判断一致。
  - 相关位置：`tools.py:81-139`，`agent_core.py:1357-1390`

## 本次明确不做

- [ ] 不做针对 `Ez_bypass` 这类题目的定向题型识别增强
- [ ] 不做针对 PHP 比较绕过的专门 planner/payload 策略增强

本轮目标是先把**框架 bug、成功语义、记账一致性、回归覆盖**修稳。
