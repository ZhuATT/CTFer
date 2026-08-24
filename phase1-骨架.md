# Phase 1 —— 骨架（M1）执行计划

> 依据：`docs/at1-施工执行单.md` 卡 1.1-1.3 + headless 实测四事实（commit 51aed76）
> 目标：跑通"控制器 spawn 一个 `-p` 会话 → 解析流 → 落事件 → 收割 Handoff"的最小闭环。**Phase 1 结束时 AT1 还不能挖洞**，但进程桥这一地基是实的。
> 工作目录：`D:\Downloads\hacker\at1-github`（本仓库根 = 项目根）

---

## 0. 范围

**做**：providers.py / events.py / runner.py / untrusted.py / selftest，共 4 文件 + 测试
**不做**（后续 Phase）：board 与事实抽取（M2）、Handoff 代码合成兜底（M2，本阶段只做正则提取）、verify（M3）、driver 主循环（M4）、工作台（M5）

## 1. 布局定版（本 Phase 决定的结构调整）

设计文档写的 `script/at1/` 是旧假设（当时项目挂在 hacker 目录下）。现在仓库即项目，**压平一层**：

```
at1-github/                ← 仓库根 = 项目根
├── at1/                   # 控制器包（= 设计§2.1 的 pilot/ 包）
│   ├── __init__.py
│   ├── __main__.py        # 入口：python -m at1 …（Phase 1 只有 selftest 子命令）
│   ├── providers.py
│   ├── events.py
│   ├── runner.py
│   └── untrusted.py
├── tests/                 # pytest
├── docs/                  # 设计文档（已有）
├── .venv/                 # 已有（3.13.11）
└── phase1-骨架.md         # 本文件
```

对应关系：设计文档中 `script/pilot/xxx` 一律读作仓库根 `xxx`。**不动**：`canary-web/`（M3.5）、`scaffolding/`（M4）。

## 2. 任务卡

### P1.0 工程化打底（~10 分钟）

- `at1/__init__.py`（空）+ `at1/__main__.py`（argparse 骨架，只认 `selftest`）
- `.venv` 装 pytest：`.venv/Scripts/pip.exe install pytest`
- 验收：`.venv/Scripts/python.exe -m at1 selftest --help` 有输出；pytest 空跑通过

### P1.1 providers.py（卡 1.1，vendor+微改）

```bash
cp /d/Downloads/hacker/lernproject/hxbai-main/hxbai/config.py at1/providers.py
```

- 删：`_to_gateway`、`SOLVER_GATEWAY`
- 留：`anthropic_env()` 原样（solver 通道整套环境变量）
- 改：预设表 = deepseek / deepseek-1m / glm / glm-1m + `"custom"` 占位；消毒键名前缀 `AT1_*`
- 验收：单测——预设表可解析；`anthropic_env()` 返回 dict 的键名与文档一致；无明文 key 出现在 repr 中

### P1.2 events.py（卡 1.2，新写）

- `EventWriter(path)`：只追加，每行 `{"ts","type","round","data"}`，写后 flush
- `_redact(data)`：键名匹配 `cookie|token|key|secret|authorization|session`（大小写不敏感）→ 值替换 `***`
- 事件类型常量从设计§4.1 表生成（枚举 or frozenset）
- 验收：单测——写 3 条含 secret 的假事件，读回验证脱敏 + 逐行可 `json.loads`

### P1.3 runner.py + untrusted.py（卡 1.3，本 Phase 核心）

```bash
cp /d/Downloads/hacker/lernproject/hxbai-main/hxbai/ccrunner.py at1/runner.py
cp /d/Downloads/hacker/lernproject/defending-code-reference-harness-main/harness/prompts/untrusted.py at1/untrusted.py
```

runner 改造清单（按实测事实，逐条对应）：

| # | 改造 | 依据 |
|---|---|---|
| 1 | spawn 命令 = `claude -p --output-format stream-json --verbose --dangerously-skip-permissions --max-turns N --model M`；删 hxbai 的 tsec 引用 | 实测① |
| 2 | 解析器：逐行 `try json.loads`，失败**静默跳过**；按 `type/subtype` 分派：`system/init`→抓 session_id、`assistant/tool_use`→按 id 暂存、`user/tool_result`→配对后调 `on_fact`、`assistant/text`→暂存、`result`→终态 | 实测②③ |
| 3 | prompt 经 stdin 写入后**立即 close stdin** | 实测④ |
| 4 | 心跳：tool_result 计数每满 25 → `heartbeat` 事件 + `on_heartbeat` 回调（不与 worker 交互） | 设计§3.1 |
| 5 | transcript：原始流逐行 append 到 `<workdir>/.pilot/transcript.jsonl`，每行 flush | 设计§3.1 |
| 6 | resume：session_id 落盘；异常退出（非 max-turns）→ `--resume <session_id>`，上限 20；`result.stop_reason` 含 max-turns 类 → 不 resume | 设计§3.1 |
| 7 | Handoff 收割：assistant.text 消息**从后向前**找 `<Handoff>…</Handoff>` 正则 | 设计§3.1 |
| 8 | 环境消毒：spawn 前剥 API key 类变量，注入 `AT1_*` | 设计§3.1 |

untrusted.py：原样移植（37 行），加一条单测（nonce 包裹 + 闭合标签消毒）。

### P1.4 selftest + Phase 验收

`python -m at1 selftest --dry-run` 做这件事：

1. 在临时目录放一个 `hello.txt`（内容随机）
2. spawn 真 `-p` 会话，prompt = "读 hello.txt，把内容写入 out.txt，然后输出 `<Handoff>done</Handoff>`"
3. 全流程走 P1.3 的解析/落盘/心跳/收割

**Phase 1 完成定义（DoD，全部可演示）**：

- [ ] stream-json 被逐行解析，`session_start/fact_added(≥1)/heartbeat?(若≥25次调用)/session_end` 事件落 auto-log.jsonl
- [ ] `.pilot/transcript.jsonl` 存在且含完整消息流
- [ ] `<Handoff>` 正则提取成功
- [ ] 会话中途 Ctrl+C / kill：transcript 留有已发生部分（可读）
- [ ] `result` 事件的 num_turns/stop_reason/total_cost_usd 被记录进 session_end 事件
- [ ] pytest 全绿；单次 selftest 成本 ~$0.15 量级（25k input 基线，实测数据）

## 3. 节奏与纪律

- commit 节奏：每张任务卡一个 commit，格式 `feat(P1.x): …`
- 施工冲突处理：发现设计文档与实际不符 → 改 `docs/at1-执行开发计划.md` 并在同 commit 提交，再继续施工
- vendor 来源只读，不回写 hxbai/dcr-harness 源文件
- Phase 1 完成后：更新施工执行单 M1 行打勾 → 开 Phase 2（M2 状态）计划

## 4. 已知风险

| 风险 | 应对 |
|---|---|
| hxbai ccrunner.py 与当前 CLI 行为差异大（它是旧版写的） | 改造以 P1.3 清单为准，hxbai 只提供骨架参考；对不上的地方以实测为准 |
| Windows 下子进程 stdin 关闭时序（pipe deadlock） | prompt 一次性写入后 close，用 `subprocess.Popen(..., stdin=PIPE)` + 显式 `communicate`/线程读 stdout，M1 实测定 |
| 中文路径/编码（git-bash cp 与 Python 读取） | 文件 IO 统一 `encoding="utf-8"`；selftest 临时目录用英文路径 |
| glm 端点偶发 429 | P1 不做 resume 的完整实现也行（标记 TODO），M2 补齐——验收不依赖 |
