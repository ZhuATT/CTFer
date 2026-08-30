# Phase 4 —— 闭环（M4）执行计划

> 依据：`docs/at1-执行开发计划.md` §6.1 M4 行 + `phase3.5-中期审核.md` 全部定稿。**观察者架构是 M4 唯一设计输入**（旧四门漏斗方案作废，verify.py 旧代码 M4 末期清理）。
> 目标：**AT1 从"有记忆 + 有裁判"变成"能自己跑完一个 engagement"**——driver 主循环 + guard/stoploss + engagement 三件套进出写回 + watch，先过 canary 全量回归，再跑真实 engagement。
> 工作目录：`D:\Downloads\hacker\at1-github`；上一 Phase：`22e5598`（观察者转向 + Phase 3 全量）+ 未提交的 xfyun-glm 观察者通道切换（`providers.py`/`test_providers.py`）。

---

## 0. 范围与前置

**做**（依赖序）：前置清账（P4.0）→ scaffolding → guard → stoploss → transcript 比对 → driver 主循环 → engagement 写回 → 阶段手册定稿 → watch → canary 全量回归 →（可选）真实 engagement → 旧 verify 清理

**不做**（M4 后）：
| 不做 | 原因 |
|---|---|
| evaluator（任务级裁决，§3.7） | M4 后启用，终止 C 的验收闸下一版做 |
| oob.py vendor（SSRF 回连） | 等用户配置（观察者文本判断够用） |
| 反馈学习回路 / tentative 比例观察 | M4 后首个真实 engagement |
| scheduler / 多任务并发 | v2 |
| 工作台（M5） | M4 用 CLI 验收 |
| 门1.5 独立重放 | 旧架构；观察者 + transcript 比对已覆盖验证层 |
| 链式思考 / follow_up 验证 | observer.py 占位注释，验证后启用 |

**前置核对**：
| # | 事项 | 状态 |
|---|---|---|
| 1 | 观察者架构全链路（A1-A4） | ✅ 已验收（4 confirmed / 退出码 0） |
| 2 | 观察者模型 glm-5.3 经 xfyun 中转 | ✅ 已改未提交（`xfyun-glm` preset） |
| 3 | worker 模型 glm-5.3 全量 | ⚠ **需确认**：`_SOLVER_PRESETS["glm"]` 默认 `glm-5.3-flash`，phase3.5 说全量——查 `.secrets.env` 是否 `AT1_MODEL=glm-5.3` 覆写；没覆写则 flash（thinking 洪水根因） |
| 4 | runner thinking 短路 | ❌ 待做（P4.0b，phase3.5 §六明确"开工第一件事"） |
| 5 | transcript 定点比对（evidence_verified） | ❌ **未实现**——observer.py 只有 docstring 承诺；`verify.py` 旧 `verify_claims` 还在但无人调用 |
| 6 | 绝对不报表代码化 | ❌ 待做（P4.0c；A4 证明 prompt 软约束拦不住开放重定向） |

---

## 1. 契约定版（本 Phase 锁死）

### 1.1 FINDINGS 行（新契约，4 字段）

```json
{"id":"F-001","endpoint":"/search","evidence":"evidence/sql-test.md","summary":"单引号返回 SQL 报错","round":1}
```
- 只读校验：`endpoint` + `evidence` 非空（`canary-web/run_chain.py::_parse_finding` 现行实现，driver 复用）
- 文件名兼容 `.jsonl` 变体（`_find_findings_file` 兜底逻辑 driver 继承）
- worker 提交不设防（提交是 worker 的事，验证是系统的事）

### 1.2 观察者输出 schema（入板格式）

```json
{"findings":[{"id","endpoint","summary","assessment","severity","reason","evidence","round"}],
 "session_intel":{"coverage_gaps","effective_patterns","suggestions","notable_attempts","intel_summary"}}
```
- assessment ∈ `confirmed / likely_false_positive / uncertain / duplicate`
- 入板：`bb.add_finding`（同 id 覆盖）/ `bb.update_session_intel`

### 1.3 engagement 三件套（driver fail-fast 消费）

- `engagement.json`：`target/mission/date/scope.allow+deny/credentials`。`scope.allow` 非空 = fail-fast 条件
- `status.md`：固定四段锚点 `## 漏洞表 / ## 攻击面 / ## 已确认非漏洞 / ## 阻断项`；driver 只追加漏洞表**表尾**，启动反向读"已确认非漏洞"播种 immune
- `notes/prior-intel.md`：首次 run 播种黑板；收尾生成 `prior-intel-draft.md`（续跑半边）

### 1.4 控制器区与 I/O 分级（不可破坏）

- `.at1/_blackboard.json` + `.at1/transcript.jsonl` 在 workdir 之外，guard 禁 worker 写
- transcript 写入分级：`init/result/tool_result` 每条 fsync；assistant text/tool_use 批量 flush；thinking 进度只计数 + 1/100 采样；遥测前缀行不写

### 1.5 终止三条件（driver 判定，worker 声明零权重）

- A：黑板 findings 出现 confirmed → 停，待人收割
- B：预算耗尽
- C：`check_goal` 到 report 且出口满足（evidence/ 非空 + status.md 有行 + report.md 草稿存在）→ TERMINAL_C

---

## 2. 任务卡

### P4.0 前置清账（三小项，先做，互不依赖）

**P4.0a commit Phase 3 全量 + 观察者通道切换**
- 内容：把观察者层全部落盘成基线（observer.py / board 观察层 / test_observer* / run_chain 新版 + xfyun-glm 切换）
- 验收：`git commit`，`git status` 干净，pytest 全绿

**P4.0b runner thinking 短路（phase3.5 §六，~40 行 + 单测）**
- 改 `src/runner.py::StreamParser.feed_line`：
  - 先检测再写盘——`json.loads` 后若事件为 thinking 类（assistant 消息 content 块 `type=="thinking"`），只 `thinking_count += 1`，每 100 条采样写 1 条进 transcript，**不 fsync**
  - 遥测/非 JSON 前缀行：不写 transcript（现行是全写——按 I/O 分级改）
  - `init/result/tool_result`：保持每条写 + flush
- 单测：喂合成流（混合 thinking/tool_result/遥测行），断言 transcript 里 thinking 行 ≤ 1%，tool_result 全在，fsync 次数受控
- 验收：canary 跑一轮，transcript 体积相对修复前显著下降，tool_result 完整性不变

**P4.0c 绝对不报表代码化硬拒（`src/noreport.py`，~80 行 + 单测）**
- 背景：A4 证明开放重定向被观察者 confirmed——绝对不报表写在 prompt 里（JUDGE/SESSION）拦不住。确定性类别不该靠 LLM 判断
- 实现：`noreport.check(finding, evidence_text) -> {match: bool, category: str, reason: str}`，确定性硬拒四类：
  - sourcemap（evidence/端点含 `.map` 文件引用）
  - 安全头缺失（evidence 是纯响应头、无 `X-Content-Type-Options`/CSP 等 + 无数据）
  - 版本指纹（`Server: / X-Powered-By:` 行，无凭证数据）
  - 裸 instance-id/内网 IP（命中 `i-[0-9a-z]{17}` / 内网 IP 正则，且无 AK/SK/凭据跟随）
  - CORS `*`（响应 `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials` 且无具体泄露数据）
- 接线：`Observer.run()` 对每条 finding 先跑 `noreport.check`，命中 → 直接标 `likely_false_positive`（附 category/reason），不调用 judge LLM
- **开放重定向等语义类不代码硬拒**（"单独"无法确定判断）——强化 JUDGE/SESSION prompt：绝对不报表提为"先于四步框架的硬否决"（现有列表是四步框架里的一条，弱；改成命中即拒）。canary 回归盯着 F-003 不再 confirmed
- 单测：四类各正负例（负例 = 同类但带真实数据/凭证 → 不得硬拒，留给观察者）
- 验收：canary 全量回归干扰项 0 误报（含开放重定向不再 confirmed）

### P4.1 scaffolding（`scaffolding/` + 展开函数，~80 行 + 单测）

- `scaffolding/` 模板目录：`WORKER-CLAUDE.md`（六段骨架，§3.5.2：身份/授权块 + 质量分层三段式 + 4 字段输出契约 + 台账纪律 + 信号→skill 路由表 + 写操作约束）/ `.mcp.json`（Playwright → 本地 chrome.exe）/ `FINDINGS`+`FACTS` 空文件 / `evidence/` 目录
- `scaffolding.expand(engagement_root, scope_info) -> workdir`：在 `<engagement>/.auto/` 展开；storage-state.json 存在则复制；按指纹信号预复制 `.claude/skills/`
- 输出契约文本 = `run_chain.py` CONTRACT 的通用化（去 canary 专用行）
- 单测：展开后文件齐全、FINDINGS/FACTS 存在、deny 列表渲染进 WORKER-CLAUDE.md
- 验收：dry-run 展开一个合成 engagement，结构符合 §2.3

### P4.2 guard.py（~100 行 + 单测）

- **scope 拦截**：消费 `engagement.json scope.allow/deny` → `guard.check_tool(tool, args) -> GuardVerdict{ok, reason}`（URL 主机名校验 allow 白名单 + deny 先行拦截）
- **控制器区禁写**：对 `workdir` 相对路径写操作，目标落在 `.at1/**` / `state/**` → deny（transcript 独立性物理锚）
- **自毁检测**：危险命令特征（`rm -rf`、`del /s`、覆盖 `_blackboard.json`/`transcript.jsonl`）
- **机制诚实**：worker 跑 `--dangerously-skip-permissions`，guard 没有 OS 层强制执行力——拦截 = ① deny 列表渲染进 WORKER-CLAUDE.md（教育层）② `on_fact` 实时 post-hoc 检测 → 越界记 `guard_violation` 事件 + 注入下一轮 prompt 告警 ③ 自毁命中记高危事件。detect 不阻断，但每类 violation 有自动事件
- 单测：scope 外 URL 命中 / `.at1` 写命中 / 合法 curl 放行 / 自毁命令命中
- 验收：driver 接上后，canary 跑一轮事件流无 guard 误报

### P4.3 stoploss.py（~60 行 + 单测）

- 四维：`会话上限 3 / 活跃预算(总预算秒，进 driver) / 无新事实连击 3 / 不可达连击 3`（§7 默认）
- 接口：`Stoploss.should_stop(board, budget_left_s, round_no, facts_delta) -> (bool, reason)`；连击语义 = 连续轮次 `facts_delta == 0` 或 `untested_surface` 不缩水
- 单测：四维各触发边界 + 恢复（新事实清零连击）
- 验收：driver 轮末调用，触发记 `stoploss_trigger` 事件，终止走 B

### P4.4 transcript 定点比对（`src/transcript_check.py`，~30 行 + 单测）

- 补 phase3.5 §四"要新写"项——**事实层物理锚，缺它观察者的"证据真实"承诺没有验证**
- 接口：`verify_evidence_in_transcript(transcript_path, evidence_text) -> bool`
- 实现：从 evidence"请求"段提取 method+url+关键头；逐行 `json.loads` 解码 transcript（防 `\u`/`\"` 转义假阴性，phase3 附录 D 教训），压空白+小写后找规范化子串
- 接线：driver 在调 observer 前对每条 finding 的 evidence 跑此函数 → `evidence_verified` 标记（真）或标记"未找到请求原文"（观察者 prompt 已声明"证据经事实验证"——现在真正验证）
- 单测：伪造请求不在 transcript → False；真实请求（含转义变体）→ True
- 验收：canary 跑一轮，每条 confirmed finding 的 evidence_verified=True

### P4.5 driver.py 主循环（`src/driver.py`，~500 行，最大卡）

**来源**：提取 `canary-web/run_chain.py` 已验证循环泛化（FINDINGS 文件名兜底 / lazy LLM client / 未测面传递 / observer 输出入板全部保留），不重写不抄旧 plan 的四门漏斗。

**结构**（函数级）：
```python
def run_engagement(engagement_root, *, budget_s, max_rounds, provider) -> int
def _bootstrap(engagement_root) -> Blackboard   # fail-fast 三件套 + 播种
def _round(bb, solver, round_no, ev) -> RoundResult   # 一轮
def _harvest_findings(workdir, bb) -> list[dict]      # 收割 + noreport + transcript + observer
def _write_back(bb, engagement_root, round_no)        # status.md 追加 + 深度刷新
def _terminate(bb, reason) -> bool
```

**轮内流程**（对应 run_chain 已验模式 + M4 新增）：
1. `render_round_prompt(bb, round_=n, tested_endpoints=tested)` → 追加任务简报（阶段/出口/预算/CONTRACT 四字段版）
2. `runner.run(prompt, workdir, solver, task, time_box_s=阶梯)`；`task` 挂 `on_fact→bb.observe` / `on_heartbeat→ev` / `transcript_path=.at1/transcript.jsonl` / `on_spawn→CONTROL` 与杀进程
3. 轮末收割：`harvest.diff_new_lines` FINDINGS/FACTS（兼容 `.jsonl`）→ FACTS `ingest_facts`
4. FINDINGS → `noreport.check`（P4.0c）→ `transcript_check`（P4.4）→ `observer.run` → `bb.add_finding` + `update_session_intel`；tested 端点从 evidence/FINDINGS/immune 收集（控制器算账，不信 worker 自报）
5. Handoff：`res.handoff`（模型版）优先；被杀无 → `harvest.synthesize_handoff(bb, tool_events_tail)`（runner 需暴露尾部 tool_events——run_chain 已通过 task 回调收集）
6. `bb.record_handoff` → 接力块渲染时现算
7. CONTROL 轮询（stop/pause/directive）：stop → 收割 Handoff 优雅停（terminate D）
8. stoploss（P4.3）→ 终止三条件（A/B/C）→ 未停回 1

**新增（相对 run_chain）**：fail-fast 三件套校验 + guard/stoploss 接线 + CONTROL + 预算递减 + 时间盒阶梯（600→1200→1800）+ 终止写回。

**单测**：mock runner（不真 spawn，注入伪 AgentResult），测：三件套缺件拒启 / scope 外 deny / 轮次循环推进 / 终止三条件各触发 / CONTROL stop 优雅停 / guard 命中事件。加 `--dry-run`（渲染第一轮 prompt 不 spawn）便于手工验。

### P4.6 engagement 写回（纯函数 + 单测）

- `status.md`：按锚点定位漏洞表**表尾**追加行（confirmed → 一行 + 深度列标 deep）；"已确认非漏洞"段反向读播种 immune；攻击面解析失败 → 跳过 + `surface_parse_fail` 事件（宽容模式）
- 攻击面深度刷新：confirmed→deep / tentative→tested / 事实→seen
- 收尾生成 `notes/prior-intel-draft.md`（免疫清单 + 未完成方向 + identity_model 结论 + 待跟进端点）
- evidence 归位：worker evidence/ 直写 engagement evidence/（§7 默认已如此）
- 单测：追加不覆盖 / 四段锚点缺失宽容 / 深度刷新映射 / draft 生成
- 验收：canary 跑完 status.md 出现漏洞表行 + 攻击面深度列正确

### P4.7 阶段手册定稿（改 `prompt.py` MANUALS，不写码）

- **exploit 手册**（占位 → 全文）：利用观察者标注——"已确认发现"段同根因勿重交 / "未测面"+"观察者建议"段决定探哪 / 写操作必须读回 / 每发现当场 evidence+FINDINGS
- **report 手册**（占位 → 全文）：同根因合并 / 已确认发现 + 已否决 + 阴性三源取数 / SRC 标准校准（docs/src-standards-distilled.md）/ report.md 草稿规范
- **recon 手册**：现状是 DRAFT（prompt.py docstring 注明"需用户过目才定稿"）——本次过目定稿
- 验收：用户 review 三份手册全文

### P4.8 watch 子命令（`__main__.py` 加 subcommand，~80 行）

- `python -m src watch <engagement>`：tail `state/auto-log.jsonl`，事件→呈现映射渲染彩色一行式（isatty 才着色）
- 映射（§4.3）：heartbeat 活性三态 / finding_confirmed 高亮 / stoploss 黄警 / gate 管线行
- 验收：canary 跑时 watch 实时渲染，M5 复用同一映射表

### P4.9 canary 全量回归（M4 验收 #1）

- canary-web 适配：加 `canary-web/run_engagement.py`（或给 target.py 加 driver 兼容包装）——起靶 → 生成 engagement 三件套（engagement.json 指向 `127.0.0.1:8790`、status.md、prior-intel.md、credentials storage-state）→ `driver.run_engagement` → `grade.py` 对分
- 验收：**真洞 ≥3/4 检出、干扰项 0 误报、黑板 findings 有 confirmed、prompt 渲染含"已确认发现"+"观察者建议"、退出码 0**（判定线 §6.2）
- 跑完 run_chain.py 编排功能冻结（保留作对照，driver 是唯一主循环）

### P4.10 真实 engagement（M4 验收 #2，✅ 用户已拍板：有真实授权目标，会提供）

- **前置**：用户提供目标细节——`target/scope(allow+deny)/credentials(storage-state)/prior-intel`（走 §2.2 三件套）
- 完整跑一遍，验收 `§6.1 M4` 行全项：三件套正确读写 / scope 外目标被 deny / 缺件拒启 / 终止条件触发 / 攻击面深度刷新 / CONTROL 中断生效 / auto-log 完整可回放
- 首跑即承载 phase3.5 遗留 #5/#6：反馈学习回路 + tentative 比例观察（首真实 engagement）
- 目标未就绪时 P4.10 不阻塞 P4.1-P4.9 主线，P4.9 后插队

### P4.11 旧 verify.py 清理（M4 末期）

- 删：`gate1/gate2/gate3/verify_claims/Claim/CLASS_REQS/_OASSERT/_SEC_VARIANTS/占位词表`（phase3.5 §四"要删除"表）
- 留：`parse_llm_json`（observer.py 依赖，迁到独立 `src/json_utils.py` 或保留文件名）
- 重写 `tests/test_verify.py` → 观察者相关测试移入 `tests/test_observer.py`；旧门测试删除
- 验收：删除后 pytest 全绿 + canary 回归不回归（观察者独立跑，不依赖旧门）

---

## 3. DoD（本 Phase 验收总闸）

- [ ] P4.0a commit 干净、P4.0b/c 单测绿、canary 干扰项 0 误报
- [ ] P4.1-P4.4 各单测绿
- [ ] P4.5/P4.6 driver 单测绿（mock runner）+ `--dry-run` 手工验证渲染
- [ ] P4.7 三份手册用户过目定稿
- [ ] P4.8 watch 实时渲染可用
- [ ] **P4.9 canary 全量回归 PASS**：真洞 ≥3/4、干扰项 0 误报、黑板 confirmed、退出码 0
- [ ] **P4.10 engagement 全链路 PASS**（或按用户确认缩小）
- [ ] P4.11 旧 verify 清理后 pytest 全绿 + 不回归

---

## 4. 已知风险

| 风险 | 应对 |
|---|---|
| 观察者 LLM 在真实目标上误判（canary 全合成，真实面未知） | 首次真实 engagement 观察 tentative 比例；误报 → 强化判例（P4.0c 思路扩展） |
| thinking 短路改坏 transcript 完整性 | I/O 分级保 tool_result/result 全量 fsync；canary 跑一轮回归对比 |
| 绝对不报表硬拒误杀真洞（负例边界） | P4.0c 单测含"同类但带数据 → 不得硬拒"；硬拒只限确定性四类+CORS\*，语义类不硬拒 |
| guard post-hoc 检测误报合法测试 | guard 只对 `.at1/**` `state/**` 写 + 自毁命令硬判；scope 拦截宽松（记录不阻断） |
| run_chain.py 与 driver.py 双轨漂移 | P4.9 后 run_chain 编排功能冻结，driver 唯一主循环 |
| worker 不守新契约（文件名/字段） | `_find_findings_file` 兼容 + `_parse_finding` 只校验 endpoint/evidence 非空（run_chain 已验证） |
| status.md 写回解析失败 | 宽容模式：跳过 + `surface_parse_fail` 事件 |
| worker 模型没切到 glm-5.3 全量（仍 flash） | P4.0 前置核对 #3：确认 `AT1_MODEL` 覆写 |

---

## 附录 A：run_chain.py → driver.py 复用映射

| run_chain.py | driver.py |
|---|---|
| 手工建 workdir + 预创建 FINDINGS/FACTS | P4.1 scaffolding |
| CONTRACT 常量 | scaffolding WORKER-CLAUDE.md 输出契约段 |
| `_find_findings_file` / `_find_facts_file` / `_parse_finding` | 原样迁入 driver（或提 `src/contract.py`） |
| `_parse_finding` 4 字段校验 | driver 收割步骤 |
| 观察者调用块（lazy LLM client + observer.run + 入板） | driver 步骤 4 + P4.0c/P4.4 前置 |
| `tested` 集合 + `bb.untested_surface` | 原样 |
| 轮次循环 for rnd | driver 主循环 + CONTROL/stoploss/终止/写回 |
| `grade.py` 对分 | P4.9 验收 |

## 附录 B：关键决策记录（用户拍板位）

| # | 待拍板 | 决定 |
|---|---|---|
| D1 | M4 验收范围 | ✅ **有真实授权目标，用户会提供**（P4.10 全项验收） |
| D2 | 绝对不报表硬拒方式 | ✅ **确定性硬拒 + 语义类 prompt 强化**（P4.0c 按此施工） |
| D3 | driver.py 来源 | ✅ **提取 run_chain 泛化**（P4.5 按此施工） |
| D4 | 旧 verify.py 删除时机 | ✅ **M4 末期删**（P4.11 按此施工） |
| D5 | worker 模型确认 glm-5.3 全量（AT1_MODEL 覆写） | ⏳ P4.0 前置核对，确认即锁定 |

---

*变更记录：v1 draft（2026-08-30），等待用户对 D1-D5 拍板后定稿施工。*
