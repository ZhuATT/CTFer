# 知识库检索升级与 ARTEX 漏洞体系借鉴方案

> **文件路径**：`docs/知识库检索升级与ARTEX漏洞体系借鉴方案.md`  
> **关联工程**：`at1-github/AT-src`（执行底座）、`at1-github/docs/图与基底重构设计.md`（基底设计）、`lernproject/skilllls`（外部技能库）、`lernproject/ARTEX-new`（参照系）  
> **成文日期**：2026-10-19  
> **核心定位**：解决 AT1 迁移到 pi 微内核后“外部 Markdown 技能库的高效检索与消费”，并深度拆解 ARTEX 的“漏洞库（Findings）体系”，将“**流量证据强绑定**”与“**跨任务继承/知识交接**”两项杀手级机制针对性优化、裁剪并融合进 AT1 的新图与基底架构中。

---

## 目录

1. [外部知识库（Skills）的 Grep 与检索方案调研](#1-外部知识库skills的-grep-与检索方案调研)
   - 1.1 现状与需求分析
   - 1.2 各类 Grep/检索工具选型对比
   - 1.3 为什么 AST 级 Grep 不适用于 Markdown
   - 1.4 AT1 推荐落地方案：两级检索架构（Catalog 路由 + 章节精准提取）
2. [ARTEX 漏洞库（Findings 系统）深度剖析](#2-artex-漏洞库findings-系统深度剖析)
   - 2.1 架构本质：为什么需要独立于探索图的漏洞库？
   - 2.2 核心数据模型与状态流转
   - 2.3 六大利用闭环机制全景
3. [核心机制消化与改良一：流量证据强绑定（Traffic Evidence Binding）](#3-核心机制消化与改良一流量证据强绑定traffic-evidence-binding)
   - 3.1 ARTEX 原版机制剖析与实战价值
   - 3.2 针对 AT1 架构的痛点分析与裁切改造
   - 3.3 AT1 落地设计：四角色划分 + SHA256 原子存证 + SQLite 单库绑定
4. [核心机制消化与改良二：跨任务继承与知识交接（Hint & Inheritance）](#4-核心机制消化与改良二跨任务继承与知识交接hint--inheritance)
   - 4.1 ARTEX 原版机制剖析（add_task_hint 与黑板继承）
   - 4.2 AT1 的天然架构优势（单库多 Task）
   - 4.3 AT1 落地设计：两档交接（冷启动简报 + 结构化 Hint 注入）
5. [AT-src 落地工程实施蓝图](#5-at-src-落地工程实施蓝图)
   - 5.1 数据库表扩展（SQLite DDL）
   - 5.2 核心工具集实现设计（TypeScript）
   - 5.3 调度器与 Prompt 改造点
6. [总结与建议行动项](#6-总结与建议行动项)
7. [核心机制消化与改良三：外延关联资产发现与人在回路（HITL）审批扩权](#7-核心机制消化与改良三外延关联资产发现与人在回路hitl审批扩权)
   - 7.1 背景与实战痛点：为什么纯 Prompt 约束会失效？
   - 7.2 ARTEX 原版机制剖析与致命缺陷（自主扩权越权 vs 同步阻塞假死）
   - 7.3 AT1 推荐落地方案：异步请示 + 前端卡片 + 唤醒闭环（不增新工具）
   - 7.4 工程改动蓝图与数据流设计

---

## 1. 外部知识库（Skills）的 Grep 与检索方案调研

### 1.1 现状与需求分析

- **数据资产**：`lernproject/skilllls` 下汇集了 340+ 个高质量技能文件与实战报告（涵盖 `Claude-Red-main/Skills/` 下的各类 Web 注入、逻辑漏洞、内网横向、提权以及各类 SRC/EDU 实战报告）。
- **形态特征**：每个 Skill 均采用标准的 Markdown 文档组织（YAML frontmatter 包含 `name`、`description`，正文包含检测探测流、Payload 矩阵、绕过备忘录、修复建议等章节）。
- **框架约束**：AT1 的基座已经从原先的 Claude Code 外壳重构为基于 **pi 微内核**（`AT-src`）的独立单进程架构，失去了原有 Claude Skill 的自动全局加载机制。
- **目标**：不将全部 340+ 篇技能硬塞入 prompt（避免上下文爆炸和巨额 token 消耗），将外部技能作为只读外部知识库，让 Worker/Planner 在遇到特定目标与信号时，能**快、准、省**地检索出所需武器库。

---

### 1.2 各类 Grep/检索工具选型对比

| 工具类别 | 代表工具 | 适用场景 | 在 Skills 知识库检索中的优势 | 致命缺陷 / 局限 | 结论 |
|---|---|---|---|---|---|
| **原生 CLI** | `grep` / `egrep` | 简单文本查找 | POSIX 原生自带，无依赖 | 递归多文件速度慢；中文编码支持差；无上下文语法理解；大小写与多词逻辑笨拙 | ❌ 不推荐 |
| **现代极速文本** | **`ripgrep` (`rg`)** | 源码、配置多文件全文快搜 | Rust 开发，单核/多核性能天花板；原生过滤二进制与忽略项；正则匹配速度最快 | 缺乏拼写容错；要求关键词绝对精确（搜 `越权` 会漏掉 `IDOR` / `BOLA`） |  **适合作为底层搜索管道** |
| **全能终端 Grep** | **`ugrep` (`ug`)** | 深度文本/压缩包/模糊检索 | 支持 `-Z` 模糊搜索（容忍 1~2 字符拼写差异）；支持 `--bool` 复杂逻辑与近义词查询；内置 Markdown 高亮 | 需额外安装独立二进制（相比 rg 普及率稍低） |  **单点能力最强，备选底层** |
| **代码 AST 语法树** | `ast-grep` (`sg`) / `semgrep` | 源代码重构、审计、找漏洞 Sink | 能够解析 JS/TS/Go/C/Py 等语言的抽象语法树，忽略空格、换行、变量重命名 | **只能解析结构化代码**，无法理解 Markdown 的自然语言、标题结构和列表 | ❌ **彻底不适用** |
| **交互式模糊检索** | `fzf` | 人机交互实时过滤 | 终端实时反馈极佳，对人类极度友好 | 面向人类终端 stdin/stdout 设计，不适合作为 Agent 的自治 Tool | ❌ 仅限操作员手工用 |

### 1.3 为什么 AST 级 Grep 不适用于 Markdown

`ast-grep` 和 `semgrep` 的核心杀伤力在于：将代码解析为 **CST/AST（具体/抽象语法树）**，比如将 `db.query("SELECT " + x)` 解析为 `CallExpression(MemberExpression, BinaryExpression)`，从而无视代码写在几行、中间有没有空行或注释。

但我们的 `skilllls` 知识库是**自然语言文档 + Markdown 格式文本**。Markdown 的解析树（CommonMark AST）只有 `Heading`、`Paragraph`、`CodeBlock` 等节点。AST grep 根本无法对自然语言里的“延迟注入探测语句”或“权限越界逻辑”做语义匹配。用 AST grep 搜 Markdown 技能库属于工具属性错配。

---

### 1.4 AT1 推荐落地方案：两级检索架构（Catalog 路由 + 章节精准提取）

如果直接向 Worker 暴露一个 `exec("rg ...")` 工具，Worker 经常会陷入两个极端：
1. **关键词不对齐**：搜索 `越权`，但文档里写的是 `IDOR` 或 `水平越权`，导致返回 0 条；
2. **返回内容撑爆上下文**：一次 `rg -C 20` 搜出十几处命中，一口气吐出上万字符，把单轮上下文直接打满。

**业界验证的最优解法：两级检索（Catalog 信号路由 + 章节按需提取）：**

```
┌────────────────────────────────────────────────────────┐
│  一级：轻量 Catalog 信号索引（System Prompt / 静态缓存） │
│  - 仅加载 name + 核心 description                      │
│  - 340+ 个 Skill 压缩至 ~5KB Token，常驻或按需 list     │
└──────────────────────────┬─────────────────────────────┘
                           │ 匹配到候选 Skill (如: offensive-sqli)
                           ▼
┌────────────────────────────────────────────────────────┐
│  二级：章节精准提取工具 (read_skill_section)            │
│  - 按 Markdown 二级标题（H2/H3）切块                   │
│  - 仅返回当前步骤所需的 Payload/步骤（< 800 Token）     │
└────────────────────────────────────────────────────────┘
```

#### 实施步骤：
1. **预编译 Catalog（离线/构建时）**：
   解析 `skilllls/` 下所有 `.md` 的 YAML frontmatter，输出轻量级 JSON 索引：
   ```json
   [
     {
       "name": "offensive-sqli",
       "tags": ["web", "injection", "database"],
       "description": "SQL注入全流程：报错、联合、布尔/时间盲注、WAF绕过、带外与权限提升。"
     },
     {
       "name": "offensive-idor",
       "tags": ["web", "logic", "auth"],
       "description": "越权漏洞：水平/垂直越权、ID枚举、多阶段参数覆盖验证。"
     }
   ]
   ```
2. **暴露核心工具 `tools/knowledge.ts`**：
   - `search_skills(query: string)`：先搜 Catalog 的 name、tags、description；若未命中，底层走 `rg -i` 搜技能正文标题，返回匹配到的 **Skill 列表与主要章节标题清单**。
   - `read_skill(skill_name: string, section?: string)`：如果指定 `section`（如 `"Time-Based Blind"`），程序使用正则或轻量 AST 提取该 `##` 到下一个同级标题之间的内容，精准返回 50~100 行关键操作，严防 Context 爆炸。

---

## 2. ARTEX 漏洞库（Findings 系统）深度剖析

### 2.1 架构本质：为什么需要独立于探索图的漏洞库？

在 ARTEX 中，探索图（Exploration Graph）记录的是任务运行时的微观动态（`goals`、`intents`、`facts`、`findings`），但它在实际落地中遇到了几个不可调和的矛盾：

1. **生命周期不一致**：扫描任务（Task）可能经常重置、归档或删除，但确认的**漏洞成果（Findings）必须是永久沉淀的系统级资产**；
2. **多任务资产视图（全局大盘）**：客户需要站在企业或域名资产角度，查看“该主域名过去 1 个月发现了哪些高危漏洞”，如果漏洞死锁在某次任务的探索图里，跨任务统计和报表导出极其痛苦；
3. **长期处置状态跟踪**：漏洞从发现到修复需要经历真实的管理周期（`pending` 待处理 → `confirmed` 已确认 → `fixed` 已修复 → `false_positive` 误报）。这些属性属于业务管理面，不属于单次运行的图状态机。

因此，ARTEX 在 PostgreSQL 中建立了独立的 `findings` 表（配建 `finding_traffic`、`finding_retests`、`finding_assets`），将漏洞升格为第一等公民业务实体。

---

### 2.2 核心数据模型与状态流转

#### ARTEX 漏洞状态机枚举（`findings.status`）：
```
  [pending] 待处理 (刚录入)
      │
      ├──> [false_positive] 误报 (人工驳回)
      ├──> [ignored] / [risk_accepted] 忽略 / 风险接受
      ▼
  [in_progress] 处理中
      │
      ▼
  [confirmed] 已确认 (经核实真实存在)
      │
      ├──> (启动 Retester 复测)
      ▼
  [fixed] 已修复 (复测确认原触发失效且正常服务在线)
```

#### 数据库关系全景：
- **`findings`**：核心表（ID、task_id、node_id、vulnclass、name、severity、summary、evidence、report、status）。
- **`finding_traffic`**：存储关联的抓包证据（finding_id、traffic_id、role、note）。
- **`finding_retests`**：复测流水记录（retest 会话 ID、verdict、summary、evidence）。
- **`finding_assets`**：绑定的具体资产（asset_id，实现漏洞与资产库互通）。

---

### 2.3 六大利用闭环机制全景

```
                ┌──────────────┐
                │ Worker 渗透  │
                └──────┬───────┘
                       │ 1. 真实触发 PoC, 录入最小断言 (report_finding)
                       ▼
            ┌──────────────────────┐
            │   findings (漏洞库)   │
            └──────────┬───────────┘
                       │
       ┌───────────────┼───────────────┬────────────────┐
       │ 2. 异步出报告  │ 3. 流量存证   │ 4. 隔离复测    │ 5. 深入利用 (Deepen)
       ▼               ▼               ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
│Reporter Agent│ │Traffic 快照  │ │Retester Agent│ │原任务注入 Step    │
│(生成MD规范报告)│ │(SHA256哈希防 │ │(三态核验并自 │ │(最高优先级派工， │
│              │ │ 篡改/独立归档)│ │ 动翻转状态)  │ │ 自动继承资产锚点)│
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────────┘
       │
       ▼
 6. 跨任务继承 (Hint & Blackboard Inheritance)
    - 新任务复用旧漏洞资产与流量快照，跳过前期盲目侦察
```

1. **机制一：Reporter Agent 异步撰写报告**  
   Worker 在前线打点时，写报告是最耗费上下文和时间的。ARTEX 将报告撰写剥离为后台异步任务：漏洞录入后，系统唤醒专职的 `Reporter Agent`，对照 Worker 提交的命令与回显，生成规范的八段式 Markdown 报告（概述、影响面、利用前提、复现步骤、修复建议）。
2. **机制二：流量证据强绑定（Traffic Evidence Binding）**（详见 §3）
3. **机制三：独立复测 Agent（Retester）与状态自动翻转**  
   复测从不污染原渗透会话。系统为 Retester 提供干净的环境与原 PoC，按标准三态（`reproduced` / `fixed` / `inconclusive`）输出裁决；若确认 `fixed`，系统机械自动更新漏洞库状态。
4. **机制四：深入利用（Deepening）机制**  
   操作员在后台点击“深入利用”，系统在原任务图谱中动态生成一条 **Priority=10（最高级）** 的新 Intent/Step，自动挂载原漏洞的资产与事实上下文，驱动 Worker 立即由点拓面、横向内网渗透。
5. **机制五：跨任务继承与知识交接（Hint & Inheritance）**（详见 §4）
6. **机制六：多渠道实时告警与分流**  
   集成钉钉、飞书、企业微信群机器人，按严重等级与处置状态变化实时推送，支持漏洞回链。

---

## 3. 核心机制消化与改良一：流量证据强绑定（Traffic Evidence Binding）

### 3.1 ARTEX 原版机制剖析与实战价值

AI 渗透测试最被诟病的两个顽疾是：**“张口就来（LLM 幻觉生成漏洞）”** 和 **“截屏/文本容易被篡改伪造”**。
ARTEX 针对此设计了整套网络流量与漏洞证据强绑定机制：

1. **流量池采集（Traffic Capture）**：所有测试流量通过本地透明代理/抓包池，在 `exchanges` 表中持久化保存每个 HTTP 请求和响应原文，分配唯一 `traffic_id`。
2. **四种证据角色划分（Role-Based Evidence）**：
   - `baseline`（正常基线）：正常访问的请求/响应（证明目标原本状态正常，而非一直 500/404）；
   - `proof`（漏洞证明）：注入 Payload、越权请求或触发特定错误的关键报文对；
   - `verification`（二次验证）：改变参数或二次发包验证漏洞确定性的报文；
   - `supporting`（辅助线索）：环境探测、指纹泄露等外围依据。
3. **独立证据存证区（Evidence Store）**：
   - 漏洞一旦绑定流量，系统会将对应的报文原文从全局易清理的临时流量池中导出，存储到受保护的独立证据存储区（`evidence/`）；
   - 对报文内容计算 **SHA256 哈希**，生成版本号 `evidence_version`；
   - **效果**：后续即使清理了整个任务的全局访问日志，**已归档漏洞的 HTTP 证明流量永久不可篡改、不可丢失**。

---

### 3.2 针对 AT1 架构的痛点分析与裁切改造

| 维度 | ARTEX 原始做法 | AT1（我们的环境）约束与痛点 | AT1 改造裁切决策 |
|---|---|---|---|
| **网络代理形态** | 内置复杂的 HTTP/HTTPS MITM 代理服务与证书托管 | 单机 Node 架构，目前 Worker 主要靠 curl / `exec.ts` 和 Playwright 浏览器 | **不强制常驻重型 MITM 代理**；通过抓取 Playwright 的 network 事件与 curl 包装器输出进行捕获 |
| **存储后端** | PostgreSQL 独立 exchanges 表 + 文件系统 | SQLite 单文件存储 + 文件系统 | **采用 SQLite 表存储元数据，磁盘文本文件存储 Raw HTTP 报文** |
| **实体关系** | 独立的 `findings` 表与独立的 `finding_traffic` 绑定表（双 ID 容易混淆） | AT1 坚持**单图节点（nodes 表中 kind='finding'）**哲学 | **直接将证据绑定锚定在 `node_id` 上**，彻底消灭双表双 ID 混乱 |

---

### 3.3 AT1 落地设计：四角色划分 + SHA256 原子存证 + SQLite 单库绑定

#### 1. 证据数据结构（SQLite 表设计）

在 AT1 的 SQLite 数据库中增加一张轻量的 `finding_traffic` 关联表：

```sql
CREATE TABLE IF NOT EXISTS finding_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    node_id INTEGER NOT NULL,            -- 关联 nodes 表中 kind='finding' 的节点 ID
    role TEXT CHECK(role IN ('baseline', 'proof', 'verification', 'supporting')) NOT NULL,
    request_raw TEXT NOT NULL,           -- HTTP 请求原文 (含方法、路径、Header、Body)
    response_raw TEXT NOT NULL,          -- HTTP 响应原文 (含状态码、Header、Body)
    sha256 TEXT NOT NULL,                -- request+response 的 SHA256 哈希
    note TEXT,                           -- 这条请求证明了什么
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_traffic_node ON finding_traffic(node_id);
```

#### 2. Worker 提交 Finding 时的进件工具（TypeScript 接口定义）

在 `AT-src/src/tools/submit.ts` 中增强 `submit_finding` 工具契约：

```typescript
export interface TrafficEvidenceInput {
  role: 'baseline' | 'proof' | 'verification' | 'supporting';
  request: string;   // 完整的 HTTP Request 原文
  response: string;  // 完整的 HTTP Response 原文
  note: string;      // 证据解释（例如: "正常访问返回 200且仅含公共字段"）
}

export interface SubmitFindingArgs {
  step_id: number;
  summary: string;
  vulnclass: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  poc: string;
  traffic_refs?: TrafficEvidenceInput[]; // 推荐必填
  asset_ids?: number[];
}
```

#### 3. 进件程序机械校验与防伪存储逻辑
1. Worker 提交 `submit_finding` 时：
   - 程序校验：如果是 Web 类漏洞（SQLi / XSS / IDOR / SSRF 等），若未附带 `proof` 角色的 traffic，工具返回警告，提示 Worker 补充致命发包报文；
   - 程序对每条 traffic 计算 `sha256 = crypto.createHash('sha256').update(req + resp).digest('hex')`；
   - 写入 `finding_traffic` 表，同时将主证明报文的 SHA256 存入 `nodes.evidence_sha256` 列；
   - 在证据目录自动同步落盘：`evidence/tasks/<task_id>/finding_<node_id>_<sha256>.http`。
2. **断言永久闭环**：后续报告生成、Retester 复测时，直接读取该哈希对应的报文，绝对杜绝大模型“自己编造响应文本”的幻觉。

---

## 4. 核心机制消化与改良二：跨任务继承与知识交接（Hint & Inheritance）

### 4.1 ARTEX 原版机制剖析（add_task_hint 与黑板继承）

在真实的渗透实战中，渗透往往不是一个任务单次跑完的，通常表现为多次任务：
- 第 1 次任务：做全子域名资产发现与端口服务识别；
- 第 2 次任务：针对特定资产做身份认证漏洞挖掘；
- 第 3 次任务：从已发现的未授权接口切入内网横向。

如果每次新任务都把之前的记忆清零，新任务的 Agent 就会重复消耗几十万 Token 从头做资产指纹收集和端口扫描。
ARTEX 针对跨任务协同设计了两种机制：
1. **结构化 Hint 传递（`add_task_hint`）**：操作员或主调度器将老任务中已确认的事实（例如：“存在未授权下载接口，携带具体 qzwffileid 参数”）以 Hint 形式派发进新任务。
2. **黑板继承（`blackboard_inheritance`）**：在查询探索图时，新任务可以在底层配置继承源任务 ID，只读加载老任务的祖先节点，使老事实在视觉和逻辑上成为新任务的“既有世界状态”。

---

### 4.2 AT1 的天然架构优势（单库多 Task）

在 `at1-github/docs/图与基底重构设计.md` 中，我们做过一个极其英明的架构拍板：
> **“存储采用 SQLite 单文件，项目级一个 .db，多 Task 共库；资产表（assets）项目级共享。”**

**这个决策让 AT1 具备了比 ARTEX 更简单的天然继承优势：**
- ARTEX 跨任务需要跨 Exploration 隔离树，或者依赖复杂的中间件。
- 在 AT1 中，同属一个项目的多个 Task（例如 `task_recon_01`、`task_exploit_02`）的数据**物理上存放在同一个 SQLite 文件里**！
  - `assets` 表没有 task_id 隔离，天然全项目共享；
  - `nodes` 表仅用 `task_id` 做逻辑区分。

这意味着：**在新任务中“复用前任知识”，在底层不过是一句 SQL 过滤条件的变化，无需设计庞大复杂的分布式黑板继承机制！**

---

### 4.3 AT1 落地设计：两档交接（冷启动简报 + 结构化 Hint 注入）

结合实战复杂度控制，我们在 AT1 中设计**轻重两档**继承交接方案：

```
                    ┌──────────────────────────────┐
                    │ 同一项目 SQLite (.db) 存储库   │
                    │ (assets 表 + 历史 task 节点)  │
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
   【第一档：项目简报冷启动】                   【第二档：结构化 Hint 注入】
(轻量级，零新增机制，每次新任务默认跑)       (用于精准交接已有漏洞/立足点)
- 读取已确认高价值事实与 Findings 列表      - 显式在当前图插入 step/fact 节点
- 渲染为 1 页面板进入首轮 Planner Prompt   - 标记 origin='inherited', 指向前任证据
- Planner 第一轮直接具备全局情报           - Worker 领到后跳过侦察直接深入利用
```

#### 第一档：项目情报简报（Prior Intel Summary，开箱默认）
当新 Task 启动时，驱动层（Driver）在构造首轮 Planner 上下文前，执行一条极轻量 SQL：
```sql
SELECT kind, summary, payload 
FROM nodes 
WHERE project_id = $project_id 
  AND task_id != $current_task_id 
  AND (
    (kind = 'finding' AND state IN ('reported', 'confirmed')) OR
    (kind = 'fact' AND json_extract(payload, '$.confidence') = 'observed')
  )
ORDER BY id DESC LIMIT 20;
```
由程序自动渲染出一段纯文本简报，挂载到首轮 Planner 的开场白中：
```markdown
## [项目历史沉淀情报（前任任务已确认）]
- 【已确认漏洞】#12: workflowFileDown.do 任意文件读取 (严重度: High, 资产: 10.10.1.25)
- 【关键事实】#8: 统一身份认证接口存在弱加密，GUID 计数器每步增量为固定 145
- 【已有资产】系统已登记该企业有效资产 14 个，无需重复全量端口扫描
```
**优势**：0 架构负担，只需几十行 TypeScript，完全不涉及状态迁移，新任务 Planner 开局就站在巨人的肩膀上。

#### 第二档：结构化继承节点（Inherited Node Injection）
若需要针对特定历史漏洞做“二次深入利用（Deepening）”或“串联内网渗透”：
1. 调度器或操作员调用命令/接口：`inherit_to_task(from_node_id, target_task_id)`；
2. 程序在目标任务中复制生成一个镜像节点：
   - `kind = 'fact'`（或保留原 `finding`）；
   - `origin = 'inherited'`；
   - `payload` 携带 `inherited_from_node_id = from_node_id`，并**自动软链接原节点的 traffic 证据与资产锚点**；
3. Planner 接收到这个 `inherited` 节点，可以直接以它为 `parent_id` 派发新的攻击 Step（例如：“利用 #12 的文件读取漏洞提取数据库密码并尝试远程连接”）。

---

## 5. AT-src 落地工程实施蓝图

为了在现有的 `AT-src`（Node + TypeScript + SQLite）中落地上述方案，以下给出确切的文件改造清单与代码规范。

### 5.1 数据库表扩展（SQLite DDL）

在 `AT-src/src/db.ts` 的初始化建表逻辑中追加：

```sql
-- 1. 流量证据表 (Traffic Evidence)
CREATE TABLE IF NOT EXISTS finding_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    node_id INTEGER NOT NULL,
    role TEXT CHECK(role IN ('baseline', 'proof', 'verification', 'supporting')) NOT NULL,
    request_raw TEXT NOT NULL,
    response_raw TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_traffic_node ON finding_traffic(node_id);

-- 2. 节点表新增 inherited_from 与 evidence_sha256 字段（如原表未包含）
-- SQLite 支持 ALTER TABLE ADD COLUMN（若已有字段则忽略）
-- ALTER TABLE nodes ADD COLUMN inherited_from INTEGER;
-- ALTER TABLE nodes ADD COLUMN evidence_sha256 TEXT;
```

---

### 5.2 核心工具集实现设计（TypeScript）

#### 1. 新增技能库检索工具：`AT-src/src/tools/knowledge.ts`

```typescript
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const SKILLS_DIR = path.resolve('D:/Downloads/hacker/lernproject/skilllls/Claude-Red-main/Skills');

export interface SkillSearchResult {
  skill: string;
  matchedSections: string[];
  summary: string;
}

/**
 * 快速根据关键词搜索 Skill 库（第一级检索）
 */
export function searchKnowledge(query: string): SkillSearchResult[] {
  // 使用 ripgrep 定位包含关键字的 Markdown 标题
  try {
    const stdout = execFileSync('rg', ['-i', '-m', '3', '--heading', query, SKILLS_DIR], {
      encoding: 'utf-8',
      timeout: 3000,
    });
    // 解析输出，返回匹配到的 Skill 名称与二级标题列表
    return parseRgOutput(stdout);
  } catch (err) {
    return [];
  }
}

/**
 * 精准读取特定 Skill 的特定章节（第二级检索，防上下文爆炸）
 */
export function readSkillSection(skillName: string, sectionTitle?: string): string {
  const filePath = path.join(SKILLS_DIR, skillName, 'SKILL.md');
  if (!fs.existsSync(filePath)) {
    return `Error: Skill "${skillName}" not found.`;
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  if (!sectionTitle) {
    // 默认仅返回前 60 行（包含 Workflow 和速查步骤）
    return content.split('\n').slice(0, 60).join('\n') + '\n\n... (使用 section 参数获取具体章节细节) ...';
  }

  // 按 Markdown H2 (##) 标题分割提取目标小节
  const sections = content.split(/\n(?=##\s+)/);
  const matched = sections.find(s => s.toLowerCase().includes(sectionTitle.toLowerCase()));
  if (!matched) {
    return `Section "${sectionTitle}" not found in skill "${skillName}". Available sections:\n` +
      sections.map(s => s.split('\n')[0].replace('##', '').trim()).join('\n');
  }

  return matched;
}

function parseRgOutput(raw: string): SkillSearchResult[] {
  // 简单文本解析逻辑...
  return [];
}
```

#### 2. 增强漏洞提交工具：`AT-src/src/tools/submit.ts`

在 `submit_finding` 执行体中加入**流量证据哈希计算与落库**：

```typescript
import crypto from 'node:crypto';
import type { Database } from 'better-sqlite3';

export function recordFindingWithTraffic(
  db: Database,
  taskId: string,
  nodeId: number,
  trafficRefs?: Array<{ role: string; request: string; response: string; note: string }>
) {
  if (!trafficRefs || trafficRefs.length === 0) return;

  const insertStmt = db.prepare(`
    INSERT INTO finding_traffic (task_id, node_id, role, request_raw, response_raw, sha256, note)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const updateNodeShaStmt = db.prepare(`
    UPDATE nodes SET evidence_sha256 = ? WHERE id = ?
  `);

  let primarySha256 = '';

  const tx = db.transaction(() => {
    for (const ref of trafficRefs) {
      const sha256 = crypto.createHash('sha256')
        .update(ref.request + '\n---\n' + ref.response)
        .digest('hex');

      insertStmt.run(taskId, nodeId, ref.role, ref.request, ref.response, sha256, ref.note);
      
      // 优先将 proof 角色的流量哈希记录在节点主表
      if (ref.role === 'proof' || !primarySha256) {
        primarySha256 = sha256;
      }
    }

    if (primarySha256) {
      updateNodeShaStmt.run(primarySha256, nodeId);
    }
  });

  tx();
}
```

---

### 5.3 调度器与 Prompt 改造点

1. **Planner 提示词注入（Prior Intel 简报）**：
   在 `AT-src/src/planner-prompt.ts` 中增加一段 `renderPriorIntel(db, projectId, currentTaskId)`，只要同一个 `.db` 里存在其他 task 的已确认 findings，开场即向 Planner 注入简报，避免重复下发侦察 Step。
2. **Worker 工具集注入**：
   将 `searchKnowledge` 与 `readSkillSection` 注册为 Worker 的可用工具（或直接与 `exec` 搭配，形成一套标准的 `knowledge_query` 工具接口）。
3. **纪律门禁约束**：
   在 Worker 的 System Prompt 中强化纪律：
   > *“遇到未授权/注入/逻辑漏洞时，先调用 `read_skill` 获取正规绕过与验证清单；上报漏洞必须调用带有流量原文的 `submit_finding`，杜绝无请求/响应凭证的文字推断。”*

---

## 6. 总结与建议行动项

| 模块 | 核心落地原则 | 建议施工优先级 | 预期效果 |
|---|---|---|---|
| **技能库检索** | **拒绝全局加载，拒绝 AST grep**；采用两级目录检索（`rg` 搜标题 + 章节切块读取） | **P1 (立即施工)** | 340+ 个 Skill 立刻转化为可用武器库，每轮交互仅消耗几百 Token |
| **流量证据强绑定** | 引入 `finding_traffic` 划分 4 种证据角色；落 SHA256 哈希到 `nodes` 列，固化存证 | **P1 (立即施工)** | 彻底消灭 Agent 幻觉漏洞与假报告，达成金融级证据链可信度 |
| **跨任务知识交接** | 借 SQLite 单库多任务天然红利；首期实现“冷启动项目简报注入”，二期实现继承节点 | **P2 (紧随其后)** | 彻底解决多任务重复侦察浪费 token 的问题，前序渗透成果直连后续利用 |
| **外延资产扩权闭环** | 升级 `register_asset` 自动识别超范围；异步推前端卡片 + 复用现有 `scope-add watcher` | **P1 (立即施工)** | 既防 AI 擅自越权触碰法律红线，又打通高价值关联资产被审批攻打的真实实战闭环 |

---

## 7. 核心机制消化与改良三：外延关联资产发现与人在回路（HITL）审批扩权

### 7.1 背景与实战痛点：为什么纯 Prompt 约束会失效？

- **实战价值矛盾**：在授权黑盒 Web 渗透、SRC 挖掘与红队演练中，**最具突破价值的漏洞往往恰恰藏在初始 Scope 之外的关联资产上**。典型场景：
  1. 主站登录接口通过 302 重定向到跨域 SSO 单点登录系统（如 `auth.corp-partner.net`）；
  2. 前端 Webpack 源码泄露了第三方未授权 API 网关、云存储桶或微服务地址；
  3. CDN 或反向代理报错，回显了未在资产白名单里的真实后端物理 IP。
- **授权法律红线**：一旦 Agent 自主向范围外资产发起扫描或注入发包，直接触犯授权协议，构成非授权入侵；
- **现状断层痛点**：目前在 Worker 的 `register_asset` 工具提示词中写有：
  > *“但发现约束外新目标≠获得授权，动手与否由规划者/操作员决定。探索结论走 submit_fact，别串。”*
  
  **在工程实践中，这句提示词成了没有任何执行落点的空话**：
  1. **无声入库**：Worker 调 `register_asset`，SQLite 默默插入一条资产记录，系统不发出任何通知；
  2. **人类完全不知情**：前端控制台没有任何弹窗或事件广播，操作员不知道 Worker 在暗中挖出了高价值外延资产；
  3. **Planner 不会被唤醒**：`register_asset` 不会发射 `TriggerEvent`，Planner 根本不知道需要做出判断；
  4. **两头堵死**：Worker 不敢测（强行发包被 `guard` 内存白名单硬拒）；Planner 没收到信号不派单；人类没通道审批。高价值资产就此“死”在数据库中。

---

### 7.2 ARTEX 原版机制剖析与致命缺陷

ARTEX 在面对资产范围与拦截审批时，提供了两套机制，但均存在严重的实战缺陷：

#### 1. 范围越界风险：AI 自主扩权（严重违背安全红线）
- **Worker 侧（`insert_assets`）**：Worker 只要调用 `insert_assets`，ARTEX 底层代码会自动调用 `AddAutoScope(taskID, typ, domain, url, ip)`，**静默将新发现的子域/IP 直接并入当前任务的测试范围**；
- **Planner 侧（`add_task_scope`）**：ARTEX 直接为 Planner 开放了 `add_task_scope` 工具，Planner 只要认为“这个根域也是目标的”，可以自己调工具将整个根域纳入范围；
- **致命缺陷**：**AI 不能自己给自己签发授权！** 实战中遇到属于第三方 CDN、供应商甚至误报的资产时，模型自作主张扩权开打，会引发严重的法律事故。

#### 2. 拦截审批机制：HandleAsk 同步阻塞死等（导致 Agent 假死）
- ARTEX 在 `guard` 和 `intercept` 模块中设计了 `HandleAsk`：当命中需人工审批的规则时，系统向前端推送待审记录，并在 Go 协程中通过 Channel **同步阻塞死等**人类决定（`ch := i.pending.add(...)`）；
- **致命缺陷**：**同步阻塞会导致 Worker 假死**。若操作员离开电脑，Worker 的超时时钟持续空转，最终触发 `stepTimeout` 崩溃退出，严重破坏自动化流转。

---

### 7.3 AT1 推荐落地方案：异步请示 + 前端卡片 + 唤醒闭环（不增新工具）

针对上述矛盾，AT1 采取**“不增新工具、异步不阻塞、前端一键审批、底层原位唤醒”**的高效闭环架构：

```
                    Worker 侦察发现外部关联目标 foo.partner.com
                                      │
                                      ▼
                        调用 register_asset 工具
                                      │
                         [代码底层自检 host 是否在 scopeHosts?]
                         ├── 在 Scope 内 ──> 正常登记入库并返回资产 ID
                         │
                         └── 超出 Scope（核心触发点！）
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
        【工具回执明确指路】                    【系统发射前端事件】
   "已登记资产 #N (待审批)。                向前端推送 asset_scope_proposal
    该资产不在当前授权 scope 内，              界面顶部弹出一个醒目提醒卡片:
    系统已自动向操作员发起扩权请示。            "发现关联资产 foo.partner.com，
    纪律：严禁对该目标主动发包；                 是否扩权加入本任务？"
    将其作为 observed fact 上抛结束。"                   │
                   │                                     │
                   ▼                                     ▼
           Worker 不阻塞死等                       操作员点击 [批准扩权]
          在 fact 里写下观察                               │
             安全结束当前 step                             ▼
                                                 触发原有的 scope-add 机制!
                                                 (guard 放行 + Planner 被 scope_changed 唤醒
                                                  下一轮自主派新 step 攻打!)
```

#### 核心优势：
1. **认知零负担（坚决不增加新工具）**：Worker 依然只使用 `register_asset`。无需让大模型在“登记资产”还是“请示权限”之间纠结，杜绝工具调用混乱与漏调；
2. **异步非阻塞**：工具回执立刻指示 Worker“*已提交请示，当前不要乱动，写 fact 结案*”。Worker 正常结束当前 step，不消耗思考预算和超时时间；
3. **安全合规闭环**：扩权动作完全由人类操作员点击前端按钮决定，AI 无法越权；
4. **完全复用既有基建**：操作员批准后，直接调用 AT1 已经完全就绪的 `scope-add watcher`：
   - ≤1.5s 内存热更新，`guard` 即刻放行；
   - 调度器自动向 Planner 发送 `scope_changed` 触发事件；
   - Planner 在下一轮感知到新目标，从容生成合法且深度的攻击 Step。

---

### 7.4 工程改动蓝图与数据流设计

#### 1. 资产表扩展字段（`assets.ts`）
在资产库中增加审批与关联标记：
- `approval_state`: `'approved' | 'pending' | 'rejected'`（默认若在 scope 初始列表里为 `approved`，超出范围为 `pending`）；
- `proposal_source`: 记录是由哪个 step、哪个 worker 提出的外延关联。

#### 2. 工具层改造（`AT-src/src/tools/assets.ts`）
在 `createRegisterAssetTool` 的 `execute` 处理函数中：
```typescript
const inScope = opts.scopeHosts ? isHostInScope(params.host, opts.scopeHosts) : true;

if (!inScope) {
    // 1. 写入资产库，标记 approval_state = 'pending'
    // 2. 发射系统事件/写前端待审队列表（emit asset_scope_proposal）
    // 3. 返回明确回执给 Worker：
    return textResult(
        `[范围外关联资产·已提交扩权请示] 已登记资产 #${res.asset.id} [${res.asset.type}] ${params.host}（状态：待审批）。\n` +
        `⚠️ 纪律红线：该目标超出当前授权白名单，系统已向前台推送操作员审批卡片。\n` +
        `当前严禁发起主动探测或漏洞利用；请把发现该关联资产的线索以 submit_fact（confidence=observed）上报后结束本 step。`
    );
}
```

#### 3. 前端交互卡片设计
前端收到 `asset_scope_proposal` 后，在任务控制台顶部浮动卡片：
- **卡片标题**：`🔔 发现潜在关联外延资产`
- **详细信息**：
  - **资产目标**：`auth.corp-partner.net`
  - **类型**：`subdomain`
  - **发现来源**：Step #4 登录包响应 302 Location 提取
  - **Worker Note**：*“主站单点登录跳转该域名，疑似企业内聚 SSO 服务”*
- **操作按钮**：
  - `[ 批准加入 Scope ]` ➔ 调用 `POST /api/tasks/:id/scope-add`，立即触发 watcher；
  - `[ 保持只读/拒绝 ]` ➔ 标记 `rejected`，从待审列表划出。

---
*(本文档归档于 `docs/知识库检索升级与ARTEX漏洞体系借鉴方案.md`，作为后续 P3/P4 阶段施工的基准依据)*
