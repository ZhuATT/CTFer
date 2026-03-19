---
name: wooyun
description: AI内部知识增强 - 基于WooYun漏洞库（22,132真实案例）的RAG检索。全自动运行，无需用户手动调用。会在解题过程中自动检索并整合相关案例、Payload与实战思路，增强AI决策。
allowed-tools: []
---

# WooYun知识库（AI内部增强）

## 概述

> **⚠️ 用户无需手动调用该Skill** - 这是AI内部使用的知识增强模块

WooYun（2010-2016）收录了22,132个真实业务逻辑漏洞案例。本Skill通过RAG（Retrieval-Augmented Generation）技术，让AI在CTF解题过程中**自动检索、参考和借鉴**这些真实案例，从而做出更准确的决策。

## 如何工作（全自动）

### 1. 题目初始化时自动检索

当用户调用`init_problem()`时，AI会：

```python
# 在tools.py内部自动执行（用户无需干预）

# Step 1: 识别题目类型（sqli/lfi/rce等）
probable_types = auto_identify_and_load(url, hint)

# Step 2: 自动从WooYun知识库检索
wooyun_ref = retrieve_knowledge(
    query=f"{description} {hint}",
    context={
        "current_vuln_type": "sql-injection",
        "target_url": "http://target.com/login.php",
        "tech_stack": ["PHP", "MySQL"],
        "attempted_methods": []
    },
    top_k=3
)

# Step 3: 将检索结果整合到系统消息（AI使用）
system_message += f"""
【WooYun真实案例参考】
- Payload样例: ...
- 攻击技术: ...
- 类似案例: ...

建议做法: ...
"""
```

**输出示例**：
```
[Agent] 开始解题: http://target.com/login.php
[Agent] 识别到的类型: sql-injection

=== 【WooYun知识】AI自动加载 ===
【WooYun真实案例参考】
1. Payload样例: ' OR '1'='1-- ...
2. 攻击技术: MySQL报错注入函数: updatexml(), extractvalue()...
3. 高频参数: 参数: id, 场景: 通用ID参数...

建议做法: 建议使用检索到的Payload进行测试
=== 解题指南 ===
...
```

### 2. 攻击过程中自动参考

AI在生成Payload、构造攻击向量时，会自动参考WooYun案例：

**场景1：常规Payload失败，需要绕过WAF**
- AI认知："基础union注入被拦截"
- 自动检索：`retrieve_knowledge(query="SQL注入WAF绕过", context={...})`
- 检索结果：`%c0%ae%c0%ae/`、`%00截断`等绕过技术
- AI决策："将尝试WooYun案例中的编码绕过方法"

**场景2：需要构造复杂Payload**
- AI认知："需要提取数据库信息"
- 自动检索：`retrieve_knowledge(query="MySQL信息提取", context={...})`
- 检索结果：`@@version`、`information_schema.tables`等Payload
- AI决策："使用案例中验证的Payload提取数据"

### 3. 获得flag后生成专业报告

AI自动引用WooYun案例，使报告更具说服力：

```
【解题报告】

漏洞类型: SQL注入
获取的Flag: flag{xxx}

【WooYun真实案例支持】
- 类似案例: 某大型网站SQL注入漏洞（高危）
- 攻击技术: UNION注入绕过WAF
- 数据支撑: WooYun SQL注入案例中68.7%为高危

【参考Payload】
- Union注入: '?id=-1 UNION SELECT 1,2,3--'
...
```

## 技术优势

### ✅ 全自动运行
- **无需用户干预**：所有检索和整合都在AI内部完成
- **透明化**：检索过程可见，增强信任

### ✅ 上下文感知
- 根据当前题目类型检索
- 根据技术栈（PHP/MySQL等）优化结果
- 根据已尝试方法调整检索方向

### ✅ token高效
- 限制返回数量（top_k=3）
- 只返回最相关知识片段
- 自动过滤无关信息

### ✅ 持续增强
- 可扩展到更多知识库
- 后续可接入向量数据库
- BM25 + 上下文增强评分

## 知识来源

### `wooyun/knowledge/` — 元知识库（50-80KB/文件）

已分析提炼的元知识，包含：

| 漏洞类型 | 案例数 | 主要内容 |
|---------|--------|---------|
| sql-injection | 56104 | 高频参数、Payload、绕过技巧 |
| file-traversal | 28598 | 目录遍历Payload、编码绕过 |
| file-upload | 84644 | 上传漏洞、绕过技术 |
| command-execution | 44897 | RCE利用、命令注入 |
| info-disclosure | 24443 | 信息泄露路径 |
| unauthorized-access | 24617 | 未授权访问模式 |
| xss | 18611 | XSS Payload、场景 |

**每份知识文件包含**：
- 漏洞参数命名模式（高频参数Top 10）
- Payload大全（Base64绕过、Unicode绕过、%00截断等）
- 攻击策略分布（按成功率排序）

### `wooyun/categories/` — 完整案例库（1-20MB/文件）

全部22,132个案例的完整标题、分类、严重程度：

- 案例编号、标题、厂商信息
- 漏洞类型、严重程度
- 提交日期、修复状态

### `wooyun/examples/` — 实战渗透方法论

- `bank-penetration.md` - 银行行业渗透思路
- `telecom-penetration.md` - 运营商渗透方法

## 技术架构

```
┌─────────────────────────────────────────┐
│  AI Agent（Claude解題）                  │
│                                         │
│  init_problem()                         │
│    ↓                                    │
│  auto_identify_and_load() → 识别类型   │
│    ↓                                    │
│  retrieve_knowledge() → RAG检索        │
│    ↓                                    │
│  generate_attack_plan() → 生成攻击计划 │
│    ↓                                    │
│  执行直到获得flag                       │
└────────────┬────────────────────────────┘
             │ 自动调用
             ↓
┌─────────────────────────────────────────┐
│  Wooyun RAG引擎（wooyun_rag.py）        │
│                                         │
│  1. 构建索引（knowledge/categories）    │
│ 2. BM25相似度评分                      │
│ 3. 上下文增强（技术栈、已尝试方法）     │
│ 4. 返回Top-K最相关                     │
└─────────────────────────────────────────┘
```

## 自动检索关键节点

### 🔍 初始化时（init_problem）
- **触发**：用户调用init_problem()
- **查询**：`{description} + {hint}`
- **上下文**：初始题目信息
- **用途**：让AI一开始就有WooYun知识支撑

### 🔍 攻击向量生成时
- **触发**：AI需要生成Payload
- **查询**：`"{vuln_type}有效payload"`
- **上下文**：当前技术栈、已尝试方法
- **用途**：优先使用历史验证过的Payload

### 🔍 方法失败时
- **触发**：当前方法失败（WAF屏蔽、绕过失败）
- **查询**：`"{failed_method}绕过"`
- **上下文**：失败原因和目标特征
- **用途**：从案例中寻找绕过技术

### 🔍 生成报告时
- **触发**：获得flag后
- **查询**：`"类似{vuln_type}的案例"`
- **上下文**：漏洞类型和利用过程
- **用途**：引用真实案例，增加报告说服力

## 案例演示

### 场景1：SQL注入题目

**题目信息**：
```
URL: http://target.com/login.php
Hint: 登录页面可能存在注入
```

**AI自动检索**：
```python
wooyun_context = retrieve_knowledge(
    query="登录页面SQL注入",
    context={"current_vuln_type": "sql-injection"},
    top_k=3
)
```

**AI获得的知识**：
```
【WooYun参考】
1. Payload样例: ' OR '1'='1-- (高危案例占比68.7%)
2. 高频参数: 参数: username, 场景: 登录表单
3. 绕过技术: %c0%ae%c0%ae/ (Unicode绕过方案)
```

**AI决策**：
> "根据WooYun案例，登录页面SQL注入占比68.7%为高危，高频参数是username/password。将优先测试这些参数..."

### 场景2：文件上传绕过

**AI认知**：
> "基础PHP上传被拦截，需要寻找绕过方法"

**AI自动检索**：
```python
retrieve_knowledge(
    query="文件上传绕过WAF",
    context={"current_vuln_type": "file-upload"}
)
```

**检索结果**：
```
【WooYun参考】
1. 绕过Payload: .htaccess、user.ini重写解析
2. 编码绕过: 双写、大小写、空格绕过
3. 真实案例: XX公司文件上传（高危）
```

**AI决策**：
> "将尝试.htaccess方法，配合大小写混淆..."

## 文件结构

```
D:\CTF_agent\
├── wooyun/                           # WooYun仓库（已克隆）
│   ├── categories/ (15个案例文件)
│   ├── knowledge/ (8个知识文件)
│   └── examples/ (渗透实例)
├── skills/
│   └── wooyun/
│       ├── SKILL.md                # 本文档
│       └── wooyun_rag.py           # RAG引擎（核心）
├── tools.py                        # + 集成检索调用
└── .cache/
 └── wooyun_index.json           # 自动生成的索引
```

## 维护与扩展

### 更新索引

当WooYun仓库更新时，重建索引：

```bash
python -c "from skills.wooyun.wooyun_rag import build_wooyun_index; build_wooyun_index()"
```

### 添加新知识

如果想添加其他知识库（CNVD、Seebug等）：

1. 在`wooyun_rag.py`中添加解析逻辑
2. 添加到索引构建函数`_parse_knowledge()`
3. 重新构建索引

## 总结

**用户无需了解本Skill的实现细节** - 这是AI的内部增强模块。

**核心价值**：
- 让AI拥有22,132个真实案例作为决策依据
- 解题思路更贴近真实渗透场景
- 报告更具说服力（有数据支撑）
- 全自动运行，无缝集成

**使用时只需**：
```python
from tools import init_problem

# AI自动完成一切
tools = init_problem(
 url="http://target.com",
 description="登录页面存在注入",
 hint="初步判断为SQL注入"
)
```
