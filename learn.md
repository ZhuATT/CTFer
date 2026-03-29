# 知识管理计划

## 目标

优化 RAG 知识检索体系，明确各知识库的定位和利用方式。

---

## Step 1：从 RAG 移除 wooyun

**状态**：✅ 已完成

**改动位置**：`core/rag_knowledge.py`

**改动内容**：
- `search()` 方法：移除 wooyun 和 wooyun_cases 的检索
- `get_all_type_knowledge()` 方法：只检索 experiences 和 skills
- `search()` 方法：使用 `sort_by_type_priority()` 排序，确保同题型优先

**wooyun 数据处理**：
- 数据保持不动
- 后续作为"原材料库"，按需提炼到 experiences/skills

**改动后检索结构**：
```
get_all_type_knowledge('rce')
  ├── experiences/      # 成功经验（精炼）
  ├── skills/            # 方法论速查
  └── wooyun/           # 不参与 RAG（原材料库）
```

---

## Step 2：整理 skills 格式

**目标**：统一整理成好检索的形式

**理想格式**：
```
## 命令注入 bypass

### 管道符绕过
#### payload
; id | id `id` $(id)
#### 适用场景
cmd=, exec=, ping= 参数

### 管道符绕过
#### payload
; id | id `id` $(id)
#### 适用场景
cmd=, exec=, ping= 参数

---

## 命令注入 bypass

### 空格绕过
#### payload
$IFS, ${IFS}, %09, <>

...
```

**整理原则**：
- 每个 `##` 是一个攻击向量（如"命令注入 bypass"）
- `###` 是具体方法（如"管道符绕过"）
- `#### payload` 存放代码
- 移除混杂的"来自外部导入内容"等冗余部分

**待整理的 skills 文件**：
- skills/rce/SKILL.md
- skills/sqli/SKILL.md
- skills/auth-bypass/SKILL.md
- skills/file-inclusion/SKILL.md
- skills/upload/SKILL.md
- skills/xss/SKILL.md
- skills/ssrf/SKILL.md
- skills/ssti/SKILL.md
- skills/deserialization/SKILL.md
- skills/recon/SKILL.md
- skills/awdp/SKILL.md
- skills/decoder/SKILL.md
- skills/encoding_fix/SKILL.md
- skills/web-recon/SKILL.md

---

## Step 3：wooyun 学习流程（按需触发）

**触发方式**：用户指令，如 `学习 wooyun 的 sqli 案例`

**流程**：
1. 读取 wooyun 相关案例
2. 分析提炼精华
3. 写入 experiences 或 skills 对应位置

**wooyun 数据结构**：
```
wooyun/
├── knowledge/                    # 技术手册（不参与 RAG）
└── plugins/wooyun-legacy/categories/  # 案例库（原材料）
```

**后续利用方式**：
- 不直接调用 wooyun
- 通过用户指令触发学习
- 提炼的知识写入 experiences/skills
- 解题时只使用 experiences/skills

---

## 预期效果

1. **RAG 检索更精准**：experiences + skills 精炼检索，不被 wooyun 淹没
2. **skills 格式统一**：好检索，好维护
3. **wooyun 知识转化**：按需提炼，沉淀到精炼知识库
4. **解题流程不变**：直接 `get_all_type_knowledge()` 使用
