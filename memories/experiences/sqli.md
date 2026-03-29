## SQL注入 UNION SELECT 绕过

### 核心 bypass
通过构造负数ID触发数据库返回空结果集，使UNION SELECT语句直接显示在页面中，从而绕过原查询的干扰。

### payload
id=-1 UNION SELECT 1,username,password FROM users

### 原理分析
- **负数ID利用**：id=-1 使得原查询返回空结果，页面结构仍然保留，UNION SELECT的查询结果直接填充到页面显示位。
- **列数匹配**：通过order by或盲注确定列数为3，确保UNION前后列数一致。
- **显示位确定**：标题位置显示第1、2列，内容位置显示第3列，因此直接select username,password到显示位。
- **关键防御绕过点**：未对id参数进行严格类型检查，允许负整数传入；未对UNION关键字过滤。

### 失败方法
（无）

### 适用场景
- 存在回显位的SQL注入
- 需要从数据库中提取用户凭据或敏感数据
- 靶机存在users表且包含username/password字段

### 案例
| 日期 | 靶机 | 成功方法 | Flag |
|------|------|---------|------|
| 2026-03-29 | 9068457c-c5c6-4333-8df6-c2ddd3d7713e.challenge.ctf.show | UNION SELECT 绕过 | CTF{admin_secret_password} |

---
doc_kind: experience
type: sqli
created: 2026-03-29
tags: [sqli, union_select, bypass]

