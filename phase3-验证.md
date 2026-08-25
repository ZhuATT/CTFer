# Phase 3 —— 验证（M3）执行计划

> 依据：`docs/at1-施工执行单.md` 卡 3.1-3.4 + 设计§3.4 全节（含 §3.4.4 实现契约与门 2 prompt 草案）
> 目标：**worker 报的发现可以被机器验真**——Claim 进四门漏斗，confirmed 才算数。
> Phase 3 结束时 AT1 有记忆+有裁判，但没有主循环（M4）——canary-web（M3.5）并行开建，另立 `phase3.5-canary.md`。
> 工作目录：`D:\Downloads\hacker\at1-github`；上一 Phase：`b3e641f`（状态层，52 单测 + relay 双场景）

---

## 0. 范围与前置

**做**：verify.py（Claim 校验 + 四门状态机 + 词表）/ llm.py（vendor，门 2 通道）/ 七案测试
**不做**：driver 调用接线（M4）、门 1.5 默认开启（留接口默认关，设计§7）、canary-web（并行轨道，独立计划）、evaluator（M4 后）

**前置**：
| # | 事项 | 状态 |
|---|---|---|
| 1 | 门 2 异构 verifier 通道 | ✅ **已就位（2026-08-25 实测）**：讯飞 maas 承载 DeepSeek V4 Pro（`xopdeepseekv4pro`，OpenAI 兼容 `/v2`），key 在 `.secrets.env`（gitignored）；Bearer id:secret 整串认证；developer role 被拒（llm.py 不用）；providers 预设 `xfyun` 已加。原 deepseek 官方 key 不再需要 |

## 1. 契约定版（本 Phase 锁死）

### 1.1 FINDINGS 行 = 一个 Claim（设计§3.4.1）

```json
{"id":"F-001", "class":"idor", "endpoint":"/api/order/detail",
 "as_identity":"userA", "owner_identity":"userB",
 "marker":"13800138000", "marker_source":"evidence/userB-profile.md",
 "evidence":"evidence/idor-1.md",
 "expect":null, "expect_denied":null,
 "distinct_from":"status.md 无越权类已确认项；本 run 首条", "round":3}
```
校验：class ∈ 词表类目；evidence/marker_source 相对 workdir 路径；distinct_from 非空（缺 = 门 1 机械拒收）。

### 1.2 正则同源（设计§3.4.3）

词表与 board 抽取**共用一份正则**：board 的 `_CRED_RXS` 等提为公开常量（或抽 `src/lexicon.py`），verify 只引用不复制——情报和验收永远同一套形状定义。

### 1.3 门 3 的 transcript 匹配策略（新定，防转义坑）

transcript 是 JSON 行，命令串在里面带 `\u`/`\"` 转义——**逐字节 grep 会假阴性**。实现：逐行 `json.loads` 后在**解码后的文本**里找 evidence 请求段的规范化子串（压空白+小写）。

## 2. 任务卡

### P3.0 原料阅读（不写码）

- 精读 `hxbai/verify.py`（三重门主体）：门 2/门 3 的调用形态、verifier 输入构造
- 精读 `hxbai/llm.py`（OpenAI 兼容客户端）：重试/空响应处理——vendor 主体
- 产出：可抄/重写清单进本文件附录

### P3.1 Claim schema + FINDINGS 收割（~80 行 + 单测）

- `parse_claim(line) -> Claim`：容错解析（BOM/尾逗号——P2 实测教训），字段校验，坏行拒收并返回原因
- `load_new_claims(path, offset)`：复用 harvest.diff_new_lines
- **验收**：合法行解析全字段；缺 distinct_from / class 不认识 / evidence 路径不存在 → 各自拒收

### P3.2 门 1 词表 + gate1（核心，~200 行 + 单测）

- 11 类判据逐行落（设计§3.4.3 表）：
  - idor 读：**双点接地**（marker ∈ evidence"响应"段含 URL-decode 变体 **且** ∈ marker_source 原文）
  - idor 写 / authbypass / sqli 报错 / 布尔差分（baseline+attack 两段+差异声明）/ ssrf（OOB 命中标记或内网实据）/ xxe·lfi（特征串）/ xss（payload 标记）/ infoleak（凭证正则 − instance-id/内网 IP 黑名单）/ logic·race（before/after+delta）
  - **负 oracle**：401/403 或 expect_denied → 返回 immune 记录（入板由 driver 做，M4）
- **验收**：每类至少 1 正 1 负单测；marker URL-decode 变体命中；instance-id 被黑名单挡（铁律）

### P3.3 门 2 gate2（vendor llm.py + prompt 定稿，~150 行）

- vendor `hxbai/llm.py` → `src/llm.py`（微改：错误处理对齐）
- prompt = 设计§3.4.4 草案 + **class 要件全表**（从 CLAUDE.md 绝对不报表逐条翻译，11 类每类一段"什么情况下不成立"）——这就是当初说的"M3 施工件"
- 温度 0；输出严格 JSON；解析失败重试 1 次 → 仍失败降 tentative
- verifier 配置走 `build_verifier_config`（已就位，异构默认）
- **验收（需 live LLM）**：两案——共享地址场景 refuted=true；真 idor refuted=false

### P3.4 门 3 gate3 + 状态机串联（~120 行）

- gate3：evidence"来源命令/请求"段规范化后在 transcript 解码文本中可寻（§1.3 策略）；"可复现"问在门 1.5 关闭时跳过并在 reason 记录
- `verify_claims(claims, *, transcript_path, gate2_fn=None, replay=False) -> list[Verdict]`：漏斗串联；**纯函数无副作用**（写回是 driver 的活，M4）
- 门 1.5 留接口：`replay=True` 时 urllib 重放只读类（凭证过期→tentative；写操作类永不重放）
- **验收（七案，M3 核心 demo）**：
  ①伪造 marker（不在响应原文）→ rejected
  ②编造 marker_source → rejected
  ③真实双点 → 过门 1
  ④负 oracle：403 证据 → immune 记录
  ⑤共享收货地址（buyer=userA 语境）→ 门 2 refuted → rejected
  ⑥真 idor → 门 2 放行 → confirmed
  ⑦整体虚构（三件套自洽但请求不在 transcript）→ 门 3 杀

## 3. Phase 3 DoD

- [ ] P3.1-P3.2 单测全绿（每类正负例）
- [ ] 七案测试全过（①-④⑦纯单测；⑤⑥真 LLM——无 deepseek key 时用降级方案跑并标注）
- [ ] pytest 总数 ≥65 且 P1/P2 的 52 条零回归
- [ ] gate2 live 调用成功 ≥2 次（成本 <¥0.1/次）
- [ ] 设计文档回写：门 3 匹配策略（§1.3）若与设计有出入
- [ ] 成本：live 验证仅门 2 两案 + 自测若干，<$1

## 4. 已知风险

| 风险 | 应对 |
|---|---|
| deepseek 无 key | 降级预案已定：verifier=glm + 门 3 加严（providers 一行）；七案照跑，⑤⑥标注"同模型验证" |
| gate2 输出不稳定（JSON 格式漂移） | 温度 0 + 严格解析 + 重试 1 次 + 失败降 tentative（绝不误放）；单测用 mock llm，live 只验两案 |
| evidence 四段格式 worker 不守约 | 解析容错（标题变体/BOM/缺段）；缺"响应"段的 idor claim → rejected（reason=evidence 格式不符）——宁可错杀进 tentative 不放行 |
| transcript 转义导致门 3 假阴性 | §1.3 策略：解码后规范化匹配；单测造含 `\u` 转义的 transcript 验证 |
| hxbai verify.py 与我们的 Claim 语义差异大 | P3.0 先读：预计只抄"多票/重试"骨架，判据全部按设计词表重写（P2 同款打法：hxbai 降级为参考读物） |
