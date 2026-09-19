# 输出格式（系统每轮重写本文件——改动无效；写盘前通读一遍）

## FINDINGS（每行一个 JSON，append-only）

```json
{"id":"F-001","endpoint":"h:5000/v2/_catalog","evidence":"evidence/r1.md","summary":"匿名枚举全部仓库并拉取镜像层（100 仓库，业务+k8s 基建）","round":2,"report":"reports/F-001.md"}
```

- 字段：`id`（F-xxx 递增）/ `endpoint` / `evidence`（evidence/ 下文件）/ `summary`（一句话攻击断言）/ `round` / `report`（**交 FINDING 必写**，reports/ 下报告文件名）
- 可选 `chain`：`{"rel":"derived_from|sources|yields","refs":["F-001","D-002","T-003"],"note":"…"}`——与图中节点的关系声明（refs 可指 F/D/T）。三个动词：`derived_from`=本条派生自某节点；`sources`=本条线索支撑某方向（指向 D-xxx）；`yields`=本条产出源自某方向（来自 D-xxx）。同根因判重（same_root）不归你声明——观察者裁

## FACTS（每行一个 JSON，append-only）

```json
{"value":"5000 Registry 匿名可枚举（_catalog 200）","endpoint":"h:5000","evidence":"evidence/r0.md","round":1}
```

- 字段：`value`（紧凑一句话：**对攻击真有效**的知识——可利用线索 / 攻击方向 / 身份模型 / WAF 指纹 / 目标画像）/ `endpoint`（无端点的全局知识省略此字段）/ `evidence` **必填**（细节指针）/ `round`
- 可选 `chain` 同 FINDINGS
- **不写**：端点存在性（系统从测试记录自动统计，写了算双记）；阴性结论（那是方向的 note，不是事实）

## 三层判层正反例（写前对照）

| 你看到的 | 层 | 去处 |
|---|---|---|
| 单引号返回 SQL 报错 | 纯现象 | 方向动机——报错原文进 evidence/，围绕它验证"语法可控" |
| `' AND 1=1--` 与 `' AND 1=2--` 响应可辨（语法可控，还没拖数据） | 中间能力 | FACTS（evidence=两次请求响应） |
| UNION 拖出他人订单手机号 | 成果 | FINDINGS + 报告 |
| Registry `_catalog` 200 列出仓库（匿名枚举，未拉取） | 中间能力 | FACTS（枚举=能力） |
| 同一次又验证了匿名拉取镜像层数据 | 成果 | FINDINGS（**一个**断言："我能匿名访问并操作 Registry"，枚举/拉取是同一断言的影响描述） |
| 弱口令进后台 + 越权导出数据 | 成果（链） | **一个**链式 FINDING + chain 报告（导出依赖登录，单独登录不构成危害） |

## 报告（交 FINDING 必写）

- 单洞 → `reports/F-xxx.md`；多步链 → `reports/chain-xxx.md`
- 八段：**漏洞描述 / 触发条件 / 攻击动机 / 实际影响 / 业务语境判断 / 链路（引用 T-xxx/F-xxx 谱系）/ 严重度评级（可自评，审查为准）/ 复现要点（引 evidence 文件）**
- 链报告自检："把链中间任何一步删掉，最终断言还成立吗？"——不成立 = 同一条链；成立 = 独立的另一条，拆开写
- 链式严重度按**链的终点**定级

## log.jsonl（每次主动测试一行）

```json
{"ts":"2026-09-18T12:00:00","cmd":"curl -s http://h:5000/v2/_catalog","endpoint":"h:5000","result":"200 匿名"}
```

## 目标画像

FACTS 里的一条滚动 fact，value 以 `目标画像：` 开头（全图唯一）：

```json
{"value":"目标画像：SpringCloud 微服务站，9098 奕云CaaS 是唯一 Web 面，带 Druid 指纹","evidence":"evidence/profile.md","round":1}
```

更新 = **追加新版**（不改动旧行），系统标旧版被取代；冷启动轮产出。
