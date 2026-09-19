# contracts/ — 权威格式契约

机器可执行的协议/格式契约集中地。**改这里的文件 = 改协议**，必须与实现（board.py/执行器）同 commit，配套契约测试锁死。

| 文件 | 管什么 | 消费方 |
|---|---|---|
| `blackboard.schema.json` | 图的存储形态（节点/边/bookkeeping 合法结构）——落盘真相 | board.py、tests/test_schema_contract.py |
| `OBSERVER-INTERFACE.md` | 观察者判断书（请求体）+ 任务单（stdin）的权威协议——翻译规则与纪律 | observer.py、observer_harvest v2 执行器 |

区别一句话：**blackboard.schema 管"图里能存什么"，OBSERVER-INTERFACE 管"观察者被允许请求什么"**，执行器站在中间当翻译兼门卫。

设计叙事/决策史在 `docs/`（图与黑板v3设计.md、at1-v3批3-真轮待测试.md §11-§12），本目录只放契约本体。
