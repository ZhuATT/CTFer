# 在线教育平台 — 竞态条件与状态机漏洞专项测试方案

## 一、威胁建模

### 1.1 优惠券领取 — 竞态条件（Race Condition）

**业务规则**: 每个用户限领一张优惠券。

**攻击面分析**:

| 攻击向量 | 描述 | 风险等级 |
|---------|------|---------|
| TOCTOU（检查-使用时间差） | 服务端先查询"是否已领取"，再执行"插入领取记录"，两步之间存在时间窗口 | 高 |
| 并发重放 | 同一用户同时发送 N 个领取请求，绕过单次校验 | 高 |
| 分布式节点不一致 | 多实例部署时，各节点缓存/DB 状态不同步，导致重复领取 | 中 |
| 前端绕过 | 前端按钮置灰但未做后端幂等校验 | 低 |

**根因**: 缺乏原子性操作。典型漏洞代码模式：

```python
# 漏洞模式 — 非原子检查
def claim_coupon(user_id, coupon_id):
    existing = db.query("SELECT * FROM user_coupons WHERE user_id=? AND coupon_id=?", user_id, coupon_id)
    if existing:                          # <-- 检查
        return "already_claimed"
    db.execute("INSERT INTO user_coupons ...", user_id, coupon_id)  # <-- 使用（两步之间有窗口）
    return "success"
```

### 1.2 课程购买流程 — 状态机漏洞（State Machine Bypass）

**预期状态流转**:

```
[浏览课程] → [加入购物车] → [创建订单] → [待支付] → [支付中] → [已支付] → [已完成]
                                            ↓                         ↓
                                        [已取消]                  [退款中] → [已退款]
```

**攻击面分析**:

| 攻击向量 | 描述 | 风险等级 |
|---------|------|---------|
| 状态跳跃 | 直接从"待支付"跳到"已完成"，跳过支付环节 | 严重 |
| 状态回退 | 将"已支付"订单改回"待支付"后再取消获得退款 | 严重 |
| 支付金额篡改 | 支付回调中金额未与订单金额校验，0.01 元购买课程 | 严重 |
| 并发支付+取消 | 同时触发支付成功回调和取消订单，获得课程+退款 | 高 |
| 重复回调 | 伪造或重放支付回调，重复发放课程权益 | 高 |
| 已取消订单复活 | 对已取消订单发送支付成功通知，使其"复活" | 高 |
| 负数量/负价格 | 购物车中商品数量或价格为负数，导致总价异常 | 中 |

---

## 二、测试方案设计

### 2.1 优惠券竞态条件测试矩阵

| 测试编号 | 测试场景 | 并发数 | 预期结果 | 验证方法 |
|---------|---------|--------|---------|---------|
| RC-01 | 单用户并发领取同一优惠券 | 50 | 仅 1 次成功，49 次失败 | 数据库计数 = 1 |
| RC-02 | 单用户并发领取 + 人为延迟（模拟慢查询） | 20 | 仅 1 次成功 | 数据库计数 = 1 |
| RC-03 | 多用户各自并发领取同一限量优惠券（总量10张） | 100用户x5并发 | 恰好发出10张 | 数据库总计 = 10 |
| RC-04 | 同一用户不同 session/token 并发领取 | 10 | 仅 1 次成功 | 数据库计数 = 1 |
| RC-05 | 优惠券过期边界并发（过期前1ms大量请求） | 30 | 过期后全部失败 | 无新增记录 |

### 2.2 订单状态机测试矩阵

| 测试编号 | 测试场景 | 方法 | 预期结果 |
|---------|---------|------|---------|
| SM-01 | 未支付订单直接调用"完成"接口 | API 直接调用 | 拒绝，返回状态不合法 |
| SM-02 | 已取消订单发送支付回调 | 伪造回调 | 拒绝，订单不可变更 |
| SM-03 | 已支付订单再次支付（重复回调） | 重放回调 | 幂等处理，不重复发放 |
| SM-04 | 已退款订单尝试再次退款 | API 调用 | 拒绝 |
| SM-05 | 并发：支付回调 + 取消订单同时触发 | 并发测试 | 只有一个操作成功 |
| SM-06 | 修改支付金额（回调金额 ≠ 订单金额） | 篡改回调 | 拒绝，金额不匹配 |
| SM-07 | 负数量商品加入购物车 | API 调用 | 拒绝，数量必须 > 0 |
| SM-08 | 0 元订单直接跳过支付 | API 调用 | 按业务规则处理 |
| SM-09 | 逆向状态流转遍历（全部非法转换） | 自动化遍历 | 所有非法转换被拒绝 |
| SM-10 | 并发修改购物车 + 创建订单 | 并发测试 | 订单金额与最终购物车一致 |

---

## 三、并发测试脚本

### 3.1 优惠券竞态条件测试脚本（Python + asyncio）

```python
#!/usr/bin/env python3
"""
优惠券竞态条件测试脚本
测试目标：验证同一用户并发领取优惠券时，系统是否能保证只领取一张
"""

import asyncio
import aiohttp
import time
import json
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class TestConfig:
    """测试配置"""
    base_url: str = "http://localhost:8000"
    claim_endpoint: str = "/api/v1/coupons/claim"
    query_endpoint: str = "/api/v1/coupons/user"
    user_token: str = "Bearer <test_user_token>"
    coupon_id: str = "COUPON_001"
    concurrency: int = 50
    timeout: int = 10


@dataclass
class TestResult:
    """测试结果"""
    total_requests: int = 0
    success_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    status_codes: Counter = field(default_factory=Counter)
    response_details: list = field(default_factory=list)
    elapsed_seconds: float = 0.0


async def claim_coupon(session: aiohttp.ClientSession, config: TestConfig, request_id: int) -> dict:
    """发送单次优惠券领取请求"""
    headers = {
        "Authorization": config.user_token,
        "Content-Type": "application/json",
        "X-Request-ID": f"race-test-{request_id}-{time.time_ns()}"
    }
    payload = {"coupon_id": config.coupon_id}

    try:
        async with session.post(
            f"{config.base_url}{config.claim_endpoint}",
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=config.timeout)
        ) as resp:
            body = await resp.text()
            return {
                "request_id": request_id,
                "status": resp.status,
                "body": body,
                "success": resp.status == 200
            }
    except Exception as e:
        return {
            "request_id": request_id,
            "status": -1,
            "body": str(e),
            "success": False,
            "error": True
        }


async def run_race_condition_test(config: TestConfig) -> TestResult:
    """
    核心测试：使用 asyncio.gather 同时发送 N 个请求
    所有请求共享同一个 TCP 连接池，尽可能同时到达服务端
    """
    result = TestResult()
    connector = aiohttp.TCPConnector(limit=0, force_close=False)

    async with aiohttp.ClientSession(connector=connector) as session:
        # 预热连接（确保 TCP 握手不影响并发时序）
        try:
            await session.options(f"{config.base_url}/health")
        except Exception:
            pass

        # 使用 Event 实现所有协程同时启动（栅栏同步）
        barrier = asyncio.Event()

        async def gated_claim(req_id: int):
            await barrier.wait()  # 所有协程在此等待
            return await claim_coupon(session, config, req_id)

        # 创建所有协程
        tasks = [gated_claim(i) for i in range(config.concurrency)]
        gathered = asyncio.gather(*tasks)

        # 释放栅栏，所有请求同时发出
        start_time = time.monotonic()
        barrier.set()
        responses = await gathered
        result.elapsed_seconds = time.monotonic() - start_time

    # 统计结果
    result.total_requests = len(responses)
    for resp in responses:
        result.status_codes[resp["status"]] += 1
        if resp.get("error"):
            result.error_count += 1
        elif resp["success"]:
            result.success_count += 1
        else:
            result.fail_count += 1
        result.response_details.append(resp)

    return result


async def verify_database_state(config: TestConfig) -> dict:
    """验证数据库中该用户的优惠券领取记录数"""
    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": config.user_token}
        async with session.get(
            f"{config.base_url}{config.query_endpoint}",
            headers=headers,
            params={"coupon_id": config.coupon_id}
        ) as resp:
            data = await resp.json()
            return data


def print_report(result: TestResult, db_state: dict = None):
    """输出测试报告"""
    print("=" * 70)
    print("    优惠券竞态条件测试报告")
    print("=" * 70)
    print(f"  总请求数:       {result.total_requests}")
    print(f"  成功领取:       {result.success_count}")
    print(f"  被拒绝:         {result.fail_count}")
    print(f"  网络错误:       {result.error_count}")
    print(f"  耗时:           {result.elapsed_seconds:.3f}s")
    print(f"  HTTP状态码分布: {dict(result.status_codes)}")
    print("-" * 70)

    # 判定
    if result.success_count == 1:
        print("  [PASS] 竞态条件防护有效：仅 1 次领取成功")
    elif result.success_count == 0:
        print("  [WARN] 0 次成功 — 可能测试配置有误（token/endpoint）")
    else:
        print(f"  [FAIL] 竞态条件漏洞！成功领取 {result.success_count} 次（预期 1 次）")
        print("  [FAIL] 存在 TOCTOU 漏洞，需要引入分布式锁或数据库唯一约束")

    if db_state:
        count = db_state.get("count", "unknown")
        print(f"  数据库实际记录: {count} 条")
        if count != 1:
            print(f"  [FAIL] 数据库记录数异常！预期 1 条，实际 {count} 条")

    print("=" * 70)


async def main():
    config = TestConfig(
        base_url="http://localhost:8000",
        concurrency=50,
    )

    print(f"[*] 开始竞态条件测试：{config.concurrency} 个并发请求")
    result = await run_race_condition_test(config)

    # 可选：验证数据库状态
    db_state = None
    try:
        db_state = await verify_database_state(config)
    except Exception as e:
        print(f"[!] 数据库验证跳过: {e}")

    print_report(result, db_state)

    # 返回退出码
    return 0 if result.success_count == 1 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
```

### 3.2 多用户抢购限量优惠券测试脚本

```python
#!/usr/bin/env python3
"""
限量优惠券抢购竞态测试
测试目标：N 张限量券被 M 个用户并发抢购，最终发放数 <= N
"""

import asyncio
import aiohttp
import time
from collections import Counter


TOTAL_COUPONS = 10       # 优惠券限量
TOTAL_USERS = 100        # 并发用户数
REQUESTS_PER_USER = 3    # 每个用户重复请求次数
BASE_URL = "http://localhost:8000"
CLAIM_ENDPOINT = "/api/v1/coupons/claim"
COUPON_ID = "LIMITED_COUPON_001"


async def user_claim(session, user_id: int, attempt: int):
    """模拟单个用户的领取请求"""
    headers = {
        "Authorization": f"Bearer test_token_user_{user_id}",
        "Content-Type": "application/json",
    }
    payload = {"coupon_id": COUPON_ID}
    try:
        async with session.post(
            f"{BASE_URL}{CLAIM_ENDPOINT}",
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            return {"user_id": user_id, "attempt": attempt, "status": resp.status}
    except Exception as e:
        return {"user_id": user_id, "attempt": attempt, "status": -1, "error": str(e)}


async def main():
    connector = aiohttp.TCPConnector(limit=0)
    barrier = asyncio.Event()

    async with aiohttp.ClientSession(connector=connector) as session:
        async def gated(user_id, attempt):
            await barrier.wait()
            return await user_claim(session, user_id, attempt)

        tasks = [
            gated(uid, att)
            for uid in range(TOTAL_USERS)
            for att in range(REQUESTS_PER_USER)
        ]

        start = time.monotonic()
        barrier.set()
        results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start

    # 分析
    success_users = set()
    total_success = 0
    status_dist = Counter()

    for r in results:
        status_dist[r["status"]] += 1
        if r["status"] == 200:
            total_success += 1
            success_users.add(r["user_id"])

    print("=" * 70)
    print("    限量优惠券抢购竞态测试报告")
    print("=" * 70)
    print(f"  优惠券限量:     {TOTAL_COUPONS}")
    print(f"  参与用户:       {TOTAL_USERS}")
    print(f"  总请求数:       {len(results)}")
    print(f"  成功领取:       {total_success} 次（{len(success_users)} 个不同用户）")
    print(f"  耗时:           {elapsed:.3f}s")
    print(f"  状态码分布:     {dict(status_dist)}")
    print("-" * 70)

    if total_success <= TOTAL_COUPONS and len(success_users) == total_success:
        print(f"  [PASS] 发放数({total_success}) <= 限量({TOTAL_COUPONS})，每用户最多1张")
    else:
        if total_success > TOTAL_COUPONS:
            print(f"  [FAIL] 超发！发放 {total_success} 张（限量 {TOTAL_COUPONS}）")
        if len(success_users) < total_success:
            print(f"  [FAIL] 同用户重复领取！{total_success} 次成功但只有 {len(success_users)} 个用户")

    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
```

### 3.3 Go 高并发压测脚本（更极端的竞态触发）

```go
// race_test.go — 使用 Go 原生并发实现更精确的竞态触发
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	baseURL      = "http://localhost:8000"
	claimPath    = "/api/v1/coupons/claim"
	userToken    = "Bearer test_user_token"
	couponID     = "COUPON_001"
	concurrency  = 100
)

type ClaimRequest struct {
	CouponID string `json:"coupon_id"`
}

func main() {
	var (
		successCount int64
		failCount    int64
		errorCount   int64
		wg           sync.WaitGroup
		startGate    = make(chan struct{}) // 栅栏：所有 goroutine 就绪后同时释放
	)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: concurrency,
			MaxConnsPerHost:     concurrency,
		},
	}

	payload, _ := json.Marshal(ClaimRequest{CouponID: couponID})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-startGate // 等待栅栏打开

			req, _ := http.NewRequest("POST", baseURL+claimPath, bytes.NewReader(payload))
			req.Header.Set("Authorization", userToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			defer resp.Body.Close()
			io.ReadAll(resp.Body)

			if resp.StatusCode == 200 {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
		}(i)
	}

	// 所有 goroutine 就绪 → 同时释放
	start := time.Now()
	close(startGate)
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Println("====================================================")
	fmt.Println("    Go 竞态条件压测报告")
	fmt.Println("====================================================")
	fmt.Printf("  并发数:    %d\n", concurrency)
	fmt.Printf("  成功领取:  %d\n", successCount)
	fmt.Printf("  被拒绝:    %d\n", failCount)
	fmt.Printf("  网络错误:  %d\n", errorCount)
	fmt.Printf("  耗时:      %v\n", elapsed)
	fmt.Println("----------------------------------------------------")

	if successCount == 1 {
		fmt.Println("  [PASS] 防护有效")
	} else {
		fmt.Printf("  [FAIL] 竞态漏洞！成功 %d 次\n", successCount)
	}
	fmt.Println("====================================================")
}
```

### 3.4 订单状态机非法转换遍历测试

```python
#!/usr/bin/env python3
"""
订单状态机安全测试
测试目标：遍历所有非法状态转换，确保系统拒绝每一个
"""

import asyncio
import aiohttp
import json
from itertools import product


# ============================================================
# 状态机定义
# ============================================================

STATES = [
    "cart",           # 购物车
    "pending",        # 待支付
    "paying",         # 支付中
    "paid",           # 已支付
    "completed",      # 已完成
    "cancelled",      # 已取消
    "refunding",      # 退款中
    "refunded",       # 已退款
]

# 合法的状态转换（from_state -> to_state）
LEGAL_TRANSITIONS = {
    ("cart", "pending"),        # 提交订单
    ("pending", "paying"),     # 发起支付
    ("pending", "cancelled"),  # 取消订单
    ("paying", "paid"),        # 支付成功
    ("paying", "pending"),     # 支付超时/失败回退
    ("paid", "completed"),     # 确认完成
    ("paid", "refunding"),     # 申请退款
    ("refunding", "refunded"), # 退款成功
    ("refunding", "paid"),     # 退款拒绝
}

# 所有可能的转换
ALL_TRANSITIONS = set(product(STATES, STATES))

# 非法转换 = 全部 - 合法 - 自身到自身
ILLEGAL_TRANSITIONS = ALL_TRANSITIONS - LEGAL_TRANSITIONS - {(s, s) for s in STATES}


BASE_URL = "http://localhost:8000"
ADMIN_TOKEN = "Bearer admin_test_token"


async def create_test_order(session, initial_state: str) -> str:
    """通过测试接口创建指定初始状态的订单"""
    headers = {
        "Authorization": ADMIN_TOKEN,
        "Content-Type": "application/json",
    }
    payload = {
        "course_id": "COURSE_001",
        "initial_state": initial_state,  # 测试环境专用参数
        "test_mode": True,
    }
    async with session.post(
        f"{BASE_URL}/api/v1/test/orders/create",
        json=payload,
        headers=headers,
    ) as resp:
        data = await resp.json()
        return data.get("order_id")


async def attempt_transition(session, order_id: str, target_state: str) -> dict:
    """尝试将订单转换到目标状态"""
    headers = {
        "Authorization": ADMIN_TOKEN,
        "Content-Type": "application/json",
    }

    # 不同目标状态对应不同的 API 端点
    endpoint_map = {
        "pending":   f"/api/v1/orders/{order_id}/submit",
        "paying":    f"/api/v1/orders/{order_id}/pay",
        "paid":      f"/api/v1/orders/{order_id}/confirm-payment",
        "completed": f"/api/v1/orders/{order_id}/complete",
        "cancelled": f"/api/v1/orders/{order_id}/cancel",
        "refunding": f"/api/v1/orders/{order_id}/refund",
        "refunded":  f"/api/v1/orders/{order_id}/confirm-refund",
        "cart":      f"/api/v1/orders/{order_id}/revert-to-cart",
    }

    endpoint = endpoint_map.get(target_state, f"/api/v1/orders/{order_id}/transition")
    payload = {"target_state": target_state}

    try:
        async with session.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            body = await resp.text()
            return {
                "status": resp.status,
                "body": body,
                "blocked": resp.status in (400, 403, 409, 422),
            }
    except Exception as e:
        return {"status": -1, "body": str(e), "blocked": False, "error": True}


async def test_illegal_transitions():
    """遍历所有非法状态转换"""
    results = {"passed": [], "failed": [], "errors": []}

    async with aiohttp.ClientSession() as session:
        for from_state, to_state in sorted(ILLEGAL_TRANSITIONS):
            # 创建处于 from_state 的测试订单
            order_id = await create_test_order(session, from_state)
            if not order_id:
                results["errors"].append((from_state, to_state, "无法创建测试订单"))
                continue

            # 尝试非法转换
            resp = await attempt_transition(session, order_id, to_state)
            label = f"{from_state} -> {to_state}"

            if resp.get("error"):
                results["errors"].append((from_state, to_state, resp["body"]))
            elif resp["blocked"]:
                results["passed"].append(label)
            else:
                results["failed"].append((label, resp["status"], resp["body"]))

    return results


async def test_payment_amount_tampering():
    """测试支付金额篡改"""
    async with aiohttp.ClientSession() as session:
        # 创建正常订单（假设课程价格 99.00）
        order_id = await create_test_order(session, "paying")

        # 模拟支付回调，但金额不匹配
        tampered_amounts = [0.01, 0, -1, 98.99, 99.01, 9900]
        results = []

        for amount in tampered_amounts:
            payload = {
                "order_id": order_id,
                "paid_amount": amount,
                "payment_channel": "test",
                "transaction_id": f"TXN_TAMPER_{amount}",
            }
            async with session.post(
                f"{BASE_URL}/api/v1/payments/callback",
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                blocked = resp.status in (400, 403, 409, 422)
                results.append({
                    "amount": amount,
                    "status": resp.status,
                    "blocked": blocked,
                })

        return results


async def test_concurrent_pay_and_cancel():
    """并发测试：同时支付和取消同一订单"""
    async with aiohttp.ClientSession() as session:
        order_id = await create_test_order(session, "paying")
        barrier = asyncio.Event()

        async def pay():
            await barrier.wait()
            return await attempt_transition(session, order_id, "paid")

        async def cancel():
            await barrier.wait()
            return await attempt_transition(session, order_id, "cancelled")

        # 创建多组并发任务（放大竞态窗口）
        pay_tasks = [pay() for _ in range(10)]
        cancel_tasks = [cancel() for _ in range(10)]
        all_tasks = asyncio.gather(*(pay_tasks + cancel_tasks))

        barrier.set()
        results = await all_tasks

        pay_success = sum(1 for r in results[:10] if not r.get("blocked", True))
        cancel_success = sum(1 for r in results[10:] if not r.get("blocked", True))

        return {
            "order_id": order_id,
            "pay_success": pay_success,
            "cancel_success": cancel_success,
            "total_success": pay_success + cancel_success,
            "verdict": "PASS" if (pay_success + cancel_success) <= 1 else "FAIL"
        }


def print_state_machine_report(illegal_results, amount_results, concurrent_result):
    """输出状态机测试报告"""
    print("=" * 70)
    print("    订单状态机安全测试报告")
    print("=" * 70)

    # 非法转换
    print("\n[1] 非法状态转换遍历")
    print(f"    测试总数:  {len(ILLEGAL_TRANSITIONS)}")
    print(f"    通过:      {len(illegal_results['passed'])}")
    print(f"    失败:      {len(illegal_results['failed'])}")
    print(f"    错误:      {len(illegal_results['errors'])}")

    if illegal_results["failed"]:
        print("\n    !! 以下非法转换未被阻止:")
        for label, status, body in illegal_results["failed"]:
            print(f"       {label} => HTTP {status}")

    # 金额篡改
    print("\n[2] 支付金额篡改测试")
    if amount_results:
        for r in amount_results:
            status = "BLOCKED" if r["blocked"] else "ALLOWED"
            print(f"    金额 {r['amount']:>10} => HTTP {r['status']} [{status}]")
        unblocked = [r for r in amount_results if not r["blocked"]]
        if unblocked:
            print(f"    [FAIL] {len(unblocked)} 个篡改金额未被拦截！")
        else:
            print("    [PASS] 所有篡改金额均被拦截")

    # 并发支付+取消
    print("\n[3] 并发支付+取消测试")
    print(f"    支付成功次数: {concurrent_result['pay_success']}")
    print(f"    取消成功次数: {concurrent_result['cancel_success']}")
    print(f"    判定: [{concurrent_result['verdict']}]")
    if concurrent_result["verdict"] == "FAIL":
        print("    [FAIL] 订单同时被支付和取消 — 存在竞态条件！")

    print("=" * 70)


async def main():
    print("[*] 开始订单状态机安全测试...\n")

    illegal_results = await test_illegal_transitions()
    amount_results = await test_payment_amount_tampering()
    concurrent_result = await test_concurrent_pay_and_cancel()

    print_state_machine_report(illegal_results, amount_results, concurrent_result)


if __name__ == "__main__":
    asyncio.run(main())
```

### 3.5 curl 快速验证脚本（单行命令）

```bash
#!/usr/bin/env bash
# 快速竞态条件验证 — 用 curl 并发发送请求
# 适用于没有 Python 环境的快速验证场景

BASE_URL="http://localhost:8000"
TOKEN="Bearer test_user_token"
COUPON_ID="COUPON_001"
CONCURRENCY=50
RESULTS_DIR="/tmp/race_test_$$"

mkdir -p "$RESULTS_DIR"

echo "[*] 发送 $CONCURRENCY 个并发优惠券领取请求..."

# 使用 background jobs 实现并发
for i in $(seq 1 $CONCURRENCY); do
    curl -s -o "$RESULTS_DIR/resp_$i.txt" -w "%{http_code}" \
        -X POST "$BASE_URL/api/v1/coupons/claim" \
        -H "Authorization: $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"coupon_id\": \"$COUPON_ID\"}" \
        > "$RESULTS_DIR/status_$i.txt" 2>/dev/null &
done

# 等待所有请求完成
wait

# 统计结果
SUCCESS=0
FAIL=0
for i in $(seq 1 $CONCURRENCY); do
    code=$(cat "$RESULTS_DIR/status_$i.txt" 2>/dev/null)
    if [ "$code" = "200" ]; then
        SUCCESS=$((SUCCESS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
done

echo "============================================"
echo "  成功: $SUCCESS"
echo "  失败: $FAIL"
if [ "$SUCCESS" -eq 1 ]; then
    echo "  [PASS] 竞态防护有效"
elif [ "$SUCCESS" -eq 0 ]; then
    echo "  [WARN] 0 次成功，检查配置"
else
    echo "  [FAIL] 竞态漏洞！成功 $SUCCESS 次"
fi
echo "============================================"

# 清理
rm -rf "$RESULTS_DIR"
```

---

## 四、修复建议

### 4.1 优惠券竞态条件修复

**方案 A：数据库唯一约束（推荐）**

```sql
-- 在 user_coupons 表上添加唯一约束
ALTER TABLE user_coupons ADD UNIQUE INDEX uk_user_coupon (user_id, coupon_id);
```

```python
# 应用层利用唯一约束的幂等写入
def claim_coupon(user_id, coupon_id):
    try:
        db.execute(
            "INSERT INTO user_coupons (user_id, coupon_id, claimed_at) VALUES (?, ?, NOW())",
            user_id, coupon_id
        )
        return "success"
    except IntegrityError:
        return "already_claimed"
```

**方案 B：Redis 分布式锁**

```python
import redis

def claim_coupon_with_lock(user_id, coupon_id):
    r = redis.Redis()
    lock_key = f"coupon_lock:{user_id}:{coupon_id}"

    # SET NX + EX 实现原子锁
    if not r.set(lock_key, "1", nx=True, ex=10):
        return "already_claimed"

    try:
        # 二次确认（防止锁过期后的边界情况）
        if db.query("SELECT 1 FROM user_coupons WHERE user_id=? AND coupon_id=?", user_id, coupon_id):
            return "already_claimed"
        db.execute("INSERT INTO user_coupons ...", user_id, coupon_id)
        return "success"
    finally:
        r.delete(lock_key)
```

**方案 C：SELECT ... FOR UPDATE（悲观锁）**

```python
def claim_coupon_pessimistic(user_id, coupon_id):
    with db.begin():
        # 行级锁，阻塞其他并发事务
        coupon = db.query(
            "SELECT * FROM coupons WHERE id=? FOR UPDATE",
            coupon_id
        )
        if coupon.remaining <= 0:
            return "sold_out"

        existing = db.query(
            "SELECT 1 FROM user_coupons WHERE user_id=? AND coupon_id=?",
            user_id, coupon_id
        )
        if existing:
            return "already_claimed"

        db.execute("INSERT INTO user_coupons ...", user_id, coupon_id)
        db.execute("UPDATE coupons SET remaining = remaining - 1 WHERE id=?", coupon_id)
        return "success"
```

### 4.2 订单状态机修复

**核心原则：状态转换必须是原子的、有约束的**

```python
# 状态机定义 + 数据库乐观锁
class OrderStateMachine:
    TRANSITIONS = {
        "cart":      {"pending"},
        "pending":   {"paying", "cancelled"},
        "paying":    {"paid", "pending"},
        "paid":      {"completed", "refunding"},
        "refunding": {"refunded", "paid"},
        # "completed", "cancelled", "refunded" 为终态，无出边
    }

    @classmethod
    def transition(cls, order_id: str, expected_from: str, target: str):
        allowed = cls.TRANSITIONS.get(expected_from, set())
        if target not in allowed:
            raise ValueError(f"非法转换: {expected_from} -> {target}")

        # 乐观锁：WHERE 子句包含当前状态，防止并发篡改
        rows_affected = db.execute(
            """UPDATE orders
               SET status = ?, updated_at = NOW(), version = version + 1
               WHERE id = ? AND status = ? AND version = ?""",
            target, order_id, expected_from, current_version
        )

        if rows_affected == 0:
            raise ConcurrentModificationError("订单状态已被其他操作修改")

        return True
```

**支付回调金额校验**:

```python
def handle_payment_callback(callback_data):
    order = db.query("SELECT * FROM orders WHERE id=?", callback_data["order_id"])

    # 1. 状态校验
    if order.status != "paying":
        log.warning(f"非法回调：订单 {order.id} 状态为 {order.status}")
        return

    # 2. 金额校验（分级别比较，避免浮点精度问题）
    expected_cents = int(order.total_price * 100)
    actual_cents = int(callback_data["paid_amount"] * 100)
    if expected_cents != actual_cents:
        log.error(f"金额不匹配：期望 {expected_cents}，实际 {actual_cents}")
        raise PaymentAmountMismatch()

    # 3. 幂等性（防重复回调）
    if db.query("SELECT 1 FROM payment_records WHERE txn_id=?", callback_data["transaction_id"]):
        return  # 已处理过

    # 4. 原子状态转换
    OrderStateMachine.transition(order.id, "paying", "paid")
```

---

## 五、测试执行清单

### 第一阶段：环境准备

- [ ] 搭建测试环境（与生产隔离）
- [ ] 准备测试账号和 token
- [ ] 确认优惠券和订单的 API 端点
- [ ] 创建测试专用优惠券（可重置）
- [ ] 部署数据库监控（查询慢日志、锁等待）

### 第二阶段：竞态条件测试

- [ ] RC-01: 单用户 50 并发领取（Python 脚本）
- [ ] RC-01: 单用户 100 并发领取（Go 脚本，更极端）
- [ ] RC-02: 注入 50ms 延迟后重测
- [ ] RC-03: 限量券多用户抢购
- [ ] RC-04: 多 session 并发
- [ ] 每轮测试后检查数据库实际记录数

### 第三阶段：状态机测试

- [ ] SM-01~SM-04: 单个非法转换手动验证
- [ ] SM-09: 自动化遍历全部 48 种非法转换
- [ ] SM-05: 并发支付+取消（10轮）
- [ ] SM-06: 金额篡改（6种金额）
- [ ] SM-07: 负数量/负价格购物车
- [ ] SM-10: 并发修改购物车+下单

### 第四阶段：回归验证

- [ ] 修复后重跑所有失败用例
- [ ] 压测通过标准：连续 10 轮全部 PASS
- [ ] 将测试脚本集成到 CI/CD 流水线

---

## 六、判定标准

| 指标 | PASS | FAIL |
|------|------|------|
| 单用户并发领取 | 成功次数 = 1 | 成功次数 > 1 |
| 限量券发放 | 发放数 <= 限量 | 发放数 > 限量 |
| 非法状态转换 | 100% 被拒绝 | 任何一个通过 |
| 金额篡改 | 100% 被拦截 | 任何一个通过 |
| 并发支付+取消 | 仅一个操作成功 | 两个都成功 |
| 重复支付回调 | 幂等处理 | 重复发放权益 |
