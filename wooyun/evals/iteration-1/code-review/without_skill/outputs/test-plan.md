# 电商下单接口代码审查报告

## 审查对象

`POST /api/order/create` — 电商下单接口

---

## 漏洞清单

### 1. 负数/零数量注入 — 价格操纵

**严重级别: 严重 (Critical)**

`quantity` 未做任何校验。攻击者可传入负数或零：
- `quantity = -10` → `total_price` 变为负数，平台反向"欠"用户钱
- `quantity = 0` → 零元下单，白拿商品
- 浮点数 `quantity = 0.001` → 极低价格购买

```python
# 漏洞触发
POST {"product_id": 1, "quantity": -5}
# total_price = 100 * (-5) = -500
```

**修复建议:**
```python
quantity = data.get('quantity')
if not isinstance(quantity, int) or quantity <= 0:
    return jsonify({'error': '数量必须为正整数'}), 400
```

---

### 2. 优惠券金额未做下限保护 — 负价订单

**严重级别: 严重 (Critical)**

优惠券折扣直接从总价中减去，没有检查结果是否为负：
- 商品总价 50 元，优惠券面额 100 元 → `total_price = -50`
- 配合负数数量可进一步放大

```python
# 当前逻辑
total_price -= coupon.discount_amount  # 无下限保护
```

**修复建议:**
```python
total_price -= coupon.discount_amount
total_price = max(total_price, 0)  # 或设最低支付金额如 0.01
```

---

### 3. 优惠券无使用次数/归属校验 — 无限复用 & 盗用

**严重级别: 严重 (Critical)**

优惠券仅检查 `is_valid`，存在以下问题：
- **无限复用**: 同一优惠券可反复使用，不会标记为已使用
- **无用户绑定**: 任何用户可使用他人的优惠券码
- **无使用条件**: 未检查优惠券适用商品、最低消费门槛等

**修复建议:**
```python
coupon = Coupon.query.filter_by(code=coupon_code).first()
if not coupon:
    return jsonify({'error': '优惠券不存在'}), 400
if not coupon.is_valid:
    return jsonify({'error': '优惠券已失效'}), 400
if coupon.used_count >= coupon.max_usage:
    return jsonify({'error': '优惠券已达使用上限'}), 400
if coupon.user_id and coupon.user_id != current_user.id:
    return jsonify({'error': '无权使用此优惠券'}), 403
if coupon.min_amount and total_price < coupon.min_amount:
    return jsonify({'error': '未达优惠券最低消费'}), 400

# 下单成功后标记优惠券已使用
coupon.used_count += 1
```

---

### 4. 商品不存在时 NoneType 崩溃 — 拒绝服务

**严重级别: 高 (High)**

`Product.query.get(product_id)` 返回 `None` 时，下一行 `product.price * quantity` 直接抛 `AttributeError`，导致 500 错误。攻击者可用不存在的 `product_id` 反复触发服务器异常。

**修复建议:**
```python
product = Product.query.get(product_id)
if not product:
    return jsonify({'error': '商品不存在'}), 404
```

---

### 5. 无库存校验 — 超卖

**严重级别: 高 (High)**

完全没有检查商品库存，可导致：
- 超卖：库存为 0 仍可下单
- 大量无法履约的订单

**修复建议:**
```python
if product.stock < quantity:
    return jsonify({'error': '库存不足'}), 400

# 下单时扣减库存（需配合数据库锁）
product.stock -= quantity
```

---

### 6. 无商品状态校验 — 下架商品可购买

**严重级别: 高 (High)**

未检查商品是否上架/可售。已下架、禁售、预售未开始的商品均可直接购买。

**修复建议:**
```python
if not product.is_on_sale:
    return jsonify({'error': '商品已下架'}), 400
```

---

### 7. 竞态条件 — 并发下单导致超卖/优惠券超用

**严重级别: 高 (High)**

读取库存/优惠券状态与写入之间无锁保护。高并发场景下：
- 多个请求同时读到库存=1，各自下单成功 → 超卖
- 多个请求同时使用同一优惠券 → 优惠券超额使用

**修复建议:**
```python
# 方案1: 数据库行级锁（悲观锁）
product = Product.query.with_for_update().get(product_id)

# 方案2: 乐观锁（version 字段）
Product.query.filter_by(id=product_id, version=product.version)\
    .update({'stock': product.stock - quantity, 'version': product.version + 1})

# 方案3: Redis 分布式锁用于优惠券
```

---

### 8. 输入参数缺失时崩溃 — 拒绝服务

**严重级别: 中 (Medium)**

`data['product_id']` 和 `data['quantity']` 使用硬取值，缺失时抛 `KeyError`。`request.json` 在 Content-Type 不对时返回 `None`，进而抛 `TypeError`。

**修复建议:**
```python
data = request.json
if not data:
    return jsonify({'error': '请求体不能为空'}), 400

product_id = data.get('product_id')
quantity = data.get('quantity')
if not product_id or not quantity:
    return jsonify({'error': '缺少必要参数'}), 400
```

---

### 9. product_id 类型未校验 — SQL 注入 / 异常

**严重级别: 中 (Medium)**

`product_id` 未做类型校验。虽然 SQLAlchemy ORM 的 `.get()` 通常安全，但传入非预期类型（字符串、数组、字典）可能导致异常或在其他 ORM 操作中引发问题。

**修复建议:**
```python
if not isinstance(product_id, int) or product_id <= 0:
    return jsonify({'error': 'product_id 必须为正整数'}), 400
```

---

### 10. 价格使用前端计算结果 — 价格篡改风险

**严重级别: 中 (Medium)**

虽然当前代码从数据库取价格（`product.price`），但价格在内存中计算后直接存入订单，中间没有二次校验机制。如果业务中存在限时价、会员价等动态定价逻辑，缺乏统一价格计算服务会导致价格不一致。

**修复建议:**
```python
# 使用统一价格计算服务
total_price = PriceService.calculate(product, quantity, current_user, coupon)
```

---

### 11. 无购买数量上限 — 恶意囤货 / 整数溢出

**严重级别: 中 (Medium)**

`quantity` 无上限限制，攻击者可传入极大数值：
- `quantity = 999999999` → 恶意囤货
- 极端大数可能导致价格计算溢出

**修复建议:**
```python
MAX_QUANTITY_PER_ORDER = 99
if quantity > MAX_QUANTITY_PER_ORDER:
    return jsonify({'error': f'单次购买不超过{MAX_QUANTITY_PER_ORDER}件'}), 400
```

---

### 12. 无重复下单防护 — 重复提交

**严重级别: 中 (Medium)**

无幂等性保护。用户网络抖动或恶意重复提交可创建多个相同订单。

**修复建议:**
```python
# 方案1: 前端生成唯一请求ID，后端去重
idempotency_key = data.get('idempotency_key')
existing = Order.query.filter_by(idempotency_key=idempotency_key).first()
if existing:
    return jsonify({'order_id': existing.id, 'total': existing.total_price})

# 方案2: Redis 分布式锁 + TTL
```

---

### 13. 事务不完整 — 数据不一致

**严重级别: 中 (Medium)**

当前只有 `add + commit`，如果后续需要扣库存、标记优惠券已用、创建支付单等操作，任一失败会导致数据不一致。缺少完整的事务管理。

**修复建议:**
```python
try:
    product.stock -= quantity
    coupon.used_count += 1
    db.session.add(order)
    db.session.commit()
except Exception:
    db.session.rollback()
    return jsonify({'error': '下单失败，请重试'}), 500
```

---

### 14. 无日志与审计 — 无法追溯异常行为

**严重级别: 低 (Low)**

下单操作无任何日志记录。出现刷单、薅羊毛等异常行为时无法追溯。

**修复建议:**
```python
import logging
logger = logging.getLogger('order')
logger.info(f'用户{current_user.id}下单: product={product_id}, qty={quantity}, '
            f'coupon={coupon_code}, total={total_price}')
```

---

### 15. 响应信息泄露 — 信息收集

**严重级别: 低 (Low)**

当商品不存在或优惠券无效时（修复后），错误消息应统一，避免攻击者通过不同响应枚举有效的商品ID或优惠券码。

**修复建议:** 对外部输入的错误使用统一的模糊错误消息，详细信息仅写日志。

---

## 漏洞严重级别汇总

| 级别 | 数量 | 漏洞编号 |
|------|------|---------|
| 严重 (Critical) | 3 | #1 负数数量, #2 负价订单, #3 优惠券滥用 |
| 高 (High) | 4 | #4 空指针崩溃, #5 超卖, #6 下架可购, #7 竞态条件 |
| 中 (Medium) | 6 | #8 参数缺失, #9 类型校验, #10 价格一致性, #11 数量上限, #12 重复下单, #13 事务完整性 |
| 低 (Low) | 2 | #14 审计日志, #15 信息泄露 |

**总计: 15 个业务逻辑漏洞**

---

## 修复优先级建议

1. **立即修复** (P0): #1, #2, #3, #4, #5, #7 — 直接影响资金安全和数据完整性
2. **尽快修复** (P1): #6, #8, #9, #11, #12, #13 — 影响业务正确性
3. **计划修复** (P2): #10, #14, #15 — 增强健壮性和可观测性
