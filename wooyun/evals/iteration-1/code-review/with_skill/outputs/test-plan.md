# 电商下单接口安全审计报告

> **方法论：** WooYun 业务逻辑漏洞方法论 v2.0（22,132 个真实案例）
> **审计目标：** `POST /api/order/create` 下单接口
> **审计日期：** 2026-03-06

---

## 第一阶段：业务流程映射

### 业务理解

- **应用类型：** 电商平台
- **核心流程：** 商品浏览 → 下单 → 支付 → 履行
- **参与者：** 已登录用户（`@login_required`）
- **资金流向：** 用户支付 `total_price` 购买商品

### 接口状态转移

```
客户端提交(product_id, quantity, coupon_code)
  → 查询商品价格
  → 计算总价
  → 应用优惠券折扣
  → 创建订单(status='pending')
  → 返回 order_id + total
```

### 信任边界分析

| 边界 | 当前状态 | 风险 |
|------|---------|------|
| 客户端 → 服务器 | `quantity` 由客户端直接传入，无验证 | 高 |
| 客户端 → 服务器 | `product_id` 无存在性校验 | 中 |
| 客户端 → 服务器 | `coupon_code` 无归属/使用次数校验 | 严重 |
| 数据库 → 业务逻辑 | 无事务隔离，存在竞态窗口 | 高 |
| 业务规则 → 输出 | `total_price` 可为负/零，无下限校验 | 严重 |

---

## 第二阶段：假设形成与漏洞发现

共识别 **9 个业务逻辑漏洞**，按严重性降序排列。

---

### 漏洞 1：金额可篡改为负数 — 优惠券折扣无上限

- **严重级别：** 严重（Critical）
- **领域：** 金融 — 金额篡改
- **WooYun 模式：** 金额篡改（176 案例，83.0% 高危）+ 支付绕过（1,056 案例，68.7% 高危）

**漏洞分析：**

```python
total_price = product.price * quantity       # 假设 product.price=10, quantity=1 → 100
total_price -= coupon.discount_amount        # 如果 coupon.discount_amount=200 → total_price = -100
```

代码中 `total_price -= coupon.discount_amount` 后没有任何下限校验。如果优惠券的 `discount_amount` 大于商品总价，`total_price` 将变为**负数**。攻击者可以：

1. 选择低价商品（如 ¥1），搭配高面额优惠券
2. 生成负金额订单，在支付/结算环节可能触发**反向转账**（平台向用户付款）

**WooYun 案例参考：**
- "百度智能微校+中国青少年基金系统可篡改捐款金额" — 金额无下限导致篡改
- "M1905电影网价值2588套餐只要5毛钱" — 价格差异 5000 倍

**统计数据：** WooYun 金额篡改领域 176 个案例中 83.0% 为高危，金融测试铁律明确指出："绝不信任客户端财务计算"。

**修复建议：**

```python
# 1. 服务器端强制价格下限
total_price = max(total_price, 0.01)  # 最低 1 分钱

# 2. 优惠券折扣不能超过商品总价
if coupon.discount_amount >= product.price * quantity:
    discount = product.price * quantity - 0.01  # 最多减到 0.01
else:
    discount = coupon.discount_amount
total_price -= discount
```

---

### 漏洞 2：优惠券无使用次数限制 — 可无限重复使用

- **严重级别：** 严重（Critical）
- **领域：** 金融 — 折扣/优惠券滥用
- **WooYun 模式：** 支付篡改 — 折扣滥用检查清单第 3 项（1,056 案例，68.7% 高危）

**漏洞分析：**

```python
if coupon_code:
    coupon = Coupon.query.filter_by(code=coupon_code).first()
    if coupon and coupon.is_valid:
        total_price -= coupon.discount_amount
    # ← 缺失：coupon.is_valid 未被置为 False
    # ← 缺失：未记录优惠券与订单/用户的绑定关系
    # ← 缺失：未检查该用户是否已使用过此优惠券
```

攻击者可以：
1. 同一个优惠券码在多个订单中**重复使用**
2. 用他人的优惠券码下单（无归属校验）
3. 将过期优惠券与 `is_valid` 未正确维护的情况结合利用

**WooYun 案例参考：**
- 金融域参考文件"折扣/优惠券滥用"检查清单：`重复应用同一优惠券`、`使用过期优惠券`、`使用针对不同产品类别的优惠券`
- "大特宝官网业务逻辑漏洞可免费甚至低款买保险" — 优惠逻辑绕过

**统计数据：** 支付篡改 1,056 个案例中，优惠券滥用是最常见的子攻击向量之一。

**修复建议：**

```python
# 1. 检查优惠券使用次数/用户绑定
if coupon.used_count >= coupon.max_uses:
    return jsonify({'error': '优惠券已用完'}), 400
if CouponUsage.query.filter_by(coupon_id=coupon.id, user_id=current_user.id).first():
    return jsonify({'error': '您已使用过该优惠券'}), 400

# 2. 下单成功后标记优惠券已使用
coupon.used_count += 1
db.session.add(CouponUsage(coupon_id=coupon.id, user_id=current_user.id, order_id=order.id))

# 3. 检查优惠券适用范围（品类/最低消费）
if coupon.min_amount and total_price < coupon.min_amount:
    return jsonify({'error': '未达到优惠券最低消费'}), 400
```

---

### 漏洞 3：竞态条件 — 优惠券/库存并发消耗

- **严重级别：** 严重（Critical）
- **领域：** 逻辑流 — 竞态条件 / TOCTOU
- **WooYun 模式：** 竞态条件（266 案例，74.8% 高危）

**漏洞分析：**

```python
# 线程 A                              # 线程 B
coupon = query(code='SAVE50')          coupon = query(code='SAVE50')
coupon.is_valid → True                 coupon.is_valid → True  (尚未被A消耗)
total_price -= 50                      total_price -= 50
order = Order(...)                     order = Order(...)
db.session.commit()                    db.session.commit()
# 结果：一张一次性优惠券被两个订单同时使用
```

整个 `查询优惠券 → 验证 → 扣减 → 创建订单` 流程没有任何并发控制：
- 无数据库事务隔离（`SELECT ... FOR UPDATE`）
- 无分布式锁（Redis SETNX）
- 无乐观锁（版本号校验）

同理，如果商品有库存限制，也存在**库存超卖**的竞态窗口。

**WooYun 案例参考：**
- 逻辑流域参考文件 TOCTOU 模式：`线程A：检查余额(100) → 足够 → 扣款(100)` 与 `线程B` 并发导致双花
- 金融域"竞态条件"检查清单：`优惠券竞速：并行应用同一单次使用优惠券`、`库存竞速：并行购买最后一件商品`

**统计数据：** 竞态条件类漏洞 266 案例中 74.8% 为高危，在金融操作中尤其致命。

**修复建议：**

```python
# 方案 A：数据库悲观锁
coupon = Coupon.query.filter_by(code=coupon_code).with_for_update().first()

# 方案 B：乐观锁（原子更新）
result = db.session.execute(
    "UPDATE coupons SET used_count = used_count + 1 "
    "WHERE code = :code AND used_count < max_uses",
    {"code": coupon_code}
)
if result.rowcount == 0:
    return jsonify({'error': '优惠券已失效'}), 400

# 方案 C：分布式锁（Redis）
with redis_lock(f"coupon:{coupon_code}", timeout=5):
    # 检查 + 扣减 + 创建订单
```

---

### 漏洞 4：数量（quantity）无验证 — 负数/零/小数/溢出

- **严重级别：** 高（High）
- **领域：** 金融 — 数量篡改
- **WooYun 模式：** 支付篡改 — 数量篡改检查清单（1,056 案例，68.7% 高危）

**漏洞分析：**

```python
quantity = data['quantity']                # 无类型校验、无范围校验
total_price = product.price * quantity     # quantity=-1 → total_price 为负
```

攻击向量：

| 攻击输入 | 效果 |
|---------|------|
| `quantity = 0` | `total_price = 0`，免费下单 |
| `quantity = -1` | `total_price` 为负数，可能触发反向支付 |
| `quantity = 0.001` | 小数购买，可能绕过库存整数检查 |
| `quantity = 99999999` | 整数溢出或库存超卖 |
| `quantity = "abc"` | 类型错误导致 500 服务端异常 |

**WooYun 案例参考：**
- 金融域检查清单明确列出：`数量设为 0（免费商品）`、`数量设为 -1（负数购买 = 退款）`、`数量设为非常大的数字（整数溢出）`、`数量设为小数（0.001 件）`
- "丽子美妆某处严重逻辑漏洞" — 电商数量/金额逻辑绕过

**统计数据：** 数量篡改是支付篡改 1,056 个案例中的第 2 大攻击面，仅次于价格直接篡改。

**修复建议：**

```python
# 严格的服务器端输入验证
if not isinstance(quantity, int) or quantity <= 0:
    return jsonify({'error': '数量必须为正整数'}), 400
if quantity > MAX_ORDER_QUANTITY:  # 业务上限，如 999
    return jsonify({'error': '超出单次购买上限'}), 400
```

---

### 漏洞 5：缺少商品存在性与状态校验

- **严重级别：** 高（High）
- **领域：** 逻辑流 — 设计缺陷 / 业务规则绕过
- **WooYun 模式：** 设计缺陷（1,391 案例，65.3% 高危）

**漏洞分析：**

```python
product = Product.query.get(product_id)
total_price = product.price * quantity     # 如果 product 为 None → AttributeError (500)
```

问题清单：
1. **product 为 None 时无处理** — 不存在的 `product_id` 导致 500 错误，可能泄露服务端堆栈信息
2. **未检查商品状态** — 已下架、未上架、已售罄的商品仍可下单
3. **未检查商品库存** — 可能导致超卖
4. **product_id 类型未校验** — 传入非整数可能触发数据库异常

**WooYun 案例参考：**
- 逻辑流域"设计缺陷"模式：`服务器信任客户端提供的：价格、角色、user_id、权限级别`
- "114票务网某站逻辑漏洞利用支付超时导致上万用户敏感信息泄漏" — 状态校验缺失

**统计数据：** 设计缺陷 1,391 案例中 65.3% 为高危。

**修复建议：**

```python
product = Product.query.get(product_id)
if not product:
    return jsonify({'error': '商品不存在'}), 404
if product.status != 'active':
    return jsonify({'error': '商品已下架'}), 400
if product.stock < quantity:
    return jsonify({'error': '库存不足'}), 400
```

---

### 漏洞 6：缺少幂等性控制 — 重复下单

- **严重级别：** 高（High）
- **领域：** 金融 — 订单篡改
- **WooYun 模式：** 订单篡改（1,227 案例，74.2% 高危）+ 竞态条件

**漏洞分析：**

接口没有任何幂等性机制：
- 无幂等键（idempotency key）
- 无请求去重
- 无前端防抖后的服务端兜底

用户（或攻击者）可以对同一请求快速重复提交，创建大量重复订单。结合优惠券漏洞，可以用同一张优惠券创建 N 个打折订单。

**WooYun 案例参考：**
- 金融域防御模式明确要求：`幂等键：唯一交易 ID，拒绝重复`
- 订单篡改测试协议：`能否多次触发？`

**统计数据：** 订单篡改 1,227 案例中 74.2% 为高危。

**修复建议：**

```python
# 客户端生成唯一请求 ID，服务端校验
idempotency_key = data.get('idempotency_key')
if not idempotency_key:
    return jsonify({'error': '缺少幂等键'}), 400

existing = Order.query.filter_by(idempotency_key=idempotency_key).first()
if existing:
    return jsonify({'order_id': existing.id, 'total': existing.total_price})
```

---

### 漏洞 7：缺少用户维度的订单频率限制

- **严重级别：** 中（Medium）
- **领域：** 逻辑流 — 业务规则绕过
- **WooYun 模式：** 业务规则绕过（266 案例，74.8% 高危）

**漏洞分析：**

接口没有任何频率限制（rate limiting），攻击者可以：
1. 脚本化批量下单，耗尽库存（恶意囤货）
2. 配合优惠券漏洞批量薅羊毛
3. 对系统发起资源耗尽攻击（每次下单都会写数据库）

**WooYun 案例参考：**
- 金融域监控要求：`高频率：每个用户每分钟多个订单/提现`
- 逻辑流域"推荐滥用"模式的变体 — 批量自动化利用

**统计数据：** 业务规则绕过 266 案例中 74.8% 为高危。

**修复建议：**

```python
# Redis 滑动窗口限流
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: current_user.id)

@app.route('/api/order/create', methods=['POST'])
@login_required
@limiter.limit("10/minute")  # 每分钟最多 10 单
def create_order():
    ...
```

---

### 漏洞 8：订单 ID 可预测（顺序整数）

- **严重级别：** 中（Medium）
- **领域：** 授权 — IDOR / 信息泄露
- **WooYun 模式：** 水平权限绕过 / IDOR（1,705 案例，62.3% 高危）

**漏洞分析：**

```python
return jsonify({'order_id': order.id, 'total': total_price})
```

`order.id` 是数据库自增主键（顺序整数），攻击者可以：
1. 通过枚举 `order_id` 推断平台订单量
2. 如果其他接口（如查询订单详情）未做归属校验，可遍历所有订单（IDOR）
3. 通过 ID 差值估算竞争对手的业务量

**WooYun 案例参考：**
- "北京现代某平台越权遍历几百万身份证件/行驶证件" — 顺序 ID 导致批量遍历
- 授权域 IDOR 检查清单：`ID 枚举：遍历 ID 范围`、`UUID 预测（如果使用了顺序 UUID）`

**统计数据：** IDOR 1,705+230 案例中，顺序 ID 是最常见的根因。授权域参考文件指出："简单改 ID 只占案例的 30%"，但这 30% 就是最低成本的攻击。

**修复建议：**

```python
import uuid

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 内部使用
    order_no = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True)

# 对外只暴露 order_no
return jsonify({'order_id': order.order_no, 'total': total_price})
```

---

### 漏洞 9：缺少输入基础校验 — 异常输入导致服务端错误

- **严重级别：** 中（Medium）
- **领域：** 逻辑流 — 设计缺陷
- **WooYun 模式：** 设计缺陷 — 客户端信任（1,391 案例，65.3% 高危）

**漏洞分析：**

```python
data = request.json                    # 如果 Content-Type 不是 JSON → None → TypeError
product_id = data['product_id']        # 如果缺失 → KeyError → 500
quantity = data['quantity']            # 如果缺失 → KeyError → 500
```

未捕获的异常会导致：
1. **500 错误泄露堆栈信息** — 可能暴露文件路径、数据库结构、框架版本
2. **拒绝服务** — 恶意构造的请求体持续触发异常
3. **类型混淆** — `product_id` 传入数组或对象可能触发 ORM 非预期行为

**WooYun 案例参考：**
- 逻辑流域"类型混淆"模式：`字符串 "0" vs 整数 0 vs 布尔值 false`
- 设计缺陷模式：`验证不一致 — 前端验证，后端不验证`

**统计数据：** 设计缺陷 1,391 案例中 65.3% 为高危，其中"客户端信任"是出现频率最高的根因模式。

**修复建议：**

```python
from marshmallow import Schema, fields, validate

class CreateOrderSchema(Schema):
    product_id = fields.Integer(required=True, strict=True)
    quantity = fields.Integer(required=True, strict=True, validate=validate.Range(min=1, max=999))
    coupon_code = fields.String(load_default=None, validate=validate.Length(max=50))

schema = CreateOrderSchema()
errors = schema.validate(request.json or {})
if errors:
    return jsonify({'errors': errors}), 400
```

---

## 第三阶段：漏洞汇总矩阵

| # | 漏洞 | 严重级别 | 领域 | WooYun 案例基数 | 高危占比 |
|---|------|---------|------|---------------|---------|
| 1 | 金额可为负数（优惠券折扣无上限） | **严重** | 金融 | 176 | 83.0% |
| 2 | 优惠券无限重复使用 | **严重** | 金融 | 1,056 | 68.7% |
| 3 | 竞态条件（优惠券/库存并发） | **严重** | 逻辑流 | 266 | 74.8% |
| 4 | 数量无验证（负数/零/溢出） | **高** | 金融 | 1,056 | 68.7% |
| 5 | 商品存在性/状态未校验 | **高** | 逻辑流 | 1,391 | 65.3% |
| 6 | 缺少幂等性（重复下单） | **高** | 金融 | 1,227 | 74.2% |
| 7 | 无订单频率限制 | **中** | 逻辑流 | 266 | 74.8% |
| 8 | 订单 ID 可预测（顺序整数） | **中** | 授权 | 1,705 | 62.3% |
| 9 | 缺少输入基础校验 | **中** | 逻辑流 | 1,391 | 65.3% |

---

## 第四阶段：综合修复方案

### 修复后的参考代码

```python
from marshmallow import Schema, fields, validate
from sqlalchemy import and_
import uuid

class CreateOrderSchema(Schema):
    product_id = fields.Integer(required=True, strict=True)
    quantity = fields.Integer(required=True, strict=True, validate=validate.Range(min=1, max=999))
    coupon_code = fields.String(load_default=None, validate=validate.Length(max=50))
    idempotency_key = fields.String(required=True, validate=validate.Length(min=16, max=64))

@app.route('/api/order/create', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def create_order():
    # [修复9] 输入校验
    schema = CreateOrderSchema()
    data = schema.load(request.json or {})

    product_id = data['product_id']
    quantity = data['quantity']
    coupon_code = data.get('coupon_code')
    idempotency_key = data['idempotency_key']

    # [修复6] 幂等性校验
    existing = Order.query.filter_by(idempotency_key=idempotency_key).first()
    if existing:
        return jsonify({'order_id': existing.order_no, 'total': float(existing.total_price)})

    # [修复5] 商品存在性 + 状态校验
    product = Product.query.get(product_id)
    if not product or product.status != 'active':
        return jsonify({'error': '商品不存在或已下架'}), 400

    # [修复5] 库存校验（悲观锁防竞态）
    product = Product.query.filter_by(id=product_id).with_for_update().first()
    if product.stock < quantity:
        return jsonify({'error': '库存不足'}), 400

    # [修复4] 数量已由 Schema 校验为正整数

    # 服务器端计算总价（绝不信任客户端）
    total_price = product.price * quantity
    discount = 0

    if coupon_code:
        # [修复3] 悲观锁防优惠券竞态
        coupon = Coupon.query.filter_by(code=coupon_code).with_for_update().first()

        if not coupon or not coupon.is_valid:
            return jsonify({'error': '优惠券无效'}), 400

        # [修复2] 检查使用次数 + 用户维度去重
        if coupon.used_count >= coupon.max_uses:
            return jsonify({'error': '优惠券已用完'}), 400
        if CouponUsage.query.filter_by(coupon_id=coupon.id, user_id=current_user.id).first():
            return jsonify({'error': '您已使用过该优惠券'}), 400

        # [修复1] 折扣不能超过商品总价，且总价不能为负
        discount = min(coupon.discount_amount, total_price - Decimal('0.01'))
        total_price -= discount

        # 标记优惠券已使用
        coupon.used_count += 1

    # [修复1] 最终兜底：总价必须 > 0
    if total_price <= 0:
        return jsonify({'error': '订单金额异常'}), 400

    # 扣减库存
    product.stock -= quantity

    # [修复8] 使用不可预测的订单号
    order = Order(
        user_id=current_user.id,
        product_id=product_id,
        quantity=quantity,
        total_price=total_price,
        status='pending',
        order_no=str(uuid.uuid4()),
        idempotency_key=idempotency_key
    )
    db.session.add(order)

    if coupon_code:
        db.session.add(CouponUsage(
            coupon_id=coupon.id,
            user_id=current_user.id,
            order_id=order.id
        ))

    db.session.commit()

    return jsonify({'order_id': order.order_no, 'total': float(total_price)})
```

### 架构层面加固建议

| 措施 | 目标漏洞 | 实现方式 |
|------|---------|---------|
| 分布式锁 | 竞态条件 | Redis SETNX，金融操作必须串行化 |
| 消息队列 | 幂等性 + 一致性 | 订单创建异步化，恰好一次语义 |
| 对账系统 | 金额篡改 | 每日自动对账：订单金额 vs 实际收款 |
| 异常监控 | 全部 | 告警规则：金额≤0.01 / 单用户高频下单 / 优惠券异常使用 |
| WAF 规则 | 输入校验 | 拦截非 JSON 请求体、超大 payload |

---

## WooYun 统计总结

本次审计覆盖的 WooYun 漏洞模式及对应案例总量：

| 模式 | WooYun 案例数 | 本接口命中 |
|------|-------------|-----------|
| 支付篡改（含金额/数量/优惠券） | 1,056 | 漏洞 1, 2, 4 |
| 订单篡改 | 1,227 | 漏洞 6 |
| 竞态条件 / TOCTOU | 266 | 漏洞 3 |
| 设计缺陷 | 1,391 | 漏洞 5, 9 |
| IDOR / 水平越权 | 1,705 | 漏洞 8 |
| 业务规则绕过 | 266 | 漏洞 7 |
| **合计覆盖** | **5,911** | **9 个漏洞** |

> 28 行代码，9 个业务逻辑漏洞。WooYun 22,132 个案例反复证明：**业务逻辑漏洞无法通过扫描器发现，它们藏在开发者的"本意"与代码"实际允许"之间的空隙中。**
