# CTFshow UA Bypass 经验

## 题目类型
前端UA检测绕过 (User-Agent Bypass)

## 靶场
CTFshow - https://2c7e2635-51bd-4dee-b28e-38b6b462c5f0.challenge.ctf.show

## 解题过程

### 1. 信息收集
- 访问主页，发现是WebGL樱花动画页面
- HTTP头显示CORS配置，暴露自定义头"Aaa"
- Server: nginx/1.20.1

### 2. 发现线索
- 根据提示"有手机就行"，推测与移动端UA有关
- 测试不同User-Agent:
  - Desktop UA -> 返回桌面版页面
  - Android/Mobile UA -> 301重定向到mb.html

### 3. 获取Flag
- 使用 `User-Agent: Mobile` 访问 `/mb.html`
- 直接返回flag: `ctfshow{...}`

## 关键技术点
1. 注意HTTP响应头中的线索（CORS配置的Aaa头暴露移动端逻辑）
2. 根据提示修改User-Agent
3. 跟踪重定向发现隐藏端点

## 通用POC
```python
import requests

url = "TARGET_URL/mb.html"
headers = {'User-Agent': 'Mobile'}
resp = requests.get(url, headers=headers, allow_redirects=False)
print(resp.text)
```
