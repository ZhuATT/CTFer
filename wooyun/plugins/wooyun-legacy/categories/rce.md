# RCE 漏洞分析

> 自动提取于 2026-01-23 18:57
> 样本数量: 3


> 总案例数: 3

### 高频参数
```
  repo: 1次
  apkpackagename: 1次
  error: 1次
  packagename: 1次
  intent: 1次
```

### 典型案例

#### wooyun-2015-0145365
**某搜索引擎输入法安卓版存在远程获取信息控制用户行为漏洞（可恶意推入内容等4G网络内可找到目标）**
- 参数: `repo, apkpackagename, error, packagename, intent`
- Payload: `oreign Address         State       PID/Program namet`

#### wooyun-2014-048949
**114网址导航(app)命令执行**
- Payload: `org/papers/548<script>function execute(cmdArgs) {ret`

#### wooyun-2011-01334
**某电商平台某电商IM工具远程ActiveX溢出0DAY**
- Payload: `<script>var buffer = '';while (buffer.length < 1111) buff`

---


### 攻击模式分布
```
  执行: 3次
```


## 典型案例标题

- 撸啊撸多玩盒子APP远程命令执行漏洞
  漏洞类型：远程代码执行
- dolphin zero APP远程代码执行漏洞
  漏洞类型：远程代码执行
- 飞鱼星路由器命令任意执行可ROOT控制路由
  漏洞类型：远程代码执行

## 高频 Payload 模式
```
org/papers/548我的android系统是4.1.2function execute(cmdA
```
