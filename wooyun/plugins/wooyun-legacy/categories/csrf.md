# CSRF 漏洞分析

> 自动提取于 2026-01-23 18:57
> 样本数量: 3


> 总案例数: 3

## 高频参数
```
  url: 1次
  desc: 1次
  callback: 1次
  get_recent_photos: 1次
  _: 1次
```


## 典型案例标题

- 格瓦拉生活网多处CSRF可刷粉，发影评及回复
  漏洞类型：CSRF
- 某相册服务CSRF保存图片
  漏洞类型：CSRF
- 佳品网CSRF可登陆任意用户漏洞
  漏洞类型：CSRF

## 高频 Payload 模式
```
orm action="https://example.com/[已脱敏]
```
