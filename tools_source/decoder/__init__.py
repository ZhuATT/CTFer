# -*- coding: utf-8 -*-
"""
CTF Decoder - 解码工具模块
提供常见的编码/解码功能，供agent调用
"""

import base64
import urllib.parse
import binascii
import html
import re
from typing import Optional, Dict, Any, List, Tuple, Union


def base64_encode(data: Union[str, bytes]) -> str:
    """Base64编码
    
    将字符串或字节数据进行Base64编码
    
    Args:
        data: 要编码的字符串或字节数据
        
    Returns:
        编码后的Base64字符串
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def base64_decode(data: str) -> Optional[str]:
    """Base64解码
    
    将Base64字符串解码为原始数据
    
    Args:
        data: Base64编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        # 尝试标准Base64
        result = base64.b64decode(data, validate=True)
        return result.decode('utf-8', errors='strict')
    except Exception:
        try:
            # 尝试URL安全的Base64
            result = base64.urlsafe_b64decode(data)
            return result.decode('utf-8', errors='strict')
        except Exception:
            return None


def url_encode(data: str, safe: str = '') -> str:
    """URL编码
    
    对字符串进行URL编码
    
    Args:
        data: 要编码的字符串
        safe: 不需要编码的字符集合
        
    Returns:
        编码后的URL字符串
    """
    return urllib.parse.quote(data, safe=safe)


def url_decode(data: str) -> Optional[str]:
    """URL解码
    
    对URL编码的字符串进行解码
    
    Args:
        data: URL编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        return urllib.parse.unquote(data)
    except Exception:
        return None


def hex_encode(data: Union[str, bytes]) -> str:
    """Hex编码
    
    将字符串或字节数据转换为十六进制表示
    
    Args:
        data: 要编码的字符串或字节数据
        
    Returns:
        编码后的Hex字符串
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return binascii.hexlify(data).decode('ascii')


def hex_decode(data: str) -> Optional[str]:
    """Hex解码
    
    将Hex字符串解码为原始数据
    
    Args:
        data: Hex编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        # 移除可能的0x前缀或空格
        data = data.replace('0x', '').replace(' ', '')
        result = binascii.unhexlify(data)
        return result.decode('utf-8', errors='strict')
    except Exception:
        return None


def unicode_encode(data: str) -> str:
    r"""Unicode编码 (\uXXXX格式)
    
    将字符串转换为Unicode转义序列
    
    Args:
        data: 要编码的字符串
        
    Returns:
        Unicode编码后的字符串
    """
    result = []
    for char in data:
        code = ord(char)
        if code > 127:
            result.append(f'\\u{code:04x}')
        else:
            result.append(char)
    return ''.join(result)


def unicode_decode(data: str) -> Optional[str]:
    """Unicode解码
    
    将Unicode转义序列解码为原始字符串
    
    Args:
        data: Unicode编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        # 处理 \uXXXX 格式
        result = re.sub(r'\\u([0-9a-fA-F]{4})', 
                       lambda m: chr(int(m.group(1), 16)), data)
        # 处理 \xXX 格式
        result = re.sub(r'\\x([0-9a-fA-F]{2})', 
                       lambda m: chr(int(m.group(1), 16)), result)
        return result
    except Exception:
        return None


def html_encode(data: str) -> str:
    """HTML实体编码
    
    将字符串转换为HTML实体
    
    Args:
        data: 要编码的字符串
        
    Returns:
        HTML实体编码后的字符串
    """
    return html.escape(data)


def html_decode(data: str) -> Optional[str]:
    """HTML实体解码
    
    将HTML实体解码为原始字符串
    
    Args:
        data: HTML实体编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        return html.unescape(data)
    except Exception:
        return None


def ascii85_encode(data: Union[str, bytes]) -> str:
    """Ascii85编码
    
    将数据进行Ascii85编码（Adobe PDF标准）
    
    Args:
        data: 要编码的字符串或字节数据
        
    Returns:
        Ascii85编码后的字符串
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.a85encode(data).decode('ascii')


def ascii85_decode(data: str) -> Optional[str]:
    """Ascii85解码
    
    将Ascii85字符串解码为原始数据
    
    Args:
        data: Ascii85编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        result = base64.a85decode(data)
        return result.decode('utf-8', errors='strict')
    except Exception:
        return None


def base32_encode(data: Union[str, bytes]) -> str:
    """Base32编码
    
    将字符串或字节数据进行Base32编码
    
    Args:
        data: 要编码的字符串或字节数据
        
    Returns:
        编码后的Base32字符串
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b32encode(data).decode('ascii')


def base32_decode(data: str) -> Optional[str]:
    """Base32解码
    
    将Base32字符串解码为原始数据
    
    Args:
        data: Base32编码的字符串
        
    Returns:
        解码后的字符串，失败返回None
    """
    try:
        result = base64.b32decode(data, casefold=True)
        return result.decode('utf-8', errors='strict')
    except Exception:
        return None


# 编码检测和解码器映射
DECODERS: Dict[str, callable] = {
    'base64': base64_decode,
    'url': url_decode,
    'hex': hex_decode,
    'unicode': unicode_decode,
    'html': html_decode,
    'ascii85': ascii85_decode,
    'base32': base32_decode,
}

ENCODERS: Dict[str, callable] = {
    'base64': base64_encode,
    'url': url_encode,
    'hex': hex_encode,
    'unicode': unicode_encode,
    'html': html_encode,
    'ascii85': ascii85_encode,
    'base32': base32_encode,
}


def detect_encoding(data: str) -> List[Tuple[str, float]]:
    """自动检测编码类型
    
    根据数据特征猜测可能的编码类型，返回置信度排序列表
    
    Args:
        data: 待检测的字符串
        
    Returns:
        [(编码类型, 置信度), ...] 列表，置信度0-1
    """
    results = []
    data_stripped = data.strip()
    
    # 检测Base64: 只包含A-Za-z0-9+/=，长度是4的倍数（但放宽长度限制，允许短字符串）
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
    if base64_pattern.match(data_stripped) and len(data_stripped) >= 4:
        # 尝试解码验证
        if base64_decode(data_stripped):
            results.append(('base64', 0.9))
    
    # 检测URL编码: 包含%XX格式
    url_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
    if url_pattern.search(data_stripped):
        if url_decode(data_stripped):
            results.append(('url', 0.85))
    
    # 检测Hex: 只包含0-9A-Fa-f，至少4位且偶数长度，排除纯数字
    hex_pattern = re.compile(r'^[0-9A-Fa-f]+$')
    if (hex_pattern.match(data_stripped) and len(data_stripped) >= 4 
        and len(data_stripped) % 2 == 0 
        and not data_stripped.isdigit()):  # 排除纯数字
        if hex_decode(data_stripped):
            results.append(('hex', 0.8))
    
    # 检测Unicode: 包含\uXXXX或\xXX
    unicode_pattern = re.compile(r'\\[ux][0-9A-Fa-f]{2,4}')
    if unicode_pattern.search(data_stripped):
        if unicode_decode(data_stripped):
            results.append(('unicode', 0.9))
    
    # 检测HTML实体: 包含&xxx;或&#xxx;格式
    html_pattern = re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9A-Fa-f]+;')
    if html_pattern.search(data_stripped):
        if html_decode(data_stripped):
            results.append(('html', 0.85))
    
    # 检测Base32: 只包含A-Z2-7=
    base32_pattern = re.compile(r'^[A-Z2-7]+=*$')
    if base32_pattern.match(data_stripped) and len(data_stripped) % 8 == 0:
        if base32_decode(data_stripped):
            results.append(('base32', 0.7))
    
    # 按置信度排序
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def auto_decode(data: str, max_iterations: int = 10) -> Dict[str, Any]:
    """自动解码（支持多层嵌套）
    
    自动检测编码类型并进行循环解码，直到得到明文
    
    Args:
        data: 待解码的字符串
        max_iterations: 最大迭代次数，防止无限循环
        
    Returns:
        包含解码结果的字典:
        {
            'success': bool,
            'result': str - 最终解码结果,
            'steps': [{'encoding': str, 'result': str}, ...] - 解码步骤,
            'detected': List[Tuple[str, float]] - 检测到的编码类型
        }
    """
    current = data
    steps = []
    detected = detect_encoding(data)
    
    for i in range(max_iterations):
        # 尝试自动检测到的编码
        encodings_tried = set()
        
        # 首先尝试检测到的编码
        for encoding_name, _ in detected:
            if encoding_name in encodings_tried:
                continue
            encodings_tried.add(encoding_name)
            
            decoder = DECODERS.get(encoding_name)
            if decoder:
                result = decoder(current)
                if result and result != current:
                    steps.append({
                        'encoding': encoding_name,
                        'result': result[:200]  # 限制长度
                    })
                    current = result
                    # 重新检测新的编码
                    detected = detect_encoding(current)
                    break
        
        # 如果没有成功解码，尝试所有解码器
        if len(steps) == i + 1:  # 没有新增步骤
            for encoding_name, decoder in DECODERS.items():
                if encoding_name in encodings_tried:
                    continue
                try:
                    result = decoder(current)
                    if result and result != current:
                        steps.append({
                            'encoding': encoding_name,
                            'result': result[:200]
                        })
                        current = result
                        break
                except Exception:
                    pass
            else:
                # 所有解码器都尝试过了
                break
        
        # 检查是否已经是明文（不可再解码）
        if not detect_encoding(current):
            break
    
    return {
        'success': len(steps) > 0,
        'result': current,
        'steps': steps,
        'detected': detected
    }


def decode(data: str, encoding: Optional[str] = None, 
           auto: bool = True, max_iterations: int = 10) -> Dict[str, Any]:
    """统一解码接口
    
    主解码函数，支持指定编码类型或自动检测
    
    Args:
        data: 待解码的字符串
        encoding: 指定编码类型（如'base64', 'url'等），None表示自动检测
        auto: 是否启用自动多层解码
        max_iterations: 最大迭代次数
        
    Returns:
        包含解码结果的字典:
        {
            'success': bool,
            'result': str - 解码结果,
            'encoding': str - 检测/使用的编码类型,
            'steps': List[Dict] - 解码步骤（如果auto=True）,
            'error': str - 错误信息（如果失败）
        }
    """
    # 指定编码类型
    if encoding:
        encoding = encoding.lower()
        decoder = DECODERS.get(encoding)
        if not decoder:
            return {
                'success': False,
                'result': '',
                'encoding': encoding,
                'error': f'不支持的编码类型: {encoding}'
            }
        
        result = decoder(data)
        if result is None:
            return {
                'success': False,
                'result': data,
                'encoding': encoding,
                'error': f'{encoding}解码失败'
            }
        
        return {
            'success': True,
            'result': result,
            'encoding': encoding,
            'steps': [{'encoding': encoding, 'result': result}]
        }
    
    # 自动解码
    if auto:
        return auto_decode(data, max_iterations)
    
    # 不自动解码，只尝试检测
    detected = detect_encoding(data)
    if detected:
        encoding_name = detected[0][0]
        decoder = DECODERS[encoding_name]
        result = decoder(data)
        return {
            'success': result is not None,
            'result': result or data,
            'encoding': encoding_name,
            'detected': detected
        }
    
    return {
        'success': False,
        'result': data,
        'encoding': 'unknown',
        'detected': []
    }


def encode(data: str, encoding: str) -> Dict[str, Any]:
    """统一编码接口
    
    对字符串进行指定类型的编码
    
    Args:
        data: 待编码的字符串
        encoding: 编码类型（如'base64', 'url'等）
        
    Returns:
        包含编码结果的字典:
        {
            'success': bool,
            'result': str - 编码结果,
            'encoding': str - 使用的编码类型,
            'error': str - 错误信息（如果失败）
        }
    """
    encoding = encoding.lower()
    encoder = ENCODERS.get(encoding)
    
    if not encoder:
        return {
            'success': False,
            'result': '',
            'encoding': encoding,
            'error': f'不支持的编码类型: {encoding}'
        }
    
    try:
        result = encoder(data)
        return {
            'success': True,
            'result': result,
            'encoding': encoding
        }
    except Exception as e:
        return {
            'success': False,
            'result': '',
            'encoding': encoding,
            'error': str(e)
        }


def get_supported_encodings() -> List[str]:
    """获取支持的编码类型列表
    
    Returns:
        支持的编码类型名称列表
    """
    return list(DECODERS.keys())


# 模块级便捷函数
def decode_base64(data: str) -> Optional[str]:
    """Base64解码便捷函数"""
    return base64_decode(data)


def decode_url(data: str) -> Optional[str]:
    """URL解码便捷函数"""
    return url_decode(data)


def decode_hex(data: str) -> Optional[str]:
    """Hex解码便捷函数"""
    return hex_decode(data)


def decode_unicode(data: str) -> Optional[str]:
    """Unicode解码便捷函数"""
    return unicode_decode(data)


def decode_html(data: str) -> Optional[str]:
    """HTML解码便捷函数"""
    return html_decode(data)
