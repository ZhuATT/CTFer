# -*- coding: utf-8 -*-
"""
CTF Toolkit - Decoder 工具封装
==============================

解码工具封装，提供统一的解码接口。
"""

import sys
import importlib.util
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Literal
from dataclasses import dataclass

# 加载 tools_source/decoder/__init__.py 作为模块
# toolkit/decoder/__init__.py -> toolkit/ -> CTF_agent/ -> tools_source/decoder/__init__.py
decoder_source = Path(__file__).parent.parent.parent / "tools_source" / "decoder" / "__init__.py"
spec = importlib.util.spec_from_file_location("decoder_module", decoder_source)
decoder_module = importlib.util.module_from_spec(spec)
sys.modules['decoder_module'] = decoder_module
spec.loader.exec_module(decoder_module)

# 导出原始函数
_decode = decoder_module.decode
_encode = decoder_module.encode
_auto_decode = decoder_module.auto_decode
_detect_encoding = decoder_module.detect_encoding
get_supported_encodings = decoder_module.get_supported_encodings
DECODERS = decoder_module.DECODERS
ENCODERS = decoder_module.ENCODERS


@dataclass
class DecodeResult:
    """解码结果"""
    success: bool
    result: str
    encoding: str
    steps: List[Dict[str, str]]
    detected: Optional[List[Tuple[str, float]]] = None
    error: Optional[str] = None

    def __str__(self) -> str:
        if self.success:
            output = f"✅ 解码成功 ({self.encoding})\n"
            output += f"结果: {self.result}\n"
            if self.steps:
                output += f"步骤: {len(self.steps)} 层\n"
            return output
        else:
            return f"❌ 解码失败: {self.error or '未知错误'}"

    @property
    def has_flag(self) -> bool:
        """检查结果中是否包含 flag"""
        flag_patterns = ['flag{', 'ctf{', 'flag=', 'ctf=']
        return any(p.lower() in self.result.lower() for p in flag_patterns)

    @property
    def flag(self) -> Optional[str]:
        """提取 flag"""
        import re
        # 常见 flag 格式
        patterns = [
            r'flag\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'flag=[a-zA-Z0-9_]+',
            r'ctf=[a-zA-Z0-9_]+',
            r'[A-Z0-9]{31,}=+',  # Base32/64 风格
        ]
        for pattern in patterns:
            match = re.search(pattern, self.result, re.IGNORECASE)
            if match:
                return match.group(0)
        return None


class DecoderTool:
    """解码工具类"""

    def __init__(self, config: dict, global_config: dict):
        """初始化（仅用于兼容接口）"""
        self.name = "decoder"
        self.config = config
        self.global_config = global_config

    @staticmethod
    def auto_decode(data: str, max_iterations: int = 10) -> DecodeResult:
        """
        自动多层解码

        Args:
            data: 待解码的字符串
            max_iterations: 最大迭代次数

        Returns:
            DecodeResult 解码结果
        """
        result = _auto_decode(data, max_iterations)

        return DecodeResult(
            success=result['success'],
            result=result['result'],
            encoding='auto',
            steps=result.get('steps', []),
            detected=result.get('detected'),
            error=None if result['success'] else "无法解码"
        )

    @staticmethod
    def decode(data: str, encoding: Optional[str] = None,
               auto: bool = True, max_iterations: int = 10) -> DecodeResult:
        """
        解码数据

        Args:
            data: 待解码的字符串
            encoding: 指定编码类型（如 'base64', 'url', 'hex' 等）
            auto: 是否启用自动多层解码（默认 True）
            max_iterations: 最大迭代次数（当 auto=True 时生效）

        Returns:
            DecodeResult 解码结果
        """
        result = _decode(data, encoding, auto, max_iterations)

        return DecodeResult(
            success=result['success'],
            result=result.get('result', data),
            encoding=result.get('encoding', 'unknown'),
            steps=result.get('steps', []),
            detected=result.get('detected'),
            error=result.get('error') if not result['success'] else None
        )

    @staticmethod
    def encode(data: str, encoding: str) -> DecodeResult:
        """
        编码数据

        Args:
            data: 待编码的字符串
            encoding: 编码类型（如 'base64', 'url', 'hex' 等）

        Returns:
            DecodeResult 编码结果
        """
        result = _encode(data, encoding)

        return DecodeResult(
            success=result['success'],
            result=result.get('result', ''),
            encoding=encoding,
            steps=[{'encoding': encoding, 'result': result.get('result', '')}] if result['success'] else [],
            error=result.get('error')
        )

    @staticmethod
    def detect(data: str) -> List[Tuple[str, float]]:
        """
        检测编码类型

        Args:
            data: 待检测的字符串

        Returns:
            [(编码类型, 置信度), ...] 置信度排序列表
        """
        return _detect_encoding(data)

    @staticmethod
    def supported_encodings() -> List[str]:
        """获取支持的编码类型列表"""
        return get_supported_encodings()

    # 便捷方法 - 单个编码类型解码
    @staticmethod
    def base64(data: str) -> DecodeResult:
        """Base64 解码"""
        return DecoderTool.decode(data, encoding='base64', auto=False)

    @staticmethod
    def url(data: str) -> DecodeResult:
        """URL 解码"""
        return DecoderTool.decode(data, encoding='url', auto=False)

    @staticmethod
    def hex(data: str) -> DecodeResult:
        """Hex 解码"""
        return DecoderTool.decode(data, encoding='hex', auto=False)

    @staticmethod
    def unicode(data: str) -> DecodeResult:
        """Unicode 解码"""
        return DecoderTool.decode(data, encoding='unicode', auto=False)

    @staticmethod
    def html(data: str) -> DecodeResult:
        """HTML 实体解码"""
        return DecoderTool.decode(data, encoding='html', auto=False)

    @staticmethod
    def ascii85(data: str) -> DecodeResult:
        """Ascii85 解码"""
        return DecoderTool.decode(data, encoding='ascii85', auto=False)

    @staticmethod
    def base32(data: str) -> DecodeResult:
        """Base32 解码"""
        return DecoderTool.decode(data, encoding='base32', auto=False)


# 创建默认实例（仅用于兼容接口）
_default_instance: Optional[DecoderTool] = None


def get_instance(config: dict, global_config: dict) -> DecoderTool:
    """获取 Decoder 实例（兼容 BaseTool 接口）"""
    global _default_instance
    if _default_instance is None:
        _default_instance = DecoderTool(config, global_config)
    return _default_instance


# 导出常量（兼容原始 decoder 模块）
__all__ = [
    "DecoderTool",
    "DecodeResult",
    "get_instance",
    "decode",
    "encode",
    "auto_decode",
    "detect_encoding",
    "supported_encodings",
]


# 顶层便捷函数（方便直接调用）
def decode(data: str, encoding: Optional[str] = None, auto: bool = True,
           max_iterations: int = 10, config: dict = None, global_config: dict = None) -> DecodeResult:
    """
    顶层便捷解码函数

    Args:
        data: 待解码的字符串
        encoding: 指定编码类型（如 'base64', 'url' 等）
        auto: 是否自动多层解码（默认 True）
        max_iterations: 最大迭代次数
        config: 工具配置（兼容 BaseTool 接口）
        global_config: 全局配置（兼容 BaseTool 接口）

    Returns:
        DecodeResult 解码结果
    """
    return DecoderTool.decode(data, encoding, auto, max_iterations)


def encode(data: str, encoding: str, config: dict = None,
           global_config: dict = None) -> DecodeResult:
    """
    顶层便捷编码函数

    Args:
        data: 待编码的字符串
        encoding: 编码类型（如 'base64', 'url', 'hex' 等）
        config: 工具配置（兼容 BaseTool 接口）
        global_config: 全局配置（兼容 BaseTool 接口）

    Returns:
        DecodeResult 编码结果
    """
    return DecoderTool.encode(data, encoding)


def auto_decode(data: str, max_iterations: int = 10, config: dict = None,
                global_config: dict = None) -> DecodeResult:
    """
    顶层便捷自动解码函数

    Args:
        data: 待解码的字符串
        max_iterations: 最大迭代次数
        config: 工具配置（兼容 BaseTool 接口）
        global_config: 全局配置（兼容 BaseTool 接口）

    Returns:
        DecodeResult 解码结果
    """
    return DecoderTool.auto_decode(data, max_iterations)


def detect_encoding(data: str) -> List[Tuple[str, float]]:
    """
    检测编码类型

    Args:
        data: 待检测的字符串

    Returns:
        [(编码类型, 置信度), ...] 置信度排序列表
    """
    return DecoderTool.detect(data)


def supported_encodings() -> List[str]:
    """获取支持的编码类型列表"""
    return DecoderTool.supported_encodings()
