"""编码修复公用模块
================
解决Windows终端GBK编码问题
"""

import sys
import locale
from typing import Optional, Any


def detect_terminal_encoding() -> str:
    """检测当前终端编码"""
    try:
        encoding = sys.stdout.encoding
        if encoding:
            return encoding.lower()
    except:
        pass

    try:
        encoding = locale.getpreferredencoding()
        if encoding:
            return encoding.lower()
    except:
        pass

    try:
        return sys.getdefaultencoding()
    except:
        pass

    return 'utf-8'


def _get_replacement(ch: str) -> str:
    """将特殊Unicode字符转为ASCII表示"""
    replacements = {
        '✓': '[OK]',
        '✗': '[X]',
        '→': '->',
        '←': '<-',
        '↓': '(down)',
        '↑': '(up)',
        '•': '*',
        '·': '*',
        '—': '-',
        '–': '-',
        '"': '"',
        '"': '"',
        ''': "'",
        ''': "'",
        '…': '...',
        '€': '(EUR)',
        '£': '(GBP)',
        '￥': '¥',
        '©': '(C)',
        '®': '(R)',
        '™': '(TM)',
        '★': '*',
        '☆': '*',
        '●': '*',
        '○': 'o',
        '√': '[OK]',
        '×': 'x',
        '÷': '/',
        '≤': '<=',
        '≥': '>=',
        '≠': '!=',
        '∞': 'inf',
        '±': '+/-',
        '≈': '~=',
        '°': 'deg',
        'µ': 'u',
        '¼': '1/4',
        '½': '1/2',
        '¾': '3/4',
        '²': '^2',
        '³': '^3',
        '¹': '^1',
    }
    return replacements.get(ch, '?')


def encode_for_terminal(text: str, to_ascii: bool = False) -> str:
    """将文本转为终端可安全显示的字符串"""
    if text is None:
        return ""

    if not isinstance(text, str):
        text = str(text)

    encoding = detect_terminal_encoding()

    if encoding in ('utf-8', 'utf8') and not to_ascii:
        return text

    if to_ascii or encoding in ('gbk', 'gb2312', 'gb18030', 'cp1252'):
        result = []
        for ch in text:
            try:
                ch.encode(encoding)
                result.append(ch)
            except UnicodeEncodeError:
                result.append(_get_replacement(ch))
        return ''.join(result)

    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode(encoding, errors='replace').decode(encoding)


def safe_print(text: Any, newline: bool = True, encoding: Optional[str] = None):
    """安全打印文本，自动处理编码问题"""
    if text is None:
        return

    text_str = str(text)

    if encoding is None:
        encoding = detect_terminal_encoding()

    safe_text = encode_for_terminal(text_str, to_ascii=False)

    try:
        sys.stdout.write(safe_text)
        if newline:
            sys.stdout.write('\n')
        sys.stdout.flush()
    except UnicodeEncodeError:
        try:
            encoded = safe_text.encode(encoding, errors='replace')
            if hasattr(sys.stdout, 'buffer'):
                sys.stdout.buffer.write(encoded)
                if newline:
                    sys.stdout.buffer.write(b'\n')
                sys.stdout.buffer.flush()
            else:
                ascii_text = encode_for_terminal(safe_text, to_ascii=True)
                print(ascii_text, end='' if not newline else '\n')
        except Exception:
            print(encode_for_terminal(text_str, to_ascii=True),
                  end='' if not newline else '\n')


class SafePrinter:
    """安全打印机类 - 替代标准print"""

    def __init__(self, encoding: Optional[str] = None):
        self.encoding = encoding or detect_terminal_encoding()

    def print(self, text: Any, newline: bool = True):
        safe_print(text, newline=newline, encoding=self.encoding)

    def info(self, text: Any):
        self.print(f"[INFO] {text}")

    def success(self, text: Any):
        self.print(f"[OK] {text}")

    def warning(self, text: Any):
        self.print(f"[WARN] {text}")

    def error(self, text: Any):
        self.print(f"[ERROR] {text}")

    def bullet(self, text: Any):
        self.print(f"  - {text}")

    def arrow(self, text: Any):
        self.print(f"-> {text}")


# 便捷函数
def print_ok(text: str):
    safe_print(f"[OK] {text}")


def print_info(text: str):
    safe_print(f"[INFO] {text}")


def print_warn(text: str):
    safe_print(f"[WARN] {text}")


def print_error(text: str):
    safe_print(f"[ERROR] {text}")


def print_bullet(text: str):
    safe_print(f"  - {text}")


# 向后兼容
print_safe = safe_print
