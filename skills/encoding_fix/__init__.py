"""编码修复公用模块
================
解决Windows终端GBK编码问题
"""

import sys
import os
import locale
from typing import Optional, Any


def detect_terminal_encoding() -> str:
    """检测当前终端编码

    注意：Windows Git Bash/MSYS2 环境下 sys.stdout.encoding 可能返回 gbk，
    但实际终端支持 UTF-8，需要特殊处理
    """
    import platform

    # 检查是否在 MSYS2/MinGW 环境（Git Bash）
    msystem = os.environ.get('MSYSTEM', '')
    term = os.environ.get('TERM', '')
    if 'MINGW' in msystem or 'MSYS' in msystem or 'bash' in term.lower():
        # MSYS2/MinGW 环境，实际支持 UTF-8
        return 'utf-8'

    # Windows cmd/PowerShell 环境
    if platform.system() == 'Windows':
        # 检查 PYTHONIOENCODING 环境变量
        py_enc = os.environ.get('PYTHONIOENCODING', '')
        if py_enc:
            return py_enc.lower()

        # 检查是否使用 Windows Terminal 或支持 UTF-8 的终端
        # Windows Terminal 会设置 WT_SESSION 或 TERM_PROGRAM=wtsm
        wt_session = os.environ.get('WT_SESSION')
        term_program = os.environ.get('TERM_PROGRAM')
        if wt_session or term_program in ('WindowsTerminal', 'vscode'):
            return 'utf-8'

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
        '⚠': '[WARN]',      # U+26A0 WARNING SIGN
        '⚡': '[HIGH]',      # U+26A1 HIGH VOLTAGE
        '✅': '[OK]',       # U+2705 WHITE HEAVY CHECK MARK
        '❌': '[X]',        # U+274C CROSS MARK
        '🔥': '[HOT]',      # U+1F525 FIRE
        '💀': '[DEAD]',     # U+1F480 SKULL
        '🛡': '[SHIELD]',   # U+1F6E1 SHIELD
        '💡': '[IDEA]',     # U+1F4A1 LIGHT BULB
        '📌': '[PIN]',      # U+1F4CC PUSHPIN
        '⚙': '[GEAR]',      # U+2699 GEAR
        '🔍': '[SEARCH]',   # U+1F50D MAGNIFYING GLASS
        '🔐': '[LOCK]',     # U+1F510 LOCK
        '🔓': '[UNLOCK]',   # U+1F511 OPEN LOCK
    }
    return replacements.get(ch, '?')


def encode_for_terminal(text: str, to_ascii: bool = False) -> str:
    """将文本转为终端可安全显示的字符串

    策略：
    1. UTF-8 环境直接返回原文
    2. GBK 环境先尝试用 GBK 编码，替换无法编码的字符
    3. 如果替换字符过多（>10%），说明编码检测不准确，尝试 UTF-8
    4. MSYS2/Git Bash 环境下返回 UTF-8 编码的 bytes（print() 可直接输出）

    Returns:
        str: 正常情况下返回字符串
        bytes: MSYS2/Git Bash 环境下返回 UTF-8 编码的字节
    """
    if text is None:
        return ""

    if not isinstance(text, str):
        text = str(text)

    encoding = detect_terminal_encoding()

    # MSYS2/Git Bash 特殊处理：返回 UTF-8 编码的 bytes
    # 这样 print() 可以直接输出而不需要编码转换
    stdout_encoding = sys.stdout.encoding or ''
    is_msys2 = (
        encoding in ('utf-8', 'utf8')
        and stdout_encoding.lower() in ('gbk', 'gb2312', 'gb18030', 'cp1252', 'cp936')
    )

    if is_msys2:
        # 返回 UTF-8 编码的 bytes，让 print() 直接处理
        return text.encode('utf-8')

    if encoding in ('utf-8', 'utf8') and not to_ascii:
        return text

    if to_ascii:
        result = []
        for ch in text:
            if ord(ch) < 128:
                result.append(ch)
            else:
                result.append(_get_replacement(ch))
        return ''.join(result)

    # 对 GBK 系列编码进行处理
    if encoding in ('gbk', 'gb2312', 'gb18030', 'cp1252'):
        result = []
        replacement_count = 0
        for ch in text:
            try:
                ch.encode(encoding)
                result.append(ch)
            except UnicodeEncodeError:
                result.append(_get_replacement(ch))
                replacement_count += 1

        # 如果替换字符过多，说明编码检测不准确，尝试 UTF-8
        if len(text) > 0 and replacement_count / len(text) > 0.1:
            # 回退到 UTF-8 尝试
            try:
                text.encode('utf-8')
                return text  # UTF-8 可以编码，直接返回原文
            except UnicodeEncodeError:
                pass  # 保持原结果

        return ''.join(result)

    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        return text.encode(encoding, errors='replace').decode(encoding)


def safe_print(text: Any, newline: bool = True, encoding: Optional[str] = None):
    """安全打印文本，自动处理编码问题

    此函数是 print() 的安全替代，会自动处理各种编码场景。
    推荐在需要输出中文或特殊字符时使用此函数。
    """
    if text is None:
        return

    text_str = str(text)

    if encoding is None:
        encoding = detect_terminal_encoding()

    safe_text = encode_for_terminal(text_str, to_ascii=False)

    # 检查是否需要强制使用 UTF-8
    # 场景：检测到终端支持 UTF-8，但 sys.stdout.encoding 仍是 gbk (Git Bash 场景)
    stdout_encoding = sys.stdout.encoding or ''
    needs_utf8_buffer = (
        encoding in ('utf-8', 'utf8')
        and stdout_encoding.lower() in ('gbk', 'gb2312', 'gb18030', 'cp1252', 'cp936')
        and hasattr(sys.stdout, 'buffer')
    )

    try:
        if needs_utf8_buffer:
            # 使用 buffer 直接写入 UTF-8 字节
            if isinstance(safe_text, bytes):
                # safe_text 已经是 UTF-8 编码的 bytes
                sys.stdout.buffer.write(safe_text)
            else:
                encoded = safe_text.encode('utf-8')
                sys.stdout.buffer.write(encoded)
            if newline:
                sys.stdout.buffer.write(b'\n')
            sys.stdout.buffer.flush()
        else:
            sys.stdout.write(safe_text)
            if newline:
                sys.stdout.write('\n')
            sys.stdout.flush()
    except UnicodeEncodeError:
        try:
            if isinstance(safe_text, bytes):
                encoded = safe_text
            else:
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
