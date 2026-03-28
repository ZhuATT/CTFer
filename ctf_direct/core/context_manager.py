"""
Context Manager - 上下文压缩管理器
参考 H-Pentest 的 ContextManager 实现
"""
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def count_tokens(text: str) -> int:
    """
    简单 token 估算（不依赖 tiktoken）
    中文：每字符约 1-2 token
    英文：每词约 1.3 token
    """
    if not text:
        return 0
    # 粗略估算：中文按字符，英文按空格分割
    chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    english_words = len([w for w in text.split() if w.strip()])
    # 经验估算
    return int(chinese_chars * 1.5 + english_words * 1.3)


def compress_messages(
    messages: List[Dict[str, str]],
    max_tokens: int = 8000,
    target_tokens: Optional[int] = None
) -> List[Dict[str, str]]:
    """
    压缩消息列表，保留关键信息

    策略：
    1. 保留 system message
    2. 保留最近 N 条消息
    3. 中间消息如果过长则截断或总结
    """
    if target_tokens is None:
        target_tokens = int(max_tokens * 0.8)

    total_tokens = sum(count_tokens(m.get('content', '')) for m in messages)
    if total_tokens <= target_tokens:
        return messages

    compressed = []
    system_msgs = [m for m in messages if m.get('role') == 'system']
    other_msgs = [m for m in messages if m.get('role') != 'system']

    # 保留 system
    compressed.extend(system_msgs)

    # 如果其他消息 token 数已经超限，从最新的开始保留
    other_tokens = sum(count_tokens(m.get('content', '')) for m in other_msgs)
    if other_tokens > target_tokens:
        # 从最新消息开始保留，直到达到目标
        kept = []
        kept_tokens = sum(count_tokens(m.get('content', '')) for m in system_msgs)

        for msg in reversed(other_msgs):
            msg_tokens = count_tokens(msg.get('content', ''))
            if kept_tokens + msg_tokens <= target_tokens:
                kept.insert(0, msg)
                kept_tokens += msg_tokens
            else:
                # 截断此消息而非完全丢弃
                content = msg.get('content', '')
                max_chars = int(target_tokens - kept_tokens) * 2  # 粗略估算
                if max_chars > 50:
                    msg = {**msg, 'content': content[:max_chars] + '...[compressed]'}
                    kept.insert(0, msg)
                break

        other_msgs = kept

    compressed.extend(other_msgs)
    return compressed


class ContextManager:
    """
    CTF 专用上下文管理器

    功能：
    1. Token 计数（基于字符估算）
    2. 消息压缩（保留 system + recent + 高优先级）
    3. 高优先级内容识别
    """

    def __init__(self, max_tokens: int = 8000):
        self.max_tokens = max_tokens
        self.target_tokens = int(max_tokens * 0.8)

    def count_tokens(self, text: str) -> int:
        """计算文本 token 数"""
        return count_tokens(text)

    def count_messages_tokens(self, messages: List[Dict[str, str]]) -> int:
        """计算消息列表总 token 数"""
        return sum(self.count_tokens(m.get('content', '')) for m in messages)

    def should_compress(self, messages: List[Dict[str, str]]) -> bool:
        """判断是否需要压缩"""
        return self.count_messages_tokens(messages) > self.target_tokens

    def compress(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """压缩消息列表"""
        return compress_messages(messages, self.max_tokens, self.target_tokens)

    def get_priority_content(self, message: Dict[str, str]) -> float:
        """
        获取消息优先级分数

        优先级：
        - system: 1.0
        - user (含 flag/FLAG): 0.9
        - assistant (含工具调用结果): 0.8
        - recent: 基于位置衰减
        """
        role = message.get('role', '')
        content = message.get('content', '')

        if role == 'system':
            return 1.0

        if role == 'user':
            if any(kw in content for kw in ['FLAG{', 'flag{', 'flag:', 'Flag:']):
                return 0.95
            return 0.7

        if role == 'assistant':
            # 工具调用结果优先级更高
            if 'tool' in content.lower() or 'execute' in content.lower():
                return 0.8
            # 推理过程优先级较低
            if 'think' in content.lower() or '推理' in content:
                return 0.4
            return 0.6

        return 0.5

    def smart_compress(
        self,
        messages: List[Dict[str, str]],
        preserve_high_priority: bool = True
    ) -> List[Dict[str, str]]:
        """
        智能压缩：保留高优先级消息

        Args:
            messages: 原始消息列表
            preserve_high_priority: 是否保留高优先级消息
        """
        if not self.should_compress(messages):
            return messages

        if not preserve_high_priority:
            return self.compress(messages)

        # 分类消息
        system_msgs = [m for m in messages if m.get('role') == 'system']
        recent_msgs = messages[-5:] if len(messages) > 5 else messages
        middle_msgs = messages[len(system_msgs):-5] if len(messages) > 5 else []

        # 保留 system
        result = list(system_msgs)

        # 保留最近消息
        result.extend(recent_msgs)

        # 如果仍超限，压缩中间消息
        if self.count_messages_tokens(result) > self.target_tokens:
            # 简单策略：只保留最近消息
            result = list(system_msgs) + messages[-10:] if len(messages) > 10 else list(system_msgs) + messages

        return result
