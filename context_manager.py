"""
CTF Context Manager - 基于 tiktoken 的智能上下文压缩
"""
from typing import Dict, Any, List, Optional

# tiktoken 可能未安装，使用 fallback
try:
    import tiktoken
    _HAS_TIKTOKEN = True
except ImportError:
    _HAS_TIKTOKEN = False
    tiktoken = None


class CTFContextManager:
    """CTF 专用上下文管理器"""

    def __init__(self, max_tokens: int = 8000):
        self.max_tokens = max_tokens
        self.encoding = None
        if _HAS_TIKTOKEN:
            try:
                self.encoding = tiktoken.get_encoding("cl100k_base")
            except Exception:
                self.encoding = None

    def count_tokens(self, text: str) -> int:
        """计算 token 数量（智能估算）"""
        if not self.encoding:
            chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
            other_chars = len(text) - chinese_chars
            return int(chinese_chars / 1.5 + other_chars / 4)
        try:
            return len(self.encoding.encode(text))
        except Exception:
            return len(text) // 4

    def count_dict_tokens(self, data: Dict[str, Any]) -> int:
        """计算字典的 token 数量"""
        return self.count_tokens(str(data))

    def compress_context(self, context: Dict[str, Any], target_ratio: float = 0.8) -> Dict[str, Any]:
        """
        压缩上下文，保留关键信息

        策略：
        1. 保留：taxonomy_signals（漏洞类型决定攻击方向）
        2. 保留：planner_signals（已知端点、参数、状态）
        3. 保留：skill（当前题型针对性知识）
        4. 保留：rag_knowledge（WooYun 相似题目）
        5. 压缩：experiences, pocs, tips（LLM 总结）
        6. 压缩：action_history（只保留最近 5 步）
        """
        if target_ratio is None:
            target_ratio = 0.8

        target_tokens = int(self.max_tokens * target_ratio)
        current_tokens = self.count_dict_tokens(context)

        if current_tokens <= target_tokens:
            return context

        compressed = context.copy()

        # 压缩 resources
        if "resources" in context:
            compressed["resources"] = self._compress_resources(context.get("resources", {}))

        # 压缩 action_history
        if "action_history" in context and isinstance(context["action_history"], list):
            action_history = context["action_history"]
            if len(action_history) > 5:
                compressed["action_history"] = action_history[-5:]
                compressed["_history_compressed"] = True
                compressed["_history_total"] = len(action_history)

        return compressed

    def _compress_resources(self, resources: Dict[str, Any]) -> Dict[str, Any]:
        """压缩资源部分，保留高优先级资源"""
        if not resources:
            return {}

        # 高优先级资源（不压缩）
        priority_resources = ["skill", "rag_knowledge", "taxonomy_signals", "wooyun_seed_knowledge"]
        result = {}

        for key in priority_resources:
            if key in resources and resources[key]:
                result[key] = resources[key]

        # 低优先级资源（压缩为摘要）
        low_priority = ["experiences", "pocs", "tips"]
        for key in low_priority:
            if key in resources and resources[key]:
                items = resources[key]
                if isinstance(items, list):
                    result[key] = f"[已压缩，共 {len(items)} 条]"
                else:
                    result[key] = items

        return result

    def smart_compress_messages(self, messages: List[Dict[str, str]], keep_recent: int = 5) -> List[Dict[str, str]]:
        """
        压缩消息历史（参考 H-Pentest ContextManager）

        策略：
        1. 保留 system 消息
        2. 保留最近 N 条消息
        3. 中间部分通过 LLM 总结压缩
        """
        if not messages:
            return messages

        # 分离 system 和非 system 消息
        system_msgs = [m for m in messages if m.get('role') == 'system']
        other_msgs = [m for m in messages if m.get('role') != 'system']

        if len(other_msgs) <= keep_recent:
            return messages

        # 保留最近的
        recent_msgs = other_msgs[-keep_recent:]
        middle_msgs = other_msgs[:-keep_recent]

        # 构建总结文本
        summary_text = self._summarize_messages(middle_msgs)

        compressed = system_msgs + [{
            'role': 'assistant',
            'content': f"[历史总结 - {len(middle_msgs)} 条消息]\n{summary_text}"
        }] + recent_msgs

        return compressed

    def _summarize_messages(self, messages: List[Dict[str, str]]) -> str:
        """总结消息列表为关键信息"""
        if not messages:
            return "无历史信息"

        tools_used = set()
        key_findings = []
        failures = []

        for msg in messages:
            content = str(msg.get('content', ''))
            role = msg.get('role', '')

            # 提取工具名
            if role == 'tool' and msg.get('name'):
                tools_used.add(msg['name'])

            # 提取关键发现
            if any(kw in content.lower() for kw in ['flag', 'found', 'success', '成功', '发现']):
                key_findings.append(content[:100])

            # 提取失败信息
            if any(kw in content.lower() for kw in ['fail', 'error', '失败', '错误']):
                failures.append(content[:100])

        summary_parts = []
        if tools_used:
            summary_parts.append(f"已使用工具: {', '.join(tools_used)}")
        if key_findings:
            summary_parts.append(f"关键发现: {'; '.join(key_findings[:3])}")
        if failures:
            summary_parts.append(f"失败记录: {'; '.join(failures[:2])}")

        return "; ".join(summary_parts) if summary_parts else "无特殊信息"

    def get_context_size_info(self, context: Dict[str, Any]) -> Dict[str, int]:
        """获取上下文中各部分的 token 大小信息（用于调试）"""
        info = {"total": self.count_dict_tokens(context)}

        if "resources" in context:
            info["resources"] = self.count_dict_tokens(context["resources"])

        if "action_history" in context and isinstance(context["action_history"], list):
            info["action_history"] = self.count_dict_tokens(context["action_history"])
            info["action_history_count"] = len(context["action_history"])

        return info
