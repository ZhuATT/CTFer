"""
LLM 客户端 - 直接模式的核心组件
从 H-Pentest `core/llm.py` 迁移，适配本地执行
关键特性：
1. 流式响应 + think_tag 过滤（不打印 <think> 内容）
2. tool_calls 增量组装（流式中逐步提取）
3. 指数退避重试
"""
import sys
import time
from typing import Any, Callable, Dict, List, Optional

import openai


def _retry_with_backoff(max_attempts: int = 3, base_delay: float = 2.0):
    """指数退避重试装饰器"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        delay = base_delay * (2 ** attempt)
                        time.sleep(delay)
            raise last_exception
        return wrapper
    return decorator


class LLMClient:
    """OpenAI兼容 API 的 LLM 客户端"""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 8000,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Ensure base_url ends with /v1 for OpenAI compatibility
        normalized_base = base_url.rstrip("/")
        if not normalized_base.endswith("/v1"):
            normalized_base += "/v1"

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=normalized_base,
            timeout=120.0,
        )

    @_retry_with_backoff(max_attempts=3, base_delay=2.0)
    def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        stream: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        调用 LLM

        Args:
            messages: 消息列表
            tools: 工具 schema 列表
            stream: 是否流式输出

        Returns:
            {"content": str, "tool_calls": list}
        """
        params = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "stream": stream,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"

        if stream:
            return self._handle_stream(params)
        else:
            return self._handle_non_stream(params)

    def _handle_stream(self, params: dict) -> Dict[str, Any]:
        """处理流式响应"""
        content_chunks = []
        tool_calls = []

        try:
            stream = self.client.chat.completions.create(**params)

            in_think_tag = False

            for chunk in stream:
                if not chunk.choices:
                    continue

                delta = chunk.choices[0].delta

                # 内容处理
                if delta.content:
                    chunk_text = delta.content

                    # 过滤 <think> 标签
                    if "<think>" in chunk_text:
                        in_think_tag = True
                    if "</think>" in chunk_text:
                        in_think_tag = False
                        chunk_text = ""

                    if not in_think_tag and chunk_text:
                        try:
                            print(chunk_text, end="", flush=True)
                        except UnicodeEncodeError:
                            # Windows GBK 终端不支持的字符，静默跳过
                            pass

                    content_chunks.append(delta.content or "")

                # tool_calls 增量组装
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        if tc.index >= len(tool_calls):
                            tool_calls.append({
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name or "",
                                    "arguments": ""
                                }
                            })
                        if tc.function.arguments:
                            tool_calls[tc.index]["function"]["arguments"] += tc.function.arguments

            if content_chunks:
                print()  # 流式结束后换行

            return {
                "content": "".join(content_chunks),
                "tool_calls": tool_calls if tool_calls else None
            }

        except Exception as e:
            raise

    def _handle_non_stream(self, params: dict) -> Dict[str, Any]:
        """处理非流式响应"""
        try:
            response = self.client.chat.completions.create(**params)
            message = response.choices[0].message

            # 处理 content 和 reasoning_content（MiniMax 等模型使用 reasoning_content）
            content = message.content or ""
            reasoning = getattr(message, "reasoning_content", None) or ""
            if reasoning and not content:
                # 如果 content 为空但有 reasoning，将其作为 content
                content = reasoning

            return {
                "content": content,
                "tool_calls": message.tool_calls
            }
        except Exception as e:
            raise
