"""
LLM 客户端 - 统一入口

支持多种配置方式（优先级从高到低）：
1. 环境变量: LLM_API_URL, LLM_API_KEY, LLM_MODEL
2. 配置文件: config.json（从项目根目录读取）
3. 代码配置: configure() 函数

支持 Provider：
- openai: OpenAI 兼容格式 (/v1/chat/completions)
- claude: Claude API 格式 (/v1/messages)

使用示例：
    # 方式1: 代码配置
    from core.llm_client import configure
    configure("https://api.openai.com/v1", "sk-xxx", "gpt-4o", "openai")

    # 方式2: Claude API
    configure("https://mydamoxing.cn", "sk-xxx", "Claude模型", "claude")

    # 方式3: 配置文件（config.json）
    {
        "llm": {
            "api_url": "https://mydamoxing.cn",
            "api_key": "sk-xxx",
            "model": "MiniMax-M2.7-highspeed",
            "provider": "claude"
        }
    }
"""
import json
import os
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# 全局配置
_llm_api_url: str = ""
_llm_api_key: str = ""
_llm_model: str = "gpt-4o-mini"
_llm_provider: str = "openai"  # openai 或 claude
_config_loaded: bool = False


def _load_config() -> None:
    """从配置文件加载配置（如果存在）"""
    global _llm_api_url, _llm_api_key, _llm_model, _llm_provider, _config_loaded

    if _config_loaded:
        return

    # 尝试从 config.json 加载
    config_path = Path(__file__).parent.parent / "config.json"
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            llm_config = config.get("llm", {})
            if llm_config.get("api_url"):
                _llm_api_url = llm_config["api_url"].rstrip("/")
            if llm_config.get("api_key"):
                _llm_api_key = llm_config["api_key"]
            if llm_config.get("model"):
                _llm_model = llm_config["model"]
            if llm_config.get("provider"):
                _llm_provider = llm_config["provider"]
        except Exception:
            pass

    # 环境变量覆盖配置文件
    if os.environ.get("LLM_API_URL"):
        _llm_api_url = os.environ["LLM_API_URL"].rstrip("/")
    if os.environ.get("LLM_API_KEY"):
        _llm_api_key = os.environ["LLM_API_KEY"]
    if os.environ.get("LLM_MODEL"):
        _llm_model = os.environ["LLM_MODEL"]
    if os.environ.get("LLM_PROVIDER"):
        _llm_provider = os.environ["LLM_PROVIDER"]

    _config_loaded = True


def configure(api_url: str, api_key: str, model: str = "gpt-4o-mini", provider: str = "openai") -> None:
    """
    配置 LLM API（优先级最高）

    Args:
        api_url: API 地址
        api_key: API 密钥
        model: 模型名称
        provider: provider 类型 ("openai" 或 "claude")
    """
    global _llm_api_url, _llm_api_key, _llm_model, _llm_provider, _config_loaded
    _llm_api_url = api_url.rstrip("/")
    _llm_api_key = api_key
    _llm_model = model
    _llm_provider = provider
    _config_loaded = True


def call_llm(
    prompt: str,
    system: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 4096,
) -> str:
    """
    调用 LLM

    Args:
        prompt: 用户提示
        system: 系统提示（可选）
        temperature: 温度参数
        max_tokens: 最大 token 数

    Returns:
        LLM 响应文本
    """
    _load_config()

    if not _llm_api_url or not _llm_api_key:
        raise ValueError(
            "LLM API 未配置。请：\n"
            "1. 复制 config.example.json 为 config.json 并填入配置\n"
            "2. 或设置环境变量: LLM_API_URL, LLM_API_KEY, LLM_MODEL\n"
            "3. 或代码调用: configure(api_url, api_key)"
        )

    if _llm_provider == "claude":
        return _call_claude(prompt, system, max_tokens)
    else:
        return _call_openai(prompt, system, temperature, max_tokens)


def _call_openai(prompt: str, system: Optional[str], temperature: float, max_tokens: int) -> str:
    """调用 OpenAI 兼容 API"""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": _llm_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {_llm_api_key}",
    }

    try:
        req = Request(
            f"{_llm_api_url}/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        with urlopen(req, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]

    except HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"LLM API HTTP 错误 {e.code}: {error_body}")
    except URLError as e:
        raise RuntimeError(f"LLM API 连接失败: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"LLM API 调用失败: {type(e).__name__}: {e}")


def _call_claude(prompt: str, system: Optional[str], max_tokens: int) -> str:
    """调用 Claude API"""
    messages = []
    if system:
        messages.append({"role": "user", "content": f"System: {system}\n\nUser: {prompt}"})
    else:
        messages.append({"role": "user", "content": prompt})

    payload = {
        "model": _llm_model,
        "messages": messages,
        "max_tokens": max_tokens,
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": _llm_api_key,
        "anthropic-version": "2023-06-01",
    }

    try:
        req = Request(
            f"{_llm_api_url}/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        with urlopen(req, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))
            # 提取 text 内容
            for item in result.get("content", []):
                if item.get("type") == "text":
                    return item["text"]
            # 如果没有 text 类型，尝试其他格式
            if "content" in result:
                content = result["content"]
                if isinstance(content, str):
                    return content
                if isinstance(content, list) and len(content) > 0:
                    # 返回第一个有 text 字段的项
                    for item in content:
                        if isinstance(item, dict) and "text" in item:
                            return item["text"]
                        if isinstance(item, dict) and "thinking" in item:
                            continue  # 跳过 thinking
                    # 返回第一个项的字符串表示
                    return str(content[0])
            raise RuntimeError(f"Claude API 响应格式未知: {result}")

    except HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"Claude API HTTP 错误 {e.code}: {error_body}")
    except URLError as e:
        raise RuntimeError(f"Claude API 连接失败: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"Claude API 调用失败: {type(e).__name__}: {e}")


def is_configured() -> bool:
    """检查是否已配置"""
    _load_config()
    return bool(_llm_api_url and _llm_api_key)


def quick_call(prompt: str) -> str:
    """快速调用"""
    return call_llm(prompt)


def get_config_info() -> dict:
    """获取当前配置信息（不包含密钥）"""
    _load_config()
    return {
        "api_url": _llm_api_url,
        "model": _llm_model,
        "provider": _llm_provider,
        "configured": is_configured(),
    }
