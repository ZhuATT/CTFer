"""AT1 providers —— 模型接入（vendor 自 hxbai config.py，改造点见 phase1 P1.1）。

改动（相对 hxbai）：
- 删 _to_gateway / SOLVER_GATEWAY（网关逻辑整体移除）
- 环境变量前缀换 AT1_*；默认 provider = glm（设计§7）
- SolverConfig.__repr__ 脱敏 api_key（禁止明文 key 进日志）
- api_key 为空时 anthropic_env() 不覆写 ANTHROPIC_* —— 复用本机 claude CLI
  已有配置（selftest 在未配 AT1_API_KEY 的机器上也能跑）
- 保留 LLMConfig / build_verifier_config（门2 verifier 用，M3 接线；已剥网关）
- 删 ControllerConfig / flag 相关（benchmark 耦合，AT1 用不上）
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


def apply_llm_profile() -> str | None:
    profile = (os.environ.get("LLM_PROFILE") or "").strip()
    if not profile:
        return None
    prefix = f"{profile.upper()}_LLM_"
    for k, v in list(os.environ.items()):
        if k.startswith(prefix) and v != "":
            os.environ["LLM_" + k[len(prefix):]] = v
    return profile


_SOLVER_PRESETS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-flash",
        "small_fast_model": "deepseek-v4-flash",
    },
    "deepseek-1m": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-pro[1m]",
        "small_fast_model": "deepseek-v4-flash",
        "subagent_model": "deepseek-v4-flash",
        "effort_level": "max",
        "auto_compact_window": "786432",
        "api_timeout_ms": "3000000",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.3-flash",
        "small_fast_model": "glm-5.3-flash",
    },
    "glm-1m": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.3-flash",
        "small_fast_model": "glm-5.3-flash",
        "auto_compact_window": "1000000",
        "api_timeout_ms": "3000000",
    },
    # 自定义位：必须显式给 AT1_BASE_URL + AT1_MODEL（+ AT1_API_KEY）
    "custom": {},
}


@dataclass
class SolverConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    small_fast_model: str
    max_turns: int
    session_seconds: int
    reasoning: bool
    subagent_model: str = ""
    effort_level: str = ""
    auto_compact_window: str = ""
    api_timeout_ms: str = ""

    def __repr__(self) -> str:  # 禁止明文 key 进日志/异常栈
        key = f"{self.api_key[:4]}***" if self.api_key else ""
        return (f"SolverConfig(provider={self.provider!r}, base_url={self.base_url!r}, "
                f"api_key={key!r}, model={self.model!r}, small_fast_model={self.small_fast_model!r}, "
                f"max_turns={self.max_turns}, session_seconds={self.session_seconds}, "
                f"reasoning={self.reasoning})")

    @classmethod
    def from_env(cls) -> "SolverConfig":
        provider = (_env("AT1_PROVIDER") or "glm").lower()
        preset = _SOLVER_PRESETS.get(provider)
        if preset is None:
            raise ValueError(f"unknown AT1_PROVIDER: {provider!r}（可选：{sorted(_SOLVER_PRESETS)}）")
        base = _env("AT1_BASE_URL", preset.get("base_url")) or ""
        model = _env("AT1_MODEL", preset.get("model")) or ""
        if provider == "custom" and (not base or not model):
            raise ValueError('AT1_PROVIDER=custom 需要显式设置 AT1_BASE_URL 与 AT1_MODEL')
        key = (_env("AT1_API_KEY") or _env("ANTHROPIC_AUTH_TOKEN") or _env("ANTHROPIC_API_KEY") or "")
        return cls(
            provider=provider,
            base_url=base.rstrip("/"),
            api_key=key,
            model=model,
            small_fast_model=_env("AT1_SMALL_FAST_MODEL", preset.get("small_fast_model")) or "",
            max_turns=int(_env("AT1_MAX_TURNS", "60") or "60"),
            session_seconds=int(_env("AT1_SESSION_SECONDS", "1500") or "1500"),
            reasoning=(_env("AT1_REASONING", "0") == "1"),
            subagent_model=_env("AT1_SUBAGENT_MODEL", preset.get("subagent_model", "")) or "",
            effort_level=_env("AT1_EFFORT", preset.get("effort_level", "")) or "",
            auto_compact_window=_env("AT1_AUTO_COMPACT_WINDOW", preset.get("auto_compact_window", "")) or "",
            api_timeout_ms=_env("AT1_API_TIMEOUT_MS", preset.get("api_timeout_ms", "")) or "",
        )

    @property
    def has_own_credentials(self) -> bool:
        return bool(self.api_key and self.base_url)

    def anthropic_env(self) -> dict:
        """solver 子进程注入的环境变量。

        有自己的凭证（key+base_url）→ 整套覆写；没有 → 只注入行为开关，
        让 claude CLI 用本机已有配置（apiKeySource 链），selftest 零配置可跑。
        """
        e: dict[str, str] = {
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_AUTOUPDATER": "1",
        }
        if self.has_own_credentials:
            e.update({
                "ANTHROPIC_BASE_URL": self.base_url,
                "ANTHROPIC_AUTH_TOKEN": self.api_key,
                "ANTHROPIC_API_KEY": self.api_key,
                "ANTHROPIC_MODEL": self.model,
                "ANTHROPIC_DEFAULT_OPUS_MODEL": self.model,
                "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.small_fast_model,
                "ANTHROPIC_SMALL_FAST_MODEL": self.small_fast_model,
            })
        if self.subagent_model:
            e["CLAUDE_CODE_SUBAGENT_MODEL"] = self.subagent_model
        if self.effort_level:
            e["CLAUDE_CODE_EFFORT_LEVEL"] = self.effort_level
        if self.auto_compact_window:
            e["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = self.auto_compact_window
        if self.api_timeout_ms:
            e["API_TIMEOUT_MS"] = self.api_timeout_ms
        return e


# ──────────────────────────────────────────────────────────────────────────────
# 门 2 verifier 配置（OpenAI 兼容通道，经 llm.py 调用——M3 接线，先 vendor 进来）
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class LLMConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    temperature: float
    max_tokens: int
    timeout: int
    min_interval: float = 0.0
    thinking: bool = True
    reasoning_effort: str = "high"
    fast_model: str = ""
    empty_retries: int = 2
    max_tokens_fast: int = 3072
    fallback_provider: str | None = None
    fallback_base_url: str | None = None
    fallback_api_key: str | None = None
    fallback_model: str | None = None

    def __repr__(self) -> str:
        key = f"{self.api_key[:4]}***" if self.api_key else ""
        return (f"LLMConfig(provider={self.provider!r}, base_url={self.base_url!r}, "
                f"api_key={key!r}, model={self.model!r})")

    @classmethod
    def from_env(cls) -> "LLMConfig":
        apply_llm_profile()
        provider = (_env("LLM_PROVIDER", "openai") or "openai").lower()
        default_base = "" if provider in ("zai", "zhipu", "glm") else "https://api.deepseek.com"
        base_url = _env("LLM_BASE_URL", default_base)
        api_key = _env("LLM_API_KEY", "")
        model = _env("LLM_MODEL", "deepseek-chat")
        return cls(
            provider=provider,
            base_url=base_url.rstrip("/") if base_url else base_url,
            api_key=api_key or "",
            model=model,
            temperature=float(_env("LLM_TEMPERATURE", "0.4")),
            max_tokens=int(_env("LLM_MAX_TOKENS", "4096")),
            timeout=int(_env("LLM_TIMEOUT", "300")),
            min_interval=float(_env("LLM_MIN_INTERVAL", "0")),
            thinking=(_env("LLM_THINKING", "1") == "1"),
            reasoning_effort=_env("LLM_REASONING_EFFORT", "high"),
            max_tokens_fast=int(_env("LLM_MAX_TOKENS_FAST", "3072")),
            empty_retries=int(_env("LLM_EMPTY_RETRIES", "2")),
            fast_model=_env("LLM_FAST_MODEL", "deepseek-v4-flash" if "deepseek" in (model or "").lower() else ""),
            fallback_provider=(lambda p: p.lower() if p else None)(_env("LLM_FALLBACK_PROVIDER")),
            fallback_base_url=(lambda u: u.rstrip("/") if u else None)(_env("LLM_FALLBACK_BASE_URL")),
            fallback_api_key=_env("LLM_FALLBACK_API_KEY"),
            fallback_model=_env("LLM_FALLBACK_MODEL"),
        )

    def has_fallback(self) -> bool:
        return bool(self.fallback_api_key and self.fallback_model)

    def is_usable(self) -> bool:
        if self.provider in ("zai", "zhipu", "glm"):
            return bool(self.api_key)
        return bool(self.api_key and self.base_url)


_VERIFIER_PRESETS = {
    "deepseek": {"provider": "openai", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-v4-flash"},
    "glm": {"provider": "zai", "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-5.3-flash"},
    # 讯飞 maas 承载 DeepSeek V4 Pro（OpenAI 兼容 /v2；实测 2026-08-25：Bearer id:secret 整串，
    # developer role 被拒——llm.py 只用 system/user 不受影响；key 放 .secrets.env 不入库）
    "xfyun": {"provider": "openai", "base_url": "https://maas-api.cn-huabei-1.xf-yun.com/v2",
              "model": "xopdeepseekv4pro"},
    # 观察者：glm-5.3 全量直连 bigmodel（与 solver 同模型同 key，OpenAI 兼容端点）
    "bigmodel-glm": {"provider": "openai", "base_url": "https://open.bigmodel.cn/api/paas/v4",
                      "model": "glm-5.3"},
}


def build_verifier_config(solver: "SolverConfig") -> LLMConfig:
    """门2 verifier：默认与 solver 异构（solver=glm → verifier=DeepSeek 经讯飞 maas，设计§7）。"""
    apply_llm_profile()
    family = "bigmodel-glm" if solver.provider.startswith("glm") else "glm"
    preset = _VERIFIER_PRESETS.get(family, _VERIFIER_PRESETS["deepseek"])
    provider = (_env("LLM_PROVIDER") or preset["provider"]).lower()
    base = _env("LLM_BASE_URL") or preset["base_url"]
    return LLMConfig(
        provider=provider,
        base_url=(base or "").rstrip("/"),
        api_key=(_env("LLM_API_KEY") or ""),
        model=_env("LLM_MODEL") or preset["model"],
        temperature=float(_env("LLM_TEMPERATURE", "0.0") or "0.0"),
        max_tokens=int(_env("LLM_MAX_TOKENS", "1024") or "1024"),
        timeout=int(_env("LLM_TIMEOUT", "120") or "120"),
        min_interval=float(_env("LLM_MIN_INTERVAL", "0") or "0"),
        thinking=(_env("LLM_THINKING", "0") == "1"),
        reasoning_effort=_env("LLM_REASONING_EFFORT", "low") or "low",
        max_tokens_fast=int(_env("LLM_MAX_TOKENS_FAST", "1024") or "1024"),
        empty_retries=int(_env("LLM_EMPTY_RETRIES", "2") or "2"),
        fast_model=_env("LLM_FAST_MODEL", preset["model"]) or preset["model"],
    )
