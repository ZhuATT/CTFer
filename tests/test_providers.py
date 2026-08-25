import pytest

from src.providers import SolverConfig, _SOLVER_PRESETS, build_verifier_config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AT1_PROVIDER", "AT1_BASE_URL", "AT1_MODEL", "AT1_API_KEY",
              "AT1_SMALL_FAST_MODEL", "AT1_MAX_TURNS", "AT1_SESSION_SECONDS",
              "AT1_REASONING", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
              "LLM_API_KEY", "LLM_PROVIDER", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(k, raising=False)


def test_presets_table():
    assert set(_SOLVER_PRESETS) == {"deepseek", "deepseek-1m", "glm", "glm-1m", "custom"}


def test_default_provider_is_glm(monkeypatch):
    monkeypatch.setenv("AT1_API_KEY", "sk-test-1234567890")
    cfg = SolverConfig.from_env()
    assert cfg.provider == "glm"
    assert cfg.base_url == "https://open.bigmodel.cn/api/anthropic"
    assert cfg.model == "glm-5.3"


def test_custom_requires_explicit_base_and_model(monkeypatch):
    monkeypatch.setenv("AT1_PROVIDER", "custom")
    with pytest.raises(ValueError, match="custom"):
        SolverConfig.from_env()
    monkeypatch.setenv("AT1_BASE_URL", "https://api.example.com/anthropic")
    monkeypatch.setenv("AT1_MODEL", "my-model")
    cfg = SolverConfig.from_env()
    assert cfg.base_url == "https://api.example.com/anthropic"
    assert cfg.model == "my-model"


def test_repr_masks_api_key(monkeypatch):
    monkeypatch.setenv("AT1_API_KEY", "sk-supersecret-value-000")
    r = repr(SolverConfig.from_env())
    assert "supersecret" not in r
    assert "sk-s***" in r


def test_anthropic_env_full_override_with_credentials(monkeypatch):
    monkeypatch.setenv("AT1_API_KEY", "sk-k1")
    env = SolverConfig.from_env().anthropic_env()
    assert env["ANTHROPIC_BASE_URL"] == "https://open.bigmodel.cn/api/anthropic"
    assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-k1"
    assert env["DISABLE_TELEMETRY"] == "1"


def test_anthropic_env_no_credentials_keeps_local_cli_config(monkeypatch):
    # 无 key：不覆写 ANTHROPIC_*，让本机 claude CLI 用自己的配置（selftest 零配置可跑）
    env = SolverConfig.from_env().anthropic_env()
    assert "ANTHROPIC_BASE_URL" not in env
    assert "ANTHROPIC_AUTH_TOKEN" not in env
    assert env["DISABLE_TELEMETRY"] == "1"


def test_verifier_defaults_heterogeneous_to_solver(monkeypatch):
    # solver=glm → verifier 默认 deepseek（异构，设计§7）
    monkeypatch.setenv("AT1_API_KEY", "sk-k1")
    v = build_verifier_config(SolverConfig.from_env())
    assert v.provider == "openai"
    assert "deepseek" in v.base_url
