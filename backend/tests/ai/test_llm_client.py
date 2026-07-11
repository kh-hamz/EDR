import pytest

from edr_backend.ai import llm_client
from edr_backend.core.config import settings


def test_client_raises_when_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", None)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(llm_client.LLMNotConfigured):
        llm_client._client()


def test_client_uses_settings_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "sk-test-123")
    client = llm_client._client()
    assert client.api_key == "sk-test-123"


def test_client_falls_back_to_env_var(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-456")
    client = llm_client._client()
    assert client.api_key == "sk-env-456"
