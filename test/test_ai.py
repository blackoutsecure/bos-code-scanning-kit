from __future__ import annotations

from ai import detect_provider

"""Tests for AI provider detection and optional summarization."""


def test_auto_detects_github_models_token():
    provider = detect_provider(environ={"GITHUB_MODELS_TOKEN": "token"})
    assert provider is not None
    assert provider.name == "github-models"
    assert provider.model == "openai/gpt-4o-mini"


def test_auto_uses_github_token_as_fallback():
    provider = detect_provider(environ={"GITHUB_TOKEN": "token"})
    assert provider is not None
    assert provider.name == "github-models"


def test_explicit_disable_skips_detection():
    assert detect_provider("none", environ={"GITHUB_TOKEN": "token"}) is None


def test_external_provider_requires_explicit_endpoint_and_key():
    assert detect_provider("openai", environ={"OPENAI_API_KEY": "key"}) is None
    provider = detect_provider(
        "openai",
        environ={"OPENAI_API_KEY": "key", "OPENAI_API_ENDPOINT": "https://example.test"},
    )
    assert provider is not None
    assert provider.name == "openai"
