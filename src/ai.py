"""Optional AI summary providers with deterministic fallback at the call site."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

GITHUB_MODELS_ENDPOINT = "https://models.github.ai/inference/chat/completions"


def _https_endpoint(value: str | None) -> str | None:
    """Accept only HTTPS AI endpoints so bearer tokens stay encrypted in transit."""
    endpoint = (value or "").strip()
    return endpoint if endpoint.startswith("https://") else None


@dataclass(frozen=True)
class Provider:
    name: str
    endpoint: str
    model: str
    token: str


def detect_provider(
    configured: str = "",
    *,
    environ: Mapping[str, str] | None = None,
) -> Provider | None:
    """Select an explicitly configured provider or GitHub Models when available.

    GitHub Actions tokens are only attempted when the caller exposes a token;
    an authorization failure is handled as normal unavailability by summarize().
    External providers require an explicit provider name and endpoint.
    """
    env = os.environ if environ is None else environ
    name = (configured or "auto").strip().lower()
    if name in {"none", "disabled", "false", "off"}:
        return None

    if name in {"auto", "github", "github-models", "copilot"}:
        token = env.get("GITHUB_MODELS_TOKEN") or env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
        if token:
            endpoint = _https_endpoint(env.get("GITHUB_MODELS_ENDPOINT", GITHUB_MODELS_ENDPOINT))
            if not endpoint:
                return None
            return Provider(
                name="github-models",
                endpoint=endpoint,
                model=(
                    env.get("GITHUB_MODELS_MODEL_CODE_SCANNING")
                    or env.get("GITHUB_MODELS_MODEL")
                    or "openai/gpt-4o-mini"
                ),
                token=token,
            )
        if name != "auto":
            return None

    if name not in {"auto", "github", "github-models", "copilot"}:
        token_name = f"{name.upper().replace('-', '_')}_API_KEY"
        token = env.get(token_name) or env.get("AI_API_KEY")
        endpoint = _https_endpoint(
            env.get(f"{name.upper().replace('-', '_')}_API_ENDPOINT")
            or env.get("AI_API_ENDPOINT")
        )
        if token and endpoint:
            return Provider(
                name=name,
                endpoint=endpoint,
                model=env.get(f"{name.upper().replace('-', '_')}_MODEL", ""),
                token=token,
            )
    return None


def summarize(
    findings: list[dict[str, Any]],
    provider: Provider,
    *,
    timeout: int = 20,
) -> str | None:
    """Request a short summary; return None for any unavailable provider/error."""
    prompt = {
        "role": "user",
        "content": (
            "Summarize these code-scanning findings in at most three concise bullets. "
            "Prioritize severity and concrete next steps. Do not invent facts.\n\n"
            + json.dumps(findings, ensure_ascii=True)
        ),
    }
    payload = {
        "model": provider.model,
        "messages": [
            {"role": "system", "content": "You are a security triage assistant."},
            prompt,
        ],
        "temperature": 0,
        "max_tokens": 300,
    }
    request = urllib.request.Request(
        provider.endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {provider.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"]
    except (OSError, ValueError, KeyError, IndexError, urllib.error.URLError):
        return None
    return content.strip() or None if isinstance(content, str) else None
