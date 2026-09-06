"""Redaction of credential-shaped text in operator-facing report surfaces.

GitHub masks only the secrets it already knows about — repository and
organization secrets — and it never masks workflow artifacts. Anything a
scanner *discovers* (a leaked token in a file, a credential in a URL, a
posture probe echoing an API error body) is therefore published verbatim
to the run log, the job summary, and any uploaded report on a public
repository.

This module is applied at the reporting boundary only: after analysis has
already produced its verdict, and never to the SARIF uploaded to code
scanning. Code scanning alerts are permission-gated and are where a
responder needs the untruncated evidence, so redacting there would remove
signal without reducing public exposure.

Patterns are deliberately high-confidence. A false positive silently
destroys evidence a reader needs, which is its own failure mode, so
entropy-style heuristics are left out in favour of known credential
shapes and explicit `key = value` assignments.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

DEFAULT_PLACEHOLDER = "***"

# Whole-token credential formats. Each is replaced in full.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # GitHub personal access, OAuth, user-to-server, server-to-server, refresh.
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    # AWS access key identifiers.
    re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    # Google API keys.
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # Slack tokens.
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # Stripe and OpenAI-style prefixed keys.
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    # JSON Web Tokens.
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
)

# PEM private key blocks, including the body, collapsed to one placeholder.
_PEM_PATTERN = re.compile(
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

# `key = value` / `key: value` assignments for credential-shaped key names.
# The key is preserved so the reader still learns *what* leaked.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(authorization|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret"
    r"|private[_-]?key|password|passwd|passphrase|token|secret)\b"
    r"(\s*[:=]\s*)"
    r"(\"[^\"\n]+\"|'[^'\n]+'|[^\s,;)\]}]+)"
)

# Credentials embedded in a URL authority (`https://user:token@host`).
_URL_CREDENTIAL_PATTERN = re.compile(r"(?<=://)([^/\s:@]+):([^/\s@]+)(?=@)")

# `Bearer <token>` / `Basic <token>` authorization values.
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=\-]{8,})")

# Auth scheme names are not themselves secrets. Once the bearer rule has
# masked the credential, re-masking the scheme only removes context.
_SCHEME_WORDS = frozenset({"bearer", "basic", "token"})


@dataclass(frozen=True)
class Redactor:
    """Replace credential-shaped substrings with a fixed placeholder."""

    enabled: bool = True
    placeholder: str = DEFAULT_PLACEHOLDER
    extra_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)

    def redact(self, value: Any) -> Any:
        """Redact a string. Non-string values are returned untouched."""
        if not self.enabled or not isinstance(value, str) or not value:
            return value

        text = _PEM_PATTERN.sub(self.placeholder, value)
        for pattern in self.extra_patterns:
            text = pattern.sub(self.placeholder, text)
        for pattern in _TOKEN_PATTERNS:
            text = pattern.sub(self.placeholder, text)
        text = _URL_CREDENTIAL_PATTERN.sub(rf"\1:{self.placeholder}", text)
        text = _BEARER_PATTERN.sub(rf"\1 {self.placeholder}", text)
        text = _ASSIGNMENT_PATTERN.sub(self._mask_assignment, text)
        return text

    def _mask_assignment(self, match: re.Match[str]) -> str:
        key, separator, value = match.group(1), match.group(2), match.group(3)
        if value.strip().lower() in _SCHEME_WORDS or value.strip() == self.placeholder:
            return match.group(0)
        return f"{key}{separator}{self.placeholder}"

    def redact_mapping(self, item: Mapping[str, Any], keys: Iterable[str]) -> dict[str, Any]:
        """Return a copy of `item` with `keys` redacted."""
        out = dict(item)
        if not self.enabled:
            return out
        for key in keys:
            if key in out:
                out[key] = self.redact(out[key])
        return out


def build(
    *,
    enabled: bool = True,
    placeholder: str = DEFAULT_PLACEHOLDER,
    extra_patterns: Iterable[str] = (),
) -> Redactor:
    """Build a `Redactor`, compiling any caller-supplied extra patterns.

    An uncompilable pattern is skipped rather than raised: redaction is a
    safety net around reporting, and a bad custom pattern must not take
    down a scan that has already produced its findings.
    """
    compiled: list[re.Pattern[str]] = []
    for raw in extra_patterns:
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            compiled.append(re.compile(raw))
        except re.error:
            continue
    return Redactor(
        enabled=enabled,
        placeholder=placeholder or DEFAULT_PLACEHOLDER,
        extra_patterns=tuple(compiled),
    )
