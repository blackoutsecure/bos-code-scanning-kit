"""Tests for `redaction` — credential masking on report surfaces."""

from __future__ import annotations

import redaction as redaction_mod


def test_disabled_redactor_is_a_passthrough():
    r = redaction_mod.build(enabled=False)
    text = "token=ghp_abcdefghijklmnopqrstuvwxyz012345"
    assert r.redact(text) == text


def test_github_token_is_masked():
    r = redaction_mod.build()
    out = r.redact("leaked ghp_abcdefghijklmnopqrstuvwxyz012345 in config.yml")
    assert "ghp_abcdefghijklmnopqrstuvwxyz012345" not in out
    assert "***" in out
    # Surrounding context survives so the finding stays actionable.
    assert "config.yml" in out


def test_aws_access_key_is_masked():
    r = redaction_mod.build()
    out = r.redact("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_jwt_is_masked():
    r = redaction_mod.build()
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    assert token not in r.redact(f"Authorization header {token}")


def test_private_key_block_is_masked():
    r = redaction_mod.build()
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEArandombase64content\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = r.redact(f"found key: {pem}")
    assert "MIIEowIBAAKCAQEArandombase64content" not in out
    assert out == "found key: ***"


def test_assignment_keeps_key_and_masks_value():
    r = redaction_mod.build()
    out = r.redact('password = "hunter2-not-a-real-value"')
    assert "hunter2-not-a-real-value" not in out
    # The key name is retained so a reader still learns what leaked.
    assert out.startswith("password")
    assert "***" in out


def test_url_embedded_credentials_are_masked():
    r = redaction_mod.build()
    out = r.redact("https://ci-user:s3cr3t-token-value@example.com/repo.git")
    assert "s3cr3t-token-value" not in out
    assert "ci-user" in out
    assert "example.com" in out


def test_bearer_value_is_masked_but_scheme_kept():
    r = redaction_mod.build()
    out = r.redact("Authorization: Bearer abcdef0123456789abcdef")
    assert "abcdef0123456789abcdef" not in out
    assert "Bearer" in out


def test_ordinary_finding_text_is_untouched():
    r = redaction_mod.build()
    text = "PS011 `permissions: write-all` found in .github/workflows/ci.yml:12"
    assert r.redact(text) == text


def test_custom_placeholder_is_used():
    r = redaction_mod.build(placeholder="[REDACTED]")
    assert "[REDACTED]" in r.redact("AKIAIOSFODNN7EXAMPLE")


def test_extra_patterns_are_applied():
    r = redaction_mod.build(extra_patterns=[r"INTERNAL-[0-9]{4}"])
    assert "INTERNAL-4821" not in r.redact("ref INTERNAL-4821")


def test_invalid_extra_pattern_is_skipped_not_raised():
    """A bad custom pattern must never break a scan that already ran."""
    r = redaction_mod.build(extra_patterns=["(unclosed"])
    assert r.redact("AKIAIOSFODNN7EXAMPLE") == "***"


def test_non_string_values_pass_through():
    r = redaction_mod.build()
    assert r.redact(None) is None
    assert r.redact(7) == 7


def test_redact_mapping_only_touches_named_keys():
    r = redaction_mod.build()
    item = {"message": "token=ghp_abcdefghijklmnopqrstuvwxyz012345", "location": "a.yml"}
    out = r.redact_mapping(item, ["message"])
    assert "***" in out["message"]
    assert out["location"] == "a.yml"
