"""Regression tests for files retained in Marketplace release artifacts."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_marketplace_release_keeps_python_package_metadata() -> None:
    config = json.loads(
        (REPO_ROOT / ".github" / "bos-universal-config.json").read_text()
    )
    marketplace = config["marketplace"]

    assert "pyproject.toml" in marketplace["allowlist_paths"]
    assert "pyproject.toml" in marketplace["required_paths"]
    assert "pyproject.toml" not in marketplace["blocked_paths"]
