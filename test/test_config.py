"""Tests for `scan_kit.config` — `.bos-scan.yml` loader, defaults, validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from scan_kit import config as cfg_mod

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def test_defaults_when_no_path_given():
    cfg = cfg_mod.load(None)
    assert cfg.owner == ""
    assert cfg.scan.tools == "auto"
    assert cfg.scan.fail_on == "high"
    assert cfg.posture.ghas.require_code_scanning == "warn"
    assert cfg.posture.ghas.require_secret_scanning == "warn"
    assert cfg.posture.ghas.require_dependabot_alerts == "warn"
    assert cfg.posture.workflows.require_permissions_block == "warn"
    assert cfg.posture.workflows.forbid_write_all == "warn"
    assert cfg.posture.codeowners.require_file == "warn"
    assert cfg.posture.codeowners.validate_users_exist is False
    assert cfg.posture.branches == {}


# ---------------------------------------------------------------------------
# Round-trip via on-disk YAML
# ---------------------------------------------------------------------------

def test_full_roundtrip(tmp_path: Path):
    yaml_text = """\
owner: blackoutsecure
project_name: my-action
email: security@example.com

scan:
  tools: auto
  exclude: [psalm]
  fail_on: high
  codeql:
    languages: [python, javascript-typescript]
    exclude_languages: []

posture:
  ghas:
    require_code_scanning: fail
    require_secret_scanning: warn
    require_dependabot_alerts: skip
  workflows:
    require_permissions_block: fail
    forbid_write_all: fail
  branches:
    main:
      required_reviews: 2
      restrict_force_push: true
      require_status_checks: true
      require_signed_commits: true
      severity: fail
    dev:
      required_reviews: 1
      severity: warn
  codeowners:
    require_file: fail
    validate_users_exist: false
"""
    p = tmp_path / ".bos-scan.yml"
    p.write_text(yaml_text)
    cfg = cfg_mod.load(p)

    assert cfg.owner == "blackoutsecure"
    assert cfg.project_name == "my-action"
    assert cfg.email == "security@example.com"

    assert cfg.scan.tools == "auto"
    assert cfg.scan.exclude == ("psalm",)
    assert cfg.scan.fail_on == "high"
    assert cfg.scan.codeql.languages == ["python", "javascript-typescript"]

    assert cfg.posture.ghas.require_code_scanning == "fail"
    assert cfg.posture.ghas.require_dependabot_alerts == "skip"
    assert cfg.posture.workflows.forbid_write_all == "fail"

    assert "main" in cfg.posture.branches
    main = cfg.posture.branches["main"]
    assert main.required_reviews == 2
    assert main.restrict_force_push is True
    assert main.require_signed_commits is True
    assert main.severity == "fail"

    dev = cfg.posture.branches["dev"]
    assert dev.required_reviews == 1
    assert dev.severity == "warn"

    assert cfg.posture.codeowners.require_file == "fail"
    assert cfg.source_path.endswith(".bos-scan.yml")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", cfg_mod.DEFAULT_FILENAMES)
def test_discover_finds_each_default_name(tmp_path: Path, name: str):
    p = tmp_path / name
    p.write_text("owner: foo\n")
    assert cfg_mod.discover(tmp_path) == p


def test_discover_returns_none_when_absent(tmp_path: Path):
    assert cfg_mod.discover(tmp_path) is None


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "yaml_text, fragment",
    [
        ("scan: {tools: bogus}",        "scan.tools"),
        ("scan: {fail_on: extreme}",    "scan.fail_on"),
        ("scan: {codeql: {languages: 7}}", "scan.codeql.languages"),
        (
            "posture:\n  ghas:\n    require_code_scanning: maybe\n",
            "require_code_scanning",
        ),
        (
            "posture:\n  branches:\n    main:\n      required_reviews: -1\n",
            "required_reviews",
        ),
    ],
)
def test_invalid_inputs_raise_config_error(tmp_path: Path, yaml_text: str, fragment: str):
    p = tmp_path / ".bos-scan.yml"
    p.write_text(yaml_text)
    with pytest.raises(cfg_mod.ConfigError) as exc_info:
        cfg_mod.load(p)
    assert fragment in str(exc_info.value)


def test_yaml_not_mapping_raises(tmp_path: Path):
    p = tmp_path / ".bos-scan.yml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(cfg_mod.ConfigError):
        cfg_mod.load(p)


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(cfg_mod.ConfigError):
        cfg_mod.load(tmp_path / "does-not-exist.yml")


def test_empty_file_uses_defaults(tmp_path: Path):
    p = tmp_path / ".bos-scan.yml"
    p.write_text("")
    cfg = cfg_mod.load(p)
    assert cfg.scan.fail_on == "high"   # default preserved


def test_unknown_keys_are_ignored(tmp_path: Path):
    """Forward-compat: future kit-only sections must not break older versions."""
    p = tmp_path / ".bos-scan.yml"
    p.write_text("marketplace:\n  community_health_source: inherit\nowner: bos\n")
    cfg = cfg_mod.load(p)
    assert cfg.owner == "bos"
