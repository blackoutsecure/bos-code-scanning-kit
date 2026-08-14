"""Tests for `config` — `.bos-scan.yml` loader, defaults, validation."""

from __future__ import annotations

from pathlib import Path

import pytest

import config as cfg_mod

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
    assert cfg.remediation.enable_ai_findings_summary is False
    assert cfg.remediation.ai_findings_summary_provider == ""
    assert cfg.remediation.local_heuristic_fallback is True
    assert cfg.posture.branches == {}


def test_remediation_flags_are_opt_in_and_safe_by_default(tmp_path: Path):
    p = tmp_path / ".bos-scan.yml"
    p.write_text("remediation:\n  enable_ai_findings_summary: true\n  ai_findings_summary_provider: openai\n  local_heuristic_fallback: true\n")
    cfg = cfg_mod.load(p)
    assert cfg.remediation.enable_ai_findings_summary is True
    assert cfg.remediation.ai_findings_summary_provider == "openai"
    assert cfg.remediation.local_heuristic_fallback is True


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


def test_resolve_cascades_marketplace_global_and_repo_config(tmp_path: Path):
        global_path = tmp_path / cfg_mod.DEFAULT_GLOBAL_CONFIG_PATH
        global_path.parent.mkdir(parents=True)
        global_path.write_text(
                """\
code_scanning:
    owner: global-owner
    posture:
        ghas:
            require_secret_scanning: fail
        branches:
            main:
                required_reviews: 2
        workflows:
            allow_tag_pin: [global/action]
"""
        )
        repo_path = tmp_path / ".github" / "bos-universal-config.yml"
        repo_path.write_text(
                """\
code_scanning:
    owner: repo-owner
    posture:
        ghas:
            require_code_scanning: skip
        branches:
            main:
                severity: fail
        workflows:
            allow_tag_pin: [repo/action]
"""
        )

        cfg = cfg_mod.resolve(tmp_path)

        assert cfg.owner == "repo-owner"
        assert cfg.posture.ghas.require_code_scanning == "skip"
        assert cfg.posture.ghas.require_secret_scanning == "fail"
        assert cfg.posture.ghas.require_dependabot_alerts == "warn"
        assert cfg.posture.branches["main"].required_reviews == 2
        assert cfg.posture.branches["main"].severity == "fail"
        assert cfg.posture.workflows.allow_tag_pin == ("repo/action",)
        assert cfg.source_paths[0].endswith(cfg_mod.MARKETPLACE_CONFIG_FILE)
        assert cfg.source_paths[1:] == (str(global_path), str(repo_path))


def test_resolve_can_require_global_config(tmp_path: Path):
        with pytest.raises(cfg_mod.ConfigError, match="global config not found"):
                cfg_mod.resolve(tmp_path, use_global_config=True)


def test_resolve_can_disable_global_config(tmp_path: Path):
        global_path = tmp_path / cfg_mod.DEFAULT_GLOBAL_CONFIG_PATH
        global_path.parent.mkdir(parents=True)
        global_path.write_text("code_scanning:\n  owner: global-owner\n")

        cfg = cfg_mod.resolve(tmp_path, use_global_config=False)

        assert cfg.owner == ""
        assert str(global_path) not in cfg.source_paths


def test_discover_prefers_github_universal_config(tmp_path: Path):
        legacy = tmp_path / ".bos-scan.yml"
        legacy.write_text("owner: legacy\n")
        preferred = tmp_path / ".github" / "bos-universal-config.yml"
        preferred.parent.mkdir()
        preferred.write_text("code_scanning:\n  owner: preferred\n")

        assert cfg_mod.discover(tmp_path) == preferred


def test_resolve_loads_preferred_json_universal_config(tmp_path: Path):
    config_path = tmp_path / ".github" / "bos-universal-config.json"
    config_path.parent.mkdir()
    config_path.write_text(
        '{"code_scanning":{"project_name":"json-project",'
        '"scan":{"fail_on":"critical"}}}'
    )

    cfg = cfg_mod.resolve(tmp_path)

    assert cfg.project_name == "json-project"
    assert cfg.scan.fail_on == "critical"
    assert cfg.source_path == str(config_path)


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


# ---------------------------------------------------------------------------
# repo_name defaulting
# ---------------------------------------------------------------------------

def test_project_name_defaults_to_repo_name_when_unset(tmp_path: Path):
    """When project_name is not in config, it defaults to the provided repo_name."""
    p = tmp_path / ".bos-scan.yml"
    p.write_text("owner: blackoutsecure\n")
    cfg = cfg_mod.load(p, repo_name="my-repo")
    assert cfg.project_name == "my-repo"


def test_project_name_in_config_takes_precedence_over_repo_name(tmp_path: Path):
    """When project_name is set in config, it is not overridden by repo_name."""
    p = tmp_path / ".bos-scan.yml"
    p.write_text("owner: blackoutsecure\nproject_name: explicit-name\n")
    cfg = cfg_mod.load(p, repo_name="my-repo")
    assert cfg.project_name == "explicit-name"


def test_project_name_stays_unset_when_no_repo_name_provided(tmp_path: Path):
    """When no repo_name is provided and project_name is unset in config."""
    p = tmp_path / ".bos-scan.yml"
    p.write_text("owner: blackoutsecure\n")
    cfg = cfg_mod.load(p, repo_name="")
    assert cfg.project_name == ""


def test_resolve_defaults_project_name_to_repo_name(tmp_path: Path):
    """The resolve() function passes repo_name through to load()."""
    config_path = tmp_path / ".bos-scan.yml"
    config_path.write_text("owner: blackoutsecure\n")

    cfg = cfg_mod.resolve(tmp_path, repo_name="resolved-repo")
    assert cfg.project_name == "resolved-repo"
