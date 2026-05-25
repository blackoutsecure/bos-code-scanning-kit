"""`.bos-scan.yml` loader, schema, and defaults.

This module is the single source of truth for what knobs the kit
exposes and what their defaults are. Both the CLI and the composite
Action read configuration through `load()`.

Design:
    * Defaults are conservative — anything that can FAIL a release
      defaults to `warn` so first-time adopters see findings without
      breaking their pipeline. Opt-in to `fail` per-rule.
    * Unknown top-level keys are NOT an error (forward-compat: future
      bos-marketplace-kit-only keys will be ignored by us, and vice
      versa).
    * Validation raises `ConfigError` with line/path context for the
      operator. The CLI converts that into a friendly stderr message.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class ConfigError(ValueError):
    """Raised when `.bos-scan.yml` parses but is semantically invalid."""


# ---------------------------------------------------------------------------
# Allowed enums
# ---------------------------------------------------------------------------

SEVERITIES = ("fail", "warn", "skip")
FAIL_ON_LEVELS = ("critical", "high", "medium", "low", "never")
SCAN_MODES = ("auto", "explicit", "none")


# ---------------------------------------------------------------------------
# Dataclasses — shape mirrors the YAML
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeQLConfig:
    languages: str | list[str] = "auto"          # "auto" | explicit list
    exclude_languages: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanConfig:
    tools: str | list[str] = "auto"              # "auto" | "none" | explicit list
    exclude: tuple[str, ...] = ()
    fail_on: str = "high"
    codeql: CodeQLConfig = field(default_factory=CodeQLConfig)


@dataclass(frozen=True)
class GHASPosture:
    require_code_scanning: str = "warn"          # severity
    require_secret_scanning: str = "warn"
    require_dependabot_alerts: str = "warn"


@dataclass(frozen=True)
class WorkflowsPosture:
    require_permissions_block: str = "warn"
    forbid_write_all: str = "warn"


@dataclass(frozen=True)
class BranchPosture:
    required_reviews: int = 1
    require_signed_commits: bool = False
    restrict_force_push: bool = True
    require_status_checks: bool = True
    require_conversation_resolution: bool = False
    severity: str = "warn"                       # one severity for the whole branch rule


@dataclass(frozen=True)
class CodeownersPosture:
    require_file: str = "warn"                   # severity
    validate_users_exist: bool = False           # opt-in (costs an API call per entry)


@dataclass(frozen=True)
class PostureConfig:
    ghas: GHASPosture = field(default_factory=GHASPosture)
    workflows: WorkflowsPosture = field(default_factory=WorkflowsPosture)
    branches: dict[str, BranchPosture] = field(default_factory=dict)
    codeowners: CodeownersPosture = field(default_factory=CodeownersPosture)


@dataclass(frozen=True)
class Config:
    # Cross-kit owner/project metadata (shared with bos-marketplace-kit).
    owner: str = ""
    project_name: str = ""
    email: str = ""

    scan: ScanConfig = field(default_factory=ScanConfig)
    posture: PostureConfig = field(default_factory=PostureConfig)

    # Path the config was loaded from (empty when defaults were used).
    source_path: str = ""


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

DEFAULT_FILENAMES = (".bos-scan.yml", ".bos-scan.yaml", "bos-scan.yml")


def discover(cwd: Path) -> Path | None:
    """Find the config file in `cwd`. Returns None if no file exists."""
    for name in DEFAULT_FILENAMES:
        candidate = cwd / name
        if candidate.is_file():
            return candidate
    return None


def load(path: Path | None) -> Config:
    """Load a config from disk. `None` returns built-in defaults."""
    if path is None:
        return Config()

    try:
        import yaml
    except ImportError as exc:                            # pragma: no cover - hard env
        raise ConfigError("PyYAML is required to load .bos-scan.yml") from exc

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc

    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(doc, dict):
        raise ConfigError(f"{path}: top-level must be a mapping")

    return _from_dict(doc, source_path=str(path))


def _from_dict(doc: dict[str, Any], *, source_path: str = "") -> Config:
    owner = _str(doc, "owner")
    project = _str(doc, "project_name")
    email = _str(doc, "email")

    scan = _scan_from_dict(_dict(doc, "scan"))
    posture = _posture_from_dict(_dict(doc, "posture"))

    return Config(
        owner=owner,
        project_name=project,
        email=email,
        scan=scan,
        posture=posture,
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# Per-section parsers
# ---------------------------------------------------------------------------

def _scan_from_dict(d: dict[str, Any]) -> ScanConfig:
    tools = d.get("tools", "auto")
    if isinstance(tools, str):
        if tools not in SCAN_MODES:
            raise ConfigError(
                f"scan.tools: '{tools}' is not one of {SCAN_MODES} (or an explicit list)"
            )
    elif isinstance(tools, list):
        if not all(isinstance(t, str) for t in tools):
            raise ConfigError("scan.tools: list entries must be strings")
        tools = list(tools)
    else:
        raise ConfigError("scan.tools: must be a string or list of strings")

    exclude = _str_tuple(d, "exclude")

    fail_on = d.get("fail_on", "high")
    if fail_on not in FAIL_ON_LEVELS:
        raise ConfigError(
            f"scan.fail_on: '{fail_on}' is not one of {FAIL_ON_LEVELS}"
        )

    cq_dict = _dict(d, "codeql")
    cq_langs = cq_dict.get("languages", "auto")
    if isinstance(cq_langs, str):
        if cq_langs != "auto":
            raise ConfigError(
                "scan.codeql.languages: must be 'auto' or a list of language names"
            )
    elif isinstance(cq_langs, list):
        if not all(isinstance(lang, str) for lang in cq_langs):
            raise ConfigError("scan.codeql.languages: list entries must be strings")
        cq_langs = list(cq_langs)
    else:
        raise ConfigError("scan.codeql.languages: must be 'auto' or a list")

    cq = CodeQLConfig(
        languages=cq_langs,
        exclude_languages=_str_tuple(cq_dict, "exclude_languages"),
    )

    return ScanConfig(tools=tools, exclude=exclude, fail_on=fail_on, codeql=cq)


def _posture_from_dict(d: dict[str, Any]) -> PostureConfig:
    ghas_d = _dict(d, "ghas")
    ghas = GHASPosture(
        require_code_scanning=_severity(ghas_d, "require_code_scanning", "warn"),
        require_secret_scanning=_severity(ghas_d, "require_secret_scanning", "warn"),
        require_dependabot_alerts=_severity(ghas_d, "require_dependabot_alerts", "warn"),
    )

    wf_d = _dict(d, "workflows")
    workflows = WorkflowsPosture(
        require_permissions_block=_severity(wf_d, "require_permissions_block", "warn"),
        forbid_write_all=_severity(wf_d, "forbid_write_all", "warn"),
    )

    branches_d = _dict(d, "branches")
    branches: dict[str, BranchPosture] = {}
    for name, branch_cfg in branches_d.items():
        if not isinstance(branch_cfg, dict):
            raise ConfigError(f"posture.branches.{name}: must be a mapping")
        branches[name] = _branch_from_dict(branch_cfg, branch_name=name)

    co_d = _dict(d, "codeowners")
    codeowners = CodeownersPosture(
        require_file=_severity(co_d, "require_file", "warn"),
        validate_users_exist=_bool(co_d, "validate_users_exist", False),
    )

    return PostureConfig(
        ghas=ghas,
        workflows=workflows,
        branches=branches,
        codeowners=codeowners,
    )


def _branch_from_dict(d: dict[str, Any], *, branch_name: str) -> BranchPosture:
    required = d.get("required_reviews", 1)
    if not isinstance(required, int) or required < 0:
        raise ConfigError(
            f"posture.branches.{branch_name}.required_reviews: must be a non-negative integer"
        )
    return BranchPosture(
        required_reviews=required,
        require_signed_commits=_bool(d, "require_signed_commits", False),
        restrict_force_push=_bool(d, "restrict_force_push", True),
        require_status_checks=_bool(d, "require_status_checks", True),
        require_conversation_resolution=_bool(d, "require_conversation_resolution", False),
        severity=_severity(d, "severity", "warn"),
    )


# ---------------------------------------------------------------------------
# Typed accessors — keep parsers free of `isinstance` boilerplate
# ---------------------------------------------------------------------------

def _dict(d: dict[str, Any], key: str) -> dict[str, Any]:
    value = d.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"`{key}`: must be a mapping")
    return value


def _str(d: dict[str, Any], key: str, default: str = "") -> str:
    value = d.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"`{key}`: must be a string")
    return value.strip()


def _bool(d: dict[str, Any], key: str, default: bool) -> bool:
    value = d.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"`{key}`: must be a boolean (true/false)")
    return value


def _severity(d: dict[str, Any], key: str, default: str) -> str:
    value = d.get(key, default)
    if value not in SEVERITIES:
        raise ConfigError(
            f"`{key}`: '{value}' is not one of {SEVERITIES}"
        )
    return value


def _str_tuple(d: dict[str, Any], key: str) -> tuple[str, ...]:
    value = d.get(key, [])
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"`{key}`: must be a list of strings")
    return tuple(value)
