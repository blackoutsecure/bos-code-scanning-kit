"""Layered configuration loader, schema, and defaults.

This module is the single source of truth for what knobs the kit
exposes and what their defaults are. Configuration is deep-merged in
marketplace, global, then repository order before schema validation.
Both the CLI and the composite Action resolve configuration here.

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
    # PS004 — secret-scanning push protection. Independent from
    # `require_secret_scanning` (PS002): base scanning catches secrets
    # already in history, push protection refuses the push before the
    # secret lands. Probed via `security_and_analysis` on the repo
    # object, which is admin-only — non-admin tokens silently get the
    # field stripped and the rule degrades to `skip` (see posture.py).
    require_push_protection: str = "warn"


@dataclass(frozen=True)
class WorkflowsPosture:
    require_permissions_block: str = "warn"
    forbid_write_all: str = "warn"
    # PS012 — every third-party `uses:` reference in workflows + composite
    # actions must be pinned to a 40-char commit SHA. Local (`./...`) and
    # `docker://` refs are exempt. `allow_tag_pin` accepts `owner/repo`
    # entries (e.g. `"actions/checkout"`) for trusted first-party actions
    # where tag pinning is intentional. Defaults to `warn` so adopters see
    # findings without breaking pipelines on day one; opt up to `"fail"`.
    require_pinned_actions: str = "warn"
    allow_tag_pin: tuple[str, ...] = ()
    # PS013 — Microsoft Security DevOps detection. Optional companion
    # probe: when `microsoft/security-devops-action` is wired into any
    # workflow, emit a `pass` row per occurrence with the pinned ref +
    # line so the audit captures it as part of the security posture.
    # When MSDO is absent, emit a single row at this severity. Defaults
    # to `"skip"` (purely informational — absent MSDO is not a finding,
    # the row only shows up in the skips JSON sidecar). Flip to
    # `"warn"` or `"fail"` to require MSDO across the org.
    detect_msdo: str = "skip"


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
class RemediationConfig:
    enable_ai_findings_summary: bool = False
    ai_findings_summary_provider: str = ""
    local_heuristic_fallback: bool = True


@dataclass(frozen=True)
class Config:
    # Cross-kit owner/project metadata (shared with bos-marketplace-kit).
    owner: str = ""
    project_name: str = ""
    email: str = ""

    scan: ScanConfig = field(default_factory=ScanConfig)
    posture: PostureConfig = field(default_factory=PostureConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)

    # Highest-precedence user config path (empty for Marketplace-only config).
    source_path: str = ""
    # All applied tiers in precedence order. The bundled marketplace
    # resource is first, followed by global and repository files.
    source_paths: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

CONFIG_SECTION = "code_scanning"
MARKETPLACE_CONFIG_FILE = "blackout-secure-code-scanning-kit-marketplace-config.json"
DEFAULT_GLOBAL_CONFIG_PATH = ".github/blackout-secure-code-scanning-kit-global-config.yml"

# Legacy names remain public for callers that import this constant.
DEFAULT_FILENAMES = (".bos-scan.yml", ".bos-scan.yaml", "bos-scan.yml")
DEFAULT_CONFIG_PATHS = (
    ".github/bos-universal-config.json",
    ".github/bos-universal-config.yml",
    ".github/bos-universal-config.yaml",
    "bos-universal-config.json",
    "bos-universal-config.yml",
    "bos-universal-config.yaml",
    *DEFAULT_FILENAMES,
)


def discover(cwd: Path) -> Path | None:
    """Find the preferred repository config. Returns None when absent."""
    for relative_path in DEFAULT_CONFIG_PATHS:
        candidate = cwd / relative_path
        if candidate.is_file():
            return candidate
    return None


def resolve(
    root: Path,
    *,
    config_path: str | Path | None = None,
    global_config_path: str | Path = DEFAULT_GLOBAL_CONFIG_PATH,
    use_global_config: bool | None = None,
) -> Config:
    """Resolve marketplace, optional global, and repository config tiers.

    ``use_global_config`` is tri-state: ``None`` auto-loads the conventional
    path when present, ``True`` requires it, and ``False`` disables it.
    Explicit relative paths are resolved from ``root``.
    """
    root = root.resolve()

    if config_path:
        repo_path = _from_root(root, config_path)
        if not repo_path.is_file():
            raise ConfigError(f"config not found: {repo_path}")
    else:
        repo_path = discover(root)

    global_path: Path | None = None
    if use_global_config is not False:
        candidate = _from_root(root, global_config_path or DEFAULT_GLOBAL_CONFIG_PATH)
        if candidate.is_file():
            global_path = candidate
        elif use_global_config is True:
            raise ConfigError(f"global config not found: {candidate}")

    return load(repo_path, global_path=global_path)


def load(path: Path | None, *, global_path: Path | None = None) -> Config:
    """Load and merge bundled marketplace, global, and repository config."""
    merged = _load_marketplace_section()
    source_paths = [f"bundled:{MARKETPLACE_CONFIG_FILE}"]

    if global_path is not None:
        merged = _deep_merge(merged, _load_section(global_path))
        source_paths.append(str(global_path))

    if path is not None:
        merged = _deep_merge(merged, _load_section(path))
        source_paths.append(str(path))

    source_path = str(path or global_path or "")
    return _from_dict(
        merged,
        source_path=source_path,
        source_paths=tuple(source_paths),
    )


def _from_root(root: Path, path: str | Path) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else root / candidate


def _load_marketplace_section() -> dict[str, Any]:
    try:
        resource = Path(__file__).with_name(MARKETPLACE_CONFIG_FILE)
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - broken package
        raise ConfigError(f"failed to load marketplace config: {exc}") from exc
    return _parse_document(text, source=f"bundled:{MARKETPLACE_CONFIG_FILE}")


def _load_section(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config must be UTF-8 text: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"failed to read config {path}: {exc}") from exc
    return _parse_document(text, source=str(path))


def _parse_document(text: str, *, source: str) -> dict[str, Any]:
    """Parse YAML/JSON and extract the optional ``code_scanning`` section."""

    try:
        import yaml
    except ImportError as exc:                            # pragma: no cover - hard env
        raise ConfigError("PyYAML is required to load code scanning config") from exc

    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {source}: {exc}") from exc

    if not isinstance(doc, dict):
        raise ConfigError(f"{source}: top-level must be a mapping")

    section = doc.get(CONFIG_SECTION, doc)
    if not isinstance(section, dict):
        raise ConfigError(f"{source}: `{CONFIG_SECTION}` must be a mapping")
    return section


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge mappings; lower-precedence lists and scalars replace."""
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _from_dict(
    doc: dict[str, Any],
    *,
    source_path: str = "",
    source_paths: tuple[str, ...] = (),
) -> Config:
    owner = _str(doc, "owner")
    project = _str(doc, "project_name")
    email = _str(doc, "email")

    scan = _scan_from_dict(_dict(doc, "scan"))
    posture = _posture_from_dict(_dict(doc, "posture"))
    remediation = _remediation_from_dict(_dict(doc, "remediation"))

    return Config(
        owner=owner,
        project_name=project,
        email=email,
        scan=scan,
        posture=posture,
        remediation=remediation,
        source_path=source_path,
        source_paths=source_paths,
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
        require_push_protection=_severity(ghas_d, "require_push_protection", "warn"),
    )

    wf_d = _dict(d, "workflows")
    workflows = WorkflowsPosture(
        require_permissions_block=_severity(wf_d, "require_permissions_block", "warn"),
        forbid_write_all=_severity(wf_d, "forbid_write_all", "warn"),
        require_pinned_actions=_severity(wf_d, "require_pinned_actions", "warn"),
        allow_tag_pin=_str_tuple(wf_d, "allow_tag_pin"),
        detect_msdo=_severity(wf_d, "detect_msdo", "skip"),
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


def _remediation_from_dict(d: dict[str, Any]) -> RemediationConfig:
    return RemediationConfig(
        enable_ai_findings_summary=_bool(d, "enable_ai_findings_summary", False),
        ai_findings_summary_provider=_str(d, "ai_findings_summary_provider", ""),
        local_heuristic_fallback=_bool(d, "local_heuristic_fallback", True),
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
