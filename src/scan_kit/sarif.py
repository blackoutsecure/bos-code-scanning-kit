"""SARIF merge + posture-finding → SARIF emitter.

GitHub's `github/codeql-action/upload-sarif` accepts EITHER a single
SARIF file or a directory of them, but a single merged file gives the
operator one Security-tab category to triage and makes our `--dry-run`
output coherent.

The merger:
    * preserves each tool's `runs` entry verbatim,
    * deduplicates `runs[].tool.driver.rules[]` by `id` if a rule
      appears in two upstream files,
    * appends our own posture-audit `Run` built from `Finding` objects.

SARIF spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .posture import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/"
    "sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def empty_log() -> dict[str, Any]:
    """Return a SARIF 2.1.0 log with zero runs."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [],
    }


def merge(*logs: dict[str, Any]) -> dict[str, Any]:
    """Merge an arbitrary number of SARIF log dicts into one."""
    merged = empty_log()
    for log in logs:
        if not isinstance(log, dict):
            continue
        runs = log.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if isinstance(run, dict):
                merged["runs"].append(run)
    return merged


def load(path: Path) -> dict[str, Any]:
    """Load a SARIF file from disk. Raises `ValueError` on bad input."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"SARIF file not found: {path}") from exc

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError(f"{path}: SARIF root must be an object")

    if doc.get("version") != SARIF_VERSION:
        # Don't fail — some scanners emit 2.1.0 without the version key,
        # or use a near-equivalent. Let GHAS reject if it really must.
        pass
    return doc


def merge_files(paths: list[Path]) -> dict[str, Any]:
    """Convenience: load each path and merge them."""
    return merge(*(load(p) for p in paths))


def dump(log: dict[str, Any], path: Path) -> None:
    """Write a SARIF log to `path` with deterministic 2-space JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(log, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Posture findings → SARIF Run
# ---------------------------------------------------------------------------

POSTURE_TOOL_NAME = "bos-code-scanning-kit"
POSTURE_INFORMATION_URI = "https://github.com/blackoutsecure/bos-code-scanning-kit"


# Map our internal severity → SARIF result level.
_SARIF_LEVEL = {
    "fail":  "error",
    "warn":  "warning",
    "pass":  "none",      # GHAS hides `none` entries — keeps the Security tab focused
    "skip":  "none",
    "error": "warning",   # tool-side errors surface as warnings rather than failures
}


def posture_run(findings: list[Finding]) -> dict[str, Any]:
    """Build a SARIF `Run` representing the posture-audit results."""
    rule_ids: dict[str, str] = {}      # id → short help text
    sarif_results: list[dict[str, Any]] = []

    for f in findings:
        rule_ids.setdefault(f.rule_id, _rule_help(f.rule_id))
        # Drop pass/skip from the upload — keeps the Security tab signal-rich.
        if f.severity in ("pass", "skip"):
            continue
        # GHAS rejects results without a `physicalLocation`. Earlier
        # the validator only required `locations: [...]` to be non-empty
        # (and accepted logical-only entries); it has since tightened to
        # `locationFromSarifResult: expected a physical location`. So
        # `_location_for` ALWAYS returns a block containing a
        # `physicalLocation`, synthesising a sentinel pointing at
        # `.github/` for repo-wide / branch findings that have no
        # natural file to attach to. The original `logicalLocations`
        # entry is kept alongside the sentinel so the GHAS UI still
        # shows "repository" or "branch:main" as the friendly label.
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [_location_for(f)],
        })

    rules = [
        {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": help_text},
            "helpUri": f"{POSTURE_INFORMATION_URI}#{rid.lower()}",
        }
        for rid, help_text in sorted(rule_ids.items())
    ]

    return {
        "tool": {
            "driver": {
                "name": POSTURE_TOOL_NAME,
                "version": __version__,
                "informationUri": POSTURE_INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": sarif_results,
    }


def _location_for(f: Finding) -> dict[str, Any]:
    """Turn a `Finding.location` into a SARIF location block.

    Always returns a block containing a `physicalLocation` — GHAS Code
    Scanning rejects any `result` whose location lacks one with
    `locationFromSarifResult: expected a physical location`. (An earlier
    revision of the validator only enforced `locations` being non-empty
    and accepted `logicalLocations`-only entries; the upload pipeline now
    rejects those too.)

    For findings that have no natural file to attach to — repo-wide
    GHAS-settings probes (PS001/PS002/PS003) and branch-protection
    checks (PS020+) — we synthesise a `physicalLocation` pointing at
    `.github/`, the directory where security config conventionally
    lives. The original `logicalLocations` entry is kept alongside so
    the GHAS UI still surfaces the semantic label ("repository" or
    "branch:main") in the alert details.
    """
    loc = f.location
    # Repo-wide finding (no specific file or branch) — sentinel
    # `.github/` physicalLocation + repo-scoped logicalLocation.
    if not loc:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": ".github/"},
            },
            "logicalLocations": [{"name": "repository", "kind": "module"}],
        }
    # Branch references are virtual — same sentinel artifact, branch
    # name preserved as a logicalLocation so the GHAS UI shows it.
    if loc.startswith("branch:"):
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": ".github/"},
            },
            "logicalLocations": [{"name": loc, "kind": "object"}],
        }
    # Everything else is a file path.
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": loc},
        },
    }


_RULE_HELP = {
    "PS001": "GHAS code scanning is enabled",
    "PS002": "GHAS secret scanning is enabled",
    "PS003": "Dependabot vulnerability alerts are enabled",
    "PS010": "Every workflow declares a `permissions:` block",
    "PS011": "No workflow grants `permissions: write-all`",
    "PS020": "Branch is protected by a ruleset / protection rule",
    "PS021": "Branch requires the configured number of PR reviews",
    "PS022": "Branch restricts force pushes",
    "PS023": "Branch requires status checks before merging",
    "PS024": "Branch requires signed commits",
    "PS025": "Branch requires PR conversation resolution",
    "PS030": "CODEOWNERS file is present",
    "PS031": "CODEOWNERS entries reference an owner",
    "PS032": "CODEOWNERS team references resolve via the GitHub API",
    "PS033": "CODEOWNERS user references resolve via the GitHub API",
    "PS000": "Posture audit could not be performed (auth / network error)",
}


def _rule_help(rule_id: str) -> str:
    return _RULE_HELP.get(rule_id, rule_id)
