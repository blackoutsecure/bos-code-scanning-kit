"""Posture auditor — GitHub repo security posture via REST API.

Audits, in one pass against the GitHub REST API:

    GHAS toggles (PS001-003)   Code scanning, Secret scanning, Dependabot alerts.
    Workflow permissions       Every workflow has a `permissions:` block,
    (PS010-011)                no `permissions: write-all` (incl. job-level).
    Branch protection          Required reviews, signed commits, force-push,
    (PS020-024)                status checks, conversation resolution.
    CODEOWNERS                 File present, syntactically valid, optionally
    (PS030-031)                API-verifies referenced users/teams.

Outputs `Finding` records with stable rule IDs. The CLI converts them
to console output and an optional SARIF artefact; the composite Action
also uploads SARIF to GHAS.

Network design: pure stdlib (`urllib.request`). One client per audit
run; 3-attempt linear backoff on 5xx; explicit error messages for the
common auth pitfalls (no token, fine-grained PAT missing scope,
SAML SSO not authorized). Reads ONLY — never mutates repo state.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .config import (
    BranchPosture,
    CodeownersPosture,
    Config,
    GHASPosture,
    WorkflowsPosture,
)

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

SEVERITIES = ("pass", "fail", "warn", "skip", "error")

# Rule-family display order — drives the section banners in the
# posture table. Keys are PS-id prefixes, values are (header, blurb).
_RULE_FAMILIES: tuple[tuple[str, str, str], ...] = (
    ("PS00", "GHAS toggles",         "Code scanning, secret scanning, Dependabot, push protection"),
    ("PS01", "Workflow permissions", "Per-file audit of `.github/workflows/*.yml`"),
    ("PS02", "Branch protection",    "Required reviews, status checks, conversation resolution"),
    ("PS03", "CODEOWNERS",           "Repo-level review routing"),
)


def _family_for(rule_id: str) -> int:
    """Return the `_RULE_FAMILIES` index for a finding (-1 = uncategorised)."""
    for i, (prefix, _, _) in enumerate(_RULE_FAMILIES):
        if rule_id.startswith(prefix):
            return i
    return -1


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _default_finding_title(rule_id: str) -> str:
    titles = {
        "PS001": "Code scanning is enabled",
        "PS002": "Secret scanning is enabled",
        "PS003": "Vulnerability alerts are enabled",
        "PS004": "Push protection is enabled",
        "PS010": "Workflow permissions are declared",
        "PS011": "Workflow write access is restricted",
        "PS012": "Actions are pinned to immutable refs",
        "PS013": "Microsoft Security DevOps is configured",
        "PS020": "Branch protection is configured",
        "PS021": "Required reviews are enforced",
        "PS022": "Force pushes are restricted",
        "PS023": "Required status checks are enforced",
        "PS024": "Signed commits are required",
        "PS025": "Conversation resolution is required",
        "PS030": "CODEOWNERS file is present",
        "PS031": "CODEOWNERS entries are valid",
        "PS032": "CODEOWNERS team owners exist",
        "PS033": "CODEOWNERS user owners exist",
    }
    return titles.get(rule_id, f"Finding {rule_id}")


def _default_finding_remediation(rule_id: str, message: str) -> str:
    if rule_id == "PS001":
        return "Enable GitHub code scanning via Default setup or Advanced setup and ensure a supported CodeQL workflow is configured."
    if rule_id == "PS002":
        return "Turn on GitHub secret scanning for the repository and review any existing alerts that should be remediated."
    if rule_id == "PS003":
        return "Enable Dependabot vulnerability alerts and configure automated dependency updates for the repository."
    if rule_id == "PS004":
        return "Enable secret-scanning push protection in repository security settings to block secrets before they are pushed."
    if rule_id.startswith("PS01"):
        return "Add or tighten the workflow permission block so the job only has the minimum required GitHub token permissions."
    if rule_id.startswith("PS012"):
        return "Pin third-party GitHub Action references to a fully qualified commit SHA and avoid floating tags or branches."
    if rule_id.startswith("PS02"):
        return "Configure branch protection rules for the target branch, including required reviews and status checks where appropriate."
    if rule_id.startswith("PS03"):
        return "Add a CODEOWNERS file or correct invalid owners so every relevant path is covered by a valid reviewer."
    return message or "Review the repository configuration and apply the required security controls."


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str            # one of SEVERITIES
    message: str
    location: str = ""       # e.g. ".github/workflows/foo.yml" or "branch:main"
    title: str = ""
    source: str = "posture"
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    remediation_confidence: str = "deterministic"
    remediation_source: str = "Blackout Secure Recommended Remediation"
    provider: str = ""

    def __post_init__(self) -> None:
        if not self.title:
            object.__setattr__(self, "title", _default_finding_title(self.rule_id))
        if not self.remediation:
            object.__setattr__(self, "remediation", _default_finding_remediation(self.rule_id, self.message))
        if not self.source:
            object.__setattr__(self, "source", "posture")
        if not self.remediation_source:
            object.__setattr__(self, "remediation_source", "Blackout Secure Recommended Remediation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "source": self.source,
            "location": self.location,
            "evidence": dict(self.evidence or {}),
            "remediation": self.remediation,
            "remediation_confidence": self.remediation_confidence,
            "remediation_source": self.remediation_source,
            "provider": self.provider,
        }


@dataclass(frozen=True)
class AuditResult:
    findings: tuple[Finding, ...] = ()

    @property
    def failed(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "fail")

    @property
    def warned(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "warn")

    @property
    def passed(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "pass")

    @property
    def errored(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "error")

    def totals(self) -> dict[str, int]:
        return {
            "pass": len(self.passed),
            "warn": len(self.warned),
            "fail": len(self.failed),
            "error": len(self.errored),
            "skip": sum(1 for f in self.findings if f.severity == "skip"),
        }

    def summary_markdown(self) -> str:
        lines: list[str] = ["## Summary", ""]
        totals = self.totals()
        lines.append(
            f"**Totals:** 🟢 {totals['pass']} pass · 🟡 {totals['warn']} warn · "
            f"🔴 {totals['fail']} fail · 🟣 {totals['error']} error · ⚪ {totals['skip']} skip"
        )
        lines.append("")

        if not self.findings:
            lines.append("_No findings._")
            return "\n".join(lines) + "\n"

        buckets: dict[int, list[Finding]] = {}
        for f in self.findings:
            buckets.setdefault(_family_for(f.rule_id), []).append(f)

        for idx, (_, header, blurb) in enumerate(_RULE_FAMILIES):
            rows = buckets.get(idx)
            if not rows:
                continue
            lines.append(f"### {header}")
            lines.append(f"_{blurb}_")
            lines.append("")
            lines.append("| Rule | Severity | Location | Title | Message | Remediation |")
            lines.append("| ---- | -------- | -------- | ----- | ------- | ------------ |")
            for f in rows:
                location = f.location or "—"
                title = f.title or "—"
                remediation = f.remediation or "—"
                lines.append(
                    f"| `{f.rule_id}` | {f.severity} | {_md_escape(location)} | "
                    f"{_md_escape(title)} | {_md_escape(f.message)} | {_md_escape(remediation)} |"
                )
            lines.append("")

        misc = buckets.get(-1)
        if misc:
            lines.append("### Other")
            lines.append("")
            lines.append("| Rule | Severity | Location | Title | Message | Remediation |")
            lines.append("| ---- | -------- | -------- | ----- | ------- | ------------ |")
            for f in misc:
                lines.append(
                    f"| `{f.rule_id}` | {f.severity} | {_md_escape(f.location or '—')} | "
                    f"{_md_escape(f.title or '—')} | {_md_escape(f.message)} | {_md_escape(f.remediation or '—')} |"
                )
            lines.append("")

        if totals["skip"]:
            lines.append(
                "> ⚪ **skip** rows mean the audit could not run that check — "
                "typically a token-scope limitation or a safe opt-out."
            )
            lines.append("")

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# GitHub REST client
# ---------------------------------------------------------------------------

class GitHubError(RuntimeError):
    """Raised for non-recoverable GitHub API errors (auth, 404, 422)."""


class GitHub:
    """Minimal stdlib REST client. Single instance per audit run."""

    BASE = "https://api.github.com"
    UA = f"bos-code-scanning-kit/{__version__}"

    def __init__(self, token: str, *, timeout: int = 20):
        if not token:
            raise GitHubError(
                "GITHUB_TOKEN is empty. Pass `github_token: ${{ secrets.GITHUB_TOKEN }}` "
                "or an admin PAT (posture audits need `repo` + `admin:org` for some checks)."
            )
        self.token = token
        self.timeout = timeout

    # GET; returns parsed JSON or None on 404.
    def get(self, path: str, *, accept: str = "application/vnd.github+json") -> Any:
        url = f"{self.BASE}{path}"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": accept,
                "User-Agent": self.UA,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        return self._do(req)

    # GET; returns (parsed JSON | None, HTTP status) — exposes 404 without raising.
    def get_or_none(self, path: str, *, accept: str = "application/vnd.github+json") -> tuple[Any, int]:
        try:
            return self.get(path, accept=accept), 200
        except GitHubError as exc:
            msg = str(exc)
            if "404" in msg:
                return None, 404
            if "403" in msg:
                return None, 403
            raise

    def get_raw_text(self, owner: str, repo: str, branch: str, path: str) -> str | None:
        """Fetch a file's contents from a branch HEAD. Returns None on 404."""
        body, status = self.get_or_none(
            f"/repos/{owner}/{repo}/contents/{path}?ref={branch}",
        )
        if status != 200 or body is None:
            return None
        if not isinstance(body, dict) or body.get("encoding") != "base64":
            return None
        import base64
        try:
            return base64.b64decode(body["content"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def _do(self, req: urllib.request.Request) -> Any:
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    if not raw:
                        return None
                    return json.loads(raw.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                # 5xx → retry; 4xx → fail fast with friendly message.
                if 500 <= exc.code < 600 and attempt < 2:
                    last_exc = exc
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise GitHubError(_friendly_http_error(exc, req.full_url)) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise GitHubError(f"network error contacting GitHub: {exc}") from exc
            except json.JSONDecodeError as exc:
                raise GitHubError(f"non-JSON response from {req.full_url}: {exc}") from exc

        # Shouldn't reach here, but be explicit.
        raise GitHubError(f"exhausted retries: {last_exc}")


def _friendly_http_error(exc: urllib.error.HTTPError, url: str) -> str:
    if exc.code == 401:
        return f"401 Unauthorized for {url}: token is invalid or expired."
    if exc.code == 403:
        body = ""
        with contextlib.suppress(Exception):
            body = exc.read().decode("utf-8", errors="replace")
        if "SAML" in body or "saml" in body:
            return (
                f"403 SAML SSO required for {url}: authorize your PAT for the org "
                "(Settings → Developer settings → Personal access tokens → Configure SSO)."
            )
        return (
            f"403 Forbidden for {url}: the token lacks required scope. "
            "Posture audits typically need `repo` + `admin:org` (Secret Scanning + "
            "Dependabot alerts require admin)."
        )
    if exc.code == 404:
        return f"404 Not Found for {url}: feature not enabled, or token cannot see the resource."
    return f"{exc.code} {exc.reason} for {url}"


# ---------------------------------------------------------------------------
# Workflow file parser — local repo walk for PS010/PS011
# ---------------------------------------------------------------------------

PERMISSIONS_BLOCK = re.compile(r"^permissions\s*:", re.MULTILINE)
WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.MULTILINE)
JOB_WRITE_ALL = re.compile(r"^\s{2,}permissions\s*:\s*write-all\s*$", re.MULTILINE)

# PS012 — captures the `uses:` value (group 1) along with its line number
# via re.finditer offsets. Tolerates the YAML list form (`- uses: ...`)
# and the bare mapping form (`uses: ...`); strips an optional trailing
# inline `# ...` comment and surrounding quotes inside the function so
# the regex itself stays simple.
USES_LINE = re.compile(
    r"^[ \t]*-?[ \t]*uses:[ \t]*(?P<ref>[^\r\n]+?)[ \t]*(?:#.*)?$",
    re.MULTILINE,
)
SHA_40 = re.compile(r"^[0-9a-f]{40}$")

# PS013 — detect `uses:` references to Microsoft Security DevOps
# (`microsoft/security-devops-action`). Matches any pinning (SHA, tag,
# branch) so the probe sees MSDO whether it's pinned by SHA (preferred)
# or by tag. Owner/repo match only; the @ref is captured inside the
# message for the audit row's `details`.
MSDO_USES = re.compile(
    r"^[ \t]*-?[ \t]*uses:[ \t]*[\"']?(?P<ref>microsoft/security-devops-action(?:@[^\s\"'#]+)?)[\"']?[ \t]*(?:#.*)?$",
    re.MULTILINE | re.IGNORECASE,
)


def _scan_workflow_perms(repo_root: Path, cfg: WorkflowsPosture) -> list[Finding]:
    """PS010 + PS011 — workflow-permissions audit, purely from the local checkout."""
    out: list[Finding] = []
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return out

    for wf in sorted(wf_dir.glob("*.y*ml")):
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError as exc:
            out.append(Finding(
                "PS010", "error",
                f"could not read workflow: {exc}",
                location=wf.relative_to(repo_root).as_posix(),
            ))
            continue

        rel = wf.relative_to(repo_root).as_posix()

        # PS010 — `permissions:` block present.
        if cfg.require_permissions_block != "skip":
            if PERMISSIONS_BLOCK.search(text):
                out.append(Finding("PS010", "pass",
                                   "`permissions:` block present", location=rel))
            else:
                out.append(Finding(
                    "PS010",
                    cfg.require_permissions_block,
                    "missing top-level `permissions:` block — workflow inherits the repo default",
                    location=rel,
                ))

        # PS011 — no `permissions: write-all` (at top level or job level).
        if cfg.forbid_write_all != "skip":
            if WRITE_ALL.search(text) or JOB_WRITE_ALL.search(text):
                out.append(Finding(
                    "PS011",
                    cfg.forbid_write_all,
                    "`permissions: write-all` grants every scope — replace with explicit minimum",
                    location=rel,
                ))
            else:
                out.append(Finding("PS011", "pass",
                                   "no `permissions: write-all` found", location=rel))

    return out


# ---------------------------------------------------------------------------
# PS012 — pinned-actions audit (workflows + composite action manifests)
# ---------------------------------------------------------------------------

def _scan_pinned_actions(repo_root: Path, cfg: WorkflowsPosture) -> list[Finding]:
    """PS012 — every third-party `uses:` ref must be pinned to a 40-char SHA.

    Walks both `.github/workflows/*.y*ml` and `.github/actions/**/*.y*ml`
    (composite action manifests). Local (`./...`, `../...`) and
    `docker://...` refs are exempt; `cfg.allow_tag_pin` exempts trusted
    `owner/repo` entries.
    """
    out: list[Finding] = []
    if cfg.require_pinned_actions == "skip":
        return out

    targets: list[Path] = []
    wf_dir = repo_root / ".github" / "workflows"
    if wf_dir.is_dir():
        targets.extend(sorted(wf_dir.glob("*.y*ml")))
    actions_dir = repo_root / ".github" / "actions"
    if actions_dir.is_dir():
        targets.extend(sorted(actions_dir.rglob("*.y*ml")))

    if not targets:
        return out

    allow = frozenset(cfg.allow_tag_pin)

    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            out.append(Finding(
                "PS012", "error",
                f"could not read file: {exc}",
                location=path.relative_to(repo_root).as_posix(),
            ))
            continue

        rel = path.relative_to(repo_root).as_posix()
        offenders: list[tuple[int, str, str]] = []  # (line, ref, reason)
        for match in USES_LINE.finditer(text):
            raw_ref = match.group("ref").strip().strip("\"'")
            if not raw_ref:
                continue
            # Local + docker refs are out of scope for PS012.
            if raw_ref.startswith(("./", "../", "docker://")):
                continue
            line_no = text.count("\n", 0, match.start()) + 1
            if "@" not in raw_ref:
                offenders.append((line_no, raw_ref, "missing `@<sha>` suffix"))
                continue
            base, _, ver = raw_ref.partition("@")
            owner_repo = "/".join(base.split("/")[:2])
            if owner_repo in allow:
                continue
            if SHA_40.match(ver):
                continue
            offenders.append((line_no, raw_ref, f"version `{ver}` is not a 40-char SHA"))

        if not offenders:
            out.append(Finding("PS012", "pass",
                               "all `uses:` references pinned to 40-char SHA",
                               location=rel))
            continue
        for line_no, ref, reason in offenders:
            out.append(Finding(
                "PS012",
                cfg.require_pinned_actions,
                f"L{line_no}: `{ref}` — {reason}",
                location=rel,
            ))

    return out


# ---------------------------------------------------------------------------
# PS013 — Microsoft Security DevOps detection
# ---------------------------------------------------------------------------

def _scan_msdo(repo_root: Path, cfg: WorkflowsPosture) -> list[Finding]:
    """PS013 — detect `microsoft/security-devops-action` usage in workflows.

    Best-effort, local-only static probe. The MSDO action is a meta-
    runner bundling Microsoft's OSS analyzers (Bandit / BinSkim / Trivy /
    Terrascan / Template-Analyzer / ESLint). We report it as part of the
    security posture so audits capture coverage even when those analyzers
    are not driven by the kit itself.

    Severity matrix (cfg.detect_msdo):
        skip (default) — absent MSDO drops out of SARIF (skips sidecar
                         only); present MSDO still records a `pass` row.
                         Matches the "if installed gather details, else
                         ignore" contract.
        warn / fail    — absent MSDO raises a finding at that severity
                         to push adoption org-wide.
    """
    out: list[Finding] = []
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        # No workflows at all — nothing to scan, but still surface the
        # absence under the configured severity (default skip).
        out.append(Finding(
            "PS013", cfg.detect_msdo,
            "Microsoft Security DevOps not detected — no `.github/workflows/` directory",
        ))
        return out

    workflows = sorted(wf_dir.glob("*.y*ml"))
    if not workflows:
        out.append(Finding(
            "PS013", cfg.detect_msdo,
            "Microsoft Security DevOps not detected — no workflow files present",
        ))
        return out

    found_any = False
    for wf in workflows:
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError as exc:
            out.append(Finding(
                "PS013", "error",
                f"could not read workflow: {exc}",
                location=wf.relative_to(repo_root).as_posix(),
            ))
            continue

        rel = wf.relative_to(repo_root).as_posix()
        for match in MSDO_USES.finditer(text):
            found_any = True
            ref = match.group("ref").strip()
            line_no = text.count("\n", 0, match.start()) + 1
            # Detail: capture pinning quality so the audit row tells the
            # operator whether this MSDO usage also meets PS012 hygiene.
            _, _, ver = ref.partition("@")
            if not ver:
                pin_note = "unpinned (no `@ref`)"
            elif SHA_40.match(ver):
                pin_note = f"SHA-pinned (`{ver[:7]}…`)"
            else:
                pin_note = f"tag/branch-pinned (`{ver}`)"
            out.append(Finding(
                "PS013", "pass",
                f"L{line_no}: MSDO detected — {ref} ({pin_note})",
                location=rel,
            ))

    if not found_any:
        # No MSDO call site found — emit the configured-severity row.
        # Default `skip` keeps the row out of SARIF but surfaces it in
        # the `--skips-json` sidecar so operators still see the gap.
        out.append(Finding(
            "PS013", cfg.detect_msdo,
            "Microsoft Security DevOps action (`microsoft/security-devops-action`) "
            "not detected in any workflow — consider adding it for OSS analyzer "
            "coverage (Bandit / BinSkim / Trivy / Terrascan / Template-Analyzer / ESLint).",
        ))

    return out


# ---------------------------------------------------------------------------
# Audit entry points
# ---------------------------------------------------------------------------

def audit(
    *,
    cfg: Config,
    owner: str,
    repo: str,
    token: str,
    repo_root: Path,
    http_timeout: int = 20,
) -> AuditResult:
    """Run the full posture audit. Returns a single `AuditResult`.

    `http_timeout` is the per-request urlopen timeout (seconds) handed to
    the `GitHub` REST client. Each probe is independent, so the practical
    upper bound on a posture run is roughly `http_timeout` * number-of-
    probes; on a baseline run that's ~10 calls. Tune via the composite
    action's `http_timeout` input or the CLI's `--http-timeout` flag.
    """
    findings: list[Finding] = []

    # Local-only checks (no API needed) — always run first so the
    # operator gets something even when the token is wrong.
    findings.extend(_scan_workflow_perms(repo_root, cfg.posture.workflows))
    findings.extend(_scan_pinned_actions(repo_root, cfg.posture.workflows))
    findings.extend(_scan_msdo(repo_root, cfg.posture.workflows))
    findings.extend(_scan_codeowners_local(repo_root, cfg.posture.codeowners))

    # API-driven checks
    try:
        gh = GitHub(token, timeout=http_timeout)
    except GitHubError as exc:
        findings.append(Finding("PS000", "error", str(exc)))
        return AuditResult(findings=tuple(findings))

    findings.extend(_audit_ghas(gh, owner, repo, cfg.posture.ghas))
    findings.extend(_audit_branches(gh, owner, repo, cfg.posture.branches))
    findings.extend(_audit_codeowners_api(gh, owner, repo, cfg.posture.codeowners, repo_root))

    return AuditResult(findings=tuple(findings))


# ---------------------------------------------------------------------------
# PS001-003 — GHAS toggles
# ---------------------------------------------------------------------------

def _ghas_entitlement(body: Any, status: int) -> str:
    # Classify whether GitHub Advanced Security is provably enabled for the
    # repo. Returns one of:
    #   "entitled"     — GHAS features (code scanning, secret scanning,
    #                    push protection) are available; run the probes.
    #   "not_entitled" — Provably off (private/internal repo whose
    #                    `security_and_analysis.advanced_security.status`
    #                    is `"disabled"`). Skip GHAS probes cleanly so we
    #                    don't warn about a toggle the operator literally
    #                    cannot flip without buying the SKU.
    #   "unknown"      — Token can't see the field, repo metadata
    #                    forbidden, etc. Fall through to each probe's
    #                    own 403/404 handling.
    if status != 200 or not isinstance(body, dict):
        return "unknown"
    # Public repos: GHAS code/secret scanning is free. Push protection on
    # public repos is also free (GHAS-for-public-repos covers all three).
    if body.get("visibility") == "public" or body.get("private") is False:
        return "entitled"
    sa = body.get("security_and_analysis")
    if not isinstance(sa, dict):
        return "unknown"
    adv = sa.get("advanced_security")
    if not isinstance(adv, dict):
        return "unknown"
    adv_status = adv.get("status")
    if adv_status == "enabled":
        return "entitled"
    if adv_status == "disabled":
        return "not_entitled"
    return "unknown"


_GHAS_NOT_ENTITLED_HINT = (
    "GitHub Advanced Security is not enabled for this private repository "
    "— Settings → Code security → GitHub Advanced Security → Enable "
    "(requires the GHAS SKU). Skipping to avoid a false-negative warning."
)


def _audit_ghas(gh: GitHub, owner: str, repo: str, cfg: GHASPosture) -> list[Finding]:
    out: list[Finding] = []

    # Single repo-metadata fetch up front: powers the entitlement gate for
    # PS001/PS002/PS004 AND is reused by PS004's push-protection probe so
    # we never hit `/repos/{owner}/{repo}` twice. PS003 (Dependabot) is
    # GHAS-independent and never consults this — vulnerability alerts are
    # free on every plan tier.
    needs_repo_body = (
        cfg.require_code_scanning != "skip"
        or cfg.require_secret_scanning != "skip"
        or cfg.require_push_protection != "skip"
    )
    repo_body: Any = None
    repo_status: int = 0
    if needs_repo_body:
        repo_body, repo_status = gh.get_or_none(f"/repos/{owner}/{repo}")
    entitlement = _ghas_entitlement(repo_body, repo_status)

    # PS001 — code scanning enabled (Default OR Advanced setup).
    #
    # GitHub exposes two mutually-exclusive UX paths to enable CodeQL on a
    # repo: "Default setup" (managed, default-setup endpoint reports
    # state=configured) and "Advanced" (caller-owned workflow that uploads
    # SARIF via `github/codeql-action/analyze`). The default-setup endpoint
    # ONLY reports on the former — a repo running CodeQL via Advanced gets
    # state=not-configured even though scanning is active. Without the
    # fallback below this rule fires a false-negative warn for every
    # caller using Advanced (incl. this kit itself).
    if cfg.require_code_scanning != "skip":
        if entitlement == "not_entitled":
            out.append(Finding(
                "PS001", "skip",
                f"GHAS code scanning unavailable — {_GHAS_NOT_ENTITLED_HINT}",
            ))
        else:
            body, status = gh.get_or_none(f"/repos/{owner}/{repo}/code-scanning/default-setup")
            if status == 200 and isinstance(body, dict) and body.get("state") == "configured":
                out.append(Finding(
                    "PS001", "pass",
                    "GHAS code scanning enabled — Default setup (recommended, managed by GitHub)",
                ))
            else:
                # Try the Advanced-setup fallback unconditionally — the
                # `code-scanning/analyses` endpoint only needs
                # `security_events: read`, which the default `GITHUB_TOKEN`
                # DOES grant (no scope escalation over the default-setup
                # probe). A 200 + non-empty array means CodeQL is actively
                # scanning via a caller-owned workflow, so we can report
                # `pass` even when the default-setup probe was forbidden
                # (403) — the previous code dropped straight to `skip` on
                # the 403 path and hid that meaningful result on baseline-
                # token runs.
                adv_body, adv_status = gh.get_or_none(
                    f"/repos/{owner}/{repo}/code-scanning/analyses?tool_name=CodeQL&per_page=1",
                )
                adv_active = (
                    adv_status == 200
                    and isinstance(adv_body, list)
                    and len(adv_body) > 0
                )

                if adv_active:
                    out.append(Finding(
                        "PS001", "pass",
                        "GHAS code scanning enabled — Advanced setup (caller-owned CodeQL workflow uploading analyses)",
                    ))
                elif status == 403:
                    # Default-setup endpoint forbidden AND no Advanced
                    # analyses visible — could be Default-setup we can't
                    # see, or Advanced not-yet-scanned, or genuinely off.
                    # `skip` keeps the row honest ("we did not determine
                    # state") instead of false-warning. Grant a PAT with
                    # `repo` via the `github_token` input to upgrade to a
                    # real pass/fail check.
                    out.append(Finding(
                        "PS001", "skip",
                        "code scanning probe forbidden — token cannot see Default setup state and no Advanced (CodeQL) analyses found via fallback (provide a PAT to differentiate)",
                    ))
                else:
                    # Default-setup reachable and reports not-configured,
                    # and no Advanced analyses either — genuinely off.
                    out.append(Finding(
                        "PS001", cfg.require_code_scanning,
                        "GHAS code scanning is not enabled — Settings → Code security → Code scanning → Set up (Default, recommended), "
                        "OR commit a workflow that calls `github/codeql-action/analyze` (Advanced)",
                    ))

    # PS002 — secret scanning enabled (probe by listing alerts; 404 = disabled)
    if cfg.require_secret_scanning != "skip":
        if entitlement == "not_entitled":
            out.append(Finding(
                "PS002", "skip",
                f"GHAS secret scanning unavailable — {_GHAS_NOT_ENTITLED_HINT}",
            ))
        else:
            _body, status = gh.get_or_none(f"/repos/{owner}/{repo}/secret-scanning/alerts?per_page=1")
            if status == 200:
                out.append(Finding("PS002", "pass", "GHAS secret scanning is enabled"))
            elif status == 404:
                out.append(Finding(
                    "PS002", cfg.require_secret_scanning,
                    "GHAS secret scanning is not enabled — Settings → Code security → Secret scanning → Enable",
                ))
            elif status == 403:
                # Token-scope limitation — see PS001 comment above.
                out.append(Finding("PS002", "skip",
                                   "secret scanning probe forbidden — token needs `admin:org` or repo admin (provide a PAT to check)"))
            else:
                out.append(Finding("PS002", "error",
                                   f"secret scanning probe returned unexpected status {status}"))

    # PS003 — Dependabot vulnerability alerts enabled.
    # NOT gated on GHAS entitlement: Dependabot alerts are free on every
    # plan tier (public, private, internal) and do not require the GHAS
    # SKU. This probe runs even when PS001/PS002/PS004 skip.
    if cfg.require_dependabot_alerts != "skip":
        _body, status = gh.get_or_none(
            f"/repos/{owner}/{repo}/vulnerability-alerts",
            accept="application/vnd.github+json",
        )
        if status == 204 or status == 200:
            out.append(Finding("PS003", "pass", "Dependabot vulnerability alerts are enabled"))
        elif status == 404:
            out.append(Finding(
                "PS003", cfg.require_dependabot_alerts,
                "Dependabot vulnerability alerts are not enabled — Settings → Code security → Dependabot alerts → Enable",
            ))
        elif status == 403:
            # Token-scope limitation — see PS001 comment above.
            out.append(Finding("PS003", "skip",
                               "Dependabot probe forbidden — token needs `repo:admin` (provide a PAT to check)"))
        else:
            out.append(Finding("PS003", "error",
                               f"Dependabot probe returned unexpected status {status}"))

    # PS004 — secret-scanning push protection enabled. Independent from PS002:
    # base scanning catches secrets already in history; push protection refuses
    # the push before the secret lands. They toggle separately in the UI and
    # warrant separate audit rows. Reuses the top-of-function `/repos/{owner}/{repo}`
    # fetch (stored in `repo_body`/`repo_status`) to avoid a second round trip.
    # `security_and_analysis` is admin-only, so non-admin tokens get a 200
    # with the field stripped silently. Treat the missing-field case as `skip`
    # (we couldn't see it) rather than `warn` (it's off).
    if cfg.require_push_protection != "skip":
        if entitlement == "not_entitled":
            out.append(Finding(
                "PS004", "skip",
                f"GHAS secret-scanning push protection unavailable — {_GHAS_NOT_ENTITLED_HINT}",
            ))
        elif repo_status == 200 and isinstance(repo_body, dict):
            sa = repo_body.get("security_and_analysis")
            if not isinstance(sa, dict) or "secret_scanning_push_protection" not in sa:
                out.append(Finding(
                    "PS004", "skip",
                    "push-protection probe needs repo admin — `security_and_analysis` not visible to this token",
                ))
            else:
                pp_status = (sa.get("secret_scanning_push_protection") or {}).get("status")
                if pp_status == "enabled":
                    out.append(Finding(
                        "PS004", "pass",
                        "secret-scanning push protection is enabled",
                    ))
                else:
                    out.append(Finding(
                        "PS004", cfg.require_push_protection,
                        "secret-scanning push protection is not enabled — "
                        "Settings → Code security → Secret scanning → Push protection → Enable",
                    ))
        elif repo_status == 403:
            out.append(Finding(
                "PS004", "skip",
                "push-protection probe forbidden — token needs `repo` (admin) (provide a PAT to check)",
            ))
        else:
            out.append(Finding(
                "PS004", "error",
                f"push-protection probe returned unexpected status {repo_status}",
            ))

    return out


# ---------------------------------------------------------------------------
# PS020-024 — Branch protection
# ---------------------------------------------------------------------------

def _audit_branches(
    gh: GitHub,
    owner: str,
    repo: str,
    branches: dict[str, BranchPosture],
) -> list[Finding]:
    out: list[Finding] = []
    for branch, expectations in branches.items():
        out.extend(_audit_one_branch(gh, owner, repo, branch, expectations))
    return out


def _audit_one_branch(
    gh: GitHub,
    owner: str,
    repo: str,
    branch: str,
    want: BranchPosture,
) -> list[Finding]:
    out: list[Finding] = []
    loc = f"branch:{branch}"
    body, status = gh.get_or_none(f"/repos/{owner}/{repo}/branches/{branch}/protection")

    if status == 404:
        out.append(Finding("PS020", want.severity,
                           f"branch `{branch}` has no protection rules", location=loc))
        return out

    if status != 200 or not isinstance(body, dict):
        out.append(Finding("PS020", "error",
                           f"could not read protection for `{branch}` (status {status})",
                           location=loc))
        return out

    # PS021 — required reviews
    reviews = body.get("required_pull_request_reviews") or {}
    actual_reviews = int(reviews.get("required_approving_review_count", 0))
    if actual_reviews >= want.required_reviews:
        out.append(Finding("PS021", "pass",
                           f"required reviews: {actual_reviews} (>= {want.required_reviews})",
                           location=loc))
    else:
        out.append(Finding(
            "PS021", want.severity,
            f"required reviews: {actual_reviews} (< {want.required_reviews})",
            location=loc,
        ))

    # PS022 — restrict force pushes
    allow_force = (body.get("allow_force_pushes") or {}).get("enabled", False)
    if want.restrict_force_push:
        if not allow_force:
            out.append(Finding("PS022", "pass",
                               "force pushes are restricted", location=loc))
        else:
            out.append(Finding("PS022", want.severity,
                               "force pushes are allowed", location=loc))

    # PS023 — required status checks
    checks = body.get("required_status_checks") or {}
    if want.require_status_checks:
        if checks:
            out.append(Finding("PS023", "pass",
                               "required status checks are configured", location=loc))
        else:
            out.append(Finding("PS023", want.severity,
                               "no required status checks", location=loc))

    # PS024 — signed commits required
    sig = (body.get("required_signatures") or {}).get("enabled", False)
    if want.require_signed_commits:
        if sig:
            out.append(Finding("PS024", "pass",
                               "signed commits are required", location=loc))
        else:
            out.append(Finding("PS024", want.severity,
                               "signed commits are NOT required", location=loc))

    # PS025 — conversation resolution
    convo = (body.get("required_conversation_resolution") or {}).get("enabled", False)
    if want.require_conversation_resolution:
        if convo:
            out.append(Finding("PS025", "pass",
                               "conversation resolution required", location=loc))
        else:
            out.append(Finding("PS025", want.severity,
                               "conversation resolution NOT required", location=loc))

    return out


# ---------------------------------------------------------------------------
# PS030-031 — CODEOWNERS
# ---------------------------------------------------------------------------

CODEOWNERS_SEARCH_PATHS = (
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
)


def _find_local_codeowners(root: Path) -> Path | None:
    for rel in CODEOWNERS_SEARCH_PATHS:
        p = root / rel
        if p.is_file():
            return p
    return None


CODEOWNER_REF = re.compile(r"@([A-Za-z0-9][\w./-]*)")


def _scan_codeowners_local(root: Path, cfg: CodeownersPosture) -> list[Finding]:
    out: list[Finding] = []
    if cfg.require_file == "skip":
        return out

    co = _find_local_codeowners(root)
    if co is None:
        out.append(Finding("PS030", cfg.require_file,
                           "no CODEOWNERS file in repo root, .github/, or docs/"))
        return out

    out.append(Finding("PS030", "pass",
                       "CODEOWNERS present", location=co.relative_to(root).as_posix()))

    # Basic syntax check — every non-comment, non-blank line should
    # have a path token plus at least one owner reference.
    try:
        lines = co.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        out.append(Finding("PS030", "error",
                           f"could not read CODEOWNERS: {exc}",
                           location=co.relative_to(root).as_posix()))
        return out

    for n, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not CODEOWNER_REF.search(line):
            out.append(Finding(
                "PS031", "warn",
                f"line {n} has no owner reference (`@user` / `@org/team`)",
                location=co.relative_to(root).as_posix(),
            ))
    return out


def _audit_codeowners_api(
    gh: GitHub,
    owner: str,
    repo: str,
    cfg: CodeownersPosture,
    root: Path,
) -> list[Finding]:
    """Optional: API-verify each `@user` / `@org/team` reference exists."""
    if not cfg.validate_users_exist:
        return []
    co = _find_local_codeowners(root)
    if co is None:
        return []

    try:
        text = co.read_text(encoding="utf-8")
    except OSError:
        return []

    refs: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for match in CODEOWNER_REF.finditer(line):
            refs.add(match.group(1))

    out: list[Finding] = []
    loc = co.relative_to(root).as_posix()
    for ref in sorted(refs):
        if "/" in ref:
            # team reference: @org/team
            org, team = ref.split("/", 1)
            _body, status = gh.get_or_none(f"/orgs/{org}/teams/{team}")
            if status == 200:
                out.append(Finding("PS032", "pass",
                                   f"team `@{ref}` exists", location=loc))
            else:
                out.append(Finding("PS032", "warn",
                                   f"team `@{ref}` not found (status {status})",
                                   location=loc))
        else:
            _body, status = gh.get_or_none(f"/users/{ref}")
            if status == 200:
                out.append(Finding("PS033", "pass",
                                   f"user `@{ref}` exists", location=loc))
            else:
                out.append(Finding("PS033", "warn",
                                   f"user `@{ref}` not found (status {status})",
                                   location=loc))
    return out
