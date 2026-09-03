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
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import licensing
from _version import __version__
from config import (
    BranchPosture,
    CodeownersPosture,
    Config,
    DependenciesPosture,
    GHASPosture,
    SourceLicensePosture,
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
    ("LD00", "Dependency licences",   "SPDX licences of the resolved dependency graph"),
    ("LF00", "Source licences",       "Licence headers and copyright notices in the working tree"),
)


def _family_for(rule_id: str) -> int:
    """Return the `_RULE_FAMILIES` index for a finding (-1 = uncategorised)."""
    for i, (prefix, _, _) in enumerate(_RULE_FAMILIES):
        if rule_id.startswith(prefix):
            return i
    return -1


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _severity_label(severity: str) -> str:
    labels = {
        "pass": "✅ Pass",
        "warn": "⚠️ Warning",
        "fail": "🔴 High",
        "error": "🔥 Critical",
        "skip": "⚪ Not Assessed",
    }
    return labels.get(severity, severity.title())


def _audit_verdict(totals: dict[str, int]) -> tuple[str, str]:
    if totals["error"]:
        return (
            "Critical attention required",
            "One or more audit controls could not complete cleanly. Review error rows before relying on the final posture result.",
        )
    if totals["fail"]:
        return (
            "Action required",
            "One or more required security controls did not meet the configured policy.",
        )
    if totals["warn"]:
        return (
            "Advisory review recommended",
            "No blocking failures were detected, but one or more controls should be reviewed and tightened.",
        )
    if totals["skip"] and not totals["pass"]:
        return (
            "Assessment limited",
            "The audit did not produce a definitive pass/fail result for the selected controls.",
        )
    return (
        "Controls passed",
        "No failing or warning-level posture findings were detected by the configured audit controls.",
    )


def _recommended_actions(totals: dict[str, int]) -> list[str]:
    actions: list[str] = []
    if totals["error"]:
        actions.append("Resolve audit errors first; they indicate incomplete evidence collection or an execution issue.")
    if totals["fail"]:
        actions.append("Remediate High findings before treating this repository as policy-compliant.")
    if totals["warn"]:
        actions.append("Review Warning findings during the next hardening cycle and document any accepted risk.")
    if totals["skip"]:
        actions.append("Re-run with a GitHub App installation token that has the required read scopes to convert Not Assessed checks into pass/fail evidence. A scoped `SCANNING_PAT` remains a legacy fallback.")
    if not actions:
        actions.append("Maintain the current controls and keep this audit in the release or pull-request evidence trail.")
    actions.append("Review the SARIF upload in GitHub code scanning for durable finding history and alert triage.")
    return actions


def _display_remediation(finding: Finding) -> str:
    if finding.severity == "pass":
        return "No action needed."
    return finding.remediation or "—"


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
        "LD001": "Dependency licence data is available",
        "LD002": "Dependencies declare a licence",
        "LD003": "Dependency licences are OSI-approved",
        "LD004": "Dependency licences match repository policy",
        "LD005": "Dependency licences are compatible with the project licence",
        "LF001": "Source files carry SPDX licence headers",
        "LF002": "Source files carry no foreign licence",
        "LF003": "Copyright notices are consistent",
        "LF004": "In-tree licences are compatible with the project licence",
    }
    return titles.get(rule_id, f"Finding {rule_id}")


def _default_finding_remediation(rule_id: str, message: str) -> str:
    if rule_id == "PS001":
        return "Enable GitHub code scanning via Default setup or Advanced setup and ensure a supported CodeQL workflow is configured."
    if rule_id == "PS002":
        return (
            "Turn on GitHub secret scanning for the repository and review any existing alerts that should be remediated. "
            "Learn about availability and eligibility: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning#how-can-i-access-this-feature"
        )
    if rule_id == "PS003":
        return "Enable Dependabot vulnerability alerts and configure automated dependency updates for the repository."
    if rule_id == "PS004":
        return "Enable secret-scanning push protection in repository security settings to block secrets before they are pushed."
    if rule_id.startswith("PS012"):
        return "Pin third-party GitHub Action references to a fully qualified commit SHA and avoid floating tags or branches."
    if rule_id == "PS013":
        return (
            "Add `microsoft/security-devops-action` to a workflow step and pin it "
            "to a full commit SHA if Microsoft Security DevOps coverage is required; "
            "otherwise leave PS013 disabled or skipped in the repository policy."
        )
    if rule_id.startswith("PS01"):
        return "Add or tighten the workflow permission block so the job only has the minimum required GitHub token permissions."
    if rule_id.startswith("PS02"):
        return "Configure branch protection rules for the target branch, including required reviews and status checks where appropriate."
    if rule_id.startswith("PS03"):
        return "Add a CODEOWNERS file or correct invalid owners so every relevant path is covered by a valid reviewer."
    if rule_id == "LD001":
        return "Enable the dependency graph under Settings > Code security so licence data can be resolved for every ecosystem in the repository."
    if rule_id == "LD002":
        return "Pin or replace dependencies that publish no licence metadata; an undeclared licence grants no rights and blocks downstream redistribution."
    if rule_id == "LD003":
        return "Replace dependencies carrying source-available or non-OSI licences, or record an explicit exception in `posture.dependencies.allow`."
    if rule_id == "LD004":
        return "Replace the dependency, or update `posture.dependencies.allow` / `posture.dependencies.deny` if the licence is acceptable for this project."
    if rule_id == "LD005":
        return "Replace the dependency, relicense this project to satisfy the stronger terms, or record the combination as reviewed and accepted."
    if rule_id == "LF001":
        return "Add an `SPDX-License-Identifier:` header to each source file so downstream consumers and scanners can attribute the code."
    if rule_id == "LF002":
        return "Remove or replace the vendored file, or add its licence to `posture.source_licenses.allow` if carrying it is intentional and permitted."
    if rule_id == "LF003":
        return "Reconcile the copyright holders named in source headers with the repository NOTICE or LICENSE so attribution is consistent."
    if rule_id == "LF004":
        return "Remove the incompatible file, relicense this project, or document why the combination is permitted."
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
            "finding_key": self.finding_key,
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

    @property
    def finding_key(self) -> str:
        """Return an identity that remains stable as recommendation text changes."""
        identity = f"{self.rule_id}|{self.location or '(repository)'}"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return f"{self.rule_id.lower()}-{digest}"

    def recommendation_dict(self) -> dict[str, str]:
        """Return the machine-readable recommendation contract for this finding."""
        return {
            "finding_key": self.finding_key,
            "rule_id": self.rule_id,
            "title": self.title,
            "location": self.location,
            "recommendation": self.remediation,
            "confidence": self.remediation_confidence,
            "source": self.remediation_source,
            "patch_status": "unavailable",
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
        totals = self.totals()
        verdict, verdict_detail = _audit_verdict(totals)
        lines: list[str] = [
            "# Blackout Secure Code Scanning Kit Audit Report",
            "",
            "**Provided by [Blackout Secure](https://blackoutsecure.app)**",
            "",
            "## Summary",
            "",
            f"**Verdict:** {_md_escape(verdict)}",
            "",
            verdict_detail,
            "",
            f"**Totals:** ✅ {totals['pass']} pass · ⚠️ {totals['warn']} warning · "
            f"🔴 {totals['fail']} high · 🔥 {totals['error']} critical · "
            f"⚪ {totals['skip']} not assessed",
            "",
            "| Severity | Count | Meaning |",
            "| -------- | ----- | ------- |",
            f"| ✅ Pass | {totals['pass']} | Control satisfied the configured policy. |",
            f"| ⚠️ Warning | {totals['warn']} | Review recommended; not usually a hard block by itself. |",
            f"| 🔴 High | {totals['fail']} | Required control failed and should be remediated. |",
            f"| 🔥 Critical | {totals['error']} | Audit execution or evidence collection error. |",
            f"| ⚪ Not Assessed | {totals['skip']} | Check was skipped or lacked sufficient token scope/evidence. |",
            "",
            "## Recommended Actions",
            "",
        ]
        for action in _recommended_actions(totals):
            lines.append(f"- {action}")
        lines.append("")
        lines.extend([
            "## Scope and Methodology",
            "",
            "This automated audit reviews repository security posture controls exposed through GitHub repository configuration, workflow definitions, branch protection, CODEOWNERS, and GitHub Advanced Security settings. Results are evidence-based at run time and are intended to support release, compliance, and engineering risk review.",
            "",
        ])

        if not self.findings:
            lines.extend([
                "## Recommendations",
                "",
                "| Finding Key | Rule | Assessment | Location | Evidence / Why | Recommended Action | Automation |",
                "| ----------- | ---- | ---------- | -------- | -------------- | ------------------- | ---------- |",
                "| — | — | — | none | No PR |",
                "",
            ])
            lines.append("## Detailed Findings")
            lines.append("")
            lines.append("_No findings were emitted by the configured audit controls._")
            return "\n".join(lines) + "\n"

        recommendations = [f for f in self.findings if f.severity != "pass" and f.remediation.strip()]
        lines.extend([
            "## Recommendations",
            "",
            "| Finding Key | Rule | Assessment | Location | Evidence / Why | Recommended Action | Automation |",
            "| ----------- | ---- | ---------- | -------- | -------------- | ------------------- | ---------- |",
        ])
        lines.extend(
            f"| `{finding.finding_key}` | `{finding.rule_id}` | {_severity_label(finding.severity)} | "
            f"{_md_escape(finding.location or '—')} | {_md_escape(finding.message)} | "
            f"{_md_escape(finding.remediation)} | `not available` |"
            for finding in recommendations
        )
        if not recommendations:
            lines.append("| — | — | — | none | No PR |")
        lines.append("")

        def is_file_finding(finding: Finding) -> bool:
            location = finding.location or ""
            return location.startswith((".github/workflows/", ".github/actions/"))

        buckets: dict[int, list[Finding]] = {}
        for f in self.findings:
            if not is_file_finding(f):
                buckets.setdefault(_family_for(f.rule_id), []).append(f)

        for idx, (_, header, blurb) in enumerate(_RULE_FAMILIES):
            rows = buckets.get(idx)
            if not rows:
                continue
            if not any(line == "## Detailed Findings" for line in lines):
                lines.append("## Detailed Findings")
                lines.append("")
            lines.append(f"### {header}")
            lines.append(f"_{blurb}_")
            lines.append("")
            attention = [f for f in rows if f.severity != "pass"]
            passed = [f for f in rows if f.severity == "pass"]
            if attention:
                lines.append("#### Findings Requiring Attention")
                lines.append("")
                lines.append("| Rule | Severity | Location | Control | Evidence | Recommended Remediation |")
                lines.append("| ---- | -------- | -------- | ------- | -------- | ----------------------- |")
                for f in attention:
                    location = f.location or "—"
                    title = f.title or "—"
                    remediation = _display_remediation(f)
                    lines.append(
                        f"| `{f.rule_id}` | {_severity_label(f.severity)} | {_md_escape(location)} | "
                        f"{_md_escape(title)} | {_md_escape(f.message)} | {_md_escape(remediation)} |"
                    )
                lines.append("")
            if passed:
                lines.append("#### Passed Controls")
                lines.append("")
                lines.append("| Rule | Severity | Location | Control | Evidence |")
                lines.append("| ---- | -------- | -------- | ------- | -------- |")
                for f in passed:
                    location = f.location or "—"
                    title = f.title or "—"
                    lines.append(
                        f"| `{f.rule_id}` | {_severity_label(f.severity)} | {_md_escape(location)} | "
                        f"{_md_escape(title)} | {_md_escape(f.message)} |"
                    )
                lines.append("")

        file_findings = [f for f in self.findings if is_file_finding(f)]
        if file_findings:
            if not any(line == "## Detailed Findings" for line in lines):
                lines.append("## Detailed Findings")
                lines.append("")
            lines.append("### Workflow and action files")
            lines.append("_Per-file workflow and composite-action audit results._")
            lines.append("")
            by_file: dict[str, list[Finding]] = {}
            for finding in file_findings:
                by_file.setdefault(finding.location or "—", []).append(finding)
            for location, rows in sorted(by_file.items()):
                lines.append(f"#### `{_md_escape(location)}`")
                lines.append("")
                attention = [f for f in rows if f.severity != "pass"]
                passed = [f for f in rows if f.severity == "pass"]
                if attention:
                    lines.append("**Findings requiring attention**")
                    lines.append("")
                    lines.append("| Rule | Severity | Control | Evidence | Recommended Remediation |")
                    lines.append("| ---- | -------- | ------- | -------- | ----------------------- |")
                    for finding in attention:
                        lines.append(
                            f"| `{finding.rule_id}` | {_severity_label(finding.severity)} | "
                            f"{_md_escape(finding.title or '—')} | {_md_escape(finding.message)} | "
                            f"{_md_escape(_display_remediation(finding))} |"
                        )
                    lines.append("")
                if passed:
                    lines.append("**Passed controls**")
                    lines.append("")
                    lines.append("| Rule | Severity | Control | Evidence |")
                    lines.append("| ---- | -------- | ------- | -------- |")
                    for finding in passed:
                        lines.append(
                            f"| `{finding.rule_id}` | {_severity_label(finding.severity)} | "
                            f"{_md_escape(finding.title or '—')} | {_md_escape(finding.message)} |"
                        )
                    lines.append("")

        misc = buckets.get(-1)
        if misc:
            if not any(line == "## Detailed Findings" for line in lines):
                lines.append("## Detailed Findings")
                lines.append("")
            lines.append("### Other Findings")
            lines.append("")
            lines.append("| Rule | Severity | Location | Control | Evidence | Recommended Remediation |")
            lines.append("| ---- | -------- | -------- | ------- | -------- | ----------------------- |")
            for f in misc:
                remediation = _display_remediation(f)
                lines.append(
                    f"| `{f.rule_id}` | {_severity_label(f.severity)} | {_md_escape(f.location or '—')} | "
                    f"{_md_escape(f.title or '—')} | {_md_escape(f.message)} | {_md_escape(remediation)} |"
                )
            lines.append("")

        if totals["skip"]:
            lines.append(
                "> ⚪ **skip** rows mean the audit could not run that check — "
                "typically a token-scope limitation or a safe opt-out."
            )
            lines.append("")

        lines.extend([
            "---",
            "",
            "_This report was generated by [Blackout Secure Code Scanning Kit](https://github.com/blackoutsecure/bos-code-scanning-kit). Validate compensating controls and accepted risks through your organization's normal security review process._",
            "",
            "_Licence findings (`LD###`, `LF###`) are automated compliance and "
            "attribution checks against the [OSI approved-licence list](https://opensource.org/licenses). "
            "We are not lawyers and this is not legal advice — the aim is to "
            "surface licence metadata that is missing, inconsistent, or worth a "
            "closer look. Decisions that turn on legal interpretation belong "
            "with qualified counsel._",
            "",
        ])

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

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        """PATCH a repository setting using an explicitly supplied JSON body."""
        req = urllib.request.Request(
            f"{self.BASE}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method="PATCH",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": self.UA,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        return self._do(req)

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
    """PS013 — assess Microsoft Security DevOps coverage.

    `action` and `auto` inspect local workflow files for the MSDO action.
    Codeless Microsoft Defender for Cloud scanning has no repository-local
    artifact, so it must be declared as `msdo_coverage: codeless`; this action
    intentionally does not claim to verify external Azure connector state.

    The MSDO action is a meta-
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
    if cfg.msdo_coverage == "codeless":
        out.append(Finding(
            "PS013", "pass",
            "Microsoft Security DevOps codeless coverage declared via Microsoft Defender for Cloud; "
            "external connector state cannot be verified from repository files",
        ))
        return out
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
            "not detected in any workflow. Codeless Defender for Cloud coverage cannot be "
            "detected from repository files; set `posture.workflows.msdo_coverage: codeless` "
            "when the organization is connected. Otherwise consider adding the action for OSS "
            "analyzer coverage (Bandit / BinSkim / Trivy / Terrascan / Template-Analyzer / ESLint).",
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
    findings.extend(_scan_source_licenses(repo_root, cfg.posture.source_licenses))

    # API-driven checks
    try:
        gh = GitHub(token, timeout=http_timeout)
    except GitHubError as exc:
        findings.append(Finding("PS000", "error", str(exc)))
        return AuditResult(findings=tuple(findings))

    findings.extend(
        _audit_ghas(
            gh,
            owner,
            repo,
            cfg.posture.ghas,
            auto_enable_secret_scanning=cfg.remediation.auto_enable_secret_scanning,
        )
    )
    findings.extend(_audit_branches(gh, owner, repo, cfg.posture.branches))
    findings.extend(_audit_codeowners_api(gh, owner, repo, cfg.posture.codeowners, repo_root))
    findings.extend(_audit_dependency_licenses(gh, owner, repo, cfg.posture.dependencies))

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


_CODE_SECURITY_NOT_ENTITLED_HINT = (
    "GitHub Code Security is not available for this private or internal repository. "
    "Code scanning is free for public repositories; private/internal repositories require the "
    "appropriate GitHub Code Security entitlement. Learn more: https://docs.github.com/en/get-started/"
    "learning-about-github/about-github-advanced-security. Skipping to avoid a false-negative warning."
)


def _secret_protection_not_entitled_hint(repo_body: Any) -> str:
    owner = repo_body.get("owner") if isinstance(repo_body, dict) else {}
    owner_type = owner.get("type") if isinstance(owner, dict) else ""
    if owner_type == "Organization":
        eligibility = (
            "Organization-owned private/internal repositories require GitHub Secret Protection "
            "on GitHub Team or Enterprise Cloud."
        )
    else:
        eligibility = (
            "User-owned private repositories require GitHub Enterprise Cloud with Enterprise Managed Users, "
            "or GitHub Enterprise Server with GitHub Secret Protection."
        )
    return (
        "GitHub Secret Protection is not available for this private or internal repository. "
        "Secret scanning is free for public repositories. "
        f"{eligibility} Review eligibility and licensing: "
        "https://docs.github.com/en/code-security/secret-scanning/introduction/"
        "about-secret-scanning#how-can-i-access-this-feature. Skipping to avoid a false-negative warning."
    )


def _audit_ghas(
    gh: GitHub,
    owner: str,
    repo: str,
    cfg: GHASPosture,
    *,
    auto_enable_secret_scanning: bool = False,
) -> list[Finding]:
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
                f"GitHub code scanning unavailable — {_CODE_SECURITY_NOT_ENTITLED_HINT}",
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
                f"GitHub secret scanning unavailable — {_secret_protection_not_entitled_hint(repo_body)}",
            ))
        else:
            _body, status = gh.get_or_none(f"/repos/{owner}/{repo}/secret-scanning/alerts?per_page=1")
            if status == 200:
                out.append(Finding("PS002", "pass", "GHAS secret scanning is enabled"))
            elif status == 404:
                if auto_enable_secret_scanning:
                    try:
                        gh.patch(
                            f"/repos/{owner}/{repo}",
                            {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}},
                        )
                    except GitHubError as exc:
                        out.append(Finding(
                            "PS002", cfg.require_secret_scanning,
                            "GHAS secret scanning is not enabled and the requested automatic enablement failed",
                            remediation=(
                                "The repository is eligible, but the supplied token could not enable secret scanning: "
                                f"{exc}. Grant the GitHub App repository Administration: write permission, or enable it manually. "
                                "Instructions: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection"
                            ),
                        ))
                    else:
                        out.append(Finding(
                            "PS002", "pass",
                            "GHAS secret scanning was enabled automatically by the configured remediation policy",
                        ))
                else:
                    out.append(Finding(
                        "PS002", cfg.require_secret_scanning,
                        "GHAS secret scanning is not enabled — Settings → Code security → Secret scanning → Enable",
                    ))
            elif status == 403:
                # Token-scope limitation — see PS001 comment above.
                out.append(Finding(
                    "PS002", "skip",
                    "secret scanning probe forbidden — token cannot read the secret-scanning endpoint (403)",
                    remediation=(
                        "Use a GitHub App installation token with Secret scanning alerts: read and repository "
                        "Administration: read access, then rerun the audit. A scoped SCANNING_PAT is a legacy fallback. Only after the setting "
                        "is readable should secret scanning be enabled or existing alerts remediated."
                    ),
                ))
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
            out.append(Finding(
                "PS003", "skip",
                "Dependabot probe forbidden — token cannot read vulnerability-alert settings (403)",
                remediation=(
                    "Use a GitHub App installation token with Dependabot alerts: read and repository Administration: read "
                    "access, then rerun the audit. A scoped SCANNING_PAT is a legacy fallback. If the setting is then confirmed disabled, enable "
                    "Dependabot alerts in Settings → Code security."
                ),
            ))
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
                f"GitHub secret-scanning push protection unavailable — {_secret_protection_not_entitled_hint(repo_body)}",
            ))
        elif repo_status == 200 and isinstance(repo_body, dict):
            sa = repo_body.get("security_and_analysis")
            if not isinstance(sa, dict) or "secret_scanning_push_protection" not in sa:
                out.append(Finding(
                    "PS004", "skip",
                    "push-protection probe needs repository administration access — `security_and_analysis` is not visible",
                    remediation=(
                        "Use a GitHub App installation token with repository Administration: read access, then rerun the audit. "
                        "A scoped SCANNING_PAT is a legacy fallback. "
                        "Only after the setting is readable should secret-scanning push protection be enabled."
                    ),
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
                "push-protection probe forbidden — token cannot read repository security settings (403)",
                remediation=(
                    "Use a GitHub App installation token with repository Administration: read access, then rerun the audit. "
                    "A scoped SCANNING_PAT is a legacy fallback. "
                    "Only after the setting is readable should secret-scanning push protection be enabled."
                ),
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

    if status == 403:
        out.append(Finding(
            "PS020",
            "skip",
            f"branch `{branch}` protection check was forbidden — token scope is insufficient",
            location=loc,
            remediation=(
                "Re-run with a GitHub App installation token that has repository "
                "Administration: read access so branch protection can be assessed. "
                "A scoped SCANNING_PAT is a legacy fallback."
            ),
        ))
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


# ---------------------------------------------------------------------------
# LD001-004 — dependency licences
# ---------------------------------------------------------------------------

def _audit_dependency_licenses(
    gh: GitHub,
    owner: str,
    repo: str,
    cfg: DependenciesPosture,
) -> list[Finding]:
    """Audit the licences of the resolved dependency graph.

    Package licences come from GitHub's dependency-graph SBOM, which
    already spans every ecosystem GitHub understands. Classification is
    offline, against the vendored OSI snapshot.
    """
    severities = (
        cfg.require_declared_license,
        cfg.forbid_non_osi_license,
        cfg.forbid_denied_license,
        cfg.check_compatibility,
    )
    if all(severity == "skip" for severity in severities):
        return [Finding(rule, "skip", "dependency licence rules disabled by policy")
                for rule in licensing.RULES]

    loc = "dependency-graph"
    body, status = gh.get_or_none(f"/repos/{owner}/{repo}/dependency-graph/sbom")
    if status != 200:
        hint = {
            403: "token lacks read access to the dependency graph",
            404: "dependency graph is disabled for this repository",
        }.get(status, f"unexpected status {status}")
        return [Finding("LD001", "skip",
                        f"dependency SBOM unavailable — {hint}", location=loc),
                *(Finding(rule, "skip", "no SBOM to evaluate (see LD001)", location=loc)
                  for rule in licensing.RULES[1:])]

    try:
        packages = licensing.parse_sbom(body)
    except (TypeError, ValueError, KeyError) as exc:
        return [Finding("LD001", "error",
                        f"dependency SBOM could not be parsed ({type(exc).__name__})",
                        location=loc),
                *(Finding(rule, "skip", "no SBOM to evaluate (see LD001)", location=loc)
                  for rule in licensing.RULES[1:])]

    cat = licensing.catalogue()
    age = licensing.catalogue_age_days()
    stale = 0 < cfg.catalogue_max_age_days < age
    message = (f"resolved licences for {len(packages)} dependencies "
               f"(OSI snapshot {cat.snapshot})")
    if stale:
        message += (f" — the snapshot is {age} days old, over the "
                    f"{cfg.catalogue_max_age_days}-day limit, so approval "
                    "verdicts may be out of date")
    out: list[Finding] = [Finding(
        "LD001", "warn" if stale else "pass", message,
        location=loc,
        evidence={"packages": len(packages), "osi_snapshot": cat.snapshot,
                  "osi_snapshot_age_days": age},
    )]
    if not packages:
        return out + [Finding(rule, "skip", "no dependencies in the graph", location=loc)
                      for rule in licensing.RULES[1:]]

    # ----- LD002: every dependency declares a licence -----------------
    undeclared = [p for p in packages if not p.identifiers]
    out.append(_dependency_finding(
        "LD002", cfg.require_declared_license, undeclared, loc,
        ok=f"all {len(packages)} dependencies declare a licence",
        bad=lambda listed, n: (
            f"{n} dependencies declare no licence (SPDX `NOASSERTION`): {listed}. "
            "Undeclared means all rights reserved — redistribution is not granted"),
    ))

    # ----- LD003: no source-available / non-OSI licences --------------
    allow = {cat.normalise(item) for item in cfg.allow}
    allow.discard("unknown")
    non_osi = [
        p for p in packages
        if p.identifiers
        and not licensing.satisfies(p, allow)
        and not any(cat.is_osi_approved(i) for i in p.identifiers)
    ]
    out.append(_dependency_finding(
        "LD003", cfg.forbid_non_osi_license, non_osi, loc,
        ok="every declared dependency licence is OSI-approved",
        bad=lambda listed, n: (
            f"{n} dependencies carry a licence that is not OSI-approved: {listed}. "
            f"See {cat.url}"),
    ))

    # ----- LD004: repository allow/deny policy ------------------------
    deny = {cat.normalise(item) for item in cfg.deny}
    deny.discard("unknown")
    if not deny and not allow:
        out.append(Finding("LD004", "skip",
                           "no `allow` or `deny` licence policy configured",
                           location=loc))
    else:
        offenders = [
            p for p in packages
            if p.identifiers
            and (
                # A denied licence only bites when every option is denied;
                # a dual-licensed package can be taken under the other one.
                all(i in deny for i in p.identifiers)
                or (allow and not licensing.satisfies(p, allow))
            )
        ]
        policy = (f"allow={sorted(allow)}" if allow else "") + \
                 (" " if allow and deny else "") + \
                 (f"deny={sorted(deny)}" if deny else "")
        out.append(_dependency_finding(
            "LD004", cfg.forbid_denied_license, offenders, loc,
            ok=f"every dependency licence satisfies repository policy ({policy})",
            bad=lambda listed, n: (
                f"{n} dependencies violate the repository licence policy "
                f"({policy}): {listed}"),
        ))

    # ----- LD005: inbound compatibility with the project licence -----
    project = _project_license(Path("."), "auto")
    if cfg.check_compatibility == "skip":
        out.append(Finding("LD005", "skip", "disabled by policy", location=loc))
    elif project == "unknown":
        out.append(Finding(
            "LD005", "skip",
            "this project's own licence could not be resolved, so inbound "
            "compatibility cannot be assessed", location=loc))
    else:
        blocked: list[licensing.Package] = []
        constrained: list[licensing.Package] = []
        for package in packages:
            if not package.identifiers:
                continue
            verdicts = [licensing.compatibility(i, project) for i in package.identifiers]
            # A dual-licensed package only needs one acceptable option.
            if any(v.status == "ok" for v in verdicts):
                continue
            if any(v.status == "incompatible" for v in verdicts):
                blocked.append(package)
            elif any(v.status == "review" for v in verdicts):
                constrained.append(package)
        if blocked:
            out.append(_dependency_finding(
                "LD005", cfg.check_compatibility, blocked, loc,
                ok="", bad=lambda listed, n: (
                    f"{n} dependencies carry a licence that cannot be combined "
                    f"into a `{project}` work: {listed}")))
        elif constrained:
            out.append(_dependency_finding(
                "LD005", cfg.check_compatibility, constrained, loc,
                ok="", bad=lambda listed, n: (
                    f"{n} dependencies are more reciprocal than `{project}` and "
                    f"may impose their terms on the combined work: {listed}")))
        else:
            out.append(Finding(
                "LD005", "pass",
                f"every dependency licence is compatible with `{project}`",
                location=loc))
    return out


def _dependency_finding(
    rule_id: str,
    severity: str,
    offenders: list[licensing.Package],
    location: str,
    *,
    ok: str,
    bad: Any,
) -> Finding:
    """Build the pass/skip/violation row for one LD rule."""
    if severity == "skip":
        return Finding(rule_id, "skip", "disabled by policy", location=location)
    if not offenders:
        return Finding(rule_id, "pass", ok, location=location)
    return Finding(
        rule_id, severity,
        bad(licensing.listed(offenders), len(offenders)),
        location=location,
        evidence={
            "count": len(offenders),
            "packages": [
                {"name": p.name, "version": p.version, "license": p.expression}
                for p in offenders[:25]
            ],
        },
    )


# ---------------------------------------------------------------------------
# LF001-004 — working-tree licence and copyright notices
# ---------------------------------------------------------------------------

def _project_license(root: Path, configured: str) -> str:
    """Resolve the licence this project ships under."""
    if configured and configured != "auto":
        return licensing.catalogue().normalise(configured)
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:12000]
        except OSError:
            continue
        spdx = re.search(r"SPDX-License-Identifier:\s*([^\s*]+)", text, re.IGNORECASE)
        if spdx:
            return licensing.catalogue().normalise(spdx.group(1))
        lowered = text.lower()
        for pattern, identifier in (
            (r"apache license[\s,]*(?:version)?[\s]*2(?:\.0)?", "Apache-2.0"),
            (r"mit license", "MIT"),
            (r"gnu affero general public license.*version\s*3", "AGPL-3.0"),
            (r"gnu lesser general public license.*version\s*3", "LGPL-3.0"),
            (r"gnu general public license.*version\s*3", "GPL-3.0"),
            (r"gnu general public license.*version\s*2", "GPL-2.0"),
            (r"mozilla public license.*2\.0", "MPL-2.0"),
            (r"bsd 3-clause", "BSD-3-Clause"),
            (r"bsd 2-clause", "BSD-2-Clause"),
            (r"\bisc license\b", "ISC"),
        ):
            if re.search(pattern, lowered):
                return identifier
        return "unknown"
    return "unknown"


def _project_holders(root: Path) -> set[str]:
    """Copyright holders the repository already declares for itself."""
    holders: set[str] = set()
    for name in ("LICENSE", "LICENSE.md", "NOTICE", "NOTICE.md", "README.md"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            continue
        for entry in licensing.parse_copyrights(text):
            if entry.holder:
                holders.add(entry.holder.casefold())
    return holders


def _scan_source_licenses(
    root: Path,
    cfg: SourceLicensePosture,
) -> list[Finding]:
    """Audit licence headers and copyright notices across the working tree."""
    severities = (
        cfg.require_spdx_headers,
        cfg.forbid_foreign_license,
        cfg.require_consistent_copyright,
        cfg.check_compatibility,
    )
    if all(severity == "skip" for severity in severities):
        return [Finding(rule, "skip", "source licence rules disabled by policy")
                for rule in licensing.FILE_RULES]

    loc = "working-tree"
    try:
        scan = licensing.scan_tree(root, max_files=cfg.max_files)
    except OSError as exc:
        return [Finding("LF001", "error",
                        f"working tree could not be scanned ({type(exc).__name__})",
                        location=loc),
                *(Finding(rule, "skip", "no scan to evaluate (see LF001)", location=loc)
                  for rule in licensing.FILE_RULES[1:])]

    project = _project_license(root, cfg.project_license)
    allow = {licensing.catalogue().normalise(item) for item in cfg.allow}
    allow.discard("unknown")
    out: list[Finding] = []

    # ----- LF001: SPDX header coverage --------------------------------
    with_spdx = scan.with_spdx
    coverage = round(100 * len(with_spdx) / scan.scanned) if scan.scanned else 0
    truncated = " (scan truncated at max_files)" if scan.truncated else ""
    if cfg.require_spdx_headers == "skip":
        out.append(Finding("LF001", "skip",
                           f"SPDX header check disabled; scanned {scan.scanned} "
                           f"source file(s){truncated}", location=loc,
                           evidence={"scanned": scan.scanned, "coverage_percent": coverage}))
    elif not scan.scanned:
        out.append(Finding("LF001", "skip", "no scannable source files found",
                           location=loc))
    elif coverage < cfg.min_header_coverage:
        out.append(Finding(
            "LF001", cfg.require_spdx_headers,
            f"{coverage}% of {scan.scanned} source files carry an "
            f"`SPDX-License-Identifier` header, below the "
            f"{cfg.min_header_coverage}% minimum{truncated}",
            location=loc,
            evidence={"scanned": scan.scanned, "coverage_percent": coverage}))
    else:
        out.append(Finding(
            "LF001", "pass",
            f"{coverage}% of {scan.scanned} source files carry an SPDX header",
            location=loc,
            evidence={"scanned": scan.scanned, "coverage_percent": coverage}))

    # ----- LF002: no foreign licence in-tree --------------------------
    foreign = [
        f for f in with_spdx
        if f.identifier != project and f.identifier not in allow
    ]
    if cfg.forbid_foreign_license == "skip":
        out.append(Finding("LF002", "skip", "disabled by policy", location=loc))
    elif project == "unknown":
        out.append(Finding("LF002", "skip",
                           "this project's own licence could not be resolved",
                           location=loc))
    elif foreign:
        out.append(Finding(
            "LF002", cfg.forbid_foreign_license,
            f"{len(foreign)} file(s) declare a licence other than the project's "
            f"`{project}`: " + _listed_files(foreign),
            location=loc,
            evidence={"count": len(foreign), "files": _file_evidence(foreign)}))
    else:
        out.append(Finding(
            "LF002", "pass",
            f"every file with an SPDX header declares the project licence "
            f"`{project}`", location=loc))

    # ----- LF003: copyright consistency -------------------------------
    declared = _project_holders(root)
    file_holders: dict[str, list[str]] = {}
    for entry in scan.files:
        for notice in entry.copyrights:
            if notice.holder and notice.holder.casefold() not in declared:
                file_holders.setdefault(notice.holder, []).append(entry.path)
    if cfg.require_consistent_copyright == "skip":
        out.append(Finding("LF003", "skip", "disabled by policy", location=loc))
    elif not declared:
        out.append(Finding(
            "LF003", "skip",
            "no copyright holder is declared in LICENSE, NOTICE, or the README, "
            "so in-tree notices have nothing to be checked against",
            location=loc))
    elif file_holders:
        names = ", ".join(f"`{h}` ({len(p)} file(s))"
                          for h, p in sorted(file_holders.items())[:_MAX_HOLDERS])
        extra = len(file_holders) - min(len(file_holders), _MAX_HOLDERS)
        out.append(Finding(
            "LF003", cfg.require_consistent_copyright,
            f"{len(file_holders)} copyright holder(s) appear in source files but "
            f"not in this repository's own notices: {names}"
            + (f", and {extra} more" if extra else "")
            + ". Mixed attribution usually means vendored code, or a NOTICE that "
              "has fallen behind its contributors",
            location=loc,
            evidence={"holders": {h: p[:10] for h, p in sorted(file_holders.items())}}))
    else:
        out.append(Finding(
            "LF003", "pass",
            f"every in-tree copyright notice names a holder this repository "
            f"already declares ({len(declared)} holder(s))", location=loc))

    # ----- LF004: in-tree licence compatibility -----------------------
    if cfg.check_compatibility == "skip":
        out.append(Finding("LF004", "skip", "disabled by policy", location=loc))
    elif project == "unknown":
        out.append(Finding("LF004", "skip",
                           "this project's own licence could not be resolved",
                           location=loc))
    else:
        risky: list[tuple[licensing.SourceFile, Any]] = []
        for entry in with_spdx:
            if entry.identifier == project or entry.identifier in allow:
                continue
            verdict = licensing.compatibility(entry.identifier, project)
            if verdict.status in ("incompatible", "review"):
                risky.append((entry, verdict))
        if risky:
            worst = "incompatible" if any(v.status == "incompatible" for _, v in risky) \
                else "review"
            sample = risky[0][1].reason
            out.append(Finding(
                "LF004", cfg.check_compatibility,
                f"{len(risky)} in-tree file(s) carry a licence flagged "
                f"`{worst}` against the project's `{project}` — {sample}: "
                + _listed_files([f for f, _ in risky]),
                location=loc,
                evidence={"count": len(risky),
                          "files": [{"path": f.path, "license": f.identifier,
                                     "status": v.status, "reason": v.reason}
                                    for f, v in risky[:25]]}))
        else:
            out.append(Finding(
                "LF004", "pass",
                f"every in-tree licence is compatible with `{project}`",
                location=loc))
    return out


_MAX_HOLDERS = 5


def _listed_files(files: list[licensing.SourceFile]) -> str:
    shown = [f"{f.path} (`{f.identifier}`)" for f in files[:10]]
    extra = len(files) - len(shown)
    return ", ".join(shown) + (f", and {extra} more" if extra > 0 else "")


def _file_evidence(files: list[licensing.SourceFile]) -> list[dict[str, str]]:
    return [{"path": f.path, "license": f.identifier, "declared": f.declared}
            for f in files[:25]]
