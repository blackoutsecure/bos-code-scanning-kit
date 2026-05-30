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
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str            # one of SEVERITIES
    message: str
    location: str = ""       # e.g. ".github/workflows/foo.yml" or "branch:main"


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
# Audit entry points
# ---------------------------------------------------------------------------

def audit(
    *,
    cfg: Config,
    owner: str,
    repo: str,
    token: str,
    repo_root: Path,
) -> AuditResult:
    """Run the full posture audit. Returns a single `AuditResult`."""
    findings: list[Finding] = []

    # Local-only checks (no API needed) — always run first so the
    # operator gets something even when the token is wrong.
    findings.extend(_scan_workflow_perms(repo_root, cfg.posture.workflows))
    findings.extend(_scan_pinned_actions(repo_root, cfg.posture.workflows))
    findings.extend(_scan_codeowners_local(repo_root, cfg.posture.codeowners))

    # API-driven checks
    try:
        gh = GitHub(token)
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

def _audit_ghas(gh: GitHub, owner: str, repo: str, cfg: GHASPosture) -> list[Finding]:
    out: list[Finding] = []

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
        body, status = gh.get_or_none(f"/repos/{owner}/{repo}/code-scanning/default-setup")
        if status == 200 and isinstance(body, dict) and body.get("state") == "configured":
            out.append(Finding(
                "PS001", "pass",
                "GHAS code scanning enabled — Default setup (recommended, managed by GitHub)",
            ))
        elif status == 403:
            # Not an error — the default `GITHUB_TOKEN` lacks the scope to
            # query this endpoint. Surface as `skip` so the row is honest
            # ("we did not check") rather than alarming, and stays out of
            # the SARIF upload entirely. Grant a PAT with `repo` via the
            # `github_token` input to upgrade to a real pass/fail check.
            out.append(Finding("PS001", "skip",
                               "code scanning probe forbidden — token needs `repo` (provide a PAT to check)"))
        else:
            # Default-setup is off — fall back to checking whether an
            # Advanced workflow has uploaded any CodeQL analyses for the
            # repo. A single 200 with non-empty array means CodeQL is
            # actively scanning via Advanced and the row should `pass`.
            # The analyses endpoint needs `security_events: read`, which
            # the default `GITHUB_TOKEN` does grant — no scope escalation
            # over the default-setup probe.
            adv_body, adv_status = gh.get_or_none(
                f"/repos/{owner}/{repo}/code-scanning/analyses?tool_name=CodeQL&per_page=1",
            )
            if adv_status == 200 and isinstance(adv_body, list) and len(adv_body) > 0:
                out.append(Finding(
                    "PS001", "pass",
                    "GHAS code scanning enabled — Advanced setup (caller-owned CodeQL workflow uploading analyses)",
                ))
            else:
                out.append(Finding(
                    "PS001", cfg.require_code_scanning,
                    "GHAS code scanning is not enabled — Settings → Code security → Code scanning → Set up (Default, recommended), "
                    "OR commit a workflow that calls `github/codeql-action/analyze` (Advanced)",
                ))

    # PS002 — secret scanning enabled (probe by listing alerts; 404 = disabled)
    if cfg.require_secret_scanning != "skip":
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
    # warrant separate audit rows. Probed via `security_and_analysis` on the
    # repo object — that field is admin-only, so non-admin tokens get a 200
    # with the field stripped silently. Treat the missing-field case as `skip`
    # (we couldn't see it) rather than `warn` (it's off).
    if cfg.require_push_protection != "skip":
        body, status = gh.get_or_none(f"/repos/{owner}/{repo}")
        if status == 200 and isinstance(body, dict):
            sa = body.get("security_and_analysis")
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
        elif status == 403:
            out.append(Finding(
                "PS004", "skip",
                "push-protection probe forbidden — token needs `repo` (admin) (provide a PAT to check)",
            ))
        else:
            out.append(Finding(
                "PS004", "error",
                f"push-protection probe returned unexpected status {status}",
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
