"""Tests for `scan_kit.posture` — workflow-perms scan, CODEOWNERS scan,
and the API-driven branch/GHAS audits exercised via a fake client.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scan_kit import posture as posture_mod
from scan_kit.config import (
    BranchPosture,
    CodeownersPosture,
    Config,
    GHASPosture,
    PostureConfig,
    WorkflowsPosture,
)

# ===========================================================================
# Fake GitHub client — captures requests, returns canned responses
# ===========================================================================

class FakeGitHub(posture_mod.GitHub):
    """Subclass that bypasses urllib and returns scripted responses."""

    def __init__(self, responses: dict[str, tuple[Any, int]]):
        # Skip parent __init__ — we don't want a token check
        self.token = "fake"
        self.timeout = 1
        self.responses = responses
        self.calls: list[str] = []

    def get_or_none(self, path, *, accept="application/vnd.github+json"):
        self.calls.append(path)
        if path in self.responses:
            return self.responses[path]
        return None, 404

    def get(self, path, *, accept="application/vnd.github+json"):
        body, status = self.get_or_none(path, accept=accept)
        if status != 200:
            raise posture_mod.GitHubError(f"{status} for {path}")
        return body


# ---------------------------------------------------------------------------
# Workflow permissions scan (PS010, PS011) — local file walk
# ---------------------------------------------------------------------------

def _write_workflow(root: Path, name: str, body: str) -> Path:
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(body)
    return p


def test_ps010_pass_when_permissions_block_present(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "name: ci\npermissions:\n  contents: read\non: push\njobs: {}\n")
    cfg = WorkflowsPosture(require_permissions_block="fail", forbid_write_all="skip")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    rules = {f.rule_id: f.severity for f in findings}
    assert rules.get("PS010") == "pass"


def test_ps010_fails_when_missing(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml", "name: ci\non: push\njobs: {}\n")
    cfg = WorkflowsPosture(require_permissions_block="fail", forbid_write_all="skip")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS010"]
    assert target and target[0].severity == "fail"


def test_ps011_fail_on_write_all_top_level(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "name: ci\npermissions: write-all\non: push\njobs: {}\n")
    cfg = WorkflowsPosture(require_permissions_block="skip", forbid_write_all="fail")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS011"]
    assert target and target[0].severity == "fail"


def test_ps011_fail_on_write_all_job_level(tmp_path: Path):
    body = (
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: write-all\n"
        "    steps: []\n"
    )
    _write_workflow(tmp_path, "ci.yml", body)
    cfg = WorkflowsPosture(require_permissions_block="skip", forbid_write_all="fail")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS011"]
    assert target and target[0].severity == "fail"


def test_ps011_pass_when_explicit_perms(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "name: ci\npermissions:\n  contents: read\non: push\njobs: {}\n")
    cfg = WorkflowsPosture(require_permissions_block="skip", forbid_write_all="fail")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS011"]
    assert target and target[0].severity == "pass"


def test_skip_severity_emits_no_finding(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "name: ci\npermissions: write-all\non: push\njobs: {}\n")
    cfg = WorkflowsPosture(require_permissions_block="skip", forbid_write_all="skip")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    assert findings == []


def test_no_workflow_dir_is_silent(tmp_path: Path):
    cfg = WorkflowsPosture(require_permissions_block="fail", forbid_write_all="fail")
    findings = posture_mod._scan_workflow_perms(tmp_path, cfg)
    assert findings == []


# ---------------------------------------------------------------------------
# PS012 — pinned-actions audit
# ---------------------------------------------------------------------------

SHA40 = "a" * 40


def _write_action_yml(root: Path, name: str, body: str) -> Path:
    p = root / ".github" / "actions" / name / "action.yml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def test_ps012_pass_when_sha_pinned(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA40}\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and all(f.severity == "pass" for f in target)


def test_ps012_fail_when_tag_pinned(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and any(f.severity == "fail" for f in target)


def test_ps012_allow_tag_pin_exempts_owner_repo(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail",
                           allow_tag_pin=("actions/checkout",))
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and all(f.severity == "pass" for f in target)


def test_ps012_local_ref_exempt(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/foo\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and all(f.severity == "pass" for f in target)


def test_ps012_docker_ref_exempt(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3.20\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and all(f.severity == "pass" for f in target)


def test_ps012_walks_composite_action_manifest(tmp_path: Path):
    _write_action_yml(tmp_path, "myaction",
                      "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n      shell: bash\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and any(f.severity == "fail" for f in target)
    assert any("actions/myaction/action.yml" in (f.location or "")
               for f in target)


def test_ps012_skip_severity_emits_nothing(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    cfg = WorkflowsPosture(require_pinned_actions="skip")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    assert findings == []


def test_ps012_warn_default_severity(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    cfg = WorkflowsPosture()  # require_pinned_actions defaults to "warn"
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and any(f.severity == "warn" for f in target)


def test_ps012_no_at_suffix_is_offender(tmp_path: Path):
    _write_workflow(tmp_path, "ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout\n")
    cfg = WorkflowsPosture(require_pinned_actions="fail")
    findings = posture_mod._scan_pinned_actions(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS012"]
    assert target and any(f.severity == "fail" for f in target)


# ---------------------------------------------------------------------------
# PS013 — Microsoft Security DevOps detection
# ---------------------------------------------------------------------------

def test_ps013_default_skip_when_absent(tmp_path: Path):
    """No MSDO + default `skip` severity → single skip row (drops from SARIF)."""
    _write_workflow(tmp_path, "ci.yml",
                    f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA40}\n")
    cfg = WorkflowsPosture()  # detect_msdo defaults to "skip"
    findings = posture_mod._scan_msdo(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS013"]
    assert len(target) == 1
    assert target[0].severity == "skip"


def test_ps013_pass_with_details_when_sha_pinned(tmp_path: Path):
    """MSDO present + SHA-pinned → pass row with shortened SHA in details."""
    _write_workflow(
        tmp_path, "msdo.yml",
        "jobs:\n  scan:\n    steps:\n"
        f"      - uses: microsoft/security-devops-action@{SHA40}\n",
    )
    cfg = WorkflowsPosture()
    findings = posture_mod._scan_msdo(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS013"]
    assert target and all(f.severity == "pass" for f in target)
    assert any("SHA-pinned" in f.message for f in target)
    assert any("msdo.yml" in (f.location or "") for f in target)


def test_ps013_pass_with_details_when_tag_pinned(tmp_path: Path):
    """MSDO present + tag-pinned → pass row but flags pinning quality in details."""
    _write_workflow(
        tmp_path, "msdo.yml",
        "jobs:\n  scan:\n    steps:\n"
        "      - uses: microsoft/security-devops-action@v1\n",
    )
    cfg = WorkflowsPosture()
    findings = posture_mod._scan_msdo(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS013"]
    assert target and all(f.severity == "pass" for f in target)
    assert any("tag/branch-pinned" in f.message and "`v1`" in f.message
               for f in target)


def test_ps013_warn_when_absent_and_warn_severity(tmp_path: Path):
    """Operator opts in → absent MSDO surfaces at the requested severity."""
    _write_workflow(tmp_path, "ci.yml",
                    f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA40}\n")
    cfg = WorkflowsPosture(detect_msdo="warn")
    findings = posture_mod._scan_msdo(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS013"]
    assert target and target[0].severity == "warn"


def test_ps013_no_workflow_dir(tmp_path: Path):
    """No .github/workflows/ at all → single row at configured severity."""
    cfg = WorkflowsPosture(detect_msdo="warn")
    findings = posture_mod._scan_msdo(tmp_path, cfg)
    target = [f for f in findings if f.rule_id == "PS013"]
    assert target and target[0].severity == "warn"
    assert "no `.github/workflows/` directory" in target[0].message


# ---------------------------------------------------------------------------
# CODEOWNERS scan (PS030, PS031)
# ---------------------------------------------------------------------------

def test_ps030_pass_when_codeowners_present(tmp_path: Path):
    co = tmp_path / ".github" / "CODEOWNERS"
    co.parent.mkdir(parents=True)
    co.write_text("* @blackoutsecure/security-team\n")
    findings = posture_mod._scan_codeowners_local(tmp_path,
                                                  CodeownersPosture(require_file="warn"))
    target = [f for f in findings if f.rule_id == "PS030"]
    assert target and target[0].severity == "pass"


def test_ps030_fails_when_missing(tmp_path: Path):
    findings = posture_mod._scan_codeowners_local(tmp_path,
                                                  CodeownersPosture(require_file="fail"))
    target = [f for f in findings if f.rule_id == "PS030"]
    assert target and target[0].severity == "fail"


def test_ps031_warns_on_line_without_owner(tmp_path: Path):
    co = tmp_path / "CODEOWNERS"
    co.write_text("* @blackoutsecure/security-team\n*.py\n")    # second line has no owner
    findings = posture_mod._scan_codeowners_local(tmp_path,
                                                  CodeownersPosture(require_file="warn"))
    target = [f for f in findings if f.rule_id == "PS031"]
    assert target


def test_ps031_ignores_blank_and_comment_lines(tmp_path: Path):
    co = tmp_path / "CODEOWNERS"
    co.write_text("# header\n\n* @org/team   # ok\n")
    findings = posture_mod._scan_codeowners_local(tmp_path,
                                                  CodeownersPosture(require_file="warn"))
    rule_ids = {f.rule_id for f in findings}
    assert "PS031" not in rule_ids


# ---------------------------------------------------------------------------
# GHAS toggle audit (PS001-003) via FakeGitHub
# ---------------------------------------------------------------------------

def test_ps001_pass_when_default_setup_configured():
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": ({"state": "configured"}, 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
        "/repos/o/r": (
            {"security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}},
            200,
        ),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    assert sev["PS001"] == "pass"
    assert sev["PS002"] == "pass"
    assert sev["PS003"] == "pass"
    assert sev["PS004"] == "pass"


def test_ps001_pass_when_advanced_setup_active():
    # Default-setup says not-configured (Advanced + Default are mutually
    # exclusive in the UI) BUT the analyses endpoint reports an existing
    # CodeQL upload — the repo is running CodeQL via Advanced. Without
    # the fallback probe this case used to false-negative warn.
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": ({"state": "not-configured"}, 200),
        "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": (
            [{"id": 1, "tool": {"name": "CodeQL"}}],
            200,
        ),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
        "/repos/o/r": (
            {"security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}},
            200,
        ),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    msg = {f.rule_id: f.message for f in out}
    assert sev["PS001"] == "pass"
    assert "Advanced" in msg["PS001"]


def test_ps001_warns_when_neither_default_nor_advanced():
    # Default-setup off AND no Advanced analyses uploaded — the rule
    # should warn with the actionable remediation hint pointing at both
    # UX paths.
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": ({"state": "not-configured"}, 200),
        "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": ([], 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": (None, 404),
        "/repos/o/r/vulnerability-alerts": (None, 404),
        "/repos/o/r": (
            {"security_and_analysis": {"secret_scanning_push_protection": {"status": "disabled"}}},
            200,
        ),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    msg = {f.rule_id: f.message for f in out}
    assert sev["PS001"] == "warn"
    assert sev["PS002"] == "warn"
    assert sev["PS003"] == "warn"
    assert sev["PS004"] == "warn"
    # Remediation hints embedded in warn messages so the operator gets
    # the Settings path without context-switching to docs.
    assert "Settings" in msg["PS001"]
    assert "Settings" in msg["PS002"]
    assert "Settings" in msg["PS003"]
    assert "Settings" in msg["PS004"]


def test_ps001_pass_when_default_setup_forbidden_but_advanced_active():
    # Baseline-token reality: default-setup returns 403, BUT the
    # analyses endpoint (only needs `security_events: read`, which
    # `GITHUB_TOKEN` grants) reports an existing CodeQL upload. The
    # repo is running Advanced setup; the rule should pass instead of
    # falsely skipping. This is the case that motivated lifting the
    # analyses fallback out of the non-403 branch.
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": (None, 403),
        "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": (
            [{"id": 1, "tool": {"name": "CodeQL"}}],
            200,
        ),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
        "/repos/o/r": (
            {"security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}},
            200,
        ),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    target = [f for f in out if f.rule_id == "PS001"]
    assert target and target[0].severity == "pass"
    assert "Advanced" in target[0].message


def test_finding_has_structured_metadata():
    finding = posture_mod.Finding(
        "PS010",
        "warn",
        "Workflow permissions were not declared.",
        location=".github/workflows/ci.yml",
        evidence={"workflow": "ci.yml"},
    )
    payload = finding.to_dict()
    assert payload["rule_id"] == "PS010"
    assert payload["severity"] == "warn"
    assert payload["title"] == "Workflow permissions are declared"
    assert payload["source"] == "posture"
    assert payload["location"] == ".github/workflows/ci.yml"
    assert payload["evidence"] == {"workflow": "ci.yml"}
    assert payload["remediation"]
    assert payload["remediation_confidence"] == "deterministic"
    assert payload["remediation_source"] == "Blackout Secure Recommended Remediation"


def test_summary_markdown_includes_summary_and_remediation_columns():
    result = posture_mod.AuditResult(
        findings=(
            posture_mod.Finding(
                "PS010",
                "warn",
                "Workflow permissions were not declared.",
                location=".github/workflows/ci.yml",
                remediation="Set a top-level permissions block for the workflow.",
            ),
        )
    )
    summary = result.summary_markdown()
    assert "# Blackout Secure Code Scanning Kit Audit Report" in summary
    assert "**Provided by [Blackout Secure](https://blackoutsecure.app)**" in summary
    assert "## Summary" in summary
    assert "**Verdict:** Advisory review recommended" in summary
    assert "**Totals:**" in summary
    assert "## Recommended Actions" in summary
    assert "#### Findings Requiring Attention" in summary
    assert "| Rule | Severity | Location | Control | Evidence | Recommended Remediation |" in summary
    assert "| `PS010` | Warning | .github/workflows/ci.yml | Workflow permissions are declared |" in summary
    assert "Set a top-level permissions block" in summary


def test_summary_markdown_omits_remediation_for_passed_findings():
    result = posture_mod.AuditResult(
        findings=(
            posture_mod.Finding(
                "PS011",
                "pass",
                "Workflow write access is restricted.",
                location=".github/workflows/ci.yml",
                remediation="Tighten workflow permissions.",
            ),
        )
    )
    summary = result.summary_markdown()
    assert "#### Passed Controls" in summary
    assert "| Rule | Severity | Location | Control | Evidence |" in summary
    assert "| `PS011` | Pass | .github/workflows/ci.yml | Workflow write access is restricted |" in summary
    assert "Tighten workflow permissions." not in summary


def test_summary_markdown_handles_no_findings():
    result = posture_mod.AuditResult(findings=())
    summary = result.summary_markdown()
    assert "# Blackout Secure Code Scanning Kit Audit Report" in summary
    assert "## Summary" in summary
    assert "**Verdict:** Controls passed" in summary
    assert "_No findings were emitted by the configured audit controls._" in summary


def test_ps001_skip_when_default_setup_forbidden_and_no_advanced_analyses():
    # Default-setup forbidden AND analyses comes back empty (or also
    # forbidden, or any non-200). We cannot distinguish "Default setup
    # we can't see" from "Advanced not-yet-scanned" from "genuinely
    # off", so `skip` is the only honest verdict. Message should hint
    # at the PAT upgrade path so the operator knows how to promote
    # this to a real check.
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": (None, 403),
        "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": ([], 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
        "/repos/o/r": (
            {"security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}},
            200,
        ),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    target = [f for f in out if f.rule_id == "PS001"]
    assert target and target[0].severity == "skip"
    assert "PAT" in target[0].message


def test_ps004_skip_when_non_admin_token_hides_security_and_analysis():
    # Non-admin tokens get `security_and_analysis` silently stripped from
    # the repo object. The rule must `skip` ("we did not check") rather
    # than `warn` ("it's off") so the operator isn't told to flip a
    # toggle that may already be enabled.
    fake = FakeGitHub({
        "/repos/o/r/code-scanning/default-setup": ({"state": "configured"}, 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
        "/repos/o/r": ({"name": "r"}, 200),  # `security_and_analysis` missing
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    target = [f for f in out if f.rule_id == "PS004"]
    assert target and target[0].severity == "skip"
    assert "admin" in target[0].message


def test_ps004_skip_on_403():
    fake = FakeGitHub({
        "/repos/o/r": (None, 403),
    })
    cfg = GHASPosture(
        require_code_scanning="skip",
        require_secret_scanning="skip",
        require_dependabot_alerts="skip",
        require_push_protection="warn",
    )
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    assert any(
        f.rule_id == "PS004" and f.severity == "skip" and "forbidden" in f.message
        for f in out
    )


def test_ps002_skip_on_403():
    # The default GITHUB_TOKEN lacks `admin:org` / repo admin scope to
    # reach this endpoint; surface as `skip` ("we did not check") rather
    # than `error` ("something broke"). Keeps the step summary honest
    # and the SARIF upload clean (skip/pass are dropped from SARIF).
    fake = FakeGitHub({
        "/repos/o/r/secret-scanning/alerts?per_page=1": (None, 403),
    })
    cfg = GHASPosture(
        require_code_scanning="skip",
        require_secret_scanning="warn",
        require_dependabot_alerts="skip",
    )
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    assert any(
        f.rule_id == "PS002" and f.severity == "skip" and "forbidden" in f.message
        for f in out
    )


def test_skip_severities_skip_api_calls():
    fake = FakeGitHub({})
    cfg = GHASPosture(
        require_code_scanning="skip",
        require_secret_scanning="skip",
        require_dependabot_alerts="skip",
        require_push_protection="skip",
    )
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    assert out == []
    assert fake.calls == []


# ---------------------------------------------------------------------------
# GHAS entitlement gate (PS001/PS002/PS004 skip when SKU not enabled)
# ---------------------------------------------------------------------------

def test_ghas_not_entitled_skips_ps001_ps002_ps004_but_runs_ps003():
    # Private repo whose `security_and_analysis.advanced_security.status`
    # is explicitly "disabled" → the operator literally cannot enable
    # code scanning / secret scanning / push protection without buying
    # the GHAS SKU. Warning them is noise; skip the three GHAS probes
    # but still run PS003 (Dependabot alerts are free on every plan).
    fake = FakeGitHub({
        "/repos/o/r": (
            {
                "visibility": "private",
                "private": True,
                "security_and_analysis": {
                    "advanced_security": {"status": "disabled"},
                },
            },
            200,
        ),
        # Dependabot is GHAS-independent; the probe still runs.
        "/repos/o/r/vulnerability-alerts": (None, 204),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    msg = {f.rule_id: f.message for f in out}
    assert sev["PS001"] == "skip"
    assert sev["PS002"] == "skip"
    assert sev["PS003"] == "pass"
    assert sev["PS004"] == "skip"
    # Message must name the SKU so the operator knows it's a paid-tier
    # issue, not a toggle they forgot to flip.
    assert "Advanced Security" in msg["PS001"]
    assert "Advanced Security" in msg["PS002"]
    assert "Advanced Security" in msg["PS004"]


def test_ghas_entitlement_gate_skips_ghas_endpoints_when_not_entitled():
    # The skip path must NOT touch the GHAS-only endpoints (default-setup,
    # secret-scanning/alerts) — those would return 403/404 and waste a
    # round trip. Verify only the repo metadata + Dependabot endpoints
    # are hit when entitlement comes back "not_entitled".
    fake = FakeGitHub({
        "/repos/o/r": (
            {
                "private": True,
                "security_and_analysis": {
                    "advanced_security": {"status": "disabled"},
                },
            },
            200,
        ),
        "/repos/o/r/vulnerability-alerts": (None, 204),
    })
    cfg = GHASPosture()
    posture_mod._audit_ghas(fake, "o", "r", cfg)
    called = set(fake.calls)
    assert "/repos/o/r" in called
    assert "/repos/o/r/vulnerability-alerts" in called
    # These GHAS-paywalled endpoints must be skipped.
    assert "/repos/o/r/code-scanning/default-setup" not in called
    assert "/repos/o/r/secret-scanning/alerts?per_page=1" not in called


def test_public_repo_is_entitled_even_without_advanced_security_field():
    # Public repos get GHAS code/secret scanning for free; the
    # `security_and_analysis.advanced_security` field is typically
    # absent on public-repo bodies. Must NOT misclassify as
    # "not_entitled" — the probes should run normally.
    fake = FakeGitHub({
        "/repos/o/r": (
            {"visibility": "public", "private": False},
            200,
        ),
        "/repos/o/r/code-scanning/default-setup": ({"state": "configured"}, 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    # PS001/PS002/PS003 pass; PS004 skips because push-protection field
    # is absent in this response (non-admin token shape) — that's the
    # existing skip path, not the entitlement skip.
    assert sev["PS001"] == "pass"
    assert sev["PS002"] == "pass"
    assert sev["PS003"] == "pass"
    assert sev["PS004"] == "skip"


def test_private_repo_with_advanced_security_enabled_runs_probes():
    # Private repo with GHAS explicitly enabled → entitlement is
    # "entitled" and existing probes run normally.
    fake = FakeGitHub({
        "/repos/o/r": (
            {
                "private": True,
                "security_and_analysis": {
                    "advanced_security": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            },
            200,
        ),
        "/repos/o/r/code-scanning/default-setup": ({"state": "configured"}, 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": ([], 200),
        "/repos/o/r/vulnerability-alerts": (None, 204),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    assert sev["PS001"] == "pass"
    assert sev["PS002"] == "pass"
    assert sev["PS003"] == "pass"
    assert sev["PS004"] == "pass"


def test_unknown_entitlement_falls_through_to_existing_probe_logic():
    # When the repo metadata fetch is forbidden (403), entitlement is
    # "unknown" — the per-probe 403/404 handling (existing behavior)
    # must still produce the right skip rows. This is the baseline-
    # token scenario where the operator hasn't supplied a PAT.
    fake = FakeGitHub({
        "/repos/o/r": (None, 403),
        "/repos/o/r/code-scanning/default-setup": (None, 403),
        "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": ([], 200),
        "/repos/o/r/secret-scanning/alerts?per_page=1": (None, 403),
        "/repos/o/r/vulnerability-alerts": (None, 204),
    })
    cfg = GHASPosture()
    out = posture_mod._audit_ghas(fake, "o", "r", cfg)
    sev = {f.rule_id: f.severity for f in out}
    msg = {f.rule_id: f.message for f in out}
    # All three GHAS probes hit their existing "skip on 403/forbidden"
    # branches — NOT the entitlement-skip branch.
    assert sev["PS001"] == "skip"
    assert "forbidden" in msg["PS001"]
    assert sev["PS002"] == "skip"
    assert "forbidden" in msg["PS002"]
    assert sev["PS003"] == "pass"  # Dependabot endpoint returned 204.
    assert sev["PS004"] == "skip"
    assert "forbidden" in msg["PS004"]
    # And neither PS001 nor PS002 nor PS004 should mention the GHAS SKU
    # (that's reserved for the explicit "not_entitled" path).
    assert "Advanced Security" not in msg["PS001"]
    assert "Advanced Security" not in msg["PS002"]
    assert "Advanced Security" not in msg["PS004"]


# ---------------------------------------------------------------------------
# Branch protection audit (PS020-025)
# ---------------------------------------------------------------------------

def _full_protection(reviews: int = 1) -> dict[str, Any]:
    return {
        "required_pull_request_reviews": {"required_approving_review_count": reviews},
        "allow_force_pushes": {"enabled": False},
        "required_status_checks": {"contexts": ["ci"]},
        "required_signatures": {"enabled": False},
        "required_conversation_resolution": {"enabled": False},
    }


def test_ps020_warns_when_branch_unprotected():
    fake = FakeGitHub({})   # 404 for everything
    out = posture_mod._audit_one_branch(fake, "o", "r", "main", BranchPosture())
    assert any(f.rule_id == "PS020" and f.severity == "warn" for f in out)


def test_ps021_pass_when_reviews_meet_threshold():
    fake = FakeGitHub({
        "/repos/o/r/branches/main/protection": (_full_protection(reviews=2), 200),
    })
    want = BranchPosture(required_reviews=2)
    out = posture_mod._audit_one_branch(fake, "o", "r", "main", want)
    sev = {f.rule_id: f.severity for f in out}
    assert sev["PS021"] == "pass"
    assert sev["PS022"] == "pass"
    assert sev["PS023"] == "pass"


def test_ps021_fails_when_reviews_short():
    fake = FakeGitHub({
        "/repos/o/r/branches/main/protection": (_full_protection(reviews=0), 200),
    })
    want = BranchPosture(required_reviews=2, severity="fail")
    out = posture_mod._audit_one_branch(fake, "o", "r", "main", want)
    target = [f for f in out if f.rule_id == "PS021"]
    assert target and target[0].severity == "fail"


def test_ps024_fires_when_signed_commits_required_but_off():
    fake = FakeGitHub({
        "/repos/o/r/branches/main/protection": (_full_protection(), 200),
    })
    want = BranchPosture(require_signed_commits=True, severity="warn")
    out = posture_mod._audit_one_branch(fake, "o", "r", "main", want)
    sev = {f.rule_id: f.severity for f in out}
    assert sev.get("PS024") == "warn"


def test_branch_audit_iterates_all_branches():
    fake = FakeGitHub({
        "/repos/o/r/branches/main/protection": (_full_protection(reviews=1), 200),
        "/repos/o/r/branches/dev/protection": (None, 404),
    })
    cfg_branches = {
        "main": BranchPosture(required_reviews=1, severity="fail"),
        "dev":  BranchPosture(required_reviews=0, severity="warn"),
    }
    out = posture_mod._audit_branches(fake, "o", "r", cfg_branches)
    locs = {f.location for f in out}
    assert "branch:main" in locs
    assert "branch:dev" in locs


# ---------------------------------------------------------------------------
# Top-level audit() ties everything together
# ---------------------------------------------------------------------------

def test_top_level_audit_with_no_token_errors_cleanly(tmp_path: Path):
    cfg = Config(posture=PostureConfig())
    result = posture_mod.audit(
        cfg=cfg, owner="o", repo="r", token="", repo_root=tmp_path,
    )
    # Local workflow + codeowners checks still run; PS000 is the
    # token-missing finding.
    rule_ids = {f.rule_id for f in result.findings}
    assert "PS000" in rule_ids


def test_audit_result_failed_warned_passed_buckets():
    findings = (
        posture_mod.Finding("PS001", "pass", "ok"),
        posture_mod.Finding("PS002", "fail", "bad"),
        posture_mod.Finding("PS003", "warn", "meh"),
        posture_mod.Finding("PS010", "error", "tool"),
    )
    r = posture_mod.AuditResult(findings=findings)
    assert len(r.passed) == 1
    assert len(r.failed) == 1
    assert len(r.warned) == 1
    assert len(r.errored) == 1


# ---------------------------------------------------------------------------
# GitHub client init
# ---------------------------------------------------------------------------

def test_github_init_rejects_empty_token():
    with pytest.raises(posture_mod.GitHubError):
        posture_mod.GitHub("")
