"""Tests for the LD### dependency-licence rules."""

from __future__ import annotations

import pytest

import licensing
import posture
from config import DependenciesPosture


def sbom(*packages: dict) -> dict:
    """Wrap package entries in a dependency-graph SBOM response."""
    repo_self = {"name": "com.github.blackoutsecure/example", "versionInfo": "0"}
    return {"sbom": {"SPDXID": "SPDXRef-DOCUMENT",
                     "packages": [repo_self, *packages]}}


def pkg(name: str, license_: str = "NOASSERTION", version: str = "1.0.0") -> dict:
    return {"name": name, "versionInfo": version, "licenseConcluded": license_}


class FakeGitHub:
    """Minimal stand-in for the posture REST client."""

    def __init__(self, body, status=200):
        self._body, self._status = body, status
        self.calls: list[str] = []

    def get_or_none(self, path, **_kwargs):
        self.calls.append(path)
        return self._body, self._status


def run(body, status=200, **cfg_kwargs) -> dict[str, posture.Finding]:
    gh = FakeGitHub(body, status)
    cfg = DependenciesPosture(**cfg_kwargs)
    findings = posture._audit_dependency_licenses(gh, "blackoutsecure", "example", cfg)
    return {f.rule_id: f for f in findings}


# ---------------------------------------------------------------------------
# Catalogue + expression handling
# ---------------------------------------------------------------------------

def test_catalogue_matches_the_marketplace_kit_snapshot():
    cat = licensing.catalogue()
    assert cat.url == "https://opensource.org/licenses"
    assert cat.is_osi_approved("Apache-2.0")
    assert not cat.is_osi_approved("BUSL-1.1")
    assert "SSPL-1.0" in cat.not_open_source


@pytest.mark.parametrize("raw,expected", [
    ("MIT", "MIT"),
    ("Apache-2.0", "Apache-2.0"),
    ("GPL-3.0-or-later", "GPL-3.0-or-later"),
    ("(MIT)", "MIT"),
    ("NOASSERTION", "unknown"),
    ("", "unknown"),
])
def test_normalise(raw, expected):
    assert licensing.catalogue().normalise(raw) == expected


def test_distinct_spdx_identifiers_do_not_collide():
    cat = licensing.catalogue()
    assert cat.normalise("GPL-3.0") == "GPL-3.0"
    assert cat.normalise("GPL-3.0+") == "GPL-3.0+"


@pytest.mark.parametrize("expression,expected", [
    ("MIT", ["MIT"]),
    ("MIT OR Apache-2.0", ["MIT", "Apache-2.0"]),
    ("(MIT AND BSD-3-Clause)", ["MIT", "BSD-3-Clause"]),
    ("GPL-2.0-or-later WITH Classpath-exception-2.0", ["GPL-2.0-or-later"]),
    ("Apache-2.0 OR (MIT AND ISC)", ["Apache-2.0", "MIT", "ISC"]),
])
def test_expression_operands(expression, expected):
    assert licensing._operands(expression) == expected


def test_parse_sbom_drops_the_repository_itself():
    packages = licensing.parse_sbom(sbom(pkg("requests", "Apache-2.0")))
    assert [p.name for p in packages] == ["requests"]
    assert packages[0].identifiers == ("Apache-2.0",)
    assert packages[0].label == "requests@1.0.0"


def test_parse_sbom_tolerates_a_bare_document():
    assert licensing.parse_sbom({"packages": [pkg("x", "MIT")]})[0].name == "x"
    assert licensing.parse_sbom({}) == ()
    assert licensing.parse_sbom([]) == ()


def test_dual_licensed_package_only_needs_one_acceptable_operand():
    package = licensing.parse_sbom(sbom(pkg("dual", "MIT OR GPL-3.0")))[0]
    assert package.identifiers == ("MIT", "GPL-3.0")
    assert licensing.satisfies(package, {"MIT"})
    assert licensing.satisfies(package, {"GPL-3.0"})
    assert not licensing.satisfies(package, {"Apache-2.0"})


# ---------------------------------------------------------------------------
# LD001 — SBOM availability
# ---------------------------------------------------------------------------

def test_disabled_dependency_graph_skips_cleanly():
    result = run(None, status=404)
    assert result["LD001"].severity == "skip"
    assert "dependency graph is disabled" in result["LD001"].message
    assert all(result[r].severity == "skip" for r in licensing.RULES[1:])


def test_forbidden_token_skips_with_a_scope_hint():
    result = run(None, status=403)
    assert "read access" in result["LD001"].message


def test_unparseable_sbom_is_an_error_not_a_crash():
    result = run({"sbom": {"packages": "not-a-list"}})
    # A malformed `packages` yields zero dependencies rather than an exception.
    assert result["LD001"].severity == "pass"
    assert all(result[r].severity == "skip" for r in licensing.RULES[1:])


def test_all_rules_skipped_makes_no_api_call():
    gh = FakeGitHub(None, 200)
    cfg = DependenciesPosture(require_declared_license="skip",
                              forbid_non_osi_license="skip",
                              forbid_denied_license="skip",
                              check_compatibility="skip")
    findings = posture._audit_dependency_licenses(gh, "o", "r", cfg)
    assert gh.calls == []
    assert {f.severity for f in findings} == {"skip"}


def test_ld001_reports_the_dependency_count():
    result = run(sbom(pkg("a", "MIT"), pkg("b", "Apache-2.0")))
    assert result["LD001"].severity == "pass"
    assert result["LD001"].evidence["packages"] == 2


# ---------------------------------------------------------------------------
# Catalogue freshness
# ---------------------------------------------------------------------------

def test_vendored_snapshot_is_within_the_default_max_age():
    limit = DependenciesPosture().catalogue_max_age_days
    age = licensing.catalogue_age_days()
    assert age >= 0, "osi-licenses.json has an unparseable `snapshot` date"
    assert age <= limit, (
        f"osi-licenses.json is {age} days old (limit {limit}) — the hub's "
        "`Refresh OSI licence catalogue` workflow has not landed in a while"
    )


def test_stale_catalogue_downgrades_ld001(monkeypatch):
    monkeypatch.setattr(licensing, "catalogue_age_days", lambda *_a, **_k: 900)
    result = run(sbom(pkg("a", "MIT")))
    assert result["LD001"].severity == "warn"
    assert "900 days old" in result["LD001"].message
    assert result["LD001"].evidence["osi_snapshot_age_days"] == 900
    # A stale catalogue must not stop the other rules from reporting.
    assert result["LD002"].severity == "pass"


def test_staleness_check_can_be_disabled(monkeypatch):
    monkeypatch.setattr(licensing, "catalogue_age_days", lambda *_a, **_k: 900)
    result = run(sbom(pkg("a", "MIT")), catalogue_max_age_days=0)
    assert result["LD001"].severity == "pass"


# ---------------------------------------------------------------------------
# LD002 — undeclared licences
# ---------------------------------------------------------------------------

def test_undeclared_license_is_reported():
    result = run(sbom(pkg("mystery"), pkg("fine", "MIT")))
    assert result["LD002"].severity == "warn"
    assert "mystery@1.0.0" in result["LD002"].message
    assert result["LD002"].evidence["count"] == 1


def test_all_declared_passes():
    result = run(sbom(pkg("a", "MIT"), pkg("b", "Apache-2.0")))
    assert result["LD002"].severity == "pass"


def test_severity_is_configurable():
    result = run(sbom(pkg("mystery")), require_declared_license="fail")
    assert result["LD002"].severity == "fail"


def test_undeclared_packages_are_not_also_flagged_as_non_osi():
    result = run(sbom(pkg("mystery")))
    assert result["LD002"].severity == "warn"
    assert result["LD003"].severity == "pass"


# ---------------------------------------------------------------------------
# LD003 — non-OSI licences
# ---------------------------------------------------------------------------

def test_source_available_license_is_flagged():
    result = run(sbom(pkg("vault", "BUSL-1.1"), pkg("ok", "MIT")))
    assert result["LD003"].severity == "warn"
    assert "vault@1.0.0" in result["LD003"].message
    assert "opensource.org/licenses" in result["LD003"].message


def test_non_osi_license_can_be_excepted_via_allow():
    result = run(sbom(pkg("vault", "BUSL-1.1")), allow=("BUSL-1.1", "MIT"))
    assert result["LD003"].severity == "pass"


def test_osi_approved_dependencies_pass():
    result = run(sbom(pkg("a", "MIT"), pkg("b", "GPL-3.0-or-later"), pkg("c", "ISC")))
    assert result["LD003"].severity == "pass"


# ---------------------------------------------------------------------------
# LD004 — repository policy
# ---------------------------------------------------------------------------

def test_no_policy_configured_skips():
    assert run(sbom(pkg("a", "MIT")))["LD004"].severity == "skip"


def test_denied_license_is_flagged():
    result = run(sbom(pkg("copyleft", "AGPL-3.0"), pkg("ok", "MIT")),
                 deny=("AGPL-3.0",))
    assert result["LD004"].severity == "warn"
    assert "copyleft@1.0.0" in result["LD004"].message
    assert "ok@1.0.0" not in result["LD004"].message


def test_dual_licensed_package_escapes_a_denylist():
    result = run(sbom(pkg("dual", "AGPL-3.0 OR Apache-2.0")), deny=("AGPL-3.0",))
    assert result["LD004"].severity == "pass"


def test_allowlist_rejects_everything_else():
    result = run(sbom(pkg("a", "MIT"), pkg("b", "GPL-3.0")),
                 allow=("MIT", "Apache-2.0"))
    assert result["LD004"].severity == "warn"
    assert "b@1.0.0" in result["LD004"].message


def test_allowlist_passes_when_satisfied():
    result = run(sbom(pkg("a", "MIT")), allow=("MIT", "Apache-2.0"))
    assert result["LD004"].severity == "pass"


def test_long_offender_lists_are_capped():
    packages = [pkg(f"dep{i}") for i in range(25)]
    result = run(sbom(*packages))
    assert "and 15 more" in result["LD002"].message
    assert len(result["LD002"].evidence["packages"]) == 25


# ---------------------------------------------------------------------------
# Integration with the posture report
# ---------------------------------------------------------------------------

def test_findings_carry_titles_and_remediation():
    result = run(sbom(pkg("mystery")))
    assert result["LD002"].title == "Dependencies declare a licence"
    assert "no licence metadata" in result["LD002"].remediation
    assert result["LD001"].title == "Dependency licence data is available"


def test_ld_rules_land_in_their_own_report_family():
    for rule in licensing.RULES:
        assert posture._family_for(rule) == 4
    assert posture._RULE_FAMILIES[4][1] == "Dependency licences"
