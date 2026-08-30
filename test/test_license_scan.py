"""Tests for LF### working-tree licence scanning and LD005 compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest

import licensing
import osi_catalogue
import posture
from config import DependenciesPosture, SourceLicensePosture

APACHE = "SPDX-License-Identifier: Apache-2.0\nCopyright 2026 Blackout Secure\n"


def write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def run(root: Path, **kwargs) -> dict[str, posture.Finding]:
    cfg = SourceLicensePosture(**kwargs)
    return {f.rule_id: f for f in posture._scan_source_licenses(root, cfg)}


# ---------------------------------------------------------------------------
# Copyright parsing and merging
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,holder,years", [
    ("Copyright 2026 Blackout Secure", "Blackout Secure", (2026,)),
    ("Copyright (c) 2020 Alice", "Alice", (2020,)),
    ("Copyright © 2019-2021 Acme Corp", "Acme Corp", (2019, 2020, 2021)),
    ("Copyright (C) 2020, 2024 Alice", "Alice", (2020, 2024)),
    ("Copyright 2020 Alice <a@example.com>", "Alice", (2020,)),
    ("Copyright 2020 Alice. All rights reserved.", "Alice", (2020,)),
])
def test_parse_single_copyright(text, holder, years):
    parsed = osi_catalogue.parse_copyrights(text)
    assert len(parsed) == 1
    assert parsed[0].holder == holder
    assert parsed[0].years == years


def test_multiple_holders_on_one_line():
    parsed = osi_catalogue.parse_copyrights("Copyright 2020 Alice and Bob")
    assert [p.holder for p in parsed] == ["Alice", "Bob"]
    assert all(p.years == (2020,) for p in parsed)


def test_multiple_notices_across_lines():
    parsed = osi_catalogue.parse_copyrights(
        "Copyright 2019 Alice\nCopyright 2021 Bob\n")
    assert [(p.holder, p.years) for p in parsed] == [("Alice", (2019,)), ("Bob", (2021,))]


def test_present_expands_to_the_current_year():
    import datetime as dt
    parsed = osi_catalogue.parse_copyrights(
        "Copyright 2024-present Alice", today=dt.date(2026, 1, 1))
    assert parsed[0].years == (2024, 2025, 2026)


def test_merge_unions_years_per_holder():
    parsed = osi_catalogue.parse_copyrights(
        "Copyright 2019 Alice\nCopyright 2021-2022 alice\nCopyright 2020 Bob\n")
    merged = osi_catalogue.merge_copyrights(parsed)
    by_holder = {m.holder.casefold(): m.years for m in merged}
    assert by_holder["alice"] == (2019, 2021, 2022)
    assert by_holder["bob"] == (2020,)


@pytest.mark.parametrize("years,rendered", [
    ((2019, 2020, 2021), "2019-2021"),
    ((2019, 2021), "2019, 2021"),
    ((2019, 2020, 2021, 2024), "2019-2021, 2024"),
    ((2026,), "2026"),
    ((), ""),
])
def test_year_ranges_render_compactly(years, rendered):
    assert osi_catalogue.format_years(years) == rendered


def test_render_round_trips_a_merged_notice():
    merged = osi_catalogue.merge_copyrights(
        osi_catalogue.parse_copyrights("Copyright 2019 Acme\nCopyright 2020 Acme\n"))
    assert merged[0].render() == "Copyright © 2019-2020 Acme"


# ---------------------------------------------------------------------------
# Compatibility engine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dependency,project,status", [
    ("MIT", "Apache-2.0", "ok"),
    ("Apache-2.0", "Apache-2.0", "ok"),
    ("BSD-3-Clause", "GPL-3.0", "ok"),
    ("GPL-3.0", "Apache-2.0", "review"),
    ("AGPL-3.0", "MIT", "review"),
    ("MPL-2.0", "MIT", "review"),
    ("MIT", "AGPL-3.0", "ok"),
    ("Apache-2.0", "GPL-2.0", "incompatible"),
    ("BUSL-1.1", "Apache-2.0", "incompatible"),
    ("MIT", "unknown", "unknown"),
])
def test_compatibility_verdicts(dependency, project, status):
    assert licensing.compatibility(dependency, project).status == status


def test_verdicts_explain_themselves():
    verdict = licensing.compatibility("GPL-3.0", "Apache-2.0")
    assert "strong-copyleft" in verdict.reason
    assert licensing.compatibility("Apache-2.0", "GPL-2.0").reason


# ---------------------------------------------------------------------------
# LF001 — header coverage
# ---------------------------------------------------------------------------

def test_header_coverage_is_reported_but_off_by_default(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "a.py", APACHE)
    write(tmp_path, "b.py", "print('no header')\n")
    result = run(tmp_path)
    assert result["LF001"].severity == "skip"
    assert result["LF001"].evidence["scanned"] == 2
    assert result["LF001"].evidence["coverage_percent"] == 50


def test_header_coverage_can_be_enforced(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "a.py", APACHE)
    write(tmp_path, "b.py", "print('no header')\n")
    result = run(tmp_path, require_spdx_headers="warn", min_header_coverage=80)
    assert result["LF001"].severity == "warn"
    assert "50%" in result["LF001"].message

    result = run(tmp_path, require_spdx_headers="warn", min_header_coverage=50)
    assert result["LF001"].severity == "pass"


def test_build_output_is_not_scanned(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "a.py", APACHE)
    write(tmp_path, "node_modules/pkg/index.js", "// SPDX-License-Identifier: GPL-3.0\n")
    write(tmp_path, ".venv/lib/thing.py", "# SPDX-License-Identifier: GPL-3.0\n")
    result = run(tmp_path)
    assert result["LF001"].evidence["scanned"] == 1
    assert result["LF002"].severity == "pass"


# ---------------------------------------------------------------------------
# LF002 — foreign licences in-tree
# ---------------------------------------------------------------------------

def test_vendored_foreign_license_is_flagged(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "src/app.py", APACHE)
    write(tmp_path, "vendor/thing.py", "# SPDX-License-Identifier: GPL-3.0\n")
    result = run(tmp_path)
    assert result["LF002"].severity == "warn"
    assert "vendor/thing.py" in result["LF002"].message
    assert result["LF002"].evidence["count"] == 1


def test_foreign_license_can_be_allowlisted(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "vendor/thing.py", "# SPDX-License-Identifier: GPL-3.0\n")
    result = run(tmp_path, allow=("GPL-3.0",))
    assert result["LF002"].severity == "pass"


def test_no_project_license_skips_cleanly(tmp_path):
    write(tmp_path, "src/app.py", APACHE)
    result = run(tmp_path)
    assert result["LF002"].severity == "skip"
    assert result["LF004"].severity == "skip"


def test_project_license_can_be_pinned(tmp_path):
    write(tmp_path, "src/app.py", "# SPDX-License-Identifier: MIT\n")
    result = run(tmp_path, project_license="MIT")
    assert result["LF002"].severity == "pass"


# ---------------------------------------------------------------------------
# LF003 — copyright consistency
# ---------------------------------------------------------------------------

def test_unknown_copyright_holder_is_flagged(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "NOTICE", "Copyright 2026 Blackout Secure\n")
    write(tmp_path, "vendor/thing.py",
          "# SPDX-License-Identifier: Apache-2.0\n# Copyright 2015 Someone Else\n")
    result = run(tmp_path)
    assert result["LF003"].severity == "warn"
    assert "Someone Else" in result["LF003"].message
    assert "Someone Else" in result["LF003"].evidence["holders"]


def test_matching_holders_pass(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "NOTICE", "Copyright 2026 Blackout Secure\n")
    write(tmp_path, "src/app.py", APACHE)
    assert run(tmp_path)["LF003"].severity == "pass"


def test_holder_matching_ignores_case(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "NOTICE", "Copyright 2026 BLACKOUT SECURE\n")
    write(tmp_path, "src/app.py", "# Copyright 2026 Blackout Secure\n")
    assert run(tmp_path)["LF003"].severity == "pass"


def test_no_declared_holder_skips(tmp_path):
    write(tmp_path, "LICENSE", "SPDX-License-Identifier: Apache-2.0\n")
    write(tmp_path, "src/app.py", "# Copyright 2020 Someone\n")
    assert run(tmp_path)["LF003"].severity == "skip"


# ---------------------------------------------------------------------------
# LF004 — in-tree compatibility
# ---------------------------------------------------------------------------

def test_incompatible_intree_license_is_flagged(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "vendor/thing.py", "# SPDX-License-Identifier: GPL-3.0\n")
    result = run(tmp_path)
    assert result["LF004"].severity == "warn"
    assert "vendor/thing.py" in result["LF004"].message
    assert result["LF004"].evidence["files"][0]["status"] == "review"


def test_permissive_intree_license_is_fine(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "vendor/thing.py", "# SPDX-License-Identifier: MIT\n")
    result = run(tmp_path)
    assert result["LF004"].severity == "pass"
    assert result["LF002"].severity == "warn"  # still foreign, just compatible


def test_all_source_rules_can_be_disabled(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    result = run(tmp_path, require_spdx_headers="skip", forbid_foreign_license="skip",
                 require_consistent_copyright="skip", check_compatibility="skip")
    assert {f.severity for f in result.values()} == {"skip"}


def test_findings_carry_titles_and_remediation(tmp_path):
    write(tmp_path, "LICENSE", APACHE)
    write(tmp_path, "vendor/thing.py", "# SPDX-License-Identifier: GPL-3.0\n")
    result = run(tmp_path)
    assert result["LF002"].title == "Source files carry no foreign licence"
    assert "allow" in result["LF002"].remediation
    assert posture._family_for("LF002") == 5


# ---------------------------------------------------------------------------
# LD005 — dependency compatibility
# ---------------------------------------------------------------------------

def sbom(*packages: dict) -> dict:
    repo_self = {"name": "com.github.blackoutsecure/example", "versionInfo": "0"}
    return {"sbom": {"packages": [repo_self, *packages]}}


def pkg(name: str, license_: str) -> dict:
    return {"name": name, "versionInfo": "1.0.0", "licenseConcluded": license_}


class FakeGitHub:
    def __init__(self, body, status=200):
        self._body, self._status = body, status

    def get_or_none(self, path, **_kwargs):
        return self._body, self._status


def deps(body, tmp_path, monkeypatch, **cfg_kwargs) -> dict[str, posture.Finding]:
    monkeypatch.chdir(tmp_path)
    cfg = DependenciesPosture(**cfg_kwargs)
    findings = posture._audit_dependency_licenses(FakeGitHub(body), "o", "r", cfg)
    return {f.rule_id: f for f in findings}


def test_ld005_flags_copyleft_into_permissive(tmp_path, monkeypatch):
    write(tmp_path, "LICENSE", APACHE)
    result = deps(sbom(pkg("copyleft", "GPL-3.0"), pkg("ok", "MIT")), tmp_path, monkeypatch)
    assert result["LD005"].severity == "warn"
    assert "copyleft@1.0.0" in result["LD005"].message
    assert "ok@1.0.0" not in result["LD005"].message


def test_ld005_passes_for_permissive_dependencies(tmp_path, monkeypatch):
    write(tmp_path, "LICENSE", APACHE)
    result = deps(sbom(pkg("a", "MIT"), pkg("b", "BSD-3-Clause")), tmp_path, monkeypatch)
    assert result["LD005"].severity == "pass"


def test_ld005_dual_license_escapes_via_the_permissive_option(tmp_path, monkeypatch):
    write(tmp_path, "LICENSE", APACHE)
    result = deps(sbom(pkg("dual", "GPL-3.0 OR MIT")), tmp_path, monkeypatch)
    assert result["LD005"].severity == "pass"


def test_ld005_skips_without_a_project_license(tmp_path, monkeypatch):
    result = deps(sbom(pkg("a", "GPL-3.0")), tmp_path, monkeypatch)
    assert result["LD005"].severity == "skip"
