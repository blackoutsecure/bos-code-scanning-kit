"""Tests for `scan_kit.sarif` — merge + posture-finding emitter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scan_kit import sarif as sarif_mod
from scan_kit.posture import AuditResult, Finding

# ---------------------------------------------------------------------------
# empty_log / merge / dump / load
# ---------------------------------------------------------------------------

def test_empty_log_shape():
    log = sarif_mod.empty_log()
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert log["runs"] == []


def test_merge_concatenates_runs():
    a = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "A"}}}]}
    b = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "B"}}},
                                        {"tool": {"driver": {"name": "B2"}}}]}
    merged = sarif_mod.merge(a, b)
    names = [r["tool"]["driver"]["name"] for r in merged["runs"]]
    assert names == ["A", "B", "B2"]


def test_merge_ignores_garbage_inputs():
    merged = sarif_mod.merge(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "X"}}}]},
        {"runs": "not a list"},
        {"no_runs_key": True},
        None,                 # type: ignore[arg-type]
    )
    assert len(merged["runs"]) == 1


def test_dump_and_load_roundtrip(tmp_path: Path):
    log = sarif_mod.merge(
        {"version": "2.1.0",
         "runs": [{"tool": {"driver": {"name": "X"}}, "results": []}]},
    )
    out = tmp_path / "out.sarif"
    sarif_mod.dump(log, out)
    assert out.read_text().endswith("\n")
    loaded = sarif_mod.load(out)
    assert loaded["runs"][0]["tool"]["driver"]["name"] == "X"


def test_load_missing_file_raises(tmp_path: Path):
    with pytest.raises(ValueError):
        sarif_mod.load(tmp_path / "no.sarif")


def test_load_invalid_json_raises(tmp_path: Path):
    p = tmp_path / "x.sarif"
    p.write_text("not json {")
    with pytest.raises(ValueError):
        sarif_mod.load(p)


def test_load_non_object_raises(tmp_path: Path):
    p = tmp_path / "x.sarif"
    p.write_text("[]")
    with pytest.raises(ValueError):
        sarif_mod.load(p)


def test_merge_files_skips_loads_in_sequence(tmp_path: Path):
    a = tmp_path / "a.sarif"
    b = tmp_path / "b.sarif"
    sarif_mod.dump({"version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "A"}}, "results": []}]}, a)
    sarif_mod.dump({"version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "B"}}, "results": []}]}, b)
    merged = sarif_mod.merge_files([a, b])
    assert [r["tool"]["driver"]["name"] for r in merged["runs"]] == ["A", "B"]


# ---------------------------------------------------------------------------
# posture_run — Finding → SARIF translation
# ---------------------------------------------------------------------------

def _ar(*findings: Finding) -> AuditResult:
    return AuditResult(findings=tuple(findings))


def test_posture_run_drops_pass_and_skip():
    findings = [
        Finding("PS001", "pass", "ok"),
        Finding("PS002", "fail", "missing"),
        Finding("PS003", "warn", "weak"),
        Finding("PS010", "skip", "off"),
    ]
    run = sarif_mod.posture_run(findings)
    rule_ids = [r["ruleId"] for r in run["results"]]
    assert "PS001" not in rule_ids
    assert "PS010" not in rule_ids
    assert "PS002" in rule_ids
    assert "PS003" in rule_ids


def test_posture_run_severity_mapping():
    findings = [
        Finding("PS001", "fail", "x"),
        Finding("PS002", "warn", "y"),
        Finding("PS003", "error", "z"),
    ]
    run = sarif_mod.posture_run(findings)
    by_id = {r["ruleId"]: r for r in run["results"]}
    assert by_id["PS001"]["level"] == "error"
    assert by_id["PS002"]["level"] == "warning"
    assert by_id["PS003"]["level"] == "warning"   # tool error => warning, not failure


def test_posture_run_records_branch_locations():
    findings = [Finding("PS020", "fail", "no protection", location="branch:main")]
    run = sarif_mod.posture_run(findings)
    locs = run["results"][0]["locations"]
    # Branch label preserved as a logicalLocation for the GHAS UI…
    assert locs[0]["logicalLocations"][0]["name"] == "branch:main"
    # …but a physicalLocation MUST be present — GHAS rejects logical-only
    # results with `locationFromSarifResult: expected a physical location`.
    # Sentinel artifact is `.github/` (where security config lives).
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"


def test_posture_run_records_file_locations():
    findings = [Finding("PS010", "fail", "no perms", location=".github/workflows/ci.yml")]
    run = sarif_mod.posture_run(findings)
    locs = run["results"][0]["locations"]
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/ci.yml"


def test_posture_run_synthesises_repo_location_when_finding_has_none():
    # Regression: PS001/PS002/PS003 emit Finding(..., "error", str(exc))
    # with NO `location=` when the default GITHUB_TOKEN lacks the scope
    # to query GHAS settings. SARIF results without a `physicalLocation`
    # are rejected by GHAS with `locationFromSarifResult: expected a
    # physical location` (an earlier validator revision only enforced
    # `locations: []` being non-empty and accepted logical-only entries;
    # the upload pipeline now rejects those too). Every result MUST
    # include a `physicalLocation` — we synthesise one pointing at
    # `.github/` and keep the repo logicalLocation for UI clarity.
    findings = [
        Finding("PS001", "error", "API 403 querying code-scanning settings"),
        Finding("PS002", "error", "API 403 querying secret-scanning settings"),
        Finding("PS003", "error", "API 403 querying Dependabot settings"),
    ]
    run = sarif_mod.posture_run(findings)
    assert len(run["results"]) == 3
    for r in run["results"]:
        locs = r["locations"]
        assert len(locs) >= 1, f"result {r['ruleId']} must have >=1 location"
        # Sentinel physicalLocation pointing at `.github/`
        assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"
        # Synthetic repo-wide logicalLocation kept for UI label
        assert locs[0]["logicalLocations"][0]["name"] == "repository"


def test_posture_run_rules_index_unique():
    findings = [Finding("PS001", "fail", f"x{n}") for n in range(3)]
    run = sarif_mod.posture_run(findings)
    rules = run["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"PS001"}


def test_posture_run_tool_metadata():
    run = sarif_mod.posture_run([])
    assert run["tool"]["driver"]["name"] == "bos-code-scanning-kit"
    assert run["tool"]["driver"]["informationUri"].startswith("https://")


# ---------------------------------------------------------------------------
# End-to-end: posture findings + scanner SARIF merge
# ---------------------------------------------------------------------------

def test_merge_with_posture_and_scanner(tmp_path: Path):
    # Scanner SARIF (one synthetic gitleaks-shaped run)
    scanner_log = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{"ruleId": "GL01", "level": "error",
                         "message": {"text": "API key"}}],
        }],
    }
    scanner_path = tmp_path / "gitleaks.sarif"
    sarif_mod.dump(scanner_log, scanner_path)

    # Posture findings → posture_run
    posture_run = sarif_mod.posture_run([
        Finding("PS020", "fail", "no protection on main", location="branch:main"),
    ])

    merged = sarif_mod.merge(scanner_log, {"runs": [posture_run]})
    names = [r["tool"]["driver"]["name"] for r in merged["runs"]]
    assert "gitleaks" in names
    assert "bos-code-scanning-kit" in names

    # JSON round-trip is clean and deterministic
    text = json.dumps(merged, indent=2)
    assert "PS020" in text
    assert "GL01" in text


# ---------------------------------------------------------------------------
# sanitize_result / sanitize_run / merge() — defensive normalization
# ---------------------------------------------------------------------------
#
# Regression: GHAS Code Scanning rejects the entire upload when ANY
# result in ANY run has a `locations[]` entry without a usable
# `physicalLocation` (missing/empty `artifactLocation.uri`), with the
# error `locationFromSarifResult: expected a physical location`.
# Gitleaks v8.21.x is the observed trigger — for a handful of detector
# rules it emits results with empty URIs — but every upstream tool we
# feed into the merger could in principle produce one.

def test_sanitize_result_preserves_valid_physical_location():
    """Valid entries — including gitleaks-style region/snippet data —
    must round-trip untouched so we don't lose line numbers in the
    Security tab.
    """
    result = {
        "ruleId": "GL01",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 42, "snippet": {"text": "***"}},
            },
        }],
    }
    sarif_mod.sanitize_result(result)
    pl = result["locations"][0]["physicalLocation"]
    assert pl["artifactLocation"]["uri"] == "src/app.py"
    assert pl["region"]["startLine"] == 42
    assert pl["region"]["snippet"]["text"] == "***"


def test_sanitize_result_synthesises_when_locations_missing():
    """`results[]` entry with no `locations` key gets a sentinel."""
    result = {"ruleId": "X"}
    sarif_mod.sanitize_result(result)
    locs = result["locations"]
    assert len(locs) == 1
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"
    assert locs[0]["logicalLocations"][0]["name"] == "repository"


def test_sanitize_result_synthesises_when_locations_empty():
    """`results[]` entry with `locations: []` gets a sentinel."""
    result = {"ruleId": "X", "locations": []}
    sarif_mod.sanitize_result(result)
    assert len(result["locations"]) == 1
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"


def test_sanitize_result_repairs_missing_physical_location():
    """Logical-only location: graft a sentinel `physicalLocation`
    while keeping the logical-location label for the UI.
    """
    result = {
        "ruleId": "X",
        "locations": [{"logicalLocations": [{"name": "main", "kind": "module"}]}],
    }
    sarif_mod.sanitize_result(result)
    loc = result["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github/"
    assert loc["logicalLocations"][0]["name"] == "main"


def test_sanitize_result_repairs_empty_uri():
    """The gitleaks-observed shape: physicalLocation present but URI
    empty. Sentinel must overwrite the broken URI but not duplicate the
    location.
    """
    result = {
        "ruleId": "GL02",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": ""},
                "region": {"startLine": 1},
            },
        }],
    }
    sarif_mod.sanitize_result(result)
    assert len(result["locations"]) == 1
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"


def test_sanitize_result_repairs_missing_artifact_location():
    """`physicalLocation` present but `artifactLocation` key missing."""
    result = {
        "ruleId": "GL03",
        "locations": [{"physicalLocation": {"region": {"startLine": 5}}}],
    }
    sarif_mod.sanitize_result(result)
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"


def test_sanitize_result_drops_non_object_entries():
    """Garbage location entries get dropped; a sentinel is emitted if
    no good entries remain.
    """
    result = {"ruleId": "X", "locations": ["bogus", 42, None]}
    sarif_mod.sanitize_result(result)
    assert len(result["locations"]) == 1
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".github/"


def test_sanitize_result_is_idempotent():
    """Sanitization must converge in one pass."""
    result = {"ruleId": "X"}
    sarif_mod.sanitize_result(result)
    snapshot = json.dumps(result, sort_keys=True)
    sarif_mod.sanitize_result(result)
    assert json.dumps(result, sort_keys=True) == snapshot


def test_sanitize_run_handles_missing_results():
    """Runs without a `results` key (or with non-list results) are no-ops."""
    sarif_mod.sanitize_run({"tool": {"driver": {"name": "X"}}})
    sarif_mod.sanitize_run({"tool": {"driver": {"name": "X"}}, "results": "nope"})


def test_merge_invokes_sanitizer_on_every_run():
    """Regression for `locationFromSarifResult: expected a physical
    location` from gitleaks-merged results. The merger MUST repair
    broken locations before the merged SARIF reaches the GHAS upload
    action — otherwise the entire upload fails for all runs.
    """
    bad = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                # Three broken-shape leaks, mirroring the production
                # failure observed in `docker-github-runner` runs.
                {"ruleId": "gl-a", "message": {"text": "leak A"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": ""}}}]},
                {"ruleId": "gl-b", "message": {"text": "leak B"},
                 "locations": [{"logicalLocations": [{"name": "blob"}]}]},
                {"ruleId": "gl-c", "message": {"text": "leak C"}},
            ],
        }],
    }
    merged = sarif_mod.merge(bad)
    results = merged["runs"][0]["results"]
    assert len(results) == 3
    for r in results:
        assert len(r["locations"]) >= 1
        pl = r["locations"][0]["physicalLocation"]
        uri = pl["artifactLocation"]["uri"]
        assert isinstance(uri, str) and uri  # non-empty


def test_merge_does_not_mutate_good_results():
    """A clean upstream run survives the merger byte-for-byte."""
    good = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "actionlint"}},
            "results": [{
                "ruleId": "syntax-check",
                "message": {"text": "OK"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                        "region": {"startLine": 7, "endLine": 7},
                    },
                }],
            }],
        }],
    }
    before = json.dumps(good, sort_keys=True)
    sarif_mod.merge(good)
    assert json.dumps(good, sort_keys=True) == before
