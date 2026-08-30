"""Tests for `cli` — argument plumbing + subcommand outputs."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

import cli as cli_mod
from _version import __version__

# ---------------------------------------------------------------------------
# version + --version
# ---------------------------------------------------------------------------

def test_version_subcommand_prints_version():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main(["version"])
    assert rc == 0
    assert buf.getvalue().strip() == __version__


def test_top_level_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_mod.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


# ---------------------------------------------------------------------------
# detect
# ---------------------------------------------------------------------------

def test_detect_table_output(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main(["detect", "--root", str(tmp_path)])
    assert rc == 0
    out = buf.getvalue()
    assert "python" in out


def test_detect_json_output(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main(["detect", "--root", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert "dockerfile" in payload["artifact_types"]


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_validate_with_defaults(tmp_path: Path):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main(["validate", "--root", str(tmp_path)])
    assert rc == 0
    out = buf.getvalue()
    assert "Package metadata:" in out
    assert "bos-code-scanning-kit" in out
    assert "marketplace-config.json" in out
    assert "scan.tools:" in out


def test_validate_loads_explicit_config(tmp_path: Path):
    cfg = tmp_path / ".bos-scan.yml"
    cfg.write_text("owner: bos\nproject_name: thing\n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main(["validate", "--root", str(tmp_path)])
    assert rc == 0
    out = buf.getvalue()
    assert "bos" in out
    assert "thing" in out


def test_validate_invalid_config_returns_2(tmp_path: Path):
    cfg = tmp_path / ".bos-scan.yml"
    cfg.write_text("scan: {fail_on: extreme}\n")
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli_mod.main(["validate", "--root", str(tmp_path)])
    assert rc == 2
    assert "fail_on" in err.getvalue()


def test_validate_loads_required_global_config(tmp_path: Path):
    global_cfg = tmp_path / "org-scan.yml"
    global_cfg.write_text("code_scanning:\n  owner: global-owner\n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_mod.main([
            "validate",
            "--root", str(tmp_path),
            "--global-config", "org-scan.yml",
            "--use-global-config",
        ])
    assert rc == 0
    assert "global-owner" in buf.getvalue()


def test_validate_missing_required_global_config_returns_2(tmp_path: Path):
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli_mod.main([
            "validate",
            "--root", str(tmp_path),
            "--use-global-config",
        ])
    assert rc == 2
    assert "global config not found" in err.getvalue()


# ---------------------------------------------------------------------------
# posture (uses argparse plumbing; auth check fails before any net call)
# ---------------------------------------------------------------------------

def test_posture_without_token_returns_failure(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    err = io.StringIO()
    out = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
        ])
    # No token → PS000 error finding → exit 1 (with fail_on=fail default).
    assert rc == 1
    assert "PS000" in out.getvalue()


def test_posture_fail_on_never_returns_zero(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--fail-on", "never",
        ])
    assert rc == 0


def test_posture_writes_sarif(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    sarif_path = tmp_path / "p.sarif"
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--sarif", str(sarif_path),
            "--fail-on", "never",
        ])
    assert sarif_path.exists()
    payload = json.loads(sarif_path.read_text())
    assert payload["version"] == "2.1.0"
    assert payload["runs"]


def test_posture_writes_skips_json_sidecar(monkeypatch, tmp_path: Path):
    """`--skips-json` must always write a well-formed sidecar.

    Even when no probe skipped, the file should exist with an empty
    `skips: []` list so the consumer (action.yml summary step) can
    treat the sidecar as the single source of truth and never has to
    guess between "no skips" and "the run never wrote the file".
    """
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    skips_path = tmp_path / "skips.json"
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--skips-json", str(skips_path),
            "--fail-on", "never",
        ])
    assert rc == 0
    assert skips_path.exists()
    payload = json.loads(skips_path.read_text())
    assert "findings" in payload
    assert isinstance(payload["findings"], list)
    assert "skips" in payload
    assert isinstance(payload["skips"], list)
    # No token + no live API → no API-driven probe emits a skip; PS000
    # is `error` (excluded). PS013 (Microsoft Security DevOps detection)
    # always emits exactly one row at the configured severity — default
    # `skip` when the workflow has no MSDO call site. The LF### licence
    # rules also skip here: a bare repo has no LICENSE, so there is no
    # project licence to check in-tree headers against.
    skip_rules = [s["rule_id"] for s in payload["skips"]]
    assert "PS013" in skip_rules
    assert set(skip_rules) <= {"PS013", "LF001", "LF002", "LF003", "LF004"}


def test_posture_writes_structured_recommendations(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    recommendations_path = tmp_path / "recommendations.json"
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--recommendations-json", str(recommendations_path),
            "--fail-on", "never",
        ])

    assert rc == 0
    payload = json.loads(recommendations_path.read_text())
    assert payload
    assert all(item["patch_status"] == "unavailable" for item in payload)
    assert all(set(item) == {
        "finding_key", "rule_id", "title", "location", "recommendation",
        "confidence", "source", "patch_status",
    } for item in payload)


def test_posture_http_timeout_default_is_20(monkeypatch, tmp_path: Path):
    """`--http-timeout` defaults to 20 and flows into `posture.audit`."""
    captured: dict[str, object] = {}

    def fake_audit(**kwargs):
        captured.update(kwargs)
        # Return the real audit's no-token result shape so the rest of
        # cmd_posture (printing, sarif, summary, exit code) runs the
        # same path as the unmocked test above.
        import posture as posture_mod_real
        return posture_mod_real.AuditResult(findings=())

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(cli_mod.posture_mod, "audit", fake_audit)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--fail-on", "never",
        ])
    assert rc == 0
    assert captured["http_timeout"] == 20


def test_posture_http_timeout_override_flows_through(monkeypatch, tmp_path: Path):
    """`--http-timeout 45` overrides the default and reaches `audit()`."""
    captured: dict[str, object] = {}

    def fake_audit(**kwargs):
        captured.update(kwargs)
        import posture as posture_mod_real
        return posture_mod_real.AuditResult(findings=())

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(cli_mod.posture_mod, "audit", fake_audit)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(out):
        rc = cli_mod.main([
            "posture",
            "--owner", "o", "--repo", "r",
            "--root", str(tmp_path),
            "--fail-on", "never",
            "--http-timeout", "45",
        ])
    assert rc == 0
    assert captured["http_timeout"] == 45


# ---------------------------------------------------------------------------
# sarif merge
# ---------------------------------------------------------------------------

def test_sarif_merge_two_inputs(tmp_path: Path):
    a = tmp_path / "a.sarif"
    b = tmp_path / "b.sarif"
    a.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "A"}}, "results": []}],
    }))
    b.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "B"}}, "results": []}],
    }))
    out = tmp_path / "out.sarif"
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli_mod.main([
            "sarif",
            "--input", str(a),
            "--input", str(b),
            "--output", str(out),
        ])
    assert rc == 0
    merged = json.loads(out.read_text())
    names = [r["tool"]["driver"]["name"] for r in merged["runs"]]
    assert names == ["A", "B"]


def test_sarif_merge_skips_missing_inputs(tmp_path: Path):
    out = tmp_path / "out.sarif"
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli_mod.main([
            "sarif",
            "--input", str(tmp_path / "absent1.sarif"),
            "--input", str(tmp_path / "absent2.sarif"),
            "--output", str(out),
        ])
    assert rc == 0
    merged = json.loads(out.read_text())
    assert merged["runs"] == []
    assert "skipping" in err.getvalue()


def test_sarif_merge_with_posture(tmp_path: Path):
    a = tmp_path / "a.sarif"
    a.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "A"}}, "results": []}],
    }))
    p = tmp_path / "posture.sarif"
    p.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "bos-code-scanning-kit"}},
                  "results": []}],
    }))
    out = tmp_path / "out.sarif"
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli_mod.main([
            "sarif",
            "--input", str(a),
            "--posture", str(p),
            "--output", str(out),
        ])
    assert rc == 0
    merged = json.loads(out.read_text())
    assert len(merged["runs"]) == 2
