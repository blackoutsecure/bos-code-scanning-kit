"""Tests for `scan_kit.cli` — argument plumbing + subcommand outputs."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from scan_kit import __version__
from scan_kit import cli as cli_mod

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
    assert "built-in defaults" in out
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
