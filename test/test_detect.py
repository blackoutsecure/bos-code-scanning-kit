"""Tests for `detect` — ecosystem detector."""

from __future__ import annotations

from pathlib import Path

import detect as detect_mod

# ---------------------------------------------------------------------------
# Empty repo
# ---------------------------------------------------------------------------

def test_empty_dir_detects_nothing(tmp_path: Path):
    result = detect_mod.detect(tmp_path)
    assert result.languages == ()
    assert result.artifact_types == ()
    assert result.package_managers == ()


def test_nonexistent_dir_is_safe(tmp_path: Path):
    result = detect_mod.detect(tmp_path / "nope")
    assert result.languages == ()


# ---------------------------------------------------------------------------
# Language signals
# ---------------------------------------------------------------------------

def test_python_detected_by_marker(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    result = detect_mod.detect(tmp_path)
    assert "python" in result.languages
    assert "pyproject" in result.package_managers


def test_python_detected_by_extension(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hi')\n")
    result = detect_mod.detect(tmp_path)
    assert "python" in result.languages


def test_javascript_typescript_both_marked(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "index.ts").write_text("export const x = 1;\n")
    result = detect_mod.detect(tmp_path)
    assert "javascript" in result.languages
    assert "typescript" in result.languages
    assert "npm" not in result.package_managers  # no lockfile -> no pm
    (tmp_path / "package-lock.json").write_text("{}")
    result = detect_mod.detect(tmp_path)
    assert "npm" in result.package_managers


def test_multiple_languages_aggregate(tmp_path: Path):
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    (tmp_path / "main.rs").write_text("fn main() {}\n")
    result = detect_mod.detect(tmp_path)
    assert {"go", "rust"} <= set(result.languages)


# ---------------------------------------------------------------------------
# Artefact types
# ---------------------------------------------------------------------------

def test_dockerfile_detected(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    result = detect_mod.detect(tmp_path)
    assert "dockerfile" in result.artifact_types


def test_dockerfile_variants_detected(tmp_path: Path):
    (tmp_path / "Dockerfile.runtime").write_text("FROM alpine\n")
    (tmp_path / "build.dockerfile").write_text("FROM alpine\n")
    result = detect_mod.detect(tmp_path)
    assert "dockerfile" in result.artifact_types


def test_compose_detected(tmp_path: Path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    result = detect_mod.detect(tmp_path)
    assert "compose" in result.artifact_types


def test_github_workflows_detected(tmp_path: Path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n")
    result = detect_mod.detect(tmp_path)
    assert "github_workflows" in result.artifact_types


def test_terraform_detected(tmp_path: Path):
    (tmp_path / "main.tf").write_text("# tf\n")
    result = detect_mod.detect(tmp_path)
    assert "terraform" in result.artifact_types


def test_shell_detected(tmp_path: Path):
    (tmp_path / "build.sh").write_text("#!/bin/bash\necho hi\n")
    result = detect_mod.detect(tmp_path)
    assert "shell" in result.artifact_types
    assert "shell" in result.languages


def test_kubernetes_detected(tmp_path: Path):
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "deploy.yaml").write_text("kind: Deployment\n")
    result = detect_mod.detect(tmp_path)
    assert "kubernetes" in result.artifact_types


# ---------------------------------------------------------------------------
# Ignored directories
# ---------------------------------------------------------------------------

def test_ignored_directories_are_skipped(tmp_path: Path):
    # Files under .git/node_modules/etc must not contribute to detection.
    for d in ("node_modules", ".git", "dist", "vendor", "__pycache__"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "main.py").write_text("print('hidden')\n")
    result = detect_mod.detect(tmp_path)
    assert "python" not in result.languages


def test_pruning_does_not_skip_visible_files(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "main.py").write_text("print('hidden')\n")
    (tmp_path / "main.py").write_text("print('visible')\n")
    result = detect_mod.detect(tmp_path)
    assert "python" in result.languages


# ---------------------------------------------------------------------------
# CodeQL language mapping
# ---------------------------------------------------------------------------

def test_codeql_language_mapping(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "main.ts").write_text("export {};\n")
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    result = detect_mod.detect(tmp_path)
    cq = result.codeql_languages()
    assert "python" in cq
    assert "javascript-typescript" in cq
    assert "go" in cq
    assert "rust" in cq


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

def test_to_dict_shape(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    result = detect_mod.detect(tmp_path)
    d = result.to_dict()
    assert set(d) == {"languages", "artifact_types", "package_managers", "files_scanned"}
    assert d["languages"] == list(result.languages)
