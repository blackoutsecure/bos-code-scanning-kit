"""Validate the executable scripts embedded in the public composite action."""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
SCRIPTS = [
    (step.get("id", step.get("name", "unnamed")), step["run"])
    for step in ACTION["runs"]["steps"]
    if step.get("shell") == "bash" and "run" in step
]
PYTHON_BLOCKS = [
    (f"{name}-{index}", source)
    for name, script in SCRIPTS
    for index, source in enumerate(
        re.findall(r"(?ms)^[^\n]*\bpython3\b[^\n]*<<'PY'[^\n]*\n(.*?)^PY$", script)
    )
]


@pytest.mark.parametrize(("name", "script"), SCRIPTS, ids=[name for name, _ in SCRIPTS])
def test_composite_bash_syntax(name: str, script: str) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to validate composite shell syntax")
    result = subprocess.run(
        [bash, "-n"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, f"{name}: {result.stderr}"


@pytest.mark.parametrize(
    ("name", "source"), PYTHON_BLOCKS, ids=[name for name, _ in PYTHON_BLOCKS]
)
def test_composite_python_syntax(name: str, source: str) -> None:
    ast.parse(source, filename=f"action.yml:{name}")


def test_summary_python_is_covered() -> None:
    assert any(name.startswith("summary-") for name, _ in PYTHON_BLOCKS)
