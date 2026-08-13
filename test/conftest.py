"""Pytest conftest — ensure `src/` is importable as a top-level module."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# When the test suite runs inside GitHub Actions, the runner sets
# `GITHUB_STEP_SUMMARY` (and friends) to real, writable paths. The CLI's
# `_write_step_summary()` helper honours that variable, so tests that exercise
# `cli_mod.main(["posture", ...])` would otherwise append a duplicate posture
# table to the job summary every invocation — see the rendered "## BOS Code
# Scanning Kit — posture audit" block in the `tests.yml` summary.
#
# Strip the well-known Actions output sinks before each test so unit tests can
# never pollute the surrounding runner's job summary or step outputs.
@pytest.fixture(autouse=True)
def _isolate_actions_output_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "GITHUB_ENV"):
        monkeypatch.delenv(var, raising=False)
