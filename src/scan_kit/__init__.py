"""BOS Code Scanning Kit — auto-detect ecosystems, run scanners, audit posture, merge SARIF.

Public surface:
    scan_kit.__version__       Semantic version.
    scan_kit.cli.main          CLI entry point (also exposed as `bos-scan`).
    scan_kit.config            Layered config loader + defaults + validation.
    scan_kit.detect            Ecosystem auto-detector.
    scan_kit.posture           GitHub REST-API posture auditor.
    scan_kit.sarif             SARIF merge helpers.

The composite Action under `action.yml` is the canonical CI surface;
this Python package is a sibling exposing the same logic as a local
`bos-scan` CLI so operators can dry-run before pushing.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
