"""Package identity independent of repository policy configuration."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import metadata as installed_metadata

from _version import __version__

PACKAGE_NAME = "bos-code-scanning-kit"
PACKAGE_AUTHOR = "Blackout Secure"
PACKAGE_DESCRIPTION = (
    "Local CLI for the BOS Code Scanning Kit — auto-detect ecosystems, run scanners, "
    "audit posture, merge SARIF for GHAS."
)


def package_metadata() -> dict[str, str]:
    """Return package identity without loading any marketplace configuration."""
    try:
        installed = installed_metadata(PACKAGE_NAME)
    except PackageNotFoundError:
        return {
            "name": PACKAGE_NAME,
            "version": __version__,
            "author": PACKAGE_AUTHOR,
            "description": PACKAGE_DESCRIPTION,
        }

    return {
        "name": installed.get("Name") or PACKAGE_NAME,
        "version": installed.get("Version") or __version__,
        "author": installed.get("Author") or PACKAGE_AUTHOR,
        "description": installed.get("Summary") or PACKAGE_DESCRIPTION,
    }
