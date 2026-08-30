"""Licence compliance — LD### (dependencies) and LF### (working tree).

The companion repo `bos-marketplace-kit` audits *this repository's own*
licence (`LC###`). This module covers the other two surfaces:

* **`LD###` — dependencies.** Source of truth is GitHub's dependency-graph
  SBOM (`GET /repos/{owner}/{repo}/dependency-graph/sbom`), which returns
  SPDX with a `licenseConcluded` / `licenseDeclared` per package across
  every ecosystem GitHub understands. That avoids shelling out to a
  resolver, a package manager, or a per-ecosystem registry.
* **`LF###` — files in the working tree.** Reads `SPDX-License-Identifier`
  headers and copyright notices straight off disk, which is what catches
  vendored third-party code carrying a licence the project cannot take.

Classification runs against the vendored OSI snapshot in
`osi-licenses.json`, never a live call to opensource.org.

None of this is legal advice — see the note in the README.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, NamedTuple

import osi_catalogue

RULES = ("LD001", "LD002", "LD003", "LD004", "LD005")
FILE_RULES = ("LF001", "LF002", "LF003", "LF004")

# Cap on how many offending packages a single finding names, so the
# Security-tab message stays readable on a large dependency graph.
_MAX_LISTED = 10

_NO_LICENCE = osi_catalogue.UNDECLARED

# Catalogue loading, identifier resolution, SPDX expression parsing, and
# the copyright/compatibility engines live in the shared `osi_catalogue`
# module, synced from the hub alongside `osi-licenses.json` so both kits
# classify a licence identically. No aliases here: a dependency SBOM only
# ever emits canonical SPDX, unlike the READMEs the marketplace kit parses.
Catalogue = osi_catalogue.Catalogue
Copyright = osi_catalogue.Copyright
_operands = osi_catalogue.operands
_key = osi_catalogue.fuzzy_key
parse_copyrights = osi_catalogue.parse_copyrights
merge_copyrights = osi_catalogue.merge_copyrights


def catalogue() -> osi_catalogue.Catalogue:
    return osi_catalogue.load()


def catalogue_age_days(today: dt.date | None = None) -> int:
    """Age of the vendored OSI snapshot in days, or -1 when unparseable."""
    return catalogue().age_days(today)


def compatibility(dependency: str, project: str) -> osi_catalogue.Verdict:
    """Assess taking `dependency` into a work licensed as `project`."""
    return osi_catalogue.compatibility(catalogue(), dependency, project)


class Package(NamedTuple):
    name: str
    version: str
    expression: str          # raw SPDX licence expression from the SBOM
    identifiers: tuple[str, ...]  # normalised operands, () when undeclared

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


# ---------------------------------------------------------------------------
# Working-tree scan (LF###)
# ---------------------------------------------------------------------------

# Only text formats that conventionally carry a licence header. Scanning
# by extension keeps the walk cheap and avoids reading binaries.
SOURCE_SUFFIXES = frozenset({
    ".bash", ".c", ".cc", ".cjs", ".cpp", ".cs", ".css", ".go", ".h", ".hpp",
    ".java", ".js", ".jsx", ".kt", ".m", ".mjs", ".php", ".pl", ".ps1", ".py",
    ".rb", ".rs", ".scala", ".sh", ".sql", ".swift", ".tf", ".ts", ".tsx",
    ".vb", ".yaml", ".yml",
})

# Directories that never contain first-party source worth attributing.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "node_modules", "dist", "build", "target",
    ".idea", ".vscode", "site-packages",
})

# Licence headers live at the top of a file; reading further wastes I/O
# and risks matching an unrelated string in the body.
_HEADER_BYTES = 4096

_SPDX_HEADER = re.compile(
    r"SPDX-License-Identifier\s*:\s*([^\s*/#\"'<>]+)", re.IGNORECASE)


class SourceFile(NamedTuple):
    path: str
    identifier: str                    # normalised SPDX id, or "unknown"
    declared: str                      # what the header literally said
    copyrights: tuple[Copyright, ...]


class TreeScan(NamedTuple):
    files: tuple[SourceFile, ...]      # only files carrying a header/notice
    scanned: int                       # candidate files actually read
    truncated: bool                    # hit `max_files` before finishing

    @property
    def with_spdx(self) -> tuple[SourceFile, ...]:
        return tuple(f for f in self.files if f.identifier != "unknown")


def scan_tree(
    root: Path | str = ".",
    *,
    max_files: int = 5000,
    suffixes: frozenset[str] = SOURCE_SUFFIXES,
    skip_dirs: frozenset[str] = SKIP_DIRS,
) -> TreeScan:
    """Read SPDX headers and copyright notices from the working tree.

    Deliberately does *not* skip vendored directories beyond build and
    tooling output: third-party code checked into the repo is exactly what
    `LF002` exists to find.
    """
    root = Path(root)
    cat = catalogue()
    found: list[SourceFile] = []
    scanned = 0
    truncated = False

    for path in sorted(root.rglob("*")):
        if scanned >= max_files:
            truncated = True
            break
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in skip_dirs for part in relative.parts):
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                head = handle.read(_HEADER_BYTES)
        except OSError:
            continue
        scanned += 1

        spdx = _SPDX_HEADER.search(head)
        notices = parse_copyrights(head)
        if not spdx and not notices:
            continue
        declared = spdx.group(1).strip() if spdx else ""
        found.append(SourceFile(
            path=relative.as_posix(),
            identifier=cat.normalise(declared) if declared else "unknown",
            declared=declared,
            copyrights=notices,
        ))
    return TreeScan(tuple(found), scanned, truncated)


# ---------------------------------------------------------------------------
# SBOM parsing
# ---------------------------------------------------------------------------


def parse_sbom(document: Any) -> tuple[Package, ...]:
    """Extract dependency packages from a dependency-graph SBOM response.

    The first SPDX package is the repository itself; it is dropped so the
    rules only ever report on third-party code.
    """
    sbom = document.get("sbom") if isinstance(document, dict) else None
    if not isinstance(sbom, dict):
        sbom = document if isinstance(document, dict) else {}
    raw_packages = sbom.get("packages")
    if not isinstance(raw_packages, list):
        return ()

    cat = catalogue()
    out: list[Package] = []
    for entry in raw_packages:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name or name.startswith("com.github."):
            continue
        declared = entry.get("licenseConcluded") or entry.get("licenseDeclared") or ""
        expression = str(declared).strip()
        identifiers = (
            () if expression.lower() in _NO_LICENCE
            else tuple(cat.normalise(op) for op in _operands(expression))
        )
        out.append(Package(
            name=name,
            version=str(entry.get("versionInfo") or "").strip(),
            expression=expression,
            identifiers=identifiers,
        ))
    return tuple(out)


def satisfies(package: Package, acceptable: set[str]) -> bool:
    """True when the package can be consumed under an acceptable licence.

    A dual-licensed package (`MIT OR GPL-3.0`) only needs one acceptable
    operand, because the consumer picks. `_operands` deliberately does not
    preserve which operator joined them, so this is the permissive
    reading — flagging a package the consumer could legitimately take
    under an allowed licence would be a false positive.
    """
    return any(identifier in acceptable for identifier in package.identifiers)


def listed(packages: list[Package]) -> str:
    """Render package labels for a finding message, capped for readability."""
    labels = [p.label for p in packages[:_MAX_LISTED]]
    extra = len(packages) - len(labels)
    return ", ".join(labels) + (f", and {extra} more" if extra > 0 else "")
