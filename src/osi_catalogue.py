"""Shared OSI/SPDX licence catalogue — synced, not imported.

Both kits classify licence identifiers, and they must reach the same
verdict for the same string. Neither can depend on the other (they are
independent Marketplace actions, and both are deliberately stdlib-only),
so this module is distributed the same way `osi-licenses.json` is:
generated/owned here in the hub and fanned out by managed file sync as
part of `license_catalogue_service`. The module and the data file are a
versioned pair and must always move together.

Do not edit the copies inside the kits. Edit this file, then let the
sync land it.

Scope is deliberately narrow — loading the catalogue and resolving one
identifier string. Everything above that stays kit-specific:

* `bos-marketplace-kit` reads README badges, `pyproject.toml`, and
  `package.json`, so it supplies free-text aliases ("Apache 2.0",
  "GPLv3") via the `aliases` argument.
* `bos-code-scanning-kit` reads dependency-graph SBOMs, which only ever
  emit canonical SPDX, so it supplies none.

Stdlib only, and no package-relative imports, so it works both as a
package module (`marketplace_kit.osi_catalogue`) and as a flat module
(`import osi_catalogue`).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any, NamedTuple

CATALOGUE_FILENAME = "osi-licenses.json"

# Values that mean "no licence was declared" across SPDX, npm, and the
# GitHub dependency graph.
UNDECLARED = frozenset({"", "unknown", "none", "null", "noassertion"})

# SPDX expression operators, matched case-sensitively and
# whitespace-delimited per the SPDX grammar. A case-insensitive
# `\bOR\b` would split `GPL-2.0-or-later` in half, because `-` is a
# word boundary.
_SPLIT_OR = re.compile(r"\s+OR\s+")
_SPLIT_AND = re.compile(r"\s+AND\s+")
_STRIP_EXCEPTION = re.compile(r"\s+WITH\s+.*$")

_SUFFIX = re.compile(r"(-only|-or-later|\+)$", re.IGNORECASE)


def fuzzy_key(value: str) -> str:
    """Collapse a display name or free text to a loose comparison key."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def default_path() -> Path:
    """Locate the vendored catalogue in either kit's layout."""
    here = Path(__file__).parent
    for candidate in (here / CATALOGUE_FILENAME, here / "data" / CATALOGUE_FILENAME):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"{CATALOGUE_FILENAME} not found next to {__file__} or in ./data/")


class Catalogue:
    """A loaded OSI/SPDX snapshot with identifier resolution."""

    def __init__(self, path: Path | None = None, *,
                 aliases: dict[str, str] | None = None) -> None:
        source = Path(path) if path is not None else default_path()
        self.document: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
        self.path = source
        self.snapshot: str = str(self.document.get("snapshot", ""))
        self.url: str = str(self.document.get("source", ""))
        self.licenses: dict[str, Any] = self.document.get("licenses") or {}
        self.not_open_source: dict[str, str] = self.document.get("not_open_source") or {}

        # Two lookup tiers, and they cannot be merged. `fuzzy_key`
        # discards punctuation so free text can match, but that same
        # collapsing makes distinct SPDX identifiers collide —
        # `GPL-3.0` and `GPL-3.0+` both reduce to `gpl30`. Exact
        # identifiers therefore win before anything fuzzy is consulted.
        self._exact: dict[str, str] = {}
        self._fuzzy: dict[str, str] = {}
        for spdx, body in sorted(self.licenses.items()):
            self._exact[spdx.lower()] = spdx
            self._fuzzy.setdefault(fuzzy_key(spdx), spdx)
            name = (body or {}).get("name")
            if name:
                self._fuzzy.setdefault(fuzzy_key(str(name)), spdx)
        for spdx in sorted(self.not_open_source):
            self._exact.setdefault(spdx.lower(), spdx)
            self._fuzzy.setdefault(fuzzy_key(spdx), spdx)
        for alias, spdx in (aliases or {}).items():
            self._fuzzy[fuzzy_key(alias)] = spdx

    def normalise(self, raw: str) -> str:
        """Map one licence spelling onto a catalogue identifier, or ``unknown``.

        A `-only` / `-or-later` / `+` suffix is only stripped when the
        full identifier is not itself catalogued, so SPDX ids that carry
        the suffix keep their own identity.
        """
        text = (raw or "").strip().strip("\"'").strip("()").strip()
        if not text or text.lower() in UNDECLARED:
            return "unknown"
        stripped = _SUFFIX.sub("", text)
        for candidate in (text, stripped):
            hit = self._exact.get(candidate.lower())
            if hit:
                return hit
        for candidate in (text, stripped):
            hit = self._fuzzy.get(fuzzy_key(candidate))
            if hit:
                return hit
        return "unknown"

    def is_osi_approved(self, identifier: str) -> bool:
        return identifier in self.licenses

    def age_days(self, today: _dt.date | None = None) -> int:
        """Age of the snapshot in days, or -1 when the date is unparseable."""
        try:
            snapshot = _dt.date.fromisoformat(self.snapshot)
        except (ValueError, TypeError):
            return -1
        return ((today or _dt.date.today()) - snapshot).days


_cache: dict[tuple[str, tuple[tuple[str, str], ...]], Catalogue] = {}


def load(path: Path | None = None, *,
         aliases: dict[str, str] | None = None) -> Catalogue:
    """Return a cached `Catalogue`. Never hits the network."""
    resolved = Path(path) if path is not None else default_path()
    key = (str(resolved), tuple(sorted((aliases or {}).items())))
    if key not in _cache:
        _cache[key] = Catalogue(resolved, aliases=aliases)
    return _cache[key]


def operands(expression: str) -> list[str]:
    """Flatten an SPDX licence expression into its individual operands.

    `WITH` binds an exception to the licence on its left, so the right
    operand is never a licence in its own right and is dropped.
    """
    text = expression.replace("(", " ").replace(")", " ")
    parts: list[str] = []
    for or_part in _SPLIT_OR.split(text):
        for and_part in _SPLIT_AND.split(or_part):
            operand = _STRIP_EXCEPTION.sub("", and_part).strip()
            if operand:
                parts.append(operand)
    return parts


# ---------------------------------------------------------------------------
# Copyright notices
# ---------------------------------------------------------------------------

# `Copyright (c) 2019-2021, 2024 Alice Example <alice@example.com>`
_COPYRIGHT_LINE = re.compile(
    r"copyright\s*(?:\((?:c|C)\)|©|&copy;|\(c\))?\s*"
    r"(?P<years>\d{4}(?:\s*[-–—,]\s*(?:\d{4}|present))*)"
    r"\s*[,:]?\s*"
    r"(?P<holder>[^\n]*)",
    re.IGNORECASE,
)

# Trailing noise that is not part of a holder's name.
_HOLDER_NOISE = re.compile(
    r"\s*(?:all rights reserved\.?|<[^>]*>|\([^)]*@[^)]*\))\s*$", re.IGNORECASE)

# Separators between several holders on one line. A pipe is deliberately
# absent: in a README header like
# `**Copyright © 2025-2026 Acme | Apache License 2.0**` it divides the
# notice from unrelated text rather than naming a second holder.
_HOLDER_SPLIT = re.compile(r"\s*(?:;|\band\b)\s*", re.IGNORECASE)

# Everything from a pipe onwards is not part of the holder.
_HOLDER_TAIL = re.compile(r"\s*\|.*$", re.DOTALL)


class Copyright(NamedTuple):
    holder: str
    years: tuple[int, ...]
    raw: str

    def render(self, symbol: str = "©") -> str:
        return f"Copyright {symbol} {format_years(self.years)} {self.holder}".strip()


def format_years(years: tuple[int, ...] | list[int]) -> str:
    """Render years as compact ranges: (2019,2020,2021,2024) -> '2019-2021, 2024'."""
    ordered = sorted(set(int(y) for y in years))
    if not ordered:
        return ""
    spans: list[str] = []
    start = previous = ordered[0]
    for year in ordered[1:]:
        if year == previous + 1:
            previous = year
            continue
        spans.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = year
    spans.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(spans)


def _expand_years(raw: str, *, today: _dt.date | None = None) -> tuple[int, ...]:
    """Expand '2019-2021, 2024' into every year it covers."""
    current = (today or _dt.date.today()).year
    years: set[int] = set()
    for chunk in re.split(r"\s*,\s*", raw):
        chunk = chunk.strip()
        if not chunk:
            continue
        span = re.match(r"^(\d{4})\s*[-–—]\s*(\d{4}|present)$", chunk, re.IGNORECASE)
        if span:
            start = int(span.group(1))
            end = current if span.group(2).lower() == "present" else int(span.group(2))
            if end < start:
                start, end = end, start
            years.update(range(start, end + 1))
        elif chunk.isdigit():
            years.add(int(chunk))
    return tuple(sorted(years))


def _clean_holder(value: str) -> str:
    holder = _HOLDER_TAIL.sub("", value).strip()
    # Markdown emphasis routinely wraps the copyright line in a README.
    holder = holder.strip("*_").strip().strip(".,;:").strip()
    while True:
        stripped = _HOLDER_NOISE.sub("", holder).strip().strip(".,;:").strip("*_").strip()
        if stripped == holder:
            break
        holder = stripped
    return holder


def parse_copyrights(text: str, *, today: _dt.date | None = None) -> tuple[Copyright, ...]:
    """Extract every copyright notice from a block of text.

    One source line may name several holders (`Copyright 2020 Alice and
    Bob`), so the result is per-holder rather than per-line.
    """
    found: list[Copyright] = []
    for match in _COPYRIGHT_LINE.finditer(text or ""):
        years = _expand_years(match.group("years"), today=today)
        raw = match.group(0).strip()
        holders = [
            holder for holder in
            (_clean_holder(part) for part in _HOLDER_SPLIT.split(match.group("holder") or ""))
            if holder
        ]
        if holders:
            found.extend(Copyright(holder, years, raw) for holder in holders)
        else:
            # A year with no holder is still a notice worth reporting.
            found.append(Copyright("", years, raw))
    return tuple(found)


def merge_copyrights(entries: tuple[Copyright, ...] | list[Copyright]) -> tuple[Copyright, ...]:
    """Collapse to one notice per holder, unioning their years.

    Case and surrounding punctuation vary between files, so holders are
    matched case-insensitively while the first-seen spelling is kept.
    """
    merged: dict[str, Copyright] = {}
    for entry in entries:
        key = entry.holder.casefold()
        existing = merged.get(key)
        if existing is None:
            merged[key] = entry
        else:
            merged[key] = Copyright(
                existing.holder,
                tuple(sorted(set(existing.years) | set(entry.years))),
                existing.raw,
            )
    return tuple(merged[key] for key in sorted(merged))


# ---------------------------------------------------------------------------
# Reciprocity and inbound-licence compatibility
# ---------------------------------------------------------------------------

# Ordered weakest to strongest. A dependency never constrains a project
# that is already at least as reciprocal as the dependency.
RECIPROCITY_ORDER = (
    "public-domain",
    "permissive",
    "weak-copyleft",
    "strong-copyleft",
    "network-copyleft",
    "proprietary",
)

# Combinations the ecosystem treats as genuinely incompatible rather than
# merely constraining. `Apache-2.0` into `GPL-2.0` is the classic one:
# the Apache patent-termination clause adds a restriction GPLv2 forbids.
_KNOWN_INCOMPATIBLE: dict[tuple[str, str], str] = {
    ("Apache-2.0", "GPL-2.0"): "Apache-2.0's patent clause adds a restriction GPL-2.0 does not permit",
    ("Apache-2.0", "GPL-2.0-only"): "Apache-2.0's patent clause adds a restriction GPL-2.0-only does not permit",
    ("GPL-3.0", "GPL-2.0-only"): "GPL-3.0 code cannot be combined into a GPL-2.0-only work",
    ("GPL-3.0-only", "GPL-2.0-only"): "GPL-3.0-only code cannot be combined into a GPL-2.0-only work",
}


class Verdict(NamedTuple):
    status: str   # "ok" | "review" | "incompatible" | "unknown"
    reason: str


def reciprocity(catalogue_obj: Catalogue, identifier: str) -> str:
    """Return the curated reciprocity class, or `unknown`."""
    entry = catalogue_obj.licenses.get(identifier)
    if isinstance(entry, dict):
        value = entry.get("reciprocity")
        if value in RECIPROCITY_ORDER:
            return value
    if identifier in catalogue_obj.not_open_source:
        return "proprietary"
    return "unknown"


def compatibility(catalogue_obj: Catalogue, dependency: str, project: str) -> Verdict:
    """Assess taking `dependency` into a work licensed as `project`.

    This models the common direction of travel — inbound code raising the
    obligations of the combined work — and deliberately returns `unknown`
    rather than guessing whenever either side is unclassified.
    """
    if not dependency or not project or "unknown" in (dependency, project):
        return Verdict("unknown", "one or both licences are unresolved")

    explicit = _KNOWN_INCOMPATIBLE.get((dependency, project))
    if explicit:
        return Verdict("incompatible", explicit)

    dep_class = reciprocity(catalogue_obj, dependency)
    project_class = reciprocity(catalogue_obj, project)
    if "unknown" in (dep_class, project_class):
        return Verdict(
            "unknown",
            f"no reciprocity classification for "
            f"`{dependency if dep_class == 'unknown' else project}`")

    if dep_class == "proprietary":
        return Verdict(
            "incompatible",
            f"`{dependency}` is not an open-source licence and cannot be "
            f"redistributed inside a `{project}` work")

    dep_rank = RECIPROCITY_ORDER.index(dep_class)
    project_rank = RECIPROCITY_ORDER.index(project_class)
    if dep_rank <= project_rank:
        return Verdict(
            "ok",
            f"`{dependency}` ({dep_class}) imposes no obligation beyond "
            f"`{project}` ({project_class})")
    return Verdict(
        "review",
        f"`{dependency}` is {dep_class} but this project is {project_class} — "
        f"distributing the combined work may require releasing it under "
        f"`{dependency}` terms")
