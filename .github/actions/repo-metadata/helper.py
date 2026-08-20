"""Helper functions for the `repo-metadata` composite action.

Lives inside the composite directory so consumers who `uses:` the
action get it for free (no `pip install`), matching the
`branch-protection/_bp.py` pattern.

Three CLI subcommands wrap the pure functions below:

  * ``extract-readme`` — pull a single prose summary from a README
    for use as deterministic description fallback OR as AI input.
  * ``clamp-description`` — read stdin, normalize whitespace, clamp
    to N chars at a word boundary.
  * ``sanitize-topics`` — split a free-form list and reduce it to
    GitHub's topic rules (lowercase, [a-z0-9-], ≤50 chars per topic,
    ≤N total, deduplicated).

The pure functions are exposed for direct import by the test suite.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path

# GitHub repo topic rules:
#   * lowercase only
#   * a-z, 0-9, hyphen
#   * must start with letter or digit (no leading hyphen)
#   * max 50 chars
#   * max 20 topics per repo
TOPIC_MAX_LEN = 50
TOPIC_MAX_COUNT = 20
TOPIC_INVALID_RE = re.compile(r"[^a-z0-9-]+")
TOPIC_COLLAPSE_RE = re.compile(r"-+")
UNICODE_ESCAPE_RE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))")
MARKDOWN_IMAGE_RE = re.compile(r"!\[([^]]*)\]\([^)]+\)")
MARKDOWN_LINK_RE = re.compile(r"\[([^]]+)\]\([^)]+\)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
GITHUB_EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}")
VARIABLE_REFERENCE_RE = re.compile(
    r"(?i)\b(?:secrets|vars|github|inputs|env|steps|needs|matrix)\.[a-z_][a-z0-9_.-]*\b"
)
SHELL_VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
DESCRIPTION_PUNCTUATION = str.maketrans({
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "-",
    "\u2014": "-",
    "\u2026": "...",
    "\u2192": " - ",
})


def extract_readme_summary(text: str, max_len: int = 1500) -> str:
    """Return the first piece of prose from a README, suitable as a
    description seed.

    Strategy (in order, first hit wins):
      1. The first top-level blockquote (``> ...``) that follows the
         H1 and is not part of a multi-paragraph quote. README
         convention puts a tagline here.
      2. The first non-empty paragraph that is plain prose — i.e.
         not a heading, not a badge/image line, not a fenced code
         block, not a list, not a table, not an HTML block.

    The returned string is whitespace-normalized (single spaces, no
    newlines) and clamped to ``max_len`` chars at a word boundary so
    very long paragraphs do not blow the AI prompt budget. This is
    a *seed* for AI rewriting, not the final description — the final
    clamp happens in ``clamp_description``.
    """
    lines = text.splitlines()
    paragraphs: list[list[str]] = []
    current: list[str] = []
    in_fence = False

    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            # Toggle code fence; treat fenced content as paragraph break.
            if current:
                paragraphs.append(current)
                current = []
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not stripped:
            if current:
                paragraphs.append(current)
                current = []
            continue
        current.append(stripped)
    if current:
        paragraphs.append(current)

    def is_badge_or_image(line: str) -> bool:
        # Markdown image, badge link, or HTML img tag.
        return bool(
            re.match(r"^\[!\[.+?\]\(.+?\)\]\(.+?\)", line)
            or re.match(r"^!\[.+?\]\(.+?\)", line)
            or re.match(r"^<img\s", line, re.IGNORECASE)
            or re.match(r"^<p\s", line, re.IGNORECASE)
        )

    def is_heading(line: str) -> bool:
        return bool(re.match(r"^#{1,6}\s", line))

    def is_list_or_table(line: str) -> bool:
        return bool(
            re.match(r"^[-*+]\s", line)
            or re.match(r"^\d+\.\s", line)
            or re.match(r"^\|", line)
        )

    def is_html_block(line: str) -> bool:
        return bool(re.match(r"^</?[a-z][a-z0-9-]*[\s>]", line, re.IGNORECASE))

    def is_blockquote(line: str) -> bool:
        return line.startswith(">")

    def is_legal_notice(value: str) -> bool:
        return bool(
            re.search(
                r"(?i)\bcopyright\b|\blicen[cs]e\b|\ball rights reserved\b",
                value,
            )
        )

    def all_lines_are(p: list[str], pred) -> bool:
        return all(pred(line) for line in p)

    def is_description_candidate(value: str) -> bool:
        return not any(
            pattern.search(value)
            for pattern in (
                INLINE_CODE_RE,
                GITHUB_EXPRESSION_RE,
                VARIABLE_REFERENCE_RE,
                SHELL_VARIABLE_RE,
            )
        )

    # Pass 1: prefer the first standalone blockquote tagline.
    for para in paragraphs:
        if all_lines_are(para, is_blockquote):
            joined = " ".join(line.lstrip("> ").strip() for line in para)
            joined = re.sub(r"\s+", " ", joined).strip()
            if (
                joined
                and not is_legal_notice(joined)
                and is_description_candidate(joined)
            ):
                return _clip_words(joined, max_len)

    # Pass 2: first plain-prose paragraph.
    for para in paragraphs:
        if any(is_heading(line) for line in para):
            continue
        if all_lines_are(para, is_badge_or_image):
            continue
        if all_lines_are(
            para, lambda line: is_list_or_table(line) or is_html_block(line)
        ):
            continue
        # Strip lingering inline badge/image lines from the head of
        # the paragraph but keep prose lines.
        prose_lines = [
            line for line in para
            if not (is_badge_or_image(line) or is_html_block(line) or is_list_or_table(line))
        ]
        if not prose_lines:
            continue
        joined = " ".join(prose_lines)
        joined = re.sub(r"\s+", " ", joined).strip()
        if (
            joined
            and not is_legal_notice(joined)
            and is_description_candidate(joined)
        ):
            return _clip_words(joined, max_len)

    return ""


def clamp_description(text: str, max_len: int) -> str:
    """Normalize whitespace and clamp ``text`` to ``max_len`` chars
    at a word boundary as ASCII-only plain text.

    If the input fits, returns the normalized text unchanged. If
    truncation is needed, walks back to the previous space so the
    output does not end mid-word, then appends ``...`` (three ASCII
    characters — keeps the total <= ``max_len``).
    """
    if max_len <= 0:
        raise ValueError("max_len must be > 0")
    decoded = UNICODE_ESCAPE_RE.sub(
        lambda match: chr(int(match.group(1) or match.group(2), 16)), text
    )
    plain_text = MARKDOWN_IMAGE_RE.sub(r"\1", decoded)
    plain_text = MARKDOWN_LINK_RE.sub(r"\1", plain_text)
    plain_text = INLINE_CODE_RE.sub("", plain_text)
    plain_text = GITHUB_EXPRESSION_RE.sub("", plain_text)
    plain_text = VARIABLE_REFERENCE_RE.sub("", plain_text)
    plain_text = SHELL_VARIABLE_RE.sub("", plain_text)
    plain_text = plain_text.replace("**", "").replace("__", "")
    plain_text = plain_text.replace("~~", "").replace("`", "")
    s = unicodedata.normalize(
        "NFKD", plain_text.translate(DESCRIPTION_PUNCTUATION)
    )
    s = s.encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= max_len:
        return s
    if max_len < 4:
        return s[:max_len]
    # Reserve 3 characters for the ASCII ellipsis.
    cut = s[: max_len - 3]
    last_space = cut.rfind(" ")
    if last_space > max_len * 0.5:
        cut = cut[:last_space]
    return cut.rstrip(" ,.;:-") + "..."


def _clip_words(text: str, max_len: int) -> str:
    """Internal: word-aware clip with NO ellipsis. Used for the AI
    prompt seed so the model gets clean trailing text."""
    if len(text) <= max_len:
        return text
    cut = text[:max_len]
    last_space = cut.rfind(" ")
    if last_space > max_len * 0.5:
        cut = cut[:last_space]
    return cut.rstrip(" ,.;:-")


def sanitize_topics(raw: str, max_count: int = TOPIC_MAX_COUNT) -> list[str]:
    """Parse ``raw`` (free-form, space/comma/newline separated) into
    a deduplicated list of GitHub-valid topics.

    Each token is:
      * lowercased
      * stripped of any character outside ``[a-z0-9-]`` (replaced
        with ``-``)
      * collapsed (runs of ``-`` reduced to a single ``-``)
      * stripped of leading/trailing ``-``
      * clipped to 50 chars
      * dropped if empty or already in the list

    The final list is truncated to ``max_count``. ``max_count`` is
    itself clamped to the GitHub ceiling (20).
    """
    cap = min(max(max_count, 0), TOPIC_MAX_COUNT)
    if cap == 0:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[\s,]+", raw):
        if not token:
            continue
        norm = TOPIC_INVALID_RE.sub("-", token.lower())
        norm = TOPIC_COLLAPSE_RE.sub("-", norm).strip("-")
        if not norm:
            continue
        norm = norm[:TOPIC_MAX_LEN].rstrip("-")
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
        if len(out) >= cap:
            break
    return out


def _cmd_extract_readme(args: argparse.Namespace) -> int:
    text = Path(args.path).read_text(encoding="utf-8", errors="replace")
    summary = extract_readme_summary(text, max_len=args.max_len)
    sys.stdout.write(summary)
    return 0


def _cmd_clamp_description(args: argparse.Namespace) -> int:
    raw = sys.stdin.read()
    sys.stdout.write(clamp_description(raw, max_len=args.max_len))
    return 0


def _cmd_sanitize_topics(args: argparse.Namespace) -> int:
    raw = sys.stdin.read() if args.stdin else args.value
    if raw is None:
        raw = ""
    topics = sanitize_topics(raw, max_count=args.max_count)
    sys.stdout.write(" ".join(topics))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="repo-metadata composite action helper"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ex = sub.add_parser("extract-readme", help="extract README summary")
    p_ex.add_argument("path")
    p_ex.add_argument("--max-len", type=int, default=1500)
    p_ex.set_defaults(func=_cmd_extract_readme)

    p_cl = sub.add_parser("clamp-description", help="clamp stdin to N chars")
    p_cl.add_argument("--max-len", type=int, required=True)
    p_cl.set_defaults(func=_cmd_clamp_description)

    p_sa = sub.add_parser("sanitize-topics", help="normalize free-form topic list")
    p_sa.add_argument("--max-count", type=int, default=TOPIC_MAX_COUNT)
    src = p_sa.add_mutually_exclusive_group()
    src.add_argument("--stdin", action="store_true")
    src.add_argument("--value", default="")
    p_sa.set_defaults(func=_cmd_sanitize_topics)

    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover - thin shim
    raise SystemExit(main())
