"""CLI companion to the BOS Code Scanning Kit composite Action.

Subcommands:
    version    Print the package version.
    detect     Walk the repo and print the ecosystem detection result.
    posture    Run the GitHub-side posture audit (GHAS toggles, branch
               protection, workflow permissions, CODEOWNERS).
    validate   Parse `.bos-scan.yml` and print the resolved config.
    sarif      Merge multiple SARIF files (and optionally inject a
               posture run) into one output file ready for GHAS upload.

The composite Action shells out to a subset of these subcommands so a
single Python file holds all kit logic — no Bash duplication, no
template drift between local dry-run and CI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from . import config as cfg_mod
from . import detect as detect_mod
from . import posture as posture_mod
from . import sarif as sarif_mod

# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bos-scan",
        description="Auto-detect ecosystems, audit repo posture, and emit SARIF "
                    "for the BOS Code Scanning Kit composite Action.",
    )
    parser.add_argument(
        "--version", action="version", version=f"bos-scan {__version__}",
    )

    sub = parser.add_subparsers(dest="cmd")
    sub.required = True

    # version
    sub.add_parser("version", help="Print the package version.")

    # detect
    p_det = sub.add_parser("detect", help="Walk the repo and print the ecosystem result.")
    p_det.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p_det.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of the human table.",
    )

    # validate
    p_val = sub.add_parser("validate", help="Parse `.bos-scan.yml` and print the config.")
    p_val.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p_val.add_argument(
        "--config", default="",
        help="Explicit config path (default: auto-discover under --root).",
    )

    # posture
    p_pos = sub.add_parser("posture", help="Run the GitHub posture audit.")
    p_pos.add_argument("--owner", required=True, help="GitHub repo owner.")
    p_pos.add_argument("--repo", required=True, help="GitHub repo name.")
    p_pos.add_argument(
        "--token", default="",
        help="GitHub token (defaults to $GITHUB_TOKEN).",
    )
    p_pos.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p_pos.add_argument("--config", default="", help="Explicit `.bos-scan.yml` path.")
    p_pos.add_argument(
        "--sarif", default="",
        help="If set, write a SARIF file with the posture findings.",
    )
    p_pos.add_argument(
        "--fail-on", choices=("never", "fail"),
        default="fail",
        help="`fail` (default) exits non-zero on any FAIL finding; `never` always exits 0.",
    )

    # sarif merge
    p_sar = sub.add_parser(
        "sarif",
        help="Merge SARIF files (and optionally a posture run) into one log.",
    )
    p_sar.add_argument(
        "--input", action="append", default=[],
        metavar="PATH",
        help="SARIF file to merge. May be repeated. Missing files are skipped.",
    )
    p_sar.add_argument(
        "--posture", default="",
        help="Optional posture-findings SARIF (the output of `posture --sarif`).",
    )
    p_sar.add_argument(
        "--output", required=True,
        help="Path to write the merged SARIF file.",
    )

    return parser


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    result = detect_mod.detect(root)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"Repository: {root}")
        print(f"Files scanned:    {result.files_scanned}")
        print(f"Languages:        {', '.join(result.languages) or '(none)'}")
        print(f"Artifact types:   {', '.join(result.artifact_types) or '(none)'}")
        print(f"Package managers: {', '.join(result.package_managers) or '(none)'}")
        if result.languages:
            print(f"CodeQL languages: {', '.join(result.codeql_languages()) or '(none mapped)'}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    cfg_path: Path | None = (
        Path(args.config).resolve() if args.config else cfg_mod.discover(root)
    )

    try:
        config = cfg_mod.load(cfg_path)
    except cfg_mod.ConfigError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if cfg_path is None:
        print("(no .bos-scan.yml found — using built-in defaults)")
    else:
        print(f"Loaded: {cfg_path}")

    print(f"owner:        {config.owner or '(unset)'}")
    print(f"project_name: {config.project_name or '(unset)'}")
    print(f"email:        {config.email or '(unset)'}")
    print(f"scan.tools:   {config.scan.tools}")
    print(f"scan.fail_on: {config.scan.fail_on}")
    print(f"branches:     {sorted(config.posture.branches.keys()) or '(none configured)'}")
    print(f"GHAS:         "
          f"cs={config.posture.ghas.require_code_scanning} "
          f"ss={config.posture.ghas.require_secret_scanning} "
          f"da={config.posture.ghas.require_dependabot_alerts}")
    return 0


def cmd_posture(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    cfg_path = Path(args.config).resolve() if args.config else cfg_mod.discover(root)
    try:
        config = cfg_mod.load(cfg_path)
    except cfg_mod.ConfigError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    token = (args.token or os.environ.get("GITHUB_TOKEN") or "").strip()

    try:
        result = posture_mod.audit(
            cfg=config,
            owner=args.owner,
            repo=args.repo,
            token=token,
            repo_root=root,
        )
    except posture_mod.GitHubError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    _print_posture_table(result)

    if args.sarif:
        run = sarif_mod.posture_run(list(result.findings))
        log = sarif_mod.merge({"runs": [run]})
        sarif_mod.dump(log, Path(args.sarif))
        sys.stderr.write(f"wrote posture SARIF: {args.sarif}\n")

    _write_step_summary(result)

    if args.fail_on == "never":
        return 0
    return 1 if result.failed or result.errored else 0


def cmd_sarif(args: argparse.Namespace) -> int:
    paths: list[Path] = []
    for raw in args.input:
        p = Path(raw)
        if not p.exists():
            sys.stderr.write(f"note: skipping missing SARIF input: {raw}\n")
            continue
        paths.append(p)

    logs: list[dict] = []
    for p in paths:
        try:
            logs.append(sarif_mod.load(p))
        except ValueError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 2

    if args.posture:
        p = Path(args.posture)
        if p.exists():
            try:
                logs.append(sarif_mod.load(p))
            except ValueError as exc:
                sys.stderr.write(f"error loading posture SARIF: {exc}\n")
                return 2

    merged = sarif_mod.merge(*logs)
    sarif_mod.dump(merged, Path(args.output))
    sys.stderr.write(
        f"wrote merged SARIF: {args.output} "
        f"({len(merged['runs'])} run(s), {len(logs)} input(s))\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_posture_table(result: posture_mod.AuditResult) -> None:
    if not result.findings:
        print("(posture audit produced no findings)")
        return

    width_id = max(len(f.rule_id) for f in result.findings)
    width_sev = max(len(f.severity) for f in result.findings)
    print(f"{'ID':<{width_id}}  {'SEV':<{width_sev}}  LOCATION / MESSAGE")
    for f in result.findings:
        loc = f"[{f.location}] " if f.location else ""
        print(f"{f.rule_id:<{width_id}}  {f.severity:<{width_sev}}  {loc}{f.message}")

    fails = len(result.failed)
    warns = len(result.warned)
    passes = len(result.passed)
    errors = len(result.errored)
    print(f"\nposture summary: {passes} pass, {warns} warn, {fails} fail, {errors} error")


def _write_step_summary(result: posture_mod.AuditResult) -> None:
    """Append a Markdown table to $GITHUB_STEP_SUMMARY when running in Actions."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines: list[str] = [
        "## BOS Code Scanning Kit — posture audit",
        "",
        "| Rule | Severity | Location | Message |",
        "| ---- | -------- | -------- | ------- |",
    ]
    for f in result.findings:
        lines.append(
            f"| `{f.rule_id}` | {f.severity} | "
            f"{_md_escape(f.location) or '—'} | {_md_escape(f.message)} |"
        )
    lines.append("")
    fails = len(result.failed)
    warns = len(result.warned)
    passes = len(result.passed)
    errors = len(result.errored)
    lines.append(f"**Summary:** {passes} pass, {warns} warn, {fails} fail, {errors} error.")
    try:
        with Path(summary_path).open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_DISPATCH = {
    "version":  cmd_version,
    "detect":   cmd_detect,
    "validate": cmd_validate,
    "posture":  cmd_posture,
    "sarif":    cmd_sarif,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _DISPATCH[args.cmd](args)


if __name__ == "__main__":                              # pragma: no cover
    raise SystemExit(main())
