# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## What this is

`bos-code-scanning-kit` is a composite GitHub Action (`runs.using: composite` in
[action.yml](action.yml)) backed by a stdlib-only Python package under [src/](src). One
Marketplace install detects which ecosystems a checked-out repo contains, runs bundled
third-party scanners (gitleaks for secrets, actionlint for workflow YAML, ShellCheck for
shell), audits GitHub-side security posture over the REST API, and merges everything into a
single SARIF 2.1.0 log uploaded to GitHub Advanced Security under one category. Artefacts,
all written into `GITHUB_WORKSPACE`: `bos-scan.sarif` (merged, the `sarif_output` input),
`bos-scan-posture.sarif`, `bos-scan-posture-skips.json` (the `pass`/`skip` findings SARIF
deliberately drops), `bos-scan-recommendations.json` (stable `finding_key` per non-pass
finding), a Markdown job summary, and five action outputs.

Verified consumers: this repo's [.github/workflows/self-scan.yml](.github/workflows/self-scan.yml)
runs the in-tree `uses: ./` composite on `ubuntu-latest` and `ubuntu-24.04-arm`, and
`blackoutsecure/bos-automation-hub` SHA-pins the published action in two reusables —
`bos-universal-security.yml` (category `bos-code-scanning-kit-gate`) and `security-scan.yml`
(category `bos-code-scanning-kit-launchpad`). Distinct categories stop two callers on one
commit from overwriting each other's upload.

Stack: Python `>=3.10` (the action installs 3.12 on the runner), hatchling backend, one runtime
dep (`PyYAML>=6.0`), dev extras `pytest>=8.0` and `ruff>=0.6`. `poetry.lock` pins `pytest 9.1.1`,
`ruff 0.16.2`, `pyyaml 6.0.3`. Scanner binaries download per run at actionlint `1.7.1`, gitleaks
`8.21.2`, ShellCheck `0.10.0`. Version `1.0.0`, mirrored in [src/\_version.py](src/_version.py).

## Commands

```bash
pip install -e ".[dev]"          # dev install
pytest -q                        # full suite: 111 tests
pytest test/test_sarif.py -q     # one file
pytest test/test_sarif.py::test_empty_log_shape -q   # one test
ruff check .                     # lint; this is what CI runs, currently clean

bos-scan detect --root . --json          # ecosystem detection
bos-scan validate --root .               # resolve + print the config cascade
bos-scan validate --root . --no-marketplace-config

export GITHUB_TOKEN=<token>
bos-scan posture --owner blackoutsecure --repo bos-code-scanning-kit --root . \
  --sarif posture.sarif --skips-json skips.json \
  --recommendations-json recs.json --fail-on never --http-timeout 20

bos-scan sarif --input posture.sarif --output bos-scan.sarif

python3 scripts/check_action_sync.py             # action.yml <-> pyproject.toml drift
python3 scripts/render_readme_inputs.py --check  # README tables vs action.yml
python3 scripts/render_readme_inputs.py --write  # regenerate them
```

`pyproject.toml` sets `pythonpath = ["src"]` and `testpaths = ["test"]`, so the suite runs
without an editable install. Do not run `ruff format`: the repo is not formatted to its output
(20 files would be reformatted), and formatting is not gated — `ruff check` is.

## Validating changes

CI has three surfaces. `self-scan.yml` is the dogfood: `uses: ./` on the current branch with
`fail_on: never`, matrixed over x64 and arm64 so the `RUNNER_ARCH` branching in the scanner
downloads is exercised. [.github/workflows/codeql.yml](.github/workflows/codeql.yml) calls the
hub's `security-scan.yml@main` with `enable_kit_composite: false` (this repo _is_ the kit) and
`codeql_languages: '["python", "actions"]'`. The hub's `bos-universal-security.yml` runs the org
gate below, including `ruff check .` and `pytest -q`. Narrowest first, before work is done:
`pytest test/test_<module>.py -q` for the module you touched, then `ruff check .`, then the full
`pytest -q`. Add `python3 scripts/check_action_sync.py` if `action.yml` or `pyproject.toml`
changed, and `bos-scan detect --root .` plus `bos-scan validate --root .` if
[src/detect.py](src/detect.py) or [src/config.py](src/config.py) changed — those two run the
real cascade against this repo's own `.github/bos-universal-config.json`.

The tests prove config merge precedence, enum validation, detection, SARIF merge and
sanitization, posture rule logic against mocked HTTP, licence classification, and provider
selection. They do not prove that the composite's bash steps work, that scanner binaries
download and parse on a real runner, that GHAS accepts the merged SARIF, or that live REST
responses match the mocks. Only `self-scan.yml` covers those, and only on push or dispatch.
Note that `render_readme_inputs.py --check` currently exits 1 because the committed tables
are column-aligned while the generator emits compact rows; `--write` reflows the whole
block, so treat that as a deliberate change rather than incidental cleanup.

## Architecture

```text
action.yml                      Composite action: 8 steps, the whole orchestration
pyproject.toml                  hatchling build, ruff + pytest config, bos-scan entrypoint
poetry.lock                     Pinned dev toolchain
src/cli.py                      argparse front end; version/detect/validate/posture/sarif
src/config.py                   Frozen dataclass schema, deep-merge cascade, ConfigError
src/detect.py                   One stdlib tree walk -> languages, package managers, artifacts
src/posture.py                  Finding/AuditResult, REST client, every PS/LD/LF probe
src/sarif.py                    SARIF 2.1.0 merge, location sanitization, posture_run emitter
src/licensing.py                LD### (dependency SBOM) and LF### (working tree) engines
src/ai.py                       Optional OpenAI-compatible summariser; None on any failure
src/metadata.py                 Package identity, independent of policy config
src/marketplace-config.json     Bundled tier-1 baseline config
src/osi_catalogue.py            Hub-owned, managed-file-sync'd licence resolver
src/osi-licenses.json           Hub-owned, managed-file-sync'd OSI snapshot (paired above)
scripts/check_action_sync.py    action.yml <-> pyproject.toml drift guard
scripts/render_readme_inputs.py README input/output table generator
test/conftest.py                Adds src/ to sys.path; strips GITHUB_STEP_SUMMARY/OUTPUT/ENV
.github/actions/repo-metadata/  Local composite for post-release About-box sync
.github/bos-universal-config.json  Repo-owned gate, marketplace, code_scanning overrides
```

Flow: step 0 sets up Python 3.12 and `pip install "${GITHUB_ACTION_PATH}"`. Step 1 runs
`bos-scan detect --json` and publishes `quality_applicability`. Step 2 runs `bos-scan posture`,
which resolves config before any probe. Steps 3a/3b/3c run actionlint (gated on
`hashFiles('.github/workflows/*.yml', ...)`), gitleaks (unconditional), and ShellCheck (gated
on `hashFiles('**/*.sh', '**/*.bash')`), each guaranteed to leave a valid SARIF behind even on
failure. Step 4 merges, step 5 uploads via `github/codeql-action/upload-sarif`, step 6 computes
`outcome` and writes the job summary, step 7 is the only step that hard-fails.

Config precedence in `config.load()`: bundled `src/marketplace-config.json` (skippable via
`use_marketplace_config: false`), then the optional org file
`.github/blackout-secure-code-scanning-kit-global-config.yml` (tri-state `auto`/`true`/`false`),
then the repository file discovered in `DEFAULT_CONFIG_PATHS` order —
`.github/bos-universal-config.json` first, legacy `.bos-scan.yml` last. Mappings deep-merge;
scalars and lists replace. Each tier reads the `code_scanning` section (a flat legacy
`.bos-scan.yml` needs no wrapper), unknown keys are ignored so sibling kits can share one
universal config, and `Config.source_paths` records applied tiers in order.

Rule IDs: `PS000` is reserved for tooling errors and is always `error`. `PS001`-`PS004` GHAS
toggles, `PS010`-`PS013` workflow hygiene (`PS012` = SHA-pinned `uses:`), `PS020`-`PS025`
branch protection, `PS030`-`PS033` CODEOWNERS. `LD001`-`LD005` read the dependency-graph SBOM;
`LF001`-`LF004` read licence headers off disk. Scanner findings keep their upstream namespace:
`SC####` for ShellCheck, plus actionlint's and gitleaks' own IDs. To add a check: extend the
relevant frozen dataclass in `config.py` with a severity field and wire it into the matching
`_*_from_dict` parser; add a `_scan_*` or `_audit_*` returning `list[Finding]` in `posture.py`
and call it from `audit()`; add help text to `_rule_help` in `sarif.py` and defaults to
`_default_finding_title` / `_default_finding_remediation`; document it in the README rule
table; add tests. Local-only checks run before the API client is built so they still produce
output when the token is bad.

Action contract. Inputs: `owner`, `repo`, `use_global_config` (`auto`), `global_config_path`,
`use_marketplace_config` (`true`), `config`, `github_token`, `enable_posture` (`true`),
`enable_scanners` (`true`), `enable_upload` (`true`), `category` (`bos-code-scanning-kit`),
`fail_on` (`fail`), `http_timeout` (`20`), `sarif_output` (`bos-scan.sarif`). Outputs:
`quality_applicability`, `sarif_path`, `posture_failures`, `recommendations_path`, `outcome`.
`outcome` is severity-only (`success`/`warn`/`failure`) and never varies with `fail_on`, so
callers gate independently of the step's exit code. `github_token` defaults to empty because
action-manifest scalars cannot carry GitHub expressions; `github.token` is applied at step level.

## Conventions

Modules are flat and single-purpose, importing each other as top-level names (`import config
as cfg_mod`) — there is no package directory, and hatchling ships `src/` via `sources = ["src"]`.
Everything uses `from __future__ import annotations` and modern typing. Config objects and
`Finding` are frozen dataclasses; `Finding` repairs its own defaults in `__post_init__`.
Comments explain why a non-obvious choice exists; the long block comments in `action.yml` and
the workflows are load-bearing history, so do not strip them. Probes take a config slice,
return `list[Finding]`, and emit a `pass` finding on success rather than staying silent:

```python
        # PS011 — no `permissions: write-all` (at top level or job level).
        if cfg.forbid_write_all != "skip":
            if WRITE_ALL.search(text) or JOB_WRITE_ALL.search(text):
                out.append(Finding(
                    "PS011",
                    cfg.forbid_write_all,
                    "`permissions: write-all` grants every scope — replace with explicit minimum",
                    location=rel,
                ))
            else:
                out.append(Finding("PS011", "pass",
                                   "no `permissions: write-all` found", location=rel))
```

Config severities are `fail`, `warn`, `skip`; findings add `pass` and `error`. `skip` means the
audit could not reach a verdict, usually a token-scope limit, and must never read as a pass.
Defaults are conservative — anything that could break a consumer defaults to `warn`. `sarif.py`
maps `fail`->`error`, `warn`->`warning`, `pass`/`skip`->`none`, drops `pass`/`skip` from the
upload, and forces every result to carry a `physicalLocation` (falling back to a `.github/`
sentinel) because GHAS rejects logical-only locations. `ConfigError` and `GitHubError` are
raised in library code and converted to a stderr line plus exit `2` in the `cmd_*` functions;
exit `1` means findings (`result.failed or result.errored`, suppressed by `--fail-on never`)
and `0` is clean. Inside the composite, posture and scanner failures are deferred — steps use
`|| true` or record `exit_code` as a step output — so upload and the summary always run and
only "Enforce failure policy" exits non-zero. Logging is plain `print` with an ANSI palette
honouring `NO_COLOR` and `GITHUB_ACTIONS`; `ai.py` returns `None` on any exception rather
than raising.

## Blackout Secure conventions

These apply to every repository in the `blackoutsecure` organization.

### Branch model

- `dev` is the default branch and where all work lands.
- `main` is the promoted stable runtime that consumers reference through `@main`.
- Version tags (`vX.Y.Z` and a floating `vX`) point at promoted runtime commits.
- Promotion is driven from `bos-automation-hub` (`release-promote.yml`). Do not push
  directly to `main` and do not move tags by hand.

### Centrally managed files - do not hand-edit here

`blackoutsecure/bos-automation-hub` distributes these through
`bos-managed-file-sync-action`. Change the source under the hub's `sync-files/`, never the
copy in this repository:

- `LICENSE`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`
- `.github/FUNDING.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/`
- `.github/workflows/bos-universal-gatekeeper-kicker.yml`
- the `# >>> managed-file-sync:<service> >>> ... # <<< managed-file-sync:<service> <<<`
  delimited blocks inside `.editorconfig`, `.markdownlint.yaml`, `.shellcheckrc`,
  `.yamllint.yml`, `.gitignore`, and `README.md`

`.github/bos-universal-config.json` is repo-owned. It holds this repository's overrides on
top of the hub's global config and is the right place to change gate behaviour.

### CI gate

Pushes and pull requests run the hub's reusable `bos-universal-security.yml`, reported as a
single required check. It runs markdownlint, yamllint, shellcheck, and actionlint; ESLint,
Prettier, Ruff, pytest, and Bats where the repository has them; `bos-code-scanning-kit`
(secret scan, SAST, GHAS posture) and CodeQL; dependency review; and compliance checks for
the canonical README header and a conventional-commit PR title
(`feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert: subject`).

Every `uses:` reference in a workflow must be a commit SHA with a trailing version comment,
for example `actions/checkout@<sha> # v4.2.2`.

This repository additionally syncs `license_catalogue_service`, which owns
`src/osi-licenses.json` and `src/osi_catalogue.py` as a versioned pair generated by the hub's
`scripts/build_osi_catalogue.py`. Edit them there, and never separately.

## Boundaries

### Always

- Keep the Python core stdlib-only apart from `PyYAML`, and keep SARIF emission deterministic.
- Add or update tests under `test/` for any `src/` change, then run `ruff check .` and `pytest -q`.
- Default new posture rules to `warn`; make anything that could break a consumer opt-in.
- Emit `pass` on success and reserve `skip` for genuinely indeterminate probes.
- After editing `action.yml`, run `scripts/render_readme_inputs.py --write` and
  `scripts/check_action_sync.py`.
- Pin any new scanner to an explicit version and branch on `RUNNER_ARCH`.

### Ask first

- Changing an `action.yml` input or output name, default, or semantics — the hub pins this
  action in two reusables, so it is a breaking change for every consuming repo.
- Changing the `outcome` tiers, the `fail_on` contract, or the deferred-failure step ordering.
- Changing the SARIF `category`, the `finding_key` derivation, or the
  `bos-scan-recommendations.json` shape that consumers deduplicate on.
- Adding a runtime Python dependency, a new external tool, or a new network call.
- Renaming or renumbering an existing `PS###`, `LD###`, or `LF###` rule, or bumping the pinned
  actionlint, gitleaks, or ShellCheck versions.

### Never

- Never weaken or disable a security check to make a build pass. Do not lower a severity, add
  a `ruff` ignore, widen `allow_tag_pin`, or set `fail_on: never` to get green.
- Never commit secrets or real scan output containing secrets — no `bos-scan*.sarif`, gitleaks
  reports, tokens, or App private keys.
- Never hand-edit managed files, including `src/osi-licenses.json`, `src/osi_catalogue.py`, and
  `.github/workflows/bos-universal-gatekeeper-kicker.yml`.
- Never use an unpinned `uses:` ref. Every reference is a 40-character SHA with a trailing
  version comment — this repo's own `PS012` rule applied to itself.
- Never push to `main` or move a version tag by hand; promotion runs from the hub.
- Never auto-apply patches from recommendation prose (`patch_status` stays `unavailable`), and
  never let a posture `skip` be reported or treated as a `pass`.
