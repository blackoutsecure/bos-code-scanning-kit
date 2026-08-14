# Blackout Secure Code Scanning Kit

**Copyright © 2025-2026 Blackout Secure | Apache License 2.0**

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/blackout-secure-code-scanning-kit)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-code-scanning-kit)](https://github.com/blackoutsecure/bos-code-scanning-kit/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Made by BlackoutSecure](https://img.shields.io/badge/made%20by-BlackoutSecure-1f1f1f)](https://github.com/blackoutsecure)

A drop-in composite GitHub Action that **detects what's in your repo →
runs the right scanners → audits repo posture → uploads one unified
SARIF to GitHub Advanced Security**.

Everything in one Marketplace install: secret scanning, workflow
linting, shell linting, and a posture auditor that checks the
Advanced Security toggles, workflow permissions, branch protection,
required reviews, and CODEOWNERS for every branch you care about.

## ✨ Features

- **Posture audit** — 30+ rules (`PS001`–`PS033`) covering GHAS toggles,
  workflow `permissions:` blocks, branch protection, required reviews,
  signed commits, status checks, conversation resolution, force-push
  restrictions, and CODEOWNERS ownership coverage. Per-rule severity
  is configurable.
- **Bundled scanners (v1.0)** — [actionlint] for workflow YAML,
  [gitleaks] for secrets across the working tree, and [shellcheck]
  for `*.sh` / `*.bash`. Each runs conditionally based on what
  ecosystems are detected.
- **Ecosystem detection** — walks the working tree and surfaces what's
  present: Python / JavaScript / TypeScript / Go / Java / C# / Ruby /
  Rust / shell, plus Dockerfiles, Compose files, GitHub workflows,
  Terraform, Kubernetes manifests, and package-manager lockfiles.
- **Unified SARIF upload** — every scanner's findings and every posture
  finding land in a single SARIF that is uploaded to GitHub Advanced
  Security under one category (`bos-code-scanning-kit`), so they all
  appear on the repo Security tab.
- **Layered config** — bundled Marketplace best practices are
  deep-merged with optional organization defaults and repository
  overrides. Legacy `.bos-scan.yml` files continue to work.
- **Pure-stdlib Python core** — no third-party Python deps beyond
  `PyYAML`. The composite Action installs the kit on the runner with a
  single `pip install`.

[actionlint]: https://github.com/rhysd/actionlint
[gitleaks]:   https://github.com/gitleaks/gitleaks
[shellcheck]: https://www.shellcheck.net

## 📖 Table of Contents

- [✨ Features](#-features)
- [📋 Prerequisites](#-prerequisites)
- [🚀 Quick start](#-quick-start)
- [⚙️ Action inputs](#%EF%B8%8F-action-inputs)
- [📤 Action outputs](#-action-outputs)
- [🏗️ Configuration inheritance and layering](#%EF%B8%8F-configuration-inheritance-and-layering)
- [📝 Config schema reference](#-config-schema-reference)
- [🔒 SCANNING_PAT — advanced posture credentials walkthrough](#-scanning_pat--advanced-posture-credentials-walkthrough)
- [🧪 Supported code scanning](#-supported-code-scanning)
- [💻 Local usage (CLI)](#-local-usage-cli)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

## 📋 Prerequisites

- GitHub-hosted Linux runner (`ubuntu-latest` or newer) — the kit
  installs `python` via `actions/setup-python@v5` automatically.
- For the **posture audit**: a token with `repo` scope. The default
  `${{ secrets.GITHUB_TOKEN }}` is enough for the code-scanning probe
  (`PS001`). Secret-scanning (`PS002`), Dependabot (`PS003`), and
  branch-protection probes (`PS020`-`PS025`) require a PAT — see
  [🔒 SCANNING_PAT — advanced posture credentials walkthrough](#-scanning_pat--advanced-posture-credentials-walkthrough)
  for the full tick / don't-tick checklist (classic and fine-grained).
- For the **SARIF upload**: `security-events: write` in your workflow
  `permissions:` block.

## 🚀 Quick start

```yaml
name: Code scanning

on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main, dev]
  schedule:
    - cron: '17 4 * * 1'   # weekly Monday 04:17 UTC

permissions:
  contents:        read
  security-events: write   # upload SARIF
  actions:         read    # workflow context

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: blackoutsecure/bos-code-scanning-kit@v1
        with:
          # Prefer SCANNING_PAT when the org/repo has set it (unlocks
          # PS002 / PS003 / PS020-PS025); otherwise fall back to the
          # workflow's built-in GITHUB_TOKEN (PS001 only — the other
          # posture rules emit `skip` rows). See § 'SCANNING_PAT —
          # advanced posture credentials' below for the PAT recipe.
          github_token: ${{ secrets.SCANNING_PAT || secrets.GITHUB_TOKEN }}
```

That's it. The kit auto-discovers your ecosystem, optional global and
repository config files, runs every applicable scanner, audits posture,
and uploads a single SARIF.

> The `secrets.SCANNING_PAT || secrets.GITHUB_TOKEN` form is safe to
> ship before you've created the PAT — when the secret is unset, the
> expression evaluates to `secrets.GITHUB_TOKEN` and the kit runs in
> baseline mode (PS001 only). Adding `SCANNING_PAT` at the org/repo
> level later upgrades every consuming workflow automatically with no
> code changes.

### Version pinning

Pick a `uses:` ref shape based on how strict your supply-chain posture
needs to be. All three forms are supported equally.

| Form | Example | When to use |
| ---- | ------- | ----------- |
| **Floating major (default)** | `blackoutsecure/bos-code-scanning-kit@v1` | Friendly default. Auto-tracks every v1.x.y patch + minor release as we ship bug fixes and new rules. Recommended for most callers. |
| **Immutable tag** | `blackoutsecure/bos-code-scanning-kit@v1.0.0` | Pin to a specific release. Predictable scan results across runs; requires manual bumps for new fixes. Recommended when failed scans break critical pipelines. |
| **SHA-pinned** | `blackoutsecure/bos-code-scanning-kit@<40-char-sha> # v1.0.0` | Strictest. Survives even a malicious tag-move on the kit repo (the [tj-actions/changed-files class of supply-chain attack][supply-chain-class]). Recommended for regulated / high-security callers. Use Dependabot's `package-ecosystem: github-actions` to keep the pin current. |

[supply-chain-class]: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-077a

The SHA for any tag is `git rev-list -n 1 v1.0.0` against this repo, or
the `commit` field of the GitHub Release JSON.

## ⚙️ Action inputs

<!-- BEGIN action-inputs -->
| Input | Default | Description |
| --- | --- | --- |
| `owner` | _(none)_ | GitHub owner of the repo being scanned. Defaults to the workflow context. |
| `repo` | _(none)_ | GitHub repo name being scanned. Defaults to the workflow context. |
| `use_global_config` | `auto` | `auto` loads the organization-level global config when present. `true` requires it; `false` disables it. |
| `global_config_path` | `.github/blackout-secure-code-scanning-kit-global-config.yml` | Organization-level config path. Loaded automatically when present, after marketplace defaults and before the repository config. |
| `config` | _(none)_ | Repository config path. Defaults to `.github/bos-universal-config.json`, `.github/bos-universal-config.yml`, then legacy `.bos-scan.yml` discovery. |
| `github_token` | _(none)_ | GitHub token for the posture audit. Leave blank to use the workflow's built-in GITHUB_TOKEN for baseline checks. For full posture coverage, create a `SCANNING_PAT` secret and pass it here with `github_token: ${{ secrets.SCANNING_PAT \|\| secrets.GITHUB_TOKEN }}`. The PAT lets the kit verify admin-gated controls such as secret scanning, Dependabot alerts, and branch protection instead of reporting them as skipped. Walkthrough: https://github.com/blackoutsecure/bos-code-scanning-kit#scanning_pat--advanced-posture-credentials-walkthrough |
| `enable_posture` | `true` | `true` to run the posture audit step. |
| `enable_scanners` | `true` | `true` to run the bundled scanners (actionlint / gitleaks / shellcheck). |
| `enable_upload` | `true` | `true` to upload the merged SARIF to GitHub Advanced Security. |
| `fail_on` | `fail` | `fail` (default) — exit non-zero if posture has any FAIL findings or any scanner reports a result. `never` — collect findings but always exit 0 (useful for first-time rollouts). |
| `http_timeout` | `20` | Per-request HTTP timeout (seconds) for the posture audit's GitHub REST calls. Default `20`. Each probe is independent, so the practical upper bound on a posture run is roughly `http_timeout` * number-of-probes (~10 on a baseline scan). Bump on self-hosted runners with slow egress, or to ride out brief GitHub API latency spikes that otherwise surface as `PS*** error: HTTP 502` rows. Bare integer string; no unit. |
| `sarif_output` | `bos-scan.sarif` | Path for the merged SARIF artefact. |
<!-- END action-inputs -->

> The table above is auto-generated from `action.yml` by
> [`scripts/render_readme_inputs.py`](scripts/render_readme_inputs.py).
> Edit `action.yml` and run `python3 scripts/render_readme_inputs.py --write`.

## 📤 Action outputs

<!-- BEGIN action-outputs -->
| Output | Description |
| --- | --- |
| `sarif_path` | Path to the merged SARIF file produced by the run. |
| `posture_failures` | Number of FAIL findings from the posture audit. |
| `outcome` | Severity-tier verdict for the run: `success` (no findings at any level), `warn` (only warning/note-level findings — nothing the enforcement policy would block on), or `failure` (at least one error-level finding from the posture audit or any scanner). Reflects severity only — it does NOT change based on `fail_on`, so callers can gate pipelines on the verdict independently of whether the kit step itself exited non-zero. |
<!-- END action-outputs -->

## 🔒 SCANNING_PAT — advanced posture credentials walkthrough

The posture audit can run in two modes:

- `secrets.GITHUB_TOKEN` gives baseline visibility. It can confirm the
  code-scanning surface, but GitHub blocks several admin-level posture
  checks from that token.
- `secrets.SCANNING_PAT` gives full posture coverage when you grant the
  required repository access and pass it through the action input.

Use this caller pattern in the workflow that runs the kit:

```yaml
with:
  github_token: ${{ secrets.SCANNING_PAT || secrets.GITHUB_TOKEN }}
```

With only `GITHUB_TOKEN`, checks that require admin-level visibility
(for example secret scanning, Dependabot alerts, and branch protection)
may appear as `skip` / `Not Assessed` rows. That means the kit could not
collect enough evidence for a real verdict. Adding `SCANNING_PAT`
upgrades those rows to real `pass`, `warn`, or `fail` evaluations.

Walkthrough:

1. Create a PAT for the repositories you want to audit.
2. Preferred: use a fine-grained PAT scoped only to the selected repos.
3. Grant the PAT read access for repository metadata plus the security
   and administration surfaces needed by posture checks.
4. Fallback: use a classic PAT with `repo` scope.
5. Store the token as an Actions secret named `SCANNING_PAT` at the org
   or repository level.
6. Pass the token with `github_token: ${{ secrets.SCANNING_PAT || secrets.GITHUB_TOKEN }}`.
7. Re-run the workflow and confirm previously skipped rows now show
   `pass`, `warn`, or `fail`.

## Posture rule reference

Severities can be overridden per rule in any global or repository config tier.

| Rule  | Default | What it checks                                                                                          |
| ----- | ------- | ------------------------------------------------------------------------------------------------------- |
| PS001 | warn    | GitHub code scanning is enabled via **either** Default setup **or** an Advanced workflow uploading CodeQL analyses. |
| PS002 | warn    | GitHub secret scanning is enabled (probed via the secret-scanning alerts API).                          |
| PS003 | warn    | Dependabot vulnerability alerts are enabled.                                                            |
| PS004 | warn    | Secret-scanning **push protection** is enabled (refuses pushes that contain detected secrets; toggles independently of PS002). |
| PS010 | warn    | Every workflow file declares an explicit top-level `permissions:` block.                                |
| PS011 | warn    | No workflow uses `permissions: write-all` at the workflow or job level.                                 |
| PS012 | warn    | Every third-party `uses:` reference (in `.github/workflows/` and `.github/actions/`) is pinned to a 40-char commit SHA. Local (`./`) and `docker://` refs are exempt; trusted `owner/repo` entries can be added to `allow_tag_pin`. |
| PS020 | warn    | The branch has _some_ branch-protection rule configured.                                                |
| PS021 | warn    | The branch requires at least N approving reviews (per-branch override).                                 |
| PS022 | warn    | The branch restricts force pushes (`allow_force_pushes.enabled = false`).                               |
| PS023 | warn    | The branch requires status checks to pass before merge.                                                 |
| PS024 | warn    | The branch requires signed commits.                                                                     |
| PS025 | warn    | The branch requires conversation resolution before merge.                                               |
| PS030 | warn    | A `CODEOWNERS` file is present (root, `.github/`, or `docs/`).                                          |
| PS031 | warn    | Every non-comment `CODEOWNERS` line references at least one owner (`@user` or `@org/team`).             |
| PS032 | warn    | _(opt-in)_ Every `@org/team` referenced in `CODEOWNERS` exists. Requires `validate_users_exist: true`.  |
| PS033 | warn    | _(opt-in)_ Every `@user` referenced in `CODEOWNERS` exists. Requires `validate_users_exist: true`.      |

`PS000` is reserved for tooling errors (e.g. missing token) and is
always emitted at `error` severity.

## 🧪 Supported code scanning

### Scanner roster

Every scanner output is normalised to SARIF 2.1.0 and merged with the
posture findings into a single upload artefact (`bos-scan.sarif` by
default). All third-party binaries are version-pinned and downloaded
fresh per run; no scanner is sourced from `latest`.

| Scanner            | Status   | Version   | Triggered when…                                              | What it scans                                                                          | Rule prefix         |
| ------------------ | -------- | --------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------- | ------------------- |
| **actionlint**     | ✅ v1.0  | `v1.7.1`  | `.github/workflows/*.{yml,yaml}` exists                      | GitHub Actions workflow YAML (syntax, expressions, embedded `run:` shell)              | `actionlint-native` |
| **gitleaks**       | ✅ v1.0  | `v8.21.2` | Always (when `enable_scanners: true`)                        | Secrets across the working tree (API keys, tokens, private keys, etc.)                 | `gitleaks-native`   |
| **shellcheck**     | ✅ v1.0  | `v0.10.0` | `**/*.sh` or `**/*.bash` exists                              | Shell-script issues (POSIX compliance, quoting, race conditions)                       | `SCNNNN`            |


### Tool inventory (v1.0)

This table covers every external tool currently used by the shipped
kit.

| Tool | Purpose | License | Site |
| ---- | ------- | ------- | ---- |
| actionlint | Lint GitHub Actions workflow syntax, expressions, and embedded shell usage. | MIT | https://github.com/rhysd/actionlint |
| gitleaks | Detect secrets in the repository working tree. | MIT | https://github.com/gitleaks/gitleaks |
| ShellCheck | Analyze shell scripts for correctness, quoting, and portability issues. | GPL-3.0 | https://www.shellcheck.net |
| PyYAML | Parse the Marketplace, global, and repository YAML/JSON config tiers. | MIT | https://pyyaml.org |

Only the tools listed above are executed by the current `action.yml`.

### Ecosystem detection coverage

The scanner roster above is driven by the ecosystem detector
([`src/detect.py`](src/detect.py)), which classifies
the working tree along three axes. Anything not in this list will be
silently ignored.

| Axis              | Recognised values                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Languages         | `python` · `javascript` · `typescript` · `go` · `java` · `csharp` · `ruby` · `rust` · `shell`                                      |
| Build artefacts   | Dockerfile · docker-compose · GitHub workflows · Terraform · Kubernetes manifests · Helm charts · shell scripts                    |
| Package managers  | `pip` · `pyproject` · `poetry` · `npm` · `yarn` · `pnpm` · `go modules` · `maven` · `gradle` · `cargo` · `bundler` · `nuget`       |
| CodeQL targets    | `python` · `javascript-typescript` · `go` · `java-kotlin` · `csharp` · `ruby` · `rust` (mapped from detected languages)            |

## 🏗️ Configuration inheritance and layering

Configuration is merged in cascade order:

1. **Marketplace config** — bundled at
   `src/blackout-secure-code-scanning-kit-marketplace-config.json`.
   It contains conservative best-practice defaults and is always available.
2. **Organization global config** — optional
   `.github/blackout-secure-code-scanning-kit-global-config.yml`. `auto`
   loads it when present, `true` requires it, and `false` disables it.
3. **Repository config** — optional `.github/bos-universal-config.json`
   (preferred), `.github/bos-universal-config.yml`, a root-level universal
   config, or a legacy `.bos-scan.yml` file.

Mappings are deep-merged. Scalars and lists from a lower tier replace the
inherited value. Repository values therefore win over global values, while
unmentioned nested policy remains inherited from the Marketplace baseline.
All files are read from the installed action or destination checkout; config
discovery does not fetch another repository.

Universal config files place this kit's settings under `code_scanning`:

```yaml
# .github/blackout-secure-code-scanning-kit-global-config.yml
code_scanning:
  owner: example-org
  posture:
    ghas:
      require_secret_scanning: fail
    branches:
      main:
        required_reviews: 2
```

```json
{
  "code_scanning": {
    "project_name": "payments-api",
    "posture": {
      "branches": {
        "main": { "severity": "fail" }
      }
    }
  }
}
```

The result keeps `required_reviews: 2` from the global tier and applies
`severity: fail` from the repo tier. A legacy `.bos-scan.yml` may remain flat;
no `code_scanning` wrapper is required.

## 📝 Config schema reference

Every field is optional. This representative file can be used either as a
flat `.bos-scan.yml` or nested under `code_scanning` in a universal config:

```yaml
# .bos-scan.yml - repository overrides

owner:        blackoutsecure
project_name: my-action
email:        security@example.com

scan:
  tools:   auto              # auto | explicit | none
  exclude: []                # scanners to skip even if their fingerprint matches
  fail_on: high              # critical | high | medium | low | never
  codeql:
    languages: []            # explicit CodeQL languages; empty => auto-detect
    exclude_languages: []

posture:
  ghas:
    require_code_scanning:     warn   # fail | warn | skip
    require_secret_scanning:   warn
    require_dependabot_alerts: warn
    require_push_protection:   warn

  workflows:
    require_permissions_block: warn
    forbid_write_all:          warn
    require_pinned_actions:    warn   # PS012 - fail | warn | skip
    allow_tag_pin: []                 # owner/repo entries exempted from PS012 (e.g. ['actions/checkout'])
    detect_msdo:                skip

  branches:
    main:
      required_reviews:                2
      restrict_force_push:             true
      require_status_checks:           true
      require_signed_commits:          true
      require_conversation_resolution: true
      severity:                        fail
    dev:
      required_reviews:                1
      severity:                        warn

  codeowners:
    require_file:         warn
    validate_users_exist: false   # set true to probe each @user/@org-team via API

remediation:
  enable_ai_findings_summary: false
  ai_findings_summary_provider: ""
  local_heuristic_fallback: true
```

Unknown keys are ignored so future kit versions and other sections in a
universal config do not break existing callers. AI summaries remain opt-in;
the default remediation path is local and deterministic.

## 💻 Local usage (CLI)

The kit also ships a standalone `bos-scan` CLI for local triage or
non-GitHub CI:

```bash
pip install bos-code-scanning-kit

# Detect ecosystems
bos-scan detect --root .

# Validate config
bos-scan validate --root .

# Require a custom organization config
bos-scan validate \
  --root . \
  --global-config .github/org-code-scanning.yml \
  --use-global-config

# Ignore a conventional global config for one local run
bos-scan validate --root . --no-global-config

# Posture audit (requires GITHUB_TOKEN)
export GITHUB_TOKEN=<your-token>
bos-scan posture \
  --owner your-org \
  --repo  bos-code-scanning-kit \
  --root  . \
  --sarif posture.sarif

# Merge multiple SARIFs
bos-scan sarif \
  --input gitleaks.sarif \
  --input actionlint.sarif \
  --posture posture.sarif \
  --output bos-scan.sarif
```

## 🤝 Contributing

Issues and PRs are welcome on `dev`. Run the tests with:

```bash
pip install -e ".[dev]"
pytest test/ -v
ruff check src test
```

## 📜 License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
