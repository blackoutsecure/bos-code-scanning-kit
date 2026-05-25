# Blackout Secure Code Scanning Kit

**Copyright © 2025-2026 Blackout Secure | Apache License 2.0**

[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-blue?logo=github)](https://github.com/marketplace/actions/blackout-secure-code-scanning-kit)
[![GitHub release](https://img.shields.io/github/v/release/blackoutsecure/bos-code-scanning-kit?sort=semver)](https://github.com/blackoutsecure/bos-code-scanning-kit/releases)
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
- **`.bos-scan.yml` config** — per-repo policy lives in one
  human-readable YAML file at the repo root. Defaults are safe; you
  only declare what you want to change.
- **Pure-stdlib Python core** — no third-party Python deps beyond
  `PyYAML`. The composite Action installs the kit on the runner with a
  single `pip install`.

[actionlint]: https://github.com/rhysd/actionlint
[gitleaks]:   https://github.com/gitleaks/gitleaks
[shellcheck]: https://www.shellcheck.net

## 📋 Prerequisites

- GitHub-hosted Linux runner (`ubuntu-latest` or newer) — the kit
  installs `python` via `actions/setup-python@v5` automatically.
- For the **posture audit**: a token with `repo` scope. The default
  `${{ secrets.GITHUB_TOKEN }}` is enough for the code-scanning probe
  (`PS001`). Secret-scanning (`PS002`) and Dependabot (`PS003`) probes
  require a PAT with `repo` and admin scope.
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
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

That's it. The kit auto-discovers your ecosystem, runs every applicable
scanner, audits posture, and uploads a single SARIF.

## ⚙️ Action inputs

| Input             | Default            | Description                                                                                                  |
| ----------------- | ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `owner`           | _workflow context_ | GitHub owner of the repo being scanned.                                                                       |
| `repo`            | _workflow context_ | GitHub repo name being scanned.                                                                               |
| `config`          | _auto-discover_    | Path to `.bos-scan.yml`. Defaults to `.bos-scan.yml` / `.bos-scan.yaml` / `bos-scan.yml` at the repo root.    |
| `github_token`    | `${{ github.token }}` | Token used for posture API calls. Use a PAT for the secret-scanning + Dependabot probes.                  |
| `enable_posture`  | `true`             | Run the posture audit.                                                                                        |
| `enable_scanners` | `true`             | Run the bundled scanners (actionlint / gitleaks / shellcheck).                                                |
| `enable_upload`   | `true`             | Upload the merged SARIF to GitHub Advanced Security.                                                          |
| `fail_on`         | `fail`             | `fail` → exit non-zero on any posture FAIL. `never` → always exit 0 (useful for first-time rollouts).         |
| `sarif_output`    | `bos-scan.sarif`   | Path for the merged SARIF artefact.                                                                           |

## 📤 Action outputs

| Output             | Description                                              |
| ------------------ | -------------------------------------------------------- |
| `sarif_path`       | Path to the merged SARIF file produced by the run.       |
| `posture_failures` | Number of FAIL findings emitted by the posture audit.    |

## 🛡️ Posture rule reference

Severities can be overridden per rule in `.bos-scan.yml`.

| Rule  | Default | What it checks                                                                                          |
| ----- | ------- | ------------------------------------------------------------------------------------------------------- |
| PS001 | warn    | GitHub code scanning is **configured** for the repo (default-setup state).                              |
| PS002 | warn    | GitHub secret scanning is enabled (probed via the secret-scanning alerts API).                          |
| PS003 | warn    | Dependabot vulnerability alerts are enabled.                                                            |
| PS010 | warn    | Every workflow file declares an explicit top-level `permissions:` block.                                |
| PS011 | warn    | No workflow uses `permissions: write-all` at the workflow or job level.                                 |
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

## 🧪 Bundled scanner reference

| Scanner    | Runs when…                                                          | Findings rule prefix |
| ---------- | ------------------------------------------------------------------- | -------------------- |
| actionlint | `.github/workflows/*.{yml,yaml}` exist                              | actionlint-native    |
| gitleaks   | always (when `enable_scanners` is `true`)                           | gitleaks-native      |
| shellcheck | `**/*.sh` or `**/*.bash` exist                                      | `SCNNNN`             |

Each scanner is downloaded as a pinned single binary at run time
(actionlint `v1.7.1`, gitleaks `v8.21.2`) or installed via `apt`
(shellcheck). Output is normalized to SARIF 2.1.0 and merged with the
posture findings before upload.

**Roadmap (v1.1+):** CodeQL, Trivy, Checkov, osv-scanner, hadolint,
Scorecard SARIF. Already scaffolded in the registry; rule fan-out
shipping in subsequent minor releases.

## 📝 `.bos-scan.yml` schema

Every field is optional — the kit ships safe defaults. A
representative full file:

```yaml
# .bos-scan.yml — Blackout Secure Code Scanning Kit config

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

  workflows:
    require_permissions_block: warn
    forbid_write_all:          warn

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
```

Unknown top-level keys are ignored so that future kit versions can
extend the schema without breaking older callers.

## 💻 Local usage (CLI)

The kit also ships a standalone `bos-scan` CLI for local triage or
non-GitHub CI:

```bash
pip install bos-code-scanning-kit

# Detect ecosystems
bos-scan detect --root .

# Validate config
bos-scan validate --root .

# Posture audit (requires GITHUB_TOKEN)
export GITHUB_TOKEN=ghp_…
bos-scan posture \
  --owner blackoutsecure \
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

## 🏗️ Repository layout & releases

This repo follows the Blackout Secure Marketplace Action dev/main
split (see [bos-automation-hub]):

- **`dev`** — active development branch. Hosts the launchpad workflow
  (`.github/workflows/bos-marketplace-launchpad.yml`). All PRs land
  here first; CI runs on every PR + every push.
- **`main`** — the curated Marketplace artefact. Receives allowlist
  promotes from `dev` via the hub-side release pipeline. **No workflow
  files** live on `main`; the hub release stage enforces this so the
  branch presents a clean Marketplace surface.

[bos-automation-hub]: https://github.com/blackoutsecure/bos-automation-hub

## 🤝 Contributing

Issues and PRs are welcome on `dev`. Run the tests with:

```bash
pip install -e .
pip install -r requirements-dev.txt
pytest test/ -v
ruff check src test
```

## 📜 License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
