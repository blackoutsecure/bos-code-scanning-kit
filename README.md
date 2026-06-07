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
  (`PS001`). Secret-scanning (`PS002`), Dependabot (`PS003`), and
  branch-protection probes (`PS020`-`PS025`) require a PAT — see
  [SCANNING_PAT — advanced posture credentials](#-scanning_pat--advanced-posture-credentials)
  for the full tick / don't-tick checklist (classic and fine-grained).
- For the **SARIF upload**: `security-events: write` in your workflow
  `permissions:` block.

## Quick start 🚀

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

That's it. The kit auto-discovers your ecosystem, runs every applicable
scanner, audits posture, and uploads a single SARIF.

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
| `config` | _(none)_ | Path to `.bos-scan.yml`. Defaults to auto-discovery at the repo root. |
| `github_token` | _(none)_ | Token used by the posture audit (PS001 code scanning, PS002 secret scanning, PS003 Dependabot alerts, PS020-PS025 branch protection). Leave empty to fall back to the workflow's built-in GITHUB_TOKEN, which is enough for PS001 only. PS002/PS003/PS020-PS025 require a PAT with admin reach — by org convention stored as a secret named `SCANNING_PAT`. See the kit README § 'SCANNING_PAT — advanced posture credentials' for the classic / fine-grained tick checklist and the recommended caller pattern. |
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

## � `SCANNING_PAT` — advanced posture credentials

The composite's `github_token` input accepts EITHER the default
`secrets.GITHUB_TOKEN` (the workflow's per-job token, App `15368`,
`github-actions[bot]`) OR a Personal Access Token stored as a repo /
org secret — by org convention named `SCANNING_PAT`. The default
token is enough for the code-scanning probe (`PS001`) but cannot read
the secret-scanning, Dependabot, or branch-protection endpoints —
those return HTTP `403`, and the posture step records them as `skip`
(not `pass` or `fail`) so the row is honest about what was checked.

### TL;DR

| Question | Answer |
|---|---|
| **Which token does the action prefer?** | Whichever the caller passes — the action sees one `github_token` input. The recommended caller pattern always prefers `SCANNING_PAT` over `GITHUB_TOKEN`: `github_token: ${{ secrets.SCANNING_PAT || secrets.GITHUB_TOKEN }}`. The expression is safe to ship before the PAT exists; when the secret is unset the `\|\|` falls through to `GITHUB_TOKEN`. |
| **What classic-PAT scope do I need?** | Just the top-level `repo` checkbox. Nothing else. That's the only classic scope that simultaneously grants admin-read on `vulnerability-alerts` and `branches/*/protection`, and it auto-selects `security_events` (which is what makes PS001/PS002 work). |
| **What does a `warn` finding mean vs a `skip` finding?** | `warn` = the feature really isn't enabled on the repo (e.g. GHAS code scanning is off). `skip` = your token couldn't see the endpoint (403). If you see `skip` rows, fix the token. If you see `warn` rows for PS001/PS002, enable the corresponding GHAS feature in **Settings → Code security**. |
| **SAML SSO?** | Mandatory for any SAML-enforced org (incl. `blackoutsecure`). After creating the PAT, click **Configure SSO → Authorize** next to it for every org it will probe. Without this, every API call returns 403 and PS001-PS025 all degrade to `skip`. |

To upgrade `skip` rows to real `pass`/`fail` evaluations, set
`SCANNING_PAT` and pass it to the action's `github_token` input. The
caller workflow shipped with `marketplace-kit generate-policy
code-scan-workflow` already does this automatically when the secret
is present; see the [bos-marketplace-kit README](https://github.com/blackoutsecure/bos-marketplace-kit#step-5b--tokens-secrets-and-variables)
for the consumer-side wiring.

### Endpoints the posture audit hits (and what scope each needs)

| Rule | Endpoint | Fine-grained permission | Classic scope |
|------|----------|-------------------------|---------------|
| `PS001` | `GET /repos/{}/code-scanning/default-setup`, fallback `GET /repos/{}/code-scanning/analyses?tool_name=CodeQL` | Code scanning alerts: Read | `security_events` or `repo` |
| `PS002` | `GET /repos/{}/secret-scanning/alerts` | Secret scanning alerts: Read | `security_events` or `repo` |
| `PS003` | `GET /repos/{}/vulnerability-alerts` | Administration: Read | `repo` (admin) |
| `PS004` | `GET /repos/{}` (reads `security_and_analysis.secret_scanning_push_protection`) | Administration: Read | `repo` (admin) |
| `PS020`-`PS025` | `GET /repos/{}/branches/{}/protection` | Administration: Read | `repo` (admin) |
| `PS030`-`PS031` | `GET /repos/{}/contents/CODEOWNERS` | Contents: Read | `repo` or `public_repo` |
| `CQ*`, `GH*`, `MS*`, `SR*` | (workflow file reads via `contents`) | Contents: Read | `repo` or `public_repo` |

Branch protection and `vulnerability-alerts` REQUIRE admin-level access
on the repo, and there is no classic-PAT scope below `repo` that grants
it. The same constraint applies to the fine-grained permission
(`Administration: Read`).

### Classic PAT recipe (minimum)

Created at <https://github.com/settings/tokens> → **Generate new
token (classic)**. The kit supports classic PATs because some org
policies disable fine-grained tokens by default. Use the minimum-scope
recipe below — anything broader is unnecessary surface area.

**One scope. That's it: tick the top-level `repo` checkbox.**

Nothing else needs to be ticked manually. GitHub auto-selects the
five sub-scopes (`repo:status`, `repo_deployment`, `public_repo`,
`repo:invite`, `security_events`) when you tick `repo`, and that
combined set is precisely the minimum that covers every posture probe:

**Tick exactly these:**

| Scope (top-level) | Tick? | Why |
|---|---|---|
| `repo` (Full control of private repositories) | ✅ **Yes** | The only classic scope that simultaneously grants admin read on `vulnerability-alerts` and `branches/*/protection`. Auto-selects `repo:status`, `repo_deployment`, `public_repo`, `repo:invite`, `security_events` — `security_events` is what makes PS001/PS002 work. No narrower classic scope covers the full posture surface. |

**Do NOT tick (over-scoped — `SCANNING_PAT` is conceptually READ-only):**

| Scope | Why not |
|---|---|
| `workflow` | The posture audit never writes workflow files. |
| `write:packages`, `delete:packages`, `read:packages` | Packages are not involved. |
| `admin:org`, `write:org`, `read:org`, `manage_runners:org` | Org admin is never required to probe a single repo. |
| `admin:enterprise` (and children: `manage_runners`, `manage_billing`, `read`, `scim`) | Enterprise-level access is never required. |
| `delete_repo`, `admin:repo_hook`, `admin:org_hook` | Destructive / hook scopes are not used. |
| `admin:public_key`, `admin:ssh_signing_key`, `admin:gpg_key` | Key management is not used. |
| `gist`, `notifications`, `user`, `audit_log`, `codespace`, `project`, `copilot`, `write:discussion`, `read:discussion` | Not used. |

**SAML SSO authorize (mandatory for any SAML-enforced org, including `blackoutsecure`):**

1. On the saved-token page (<https://github.com/settings/tokens>),
   under **"Configure SSO"** next to the token, click *Authorize*
   for every SAML-enforced org the PAT will probe.
2. Without this, every API call against the org returns HTTP `403`
   with body `Resource protected by organization SAML enforcement`,
   and PS001-PS025 all degrade to `skip`.

**Storage:** save under **Settings → Secrets and variables → Actions →
Secrets** as `SCANNING_PAT` (secret, not variable — secrets are
masked in logs). For org-wide scanning, store at the org level and
restrict to specific repos via the org-secret access policy.

**Expiration:** ≤90 days. Rotate on schedule — a leaked classic
`repo` PAT is more dangerous than a leaked fine-grained PAT because
it can write to every private repo the owner can see, not just the
selected ones. Per-repo blast-radius limiting is only possible with
fine-grained.

### Fine-grained PAT recipe (recommended)

If your org allows fine-grained tokens, prefer them — they let
`SCANNING_PAT` be truly READ-only:

| Setting | Value |
|---|---|
| Resource owner | the org being scanned |
| Repository access | Only select repositories → the repos to probe |
| Repository permissions → Contents | Read-only |
| Repository permissions → Metadata | Read-only (auto-selected, mandatory) |
| Repository permissions → Administration | Read-only |
| Repository permissions → Code scanning alerts | Read-only |
| Repository permissions → Secret scanning alerts | Read-only |
| Everything else | "No access" |
| Expiration | ≤90 days |
| Then | **Configure SSO → Authorize** for each SAML-enforced org |

### What happens with no `SCANNING_PAT`

The audit still runs. PS001 (code scanning) succeeds via
`GITHUB_TOKEN` if the workflow has `permissions: { security-events:
read }` (or `write`). PS002, PS003, and PS020-PS025 emit `skip`
findings with a remediation hint pointing at this section. No SARIF
upload failure, no posture FAIL — just an honest "we did not check"
row.

## �🛡️ Posture rule reference

Severities can be overridden per rule in `.bos-scan.yml`.

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
| **CodeQL**         | 🛠 v1.1  | _pending_ | Any detected language maps to a CodeQL target (see below)    | Semantic source-code scan via GitHub's CodeQL engine                                   | `codeql-*`          |
| **Trivy**          | 🛠 v1.1  | _pending_ | `Dockerfile*` or `compose.{yml,yaml}` exists                 | Container image CVEs + IaC misconfigurations                                           | `trivy-*`           |
| **Checkov**        | 🛠 v1.1  | _pending_ | `*.tf`, `k8s/` or `kubernetes/` manifests, or `Chart.yaml`   | IaC policy + misconfigurations (Terraform / Kubernetes / Helm)                         | `CKV_*`             |
| **osv-scanner**    | 🛠 v1.1  | _pending_ | Any package-manager lockfile present (see detection below)   | Known-vulnerability cross-reference against the [OSV](https://osv.dev) database        | `osv-*`             |
| **hadolint**       | 🛠 v1.1  | _pending_ | `Dockerfile*` exists                                         | Dockerfile linting (best practices, layer hygiene)                                     | `DL*`               |
| **Scorecard SARIF**| 🛠 v1.1  | _pending_ | Always (when enabled)                                        | OpenSSF [Scorecard](https://github.com/ossf/scorecard) checks merged with posture      | `scorecard-*`       |

`✅ v1.0` = shipping today. `🛠 v1.1` = scaffolded in the registry,
fan-out rolling out across the v1.1.x line.

### Ecosystem detection coverage

The scanner roster above is driven by the ecosystem detector
([`src/scan_kit/detect.py`](src/scan_kit/detect.py)), which classifies
the working tree along three axes. Anything not in this list will be
silently ignored.

| Axis              | Recognised values                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Languages         | `python` · `javascript` · `typescript` · `go` · `java` · `csharp` · `ruby` · `rust` · `shell`                                      |
| Build artefacts   | Dockerfile · docker-compose · GitHub workflows · Terraform · Kubernetes manifests · Helm charts · shell scripts                    |
| Package managers  | `pip` · `pyproject` · `poetry` · `npm` · `yarn` · `pnpm` · `go modules` · `maven` · `gradle` · `cargo` · `bundler` · `nuget`       |
| CodeQL targets    | `python` · `javascript-typescript` · `go` · `java-kotlin` · `csharp` · `ruby` · `rust` (mapped from detected languages)            |

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
    require_pinned_actions:    warn   # PS012 — fail | warn | skip
    allow_tag_pin: []                 # owner/repo entries exempted from PS012 (e.g. ['actions/checkout'])

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
  (`.github/workflows/bos-universal-launchpad.yml`). All PRs land
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
