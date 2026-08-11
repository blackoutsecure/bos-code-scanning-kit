# Workflow ownership policy for bos-code-scanning-kit

This repository is a Marketplace Action producer.

## Required managed kickers
- Use bos-universal-sync-kicker.
- Use bos-universal-security-kicker.
- Use bos-universal-marketplace-kicker.
- Optional: bos-universal-action-test-kicker for managed pytest matrix.

## Do not use
- Do not use bos-universal-launchpad-kicker for this repo type.

## Keep local specialized workflows unless explicitly replaced
- self-scan workflow using uses: ./
- producer-specific codeql workflow decisions
- custom drift guards for action metadata and README sync checks
- optional post-release repo metadata sync

## Source of truth
- Managed behavior config lives in bos-universal-config.json.
- Managed workflow installation/removal is controlled by bos-managed-files.yaml services.
- Do not hand-edit managed kicker workflow files.

## Change safety rules
- Before deleting any local workflow, confirm equivalent behavior exists in a managed workflow.
- Preserve producer-specific coverage for local composite testing.
- Keep external action refs SHA-pinned.
- Re-run repo validation after workflow changes.