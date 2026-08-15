#!/usr/bin/env bash
# Marketplace repo-metadata sync — composite action body.
#
# Sourced into the calling shell by action.yml after lib.sh has been
# loaded and ERR_TITLE has been set. Reads all inputs from env vars
# (declared in action.yml's `env:` block) and emits GITHUB_OUTPUT
# rows + GITHUB_STEP_SUMMARY markdown.
#
# Flow:
#   1. Validate inputs.
#   2. Resolve description (explicit > AI > README fallback > leave).
#   3. Resolve topics (explicit > AI > fallback > skip).
#   4. PATCH /repos/{owner}/{repo} with description + homepage +
#      show_* flags. PUT /repos/{owner}/{repo}/topics with names.
#   5. Write outputs + summary.
#
# Dry-run short-circuits before any API write.

set -euo pipefail

: "${ERR_TITLE:=Marketplace repo-metadata}"
: "${AI_MODEL:=auto}"

HELPER_PY="${GITHUB_ACTION_PATH}/helper.py"
[ -f "${HELPER_PY}" ] || die "internal: helper.py not found at ${HELPER_PY}"

# ---------- Input validation -------------------------------------------------

require_var REPO
require_var GH_TOKEN
require_var README_PATH

case "${REPO}" in
  */*) ;;
  *) die "input 'repo' must be 'owner/repo' (got: '${REPO}')" ;;
esac

case "${DESCRIPTION_MAX_LEN}" in
  ''|*[!0-9]*) die "input 'description_max_length' must be a positive integer (got: '${DESCRIPTION_MAX_LEN}')" ;;
esac
if [ "${DESCRIPTION_MAX_LEN}" -lt 1 ] || [ "${DESCRIPTION_MAX_LEN}" -gt 350 ]; then
  die "input 'description_max_length' must be in 1..350 (got: ${DESCRIPTION_MAX_LEN})"
fi

case "${MAX_TOPICS}" in
  ''|*[!0-9]*) die "input 'max_topics' must be a non-negative integer (got: '${MAX_TOPICS}')" ;;
esac

validate_bool GENERATE_TOPICS
validate_bool AI_ENABLED
validate_bool SHOW_RELEASES
validate_bool SHOW_DEPLOYMENTS
validate_bool SHOW_PACKAGES
validate_bool DRY_RUN

if [ -z "${AI_MODEL}" ] || [ "${AI_MODEL}" = "auto" ]; then
  AI_MODEL="${GITHUB_MODELS_MODEL_METADATA:-${GITHUB_MODELS_MODEL:-openai/gpt-4o-mini}}"
fi

# ---------- Tool checks ------------------------------------------------------

for tool in jq curl python3; do
  command -v "${tool}" >/dev/null 2>&1 || die "required tool '${tool}' not on PATH"
done

OWNER="${REPO%%/*}"
REPO_NAME="${REPO##*/}"
case "${OWNER}" in
  ''|*[!A-Za-z0-9._-]*) die "owner segment of 'repo' is invalid: '${OWNER}'" ;;
esac
case "${REPO_NAME}" in
  ''|*[!A-Za-z0-9._-]*) die "repo segment of 'repo' is invalid: '${REPO_NAME}'" ;;
esac

# ---------- Resolve description ---------------------------------------------
#
# Precedence (first non-empty wins):
#   1. ``DESCRIPTION`` input — caller explicitly provided one.
#   2. AI rewrite of the README seed, when ``AI_ENABLED=true``.
#   3. The README seed itself (deterministic fallback).
#   4. Leave the existing description untouched (source = ``existing``).

DESC_FINAL=""
DESC_SOURCE="existing"
AI_USED="false"

if [ -n "${DESCRIPTION}" ]; then
  DESC_FINAL=$(printf '%s' "${DESCRIPTION}" | python3 "${HELPER_PY}" clamp-description --max-len "${DESCRIPTION_MAX_LEN}")
  DESC_SOURCE="explicit"
else
  if [ ! -f "${README_PATH}" ]; then
    echo "::warning::repo-metadata: README '${README_PATH}' not found; leaving description unchanged"
  else
    README_SEED=$(python3 "${HELPER_PY}" extract-readme "${README_PATH}" --max-len 1500 || true)
    if [ -z "${README_SEED}" ]; then
      echo "::warning::repo-metadata: could not extract a prose summary from '${README_PATH}'; leaving description unchanged"
    else
      DESC_CANDIDATE=""
      if [ "${AI_ENABLED}" = "true" ]; then
        # ---- AI rewrite -------------------------------------------
        AI_OUT="${RUNNER_TEMP:-/tmp}/repo-metadata.desc.json"
        AI_ERR="${RUNNER_TEMP:-/tmp}/repo-metadata.desc.err"
        PROMPT=$(printf 'You are a GitHub repo description editor. Rewrite the README excerpt below as ONE punchy single-sentence summary of what this repository does, suitable for the "About" box. Hard limits: maximum %d characters, no trailing period, no markdown, no quotes, no emoji, plain prose only. Excerpt:\n\n%s' "${DESCRIPTION_MAX_LEN}" "${README_SEED}")
        PAYLOAD=$(jq -Rs --arg model "${AI_MODEL}" '{
          model: $model,
          temperature: 0.2,
          messages: [
            {"role": "system", "content": "You write concise, factual, single-sentence repository descriptions. Plain text only."},
            {"role": "user",   "content": . }
          ]
        }' <<<"${PROMPT}")
        HTTP_CODE=$(curl -sS \
          -o "${AI_OUT}" -w '%{http_code}' \
          -H "Authorization: Bearer ${GH_TOKEN}" \
          -H "Accept: application/vnd.github+json" \
          -H "Content-Type: application/json" \
          -H "X-GitHub-Api-Version: 2022-11-28" \
          -d "${PAYLOAD}" \
          'https://models.github.ai/inference/chat/completions' \
          2>"${AI_ERR}" || true)
        if [ "${HTTP_CODE}" = "200" ]; then
          AI_CONTENT=$(jq -r '.choices[0].message.content // empty' "${AI_OUT}" 2>/dev/null || true)
          if [ -n "${AI_CONTENT}" ]; then
            DESC_CANDIDATE="${AI_CONTENT}"
            DESC_SOURCE="ai"
            AI_USED="true"
            echo "::notice::repo-metadata: description from GitHub Models (${AI_MODEL})"
          else
            echo "::warning::repo-metadata: AI description returned 200 but empty; falling back to README seed"
          fi
        else
          echo "::warning::repo-metadata: AI description request failed (HTTP ${HTTP_CODE}); falling back to README seed. Most likely missing 'models: read' permission."
          head -c 500 "${AI_OUT}" >&2 || true
          cat "${AI_ERR}" >&2 || true
          echo "" >&2
        fi
      fi

      if [ -z "${DESC_CANDIDATE}" ]; then
        DESC_CANDIDATE="${README_SEED}"
        DESC_SOURCE="readme"
      fi
      DESC_FINAL=$(printf '%s' "${DESC_CANDIDATE}" | python3 "${HELPER_PY}" clamp-description --max-len "${DESCRIPTION_MAX_LEN}")
    fi
  fi
fi

# ---------- Resolve topics ---------------------------------------------------

TOPICS_FINAL=""
TOPICS_SOURCE="skipped"

if [ -n "${TOPICS}" ]; then
  TOPICS_FINAL=$(python3 "${HELPER_PY}" sanitize-topics --max-count "${MAX_TOPICS}" --value "${TOPICS}")
  TOPICS_SOURCE="explicit"
elif [ "${GENERATE_TOPICS}" = "true" ]; then
  if [ ! -f "${README_PATH}" ]; then
    echo "::warning::repo-metadata: cannot generate topics (README '${README_PATH}' missing); using fallback"
    TOPICS_FINAL=$(python3 "${HELPER_PY}" sanitize-topics --max-count "${MAX_TOPICS}" --value "${TOPICS_FALLBACK}")
    [ -n "${TOPICS_FINAL}" ] && TOPICS_SOURCE="fallback"
  else
    TOPIC_SEED=$(python3 "${HELPER_PY}" extract-readme "${README_PATH}" --max-len 3000 || true)
    AI_TOPICS_RAW=""
    if [ "${AI_ENABLED}" = "true" ] && [ -n "${TOPIC_SEED}" ]; then
      AI_OUT="${RUNNER_TEMP:-/tmp}/repo-metadata.topics.json"
      AI_ERR="${RUNNER_TEMP:-/tmp}/repo-metadata.topics.err"
      PROMPT=$(printf 'You are a GitHub repository topic curator. Read the README excerpt below and output up to %d GitHub topics that best describe this repository.\n\nGitHub topic rules — output MUST satisfy ALL of these:\n- lowercase letters, digits, hyphens only\n- each topic must be at most 50 characters\n- must start with a letter or digit\n- no leading or trailing hyphens\n\nOutput format: ONE LINE, space-separated topics. No commas, no quotes, no markdown, no preamble, no closing remarks, no explanations.\n\nExcerpt:\n\n%s' "${MAX_TOPICS}" "${TOPIC_SEED}")
      PAYLOAD=$(jq -Rs --arg model "${AI_MODEL}" '{
        model: $model,
        temperature: 0.2,
        messages: [
          {"role": "system", "content": "You output a single line of space-separated GitHub topic slugs. No other text."},
          {"role": "user",   "content": . }
        ]
      }' <<<"${PROMPT}")
      HTTP_CODE=$(curl -sS \
        -o "${AI_OUT}" -w '%{http_code}' \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "Content-Type: application/json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -d "${PAYLOAD}" \
        'https://models.github.ai/inference/chat/completions' \
        2>"${AI_ERR}" || true)
      if [ "${HTTP_CODE}" = "200" ]; then
        AI_TOPICS_RAW=$(jq -r '.choices[0].message.content // empty' "${AI_OUT}" 2>/dev/null || true)
        if [ -n "${AI_TOPICS_RAW}" ]; then
          AI_USED="true"
        fi
      else
        echo "::warning::repo-metadata: AI topics request failed (HTTP ${HTTP_CODE}); falling back. Most likely missing 'models: read' permission."
        head -c 500 "${AI_OUT}" >&2 || true
        cat "${AI_ERR}" >&2 || true
        echo "" >&2
      fi
    fi

    if [ -n "${AI_TOPICS_RAW}" ]; then
      TOPICS_FINAL=$(python3 "${HELPER_PY}" sanitize-topics --max-count "${MAX_TOPICS}" --value "${AI_TOPICS_RAW}")
      if [ -n "${TOPICS_FINAL}" ]; then
        TOPICS_SOURCE="ai"
        echo "::notice::repo-metadata: topics from GitHub Models (${AI_MODEL})"
      fi
    fi

    if [ -z "${TOPICS_FINAL}" ] && [ -n "${TOPICS_FALLBACK}" ]; then
      TOPICS_FINAL=$(python3 "${HELPER_PY}" sanitize-topics --max-count "${MAX_TOPICS}" --value "${TOPICS_FALLBACK}")
      [ -n "${TOPICS_FINAL}" ] && TOPICS_SOURCE="fallback"
    fi
  fi
fi

# ---------- Resolve homepage -------------------------------------------------

HOMEPAGE_FINAL=""
HOMEPAGE_OP="skip"     # "skip" | "set" | "clear"
case "${HOMEPAGE}" in
  '')          HOMEPAGE_OP="skip"; HOMEPAGE_FINAL="" ;;
  '__unset__') HOMEPAGE_OP="clear"; HOMEPAGE_FINAL="" ;;
  http://*|https://*) HOMEPAGE_OP="set"; HOMEPAGE_FINAL="${HOMEPAGE}" ;;
  *) die "input 'homepage' must be empty, '__unset__', or an http(s) URL (got: '${HOMEPAGE}')" ;;
esac

# ---------- Build PATCH payload + topics payload -----------------------------

PATCH_PAYLOAD=$(jq -n \
  --arg desc          "${DESC_FINAL}" \
  --arg desc_source   "${DESC_SOURCE}" \
  --arg homepage      "${HOMEPAGE_FINAL}" \
  --arg homepage_op   "${HOMEPAGE_OP}" \
  --argjson show_releases    "${SHOW_RELEASES}" \
  --argjson show_deployments "${SHOW_DEPLOYMENTS}" \
  --argjson show_packages    "${SHOW_PACKAGES}" \
  '
  ( if $desc_source == "existing" then {} else { description: $desc } end )
  + ( if $homepage_op == "set"   then { homepage: $homepage }
      elif $homepage_op == "clear" then { homepage: "" }
      else {} end )
  + { show_releases: $show_releases,
      show_deployments: $show_deployments,
      show_packages: $show_packages }
  ')

TOPICS_PAYLOAD=""
if [ "${TOPICS_SOURCE}" != "skipped" ]; then
  # ``names: []`` clears all topics; we never send that here — we only
  # PUT topics when we have a non-empty list. (Caller can pass an
  # explicit ``topics: '-'`` etc. in the future if clearing is needed.)
  if [ -n "${TOPICS_FINAL}" ]; then
    TOPICS_PAYLOAD=$(jq -n --arg t "${TOPICS_FINAL}" \
      '{ names: ($t | split(" ") | map(select(length > 0))) }')
  fi
fi

# ---------- Apply ------------------------------------------------------------

APPLIED="false"
if [ "${DRY_RUN}" = "true" ]; then
  echo "::notice::repo-metadata: dry_run=true; skipping all API writes"
else
  # ---- PATCH /repos/{owner}/{repo} -------------------------------------
  PATCH_OUT="${RUNNER_TEMP:-/tmp}/repo-metadata.patch.json"
  PATCH_ERR="${RUNNER_TEMP:-/tmp}/repo-metadata.patch.err"
  PATCH_HTTP=$(curl -sS \
    -o "${PATCH_OUT}" -w '%{http_code}' \
    -X PATCH \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -d "${PATCH_PAYLOAD}" \
    "https://api.github.com/repos/${OWNER}/${REPO_NAME}" \
    2>"${PATCH_ERR}" || true)
  case "${PATCH_HTTP}" in
    2*)
      APPLIED="true"
      echo "::notice::repo-metadata: repo PATCH ok (HTTP ${PATCH_HTTP})"
      echo "::notice::repo-metadata: 'show_releases/show_deployments/show_packages' fields are best-effort — GitHub does not document them on the public REST API; the PATCH succeeds and the documented fields (description/homepage) are applied authoritatively."
      ;;
    *)
      msg=$(jq -r '.message // empty' "${PATCH_OUT}" 2>/dev/null || true)
      head -c 500 "${PATCH_OUT}" >&2 || true
      cat "${PATCH_ERR}" >&2 || true
      echo "" >&2
      die "repo PATCH failed (HTTP ${PATCH_HTTP}): ${msg:-unknown error}. Check that 'github_token' has 'Administration: write' on this repo."
      ;;
  esac

  # ---- PUT /repos/{owner}/{repo}/topics --------------------------------
  if [ -n "${TOPICS_PAYLOAD}" ]; then
    TOPICS_OUT="${RUNNER_TEMP:-/tmp}/repo-metadata.topics.put.json"
    TOPICS_ERR="${RUNNER_TEMP:-/tmp}/repo-metadata.topics.put.err"
    TOPICS_HTTP=$(curl -sS \
      -o "${TOPICS_OUT}" -w '%{http_code}' \
      -X PUT \
      -H "Authorization: Bearer ${GH_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -d "${TOPICS_PAYLOAD}" \
      "https://api.github.com/repos/${OWNER}/${REPO_NAME}/topics" \
      2>"${TOPICS_ERR}" || true)
    case "${TOPICS_HTTP}" in
      2*)
        APPLIED="true"
        echo "::notice::repo-metadata: topics PUT ok (HTTP ${TOPICS_HTTP})"
        ;;
      *)
        msg=$(jq -r '.message // empty' "${TOPICS_OUT}" 2>/dev/null || true)
        head -c 500 "${TOPICS_OUT}" >&2 || true
        cat "${TOPICS_ERR}" >&2 || true
        echo "" >&2
        die "topics PUT failed (HTTP ${TOPICS_HTTP}): ${msg:-unknown error}. Check that 'github_token' has 'Administration: write' on this repo."
        ;;
    esac
  fi
fi

# ---------- Outputs ----------------------------------------------------------

{
  printf 'description=%s\n'        "${DESC_FINAL}"
  printf 'description_source=%s\n' "${DESC_SOURCE}"
  printf 'homepage=%s\n'           "${HOMEPAGE_FINAL}"
  printf 'topics=%s\n'             "${TOPICS_FINAL}"
  printf 'topics_source=%s\n'      "${TOPICS_SOURCE}"
  printf 'ai_used=%s\n'            "${AI_USED}"
  printf 'applied=%s\n'            "${APPLIED}"
} >> "${GITHUB_OUTPUT}"

# ---------- Summary ----------------------------------------------------------

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Marketplace repo-metadata sync"
    echo ""
    echo "| Field | Value | Source |"
    echo "|---|---|---|"
    if [ -n "${DESC_FINAL}" ]; then
      desc_md=$(printf '%s' "${DESC_FINAL}" | sed -e 's/|/\\|/g')
      echo "| Description (${#DESC_FINAL}/${DESCRIPTION_MAX_LEN}) | ${desc_md} | ${DESC_SOURCE} |"
    else
      echo "| Description | _(unchanged)_ | ${DESC_SOURCE} |"
    fi
    case "${HOMEPAGE_OP}" in
      set)   echo "| Homepage | ${HOMEPAGE_FINAL} | input |" ;;
      clear) echo "| Homepage | _(cleared)_ | input |" ;;
      *)     echo "| Homepage | _(unchanged)_ | skip |" ;;
    esac
    if [ -n "${TOPICS_FINAL}" ]; then
      topic_count=$(printf '%s' "${TOPICS_FINAL}" | tr ' ' '\n' | grep -cv '^$' || true)
      echo "| Topics (${topic_count}) | \`${TOPICS_FINAL}\` | ${TOPICS_SOURCE} |"
    else
      echo "| Topics | _(unchanged)_ | ${TOPICS_SOURCE} |"
    fi
    echo "| Show Releases    | \`${SHOW_RELEASES}\`    | input (best-effort) |"
    echo "| Show Deployments | \`${SHOW_DEPLOYMENTS}\` | input (best-effort) |"
    echo "| Show Packages    | \`${SHOW_PACKAGES}\`    | input (best-effort) |"
    echo "| AI used          | \`${AI_USED}\` | ${AI_MODEL} |"
    echo "| Applied          | \`${APPLIED}\` | dry_run=${DRY_RUN} |"
  } >> "${GITHUB_STEP_SUMMARY}"
fi
