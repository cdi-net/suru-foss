#!/usr/bin/env bash
# =============================================================================
# SURU Platform — Tier 3 Core  ·  apply-security-analytics.sh
# =============================================================================
# Purpose : Idempotent import-only provisioner for OpenSearch Security
#           Analytics. Registers SURU custom log types (confirmed wire shape,
#           tier3-core/docs/security-analytics.md), creates the headline
#           correlation rule, and provisions the email trigger-action's
#           Notifications-plugin channels. Detector import for SURU's own
#           five Sigma-bound detectors is STUBBED — see header note below.
# Runtime : bash (per bash strict-mode (set -euo pipefail) — set -euo pipefail).
#           Mirrors apply-threat-intel.sh's bash structural pattern rather
#           than the sibling POSIX-sh init scripts, per that script's own
#           header note.
# Container: suru.t3.datalake.securityanalytics-init (one-shot init
#            container, wired into deploy.sh's datalake/opensearch dispatch
#            — see compose.yaml / deploy.sh in this same change).
#
# *** STATUS: detector import is STUBBED — see tier3-core/docs/security-analytics.md ***
# All five rendered SURU detectors (tier2-telemetry/opensearch/detectors/*.yml)
# bind to CUSTOM Sigma rule IDs (custom_rules[], not pre_packaged_rules[]).
# Custom-rule registration (POST _plugins/_security_analytics/rules?category=<x>)
# is confirmed live to 500 with a server-side NullPointerException
# (SigmaRule.fromDict -> LogTypeService.getRuleFieldMappings) on every category
# and every rule body tried this session — see security-analytics.md "Custom
# Sigma rule creation — BLOCKED" for the full stack trace and root-cause
# analysis. Detector import therefore cannot proceed until that build bug is
# resolved or worked around. This script logs and SKIPS detector import,
# emitting [STUB: blocked on OpenSearch custom-rule-create NPE — see
# security-analytics.md] for each detector file found, rather than failing
# the whole run.
#
# What this script DOES provision (all confirmed live — see
# tier3-core/docs/security-analytics.md):
#   1. Custom log types  (POST /logtype)            — confirmed, idempotent
#      via create-and-treat-"already exists"-as-success.
#   2. Correlation rules (POST /correlation/rules)   — confirmed. Idempotent
#      via the confirmed-working /correlation/rules/_search check.
#   3. Email trigger action (OpenSearch Notifications plugin smtp_account +
#      email channel configs) — confirmed. Idempotent via name-based lookup
#      against GET /_plugins/_notifications/configs (best-effort; the
#      Notifications plugin has no documented upsert-by-name or search-by-name
#      filter, so this script lists all configs and greps for the target name
#      — adequate for the small, fixed set of SURU-managed channel names; on a
#      match it skips creation rather than risking a duplicate).
#   4. perimeter_block / slack / webhook actions — NOT sent to any OpenSearch
#      endpoint. perimeter_block is a SURU-internal concept (calls Tier 1's
#      api.sh, not OpenSearch); slack/webhook are explicitly unconfigured per
#      tier2-telemetry/opensearch/actions/README.md. All three are logged for
#      operator visibility only.
#
# *** ONGOING OPERATIONAL DEPENDENCY: alias rotation ***
# This script creates index aliases (e.g. suru-zeek-current, suru-suricata-current)
# as part of its one-time provisioning. Those aliases must be rotated DAILY at
# midnight UTC so detectors continue to query today's dated index. Without
# rotation, all detectors silently query yesterday's index and produce no alerts.
#
# Action: schedule tier3-core/scripts/rotate-sa-aliases.sh as a daily cron job
# at 00:10 UTC on the SIEM Docker host. See that script's header for examples.
# Verification: _cat/aliases/suru-zeek-current,suru-suricata-current?v
#
# Wired in by: tier3-core/scripts/deploy.sh (datalake/opensearch group,
#   suru.t3.datalake.securityanalytics-init, after ism-policy-init).
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Log helpers ───────────────────────────────────────────────────────────────

_ts()       { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log_info()  { printf '[%s] [INFO]  %s\n'  "$(_ts)" "$*"; }
log_warn()  { printf '[%s] [WARN]  %s\n'  "$(_ts)" "$*" >&2; }
log_error() { printf '[%s] [ERROR] %s\n'  "$(_ts)" "$*" >&2; }
log_die()   { log_error "$*"; exit 1; }
log_stub()  { printf '[%s] [STUB]  %s\n'  "$(_ts)" "$*"; }

# ── Cleanup trap ──────────────────────────────────────────────────────────────

TMPFILES=()
_cleanup() {
  local f
  for f in "${TMPFILES[@]:-}"; do
    [[ -n "${f}" && -f "${f}" ]] && rm -f -- "${f}"
  done
  return 0
}
trap _cleanup EXIT

_mktemp() {
  local f
  f="$(mktemp)" || log_die "mktemp failed"
  TMPFILES+=("${f}")
  printf '%s' "${f}"
}

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage: apply-security-analytics.sh [--dry-run] [--verbose]

Idempotent import-only provisioner for OpenSearch Security Analytics:
custom log types, the headline correlation rule, and the email trigger
action's Notifications-plugin channels. Detector import is stubbed pending
an upstream OpenSearch custom-rule-create bug — see
tier3-core/docs/security-analytics.md.

Options:
  --dry-run   Print what would be applied; make no API calls.
  --verbose   Print extra diagnostic detail.
  -h, --help  Show this help.

Required env:
  OPENSEARCH_INITIAL_ADMIN_PASSWORD   OpenSearch admin password.

Optional env (defaults shown):
  OS_USER=admin
  OS_HOST=suru-t3-datalake-opensearch
  OS_PORT=9200
  LOGTYPES_DIR=/config/field-mappings        # rendered Layer 3 field-mapping YAML->log-type source
  DETECTORS_DIR=/config/detectors            # rendered Layer 2 detector JSON (T3 output)
  CORRELATIONS_DIR=/config/correlation-rules # rendered Layer 2 correlation JSON (T3 output)
  ACTIONS_DIR=/config/actions                # rendered Layer 2 action JSON (T3 output)
  SECURITY_ANALYTICS_SMTP_HOST / _PORT / _METHOD / _FROM     SMTP transport (see .env.example)
  SECURITY_ANALYTICS_ALERT_EMAIL_TO / _CC                    Email recipients
  MAX_RETRIES=10
  RETRY_DELAY=15
EOF
}

# ── Flags ─────────────────────────────────────────────────────────────────────

DRY_RUN=false
VERBOSE=false

main() {
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --dry-run) DRY_RUN=true ;;
      --verbose) VERBOSE=true ;;
      -h|--help) usage; exit 0 ;;
      *) log_die "Unknown argument: ${arg} (see --help)" ;;
    esac
  done

  : "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?OPENSEARCH_INITIAL_ADMIN_PASSWORD must be set}"
  local pass="${OPENSEARCH_INITIAL_ADMIN_PASSWORD}"

  local os_user="${OS_USER:-admin}"
  local os_host="${OS_HOST:-suru-t3-datalake-opensearch}"
  local os_port="${OS_PORT:-9200}"
  local logtypes_dir="${LOGTYPES_DIR:-/config/field-mappings}"
  local detectors_dir="${DETECTORS_DIR:-/config/detectors}"
  local correlations_dir="${CORRELATIONS_DIR:-/config/correlation-rules}"
  local actions_dir="${ACTIONS_DIR:-/config/actions}"
  local max_retries="${MAX_RETRIES:-10}"
  local retry_delay="${RETRY_DELAY:-15}"

  command -v curl   >/dev/null 2>&1 || log_die "curl is required but not found"
  command -v awk    >/dev/null 2>&1 || log_die "awk is required but not found"
  command -v grep   >/dev/null 2>&1 || log_die "grep is required but not found"
  command -v sed    >/dev/null 2>&1 || log_die "sed is required but not found"
  command -v mktemp >/dev/null 2>&1 || log_die "mktemp is required but not found"
  command -v basename >/dev/null 2>&1 || log_die "basename is required but not found"

  log_info "=== SURU Security Analytics init starting ==="
  log_info "OpenSearch target     : https://${os_host}:${os_port}"
  log_info "Field-mappings dir     : ${logtypes_dir}"
  log_info "Detectors dir          : ${detectors_dir} (import STUBBED — see header)"
  log_info "Correlation-rules dir  : ${correlations_dir}"
  log_info "Actions dir            : ${actions_dir}"
  ${DRY_RUN} && log_info "Mode                   : DRY-RUN (no API calls will be made)"
  ${VERBOSE} && log_info "Mode                   : VERBOSE (extra diagnostic detail)"

  wait_for_opensearch "${os_user}" "${pass}" "${os_host}" "${os_port}" "${max_retries}" "${retry_delay}"

  apply_log_types       "${logtypes_dir}"      "${os_user}" "${pass}" "${os_host}" "${os_port}"
  apply_detectors_stub   "${detectors_dir}"
  apply_correlation_rules "${correlations_dir}" "${os_user}" "${pass}" "${os_host}" "${os_port}"
  apply_actions          "${actions_dir}"       "${os_user}" "${pass}" "${os_host}" "${os_port}"

  log_info "=== Security Analytics init complete ==="
}

# ── wait_for_opensearch ───────────────────────────────────────────────────────

wait_for_opensearch() {
  local os_user="$1" pass="$2" os_host="$3" os_port="$4" max_retries="$5" retry_delay="$6"
  local attempt=0 status

  while [[ "${attempt}" -lt "${max_retries}" ]]; do
    attempt=$(( attempt + 1 ))
    log_info "Waiting for OpenSearch (attempt ${attempt}/${max_retries}) ..."

    status="$(curl -sk -u "${os_user}:${pass}" \
      "https://${os_host}:${os_port}/_cluster/health?pretty" \
      --connect-timeout 5 --max-time 10 \
      | awk -F'"' '/"status"/{print $4; exit}' || true)"

    case "${status}" in
      green|yellow)
        log_info "OpenSearch is ready (status: ${status})"
        return 0
        ;;
      *)
        log_warn "OpenSearch not ready yet (status: '${status}'); retrying in ${retry_delay}s"
        sleep "${retry_delay}"
        ;;
    esac
  done

  log_die "OpenSearch did not become ready after ${max_retries} retries"
}

# ── apply_log_types ───────────────────────────────────────────────────────────
# Registers one custom log type per tier2-telemetry/opensearch/field-mappings/
# *.yml file. Idempotency strategy: create-and-treat-"already exists"-as-success
# (confirmed live: duplicate name -> HTTP 400 "Log Type with name <x> already
# exists" — tier3-core/docs/security-analytics.md). No local state file is
# needed; the plugin itself is authoritative for whether a name exists.
#
# category must be one of the plugin's confirmed display-string enum values
# (e.g. "Network Activity" — confirmed live; "network"/"Network" 400 with an
# empty-reason validation error). All SURU log types map to "Network Activity"
# today since every current source (Zeek, Suricata, pfSense, pfBlockerNG) is
# network telemetry; revisit if a non-network source is added.
# ---------------------------------------------------------------------------

apply_log_types() {
  local dir="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"

  if [[ ! -d "${dir}" ]]; then
    log_warn "Field-mappings directory not found: ${dir} — no log types to register"
    return 0
  fi

  local found=0 f
  for f in "${dir}"/*.yml; do
    [[ -f "${f}" ]] || continue
    found=$(( found + 1 ))
    apply_one_log_type "${f}" "${os_user}" "${pass}" "${os_host}" "${os_port}"
  done

  if [[ "${found}" -eq 0 ]]; then
    log_warn "No field-mapping files found in '${dir}'"
  else
    log_info "Processed ${found} log-type definition(s)"
  fi
}

apply_one_log_type() {
  local mapping_file="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"
  local log_type description

  log_type="$(awk -F': *' '/^log_type:/{print $2; exit}' "${mapping_file}")"
  description="$(awk -F'>' '/^description:/{getline; gsub(/^[ \t]+|[ \t]+$/,""); print; exit}' "${mapping_file}")"

  if [[ -z "${log_type}" ]]; then
    log_warn "No log_type found in '${mapping_file}' — skipping"
    return 0
  fi
  [[ -z "${description}" ]] && description="SURU custom log type (${log_type})"
  ${VERBOSE} && log_info "  (verbose) log_type=${log_type} description=${description}"

  # Skip the endpoint placeholder — no live index exists yet (T1c stub scaffold).
  if [[ "${log_type}" == "suru_endpoint" ]]; then
    log_stub "Skipping log-type '${log_type}' — endpoint telemetry has no live ingestion path yet (T1c stub)"
    return 0
  fi

  log_info "Log type: ${mapping_file} -> ${log_type}"

  if ${DRY_RUN}; then
    log_info "  [dry-run] would POST custom log type '${log_type}' (category: Network Activity)"
    return 0
  fi

  local body_file http_code response_file
  body_file="$(_mktemp)"
  response_file="$(_mktemp)"

  # Escape double quotes in description for safe embedding.
  local esc_desc="${description//\"/\\\"}"
  printf '{"name":"%s","description":"%s","source":"Custom","category":"Network Activity"}\n' \
    "${log_type}" "${esc_desc}" > "${body_file}"

  http_code="$(curl -sk -o "${response_file}" -w '%{http_code}' \
    -X POST -u "${os_user}:${pass}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    "https://${os_host}:${os_port}/_plugins/_security_analytics/logtype")" || true

  case "${http_code}" in
    200|201)
      log_info "OK — log type created (HTTP ${http_code}): ${log_type}"
      ;;
    400)
      if grep -q 'already exists' "${response_file}" 2>/dev/null; then
        log_info "OK — log type already exists (idempotent no-op): ${log_type}"
      else
        log_warn "Log type '${log_type}' rejected (HTTP 400): $(cat -- "${response_file}")"
      fi
      ;;
    401)
      log_die "Unauthorized (HTTP 401) creating log type: ${log_type} — check OS_USER/OPENSEARCH_INITIAL_ADMIN_PASSWORD"
      ;;
    5*)
      log_die "Server error (HTTP ${http_code}) creating log type: ${log_type} — $(cat -- "${response_file}")"
      ;;
    *)
      log_warn "Unexpected response (HTTP ${http_code}) creating log type: ${log_type}"
      ;;
  esac
}

# ── apply_detectors_stub ───────────────────────────────────────────────────────
# STUBBED. See header note + tier3-core/docs/security-analytics.md "Custom
# Sigma rule creation — BLOCKED on a live NullPointerException". Every SURU
# detector binds custom Sigma rule IDs via custom_rules[], and custom-rule
# registration 500s server-side on this OpenSearch 3.7.0.0 build regardless
# of rule body or category. This function only logs visibility — it makes
# no API calls and never fails the script.
# ---------------------------------------------------------------------------

apply_detectors_stub() {
  local dir="$1"

  if [[ ! -d "${dir}" ]]; then
    log_warn "Detectors directory not found: ${dir} — nothing to report"
    return 0
  fi

  local found=0 f name
  for f in "${dir}"/*.json; do
    [[ -f "${f}" ]] || continue
    found=$(( found + 1 ))
    name="$(basename -- "${f}")"
    name="${name%.json}"
    log_stub "Detector '${name}' (${f}) NOT imported — blocked on OpenSearch custom-rule-create NPE (see tier3-core/docs/security-analytics.md 'Custom Sigma rule creation — BLOCKED')"
  done

  if [[ "${found}" -eq 0 ]]; then
    log_warn "No detector files found in '${dir}' — has tier2-telemetry's render-tier3.sh (T3) run yet?"
  else
    log_warn "${found} detector(s) found, 0 imported (all stubbed pending upstream bug resolution)"
  fi
}

# ── apply_correlation_rules ────────────────────────────────────────────────────
# Confirmed-working wire shape: POST /correlation/rules with
# {"name":...,"correlate":[{"index":<concrete-index>,"category":...,"query":...,
# "field":...}, ...]}. Unlike detectors, correlation rules accept concrete
# dated index names directly (no alias workaround needed) — see
# security-analytics.md. Idempotency: search by name via the confirmed
# /correlation/rules/_search endpoint before creating; skip if an exact name
# match already exists (no documented upsert-by-name on this endpoint, so we
# do not attempt an update — re-running after a manual delete is the
# supported path to changing an existing correlation rule).
#
# This script imports each leg's index AS-IS from the rendered JSON's
# `legs[].index_pattern` field, converting the suru-<type>-* wildcard to
# today's concrete dated index (suru-<type>-YYYY.MM.dd) — the same
# constraint correlation-rule create does NOT strictly require (concrete
# index names worked in the live probe) but wildcards were never tried and
# are avoided here out of caution given the detector-side wildcard rejection.
# [STUB: legs[].query/aggregation pass-through for non-trivial multi-leg
# correlation has not been independently live-fire-tested — see
# security-analytics.md "Not yet usable for the SURU headline correlation".]
# ---------------------------------------------------------------------------

apply_correlation_rules() {
  local dir="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"

  if [[ ! -d "${dir}" ]]; then
    log_warn "Correlation-rules directory not found: ${dir} — nothing to apply"
    return 0
  fi

  local found=0 f
  for f in "${dir}"/*.json; do
    [[ -f "${f}" ]] || continue
    found=$(( found + 1 ))
    apply_one_correlation_rule "${f}" "${os_user}" "${pass}" "${os_host}" "${os_port}"
  done

  if [[ "${found}" -eq 0 ]]; then
    log_warn "No correlation-rule files found in '${dir}'"
  else
    log_info "Processed ${found} correlation rule(s)"
  fi
}

apply_one_correlation_rule() {
  local rule_file="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"
  local name today

  name="$(awk -F'"' '/"name":/{print $4; exit}' "${rule_file}")"
  if [[ -z "${name}" ]]; then
    log_warn "No 'name' found in '${rule_file}' — skipping"
    return 0
  fi

  log_info "Correlation rule: ${rule_file} -> ${name}"

  # T3's rendered JSON's leg structure (index_pattern/query/join_field) is a
  # source-of-truth spec, not a literal request body — this is a best-effort
  # translation honoring the index_pattern -> today's-dated-index constraint
  # and the field -> "field" rename. Resolving today's concrete date requires
  # the rendered leg's index_pattern prefix (suru-<type>-) plus today's UTC
  # date, matching the Logstash output index-naming convention
  # (suru-<type>-%{+YYYY.MM.dd}).
  today="$(date -u '+%Y.%m.%d')"

  log_stub "Correlation rule '${name}': each leg's original query predicate (e.g. threat.indicator.type:* AND event.action:\"block\") is NOT transcribed — substituted with a wildcard '*' query per leg, because several legs' queries contain embedded escaped quotes/newlines that cannot be safely round-tripped without a JSON parser in this minimal-tooling container. The rule is created with correct index/category/field bindings but loosened per-leg filtering; tighten manually via the OpenSearch API or a future JSON-aware rewrite of this script before relying on it to suppress unrelated same-IP correlations. See security-analytics.md 'Not yet usable for the SURU headline correlation'."

  local legs_json
  legs_json="$(build_correlation_legs "${rule_file}" "${today}")"
  if [[ -z "${legs_json}" ]]; then
    log_warn "Could not derive any correlation legs from '${rule_file}' — skipping create"
    return 0
  fi
  ${VERBOSE} && log_info "  (verbose) legs: [${legs_json}]"

  if ${DRY_RUN}; then
    log_info "  [dry-run] would check for existing correlation rule '${name}' and create if absent"
    return 0
  fi

  if correlation_rule_exists "${name}" "${os_user}" "${pass}" "${os_host}" "${os_port}"; then
    log_info "OK — correlation rule already exists (idempotent no-op): ${name}"
    return 0
  fi

  local body_file response_file http_code
  body_file="$(_mktemp)"
  response_file="$(_mktemp)"
  printf '{"name":"%s","correlate":[%s]}\n' "${name}" "${legs_json}" > "${body_file}"

  http_code="$(curl -sk -o "${response_file}" -w '%{http_code}' \
    -X POST -u "${os_user}:${pass}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    "https://${os_host}:${os_port}/_plugins/_security_analytics/correlation/rules")" || true

  case "${http_code}" in
    200|201)
      log_info "OK — correlation rule created (HTTP ${http_code}): ${name}"
      ;;
    401)
      log_die "Unauthorized (HTTP 401) creating correlation rule: ${name}"
      ;;
    5*)
      log_die "Server error (HTTP ${http_code}) creating correlation rule: ${name} — $(cat -- "${response_file}")"
      ;;
    *)
      log_warn "Unexpected response (HTTP ${http_code}) creating correlation rule: ${name} — $(cat -- "${response_file}")"
      ;;
  esac
}

# correlation_rule_exists <name> <os_user> <pass> <os_host> <os_port>
# Uses the confirmed-working /correlation/rules/_search endpoint.
correlation_rule_exists() {
  local name="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"
  local body_file response
  body_file="$(_mktemp)"
  printf '{"query":{"match_all":{}}}\n' > "${body_file}"

  response="$(curl -sk -u "${os_user}:${pass}" -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    "https://${os_host}:${os_port}/_plugins/_security_analytics/correlation/rules/_search" || true)"

  printf '%s' "${response}" | grep -q "\"name\":\"${name}\""
}

# build_correlation_legs <rule_file> <today_date>
# Best-effort flattening of the rendered JSON's legs[] array into the
# confirmed-working correlate[] shape: {index, category, query, field}.
#
# Deliberately extracts ONLY the two single-line, single-value scalar fields
# that are safe to pull with a line-oriented sed/grep approach without a real
# JSON parser (index_pattern, join_field) — adequate because the rendered
# files are produced by a trusted, schema-controlled renderer
# (tier2-telemetry/build/lib/render-correlations.sh). The `query` field is
# deliberately NOT transcribed: several rendered legs (see
# pfblockerng-suricata-zeek-c2-chain.json) carry multi-line query strings
# with embedded escaped double-quotes (e.g. `rule.category:(\"A Network
# Trojan...\")`) that cannot be round-tripped correctly with line-oriented
# text tools without risking a malformed request body. Every leg's `query`
# is therefore set to the safe wildcard `*` and the caller logs a [STUB] —
# see the live-fire-confirmation gap already documented in
# security-analytics.md "Not yet usable for the SURU headline correlation".
build_correlation_legs() {
  local rule_file="$1" today="$2"
  local legs=() index_pattern join_field leg_json
  local in_leg=false

  while IFS= read -r line; do
    if printf '%s' "${line}" | grep -q '"id":'; then
      in_leg=true
      index_pattern=""
      join_field=""
    fi
    if ${in_leg} && printf '%s' "${line}" | grep -q '"index_pattern":'; then
      index_pattern="$(printf '%s' "${line}" | sed -n 's/.*"index_pattern": *"\([^"]*\)".*/\1/p')"
    fi
    if ${in_leg} && printf '%s' "${line}" | grep -q '"join_field":'; then
      join_field="$(printf '%s' "${line}" | sed -n 's/.*"join_field": *"\([^"]*\)".*/\1/p')"
      # join_field marks the end of a leg's scalar fields we care about — flush it.
      if [[ -n "${index_pattern:-}" && -n "${join_field:-}" ]]; then
        # Convert suru-<type>-* wildcard to today's concrete dated index, matching
        # the Logstash output naming convention (suru-<type>-%{+YYYY.MM.dd}).
        local concrete_index="${index_pattern/\*/${today}}"
        leg_json="{\"index\":\"${concrete_index}\",\"category\":\"network\",\"query\":\"*\",\"field\":\"${join_field}\"}"
        legs+=("${leg_json}")
        in_leg=false
      fi
    fi
  done < "${rule_file}"

  local IFS=,
  printf '%s' "${legs[*]:-}"
}

# ── apply_actions ──────────────────────────────────────────────────────────────
# email-default.json -> OpenSearch Notifications plugin smtp_account + email
# channel configs (confirmed shape). perimeter-block.json, slack-unconfigured.json,
# webhook-unconfigured.json are logged for visibility only — never sent to any
# OpenSearch endpoint (see header note + actions/README.md).
# ---------------------------------------------------------------------------

apply_actions() {
  local dir="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"

  if [[ ! -d "${dir}" ]]; then
    log_warn "Actions directory not found: ${dir} — nothing to apply"
    return 0
  fi

  local f name
  for f in "${dir}"/*.json; do
    [[ -f "${f}" ]] || continue
    name="$(basename -- "${f}")"
    name="${name%.json}"
    case "${name}" in
      email-default)
        apply_email_action "${f}" "${os_user}" "${pass}" "${os_host}" "${os_port}"
        ;;
      perimeter-block)
        log_info "Action '${name}' recorded for operator visibility only — perimeter_block is a SURU-internal concept (calls Tier 1's api.sh), never sent to OpenSearch. Opt-in is per-detector (tier2-telemetry/opensearch/detectors/*.yml actions.perimeter_block: true), not configured here."
        ;;
      slack-unconfigured|webhook-unconfigured)
        log_info "Action '${name}' is intentionally unconfigured (schema-present only, per tier2-telemetry/opensearch/actions/README.md) — not provisioned."
        ;;
      *)
        log_warn "Unrecognized action file '${f}' — skipping (no handler for this action type)"
        ;;
    esac
  done
}

# apply_email_action <action_file> <os_user> <pass> <os_host> <os_port>
# Requires SECURITY_ANALYTICS_SMTP_HOST to be set (non-empty) — otherwise the
# operator has left SMTP unconfigured (SECURITY_ANALYTICS_SMTP_METHOD=none per
# .env.example) and this is a deliberate no-op, not an error.
# _reload_secure_settings <os_user> <admin_pass> <os_host> <os_port>
# Make on-disk keystore changes live on the running node (no restart). The
# notifications-core plugin is a ReloadablePlugin, so its SMTP AUTH is re-derived
# from the reloaded keystore.
_reload_secure_settings() {
  local os_user="$1" admin_pass="$2" os_host="$3" os_port="$4"
  local response_file http_code
  response_file="$(_mktemp)"
  http_code="$(curl -sk -o "${response_file}" -w '%{http_code}' \
    -X POST -u "${os_user}:${admin_pass}" \
    "https://${os_host}:${os_port}/_nodes/reload_secure_settings")" || true
  case "${http_code}" in
    200) log_info "OK — reloaded secure settings" ;;
    *)   log_warn "reload_secure_settings returned HTTP ${http_code} — keystore updated but the node may not have reloaded: $(cat -- "${response_file}")" ;;
  esac
}

# provision_smtp_keystore_auth <account> <username> <password> <os_user> <admin_pass> <os_host> <os_port>
# The OpenSearch Notifications plugin reads SMTP AUTH credentials from the node
# keystore as AffixSettings — opensearch.notifications.core.email.<account>.username
# and .password (the smtp_account config JSON cannot carry the secret).
# <account> is the smtp_account config's own name (SmtpDestination.accountName ==
# the config name). Both keys are written via stdin (no argv/ps exposure) then
# reload_secure_settings makes the running node pick them up without a restart.
# Requires the opensearch image (opensearch-keystore on PATH) with the shared
# opensearch-config volume mounted rw. Empty username/password => provision the
# account WITHOUT AUTH (unauthenticated relay / method=none).
provision_smtp_keystore_auth() {
  local account="$1" username="$2" password="$3" os_user="$4" admin_pass="$5" os_host="$6" os_port="$7"

  if ! command -v opensearch-keystore >/dev/null 2>&1; then
    log_warn "opensearch-keystore not on PATH — cannot manage SMTP AUTH in the keystore (authenticated email will fail). This step must run in the opensearch image with the opensearch-config volume mounted rw."
    return 0
  fi

  local kprefix="opensearch.notifications.core.email.${account}"

  # Blanked credentials => tear down any previously-provisioned AUTH so an
  # operator falling back to an unauthenticated relay isn't silently left with
  # stale keystore creds. Only reload if something was actually removed.
  if [[ -z "${username}" || -z "${password}" ]]; then
    if opensearch-keystore list 2>/dev/null | grep -qx "${kprefix}.username"; then
      log_info "SMTP username/password unset — removing stale keystore AUTH (${kprefix}.*)"
      opensearch-keystore remove "${kprefix}.username" 2>/dev/null || true
      opensearch-keystore remove "${kprefix}.password" 2>/dev/null || true
      _reload_secure_settings "${os_user}" "${admin_pass}" "${os_host}" "${os_port}"
    else
      log_info "SMTP username/password not set — smtp_account provisioned WITHOUT keystore AUTH (relay must accept unauthenticated relay or method=none)"
    fi
    return 0
  fi

  log_info "Provisioning SMTP AUTH into OpenSearch keystore: ${kprefix}.{username,password}"

  # Secrets are fed via stdin (never argv/URL/sed), so no charset splicing risk;
  # keep them out of any xtrace regardless. A failure after the .username write
  # leaves a half-provisioned pair, but the next --force run self-heals it.
  set +x
  if ! printf '%s' "${username}" | opensearch-keystore add --stdin --force "${kprefix}.username" 2>/dev/null; then
    log_warn "Failed to write ${kprefix}.username — email AUTH not provisioned"
    return 0
  fi
  if ! printf '%s' "${password}" | opensearch-keystore add --stdin --force "${kprefix}.password" 2>/dev/null; then
    log_warn "Failed to write ${kprefix}.password — email AUTH not provisioned (partial: .username written, will self-heal on re-run)"
    return 0
  fi

  _reload_secure_settings "${os_user}" "${admin_pass}" "${os_host}" "${os_port}"
}

apply_email_action() {
  local action_file="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"

  local smtp_host="${SECURITY_ANALYTICS_SMTP_HOST:-}"
  if [[ -z "${smtp_host}" ]]; then
    log_warn "SECURITY_ANALYTICS_SMTP_HOST is unset — email action left unconfigured (SMTP not provisioned, no operator action taken)"
    return 0
  fi

  local smtp_port="${SECURITY_ANALYTICS_SMTP_PORT:-587}"
  local smtp_method="${SECURITY_ANALYTICS_SMTP_METHOD:-start_tls}"
  local smtp_from="${SECURITY_ANALYTICS_SMTP_FROM:-siem@suru.local}"
  local alert_to="${SECURITY_ANALYTICS_ALERT_EMAIL_TO:-}"

  if [[ -z "${alert_to}" ]]; then
    log_warn "SECURITY_ANALYTICS_ALERT_EMAIL_TO is unset — email action left unconfigured (no recipient)"
    return 0
  fi

  log_info "Email action: ${action_file} -> smtp_account + email channel (host: ${smtp_host})"

  local smtp_username="${SECURITY_ANALYTICS_SMTP_USERNAME:-}"
  local smtp_password="${SECURITY_ANALYTICS_SMTP_PASSWORD:-}"

  if ${DRY_RUN}; then
    log_info "  [dry-run] would provision keystore SMTP AUTH (if username/password set) + reload, then create/verify smtp_account + email Notifications channel"
    return 0
  fi

  local smtp_channel_name="suru_security_analytics_smtp"
  local email_channel_name="suru_security_analytics_email"

  # Write SMTP AUTH creds to the keystore BEFORE the account is used, keyed by
  # the smtp_account name (== SmtpDestination.accountName). Idempotent/rotation-
  # safe (--force), and runs whether or not the account already exists.
  provision_smtp_keystore_auth "${smtp_channel_name}" "${smtp_username}" "${smtp_password}" "${os_user}" "${pass}" "${os_host}" "${os_port}"

  local smtp_id
  smtp_id="$(notifications_config_id_by_name "${smtp_channel_name}" "${os_user}" "${pass}" "${os_host}" "${os_port}")" || true

  if [[ -z "${smtp_id}" ]]; then
    local body_file response_file http_code
    body_file="$(_mktemp)"
    response_file="$(_mktemp)"
    printf '{"config":{"name":"%s","description":"SURU Security Analytics SMTP relay","config_type":"smtp_account","is_enabled":true,"smtp_account":{"from_address":"%s","host":"%s","port":%s,"method":"%s"}}}\n' \
      "${smtp_channel_name}" "${smtp_from}" "${smtp_host}" "${smtp_port}" "${smtp_method}" > "${body_file}"

    http_code="$(curl -sk -o "${response_file}" -w '%{http_code}' \
      -X POST -u "${os_user}:${pass}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${body_file}" \
      "https://${os_host}:${os_port}/_plugins/_notifications/configs")" || true

    case "${http_code}" in
      200)
        smtp_id="$(awk -F'"' '/"config_id"/{print $4; exit}' "${response_file}")"
        log_info "OK — smtp_account channel created (HTTP 200): ${smtp_channel_name} (${smtp_id})"
        ;;
      401)
        log_die "Unauthorized (HTTP 401) creating smtp_account channel"
        ;;
      5*)
        log_die "Server error (HTTP ${http_code}) creating smtp_account channel — $(cat -- "${response_file}")"
        ;;
      *)
        log_warn "Unexpected response (HTTP ${http_code}) creating smtp_account channel — $(cat -- "${response_file}")"
        return 0
        ;;
    esac
  else
    log_info "OK — smtp_account channel already exists (idempotent no-op): ${smtp_channel_name} (${smtp_id})"
  fi

  if [[ -z "${smtp_id}" ]]; then
    log_warn "No smtp_account config_id available — skipping email channel creation"
    return 0
  fi

  local email_id
  email_id="$(notifications_config_id_by_name "${email_channel_name}" "${os_user}" "${pass}" "${os_host}" "${os_port}")" || true

  if [[ -n "${email_id}" ]]; then
    log_info "OK — email channel already exists (idempotent no-op): ${email_channel_name} (${email_id})"
    return 0
  fi

  local body_file response_file http_code
  body_file="$(_mktemp)"
  response_file="$(_mktemp)"
  printf '{"config":{"name":"%s","description":"SURU Security Analytics alert recipients","config_type":"email","is_enabled":true,"email":{"email_account_id":"%s","recipient_list":[{"recipient":"%s"}]}}}\n' \
    "${email_channel_name}" "${smtp_id}" "${alert_to}" > "${body_file}"

  http_code="$(curl -sk -o "${response_file}" -w '%{http_code}' \
    -X POST -u "${os_user}:${pass}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${body_file}" \
    "https://${os_host}:${os_port}/_plugins/_notifications/configs")" || true

  case "${http_code}" in
    200)
      log_info "OK — email channel created (HTTP 200): ${email_channel_name}"
      ;;
    401)
      log_die "Unauthorized (HTTP 401) creating email channel"
      ;;
    5*)
      log_die "Server error (HTTP ${http_code}) creating email channel — $(cat -- "${response_file}")"
      ;;
    *)
      log_warn "Unexpected response (HTTP ${http_code}) creating email channel — $(cat -- "${response_file}")"
      ;;
  esac
}

# notifications_config_id_by_name <name> <os_user> <pass> <os_host> <os_port>
# Best-effort name lookup against the Notifications plugin's config list
# (GET /_plugins/_notifications/configs -> {"config_list":[{"config_id":...,
# "config":{"name":...}}]} — confirmed live shape; "name" is nested under
# "config", NOT adjacent to "config_id", so each config_list entry is
# extracted as a whole object before searching it for the target name).
# Prints the config_id if found, empty string otherwise. No documented
# "search by exact name" filter was confirmed live this session — adequate
# for the small, fixed set of SURU-managed channel names.
notifications_config_id_by_name() {
  local name="$1" os_user="$2" pass="$3" os_host="$4" os_port="$5"
  local response
  response="$(curl -sk -u "${os_user}:${pass}" \
    "https://${os_host}:${os_port}/_plugins/_notifications/configs" || true)"

  # Split on `{"config_id"` object boundaries, then keep only the one entry
  # (if any) whose embedded config.name matches exactly, and extract its id.
  printf '%s' "${response}" \
    | sed 's/{"config_id"/\n{"config_id"/g' \
    | grep "\"name\":\"${name}\"" \
    | head -1 \
    | sed -n 's/.*"config_id":"\([^"]*\)".*/\1/p'
}

main "$@"
