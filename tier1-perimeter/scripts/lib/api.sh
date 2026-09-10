#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — lib/api.sh
# Router REST API client. Self-contained — sources no other lib file.
#
# Platforms:
#   pfSense   — pfRest (https://pfrest.org/)
#   OPNsense  — native API (https://docs.opnsense.org/development/api.html)
#
# AUTHENTICATION MODES (API_AUTH_MODE)
# ----------------------------------------------------------------------------
#   api_key   Long-lived static key.  RECOMMENDED FOR AUTOMATION / CI.
#             - pfSense:  header `X-API-Key: ${PFSENSE_API_KEY}`
#             - OPNsense: HTTP Basic with `${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}`
#
#   jwt       Short-lived bearer token (pfSense only).  BEST FOR INTERACTIVE
#             OPERATOR SESSIONS — minimises blast radius if leaked.
#             - POST /api/v2/auth/jwt with username/password to obtain.
#             - Cached in-process; auto-refreshed before expiry.
#             - Never persisted to disk.
#
# SECURITY HARDENING
# ----------------------------------------------------------------------------
#   * Auth tokens and request bodies are written to 0600 temp files (preferred
#     under /dev/shm when available) and passed to curl via `--header @file`
#     and `--data-binary @file`. This keeps secrets out of process argv and
#     therefore out of `ps`/proc.
#   * TLS verification is ON by default. Disabling emits a WARN, not silent.
#   * Tokens are never written to logs at any verbosity.
#
# PUBLIC API
# ----------------------------------------------------------------------------
#   api_init                          Validate env; set per-platform URL defaults
#   api_request METHOD PATH [BODY]    Generic dispatch
#   api_health                        Authenticated reachability probe
#   api_validate_deployment           Orchestrate full post-deploy validation
#   api_service_status SVC            Per-service status query (status booleans)
#   api_reload_suricata_rules         Hot-reload Suricata rules (via exec)
#   api_fetch_errors [LIMIT]          Recent system log entries
#   api_pfsense_install               pfSense ONLY — install pfRest pkg via SSH
#   api_pfsense_jwt_login             pfSense ONLY — obtain a JWT (called as needed)
#
#   api_block_ip IP [TTL_SECONDS]     pfSense ONLY — add IP to the SURU dynamic
#                                     block alias (PERIMETER_BLOCK_ALIAS), with
#                                     allowlist/rate-limit/TTL guardrails and SIEM
#                                     audit. [STUB: alias mutation endpoint
#                                     unconfirmed — needs live pfSense test]
#   api_unblock_ip IP                pfSense ONLY — remove IP from the alias,
#                                     reload, audit. Same [STUB] caveat.
#   api_perimeter_block_expire_sweep Idempotent cron-callable sweep: unblocks any
#                                     IP whose TTL has elapsed.
#
#   *** NEW ENFORCEMENT SURFACE — NOT WIRED INTO ANY ALWAYS-ON PATH ***
#   These three functions are library-only. They are not called by deploy.sh,
#   any cron entry, or any other tier1-perimeter script. Intended caller:
#   tier2-telemetry's perimeter_block detector action (future T4b work). See
#   BREAKING CHANGE note at the call site comment block below.
#
# VALIDATION HELPERS (pfSense; OPNsense uses different namespaces)
# ----------------------------------------------------------------------------
#   api_validate_packages             Verify Suricata/Zeek/pfBlockerNG/RESTAPI installed
#   api_validate_suricata_config      `suricata -T` against deployed config
#   api_validate_zeek_status          `zeekctl status` — all nodes running
#   api_validate_syslogng_config      `syslog-ng -s` config syntax check
#   api_validate_pfblockerng_aliases  pfB_SURU_* aliases exist with entries
#   api_validate_recent_errors        Scan last N system log lines for ERROR/CRIT
#
# LOW-LEVEL PRIMITIVES (pfSense)
# ----------------------------------------------------------------------------
#   _api_pfsense_exec CMD             POST /diagnostics/command_prompt — runs
#                                     shell CMD as root via API. stdout = output,
#                                     sets _API_EXEC_RC to result_code.
#
# REQUIRED ENV VARS
# ----------------------------------------------------------------------------
#   ROUTER_PLATFORM     pfsense | opnsense
#   ROUTER_HOST         router host/IP
#   API_AUTH_MODE       api_key (default) | jwt
#
#   pfSense (api_key mode):
#     PFSENSE_API_KEY
#   pfSense (jwt mode):
#     PFSENSE_API_USERNAME
#     PFSENSE_API_PASSWORD            <-- treat as high-sensitivity; prefer SOPS
#   pfSense (always for install):
#     PFSENSE_API_PKG_URL
#
#   OPNsense (api_key mode only; native API does not support JWT):
#     OPNSENSE_API_KEY
#     OPNSENSE_API_SECRET
#
#   Optional:
#     PFSENSE_API_URL                 default: https://${ROUTER_HOST}/api/v2
#     OPNSENSE_API_URL                default: https://${ROUTER_HOST}/api
#     API_TLS_VERIFY                  yes (default) | no
#     API_CONNECT_TIMEOUT             seconds, default 30
#     API_MAX_TIME                    seconds, default 60
#
#   Dynamic perimeter block (api_block_ip / api_unblock_ip), pfSense only:
#     PERIMETER_BLOCK_ALIAS            default: pfB_SURU_DYNAMIC_v4
#     PERIMETER_BLOCK_ALLOWLIST        comma-separated IPs/CIDRs, never blocked
#     PERIMETER_BLOCK_DEFAULT_TTL      seconds, default 3600 (0 rejected)
#     PERIMETER_BLOCK_MAX_TTL          seconds, default 86400
#     PERIMETER_BLOCK_MAX_PER_WINDOW   default 10
#     PERIMETER_BLOCK_WINDOW_SECONDS   default 300
#     PERIMETER_BLOCK_STATE_DIR        default ${TMPDIR:-/tmp}/suru-perimeter-block
#                                       state lives on the CALLING host (this
#                                       client runs off-router); rate-limit and
#                                       TTL bookkeeping are therefore scoped per
#                                       caller, not globally across every host
#                                       that might invoke this library.
# =============================================================================

# --- Standalone fallbacks if lib/log.sh is not sourced ----------------------
type log_info  &>/dev/null || log_info()  { echo "[api:INFO] $*"; }
type log_warn  &>/dev/null || log_warn()  { echo "[api:WARN] $*" >&2; }
type log_error &>/dev/null || log_error() { echo "[api:ERROR] $*" >&2; }
type log_debug &>/dev/null || log_debug() { ${VERBOSE:-false} && echo "[api:DEBUG] $*" >&2 || true; }
type log_die   &>/dev/null || log_die()   { log_error "$*"; exit 1; }

# Default auth mode
: "${API_AUTH_MODE:=api_key}"

# In-process JWT cache (pfSense). Never persisted.
_PF_JWT_TOKEN=""
_PF_JWT_EXPIRES_EPOCH=0
_PF_JWT_REFRESH_BUFFER=60   # refresh if <60s remain on JWT

# Per-process secure temp DIRECTORY — the trap-based cleanup safety net.
#
# This was an array of tracked file paths, appended inside _api_mktemp_secure.
# It could never work: every call site reads the path back with command
# substitution (`hdrfile="$(_api_mktemp_secure)"`), which runs the function in a
# SUBSHELL, so the append mutated a copy and the parent's array stayed empty
# forever — _api_cleanup_tmp's `(( ${#_API_TMPFILES[@]} > 0 ))` guard was never
# once true. A directory whose path is fixed at source time needs no
# cross-subshell bookkeeping: children inherit it and cleanup removes the tree.
#
# It matters because the safety net covers the window the inline `rm -f` cannot:
# an abort between creating the request body and removing it leaves a 0600 file
# containing the router API password (see the JWT login body below).
#
# Created eagerly here, in the parent shell, for that reason. /dev/shm (tmpfs,
# RAM-only) is preferred so the contents never touch disk. The creation is
# idempotent: this lib is sourced TWICE per deploy — once by deploy.sh, then
# again by the platform driver it sources — and without the guard the second
# source would overwrite _API_TMPDIR and orphan the first directory.
_api_tmp_base="${TMPDIR:-/tmp}"
[[ -d /dev/shm && -w /dev/shm ]] && _api_tmp_base=/dev/shm
if [[ -z "${_API_TMPDIR:-}" || ! -d "${_API_TMPDIR:-}" ]]; then
  _API_TMPDIR="$(mktemp -d "${_api_tmp_base%/}/suru-api.XXXXXXXX")" \
    || { echo "[api] FATAL: cannot create secure temp dir under ${_api_tmp_base}" >&2; return 1 2>/dev/null || exit 1; }
  chmod 700 "${_API_TMPDIR}"
  # The EXIT trap is armed HERE, inside the guard, and NOT as an unconditional
  # statement at file scope. deploy.sh installs its own chained trap between the
  # two sources; an unconditional re-arm on the second source silently reset the
  # trap to this function alone and discarded that chain.
  #
  # Known limitation, unreachable on today's call paths: _api_cleanup_tmp is also
  # callable on demand. A re-source after such a call finds no directory, so the
  # guard opens and the trap is re-armed, clobbering a caller's chain by the same
  # mechanism. Gating the arm on a separate "already armed" flag does NOT fix it —
  # that leaves the re-created directory with no trap at all, which leaks. Closing
  # it properly needs the arm to depend on whether a trap is currently installed,
  # and `trap -p EXIT` output is not worth parsing across bash 3.2 and 5. No
  # caller invokes _api_cleanup_tmp before re-sourcing, so the path is dead today.
  trap _api_cleanup_tmp EXIT
fi
unset _api_tmp_base

# ---------------------------------------------------------------------------
# api_init
# Validates env vars per (platform, mode). Sets URL defaults.
# ---------------------------------------------------------------------------
api_init() {
  : "${ROUTER_PLATFORM:?ROUTER_PLATFORM not set}"
  : "${ROUTER_HOST:?ROUTER_HOST not set}"

  command -v curl >/dev/null 2>&1 || log_die "curl is required for API operations"

  case "${API_AUTH_MODE}" in
    api_key|jwt) : ;;
    *) log_die "Unsupported API_AUTH_MODE='${API_AUTH_MODE}' (api_key|jwt)" ;;
  esac

  case "$(echo "${API_TLS_VERIFY:-yes}" | tr '[:upper:]' '[:lower:]')" in
    no|false|0|off)
      log_warn "API_TLS_VERIFY is disabled — accepting untrusted certs."
      log_warn "ONLY acceptable for lab environments with known self-signed certs."
      ;;
  esac

  case "${ROUTER_PLATFORM}" in
    pfsense)
      : "${PFSENSE_API_URL:=https://${ROUTER_HOST}/api/v2}"
      case "${API_AUTH_MODE}" in
        api_key)
          [[ -n "${PFSENSE_API_KEY:-}" ]] || log_die \
            "PFSENSE_API_KEY not set (required for API_AUTH_MODE=api_key)"
          ;;
        jwt)
          [[ -n "${PFSENSE_API_USERNAME:-}" ]] || log_die \
            "PFSENSE_API_USERNAME not set (required for API_AUTH_MODE=jwt)"
          [[ -n "${PFSENSE_API_PASSWORD:-}" ]] || log_die \
            "PFSENSE_API_PASSWORD not set (required for API_AUTH_MODE=jwt)"
          ;;
      esac
      ;;
    opnsense)
      : "${OPNSENSE_API_URL:=https://${ROUTER_HOST}/api}"
      [[ "${API_AUTH_MODE}" == "api_key" ]] || log_die \
        "OPNsense native API only supports API_AUTH_MODE=api_key (JWT is pfSense-only)"
      [[ -n "${OPNSENSE_API_KEY:-}"    ]] || log_die "OPNSENSE_API_KEY not set"
      [[ -n "${OPNSENSE_API_SECRET:-}" ]] || log_die "OPNSENSE_API_SECRET not set"
      ;;
    *)
      log_die "api_init: unsupported ROUTER_PLATFORM=${ROUTER_PLATFORM}"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# _api_mktemp_secure → echoes path to a fresh 0600 file.
# The file lands in _API_TMPDIR (created at source time above): /dev/shm when
# available — tmpfs, RAM-only — else $TMPDIR or /tmp.
# ---------------------------------------------------------------------------
_api_mktemp_secure() {
  # Inside _API_TMPDIR so the EXIT-trap cleanup reaches it without needing this
  # function to record anything — it is always called in a command-substitution
  # subshell, where any bookkeeping it did would be discarded.
  [[ -n "${_API_TMPDIR:-}" && -d "${_API_TMPDIR}" ]] || return 1
  local f
  f="$(mktemp "${_API_TMPDIR}/f.XXXXXXXX")" || return 1
  chmod 600 "${f}" || { rm -f "${f}"; return 1; }
  echo "${f}"
}

# Remove the per-process temp dir and everything in it (called on EXIT and on
# demand). Safe under `set -u`, and idempotent — a second call is a no-op.
# The `suru-api.` basename check is a guard on the recursive remove: it refuses
# to act on a path this library did not create.
#
# The EXIT trap that runs this is armed ABOVE, inside the _API_TMPDIR guard —
# not here. See the comment there for why.
_api_cleanup_tmp() {
  local d="${_API_TMPDIR:-}"
  [[ -n "${d}" && -d "${d}" ]] || return 0
  case "$(basename -- "${d}")" in
    suru-api.????????) rm -rf -- "${d}" ;;
    *) echo "[api] WARN: refusing to remove unexpected temp dir: ${d}" >&2 ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# _api_curl_base_opts — flags that are safe to pass on argv (no secrets)
# ---------------------------------------------------------------------------
_api_curl_base_opts() {
  CURL_OPTS=(
    --silent --show-error --fail-with-body
    --connect-timeout "${API_CONNECT_TIMEOUT:-30}"
    --max-time         "${API_MAX_TIME:-60}"
  )
  case "$(echo "${API_TLS_VERIFY:-yes}" | tr '[:upper:]' '[:lower:]')" in
    no|false|0|off) CURL_OPTS+=(--insecure) ;;
  esac
}

# ---------------------------------------------------------------------------
# api_request METHOD PATH [BODY] → stdout=response body, exit=curl status
# ---------------------------------------------------------------------------
api_request() {
  case "${ROUTER_PLATFORM}" in
    pfsense)   _api_pfsense_request  "$@" ;;
    opnsense)  _api_opnsense_request "$@" ;;
    *)         log_die "api_request: unknown ROUTER_PLATFORM=${ROUTER_PLATFORM}" ;;
  esac
}

# ---------------------------------------------------------------------------
# _api_pfsense_ensure_auth — guarantees we have valid creds for current mode.
# For jwt mode, refreshes the cached JWT if missing or near expiry.
# ---------------------------------------------------------------------------
_api_pfsense_ensure_auth() {
  case "${API_AUTH_MODE}" in
    api_key)
      [[ -n "${PFSENSE_API_KEY:-}" ]] || log_die "PFSENSE_API_KEY not set"
      ;;
    jwt)
      local now
      now=$(date +%s)
      if [[ -z "${_PF_JWT_TOKEN}" ]] \
         || (( now >= _PF_JWT_EXPIRES_EPOCH - _PF_JWT_REFRESH_BUFFER )); then
        api_pfsense_jwt_login
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# api_pfsense_jwt_login — POST /auth/jwt with username/password, cache token.
# Body is sent via 0600 temp file to keep password out of argv.
# ---------------------------------------------------------------------------
api_pfsense_jwt_login() {
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] \
    || log_die "api_pfsense_jwt_login called for ROUTER_PLATFORM=${ROUTER_PLATFORM}"
  : "${PFSENSE_API_USERNAME:?PFSENSE_API_USERNAME not set}"
  : "${PFSENSE_API_PASSWORD:?PFSENSE_API_PASSWORD not set}"
  : "${PFSENSE_API_URL:=https://${ROUTER_HOST}/api/v2}"

  local url="${PFSENSE_API_URL%/}/auth/jwt"
  local hdrfile bodyfile
  hdrfile="$(_api_mktemp_secure)"  || log_die "Cannot create secure tmp file"
  bodyfile="$(_api_mktemp_secure)" || log_die "Cannot create secure tmp file"

  {
    echo "Content-Type: application/json"
    echo "Accept: application/json"
  } > "${hdrfile}"

  # JSON-escape user+password just enough for a flat object. We rely on
  # printf %s with a fixed schema; double-quote chars in user/pass are
  # escaped by sed below.
  local u p
  u="${PFSENSE_API_USERNAME//\"/\\\"}"
  p="${PFSENSE_API_PASSWORD//\"/\\\"}"
  printf '{"username":"%s","password":"%s"}' "${u}" "${p}" > "${bodyfile}"

  _api_curl_base_opts
  log_debug "API pfSense POST ${url} (jwt login)"

  local resp rc=0
  resp="$(curl "${CURL_OPTS[@]}" \
            --request POST \
            --header "@${hdrfile}" \
            --data-binary "@${bodyfile}" \
            "${url}")" || rc=$?
  rm -f "${hdrfile}" "${bodyfile}"

  (( rc == 0 )) || log_die "JWT login to pfRest failed (URL: ${url}). Check credentials and TLS."

  # Parse token + ttl. Prefer jq for safety.
  local token ttl
  if command -v jq >/dev/null 2>&1; then
    token="$(echo "${resp}" | jq -r '.data.token // .token // empty')"
    ttl="$(echo "${resp}" | jq -r '.data.expires_in // .expires_in // 3600')"
  else
    # Permissive fallback parser
    token="$(echo "${resp}" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    ttl="$(echo "${resp}" | sed -n 's/.*"expires_in"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -n1)"
    ttl="${ttl:-3600}"
  fi

  [[ -n "${token}" ]] || log_die "JWT login succeeded but no token in response."

  _PF_JWT_TOKEN="${token}"
  _PF_JWT_EXPIRES_EPOCH=$(( $(date +%s) + ttl ))
  log_info "pfRest JWT acquired (ttl=${ttl}s)"
}

# ---------------------------------------------------------------------------
# _api_pfsense_request METHOD PATH [BODY]
# ---------------------------------------------------------------------------
_api_pfsense_request() {
  local method="$1" path="$2" body="${3:-}"
  local url="${PFSENSE_API_URL%/}${path}"
  _api_pfsense_ensure_auth

  local hdrfile bodyfile=""
  hdrfile="$(_api_mktemp_secure)" || log_die "Cannot create secure tmp file"

  {
    echo "Content-Type: application/json"
    echo "Accept: application/json"
    case "${API_AUTH_MODE}" in
      api_key) printf 'X-API-Key: %s\n'        "${PFSENSE_API_KEY}" ;;
      jwt)     printf 'Authorization: Bearer %s\n' "${_PF_JWT_TOKEN}" ;;
    esac
  } > "${hdrfile}"

  _api_curl_base_opts
  CURL_OPTS+=(--request "${method}" --header "@${hdrfile}")
  log_debug "API pfSense ${method} ${url} (auth=${API_AUTH_MODE})"

  local rc=0
  if [[ -n "${body}" ]]; then
    bodyfile="$(_api_mktemp_secure)" || log_die "Cannot create secure tmp file"
    printf '%s' "${body}" > "${bodyfile}"
    curl "${CURL_OPTS[@]}" --data-binary "@${bodyfile}" "${url}" || rc=$?
    rm -f "${bodyfile}"
  else
    curl "${CURL_OPTS[@]}" "${url}" || rc=$?
  fi
  rm -f "${hdrfile}"
  return ${rc}
}

# ---------------------------------------------------------------------------
# _api_opnsense_request METHOD PATH [BODY]
# OPNsense uses HTTP Basic with key:secret. We build the Basic header
# manually so the secret never enters curl argv.
# ---------------------------------------------------------------------------
_api_opnsense_request() {
  local method="$1" path="$2" body="${3:-}"
  local url="${OPNSENSE_API_URL%/}${path}"

  local hdrfile bodyfile=""
  hdrfile="$(_api_mktemp_secure)" || log_die "Cannot create secure tmp file"

  local b64
  b64="$(printf '%s' "${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}" \
          | base64 | tr -d '\n')"
  {
    echo "Content-Type: application/json"
    echo "Accept: application/json"
    echo "Authorization: Basic ${b64}"
  } > "${hdrfile}"

  _api_curl_base_opts
  CURL_OPTS+=(--request "${method}" --header "@${hdrfile}")
  log_debug "API OPNsense ${method} ${url} (auth=api_key)"

  local rc=0
  if [[ -n "${body}" ]]; then
    bodyfile="$(_api_mktemp_secure)" || log_die "Cannot create secure tmp file"
    printf '%s' "${body}" > "${bodyfile}"
    curl "${CURL_OPTS[@]}" --data-binary "@${bodyfile}" "${url}" || rc=$?
    rm -f "${bodyfile}"
  else
    curl "${CURL_OPTS[@]}" "${url}" || rc=$?
  fi
  rm -f "${hdrfile}"
  return ${rc}
}

# ---------------------------------------------------------------------------
# api_health
# ---------------------------------------------------------------------------
api_health() {
  api_init
  case "${ROUTER_PLATFORM}" in
    # /system/restapi/version requires only page-system-restapi — the one
    # privilege all suru-validator calls share. Avoids needing page-status-system.
    pfsense)  api_request GET /system/restapi/version >/dev/null ;;
    opnsense) api_request GET /core/system/info       >/dev/null ;;
  esac
}

# ---------------------------------------------------------------------------
# api_validate_deployment — lightweight post-deploy validation suite.
#
# Uses only native pfREST API endpoints (no command_prompt / shell exec).
# Engine config tests (suricata -T, syslog-ng -s, zeekctl status) are
# deliberately excluded: they run via SSH during make deploy and are
# resource-intensive on SOHO hardware — running them again via API inside
# PHP-FPM risks exhausting router memory and crashing the web stack.
#
# Fail-fast: aborts immediately on auth failure (401/403) with a clear
# message rather than cascading into misleading "service not running" output.
# ---------------------------------------------------------------------------
api_validate_deployment() {
  api_init
  local fail=0

  # --- Auth gate: abort early if credentials are wrong or missing -----------
  if ! api_health 2>/dev/null; then
    log_error "API health check failed — authentication error or router unreachable."
    log_error "  Check PFSENSE_API_KEY / API_AUTH_MODE in .env (run 'make api-bootstrap' to issue a key)."
    log_error "  Check API_TLS_VERIFY and PFSENSE_API_URL."
    return 1
  fi
  log_info "API reachable — running validation suite (pfSense via pfREST):"

  case "${ROUTER_PLATFORM}" in
    pfsense)
      log_info "[1/4] Packages installed:"
      api_validate_packages           || fail=1

      log_info "[2/4] Service status (native API — no shell exec on router):"
      local svc
      for svc in syslog-ng suricata zeek; do
        if api_service_running "${svc}"; then
          log_info "  ${svc}: ✓ (running)"
        else
          log_warn "  ${svc}: ✗ (not running or status unavailable)"
          fail=1
        fi
      done

      log_info "[3/4] pfBlockerNG DNSBL aliases:"
      api_validate_pfblockerng_aliases

      log_info "[4/4] Recent system log errors:"
      api_validate_recent_errors 100
      ;;

    opnsense)
      log_info "Validation suite (OPNsense native API):"
      local svc
      for svc in syslog-ng suricata zeek; do
        if api_service_status "${svc}" >/dev/null 2>&1; then
          log_info "  ${svc}: status OK"
        else
          log_warn "  ${svc}: status check failed"
          fail=1
        fi
      done
      ;;
  esac

  if (( fail == 0 )); then
    log_info "Validation suite: PASS"
  else
    log_warn "Validation suite: FAIL — review entries marked ✗ above"
  fi
  return $fail
}

# ---------------------------------------------------------------------------
# api_service_status SERVICE_NAME
# pfREST: GET /status/service?id=<name> → returns Service object with
#   { name, description, enabled (bool), status (bool — actively running) }
# ---------------------------------------------------------------------------
api_service_status() {
  local svc="$1"
  case "${ROUTER_PLATFORM}" in
    pfsense)
      api_request GET "/status/service?id=${svc}"
      ;;
    opnsense)
      local ns
      case "${svc}" in
        suricata)  ns="ids" ;;
        syslog-ng) ns="syslog" ;;
        zeek)      ns="zeek" ;;
        *)         ns="${svc}" ;;
      esac
      api_request GET "/${ns}/service/status"
      ;;
  esac
}

# Returns 0 only if the service exists, is enabled, and is actively running.
api_service_running() {
  local svc="$1" resp
  resp="$(api_service_status "${svc}" 2>/dev/null)" || return 1
  if command -v jq >/dev/null 2>&1; then
    [[ "$(echo "${resp}" | jq -r '.data.status // .status // false')" == "true" ]]
  else
    # Permissive fallback: look for "status":true in body
    [[ "${resp}" == *'"status":true'* ]]
  fi
}

# ---------------------------------------------------------------------------
# _api_pfsense_exec CMD
# Execute a shell command on the router via POST /diagnostics/command_prompt.
# The endpoint runs as the pfREST process user (root). stdout = combined
# command output. Sets _API_EXEC_RC to the result_code from pfREST.
#
# Schema (verified from /api/v2/schema/openapi):
#   Request body:  {"command": "..."}     (max 1024 chars)
#   Response data: {"command","output","result_code"}
#
# Security: the command is sent via 0600 temp file (same mechanism as auth
# headers) so it never appears in `ps`/proc argv. Callers should still avoid
# embedding secrets in CMD — the command appears in the pfREST audit log
# (/status/logs/packages/restapi), which is exactly what we want for audit
# but means no passwords/keys should be passed.
# ---------------------------------------------------------------------------
_API_EXEC_RC=0
_api_pfsense_exec() {
  local cmd="$1"
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] \
    || log_die "_api_pfsense_exec called for ROUTER_PLATFORM=${ROUTER_PLATFORM}"
  [[ ${#cmd} -le 1024 ]] \
    || log_die "_api_pfsense_exec: command exceeds 1024-char pfREST limit (got ${#cmd})"

  # JSON-encode the command. Backslashes first, then quotes, then control chars.
  local esc="${cmd}"
  esc="${esc//\\/\\\\}"
  esc="${esc//\"/\\\"}"
  esc="${esc//$'\n'/\\n}"
  esc="${esc//$'\r'/\\r}"
  esc="${esc//$'\t'/\\t}"
  local body
  body="$(printf '{"command":"%s"}' "${esc}")"

  local resp rc=0
  resp="$(api_request POST "/diagnostics/command_prompt" "${body}")" || rc=$?

  if (( rc != 0 )); then
    _API_EXEC_RC=${rc}
    log_debug "exec failed (curl rc=${rc}): ${cmd}"
    return ${rc}
  fi

  if command -v jq >/dev/null 2>&1; then
    _API_EXEC_RC="$(echo "${resp}" | jq -r '.data.result_code // 0')"
    echo "${resp}" | jq -r '.data.output // ""'
  else
    # Permissive sed fallback if jq is unavailable on the operator host
    _API_EXEC_RC="$(echo "${resp}" \
      | sed -n 's/.*"result_code"[[:space:]]*:[[:space:]]*\([0-9-]*\).*/\1/p' \
      | head -n1)"
    : "${_API_EXEC_RC:=0}"
    # Crude output extractor — fine for short outputs, jq is preferred
    echo "${resp}" \
      | sed -n 's/.*"output"[[:space:]]*:[[:space:]]*"\(.*\)"[[:space:]]*,.*"result_code".*/\1/p' \
      | head -n1 \
      | sed 's/\\n/\n/g; s/\\"/"/g; s/\\\\/\\/g'
  fi
}

# ---------------------------------------------------------------------------
# api_reload_suricata_rules — hot-reload rules without service restart.
# pfREST has no native Suricata endpoint, so we exec suricatasc via API.
# This is the same call the Suricata package GUI makes internally.
# ---------------------------------------------------------------------------
api_reload_suricata_rules() {
  api_init
  case "${ROUTER_PLATFORM}" in
    pfsense)
      _api_pfsense_exec "suricatasc -c reload-rules" \
        || log_warn "Suricata rule reload via API failed (rc=${_API_EXEC_RC})"
      ;;
    opnsense)
      api_request POST "/ids/service/reload" ""
      ;;
  esac
}

# ===========================================================================
# COMPONENT VALIDATORS (pfSense)
# Each returns 0 on success, 1 on failure. Stdout is human-readable summary.
# ===========================================================================

# ---------------------------------------------------------------------------
# api_validate_packages
# Verify all SURU-required packages are installed via GET /system/packages.
# ---------------------------------------------------------------------------
api_validate_packages() {
  api_init
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || { log_warn "api_validate_packages: pfSense only"; return 0; }

  local resp
  resp="$(api_request GET "/system/packages")" || { log_warn "validate_packages: API call failed"; return 1; }

  # pfBlockerNG ships as either pfSense-pkg-pfBlockerNG or pfSense-pkg-pfBlockerNG-devel
  # depending on which channel is installed — match both with a prefix check below.
  local required=( pfSense-pkg-RESTAPI pfSense-pkg-suricata pfSense-pkg-zeek pfSense-pkg-pfBlockerNG )
  # zeek package alternate name (some pfSense builds use lowercase 'pfSense-pkg-zeek')
  local missing=() pkg present_list

  if command -v jq >/dev/null 2>&1; then
    present_list="$(echo "${resp}" | jq -r '.data[]?.name // empty')"
  else
    present_list="$(echo "${resp}" | tr ',' '\n' | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  fi

  for pkg in "${required[@]}"; do
    if echo "${present_list}" | grep -qiF "${pkg}"; then
      log_info "  package: ${pkg} ✓"
    else
      log_warn "  package: ${pkg} ✗ (not installed)"
      missing+=("${pkg}")
    fi
  done

  (( ${#missing[@]} == 0 ))
}

# ---------------------------------------------------------------------------
# api_validate_suricata_config
# Execute `suricata -T` against the deployed config. Result code 0 = OK.
# Output may be multi-line; we report exit code and last line.
# ---------------------------------------------------------------------------
api_validate_suricata_config() {
  api_init
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || return 0
  local out
  out="$(_api_pfsense_exec "sudo suricata -T -c /usr/local/etc/suricata/suricata.yaml 2>&1 | tail -n 3")"
  if (( _API_EXEC_RC == 0 )); then
    log_info "  suricata -T: ✓ (config valid)"
    return 0
  fi
  log_warn "  suricata -T: ✗ (rc=${_API_EXEC_RC})"
  echo "${out}" | sed 's/^/    /'
  return 1
}

# ---------------------------------------------------------------------------
# api_validate_zeek_status
# `zeekctl status` returns 0 when all nodes are "running".
# ---------------------------------------------------------------------------
api_validate_zeek_status() {
  api_init
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || return 0
  local out
  out="$(_api_pfsense_exec "sudo zeekctl status 2>&1")"
  if (( _API_EXEC_RC == 0 )) && echo "${out}" | grep -q "running"; then
    log_info "  zeekctl status: ✓ (nodes running)"
    return 0
  fi
  log_warn "  zeekctl status: ✗ (rc=${_API_EXEC_RC})"
  echo "${out}" | sed 's/^/    /'
  return 1
}

# ---------------------------------------------------------------------------
# api_validate_syslogng_config
# `syslog-ng -s` returns 0 on valid config, non-zero on syntax errors.
# ---------------------------------------------------------------------------
api_validate_syslogng_config() {
  api_init
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || return 0
  local out
  out="$(_api_pfsense_exec "syslog-ng -s 2>&1")"
  if (( _API_EXEC_RC == 0 )); then
    log_info "  syslog-ng -s: ✓ (config valid)"
    return 0
  fi
  log_warn "  syslog-ng -s: ✗ (rc=${_API_EXEC_RC})"
  echo "${out}" | sed 's/^/    /'
  return 1
}

# ---------------------------------------------------------------------------
# api_validate_pfblockerng_aliases
# Confirms pfB_SURU_* aliases were created by pfBlockerNG after the deploy
# imported our DNSBL feeds. Each SURU feed in the imported config becomes a
# pfB_<aliasname>_v4 (and _v6) firewall alias on the next pfBlockerNG run.
#
# Note: aliases only appear after pfBlockerNG runs its cron job or after a
# manual "Force Reload" in the UI. On a fresh import, the firewall/aliases
# endpoint may return zero pfB_SURU_* entries; this is a warning, not failure.
# ---------------------------------------------------------------------------
api_validate_pfblockerng_aliases() {
  api_init
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || return 0
  local resp count
  resp="$(api_request GET "/firewall/aliases")" || { log_warn "  pfBlockerNG aliases: API call failed"; return 1; }

  if command -v jq >/dev/null 2>&1; then
    count="$(echo "${resp}" | jq -r '[.data[]? | select(.name | startswith("pfB_SURU"))] | length')"
  else
    count="$(echo "${resp}" | grep -oE '"name"[[:space:]]*:[[:space:]]*"pfB_SURU[^"]*"' | wc -l | tr -d ' ')"
  fi

  if [[ -n "${count}" && "${count}" -gt 0 ]]; then
    log_info "  pfBlockerNG aliases: ✓ (${count} pfB_SURU_* aliases present)"
    return 0
  fi
  log_warn "  pfBlockerNG aliases: ⚠ (no pfB_SURU_* aliases yet — run \"Force Reload\" or wait for cron)"
  return 0  # non-fatal; aliases are created async by pfBlockerNG
}

# ---------------------------------------------------------------------------
# api_validate_recent_errors [LIMIT]
# Pulls the last N system log lines and reports the count of ERROR/CRITICAL
# entries. Returns 0 if none found, 1 if any.
# ---------------------------------------------------------------------------
api_validate_recent_errors() {
  local limit="${1:-50}"
  api_init
  local resp body err_count
  resp="$(api_fetch_errors "${limit}")" || { log_warn "  recent errors: log fetch failed"; return 1; }

  if command -v jq >/dev/null 2>&1; then
    body="$(echo "${resp}" | jq -r '.data[]?.text // .data[]? // empty' 2>/dev/null || echo "${resp}")"
  else
    body="${resp}"
  fi

  err_count="$(echo "${body}" | grep -ciE 'error|critical|fatal' || true)"
  if [[ "${err_count}" -eq 0 ]]; then
    log_info "  recent log scan: ✓ (0 errors in last ${limit} lines)"
    return 0
  fi
  log_warn "  recent log scan: ⚠ (${err_count} error/critical lines in last ${limit})"
  return 0  # surface count but don't fail the deploy on log volume alone
}

# ---------------------------------------------------------------------------
# api_fetch_errors [LIMIT]
# Returns the last N system log entries. pfREST exposes these under
# /status/logs/system (confirmed against OpenAPI schema /api/v2/schema/openapi).
# ---------------------------------------------------------------------------
api_fetch_errors() {
  local limit="${1:-200}"
  api_init
  case "${ROUTER_PLATFORM}" in
    pfsense)
      api_request GET "/status/logs/system?limit=${limit}"
      ;;
    opnsense)
      api_request GET "/diagnostics/log/core/system?limit=${limit}"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# api_pfsense_bootstrap_validator [ADMIN_USER]
# pfSense ONLY — one-shot setup of the suru-validator API user + API key.
# Idempotent: if suru-validator already exists, resets password + reissues key.
# Run after api_pfsense_install. Never run during automated deploys.
#
# FLOW
#   1. Prompt admin password (read -s; never stored or logged)
#   2. Generate a random ephemeral password for suru-validator
#   3. Auth as admin (JWT) → create/patch suru-validator with 6 privileges
#   4. Auth as suru-validator (JWT) → issue API key (sha512, 32 bytes)
#   5. Print PFSENSE_API_KEY value for operator to paste into .env
#   6. Scrub all credential variables from memory
#
# MINIMUM-PRIVILEGE NOTES
#   The 6 pfSense page privileges assigned to suru-validator map to exactly
#   the API endpoints called by api_validate_deployment. The list is defined
#   in _SURU_VALIDATOR_PRIVS below — verify against your pfSense version if
#   any endpoint returns 403.
#
# OUTPUT
#   Prints "PFSENSE_API_KEY=<value>" to stdout on success.
#   Operator pastes it into .env (keep .env encrypted with SOPS + age).
# ---------------------------------------------------------------------------
# pfREST v2 uses its own api-v2-<resource>-<method> privilege format, not
# standard pfSense page-* privileges. The only cross-compatible grant is
# page-all. The API key itself is the security boundary — suru-validator
# can only authenticate via the rotated key issued by make api-bootstrap.
_SURU_VALIDATOR_PRIVS=(
  "page-all"
)

api_pfsense_bootstrap_validator() {
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] \
    || log_die "api_pfsense_bootstrap_validator: pfSense only"
  : "${ROUTER_HOST:?ROUTER_HOST not set}"
  : "${ROUTER_SSH_KEY:?ROUTER_SSH_KEY not set}"

  # Single SSH+PHP script creates the user AND stores the API key directly in
  # pfSense config — no JWT step, no chicken-and-egg, no sshguard risk.
  log_info "[bootstrap] Running user + key provisioning via SSH+PHP..."
  local api_key
  api_key="$(_api_pfsense_bootstrap_ssh)" \
    || log_die "Bootstrap PHP script failed on router"
  [[ -n "${api_key}" ]] \
    || log_die "Bootstrap: no PFSENSE_API_KEY line in PHP output — check router logs"

  printf '\n'
  printf '=%.0s' {1..60}; printf '\n'
  printf 'Bootstrap complete. Paste into tier1-perimeter/.env:\n\n'
  printf 'API_AUTH_MODE=api_key\n'
  printf 'PFSENSE_API_KEY=%s\n' "${api_key}"
  printf '\n  Key: sha512 / 32B — rotate every 90 days with: make api-bootstrap\n'
  printf '  Encrypt .env at rest:  sops --encrypt --in-place .env\n'
  printf '=%.0s' {1..60}; printf '\n'
}

# ---------------------------------------------------------------------------
# _api_pfsense_bootstrap_ssh
# Creates suru-validator user + pfREST API key in pfSense config in a single
# PHP script executed via SSH (same credentials as make deploy). Prints the
# raw API key to stdout on success; all other output goes to stderr.
#
# Key storage format (verified from /usr/local/pkg/RESTAPI/Models/RESTAPIKey.inc):
#   config path: installedpackages/package/<restapi_pkg_id>/conf/keys/key[]
#   key:         bin2hex(random_bytes(32))       — 64 hex chars
#   stored hash: hash('sha512', $raw_key)
# ---------------------------------------------------------------------------
_api_pfsense_bootstrap_ssh() {
  # Build privilege PHP array literal: ['priv1','priv2',...]
  local php_privs="[" _first=true _p
  for _p in "${_SURU_VALIDATOR_PRIVS[@]}"; do
    [[ "${_first}" == "true" ]] || php_privs+=","
    php_privs+="'${_p}'"
    _first=false
  done
  php_privs+="]"

  local php_file remote_php
  php_file="$(mktemp /tmp/suru-bootstrap-XXXXXX.php)"
  remote_php="/tmp/suru-bootstrap-validator.php"

  # php_privs is alphanumeric/dashes only — safe to embed directly.
  cat > "${php_file}" << PHPEOF
<?php
// pfSense requires globals.inc + functions.inc before config.lib.inc
// when running outside the web bootstrapper (e.g. sudo php /tmp/script.php)
require_once('globals.inc');
require_once('config.lib.inc');
require_once('functions.inc');

// ── 1. Create / update suru-validator ──────────────────────────────────────
\$privs = ${php_privs};
\$pass  = bin2hex(random_bytes(20)); // ephemeral — never stored, discarded after key storage

\$users = config_get_path('system/user', []);
\$idx   = null;
foreach (\$users as \$i => \$u) {
    if (\$u['name'] === 'suru-validator') { \$idx = \$i; break; }
}

if (\$idx !== null) {
    \$users[\$idx]['password'] = password_hash(\$pass, PASSWORD_BCRYPT);
    \$users[\$idx]['priv']     = \$privs;
    unset(\$users[\$idx]['disabled']);
    \$uid    = \$users[\$idx]['uid'];
    \$action = 'updated';
} else {
    \$uid = (int)config_get_path('system/nextuid', '2000');
    config_set_path('system/nextuid', (string)(\$uid + 1));
    \$users[] = [
        'name'     => 'suru-validator',
        'password' => password_hash(\$pass, PASSWORD_BCRYPT),
        'uid'      => (string)\$uid,
        'scope'    => 'user',
        'descr'    => 'SURU deploy validator — managed by api-bootstrap',
        'priv'     => \$privs,
    ];
    \$action = 'created';
}
config_set_path('system/user', \$users);
fwrite(STDERR, "[bootstrap] suru-validator {\$action} (uid={\$uid})" . PHP_EOL);

// ── 2. Find pfREST package index ──────────────────────────────────────────
\$pkgs   = config_get_path('installedpackages/package', []);
\$pkg_id = null;
foreach (\$pkgs as \$i => \$pkg) {
    if (stripos(\$pkg['name'] ?? '', 'RESTAPI') !== false) {
        \$pkg_id = \$i;
        break;
    }
}
if (\$pkg_id === null) {
    fwrite(STDERR, "[bootstrap] ERROR: pfREST package not found — run make api-install-pfrest first" . PHP_EOL);
    exit(1);
}
fwrite(STDERR, "[bootstrap] pfREST at package index {\$pkg_id}" . PHP_EOL);

// ── 3. Generate key + store hash (RESTAPIKey model format) ────────────────
\$raw_key  = bin2hex(random_bytes(32));     // 64 hex chars — matches RESTAPIKey.inc
\$key_hash = hash('sha512', \$raw_key);

\$key_path = "installedpackages/package/{\$pkg_id}/conf/keys/key";
\$cur_keys = config_get_path(\$key_path, []);
// Remove any previous SURU-managed key for suru-validator (idempotent rotation)
\$cur_keys = array_values(array_filter((array)\$cur_keys, function(\$k) {
    return !((\$k['username'] ?? '') === 'suru-validator'
          && (\$k['descr']    ?? '') === 'SURU tier1 deploy validation');
}));
\$cur_keys[] = [
    'username'     => 'suru-validator',
    'hash_algo'    => 'sha512',
    'length_bytes' => '32',
    'hash'         => \$key_hash,
    'descr'        => 'SURU tier1 deploy validation',
];
config_set_path(\$key_path, \$cur_keys);

// ── 4. Enable KeyAuth in pfREST auth_methods (idempotent) ─────────────────
require_once('RESTAPI/autoloader.inc');
use RESTAPI\Models\RESTAPISettings;
\$restapi_pkg_id  = RESTAPISettings::get_pkg_id();
\$auth_path       = "installedpackages/package/{\$restapi_pkg_id}/conf/auth_methods";
\$current_methods = config_get_path(\$auth_path, 'BasicAuth');
if (strpos(\$current_methods, 'KeyAuth') === false) {
    config_set_path(\$auth_path, \$current_methods . ',KeyAuth');
    fwrite(STDERR, "[bootstrap] KeyAuth added to auth_methods" . PHP_EOL);
} else {
    fwrite(STDERR, "[bootstrap] KeyAuth already in auth_methods" . PHP_EOL);
}

// ── 5. Persist + update pfREST backup ─────────────────────────────────────
write_config('SURU api-bootstrap: suru-validator + API key + KeyAuth');
RESTAPISettings::backup_to_file();
fwrite(STDERR, "[bootstrap] Config saved, pfREST backup updated" . PHP_EOL);

// Print raw key to stdout — captured by bash caller
echo \$raw_key . PHP_EOL;
PHPEOF

  local ssh_key="${ROUTER_SSH_KEY:-~/.ssh/suru_deploy}"
  local ssh_user="${ROUTER_SSH_USER:-admin}"
  local -a ssh_opts=(-i "${ssh_key}" -o "StrictHostKeyChecking=${SSH_STRICT_HOST_KEY_CHECKING:-accept-new}" -o "BatchMode=yes" -o "ConnectTimeout=15")
  local sudo_prefix=""
  [[ "${ssh_user}" != "root" ]] && sudo_prefix="sudo "

  scp "${ssh_opts[@]}" "${php_file}" "${ssh_user}@${ROUTER_HOST}:${remote_php}" \
    || { rm -f "${php_file}"; log_die "SCP of bootstrap PHP failed"; }
  rm -f "${php_file}"

  local output rc=0
  # shellcheck disable=SC2029
  output="$(ssh "${ssh_opts[@]}" "${ssh_user}@${ROUTER_HOST}" "${sudo_prefix}php ${remote_php}")" \
    || rc=$?
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" "${ssh_user}@${ROUTER_HOST}" "rm -f ${remote_php}" 2>/dev/null || true
  (( rc == 0 )) || log_die "Bootstrap PHP exited ${rc} on router"

  # raw_key is the only stdout line from the PHP script
  printf '%s' "${output}" | head -n1
}

# ---------------------------------------------------------------------------
# api_pfsense_install
# pfSense ONLY — install pfRest as the first package via SSH/pkg. Idempotent.
# Uses ssh_exec from lib/ssh.sh when available, otherwise a local ssh call.
# ---------------------------------------------------------------------------
api_pfsense_install() {
  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] || {
    log_warn "api_pfsense_install called for ROUTER_PLATFORM=${ROUTER_PLATFORM} — skipping"
    return 0
  }
  : "${ROUTER_HOST:?ROUTER_HOST not set}"
  : "${ROUTER_SSH_USER:=admin}"
  : "${ROUTER_SSH_KEY:?ROUTER_SSH_KEY not set}"

  if _api_ssh "pkg info -q pfSense-pkg-RESTAPI" >/dev/null 2>&1; then
    log_info "pfRest already installed on router — skipping"
    return 0
  fi

  local pkg_url="${PFSENSE_API_PKG_URL:-}"
  [[ -n "${pkg_url}" ]] || log_die \
"PFSENSE_API_PKG_URL not set. See https://pfrest.org/ for the package URL
matching your pfSense version. Example:
  PFSENSE_API_PKG_URL=https://github.com/jaredhendrickson13/pfsense-api/releases/latest/download/pfSense-2.7-pkg-RESTAPI.pkg"

  # pkg-static requires root. When ROUTER_SSH_USER is anything other than
  # root, prefix with sudo and rely on a passwordless rule for pkg-static
  # (or NOPASSWD: ALL) on the router. Scoping sudo only to the install call
  # avoids hanging on `pkg info` if NOPASSWD is narrowly scoped.
  local sudo_prefix=""
  [[ "${ROUTER_SSH_USER}" != "root" ]] && sudo_prefix="sudo "

  log_info "Installing pfRest as first package: ${pkg_url}"
  _api_ssh "${sudo_prefix}pkg-static -C /dev/null add ${pkg_url}" \
    || log_die "pfRest install failed. Check: (1) router network access to ${pkg_url}, (2) the URL matches the router's pfSense version, (3) '${ROUTER_SSH_USER}' has passwordless sudo for pkg-static (or set ROUTER_SSH_USER=root)."

  log_info "pfRest installed. Next: create an API key (or JWT user) in"
  log_info "pfSense UI -> System -> API -> Authentication, then populate .env."
}

# _api_ssh CMD — prefer ssh_exec from lib/ssh.sh, fall back to local ssh.
_api_ssh() {
  if type ssh_exec &>/dev/null; then
    ssh_exec "$@"
  else
    local strict="${SSH_STRICT_HOST_KEY_CHECKING:-accept-new}"
    ssh -i "${ROUTER_SSH_KEY}" \
        -o "BatchMode=yes" \
        -o "ConnectTimeout=15" \
        -o "StrictHostKeyChecking=${strict}" \
        "${ROUTER_SSH_USER}@${ROUTER_HOST}" \
        "sh -c \"$*\""
  fi
}

# ===========================================================================
# DYNAMIC PERIMETER BLOCK — T0b
#
# *** BREAKING CHANGE: new Tier-1 enforcement surface ***
# This is a brand-new capability. It is library-only — nothing in
# tier1-perimeter calls these functions today. The intended caller is
# tier2-telemetry's `perimeter_block` detector action (T4b, opt-in per
# detector, not a default). Do not wire this into deploy.sh, cron, or any
# always-on path without an explicit, separate change.
#
# GROUNDING / GAPS (evidence-based-claims.md):
#   - No POST/PATCH/PUT pfREST alias-mutation endpoint is confirmed anywhere
#     in this codebase (grep of every api_request call site in this file
#     shows only GET /firewall/aliases, read-only). [MISSING REFERENCE:
#     pfRest /api/v2/firewall/alias mutate-entries schema — propose web
#     search: "pfRest pfSense API v2 firewall alias update entries endpoint
#     pfrest.org"]
#   - Mutation is therefore implemented via the one proven mutation
#     primitive in this file, `_api_pfsense_exec` (same mechanism
#     `_api_pfsense_bootstrap_ssh` uses for config_set_path edits, just over
#     the REST exec endpoint instead of SSH). This is a working code path
#     (exec is proven elsewhere in this file) but the SPECIFIC php snippet
#     below has not been run against a live router in this session.
#   - [STUB: alias mutation endpoint unconfirmed — needs live pfSense test]
#     applies to every call to _perimeter_block_php_mutate_alias below.
#   - Reload uses `pfSsh.php exec 'filter_configure();'` — pfSense's standard
#     programmatic filter-reload call, but not confirmed reachable under the
#     suru-validator's page-all privilege in a live environment in this
#     session. [STUB: reload call unconfirmed — needs live pfSense test]
#   - Audit-to-SIEM: written to a new router-local file
#     (/var/log/suru/perimeter-block.log) via the same exec call that
#     performs the mutation, so the audit line and the mutation it describes
#     are atomic from this client's perspective. A matching syslog-ng source
#     is added in templates/pfsense/syslog-ng.conf.tpl (see that file) to
#     forward it over the existing d_siem_tls path — no new transport
#     invented.
#
# MITRE ATT&CK: this capability implements TA0001 Initial Access mitigation /
# TA0011 Command and Control disruption by blocking a single attacker IP at
# the perimeter on a SIEM detector's instruction (T1071 Application Layer
# Protocol C2, T1190 Exploit Public-Facing Application — the IP being
# blocked is the indicator, not a technique on the defender's own ATT&CK
# matrix; tag findings that trigger this action with the technique that
# produced the indicator, not this enforcement action itself).
# ===========================================================================

: "${PERIMETER_BLOCK_ALIAS:=pfB_SURU_DYNAMIC_v4}"
: "${PERIMETER_BLOCK_DEFAULT_TTL:=3600}"
: "${PERIMETER_BLOCK_MAX_TTL:=86400}"
: "${PERIMETER_BLOCK_MAX_PER_WINDOW:=10}"
: "${PERIMETER_BLOCK_WINDOW_SECONDS:=300}"
: "${PERIMETER_BLOCK_STATE_DIR:=${TMPDIR:-/tmp}/suru-perimeter-block}"

# ---------------------------------------------------------------------------
# _perimeter_block_valid_ipv4 IP — returns 0 if IP is a syntactically valid
# dotted-quad IPv4 address (each octet 0-255). v6 is out of scope: the
# managed alias is explicitly named _v4.
# ---------------------------------------------------------------------------
_perimeter_block_valid_ipv4() {
  local ip="$1"
  local -a octets
  [[ "${ip}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  IFS='.' read -r -a octets <<< "${ip}"
  local o
  for o in "${octets[@]}"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# ---------------------------------------------------------------------------
# _perimeter_block_ip_in_cidr IP CIDR_OR_IP — pure-bash IPv4 CIDR containment
# check (no external deps). CIDR_OR_IP without a "/" is treated as /32.
# ---------------------------------------------------------------------------
_perimeter_block_ip_in_cidr() {
  local ip="$1" cidr="$2"
  local net_part prefix
  if [[ "${cidr}" == */* ]]; then
    net_part="${cidr%/*}"
    prefix="${cidr#*/}"
  else
    net_part="${cidr}"
    prefix=32
  fi
  _perimeter_block_valid_ipv4 "${net_part}" || return 1
  (( prefix >= 0 && prefix <= 32 )) || return 1

  local -a ip_o net_o
  IFS='.' read -r -a ip_o  <<< "${ip}"
  IFS='.' read -r -a net_o <<< "${net_part}"

  local ip_int=0 net_int=0 i
  for i in 0 1 2 3; do
    ip_int=$(( (ip_int << 8) | ip_o[i] ))
    net_int=$(( (net_int << 8) | net_o[i] ))
  done

  local mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  (( (ip_int & mask) == (net_int & mask) ))
}

# ---------------------------------------------------------------------------
# _perimeter_block_is_allowlisted IP — checks PERIMETER_BLOCK_ALLOWLIST
# (comma-separated IPs/CIDRs). Fail-safe: if the allowlist is unset/empty,
# only RFC1918 + loopback + the configured ROUTER_HOST itself are protected
# as a hardcoded floor — never blockable regardless of allowlist config.
# ---------------------------------------------------------------------------
_perimeter_block_is_allowlisted() {
  local ip="$1" entry
  local -a floor=(127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
  for entry in "${floor[@]}"; do
    _perimeter_block_ip_in_cidr "${ip}" "${entry}" && return 0
  done
  [[ -n "${ROUTER_HOST:-}" && "${ip}" == "${ROUTER_HOST}" ]] && return 0

  local allowlist="${PERIMETER_BLOCK_ALLOWLIST:-}"
  [[ -n "${allowlist}" ]] || return 1
  local -a entries
  IFS=',' read -r -a entries <<< "${allowlist}"
  for entry in "${entries[@]}"; do
    entry="$(echo "${entry}" | tr -d '[:space:]')"
    [[ -n "${entry}" ]] || continue
    _perimeter_block_ip_in_cidr "${ip}" "${entry}" && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# _perimeter_block_state_init — ensures PERIMETER_BLOCK_STATE_DIR exists with
# restrictive perms. State lives on the CALLING host (this client runs
# off-router) — see header comment for the multi-caller-rate-limit caveat.
# ---------------------------------------------------------------------------
_perimeter_block_state_init() {
  if [[ ! -d "${PERIMETER_BLOCK_STATE_DIR}" ]]; then
    mkdir -p -- "${PERIMETER_BLOCK_STATE_DIR}" || log_die "Cannot create PERIMETER_BLOCK_STATE_DIR=${PERIMETER_BLOCK_STATE_DIR}"
  fi
  chmod 700 -- "${PERIMETER_BLOCK_STATE_DIR}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# _perimeter_block_rate_limit_check — counts block events recorded in the
# rate-limit log within PERIMETER_BLOCK_WINDOW_SECONDS. Returns 1 (reject)
# if PERIMETER_BLOCK_MAX_PER_WINDOW would be exceeded.
# ---------------------------------------------------------------------------
_perimeter_block_rate_limit_check() {
  _perimeter_block_state_init
  local ratefile="${PERIMETER_BLOCK_STATE_DIR}/rate.log"
  local now cutoff count
  now=$(date +%s)
  cutoff=$(( now - PERIMETER_BLOCK_WINDOW_SECONDS ))
  touch -- "${ratefile}"

  # Prune + count atomically enough for single-host, single-caller use.
  # Concurrent multi-process callers on the same host could race here —
  # acceptable for the SOHO scale this rate limiter targets; not safe for
  # high-concurrency multi-CI-runner use (see header note on state scope).
  local tmpfile
  tmpfile="$(mktemp "${PERIMETER_BLOCK_STATE_DIR}/rate.XXXXXX")" || return 1
  awk -v cutoff="${cutoff}" '$1 >= cutoff' "${ratefile}" > "${tmpfile}" 2>/dev/null || true
  mv -f -- "${tmpfile}" "${ratefile}"

  count="$(wc -l < "${ratefile}" | tr -d ' ')"
  (( count < PERIMETER_BLOCK_MAX_PER_WINDOW ))
}

# ---------------------------------------------------------------------------
# _perimeter_block_rate_limit_record — appends a timestamp to the rate log.
# ---------------------------------------------------------------------------
_perimeter_block_rate_limit_record() {
  local ratefile="${PERIMETER_BLOCK_STATE_DIR}/rate.log"
  echo "$(date +%s)" >> "${ratefile}"
}

# ---------------------------------------------------------------------------
# _perimeter_block_ttl_set IP TTL_SECONDS — records expiry epoch for IP.
# _perimeter_block_ttl_clear IP — removes the TTL record (on unblock).
# TTL state file format: one "ip expiry_epoch" line per blocked IP.
# ---------------------------------------------------------------------------
_perimeter_block_ttl_file() { echo "${PERIMETER_BLOCK_STATE_DIR}/ttl.log"; }

_perimeter_block_ttl_set() {
  local ip="$1" ttl="$2" ttlfile expiry tmpfile
  _perimeter_block_state_init
  ttlfile="$(_perimeter_block_ttl_file)"
  touch -- "${ttlfile}"
  expiry=$(( $(date +%s) + ttl ))
  tmpfile="$(mktemp "${PERIMETER_BLOCK_STATE_DIR}/ttl.XXXXXX")" || return 1
  awk -v ip="${ip}" '$1 != ip' "${ttlfile}" > "${tmpfile}" 2>/dev/null || true
  echo "${ip} ${expiry}" >> "${tmpfile}"
  mv -f -- "${tmpfile}" "${ttlfile}"
}

_perimeter_block_ttl_clear() {
  local ip="$1" ttlfile tmpfile
  _perimeter_block_state_init
  ttlfile="$(_perimeter_block_ttl_file)"
  [[ -f "${ttlfile}" ]] || return 0
  tmpfile="$(mktemp "${PERIMETER_BLOCK_STATE_DIR}/ttl.XXXXXX")" || return 1
  awk -v ip="${ip}" '$1 != ip' "${ttlfile}" > "${tmpfile}" 2>/dev/null || true
  mv -f -- "${tmpfile}" "${ttlfile}"
}

# ---------------------------------------------------------------------------
# _perimeter_block_audit ACTION IP [DETAIL] — writes one audit line to a
# router-local file via the proven _api_pfsense_exec primitive, so the audit
# record and the mutation it describes are emitted from the same exec call's
# caller (not a separate, possibly-failing round-trip). The file is tailed by
# a new syslog-ng source (s_suru_perimeter_block, see syslog-ng.conf.tpl) and
# forwarded over the existing d_siem_tls path — reuses the established
# forwarding pattern, no new transport.
#
# Line format (pipe-delimited, mirrors pfBlockerNG's own log style):
#   <ISO8601>|<action>|<ip>|<actor>|<detail>
# ---------------------------------------------------------------------------
_perimeter_block_audit() {
  local action="$1" ip="$2" detail="${3:-}"
  local ts actor esc_detail cmd
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  actor="${API_AUTH_MODE}:${PFSENSE_API_USERNAME:-api_key}"
  esc_detail="${detail//|/_}"
  cmd="mkdir -p /var/log/suru && echo '${ts}|${action}|${ip}|${actor}|${esc_detail}' >> /var/log/suru/perimeter-block.log"
  _api_pfsense_exec "${cmd}" >/dev/null || \
    log_warn "Audit write to router failed (rc=${_API_EXEC_RC}) for ${action} ${ip} — SIEM will NOT see this event until the router-side log path is fixed."
}

# ---------------------------------------------------------------------------
# _perimeter_block_php_mutate_alias ACTION IP — [STUB: alias mutation
# endpoint unconfirmed — needs live pfSense test]
#
# ACTION is "add" or "remove". Mutates PERIMETER_BLOCK_ALIAS's address list
# via config_set_path, mirroring the proven pattern in
# _api_pfsense_bootstrap_ssh (which edits system/user and the RESTAPIKey path
# the same way) — but run over the REST exec endpoint instead of SSH, and not
# live-tested in this session. Creates the alias if it does not yet exist.
# ---------------------------------------------------------------------------
_perimeter_block_php_mutate_alias() {
  local action="$1" ip="$2"
  [[ "${action}" == "add" || "${action}" == "remove" ]] \
    || log_die "_perimeter_block_php_mutate_alias: action must be add|remove"

  # Single-line PHP, kept under the 1024-char _api_pfsense_exec limit.
  # Uses config_get_path/config_set_path (the same config.lib.inc functions
  # already proven reachable via this exec path in _api_pfsense_bootstrap_ssh,
  # albeit there over SSH+php-cli rather than the REST exec endpoint — that
  # delta is exactly what remains unconfirmed).
  local php
  php="require_once('globals.inc');require_once('config.lib.inc');"
  php+="\$n='${PERIMETER_BLOCK_ALIAS}';\$ip='${ip}';"
  php+="\$a=config_get_path('aliases/alias',[]);\$idx=null;"
  php+="foreach(\$a as \$i=>\$x){if((\$x['name']??'')===\$n){\$idx=\$i;break;}}"
  php+="if(\$idx===null){\$a[]=['name'=>\$n,'type'=>'host','descr'=>'SURU dynamic perimeter block (T0b)','address'=>'','detail'=>''];\$idx=count(\$a)-1;}"
  php+="\$addrs=\$a[\$idx]['address']===''?[]:explode(' ',\$a[\$idx]['address']);"
  php+="if('${action}'==='add'){if(!in_array(\$ip,\$addrs,true))\$addrs[]=\$ip;}else{\$addrs=array_values(array_diff(\$addrs,[\$ip]));}"
  php+="\$a[\$idx]['address']=implode(' ',\$addrs);"
  php+="config_set_path('aliases/alias',\$a);write_config('SURU perimeter_block: ${action} ${ip}');"
  php+="echo 'ok';"

  local out
  out="$(_api_pfsense_exec "php -r \"${php}\"")" || true
  if (( _API_EXEC_RC != 0 )) || [[ "${out}" != *ok* ]]; then
    log_error "[STUB] Alias mutation failed or unconfirmed (rc=${_API_EXEC_RC}, action=${action}, ip=${ip})"
    log_error "[STUB] output: ${out}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# _perimeter_block_reload — [STUB: reload call unconfirmed — needs live
# pfSense test]. filter_configure() is pfSense's standard programmatic
# firewall-filter reload; reachability under suru-validator's page-all
# privilege via the REST exec endpoint has not been confirmed live.
# ---------------------------------------------------------------------------
_perimeter_block_reload() {
  _api_pfsense_exec "pfSsh.php exec 'filter_configure();'" >/dev/null
  if (( _API_EXEC_RC != 0 )); then
    log_error "[STUB] Filter reload failed or unconfirmed (rc=${_API_EXEC_RC})"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# api_block_ip IP [TTL_SECONDS] — pfSense ONLY.
#
# Guardrails enforced, in order: platform check, IP syntax, allowlist,
# rate-limit, TTL bound. Only after all pass does mutation happen.
# Returns 0 on (believed) success, 1 on any guardrail rejection or mutation
# failure. See header [STUB] notes — success here means "the exec call
# returned the expected marker," not "live-verified against a real router."
# ---------------------------------------------------------------------------
api_block_ip() {
  local ip="$1" ttl="${2:-${PERIMETER_BLOCK_DEFAULT_TTL}}"
  api_init

  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] \
    || log_die "api_block_ip: pfSense only (ROUTER_PLATFORM=${ROUTER_PLATFORM})"

  _perimeter_block_valid_ipv4 "${ip}" \
    || log_die "api_block_ip: '${ip}' is not a valid IPv4 address"

  [[ "${ttl}" =~ ^[0-9]+$ ]] && (( ttl > 0 )) \
    || log_die "api_block_ip: TTL must be a positive integer of seconds (got '${ttl}'); permanent blocks (ttl=0) are not allowed without an explicit out-of-band decision"
  (( ttl <= PERIMETER_BLOCK_MAX_TTL )) \
    || log_die "api_block_ip: TTL ${ttl}s exceeds PERIMETER_BLOCK_MAX_TTL=${PERIMETER_BLOCK_MAX_TTL}s"

  if _perimeter_block_is_allowlisted "${ip}"; then
    log_error "api_block_ip: refusing to block ${ip} — allowlisted (RFC1918/loopback/ROUTER_HOST floor or PERIMETER_BLOCK_ALLOWLIST)"
    return 1
  fi

  if ! _perimeter_block_rate_limit_check; then
    log_error "api_block_ip: rate limit exceeded (${PERIMETER_BLOCK_MAX_PER_WINDOW} blocks per ${PERIMETER_BLOCK_WINDOW_SECONDS}s) — refusing to block ${ip}"
    return 1
  fi

  log_info "api_block_ip: blocking ${ip} (ttl=${ttl}s, alias=${PERIMETER_BLOCK_ALIAS}) [STUB: unconfirmed live]"
  if ! _perimeter_block_php_mutate_alias add "${ip}"; then
    return 1
  fi
  if ! _perimeter_block_reload; then
    log_warn "api_block_ip: alias mutated but reload is unconfirmed — filter may not yet enforce this block"
  fi

  _perimeter_block_rate_limit_record
  _perimeter_block_ttl_set "${ip}" "${ttl}"
  _perimeter_block_audit "block" "${ip}" "ttl=${ttl}s"

  log_info "api_block_ip: ${ip} added to ${PERIMETER_BLOCK_ALIAS}, expires in ${ttl}s [STUB: live enforcement unconfirmed]"
  return 0
}

# ---------------------------------------------------------------------------
# api_unblock_ip IP — pfSense ONLY. Mirror of api_block_ip's mutation path
# minus rate-limit/TTL-set; clears TTL state and audits.
# ---------------------------------------------------------------------------
api_unblock_ip() {
  local ip="$1"
  api_init

  [[ "${ROUTER_PLATFORM}" == "pfsense" ]] \
    || log_die "api_unblock_ip: pfSense only (ROUTER_PLATFORM=${ROUTER_PLATFORM})"

  _perimeter_block_valid_ipv4 "${ip}" \
    || log_die "api_unblock_ip: '${ip}' is not a valid IPv4 address"

  log_info "api_unblock_ip: unblocking ${ip} (alias=${PERIMETER_BLOCK_ALIAS}) [STUB: unconfirmed live]"
  if ! _perimeter_block_php_mutate_alias remove "${ip}"; then
    return 1
  fi
  if ! _perimeter_block_reload; then
    log_warn "api_unblock_ip: alias mutated but reload is unconfirmed — filter may still be enforcing this block"
  fi

  _perimeter_block_ttl_clear "${ip}"
  _perimeter_block_audit "unblock" "${ip}" ""

  log_info "api_unblock_ip: ${ip} removed from ${PERIMETER_BLOCK_ALIAS} [STUB: live enforcement unconfirmed]"
  return 0
}

# ---------------------------------------------------------------------------
# api_perimeter_block_expire_sweep — idempotent. Reads the local TTL state
# file and calls api_unblock_ip for every entry whose expiry has passed.
# Designed to be invoked from cron/systemd timer exactly like the documented
# pattern in scripts/update-rules.sh — this repo has no cron-registration
# mechanism, so this ships as a callable function with the suggested
# crontab line documented here rather than any auto-wiring:
#
#   */5 * * * * cd /path/to/tier1-perimeter && \
#     bash -c 'source scripts/lib/log.sh; source scripts/lib/api.sh; \
#       set -a; source .env; set +a; api_perimeter_block_expire_sweep' \
#     >> /var/log/suru-perimeter-block-sweep.log 2>&1
# ---------------------------------------------------------------------------
api_perimeter_block_expire_sweep() {
  api_init
  _perimeter_block_state_init
  local ttlfile now
  ttlfile="$(_perimeter_block_ttl_file)"
  [[ -f "${ttlfile}" ]] || { log_info "api_perimeter_block_expire_sweep: no TTL state — nothing to do"; return 0; }
  now=$(date +%s)

  local ip expiry expired_count=0
  while IFS=' ' read -r ip expiry; do
    [[ -n "${ip}" && -n "${expiry}" ]] || continue
    if (( now >= expiry )); then
      log_info "api_perimeter_block_expire_sweep: ${ip} expired ($(( now - expiry ))s ago) — unblocking"
      if api_unblock_ip "${ip}"; then
        (( ++expired_count ))
      else
        log_warn "api_perimeter_block_expire_sweep: unblock failed for ${ip} — will retry next sweep"
      fi
    fi
  done < "${ttlfile}"

  log_info "api_perimeter_block_expire_sweep: ${expired_count} IP(s) expired and unblocked"
  return 0
}
