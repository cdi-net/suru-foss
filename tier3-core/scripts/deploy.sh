#!/usr/bin/env bash
# =============================================================================
# SURU Platform — Tier 3 Core SIEM  ·  deploy.sh
# =============================================================================
set -euo pipefail
trap '_on_error $LINENO' ERR
_on_error() { log ERROR "Script failed on line $1 — re-run with --verbose for details"; exit 1; }

# ── Paths ───────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIER3_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${TIER3_DIR}/.env"

# ── Runtime flags ──────────────────────────────────────────────────────────────────
DRY_RUN=false
VERBOSE=false
COMMAND=""
TARGET_GROUP=""
TARGET_SERVICE=""
NO_REPAIR_SECURITY=false
# Logstash profile selection: "all" (default) | any value in LOGSTASH_PROFILES
# "all" is overridden at runtime by ROUTER_PLATFORM from .env (pfsense → pfsense,
# opnsense → default) unless --logstash-profile is passed explicitly.
LOGSTASH_PROFILE="all"
LOGSTASH_PROFILE_EXPLICIT=false   # true when --logstash-profile is set via CLI

# ── Compose groups (startup order; teardown is reversed) ──────────────────────────────
# Note: the monitoring group (InfluxDB, Prometheus, Grafana, Watchdog) has
# moved to tier4-operations/monitoring/ as part of the Tier 4 operations /
# control-plane split. It is now deployed by tier4-operations rather than
# tier3-core. See tier4-operations/README.md.
ALL_GROUPS=(
  "datalake/opensearch"   # OpenSearch + Dashboards — primary datalake engine
  "ingestion/logstash"    # Logstash ingest pipelines — multi-profile
)
# Add new engines as:
#   "datalake/<engine>"   e.g. datalake/elasticsearch
#   "ingestion/<engine>"  e.g. ingestion/filebeat, ingestion/packetbeat

# ── Known logstash config profiles ─────────────────────────────────────────────────
# Each profile name maps to:
#   - a Docker Compose profile in ingestion/logstash/compose.yaml
#   - a config directory at tier3-core/config/logstash-<profile>/
#   - a container named suru.t3.ingestion.logstash-<profile>
# Naming convention: suru.t<N>.<group>.<function>
# Adding a new profile: add the name here and add the service block in compose.yaml
LOGSTASH_PROFILES=(pfsense opnsense)

# ── Colour codes ──────────────────────────────────────────────────────────────────────
C_RESET="\033[0m"
C_RED="\033[0;31m"
C_GREEN="\033[0;32m"
C_YELLOW="\033[1;33m"
C_CYAN="\033[0;36m"
C_BOLD="\033[1m"

# ── Logging ─────────────────────────────────────────────────────────────────────────
log() {
  local level="$1"; shift; local ts; ts="$(date '+%Y-%m-%dT%H:%M:%S')"
  case "$level" in
    INFO)  printf "${C_CYAN}[%s] [INFO]${C_RESET}  %s\n"  "$ts" "$*" ;;
    OK)    printf "${C_GREEN}[%s] [ OK ]${C_RESET}  %s\n" "$ts" "$*" ;;
    WARN)  printf "${C_YELLOW}[%s] [WARN]${C_RESET}  %s\n" "$ts" "$*" ;;
    ERROR) printf "${C_RED}[%s] [ERR ]${C_RESET}  %s\n"  "$ts" "$*" >&2 ;;
    STEP)  printf "\n${C_BOLD}━━━ %s ━━━${C_RESET}\n" "$*" ;;
  esac
}

# ── Help ──────────────────────────────────────────────────────────────────────────
usage() {
  printf "${C_BOLD}SURU Platform — Tier 3 Deployment Tool${C_RESET}\n\n"
  printf "${C_BOLD}USAGE${C_RESET}\n"
  printf "  deploy.sh <command> [--group <group>] [options]\n\n"
  printf "${C_BOLD}COMMANDS${C_RESET}\n"
  printf "  %-18s %s\n" "deploy"      "Full deployment: certs → network → all groups → health check"
  printf "  %-18s %s\n" "start"       "Start all groups (or one with --group)"
  printf "  %-18s %s\n" "stop"        "Stop all groups (or one with --group), reverse order"
  printf "  %-18s %s\n" "restart"     "Stop then start all groups (or one with --group)"
  printf "  %-18s %s\n" "destroy"     "Remove containers and networks; keep data volumes"
  printf "  %-18s %s\n" "destroy-all" "Remove containers, networks AND volumes  ⚠️  irreversible"
  printf "  %-18s %s\n" "status"      "Print health/status table for all containers"
  printf "  %-18s %s\n" "check"       "API-level health probes (OpenSearch, Dashboards, Logstash)"
  printf "  %-18s %s\n" "logs"        "Tail logs for all groups or one service (--service <name>)"
  printf "  %-18s %s\n" "reimport"    "Re-run the OpenSearch Dashboards importer"
  printf "  %-18s %s\n" "repair"      "Re-sync security index, re-apply templates/policies, and verify dashboards are imported — single-command recovery"
  printf "  %-18s %s\n" "certs"       "Generate TLS certificates only"
  printf "  %-18s %s\n" "network"     "Create shared Docker networks only"
  printf "  %-18s %s\n" "kernel-tune"     "Set vm.max_map_count=262144 (required by OpenSearch)"
  printf "  %-18s %s\n" "configure-host"  "Deploy Docker daemon.json to this host (local — no SSH)"
  printf "\n${C_BOLD}GROUPS${C_RESET}  (use with --group)\n"
  for g in "${ALL_GROUPS[@]}"; do
    local compose_file="${TIER3_DIR}/${g}/compose.yaml"
    local exists="[compose.yaml present]"
    [[ -f "$compose_file" ]] || exists="${C_YELLOW}[compose.yaml not found]${C_RESET}"
    printf "  %-26s %b\n" "$g" "$exists"
  done
  printf "\n${C_BOLD}LOGSTASH PROFILES${C_RESET}  (use --logstash-profile with --group ingestion/logstash)\n"
  printf "  %-18s %s\n" "all" "Start all profiles (default — no --profile filter)"
  for p in "${LOGSTASH_PROFILES[@]}"; do
    local cfg_dir="${TIER3_DIR}/config/logstash-${p}"
    local cfg_status="[config present]"
    [[ -d "$cfg_dir" ]] || cfg_status="${C_YELLOW}[config dir not found]${C_RESET}"
    printf "  %-18s %b  →  suru.t3.ingestion.logstash-%s\n" "$p" "$cfg_status" "$p"
  done
  printf "\n${C_BOLD}OPTIONS${C_RESET}\n"
  printf "  %-30s %s\n" "--group <group>"               "Scope start / stop / restart / deploy / destroy to one group"
  printf "  %-30s %s\n" "--logstash-profile <name|all>" "Logstash profile (default: derived from ROUTER_PLATFORM in .env; fallback: all)"
  printf "  %-30s %s\n" "--service <name>"              "Scope logs or check to a single container name"
  printf "  %-30s %s\n" "--env <file>"                  "Path to .env file  (default: <tier3>/.env)"
  printf "  %-30s %s\n" "--dry-run"                     "Print commands without executing"
  printf "  %-30s %s\n" "--verbose"                     "Extra output (command echo, wait progress, dep versions)"
  printf "  %-30s %s\n" "--no-repair-security"          "Skip automatic admin-credential seed/repair during start"
  printf "  %-30s %s\n" "-h | --help"                   "Show this help"
  printf "\n${C_BOLD}EXAMPLES${C_RESET}\n"
  printf "  # First-time full deployment (all logstash profiles)\n"
  printf "  bash deploy.sh deploy --verbose\n\n"
  printf "  # Deploy only the pfsense logstash profile\n"
  printf "  bash deploy.sh deploy --group ingestion/logstash --logstash-profile pfsense\n\n"
  printf "  # Start only the default logstash profile\n"
  printf "  bash deploy.sh start --group ingestion/logstash --logstash-profile default\n\n"
  printf "  # Restart both logstash profiles\n"
  printf "  bash deploy.sh restart --group ingestion/logstash\n\n"
  printf "  # Redeploy only the datalake group\n"
  printf "  bash deploy.sh destroy --group datalake/opensearch\n"
  printf "  bash deploy.sh start   --group datalake/opensearch --verbose\n\n"
  printf "  # Tail logs for a specific container\n"
  printf "  bash deploy.sh logs --service suru.t3.ingestion.logstash-pfsense\n\n"
  printf "  # Health check only\n"
  printf "  bash deploy.sh check\n\n"
  printf "  # Re-import dashboards after an OSD restart\n"
  printf "  bash deploy.sh reimport\n\n"
}

# ── Argument parsing ──────────────────────────────────────────────────────────────────
parse_args() {
  [[ $# -eq 0 ]] && { usage; exit 0; }
  COMMAND="$1"; shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)              DRY_RUN=true ;;
      --verbose)              VERBOSE=true ;;
      --env)                  ENV_FILE="$2"; shift ;;
      --group)                TARGET_GROUP="$2"; shift ;;
      --service)              TARGET_SERVICE="$2"; shift ;;
      --logstash-profile)     LOGSTASH_PROFILE="$2"; LOGSTASH_PROFILE_EXPLICIT=true; shift ;;
      --no-repair-security)   NO_REPAIR_SECURITY=true ;;
      -h|--help)              usage; exit 0 ;;
      *) log WARN "Unknown option: $1" ;;
    esac
    shift
  done

  # Validate --group if provided
  if [[ -n "$TARGET_GROUP" ]]; then
    local valid=false
    for g in "${ALL_GROUPS[@]}"; do
      [[  "$(_group_path "$g")" == "$TARGET_GROUP" ]] && valid=true && break
    done
    if ! $valid; then
      log ERROR "Unknown group: '${TARGET_GROUP}'"
      log ERROR "Valid groups: ${ALL_GROUPS[*]}"
      exit 1
    fi
  fi

  # Validate --logstash-profile if provided
  if [[ "$LOGSTASH_PROFILE" != "all" ]]; then
    local valid_profile=false
    for p in "${LOGSTASH_PROFILES[@]}"; do
      [[  "$p" == "$LOGSTASH_PROFILE" ]] && valid_profile=true && break
    done
    if ! $valid_profile; then
      log ERROR "Unknown logstash profile: '${LOGSTASH_PROFILE}'"
      log ERROR "Valid profiles: all ${LOGSTASH_PROFILES[*]}"
      exit 1
    fi
  fi
}

# ── Dependency check ───────────────────────────────────────────────────────────────────
check_deps() {
  log STEP "Checking dependencies"
  local missing=0
  for cmd in docker openssl curl jq; do
    if command -v "$cmd" >/dev/null 2>&1; then
      $VERBOSE && log OK "$cmd → $(command -v "$cmd")"
    else
      log ERROR "$cmd not found — please install it"; missing=$((missing + 1))
    fi
  done
  local compose_ver
  compose_ver="$(docker compose version 2>/dev/null || true)"
  if ! echo "$compose_ver" | grep -qE "v[2-9]\.|v[1-9][0-9]\."; then
    log ERROR "Docker Compose v2+ required (docker compose, not docker-compose)"
    log ERROR "Detected: ${compose_ver:-not found}"; missing=$((missing + 1))
  else
    $VERBOSE && log OK "Docker Compose $(echo "$compose_ver" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')"
  fi
  case "$(uname -s)" in
    Linux)
      local mc; mc="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
      [[ "$mc" -lt 262144 ]] && \
        log WARN "vm.max_map_count=${mc} < 262144 — run: bash deploy.sh kernel-tune" || \
        { $VERBOSE && log OK "vm.max_map_count=${mc}"; }
      ;;
    Darwin) $VERBOSE && log INFO "macOS: vm.max_map_count check deferred to kernel-tune" ;;
  esac
  [[ $missing -gt 0 ]] && { log ERROR "$missing dependency/ies missing — aborting"; exit 1; }
  log OK "All dependencies satisfied"
}

# ── Load env ───────────────────────────────────────────────────────────────────────────
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    $VERBOSE && log OK "Loaded env from $ENV_FILE"
  else
    log WARN ".env not found at $ENV_FILE — using shell environment only"
  fi

  # Derive Logstash profile from ROUTER_PLATFORM when not set via CLI.
  # pfsense  → logstash-pfsense  (mTLS syslog-ng input, dedicated pfSense pipelines)
  # opnsense → logstash-opnsense  (syslog UDP input, OPNsense pipelines)
  # unset    → all               (starts every profile; fallback for multi-platform setups)
  if ! $LOGSTASH_PROFILE_EXPLICIT && [[ "$LOGSTASH_PROFILE" == "all" ]]; then
    case "${ROUTER_PLATFORM:-}" in
      pfsense)  LOGSTASH_PROFILE="pfsense"  ; log INFO "Logstash profile: pfsense (from ROUTER_PLATFORM)" ;;
      opnsense) LOGSTASH_PROFILE="opnsense"  ; log INFO "Logstash profile: opnsense (from ROUTER_PLATFORM)" ;;
      *)        : ;;  # keep "all" — ROUTER_PLATFORM unset or unknown
    esac
  fi
}

# ── Run or dry-run ─────────────────────────────────────────────────────────────────────
run() {
  if $DRY_RUN; then printf "${C_YELLOW}[DRY-RUN]${C_RESET} %s\n" "$*"
  else $VERBOSE && printf "${C_CYAN}[CMD]${C_RESET} %s\n" "$*"; "$@"; fi
}

# ── Compose helper ─────────────────────────────────────────────────────────────────────
# For ingestion/logstash: automatically applies --profile flags based on
# LOGSTASH_PROFILE. "all" passes no --profile (starts every service).
# Any other value passes --profile <name> to scope to that profile only.
compose_cmd() {
  local group="$1"; shift
  local compose_file="${TIER3_DIR}/${group}/compose.yaml"
  if [[ ! -f "$compose_file" ]]; then
    log ERROR "compose.yaml not found: $compose_file"; return 1
  fi
  local profile_flags=()
  if [[ "$group" == "ingestion/logstash" && "$LOGSTASH_PROFILE" != "all" ]]; then
    profile_flags=(--profile "$LOGSTASH_PROFILE")
    $VERBOSE && log INFO "Logstash profile filter: ${LOGSTASH_PROFILE}"
  elif [[ "$group" == "ingestion/logstash" && "$LOGSTASH_PROFILE" == "all" ]]; then
    # Pass all known profiles explicitly so compose does not skip profile-gated services
    for p in "${LOGSTASH_PROFILES[@]}"; do
      profile_flags+=(--profile "$p")
    done
    $VERBOSE && log INFO "Logstash profiles: all (${LOGSTASH_PROFILES[*]})"
  fi
  run docker compose --env-file "$ENV_FILE" --file "$compose_file" "${profile_flags[@]+${profile_flags[@]}}" "$@"
}

# ── Idempotent one-shot init runner ───────────────────────────────────────────────────
# Pre-removes any leftover container with the same name before `run --rm`, then runs it.
# This is the structural fix for "failed to set up container networking: network <id>
# not found" — a leftover one-shot container from an aborted prior run can pin a deleted
# network ID, which makes every subsequent `run --rm` for that container name fail.
#
# Args:
#   $1  group           — group path, e.g. "datalake/opensearch" or "ingestion/logstash"
#   $2  container_name   — the container_name: value in compose.yaml (also the service key)
#   $3  profile          — Compose profile to pass (e.g. "init", "pfsense", "opnsense")
#   $@  (remaining)      — extra args appended to the compose `run --rm` invocation
run_init() {
  local group="$1" container_name="$2" profile="$3"; shift 3
  local compose_file="${TIER3_DIR}/${group}/compose.yaml"
  # Pre-remove any leftover container with this name (e.g. from an aborted prior
  # run) before `run --rm`. `run()` prints/skips per --dry-run; stderr is
  # suppressed and `|| true` tolerates "no such container" (matches the
  # established `docker network rm ... 2>/dev/null || true` idiom below).
  run docker rm -f "$container_name" 2>/dev/null || true
  run docker compose --env-file "$ENV_FILE" --file "$compose_file" \
    --profile "$profile" run --rm "$container_name" "$@"
}

# ── Container start-time snapshot helpers (recreation detection) ─────────────────────
# Go zero-time — emitted by `docker inspect` for a container that was Created but has
# never actually been started (StartedAt is never set in that state).
readonly _GO_ZERO_TIME="0001-01-01T00:00:00Z"

# snapshot_started_at <container>
# Echoes "absent" if the container does not exist OR has never been started
# (StartedAt == Go zero-time); otherwise echoes the real RFC3339 StartedAt value.
# Always exits 0.
snapshot_started_at() {
  local container="$1" started_at
  started_at="$(docker inspect --format '{{.State.StartedAt}}' -- "$container" 2>/dev/null || true)"
  if [[ -z "$started_at" || "$started_at" == "$_GO_ZERO_TIME" ]]; then
    echo "absent"
  else
    echo "$started_at"
  fi
  return 0
}

# container_recreated <container> <before_snapshot>
# Returns 0 (true — needs init) when the container is not currently running, OR its
# current start-time snapshot differs from <before_snapshot>, OR <before_snapshot> was
# "absent". Returns 1 (false) only when the container is running AND its start time is
# unchanged — i.e. a plain restart of an already-up, unchanged container.
container_recreated() {
  local container="$1" before="$2"
  if [[ "$before" == "absent" ]]; then
    return 0
  fi
  local status
  status="$(docker inspect --format '{{.State.Status}}' -- "$container" 2>/dev/null || echo "missing")"
  [[ "$status" == "running" ]] || return 0
  local after
  after="$(snapshot_started_at "$container")"
  [[ "$after" == "$before" ]] && return 1
  return 0
}

# ── Resolve groups: all or just TARGET_GROUP ─────────────────────────────────────────
# Strip inline bash comments from group name entries in ALL_GROUPS
_group_path() { echo "$1" | awk '{print $1}'; }

resolve_groups() {
  local out=()
  if [[ -n "$TARGET_GROUP" ]]; then
    out=("$TARGET_GROUP")
  else
    for g in "${ALL_GROUPS[@]}"; do out+=("$(_group_path "$g")"); done
  fi
  echo "${out[@]}"
}

resolve_groups_reversed() {
  local groups=()
  if [[ -n "$TARGET_GROUP" ]]; then
    groups=("$TARGET_GROUP")
  else
    for g in "${ALL_GROUPS[@]}"; do groups+=("$(_group_path "$g")"); done
  fi
  local reversed=()
  for (( i=${#groups[@]}-1; i>=0; i-- )); do reversed+=("${groups[$i]}"); done
  echo "${reversed[@]}"
}

# ── Resolve active logstash containers based on LOGSTASH_PROFILE ─────────────────────
resolve_logstash_containers() {
  local out=()
  if [[ "$LOGSTASH_PROFILE" == "all" ]]; then
    for p in "${LOGSTASH_PROFILES[@]}"; do
      out+=("suru.t3.ingestion.logstash-${p}")
    done
  else
    out+=("suru.t3.ingestion.logstash-${LOGSTASH_PROFILE}")
  fi
  echo "${out[@]}"
}

# ═════════════════════════════════════════════════════════════════════════════
# HELPER: check_docker_host_config  (non-blocking preflight)
# ═════════════════════════════════════════════════════════════════════════════
check_docker_host_config() {
  log STEP "Preflight: Docker host configuration"

  local repo_root; repo_root="$(cd "${TIER3_DIR}/.." && pwd)"
  local src_daemon="${repo_root}/tier4-operations/docker/daemon.json"
  local warn=0

  case "$(uname -s)" in
    Darwin)
      # macOS: use daemon-macos.json (log settings only — storage-driver and
      # live-restore are unsupported by Docker Desktop and crash the daemon)
      local src_macos="${repo_root}/tier4-operations/docker/daemon-macos.json"
      local dst_daemon="${HOME}/.docker/daemon.json"
      if [[ ! -f "$dst_daemon" ]]; then
        log WARN "${dst_daemon} not present — run: bash deploy.sh configure-host"
        warn=$((warn + 1))
      elif ! cmp -s "$src_macos" "$dst_daemon"; then
        log WARN "${dst_daemon} differs from managed config — run: bash deploy.sh configure-host"
        $VERBOSE && diff -- "$src_macos" "$dst_daemon" || true
        warn=$((warn + 1))
      else
        log OK "daemon.json matches managed config (${dst_daemon})"
      fi
      [[ $warn -gt 0 ]] && log WARN "Docker host config not applied — deploy continues with daemon defaults"
      return 0
      ;;
  esac

  if [[ ! -f /etc/docker/daemon.json ]]; then
    log WARN "/etc/docker/daemon.json not present — run: bash deploy.sh configure-host"
    warn=$((warn + 1))
  elif ! cmp -s "$src_daemon" /etc/docker/daemon.json; then
    log WARN "/etc/docker/daemon.json differs from managed config — run: bash deploy.sh configure-host"
    $VERBOSE && diff -- "$src_daemon" /etc/docker/daemon.json || true
    warn=$((warn + 1))
  else
    log OK "daemon.json matches managed config"
  fi

  [[ $warn -gt 0 ]] && log WARN "Docker host config not applied — deploy continues with daemon defaults"
  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: configure-host
# ═════════════════════════════════════════════════════════════════════════════
# Deploys daemon.json to the local Docker host via a one-shot Compose service.
# No SSH — runs entirely on this machine (Tier 3).
# Restart Docker afterward for changes to take effect.
cmd_configure_host() {
  local repo_root; repo_root="$(cd "${TIER3_DIR}/.." && pwd)"
  local src_daemon="${repo_root}/tier4-operations/docker/daemon.json"

  case "$(uname -s)" in
    Darwin)
      # Docker Desktop on macOS reads ~/.docker/daemon.json.
      # Use daemon-macos.json (log settings only) — storage-driver and
      # live-restore are unsupported by Docker Desktop and crash the daemon.
      log STEP "Configuring Docker Desktop (macOS)"
      local src_macos="${repo_root}/tier4-operations/docker/daemon-macos.json"
      local dst_daemon="${HOME}/.docker/daemon.json"
      run mkdir -p "${HOME}/.docker"
      run cp -- "$src_macos" "$dst_daemon"
      log OK "daemon-macos.json deployed to ${dst_daemon}"
      log WARN "Restart Docker Desktop to activate: quit and reopen from the menu bar"
      log WARN "  or: osascript -e 'quit app \"Docker\"' && sleep 3 && open -a Docker"
      return 0
      ;;
  esac

  # Linux — deploy via one-shot Compose service that bind-mounts /etc/docker
  log STEP "Configuring local Docker host (daemon.json)"
  local compose_file="${TIER3_DIR}/docker/compose.yaml"
  [[ -f "$compose_file" ]] || { log ERROR "docker/compose.yaml not found: $compose_file"; exit 1; }
  run docker compose --file "$compose_file" run --rm suru.t3.docker-host-init
  log OK "Docker host configuration deployed"
  log WARN "Restart Docker to activate: sudo systemctl restart docker"
  log WARN "live-restore=true is enabled — containers survive daemon restart."
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: kernel-tune
# ═════════════════════════════════════════════════════════════════════════════
cmd_kernel_tune() {
  log STEP "Kernel tuning — vm.max_map_count (OpenSearch requirement)"
  case "$(uname -s)" in
    Linux)
      local current; current="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
      if [[ "$current" -ge 262144 ]]; then
        log OK "vm.max_map_count=${current} (already sufficient)"
      else
        log INFO "Raising vm.max_map_count from ${current} to 262144"
        run sudo sysctl -w vm.max_map_count=262144
        grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null || \
          run sudo bash -c 'echo "vm.max_map_count=262144" >> /etc/sysctl.conf'
        log OK "vm.max_map_count=262144 set and persisted"
      fi
      ;;
    Darwin)
      log INFO "macOS — applying vm.max_map_count inside Docker VM"
      $DRY_RUN && { log INFO "[DRY-RUN] Would run sysctl inside Docker VM"; return 0; }
      local current
      current="$(docker run --rm --privileged --pid=host \
        busybox:1.37.0@sha256:7a3ebe5bfd1a4a19797d20b0c0bb39d44393e9a03fd852c0865b0f540d868df0 sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
      if [[ "$current" -ge 262144 ]]; then
        log OK "Docker VM vm.max_map_count=${current}"
      else
        docker run --rm --privileged --pid=host busybox:1.37.0@sha256:7a3ebe5bfd1a4a19797d20b0c0bb39d44393e9a03fd852c0865b0f540d868df0 sysctl -w vm.max_map_count=262144
        log OK "vm.max_map_count=262144 applied inside Docker VM (resets on Docker restart)"
        log WARN "To persist, add to ~/.lima/colima/override.yaml or Docker Desktop settings"
      fi
      ;;
    *MINGW*|*MSYS*|*CYGWIN*)
      log WARN "Windows host — apply inside WSL2: wsl -d docker-desktop sh -c 'sysctl -w vm.max_map_count=262144'"
      ;;
    *) log WARN "Unknown OS — ensure vm.max_map_count >= 262144 in your container runtime" ;;
  esac
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: certs
# ═════════════════════════════════════════════════════════════════════════════
cmd_certs() {
  log STEP "Generating TLS certificates"
  local certs_dir="${TIER3_DIR}/certs"
  # PKI authority lives in Tier 4 — one Root CA signs all service certs.
  local repo_root; repo_root="$(cd "${TIER3_DIR}/.." && pwd)"
  local pki_script="${repo_root}/tier4-operations/pki/scripts/generate-certs.sh"

  # Idempotent skip: if the key service certs are already present, nothing to do.
  if [[ -f "${certs_dir}/root-ca.pem" && \
        -f "${certs_dir}/node.pem"    && \
        -f "${certs_dir}/logstash.pem" ]]; then
    $VERBOSE && log OK "TLS certificates already present in ${certs_dir} — skipping generation"
    log OK "TLS certificates ready in ${certs_dir}"
    return 0
  fi

  # Certs absent — run the Tier 4 PKI bootstrap (generates Root CA + all Tier 3 service certs).
  log WARN "TLS certificates not found in ${certs_dir} — running PKI bootstrap"
  if [[ ! -f "$pki_script" ]]; then
    log ERROR "PKI bootstrap script not found: ${pki_script}"
    log ERROR "Run it manually first: bash tier4-operations/pki/scripts/generate-certs.sh"
    exit 1
  fi
  [[ -x "$pki_script" ]] || chmod +x "$pki_script"
  local flags=()
  $DRY_RUN && flags+=("--dry-run")
  $VERBOSE && flags+=("--verbose")
  run bash "$pki_script" "${flags[@]+${flags[@]}}"
  $DRY_RUN || log OK "TLS certificates ready in ${certs_dir}"
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: network
# ═════════════════════════════════════════════════════════════════════════════
cmd_network() {
  log STEP "Ensuring shared external network: suru-t3-core-internal"
  local net="suru-t3-core-internal"
  if docker network inspect "$net" >/dev/null 2>&1; then
    log OK "Network ${net} already exists"
  else
    run docker network create --driver bridge \
      --label project=suru \
      --label tier=t3 \
      --label managed_by=deploy.sh \
      "$net"
    log OK "Created network: ${net}"
  fi
}

# Removes a Compose-managed network if it exists with stale/wrong labels.
ensure_network_clean() {
  local net_name="$1"
  local expected_project="$2"
  local expected_key="$3"

  if ! docker network inspect "$net_name" >/dev/null 2>&1; then
    return 0
  fi

  local actual_project actual_key
  actual_project="$(docker network inspect "$net_name" \
    --format '{{ index .Labels "com.docker.compose.project" }}')"
  actual_key="$(docker network inspect "$net_name" \
    --format '{{ index .Labels "com.docker.compose.network" }}')"

  if [[ "$actual_project" == "$expected_project" && "$actual_key" == "$expected_key" ]]; then
    log OK "Network ${net_name} labels OK (project=${expected_project}, key=${expected_key})"
    return 0
  fi

  log WARN "Network ${net_name} has stale labels (project=\"${actual_project}\" key=\"${actual_key}\") — removing for Compose to recreate"
  run docker network rm "$net_name"
}


# ═════════════════════════════════════════════════════════════════════════════
# HELPER: repair_security_credentials_if_needed
# ═════════════════════════════════════════════════════════════════════════════
# Probe-driven repair for ANY persistent admin-credential failure against the
# running OpenSearch container — not just drift against a surviving volume.
#
# This also covers a fresh bootstrap: DISABLE_INSTALL_DEMO_CONFIG=true disables
# the image's only password-substitution mechanism, so on a brand-new
# opensearch-data volume the security index still seeds with the image's
# bundled default credential hash, not OPENSEARCH_INITIAL_ADMIN_PASSWORD. The
# healthcheck (which authenticates with that real password) can never pass
# until security-init has run — identical deadlock to password drift against a
# surviving volume. The probe below treats both cases identically: a 401 means
# "the security index does not have today's admin credential," regardless of
# whether the volume is new or old, and triggers the same repair.
#
# Repair re-runs security-init via its mTLS admin-cert path (securityadmin.sh
# authenticates with the admin client cert, not the REST password, so it works
# even though the basic-auth healthcheck is failing).
#
# Args: $1 — "force" used by `repair`, an explicit operator-invoked recovery.
#            No functional difference from the default "gated" mode anymore —
#            the function is unconditionally probe-driven in both modes; the
#            arg is retained so call sites stay self-documenting.
# ── Single-node system-index replica normalization ────────────────────────────
# On this single-node cluster (discovery.type: single-node) a replica shard can
# never allocate alongside its own primary, so any plugin-created index born
# with replicas > 0 (SA .opensearch-sap-*, alerting config/history, ISM
# bookkeeping) leaves the cluster permanently yellow. suru-* is covered by the
# ECS template (replicas 0) and ISM history by opensearch.yml
# (plugins.index_state_management.history.number_of_replicas: 0) — this handles
# everything else the plugins create with no replica-count setting of their
# own. auto_expand_replicas 0-1 self-shrinks to 0 replicas on one node and
# grows back automatically if a node ever joins (same mechanism the security
# plugin uses for .opendistro_security). Idempotent: re-PUTting the same value
# is a no-op; best-effort: a failure here must never abort a start.
normalize_system_index_replicas() {
  if ! docker inspect suru.t3.datalake.opensearch >/dev/null 2>&1; then
    return 0
  fi
  if $DRY_RUN; then
    log INFO "[DRY-RUN] Would apply auto_expand_replicas 0-1 to plugin system indices (single-node green)"
    return 0
  fi
  log INFO "Normalizing plugin system-index replicas (single-node: auto_expand_replicas 0-1)..."
  if docker exec suru.t3.datalake.opensearch sh -c \
    'curl -sk -u "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" -X PUT \
      "https://localhost:9200/.opendistro-ism-*,.opensearch-sap-*,.opendistro-alerting-*,.opensearch-alerting-*/_settings?expand_wildcards=all&ignore_unavailable=true" \
      -H "Content-Type: application/json" \
      -d "{\"index\":{\"auto_expand_replicas\":\"0-1\"}}"' | grep -q '"acknowledged":true'; then
    log OK "System-index replicas normalized"
  else
    log WARN "System-index replica normalization not acknowledged — cluster may stay yellow (harmless); inspect with: _cat/indices?health=yellow&expand_wildcards=all"
  fi
}

repair_security_credentials_if_needed() {
  local mode="${1:-gated}"

  if $NO_REPAIR_SECURITY; then
    log INFO "Automatic admin-credential seed/repair disabled (--no-repair-security) — skipping"
    return 0
  fi

  if ! docker inspect suru.t3.datalake.opensearch >/dev/null 2>&1; then
    $VERBOSE && log INFO "OpenSearch container not present yet — skipping credential check"
    return 0
  fi

  if $DRY_RUN; then
    log INFO "[DRY-RUN] Would probe OpenSearch admin credentials (docker exec curl) and auto-repair security-init on any definitive non-200 response — covers both fresh bootstrap and drift against a surviving volume"
    return 0
  fi

  log INFO "Probing OpenSearch admin credentials (mode=${mode})..."
  local http_code="" attempt=0 max_attempts=12
  while [[ $attempt -lt $max_attempts ]]; do
    http_code="$(docker exec suru.t3.datalake.opensearch \
      curl -sk -o /dev/null -w '%{http_code}' \
      -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
      https://localhost:9200/_cluster/health 2>/dev/null || true)"
    # Any well-formed, non-"000" 3-digit HTTP status is a definitive response —
    # stop polling. This covers 200 (healthy), 401 (credential mismatch), and
    # 503 (security plugin up but .opendistro_security index doesn't exist yet
    # — seen live on a genuinely fresh bootstrap with
    # allow_default_init_securityindex=false, where the plugin never
    # auto-creates the index and only security-init's securityadmin.sh can).
    # "000" is curl's documented %{http_code} output on a failed/refused
    # connection or timeout (curl(1), -w section) — NOT a real HTTP status —
    # and must be excluded here, or a container whose HTTPS listener simply
    # hasn't come up yet on attempt 1 gets misclassified as a definitive
    # failure and short-circuits straight into a repair run against a
    # not-yet-listening OpenSearch. Empty/connection-refused/000 means
    # OpenSearch's HTTP listener itself isn't up yet — keep waiting for that
    # specifically.
    [[ "$http_code" =~ ^[0-9]{3}$ && "$http_code" != "000" ]] && break
    attempt=$((attempt + 1))
    $VERBOSE && log INFO "  OpenSearch not yet answering (attempt ${attempt}/${max_attempts}) — waiting..."
    sleep 5
  done

  if [[ "$http_code" == "200" ]]; then
    $VERBOSE && log OK "Admin credentials valid — no repair needed"
    return 0
  elif [[ "$http_code" =~ ^[0-9]{3}$ && "$http_code" != "000" ]]; then
    log WARN "Admin credentials not yet usable (HTTP ${http_code} from OpenSearch) — auto-repairing security index via admin mTLS cert"
    log INFO "Re-running security-init, bypassing the service_healthy gate (securityadmin.sh authenticates via admin client cert, not the REST password — and creates .opendistro_security itself if it doesn't exist yet)"
    run docker compose --env-file "$ENV_FILE" \
      --file "${TIER3_DIR}/datalake/opensearch/compose.yaml" \
      run --rm --no-deps suru.t3.datalake.security-init
    log OK "Security index re-synced — re-probing admin credentials"
    local recheck
    recheck="$(docker exec suru.t3.datalake.opensearch \
      curl -sk -o /dev/null -w '%{http_code}' \
      -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
      https://localhost:9200/_cluster/health 2>/dev/null || true)"
    if [[ "$recheck" == "200" ]]; then
      log OK "Admin credentials valid after repair"
    else
      log ERROR "Admin credentials still failing after security-init repair (http_code=${recheck:-none})"
      return 1
    fi
    return 0
  else
    $VERBOSE && log WARN "Could not get a definitive health probe response (last http_code='${http_code:-none}') — skipping repair, wait_healthy will report the real failure"
    return 0
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# HELPER: assert_dashboards_imported
# ═════════════════════════════════════════════════════════════════════════════
# Verifies that .kibana actually contains imported dashboards (total > 0), not
# merely that the saved_objects API answered. One auto-reimport retry on an
# empty/unparseable result; hard-fails (return 1) if still empty after that.
assert_dashboards_imported() {
  local group="$1"
  local dash_user="${OPENSEARCH_DASHBOARDS_USER:-kibanaserver}"
  local dash_pass="${OPENSEARCH_DASHBOARDS_PASSWORD:-admin}"

  if $DRY_RUN; then
    log INFO "[DRY-RUN] Would assert dashboards saved_objects total > 0 (and auto-reimport once if empty)"
    return 0
  fi

  local total
  total="$(docker exec suru.t3.datalake.dashboards \
    curl -sk -u "${dash_user}:${dash_pass}" \
    'https://localhost:5601/dashboards/api/saved_objects/_find?type=dashboard&per_page=1' \
    2>/dev/null | jq -r '.total // empty' 2>/dev/null || true)"

  if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
    log OK "Dashboards saved objects present (total=${total})"
    return 0
  fi

  log WARN "Dashboards saved_objects total is ${total:-unparseable} — triggering one auto-reimport attempt"
  run_init "$group" "suru.t3.datalake.dashboard-importer" "init"
  sleep 5

  total="$(docker exec suru.t3.datalake.dashboards \
    curl -sk -u "${dash_user}:${dash_pass}" \
    'https://localhost:5601/dashboards/api/saved_objects/_find?type=dashboard&per_page=1' \
    2>/dev/null | jq -r '.total // empty' 2>/dev/null || true)"

  if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
    log OK "Dashboards saved objects present after auto-reimport (total=${total})"
    return 0
  fi

  log ERROR "Dashboards saved_objects total is still ${total:-unparseable} after auto-reimport — .kibana appears empty"
  log ERROR "Operator recovery: bash scripts/deploy.sh repair"
  return 1
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: start
# ═════════════════════════════════════════════════════════════════════════════
cmd_start() {
  local ls_label=""
  [[ "$LOGSTASH_PROFILE" != "all" ]] && ls_label=" [logstash profile: ${LOGSTASH_PROFILE}]"
  log STEP "Starting Tier 3 service groups${TARGET_GROUP:+ — group: ${TARGET_GROUP}}${ls_label}"
  load_env
  local groups
  read -ra groups <<< "$(resolve_groups)"
  # Snapshot container start times before compose up so recreation can be detected below.
  local _dash_started_before="" _os_started_before=""
  for group in "${groups[@]}"; do
    log INFO "Starting group: ${group}"

    case "$group" in
      datalake/opensearch)
        ensure_network_clean "suru-t3-datalake-internal"  "suru-t3-datalake"  "datalake-internal"
        _os_started_before="$(snapshot_started_at suru.t3.datalake.opensearch)"
        _dash_started_before="$(snapshot_started_at suru.t3.datalake.dashboards)"
        # compose.yaml deliberately keeps `depends_on: security-init: condition:
        # service_healthy` (and the same on dashboards) strict — security-init is
        # the single authority allowed to seed the security index (SEC-076); we do
        # not weaken that dependency graph here. Instead, two distinct deadlock
        # shapes against that strict graph are broken by sequencing the
        # `compose up -d` calls below, not by editing compose.yaml:
        #
        # Branch A — container already existed from a prior run
        # ("$_os_started_before" != "absent"): opensearch may currently be
        # unhealthy (e.g. it exhausted its healthcheck retries waiting on admin
        # credentials that were never seeded). In that case a plain
        # `compose up -d` for the whole group refuses to proceed at all:
        # security-init/dashboards depend on `opensearch: condition:
        # service_healthy`, and compose treats an already-unhealthy dependency as
        # fatal before attempting to start anything — "dependency ... failed to
        # start: container ... is unhealthy" — aborting before the post-up-d
        # repair call further down ever runs. Repair (and let the healthcheck
        # catch up) BEFORE the shared full `up -d` below, so compose sees a
        # healthy dependency by the time it evaluates the condition.
        #
        # Branch B — true first-ever bootstrap
        # ("$_os_started_before" == "absent"): there is nothing to probe/repair
        # yet (Branch A's guard correctly skips), but a plain `compose up -d` for
        # the whole group is ITSELF the deadlock here: opensearch's healthcheck
        # can only ever pass once security-init has seeded the security index via
        # the admin mTLS cert (bypassing the broken REST password) — but
        # security-init/dashboards are gated behind that exact same
        # `service_healthy` condition on opensearch, so compose never even
        # attempts to start security-init. The group blocks for the full
        # healthcheck retry budget (~270s) and then fails outright. Break this by
        # bringing up ONLY opensearch first (explicit service arg — NOT
        # `--no-deps`, so compose still resolves and starts opensearch's own
        # `service_completed_successfully` dependency on config-init; naming
        # opensearch as the target rather than the whole group is what excludes
        # security-init/dashboards, which depend on opensearch itself), then
        # running the same repair helper to seed the security index via the admin
        # mTLS cert once opensearch is reachable. Both branches then fall through
        # to the SAME shared full `up -d` (idempotent on the now-healthy
        # opensearch container) which is what actually starts security-init and
        # dashboards against a dependency condition that can now genuinely pass.
        if [[ "$_os_started_before" != "absent" ]]; then
          # Best-effort: a non-zero return here must NOT abort the script under
          # set -e/ERR-trap — this call exists only to get a pre-existing
          # container's healthcheck passing before `compose up -d` evaluates
          # `depends_on: condition: service_healthy`. The unchanged post-up-d
          # repair_security_credentials_if_needed (bare, fatal) is the
          # authoritative pass/fail gate; if repair is still broken after
          # this attempt, that later call reports and fails the run properly.
          repair_security_credentials_if_needed || true
          wait_healthy "suru.t3.datalake.opensearch" 120 || true
        else
          # Fresh bootstrap: stage 1 of 2 — bring up only opensearch (+ its own
          # `service_completed_successfully` deps, e.g. config-init) so it has a
          # running container to probe/repair against. Unlike Branch A above,
          # there is no later fallback on this path if repair hard-fails here, so
          # this call is bare (not `|| true`) — a real failure aborts via the
          # existing ERR trap, matching the post-up-d block's fatal semantics.
          log INFO "Fresh bootstrap detected — starting opensearch alone first to break the security-init healthcheck deadlock"
          compose_cmd "$group" up -d --remove-orphans suru.t3.datalake.opensearch
          repair_security_credentials_if_needed
        fi
        ;;
    esac

    # Stage 2 (fresh bootstrap) / only stage (existing container): shared full
    # `up -d` for the whole group. Idempotent on the already-started opensearch
    # container; this is what actually brings up security-init/dashboards, which
    # by this point see a genuinely healthy opensearch and proceed normally.
    compose_cmd "$group" up -d --remove-orphans
    log OK "Started: ${group}"

    case "$group" in
      datalake/opensearch)
        repair_security_credentials_if_needed
        wait_healthy "suru.t3.datalake.opensearch" 120
        # Re-apply index templates only when OpenSearch was recreated or created fresh.
        if container_recreated "suru.t3.datalake.opensearch" "$_os_started_before"; then
          $DRY_RUN && log INFO "[DRY-RUN] Would apply index templates (OpenSearch recreated or new)" \
            || log INFO "OpenSearch recreated — applying index templates..."
          run_init "$group" "suru.t3.datalake.template-init" "init"
          $DRY_RUN && log INFO "[DRY-RUN] Would apply ISM retention policies" \
            || log INFO "Applying ISM retention policies..."
          run_init "$group" "suru.t3.datalake.ism-policy-init" "init"
        else
          log INFO "OpenSearch unchanged — skipping template-init and ism-policy-init"
        fi
        # Run every start (idempotent, best-effort) — plugins create new
        # bookkeeping indices on their own cadence; see the function header.
        normalize_system_index_replicas || true
        wait_healthy "suru.t3.datalake.dashboards" 180
        # Re-import dashboards only when the Dashboards container was recreated or created
        # fresh. Running the importer unconditionally on every start would silently
        # overwrite any customisations an operator made in the Dashboards UI.
        if container_recreated "suru.t3.datalake.dashboards" "$_dash_started_before"; then
          $DRY_RUN && log INFO "[DRY-RUN] Would import dashboards (Dashboards container recreated or new)" \
            || log INFO "Dashboards container recreated — importing dashboards..."
          run_init "$group" "suru.t3.datalake.dashboard-importer" "init"
        else
          log INFO "Dashboards unchanged — skipping import (use 'reimport' to force)"
        fi
        assert_dashboards_imported "$group"
        ;;
      ingestion/logstash)
        # Re-run volume-init for each active logstash profile before up
        local ls_containers
        read -ra ls_containers <<< "$(resolve_logstash_containers)"
        for cname in "${ls_containers[@]}"; do
          local profile_name="${cname##*logstash-}"
          local init_svc="suru.t3.ingestion.volume-init-${profile_name}"
          log INFO "Ensuring volume ownership for ${cname} (uid 1000)..."
          run_init "$group" "$init_svc" "$profile_name"
          wait_healthy "${cname}" 120
        done
        ;;
    esac
  done
  log OK "Start complete"
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: stop
# ═════════════════════════════════════════════════════════════════════════════
cmd_stop() {
  local ls_label=""
  [[ "$LOGSTASH_PROFILE" != "all" ]] && ls_label=" [logstash profile: ${LOGSTASH_PROFILE}]"
  log STEP "Stopping Tier 3 service groups${TARGET_GROUP:+ — group: ${TARGET_GROUP}}${ls_label}"
  load_env
  local groups
  read -ra groups <<< "$(resolve_groups_reversed)"
  for group in "${groups[@]}"; do
    log INFO "Stopping group: ${group}"
    compose_cmd "$group" down --remove-orphans --timeout 30
    log OK "Stopped: ${group}"
  done
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: restart
# ═════════════════════════════════════════════════════════════════════════════
cmd_restart() {
  cmd_stop
  cmd_start
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: deploy
# ═════════════════════════════════════════════════════════════════════════════
cmd_deploy() {
  if [[ -n "$TARGET_GROUP" ]]; then
    log STEP "Targeted deploy — group: ${TARGET_GROUP}${LOGSTASH_PROFILE:+ [logstash profile: ${LOGSTASH_PROFILE}]}"
    load_env
    cmd_network
    cmd_start
    print_access_summary
  else
    log STEP "SURU Tier 3 — Full Deployment"
    check_deps
    load_env
    check_docker_host_config
    cmd_kernel_tune
    cmd_certs
    cmd_network
    cmd_start
    cmd_check
    print_access_summary
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: destroy
# ═════════════════════════════════════════════════════════════════════════════
cmd_destroy() {
  log STEP "Destroying containers and networks${TARGET_GROUP:+ — group: ${TARGET_GROUP}} (volumes preserved)"
  load_env
  local groups
  read -ra groups <<< "$(resolve_groups_reversed)"
  for group in "${groups[@]}"; do
    log INFO "Removing group: ${group}"
    # --profile init: `down` only considers containers in its currently-active
    # profile set, same as `up`. template-init/ism-policy-init/dashboard-importer
    # (datalake/opensearch) are `profiles: [init]` one-shot containers — without
    # this flag, `down` silently leaves them in place (Created/Exited, but never
    # removed), which then blocks volume removal on a later destroy-all with
    # "Resource is still in use". Harmless no-op for groups without an "init"
    # profile (e.g. ingestion/logstash).
    compose_cmd "$group" --profile init down --remove-orphans --timeout 30 --volumes=false
    log OK "Removed: ${group}"
  done
  if [[ -z "$TARGET_GROUP" ]]; then
    run docker network rm suru-t3-core-internal        2>/dev/null || true
    run docker network rm suru-t3-datalake-internal    2>/dev/null || true
    log OK "Networks removed"
  else
    case "$TARGET_GROUP" in
      datalake/opensearch)
        run docker network rm suru-t3-datalake-internal   2>/dev/null || true ;;
    esac
  fi
  log OK "Destroy complete (data volumes retained)"
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: destroy-all
# ═════════════════════════════════════════════════════════════════════════════
cmd_destroy_all() {
  log WARN "⚠️  This will DELETE all data volumes — irreversible!"
  if ! $DRY_RUN; then
    read -r -p "Type 'yes-destroy-all' to confirm: " confirm
    [[  "$confirm" == "yes-destroy-all" ]] || { log INFO "Aborted."; exit 0; }
  fi
  log STEP "Destroying containers, networks AND volumes${TARGET_GROUP:+ — group: ${TARGET_GROUP}}"
  load_env
  local groups
  read -ra groups <<< "$(resolve_groups_reversed)"
  for group in "${groups[@]}"; do
    log INFO "Removing group with volumes: ${group}"
    # --profile init: see cmd_destroy for why this is required — without it,
    # leftover profile-gated one-shot containers survive `down --volumes` and
    # block the very volume removal this command exists to perform.
    compose_cmd "$group" --profile init down --volumes --remove-orphans --timeout 30
    log OK "Removed: ${group}"
  done
  if [[ -z "$TARGET_GROUP" ]]; then
    run docker network rm suru-t3-core-internal     2>/dev/null || true
    run docker network rm suru-t3-datalake-internal 2>/dev/null || true
  fi
  log OK "Full destruction complete"
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: status
# ═════════════════════════════════════════════════════════════════════════════
cmd_status() {
  log STEP "Container Status"
  printf "\n%-48s %-12s %-15s %s\n" "CONTAINER" "HEALTH" "STATUS" "PORTS"
  printf '%0.s─' {1..100}; echo

  # Build logstash container list based on active profile
  local ls_containers=()
  read -ra ls_containers <<< "$(resolve_logstash_containers)"

  local containers=(
    suru.t3.datalake.opensearch
    suru.t3.datalake.dashboards
    suru.t3.datalake.template-init
    suru.t3.datalake.dashboard-importer
    "${ls_containers[@]}"
  )
  for cname in "${containers[@]}"; do
    if docker inspect "$cname" >/dev/null 2>&1; then
      local state health ports
      state="$(docker inspect --format='{{.State.Status}}' -- "$cname")"
      health="$(docker inspect \
        --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' \
        -- "$cname")"
      ports="$(docker inspect \
        --format='{{range $p,$c := .NetworkSettings.Ports}}{{$p}}->{{(index $c 0).HostPort}} {{end}}' \
        -- "$cname" 2>/dev/null | tr -d '\n' | sed 's/ $//')"
      case "$health" in
        healthy)   health="${C_GREEN}healthy${C_RESET}" ;;
        unhealthy) health="${C_RED}unhealthy${C_RESET}" ;;
        starting)  health="${C_YELLOW}starting${C_RESET}" ;;
        *)         health="${C_CYAN}${health}${C_RESET}" ;;
      esac
      case "$state" in
        running) state="${C_GREEN}running${C_RESET}" ;;
        exited)  state="${C_RED}exited${C_RESET}" ;;
        *)       state="${C_YELLOW}${state}${C_RESET}" ;;
      esac
      printf "%-48s %-22b %-25b %s\n" "$cname" "$health" "$state" "$ports"
    else
      printf "%-48s %-12s %-15s\n" "$cname" "─" "not found"
    fi
  done
  echo
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: check
# ═════════════════════════════════════════════════════════════════════════════
cmd_check() {
  log STEP "Deep Service Health Checks"
  load_env
  local pass=0 fail=0 warn=0

  probe() {
    local name="$1" cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
      printf "  ${C_GREEN}✅ PASS${C_RESET}  %s\n" "$name"; pass=$((pass + 1))
    else
      printf "  ${C_RED}❌ FAIL${C_RESET}  %s\n" "$name"
      fail=$((fail + 1))
    fi
  }
  probe_warn() {
    local name="$1" cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
      printf "  ${C_GREEN}✅ PASS${C_RESET}  %s\n" "$name"; pass=$((pass + 1))
    else
      printf "  ${C_YELLOW}⚠️  WARN${C_RESET}  %s\n" "$name"; warn=$((warn + 1))
    fi
  }

  # Backends no longer bind host ports — probe each one through docker exec
  # so the check works regardless of the frontdoor's state. Frontdoor itself
  # is probed last via its public healthz endpoint.
  local OS_PASS="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-admin}"
  local DASH_USER="${OPENSEARCH_DASHBOARDS_USER:-kibanaserver}"
  local DASH_PASS="${OPENSEARCH_DASHBOARDS_PASSWORD:-admin}"

  echo ""
  log INFO "── OpenSearch ───────────────────────────────────────────────────────────────"
  probe "OpenSearch REST API reachable" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} https://localhost:9200 | grep -q 'cluster_name'"
  probe "Cluster status green/yellow" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} https://localhost:9200/_cluster/health | grep -Eq '\"status\":\"(green|yellow)\"'"
  probe "Node count >= 1" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} https://localhost:9200/_cat/nodes | grep -qE '[0-9]+\\.[0-9]+'"
  probe "suru-ecs-template applied (suru-* pattern, priority 100)" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} 'https://localhost:9200/_index_template/suru-ecs-template' | grep -q '\"suru-\\*\"'"
  probe_warn "suru-pfsense index accessible" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} 'https://localhost:9200/_cat/indices/suru-pfsense-*?h=status' | grep -q 'open'"
  probe_warn "suru-suricata index exists" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} 'https://localhost:9200/_cat/indices/suru-suricata-*?h=status' | grep -q 'open'"
  probe_warn "suru-zeek index exists" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} 'https://localhost:9200/_cat/indices/suru-zeek-*?h=status' | grep -q 'open'"
  probe_warn "suru-pfblockerng index accessible" \
    "docker exec suru.t3.datalake.opensearch curl -sk -u admin:${OS_PASS} 'https://localhost:9200/_cat/indices/suru-pfblockerng-*?h=status' | grep -q 'open'"

  echo ""
  log INFO "── OpenSearch Dashboards ───────────────────────────────────────────────────────────────"
  probe "Dashboards API reachable" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} https://localhost:5601/dashboards/api/status | grep -q 'state'"
  probe "Dashboards state green/yellow" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} https://localhost:5601/dashboards/api/status | grep -Eq '\"state\":\"(green|yellow)\"'"
  probe_warn "Dashboards saved objects imported" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/_find?type=dashboard&per_page=1' | jq -e '.total > 0' >/dev/null"
  probe_warn "index-pattern: suru-pfsense-* exists" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/index-pattern/suru-pfsense-index-pattern' | grep -q '\"type\":\"index-pattern\"'"
  probe_warn "index-pattern: suru-suricata-* exists" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/index-pattern/suru-ids-index-pattern' | grep -q '\"type\":\"index-pattern\"'"
  probe_warn "index-pattern: suru-zeek-* exists" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/index-pattern/suru-netservices-index-pattern' | grep -q '\"type\":\"index-pattern\"'"
  probe_warn "index-pattern: suru-pfblockerng-* exists" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/index-pattern/suru-pfblockerng-index-pattern' | grep -q '\"type\":\"index-pattern\"'"
  probe_warn "index-pattern: suru-* exists" \
    "docker exec suru.t3.datalake.dashboards curl -sk -u ${DASH_USER}:${DASH_PASS} 'https://localhost:5601/dashboards/api/saved_objects/index-pattern/suru-all-index-pattern' | grep -q '\"type\":\"index-pattern\"'"

  echo ""
  log INFO "── Logstash Instances (profile: ${LOGSTASH_PROFILE}) ────────────────────────────────────────────"
  local ls_containers=()
  read -ra ls_containers <<< "$(resolve_logstash_containers)"
  for cname in "${ls_containers[@]}"; do
    probe "${cname} metrics API reachable" \
      "docker exec ${cname} curl -sk http://localhost:9600 | grep -q 'status'"
    probe_warn "${cname} pipeline running" \
      "docker exec ${cname} curl -sk http://localhost:9600/_node/stats/pipelines | grep -q '\"events\"'"
  done

  echo ""
  log INFO "── Monitoring ────────────────────────────────────────────────────────────────────────"
  probe_warn "Prometheus reachable" \
    "docker exec suru.t4.monitoring.prometheus wget -qO- http://localhost:9090/-/healthy | grep -qi 'ok\\|healthy'"
  probe_warn "Grafana reachable" \
    "docker exec suru.t4.monitoring.grafana wget -qO- http://localhost:3000/api/health | grep -q 'ok'"
  probe_warn "InfluxDB reachable" \
    "docker exec suru.t4.monitoring.influxdb wget -qO- http://localhost:8086/health | grep -q 'pass'"

  echo ""
  log INFO "── Frontdoor (public LAN entry point) ────────────────────────────────────────────────────────"
  probe_warn "Frontdoor /healthz reachable" \
    "curl -sk https://localhost:${FRONTDOOR_PORT:-443}/healthz | grep -q 'ok'"

  echo ""
  printf "  Results: ${C_GREEN}%d passed${C_RESET}  ${C_YELLOW}%d warned${C_RESET}  ${C_RED}%d failed${C_RESET}\n\n" \
    "$pass" "$warn" "$fail"
  [[ $fail -gt 0 ]] && return 1 || return 0
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: logs
# ═════════════════════════════════════════════════════════════════════════════
cmd_logs() {
  load_env
  if [[ -n "$TARGET_SERVICE" ]]; then
    log INFO "Tailing logs for container: ${TARGET_SERVICE}"
    run docker logs --follow --tail 100 -- "$TARGET_SERVICE"
  elif [[ -n "$TARGET_GROUP" ]]; then
    log INFO "Tailing logs for group: ${TARGET_GROUP}"
    compose_cmd "$TARGET_GROUP" logs --follow --tail 50
  else
    log INFO "Tailing logs for all Tier 3 groups (Ctrl+C to stop)"
    local compose_files=()
    for g in "${ALL_GROUPS[@]}"; do
      local gpath; gpath="$(_group_path "$g")"
      [[ -f "${TIER3_DIR}/${gpath}/compose.yaml" ]] && compose_files+=(--file "${TIER3_DIR}/${gpath}/compose.yaml")
    done
    run docker compose --env-file "$ENV_FILE" "${compose_files[@]}" logs --follow --tail 50
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: reimport
# ═════════════════════════════════════════════════════════════════════════════
cmd_reimport() {
  load_env
  log STEP "Re-importing OpenSearch Dashboards"
  run_init "datalake/opensearch" "suru.t3.datalake.dashboard-importer" "init"
  log OK "Dashboard reimport complete"
}

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND: repair
# ═════════════════════════════════════════════════════════════════════════════
# Single-command operator recovery: re-sync the security index (bypassing the
# service_healthy gate so password drift can be repaired even when OpenSearch
# is reporting unhealthy for that exact reason), re-apply index templates and
# ISM policies, then verify dashboards are actually imported (not just that
# Dashboards itself is reachable).
cmd_repair() {
  log STEP "Tier 3 — Recovery: security re-sync, templates/policies, dashboards verification"
  load_env

  log INFO "Step 1/7 — Re-sync security index if admin credentials are missing or have drifted"
  repair_security_credentials_if_needed "force"

  log INFO "Step 2/7 — Re-apply OpenSearch index templates"
  run_init "datalake/opensearch" "suru.t3.datalake.template-init" "init"

  log INFO "Step 3/7 — Re-apply ISM retention policies"
  run_init "datalake/opensearch" "suru.t3.datalake.ism-policy-init" "init"

  log INFO "Step 4/7 — Normalize plugin system-index replicas (single-node green)"
  normalize_system_index_replicas || true

  log INFO "Step 5/7 — Wait for Dashboards to report healthy"
  wait_healthy "suru.t3.datalake.dashboards" 180

  log INFO "Step 6/7 — Re-run the dashboard importer"
  run_init "datalake/opensearch" "suru.t3.datalake.dashboard-importer" "init"

  log INFO "Step 7/7 — Verify dashboards are actually imported"
  assert_dashboards_imported "datalake/opensearch"

  log OK "Repair complete"
}

# ═════════════════════════════════════════════════════════════════════════════
# HELPER: wait_healthy
# ═════════════════════════════════════════════════════════════════════════════
wait_healthy() {
  local container="$1" timeout="${2:-120}" elapsed=0 interval=10
  log INFO "Waiting for ${container} to be healthy (timeout: ${timeout}s)..."
  if $DRY_RUN; then log INFO "[DRY-RUN] Skipping wait for ${container}"; return 0; fi
  while true; do
    local status
    status="$(docker inspect \
      --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}' \
      -- "$container" 2>/dev/null || echo "missing")"
    case "$status" in
      healthy|running) log OK "${container} is ${status}"; return 0 ;;
      missing)         log ERROR "Container ${container} not found"; return 1 ;;
    esac
    if [[ $elapsed -ge $timeout ]]; then
      log ERROR "Timeout waiting for ${container} (status: ${status})"
      log WARN  "Inspect logs: bash deploy.sh logs --service ${container}"
      return 1
    fi
    $VERBOSE && log INFO "  ${container} → ${status} (${elapsed}s / ${timeout}s)"
    sleep "$interval"; elapsed=$((elapsed + interval))
  done
}

# ── Access summary ───────────────────────────────────────────────────────────────────────
print_access_summary() {
  local fqdn="${FRONTDOOR_FQDN:-suru.local}"
  local port="${FRONTDOOR_PORT:-443}"
  local base="https://${fqdn}"
  [[  "$port" != "443" ]] && base="${base}:${port}"
  printf "\n${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}\n"
  printf "${C_BOLD} SURU — LAN Access (via Tier 4 frontdoor proxy)${C_RESET}\n"
  printf "${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}\n"
  printf "  %-38s %s\n" "OpenSearch Dashboards:"         "${base}/"
  printf "  %-38s %s\n" "Grafana:"                       "${base}/grafana"
  printf "  %-38s %s\n" "Prometheus:"                    "${base}/prometheus"
  printf "  %-38s %s\n" "OpenSearch REST API:"           "${base}/api/search"
  printf "  %-38s %s\n" "Logstash (default) Metrics:"    "${base}/ingestion"
  printf "  %-38s %s\n" "Logstash (default) Beats:"      "${fqdn}:5044"
  printf "  %-38s %s\n" "Logstash (pfsense) Beats:"      "${fqdn}:5045"
  printf "  %-38s %s\n" "Logstash (default) syslog UDP:" "${fqdn}:5140-5142"
  printf "  %-38s %s\n" "Logstash (pfsense) syslog UDP:" "${fqdn}:5143-5145"
  printf "${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}\n"
  printf "  Frontdoor compose: tier4-operations/frontdoor/proxy/compose.yaml\n"
  printf "  Routing manifest:  tier4-operations/frontdoor/proxy/config/routes.yaml\n\n"
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════
main() {
  parse_args "$@"
  case "$COMMAND" in
    deploy)      check_deps; cmd_deploy ;;
    start)       check_deps; cmd_start; print_access_summary ;;
    stop)        cmd_stop ;;
    restart)     check_deps; cmd_restart; print_access_summary ;;
    status)      cmd_status ;;
    check)       cmd_check ;;
    logs)        cmd_logs ;;
    reimport)    cmd_reimport ;;
    repair)      check_deps; cmd_repair ;;
    destroy)     cmd_destroy ;;
    destroy-all) cmd_destroy_all ;;
    kernel-tune)     cmd_kernel_tune ;;
    configure-host)  cmd_configure_host ;;
    certs)           cmd_certs ;;
    network)         cmd_network ;;
    -h|--help)   usage; exit 0 ;;
    *)
      log ERROR "Unknown command: '${COMMAND}'"
      printf "\nRun 'bash deploy.sh --help' for usage.\n\n"
      exit 1
      ;;
  esac
}

main "$@"
