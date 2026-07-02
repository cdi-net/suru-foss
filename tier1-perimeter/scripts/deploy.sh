#!/usr/bin/env bash
# =============================================================================
# SURU Platform — Tier 1 Perimeter Deployment Orchestrator
# Version: 3.0.0
#
# Deploys rendered artefacts from tier1-perimeter/rendered/<platform>/
# to the target perimeter device.
#
# INVARIANT 11: This script MUST NOT contain security policy.
# All rule selection, feed categories, and detection logic live in
# tier2-telemetry/. Run `make render` before `make deploy`.
#
# Usage:
#   deploy.sh --platform pfsense|opnsense [--dry-run] [--verbose]
#   deploy.sh --platform pfsense --target 192.168.1.1
#
# Environment variables:
#   ROUTER_HOST     — router SSH/API host (required)
#   ROUTER_SSH_KEY  — path to SSH private key
#   FRONTDOOR_SYSLOG_SNI — SNI hostname for Tier 4 frontdoor stream demux (default: syslog.suru.local)
#   FRONTDOOR_PORT       — Port for Tier 1 → frontdoor connections (default: 443)
#   SENSOR_NAME     — sensor label (default: suru-tier1)
#   WAN_IFACE       — WAN interface (default: igb0)
#   LAN_IFACE       — LAN interface (default: igb1)
#
# Secrets: never hardcoded. Source from env vars or Vault/SOPS.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.."; pwd)"
PLATFORMS_DIR="${SCRIPT_DIR}/platforms"
TIER1_DIR="${REPO_ROOT}/tier1-perimeter"

# shellcheck source=lib/log.sh
source "${SCRIPT_DIR}/lib/log.sh"
# shellcheck source=lib/ssh.sh
source "${SCRIPT_DIR}/lib/ssh.sh"
# shellcheck source=lib/certs.sh
source "${SCRIPT_DIR}/lib/certs.sh"
# shellcheck source=lib/api.sh
source "${SCRIPT_DIR}/lib/api.sh"
# shellcheck source=lib/safety-timer.sh
source "${SCRIPT_DIR}/lib/safety-timer.sh"

for cmd in ssh scp envsubst; do
  command -v "${cmd}" > /dev/null 2>&1 || { echo "[deploy:ERROR] Missing required command: ${cmd}" >&2; exit 1; }
done

DRY_RUN=false
VERBOSE=false
PLATFORM=""
TARGET="${ROUTER_HOST:-}"

trap '_deploy_cleanup' EXIT
_deploy_cleanup() { : ; }

_log()  { echo "[deploy] $*"; }
_vlog() { ${VERBOSE} && echo "[deploy:verbose] $*" || true; }
_die()  { echo "[deploy:ERROR] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --target)   TARGET="$2";   shift 2 ;;
    --dry-run)  DRY_RUN=true;  shift ;;
    --verbose)  VERBOSE=true;  shift ;;
    *)          _die "Unknown argument: $1" ;;
  esac
done

[[ -n "${PLATFORM}" ]] || _die "--platform is required (pfsense|opnsense)"

# Runtime dry-run auto-detection: if no target host is available and the caller
# did not explicitly pass --dry-run, fall back to dry-run automatically so that
# a bare `make deploy` with no ROUTER_HOST is always safe. When ROUTER_HOST IS
# set (e.g. loaded from .env), DRY_RUN stays false and a real deploy proceeds.
if [[ -z "${TARGET}" ]]; then
  if [[ "${DRY_RUN}" != "true" ]]; then
    _log "No ROUTER_HOST/--target set; activating dry-run automatically."
    _log "Set ROUTER_HOST in .env or pass --target <host> for a real deploy."
    DRY_RUN=true
  fi
  TARGET="dryrun-host.invalid"
fi

RENDERED_DIR="${REPO_ROOT}/tier1-perimeter/rendered/${PLATFORM}"
if [[ ! -d "${RENDERED_DIR}" ]]; then
  if [[ "${DRY_RUN}" == "true" ]]; then
    _log "Rendered artefacts not found at ${RENDERED_DIR} — dry-run skipping deploy step. (Run 'make render' to materialise files.)"
    exit 0
  fi
  _die "Rendered artefacts not found at ${RENDERED_DIR}. Run 'make render' first."
fi

case "${PLATFORM}" in
  pfsense|opnsense) ;;
  *) _die "Invalid PLATFORM '${PLATFORM}' — must be pfsense or opnsense" ;;
esac

DRIVER="${PLATFORMS_DIR}/${PLATFORM}.sh"
[[ -f "${DRIVER}" ]] || _die "Platform driver not found: ${DRIVER}"

_log "Platform: ${PLATFORM}  Target: ${TARGET}  DryRun: ${DRY_RUN}"

export REPO_ROOT TIER1_DIR DRY_RUN VERBOSE

# Source the platform driver and execute deploy
# shellcheck source=platforms/pfsense.sh
source "${DRIVER}"

if declare -f _platform_deploy > /dev/null; then
  _platform_deploy "${TARGET}" "${RENDERED_DIR}" "${DRY_RUN}" "${VERBOSE}"
else
  _die "Platform driver ${DRIVER} does not export _platform_deploy()"
fi

_log "Deployment complete for ${PLATFORM} at ${TARGET}."
