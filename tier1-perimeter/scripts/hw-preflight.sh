#!/usr/bin/env bash
# SURU Platform — Hardware Preflight CLI Wrapper
# Detects router hardware and writes /usr/local/etc/suru/hw-profile.conf
# (router) + tier1-perimeter/.hw-profile (local mirror).
#
# Called by 'make preflight' before 'make render'. Best-effort — never
# fails the deploy pipeline on SSH or detection error.
#
# Usage:
#   hw-preflight.sh --platform pfsense|opnsense [--dry-run] [--verbose]
#   hw-preflight.sh --platform pfsense --target 192.168.1.1
#
# Environment variables (inherited from .env / Makefile):
#   ROUTER_HOST         — router address (required for live run)
#   ROUTER_SSH_USER     — SSH user (default: admin for pfsense, root for opnsense)
#   ROUTER_SSH_KEY      — path to SSH private key
#   SURU_SKIP_HW_PREFLIGHT — set to true to skip detection entirely

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export TIER1_DIR="${REPO_ROOT}/tier1-perimeter"

# shellcheck source=lib/log.sh
source "${SCRIPT_DIR}/lib/log.sh"
# shellcheck source=lib/hw-preflight.sh
source "${SCRIPT_DIR}/lib/hw-preflight.sh"

DRY_RUN=false
VERBOSE=false
PLATFORM=""
TARGET="${ROUTER_HOST:-}"

_log()  { echo "[hw-preflight] $*"; }
_vlog() { ${VERBOSE} && echo "[hw-preflight:verbose] $*" || true; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --target)   TARGET="$2";   shift 2 ;;
    --dry-run)  DRY_RUN=true;  shift ;;
    --verbose)  VERBOSE=true;  shift ;;
    *) echo "[hw-preflight] WARN: unknown argument '$1' — ignoring" >&2; shift ;;
  esac
done

# Skip flag: operator can bypass hardware detection entirely
if [[ "${SURU_SKIP_HW_PREFLIGHT:-false}" == "true" ]]; then
  _log "SURU_SKIP_HW_PREFLIGHT=true — skipping hardware detection."
  exit 0
fi

# Auto dry-run if no target host (mirrors deploy.sh:76-83 guard)
if [[ -z "${TARGET}" ]]; then
  if [[ "${DRY_RUN}" != "true" ]]; then
    _log "No ROUTER_HOST/--target set; activating dry-run automatically."
    _log "Set ROUTER_HOST in .env or pass --target <host> for live detection."
    DRY_RUN=true
  fi
  TARGET="dryrun-host.invalid"
fi

# Resolve SSH user based on platform default
case "${PLATFORM:-pfsense}" in
  pfsense)  SSH_USER="${ROUTER_SSH_USER:-admin}" ;;
  opnsense) SSH_USER="${ROUTER_SSH_USER:-root}"  ;;
  *)        SSH_USER="${ROUTER_SSH_USER:-admin}" ;;
esac

SSH_KEY="${ROUTER_SSH_KEY:-~/.ssh/suru_deploy}"

# Resolve StrictHostKeyChecking (mirrors pfsense.sh pattern)
local_strict_default="accept-new"
case "$(uname -s)" in
  Darwin) local_strict_default="accept-new" ;;
  *)      local_strict_default="yes" ;;
esac
STRICT="${SSH_STRICT_HOST_KEY_CHECKING:-${local_strict_default}}"
case "$(echo "${STRICT}" | tr '[:upper:]' '[:lower:]')" in
  yes|true|strict)       STRICT="yes" ;;
  no|false|accept-new)   STRICT="accept-new" ;;
  off|none)              STRICT="no" ;;
esac

_log "Platform: ${PLATFORM:-pfsense}  Target: ${TARGET}  DryRun: ${DRY_RUN}"

# hw_preflight_run never exits non-zero — all errors degrade gracefully
hw_preflight_run "${TARGET}" "${SSH_USER}" "${SSH_KEY}" "${STRICT}" "${DRY_RUN}" "${VERBOSE}" || true
