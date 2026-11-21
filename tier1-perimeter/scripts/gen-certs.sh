#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — gen-certs.sh
# Issues the Tier 1 syslog-ng mTLS client pair (tier1-perimeter/certs/) from the
# existing SURU Root CA, on the PKI host. Wrapper around certs_generate_client
# (lib/certs.sh), which is idempotent: it skips when the pair already verifies
# against the Root CA. It never creates a CA.
#
# Usage: gen-certs.sh [--dry-run] [--verbose]
#   (or: make -C tier1-perimeter gen-certs [DRY_RUN=true] [VERBOSE=true])
#
# Requires root-ca.pem and root-ca-key.pem in SURU_PKI_DIR (default
# tier4-operations/pki/certs; created by tier4-operations/pki/scripts/
# generate-certs.sh, run once).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIER1_DIR="${REPO_ROOT}/tier1-perimeter"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true;  shift ;;
    --verbose) VERBOSE=true;  shift ;;
    *) echo "[gen-certs:ERROR] Unknown argument: $1" >&2; exit 1 ;;
  esac
done

command -v openssl > /dev/null 2>&1 || { echo "[gen-certs:ERROR] Missing required command: openssl" >&2; exit 1; }

export REPO_ROOT TIER1_DIR DRY_RUN VERBOSE

# shellcheck source=lib/log.sh
source "${SCRIPT_DIR}/lib/log.sh"
# shellcheck source=lib/certs.sh
source "${SCRIPT_DIR}/lib/certs.sh"

# The issuer mode is always local signing here, whatever the caller exported.
export SURU_PKI_PREISSUED=false
certs_generate_client "tier1-pfsense-syslogng"
