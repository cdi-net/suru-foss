#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — static guard: log rotation stays with each file's native owner
#
# `logrotate` is a declared dependency of pfSense-pkg-syslog-ng; deleting it
# deinstalls the syslog-ng package and stops SIEM ingestion (`pkg delete`
# follows reverse dependencies, `-y` answers the prompt). This guard fails if
# a platform driver ever deletes a package with `pkg delete` (both drivers),
# or if the pfSense driver installs a platform newsyslog drop-in for the
# syslog-ng package's /var/syslog-ng/default.log (rotated by the package's own
# logrotate) — while the pfBlockerNG drop-in (a file whose owner has no
# rename rotation) must stay. The OPNsense driver installs no rotation at
# all: the appliance's native newsyslog owns its logs. Hermetic: reads the
# driver sources only. It is a textual guard: the default.log checks pin the
# LOG PATH (any drop-in name, any call site); a path smuggled through a
# variable is beyond a grep and is what review is for.
#
# Usage: bash tier1-perimeter/scripts/lib/tests/test-rotation-native-owner.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="${SCRIPT_DIR}/../../platforms/pfsense.sh"
OPN_DRIVER="${SCRIPT_DIR}/../../platforms/opnsense.sh"
for d in "${DRIVER}" "${OPN_DRIVER}"; do
  [[ -r "${d}" ]] || { echo "[FAIL] driver not readable: ${d}" >&2; exit 2; }
done

failed=0
check() { # description, expected(0=absent,1=present), grep-pattern [, file]
  local desc="$1" want="$2" pat="$3" file="${4:-${DRIVER}}" hits
  hits="$(grep -cE -- "${pat}" "${file}" || true)"
  if { [[ "${want}" -eq 0 && "${hits}" -eq 0 ]] || [[ "${want}" -eq 1 && "${hits}" -gt 0 ]]; }; then
    echo "[ OK ] ${desc} (matches=${hits})"
  else
    echo "[FAIL] ${desc} (matches=${hits}, expected $([[ "${want}" -eq 0 ]] && echo none || echo '>=1'))"
    failed=1
  fi
}

check "pfSense driver never runs pkg delete"                           0 'pkg delete'
check "OPNsense driver never runs pkg delete"                          0 'pkg delete' "${OPN_DRIVER}"
check "OPNsense driver installs no newsyslog drop-in (native owner)"   0 'newsyslog' "${OPN_DRIVER}"
check "no newsyslog drop-in is installed for default.log (any name)"    0 '_pf_install_newsyslog_dropin [^ ]+ .*/var/syslog-ng/default\.log'
check "default.log path appears in no executable driver line"           0 '^[^#]*/var/syslog-ng/default\.log'
check "pfBlockerNG block-log drop-in is still installed"                1 '_pf_install_newsyslog_dropin suru-pfblockerng'

if [[ "${failed}" -ne 0 ]]; then echo "FAILED"; exit 1; fi
echo "6/6 passed"
