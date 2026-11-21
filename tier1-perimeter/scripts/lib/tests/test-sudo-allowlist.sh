#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — test-sudo-allowlist.sh
#
# Keeps the pfSense deploy account's sudo surface honest. Hermetic: reads the
# three scripts and the privilege matrix document, runs nothing remote.
#
#   1. Every sudo-prefixed remote command in pfsense.sh, lib/safety-timer.sh
#      and lib/hw-preflight.sh names its binary through a _PF_BIN_* /
#      SAFETY_BIN_* / _HW_BIN_* constant (a full path), never a bare name.
#   2. The set of constant default paths equals the set of paths in the
#      `Cmnd_Alias SURU_DEPLOY` block of docs/privilege-matrix-pfsense.md.
#   3. The deploy path has no `sudo sh`, no `php -d`/PHP on stdin and no
#      pkg-static.
#   4. Hardware-profile values read back from the router are validated before
#      they reach a remote command (the validators are extracted from the
#      shipped driver and exercised).
#
# Usage: bash tier1-perimeter/scripts/lib/tests/test-sudo-allowlist.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIER1_DIR="$(cd "${SUITE_DIR}/../../.." && pwd)"
PFSENSE="${TIER1_DIR}/scripts/platforms/pfsense.sh"
SAFETY="${TIER1_DIR}/scripts/lib/safety-timer.sh"
HWPRE="${TIER1_DIR}/scripts/lib/hw-preflight.sh"
MATRIX="${TIER1_DIR}/docs/privilege-matrix-pfsense.md"
for f in "${PFSENSE}" "${SAFETY}" "${HWPRE}" "${MATRIX}"; do
  [ -r "${f}" ] || { echo "FATAL: not readable: ${f}"; exit 2; }
done

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }
check() { # description expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 — expected [$2] got [$3]"; fi
}

# Executable lines only: drop comment-only lines (the scripts carry long prose
# about sudo in comments).
code_of() { grep -vE '^[[:space:]]*#' "$1"; }

echo "== 1. sudo-prefixed commands use a full-path constant =="
for f in "${PFSENSE}" "${SAFETY}" "${HWPRE}"; do
  name="$(basename "${f}")"
  # (a) a ${..SUDO} variable must be followed by a constant expansion; lines
  #     that only assign the prefix (SAFETY_SUDO="${_SURISUDO}") are not commands.
  bare="$(code_of "${f}" | grep -E '\$\{[A-Za-z_]*[Ss][Uu][Dd][Oo]\}[^$]' \
          | grep -vE '(SUDO|_sudo)="\$\{' || true)"
  check "${name}: no bare command after a sudo variable" "" "${bare}"
  # (b) literal "sudo <cmd>" in executable lines (assignments of the prefix excluded)
  lit="$(code_of "${f}" | grep -nE 'sudo [/a-zA-Z]' | grep -vE '(echo|log_|printf)' || true)"
  check "${name}: no literal 'sudo <cmd>' in code" "" "${lit}"
done
n_const="$(grep -cE '_PF_BIN_[A-Z]+\}|SAFETY_BIN_[A-Z]+\}|_HW_BIN_[A-Z]+\}' "${PFSENSE}" "${SAFETY}" "${HWPRE}" | awk -F: '{s+=$2} END{print s+0}')"
if [ "${n_const}" -gt 30 ]; then ok "constants are referenced (${n_const} lines)"; else bad "too few constant references (${n_const})"; fi

echo "== 2. constant defaults == Cmnd_Alias SURU_DEPLOY paths =="
{ code_of "${PFSENSE}"; code_of "${SAFETY}"; code_of "${HWPRE}"; } \
  | sed -nE 's/^: "\$\{(_PF_BIN_|SAFETY_BIN_|_HW_BIN_)[A-Z]+:=(\/[^}]+)\}"$/\2/p' \
  | sort -u > "${TMP}/const-paths"
awk '
  /^```sudoers[[:space:]]*$/ { inblk = 1; next }
  inblk && /^```[[:space:]]*$/ { inblk = 0; next }
  inblk { print }
' "${MATRIX}" > "${TMP}/block"
grep -qE '^Cmnd_Alias SURU_DEPLOY = \\$' <<< "$(head -n 1 "${TMP}/block")" \
  && ok "matrix block starts with 'Cmnd_Alias SURU_DEPLOY = \\'" \
  || bad "matrix block does not start with 'Cmnd_Alias SURU_DEPLOY = \\'"
tail -n +2 "${TMP}/block" | sed -E 's/^[[:space:]]+//; s/[[:space:]]*,?[[:space:]]*\\?[[:space:]]*$//' \
  | grep -E '^/' | sort -u > "${TMP}/doc-paths"
check "matrix lists 14 paths" "14" "$(wc -l < "${TMP}/doc-paths" | tr -d ' ')"
check "driver constants define 14 distinct paths" "14" "$(wc -l < "${TMP}/const-paths" | tr -d ' ')"
check "constant defaults equal the matrix paths" "" "$(diff "${TMP}/const-paths" "${TMP}/doc-paths" || true)"

echo "== 3. banned privileged forms =="
for f in "${PFSENSE}" "${SAFETY}" "${HWPRE}"; do
  name="$(basename "${f}")"
  check "${name}: no 'sudo sh' / sudo-var + sh" "" "$(code_of "${f}" | grep -nE '(sudo|SUDO\})[[:space:]]*(/bin/)?sh([[:space:]]|$)' || true)"
  check "${name}: no 'php -d' (PHP on stdin)" "" "$(code_of "${f}" | grep -nE 'php -d|PHP_BIN\}[[:space:]]+-d' || true)"
  check "${name}: no pkg-static" "" "$(code_of "${f}" | grep -n 'pkg-static' || true)"
  check "${name}: no PHP heredoc fed to ssh" "" "$(code_of "${f}" | grep -nE "<<'?EOPHP" || true)"
done
check "pfsense.sh: post-deploy validation gates on PFSENSE_API_KEY" "" "$(code_of "${PFSENSE}" | grep -n 'PFSENSE_API_CLIENT_TOKEN' || true)"
check "pfsense.sh: no per-run \$\$ name in a privileged command (safety-timer.sh)" "" "$(code_of "${SAFETY}" | grep -nE 'SAFETY_BIN_MV[^"]*\$\$' || true)"
[ -r "${TIER1_DIR}/pfsense/verify-xml-state.php" ] \
  && ok "pfsense/verify-xml-state.php is shipped" || bad "pfsense/verify-xml-state.php missing"

echo "== 4. hw-profile values are validated before use =="
# Extract the two validator helpers from the shipped driver and run them.
awk '
  /^[[:space:]]*_pf_hw_require_int\(\) \{/    { grab = 1 }
  /^[[:space:]]*_pf_hw_require_memcap\(\) \{/ { grab = 1 }
  grab { print }
  grab && /^[[:space:]]*\}[[:space:]]*$/ { grab = 0 }
' "${PFSENSE}" > "${TMP}/validators.sh"
if [ -s "${TMP}/validators.sh" ]; then
  ok "validators extracted from the driver"
else
  bad "validators not found in the driver"
fi
cat > "${TMP}/run-validators.sh" <<EOF
log_die() { echo "DIE: \$*"; exit 1; }
_hw_profile=/x/.hw-profile
$(cat "${TMP}/validators.sh")
case "\$1" in
  int) _pf_hw_require_int KEY "\$2" ;;
  memcap) _pf_hw_require_memcap KEY "\$2" ;;
esac
echo VALID
EOF
vcheck() { # kind value expect(VALID|DIE)
  local out; out="$(bash "${TMP}/run-validators.sh" "$1" "$2" 2>&1 || true)"
  case "${out}" in
    VALID) [ "$3" = "VALID" ] && ok "$1 '$2' accepted" || bad "$1 '$2' accepted, expected refusal" ;;
    DIE:*KEY*) [ "$3" = "DIE" ] && ok "$1 '$2' refused, names the key" || bad "$1 '$2' refused, expected accept" ;;
    *) bad "$1 '$2': unexpected output [${out}]" ;;
  esac
}
vcheck int 800000 VALID
vcheck int "" DIE
vcheck int "1; reboot" DIE
vcheck int '$(id)' DIE
vcheck int "-5" DIE
vcheck memcap 256mb VALID
vcheck memcap 256MB VALID
vcheck memcap 268435456 VALID
vcheck memcap "" DIE
vcheck memcap "64mb;id" DIE
vcheck memcap "1gb" DIE
# The enum guard for the engine profile is a case statement in the driver.
grep -qE 'low\|medium\|high\) ;;' "${PFSENSE}" \
  && ok "SURU_HW_SURICATA_PROFILE is restricted to low|medium|high" \
  || bad "SURU_HW_SURICATA_PROFILE enum guard missing"
for key in SURU_HW_PF_TABLE_ENTRIES SURU_HW_PF_MAX_STATES SURU_HW_ZEEK_LB_PROCS SURU_HW_SURICATA_STREAM_MEMCAP \
           SURU_HW_SURICATA_REASSEMBLY_MEMCAP SURU_HW_SURICATA_DEFRAG_MEMCAP SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES \
           SURU_HW_UNBOUND_MSG_CACHE_MB SURU_HW_UNBOUND_RRSET_CACHE_MB; do
  grep -qE "_pf_hw_require_(int|memcap)[[:space:]]+${key}[[:space:]]" "${PFSENSE}" \
    && ok "${key} is validated" || bad "${key} is not validated"
done

echo
echo "passed=${PASS} failed=${FAIL}"
[ "${FAIL}" -eq 0 ]
