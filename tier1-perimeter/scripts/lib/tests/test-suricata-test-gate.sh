#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for the pre-restart Suricata config-test gate
#
# The pfSense driver runs `suricata -T` on every configured per-interface yaml
# between the Suricata applier chain and the A10 consolidated restart. This suite
# extracts the SHIPPED gate block from scripts/platforms/pfsense.sh at run time
# (the text between the `# --- Suricata config test (pre-restart gate) ---`
# marker and the `# --- Suricata consolidated restart (A10)` marker), wraps it in
# a function, and runs it with the driver helpers stubbed. Extracting rather than
# retyping keeps the assertions from drifting away from the driver.
#
# Covers: the mode/hw/change decision matrix, the skip when
# SURU_SURICATA_RESTART=false (no restart to gate), the keepalive SSH helper
# for the long remote call, the dry-run path (no SSH), and the
# refusal path (rc=1 from the remote test): the function returns 1, an ERROR
# block is printed, iff armed the dead-man's switch is disarmed, `_pf_revert`
# is never called — including under `set -e` with an ERR trap installed — and no
# restart is issued.
#
# Hermetic: no network, no router, no docker; no PATH shims (so it cannot
# interfere with suites that shim mktemp). ssh/scp helpers are shell stubs.
#
# Usage: bash tier1-perimeter/scripts/lib/tests/test-suricata-test-gate.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="${1:-${SUITE_DIR}/../../platforms/pfsense.sh}"
[ -r "${DRIVER}" ] || { echo "FATAL: not readable: ${DRIVER}"; exit 2; }
# The shipped driver's sudo-binary constants (full paths), so expected command
# strings follow the driver rather than restating the paths.
_BIN_PRELUDE="$(grep '^: "${_PF_BIN_' "${DRIVER}")"
eval "${_BIN_PRELUDE}"

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT
LOG="${TMP}/calls.log"

PASS=0
FAIL=0
check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then
    PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"
  else
    FAIL=$((FAIL + 1)); printf '  FAIL %s (expected %q, got %q)\n' "$1" "$2" "$3"
  fi
}
check_contains() {
  # check_contains <description> <needle> <haystack>
  case "$3" in
    *"$2"*) PASS=$((PASS + 1)); printf '  ok   %s\n' "$1" ;;
    *) FAIL=$((FAIL + 1)); printf '  FAIL %s (missing %q)\n' "$1" "$2" ;;
  esac
}
check_absent() {
  case "$3" in
    *"$2"*) FAIL=$((FAIL + 1)); printf '  FAIL %s (unexpected %q)\n' "$1" "$2" ;;
    *) PASS=$((PASS + 1)); printf '  ok   %s\n' "$1" ;;
  esac
}

# --- Extract the shipped fragment --------------------------------------------
START='  # --- Suricata config test (pre-restart gate) ---'
FRAGMENT="$(awk -v start="${START}" '
  $0 == start { on = 1 }
  on && index($0, "  # --- Suricata consolidated restart (A10)") == 1 { exit }
  on { print }
' "${DRIVER}")"
if [ -z "${FRAGMENT}" ]; then
  echo "FATAL: gate block not found in ${DRIVER} (marker: ${START})"
  exit 2
fi
if ! grep -qF -- "  # --- Suricata consolidated restart (A10)" "${DRIVER}"; then
  echo "FATAL: end marker (A10 consolidated restart) not found in ${DRIVER}"
  exit 2
fi
FRAG_LINES="$(printf '%s\n' "${FRAGMENT}" | wc -l | tr -d ' ')"
echo "extracted gate block: ${FRAG_LINES} lines from $(basename "${DRIVER}")"

# Static: the block must not talk to the router except through the helpers.
for forbidden in ssh_user ssh_opts target; do
  if grep -qw -- "${forbidden}" <<< "$(grep -v '^[[:space:]]*#' <<< "${FRAGMENT}")"; then
    check "fragment does not reference ${forbidden} directly" "absent" "present"
  else
    check "fragment does not reference ${forbidden} directly" "absent" "absent"
  fi
done

# --- Stubs (the only driver helpers the block may call) -----------------------
REMOTE_RC=0
COUNT_OUT="2"
COUNT_RC=0
ARM_FAIL_AT=0   # 1-based safety_timer_arm call that fails; 0 = none
ARM_N=0
_pf_stage_and_install() { echo "stage $*" >> "${LOG}"; return 0; }
_pf_remote_exec()       { echo "plainexec $*" >> "${LOG}"; echo "[pfsense] SSH: $*"; printf '%s\n' "${COUNT_OUT}"; return "${COUNT_RC}"; }
safety_timer_arm()      {
  ARM_N=$((ARM_N + 1)); echo "arm $1 $2 $3" >> "${LOG}"
  [ "${ARM_N}" -eq "${ARM_FAIL_AT}" ] && return 1
  return 0
}
_pf_remote_exec_long()  { echo "exec $*" >> "${LOG}"; return "${REMOTE_RC}"; }
safety_timer_disarm()   { echo "disarm" >> "${LOG}"; return 0; }
safety_timer_disarm_quiet() { echo "disarm" >> "${LOG}"; return 0; }
_pf_revert()            { echo "revert" >> "${LOG}"; return 0; }
_pf_revert_disarm()     { echo "pfrevertdisarm" >> "${LOG}"; return 0; }
log_die()               { echo "log_die $*" >> "${LOG}"; return 1; }

eval "_frag() {
${FRAGMENT}
  return 0
}"

OUT=""
RC=0
# run_case <mode> <hw_gb> <change_seen> <dry_run> <safety_armed> <remote_rc> [restart_enabled]
run_case() {
  : > "${LOG}"
  OUT="$(
    _suri_test_mode="$1"
    _hw_physmem_gb="$2"
    _suri_change_seen="$3"
    # shellcheck disable=SC2034
    dry_run="$4"
    _pf_safety_armed="$5"
    REMOTE_RC="$6"
    _suri_restart_enabled="${7:-true}"
    _suri_ips_mode="${IPS_MODE:-legacy}"
    _suri_ifaces="${IFACES:-igb1}"
    _pf_safety_secs=600
    _pf_safety_remote="/tmp/suru-safety/suricata-safety-revert.php"
    _PF_APPLIER_SURICATA_SAFETY_REVERT="/repo/pfsense/suricata-safety-revert.php"
    _suri_test_timeout=300
    _SURISUDO="sudo "
    _PF_REMOTE_STAGING="/tmp/suru-staging"
    _PF_APPLIER_SURICATA_TEST="/repo/pfsense/suricata-test-configs.php"
    set +e
    exec 2>&1
    _frag
    echo "FRAG_RC=$?"
  )"
  RC="${OUT##*FRAG_RC=}"
}
calls() { grep -c "^$1" "${LOG}" || true; }

echo "case: change seen, auto, hw unknown -> runs and passes"
run_case auto "" true false false 0
check "returns 0" "0" "${RC}"
check "one remote exec" "1" "$(calls exec)"
check_contains "exec passes the timeout" "--timeout=300" "$(cat "${LOG}")"
check_contains "exec uses the staged path under sudo" "exec sudo ${_PF_BIN_PHP} /tmp/suru-staging/suricata-test-configs.php" "$(cat "${LOG}")"
check "applier staged once" "1" "$(calls stage)"
check "the keepalive exec helper is used, not the plain one" "0" "$(calls plainexec)"
check "no disarm" "0" "$(calls disarm)"
check_contains "decision line enabled" "hw_gb=unknown → enabled (timeout 300s/instance)" "${OUT}"
check_contains "pass line" "all instances passed — proceeding to the consolidated restart" "${OUT}"

echo "case: auto, hw 2 GB -> skipped with WARN, no SSH"
run_case auto 2 true false false 0
check "returns 0" "0" "${RC}"
check "no stage/exec" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "WARN names the hw gate" "WARN: Suricata config test" "${OUT}"
check_contains "skip reason" "hw gate: 2 GB < 4 GB (set SURU_SURICATA_TEST=true to force)" "${OUT}"

echo "case: auto, hw 4 GB -> runs"
run_case auto 4 true false false 0
check "one remote exec" "1" "$(calls exec)"

echo "case: true, hw 2 GB -> forced"
run_case true 2 true false false 0
check "one remote exec" "1" "$(calls exec)"
check_contains "decision line enabled" "mode=true hw_gb=2 → enabled" "${OUT}"

echo "case: false -> skipped"
run_case false 8 true false false 0
check "no SSH" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "skip reason" "SURU_SURICATA_TEST=false; set auto or true to enable" "${OUT}"
check_absent "off is the default, not a warning" "WARN" "${OUT}"

echo "case: SURU_SURICATA_RESTART=false -> nothing to gate, skipped, no SSH"
run_case auto 8 true false false 0 false
check "returns 0" "0" "${RC}"
check "no SSH" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "skip reason" "mode=auto → skipped (SURU_SURICATA_RESTART=false; no restart to gate)" "${OUT}"
check_absent "not a warning" "WARN" "${OUT}"
run_case true 8 true true false 0 false
check_absent "dry-run: no would-run line" "would run suricata-test-configs.php" "${OUT}"
echo "case: the keepalive helper carries ServerAlive options"
check_contains "ServerAliveInterval on the long exec" 'ssh "${ssh_opts[@]}" -o ServerAliveInterval=30 -o ServerAliveCountMax=10' "$(cat "${DRIVER}")"
echo "case: defaults in the pre-mutation validation — off, 900 s per instance"
check_contains "SURU_SURICATA_TEST defaults to false" '_suri_test_mode="${SURU_SURICATA_TEST:-false}"' "$(cat "${DRIVER}")"
check_contains "SURU_SURICATA_TEST_TIMEOUT defaults to 900" '_suri_test_timeout="${SURU_SURICATA_TEST_TIMEOUT:-900}"' "$(cat "${DRIVER}")"

echo "case: no applier changed config -> nothing to test, no SSH"
run_case auto 8 false false false 0
check "returns 0" "0" "${RC}"
check "no SSH" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "idempotent info line" "no applier changed config" "${OUT}"

echo "case: dry-run -> decision + would-run lines, no SSH"
run_case auto 8 false true false 0
check "returns 0" "0" "${RC}"
check "no SSH" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "decision line" "Suricata config test: mode=auto hw_gb=8 → enabled" "${OUT}"
check_contains "would-run line" "(dry-run) would run suricata-test-configs.php on every configured instance before the consolidated restart" "${OUT}"

echo "case: dry-run with the gate off -> no would-run line"
run_case false 8 false true false 0
check_absent "no would-run line" "would run suricata-test-configs.php" "${OUT}"

echo "case: remote test fails, timer not armed -> refusal"
run_case auto "" true false false 1
check "function returns 1" "1" "${RC}"
check "no revert" "0" "$(calls revert)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"
check "no disarm (not armed)" "0" "$(calls disarm)"
check_absent "no switch text when not armed" "dead-man's switch:" "${OUT}"
check_contains "ERROR block names the failure" "Suricata config test FAILED" "${OUT}"
check_contains "ERROR block states engines untouched" "no restart issued" "${OUT}"
check_contains "ERROR block states the config is left in place" "now hold the failing config" "${OUT}"
check_contains "ERROR block gives recovery" "recovery:" "${OUT}"
check_absent "no pass line" "proceeding to the consolidated restart" "${OUT}"
check_absent "no restart issued by the block" "restart.php" "$(cat "${LOG}")"
ERR_LINES="$(printf '%s\n' "${OUT}" | grep -c 'ERROR:' || true)"
check "ERROR block has at least 5 lines" "1" "$([ "${ERR_LINES}" -ge 5 ] && echo 1 || echo 0)"

echo "case: remote test fails, timer armed -> sleeper disarmed"
run_case auto "" true false true 1
check "function returns 1" "1" "${RC}"
check "re-armed once for the test, not again after the failure" "1" "$(calls arm)"
check "sleeper disarmed once" "1" "$(calls disarm)"
check_contains "ERROR says the inline config stays saved" "the inline config stays saved in config.xml" "${OUT}"
check_contains "ERROR says a corrected deploy is needed" "until a corrected deploy" "${OUT}"
check "no revert" "0" "$(calls revert)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"

echo "case: timer armed, test passes -> re-armed to base + timeout x N before, to base after"
IFACES="igb1"; COUNT_OUT="2"
run_case auto "" true false true 0
check "returns 0" "0" "${RC}"
check "success path does not disarm the revert" "0" "$(calls pfrevertdisarm)"
check "count probe via the plain helper" "1" "$(calls plainexec)"
check_contains "count probe runs the staged applier with --count" "plainexec sudo ${_PF_BIN_PHP} /tmp/suru-staging/suricata-test-configs.php --count" "$(cat "${LOG}")"
check "two re-arms" "2" "$(calls arm)"
check "log order: count, arm test window, test, arm base window" \
  "plainexec|arm 1200|exec|arm 600" \
  "$(awk '$1 != "stage" { print ($1 == "arm") ? $1 " " $2 : $1 }' "${LOG}" | paste -sd '|' -)"
check_contains "re-arm carries the staged revert" "arm 1200 /repo/pfsense/suricata-safety-revert.php sudo ${_PF_BIN_PHP} /tmp/suru-safety/suricata-safety-revert.php" "$(cat "${LOG}")"
check "no disarm on success (the restart's own disarm follows)" "0" "$(calls disarm)"
check_contains "window line names both counts" "600s + 300s x 2 instance(s) (SURICATA_IFACES 1, configured 2) = 1200s" "${OUT}"
check_contains "post-test re-arm line" "dead-man's switch re-armed to 600s for the consolidated restart" "${OUT}"

echo "case: timer armed, SURICATA_IFACES larger than the configured set -> sized from SURICATA_IFACES"
IFACES="igb1,igb2,igb3"; COUNT_OUT="1"
run_case auto "" true false true 0
check_contains "window from the larger count" "arm 1500 " "$(cat "${LOG}")"
IFACES="igb1"; COUNT_OUT="2"

echo "case: timer armed, count probe fails -> refusal, no test, sleeper disarmed"
COUNT_RC=1
run_case auto "" true false true 0
check "returns 1" "1" "${RC}"
check "no test run" "0" "$(calls exec)"
check "no re-arm" "0" "$(calls arm)"
check "sleeper disarmed once" "1" "$(calls disarm)"
check "no revert" "0" "$(calls revert)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"
check_contains "refusal names the count" "could not read the configured Suricata instance count" "${OUT}"
COUNT_RC=0

echo "case: timer armed, count probe output not a number -> refusal"
COUNT_OUT="Fatal error"
run_case auto "" true false true 0
check "returns 1" "1" "${RC}"
check "no test run" "0" "$(calls exec)"
check "sleeper disarmed once" "1" "$(calls disarm)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"
COUNT_OUT="2"

echo "case: timer armed, re-arm before the test fails -> refusal, no test, sleeper disarmed"
ARM_FAIL_AT=1
run_case auto "" true false true 0
check "returns 1" "1" "${RC}"
check "no test run" "0" "$(calls exec)"
check "sleeper disarmed once" "1" "$(calls disarm)"
check "no revert" "0" "$(calls revert)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"
check_contains "refusal text" "could not re-arm the dead-man's switch for the config test" "${OUT}"

echo "case: timer armed, re-arm after a passing test fails -> refusal before the restart, sleeper disarmed"
ARM_FAIL_AT=2
run_case auto "" true false true 0
check "returns 1" "1" "${RC}"
check "the test ran" "1" "$(calls exec)"
check "sleeper disarmed once" "1" "$(calls disarm)"
check "no revert" "0" "$(calls revert)"
check "revert disarmed once for the refusal" "1" "$(calls pfrevertdisarm)"
check_contains "refusal text" "could not re-arm the dead-man's switch after the config test" "${OUT}"
ARM_FAIL_AT=0

echo "case: timer not armed -> no count probe, no re-arm"
run_case auto "" true false false 0
check "no count probe" "0" "$(calls plainexec)"
check "no re-arm" "0" "$(calls arm)"

echo "case: dry-run inline -> would-re-arm line, no SSH"
IPS_MODE=inline
run_case auto 8 false true false 0
check "no SSH" "0" "$(wc -l < "${LOG}" | tr -d ' ')"
check_contains "would-re-arm line" "would re-arm the dead-man's switch to 600s + 300s x instances before the test and to 600s after it" "${OUT}"
IPS_MODE=legacy

echo "case: refusal under set -E, the ERR trap and the EXIT revert leaves _pf_revert uncalled"
# The driver's contract: the refusal disarms the revert (_pf_revert_disarm), so
# neither the ERR trap nor the EXIT trap that follows the non-zero exit reverts.
cat > "${TMP}/errtrap.sh" <<EOF
set -eEu
LOG='${LOG}'
_ARMED=true
_pf_stage_and_install() { echo "stage \$*" >> "\${LOG}"; }
_pf_remote_exec_long()  { echo "exec \$*" >> "\${LOG}"; return 1; }
safety_timer_disarm()   { echo "disarm" >> "\${LOG}"; }
${_BIN_PRELUDE}
_pf_revert()            { echo "revert" >> "\${LOG}"; }
_pf_revert_disarm()     { trap - ERR; _ARMED=false; echo "pfrevertdisarm" >> "\${LOG}"; }
$(declare -f _frag)
_suri_test_mode=auto; _hw_physmem_gb=""; _suri_change_seen=true; dry_run=false
_pf_safety_armed=false; _suri_restart_enabled=true; _suri_test_timeout=300; _SURISUDO="sudo "
_suri_ips_mode=legacy; _suri_ifaces=igb1
_PF_REMOTE_STAGING=/tmp/suru-staging; _PF_APPLIER_SURICATA_TEST=/repo/x.php
trap '[ "\${_ARMED}" = true ] && _pf_revert' ERR
trap 'rc=\$?; if [ "\${_ARMED}" = true ] && [ "\${rc}" -ne 0 ]; then _pf_revert; fi' EXIT
_deploy() { _frag; echo "after-gate-reached"; }
_deploy
echo "script-continued"
EOF
: > "${LOG}"
EOUT="$(bash "${TMP}/errtrap.sh" 2>&1)"
ERC=$?
check "script stopped on the refusal (non-zero, not 127)" "1" "$([ "${ERC}" -ne 0 ] && [ "${ERC}" -ne 127 ] && echo 1 || echo 0)"
check "gate did not fall through to the restart stage" "0" "$(printf '%s\n' "${EOUT}" | grep -c 'after-gate-reached' || true)"
check "the refusal disarmed the revert once" "1" "$(calls pfrevertdisarm)"
check "neither trap called _pf_revert" "0" "$(calls revert)"
check "the remote test did run" "1" "$(calls exec)"
# control: the same traps DO revert when nothing disarmed them
sed -i.bak 's/^_pf_revert_disarm()     {.*/_pf_revert_disarm()     { echo "pfrevertdisarm" >> "${LOG}"; }/' "${TMP}/errtrap.sh"
: > "${LOG}"
bash "${TMP}/errtrap.sh" > /dev/null 2>&1
check "control: without the disarm the same traps revert" "1" "$([ "$(calls revert)" -ge 1 ] && echo 1 || echo 0)"

echo "case: the success path keeps the full disarm after the restart"
check_contains "early disarm after the consolidated restart is the full one" \
  "$(printf '  if [[ "${_pf_safety_armed}" == "true" ]]; then\n    safety_timer_disarm\n')" "$(cat "${DRIVER}")"

# --- Validation block: timeout 0 with inline + the switch is refused -----------
VSTART='  # SURU_SURICATA_TEST / SURU_SURICATA_TEST_TIMEOUT: pre-restart `suricata -T`'
VBLOCK="$(awk -v start="${VSTART}" '
  $0 == start { on = 1 }
  on && index($0, "  # --- Setup: create remote staging dir") == 1 { exit }
  on { print }
' "${DRIVER}")"
if [ -z "${VBLOCK}" ]; then
  check "validation block found" "found" "missing"
else
  eval "_val() {
${VBLOCK}
  return 0
}"
  # val_case <test> <timeout> <ips_mode> <safety_timer> <restart>
  val_case() {
    : > "${LOG}"
    (
      SURU_SURICATA_TEST="$1" SURU_SURICATA_TEST_TIMEOUT="$2" SURICATA_IPS_MODE="$3" \
        SURU_SAFETY_TIMER="$4" SURU_SURICATA_RESTART="$5" _val
    ) > /dev/null 2>&1
    grep -c "^log_die SURU_SURICATA_TEST_TIMEOUT=0" "${LOG}" || true
  }
  echo "case: validation — SURU_SURICATA_TEST_TIMEOUT=0"
  check "refused: test on, timeout 0, inline, switch on" "1" "$(val_case auto 0 inline true true)"
  check "refused: test=true too" "1" "$(val_case true 0 inline true true)"
  check "allowed: legacy mode" "0" "$(val_case auto 0 legacy true true)"
  check "allowed: switch off" "0" "$(val_case auto 0 inline false true)"
  check "allowed: test off" "0" "$(val_case false 0 inline true true)"
  check "allowed: restart off (no test)" "0" "$(val_case auto 0 inline true false)"
  check "allowed: non-zero timeout" "0" "$(val_case auto 300 inline true true)"
fi

echo
echo "bash ${BASH_VERSION}: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
