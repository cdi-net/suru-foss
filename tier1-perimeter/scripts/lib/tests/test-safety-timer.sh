#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — test-safety-timer.sh
# Local-only unit tests for lib/safety-timer.sh. Exercises the parts that don't
# need a live router: full-path sudo binaries, the dry-run short-circuit, the
# disarm and the fresh-connection rule. Remote SSH/scp are stubbed.
# Run: bash tier1-perimeter/scripts/lib/tests/test-safety-timer.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../safety-timer.sh
source "${SCRIPT_DIR}/../safety-timer.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
# shellcheck source=../../../../lib/bash/test-harness.sh
source "${REPO_ROOT}/lib/bash/test-harness.sh"

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

# Capture dir: our _safety_scp stub copies staged files here, keyed by basename,
# so we can inspect the generated runner without a router.
CAP="${WORK}/captured"
mkdir -p "${CAP}"

# Stub the two remote primitives. No network; record what would have been sent.
# They honour SAFETY_DRYRUN exactly like the real ones so the dry-run test is valid.
_safety_ssh() {
  [[ "${SAFETY_DRYRUN}" == "true" ]] && { echo "SSH(dry): $*" >> "${WORK}/ssh.log"; return 0; }
  echo "SSH: $*" >> "${WORK}/ssh.log"; return 0
}
_safety_scp() {
  [[ "${SAFETY_DRYRUN}" == "true" ]] && { echo "SCP(dry): $1 -> $2" >> "${WORK}/scp.log"; return 0; }
  cp -f "$1" "${CAP}/$(basename "$1")" 2>/dev/null || true
  echo "SCP: $1 -> $2" >> "${WORK}/scp.log"; return 0
}

# Required caller-contract vars — consumed by the sourced safety-timer functions,
# not by this test directly.
SAFETY_TARGET="router.test"; SAFETY_USER="deploy"; SAFETY_SUDO="sudo "
SAFETY_SSH_OPTS=(-o BatchMode=yes)
: "${SAFETY_TARGET}" "${SAFETY_USER}" "${SAFETY_SUDO}" "${SAFETY_SSH_OPTS[*]}"  # ref for shellcheck

# A stand-in local revert applier (contents irrelevant to these tests).
REVERT_LOCAL="${WORK}/suricata-safety-revert.php"
printf '<?php // stub revert\n' > "${REVERT_LOCAL}"

echo "[test-safety-timer] Test 1: arm() stages a well-formed sleeper runner"
SAFETY_DRYRUN="false" \
  safety_timer_arm 60 "${REVERT_LOCAL}" "sudo php /tmp/suru-safety/suricata-safety-revert.php" \
  > "${WORK}/arm.out" 2>&1 && _pass "arm() returned 0" || _fail "arm() returned non-zero"
runner="$(grep -lE '^sleep 60$' "${CAP}"/* 2>/dev/null | head -1 || true)"
if [[ -n "${runner}" ]]; then
  _pass "sleeper runner was staged"
  sh -n "${runner}" && _pass "generated runner passes sh -n" || _fail "generated runner fails sh -n"
else
  _fail "sleeper runner was not staged"
fi

echo "[test-safety-timer] Test 1b: privileged commands use full-path binaries"
: > "${WORK}/ssh.log"; : > "${WORK}/scp.log"; rm -f "${CAP}"/*
SAFETY_DRYRUN="false" safety_timer_arm 60 "${REVERT_LOCAL}" "x" > /dev/null 2>&1 || true
grep -q "sudo ${SAFETY_BIN_DAEMON} -f -p" "${WORK}/ssh.log" \
  && _pass "sleeper is launched through the full-path daemon" || _fail "sleeper is not launched through ${SAFETY_BIN_DAEMON}"
if grep -E 'sudo [^ ]*(rm|pkill|daemon) ' "${WORK}/ssh.log" | grep_q -vqE 'sudo /(bin|usr/sbin)/'; then
  _fail "a sudo-prefixed command is not a full path"
else
  _pass "every sudo-prefixed command is a full path"
fi

echo "[test-safety-timer] Test 2: dry-run performs no remote mutation"
: > "${WORK}/ssh.log"; : > "${WORK}/scp.log"; rm -f "${CAP}"/*
SAFETY_DRYRUN="true" \
  safety_timer_arm 60 "${REVERT_LOCAL}" "sudo php /tmp/x.php" > "${WORK}/dry.out" 2>&1 || true
# No file may actually be staged, and scp.log must contain only "(dry)" entries
# (no real "SCP:" line). The dry-run log lines themselves are expected.
if [[ -z "$(ls -A "${CAP}" 2>/dev/null)" ]] && ! grep -q '^SCP: ' "${WORK}/scp.log"; then
  _pass "dry-run staged nothing (no real scp, no captures)"
else
  _fail "dry-run performed staging"
fi

echo "[test-safety-timer] Test 3: disarm kills the sleeper through its pidfile and removes its state"
: > "${WORK}/ssh.log"
SAFETY_DRYRUN="false" safety_timer_disarm > /dev/null 2>&1 \
  && _pass "disarm returned 0" || _fail "disarm returned non-zero"
stop_line="$(grep -F 'pkill -F /tmp/suru-safety/revert.pid' "${WORK}/ssh.log" | head -1 || true)"
[[ -n "${stop_line}" ]] && _pass "sleeper killed via its pidfile" || _fail "no sleeper kill sent"
[[ "${stop_line}" == *"rm -rf /tmp/suru-safety"* ]] && _pass "sleeper state removed" || _fail "sleeper state not removed"

echo "[test-safety-timer] Test 4: arm reuses the driver's connection; the disarm forces a fresh one"
# A subshell re-sources the library so the real _safety_ssh/_safety_scp run
# against PATH stubs that log, per call, the first ControlMaster and ControlPath
# value they receive (ssh keeps the first value of an option).
(
  # shellcheck source=../safety-timer.sh
  source "${SCRIPT_DIR}/../safety-timer.sh"
  mkdir -p "${WORK}/bin"
  for tool in ssh scp; do
    cat > "${WORK}/bin/${tool}" <<'STUB'
#!/usr/bin/env bash
master="" path=""
for a in "$@"; do
  case "${a}" in
    ControlMaster=*) [[ -z "${master}" ]] && master="${a#ControlMaster=}" ;;
    ControlPath=*)   [[ -z "${path}" ]] && path="${a#ControlPath=}" ;;
  esac
done
printf '%s %s %s\n' "${0##*/}" "${master:-unset}" "${path:-unset}" >> "${CONN_LOG}"
[[ "${0##*/}" == ssh ]] && cat > /dev/null
exit 0
STUB
    chmod +x "${WORK}/bin/${tool}"
  done
  export PATH="${WORK}/bin:${PATH}" CONN_LOG="${WORK}/conn.log"
  SAFETY_SSH_OPTS=(-o BatchMode=yes -o ControlMaster=auto -o "ControlPath=/tmp/suru-ssh.test/%C")
  : "${SAFETY_SSH_OPTS[*]}"

  # Arm: its first call is the stale-timer disarm (fresh); the staging calls after it reuse the master.
  : > "${CONN_LOG}"
  SAFETY_DRYRUN="false" \
    safety_timer_arm 60 "${REVERT_LOCAL}" "sudo php /tmp/x.php" > /dev/null 2>&1 || true
  head -n 1 "${CONN_LOG}" | grep_q -qx 'ssh no none' \
    && _pass "arm: the stale-timer disarm uses a fresh connection" \
    || _fail "arm: the stale-timer disarm uses a fresh connection ($(head -n 1 "${CONN_LOG}"))"
  if tail -n +2 "${CONN_LOG}" | grep_q -q . && ! tail -n +2 "${CONN_LOG}" | grep_q -qv ' auto /tmp/suru-ssh.test/%C$'; then
    _pass "arm: staging and launch reuse the driver's connection"
  else
    _fail "arm: staging and launch reuse the driver's connection"
  fi

  : > "${CONN_LOG}"
  SAFETY_DRYRUN="false" safety_timer_disarm > /dev/null 2>&1 || true
  if grep -q . "${CONN_LOG}" && ! grep -qv '^ssh no none$' "${CONN_LOG}"; then
    _pass "disarm: every call is a fresh connection"
  else
    _fail "disarm: every call is a fresh connection ($(tr '\n' ';' < "${CONN_LOG}"))"
  fi

  : > "${CONN_LOG}"
  SAFETY_DRYRUN="false" safety_timer_arm 60 "${REVERT_LOCAL}" "x" > /dev/null 2>&1 || true
  grep -q ' auto ' "${CONN_LOG}" \
    && _pass "fresh-connection prefix does not leak out of a disarm" \
    || _fail "fresh-connection prefix does not leak out of a disarm"
  test_summary
) || exit 1
exit 0
