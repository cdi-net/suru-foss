#!/usr/bin/env bash
# =============================================================================
# SURU — lib/bash/test-harness.sh
# Shared PASS/FAIL harness for the platform's self-contained test scripts.
# One copy, so the counting, formatting, and exit semantics cannot drift
# between suites.
#
# This is a SOURCED library — it defines functions and counters only, never
# executes anything, and deliberately does not set strict mode (the sourcing
# script owns its own `set -euo pipefail`).
#
# Usage (from any test script, after resolving REPO_ROOT):
#   # shellcheck source=../../../lib/bash/test-harness.sh
#   source "${REPO_ROOT}/lib/bash/test-harness.sh"
#   _pass "message"                      # "  [PASS] message"        PASS++
#   _fail "message"                      # "  [FAIL] message" (>&2)  FAIL++
#   assert_eq "label" "expected" "got"   # _pass/_fail + detail on mismatch
#   test_summary                         # "[<name>] N passed, M failed";
#                                        # returns 1 when FAIL > 0 — use as the
#                                        # script's final command so the exit
#                                        # status reflects the result
#
# TEST_NAME defaults to the sourcing script's basename (without .sh); export
# TEST_NAME before sourcing to override the summary label.
# =============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "test-harness.sh is a sourced library, not an executable" >&2
  exit 64
fi

TEST_NAME="${TEST_NAME:-$(basename "${BASH_SOURCE[1]:-${0}}" .sh)}"

PASS=0
FAIL=0

# Use $((var+1)) instead of ((var++)) so the helpers always return 0:
# ((PASS++)) is post-increment and evaluates to the OLD value, which means it
# returns non-zero when PASS=0. That makes `cond && _pass || _fail` fire BOTH
# branches on the first PASS (and aborts a `set -e` caller).
_pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
_fail() { echo "  [FAIL] $*" >&2; FAIL=$((FAIL + 1)); }

# grep_q <grep args…> — grep that always drains its stdin. Under pipefail a
# `<producer> | grep -q` exits at the first match and a producer still writing
# dies of SIGPIPE (EPIPE), so the pipeline reads as "no match". Use
# `<producer> | grep_q -q …`; match a variable through a here-string instead.
grep_q() { local rc=0; grep "$@" || rc=$?; cat > /dev/null; return "${rc}"; }

# assert_eq <label> <expected> <actual>
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    _pass "${label}"
  else
    _fail "${label}"
    {
      echo "        expected: '${expected}'"
      echo "        actual:   '${actual}'"
    } >&2
  fi
}

# Print the result line and return non-zero on any failure. Call as the last
# command of the test script so the script's exit status is the verdict.
test_summary() {
  echo ""
  echo "[${TEST_NAME}] ${PASS} passed, ${FAIL} failed"
  [[ "${FAIL}" -eq 0 ]]
}
