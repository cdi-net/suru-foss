#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for the OPNsense unbound-localzones deploy stage
#
# Extracts the SHIPPED case block, revert helper and stage text from
# scripts/platforms/opnsense.sh at run time and exercises them with a stubbed
# revert, so the assertions cannot drift from a retyped copy of the code.
#
# Covers: which applier exit codes revert and which do not, the one documented
# no-revert hard failure (rc 3), the distinct operator guidance per code, and
# two static invariants that guard regressions this stage has already had —
# an unguarded `return` (bash fires no ERR trap for the return builtin) and a
# bareword `rc=$?` relay inside a remote command string (csh-family login
# shells have no such assignment, so the applier's exit code is lost).
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-${SUITE_DIR}/../../platforms/opnsense.sh}"
[ -r "${SRC}" ] || { echo "FATAL: driver not found at ${SRC}"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

pass=0; fail=0
check() {
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "  ok   $1 ($3)"
  else fail=$((fail+1)); echo "  FAIL $1 — expected [$2] got [$3]"; fi
}

HELPER="$(awk '/^  _opn_ulz_revert_and_fail\(\) \{/,/^  \}/' "${SRC}")"
CASEBLK="$(awk '/^      case "\$\{_ulz_rc\}" in/,/^      esac/' "${SRC}")"
[ -n "${HELPER}" ]  || { echo "FATAL: revert helper not found — did the stage change?"; exit 1; }
[ -n "${CASEBLK}" ] || { echo "FATAL: case block not found — did the stage change?"; exit 1; }

run_case() { # rc  backup_tracked
  local _ulz_rc="$1"
  rm -f -- "${TMP}/revert.marker"
  # shellcheck disable=SC2034  # consumed by the extracted helper
  local _opn_backup_remote="$2"
  _opn_revert() { echo "revert" >> "${TMP}/revert.marker"; return "${REVERT_RC:-0}"; }
  eval "${HELPER}"
  _outer() {
    trap '_opn_revert' ERR
    eval "${CASEBLK}"
    return 0
  }
  _outer > "${TMP}/drv.out" 2>&1
  echo $?
}
reverts() { [ -f "${TMP}/revert.marker" ] && wc -l < "${TMP}/revert.marker" | tr -d ' ' || echo 0; }

echo "== advisory codes must NOT revert =="
for rc in 0 6 7; do
  r=$(run_case "$rc" "/root/backup.bak")
  check "rc=$rc returns 0" 0 "$r"; check "rc=$rc no revert" 0 "$(reverts)"
done

echo "== rc 3 is the one hard failure that must NOT revert =="
r=$(run_case 3 "/root/backup.bak")
check "rc=3 returns 1" 1 "$r"
check "rc=3 does not revert" 0 "$(reverts)"
check "rc=3 says why not" yes "$(grep -q 'NOT reverting' ${TMP}/drv.out && echo yes || echo no)"

echo "== hard failures MUST revert, exactly once =="
for rc in 2 4 5 127; do
  r=$(run_case "$rc" "/root/backup.bak")
  check "rc=$rc returns 1" 1 "$r"; check "rc=$rc reverted once" 1 "$(reverts)"
done

echo "== rc 4 / 5 / unknown carry distinct, non-overlapping guidance =="
run_case 4 "/root/backup.bak" >/dev/null
# rc 4 now means exactly one thing — the left-in-place case is rc 3 — so it may
# assert the rollback again
check "rc=4 names a post-write failure" yes "$(grep -q 'failed after writing (rc=4)' ${TMP}/drv.out && echo yes || echo no)"
check "rc=4 states the rollback happened" yes "$(grep -q 'rolled back and unbound restarted' ${TMP}/drv.out && echo yes || echo no)"
check "rc=4 points at rc 5 for a failed rollback" yes "$(grep -q 'that is rc 5' ${TMP}/drv.out && echo yes || echo no)"
check "rc=4 does not say do-not-delete" no "$(grep -q 'Do NOT delete' ${TMP}/drv.out && echo yes || echo no)"
run_case 5 "/root/backup.bak" >/dev/null
check "rc=5 says resolver may be down" yes "$(grep -q 'rollback FAILED' ${TMP}/drv.out && echo yes || echo no)"
check "rc=5 warns against deleting" yes "$(grep -q 'Do NOT delete' ${TMP}/drv.out && echo yes || echo no)"
run_case 127 "/root/backup.bak" >/dev/null
check "unknown rc says died before acting" yes "$(grep -q 'died before acting' ${TMP}/drv.out && echo yes || echo no)"
check "unknown rc offers removal" yes "$(grep -q 'rm -f /usr/local/etc/unbound.opnsense.d' ${TMP}/drv.out && echo yes || echo no)"

echo "== no backup tracked (SURU_SKIP_BACKUP): fail without a bogus revert =="
r=$(run_case 4 ""); check "returns 1" 1 "$r"; check "no revert attempted" 0 "$(reverts)"

echo "== a failing revert is reported, not swallowed =="
REVERT_RC=1 r=$(REVERT_RC=1; run_case 4 "/root/backup.bak"); check "still returns 1" 1 "$r"
check "CRITICAL surfaced" yes "$(grep -q 'CRITICAL: revert after the unbound-localzones failure' ${TMP}/drv.out && echo yes || echo no)"

echo "== invariant: every hard-failure return in the stage block reverts first =="
BLOCK="$(awk '/--- Local-DNS hygiene: unbound special-use zones/,/--- Dead-man/' "$SRC")"
# strip comment lines first — prose about `return 1` is not a code path
bare="$(printf '%s\n' "$BLOCK" | grep -v '^\s*#' | grep 'return 1' | grep -cv '_opn_ulz_revert_and_fail' || true)"
guarded="$(printf '%s\n' "$BLOCK" | grep -v '^\s*#' | grep -c '_opn_ulz_revert_and_fail; return 1' || true)"
total="$(printf '%s\n' "$BLOCK" | grep -v '^\s*#' | grep -c 'return 1' || true)"
# rc 3 deliberately returns without reverting (nothing written, nothing to undo)
check "only the documented exception is unguarded" 1 "$bare"
check "guarded exits = all but that one" "$((total - 1))" "$guarded"

echo "== invariant: remote invocations survive a csh-family login shell =="
# match the invocation anywhere on the line — it may be prefixed (`if ! ssh …`)
SSHLINES="$(printf '%s\n' "$BLOCK" | grep -v '^\s*#' | grep -A2 'ssh "\${ssh_opts\[@\]}"')"
ssh_calls="$(printf '%s\n' "$BLOCK" | grep -v '^\s*#' | grep -c 'ssh "\${ssh_opts\[@\]}"' || true)"
# the literal escaped form only ever appears INSIDE a remote command string;
# the local `|| _ulz_rc=$?` capture is unescaped and legitimate
check "no bareword rc assignment in a remote string" 0 "$(printf '%s\n' "$SSHLINES" | grep -c -F 'rc=\$?' || true)"
# every raw ssh invocation in the stage must carry the sh -c wrap, however many there are
check "every remote invocation wrapped in sh -c" "$ssh_calls" "$(printf '%s\n' "$SSHLINES" | grep -c 'sh -c' || true)"
# Live proof of why the wrap matters: a csh-family shell has no var=value
# assignment, so the relay form loses the exit code entirely. Most CI images
# ship no csh — probe that one actually runs and returns a status before
# trusting anything it reports, rather than reading "command not found" as a
# result. The static invariants above hold either way.
CSH="${SURU_TEST_CSH:-/bin/csh}"
csh_usable=0
if [ -x "${CSH}" ]; then
  "${CSH}" -c "exit 6" >/dev/null 2>&1
  [ $? -eq 6 ] && csh_usable=1
fi
if [ "${csh_usable}" -eq 1 ]; then
  printf '#!/bin/sh\nexit 6\n' > "${TMP}/rcstub"; chmod +x "${TMP}/rcstub"
  "${CSH}" -c "${TMP}/rcstub; rc=\$?; exit \${rc}" >/dev/null 2>&1; old=$?
  "${CSH}" -c "sh -c \"${TMP}/rcstub\"" >/dev/null 2>&1; new=$?
  check "csh: relay form loses the exit code" 1 "$old"
  check "csh: sh -c form preserves it" 6 "$new"
else
  echo "  skip csh comparison (no usable csh at ${CSH}) — static invariants above still apply"
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
