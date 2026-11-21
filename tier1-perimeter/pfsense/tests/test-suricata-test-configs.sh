#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — behavioural tests for pfsense/suricata-test-configs.php
#
# The applier runs `suricata -T -c <yaml>` against every configured per-interface
# yaml. This suite never touches a real Suricata or pfSense: it runs the applier
# in --no-live mode (no pfSense includes) against a temp tree of fake instance
# directories (suricata_<uuid>_<iface>/suricata.yaml) with a FAKE suricata
# binary (a sh script) that exits 0 unless the yaml contains SURU_TEST_BROKEN.
#
# Scenarios: all instances OK, tested in the tolerant mode
# (--set engine.init-failure-fatal=0); rules that fail to parse in an instance
# that loads are reported by sid on a WARN line and do not fail the run (the
# rule text is not echoed); missing rule files are reported on their own WARN
# line (file names only) and do not fail the run; a config that loads no rules
# at all fails that instance; --count prints the instance count only;
# one broken instance (rc and output tail carried,
# exit 1, later instances still tested); missing yaml counts as a failure;
# strictly sequential execution in --instances order; per-instance timeout
# (skipped when /usr/bin/timeout is absent); bad --timeout, unknown argument,
# missing binary, live-mode override flags and shell metacharacters in
# --instances are rejected with exit 2 and the fake binary is never invoked.
#
# Every applier invocation goes through run(), which captures the exit code
# instead of letting `set -e` abort the suite.
#
# Skips (exit 0) when php is unavailable.
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APPLIER="${APPLIER:-${SCRIPT_DIR}/../suricata-test-configs.php}"

if ! command -v php > /dev/null 2>&1; then
  echo "SKIP: php not available — cannot exercise suricata-test-configs.php."
  exit 0
fi
[[ -f "${APPLIER}" ]] || { echo "FATAL: applier not found at ${APPLIER}"; exit 1; }

# Shared harness inside the repo; minimal fallback when copied to a scratch host.
if [[ -f "${REPO_ROOT}/lib/bash/test-harness.sh" ]]; then
  # shellcheck source=../../../lib/bash/test-harness.sh
  source "${REPO_ROOT}/lib/bash/test-harness.sh"
else
  _T_PASS=0; _T_FAIL=0
  _pass() { _T_PASS=$((_T_PASS + 1)); echo "  [PASS] $*"; }
  _fail() { _T_FAIL=$((_T_FAIL + 1)); echo "  [FAIL] $*" >&2; }
  test_summary() { echo; echo "[test-suricata-test-configs] ${_T_PASS} passed, ${_T_FAIL} failed"; [[ ${_T_FAIL} -eq 0 ]]; }
fi

ROOT="$(mktemp -d)"
trap 'rm -rf -- "${ROOT}"' EXIT

# --- fixture ---------------------------------------------------------------
SDIR="${ROOT}/suricata/"
FAKE="${ROOT}/fake-suricata"
LOG="${ROOT}/fake.log"
UUID_A="aaaa1111"; IFACE_A="igb0"
UUID_B="bbbb2222"; IFACE_B="igb1"
UUID_C="cccc3333"; IFACE_C="igb2"

_mk_instance() {  # uuid iface content
  mkdir -p "${SDIR}suricata_${1}_${2}"
  printf '%s\n' "$3" > "${SDIR}suricata_${1}_${2}/suricata.yaml"
}
_mk_instance "${UUID_A}" "${IFACE_A}" "%YAML 1.1"
_mk_instance "${UUID_B}" "${IFACE_B}" "%YAML 1.1"

# Fake suricata: argv is `-T -c <yaml> --set engine.init-failure-fatal=0`.
# Logs start/end per invocation and the arguments around the yaml.
cat > "${FAKE}" <<'FAKEEOF'
#!/bin/sh
yaml="$3"
[ -n "${SURU_FAKE_LOG:-}" ] && echo "start ${yaml}" >> "${SURU_FAKE_LOG}"
[ -n "${SURU_FAKE_ARGS:-}" ] && echo "$1 $2 $4 $5" >> "${SURU_FAKE_ARGS}"
if grep -q SURU_TEST_BADRULES "${yaml}"; then
  echo '<Error> -- protocol "x" cannot be used in a signature.'
  echo '<Error> -- error parsing signature "alert x any any -> any any (msg:\"SURU_RULE_TEXT one\"; sid:2066251; rev:1;)" from file rules at line 1'
  echo '<Error> -- error parsing signature "alert x any any -> any any (msg:\"SURU_RULE_TEXT two\"; sid: 9000001; rev:1;)" from file rules at line 2'
  echo '<Info> -- 2 rule files processed. 10 rules successfully loaded, 2 rules failed, 0'
  [ -n "${SURU_FAKE_LOG:-}" ] && echo "end ${yaml}" >> "${SURU_FAKE_LOG}"
  exit 0
fi
# Loader wording of Suricata 7.0 with init-failure-fatal=0 (observed on
# 7.0.10): a missing rule file and an empty rule set are warnings, and -T exits 0.
if grep -q SURU_TEST_MISSONE "${yaml}"; then
  echo 'W: detect: No rule files match the pattern /fake/rules/does-not-exist.rules'
  echo 'W: detect: No rule files match the pattern /fake/rules/also;missing$(x).rules'
  [ -n "${SURU_FAKE_LOG:-}" ] && echo "end ${yaml}" >> "${SURU_FAKE_LOG}"
  exit 0
fi
if grep -q SURU_TEST_NORULES "${yaml}"; then
  echo 'W: detect: No rule files match the pattern /fake/rules/does-not-exist.rules'
  echo 'W: detect: 1 rule files specified, but no rules were loaded!'
  [ -n "${SURU_FAKE_LOG:-}" ] && echo "end ${yaml}" >> "${SURU_FAKE_LOG}"
  exit 0
fi
if grep -q SURU_TEST_BROKEN "${yaml}"; then
  echo "fake: config parse error in ${yaml}"
  echo "fake: engine could not be initialised"
  [ -n "${SURU_FAKE_LOG:-}" ] && echo "end ${yaml}" >> "${SURU_FAKE_LOG}"
  exit 1
fi
if grep -q SURU_TEST_SLEEP "${yaml}"; then
  exec sleep 30
fi
[ -n "${SURU_FAKE_LOG:-}" ] && echo "end ${yaml}" >> "${SURU_FAKE_LOG}"
exit 0
FAKEEOF
chmod 755 "${FAKE}"
export SURU_FAKE_LOG="${LOG}"
ARGS="${ROOT}/fake.args"
export SURU_FAKE_ARGS="${ARGS}"

OUT=""; RC=0
run() {  # captures the applier's exit code — never aborts the suite
  : > "${LOG}"
  set +e
  OUT="$(php "${APPLIER}" --no-live --suricata-bin="${FAKE}" --suricata-dir="${SDIR}" "$@" 2>&1)"; RC=$?
  set -e
}
_last() { printf '%s\n' "${OUT}" | tail -1; }
_has() { grep -qF -- "$1" <<< "${OUT}"; }
_fake_calls() { grep -c '^start ' "${LOG}" || true; }

echo "[test-suricata-test-configs] 1. php -l"
php -l "${APPLIER}" > /dev/null && _pass "applier parses" || _fail "applier does not parse"

echo "[test-suricata-test-configs] 2. all instances OK"
run --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
if [[ ${RC} -eq 0 ]] \
  && _has "iface=${IFACE_A} uuid=${UUID_A} yaml=${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml: OK (" \
  && _has "iface=${IFACE_B} uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: OK (" \
  && _has "2 instance(s) tested, 0 failed."; then
  _pass "exit 0, one OK line per instance, summary 2 tested / 0 failed"
else
  _fail "all-OK case rc=${RC}: $(_last)"
fi
if [[ "$(sort -u "${ARGS}")" == "-T -c --set engine.init-failure-fatal=0" ]]; then
  _pass "every instance tested as -T -c <yaml> --set engine.init-failure-fatal=0"
else
  _fail "unexpected suricata arguments: $(sort -u "${ARGS}" | tr '\n' '|')"
fi
! _has "WARN" && _pass "no WARN line when every rule parses" || _fail "spurious WARN: $(_last)"

echo "[test-suricata-test-configs] 2b. rules that fail to parse are reported, not fatal"
_mk_instance "${UUID_B}" "${IFACE_B}" "SURU_TEST_BADRULES"
run --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
if [[ ${RC} -eq 0 ]] \
  && _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: OK (" \
  && _has "iface=${IFACE_B} uuid=${UUID_B}: WARN 2 rule(s) failed to parse and are skipped (sid 2066251,9000001)" \
  && _has "2 instance(s) tested, 0 failed."; then
  _pass "exit 0, OK line plus one WARN line with both sids"
else
  _fail "bad-rules case rc=${RC}: ${OUT}"
fi
! _has "SURU_RULE_TEXT" && _pass "rule text is not echoed" || _fail "rule text leaked into the output"
! _has "rule file(s) not found" && ! _has "no rules loaded" \
  && _pass "no missing-file WARN or empty-set FAIL when rules loaded" || _fail "spurious loader line: ${OUT}"
_mk_instance "${UUID_B}" "${IFACE_B}" "%YAML 1.1"

echo "[test-suricata-test-configs] 2c. missing rule files with rules still loaded are reported, not fatal"
_mk_instance "${UUID_B}" "${IFACE_B}" "SURU_TEST_MISSONE"
run --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
if [[ ${RC} -eq 0 ]] \
  && _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: OK (" \
  && _has "iface=${IFACE_B} uuid=${UUID_B}: WARN 2 rule file(s) not found and skipped (does-not-exist.rules,also?missing??x?.rules)" \
  && _has "2 instance(s) tested, 0 failed."; then
  _pass "exit 0, OK line plus the missing-file WARN (names only, sanitised)"
else
  _fail "missing-file case rc=${RC}: ${OUT}"
fi
! _has "/fake/rules/" && _pass "rule file paths are reduced to file names" || _fail "rule file path echoed: ${OUT}"
! _has "iface=${IFACE_A} uuid=${UUID_A}: WARN" && _pass "the WARN lines name only the affected instance" \
  || _fail "WARN attributed to the wrong instance: ${OUT}"

echo "[test-suricata-test-configs] 2d. a config that loads no rules at all fails that instance"
_mk_instance "${UUID_B}" "${IFACE_B}" "SURU_TEST_NORULES"
run --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
if [[ ${RC} -eq 1 ]] \
  && _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: FAIL (no rules loaded — the engine would run without detection)" \
  && _has "uuid=${UUID_A} yaml=${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml: OK (" \
  && _has "iface=${IFACE_B} uuid=${UUID_B}: WARN 1 rule file(s) not found and skipped (does-not-exist.rules)" \
  && _has "2 instance(s) tested, 1 failed."; then
  _pass "exit 1, FAIL (no rules loaded) for that instance only, the other instance OK"
else
  _fail "zero-rules case rc=${RC}: ${OUT}"
fi
! _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: OK (" \
  && _pass "no OK line for the instance that loaded no rules" || _fail "zero-rules instance also reported OK: ${OUT}"
_mk_instance "${UUID_B}" "${IFACE_B}" "%YAML 1.1"

echo "[test-suricata-test-configs] 2e. --count prints the configured instance count and runs nothing"
run --count --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B},${UUID_C}:${IFACE_C}"
[[ ${RC} -eq 0 && "${OUT}" == "3" && "$(_fake_calls)" -eq 0 ]] \
  && _pass "--count: exit 0, output exactly '3', binary not run" || _fail "count case rc=${RC} calls=$(_fake_calls): ${OUT}"
set +e
OUT="$(php "${APPLIER}" --no-live --count --suricata-bin="${ROOT}/does-not-exist" --instances="${UUID_A}:${IFACE_A}" 2>&1)"; RC=$?
set -e
[[ ${RC} -eq 0 && "${OUT}" == "1" ]] && _pass "--count needs no Suricata binary" || _fail "count without binary rc=${RC}: ${OUT}"

echo "[test-suricata-test-configs] 3. one broken instance fails the run, later instances still tested"
_mk_instance "${UUID_A}" "${IFACE_A}" "SURU_TEST_BROKEN"
run --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
if [[ ${RC} -eq 1 ]] \
  && _has "uuid=${UUID_A} yaml=${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml: FAIL rc=1" \
  && _has "    fake: config parse error in " \
  && _has "    fake: engine could not be initialised" \
  && _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: OK (" \
  && _has "2 instance(s) tested, 1 failed."; then
  _pass "exit 1 with rc and indented tail; the instance after the failure was still tested"
else
  _fail "broken case rc=${RC}: $(_last)"
fi
# the broken instance as the LAST entry must fail the run too
run --instances="${UUID_B}:${IFACE_B},${UUID_A}:${IFACE_A}"
[[ ${RC} -eq 1 ]] && _has "2 instance(s) tested, 1 failed." \
  && _pass "failure in the last instance still exits 1" || _fail "last-broken case rc=${RC}: $(_last)"
_mk_instance "${UUID_A}" "${IFACE_A}" "%YAML 1.1"

echo "[test-suricata-test-configs] 4. missing yaml is a failure"
run --instances="${UUID_A}:${IFACE_A},${UUID_C}:${IFACE_C}"
if [[ ${RC} -eq 1 ]] \
  && _has "iface=${IFACE_C} uuid=${UUID_C} yaml=${SDIR}suricata_${UUID_C}_${IFACE_C}/suricata.yaml: FAIL (yaml missing)" \
  && _has "2 instance(s) tested, 1 failed." \
  && [[ "$(_fake_calls)" -eq 1 ]]; then
  _pass "missing yaml: exit 1, FAIL (yaml missing), fake binary not run for it"
else
  _fail "missing-yaml case rc=${RC} calls=$(_fake_calls): $(_last)"
fi

echo "[test-suricata-test-configs] 5. sequential execution in --instances order"
_mk_instance "${UUID_C}" "${IFACE_C}" "%YAML 1.1"
run --instances="${UUID_C}:${IFACE_C},${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
EXPECT="start ${SDIR}suricata_${UUID_C}_${IFACE_C}/suricata.yaml
end ${SDIR}suricata_${UUID_C}_${IFACE_C}/suricata.yaml
start ${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml
end ${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml
start ${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml
end ${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml"
if [[ ${RC} -eq 0 && "$(cat "${LOG}")" == "${EXPECT}" ]]; then
  _pass "start/end pairs strictly alternate, in --instances order"
else
  _fail "sequential case rc=${RC}; log: $(tr '\n' '|' < "${LOG}")"
fi

echo "[test-suricata-test-configs] 6. per-instance timeout"
if [[ -x /usr/bin/timeout ]]; then
  _mk_instance "${UUID_B}" "${IFACE_B}" "SURU_TEST_SLEEP"
  run --timeout=1 --instances="${UUID_A}:${IFACE_A},${UUID_B}:${IFACE_B}"
  if [[ ${RC} -eq 1 ]] \
    && _has "uuid=${UUID_B} yaml=${SDIR}suricata_${UUID_B}_${IFACE_B}/suricata.yaml: FAIL rc=" \
    && _has "uuid=${UUID_A} yaml=${SDIR}suricata_${UUID_A}_${IFACE_A}/suricata.yaml: OK ("; then
    _pass "a hung instance is killed by --timeout and fails the run"
  else
    _fail "timeout case rc=${RC}: $(_last)"
  fi
  _mk_instance "${UUID_B}" "${IFACE_B}" "%YAML 1.1"
else
  echo "  [SKIP] /usr/bin/timeout not present on this host — timeout case not exercised"
fi

echo "[test-suricata-test-configs] 7. usage errors exit 2 and never reach the binary"
run --timeout=abc --instances="${UUID_A}:${IFACE_A}"
[[ ${RC} -eq 2 && "$(_fake_calls)" -eq 0 ]] && _pass "--timeout=abc rejected (exit 2)" || _fail "bad timeout rc=${RC}: $(_last)"
run --timeout=-5 --instances="${UUID_A}:${IFACE_A}"
[[ ${RC} -eq 2 && "$(_fake_calls)" -eq 0 ]] && _pass "--timeout=-5 rejected (exit 2)" || _fail "negative timeout rc=${RC}: $(_last)"
run --bogus --instances="${UUID_A}:${IFACE_A}"
[[ ${RC} -eq 2 && "$(_fake_calls)" -eq 0 ]] && _pass "unknown argument rejected (exit 2)" || _fail "unknown arg rc=${RC}: $(_last)"
run
[[ ${RC} -eq 2 ]] && _pass "--no-live without --instances rejected (exit 2)" || _fail "no instances rc=${RC}: $(_last)"

set +e
OUT="$(php "${APPLIER}" --no-live --suricata-bin="${ROOT}/does-not-exist" --suricata-dir="${SDIR}" \
  --instances="${UUID_A}:${IFACE_A}" 2>&1)"; RC=$?
set -e
[[ ${RC} -eq 2 ]] && _pass "missing suricata binary rejected (exit 2)" || _fail "missing bin rc=${RC}: $(_last)"

# live mode must not honour the test-mode overrides (and must fail before loading pfSense includes)
: > "${LOG}"
set +e
OUT="$(php "${APPLIER}" --suricata-bin="${FAKE}" --suricata-dir="${SDIR}" --instances="${UUID_A}:${IFACE_A}" 2>&1)"; RC=$?
set -e
[[ ${RC} -eq 2 && "$(_fake_calls)" -eq 0 ]] && _pass "live mode rejects --instances/--suricata-dir (exit 2)" || _fail "live override rc=${RC}: $(_last)"

echo "[test-suricata-test-configs] 8. shell metacharacters in --instances"
PWN="${ROOT}/pwned"
for bad in "${UUID_A}:${IFACE_A};touch ${PWN}" "${UUID_A}:\$(touch ${PWN})" "${UUID_A}:${IFACE_A} touch" "../x:${IFACE_A}" "${UUID_A}:a/b" "${UUID_A}:\`touch ${PWN}\`"; do
  run --instances="${bad}"
  if [[ ${RC} -eq 2 && "$(_fake_calls)" -eq 0 && ! -e "${PWN}" ]]; then
    _pass "rejected: ${bad//${ROOT}/<root>}"
  else
    _fail "metachar entry accepted rc=${RC} calls=$(_fake_calls) pwned=$([[ -e ${PWN} ]] && echo yes || echo no): ${bad//${ROOT}/<root>}"
  fi
done

test_summary
