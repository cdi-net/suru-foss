#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — test-syslog-ng-metrics.sh
# Hermetic tests for scripts/syslog-ng-metrics.sh: per-file disk-buffer
# enumeration, orphan flagging, capacity ceiling provenance, and the "no silent
# zero" rule (a failed read is reported, never rendered as 0).
#
# The router is replaced by a PATH-stubbed `ssh` that records its arguments and
# stdin, then prints a hand-written collection fixture (the C1 section format:
# STATS / DQFILES / OPENFILES / CAPACITY / TIME / SVCSTATUS). No network, no
# router; everything is written under a mktemp directory.
# Fixed clock: every fixture carries NOW=1760500000.
# Run: bash tier1-perimeter/scripts/tests/test-syslog-ng-metrics.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
# shellcheck source=../../../lib/bash/test-harness.sh
source "${REPO_ROOT}/lib/bash/test-harness.sh"

SUT="${SCRIPT_DIR}/../syslog-ng-metrics.sh"
FIX="${SCRIPT_DIR}/fixtures"

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

mkdir -p "${WORK}/bin"
: > "${WORK}/key"
printf 'ROUTER_HOST=router.test\nROUTER_SSH_USER=deploy\nROUTER_SSH_KEY=%s\n' "${WORK}/key" > "${WORK}/env"

# ssh stub: record argv, capture the remote script from stdin, answer with the
# fixture named by SNG_FIXTURE.
cat > "${WORK}/bin/ssh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${SNG_WORK}/ssh-args.log"
cat > "${SNG_WORK}/remote-script.sh"
cat "${SNG_FIXTURE}"
STUB
chmod +x "${WORK}/bin/ssh"
export SNG_WORK="${WORK}"

OUT="${WORK}/out.txt"
RC=0

# run_sng <fixture> [script args...] — stdout to ${OUT}, exit code in RC.
run_sng() {
  local fixture="$1"; shift
  RC=0
  [[ "${fixture}" == /* ]] || fixture="${FIX}/${fixture}"
  SNG_FIXTURE="${fixture}" PATH="${WORK}/bin:${PATH}" \
    bash "${SUT}" --env "${WORK}/env" "$@" > "${OUT}" 2> "${WORK}/err.txt" || RC=$?
}

# jcheck <label> <python expression over d> — the JSON in ${OUT} must satisfy it.
jcheck() {
  local label="$1" expr="$2"
  if python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if eval(sys.argv[2]) else 1)' "${OUT}" "${expr}" 2> "${WORK}/py.err"; then
    _pass "${label}"
  else
    _fail "${label}  [${expr}]"
    sed 's/^/        /' "${WORK}/py.err" >&2 || true
  fi
}

# hnot <label> <fixed string> — the human output must NOT contain the string.
hnot() {
  if grep -qF -- "$2" "${OUT}"; then _fail "$1  [unexpected: $2]"; else _pass "$1"; fi
}

# hcheck <label> <fixed string> — the human output must contain the string.
hcheck() {
  if grep -qF -- "$2" "${OUT}"; then _pass "$1"; else _fail "$1  [missing: $2]"; fi
}

echo "== A: live file + probable orphan =="
run_sng sng-metrics-live-and-orphan.txt --buffer
assert_eq "A human: exit 0" "0" "${RC}"
assert_eq "A human: exactly one ORPHAN? row" "1" "$(grep -c 'ORPHAN?' "${OUT}" || true)"
if grep 'ORPHAN?' "${OUT}" | grep_q -q 'syslog-ng-00002'; then _pass "A human: ORPHAN? row names 00002"; else _fail "A human: ORPHAN? row names 00002"; fi
if grep 'syslog-ng-00003' "${OUT}" | grep_q -q '✓'; then _pass "A human: 00003 row carries the live marker"; else _fail "A human: 00003 row carries the live marker"; fi
if grep 'syslog-ng-00003' "${OUT}" | grep_q -q 'held open: yes'; then _pass "A human: 00003 held open: yes"; else _fail "A human: 00003 held open: yes"; fi
if grep 'Capacity' "${OUT}" | grep_q -q '4.0 GB' && grep 'Capacity' "${OUT}" | grep_q -q 'syslog-ng.conf'; then
  _pass "A human: ceiling 4.0 GB from syslog-ng.conf"
else
  _fail "A human: ceiling 4.0 GB from syslog-ng.conf"
fi
hcheck "A human: probable-orphan summary" "1 probable orphan"
hcheck "A human: orphan threshold shown" "orphan threshold: 24h"
if grep 'syslog-ng-00003' "${OUT}" | grep_q -q '%'; then _pass "A human: file rows show pct when ceiling known"; else _fail "A human: file rows show pct when ceiling known"; fi

run_sng sng-metrics-live-and-orphan.txt --json
assert_eq "A json: exit 0" "0" "${RC}"
jcheck "A json: parses and orphan_count == 1" "d['buffer']['orphan_count'] == 1"
jcheck "A json: files[0] is 00003 and live" "d['buffer']['files'][0]['path'].endswith('00003.rqf') and d['buffer']['files'][0]['live'] is True"
jcheck "A json: files[1] is the orphan" "d['buffer']['files'][1]['orphan'] is True"
jcheck "A json: live file not an orphan" "d['buffer']['files'][0]['orphan'] is False"
jcheck "A json: messages_queued == 0 (real dqtool zero)" "d['buffer']['messages_queued'] == 0"
jcheck "A json: lag.queued_messages == 0" "d['lag']['queued_messages'] == 0"
jcheck "A json: queue_ceiling_bytes == 4294967296" "d['buffer']['queue_ceiling_bytes'] == 4294967296"
jcheck "A json: ceiling source syslog-ng.conf" "d['buffer']['queue_ceiling_source'] == 'syslog-ng.conf'"
jcheck "A json: collection_errors empty" "d['buffer']['collection_errors'] == []"
jcheck "A json: orphan file carries its dqtool count" "d['buffer']['files'][1]['messages'] == 325239"
jcheck "A json: queue_file is the live file" "d['buffer']['queue_file'].endswith('00003.rqf')"
jcheck "A json: threshold default 24h" "d['buffer']['orphan_age_threshold_seconds'] == 86400"

run_sng sng-metrics-live-and-orphan.txt --buffer --orphan-age-hours 2000
assert_eq "A threshold 2000h: no ORPHAN? row" "0" "$(grep -c 'ORPHAN?' "${OUT}" || true)"
run_sng sng-metrics-live-and-orphan.txt --json --orphan-age-hours 2000
jcheck "A threshold 2000h json: orphan_count == 0" "d['buffer']['orphan_count'] == 0"

run_sng sng-metrics-live-and-orphan.txt --buffer --orphan-age-hours abc
if [[ "${RC}" -ne 0 ]]; then _pass "A: --orphan-age-hours abc exits non-zero"; else _fail "A: --orphan-age-hours abc exits non-zero"; fi

run_sng sng-metrics-live-and-orphan.txt --status
assert_eq "A: --status exit 0" "0" "${RC}"
run_sng sng-metrics-live-and-orphan.txt --lag
assert_eq "A: --lag exit 0" "0" "${RC}"

echo "== A2: held-open state gates the orphan flag =="
# Same fixture, but syslog-ng also holds 00002 open: aged and non-empty, yet not an orphan.
HELD_FIX="${WORK}/sng-held-open.txt"
sed '/^OPEN|\/var\/db\/syslog-ng-00003\.rqf$/a\
OPEN|/var/db/syslog-ng-00002.rqf
' "${FIX}/sng-metrics-live-and-orphan.txt" > "${HELD_FIX}"
if grep -q '^OPEN|/var/db/syslog-ng-00002.rqf$' "${HELD_FIX}"; then _pass "A2: fixture holds 00002 open"; else _fail "A2: fixture holds 00002 open"; fi
run_sng "${HELD_FIX}" --buffer
assert_eq "A2 held: exit 0" "0" "${RC}"
assert_eq "A2 held: no ORPHAN? row" "0" "$(grep -c 'ORPHAN?' "${OUT}" || true)"
if grep 'syslog-ng-00002' "${OUT}" | grep_q -q 'held open: yes'; then _pass "A2 held: 00002 held open: yes"; else _fail "A2 held: 00002 held open: yes"; fi
run_sng "${HELD_FIX}" --json
jcheck "A2 held json: orphan_count == 0 and 00002 not an orphan" "d['buffer']['orphan_count'] == 0 and d['buffer']['files'][1]['orphan'] is False and d['buffer']['files'][1]['held_open'] is True"
# The open-file read failed (no pid found): held is unknown, so 00002 still flags.
UNK_FIX="${WORK}/sng-held-unknown.txt"
sed -e 's/^RC|0|89101$/RC|127|-/' -e '/^OPEN|/d' "${FIX}/sng-metrics-live-and-orphan.txt" > "${UNK_FIX}"
if grep -q '^RC|127|-$' "${UNK_FIX}" && ! grep -q '^OPEN|' "${UNK_FIX}"; then _pass "A2: unknown fixture has RC 127 and no OPEN rows"; else _fail "A2: unknown fixture has RC 127 and no OPEN rows"; fi
run_sng "${UNK_FIX}" --buffer
assert_eq "A2 unknown: exactly one ORPHAN? row (conservative)" "1" "$(grep -c 'ORPHAN?' "${OUT}" || true)"
if grep 'ORPHAN?' "${OUT}" | grep_q -q 'held open: unknown'; then _pass "A2 unknown: ORPHAN? row shows held open: unknown"; else _fail "A2 unknown: ORPHAN? row shows held open: unknown"; fi

echo "== B: no buffer file =="
run_sng sng-metrics-no-files.txt --buffer
assert_eq "B human: exit 0" "0" "${RC}"
hcheck "B human: says no buffer file" "no buffer file"
run_sng sng-metrics-no-files.txt --json
jcheck "B json: files == []" "d['buffer']['files'] == []"
jcheck "B json: queue_file is None" "d['buffer']['queue_file'] is None"
jcheck "B json: orphan_count == 0" "d['buffer']['orphan_count'] == 0"
run_sng sng-metrics-no-files.txt --lag
assert_eq "B lag: exit 0" "0" "${RC}"
hcheck "B lag: says none - no buffer file found" "none — no buffer file found"
hnot "B lag: never claims buffer empty" "buffer empty"

echo "== C: dqtool failure is reported, not zero =="
run_sng sng-metrics-dqtool-error.txt --buffer
assert_eq "C human: exit 0" "0" "${RC}"
hcheck "C human: error marker" "✗"
hcheck "C human: dqtool error text surfaced" "dqtool: not found"
run_sng sng-metrics-dqtool-error.txt --json
jcheck "C json: files[0].messages is None" "d['buffer']['files'][0]['messages'] is None"
jcheck "C json: files[0].error mentions not found" "'not found' in d['buffer']['files'][0]['error']"
jcheck "C json: collection_errors non-empty" "len(d['buffer']['collection_errors']) >= 1"
jcheck "C json: errored file is not an orphan" "d['buffer']['files'][0]['orphan'] is False"

echo "== D: ceiling unknown =="
run_sng sng-metrics-ceiling-unknown.txt --buffer
if grep 'Capacity' "${OUT}" | grep_q -q 'unknown' && grep 'Capacity' "${OUT}" | grep_q -q 'Permission denied'; then
  _pass "D human: ceiling line says unknown with the reason"
else
  _fail "D human: ceiling line says unknown with the reason"
fi
assert_eq "D human: file rows are present" "2" "$(grep -c 'syslog-ng-0000' "${OUT}" || true)"
if grep 'syslog-ng-0000' "${OUT}" | grep_q -q '%'; then _fail "D human: file rows omit pct"; else _pass "D human: file rows omit pct"; fi
run_sng sng-metrics-ceiling-unknown.txt --json
jcheck "D json: queue_ceiling_bytes is None" "d['buffer']['queue_ceiling_bytes'] is None"
jcheck "D json: source unknown" "d['buffer']['queue_ceiling_source'] == 'unknown'"
jcheck "D json: capacity read failures recorded" "len(d['buffer']['collection_errors']) >= 2"

echo "== F: live file, dqtool failed with empty output =="
run_sng sng-metrics-dqtool-empty.txt --lag
assert_eq "F lag: exit 0" "0" "${RC}"
if grep 'Queued in buffer' "${OUT}" | grep_q -q 'unknown'; then _pass "F lag: queued count reported unknown"; else _fail "F lag: queued count reported unknown"; fi
hnot "F lag: never claims buffer empty" "buffer empty"
hcheck "F lag: collection error lists the live count failure" "dqtool info exited rc=127 with no output"
run_sng sng-metrics-dqtool-empty.txt --json
jcheck "F json: files[0].messages is None" "d['buffer']['files'][0]['messages'] is None"
jcheck "F json: files[0].error carries the rc text" "'rc=127' in d['buffer']['files'][0]['error']"
jcheck "F json: collection_errors has the live count entry" "any('live buffer message count unavailable' in e for e in d['buffer']['collection_errors'])"

echo "== G: count and error both '-' (backstop) =="
run_sng sng-metrics-count-backstop.txt --buffer
hcheck "G human: message count unavailable" "message count unavailable"
run_sng sng-metrics-count-backstop.txt --json
jcheck "G json: files[0].messages is None" "d['buffer']['files'][0]['messages'] is None"
jcheck "G json: files[0].error is message count unavailable" "d['buffer']['files'][0]['error'] == 'message count unavailable'"

echo "== E: hw-profile fallback =="
run_sng sng-metrics-hwprofile-fallback.txt --buffer
if grep 'Capacity' "${OUT}" | grep_q -q '8.0 GB'; then _pass "E human: ceiling 8.0 GB"; else _fail "E human: ceiling 8.0 GB"; fi
run_sng sng-metrics-hwprofile-fallback.txt --json
jcheck "E json: ceiling 8589934592" "d['buffer']['queue_ceiling_bytes'] == 8589934592"
jcheck "E json: source hw-profile.conf" "d['buffer']['queue_ceiling_source'] == 'hw-profile.conf'"

echo "== H: router text cannot carry terminal control sequences =="
# The dqtool error line gains an OSC window-title sequence (ESC ] 0 ; ... BEL).
CTRL_FIX="${WORK}/sng-metrics-control-chars.txt"
sed "s/sh: dqtool: not found/sh: dqtool: not found$(printf '\033]0;sng-injected\007')/" \
  "${FIX}/sng-metrics-dqtool-error.txt" > "${CTRL_FIX}"
if grep -q "$(printf '\007')" "${CTRL_FIX}"; then _pass "H: fixture carries the control sequence"; else _fail "H: fixture carries the control sequence"; fi
run_sng "${CTRL_FIX}" --buffer
assert_eq "H human: exit 0" "0" "${RC}"
hcheck "H human: error text still surfaced" "dqtool: not found]0;sng-injected"
hnot "H human: no BEL from router text" "$(printf '\007')"
hnot "H human: no OSC introducer from router text" "$(printf '\033]')"
run_sng "${CTRL_FIX}" --json
jcheck "H json: parses, error text kept without control chars" "d['buffer']['files'][0]['error'] == 'sh: dqtool: not found]0;sng-injected'"

echo "== I: a non-numeric eps value is never run as awk code =="
# eps_last_1h / eps_last_24h become an awk system() call that would create MARKER.
MARKER="${WORK}/eps-injected"
EPS_FIX="${WORK}/sng-metrics-eps-injection.txt"
sed -e "s|eps_last_1h;12.3|eps_last_1h;system(\"touch ${MARKER}\")|" \
    -e "s|eps_last_24h;10.1|eps_last_24h;system(\"touch ${MARKER}\")|" \
  "${FIX}/sng-metrics-live-and-orphan.txt" > "${EPS_FIX}"
if grep -q 'eps_last_1h;system(' "${EPS_FIX}"; then _pass "I: fixture carries the payload"; else _fail "I: fixture carries the payload"; fi
for mode in --status --lag; do
  run_sng "${EPS_FIX}" "${mode}"
  assert_eq "I ${mode}: exit 0" "0" "${RC}"
done
run_sng "${EPS_FIX}" --json
jcheck "I json: parses, eps fields fall back to 0" "d['service']['write_eps_1h'] == 0 and d['service']['write_eps_24h'] == 0"
if [[ -e "${MARKER}" ]]; then _fail "I: payload never executed (marker absent)"; else _pass "I: payload never executed (marker absent)"; fi
run_sng sng-metrics-live-and-orphan.txt --json
jcheck "I control: numeric eps kept as written" "d['service']['write_eps_1h'] == 12.3 and d['service']['write_eps_24h'] == 10.1"

echo "== ssh contract and remote script =="
run_sng sng-metrics-live-and-orphan.txt --buffer
ARGS="${WORK}/ssh-args.log"
assert_eq "ssh: last arg is 'sudo sh'" "sudo sh" "$(tail -n 1 "${ARGS}")"
assert_eq "ssh: second-to-last arg is deploy@router.test" "deploy@router.test" "$(tail -n 2 "${ARGS}" | head -n 1)"
if grep -qxF 'StrictHostKeyChecking=yes' "${ARGS}"; then _pass "ssh: lib default StrictHostKeyChecking=yes"; else _fail "ssh: lib default StrictHostKeyChecking=yes"; fi
if grep -qxF 'BatchMode=yes' "${ARGS}"; then _pass "ssh: BatchMode=yes"; else _fail "ssh: BatchMode=yes"; fi
if grep -qxF 'ConnectTimeout=15' "${ARGS}"; then _pass "ssh: lib ConnectTimeout=15"; else _fail "ssh: lib ConnectTimeout=15"; fi
if grep -qxF -- "${WORK}/key" "${ARGS}"; then _pass "ssh: identity file passed with -i"; else _fail "ssh: identity file passed with -i"; fi
printf 'ROUTER_HOST=router.test\nROUTER_SSH_USER=deploy\nROUTER_SSH_KEY=%s\nSSH_STRICT_HOST_KEY_CHECKING=accept-new\n' "${WORK}/key" > "${WORK}/env"
run_sng sng-metrics-live-and-orphan.txt --buffer
if grep -qxF 'StrictHostKeyChecking=accept-new' "${ARGS}"; then _pass "ssh: env file accept-new is passed through"; else _fail "ssh: env file accept-new is passed through"; fi
printf 'ROUTER_HOST=router.test\nROUTER_SSH_USER=deploy\nROUTER_SSH_KEY=%s\n' "${WORK}/key" > "${WORK}/env"
if grep -nE '^[^#]*(^|[^_[:alnum:]])ssh[[:space:]]' "${SUT}" > /dev/null; then _fail "static: no inline ssh in the script"; else _pass "static: no inline ssh in the script"; fi
assert_eq "static: lib/ssh.sh sourced once" "1" "$(grep -c 'source "${SCRIPT_DIR}/lib/ssh.sh"' "${SUT}" || true)"
: > "${ARGS}"
DRY_RUN=true run_sng sng-metrics-live-and-orphan.txt --buffer
assert_eq "DRY_RUN=true: exit 1" "1" "${RC}"
if grep -qF 'DRY_RUN=true is set' "${WORK}/err.txt"; then _pass "DRY_RUN=true: refused with a plain message"; else _fail "DRY_RUN=true: refused with a plain message"; fi
if grep -qF 'failed' "${WORK}/err.txt"; then _fail "DRY_RUN=true: no second 'SSH … failed' diagnosis"; else _pass "DRY_RUN=true: no second 'SSH … failed' diagnosis"; fi
if [[ -s "${ARGS}" ]]; then _fail "DRY_RUN=true: ssh never invoked"; else _pass "DRY_RUN=true: ssh never invoked"; fi
run_sng sng-metrics-live-and-orphan.txt --buffer
REMOTE="${WORK}/remote-script.sh"
if [[ -s "${REMOTE}" ]]; then _pass "remote script captured from stdin"; else _fail "remote script captured from stdin"; fi
if sh -n "${REMOTE}"; then _pass "remote script: sh -n clean"; else _fail "remote script: sh -n clean"; fi
if command -v shellcheck > /dev/null 2>&1; then
  if shellcheck -s sh --severity=warning "${REMOTE}"; then _pass "remote script: shellcheck clean"; else _fail "remote script: shellcheck clean"; fi
else
  echo "  [SKIP] remote script shellcheck (shellcheck not installed)"
fi
if grep -q '2>/dev/null' "${REMOTE}"; then _fail "remote script: no 2>/dev/null"; else _pass "remote script: no 2>/dev/null"; fi
# BSD ps takes everything after '=' in a -o argument as the header, commas
# included: 'ps -o pid=,comm=' prints only pid. One -o per renamed field.
if grep -qE '(^|[^a-z])ps .*-[a-zA-Z]*o +[a-z]+=[^ ]*,' "${REMOTE}"; then
  _fail "remote script: ps gives each '=' field its own -o"
else
  _pass "remote script: ps gives each '=' field its own -o"
fi
if grep -qF 'ps -axo pid= -o comm=' "${REMOTE}"; then _pass "remote script: syslog-ng pid lookup selects pid and comm"; else _fail "remote script: syslog-ng pid lookup selects pid and comm"; fi

test_summary
