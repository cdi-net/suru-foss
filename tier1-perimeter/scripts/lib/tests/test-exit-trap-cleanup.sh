#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for the Tier 1 EXIT-trap cleanup chain
#
# Bash has exactly ONE EXIT trap and each install REPLACES the last. Tier 1
# installs three, in this order: lib/api.sh (temp-file cleanup, at source time),
# deploy.sh, then the pfSense driver's staging cleanup. Every link must therefore
# chain the one it replaced, and no link may read a caller's function-locals.
# This suite covers all three links.
#
# Extracts the SHIPPED `_pf_cleanup_staging` body and the SHIPPED `_PF_TRAP_*`
# default block from scripts/platforms/pfsense.sh at run time and executes them
# at GLOBAL scope under `set -euo pipefail` — the scope the EXIT trap actually
# fires in — with `ssh` and the chained `_deploy_cleanup` stubbed. Extracting
# rather than retyping keeps the assertions from drifting away from the driver.
#
# The bug: the cleanup was a closure nested in _platform_deploy but was
# fired by a global EXIT trap, reading four of that function's locals. Bash keeps
# locals visible to an EXIT trap only while the function is still on the call
# stack, so on the two abort paths that `return` out of _platform_deploy the trap
# died on "dry_run: unbound variable" and the staging dir was never removed —
# precisely when a half-staged directory is left behind.
#
# The second bug, found alongside it: bash has ONE EXIT trap and each install replaces the
# last, so this trap silently discarded lib/api.sh's `_api_cleanup_tmp` and its
# 0600 temp files were never removed. Each link now chains the one it replaced,
# and the success path stops disarming the trap outright.
#
# Hermetic: no network, no router, no docker. `ssh` is a shell-function stub.
#
# Usage: bash tier1-perimeter/scripts/lib/tests/test-exit-trap-cleanup.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="${1:-${SUITE_DIR}/../../platforms/pfsense.sh}"
DEPLOY="${SUITE_DIR}/../../deploy.sh"
APILIB="${SUITE_DIR}/../api.sh"
LOGLIB="${SUITE_DIR}/../log.sh"
for f in "${DRIVER}" "${DEPLOY}" "${APILIB}" "${LOGLIB}"; do
  [ -r "${f}" ] || { echo "FATAL: not readable: ${f}"; exit 2; }
done
# The shipped driver's sudo-binary constants (full paths), so expected command
# strings follow the driver rather than restating the paths.
_BIN_PRELUDE="$(grep '^: "${_PF_BIN_' "${DRIVER}")"
eval "${_BIN_PRELUDE}"

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

# Record every api.sh temp dir THIS suite causes. api.sh creates its dir under a
# shared base (/dev/shm on Linux, $TMPDIR elsewhere), and other suites that
# source api.sh run at the same time in CI, so counting every suru-api.* in that
# base also sees their live dirs. A mktemp shim first on PATH logs each
# suru-api.* path created by this suite's processes; the final assertion checks
# exactly those are gone.
REAL_MKTEMP="$(command -v mktemp)"
mkdir -p "${TMP}/shim"
cat > "${TMP}/shim/mktemp" <<SHIM
#!/usr/bin/env bash
out="\$("${REAL_MKTEMP}" "\$@")" || exit \$?
case "\${out##*/}" in suru-api.*) printf '%s\n' "\${out}" >> "${TMP}/api-dirs.log" ;; esac
printf '%s\n' "\${out}"
SHIM
chmod 755 "${TMP}/shim/mktemp"
export PATH="${TMP}/shim:${PATH}"
: > "${TMP}/api-dirs.log"

pass=0; fail=0
check() { # description, expected, actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "  ok   $1 ($3)"
  else fail=$((fail+1)); echo "  FAIL $1 — expected [$2] got [$3]"; fi
}

# --- Extract the shipped artefacts -------------------------------------------
FRAG="$(awk '/^  _pf_cleanup_staging\(\) \{/,/^  \}/' "${DRIVER}")"
PREINIT="$(awk '/^_PF_TRAP_DRY_RUN=/,/^_PF_REVERT_ARM_DONE=/' "${DRIVER}")"
REMOVER="$(awk '/^_pf_remove_tmp_files\(\) \{/,/^\}/' "${DRIVER}")"
ARM_FRAG="$(awk '/^  _pf_revert_arm\(\) \{/,/^  \}/' "${DRIVER}")"
DISARM_FRAG="$(awk '/^  _pf_revert_disarm\(\) \{/,/^  \}/' "${DRIVER}")"
RESTORE_FRAG="$(awk '/^  _pf_revert_restore\(\) \{/,/^  \}/' "${DRIVER}")"
ONCE_FRAG="$(awk '/^  _pf_revert_once\(\) \{/,/^  \}/' "${DRIVER}")"
[ -n "${REMOVER}" ] && [ -n "${ARM_FRAG}" ] && [ -n "${DISARM_FRAG}" ] && [ -n "${RESTORE_FRAG}" ] && [ -n "${ONCE_FRAG}" ] \
  || { echo "FATAL: revert helpers not found in the driver"; exit 2; }
[ -n "${FRAG}" ]    || { echo "FATAL: _pf_cleanup_staging not found — did the trap change?"; exit 2; }
[ -n "${PREINIT}" ] || { echo "FATAL: _PF_TRAP_* default block not found — did the snapshot change?"; exit 2; }

# Build and run one invocation of the shipped cleanup at global scope.
# $1 = extra assignments applied AFTER the shipped defaults (the snapshot a real
# deploy would have populated); empty means "trap fired before the snapshot was
# ever written" — that shape.
run_cleanup() {
  rm -f -- "${TMP}/ssh.log" "${TMP}/chain.log" "${TMP}/err.log"
  : > "${TMP}/ssh.log"; : > "${TMP}/chain.log"
  cat > "${TMP}/case.sh" <<EOF
set -euo pipefail
_PF_REMOTE_STAGING="/tmp/suru-staging"
${_BIN_PRELUDE}
${PREINIT}
${REMOVER}
ssh() { printf '%s\n' "\$*" >> "${TMP}/ssh.log"; }
_deploy_cleanup() { printf 'chained\n' >> "${TMP}/chain.log"; }
${FRAG}
${1}
_pf_cleanup_staging
EOF
  bash "${TMP}/case.sh" 2> "${TMP}/err.log"
  echo $?
}
ssh_calls()  { wc -l < "${TMP}/ssh.log" | tr -d ' '; }
chain_calls(){ wc -l < "${TMP}/chain.log" | tr -d ' '; }
unbound()    { grep -c 'unbound variable' "${TMP}/err.log" | tr -d ' '; }

POPULATED='_PF_TRAP_DRY_RUN="false"
_PF_TRAP_SSH_USER="deployer"
_PF_TRAP_TARGET="203.0.113.10"
_PF_TRAP_SSH_OPTS=(-i /dev/null -o BatchMode=yes)
_PF_TRAP_STAGING_KEEP="false"'

echo "== the trap fires at global scope with NO snapshot populated =="
r=$(run_cleanup "")
check "exits 0 instead of dying"        0 "$r"
check "no 'unbound variable' on stderr" 0 "$(unbound)"
check "issues no ssh (fail-safe)"       0 "$(ssh_calls)"
check "still runs the chained cleanup"  1 "$(chain_calls)"

echo "== real abort path: snapshot populated, dry-run false =="
r=$(run_cleanup "${POPULATED}")
check "exits 0"                          0 "$r"
check "no 'unbound variable' on stderr"  0 "$(unbound)"
check "issues exactly one ssh"           1 "$(ssh_calls)"
check "removes the staging dir"          1 "$(grep -c -- 'rm -rf /tmp/suru-staging' "${TMP}/ssh.log")"
check "sudo for a non-root ssh user"     1 "$(grep -c -- "sudo ${_PF_BIN_RM} -rf" "${TMP}/ssh.log")"
check "targets the snapshot host"        1 "$(grep -c -- 'deployer@203.0.113.10' "${TMP}/ssh.log")"
check "chained cleanup ran"              1 "$(chain_calls)"

echo "== root ssh user takes no sudo prefix =="
r=$(run_cleanup "${POPULATED}
_PF_TRAP_SSH_USER=\"root\"")
check "exits 0"                     0 "$r"
check "no sudo prefix"              0 "$(grep -c -- "sudo ${_PF_BIN_RM} -rf" "${TMP}/ssh.log")"
check "still removes staging"       1 "$(grep -c -- 'rm -rf /tmp/suru-staging' "${TMP}/ssh.log")"

echo "== dry-run touches nothing on the router =="
r=$(run_cleanup "${POPULATED}
_PF_TRAP_DRY_RUN=\"true\"")
check "exits 0"                        0 "$r"
check "issues no ssh"                  0 "$(ssh_calls)"
check "still runs the chained cleanup" 1 "$(chain_calls)"

echo "== success path keeps staging but still chains the temp cleanup =="
r=$(run_cleanup "${POPULATED}
_PF_TRAP_STAGING_KEEP=\"true\"")
check "exits 0"                        0 "$r"
check "staging dir deliberately kept"  0 "$(ssh_calls)"
check "chained cleanup still ran"      1 "$(chain_calls)"

echo "== an empty opts array must not expand (bash 3.2 + set -u) =="
r=$(run_cleanup "${POPULATED}
_PF_TRAP_SSH_OPTS=()")
check "exits 0"                         0 "$r"
check "no 'unbound variable' on stderr" 0 "$(unbound)"
check "issues no ssh"                   0 "$(ssh_calls)"

# --- temp files and the exit-triggered revert --------------------------
# The shipped cleanup, fired as a REAL EXIT trap (the script exits with a chosen
# status), with the revert entry point stubbed.
run_exit() { # $1 = assignments before the trap fires, $2 = exit status
  rm -f -- "${TMP}/ssh.log" "${TMP}/chain.log" "${TMP}/revert.log" "${TMP}/err.log"
  : > "${TMP}/ssh.log"; : > "${TMP}/chain.log"; : > "${TMP}/revert.log"
  cat > "${TMP}/case.sh" <<EOF
set -euo pipefail
_PF_REMOTE_STAGING="/tmp/suru-staging"
${_BIN_PRELUDE}
${PREINIT}
${REMOVER}
ssh() { printf '%s\n' "\$*" >> "${TMP}/ssh.log"; }
_deploy_cleanup() { printf 'chained\n' >> "${TMP}/chain.log"; }
_pf_revert_once() { printf 'reverted\n' >> "${TMP}/revert.log"; }
${FRAG}
${1}
trap '_pf_cleanup_staging' EXIT
exit ${2}
EOF
  bash "${TMP}/case.sh" 2> "${TMP}/err.log"
  echo $?
}
revert_calls() { wc -l < "${TMP}/revert.log" | tr -d ' '; }

echo "== the driver's temp files are removed by the EXIT trap =="
: > "${TMP}/leak1"; : > "${TMP}/leak2"
r=$(run_exit "_PF_TMP_FILES=(\"${TMP}/leak1\" \"${TMP}/leak2\")" 3)
check "exit status preserved"             3 "$r"
check "both registered files removed"     0 "$(ls "${TMP}"/leak1 "${TMP}"/leak2 2>/dev/null | wc -l | tr -d ' ')"
check "chained cleanup ran"               1 "$(chain_calls)"
r=$(run_exit "" 0)
check "an empty file list is harmless"    0 "$r"

echo "== a non-zero exit while armed reverts, once; otherwise never =="
r=$(run_exit '_PF_REVERT_ARMED="true"' 1)
check "armed + exit 1 reverts"            1 "$(revert_calls)"
check "exit status preserved"             1 "$r"
r=$(run_exit '_PF_REVERT_ARMED="true"' 0)
check "armed + exit 0 does not revert"    0 "$(revert_calls)"
r=$(run_exit '_PF_REVERT_ARMED="false"' 1)
check "disarmed + exit 1 does not revert" 0 "$(revert_calls)"
check "cleanup still chains"              1 "$(chain_calls)"

echo "== an interrupt after the backup reverts once and leaves no secret file =="
# The shipped arm / disarm / once / cleanup fragments run as a real script that
# arms the revert, then sits in `wait`; the test sends it SIGTERM. The revert is
# a stub that writes the revert password file the way _pf_revert does.
SIG_DIR="${TMP}/sig"
SIG_RC=""
run_signal() { # $1 = 1 for a slow revert (a second TERM arrives during it), $2 = signals to send
  rm -rf -- "${SIG_DIR}"; mkdir -p "${SIG_DIR}"
  {
    cat <<EOF
set -euo pipefail
_PF_REMOTE_STAGING="/tmp/suru-staging"
${_BIN_PRELUDE}
${PREINIT}
${REMOVER}
dry_run=false
ssh() { :; }
_deploy_cleanup() { :; }
${ARM_FRAG}
${RESTORE_FRAG}
${DISARM_FRAG}
${ONCE_FRAG}
${FRAG}
EOF
    cat <<'EOF'
_pf_revert() {
  : > "${TMPDIR}/.suru-bkpass.$$"
  printf 'reverted\n' >> "${TMPDIR}/revert.log"
  if [ "${SLOW_REVERT}" = 1 ]; then : > "${TMPDIR}/reverting"; sleep 5 & wait $!; fi
  rm -f -- "${TMPDIR}/.suru-bkpass.$$"
}
_PF_TMP_FILES+=("${TMPDIR}/.suru-bkpass.$$" "${TMPDIR}/step.tmp")
: > "${TMPDIR}/step.tmp"
: > "${TMPDIR}/.suru-bkpass.$$"
_pf_revert_arm
trap '_pf_cleanup_staging' EXIT
: > "${TMPDIR}/ready"
sleep 5 & wait $!
EOF
  } > "${TMP}/sigcase.sh"
  TMPDIR="${SIG_DIR}" SLOW_REVERT="$1" bash "${TMP}/sigcase.sh" > "${SIG_DIR}.out" 2>&1 &
  local pid=$! i=0
  while [ ! -e "${SIG_DIR}/ready" ] && [ "${i}" -lt 60 ]; do sleep 0.1; i=$((i + 1)); done
  kill -TERM "${pid}" 2>/dev/null
  if [ "$2" -ge 2 ]; then
    i=0
    while [ ! -e "${SIG_DIR}/reverting" ] && [ "${i}" -lt 60 ]; do sleep 0.1; i=$((i + 1)); done
    kill -TERM "${pid}" 2>/dev/null
  fi
  wait "${pid}"; SIG_RC=$?
}
sig_files() { local n=0 f; for f in "${SIG_DIR}"/.suru-bkpass.* "${SIG_DIR}"/step.tmp; do [ -e "${f}" ] && n=$((n + 1)); done; echo "${n}"; }
sig_reverts() { wc -l < "${SIG_DIR}/revert.log" 2>/dev/null | tr -d ' '; }

run_signal 0 1
check "SIGTERM after arm: exits 143"           143 "${SIG_RC}"
check "exactly one revert"                      1 "$(sig_reverts)"
check "no temp or password file left"           0 "$(sig_files)"
run_signal 1 2
check "second SIGTERM during the revert: exits" 1 "${SIG_RC}"
check "no second revert (disarmed)"             1 "$(sig_reverts)"
check "no password file left after the second"  0 "$(sig_files)"
check "arm installs INT, TERM and HUP handlers" 3 "$(printf '%s\n' "${ARM_FRAG}" | grep -cE "trap 'exit (130|143|129)' (INT|TERM|HUP)")"

# Behavioural: a pre-existing INT trap survives arm + disarm unchanged, and a
# TERM that arrives right after the arm still reverts once.
run_body() { # $1 = script body after the shipped fragments; output to ${SIG_DIR}.out
  rm -rf -- "${SIG_DIR}"; mkdir -p "${SIG_DIR}"
  {
    cat <<EOF
set -euo pipefail
export TMPDIR="${SIG_DIR}"
_PF_REMOTE_STAGING="/tmp/suru-staging"
${_BIN_PRELUDE}
${PREINIT}
${REMOVER}
dry_run=false
ssh() { :; }
_deploy_cleanup() { :; }
${ARM_FRAG}
${RESTORE_FRAG}
${DISARM_FRAG}
${ONCE_FRAG}
${FRAG}
_pf_revert() { printf 'reverted\n' >> "${SIG_DIR}/revert.log"; }
EOF
    printf '%s\n' "$1"
  } > "${TMP}/body.sh"
  bash "${TMP}/body.sh" > "${SIG_DIR}.out" 2>&1
  SIG_RC=$?
}
run_body "trap 'echo orig' INT
before=\"\$(trap -p INT)\"
_pf_revert_arm
during=\"\$(trap -p INT)\"
_pf_revert_disarm
after=\"\$(trap -p INT)\"
[ \"\${during}\" != \"\${before}\" ] || exit 11
case \"\${during}\" in *'exit 130'*) ;; *) exit 12 ;; esac
[ \"\${after}\" = \"\${before}\" ] || exit 13
[ \"\${_PF_REVERT_ARMED}\" = false ] || exit 14
exit 0"
check "arm replaces INT, disarm restores the original trap" 0 "${SIG_RC}"
run_body "_pf_revert_arm
trap '_pf_cleanup_staging' EXIT
kill -TERM \$\$
sleep 5"
check "TERM right after arm: exits 143"          143 "${SIG_RC}"
check "TERM right after arm: exactly one revert"   1 "$(sig_reverts)"

# A disarm that never followed an arm (dry run, no backup)
# leaves the shell's traps and errtrace alone.
run_body "trap 'echo orig' INT
set -E
_pf_revert_disarm
case \"\$-\" in *E*) ;; *) exit 11 ;; esac
case \"\$(trap -p INT)\" in *orig*) ;; *) exit 12 ;; esac
[ \"\${_PF_REVERT_ARMED}\" = false ] || exit 13
exit 0"
check "disarm without an arm leaves INT trap and errtrace alone" 0 "${SIG_RC}"
run_body "_pf_revert_arm
_pf_revert_disarm
[ \"\${_PF_REVERT_ARM_DONE}\" = false ] || exit 11
_pf_revert_disarm
exit 0"
check "disarm after an arm resets the arm state; a second disarm is a no-op" 0 "${SIG_RC}"

# The revert bounces Suricata only when this deploy already
# restarted it. The shipped _pf_revert runs against stubbed ssh/scp.
REVERT_FRAG="$(awk '/^  _pf_revert\(\) \{/,/^  \}/' "${DRIVER}")"
[ -n "${REVERT_FRAG}" ] || { echo "FATAL: _pf_revert not found"; exit 2; }
run_revert() { # $1 = _pf_suri_restarted, $2 = _pf_safety_armed
  : > "${TMP}/revert-calls.log"
  cat > "${TMP}/revertcase.sh" <<EOF
set -euo pipefail
_PF_REMOTE_STAGING="/tmp/suru-staging"
_PF_APPLIER_RESTORE="/repo/pfsense/backup-restore.php"
${_BIN_PRELUDE}
ssh_opts=(-i /dev/null); ssh_user=deployer; target=203.0.113.10
_pf_backup_remote=/root/suru-backups/b.bak; _pf_backup_local=/nonexistent
_pf_suri_restarted="$1"; _pf_safety_armed="$2"
_pf_write_password_file() { echo "${TMP}/pw.\$\$"; : > "${TMP}/pw.\$\$"; }
scp() { :; }
ssh() { :; }
_pf_svc_restart() { echo "svc \$1" >> "${TMP}/revert-calls.log"; }
safety_timer_disarm_quiet() { echo quiet >> "${TMP}/revert-calls.log"; }
${REVERT_FRAG}
_pf_revert
EOF
  REV_OUT="$(bash "${TMP}/revertcase.sh" 2>"${TMP}/rev.err")"
  REV_RC=$?
  REV_ERR="$(cat "${TMP}/rev.err")"
}
revert_svcs() { grep '^svc ' "${TMP}/revert-calls.log" | sed 's/^svc //' | paste -sd, -; }
run_revert false false
check "no Suricata restart by the deploy: revert completes"   0 "${REV_RC}"
check "no Suricata restart by the deploy: syslog-ng only"     "syslog-ng" "$(revert_svcs)"
case "${REV_OUT}" in *"Suricata was not restarted by this deploy"*) _s=1 ;; *) _s=0 ;; esac
check "no Suricata restart by the deploy: says so" 1 "${_s}"
case "${REV_ERR}" in *"WARN: config.xml is restored"*"may still hold this deploy's partial config"*"Services > Suricata > Interfaces > Save"*"corrected deploy"*) _s=1 ;; *) _s=0 ;; esac
check "no Suricata restart by the deploy: stderr WARN on the stale yamls and the remedy" 1 "${_s}"
run_revert true false
check "Suricata restarted by the deploy: revert completes"    0 "${REV_RC}"
check "Suricata restarted by the deploy: both bounced"        "syslog-ng,suricata" "$(revert_svcs)"
case "${REV_OUT}" in *"Suricata was not restarted"*) _s=1 ;; *) _s=0 ;; esac
check "Suricata restarted by the deploy: no 'not restarted' line" 0 "${_s}"
case "${REV_ERR}" in *"partial config"*) _s=1 ;; *) _s=0 ;; esac
check "Suricata restarted by the deploy: no stale-yaml warning" 0 "${_s}"
run_revert false true
check "no restart, timer armed: timer still disarmed once"    1 "$(grep -c '^quiet' "${TMP}/revert-calls.log")"
run_revert true true
check "restart, timer armed: timer disarmed once"             1 "$(grep -c '^quiet' "${TMP}/revert-calls.log")"
run_revert false false
check "timer not armed: no disarm"                            0 "$(grep -c '^quiet' "${TMP}/revert-calls.log")"

echo "== static: every temp file the driver creates is registered for the trap =="
# The oracle can only see a leaked file where mktemp honours TMPDIR (Linux); this
# holds on every host: each mktemp / secret_mktemp call site is followed by a
# registration, so a new one cannot be added without one.
made="$(grep -cE '\(mktemp\)"|\(secret_mktemp\)"' "${DRIVER}" || true)"
registered="$(grep -cE '^\s*_PF_TMP_FILES\+=\("\$\{' "${DRIVER}" || true)"
check "at least one temp-file call site found" 1 "$([ "${made:-0}" -gt 0 ] && echo 1 || echo 0)"
check "each call site is registered (${made} created)" "${made}" "${registered}"
# The line right after each call site registers THAT variable: an extra
# registration elsewhere cannot mask a missing one, and consecutive call sites
# are each checked on their own (no getline). A call-site line the pattern
# cannot read a variable from counts as unregistered.
reg_guard() {
  awk '
    want != "" {
      if (index($0, "_PF_TMP_FILES+=(\"${" want "}\")") == 0) bad++
      want = ""
    }
    /\((secret_)?mktemp\)"/ {
      if (match($0, /[A-Za-z_][A-Za-z_0-9]*="\$\((secret_)?mktemp\)"/)) {
        want = substr($0, RSTART, RLENGTH)
        sub(/=.*/, "", want)
      } else bad++
    }
    END { if (want != "") bad++; print bad + 0 }
  ' "$1"
}
unregistered="$(reg_guard "${DRIVER}")"
check "the line after each call site is its _PF_TMP_FILES registration" 0 "${unregistered}"
printf '%s\n' 'a="$(mktemp)"' '_PF_TMP_FILES+=("${a}")' 'b="$(mktemp)"' 'c="$(mktemp)"' '_PF_TMP_FILES+=("${c}")' > "${TMP}/guard-bad.txt"
check "control: a call site whose registration is missing is caught" 1 "$(reg_guard "${TMP}/guard-bad.txt")"
printf '%s\n' 'a="$(mktemp)"' '_PF_TMP_FILES+=("${other}")' > "${TMP}/guard-bad2.txt"
check "control: a registration of another variable is caught"        1 "$(reg_guard "${TMP}/guard-bad2.txt")"

# --- Static invariants — guard the regressions themselves --------------------
echo "== static: the cleanup body reads no _platform_deploy local =="
for lcl in dry_run ssh_user ssh_opts target; do
  # Any bare reference — "${dry_run}", "$ssh_user" — is the closure bug
  # returning. The _PF_TRAP_ prefixed names are the sanctioned snapshot.
  n="$(printf '%s\n' "${FRAG}" | grep -cE '\$\{?'"${lcl}"'[\[}:]' || true)"
  check "body does not read \${${lcl}}" 0 "${n}"
done

echo "== static: the snapshot is populated BEFORE the trap is armed =="
snap_line="$(grep -n '^  _PF_TRAP_SSH_OPTS=(' "${DRIVER}" | head -1 | cut -d: -f1)"
trap_line="$(grep -n "^  trap '_pf_cleanup_staging' EXIT" "${DRIVER}" | head -1 | cut -d: -f1)"
check "snapshot assignment found"  1 "$([ -n "${snap_line}" ] && echo 1 || echo 0)"
check "trap install found"         1 "$([ -n "${trap_line}" ] && echo 1 || echo 0)"
check "snapshot precedes the trap" 1 "$([ -n "${snap_line}" ] && [ -n "${trap_line}" ] && [ "${snap_line}" -lt "${trap_line}" ] && echo 1 || echo 0)"

echo "== static: the success path must not disarm the EXIT trap =="
check "no bare 'trap - EXIT' in the driver" 0 "$(grep -cE '^\s*trap - EXIT\s*$' "${DRIVER}" || true)"
check "success path sets the keep flag"     1 "$(grep -cE '^\s*_PF_TRAP_STAGING_KEEP="true"' "${DRIVER}" || true)"

echo "== static: deploy.sh chains the trap it replaces =="
check "_deploy_cleanup is not a bare no-op" 0 "$(grep -cE '^_deploy_cleanup\(\) \{ : ; \}' "${DEPLOY}" || true)"
check "_deploy_cleanup calls _api_cleanup_tmp" 1 "$(grep -qE '^\s*declare -f _api_cleanup_tmp .*&& _api_cleanup_tmp' "${DEPLOY}" && echo 1 || echo 0)"
check "driver chains _deploy_cleanup"         1 "$(printf '%s\n' "${FRAG}" | grep -cE '_deploy_cleanup' || true)"
# The SSH master is closed by the chain head, after the driver's staging
# cleanup ran over it; reuse is enabled only for a real deploy.
check "_deploy_cleanup closes the SSH master"  1 "$(grep -qE '^\s*declare -f ssh_mux_close .*&& ssh_mux_close' "${DEPLOY}" && echo 1 || echo 0)"
check "deploy.sh enables reuse outside dry-run" 1 "$(grep -B2 -E '^\s*ssh_mux_enable$' "${DEPLOY}" | grep -cE 'DRY_RUN.*!= "true"' || true)"

# Where does api.sh actually put its temp dir? ASK IT, rather than restating its
# rule here. api.sh prefers /dev/shm when present and writable, else ${TMPDIR:-/tmp},
# so on a Linux CI runner every _API_TMPDIR lands in /dev/shm while a macOS host
# uses $TMPDIR. An orphan check hardcoded to the wrong base reports zero whether or
# not a leak occurred — the defect this replaced. Deriving the base from the library
# cannot drift from the library, and needs no per-platform branch in this suite.
_API_TMP_BASE="$(bash -c 'set -euo pipefail
source "'"${LOGLIB}"'"
source "'"${APILIB}"'"
dirname "${_API_TMPDIR}"')"
[ -d "${_API_TMP_BASE}" ] || { echo "FATAL: could not derive api.sh temp base"; exit 2; }

# --- lib/api.sh: the first link in the chain ---------------------------------
# The tracked-temp-file cleanup was an array appended inside _api_mktemp_secure,
# but every call site reads the path back with command substitution — a SUBSHELL —
# so the parent's array stayed empty and the cleanup never removed anything. The
# exposure is real: an abort between creating the JWT request body and the inline
# `rm -f` leaves a 0600 file holding the router API password.
echo "== lib/api.sh: a file made in a subshell is still cleaned in the parent =="
api_probe() { # $1 = body appended after sourcing; echoes the script's rc
  cat > "${TMP}/api.sh" <<EOF
set -euo pipefail
source "${LOGLIB}"
source "${APILIB}"
${1}
EOF
  bash "${TMP}/api.sh" > "${TMP}/api.out" 2> "${TMP}/api.err"
  echo $?
}

r=$(api_probe 'f="$(_api_mktemp_secure)"
printf "%s" "${f}" > '"${TMP}"'/apifile
[ -f "${f}" ] || exit 9
[ "$(stat -c "%a" "${f}" 2>/dev/null || stat -f "%OLp" "${f}" 2>/dev/null)" = "600" ] || exit 8
_api_cleanup_tmp
[ -e "${f}" ] && exit 7
exit 0')
check "0600 file created, then removed by cleanup" 0 "$r"

r=$(api_probe 'f="$(_api_mktemp_secure)"
_api_cleanup_tmp
_api_cleanup_tmp
exit 0')
check "cleanup is idempotent"                      0 "$r"

r=$(api_probe 'f="$(_api_mktemp_secure)"
printf "%s" "${f}" > '"${TMP}"'/apifile2
exit 3')
check "abort path exits with its own code"         3 "$r"
apifile2="$(cat "${TMP}/apifile2" 2>/dev/null || echo /nonexistent)"
check "temp file removed by the EXIT trap on abort" 0 "$([ -e "${apifile2}" ] && echo 1 || echo 0)"
check "its parent dir removed too"                  0 "$([ -d "$(dirname "${apifile2}")" ] && echo 1 || echo 0)"

# Saves and restores the real _API_TMPDIR: pointing it elsewhere would orphan the
# source-time dir, leaking one per run of this suite in CI.
r=$(api_probe '_saved="${_API_TMPDIR}"
_API_TMPDIR="'"${TMP}"'/not-ours"
mkdir -p "${_API_TMPDIR}"
_api_cleanup_tmp
[ -d "${_API_TMPDIR}" ] || exit 6
_API_TMPDIR="${_saved}"
exit 0')
check "recursive remove refuses a foreign dir"     0 "$r"

echo "== lib/api.sh is sourced twice per deploy — the temp dir must not be orphaned =="
r=$(api_probe 'first="${_API_TMPDIR}"
source "'"${APILIB}"'"
[ "${first}" = "${_API_TMPDIR}" ] || exit 5
[ -d "${_API_TMPDIR}" ] || exit 4
exit 0')
check "re-sourcing api.sh keeps the same temp dir" 0 "$r"

echo "== static: the subshell-lost array is gone =="
check "no _API_TMPFILES in api.sh code" 0 "$(grep -v '^\s*#' "${APILIB}" | grep -c '_API_TMPFILES' || true)"
# Leading whitespace tolerated: the arm now lives INSIDE the _API_TMPDIR guard.
check "api.sh still arms its own EXIT trap" 1 "$(grep -cE '^[[:space:]]*trap _api_cleanup_tmp EXIT' "${APILIB}" || true)"
check "api.sh guards against a second source"   1 "$(grep -cE '^if \[\[ -z "\$\{_API_TMPDIR:-\}"' "${APILIB}" || true)"

echo "== re-sourcing api.sh must not clobber a trap the caller armed in between =="
rm -f -- "${TMP}/chain2.log"
r=$(api_probe 'chain() { printf "chained\n" >> '"${TMP}"'/chain2.log; declare -f _api_cleanup_tmp > /dev/null 2>&1 && _api_cleanup_tmp || true; }
trap chain EXIT
source "'"${APILIB}"'"
exit 0')
check "process exits 0"                       0 "$r"
check "the caller's chained trap still fires" 1 "$(wc -l < "${TMP}/chain2.log" 2>/dev/null | tr -d ' ')"

# The empty-array guard below is only ENFORCED by the interpreter on bash 3.2,
# where "${arr[@]}" on an empty array errors under `set -u`; bash >= 4.4 (CI's
# ubuntu runner) permits it. The dynamic case above therefore cannot catch its
# removal in CI — assert the guard's presence statically so both hosts do.
check "empty-opts guard present in the cleanup" 1 "$(printf '%s\n' "${FRAG}" | grep -cE '\$\{#_PF_TRAP_SSH_OPTS\[@\]\} -gt 0' || true)"


echo "== nothing leaked: no api.sh temp dir survives the whole suite =="
# LAST assertion deliberately: every preceding section sources api.sh, so this can
# only account for all of them if it runs after all of them. It checks the dirs
# this suite created (logged by the mktemp shim), not every suru-api.* in the
# shared base, which a concurrently running suite can populate.
created="$(grep -c . "${TMP}/api-dirs.log" || true)"
survivors=0
while IFS= read -r d; do
  if [ -n "${d}" ] && [ -e "${d}" ]; then survivors=$((survivors + 1)); fi
done < "${TMP}/api-dirs.log"
check "the mktemp shim recorded this suite's api.sh temp dirs" yes "$([ "${created:-0}" -gt 0 ] && echo yes || echo no)"
check "every recorded dir is under the api.sh base" 0 "$(grep -cv "^${_API_TMP_BASE%/}/suru-api\\." "${TMP}/api-dirs.log" || true)"
check "no suru-api dir orphaned by this suite (${created:-0} created)" 0 "${survivors}"
echo
echo "passed=${pass} failed=${fail}"
[ "${fail}" -eq 0 ]
