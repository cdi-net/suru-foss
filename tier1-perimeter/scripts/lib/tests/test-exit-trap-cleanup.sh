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

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

pass=0; fail=0
check() { # description, expected, actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "  ok   $1 ($3)"
  else fail=$((fail+1)); echo "  FAIL $1 — expected [$2] got [$3]"; fi
}

# --- Extract the shipped artefacts -------------------------------------------
FRAG="$(awk '/^  _pf_cleanup_staging\(\) \{/,/^  \}/' "${DRIVER}")"
PREINIT="$(awk '/^_PF_TRAP_DRY_RUN=/,/^_PF_TRAP_STAGING_KEEP=/' "${DRIVER}")"
[ -n "${FRAG}" ]    || { echo "FATAL: _pf_cleanup_staging not found — did the trap change?"; exit 2; }
[ -n "${PREINIT}" ] || { echo "FATAL: _PF_TRAP_* default block not found — did the snapshot change?"; exit 2; }

# Build and run one invocation of the shipped cleanup at global scope.
# $1 = extra assignments applied AFTER the shipped defaults (the snapshot a real
# deploy would have populated); empty means "trap fired before the snapshot was
# ever written" — the the trap-scope defect shape.
run_cleanup() {
  rm -f -- "${TMP}/ssh.log" "${TMP}/chain.log" "${TMP}/err.log"
  : > "${TMP}/ssh.log"; : > "${TMP}/chain.log"
  cat > "${TMP}/case.sh" <<EOF
set -euo pipefail
_PF_REMOTE_STAGING="/tmp/suru-staging"
${PREINIT}
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
check "targets the snapshot host"        1 "$(grep -c -- 'deployer@203.0.113.10' "${TMP}/ssh.log")"
check "chained cleanup ran"              1 "$(chain_calls)"

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

# --- Static invariants — guard the regressions themselves --------------------
echo "== static: the cleanup body reads no _platform_deploy local =="
for lcl in dry_run ssh_user ssh_opts target; do
  # Any bare reference — "${dry_run}", "$ssh_user" — is the the trap-scope defect closure bug
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

echo "== static: the subshell-lost array is gone (companion defect) =="
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
# only account for all of them if it runs after all of them.
check "no suru-api dir orphaned by this suite"     0 "$(find "${_API_TMP_BASE}" -maxdepth 1 -name 'suru-api.*' 2>/dev/null | wc -l | tr -d ' ')"
echo
echo "passed=${pass} failed=${fail}"
[ "${fail}" -eq 0 ]
