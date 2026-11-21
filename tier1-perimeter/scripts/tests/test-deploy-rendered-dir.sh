#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for deploy.sh --rendered-dir
#
# Runs a copy of the shipped deploy.sh and lib/ in a mktemp layout with a stub
# platform driver that records the arguments of _platform_deploy. Asserts:
#   - --rendered-dir <dir> is passed to the hook as its second argument;
#   - without the flag the default tier1-perimeter/rendered/<platform> is used
#     (and a missing default still ends a dry-run early, driver not called);
#   - a non-directory, a relative path and a missing value are refused;
#   - an unknown option is refused;
#   - a dry run opens no SSH control directory.
#
# Hermetic: ssh/scp/envsubst are PATH stubs, no network, no router, no .env.
# Usage: bash tier1-perimeter/scripts/tests/test-deploy-rendered-dir.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SUITE_DIR}/../../.." && pwd)"
# shellcheck source=../../../lib/bash/test-harness.sh
source "${SRC_ROOT}/lib/bash/test-harness.sh"

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

# Layout: ${TMP}/repo/tier1-perimeter/scripts/{deploy.sh,lib,platforms}
REPO="${TMP}/repo"
SCR="${REPO}/tier1-perimeter/scripts"
mkdir -p "${SCR}/platforms" "${TMP}/bin"
cp "${SUITE_DIR}/../deploy.sh" "${SCR}/deploy.sh"
cp -R "${SUITE_DIR}/../lib" "${SCR}/lib"
rm -rf "${SCR}/lib/tests"

cat > "${SCR}/platforms/pfsense.sh" << 'EOF'
_platform_deploy() {
  echo "HOOK target=$1 rendered=$2 dry=$3 verbose=$4"
}
EOF

for c in ssh scp envsubst; do
  printf '#!/bin/sh\nexit 0\n' > "${TMP}/bin/${c}"
  chmod 755 "${TMP}/bin/${c}"
done

# _deploy <args...> -> OUT (stdout+stderr), RC
_deploy() {
  OUT="$(env -u ROUTER_HOST PATH="${TMP}/bin:${PATH}" bash "${SCR}/deploy.sh" "$@" 2>&1)"
  RC=$?
}

RD="${TMP}/rd"
mkdir -p "${RD}"

echo "== --rendered-dir"
_deploy --platform pfsense --dry-run --rendered-dir "${RD}"
assert_eq "explicit dir: exit 0" "0" "${RC}"
case "${OUT}" in
  *"rendered=${RD} "*) _pass "explicit dir is the hook's second argument" ;;
  *) _fail "explicit dir is the hook's second argument (got: ${OUT})" ;;
esac

echo "== default path unchanged"
DEF="${REPO}/tier1-perimeter/rendered/pfsense"
_deploy --platform pfsense --dry-run
assert_eq "no flag, no default dir, dry-run: exit 0" "0" "${RC}"
case "${OUT}" in
  *HOOK*) _fail "no default dir: hook must not run (got: ${OUT})" ;;
  *"dry-run skipping deploy step"*) _pass "no default dir: dry-run skips the hook" ;;
  *) _fail "no default dir: expected the skip message (got: ${OUT})" ;;
esac
mkdir -p "${DEF}"
_deploy --platform pfsense --dry-run
case "${OUT}" in
  *"rendered=${DEF} "*) _pass "no flag: default rendered path is the hook's second argument" ;;
  *) _fail "no flag: default rendered path (got: ${OUT})" ;;
esac

echo "== refusals"
_deploy --platform pfsense --dry-run --rendered-dir "${TMP}/nope"
assert_eq "non-directory: exit 1" "1" "${RC}"
case "${OUT}" in
  *"not a directory"*) _pass "non-directory names the problem" ;;
  *) _fail "non-directory names the problem (got: ${OUT})" ;;
esac
case "${OUT}" in *HOOK*) _fail "non-directory: hook must not run" ;; *) _pass "non-directory: hook not run" ;; esac

_deploy --platform pfsense --dry-run --rendered-dir "relative/dir"
assert_eq "relative path: exit 1" "1" "${RC}"

_deploy --platform pfsense --dry-run --rendered-dir
assert_eq "missing value: exit 1" "1" "${RC}"

_deploy --platform pfsense --dry-run --no-such-option "${RD}"
assert_eq "unknown option: exit 1" "1" "${RC}"
case "${OUT}" in
  *"Unknown argument"*) _pass "unknown option is named" ;;
  *) _fail "unknown option is named (got: ${OUT})" ;;
esac

echo "== a dry run opens no SSH control directory"
before="$(find /tmp -maxdepth 1 -name 'suru-ssh.*' 2> /dev/null | wc -l | tr -d ' ')"
_deploy --platform pfsense --dry-run --rendered-dir "${RD}"
after="$(find /tmp -maxdepth 1 -name 'suru-ssh.*' 2> /dev/null | wc -l | tr -d ' ')"
assert_eq "no /tmp/suru-ssh.* directory is left by a dry run" "${before}" "${after}"
test_summary
