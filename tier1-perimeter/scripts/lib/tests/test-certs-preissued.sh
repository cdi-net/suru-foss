#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for lib/certs.sh pre-issued mode (SURU_PKI_PREISSUED)
#
# Proves, against a throwaway CA generated in a mktemp tree:
#   - pre-issued mode needs only root-ca.pem (certs_check_ca passes with no CA
#     key present) and certs_generate_client only verifies the staged pair;
#   - a CA key without its certificate dies and never names generate-certs.sh
#     (which rotates the CA) as the remedy;
#   - it dies naming the remedy when the pair is absent, the key is unreadable,
#     or the cert was signed by a different CA;
#   - it never signs: no .csr / new file appears in TIER1_CERTS_DIR and the CA
#     key is absent from the tree it runs against;
#   - the default (non-pre-issued) branch still signs with the CA key and is
#     idempotent, writing under ${TIER1_DIR}/certs.
#
# Hermetic: openssl only, no network, no .env, no router.
# Usage: bash tier1-perimeter/scripts/lib/tests/test-certs-preissued.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SUITE_DIR}/../../../.." && pwd)"
# shellcheck source=../../../../lib/bash/test-harness.sh
source "${SRC_ROOT}/lib/bash/test-harness.sh"

command -v openssl > /dev/null 2>&1 || { echo "SKIP: openssl not available"; exit 0; }

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

# shellcheck source=../log.sh
source "${SUITE_DIR}/../log.sh"
# shellcheck source=../certs.sh
source "${SUITE_DIR}/../certs.sh"

NAME="tier1-pfsense-syslogng"
# The Makefile exports SURU_PKI_DIR to its recipes; every fixture below places
# its CA under REPO_ROOT, so start from none of the path overrides.
unset SURU_PKI_DIR TIER1_CERTS_DIR SURU_PKI_PREISSUED

# _mk_ca <dir>: writes <dir>/root-ca.pem and <dir>/root-ca-key.pem
_mk_ca() {
  mkdir -p "$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/root-ca-key.pem" 2> /dev/null
  openssl req -new -x509 -sha256 -days 400 -subj "/CN=test-root-ca" \
    -key "$1/root-ca-key.pem" -out "$1/root-ca.pem" 2> /dev/null
}

# _mk_client <ca-dir> <out-dir>: client pair signed by the CA in <ca-dir>.
_mk_client() {
  mkdir -p "$2"
  openssl ecparam -name prime256v1 -genkey -noout -out "$2/${NAME}-key.pem" 2> /dev/null
  openssl req -new -sha256 -subj "/C=RO/O=SURU Platform/OU=Tier1/CN=suru-${NAME}" -key "$2/${NAME}-key.pem" \
    -out "$2/${NAME}.csr" 2> /dev/null
  openssl x509 -req -sha256 -days 30 -CA "$1/root-ca.pem" -CAkey "$1/root-ca-key.pem" \
    -CAcreateserial -in "$2/${NAME}.csr" -out "$2/${NAME}.pem" 2> /dev/null
  rm -f "$2/${NAME}.csr"
}

# Fixture: the authoritative CA (key kept aside), a tree that holds ONLY the
# public CA cert, a foreign CA.
CA_FULL="${TMP}/ca-full"
_mk_ca "${CA_FULL}"
REPO_PUB="${TMP}/repo-pub"
mkdir -p "${REPO_PUB}/tier4-operations/pki/certs" "${REPO_PUB}/tier1-perimeter"
cp "${CA_FULL}/root-ca.pem" "${REPO_PUB}/tier4-operations/pki/certs/root-ca.pem"
STAGED="${TMP}/staged"
_mk_client "${CA_FULL}" "${STAGED}"
FOREIGN="${TMP}/foreign"
_mk_ca "${FOREIGN}"
FOREIGN_CLIENT="${TMP}/foreign-client"
_mk_client "${FOREIGN}" "${FOREIGN_CLIENT}"

# _run_pre <certs-dir> -> sets RC and OUT (stdout+stderr), in a subshell
_run_pre() {
  OUT="$(
    export REPO_ROOT="${REPO_PUB}" TIER1_DIR="${REPO_PUB}/tier1-perimeter" DRY_RUN=false
    export SURU_PKI_PREISSUED=true TIER1_CERTS_DIR="$1"
    certs_generate_client "${NAME}" 2>&1
  )"
  RC=$?
}

echo "== pre-issued mode"

# 1. certs_check_ca passes with only the public CA cert present
OUT="$(REPO_ROOT="${REPO_PUB}" SURU_PKI_PREISSUED=true certs_check_ca 2>&1)"; RC=$?
assert_eq "certs_check_ca passes with only root-ca.pem (no CA key)" "0" "${RC}"

# 1b. the default mode still requires the CA key
OUT="$( (REPO_ROOT="${REPO_PUB}" SURU_PKI_PREISSUED=false certs_check_ca) 2>&1)"; RC=$?
assert_eq "default mode still dies without root-ca-key.pem" "1" "${RC}"

# 1c. CA key present, certificate absent: dies, and never names generate-certs.sh
# as the remedy (it rotates the CA)
REPO_KEYONLY="${TMP}/repo-keyonly"
mkdir -p "${REPO_KEYONLY}/tier4-operations/pki/certs"
cp "${CA_FULL}/root-ca-key.pem" "${REPO_KEYONLY}/tier4-operations/pki/certs/"
OUT="$( (REPO_ROOT="${REPO_KEYONLY}" SURU_PKI_PREISSUED=false certs_check_ca) 2>&1)"; RC=$?
assert_eq "key without certificate dies" "1" "${RC}"
case "${OUT}" in
  *"Do NOT run generate-certs.sh"*"Restore root-ca.pem from your backup"*) _pass "key without certificate points at the restore, not at generate-certs.sh" ;;
  *) _fail "key without certificate message (got: ${OUT})" ;;
esac
INSTALL_PKI="${TMP}/install-pki"
mkdir -p "${INSTALL_PKI}"
cp "${CA_FULL}/root-ca-key.pem" "${INSTALL_PKI}/"
OUT="$( (REPO_ROOT="${REPO_KEYONLY}" SURU_PKI_DIR="${INSTALL_PKI}" SURU_PKI_PREISSUED=false certs_check_ca) 2>&1)"; RC=$?
assert_eq "SURU_PKI_DIR key without certificate dies" "1" "${RC}"
case "${OUT}" in
  *"Do NOT run generate-certs.sh"*"backup"*) _pass "SURU_PKI_DIR key-only message says restore from the backup" ;;
  *) _fail "SURU_PKI_DIR key-only message (got: ${OUT})" ;;
esac
OUT="$( (REPO_ROOT="${REPO_KEYONLY}" SURU_PKI_DIR="${TMP}/does-not-exist" SURU_PKI_PREISSUED=false certs_check_ca) 2>&1)"; RC=$?
case "${OUT}" in
  *"but the CA key exists"*) _fail "unresolvable dir with no key must not claim a key exists (got: ${OUT})" ;;
  *) _pass "unresolvable SURU_PKI_DIR is not treated as a half-pair" ;;
esac

# 2. valid staged pair -> passes, nothing written into the certs dir
before="$(ls -1 "${STAGED}" | sort | tr '\n' ' ')"
_run_pre "${STAGED}"
after="$(ls -1 "${STAGED}" | sort | tr '\n' ' ')"
assert_eq "valid staged pair accepted" "0" "${RC}"
assert_eq "no file created or removed in TIER1_CERTS_DIR" "${before}" "${after}"

# 3. no .csr or key anywhere under the repo tree (it never signs)
n_csr="$(find "${REPO_PUB}" "${STAGED}" -name '*.csr' | wc -l | tr -d ' ')"
assert_eq "no .csr produced" "0" "${n_csr}"
assert_eq "tier1 certs dir not created in the pre-issued tree" "no" \
  "$([ -e "${REPO_PUB}/tier1-perimeter/certs" ] && echo yes || echo no)"

# 4. absent pair -> dies naming the remedy
EMPTY="${TMP}/empty"; mkdir -p "${EMPTY}"
_run_pre "${EMPTY}"
assert_eq "absent pair dies" "1" "${RC}"
case "${OUT}" in
  *"make -C tier1-perimeter gen-certs"*"copy the pair to ${EMPTY}"*) _pass "absent pair names the remedy" ;;
  *) _fail "absent pair names the remedy (got: ${OUT})" ;;
esac
assert_eq "absent pair: nothing created" "0" "$(ls -1 "${EMPTY}" | wc -l | tr -d ' ')"

# 5. cert signed by another CA -> dies
_run_pre "${FOREIGN_CLIENT}"
assert_eq "cert from another CA dies" "1" "${RC}"
case "${OUT}" in
  *"missing or invalid"*) _pass "foreign-CA cert reports invalid" ;;
  *) _fail "foreign-CA cert reports invalid (got: ${OUT})" ;;
esac

# 6. cert present, key missing -> dies
NOKEY="${TMP}/nokey"; mkdir -p "${NOKEY}"
cp "${STAGED}/${NAME}.pem" "${NOKEY}/${NAME}.pem"
_run_pre "${NOKEY}"
assert_eq "cert without key dies" "1" "${RC}"

# 7. valid cert with a key from a second throwaway key -> dies, no key material printed
MISMATCH="${TMP}/mismatch"; mkdir -p "${MISMATCH}"
cp "${STAGED}/${NAME}.pem" "${MISMATCH}/${NAME}.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "${MISMATCH}/${NAME}-key.pem" 2> /dev/null
_run_pre "${MISMATCH}"
assert_eq "key not matching the cert dies" "1" "${RC}"
case "${OUT}" in
  *"does not match"*"make -C tier1-perimeter gen-certs"*) _pass "mismatched key names the remedy" ;;
  *) _fail "mismatched key names the remedy (got: ${OUT})" ;;
esac
case "${OUT}" in
  *"PRIVATE KEY"*) _fail "mismatched key: key material printed" ;;
  *) _pass "mismatched key: no key material printed" ;;
esac

echo "== default (non-pre-issued) branch still signs"
REPO_FULL="${TMP}/repo-full"
mkdir -p "${REPO_FULL}/tier4-operations/pki/certs" "${REPO_FULL}/tier1-perimeter"
cp "${CA_FULL}/root-ca.pem" "${CA_FULL}/root-ca-key.pem" "${REPO_FULL}/tier4-operations/pki/certs/"
OUT="$(
  export REPO_ROOT="${REPO_FULL}" TIER1_DIR="${REPO_FULL}/tier1-perimeter" DRY_RUN=false
  unset SURU_PKI_PREISSUED TIER1_CERTS_DIR
  certs_generate_client "${NAME}" 2>&1
)"; RC=$?
assert_eq "default branch generates the pair" "0" "${RC}"
if [ -f "${REPO_FULL}/tier1-perimeter/certs/${NAME}.pem" ] \
   && openssl verify -CAfile "${CA_FULL}/root-ca.pem" "${REPO_FULL}/tier1-perimeter/certs/${NAME}.pem" > /dev/null 2>&1; then
  _pass "generated cert verifies against the CA"
else
  _fail "generated cert verifies against the CA"
fi
sum1="$(openssl x509 -in "${REPO_FULL}/tier1-perimeter/certs/${NAME}.pem" -noout -fingerprint -sha256)"
OUT="$(
  export REPO_ROOT="${REPO_FULL}" TIER1_DIR="${REPO_FULL}/tier1-perimeter" DRY_RUN=false
  unset SURU_PKI_PREISSUED TIER1_CERTS_DIR
  certs_generate_client "${NAME}" 2>&1
)"; RC=$?
sum2="$(openssl x509 -in "${REPO_FULL}/tier1-perimeter/certs/${NAME}.pem" -noout -fingerprint -sha256)"
assert_eq "re-run is idempotent (cert unchanged)" "${sum1}" "${sum2}"

echo "== static: the CA key is read only outside the pre-issued path"
# The CA key path appears in certs_check_ca (guarded) and the default branch.
guard="$(grep -c 'SURU_PKI_PREISSUED' "${SUITE_DIR}/../certs.sh")"
if [ "${guard}" -ge 3 ]; then _pass "certs.sh gates on SURU_PKI_PREISSUED (${guard} sites)"; else _fail "certs.sh gates on SURU_PKI_PREISSUED"; fi

test_summary
