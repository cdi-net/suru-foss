#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — tests for SURU_PKI_DIR
#
# Proves:
#   - certs_check_ca and certs_generate_client read the Root CA from
#     SURU_PKI_DIR when it is set (a temp CA outside any repo tree), and fall
#     back to ${REPO_ROOT}/tier4-operations/pki/certs when it is unset;
#   - a client certificate issued by certs_generate_client carries a Subject
#     Key Identifier and an Authority Key Identifier;
#   - SURU_PKI_DIR defaults under REPO_ROOT in the Makefile, an explicit value
#     wins, and the variable reaches child processes (deploy.sh);
#   - the Tier 1 scripts read the Root CA only through SURU_PKI_DIR.
#
# Hermetic: openssl + make, no network, no .env, no router.
# Usage: bash tier1-perimeter/scripts/lib/tests/test-pki-dir-norepo.sh
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SUITE_DIR}/../../../.." && pwd)"
# shellcheck source=../../../../lib/bash/test-harness.sh
source "${SRC_ROOT}/lib/bash/test-harness.sh"

command -v openssl > /dev/null 2>&1 || { echo "SKIP: openssl not available"; exit 0; }
command -v make > /dev/null 2>&1 || { echo "SKIP: make not available"; exit 0; }

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

# shellcheck source=../log.sh
source "${SUITE_DIR}/../log.sh"
# shellcheck source=../certs.sh
source "${SUITE_DIR}/../certs.sh"

NAME="tier1-pfsense-syslogng"

echo "== certs.sh reads the Root CA from SURU_PKI_DIR"
CA_DIR="${TMP}/pki"
mkdir -p "${CA_DIR}"
openssl ecparam -name prime256v1 -genkey -noout -out "${CA_DIR}/root-ca-key.pem" 2> /dev/null
openssl req -new -x509 -sha256 -days 400 -subj "/CN=test-root-ca" \
  -key "${CA_DIR}/root-ca-key.pem" -out "${CA_DIR}/root-ca.pem" 2> /dev/null

# A repo root that carries no CA at all: only SURU_PKI_DIR can satisfy the read.
EMPTY_REPO="${TMP}/repo-empty"
mkdir -p "${EMPTY_REPO}/tier1-perimeter"

OUT="$( (REPO_ROOT="${EMPTY_REPO}" SURU_PKI_DIR="${CA_DIR}" certs_check_ca) 2>&1)"; RC=$?
assert_eq "certs_check_ca passes with the CA only in SURU_PKI_DIR" "0" "${RC}"

OUT="$( (REPO_ROOT="${EMPTY_REPO}" SURU_PKI_DIR="${TMP}/nowhere" certs_check_ca) 2>&1)"; RC=$?
assert_eq "certs_check_ca dies when SURU_PKI_DIR holds no CA" "1" "${RC}"

OUT="$( (unset SURU_PKI_DIR; REPO_ROOT="${EMPTY_REPO}" certs_check_ca) 2>&1)"; RC=$?
assert_eq "unset SURU_PKI_DIR falls back to the repo-relative path (absent -> dies)" "1" "${RC}"

mkdir -p "${EMPTY_REPO}/tier4-operations/pki/certs"
cp "${CA_DIR}/root-ca.pem" "${CA_DIR}/root-ca-key.pem" "${EMPTY_REPO}/tier4-operations/pki/certs/"
OUT="$( (unset SURU_PKI_DIR; REPO_ROOT="${EMPTY_REPO}" certs_check_ca) 2>&1)"; RC=$?
assert_eq "unset SURU_PKI_DIR uses the repo-relative default when present" "0" "${RC}"

OUT="$(
  export REPO_ROOT="${TMP}/no-repo" TIER1_DIR="${TMP}/tier1" DRY_RUN=false SURU_PKI_DIR="${CA_DIR}"
  unset SURU_PKI_PREISSUED TIER1_CERTS_DIR
  certs_generate_client "${NAME}" 2>&1
)"; RC=$?
assert_eq "certs_generate_client signs with the CA from SURU_PKI_DIR" "0" "${RC}"
if [ -f "${TMP}/tier1/certs/${NAME}.pem" ] \
   && openssl verify -CAfile "${CA_DIR}/root-ca.pem" "${TMP}/tier1/certs/${NAME}.pem" > /dev/null 2>&1; then
  _pass "client cert verifies against the SURU_PKI_DIR CA"
else
  _fail "client cert verifies against the SURU_PKI_DIR CA (${OUT})"
fi
CERT_TEXT="$(openssl x509 -in "${TMP}/tier1/certs/${NAME}.pem" -noout -text 2> /dev/null || true)"
if grep -q 'Subject Key Identifier' <<< "${CERT_TEXT}" && grep -q 'Authority Key Identifier' <<< "${CERT_TEXT}"; then
  _pass "the issued client cert carries SKI and AKI"
else
  _fail "the issued client cert carries SKI and AKI"
fi

echo "== Makefile: SURU_PKI_DIR"
GIT_BIN="$(command -v git || true)"
if [ -z "${GIT_BIN}" ]; then
  echo "SKIP: git not available (the Makefile resolves REPO_ROOT through it)"
else
  REPO_TOP="$("${GIT_BIN}" -C "${SRC_ROOT}" rev-parse --show-toplevel 2> /dev/null)"
  # the .env include is Make-parse-time; point it at an absent file
  export ENV_FILE="${TMP}/absent.env"
  # _mk_print VAR [env...]: prints the Makefile's value of VAR
  _mk_print() {
    local var="$1"; shift
    printf 'print-%%:\n\t@echo $($*)\n' > "${TMP}/print.mk"
    env "$@" make -s -C "${SRC_ROOT}/tier1-perimeter" -f Makefile -f "${TMP}/print.mk" "print-${var}" 2>&1
  }

  got="$(_mk_print SURU_PKI_DIR -u SURU_PKI_DIR)"
  assert_eq "SURU_PKI_DIR defaults under REPO_ROOT" "${REPO_TOP}/tier4-operations/pki/certs" "${got}"

  got="$(_mk_print SURU_PKI_DIR SURU_PKI_DIR="${CA_DIR}")"
  assert_eq "an explicit SURU_PKI_DIR wins" "${CA_DIR}" "${got}"

  # SURU_PKI_DIR is exported to child processes (deploy.sh, gen-certs.sh)
  printf 'show-env:\n\t@echo "$$SURU_PKI_DIR"\n' > "${TMP}/env.mk"
  got="$(env -u SURU_PKI_DIR make -s -C "${SRC_ROOT}/tier1-perimeter" -f Makefile -f "${TMP}/env.mk" show-env 2>&1)"
  assert_eq "SURU_PKI_DIR is exported to recipes" "${REPO_TOP}/tier4-operations/pki/certs" "${got}"
fi

echo "== static: the driver reads the Root CA only through SURU_PKI_DIR"
CA_PATH_RE='REPO_ROOT\}?/tier4-operations/pki/certs'
all_sites="$(grep -rnE "${CA_PATH_RE}" "${SRC_ROOT}/tier1-perimeter/scripts" --include='*.sh' \
  | grep -v '/tests/' | grep -vE ':[0-9]+:[[:space:]]*#' || true)"
bare="$(printf '%s\n' "${all_sites}" | grep -v 'SURU_PKI_DIR:-' || true)"
n_sites="$(printf '%s\n' "${all_sites}" | grep -c 'SURU_PKI_DIR:-' || true)"
assert_eq "no Tier 1 script reads the CA path without SURU_PKI_DIR" "" "${bare}"
if [ "${n_sites}" -ge 7 ]; then _pass "the CA path pattern finds the guarded reader sites (${n_sites})"; else _fail "the CA path pattern finds the guarded reader sites (got ${n_sites})"; fi

test_summary
