#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — lib/certs.sh
# mTLS client certificate generation signed by the SURU Root CA.
# The Root CA is managed exclusively by tier4-operations/pki/scripts/generate-certs.sh
# and lives at tier4-operations/pki/certs/root-ca.pem. Every reader resolves that
# directory through SURU_PKI_DIR (default ${REPO_ROOT}/tier4-operations/pki/certs),
# so a tree without git, or a CA kept outside the repository, needs only the
# variable.
# =============================================================================

# certs_check_ca
# Validates that the SURU Root CA exists and is not near expiry.
#
# SURU_PKI_PREISSUED=true (default false): the client pair was issued on the PKI
# host and staged; only the public Root CA is required here and the CA key is
# never read.
certs_check_ca() {
  local ca_cert="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca.pem"
  local ca_key="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca-key.pem"

  if [[ ! -f "$ca_cert" ]]; then
    # Key present, cert absent: generate-certs.sh would rotate the CA — restore instead.
    if [[ -f "$ca_key" ]]; then
      log_die "SURU Root CA certificate not found: ${ca_cert}, but the CA key exists.\nDo NOT run generate-certs.sh (it rotates the Root CA). Restore root-ca.pem from your backup."
    fi
    log_die "SURU Root CA not found: ${ca_cert}\nRun: tier4-operations/pki/scripts/generate-certs.sh (only on a host with no Root CA yet)"
  fi
  if [[ "${SURU_PKI_PREISSUED:-false}" != "true" ]]; then
    [[ -f "$ca_key"  ]] || log_die "SURU Root CA key not found: ${ca_key}\nDo NOT run generate-certs.sh (it rotates the Root CA). Restore root-ca-key.pem from your secure backup."
  fi

  # Warn if CA expires within 60 days
  local expiry expiry_epoch now_epoch days_left
  expiry=$(openssl x509 -in "$ca_cert" -noout -enddate 2>/dev/null | cut -d= -f2)
  expiry_epoch=$(date -d "${expiry}" +%s 2>/dev/null || \
                 date -j -f "%b %d %T %Y %Z" "${expiry}" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  if [[ $days_left -lt 60 ]]; then
    log_warn "SURU Root CA expires in ${days_left} days (${expiry}) — consider renewal"
  else
    log_debug "Root CA valid for ${days_left} days"
  fi

  log_info "SURU Root CA: OK (${ca_cert})"
}

# _certs_check_preissued CERT_NAME CERT_DIR
# Pre-issued mode body: verify only, never sign.
_certs_check_preissued() {
  local name="$1" cert_dir="$2"
  local ca_cert="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca.pem"
  local client_cert="${cert_dir}/${name}.pem"
  local client_key="${cert_dir}/${name}-key.pem"
  local remedy="pre-issued client cert missing or invalid (${client_cert}) — issue it on the PKI host with: make -C tier1-perimeter gen-certs, then copy the pair to ${cert_dir}"

  certs_check_ca
  [[ -f "$client_cert" ]] || log_die "$remedy"
  openssl verify -CAfile "$ca_cert" "$client_cert" >/dev/null 2>&1 || log_die "$remedy"
  [[ -r "$client_key" ]] || log_die "pre-issued client key not readable (${client_key}) — ${remedy}"
  local cert_pub key_pub
  cert_pub="$(openssl x509 -in "$client_cert" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null)" || cert_pub=""
  key_pub="$(openssl pkey -in "$client_key" -passin pass: -pubout 2>/dev/null | openssl sha256 2>/dev/null)" || key_pub=""
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || log_die "pre-issued client key does not match ${client_cert} — ${remedy}"
  log_info "Pre-issued client cert verified: ${client_cert}"
}

# certs_generate_client CERT_NAME
# Generates a client cert+key pair in tier1-perimeter/certs/, signed by the
# SURU Root CA. Idempotent: skips if a valid cert already exists.
#
# With SURU_PKI_PREISSUED=true it never signs: it verifies the pair in
# TIER1_CERTS_DIR (default ${TIER1_DIR}/certs) against the Root CA and dies,
# naming the remedy, when the pair is absent or invalid.
#
# Args:
#   CERT_NAME  — base name without extension, e.g. tier1-pfsense-syslogng
certs_generate_client() {
  local name="$1"
  local cert_dir="${TIER1_DIR}/certs"
  if [[ "${SURU_PKI_PREISSUED:-false}" == "true" ]]; then
    _certs_check_preissued "$name" "${TIER1_CERTS_DIR:-${TIER1_DIR}/certs}"
    return 0
  fi
  local ca_cert="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca.pem"
  local ca_key="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca-key.pem"
  local ca_srl="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca.srl"
  local client_key="${cert_dir}/${name}-key.pem"
  local client_csr="${cert_dir}/${name}.csr"
  local client_cert="${cert_dir}/${name}.pem"
  local subj="/C=RO/O=SURU Platform/OU=Tier1/CN=suru-${name}"

  certs_check_ca

  # Idempotency check — skip if cert exists and verifies against CA
  if [[ -f "$client_cert" ]]; then
    if openssl verify -CAfile "$ca_cert" "$client_cert" >/dev/null 2>&1; then
      log_info "Client cert already valid, skipping generation: ${client_cert}"
      return 0
    else
      log_warn "Existing cert ${client_cert} failed verification against ${ca_cert} — regenerating"
    fi
  fi

  run mkdir -p "$cert_dir"

  log_info "Generating EC P-256 key: ${client_key}"
  run openssl ecparam -name prime256v1 -genkey -noout -out "$client_key"

  log_info "Generating CSR: ${client_csr}"
  run openssl req -new -sha256 \
      -subj  "$subj" \
      -key   "$client_key" \
      -out   "$client_csr"

  log_info "Signing with SURU Root CA ..."
  # The extension file carries the key identifiers, so the certificate is the
  # same on every openssl: 3.0 adds no extension to one signed without a file
  # (X.509 v1, no SKI/AKI), 3.2 and later add SKI and AKI. No keyUsage or
  # extendedKeyUsage, no SAN (a client certificate).
  local client_ext
  client_ext="$(mktemp)"
  printf 'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' > "$client_ext"
  if [[ -f "$ca_srl" ]]; then
    run openssl x509 -req -sha256 -days 365 \
        -CA "$ca_cert" -CAkey "$ca_key" -CAserial "$ca_srl" \
        -extfile "$client_ext" \
        -in "$client_csr" -out "$client_cert"
  else
    run openssl x509 -req -sha256 -days 365 \
        -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
        -extfile "$client_ext" \
        -in "$client_csr" -out "$client_cert"
  fi
  rm -f "$client_ext"

  run chmod 600 "$client_key"
  # CSR is single-use once signed — clean it up explicitly rather than via a
  # `trap ... RETURN` (a prior version of this function used one: it fires on
  # every SUBSEQUENT function return in the whole script, not just this one,
  # so once this function's own early-return path fired it once, it kept
  # firing on unrelated later function returns where client_csr was long out
  # of scope, throwing "client_csr: unbound variable" under set -u).
  run rm -f "$client_csr"
  log_info "Client cert generated: ${client_cert}"
}
