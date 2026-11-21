#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — test-secrets.sh
# Self-contained unit tests for lib/secrets.sh (no framework required).
# Run: bash tier1-perimeter/scripts/lib/tests/test-secrets.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../secrets.sh
source "${SCRIPT_DIR}/../secrets.sh"

REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
# shellcheck source=../../../../lib/bash/test-harness.sh
source "${REPO_ROOT}/lib/bash/test-harness.sh"

echo "[test-secrets] secret_charset_ok — accepts valid values"
for v in abc123 ABC123def 0123456789 a.b_c-d MAxMind_Key-1.2; do
  if secret_charset_ok "${v}"; then _pass "accepted: ${v}"; else _fail "rejected valid: ${v}"; fi
done

echo "[test-secrets] secret_charset_ok — rejects injection / empty values"
# Each of these must be rejected: empty, and every sed/URL/shell metacharacter.
reject_empty=""
if ! secret_charset_ok "${reject_empty}"; then _pass "rejected: <empty>"; else _fail "accepted empty"; fi
for v in \
  'a|b' 'a&b' 'a\b' 'a/b' 'a b' 'a;b' 'a$b' "a\`b" 'a(b)' 'a<b>' 'a"b' "a'b" 'a=b' 'a%b' \
  "$(printf 'a\nb')"; do
  if ! secret_charset_ok "${v}"; then _pass "rejected: $(printf '%q' "${v}")"; else _fail "ACCEPTED injection: $(printf '%q' "${v}")"; fi
done

echo "[test-secrets] secret_charset_ok — rejects non-ASCII (LC_ALL=C pinned, no locale range leak)"
# Run under a UTF-8 locale to prove the function's internal LC_ALL=C pin holds
# regardless of the caller's locale — accented/non-ASCII must NOT match [A-Za-z].
for v in 'café' 'naïve' 'Zürich' 'αβγ' 'a·b'; do
  if ! LC_ALL=en_US.UTF-8 secret_charset_ok "${v}"; then _pass "rejected non-ASCII: ${v}"; else _fail "ACCEPTED non-ASCII: ${v}"; fi
done

echo "[test-secrets] secret_charset_ok — honours a custom (stricter) regex"
if secret_charset_ok "abc123" '^[A-Za-z0-9]+$'; then _pass "custom regex accepts alnum"; else _fail "custom regex rejected alnum"; fi
if ! secret_charset_ok "a.b" '^[A-Za-z0-9]+$'; then _pass "custom regex rejects dot"; else _fail "custom regex accepted dot"; fi

echo "[test-secrets] secret_mktemp — creates a 0600 temp and is unique"
t1="$(secret_mktemp)"; t2="$(secret_mktemp)"
if [[ -f "${t1}" && -f "${t2}" ]]; then _pass "both temp files exist"; else _fail "temp file(s) missing"; fi
if [[ "${t1}" != "${t2}" ]]; then _pass "temp paths are unique"; else _fail "temp paths collided"; fi
# Mode check — GNU stat -c%a first, BSD stat -f%Lp fallback. GNU MUST come
# first: on GNU, `stat -f '%Lp' FILE` does not fail cleanly (-f means
# --file-system, '%Lp' becomes a filename) — it prints a default-format
# filesystem block on stdout, polluting the capture (caught by CI on
# ubuntu-24.04). On macOS, `stat -c` errors with no stdout, so the chain
# falls through to the BSD form correctly.
mode="$(stat -c '%a' "${t1}" 2>/dev/null || stat -f '%Lp' "${t1}" 2>/dev/null || echo '?')"
if [[ "${mode}" == "600" ]]; then _pass "temp mode is 0600"; else _fail "temp mode is ${mode}, expected 600"; fi
# A value written to it round-trips (proves it is a usable, writable file)
printf 'secret-xyz' > "${t1}"
if [[ "$(cat "${t1}")" == "secret-xyz" ]]; then _pass "temp is writable/readable"; else _fail "temp round-trip failed"; fi
rm -f -- "${t1}" "${t2}"

test_summary
