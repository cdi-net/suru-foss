#!/usr/bin/env bash
# SURU Platform — Render pipeline integration test
# Covers both dispatcher scopes:
#   render.sh --scope tier1 (default, existing perimeter render — unchanged)
#   render.sh --scope tier3 (new SIEM Security Analytics render)
# Usage: ./test-render.sh [--verbose]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.."; pwd)"
RENDER="${SCRIPT_DIR}/../render.sh"
LIB_DIR="${SCRIPT_DIR}/../lib"

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0; FAIL=0
# Use $((var+1)) instead of ((var++)) so the helpers always return 0:
# ((PASS++)) is post-increment and evaluates to the OLD value, which
# means it returns non-zero when PASS=0. That makes `cond && _pass || _fail`
# fire BOTH branches on the first PASS.
_pass() { echo "  [PASS] $*"; PASS=$((PASS+1)); }
_fail() { echo "  [FAIL] $*" >&2; FAIL=$((FAIL+1)); }

_verbose_flag=()
$VERBOSE && _verbose_flag=(--verbose)

# Test 1: render.sh exists and is executable
echo "[test-render] Test 1: render.sh executable"
[[ -x "${RENDER}" ]] && _pass "render.sh is executable" || _fail "render.sh missing or not executable"

# Test 2: dry-run completes without error for all platforms (no --scope flag —
# exercises the default scope, which MUST remain tier1 for backward compat)
echo "[test-render] Test 2: dry-run all platforms (default scope)"
if bash "${RENDER}" --dry-run --platform all ${_verbose_flag[@]+"${_verbose_flag[@]}"} 2>&1; then
  _pass "dry-run completed"
else
  _fail "dry-run failed"
fi

# Test 2b: default scope output is identical to explicit --scope tier1 output
# (the BACKWARD COMPATIBILITY contract render.sh's header comment asserts).
echo "[test-render] Test 2b: default scope == explicit --scope tier1"
default_out="$(bash "${RENDER}" --dry-run --platform all 2>&1)"
explicit_out="$(bash "${RENDER}" --dry-run --platform all --scope tier1 2>&1)"
[[ "${default_out}" == "${explicit_out}" ]] \
  && _pass "default scope output matches --scope tier1 output" \
  || _fail "default scope output DIFFERS from --scope tier1 output (backward-compat break)"

# Test 3: template files exist
# Note: pfblockerng.xml.tpl was removed — render-pfblockerng.sh emits a
# PHP importer directly, no XML side file. DNSBL feed YAML is the only
# input now (covered by Test 4).
echo "[test-render] Test 3: template files present"
for f in \
  "${REPO_ROOT}/tier1-perimeter/templates/suricata/suricata.yaml.tpl" \
  "${REPO_ROOT}/tier1-perimeter/templates/zeek/local.zeek.tpl"
do
  [[ -f "${f}" ]] && _pass "template exists: $(basename "${f}")" || _fail "missing template: ${f}"
done

# Test 4: T2 data files exist
echo "[test-render] Test 4: T2 data files present"
for f in \
  "${REPO_ROOT}/tier2-telemetry/suricata/rule-selection/enable.conf" \
  "${REPO_ROOT}/tier2-telemetry/pfblockerng/categories/dnsbl-categories.yml" \
  "${REPO_ROOT}/tier2-telemetry/zeek/scripts/soho-telemetry.zeek"
do
  [[ -f "${f}" ]] && _pass "T2 data: $(basename "${f}")" || _fail "missing T2 data: ${f}"
done

# Test 5: _php_esc escaping correctness (SEC-001 regression guard)
# The pfBlockerNG importer emits PHP that runs as root on pfSense; field values
# are embedded in PHP single-quoted literals. A prior fix used ${v//\'/\\\'} which
# produces \\' (string-closing in PHP) and reopened the injection. This test pins
# the correct escaping so that regression cannot ship again.
echo "[test-render] Test 5: _php_esc PHP single-quote escaping (SEC-001)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/../lib/render-pfblockerng.sh"
# ' -> \'  (backslash + quote)
[[ "$(_php_esc "foo'bar")" == $'foo\\\'bar' ]] \
  && _pass "single-quote escaped to \\'" || _fail "single-quote NOT escaped: $(_php_esc "foo'bar")"
# \ -> \\  (doubled backslash)
[[ "$(_php_esc 'foo\bar')" == $'foo\\\\bar' ]] \
  && _pass "backslash escaped to \\\\" || _fail "backslash NOT escaped: $(_php_esc 'foo\bar')"
# trailing backslash must not dangle (would escape the closing quote in PHP)
[[ "$(_php_esc 'foo\')" == $'foo\\\\' ]] \
  && _pass "trailing backslash doubled" || _fail "trailing backslash NOT doubled: $(_php_esc 'foo\')"
# injection payload: every ' must be backslash-escaped (no bare quote can close the string)
sec001_payload="$(_php_esc "'];system('id');#")"
[[ "$sec001_payload" != *"'"* || "$sec001_payload" == *"\\'"* ]] \
  && [[ "$sec001_payload" == $'\\\'];system(\\\'id\\\');#' ]] \
  && _pass "injection payload neutralised" || _fail "injection payload NOT neutralised: $sec001_payload"

# Test 5d: render_zeek SURU_AUTHORIZED_AD_DOMAINS validation (regression).
# The authorized-domains value is spliced into an EXECUTED Zeek string literal;
# render-zeek.sh gates every entry on a strict RFC 1035-ish domain shape. Pins all
# three branches: valid list → quoted splice; injection/invalid shape → render
# FAILS (no artifact with the payload); unset → marker survives for the
# apply-time substitution. Same convention as the 5c injection regression.
echo "[test-render] Test 5d: render_zeek authorized-domains validation"
# shellcheck source=../lib/render-zeek.sh
source "${SCRIPT_DIR}/../lib/render-zeek.sh"
fd_dir="$(mktemp -d)"
mkdir -p "${fd_dir}/t1/templates/zeek" "${fd_dir}/t2/zeek/scripts"
printf '__ZEEK_SCRIPTS__ __ZEEK_IFACE__ __ZEEK_LOG_MDNS__\n' > "${fd_dir}/t1/templates/zeek/local.zeek.tpl"
printf 'const authorized_domains: set[string] = { "@@SURU_AUTHORIZED_AD_DOMAINS@@" } &redef;\n' \
  > "${fd_dir}/t2/zeek/scripts/suru-foreign-domain.zeek"
fd_out="${fd_dir}/rendered/zeek/scripts/suru-foreign-domain.zeek"

# Branch 1: valid mixed-case/spaced list → lowercased quoted entries, no marker
mkdir -p "${fd_dir}/rendered/zeek"
if (SURU_AUTHORIZED_AD_DOMAINS=" Corp.Example , branch.example " \
    render_zeek pfsense "${fd_dir}/t1" "${fd_dir}/t2" "${fd_dir}/rendered" false > /dev/null 2>&1) \
   && grep -qF '{ "corp.example", "branch.example" }' "${fd_out}" \
   && ! grep -qF 'SURU_AUTHORIZED_AD_DOMAINS@@' "${fd_out}"; then
  _pass "valid list spliced (lowercased, no marker residue)"
else
  _fail "valid-list splice broken (expected quoted lowercased entries)"
fi

# Branch 2: quote-breakout payload → render must FAIL and no artifact may carry it
if (SURU_AUTHORIZED_AD_DOMAINS='corp.example,evil"; @load /x' \
    render_zeek pfsense "${fd_dir}/t1" "${fd_dir}/t2" "${fd_dir}/rendered" false > /dev/null 2>&1); then
  _fail "injection payload accepted — render should exit non-zero"
else
  if grep -rqF '@load /x' "${fd_dir}/rendered" 2> /dev/null; then
    _fail "bare-quote breakout reached a rendered artifact"
  else
    _pass "injection payload fails the render; no breakout in rendered output"
  fi
fi

# Branch 3: unset → marker survives for zeek-scripts-apply.php substitution
if (env -u SURU_AUTHORIZED_AD_DOMAINS \
    bash -c "source '${SCRIPT_DIR}/../lib/render-zeek.sh'; render_zeek pfsense '${fd_dir}/t1' '${fd_dir}/t2' '${fd_dir}/rendered' false" > /dev/null 2>&1) \
   && grep -qF '{ "@@SURU_AUTHORIZED_AD_DOMAINS@@" }' "${fd_out}"; then
  _pass "unset env leaves the marker intact for apply-time substitution"
else
  _fail "unset-env fallback broken — marker must survive the render"
fi
# Branch 4: set-but-all-empty (e.g. ",") is an operator mistake → render fails
if (SURU_AUTHORIZED_AD_DOMAINS=' , ' \
    render_zeek pfsense "${fd_dir}/t1" "${fd_dir}/t2" "${fd_dir}/rendered" false > /dev/null 2>&1); then
  _fail "all-empty SURU_AUTHORIZED_AD_DOMAINS accepted — must fail loudly, not fall through"
else
  _pass "set-but-no-valid-entries fails the render loudly"
fi
rm -rf "${fd_dir}"

# Test 6: render.sh --scope tier3 --dry-run completes without error
echo "[test-render] Test 6: dry-run --scope tier3"
if bash "${RENDER}" --dry-run --scope tier3 ${_verbose_flag[@]+"${_verbose_flag[@]}"} 2>&1; then
  _pass "tier3 dry-run completed"
else
  _fail "tier3 dry-run failed"
fi

# Test 7: tier3 live (non-dry-run) render produces the expected output
# directory structure under a scratch copy of the repo tree, without
# touching the real tier3-core/config/opensearch/security-analytics/ path.
# Mirrors render_tier3's own mkdir layout (sigma/, detectors/,
# correlation-rules/, actions/).
echo "[test-render] Test 7: tier3 render output directory structure"
T3_SCRATCH="$(mktemp -d)"
trap '[[ -n "${T3_SCRATCH:-}" ]] && rm -rf "${T3_SCRATCH}"' EXIT

(
  set -euo pipefail
  # shellcheck disable=SC1091
  source "${LIB_DIR}/render-tier3.sh"
  _log()  { :; }
  _vlog() { :; }
  _warn() { :; }
  _die()  { echo "$*" >&2; exit 1; }
  _run_renderer() {
    local lib="$1"; shift
    # shellcheck disable=SC1090
    source "${lib}"
    local fn="$1"; shift
    "${fn}" "$@"
  }
  render_tier3 "${REPO_ROOT}/tier2-telemetry" "${T3_SCRATCH}" "${LIB_DIR}" "false"
)

t3_out="${T3_SCRATCH}/config/opensearch/security-analytics"
for d in sigma detectors correlation-rules actions; do
  [[ -d "${t3_out}/${d}" ]] && _pass "tier3 output dir exists: ${d}/" || _fail "missing tier3 output dir: ${d}/"
done
[[ -f "${t3_out}/sigma/manifest.json" ]] \
  && _pass "sigma manifest.json rendered" || _fail "sigma manifest.json missing"

# Test 8: *.stub.* files are correctly skipped — never rendered into tier3 output
echo "[test-render] Test 8: *.stub.* skip convention enforced"
if [[ -f "${t3_out}/detectors/execution-persistence.stub.json" ]]; then
  _fail "stub detector was rendered (must be skipped): execution-persistence.stub.json"
else
  _pass "stub detector correctly skipped: execution-persistence.stub.yml"
fi
if [[ -f "${t3_out}/correlation-rules/endpoint-execution-c2.stub.json" ]]; then
  _fail "stub correlation rule was rendered (must be skipped): endpoint-execution-c2.stub.json"
else
  _pass "stub correlation rule correctly skipped: endpoint-execution-c2.stub.yml"
fi

# Test 9: every rendered detector/correlation/action JSON is valid JSON and
# carries the pending-T0a schema_verified:false marker (no fabricated-as-
# confirmed schema per evidence-based-claims.md).
echo "[test-render] Test 9: rendered JSON validity + schema_verified:false marker"
rendered_json_count=0
for f in "${t3_out}"/detectors/*.json "${t3_out}"/correlation-rules/*.json "${t3_out}"/actions/*.json; do
  [[ -f "${f}" ]] || continue
  rendered_json_count=$((rendered_json_count + 1))
  if ! jq -e . "${f}" > /dev/null 2>&1; then
    _fail "invalid JSON: $(basename "${f}")"
    continue
  fi
  if jq -e '._render_meta.schema_verified == false' "${f}" > /dev/null 2>&1; then
    _pass "valid JSON + schema_verified:false marker: $(basename "${f}")"
  else
    _fail "missing/incorrect _render_meta.schema_verified marker: $(basename "${f}")"
  fi
done
[[ "${rendered_json_count}" -gt 0 ]] || _fail "no rendered JSON files found to validate"

echo ""
echo "[test-render] Results: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
