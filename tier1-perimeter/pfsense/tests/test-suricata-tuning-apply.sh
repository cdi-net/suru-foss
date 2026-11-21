#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — behavioural tests for pfsense/suricata-tuning-apply.php
#
# The applier sets the detect profile, the memcaps and the app-layer parsers on
# every Suricata interface in installedpackages/suricata/rule[]. This suite never
# touches a real pfSense: it runs the shipped applier with an include_path whose
# config.inc / config.lib.inc are stubs backed by a JSON fixture (the rule
# array). config_set_path() edits it in memory and write_config() persists it
# and counts the call. The Suricata package include is absent on a dev host, so
# no resync or restart runs.
#
# Scenarios: an unset bittorrent_parser is set to yes on every interface and
# counts as a change (the driver's restart tracker sees no no-change sentinel);
# an explicit "no" is set to yes; a re-run with everything at target prints the
# no-change sentinel and writes nothing; without --app-layer-parsers the key is
# never touched; an unknown parser name is rejected with exit 1 and nothing
# written; a parser change alone (profile and memcaps at target) still writes,
# and the config-history description names the parsers; with --ifaces only the
# scoped interface's parser is turned on (a copy of the applier runs next to a
# stub suru-iface-resolve.php, so the include its __DIR__ names is the stub).
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
APPLIER="${APPLIER:-${SCRIPT_DIR}/../suricata-tuning-apply.php}"

if ! command -v php > /dev/null 2>&1; then
  echo "SKIP: php not available — cannot exercise suricata-tuning-apply.php."
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
  test_summary() { echo; echo "[test-suricata-tuning-apply] ${_T_PASS} passed, ${_T_FAIL} failed"; [[ ${_T_FAIL} -eq 0 ]]; }
fi

ROOT="$(mktemp -d)"
trap 'rm -rf -- "${ROOT}"' EXIT

# --- stubs -----------------------------------------------------------------
STUB="${ROOT}/inc"
mkdir -p "${STUB}"
cat > "${STUB}/config.inc" <<'PHPEOF'
<?php
// Test stub: the rule array lives in the JSON file named by SURU_TEST_CFG.
$GLOBALS['suru_cfg'] = json_decode(file_get_contents(getenv('SURU_TEST_CFG')), true);
function config_get_path($path, $default = null) {
    $node = $GLOBALS['suru_cfg'];
    foreach (explode('/', $path) as $k) {
        if (!is_array($node) || !array_key_exists($k, $node)) { return $default; }
        $node = $node[$k];
    }
    return $node;
}
function config_set_path($path, $value) {
    $node = &$GLOBALS['suru_cfg'];
    foreach (explode('/', $path) as $k) {
        if (!isset($node[$k]) || !is_array($node[$k])) { $node[$k] = $node[$k] ?? []; }
        $node = &$node[$k];
    }
    $node = $value;
}
function write_config($desc) {
    file_put_contents(getenv('SURU_TEST_CFG'), json_encode($GLOBALS['suru_cfg']));
    file_put_contents(getenv('SURU_TEST_WRITES'), $desc . "\n", FILE_APPEND);
}
PHPEOF
printf '<?php\n' > "${STUB}/config.lib.inc"

CFG="${ROOT}/cfg.json"
WRITES="${ROOT}/writes.log"
OUT="${ROOT}/out.txt"
RC=0

# Two interfaces at the memcap/profile targets used below; bittorrent_parser
# per scenario ("" = key absent).
_fixture() {  # parser value for iface 0, parser value for iface 1
  php -r '
    $mk = function ($iface, $p) {
      $r = ["interface" => $iface, "detect_eng_profile" => "medium",
            "stream_memcap" => "134217728", "reassembly_memcap" => "268435456",
            "frag_memcap" => "67108864"];
      if ($p !== "") { $r["bittorrent_parser"] = $p; }
      return $r;
    };
    echo json_encode(["installedpackages" => ["suricata" => ["rule" => [
      $mk("lan", $argv[1]), $mk("opt1", $argv[2])]]]]);
  ' -- "$1" "$2" > "${CFG}"
  : > "${WRITES}"
}

TARGETS=(--profile=medium --stream-memcap=128mb --reassembly-memcap=256mb --defrag-memcap=64mb)

run() {
  RC=0
  SURU_TEST_CFG="${CFG}" SURU_TEST_WRITES="${WRITES}" \
    php -d include_path="${STUB}" "${APPLIER}" "$@" > "${OUT}" 2>&1 || RC=$?
}

_parser_of() {  # index
  php -r '$c = json_decode(file_get_contents($argv[1]), true);
          echo $c["installedpackages"]["suricata"]["rule"][(int)$argv[2]]["bittorrent_parser"] ?? "ABSENT";' -- "${CFG}" "$1"
}

_writes() { grep -c . "${WRITES}" || true; }

echo "--- unset parser key is turned on ---"
_fixture "" ""
run "${TARGETS[@]}" --app-layer-parsers=bittorrent-dht
[[ ${RC} -eq 0 ]] && _pass "exit 0" || { _fail "exit ${RC}"; cat "${OUT}"; }
[[ "$(_parser_of 0)" == "yes" && "$(_parser_of 1)" == "yes" ]] \
  && _pass "bittorrent_parser=yes on both interfaces" || _fail "parser values: $(_parser_of 0) $(_parser_of 1)"
grep -q 'iface=lan: bittorrent_parser (bittorrent-dht) unset -> yes' "${OUT}" \
  && _pass "change line names key, parser and old value" || { _fail "change line missing"; cat "${OUT}"; }
[[ "$(_writes)" == "1" ]] && _pass "one write_config" || _fail "write_config calls: $(_writes)"
grep -q 'config.xml updated: 2 value(s)' "${OUT}" && _pass "2 values counted" || _fail "count line missing"
grep -qx 'SURU: set Suricata tuning (profile=medium; parsers=bittorrent-dht) on 2 value(s)' "${WRITES}" \
  && _pass "config-history description names the parsers" || { _fail "write_config description"; cat "${WRITES}"; }
grep -q 'No changes — all tuning values already at target' "${OUT}" \
  && _fail "no-change sentinel printed on a change (restart tracker would miss it)" \
  || _pass "no-change sentinel absent, so the driver's restart tracker sees a change"

echo "--- explicit no is turned on ---"
_fixture "no" "yes"
run "${TARGETS[@]}" --app-layer-parsers=bittorrent-dht
[[ ${RC} -eq 0 && "$(_parser_of 0)" == "yes" ]] && _pass "no -> yes" || _fail "rc=${RC} parser=$(_parser_of 0)"
grep -q 'iface=opt1: bittorrent_parser' "${OUT}" \
  && _fail "interface already at yes was touched" || _pass "interface already at yes untouched"
grep -q 'config.xml updated: 1 value(s)' "${OUT}" && _pass "1 value counted" || _fail "count line missing"

echo "--- re-run at target is a no-op ---"
_fixture "yes" "yes"
run "${TARGETS[@]}" --app-layer-parsers=bittorrent-dht
[[ ${RC} -eq 0 ]] && _pass "exit 0" || _fail "exit ${RC}"
grep -q 'No changes — all tuning values already at target' "${OUT}" \
  && _pass "no-change sentinel printed" || { _fail "sentinel missing"; cat "${OUT}"; }
[[ "$(_writes)" == "0" ]] && _pass "no write_config" || _fail "write_config calls: $(_writes)"

echo "--- without the option the key is never touched ---"
_fixture "" "no"
run "${TARGETS[@]}"
[[ ${RC} -eq 0 && "$(_parser_of 0)" == "ABSENT" && "$(_parser_of 1)" == "no" ]] \
  && _pass "keys unchanged" || _fail "rc=${RC} parsers=$(_parser_of 0) $(_parser_of 1)"
[[ "$(_writes)" == "0" ]] && _pass "no write_config" || _fail "write_config calls: $(_writes)"

echo "--- unknown parser name is rejected ---"
_fixture "" ""
run "${TARGETS[@]}" --app-layer-parsers=bittorrent-dht,nosuchproto
[[ ${RC} -eq 1 ]] && _pass "exit 1" || _fail "exit ${RC}"
grep -q 'unknown --app-layer-parsers name: nosuchproto (allowed: bittorrent-dht)' "${OUT}" \
  && _pass "error names the value and the allowed set" || { _fail "error text"; cat "${OUT}"; }
[[ "$(_writes)" == "0" && "$(_parser_of 0)" == "ABSENT" ]] && _pass "nothing written" || _fail "written"

echo "--- malformed option value is rejected ---"
run "${TARGETS[@]}" '--app-layer-parsers=bittorrent-dht;id'
[[ ${RC} -eq 1 ]] && _pass "exit 1 (unknown arg)" || _fail "exit ${RC}"
[[ "$(_writes)" == "0" ]] && _pass "nothing written" || _fail "written"

echo "--- --ifaces scopes the parser to the resolved interface ---"
# The applier loads suru-iface-resolve.php from its own directory; run a copy
# beside a stub that maps the physical NIC igb1 to the carrier alias lan.
SCOPED="${ROOT}/scoped"
mkdir -p "${SCOPED}"
cp "${APPLIER}" "${SCOPED}/suricata-tuning-apply.php"
cat > "${SCOPED}/suru-iface-resolve.php" <<'PHPEOF'
<?php
// Test stub: physical NIC -> carrier alias, without pfSense interface lookups.
function suru_resolve_physical_ifaces(array $physical_list): array {
    $map = ['igb1' => 'lan'];
    $out = [];
    foreach ($physical_list as $nic) { $out[$nic] = $map[$nic] ?? ''; }
    return $out;
}
PHPEOF
_fixture "" ""
RC=0
SURU_TEST_CFG="${CFG}" SURU_TEST_WRITES="${WRITES}" \
  php -d include_path="${STUB}" "${SCOPED}/suricata-tuning-apply.php" \
  "${TARGETS[@]}" --app-layer-parsers=bittorrent-dht --ifaces=igb1 > "${OUT}" 2>&1 || RC=$?
[[ ${RC} -eq 0 ]] && _pass "exit 0" || { _fail "exit ${RC}"; cat "${OUT}"; }
[[ "$(_parser_of 0)" == "yes" && "$(_parser_of 1)" == "ABSENT" ]] \
  && _pass "parser on for the scoped interface only" || _fail "parser values: $(_parser_of 0) $(_parser_of 1)"
grep -q 'iface=opt1:' "${OUT}" && _fail "unscoped interface was visited" || _pass "unscoped interface not visited"
grep -q 'config.xml updated: 1 value(s)' "${OUT}" && _pass "1 value counted" || { _fail "count line missing"; cat "${OUT}"; }

test_summary
