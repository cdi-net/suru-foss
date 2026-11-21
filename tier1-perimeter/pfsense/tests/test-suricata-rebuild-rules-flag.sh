#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — the $rebuild_rules invariant of the Suricata appliers
#
# The pfSense Suricata package rebuilds an instance's enforcing
# rules/suricata.rules in suricata_prepare_rule_files(), which returns at once
# unless the package global $rebuild_rules is TRUE ("if there is no reason to
# rebuild the rules, exit to save time", /usr/local/pkg/suricata/suricata.inc).
# sync_suricata_package_config() does not set it; the GUI pages, the rule-update
# cron and the boot script do. An applier that changes what the engine must load
# and then calls sync_suricata_package_config() without forcing the flag writes
# config.xml and the yaml, and the engine keeps the previous ruleset until the
# nightly rule update or a reboot (observed live: new categories and removed
# engine-event files, a clean restart, the old set still loaded).
#
# This suite reads the shipped appliers (no php, no router) and asserts, for
# every applier that changes rule selection or SID modifications and then syncs:
#   - `$GLOBALS['rebuild_rules'] = true;` appears before the first
#     `sync_suricata_package_config();` call, and
#   - `$GLOBALS['rebuild_rules'] = false;` appears after it,
# and that the two yaml-only appliers (tuning, clear-interfaces) do not force a
# rebuild they do not need. A new applier that syncs is added to one of the two
# lists below, deliberately.
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PF_DIR="${SCRIPT_DIR}/.."

if [[ -f "${REPO_ROOT}/lib/bash/test-harness.sh" ]]; then
  # shellcheck source=../../../lib/bash/test-harness.sh
  source "${REPO_ROOT}/lib/bash/test-harness.sh"
else
  _T_PASS=0; _T_FAIL=0
  _pass() { _T_PASS=$((_T_PASS + 1)); echo "  [PASS] $*"; }
  _fail() { _T_FAIL=$((_T_FAIL + 1)); echo "  [FAIL] $*" >&2; }
  test_summary() { echo; echo "[test-suricata-rebuild-rules-flag] ${_T_PASS} passed, ${_T_FAIL} failed"; [[ ${_T_FAIL} -eq 0 ]]; }
fi

# Appliers whose change reaches the engine only through a rules rebuild.
MUST_REBUILD=(
  suricata-rules-apply.php
  suricata-drop-policy-apply.php
  suricata-safety-revert.php
)
# Appliers that change the yaml only; a rebuild there would be wasted time on
# every deploy.
YAML_ONLY=(
  suricata-tuning-apply.php
  suricata-clear-interfaces.php
)

SYNC_RE='^[[:space:]]*sync_suricata_package_config\(\);'
SET_RE="^[[:space:]]*\\\$GLOBALS\\['rebuild_rules'\\] = true;"
RESET_RE="^[[:space:]]*\\\$GLOBALS\\['rebuild_rules'\\] = false;"

_first_line() {  # file regex -> line number of the first match, or 0
  local n
  n="$(grep -n -E "$2" "$1" | head -1 | cut -d: -f1 || true)"
  echo "${n:-0}"
}
_last_line() {  # file regex -> line number of the last match, or 0
  local n
  n="$(grep -n -E "$2" "$1" | tail -1 | cut -d: -f1 || true)"
  echo "${n:-0}"
}

echo "--- appliers that must force the rebuild ---"
for f in "${MUST_REBUILD[@]}"; do
  p="${PF_DIR}/${f}"
  [[ -f "${p}" ]] || { _fail "${f}: applier not found"; continue; }
  sync_at="$(_first_line "${p}" "${SYNC_RE}")"
  set_at="$(_first_line "${p}" "${SET_RE}")"
  reset_at="$(_last_line "${p}" "${RESET_RE}")"
  if [[ "${sync_at}" -eq 0 ]]; then
    _fail "${f}: no sync_suricata_package_config() call — remove it from MUST_REBUILD if that is intended"
    continue
  fi
  if [[ "${set_at}" -gt 0 && "${set_at}" -lt "${sync_at}" ]]; then
    _pass "${f}: rebuild_rules=true (line ${set_at}) before sync (line ${sync_at})"
  else
    _fail "${f}: rebuild_rules=true missing before sync (set=${set_at}, sync=${sync_at}) — the engine would keep the previous ruleset"
  fi
  if [[ "${reset_at}" -gt "${sync_at}" ]]; then
    _pass "${f}: rebuild_rules=false (line ${reset_at}) after sync"
  else
    _fail "${f}: rebuild_rules not reset after sync (reset=${reset_at}, sync=${sync_at})"
  fi
done

echo "--- yaml-only appliers do not force a rebuild ---"
for f in "${YAML_ONLY[@]}"; do
  p="${PF_DIR}/${f}"
  [[ -f "${p}" ]] || { _fail "${f}: applier not found"; continue; }
  if grep -q -E "${SET_RE}" "${p}"; then
    _fail "${f}: forces rebuild_rules — move it to MUST_REBUILD if its change needs the rebuild"
  else
    _pass "${f}: no forced rebuild"
  fi
done

echo "--- every applier that syncs is classified ---"
while IFS= read -r p; do
  f="$(basename "${p}")"
  listed=false
  for k in "${MUST_REBUILD[@]}" "${YAML_ONLY[@]}"; do
    [[ "${k}" == "${f}" ]] && listed=true
  done
  if [[ "${listed}" == true ]]; then
    _pass "${f}: classified"
  else
    _fail "${f}: calls sync_suricata_package_config() but is in neither list — decide whether its change needs the rules rebuild"
  fi
done < <(grep -l -E "${SYNC_RE}" "${PF_DIR}"/*.php)

echo "--- the one-shot --rebuild knob is wired end to end ---"
APPLIER="${PF_DIR}/suricata-rules-apply.php"
DRIVER="${REPO_ROOT}/tier1-perimeter/scripts/platforms/pfsense.sh"
ENV_EXAMPLE="${REPO_ROOT}/tier1-perimeter/.env.example"
grep -q -E "^\s*\} elseif \(\\\$arg === '--rebuild'\) \{" "${APPLIER}" \
  && _pass "applier parses --rebuild" || _fail "applier does not parse --rebuild"
grep -q -E '^if \(!\$needs_sync && \$force_rebuild\) \{' "${APPLIER}" \
  && _pass "applier turns --rebuild into a sync when nothing changed" || _fail "applier: --rebuild does not force the sync"
sync_at="$(_first_line "${APPLIER}" "${SYNC_RE}")"
force_at="$(_first_line "${APPLIER}" '^if \(!\$needs_sync && \$force_rebuild\) \{')"
[[ "${force_at}" -gt 0 && "${force_at}" -lt "${sync_at}" ]] \
  && _pass "the forced sync (line ${force_at}) precedes the sync call (line ${sync_at})" || _fail "forced-sync block out of order (force=${force_at}, sync=${sync_at})"
grep -q 'SURU_SURICATA_REBUILD:-false' "${DRIVER}" \
  && _pass "driver reads SURU_SURICATA_REBUILD (default false)" || _fail "driver does not read SURU_SURICATA_REBUILD"
# The knob is validated where SURU_SURICATA_TEST is: before the revert arm (and so the backup) and the
# dead-man's switch, so a typo dies before any config change.
val_at="$(_first_line "${DRIVER}" 'SURU_SURICATA_REBUILD:-false')"
backup_at="$(_first_line "${DRIVER}" '^[[:space:]]*_pf_revert_arm$')"
[[ "${val_at}" -gt 0 && "${backup_at}" -gt 0 && "${val_at}" -lt "${backup_at}" ]] \
  && _pass "knob validated (line ${val_at}) before the revert trap, i.e. before the backup and any config change (line ${backup_at})" || _fail "knob validated after the revert trap (val=${val_at}, backup=${backup_at})"
grep -q -E "SURU_SURICATA_REBUILD:-false.*tr '\[:upper:\]' '\[:lower:\]'" "${DRIVER}" \
  && _pass "knob value is case-normalised" || _fail "knob value is case-sensitive"
grep -q 'log_warn "SURU_SURICATA_REBUILD=true' "${DRIVER}" \
  && _pass "driver WARNs when the one-shot knob is on" || _fail "no WARN when the knob is on"
grep -q -E '_suri_run_applier "Nothing changed — skipping sync/restart" .*\$\{_suri_rebuild_flag\}' "${DRIVER}" \
  && _pass "driver appends the --rebuild flag to the rules-applier invocation" || _fail "driver invocation lacks the --rebuild flag"
grep -q '^# SURU_SURICATA_REBUILD=false' "${ENV_EXAMPLE}" \
  && _pass ".env.example documents SURU_SURICATA_REBUILD" || _fail ".env.example lacks SURU_SURICATA_REBUILD"

test_summary
