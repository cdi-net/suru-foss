#!/usr/bin/env bash
# SURU Platform — Unit tests for hw-preflight pure functions
# Tests hw_compute_profile and hw_reconcile_profile boundary cases.
# No SSH, no live router required.
#
# Usage: bash test-hw-preflight.sh
# Exit: 0 = all pass, 1 = any failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
LIB="${REPO_ROOT}/tier1-perimeter/scripts/lib/hw-preflight.sh"

if [[ ! -f "${LIB}" ]]; then
  echo "[test-hw-preflight] FATAL: library not found: ${LIB}" >&2
  exit 1
fi

# Source only — suppress set -e on source so we get function defs
# shellcheck source=/dev/null
source "${LIB}"

PASS=0; FAIL=0

# assert_eq <label> <expected> <actual>
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    echo "  PASS: ${label}"
    PASS=$(( PASS + 1 ))
  else
    echo "  FAIL: ${label}"
    echo "        expected: '${expected}'"
    echo "        actual:   '${actual}'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# hw_compute_physmem_gb tests
# ---------------------------------------------------------------------------
echo ""
echo "== hw_compute_physmem_gb =="

# 1.5 GB (1610612736) → nearest is 2 GB
assert_eq "1.5 GB rounds to 2"  "2" "$(hw_compute_physmem_gb 1610612736)"
# 1 GB exactly → 1
assert_eq "1 GB rounds to 1"    "1" "$(hw_compute_physmem_gb 1073741824)"
# 2 GB exactly → 2
assert_eq "2 GB rounds to 2"    "2" "$(hw_compute_physmem_gb 2147483648)"
# 3.5 GB → rounds to 4
assert_eq "3.5 GB rounds to 4"  "4" "$(hw_compute_physmem_gb 3758096384)"
# 7.6 GB (firmware-reserved 8 GB box) → rounds to 8
assert_eq "7.6 GB rounds to 8"  "8" "$(hw_compute_physmem_gb 8160437248)"

# ---------------------------------------------------------------------------
# Helper: get one key from hw_compute_profile output
# ---------------------------------------------------------------------------
_profile_key() {
  local ncpu="$1" physmem="$2" key="$3"
  hw_compute_profile "${ncpu}" "${physmem}" | grep "^${key}=" | cut -d= -f2
}

# ---------------------------------------------------------------------------
# hw_compute_profile — pf table entries
# ---------------------------------------------------------------------------
echo ""
echo "== hw_compute_profile: pf table entries =="

# ncpu=1, physmem=1 GB → 200000
assert_eq "1GB → 200000" "200000" "$(_profile_key 1 1073741824 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=2 GB → 400000
assert_eq "2GB → 400000" "400000" "$(_profile_key 2 2147483648 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=3 GB → 400000 (still < 4)
assert_eq "3GB → 400000" "400000" "$(_profile_key 2 3221225472 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=4 GB → 800000
assert_eq "4GB → 800000" "800000" "$(_profile_key 4 4294967296 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=6 GB → 800000 (still < 8)
assert_eq "6GB → 800000" "800000" "$(_profile_key 4 6442450944 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=8 GB → 1000000
assert_eq "8GB → 1000000" "1000000" "$(_profile_key 8 8589934592 SURU_HW_PF_TABLE_ENTRIES)"
# physmem=16 GB → 1000000
assert_eq "16GB → 1000000" "1000000" "$(_profile_key 16 17179869184 SURU_HW_PF_TABLE_ENTRIES)"

# ---------------------------------------------------------------------------
# hw_compute_profile — Zeek lb_procs
# ---------------------------------------------------------------------------
echo ""
echo "== hw_compute_profile: Zeek lb_procs =="

assert_eq "ncpu=1  → lb_procs=1" "1"  "$(_profile_key 1  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=2  → lb_procs=1" "1"  "$(_profile_key 2  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=3  → lb_procs=2" "2"  "$(_profile_key 3  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=4  → lb_procs=2" "2"  "$(_profile_key 4  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=5  → lb_procs=3" "3"  "$(_profile_key 5  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=8  → lb_procs=6" "6"  "$(_profile_key 8  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=9  → lb_procs=7" "7"  "$(_profile_key 9  8589934592 SURU_HW_ZEEK_LB_PROCS)"
assert_eq "ncpu=16 → lb_procs=8 (cap)" "8" "$(_profile_key 16 8589934592 SURU_HW_ZEEK_LB_PROCS)"

# ---------------------------------------------------------------------------
# hw_compute_profile — Suricata detect.profile
# ---------------------------------------------------------------------------
echo ""
echo "== hw_compute_profile: Suricata profile =="

assert_eq "ncpu=1  → low"    "low"    "$(_profile_key 1  8589934592 SURU_HW_SURICATA_PROFILE)"
assert_eq "ncpu=3  → low"    "low"    "$(_profile_key 3  8589934592 SURU_HW_SURICATA_PROFILE)"
assert_eq "ncpu=4  → medium" "medium" "$(_profile_key 4  8589934592 SURU_HW_SURICATA_PROFILE)"
assert_eq "ncpu=7  → medium" "medium" "$(_profile_key 7  8589934592 SURU_HW_SURICATA_PROFILE)"
assert_eq "ncpu=8  → high"   "high"   "$(_profile_key 8  8589934592 SURU_HW_SURICATA_PROFILE)"
assert_eq "ncpu=16 → high"   "high"   "$(_profile_key 16 8589934592 SURU_HW_SURICATA_PROFILE)"

# ---------------------------------------------------------------------------
# hw_compute_profile — Suricata memcaps
# ---------------------------------------------------------------------------
echo ""
echo "== hw_compute_profile: Suricata memcaps =="

# 1 GB
assert_eq "1GB stream"     "32mb"  "$(_profile_key 2 1073741824 SURU_HW_SURICATA_STREAM_MEMCAP)"
assert_eq "1GB reassembly" "64mb"  "$(_profile_key 2 1073741824 SURU_HW_SURICATA_REASSEMBLY_MEMCAP)"
assert_eq "1GB defrag"     "16mb"  "$(_profile_key 2 1073741824 SURU_HW_SURICATA_DEFRAG_MEMCAP)"
# 2 GB
assert_eq "2GB stream"     "64mb"  "$(_profile_key 4 2147483648 SURU_HW_SURICATA_STREAM_MEMCAP)"
assert_eq "2GB reassembly" "128mb" "$(_profile_key 4 2147483648 SURU_HW_SURICATA_REASSEMBLY_MEMCAP)"
assert_eq "2GB defrag"     "32mb"  "$(_profile_key 4 2147483648 SURU_HW_SURICATA_DEFRAG_MEMCAP)"
# 4 GB
assert_eq "4GB stream"     "128mb" "$(_profile_key 4 4294967296 SURU_HW_SURICATA_STREAM_MEMCAP)"
assert_eq "4GB reassembly" "256mb" "$(_profile_key 4 4294967296 SURU_HW_SURICATA_REASSEMBLY_MEMCAP)"
assert_eq "4GB defrag"     "64mb"  "$(_profile_key 4 4294967296 SURU_HW_SURICATA_DEFRAG_MEMCAP)"
# 8 GB
assert_eq "8GB stream"     "256mb" "$(_profile_key 8 8589934592 SURU_HW_SURICATA_STREAM_MEMCAP)"
assert_eq "8GB reassembly" "512mb" "$(_profile_key 8 8589934592 SURU_HW_SURICATA_REASSEMBLY_MEMCAP)"
assert_eq "8GB defrag"     "128mb" "$(_profile_key 8 8589934592 SURU_HW_SURICATA_DEFRAG_MEMCAP)"

# ---------------------------------------------------------------------------
# hw_reconcile_profile tests
# ---------------------------------------------------------------------------
echo ""
echo "== hw_reconcile_profile =="

_make_computed_blob() {
  local ncpu="$1" physmem="$2"
  printf 'SURU_HW_DETECTED_NCPU=%s\nSURU_HW_DETECTED_PHYSMEM_GB=%s\nSURU_HW_DETECTED_DISK_AVAIL_GB=50\n%s' \
    "${ncpu}" "$(hw_compute_physmem_gb "${physmem}")" "$(hw_compute_profile "${ncpu}" "${physmem}")"
}

_reconcile_key() {
  local ncpu="$1" physmem="$2" stored_path="$3" key="$4"
  local blob
  blob="$(_make_computed_blob "${ncpu}" "${physmem}")"
  hw_reconcile_profile "${blob}" "${stored_path}" | grep "^${key}=" | cut -d= -f2
}

# Test 1: no stored file → applied == auto == computed
tmpdir="$(mktemp -d)"
no_file="${tmpdir}/nonexistent"

assert_eq "no stored file: pf_table_entries applied = computed" \
  "1000000" "$(_reconcile_key 8 8589934592 "${no_file}" SURU_HW_PF_TABLE_ENTRIES)"
assert_eq "no stored file: pf_table_entries AUTO = computed" \
  "1000000" "$(_reconcile_key 8 8589934592 "${no_file}" SURU_HW_PF_TABLE_ENTRIES_AUTO)"

# Test 2: stored file with APPLIED == AUTO (not operator-edited) → take new computed
stored="${tmpdir}/stored.conf"
cat > "${stored}" <<'EOF'
SURU_HW_PF_TABLE_ENTRIES=400000
SURU_HW_PF_TABLE_ENTRIES_AUTO=400000
SURU_HW_ZEEK_LB_PROCS=1
SURU_HW_ZEEK_LB_PROCS_AUTO=1
SURU_HW_SURICATA_PROFILE=low
SURU_HW_SURICATA_PROFILE_AUTO=low
SURU_HW_SURICATA_STREAM_MEMCAP=64mb
SURU_HW_SURICATA_STREAM_MEMCAP_AUTO=64mb
SURU_HW_SURICATA_REASSEMBLY_MEMCAP=128mb
SURU_HW_SURICATA_REASSEMBLY_MEMCAP_AUTO=128mb
SURU_HW_SURICATA_DEFRAG_MEMCAP=32mb
SURU_HW_SURICATA_DEFRAG_MEMCAP_AUTO=32mb
EOF

# Simulate upgrade: 4 cores, 8 GB (was 4 cores, 2 GB) → all values should update
assert_eq "APPLIED==AUTO: pf updated to 1000000" \
  "1000000" "$(_reconcile_key 4 8589934592 "${stored}" SURU_HW_PF_TABLE_ENTRIES)"
assert_eq "APPLIED==AUTO: zeek updated to 2" \
  "2" "$(_reconcile_key 4 8589934592 "${stored}" SURU_HW_ZEEK_LB_PROCS)"
assert_eq "APPLIED==AUTO: suricata profile updated to medium" \
  "medium" "$(_reconcile_key 4 8589934592 "${stored}" SURU_HW_SURICATA_PROFILE)"

# Test 3: operator edited APPLIED to differ from AUTO → preserve operator choice
stored_op="${tmpdir}/stored_op.conf"
cat > "${stored_op}" <<'EOF'
SURU_HW_PF_TABLE_ENTRIES=2000000
SURU_HW_PF_TABLE_ENTRIES_AUTO=1000000
SURU_HW_ZEEK_LB_PROCS=4
SURU_HW_ZEEK_LB_PROCS_AUTO=2
SURU_HW_SURICATA_PROFILE=high
SURU_HW_SURICATA_PROFILE_AUTO=medium
SURU_HW_SURICATA_STREAM_MEMCAP=512mb
SURU_HW_SURICATA_STREAM_MEMCAP_AUTO=256mb
SURU_HW_SURICATA_REASSEMBLY_MEMCAP=1024mb
SURU_HW_SURICATA_REASSEMBLY_MEMCAP_AUTO=512mb
SURU_HW_SURICATA_DEFRAG_MEMCAP=256mb
SURU_HW_SURICATA_DEFRAG_MEMCAP_AUTO=128mb
EOF

assert_eq "operator edit: pf preserved at 2000000" \
  "2000000" "$(_reconcile_key 8 8589934592 "${stored_op}" SURU_HW_PF_TABLE_ENTRIES)"
assert_eq "operator edit: zeek preserved at 4" \
  "4" "$(_reconcile_key 8 8589934592 "${stored_op}" SURU_HW_ZEEK_LB_PROCS)"
assert_eq "operator edit: suricata profile preserved at high" \
  "high" "$(_reconcile_key 8 8589934592 "${stored_op}" SURU_HW_SURICATA_PROFILE)"
assert_eq "operator edit: stream memcap preserved at 512mb" \
  "512mb" "$(_reconcile_key 8 8589934592 "${stored_op}" SURU_HW_SURICATA_STREAM_MEMCAP)"
assert_eq "operator edit: AUTO still updated to new computed (1000000)" \
  "1000000" "$(_reconcile_key 8 8589934592 "${stored_op}" SURU_HW_PF_TABLE_ENTRIES_AUTO)"

rm -rf "${tmpdir}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "== Results: ${PASS} passed, ${FAIL} failed =="

[[ ${FAIL} -eq 0 ]] && exit 0 || exit 1
