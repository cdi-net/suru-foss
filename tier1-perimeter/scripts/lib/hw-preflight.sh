#!/usr/bin/env bash
# SURU Platform — Hardware Preflight Library
# Detects router hardware capabilities and derives optimal tuning values for
# pf table entries, Zeek workers, and Suricata engine profile + memcaps.
#
# All detection-derived settings are persisted to:
#   router:  /usr/local/etc/suru/hw-profile.conf
#   local:   tier1-perimeter/.hw-profile  (gitignored)
#
# Operator-override contract:
#   Each tunable has an APPLIED key (operator-editable) and an _AUTO key
#   (SURU's last computed recommendation). On re-deploy:
#     if APPLIED == AUTO (unchanged): take new computed value
#     if APPLIED != AUTO (operator edited): preserve operator value
#   Only _AUTO is updated to the latest computed value each run.
#
# Public API:
#   hw_compute_physmem_gb <physmem_bytes>
#   hw_compute_profile    <ncpu> <physmem_bytes>
#   hw_reconcile_profile  <detected_blob> <stored_path>
#   hw_write_profile_file <blob> <path>
#   hw_profile_diff       <blob> <path>
#   hw_detect_hardware    <ssh_opts_array_name> <ssh_user> <target>
#   hw_preflight_run      <target> <ssh_user> <ssh_key> <strict> <dry_run> <verbose>
#
# Caller must have sourced lib/log.sh and lib/ssh.sh before calling
# hw_preflight_run (lower-level functions are self-contained).

set -euo pipefail

# Remote path for the profile on the router.
HW_PROFILE_REMOTE="/usr/local/etc/suru/hw-profile.conf"

# ---------------------------------------------------------------------------
# hw_compute_physmem_gb <physmem_bytes>
# Rounds physmem_bytes to nearest GiB (integer). Avoids firmware-reserved RAM
# boundary issues where an 8 GB box reports ~7.6 GiB.
# ---------------------------------------------------------------------------
hw_compute_physmem_gb() {
  local bytes="$1"
  # (bytes + 512MiB) / 1GiB  →  rounds to nearest
  echo $(( (bytes + 536870912) / 1073741824 ))
}

# ---------------------------------------------------------------------------
# hw_compute_profile <ncpu> <physmem_bytes> <disk_kb>
# Echoes KEY=VALUE lines (applied-key names, no _AUTO suffix).
# Pure function — no I/O, no side effects.
# ---------------------------------------------------------------------------
hw_compute_profile() {
  local ncpu="$1"
  local physmem_bytes="$2"
  local disk_kb="${3:-10485760}"  # default 10 GB if unset
  local physmem_gb
  physmem_gb="$(hw_compute_physmem_gb "${physmem_bytes}")"

  # pf table entries (~56 bytes/entry; shared pool across ALL pf tables)
  # FreeBSD pf docs: set limit table-entries N in /tmp/rules.debug
  # Confirmed XML key: system/maximumtableentries (string integer)
  local pf_table_entries
  if   (( physmem_gb < 2 )); then pf_table_entries=200000
  elif (( physmem_gb < 4 )); then pf_table_entries=400000
  elif (( physmem_gb < 8 )); then pf_table_entries=800000
  else                             pf_table_entries=1000000
  fi

  # pf state table maximum (~1.4 KB/entry; kernel default on this router: 402000)
  # Confirmed XML key: system/maximumstates (string integer; NULL = kernel default)
  # Formula: explicit override sized to ~10% of RAM budget for state tracking.
  local pf_max_states
  if   (( physmem_gb < 2 )); then pf_max_states=150000
  elif (( physmem_gb < 4 )); then pf_max_states=250000
  elif (( physmem_gb < 8 )); then pf_max_states=400000
  else                             pf_max_states=800000
  fi

  # Zeek lb_procs (packet-capture worker threads)
  # Zeek node.cfg; lb_procs > 1 requires lb_method=netmap (zeek-iface-apply.php)
  local zeek_lb_procs
  if   (( ncpu <= 2 )); then zeek_lb_procs=1
  elif (( ncpu <= 4 )); then zeek_lb_procs=2
  elif (( ncpu <= 8 )); then zeek_lb_procs=$(( ncpu - 2 ))
  else                        zeek_lb_procs=$(( ncpu - 2 > 8 ? 8 : ncpu - 2 ))
  fi

  # Suricata detect.profile
  # Suricata docs: low/medium/high controls pattern-matching depth
  local suricata_profile
  if   (( ncpu <= 3 )); then suricata_profile="low"
  elif (( ncpu <= 7 )); then suricata_profile="medium"
  else                        suricata_profile="high"
  fi

  # Suricata memcaps (stream / reassembly / defrag)
  # Suricata docs: stream.memcap, stream.reassembly.memcap, defrag.memcap
  local stream_memcap reassembly_memcap defrag_memcap
  if   (( physmem_gb < 2 )); then
    stream_memcap="32mb"; reassembly_memcap="64mb";  defrag_memcap="16mb"
  elif (( physmem_gb < 4 )); then
    stream_memcap="64mb"; reassembly_memcap="128mb"; defrag_memcap="32mb"
  elif (( physmem_gb < 8 )); then
    stream_memcap="128mb"; reassembly_memcap="256mb"; defrag_memcap="64mb"
  else
    stream_memcap="256mb"; reassembly_memcap="512mb"; defrag_memcap="128mb"
  fi

  # syslog-ng reliable disk-buffer capacity (bytes)
  # Scales with available disk; capped to avoid over-committing storage.
  # Formula: 10% of available disk, floored at 1 GB, capped at 8 GB.
  # Stored as bytes (syslog-ng capacity-bytes expects integer bytes).
  local disk_gb; disk_gb=$(( disk_kb / 1048576 ))
  local syslogng_disk_buf_bytes
  if   (( disk_gb < 10  )); then syslogng_disk_buf_bytes=1073741824   # 1 GB
  elif (( disk_gb < 20  )); then syslogng_disk_buf_bytes=2147483648   # 2 GB
  elif (( disk_gb < 50  )); then syslogng_disk_buf_bytes=4294967296   # 4 GB
  else                            syslogng_disk_buf_bytes=8589934592   # 8 GB
  fi

  # Unbound DNS cache sizes for pfBlockerNG DNSBL (MB)
  # Confirmed XML keys 2026-07-01: unbound/msgcachesize (MB string), unbound/rrsetcachesize (MB string)
  # Current value observed: msgcachesize=50, rrsetcachesize=NULL (unbound default).
  # unbound convention: rrset-cache-size = 2× msg-cache-size.
  local unbound_msg_cache_mb unbound_rrset_cache_mb
  if   (( physmem_gb < 2 )); then unbound_msg_cache_mb=16;  unbound_rrset_cache_mb=32
  elif (( physmem_gb < 4 )); then unbound_msg_cache_mb=32;  unbound_rrset_cache_mb=64
  elif (( physmem_gb < 8 )); then unbound_msg_cache_mb=50;  unbound_rrset_cache_mb=100
  else                             unbound_msg_cache_mb=100; unbound_rrset_cache_mb=200
  fi

  printf 'SURU_HW_PF_TABLE_ENTRIES=%s\n'              "${pf_table_entries}"
  printf 'SURU_HW_PF_MAX_STATES=%s\n'                "${pf_max_states}"
  printf 'SURU_HW_ZEEK_LB_PROCS=%s\n'               "${zeek_lb_procs}"
  printf 'SURU_HW_SURICATA_PROFILE=%s\n'             "${suricata_profile}"
  printf 'SURU_HW_SURICATA_STREAM_MEMCAP=%s\n'       "${stream_memcap}"
  printf 'SURU_HW_SURICATA_REASSEMBLY_MEMCAP=%s\n'   "${reassembly_memcap}"
  printf 'SURU_HW_SURICATA_DEFRAG_MEMCAP=%s\n'       "${defrag_memcap}"
  printf 'SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES=%s\n'   "${syslogng_disk_buf_bytes}"
  printf 'SURU_HW_UNBOUND_MSG_CACHE_MB=%s\n'         "${unbound_msg_cache_mb}"
  printf 'SURU_HW_UNBOUND_RRSET_CACHE_MB=%s\n'       "${unbound_rrset_cache_mb}"
}

# ---------------------------------------------------------------------------
# _hw_read_kv <key> <file>
# Reads KEY=VALUE from a profile file. Returns empty string if absent.
# ---------------------------------------------------------------------------
_hw_read_kv() {
  local key="$1" path="$2"
  [[ -f "${path}" ]] || { echo ""; return 0; }
  local val
  val="$(grep -m1 "^${key}=" "${path}" 2>/dev/null || true)"
  echo "${val#"${key}="}"
}

# ---------------------------------------------------------------------------
# hw_reconcile_profile <computed_blob> <stored_path>
# Merges computed values with existing operator overrides.
# Returns a full profile blob on stdout.
# ---------------------------------------------------------------------------
hw_reconcile_profile() {
  local computed_blob="$1"
  local stored_path="$2"

  # Parse computed values into local vars
  local c_pf c_pf_states c_zeek c_suri_prof c_suri_stream c_suri_reassembly c_suri_defrag
  local c_sng_buf c_unbound_msg c_unbound_rrset
  c_pf="$(echo "${computed_blob}"              | grep -m1 '^SURU_HW_PF_TABLE_ENTRIES='            | cut -d= -f2)"
  c_pf_states="$(echo "${computed_blob}"       | grep -m1 '^SURU_HW_PF_MAX_STATES='              | cut -d= -f2)"
  c_zeek="$(echo "${computed_blob}"            | grep -m1 '^SURU_HW_ZEEK_LB_PROCS='              | cut -d= -f2)"
  c_suri_prof="$(echo "${computed_blob}"       | grep -m1 '^SURU_HW_SURICATA_PROFILE='           | cut -d= -f2)"
  c_suri_stream="$(echo "${computed_blob}"     | grep -m1 '^SURU_HW_SURICATA_STREAM_MEMCAP='     | cut -d= -f2)"
  c_suri_reassembly="$(echo "${computed_blob}" | grep -m1 '^SURU_HW_SURICATA_REASSEMBLY_MEMCAP=' | cut -d= -f2)"
  c_suri_defrag="$(echo "${computed_blob}"     | grep -m1 '^SURU_HW_SURICATA_DEFRAG_MEMCAP='     | cut -d= -f2)"
  c_sng_buf="$(echo "${computed_blob}"         | grep -m1 '^SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES=' | cut -d= -f2)"
  c_unbound_msg="$(echo "${computed_blob}"     | grep -m1 '^SURU_HW_UNBOUND_MSG_CACHE_MB='       | cut -d= -f2)"
  c_unbound_rrset="$(echo "${computed_blob}"   | grep -m1 '^SURU_HW_UNBOUND_RRSET_CACHE_MB='     | cut -d= -f2)"

  # Reconcile each applied key: operator edit wins if APPLIED != AUTO (stored)
  _reconcile_one() {
    local key="$1" new_auto="$2"
    local applied_stored auto_stored
    applied_stored="$(_hw_read_kv "${key}"       "${stored_path}")"
    auto_stored="$(   _hw_read_kv "${key}_AUTO"  "${stored_path}")"
    if [[ -z "${applied_stored}" ]] || [[ "${applied_stored}" == "${auto_stored}" ]]; then
      # First run or not operator-edited: use new computed value
      echo "${new_auto}"
    else
      # Operator changed this key: preserve their value
      echo "${applied_stored}"
    fi
  }

  local r_pf r_pf_states r_zeek r_suri_prof r_suri_stream r_suri_reassembly r_suri_defrag
  local r_sng_buf r_unbound_msg r_unbound_rrset
  r_pf="$(             _reconcile_one SURU_HW_PF_TABLE_ENTRIES            "${c_pf}")"
  r_pf_states="$(      _reconcile_one SURU_HW_PF_MAX_STATES               "${c_pf_states}")"
  r_zeek="$(           _reconcile_one SURU_HW_ZEEK_LB_PROCS               "${c_zeek}")"
  r_suri_prof="$(      _reconcile_one SURU_HW_SURICATA_PROFILE            "${c_suri_prof}")"
  r_suri_stream="$(    _reconcile_one SURU_HW_SURICATA_STREAM_MEMCAP      "${c_suri_stream}")"
  r_suri_reassembly="$(_reconcile_one SURU_HW_SURICATA_REASSEMBLY_MEMCAP  "${c_suri_reassembly}")"
  r_suri_defrag="$(    _reconcile_one SURU_HW_SURICATA_DEFRAG_MEMCAP      "${c_suri_defrag}")"
  r_sng_buf="$(        _reconcile_one SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES  "${c_sng_buf}")"
  r_unbound_msg="$(    _reconcile_one SURU_HW_UNBOUND_MSG_CACHE_MB        "${c_unbound_msg}")"
  r_unbound_rrset="$(  _reconcile_one SURU_HW_UNBOUND_RRSET_CACHE_MB      "${c_unbound_rrset}")"

  # Read detected specs for the header section
  local ncpu_val phys_val disk_val
  ncpu_val="$(_hw_read_kv SURU_HW_DETECTED_NCPU          <<< "${computed_blob}" 2>/dev/null || true)"
  phys_val="$(_hw_read_kv SURU_HW_DETECTED_PHYSMEM_GB    <<< "${computed_blob}" 2>/dev/null || true)"
  disk_val="$(_hw_read_kv SURU_HW_DETECTED_DISK_AVAIL_GB <<< "${computed_blob}" 2>/dev/null || true)"

  cat <<PROFILE
# SURU Platform — Hardware Profile
# Auto-generated by hw-preflight at deploy time.
# Edit APPLIED values below to override auto-detected settings.
# _AUTO values are SURU's recommendations — DO NOT EDIT.
# Override logic: if APPLIED == AUTO (previous), your edit wins on re-deploy.

## Detected hardware
SURU_HW_DETECTED_NCPU=${ncpu_val}
SURU_HW_DETECTED_PHYSMEM_GB=${phys_val}
SURU_HW_DETECTED_DISK_AVAIL_GB=${disk_val}

## Applied values (operator-editable)
SURU_HW_PF_TABLE_ENTRIES=${r_pf}
SURU_HW_PF_MAX_STATES=${r_pf_states}
SURU_HW_ZEEK_LB_PROCS=${r_zeek}
SURU_HW_SURICATA_PROFILE=${r_suri_prof}
SURU_HW_SURICATA_STREAM_MEMCAP=${r_suri_stream}
SURU_HW_SURICATA_REASSEMBLY_MEMCAP=${r_suri_reassembly}
SURU_HW_SURICATA_DEFRAG_MEMCAP=${r_suri_defrag}
SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES=${r_sng_buf}
SURU_HW_UNBOUND_MSG_CACHE_MB=${r_unbound_msg}
SURU_HW_UNBOUND_RRSET_CACHE_MB=${r_unbound_rrset}

## Baseline — SURU-computed values. DO NOT EDIT.
SURU_HW_PF_TABLE_ENTRIES_AUTO=${c_pf}
SURU_HW_PF_MAX_STATES_AUTO=${c_pf_states}
SURU_HW_ZEEK_LB_PROCS_AUTO=${c_zeek}
SURU_HW_SURICATA_PROFILE_AUTO=${c_suri_prof}
SURU_HW_SURICATA_STREAM_MEMCAP_AUTO=${c_suri_stream}
SURU_HW_SURICATA_REASSEMBLY_MEMCAP_AUTO=${c_suri_reassembly}
SURU_HW_SURICATA_DEFRAG_MEMCAP_AUTO=${c_suri_defrag}
SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES_AUTO=${c_sng_buf}
SURU_HW_UNBOUND_MSG_CACHE_MB_AUTO=${c_unbound_msg}
SURU_HW_UNBOUND_RRSET_CACHE_MB_AUTO=${c_unbound_rrset}
PROFILE
}

# ---------------------------------------------------------------------------
# hw_write_profile_file <blob> <path>
# Writes blob to path (creates parent dir). Caller is responsible for
# ensuring it has write permission to path.
# ---------------------------------------------------------------------------
hw_write_profile_file() {
  local blob="$1" path="$2"
  mkdir -p "$(dirname "${path}")"
  printf '%s\n' "${blob}" > "${path}"
}

# ---------------------------------------------------------------------------
# hw_profile_diff <blob> <path>
# Returns 0 if file content matches blob, 1 if different or absent.
# ---------------------------------------------------------------------------
hw_profile_diff() {
  local blob="$1" path="$2"
  [[ -f "${path}" ]] || return 1
  local stored
  stored="$(cat "${path}")"
  [[ "${stored}" == "${blob}" ]]
}

# ---------------------------------------------------------------------------
# hw_detect_hardware <ssh_user> <target> <ssh_opts...>
# Runs sysctl + df over SSH to detect CPU, RAM, and disk.
# On success, exports: HW_NCPU, HW_PHYSMEM_BYTES, HW_DISK_KB_AVAIL
# Returns 1 on any parse failure (caller falls back to defaults).
# ---------------------------------------------------------------------------
hw_detect_hardware() {
  local ssh_user="$1" target="$2"
  shift 2
  local -a ssh_opts=("$@")

  local raw
  # sysctl -n outputs one value per line: line 1 = hw.ncpu, line 2 = hw.physmem
  # df -k: header + data line; awk extracts column 4 (Avail).
  # Column layout confirmed 2026-07-01 on live pfSense ZFS root:
  #   Filesystem  1024-blocks  Used  Avail  Capacity  Mounted-on
  #   col:        1            2     3      4          5           6
  if ! raw="$(ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
    'sysctl -n hw.ncpu hw.physmem && df -k / | awk '\''NR==2{print $4}'\''' 2>&1)"; then
    echo "[hw-preflight] WARN: SSH hardware detection failed: ${raw}" >&2
    return 1
  fi

  local ncpu physmem disk_kb
  ncpu="$(echo "${raw}"    | sed -n '1p')"
  physmem="$(echo "${raw}" | sed -n '2p')"
  disk_kb="$(echo "${raw}" | sed -n '3p')"

  # Validate: all three must be non-empty integers
  if ! [[ "${ncpu}"    =~ ^[0-9]+$ ]] || \
     ! [[ "${physmem}" =~ ^[0-9]+$ ]] || \
     ! [[ "${disk_kb}" =~ ^[0-9]+$ ]]; then
    echo "[hw-preflight] WARN: unexpected sysctl/df output: ncpu='${ncpu}' physmem='${physmem}' disk_kb='${disk_kb}'" >&2
    return 1
  fi

  export HW_NCPU="${ncpu}"
  export HW_PHYSMEM_BYTES="${physmem}"
  export HW_DISK_KB_AVAIL="${disk_kb}"
}

# ---------------------------------------------------------------------------
# hw_preflight_run <target> <ssh_user> <ssh_key> <strict> <dry_run> <verbose>
# Main orchestration: detect → compute → reconcile → write (idempotent).
# Never fails the pipeline — all errors are logged as WARN and degrade gracefully.
# ---------------------------------------------------------------------------
hw_preflight_run() {
  local target="$1" ssh_user="$2" ssh_key="$3" strict="$4" dry_run="$5" verbose="$6"
  local local_profile_path="${HW_LOCAL_PROFILE_PATH:-${TIER1_DIR:-.}/.hw-profile}"
  local -a ssh_opts=(-i "${ssh_key}" -o "StrictHostKeyChecking=${strict}" -o "BatchMode=yes" -o "ConnectTimeout=15")

  local preflight_status="ok"
  local ncpu physmem_bytes disk_kb

  echo "[hw-preflight] Detecting router hardware at ${ssh_user}@${target}..."

  if "${dry_run}"; then
    echo "[hw-preflight] (dry-run) Would SSH to ${target} to detect hw.ncpu, hw.physmem, df /."
    echo "[hw-preflight] (dry-run) Would write ${HW_PROFILE_REMOTE} and ${local_profile_path}."
    echo "SURU_HW_PREFLIGHT=dry-run"
    return 0
  fi

  if hw_detect_hardware "${ssh_user}" "${target}" "${ssh_opts[@]}"; then
    ncpu="${HW_NCPU}"
    physmem_bytes="${HW_PHYSMEM_BYTES}"
    disk_kb="${HW_DISK_KB_AVAIL}"
    echo "[hw-preflight] Detected: ncpu=${ncpu} physmem=$(hw_compute_physmem_gb "${physmem_bytes}")GB disk_avail=$(( disk_kb / 1048576 ))GB"
  else
    echo "[hw-preflight] WARN: Hardware detection failed — using safe minimal defaults."
    preflight_status="degraded"
    # Safe minimal defaults (2 cores, 4 GB, 10 GB disk)
    ncpu=2; physmem_bytes=4294967296; disk_kb=10485760
  fi

  # Compute optimal values
  local computed_applied
  computed_applied="$(hw_compute_profile "${ncpu}" "${physmem_bytes}" "${disk_kb}")"

  local physmem_gb disk_gb
  physmem_gb="$(hw_compute_physmem_gb "${physmem_bytes}")"
  disk_gb=$(( disk_kb / 1048576 ))

  local computed_blob
  computed_blob="$(printf 'SURU_HW_DETECTED_NCPU=%s\nSURU_HW_DETECTED_PHYSMEM_GB=%s\nSURU_HW_DETECTED_DISK_AVAIL_GB=%s\n%s' \
    "${ncpu}" "${physmem_gb}" "${disk_gb}" "${computed_applied}")"

  # Fetch existing profile from router for reconciliation
  local stored_tmp
  stored_tmp="$(mktemp)"
  if ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
       "test -f '${HW_PROFILE_REMOTE}' && cat '${HW_PROFILE_REMOTE}'" \
       > "${stored_tmp}" 2>/dev/null; then
    if "${verbose}"; then
      echo "[hw-preflight] Fetched existing profile from router for reconciliation."
    fi
  fi

  # Reconcile (operator-override-wins)
  local reconciled_blob
  reconciled_blob="$(hw_reconcile_profile "${computed_blob}" "${stored_tmp}")"
  rm -f -- "${stored_tmp}"

  # Write to router only if changed.
  # Use a temp file for the current remote content — [[ -f /dev/stdin ]] is always
  # false on macOS/FreeBSD so passing /dev/stdin to hw_profile_diff never matches.
  local diff_tmp; diff_tmp="$(mktemp)"
  ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
      "cat '${HW_PROFILE_REMOTE}' 2>/dev/null || true" \
      > "${diff_tmp}" 2>/dev/null || true
  if hw_profile_diff "${reconciled_blob}" "${diff_tmp}"; then
    rm -f -- "${diff_tmp}"
    echo "[hw-preflight] Router profile unchanged — no write needed."
  else
    rm -f -- "${diff_tmp}"
    echo "[hw-preflight] Writing hardware profile to router: ${HW_PROFILE_REMOTE}"
    local stage_path="/tmp/suru-staging/.hw-profile"
    local profile_tmp
    profile_tmp="$(mktemp)"
    hw_write_profile_file "${reconciled_blob}" "${profile_tmp}"

    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
    # Stage to /tmp/suru-staging/ (writable by admin), then move to protected path as root.
    # /tmp/suru-staging/ must be pre-created by the platform driver before this runs.
    if scp -i "${ssh_key}" -o "StrictHostKeyChecking=${strict}" -o "BatchMode=yes" \
         "${profile_tmp}" "${ssh_user}@${target}:${stage_path}" 2>/dev/null; then
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
        "${_SUDO}mkdir -p '$(dirname "${HW_PROFILE_REMOTE}")' && \
         ${_SUDO}mv '${stage_path}' '${HW_PROFILE_REMOTE}' && \
         ${_SUDO}chmod 644 '${HW_PROFILE_REMOTE}'" 2>/dev/null \
        || echo "[hw-preflight] WARN: could not write ${HW_PROFILE_REMOTE} on router." >&2
    else
      echo "[hw-preflight] WARN: SCP to router staging failed — profile not written to router." >&2
      preflight_status="degraded"
    fi
    rm -f -- "${profile_tmp}"
  fi

  # Always write local mirror (render pipeline reads this)
  hw_write_profile_file "${reconciled_blob}" "${local_profile_path}"
  echo "[hw-preflight] Local profile written: ${local_profile_path}"

  # Emit a summary of applied values
  echo "[hw-preflight] Applied:"
  echo "${reconciled_blob}" | grep '^SURU_HW_[A-Z_]*=[^_A-Z]' | grep -v '_AUTO=' | \
    while IFS='=' read -r k v; do printf "  %-40s = %s\n" "${k}" "${v}"; done

  echo "SURU_HW_PREFLIGHT=${preflight_status}"
}
