#!/usr/bin/env bash
# SURU Platform — Suricata render library
# Merges tier2-telemetry/suricata/ rule-selection + update-policy with
# tier1-perimeter/templates/suricata/suricata.yaml.tpl
# Output: <rendered>/suricata/suricata.yaml, enable.conf, disable.conf
# Called by: tier2-telemetry/build/render.sh
#
# Multi-interface: set SURICATA_IFACES=lan,opt1 (comma-separated) in .env.
# SURICATA_IFACE (singular, legacy) is supported as a single-interface alias.

render_suricata() {
  local platform="$1" t1_dir="$2" t2_dir="$3" rendered="$4" dry_run="$5"

  local tpl="${t1_dir}/templates/suricata/suricata.yaml.tpl"
  local out="${rendered}/suricata/suricata.yaml"
  local enable_src="${t2_dir}/suricata/rule-selection/enable.conf"
  local disable_src="${t2_dir}/suricata/rule-selection/disable.conf"
  local update_src="${t2_dir}/suricata/update-policy/update.yaml"

  [[ -f "${tpl}" ]]         || { echo "[render-suricata:ERROR] Missing template: ${tpl}" >&2; return 1; }
  [[ -f "${enable_src}" ]]  || { echo "[render-suricata:WARN] Missing enable.conf: ${enable_src}" >&2; }
  [[ -f "${disable_src}" ]] || { echo "[render-suricata:WARN] Missing disable.conf: ${disable_src}" >&2; }

  echo "[render-suricata] ${platform}: ${tpl} -> ${out}"
  if [[ "${dry_run}" != "true" ]]; then
    # Load hardware profile for token substitution.
    # hw-profile.conf is written by 'make preflight' to tier1-perimeter/.hw-profile.
    # Safe defaults if absent (2 GB RAM profile).
    local hw_profile="${t1_dir}/.hw-profile"
    local _suricata_profile="medium"
    local _stream_memcap="64mb"
    local _reassembly_memcap="128mb"
    local _defrag_memcap="32mb"
    if [[ -f "${hw_profile}" ]]; then
      # Read individual keys with grep|cut — never source a router-derived file as shell.
      _suricata_profile="$(grep -m1 '^SURU_HW_SURICATA_PROFILE='           "${hw_profile}" | cut -d= -f2)"
      _stream_memcap="$(grep -m1    '^SURU_HW_SURICATA_STREAM_MEMCAP='      "${hw_profile}" | cut -d= -f2)"
      _reassembly_memcap="$(grep -m1 '^SURU_HW_SURICATA_REASSEMBLY_MEMCAP=' "${hw_profile}" | cut -d= -f2)"
      _defrag_memcap="$(grep -m1    '^SURU_HW_SURICATA_DEFRAG_MEMCAP='      "${hw_profile}" | cut -d= -f2)"
      _suricata_profile="${_suricata_profile:-medium}"
      _stream_memcap="${_stream_memcap:-64mb}"
      _reassembly_memcap="${_reassembly_memcap:-128mb}"
      _defrag_memcap="${_defrag_memcap:-32mb}"
      echo "[render-suricata] hw-profile: profile=${_suricata_profile} stream=${_stream_memcap} reassembly=${_reassembly_memcap} defrag=${_defrag_memcap}"
    else
      echo "[render-suricata] hw-profile not found (${hw_profile}) — using defaults: profile=medium stream=64mb reassembly=128mb defrag=32mb"
    fi

    # Resolve interface list.
    # SURICATA_IFACES (multi): comma-separated, e.g. "lan,opt1" or "eth0,eth1"
    # SURICATA_IFACE  (legacy single): falls back to em0 if both unset.
    local iface_list="${SURICATA_IFACES:-${SURICATA_IFACE:-em0}}"
    IFS=',' read -ra _ifaces <<< "${iface_list}"

    # Build the platform-appropriate capture section.
    # pfsense/opnsense: netmap: (FreeBSD 11+ built-in; af-packet is Linux-only).
    # linux/standalone/default: af-packet: (Linux kernel ring buffer).
    local capture_block
    case "${platform}" in
      pfsense|opnsense)
        # Netmap IDS (sniffer-only): no copy-mode/copy-iface.
        # threads: auto = NIC RSS queue count; equivalent to suricata_get_supported_netmap_queues().
        # checksum-checks: auto handles hardware checksum offloading on FreeBSD igb/em/vmx NICs.
        # FreeBSD: netmap is built into the kernel since FreeBSD 11; kldstat | grep netmap to verify.
        # Note: for pfSense the engine yaml is managed by sync_suricata_package_config().
        # This rendered yaml is not deployed by pfsense.sh — rendered for structural correctness.
        local netmap_entries=""
        for _iface in "${_ifaces[@]}"; do
          _iface="${_iface// /}"; [[ -z "${_iface}" ]] && continue
          netmap_entries+="  - interface: ${_iface}
    threads: auto
    checksum-checks: auto
    disable-promisc: no
    bpf-filter: \"\"
"
        done
        netmap_entries+="  - interface: default
    checksum-checks: auto"
        capture_block="netmap:
${netmap_entries}"
        ;;
      *)
        # Linux AF_PACKET ring buffer — one entry per interface, unique cluster-ids.
        local afpkt_entries=""
        local cluster_id=99
        for _iface in "${_ifaces[@]}"; do
          _iface="${_iface// /}"; [[ -z "${_iface}" ]] && continue
          afpkt_entries+="  - interface: ${_iface}
    cluster-id: ${cluster_id}
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    block-timeout: 10
    use-emergency-flush: yes
    buffer-size: 67108864
    bypass: no
    copy-mode: none
    copy-iface: none
    bpf-filter: \"\"
    threads: auto
"
          cluster_id=$(( cluster_id - 1 ))
        done
        afpkt_entries="${afpkt_entries%$'\n'}"
        capture_block="af-packet:
${afpkt_entries}"
        ;;
    esac

    # Substitute __SURICATA_CAPTURE_SECTION__ placeholder (multi-line block via awk),
    # then substitute the four single-value hw tokens via sed.
    local tmp_block; tmp_block="$(mktemp)"
    printf '%s' "${capture_block}" > "${tmp_block}"
    awk -v block_file="${tmp_block}" '
      /^__SURICATA_CAPTURE_SECTION__$/ {
        while ((getline line < block_file) > 0) print line
        close(block_file)
        next
      }
      { print }
    ' "${tpl}" \
    | sed \
        -e "s/__SURICATA_DETECT_PROFILE__/${_suricata_profile}/g" \
        -e "s/__SURICATA_STREAM_MEMCAP__/${_stream_memcap}/g" \
        -e "s/__SURICATA_REASSEMBLY_MEMCAP__/${_reassembly_memcap}/g" \
        -e "s/__SURICATA_DEFRAG_MEMCAP__/${_defrag_memcap}/g" \
    > "${out}"
    rm -f -- "${tmp_block}"

    echo "[render-suricata] ${platform}: expanded ${#_ifaces[@]} interface(s): ${iface_list}"

    # Copy rule-selection files alongside the yaml
    [[ -f "${enable_src}" ]]  && cp "${enable_src}"  "${rendered}/suricata/enable.conf"
    [[ -f "${disable_src}" ]] && cp "${disable_src}" "${rendered}/suricata/disable.conf"
    [[ -f "${update_src}" ]]  && cp "${update_src}"  "${rendered}/suricata/update.yaml"
  fi
}
