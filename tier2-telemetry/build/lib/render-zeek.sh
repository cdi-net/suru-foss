#!/usr/bin/env bash
# SURU Platform — Zeek render library
# Injects tier2-telemetry/zeek/scripts/*.zeek @load directives into
# tier1-perimeter/templates/zeek/local.zeek.tpl and renders zeekctl.cfg.tpl.
# Output: <rendered>/zeek/local.zeek, <rendered>/zeek/zeekctl.cfg
# Also copies intel/ feed to rendered/
# Called by: tier2-telemetry/build/render.sh

render_zeek() {
  local platform="$1" t1_dir="$2" t2_dir="$3" rendered="$4" dry_run="$5"

  local tpl="${t1_dir}/templates/zeek/local.zeek.tpl"
  local zeekctl_tpl="${t1_dir}/templates/zeek/zeekctl.cfg.tpl"
  local scripts_dir="${t2_dir}/zeek/scripts"
  local intel_dir="${t2_dir}/zeek/intel"
  local out="${rendered}/zeek/local.zeek"
  local zeekctl_out="${rendered}/zeek/zeekctl.cfg"

  [[ -f "${tpl}" ]] || { echo "[render-zeek:ERROR] Missing template: ${tpl}" >&2; return 1; }

  echo "[render-zeek] ${platform}: ${tpl} -> ${out}"
  if [[ "${dry_run}" != "true" ]]; then
    # Build @load directives for every .zeek script in T2
    local load_lines=""
    if [[ -d "${scripts_dir}" ]]; then
      for script in "${scripts_dir}"/*.zeek; do
        [[ -f "${script}" ]] || continue
        local basename; basename="$(basename "${script}" .zeek)"
        # Use site/<name> so Zeek resolves via ZEEKPATH (/usr/local/share/zeek).
        # Bare `@load <name>` does NOT resolve from site/ — ZEEKPATH only includes
        # the top-level share/zeek dir, not share/zeek/site.
        load_lines+="@load site/${basename}\n"
      done
    fi

    # Substitute __ZEEK_SCRIPTS__ and __ZEEK_IFACE__ placeholders.
    # ZEEK_IFACE: physical trunk interface (e.g. igb1). Defaults to em0.
    # Use the parent trunk, not a VLAN sub-interface — Zeek handles 802.1Q natively.
    local zeek_iface_val="${ZEEK_IFACE:-em0}"
    # ZEEK_LOG_MDNS: true keeps mDNS/5353 records in dns.log; default
    # (unset/anything-but-true) drops them. Normalised to a Zeek bool literal
    # so the rendered `redef SURU_Telemetry::log_mdns = <T|F>;` always parses.
    local zeek_log_mdns_val="F"
    [[ "${ZEEK_LOG_MDNS:-false}" == "true" ]] && zeek_log_mdns_val="T"
    sed "s|__ZEEK_SCRIPTS__|${load_lines}|g; s|__ZEEK_IFACE__|${zeek_iface_val}|g; s|__ZEEK_LOG_MDNS__|${zeek_log_mdns_val}|g" "${tpl}" > "${out}"

    # Render zeekctl.cfg — substitute __ZEEK_MAILTO__.
    # ZEEK_MAILTO defaults to root (local delivery; no relay required).
    if [[ -f "${zeekctl_tpl}" ]]; then
      echo "[render-zeek] ${platform}: ${zeekctl_tpl} -> ${zeekctl_out}"
      local zeek_mailto_val="${ZEEK_MAILTO:-root}"
      sed "s|__ZEEK_MAILTO__|${zeek_mailto_val}|g" "${zeekctl_tpl}" > "${zeekctl_out}"
    fi

    # Copy detection scripts so pfsense.sh can deploy them to site/scripts/
    # Clean first to remove stale files from previous renders.
    if [[ -d "${scripts_dir}" ]]; then
      rm -rf "${rendered}/zeek/scripts"
      mkdir -p "${rendered}/zeek/scripts"
      cp "${scripts_dir}"/*.zeek "${rendered}/zeek/scripts/"
    fi

    # Copy intel feed
    if [[ -d "${intel_dir}" ]]; then
      mkdir -p "${rendered}/zeek/intel"
      cp -r "${intel_dir}/"* "${rendered}/zeek/intel/"
    fi
  fi
}
