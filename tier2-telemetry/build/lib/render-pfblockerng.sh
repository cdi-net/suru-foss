#!/usr/bin/env bash
# SURU Platform — pfBlockerNG render library
# Reads tier2-telemetry/pfblockerng/categories/dnsbl-categories.yml and emits
# the PHP applier that writes the DNSBL feed set into pfSense's
# installedpackages/pfblockerngdnsbl/config via config_set_path / write_config.
# Output: <rendered>/pfblockerng/pfblockerng-import.php
# Called by: tier2-telemetry/build/render.sh
#
# Note: previous versions also emitted <rendered>/pfblockerng/pfblockerng.xml
# from tier1-perimeter/templates/pfsense/pfblockerng.xml.tpl. That file was
# never consumed by anything on the router — the PHP importer below is the
# only artefact that mutates pfSense state. The XML output and its template
# were removed.
#
# Arithmetic note: all (( expr )) replaced with x=$(( expr )) to avoid
# set -e treating arithmetic-result-0 as an error exit.

# ---------------------------------------------------------------------------
# _yq_field <file> <yq_path>
# ---------------------------------------------------------------------------
_yq_field() {
  local file="$1" path="$2" val
  val="$(yq eval "${path}" "${file}" 2>/dev/null || true)"
  [[ "${val}" == "null" ]] && val=""
  printf '%s' "${val}"
}

_yq_feed_count() {
  local file="$1" n
  n="$(yq eval '.feeds | length' "${file}" 2>/dev/null || true)"
  [[ -z "${n}" ]] && n=0
  printf '%s' "${n}"
}

# ---------------------------------------------------------------------------
# Pure-bash YAML parser fallback
# ---------------------------------------------------------------------------
_yaml_get_feed_field() {
  local file="$1" idx="$2" field="$3"
  local in_feeds=0 feed_count=-1
  while IFS= read -r line; do
    [[ "${line}" =~ ^feeds: ]] && { in_feeds=1; continue; }
    [[ ${in_feeds} -eq 0 ]] && continue
    if [[ "${line}" =~ ^[[:space:]]*-[[:space:]] ]]; then
      feed_count=$(( feed_count + 1 ))
      if [[ ${feed_count} -eq ${idx} ]]; then
        local inline="${line#*- }"
        if [[ "${inline}" =~ ^${field}:[[:space:]]*(.*) ]]; then
          local val="${BASH_REMATCH[1]}"
          val="${val#\"}" ; val="${val%\"}"
          val="${val#\'}"  ; val="${val%\'}"
          printf '%s' "${val}"; return 0
        fi
      fi
      continue
    fi
    if [[ ${feed_count} -eq ${idx} ]] && [[ "${line}" =~ ^[[:space:]]+([a-zA-Z_]+):[[:space:]]*(.*) ]]; then
      local key="${BASH_REMATCH[1]}" val="${BASH_REMATCH[2]}"
      if [[ "${key}" == "${field}" ]]; then
        val="${val#\"}" ; val="${val%\"}"
        val="${val#\'}"  ; val="${val%\'}"
        printf '%s' "${val}"; return 0
      fi
    fi
  done < "${file}"
  return 0  # not found -> empty; caller uses || echo default
}

_yaml_count_feeds() {
  local file="$1" count=0 in_feeds=0
  while IFS= read -r line; do
    [[ "${line}" =~ ^feeds: ]] && { in_feeds=1; continue; }
    [[ ${in_feeds} -eq 0 ]] && continue
    if [[ "${line}" =~ ^[[:space:]]*-[[:space:]] ]]; then
      count=$(( count + 1 ))
    fi
  done < "${file}"
  printf '%s' "${count}"
}

# ---------------------------------------------------------------------------
# _php_esc <string>
# Escape a string for safe embedding inside a PHP single-quoted literal.
# PHP single-quoted strings treat only \\ and \' as escape sequences:
#   1. escape every backslash  \  -> \\   (must be done first)
#   2. escape every single quote ' -> \'
# The two-step order matters: doing quotes first would double-escape the
# backslashes added by step 1.
# ---------------------------------------------------------------------------
_php_esc() { printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g"; }

# ---------------------------------------------------------------------------
# _generate_php_importer <dnsbl_yml>
# Emits a PHP script that writes pfBlockerNG DNSBL feeds into pfSense
# config using config_set_path / write_config (the correct pfSense API).
# The script merges SURU feeds by aliasname, preserving any existing
# entries not managed by SURU.
# ---------------------------------------------------------------------------
_generate_php_importer() {
  local yml="$1"
  local count i
  if command -v yq > /dev/null 2>&1; then
    count="$(_yq_feed_count "${yml}")"
  else
    count="$(_yaml_count_feeds "${yml}")"
  fi

  printf '<?php\nrequire_once("config.lib.inc");\nrequire_once("pkg-utils.inc");\n$dnsbl_feeds = [];\n'

  i=0
  while [[ ${i} -lt ${count} ]]; do
    local aliasname action url format state blocking
    if command -v yq > /dev/null 2>&1; then
      aliasname="$( _yq_field "${yml}" ".feeds[${i}].aliasname" )"
      action="$(    _yq_field "${yml}" ".feeds[${i}].action"    )"
      url="$(       _yq_field "${yml}" ".feeds[${i}].url"       )"
      format="$(    _yq_field "${yml}" ".feeds[${i}].format"    )"
      state="$(     _yq_field "${yml}" ".feeds[${i}].state"     )"
      blocking="$(  _yq_field "${yml}" ".feeds[${i}].blocking"  )"
    else
      aliasname="$( _yaml_get_feed_field "${yml}" ${i} aliasname || true )"
      action="$(    _yaml_get_feed_field "${yml}" ${i} action    || true )"
      url="$(       _yaml_get_feed_field "${yml}" ${i} url       || true )"
      format="$(    _yaml_get_feed_field "${yml}" ${i} format    || true )"
      state="$(     _yaml_get_feed_field "${yml}" ${i} state     || true )"
      blocking="$(  _yaml_get_feed_field "${yml}" ${i} blocking  || true )"
    fi
    [[ -z "${aliasname}" ]] && aliasname="FEED_${i}"
    # DNSBL alias action MUST be "unbound" — pfBlockerNG's cron list-builder
    # (pfblockerng.inc) only queues an alias for DNSBL download/compile when
    # action=='unbound'; any other value (e.g. an IP-alias-style "Deny Both")
    # silently routes it into the IP-deny build path instead, where domain
    # content never downloads. See dnsbl-categories.yml header for the
    # live-router evidence behind this rule.
    [[ -z "${action}" ]]    && action="unbound"
    [[ -z "${format}" ]]    && format="Domain"
    [[ -z "${state}" ]]     && state="Enabled"
    # Per-feed `blocking` -> pfBlockerNG per-group Logging/Blocking Mode
    # (pfblockerng_dnsbl.php). Default is Null Block (logging): blocked
    # domains answer 0.0.0.0 and clients fail in milliseconds — a block must
    # fail closed AND fast, never a black hole. 'vip' (Blocked Webpage/VIP)
    # is opt-in only and requires the VIP to be TCP-reachable from client
    # LANs (verify-pfblockerng-feeds.sh probes it). See the
    # dnsbl-categories.yml header for the incident evidence behind this rule.
    [[ -z "${blocking}" ]]  && blocking="null_log"
    local logging_mode
    case "${blocking}" in
      null_log) logging_mode="disabled_log" ;;
      null)     logging_mode="disabled"     ;;
      vip)      logging_mode="enabled"      ;;
      *)
        printf '[render-pfblockerng] ERROR: feed %s has invalid blocking: %s (valid: null_log | null | vip)\n' \
          "${aliasname}" "${blocking}" >&2
        exit 1
        ;;
    esac
    # Escape every field for safe embedding in PHP single-quoted strings (see _php_esc).
    local alias_esc; alias_esc="$(_php_esc "${aliasname}")"
    local action_esc; action_esc="$(_php_esc "${action}")"
    local url_esc; url_esc="$(_php_esc "${url}")"
    local fmt_esc; fmt_esc="$(_php_esc "${format}")"
    local state_esc; state_esc="$(_php_esc "${state}")"
    printf "\$dnsbl_feeds[] = ['aliasname'=>'%s','action'=>'%s','logging'=>'%s','row'=>[['header'=>'%s','url'=>'%s','format'=>'%s','state'=>'%s']]];\n" \
      "${alias_esc}" "${action_esc}" "${logging_mode}" "${alias_esc}" "${url_esc}" "${fmt_esc}" "${state_esc}"
    i=$(( i + 1 ))
  done

  # Merge-by-aliasname: preserves existing non-SURU entries, and prunes any
  # SURU_-prefixed entry that is no longer in this YAML — without this, a
  # feed removed from dnsbl-categories.yml (e.g. a dead/deprecated URL)
  # lingers in pfSense's config.xml forever with whatever stale action/url
  # it last had, since the original merge only ever added/overwrote keys
  # and never deleted any. Live-confirmed 2026-06-23: SURU_ET_DNSBL and
  # SURU_PhishTank, both removed from dnsbl-categories.yml in the same PR
  # that fixed the action='unbound' bug, were still present post-deploy
  # with their old broken action="Deny Both".
  printf '%s\n' \
    'global $config;' \
    '$dnsbl_existing = config_get_path("installedpackages/pfblockerngdnsbl/config", []);' \
    '$dnsbl_desired = array_map(function ($f) { return $f["aliasname"]; }, $dnsbl_feeds);' \
    '$dnsbl_by_alias = [];' \
    'foreach ($dnsbl_existing as $e) {' \
    '  $is_suru = (strpos($e["aliasname"], "SURU_") === 0);' \
    '  if ($is_suru && !in_array($e["aliasname"], $dnsbl_desired, true)) { continue; }' \
    '  $dnsbl_by_alias[$e["aliasname"]] = $e;' \
    '}' \
    'foreach ($dnsbl_feeds as $f)    { $dnsbl_by_alias[$f["aliasname"]] = $f; }' \
    'config_set_path("installedpackages/pfblockerngdnsbl/config", array_values($dnsbl_by_alias));' \
    'write_config("SURU: imported pfBlockerNG DNSBL feeds");' \
    '$dnsbl_written = config_get_path("installedpackages/pfblockerngdnsbl/config", []);' \
    'echo "[pfblockerng] Wrote " . count($dnsbl_written) . " DNSBL feed entries:" . PHP_EOL;' \
    'foreach ($dnsbl_written as $e) { echo "  " . $e["aliasname"] . " - " . $e["action"] . " - " . ($e["logging"] ?? "?") . PHP_EOL; }'
}

# ---------------------------------------------------------------------------
# _generate_php_importer_ip <ip_yml>
# Appends a PHP block to the importer that writes pfBlockerNG IPv4 aliases
# into installedpackages/pfblockernglistsv4/config. Schema is nested:
#   .aliases[N].{aliasname,description,action,cron,feeds[]}
#   .aliases[N].feeds[M].{header,url,format,state}
# yq is required for this path (nested YAML). Falls through to a WARN-only
# no-op if yq is missing — the dev/CI hosts auto-install yq via render.sh
# so this should never actually skip in normal runs.
# ---------------------------------------------------------------------------
_generate_php_importer_ip() {
  local yml="$1"

  if ! command -v yq > /dev/null 2>&1; then
    echo "[render-pfblockerng:WARN] yq not available — skipping IPv4 alias emission (nested YAML requires yq)" >&2
    return 0
  fi

  local alias_count
  alias_count="$(yq eval '.aliases | length' "${yml}" 2>/dev/null || true)"
  [[ -z "${alias_count}" || "${alias_count}" == "null" ]] && alias_count=0
  if [[ "${alias_count}" -eq 0 ]]; then
    echo "[render-pfblockerng:WARN] ${yml} declared 0 aliases — IPv4 section will be empty" >&2
  fi

  printf '\n// === SURU pfBlockerNG IPv4 aliases ===\n$ipv4_aliases = [];\n'

  local i=0
  while [[ ${i} -lt ${alias_count} ]]; do
    local aliasname description action cron logging
    aliasname="$(  _yq_field "${yml}" ".aliases[${i}].aliasname"   )"
    description="$(_yq_field "${yml}" ".aliases[${i}].description" )"
    action="$(     _yq_field "${yml}" ".aliases[${i}].action"      )"
    cron="$(       _yq_field "${yml}" ".aliases[${i}].cron"        )"
    [[ -z "${aliasname}" ]]   && aliasname="SURU_IP_${i}"
    [[ -z "${action}" ]]      && action="Deny_Both"
    [[ -z "${cron}" ]]        && cron="EveryDay"
    [[ -z "${description}" ]] && description="${aliasname}"
    logging="enabled"

    # Escape every field for safe embedding in PHP single-quoted strings.
    # _php_esc escapes backslash *then* single-quote (correct order); the old
    # ${var//\'/\\\'} form escaped ' but not a trailing \, reopening the same
    # single-quote break-out the DNSBL importer above already guards against.
    local alias_esc; alias_esc="$(_php_esc "${aliasname}")"
    local desc_esc; desc_esc="$(_php_esc "${description}")"
    local action_esc; action_esc="$(_php_esc "${action}")"
    local cron_esc; cron_esc="$(_php_esc "${cron}")"

    # Open the alias entry. We emit all fields the pfBlockerNG package writes
    # on a GUI save; omitting some causes the GUI to show empty cells but no
    # functional break. Auto* fields are left blank — pfBlockerNG fills them
    # during its next list-build cron run.
    printf "\$ipv4_aliases[] = [\n"
    printf "  'aliasname'    => '%s',\n" "${alias_esc}"
    printf "  'description'  => '%s',\n" "${desc_esc}"
    printf "  'action'       => '%s',\n" "${action_esc}"
    printf "  'cron'         => '%s',\n" "${cron_esc}"
    printf "  'aliaslog'     => '%s',\n" "${logging}"
    printf "  'stateremoval' => 'enabled',\n"
    printf "  'row'          => [\n"

    local feed_count
    feed_count="$(yq eval ".aliases[${i}].feeds | length" "${yml}" 2>/dev/null || true)"
    [[ -z "${feed_count}" || "${feed_count}" == "null" ]] && feed_count=0
    local j=0
    while [[ ${j} -lt ${feed_count} ]]; do
      local header url format state
      header="$(_yq_field "${yml}" ".aliases[${i}].feeds[${j}].header")"
      url="$(   _yq_field "${yml}" ".aliases[${i}].feeds[${j}].url"   )"
      format="$(_yq_field "${yml}" ".aliases[${i}].feeds[${j}].format")"
      state="$( _yq_field "${yml}" ".aliases[${i}].feeds[${j}].state" )"
      [[ -z "${header}" ]] && header="${aliasname}_${j}"
      [[ -z "${format}" ]] && format="auto"
      [[ -z "${state}" ]]  && state="Enabled"
      # Escape all four feed fields via _php_esc (backslash-then-quote). The
      # prior ${var//\'/\\\'} form left format/state unescaped entirely and
      # url/header vulnerable to a trailing-backslash break-out.
      local url_esc; url_esc="$(_php_esc "${url}")"
      local hdr_esc; hdr_esc="$(_php_esc "${header}")"
      local fmt_esc; fmt_esc="$(_php_esc "${format}")"
      local state_esc; state_esc="$(_php_esc "${state}")"
      printf "    ['format'=>'%s','state'=>'%s','url'=>'%s','header'=>'%s'],\n" \
        "${fmt_esc}" "${state_esc}" "${url_esc}" "${hdr_esc}"
      j=$(( j + 1 ))
    done

    printf "  ],\n"
    printf "];\n"
    i=$(( i + 1 ))
  done

  # Merge-by-aliasname: same stale-SURU_-entry pruning as the DNSBL importer
  # above (see its comment) — without this, a removed alias like
  # SURU_SSLBL or SURU_TalosBL lingers in config.xml forever.
  printf '%s\n' \
    '$ipv4_existing = config_get_path("installedpackages/pfblockernglistsv4/config", []);' \
    '$ipv4_desired = array_map(function ($a) { return $a["aliasname"]; }, $ipv4_aliases);' \
    '$ipv4_by_alias = [];' \
    'foreach ($ipv4_existing as $e) {' \
    '  $is_suru = (strpos($e["aliasname"], "SURU_") === 0);' \
    '  if ($is_suru && !in_array($e["aliasname"], $ipv4_desired, true)) { continue; }' \
    '  $ipv4_by_alias[$e["aliasname"]] = $e;' \
    '}' \
    'foreach ($ipv4_aliases as $a)  { $ipv4_by_alias[$a["aliasname"]] = $a; }' \
    'config_set_path("installedpackages/pfblockernglistsv4/config", array_values($ipv4_by_alias));' \
    'write_config("SURU: imported pfBlockerNG IPv4 aliases");' \
    '$ipv4_written = config_get_path("installedpackages/pfblockernglistsv4/config", []);' \
    'echo "[pfblockerng] Wrote " . count($ipv4_written) . " IPv4 alias entries:" . PHP_EOL;' \
    'foreach ($ipv4_written as $a) { echo "  " . $a["aliasname"] . " - " . $a["action"] . " (" . count($a["row"]) . " feeds)" . PHP_EOL; }'
}

# ---------------------------------------------------------------------------
# render_pfblockerng
# ---------------------------------------------------------------------------
render_pfblockerng() {
  local platform="$1" t2_dir="$2" rendered="$3" dry_run="$4"

  local dnsbl_yml="${t2_dir}/pfblockerng/categories/dnsbl-categories.yml"
  local ip_yml="${t2_dir}/pfblockerng/categories/ip-categories.yml"
  local php_out="${rendered}/pfblockerng/pfblockerng-import.php"

  if [[ "${platform}" != "pfsense" ]]; then
    echo "[render-pfblockerng] Skipping pfBlockerNG for non-pfSense platform: ${platform}"
    return 0
  fi

  [[ -f "${dnsbl_yml}" ]] || { echo "[render-pfblockerng:ERROR] Missing DNSBL categories: ${dnsbl_yml}" >&2; return 1; }
  [[ -f "${ip_yml}" ]]    || echo "[render-pfblockerng:WARN] Missing IP categories: ${ip_yml} (IPv4 aliases skipped)" >&2

  echo "[render-pfblockerng] ${platform}: ${dnsbl_yml} -> ${php_out}"

  if [[ "${dry_run}" != "true" ]]; then
    # Emit the combined PHP importer: DNSBL feeds (always) + IPv4 aliases
    # (when ip-categories.yml is present and yq is available). Both blocks
    # share the importer file; each calls its own write_config() so a
    # partial run still leaves config.xml consistent for whichever block
    # succeeded.
    _generate_php_importer "${dnsbl_yml}" > "${php_out}"
    if [[ -f "${ip_yml}" ]]; then
      _generate_php_importer_ip "${ip_yml}" >> "${php_out}"
    fi
    echo "[render-pfblockerng] Written: ${php_out}"
  fi
}
