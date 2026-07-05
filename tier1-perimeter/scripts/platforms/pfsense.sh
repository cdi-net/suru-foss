#!/usr/bin/env bash
# SURU Platform — pfSense platform driver
# Called by deploy.sh. Pushes rendered artefacts to pfSense via SSH/SCP.
#
# INVARIANT 11: This script contains NO security policy.
# Path constants point to rendered/ — populated by tier2-telemetry/build/render.sh.
#
# Environment variables (all required unless defaulted):
#   ROUTER_HOST, ROUTER_SSH_USER, ROUTER_SSH_KEY, SSH_STRICT_HOST_KEY_CHECKING,
#   FRONTDOOR_SYSLOG_SNI, FRONTDOOR_PORT, SENSOR_NAME, WAN_IFACE, LAN_IFACE
#
# SCP PRIVILEGE MODEL — pfSense
# ==============================
# pfSense's admin user has SSH shell access but cannot write to /usr/local/etc/
# or /usr/local/share/ via SCP directly (Permission denied). The correct pattern:
#
#   1. SCP file to /tmp/suru-staging/ (world-writable, admin-accessible)
#   2. Move into final location using pfSsh.php (runs as root via PHP CLI)
#
# _pf_stage_and_install() implements this two-step for every protected path.
# /tmp/suru-staging/ is created at deploy start and cleaned up on EXIT.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PF_TEMPLATES_DIR="$(cd "${SCRIPT_DIR}/../../templates" && pwd)"

# Source REST API client. Self-contained — no other lib deps required.
# Provides: api_init, api_health, api_validate_deployment,
#           api_pfsense_install (first-package install), api_fetch_errors,
#           api_reload_suricata_rules.
# shellcheck source=../lib/api.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/api.sh"

# --- Rendered artefact paths (source: tier1-perimeter/rendered/pfsense/) ------
_PF_RENDERED_SURICATA_YAML="suricata/suricata.yaml"
_PF_RENDERED_SURICATA_ENABLE="suricata/enable.conf"
_PF_RENDERED_SURICATA_DISABLE="suricata/disable.conf"
_PF_RENDERED_SURICATA_UPDATE="suricata/update.yaml"
_PF_RENDERED_PFBLOCKER_PHP="pfblockerng/pfblockerng-import.php"

# Static PHP applier for pfBlockerNG global baseline. Version-controlled in
# tier1-perimeter/pfsense/. Writes installedpackages/pfblockerng/config/0
# (master enable, update cadence) and
# installedpackages/pfblockerngdnsblsettings/config/0 (DNSBL feature defaults).
# Conservative: only touches SURU-claimed keys, preserves operator settings
# for interface bindings, listener ports, custom TLDs etc.
_PF_APPLIER_PFB_GLOBALS="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/pfblockerng-globals-apply.php"
_PF_RENDERED_ZEEK_LOCAL="zeek/local.zeek"
_PF_RENDERED_ZEEK_CTRL="zeek/zeekctl.cfg"
_PF_RENDERED_ZEEK_SCRIPTS_DIR="zeek/scripts"
_PF_RENDERED_ZEEK_INTEL_DIR="zeek/intel"
_PF_SYSLOGNG_TPL="${_PF_TEMPLATES_DIR}/pfsense/syslog-ng.conf.tpl"

# Static PHP appliers — version-controlled in tier1-perimeter/pfsense/.
# These mutate /conf/config.xml via the same APIs the pfSense GUI uses
# (config_set_path + write_config + the package resync fn), so deployed
# configuration is reflected in the GUI and survives subsequent user
# GUI saves on the corresponding pages.
_PF_APPLIER_SYSLOGNG="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/syslog-ng-apply.php"
_PF_APPLIER_ZEEK="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/zeek-scripts-apply.php"
_PF_APPLIER_ZEEK_IFACE="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/zeek-iface-apply.php"
_PF_APPLIER_SURICATA="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-rules-apply.php"
_PF_LIB_IFACE_RESOLVE="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suru-iface-resolve.php"
_PF_APPLIER_BACKUP="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/backup-encrypt.php"
_PF_APPLIER_RESTORE="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/backup-restore.php"
_PF_APPLIER_SURICATA_TUNING="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-tuning-apply.php"
_PF_APPLIER_SURICATA_DROP="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-drop-policy-apply.php"
_PF_APPLIER_SURICATA_SAFETY_REVERT="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-safety-revert.php"
_PF_APPLIER_PF_TUNING="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/pf-tuning-apply.php"
_PF_APPLIER_DNS_TUNING="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/dns-tuning-apply.php"

# Remote location for encrypted backups (router-side). Persists across deploys
# so the operator has on-router history even when a local pull fails.
_PF_REMOTE_BACKUP_DIR="/root/suru-backups"
# Local mirror — pulled via SCP after each successful encrypt. Files are
# AES-256-CBC + PBKDF2 (sha256, 500_000 iter) and restorable via pfSense
# Diagnostics > Backup & Restore (check "Encrypted") with the same password.
_PF_LOCAL_BACKUP_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/backups"

# --- Remote target paths on pfSense device ------------------------------------
_PF_REMOTE_SURICATA_CONF="/usr/local/etc/suricata/suricata.yaml"
_PF_REMOTE_SURICATA_UPDATE="/usr/local/etc/suricata/update.yaml"
_PF_REMOTE_SYSLOGNG_CONF="/usr/local/etc/syslog-ng.conf"
_PF_REMOTE_ZEEK_LOCAL="/usr/local/share/zeek/site/local.zeek"
_PF_REMOTE_ZEEK_CTRL="/usr/local/etc/zeekctl.cfg"
_PF_REMOTE_ZEEK_SCRIPTS_DIR="/usr/local/share/zeek/site/scripts"
_PF_REMOTE_ZEEK_INTEL_DIR="/usr/local/share/zeek/intel"

# Remote staging directory — writable by admin, cleaned up after deploy
_PF_REMOTE_STAGING="/tmp/suru-staging"

_platform_deploy() {
  local target="$1" rendered="$2" dry_run="$3"
  local ssh_key="${ROUTER_SSH_KEY:-~/.ssh/suru_deploy}"
  local ssh_user="${ROUTER_SSH_USER:-admin}"  # pfSense default user is admin

  # SSH_STRICT_HOST_KEY_CHECKING: controls StrictHostKeyChecking behaviour.
  # Precedence: .env / env var > OS default.
  # macOS default: accept-new  (convenient for lab/SOHO first-connect)
  # Linux default:  yes         (strict; production-safe)
  local _strict_default
  case "$(uname -s)" in
    Darwin) _strict_default="accept-new" ;;
    *)      _strict_default="yes" ;;
  esac
  local _strict="${SSH_STRICT_HOST_KEY_CHECKING:-${_strict_default}}"
  case "$(echo "${_strict}" | tr '[:upper:]' '[:lower:]')" in
    yes|true|strict)       _strict="yes" ;;
    no|false|accept-new)   _strict="accept-new" ;;
    off|none)              _strict="no" ;;
  esac

  local -a ssh_opts=(-i "${ssh_key}" -o "StrictHostKeyChecking=${_strict}" -o "BatchMode=yes" -o "ConnectTimeout=15")

  # --- Hardware profile — load operator-reconciled values from hw-profile.conf ---
  # Written by 'make preflight' (tier1-perimeter/.hw-profile). Safe defaults when
  # absent so deploy does not break on first-run before preflight has been run.
  # Defaults match the 4 GB RAM / 4-core profile to stay conservative.
  local _hw_pf_table_entries="800000"
  local _hw_pf_max_states="400000"
  local _hw_zeek_lb_procs="2"
  local _hw_suricata_profile="medium"
  local _hw_suricata_stream_memcap="64mb"
  local _hw_suricata_reassembly_memcap="128mb"
  local _hw_suricata_defrag_memcap="32mb"
  local _hw_syslogng_disk_buf_bytes="4294967296"   # 4 GB default
  local _hw_unbound_msg_cache_mb="50"
  local _hw_unbound_rrset_cache_mb="100"
  local _hw_profile="${TIER1_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}/.hw-profile"
  if [[ -f "${_hw_profile}" ]]; then
    # Read individual keys with grep|cut — never source a router-derived file as shell.
    _hw_pf_table_entries="$(grep -m1        '^SURU_HW_PF_TABLE_ENTRIES='              "${_hw_profile}" | cut -d= -f2)"
    _hw_pf_max_states="$(grep -m1           '^SURU_HW_PF_MAX_STATES='                 "${_hw_profile}" | cut -d= -f2)"
    _hw_zeek_lb_procs="$(grep -m1           '^SURU_HW_ZEEK_LB_PROCS='                 "${_hw_profile}" | cut -d= -f2)"
    _hw_suricata_profile="$(grep -m1        '^SURU_HW_SURICATA_PROFILE='              "${_hw_profile}" | cut -d= -f2)"
    _hw_suricata_stream_memcap="$(grep -m1  '^SURU_HW_SURICATA_STREAM_MEMCAP='        "${_hw_profile}" | cut -d= -f2)"
    _hw_suricata_reassembly_memcap="$(grep -m1 '^SURU_HW_SURICATA_REASSEMBLY_MEMCAP=' "${_hw_profile}" | cut -d= -f2)"
    _hw_suricata_defrag_memcap="$(grep -m1  '^SURU_HW_SURICATA_DEFRAG_MEMCAP='        "${_hw_profile}" | cut -d= -f2)"
    _hw_syslogng_disk_buf_bytes="$(grep -m1 '^SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES='   "${_hw_profile}" | cut -d= -f2)"
    _hw_unbound_msg_cache_mb="$(grep -m1    '^SURU_HW_UNBOUND_MSG_CACHE_MB='          "${_hw_profile}" | cut -d= -f2)"
    _hw_unbound_rrset_cache_mb="$(grep -m1  '^SURU_HW_UNBOUND_RRSET_CACHE_MB='        "${_hw_profile}" | cut -d= -f2)"
    _hw_pf_table_entries="${_hw_pf_table_entries:-800000}"
    _hw_pf_max_states="${_hw_pf_max_states:-400000}"
    _hw_zeek_lb_procs="${_hw_zeek_lb_procs:-2}"
    _hw_suricata_profile="${_hw_suricata_profile:-medium}"
    _hw_suricata_stream_memcap="${_hw_suricata_stream_memcap:-64mb}"
    _hw_suricata_reassembly_memcap="${_hw_suricata_reassembly_memcap:-128mb}"
    _hw_suricata_defrag_memcap="${_hw_suricata_defrag_memcap:-32mb}"
    _hw_syslogng_disk_buf_bytes="${_hw_syslogng_disk_buf_bytes:-4294967296}"
    _hw_unbound_msg_cache_mb="${_hw_unbound_msg_cache_mb:-50}"
    _hw_unbound_rrset_cache_mb="${_hw_unbound_rrset_cache_mb:-100}"
    echo "[pfsense] hw-profile: pf_table_entries=${_hw_pf_table_entries} pf_max_states=${_hw_pf_max_states} zeek_lb_procs=${_hw_zeek_lb_procs} suricata=${_hw_suricata_profile} stream=${_hw_suricata_stream_memcap} reassembly=${_hw_suricata_reassembly_memcap} defrag=${_hw_suricata_defrag_memcap} sng_buf_bytes=${_hw_syslogng_disk_buf_bytes} unbound_msg=${_hw_unbound_msg_cache_mb}MB rrset=${_hw_unbound_rrset_cache_mb}MB"
  else
    echo "[pfsense] hw-profile not found (${_hw_profile}) — using defaults: pf_table_entries=${_hw_pf_table_entries} pf_max_states=${_hw_pf_max_states} zeek_lb_procs=${_hw_zeek_lb_procs} suricata_profile=${_hw_suricata_profile}"
    echo "[pfsense]   Run 'make preflight' to detect hardware and write hw-profile."
  fi

  # --- Internal helpers -------------------------------------------------------

  # _pf_svc_restart SERVICE
  # Restart a pfSense service using the official pfSense CLI API:
  #   pfSsh.php playback svc restart <service>
  #
  # This is the documented, stable interface for pfSense 2.x (all versions
  # including 2.8) — equivalent to clicking restart in Status > Services.
  # Ref: https://docs.netgate.com/pfsense/en/latest/development/php-shell.html
  #
  # NOTE: pluginctl is an OPNsense tool — do NOT use it for pfSense.
  # NOTE: 'service onerestart' is a raw FreeBSD fallback, not pfSense-aware.
  _pf_svc_restart() {
    local svc="$1"
    echo "[pfsense] Restarting service: ${svc}"
    if [[ "${dry_run}" == "true" ]]; then
      echo "[pfsense] SSH (dry-run): pfSsh.php playback svc restart ${svc}"
      return 0
    fi
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
      "pfSsh.php playback svc restart ${svc}"
  }

  _pf_remote_exec() {
    echo "[pfsense] SSH: $*"
    if [[ "${dry_run}" != "true" ]]; then
      # shellcheck disable=SC2029
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "$@"
    fi
  }

  # --------------------------------------------------------------------
  # Encrypted backup + revert
  # --------------------------------------------------------------------
  # Captured filename for revert. Set by _pf_backup; consumed by _pf_revert
  # (auto-fired by the ERR trap installed just before deploy steps).
  local _pf_backup_local="" _pf_backup_remote="" _pf_pass_remote=""

  # _pf_write_password_file — write SURU_BACKUP_PASSWORD to a 0600 file
  # under /dev/shm when available (tmpfs, not paged to disk). Falls back to
  # /tmp. Echoes the path. The caller (driver) is responsible for unlinking
  # the local copy; the remote copy is unlinked at the end of _pf_backup
  # and again on cleanup trap.
  _pf_write_password_file() {
    if [[ -z "${SURU_BACKUP_PASSWORD:-}" ]]; then
      echo "[pfsense] ERROR: SURU_BACKUP_PASSWORD is unset — refusing to deploy without an" >&2
      echo "[pfsense]        encrypted backup. Set it in .env (preferably SOPS-encrypted) or" >&2
      echo "[pfsense]        export inline. The password is required to encrypt /conf/config.xml" >&2
      echo "[pfsense]        before any deploy step modifies it." >&2
      return 1
    fi
    local dir="/dev/shm"
    [[ -d "${dir}" && -w "${dir}" ]] || dir="${TMPDIR:-/tmp}"
    local path="${dir}/.suru-bkpass.$$"
    ( umask 077; printf '%s' "${SURU_BACKUP_PASSWORD}" > "${path}" )
    echo "${path}"
  }

  # _pf_backup — pre-deploy snapshot of /conf/config.xml.
  # Encrypts on the router using crypt.inc's encrypt_data + tagfile_reformat
  # (the same code path GUI > Diagnostics > Backup & Restore runs with the
  # "Encrypt this configuration file" checkbox), then SCP-pulls the result
  # into tier1-perimeter/backups/. Returns non-zero on any failure — deploy
  # MUST refuse to proceed if backup fails.
  _pf_backup() {
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local fname="pfsense-config.xml.suru-${ts}.bak"
    _pf_backup_remote="${_PF_REMOTE_BACKUP_DIR}/${fname}"
    _pf_backup_local="${_PF_LOCAL_BACKUP_DIR}/${fname}"
    local stage_applier="${_PF_REMOTE_STAGING}/backup-encrypt.php"
    local pass_local pass_stage
    pass_stage="${_PF_REMOTE_STAGING}/.suru-bkpass"

    echo "[pfsense] === Backup: encrypting /conf/config.xml ==="

    if ! pass_local="$(_pf_write_password_file)"; then
      return 1
    fi

    if [[ "${dry_run}" == "true" ]]; then
      echo "[pfsense] (dry-run) Would encrypt /conf/config.xml -> ${_pf_backup_remote}"
      echo "[pfsense] (dry-run) Would SCP-pull -> ${_pf_backup_local}"
      rm -f -- "${pass_local}"
      return 0
    fi

    # Stage applier + password file (the password file is 0600 on the router
    # too; we scp first then chmod via PHP's umask isn't reliable across
    # implementations, so we explicitly chmod after copy).
    scp "${ssh_opts[@]}" "${_PF_APPLIER_BACKUP}" "${ssh_user}@${target}:${stage_applier}" \
      || { rm -f -- "${pass_local}"; return 1; }
    scp "${ssh_opts[@]}" "${pass_local}" "${ssh_user}@${target}:${pass_stage}" \
      || { rm -f -- "${pass_local}"; return 1; }
    rm -f -- "${pass_local}"

    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
    # Capture remote pass path for cleanup on EXIT trap.
    _pf_pass_remote="${pass_stage}"

    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "\
        chmod 600 '${pass_stage}' && \
        ${_SUDO}mkdir -p '${_PF_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}chmod 700 '${_PF_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}php '${stage_applier}' '${pass_stage}' '${_pf_backup_remote}'"; then
      echo "[pfsense] ERROR: on-router backup encrypt failed." >&2
      return 1
    fi

    # Pull encrypted copy locally. /root/suru-backups is root-owned (700), so
    # admin cannot SCP from it directly. Stage a world-readable copy in the
    # staging dir, pull that, then remove it. The root copy is left intact.
    mkdir -p "${_PF_LOCAL_BACKUP_DIR}"
    local _bkp_stage="${_PF_REMOTE_STAGING}/${fname}"
    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
        "${_SUDO}cp '${_pf_backup_remote}' '${_bkp_stage}' && ${_SUDO}chmod 644 '${_bkp_stage}'"; then
      echo "[pfsense] WARN: could not stage backup for pull; on-router copy at ${_pf_backup_remote} is still valid." >&2
    elif ! scp "${ssh_opts[@]}" "${ssh_user}@${target}:${_bkp_stage}" "${_pf_backup_local}"; then
      echo "[pfsense] WARN: SCP pull failed; on-router copy at ${_pf_backup_remote} is still valid." >&2
    else
      chmod 600 "${_pf_backup_local}" 2>/dev/null || true
      echo "[pfsense] Backup pulled: ${_pf_backup_local}"
    fi
    # Remove the staged (world-readable) copy; the secured root copy stays.
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}rm -f '${_bkp_stage}'" 2>/dev/null || true

    # Best-effort wipe of the remote password file.
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
    _pf_pass_remote=""

    echo "[pfsense] === Backup complete ==="
    return 0
  }

  # _pf_revert — restore the encrypted backup captured by _pf_backup.
  # Fired automatically by the ERR trap that wraps the deploy steps. Safe to
  # call manually too. Always tries the on-router copy first; if that's been
  # removed, falls back to the local mirror by SCP-pushing it back.
  _pf_revert() {
    if [[ -z "${_pf_backup_remote}" ]]; then
      echo "[pfsense] WARN: revert called but no backup file is tracked — pre-backup failure?" >&2
      return 1
    fi

    echo "[pfsense] === Revert: restoring ${_pf_backup_remote} ==="

    local pass_local pass_stage
    pass_stage="${_PF_REMOTE_STAGING}/.suru-bkpass-revert"
    if ! pass_local="$(_pf_write_password_file)"; then
      echo "[pfsense] ERROR: cannot revert — SURU_BACKUP_PASSWORD unset." >&2
      return 1
    fi

    local stage_applier="${_PF_REMOTE_STAGING}/backup-restore.php"
    scp "${ssh_opts[@]}" "${_PF_APPLIER_RESTORE}" "${ssh_user}@${target}:${stage_applier}" \
      || { rm -f -- "${pass_local}"; return 1; }
    scp "${ssh_opts[@]}" "${pass_local}" "${ssh_user}@${target}:${pass_stage}" \
      || { rm -f -- "${pass_local}"; return 1; }
    rm -f -- "${pass_local}"

    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "

    # If the on-router copy is gone, push the local mirror back first.
    # Probe with sudo — /root/suru-backups/ is root-owned (700) and unreadable
    # by the unprivileged SSH user.
    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}test -r '${_pf_backup_remote}'" 2>/dev/null; then
      if [[ -r "${_pf_backup_local}" ]]; then
        echo "[pfsense] On-router backup absent; pushing local copy back: ${_pf_backup_local}"
        local _bkp_fname _bkp_stage
        _bkp_fname="$(basename -- "${_pf_backup_remote}")"
        _bkp_stage="${_PF_REMOTE_STAGING}/${_bkp_fname}"
        # Stage to world-writable /tmp/suru-staging/, then sudo-move to root-only path.
        scp "${ssh_opts[@]}" "${_pf_backup_local}" "${ssh_user}@${target}:${_bkp_stage}" \
          || { echo "[pfsense] ERROR: cannot stage backup for revert push" >&2; return 1; }
        # shellcheck disable=SC2029
        ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
          "${_SUDO}mkdir -p '${_PF_REMOTE_BACKUP_DIR}' && \
           ${_SUDO}chmod 700 '${_PF_REMOTE_BACKUP_DIR}' && \
           ${_SUDO}cp -- '${_bkp_stage}' '${_pf_backup_remote}' && \
           ${_SUDO}chmod 600 '${_pf_backup_remote}'" \
          || { echo "[pfsense] ERROR: cannot move staged backup to ${_pf_backup_remote}" >&2; return 1; }
      else
        echo "[pfsense] ERROR: neither remote nor local backup is readable — cannot revert." >&2
        return 1
      fi
    fi

    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "\
        chmod 600 '${pass_stage}' && \
        ${_SUDO}php '${stage_applier}' '${pass_stage}' '${_pf_backup_remote}'"; then
      echo "[pfsense] CRITICAL: revert failed — config.xml may be inconsistent." >&2
      echo "[pfsense] Manual recovery: pfSense GUI > Diagnostics > Backup & Restore > Restore" >&2
      echo "[pfsense]                   Configuration (Encrypted), using ${_pf_backup_local}" >&2
      echo "[pfsense]                   and SURU_BACKUP_PASSWORD." >&2
      echo "[pfsense] Or via /cf/conf/backup/ (pfSense keeps its own write_config history)." >&2
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
      return 1
    fi

    # Bounce the services that may have started under partially-written XML.
    _pf_svc_restart "syslog-ng" || true
    _pf_svc_restart "suricata"  || true
    # zeek doesn't restart via pfSsh; zeekctl deploy is the canonical path,
    # but post-revert config is the pre-deploy known-good — leave zeek as-is
    # and rely on operator to redeploy when ready.

    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true

    # This SSH-based revert just succeeded, which PROVES the management path is
    # intact — so the router-side dead-man's-switch is no longer needed and would
    # otherwise fire a redundant (and confusing) second revert ~10 min later.
    # Cancel it. (If SSH were actually cut, we'd never reach here and the timer
    # would correctly fire instead.)
    if [[ "${_pf_safety_armed:-false}" == "true" ]]; then
      safety_timer_disarm_quiet
      echo "[pfsense] Dead-man's-switch disarmed after successful revert."
    fi
    echo "[pfsense] === Revert complete ==="
  }

  # _pf_verify_xml_state — post-deploy assertions against /conf/config.xml.
  # Runs a PHP probe over SSH that reports presence/absence of the SURU-managed
  # XML nodes. WARN-only: the goal is to surface drift, not block deploys.
  # The expected SURU node names are the conventions PR A and PR B will write.
  _pf_verify_xml_state() {
    echo "[pfsense] Verifying XML state of deployed config..."
    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
    # Pass the probe script via heredoc on stdin so quoting stays simple.
    # PHP prints `STATUS=ok` / `STATUS=warn` lines that we parse client-side.
    local out
    if ! out="$(
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}/usr/local/bin/php -d display_errors=0" <<'EOPHP' 2>&1
<?php
$cfg = '/conf/config.xml';
if (!is_readable($cfg)) {
  echo "STATUS=fail reason=config_xml_unreadable" . PHP_EOL;
  exit(0);
}
$x = @simplexml_load_file($cfg);
if ($x === false) {
  echo "STATUS=fail reason=config_xml_parse_failed" . PHP_EOL;
  exit(0);
}
$ip = $x->installedpackages;

// 1. syslog-ng enabled + a SURU-tagged destination present
$sng_enable = (string)($ip->syslogng->config->enable ?? '');
$has_suru_dest = false;
foreach (($ip->syslogngadvanced->config ?? []) as $o) {
  $name = (string)$o->objectname;
  if (stripos($name, 'suru') !== false) { $has_suru_dest = true; break; }
}
echo "CHECK syslogng.enable=" . ($sng_enable === 'on' ? 'ok' : 'warn:' . ($sng_enable ?: 'unset')) . PHP_EOL;
echo "CHECK syslogng.suru_destination=" . ($has_suru_dest ? 'ok' : 'warn:no_suru_named_object') . PHP_EOL;

// 2. Zeek scripts: any zeekscript entries registered at all
$zeekscript_count = isset($ip->zeekscript->config) ? count($ip->zeekscript->config) : 0;
echo "CHECK zeekscript.count=" . ($zeekscript_count > 0 ? 'ok:' . $zeekscript_count : 'warn:0') . PHP_EOL;

// 3. Suricata: each interface has a non-empty rulesets list
$any_iface = false; $any_rulesets_empty = false;
foreach (($ip->suricata->rule ?? []) as $r) {
  $any_iface = true;
  $rs = trim((string)$r->rulesets);
  if ($rs === '') { $any_rulesets_empty = true; break; }
}
if (!$any_iface) {
  echo "CHECK suricata.interfaces=warn:no_iface_configured" . PHP_EOL;
} else {
  echo "CHECK suricata.rulesets=" . ($any_rulesets_empty ? 'warn:empty_on_some_iface' : 'ok') . PHP_EOL;
}

// 4. pfBlockerNG DNSBL feeds — should have at least one SURU-managed entry,
//    and every SURU-managed entry's action MUST be the literal "unbound".
//    pfBlockerNG's cron list-builder (pfblockerng.inc) only queues an alias
//    for DNSBL download/compile when action=='unbound'; any other value
//    (e.g. an IP-alias-style "Deny Both") silently routes it into the IP-deny
//    build path instead, where domain content never downloads. Live-verified
//    2026-06-23: every SURU_ DNSBL alias on the router had action="Deny Both"
//    and zero files in /var/db/pfblockerng/dnsblorig/ — this CHECK exists to
//    catch a regression of that exact bug class before it reaches the router.
$pfb = $ip->pfblockerngdnsbl->config ?? [];
$has_suru_pfb = false;
$bad_action_aliases = [];
foreach ($pfb as $f) {
  $is_suru = stripos((string)$f->aliasname, 'suru') !== false || stripos((string)$f->aliasname, 'pfb_') !== false;
  if ($is_suru) {
    $has_suru_pfb = true;
    if ((string)$f->action !== 'unbound') {
      $bad_action_aliases[] = (string)$f->aliasname . ':' . (string)$f->action;
    }
  }
}
echo "CHECK pfblockerngdnsbl.suru_entry=" . ($has_suru_pfb ? 'ok' : 'warn:no_suru_named_feed') . PHP_EOL;
echo "CHECK pfblockerngdnsbl.action_unbound=" . (empty($bad_action_aliases) ? 'ok' : 'warn:' . implode(',', $bad_action_aliases)) . PHP_EOL;

echo "STATUS=done" . PHP_EOL;
EOPHP
    )"; then
      echo "[pfsense] WARN: XML verify probe failed to run (network/auth/php). Skipping drift checks."
      echo "[pfsense]       ${out}"
      return 0
    fi

    local warn_count=0 ok_count=0
    while IFS= read -r line; do
      case "${line}" in
        CHECK*=ok*)   ok_count=$((ok_count + 1)); echo "[pfsense]   ✓ ${line#CHECK }" ;;
        CHECK*=warn*) warn_count=$((warn_count + 1)); echo "[pfsense]   ⚠ ${line#CHECK }" ;;
        STATUS=fail*) echo "[pfsense] WARN: probe failed: ${line}"; return 0 ;;
        STATUS=done)  : ;;
        *)            [[ -n "${line}" ]] && echo "[pfsense]   ${line}" ;;
      esac
    done <<< "${out}"

    if [[ ${warn_count} -gt 0 ]]; then
      echo "[pfsense] WARN: ${warn_count} XML state assertion(s) failed."
      echo "[pfsense]       SURU-managed configuration may not be reflected in /conf/config.xml."
      echo "[pfsense]       A subsequent GUI save (Status > syslog-ng, Services > Zeek/Suricata) will"
      echo "[pfsense]       silently overwrite the on-disk config files written by this deploy."
      echo "[pfsense]       Override with SURU_SKIP_XML_VERIFY=true to silence this check."
    else
      echo "[pfsense] XML state OK: ${ok_count} assertions passed."
    fi
  }

  # _pf_stage_and_install LOCAL_SRC REMOTE_DST
  # SCP to /tmp/suru-staging/, then move to protected REMOTE_DST via pfSsh.php.
  # This is required because admin cannot write to /usr/local/ directly via SCP.
  _pf_stage_and_install() {
    local src="$1" dst="$2"
    local fname; fname="$(basename "${dst}")"
    local stage_path="${_PF_REMOTE_STAGING}/${fname}"
    echo "[pfsense] SCP (stage): ${src} -> ${target}:${stage_path}"
    echo "[pfsense] Install:     ${stage_path} -> ${dst}"
    if [[ "${dry_run}" != "true" ]]; then
      scp "${ssh_opts[@]}" "${src}" "${ssh_user}@${target}:${stage_path}"
      # When dst already lives in the staging dir, the SCP above placed the
      # file at its final path — an install cp would be a self-copy, which
      # FreeBSD cp rejects ("identical files not copied", exit 1). Skip it.
      if [[ "${stage_path}" == "${dst}" ]]; then
        return 0
      fi
      # Install staged file to protected destination as root.
      # The previous `pfSsh.php playback svc exec 'copy ...'` primary path
      # is a silent no-op on current pfSense builds — exit 0, no copy —
      # so the fallback `php -r` (with $/` escaping that breaks under
      # csh anyway) never triggered. Use sudo cp directly, matching the
      # pattern used by api_pfsense_install, suricata-update, and the
      # dir-merge install.
      local _SUDO=""
      [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
      _pf_remote_exec "${_SUDO}cp '${stage_path}' '${dst}'"
    fi
  }

  # _pf_stage_and_install_dir LOCAL_SRC_DIR REMOTE_DST_DIR
  # SCP directory to staging, then move each file into protected destination.
  _pf_stage_and_install_dir() {
    local src_dir="$1" dst_dir="$2"
    local dir_name; dir_name="$(basename "${src_dir}")"
    local stage_dir="${_PF_REMOTE_STAGING}/${dir_name}"
    echo "[pfsense] SCP-dir (stage): ${src_dir}/ -> ${target}:${stage_dir}/"
    echo "[pfsense] Install-dir:     ${stage_dir}/ -> ${dst_dir}/"
    if [[ "${dry_run}" != "true" ]]; then
      scp -r "${ssh_opts[@]}" "${src_dir}" "${ssh_user}@${target}:${stage_dir}"
      # Merge contents of staging dir into the protected destination as
      # root. The previous php -r heredoc failed under pfSense's default
      # csh login shell — csh consumed $ and ! before php saw the input.
      # Use sudo + shell to match the pattern already used for pkg-static
      # and suricata-update; requires sudoers entries for mkdir and cp.
      local _SUDO=""
      [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
      _pf_remote_exec "${_SUDO}mkdir -p '${dst_dir}' && ${_SUDO}cp -R '${stage_dir}'/. '${dst_dir}'/"
    fi
  }

  # _pf_deploy_file — deploy a rendered artefact to a protected remote path
  _pf_deploy_file() {
    local src="${rendered}/$1" dst="$2"
    _pf_stage_and_install "${src}" "${dst}"
  }

  # _pf_deploy_dir — deploy a rendered directory to a protected remote path
  _pf_deploy_dir() {
    local src_dir="${rendered}/$1" dst_dir="$2"
    _pf_stage_and_install_dir "${src_dir}" "${dst_dir}"
  }

  # --- Install pfRest as FIRST package via SSH/pkg ----------------------------
  # pfRest is the management-plane REST API used for post-deploy validation
  # and incremental rules reloads. It must be present before any subsequent
  # API-based operations. api_pfsense_install is idempotent.
  if [[ "${dry_run}" != "true" ]] && [[ "${SURU_SKIP_API_INSTALL:-false}" != "true" ]]; then
    echo "[pfsense] Ensuring pfRest is installed (api_pfsense_install)..."
    api_pfsense_install || {
      echo "[pfsense] WARN: pfRest install/check failed — continuing with SSH-only deploy."
      echo "[pfsense]       See https://pfrest.org/ for installation help."
    }
  else
    echo "[pfsense] Skipping pfRest install (dry-run or SURU_SKIP_API_INSTALL=true)"
  fi

  # --- Pre-flight: assert required lib functions are loaded ------------------
  # deploy.sh is the sole point responsible for sourcing lib/. If a refactor
  # breaks lib loading this guard fires before _pf_backup runs and before any
  # state changes on the router — converting a mid-deploy silent failure into
  # an early, actionable error.
  declare -f certs_generate_client > /dev/null || {
    echo "[pfsense] ERROR: required lib function 'certs_generate_client' not loaded." >&2
    echo "[pfsense]        deploy.sh must source lib/certs.sh before sourcing the driver." >&2
    return 1
  }
  [[ -n "${REPO_ROOT:-}" ]] || { echo "[pfsense] ERROR: REPO_ROOT not exported from deploy.sh" >&2; return 1; }
  [[ -n "${TIER1_DIR:-}" ]] || { echo "[pfsense] ERROR: TIER1_DIR not exported from deploy.sh" >&2; return 1; }

  # --- Setup: create remote staging dir, register cleanup --------------------
  echo "[pfsense] Creating remote staging dir: ${_PF_REMOTE_STAGING}"
  if [[ "${dry_run}" != "true" ]]; then
    _pf_remote_exec "mkdir -p ${_PF_REMOTE_STAGING}"
  fi
  # Cleanup staging dir on script exit (best-effort — does not fail deploy).
  # Also wipes any leftover password file from the backup/revert hooks.
  trap '_pf_cleanup_staging' EXIT
  _pf_cleanup_staging() {
    if [[ "${dry_run}" != "true" ]]; then
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -rf ${_PF_REMOTE_STAGING}" 2>/dev/null || true
    fi
  }

  # --- Encrypted pre-deploy backup -------------------------------------------
  # MUST succeed before any deploy step mutates /conf/config.xml. On any
  # failure below this point, the ERR trap fires _pf_revert which restores
  # from the encrypted backup we just took.
  if [[ "${SURU_SKIP_BACKUP:-false}" == "true" ]]; then
    echo "[pfsense] WARN: SURU_SKIP_BACKUP=true — deploying without an encrypted snapshot."
    echo "[pfsense]       Auto-revert will be unavailable if any step fails."
  else
    if ! _pf_backup; then
      echo "[pfsense] ERROR: pre-deploy backup failed — aborting before any config change." >&2
      return 1
    fi
    # Auto-revert on any subsequent failure. Disable just before the final
    # successful return so the trap doesn't fire on normal post-deploy exit.
    trap '_pf_revert' ERR
  fi

  # --- Generate and deploy syslog-ng mTLS certificates ----------------------
  # Three cert files must exist on pfSense before syslog-ng can open the
  # mTLS connection through the Tier 4 frontdoor SNI passthrough to Logstash.
  # certs_generate_client is idempotent — skips if the existing cert verifies.
  #
  #   tls/ca/root-ca.pem  verifies Logstash server cert (ca-dir + openssl rehash)
  #   tls/client.pem      mTLS client identity
  #   tls/client-key.pem  private key (0600)
  #
  # ca-dir() requires OpenSSL hash symlinks in the CA directory. openssl rehash
  # creates them so syslog-ng can find the issuer cert by subject hash lookup.
  echo "[pfsense] Checking syslog-ng mTLS certificates..."
  certs_generate_client "tier1-pfsense-syslogng"

  local _tls_dst="/usr/local/etc/syslog-ng/tls"
  local _ca_dir="${_tls_dst}/ca"
  local _ca_local="${REPO_ROOT}/tier4-operations/pki/certs/root-ca.pem"
  local _cert_local="${TIER1_DIR}/certs/tier1-pfsense-syslogng.pem"
  local _key_local="${TIER1_DIR}/certs/tier1-pfsense-syslogng-key.pem"
  local _TLSSUDO=""
  [[ "${ssh_user}" != "root" ]] && _TLSSUDO="sudo "

  # tls/ holds the private key — keep it root-only (700).
  # tls/ca/ holds only public CA certs — world-readable (755) so syslog-ng can
  # enter the directory regardless of the user it runs as.
  _pf_remote_exec "${_TLSSUDO}mkdir -p '${_tls_dst}' && ${_TLSSUDO}chmod 700 '${_tls_dst}'"
  _pf_remote_exec "${_TLSSUDO}mkdir -p '${_ca_dir}' && ${_TLSSUDO}chmod 755 '${_ca_dir}'"
  _pf_stage_and_install "${_ca_local}"   "${_ca_dir}/root-ca.pem"
  _pf_remote_exec "${_TLSSUDO}chmod 644 '${_ca_dir}/root-ca.pem'"
  # Create OpenSSL subject-hash symlinks required by ca-dir() lookup.
  # openssl rehash creates the new-format SHA-1 hash symlink (<hash>.0).
  # Also create the legacy MD5 hash symlink so syslog-ng libraries linked
  # against older OpenSSL/LibreSSL (which uses the old hash format) can
  # find the issuer cert. Hash is computed locally to avoid remote quoting.
  _pf_remote_exec "${_TLSSUDO}openssl rehash '${_ca_dir}'"
  local _ca_old_hash
  _ca_old_hash="$(openssl x509 -subject_hash_old -noout -in "${_ca_local}" 2>/dev/null || true)"
  if [[ -n "${_ca_old_hash}" ]]; then
    _pf_remote_exec "${_TLSSUDO}ln -sf root-ca.pem '${_ca_dir}/${_ca_old_hash}.0'"
    echo "[pfsense] syslog-ng CA hash symlinks: new=$(openssl x509 -subject_hash -noout -in "${_ca_local}") old=${_ca_old_hash}"
  fi
  _pf_stage_and_install "${_cert_local}" "${_tls_dst}/client.pem"
  _pf_stage_and_install "${_key_local}"  "${_tls_dst}/client-key.pem"
  _pf_remote_exec "${_TLSSUDO}chmod 600 '${_tls_dst}/client-key.pem'"
  _pf_remote_exec "${_TLSSUDO}chmod 644 '${_tls_dst}/client.pem'"
  echo "[pfsense] syslog-ng mTLS certs installed to ${_tls_dst}"

  # --- Deploy syslog-ng via XML model (GUI-aware) ----------------------------
  # Stage the rendered config + the static applier PHP, then invoke the
  # applier which parses the config, writes objects to
  # installedpackages/syslogngadvanced/config, sets globals on
  # installedpackages/syslogng/config/0, write_config()'s, and calls
  # syslogng_resync() — the same function the GUI calls on Save in
  # Status > syslog-ng. The resync regenerates /usr/local/etc/syslog-ng.conf
  # from XML and restarts the service in one shot, so no explicit
  # _pf_svc_restart is needed (and would race).
  # envsubst doesn't recognise the @@VAR@@ token style used in our template;
  # the previous invocation left tokens literal. Use sed for substitution.
  echo "[pfsense] Rendering syslog-ng.conf with env tokens..."
  local tmp_syslogng; tmp_syslogng="$(mktemp)"
  local _sng_sni="${FRONTDOOR_SYSLOG_SNI:-syslog.suru.local}"
  local _sng_port="${FRONTDOOR_PORT:-443}"
  local _sng_sensor="${ROUTER_SENSOR_NAME:-suru-tier1}"
  local _sng_wan="${WAN_IFACE:-igb0}"
  local _sng_lan="${LAN_IFACE:-igb1}"
  sed \
    -e "s|@@FRONTDOOR_SYSLOG_SNI@@|${_sng_sni}|g" \
    -e "s|@@FRONTDOOR_PORT@@|${_sng_port}|g" \
    -e "s|@@SENSOR_NAME@@|${_sng_sensor}|g" \
    -e "s|@@WAN_IFACE@@|${_sng_wan}|g" \
    -e "s|@@LAN_IFACE@@|${_sng_lan}|g" \
    -e "s|@@SYSLOGNG_DISK_BUFFER_BYTES@@|${_hw_syslogng_disk_buf_bytes}|g" \
    < "${_PF_SYSLOGNG_TPL}" > "${tmp_syslogng}"
  local pf_syslogng_src="${_PF_REMOTE_STAGING}/syslog-ng.conf-source"
  local pf_syslogng_applier="${_PF_REMOTE_STAGING}/syslog-ng-apply.php"
  _pf_stage_and_install "${tmp_syslogng}"        "${pf_syslogng_src}"
  _pf_stage_and_install "${_PF_APPLIER_SYSLOGNG}" "${pf_syslogng_applier}"
  rm -f "${tmp_syslogng}"
  local _SNGSUDO=""
  [[ "${ssh_user}" != "root" ]] && _SNGSUDO="sudo "
  _pf_remote_exec "${_SNGSUDO}php ${pf_syslogng_applier} ${pf_syslogng_src}"

  # SURICATA_IPS_MODE: legacy (default; pcap + reactive pf-table block) or
  # inline (netmap in-flight drop on the physical NIC). Resolved here
  # (before the safety-timer arm, which depends on it).
  local _suri_ips_mode="${SURICATA_IPS_MODE:-legacy}"
  if [[ "${_suri_ips_mode}" != "legacy" && "${_suri_ips_mode}" != "inline" ]]; then
    log_die "SURICATA_IPS_MODE must be 'legacy' or 'inline', got: '${_suri_ips_mode}'"
  fi

  # sudo prefix for on-router privileged calls — declared here (before the
  # safety-timer arm block, which references it). Under `set -u` a `local`
  # declared later would be an unbound-variable abort when read here.
  local _SURISUDO=""
  [[ "${ssh_user}" != "root" ]] && _SURISUDO="sudo "

  # --- Arm the dead-man's-switch before the self-lockout-risky inline flip -----
  # An inline netmap flip can drop the host stack on the NIC carrying ROUTER_HOST
  # (e.g. igb1.10 on the igb1 trunk) — the deploy's own SSH path. The ERR-trap
  # _pf_revert also runs over SSH and cannot recover that. So before touching
  # Suricata, arm a router-side timer (scripts/lib/safety-timer.sh) that reverts
  # to legacy autonomously if this deploy never reaches its disarm call. Only for
  # inline (legacy carries no lockout risk); opt out with SURU_SAFETY_TIMER=false.
  local _pf_safety_armed="false"
  if [[ "${_suri_ips_mode}" == "inline" \
        && "${SURU_SAFETY_TIMER:-true}" == "true" \
        && "${dry_run}" != "true" ]]; then
    # Consumed by safety_timer_arm/disarm in the sourced scripts/lib/safety-timer.sh
    # (cross-file read — shellcheck can't see it).
    # shellcheck disable=SC2034
    SAFETY_TARGET="${target}"
    # shellcheck disable=SC2034
    SAFETY_USER="${ssh_user}"
    # shellcheck disable=SC2034
    SAFETY_SUDO="${_SURISUDO}"
    # shellcheck disable=SC2034
    SAFETY_DRYRUN="${dry_run}"
    # shellcheck disable=SC2034
    SAFETY_SSH_OPTS=("${ssh_opts[@]}")
    local _pf_safety_secs="${SURU_SAFETY_REVERT_SECONDS:-600}"
    # Derive the remote revert path from the library (single source of truth for
    # the remote layout — no hardcoded /tmp/suru-safety string to drift).
    local _pf_safety_remote; _pf_safety_remote="$(safety_timer_remote_path "${_PF_APPLIER_SURICATA_SAFETY_REVERT}")"
    if safety_timer_arm "${_pf_safety_secs}" "${_PF_APPLIER_SURICATA_SAFETY_REVERT}" \
         "${_SURISUDO}php ${_pf_safety_remote}"; then
      _pf_safety_armed="true"
    else
      echo "[pfsense] ERROR: could not arm the inline-flip safety timer — refusing to flip inline blind." >&2
      return 1
    fi
  elif [[ "${_suri_ips_mode}" == "inline" && "${dry_run}" == "true" ]]; then
    echo "[pfsense] (dry-run) would arm inline-flip dead-man's-switch (revert in ${SURU_SAFETY_REVERT_SECONDS:-600}s if not disarmed)"
  fi

  # --- Deploy Suricata via XML model (GUI-aware) -----------------------------
  # The pfSense Suricata package does NOT consume any top-level
  # /usr/local/etc/suricata/{suricata.yaml,update.yaml,enable.conf,disable.conf}.
  # Those are inputs to the unrelated `suricata-update` tool; the package
  # has its own rule manager and stores per-interface rule selection in
  # installedpackages/suricata/rule/<n>/rulesets. Each running suricata
  # process is started against /usr/local/etc/suricata/suricata_<UUID>_<iface>/suricata.yaml
  # which the package regenerates from XML on every GUI save.
  #
  # Path: stage enable.conf + disable.conf + applier under /tmp/suru-staging,
  # then invoke the applier. The applier writes the XML, calls
  # sync_suricata_package_config() to rebuild per-interface yamls, and
  # (when SURU_SURICATA_RESTART != false) restarts all Suricata interfaces.
  local pf_suri_enable="${_PF_REMOTE_STAGING}/suricata-enable.conf"
  local pf_suri_disable="${_PF_REMOTE_STAGING}/suricata-disable.conf"
  local pf_suri_applier="${_PF_REMOTE_STAGING}/suricata-rules-apply.php"
  _pf_stage_and_install "${rendered}/${_PF_RENDERED_SURICATA_ENABLE}"  "${pf_suri_enable}"
  _pf_stage_and_install "${rendered}/${_PF_RENDERED_SURICATA_DISABLE}" "${pf_suri_disable}"
  _pf_stage_and_install "${_PF_APPLIER_SURICATA}"                       "${pf_suri_applier}"
  # _SURISUDO already declared+set above (hoisted before the safety-timer arm).
  local _suri_restart_flag=""
  [[ "${SURU_SURICATA_RESTART:-true}" == "true" ]] && _suri_restart_flag=" --restart"
  # --ifaces: PHYSICAL NIC names only (e.g. igb1,igb2) — the physical-NIC-only
  # interface contract.
  # The applier resolves each NIC to its pfSense carrier alias on-router via
  # suru-iface-resolve.php (staged below). Resolved from SURICATA_IFACES
  # (multi) with fallback to SURICATA_IFACE (legacy single).
  local _suri_ifaces="${SURICATA_IFACES:-${SURICATA_IFACE:-}}"
  # SEC-022: validate interface list before embedding in remote shell command.
  if [[ -n "${_suri_ifaces}" ]] && ! [[ "${_suri_ifaces}" =~ ^[A-Za-z0-9,._-]+$ ]]; then
    log_die "SURICATA_IFACES contains invalid characters: '${_suri_ifaces}' (allowed: A-Za-z0-9,._-)"
  fi
  # Fast client-side rejection of the old alias contract (authoritative check
  # runs on-router in suru-iface-resolve.php with config.xml access).
  local _suri_entry
  for _suri_entry in ${_suri_ifaces//,/ }; do
    if [[ "${_suri_entry}" == *.* ]]; then
      log_die "SURICATA_IFACES entry '${_suri_entry}' is a VLAN sub-interface — list the physical parent NIC (e.g. '${_suri_entry%%.*}')"
    fi
    if [[ "${_suri_entry}" =~ ^(lan|wan|opt[0-9]+)$ ]]; then
      log_die "SURICATA_IFACES entry '${_suri_entry}' is a pfSense logical alias — the contract is physical NICs only (e.g. igb1,igb2). See .env.example."
    fi
  done
  # SURICATA_IPS_MODE resolved+validated above (before the safety-timer arm).
  local _suri_netmap_threads_flag=""
  if [[ -n "${SURICATA_NETMAP_THREADS:-}" ]]; then
    if ! [[ "${SURICATA_NETMAP_THREADS}" =~ ^[1-8]$ ]]; then
      log_die "SURICATA_NETMAP_THREADS must be 1-8, got: '${SURICATA_NETMAP_THREADS}'"
    fi
    _suri_netmap_threads_flag=" --netmap-threads=${SURICATA_NETMAP_THREADS}"
  fi
  local _suri_ifaces_flag=""
  [[ -n "${_suri_ifaces}" ]] && _suri_ifaces_flag=" --ifaces=${_suri_ifaces}"
  # Stage the shared physical->carrier resolver next to both Suricata appliers
  # (only needed when an interface list is passed — the appliers require_once
  # it solely on that path).
  if [[ -n "${_suri_ifaces}" ]]; then
    local pf_iface_resolve="${_PF_REMOTE_STAGING}/suru-iface-resolve.php"
    _pf_stage_and_install "${_PF_LIB_IFACE_RESOLVE}" "${pf_iface_resolve}"
  fi
  _pf_remote_exec "${_SURISUDO}php ${pf_suri_applier} ${pf_suri_enable} ${pf_suri_disable}${_suri_ifaces_flag} --ips-mode=${_suri_ips_mode}${_suri_netmap_threads_flag}${_suri_restart_flag}"

  # --- Suricata engine tuning (detect profile) — hardware-adaptive ------------
  # Sets detect_eng_profile on every Suricata interface to the hw-profile value.
  # Skipped when SURU_SURICATA_TUNING=false (operator opt-out).
  if [[ "${SURU_SURICATA_TUNING:-true}" == "true" ]]; then
    local pf_suri_tuning="${_PF_REMOTE_STAGING}/suricata-tuning-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_TUNING}" "${pf_suri_tuning}"
    _pf_remote_exec "${_SURISUDO}php ${pf_suri_tuning} --profile=${_hw_suricata_profile} --stream-memcap=${_hw_suricata_stream_memcap} --reassembly-memcap=${_hw_suricata_reassembly_memcap} --defrag-memcap=${_hw_suricata_defrag_memcap}${_suri_ifaces_flag}"
    echo "[pfsense] Suricata tuning applied: profile=${_hw_suricata_profile} stream=${_hw_suricata_stream_memcap} reassembly=${_hw_suricata_reassembly_memcap} defrag=${_hw_suricata_defrag_memcap}"
  else
    echo "[pfsense] Skipping Suricata engine tuning (SURU_SURICATA_TUNING=false)"
  fi

  # --- Suricata inline-drop policy (alert->drop for CRITICAL categories) --------
  # Hard precondition for SURICATA_IPS_MODE=inline: inline netmap enforces only
  # via drop-action rules (the legacy pf-table block plugin is off in inline
  # mode). Converts SURICATA_DROP_CATEGORIES to drop via the package SID-Mgmt
  # subsystem. Inert under legacy mode (pf-table block is action-agnostic),
  # enforcing under inline. Gated by SURU_SURICATA_DROP_POLICY (default true).
  # An empty SURICATA_DROP_CATEGORIES reverts the policy (clears the drop list).
  if [[ "${SURU_SURICATA_DROP_POLICY:-true}" == "true" ]]; then
    # Distinguish UNSET (use CRITICAL default) from EXPLICITLY-EMPTY (operator
    # asked to revert the policy). `${VAR:-default}` would collapse both to the
    # default and make the documented `SURICATA_DROP_CATEGORIES=` revert path
    # unreachable — use the `+x` set-check instead.
    local _suri_drop_cats
    if [[ -z "${SURICATA_DROP_CATEGORIES+x}" ]]; then
      _suri_drop_cats="emerging-botcc,emerging-malware,emerging-exploit,emerging-attack_response"
    else
      _suri_drop_cats="${SURICATA_DROP_CATEGORIES}"
    fi
    if [[ -n "${_suri_drop_cats}" ]] && ! [[ "${_suri_drop_cats}" =~ ^[A-Za-z0-9,._-]+$ ]]; then
      log_die "SURICATA_DROP_CATEGORIES contains invalid characters: '${_suri_drop_cats}' (allowed: A-Za-z0-9,._-)"
    fi
    local pf_suri_drop="${_PF_REMOTE_STAGING}/suricata-drop-policy-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_DROP}" "${pf_suri_drop}"
    # Resolver already staged above with the rules applier (only when ifaces set).
    # An empty --drop-categories reaches the applier and triggers its revert path.
    _pf_remote_exec "${_SURISUDO}php ${pf_suri_drop}${_suri_ifaces_flag} --drop-categories=${_suri_drop_cats}${_suri_restart_flag}"
    if [[ -n "${_suri_drop_cats}" ]]; then
      echo "[pfsense] Suricata drop policy applied: categories=${_suri_drop_cats}"
    else
      echo "[pfsense] Suricata drop policy reverted (SURICATA_DROP_CATEGORIES empty)"
    fi
  else
    # NOTE: this only SKIPS the applier — it does NOT revert an already-applied
    # policy. A previously-materialised drop list stays in config.xml. To revert,
    # set SURICATA_DROP_CATEGORIES= (empty) with the policy enabled.
    echo "[pfsense] Skipping Suricata inline-drop policy (SURU_SURICATA_DROP_POLICY=false — existing state left as-is)"
  fi

  # --- pf state-table tuning — hardware-adaptive --------------------------------
  # Sets system/maximumstates to prevent RAM exhaustion under heavy traffic.
  # Enables adaptive state expiry (60%→120% threshold) for graceful degradation.
  # Skipped when SURU_PF_TUNING=false (operator opt-out).
  if [[ "${SURU_PF_TUNING:-true}" == "true" ]]; then
    local pf_pf_tuning="${_PF_REMOTE_STAGING}/pf-tuning-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_PF_TUNING}" "${pf_pf_tuning}"
    _pf_remote_exec "${_SURISUDO}php ${pf_pf_tuning} --max-states=${_hw_pf_max_states} --adaptive"
    echo "[pfsense] pf tuning applied: max-states=${_hw_pf_max_states} adaptive=enabled"
  else
    echo "[pfsense] Skipping pf state-table tuning (SURU_PF_TUNING=false)"
  fi

  # --- DNS/unbound cache tuning — hardware-adaptive ----------------------------
  # Sets unbound message-cache and rrset-cache sizes for pfBlockerNG DNSBL performance.
  # Skipped when SURU_DNS_TUNING=false (operator opt-out).
  if [[ "${SURU_DNS_TUNING:-true}" == "true" ]]; then
    local pf_dns_tuning="${_PF_REMOTE_STAGING}/dns-tuning-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_DNS_TUNING}" "${pf_dns_tuning}"
    _pf_remote_exec "${_SURISUDO}php ${pf_dns_tuning} --msg-cache-mb=${_hw_unbound_msg_cache_mb} --rrset-cache-mb=${_hw_unbound_rrset_cache_mb}"
    echo "[pfsense] DNS tuning applied: msg-cache=${_hw_unbound_msg_cache_mb}MB rrset-cache=${_hw_unbound_rrset_cache_mb}MB"
  else
    echo "[pfsense] Skipping DNS/unbound cache tuning (SURU_DNS_TUNING=false)"
  fi

  # --- Deploy Zeek via XML model (GUI-aware) ---------------------------------
  # Stage rendered .zeek scripts under /tmp/suru-staging/zeek-scripts/, then
  # the applier copies each flat to /usr/local/share/zeek/site/<name>.zeek
  # (so the package's hardcoded `@load <basename>` resolution finds them)
  # and registers each in installedpackages/zeekscript/config. Calling
  # zeek_script_resync() then regenerates local.zeek from XML — the same
  # codepath GUI Save uses. Intel files are not touched by resync so
  # continue to deploy via the existing dir-merge path.
  #
  local pf_zeek_stage="${_PF_REMOTE_STAGING}/zeek-scripts"
  local pf_zeek_applier="${_PF_REMOTE_STAGING}/zeek-scripts-apply.php"
  _pf_stage_and_install_dir "${rendered}/${_PF_RENDERED_ZEEK_SCRIPTS_DIR}" "${pf_zeek_stage}"
  _pf_stage_and_install     "${_PF_APPLIER_ZEEK}"                          "${pf_zeek_applier}"
  local _ZSUDO=""
  [[ "${ssh_user}" != "root" ]] && _ZSUDO="sudo "
  _pf_remote_exec "${_ZSUDO}php ${pf_zeek_applier} ${pf_zeek_stage}"

  # Intel files live outside the package's resync scope — push as before.
  _pf_deploy_dir "${_PF_RENDERED_ZEEK_INTEL_DIR}" "${_PF_REMOTE_ZEEK_INTEL_DIR}"

  # zeek_script_resync() rebuilds local.zeek from installedpackages/zeekscript/config,
  # emitting `@load <basename>` for every registered script. Because suru-base.zeek
  # is registered, resync always emits `@load suru-base` — so base protocol analysis,
  # engine tuning, the log directory (Log::default_logdir=/var/log/zeek), and the
  # intel framework survive any subsequent GUI save in Services > Zeek > Scripts.
  # Pushing our rendered local.zeek here adds the ZEEK_IFACE label and capture
  # filter as defence-in-depth; they are restored by `make deploy` if lost.
  _pf_deploy_file "${_PF_RENDERED_ZEEK_LOCAL}" "${_PF_REMOTE_ZEEK_LOCAL}"

  # Deploy zeekctl.cfg — corrects LogDir to /var/log/zeek (zeekctl.cfg default
  # ships with the typo /var/logs/zeek from the pfSense package). Idempotent.
  if [[ -f "${rendered}/${_PF_RENDERED_ZEEK_CTRL}" ]]; then
    _pf_deploy_file "${_PF_RENDERED_ZEEK_CTRL}" "${_PF_REMOTE_ZEEK_CTRL}"
  else
    echo "[pfsense] WARN: ${rendered}/${_PF_RENDERED_ZEEK_CTRL} not found — skipping zeekctl.cfg deploy."
    echo "[pfsense]       Run 'make render' to generate it."
  fi

  # Ensure Zeek log directory exists before zeekctl deploy starts writing.
  # Log::default_logdir in local.zeek points here; syslog-ng reads from here.
  _pf_remote_exec "${_ZSUDO}mkdir -p /var/log/zeek"

  # Set Zeek capture interface in pfSense config.xml (GUI-visible) and in
  # /usr/local/etc/node.cfg (zeekctl's actual source of truth). Must be done
  # via the pfSense PHP API so the GUI reflects the setting and it survives
  # pfSense package resyncs. zeek_settings_resync() in the applier handles
  # logical names (lan→igb1.10); direct node.cfg write handles physical trunk
  # names (igb1) that have no pfSense logical alias.
  if [[ -n "${ZEEK_IFACE:-}" ]]; then
    # SEC-022: validate ZEEK_IFACE before embedding in remote shell command string.
    if ! [[ "${ZEEK_IFACE}" =~ ^[A-Za-z0-9._-]+$ ]]; then
      log_die "ZEEK_IFACE contains invalid characters: '${ZEEK_IFACE}' (allowed: A-Za-z0-9._-)"
    fi
    local pf_zeek_iface_applier="${_PF_REMOTE_STAGING}/zeek-iface-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_ZEEK_IFACE}" "${pf_zeek_iface_applier}"
    _pf_remote_exec "${_ZSUDO}php ${pf_zeek_iface_applier} '${ZEEK_IFACE}' '${_hw_zeek_lb_procs}'"
  else
    echo "[pfsense] WARN: ZEEK_IFACE is unset — skipping Zeek interface config."
    echo "[pfsense]       node.cfg will keep its current interface. Set ZEEK_IFACE in .env."
  fi

  # zeekctl deploy activates the freshly written local.zeek and node.cfg.
  _pf_remote_exec "${_ZSUDO}zeekctl deploy"

  # --- pfBlockerNG global baseline (master + DNSBL feature switches) ----------
  # Run BEFORE the feed importer so feeds land into a known-on configuration.
  # Conservative: only writes SURU-claimed keys; operator interface bindings
  # and custom TLDs are preserved. Override with SURU_PFBLOCKER_GLOBALS=false.
  if [[ "${SURU_PFBLOCKER_GLOBALS:-true}" == "true" ]]; then
    local pf_pfb_globals_remote="${_PF_REMOTE_STAGING}/pfblockerng-globals-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_PFB_GLOBALS}" "${pf_pfb_globals_remote}"
    local _PFGSUDO=""
    [[ "${ssh_user}" != "root" ]] && _PFGSUDO="sudo "

    # IP Configuration (GeoIP via MaxMind / ASN via IPinfo): stage a 0600
    # secrets file ONLY when at least one token is configured in .env. The
    # applier enables each feature per-token, so this is a no-op for operators
    # who left MAXMIND_LICENSE_KEY / IPINFO_TOKEN unset. Secret is written via
    # mktemp (0600), pushed, consumed, then shredded on both ends.
    local _pfb_ip_secrets_remote=""
    if [[ -n "${MAXMIND_ACCOUNT_ID:-}" || -n "${MAXMIND_LICENSE_KEY:-}" || -n "${IPINFO_TOKEN:-}" ]]; then
      local _pfb_secrets_local
      _pfb_secrets_local="$(mktemp)"
      # No `--` here: BSD chmod (both the macOS dev workstation and the
      # FreeBSD-based router) does not support the GNU `--` end-of-options
      # marker — it errors "chmod: --: No such file or directory". Safe
      # without it: _pfb_secrets_local is always a mktemp-generated path,
      # never user input, so there's no leading-`-` injection risk to guard
      # against.
      chmod 600 "${_pfb_secrets_local}"
      # GeoIP needs both MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY (the applier
      # only enables GeoIP when both are present); ASN needs IPINFO_TOKEN.
      {
        [[ -n "${MAXMIND_ACCOUNT_ID:-}" ]]  && printf 'MAXMIND_ACCOUNT_ID=%s\n' "${MAXMIND_ACCOUNT_ID}"
        [[ -n "${MAXMIND_LICENSE_KEY:-}" ]] && printf 'MAXMIND_KEY=%s\n'        "${MAXMIND_LICENSE_KEY}"
        [[ -n "${IPINFO_TOKEN:-}" ]]        && printf 'ASN_TOKEN=%s\n'          "${IPINFO_TOKEN}"
      } > "${_pfb_secrets_local}"
      _pfb_ip_secrets_remote="${_PF_REMOTE_STAGING}/pfb-ipconfig.secrets"
      if [[ "${dry_run}" != "true" ]]; then
        scp "${ssh_opts[@]}" "${_pfb_secrets_local}" "${ssh_user}@${target}:${_pfb_ip_secrets_remote}"
        _pf_remote_exec "${_PFGSUDO}chmod 600 '${_pfb_ip_secrets_remote}'"
      fi
      rm -f -- "${_pfb_secrets_local}"
      echo "[pfsense] pfBlockerNG IP-config secrets staged (GeoIP/ASN enable on demand)."
    fi

    _pf_remote_exec "${_PFGSUDO}php ${pf_pfb_globals_remote} ${_pfb_ip_secrets_remote} --table-entries=${_hw_pf_table_entries}"

    # Shred the staged secrets file after the applier has consumed it.
    if [[ -n "${_pfb_ip_secrets_remote}" && "${dry_run}" != "true" ]]; then
      _pf_remote_exec "${_PFGSUDO}rm -f '${_pfb_ip_secrets_remote}'"
    fi
  else
    echo "[pfsense] Skipping pfBlockerNG global baseline (SURU_PFBLOCKER_GLOBALS=false)"
  fi

  # --- pfBlockerNG — import feeds via rendered PHP importer -------------------
  # render-pfblockerng.sh emits pfblockerng-import.php. The PHP uses
  # config_set_path / write_config — the correct pfSense API for writing to
  # installedpackages/pfblockerngdnsbl/config. Merges by aliasname; preserves
  # any existing entries not managed by SURU.
  #
  # The SURU_AbuseIPDB feed row (ip-categories.yml) carries an
  # @@ABUSEIPDB_API_KEY@@ token — same env-token convention as the syslog-ng
  # template above. With ABUSEIPDB_API_KEY set, the key is substituted into
  # the staged copy only (rendered/ stays secret-free). Unset or invalid, the
  # token-bearing row is DELETED so pfBlockerNG never fetches a token-literal
  # URL and verify-pfblockerng-feeds.sh (which derives its expectations from
  # the live config.xml rows, with no state filter) stays green.
  local pf_importer_remote="${_PF_REMOTE_STAGING}/import-pfblockerng.php"
  local tmp_importer; tmp_importer="$(mktemp)"
  local _pfb_abuseipdb_key="${ABUSEIPDB_API_KEY:-}"
  if [[ -n "${_pfb_abuseipdb_key}" && ! "${_pfb_abuseipdb_key}" =~ ^[A-Za-z0-9]+$ ]]; then
    echo "[pfsense] WARN: ABUSEIPDB_API_KEY contains non-alphanumeric characters — treating as unset (sed/URL injection guard)."
    _pfb_abuseipdb_key=""
  fi
  if [[ -n "${_pfb_abuseipdb_key}" ]]; then
    sed -e "s|@@ABUSEIPDB_API_KEY@@|${_pfb_abuseipdb_key}|g" \
      < "${rendered}/${_PF_RENDERED_PFBLOCKER_PHP}" > "${tmp_importer}"
    echo "[pfsense] pfBlockerNG: AbuseIPDB API key injected into staged importer (SURU_AbuseIPDB active)."
  else
    sed -e "/@@ABUSEIPDB_API_KEY@@/d" \
      < "${rendered}/${_PF_RENDERED_PFBLOCKER_PHP}" > "${tmp_importer}"
    echo "[pfsense] ABUSEIPDB_API_KEY unset — SURU_AbuseIPDB feed row omitted from import (set it in tier1-perimeter/.env to activate)."
  fi
  _pf_stage_and_install "${tmp_importer}" "${pf_importer_remote}"
  rm -f -- "${tmp_importer}"
  local _PBSUDO=""
  [[ "${ssh_user}" != "root" ]] && _PBSUDO="sudo "
  # When the staged importer carries a substituted API key, tighten its mode
  # before running it and shred it immediately after (chmod 600 + rm -f) — the
  # key must not linger in the world-writable staging dir.
  if [[ -n "${_pfb_abuseipdb_key}" && "${dry_run}" != "true" ]]; then
    _pf_remote_exec "${_PBSUDO}chmod 600 '${pf_importer_remote}'"
  fi
  _pf_remote_exec "${_PBSUDO}php ${pf_importer_remote}"
  if [[ -n "${_pfb_abuseipdb_key}" && "${dry_run}" != "true" ]]; then
    _pf_remote_exec "${_PBSUDO}rm -f '${pf_importer_remote}'"
  fi
  trap - EXIT
  # Deploy succeeded — disarm the auto-revert trap so a failure in the
  # purely-informational verify/validate blocks below doesn't roll us back.
  trap - ERR

  # Reaching this line means every risky step (incl. the inline flip) completed
  # AND we are still reachable over SSH — connectivity survived. Cancel the
  # router-side dead-man's-switch so no auto-revert fires. If we had instead lost
  # SSH mid-deploy, control never reaches here, the timer is left armed, and the
  # router reverts itself to legacy — restoring the management path.
  if [[ "${_pf_safety_armed}" == "true" ]]; then
    safety_timer_disarm
  fi

  # --- Post-deploy XML drift verify -------------------------------------------
  # Reads /conf/config.xml on the router and warns if SURU-managed XML nodes
  # are absent. This catches the case where a previous deploy wrote files to
  # disk that bypassed config.xml — a subsequent GUI save in Status > syslog-ng,
  # Services > Zeek > Scripts, or Services > Suricata regenerates the on-disk
  # config from XML and silently overwrites the deployed file.
  #
  # WARN-only on the current driver: until PR A (syslog-ng + Zeek XML model)
  # and PR B (Suricata XML alignment) land, none of the asserted nodes are
  # actually populated by deploy. The verify becomes useful immediately as a
  # visible signal that the deploy is at risk of being overwritten by a GUI
  # save. Flip warn→fail once PRs A and B are merged.
  if [[ "${dry_run}" != "true" ]] && [[ "${SURU_SKIP_XML_VERIFY:-false}" != "true" ]]; then
    _pf_verify_xml_state || true
  fi

  # --- Post-deploy validation via REST API ------------------------------------
  # Non-fatal: a validation failure does not roll back the deploy. It surfaces
  # the failure to the operator and pulls recent system log entries via the
  # API to feed error analysis. Skipped on dry-run and when API creds absent.
  if [[ "${dry_run}" != "true" ]] \
     && [[ -n "${PFSENSE_API_CLIENT_TOKEN:-}" ]] \
     && [[ "${SURU_SKIP_API_VALIDATE:-false}" != "true" ]]; then
    echo "[pfsense] Running post-deploy API validation..."
    if api_health; then
      echo "[pfsense] API health OK."
      if ! api_validate_deployment; then
        echo "[pfsense] WARN: post-deploy validation flagged at least one service."
        echo "[pfsense] Recent system log entries (for diagnostic analysis):"
        api_fetch_errors 100 || echo "[pfsense] (log fetch failed)"
      fi
    else
      echo "[pfsense] WARN: API health check failed — pfRest may not be configured yet."
      echo "[pfsense]       Configure client credentials in pfSense UI -> System -> API."
    fi
  fi
}
