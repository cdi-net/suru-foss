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
# SCP PRIVILEGE MODEL — pfSense (privilege matrix: docs/privilege-matrix-pfsense.md)
# ==============================
# pfSense's admin user has SSH shell access but cannot write to /usr/local/etc/
# or /usr/local/share/ via SCP directly (Permission denied). The correct pattern:
#
#   1. SCP file to /tmp/suru-staging/ (world-writable, admin-accessible)
#   2. Move into final location with `sudo cp` (full-path binaries, see _PF_BIN_*)
#
# _pf_stage_and_install() implements this two-step for every protected path.
# /tmp/suru-staging/ is sudo-cleaned to a clean slate at deploy start (a prior
# deploy's sudo dir-installs can leave root-owned cruft a non-root cleanup
# can't remove) and sudo-removed again on EXIT.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PF_TEMPLATES_DIR="$(cd "${SCRIPT_DIR}/../../templates" && pwd)"

# Source REST API client. Self-contained — no other lib deps required.
# Provides: api_init, api_health, api_validate_deployment,
#           api_pfsense_install (first-package install), api_fetch_errors,
#           api_reload_suricata_rules.
# shellcheck source=../lib/api.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/api.sh"

# Shared secret-hygiene primitives (secret_charset_ok / secret_mktemp) — the
# single implementation both perimeter secret patterns use so their validation
# and temp-file handling cannot drift.
# shellcheck source=../lib/secrets.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/secrets.sh"

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
# Static PHP applier for the unbound local-zones platform default:
# manages a SURU sentinel block in unbound/custom_options so local
# namespaces (.local, wpad.<domain>) are answered locally, never forwarded
# upstream. Preserves operator custom options outside the sentinel block.
_PF_APPLIER_UNBOUND_LZ="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/unbound-localzones-apply.php"
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
_PF_APPLIER_SURICATA_LOGMGMT="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-logmgmt-apply.php"
_PF_APPLIER_SURICATA_RESTART="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-restart.php"
_PF_APPLIER_SURICATA_TEST="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-test-configs.php"
_PF_APPLIER_SURICATA_SAFETY_REVERT="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/suricata-safety-revert.php"
_PF_APPLIER_PF_TUNING="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/pf-tuning-apply.php"
_PF_APPLIER_DNS_TUNING="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/dns-tuning-apply.php"
_PF_APPLIER_VERIFY_XML="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/verify-xml-state.php"

# Remote location for encrypted backups (router-side). Persists across deploys
# so the operator has on-router history even when a local pull fails.
_PF_REMOTE_BACKUP_DIR="/root/suru-backups"
# Local mirror — pulled via SCP after each successful encrypt. Files are
# AES-256-CBC + PBKDF2 (sha256, 500_000 iter) and restorable via pfSense
# Diagnostics > Backup & Restore (check "Encrypted") with the same password.
_PF_LOCAL_BACKUP_DIR="${SURU_TIER1_BACKUP_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)/backups}"

# --- Remote target paths on pfSense device ------------------------------------
_PF_REMOTE_SURICATA_CONF="/usr/local/etc/suricata/suricata.yaml"
_PF_REMOTE_SURICATA_UPDATE="/usr/local/etc/suricata/update.yaml"
_PF_REMOTE_SYSLOGNG_CONF="/usr/local/etc/syslog-ng.conf"
_PF_REMOTE_ZEEK_LOCAL="/usr/local/share/zeek/site/local.zeek"
_PF_REMOTE_ZEEK_CTRL="/usr/local/etc/zeekctl.cfg"
_PF_REMOTE_ZEEK_SCRIPTS_DIR="/usr/local/share/zeek/site/scripts"
_PF_REMOTE_ZEEK_INTEL_DIR="/usr/local/share/zeek/intel"
# Router-side copy of the deployment Root CA, installed by the syslog-ng mTLS
# cert step (single source of truth for the router-side CA path).
_PF_REMOTE_SYSLOG_TLS_CA="/usr/local/etc/syslog-ng/tls/ca/root-ca.pem"

# Remote staging directory — writable by admin, cleaned up after deploy
_PF_REMOTE_STAGING="/tmp/suru-staging"
: "${_PF_BIN_PHP:=/usr/local/bin/php}"
: "${_PF_BIN_CP:=/bin/cp}"
: "${_PF_BIN_MKDIR:=/bin/mkdir}"
: "${_PF_BIN_CHMOD:=/bin/chmod}"
: "${_PF_BIN_RM:=/bin/rm}"
: "${_PF_BIN_MV:=/bin/mv}"
: "${_PF_BIN_LN:=/bin/ln}"
: "${_PF_BIN_OPENSSL:=/usr/bin/openssl}"
: "${_PF_BIN_TEST:=/bin/test}"
: "${_PF_BIN_NEWSYSLOG:=/usr/sbin/newsyslog}"
: "${_PF_BIN_ZEEKCTL:=/usr/local/bin/zeekctl}"
: "${_PF_BIN_PFSSH:=/usr/local/sbin/pfSsh.php}"

# --- EXIT-trap snapshot -------------------------------------------------------
# Bash keeps a function's locals visible to an EXIT trap only while that function
# is still on the call stack. The staging-cleanup trap below is armed inside
# _platform_deploy but fires at *global* scope on the two abort paths that
# `return` out of it — the pre-deploy backup gate and the inline-flip safety-timer
# refusal — where the locals are gone and reading them aborted the trap under
# `set -u` ("dry_run: unbound variable"). That skipped the cleanup on
# exactly the paths that leave a half-staged directory behind. The trap therefore
# reads this snapshot and never a local. Pre-initialised so every reference is
# bound however early the script exits; dry-run defaults true and the target
# defaults empty, so a trap that fires before the snapshot is populated does
# nothing rather than SSHing blind.
_PF_TRAP_DRY_RUN="true"
_PF_TRAP_SSH_USER=""
_PF_TRAP_TARGET=""
_PF_TRAP_SSH_OPTS=()
# Success path sets this: the staging dir is deliberately left on the router for
# the next deploy's clean-slate rm, while the trap stays armed for its chained
# temp-file cleanup.
_PF_TRAP_STAGING_KEEP="false"

# --- Revert-on-failure state --------------------------------------------------
# The revert is armed once the encrypted backup exists and disarmed on the
# success path and on the deliberate refusals (the inline-flip arm failure and
# the pre-restart config-test refusals, which keep the running engines
# untouched). It fires at most once, from the main shell only:
#   * the ERR trap (errtrace, so it reaches nested functions and the failing
#     command's own context), and
#   * the EXIT trap, for an `exit` (log_die, a lib die) which fires no ERR trap.
# _PF_REVERT_BASE_SUBSHELL is BASH_SUBSHELL at arm time: a command substitution
# or pipeline element inherits the ERR trap under errtrace but runs one level
# deeper, and must never revert on its own.
_PF_REVERT_ARMED="false"
_PF_REVERT_BASE_SUBSHELL=0
_PF_ERRTRACE_WAS_ON="false"
# Temp files the driver creates; the EXIT trap removes them, so a step that dies
# before its own `rm` leaves nothing under TMPDIR.
_PF_TMP_FILES=()
# Dispositions of INT/TERM/HUP before the revert was armed (`trap -p` text),
# restored on disarm.
_PF_PREV_SIGTRAPS=""
# True once _pf_revert_arm installed its traps; the disarm touches the shell's
# traps and options only then (not on a dry run or with SURU_SKIP_BACKUP).
_PF_REVERT_ARM_DONE="false"

# _pf_remove_tmp_files — remove every registered temp file. Global, so the EXIT
# trap and the signal handler used while the revert runs can call it wherever
# the stack stands; it reads no _platform_deploy local.
_pf_remove_tmp_files() {
  if [[ ${#_PF_TMP_FILES[@]} -gt 0 ]]; then
    rm -f -- "${_PF_TMP_FILES[@]}" 2>/dev/null || true
  fi
}

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
  # Connection reuse when deploy.sh enabled it (lib/ssh.sh ssh_mux_enable):
  # every ssh/scp below, the EXIT-trap staging cleanup and the safety timer's
  # arm path share one connection. The safety timer's disarm paths force a
  # fresh one (lib/safety-timer.sh _SAFETY_FRESH_CONN).
  if [[ -n "${SSH_MUX_OPTS+set}" && ${#SSH_MUX_OPTS[@]} -gt 0 ]]; then
    ssh_opts+=("${SSH_MUX_OPTS[@]}")
  fi

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
  # Detected physical memory (whole GB). Empty = unknown (no .hw-profile, or the
  # key is absent); consumed by the pre-restart Suricata config-test gate.
  local _hw_physmem_gb=""
  local _hw_profile="${SURU_HW_PROFILE:-${TIER1_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}/.hw-profile}"
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
    _hw_physmem_gb="$(grep -m1              '^SURU_HW_DETECTED_PHYSMEM_GB='           "${_hw_profile}" | cut -d= -f2)"
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
    # The profile is read back from the router, so every value is validated
    # before it reaches a root command. hw_compute_profile writes the computed
    # values and hw_reconcile_profile (scripts/lib/hw-preflight.sh) preserves
    # operator overrides, so a hand-edited profile can carry any string. The
    # memcap check accepts exactly what suru_parse_memcap_bytes() in
    # pfsense/suricata-tuning-apply.php accepts: <integer>mb (any case) or a
    # plain byte count.
    _pf_hw_require_int() {
      [[ "$2" =~ ^[0-9]+$ ]] || log_die "hw-profile ${1}='${2}' is not an integer — fix ${_hw_profile} (re-run 'make preflight')"
    }
    _pf_hw_require_memcap() {
      [[ "$2" =~ ^[0-9]+([mM][bB])?$ ]] || log_die "hw-profile ${1}='${2}' is not <integer>mb or a byte count — fix ${_hw_profile} (re-run 'make preflight')"
    }
    _pf_hw_require_int    SURU_HW_PF_TABLE_ENTRIES             "${_hw_pf_table_entries}"
    _pf_hw_require_int    SURU_HW_PF_MAX_STATES                "${_hw_pf_max_states}"
    _pf_hw_require_int    SURU_HW_ZEEK_LB_PROCS                "${_hw_zeek_lb_procs}"
    _pf_hw_require_memcap SURU_HW_SURICATA_STREAM_MEMCAP       "${_hw_suricata_stream_memcap}"
    _pf_hw_require_memcap SURU_HW_SURICATA_REASSEMBLY_MEMCAP   "${_hw_suricata_reassembly_memcap}"
    _pf_hw_require_memcap SURU_HW_SURICATA_DEFRAG_MEMCAP       "${_hw_suricata_defrag_memcap}"
    _pf_hw_require_int    SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES   "${_hw_syslogng_disk_buf_bytes}"
    _pf_hw_require_int    SURU_HW_UNBOUND_MSG_CACHE_MB         "${_hw_unbound_msg_cache_mb}"
    _pf_hw_require_int    SURU_HW_UNBOUND_RRSET_CACHE_MB       "${_hw_unbound_rrset_cache_mb}"
    case "${_hw_suricata_profile}" in
      low|medium|high) ;;
      *) log_die "hw-profile SURU_HW_SURICATA_PROFILE='${_hw_suricata_profile}' is not low|medium|high — fix ${_hw_profile} (re-run 'make preflight')" ;;
    esac
    if [[ -n "${_hw_physmem_gb}" ]]; then
      _pf_hw_require_int SURU_HW_DETECTED_PHYSMEM_GB "${_hw_physmem_gb}"
    fi
    echo "[pfsense] hw-profile: pf_table_entries=${_hw_pf_table_entries} pf_max_states=${_hw_pf_max_states} zeek_lb_procs=${_hw_zeek_lb_procs} suricata=${_hw_suricata_profile} stream=${_hw_suricata_stream_memcap} reassembly=${_hw_suricata_reassembly_memcap} defrag=${_hw_suricata_defrag_memcap} sng_buf_bytes=${_hw_syslogng_disk_buf_bytes} unbound_msg=${_hw_unbound_msg_cache_mb}MB rrset=${_hw_unbound_rrset_cache_mb}MB physmem_gb=${_hw_physmem_gb:-unknown}"
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
    local _svc_sudo=""
    [[ "${ssh_user}" != "root" ]] && _svc_sudo="sudo "
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
      "${_svc_sudo}${_PF_BIN_PFSSH} playback svc restart ${svc}"
  }

  _pf_remote_exec() {
    echo "[pfsense] SSH: $*"
    if [[ "${dry_run}" != "true" ]]; then
      # shellcheck disable=SC2029
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "$@"
    fi
  }

  # _pf_remote_exec_long — _pf_remote_exec for a command that stays silent for
  # minutes (the pre-restart Suricata config test prints nothing while one
  # instance is tested). Client keepalives keep an idle-timeout middlebox from
  # dropping the session; a router that stops answering for 10 x 30 s ends it.
  _pf_remote_exec_long() {
    echo "[pfsense] SSH: $*"
    if [[ "${dry_run}" != "true" ]]; then
      # shellcheck disable=SC2029
      ssh "${ssh_opts[@]}" -o ServerAliveInterval=30 -o ServerAliveCountMax=10 \
        "${ssh_user}@${target}" "$@"
    fi
  }

  # --------------------------------------------------------------------
  # Encrypted backup + revert
  # --------------------------------------------------------------------
  # Captured filename for revert. Set by _pf_backup; consumed by _pf_revert
  # (auto-fired through _pf_revert_once by the ERR and EXIT traps armed right
  # after the backup).
  local _pf_backup_local="" _pf_backup_remote="" _pf_pass_remote=""
  # Set to true right before the one Suricata restart of a deploy is issued (the
  # consolidated restart, which also engages an inline flip). The revert bounces
  # Suricata only then.
  local _pf_suri_restarted="false"

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
        ${_SUDO}${_PF_BIN_MKDIR} -p '${_PF_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}${_PF_BIN_CHMOD} 700 '${_PF_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}${_PF_BIN_PHP} '${stage_applier}' '${pass_stage}' '${_pf_backup_remote}'"; then
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
        "${_SUDO}${_PF_BIN_CP} '${_pf_backup_remote}' '${_bkp_stage}' && ${_SUDO}${_PF_BIN_CHMOD} 644 '${_bkp_stage}'"; then
      echo "[pfsense] WARN: could not stage backup for pull; on-router copy at ${_pf_backup_remote} is still valid." >&2
    elif ! scp "${ssh_opts[@]}" "${ssh_user}@${target}:${_bkp_stage}" "${_pf_backup_local}"; then
      echo "[pfsense] WARN: SCP pull failed; on-router copy at ${_pf_backup_remote} is still valid." >&2
    else
      chmod 600 "${_pf_backup_local}" 2>/dev/null || true
      echo "[pfsense] Backup pulled: ${_pf_backup_local}"
    fi
    # Remove the staged (world-readable) copy; the secured root copy stays.
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}${_PF_BIN_RM} -f '${_bkp_stage}'" 2>/dev/null || true

    # Best-effort wipe of the remote password file.
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
    _pf_pass_remote=""

    echo "[pfsense] === Backup complete ==="
    return 0
  }

  # _pf_revert — restore the encrypted backup captured by _pf_backup.
  # Fired automatically, once, by _pf_revert_once (the ERR trap under errtrace,
  # and the EXIT trap for an `exit`) on any failure after the backup.
  # Safe to call manually too. Always tries the on-router copy first; if that's been
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
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}${_PF_BIN_TEST} -r '${_pf_backup_remote}'" 2>/dev/null; then
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
          "${_SUDO}${_PF_BIN_MKDIR} -p '${_PF_REMOTE_BACKUP_DIR}' && \
           ${_SUDO}${_PF_BIN_CHMOD} 700 '${_PF_REMOTE_BACKUP_DIR}' && \
           ${_SUDO}${_PF_BIN_CP} -- '${_bkp_stage}' '${_pf_backup_remote}' && \
           ${_SUDO}${_PF_BIN_CHMOD} 600 '${_pf_backup_remote}'" \
          || { echo "[pfsense] ERROR: cannot move staged backup to ${_pf_backup_remote}" >&2; return 1; }
      else
        echo "[pfsense] ERROR: neither remote nor local backup is readable — cannot revert." >&2
        return 1
      fi
    fi

    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "\
        chmod 600 '${pass_stage}' && \
        ${_SUDO}${_PF_BIN_PHP} '${stage_applier}' '${pass_stage}' '${_pf_backup_remote}'"; then
      echo "[pfsense] CRITICAL: revert failed — config.xml may be inconsistent." >&2
      echo "[pfsense] Manual recovery: pfSense GUI > Diagnostics > Backup & Restore > Restore" >&2
      echo "[pfsense]                   Configuration (Encrypted), using ${_pf_backup_local}" >&2
      echo "[pfsense]                   and SURU_BACKUP_PASSWORD." >&2
      echo "[pfsense] Or via /cf/conf/backup/ (pfSense keeps its own write_config history)." >&2
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
      return 1
    fi

    # Bounce the services that may have started under partially-written XML.
    _pf_svc_restart "syslog-ng" || echo "[pfsense] WARN: could not restart syslog-ng after revert — restart it from the GUI (Status > Services)." >&2
    # Suricata only when this deploy already restarted it. The appliers run
    # without --restart, so until the consolidated restart the engines still
    # hold their pre-deploy config; restarting them now would load per-interface
    # yamls nobody regenerated from the restored config.xml, likely the
    # very config that just failed.
    if [[ "${_pf_suri_restarted:-false}" == "true" ]]; then
      _pf_svc_restart "suricata"  || echo "[pfsense] WARN: could not restart suricata after revert — restart it from the GUI (Status > Services)." >&2
    else
      echo "[pfsense] Suricata was not restarted by this deploy — leaving the running engines on their pre-deploy config."
      echo "[pfsense] WARN: config.xml is restored but the per-interface Suricata yamls were not regenerated and may still hold this deploy's partial config; a Suricata restart or reboot before a corrected deploy would start against them. Re-save each interface in the GUI (Services > Suricata > Interfaces > Save) or run a corrected deploy before restarting Suricata or rebooting." >&2
    fi
    # zeek doesn't restart via pfSsh; zeekctl deploy is the canonical path,
    # but post-revert config is the pre-deploy known-good — leave zeek as-is
    # and rely on operator to redeploy when ready.

    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true

    # This SSH-based revert just succeeded, which PROVES the management path is
    # intact — so the router-side dead-man's-switch is no longer needed and would
    # otherwise fire a redundant (and confusing) second revert ~10 min later.
    # Cancel it. (If SSH were actually cut, we'd never reach here and the timer
    # would correctly fire instead.) This holds with no Suricata restart too:
    # the timer guards the inline flip, which only engages at the restart, so the
    # engines never left their pre-deploy state and config.xml is back to it.
    if [[ "${_pf_safety_armed:-false}" == "true" ]]; then
      safety_timer_disarm_quiet
      echo "[pfsense] Dead-man's-switch disarmed after successful revert."
    fi
    echo "[pfsense] === Revert complete ==="
  }

  # _pf_revert_arm — called once, right after the backup exists. Not armed on a
  # dry run (nothing was changed, and the revert is not dry-run aware) nor with
  # SURU_SKIP_BACKUP=true (there is no backup to restore).
  _pf_revert_arm() {
    [[ "${dry_run}" != "true" ]] || return 0
    # An interrupt after the backup reverts like any other failure: INT, TERM
    # and HUP exit non-zero on every bash version, so the EXIT trap sees a
    # failing status and reverts once. Installed BEFORE the revert is armed, so
    # no signal can arrive while armed without a non-zero-exit handler.
    _PF_PREV_SIGTRAPS="$(trap -p INT TERM HUP)"
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    _PF_REVERT_BASE_SUBSHELL="${BASH_SUBSHELL}"
    case "$-" in *E*) _PF_ERRTRACE_WAS_ON="true" ;; *) _PF_ERRTRACE_WAS_ON="false" ;; esac
    set -E
    _PF_REVERT_ARMED="true"
    trap '_pf_revert_once' ERR
    _PF_REVERT_ARM_DONE="true"
  }

  # _pf_revert_restore — put back the errtrace option and the INT/TERM/HUP
  # dispositions the arm replaced (shared by the disarm and the revert).
  _pf_revert_restore() {
    trap - INT TERM HUP
    if [[ -n "${_PF_PREV_SIGTRAPS}" ]]; then
      # The text is this shell's own `trap -p` output, saved at arm time.
      eval "${_PF_PREV_SIGTRAPS}"
    fi
    [[ "${_PF_ERRTRACE_WAS_ON}" == "true" ]] || set +E
  }

  # _pf_revert_disarm — the success path and the deliberate no-revert refusals.
  # Idempotent. Drops the ERR trap, restores the errtrace option and the
  # INT/TERM/HUP dispositions the arm replaced.
  _pf_revert_disarm() {
    _PF_REVERT_ARMED="false"
    [[ "${_PF_REVERT_ARM_DONE}" == "true" ]] || return 0
    trap - ERR
    _pf_revert_restore
    _PF_REVERT_ARM_DONE="false"
  }

  # _pf_revert_once — the one entry point of both triggers. Runs _pf_revert at
  # most once: it marks itself spent first, so the revert's own failures (and
  # the EXIT trap that follows an ERR-triggered exit) cannot re-enter it. A
  # no-op outside the main shell (a command substitution or pipeline element
  # that failed is the parent's failure to judge) and whenever it is not armed.
  # It does not call _pf_revert_disarm: that clears the signal traps before the
  # armed flag, opening a window in which a signal skips the revert. The signal
  # handler installed here first removes the registered temp and password files
  # and exits, so an interrupt arriving after the first one — before the revert
  # starts, or during it — ends the run without (another) revert and with no
  # secret material left; config.xml may be left partly restored.
  _pf_revert_once() {
    [[ "${_PF_REVERT_ARMED}" == "true" ]] || return 0
    [[ "${BASH_SUBSHELL}" -eq "${_PF_REVERT_BASE_SUBSHELL}" ]] || return 0
    trap '_pf_remove_tmp_files; exit 1' INT TERM HUP
    _PF_REVERT_ARMED="false"
    trap - ERR
    echo "[pfsense] ERROR: deploy failed after the pre-deploy backup — reverting config.xml." >&2
    _pf_revert || echo "[pfsense] ERROR: the revert did not complete — see the messages above." >&2
    _pf_revert_restore
    _PF_REVERT_ARM_DONE="false"
    return 0
  }

  # _pf_verify_xml_state — post-deploy assertions against /conf/config.xml.
  # Runs a PHP probe over SSH that reports presence/absence of the SURU-managed
  # XML nodes. WARN-only: the goal is to surface drift, not block deploys.
  # The expected SURU node names are the conventions PR A and PR B will write.
  _pf_verify_xml_state() {
    echo "[pfsense] Verifying XML state of deployed config..."
    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
    # The probe is a staged applier (pfsense/verify-xml-state.php), run like
    # every other applier — root PHP is never fed on stdin.
    # PHP prints `STATUS=ok` / `STATUS=warn` lines that we parse client-side.
    local out _vx_stage="${_PF_REMOTE_STAGING}/verify-xml-state.php" _vx_scp
    if ! _vx_scp="$(scp "${ssh_opts[@]}" "${_PF_APPLIER_VERIFY_XML}" "${ssh_user}@${target}:${_vx_stage}" 2>&1)"; then
      echo "[pfsense] WARN: could not stage verify-xml-state.php. Skipping drift checks."
      echo "[pfsense]       ${_vx_scp}"
      return 0
    fi
    if ! out="$(ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_SUDO}${_PF_BIN_PHP} ${_vx_stage}" 2>&1)"; then
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
      # pattern used by the dir-merge install.
      local _SUDO=""
      [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
      _pf_remote_exec "${_SUDO}${_PF_BIN_CP} '${stage_path}' '${dst}'"
    fi
  }

  # _pf_install_newsyslog_dropin NAME LOCAL_CONF LOGPATH...
  # Installs LOCAL_CONF as /var/etc/newsyslog.conf.d/NAME.conf (pfSense's
  # generated /etc/newsyslog.conf includes that directory and keeps manually
  # added files; newsyslog runs every minute from /etc/crontab) — persistence
  # class B, re-converged on every deploy — then PROVES it with a newsyslog dry
  # run (-n never rotates or creates), judged LOCALLY on the captured output:
  # newsyslog exits 0 on an illegal flag and on an unknown owner (it only
  # prints an error line, and the owner error echoes the whole config line), so
  # the exit status is no verdict and a path-only grep would match the echoed
  # offending line. Require one registered decision line per LOGPATH — either
  # form, both captured live from this newsyslog (FreeBSD 15):
  #   /var/log/pfblockerng/dnsbl.log <7J>: --> will trim at Sat Sep  5 23:59:00 2026
  #   /var/log/pfblockerng/suru-probe-missing.log <7J>: does not exist, skipped.
  # — and no error line. The not-yet-existing case is accepted by an explicit
  # alternate (not by the accident of its "<path> <" prefix): newsyslog
  # re-evaluates every minute and engages once the producer creates the file.
  # An unparseable drop-in is removed again (newsyslog would complain every
  # minute) and the deploy dies. Rotate-by-rename contract: see
  # docs/DEPLOYMENT-ARCHITECTURE.md "Log Rotation Contract".
  # _pf_newsyslog_dropin_path NAME — the one place the drop-in path convention
  # lives (/var/etc/newsyslog.conf.d/NAME.conf); the installer and the stage
  # messages derive it from here so they cannot drift apart.
  _pf_newsyslog_dropin_path() { printf '/var/etc/newsyslog.conf.d/%s.conf' "$1"; }

  _pf_install_newsyslog_dropin() {
    local name="$1" local_conf="$2"; shift 2
    local remote; remote="$(_pf_newsyslog_dropin_path "${name}")"
    _pf_stage_and_install "${local_conf}" "${remote}"
    local _NSUDO=""
    [[ "${ssh_user}" != "root" ]] && _NSUDO="sudo "
    # The staged copy inherits mktemp's 0600; match pfSense's own generated files (644).
    _pf_remote_exec "${_NSUDO}${_PF_BIN_CHMOD} 644 '${remote}'"
    if [[ "${dry_run}" != "true" ]]; then
      local _ns_out _ns_bad=0 _ns_log _ns_re
      _ns_out="$(ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "${_NSUDO}${_PF_BIN_NEWSYSLOG} -nvf '${remote}'" 2>&1 || true)"
      grep -qiE 'error in config|illegal flag|missing field' <<< "${_ns_out}" && _ns_bad=1
      for _ns_log in "$@"; do
        _ns_re="${_ns_log//./\\.}"
        grep -qE "^${_ns_re} <|^${_ns_re}.*does not exist, skipped" <<< "${_ns_out}" || _ns_bad=1
      done
      if [[ "${_ns_bad}" -eq 1 ]]; then
        echo "[pfsense] newsyslog dry-run output for ${remote}:" >&2
        printf '%s\n' "${_ns_out}" | sed 's/^/[pfsense]   /' >&2
        _pf_remote_exec "${_NSUDO}${_PF_BIN_RM} -f '${remote}'" || true
        log_die "newsyslog drop-in ${name} failed the dry-run check — removed ${remote}"
      fi
      if grep -q 'does not exist, skipped' <<< "${_ns_out}"; then
        echo "[pfsense] NOTE: a log named in ${remote} does not exist yet — newsyslog has registered it and rotates it once its producer creates it."
      fi
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
      # Full-path sudo binaries (_PF_BIN_MKDIR, _PF_BIN_CP) are used, so the
      # deploy account's sudo allow-list needs exactly those two entries.
      local _SUDO=""
      [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "
      _pf_remote_exec "${_SUDO}${_PF_BIN_MKDIR} -p '${dst_dir}' && ${_SUDO}${_PF_BIN_CP} -R '${stage_dir}'/. '${dst_dir}'/"
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

  # SURU_SURICATA_TEST / SURU_SURICATA_TEST_TIMEOUT: pre-restart `suricata -T`
  # gate. Validated here, before the staging setup, so a typo dies
  # before the backup and any config change.
  local _suri_test_mode="${SURU_SURICATA_TEST:-false}"
  _suri_test_mode="$(printf '%s' "${_suri_test_mode}" | tr '[:upper:]' '[:lower:]')"
  case "${_suri_test_mode}" in
    auto|true|false) ;;
    *) log_die "SURU_SURICATA_TEST must be 'auto', 'true' or 'false', got: '${SURU_SURICATA_TEST:-}'" ;;
  esac
  local _suri_test_timeout="${SURU_SURICATA_TEST_TIMEOUT:-900}"
  if ! [[ "${_suri_test_timeout}" =~ ^[0-9]+$ ]]; then
    log_die "SURU_SURICATA_TEST_TIMEOUT must be a non-negative integer (seconds per instance; 0 = unbounded), got: '${_suri_test_timeout}'"
  fi
  # SURU_SURICATA_REBUILD: true adds --rebuild to the rules applier, which
  # then syncs with the package rules rebuild even when the rule selection is
  # already at target, prints no no-change sentinel, and the consolidated
  # restart follows (a deploy made before the applier forced $rebuild_rules
  # left the engines on a stale rules/suricata.rules). Validated here with the
  # other Suricata knobs, before the backup and the dead-man's switch, so a typo
  # dies before any config change. One-shot: set it for one deploy, unset it.
  local _suri_rebuild_flag=""
  case "$(printf '%s' "${SURU_SURICATA_REBUILD:-false}" | tr '[:upper:]' '[:lower:]')" in
    true)
      _suri_rebuild_flag=" --rebuild"
      log_warn "SURU_SURICATA_REBUILD=true — this deploy rebuilds the Suricata rules and restarts the engines even with no rule-selection change; unset it after this deploy"
      ;;
    false) ;;
    *) log_die "SURU_SURICATA_REBUILD must be 'true' or 'false', got: '${SURU_SURICATA_REBUILD:-}'" ;;
  esac
  # On an inline deploy the gate re-arms the dead-man's switch to cover the test
  # (SURU_SAFETY_REVERT_SECONDS + timeout x instances); an unbounded
  # test cannot be covered, so that combination is refused here, before the backup.
  if [[ "${_suri_test_mode}" != "false" && "${_suri_test_timeout}" == "0" \
        && "${SURICATA_IPS_MODE:-legacy}" == "inline" \
        && "${SURU_SAFETY_TIMER:-true}" == "true" \
        && "${SURU_SURICATA_RESTART:-true}" == "true" ]]; then
    log_die "SURU_SURICATA_TEST_TIMEOUT=0 (unbounded) cannot be combined with SURICATA_IPS_MODE=inline and the dead-man's switch: its window is sized from the per-instance limit. Set a non-zero SURU_SURICATA_TEST_TIMEOUT, or SURU_SURICATA_TEST=false."
  fi

  # --- Setup: create remote staging dir, register cleanup --------------------
  # Clean-slate every deploy: sudo-remove any leftover staging first, THEN
  # recreate it as the deploy user. This is load-bearing — dir-installs below
  # run `sudo cp`/`sudo mkdir` into staging, so a prior deploy can leave
  # root-owned files/dirs there that a non-root cleanup cannot unlink. A stale
  # root-owned file then blocks the next deploy's SCP re-stage with
  # "dest open: Permission denied" (observed live 2026-07-03). Removing with
  # sudo at setup guarantees a clean start regardless of how a previous deploy
  # exited (its EXIT-trap cleanup may have been interrupted or unable to remove
  # root-owned cruft). the deploy account's sudo allow-list covers rm; the path is a fixed constant
  # (never interpolated from untrusted input).
  echo "[pfsense] Creating remote staging dir (clean slate): ${_PF_REMOTE_STAGING}"
  local _stage_sudo=""; [[ "${ssh_user}" != "root" ]] && _stage_sudo="sudo "
  if [[ "${dry_run}" != "true" ]]; then
    # chmod 700: secret-bearing files (AbuseIPDB/MaxMind patterns) are
    # scp'd here before their own chmod 600 — a 0755 staging dir leaves a brief
    # world-readable window for another local user on a multi-account router.
    _pf_remote_exec "${_stage_sudo}${_PF_BIN_RM} -rf ${_PF_REMOTE_STAGING} && mkdir -p ${_PF_REMOTE_STAGING} && chmod 700 ${_PF_REMOTE_STAGING}"
  fi
  # Cleanup staging dir on script exit (best-effort — does not fail deploy).
  # Uses sudo so it also removes any root-owned files created by sudo
  # dir-installs during this deploy; the setup-time clean-slate above is the
  # real guarantee, this just keeps the box tidy between deploys.
  #
  # Reads ONLY the _PF_TRAP_* snapshot — never this function's locals, which are
  # out of scope when the trap fires after a `return`. The empty-target /
  # empty-opts guards are load-bearing under bash 3.2, where "${arr[@]}" on an
  # empty array is itself an unbound-variable error with `set -u`.
  #
  # Chains _deploy_cleanup because bash has a single EXIT trap and each install
  # REPLACES the last: lib/api.sh arms `trap _api_cleanup_tmp EXIT` on its first
  # source, deploy.sh replaces it, and this replaces that. (This driver sources
  # the lib a second time; that arm is guarded so it cannot reset the chain.)
  # Unchained, lib/api.sh's 0600 temp files survived every run via deploy.sh.
  # Guarded with `declare -f` so the driver still cleans up when sourced
  # standalone by a test.
  _pf_cleanup_staging() {
    local _exit_rc=$?
    # Temp files and the deterministic local password-file paths first:
    # the revert needs none of them (_pf_revert writes its own password file
    # and removes it right after the scp), so an interrupt during the revert
    # finds no secret material left behind by the failed step.
    _pf_remove_tmp_files
    # A non-zero exit while the revert is armed — an `exit` (log_die, a lib
    # die) that fires no ERR trap, or an interrupt (the INT/TERM/HUP traps exit
    # 130/143/129): restore the backup before the staging is cleaned up. Reads
    # the function's locals, so it runs while _platform_deploy is still on the
    # stack — which holds for `exit` and for a set -e exit; the `return`
    # refusals disarmed the revert already.
    if [[ ${_exit_rc} -ne 0 && "${_PF_REVERT_ARMED}" == "true" ]]; then
      _pf_revert_once
    fi
    if [[ "${_PF_TRAP_STAGING_KEEP}" != "true" \
       && "${_PF_TRAP_DRY_RUN}" != "true" \
       && -n "${_PF_TRAP_TARGET}" \
       && ${#_PF_TRAP_SSH_OPTS[@]} -gt 0 ]]; then
      local _cl_sudo=""; [[ "${_PF_TRAP_SSH_USER}" != "root" ]] && _cl_sudo="sudo "
      ssh "${_PF_TRAP_SSH_OPTS[@]}" "${_PF_TRAP_SSH_USER}@${_PF_TRAP_TARGET}" \
        "${_cl_sudo}${_PF_BIN_RM} -rf ${_PF_REMOTE_STAGING}" 2>/dev/null || true
    fi
    declare -f _deploy_cleanup > /dev/null 2>&1 && _deploy_cleanup || true
  }
  _PF_TRAP_DRY_RUN="${dry_run}"
  _PF_TRAP_SSH_USER="${ssh_user}"
  _PF_TRAP_TARGET="${target}"
  _PF_TRAP_SSH_OPTS=("${ssh_opts[@]}")
  _PF_TRAP_STAGING_KEEP="false"
  # The backup and revert password files live at these deterministic local paths
  # (_pf_write_password_file runs in a command substitution and cannot register
  # itself); registered so an exit or an interrupt removes them.
  _PF_TMP_FILES+=("/dev/shm/.suru-bkpass.$$" "${TMPDIR:-/tmp}/.suru-bkpass.$$")
  trap '_pf_cleanup_staging' EXIT

  # --- Encrypted pre-deploy backup -------------------------------------------
  # MUST succeed before any deploy step mutates /conf/config.xml. On any
  # failure below this point, _pf_revert_arm's ERR trap (under errtrace) and the
  # EXIT trap call _pf_revert_once, which restores the encrypted backup we just
  # took.
  if [[ "${SURU_SKIP_BACKUP:-false}" == "true" ]]; then
    echo "[pfsense] WARN: SURU_SKIP_BACKUP=true — deploying without an encrypted snapshot."
    echo "[pfsense]       Auto-revert will be unavailable if any step fails."
  else
    if ! _pf_backup; then
      echo "[pfsense] ERROR: pre-deploy backup failed — aborting before any config change." >&2
      return 1
    fi
    # Auto-revert on any subsequent failure: errtrace + the ERR trap for a failed
    # command anywhere (nested functions included), the EXIT trap for an `exit`
    # such as log_die. Disarmed on the success path below and before the
    # deliberate no-revert refusals.
    _pf_revert_arm
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
  # _ca_dir is derived from _PF_REMOTE_SYSLOG_TLS_CA (never hand-duplicated).
  local _ca_dir
  _ca_dir="$(dirname "${_PF_REMOTE_SYSLOG_TLS_CA}")"
  local _ca_local="${SURU_PKI_DIR:-${REPO_ROOT}/tier4-operations/pki/certs}/root-ca.pem"
  local _cert_local="${TIER1_CERTS_DIR:-${TIER1_DIR}/certs}/tier1-pfsense-syslogng.pem"
  local _key_local="${TIER1_CERTS_DIR:-${TIER1_DIR}/certs}/tier1-pfsense-syslogng-key.pem"
  local _TLSSUDO=""
  [[ "${ssh_user}" != "root" ]] && _TLSSUDO="sudo "

  # tls/ holds the private key — keep it root-only (700).
  # tls/ca/ holds only public CA certs — world-readable (755) so syslog-ng can
  # enter the directory regardless of the user it runs as.
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_MKDIR} -p '${_tls_dst}' && ${_TLSSUDO}${_PF_BIN_CHMOD} 700 '${_tls_dst}'"
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_MKDIR} -p '${_ca_dir}' && ${_TLSSUDO}${_PF_BIN_CHMOD} 755 '${_ca_dir}'"
  _pf_stage_and_install "${_ca_local}"   "${_PF_REMOTE_SYSLOG_TLS_CA}"
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_CHMOD} 644 '${_PF_REMOTE_SYSLOG_TLS_CA}'"
  # Create OpenSSL subject-hash symlinks required by ca-dir() lookup.
  # openssl rehash creates the new-format SHA-1 hash symlink (<hash>.0).
  # Also create the legacy MD5 hash symlink so syslog-ng libraries linked
  # against older OpenSSL/LibreSSL (which uses the old hash format) can
  # find the issuer cert. Hash is computed locally to avoid remote quoting.
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_OPENSSL} rehash '${_ca_dir}'"
  local _ca_old_hash
  _ca_old_hash="$(openssl x509 -subject_hash_old -noout -in "${_ca_local}" 2>/dev/null || true)"
  if [[ -n "${_ca_old_hash}" ]]; then
    _pf_remote_exec "${_TLSSUDO}${_PF_BIN_LN} -sf root-ca.pem '${_ca_dir}/${_ca_old_hash}.0'"
    echo "[pfsense] syslog-ng CA hash symlinks: new=$(openssl x509 -subject_hash -noout -in "${_ca_local}") old=${_ca_old_hash}"
  fi
  _pf_stage_and_install "${_cert_local}" "${_tls_dst}/client.pem"
  _pf_stage_and_install "${_key_local}"  "${_tls_dst}/client-key.pem"
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_CHMOD} 600 '${_tls_dst}/client-key.pem'"
  _pf_remote_exec "${_TLSSUDO}${_PF_BIN_CHMOD} 644 '${_tls_dst}/client.pem'"
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
  _PF_TMP_FILES+=("${tmp_syslogng}")
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
  _pf_remote_exec "${_SNGSUDO}${_PF_BIN_PHP} ${pf_syslogng_applier} ${pf_syslogng_src}"

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
         "${_SURISUDO}${_PF_BIN_PHP} ${_pf_safety_remote}"; then
      _pf_safety_armed="true"
    else
      echo "[pfsense] ERROR: could not arm the inline-flip safety timer — refusing to flip inline blind." >&2
      # DELIBERATE no-revert: this declines to continue WITHOUT rolling back the
      # stages that already succeeded (syslog-ng, certs). Only the inline flip is
      # refused; a genuine command failure still reverts. The revert is disarmed
      # explicitly: the non-zero exit that follows this `return` would otherwise
      # reach the EXIT trap. Deliberate — do not "fix"
      # this into a _pf_revert call.
      _pf_revert_disarm
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
  #
  # A10 — consolidate Suricata restarts to ONE per deploy.
  # Each Suricata applier (rules / tuning / drop-policy) calls
  # sync_suricata_package_config() UNCONDITIONALLY (writes config.xml + rebuilds
  # every per-interface yaml/rules file) and only early-exits BEFORE the sync
  # when it detects no change. A service restart just makes the running daemon
  # reload the on-disk config. Previously each applier restarted itself when it
  # changed something (`--restart`), so a fresh deploy touching several appliers
  # restarted Suricata several times back-to-back (×N interfaces, each a full
  # rule reload). Now we suppress the per-applier restart (pass NO `--restart`)
  # and, iff at least one applier actually changed config, run suricata-restart.php
  # exactly once at the end — a single reload picks up all accumulated changes.
  # An idempotent (no-op) re-deploy changes nothing, so it still triggers ZERO
  # restarts (the platform's idempotency contract).
  #
  # Change detection is by the applier's own terminal "no change" sentinel line,
  # in the SAFE direction: a Suricata applier is treated as having changed unless
  # its output explicitly contains its no-change sentinel. A future wording change
  # therefore causes an extra (harmless) restart, never a stranded unloaded config.
  local _suri_restart_enabled="true"
  [[ "${SURU_SURICATA_RESTART:-true}" == "true" ]] || _suri_restart_enabled="false"
  local _suri_change_seen="false"
  # _suri_run_applier <no-change-sentinel> <remote-cmd...>
  # Runs a Suricata applier over SSH, streams AND captures its output (via tee),
  # and flips _suri_change_seen=true unless the sentinel is present. Returns the
  # applier's own exit code so a real applier error still aborts the deploy under
  # `set -e` (and fires the ERR-trap revert) exactly as _pf_remote_exec would.
  _suri_run_applier() {
    local _sentinel="$1"; shift
    echo "[pfsense] SSH: $*"
    if [[ "${dry_run}" == "true" ]]; then
      return 0
    fi
    local _cap; _cap="$(mktemp)"
    _PF_TMP_FILES+=("${_cap}")
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "$@" 2>&1 | tee "${_cap}"
    local _rc=${PIPESTATUS[0]}
    if [[ ${_rc} -eq 0 ]] && ! grep -qF "${_sentinel}" "${_cap}"; then
      _suri_change_seen="true"
    fi
    rm -f "${_cap}"
    return "${_rc}"
  }
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
    # WAN-inline guard: inline netmap takes exclusive control of the NIC
    # rings, so arming it on the WAN uplink black-holes ALL LAN internet traffic
    # on any drop-rule false positive or a failed netmap bring-up — and the
    # dead-man's-switch restores the management path, not LAN egress. Refuse the
    # WAN NIC in inline mode unless the operator explicitly opts in.
    if [[ "${_suri_ips_mode}" == "inline" && "${_suri_entry}" == "${WAN_IFACE:-igb0}" \
          && "${SURU_ALLOW_WAN_INLINE:-false}" != "true" ]]; then
      log_die "SURICATA_IFACES entry '${_suri_entry}' is the WAN uplink (WAN_IFACE='${WAN_IFACE:-igb0}') and SURICATA_IPS_MODE=inline — inline drop on the WAN can black-hole all LAN internet traffic. Set SURU_ALLOW_WAN_INLINE=true to override (not recommended)."
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
  # SURU_SURICATA_REBUILD (validated with the other Suricata knobs above, before
  # the backup): _suri_rebuild_flag is " --rebuild" or empty.
  # A10: no --restart — the consolidated restart runs once at the end iff any
  # applier changed. Sentinel matches suricata-rules-apply.php's no-change line.
  _suri_run_applier "Nothing changed — skipping sync/restart" "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_applier} ${pf_suri_enable} ${pf_suri_disable}${_suri_ifaces_flag} --ips-mode=${_suri_ips_mode}${_suri_netmap_threads_flag}${_suri_rebuild_flag}"

  # --- Suricata engine tuning (detect profile) — hardware-adaptive ------------
  # Sets detect_eng_profile on every Suricata interface to the hw-profile value,
  # and turns on the app-layer parsers the deployed rule set needs: with a
  # parser off, a signature on its protocol never loads (bittorrent-dht,
  # which the package generates as off when the key is unset).
  # Skipped when SURU_SURICATA_TUNING=false (operator opt-out).
  if [[ "${SURU_SURICATA_TUNING:-true}" == "true" ]]; then
    local pf_suri_tuning="${_PF_REMOTE_STAGING}/suricata-tuning-apply.php"
    local _suri_parsers="bittorrent-dht"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_TUNING}" "${pf_suri_tuning}"
    # A10: tuning never self-restarted (it relied on a later applier's restart);
    # route it through the change tracker so a tuning-only change still triggers
    # the single consolidated restart. Sentinel matches suricata-tuning-apply.php.
    _suri_run_applier "No changes — all tuning values already at target" "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_tuning} --profile=${_hw_suricata_profile} --stream-memcap=${_hw_suricata_stream_memcap} --reassembly-memcap=${_hw_suricata_reassembly_memcap} --defrag-memcap=${_hw_suricata_defrag_memcap} --app-layer-parsers=${_suri_parsers}${_suri_ifaces_flag}"
    echo "[pfsense] Suricata tuning applied: profile=${_hw_suricata_profile} stream=${_hw_suricata_stream_memcap} reassembly=${_hw_suricata_reassembly_memcap} defrag=${_hw_suricata_defrag_memcap} parsers=${_suri_parsers}"
  else
    echo "[pfsense] Skipping Suricata engine tuning (SURU_SURICATA_TUNING=false)"
  fi

  # --- Suricata log management (eve.json rotation) — incident-hardening --------
  # Enables pfSense Suricata's built-in log-rotation cron and caps eve.json /
  # http.log size + retention. Without this the master toggle enable_log_mgmt
  # is unset and the rotation cron no-ops, letting eve.json grow unbounded
  # (2026-07-03 incident: a 96 GB eve.json was replayed byte-0 by syslog-ng
  # after a reboot, filling the SIEM disk). Global package setting, so this is
  # a single write to installedpackages/suricata/config/0 (not per-interface).
  # --run-now caps an already-oversized file on this deploy; no restart needed
  # (the cron SIGHUPs Suricata itself on rotation). Skipped when
  # SURU_SURICATA_LOG_MGMT=false (operator opt-out — leaves existing state).
  if [[ "${SURU_SURICATA_LOG_MGMT:-true}" == "true" ]]; then
    local _suri_eve_limit_kb="${SURICATA_EVE_LOG_LIMIT_KB:-500000}"
    local _suri_http_limit_kb="${SURICATA_HTTP_LOG_LIMIT_KB:-500000}"
    local _suri_log_retention_h="${SURICATA_LOG_RETENTION_HOURS:-24}"
    for _v in "${_suri_eve_limit_kb}" "${_suri_http_limit_kb}" "${_suri_log_retention_h}"; do
      [[ "${_v}" =~ ^[0-9]+$ ]] || log_die "SURICATA_*_LOG_* values must be integers, got: '${_v}'"
    done
    local pf_suri_logmgmt="${_PF_REMOTE_STAGING}/suricata-logmgmt-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_LOGMGMT}" "${pf_suri_logmgmt}"
    _pf_remote_exec "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_logmgmt} --enable --eve-limit-kb=${_suri_eve_limit_kb} --http-limit-kb=${_suri_http_limit_kb} --retention-hours=${_suri_log_retention_h} --run-now"
    echo "[pfsense] Suricata log management applied: eve/http limit=${_suri_eve_limit_kb}/${_suri_http_limit_kb} KB, retention=${_suri_log_retention_h}h"
  else
    echo "[pfsense] Skipping Suricata log management (SURU_SURICATA_LOG_MGMT=false — existing rotation state left as-is)"
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
    # A10: no --restart; sentinel matches suricata-drop-policy-apply.php's no-change line.
    _suri_run_applier "No changes — policy already at target" "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_drop}${_suri_ifaces_flag} --drop-categories=${_suri_drop_cats}"
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

  # --- Suricata config test (pre-restart gate) ---
  # Runs `suricata -T` against every configured per-interface yaml BEFORE the
  # consolidated restart below, so a config the package just regenerated is
  # proven loadable before any engine is asked to load it. Runs only when at
  # least one applier changed config (_suri_change_seen) — an idempotent deploy
  # regenerated nothing and pays nothing. Transport is SSH (staged applier), not
  # the REST API: a config test inside PHP-FPM risks exhausting router memory.
  # Opt-in (SURU_SURICATA_TEST default false): a full test builds the detection
  # engine and takes minutes per instance (about 300 s on a 4 GB router with the
  # ET Open set), hence the 900 s default limit. Rules that fail to parse are
  # reported by the applier and do not fail the test (the running engines skip
  # them too), as are missing rule files (on a WARN line); a configuration the
  # engine cannot load fails, and so does one that loads no rules at all. With
  # SURU_SURICATA_RESTART=false there is no restart to gate, so the test is
  # skipped too. The remote call uses SSH keepalives (_pf_remote_exec_long): the
  # applier prints nothing while one instance is being tested.
  #
  # DEAD-MAN'S-SWITCH WINDOW (inline deploys): the timer
  # armed before the appliers would otherwise fire mid-test, revert to legacy and
  # restart Suricata into the untested config. So, when it is armed, the gate
  # re-arms it BEFORE the test to SURU_SAFETY_REVERT_SECONDS + timeout x N, and
  # AFTER a pass to the plain SURU_SAFETY_REVERT_SECONDS, so the consolidated
  # restart gets its usual window. N is the larger of the SURICATA_IFACES count
  # (local) and the router's configured instance count (`--count`, the exact set
  # the test runs): the two differ when the router carries instances the deploy
  # does not manage. An unreadable count or a failed re-arm refuses like a failed
  # test. Timeout 0 with the switch is refused at validation, before the backup.
  # Every refusal disarms the switch (_suri_test_refuse_switch): the inline
  # config is saved but unproven, and no revert is wanted (see below).
  #
  # DELIBERATE no-revert on failure: this refuses with `return 1` from inside an
  # `if !` guard after disarming the revert (_suri_test_refuse_switch calls
  # _pf_revert_disarm), so _pf_revert is not called. The appliers
  # ran without --restart, so the running engines still hold their previous,
  # working config; a revert would restore config.xml and then restart Suricata
  # against per-interface yamls nobody regenerated — i.e. likely into the very
  # config that just failed. Refusing leaves the IDS running. Documented in
  # Deliberate — do not "fix" this into a _pf_revert call.
  local _suri_test_min_gb=4
  local _suri_test_run="true"
  local _suri_test_reason=""
  local _suri_test_hw="unknown"
  [[ "${_hw_physmem_gb}" =~ ^[0-9]+$ ]] && _suri_test_hw="${_hw_physmem_gb}"
  if [[ "${_suri_test_mode}" == "false" ]]; then
    _suri_test_run="false"
    _suri_test_reason="SURU_SURICATA_TEST=false; set auto or true to enable"
  elif [[ "${_suri_restart_enabled}" != "true" ]]; then
    _suri_test_run="false"
    _suri_test_reason="SURU_SURICATA_RESTART=false; no restart to gate"
  elif [[ "${_suri_test_mode}" == "auto" && "${_suri_test_hw}" != "unknown" ]] \
       && (( _suri_test_hw < _suri_test_min_gb )); then
    _suri_test_run="false"
    _suri_test_reason="hw gate: ${_suri_test_hw} GB < ${_suri_test_min_gb} GB (set SURU_SURICATA_TEST=true to force)"
  fi
  if [[ "${_suri_test_run}" == "true" ]]; then
    echo "[pfsense] Suricata config test: mode=${_suri_test_mode} hw_gb=${_suri_test_hw} → enabled (timeout ${_suri_test_timeout}s/instance)"
  elif [[ "${_suri_test_mode}" == "false" || "${_suri_restart_enabled}" != "true" ]]; then
    echo "[pfsense] Suricata config test: mode=${_suri_test_mode} → skipped (${_suri_test_reason})"
  else
    echo "[pfsense] WARN: Suricata config test: mode=${_suri_test_mode} hw_gb=${_suri_test_hw} → skipped (${_suri_test_reason})"
  fi
  if [[ "${dry_run}" == "true" ]]; then
    if [[ "${_suri_test_run}" == "true" ]]; then
      echo "[pfsense] (dry-run) would run suricata-test-configs.php on every configured instance before the consolidated restart"
      if [[ "${_suri_ips_mode}" == "inline" && "${SURU_SAFETY_TIMER:-true}" == "true" ]]; then
        echo "[pfsense] (dry-run) would re-arm the dead-man's switch to ${SURU_SAFETY_REVERT_SECONDS:-600}s + ${_suri_test_timeout}s x instances before the test and to ${SURU_SAFETY_REVERT_SECONDS:-600}s after it"
      fi
    fi
  elif [[ "${_suri_test_run}" == "true" && "${_suri_change_seen}" == "true" ]]; then
    # _suri_test_refuse_switch — every refusal below, when the switch is armed:
    # cancel the pending sleeper. The inline config is saved but no restart
    # proved it, and the sleeper would otherwise fire a revert-to-legacy restart
    # mid-refusal.
    _suri_test_refuse_switch() {
      # Every refusal is a deliberate no-revert (see the note above): disarm the
      # revert first so the non-zero exit that follows the `return 1` cannot
      # reach the EXIT trap's revert.
      _pf_revert_disarm
      [[ "${_pf_safety_armed}" == "true" ]] || return 0
      safety_timer_disarm_quiet
      _pf_safety_armed="false"
      echo "[pfsense] ERROR: dead-man's switch: the sleeper is stopped; the inline config stays saved in config.xml until a corrected deploy." >&2
    }
    local pf_suri_test="${_PF_REMOTE_STAGING}/suricata-test-configs.php"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_TEST}" "${pf_suri_test}"
    if [[ "${_pf_safety_armed}" == "true" ]]; then
      local _suri_test_n_ifaces=0 _suri_test_n_cfg="" _suri_test_n _suri_test_window _suri_test_e
      for _suri_test_e in ${_suri_ifaces//,/ }; do
        _suri_test_n_ifaces=$((_suri_test_n_ifaces + 1))
      done
      if ! _suri_test_n_cfg="$(_pf_remote_exec "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_test} --count" | tail -n 1)" \
         || ! [[ "${_suri_test_n_cfg}" =~ ^[0-9]+$ ]]; then
        echo "[pfsense] ERROR: could not read the configured Suricata instance count — cannot size the dead-man's-switch window for the config test; refusing to test and restart without it." >&2
        echo "[pfsense] ERROR: no restart issued — the running Suricata engines are untouched; config.xml and the per-interface yamls hold the new, untested config." >&2
        _suri_test_refuse_switch
        return 1
      fi
      _suri_test_n="${_suri_test_n_ifaces}"
      if (( _suri_test_n_cfg > _suri_test_n )); then _suri_test_n="${_suri_test_n_cfg}"; fi
      _suri_test_window=$(( _pf_safety_secs + _suri_test_timeout * _suri_test_n ))
      echo "[pfsense] Suricata config test: dead-man's switch re-armed for the test — ${_pf_safety_secs}s + ${_suri_test_timeout}s x ${_suri_test_n} instance(s) (SURICATA_IFACES ${_suri_test_n_ifaces}, configured ${_suri_test_n_cfg}) = ${_suri_test_window}s"
      if ! safety_timer_arm "${_suri_test_window}" "${_PF_APPLIER_SURICATA_SAFETY_REVERT}" "${_SURISUDO}${_PF_BIN_PHP} ${_pf_safety_remote}"; then
        echo "[pfsense] ERROR: could not re-arm the dead-man's switch for the config test — refusing to test and restart inline without it." >&2
        echo "[pfsense] ERROR: no restart issued — the running Suricata engines are untouched; config.xml and the per-interface yamls hold the new, untested config." >&2
        _suri_test_refuse_switch
        return 1
      fi
    fi
    if ! _pf_remote_exec_long "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_test} --timeout=${_suri_test_timeout}"; then
      echo "[pfsense] ERROR: Suricata config test FAILED — see the [suricata-test] lines above for the failing instance(s)." >&2
      echo "[pfsense] ERROR: no restart issued — the running Suricata engines are untouched and keep their previous config." >&2
      echo "[pfsense] ERROR: config.xml and the per-interface yamls now hold the failing config; a Suricata restart or reboot before a corrected deploy will start against it." >&2
      echo "[pfsense] ERROR: recovery: fix the offending content and re-run 'make deploy', or restore a backup from tier1-perimeter/backups/ via the GUI." >&2
      echo "[pfsense] ERROR: to bypass this gate deliberately, set SURU_SURICATA_TEST=false." >&2
      _suri_test_refuse_switch
      return 1
    fi
    echo "[pfsense] Suricata config test: all instances passed — proceeding to the consolidated restart."
    if [[ "${_pf_safety_armed}" == "true" ]]; then
      echo "[pfsense] Suricata config test: dead-man's switch re-armed to ${_pf_safety_secs}s for the consolidated restart."
      if ! safety_timer_arm "${_pf_safety_secs}" "${_PF_APPLIER_SURICATA_SAFETY_REVERT}" "${_SURISUDO}${_PF_BIN_PHP} ${_pf_safety_remote}"; then
        echo "[pfsense] ERROR: could not re-arm the dead-man's switch after the config test — refusing to restart inline without it." >&2
        echo "[pfsense] ERROR: no restart issued — the running Suricata engines are untouched; config.xml and the per-interface yamls hold the new, tested config." >&2
        _suri_test_refuse_switch
        return 1
      fi
    fi
  elif [[ "${_suri_test_run}" == "true" ]]; then
    echo "[pfsense] Suricata config test: no applier changed config — nothing to test (idempotent deploy)."
  fi

  # --- Suricata consolidated restart (A10) -------------------------------------
  # Exactly ONE restart for the whole Suricata applier chain above, and only if
  # at least one applier actually changed config (_suri_change_seen). An
  # idempotent re-deploy changed nothing → zero restarts. Honors the
  # SURU_SURICATA_RESTART=false operator opt-out (then never restarts, even on a
  # change — the operator has taken ownership of restarting Suricata manually).
  if [[ "${_suri_restart_enabled}" == "true" && "${_suri_change_seen}" == "true" ]]; then
    local pf_suri_restart="${_PF_REMOTE_STAGING}/suricata-restart.php"
    _pf_stage_and_install "${_PF_APPLIER_SURICATA_RESTART}" "${pf_suri_restart}"
    # Set before issuing it: a restart that fails midway may have restarted engines.
    _pf_suri_restarted="true"
    _pf_remote_exec "${_SURISUDO}${_PF_BIN_PHP} ${pf_suri_restart}"
    echo "[pfsense] Suricata: single consolidated restart issued (A10 — ≥1 applier changed config)."
  elif [[ "${_suri_restart_enabled}" != "true" ]]; then
    echo "[pfsense] Suricata restart disabled (SURU_SURICATA_RESTART=false) — no restart despite any applier changes."
  else
    echo "[pfsense] Suricata: no applier changed config — no restart needed (idempotent deploy, A10)."
  fi

  # --- Early disarm of the inline-flip dead-man's-switch ----------------------
  # Disarm HERE — immediately after the A10 consolidated restart, the ONE action
  # in the whole chain that actually restarts the Suricata daemon and engages
  # netmap on the physical NIC (every applier above runs with no --restart, so the
  # daemon has not moved off legacy/pcap until this point). This SSH round-trip
  # returning shows the shared connection survived the flip; the proof that a
  # NEW login still reaches the router is the disarm itself, which forces a
  # fresh connection (lib/safety-timer.sh _SAFETY_FRESH_CONN). Disarming any
  # earlier (e.g.
  # right after the drop-policy applier) would cancel the timer BEFORE the risky
  # restart — removing the backstop during the exact window it exists for.
  # Disarming here (rather than at end-of-deploy) still shrinks the window to
  # exclude the long pfBlockerNG-import/Zeek tail, so a slow deploy can no longer
  # trip a mid-deploy auto-revert (the silent inline->legacy downgrade).
  if [[ "${_pf_safety_armed}" == "true" ]]; then
    safety_timer_disarm
    _pf_safety_armed="false"
  fi

  # --- pf state-table tuning — hardware-adaptive --------------------------------
  # Sets system/maximumstates to prevent RAM exhaustion under heavy traffic.
  # Enables adaptive state expiry (60%→120% threshold) for graceful degradation.
  # Skipped when SURU_PF_TUNING=false (operator opt-out).
  if [[ "${SURU_PF_TUNING:-true}" == "true" ]]; then
    local pf_pf_tuning="${_PF_REMOTE_STAGING}/pf-tuning-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_PF_TUNING}" "${pf_pf_tuning}"
    _pf_remote_exec "${_SURISUDO}${_PF_BIN_PHP} ${pf_pf_tuning} --max-states=${_hw_pf_max_states} --adaptive"
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
    _pf_remote_exec "${_SURISUDO}${_PF_BIN_PHP} ${pf_dns_tuning} --msg-cache-mb=${_hw_unbound_msg_cache_mb} --rrset-cache-mb=${_hw_unbound_rrset_cache_mb}"
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
  _pf_remote_exec "${_ZSUDO}${_PF_BIN_PHP} ${pf_zeek_applier} ${pf_zeek_stage}"

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
  _pf_remote_exec "${_ZSUDO}${_PF_BIN_MKDIR} -p /var/log/zeek"

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
    _pf_remote_exec "${_ZSUDO}${_PF_BIN_PHP} ${pf_zeek_iface_applier} '${ZEEK_IFACE}' '${_hw_zeek_lb_procs}'"
  else
    echo "[pfsense] WARN: ZEEK_IFACE is unset — skipping Zeek interface config."
    echo "[pfsense]       node.cfg will keep its current interface. Set ZEEK_IFACE in .env."
  fi

  # zeekctl deploy activates the freshly written local.zeek and node.cfg.
  _pf_remote_exec "${_ZSUDO}${_PF_BIN_ZEEKCTL} deploy"

  # --- unbound local-zones platform default ----------------------------------
  # Answer local namespaces locally, never forwarded upstream:
  #   .local (RFC 6762) + wpad.<system domain> -> always_nxdomain (SURU sentinel
  #     block in the DNS Resolver custom options), and
  #   the system domain itself -> system_domain_local_zone_type=static (pfSense
  #     native field) so unknown internal names get a LOCAL NXDOMAIN instead of
  #     leaking to / looping through the upstream forwarder.
  # Runs BEFORE the pfBlockerNG stage; the applier re-runs
  # sync_package_pfblockerng('noupdates') after reconfiguring unbound (the
  # module-config regression on resolver reconfigure) and verifies the zones +
  # python module + system-domain static from live config. The applier
  # auto-skips the system-domain static when a domain-override forwards the
  # system domain to a NON-local (real internal) DNS server, so it never breaks
  # split-horizon. Override the whole stage with SURU_UNBOUND_LOCALZONES=false;
  # keep the .local hardening but skip only the system-domain static with
  # SURU_UNBOUND_SYSTEM_DOMAIN_STATIC=false.
  if [[ "${SURU_UNBOUND_LOCALZONES:-true}" == "true" ]]; then
    local pf_unbound_lz_remote="${_PF_REMOTE_STAGING}/unbound-localzones-apply.php"
    _pf_stage_and_install "${_PF_APPLIER_UNBOUND_LZ}" "${pf_unbound_lz_remote}"
    local _ULZSUDO=""
    [[ "${ssh_user}" != "root" ]] && _ULZSUDO="sudo "
    local _ulz_args=""
    [[ "${SURU_UNBOUND_SYSTEM_DOMAIN_STATIC:-true}" != "true" ]] && _ulz_args=" --no-system-domain-static"
    _pf_remote_exec "${_ULZSUDO}${_PF_BIN_PHP} ${pf_unbound_lz_remote}${_ulz_args}"
    _pf_remote_exec "${_ULZSUDO}${_PF_BIN_RM} -f '${pf_unbound_lz_remote}'"
  else
    echo "[pfsense] Skipping unbound local-zones (SURU_UNBOUND_LOCALZONES=false)."
  fi

  # --- pfBlockerNG block-log rotation (dnsbl.log / ip_block.log) --------------
  # pfBlockerNG has NO rename-based rotation for its block logs: its nightly
  # cron ends with pfb_log_mgmt() (pfblockerng.inc), which rewrites each log
  # IN PLACE — `tail -n <log_max_*> log > tmp; mv -f tmp log`. The inode swap
  # makes syslog-ng's file() source re-read the whole retained tail from byte 0
  # every night (~40k lines of already-shipped history), and the GUI's
  # "No Limit" cap is unreachable — pfb_filter(PFB_FILTER_NUM) rejects the
  # literal and returns the 20000 default — so the rewrite cannot be switched
  # off. The platform therefore owns retention through pfSense's NATIVE
  # newsyslog (runs every minute from /etc/crontab; the generated
  # /etc/newsyslog.conf includes /var/etc/newsyslog.conf.d/*, where pfSense
  # keeps manually added files): a drop-in rotates both logs by RENAME at a
  # time-of-day just BEFORE the pfBlockerNG cron hour (default @T2359 vs the
  # 00:00 cron), so the vendor rewrite only ever touches a ~1-minute file, and
  # by size as a backstop. The SIEM pipeline restores each line's own event
  # time (tier3-core/config/logstash-pfsense/pipelines/40-pfblockerng.conf),
  # so any residual re-read keeps its original day and, with the pipeline's
  # deterministic _id, UPSERTS instead of duplicating. Persistence class B: a
  # file on persistent /var, re-converged on every deploy (like zeekctl.cfg).
  # Flags: J = bzip2 (pfSense's own compression choice), B = no "logfile
  # turned over" banner (it would land in Tier 3 as a _csvparsefailure doc).
  # Both writers append per event by path (pfb_unbound.py log_entry: open(..,
  # "a"); pfblockerng.inc: file_put_contents(.., FILE_APPEND)), so a rename
  # loses nothing. Owners below are the live ones — dnsbl.log unbound:unbound
  # 0600 (pfb_unbound_python() chowns it to unbound on every reload,
  # pfblockerng.inc:2459-2466; the resolver's python hook writes as unbound),
  # ip_block.log root:wheel 0600 (written by the root filterlog daemon; see
  # also templates/pfsense/syslog-ng.conf.tpl) — newsyslog recreates each log
  # with exactly these credentials after the rename. The files are deliberately
  # NOT pre-created: the filterlog daemon parses the full filter.log backlog
  # only when none of its logs exist yet (pfblockerng.inc:5429), and a
  # pre-created file would change that. Install + dry-run proof:
  # _pf_install_newsyslog_dropin. Skipped with
  # SURU_PFBLOCKERNG_LOG_ROTATION=false (leaves existing state as-is).
  if [[ "${SURU_PFBLOCKERNG_LOG_ROTATION:-true}" == "true" ]]; then
    local _pfbrot_time="${PFBLOCKERNG_LOG_ROTATE_TIME:-@T2359}"
    local _pfbrot_kb="${PFBLOCKERNG_LOG_ROTATE_KB:-10240}"
    local _pfbrot_count="${PFBLOCKERNG_LOG_ROTATE_COUNT:-7}"
    [[ "${_pfbrot_time}" =~ ^@T([01][0-9]|2[0-3])[0-5][0-9]$ ]] \
      || log_die "PFBLOCKERNG_LOG_ROTATE_TIME must be a newsyslog daily time-of-day '@Thhmm', got: '${_pfbrot_time}'"
    for _v in "${_pfbrot_kb}" "${_pfbrot_count}"; do
      [[ "${_v}" =~ ^[0-9]+$ ]] || log_die "PFBLOCKERNG_LOG_ROTATE_KB / _COUNT must be integers, got: '${_v}'"
    done
    local tmp_pfbrot; tmp_pfbrot="$(mktemp)"
    _PF_TMP_FILES+=("${tmp_pfbrot}")
    {
      printf '# SURU Tier 1 — pfBlockerNG block-log rotation. Managed by deploy; do not edit.\n'
      printf '# Rotates by RENAME just before the pfBlockerNG cron hour so its in-place log\n'
      printf '# rewrite (pfb_log_mgmt) never re-feeds a full log to syslog-ng. B = no banner.\n'
      printf '# logfilename\t\t\t\towner:group\tmode\tcount\tsize(KB)\twhen\tflags\n'
      printf '/var/log/pfblockerng/dnsbl.log\t\tunbound:unbound\t600\t%s\t%s\t%s\tJB\n' "${_pfbrot_count}" "${_pfbrot_kb}" "${_pfbrot_time}"
      printf '/var/log/pfblockerng/ip_block.log\troot:wheel\t600\t%s\t%s\t%s\tJB\n' "${_pfbrot_count}" "${_pfbrot_kb}" "${_pfbrot_time}"
    } > "${tmp_pfbrot}"
    _pf_install_newsyslog_dropin suru-pfblockerng "${tmp_pfbrot}" /var/log/pfblockerng/dnsbl.log /var/log/pfblockerng/ip_block.log
    rm -f -- "${tmp_pfbrot}"
    local pf_pfbrot_remote; pf_pfbrot_remote="$(_pf_newsyslog_dropin_path suru-pfblockerng)"
    echo "[pfsense] pfBlockerNG log rotation installed: ${pf_pfbrot_remote} (daily at ${_pfbrot_time} or ${_pfbrot_kb} KB, keep ${_pfbrot_count}, rename + bzip2, no banner)"
  else
    echo "[pfsense] Skipping pfBlockerNG log rotation (SURU_PFBLOCKERNG_LOG_ROTATION=false — existing rotation state left as-is)"
  fi

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
    # The GeoIP/ASN keys are passed to the globals applier as a 0600 secrets
    # FILE (not embedded in rendered content). Each value is validated with the
    # same shared guard the AbuseIPDB key uses, then staged via secret_mktemp
    # (tmpfs-preferred, 0600). An invalid value is ignored (treated as unset)
    # with a WARN — never written into the file, where a newline/metachar could
    # otherwise inject a spurious KEY=VALUE line.
    local _mm_acct="${MAXMIND_ACCOUNT_ID:-}" _mm_key="${MAXMIND_LICENSE_KEY:-}" _ipinfo_tok="${IPINFO_TOKEN:-}"
    if [[ -n "${_mm_acct}" ]]    && ! secret_charset_ok "${_mm_acct}";    then echo "[pfsense] WARN: MAXMIND_ACCOUNT_ID has invalid characters (allowed: A-Za-z0-9._-) — ignoring."; _mm_acct=""; fi
    if [[ -n "${_mm_key}" ]]     && ! secret_charset_ok "${_mm_key}";     then echo "[pfsense] WARN: MAXMIND_LICENSE_KEY has invalid characters (allowed: A-Za-z0-9._-) — ignoring."; _mm_key=""; fi
    if [[ -n "${_ipinfo_tok}" ]] && ! secret_charset_ok "${_ipinfo_tok}"; then echo "[pfsense] WARN: IPINFO_TOKEN has invalid characters (allowed: A-Za-z0-9._-) — ignoring."; _ipinfo_tok=""; fi
    if [[ -n "${_mm_acct}" || -n "${_mm_key}" || -n "${_ipinfo_tok}" ]]; then
      local _pfb_secrets_local
      _pfb_secrets_local="$(secret_mktemp)"   # already mode 0600 (see lib/secrets.sh)
      _PF_TMP_FILES+=("${_pfb_secrets_local}")
      # GeoIP needs both MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY (the applier
      # only enables GeoIP when both are present); ASN needs IPINFO_TOKEN.
      {
        [[ -n "${_mm_acct}" ]]    && printf 'MAXMIND_ACCOUNT_ID=%s\n' "${_mm_acct}"
        [[ -n "${_mm_key}" ]]     && printf 'MAXMIND_KEY=%s\n'        "${_mm_key}"
        [[ -n "${_ipinfo_tok}" ]] && printf 'ASN_TOKEN=%s\n'         "${_ipinfo_tok}"
      } > "${_pfb_secrets_local}"
      _pfb_ip_secrets_remote="${_PF_REMOTE_STAGING}/pfb-ipconfig.secrets"
      if [[ "${dry_run}" != "true" ]]; then
        scp "${ssh_opts[@]}" "${_pfb_secrets_local}" "${ssh_user}@${target}:${_pfb_ip_secrets_remote}"
        _pf_remote_exec "${_PFGSUDO}${_PF_BIN_CHMOD} 600 '${_pfb_ip_secrets_remote}'"
      fi
      rm -f -- "${_pfb_secrets_local}"
      echo "[pfsense] pfBlockerNG IP-config secrets staged (GeoIP/ASN enable on demand)."
    fi

    _pf_remote_exec "${_PFGSUDO}${_PF_BIN_PHP} ${pf_pfb_globals_remote} ${_pfb_ip_secrets_remote} --table-entries=${_hw_pf_table_entries}"

    # Shred the staged secrets file after the applier has consumed it.
    if [[ -n "${_pfb_ip_secrets_remote}" && "${dry_run}" != "true" ]]; then
      _pf_remote_exec "${_PFGSUDO}${_PF_BIN_RM} -f '${_pfb_ip_secrets_remote}'"
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
  # The key rides inside the rendered importer's feed URL, so it is validated +
  # substituted into a tmpfs-preferred 0600 staged copy via the shared
  # secret-hygiene helpers (lib/secrets.sh) that the GeoIP/ASN secrets file
  # above also uses.
  local tmp_importer; tmp_importer="$(secret_mktemp)"
  _PF_TMP_FILES+=("${tmp_importer}")
  local _pfb_abuseipdb_key="${ABUSEIPDB_API_KEY:-}"
  if [[ -n "${_pfb_abuseipdb_key}" ]] && ! secret_charset_ok "${_pfb_abuseipdb_key}"; then
    echo "[pfsense] WARN: ABUSEIPDB_API_KEY has invalid characters (allowed: A-Za-z0-9._-) — treating as unset (sed/URL injection guard)."
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
    _pf_remote_exec "${_PBSUDO}${_PF_BIN_CHMOD} 600 '${pf_importer_remote}'"
  fi
  _pf_remote_exec "${_PBSUDO}${_PF_BIN_PHP} ${pf_importer_remote}"
  if [[ -n "${_pfb_abuseipdb_key}" && "${dry_run}" != "true" ]]; then
    _pf_remote_exec "${_PBSUDO}${_PF_BIN_RM} -f '${pf_importer_remote}'"
  fi
  # Deploy succeeded — keep the staging dir on the router for the next deploy's
  # clean-slate rm (see the note above). The EXIT trap stays ARMED so its chained
  # temp-file cleanup still runs: disarming it outright here also silently
  # skipped that, leaking lib/api.sh's 0600 temp files on every success.
  _PF_TRAP_STAGING_KEEP="true"
  # Deploy succeeded — disarm the auto-revert (ERR and EXIT) so a failure in the
  # purely-informational verify/validate blocks below doesn't roll us back.
  _pf_revert_disarm

  # Reaching this line means every risky step (incl. the inline flip) completed
  # over the shared connection. The disarm below opens a fresh connection
  # (lib/safety-timer.sh _SAFETY_FRESH_CONN): only if a NEW login still reaches
  # the router does it cancel the router-side dead-man's-switch, so no
  # auto-revert fires. If we had instead lost SSH mid-deploy, control never
  # reaches here, the timer is left armed, and the router reverts itself to
  # legacy — restoring the management path.
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

  # --- Remove secret material from staging ------------------------------------
  # The staging dir stays on the router until the next deploy's clean-slate rm,
  # so anything secret-bearing is removed now: the staged client private key,
  # the backup-password files, the pfBlockerNG IP-config secrets file and the
  # importer (it carries the AbuseIPDB key when one is set). Account-owned
  # files use a plain rm; the two root-touched ones use sudo rm. Explicit names,
  # never a glob (the remote login shell for a non-root user is tcsh, which
  # aborts a command whose glob matches nothing).
  if [[ "${dry_run}" != "true" ]]; then
    local _sec_sudo=""; [[ "${ssh_user}" != "root" ]] && _sec_sudo="sudo "
    _pf_remote_exec "rm -f '${_PF_REMOTE_STAGING}/client-key.pem' '${_PF_REMOTE_STAGING}/.suru-bkpass' '${_PF_REMOTE_STAGING}/.suru-bkpass-revert'" \
      || echo "[pfsense] WARN: could not remove staged key/password files from ${_PF_REMOTE_STAGING}; the next deploy's clean-slate removes them." >&2
    _pf_remote_exec "${_sec_sudo}${_PF_BIN_RM} -f '${_PF_REMOTE_STAGING}/pfb-ipconfig.secrets' '${_PF_REMOTE_STAGING}/import-pfblockerng.php'" \
      || echo "[pfsense] WARN: could not remove staged pfBlockerNG secret files from ${_PF_REMOTE_STAGING}; the next deploy's clean-slate removes them." >&2
  fi

  # --- Post-deploy validation via REST API ------------------------------------
  # Non-fatal: a validation failure does not roll back the deploy. It surfaces
  # the failure to the operator and pulls recent system log entries via the
  # API to feed error analysis. Skipped on dry-run and when API creds absent.
  if [[ "${dry_run}" != "true" ]] \
     && [[ -n "${PFSENSE_API_KEY:-}" ]] \
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
