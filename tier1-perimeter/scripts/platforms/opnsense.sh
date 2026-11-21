#!/usr/bin/env bash
# SURU Platform — OPNsense platform driver
# Called by deploy.sh. Pushes rendered artefacts to OPNsense via SSH/API.
#
# INVARIANT 11: This script contains NO security policy.
# Path constants point to rendered/ — populated by tier2-telemetry/build/render.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_OPN_TEMPLATES_DIR="$(cd "${SCRIPT_DIR}/../../templates" && pwd)"

# Source REST API client. OPNsense uses its native API (built-in since 18.x).
# Provides: api_init, api_health, api_validate_deployment,
#           api_fetch_errors, api_reload_suricata_rules.
# shellcheck source=../lib/api.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/api.sh"

# --- Rendered artefact paths (source: tier1-perimeter/rendered/opnsense/) -----
_OPN_RENDERED_SURICATA_YAML="suricata/suricata.yaml"
_OPN_RENDERED_ZEEK_LOCAL="zeek/local.zeek"
_OPN_SYSLOGNG_TPL="${_OPN_TEMPLATES_DIR}/opnsense/syslog-ng.conf.tpl"

# --- Remote target paths on OPNsense device -----------------------------------
_OPN_REMOTE_SURICATA_CONF="/usr/local/etc/suricata/suricata.yaml"
_OPN_REMOTE_SYSLOGNG_CONF="/usr/local/etc/syslog-ng.conf.d/suru.conf"
_OPN_REMOTE_ZEEK_LOCAL="/usr/local/share/zeek/site/local.zeek"

# OPNsense inherits crypt.inc from its pfSense fork point — encrypt_data /
# tagfile_reformat have the same signatures and produce a backup file the
# OPNsense GUI's "System > Configuration > Backups > Restore" accepts when
# "encrypted" is selected. We can therefore reuse the same PHP appliers we
# ship for pfSense without modification.
_OPN_APPLIER_BACKUP="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/backup-encrypt.php"
_OPN_APPLIER_RESTORE="$(cd "${SCRIPT_DIR}/../../pfsense" && pwd)/backup-restore.php"
_OPN_REMOTE_STAGING="/tmp/suru-staging"
_OPN_REMOTE_BACKUP_DIR="/root/suru-backups"
_OPN_LOCAL_BACKUP_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)/backups"

_platform_deploy() {
  local target="$1" rendered="$2" dry_run="$3"
  local ssh_key="${ROUTER_SSH_KEY:-~/.ssh/suru_deploy}"
  local ssh_user="${ROUTER_SSH_USER:-root}"  # OPNsense default user is root

  # SSH_STRICT_HOST_KEY_CHECKING: controls StrictHostKeyChecking behaviour.
  # Precedence: .env / env var > OS default.
  # macOS default: accept-new  (convenient for lab/SOHO first-connect)
  # Linux default:  yes         (strict; production-safe)
  # Set SSH_STRICT_HOST_KEY_CHECKING=yes in .env to enforce on macOS too.
  local _strict_default
  case "$(uname -s)" in
    Darwin) _strict_default="accept-new" ;;
    *)      _strict_default="yes" ;;
  esac
  local _strict="${SSH_STRICT_HOST_KEY_CHECKING:-${_strict_default}}"
  # Normalise legacy boolean values from .env (yes/no/true/false)
  case "$(echo "${_strict}" | tr '[:upper:]' '[:lower:]')" in
    yes|true|strict)       _strict="yes" ;;
    no|false|accept-new)   _strict="accept-new" ;;
    off|none)              _strict="no" ;;
  esac

  # SEC-020/SEC-021: use array to avoid word-splitting on key paths; add ConnectTimeout.
  local -a ssh_opts=(-i "${ssh_key}" -o "StrictHostKeyChecking=${_strict}" -o "BatchMode=yes" -o "ConnectTimeout=15")
  # Connection reuse when deploy.sh enabled it (lib/ssh.sh ssh_mux_enable).
  if [[ -n "${SSH_MUX_OPTS+set}" && ${#SSH_MUX_OPTS[@]} -gt 0 ]]; then
    ssh_opts+=("${SSH_MUX_OPTS[@]}")
  fi

  # --- Pre-deploy API auth probe ----------------------------------------------
  # OPNsense API is built-in. We verify credentials before SSH-deploying so
  # the operator gets a fast clear failure if the key/secret is wrong.
  if [[ "${dry_run}" != "true" ]] \
     && [[ -n "${OPNSENSE_API_KEY:-}" ]] \
     && [[ "${SURU_SKIP_API_VALIDATE:-false}" != "true" ]]; then
    echo "[opnsense] Probing OPNsense API auth..."
    if api_health; then
      echo "[opnsense] API health OK."
    else
      echo "[opnsense] WARN: API health check failed — check OPNSENSE_API_KEY/SECRET."
      echo "[opnsense]       Continuing with SSH-only deploy."
    fi
  fi

  _opn_deploy_file() {
    local src="${rendered}/$1" dst="$2"
    echo "[opnsense] SCP: ${src} -> ${target}:${dst}"
    if [[ "${dry_run}" != "true" ]]; then
      scp "${ssh_opts[@]}" "${src}" "${ssh_user}@${target}:${dst}"
    fi
  }

  _opn_remote_exec() {
    echo "[opnsense] SSH: $*"
    if [[ "${dry_run}" != "true" ]]; then
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "$@"
    fi
  }

  # --------------------------------------------------------------------
  # Encrypted backup + revert (same code path as pfSense — crypt.inc is
  # shared across both code lines).
  # --------------------------------------------------------------------
  local _opn_backup_local="" _opn_backup_remote=""

  _opn_write_password_file() {
    if [[ -z "${SURU_BACKUP_PASSWORD:-}" ]]; then
      echo "[opnsense] ERROR: SURU_BACKUP_PASSWORD is unset — refusing to deploy without an" >&2
      echo "[opnsense]        encrypted backup. Set it in .env (preferably SOPS-encrypted)." >&2
      return 1
    fi
    local dir="/dev/shm"
    [[ -d "${dir}" && -w "${dir}" ]] || dir="${TMPDIR:-/tmp}"
    local path="${dir}/.suru-bkpass.$$"
    ( umask 077; printf '%s' "${SURU_BACKUP_PASSWORD}" > "${path}" )
    echo "${path}"
  }

  _opn_backup() {
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    local fname="opnsense-config.xml.suru-${ts}.bak"
    _opn_backup_remote="${_OPN_REMOTE_BACKUP_DIR}/${fname}"
    _opn_backup_local="${_OPN_LOCAL_BACKUP_DIR}/${fname}"
    local stage_applier="${_OPN_REMOTE_STAGING}/backup-encrypt.php"
    local pass_local pass_stage
    pass_stage="${_OPN_REMOTE_STAGING}/.suru-bkpass"

    echo "[opnsense] === Backup: encrypting /conf/config.xml ==="

    if ! pass_local="$(_opn_write_password_file)"; then
      return 1
    fi

    if [[ "${dry_run}" == "true" ]]; then
      echo "[opnsense] (dry-run) Would encrypt /conf/config.xml -> ${_opn_backup_remote}"
      echo "[opnsense] (dry-run) Would SCP-pull -> ${_opn_backup_local}"
      rm -f -- "${pass_local}"
      return 0
    fi

    _opn_remote_exec "mkdir -p '${_OPN_REMOTE_STAGING}'"
    scp "${ssh_opts[@]}" "${_OPN_APPLIER_BACKUP}" "${ssh_user}@${target}:${stage_applier}" \
      || { rm -f -- "${pass_local}"; return 1; }
    scp "${ssh_opts[@]}" "${pass_local}" "${ssh_user}@${target}:${pass_stage}" \
      || { rm -f -- "${pass_local}"; return 1; }
    rm -f -- "${pass_local}"

    # OPNsense default user is root, so no sudo needed; pfSense's admin user
    # gets sudo via the same passwordless sudoers rules SURU already
    # documents. Detect and prefix accordingly.
    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "

    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "\
        chmod 600 '${pass_stage}' && \
        ${_SUDO}mkdir -p '${_OPN_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}chmod 700 '${_OPN_REMOTE_BACKUP_DIR}' && \
        ${_SUDO}php '${stage_applier}' '${pass_stage}' '${_opn_backup_remote}'"; then
      echo "[opnsense] ERROR: on-router backup encrypt failed." >&2
      echo "[opnsense]        Note: requires /etc/inc/crypt.inc on router. OPNsense versions" >&2
      echo "[opnsense]        that have removed this file from upstream pfSense fork will" >&2
      echo "[opnsense]        fail; a follow-up can add an os-backup API path. [STUB]" >&2
      return 1
    fi

    mkdir -p "${_OPN_LOCAL_BACKUP_DIR}"
    if ! scp "${ssh_opts[@]}" "${ssh_user}@${target}:${_opn_backup_remote}" "${_opn_backup_local}"; then
      echo "[opnsense] WARN: SCP pull failed; on-router copy at ${_opn_backup_remote} is still valid." >&2
    else
      chmod 600 "${_opn_backup_local}" 2>/dev/null || true
      echo "[opnsense] Backup pulled: ${_opn_backup_local}"
    fi

    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true

    echo "[opnsense] === Backup complete ==="
    return 0
  }

  _opn_revert() {
    if [[ -z "${_opn_backup_remote}" ]]; then
      echo "[opnsense] WARN: revert called but no backup file is tracked — pre-backup failure?" >&2
      return 1
    fi

    echo "[opnsense] === Revert: restoring ${_opn_backup_remote} ==="

    local pass_local pass_stage
    pass_stage="${_OPN_REMOTE_STAGING}/.suru-bkpass-revert"
    if ! pass_local="$(_opn_write_password_file)"; then
      echo "[opnsense] ERROR: cannot revert — SURU_BACKUP_PASSWORD unset." >&2
      return 1
    fi

    local stage_applier="${_OPN_REMOTE_STAGING}/backup-restore.php"
    scp "${ssh_opts[@]}" "${_OPN_APPLIER_RESTORE}" "${ssh_user}@${target}:${stage_applier}" \
      || { rm -f -- "${pass_local}"; return 1; }
    scp "${ssh_opts[@]}" "${pass_local}" "${ssh_user}@${target}:${pass_stage}" \
      || { rm -f -- "${pass_local}"; return 1; }
    rm -f -- "${pass_local}"

    local _SUDO=""
    [[ "${ssh_user}" != "root" ]] && _SUDO="sudo "

    # If the on-router copy was wiped, push local mirror back first.
    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "test -r '${_opn_backup_remote}'" 2>/dev/null; then
      if [[ -r "${_opn_backup_local}" ]]; then
        echo "[opnsense] On-router backup absent; pushing local copy back: ${_opn_backup_local}"
        scp "${ssh_opts[@]}" "${_opn_backup_local}" "${ssh_user}@${target}:${_opn_backup_remote}" \
          || { echo "[opnsense] ERROR: cannot push local backup to router" >&2; return 1; }
      else
        echo "[opnsense] ERROR: neither remote nor local backup is readable — cannot revert." >&2
        return 1
      fi
    fi

    # shellcheck disable=SC2029
    if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "\
        chmod 600 '${pass_stage}' && \
        ${_SUDO}php '${stage_applier}' '${pass_stage}' '${_opn_backup_remote}'"; then
      echo "[opnsense] CRITICAL: revert failed — config.xml may be inconsistent." >&2
      echo "[opnsense] Manual recovery: GUI > System > Configuration > Backups > Restore" >&2
      echo "[opnsense]                   (encrypted), using ${_opn_backup_local} and SURU_BACKUP_PASSWORD." >&2
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
      return 1
    fi

    # Re-apply service configuration from the restored XML.
    _opn_remote_exec "configctl syslog restart" || true
    _opn_remote_exec "configctl ids restart"    || true

    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "rm -f '${pass_stage}'" 2>/dev/null || true
    echo "[opnsense] === Revert complete ==="
  }

  # Run the backup BEFORE any deploy step touches config.xml.
  if [[ "${SURU_SKIP_BACKUP:-false}" == "true" ]]; then
    echo "[opnsense] WARN: SURU_SKIP_BACKUP=true — deploying without an encrypted snapshot."
    echo "[opnsense]       Auto-revert will be unavailable if any step fails."
  else
    if ! _opn_backup; then
      echo "[opnsense] ERROR: pre-deploy backup failed — aborting before any config change." >&2
      return 1
    fi
    trap '_opn_revert' ERR
  fi

  # --- Local-DNS hygiene: unbound special-use zones + system-domain audit ------
  # OPNsense counterpart of the pfSense unbound-localzones stage. Leg A (special-use always_nxdomain zones) is automated via the
  # unbound.opnsense.d drop-in dir; leg B (system-domain static) is
  # evidence-driven — the applier reads the LIVE zone list and exits 6 with
  # the exact GUI step when static is desired, safe, and absent (the OPNsense
  # Unbound model path is unverified on a live box; no blind config write).
  # Limitation: leg B reports instead of converging system_domain_local_zone_type;
  # a converging write needs the model path captured from a live OPNsense box.
  # rc 6/7 are ADVISORY (GUI action pending / read-back unavailable): warn and
  # continue. rc 4 vs 5 distinguishes a completed rollback from a failed one, so
  # the recovery guidance does not depend on parsing the applier's log text. rc 3
  # is the one hard failure that deliberately does NOT revert: the run wrote
  # nothing, so a config.xml revert would undo other stages over drift this
  # deploy did not cause. A hard failure reverts EXPLICITLY: bash does not fire an ERR trap
  # for the `return` builtin (verified — a bare failing command does, `return 1`
  # does not), so relying on the trap here would silently skip the revert every
  # other failure point in this window gets. Gates:
  # SURU_UNBOUND_LOCALZONES / SURU_UNBOUND_SYSTEM_DOMAIN_STATIC (same as pfSense).
  # The drop-in is outside config.xml, so _opn_revert() cannot restore it: the
  # applier rolls its own write back (pre-run content, or removal) and restarts
  # unbound on every post-write failure before returning non-zero. A drop-in
  # that survives to a later stage's revert is one unbound already accepted and
  # the zone read-back verified — benign, and re-converged by the next deploy —
  # so revert deliberately leaves it alone rather than restarting the resolver
  # a second time.
  # Explicit revert for this stage's hard failures (see the note above on
  # `return` and the ERR trap). Disarms the trap first so a failing command
  # inside the revert cannot re-enter it, and skips entirely when no backup is
  # tracked (SURU_SKIP_BACKUP) rather than emitting a confusing revert warning.
  _opn_ulz_revert_and_fail() {
    [[ -n "${_opn_backup_remote}" ]] || return 0
    trap - ERR
    if ! _opn_revert; then
      echo "[opnsense] CRITICAL: revert after the unbound-localzones failure did not complete — see above." >&2
    fi
  }

  if [[ "${SURU_UNBOUND_LOCALZONES:-true}" == "true" ]]; then
    local _opn_ulz_local
    _opn_ulz_local="$(cd "${SCRIPT_DIR}/../../opnsense" && pwd)/unbound-localzones-apply.php"
    local _opn_ulz_remote="${_OPN_REMOTE_STAGING}/unbound-localzones-apply.php"
    local _ULZSUDO=""
    [[ "${ssh_user}" != "root" ]] && _ULZSUDO="sudo "
    local _ulz_args=""
    [[ "${SURU_UNBOUND_SYSTEM_DOMAIN_STATIC:-true}" != "true" ]] && _ulz_args=" --no-system-domain-static"
    echo "[opnsense] === Local-DNS hygiene: unbound local-zones ==="
    if [[ "${dry_run}" == "true" ]]; then
      echo "[opnsense] (dry-run) Would stage + run unbound-localzones-apply.php${_ulz_args}"
    else
      _opn_remote_exec "mkdir -p '${_OPN_REMOTE_STAGING}'"
      # Named cause: an unchecked scp failure would surface later as the applier
      # "failing" with rc 127, pointing at the wrong thing entirely.
      if ! scp "${ssh_opts[@]}" "${_opn_ulz_local}" "${ssh_user}@${target}:${_opn_ulz_remote}"; then
        echo "[opnsense] ERROR: could not stage unbound-localzones-apply.php to ${_opn_ulz_remote}." >&2
        _opn_ulz_revert_and_fail; return 1
      fi
      local _ulz_rc=0
      # The exit code IS the contract here, so it must not depend on the remote
      # login shell: SSH accounts on these platforms get a csh-family shell,
      # which has no `var=value` assignment at all (lib/ssh.sh header). A
      # `rc=$?; ...; exit $rc` relay would run the applier and then lose its
      # status. Run the applier as the only remote command so ssh returns its
      # status directly, wrapped `sh -c "…"` as a single argument per that same
      # rule, and clean the staged file up separately.
      # shellcheck disable=SC2029
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
        "sh -c \"${_ULZSUDO}php '${_opn_ulz_remote}'${_ulz_args}\"" \
        || _ulz_rc=$?
      # Best-effort: a drop between the two calls is the cost of not relaying the
      # rc through the remote shell. Say when it happens — silence would leave the
      # operator with an unexplained file on the router.
      # shellcheck disable=SC2029
      if ! ssh "${ssh_opts[@]}" "${ssh_user}@${target}" \
        "sh -c \"${_ULZSUDO}rm -f '${_opn_ulz_remote}'\"" >/dev/null 2>&1; then
        echo "[opnsense] WARN: could not remove the staged applier at ${_opn_ulz_remote} — harmless, and the next deploy overwrites it."
      fi
      case "${_ulz_rc}" in
        0) ;;
        6) echo "[opnsense] WARN: system-domain static needs the GUI step reported above — deploy continues." ;;
        7) echo "[opnsense] WARN: local-zones applied but UNVERIFIED (unbound-control unreachable) — verify manually." ;;
        2) echo "[opnsense] ERROR: unbound-localzones applier refused before writing (rc=2) — see the named reason above." >&2
           echo "[opnsense]        Nothing was written; any existing drop-in is intact — no cleanup here." >&2
           _opn_ulz_revert_and_fail; return 1 ;;
        3) echo "[opnsense] ERROR: unbound-localzones zones are not being served (rc=3), and this run wrote nothing." >&2
           echo "[opnsense]        Pre-existing drift: the drop-in is present but unbound is not serving it." >&2
           echo "[opnsense]        Check that /usr/local/etc/unbound.opnsense.d is included by the" >&2
           echo "[opnsense]        generated config, and that unbound restarted." >&2
           echo "[opnsense]        NOT reverting: nothing this deploy did caused it, and a config.xml revert" >&2
           echo "[opnsense]        would undo the other stages' work without fixing the resolver." >&2
           return 1 ;;
        4) echo "[opnsense] ERROR: unbound-localzones applier failed after writing (rc=4) — its write was" >&2
           echo "[opnsense]        rolled back and unbound restarted on the pre-run configuration. The" >&2
           echo "[opnsense]        rollback did not fail (that is rc 5); investigate why the apply did not take." >&2
           _opn_ulz_revert_and_fail; return 1 ;;
        5) echo "[opnsense] CRITICAL: unbound-localzones rollback FAILED (rc=5) — the resolver may be down." >&2
           echo "[opnsense]        Do NOT delete /usr/local/etc/unbound.opnsense.d/suru-localzones.conf;" >&2
           echo "[opnsense]        it may hold the restored content. Investigate unbound directly:" >&2
           echo "[opnsense]          configctl unbound restart" >&2
           _opn_ulz_revert_and_fail; return 1 ;;
        *) echo "[opnsense] ERROR: unbound-localzones applier failed (rc=${_ulz_rc})." >&2
           # rc 4 and 5 above carry the rollback outcome in the exit status.
           # Anything else here means the applier never reported one — it died
           # before it could act (SSH drop, PHP fatal, an rc it does not define).
           echo "[opnsense]        The applier reported no rollback outcome — it likely died before acting." >&2
           echo "[opnsense]        If its output shows neither 'Rollback complete' nor 'CRITICAL', recover with:" >&2
           echo "[opnsense]          rm -f /usr/local/etc/unbound.opnsense.d/suru-localzones.conf" >&2
           echo "[opnsense]          configctl unbound restart" >&2
           _opn_ulz_revert_and_fail; return 1 ;;
      esac
    fi
  else
    echo "[opnsense] Skipping unbound local-zones (SURU_UNBOUND_LOCALZONES=false)."
  fi

  # --- Dead-man's-switch for the (future) OPNsense inline flip -----------------
  # Wired symmetric to pfSense (scripts/lib/safety-timer.sh): when the OPNsense
  # Suricata inline deploy below is implemented and SURICATA_IPS_MODE=inline, this
  # arms a router-side auto-revert so a self-lockout (inline flip dropping the NIC
  # carrying ROUTER_HOST) heals itself. INERT TODAY: the OPNsense Suricata deploy
  # is a [STUB] (no inline flip happens), and the revert payload
  # (opnsense/suricata-safety-revert.sh) is unverified on a live OPNsense — so the
  # arm is gated off until both land. The library + scheduling (daemon(8)) are
  # FreeBSD-native and already work on OPNsense; only the revert payload needs
  # live validation. Opt out with SURU_SAFETY_TIMER=false.
  if [[ "${SURICATA_IPS_MODE:-legacy}" == "inline" \
        && "${SURU_SAFETY_TIMER:-true}" == "true" \
        && "${dry_run}" != "true" ]]; then
    echo "[opnsense] NOTE: SURICATA_IPS_MODE=inline requested, but the OPNsense Suricata"
    echo "[opnsense]       inline deploy + safety-revert payload are [STUB] pending live"
    echo "[opnsense]       OPNsense validation — NOT arming the dead-man's-switch. Once the"
    echo "[opnsense]       OPNsense inline deploy lands, wire safety_timer_arm here (mirror"
    echo "[opnsense]       of pfsense.sh) with _OPN_APPLIER_SURICATA_SAFETY_REVERT."
  fi

  # Suricata: previous SCP of /usr/local/etc/suricata/suricata.yaml is a
  # no-op. OPNsense's os-ids plugin regenerates that file from /conf/config.xml
  # (OPNsense/IDS) on every `configctl ids reload`. Direct SCP is overwritten
  # the next time the GUI saves Services > Intrusion Detection.
  # [STUB: alignment requires POSTing to /api/ids/settings/set + setRule per
  #        SID-or-ruleset, then /api/ids/service/reconfigure. Pending live
  #        OPNsense 24.x validation.]
  echo "[opnsense] WARN: Suricata deploy skipped — direct SCP to /usr/local/etc/suricata/suricata.yaml"
  echo "[opnsense]       is overwritten by os-ids on configctl reload. Use os-ids API (TODO)."
  _opn_deploy_file "${_OPN_RENDERED_ZEEK_LOCAL}"    "${_OPN_REMOTE_ZEEK_LOCAL}"

  # envsubst does not recognise the @@VAR@@ token style — use sed instead so
  # the deployed config has real values, not literal placeholders.
  # [STUB: OPNsense is model-driven — /usr/local/etc/syslog-ng.conf is
  #        regenerated from /conf/config.xml on `configctl syslog reload`.
  #        Writing into /usr/local/etc/syslog-ng.conf.d/suru.conf survives
  #        only as long as the bundled syslog-ng.conf @include's conf.d/*,
  #        which is plugin-dependent. The model-correct path is the
  #        os-syslog plugin API at /api/syslog/settings/* — pending live
  #        validation against an OPNsense 24.x with os-syslog installed.]
  local tmp_syslogng; tmp_syslogng="$(mktemp)"
  local _sng_sni="${FRONTDOOR_SYSLOG_SNI:-syslog.suru.local}"
  local _sng_port="${FRONTDOOR_PORT:-443}"
  local _sng_sensor="${ROUTER_SENSOR_NAME:-suru-tier1-opn}"
  local _sng_wan="${WAN_IFACE:-igb0}"
  local _sng_lan="${LAN_IFACE:-igb1}"
  sed \
    -e "s|@@FRONTDOOR_SYSLOG_SNI@@|${_sng_sni}|g" \
    -e "s|@@FRONTDOOR_PORT@@|${_sng_port}|g" \
    -e "s|@@SENSOR_NAME@@|${_sng_sensor}|g" \
    -e "s|@@WAN_IFACE@@|${_sng_wan}|g" \
    -e "s|@@LAN_IFACE@@|${_sng_lan}|g" \
    < "${_OPN_SYSLOGNG_TPL}" > "${tmp_syslogng}"
  [[ "${dry_run}" != "true" ]] && scp "${ssh_opts[@]}" "${tmp_syslogng}" "${ssh_user}@${target}:${_OPN_REMOTE_SYSLOGNG_CONF}"
  rm -f "${tmp_syslogng}"

  _opn_remote_exec "configctl syslog restart"

  # --- Hardware tuning (OPNsense) -----------------------------------------------
  # [STUB: OPNsense hardware-adaptive tuning is not yet implemented.
  #  pf table entries: OPNsense exposes system.maximumtableentries via
  #    POST /api/core/tunables/setItem or editing /conf/config.xml.
  #    hw-profile.conf SURU_HW_PF_TABLE_ENTRIES value would apply here.
  #  Zeek lb_procs: same node.cfg path as pfSense; zeek-iface-apply.php
  #    should be portable with a sudo-as-root call — pending live OPNsense test.
  #  Suricata detect profile: OPNsense IDS uses /api/ids/settings/set endpoint;
  #    key name for detect_eng_profile is unverified — pending live validation.
  #  Load hw-profile once confirmed OPNsense applier paths exist:
  #    local _hw_profile="${TIER1_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}/.hw-profile"
  #    [[ -f "${_hw_profile}" ]] && source "${_hw_profile}"
  # ]
  echo "[opnsense] HW tuning: STUB — OPNsense-specific applier paths not yet verified."

  _opn_remote_exec "configctl ids restart" || _opn_remote_exec "service suricata onerestart"
  _opn_remote_exec "zeekctl deploy"

  # Deploy mutations complete — disarm auto-revert so verify/validate
  # blocks below don't roll us back on informational failures.
  trap - ERR

  # --- Post-deploy XML drift verify -------------------------------------------
  # OPNsense regenerates every service config from /conf/config.xml on each
  # `configctl <svc> reload`. Direct SCP into /usr/local/etc/* will be
  # overwritten on the next GUI save. This warn-only check reads the live
  # XML view via SSH+PHP and reports whether SURU-managed nodes exist.
  # Flips to fail once the API-driven applier (PR A) is wired in.
  # [STUB: untested on live OPNsense — endpoints may differ by plugin
  #        version; treat output as best-effort signal, not gating.]
  if [[ "${dry_run}" != "true" ]] && [[ "${SURU_SKIP_XML_VERIFY:-false}" != "true" ]]; then
    local _xml_out _xml_warn=0 _xml_ok=0
    if ! _xml_out="$(
      ssh "${ssh_opts[@]}" "${ssh_user}@${target}" "/usr/local/bin/php -d display_errors=0" <<'EOPHP' 2>&1
<?php
$cfg = '/conf/config.xml';
if (!is_readable($cfg)) { echo "STATUS=fail reason=config_xml_unreadable" . PHP_EOL; exit(0); }
$x = @simplexml_load_file($cfg);
if ($x === false) { echo "STATUS=fail reason=config_xml_parse_failed" . PHP_EOL; exit(0); }

// os-syslog plugin: OPNsense/Syslog/destinations
$dest_count = 0; $has_suru = false;
$os_syslog = $x->OPNsense->Syslog->destinations ?? null;
if ($os_syslog !== null) {
  foreach ($os_syslog->destination ?? [] as $d) {
    $dest_count++;
    if (stripos((string)$d->description, 'suru') !== false) { $has_suru = true; }
  }
}
echo "CHECK syslog.destinations=" . ($dest_count > 0 ? "ok:$dest_count" : 'warn:none') . PHP_EOL;
echo "CHECK syslog.suru_dest=" . ($has_suru ? 'ok' : 'warn:no_suru_described_destination') . PHP_EOL;

// os-ids (Suricata) — interfaces present
$ids_ifaces = 0;
$ids = $x->OPNsense->IDS->interfaces ?? null;
if ($ids !== null) { foreach ($ids->interface ?? [] as $i) { $ids_ifaces++; } }
echo "CHECK ids.interfaces=" . ($ids_ifaces > 0 ? "ok:$ids_ifaces" : 'warn:none') . PHP_EOL;

// os-zeek plugin (may not be installed)
$zeek_node = $x->OPNsense->Zeek ?? null;
echo "CHECK zeek.plugin_node=" . ($zeek_node !== null ? 'ok' : 'warn:os-zeek_plugin_absent') . PHP_EOL;

echo "STATUS=done" . PHP_EOL;
EOPHP
    )"; then
      echo "[opnsense] WARN: XML verify probe failed to run. Skipping drift checks."
      echo "[opnsense]       ${_xml_out}"
    else
      while IFS= read -r line; do
        case "${line}" in
          CHECK*=ok*)   _xml_ok=$((_xml_ok + 1));   echo "[opnsense]   ✓ ${line#CHECK }" ;;
          CHECK*=warn*) _xml_warn=$((_xml_warn + 1)); echo "[opnsense]   ⚠ ${line#CHECK }" ;;
          STATUS=fail*) echo "[opnsense] WARN: probe failed: ${line}" ;;
          STATUS=done)  : ;;
          *)            [[ -n "${line}" ]] && echo "[opnsense]   ${line}" ;;
        esac
      done <<< "${_xml_out}"
      if [[ ${_xml_warn} -gt 0 ]]; then
        echo "[opnsense] WARN: ${_xml_warn} XML state assertion(s) failed."
        echo "[opnsense]       Direct SCP'd files in /usr/local/etc/* will be regenerated"
        echo "[opnsense]       from /conf/config.xml on the next configctl reload. Use the"
        echo "[opnsense]       API-driven applier (PR A) to write via /api/<plugin>/settings/set."
      else
        echo "[opnsense] XML state OK: ${_xml_ok} assertions passed."
      fi
    fi
  fi

  # --- Post-deploy validation via REST API ------------------------------------
  # Non-fatal: surfaces failures and pulls recent log entries for analysis.
  if [[ "${dry_run}" != "true" ]] \
     && [[ -n "${OPNSENSE_API_KEY:-}" ]] \
     && [[ "${SURU_SKIP_API_VALIDATE:-false}" != "true" ]]; then
    echo "[opnsense] Running post-deploy API validation..."
    if ! api_validate_deployment; then
      echo "[opnsense] WARN: post-deploy validation flagged at least one service."
      echo "[opnsense] Recent system log entries (for diagnostic analysis):"
      api_fetch_errors 100 || echo "[opnsense] (log fetch failed)"
    fi
  fi
}
