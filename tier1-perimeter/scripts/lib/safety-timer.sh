#!/usr/bin/env bash
# safety-timer.sh — deploy-time dead-man's-switch for self-lockout-risky changes
#
# Problem: some Tier 1 changes reconfigure the very interface the deploy SSHes
# over — most notably flipping Suricata to inline netmap on a NIC that carries
# the management IP (ROUTER_HOST). If that flip drops the host stack, the deploy
# loses its own SSH path and the existing ERR-trap revert (which ALSO runs over
# SSH) cannot recover it.
#
# Mechanism: before the risky step, arm a router-side delayed revert that runs
# autonomously via daemon(8) (FreeBSD base; pfSense + OPNsense). If the deploy
# reaches its disarm call, connectivity survived and the timer is cancelled. If
# the deploy never reaches disarm (SSH cut, or any aborting error), the timer
# fires after SURU_SAFETY_REVERT_SECONDS and reverts the risky change, restoring
# the management path. End-to-end: no residue on success, self-healing on failure.
#
# Scope: this library only SCHEDULES an arbitrary revert command. The caller
# supplies the platform-specific revert (a local script to stage + the remote
# command to run it). It is deliberately independent of the driver's own
# backup/ERR-trap revert — that stays the full-config rollback for the
# connectivity-intact case; this is the narrow "restore my SSH path" backstop.
#
# Caller contract — set these before calling (both drivers already have them):
#   SAFETY_TARGET      router host (ROUTER_HOST)
#   SAFETY_USER        ssh user
#   SAFETY_SUDO        "sudo " when the user is non-root, else ""
#   SAFETY_DRYRUN      "true" | "false"
#   SAFETY_SSH_OPTS    array of ssh/scp options (same as the driver builds)
#
# Functions:
#   safety_timer_arm SECONDS REVERT_SCRIPT_LOCAL REVERT_REMOTE_CMD
#   safety_timer_disarm
#
# Remote layout (persistent dir, NOT the deploy's /tmp/suru-staging which is
# cleaned on EXIT): /tmp/suru-safety/{<revert-script>, revert.sh, revert.pid,
# revert.log}. The sleeper runs as root (launched via ${SAFETY_SUDO}daemon) so
# the revert has the privileges sync/restart need.

_SAFETY_DIR="/tmp/suru-safety"
_SAFETY_PID="${_SAFETY_DIR}/revert.pid"
_SAFETY_RUNNER="${_SAFETY_DIR}/revert.sh"

# safety_timer_remote_path LOCAL_SCRIPT -> the path the staged revert script
# lands at on the router. Single source of truth for the remote layout so the
# caller's revert command never drifts from _SAFETY_DIR.
safety_timer_remote_path() {
  echo "${_SAFETY_DIR}/$(basename "$1")"
}

_safety_ssh() {
  # Run a POSIX-sh command on the router. Honours SAFETY_DRYRUN.
  # The command is piped to `sh -s` via STDIN rather than passed as an ssh
  # argument: the deploy user's login shell is csh on this pfSense, which cannot
  # parse the POSIX `if [ -f ... ]; then ... fi` conditional in the disarm path
  # (csh needs `if (...) then ... endif`) when it arrives as argv. `sh -s` reads
  # the script from stdin and executes it in POSIX sh regardless of login shell
  # (the same pattern the deploy's own recon uses). Plain `&&`-chained commands
  # would work as raw argv, but the conditional and future sh syntax would not.
  if [[ "${SAFETY_DRYRUN}" == "true" ]]; then
    echo "[safety-timer] (dry-run) SSH: $*"
    return 0
  fi
  printf '%s\n' "$*" | ssh "${SAFETY_SSH_OPTS[@]}" "${SAFETY_USER}@${SAFETY_TARGET}" sh -s
}

_safety_scp() {
  # $1 local, $2 remote path. Honours SAFETY_DRYRUN.
  if [[ "${SAFETY_DRYRUN}" == "true" ]]; then
    echo "[safety-timer] (dry-run) SCP: $1 -> ${SAFETY_TARGET}:$2"
    return 0
  fi
  scp "${SAFETY_SSH_OPTS[@]}" "$1" "${SAFETY_USER}@${SAFETY_TARGET}:$2"
}

# safety_timer_arm SECONDS REVERT_SCRIPT_LOCAL REVERT_REMOTE_CMD
safety_timer_arm() {
  local seconds="$1" revert_local="$2" revert_cmd="$3"
  local revert_base; revert_base="$(basename "${revert_local}")"

  if ! [[ "${seconds}" =~ ^[0-9]+$ ]] || (( seconds < 30 )); then
    echo "[safety-timer] ERROR: revert seconds must be an integer >= 30 (got '${seconds}')" >&2
    return 1
  fi

  echo "[safety-timer] Arming dead-man's-switch: revert in ${seconds}s if the deploy does not disarm."

  # Disarm any stale timer from a prior aborted deploy before re-arming.
  safety_timer_disarm_quiet

  # Owned by the deploy user so scp can write; the sleeper runs as root.
  _safety_ssh "mkdir -p ${_SAFETY_DIR} && chmod 755 ${_SAFETY_DIR}" || {
    echo "[safety-timer] ERROR: could not create ${_SAFETY_DIR} on router" >&2; return 1; }

  _safety_scp "${revert_local}" "${_SAFETY_DIR}/${revert_base}" || {
    echo "[safety-timer] ERROR: could not stage revert script ${revert_base}" >&2; return 1; }

  # Build the sleeper runner locally, then stage it. Base64 avoids quoting hell.
  local runner_tmp
  runner_tmp="$(mktemp "${TMPDIR:-/tmp}/suru-safety-runner.XXXXXX")"
  cat > "${runner_tmp}" <<RUNNER
#!/bin/sh
# SURU deploy dead-man's-switch runner — auto-generated, do not edit.
sleep ${seconds}
${revert_cmd} >> ${_SAFETY_DIR}/revert.log 2>&1
logger -t suru-safety "dead-man's-switch FIRED after ${seconds}s: reverted Suricata to legacy (deploy did not disarm within the window; management path presumed lost)"
rm -f ${_SAFETY_PID}
RUNNER

  _safety_scp "${runner_tmp}" "${_SAFETY_RUNNER}" || {
    rm -f "${runner_tmp}"; echo "[safety-timer] ERROR: could not stage runner" >&2; return 1; }
  rm -f "${runner_tmp}"

  # Launch the detached sleeper as root. daemon(8) forks, redirects std fds to
  # /dev/null, and writes the child pid to the pidfile. Killing that pid cancels
  # the pending revert.
  _safety_ssh "${SAFETY_SUDO}daemon -f -p ${_SAFETY_PID} /bin/sh ${_SAFETY_RUNNER}" || {
    echo "[safety-timer] ERROR: could not launch revert daemon" >&2; return 1; }

  echo "[safety-timer] Armed. Router will auto-revert Suricata to legacy in ${seconds}s unless disarmed."
  return 0
}

# safety_timer_disarm — cancel the pending revert and remove all state.
safety_timer_disarm() {
  echo "[safety-timer] Disarming dead-man's-switch (deploy succeeded / connectivity intact)."
  safety_timer_disarm_quiet
  echo "[safety-timer] Disarmed — no auto-revert will fire."
}

# safety_timer_disarm_quiet — kill the sleeper + remove state, no headline log.
# Safe to call when nothing is armed (idempotent no-op). Never fails the deploy.
safety_timer_disarm_quiet() {
  if [[ "${SAFETY_DRYRUN}" == "true" ]]; then
    echo "[safety-timer] (dry-run) would kill ${_SAFETY_PID} and rm -rf ${_SAFETY_DIR}"
    return 0
  fi
  # Kill the sleeper via `pkill -F` (runs as root so it can READ the root-owned
  # 0600 pidfile — a plain `kill $(cat ...)` as the deploy user gets EACCES on
  # the pidfile and silently fails to kill, leaving the sleeper to fire the
  # revert after a *successful* deploy). The `-f suru-safety/revert.sh` pattern
  # guards against a recycled PID. Then remove all state (sudo: the pidfile/log
  # are root-owned).
  if ! _safety_ssh "if [ -f ${_SAFETY_PID} ]; then ${SAFETY_SUDO}pkill -F ${_SAFETY_PID} -f suru-safety/revert.sh 2>/dev/null || true; fi; ${SAFETY_SUDO}rm -rf ${_SAFETY_DIR} 2>/dev/null || true"; then
    # The disarm SSH call itself failed to reach the router. The switch is NOT
    # cancelled and will still fire — surface it so a later autonomous revert is
    # diagnosable, but never fail the deploy (contract).
    echo "[safety-timer] WARN: disarm SSH call failed to reach the router — the timer may still be armed and could auto-revert." >&2
  fi
  return 0
}
