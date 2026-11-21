#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — lib/ssh.sh
# Shared SSH / SCP wrappers.
# Requires globals: ROUTER_HOST, ROUTER_SSH_USER, ROUTER_SSH_KEY,
#                   SSH_STRICT_HOST_KEY_CHECKING
#
# FreeBSD / pfSense shell compatibility — IMPORTANT for future maintainers
# =========================================================================
# pfSense sets /bin/tcsh as the login shell for unprivileged SSH users.
#
# PROBLEM 1 — metacharacter handling:
#   tcsh does NOT evaluate POSIX redirects (2>/dev/null) or logic operators
#   (||, &&) when SSH passes a command string as a single argument via exec().
#   Result: 'cat /etc/version 2>/dev/null' → cat: 2: No such file or directory
#
# PROBLEM 2 — stdin stall with multi-token sh -c:
#   ssh ... host sh -c "cmd"  → SSH sends three argv tokens to the remote side.
#   FreeBSD /bin/sh -c "cmd" runs the command but inherits the SSH stdin
#   channel, which stays open (no EOF) → process completes but SSH hangs.
#
# SOLUTION — single-string quoting:
#   ssh ... host 'sh -c "cmd"'
#   Pass the ENTIRE invocation as ONE string to SSH. SSH hands it to the
#   remote login shell as a command string. The login shell execs /bin/sh -c
#   and SSH's non-interactive channel delivers EOF on stdin automatically.
#   All POSIX redirects, pipes, and logic operators work correctly.
#
# RULE: ssh_exec() always wraps CMD as the single string: sh -c "CMD"
#       ssh_exec_raw() passes argv tokens directly — use for pfSsh.php only.
# =============================================================================

# Build SSH options array — avoids fragile $(echo ...) word-split subshell.
_ssh_opts_array() {
  SSH_OPTS=(
    -i "${ROUTER_SSH_KEY}"
    -o "BatchMode=yes"
    -o "ConnectTimeout=15"
    -o "StrictHostKeyChecking=${SSH_STRICT_HOST_KEY_CHECKING:-yes}"
  )
  if [[ ${#SSH_MUX_OPTS[@]} -gt 0 ]]; then
    SSH_OPTS+=("${SSH_MUX_OPTS[@]}")
  fi
}

# =============================================================================
# Connection reuse
# =============================================================================
# A deploy runs every remote step as its own ssh/scp process. Without reuse each
# one is a new TCP connection and a new key login, and a single deploy crosses
# the perimeter's own SSH brute-force threshold (suru-ssh-bruteforce.zeek counts
# completed connections per source/target pair). ssh_mux_enable turns on OpenSSH
# connection multiplexing for the calling process: the first ssh becomes the
# master, every later ssh/scp carrying SSH_MUX_OPTS runs as a channel inside it.
#
#   ControlMaster=auto    attach to a live master, else become one; a stale or
#                         dead socket falls back to a plain connection
#   ControlPath=<dir>/%C  per-run 0700 directory under /tmp (a Unix socket path
#                         is capped near 104 bytes; %C is 40 hex characters)
#   ControlPersist        the master outlives the step that started it; it is
#                         closed by ssh_mux_close, the timeout is the backstop
#                         (default 120 s: it also bounds how long a master
#                         left by a killed deploy stays usable by the same
#                         user; a step starting later than that reconnects)
#   ServerAlive*          a master whose link died must exit, or every channel
#                         attached to it hangs. The probes go through the
#                         encrypted channel and ask sshd itself for a reply
#                         (ssh_config(5)), so a remote command that prints
#                         nothing does not spend the budget; the probes
#                         keep an idle-timeout middlebox from dropping the
#                         shared connection, and 10 unanswered probes 30 s
#                         apart (about 5 minutes) end it. Same budget as
#                         pfsense.sh _pf_remote_exec_long, inside the safety
#                         timer's default revert window
#                         (SURU_SAFETY_REVERT_SECONDS, 600 s)
#
# ssh keeps the FIRST value it sees for an option, so a caller that needs a
# fresh connection (proving a new login still works, as the safety timer's
# disarm does) prepends `-o ControlMaster=no -o ControlPath=none`.
#
# SURU_SSH_MUX=false disables reuse (one connection per step, as before).

# Initialised once: a second source of this file must not drop a live master.
if [[ -z "${_SSH_MUX_DIR+set}" ]]; then
  SSH_MUX_OPTS=()
  _SSH_MUX_DIR=""
fi

# ssh_mux_enable — idempotent. Never fails the caller: without a socket
# directory the deploy runs one connection per step.
ssh_mux_enable() {
  [[ "${SURU_SSH_MUX:-true}" == "false" ]] && return 0
  [[ -n "${_SSH_MUX_DIR}" && -d "${_SSH_MUX_DIR}" ]] && return 0
  local dir
  if ! dir="$(mktemp -d /tmp/suru-ssh.XXXXXX)"; then
    echo "[ssh] WARN: could not create an SSH control directory; one connection per step." >&2
    return 0
  fi
  chmod 700 "${dir}"
  _SSH_MUX_DIR="${dir}"
  SSH_MUX_OPTS=(
    -o "ControlMaster=auto"
    -o "ControlPath=${dir}/%C"
    -o "ControlPersist=${SURU_SSH_CONTROL_PERSIST:-120}"
    -o "ServerAliveInterval=30"
    -o "ServerAliveCountMax=10"
  )
}

# ssh_mux_close — stop every master in the directory and remove it. Safe when
# reuse is off or nothing connected. The state is not exported: a child script
# that sources this library starts with reuse off and never closes the parent's.
ssh_mux_close() {
  [[ -n "${_SSH_MUX_DIR}" ]] || return 0
  local sock
  for sock in "${_SSH_MUX_DIR}"/*; do
    [[ -S "${sock}" ]] || continue
    ssh -o "ControlPath=${sock}" -O exit suru-mux > /dev/null 2>&1 || true
  done
  rm -rf "${_SSH_MUX_DIR}"
  _SSH_MUX_DIR=""
  SSH_MUX_OPTS=()
}

# ssh_exec COMMAND
# Runs COMMAND on the router over SSH.
# Wraps COMMAND as: sh -c "COMMAND" passed as a SINGLE string to SSH.
# This is the correct pattern for FreeBSD/pfSense (tcsh login shell):
#   - Avoids stdin stall from multi-token sh -c
#   - Guarantees POSIX sh semantics for redirects and logic operators
# Single-quotes inside COMMAND must be escaped as '\'' if needed.
ssh_exec() {
  local cmd="$1"
  log_debug "SSH [${ROUTER_SSH_USER}@${ROUTER_HOST}]: ${cmd}"
  if ${DRY_RUN:-false}; then
    _log DRY-RUN "ssh ${ROUTER_SSH_USER}@${ROUTER_HOST} 'sh -c \"${cmd}\"'"
    return 0
  fi
  _ssh_opts_array
  # Pass entire invocation as ONE string — prevents stdin stall on FreeBSD sh
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" \
    "${ROUTER_SSH_USER}@${ROUTER_HOST}" \
    "sh -c \"${cmd}\""
}

# ssh_exec_raw COMMAND [ARGS...]
# Runs COMMAND on the router with discrete argv tokens — NO sh -c wrapping.
# Use ONLY for pfSsh.php invocations where the command is an exec() call
# with its own argument list (pfSsh.php playback svc restart syslog-ng).
# Do NOT use for commands containing shell metacharacters.
ssh_exec_raw() {
  log_debug "SSH raw [${ROUTER_SSH_USER}@${ROUTER_HOST}]: $*"
  if ${DRY_RUN:-false}; then
    _log DRY-RUN "ssh ${ROUTER_SSH_USER}@${ROUTER_HOST} $*"
    return 0
  fi
  _ssh_opts_array
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" \
    "${ROUTER_SSH_USER}@${ROUTER_HOST}" \
    "$@"
}

# ssh_exec_heredoc SCRIPT [INTERPRETER]
# Sends a multi-line script to the router via stdin over SSH. INTERPRETER is
# the remote command that reads the script, passed as ONE argv token (default
# "bash -s"). Pass 'sudo sh' for a POSIX sh under sudo (root-only reads): the
# string is what the tcsh login shell execs, the same rule as above.
# Used to drive pfSsh.php interactive stdin commands and root-only collection.
ssh_exec_heredoc() {
  local script="$1" interp="${2:-bash -s}"
  log_debug "SSH heredoc [${ROUTER_SSH_USER}@${ROUTER_HOST}] via '${interp}' ($(printf '%s' "$script" | wc -l) lines)"
  if ${DRY_RUN:-false}; then
    _log DRY-RUN "ssh heredoc (${interp}) to ${ROUTER_SSH_USER}@${ROUTER_HOST}:"
    printf '%s\n' "$script" | sed 's/^/    /'
    return 0
  fi
  _ssh_opts_array
  # shellcheck disable=SC2029
  printf '%s\n' "$script" | ssh "${SSH_OPTS[@]}" \
    "${ROUTER_SSH_USER}@${ROUTER_HOST}" \
    "${interp}"
}

# scp_push LOCAL REMOTE
# Copies LOCAL file to REMOTE path on the router.
scp_push() {
  local src="$1"
  local dst="$2"
  log_debug "SCP push ${src} → ${ROUTER_SSH_USER}@${ROUTER_HOST}:${dst}"
  if ${DRY_RUN:-false}; then
    _log DRY-RUN "scp ${src} ${ROUTER_SSH_USER}@${ROUTER_HOST}:${dst}"
    return 0
  fi
  _ssh_opts_array
  scp "${SSH_OPTS[@]}" \
    "${src}" \
    "${ROUTER_SSH_USER}@${ROUTER_HOST}:${dst}"
}

# scp_pull REMOTE LOCAL
# Copies REMOTE file from the router to LOCAL path.
scp_pull() {
  local src="$1"
  local dst="$2"
  log_debug "SCP pull ${ROUTER_SSH_USER}@${ROUTER_HOST}:${src} → ${dst}"
  if ${DRY_RUN:-false}; then
    _log DRY-RUN "scp ${ROUTER_SSH_USER}@${ROUTER_HOST}:${src} ${dst}"
    return 0
  fi
  _ssh_opts_array
  scp "${SSH_OPTS[@]}" \
    "${ROUTER_SSH_USER}@${ROUTER_HOST}:${src}" \
    "${dst}"
}
