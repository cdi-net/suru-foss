#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — lib/secrets.sh
# Shared secret-hygiene primitives for deploy-time credential injection.
# Sourced into platform drivers (e.g. platforms/pfsense.sh).
#
# WHY THIS EXISTS
# ===============
# A secret reaches the router by one of two paths: `@@TOKEN@@` sed-substitution
# into a rendered file, or a 0600 secrets file passed to an applier. Both must
# validate the value against the same charset and use the same tmpfs-preferred
# 0600 temp file. This lib is the single implementation both call sites use so
# they cannot drift.
#
# Pure functions only — NO ssh / remote I/O. Remote staging + shred stays in
# the driver's nested closures (they capture ssh_opts/target/dry_run). This
# file is sourced, so it does NOT set strict mode; every function returns an
# explicit status and is safe under the caller's `set -euo pipefail`.
# =============================================================================

# Injection-safe charset for a secret spliced into a `sed` replacement, a URL
# query parameter, or a `KEY=VALUE` secrets-file line. Excludes every sed
# metacharacter (`&`, `|`, `\`), shell metacharacters, whitespace, and
# newlines — so a validated value cannot break out of any of those contexts.
SURU_SECRET_CHARSET_DEFAULT='^[A-Za-z0-9._-]+$'

# secret_charset_ok VALUE [REGEX]
#   Returns 0 iff VALUE is non-empty AND fully matches REGEX (default
#   SURU_SECRET_CHARSET_DEFAULT). An empty VALUE returns 1, so callers should
#   first decide "is this secret set?" with a `[[ -n ... ]]` test and use this
#   only to validate a set value — the canonical caller shape is:
#       if [[ -n "${KEY}" ]] && ! secret_charset_ok "${KEY}"; then
#           log "invalid — treating as unset"; KEY=""
#       fi
#   This is the mandatory injection guard that MUST run before a secret is
#   spliced into a sed replacement, a URL, or a secrets file.
secret_charset_ok() {
  local value="${1-}" regex="${2:-${SURU_SECRET_CHARSET_DEFAULT}}"
  # Pin the C locale for the match: under some glibc locales an `[A-Za-z]`
  # range can collate in accented/non-ASCII characters, which would widen the
  # guard on the Linux deploy host. `local LC_ALL=C` scopes the override to
  # this function call so `[A-Za-z0-9._-]` is exactly ASCII everywhere.
  local LC_ALL=C
  [[ -n "${value}" ]] || return 1
  # Unquoted RHS so the value is matched as a regex (bash requirement for a
  # variable pattern); the pattern is a project constant, never user input.
  [[ "${value}" =~ ${regex} ]] || return 1
  return 0
}

# secret_mktemp
#   Echo the path of a fresh mode-0600 temp file, preferring /dev/shm (tmpfs,
#   not paged to disk) and falling back to $TMPDIR/tmp.
#   `mktemp` already creates 0600 regardless of umask; an explicit
#   `chmod 600` is applied belt-and-braces. The CALLER owns the file and MUST
#   shred it (`rm -f`) after use. Returns non-zero (and echoes nothing) if the
#   temp file could not be created.
secret_mktemp() {
  local dir="/dev/shm"
  [[ -d "${dir}" && -w "${dir}" ]] || dir="${TMPDIR:-/tmp}"
  dir="${dir%/}"   # strip any trailing slash so the template has no "//"
  local path
  path="$(mktemp "${dir}/.suru-secret.XXXXXX")" || return 1
  # BSD chmod (macOS dev workstation) rejects the GNU `--`; the path is a
  # mktemp-generated constant, never user input, so it is safe without it.
  chmod 600 "${path}" 2>/dev/null || true
  printf '%s' "${path}"
}
