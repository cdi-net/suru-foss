#!/usr/bin/env bash
# =============================================================================
# SURU Platform — Tier 1 syslog-ng telemetry
# =============================================================================
# Connects to the Tier 1 router (pfSense) via SSH and reports:
#   --status   Service state and SIEM connectivity
#   --buffer   Disk-buffer inventory: every /var/db/syslog-ng-*.rqf|.qf file with
#              message count, size, last-write age, held-open state and an
#              ORPHAN? flag, plus the capacity ceiling and its source
#   --lag      Per-source read lag + delivery lag to SIEM (count, bytes, time)
#
# All three sections are shown when no section flag is given.
#
# This tool needs a root shell on the router over the deploy identity
# ('sudo sh'). A restricted deploy account does not allow that, so the tool
# cannot run under one.
#
# Usage:
#   bash scripts/syslog-ng-metrics.sh [OPTIONS]
#
# Options:
#   --status         Service state + SIEM connection counters
#   --buffer         Per-file disk-buffer enumeration, orphan flag, ceiling %
#   --lag            Source read lag + delivery queue analysis
#   --all            All sections (default when no section flag is given)
#   --orphan-age-hours N
#                    A non-live buffer file that syslog-ng does not hold open,
#                    with messages and a last write older than N hours, is
#                    flagged ORPHAN? (default: 24; held open: unknown flags)
#   --json           Emit a single JSON object instead of human-readable text
#   --env FILE       Path to .env file  (default: <tier1>/.env)
#   --verbose        Show raw SSH output and parsed fields
#   -h | --help      Show this help
#
# Environment variables (loaded from .env):
#   ROUTER_HOST, ROUTER_SSH_KEY, ROUTER_SSH_USER,
#   SSH_STRICT_HOST_KEY_CHECKING
#
# SSH goes through scripts/lib/ssh.sh (ssh_exec_heredoc ... 'sudo sh'), so the
# lib's contract applies: SSH_STRICT_HOST_KEY_CHECKING takes yes|accept-new|no
# (default yes, see .env.example) and ConnectTimeout is 15 s. --verbose also
# prints the SSH target via the script's own debug line.
#
# Buffer semantics:
#   - The LIVE file is the one with the newest mtime (ties: all live). JSON
#     buffer.messages_queued / queue_file* describe the live file only.
#   - ORPHAN? = not live AND not held open by syslog-ng (held open: unknown still
#     flags) AND last write older than the threshold AND messages > 0
#     (likely stranded: syslog-ng may not replay files it does not hold open).
#     Ages use the router clock.
#   - The ceiling is read from the router's live syslog-ng.conf capacity-bytes(),
#     falling back to SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES in hw-profile.conf;
#     JSON buffer.queue_ceiling_bytes is null (source "unknown") when neither
#     can be read. Read failures are reported (collection_errors), not hidden.
#   - No repo consumer parses the JSON output (only the Makefile sng-* targets
#     call the script).
#
# MITRE ATT&CK: TA0009 Collection / T1005 — operator visibility into log pipeline
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/log.sh
source "${SCRIPT_DIR}/lib/log.sh"
# shellcheck source=lib/ssh.sh
source "${SCRIPT_DIR}/lib/ssh.sh"
TIER1_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${TIER1_DIR}/.env"

# ── Runtime flags ─────────────────────────────────────────────────────────────
SHOW_STATUS=false
SHOW_BUFFER=false
SHOW_LAG=false
OUTPUT_JSON=false
VERBOSE=false
SECTIONS_GIVEN=false
ORPHAN_AGE_HOURS=24
ORPHAN_AGE_SECONDS=86400

# ── Colour codes ──────────────────────────────────────────────────────────────
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_CYAN='\033[0;36m'
C_DIM='\033[2m'

ok()   { printf "${C_GREEN}✓${C_RESET}"; }
warn() { printf "${C_YELLOW}⚠${C_RESET}"; }
err()  { printf "${C_RED}✗${C_RESET}"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
die()     { printf "${C_RED}[ERR]${C_RESET} %s\n" "$*" >&2; exit 1; }
verbose() { $VERBOSE && printf "${C_DIM}[dbg] %s${C_RESET}\n" "$*" >&2 || true; }

# human_bytes BYTES — print bytes as human-readable
human_bytes() {
  local b="$1"
  if (( b >= 1073741824 )); then
    awk "BEGIN { printf \"%.1f GB\", $b/1073741824 }"
  elif (( b >= 1048576 )); then
    awk "BEGIN { printf \"%.1f MB\", $b/1048576 }"
  elif (( b >= 1024 )); then
    awk "BEGIN { printf \"%.1f KB\", $b/1024 }"
  else
    printf '%d B' "$b"
  fi
}

# human_duration SECONDS — print seconds as h/m/s
human_duration() {
  local s="$1"
  if (( s < 0 ));  then printf '0s'; return; fi
  if (( s < 60 )); then printf '%ds' "$s"; return; fi
  if (( s < 3600 )); then
    printf '%dm %ds' "$(( s/60 ))" "$(( s%60 ))"
  elif (( s < 86400 )); then
    printf '%dh %dm' "$(( s/3600 ))" "$(( (s%3600)/60 ))"
  else
    printf '%dd %dh' "$(( s/86400 ))" "$(( (s%86400)/3600 ))"
  fi
}

# comma_num N — add thousands separators (BSD/POSIX awk, no GNU sed \B)
comma_num() {
  printf '%d\n' "$1" | awk '{
    s = $0; r = ""
    while (length(s) > 3) {
      r = "," substr(s, length(s)-2) r
      s = substr(s, 1, length(s)-3)
    }
    print s r
  }'
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
Usage: bash scripts/syslog-ng-metrics.sh [OPTIONS]

Sections (default: all):
  --status         Service state and SIEM connection counters
  --buffer         Per-file disk-buffer enumeration, orphan flag, ceiling usage
  --lag            Per-source read lag + delivery queue analysis

Buffer options:
  --orphan-age-hours N   Flag non-live buffer files not held open by syslog-ng,
                         with messages and no write for N hours, as ORPHAN?
                         (positive integer, default 24; held open: unknown flags)

Output:
  --json           Emit JSON instead of human-readable text
  --verbose        Show raw SSH responses and parsed fields

Environment:
  --env FILE       Path to .env (default: <tier1-perimeter>/.env)

  -h | --help      Show this help
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --status)  SHOW_STATUS=true;  SECTIONS_GIVEN=true ;;
      --buffer)  SHOW_BUFFER=true;  SECTIONS_GIVEN=true ;;
      --lag)     SHOW_LAG=true;     SECTIONS_GIVEN=true ;;
      --all)     SHOW_STATUS=true; SHOW_BUFFER=true; SHOW_LAG=true; SECTIONS_GIVEN=true ;;
      --orphan-age-hours)
        [[ $# -gt 1 ]] || die "--orphan-age-hours requires a value"
        [[ "$2" =~ ^[1-9][0-9]*$ ]] || die "--orphan-age-hours must be a positive integer (got: $2)"
        ORPHAN_AGE_HOURS="$2"; shift ;;
      --json)    OUTPUT_JSON=true ;;
      --verbose) VERBOSE=true ;;
      --env)     [[ $# -gt 1 ]] || die "--env requires a path"; ENV_FILE="$2"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1  (try --help)" ;;
    esac
    shift
  done
  ORPHAN_AGE_SECONDS=$(( ORPHAN_AGE_HOURS * 3600 ))
  # Default: show everything
  if ! $SECTIONS_GIVEN; then
    SHOW_STATUS=true; SHOW_BUFFER=true; SHOW_LAG=true
  fi
}

# ── Load env ──────────────────────────────────────────────────────────────────
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
    verbose "loaded env from $ENV_FILE"
  else
    verbose ".env not found at $ENV_FILE — using shell environment"
  fi
  [[ -n "${ROUTER_HOST:-}" ]] || die "ROUTER_HOST not set — populate .env or export it"
  # Globals read by lib/ssh.sh
  ROUTER_SSH_USER="${ROUTER_SSH_USER:-admin}"
  ROUTER_SSH_KEY="${ROUTER_SSH_KEY:-${HOME}/.ssh/suru_deploy}"
}

# ── SSH wrapper ───────────────────────────────────────────────────────────────
# Runs a local heredoc script on the router via `sudo sh` reading from stdin,
# through lib/ssh.sh (ssh_exec_heredoc). pfSense uses tcsh as login shell;
# piping to 'sudo sh' gives us POSIX sh.
ssh_collect() {
  local REMOTE=""
  verbose "SSH target ${ROUTER_SSH_USER}@${ROUTER_HOST} (key=${ROUTER_SSH_KEY})"

  # The collection script travels on stdin so quoting never hits tcsh.
  # Each section delimited by ===SECTION=== for local parsing.
  IFS= read -r -d '' REMOTE <<'REMOTE_SCRIPT' || true
export PATH="$PATH:/usr/local/bin:/usr/local/sbin"

printf '===STATS===\n'
s=$(syslog-ng-ctl stats 2>&1); s_rc=$?
if [ "$s_rc" -eq 0 ]; then
  printf '%s\n' "$s"
else
  printf 'ERR_STATS|%s\n' "$(printf '%s\n' "$s" | head -1 | tr '|' '/')"
fi

printf '===DQFILES===\n'
for f in /var/db/syslog-ng-*.rqf /var/db/syslog-ng-*.qf; do
  [ -e "$f" ] || continue
  st=$(stat -f '%m %z' "$f" 2>&1); st_rc=$?
  dq=$(dqtool info "$f" 2>&1); dq_rc=$?
  err='-'
  if [ "$st_rc" -eq 0 ]; then
    mt=${st%% *}; sz=${st##* }
  else
    mt='-'; sz='-'
    err=$(printf '%s\n' "$st" | head -1 | tr '|' '/')
    [ -n "$err" ] || err="stat exited rc=${st_rc} with no output"
  fi
  n=$(printf '%s\n' "$dq" | sed -n "s/.*number_of_messages='\([0-9][0-9]*\)'.*/\1/p" | head -1)
  if [ "$dq_rc" -ne 0 ] || [ -z "$n" ]; then
    if [ "$err" = '-' ]; then
      if [ "$dq_rc" -ne 0 ]; then
        err=$(printf '%s\n' "$dq" | head -1 | tr '|' '/')
        [ -n "$err" ] || err="dqtool info exited rc=${dq_rc} with no output"
      else
        err='dqtool output has no number_of_messages'
      fi
    fi
    n='-'
  fi
  [ -n "$err" ] || err='-'
  printf 'FILE|%s|%s|%s|%s|%s|%s|%s\n' "$f" "$mt" "$sz" "$st_rc" "$dq_rc" "$n" "$err"
done

printf '===OPENFILES===\n'
pids=$(ps -axo pid= -o comm= | awk '$2=="syslog-ng"{print $1}' | tr '\n' ' ')
if [ -z "$pids" ]; then
  printf 'RC|127|-\n'
else
  # shellcheck disable=SC2086 # intentional word-split of the pid list
  out=$(procstat -f $pids 2>&1); rc=$?
  printf 'RC|%s|%s\n' "$rc" "$pids"
  printf '%s\n' "$out" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\/var\/db\/syslog-ng-[^ ]*\.r?qf$/) print "OPEN|" $i}'
fi

printf '===CAPACITY===\n'
c=$(grep -m1 -o 'capacity-bytes([0-9]*)' /usr/local/etc/syslog-ng.conf 2>&1); c_rc=$?
printf 'CONF|%s|%s\n' "$c_rc" "$(printf '%s\n' "$c" | head -1 | tr '|' '/')"
h=$(grep -m1 '^SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES=' /usr/local/etc/suru/hw-profile.conf 2>&1); h_rc=$?
printf 'HWPROFILE|%s|%s\n' "$h_rc" "$(printf '%s\n' "$h" | head -1 | tr '|' '/')"

printf '===TIME===\n'
date +%s

printf '===SVCSTATUS===\n'
svc=$(pfSsh.php playback svc status syslog-ng 2>&1) || svc='unknown'
printf '%s\n' "$svc"

printf '===END===\n'
REMOTE_SCRIPT
  REMOTE="${REMOTE%$'\n'}"
  ssh_exec_heredoc "${REMOTE}" 'sudo sh'
}

# ── Parse helpers (awk-based for shellcheck safety) ──────────────────────────

# stat_field DATA MATCH TYPE — get a single numeric field from syslog-ng stats
# E.g.: stat_field "$stats" "d_siem_tls" "written"
stat_field() {
  local data="$1" match="$2" field="$3"
  printf '%s\n' "$data" | awk -F';' -v m="$match" -v f="$field" \
    '$0 ~ m && $5 == f { v=$6 } END { print (v+0) }'
}

# stat_string DATA MATCH TYPE — like stat_field but keeps the value as written
# (e.g. "12.3"). Only a decimal number is returned, otherwise nothing: callers
# interpolate it into awk programs and JSON, so router text never reaches them.
stat_string() {
  local data="$1" match="$2" field="$3"
  printf '%s\n' "$data" | awk -F';' -v m="$match" -v f="$field" \
    '$0 ~ m && $5 == f {
       if ($6 ~ /^-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) print $6
       exit
     }'
}

# source_stamps DATA — print "LABEL STAMP" lines for active file sources
# Returns only sources with stamp > 0 (have processed at least one message).
# Uses POSIX awk (no 3-arg match; no GNU extensions).
source_stamps() {
  local data="$1"
  printf '%s\n' "$data" | awk -F';' '
    $1 == "src.file" && $5 == "stamp" && $6+0 > 0 {
      path = $3
      # Extract basename without extension
      n = split(path, parts, "/")
      base = parts[n]
      sub(/\.[^.]+$/, "", base)
      # Build a readable label
      if (index(path, "suricata") > 0 && index(path, "eve.json") > 0)
        label = "suricata-eve"
      else if (index(path, "/zeek/") > 0)
        label = "zeek-" base
      else
        label = base
      printf "%s %s\n", label, $6
    }
  '
}

# extract_section RAW SECTION_NAME — extract text between ===NAME=== markers
extract_section() {
  local raw="$1" name="$2"
  printf '%s\n' "$raw" | awk \
    -v start="===${name}===" \
    -v end_pat='===.*===' \
    'found && $0 ~ end_pat { exit }
     found { print }
     $0 == start { found=1 }'
}

# ── Buffer-file parsing (bash 3.2 safe: awk/while-read only) ─────────────────

# parse_buffer_files RAW_DQFILES RAW_OPENFILES NOW THRESHOLD_SECONDS
# Prints one normalized row per buffer file, newest mtime first:
#   path|type|mtime|size|age|messages|held|live|orphan|error
# live   = max mtime among rows with a numeric mtime (ties: all live)
# orphan = !live && held != yes && age > threshold && messages > 0
#          (held unknown still flags: the conservative reading)
# held   = yes|no when the open-file read succeeded (RC 0), else unknown
parse_buffer_files() {
  local raw_files="$1" raw_open="$2" now="$3" thr="$4"
  local held_rc open_list
  held_rc=$(printf '%s\n' "$raw_open" | awk -F'|' '$1=="RC" { print $2; exit }')
  open_list=$(printf '%s\n' "$raw_open" | awk -F'|' '$1=="OPEN" { printf "%s ", $2 }')

  printf '%s\n' "$raw_files" | awk -F'|' \
    -v now="$now" -v thr="$thr" -v hrc="${held_rc:-}" -v open=" ${open_list}" '
    function key(k) { return (mt[k] ~ /^[0-9]+$/) ? mt[k] + 0 : -1 }
    $1 == "FILE" && NF >= 8 {
      n++
      path[n] = $2; mt[n] = $3; sz[n] = $4; msg[n] = $7
      e = $8
      for (i = 9; i <= NF; i++) e = e "/" $i
      err[n] = (e == "") ? "-" : e
      if (msg[n] !~ /^[0-9]+$/ && err[n] == "-") err[n] = "message count unavailable"
      if (key(n) >= 0 && (!hasmax || key(n) > max)) { max = key(n); hasmax = 1 }
    }
    END {
      for (i = 1; i <= n; i++) idx[i] = i
      for (i = 1; i <= n; i++)
        for (j = i + 1; j <= n; j++)
          if (key(idx[j]) > key(idx[i]) ||
              (key(idx[j]) == key(idx[i]) && path[idx[j]] < path[idx[i]])) {
            t = idx[i]; idx[i] = idx[j]; idx[j] = t
          }
      for (i = 1; i <= n; i++) {
        k = idx[i]
        type = (path[k] ~ /\.rqf$/) ? "reliable" : "normal"
        if (key(k) >= 0) { age = now - mt[k]; if (age < 0) age = 0 } else age = "-"
        live = (hasmax && key(k) == max) ? "yes" : "no"
        if (hrc == "0") held = (index(open, " " path[k] " ") > 0) ? "yes" : "no"
        else held = "unknown"
        orphan = (live == "no" && held != "yes" && age != "-" && age + 0 > thr + 0 &&
                  msg[k] ~ /^[0-9]+$/ && msg[k] + 0 > 0) ? "yes" : "no"
        printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", path[k], type, mt[k], sz[k], age, msg[k], held, live, orphan, err[k]
      }
    }'
}

# cap_field RAW_CAPACITY KEY FIELD — field 2 (rc) or 3+ (text) of a CAPACITY row
cap_field() {
  local raw="$1" key="$2" field="$3"
  printf '%s\n' "$raw" | awk -F'|' -v k="$key" -v f="$field" '
    $1 == k {
      if (f == 2) { print $2; exit }
      t = $3
      for (i = 4; i <= NF; i++) t = t "/" $i
      print t; exit
    }'
}

# parse_capacity RAW_CAPACITY — prints bytes|source|reason
#   syslog-ng.conf capacity-bytes() wins; hw-profile.conf is the fallback;
#   otherwise -|unknown|<conf reason>; <hw-profile reason>
parse_capacity() {
  local raw="$1"
  local conf_rc conf_txt hw_rc hw_txt v
  conf_rc=$(cap_field "$raw" CONF 2);       conf_txt=$(cap_field "$raw" CONF 3)
  hw_rc=$(cap_field "$raw" HWPROFILE 2);    hw_txt=$(cap_field "$raw" HWPROFILE 3)

  if [[ "$conf_rc" == "0" ]]; then
    v=$(printf '%s\n' "$conf_txt" | sed -n 's/.*capacity-bytes(\([0-9][0-9]*\)).*/\1/p' | head -1)
    if [[ -n "$v" ]] && (( v > 0 )); then
      printf '%s|syslog-ng.conf|-\n' "$v"; return 0
    fi
  fi
  if [[ "$hw_rc" == "0" ]]; then
    v=$(printf '%s\n' "$hw_txt" | sed -n 's/^[^=]*=[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -1)
    if [[ -n "$v" ]] && (( v > 0 )); then
      printf '%s|hw-profile.conf|-\n' "$v"; return 0
    fi
  fi
  local c_reason h_reason
  c_reason="${conf_txt:-no capacity-bytes() value (rc=${conf_rc:-no data})}"
  h_reason="${hw_txt:-no SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES value (rc=${hw_rc:-no data})}"
  printf -- '-|unknown|syslog-ng.conf: %s; hw-profile.conf: %s\n' "$c_reason" "$h_reason"
}

# collect_errors RAW_STATS RAW_DQFILES RAW_OPENFILES RAW_CAPACITY
# One line per failed read (never silent).
collect_errors() {
  local raw_stats="$1" raw_files="$2" raw_open="$3" raw_cap="$4"
  printf '%s\n' "$raw_stats" | awk -F'|' '
    $1 == "ERR_STATS" { t = $2; for (i = 3; i <= NF; i++) t = t "/" $i; print "syslog-ng-ctl stats failed: " t }'
  printf '%s\n' "$raw_files" | awk -F'|' '
    $1 == "FILE" && NF >= 8 {
      t = $8; for (i = 9; i <= NF; i++) t = t "/" $i
      if (t == "" || t == "-") { if ($7 ~ /^[0-9]+$/) next; t = "message count unavailable" }
      print $2 ": " t }'
  local orc
  orc=$(printf '%s\n' "$raw_open" | awk -F'|' '$1=="RC" { print $2; exit }')
  case "$orc" in
    0)   ;;
    127) printf 'open-file check skipped: no syslog-ng process found (held-open state unknown)\n' ;;
    "")  printf 'open-file check returned no data (held-open state unknown)\n' ;;
    *)   printf 'procstat -f failed (rc=%s); held-open state unknown\n' "$orc" ;;
  esac
  local crc ctxt
  crc=$(cap_field "$raw_cap" CONF 2); ctxt=$(cap_field "$raw_cap" CONF 3)
  if [[ -z "$crc" ]]; then printf 'capacity read of syslog-ng.conf returned no data\n'
  elif [[ "$crc" != "0" ]]; then printf 'capacity read of /usr/local/etc/syslog-ng.conf failed (rc=%s): %s\n' "$crc" "${ctxt:-no match}"; fi
  crc=$(cap_field "$raw_cap" HWPROFILE 2); ctxt=$(cap_field "$raw_cap" HWPROFILE 3)
  if [[ -z "$crc" ]]; then printf 'capacity read of hw-profile.conf returned no data\n'
  elif [[ "$crc" != "0" ]]; then printf 'capacity read of /usr/local/etc/suru/hw-profile.conf failed (rc=%s): %s\n' "$crc" "${ctxt:-no match}"; fi
}

# live_messages ROWS — message count of the first live row; "unknown" when there
# is no live row or its count is not numeric (never a fabricated 0)
live_messages() {
  printf '%s\n' "$1" | awk -F'|' '$8 == "yes" { if ($6 ~ /^[0-9]+$/) print $6; else print "unknown"; found = 1; exit } END { if (!found) print "unknown" }'
}

# ── Output: human-readable ────────────────────────────────────────────────────
print_header() {
  local host="$1" ts="$2"
  local dt; dt=$(date -r "$ts" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -d "@${ts}" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || printf '%s' "$ts")
  printf '\n'
  printf "${C_BOLD}══════════════════════════════════════════════════${C_RESET}\n"
  printf "${C_BOLD}  SURU Tier 1 — syslog-ng Metrics${C_RESET}\n"
  printf "  Router: ${C_CYAN}%s${C_RESET}  │  %s\n" "$host" "$dt"
  printf "${C_BOLD}══════════════════════════════════════════════════${C_RESET}\n"
}

print_status() {
  local stats="$1" svc="$2"
  printf '\n%bSERVICE%b\n' "${C_BOLD}" "${C_RESET}"

  # Service status
  local svc_state
  if printf '%s\n' "$svc" | grep -qi 'running'; then
    svc_state="$(ok) running"
  elif printf '%s\n' "$svc" | grep -qi 'stopped'; then
    svc_state="$(err) stopped"
  else
    svc_state="$(warn) unknown"
  fi
  printf "  %-22s %b\n" "Status" "$svc_state"

  # SIEM destination — derive address from stats instance field (e.g. "tls,syslog.suru.corp.example:443")
  local siem_addr; siem_addr=$(printf '%s\n' "$stats" | awk -F';' '/d_siem_tls#0/ { print $3; exit }')
  [[ -n "$siem_addr" ]] && printf "  %-22s %s\n" "SIEM" "$siem_addr"

  # Counters
  local written dropped
  written=$(stat_field "$stats" "d_siem_tls#0" "written")
  dropped=$(stat_field "$stats" "d_siem_tls#0" "dropped")

  printf "  %-22s %s messages\n" "Total delivered" "$(comma_num "${written:-0}")"
  if [[ "${dropped:-0}" -eq 0 ]]; then
    printf "  %-22s %s  %b\n" "Dropped" "0" "$(ok)"
  else
    printf "  %-22s %s  %b\n" "Dropped" "$(comma_num "$dropped")" "$(err) MESSAGES LOST"
  fi

  # Write rate
  local eps_1h eps_24h
  eps_1h=$(stat_string  "$stats" "d_siem_tls#0" "eps_last_1h")
  eps_24h=$(stat_string "$stats" "d_siem_tls#0" "eps_last_24h")
  local rate_icon
  if awk "BEGIN { exit (${eps_1h:-0} > 0) ? 0 : 1 }"; then
    rate_icon="$(ok)"
  else
    rate_icon="$(warn) SIEM not receiving"
  fi
  printf "  %-22s %.1f eps (1h)  /  %.1f eps (24h)  %b\n" \
    "Write rate" "${eps_1h:-0}" "${eps_24h:-0}" "$rate_icon"
}

print_buffer() {
  local stats="$1" rows="$2" capacity="$3" now="$4"
  # shellcheck disable=SC2034 # now: ages are already normalized in ROWS
  : "$now"
  printf '\n%bDISK BUFFER%b\n' "${C_BOLD}" "${C_RESET}"

  local cbytes csrc creason
  IFS='|' read -r cbytes csrc creason <<< "$capacity"
  case "$csrc" in
    syslog-ng.conf)
      printf "  %-22s %s  (source: /usr/local/etc/syslog-ng.conf capacity-bytes)\n" \
        "Capacity (ceiling)" "$(human_bytes "$cbytes")" ;;
    hw-profile.conf)
      printf "  %-22s %s  (source: /usr/local/etc/suru/hw-profile.conf)\n" \
        "Capacity (ceiling)" "$(human_bytes "$cbytes")" ;;
    *)
      printf "  %-22s unknown — %s\n" "Capacity (ceiling)" "$creason" ;;
  esac

  local nfiles
  nfiles=$(printf '%s\n' "$rows" | awk 'NF { c++ } END { print c + 0 }')
  printf "  %-22s %s under /var/db  (orphan threshold: %sh)\n" \
    "Buffer files" "$nfiles" "$ORPHAN_AGE_HOURS"

  local path type mtime size age msgs held live orphan error
  local norphans=0
  while IFS='|' read -r path type mtime size age msgs held live orphan error; do
    [[ -n "$path" ]] || continue
    local icon msg_txt size_txt pct_txt age_txt
    if   [[ "$error" != "-" ]];  then icon="$(err)"
    elif [[ "$orphan" == "yes" ]]; then icon="$(warn) ORPHAN?"; norphans=$(( norphans + 1 ))
    elif [[ "$live" == "yes" ]];   then icon="$(ok)"
    else icon="-"
    fi
    if [[ "$msgs" =~ ^[0-9]+$ ]]; then msg_txt="$(comma_num "$msgs") messages"; else msg_txt="messages unknown"; fi
    if [[ "$size" =~ ^[0-9]+$ ]]; then
      size_txt="$(human_bytes "$size")"
      if [[ "$cbytes" =~ ^[0-9]+$ ]]; then
        pct_txt=" ($(awk "BEGIN { printf \"%.1f\", (${size}/${cbytes})*100 }")%)"
      else
        pct_txt=""
      fi
    else
      size_txt="size unknown"; pct_txt=""
    fi
    if [[ "$age" =~ ^[0-9]+$ ]]; then age_txt="last write $(human_duration "$age") ago"; else age_txt="last write unknown"; fi
    printf "  %b %s  %s  %s%s  %s  held open: %s\n" \
      "$icon" "$path" "$msg_txt" "$size_txt" "$pct_txt" "$age_txt" "$held"
  done <<< "$rows"

  local queued_bytes live_msgs
  queued_bytes=$(stat_field "$stats" "d_siem_tls#0" "queued")
  if [[ "$nfiles" -eq 0 ]]; then
    printf "  %-22s %s  (no buffer file)\n" "Queue depth (live)" "$(human_bytes "${queued_bytes:-0}")"
    printf "  %b no buffer file found under /var/db (syslog-ng-*.rqf, syslog-ng-*.qf)\n" "$(warn)"
  else
    live_msgs=$(printf '%s\n' "$rows" | awk -F'|' '$8 == "yes" { print $6; exit }')
    if [[ "$live_msgs" =~ ^[0-9]+$ ]]; then
      printf "  %-22s %s  (%s messages)\n" "Queue depth (live)" \
        "$(human_bytes "${queued_bytes:-0}")" "$(comma_num "$live_msgs")"
    else
      printf "  %-22s %s  (messages unknown)\n" "Queue depth (live)" "$(human_bytes "${queued_bytes:-0}")"
    fi
  fi

  if (( norphans > 0 )); then
    printf '  %b %d probable orphan(s) — likely stranded (confirm on the router when held open: unknown); see DEPLOYMENT-NOTES "Orphaned buffer files"\n' \
      "$(warn)" "$norphans"
  fi

  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '  %b %s\n' "$(err)" "$line"
  done <<< "$COLLECTION_ERRORS"
}

print_lag() {
  local stats="$1" rows="$2" now="$3"
  printf '\n%bSOURCE LAG%b  (time since last event read per source)\n' "${C_BOLD}" "${C_RESET}"

  local max_lag=0
  local any_source=false

  while IFS=' ' read -r label stamp; do
    any_source=true
    local age=$(( now - stamp ))
    [[ $age -lt 0 ]] && age=0
    [[ $age -gt $max_lag ]] && max_lag=$age
    local icon
    if   (( age <   60 )); then icon="$(ok)"
    elif (( age < 3600 )); then icon="$(warn)"
    else                        icon="$(err)"
    fi
    printf "  %-24s %s  %b\n" "$label" "$(human_duration "$age")" "$icon"
  done < <(source_stamps "$stats")

  $any_source || printf "  (no active file sources with processed messages)\n"

  printf '\n%bDELIVERY LAG%b\n' "${C_BOLD}" "${C_RESET}"

  local written queued_bytes msg_count eps_1h eps_24h
  written=$(stat_field      "$stats" "d_siem_tls#0" "written")
  queued_bytes=$(stat_field "$stats" "d_siem_tls#0" "queued")
  eps_1h=$(stat_string      "$stats" "d_siem_tls#0" "eps_last_1h")
  eps_24h=$(stat_string     "$stats" "d_siem_tls#0" "eps_last_24h")

  msg_count=$(live_messages "$rows")

  local eps; eps="${eps_1h:-0}"

  if [[ "$msg_count" == "unknown" ]]; then
    local no_file=false
    [[ -n "$rows" ]] || no_file=true
    if $no_file; then
      printf "  %-24s none — no buffer file found under /var/db  (%s)  %b\n" \
        "Queued in buffer" "$(human_bytes "${queued_bytes:-0}")" "$(warn)"
    else
      printf "  %-24s unknown  (%s)  %b\n" \
        "Queued in buffer" "$(human_bytes "${queued_bytes:-0}")" "$(warn)"
    fi
    if awk "BEGIN { exit (${eps} > 0) ? 0 : 1 }"; then
      printf "  %-24s %.1f eps  %b\n" "SIEM write rate" "$eps" "$(ok)"
    else
      printf "  %-24s 0.0 eps  %b\n" "SIEM write rate" "$(warn) SIEM unreachable or idle"
    fi
    printf "  %-24s buffer depth unknown — drain estimate skipped\n" "Drain"
    printf '\n  %b buffer depth unknown — see --buffer / collection errors\n' "$(warn)"
    local eline
    while IFS= read -r eline; do
      [[ -n "$eline" ]] || continue
      printf '  %b %s\n' "$(err)" "$eline"
    done <<< "$COLLECTION_ERRORS"
    return 0
  fi

  printf "  %-24s %s messages  (%s)\n" \
    "Queued in buffer" \
    "$(comma_num "${msg_count:-0}")" \
    "$(human_bytes "${queued_bytes:-0}")"

  if awk "BEGIN { exit (${eps} > 0) ? 0 : 1 }"; then
    # SIEM is receiving — calculate drain time
    local drain_secs
    drain_secs=$(awk "BEGIN {
      eps = ${eps}+0; q = ${msg_count}+0
      if (eps > 0 && q > 0) printf \"%d\", q/eps
      else printf \"0\"
    }")
    if [[ "$drain_secs" -gt 0 ]]; then
      printf "  %-24s %.1f eps  %b\n" "SIEM write rate" "$eps" "$(ok)"
      printf "  %-24s ~%s at current rate\n" "Estimated drain" "$(human_duration "$drain_secs")"
    else
      printf "  %-24s %.1f eps  %b  (buffer drained)\n" "SIEM write rate" "$eps" "$(ok)"
    fi
  else
    printf "  %-24s 0.0 eps  %b\n" "SIEM write rate" "$(warn) SIEM unreachable or idle"
    if [[ "${msg_count:-0}" -gt 0 ]]; then
      printf "  %-24s buffer will drain when SIEM reconnects\n" "Drain"
      # Estimate time behind using 24h rate if available
      if awk "BEGIN { exit (${eps_24h:-0} > 0) ? 0 : 1 }"; then
        local drain_est
        drain_est=$(awk "BEGIN { printf \"%d\", ${msg_count}/${eps_24h} }")
        printf "  %-24s ~%s  (based on 24h rate of %.0f eps)\n" \
          "Drain estimate" "$(human_duration "$drain_est")" "${eps_24h}"
      fi
    fi
  fi

  # Time-behind summary — only shown when lag is meaningful (>60s) or buffer non-empty
  if [[ $max_lag -gt 60 ]] || [[ "${msg_count:-0}" -gt 0 ]]; then
    printf '\n  %b OVERALL LAG SUMMARY\n' "$(warn)"
    printf "  Source read lag:  %s (most lagged source)\n" "$(human_duration "$max_lag")"
    printf "  Delivery backlog: %s messages\n" "$(comma_num "${msg_count:-0}")"
    # Days behind estimate
    local day_est=0
    if awk "BEGIN { exit (${eps_24h:-0} > 0) ? 0 : 1 }"; then
      day_est=$(awk "BEGIN { printf \"%.1f\", ${msg_count}/(${eps_24h}*86400) }")
      printf "  Behind by:        ~%s days of log volume\n" "$day_est"
    fi
  else
    printf '\n  %b  All sources current, buffer empty — delivery live\n' "$(ok)"
  fi
}

# json_str STRING — JSON-escape (control chars dropped)
json_str() {
  printf '%s' "$1" | tr -d '[:cntrl:]' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# jnum VALUE — numeric passthrough, anything else (e.g. "-") becomes null
jnum() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; else printf 'null'; fi
}

# jbool VALUE — yes|no -> true|false, anything else -> null
jbool() {
  case "$1" in yes) printf 'true' ;; no) printf 'false' ;; *) printf 'null' ;; esac
}

# ── Output: JSON ──────────────────────────────────────────────────────────────
print_json() {
  local stats="$1" rows="$2" capacity="$3" svc="$4" now="$5"

  local written dropped queued_bytes eps_1h eps_24h msg_count svc_running
  written=$(stat_field      "$stats" "d_siem_tls#0" "written")
  dropped=$(stat_field      "$stats" "d_siem_tls#0" "dropped")
  queued_bytes=$(stat_field "$stats" "d_siem_tls#0" "queued")
  eps_1h=$(stat_string      "$stats" "d_siem_tls#0" "eps_last_1h")
  eps_24h=$(stat_string     "$stats" "d_siem_tls#0" "eps_last_24h")
  msg_count=$(live_messages "$rows")
  [[ "$msg_count" =~ ^[0-9]+$ ]] || msg_count=0
  printf '%s\n' "$svc" | grep -qi 'running' && svc_running=true || svc_running=false

  # Live file (first live row) and orphan count
  local live_row q_path="" q_size=0 q_mtime=0 q_path_json="null"
  live_row=$(printf '%s\n' "$rows" | awk -F'|' '$8 == "yes" { print; exit }')
  if [[ -n "$live_row" ]]; then
    local _t _a _m _h _l _o _e
    IFS='|' read -r q_path _t q_mtime q_size _a _m _h _l _o _e <<< "$live_row"
    [[ "$q_size" =~ ^[0-9]+$ ]] || q_size=0
    [[ "$q_mtime" =~ ^[0-9]+$ ]] || q_mtime=0
    q_path_json="\"$(json_str "$q_path")\""
  fi
  local orphan_count
  orphan_count=$(printf '%s\n' "$rows" | awk -F'|' '$9 == "yes" { c++ } END { print c + 0 }')

  local cbytes csrc creason
  IFS='|' read -r cbytes csrc creason <<< "$capacity"

  # files[]
  local files_json="" sep="" path type mtime size age msgs held live orphan error
  while IFS='|' read -r path type mtime size age msgs held live orphan error; do
    [[ -n "$path" ]] || continue
    local err_json="null"
    [[ "$error" != "-" ]] && err_json="\"$(json_str "$error")\""
    files_json="${files_json}${sep}
      {\"path\": \"$(json_str "$path")\", \"type\": \"${type}\", \"messages\": $(jnum "$msgs"), \"size_bytes\": $(jnum "$size"), \"mtime\": $(jnum "$mtime"), \"age_seconds\": $(jnum "$age"), \"held_open\": $(jbool "$held"), \"live\": $(jbool "$live"), \"orphan\": $(jbool "$orphan"), \"error\": ${err_json}}"
    sep=","
  done <<< "$rows"

  # collection_errors[]
  local errs_json="" esep="" line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    errs_json="${errs_json}${esep}
      \"$(json_str "$line")\""
    esep=","
  done <<< "$COLLECTION_ERRORS"

  local max_src_lag=0
  while IFS=' ' read -r _ stamp; do
    local age_s=$(( now - stamp ))
    [[ $age_s -gt $max_src_lag ]] && max_src_lag=$age_s
  done < <(source_stamps "$stats")

  local drain_secs=0
  if awk "BEGIN { exit (${eps_1h:-0} > 0) ? 0 : 1 }"; then
    drain_secs=$(awk "BEGIN { eps=${eps_1h}+0; q=${msg_count}+0; printf \"%d\", (eps>0&&q>0)?q/eps:0 }")
  fi

  cat <<EOF
{
  "timestamp": ${now},
  "router": "$(json_str "${ROUTER_HOST}")",
  "service": {
    "running": ${svc_running},
    "delivered_total": ${written:-0},
    "dropped_total": ${dropped:-0},
    "write_eps_1h": ${eps_1h:-0},
    "write_eps_24h": ${eps_24h:-0}
  },
  "buffer": {
    "messages_queued": ${msg_count:-0},
    "bytes_queued": ${queued_bytes:-0},
    "queue_file": ${q_path_json},
    "queue_file_size_bytes": ${q_size},
    "queue_file_mtime": ${q_mtime},
    "queue_ceiling_bytes": $(jnum "$cbytes"),
    "queue_ceiling_source": "${csrc}",
    "orphan_age_threshold_seconds": ${ORPHAN_AGE_SECONDS},
    "orphan_count": ${orphan_count},
    "files": [${files_json}
    ],
    "collection_errors": [${errs_json}
    ]
  },
  "lag": {
    "max_source_read_lag_seconds": ${max_src_lag},
    "queued_messages": ${msg_count:-0},
    "estimated_drain_seconds": ${drain_secs}
  }
}
EOF
}

# ── Main ──────────────────────────────────────────────────────────────────────
COLLECTION_ERRORS=""

main() {
  parse_args "$@"
  load_env

  # The lib's DRY_RUN prints the command instead of running it, which would
  # leave nothing to parse; these reads are read-only, so refuse plainly.
  # Checked here, not inside ssh_collect: that runs in a command substitution,
  # where a die would be followed by the misleading "SSH … failed" below.
  printf '%s\n' "[notice] syslog-ng-metrics needs a root shell over the deploy identity; a restricted deploy account does not allow it" >&2

  [[ "${DRY_RUN:-false}" == "true" ]] && die "DRY_RUN=true is set: sng-* only reads the router and has no dry-run mode — unset DRY_RUN"

  # Validate SSH key exists
  [[ -f "$ROUTER_SSH_KEY" ]] || die "SSH key not found: $ROUTER_SSH_KEY  (set ROUTER_SSH_KEY in .env)"

  # Collect all metrics in one SSH session
  local raw
  raw=$(ssh_collect) || die "SSH to ${ROUTER_HOST} failed — check ROUTER_HOST and SSH key"
  # Router output (error text included) reaches the terminal: drop control
  # characters other than tab and newline so it cannot carry terminal escapes.
  raw=$(printf '%s' "$raw" | LC_ALL=C tr -d '\001-\010\013-\037\177')
  verbose "raw output:\n${raw}"

  # Extract sections
  local stats svc_raw dqfiles_raw openfiles_raw capacity_raw now
  stats=$(extract_section         "$raw" "STATS")
  svc_raw=$(extract_section       "$raw" "SVCSTATUS")
  dqfiles_raw=$(extract_section   "$raw" "DQFILES")
  openfiles_raw=$(extract_section "$raw" "OPENFILES")
  capacity_raw=$(extract_section  "$raw" "CAPACITY")
  now=$(extract_section           "$raw" "TIME" | tr -d '[:space:]')

  verbose "parsed STATS lines: $(printf '%s\n' "$stats" | wc -l | tr -d ' ')"
  verbose "parsed DQFILES: $dqfiles_raw"
  verbose "parsed OPENFILES: $openfiles_raw"
  verbose "parsed CAPACITY: $capacity_raw"
  verbose "parsed NOW: $now"

  # Sanity check
  [[ -n "$now" && "$now" =~ ^[0-9]+$ ]] || die "Could not parse router timestamp — SSH succeeded but output is unexpected"

  local rows capacity
  rows=$(parse_buffer_files "$dqfiles_raw" "$openfiles_raw" "$now" "$ORPHAN_AGE_SECONDS")
  capacity=$(parse_capacity "$capacity_raw")
  COLLECTION_ERRORS=$(collect_errors "$stats" "$dqfiles_raw" "$openfiles_raw" "$capacity_raw")
  verbose "parsed buffer rows: $rows"
  if [[ -n "$rows" && "$(live_messages "$rows")" == "unknown" ]]; then
    COLLECTION_ERRORS="${COLLECTION_ERRORS}${COLLECTION_ERRORS:+
}live buffer message count unavailable"
  fi

  # JSON mode
  if $OUTPUT_JSON; then
    print_json "$stats" "$rows" "$capacity" "$svc_raw" "$now"
    exit 0
  fi

  # Human-readable mode
  print_header "${ROUTER_HOST}" "$now"

  if $SHOW_STATUS; then print_status "$stats" "$svc_raw";                       fi
  if $SHOW_BUFFER; then print_buffer "$stats" "$rows" "$capacity" "$now";       fi
  if $SHOW_LAG;    then print_lag    "$stats" "$rows" "$now";                   fi

  printf '\n'
}

main "$@"
