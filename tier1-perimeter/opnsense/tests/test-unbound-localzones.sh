#!/usr/bin/env bash
# =============================================================================
# SURU Tier 1 — behavioural tests for opnsense/unbound-localzones-apply.php
#
# The applier addresses absolute firewall paths (/conf/config.xml,
# /usr/local/etc/unbound.opnsense.d, /var/unbound) and shells out to configctl
# and unbound-control. Rather than give production code a test-only path seam,
# this runs a COPY of the applier with its path constants rewritten to a temp
# root, and puts stub configctl/unbound-control binaries first on PATH. Nothing
# outside the temp root is touched and no privileges are needed.
#
# Every rewrite is asserted: a pattern that stops matching fails the suite
# instead of silently leaving the copy pointed at a real system path.
#
# Skips (exit 0) when php is unavailable. One scenario additionally needs root
# to drop privileges and is skipped otherwise; it says so.
# =============================================================================
set -uo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLIER="${SUITE_DIR}/../unbound-localzones-apply.php"

if ! command -v php >/dev/null 2>&1; then
  echo "SKIP: php not available — cannot exercise the applier."
  exit 0
fi
[ -r "${APPLIER}" ] || { echo "FATAL: applier not found at ${APPLIER}"; exit 1; }

ROOT="$(mktemp -d)"
BIN="${ROOT}/bin"
SRC="${ROOT}/applier.php"
trap 'rm -rf -- "${ROOT:?}"' EXIT
mkdir -p "${BIN}"
PATH="${BIN}:${PATH}"
# One scenario drops privileges to prove a read-denial; mktemp's 0700 root would
# block traversal before the applier ever runs, masking what is under test.
chmod 755 "${ROOT}" "${BIN}"

pass=0; fail=0
check() {
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "  ok   $1 ($3)"
  else fail=$((fail+1)); echo "  FAIL $1 — expected [$2] got [$3]"; fi
}

# --- build the rewritten copy ------------------------------------------------
rewrite() { # description  from  to
  local before after
  before="$(grep -c -F -- "$2" "${SRC}" || true)"
  if [ "${before}" -eq 0 ]; then
    echo "FATAL: rewrite target vanished — '$1' no longer matches the applier."
    echo "       The applier changed; update this suite rather than skipping it."
    exit 1
  fi
  perl -pi -e "s{\Q$2\E}{$3}g" "${SRC}"
  after="$(grep -o -F -- "$2" "${SRC}" | wc -l | tr -d ' ')"
  # When the replacement embeds the original (a path gaining a temp-root
  # prefix), every remaining hit must be one of the rewritten paths; otherwise
  # none may remain at all.
  local expected=0
  case "$3" in
    *"$2"*) expected="$(grep -o -F -- "$3" "${SRC}" | wc -l | tr -d ' ')" ;;
  esac
  [ "${after}" = "${expected}" ] || {
    echo "FATAL: rewrite '$1' left $(( after - expected )) unrewritten occurrence(s)"; exit 1; }
}
cp -- "${APPLIER}" "${SRC}"
rewrite "drop-in dir"      "/usr/local/etc/unbound.opnsense.d" "${ROOT}/usr/local/etc/unbound.opnsense.d"
rewrite "config.xml"       "/conf/config.xml"                  "${ROOT}/conf/config.xml"
rewrite "unbound-control"  "/usr/local/sbin/unbound-control"   "unbound-control"
rewrite "generated tree"   "/var/unbound/"                     "${ROOT}/var/unbound/"

# Nothing may still point at a real system path.
if grep -nE "'/(conf|usr|var|sbin)/" "${SRC}" | grep -v "${ROOT}" | grep -v '/sbin/ifconfig'; then
  echo "FATAL: rewritten copy still references a production path (listed above)."
  exit 1
fi
chmod 644 "${SRC}"
php -l "${SRC}" >/dev/null || { echo "FATAL: rewritten copy does not parse"; exit 1; }

setup() {
  rm -rf -- "${ROOT:?}/conf" "${ROOT:?}/usr" "${ROOT:?}/var"
  mkdir -p "${ROOT}/conf" "${ROOT}/usr/local/etc/unbound.opnsense.d" "${ROOT}/var/unbound/etc"
  chmod -R a+rX "${ROOT}/conf" "${ROOT}/usr" "${ROOT}/var"
  printf '<?xml version="1.0"?>\n<opnsense><system><domain>corp.example</domain></system></opnsense>\n' > "${ROOT}/conf/config.xml"
  echo 0 > "${ROOT}/configctl.rc"; rm -f -- "${ROOT}/configctl.always_fail"
  # Models the real sequence: the restart fails while the rejected drop-in is in
  # place, then succeeds once the rollback has removed or restored it.
  cat > "${BIN}/configctl" <<EOS
#!/bin/sh
echo "configctl: \$*"
[ -f "${ROOT}/configctl.always_fail" ] && exit 1
rc=\$(cat "${ROOT}/configctl.rc")
[ "\$rc" = "0" ] || echo 0 > "${ROOT}/configctl.rc"
exit "\$rc"
EOS
  cat > "${BIN}/unbound-control" <<EOS
#!/bin/sh
[ -f "${ROOT}/zones.txt" ] || exit 1
cat "${ROOT}/zones.txt"
EOS
  chmod 755 "${BIN}/configctl" "${BIN}/unbound-control"
  cat > "${ROOT}/zones.txt" <<'EOS'
local. always_nxdomain
alt. always_nxdomain
wpad.corp.example. always_nxdomain
isatap.corp.example. always_nxdomain
home.arpa. static
resolver.arpa. static
service.arpa. static
localhost. redirect
onion. always_nxdomain
test. always_nxdomain
invalid. always_nxdomain
corp.example. transparent
EOS
  printf 'server:\n  local-zone: "x." refuse\n' > "${ROOT}/var/unbound/unbound.conf"
}
DROPIN="${ROOT}/usr/local/etc/unbound.opnsense.d/suru-localzones.conf"
run() { php "${SRC}" "$@" > "${ROOT}/out.txt" 2>&1; echo $?; }

echo "== 1. fresh apply, restart ok, zones live, no forward zone -> exit 6 (GUI step) =="
setup; rc=$(run); check "exit" 6 "$rc"
check "drop-in present" yes "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "ACTION REQUIRED" yes "$(grep -qc 'ACTION REQUIRED' ${ROOT}/out.txt >/dev/null && grep -q 'ACTION REQUIRED' ${ROOT}/out.txt && echo yes || echo no)"
check "no scan caveat" no "$(grep -q 'Split-horizon scan incomplete' ${ROOT}/out.txt && echo yes || echo no)"
check "scan ran" yes "$(grep -q 'Split-horizon scan: ' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 2. restart FAILS, no pre-existing drop-in -> rollback removes file, exit 4 =="
setup; echo 1 > ${ROOT}/configctl.rc; rc=$(run); check "exit" 4 "$rc"
check "drop-in removed" no "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "rollback logged" yes "$(grep -q 'Rollback: removed' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 3. restart FAILS, pre-existing drop-in -> prior content restored, exit 4 =="
setup; printf 'PREVIOUS-OPERATOR-STATE\n' > "$DROPIN"; echo 1 > ${ROOT}/configctl.rc
rc=$(run); check "exit" 4 "$rc"
check "prior content restored" "PREVIOUS-OPERATOR-STATE" "$(cat "$DROPIN")"
check "rollback logged" yes "$(grep -q 'Rollback: restored the pre-run' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 4. zones MISSING after apply (this run wrote) -> rollback, exit 4 =="
setup; printf 'home.arpa. static\ncorp.example. transparent\n' > ${ROOT}/zones.txt
rc=$(run); check "exit" 4 "$rc"
check "drop-in removed" no "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "rollback logged" yes "$(grep -q 'Rollback: removed' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 5. zones MISSING but drop-in UNCHANGED -> no rollback, file kept, exit 3 =="
setup
php "$SRC" >/dev/null 2>&1   # converge first (writes target content)
printf 'home.arpa. static\ncorp.example. transparent\n' > ${ROOT}/zones.txt
rc=$(run); check "exit 3 (pre-existing drift, nothing written)" 3 "$rc"
check "drop-in kept" yes "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "no rollback" no "$(grep -q 'Rollback' ${ROOT}/out.txt && echo yes || echo no)"
check "no restart churn" no "$(grep -q 'Reloading unbound' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 6. generated tree ABSENT -> WARN + caveat carried into exit 6 =="
setup; rm -rf ${ROOT}/var/unbound; mkdir -p ${ROOT}/var/unbound_missing
rc=$(run); check "exit" 6 "$rc"
check "UNKNOWN warn" yes "$(grep -q 'split-horizon state UNKNOWN' ${ROOT}/out.txt && echo yes || echo no)"
check "caveat in recommendation" yes "$(grep -q 'Split-horizon scan incomplete' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 7. real forward-zone for system domain -> split-horizon skip, exit 0 =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-addr: 192.0.2.10\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 0 "$rc"
check "split-horizon WARN" yes "$(grep -q 'NOT recommending static' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 8. negative control: auth-zone names domain + unrelated forward-zone -> no false hit =="
setup; printf 'auth-zone:\n  name: "corp.example"\nforward-zone:\n  name: "other.example"\n  forward-addr: 192.0.2.11\n' > ${ROOT}/var/unbound/mixed.conf
rc=$(run); check "exit" 6 "$rc"
check "no false split-horizon" no "$(grep -q 'NOT recommending static' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 9. idempotent re-run, system domain already static -> exit 0, no churn =="
setup; php "$SRC" >/dev/null 2>&1
sed -i 's/^corp.example. transparent$/corp.example. static/' ${ROOT}/zones.txt
rc=$(run); check "exit" 0 "$rc"
check "no rewrite" yes "$(grep -q 'Drop-in already at target content' ${ROOT}/out.txt && echo yes || echo no)"
check "no restart churn" no "$(grep -q 'Reloading unbound' ${ROOT}/out.txt && echo yes || echo no)"
check "static verified" yes "$(grep -q 'system domain is a static local-zone' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 11. rc=2 probe failure with a pre-existing drop-in -> file untouched =="
setup; php "$SRC" >/dev/null 2>&1          # converge: a good drop-in exists
before=$(md5sum "$DROPIN" | cut -d" " -f1)
rm -f ${BIN}/configctl             # probe now fails
rc=$(run); check "exit" 2 "$rc"
check "drop-in untouched" "$before" "$(md5sum "$DROPIN" | cut -d' ' -f1)"
check "no rollback attempted" no "$(grep -q 'Rollback' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 12. rollback marker strings the driver keys off are emitted verbatim =="
setup; echo 1 > ${ROOT}/configctl.rc; rc=$(run)
check "exit" 4 "$rc"
check "'Rollback complete' marker" yes "$(grep -q 'Rollback complete' ${ROOT}/out.txt && echo yes || echo no)"
check "no CRITICAL when rollback worked" no "$(grep -q 'CRITICAL' ${ROOT}/out.txt && echo yes || echo no)"
setup; echo 1 > ${ROOT}/configctl.rc; touch ${ROOT}/configctl.always_fail; rc=$(run)
check "exit 5 (rollback itself failed)" 5 "$rc"
check "CRITICAL marker (resolver stays down)" yes "$(grep -q 'CRITICAL: unbound did not restart after rollback' ${ROOT}/out.txt && echo yes || echo no)"
check "no false 'Rollback complete'" no "$(grep -q 'Rollback complete' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 13. decoy zone ending in the asked-for name must NOT satisfy the read-back =="
setup
# real 'alt.' zone absent; a longer name that ENDS with it is present instead
sed -i 's/^alt. always_nxdomain$/cobalt. always_nxdomain/' ${ROOT}/zones.txt
rc=$(run); check "exit" 4 "$rc"
check "named the missing zone" yes "$(grep -q 'zone missing from live zone list after apply: alt. always_nxdomain' ${ROOT}/out.txt && echo yes || echo no)"
check "rolled back" yes "$(grep -q 'Rollback' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 14. builtin-defaults WARN is line-anchored too =="
setup; sed -i 's/^onion. always_nxdomain$/notonion. always_nxdomain/' ${ROOT}/zones.txt
run >/dev/null
check "WARN for onion." yes "$(grep -q "builtin default zone 'onion.' NOT in the live zone list" ${ROOT}/out.txt && echo yes || echo no)"
setup; run >/dev/null
check "no WARN when present" no "$(grep -q 'builtin default zone' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 15. --no-system-domain-static: reports zone type, skips the unused scan =="
setup; rc=$(run --no-system-domain-static); check "exit" 0 "$rc"
check "live zone type still reported" yes "$(grep -q "live zone type" ${ROOT}/out.txt && echo yes || echo no)"
check "opt-out reported" yes "$(grep -q 'operator opt-out' ${ROOT}/out.txt && echo yes || echo no)"
check "scan skipped" no "$(grep -q 'Split-horizon scan' ${ROOT}/out.txt && echo yes || echo no)"
# opt-out must not suppress leg A: the zones are still applied and verified
check "leg A still verified" yes "$(grep -q 'SURU zone(s) present in the live zone list' ${ROOT}/out.txt && echo yes || echo no)"
setup; rc=$(run); check "scan still runs without the flag" yes "$(grep -q 'Split-horizon scan' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 16. unchanged drop-in + zones missing: left-in-place state is explained =="
setup; php "$SRC" >/dev/null 2>&1
printf 'home.arpa. static
corp.example. transparent
' > ${ROOT}/zones.txt
rc=$(run); check "exit 3 (distinct from a rolled-back 4)" 3 "$rc"
check "explains no-undo" yes "$(grep -q 'left in place — this run wrote nothing to undo' ${ROOT}/out.txt && echo yes || echo no)"
check "still no rollback" no "$(grep -q 'Rollback' ${ROOT}/out.txt && echo yes || echo no)"

skip17=0
[ "$(id -u)" = "0" ] || skip17=1
if [ "$skip17" = "1" ]; then echo "== 17. SKIPPED (needs root to drop privileges for the read-denial) =="; else
echo "== 17. unreadable pre-existing drop-in: refuse, never delete it =="
# Root bypasses mode bits, so the read must be denied to a real unprivileged
# user: the drop-in stays root-owned 000 while everything else the applier
# needs is readable/writable by nobody.
setup; printf 'OPERATOR-STATE\n' > "$DROPIN"; chmod 000 "$DROPIN"
chown -R nobody ${ROOT}/usr/local/etc/unbound.opnsense.d; chown root "$DROPIN"
chmod 644 ${ROOT}/conf/config.xml
su nobody -s /bin/sh -c "php $SRC" > ${ROOT}/out.txt 2>&1; rc=$?
check "exit" 2 "$rc"
check "refused, not deleted" yes "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "content intact" "OPERATOR-STATE" "$(cat "$DROPIN")"
check "names the reason" yes "$(grep -q 'exists but could not be read' ${ROOT}/out.txt && echo yes || echo no)"
chmod 644 "$DROPIN"

fi
echo "== 18. empty pre-existing drop-in is restored, never unlinked =="
setup; : > "$DROPIN"; echo 1 > ${ROOT}/configctl.rc
rc=$(run); check "exit" 4 "$rc"
check "file still exists" yes "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "restored empty" 0 "$(wc -c < "$DROPIN" | tr -d ' ')"

echo "== 19. symlink at the drop-in path: warned, target never modified =="
setup; printf 'TARGET-CONTENT\n' > ${ROOT}/link-target.conf
ln -s ${ROOT}/link-target.conf "$DROPIN"
rc=$(run); check "exit" 6 "$rc"
check "symlink warned" yes "$(grep -q 'is a symlink' ${ROOT}/out.txt && echo yes || echo no)"
check "link target untouched" "TARGET-CONTENT" "$(cat ${ROOT}/link-target.conf)"
check "path is now a regular file" yes "$([ -f "$DROPIN" ] && [ ! -L "$DROPIN" ] && echo yes || echo no)"
rm -f ${ROOT}/link-target.conf

echo "== 20. no symlink -> no warning (negative control) =="
setup; run >/dev/null
check "no symlink warning" no "$(grep -q 'is a symlink' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 21. self-referential forward (loop) -> recommend static, not skip =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-addr: 127.0.0.1\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 6 "$rc"
check "named as a loop" yes "$(grep -q 'points back at this firewall' ${ROOT}/out.txt && echo yes || echo no)"
check "recommendation issued" yes "$(grep -q 'ACTION REQUIRED' ${ROOT}/out.txt && echo yes || echo no)"
check "not treated as split-horizon" no "$(grep -q 'NOT recommending static' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 22. mixed forward: any NON-local address wins -> skip =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-addr: 127.0.0.1\n  forward-addr: 192.0.2.10@853\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 0 "$rc"
check "NON-local skip" yes "$(grep -q 'NON-local resolver' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 23. forward stanza with no readable address -> conservative skip =="
setup; printf 'forward-zone:\n  name: "corp.example"\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 0 "$rc"
check "conservative skip" yes "$(grep -q 'no address this applier could read' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 24. view: clause -> caveat, scan declared incomplete =="
setup; printf 'view:\n  name: "internal"\n  local-zone: "corp.example." transparent\n  forward-zone:\n    name: "corp.example."\n    forward-addr: 192.0.2.53\n' > ${ROOT}/var/unbound/view.conf
rc=$(run); check "exit" 6 "$rc"
check "view warned" yes "$(grep -q 'per-view overrides are outside' ${ROOT}/out.txt && echo yes || echo no)"
check "caveat in recommendation" yes "$(grep -q 'view: clause exists in' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 25. operator-set zone type -> left untouched, no recommendation =="
setup; sed -i 's/^corp.example. transparent$/corp.example. refuse/' ${ROOT}/zones.txt
rc=$(run); check "exit" 0 "$rc"
check "operator choice respected" yes "$(grep -q 'operator-set, neither the default' ${ROOT}/out.txt && echo yes || echo no)"
check "no recommendation" no "$(grep -q 'ACTION REQUIRED' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 26. builtin sentinels: service.arpa./localhost. now checked =="
setup; sed -i '/^service.arpa. static$/d' ${ROOT}/zones.txt; run >/dev/null
check "service.arpa WARN" yes "$(grep -q "builtin default zone 'service.arpa.' NOT" ${ROOT}/out.txt && echo yes || echo no)"
setup; run >/dev/null
check "silent when all present" no "$(grep -q 'builtin default zone' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 27. forward-host: localhost -> circular, recommend static =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-host: localhost\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 6 "$rc"
check "named circular" yes "$(grep -q 'cannot reach a working resolver' ${ROOT}/out.txt && echo yes || echo no)"
check "not called non-local" no "$(grep -q 'NON-local resolver' ${ROOT}/out.txt && echo yes || echo no)"
check "recommendation issued" yes "$(grep -q 'ACTION REQUIRED' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 28. forward-host under the forwarded zone -> circular per unbound docs =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-host: ns1.corp.example\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 6 "$rc"
check "named circular" yes "$(grep -q 'cannot reach a working resolver' ${ROOT}/out.txt && echo yes || echo no)"
check "mentions forward-first fallback" yes "$(grep -q 'forward-first' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 29. unclassifiable hostname -> UNKNOWN, never asserted as a real forward =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-host: dns.example.net\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 0 "$rc"
check "declared UNKNOWN" yes "$(grep -q 'UNKNOWN, not "a real forward"' ${ROOT}/out.txt && echo yes || echo no)"
check "not asserted non-local" no "$(grep -q 'a NON-local resolver' ${ROOT}/out.txt && echo yes || echo no)"
check "no recommendation" no "$(grep -q 'ACTION REQUIRED' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 30. lookalike domain must NOT read as a subdomain of the zone =="
setup; printf 'forward-zone:\n  name: "corp.example"\n  forward-host: ns.notcorp.example\n' > ${ROOT}/var/unbound/fwd.conf
rc=$(run); check "exit" 0 "$rc"
check "treated as UNKNOWN, not circular" yes "$(grep -q 'UNKNOWN' ${ROOT}/out.txt && echo yes || echo no)"
check "not called circular" no "$(grep -q 'cannot reach a working resolver' ${ROOT}/out.txt && echo yes || echo no)"

echo "== 10. no stray temp files left in the drop-in dir =="
check "temp files" 0 "$(find ${ROOT}/usr/local/etc/unbound.opnsense.d -name '.suru-localzones-*' | wc -l | tr -d ' ')"


echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
