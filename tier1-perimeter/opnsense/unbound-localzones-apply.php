<?php
/**
 * SURU Tier 1 — unbound local-zones applier for OPNsense
 *
 * OPNsense counterpart of pfsense/unbound-localzones-apply.php. Same
 * platform default: local namespaces are answered locally by
 * the resolver — never forwarded upstream — and the system domain must not
 * leak or loop through the upstream forwarder.
 *
 * Zones written (leg A — fully automated):
 *   local-zone: "local." always_nxdomain                   (RFC 6762 — mDNS namespace)
 *   local-zone: "alt."   always_nxdomain                   (RFC 9476 — non-DNS namespace)
 *   local-zone: "wpad.<system domain>."   always_nxdomain  (WPAD hijack guard)
 *   local-zone: "isatap.<system domain>." always_nxdomain  (ISATAP hijack guard)
 * The <system domain> is read from THIS firewall's /conf/config.xml
 * (<system><domain>) — never hardcoded. Only these zones are added; unbound
 * ships built-in defaults for the other IANA special-use names (invalid,
 * localhost, onion, home.arpa, resolver.arpa, service.arpa, test, RFC 6303
 * reverse zones) — re-verified at runtime below rather than assumed, since
 * the OPNsense unbound build has not been live-audited the way the pfSense
 * one was.
 *
 * Mechanism (differs from pfSense): OPNsense's sanctioned custom-unbound
 * surface is the DROP-IN DIRECTORY /usr/local/etc/unbound.opnsense.d/ —
 * *.conf files there are included into the generated configuration on
 * every unbound (re)start. This applier owns ONE whole file
 * (suru-localzones.conf) instead of a sentinel block inside a shared
 * textarea, so no merge/strip logic is needed and operator drop-ins are
 * never touched. Written atomically (tmp + rename).
 *
 * Leg B — system-domain local zone type (ASSISTED, deliberately not
 * auto-written): pfSense's applier converges the native
 * system_domain_local_zone_type field; OPNsense keeps the equivalent
 * setting in its Unbound MVC model, whose config path has NOT been
 * verified against a live OPNsense install. Blind-writing an unverified
 * model path risks taking the resolver down. (A duplicate `local-zone:`
 * for an already-declared zone is NOT fatal — unbound accepts it with a
 * warning and last-declaration-wins, include-order-dependent semantics —
 * but that unpredictability is reason enough to avoid it.) So this leg is
 * EVIDENCE-DRIVEN instead:
 *   1. Read the LIVE zone list (unbound-control list_local_zones) and
 *      report the system domain's current zone type.
 *   2. Inspect the LIVE generated config tree for a forward-zone /
 *      stub-zone covering the system domain (split-horizon guard — a
 *      static zone would shadow a legitimate internal-DNS forward). A
 *      forward pointing at THIS firewall is the opposite case: a resolution
 *      loop that static fixes, so its addresses are canonicalized and
 *      compared against the firewall's own before the guard decides. A
 *      forward-host naming the zone itself or a name under it is circular by
 *      unbound's own definition and counts as the same loop; a hostname that
 *      cannot be classified without resolving it is reported UNKNOWN rather
 *      than asserted to be a real forward. A
 *      `view:` clause anywhere in the scanned config makes the scan
 *      incomplete by construction (per-view zone tables are invisible to
 *      both the file scan and the live zone list) and is reported as such.
 *      A zone type the operator set to something other than the default or
 *      static is left alone, never argued with.
 *   3. When static is desired, safe (no non-local forward), and absent:
 *      exit non-zero with the exact GUI step (Services > Unbound DNS >
 *      General > "Local Zone Type" -> static) so the gap is loud, never
 *      silent. When a legitimate forward exists, or the operator opted
 *      out (--no-system-domain-static), the skip is reported as such.
 * First live run on an OPNsense box upgrades this leg from assisted to
 * automated once the model path is captured from that box.
 *
 * Runtime assumption probes (this applier has never run on a live
 * OPNsense box — every platform assumption is probed, with a named
 * failure, before anything is written):
 *   - /conf/config.xml readable + <system><domain> present   (exit 2)
 *   - /usr/local/etc/unbound.opnsense.d/ exists              (exit 2)
 *   - configctl present                                       (exit 2)
 *   - unbound-control reachable for read-back; the generated config dir
 *     for the forward-zone scan (exit 7 when read-back is impossible —
 *     the zones may be live but UNVERIFIED; never reported as success)
 *
 * Safety rails (mirrors the pfSense applier):
 *   - system domain in/under .local -> skip the "local." zone (WARN).
 *   - domain must be DNS-shaped (same RFC 1035-ish charset gate) before
 *     any domain-derived zone is written (CWE-20/74).
 *   - idempotent: identical drop-in content + zones live -> no write, no
 *     service churn, exit 0.
 *   - self-rollback: the drop-in lives outside config.xml, so the deploy
 *     driver's config.xml revert cannot undo it. Every post-write failure
 *     (restart non-zero, zones absent from the live list) restores the
 *     pre-run file — or removes it when there was none — and restarts
 *     unbound, so a rejected drop-in never survives to break the next start.
 *   - single-writer assumption: the drop-in path is read once and written
 *     once, with no lock between. A concurrent writer racing that gap could
 *     have its file treated as absent (and removed by a later rollback). The
 *     directory is root-owned and this applier is the only thing that manages
 *     this file, so the race needs privileges that already own the resolver
 *     config; it is documented rather than locked against.
 *   - the split-horizon scan reports whether it could run: zero config files
 *     matched is UNKNOWN, carried into the exit-6 recommendation, never
 *     silently read as "no conflicting forward zone".
 *
 * Usage (run on the firewall as root):
 *   php unbound-localzones-apply.php [--no-system-domain-static]
 * Exit codes: 0 ok/converged; 2 refused before writing (named — a platform
 *   assumption failed, or an existing drop-in could not be read safely;
 *   nothing written, any existing drop-in untouched);
 *   3 the zones are missing from the live list but this run wrote nothing —
 *   pre-existing drift, so there is nothing to roll back and nothing for the
 *   deploy's config.xml revert to undo;
 *   4 post-write failure: the
 *   unbound restart returned non-zero, or the zones are missing from the live
 *   zone list after apply, and the rollback put the resolver back on its
 *   pre-run configuration (the left-in-place case is exit 3, above);
 *   5 as 4, but the ROLLBACK ITSELF failed — the resolver may be down and the
 *   drop-in may hold restored content; never delete it blindly;
 *   6 system-domain static desired+safe but not configured (operator GUI
 *   action needed);
 *   7 read-back impossible (unbound-control unreachable) — applied but
 *   UNVERIFIED.
 */

const SURU_DROPIN_DIR  = '/usr/local/etc/unbound.opnsense.d';
const SURU_DROPIN_FILE = SURU_DROPIN_DIR . '/suru-localzones.conf';
const OPN_CONFIG_XML   = '/conf/config.xml';

function suru_lz_log($msg) { echo "[unbound-localzones] {$msg}\n"; }
// Console-log sanitizer for config-sourced values (CWE-117 — same rationale
// as the pfSense applier's suru_lz_safe).
function suru_lz_safe($s) { return preg_replace('/[^\x20-\x7e]/', '?', (string)$s); }

/* ---- args ------------------------------------------------------------------ */
$want_sysdomain_static = true;
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--no-system-domain-static') { $want_sysdomain_static = false; }
}

/* ---- platform assumption probes -------------------------------------------- */
if (!is_readable(OPN_CONFIG_XML)) {
    suru_lz_log('ERROR: ' . OPN_CONFIG_XML . ' not readable — is this an OPNsense box (run as root)?');
    exit(2);
}
$cfg = @simplexml_load_file(OPN_CONFIG_XML);
if ($cfg === false || !isset($cfg->system->domain)) {
    suru_lz_log('ERROR: cannot parse <system><domain> from ' . OPN_CONFIG_XML . ' — refusing to derive zones.');
    exit(2);
}
if (!is_dir(SURU_DROPIN_DIR)) {
    suru_lz_log('ERROR: drop-in dir ' . SURU_DROPIN_DIR . ' missing — this OPNsense version may not support unbound.opnsense.d includes; investigate before applying.');
    exit(2);
}
$configctl = trim((string)shell_exec('command -v configctl 2>/dev/null'));
if ($configctl === '') {
    suru_lz_log('ERROR: configctl not found — cannot reload unbound; is this OPNsense?');
    exit(2);
}

/* ---- desired drop-in content ----------------------------------------------- */
$system_domain = strtolower(trim((string)$cfg->system->domain));
// Same DNS-shaped input gate as the pfSense applier (CWE-20/74): the domain
// reaches written resolver config.
$domain_dns_shaped = ($system_domain !== '' && preg_match('/^[a-z0-9.-]+$/', $system_domain) === 1);
$sysdomain_is_dotlocal = ($system_domain !== '' && preg_match('/(^|\.)local\.?$/', $system_domain) === 1);

$zones = [];
if ($sysdomain_is_dotlocal) {
    suru_lz_log("WARN: system domain '" . suru_lz_safe($system_domain) . "' is or ends in .local — skipping the 'local.' zone (it would break local name resolution). Fix the system domain, then re-deploy.");
} else {
    $zones[] = 'local-zone: "local." always_nxdomain';
}
$zones[] = 'local-zone: "alt." always_nxdomain';
if ($domain_dns_shaped) {
    $zones[] = 'local-zone: "wpad.' . $system_domain . '." always_nxdomain';
    $zones[] = 'local-zone: "isatap.' . $system_domain . '." always_nxdomain';
} else {
    suru_lz_log("WARN: system domain empty or non-DNS characters ('" . suru_lz_safe($system_domain) . "') — skipping the wpad/isatap zones.");
}

$dropin = "# SURU-managed — local-DNS hygiene. Do not edit; regenerated on deploy.\n"
        . "server:\n"
        . implode("\n", $zones) . "\n";

/* ---- write drop-in (atomic, idempotent) ------------------------------------ */
// Atomic replace (tmp + rename): unbound may read the include at any moment,
// and a half-written file is a fatal parse error. Shared by the apply path and
// the rollback below.
function suru_lz_write_atomic($content) {
    $tmp = tempnam(SURU_DROPIN_DIR, '.suru-localzones-');
    if ($tmp === false) {
        suru_lz_log('ERROR: could not create a temp file in ' . SURU_DROPIN_DIR);
        return false;
    }
    if (file_put_contents($tmp, $content) === false) {
        @unlink($tmp);
        suru_lz_log('ERROR: write failed: ' . $tmp);
        return false;
    }
    // tempnam() creates the file 0600; the include must be readable by whatever
    // user unbound reads its config as. A failed chmod is not fatal (the zone
    // read-back below catches a config unbound could not load), but it must not
    // be silent — an unreadable include is otherwise a puzzling zones-missing.
    if (!@chmod($tmp, 0644)) {
        $GLOBALS['suru_lz_chmod_failed'] = true;
        suru_lz_log('WARN: could not chmod 0644 ' . $tmp . ' — the drop-in may stay 0600 and unreadable to unbound.');
    }
    if (!rename($tmp, SURU_DROPIN_FILE)) {
        @unlink($tmp);
        suru_lz_log('ERROR: rename failed: ' . $tmp . ' -> ' . SURU_DROPIN_FILE);
        return false;
    }
    return true;
}

// Undo this run's drop-in change and put the resolver back on the configuration
// it had before. This file lives OUTSIDE config.xml, so the deploy driver's
// config.xml revert cannot restore it: a drop-in that unbound refuses would
// otherwise survive the "revert" and break every subsequent (re)start until an
// operator removed it by hand. $previous is the pre-run content, or false when
// no drop-in existed.
function suru_lz_rollback($previous) {
    if ($previous === false) {
        if (!@unlink(SURU_DROPIN_FILE)) {
            suru_lz_log('CRITICAL: rollback could not remove ' . SURU_DROPIN_FILE
                      . ' — remove it manually, then: configctl unbound restart');
            return false;
        }
        suru_lz_log('Rollback: removed ' . SURU_DROPIN_FILE . ' (no drop-in existed before this run).');
    } else {
        if (!suru_lz_write_atomic($previous)) {
            suru_lz_log('CRITICAL: rollback could not restore the previous ' . SURU_DROPIN_FILE
                      . ' — restore or remove it manually, then: configctl unbound restart');
            return false;
        }
        suru_lz_log('Rollback: restored the pre-run ' . SURU_DROPIN_FILE . '.');
    }
    $rc = 0; $lines = [];
    exec('configctl unbound restart 2>&1', $lines, $rc);
    foreach ($lines as $l) { suru_lz_log('configctl(rollback): ' . suru_lz_safe($l)); }
    if ($rc !== 0) {
        suru_lz_log('CRITICAL: unbound did not restart after rollback (rc=' . $rc
                  . ') — the resolver may be down. Recover manually: configctl unbound restart');
        return false;
    }
    suru_lz_log('Rollback complete: unbound restarted on the pre-run configuration.');
    return true;
}

// Absent and unreadable must not collapse into the same value: rollback reads
// `false` as "there was no drop-in" and unlinks. A file that exists but cannot
// be read would then be deleted rather than restored, so refuse the run instead
// — nothing is written, and rc 2 already means "existing drop-in untouched".
$had_dropin = file_exists(SURU_DROPIN_FILE);
$existing   = $had_dropin ? @file_get_contents(SURU_DROPIN_FILE) : false;
if ($had_dropin && $existing === false) {
    suru_lz_log('ERROR: ' . SURU_DROPIN_FILE . ' exists but could not be read — refusing to write,'
              . ' since a rollback could not restore it. Check its permissions and re-run.');
    exit(2);
}
if (is_link(SURU_DROPIN_FILE)) {
    // rename() replaces the link's own directory entry, so the target file is
    // never written through — but the link does not survive, and a rollback
    // would restore a copy of its content rather than the link. Not silently.
    suru_lz_log('WARN: ' . SURU_DROPIN_FILE . ' is a symlink — it will be replaced by a regular'
              . ' file (the link target itself is never modified).');
}
$dropin_changed = ($existing === false || $existing !== $dropin);
if ($dropin_changed) {
    if (!suru_lz_write_atomic($dropin)) { exit(2); }
    suru_lz_log('Drop-in written: ' . SURU_DROPIN_FILE . ' (' . count($zones) . ' zone(s)).');
} else {
    suru_lz_log('Drop-in already at target content.');
}

// Canonicalize an address for comparison: lowercase, %scope stripped, and round
// tripped through inet_pton so IPv6 textual variants compare equal.
function suru_lz_canon_ip($s) {
    $s = strtolower(trim((string)$s));
    $s = preg_replace('/%.*$/', '', $s);
    $bin = @inet_pton($s);
    return ($bin !== false) ? inet_ntop($bin) : $s;
}

function suru_lz_is_ip($s) { return @inet_pton((string)$s) !== false; }

// A forward-host/stub-host value that cannot work as a forward target for this
// zone, without resolving anything to find out. unbound.conf(5) (FORWARD ZONE
// OPTIONS, forward-host) warns that naming the zone itself or a subdomain of it
// "will unavoidably introduce a circular dependency" on resolving the target —
// which is the loop shape, whether or not the name happens to be this firewall.
// "localhost" is unbound's own built-in special-use name, resolving here by
// definition.
function suru_lz_is_circular_host($name, $zone) {
    $n = rtrim(strtolower(trim((string)$name)), '.');
    if ($n === 'localhost') { return true; }
    $z = rtrim(strtolower(trim((string)$zone)), '.');
    if ($z === '' || $n === '') { return false; }
    if ($n === $z) { return true; }
    $suffix = '.' . $z;
    return strlen($n) > strlen($suffix) && substr($n, -strlen($suffix)) === $suffix;
}

// This firewall's own addresses, for telling a self-referential forward apart
// from a forward to a real other resolver.
function suru_lz_local_addresses() {
    $ips = ['127.0.0.1', '::1'];
    $out = [];
    exec('/sbin/ifconfig -a 2>/dev/null', $out);
    foreach ($out as $l) {
        if (preg_match('/\binet6?\s+([0-9a-fA-F:.%]+)/i', $l, $m)) {
            $ips[] = suru_lz_canon_ip($m[1]);
        }
    }
    return array_values(array_unique($ips));
}

/* ---- live zone list (single read-back source for both legs) ---------------- */
function suru_lz_live_zones() {
    // Preferred: unbound-control against OPNsense's unbound. Probe the two
    // plausible invocations rather than assuming either; both failing means
    // read-back is impossible (exit 7 at the call sites), not "assume ok".
    foreach (['/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf list_local_zones',
              '/usr/local/sbin/unbound-control list_local_zones'] as $cmd) {
        $out = @shell_exec($cmd . ' 2>/dev/null');
        if (is_string($out) && trim($out) !== '') { return $out; }
    }
    return false;
}

if ($dropin_changed) {
    suru_lz_log('Reloading unbound (configctl unbound restart)...');
    $rc = 0; $lines = [];
    exec('configctl unbound restart 2>&1', $lines, $rc);
    foreach ($lines as $l) { suru_lz_log('configctl: ' . suru_lz_safe($l)); }
    if ($rc !== 0) {
        suru_lz_log('ERROR: configctl unbound restart exited ' . $rc . ' — rolling the drop-in back.');
        // 4 vs 5 carries the rollback's own outcome, so tooling checking only
        // the exit status can tell "healed" from "resolver may still be down"
        // without parsing log text.
        exit(suru_lz_rollback($existing) ? 4 : 5);
    }
}

$live = suru_lz_live_zones();
if ($live === false) {
    suru_lz_log('ERROR: unbound-control unreachable — zones applied but UNVERIFIED. Verify manually: unbound-control list_local_zones, then dig a .local name (expect aa NXDOMAIN, AUTHORITY:0).');
    exit(7);
}

/* ---- leg A read-back: SURU zones present ------------------------------------ */
foreach ($zones as $z) {
    // 'local-zone: "local." always_nxdomain' -> list form 'local. always_nxdomain'
    if (!preg_match('/^local-zone: "([^"]+)" (\S+)$/', $z, $m)) { continue; }
    // Line-anchored, like the system-domain lookup below: a bare substring test
    // would accept a longer zone name ending in the one we asked for
    // ('cobalt. always_nxdomain' satisfying a search for 'alt. always_nxdomain'),
    // and this check is the gate that decides whether to roll back.
    if (!preg_match('/^' . preg_quote($m[1], '/') . '\s+' . preg_quote($m[2], '/') . '$/mi', $live)) {
        suru_lz_log('ERROR: zone missing from live zone list after apply: ' . $m[1] . ' ' . $m[2]);
        if (!empty($GLOBALS['suru_lz_chmod_failed'])) {
            // Don't make the operator connect a WARN many lines earlier to this
            // error: an unreadable include presents exactly as a missing zone.
            suru_lz_log('  Likely cause: the chmod WARN above — a 0600 drop-in is unreadable to a'
                      . ' non-root unbound, which presents as the zone never being loaded.');
        }
        // Only this run's own change is undone; an unchanged drop-in that the
        // resolver never loaded is an operator/platform question, not ours to
        // delete.
        if ($dropin_changed) {
            if (!suru_lz_rollback($existing)) { exit(5); }
            exit(4);
        }
        // Nothing was written this run: nothing to roll back, and nothing in
        // config.xml for the deploy's revert to undo either. Reverting the other
        // stages over pre-existing drift would be collateral damage, so this is
        // its own exit code rather than 4.
        suru_lz_log('Drop-in was already at target content and is left in place — this run wrote'
                  . ' nothing to undo. The file exists but the resolver is not serving its zones:'
                  . ' check that unbound restarted, and that ' . SURU_DROPIN_DIR
                  . ' is actually included by the generated configuration.');
        exit(3);
    }
}
suru_lz_log('Verified: ' . count($zones) . ' SURU zone(s) present in the live zone list.');

/* ---- builtin special-use defaults: re-verify, don't assume */
foreach (['home.arpa.', 'resolver.arpa.', 'service.arpa.', 'localhost.',
          'onion.', 'test.', 'invalid.'] as $builtin) {
    // Anchored for the same reason as the read-back above, though this one only
    // gates a WARN.
    if (!preg_match('/^' . preg_quote($builtin, '/') . '\s/mi', $live)) {
        suru_lz_log("WARN: unbound builtin default zone '{$builtin}' NOT in the live zone list — this OPNsense unbound build diverges from the assumption the SURU zone set rests on; consider adding it to the drop-in.");
    }
}

/* ---- leg B: system-domain zone type (evidence-driven, no blind write) ------- */
if (!$domain_dns_shaped || $sysdomain_is_dotlocal) {
    suru_lz_log('System-domain static: out of scope (domain empty, non-DNS-shaped, or .local) — leaving resolver defaults untouched.');
    exit(0);
}
$sd_dot = $system_domain . '.';
$sys_type = '';
foreach (preg_split('/\R/', $live) as $line) {
    $parts = preg_split('/\s+/', trim($line));
    if (count($parts) === 2 && strcasecmp($parts[0], $sd_dot) === 0) { $sys_type = $parts[1]; break; }
}
suru_lz_log("System domain '" . suru_lz_safe($system_domain) . "' live zone type: " . ($sys_type !== '' ? suru_lz_safe($sys_type) : '(none listed)') . '.');

// Opt-out short-circuits here: the live zone type above is the whole point of
// leg B's reporting, and everything below only feeds a recommendation the
// operator has declined. Scanning for it anyway is work whose result is
// discarded on every deploy.
if (!$want_sysdomain_static) {
    suru_lz_log('System-domain static: operator opt-out (--no-system-domain-static) — reported only, nothing to do.');
    exit(0);
}

// Split-horizon guard: a forward/stub zone for the system domain in the LIVE
// generated config means static would shadow a real internal-DNS forward.
// The generated tree's location is a platform assumption like every other one
// here, so the scan reports whether it could actually RUN: zero files matched is
// UNKNOWN, never "no conflict found" (the read-back path has exit 7 for the same
// distinction). Several plausible locations are swept — for a guard, a
// false negative is the expensive direction.
$gen_globs  = ['/var/unbound/*.conf', '/var/unbound/etc/*.conf'];
$gen_files  = [];
foreach ($gen_globs as $g) { $gen_files = array_merge($gen_files, glob($g) ?: []); }
// Operator drop-ins are scanned too (a forward-zone there is just as real), but
// they do NOT count as evidence the generated tree was found — this applier's
// own file would otherwise always satisfy the check.
$scan_files = array_unique(array_merge($gen_files, glob(SURU_DROPIN_DIR . '/*.conf') ?: []));
$scan_caveat = '';
if (!$gen_files) {
    $scan_caveat = ' Split-horizon scan incomplete: the generated unbound config tree was not'
                 . ' found (' . implode(', ', $gen_globs) . ') — confirm no forward/stub zone'
                 . ' covers the system domain before applying.';
    suru_lz_log('WARN: generated unbound config tree not found (' . implode(', ', $gen_globs)
              . ') — split-horizon state UNKNOWN, not "no conflict"; scanning '
              . count($scan_files) . ' drop-in file(s) only.');
} else {
    suru_lz_log('Split-horizon scan: ' . count($scan_files) . ' unbound config file(s) inspected.');
}

$scan_contents = [];
foreach ($scan_files as $f) {
    $c = @file_get_contents($f);
    if ($c !== false) { $scan_contents[$f] = $c; }
}

// A `view:` clause carries its OWN local-zone/forward-zone table. It is invisible
// both to this scan (nested directives stay grouped under the `view:` stanza
// header, so they never start a forward-zone stanza) and to
// `unbound-control list_local_zones`, which reports the GLOBAL table only. Say so
// rather than reporting a clean scan over config this scan structurally cannot
// read.
foreach ($scan_contents as $f => $c) {
    if (preg_match('/^\s*view:\s*$/mi', $c)) {
        $scan_caveat .= ' A view: clause exists in ' . suru_lz_safe($f) . ' — per-view'
                      . ' local-zone/forward-zone overrides are not visible to this scan or to'
                      . ' the live zone list; confirm no view maps a different policy for the'
                      . ' system domain.';
        suru_lz_log('WARN: view: clause in ' . suru_lz_safe($f)
                  . ' — per-view overrides are outside what this scan and the live zone list can see.');
        break;
    }
}

$fwd_hit = '';
$fwd_stanza = '';
foreach ($scan_contents as $f => $c) {
    // Split into unbound clause stanzas (a clause header is a line that is
    // exactly `word:`), then require the name match INSIDE a forward-zone/
    // stub-zone stanza — an auth-zone/view naming the domain, or an
    // unrelated forward-zone elsewhere in the file, must not count.
    foreach (preg_split('/^(?=[a-z0-9-]+:\s*$)/mi', $c) as $stanza) {
        if (!preg_match('/^\s*(forward-zone|stub-zone):/i', $stanza)) { continue; }
        if (preg_match('/^\s*name:\s*"?' . preg_quote($system_domain, '/') . '\.?"?\s*$/mi', $stanza)) {
            $fwd_hit = $f;
            $fwd_stanza = $stanza;
            break 2;
        }
    }
}

if ($fwd_hit !== '') {
    // A forward for the system domain is two very different situations, and the
    // one that motivated this whole default is the one a bare "a forward exists"
    // WARN gets wrong: a forward pointing at THIS firewall is a self-loop that
    // resolves to SERVFAIL, and static is precisely what fixes it. Only a forward
    // to a real other resolver is shadowed by static. Same distinction the
    // pfSense applier draws over domainoverrides, ported to config-file stanzas.
    $fwd_addrs = [];
    if (preg_match_all('/^\s*(?:forward-addr|forward-host|stub-addr|stub-host):\s*(\S+)/mi', $fwd_stanza, $fm)) {
        $fwd_addrs = $fm[1];
    }
    $local_ips = suru_lz_local_addresses();
    $nonlocal  = '';   // a real other resolver, by address — static would shadow it
    $unknown   = '';   // a hostname this cannot classify without resolving it
    foreach ($fwd_addrs as $a) {
        // Strip unbound's @port / #tls-hostname decoration, then canonicalize so
        // IPv6 textual variants and %scope suffixes cannot disguise a self-loop.
        $bare = suru_lz_canon_ip(preg_replace('/[@#].*$/', '', $a));
        if (suru_lz_is_ip($bare)) {
            if (!in_array($bare, $local_ips, true)) { $nonlocal = $a; break; }
            continue;
        }
        // Not an address: circular by the zone's own definition, or a name whose
        // target is simply unknown from here. Guessing "real forward" for the
        // latter would state something this cannot know.
        if (!suru_lz_is_circular_host($bare, $system_domain)) { $unknown = $a; }
    }
    if (!$fwd_addrs) {
        suru_lz_log('WARN: a forward/stub zone for the system domain exists in the live config ('
                  . suru_lz_safe($fwd_hit) . ') with no address this applier could read — NOT'
                  . ' recommending static, since it may shadow a real forward. Inspect that stanza.');
        exit(0);
    }
    if ($nonlocal !== '') {
        suru_lz_log('WARN: a forward/stub zone for the system domain exists in the live config ('
                  . suru_lz_safe($fwd_hit) . ') pointing at ' . suru_lz_safe($nonlocal)
                  . ', a NON-local resolver — NOT recommending static (it would shadow that'
                  . ' forward). Set SURU_UNBOUND_SYSTEM_DOMAIN_STATIC=false to make this skip'
                  . ' the default.');
        exit(0);
    }
    if ($unknown !== '') {
        suru_lz_log('WARN: a forward/stub zone for the system domain exists in the live config ('
                  . suru_lz_safe($fwd_hit) . ') pointing at the hostname '
                  . suru_lz_safe($unknown) . '. Whether that resolves back to this firewall'
                  . ' cannot be determined without resolving it, which would query the resolver'
                  . ' under audit — UNKNOWN, not "a real forward". NOT recommending static;'
                  . ' check that target by hand.');
        exit(0);
    }
    suru_lz_log('Forward/stub zone for the system domain in ' . suru_lz_safe($fwd_hit)
              . ' cannot reach a working resolver (' . suru_lz_safe(implode(', ', $fwd_addrs))
              . ') — it points back at this firewall, or names the zone it is forwarding, which'
              . ' is circular either way. A resolution loop, not a split-horizon forward: static'
              . ' answers the domain locally and makes that stanza inert; removing the stanza is'
              . ' the tidier fix. (A circular forward-host with forward-first: yes has a'
              . ' documented fallback and may be deliberate.)');
    // fall through to the recommendation
}
if (strcasecmp($sys_type, 'static') === 0) {
    suru_lz_log('Verified: system domain is a static local-zone (answered locally, never forwarded).');
    exit(0);
}
if ($sys_type !== '' && strcasecmp($sys_type, 'transparent') !== 0) {
    // Operator-set, neither unbound's default (transparent) nor SURU's target
    // (static): their call, and this applier never argues with it. Same
    // operator-choice principle the pfSense applier applies to the equivalent
    // field.
    suru_lz_log("System domain local zone type is '" . suru_lz_safe($sys_type)
              . "' — operator-set, neither the default (transparent) nor static. Left untouched,"
              . ' no recommendation.');
    exit(0);
}
suru_lz_log('ACTION REQUIRED: system domain is not static (live type: ' . ($sys_type !== '' ? suru_lz_safe($sys_type) : 'unbound default') . '). Set it in the GUI: Services > Unbound DNS > General > "Local Zone Type" -> static, apply, then re-run this applier to verify.' . $scan_caveat . ' (Not auto-written: the OPNsense Unbound model path is unverified on a live box — first verified run may upgrade this to an automated write.)');
exit(6);
