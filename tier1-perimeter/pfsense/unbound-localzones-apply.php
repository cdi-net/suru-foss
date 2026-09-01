<?php
/**
 * SURU Tier 1 — unbound local-zones applier for pfSense (local-DNS hygiene default)
 *
 * Platform default: local namespaces must be answered locally by the
 * resolver — never forwarded upstream. Live evidence (2026-08-30):
 *   - `.local` queries leaked to the public root servers (NXDOMAIN with the
 *     DNSSEC ad flag — i.e. answered upstream), leaking LAN hostnames and
 *     mDNS service names off-box (RFC 6762 forbids unicast .local).
 *   - `wpad.<system domain>` traversed the system domain's `transparent`
 *     local-zone toward the PUBLIC parent zone — whoever controls the
 *     public DNS of the system domain could answer WPAD and hijack client
 *     proxy configuration (16,421 wpad queries observed in 30d).
 *
 * Mechanism: manages a SURU sentinel block inside the DNS Resolver's
 * "Custom options" (config.xml `unbound/custom_options`, base64-encoded —
 * pfSense injects the decoded text verbatim into unbound.conf). Operator
 * content outside the sentinel block is NEVER touched (same
 * preserve-operator-content contract as suricata-policy-apply.php's
 * customrules sentinel).
 *
 * Zones written (SURU-LOCALZONES-BEGIN/END block, unbound custom options).
 * The <system domain> is read from THIS router's config (system/domain) — never
 * hardcoded — so the same code hardens whatever domain a deployment uses:
 *   local-zone: "local." always_nxdomain                   (RFC 6762 — mDNS namespace)
 *   local-zone: "alt."   always_nxdomain                   (RFC 9476 — non-DNS namespace)
 *   local-zone: "wpad.<system domain>."   always_nxdomain  (WPAD hijack guard)
 *   local-zone: "isatap.<system domain>." always_nxdomain  (ISATAP hijack guard — WPAD sibling)
 * Only these are added; unbound already ships defaults for the other IANA
 * special-use names (see the scope note at the zone-building code below).
 *
 * System domain (the router's configured `<system><domain>`) — made locally
 * authoritative via pfSense's NATIVE knob `unbound/system_domain_local_zone_type`
 * set to `static` (whitelisted in /etc/inc/unbound.inc unbound_local_zone_types()).
 * pfSense then emits `local-zone: "<domain>." static` into host_entries.conf, so
 * names WITH a host-override resolve (AA) and unknown names get an authoritative
 * NXDOMAIN answered LOCALLY — never forwarded to the upstream resolver. The
 * default `transparent` forwards unknown internal names off-box, which both leaks
 * internal hostnames to the upstream AND (when a self-referential domain-override
 * exists — see below) loops and returns SERVFAIL. Using the native field avoids a
 * fragile duplicate `local-zone` in custom_options fighting the one pfSense
 * auto-generates.
 *
 * Safety guard (the reason this is not unconditional): a `static` system-domain
 * zone is consulted BEFORE any forward-zone, so it SHADOWS a domain-override that
 * forwards the system domain to a real internal DNS server. Before applying
 * static we inspect any `unbound/domainoverrides` entry for the system domain:
 *   - no override, or the override points at one of THIS router's own IPs
 *     (a forward loop — the live 2026-08-31 finding: suru.local -> the router's
 *     own unbound IP -> SERVFAIL) -> apply static (fixes the leak AND the loop).
 *   - override points at a NON-local resolver (a legitimate internal-DNS forward)
 *     -> SKIP static with a WARN, so we never break split-horizon resolution.
 * Force-skip regardless via the --no-system-domain-static flag
 * (SURU_UNBOUND_SYSTEM_DOMAIN_STATIC=false in .env).
 *
 * REVERSIBLE (the guard is two-directional): for a domain SURU manages (DNS-shaped,
 * not .local) the zone-type is converged to the DESIRED value each run — `static`
 * when applying, `transparent` (pfSense's own default) when skipping. So a later
 * force-skip, or a newly-added legitimate non-local domain-override, actively
 * UNDOES a `static` set by an earlier run instead of leaving it stale. Without
 * this the "SKIP to avoid shadowing" WARN was a lie — the earlier `static` kept
 * shadowing the override (review finding). Out-of-scope domains (empty,
 * non-DNS-shaped, or .local) are left untouched — the field is not SURU's to
 * revert there, since any `static` on such a domain was a manual operator choice.
 * The same operator-choice principle applies IN scope: SURU converges only
 * between `transparent` (pfSense's default) and `static` (its own target); a
 * manually-set OTHER zone-type (refuse, redirect, always_nxdomain, ...) is
 * never overwritten — logged and left as-is (review finding).
 *
 * Safety rails:
 *   - If the system domain itself is, or ends in, ".local" (against pfSense's own
 *     guidance but seen in the field), the "local." zone is SKIPPED with a
 *     WARN — it would break the operator's own name resolution.
 *   - RFC1918 reverse zones are NOT written here: unbound's built-in
 *     locally-served-zone defaults (RFC 6303) already cover them, and this
 *     install additionally carries typetransparent zones for its configured
 *     subnets (live-read 2026-08-30).
 *
 * Live-apply chain (hard-won lesson: config.xml alone is inert):
 *   1. write_config() when the sentinel block changed.
 *   2. services_unbound_configure() to regenerate + reload unbound.
 *   3. sync_package_pfblockerng('noupdates') when pfBlockerNG is installed:
 *      step 2 regenerates unbound.conf from pfSense's own template, which
 *      knows nothing about pfBlockerNG's python module — without this call
 *      module-config degrades to "validator iterator" and DNSBL enforcement
 *      silently dies (a recurring live-incident class on pfSense).
 *   4. Read-back verification of BOTH invariants from the live
 *      /var/unbound/unbound.conf: our zones present AND (when pfBlockerNG
 *      is installed) "python" still leads module-config. Non-zero exit on
 *      either failure.
 *
 * Idempotent: identical desired block + live conf already carrying the
 * zones => no write, no service churn, exit 0.
 *
 * Usage (run on router as root): php unbound-localzones-apply.php [--no-system-domain-static]
 * Exit codes: 0 ok/converged; 1 existing unbound/custom_options unusable
 *             (invalid base64, or PCRE failure during the sentinel strip) —
 *             refuse to touch; 4 custom-options zones missing after
 *             apply; 5 module-config lost python after apply; 6 system-domain
 *             zone-type not at its desired live state after apply (static missing
 *             when applying, or still present when reverting to transparent).
 */

require_once("config.inc");
require_once("services.inc");

const SURU_LZ_BEGIN = "# SURU-LOCALZONES-BEGIN (managed - do not edit inside this block)";
const SURU_LZ_END   = "# SURU-LOCALZONES-END";
const UNBOUND_LIVE_CONF = "/var/unbound/unbound.conf";

function suru_lz_log($msg) { echo "[unbound-localzones] {$msg}\n"; }

// Render an untrusted, config-sourced value safe for a single-line console log
// (review finding — CWE-117 log injection): system/domain and a
// domain-override IP are normally constrained by pfSense's webConfigurator, but
// a directly-edited/corrupted config.xml could carry control bytes (newline, CR,
// terminal escapes) that would forge or corrupt log lines when echoed raw. Strip
// everything outside printable ASCII to a '?' before interpolating into a log
// message. A no-op on already-validated DNS-shaped values.
function suru_lz_safe($s) { return preg_replace('/[^\x20-\x7e]/', '?', (string)$s); }

// Canonicalize an IP address string for comparison (review finding — IPv6 self-loop
// match): lowercase, strip any IPv6 %scope suffix (FreeBSD ifconfig prints
// `fe80::1%igb0`; a config-stored override could carry it too), then round-trip
// through inet_pton/inet_ntop so textual variants of the same address compare
// equal (`FE80:0:0:0:0:0:0:1` ≡ `fe80::1`). Canonical binary forms are injective
// — this removes false NON-matches (a genuine self-loop misread as legit
// internal DNS) without ever creating a false match between distinct addresses.
// Non-IP strings pass through lowercased/scope-stripped (inet_pton fails → keep).
// inet_pton/inet_ntop live-verified present on the target router's PHP
// (2026-09-01: inet_ntop(inet_pton('fe80:0:0:0:0:0:0:1')) → 'fe80::1').
function suru_lz_canon_ip($s) {
    $s = strtolower(trim((string)$s));
    $s = preg_replace('/%.*$/', '', $s);
    $bin = @inet_pton($s);
    return ($bin !== false) ? inet_ntop($bin) : $s;
}

/* ---- args ------------------------------------------------------------------ */
$want_sysdomain_static = true;
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--no-system-domain-static') { $want_sysdomain_static = false; }
}

/* ---- desired sentinel block ------------------------------------------------ */
// The system domain is read from THIS router's config — never hardcoded. Every
// per-domain zone below is derived from it, so the same code hardens whatever
// domain a given deployment uses.
//
// Scope note (why this set and not more): unbound already ships local-zone
// defaults for the other IANA special-use names (invalid, localhost, onion
// [RFC 7686], home.arpa [RFC 8375], resolver.arpa [RFC 9462], service.arpa
// [RFC 9665], test [RFC 6761], and the RFC 6303/6761 reverse zones) — verified
// live via `unbound-control list_local_zones`. SURU only adds the genuine gaps:
//   - local.  (RFC 6762 mDNS) — unbound does NOT default it; leaks upstream.
//   - alt.    (RFC 9476 alternative/non-DNS namespace) — must never hit DNS.
//   - wpad.<system domain> + isatap.<system domain> — the two name-hijack
//     surfaces Microsoft's DNS Global Query Block List blocks by default
//     (rogue proxy-autodiscovery / rogue ISATAP gateway). Redundant once the
//     system domain is `static` below, but kept as defense-in-depth so they
//     still protect if system-domain-static is disabled for a split-horizon site.
// Deliberately NOT localised: example.* (documentation, meant to resolve) and
// ipv4only.arpa (RFC 8880 — has a real NAT64 function; blackholing breaks it).
$system_domain = (string) config_get_path('system/domain', '');
// Single DNS-shaped input guard for the config-sourced domain (review
// finding — CWE-20/CWE-74): the domain reaches WRITTEN resolver config (the
// wpad/isatap local-zones, and pfSense's `local-zone: "<domain>." static`
// emitted from system_domain_local_zone_type). Validate the charset ONCE and
// gate every domain-derived write on it, so a non-DNS-shaped value (newline,
// quote, space, unbound directive) can never be injected into unbound.conf.
// pfSense also validates system/domain on input — this is defence-in-depth.
$domain_dns_shaped = ($system_domain !== '' && preg_match('/^[a-z0-9.-]+$/i', $system_domain) === 1);
$zones = [];

// Is the system domain in the mDNS `.local` namespace? Matches `*.local`, the
// bare string `local` itself, and trailing-dot variants (`(^|\.)` boundary —
// a plain /\.local$/ missed bare `local`, review finding: pfSense's system.php
// only validates the domain charset via is_domain() (live-read :192-193,
// 2026-09-02) — the "don't use .local" text at :544-548 is help prose, not
// enforced — so a bare-`local` system domain is UI-reachable. Without this,
// SURU would declare local-zone "local." TWICE with conflicting types:
// always_nxdomain via custom_options AND static via the native field.
$sysdomain_is_dotlocal = ($system_domain !== '' && preg_match('/(^|\.)local\.?$/i', $system_domain) === 1);

// Global special-use names (independent of the deployment's system domain).
if ($sysdomain_is_dotlocal) {
    suru_lz_log("WARN: system domain '" . suru_lz_safe($system_domain) . "' is or ends in .local — skipping the 'local.' zone (it would break local name resolution). Fix the system domain, then re-deploy.");
} else {
    $zones[] = 'local-zone: "local." always_nxdomain';
}
$zones[] = 'local-zone: "alt." always_nxdomain';

// Per-system-domain name-hijack guards (WPAD + ISATAP), derived from this
// deployment's own domain.
if ($domain_dns_shaped) {
    $sd = strtolower($system_domain);
    $zones[] = 'local-zone: "wpad.' . $sd . '." always_nxdomain';
    $zones[] = 'local-zone: "isatap.' . $sd . '." always_nxdomain';
} else {
    suru_lz_log("WARN: system domain empty or non-DNS characters ('" . suru_lz_safe($system_domain) . "') — skipping the wpad/isatap zones.");
}

// Invariant: $zones is never empty — the 'alt.' zone above is unconditional,
// so there is no skip-all path. (A former count()===0 early-exit here was
// unreachable dead code — review finding. If a future change makes
// every zone conditional, reintroduce an empty-set guard then.)

$block = SURU_LZ_BEGIN . "\n"
       . "server:\n"
       . implode("\n", $zones) . "\n"
       . SURU_LZ_END;

/* ---- merge into custom_options (operator content preserved) ---------------- */
$existing_b64 = (string) config_get_path('unbound/custom_options', '');
// Strict decode (review finding): without $strict=true, base64_decode()
// silently DISCARDS invalid characters instead of returning false, so the
// "refuse to touch corrupted custom_options" guard below would almost never
// fire and garbage would be merged/written back. Strict mode makes the guard
// real, honouring the exit-1 contract documented in this file's header.
$existing = ($existing_b64 !== '') ? base64_decode($existing_b64, true) : '';
if ($existing_b64 !== '' && $existing === false) {
    suru_lz_log("ERROR: existing unbound/custom_options is not valid base64 — refusing to touch it.");
    exit(1);
}

// Strip-ALL-copies-then-append-one (review finding — self-healing merge): a plain
// preg_replace($pattern, $block, $existing) rewrites EVERY sentinel copy, so a
// duplicated block (interrupted prior write, hand-edit) would persist forever
// instead of collapsing to one — quietly contradicting the idempotency contract
// in this file's header. Mirrors suricata-policy-apply.php's
// suru_policy_strip_sentinel() + build pattern (the canonical sentinel merge in
// this tier). Append position is context-independent in unbound.conf because
// the block opens with its own `server:` clause header. The `(?:\n{1,2})?` /
// `\n?` fringes keep a healthy single-block layout byte-identical across runs
// (strip + re-append reproduces the same bytes -> no spurious config write).
$pattern = '/(?:\n{1,2})?' . preg_quote(SURU_LZ_BEGIN, '/') . '.*?' . preg_quote(SURU_LZ_END, '/') . '\n?/s';
$stripped = preg_replace($pattern, '', $existing);
if ($stripped === null) {
    suru_lz_log("ERROR: PCRE failure stripping the SURU sentinel block from custom_options — refusing to touch it.");
    exit(1);
}
$merged = rtrim($stripped);
$merged = ($merged === '') ? $block : $merged . "\n" . $block;

$config_changed = ($merged !== $existing);

/* ---- system domain: make it locally authoritative (static) ----------------- */
// Decide whether to set unbound/system_domain_local_zone_type=static, honouring
// the self-loop-vs-legit-internal-DNS safety guard documented in the header.
$sysdomain_changed = false;

// SURU only MANAGES the system-domain zone-type for a domain it can reason about
// safely: DNS-shaped (same CWE-20/CWE-74 input guard as the wpad/isatap zones —
// setting static makes pfSense emit `local-zone: "<domain>." static`) and not
// itself `.local` (a static `.local` would break the operator's own `.local`
// resolution). OUTSIDE that scope SURU never touches the field — neither setting
// nor reverting — because the only way it could already read `static` there is a
// manual operator choice, and clobbering that would be overreach (review
// finding — explicit design call).
$domain_in_scope = $domain_dns_shaped
    && !$sysdomain_is_dotlocal;

// Desired state for an in-scope domain: static UNLESS the operator opted out
// (--no-system-domain-static). The override-vs-loop check below may still
// downgrade it to transparent when a legitimate non-local domain-override exists.
$apply_static = $want_sysdomain_static && $domain_in_scope;

if ($want_sysdomain_static && !$domain_in_scope) {
    suru_lz_log("Skipping system-domain static (domain empty, non-DNS characters, or .local): '" . suru_lz_safe($system_domain) . "'.");
}

if ($apply_static) {
    // Is there a domain-override that forwards the system domain somewhere?
    // Array shape LIVE-VERIFIED (review finding, 2026-09-01):
    // `php -r "require('config.inc'); var_export(config_get_path('unbound/domainoverrides', []));"`
    // on the target router returns a FLAT indexed array of
    // ['domain'=>..,'ip'=>..,'descr'=>..(,'tls_hostname'=>..)] entries — no
    // 'item' sub-key nesting — so the $ov['domain']/$ov['ip'] reads below are
    // correct and the split-horizon guard actually fires.
    // Collect ALL matching entries, not just the first: pfSense's webConfigurator
    // does NOT prevent duplicate same-domain overrides (live-read
    // services_unbound_domainoverride_edit.php 2026-09-01: input validation
    // covers domain/IP/TLS-hostname syntax only — no duplicate check), so a
    // first-match-wins scan would make the guard's verdict depend on array
    // order (review finding). Policy: if ANY entry forwards to a
    // non-local resolver, skip static (never shadow a possibly-legit internal-
    // DNS forward); apply static only when every matching entry is self/loop.
    $ov_ips = [];
    $sd_key = rtrim(strtolower($system_domain), '.');
    foreach (config_get_path('unbound/domainoverrides', []) as $ov) {
        if (rtrim(strtolower((string)($ov['domain'] ?? '')), '.') === $sd_key) {
            $ip = (string)($ov['ip'] ?? '');
            if ($ip !== '') { $ov_ips[] = $ip; }
        }
    }
    if (count($ov_ips) > 0) {
        // Gather this router's own interface IPs (canonicalized) to detect a
        // self-referential (loop) forward vs a real external internal-DNS server.
        $local_ips = ['127.0.0.1', '::1'];
        $ifout = [];
        exec('/sbin/ifconfig -a 2>/dev/null', $ifout);
        foreach ($ifout as $l) {
            if (preg_match('/\binet6?\s+([0-9a-fA-F:.%a-z]+)/i', $l, $m)) { $local_ips[] = suru_lz_canon_ip($m[1]); }
        }
        foreach ($ov_ips as $ov_ip) {
            // Strip any @port / #tls-hostname decoration to get the bare
            // address, then canonicalize (lowercase, %scope-stripped,
            // inet_pton round-trip) so IPv6 textual variants / scope suffixes
            // cannot make a genuine self-loop look like a legit internal-DNS
            // forward (review finding — the miss direction would skip+revert
            // static and leave the SERVFAIL loop).
            $ov_addr = suru_lz_canon_ip(preg_replace('/[@#].*$/', '', $ov_ip));
            if (in_array($ov_addr, $local_ips, true)) {
                suru_lz_log("system-domain override '" . suru_lz_safe($system_domain) . "' -> " . suru_lz_safe($ov_ip) . " is a LOCAL/self address (forward loop → SERVFAIL). Static makes this override inert (recommend removing it).");
            } else {
                $apply_static = false;
                suru_lz_log("WARN: system-domain override '" . suru_lz_safe($system_domain) . "' -> " . suru_lz_safe($ov_ip) . " points at a NON-local resolver (internal DNS). NOT applying static — reverting any prior static below — to avoid shadowing it. Set SURU_UNBOUND_SYSTEM_DOMAIN_STATIC=false to make skip the default, or remove the override to harden.");
                break; // one legit non-local forward decides — no need to scan further
            }
        }
    }
}

// Converge the zone-type in BOTH directions for an in-scope domain so the applier
// is reversible (review finding): a later --no-system-domain-static, or a
// newly-added legitimate non-local domain-override, now actively UNDOES a `static`
// set by an earlier run. Before this the field only ever moved TO `static` and
// never back, so the WARN above ("NOT applying static ... to avoid shadowing")
// asserted a mitigation that never took effect — the stale `static` zone kept
// shadowing the override exactly as the local-DNS driver contract says it must not. `transparent` is
// pfSense's own default (restores forward-zone consultation). Out-of-scope
// domains are left untouched (see the $domain_in_scope note above).
$sysdomain_managed = $domain_in_scope;
if ($domain_in_scope) {
    $cur_type = (string) config_get_path('unbound/system_domain_local_zone_type', 'transparent');
    if ($cur_type !== 'transparent' && $cur_type !== 'static') {
        // Operator manually chose one of pfSense's OTHER valid zone-types
        // (refuse/redirect/always_*/...): that is their call — SURU converges
        // only between pfSense's default (transparent) and its own target
        // (static), never over a deliberate non-default value (review
        // finding — same operator-choice principle as out-of-scope domains).
        $sysdomain_managed = false;
        suru_lz_log("system_domain_local_zone_type is '" . suru_lz_safe($cur_type) . "' (operator-set, neither transparent nor static) — leaving it untouched.");
    } else {
        $want_type = $apply_static ? 'static' : 'transparent';
        if ($cur_type !== $want_type) {
            config_set_path('unbound/system_domain_local_zone_type', $want_type);
            $sysdomain_changed = true;
            $why = $apply_static
                ? 'system domain answered locally, never forwarded'
                : 'reverted — operator opt-out or legitimate non-local override now applies';
            // $cur_type is config-sourced (webConfigurator whitelists it, but a
            // hand-edited config.xml could not) — sanitize like every other
            // config-sourced log value. $want_type is a hardcoded literal.
            suru_lz_log("system_domain_local_zone_type: '" . suru_lz_safe($cur_type) . "' -> '{$want_type}' ({$why}).");
        } else {
            suru_lz_log("system_domain_local_zone_type already '{$want_type}'.");
        }
    }
}

/* ---- live-state check (config can be converged while live conf is stale) --- */
$live_conf = @file_get_contents(UNBOUND_LIVE_CONF);
$live_has_zones = true;
foreach ($zones as $z) {
    if ($live_conf === false || strpos($live_conf, $z) === false) {
        $live_has_zones = false;
        break;
    }
}

// Live-state check for the system-domain zone-type (pfSense emits the static
// zone into the host_entries.conf include, not the main unbound.conf). Only when
// SURU actually MANAGES the field ($sysdomain_managed — in-scope AND not an
// operator-set non-default value) do we assert the live state matches the
// desired direction: the `static` line PRESENT when applying, ABSENT when
// reverting to transparent. An unmanaged zone-type (refuse/redirect/...) emits
// its own different local-zone line — asserting static-absence there would
// false-fail (review finding).
$sysdomain_live_ok = true;
// Matched with stripos() (case-insensitive), not strpos(): pfSense's emitter
// interpolates the RAW config value — unbound_generate_zone_data() writes
// `local-zone: "{$domain}." {$zone_type}` with $domain passed straight from
// config_get_path('system/domain') (live-read /etc/inc/unbound.inc:762 + the
// call at :826, 2026-09-01 — no strtolower anywhere in that chain). A
// mixed-case stored domain therefore keeps its case in host_entries.conf,
// and an exact lowercase match would exit(6) on every deploy for such an
// install (review finding). DNS names are case-insensitive (RFC 1035),
// so a case-blind comparison is semantically correct on both directions.
$sysdomain_static_line = 'local-zone: "' . strtolower($system_domain) . '." static';
if ($sysdomain_managed) {
    $he = @file_get_contents('/var/unbound/host_entries.conf');
    if ($he === false) {
        $sysdomain_live_ok = false;
    } elseif ($apply_static) {
        $sysdomain_live_ok = (stripos($he, $sysdomain_static_line) !== false);
    } else {
        // Reverting: the static zone must be gone for the guard to be real.
        $sysdomain_live_ok = (stripos($he, $sysdomain_static_line) === false);
    }
}

if (!$config_changed && !$sysdomain_changed && $live_has_zones && $sysdomain_live_ok) {
    suru_lz_log("No changes — custom-options zones and system-domain zone already at target.");
    exit(0);
}

if ($config_changed) {
    config_set_path('unbound/custom_options', base64_encode($merged));
}
if ($config_changed || $sysdomain_changed) {
    write_config("SURU: unbound local-zones + system-domain static (local-DNS hygiene)");
    suru_lz_log("config.xml updated (custom-options changed=" . ($config_changed ? 'yes' : 'no') . ", system-domain zone-type changed=" . ($sysdomain_changed ? 'yes' : 'no') . ").");
} else {
    suru_lz_log("config.xml already at target but live conf is stale — reconfiguring resolver.");
}

/* ---- apply live ------------------------------------------------------------ */
suru_lz_log("Reconfiguring unbound (services_unbound_configure)...");
services_unbound_configure(false);

$pfb_inc = "/usr/local/pkg/pfblockerng/pfblockerng.inc";
$pfb_installed = file_exists($pfb_inc);
if ($pfb_installed) {
    require_once($pfb_inc);
    if (function_exists('sync_package_pfblockerng')) {
        // 'noupdates' = full reconfigure (module-config restore) with no feed
        // re-download and no DNSBL data rebuild — the data files on disk stay
        // valid; only the unbound integration needs re-asserting.
        suru_lz_log("Restoring pfBlockerNG unbound integration (sync_package_pfblockerng noupdates)...");
        sync_package_pfblockerng('noupdates');
    }
}

/* ---- read-back verification ------------------------------------------------ */
$live_conf = @file_get_contents(UNBOUND_LIVE_CONF);
if ($live_conf === false) {
    suru_lz_log("ERROR: cannot read " . UNBOUND_LIVE_CONF . " for verification.");
    exit(4);
}
foreach ($zones as $z) {
    if (strpos($live_conf, $z) === false) {
        suru_lz_log("ERROR: zone missing from live unbound.conf after apply: {$z}");
        exit(4);
    }
}
suru_lz_log("Verified: " . count($zones) . " custom-options zone(s) present in live unbound.conf.");

if ($sysdomain_managed) {
    $he = @file_get_contents('/var/unbound/host_entries.conf');
    if ($he === false) {
        suru_lz_log("ERROR: cannot read host_entries.conf to verify the system-domain zone-type after apply.");
        exit(6);
    }
    if ($apply_static) {
        // stripos: pfSense emits the domain in its stored case (see the
        // $sysdomain_static_line comment above); DNS names are case-insensitive.
        if (stripos($he, $sysdomain_static_line) === false) {
            suru_lz_log("ERROR: system-domain static zone missing from host_entries.conf after apply (expected: {$sysdomain_static_line}).");
            exit(6);
        }
        suru_lz_log("Verified: system domain '" . suru_lz_safe($system_domain) . "' is now a static local-zone (answered locally, not forwarded).");
    } else {
        // Reverted to transparent: assert the static zone is GONE so the guard's
        // "not shadowing the override" claim is actually true (review finding).
        if (stripos($he, $sysdomain_static_line) !== false) {
            suru_lz_log("ERROR: system-domain static zone still present in host_entries.conf after revert (expected absent: {$sysdomain_static_line}).");
            exit(6);
        }
        suru_lz_log("Verified: system domain '" . suru_lz_safe($system_domain) . "' is NOT a static local-zone (transparent — any legitimate domain-override forward is honoured).");
    }
}

if ($pfb_installed) {
    if (!preg_match('/^module-config:\s*"python\b/m', $live_conf)) {
        suru_lz_log("ERROR: pfBlockerNG python module missing from module-config after apply — DNSBL enforcement would be dead. Run sync_package_pfblockerng manually and investigate.");
        exit(5);
    }
    suru_lz_log("Verified: module-config still leads with python (DNSBL enforcement intact).");
}

suru_lz_log("Done.");
