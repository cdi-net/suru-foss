<?php
/**
 * SURU Tier 1 — syslog-ng XML applier for pfSense
 *
 * Reads a rendered syslog-ng.conf (path on $argv[1]) on the router, parses
 * it into discrete syslog-ng objects, then writes each into the pfSense
 * config XML at installedpackages/syslogngadvanced/config so the pfSense
 * GUI sees them. Finally calls syslogng_resync() — the same function the
 * GUI calls after a Save — which rebuilds /usr/local/etc/syslog-ng.conf
 * from XML and restarts the service.
 *
 * Why this is durable across reboots and GUI saves, with no extra boot
 * mechanism: syslogng_build_conf() (in syslog-ng.inc) is RAW PASSTHROUGH —
 * for every stored object it writes `objecttype objectname <raw decoded
 * params>` verbatim. It is not a constrained schema; it can express
 * disk-buffer, ca-dir, sni, anything we store, because it's just replaying
 * our own stored text. syslogng_resync() is what /etc/rc.start_packages
 * calls at every boot, so reapplying through XML (not bypassing the native
 * builder) is durable for free. CONFIRMED by two live reboot tests
 * (2026-06-23) plus reading syslog-ng.inc directly on the router.
 *
 * What actually caused the 2026-06-22 incident (syslog-ng came up with a
 * broken config after a reboot, `s_syslog_udp` referenced but undefined):
 * NOT a schema limitation. syslogng_resync() merges our stored objects with
 * pre-existing "non-SURU" objects this applier preserves (see below) — one
 * of those preserved objects was a stale, pre-SURU manual-GUI artifact with
 * a dangling reference, and the native passthrough builder faithfully
 * reproduced that breakage. Two earlier fix attempts (system/shellcmd, then
 * cron/item polling every minute) treated this as a boot-ordering problem
 * and bypassed the native builder instead of fixing the actual cause — both
 * added ongoing resource cost (the cron variant) or didn't work at all (the
 * shellcmd variant: it runs before /etc/rc.start_packages, so always lost
 * the race). The real fix is below: validate referential integrity of the
 * full merged object set before writing it, drop stale non-SURU objects
 * that reference something undefined, and trust syslogng_resync() — no
 * bypass, no boot-time re-apply mechanism, zero ongoing cost.
 *
 * Idempotent: SURU-managed objects are identified by name. The applier
 * removes every object whose objectname is in the rendered file's
 * declared name set, then re-adds the fresh definitions. Any user-managed
 * objects are preserved, UNLESS they fail the referential-integrity check
 * below (see suru_drop_dangling_objects()), or match the SURU-synthetic
 * naming pattern for nameless log/options blocks (see SURU_SYNTHETIC_NAME_RE
 * — these are our own past leftovers, never an operator's object, and are
 * pruned rather than preserved).
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/syslog-ng-apply.php /tmp/suru-staging/syslog-ng.conf-source
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/syslog-ng.inc');
require_once('services.inc'); // configure_cron() — removing the superseded cron/item entry below

if ($argc < 2 || !is_readable($argv[1])) {
  fwrite(STDERR, "usage: php syslog-ng-apply.php <rendered-syslog-ng.conf>\n");
  exit(2);
}
$src = file_get_contents($argv[1]);
if ($src === false) {
  fwrite(STDERR, "[syslog-ng-apply] cannot read source file\n");
  exit(2);
}

/**
 * Parse a syslog-ng.conf source string into a list of objects.
 *
 * syslog-ng grammar accepted here:
 *   options { ... };
 *   <type> <name> { ... };
 *   where <type> ∈ {source, destination, filter, parser, rewrite, template, log}
 *
 * No nested braces in bodies — that's true of the SURU template; if it
 * ever isn't, this parser must be replaced with a proper lexer.
 *
 * Top-level @version: and @include "..." directives are stripped here:
 *   @version is emitted by syslogng_build_conf based on the installed
 *   package version. @include "scl.conf" is controlled by the
 *   include_scl global setting (set below).
 */
function suru_parse_syslogng_conf(string $src): array {
  $objects = [];
  $re = '/^[ \t]*(options|source|destination|filter|parser|rewrite|template|log)(?:[ \t]+([A-Za-z0-9_]+))?[ \t]*\{(.*?)\};/sm';
  if (!preg_match_all($re, $src, $m, PREG_SET_ORDER)) {
    return $objects;
  }
  // options/log blocks are nameless in syslog-ng grammar. The pfSense build
  // function ignores objectname for these. A synthetic name is needed so
  // the merge-by-name logic can deduplicate across reapplies — but it MUST
  // be stable independent of body content. An earlier version hashed the
  // body (sha1) to derive the name; that meant ANY edit to a log/options
  // block's literal text (reordering a rewrite, fixing a file path, even
  // re-wrapping a comment) changed its hash, so the merge logic in the
  // caller (which only replaces an existing object whose name matches one
  // we're about to (re)write) never recognized the edited block as "the
  // same one, updated" — it just added a new name and left the old one
  // behind as if it were a genuine operator object. Live-confirmed
  // 2026-06-24: this router had accumulated 2-3 duplicate copies of nearly
  // every log{} block (firewall, dns, zeek, vpn, suricata, auth, dhcp,
  // pfblocker) across the template's edit history, double/triple-shipping
  // every event type to the SIEM. Fixed: name by sequential position
  // instead of content hash — stable across content edits to any
  // individual block, since the template always emits the same ordered
  // sequence of log/options blocks. The caller's pruning step (below) also
  // sweeps any leftover hash-named or now-unused ordinal-named SURU object
  // to self-heal the cruft already on a router from before this fix.
  $ordinal = ['log' => 0, 'options' => 0];
  foreach ($m as $match) {
    $type = $match[1];
    $name = isset($match[2]) ? trim($match[2]) : '';
    $body = '{' . $match[3] . '}';
    if ($name === '' && ($type === 'log' || $type === 'options')) {
      $name = $type . '_suru_' . sprintf('%03d', $ordinal[$type]++);
    }
    $objects[] = [
      'objecttype'       => $type,
      'objectname'       => $name,
      'objectparameters' => base64_encode($body . ';'),
    ];
  }
  return $objects;
}

// Matches both this fix's ordinal-named synthetic objects (log_suru_000,
// options_suru_003, …) and the prior version's sha1-hash-named ones
// (log_suru_a1b2c3d4) — anything matching this pattern is SURU-owned, never
// an operator's own object, regardless of which naming scheme produced it.
const SURU_SYNTHETIC_NAME_RE = '/^(log|options)_suru_[0-9a-f]+$/';

// Named objects that PRIOR template versions emitted under SURU ownership but
// the current template no longer does. Because they carry an operator-style
// (non-synthetic) name, the keep/prune loop below would otherwise misclassify
// them as operator-authored and preserve them forever. They must be pruned so
// a template refactor that drops a named object self-heals on the next deploy.
//   - t_json_base: removed 2026-06-25. The JSON template is now INLINED into
//     d_siem_tls. As a separate `template` object it was re-emitted AFTER the
//     destination by syslogng_build_conf's type-grouped ordering, so the
//     destination's `template(t_json_base)` reference degraded to the literal
//     string "t_json_base" (syslog-ng does not forward-resolve template refs) —
//     shipping 11 bytes of constant text instead of JSON and breaking all SIEM
//     ingestion (incident 2026-06-23). Pruning removes the now-inert leftover.
//   - s_pfsense_syslog: removed 2026-07-05. This unix-dgram("/var/run/log")
//     source made syslog-ng compete with pfSense's syslogd for the syslog
//     socket; syslog-ng won after a 2026-06-30 config regen and starved
//     syslogd, freezing /var/log/filter.log so firewall block events stopped
//     reaching the SIEM for 5 days. WITHOUT this prune entry the template's
//     deletion of the source is inert — the applier merges by name and would
//     preserve the orphaned source, which still binds the socket even with no
//     log{} path consuming it (a declared source is opened at startup). Pruning
//     it is what actually removes the competing bind.
const SURU_LEGACY_OWNED_NAMES = ['t_json_base', 's_pfsense_syslog'];

// Object types that can be the TARGET of a reference (source(NAME),
// destination(NAME), filter(NAME), rewrite(NAME), parser(NAME),
// template(NAME) calls inside another object's body). 'log' and 'options'
// are never referenced this way, so they're excluded from the defined-set.
const SURU_REFERENCABLE_TYPES = ['source', 'destination', 'filter', 'rewrite', 'parser', 'template'];

function suru_object_key(array $o): string {
  return $o['objecttype'] . ':' . $o['objectname'];
}

/**
 * Extract every reference call (source(NAME), destination(NAME), …) found
 * in an object's decoded body text.
 *
 * Returns a list of "type:name" keys, matching suru_object_key()'s format,
 * so callers can look them up directly against a defined-set built the
 * same way.
 */
function suru_collect_references(string $body): array {
  $refs = [];
  foreach (SURU_REFERENCABLE_TYPES as $type) {
    if (preg_match_all('/\b' . $type . '\s*\(\s*([A-Za-z0-9_]+)\s*\)/', $body, $m)) {
      foreach ($m[1] as $name) {
        $refs[] = $type . ':' . $name;
      }
    }
  }
  return $refs;
}

/**
 * Drop preserved (non-SURU) objects whose body references something not
 * defined anywhere in the final merged set — this is the actual fix for
 * the 2026-06-22 incident: a stale legacy object (predating SURU) with a
 * dangling reference, faithfully reproduced by syslogng_resync()'s raw-
 * passthrough builder. Iterates to a fixed point: dropping object A can
 * make object B's reference to A dangling too (B referenced A, A is now
 * gone), so re-check after every round until nothing more is dropped.
 *
 * Only touches $kept (non-SURU objects) — never drops a SURU object;
 * see suru_assert_no_dangling_refs() below for why that's a hard failure
 * instead.
 */
function suru_drop_dangling_objects(array $kept, array $parsed): array {
  $dropped = [];
  do {
    $defined = [];
    foreach (array_merge($kept, $parsed) as $o) {
      if (in_array($o['objecttype'], SURU_REFERENCABLE_TYPES, true)) {
        $defined[suru_object_key($o)] = true;
      }
    }
    $still_kept = [];
    $dropped_this_round = [];
    foreach ($kept as $o) {
      $body = base64_decode($o['objectparameters']);
      $broken = false;
      foreach (suru_collect_references($body) as $ref) {
        if (!isset($defined[$ref])) { $broken = true; break; }
      }
      if ($broken) {
        $dropped_this_round[] = $o;
      } else {
        $still_kept[] = $o;
      }
    }
    $kept = $still_kept;
    $dropped = array_merge($dropped, $dropped_this_round);
  } while (count($dropped_this_round) > 0);
  return [$kept, $dropped];
}

/**
 * Refuse to deploy if any SURU-managed object references something
 * undefined in the final merged set. Unlike stale non-SURU objects (which
 * we drop and self-heal), a dangling reference in OUR OWN template is an
 * authoring bug in the rendered conf — fail loud immediately rather than
 * silently shipping a config that will break syslog-ng on the next
 * resync (boot or GUI save), the exact failure mode this applier exists
 * to prevent.
 */
function suru_assert_no_dangling_refs(array $parsed, array $defined): void {
  foreach ($parsed as $o) {
    $body = base64_decode($o['objectparameters']);
    foreach (suru_collect_references($body) as $ref) {
      if (!isset($defined[$ref])) {
        fwrite(STDERR, "[syslog-ng-apply] FATAL: SURU object '{$o['objecttype']} {$o['objectname']}' "
          . "references undefined '{$ref}' — template authoring bug, refusing to deploy.\n");
        exit(7);
      }
    }
  }
}

$parsed = suru_parse_syslogng_conf($src);
if (count($parsed) === 0) {
  fwrite(STDERR, "[syslog-ng-apply] parser produced 0 objects — refusing to wipe config\n");
  exit(3);
}
echo "[syslog-ng-apply] Parsed " . count($parsed) . " syslog-ng objects from " . basename($argv[1]) . PHP_EOL;

// Build a name-set of objects we will own. Anything currently in XML with
// a name in this set gets replaced; everything else is a candidate to keep.
$suru_names = [];
foreach ($parsed as $o) { $suru_names[$o['objectname']] = true; }

$existing = config_get_path('installedpackages/syslogngadvanced/config', []);
$kept = [];
$dropped_synthetic = [];
foreach ($existing as $o) {
  $name = isset($o['objectname']) ? $o['objectname'] : '';
  if (isset($suru_names[$name])) { continue; }
  // A SURU-synthetic name (this run's or an earlier run's naming scheme —
  // see SURU_SYNTHETIC_NAME_RE) that ISN'T in this run's desired set is our
  // own leftover, never an operator's object — prune it instead of
  // preserving it. This is what self-heals the duplicate log{} blocks
  // already accumulated on a router from before this fix (see the comment
  // in suru_parse_syslogng_conf()), and stops future template edits from
  // accumulating new ones.
  if (preg_match(SURU_SYNTHETIC_NAME_RE, $name)) {
    $dropped_synthetic[] = $o;
    continue;
  }
  // Legacy SURU-owned named objects the current template no longer emits
  // (e.g. t_json_base after it was inlined) — prune, don't preserve.
  if (in_array($name, SURU_LEGACY_OWNED_NAMES, true)) {
    $dropped_synthetic[] = $o;
    continue;
  }
  $kept[] = $o;
}
if (count($dropped_synthetic) > 0) {
  echo "[syslog-ng-apply] Pruned " . count($dropped_synthetic) . " stale SURU-synthetic object(s) (superseded log/options blocks):" . PHP_EOL;
  foreach ($dropped_synthetic as $o) {
    echo "  - {$o['objecttype']} {$o['objectname']}" . PHP_EOL;
  }
}

[$kept, $dropped_stale] = suru_drop_dangling_objects($kept, $parsed);
if (count($dropped_stale) > 0) {
  echo "[syslog-ng-apply] Dropped " . count($dropped_stale) . " stale non-SURU object(s) with dangling references:" . PHP_EOL;
  foreach ($dropped_stale as $o) {
    echo "  - {$o['objecttype']} {$o['objectname']}" . PHP_EOL;
  }
}

$final_defined = [];
foreach (array_merge($kept, $parsed) as $o) {
  if (in_array($o['objecttype'], SURU_REFERENCABLE_TYPES, true)) {
    $final_defined[suru_object_key($o)] = true;
  }
}
suru_assert_no_dangling_refs($parsed, $final_defined);

$merged = array_merge($kept, $parsed);
config_set_path('installedpackages/syslogngadvanced/config', $merged);

// Global settings — turn the service on, set include_scl on so @include "scl.conf"
// is emitted by syslogng_build_conf (the SURU template uses scl.conf macros).
$settings = config_get_path('installedpackages/syslogng/config/0', []);
$settings['enable'] = 'on';
$settings['include_scl'] = 'on';
// Keep operator-set values for archive_*, default_logdir etc. — never overwrite
// what isn't explicitly SURU territory.
config_set_path('installedpackages/syslogng/config/0', $settings);

write_config('SURU: applied syslog-ng objects from rendered template');

echo "[syslog-ng-apply] Wrote " . count($parsed) . " SURU objects to installedpackages/syslogngadvanced/config" . PHP_EOL;
echo "[syslog-ng-apply] Preserved " . count($kept) . " pre-existing non-SURU object(s) (referential integrity OK)" . PHP_EOL;

// Trust the native builder — no bypass, no direct conf overwrite, no
// separate boot-time re-apply mechanism. This is the same call
// /etc/rc.start_packages makes at every boot and the GUI makes on every
// Save, so exercising it here means deploy-time and boot-time behavior are
// IDENTICAL — there is only one code path to ever validate.
echo "[syslog-ng-apply] Calling syslogng_resync() to rebuild syslog-ng.conf and (re)start the service..." . PHP_EOL;
syslogng_resync();

// syslogng_resync() calls restart_service('syslog-ng'), which (per
// service-utils.inc) does stop_service() — blocking ~5s+ via syslog-ng.sh's
// rc_stop(): kill, sleep 5, killall -9 — then start_service(), which runs
// syslog-ng.sh's rc_start() via mwexec_bg() (non-blocking). rc_start()
// itself guards on "is a syslog-ng process already visible in `ps`" before
// starting — a real, observed race: if that check runs while the
// just-killed old process is still exiting (not yet reaped), it sees a
// match and skips starting entirely, leaving nothing running once the old
// process finishes exiting a moment later. CONFIRMED reproducible (not a
// one-off flake) across multiple consecutive deploys, by reading
// syslog-ng.sh's rc_start()/rc_stop() directly.
//
// Fix: if syslog-ng isn't up after a short wait, force a clean stop+start
// cycle ourselves — still the native pfSense service API, just a defensive
// retry against the race above (an explicit stop first clears any
// ambiguous half-dead state, rather than layering another start attempt on
// top of it). The race is intermittent — confirmed both a clean resync
// with no retry needed, and a stuck state requiring this retry, across
// repeated runs — so retry a few times rather than once.
function suru_syslogng_running(): bool {
    $rc = 1;
    @exec('pgrep -x syslog-ng', $out, $rc);
    return $rc === 0;
}

// _DEFAULT's UDP listener port — checked directly via sockstat rather than
// just sleeping, since the actual observed failure was "Address already in
// use" on this exact port immediately after a restart (the just-killed
// process's socket hadn't released yet). Waiting for the port to genuinely
// be free is more reliable than a fixed sleep when this is sensitive to
// ambient system load (confirmed: reproduces reliably through the full
// deploy pipeline, never in an isolated quiet SSH session).
function suru_port_5140_free(): bool {
    @exec("sockstat -4 -6 2>/dev/null | awk '{print \$6}' | grep -q ':5140$'", $out, $rc);
    return $rc !== 0; // grep -q: rc=1 means no match = port free
}

for ($i = 0; $i < 10 && !suru_syslogng_running(); $i++) {
    sleep(1);
}

for ($attempt = 1; $attempt <= 3 && !suru_syslogng_running(); $attempt++) {
    echo "[syslog-ng-apply] Not running after resync (rc_start()/rc_stop() race) — forcing stop+start, attempt {$attempt}/3..." . PHP_EOL;
    stop_service('syslog-ng');
    @exec('killall -9 syslog-ng 2>/dev/null');
    for ($i = 0; $i < 15 && !suru_port_5140_free(); $i++) {
        sleep(1);
    }
    start_service('syslog-ng');
    for ($i = 0; $i < 10 && !suru_syslogng_running(); $i++) {
        sleep(1);
    }
}

// Last resort: pfSense's own service-restart helper (rc_start()/rc_stop())
// has, despite the retries above, intermittently failed to actually get
// syslog-ng running again under load. The config itself is never in
// question here (validated below) — only the daemon-start mechanism. Run
// the already-validated binary directly, with full error output captured,
// so if this ever triggers we get the real cause instead of guessing again.
if (!suru_syslogng_running()) {
    echo "[syslog-ng-apply] Still not running after 3 retries — falling back to a direct start with captured output..." . PHP_EOL;
    $direct_out = [];
    $direct_rc = 0;
    exec('/usr/local/sbin/syslog-ng -p /var/run/syslog-ng.pid 2>&1', $direct_out, $direct_rc);
    if (count($direct_out) > 0) {
        echo "[syslog-ng-apply] Direct start output: " . implode(' | ', $direct_out) . PHP_EOL;
    }
    for ($i = 0; $i < 10 && !suru_syslogng_running(); $i++) {
        sleep(1);
    }
}
$pgrep_rc = suru_syslogng_running() ? 0 : 1;

// Verify the result. If this ever fails, the fix is to improve the
// referential-integrity check above (or the template), NOT to fall back to
// a bypass — that would silently reintroduce the exact failure mode this
// applier exists to prevent.
$sng_conf = '/usr/local/etc/syslog-ng.conf';
$sng_bin  = '/usr/local/sbin/syslog-ng';

$validate_cmd = escapeshellcmd($sng_bin) . ' --syntax-only -f ' . escapeshellarg($sng_conf) . ' 2>&1';
$validate_out = [];
$validate_rc  = 0;
exec($validate_cmd, $validate_out, $validate_rc);
if ($validate_rc !== 0) {
    fwrite(STDERR, "[syslog-ng-apply] FATAL: syslogng_resync() produced an invalid {$sng_conf} (rc={$validate_rc}):\n");
    fwrite(STDERR, implode("\n", $validate_out) . "\n");
    fwrite(STDERR, "[syslog-ng-apply] This means the referential-integrity check above missed something —\n");
    fwrite(STDERR, "[syslog-ng-apply] inspect installedpackages/syslogngadvanced/config for the actual cause.\n");
    exit(5);
}

if ($pgrep_rc !== 0) {
    fwrite(STDERR, "[syslog-ng-apply] ERROR: syslog-ng failed to start even after 3 stop+start retries — check /var/log/system.log\n");
    exit(6);
}
$pgrep_out = [];
@exec('pgrep -x syslog-ng', $pgrep_out);
echo "[syslog-ng-apply] syslog-ng is running with a valid SURU-derived config (pid(s): " . implode(', ', $pgrep_out) . ")" . PHP_EOL;

// --- Cleanup: remove the now-unnecessary cron/item self-heal job and its
// files from a previous version of this applier (2026-06-23). Trusting
// syslogng_resync() natively (above) makes this unnecessary — see the file
// header. Safe no-op if absent.
$sng_dir      = '/usr/local/etc/syslog-ng';
$sng_rendered = $sng_dir . '/suru-rendered.conf';
$sng_boot_sh  = $sng_dir . '/suru-boot-apply.sh';

$cron_items = config_get_path('cron/item', []);
$cron_items_before = count($cron_items);
$cron_items = array_values(array_filter($cron_items, function ($i) use ($sng_boot_sh) {
    return strpos((string)($i['command'] ?? ''), $sng_boot_sh) === false;
}));
if (count($cron_items) !== $cron_items_before) {
    config_set_path('cron/item', $cron_items);
    write_config('SURU: removed superseded syslog-ng self-heal cron job');
    configure_cron();
    echo "[syslog-ng-apply] Removed superseded cron/item entry for {$sng_boot_sh}." . PHP_EOL;
}
@unlink($sng_boot_sh);
@unlink($sng_rendered);

// --- Hand /var/run/log back to pfSense's syslogd (2026-07-05) ----------------
// syslog-ng and syslogd both want the /var/run/log datagram socket. syslog-ng
// unlink()s-and-rebinds it on every start, so it wins whenever it restarts
// last — which is exactly what the syslogng_resync() above just did. Now that
// syslog-ng's config no longer declares the /var/run/log source (s_pfsense_syslog
// was removed + pruned), restart syslogd so it reclaims the socket: pfSense's
// filterlog/kea/unbound/etc. reconnect to syslogd, which resumes writing
// /var/log/{filter,auth,resolver,...}.log — the FILES syslog-ng reads. Without
// this step the socket is left orphaned (syslog-ng released it, nothing rebinds)
// until the next reboot, and firewall block events never reach the SIEM.
// system_syslogd_start() is pfSense's own (re)start path — the same one boot and
// the GUI log-settings save use — so deploy and boot behavior stay identical.
if (function_exists('system_syslogd_start')) {
    echo "[syslog-ng-apply] Restarting pfSense syslogd so it reclaims /var/run/log..." . PHP_EOL;
    system_syslogd_start();
    // Confirm syslogd is the socket owner now (best-effort, non-fatal).
    // system_syslogd_start() launches syslogd asynchronously, so it may not have
    // bound the socket the instant it returns — retry the check a few times
    // rather than reporting a spurious WARN on a slow bind.
    $owned_by_syslogd = false;
    for ($i = 0; $i < 5 && !$owned_by_syslogd; $i++) {
        if ($i > 0) { sleep(1); }
        $sock_out = [];
        @exec('sockstat 2>/dev/null | grep " /var/run/log "', $sock_out);
        foreach ($sock_out as $l) { if (strpos($l, 'syslogd') !== false) { $owned_by_syslogd = true; break; } }
    }
    echo $owned_by_syslogd
        ? "[syslog-ng-apply] OK — syslogd owns /var/run/log." . PHP_EOL
        : "[syslog-ng-apply] WARN — could not confirm syslogd owns /var/run/log after 5s; verify filter.log resumes." . PHP_EOL;
} else {
    echo "[syslog-ng-apply] WARN — system_syslogd_start() unavailable; syslogd not restarted (verify /var/run/log ownership)." . PHP_EOL;
}

echo "[syslog-ng-apply] Done." . PHP_EOL;
