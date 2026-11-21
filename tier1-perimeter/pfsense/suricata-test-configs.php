<?php
/**
 * SURU Tier 1 — Suricata pre-restart configuration test for pfSense
 *
 * Runs `suricata -T -c <yaml>` against the per-interface yaml of EVERY
 * configured Suricata instance, sequentially, and exits non-zero when any
 * instance fails. The deploy driver (scripts/platforms/pfsense.sh) runs this
 * after the Suricata appliers regenerated the on-disk configuration and BEFORE
 * the single consolidated restart (suricata-restart.php), so a configuration
 * Suricata cannot load is refused while the running engines still hold their
 * previous, working config.
 *
 * WHY THIS EXISTS:
 *   The pfSense package consumes the generated per-interface yaml
 *   (suricata_<UUID>_<iface>/suricata.yaml), not a top-level suricata.yaml, so
 *   only a test of those files proves what the restart will load.
 *
 * SCOPE PARITY with the restart:
 *   Instances are enumerated from config_get_path('installedpackages/suricata/rule')
 *   — the same set suricata-restart.php hands to suricata_restart_all_interfaces()
 *   — and each yaml path is derived exactly as suricata-rules-apply.php does
 *   (SURICATADIR . "suricata_{uuid}_{real}/suricata.yaml"). A shell glob is
 *   deliberately not used: it would include stale directories and diverge from
 *   the set the restart acts on.
 *
 * WHY OVER SSH, NOT THE REST API:
 *   A rule load per instance is memory-heavy; running it inside the PHP-FPM
 *   workers behind the REST API risks exhausting router memory (see
 *   docs/API-VALIDATION-SETUP.md). This script runs as a one-shot CLI process.
 *
 * RULE PARSE FAILURES ARE REPORTED, NOT FATAL:
 *   A strict `suricata -T` exits 1 when any single rule fails to parse, while
 *   the running engines skip such a rule and load the rest. Vendor rule sets
 *   regularly carry a rule the installed engine build cannot parse, so the test
 *   runs with `--set engine.init-failure-fatal=0`: a configuration the engine
 *   cannot load (a yaml syntax error, an invalid output section) still fails,
 *   and each skipped rule is listed by sid on a WARN line.
 *   The same setting also turns a rule file that does not exist into a warning;
 *   such a file is listed by name on a WARN line and does not fail the test.
 *   A run that loads no rules at all exits 0 from Suricata in this mode (every
 *   rule file missing, or an empty rule set, which exits 0 even in strict mode;
 *   observed on 7.0.10), but an engine started from it has no detection, so the
 *   loader's "no rules were loaded" line FAILS that instance.
 *
 * --count:
 *   Prints only the number of configured instances (the set the test would
 *   run) and exits 0. The driver uses it to size the dead-man's-switch window
 *   before the test on an inline deploy.
 *
 * SEQUENTIAL BY DESIGN:
 *   Each test loads the full rule set; running instances one at a time bounds
 *   the peak memory next to the live engines on a small router.
 *
 * Invoked as:
 *   sudo php suricata-test-configs.php [--timeout=<sec>] [--suricata-bin=<path>]
 *   sudo php suricata-test-configs.php --count
 *   Test mode (no pfSense includes, instances given explicitly):
 *   php suricata-test-configs.php --no-live --instances=<uuid>:<real>[,...]
 *       --suricata-dir=<dir> [--timeout=<sec>] [--suricata-bin=<path>] [--count]
 *
 * Options:
 *   --timeout=<sec>      per-instance limit via /usr/bin/timeout; 0 = unbounded
 *                        (default 900). Without timeout(1) the test runs
 *                        unbounded and says so.
 *   --suricata-bin=<p>   Suricata binary (default /usr/local/bin/suricata)
 *   --no-live            test mode; required for --instances / --suricata-dir
 *   --count              print the configured instance count and exit 0
 *
 * Output (one line per instance, then a summary):
 *   [suricata-test] iface=<carrier> uuid=<uuid> yaml=<path>: OK (<n>s)
 *   [suricata-test] iface=<carrier> uuid=<uuid>: WARN <k> rule(s) failed to parse and are skipped (sid <list>)
 *   [suricata-test] iface=<carrier> uuid=<uuid>: WARN <k> rule file(s) not found and skipped (<names>)
 *   [suricata-test] iface=<carrier> uuid=<uuid> yaml=<path>: FAIL (no rules loaded — the engine would run without detection)
 *   [suricata-test] iface=<carrier> uuid=<uuid> yaml=<path>: FAIL rc=<rc>
 *       <last 20 lines of suricata output, indented 4 spaces>
 *   [suricata-test] iface=<carrier> uuid=<uuid> yaml=<path>: FAIL (yaml missing)
 *   [suricata-test] iface=<carrier> uuid=<uuid> yaml=: FAIL (interface unresolved)
 *   [suricata-test] <n> instance(s) tested, <f> failed.
 *
 * Exit: 0 every instance OK (or none configured); 1 at least one FAIL;
 *       2 usage error or Suricata binary not executable.
 */

const SURU_TEST_DEFAULT_BIN = '/usr/local/bin/suricata';
const SURU_TEST_DEFAULT_DIR = '/usr/local/etc/suricata/';
const SURU_TEST_TIMEOUT_BIN = '/usr/bin/timeout';
const SURU_TEST_TAIL_LINES  = 20;
const SURU_TEST_MAX_SIDS    = 20;

function st_usage_fail(string $msg): void {
    fwrite(STDERR, "[suricata-test] ERROR: {$msg}" . PHP_EOL);
    exit(2);
}

// --- argument parsing (strict: unknown arguments are rejected) --------------
$opt = [
    'timeout'   => 900,
    'bin'       => SURU_TEST_DEFAULT_BIN,
    'live'      => true,
    'instances' => null,
    'dir'       => null,
    'count'     => false,
];
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--no-live') { $opt['live'] = false; continue; }
    if ($a === '--count')   { $opt['count'] = true; continue; }
    if (preg_match('/^--timeout=(.*)$/s', $a, $m)) {
        if (!preg_match('/^[0-9]+$/', $m[1])) { st_usage_fail("--timeout must be a non-negative integer"); }
        $opt['timeout'] = (int)$m[1];
        continue;
    }
    if (preg_match('/^--suricata-bin=(.+)$/s', $a, $m)) { $opt['bin'] = $m[1]; continue; }
    if (preg_match('/^--instances=(.*)$/s', $a, $m))    { $opt['instances'] = $m[1]; continue; }
    if (preg_match('/^--suricata-dir=(.+)$/s', $a, $m)) { $opt['dir'] = $m[1]; continue; }
    st_usage_fail("unknown argument");
}
if ($opt['live'] && ($opt['instances'] !== null || $opt['dir'] !== null)) {
    st_usage_fail("--instances/--suricata-dir are only valid with --no-live");
}
if (!$opt['live'] && $opt['instances'] === null) {
    st_usage_fail("--no-live requires --instances=<uuid>:<real>[,...]");
}

// --- instance list -----------------------------------------------------------
// Each entry: [carrier label, uuid, yaml path].
$instances = [];
if ($opt['live']) {
    require_once('config.inc');
    require_once('config.lib.inc');
    require_once('/usr/local/pkg/suricata/suricata.inc');

    // SURICATADIR is the package's install-dir constant; same defensive
    // fallback to the literal path as suricata-rules-apply.php.
    $dir = defined('SURICATADIR') ? SURICATADIR : SURU_TEST_DEFAULT_DIR;
    $dir = rtrim($dir, '/') . '/';
    foreach (config_get_path('installedpackages/suricata/rule', []) as $entry) {
        $carrier = (string)($entry['interface'] ?? '');
        $uuid    = (string)($entry['uuid'] ?? '');
        $real    = (string)get_real_interface($carrier);
        // An unresolved interface leaves no yaml to test: '' is reported as
        // "interface unresolved" below and counts as a failure.
        $instances[] = [$carrier, $uuid, $real === '' ? '' : $dir . "suricata_{$uuid}_{$real}/suricata.yaml"];
    }
} else {
    $dir = rtrim($opt['dir'] ?? SURU_TEST_DEFAULT_DIR, '/') . '/';
    if ($opt['instances'] === '') { st_usage_fail("--instances is empty"); }
    foreach (explode(',', $opt['instances']) as $pair) {
        if (!preg_match('/^([A-Za-z0-9]+):([A-Za-z0-9._-]+)$/', $pair, $m)) {
            st_usage_fail("invalid --instances entry (expected <uuid>:<real>)");
        }
        $instances[] = [$m[2], $m[1], $dir . "suricata_{$m[1]}_{$m[2]}/suricata.yaml"];
    }
}

if ($opt['count']) {
    echo count($instances) . PHP_EOL;
    exit(0);
}

if (count($instances) === 0) {
    echo "[suricata-test] No Suricata interfaces configured — nothing to test." . PHP_EOL;
    exit(0);
}

if (!is_executable($opt['bin'])) {
    st_usage_fail("Suricata binary not executable: " . $opt['bin']);
}

// --- timeout(1) prefix -------------------------------------------------------
$prefix = '';
if ($opt['timeout'] > 0) {
    if (is_executable(SURU_TEST_TIMEOUT_BIN)) {
        $prefix = escapeshellarg(SURU_TEST_TIMEOUT_BIN) . ' ' . (int)$opt['timeout'] . ' ';
    } else {
        echo "[suricata-test] WARN: timeout(1) not found — running unbounded" . PHP_EOL;
    }
}

// --- test every instance, sequentially; never stop at the first failure ------
$failed = 0;
foreach ($instances as [$carrier, $uuid, $yaml]) {
    $label = "iface={$carrier} uuid={$uuid} yaml={$yaml}";
    if ($yaml === '') {
        echo "[suricata-test] {$label}: FAIL (interface unresolved)" . PHP_EOL;
        $failed++;
        continue;
    }
    if (!is_file($yaml)) {
        echo "[suricata-test] {$label}: FAIL (yaml missing)" . PHP_EOL;
        $failed++;
        continue;
    }
    $cmd = $prefix . escapeshellarg($opt['bin']) . ' -T -c ' . escapeshellarg($yaml)
         . ' --set engine.init-failure-fatal=0 2>&1';
    $out = [];
    $rc  = 0;
    $t0  = microtime(true);
    exec($cmd, $out, $rc);
    $secs = (int)round(microtime(true) - $t0);
    if ($rc === 0) {
        // Scan the loader output. Only the sid of a skipped rule is echoed: the
        // rule text is vendor content and is not repeated into the deploy output.
        $sids    = [];
        $bad     = 0;
        $missing = [];
        $norules = false;
        foreach ($out as $line) {
            if (strpos($line, 'error parsing signature') !== false) {
                $bad++;
                if (preg_match('/\bsid:\s*([0-9]+)\s*;/', $line, $sm)) { $sids[] = $sm[1]; }
                continue;
            }
            // Loader wording: "No rule files match the pattern <path>". Only the
            // file name is echoed, reduced to a safe character set.
            if (preg_match('/No rule files match the pattern (\S+)/', $line, $fm)) {
                $name = preg_replace('/[^A-Za-z0-9._-]/', '?', basename($fm[1]));
                $missing[] = $name;
                continue;
            }
            // Loader wording: "<n> rule files specified, but no rules were loaded!"
            if (strpos($line, 'but no rules were loaded') !== false) { $norules = true; }
        }
        if ($norules) {
            // Suricata exits 0 here even in strict mode, but an engine started
            // from this config has no detection: a failure, not a warning.
            $failed++;
            echo "[suricata-test] {$label}: FAIL (no rules loaded — the engine would run without detection)" . PHP_EOL;
        } else {
            echo "[suricata-test] {$label}: OK ({$secs}s)" . PHP_EOL;
        }
        $prefix_warn = "[suricata-test] iface={$carrier} uuid={$uuid}: WARN";
        if ($bad > 0) {
            $list = implode(',', array_slice($sids, 0, SURU_TEST_MAX_SIDS));
            if (count($sids) > SURU_TEST_MAX_SIDS) { $list .= ',...'; }
            if ($list === '') { $list = 'unknown'; }
            echo "{$prefix_warn} {$bad} rule(s) failed to parse and are skipped (sid {$list})" . PHP_EOL;
        }
        if (count($missing) > 0) {
            $names = implode(',', array_slice($missing, 0, SURU_TEST_MAX_SIDS));
            if (count($missing) > SURU_TEST_MAX_SIDS) { $names .= ',...'; }
            echo "{$prefix_warn} " . count($missing) . " rule file(s) not found and skipped ({$names})" . PHP_EOL;
        }
        continue;
    }
    $failed++;
    echo "[suricata-test] {$label}: FAIL rc={$rc}" . PHP_EOL;
    foreach (array_slice($out, -SURU_TEST_TAIL_LINES) as $line) {
        echo '    ' . $line . PHP_EOL;
    }
}

echo "[suricata-test] " . count($instances) . " instance(s) tested, {$failed} failed." . PHP_EOL;
exit($failed > 0 ? 1 : 0);
