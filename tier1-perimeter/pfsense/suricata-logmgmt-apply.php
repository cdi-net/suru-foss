<?php
/**
 * SURU Tier 1 — Suricata log-management (rotation) applier for pfSense
 *
 * Enables pfSense Suricata's built-in log-management cron and sets per-file
 * size caps + retention, so eve.json / http.log rotate instead of growing
 * without bound.
 *
 * INCIDENT ROOT CAUSE (2026-07-03): the log-management master toggle
 * `enable_log_mgmt` was UNSET in installedpackages/suricata/config/0, so the
 * rotation cron (suricata_check_cron_misc.inc, every 5 min) skipped every file —
 * its whole loop is gated on
 *   config_get_path('installedpackages/suricata/config/0/enable_log_mgmt') == 'on'
 * (suricata_check_cron_misc.inc:368, confirmed live 2026-07-03). eve.json grew
 * to 96 GB; syslog-ng's recursive wildcard-file source replayed it from byte 0
 * after a reboot, filling the SIEM disk and stalling ingestion.
 *
 * These settings live in the GLOBAL package config block
 * (installedpackages/suricata/config/0), NOT per-interface — the cron iterates
 * every configured interface's log dir itself. So this applier writes once to
 * the global block, unlike suricata-tuning-apply.php (per-rule[]).
 *
 * XML keys confirmed 2026-07-03 from live router
 * (/usr/local/pkg/suricata/suricata_check_cron_misc.inc:349-364):
 *   enable_log_mgmt       — 'on' | '' (unset). Master toggle for the cron loop.
 *   eve_log_limit_size    — KB integer; rotate eve.json when it reaches this.
 *   eve_log_retention     — hours; prune rotated eve.json.* older than this.
 *   http_log_limit_size   — KB integer; same for http.log.
 *   http_log_retention    — hours.
 * A limit of 0 means "never rotate"; a retention of 0 means "never prune".
 *
 * Rotation mechanism (suricata_check_rotate_log, ...:275): rename current log
 * to <name>.YYYY_MMDD_HHMM, touch a fresh empty file, SIGHUP Suricata to
 * reopen. The SURU syslog-ng source matches the exact filename `eve.json`
 * (filename-pattern("eve.json")), so a rotated `eve.json.*` copy is NOT
 * re-read — no replay. No Suricata restart is needed here; the cron itself
 * SIGHUPs on rotation.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/suricata-logmgmt-apply.php \
 *       [--enable|--disable] \
 *       [--eve-limit-kb=N] [--http-limit-kb=N] [--retention-hours=N] \
 *       [--run-now]
 *
 * --run-now invokes one rotation pass immediately after writing config
 * (php-cgi suricata_check_cron_misc.inc), so an oversized eve.json is capped
 * on this deploy rather than at the next 5-minute cron tick.
 *
 * Idempotent: re-running with identical values produces no config.xml diff
 * and no write_config().
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('util.inc');

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
$enable          = true;    // default: enable log management
$eve_limit_kb    = null;    // null = do not touch (keep existing)
$http_limit_kb   = null;
$retention_hours = null;
$run_now         = false;

foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--enable') {
        $enable = true;
    } elseif ($arg === '--disable') {
        $enable = false;
    } elseif (preg_match('/^--eve-limit-kb=(\d+)$/', $arg, $m)) {
        $eve_limit_kb = (int)$m[1];
    } elseif (preg_match('/^--http-limit-kb=(\d+)$/', $arg, $m)) {
        $http_limit_kb = (int)$m[1];
    } elseif (preg_match('/^--retention-hours=(\d+)$/', $arg, $m)) {
        $retention_hours = (int)$m[1];
    } elseif ($arg === '--run-now') {
        $run_now = true;
    } else {
        fwrite(STDERR, "[suricata-logmgmt-apply] ERROR: unknown arg: {$arg}\n");
        exit(1);
    }
}

$base = 'installedpackages/suricata/config/0';

// Suricata must be installed and have a config block to manage.
if (config_get_path($base) === null) {
    fwrite(STDERR, "[suricata-logmgmt-apply] Suricata global config block not found — is the package installed? Nothing to do.\n");
    exit(0);
}

$changed = 0;

// --- Master toggle ---------------------------------------------------------
$want_mgmt = $enable ? 'on' : '';
$cur_mgmt  = (string)(config_get_path("{$base}/enable_log_mgmt") ?? '');
if ($cur_mgmt !== $want_mgmt) {
    config_set_path("{$base}/enable_log_mgmt", $want_mgmt);
    echo "[suricata-logmgmt-apply] enable_log_mgmt '{$cur_mgmt}' -> '{$want_mgmt}'" . PHP_EOL;
    $changed++;
} else {
    echo "[suricata-logmgmt-apply] enable_log_mgmt already '{$cur_mgmt}' — no change." . PHP_EOL;
}

// --- Size caps + retention (only when a value was supplied) ----------------
// Each is an independent config key; a null arg means "leave as-is".
$targets = [
    'eve_log_limit_size'  => $eve_limit_kb,
    'http_log_limit_size' => $http_limit_kb,
    'eve_log_retention'   => $retention_hours,
    'http_log_retention'  => $retention_hours,
];
foreach ($targets as $key => $val) {
    if ($val === null) {
        continue;
    }
    $cur  = (string)(config_get_path("{$base}/{$key}") ?? '');
    $want = (string)$val;
    if ($cur !== $want) {
        config_set_path("{$base}/{$key}", $want);
        echo "[suricata-logmgmt-apply] {$key} '{$cur}' -> '{$want}'" . PHP_EOL;
        $changed++;
    } else {
        echo "[suricata-logmgmt-apply] {$key} already '{$cur}' — no change." . PHP_EOL;
    }
}

if ($changed > 0) {
    write_config('SURU: Suricata log management (' . ($enable ? 'enabled' : 'disabled') . ') — ' . $changed . ' value(s)');
    echo "[suricata-logmgmt-apply] config.xml updated: {$changed} value(s)." . PHP_EOL;
} else {
    echo "[suricata-logmgmt-apply] No changes — all log-management values already at target." . PHP_EOL;
}

// --- Optional immediate rotation pass --------------------------------------
// Run the package's own log-management cron once so an already-oversized
// eve.json is capped on this deploy, not at the next 5-minute tick. This is
// the same script pfSense schedules; it honours the settings just written.
if ($run_now && $enable) {
    $cron = '/usr/local/pkg/suricata/suricata_check_cron_misc.inc';
    if (file_exists($cron)) {
        echo "[suricata-logmgmt-apply] Running one rotation pass now ({$cron})..." . PHP_EOL;
        // php-cgi is the interpreter pfSense schedules this cron under — confirmed
        // live from this router's /etc/crontab 2026-07-03:
        //   */5 * * * * root /usr/bin/nice -n20 /usr/local/bin/php-cgi -f \
        //     /usr/local/pkg/suricata/suricata_check_cron_misc.inc
        // Re-entering via php-cgi keeps the include's is_platform_booting() /
        // config guards behaving exactly as they do under the scheduled run.
        $out = [];
        $rc  = 0;
        exec('/usr/local/bin/php-cgi -f ' . escapeshellarg($cron) . ' 2>&1', $out, $rc);
        echo "[suricata-logmgmt-apply] Rotation pass exit={$rc}." . PHP_EOL;
        // Propagate a real failure so the deploy's ERR trap fires instead of
        // reporting success while the oversized eve.json was never capped. The
        // config write above already succeeded (persisted), so the toggle is on
        // for the next 5-min cron even if this immediate pass failed — but the
        // "cap it now" guarantee this flag exists for did NOT hold, so fail loud.
        if ($rc !== 0) {
            fwrite(STDERR, "[suricata-logmgmt-apply] ERROR: immediate rotation pass failed (exit={$rc}):" . PHP_EOL
                . implode(PHP_EOL, $out) . PHP_EOL);
            exit(1);
        }
    } else {
        echo "[suricata-logmgmt-apply] WARN: {$cron} not found — skipping immediate rotation." . PHP_EOL;
    }
}
