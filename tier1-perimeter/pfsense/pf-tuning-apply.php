<?php
/**
 * SURU Tier 1 — pf firewall state-table tuning applier for pfSense
 *
 * Sets the pf maximum state-table size (system/maximumstates) and enables
 * adaptive state expiry (system/adaptive, adaptivestart, adaptiveend).
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/pf-tuning-apply.php \
 *       --max-states=400000 \
 *       [--adaptive] [--dry-run]
 *
 * XML key names confirmed 2026-07-01 from live router /tmp/rules.debug:
 *   system/maximumstates   — integer string; NULL = kernel default (observed: 402000)
 *   system/adaptive        — any non-empty value enables adaptive expiry
 *   system/adaptivestart   — % of max-states at which adaptive expiry begins (default 60%)
 *   system/adaptiveend     — % of max-states at which aggressive expiry begins (default 120%)
 *
 * Applied via filter_configure() which regenerates /tmp/rules.debug and reloads pf.
 *
 * Idempotent: re-running with identical values produces no config.xml diff.
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('filter.inc');

$max_states   = null;
$enable_adapt = false;
$dry_run      = false;

foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--max-states=(\d+)$/', $arg, $m)) {
        $max_states = (int)$m[1];
        if ($max_states < 10000 || $max_states > 10000000) {
            fwrite(STDERR, "[pf-tuning-apply] ERROR: --max-states must be 10000–10000000, got: {$m[1]}\n");
            exit(1);
        }
    } elseif ($arg === '--adaptive') {
        $enable_adapt = true;
    } elseif ($arg === '--dry-run') {
        $dry_run = true;
    } else {
        fwrite(STDERR, "[pf-tuning-apply] ERROR: unknown arg: {$arg}\n");
        exit(1);
    }
}

if ($max_states === null) {
    fwrite(STDERR, "[pf-tuning-apply] ERROR: --max-states=N is required\n");
    exit(1);
}

echo "[pf-tuning-apply] max-states target: {$max_states}" . PHP_EOL;
if ($enable_adapt) {
    echo "[pf-tuning-apply] adaptive: enabled (start=60% end=120%)" . PHP_EOL;
}
if ($dry_run) {
    echo "[pf-tuning-apply] dry-run: no changes will be written." . PHP_EOL;
    exit(0);
}

$changed = 0;

// system/maximumstates
$cur = config_get_path('system/maximumstates', null);
$want = (string)$max_states;
if ((string)$cur !== $want) {
    config_set_path('system/maximumstates', $want);
    echo "[pf-tuning-apply] system/maximumstates {$cur} -> {$want}" . PHP_EOL;
    $changed++;
} else {
    echo "[pf-tuning-apply] system/maximumstates already {$want} — no change." . PHP_EOL;
}

// Adaptive state expiry: prevents table exhaustion under load by expiring states
// more aggressively as the table fills.
if ($enable_adapt) {
    $adapt_start = (string)(int)($max_states * 0.60);
    $adapt_end   = (string)(int)($max_states * 1.20);
    foreach (['adaptive' => '1', 'adaptivestart' => $adapt_start, 'adaptiveend' => $adapt_end] as $k => $v) {
        $cur = config_get_path("system/{$k}", null);
        if ((string)$cur !== $v) {
            config_set_path("system/{$k}", $v);
            echo "[pf-tuning-apply] system/{$k} -> {$v}" . PHP_EOL;
            $changed++;
        }
    }
}

if ($changed > 0) {
    write_config('SURU: set pf state-table max-states=' . $max_states
        . ($enable_adapt ? ' adaptive=enabled' : ''));
    echo "[pf-tuning-apply] config.xml updated: {$changed} value(s)." . PHP_EOL;
    // filter_configure() regenerates /tmp/rules.debug and reloads pf with new limits.
    filter_configure();
    echo "[pf-tuning-apply] pf reloaded via filter_configure()." . PHP_EOL;
} else {
    echo "[pf-tuning-apply] No changes — pf tuning already at target." . PHP_EOL;
}
