<?php
/**
 * SURU Tier 1 — Clear all Suricata interface configs for a fresh deploy
 *
 * Removes all entries from installedpackages/suricata/rule[] and calls
 * sync_suricata_package_config() to clean up any stale per-interface yamls.
 * Run this before a fresh SURU deploy to ensure no stale interface configs remain.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/suricata-clear-interfaces.php
 *
 * After running, execute the normal SURU deploy which re-adds interfaces from .env.
 */

require_once('config.inc');
require_once('config.lib.inc');

if (file_exists('/usr/local/pkg/suricata/suricata.inc')) {
    require_once('/usr/local/pkg/suricata/suricata.inc');
    $pkg_available = true;
} else {
    fwrite(STDERR, "[suricata-clear] WARN: Suricata package not found — will clear XML only.\n");
    $pkg_available = false;
}

$rules = config_get_path('installedpackages/suricata/rule', []);
$count = count($rules);

if ($count === 0) {
    echo "[suricata-clear] No Suricata interface entries found — nothing to clear." . PHP_EOL;
    exit(0);
}

echo "[suricata-clear] Clearing {$count} Suricata interface entries:" . PHP_EOL;
foreach ($rules as $idx => $r) {
    echo "  rule[{$idx}]: interface=" . ($r['interface'] ?? '?') . " uuid=" . ($r['uuid'] ?? 'N/A') . PHP_EOL;
}

// Stop all running Suricata instances first
if ($pkg_available && function_exists('suricata_stop_all_interfaces')) {
    echo "[suricata-clear] Stopping all Suricata interfaces..." . PHP_EOL;
    suricata_stop_all_interfaces();
} elseif ($pkg_available && function_exists('suricata_stop')) {
    foreach ($rules as $r) {
        suricata_stop($r);
    }
    echo "[suricata-clear] Stopped all Suricata interfaces." . PHP_EOL;
}

// Clear the interface rule entries
config_set_path('installedpackages/suricata/rule', []);
write_config('SURU: cleared all Suricata interface configs for fresh deploy');
echo "[suricata-clear] config.xml cleared." . PHP_EOL;

// Regenerate (now empty) per-interface yamls
if ($pkg_available && function_exists('sync_suricata_package_config')) {
    sync_suricata_package_config();
    echo "[suricata-clear] sync_suricata_package_config() applied (empty config)." . PHP_EOL;
}

echo "[suricata-clear] Done. Run SURU deploy to re-add interfaces from .env." . PHP_EOL;
