<?php
/**
 * SURU Tier 1 — Suricata consolidated restart (A10) for pfSense
 *
 * Restarts every configured Suricata interface instance ONCE, via the pfSense
 * package's own suricata_restart_all_interfaces() (suricata.inc:138) — the
 * exact function suricata-{rules,drop-policy}-apply.php call internally,
 * so the restart behaviour is identical.
 *
 * WHY THIS EXISTS (A10 restart consolidation):
 *   The Suricata deploy chain runs up to three appliers in sequence
 *   (rules -> tuning -> drop-policy). Each calls
 *   sync_suricata_package_config() UNCONDITIONALLY (writes config.xml +
 *   rebuilds every per-interface yaml/rules file); a service restart only makes
 *   the running daemon reload that on-disk config. Previously each applier
 *   restarted itself when it changed something, so a fresh deploy that touched
 *   several appliers restarted Suricata several times in a row (x N interfaces).
 *   Now the deploy driver (scripts/platforms/pfsense.sh) suppresses the
 *   per-applier restart and, iff at least one applier actually changed config,
 *   invokes THIS script exactly once at the end of the chain — the daemon
 *   reloads a single time with all accumulated changes. On a fully idempotent
 *   (no-op) deploy the driver does not call this at all, so an unchanged
 *   re-deploy still triggers zero restarts.
 *
 * Invoked as: sudo php suricata-restart.php   (no arguments)
 * Idempotent: restarting an already-running Suricata is safe; this script is
 * only ever called when the driver has already determined a change occurred.
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

$rules = config_get_path('installedpackages/suricata/rule', []);
if (empty($rules)) {
    echo "[suricata-restart] No Suricata interfaces configured — nothing to restart." . PHP_EOL;
    exit(0);
}

echo "[suricata-restart] Restarting all " . count($rules) . " Suricata interface(s) (consolidated A10 restart)..." . PHP_EOL;
suricata_restart_all_interfaces();
echo "[suricata-restart] Restart issued." . PHP_EOL;
exit(0);
