<?php
/**
 * SURU Tier 1 — Suricata safety revert (dead-man's-switch payload) for pfSense
 *
 * Flips every SURU-managed Suricata interface back to ips_mode_legacy and
 * rebuilds/restarts, restoring the FreeBSD host stack on any interface that was
 * in inline netmap mode. This is the payload the deploy-time dead-man's-switch
 * (scripts/lib/safety-timer.sh) runs autonomously on the router if the deploy
 * fails to disarm within the window — the failure mode being a self-lockout
 * where the inline flip cut the deploy's own SSH path (ROUTER_HOST lives on a
 * flipped NIC, e.g. igb1.10 on the igb1 trunk).
 *
 * Why legacy restores connectivity: legacy = pcap capture, so the NIC stays
 * attached to the OS network stack. Inline netmap takes exclusive control of the
 * NIC rings and bridges to the host stack; if that bridge is not up, the host
 * (and its management IP) is off the wire. Reverting to legacy releases netmap
 * and reconnects the NIC to the stack.
 *
 * Runs as root (the sleeper is launched via `sudo daemon`). No arguments — it
 * reverts ALL SURU-managed interfaces uniformly, which is the correct safe state
 * regardless of how far a partial inline flip got.
 *
 * Idempotent: if everything is already legacy it still syncs + restarts (cheap,
 * and guarantees the running daemons match the reverted config).
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

// Force the rule rebuild — suricata_prepare_rule_files() early-returns without
// this (suricata.inc:3241); a plain sync would not re-materialise the ruleset.
$GLOBALS['rebuild_rules'] = true;

$ifs = config_get_path('installedpackages/suricata/rule', []);
$changed = 0;
foreach ($ifs as $i => $r) {
  if (($r['descr'] ?? '') !== 'SURU managed') continue;
  if (($r['ips_mode'] ?? '') !== 'ips_mode_legacy') {
    $ifs[$i]['ips_mode'] = 'ips_mode_legacy';
    $ifs[$i]['ips_netmap_threads'] = '';
    $changed++;
    echo "[suricata-safety-revert] {$r['interface']}: ips_mode -> ips_mode_legacy\n";
  }
}

if ($changed > 0) {
  config_set_path('installedpackages/suricata/rule', $ifs);
  write_config('SURU safety timer: auto-revert Suricata to legacy (deploy did not disarm)');
  echo "[suricata-safety-revert] Reverted {$changed} interface(s) to legacy; config written.\n";
} else {
  echo "[suricata-safety-revert] All SURU-managed interfaces already legacy — resyncing anyway.\n";
}

// Rebuild per-interface yamls + rules, then restart so the running daemons drop
// netmap and reattach to the OS stack.
sync_suricata_package_config();
$GLOBALS['rebuild_rules'] = false;  // reset the flag after the rebuild (matches suricata-drop-policy-apply.php)
if (function_exists('suricata_restart_all_interfaces')) {
  suricata_restart_all_interfaces();
  echo "[suricata-safety-revert] Suricata restarted (all interfaces) in legacy mode.\n";
}

echo "[suricata-safety-revert] Done — host stack restored on any previously-inline NIC.\n";
