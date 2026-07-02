<?php
/**
 * SURU Tier 1 — Suricata inline-drop policy applier for pfSense
 *
 * Converts selected ET Open rule categories from the default `alert` action to
 * `drop`, so that under inline netmap IPS (SURICATA_IPS_MODE=inline)
 * matching packets are dropped in-flight. Without a drop policy an inline
 * instance enforces NOTHING — verified live 2026-07-02: the shipped ruleset is
 * 26,382 `alert` / 0 `drop`, and the pfSense package disables the legacy
 * pf-table block plugin in inline mode (suricata_generate_yaml.php gates it on
 * `ips_mode_legacy`). This applier is the hard precondition for the inline flip.
 *
 * Mechanism (all confirmed live on the router, 2026-07-02):
 *   - A SID-Mgmt "drop" list is an item under
 *     installedpackages/suricata/sid_mgmt_lists/item[] = {name, modtime,
 *     content(base64)}. A bare category name (e.g. `emerging-botcc`) on its own
 *     line matches the category branch of suricata_modify_sid_state()
 *     (suricata.inc:2419-2432) and flips every rule in that category
 *     `alert -> drop` (drop branch suricata.inc:2468-2471).
 *   - Global gate: installedpackages/suricata/config/0/auto_manage_sids = 'on'.
 *   - Per-interface: rule[N]/drop_sid_file = <list name>, plus a valid
 *     sid_state_order ('disable_enable' | 'enable_disable'; the drop step runs
 *     in both branches — suricata.inc:2892-2955).
 *   - Application happens inside sync_suricata_package_config() ->
 *     suricata_generate_yaml.php:1304 -> suricata_prepare_rule_files() ->
 *     suricata_auto_sid_mgmt() -> suricata_process_dropsid(). No rule
 *     re-download is required. NOTE: suricata_prepare_rule_files() early-returns
 *     unless the global $rebuild_rules is TRUE (suricata.inc:3241-3242), so this
 *     applier forces $rebuild_rules=true around the sync (a plain sync skips the
 *     rule rebuild "to save time").
 *
 * Staged in legacy, ACTIVATES on inline: the drop conversion itself is gated by
 * suricata.inc:2915 — it runs only when
 *   drop_sid_file set && blockoffenders==on && (block_drops_only==on || ips_mode==inline).
 * Under ips_mode_legacy the package deliberately does NOT convert alert->drop
 * (legacy blocks via the pf-table on alert, action-agnostic). This applier
 * therefore STAGES the policy (list + drop_sid_file + auto_manage_sids) in any
 * mode; the alert->drop rewrite materialises atomically when SURICATA_IPS_MODE
 * flips to inline and the rules applier sets ips_mode_inline. Confirmed live
 * 2026-07-02: staged in legacy, drop count stays 0 (gate not satisfied) until
 * inline. This is why the drop-policy step runs AFTER the rules applier in
 * pfsense.sh — the rules applier sets ips_mode first, then this rebuild applies.
 *
 * Scope: only SURU-managed interfaces (descr == 'SURU managed'). The list item
 * is SURU-owned by name; the four package `*-sample.conf` lists are untouched.
 *
 * Usage (run on router as root):
 *   sudo php suricata-drop-policy-apply.php \
 *     --ifaces=igb1,igb2 \
 *     --drop-categories=emerging-botcc,emerging-malware,emerging-exploit,emerging-attack_response \
 *     [--list-name=suru-drop-critical.conf] [--restart]
 *
 *   Empty/omitted --drop-categories REMOVES the SURU drop policy (revert):
 *   clears drop_sid_file on SURU-managed interfaces, deletes the SURU list item,
 *   and sets auto_manage_sids='off' iff no other interface still references a
 *   drop/enable/disable list.
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/suricata/suricata.inc');

define('SURU_DROP_LIST_DEFAULT', 'suru-drop-critical.conf');

$desired_physical = [];
$drop_categories  = [];
$list_name        = SURU_DROP_LIST_DEFAULT;
$do_restart       = false;

foreach (array_slice($argv, 1) as $arg) {
  if ($arg === '--restart') {
    $do_restart = true;
  } elseif (preg_match('/^--ifaces=(.+)$/', $arg, $m)) {
    $desired_physical = array_values(array_filter(array_map('trim', explode(',', $m[1]))));
  } elseif (preg_match('/^--drop-categories=(.*)$/', $arg, $m)) {
    $drop_categories = array_values(array_filter(array_map('trim', explode(',', $m[1]))));
  } elseif (preg_match('/^--list-name=(.+)$/', $arg, $m)) {
    $list_name = trim($m[1]);
  } else {
    fwrite(STDERR, "[suricata-drop-policy] ERROR: unknown arg: {$arg}\n");
    exit(2);
  }
}

// Validate category tokens: ET category basenames — letters, digits, . _ -
foreach ($drop_categories as $c) {
  if (!preg_match('/^[A-Za-z0-9._-]+$/', $c)) {
    fwrite(STDERR, "[suricata-drop-policy] ERROR: invalid category token: '{$c}'\n");
    exit(2);
  }
}
if (!preg_match('/^[A-Za-z0-9._-]+$/', $list_name)) {
  fwrite(STDERR, "[suricata-drop-policy] ERROR: invalid --list-name: '{$list_name}'\n");
  exit(2);
}

$revert = (count($drop_categories) === 0);
echo "[suricata-drop-policy] mode: " . ($revert ? "REVERT (remove drop policy)" : "APPLY " . count($drop_categories) . " categories") . PHP_EOL;

// Resolve physical NICs -> carrier aliases (physical-only interface contract).
$desired_ifaces = [];
if (count($desired_physical) > 0) {
  require_once(__DIR__ . '/suru-iface-resolve.php');
  $desired_ifaces = array_values(suru_resolve_physical_ifaces($desired_physical));
}

$interfaces = config_get_path('installedpackages/suricata/rule', []);
if (count($interfaces) === 0) {
  echo "[suricata-drop-policy] No Suricata interfaces configured — nothing to do." . PHP_EOL;
  exit(0);
}

// Which SURU-managed carriers are in scope.
$scope = [];
foreach ($interfaces as $iface) {
  if (($iface['descr'] ?? '') !== 'SURU managed') continue;
  $name = (string)($iface['interface'] ?? '');
  if (count($desired_ifaces) > 0 && !in_array($name, $desired_ifaces, true)) continue;
  $scope[$name] = true;
}
if (count($scope) === 0) {
  echo "[suricata-drop-policy] No SURU-managed interfaces in scope — nothing to do." . PHP_EOL;
  exit(0);
}

$dirty = false;

// ---------------------------------------------------------------------------
// Maintain the SURU-owned SID-Mgmt drop list item.
// ---------------------------------------------------------------------------
$lists = config_get_path('installedpackages/suricata/sid_mgmt_lists/item', []);
$list_idx = null;
foreach ($lists as $i => $it) {
  if (($it['name'] ?? '') === $list_name) { $list_idx = $i; break; }
}

if (!$revert) {
  // One category per line; bare names match the package's category branch.
  $body = "# SURU-managed inline-drop policy — do not edit by hand.\n"
        . "# Generated by suricata-drop-policy-apply.php. Each line is an ET\n"
        . "# category whose rules are converted alert -> drop for inline IPS.\n";
  foreach ($drop_categories as $c) {
    $body .= preg_replace('/\.rules$/', '', $c) . "\n";
  }
  $content_b64 = base64_encode($body);

  if ($list_idx === null) {
    $lists[] = ['name' => $list_name, 'modtime' => (string)time(), 'content' => $content_b64];
    $dirty = true;
    echo "[suricata-drop-policy] Created SID-Mgmt drop list '{$list_name}' ("
       . count($drop_categories) . " categories)\n";
  } elseif (($lists[$list_idx]['content'] ?? '') !== $content_b64) {
    $lists[$list_idx]['content'] = $content_b64;
    $lists[$list_idx]['modtime'] = (string)time();
    $dirty = true;
    echo "[suricata-drop-policy] Updated SID-Mgmt drop list '{$list_name}'\n";
  } else {
    echo "[suricata-drop-policy] Drop list '{$list_name}' already current\n";
  }
} else {
  if ($list_idx !== null) {
    // Only delete the shared list item when NO out-of-scope interface still
    // references it — a scoped (--ifaces-limited) revert must not orphan
    // another interface's drop_sid_file pointer.
    $any_ref_outside_scope = false;
    foreach ($interfaces as $iface) {
      $n = (string)($iface['interface'] ?? '');
      if (isset($scope[$n])) continue;
      if (($iface['drop_sid_file'] ?? '') === $list_name) { $any_ref_outside_scope = true; break; }
    }
    if (!$any_ref_outside_scope) {
      unset($lists[$list_idx]);
      $lists = array_values($lists);
      $dirty = true;
      echo "[suricata-drop-policy] Removed SID-Mgmt drop list '{$list_name}'\n";
    } else {
      echo "[suricata-drop-policy] Kept SID-Mgmt drop list '{$list_name}' — still referenced outside scope\n";
    }
  }
}
config_set_path('installedpackages/suricata/sid_mgmt_lists/item', $lists);

// ---------------------------------------------------------------------------
// Per-interface: set/clear drop_sid_file + sid_state_order on SURU carriers.
// ---------------------------------------------------------------------------
foreach ($interfaces as $idx => $iface) {
  $name = (string)($iface['interface'] ?? '');
  if (!isset($scope[$name])) continue;

  if (!$revert) {
    if (($iface['drop_sid_file'] ?? '') !== $list_name) {
      $interfaces[$idx]['drop_sid_file'] = $list_name;
      $dirty = true;
      echo "[suricata-drop-policy] carrier={$name}: drop_sid_file -> {$list_name}\n";
    }
    // sid_state_order must be valid or the auto-category step is skipped.
    $order = (string)($iface['sid_state_order'] ?? '');
    if ($order !== 'disable_enable' && $order !== 'enable_disable') {
      $interfaces[$idx]['sid_state_order'] = 'disable_enable';
      $dirty = true;
      echo "[suricata-drop-policy] carrier={$name}: sid_state_order -> disable_enable\n";
    }
  } else {
    if (($iface['drop_sid_file'] ?? '') === $list_name) {
      $interfaces[$idx]['drop_sid_file'] = '';
      $dirty = true;
      echo "[suricata-drop-policy] carrier={$name}: drop_sid_file cleared\n";
      // Clear the order we set on apply only if no other SID list remains on
      // this interface (leaving it is inert once auto_manage_sids goes off, but
      // symmetric cleanup avoids stale residue).
      if (empty($interfaces[$idx]['enable_sid_file']) && empty($interfaces[$idx]['disable_sid_file'])
          && empty($interfaces[$idx]['modify_sid_file'])) {
        if (!empty($interfaces[$idx]['sid_state_order'])) {
          $interfaces[$idx]['sid_state_order'] = '';
          echo "[suricata-drop-policy] carrier={$name}: sid_state_order cleared\n";
        }
      }
    }
  }
}
config_set_path('installedpackages/suricata/rule', $interfaces);

// ---------------------------------------------------------------------------
// Global auto_manage_sids gate.
// ---------------------------------------------------------------------------
$auto_now = (string)config_get_path('installedpackages/suricata/config/0/auto_manage_sids', 'off');
if (!$revert) {
  if ($auto_now !== 'on') {
    config_set_path('installedpackages/suricata/config/0/auto_manage_sids', 'on');
    $dirty = true;
    echo "[suricata-drop-policy] global auto_manage_sids -> on\n";
  }
} else {
  // Only turn the global gate off when NO interface still references any
  // enable/disable/drop list (ours or a manually-configured one).
  $any_ref = false;
  foreach (config_get_path('installedpackages/suricata/rule', []) as $iface) {
    if (!empty($iface['drop_sid_file']) || !empty($iface['enable_sid_file']) || !empty($iface['disable_sid_file'])) {
      $any_ref = true; break;
    }
  }
  if (!$any_ref && $auto_now !== 'off') {
    config_set_path('installedpackages/suricata/config/0/auto_manage_sids', 'off');
    $dirty = true;
    echo "[suricata-drop-policy] global auto_manage_sids -> off (no lists referenced)\n";
  }
}

if (!$dirty) {
  echo "[suricata-drop-policy] No changes — policy already at target. Done." . PHP_EOL;
  exit(0);
}

write_config('SURU: applied Suricata inline-drop policy (' . ($revert ? 'revert' : $list_name) . ')');

// suricata_prepare_rule_files() early-returns unless the global $rebuild_rules
// is TRUE (suricata.inc:3241-3242 — "if there is no reason to rebuild the
// rules, exit to save time"). A plain sync regenerates the yaml but skips the
// SID-Mgmt drop conversion. Force the rebuild so process_dropsid() actually
// rewrites the enforcing suricata.rules with alert->drop applied.
$GLOBALS['rebuild_rules'] = true;
echo "[suricata-drop-policy] Rebuilding rules with drop policy (rebuild_rules=true)..." . PHP_EOL;
sync_suricata_package_config();
$GLOBALS['rebuild_rules'] = false;

if ($do_restart) {
  echo "[suricata-drop-policy] --restart: restarting all Suricata interfaces..." . PHP_EOL;
  suricata_restart_all_interfaces();
  echo "[suricata-drop-policy] Restart issued." . PHP_EOL;
} else {
  echo "[suricata-drop-policy] No --restart; operator must restart to load the new ruleset." . PHP_EOL;
}

echo "[suricata-drop-policy] Done." . PHP_EOL;
