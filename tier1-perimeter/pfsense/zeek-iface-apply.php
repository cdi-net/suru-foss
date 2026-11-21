<?php
/**
 * SURU Tier 1 — Zeek capture interface applier for pfSense
 *
 * Sets the Zeek capture interface in /conf/config.xml via the same PHP API
 * the pfSense GUI uses, then calls zeek_settings_resync() to regenerate
 * /usr/local/etc/node.cfg. If zeek_settings_resync() cannot resolve a
 * physical trunk interface name (e.g. igb1 has no pfSense logical alias),
 * node.cfg is written directly so the correct interface is always set.
 *
 * Why this exists: pfSense Zeek package stores the capture interface as
 * active_interface in installedpackages/zeek/config/0. zeek_settings_resync()
 * calls get_real_interface($iface) which only resolves pfSense logical names
 * (lan, wan, opt1 …). A physical trunk like igb1 is not a logical interface,
 * so get_real_interface() returns empty and node.cfg is never written —
 * leaving whatever was already on disk untouched.
 *
 * No boot-persistence mechanism needed (CONFIRMED by reading zeek.inc on
 * the router, 2026-06-23): zeek_settings_resync() only writes node.cfg
 * inside `if ($iface) { ... }` — when get_real_interface() returns empty
 * for a physical trunk name, the write is skipped entirely. It never
 * overwrites node.cfg with a broken default; it just leaves our last
 * direct write alone. Two earlier fix attempts (system/shellcmd, then a
 * cron/item polling every minute) were built on the wrong assumption that
 * this needed reapplying after every boot/resync — both were removed.
 * node.cfg, once correctly written by this applier, already survives every
 * reboot for free, confirmed by two live reboot tests.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/zeek-iface-apply.php igb1 [lb_procs]
 *
 * Optional second arg lb_procs: number of lb workers (integer 1–8, default 1).
 * Currently always writes type=standalone regardless of lb_procs — lb_method=netmap
 * requires both (a) the netmap kernel module loaded (kldstat | grep netmap) and
 * (b) zeekctl compiled with netmap support; neither is confirmed on this install.
 * lb_procs > 1 is accepted and logged for future cluster activation but does not
 * yet change the node.cfg layout. See SURU_HW_ZEEK_LB_PROCS hw-profile key.
 * Confirm netmap is loaded: kldstat | grep netmap
 * Relevant netmap sysctl tunables (persist in /etc/sysctl.conf):
 *   dev.netmap.buf_size   — per-buffer size in bytes (default 2048)
 *   dev.netmap.ring_num   — rings per NIC direction (default 2)
 *   dev.netmap.buf_num    — total netmap buffers; raise for high-throughput links
 *   hw.pci.enable_msix    — MSI-X for multi-queue NICs (default 1, keep enabled)
 * Note: suricata_get_supported_netmap_queues($if_real) in suricata.inc:238
 *   returns the NIC's maximum supported netmap queue count — query it to bound
 *   lb_procs when computing hw-profile values (hw-preflight.sh future work).
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/zeek.inc');
require_once('services.inc'); // configure_cron() — removing the superseded cron/item entry below

define('ZEEK_NODE_CFG', '/usr/local/etc/node.cfg');

if ($argc < 2 || empty(trim($argv[1]))) {
    fwrite(STDERR, "usage: php zeek-iface-apply.php <interface> [lb_procs]\n");
    fwrite(STDERR, "  interface: physical device name (e.g. igb1, em0)\n");
    fwrite(STDERR, "  lb_procs:  number of lb workers, 1-8 (default 1 = standalone)\n");
    exit(2);
}

$iface = trim($argv[1]);

if (!preg_match('/^[A-Za-z0-9._-]+$/', $iface)) {
    fwrite(STDERR, "[zeek-iface-apply] ERROR: invalid interface name: '{$iface}'\n");
    fwrite(STDERR, "  Allowed characters: A-Za-z0-9._-\n");
    exit(2);
}

// Optional second arg: lb_procs
$lb_procs = 1;
if ($argc >= 3 && trim($argv[2]) !== '') {
    $lb_procs_raw = (int)trim($argv[2]);
    if ($lb_procs_raw < 1 || $lb_procs_raw > 8) {
        fwrite(STDERR, "[zeek-iface-apply] ERROR: lb_procs must be 1–8, got: {$argv[2]}\n");
        exit(2);
    }
    $lb_procs = $lb_procs_raw;
}
echo "[zeek-iface-apply] lb_procs={$lb_procs}" . ($lb_procs > 1 ? " (lb_method=netmap; confirm: kldstat | grep netmap)" : "") . PHP_EOL;

// 1. Write active_interface to config.xml so the GUI reflects the setting.
config_set_path('installedpackages/zeek/config/0/active_interface', $iface);
write_config('SURU: set Zeek active_interface to ' . $iface);
echo "[zeek-iface-apply] Updated config.xml: active_interface={$iface}" . PHP_EOL;

// 2. Call pfSense Zeek package resync — regenerates node.cfg and networks.cfg
//    from config.xml. For logical interface names (lan, opt1…) this is
//    sufficient. For physical names that have no logical alias (igb1 trunk),
//    get_real_interface() returns empty and node.cfg is not written.
zeek_settings_resync();

// 3. Write node.cfg unconditionally.
//    When lb_procs > 1: a mini-cluster config (manager + worker) is required —
//    zeekctl does not allow lb_procs/lb_method on type=standalone nodes.
//    When lb_procs == 1: standalone config (simplest, no cluster overhead).
//    We always overwrite: zeek_settings_resync() either skipped the write
//    (physical trunk) or produced a standalone config that may need upgrading.
$hostname = config_get_path('installedpackages/zeek/config/0/hostname', 'localhost');

// Always write standalone mode: lb_method=netmap requires the netmap kernel
// module (kldstat | grep netmap) AND zeekctl compiled with netmap support —
// neither is confirmed on this install. SURU_HW_ZEEK_LB_PROCS is computed for
// future activation; until confirmed, log it but don't change the node layout.
if ($lb_procs > 1) {
    echo "[zeek-iface-apply] NOTE: lb_procs={$lb_procs} logged but not applied — netmap lb not confirmed available (kldstat | grep netmap)." . PHP_EOL;
}
$content = "# Managed by SURU deploy — do not edit manually.\n"
    . "# Source: tier1-perimeter/pfsense/zeek-iface-apply.php\n"
    . "# Mode: standalone\n"
    . "[zeek]\n"
    . "type=standalone\n"
    . "host={$hostname}\n"
    . "interface={$iface}\n";

if (file_put_contents(ZEEK_NODE_CFG, $content) === false) {
    fwrite(STDERR, "[zeek-iface-apply] ERROR: failed to write " . ZEEK_NODE_CFG . "\n");
    exit(4);
}
chmod(ZEEK_NODE_CFG, 0640);
echo "[zeek-iface-apply] node.cfg written: interface={$iface} mode=standalone" . PHP_EOL;

// --- Cleanup: remove the now-unnecessary cron/item self-heal job and its
// files from a previous version of this applier (2026-06-23). node.cfg is
// already durable without it — see the file header. Safe no-op if absent.
$zeek_dir     = '/usr/local/etc/zeek';
$zeek_marker  = $zeek_dir . '/suru-active-interface';
$zeek_boot_sh = $zeek_dir . '/suru-boot-apply.sh';

$cron_items = config_get_path('cron/item', []);
$cron_items_before = count($cron_items);
$cron_items = array_values(array_filter($cron_items, function ($i) use ($zeek_boot_sh) {
    return strpos((string)($i['command'] ?? ''), $zeek_boot_sh) === false;
}));
if (count($cron_items) !== $cron_items_before) {
    config_set_path('cron/item', $cron_items);
    write_config('SURU: removed superseded Zeek interface self-heal cron job');
    configure_cron();
    echo "[zeek-iface-apply] Removed superseded cron/item entry for {$zeek_boot_sh}." . PHP_EOL;
}
@unlink($zeek_boot_sh);
@unlink($zeek_marker);

echo "[zeek-iface-apply] Done. Caller must run 'zeekctl deploy' to activate." . PHP_EOL;
