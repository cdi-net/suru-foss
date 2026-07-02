<?php
/**
 * SURU Tier 1 — Unbound DNS cache tuning applier for pfSense
 *
 * Sets unbound message-cache and rrset-cache sizes (used by pfBlockerNG DNSBL).
 * Larger caches reduce DNS latency and improve pfBlockerNG feed responsiveness
 * on routers with more RAM.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/dns-tuning-apply.php \
 *       --msg-cache-mb=50 --rrset-cache-mb=100
 *
 * XML key names confirmed 2026-07-01 from live router:
 *   unbound/msgcachesize   — string integer (MB); observed: '50'
 *   unbound/rrsetcachesize — string integer (MB); observed: NULL (unbound default)
 * unbound convention: rrset-cache-size = 2× msg-cache-size.
 *
 * Applied via services_unbound_configure() which regenerates unbound.conf.
 *
 * Idempotent: re-running with identical values produces no config.xml diff.
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('unbound.inc');

$msg_cache_mb  = null;
$rrset_cache_mb = null;

foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--msg-cache-mb=(\d+)$/', $arg, $m)) {
        $msg_cache_mb = (int)$m[1];
        if ($msg_cache_mb < 4 || $msg_cache_mb > 2048) {
            fwrite(STDERR, "[dns-tuning-apply] ERROR: --msg-cache-mb must be 4–2048, got: {$m[1]}\n");
            exit(1);
        }
    } elseif (preg_match('/^--rrset-cache-mb=(\d+)$/', $arg, $m)) {
        $rrset_cache_mb = (int)$m[1];
        if ($rrset_cache_mb < 4 || $rrset_cache_mb > 4096) {
            fwrite(STDERR, "[dns-tuning-apply] ERROR: --rrset-cache-mb must be 4–4096, got: {$m[1]}\n");
            exit(1);
        }
    } else {
        fwrite(STDERR, "[dns-tuning-apply] ERROR: unknown arg: {$arg}\n");
        exit(1);
    }
}

if ($msg_cache_mb === null) {
    fwrite(STDERR, "[dns-tuning-apply] ERROR: --msg-cache-mb=N is required\n");
    exit(1);
}
if ($rrset_cache_mb === null) {
    $rrset_cache_mb = $msg_cache_mb * 2;
    echo "[dns-tuning-apply] rrset-cache-mb defaulting to 2× msg-cache: {$rrset_cache_mb}" . PHP_EOL;
}

echo "[dns-tuning-apply] msg-cache-mb={$msg_cache_mb} rrset-cache-mb={$rrset_cache_mb}" . PHP_EOL;

$changed = 0;

// unbound/msgcachesize (MB, string)
$cur = config_get_path('unbound/msgcachesize', null);
$want = (string)$msg_cache_mb;
if ((string)$cur !== $want) {
    config_set_path('unbound/msgcachesize', $want);
    echo "[dns-tuning-apply] unbound/msgcachesize {$cur} -> {$want}" . PHP_EOL;
    $changed++;
} else {
    echo "[dns-tuning-apply] unbound/msgcachesize already {$want} — no change." . PHP_EOL;
}

// unbound/rrsetcachesize (MB, string)
$cur = config_get_path('unbound/rrsetcachesize', null);
$want = (string)$rrset_cache_mb;
if ((string)$cur !== $want) {
    config_set_path('unbound/rrsetcachesize', $want);
    echo "[dns-tuning-apply] unbound/rrsetcachesize {$cur} -> {$want}" . PHP_EOL;
    $changed++;
} else {
    echo "[dns-tuning-apply] unbound/rrsetcachesize already {$want} — no change." . PHP_EOL;
}

if ($changed > 0) {
    write_config('SURU: set unbound cache sizes msg=' . $msg_cache_mb . 'MB rrset=' . $rrset_cache_mb . 'MB');
    echo "[dns-tuning-apply] config.xml updated: {$changed} value(s)." . PHP_EOL;
    services_unbound_configure();
    echo "[dns-tuning-apply] Unbound reconfigured." . PHP_EOL;
} else {
    echo "[dns-tuning-apply] No changes — DNS cache sizes already at target." . PHP_EOL;
}
