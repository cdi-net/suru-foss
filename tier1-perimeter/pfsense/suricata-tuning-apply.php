<?php
/**
 * SURU Tier 1 — Suricata per-interface engine tuning applier for pfSense
 *
 * Sets hardware-adaptive detect profile and memcap values on all SURU-managed
 * Suricata interfaces. Interface rule selection (suricata-rules-apply.php) is
 * NOT touched.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/suricata-tuning-apply.php \
 *       --profile=low|medium|high \
 *       [--stream-memcap=Xmb] [--reassembly-memcap=Xmb] [--defrag-memcap=Xmb] \
 *       [--ifaces=igb1,igb2] [--restart]
 *
 * --ifaces takes PHYSICAL NIC names (physical-only contract); each resolves
 * to its pfSense carrier alias via suru-iface-resolve.php (staged alongside).
 *
 * XML key names confirmed 2026-07-01 from live router:
 *   grep -r 'stream_memcap\|reassembly_memcap\|frag_memcap' \
 *        /usr/local/pkg/suricata/suricata_generate_yaml.php
 *   detect_eng_profile  — low|medium|high
 *   stream_memcap       — bytes integer (pfSense default: 268435456 = 256 MB)
 *   reassembly_memcap   — bytes integer (pfSense default: 131217728 = ~125 MB)
 *   frag_memcap         — bytes integer (pfSense default: 33554432 = 32 MB)
 *
 * Restart function confirmed 2026-07-01 from live router:
 *   grep -n 'function suricata_' /usr/local/pkg/suricata/suricata.inc
 *   suricata_restart_all_interfaces() at suricata.inc:138 (no args)
 *   suricata_reload_config($suricatacfg, $signal=SIGUSR2) at suricata.inc:155
 *   Using suricata_restart_all_interfaces() — simpler, no per-interface arg needed.
 *
 * Idempotent: re-running with identical values produces no config.xml diff.
 *
 * Relates to: hw-profile.conf SURU_HW_SURICATA_* keys.
 * See: tier1-perimeter/scripts/lib/hw-preflight.sh
 */

require_once('config.inc');
require_once('config.lib.inc');

// Suricata package provides sync_suricata_package_config() + restart functions
if (file_exists('/usr/local/pkg/suricata/suricata.inc')) {
    require_once('/usr/local/pkg/suricata/suricata.inc');
    $pkg_available = true;
} else {
    fwrite(STDERR, "[suricata-tuning-apply] WARN: Suricata package not found at " .
        "/usr/local/pkg/suricata/suricata.inc — will write XML but cannot resync.\n");
    $pkg_available = false;
}

// ---------------------------------------------------------------------------
// Helper: parse "Xmb" memcap string → bytes integer.
// Accepts "64mb", "256mb" etc. (hw-profile.conf format).
// Returns null on unrecognised format — caller uses the pfSense default.
// ---------------------------------------------------------------------------
function suru_parse_memcap_bytes(string $val): ?int {
    if (preg_match('/^(\d+)mb$/i', $val, $m)) {
        return (int)$m[1] * 1048576;
    }
    if (ctype_digit($val) && $val !== '') {
        return (int)$val;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
$profile          = 'medium';   // detect_eng_profile default
$stream_memcap    = null;        // null = do not touch (keep pfSense default)
$reassembly_memcap = null;
$defrag_memcap    = null;
$ifaces           = [];
$do_restart       = false;

foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--profile=(low|medium|high)$/', $arg, $m)) {
        $profile = $m[1];
    } elseif (preg_match('/^--stream-memcap=(\S+)$/', $arg, $m)) {
        $stream_memcap = suru_parse_memcap_bytes($m[1]);
        if ($stream_memcap === null) {
            fwrite(STDERR, "[suricata-tuning-apply] ERROR: invalid --stream-memcap value: {$m[1]}\n");
            exit(1);
        }
    } elseif (preg_match('/^--reassembly-memcap=(\S+)$/', $arg, $m)) {
        $reassembly_memcap = suru_parse_memcap_bytes($m[1]);
        if ($reassembly_memcap === null) {
            fwrite(STDERR, "[suricata-tuning-apply] ERROR: invalid --reassembly-memcap value: {$m[1]}\n");
            exit(1);
        }
    } elseif (preg_match('/^--defrag-memcap=(\S+)$/', $arg, $m)) {
        $defrag_memcap = suru_parse_memcap_bytes($m[1]);
        if ($defrag_memcap === null) {
            fwrite(STDERR, "[suricata-tuning-apply] ERROR: invalid --defrag-memcap value: {$m[1]}\n");
            exit(1);
        }
    } elseif (preg_match('/^--ifaces=([A-Za-z0-9,._-]+)$/', $arg, $m)) {
        $ifaces = array_filter(array_map('trim', explode(',', $m[1])));
    } elseif ($arg === '--restart') {
        $do_restart = true;
    } else {
        fwrite(STDERR, "[suricata-tuning-apply] ERROR: unknown arg: {$arg}\n");
        exit(1);
    }
}

echo "[suricata-tuning-apply] detect_eng_profile target: {$profile}" . PHP_EOL;
if ($stream_memcap !== null) {
    echo "[suricata-tuning-apply] stream_memcap target: {$stream_memcap} bytes" . PHP_EOL;
}
if ($reassembly_memcap !== null) {
    echo "[suricata-tuning-apply] reassembly_memcap target: {$reassembly_memcap} bytes" . PHP_EOL;
}
if ($defrag_memcap !== null) {
    echo "[suricata-tuning-apply] frag_memcap target: {$defrag_memcap} bytes" . PHP_EOL;
}

// ---------------------------------------------------------------------------
// --ifaces now carries PHYSICAL NIC names (physical-only interface contract).
// Resolve each to its pfSense carrier alias so the XML filter below matches;
// suru-iface-resolve.php is staged alongside this applier.
// ---------------------------------------------------------------------------
if (!empty($ifaces)) {
    require_once(__DIR__ . '/suru-iface-resolve.php');
    $ifaces = array_values(suru_resolve_physical_ifaces($ifaces));
}

// ---------------------------------------------------------------------------
// Walk installedpackages/suricata/rule[] and apply tuning values
// Same interface-scoping pattern as suricata-rules-apply.php.
// ---------------------------------------------------------------------------
$rules = config_get_path('installedpackages/suricata/rule', []);
if (empty($rules)) {
    echo "[suricata-tuning-apply] No Suricata interfaces configured in config.xml — nothing to do." . PHP_EOL;
    exit(0);
}

$changed = 0;
foreach ($rules as $idx => $rule) {
    $iface = (string)($rule['interface'] ?? '');

    // Filter to requested interfaces when --ifaces= is given
    if (!empty($ifaces) && !in_array($iface, $ifaces, true)) {
        continue;
    }

    // detect_eng_profile
    $current_profile = (string)($rule['detect_eng_profile'] ?? '');
    if ($current_profile !== $profile) {
        config_set_path("installedpackages/suricata/rule/{$idx}/detect_eng_profile", $profile);
        echo "[suricata-tuning-apply] iface={$iface}: detect_eng_profile {$current_profile} -> {$profile}" . PHP_EOL;
        $changed++;
    } else {
        echo "[suricata-tuning-apply] iface={$iface}: detect_eng_profile already {$profile} — no change." . PHP_EOL;
    }

    // stream_memcap (XML key confirmed: suricata_generate_yaml.php, 2026-07-01)
    if ($stream_memcap !== null) {
        $cur = (string)($rule['stream_memcap'] ?? '268435456');
        $want = (string)$stream_memcap;
        if ($cur !== $want) {
            config_set_path("installedpackages/suricata/rule/{$idx}/stream_memcap", $want);
            echo "[suricata-tuning-apply] iface={$iface}: stream_memcap {$cur} -> {$want}" . PHP_EOL;
            $changed++;
        }
    }

    // reassembly_memcap (XML key confirmed: suricata_generate_yaml.php, 2026-07-01)
    if ($reassembly_memcap !== null) {
        $cur = (string)($rule['reassembly_memcap'] ?? '131217728');
        $want = (string)$reassembly_memcap;
        if ($cur !== $want) {
            config_set_path("installedpackages/suricata/rule/{$idx}/reassembly_memcap", $want);
            echo "[suricata-tuning-apply] iface={$iface}: reassembly_memcap {$cur} -> {$want}" . PHP_EOL;
            $changed++;
        }
    }

    // frag_memcap (XML key confirmed: suricata_generate_yaml.php, 2026-07-01)
    // Note: our hw-profile key is SURU_HW_SURICATA_DEFRAG_MEMCAP; pfSense's XML
    // key is frag_memcap — the names differ, the value is the same concept.
    if ($defrag_memcap !== null) {
        $cur = (string)($rule['frag_memcap'] ?? '33554432');
        $want = (string)$defrag_memcap;
        if ($cur !== $want) {
            config_set_path("installedpackages/suricata/rule/{$idx}/frag_memcap", $want);
            echo "[suricata-tuning-apply] iface={$iface}: frag_memcap {$cur} -> {$want}" . PHP_EOL;
            $changed++;
        }
    }
}

if ($changed > 0) {
    write_config('SURU: set Suricata tuning (profile=' . $profile . ') on ' . $changed . ' value(s)');
    echo "[suricata-tuning-apply] config.xml updated: {$changed} value(s)." . PHP_EOL;

    if ($pkg_available && function_exists('sync_suricata_package_config')) {
        sync_suricata_package_config();
        echo "[suricata-tuning-apply] sync_suricata_package_config() applied." . PHP_EOL;
    }

    if ($do_restart) {
        // suricata_restart_all_interfaces() confirmed at suricata.inc:138 (no args).
        // Using restart (not per-interface reload) since detect profile + memcap
        // changes require a full restart to take effect.
        if ($pkg_available && function_exists('suricata_restart_all_interfaces')) {
            suricata_restart_all_interfaces();
            echo "[suricata-tuning-apply] Suricata restarted (all interfaces)." . PHP_EOL;
        } else {
            echo "[suricata-tuning-apply] WARN: restart requested but suricata_restart_all_interfaces() unavailable." . PHP_EOL;
        }
    }
} else {
    echo "[suricata-tuning-apply] No changes — all tuning values already at target on all scoped interfaces." . PHP_EOL;
}
