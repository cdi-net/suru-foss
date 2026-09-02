<?php
/**
 * SURU Tier 1 — Zeek scripts XML applier for pfSense
 *
 * Takes a staging directory containing .zeek script files (SCP'd into
 * /tmp/suru-staging/zeek-scripts/ by the deploy driver). For each file:
 *   1. Copy to /usr/local/share/zeek/site/<basename>.zeek
 *      (flat layout — pfSense's zeek_script_resync emits `@load <basename>`
 *       which Zeek resolves via ZEEKPATH against site/).
 *   2. Register a row in installedpackages/zeekscript/config so the
 *      pfSense GUI shows the script.
 * Then call zeek_script_resync() — the same function the GUI calls on
 * Save in Services > Zeek > Scripts — which rebuilds local.zeek from XML.
 *
 * Why: pfSense's Zeek package's zeek_script_resync() overwrites
 * /usr/local/share/zeek/site/local.zeek with a hardcoded boilerplate +
 * @load lines built from installedpackages/zeekscript/config. Direct SCP
 * into local.zeek is silently destroyed on the next GUI save. Scripts
 * living on disk but unregistered in XML are not @load'd.
 *
 * Idempotent: SURU-managed scripts are tagged by zeekscriptpath. The
 * applier removes any zeekscript row whose zeekscriptpath matches one
 * being applied, then re-adds. User-added scripts are preserved.
 *
 * Usage (run on router as root):
 *   sudo php /tmp/suru-staging/zeek-scripts-apply.php /tmp/suru-staging/zeek-scripts
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('/usr/local/pkg/zeek.inc');

if ($argc < 2) {
  fwrite(STDERR, "usage: php zeek-scripts-apply.php <staging-dir>\n");
  exit(2);
}
$staging = rtrim($argv[1], '/');
if (!is_dir($staging)) {
  fwrite(STDERR, "[zeek-scripts-apply] staging dir not found: {$staging}\n");
  exit(2);
}

$site_dir = '/usr/local/share/zeek/site';
if (!is_dir($site_dir)) {
  fwrite(STDERR, "[zeek-scripts-apply] site dir missing: {$site_dir} (zeek package not installed?)\n");
  exit(2);
}

$files = glob($staging . '/*.zeek') ?: [];
sort($files);
if (count($files) === 0) {
  fwrite(STDERR, "[zeek-scripts-apply] no .zeek files in {$staging}\n");
  exit(3);
}

// Apply-time default for the foreign-domain detection: when the
// render left the @@SURU_AUTHORIZED_AD_DOMAINS@@ marker (env unset), the
// authorized set defaults to THIS router's configured system domain — read
// live from config, never hardcoded (same deployment-agnostic principle as
// unbound-localzones-apply.php). The domain is shape-gated (the same
// RFC 1035-ish contract render-zeek.sh / _policy_valid_domain enforce at
// render time) before it is written into Zeek source (CWE-20/74); on an
// empty/invalid domain the quoted
// marker entry is REMOVED entirely — fail-safe by omission, the same branch
// shape unbound-localzones-apply.php uses — leaving a valid empty set
// (nothing authorized, so AD-membership bursts still alert) rather than an
// empty-string entry whose suffix-match semantics would be undefined.
$suru_system_domain = strtolower((string) config_get_path('system/domain', ''));
if (!preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/', $suru_system_domain)) {
  $suru_system_domain = '';
}

$rows = [];
foreach ($files as $stage_path) {
  $name = basename($stage_path);
  $final = $site_dir . '/' . $name;
  $content = file_get_contents($stage_path);
  if ($content === false) {
    fwrite(STDERR, "[zeek-scripts-apply] read failed: {$stage_path}\n");
    exit(4);
  }
  if (strpos($content, '@@SURU_AUTHORIZED_AD_DOMAINS@@') !== false) {
    if ($suru_system_domain === '') {
      fwrite(STDERR, "[zeek-scripts-apply] WARN: system domain empty/non-DNS-shaped — no authorized-domains entry applied (empty set: every AD-membership burst will alert); set SURU_AUTHORIZED_AD_DOMAINS in .env\n");
      $content = str_replace('"@@SURU_AUTHORIZED_AD_DOMAINS@@"', '', $content);
      echo "[zeek-scripts-apply] {$name}: authorized AD domains set is EMPTY (no valid system domain)" . PHP_EOL;
    } else {
      $content = str_replace('@@SURU_AUTHORIZED_AD_DOMAINS@@', $suru_system_domain, $content);
      echo "[zeek-scripts-apply] {$name}: authorized AD domains defaulted to the system domain" . PHP_EOL;
    }
  }
  // Write-to-temp + rename so $final is atomically replaced — an interrupt
  // (reboot, PHP timeout) leaves either the old script or the new one,
  // never a truncated file that zeekctl deploy would then load.
  $tmp = $final . '.suru-tmp';
  if (file_put_contents($tmp, $content) === false) {
    fwrite(STDERR, "[zeek-scripts-apply] write failed: {$tmp}\n");
    exit(4);
  }
  @chmod($tmp, 0644);
  if (!rename($tmp, $final)) {
    @unlink($tmp);
    fwrite(STDERR, "[zeek-scripts-apply] rename failed: {$tmp} -> {$final}\n");
    exit(4);
  }
  $rows[] = [
    'zeekscriptpath' => $final,
    'name'           => 'SURU ' . basename($name, '.zeek'),
    'description'    => 'SURU Tier 2 detection script (managed by deploy)',
  ];
}

// Merge by zeekscriptpath: replace SURU-owned rows, preserve others.
$suru_paths = [];
foreach ($rows as $r) { $suru_paths[$r['zeekscriptpath']] = true; }

$existing = config_get_path('installedpackages/zeekscript/config', []);
$kept = [];
foreach ($existing as $r) {
  $p = isset($r['zeekscriptpath']) ? $r['zeekscriptpath'] : '';
  if (!isset($suru_paths[$p])) { $kept[] = $r; }
}
$merged = array_merge($kept, $rows);
config_set_path('installedpackages/zeekscript/config', $merged);

write_config('SURU: applied Zeek script registrations from rendered set');

echo "[zeek-scripts-apply] Copied and registered " . count($rows) . " SURU script(s):" . PHP_EOL;
foreach ($rows as $r) { echo "  + " . $r['zeekscriptpath'] . PHP_EOL; }
echo "[zeek-scripts-apply] Preserved " . count($kept) . " pre-existing non-SURU script row(s)" . PHP_EOL;

// zeek_script_resync() rebuilds /usr/local/share/zeek/site/local.zeek from
// the hardcoded boilerplate plus one `@load <basename>` per registered row.
// It does NOT restart zeek — caller runs 'zeekctl deploy' after this.
echo "[zeek-scripts-apply] Calling zeek_script_resync() to rebuild local.zeek..." . PHP_EOL;
zeek_script_resync();

echo "[zeek-scripts-apply] Done. Caller must run 'zeekctl deploy' to activate." . PHP_EOL;
