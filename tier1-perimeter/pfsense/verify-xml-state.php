<?php
/**
 * SURU Tier 1 — post-deploy XML state probe for pfSense
 *
 * Read-only: reports presence/absence of the SURU-managed nodes in
 * /conf/config.xml as `CHECK ...` lines, ending with `STATUS=done`
 * (or `STATUS=fail reason=...`). The driver stages and runs it like every
 * other applier:
 *   sudo /usr/local/bin/php /tmp/suru-staging/verify-xml-state.php
 */
ini_set('display_errors', '0');
$cfg = '/conf/config.xml';
if (!is_readable($cfg)) {
  echo "STATUS=fail reason=config_xml_unreadable" . PHP_EOL;
  exit(0);
}
$x = @simplexml_load_file($cfg);
if ($x === false) {
  echo "STATUS=fail reason=config_xml_parse_failed" . PHP_EOL;
  exit(0);
}
$ip = $x->installedpackages;

// 1. syslog-ng enabled + a SURU-tagged destination present
$sng_enable = (string)($ip->syslogng->config->enable ?? '');
$has_suru_dest = false;
foreach (($ip->syslogngadvanced->config ?? []) as $o) {
  $name = (string)$o->objectname;
  if (stripos($name, 'suru') !== false) { $has_suru_dest = true; break; }
}
echo "CHECK syslogng.enable=" . ($sng_enable === 'on' ? 'ok' : 'warn:' . ($sng_enable ?: 'unset')) . PHP_EOL;
echo "CHECK syslogng.suru_destination=" . ($has_suru_dest ? 'ok' : 'warn:no_suru_named_object') . PHP_EOL;

// 2. Zeek scripts: any zeekscript entries registered at all
$zeekscript_count = isset($ip->zeekscript->config) ? count($ip->zeekscript->config) : 0;
echo "CHECK zeekscript.count=" . ($zeekscript_count > 0 ? 'ok:' . $zeekscript_count : 'warn:0') . PHP_EOL;

// 3. Suricata: each interface has a non-empty rulesets list
$any_iface = false; $any_rulesets_empty = false;
foreach (($ip->suricata->rule ?? []) as $r) {
  $any_iface = true;
  $rs = trim((string)$r->rulesets);
  if ($rs === '') { $any_rulesets_empty = true; break; }
}
if (!$any_iface) {
  echo "CHECK suricata.interfaces=warn:no_iface_configured" . PHP_EOL;
} else {
  echo "CHECK suricata.rulesets=" . ($any_rulesets_empty ? 'warn:empty_on_some_iface' : 'ok') . PHP_EOL;
}

// 4. pfBlockerNG DNSBL feeds — should have at least one SURU-managed entry,
//    and every SURU-managed entry's action MUST be the literal "unbound".
//    pfBlockerNG's cron list-builder (pfblockerng.inc) only queues an alias
//    for DNSBL download/compile when action=='unbound'; any other value
//    (e.g. an IP-alias-style "Deny Both") silently routes it into the IP-deny
//    build path instead, where domain content never downloads. Live-verified
//    2026-06-23: every SURU_ DNSBL alias on the router had action="Deny Both"
//    and zero files in /var/db/pfblockerng/dnsblorig/ — this CHECK exists to
//    catch a regression of that exact bug class before it reaches the router.
$pfb = $ip->pfblockerngdnsbl->config ?? [];
$has_suru_pfb = false;
$bad_action_aliases = [];
foreach ($pfb as $f) {
  $is_suru = stripos((string)$f->aliasname, 'suru') !== false || stripos((string)$f->aliasname, 'pfb_') !== false;
  if ($is_suru) {
    $has_suru_pfb = true;
    if ((string)$f->action !== 'unbound') {
      $bad_action_aliases[] = (string)$f->aliasname . ':' . (string)$f->action;
    }
  }
}
echo "CHECK pfblockerngdnsbl.suru_entry=" . ($has_suru_pfb ? 'ok' : 'warn:no_suru_named_feed') . PHP_EOL;
echo "CHECK pfblockerngdnsbl.action_unbound=" . (empty($bad_action_aliases) ? 'ok' : 'warn:' . implode(',', $bad_action_aliases)) . PHP_EOL;

echo "STATUS=done" . PHP_EOL;
