<?php
/**
 * SURU Tier 1 — physical-NIC → carrier-alias resolver (shared library)
 *
 * SURICATA_IFACES is a physical-only contract (e.g. igb1,igb2). The pfSense
 * Suricata package, however, keys every instance on a pfSense LOGICAL
 * interface name (lan, opt1, …) — get_real_interface() on a bare physical
 * name returns empty and the instance silently never starts (the historic
 * `sec` bug). This library maps each physical NIC to a deterministic
 * "carrier" alias the package can run on:
 *
 *   1. A logical interface assigned DIRECTLY to the NIC wins (if === NIC).
 *   2. Else the VLAN alias with the LOWEST tag on that NIC (if === NIC.tag).
 *   3. No assigned logical interface at all → hard error.
 *
 * Under ips_mode_inline the package redirects a VLAN carrier's netmap
 * capture to the physical parent (suricata_generate_yaml.php:1350-1356 on
 * the router), so the physical NIC named in .env is literally what netmap
 * opens. Under ips_mode_legacy, pcap attaches to the carrier's real
 * interface (a VLAN sub-if on a trunk) — documented transitional limitation.
 *
 * Consumers: suricata-rules-apply.php, suricata-tuning-apply.php — staged
 * to the same remote directory and loaded via require_once(__DIR__ . '/...').
 */

/**
 * Resolve a list of physical NIC names to carrier aliases.
 *
 * @param string[] $physical_list e.g. ['igb1', 'igb2']
 * @return array<string,string>   physical => carrier alias, e.g.
 *                                ['igb1' => 'lan', 'igb2' => 'opt1']
 * Exits 2 with a remediation message on any invalid entry.
 */
function suru_resolve_physical_ifaces(array $physical_list): array {
  $logical = config_get_path('interfaces', []);
  $map = [];

  foreach ($physical_list as $nic) {
    // Reject VLAN sub-interfaces: the contract is the parent NIC.
    if (strpos($nic, '.') !== false) {
      fwrite(STDERR, "[suru-iface-resolve] ERROR: '{$nic}' is a VLAN sub-interface.\n");
      fwrite(STDERR, "  SURICATA_IFACES takes physical NICs only (e.g. igb1); the parent\n");
      fwrite(STDERR, "  covers all its VLANs in inline mode.\n");
      exit(2);
    }
    // Reject pfSense logical alias names: the contract changed to physical.
    if (array_key_exists($nic, $logical)) {
      $real = (string)($logical[$nic]['if'] ?? '?');
      fwrite(STDERR, "[suru-iface-resolve] ERROR: '{$nic}' is a pfSense logical alias (-> {$real}).\n");
      fwrite(STDERR, "  SURICATA_IFACES now takes physical NICs only. Use the parent NIC\n");
      fwrite(STDERR, "  (e.g. '" . preg_replace('/\..*$/', '', $real) . "') instead of '{$nic}'.\n");
      exit(2);
    }
    // Must exist as a device on this router.
    if (!does_interface_exist($nic)) {
      fwrite(STDERR, "[suru-iface-resolve] ERROR: physical interface '{$nic}' not found on this router.\n");
      exit(2);
    }

    // 1) Direct assignment wins.
    $carrier = null;
    foreach ($logical as $alias => $cfg) {
      if ((string)($cfg['if'] ?? '') === $nic) { $carrier = $alias; break; }
    }
    // 2) Else lowest-tag VLAN alias on this NIC.
    if ($carrier === null) {
      $best_tag = PHP_INT_MAX;
      foreach ($logical as $alias => $cfg) {
        $real = (string)($cfg['if'] ?? '');
        if (preg_match('/^' . preg_quote($nic, '/') . '\.(\d+)$/', $real, $m)) {
          $tag = (int)$m[1];
          if ($tag < $best_tag) { $best_tag = $tag; $carrier = $alias; }
        }
      }
    }
    if ($carrier === null) {
      fwrite(STDERR, "[suru-iface-resolve] ERROR: '{$nic}' has no assigned pfSense logical interface\n");
      fwrite(STDERR, "  (direct or VLAN). The Suricata package cannot run an instance without one.\n");
      fwrite(STDERR, "  Assign the NIC (or one of its VLANs) under Interfaces > Assignments first.\n");
      exit(2);
    }

    $map[$nic] = $carrier;
    echo "[suru-iface-resolve] {$nic} -> carrier alias '{$carrier}' (real: "
       . (string)($logical[$carrier]['if'] ?? '?') . ")" . PHP_EOL;
  }

  return $map;
}
