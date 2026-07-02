# =============================================================================
# SURU Platform — syslog-ng pfSense Comprehensive Security Log Forwarder
# Version: 2.8.0
# Target pfSense: 2.7.x / 2.8.x / 24.x (FreeBSD 14, syslog-ng 4.6)
# Install path: /usr/local/etc/syslog-ng.conf
#
# TEMPLATE: tier1-perimeter/templates/pfsense/syslog-ng.conf.tpl
# Rendered by: tier1-perimeter/scripts/platforms/pfsense.sh _pf_deploy_syslogng
#
# Template tokens (substituted by pfsense.sh _pf_deploy_syslogng):
#   @@FRONTDOOR_SYSLOG_SNI@@          — SNI hostname for the frontdoor stream demux (env: FRONTDOOR_SYSLOG_SNI, default: syslog.suru.local)
#   @@FRONTDOOR_PORT@@                — Frontdoor port, literal 443 (env: FRONTDOOR_PORT, default: 443)
#   @@SENSOR_NAME@@                   — human label for this sensor    (env: ROUTER_SENSOR_NAME, default: pfsense-tier1)
#   @@WAN_IFACE@@                     — WAN interface (informational; Suricata uses glob) (env: WAN_IFACE, default: igb0)
#   @@LAN_IFACE@@                     — LAN interface (informational; Suricata uses glob) (env: LAN_IFACE, default: igb1)
#   @@SYSLOGNG_DISK_BUFFER_BYTES@@    — hw-adaptive reliable disk-buffer capacity in bytes
#                                       (env: SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES from hw-profile.conf)
#                                       Default: 4294967296 (4 GB). Scales 1–8 GB with available disk.
#
# Log sources forwarded (pfSense live paths — confirmed 2026-05-28 on pfSense 2.7/FreeBSD 14):
#   Suricata EVE  /var/log/suricata/suricata_*/eve.json   wildcard-file(recursive), all iface UUID dirs
#   Zeek          /var/log/zeek/*.log                     follow-tail, optional — survives Zeek stop/absent dir
#   Resolver      /var/log/resolver.log                   unbound output (pfSense services_unbound.inc)
#   DHCP (Zeek)   /var/log/zeek/dhcp.log                  network-observed leases — AUTHORITATIVE DHCP source
#   DHCP (legacy) /var/log/dhcpd.log                      ISC dhcpd direct log — DEAD on Kea-based pfSense (kept for ISC installs)
#   Firewall/auth /var/run/log, /var/run/logpriv          pfSense syslog unix sockets
#   pfBlockerNG   /var/log/pfblockerng/{dnsbl,ip_block}.log — NOT pfblockerng.log
#                 (that file is pfBlockerNG's status/admin log — "Saving
#                 configuration", "Restarting firewall filter daemon" — never
#                 block events; confirmed live on-router 2026-06-23)
#   VPN           /var/log/{openvpn,ipsec}.log
#
# TLS cert paths (written by deploy script):
#   /usr/local/etc/syslog-ng/tls/ca/root-ca.pem  — SURU Root CA (ca-dir + openssl rehash symlinks)
#   /usr/local/etc/syslog-ng/tls/client.pem      — client certificate
#   /usr/local/etc/syslog-ng/tls/client-key.pem  — client private key (0600)
# =============================================================================

@version: 4.6
@include "scl.conf"

options {
    flush_lines(0);
    time_reopen(10);
    log_fifo_size(10000);
    chain_hostnames(off);
    use_dns(no);
    use_fqdn(yes);
    dns_cache(no);
    keep_hostname(yes);
    stats(freq(3600));
    bad_hostname("^gconfd$");
    trim_large_messages(yes);
};

# --- Destination -------------------------------------------------------------
# NOTE: the JSON template is INLINED into the destination below, NOT defined as a
# named `template t_json_base {}` object. The pfSense syslog-ng package renders
# this config via syslogng_resync()/syslogng_build_conf(), which re-emits objects
# grouped by type in a FIXED order — templates are emitted AFTER destinations.
# syslog-ng resolves source/filter/log references globally (forward refs are fine),
# but a `template(NAME)` whose NAME is not yet defined silently degrades to a
# literal inline template string "NAME". A named template emitted after the
# destination that references it therefore ships the constant text "t_json_base"
# on every message instead of JSON — breaking all SIEM ingestion (incident
# 2026-06-23). Inlining removes the only order-sensitive reference, so emit order
# no longer matters. Do NOT reintroduce a named template here.

destination d_siem_tls {
    network(
        "@@FRONTDOOR_SYSLOG_SNI@@"
        port(@@FRONTDOOR_PORT@@)
        transport("tls")
        tls(
            ca-dir("/usr/local/etc/syslog-ng/tls/ca")
            cert-file("/usr/local/etc/syslog-ng/tls/client.pem")
            key-file("/usr/local/etc/syslog-ng/tls/client-key.pem")
            peer-verify(required-trusted)
            ssl-options(no-sslv2, no-sslv3, no-tlsv1, no-tlsv11)
            sni(yes)
        )
        keep-alive(yes)
        so-keepalive(yes)
        log-fifo-size(10000)
        throttle(0)
        # Inlined JSON template (see destination header note — must NOT be a
        # named `template t_json_base` object: resync re-emits templates after
        # destinations, degrading a named reference to the literal string).
        template("$(format-json \
            time=$ISODATE \
            host=$HOST \
            facility=$FACILITY \
            severity=$LEVEL \
            program=$PROGRAM \
            pid=$PID \
            message=$MSG \
            raw_message=$RAWMSG \
            syslog_tag=$SYSLOGTAG \
            source_type=syslog \
            sensor=@@SENSOR_NAME@@ \
            --scope dot-nv-pairs \
        )\n")
        # Reliable disk-buffer: every message written to disk before ACK.
        # Survives syslog-ng restarts and SIEM outages — position is tracked
        # in the queue file and replay is automatic on reconnect.
        # dir() omitted: uses syslog-ng default (/var/db, same as persist file).
        # capacity-bytes: hw-adaptive ceiling (1–8 GB), set by hw-preflight from
        #   SURU_HW_SYSLOGNG_DISK_BUFFER_BYTES (scales with available disk space).
        # flow-control-window-bytes: 10 MB in-memory window before spilling to disk.
        disk-buffer(
            reliable(yes)
            capacity-bytes(@@SYSLOGNG_DISK_BUFFER_BYTES@@)
            flow-control-window-bytes(10485760)
        )
    );
};

# --- Sources -----------------------------------------------------------------

source s_pfsense_syslog {
    # flags(syslog-protocol): pfSense syslogd launches with -O rfc5424, so every
    # message on the socket is in RFC 5424 format (<PRI>1 ISO8601 HOST APP PID - - MSG).
    # Without this flag, syslog-ng's BSD (RFC 3164) parser extracts the version field
    # "1" as $PROGRAM — breaking every program() filter. With syslog-protocol, syslog-ng
    # parses RFC 5424 correctly: $PROGRAM=APPNAME, $PID=PROCID, $MSG=message body.
    # $FACILITY and $LEVEL are also parsed from <PRI>, so facility() filters work too.
    unix-dgram("/var/run/log" flags(syslog-protocol));
    unix-dgram("/var/run/logpriv" perm(0600) flags(syslog-protocol));
};

# MITRE ATT&CK: TA0009 Collection / T1005 Data from Local System
# wildcard-file(recursive) discovers all per-interface UUID dirs automatically
# (e.g. suricata_igb1.1020574/eve.json). New interfaces are picked up without
# a config change or service restart.
source s_suricata_eve {
    wildcard-file(
        base-dir("/var/log/suricata")
        filename-pattern("eve.json")
        recursive(yes)
        follow-freq(1)
        flags(no-parse)
        program-override("suricata")
    );
};

# MITRE ATT&CK: TA0009 Collection / T1005 Data from Local System
# syslog-ng 4.x file() monitors for file creation automatically — missing files
# do not fail startup and optional() is not a valid keyword in 4.8.1.
# Log path: Log::default_logdir in suru-base.zeek directs Zeek output to /var/log/zeek.
source s_zeek_conn   { file("/var/log/zeek/conn.log"   follow-freq(1) flags(no-parse) program-override("zeek-conn")); };
source s_zeek_dns    { file("/var/log/zeek/dns.log"    follow-freq(1) flags(no-parse) program-override("zeek-dns")); };
source s_zeek_http   { file("/var/log/zeek/http.log"   follow-freq(1) flags(no-parse) program-override("zeek-http")); };
source s_zeek_ssl    { file("/var/log/zeek/ssl.log"    follow-freq(1) flags(no-parse) program-override("zeek-ssl")); };
source s_zeek_notice { file("/var/log/zeek/notice.log" follow-freq(1) flags(no-parse) program-override("zeek-notice")); };
source s_zeek_weird  { file("/var/log/zeek/weird.log"  follow-freq(1) flags(no-parse) program-override("zeek-weird")); };
source s_zeek_files  { file("/var/log/zeek/files.log"  follow-freq(1) flags(no-parse) program-override("zeek-files")); };
# MITRE ATT&CK: TA0007 Discovery / T1018 Remote System Discovery
# Zeek DHCP analyzer log — network-observed lease activity (IP<->MAC<->hostname).
# Backend-agnostic: works whether pfSense runs ISC dhcpd or Kea. Authoritative
# DHCP source here (the /var/log/dhcpd.log path below is dead on Kea-based pfSense).
source s_zeek_dhcp   { file("/var/log/zeek/dhcp.log"   follow-freq(1) flags(no-parse) program-override("zeek-dhcp")); };

# MITRE ATT&CK: TA0001 Initial Access / T1190 Exploit Public-Facing Application
# File-tail of pfSense's syslogd-written firewall log. Using file source avoids
# the syslogd/syslog-ng unix-socket competition — syslogd wins most socket
# datagrams; the log file is authoritative and receives every filterlog event.
# pfSense syslogd writes RFC 5424 lines; flags(no-parse) preserves the full line
# so Logstash can extract the precise RFC 5424 timestamp.
source s_filter_log { file("/var/log/filter.log" follow-freq(1) flags(no-parse) program-override("filterlog")); };

# pfBlockerNG writes per-event CSV lines (not the legacy pipe-delimited
# format) to dnsbl.log (DNS blocks) and ip_block.log (firewall IP blocks).
# pfblockerng.log is NOT a block-event log — it only carries status/admin
# messages ("Saving configuration", daemon restarts) and was wrongly tailed
# here in earlier versions of this template; ip_block.log is root-owned
# 0600 but syslog-ng runs as root on pfSense so the file() source reads it.
source s_pfblocker_dnsbl { file("/var/log/pfblockerng/dnsbl.log"    follow-freq(1) flags(no-parse) program-override("pfblockerng-dnsbl")); };
source s_pfblocker_ip    { file("/var/log/pfblockerng/ip_block.log" follow-freq(1) flags(no-parse) program-override("pfblockerng-ip")  ); };
source s_openvpn         { file("/var/log/openvpn.log"                 follow-freq(1) flags(no-parse) program-override("openvpn")          ); };
source s_ipsec           { file("/var/log/ipsec.log"                   follow-freq(1) flags(no-parse) program-override("ipsec")            ); };

# MITRE ATT&CK: TA0009 Collection / T1005 Data from Local System
# pfSense routes unbound output to /var/log/resolver.log (services_unbound.inc).
# program-override("unbound") preserves ECS program demux in Tier 3 pipelines.
source s_resolver { file("/var/log/resolver.log" follow-freq(1) flags(no-parse) program-override("unbound")); };

# MITRE ATT&CK: TA0009 Collection / T1005 Data from Local System
# File-tail ISC dhcpd direct log (services_dhcp.inc). Supplements syslog path
# for reliability across dhcpd log rotation. Tier 3 Logstash deduplicates on
# message content + timestamp when both paths deliver the same event.
source s_dhcpd { file("/var/log/dhcpd.log" follow-freq(1) flags(no-parse) program-override("dhcpd")); };

# MITRE ATT&CK: TA0001 Initial Access mitigation / TA0011 Command and Control
# disruption — audit trail for T0b dynamic single-IP perimeter blocks. Written
# by tier1-perimeter/scripts/lib/api.sh's api_block_ip/api_unblock_ip via the
# same _api_pfsense_exec call that performs the alias mutation (atomic from the
# caller's perspective). New capability — library-only, not wired into any
# always-on path; see api.sh's "DYNAMIC PERIMETER BLOCK — T0b" section.
# [STUB: alias mutation + reload calls unconfirmed — needs live pfSense test]
source s_suru_perimeter_block { file("/var/log/suru/perimeter-block.log" follow-freq(1) flags(no-parse) program-override("suru-perimeter-block")); };

# --- Filters -----------------------------------------------------------------

filter f_firewall   { program("filterlog"); };
filter f_dhcp       { program("dhcpd") or program("dhclient") or program("kea-dhcp4") or program("kea-dhcp6") or program("kea2unbound"); };
filter f_dns_all    { program("unbound") or program("dnsmasq"); };
filter f_vpn        { program("openvpn") or program("ipsec") or program("charon"); };
filter f_auth       { facility(auth, authpriv); };
filter f_suricata   { program("suricata") or program("suricata-fast"); };
filter f_zeek       { program("zeek-conn") or program("zeek-dns") or program("zeek-http") or program("zeek-ssl") or program("zeek-notice") or program("zeek-weird") or program("zeek-files") or program("zeek-dhcp"); };
filter f_pfblocker  { program("pfblockerng-dnsbl") or program("pfblockerng-ip"); };
filter f_suru_perimeter_block { program("suru-perimeter-block"); };
filter f_drop_noise { match("last message repeated" value("MESSAGE")) or program("cron"); };

# --- Rewrites ----------------------------------------------------------------

rewrite r_add_tag_firewall  { set("pfsense-firewall",   value(".suru.log_type")); };
rewrite r_add_tag_dhcp      { set("pfsense-dhcp",       value(".suru.log_type")); };
rewrite r_add_tag_dns       { set("pfsense-dns",        value(".suru.log_type")); };
rewrite r_add_tag_vpn       { set("pfsense-vpn",        value(".suru.log_type")); };
rewrite r_add_tag_auth      { set("pfsense-auth",       value(".suru.log_type")); };
rewrite r_add_tag_suricata  { set("suricata-eve",       value(".suru.log_type")); };
rewrite r_add_tag_zeek      { set("zeek",               value(".suru.log_type")); };
rewrite r_add_tag_pfblocker { set("pfblockerng",        value(".suru.log_type")); };
rewrite r_add_tag_perimeter_block { set("suru-perimeter-block", value(".suru.log_type")); };
rewrite r_add_hostname      { set("${HOST}",            value(".suru.sensor")); };
rewrite r_add_tier          { set("tier1-perimeter",    value(".suru.tier")); };
rewrite r_add_version       { set("2.7.0",              value(".suru.config_version")); };

# --- Log paths ---------------------------------------------------------------

log { source(s_pfsense_syslog); filter(f_drop_noise); flags(final); };

log { source(s_filter_log); filter(f_firewall);
      rewrite(r_add_tag_firewall); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_pfsense_syslog); source(s_dhcpd); filter(f_dhcp);
      rewrite(r_add_tag_dhcp); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_pfsense_syslog); source(s_resolver); filter(f_dns_all);
      rewrite(r_add_tag_dns); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_pfsense_syslog); source(s_openvpn); source(s_ipsec); filter(f_vpn);
      rewrite(r_add_tag_vpn); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_pfsense_syslog); filter(f_auth);
      rewrite(r_add_tag_auth); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_suricata_eve); filter(f_suricata);
      rewrite(r_add_tag_suricata); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_zeek_conn); source(s_zeek_dns); source(s_zeek_http); source(s_zeek_ssl);
      source(s_zeek_notice); source(s_zeek_weird); source(s_zeek_files); source(s_zeek_dhcp);
      rewrite(r_add_tag_zeek); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_pfblocker_dnsbl); source(s_pfblocker_ip);
      rewrite(r_add_tag_pfblocker); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };

log { source(s_suru_perimeter_block); filter(f_suru_perimeter_block);
      rewrite(r_add_tag_perimeter_block); rewrite(r_add_hostname); rewrite(r_add_tier); rewrite(r_add_version);
      destination(d_siem_tls); flags(flow-control); };
