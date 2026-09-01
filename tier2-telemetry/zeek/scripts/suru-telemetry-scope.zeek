# SURU Platform — telemetry scoping for the DNS log stream
# NOT a detection — a platform default deciding what dns.log records ship
# to the SIEM. mDNS (port 5353) service-discovery chatter was ~70% of ALL
# DNS events on the live baseline (1.5M of 2.15M/30d: _companion-link,
# _spotify-connect, AirPlay/RAOP, _googlecast, host announcements) with no
# per-record security value — while costing shipping bandwidth, ingestion
# CPU, storage, and detector scan time end-to-end.
#
# CRITICAL PROPERTY: this filters the LOG stream only. Zeek detection
# scripts (suru-dns-entropy.zeek legs, suru-name-poisoning.zeek) run on the
# live EVENT stream and are entirely unaffected — mDNS-borne attacks still
# raise notices, and notices still ship. What is lost is only the raw
# per-query mDNS history in the SIEM; flip the switch below and redeploy to
# restore full capture for an investigation.
#
# Operator switch: ZEEK_LOG_MDNS=true in tier1-perimeter/.env → render
# emits `redef SURU_Telemetry::log_mdns = T;` into local.zeek (see
# render-zeek.sh __ZEEK_LOG_MDNS__). Default (unset/false): mDNS records
# are excluded from dns.log.
#
# Kept unconditionally (deliberate disposition list): NBNS :137 and
# LLMNR :5355 (T1557.001 poisoning surface), unicast :53 local-name leaks
# (foreign-AD/guest-device fingerprinting), reverse .arpa lookups.
# Validation: zeek -b --parse-only suru-telemetry-scope.zeek

@load base/protocols/dns

module SURU_Telemetry;

export {
    ## When F (the SURU default), mDNS (UDP/5353) records are excluded from
    ## dns.log before it is written/shipped. Set via ZEEK_LOG_MDNS in .env.
    const log_mdns: bool = F &redef;
}

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
    {
    if ( ! log_mdns && rec$id$resp_p == 5353/udp )
        break;
    }
