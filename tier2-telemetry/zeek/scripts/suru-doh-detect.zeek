# SURU Platform — DNS-over-HTTPS (DoH) resolver-bypass detection
# Fires when an internal client completes a TLS handshake whose SNI is a known
# public DoH endpoint — the client is resolving names over HTTPS, bypassing the
# local unbound + pfBlockerNG DNSBL enforcement entirely (malware and privacy
# tools both do this; it defeats the platform's own DNS-layer blocking).
# MITRE ATT&CK: TA0005 Defense Evasion / T1572 Protocol Tunneling;
#               TA0011 Command and Control / T1071.001 Web Protocols
# Validation: zeek -b suru-doh-detect.zeek
#
# SOURCE OF TRUTH: tier2-telemetry/zeek/scripts/
#
# This is the SECOND, INDEPENDENT leg of DoH detection. The first is the Tier 1
# Suricata custom rule SID 9990003 (suru-doh-bypass.rules), which matches the
# same SNI inline on the wire. Two engines (Suricata payload/SNI + Zeek
# ssl.log SNI) give defense-in-depth if one is disabled or misses a session.
#
# EXPECTED VOLUME / FP: Firefox and iOS/macOS enable DoH by default, so on a
# fresh network this fires steadily until the operator decides policy. It is as
# much a POLICY-VISIBILITY control ("who is bypassing our resolver?") as a
# threat detector. Exempt the router's own upstream-DoH resolver IP and any
# sanctioned client by redef-ing exempt_hosts in local.zeek.

@load base/frameworks/notice
@load base/protocols/ssl

module SURU_DOH;

export {
    redef enum Notice::Type += {
        ## An internal client used a public DoH endpoint (resolver bypass).
        DoH_Resolver_Bypass
    };

    ## Clients exempt from this detection — the router's own upstream-DoH
    ## resolver, or a sanctioned client. Add via `redef` in local.zeek.
    const exempt_hosts: set[subnet] = {} &redef;

    ## Known public DoH endpoint SNIs. Exact server_name match (these are
    ## specific hostnames, so exact match is low-FP). &redef to extend.
    ## Sources: the providers' published DoH endpoint hostnames.
    const doh_endpoints: set[string] = {
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "one.one.one.one",
        "dns.google",
        "dns.quad9.net",
        "doh.opendns.com",
        "dns.nextdns.io",
        "doh.cleanbrowsing.org",
        "dns.adguard-dns.com",
        "chrome.cloudflare-dns.com"
    } &redef;

    ## Internal address space — only internal clients are of interest (an
    ## external host doing DoH is not a resolver-bypass on this network).
    const private_nets: set[subnet] = {
        10.0.0.0/8,
        172.16.0.0/12,
        192.168.0.0/16
    } &redef;
}

# ssl_established fires after a completed TLS handshake; c$ssl$server_name holds
# the SNI the client sent. (An SNI-less or ESNI/ECH connection carries no
# server_name and is out of scope for this hostname-based check by design.)
event ssl_established(c: connection)
    {
    if ( ! c?$ssl ) return;
    if ( ! c$ssl?$server_name ) return;

    local orig = c$id$orig_h;
    if ( orig !in private_nets ) return;

    # Exempt the router's own upstream-DoH resolver or a sanctioned client
    # (redef exempt_hosts in local.zeek) so only unsanctioned bypasses alert.
    if ( orig in exempt_hosts ) return;

    local sni = to_lower(c$ssl$server_name);
    if ( sni !in doh_endpoints ) return;

    NOTICE([
        $note        = DoH_Resolver_Bypass,
        $conn        = c,
        $msg         = fmt("Internal host %s used DoH endpoint %s — resolver bypass, T1572/T1071.001", orig, sni),
        # One NOTICE per (client, DoH endpoint) per hour — DoH clients reconnect
        # constantly; this keeps it to a policy-visibility cadence, not a flood.
        $identifier  = cat(orig, sni),
        $suppress_for = 1hr
    ]);
    }
