# SURU Platform — foreign-domain member-device detection
# MITRE ATT&CK: TA0007 Discovery / T1018 Remote System Discovery — the
# observed behaviour is AD service (domain controller) location via DNS
# SRV (_ldap._tcp/_kerberos/_msdcs) plus WPAD lookup. A device doing this
# for a domain outside the deployment's authorized set broadcasts a
# foreign org's naming and participates in poisonable name resolution —
# an information leak and a credential-relay exposure (T1557.001,
# secondary context) on the trusted segment.
#
# Signals (live event stream; unaffected by suru-telemetry-scope.zeek's
# mDNS log filtering):
#   - unicast :53 queries with AD-membership shapes for a non-authorized
#     domain: _ldap._tcp.*, _kerberos*, *_msdcs*, wpad.<domain>
#   - threshold >= query_threshold per client per 24h window; ONE notice
#     per device per day (exact-threshold fire + suppression)
# Identity: the notice carries the client's DHCP-known hostname and MAC
# when available, cached from dhcp.log records (DHCP::log_policy hook —
# read-only use; the hook never breaks, so logging is unaffected).
#
# Authorized domains: SURU_ForeignDomain::authorized_domains is rendered
# from SURU_AUTHORIZED_AD_DOMAINS (.env, comma-separated); when unset the
# deploy substitutes the perimeter's own configured system domain at apply
# time (zeek-scripts-apply.php reads it from the router config — never
# hardcoded — deployment-agnostic).
# Per-device exceptions (an accepted guest): redef exempt_hosts in
# local.zeek.
#
# Validation contract: fires exactly once/day for a known
# foreign-domain device (hundreds of foreign-domain queries daily, well above
# the threshold) and stays silent for every authorized-domain client.
# Validation: zeek -b --parse-only suru-foreign-domain.zeek

@load base/frameworks/notice
@load base/protocols/dns
@load base/protocols/dhcp

module SURU_ForeignDomain;

export {
    redef enum Notice::Type += {
        ## A client shows AD-membership behaviour (SRV/kerberos/msdcs/WPAD
        ## discovery) for a domain outside the authorized set — a
        ## foreign-domain member device on the trusted segment.
        ForeignDomain_Member_Device
    };

    ## Domains whose AD-membership traffic is expected. The marker below is
    ## replaced at RENDER time from SURU_AUTHORIZED_AD_DOMAINS when set
    ## (comma-separated -> quoted set entries); when unset it survives the
    ## render and zeek-scripts-apply.php substitutes the perimeter's own
    ## configured system domain at APPLY time (read from the router config —
    ## never hardcoded). If the router has no valid system domain either,
    ## the applier removes the quoted entry, leaving an EMPTY set — nothing
    ## authorized, every AD-membership burst alerts (fail-safe by omission;
    ## both apply-time variants parse-verified). The authored literal parses
    ## as a plain string, so `zeek -b --parse-only` stays valid on this file.
    const authorized_domains: set[string] = { "@@SURU_AUTHORIZED_AD_DOMAINS@@" } &redef;

    ## Foreign AD-shaped queries per client per window before the notice.
    const query_threshold: count = 25 &redef;

    ## Counting window (fixed from first-seen, &create_expire semantics).
    const window = 24hr &redef;

    ## Clients exempt from this detection — an accepted guest device.
    ## Add exempt hosts/subnets via `redef` in local.zeek.
    const exempt_hosts: set[subnet] = {} &redef;
}

# Per-client foreign-query counter; fixed 24h window from first sighting.
# Residual evasion (accepted threshold trade-off, same shape as the other
# threshold-based detections): a client pacing itself below the threshold
# per window — or straddling two windows, since the window anchors at
# first sighting rather than rolling — never fires. Acceptable here: the
# behaviour detected is ambient AD-membership chatter (hundreds of
# queries/day on the validation data), not an adversary who paces.
global foreign_hits: table[addr] of count &create_expire=window;

# DHCP identity cache: hostname + MAC per client address. Written from
# dhcp.log records. &write_expire (not &create_expire) so the 3-day timer
# RESETS on every re-assignment — the identity survives as long as the
# client keeps renewing; &create_expire would anchor at first sighting and
# silently drop the enrichment for any lease cadence longer than 3 days.
global dhcp_hostname: table[addr] of string &write_expire=3days;
global dhcp_mac: table[addr] of string &write_expire=3days;

hook DHCP::log_policy(rec: DHCP::Info, id: Log::ID, filter: Log::Filter)
    {
    # Read-only identity harvesting — never `break`, logging is untouched.
    if ( rec?$client_addr )
        {
        if ( rec?$host_name && rec$host_name != "" )
            dhcp_hostname[rec$client_addr] = rec$host_name;
        if ( rec?$mac && rec$mac != "" )
            dhcp_mac[rec$client_addr] = rec$mac;
        }
    }

# Suffix membership against authorized_domains (lowercased input): exact
# match or dot-anchored suffix — ends_with() per the repo precedent, no
# substring forgery.
function is_authorized_domain(qlower: string): bool
    {
    for ( d in authorized_domains )
        {
        if ( qlower == d || ends_with(qlower, "." + d) )
            return T;
        }
    return F;
    }

# AD-membership query shapes. Anchored at label boundaries where the shape
# demands it; kept deliberately narrow for v1 (bare-domain SOA/SRV is
# excluded — FP-prone to define generically; the SRV/kerberos/msdcs/wpad
# set alone exceeds the threshold many times over on the validation data).
function is_ad_shape(qlower: string): bool
    {
    return /^_ldap\._tcp\./ in qlower ||
           /^_kerberos/ in qlower ||
           /(^|\.)_msdcs\./ in qlower ||
           /^wpad\./ in qlower;
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    # Unicast resolver traffic only — mDNS/LLMNR/NBNS name chatter is a
    # different question (suru-name-poisoning.zeek owns that surface).
    if ( c$id$resp_p != 53/udp && c$id$resp_p != 53/tcp )
        return;

    # Per-device exception surface (accepted guests) — redef exempt_hosts
    # in local.zeek.
    if ( c$id$orig_h in exempt_hosts )
        return;

    local qlower = to_lower(query);
    if ( ! is_ad_shape(qlower) )
        return;
    if ( is_authorized_domain(qlower) )
        return;

    local h = c$id$orig_h;
    if ( h !in foreign_hits )
        foreign_hits[h] = 0;
    ++foreign_hits[h];

    # Exact-threshold fire: one evaluation crosses the line once per
    # window; suppression backs it for the identifier.
    if ( foreign_hits[h] == query_threshold )
        {
        local ident = "";
        if ( h in dhcp_hostname )
            ident = fmt(" host=%s", dhcp_hostname[h]);
        if ( h in dhcp_mac )
            ident = fmt("%s mac=%s", ident, dhcp_mac[h]);
        NOTICE([
            $note        = ForeignDomain_Member_Device,
            $conn        = c,
            $msg         = fmt("Client %s%s performed %d AD-membership queries for non-authorized domain(s) in %s (sample: %s) — foreign-domain member device on the trusted segment (T1018 discovery; T1557.001 relay exposure). Runbook: authorize the domain (SURU_AUTHORIZED_AD_DOMAINS or redef authorized_domains), move the device to the guest segment, or quarantine.", h, ident, query_threshold, window, query),
            $sub         = query,
            $identifier  = cat(h),
            $suppress_for = 24hr
        ]);
        }
    }
