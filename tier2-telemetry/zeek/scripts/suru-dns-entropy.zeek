# SURU Platform — DNS entropy-based tunneling detection
# Detects high-entropy DNS queries indicative of DNS tunneling / C2 over DNS.
# MITRE ATT&CK: TA0011 Command and Control / T1071.004 DNS
# Validation: zeek -b suru-dns-entropy.zeek
#
# SOURCE OF TRUTH: tier2-telemetry/zeek/scripts/

# Load the notice framework explicitly (SEC-045). This script defines a
# Notice::Type and calls NOTICE(); it currently works only because suru-base.zeek
# happens to pull in the framework transitively (intel/do_notice) and loads first
# under filesystem-sort order. Loading it here makes the script self-contained and
# robust to load-order changes.
@load base/frameworks/notice

module SURU_DNS;

export {
    redef enum Notice::Type += {
        ## Fired when a DNS query subdomain exceeds the entropy threshold
        DNS_High_Entropy_Query,
        ## Fired when a unicast DNS query name approaches the protocol length
        ## ceiling (length leg). iodine/dns2tcp-class tunnels pack labels
        ## toward the 255-byte limit; legitimate FQDNs rarely exceed ~80
        ## chars. Local/service-discovery namespaces are excluded at source.
        ## MITRE ATT&CK: TA0011/T1071.004, TA0010/T1048.003.
        DNS_Excessive_Name_Length
    };

    ## Minimum query label length to evaluate
    const min_label_len: count = 20 &redef;

    ## Shannon entropy threshold (bits per character) above which alert fires
    const entropy_threshold: double = 3.8 &redef;

    ## Unicast (port 53) full-query-name length at/above which the length-leg
    ## notice fires. Evidence for the default (30d live baseline): only
    ## 170,638 of 2.15M names were >=40 chars and 40.3% of those were
    ## local/service-discovery — at >=100 with local excluded, expected
    ## benign volume is near zero.
    const max_name_len: count = 100 &redef;

    ## Name suffixes treated as local namespaces — never evaluated by the
    ## length leg (RFC 6762 .local, RFC 8375 home/.home, private-use
    ## internal/lan/localdomain, and ONLY the two real reverse zones under
    ## .arpa). Suffix-matched (not last-label) so a bare `.arpa` no longer
    ## excludes an attacker-delegated `*.evil.arpa` (review finding).
    const local_suffixes: set[string] = {
        ".local", ".internal", ".lan", ".home", ".localdomain",
        ".in-addr.arpa", ".ip6.arpa"
    } &redef;

    ## DNS record types DNS-SD (RFC 6763) actually uses (PTR=12, TXT=16,
    ## SRV=33). The length-leg DNS-SD exclusion only applies to these types
    ## — a tunneling data channel optimising for payload density does not use
    ## them, so an attacker cannot cheaply dress an A/AAAA data query as
    ## service discovery (review finding).
    const dnssd_qtypes: set[count] = { 12, 16, 33 } &redef;
}

# Suffix match over local_suffixes (lowercased input expected). Uses the
# ends_with() builtin (base/bif/strings.bif.zeek) rather than a
# negative-index string slice (review finding).
function suru_is_local_name(qlower: string): bool
    {
    for ( sfx in local_suffixes )
        if ( ends_with(qlower, sfx) )
            return T;
    return F;
    }

# Structural DNS-SD check: a `_tcp`/`_udp` label immediately preceded by
# another underscore-prefixed (service) label — RFC 6763 `_svc._proto.` —
# AND a DNS-SD query type. Anchored to label position + qtype so it cannot
# be forged by placing "._tcp." as a free substring in attacker content.
function suru_is_dnssd(parts: string_vec, qtype: count): bool
    {
    if ( qtype !in dnssd_qtypes )
        return F;
    local i: count;
    for ( i in parts )
        if ( i > 0 && ( parts[i] == "_tcp" || parts[i] == "_udp" ) &&
             |parts[i-1]| > 0 && parts[i-1][0] == "_" )
            return T;
    return F;
    }

function shannon_entropy(s: string): double
    {
    local freq: table[string] of count;
    local len = |s|;
    if ( len == 0 ) return 0.0;
    # Zeek 6.x: for-in over a string yields each character as a string
    for ( ch in s )
        {
        if ( ch !in freq ) freq[ch] = 0;
        ++freq[ch];
        }
    local entropy = 0.0;
    for ( ch in freq )
        {
        local p = freq[ch] * 1.0 / len;
        entropy -= p * ln(p) / ln(2.0);
        }
    return entropy;
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    # ── Length leg ─────────────────────────────────────────────────────────
    # Unicast resolver traffic only: mDNS (5353), LLMNR (5355), NBNS (137)
    # carry long service-discovery names by design and are not tunneling
    # candidates. Replaces the retired SA pre-packaged "Possible DNS
    # Tunneling" rule, whose shipped detection was a match-all
    # (parent_domain: '*').
    if ( ( c$id$resp_p == 53/udp || c$id$resp_p == 53/tcp ) &&
         |query| >= max_name_len )
        {
        # Both exclusions operate on the lowercased name (Zeek does NOT
        # downcase the DNS question name — review finding), and both are
        # anchored (suffix / label-position + qtype) so neither can be
        # forged by attacker-controlled substring content. Residual risk:
        # an attacker willing to use a PTR/SRV/TXT qtype AND real
        # `_svc._tcp.` structure can still evade the length leg; the
        # entropy leg is the backstop.
        local qlower = to_lower(query);
        local llparts = split_string(qlower, /\./);
        if ( ! suru_is_local_name(qlower) && ! suru_is_dnssd(llparts, qtype) )
            NOTICE([
                $note        = DNS_Excessive_Name_Length,
                $conn        = c,
                $msg         = fmt("Unicast DNS query name %d chars (>=%d) — T1071.004/T1048.003", |query|, max_name_len),
                $sub         = query,
                # Per-(host,name) suppression, same policy as the entropy leg.
                $identifier  = cat(c$id$orig_h, query),
                $suppress_for = 10min
            ]);
        }

    # Only evaluate the leftmost label (subdomain portion)
    local parts = split_string(query, /\./);
    if ( |parts| < 2 ) return;
    local label = parts[0];
    if ( |label| < min_label_len ) return;

    local e = shannon_entropy(label);
    if ( e >= entropy_threshold )
        {
        NOTICE([
            $note        = DNS_High_Entropy_Query,
            $conn        = c,
            $msg         = fmt("High-entropy DNS subdomain: %s (entropy=%.2f) — T1071.004", query, e),
            # Per-(host,query) suppression: each distinct high-entropy query alerts
            # once per 10 min. If a DGA host floods many distinct names and the
            # notice volume becomes noisy, switch to per-host suppression by using
            # `cat(c$id$orig_h)` here (one alert per host per window).
            $identifier  = cat(c$id$orig_h, query),
            $suppress_for = 10min
        ]);
        }
    }
