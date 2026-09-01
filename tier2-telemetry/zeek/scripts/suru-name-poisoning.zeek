# SURU Platform — LLMNR/NBT-NS poisoning + WPAD-answer detection
# MITRE ATT&CK: TA0006 Credential Access / T1557.001 (Adversary-in-the-Middle:
# LLMNR/NBT-NS Poisoning and SMB Relay)
#
# Threat model: in a healthy SOHO LAN, LLMNR (UDP/5355) and NetBIOS-NS
# (UDP/137) name queries go UNANSWERED — Windows hosts broadcast them as a
# fallback and nothing legitimate replies for arbitrary names. A
# Responder-class attacker answers EVERY such query to harvest NTLM
# credentials. Two behavioural signals, both from the live event stream
# (unaffected by suru-telemetry-scope.zeek's mDNS log filtering):
#
#   1. Responder_Suspected — one responder host answers queries for multiple
#      DISTINCT names on :137/:5355 within the tracking window. A host
#      legitimately answers only its OWN name(s); answering >= threshold
#      distinct names is the poisoning fingerprint.
#   2. WPAD_Answer_Detected — ANY answered name query for wpad on a port whose
#      replies reach dns_A_reply/dns_AAAA_reply: 53/5353 (Zeek default DNS
#      binding) + 5355 (registered below). NBT-NS/137 reply-event firing is NOT
#      yet live-fire-confirmed — same caveat as the Responder leg. WPAD
#      must never resolve: the unbound local-zones default
#      (unbound-localzones-apply.php) NXDOMAINs it at the resolver, LLMNR/NBNS
#      should never answer it, and a successful answer means a client is one
#      HTTP fetch away from attacker-controlled proxy config.
#
# Observed baseline (30d live): 14,145 NBNS events, zero legitimate
# multi-name responders — expected steady-state notice volume is zero.
# Validation: zeek -b --parse-only suru-name-poisoning.zeek

@load base/frameworks/notice
@load base/frameworks/analyzer
@load base/protocols/dns

# LLMNR is DNS-over-UDP-5355; Zeek does NOT bind the DNS analyzer to 5355 by
# default, so LLMNR queries/replies are otherwise invisible (review
# finding — live-confirmed: 0 records for resp_p 5355 in dns.log before this).
# Registering the port makes LLMNR parse as DNS, so dns_request/dns_*_reply
# fire for it. mDNS (5353) is already bound by default; NBT-NS (137) queries
# already reach dns.log on this install (NetBIOS name-service is a distinct
# protocol — its *reply* events are NOT yet confirmed to fire, so the NBT-NS
# leg is validation-pending; live-fire confirmation is a tracked follow-up).
event zeek_init()
    {
    Analyzer::register_for_port(Analyzer::ANALYZER_DNS, 5355/udp);
    }

module SURU_NamePoison;

export {
    redef enum Notice::Type += {
        ## A host answered LLMNR/NBT-NS queries for multiple distinct names
        ## within the tracking window — Responder-class poisoning fingerprint.
        Responder_Suspected,
        ## A name query for wpad received an actual answer (any protocol) —
        ## proxy-autodiscovery hijack in progress or resolver misconfig.
        WPAD_Answer_Detected
    };

    ## Distinct names answered by one responder before Responder_Suspected.
    const responder_name_threshold: count = 3 &redef;

    ## Per-responder tracking window. NOTE (review finding nit): `&create_expire`
    ## below expires an entry a fixed `responder_window` after it was first
    ## created (first answer seen from that responder) — NOT a last-activity
    ## sliding window. A sustained attacker answers many names in seconds, so a
    ## fixed 10-min window catches it; whether to switch to `&write_expire`
    ## (true activity-sliding) for a slow-drip responder is a live-tuning call
    ## deferred to a follow-up validation.
    const responder_window = 10min &redef;
}

# responder host -> set of distinct lowercased names it answered on :137/:5355.
# Fixed window from first-seen (see responder_window note above).
global answered_names: table[addr] of set[string] &create_expire=responder_window;

function suru_is_multicast_ns_port(p: port): bool
    {
    return p == 137/udp || p == 5355/udp;
    }

function suru_check_wpad(c: connection, query: string)
    {
    local q = to_lower(query);
    # wpad, wpad.<anything>, and NetBIOS-padded variants.
    if ( /^wpad(\.|$)/ in q )
        NOTICE([
            $note        = WPAD_Answer_Detected,
            $conn        = c,
            $msg         = fmt("Answered WPAD name query '%s' on port %s — proxy auto-discovery hijack indicator (T1557.001)", query, c$id$resp_p),
            $sub         = query,
            $identifier  = cat(c$id$resp_h, q),
            $suppress_for = 10min
        ]);
    }

function suru_track_responder(c: connection, query: string)
    {
    if ( ! suru_is_multicast_ns_port(c$id$resp_p) )
        return;

    # c$id$resp_h is the host that ANSWERED (the potential attacker), not the
    # querier. PCAP-VERIFIED 2026-08-31 (review finding): replaying an
    # LLMNR spoof (victim broadcasts a query to 224.0.0.252:5355; attacker
    # sends a unicast reply) through this Zeek build, dns_A_reply fired with
    # orig_h=victim, resp_h=attacker — because Zeek anchors the reply's UDP
    # flow on the querier endpoint it already saw (conn.log:
    # id.orig=victim:<eph> id.resp=attacker:5355). The review's hypothesis
    # (reply becomes a fresh flow with orig=attacker) did NOT hold here, so
    # resp_h is the correct responder. (Assumes the sensor sees the query too,
    # which it does inline on the LAN.) NBT-NS/137 reply attribution is a
    # distinct wire format, still pending live-fire in a tracked follow-up.
    local responder = c$id$resp_h;
    local q = to_lower(query);

    if ( responder !in answered_names )
        answered_names[responder] = set();
    add answered_names[responder][q];

    if ( |answered_names[responder]| >= responder_name_threshold )
        NOTICE([
            $note        = Responder_Suspected,
            $conn        = c,
            $msg         = fmt("Host %s answered %d distinct LLMNR/NBT-NS names in %s — Responder-class poisoning suspected (T1557.001)", responder, |answered_names[responder]|, responder_window),
            $sub         = q,
            $identifier  = cat(responder),
            $suppress_for = 30min
        ]);
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    suru_check_wpad(c, ans$query);
    suru_track_responder(c, ans$query);
    }

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    suru_check_wpad(c, ans$query);
    suru_track_responder(c, ans$query);
    }
