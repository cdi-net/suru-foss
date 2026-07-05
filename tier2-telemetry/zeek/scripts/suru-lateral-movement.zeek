# SURU Platform — Internal admin-port lateral-movement detection
# Fires when one internal host establishes connections to N or more DISTINCT
# internal hosts on remote-admin ports (SSH/SMB/RDP/VNC) within a window — the
# fan-out signature of an attacker pivoting across the LAN.
# MITRE ATT&CK: TA0008 Lateral Movement / T1021 Remote Services
#   (T1021.001 RDP, T1021.002 SMB/Windows Admin Shares, T1021.004 SSH)
# Validation: zeek -b suru-lateral-movement.zeek
#
# SOURCE OF TRUTH: tier2-telemetry/zeek/scripts/
#
# WHY A ZEEK NOTICE, NOT A SIEM conn.log DETECTOR:
# soho-telemetry.zeek's Conn::log_policy hook DROPS RFC1918->RFC1918 flows under
# 10000 bytes from conn.log before it is written, so a SIEM aggregation over
# conn.log would never see short internal admin-port connections — exactly the
# fan-out this rule targets. A NOTICE fires from the connection_established
# event, which is independent of the conn.log write policy, so the detection is
# unaffected by that suppression. This supersedes the *intent* of the retired
# endpoint-telemetry Sigma stub sigma/rules/lateral-movement/remote-services.yml
# (Sysmon Image/CommandLine — no live ECS source on this deployment) with a
# network-observable mechanism.

@load base/frameworks/notice
@load base/protocols/conn

module SURU_LM;

export {
    redef enum Notice::Type += {
        ## One internal host reached too many distinct internal hosts on
        ## remote-admin ports within the window (lateral-movement fan-out).
        Internal_Admin_Fanout
    };

    ## Sources exempt from this detection — a legitimate management/backup
    ## station that fans out to many hosts on admin ports (a patch server, a
    ## monitoring box). Add exempt hosts/subnets via `redef` in local.zeek.
    const exempt_hosts: set[subnet] = {} &redef;

    ## Remote-administration destination ports that constitute lateral movement
    ## when fanned out across many internal hosts. SSH(22)/SMB(445)/RDP(3389)/
    ## VNC(5900). &redef so a site can add e.g. WinRM(5985) or MSSQL(1433).
    const admin_ports: set[port] = {
        22/tcp, 445/tcp, 3389/tcp, 5900/tcp
    } &redef;

    ## Internal address space. A connection is only a lateral-movement candidate
    ## when BOTH endpoints are internal (external admin access is a different
    ## detection surface handled by the perimeter firewall/Suricata).
    const private_nets: set[subnet] = {
        10.0.0.0/8,
        172.16.0.0/12,
        192.168.0.0/16
    } &redef;

    ## Distinct internal admin-port destinations from one source, within the
    ## window, at or above which the NOTICE fires. Seed value; tune per site.
    const fanout_threshold: count = 5 &redef;

    ## Per-source window, ANCHORED at first-seen (Zeek &create_expire evicts a
    ## source's set this interval after its FIRST entry, not a sliding/last-seen
    ## window). Evasion caveat: an attacker pacing pivots to stay under
    ## fanout_threshold within each anchored window, or straddling a window
    ## boundary, can evade — inherent to anchored counters; tune per site.
    const fanout_window: interval = 10min &redef;
}

# Per-source set of distinct internal admin-port destinations seen this window.
# &create_expire evicts a source's set fanout_window after its first entry, so
# the count is bounded to activity within one window (not all-time).
global admin_fanout: table[addr] of set[addr] &create_expire = fanout_window;

# connection_established (not new_connection): real lateral movement completes
# the TCP handshake. Counting SYN-only attempts would overlap the port-scan
# detector (zero-byte fan-out, T1595.001) and inflate FPs from health checks.
event connection_established(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    # Both endpoints internal, destination is an admin port.
    if ( orig !in private_nets ) return;
    if ( resp !in private_nets ) return;
    if ( c$id$resp_p !in admin_ports ) return;

    # Exempt a sanctioned management source (redef exempt_hosts in local.zeek)
    # so a patch/backup/monitoring host does not trip the fan-out heuristic.
    if ( orig in exempt_hosts ) return;

    if ( orig !in admin_fanout )
        admin_fanout[orig] = set();
    add admin_fanout[orig][resp];

    if ( |admin_fanout[orig]| == fanout_threshold )
        {
        NOTICE([
            $note        = Internal_Admin_Fanout,
            $conn        = c,
            $msg         = fmt("Internal host %s reached %d distinct internal hosts on admin ports (%s) in %s — lateral-movement fan-out, T1021",
                               orig, |admin_fanout[orig]|, c$id$resp_p, fanout_window),
            # One NOTICE per source per window: identifier keyed on the source
            # only (not the destination) so a burst of pivots collapses to a
            # single lateral-movement alert rather than one per target.
            $identifier  = cat(orig),
            $suppress_for = fanout_window
        ]);
        }
    }
