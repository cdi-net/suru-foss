# SURU Platform — SSH brute-force / password-spray detection
# Fires when one source opens N or more SSH connections to a single target
# within a window — the connection-rate signature of credential brute-forcing
# or password spraying against SSH.
# MITRE ATT&CK: TA0006 Credential Access / T1110 Brute Force
#   (T1110.001 Password Guessing, T1110.003 Password Spraying)
# Validation: zeek -b suru-ssh-bruteforce.zeek
#
# SOURCE OF TRUTH: tier2-telemetry/zeek/scripts/
#
# WHY A ZEEK NOTICE (not the SIEM, not ssh.log):
#  1. Zeek ssh.log is NOT one of the 8 Zeek log types the tier3 Logstash Zeek
#     pipeline routes (conn/dns/dhcp/http/ssl/notice/weird/files), so ssh.log
#     never reaches the SIEM on this deployment. A NOTICE flows in as
#     event.dataset:"notice" / event.kind:"alert".
#  2. LAN->LAN SSH connections are dropped from conn.log by soho-telemetry.zeek's
#     under-10000-byte suppression, so a conn.log SIEM aggregation would miss
#     internal brute-forcing. connection_established fires regardless.
# Credential-access is otherwise only covered at Tier 1 by Suricata's
# emerging-ftp (FTP brute) — this adds the SSH surface.

@load base/frameworks/notice
@load base/protocols/conn

module SURU_SSH;

export {
    redef enum Notice::Type += {
        ## One source opened too many SSH connections to a single target in the
        ## window (brute-force / password-spray connection rate).
        SSH_Bruteforce
    };

    ## Sources exempt from this detection — a sanctioned automation source
    ## (CI/bastion/backup that legitimately reconnects SSH frequently). Add
    ## exempt hosts/subnets via `redef` in local.zeek.
    const exempt_hosts: set[subnet] = {} &redef;

    ## The SSH port. &redef for sites running SSH on a non-standard port.
    const ssh_ports: set[port] = { 22/tcp } &redef;

    ## Connections from one source to one target's SSH port, within the window,
    ## at or above which the NOTICE fires. A legitimate client rarely reopens
    ## SSH tens of times a minute; automated guessing does. Seed value.
    const conn_threshold: count = 15 &redef;

    ## Per-(source,target) window, ANCHORED at first-seen (Zeek &create_expire
    ## evicts the counter this interval after its FIRST connection, not a
    ## sliding/last-seen window). Evasion caveat: a source pacing attempts to
    ## stay under conn_threshold within each anchored window, or straddling a
    ## window boundary, can evade — inherent to anchored counters; tune per site.
    const conn_window: interval = 5min &redef;
}

# Per (source, target) SSH connection count for the current window.
# &create_expire bounds the count to one window from its first connection.
global ssh_attempts: table[addr, addr] of count &create_expire = conn_window &default = 0;

event connection_established(c: connection)
    {
    if ( c$id$resp_p !in ssh_ports ) return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    # Exempt a sanctioned automation source (redef exempt_hosts in local.zeek).
    if ( orig in exempt_hosts ) return;

    ++ssh_attempts[orig, resp];

    if ( ssh_attempts[orig, resp] == conn_threshold )
        {
        NOTICE([
            $note        = SSH_Bruteforce,
            $conn        = c,
            $msg         = fmt("Source %s opened %d SSH connections to %s in %s — brute-force/spray connection rate, T1110",
                               orig, conn_threshold, resp, conn_window),
            # One NOTICE per (source -> target) pair per window.
            $identifier  = cat(orig, resp),
            $suppress_for = conn_window
        ]);
        }
    }
