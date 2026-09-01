# SURU Platform — Zeek site policy template (render-time tokens only)
# TEMPLATE: tier1-perimeter/templates/zeek/local.zeek.tpl
# Rendered by: tier2-telemetry/build/lib/render-zeek.sh
# Output to:   tier1-perimeter/rendered/<platform>/zeek/local.zeek
#
# Engine bootstrap (base protocol loads, engine tuning, log directory, intel
# framework) now lives in the REGISTERED script:
#   tier2-telemetry/zeek/scripts/suru-base.zeek
# Because suru-base.zeek is registered in installedpackages/zeekscript/config,
# zeek_script_resync() always includes `@load suru-base` in the generated
# local.zeek — making base protocol analysis survive any pfSense GUI save.
#
# This file only carries render-time tokens (ZEEK_IFACE substitution; detection-script @loads).
# They are restored on `make deploy` and are non-load-bearing if lost to a
# GUI save — losing them does not stop Zeek from generating protocol logs.

# --- Capture interface label (rendered from ZEEK_IFACE; informational only) ---
# Use the physical TRUNK interface, not a VLAN sub-interface or pfSense logical
# name. Zeek understands 802.1Q natively; one sensor on igb1 covers all VLANs.
const zeek_iface = "__ZEEK_IFACE__" &redef;
redef capture_filters = { ["default"] = "not port 22" };

# --- Detection scripts injected by render-zeek.sh from tier2-telemetry/zeek/scripts/ ---
# Includes @load suru-base (engine bootstrap) automatically via the *.zeek glob.
__ZEEK_SCRIPTS__

# Telemetry scope: keep mDNS (UDP/5353) records in dns.log only when
# the operator opts in via ZEEK_LOG_MDNS=true. Default drops them (~70% of DNS
# event volume, no per-record security value; detection scripts are unaffected
# — they run on the live event stream, not the log). Substituted by render-zeek.sh.
redef SURU_Telemetry::log_mdns = __ZEEK_LOG_MDNS__;
