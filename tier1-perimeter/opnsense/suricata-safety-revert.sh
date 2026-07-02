#!/bin/sh
# SURU Tier 1 — OPNsense IDS inline-revert (dead-man's-switch payload)
#
# Counterpart to pfsense/suricata-safety-revert.php: reverts OPNsense's
# Suricata/os-ids from inline IPS mode back to non-inline so the host stack
# reattaches to any NIC that was in inline netmap, restoring the management path
# if a deploy self-locked-out. Scheduled autonomously by
# scripts/lib/safety-timer.sh via daemon(8) (FreeBSD base; present on OPNsense).
#
# [STUB: UNVERIFIED on a live OPNsense 24.x — this deployment has only a pfSense
#        router. OPNsense IDS is model-driven: "IPS mode" is the config flag
#        OPNsense/IDS/general/ips, applied by the os-ids plugin. The model-correct
#        revert is to set that flag off and reconfigure the service. The exact
#        configctl/pluginctl/API invocation below MUST be validated against a live
#        OPNsense before the OPNsense inline flip is enabled. Until then the OPNsense Suricata
#        inline deploy itself is a [STUB] (scripts/platforms/opnsense.sh), so this
#        payload is wired-and-ready but never actually armed.]
#
# Runs as root (launched via `sudo daemon`).

set -u

logger -t suru-safety "OPNsense IDS inline-revert invoked (STUB — validate configctl path on live OPNsense)"

# Best-effort, model-correct attempt. Both lines are the most likely correct
# OPNsense idioms; verify on a live box and delete the STUB marker once confirmed.
#   1) turn IPS (inline) mode off in the config model
#   2) reconfigure/reload the os-ids service so the change takes effect
if command -v configctl >/dev/null 2>&1; then
  # The os-ids plugin exposes reconfigure; the config flag itself is normally set
  # via the API/model, not configctl — this reload assumes the flag was already
  # cleared by the (future) OPNsense revert applier. Left as the reload step.
  configctl ids reconfigure 2>&1 || echo "[opnsense-safety-revert] WARN: configctl ids reconfigure failed"
else
  echo "[opnsense-safety-revert] ERROR: configctl not found — cannot revert IDS mode"
fi

echo "[opnsense-safety-revert] Done (STUB — confirm host-stack restoration on live OPNsense)."
