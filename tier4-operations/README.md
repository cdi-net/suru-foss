# Tier 4 — Operations / Control Plane

`tier4-operations/` is the control and automation layer of the SURU platform.
It orchestrates configuration, health, content lifecycle, and operator
workflows across Tiers 1–3 so the platform can be operated without dedicated
security technicians.

The design intent for this tier — the operations / control plane that the
monitoring and frontdoor subsystems below are the first components of:

- **Orchestrator Service** — control plane that owns idempotent install,
  upgrade, and reconfiguration of Tier 1–3 components.
- **Integration & Pipeline Manager** — manages log paths, transforms, and
  enrichment between perimeter, detection, and SIEM tiers.
- **Content & Ruleset Manager** — pulls/curates rule packs (Suricata,
  Sigma, YARA rule packs) and applies SOHO-appropriate defaults.
- **Health, Telemetry, and Self-Healing Service** — monitors the platform
  itself (the current `monitoring/` subtree); restarts or quarantines
  failing components.
- **Alert Curator & Playbook Engine** — converts noisy detections into
  plain-language, one-click operator actions.
- **Threat Intelligence Orchestrator** — coordinates IOC ingestion and
  redistribution to detection engines.

## Current Subtree

| Subdir | Purpose | Status |
|--------|---------|--------|
| `monitoring/` | Prometheus / Grafana / Alertmanager stack | Migrated from `tier3-core/monitoring/` |
| `frontdoor/proxy/` | Single LAN entry point: nginx reverse proxy + stream LB + mDNS sidecar + git-sync sidecar serving the [suru-frontdoor-content](https://github.com/cdi-net/suru-frontdoor-content) repo at `/` | Implemented |
| `scripts/` | Orchestrator (`deploy.sh`), DNS registrar (`register-dns.sh`), legacy cleanup | Implemented |

The remaining services (orchestrator, integration manager, content manager,
alert curator, threat-intel orchestrator) are not yet scaffolded.

## Operate

```bash
# One-time setup
cp tier4-operations/.env.example tier4-operations/.env
$EDITOR tier4-operations/.env                   # fill FRONTDOOR_*, INFLUXDB_*, GRAFANA_*

# First-time deploy (tier3-core must be running first)
bash tier4-operations/scripts/deploy.sh deploy

# Other actions
bash tier4-operations/scripts/deploy.sh status
bash tier4-operations/scripts/deploy.sh check
bash tier4-operations/scripts/deploy.sh logs --service suru.t4.frontdoor.proxy
bash tier4-operations/scripts/deploy.sh reload          # nginx reload
bash tier4-operations/scripts/deploy.sh register-dns    # router-side DNS for FRONTDOOR_FQDN
bash tier4-operations/scripts/deploy.sh --help
```

## Tier Boundary

Tier 4 manages and observes Tiers 1–3 but does **not** participate in the
data plane (no log ingest, no detection, no enforcement). All security
telemetry continues to flow Tier 1 → Tier 2 → Tier 3. Tier 4 reads from
those tiers' health/metrics endpoints and writes back configuration.
