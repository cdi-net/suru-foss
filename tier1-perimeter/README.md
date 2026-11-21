# SURU Platform — Tier 1: Perimeter

Tier 1 contains **deployment scaffolding** for perimeter devices (pfSense, OPNsense).
It does **not** contain security policy. All security intelligence (rules, feeds, scripts)
lives in [`../tier2-telemetry/`](../tier2-telemetry/).

## Directory Structure

```
tier1-perimeter/
├── templates/                        # Structural config templates (schema only)
│   ├── pfsense/
│   │   ├── config-base.xml.tpl       # pfSense base config schema
│   │   └── syslog-ng.conf.tpl        # syslog-ng forwarder (token substitution)
│   ├── suricata/
│   │   └── suricata.yaml.tpl         # Suricata 7.x engine config (no rule selection)
│   ├── zeek/
│   │   └── local.zeek.tpl            # Zeek engine bootstrap (__ZEEK_SCRIPTS__ placeholder)
│   └── opnsense/
│       ├── config-base.xml.tpl
│       └── syslog-ng.conf.tpl
├── pfsense/                          # Static PHP appliers staged + run on the router by the pfSense driver
│   └── unbound-localzones-apply.php  # Local-DNS hygiene default (see section below)
├── rendered/                         # BUILD OUTPUT — git-ignored, do not edit
│   ├── pfsense/                      # Populated by `make render PLATFORM=pfsense`
│   └── opnsense/                     # Populated by `make render PLATFORM=opnsense`
├── scripts/
│   ├── deploy.sh                     # Deployment orchestrator
│   ├── gen-certs.sh                  # Issue the syslog-ng mTLS client pair from the Root CA
│   ├── lib/                          # ssh (connection reuse), certs, safety timer, hw-preflight, secrets, api
│   └── platforms/
│       ├── pfsense.sh                # pfSense platform driver
│       └── opnsense.sh               # OPNsense platform driver
├── docs/                             # Deployment notes, architecture, prerequisites, privilege matrix
└── Makefile                          # render / deploy / deploy-full / gen-certs / clean / test
```

## Operator Workflow

```bash
# 1. Edit security policy in tier2-telemetry/ (rules, feeds, Zeek scripts)

# 2. Render: merge T2 intelligence into T1 templates
make render PLATFORM=pfsense

# 3. Deploy: push rendered artefacts to the router
make deploy PLATFORM=pfsense

# Or: render + deploy in one step
make deploy-full PLATFORM=pfsense

# Dry run (no changes to device)
make deploy-full PLATFORM=pfsense DRY_RUN=true

# Deploy artefacts rendered elsewhere (absolute path, must exist)
tier1-perimeter/scripts/deploy.sh --platform pfsense --rendered-dir /path/to/rendered/pfsense

# On the PKI host: issue the syslog-ng mTLS client pair from the existing Root CA
make gen-certs
```

A deploy host that does not hold the Root CA key sets `SURU_PKI_PREISSUED=true`
and `TIER1_CERTS_DIR=<dir with the pair issued by make gen-certs>`; the driver
then verifies the pair against the public Root CA and never signs.
`SURU_PKI_DIR` points every reader at a Root CA directory other than
`tier4-operations/pki/certs`. See [`.env.example`](./.env.example) and
[`docs/DEPLOYMENT-NOTES.md`](./docs/DEPLOYMENT-NOTES.md).

## Required Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ROUTER_HOST` | — | Router SSH/API host |
| `ROUTER_SSH_KEY` | `~/.ssh/suru_deploy` | SSH private key path |
| `FRONTDOOR_SYSLOG_SNI` | `syslog.suru.local` | SNI hostname for Tier 4 frontdoor stream demux |
| `FRONTDOOR_PORT` | `443` | Port for Tier 1 → frontdoor connections |
| `WAN_IFACE` | `igb0` | WAN interface name |
| `LAN_IFACE` | `igb1` | LAN interface name |
| `ROUTER_SENSOR_NAME` | `suru-tier1` | Sensor label in logs |

## Local-DNS hygiene (platform default)

The pfSense deploy applies a local-DNS default via
`pfsense/unbound-localzones-apply.php` (runs after the Zeek stage, before
pfBlockerNG):

- **Special-use zones answered locally** — `local.` (RFC 6762 mDNS),
  `alt.` (RFC 9476), and the two name-hijack guards `wpad.<system domain>.`
  / `isatap.<system domain>.` are declared `always_nxdomain` in a managed
  sentinel block inside the DNS Resolver custom options (operator content
  outside the block is never touched). These names must never be forwarded
  upstream: `.local` leaks LAN hostnames to the public roots, and an
  answered WPAD/ISATAP query hands clients to a rogue proxy/gateway.
- **System domain made locally authoritative** — pfSense's native
  `system_domain_local_zone_type` is set to `static`, so unknown internal
  names get a local NXDOMAIN instead of leaking upstream. A reversible
  split-horizon guard inspects `domainoverrides` first: if the system
  domain legitimately forwards to a real internal DNS server, `static` is
  skipped (and a previously-set `static` is actively reverted) so
  split-horizon resolution is never broken. Gates:
  `SURU_UNBOUND_LOCALZONES` (whole stage) and
  `SURU_UNBOUND_SYSTEM_DOMAIN_STATIC` (static only), both default `true`.
- **mDNS telemetry scoping** — `ZEEK_LOG_MDNS` (default `false`) drops
  mDNS/5353 records from Zeek's `dns.log` before shipping (~70% of DNS
  event volume on a 30d live baseline, no per-record security value).
  Log-stream filter only: detection scripts run on the live event stream
  and still fire on mDNS-borne attacks.

On pfSense the stage runs `pfsense/unbound-localzones-apply.php`. On OPNsense it runs
`opnsense/unbound-localzones-apply.php`, which owns one drop-in file
(`/usr/local/etc/unbound.opnsense.d/suru-localzones.conf`) for the special-use zones and
rolls its own write back on failure. The system-domain static setting is reported, not
written, on OPNsense (its Unbound model path is not converged by the applier); the
deploy continues with a warning. The same two gates apply on both platforms.

## Invariant 11

> **T2 is the sole authority for security policy.**
> Any PR adding Suricata SID selection, DNSBL categories, or Zeek detection
> scripts directly inside `tier1-perimeter/` **must be rejected** at review.
> Templates contain structure. Intelligence lives in `tier2-telemetry/`.
