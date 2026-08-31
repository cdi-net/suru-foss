# する SURU — Security Unified Resilience Unit

**Self-hosted, modular cybersecurity platform for small offices and home labs (SOHO).**
Detection and response — not alert spam.

[![CI](https://github.com/cdi-net/suru-foss/actions/workflows/ci.yml/badge.svg)](https://github.com/cdi-net/suru-foss/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](./LICENSE)

> This is **suru-foss**, the open-source edition of the [SURU platform](https://cdinet.ro/#suru), released
> under the **Mozilla Public License 2.0**. It provides a complete, deployable
> defence-in-depth stack built entirely from open-source components. It is
> designed to be simple to understand, review, and extend by any human or tool —
> no proprietary dependencies, no telemetry, no lock-in.

---

## What it does

SURU turns a commodity firewall and a small Linux box into a layered security
monitoring stack. Network traffic is inspected at the perimeter, normalised to a
single schema, stored in a search engine, and surfaced through dashboards — all
on hardware you own, with data that never leaves your network unless you opt in.

- **Inline intrusion detection/prevention** at the perimeter (Suricata, ET Open + Talos rules).
- **Passive network telemetry** (Zeek) for DNS, DHCP, HTTP, TLS, connection and file visibility.
- **DNS/IP reputation blocking** (pfBlockerNG) with threat-feed aggregation.
- **Behavioural detection** via MITRE ATT&CK–mapped Sigma rules.
- **Centralised analytics** — every event normalised to **Elastic Common Schema (ECS) v8**,
  indexed in **OpenSearch**, browsable in **OpenSearch Dashboards**.
- **GeoIP / ASN enrichment** of public source/destination IPs (MaxMind GeoLite2).
- **Encrypted log transport** — mutual-TLS (mTLS) from the perimeter to the core,
  signed by a single platform Root CA.
- **Operations plane** — Prometheus + Grafana + Alertmanager monitoring and a single
  nginx **frontdoor** that is the only LAN entry point to the stack.

Everything is driven by idempotent, re-runnable shell scripts and Docker Compose —
no manual GUI clicking required to stand the platform up or tear it down.

---

## Architecture — four tiers, defence in depth

| Tier | Directory | Role | Key components |
|------|-----------|------|----------------|
| **T1 — Perimeter** | [`tier1-perimeter/`](./tier1-perimeter/) | First line of defence on the router | pfSense / OPNsense, Suricata IPS, Zeek NSM, syslog-ng mTLS forwarder |
| **T2 — Telemetry** | [`tier2-telemetry/`](./tier2-telemetry/) | Signature & behavioural detection content | ET Open + Talos rule selection, MITRE ATT&CK Sigma rules, pfBlockerNG feeds |
| **T3 — Core** | [`tier3-core/`](./tier3-core/) | Analytics, storage & detection | OpenSearch + Dashboards, Logstash ingest pipelines, ECS v8 normalisation, GeoIP enrichment |
| **T4 — Operations** | [`tier4-operations/`](./tier4-operations/) | Control plane | PKI (single Root CA), nginx frontdoor, Prometheus/Grafana/Alertmanager monitoring |

The tiers are independent and degrade gracefully: Tier 1 runs without the SIEM,
the SIEM runs without endpoint agents, and there is no single point of failure.
The four-tier layout is intentional and stable — new capabilities are added
**within** the matching tier so the structure stays predictable for operators and
contributors alike.

---

## Quick start

Full step-by-step instructions — prerequisites, environment variables, and
per-tier verification — are in **[INSTALL.md](./INSTALL.md)**.

The deployment order follows the defence-in-depth dependency chain:

```text
1. Certificates   →  generate the single SURU Root CA + service certs
2. Tier 3 (Core)  →  bring up OpenSearch, Dashboards, Logstash ingest
3. Tier 4 (Ops)   →  bring up the frontdoor + monitoring
4. Tier 1 (Edge)  →  push config + mTLS client cert to the router
```

```bash
# 1. Certificates (single Root CA — run once)
bash tier4-operations/pki/scripts/generate-certs.sh --verbose

# 2. Tier 3 — Core analytics stack
bash tier3-core/scripts/deploy.sh deploy --verbose
bash tier3-core/scripts/deploy.sh check

# 3. Tier 4 — Frontdoor + monitoring
bash tier4-operations/scripts/deploy.sh deploy --verbose
bash tier4-operations/scripts/deploy.sh check

# 4. Tier 1 — Perimeter (run from tier1-perimeter/)
make -C tier1-perimeter deploy-full PLATFORM=pfsense VERBOSE=true
```

---

## Requirements

- A **pfSense** or **OPNsense** firewall (the perimeter you already run).
- A small always-on **Linux host** for the core (Docker + Compose v2; 8 GB RAM
  minimum, 16 GB recommended; ~50 GB disk for index data).
- `bash`, `docker`, `openssl`, `make`, and SSH access to the router.

---

## Repository layout

```text
suru-foss/
├── README.md              ← this file
├── INSTALL.md             ← end-to-end deployment guide
├── CONTRIBUTING.md        ← workflow, branch strategy, PR rules, roadmap
├── SECURITY.md            ← how to report a vulnerability
├── LICENSE                ← Mozilla Public License 2.0
├── .github/               ← CI pipeline, PR/issue templates, CODEOWNERS
├── terraform/             ← optional IaC scaffolding (networking module)
├── tier1-perimeter/       ← router config, Suricata, Zeek, syslog-ng, deploy driver
├── tier2-telemetry/       ← Suricata rule selection, Sigma rules, pfBlockerNG feeds
├── tier3-core/            ← OpenSearch, Logstash pipelines, dashboards, ECS templates
└── tier4-operations/      ← pki/, frontdoor/, monitoring/
```

Each tier has its own `README.md` and `docs/` with operational detail.

---

## Conventions

- **Branches:** `main` (protected) → `develop` → `feature/<name>`, `fix/<name>`, `release/<version>`.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `security:`.
- **Logs:** every source normalised to **ECS v8**.
- **Detection content:** annotated with MITRE ATT&CK Tactic (`TA####`) + Technique (`T####`).
- **TLS everywhere:** minimum TLS 1.2, prefer 1.3; mTLS for service-to-service log shipping.
- **Containers:** non-root, `cap_drop: [ALL]`, `no-new-privileges`, pinned images, never mount the Docker socket.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full developer workflow and the
code/detection standards that apply to each file type.

---

## Licensing

suru-foss is licensed under the **Mozilla Public License, v. 2.0**. The full text
is in [LICENSE](./LICENSE). MPL-2.0 is a file-level copyleft license: you may
combine these files with proprietary code, but modifications to MPL-licensed files
must be shared under the same license. Unless a file states otherwise, every file
in this repository is covered by the MPL-2.0.

---

## Security

Found a vulnerability? Please follow the coordinated-disclosure process in
[SECURITY.md](./SECURITY.md) — do not open a public issue for security reports.
