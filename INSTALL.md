# Installing SURU (suru-foss)

This guide deploys the full platform end-to-end. SURU is **layered defence in
depth**, so the deployment order is **not** tier-1-first — it follows the
dependency chain:

```text
1. Certificates  →  2. Tier 3 (Core)  →  3. Tier 4 (Operations)  →  4. Tier 1 (Perimeter)
```

The single SURU Root CA must exist before anything else, because every
service certificate and the perimeter's mTLS client certificate are signed by it.
Tier 3 must be running before Tier 4 (the frontdoor proxies to it), and Tier 1 is
configured last because it ships logs *into* the already-running core.

---

## 0. Prerequisites

| Where | Needs |
|-------|-------|
| Core host (Linux) | Docker 24+, Compose v2 (`docker compose`), `bash`, `openssl`, `make`, `git`. 8 GB RAM min (16 GB recommended), ~50 GB disk. |
| Perimeter | pfSense or OPNsense reachable over SSH (key-based auth). |
| Workstation | SSH access to the router; ability to run the `tier1-perimeter` Makefile. |

Clone the repository on the core host:

```bash
git clone https://github.com/cdi-net/suru-foss.git
cd suru-foss
```

### Configure environment files

Each tier reads a local `.env` (never committed). Copy the templates and fill in
secrets — use strong, unique passwords:

```bash
cp tier3-core/.env.example       tier3-core/.env
cp tier4-operations/.env.example tier4-operations/.env
cp tier1-perimeter/.env.example  tier1-perimeter/.env
```

Key variables to set (see each `.env.example` for the full annotated list):

| Tier | Variable | Purpose |
|------|----------|---------|
| 3 | `ROUTER_PLATFORM` | `pfsense` or `opnsense` — selects the matching Logstash ingest profile |
| 3 | `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | OpenSearch admin password (also set identically in Tier 4) |
| 3 | `LOGSTASH_OPENSEARCH_PASSWORD` | Logstash → OpenSearch credential |
| 3 / 1 | `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | Optional GeoIP/ASN enrichment (leave blank to disable) |
| 4 | `FRONTDOOR_FQDN` | Primary hostname (e.g. `suru.local`) |
| 4 | `FRONTDOOR_INGESTION_FQDNS` | Comma-separated SNI hostnames routed to ingestion (e.g. `syslog.suru.local`) — **must match the SANs on the backend ingestion cert** |
| 4 | `FRONTDOOR_IP` | LAN-routable IPv4 of the core host |
| 4 | `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | Must equal the Tier 3 value |
| 1 | `ROUTER_HOST`, `ROUTER_SSH_USER`, `ROUTER_SSH_KEY` | Router SSH target + key path |
| 1 | `ROUTER_PLATFORM` | `pfsense` or `opnsense` |
| 1 | `SURICATA_IFACES`, `ZEEK_IFACE` | Capture interfaces (`ZEEK_IFACE` must be a physical trunk, not a VLAN sub-interface) |
| 1 | `FRONTDOOR_SYSLOG_SNI` | SNI hostname the router presents (must be in Tier 4 `FRONTDOOR_INGESTION_FQDNS`) |

> **PKI / SAN rule:** every hostname in `FRONTDOOR_INGESTION_FQDNS` must appear as
> a Subject Alternative Name on the backend ingestion certificate, or TLS
> ingestion fails silently. See [`tier4-operations/pki/README.md`](./tier4-operations/pki/README.md).

---

## 1. Certificates — the single SURU Root CA

Generate the Root CA and all service certificates **once**:

```bash
bash tier4-operations/pki/scripts/generate-certs.sh --verbose
```

This creates:

- `tier4-operations/pki/certs/root-ca.pem` (public cert) and `root-ca-key.pem`
  (private key — gitignored, never leaves the host),
- Tier 3 service certs under `tier3-core/certs/` (OpenSearch node/admin,
  Dashboards, Logstash).

> ⚠️ **Re-running this script rotates the Root CA** (it overwrites `root-ca-key.pem`).
> Only run it again when you intend a full CA rotation — see the PKI README.

**Verify** the chain:

```bash
openssl verify -CAfile tier4-operations/pki/certs/root-ca.pem \
  tier3-core/certs/logstash.pem
```

---

## 2. Tier 3 — Core (OpenSearch, Dashboards, Logstash)

```bash
# One-time host tuning required by OpenSearch (sets vm.max_map_count=262144)
bash tier3-core/scripts/deploy.sh kernel-tune

# Full deployment: networks → certs → all groups → health
bash tier3-core/scripts/deploy.sh deploy --verbose
```

**Verify:**

```bash
bash tier3-core/scripts/deploy.sh check
# Expect: OpenSearch cluster health 'yellow' (normal for single-node),
# Dashboards reachable, Logstash pipelines reporting status 'green'.
```

Useful follow-ups:

```bash
bash tier3-core/scripts/deploy.sh status
bash tier3-core/scripts/deploy.sh logs --service suru.t3.ingestion.logstash-pfsense
bash tier3-core/scripts/deploy.sh reimport     # re-import dashboard saved objects
```

---

## 3. Tier 4 — Operations (frontdoor + monitoring)

Tier 4 generates its own frontdoor certificate signed by the Root CA, then brings
up the nginx frontdoor (the sole LAN entry point) and the monitoring stack.

```bash
bash tier4-operations/scripts/deploy.sh deploy --verbose
```

**Verify:**

```bash
bash tier4-operations/scripts/deploy.sh check
docker exec suru.t4.frontdoor.proxy nginx -t      # config OK
```

After deploy, the stack is reachable through the frontdoor (default `suru.local`):

| Service | URL |
|---------|-----|
| OpenSearch Dashboards | `https://suru.local/` |
| Grafana | `https://suru.local/grafana` |
| Prometheus | `https://suru.local/prometheus` |

---

## 4. Tier 1 — Perimeter (router)

Run from the `tier1-perimeter/` directory (or use `make -C tier1-perimeter`).
This renders the Tier 2 detection content into the router templates, signs a Tier 1
mTLS client certificate against the Root CA, and pushes everything to the device.

```bash
cd tier1-perimeter

# Optional: confirm connectivity first
make api-health PLATFORM=pfsense VERBOSE=true

# Render + deploy in one step
make deploy-full PLATFORM=pfsense VERBOSE=true
```

> Use `PLATFORM=opnsense` for OPNsense. Run `make deploy-dry` / pass
> `RENDER_DRY_RUN=true` to preview actions without touching the router.

**Verify:**

```bash
make api-validate PLATFORM=pfsense     # post-deploy service validation
make sng-metrics  VERBOSE=true         # syslog-ng forwarder telemetry
```

---

## 5. End-to-end verification

```bash
# Each tier's own health check
bash tier3-core/scripts/deploy.sh check
bash tier4-operations/scripts/deploy.sh check
make -C tier1-perimeter api-health PLATFORM=pfsense

# Confirm events are arriving and indexed (browse in Dashboards at https://suru.local/)
bash tier3-core/scripts/deploy.sh logs --service suru.t3.ingestion.logstash-pfsense
```

If logs are flowing from the router into OpenSearch and the dashboards populate,
the platform is up end-to-end.

---

## Teardown

```bash
bash tier4-operations/scripts/deploy.sh destroy     # keeps data volumes
bash tier3-core/scripts/deploy.sh destroy           # keeps data volumes
# add 'destroy-all' instead of 'destroy' to also remove data volumes (irreversible)
```

---

## Troubleshooting

- **`SURU Root CA not found`** — run step 1 before Tier 1/3/4 deploys.
- **`CA certificate and CA private key do not match`** — the Root CA pair was
  rotated out of sync; see the recovery steps in
  [`tier4-operations/pki/README.md`](./tier4-operations/pki/README.md).
- **Silent ingestion outage after a cert change** — a hostname in
  `FRONTDOOR_INGESTION_FQDNS` is missing from the backend cert SANs. Regenerate
  the cert and restart the backend.
- **OpenSearch container won't start** — `vm.max_map_count` too low; re-run
  `bash tier3-core/scripts/deploy.sh kernel-tune`.
