# SURU — Tier 4 / frontdoor / proxy

Single external entry point for the SURU platform. Every LAN-facing service
flows through this nginx reverse proxy + stream load balancer. Internal
containers no longer bind host ports of their own.

## Architecture

```
                                                           ┌── static landing (/) ◀── suru.t4.frontdoor.content
                                                           │                          (git-sync of cdi-net/suru-frontdoor-content)
pfSense syslog-ng ──TCP+TLS:443 (SNI=syslog.suru.local)──┐│
                                                           ││  suru.t4.frontdoor.proxy
LAN client ──HTTPS:443──────────────────────────────────┐  │   (nginx 1.27-alpine,    │── suru-t3-datalake-dashboards:5601 (/dashboards/)
                                                        │  │    http + stream modules) │── suru-t3-ingestion-logstash-default:9600 (/ingestion)
LAN client ──TCP:5044───────────────────────────────────┤  │                           │── suru-t4-monitoring-grafana:3000 (/grafana)
LAN client ──UDP:5140───────────────────────────────────┤  │   Port 443 SNI demux:     │── suru-t4-monitoring-prometheus:9090 (/prometheus)
                                                        └──┘   syslog.suru.local →     │── suru-t3-datalake-opensearch:9200 (/api/search)
                                                               logstash-pfsense:5140   │── suru-t3-ingestion-logstash-{default,pfsense}:5044 (Beats)
                                                               (TCP passthrough/mTLS)  └── suru-t3-ingestion-logstash-{default,pfsense}:5140-5142 (UDP)
                                                               default → 127.0.0.1:8443
                                                               (HTTPS termination)
```

### Port 443 SNI demux

All traffic arriving on port 443 is handled by an nginx `stream` block using
`ssl_preread on`. The TLS ClientHello SNI is inspected **without** terminating
TLS:

- **Ingestion FQDNs** (set via `FRONTDOOR_INGESTION_FQDNS`) — TCP passthrough
  to `127.0.0.1:9443`, which forwards the raw TLS stream to the appropriate
  backend (default: `suru-t3-ingestion-logstash-pfsense:5140`). mTLS is
  terminated at the backend. The nginx SNI map for these hostnames is generated
  automatically by the container entrypoint at startup from the
  `FRONTDOOR_INGESTION_FQDNS` environment variable — no `nginx.conf` edits
  required when adding new collectors.
- Any other SNI — proxied to the loopback HTTPS listener on `127.0.0.1:8443`
  (the `http {}` server block) with `proxy_protocol on` so the real client IP
  is preserved in nginx access logs and `$remote_addr`.

This route is hand-authored in `config/nginx.conf` and is intentionally absent
from `config/routes.yaml` — `render-routes.sh` cannot express the `ssl_preread`
/ `proxy_protocol` pattern.

**DNS registration:** `register-dns.sh` (invoked automatically when
`REGISTER_DNS_ON_DEPLOY=yes`) registers every FQDN listed in both
`FRONTDOOR_FQDN` and `FRONTDOOR_INGESTION_FQDNS` as host overrides on
the perimeter router, all pointing to `FRONTDOOR_IP`. Add new ingestion
hostnames to `FRONTDOOR_INGESTION_FQDNS` in `tier4-operations/.env`; the
next `deploy.sh register-dns` run will pick them up automatically.

- **External-facing:** the only Docker network with host port bindings is
  `suru-t4-frontdoor-external`. The frontdoor container is the sole resident.
- **Internal-facing:** the frontdoor joins `suru-t3-core-internal` (created by
  `tier3-core/datalake/opensearch/compose.yaml`) to reach every backend via
  short Docker DNS names.
- **Routing:** driven by [`config/routes.yaml`](./config/routes.yaml).
  `scripts/render-routes.sh` materialises that manifest into nginx include
  files under `config/http/` (HTTP locations) and `config/stream/` (TCP/UDP
  listeners). Both manifests and renders are committed.
- **Static content (`/`):** served by nginx directly from a shared
  `suru-t4-frontdoor-content` volume, populated by the
  `suru.t4.frontdoor.content` sidecar (git-sync of the
  [cdi-net/suru-frontdoor-content](https://github.com/cdi-net/suru-frontdoor-content)
  repository). The sidecar uses a fine-grained PAT scoped to that repo
  with **Contents: read-only** — write access stays with content authors,
  not with the platform. Content authoring conventions live in the
  content repository's own documentation; the proxy here treats the volume
  as opaque.

## Prerequisites

One-time, per host:

1. **SURU root CA** — `tier4-operations/pki/scripts/generate-certs.sh`
2. **`.env` settings** — copy `tier4-operations/.env.example` to
   `tier4-operations/.env` and fill in:
   ```
   FRONTDOOR_FQDN=suru.local                       # default
   FRONTDOOR_MDNS_ALIASES=suru.local,soc.local     # default — both advertised via mDNS
   FRONTDOOR_PORT=443                              # default
   FRONTDOOR_IP=<host LAN IPv4>                    # cert SAN + mDNS + router DNS target
   FRONTDOOR_BASIC_AUTH_USER=admin
   FRONTDOOR_BASIC_AUTH_PASSWORD=<strong-password>

   CONTENT_REPO_URL=https://github.com/cdi-net/suru-frontdoor-content.git
   CONTENT_REPO_REF=main
   CONTENT_REPO_TOKEN=<github fine-grained PAT — contents: read on the content repo>
   CONTENT_SYNC_PERIOD=60s
   ```
3. **Frontdoor cert** — `bash tier4-operations/scripts/deploy.sh certs`
   (or call `tier4-operations/frontdoor/proxy/scripts/generate-frontdoor-cert.sh`
   directly). Signs `certs/frontdoor.pem` with the SURU root CA; SAN
   includes every entry in `FRONTDOOR_MDNS_ALIASES` plus `FRONTDOOR_IP`.

LAN name resolution comes from two places:

- **`suru.t4.frontdoor.mdns` sidecar** — runs avahi-daemon in
  `network_mode: host`, advertises each name in `FRONTDOOR_MDNS_ALIASES`
  as an A record pointing at `FRONTDOOR_IP`. Auto-resolves on
  macOS / Linux. (Refuses to advertise loopback — set `FRONTDOOR_IP`
  to the host's real LAN IPv4.)
- **(Optional) Router DNS** — `bash tier4-operations/scripts/deploy.sh register-dns`
  creates a host override on the perimeter router (pfSense/OPNsense)
  so Windows clients (no Bonjour) also resolve the FQDN. Set
  `REGISTER_DNS_ON_DEPLOY=true` in `tier4-operations/.env` to run
  this automatically as part of `deploy.sh deploy`.

## Operate

```bash
# Bring it up (after tier3-core + tier4-operations/monitoring are running)
bash tier4-operations/scripts/deploy.sh deploy

# Reload after editing routes.yaml + re-rendering
bash tier4-operations/frontdoor/proxy/scripts/render-routes.sh
bash tier4-operations/scripts/deploy.sh reload

# Healthcheck
curl -sk https://suru.local/healthz       # mDNS-resolved on macOS / Linux
bash tier4-operations/scripts/deploy.sh check
```

## Update the static landing page (or future docs)

The landing page at `/` is **not** authored in this repo. Push commits
to [cdi-net/suru-frontdoor-content][content]; the `suru.t4.frontdoor.content`
sidecar picks them up within `CONTENT_SYNC_PERIOD` (default 60s).
That repository has its own documentation describing the
authoring conventions.

```bash
# Verify the content sidecar saw the latest commit:
docker logs --tail 20 suru.t4.frontdoor.content
# Force an immediate re-sync (drops the volume and re-clones on restart):
docker restart suru.t4.frontdoor.content
```

[content]: https://github.com/cdi-net/suru-frontdoor-content

## Add a new route

1. Append an entry to `config/routes.yaml`:
   - `http_routes[]` for an HTTP/HTTPS backend
   - `stream_routes[]` for a TCP/UDP backend (requires a matching host
     `ports:` entry in `compose.yaml`)
2. `bash scripts/render-routes.sh`
3. Commit `routes.yaml` + the regenerated `config/{http,stream}/`.
4. Apply: `docker exec suru.t4.frontdoor.proxy nginx -s reload`

## Auth

Basic auth, single shared user. `htpasswd` is materialised inside the
container at start from `FRONTDOOR_BASIC_AUTH_USER` /
`FRONTDOOR_BASIC_AUTH_PASSWORD`. Never written to the host bind-mount;
never committed.

A future PR will add OIDC/oauth2-proxy as an alternative auth method
(planned — see the roadmap in `CONTRIBUTING.md`).

## mTLS

This PR terminates TLS at the frontdoor only. Backend traffic uses
HTTPS-where-already-required (OpenSearch on `9200`) or HTTP on the
internal-only network. Full backend mTLS is a follow-up PR.
