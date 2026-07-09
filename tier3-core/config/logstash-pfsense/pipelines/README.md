# Logstash pfSense Pipelines

> **AI-CONTEXT:** This directory contains the production Logstash pipelines for
> processing pfSense telemetry forwarded via syslog-ng over mTLS.
> All pipelines normalise events to **ECS v8** before writing to OpenSearch.

---

## Pipeline Execution Order

```
00-input-beats-tls.conf      ← TLS input, RFC 5424 parse, routing tag
        │
        ├── suru.log_type = "firewall"    → 10-pfsense-firewall.conf
        ├── suru.log_type = "dhcp"        → 11-pfsense-services.conf
        ├── suru.log_type = "dns"         → 11-pfsense-services.conf
        ├── suru.log_type = "vpn-*"       → 11-pfsense-services.conf
        ├── suru.log_type = "auth"        → 11-pfsense-services.conf
        ├── suru.log_type = "suricata"    → 20-suricata-eve.conf
        ├── suru.log_type = "zeek"        → 30-zeek.conf
        ├── suru.log_type = "pfblockerng" → 40-pfblockerng.conf
        └── [unmatched]                   → 90-deadletter.conf
```

---

## File Reference

| File | ECS Category | OpenSearch Index |
|------|-------------|------------------|
| `00-input-beats-tls.conf` | — | (input only, no output) |
| `10-pfsense-firewall.conf` | `network` | `suru-pfsense-firewall-*` |
| `11-pfsense-services.conf` | `network`, `authentication`, `session`, `configuration` | `suru-pfsense-services-*` |
| `20-suricata-eve.conf` | `intrusion_detection` | `suru-suricata-*` |
| `30-zeek.conf` | `network` | `suru-zeek-*` |
| `40-pfblockerng.conf` | `threat` | `suru-pfblockerng-*` |
| `90-deadletter.conf` | — | `suru-deadletter-*` |

---

## Adding a New Pipeline

See [`../../docs/extending.md`](../../docs/extending.md) — REQ-001 through REQ-009.

### Validating a pipeline (safely)

⚠️ **Never `docker exec` the LIVE container to validate.**
`docker exec suru.t3.ingestion.logstash-pfsense logstash --config.test_and_exit …`
spawns a **second ~1 GB JVM inside the live container's cgroup**, which — on a box
whose Logstash is already near its memory limit — can **OOM-crash production
ingestion mid-check** (observed: an unclean restart with persisted-queue recovery
across every pipeline). It looks like a read-only syntax check; against the live
container it is not.

Validate in a **throwaway container** (its own cgroup — cannot touch live ingestion).
`--config.test_and_exit` interpolates `${ENV}`, so pass a dummy for every env var the
pipeline references; it checks config grammar only, not connectivity. Match the image
digest pinned in `tier3-core/ingestion/logstash/compose.yaml`:

```bash
docker run --rm \
  -e LS_JAVA_OPTS='-Xms256m -Xmx256m' \
  -e OPENSEARCH_HOST=localhost -e OPENSEARCH_PORT=9200 \
  -e OPENSEARCH_USER=x -e OPENSEARCH_PASSWORD=x \
  -v "$PWD/tier3-core/config/logstash-pfsense/pipelines/<filename>.conf":/tmp/p.conf:ro \
  docker.elastic.co/logstash/logstash-oss:9.3.1 \
  logstash --config.test_and_exit -f /tmp/p.conf
```

If you must use the live container's real env, first confirm headroom
(`docker stats --no-stream suru.t3.ingestion.logstash-pfsense`, need > ~300 MiB free)
and bound the test JVM (`docker exec -e LS_JAVA_OPTS='-Xmx256m' …`) — but prefer the
throwaway container above.
