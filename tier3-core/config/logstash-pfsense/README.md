# SURU Platform — Logstash pfSense Pipelines

Production-grade Logstash configuration set for pfSense-centric ingestion into the SURU Tier 3 Core (analytics & active defense).

## Contents

- `logstash.yml` — main Logstash settings baseline
- `pipelines.yml` — multi-pipeline definitions for pfSense-specific ingestion
- `pipelines/00-input-beats-tls.conf` — TLS/mTLS input and routing pipeline
- `pipelines/10-pfsense-firewall.conf` — pfSense filterlog/NAT pipeline
- `pipelines/11-pfsense-services.conf` — DHCP, DNS, auth, config, system, VPN pipeline
- `pipelines/20-suricata-eve.conf` — Suricata EVE JSON pipeline
- `pipelines/30-zeek.conf` — Zeek JSON/TSV pipeline
- `pipelines/40-pfblockerng.conf` — pfBlockerNG DNSBL/IP reputation pipeline
- `pipelines/90-deadletter.conf` — fallback / quarantine pipeline

## Mount path

Recommended container mount target:

`/usr/share/logstash/config/logstash-pfsense`

Recommended pipeline mount target:

`/usr/share/logstash/pipeline-pfsense`

## Validation

⚠️ **Never run this inside the LIVE container** (`docker exec suru.t3.ingestion.logstash-pfsense …`)
— a second JVM in its cgroup can OOM-crash production ingestion. Validate in a
throwaway container instead (own cgroup); the full command is in
[`pipelines/README.md`](pipelines/README.md) ("Validating a pipeline (safely)"):

```bash
docker run --rm -e LS_JAVA_OPTS='-Xmx256m' \
  -e OPENSEARCH_HOST=x -e OPENSEARCH_PORT=9200 -e OPENSEARCH_USER=x -e OPENSEARCH_PASSWORD=x \
  -v "$PWD/<file>.conf":/tmp/p.conf:ro \
  docker.elastic.co/logstash/logstash-oss:9.3.1 logstash --config.test_and_exit -f /tmp/p.conf
```

### Functional tests

`--config.test_and_exit` proves a pipeline compiles, not what it computes. A
`ruby { code => … }` block gets an executable test under `tests/` that
extracts the block and runs it under plain ruby with a stub `event`:

```bash
bash tier3-core/config/logstash-pfsense/tests/test-40-pfblockerng-timestamp.sh   # pfBlockerNG event-time derivation, 9 fixtures
```

## Notes

- ECS version target: v8
- OpenSearch output with TLS enabled
- Uses pipeline-to-pipeline routing for modular parsing
- Intended to pair with the SURU syslog-ng pfSense forwarder
