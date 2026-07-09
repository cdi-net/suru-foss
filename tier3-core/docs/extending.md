# Tier 3 — Extension Contract

> **AI-CONTEXT:** This document defines the machine-readable contract for adding
> new log sources, pipelines, or services to `tier3-core`. An AI agent
> implementing an extension **must** follow every numbered requirement below.
> Each requirement is tagged `[REQ-NNN]` for traceability.

---

## Adding a New Log Source (Logstash Pipeline)

### [REQ-001] File Naming

```
config/logstash-pfsense/pipelines/NN-<source-slug>.conf
```

- `NN` is a two-digit prefix in the range `10–89` (00 = input, 90+ = fallback/output)
- `<source-slug>` is lowercase hyphen-delimited, matching the `suru.log_type` tag
- Examples: `12-pfsense-nat.conf`, `36-geoip-extra.conf`, `40-suricata-flow.conf`

### [REQ-002] Pipeline Registry

Add an entry to `config/logstash-pfsense/pipelines.yml`:

```yaml
- pipeline.id: <source-slug>
  path.config: "/etc/logstash/pipelines/NN-<source-slug>.conf"
  pipeline.workers: 2
  pipeline.batch.size: 125
  queue.type: persisted
```

### [REQ-003] Input Routing Tag

The pipeline **must** set `[suru][log_type]` to a unique slug before any routing
filter. This tag is how downstream pipelines and dashboards identify the source.

```ruby
# In the filter block, always set:
filtermutate {
  add_field => {
    "[suru][log_type]" => "<source-slug>"
    "[suru][tier]"     => "tier1"   # or tier2, tier3
    "[event][module]"  => "<module-name>"
  }
}
```

### [REQ-004] ECS v8 Mandatory Fields

Every event **must** populate these fields before the output block:

| Field | Type | Notes |
|-------|------|-------|
| `@timestamp` | date | Must be the **original event time**, not ingest time |
| `event.kind` | keyword | `event`, `alert`, `metric`, or `state` |
| `event.category` | keyword[] | See ECS category taxonomy |
| `event.type` | keyword[] | See ECS type taxonomy |
| `event.module` | keyword | Lowercase source name |
| `host.name` | keyword | Source device hostname |
| `observer.type` | keyword | `firewall`, `ids`, `network-sensor`, etc. |
| `suru.log_type` | keyword | [REQ-003] routing tag |
| `suru.tier` | keyword | `tier1`, `tier2`, or `tier3` |

### [REQ-005] MITRE ATT&CK Annotations

If the log source produces detection-relevant events, annotate the pipeline
filter block with MITRE references as comments:

```ruby
# MITRE ATT&CK:
# Tactic:   TA0011 — Command and Control
# Technique: T1071.001 — Web Protocols
# Relevant when: destination.port in [80, 443] AND event.action == "block"
```

If ATT&CK metadata is available in the raw event (e.g. Suricata rule metadata),
map it to `threat.technique.id` and `threat.tactic.id`.

### [REQ-006] Output Target

```ruby
output {
  if [suru][log_type] == "<source-slug>" {
    opensearch {
      hosts            => ["${OPENSEARCH_HOST:opensearch-node1}:${OPENSEARCH_PORT:9200}"]
      index            => "suru-<source-slug>-%{+YYYY.MM.dd}"
      user             => "${LOGSTASH_OPENSEARCH_USER:logstash}"
      password         => "${LOGSTASH_OPENSEARCH_PASSWORD}"
      ssl_enabled      => true
      ssl_certificate_authorities => ["/etc/logstash/certs/root-ca.pem"]
      ssl_verification_mode => "full"
    }
  }
}
```

### [REQ-007] Dead Letter Fallback

Do **not** modify `90-deadletter.conf`. The dead-letter pipeline automatically
catches any event that does not match a known `suru.log_type`. Your pipeline
must set `suru.log_type` (REQ-003) to prevent legitimate events from falling
through to dead letter.

### [REQ-008] Validation

After creating the pipeline file:

```bash
# Syntax check — ⚠️ NOT via `docker exec` into the live container: a 2nd JVM in
# its cgroup can OOM-crash production ingestion. Use a throwaway container (own
# cgroup); full command in config/logstash-pfsense/pipelines/README.md:
docker run --rm -e LS_JAVA_OPTS='-Xmx256m' \
  -e OPENSEARCH_HOST=x -e OPENSEARCH_PORT=9200 -e OPENSEARCH_USER=x -e OPENSEARCH_PASSWORD=x \
  -v "$PWD/NN-<source-slug>.conf":/tmp/p.conf:ro \
  docker.elastic.co/logstash/logstash-oss:9.3.1 logstash --config.test_and_exit -f /tmp/p.conf

# Live reload (if pipeline.reload.automatic is enabled)
# Or restart: docker compose restart logstash

# Verify index created
curl -k -u admin:$PASS \
  https://localhost:9200/_cat/indices/suru-<source-slug>-*?v
```

### [REQ-009] Documentation

Update these files after adding a pipeline:

1. `docs/pipelines.md` — add to Pipeline Registry table and Pipeline Detail section
2. `docs/architecture.md` — add to Data Flow section if routing changes
3. `config/opensearch/index-templates/README.md` — add new index pattern if needed

---

## Adding a New Service (Docker Compose)

### [REQ-010] Compose File Location

Place the compose file in a logical subsystem directory:

```
tier3-core/<subsystem>/<service-name>/compose.yaml
```

### [REQ-011] Compose File Standards

Every service definition must include:

```yaml
services:
  <service-name>:
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "<health-command>"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
    networks:
      - suru-t3-core-internal
    deploy:
      resources:
        limits:
          memory: <NNN>m
```

### [REQ-012] Metrics Endpoint

Every Go service must expose:
- `GET /healthz` → HTTP 200 when healthy
- `GET /metrics` → Prometheus-compatible exposition format

Add a Prometheus scrape config to `../tier4-operations/monitoring/compose.yaml`.

### [REQ-013] RBAC for New API-Exposing Services

Any service exposing an internal API must:
1. Define roles in `config/opensearch/security/roles.yml` (if it reads/writes OpenSearch)
2. Add a dedicated service account to `config/opensearch/security/internal_users.yml`
3. Apply the mapping in `config/opensearch/security/roles_mapping.yml`
4. Document the account in `docs/opensearch.md` under **Defined Roles**

### [REQ-014] Secrets Management

- No secrets in `compose.yaml` — use `env_file: .env` or Docker secrets
- No secrets in any file tracked by Git
- All sensitive outputs in Terraform must use `sensitive = true`
- Runtime: read from environment variables mounted at container start

---

## Adding a New Index Template

### [REQ-015] Template Naming

```
config/opensearch/index-templates/suru-<source-slug>-template.json
```

If the new source fits within the existing `suru-*` template, do **not** create
a new template — instead, extend `suru-ecs-template.json` with the new field
mappings. Create a separate template only when field types conflict.

---

## Checklist for AI Agents

When implementing any extension, verify the following before submitting:

- [ ] [REQ-001] Pipeline file named correctly with numeric prefix
- [ ] [REQ-002] Entry added to `pipelines.yml`
- [ ] [REQ-003] `suru.log_type` set in filter block
- [ ] [REQ-004] All mandatory ECS fields populated
- [ ] [REQ-005] MITRE ATT&CK annotations present (if detection-relevant)
- [ ] [REQ-006] Output writes to `suru-<source-slug>-*` index
- [ ] [REQ-007] Dead letter pipeline not modified
- [ ] [REQ-008] `logstash --config.test_and_exit` passes
- [ ] [REQ-009] `docs/pipelines.md` and `docs/architecture.md` updated
- [ ] Unit test or sample event documented in pipeline file header comment
