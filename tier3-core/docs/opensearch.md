# Tier 3 — OpenSearch Configuration Reference

---

## Index Lifecycle (ISM Policy)

All `suru-*` indices are managed by the OpenSearch ISM (Index State Management)
policy **`suru-default`**, defined in:

```
tier3-core/config/opensearch/ism-policies/suru-default-policy.json
```

### Current policy (30-day delete)

```
Hot phase   : day 0–30  — writable, full primary shard
Delete phase: day 30+   — automatic index deletion
```

No warm phase is implemented. Single-node SOHO clusters cannot migrate shards
or shrink replicas, so a warm phase provides no benefit.

The policy is auto-attached to every new `suru-*` index via `ism_template`
(priority 100). It is applied by the `ism-policy-init` one-shot container on
deployment, and by `scripts/apply-ism-policies.sh` when run manually.

### Capacity planning

| Source | Growth rate | 30-day footprint |
|--------|-------------|-----------------|
| Suricata EVE | ~580 MB/day | ~17 GB |
| Zeek NSM | ~40 MB/day | ~1.2 GB |
| pfBlockerNG | ~300 KB/day | ~9 MB |
| pfSense firewall | ~10 MB/day | ~300 MB |
| **Total** | ~630 MB/day | **~19 GB** |

59 GB disk, 85% watermark = 50 GB ceiling. 30-day retention leaves ~31 GB
headroom — about 49 days of additional buffer.

### Customising the retention period

Edit `config/opensearch/ism-policies/suru-default-policy.json` — change the
`min_index_age` value in the `delete` transition:

```json
"transitions": [
  {
    "state_name": "delete",
    "conditions": {
      "min_index_age": "30d"   ← change this (e.g. "60d", "14d")
    }
  }
]
```

Then apply the updated policy:

```bash
# Via the deploy script (preferred — handles seq_no/primary_term automatically):
bash tier3-core/scripts/apply-ism-policies.sh

# Or directly with docker exec:
PASS=$(grep OPENSEARCH_INITIAL_ADMIN_PASSWORD tier3-core/.env | cut -d= -f2)
SEQ=$(docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS https://localhost:9200/_plugins/_ism/policies/suru-default \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['_seq_no'])")
PT=$(docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS https://localhost:9200/_plugins/_ism/policies/suru-default \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['_primary_term'])")
BODY=$(sed -n '/^{/,$p' tier3-core/config/opensearch/ism-policies/suru-default-policy.json)
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X PUT "https://localhost:9200/_plugins/_ism/policies/suru-default?if_seq_no=${SEQ}&if_primary_term=${PT}" \
  -H 'Content-Type: application/json' \
  -d "${BODY}"
```

### Check ISM policy status

```bash
PASS=$(grep OPENSEARCH_INITIAL_ADMIN_PASSWORD tier3-core/.env | cut -d= -f2)

# Policy definition
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS https://localhost:9200/_plugins/_ism/policies/suru-default?pretty

# Per-index state (shows which phase each index is in, days since creation)
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS "https://localhost:9200/_plugins/_ism/explain/suru-*?pretty" \
  | grep -E '"index"|"policy_id"|"state"|"min_index_age"'

# Force ISM to evaluate and act now (normally runs every 5 minutes)
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS -X POST \
  "https://localhost:9200/_plugins/_ism/retry/suru-*"
```

---

## Index Template

**File:** `config/opensearch/index-templates/suru-ecs-template.json`

- **Pattern:** `suru-*` — applies to every index created by Logstash
- **ECS version:** 8.x field mappings
- **Key settings:**
  - `number_of_shards: 1` (single-node SOHO default; scale up for cluster)
  - `number_of_replicas: 0` (single-node; set to 1 for HA)
  - `codec: best_compression`
  - `refresh_interval: 10s`
  - `index.mapping.ignore_malformed: true` — malformed field values (e.g. a
    non-IP token in `source.ip`) are silently skipped rather than rejecting
    the whole document to the DLQ. Monitor `_ignored` (see below) to catch
    persistent type mismatches.
  - `index.mapping.total_fields.limit: 2000` — ECS v8 + Suricata EVE +
    dynamic keyword templates can exceed the default 1000-field ceiling; new
    fields would otherwise be rejected silently. 2000 provides intentional
    headroom for all current sources.
- **Dynamic mapping:** `strings_as_keyword` dynamic template maps all string
  fields as `keyword` (aggregatable). The `message` field is mapped as `text`
  for full-text search.
- **Priority:** 100 — matches the ISM policy `ism_template` priority so both
  apply consistently to new indices.

### Mapping structure — nested objects, not dotted keys

Every multi-segment ECS field is declared as a **nested `object` + `properties`** tree,
not as a dotted-leaf key (`"source.ip": {"type":"ip"}`). Dotted keys in an OpenSearch
`properties` block register as literal field names, not as nested object paths — they
receive no data from Logstash (which serialises `[source][ip]` as a true nested JSON
object), causing `source.ip` to appear empty in dashboards while the `source` field
displays a serialised hash blob.

**Anti-pattern (wrong):**
```json
"properties": {
  "source.ip": { "type": "ip" }
}
```

**Correct:**
```json
"properties": {
  "source": {
    "properties": {
      "ip": { "type": "ip" }
    }
  }
}
```

All 15 ECS object groups (`source`, `destination`, `event`, `network`, `observer`,
`rule`, `dns`, `dhcp`, `http`, `tls`, `threat`, `zeek`, `_suru`, `service`, `host`,
`process`) are declared as explicit nested objects. Leaf-only fields (`@timestamp`,
`tags`, `in_iface`) remain at the top level.

### Pinned canon fields

The following fields are explicitly pinned in `properties` to prevent dynamic
mapping from assigning the wrong type and to lock in the constraints the
platform's dashboards and detection rules depend on:

| Field | Type | Constraint | Notes |
|-------|------|------------|-------|
| `in_iface` | `keyword` | `ignore_above: 1024`, **no `.keyword` sub-field** | Use bare `in_iface` in KQL and aggregations. `in_iface.keyword` does not exist and will silently return no results. |
| `network.application` | `keyword` | — | Suricata detected application/service protocol (renamed from the raw `service` field). |
| `dns.rrname` | `keyword` | — | DNS query name (Suricata EVE). |
| `dns.rrtype` | `keyword` | — | DNS record type. |
| `dns.question.name` | `keyword` | — | DNS query name (pfBlockerNG). |
| `http.hostname` | `keyword` | — | HTTP host header. |
| `http.url` | `keyword` | — | HTTP request URL. |
| `http.http_method` | `keyword` | — | HTTP method. |
| `http.status` | `long` | — | HTTP response code. Must be numeric; string values are silently dropped by `ignore_malformed`. |
| `tls.sni` | `keyword` | — | TLS Server Name Indication. |
| `tls.version` | `keyword` | — | TLS version string. |
| `threat.indicator.name` | `keyword` | — | Blocked FQDN or IP (pfBlockerNG). |
| `threat.indicator.type` | `keyword` | — | Indicator type (`domain-name` / `ipv4-addr`). |
| `threat.feed.name` | `keyword` | — | Block list name. |
| `_suru.log_type` | `keyword` | — | Internal routing tag set by syslog-ng. |
| `_suru.tier` | `keyword` | — | Origin tier (`tier1-perimeter` / `tier2` / `tier3`). |

**`in_iface` constraint:** the field is mapped as a pure `keyword` with
`ignore_above: 1024` and **no `fields` sub-object**. Never use
`in_iface.keyword` — it does not exist. The `strings_as_keyword` dynamic
template would also map it correctly, but an explicit pin eliminates any
ambiguity after a reindex.

### Monitoring `_ignored` (malformed-field silencing)

`ignore_malformed: true` prevents whole-document rejection, but it silently
drops the offending field value and records the field name in the document's
`_ignored` metadata. A rising `_ignored` count for a specific field indicates
values are being silently dropped due to a type mismatch — investigate the
source pipeline and fix the upstream parser.

```bash
# Find documents with silently-dropped malformed fields
GET suru-*/_search?size=0
{
  "query": { "exists": { "field": "_ignored" } },
  "aggs": { "dropped_fields": { "terms": { "field": "_ignored" } } }
}
```

Run this after any pipeline change. If a field appears in `dropped_fields`,
the ingestion pipeline is emitting that field with the wrong type — correct
the Logstash `mutate` block and reindex or wait for new-index rotation.

Applied automatically by the `template-init` one-shot container on deployment.
To apply or update manually:

```bash
PASS=$(grep OPENSEARCH_INITIAL_ADMIN_PASSWORD tier3-core/.env | cut -d= -f2)
BODY=$(sed -n '/^{/,$p' tier3-core/config/opensearch/index-templates/suru-ecs-template.json)
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X PUT "https://localhost:9200/_index_template/suru-ecs-template" \
  -H 'Content-Type: application/json' \
  -d "${BODY}"
```

> **Note:** template changes only affect **new** indices. Existing indices keep
> their current mapping. To apply a mapping change to existing data, reindex.

---

## Index Naming and Rollover

```
suru-pfsense-firewall-YYYY.MM.DD
suru-pfsense-services-YYYY.MM.DD
suru-suricata-YYYY.MM.DD
suru-zeek-YYYY.MM.DD
suru-pfblockerng-YYYY.MM.DD
suru-audit-YYYY.MM.DD
suru-deadletter-YYYY.MM.DD
```

Datestamps are set by Logstash at write time using `%{+YYYY.MM.dd}` in the output.
All indices are covered by the `suru-*` template pattern.

---

## Security (RBAC)

**Config directory:** `config/opensearch/security/`

### Defined Roles

| Role | Permissions | Assigned To |
|------|-------------|-------------|
| `suru_admin` | Full cluster + index admin | `admin` user |
| `suru_logstash` | Write to `suru-*` indices (no index delete/close) | `logstash` user |
| `suru_analyst` | Read `suru-*`, Dashboards read | `analyst` user |
| `suru_readonly` | Read `suru-*` (no Dashboards admin) | `readonly` user |

### Adding a New User

1. Generate bcrypt hash: `htpasswd -nbB -C 12 "" "<password>" | cut -d: -f2`
2. Add to `config/opensearch/security/internal_users.yml`
3. Map to role in `config/opensearch/security/roles_mapping.yml`
4. Apply: run `securityadmin.sh` (see deployment.md Step 4)

### Role Definitions

See `config/opensearch/security/roles.yml` for the full RBAC definitions.
Key design decisions:
- No role grants `cluster:admin/snapshot/delete` to non-admin users
- `suru_logstash` (ingest) role is index-pattern scoped to `suru-*` only and grants
  only `crud` + `create_index` + bulk-write + mapping-put — **never `indices_all`**;
  index delete/close is reserved for the ISM-managed lifecycle (SEC-074)
- All roles deny access to `.opendistro_security` and `.kibana_*` admin indices

---

## Node Configuration

**File:** `config/opensearch/opensearch.yml`

Key settings:

```yaml
# Single-node mode (SOHO)
discovery.type: single-node

# TLS — REST layer
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/opensearch-node.pem
plugins.security.ssl.http.pemkey_filepath:  certs/opensearch-node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem

# TLS — Transport layer (node-to-node)
plugins.security.ssl.transport.enforce_hostname_verification: true
plugins.security.nodes_dn:
  - "CN=suru-opensearch,O=SURU"
```

For a multi-node cluster, change `discovery.type` to `zen` and add
`discovery.seed_hosts` and `cluster.initial_master_nodes`.

---

## Dashboards Configuration

**File:** `config/opensearch/opensearch_dashboards.yml`

- Connects to OpenSearch via TLS with admin credentials from `.env`
- Multi-tenancy enabled (global + private tenants)
- Saved objects exported to `config/opensearch/dashboards/` via
  `scripts/import-dashboards.sh`

---

## Health Checks

```bash
# Cluster health
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS https://localhost:9200/_cluster/health?pretty

# Index stats
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS "https://localhost:9200/_cat/indices/suru-*?v&s=index"

# Disk usage per node (check before assuming index retention is the problem)
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS "https://localhost:9200/_cat/allocation?v&h=node,disk.total,disk.used,disk.avail,disk.percent,shards"

# ILM policy status
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS https://localhost:9200/_plugins/_ism/explain/suru-*

# Check for active cluster-level blocks
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS "https://localhost:9200/_cluster/settings?pretty&flat_settings=true"
```

### Cluster color — green is the expected steady state (single-node)

This is a single-node cluster (`discovery.type: single-node`): a replica shard
can never allocate alongside its own primary, so any index born with
`number_of_replicas > 0` leaves the cluster **permanently yellow**. Green is
enforced at three layers:

| Layer | Mechanism | Covers |
|-------|-----------|--------|
| `suru-ecs-template.json` (`number_of_replicas: 0`) | template at index creation | all `suru-*` data indices |
| `opensearch.yml` `plugins.index_state_management.history.number_of_replicas: 0` | plugin setting at node start | ISM's daily-rolling `.opendistro-ism-managed-index-history-*` (the largest recurring source) |
| `deploy.sh normalize_system_index_replicas()` (`auto_expand_replicas 0-1`, idempotent, every datalake start + `repair` step 4/7) | per-index setting after the fact | everything plugins create with no replica setting of their own: Security Analytics `.opensearch-sap-*` alert/finding indices, `.opendistro-alerting-config`, `.opensearch-alerting-config-lock` |

`auto_expand_replicas: 0-1` self-shrinks to 0 replicas on one node and grows a
replica automatically if a second node ever joins — the same mechanism the
security plugin uses for `.opendistro_security`. A yellow cluster is therefore
a *finding*, not an expected state: list the culprits with

```bash
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS "https://localhost:9200/_cat/indices?v&health=yellow&expand_wildcards=all"
```

(`expand_wildcards=all` is required — the plugin indices are hidden and
invisible to a plain `_cat/indices`.)

---

## Disk Watermark Recovery

OpenSearch blocks index creation when a node breaches the high disk watermark
(default 85%). The block is set as a **persistent** cluster setting:

```
"cluster.blocks.create_index" : "true"
```

**Step 1 — Find the actual consumer.** OpenSearch data is often small; check
Docker overhead first:

```bash
docker system df
docker exec suru.t3.datalake.opensearch \
  du -sh /usr/share/opensearch/data /usr/share/opensearch/logs
```

If Docker images + stopped containers account for the bulk of usage, prune them
(**does not touch named volumes**):

```bash
docker system prune -a -f
```

**Step 2 — Raise watermarks transiently** (buys time while reclaiming space):

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X PUT https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"transient":{"cluster.routing.allocation.disk.watermark.low":"90%","cluster.routing.allocation.disk.watermark.high":"93%","cluster.routing.allocation.disk.watermark.flood_stage":"97%"}}'
```

**Step 3 — Remove the index create block:**

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X PUT https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.blocks.create_index":null}}'
```

**Step 4 — Delete old indices / force ILM** if disk is genuinely full of index
data (not Docker overhead):

```bash
# Largest indices first
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  "https://localhost:9200/_cat/indices/suru-*?v&s=store.size:desc&h=index,store.size,docs.count"

# Delete a date range
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X DELETE "https://localhost:9200/suru-*-2025.*"

# Force ILM to run immediately
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X POST "https://localhost:9200/_plugins/_ism/retry/suru-*"
```

**Step 5 — Reset transient watermarks** once disk is below 80%:

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS \
  -X PUT https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"transient":{"cluster.routing.allocation.disk.watermark.low":null,"cluster.routing.allocation.disk.watermark.high":null,"cluster.routing.allocation.disk.watermark.flood_stage":null}}'
```
