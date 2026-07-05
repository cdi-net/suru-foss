# OpenSearch Security Analytics — Verified Plugin/API Surface

Registry doc for the SIEM Security Analytics feature (T0a, extended by T7's
follow-up live probes). All claims below are live observations against the
running `suru.t3.datalake.opensearch` container, captured 2026-06-25. Per
CONTRIBUTING.md, every endpoint claim cites the exact
command run — no claim is taken from the plugin's published docs without
independent live confirmation here.

`$PASS` below = the value of `OPENSEARCH_INITIAL_ADMIN_PASSWORD` in `tier3-core/.env`.

---

## Operational Requirements — read before assuming detection is active

Security Analytics detection depends on a **daily operational task** that is
separate from the one-time `apply-security-analytics.sh` provisioning step.

### Alias rotation — required for functional detection

Detectors query OpenSearch through stable index aliases
(`suru-zeek-current`, `suru-suricata-current`) rather than wildcard patterns
or dated index names. Logstash rolls to a new dated index each midnight UTC
(`suru-<type>-YYYY.MM.dd`). Unless the alias is rotated to point at the new
index, **all detectors will query yesterday's index and produce no alerts on
today's data**.

**Action required:** schedule `tier3-core/scripts/rotate-sa-aliases.sh` to
run daily at 00:10 UTC on the SIEM Docker host.

```bash
# Quick manual check — do the aliases point to today's index?
docker exec suru.t3.datalake.opensearch \
  curl -sk -u admin:$PASS \
  "https://localhost:9200/_cat/aliases/suru-zeek-current,suru-suricata-current?v"
```

If either alias points to a date before today, run the rotation manually:

```bash
OPENSEARCH_INITIAL_ADMIN_PASSWORD=<password> \
  bash tier3-core/scripts/rotate-sa-aliases.sh --verbose
```

See `tier3-core/scripts/rotate-sa-aliases.sh` header for cron setup
(`/etc/cron.d` and `crontab -e` examples).

---

## Plugin installed (confirmed)

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS "https://localhost:9200/_cat/plugins?v" | grep -i analytics
```
Output:
```
suru-t3-datalake-opensearch opensearch-security-analytics 3.7.0.0
```

## Verified endpoints

### 1. `POST _plugins/_security_analytics/rules/_search?pre_packaged=true`

**Param name is `pre_packaged` (snake_case), NOT `prePackaged`.** The camelCase
form returns a 400:
```
{"error":{"root_cause":[{"type":"illegal_argument_exception","reason":"request
[/_plugins/_security_analytics/rules/_search] contains unrecognized parameter:
[prePackaged] -> did you mean [pre_packaged]?"}],...,"status":400}
```

Corrected call:
```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS -X POST \
  "https://localhost:9200/_plugins/_security_analytics/rules/_search?pre_packaged=true" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
```
→ HTTP 200. Response top-level keys: `took`, `timed_out`, `_shards`, `hits`
(standard OpenSearch search-response shape; rule documents live under `hits.hits`).

### 2. `POST _plugins/_security_analytics/detectors/_search`

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS -X POST \
  "https://localhost:9200/_plugins/_security_analytics/detectors/_search" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
```
→ HTTP 200. Response top-level keys: `_scroll_id`, `took`, `timed_out`,
`terminated_early`, `num_reduce_phases`, `_shards`, `hits`, `suggest`, `profile`
— a richer/scroll-capable search response than the rules endpoint.

### 3. `POST _plugins/_security_analytics/correlation/rules/_search`

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS -X POST \
  "https://localhost:9200/_plugins/_security_analytics/correlation/rules/_search" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}'
```
→ HTTP 200. Response top-level keys: `took`, `timed_out`, `_shards`, `hits`
(same shape as the rules endpoint).

## Log-type CRUD — now verified (create + delete)

Initial probing under §"Endpoint requiring further investigation" (below, kept
for the record of the wrong shapes that returned 500) found the correct shape
on a follow-up pass:

### Create: `POST _plugins/_security_analytics/logtype`

Body requires `name`/`description`/`source` (NOT a `query`-style search body —
that's what caused the earlier 500 NPEs):
```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS -X POST \
  "https://localhost:9200/_plugins/_security_analytics/logtype" \
  -H 'Content-Type: application/json' \
  -d '{"name":"suru_test_probe","description":"probe only","source":"Custom"}'
```
→ **HTTP 201** (re-verified with `-w '%{http_code}'` during T7's follow-up
probe — the original capture below omitted the status code and is corrected
here; do not assume 200 for this endpoint):
```json
{"_id":"D24t_p4BG5lWI50icpOE","_version":1,"logType":{"name":"suru_test_probe","description":"probe only","category":"Other","source":"Custom","tags":{"correlation_id":25}}}
```
Note: response auto-fills `category:"Other"` when not supplied — T7 should
supply an explicit `category` for each SURU custom log type rather than
relying on the default. **Also confirmed by T7:** `category` must be one of
the plugin's specific display-string enum values — `"Network Activity"` is
confirmed working; both `"network"` and `"Network"` 400 with an empty-reason
`action_request_validation_exception`. See "Implication for T7" below for
the full enum-value finding.

### Delete: `DELETE _plugins/_security_analytics/logtype/<_id>`

```bash
docker exec suru.t3.datalake.opensearch curl -sk -u admin:$PASS -X DELETE \
  "https://localhost:9200/_plugins/_security_analytics/logtype/D24t_p4BG5lWI50icpOE"
```
→ HTTP 200: `{"_id":"D24t_p4BG5lWI50icpOE","_version":1}`

The test log type above was created and deleted live during this verification
pass; cleanup confirmed (`rules/_search` still HTTP 200 immediately after).
**T7 can rely on this create/delete shape** for the SURU custom log types in
`tier2-telemetry/opensearch/field-mappings/`. List/search-all-logtypes shape is
still unconfirmed (see below) — T7 should track created `_id`s itself for
idempotent re-runs rather than depending on a list call.

## Endpoint still unconfirmed: list/search all log types

- `GET _plugins/_security_analytics/logtype` → HTTP 405 (`allowed: [POST]`).
- `POST _plugins/_security_analytics/logtype` with `{}`, `{"query":{"match_all":{}}}`,
  or `{"is_builtin":true}` → **HTTP 500** every time (NPE) — these bodies are
  being routed to the CREATE handler (since POST means create here, confirmed
  above), not a list/search handler, and a create call with no `name` field
  NPEs. **There is no separate POST-based search verb for logtype** the way
  there is for rules/detectors/correlation-rules — `_search` is not a valid
  sub-path (`/logtype/search` → 405, `allowed: [DELETE, PUT]`, i.e. that path
  is for delete-by-name/update-by-name, not search).
- **Conclusion:** this plugin version (3.7.0.0) likely has no bulk list-all
  endpoint exposed the same way as rules/detectors/correlations, or it exists
  under an undiscovered path. T7 must NOT call `POST logtype` with an empty
  or query-shaped body expecting a list — it will always 500. For idempotency,
  T7 should persist the `_id` returned at creation time (e.g. in a local state
  file or by using a deterministic `name` and treating "create fails because
  name exists" as the existence check, if the plugin enforces unique names —
  verify that specific behavior before relying on it).

## Detector creation — CONFIRMED (T7 follow-up probe, 2026-06-25)

The 400 `parsing_exception` documented above was resolved by populating
`pre_packaged_rules` with a real rule ID. The follow-up probe surfaced two
*additional* undocumented constraints beyond the empty-array parser bug —
both confirmed live:

### Constraint 1 — `indices` must be a concrete index/alias, never a wildcard pattern

```bash
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_plugins/_security_analytics/detectors" \
  -H "Content-Type: application/json" \
  -d "{ ... \"indices\":[\"suru-suricata-*\"] ... }"'
```
→ HTTP 500:
```
{"error":{"root_cause":[{"type":"security_analytics_exception","reason":
"Validation Failed: 1: Index patterns are not supported for doc level
monitors.;"}],...}}
```
This 500 persisted even with a **concrete dated index name**
(`suru-suricata-2026.06.23`, no wildcard) — the underlying Security Analytics
monitor is a doc-level monitor and apparently rejects any index name
containing a literal `.` followed by digits the same way it rejects a glob,
OR (more likely per the error text) it specifically rejects any name it
classifies as matching an index-pattern shape. The fix that worked: create a
plain **index alias** with no special characters
(`_aliases` API, `{"actions":[{"add":{"index":"<concrete-index>","alias":
"<alias-name>"}}]}`) and pass the alias name in `indices`.

**Implication for `apply-security-analytics.sh`:** every detector's
`inputs[].detector_input.indices` must reference a **stable alias**, not the
`suru-<type>-*` wildcard the rendered JSON's `index_pattern` field carries.
This script creates one alias per log type (e.g. `suru-zeek-conn-current` →
the most recent `suru-zeek-YYYY.MM.dd` index) before creating any detector
that targets it. Alias rotation is automated by `tier3-core/scripts/rotate-sa-aliases.sh`.
Run it once manually after each midnight UTC rollover, or schedule it as a
daily system cron job on the SIEM host (see that script's header for
`/etc/cron.d` and `crontab -e` setup examples). The script is idempotent —
safe to re-run if today's alias is already current.

### Constraint 2 — rule compatibility is enforced by `category` vs `detector_type`

A `pre_packaged_rules` entry's rule must have a Sigma `category` (the
*plugin's own* nested `rule.category` field, confirmed via mapping
inspection — see below) that the detector's `detector_type` recognizes as
compatible. A rule with `category: others_cloud` against
`detector_type: "network"` fails with:
```
{"error":{"root_cause":[{"type":"status_exception","reason":
"Detector cannot be created as no compatible rules were provided"}],...}}
```
Confirmed working: a rule with `category: network` (found via
`POST rules/_search?pre_packaged=true` with a `nested` query against
`rule.category` — the API's flattened response `_source.category` is
correct, but the underlying mapping is `nested` under `rule`, so direct
top-level `category`/`category.keyword` term queries against the search
response return zero hits; use `{"query":{"nested":{"path":"rule","query":
{"term":{"rule.category":"<value>"}}}}}`) against `detector_type: "network"`.

### Confirmed working create + delete

```bash
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_aliases" -H "Content-Type: application/json" \
  -d "{\"actions\":[{\"add\":{\"index\":\"suru-suricata-2026.06.23\",\"alias\":\"suru-probe-alias\"}}]}"'
# -> {"acknowledged":true}

docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_plugins/_security_analytics/detectors" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"detector\",\"name\":\"suru_probe_detector\",
       \"detector_type\":\"network\",\"enabled\":false,\"enabled_time\":null,
       \"schedule\":{\"period\":{\"interval\":5,\"unit\":\"MINUTES\"}},
       \"inputs\":[{\"detector_input\":{\"description\":\"probe\",
         \"indices\":[\"suru-probe-alias\"],
         \"pre_packaged_rules\":[{\"id\":\"56fa3cd6-f8d6-4520-a8c7-607292971886\"}],
         \"custom_rules\":[]}}],\"triggers\":[]}"'
```
→ **HTTP 201** (re-verified with `-w '%{http_code}'`; do not assume 200 for
detector create), `_id` returned. Delete (`DELETE /detectors/<_id>`) → HTTP
200 `{"_id":"...","_version":1}`. Both confirmed live and cleaned up.

**Not yet usable for SURU's actual detector content:** all five rendered
SURU detectors (`tier2-telemetry/opensearch/detectors/*.yml`) bind to
**custom Sigma rule IDs** (tier2-authored, e.g.
`9c1d4a2b-0010-4e7f-8a1b-c2d3e4f5a6b7`), populated into
`custom_rules`, not `pre_packaged_rules`. Custom-rule registration is a
prerequisite (see next section) and is currently **blocked by a live build
bug** — `apply-security-analytics.sh`'s detector-import step is therefore
stubbed for the five SURU-authored detectors pending that bug's resolution,
even though the detector-create wire shape itself is now fully confirmed.

## Custom Sigma rule creation — RESOLVED (2026-06-25)

All 5 SURU custom rules are now registered live. OpenSearch-assigned IDs:

| Sigma UUID | OS _id | Title | Category |
|---|---|---|---|
| `9c1d4a2b-0010-4e7f-8a1b-c2d3e4f5a6b7` | `gW6e_54BG5lWI50iPpPB` | Port Scan or Host Sweep | network |
| `ad2e5b3c-0011-4f8a-9b2c-d3e4f5a6b7c8` | `gm6e_54BG5lWI50iP5O2` | Large Outbound Transfer | network |
| `7b4e3f2a-0002-4c6d-9e0f-b2c3d4e5f6a7` | `g26e_54BG5lWI50iQJNl` | DNS Tunneling | dns |
| `be3f6c4d-0012-4a9b-8c3d-e4f5a6b7c8d9` | `hG6e_54BG5lWI50iQZMN` | TLS Certificate Anomaly | network |
| `6a3d2e1f-0001-4b5c-8d9e-a1b2c3d4e5f6` | `lG6g_54BG5lWI50iUZO3` | Exploit Public-Facing App | network |

**Detectors live (all 5, enabled=true):**

| _id | Detector name |
|---|---|
| `nW6k_54BG5lWI50ivJPa` | suru-recon-port-scan |
| `pG6k_54BG5lWI50ivZP5` | suru-exfil-large-transfer |
| `q26k_54BG5lWI50iv5MZ` | suru-c2-dns-tunneling |
| `sm6k_54BG5lWI50iwJNJ` | suru-defevasion-tls-anomaly |
| `uW6k_54BG5lWI50iwZOS` | suru-initaccess-exploit |

**Root cause of the earlier NPEs (documented for future reference):**

The NPE was NOT a log-type field-mapping issue, NOT a missing category match, and NOT
an upstream OpenSearch bug. Two SURU-side errors caused it:
1. `date:` and `modified:` fields used ISO `YYYY-MM-DD` format — OpenSearch SA's
   `SigmaRule` parser requires `YYYY/MM/DD` (slash-separated). Parsing fails → null
   `Date` object → `getDate().getTime()` → NullPointerException.
2. `status: production` is not a valid SA status value; accepted values are
   `experimental`, `test`, `stable`, `deprecated`.

Both fixed in `tier2-telemetry/sigma/rules/**` on 2026-06-25. Earlier NPE probes also
had missing `author`/`references`/`tags` fields which independently caused a different
`fromDict` null access, masking the date-format root cause.

**Confirmed working rule-create call:**
```bash
docker exec -i suru.t3.datalake.opensearch sh -c \
  "cat > /tmp/rule.yml && curl -sk -u \"admin:\$OPENSEARCH_INITIAL_ADMIN_PASSWORD\" \\
  -X POST 'https://localhost:9200/_plugins/_security_analytics/rules?category=network' \\
  -H 'Content-Type: application/json' --data-binary @/tmp/rule.yml" < rule.yml
```
Body: raw Sigma YAML (not JSON-wrapped). Required fields: `title`, `id`, `status`
(one of `experimental|test|stable|deprecated`), `description`, `author`, `date`
(**YYYY/MM/DD**), `modified` (**YYYY/MM/DD**), `tags` (non-empty), `references`,
`logsource`, `detection`, `falsepositives`, `level`.

**Confirmed working detector-create call (flat top-level, NOT wrapped in `"detector":{}`)**:
```bash
POST _plugins/_security_analytics/detectors
{
  "type": "detector",
  "name": "<name>",
  "detector_type": "<built-in category e.g. network|dns|windows>",
  "enabled": true,
  "enabled_time": null,
  "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
  "inputs": [{"detector_input": {
    "description": "...",
    "indices": ["<concrete-alias-no-wildcards>"],
    "custom_rules": [{"id": "<opensearch-assigned-rule-id>"}],
    "pre_packaged_rules": []
  }}],
  "triggers": []
}
```
→ **HTTP 201**, detector `_id` returned. The body is FLAT at top level (NOT nested
under a `"detector":{}` key — that form returns "Detector name is null").

---

## Custom Sigma rule creation — historical investigation record (superseded above)

`POST _plugins/_security_analytics/rules?category=<cat>` (category is a
**query param**, confirmed by the same snake_case-param pattern as
`pre_packaged`; body `{"category":...}` 400s with `"Missing category"`) is
the create endpoint for custom (non-pre-packaged) Sigma rules. Tried against
three rule bodies — SURU's actual `port-scan-sweep.yml`, a 12-line minimal
Sigma rule, and a second minimal variant closer to a confirmed pre-packaged
rule's shape — and against every recognized category value
(`network`, `Network`, `windows`, `linux`, `dns`, `apache_access`,
`cloudtrail`): **all return an identical HTTP 500**:
```
{"error":{"root_cause":[{"type":"security_analytics_exception","reason":
"Cannot invoke \"Object.toString()\" because the return value of
\"java.util.Map.get(Object)\" is null"}],...,
"caused_by":{"type":"null_pointer_exception",...}}
```
Unrecognized categories (`other`, `cloud`, `web`) correctly 400 with
`"Invalid rule category <x>"` instead — proving the query param IS being
validated and `network`/`windows`/etc. ARE accepted as valid categories; the
NPE fires only after that validation passes, inside rule indexing itself.

**Root cause located via container logs** (`docker logs
suru.t3.datalake.opensearch`), confirming the failure is server-side, not a
request-shape issue:
```
Caused by: java.lang.NullPointerException: Cannot invoke "Object.toString()"
because the return value of "java.util.Map.get(Object)" is null
  at org.opensearch.securityanalytics.rules.objects.SigmaRule.fromDict(SigmaRule.java:193)
  at org.opensearch.securityanalytics.rules.objects.SigmaRule.fromYaml(SigmaRule.java:204)
  at org.opensearch.securityanalytics.transport.TransportIndexRuleAction$AsyncIndexRulesAction$2.onResponse(TransportIndexRuleAction.java:204)
  at ...LogTypeService.getRuleFieldMappings(LogTypeService.java:658)
  at ...TransportIndexRuleAction$AsyncIndexRulesAction.prepareRuleIndexing(TransportIndexRuleAction.java:198)
```
`LogTypeService.getRuleFieldMappings` calls into `SigmaRule.fromDict`, which
NPEs on a `Map.get()` returning null — this fires during **field-mapping
resolution for the registered log type**, before the rule document is
indexed. Per `evidence-based-claims.md` §4, this is reported as
"insufficient evidence to determine the exact missing key" rather than a
guessed fix — the NPE is in OpenSearch's own internal Sigma-to-rule-field
translation, not in any field of the YAML bodies tried (three independently
varied YAML shapes, including a near-verbatim copy of a confirmed-working
pre-packaged rule's `logsource`/`detection` structure, all hit the identical
stack trace at the identical line). The most likely mechanism — not yet
independently confirmed per the best-of-N discipline in
`evidence-based-claims.md` §6 — is that `getRuleFieldMappings` expects the
target log type's field-mapping document (the thing `_plugins/
_security_analytics/mappings` reads) to already exist and be non-empty for
whatever the rule's logsource resolves to, and our custom rules' logsource
(`product: zeek`, `service: conn`, etc.) resolves to a log-type bucket with
no registered field-mapping, causing the internal lookup map to come back
empty and `.get()` to return null on a key the code assumes is always
present.

**`[MISSING REFERENCE: OpenSearch Security Analytics custom-rule creation
prerequisite ordering vs. log-type field-mapping registration — propose web
search: "OpenSearch Security Analytics POST _plugins/_security_analytics/rules
NullPointerException SigmaRule.fromDict getRuleFieldMappings"]`**

**Operator action needed before this can be unblocked:** confirm whether
custom-rule creation requires a `PUT _plugins/_security_analytics/mappings`
call (field-mapping registration for the target log type) to run first, or
file an upstream OpenSearch bug report citing the stack trace above.

**UPDATE (2026-06-25) — mapping-prerequisite theory tested and REFUTED.**

Live test performed: created a real index alias (`suru_zeek_conn_probe` →
`suru-zeek-2026.06.23`, a real live index with data), then registered a field
mapping against it:
```bash
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" -X POST \
  "https://localhost:9200/_plugins/_security_analytics/mappings" \
  -H "Content-Type: application/json" -d "{
    \"index_name\": \"suru_zeek_conn_probe\",
    \"rule_topic\": \"network\",
    \"partial\": true,
    \"alias_mappings\": {\"properties\":{\"source.ip\":{\"path\":\"orig_h\",\"type\":\"alias\"}}}
  }"'
```
→ HTTP 200 `{"acknowledged":true}` — this call itself works fine and is a
legitimate, separate, confirmed-working endpoint (`POST/GET
_plugins/_security_analytics/mappings?index_name=<alias>` — note the query
param is `index_name`, snake_case, same pattern as `pre_packaged`; `logtype`
and `index` are both rejected as unrecognized).

Then retried the exact same minimal probe rule (`logsource: {category:
network, product: zeek, service: conn}`) against `POST
_plugins/_security_analytics/rules?category=network`:
```bash
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD" -X POST \
  "https://localhost:9200/_plugins/_security_analytics/rules?category=network" \
  -H "Content-Type: application/json" --data-binary @/tmp/probe2.json'
```
→ **Identical HTTP 500, identical NPE, identical stack trace** as before the
mapping was registered.

**Conclusion: registering an index-level field mapping does NOT unblock
custom-rule creation.** This is consistent with the rule-create call's own
shape — it takes no `index_name`/`index` parameter at all, only `category`
(a query param) and the rule body — so there is no mechanism by which an
index-scoped mapping could be consulted during rule creation in the first
place. The NPE fires purely from `category` + rule-body resolution, before
any index is ever in scope. **Point 1 (mapping prerequisite) is refuted.**

Test artifacts (alias `suru_zeek_conn_probe`) were created and removed live;
cleanup confirmed via `_cat/aliases` showing no `suru_*` test aliases
remaining.

**Revised operator action: this is a genuine upstream OpenSearch
Security Analytics bug (3.7.0.0), not a sequencing/prerequisite issue in our
control.** File an upstream bug report against
`opensearch-project/security-analytics` citing:
- Endpoint: `POST _plugins/_security_analytics/rules?category=network`
- Stack trace: `SigmaRule.fromDict` (`SigmaRule.java:193`) ←
  `LogTypeService.getRuleFieldMappings` (`LogTypeService.java:658`) ←
  `TransportIndexRuleAction$AsyncIndexRulesAction.prepareRuleIndexing`
- Reproduction: any well-formed custom Sigma rule YAML, any valid category
  (`network`, `windows`, `linux`, `dns`, etc.) — 100% reproduction rate across
  3 independently varied rule bodies and 7 category values tried.
- Confirms server-side defect: `getRuleFieldMappings` calls `Map.get()` on
  something that returns null and then unconditionally calls `.toString()`
  on the result, with no null-check, regardless of whether any field mapping
  has been registered for any index.

Until this is fixed upstream (or a version bump to a patched OpenSearch
release resolves it), SURU's 5 custom-Sigma-rule-backed detectors cannot be
imported. `apply-security-analytics.sh`'s detector-import step remains
correctly `[STUB]`-skipped for these five detectors.

## Correlation-rule creation — CONFIRMED

```bash
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_plugins/_security_analytics/correlation/rules" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"suru_probe_correlation\",\"correlate\":[
        {\"index\":\"suru-suricata-2026.06.23\",\"category\":\"network\",\"query\":\"*\",\"field\":\"source.ip\"},
        {\"index\":\"suru-pfblockerng-2026.06.23\",\"category\":\"network\",\"query\":\"*\",\"field\":\"source.ip\"}
      ]}"'
```
→ **HTTP 201** (re-verified with `-w '%{http_code}'`; do not assume 200 for
correlation-rule create either), `_id` returned (note: unlike a detector,
**concrete dated index names work directly here** — no alias workaround
needed for correlation rules; the "index patterns not supported" restriction
documented above is specific to detectors/doc-level monitors).

Delete: `DELETE _plugins/_security_analytics/correlation/rules/<_id>` → HTTP
200 `{"acknowledged":true}` (different response shape than detector delete —
no `_id`/`_version` echoed back, just `acknowledged`). Both confirmed live
and cleaned up.

**Not yet usable for the SURU headline correlation
(`pfblockerng-suricata-zeek-c2-chain.json`):** the rendered correlation rule
has 3 legs, each with its own `query`/`aggregation` (not a bare `"*"`), and
the live wire format's `correlate[].query` field's exact query-DSL/Lucene
acceptance for non-trivial queries is unconfirmed — only a wildcard `"*"`
match was probed. `apply-security-analytics.sh` imports this correlation
rule using the confirmed bare shape (`index`/`category`/`field`, with
`query` passed through from the rendered JSON's `legs[].query` Lucene string
verbatim) but this exact pass-through has not been independently live-fired
against a real multi-leg match — flagged in Assumptions below.

## Action / notification-channel creation — CONFIRMED (OpenSearch Notifications plugin)

Security Analytics' email trigger action is backed by the **OpenSearch
Notifications plugin** (`opensearch-notifications` +
`opensearch-notifications-core`, confirmed installed via `_cat/plugins`), not
a Security-Analytics-specific endpoint. Two chained config types are
required: an `smtp_account` channel, then an `email` channel referencing it
by `email_account_id`.

```bash
# 1. SMTP account (field is "from_address", NOT "sender_address" — the
#    first attempt with sender_address 400s: "from_address field absent")
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_plugins/_notifications/configs" \
  -H "Content-Type: application/json" \
  -d "{\"config\":{\"name\":\"suru_probe_email_channel\",\"description\":\"probe\",
       \"config_type\":\"smtp_account\",\"is_enabled\":true,
       \"smtp_account\":{\"from_address\":\"siem@suru.local\",
       \"host\":\"smtp.example.com\",\"port\":587,\"method\":\"start_tls\"}}}"'
# -> {"config_id":"<id>"}
# NOTE: top-level "config_id" key must be OMITTED from the request body
# entirely (not set to "") — an empty-string config_id 400s with
# "Invalid characters in id : ". Let the server assign it.

# 2. Email recipient channel, referencing the smtp_account by ID
docker exec suru.t3.datalake.opensearch sh -c '
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" -X POST \
  "https://localhost:9200/_plugins/_notifications/configs" \
  -H "Content-Type: application/json" \
  -d "{\"config\":{\"name\":\"suru_probe_email_recipient\",\"description\":\"probe\",
       \"config_type\":\"email\",\"is_enabled\":true,
       \"email\":{\"email_account_id\":\"<smtp_account_config_id>\",
       \"recipient_list\":[{\"recipient\":\"soc@suru.local\"}]}}}"'
# -> {"config_id":"<id>"}
```
Both → HTTP 200. Delete: `DELETE _plugins/_notifications/configs/<id>` →
HTTP 200 `{"delete_response_list":{"<id>":"OK"}}`. All four calls (2 creates,
2 deletes) confirmed live and cleaned up.

### SMTP AUTH — OpenSearch keystore AffixSettings

The `smtp_account` config JSON carries **no** username/password field — SMTP
AUTH is supplied exclusively via the node's OpenSearch **keystore**, as
AffixSettings `opensearch.notifications.core.email.<account>.username` /
`.password` (`PluginSettings.EMAIL_USERNAME`/`EMAIL_PASSWORD` in
`opensearch-notifications-core-3.7.0.0.jar` — both `SecureSetting.secureString`
AffixSettings). `<account>` is the `smtp_account` config's own `name`
(`SmtpDestination.accountName`); SURU uses `suru_security_analytics_smtp`.
`mail.smtp.auth` is enabled by the client whenever `method != none`.

`opensearch-notifications-core`'s plugin class (`NotificationCorePlugin`)
implements `ReloadablePlugin`; its `reload(Settings)` re-derives destination
settings from the reloaded keystore (`PluginSettings.loadDestinationSettings` /
`setDestinationSettings`). So `POST _nodes/reload_secure_settings` makes
new/rotated SMTP AUTH creds live **without a node restart** — verified
end-to-end by a `_plugins/_notifications/feature/test/<email_channel_id>` send
returning `delivery_status: 200 Success` to a real inbox.

`apply-security-analytics.sh`'s `provision_smtp_keystore_auth` writes both keys
via `opensearch-keystore add --stdin --force` (stdin only — never argv/log),
then calls `reload_secure_settings`; blanking both env vars removes any
previously-provisioned keys. Requires the `opensearch-config` named volume
mounted **rw** into the init container (see `securityanalytics-init` in
`datalake/opensearch/compose.yaml`) — writable under the full hardening profile
(`cap_drop: ALL`, `no-new-privileges`, `read_only` rootfs, non-root
`1000:1000`; the keystore file is created uid/gid 1000 on the node's first boot,
before `securityanalytics-init` runs via the `depends_on` chain). This is the
product-native secure-keystore credential-injection model — the secret never
touches the config JSON, an env var in the running node, or a log line.

Hardening follow-up: the rw mount grants the init container write access to the
whole config dir (certs, `internal_users.yml`) for its run, not just
`opensearch.keystore` — scoping it via a volume `subpath` is a future refinement.

**Not yet confirmed:** how a detector's `triggers[].actions[]` actually
*references* a Notifications `email`-type config_id at the Security
Analytics layer (i.e. the `trigger.actions[]` binding schema mentioned in
the rendered `email-default.json`'s `_render_meta` note) — this probe only
confirmed the Notifications plugin's own config CRUD, not the
detector-trigger-to-notification-channel wiring. `slack`/`webhook` action
types in the rendered actions (`slack-unconfigured.json`,
`webhook-unconfigured.json`) were not probed at all — both remain
`status: unconfigured` in the rendered JSON and are intentionally **not**
created by `apply-security-analytics.sh` (the script logs and skips them).
`perimeter-block.json`'s `action_type: perimeter_block` is a SURU-internal
concept (calls T0b's Tier-1 API), not an OpenSearch-native action/channel
type at all — it is recorded in `apply-security-analytics.sh`'s local state
file for the operator's reference but never sent to any OpenSearch endpoint.

## Implication for T7 (tier3 import-only provisioner)

- **Log-type creation: CONFIRMED**, with a corrected `category` enum value.
  `category` must be one of the plugin's specific display strings (e.g.
  `"Network Activity"` — confirmed; both `"network"` and `"Network"` 400 with
  an empty-reason `action_request_validation_exception`). Duplicate-name
  creation **is rejected** (`"Log Type with name <x> already exists"`,
  HTTP 400) — confirmed live — so `apply-security-analytics.sh` uses
  create-and-treat-409/400-as-exists for idempotency, rather than persisting
  `_id`s in a state file (simpler, no extra state file to keep in sync; the
  plugin itself is the source of truth for "does this name exist").
- **Detector creation: CONFIRMED** for the wire shape (concrete alias in
  `indices`, category-compatible `pre_packaged_rules`/`custom_rules` IDs).
  SURU's own five detectors cannot be created yet because they depend on
  custom-rule registration, which is blocked by the NPE above.
- **Correlation-rule creation: CONFIRMED** for the bare shape; the SURU
  headline 3-leg correlation rule's exact `query` field pass-through is
  imported but not independently live-fire-tested beyond the wire format.
- **Notification (email) channel creation: CONFIRMED.** Slack/webhook
  remain unconfigured by design; perimeter_block is SURU-internal and never
  sent to OpenSearch.
- `_render_meta.schema_verified` should be updated to `true` for `detectors`
  (wire shape confirmed, though SURU's specific detectors are still blocked
  on custom-rule creation), `correlation-rules` (confirmed), and
  `actions/email-default` + `actions/perimeter-block` (channel-CRUD
  confirmed; the actual trigger-binding schema is still unconfirmed — see
  above). `actions/slack-unconfigured` and `actions/webhook-unconfigured`
  stay `false` (genuinely unconfigured/unprobed). Custom Sigma rule files
  under `sigma/` stay `false` (blocked on the NPE).
