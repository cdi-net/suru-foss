# Tier 3 — Logstash Pipeline Catalogue

> **AI-CONTEXT:** This document catalogues every Logstash pipeline in
> `config/logstash-pfsense/pipelines/` (primary, live deployment) and
> `config/logstash-opnsense/pipelines/` (OPNsense standby — not currently deployed).
> Profile selection is controlled by `ROUTER_PLATFORM` in `tier3-core/.env`.
> When adding a new log source, read `extending.md` first, then add an entry here.

---

## Pipeline Registry (`pipelines.yml`)

Pipelines are numbered to enforce load order. Each pipeline is an independent
Logstash pipeline (separate JVM thread pool).

| File | ID | Load Order | Source |
|------|----|-----------|--------|
| `00-input-beats-tls.conf` | `pfsense-input` | 1 | mTLS syslog-ng TCP (port 5140) |
| `10-pfsense-firewall.conf` | `pfsense-firewall` | 2 | pfSense firewall filter, NAT |
| `11-pfsense-services.conf` | `pfsense-services` | 3 | DHCP, DNS, VPN, auth, system |
| `20-suricata-eve.conf` | `suricata` | 4 | Suricata EVE JSON |
| `30-zeek.conf` | `zeek` | 5 | Zeek TSV/JSON logs |
| `40-pfblockerng.conf` | `pfblockerng` | 6 | pfBlockerNG DNSBL/IP rep |
| `90-deadletter.conf` | `deadletter` | 7 | Unmatched events fallback |

---

## Pipeline Detail

### 00 — Input (mTLS TLS Syslog)
**File:** `config/logstash-pfsense/pipelines/00-input-beats-tls.conf`

- **Input:** `tcp` plugin, port 5140, TLS 1.3, `verify_mode => peer`
- **Client cert CA:** `certs/root-ca.pem`
- **Output:** internal pipeline queue → routing filter
- **Sets:** `suru.source = "pfsense"`, `suru.tier = "tier1"`
- **Tags on parse failure:** `["_syslog_parse_failure"]` → routed to deadletter

### 10 — pfSense Firewall
**File:** `config/logstash-pfsense/pipelines/10-pfsense-firewall.conf`

| ECS Field | Source / Grok Reference |
|-----------|------------------------|
| `@timestamp` | Syslog header timestamp |
| `event.action` | `pass` / `block` from PF log |
| `event.category` | `["network"]` |
| `event.type` | `["connection", "allowed"]` or `["connection", "denied"]` |
| `event.module` | `pfsense` |
| `network.transport` | `tcp` / `udp` / `icmp` (lowercase L4 name per ECS) |
| `network.protocol` | Derived from dst port (best-effort) |
| `source.ip` | PF src IP |
| `source.port` | PF src port |
| `source.geo.*` | GeoIP enrichment |
| `destination.ip` | PF dst IP |
| `destination.port` | PF dst port |
| `destination.geo.*` | GeoIP enrichment |
| `rule.id` | PF rule number |
| `observer.ingress.interface.name` | PF interface |
| `observer.type` | `firewall` |
| `suru.log_type` | `firewall` |

**MITRE ATT&CK annotations:**
- Blocked inbound: TA0001 Initial Access
- Outbound C2 ports (443/80 non-browser): TA0011 Command and Control, T1071

### 11 — pfSense Services (DHCP / DNS / VPN / Auth)
**File:** `config/logstash-pfsense/pipelines/11-pfsense-services.conf`

| `suru.log_type` | ECS Fields Set |
|-----------------|----------------|
| `dhcp` | `network.type`, `client.ip`, `client.mac`, `dhcp.lease_time` |
| `dns` | `dns.question.name`, `dns.question.type`, `dns.response_code`, `dns.answers` |
| `vpn-openvpn` | `event.category=["session"]`, `user.name`, `network.tunnel.type=openvpn` |
| `vpn-ipsec` | `event.category=["session"]`, `user.name`, `network.tunnel.type=ipsec` |
| `auth` | `event.category=["authentication"]`, `user.name`, `event.outcome` |
| `config-change` | `event.category=["configuration"]`, `user.name`, `event.action` |

### 20 — Suricata EVE JSON
**File:** `config/logstash-pfsense/pipelines/20-suricata-eve.conf`

- **Input format:** Native Suricata EVE JSON (forwarded via syslog-ng `json()` template)
- **json_filter:** `suricata.*` fields extracted, then mapped

| ECS Field | EVE Source Field |
|-----------|------------------|
| `@timestamp` | `timestamp` |
| `event.kind` | `alert` |
| `event.category` | `["intrusion_detection"]` |
| `rule.id` | `alert.signature_id` |
| `rule.name` | `alert.signature` |
| `rule.category` | `alert.category` |
| `source.ip` | `src_ip` |
| `source.port` | `src_port` |
| `destination.ip` | `dest_ip` |
| `destination.port` | `dest_port` |
| `network.transport` | `proto` (lowercased — Suricata EVE emits `TCP`/`UDP`) |
| `threat.technique.id` | `alert.metadata.mitre_technique_id` |
| `threat.tactic.id` | `alert.metadata.mitre_tactic_id` |

### 30 — Zeek Logs
**File:** `config/logstash-pfsense/pipelines/30-zeek.conf`

Routed by the syslog `program` field (set by `program-override("zeek-<type>")` in the
Tier 1 syslog-ng template) → `event.dataset` is the **bare** Zeek log name. A common
stage maps the connection 5-tuple on every type: `id.orig_h`/`id.orig_p` →
`source.ip`/`source.port`, `id.resp_h`/`id.resp_p` → `destination.ip`/`destination.port`,
`proto` → `network.transport`, `uid` → `zeek.uid`.

| `program` | `event.dataset` | Type-specific ECS mapping |
|-----------|-----------------|---------------------------|
| `zeek-conn` | `conn` | (common 5-tuple only) |
| `zeek-dns` | `dns` | `query`→`dns.question.name`, `qtype_name`→`dns.question.type`, `qclass_name`→`dns.question.class`, `rcode_name`→`dns.response_code`, `answers`→`dns.resolved` |
| `zeek-dhcp` | `dhcp` | `client_addr`→`source.ip`, `server_addr`→`destination.ip`, `mac`→`source.mac`, `host_name`/`assigned_addr`/`requested_addr`/`lease_time`/`msg_types`/`domain`→`dhcp.*` |
| `zeek-http` | `http` | (common 5-tuple; raw Zeek http fields retained) |
| `zeek-ssl` | `ssl` | (common 5-tuple; raw Zeek ssl fields retained) |
| `zeek-notice` | `notice` | (common 5-tuple) |
| `zeek-weird` | `weird` | (common 5-tuple) |
| `zeek-files` | `files` | scalar `source` (="HTTP") renamed to `zeek.file_source` to avoid ECS `source` object collision |

**DHCP source:** Zeek `dhcp.log` (network-observed; backend-agnostic). The pfSense
`dhcpd.log` path is dead on Kea-based routers. `zeek-dhcp` forwarding is added in
`tier1-perimeter/templates/pfsense/syslog-ng.conf.tpl`.

### 35 — GeoIP / ASN Enrichment (central)
**File:** `config/logstash-pfsense/pipelines/35-geoip.conf` (+ `35-geoip-passthrough.conf`)

Central enrichment pipeline. `10-pfsense-firewall`, `20-suricata-eve`, and
`30-zeek` route their good events to it via `pipeline { send_to => "geoip-pipe" }`
(instead of indexing directly); the geoip pipeline enriches and indexes back to
each source index (by `event.module`). The Logstash `geoip` filter (ecs_compatibility
v8, auto-derived target — no explicit `target`) adds:

| ECS field | Source |
|-----------|--------|
| `source.geo.*` / `destination.geo.*` (country, city, region, `location` geo_point) | GeoLite2-City |
| `source.as.{number,organization.name}` / `destination.as.*` | GeoLite2-ASN |

DBs come from the `suru.t3.ingestion.geoipupdate` init (MaxMind `MAXMIND_ACCOUNT_ID`
+ `MAXMIND_LICENSE_KEY`) into the `geoip` volume. **Conditional:** the
`logstash-entrypoint.sh` copies the geoip-enabled `35-geoip.conf` to
`/tmp/geoip-pipeline/35-geoip.conf` only when the City DB is present; otherwise it
copies `35-geoip-passthrough.conf` (no geoip — the filter is fatal at startup if its
DB is missing). So ingestion is unaffected when no MaxMind creds are configured.
syslog-ng geoip2 was evaluated and rejected — the pfSense syslog-ng build lacks the
geoip2 module.

### 40 — pfBlockerNG
**File:** `config/logstash-pfsense/pipelines/40-pfblockerng.conf`

Two event formats are parsed — DNSBL (DNS blocklist hits) and IP reputation blocks:

| ECS Field | DNSBL source | IP reputation source |
|-----------|-------------|----------------------|
| `event.kind` | `alert` | `alert` |
| `event.category` | `["threat", "network"]` | `["threat", "network"]` |
| `event.type` | `["denied", "connection"]` | `["denied", "connection"]` |
| `event.action` | `block` | `block` |
| `event.module` | `pfblockerng` | `pfblockerng` |
| `threat.indicator.type` | `domain-name` | `ipv4-addr` |
| `threat.indicator.name` | Blocked FQDN | Blocked source IP |
| `threat.indicator.confidence` | `High` | `High` |
| `threat.feed.name` | pfBlockerNG list name | pfBlockerNG list name |
| `dns.question.name` | Blocked DNS query | — |
| `source.ip` | Requesting client IP | Blocked source IP |
| `destination.ip` | — | Destination IP |
| `destination.port` | — | Destination port |
| `network.transport` | — | Lowercase L4 name (`tcp`/`udp`/`icmp`/`gre`/…) resolved from the IANA protocol; unset for protocols outside the name dictionary |
| `network.iana_number` | — | Numeric IANA protocol id as a string (e.g. `"6"`, `"47"`) — always set; the fallback carrier when no `network.transport` name exists |
| `network.direction` | — | `ingress` / `egress` (pf interface-relative `in`/`out` normalised to the ECS enum) |
| `observer.type` | `firewall` | `firewall` |
| `suru.tier` | `tier1` | `tier1` |

**MITRE:** TA0011 Command and Control / T1071 Application Layer Protocol (DNS C2 blocked by DNSBL);
TA0043 Reconnaissance / T1590 Gather Victim Network Information (recon source IP blocked by IP rep)

### 90 — Dead Letter / Quarantine
**File:** `config/logstash-pfsense/pipelines/90-deadletter.conf`

- Catches all events routed to `quarantine-pipe` (grok failures, date-parse failures)
- Sets `event.kind: pipeline_error`, `event.module: quarantine`, `event.dataset: suru.quarantine`
- Indexed to `suru-quarantine-YYYY.MM.dd` (SEC-053: OpenSearch output, not file)
- A high quarantine rate indicates a new log format that needs a new pipeline
- Query: `GET suru-quarantine-*/_count` to monitor quarantine volume

---

## OPNsense Standby Profile (`config/logstash-opnsense/`)

**Status: STANDBY — not deployed. Active only when `ROUTER_PLATFORM=opnsense` in `.env`.**

The opnsense profile mirrors the pfsense pipeline set but targets OPNsense log formats.
No OPNsense deployment currently exists; `ROUTER_PLATFORM=pfsense` is the live value.

### Routing Tag Contract (SEC-056)

The OPNsense syslog-ng shipper MUST emit the following Logstash tags for correct routing:

| Tag | Destination | Pipeline |
|-----|------------|---------|
| `pfblocker-ip` | `pfblocker-pipe` | `40-pfblocker.conf` |
| `pfblocker-dns` | `pfblocker-pipe` | `40-pfblocker.conf` |
| (none) | `pfsense-pipe` | `10-pfsense.conf` |

Without these tags, all pfBlockerNG events fall through to `pfsense-pipe` and are
indexed in `suru-pfsense-*` with the wrong schema.

**[STUB: opnsense routing tags must be emitted by the syslog-ng config on the OPNsense
router — no OPNsense deployment exists yet.]**

---

## Adding a New Pipeline

See [`extending.md`](./extending.md) for the full AI-parseable contract.
Short version:

1. Create `config/logstash-pfsense/pipelines/NN-<source>.conf`
2. Add entry to `config/logstash-pfsense/pipelines.yml`
3. Add routing condition in the input or a routing filter stage
4. Map all fields to ECS v8 (see `architecture.md` for mandatory fields)
5. Annotate MITRE ATT&CK tactics/techniques as code comments
6. Add entry to this file (`pipelines.md`) under **Pipeline Detail**
7. Validate — ⚠️ **not** by `docker exec` into the live container (a 2nd JVM in its
   cgroup can OOM-crash production ingestion); use a throwaway container:
   `docker run --rm -e LS_JAVA_OPTS='-Xmx256m' -e OPENSEARCH_HOST=x -e OPENSEARCH_PORT=9200 -e OPENSEARCH_USER=x -e OPENSEARCH_PASSWORD=x -v "$PWD/NN-<source>.conf":/tmp/p.conf:ro docker.elastic.co/logstash/logstash-oss:9.3.1 logstash --config.test_and_exit -f /tmp/p.conf` (full command: `../config/logstash-pfsense/pipelines/README.md`)
8. Idempotent ingest — every pipeline that writes to OpenSearch ends its
   `filter {}` with the `fingerprint` block (`[@metadata][doc_fingerprint]` =
   base64(SHA256(`message`))), routes `_fingerprint_missing_source` to
   `quarantine-pipe`, and sets `document_id => "%{[@metadata][doc_fingerprint]}"`
   on each `opensearch` output, so a re-read source log (byte-0 replay after a
   reboot, a producer rewriting its log in place) upserts instead of duplicating.
   Copy the block from `35-geoip.conf`.
