# tier2-telemetry/sigma — Canonical Sigma Rules (Layer 1)

This is the **single canonical Sigma rule tree** for the SURU platform. It
supersedes the prior split between `tier2-telemetry/sigma-rules/` (retired,
**deleted** — do not recreate it) and an earlier unstructured `sigma/rules/`.

`BREAKING CHANGE:` this is a breaking change to the Sigma authoring contract.
Prior rules referenced raw Suricata EVE field paths (`alert.category`,
`alert.severity`) or fields with no ECS mapping in this deployment
(`zeek.notice.note`, `http.response.status_code`, `url.path`). Every rule in
this tree now resolves exclusively against the ECS v8 fields this platform
actually indexes.

## Position in the three-layer rule architecture

```
sigma/rules/<tactic>/<slug>.yml      ← LAYER 1 (this directory) — canonical, ECS-field rules
opensearch/field-mappings/*.yml      ← LAYER 3 — Sigma field ↔ concrete OpenSearch field-mapping bridge
opensearch/detectors/*.yml           ← LAYER 2 — binds Layer-1 rule(s) to an index pattern + schedule
```

See the platform plan ("SIEM Security Analytics") and
`docs/architecture.md` for the full three-layer rationale. `tier3-core` never
reads this directory directly — it only imports artifacts already rendered
by `tier2-telemetry/build/render.sh` (`render-tier3.sh` → `render-sigma.sh`).

## ECS-field-only contract (mandatory)

Every rule's `logsource:` and `detection:` selectors MUST use field names that
exist in `tier3-core/config/opensearch/index-templates/suru-ecs-template.json`,
cross-referenced against the canonical field table in
`tier2-telemetry/opensearch/field-mappings/README.md`. Do not invent a field because it
"sounds right" or because the upstream product (Suricata EVE, Zeek, Sysmon)
exposes it under that name — if the field is not in the ECS template, it does
not exist in this deployment's index, and a rule built on it produces a
**silent zero-detection** (import succeeds, nothing ever matches; see plan
Risk R2). Confirm before authoring:

```bash
grep -A3 '"<field-leaf>"' tier3-core/config/opensearch/index-templates/suru-ecs-template.json
```

### Deny-list — never use these in a rule's `detection:`/`logsource:`

These are raw-EVE / pre-ECS field paths from the retired corpora. Their
presence anywhere under this directory is a regression:

```bash
grep -rnE 'alert\.|suricata\.eve|qtype_name' tier2-telemetry/sigma/rules/
# must return zero matches
```

| Forbidden (raw EVE / non-ECS) | Use instead |
|---|---|
| `alert.category` | `rule.category` |
| `alert.severity` | `event.severity` |
| `alert.signature` | `rule.name` |
| `suricata.eve.*` (any nested EVE path) | the flattened ECS field from the §4 table |
| `qtype_name` | `dns.question.type` |
| `zeek.notice.note` | `rule.name` (with `event.dataset:"notice"`, `event.kind:"alert"`) |
| `http.response.status_code` | not mapped in this deployment — do not use |
| `http.request.method` | `http.http_method` |
| `url.path` | `http.url` (carries the full request path) |

### Fields with no ECS mapping today — endpoint/process telemetry

`suru-ecs-template.json`'s `process` object maps only `process.pid`. There is
no `process.command_line`, `process.executable`, or `process.name` — no
endpoint/EDR log source is ingested in this deployment yet (see T1c stub
scaffold). Any rule needing Sysmon-style `Image`/`CommandLine` fields (e.g.
lateral-movement-via-remote-services) must be authored as an explicit
`[STUB: ...]` rule and is not expected to fire until an endpoint data source
and its field-mapping bridge exist. Do not invent `process.*` fields to make
such a rule "work."

## Directory layout

```
sigma/
  README.md                                          ← this file
  rules/
    initial-access/
      exploit-public-facing-application.yml          T1190
    command-and-control/
      dns-tunneling-high-entropy.yml                 T1071.004
      dns-excessive-name-length.yml                  T1071.004, T1048.003
    lateral-movement/
      remote-services.yml                            T1021 — STUB (no live ECS source)
```

New tactic subdirectories use the kebab-case MITRE ATT&CK tactic name
(`initial-access`, `command-and-control`, `lateral-movement`, `exfiltration`,
`defense-evasion`, `reconnaissance`, `execution`, `persistence`, …).

## Mandatory rule fields

Every rule must carry:

- `title`, `id` (stable identifier — UUID or a stable slug, never reused
  across rules), `status` (`experimental` | `test` | `stable` | `production`)
- `description` — what it detects and, where relevant, which upstream
  detector/script raises the underlying signal (e.g. a Zeek notice type)
- `tags: [attack.ta####, attack.t####]` — MITRE Tactic AND Technique, always
  both
- `logsource`, `detection` — ECS-field-only per the contract above
- `falsepositives` — populated, not `[]` or omitted
- `level`

Rules without MITRE tags or `falsepositives` will be reverted per
`tier2-telemetry/opensearch/README.md` (Safety Gates).

## Validation

```bash
# Deny-list (raw EVE / non-ECS field paths) — must return zero matches
grep -rnE 'alert\.|suricata\.eve|qtype_name' tier2-telemetry/sigma/rules/

# Sigma CLI structural/schema check (per rule) — if `sigma` is installed
sigma check tier2-telemetry/sigma/rules/<tactic>/<slug>.yml

# YAML + required-field sanity (works even without the sigma CLI installed)
python3 -c "
import yaml
d = yaml.safe_load(open('<file>'))
required = ['title','id','status','description','logsource','detection','level']
assert not [k for k in required if k not in d]
assert any(t.startswith('attack.ta') for t in d.get('tags', []))
assert any(t.startswith('attack.t') and not t.startswith('attack.ta') for t in d.get('tags', []))
assert d.get('falsepositives')
"
```

As of 2026-06-24, the `sigma` CLI (`sigma check` / `sigma convert`) is **not
installed** in the dev/CI environment used to author this tree — this is a
verification gap, not a skipped step. Every rule was instead validated by:
the deny-list grep above, the YAML/required-field/MITRE-tag script above, and
a manual field-by-field cross-reference against
`tier3-core/config/opensearch/index-templates/suru-ecs-template.json`. Install
`sigma-cli` (`pip install sigma-cli`) and re-run `sigma check` against this
tree before the Layer-2/Layer-3 work (T1b/T2) depends on these rules being
schema-valid, not just field-valid.

## What changed in the 2026-06-24 consolidation

- Retired `tier2-telemetry/sigma-rules/` entirely (not kept as an alias).
  Its two rules were migrated here:
  - `sigma-rules/initial-access/t1190-exploit-public-facing.yaml` → merged
    into `initial-access/exploit-public-facing-application.yml` alongside
    the pre-existing `sigma/rules/suru-exploit-public-facing.yml` (same
    technique, two detection angles: EVE alert classification + HTTP
    exploit-pattern matching).
  - `sigma-rules/lateral-movement/t1021-remote-services.yaml` → migrated to
    `lateral-movement/remote-services.yml`, now marked `[STUB]` — its
    `Image`/`CommandLine` process-creation fields have no ECS mapping in
    this deployment.
- `sigma/rules/suru-c2-dns-tunneling.yml` → `command-and-control/dns-tunneling-high-entropy.yml`,
  rewritten off `zeek.notice.note` (not a real field) onto `rule.name` +
  `event.dataset:"notice"` + `event.kind:"alert"`.
- `sigma/rules/suru-exploit-public-facing.yml` → folded into
  `initial-access/exploit-public-facing-application.yml`, rewritten off
  `http.response.status_code`/`http.request.method`/`url.path` (none exist
  in this deployment's ECS template) onto `http.http_method`/`http.url`.
