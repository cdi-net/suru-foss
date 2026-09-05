#!/usr/bin/env bash
# =============================================================================
# SURU Tier 3 — functional test of the Logstash pfBlockerNG PIPELINE
#
# Runs the REAL `filter { … }` section of pipelines/40-pfblockerng.conf in a
# throwaway logstash-oss container (stdin json_lines → stdout json_lines) and
# asserts what the whole pipeline computes for live-shaped fixtures — filter
# ORDER included. The ruby-block harness (test-40-pfblockerng-timestamp.sh)
# proves the timestamp block in isolation; it cannot see a scratch field that
# is removed before it is copied into the block's input — the failure mode in
# which every dnsbl.log event silently kept the envelope time.
# `--config.test_and_exit` only proves the file compiles.
#
# Never `docker exec` into the live container (a second JVM inside its cgroup
# can OOM-crash ingestion) — this run is its own cgroup.
#
# Usage: bash tier3-core/config/logstash-pfsense/tests/test-40-pfblockerng-pipeline.sh [pipeline.conf]
# Requires: docker + the logstash-oss image pinned in
# tier3-core/ingestion/logstash/compose.yaml (pulled on first run). One JVM
# boot per run (~30-60 s). Exit 0 = all cases pass, 1 = assertion failure,
# 2 = environment error.
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIER3_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CONF="${1:-${SCRIPT_DIR}/../pipelines/40-pfblockerng.conf}"
COMPOSE="${TIER3_DIR}/ingestion/logstash/compose.yaml"

command -v docker  >/dev/null 2>&1 || { echo "[FAIL] docker not found on PATH" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "[FAIL] python3 not found on PATH" >&2; exit 2; }
[[ -r "${CONF}" ]]    || { echo "[FAIL] pipeline not readable: ${CONF}" >&2; exit 2; }
[[ -r "${COMPOSE}" ]] || { echo "[FAIL] compose not readable: ${COMPOSE}" >&2; exit 2; }

# Same image (and digest) as the live service — never a floating tag.
IMAGE="$(grep -m1 -oE 'docker\.elastic\.co/logstash/logstash-oss:[^[:space:]"]+' "${COMPOSE}" || true)"
[[ -n "${IMAGE}" ]] || { echo "[FAIL] no logstash-oss image pin found in ${COMPOSE}" >&2; exit 2; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/suru-ls-pfb.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
chmod 755 "${TMP_DIR}"   # the container runs as uid 1000 and must read the mount

# --- test pipeline: the real filter section, stdin in, stdout out ------------
# The input/output blocks are swapped (the live ones need the intra-Logstash
# pipeline bus and an OpenSearch); the filter block is used byte-for-byte.
{
  echo 'input { stdin { codec => json_lines } }'
  awk '/^filter \{/ { f = 1 } /^output \{/ { f = 0 } f' "${CONF}"
  echo 'output { stdout { codec => json_lines } }'
} > "${TMP_DIR}/pipeline.conf"
chmod 644 "${TMP_DIR}/pipeline.conf"
grep -q '^filter {' "${TMP_DIR}/pipeline.conf" \
  || { echo "[FAIL] filter section not extracted from ${CONF}" >&2; exit 2; }

# --- fixtures: live-shaped dnsbl.log / ip_block.log lines --------------------
# `case` is a marker so output events are matched regardless of order.
fixture() { # case program envelope-time message
  printf '{"case":"%s","program":"%s","time":"%s","host":{"hostname":"router.example"},"facility":"local3","severity":"info","_suru":{"log_type":"pfblockerng","tier":"tier1-perimeter"},"source_type":"syslog","message":"%s"}\n' \
    "$1" "$2" "$3" "$4"
}
{
  fixture dnsbl_event_time              pfblockerng-dnsbl '2026-09-05T10:36:35+03:00' 'DNSBL-python,Sep 5 10:36:35,telemetry.cdn.example,192.0.2.168,Python,DNSBL,DNSBL_SURU_StevenBlack_Unified,telemetry.cdn.example,SURU_StevenBlack_Unified,+'
  fixture ip_block                      pfblockerng-ip    '2026-06-23T23:49:57+03:00' 'Jun 23 23:49:57,1770009049,pppoe0,WAN,block,4,6,TCP-S,203.0.113.2,192.0.2.239,21518,61234,in,US,pfB_PRI1_v4,203.0.113.255,SURU_DShield_v4,crawler.example,wan,|ASN:  AS64500 | domain:  x.example | name:  X |,+'
  fixture dnsbl_replay_keeps_event_day  pfblockerng-dnsbl '2026-09-05T00:03:50+03:00' 'DNSBL-python,Aug 14 14:12:08,cdn.consent.example,192.0.2.197,Python,DNSBL,DNSBL_SURU_StevenBlack_Unified,cdn.consent.example,SURU_StevenBlack_Unified,-'
  fixture ip_block_replay_keeps_day     pfblockerng-ip    '2026-09-05T00:03:52+03:00' 'Sep 3 18:20:11,1770009049,pppoe0,WAN,block,4,6,TCP-S,203.0.113.60,192.0.2.10,44321,443,in,US,pfB_SURU_IP_REP_v4,203.0.113.60,SURU_AbuseIPDB_v4,Unknown,wan,|ASN:  AS64501 | domain:  x.example | name:  X |,+'
  fixture year_rollover                 pfblockerng-dnsbl '2027-01-01T00:00:05+02:00' 'DNSBL-python,Dec 31 23:59:58,ads.example,192.0.2.20,Python,DNSBL,DNSBL_SURU_StevenBlack_Unified,ads.example,SURU_StevenBlack_Unified,+'
  fixture colonless_envelope_offset     pfblockerng-dnsbl '2026-09-05T10:36:35+0300'  'DNSBL-python,Sep 5 10:36:35,telemetry.cdn.example,192.0.2.168,Python,DNSBL,DNSBL_SURU_StevenBlack_Unified,telemetry.cdn.example,SURU_StevenBlack_Unified,+'
  fixture expired_replay_quarantined    pfblockerng-dnsbl '2026-09-05T00:03:50+03:00' 'DNSBL-python,Jun 1 08:00:00,old.example,192.0.2.21,Python,DNSBL,DNSBL_SURU_StevenBlack_Unified,old.example,SURU_StevenBlack_Unified,+'
  fixture no_payload_time_fallback      pfblockerng-dnsbl '2026-09-05T10:36:35+03:00' 'DNSBL-python,garbled'
} > "${TMP_DIR}/fixtures.jsonl"

echo "── logstash pipeline run (${IMAGE##*/}) ──"
# Heap: tier3-core/ingestion/logstash/compose.yaml documents a 1g floor for
# this image (a 512m heap OOM-looped live 2026-07-08 during the entrypoint's
# plugin install). This run skips that entrypoint and loads a single pipeline,
# but the documented floor is kept rather than argued away — it costs nothing
# on a throwaway container.
rc=0
docker run --rm -i \
  -e LS_JAVA_OPTS='-Xms1g -Xmx1g' \
  -v "${TMP_DIR}/pipeline.conf":/tmp/p.conf:ro \
  "${IMAGE}" \
  logstash -f /tmp/p.conf --path.data /tmp/lsdata --log.level warn --pipeline.workers 1 \
  < "${TMP_DIR}/fixtures.jsonl" > "${TMP_DIR}/stdout.txt" 2> "${TMP_DIR}/stderr.txt" || rc=$?
if [[ "${rc}" -ne 0 ]]; then
  echo "[FAIL] logstash exited ${rc}" >&2
  tail -40 "${TMP_DIR}/stderr.txt" "${TMP_DIR}/stdout.txt" >&2
  exit 2
fi
# Events are JSON lines; Logstash's own log lines start with "[".
grep '^{' "${TMP_DIR}/stdout.txt" > "${TMP_DIR}/events.jsonl" || true

python3 - "${TMP_DIR}/events.jsonl" <<'PY'
import json, re, sys

# expected @timestamp (second precision, UTC) and flags per case
EXPECT = {
    "dnsbl_event_time":             {"ts": "2026-09-05T07:36:35Z", "dup": False, "dns": "telemetry.cdn.example"},
    "ip_block":                     {"ts": "2026-06-23T20:49:57Z", "src": "203.0.113.2"},
    "dnsbl_replay_keeps_event_day": {"ts": "2026-08-14T11:12:08Z", "dup": True},
    "ip_block_replay_keeps_day":    {"ts": "2026-09-03T15:20:11Z"},
    "year_rollover":                {"ts": "2026-12-31T21:59:58Z"},
    "colonless_envelope_offset":    {"ts": "2026-09-05T07:36:35Z"},
    "expired_replay_quarantined":   {"expired": True},
    "no_payload_time_fallback":     {"ts": "2026-09-05T07:36:35Z", "no_dns": True},
}

docs = {}
with open(sys.argv[1]) as f:
    for line in f:
        d = json.loads(line)
        docs[d.get("case")] = d

def norm_ts(v):
    return re.sub(r"\.\d+Z$", "Z", str(v))

def get(d, *path):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d

failed = 0
for case, exp in EXPECT.items():
    d = docs.get(case)
    errs = []
    if d is None:
        errs.append("no output event")
    else:
        tags = d.get("tags") or []
        if "ts" in exp and norm_ts(d.get("@timestamp")) != exp["ts"]:
            errs.append(f'@timestamp={d.get("@timestamp")} expected {exp["ts"]} (envelope time={d.get("time")})')
        if exp.get("expired") and "_replay_expired" not in tags:
            errs.append(f"_replay_expired tag missing (tags={tags})")
        if not exp.get("expired") and "_replay_expired" in tags:
            errs.append("unexpected _replay_expired")
        if "_dateparsefailure" in tags:
            errs.append("unexpected _dateparsefailure")
        if "dup" in exp and get(d, "event", "duplicate") is not exp["dup"]:
            errs.append(f'event.duplicate={get(d, "event", "duplicate")!r} expected {exp["dup"]!r}')
        if "dns" in exp and get(d, "dns", "question", "name") != exp["dns"]:
            errs.append(f'dns.question.name={get(d, "dns", "question", "name")!r}')
        if exp.get("no_dns") and get(d, "dns", "question", "name") is not None:
            errs.append("dns.question.name present on a truncated line")
        if "src" in exp and get(d, "source", "ip") != exp["src"]:
            errs.append(f'source.ip={get(d, "source", "ip")!r}')
        for scratch in ("_pfb_datereq", "_pfb_ts_human", "_pfb_type", "_pfb_build_epoch"):
            if scratch in d:
                errs.append(f"scratch field {scratch} leaked into the document")
        if get(d, "event", "ingested") is None:
            errs.append("event.ingested missing")
    if errs:
        failed += 1
        print(f"[FAIL] {case}: " + "; ".join(errs))
    else:
        print(f"[ OK ] {case}: @timestamp={norm_ts(d.get('@timestamp'))} tags={d.get('tags')}")

extra = set(docs) - set(EXPECT) - {None}
if extra:
    print(f"[WARN] unexpected cases in output: {sorted(extra)}")
print(f"{len(EXPECT) - failed}/{len(EXPECT)} passed")
sys.exit(1 if failed else 0)
PY
