#!/usr/bin/env bash
# =============================================================================
# SURU Tier 3 — functional test for the Logstash pfBlockerNG timestamp mirror
#
# Executes the `ruby { code => '…' }` block of pipelines/40-pfblockerng.conf
# (the pfBlockerNG event-time derivation) under plain ruby with a stub event,
# against fixtures shaped like live dnsbl.log / ip_block.log lines.
# `logstash --config.test_and_exit` only proves the block compiles; this
# proves what it computes: payload time
# + envelope year/offset, Dec→Jan rollback, colon-less offset normalisation,
# the 30-day replay-expiry tag, and the no-payload-time fallback path.
#
# Usage: bash tier3-core/config/logstash-pfsense/tests/test-40-pfblockerng-timestamp.sh
# Requires: ruby (any 2.6+; the block uses only Time/strptime and event.get/
# set/tag, so plain MRI is faithful enough — JRuby-specific behaviour is not
# exercised here).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${1:-${SCRIPT_DIR}/../pipelines/40-pfblockerng.conf}"

command -v ruby >/dev/null 2>&1 || { echo "[FAIL] ruby not found on PATH" >&2; exit 2; }
[[ -r "${CONF}" ]] || { echo "[FAIL] pipeline not readable: ${CONF}" >&2; exit 2; }

ruby - "${CONF}" <<'RUBY'
require "time"

conf = File.read(ARGV[0])
m = conf.match(/ruby \{\s*code => '(.*?)'\s*\}/m) or abort "[FAIL] ruby { code => '…' } block not found in #{ARGV[0]}"
CODE = m[1]

# --- minimal stand-ins for the Logstash runtime the block touches ------------
module LogStash
  class Timestamp
    attr_reader :time
    def initialize(t)
      @time = t.utc
    end
    def to_s
      @time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end
  end
end

class StubEvent
  attr_reader :tags
  def initialize(fields)
    @f = fields
    @tags = []
  end
  def get(k)
    @f[k]
  end
  def set(k, v)
    @f[k] = v
  end
  def tag(t)
    @tags << t
  end
end

def run_block(time, ts_text)
  event = StubEvent.new({ "time" => time, "[@metadata][pfb_ts_text]" => ts_text })
  eval(CODE, binding)
  event
end

# --- fixtures (live line shapes; identifiers are documentation values) --------
# [name, envelope time, payload time text, expected @timestamp (UTC) or :tag/:unset, expected tag]
FIXTURES = [
  ["event time, single-digit day",     "2026-09-05T10:36:35+03:00", "Sep 5 10:36:35",  "2026-09-05T07:36:35Z", nil],
  ["dnsbl replay keeps its day",       "2026-09-05T00:03:50+03:00", "Aug 14 14:12:08", "2026-08-14T11:12:08Z", nil],
  ["ip_block replay keeps its day",    "2026-09-05T00:03:52+03:00", "Sep 3 18:20:11",  "2026-09-03T15:20:11Z", nil],
  ["Dec line read in Jan → prev year", "2027-01-01T00:00:05+02:00", "Dec 31 23:59:58", "2026-12-31T21:59:58Z", nil],
  ["colon-less envelope offset",       "2026-09-05T10:36:35+0300",  "Sep 5 10:36:35",  "2026-09-05T07:36:35Z", nil],
  ["Z envelope offset",                "2026-09-05T07:36:35Z",      "Sep 5 07:36:35",  "2026-09-05T07:36:35Z", nil],
  ["fractional-second envelope",       "2026-09-05T10:36:35.575537+03:00", "Sep 5 10:36:35", "2026-09-05T07:36:35Z", nil],
  ["older than 30 d → _replay_expired","2026-09-05T00:03:50+03:00", "Jun 1 08:00:00",  :unset, "_replay_expired"],
  ["no payload time → untouched (date{} fallback)", "2026-09-05T10:36:35+03:00", "garbled", :unset, nil],
]

failed = 0
FIXTURES.each do |name, time, ts, want, want_tag|
  ev = run_block(time, ts)
  got = ev.get("@timestamp")
  got_s = got.nil? ? :unset : got.to_s
  set_flag = ev.get("[@metadata][pfb_ts_set]")
  ok = (got_s == want) && (want_tag.nil? ? ev.tags.empty? : ev.tags == [want_tag]) && (want == :unset ? set_flag.nil? : set_flag == true)
  puts format("%s  %-48s  @timestamp=%-22s tags=%s", ok ? "[PASS]" : "[FAIL]", name, got_s, ev.tags.inspect)
  failed += 1 unless ok
end

puts "#{FIXTURES.size - failed}/#{FIXTURES.size} passed"
exit(failed.zero? ? 0 : 1)
RUBY
