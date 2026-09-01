# tier2-telemetry/zeek — Zeek Detection Scripts & Intel

This directory contains all SURU-authored Zeek detection scripts and IOC intel feeds.
It is consumed by the Tier 1 render pipeline to assemble the final `local.zeek` and
populate the Zeek intel directory on the router.

## Directory Layout

```
zeek/
├── scripts/             # Custom Zeek detection and telemetry scripts
│   ├── suru-base.zeek            # Engine bootstrap — base protocols, intel framework, log dir (GUI-save resilient)
│   ├── soho-telemetry.zeek       # Flow suppression — local-to-local noise reduction
│   ├── suru-dns-entropy.zeek     # DNS tunneling detection — entropy + length legs (TA0011/T1071.004, TA0010/T1048.003)
│   ├── suru-name-poisoning.zeek  # LLMNR/NBT-NS Responder-class poisoning + WPAD-answer detection (TA0006/T1557.001)
│   ├── suru-lateral-movement.zeek # Admin-port fan-out lateral movement (TA0008/T1021)
│   ├── suru-ssh-bruteforce.zeek  # SSH brute-force / spray connection rate (TA0006/T1110)
│   ├── suru-doh-detect.zeek      # DoH resolver-bypass via SNI (TA0005/T1572, T1071.001)
│   ├── suru-telemetry-scope.zeek # mDNS log-stream scoping — NOT a detection; dns.log filter only, ZEEK_LOG_MDNS opt-in
│   └── suru-ssl-ja3.zeek.optional # JA3/JA3S fingerprinting (TA0011/T1071) — disabled (.optional; rename to .zeek to enable)
└── intel/               # Zeek Intelligence Framework feeds
    └── suru-ioc.dat     # SURU IOC feed (domain/IP/hash format)
```

## Invariant

Zeek detection logic lives here, not in `tier1-perimeter/`. The T1 template
(`tier1-perimeter/templates/zeek/local.zeek.tpl`) only contains the engine bootstrap;
all `@load site/scripts/*` directives are injected by the render pipeline from this directory.

## MITRE ATT&CK Annotations

Every `.zeek` script in `scripts/` MUST have a header comment with tactic and technique IDs.

## Validation

```bash
zeek -b scripts/suru-dns-entropy.zeek
```
