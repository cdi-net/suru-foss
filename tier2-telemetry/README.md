# SURU Platform — Tier 2: Security Intelligence

Tier 2 is the **authoritative source of all security policy and detection intelligence**
for the SURU platform. It defines *what* to detect and *what* to block.
Tier 1 defines *how* to deploy it.

## Architecture Role

```
tier2-telemetry/  ——[render]→  tier1-perimeter/rendered/  ——[deploy.sh]→  Router
```

The render pipeline (`build/render.sh`) merges T2 data files with T1 templates.
The deploy pipeline (`tier1-perimeter/scripts/deploy.sh`) pushes the rendered output
to the target device. **Neither pipeline modifies T2.**

## Directory Structure

```
tier2-telemetry/
├── suricata/
│   ├── rule-selection/              # SID enable/disable lists
│   │   ├── enable.conf
│   │   └── disable.conf
│   ├── update-policy/               # suricata-update source + modifier policy
│   │   └── update.yaml
│   └── custom-rules/                # SURU-authored detection rules
│       └── suru-c2-beacons.rules
├── zeek/
│   ├── scripts/                     # Zeek detection + telemetry scripts
│   │   ├── soho-telemetry.zeek      # RFC1918→RFC1918 flow suppression
│   │   ├── suru-dns-entropy.zeek    # T1071.004 DNS tunneling
│   │   └── suru-ssl-ja3.zeek.optional   # JA3/JA3S — requires zeek-ja3 pkg; rename to .zeek to enable
│   └── intel/
│       └── suru-ioc.dat             # Zeek Intel Framework IOC feed
├── pfblockerng/
│   ├── categories/
│   │   ├── dnsbl-categories.yml     # DNSBL feed list (8 feeds)
│   │   └── ip-reputation.yml        # IP reputation feed list
│   └── allowlists/
│       └── local-allowlist.txt
├── sigma/
│   └── rules/                       # Sigma detection rules (MITRE-mapped)
└── build/
    ├── render.sh                    # Master render orchestrator
    ├── lib/
    │   ├── render-suricata.sh
    │   ├── render-pfblockerng.sh
    │   └── render-zeek.sh
    └── tests/
        └── test-render.sh
```

## Security Policy Contract

### Invariant 11
> **Tier 2 is the sole authority for security policy.**
> No Suricata SID selection, DNSBL category, or Zeek detection script
> may exist in `tier1-perimeter/`. PRs violating this invariant must be rejected.

### Adding a new DNSBL feed
1. Add an entry to `pfblockerng/categories/dnsbl-categories.yml`.
   The optional per-feed `blocking:` key selects the pfBlockerNG
   Logging/Blocking Mode — omit it for the default `null_log` (Null Block:
   blocked domains answer `0.0.0.0` and clients fail instantly). `vip`
   (block-page webserver) is opt-in only and requires the DNSBL VIP to be
   reachable from client LANs; `verify-pfblockerng-feeds.sh`'s no-blackhole
   probe enforces this invariant on every run.
2. Run `make render PLATFORM=pfsense` from `tier1-perimeter/`
3. Review `tier1-perimeter/rendered/pfsense/pfblockerng/pfblockerng.xml`
4. Run `make deploy PLATFORM=pfsense`

### Adding a Suricata SID
1. Add SID to `suricata/rule-selection/enable.conf` or a custom rule to `suricata/custom-rules/`
2. Run `make render && make deploy`

### Adding a Zeek detection script
1. Place `.zeek` file in `zeek/scripts/`
2. Run `make render` — render-zeek.sh auto-discovers all `*.zeek` files
3. Run `make deploy`

## MITRE ATT&CK Coverage

| Component | Tactics | Techniques |
|---|---|---|
| Suricata rules | TA0001, TA0011, TA0010 | T1071, T1566, T1595 |
| Zeek suru-dns-entropy | TA0011 | T1071.004 |
| Zeek suru-ssl-ja3 | TA0011 | T1071 |
| pfBlockerNG DNSBL | TA0011 | T1071.004, T1568 |
| Sigma rules | TA0001, TA0011 | T1190, T1071, T1566 |
