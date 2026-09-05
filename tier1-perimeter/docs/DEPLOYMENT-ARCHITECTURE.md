# Tier 1 Perimeter — Deployment Architecture

> **Canonical reference** for maintainers, operators, and future AI-assisted
> development threads.
> Update this document whenever the orchestrator contract, hook lifecycle,
> trust model, or rollback semantics change.

---

## 1. Context

`tier1-perimeter` targets **native perimeter appliances** (pfSense, OPNsense)
rather than a container runtime. There is no `docker-compose.yaml` in this
tier. Deployment is SSH-based and the entrypoint is a modular Bash orchestrator.

This is intentional: pfSense and OPNsense run on FreeBSD and manage their own
service lifecycle. Wrapping them in containers would create a second layer of
complexity without adding value at the network perimeter.

---

## 2. Design Goals

| # | Goal | Implementation |
|---|---|---|
| 1 | Protect existing host config | `platform_backup` is mandatory before any change |
| 2 | Rollback on failure | `platform_revert` is auto-invoked by `deploy.sh` error trap |
| 3 | Separate orchestration from platform logic | `deploy.sh` calls hooks; drivers implement them |
| 4 | Extensible to new platforms | Add one file under `scripts/platforms/` |
| 5 | Single SURU PKI boundary | Tier 1 mTLS certs are signed by the SURU Root CA (Tier 4 PKI) |
| 6 | Dry-run safe | All I/O goes through `run()` in `lib/log.sh` |

---

## 3. Repository Structure

```text
tier1-perimeter/
├── .env.example                    # Required variables, copy to .env
├── Makefile                        # Operator-facing targets
├── certs/                          # Generated Tier 1 mTLS client certs (git-ignored)
├── backups/                        # Local copies of pre-deploy config backups (git-ignored)
├── docs/
│   ├── DEPLOYMENT-ARCHITECTURE.md  # This file
│   └── DEPLOYMENT-NOTES.md         # Quick-start operator and AI guide
├── pfsense/
│   ├── syslog-ng-apply.php          # Parses rendered syslog-ng.conf into pfSense XML objects
│   ├── pfblockerng-globals-apply.php # pfBlockerNG global settings + live resync (sync_package_pfblockerng)
│   ├── zeek-iface-apply.php         # Sets Zeek capture interface in config.xml + node.cfg
│   ├── zeek-scripts-apply.php       # Registers tier2 Zeek scripts in pfSense XML
│   ├── suricata-rules-apply.php     # Suricata rule enable/disable applier
│   ├── backup-encrypt.php / backup-restore.php # Pre-deploy config.xml backup
│   └── config-template.xml          # Base config.xml patch template
├── suricata/
│   ├── suricata.yaml
│   ├── update.yaml
│   ├── disable.conf
│   └── enable.conf
├── templates/
│   └── zeek/local.zeek.tpl        # Zeek site policy template (rendered into rendered/<platform>/zeek/local.zeek)
# Tier 2 owns detection scripts:
#   tier2-telemetry/zeek/scripts/soho-telemetry.zeek
#   tier2-telemetry/zeek/scripts/suru-dns-entropy.zeek
# These are rendered into tier1-perimeter/rendered/<platform>/zeek/scripts/
# by tier2-telemetry/build/lib/render-zeek.sh
└── scripts/
    ├── deploy.sh                   # Orchestrator (entry point)
    ├── update-rules.sh             # Suricata rule updater
    ├── lib/
    │   ├── log.sh                  # Logging + dry-run wrapper
    │   ├── ssh.sh                  # SSH/SCP helpers
    │   └── certs.sh                # mTLS cert generation
    └── platforms/
        ├── README.md               # Driver contract quick-reference
        ├── pfsense.sh              # pfSense driver (REFERENCE IMPLEMENTATION)
        └── opnsense.sh             # OPNsense driver (scaffold, not production-validated)
```

---

## 4. Orchestrator Lifecycle

`scripts/deploy.sh` owns these responsibilities only — it contains no
platform-specific logic:

1. Parse flags (`--dry-run`, `--verbose`, `--skip-certs`, `--skip-rules`,
   `--platform`).
2. Load `.env` and validate required variables.
3. Resolve `ROUTER_PLATFORM` and source the matching driver from
   `scripts/platforms/<platform>.sh`.
4. Register a global `trap ERR` that calls `platform_revert` if failure
   occurs after deployment has started.
5. Execute stages in order:

```
Stage 1  platform_preflight   Connectivity + capability checks
Stage 2  certs_generate_client  mTLS client cert vs SURU Root CA (Tier 4 PKI)
Stage 3  platform_backup      config.xml backup (remote + local)
Stage 4  platform_deploy      Push configs, certs; reload services
Stage 5  platform_verify      Post-deploy sanity checks
         [on ERR] platform_revert   Auto-triggered by error trap
```

### Platform Selection

```bash
# Via .env (default)
ROUTER_PLATFORM=pfsense

# Via flag (overrides .env)
./scripts/deploy.sh --platform opnsense
```

The driver name must match the filename under `scripts/platforms/` without
the `.sh` extension.

---

## 5. Platform Driver Contract

Every driver is a Bash file sourced into `deploy.sh`'s process. It must
implement exactly these five functions:

### `platform_preflight()`
- Verify SSH reachability with a probe command.
- Detect the platform version string.
- Assert that required binaries exist on the router (e.g. `pfSsh.php`,
  `pluginctl`).
- **Must fail fast** — abort before any backup or change if capabilities are
  missing.

### `platform_backup()`
- Create a timestamped backup of the router's live configuration.
- Store a remote copy on the router in a known directory.
- Pull a local copy into `tier1-perimeter/backups/` for offline auditability.
- **Must fail the deployment** if backup creation fails — never deploy without
  a confirmed backup.
- Set an internal variable (e.g. `_PF_BACKUP_FILE`) consumed by
  `platform_revert`.

### `platform_deploy()`
- Push all configuration files via `scp_push`.
- Render templates with `sed` before pushing where environment-specific values
  are needed.
- Run on-router syntax/config validation **before** activating services.
- Push mTLS certificates exported from `lib/certs.sh`.
- Restart or reload services using native platform mechanisms only.

### `platform_verify()`
- Confirm critical processes are alive.
- Confirm mTLS certificate files are present on the router.
- Warn (do not fail) on non-critical missing services.
- **Fail** on missing security-critical material (missing CA or client cert).

### `platform_revert()`
- Restore the backup recorded in `platform_backup`.
- Clear any configuration caches so the platform re-reads the restored file.
- Reload or restart the configuration-aware runtime.
- Log clearly if revert also fails — operators need an explicit message to
  intervene manually.
- **Called automatically by `deploy.sh` on ERR** — must also be safe to call
  manually.

---

## 6. Shared Libraries

### `lib/log.sh`

Provides `log_info`, `log_warn`, `log_error`, `log_debug`, `log_die`, and
`run()`.

`run()` is the **dry-run gate** — every command that changes state must go
through `run()`. In `--dry-run` mode it prints the command and returns 0
without executing.

All platform drivers and library scripts must use these functions. Never
define custom log formats in driver files.

### `lib/ssh.sh`

Provides `ssh_exec`, `ssh_exec_heredoc`, `scp_push`, `scp_pull`.

All functions read `ROUTER_HOST`, `ROUTER_SSH_USER`, `ROUTER_SSH_KEY`, and
`SSH_STRICT_HOST_KEY_CHECKING` from the environment. SSH options are
centralized in `_ssh_opts()` — update that function to harden SSH behavior
across all drivers at once.

### `lib/api.sh`

Self-contained REST API client used by both platform drivers. Sources no
other lib (provides log_* fallbacks). Public functions:

| Function | Purpose |
|---|---|
| `api_init` | Validate env, set per-platform `*_API_URL` defaults |
| `api_request METHOD PATH [BODY]` | Generic dispatched curl call |
| `api_health` | Authenticated reachability probe |
| `api_validate_deployment` | Verify syslog-ng, Suricata, Zeek are running |
| `api_service_status SVC` | Per-service status check |
| `api_reload_suricata_rules` | Incremental rules reload without service restart |
| `api_fetch_errors [LIMIT]` | Pull recent system log entries for failure analysis |
| `api_pfsense_install` | **pfSense only** — install pfRest as first package |

Platforms:
- **pfSense** uses pfRest (<https://pfrest.org/>). The package must be
  installed first; `api_pfsense_install` does this idempotently on every
  deploy.
- **OPNsense** uses its native API
  (<https://docs.opnsense.org/development/api.html>).

#### Authentication modes (`API_AUTH_MODE`)

| Mode | When to use | pfSense | OPNsense |
|---|---|---|---|
| `api_key` *(default, recommended for automation)* | CI, cron, unattended pipelines. Long-lived static credential; rotate quarterly. | `X-API-Key: ${PFSENSE_API_KEY}` | HTTP Basic with `${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}` (constructed manually so the secret is never on argv) |
| `jwt` *(best for short-lived sessions)* | Interactive operator runs. Token TTL is whatever pfRest issues (default ~1h). Auto-refreshed in-process before expiry. | `POST /auth/jwt` with `PFSENSE_API_USERNAME`+`PFSENSE_API_PASSWORD`, then `Authorization: Bearer <jwt>` | **Not supported.** OPNsense core has no JWT endpoint; setting `API_AUTH_MODE=jwt` with `ROUTER_PLATFORM=opnsense` fails at `api_init` time. |

#### Security hardening built into `lib/api.sh`

- **Tokens are kept out of process argv.** All auth headers and request
  bodies are written to **0600 temp files** under `/dev/shm` (when
  available) and passed to curl via `--header @file` / `--data-binary @file`.
  `ps`/`/proc/<pid>/cmdline` therefore cannot leak the secret.
- **JWT cache is in-process only.** Cached as bash variables in the sourced
  `lib/api.sh`; never written to disk. The cache dies with the process.
- **Auto-refresh.** JWT is refreshed automatically if less than 60 seconds
  remain on the TTL.
- **TLS verification on by default.** Setting `API_TLS_VERIFY=no` logs a
  `WARN`, not a silent allow — lab use only.
- **No tokens in logs.** Debug logging prints method/URL/mode only.
- **Temp file cleanup.** Each request unlinks its temp files immediately;
  an `EXIT` trap collects any orphans if a command aborts unexpectedly.

When credentials are absent in `.env`, drivers skip API operations and the
SSH-based deploy path remains fully functional.

### `lib/certs.sh`

Provides `certs_check_ca()` and `certs_generate_client(CERT_NAME)`.

`certs_check_ca()` validates that the SURU Root CA files exist and warns
if expiry is within 60 days.

`certs_generate_client()` generates a 2048-bit RSA client key and certificate
under `tier1-perimeter/certs/`, signed by the SURU Root CA. It is idempotent:
if a valid cert already passes `openssl verify -CAfile`, it is reused.

---

## 7. Certificate Trust Model

```
tier4-operations/pki/certs/root-ca.pem       ← SURU Root CA (authority, owned by Tier 4 PKI)
         │
         └── signs ──► tier1-perimeter/certs/tier1-<platform>-syslogng.pem
                                            ← Tier 1 mTLS client cert
```

**The SURU Root CA is the only CA in the platform.** `lib/certs.sh`
enforces this by failing deployment if `tier4-operations/pki/certs/root-ca.pem`
does not exist before any Tier 1 cert can be generated.

If the SURU Root CA does not yet exist, run:
```bash
tier4-operations/pki/scripts/generate-certs.sh
```

The generated client cert and CA cert are pushed to the router at:
```
/usr/local/etc/syslog-ng/tls/client.pem
/usr/local/etc/syslog-ng/tls/client-key.pem
/usr/local/etc/syslog-ng/tls/root-ca.pem
```

---

## 8. pfSense Driver Reference

`scripts/platforms/pfsense.sh` is the **reference implementation**. All other
drivers should follow its structure.

### Configuration Storage

PfSense stores all settings — core config and installed package config — in a
single XML file at `/conf/config.xml`.
Reference: https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html

**Critical rules when editing `config.xml`:**
- Always back it up first.
- After replacing it, flush the config cache:
  ```bash
  rm /tmp/config.cache
  ```
- Then reload config into PHP memory:
  ```php
  parse_config(true);
  ```

### PHP Shell (`pfSsh.php`)

Netgate documents `pfSsh.php` as the native PHP developer shell for pfSense.
Reference: https://docs.netgate.com/pfsense/en/latest/development/php-shell.html

Key mechanics used by the pfSense driver:

| Construct | Effect |
|---|---|
| `exec;` | Executes queued PHP statements |
| `parse_config(true);` | Reloads `$config` array from `/conf/config.xml` |
| `write_config();` | Persists in-memory `$config` back to `config.xml` |
| `pfSsh.php playback svc <action> <svc>` | Native CLI service control (mirrors GUI Status > Services) |

The driver exposes two helpers:

```bash
# Service control — pfSsh.php playback svc restart syslog-ng
_pf_pfsh_svc  restart  syslog-ng

# Arbitrary PHP execution via pfSsh.php heredoc
_pf_pfsh_php  'parse_config(true);'
```

`_pf_pfsh_php()` is available for future drivers that need to apply
configuration mutations programmatically via `write_config()`.

### Backup and Revert Flow

The driver runs an **encrypted** snapshot of `/conf/config.xml` BEFORE any
deploy step mutates state. The on-router encryption uses pfSense's
(and OPNsense's inherited) `crypt.inc` helpers — `encrypt_data()` /
`tagfile_reformat()` — which is the same code path the GUI's "Encrypt
this configuration file" checkbox runs.

```
_pf_backup / _opn_backup:
  Password from SURU_BACKUP_PASSWORD env var → 0600 file under /dev/shm
  SCP applier (tier1-perimeter/pfsense/backup-encrypt.php) + pass file
    to /tmp/suru-staging on router
  ssh "sudo php backup-encrypt.php <pass-file> /root/suru-backups/<plat>-<ts>.bak"
    → AES-256-CBC + PBKDF2 (sha256, 500_000 iter), envelope-wrapped
  scp_pull → tier1-perimeter/backups/<plat>-<ts>.bak (chmod 600)
  ssh "rm -f <pass-file-stage>"   # wipe remote copy of pass

trap '_pf_revert' ERR             # auto-fired on any subsequent failure

_pf_revert / _opn_revert (on ERR):
  Re-stage pass file + restore applier (backup-restore.php)
  If on-router backup is gone, SCP local copy back first
  ssh "sudo php backup-restore.php <pass-file> <backup-path>"
    → tagfile_deformat + decrypt_data → sanity check (root element
      must be <pfsense> or <opnsense>; payload must start with the
      XML processing instruction) → atomic rename into /conf/config.xml
    → flush /tmp/config.cache + parse_config(true)
  Restart affected services (syslog-ng, suricata) so they reload the
  pre-deploy known-good config.
```

**Manual recovery options when the auto-revert itself fails:**
- pfSense GUI: Diagnostics → Backup & Restore → Restore Configuration
  (check "Encrypted"), upload the local `.bak`, supply the password.
- OPNsense GUI: System → Configuration → Backups → Restore.
- pfSense also keeps its own write_config history at `/cf/conf/backup/`
  (auto, plaintext, last ~30 entries) — separate safety net.

The password is **never** passed on argv or stored beyond the deploy run:
it lives in `.env` (operators should SOPS-encrypt the file), transits to
the router as a 0600 file in `/tmp/suru-staging`, and is wiped on the
remote side as soon as the encrypt/decrypt step returns.

### Deployment Sub-functions

| Function | Action |
|---|---|
| `_pf_deploy_syslogng` | Render template, push config + mTLS certs, run `syslog-ng --syntax-only` on router |
| `_pf_deploy_suricata` | Push YAML + rule configs, run `suricata --test-config` on router |
| `_pf_deploy_zeek` | Push Zeek site policy, SOHO telemetry module, and zeekctl.cfg; `mkdir -p /var/log/zeek` |
| `_pf_reload_services` | `pfSsh.php playback svc` for syslog-ng + zeek; `suricatasc -c reload-rules` for live rule hot-reload |
| Suricata log-management stage (`SURU_SURICATA_LOG_MGMT`) | `suricata-logmgmt-apply.php` enables the Suricata package's Log Management cron (`enable_log_mgmt`, unset by default — without it `eve.json` never rotates) and caps `eve.json`/`http.log` size + retention; the cron rotates by rename + SIGHUP, so syslog-ng never re-reads a rotated copy |
| pfBlockerNG log-rotation stage (`SURU_PFBLOCKERNG_LOG_ROTATION`) | Generates and installs `/var/etc/newsyslog.conf.d/suru-pfblockerng.conf` (rename-rotation of `dnsbl.log`/`ip_block.log` ahead of the pfBlockerNG cron), proven with a `newsyslog -nvf` dry run |

### Boot Persistence (syslog-ng, Zeek interface)

Two of the pfSense appliers in `tier1-perimeter/pfsense/` deliberately bypass
pfSense's native XML-driven config builder, because that builder cannot
express what we need:

- `syslog-ng-apply.php` — pfSense's syslog-ng XML schema can't express
  syslog-ng 4.x features (`disk-buffer`, `ca-dir`, `sni`) the SURU template
  relies on. The applier calls `syslogng_resync()` only for its side effects,
  then overwrites `/usr/local/etc/syslog-ng.conf` directly with the full
  rendered template and starts the daemon directly.
- `zeek-iface-apply.php` — `zeek_settings_resync()`'s `get_real_interface()`
  can only resolve pfSense *logical* interface names (`lan`, `opt1`, …); a
  physical trunk like `igb1` (this deployment's capture interface) has no
  logical alias, so the native resync silently fails to write `node.cfg`.
  The applier detects this and writes `node.cfg` directly.

Both bypasses only fix the **current boot**: pfSense's own boot sequence
re-runs its native config builders, which would silently revert both fixes
on every reboot until an operator re-ran `make deploy` by hand — this is
exactly what caused an ingestion outage on 2026-06-22 (syslog-ng came up
with a broken, native-schema-generated config after a router reboot).

**First attempt — `system/shellcmd` — DISPROVEN by a live reboot test
(2026-06-23).** Netgate's boot-commands documentation
(https://docs.netgate.com/pfsense/en/latest/development/boot-commands.html)
says `shellcmd` runs "late in boot," and a `system/shellcmd` entry was
registered on that basis. Reading the actual pfSense source on the router
disproved this: `/etc/rc.bootup` calls `system_do_shell_commands()`
(`shellcmd`) at line ~415, then `register_all_installed_packages()` —
which re-triggers `syslogng_resync()` and Zeek's settings resync — at line
~481, **after** shellcmd. So the shellcmd-applied fix always lost the race.
The first reboot test didn't visibly fail only because the underlying XML
object set happened to already be self-consistent (this deploy's own
`write_config()` calls had incidentally cleaned up the dangling reference
from the original incident) — confirmed via file evidence: post-reboot
`syslog-ng.conf` had a different mtime/size than `suru-rendered.conf`
(natively regenerated, not our copy) and zero `suru-boot-apply` entries in
`system.log` despite the shellcmd being registered.

**Actual fix — pfSense `cron/item`** (core `configure_cron()` in
`/etc/inc/services.inc`, not the optional Cron package): both appliers now:
1. Persist their validated output to a durable path (survives reboot, unlike
   `/tmp/suru-staging`): `/usr/local/etc/syslog-ng/suru-rendered.conf` and
   `/usr/local/etc/zeek/suru-active-interface` respectively.
2. Write a small, idempotent, no-op-safe re-apply shell script next to it
   (`suru-boot-apply.sh` in each directory) — idempotency (a `cmp`/`grep`
   check before touching anything) is mandatory here, not optional: the job
   runs every minute, and without the check syslog-ng would restart every
   single minute.
3. Register that script as a `cron/item` entry (`* * * * *`, i.e. every
   minute) in `config.xml`, deduplicated by command path on every run.

`cron(8)` only starts once `/etc/rc.bootup` fully completes — confirmed on
the router: the `cron` process start time matches boot time, after
`register_all_installed_packages()` — so it reliably has the last word. As
a recurring job it also self-heals any *future* drift (an operator GUI
save in Status > syslog-ng, for example), not just the boot-time case,
which `shellcmd` (a one-shot) never could have covered either.

**Confirmed durable by a second live reboot test (2026-06-23):**
post-reboot, `/usr/local/etc/syslog-ng.conf`'s mtime landed exactly on the
next cron minute-tick boundary and was byte-identical to
`suru-rendered.conf`; `node.cfg` showed `interface=igb1`; Tier 3's frontdoor
logged a new syslog TLS session within 3 minutes of the router coming back
up. The stale `system/shellcmd` entries from the first attempt were removed
from both appliers and from the live router's `config.xml`.

The other three appliers (`suricata-rules-apply.php`,
`zeek-scripts-apply.php`, `pfblockerng-globals-apply.php`) write
exclusively through `config_set_path()`/`write_config()` and their package's
native resync function — fully native, durable across reboots, no
cron/shellcmd needed.

---

### Log Rotation Contract and Persistence Classes

Every file the platform tails must rotate **by rename**, through the mechanism
that owns the file, enabled and sized by the platform by default — never an
in-place rewrite. pfBlockerNG violates this: its cron's `tail -n N` + `mv -f`
rewrite makes syslog-ng re-read ~40k lines every night, and the vendor's
"No Limit" cap is unreachable (`pfb_filter` accepts digits only and returns
the 20000 default), so the driver installs a pfSense-native `newsyslog`
drop-in that rotates both block logs just before the cron hour.

| Tailed log | Owner mechanism | Platform-enabled by |
|---|---|---|
| pfSense system logs | native `newsyslog` (`/var/etc/newsyslog.conf.d/pfSense.conf`) | pfSense default |
| Suricata `eve.json` | package cron (rename + SIGHUP) | `suricata-logmgmt-apply.php` (log-management stage) |
| Zeek `*.log` | `zeekctl cron` (`LogRotationInterval`) | deployed `zeekctl.cfg` |
| pfBlockerNG `dnsbl.log` / `ip_block.log` | native `newsyslog` drop-in | log-rotation stage |

Everything the driver changes on pfSense belongs to one persistence class:

| Class | Mechanism | Examples | Durability |
|---|---|---|---|
| **A** | `config.xml` via PHP applier + native resync | syslog-ng objects, Suricata, Zeek interface, pfBlockerNG globals, unbound zones | reboot/upgrade/restore safe by construction |
| **B** | file on disk via `_pf_stage_and_install` | certs, `zeekctl.cfg`, `node.cfg`, Zeek site scripts, Suricata rule files, the newsyslog drop-in | reboot-safe (persistent `/var`); re-converged every deploy; not in `config.xml` — a fresh box or a config restore needs `make deploy` |
| **C** | native crons/state owned by pfSense or a package | `newsyslog`, package crons | toggled only through class A |

Mechanism, evidence and verification: the stage comment in
`scripts/platforms/pfsense.sh` (search "pfBlockerNG block-log rotation").

---

## 9. OPNsense Driver Status

`scripts/platforms/opnsense.sh` implements all five hooks as a scaffold.

- Uses `pluginctl -s <svc> restart` (OPNsense 21+) with `service` fallback.
- Uses `configctl template reload all` for post-revert config reload.
- Marked with `[STUB: ...]` comments where router-side verification is
  required before production use.
- **Not production-validated.** Use `pfsense.sh` as the authoritative
  reference; use `opnsense.sh` as the extension template.

---

## 10. Extension Rules for New Drivers

When adding a new platform driver:

1. Create `scripts/platforms/<name>.sh`.
2. Implement all five hooks: `platform_preflight`, `platform_backup`,
   `platform_deploy`, `platform_verify`, `platform_revert`.
3. Use only functions from `lib/log.sh`, `lib/ssh.sh`, `lib/certs.sh` for
   I/O, SSH, and cert operations — no custom SSH calls.
4. Prefer native platform mechanisms over ad hoc shell edits where they
   exist.
5. Never modify host configuration before `platform_backup` has succeeded.
6. Set `ROUTER_PLATFORM=<name>` in `.env` or pass `--platform <name>`.
7. Add the driver to the table in `scripts/platforms/README.md`.
8. Update `.env.example` if new environment variables are required.
9. Update `Makefile` if new `make` targets are useful for the platform.
10. **Update this document** to reflect the driver's design choices and
    current validation status.

---

## 11. Environment Variables Reference

All variables are defined in `.env` (copied from `.env.example`):

| Variable | Required | Default | Description |
|---|---|---|---|
| `ROUTER_HOST` | ✅ | — | IP or hostname of the target router |
| `ROUTER_SSH_USER` | ✅ | — | SSH username (e.g. `admin`) |
| `ROUTER_SSH_KEY` | ✅ | — | Path to SSH private key |
| `ROUTER_PLATFORM` | ✅ | — | Platform driver name: `pfsense` or `opnsense` |
| `SSH_STRICT_HOST_KEY_CHECKING` | — | `yes` | SSH host key enforcement |
| `FRONTDOOR_SYSLOG_SNI` | ✅ | `syslog.suru.local` | SNI hostname presented by syslog-ng to the Tier 4 frontdoor stream demux; nginx routes this SNI to logstash-pfsense:5140 via TCP passthrough |
| `FRONTDOOR_PORT` | — | `443` | Port for all Tier 1 → frontdoor connections (literal port 443) |
| `SURICATA_IFACES` | — | `igb1` | Comma-separated **physical NIC names only** (e.g. `igb1,igb2` / `eth0,eth1`) — one Suricata instance per NIC. pfSense logical aliases (`lan`, `opt1`) and VLAN sub-interfaces (`igb1.10`) are **rejected at deploy time**; on pfSense the deploy resolves each NIC to a carrier alias internally via `suru-iface-resolve.php`. Same contract as `ZEEK_IFACE`. |
| `SURICATA_IPS_MODE` | — | `legacy` | Capture/enforcement mode. `legacy` = pcap capture + reactive pf-table block. `inline` = netmap in-flight drop on the physical NIC (Suricata joins the datapath; arms the inline-flip dead-man's-switch first). |
| `SURICATA_NETMAP_THREADS` | — | auto | Explicit netmap threads (1-8) for inline mode; unset = `min(NIC netmap queues, ncpu/2)` computed on the router (never `auto`). |
| `SURICATA_DROP_CATEGORIES` | — | CRITICAL set | ET categories converted `alert→drop` so inline mode enforces (default: `emerging-botcc,emerging-malware,emerging-exploit,emerging-attack_response`). Empty value reverts the drop policy. |
| `SURU_SURICATA_DROP_POLICY` | — | `true` | Set `false` to skip the drop-policy applier (does not revert an applied policy). |
| `SURU_SURICATA_LOG_MGMT` | — | `true` | Enable the Suricata package's log-management cron and apply the caps below (global Suricata config, all interfaces) |
| `SURICATA_EVE_LOG_LIMIT_KB` / `SURICATA_HTTP_LOG_LIMIT_KB` | — | `500000` | Per-file rotation size caps in KB (pfSense's unit) |
| `SURICATA_LOG_RETENTION_HOURS` | — | `24` | Retention of rotated `eve.json.*` / `http.log.*` copies on the router |
| `SURU_SAFETY_TIMER` | — | `true` | Arm a router-side auto-revert before an inline flip (self-lockout guard); disarmed on success. |
| `SURU_SAFETY_REVERT_SECONDS` | — | `600` | Dead-man's-switch window (min 30) before the router auto-reverts to legacy if the deploy never disarms. |
| `SURU_SKIP_HW_PREFLIGHT` | — | `false` | Skip hardware detection; deploy uses conservative built-in defaults (4 GB / 4-core profile). |
| `SURU_SURICATA_TUNING` / `SURU_PF_TUNING` / `SURU_DNS_TUNING` | — | `true` | Per-applier opt-outs for the hardware-adaptive tuning steps (Suricata detect profile/memcaps, pf state-table, unbound cache). |
| `SURICATA_IFACE` | — | — | **Deprecated** single-interface alias; honoured as fallback when `SURICATA_IFACES` is unset (physical NIC only). |
| `ZEEK_IFACE` | — | `em0` | **Physical trunk interface** for Zeek (e.g. `igb1`, `em0`). Unlike Suricata, Zeek's interface is written directly into `local.zeek`/`node.cfg` — use the parent trunk, not a VLAN sub-interface. Zeek understands 802.1Q natively: one sensor on the trunk covers all VLANs. |
| `ZEEK_MAILTO` | — | `root` | zeekctl alert email recipient; baked into rendered `zeekctl.cfg` |
| `SURU_PFBLOCKERNG_LOG_ROTATION` | — | `true` | Install the newsyslog drop-in that rotates pfBlockerNG's `dnsbl.log`/`ip_block.log` by rename ahead of its cron |
| `PFBLOCKERNG_LOG_ROTATE_TIME` | — | `@T2359` | Daily rotation time-of-day (`@Thhmm`); must precede the pfBlockerNG cron hour |
| `PFBLOCKERNG_LOG_ROTATE_KB` | — | `10240` | Size backstop (KB) for the same rotation |
| `PFBLOCKERNG_LOG_ROTATE_COUNT` | — | `7` | Archives kept per log (bzip2) |
| `API_AUTH_MODE` | — | `api_key` | Router API auth mode: `api_key` (automation) \| `jwt` (short-lived, pfSense only) |
| `API_TLS_VERIFY` | — | `yes` | Verify TLS on router API calls (`no` for self-signed; emits WARN) |
| `API_CONNECT_TIMEOUT` | — | `30` | curl connect timeout for API calls |
| `API_MAX_TIME` | — | `60` | curl total deadline for API calls |
| `PFSENSE_API_PKG_URL` | pfSense | — | URL to `pfSense-pkg-RESTAPI.pkg` for first-package install |
| `PFSENSE_API_URL` | — | `https://${ROUTER_HOST}/api/v2` | pfRest base URL |
| `PFSENSE_API_KEY` | pfSense (`api_key`) | — | pfRest API key, sent as `X-API-Key` (UI: System → API → Authentication) |
| `PFSENSE_API_USERNAME` | pfSense (`jwt`) | — | Login username for `POST /auth/jwt` |
| `PFSENSE_API_PASSWORD` | pfSense (`jwt`) | — | Login password — **store via SOPS / secret manager** |
| `OPNSENSE_API_URL` | — | `https://${ROUTER_HOST}/api` | OPNsense API base URL |
| `OPNSENSE_API_KEY` | OPNsense | — | OPNsense API key (UI: System → Access → Users → API keys) |
| `OPNSENSE_API_SECRET` | OPNsense | — | OPNsense API secret |
| `SURU_SKIP_API_INSTALL` | — | `false` | Skip pfRest install step in deploy |
| `SURU_SKIP_API_VALIDATE` | — | `false` | Skip post-deploy API validation |

---

## 12. Operator Validation Workflow

On-router config validation (`suricata --test-config`, `syslog-ng --syntax-only`)
runs automatically inside `platform_deploy` before any service is reloaded;
there are no standalone `make` targets for those checks. Post-deploy service
health is validated via the REST API targets.

```bash
# 0. Ensure SURU Root CA exists (owned by Tier 4 PKI)
ls -la ../tier4-operations/pki/certs/root-ca.pem

# 1. Populate .env
cp .env.example .env && $EDITOR .env

# 2. Render Tier 2 intelligence into platform-specific artefacts
make render

# 3. Dry-run preview — deploy.sh also auto-engages dry-run if ROUTER_HOST
#    is unset, so a bare `make deploy` without a target host is always safe.
DRY_RUN=true make deploy

# 4. Live deploy — render + push + on-router config tests + verify
make deploy

# 5. Post-deploy API health + service validation (requires API credentials)
make api-health
make api-validate
```

---

## 13. REST API Integration

In addition to the SSH-based deploy path, Tier 1 uses a router REST API to:

1. **Validate deployments** — after SSH push, query the API to confirm
   `syslog-ng`, `suricata`, and `zeek` are actually running.
2. **Validate configuration updates** — drivers can call platform validation
   endpoints before reloading services.
3. **Incremental security rules updates** — push Suricata SID toggles via
   `api_reload_suricata_rules` and avoid a full service restart.
4. **Surface errors for analysis** — on validation failure,
   `api_fetch_errors` pulls recent system log entries from the router so the
   operator (or an AI session) has structured context for diagnosis.

### Platform-specific transports

| Platform | Stack | Auth | First-deploy bootstrap |
|---|---|---|---|
| pfSense  | **pfRest** (<https://pfrest.org/>) | Bearer token + client id | Auto-install via SSH `pkg-static add ${PFSENSE_API_PKG_URL}`, called by `api_pfsense_install` at the start of `_platform_deploy` |
| OPNsense | **Native API** (<https://docs.opnsense.org/development/api.html>) | HTTP Basic (key:secret) | None — built into OPNsense since 18.x; operator creates an API key in **System → Access → Users → API keys** |

### Failure semantics

API failures are **non-fatal** in the current implementation. The SSH-based
deploy continues to be the authoritative path; API validation only surfaces
findings. This is intentional during the initial rollout so the API layer
can be observed before being made deploy-gating.

To opt out entirely (e.g. on isolated networks):
- `SURU_SKIP_API_INSTALL=true` — skip pfRest pkg install
- `SURU_SKIP_API_VALIDATE=true` — skip all post-deploy API calls

### Implementation caveat — driver hook contract

The 5-hook contract described in §5 (`platform_preflight`, `_backup`,
`_deploy`, `_verify`, `_revert`) is the **target** design. The current
drivers (`pfsense.sh`, `opnsense.sh`) instead expose a single
`_platform_deploy()` function called by `deploy.sh` v3.0.0. API
integration is wired into this single entrypoint:

- pfSense: `api_pfsense_install` at the start of `_platform_deploy`,
  `api_health` + `api_validate_deployment` + `api_fetch_errors` at the
  end.
- OPNsense: `api_health` probe before SSH-deploy, validation +
  error-fetch at the end.

When the drivers migrate to the 5-hook contract, the API calls move into
`platform_preflight` (install + auth check) and `platform_verify`
(validation + error fetch).

---

## 14. Canonical Source-of-Truth Files

For future AI-assisted development sessions, read these files first:

| File | Purpose |
|---|---|
| `docs/DEPLOYMENT-ARCHITECTURE.md` | This document — design intent |
| `docs/DEPLOYMENT-NOTES.md` | Operator quick-start |
| `scripts/deploy.sh` | Orchestrator and stage lifecycle |
| `scripts/lib/log.sh` | Logging and dry-run contract |
| `scripts/lib/ssh.sh` | SSH/SCP primitives |
| `scripts/lib/certs.sh` | PKI trust chain and cert generation |
| `scripts/lib/api.sh` | Router REST API client (pfRest / OPNsense native) |
| `scripts/platforms/pfsense.sh` | Reference driver implementation |
| `scripts/platforms/opnsense.sh` | Extension template (scaffold) |
| `scripts/platforms/README.md` | Driver hook contract quick-reference |
| `.env.example` | All required environment variables |
| `Makefile` | All user-facing operations |
