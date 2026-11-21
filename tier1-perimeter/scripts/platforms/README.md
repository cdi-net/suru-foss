# Tier 1 Platform Drivers

Each file in this directory is a self-contained platform driver sourced by `deploy.sh`.
All drivers implement the same five hooks:

| Hook | Purpose |
|---|---|
| `platform_preflight` | SSH connectivity check, version detection, capability assertions |
| `platform_backup` | Backup `/conf/config.xml` to timestamped file (remote + local copy) |
| `platform_deploy` | Push syslog-ng, Suricata, Zeek configs; push mTLS certs; reload services |
| `platform_verify` | Post-deploy sanity checks (process alive, certs on disk, port reachable) |
| `platform_revert` | Restore pre-deploy backup on failure; flush config cache; restart services |

## Available Drivers

| File | Platform | Status | Method | REST API |
|---|---|---|---|---|
| `pfsense.sh` | pfSense CE / Plus | ✅ Production | SSH + `pfSsh.php playback svc` | pfRest (<https://pfrest.org/>) — installed as first package |
| `opnsense.sh` | OPNsense 21+ | 🚧 Scaffold | SSH + `pluginctl` / `confctl` | Native API (<https://docs.opnsense.org/development/api.html>) |

## Privilege matrix

The pfSense deploy account's sudo command list (full-path constants in the
driver, checked by `scripts/lib/tests/test-sudo-allowlist.sh`) and the API
account are documented in
[`../../docs/privilege-matrix-pfsense.md`](../../docs/privilege-matrix-pfsense.md).
A driver change that adds a root-run binary updates the matrix in the same
change. The OPNsense scaffold has no matrix yet.

## SSH connection reuse

`deploy.sh` calls `ssh_mux_enable` (`../lib/ssh.sh`) for a real deploy, and the
drivers append `SSH_MUX_OPTS` to their ssh/scp options, so every remote step of
a deploy shares one OpenSSH connection. `deploy.sh` closes it on exit
(`ssh_mux_close`, the last link of the EXIT-trap chain). The safety timer's
disarm path forces a fresh connection, so it proves a new login still reaches
the router. `SURU_SSH_MUX=false` turns reuse off.

## REST API Layer

All drivers source `../lib/api.sh` for post-deploy validation, incremental
Suricata rules reload, and on-failure error analysis (recent system log
fetch). Public functions:

| Function | Purpose |
|---|---|
| `api_init` | Validate env vars; sets per-platform URL defaults |
| `api_health` | Authenticated reachability probe |
| `api_validate_deployment` | Check core services (syslog-ng, suricata, zeek) are running |
| `api_reload_suricata_rules` | Hot-reload Suricata rules without service restart |
| `api_fetch_errors [LIMIT]` | Pull recent system log entries for diagnostic analysis |
| `api_pfsense_install` | **pfSense only** — install pfRest as first package (idempotent) |

When API credentials are absent in `.env`, the SSH-only deploy path remains
fully functional; only validation/error-analysis features are skipped.

### Authentication modes (`API_AUTH_MODE`)

| Mode | When to use | pfSense | OPNsense |
|---|---|---|---|
| `api_key` *(default; recommended for automation)* | CI, cron, unattended deploys | `X-API-Key: ${PFSENSE_API_KEY}` | HTTP Basic with `${OPNSENSE_API_KEY}:${OPNSENSE_API_SECRET}` |
| `jwt` *(best for short-lived sessions)* | Interactive operator runs | `POST /auth/jwt`, then `Authorization: Bearer <jwt>`. Auto-refreshed in-process. | **Not supported** — fails at `api_init`. |

`lib/api.sh` keeps secrets out of `ps` by writing auth headers / bodies to
0600 temp files (`/dev/shm` when available) and passing them via
`--header @file` / `--data-binary @file`.

### Env vars (set in `tier1-perimeter/.env`)

```
# Shared
API_AUTH_MODE=api_key                # api_key | jwt
API_TLS_VERIFY=yes
API_CONNECT_TIMEOUT=30
API_MAX_TIME=60

# pfSense / pfRest
PFSENSE_API_PKG_URL=https://github.com/jaredhendrickson13/pfsense-api/releases/.../pfSense-2.7-pkg-RESTAPI.pkg
# api_key mode
PFSENSE_API_KEY=<UI: System -> API -> Authentication -> Issue Key>
# jwt mode (alternative — store password via SOPS)
# PFSENSE_API_USERNAME=
# PFSENSE_API_PASSWORD=

# OPNsense (api_key mode only)
OPNSENSE_API_KEY=<UI: System -> Access -> Users -> API keys>
OPNSENSE_API_SECRET=<from same UI>
```

## Adding a New Driver

1. Copy `opnsense.sh` as a starting template.
2. Implement all five hook functions.
3. Set `ROUTER_PLATFORM=<driver_name>` in `.env` or pass `--platform <name>` to `deploy.sh`.
4. The driver name must match the filename without `.sh`.

## pfSense Driver Notes

- Uses `pfSsh.php playback svc <action> <service>` for all service control.
  See: <https://docs.netgate.com/pfsense/en/latest/development/php-shell.html>
- Uses `parse_config(true)` via `pfSsh.php` to reload in-memory config after revert.
  See: <https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html>
- `rm /tmp/config.cache` is always called after restoring `config.xml` to ensure
  pfSense does not serve stale cached config.
- `write_config()` is available for future use when deploying XML config changes
  programmatically via `_pf_pfsh_php()`.
