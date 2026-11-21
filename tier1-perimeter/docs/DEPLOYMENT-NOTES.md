# Tier 1 Perimeter — Deployment Notes

Quick-start reference for operators and future AI-assisted development
sessions. For the full design rationale, read
[`DEPLOYMENT-ARCHITECTURE.md`](./DEPLOYMENT-ARCHITECTURE.md).

---

## What This Tier Does

Tier 1 is the network perimeter. It deploys and manages:

- **Suricata** — inline IPS with ET Open + Talos rules (MITRE T1071, T1566,
  T1595)
- **Zeek** — passive network telemetry (conn, dns, ssl, http, ssh, smtp, files,
  x509)
- **syslog-ng** — structured log aggregation with mTLS shipping to Tier 3 SIEM
- **pfBlockerNG / DNS** — configured separately via pfSense GUI / XML

This tier runs **natively on the router**. There are no containers here.

---

## Prerequisites

Before running `deploy.sh`:

1. The SURU Root CA (managed by Tier 4 PKI) must exist:
   ```
   tier4-operations/pki/certs/root-ca.pem
   tier4-operations/pki/certs/root-ca-key.pem
   ```
   If not, run `tier4-operations/pki/scripts/generate-certs.sh` first.

2. SSH key-based access must be configured on the router.

3. On pfSense, `syslog-ng`, `suricata`, and `zeek` packages must be installed
   via **System > Package Manager** before deployment.

4. `.env` must be populated from `.env.example`.

5. **Router REST API credentials (for post-deploy validation, error analysis,
   and incremental rules reload):**

   Pick an auth mode and set the matching variables in `.env`:

   ```
   # api_key  = long-lived static key  (RECOMMENDED for automation/CI)
   # jwt      = short-lived bearer token, pfSense only
   #            (RECOMMENDED for interactive operator sessions)
   API_AUTH_MODE=api_key
   ```

   ### pfSense (pfRest) — automated setup (recommended)

   Two one-shot Make targets create everything you need:

   ```bash
   # 1. Install pfRest package
   echo 'PFSENSE_API_PKG_URL=https://...your-version.pkg' >> .env   # see https://pfrest.org/
   make api-install-pfrest PLATFORM=pfsense

   # 2. Create suru-validator user, enable KeyAuth, issue a sha512 API key.
   #    Uses ROUTER_SSH_KEY from .env — no admin password required.
   #    Idempotent: re-run to rotate the key.
   make api-bootstrap

   # 3. Paste the printed PFSENSE_API_KEY into .env, then verify:
   make api-health
   ```

   See `docs/API-VALIDATION-SETUP.md` for the full privilege model and
   the rationale for using the automated bootstrap over a manual user.

   ### pfSense (pfRest) — manual setup (alternative)

   If you prefer to manage the API user yourself instead of using
   `make api-bootstrap`, choose ONE of the auth modes below:

   - **`api_key` mode (automation / CI):**
     - pfSense UI → **System → REST API → Authentication → Issue Key**.
     - Set in `.env`: `PFSENSE_API_KEY=<key>`.
     - Verify: `make api-health PLATFORM=pfsense`.

   - **`jwt` mode (short-lived operator sessions):**
     - Use an existing pfSense user with API permissions.
     - Set in `.env`:
       ```
       API_AUTH_MODE=jwt
       PFSENSE_API_USERNAME=<user>
       PFSENSE_API_PASSWORD=<password>   # store the .env via SOPS
       ```
     - Verify: `make api-health PLATFORM=pfsense`.
       The first call logs in to `/api/v2/auth/jwt`; subsequent calls reuse
       the cached token until it nears expiry.

   ### OPNsense (native API — `api_key` mode only)

   - In OPNsense UI: **System → Access → Users → [user] → API keys → +**.
   - OPNsense downloads `apikey.txt` containing `key=...` / `secret=...`.
   - Set in `.env`:
     ```
     OPNSENSE_API_KEY=...
     OPNSENSE_API_SECRET=...
     ```
   - Verify: `make api-health PLATFORM=opnsense`.
   - OPNsense core does **not** support JWT — `API_AUTH_MODE=jwt` with
     OPNsense fails at `api_init` with a clear error.

   If left unset, the SSH-based deploy still works; only API-based
   validation and incremental rules reload are disabled.

   **Secret handling:** never commit `.env`. Use SOPS + age (already a
   project standard — see `.sops.yaml`) when distributing this file or
   storing it in CI secret stores.

---

## First Deployment

```bash
# Copy and edit environment file
cp .env.example .env
$EDITOR .env

# Render Tier 2 intelligence into Tier 1 platform-specific artefacts
# under rendered/<platform>/
make render

# Dry-run preview — passes --dry-run to deploy.sh. Note: deploy.sh also
# auto-forces dry-run when ROUTER_HOST is unset, so a bare `make deploy`
# without a target host is always safe.
DRY_RUN=true make deploy

# Live deploy (only after reviewing dry-run output)
make deploy

# Render + deploy in one step
make deploy-full
```

The Makefile picks up the target platform from `ROUTER_PLATFORM` in `.env`.
Override per-invocation with `PLATFORM=opnsense make deploy`.

---

## Available Make Targets

| Target | Action |
|---|---|
| `make render` | Merge Tier 2 intelligence into Tier 1 templates → `rendered/<platform>/` |
| `make deploy` | Hardware preflight, render, then push rendered artefacts to the router |
| `make deploy-full` | Explicit `render` + `deploy` in one step |
| `make clean` | Remove `rendered/` artefacts (preserves `.gitkeep`) |
| `make gen-certs` | Issue the Tier 1 syslog-ng mTLS client pair from the existing Root CA (idempotent; run on the PKI host, never creates a CA) |
| `make test` | Run the render pipeline tests and the Tier 1 suites (PHP-backed suites skip when `php` is not installed) |
| `make api-health` | Probe router REST API (pfRest or OPNsense native) |
| `make api-validate` | Verify core services running via API |
| `make api-install-pfrest` | One-shot: install pfRest on pfSense as first package |
| `make api-bootstrap` | One-shot: create `suru-validator` user + issue API key (pfSense, SSH-based, idempotent — rotates the key on re-run) |
| `make api-reload-rules` | Incremental Suricata rules reload without service restart |
| `make sng-metrics` / `sng-status` / `sng-buffer` / `sng-lag` | syslog-ng telemetry over SSH: service state, per-file disk-buffer inventory, delivery lag (needs a root shell on the router) |

### Variable overrides

| Variable | Effect |
|---|---|
| `PLATFORM=pfsense\|opnsense` | Override platform from `.env` for a single `make` invocation |
| `DRY_RUN=true` | Pass `--dry-run` through to `deploy.sh` and `render.sh` |
| `VERBOSE=true` | Pass `--verbose` to the underlying scripts |

For direct script use, bypassing the Makefile:

```bash
./scripts/deploy.sh --platform pfsense [--target <host>] [--dry-run] [--verbose] [--rendered-dir <abs-dir>]
```

`deploy.sh` auto-engages dry-run when `ROUTER_HOST` / `--target` is unset.
`--rendered-dir` reads the rendered artefacts from an absolute directory that
must exist, instead of `tier1-perimeter/rendered/<platform>`.

---

## How Deployment Works

`scripts/deploy.sh` is the orchestrator. It:

1. Loads `.env` and resolves the platform driver.
2. Validates the SURU Root CA (tier4-operations/pki/certs/root-ca.pem).
3. Generates a Tier 1 mTLS client certificate if needed.
4. Backs up the router's `/conf/config.xml` before any change.
5. Dispatches to the platform driver for deploy and service reload.
6. Verifies post-deploy state.
7. **Automatically reverts** to the backup if any step fails.

### pfSense deploy behaviour

- **One SSH connection.** A real deploy runs every remote step over one OpenSSH
  connection (`SURU_SSH_MUX`, `SURU_SSH_CONTROL_PERSIST`), so a deploy stays
  below the perimeter's own SSH brute-force threshold. `deploy.sh` closes the
  connection on exit. A dry run opens none.
- **One Suricata restart.** The Suricata appliers (rules, tuning, drop policy)
  run without `--restart`. Only when at least one of them changed config does
  the driver issue one consolidated restart (`suricata-restart.php`); an
  idempotent re-deploy restarts nothing. Each applier prints a fixed no-change
  line that the driver matches, so a reworded line errs toward an extra restart,
  never a stranded config. `SURU_SURICATA_RESTART=false` turns the restart off.
- **Pre-restart config test (opt-in).** With `SURU_SURICATA_TEST=auto|true`, the
  deploy runs `suricata -T` over each instance's generated yaml before the
  restart (`suricata-test-configs.php`). A failing test refuses the deploy with
  no restart and no revert: the running engines keep their previous config.
  On an inline deploy the dead-man's switch is re-armed to cover the test.
- **Rules rebuild.** `SURU_SURICATA_REBUILD=true` forces one deploy to rebuild
  the Suricata rules and restart, for engines left on a stale ruleset.
- **WAN-inline guard.** With `SURICATA_IPS_MODE=inline` the deploy refuses a
  `SURICATA_IFACES` entry equal to `WAN_IFACE` unless `SURU_ALLOW_WAN_INLINE=true`.
- **Dead-man's switch.** An inline deploy arms a router-side timer that reverts
  Suricata to legacy if the deploy does not disarm it. The disarm uses a fresh
  SSH connection, so it only cancels the timer when a new login still reaches
  the router. The timer does not survive a router reboot.
- **Privileged commands.** Every root-run command names its binary by full path;
  the allow-list and the per-account matrix are in
  [`privilege-matrix-pfsense.md`](./privilege-matrix-pfsense.md).
- **Secrets in staging.** The staging directory is created mode 700, cleared
  with sudo at the start of each deploy, and the client key, the backup
  passphrase file, the GeoIP/ASN secrets file and the AbuseIPDB-bearing importer
  are removed from it on success. Secret values are charset-checked
  (`lib/secrets.sh`) before they reach a sed substitution or a secrets file.
- **Hardware profile.** Values read back from `.hw-profile` are validated
  (integers, `<integer>mb` memcaps, `low|medium|high`) before they reach a root
  command. `SURU_HW_PROFILE` and `SURU_TIER1_BACKUP_DIR` relocate the profile and
  the local backup mirror.
- **Root CA location.** Every reader resolves the Root CA through `SURU_PKI_DIR`
  (default `tier4-operations/pki/certs`). With `SURU_PKI_PREISSUED=true` the
  deploy host needs only `root-ca.pem`: it verifies the pair in `TIER1_CERTS_DIR`
  (issued by `make gen-certs` on the PKI host) and never signs. Client
  certificates carry subject and authority key identifiers on every OpenSSL
  version.

---

## Platform Drivers

| Platform | File | Status |
|---|---|---|
| pfSense CE / Plus | `scripts/platforms/pfsense.sh` | Production |
| OPNsense 21+ | `scripts/platforms/opnsense.sh` | Scaffold |

To add a new platform, implement the five hooks in a new file under
`scripts/platforms/` and register it in `scripts/platforms/README.md`.
See [`DEPLOYMENT-ARCHITECTURE.md`](./DEPLOYMENT-ARCHITECTURE.md) §10.

---

## Zeek Protocol Analysis

Base protocol analysis (DNS, SSL, HTTP, conn, etc.) is **GUI-save resilient** via
`tier2-telemetry/zeek/scripts/suru-base.zeek`. That script is registered in
`installedpackages/zeekscript/config` in `config.xml`, so pfSense's
`zeek_script_resync()` always emits `@load suru-base` regardless of what else is
saved in Services > Zeek > Scripts.

The rendered `local.zeek` (deployed by `make deploy`) carries additional render-time
settings (`zeek_iface` label, capture filter). These are re-applied on `make deploy`
but are non-load-bearing if lost to a GUI save — losing them does not stop Zeek
from generating protocol logs.

**Intel path invariant:** the intel read path in `suru-base.zeek` is
`/usr/local/share/zeek/intel/suru-ioc.dat`. This must always match
`_PF_REMOTE_ZEEK_INTEL_DIR` in `scripts/platforms/pfsense.sh`. Never change
one without changing the other.

**Diagnosing missing Zeek logs:**
```bash
# Confirm base protocol loads are active on the router
ssh admin@gw.suru.local 'grep -c "suru-base" /usr/local/share/zeek/site/local.zeek'
ssh admin@gw.suru.local 'sudo zeekctl status'
ssh admin@gw.suru.local 'ls -la /var/log/zeek/'
# Restore if GUI save stripped local.zeek content (suru-base @load always survives)
make deploy
```

---

## syslog-ng Queue Monitoring

syslog-ng forwards all log sources to the Tier 3 SIEM via mTLS. A **hardware-adaptive
reliable disk-buffer** (`/var/db/syslog-ng-00000.rqf`, sized 1–8 GB by available disk —
default 4 GB — via the hardware preflight) absorbs messages when the SIEM is
unreachable and replays them automatically on reconnect. Position is tracked in
`/var/db/syslog-ng.persist` across restarts.

Run these directly on the router (`ssh admin@gw.suru.local 'sudo <cmd>'`):

### Check exact file-read positions (byte offset per source)

```bash
sudo persist-tool dump /var/db/syslog-ng.persist
```

Shows every tracked file source and its current byte offset — the position
syslog-ng resumes from on restart.

### Check disk-buffer queue state

```bash
sudo dqtool info /var/db/syslog-ng-00000.rqf
```

Shows number of messages queued, queue file size, and reliable (`.rqf`) mode
confirmation. A growing queue means the SIEM is not consuming; a draining queue
means delivery is caught up.

### Workstation check: per-file buffer report

```bash
make -C tier1-perimeter sng-buffer                      # human report
make -C tier1-perimeter sng-buffer ORPHAN_AGE_HOURS=48  # change the orphan threshold (default 24)
bash tier1-perimeter/scripts/syslog-ng-metrics.sh --buffer --json
```

The tool needs a root shell on the router over the deploy identity
(`sudo sh`); a restricted deploy account does not allow it. The `sng-*`
targets reach the router through `scripts/lib/ssh.sh`, so the lib's SSH
contract applies: `SSH_STRICT_HOST_KEY_CHECKING` takes `yes`, `accept-new` or
`no` and defaults to `yes` (`.env.example`); a router not yet in `known_hosts`
needs `accept-new` once.

The `DISK BUFFER` section prints one row per file matched by
`/var/db/syslog-ng-*.rqf` and `/var/db/syslog-ng-*.qf`:

| Token | Meaning |
|---|---|
| `Capacity (ceiling)` | Configured ceiling and where it was read: `/usr/local/etc/syslog-ng.conf capacity-bytes`, else `/usr/local/etc/suru/hw-profile.conf`, else `unknown — <reason>` |
| `✓` row | Live file (newest mtime): path, messages, size (and percent of ceiling when known), last write age |
| `⚠ ORPHAN?` row | Not the live file, not held open by syslog-ng (`held open: no`, or `unknown` when the open-file read failed), non-zero messages, and no write for longer than the threshold (`ORPHAN_AGE_HOURS`, default 24) |
| `-` row | Not the live file and not flagged as an orphan: syslog-ng holds it open, its last write is within the threshold, it holds 0 messages, or its age could not be read |
| `✗` row / `✗ <text>` line | A file or collection read failed; the text is the captured error. The row shows `✗` even when it is the live file or would otherwise be an orphan, and its count reads `messages unknown` |
| `held open: yes\|no\|unknown` | Whether the syslog-ng process has the file open (from `procstat -f`); `unknown` when that read could not be made |
| `Queue depth (live)` | `d_siem_tls` queued bytes and the live file's message count; `(messages unknown)` when the live file's count could not be read, `(no buffer file)` when no file exists |

`--json` emits one object. Under `buffer`: `messages_queued` and
`queue_file*` describe the live file only; `queue_ceiling_bytes` is `null`
when no ceiling could be read, with `queue_ceiling_source` set to
`syslog-ng.conf`, `hw-profile.conf` or `unknown`; `orphan_count` and
`orphan_age_threshold_seconds` summarise the orphan check; `files[]` lists
every file newest first (`path`, `type`, `messages`, `size_bytes`, `mtime`,
`age_seconds`, `held_open`, `live`, `orphan`, `error`); `collection_errors[]`
is empty when every read succeeded. A failed read is listed there, never
shown as zero: with no buffer file `files[]` is empty and `queue_file` is
`null`, and when the live file's count could not be read its
`files[].messages` is `null` and `collection_errors[]` carries
`live buffer message count unavailable`. `buffer.messages_queued` and
`lag.queued_messages` stay numeric and read `0` in those two cases, so check
those fields before trusting a `0`.

### Orphaned buffer files

An orphan has an older mtime, a non-zero `number_of_messages` and
`held open: no`, while the newest file is written continuously. A running
syslog-ng may not replay buffer files it does not hold open; if so, their
messages stay undelivered. Treat any non-live file with messages as a
candidate orphan, not as a known cause.

Cleanup is an operator action:

1. Run `make -C tier1-perimeter sng-buffer` and note the `ORPHAN?` rows.
2. Confirm the row shows `held open: no`. A row showing `held open: unknown`
   is still flagged: confirm on the router with
   `sudo procstat -f $(pgrep -x syslog-ng)` that the file is not open.
3. Decide delete vs replay; review the messages first, since a replay
   re-delivers them to the SIEM.
4. Delete only the unheld files, one by one, from `/var/db` on the router.
5. Re-run `make -C tier1-perimeter sng-buffer` and confirm only the live file
   remains and `Queue depth (live)` is unchanged.

### Workstation check: delivery lag

```bash
make -C tier1-perimeter sng-lag
```

The `DELIVERY LAG` section takes `Queued in buffer` from the live file's
`dqtool` count and the bytes in brackets from the `d_siem_tls#0` queued
counter of `syslog-ng-ctl stats`. When the count is known it prints
`<N> messages` and a write rate, plus a drain estimate when messages are
queued. When it is not known the line reads `unknown (<bytes>) ⚠` (buffer
files exist, live count unreadable) or `none — no buffer file found under
/var/db (<bytes>) ⚠`, `Drain` reads `buffer depth unknown — drain estimate
skipped`, and the collection errors print as `✗` lines.

### Router-side commands

```bash
# Enumerate buffer files
ls -l /var/db/syslog-ng-*.rqf /var/db/syslog-ng-*.qf

# Message count per file
for f in /var/db/syslog-ng-*.rqf; do echo "$f"; sudo dqtool info "$f"; done

# Configured capacity: rendered conf and hw profile
grep -o 'capacity-bytes([0-9]*)' /usr/local/etc/syslog-ng.conf
grep SYSLOGNG_DISK_BUFFER /usr/local/etc/suru/hw-profile.conf
```

### Check whether the SIEM destination host is reachable

```bash
# TCP reachability
nc -z syslog.suru.local 443 && echo UP || echo DOWN

# Full TLS + mTLS handshake (end-to-end cert verification)
sudo openssl s_client \
  -connect syslog.suru.local:443 \
  -cert /usr/local/etc/syslog-ng/tls/client.pem \
  -key  /usr/local/etc/syslog-ng/tls/client-key.pem \
  -CApath /usr/local/etc/syslog-ng/tls/ca \
  -verify_return_error \
  -brief 2>&1 | head -5
```

### Check live delivery rate

```bash
sudo syslog-ng-ctl stats | grep d_siem_tls
```

Key fields:

| Field | Meaning |
|---|---|
| `written` | Messages ACKed by the SIEM — should increase over time |
| `queued` | Bytes currently held in the disk-buffer |
| `dropped` | Messages lost — should always be 0 |
| `eps_last_1h` | Events/sec to SIEM over the last hour; 0 = SIEM down or idle |

`written` not increasing + `queued` growing = SIEM unreachable; disk-buffer
absorbing. `written` increasing + `queued` draining = caught up.

---

## pfSense Specifics

pfSense stores all configuration in `/conf/config.xml`. The pfSense driver:

- Uses `pfSsh.php playback svc <action> <service>` for native service control.
  Reference: https://docs.netgate.com/pfsense/en/latest/development/php-shell.html
- Flushes `/tmp/config.cache` and calls `parse_config(true)` during revert so
  pfSense reloads cleanly.
  Reference: https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html
- Uses `suricatasc -c reload-rules` for live Suricata rule reload without
  service restart.

---

## Certificate Trust Chain

```
SURU Root CA (tier4-operations/pki/certs/root-ca.pem)
  └── signs → Tier 1 syslog-ng client cert (tier1-perimeter/certs/tier1-<platform>-syslogng.pem)
                └── pushed to router at /usr/local/etc/syslog-ng/tls/
```

This gives syslog-ng mutual TLS authentication to the Tier 3 SIEM receiver
without a separate PKI per tier.

---

## Encrypted Pre-Deploy Backup

Every `make deploy` snapshots `/conf/config.xml` on the router BEFORE any
deploy step mutates it. The backup is encrypted on the router with the
platform's native helpers (AES-256-CBC + PBKDF2 sha256, 500_000 iterations
— same code path the GUI's "Encrypt this configuration file" checkbox
runs) and SCP-pulled to a local mirror. On any deploy-step failure an ERR
trap auto-restores from this backup.

Passwords are supplied via `SURU_BACKUP_PASSWORD` in `.env`. The env file
should be SOPS-encrypted. Deploy refuses to run without a password unless
`SURU_SKIP_BACKUP=true` is set — strongly discouraged.

Backup locations after a successful deploy:

- **Router**:  `/root/suru-backups/<platform>-config.xml.suru-<TIMESTAMP>.bak`
- **Local**:   `tier1-perimeter/backups/<platform>-config.xml.suru-<TIMESTAMP>.bak`

Both files are AES-256-encrypted. Decryption requires the password used
at deploy time.

## Revert Procedure

### Automatic (default)
If any deploy step fails after the backup completes, the driver's ERR and EXIT
traps call `_pf_revert` (pfSense) once; an interrupt (INT/TERM/HUP) after the
backup reverts the same way, and the deliberate refusals (the inline-flip arm
failure, the pre-restart config-test refusal) disarm the revert first. The
OPNsense driver uses `_opn_revert`. The revert:
1. SCP-pushes the local mirror back to the router if the on-router copy
   was lost.
2. Decrypts and atomically restores `/conf/config.xml`.
3. Flushes `/tmp/config.cache`, calls `parse_config(true)`.
4. Restarts affected services: syslog-ng always, Suricata only when this deploy
   already restarted it (the appliers run without `--restart`, so otherwise the
   running engines still hold their pre-deploy config and are left alone).

### Manual — GUI (easiest)
Both platforms accept the SURU backup format in their native restore UI:
- **pfSense**:  Diagnostics → Backup & Restore → Restore Configuration
                → check "Configuration file is encrypted" → supply
                `SURU_BACKUP_PASSWORD` → upload the `.bak` file.
- **OPNsense**: System → Configuration → Backups → Restore (encrypted).

### Manual — CLI (when GUI is unreachable)
```bash
# Copy the encrypted backup to the router staging dir.
scp tier1-perimeter/backups/<file>.bak admin@<ROUTER_HOST>:/tmp/suru-staging/

# Write the password to a 0600 file under /tmp.
ssh admin@<ROUTER_HOST> "umask 077; cat > /tmp/suru-staging/.suru-bkpass"
# (type the password, then ctrl-D)

# Decrypt + restore (atomic; verifies decrypted payload is a sane config).
ssh admin@<ROUTER_HOST> "sudo php tier1-perimeter/pfsense/backup-restore.php \
  /tmp/suru-staging/.suru-bkpass \
  /tmp/suru-staging/<file>.bak"

# Restart services.
ssh admin@<ROUTER_HOST> "pfSsh.php playback svc restart syslog-ng"
ssh admin@<ROUTER_HOST> "pfSsh.php playback svc restart suricata"
```

---

## For Future AI Sessions

When working on Tier 1 in a new AI thread:

1. Read `docs/DEPLOYMENT-ARCHITECTURE.md` for full design context.
2. Inspect `scripts/platforms/pfsense.sh` as the reference driver.
3. Use `scripts/platforms/opnsense.sh` as the extension template.
4. The five platform hook functions are the extension contract — do not
   change their names or signatures without updating both drivers and
   `DEPLOYMENT-ARCHITECTURE.md`.
5. All new SSH/SCP calls must go through `lib/ssh.sh` helpers.
6. All new cert operations must go through `lib/certs.sh`.
7. Never add platform-specific logic to `scripts/deploy.sh`.
