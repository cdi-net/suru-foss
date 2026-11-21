# pfSense privilege matrix

The privilege matrix for the pfSense driver (`scripts/platforms/pfsense.sh`),
maintained with that driver. It lists every router-side account SURU uses, the
channel it uses, and for each need the command it takes and whether that command
runs as root. A driver change that adds a privileged binary updates this file in
the same change.

Access is least privilege per channel. The OPNsense driver is a scaffold and has
no matrix yet.

---

## 1. Accounts

| Account | Channel | Purpose |
|---|---|---|
| deploy account (for example `suru-deploy`) | SSH, key-only | the Tier 1 deploy (`_platform_deploy`); its sudo surface is section 2 |
| `suru-validator` | pfREST, API key | post-deploy validation (`PFSENSE_API_KEY`); created by `make api-bootstrap`; holds `page-all`, because pfREST v2 has no narrower page grant that covers every call the validation makes |
| operator admin | GUI / SSH | bootstrap only: install pfREST (`make api-install-pfrest`, which runs `pkg-static`, not on the deploy allow-list) and run `make api-bootstrap` |

Rules for every account:

- Dedicated: never shared with a person or with another account's channel.
- Key-only SSH, with `no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty`
  on the key line.
- API keys rotated regularly (`make api-bootstrap` is idempotent and issues a fresh key).

---

## 2. Deploy account: need, command, sudo

Every remote command that runs as root is invoked by full path through a driver
constant (`_PF_BIN_<NAME>` in `pfsense.sh`, `SAFETY_BIN_<NAME>` in
`lib/safety-timer.sh`, `_HW_BIN_<NAME>` in `lib/hw-preflight.sh`), so the sudoers
list can name each binary. A drift test
(`scripts/lib/tests/test-sudo-allowlist.sh`) keeps the constants and the sudoers
block below equal.

| # | Need | Command on the router | sudo | Where |
|---|---|---|---|---|
| D1 | hardware detection | `sysctl -n hw.ncpu hw.physmem`, `df -k /` | no | `hw_detect_hardware` |
| D2 | write the hardware profile | `mkdir`, `mv` from staging, `chmod 644` into `/usr/local/etc/suru/hw-profile.conf` | yes | `hw_preflight_run` |
| D4 | staging directory | `rm -rf` (root-owned leftovers), `mkdir`, `chmod 700` of the staging directory | rm: yes | `_platform_deploy` (staging setup) |
| D5 | encrypted config backup and pull | `mkdir`, `chmod 700` of the backup directory; `php backup-encrypt.php`; `cp` to staging; `chmod 644`; `rm -f` | yes | `_pf_backup` |
| D6 | revert (ERR and EXIT traps) | `test -r`, `cp`, `chmod`, `php backup-restore.php`; `pfSsh.php playback svc restart` for syslog-ng and, when this deploy restarted it, suricata | yes (`pfSsh.php` is on the list) | `_pf_revert` |
| D7 | syslog-ng mTLS material | `mkdir`, `cp`, `chmod` under the syslog-ng `tls` and `tls/ca` directories; `openssl rehash`; `ln -sf` of the CA to its hash name | yes | cert install in `_platform_deploy` |
| D8 | syslog-ng configuration | `php syslog-ng-apply.php` | yes | `pfsense/syslog-ng-apply.php` |
| D9 | Suricata rules, tuning, log management, drop policy, restart | `php suricata-{rules,tuning,logmgmt,drop-policy}-apply.php`, `php suricata-restart.php` | yes | `pfsense/suricata-*.php` |
| D10 | Suricata config test (opt-in, `SURU_SURICATA_TEST`) | `php suricata-test-configs.php` (runs `suricata -T` as root) | yes | `pfsense/suricata-test-configs.php` |
| D11 | inline safety timer | `daemon -f -p <pidfile> /bin/sh <revert script>` (runs from the account-owned safety directory); `pkill -F`; `rm -rf` of the safety directory | yes | `safety_timer_arm`, `safety_timer_disarm` |
| D12 | pf and unbound tuning | `php pf-tuning-apply.php`, `php dns-tuning-apply.php` | yes | `pfsense/*-tuning-apply.php` |
| D13 | Zeek scripts, intel, site files, `zeekctl.cfg`, interface, activation | `mkdir`, `cp`; `php zeek-scripts-apply.php`, `php zeek-iface-apply.php`; `zeekctl deploy` | yes | `pfsense/zeek-*.php` |
| D14 | unbound local zones | `php unbound-localzones-apply.php`; `rm -f` | yes | `pfsense/unbound-localzones-apply.php` |
| D15 | newsyslog drop-ins | `cp`, `chmod 644`; `newsyslog -nvf`; `rm -f` on a failed verdict | yes | `_pf_install_newsyslog_dropin` |
| D16 | pfBlockerNG import and globals | `chmod 600`; `php import-pfblockerng.php`, `php pfblockerng-globals-apply.php`; `rm -f` | yes | `pfsense/pfblockerng-*.php` |
| D17 | XML state verification | `php verify-xml-state.php` (staged like the other appliers) | yes | `_pf_verify_xml_state` |
| D18 | pfREST installation | `pkg-static add` through `api_pfsense_install` in `lib/api.sh` | outside the list | `api_pfsense_install` |
| D19 | post-deploy validation | pfREST reads, only when `PFSENSE_API_KEY` is set | API | `api_validate_deployment` |

D18 is not part of the allow-list below: a deploy account restricted to that
list cannot install pfREST. Install it once with an admin account
(`make api-install-pfrest ROUTER_SSH_USER=<admin account> ROUTER_SSH_KEY=<admin key>`)
and set `SURU_SKIP_API_INSTALL=true` for the restricted account.

After a successful deploy the secret material is removed from staging
(`client-key.pem`, the encrypted-backup passphrase file, `pfb-ipconfig.secrets`,
`import-pfblockerng.php`); the rest of staging stays for the next deploy's
clean-slate removal.

### 2a. The sudoers allow-list

The deploy account may run these 14 binaries as root with No Password, and
nothing else. `pkg-static` and `sh` are not on the list; `pfSsh.php` is.

```sudoers
Cmnd_Alias SURU_DEPLOY = \
  /usr/local/bin/php, \
  /bin/cp, \
  /bin/mkdir, \
  /bin/chmod, \
  /bin/rm, \
  /bin/mv, \
  /bin/ln, \
  /usr/bin/openssl, \
  /bin/test, \
  /usr/sbin/newsyslog, \
  /usr/local/bin/zeekctl, \
  /usr/sbin/daemon, \
  /bin/pkill, \
  /usr/local/sbin/pfSsh.php
```

The pfSense `sudo` package takes the same list through its GUI form
(System > sudo > Add): User the deploy account, Run As `root`, **No Password**
checked, and a **Commands** field holding the 14 paths comma-separated:

```
/usr/local/bin/php,/bin/cp,/bin/mkdir,/bin/chmod,/bin/rm,/bin/mv,/bin/ln,/usr/bin/openssl,/bin/test,/usr/sbin/newsyslog,/usr/local/bin/zeekctl,/usr/sbin/daemon,/bin/pkill,/usr/local/sbin/pfSsh.php
```

The remote login shell for a non-root account is tcsh, so the driver runs
`sudo /bin/test ! -f <path>` rather than a shell conditional, and never
`sudo sh -c`.

### 2b. Root-equivalent by construction

**The deploy account is root-equivalent on pfSense.** Every applier is uploaded
by the account into a staging directory it owns and then run as
`sudo /usr/local/bin/php <applier>`; the safety timer has root run a script
from a directory the account owns. Whoever holds the deploy key can therefore
run any PHP as root, whatever the sudoers list says. The allow-list still has
value: it documents the deploy surface, removes `ALL` (no `su`, no interactive
shell, no `pfctl`, no `passwd`), and makes a driver change that adds a
privileged binary visible in review. It is not a security boundary against the
holder of the key. Protecting the key (dedicated account, `from=` restriction)
is the control.

---

## 3. Verification

- **Binary paths.** As the deploy account, feed `sh -s` a loop over the section
  2a paths that prints `OK` or `MISSING` for each `[ -x <path> ]` (the login
  shell of a non-root account is tcsh, hence `sh`; `command -v test` names the
  shell builtin, so test the paths, not the names). A path that differs is
  corrected in the driver constants, this block and the drift test in one
  change. Re-run after a pfSense major upgrade and on each new router.
- **Service restart without sudo.** `pfSsh.php playback svc restart` fails for a
  non-root account without sudo, which is why the revert bounce carries the sudo
  prefix.

## 4. Maintenance

- A driver change that adds or removes a root-run binary updates the constants,
  section 2a and `scripts/lib/tests/test-sudo-allowlist.sh` together.
- The first line of the fenced `sudoers` block is `Cmnd_Alias SURU_DEPLOY = \`
  and each following line is one path; the drift test parses exactly that
  block, so keep the format.
