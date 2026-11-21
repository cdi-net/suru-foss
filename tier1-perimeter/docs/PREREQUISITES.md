# SURU Tier 1 — pfSense Prerequisites

These steps must be completed **once** in the pfSense GUI before running
`make deploy` for the first time. They are manual by design — Netgate does
not expose package installation or sudo configuration via unauthenticated SSH.

---

## 1. Create the deploy SSH user

**System > User Manager > Add**

| Field | Value |
|---|---|
| Username | `done` (or your chosen deploy user) |
| Password | strong password or leave blank if key-only |
| Groups | `admins` |
| Effective Privileges | `User - System: Shell account access` |
| Authorized SSH Keys | paste the public key from `~/.ssh/id_ed25519.pub` (or the key set in `.env` as `ROUTER_SSH_KEY`) |

> **Why `admins` group?**  
> pfSense's default `admins` group is already configured by the sudo package
> as the target for privilege delegation. Adding the deploy user to `admins`
> means the sudo rule created in Step 3 works without naming the user explicitly.

---

## 2. Install the sudo package

Netgate's official mechanism for non-root SSH users to run administrative
commands. Reference: <https://docs.netgate.com/pfsense/en/latest/packages/sudo.html>

**System > Package Manager > Available Packages**

Search for **sudo** → click **Install** → confirm.

---

## 3. Configure the sudo rule

**System > sudo > Add**

| Field | Value | Notes |
|---|---|---|
| User/Group | Group: `admins` | Covers all members of admins group |
| Run As | User: `root` | Elevate to root |
| No Password | **Checked** | **Mandatory** — deploy script is non-interactive (no TTY, no prompt) |
| Commands | `ALL` | Full admin access for the deploy user |

Click **Save**.

> **Security note:** `NOPASSWD ALL` for the `admins` group is Netgate's own
> documented example for automation use cases. The deploy user's SSH access
> is already restricted to key-only authentication, which limits the attack
> surface. If a narrower command set is preferred, the pfSense driver names
> every root-run binary by full path: replace `ALL` with the 14-path allow-list
> in [the pfSense privilege matrix](./privilege-matrix-pfsense.md) section 2a, and
> set `SURU_SKIP_API_INSTALL=true` (pfREST installation needs `pkg-static`,
> which is not on that list).

---

## 4. Verify SSH key authentication

Ensure `SSHd Key Only` is set to **Public Key Only**:  
**System > Advanced > Admin Access > SSHd Key Only**

---

## 5. Smoke-test from your local machine

```bash
ssh -i <ROUTER_SSH_KEY> <ROUTER_SSH_USER>@<ROUTER_HOST> 'sudo id'
# Expected output: uid=0(root) gid=0(wheel) groups=0(wheel),...
```

If this returns `uid=0(root)` without a password prompt, the prerequisites
are complete and `make deploy` will succeed.

---

## 6. Certificates (first deploy only)

Generate the mTLS certificate bundle before deploying:

```bash
make gen-certs
```

This creates the CA, client cert, and key under `certs/` (excluded from git
via `.gitignore`). The `deploy.sh` script copies these to the router during
`platform_deploy`.

---

## Summary checklist

- [ ] Deploy user created in System > User Manager, added to `admins` group
- [ ] `User - System: Shell account access` privilege assigned
- [ ] SSH public key uploaded to the user account
- [ ] `sudo` package installed via System > Package Manager
- [ ] sudo rule: Group `admins`, Run As `root`, **No Password checked**, Commands ALL
- [ ] SSHd Key Only set to Public Key Only
- [ ] Smoke-test: `ssh ... 'sudo id'` returns `uid=0(root)` with no prompt
- [ ] `make gen-certs` run at least once
