# Contributing to suru-foss

Thank you for helping improve SURU. This project is community-driven and licensed
under the **Mozilla Public License 2.0**. Contributions of any size are welcome:
detection rules, pipeline fixes, dashboards, documentation, and new tier features.

By submitting a contribution you agree it is licensed under the MPL-2.0 (the
license of this repository).

---

## Ground rules

- **Every change lands through a Pull Request.** Direct pushes to `main` are not
  accepted — `main` is protected.
- **Keep changes scoped to one tier where possible.** The four-tier layout is
  load-bearing; new capabilities go *inside* the tier they belong to.
- **A change is not complete until its docs are updated** in the same PR (tier
  `README.md`, tier `docs/`, and `.env.example` for any new variable).
- **No secrets, ever.** No `.env`, `*-key.pem`, private keys, real hostnames, or
  credentials in commits. `.gitignore` enforces the common cases — double-check
  your diff.

---

## Workflow

1. **Fork** the repository and clone your fork.
2. **Branch** from `main`:
   ```bash
   git switch main
   git switch -c feature/<short-name>      # or fix/<short-name>, docs/<short-name>
   ```
3. **Make your change** following the standards below.
4. **Verify locally** (see "Verification" — match what CI runs).
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   ```text
   feat(tier3): add ssh brute-force sigma rule
   fix(tier1): correct zeek capture interface default
   docs: clarify frontdoor SNI routing
   ```
   Prefix with `BREAKING CHANGE:` when you alter an API, schema, or container interface.
   Sign off every commit with `git commit -s` (Developer Certificate of Origin) to certify you may contribute it under the MPL-2.0.
6. **Open a PR** against `main`. Fill in the PR template. Link any related issue.

### Branch strategy

```text
main (protected, release state)
  ├── feature/<name>
  ├── fix/<name>
  └── release/<version>
```

### PR requirements (merge gate)

A PR can merge once:

- [ ] **CI is green** (lint → test → scan — see `.github/workflows/ci.yml`).
- [ ] **A CODEOWNER has approved** (see `.github/CODEOWNERS`). Branch protection on
      `main` should enable *Require review from Code Owners*.
- [ ] **Docs updated** for any changed workflow, config, script, or new env var.
- [ ] **No secrets** in the diff.
- [ ] Commit messages follow Conventional Commits. Signed commits (`--gpg-sign`)
      are encouraged for security-sensitive changes.

---

## Standards by file type

| You're touching | Run before pushing | Notes |
|-----------------|--------------------|-------|
| `*.sh` | `bash -n <file>` and `shellcheck --severity=warning <file>` | `#!/usr/bin/env bash`, `set -euo pipefail`, quote expansions, `--dry-run`/`--verbose` flags, mode `755`. |
| `compose.yaml` | `docker compose -f <file> config` | v2 syntax, `restart: unless-stopped`, healthcheck, json-file logging w/ limits, resource limits, pinned images. |
| Container images | — | Non-root `user:`, `cap_drop: [ALL]` + selective `cap_add`, `security_opt: [no-new-privileges:true]`, `read_only` where feasible. **Never** mount `docker.sock`. |
| `*.tf` / `*.tfvars` | `terraform validate && terraform fmt -check` | Pin provider/module versions. |
| Suricata/Snort rules | `suricata -T -S <file>` | Annotate with MITRE ATT&CK `TA####`/`T####`. |
| Sigma rules | `sigma check <file>` | Map to ATT&CK; note false-positive sources. |
| Zeek scripts | `zeek -s <file>` | — |
| OpenSearch dashboards (`*.ndjson`) | JSON-parse every line; `deploy.sh reimport` returns HTTP 200 | Follow the rules in `tier3-core/config/opensearch/dashboards/README.md` (canonical index patterns, ECS field canon, MITRE annotations, `timeRestore`). |

**Container / identifier naming:** containers `suru.t<N>.*`; networks, volumes,
and hostnames `suru-t<N>-*`, where `<N>` is the tier number.

**Logging:** all event output normalises to **ECS v8**. `@timestamp` must be the
event's own time (parsed from the log), never the ingest time.

---

## Verification

CI runs lint (shellcheck, `docker compose config`), the Go test/SAST gates (inert
until Go code exists), and security scans (Trivy, semgrep). Reproduce the core
checks locally:

```bash
find . -name '*.sh' -print0 | xargs -0 shellcheck --severity=warning
find . \( -name 'compose.yaml' -o -name 'docker-compose*.y*ml' \) -print0 \
  | xargs -0 -I{} docker compose -f {} config >/dev/null
```

Do not claim a change works without evidence — paste the command output (or say
explicitly what you could not verify and what the maintainer should run).

---

## Roadmap

The four tiers are stable; these are the active expansion areas where help is
especially welcome:

- **Tier 4 operations plane** — orchestrator service, content/ruleset manager,
  alert curator, and an OIDC/oauth2-proxy auth option for the frontdoor.
- **More detection content** — additional ATT&CK-mapped Sigma rules and Suricata
  rule-selection profiles for SOHO threat models.
- **More dashboards** — new OpenSearch saved-object dashboards for additional data
  sources.
- **Additional ingest sources** — new Logstash pipelines (each must normalise to
  ECS v8 and resolve `@timestamp` to event time).

Open a discussion or issue before starting large work so we can align on approach.

---

## Reporting bugs and requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For **security
vulnerabilities**, do not open a public issue — follow [SECURITY.md](./SECURITY.md).
