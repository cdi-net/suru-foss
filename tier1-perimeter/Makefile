# =============================================================================
# SURU Platform — tier1-perimeter Makefile
# Targets: render, deploy, deploy-full, clean, api-health, api-validate,
#          api-install-pfrest, api-reload-rules, api-bootstrap
#
# Usage:
#   make render                       # merge T2 intel into T1 templates
#   make deploy PLATFORM=pfsense      # preflight -> render -> push to device
#   make deploy-full PLATFORM=pfsense # render + deploy in one step
#   make clean                        # remove rendered/ directory
#   make gen-certs                    # issue the Tier 1 syslog-ng mTLS client pair from the existing Root CA
#   make test                         # run render pipeline tests and the Tier 1 suites
#   make api-health                   # probe router REST API
#   make api-validate                 # validate post-deploy service state via API
#   make api-install-pfrest           # one-shot: install pfRest on pfSense
#   make api-reload-rules             # incremental Suricata rules reload via API
#   make api-bootstrap [ADMIN_USER=admin]  # one-shot: create suru-validator + issue API key
#
# Environment:
#   Variables are loaded automatically from tier1-perimeter/.env if it exists.
#   Copy .env.example -> .env and fill in real values. Never commit .env.
#   Command-line overrides (e.g. ROUTER_HOST=x make deploy) always win.
# =============================================================================

SHELL := /bin/bash

# ---------------------------------------------------------------------------
# Auto-load .env from the same directory as this Makefile.
# ?= assignments below will NOT override variables already set in the
# environment or on the make command line — correct precedence is preserved.
# ---------------------------------------------------------------------------
ENV_FILE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/.env
-include $(ENV_FILE)
export

# Map .env key ROUTER_PLATFORM -> Makefile variable PLATFORM
# (ROUTER_PLATFORM in .env, PLATFORM as the Makefile/script flag)
ifdef ROUTER_PLATFORM
PLATFORM ?= $(ROUTER_PLATFORM)
endif
PLATFORM ?= pfsense
# RENDER_DRY_RUN: skip writing rendered files (default false).
RENDER_DRY_RUN ?= false
# DRY_RUN (legacy alias): sets RENDER_DRY_RUN and passes --dry-run to deploy.sh.
# deploy.sh itself decides whether to dry-run based on ROUTER_HOST at runtime.
ifdef DRY_RUN
RENDER_DRY_RUN := $(DRY_RUN)
endif
VERBOSE ?= false

REPO_ROOT := $(shell git rev-parse --show-toplevel)
# SURU_PKI_DIR: directory holding the SURU Root CA (root-ca.pem, root-ca-key.pem);
# the one variable every Tier 1 reader of the CA path resolves.
SURU_PKI_DIR ?= $(REPO_ROOT)/tier4-operations/pki/certs
export SURU_PKI_DIR
T2_RENDER  := $(REPO_ROOT)/tier2-telemetry/build/render.sh
DEPLOY     := $(REPO_ROOT)/tier1-perimeter/scripts/deploy.sh
TESTS      := $(REPO_ROOT)/tier2-telemetry/build/tests/test-render.sh
HW_PREFLIGHT := $(REPO_ROOT)/tier1-perimeter/scripts/hw-preflight.sh

API_LIB   := $(REPO_ROOT)/tier1-perimeter/scripts/lib/api.sh

SNG_METRICS := $(REPO_ROOT)/tier1-perimeter/scripts/syslog-ng-metrics.sh
VERIFY_PFB  := $(REPO_ROOT)/tier1-perimeter/scripts/verify-pfblockerng-feeds.sh

.PHONY: render deploy deploy-full gen-certs preflight clean test \
        api-health api-validate api-install-pfrest api-reload-rules api-bootstrap \
        sng-metrics sng-status sng-buffer sng-lag verify-pfblockerng

# preflight: detect router hardware and write tier1-perimeter/.hw-profile
# Best-effort — never fails the pipeline; render reads .hw-profile if present.
preflight:
	@echo "[suru] Running hardware preflight for platform: $(PLATFORM)"
	@bash $(HW_PREFLIGHT) --platform $(PLATFORM) $(if $(filter true,$(VERBOSE)),--verbose,) || true

render:
	@echo "[suru] Rendering T2 intelligence into T1 templates for platform: $(PLATFORM)"
	@bash $(T2_RENDER) --platform $(PLATFORM) $(if $(filter true,$(RENDER_DRY_RUN)),--dry-run,) $(if $(filter true,$(VERBOSE)),--verbose,)

deploy: preflight render
	@echo "[suru] Deploying rendered artefacts to $(PLATFORM) device..."
	@bash $(DEPLOY) --platform $(PLATFORM) $(if $(filter true,$(DRY_RUN)),--dry-run,) $(if $(filter true,$(VERBOSE)),--verbose,)

deploy-full: deploy
	@echo "[suru] Deploy-full complete for $(PLATFORM)."

# gen-certs: issue the Tier 1 syslog-ng mTLS client pair from the existing Root
# CA (idempotent: skips a pair that verifies). Run on the PKI host; it never
# creates a CA. A deploy host that does not hold the CA key runs with
# SURU_PKI_PREISSUED=true and TIER1_CERTS_DIR pointing at the pair issued here.
gen-certs:
	@echo "[suru] Issuing the Tier 1 client cert (idempotent)"
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/gen-certs.sh $(if $(filter true,$(DRY_RUN)),--dry-run,) $(if $(filter true,$(VERBOSE)),--verbose,)

clean:
	@echo "[suru] Removing rendered/ artefacts (preserving .gitkeep)"
	@find $(REPO_ROOT)/tier1-perimeter/rendered/ -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true

test:
	@bash $(TESTS) $(if $(filter true,$(VERBOSE)),--verbose,)
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-exit-trap-cleanup.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-rotation-native-owner.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-secrets.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-ssh.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-safety-timer.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-sudo-allowlist.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-suricata-test-gate.sh
	@bash $(REPO_ROOT)/tier1-perimeter/pfsense/tests/test-suricata-test-configs.sh
	@bash $(REPO_ROOT)/tier1-perimeter/pfsense/tests/test-suricata-tuning-apply.sh
	@bash $(REPO_ROOT)/tier1-perimeter/pfsense/tests/test-suricata-rebuild-rules-flag.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-certs-preissued.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-pki-dir-norepo.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/tests/test-deploy-rendered-dir.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/lib/tests/test-opnsense-localzones-stage.sh
	@bash $(REPO_ROOT)/tier1-perimeter/opnsense/tests/test-unbound-localzones.sh
	@bash $(REPO_ROOT)/tier1-perimeter/scripts/tests/test-syslog-ng-metrics.sh

# ---------------------------------------------------------------------------
# REST API targets — source lib/api.sh and dispatch on ROUTER_PLATFORM
# ---------------------------------------------------------------------------
api-health:
	@echo "[suru] API health probe — platform: $(PLATFORM)"
	@bash -c 'source "$(API_LIB)" && ROUTER_PLATFORM="$(PLATFORM)" api_health \
	  && echo "[suru] API health: OK" \
	  || { echo "[suru] API health: FAILED"; exit 1; }'

api-validate:
	@echo "[suru] API post-deploy validation — platform: $(PLATFORM)"
	@bash -c 'source "$(API_LIB)" && ROUTER_PLATFORM="$(PLATFORM)" api_validate_deployment'

api-install-pfrest:
	@[[ "$(PLATFORM)" == "pfsense" ]] || { echo "api-install-pfrest is pfSense-only (PLATFORM=$(PLATFORM))"; exit 1; }
	@echo "[suru] Installing pfRest on pfSense router..."
	@bash -c 'source "$(API_LIB)" && ROUTER_PLATFORM=pfsense api_pfsense_install'

api-reload-rules:
	@echo "[suru] Incremental Suricata rules reload via API — platform: $(PLATFORM)"
	@bash -c 'source "$(API_LIB)" && ROUTER_PLATFORM="$(PLATFORM)" api_reload_suricata_rules'

api-bootstrap:
	@[[ "$(PLATFORM)" == "pfsense" ]] \
	  || { echo "[suru] api-bootstrap is pfSense-only (PLATFORM=$(PLATFORM))"; exit 1; }
	@echo "[suru] Bootstrapping suru-validator API user on pfSense (one-shot)..."
	@echo "[suru] Prerequisite: pfRest must be installed (run 'make api-install-pfrest' first)."
	@echo "[suru] Uses ROUTER_SSH_KEY from .env — no additional password required."
	@bash -c 'source "$(API_LIB)" && api_pfsense_bootstrap_validator $(ADMIN_USER)'

# ---------------------------------------------------------------------------
# syslog-ng telemetry  (SSH to router — no deploy required)
# ---------------------------------------------------------------------------
sng-metrics:
	@bash $(SNG_METRICS) $(if $(filter true,$(VERBOSE)),--verbose,)

sng-status:
	@bash $(SNG_METRICS) --status $(if $(filter true,$(VERBOSE)),--verbose,)

sng-buffer:
	@bash $(SNG_METRICS) --buffer $(if $(ORPHAN_AGE_HOURS),--orphan-age-hours $(ORPHAN_AGE_HOURS),) $(if $(filter true,$(VERBOSE)),--verbose,)

sng-lag:
	@bash $(SNG_METRICS) --lag $(if $(filter true,$(VERBOSE)),--verbose,)

# ---------------------------------------------------------------------------
# pfBlockerNG feed validation — cross-checks live config.xml against
# /var/db/pfblockerng/{deny,dnsbl,dnsblorig}/ on the router
# ---------------------------------------------------------------------------
verify-pfblockerng:
	@bash $(VERIFY_PFB) $(if $(filter true,$(VERBOSE)),--verbose,)
