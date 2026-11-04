# edge-plane operator targets.
#
# Bespoke Makefile (data-plane/obs-plane pattern), NOT make/common.mk:
# edge-plane pulls rather than builds (its one Python script, the auth-audit
# exporter, runs as-is on a pulled python image) and adds
# user/ca-export/smoke targets common.mk does not model. It adopts the
# shared airgap bundle library (scripts/bundle-lib.sh, CI drift-checked)
# via scripts/bundle_images.sh.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

EDGE_NET ?= $(or $(strip $(shell test -f .env && grep -E '^EDGE_NET=' .env | cut -d= -f2)),edge-net)

# External named volumes this project owns. Keep in sync with docker/compose.yaml.
# `make nuke` destroys VOLUMES only: auth-audit keeps its export position, so a
# replaced Authelia database is recorded in the audit trail (docs/audit.md).
VOLUMES := edge-state edge-ca
AUDIT_VOLUMES := edge-audit-state

COMPOSE     := docker compose --env-file .env -f docker/compose.yaml
COMPOSE_DEV := docker compose --env-file .env -f docker/compose.yaml -f docker/compose.override.yaml

.PHONY: help network volumes pull bundle up up-dev stop down restart ps logs health nuke user secret totp ca-export smoke

help:
	@echo "edge-plane — the federation's edge gateway (Caddy + Authelia)."
	@echo
	@echo "Lifecycle:"
	@echo "  make network    create external $(EDGE_NET) if missing"
	@echo "  make volumes    create the external edge volumes if missing"
	@echo "  make pull       pull all images from the registries"
	@echo "  make bundle     save images as a versioned airgap tarball"
	@echo "  make up         start (production shape — :443/:80/:8443 only)"
	@echo "  make up-dev     like 'up', plus the whoami header-echo upstream"
	@echo "  make stop       stop containers without removing them"
	@echo "  make down       stop + remove containers (volumes preserved)"
	@echo "  make restart    down + up"
	@echo "  make nuke       DESTROY auth state + CA volumes (interactive; not the audit export position)"
	@echo
	@echo "Operations:"
	@echo "  make ps         service status"
	@echo "  make health     caddy + authelia readiness, auth-audit export"
	@echo "  make logs S=caddy   tail logs for one service"
	@echo "  make user       hash a password for authelia/users.yml"
	@echo "  make secret     generate a random secret for .env"
	@echo "  make totp U=<user> [FORCE=1]  provision a user's TOTP second factor (prints the otpauth URI;"
	@echo "                 needs the running stack, recorded in the audit trail)"
	@echo "  make ca-export  write the internal CA root to edge-ca-root.crt"
	@echo "  make smoke      end-to-end auth/header checks (needs up-dev)"

network:
	@docker network inspect $(EDGE_NET) >/dev/null 2>&1 \
	  || (echo ">> creating external network $(EDGE_NET)" && docker network create $(EDGE_NET))

volumes:
	@for v in $(VOLUMES) $(AUDIT_VOLUMES); do \
	  docker volume inspect $$v >/dev/null 2>&1 \
	    || (echo ">> creating external volume $$v" && docker volume create $$v >/dev/null); \
	done

pull:
	$(COMPOSE) pull

bundle:
	./scripts/bundle_images.sh

up: network volumes
	@test -f authelia/users.yml || { echo "authelia/users.yml missing — cp authelia/users.template.yml authelia/users.yml and edit"; exit 1; }
	$(COMPOSE) up --no-build -d

up-dev: network volumes
	@test -f authelia/users.yml || { echo "authelia/users.yml missing — cp authelia/users.template.yml authelia/users.yml and edit"; exit 1; }
	$(COMPOSE_DEV) up --no-build -d

stop:
	$(COMPOSE) stop

down:
	$(COMPOSE) down --remove-orphans

restart: down up

nuke:
	@echo "This will DESTROY all edge-plane volumes (auth DB — TOTP secrets, user preferences; internal CA):"
	@for v in $(VOLUMES); do echo "  - $$v"; done
	@echo "auth-audit's export position is kept: $(AUDIT_VOLUMES)"
	@read -p "Type 'nuke' to confirm: " confirm && [ "$$confirm" = "nuke" ] \
	  || (echo "aborted"; exit 1)
	$(COMPOSE) down --remove-orphans
	@for v in $(VOLUMES); do \
	  docker volume rm $$v >/dev/null 2>&1 && echo "  removed $$v" || true; \
	done

ps:
	$(COMPOSE) ps

health:
	@$(COMPOSE) ps --format '{{.Name}}\t{{.State}}\t{{.Status}}'
	@echo
	@$(COMPOSE) exec -T caddy wget -qO- http://127.0.0.1:2019/config/ >/dev/null && echo "caddy: ready"
	@$(COMPOSE) exec -T caddy wget -qO- http://authelia:9091/auth/api/health >/dev/null && echo "authelia: ready"
	@$(COMPOSE) exec -T auth-audit python /app/edge_audit.py health && echo "auth-audit: exporting the authentication log"

logs:
ifndef S
	$(COMPOSE) logs --tail=200 -f
else
	$(COMPOSE) logs --tail=200 -f $(S)
endif

user:
	@test -f authelia/users.yml || { echo "authelia/users.yml missing — cp authelia/users.template.yml authelia/users.yml and edit"; exit 1; }
	$(COMPOSE) run --rm --no-deps authelia authelia crypto hash generate argon2

secret:
	@test -f authelia/users.yml || { echo "authelia/users.yml missing — cp authelia/users.template.yml authelia/users.yml and edit"; exit 1; }
	$(COMPOSE) run --rm --no-deps authelia authelia crypto rand --length 64

# Second factors are provisioned by an admin, never enrolled through the
# portal (docs/user-accounts.md#second-factor). Prints the otpauth:// URI,
# which contains the secret: hand it to the user in person. FORCE=1 replaces
# an existing registration (lost device). Needs the stack running: the change
# is recorded as an admin event by auth-audit, and refused when it cannot be
# (scripts/audit-admin.sh, docs/audit.md).
totp:
	@test -n "$(U)" || { echo "usage: make totp U=<username> [FORCE=1]"; exit 1; }
	@COMPOSE='$(COMPOSE)' ./scripts/audit-admin.sh account.totp '$(U)' force=$(if $(FORCE),true,false) -- \
	  $(COMPOSE) exec authelia sh -c 'authelia storage user totp generate "$$1" --issuer "$$EDGE_HOST" --config /config/configuration.yml $(if $(FORCE),--force,)' _ '$(U)'

ca-export:
	@$(COMPOSE) exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > edge-ca-root.crt
	@echo "Wrote edge-ca-root.crt — distribute to LAN browsers (see docs/tls-runbook.md)."

smoke:
	./scripts/smoke.sh
