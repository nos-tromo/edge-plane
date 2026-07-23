# edge-plane operator targets.
#
# Bespoke Makefile (data-plane/obs-plane pattern), NOT make/common.mk:
# edge-plane pulls rather than builds, has no Python, and adds
# user/ca-export/smoke targets common.mk does not model. It adopts the
# shared airgap bundle library (scripts/bundle-lib.sh, CI drift-checked)
# via scripts/bundle_images.sh.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

EDGE_NET ?= $(or $(strip $(shell test -f .env && grep -E '^EDGE_NET=' .env | cut -d= -f2)),edge-net)

# External named volumes this project owns. Keep in sync with docker/compose.yaml.
VOLUMES := edge-state edge-ca

COMPOSE     := docker compose --env-file .env -f docker/compose.yaml
COMPOSE_DEV := docker compose --env-file .env -f docker/compose.yaml -f docker/compose.override.yaml

.PHONY: help network volumes pull bundle up up-dev stop down restart ps logs health nuke user ca-export smoke

help:
	@echo "edge-plane — the federation's edge gateway (Caddy + Authelia)."
	@echo
	@echo "Lifecycle:"
	@echo "  make network    create external edge-net if missing"
	@echo "  make volumes    create the external edge volumes if missing"
	@echo "  make pull       pull all images from the registries"
	@echo "  make bundle     save images as a versioned airgap tarball"
	@echo "  make up         start (production shape — :443/:80 only)"
	@echo "  make up-dev     like 'up', plus the whoami header-echo upstream"
	@echo "  make down       stop (volumes preserved)"
	@echo "  make restart    down + up"
	@echo "  make nuke       DESTROY auth state + CA volumes (interactive)"
	@echo
	@echo "Operations:"
	@echo "  make ps         service status"
	@echo "  make health     caddy + authelia readiness"
	@echo "  make logs S=caddy   tail logs for one service"
	@echo "  make user       hash a password for authelia/users.yml"
	@echo "  make ca-export  write the internal CA root to edge-ca-root.crt"
	@echo "  make smoke      end-to-end auth/header checks (needs up-dev)"

network:
	@docker network inspect $(EDGE_NET) >/dev/null 2>&1 \
	  || (echo ">> creating external network $(EDGE_NET)" && docker network create $(EDGE_NET))

volumes:
	@for v in $(VOLUMES); do \
	  docker volume inspect $$v >/dev/null 2>&1 \
	    || (echo ">> creating external volume $$v" && docker volume create $$v >/dev/null); \
	done

pull:
	$(COMPOSE) pull

bundle:
	./scripts/bundle_images.sh

up: network volumes
	$(COMPOSE) up --no-build -d

up-dev: network volumes
	$(COMPOSE_DEV) up --no-build -d

stop:
	$(COMPOSE) stop

down:
	$(COMPOSE) down --remove-orphans

restart: down up

nuke:
	@echo "This will DESTROY all edge-plane volumes (auth DB, sessions/TOTP, internal CA):"
	@for v in $(VOLUMES); do echo "  - $$v"; done
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

logs:
ifndef S
	$(COMPOSE) logs --tail=200 -f
else
	$(COMPOSE) logs --tail=200 -f $(S)
endif

user:
	$(COMPOSE) run --rm --no-deps authelia authelia crypto hash generate argon2

ca-export:
	@$(COMPOSE) exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > edge-ca-root.crt
	@echo "Wrote edge-ca-root.crt — distribute to LAN browsers (see README)."

smoke:
	./scripts/smoke.sh
