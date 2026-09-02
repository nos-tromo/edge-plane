# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Confidentiality — hard rule

Never commit real production/testing data or metadata referencing it
(usernames, handles, log excerpts, screenshots) — use synthetic
placeholders (`authelia/users.template.yml` is the model). Never commit
local development filepaths (`/Users/<name>/...` etc.); only relative
project paths. Never commit `.env`, `authelia/users.yml`, or anything in
`certs/` (all gitignored).

## Planning

For any non-trivial change (>1 file or any root-cause fix), present a plan and wait for approval BEFORE editing code. Do not start with Edit/Write on a fresh investigation.

## What this repo is

The federation's edge gateway — pure infra, no application source. Two
pulled, digest-pinned images: **Caddy** (TLS on `:443` + `:80` redirect,
path routing, `forward_auth`, identity-header injection; dedicated
`:8443` site for Open WebUI) and **Authelia** (file-backed users, SQLite
state, filesystem notifier — airgap-clean, no SMTP/egress). These are the
only published host ports in the whole production federation.

`README.md` is the entry point — what the gateway is, the routing table,
and a quickstart. The operator runbooks live in `docs/`, indexed by
`docs/README.md`: `docs/configuration.md` (every env var),
`docs/user-accounts.md` (provisioning, first-start secrets, sessions),
`docs/tls-runbook.md` (cert sources, client trust, `EDGE_HOST` rules),
`docs/identity-contract.md` (the trusted-header contract and the
admins-group `/grafana` gate), `docs/portal-tokens.md` (the vendored
design tokens and their CI checks). Architecture decisions:
`docs/decisions/`. Design rationale:
`docs/2026-07-23-edge-plane-design.md` (note: its Open WebUI sub-path
assumption did not hold — see
`docs/decisions/0002-open-webui-dedicated-port.md`). Pinned image
references: `docs/images.md` — the source of truth CI and compose must
match.

## Commands

There is no build and no test suite in the usual sense — the "tests" are
config validation and an end-to-end smoke script. Bespoke Makefile
(data-plane/obs-plane pattern), not `common.mk`; no `make verify`, no
`bundle-dev`.

```bash
make up             # production shape (:443/:80/:8443 only); requires .env + authelia/users.yml
make up-dev         # + whoami header-echo upstream and its /whoami route
make smoke          # end-to-end auth/header contract test — needs a running `make up-dev`
make health         # caddy + authelia readiness
make logs S=caddy   # tail one service (omit S= for all)
make down           # stop, volumes preserved
make user           # hash a password for authelia/users.yml (argon2)
make secret         # generate a random secret for .env
make ca-export      # write internal CA root to edge-ca-root.crt
make bundle         # airgap tarball of the latest annotated tag
EDGE_PLANE_VERSION_OVERRIDE=<v> make bundle   # bundle the working tree instead
make nuke           # DESTROYS edge-state + edge-ca volumes — interactive; new CA root on next up
```

First-time setup: `cp .env.example .env` (set `EDGE_HOST`, real secrets —
storage encryption key must be right **before first up**, see
`docs/user-accounts.md`),
`cp authelia/users.template.yml authelia/users.yml`, `make user`.

Local CI equivalents (what `.github/workflows/ci.yml` runs):

```bash
docker compose --env-file .env -f docker/compose.yaml config --quiet            # compose validation
docker run --rm -e EDGE_HOST=127.0.0.1 -v "$PWD/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$PWD/caddy/conf.d:/etc/caddy/conf.d:ro" <pinned caddy image> \
  caddy validate --config /etc/caddy/Caddyfile                                  # Caddyfile validation
./scripts/check-tokens-vendor.sh                                                # landing/tokens.css vendoring header
./scripts/check-no-literal-dimensions.sh                                        # portal font-size/border-radius must be tokens
./scripts/smoke.sh                                                              # after make up-dev
```

CI also runs shared infra checks (yamllint, shellcheck, and a drift-check
of `scripts/bundle-lib.sh` against its canonical copy in
`nos-tromo/.github` — never hand-edit that file; re-vendor it). The portal
similarly vendors `landing/tokens.css` from `nos-tromo/infra-ui`
(`dist/tokens.css`); `scripts/check-tokens-vendor.sh` checks its header
records a canonical source + pinned ref, either a commit or a release tag
(no live network fetch — this repo is airgap-first, not because infra-ui
lacks a stable ref) — never hand-edit that file either; re-vendor it per
`docs/portal-tokens.md`'s "Re-vendoring" section and the file's own
header comment. `scripts/check-no-literal-dimensions.sh` guards the other half of
that vendoring: it fails if either portal page's `font-size`, the `font`
shorthand, or any `border-radius` (including longhands) resolves to
anything but one of the vendored `--text-*`/`--radius-*` tokens, a CSS-wide
keyword, or the `border-radius: 50%` circle exception — see
`docs/portal-tokens.md`'s "Enforcing the dimensional scale" section and
the script's own header comment.

Releases: bump the one-line `VERSION` file in the PR; the `release-tag`
workflow mints the annotated `vX.Y.Z` tag on merge to `main`.

## Architecture

### The trusted-header contract (the load-bearing thing)

Every request through the gateway follows strip → auth → inject:

1. `strip_identity` snippet (`caddy/Caddyfile`) unconditionally deletes
   client-supplied `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`,
   `X-Auth-Name`, and all `Remote-*` headers before any routing.
2. `authed` snippet runs `forward_auth` against `authelia:9091`;
   unauthenticated requests redirect to the `/auth` portal.
3. On success, `copy_headers` renames Authelia's `Remote-User` →
   `X-Auth-User`, `Remote-Email` → `X-Auth-Email`, `Remote-Groups` →
   `X-Auth-Groups`, and `Remote-Name` → `X-Auth-Name` for the upstream.
   `X-Auth-Name` (the `displayname` from `authelia/users.yml`) is
   decorative — UI display only, e.g. the portal's greeting; apps must
   keep keying identity on `X-Auth-User`.

`Authorization` passes through untouched — it is not part of the contract
(upstreams like Open WebUI use it internally). Downstream apps (chorus,
docint, Nextext) consume `X-Auth-User` fail-closed; the whole model is
sound only because production publishes no other host ports and the
gateway strips before injecting — which is exactly what
`scripts/smoke.sh`'s spoof test proves (forged `X-Auth-User: mallory`
must never reach the upstream). Any Caddyfile change should keep that
test passing.

### Caddyfile ordering traps (why the file is shaped the way it is)

These were all hit in anger; don't "simplify" them away:

- Proxies needing auth must live inside `handle` blocks: at site level
  Caddy orders `forward_auth` **before** `request_header`, so
  `strip_identity` would delete the headers `copy_headers` just injected.
- Every app matcher covers the bare prefix too (`/chorus` and
  `/chorus/*`) — the path matcher alone misses the slash-less form
  (gateway 404).
- Bare `/auth` must be matched: Authelia's login redirects target the
  slash-less portal URL, which must not fall into the authenticated
  catch-all (redirect loop → 404 after login).
- The `/webui` block cannot carry `forward_auth` (Caddy orders `redir`
  first, so it would never run) — auth is enforced at the `:8443`
  destination instead.
- `:8443` caps streams at `stream_timeout 30m`: `forward_auth` gates only
  the WebSocket upgrade, so an open socket would otherwise outlive the
  Authelia session.
- `default_sni {$EDGE_HOST}` is required because RFC 6066 forbids SNI for
  literal IPs — without it every handshake to an IP `EDGE_HOST` fails.
- App route prefixes are NOT stripped — each SPA serves under its
  sub-path; Open WebUI can't (root-absolute baked asset paths), hence the
  dedicated `:8443` site.

### Other structural facts

- Caddy joins **only** `edge-net` (external network; `make network`
  creates it) plus the project-internal default network where Authelia
  lives — never `inference-net`/`data-net`. Authelia is on the internal
  network only, reachable solely via Caddy. Upstreams are reached by
  `edge-net` alias (`chorus-frontend`, `docint-frontend`,
  `nextext-frontend`, `translator-frontend`, `open-webui`, `grafana`);
  this repo does not own those services. Do not route Neo4j/Qdrant/
  `vllm-router` — that is the seam violation the network design prevents.
- Two external volumes: `edge-state` (Authelia's encrypted SQLite —
  TOTP secrets, sessions) and `edge-ca` (Caddy's internal CA + private
  key). `docker compose down -v` can't destroy them; only `make nuke`.
  A third, `edge-notify`, is deliberately project-scoped rather than
  external: it carries Authelia's filesystem notifications (the one-time
  codes the `/auth-code` viewer renders), which are short-lived, not
  durable identity state.
- Access control lives in `authelia/configuration.yml`: `default_policy:
  deny`, with a domain-wide catch-all rule granting `one_factor` — so in
  practice every provisioned account reaches every routed app. The
  exception is `/grafana`, admins-group only via a match-then-explicit-deny
  rule pair placed ahead of the catch-all (order matters, first match
  wins; without the explicit deny a non-admin falls through and is let
  in). The file is rendered with `X_AUTHELIA_CONFIG_FILTERS=template`,
  which is what lets those rules read `EDGE_HOST` from the environment.
- Dev vs prod divergence is a whole-directory swap:
  `compose.override.yaml` replaces the `caddy/conf.d` mount with
  `caddy/conf.d.dev` (containing the `/whoami` route) because Docker
  can't nest a file mount inside a read-only bind-mounted directory.
  Production ships only `caddy/conf.d/empty.caddy`; the whoami image is
  never bundled.
- Airgap-first: internal CA by default (no ACME/OCSP/egress), or
  org-issued PEMs via `EDGE_TLS` + `certs/` (see `docs/tls-runbook.md`).
  Never add anything that fetches at runtime. When bumping an image,
  update the digest pin in `docker/compose.yaml`, `docs/images.md`, and
  `ci.yml` together.

## Git & PR Workflow

- Never commit directly to `main`; always branch (`feat/`, `fix/`) and open a PR.
- Never create a NEW PR when an existing PR for the work is open — push additional commits to that branch.
- Release order is strict: bump VERSION file -> commit -> tag. Never tag before the VERSION bump.
- Use single, non-compound shell commands for `gh` operations (no `&&` chains); if `gh pr merge` is blocked, fall back to the GitHub MCP merge tool.

## Verification

Before claiming a check is green, run the actual command and paste the output. `git ls-files` does not cover untracked files — use `pre-commit run --all-files`. After opening a PR, confirm CI actually triggered on the latest push before declaring done.

## Communication Style

Keep changes minimal and scoped. Do not add explanatory code comments for trivial or self-evident changes. Do not overwrite existing test files with Write — use Edit to append or modify tests.
