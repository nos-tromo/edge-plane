# edge-plane

The federation's edge gateway: Caddy (TLS, path routing) + Authelia
(forward-auth identity), both pulled and digest-pinned, bundleable for
airgap. It is the single production entry point for the federation — the
one member whose `compose.yaml` publishes host ports at all — and the
authentication boundary that populates the trusted-header identity
contract (`X-Auth-User`) three apps already implement.

## What lives here

Two services:

| Service | Role | Network membership |
|---|---|---|
| `caddy` | TLS termination (`:443`, `:80` redirect), path routing, `forward_auth`, `X-Auth-User` injection | `edge-net` only |
| `authelia` | Identity provider: file-backed users, SQLite state (sessions/TOTP/preferences), filesystem notifier | project-internal (default) network only, reached by Caddy via `forward_auth` |

`caddy` joins **only** `edge-net` — never `inference-net` or `data-net` —
so the gateway itself can never reach a backend or a database directly.
All application traffic flows through each app's own frontend nginx,
reached by alias on `edge-net` (`chorus-frontend`, `docint-frontend`,
`nextext-frontend`, `translator-frontend`, `open-webui`, `grafana`).
`edge-net` is the federation's third external network seam, alongside
`inference-net` and `data-net`; `make network` creates it.

## Routing

| Path | Upstream (`edge-net` alias) | Auth | Notes |
|---|---|---|---|
| `/chorus/*` | `chorus-frontend:80` | forward_auth | SPA serves from the sub-path |
| `/docint/*` | `docint-frontend:80` | forward_auth | same |
| `/nextext/*` | `nextext-frontend:80` | forward_auth | same |
| `/translator/*` | `translator-frontend:80` | forward_auth | app ignores `X-Auth-User` (stateless) |
| `/webui/*` | `open-webui:8080` | forward_auth | SSO via `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`; Authelia login is the only login |
| `/grafana/*` | `grafana:3000` | forward_auth | `serve_from_sub_path` + `auth.proxy` |
| `/auth/*` | `authelia:9091` | — | Authelia's own login portal + API (sub-path mode) |
| `/whoami/*` | `whoami:80` | forward_auth | **dev only** — header-echo upstream, added by `docker/compose.override.yaml` and routed via `caddy/conf.d.dev/dev.caddy`; absent in production |
| everything else | static landing page (`landing/`) | forward_auth | links to the routed apps |

See `docs/2026-07-23-edge-plane-design.md` for the full design rationale,
including the risk analysis for SPA sub-path serving and the Grafana
access-model change from obs-plane's tunnel-only v1 decision.

## Quickstart

```bash
cp .env.example .env
$EDITOR .env                              # set EDGE_HOST; generate real secrets (see below)
cp authelia/users.template.yml authelia/users.yml
make user                                 # hash a real password, paste the result into users.yml
make up                                   # production shape — :443 (+:80 redirect) only
```

For local iteration, `make up-dev` layers `docker/compose.override.yaml`,
which adds a `whoami` header-echo upstream and its `/whoami/*` route —
useful for exercising the auth/header contract without any real app
attached. Generate production secrets with:

```bash
make secret
```

and set `AUTHELIA_SESSION_SECRET`, `AUTHELIA_STORAGE_ENCRYPTION_KEY`, and
`AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET` in `.env` — the
`.env.example` values are insecure dev/CI placeholders only.

Set the real secrets **before the first `make up`**: Authelia encrypts its
SQLite DB on the `edge-state` volume with `AUTHELIA_STORAGE_ENCRYPTION_KEY`
at first startup, so rotating the key afterwards (e.g. after a dev/smoke
run on the placeholder key) makes the next start fail its storage check
("the configured encryption key does not appear to be valid for this
database") and the container stays unhealthy. If the DB holds nothing
real yet, clear it and let Authelia recreate it under the new key:

```bash
make down
docker run --rm -v edge-state:/data --entrypoint sh \
  docker.io/authelia/authelia:<pinned tag, see docs/images.md> -c 'rm -f /data/db.sqlite3'
make up
```

With real data in the DB, use `authelia storage encryption change-key`
(run with the old key still configured) instead of deleting.

## The trusted-header contract

Three apps (chorus, docint, Nextext) already implement an identical
seam: a configurable header (default `X-Auth-User`) resolved fail-closed
to a principal, with the upstream reverse proxy named as the intended
issuer. Nothing issued it in production before edge-plane. The flow:

1. Caddy **unconditionally strips** client-supplied `X-Auth-User` and
   `Remote-*` headers on every request, before anything else — the
   `strip_identity` snippet in `caddy/Caddyfile`.
2. `forward_auth` sends the request to Authelia. Unauthenticated →
   redirect to `/auth/`. Authenticated → Authelia returns `Remote-User`
   (+ `Remote-Email`, `Remote-Groups`).
3. Caddy copies `Remote-User` into **`X-Auth-User`** on the proxied
   request — the `authed` snippet's `copy_headers`. The gateway also
   forwards `X-Auth-Email` (from Authelia's `Remote-Email`) for
   upstreams keyed on email, e.g. Open WebUI's
   `WEBUI_AUTH_TRUSTED_EMAIL_HEADER=X-Auth-Email`.

This is only sound because apps are unreachable except through the
gateway (production publishes no host ports anywhere else in the
federation) and the gateway strips the header before setting its own
value — verified by `scripts/smoke.sh`'s spoof test.

**`Authorization` pass-through rule**: the gateway owns `X-Auth-User` /
`Remote-*` and strips them from clients, but passes `Authorization`
through untouched. It is not part of the identity contract — upstreams
use it internally (Open WebUI issues its own JWTs after the
trusted-header handshake). Full rationale, including why trusted-header
was chosen over pushing token validation into four apps, is in
`docs/2026-07-23-edge-plane-design.md`.

## TLS / CA runbook

Caddy terminates TLS using its own internal CA (`tls internal` in the
Caddyfile) — there is no ACME, no external CA, and no egress, consistent
with the airgap-first rule. To make LAN browsers trust it:

```bash
make ca-export                # writes edge-ca-root.crt (Caddy's internal CA root)
```

Distribute `edge-ca-root.crt` to every browser/OS that will reach the
gateway and install it as a trusted root CA (the exact steps are
OS/browser-specific: e.g. macOS Keychain Access "always trust", Windows
Certificate Manager "Trusted Root Certification Authorities", Firefox's
own cert store on Linux). Until a browser trusts the root, it shows a
certificate-warning interstitial — that is the accepted fallback for a
LAN deployment with no public CA, not a bug; clicking through is safe
because the certificate is generated locally on the gateway host, not
downloaded from anywhere.

**EDGE_HOST caveat**: `EDGE_HOST` must be a dotted hostname or an IP
address — Authelia's cookie-domain validation (RFC 6265) rejects
dot-less names like `localhost`. An IP address works fine for dev/CI
(both use `127.0.0.1`); the recommended production shape is a real
dotted hostname distributed via `/etc/hosts` entries (or LAN DNS, if
available) on every client machine, since a hostname survives an IP
change and reads better in a browser address bar. The Caddyfile also
sets `default_sni {$EDGE_HOST}` — this is required because RFC 6066
forbids the SNI extension for literal IP addresses, so when `EDGE_HOST`
is an IP no conformant TLS client sends SNI at all; without a default
site, every such handshake fails with a TLS `internal_error` alert
before Caddy ever routes the request.

## `make nuke` warning

`make nuke` destroys both external volumes this project owns:
`edge-state` (Authelia's auth DB — TOTP secrets, user preferences)
and `edge-ca` (Caddy's internal CA, including its private
key). It is interactive (`Type 'nuke' to confirm`) precisely because
recovery is not a restart: destroying `edge-ca` mints a **new** root CA
on the next `make up`, so every browser that trusted the old root must
re-run the TLS runbook above and trust the new one, and every user loses
their session and must re-authenticate. Treat it as the single
destructive command in this repo, on par with `data-plane`'s `make
nuke` for the federation's databases.

## Airgap delivery

```bash
make bundle                                       # bundles the latest annotated release tag
EDGE_PLANE_VERSION_OVERRIDE=<version> make bundle  # bundles the current working tree instead
```

Both pulled images (`caddy`, `authelia`) are saved as a versioned airgap
tarball via the shared `scripts/bundle-lib.sh` (vendored, CI
drift-checked against `nos-tromo/.github`), matching the
data-plane/obs-plane pattern: bespoke Makefile, no `bundle-dev` target,
version override via env instead. `docker.io/traefik/whoami` (the dev
header-echo upstream) is never bundled — it has no place in a production
airgap image set.

## What is deliberately NOT routed

- **Neo4j Browser, Qdrant dashboard** — operator/admin surfaces, not
  end-user apps. SSH tunnel remains their access model, unchanged by
  edge-plane.
- **`vllm-router`** — backend-only; it stays on `inference-net`, which
  the gateway never joins. Apps reach inference over the network as
  today; the gateway has no business terminating user traffic there.

Routing either would mean the gateway (or a browser) reaching directly
into `inference-net` or `data-net` — exactly the seam violation the
two-network design exists to prevent.

## Operating

```bash
make ps                       # service status
make health                   # caddy + authelia readiness
make logs S=caddy             # tail logs for one service (omit S= to tail all)
make down                     # stop (volumes preserved)
make restart                  # down + up
make smoke                    # end-to-end auth/header checks (needs make up-dev)
```

## Layout

```
edge-plane/
  caddy/
    Caddyfile                 TLS, strip/inject identity headers, path routes
    conf.d/empty.caddy         production: always-matching, deliberately empty glob target
    conf.d.dev/dev.caddy       dev only: /whoami/* route (whole-dir swap, see compose.override.yaml)
  authelia/
    configuration.yml          /auth sub-path, file users, SQLite, filesystem notifier
    users.template.yml         synthetic placeholder — copy to users.yml, never commit it
  landing/index.html           unauthenticated-adjacent landing page (still behind forward_auth)
  docker/
    compose.yaml               production shape — publishes :443 (+:80) only
    compose.override.yaml      dev overlay — whoami upstream + its route, relaxed conf.d mount
  scripts/
    bundle_images.sh           airgap bundler, sources vendored bundle-lib.sh
    bundle-lib.sh              vendored verbatim from nos-tromo/.github
    smoke.sh                   end-to-end contract test (portal redirect, login, header inject/strip)
  Makefile                     bespoke operator commands (data-plane/obs-plane style)
  VERSION                      one-line semver, read by the release-tag workflow
  docs/
    images.md                  pinned image references (source of truth for CI + compose)
    2026-07-23-edge-plane-design.md   design spec
  .env.example                 copy to .env; EDGE_HOST + Authelia secrets required
```
