# edge-plane — federation edge gateway (design)

Status: approved design, pre-implementation
Date: 2026-07-23
Scope: new federation member `edge-plane` + the integration contract the
existing members implement to sit behind it.

## Problem

Production compose files across the federation publish no host ports — by
design, every app's `compose.yaml` is production-shape with `expose:` only.
The consequence is that a production bring-up is unreachable from a browser:
there is no entry point, no TLS, and no authentication layer. Meanwhile
three apps (chorus, docint, Nextext) already implement an identical
trusted-header auth seam — a configurable header (default `X-Auth-User`)
resolved fail-closed to a principal, with the upstream reverse proxy named
as the intended issuer — that nothing currently issues in production.

`edge-plane` closes both gaps: it is the single production entry point
(TLS, path routing) and the authentication boundary that populates
`X-Auth-User`.

## Decision summary

| Decision | Choice |
|---|---|
| Access topology | Single host, LAN, browser, no DNS control → **path-based routing** on one IP/hostname, HTTPS on `:443` |
| Identity provider | **Authelia** (forward-auth; file-backed user DB) |
| Reverse proxy | **Caddy** (forward_auth directive, internal CA for TLS) |
| Routed services | chorus, docint, Nextext, translator, Open WebUI (trusted-header SSO), Grafana |
| Explicitly not routed | Neo4j Browser, Qdrant dashboard (operator/admin surfaces — SSH tunnel remains their access model), vllm-router (backend-only, stays on `inference-net`) |
| Repo shape | New repo `edge-plane`, obs-plane mold: pulled digest-pinned images, bespoke Makefile, `VERSION` file |
| Network | New external network **`edge-net`** — the third federation seam |

## Architecture

### The third network seam: `edge-net`

App frontends are unreachable from the existing networks: `inference-net`
and `data-net` carry backends only, and each SPA's nginx joins only its
app-private network. `edge-plane` therefore introduces **`edge-net`**, an
external Docker network created once per host (`make network`), to which:

- the gateway (Caddy + Authelia) attaches — **and only to `edge-net`**;
  the gateway never joins `inference-net` or `data-net`, so it cannot
  reach backends or databases directly. All traffic flows through each
  app's own frontend nginx, identical to the dev shape.
- each fronted service attaches its frontend container with a stable
  alias: `chorus-frontend`, `docint-frontend`, `nextext-frontend`,
  `translator-frontend`, `open-webui`, `grafana`.

This is the symmetric extension of the two-seam pattern and becomes a
load-bearing invariant: **user traffic enters only via the edge gateway on
`edge-net`; the gateway holds no membership on the other seams.**

### Components (both pulled, digest-pinned)

**Caddy** — listens on `:443` (the only published port in production;
optional `:80` → `:443` redirect). TLS via Caddy's internal CA; the root
certificate is exported by a make target for distribution to LAN browsers
(documented runbook; an untrusted-cert warning is the accepted fallback).
Admin API bound to localhost inside the container. No ACME, no external
fetches — airgap-clean by configuration.

**Authelia** — single instance:

- **User DB**: file-backed (`users.yml`, argon2id hashes). A `make user`
  helper hashes passwords via the Authelia container. The users file is a
  provisioned template in the repo containing only synthetic examples;
  real user files live only on the deployment host.
- **Storage**: local SQLite (TOTP secrets, preferences) on the
  `edge-state` volume.
- **Sessions**: in-memory provider (single instance; sessions reset on
  restart — accepted).
- **Notifier**: filesystem notifier (no SMTP on an airgapped host;
  password-reset links land in a file on `edge-state` that the operator
  reads out-of-band).
- **Access control**: default `deny`; one `one_factor` rule covering the
  whole protected domain. TOTP 2FA is available per-user later without
  design change.

### Routing map

| Path | Upstream (edge-net alias) | Auth | Notes |
|---|---|---|---|
| `/chorus/` | `chorus-frontend:80` | forward_auth | SPA sub-path (see Risks) |
| `/docint/` | `docint-frontend:80` | forward_auth | same |
| `/nextext/` | `nextext-frontend:80` | forward_auth | same |
| `/translator/` | `translator-frontend:80` | forward_auth | app ignores `X-Auth-User` (stateless) |
| `/webui/` | `open-webui:8080` | forward_auth | SSO via `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`; Authelia login is the only login |
| `/grafana/` | `grafana:3000` | forward_auth | `serve_from_sub_path` + `auth.proxy`; revises obs-plane's tunnel-only v1 access decision (dev-override/tunnel path remains the fallback) |
| `/auth/` | `authelia:9091` | — | login portal (Authelia ≥ 4.38 sub-path support) |
| `/` | static landing page (in repo) | forward_auth | links to the routed apps |

### Identity flow and the anti-spoofing guarantee

1. Caddy **unconditionally strips** client-supplied `X-Auth-User` and
   `Remote-*` headers on every request, before anything else. The entire
   trusted-header model rests on this.
2. `forward_auth` sends the request to Authelia. Unauthenticated →
   redirect to `/auth/`. Authenticated → Authelia returns `Remote-User`
   (+ `Remote-Email`, `Remote-Groups`).
3. Caddy copies `Remote-User` into **`X-Auth-User`** on the proxied
   request. This satisfies the seam implemented identically in
   `chorus/chorus/api/auth/principal.py`,
   `docint/docint/core/auth/principal.py`, and
   `Nextext/nextext/api/identity.py`. Caddy likewise copies
   `Remote-Email` into `X-Auth-Email` for upstreams keyed on email
   (e.g. Open WebUI's trusted-email-header SSO).
4. Production `.env`s leave `CHORUS_DEFAULT_IDENTITY` /
   `DOCINT_DEFAULT_IDENTITY` / `NEXTEXT_DEFAULT_IDENTITY` unset, so a
   request that somehow bypasses the gateway fails closed with 401.
   The existing dev shape (`make up-dev` + default identity) is unchanged.

Trust boundary note: service-to-service traffic on `inference-net` /
`data-net` remains unauthenticated between members, as today. edge-plane
changes the user-facing boundary only.

### Why trusted-header (`X-Auth-User`), not `Authorization`

`Authorization` carries a *credential* (bearer token, basic auth) that
originates with the untrusted client, so every receiving service must
verify it — signature, expiry, audience, key material. `X-Auth-User` is a
*trusted assertion*: a plain string the app accepts blindly. That is only
sound under two preconditions, both guaranteed by this design:

1. Apps are unreachable except through the gateway (production publishes
   no host ports; the gateway is the sole entry on `edge-net`).
2. The gateway strips the header from every incoming request before
   setting its own value.

Given those, trusted-header wins here because:

- The three identity-aware apps already implement this exact seam; a
  token model would push JWT validation and manual key distribution into
  four Python apps on an airgapped host, for no gain with a single entry
  point.
- Auth logic (passwords, sessions, logout, future TOTP) lives in one
  place — Authelia — mirroring the "shared, never embedded" invariant.
- Both third-party upstreams are designed for it: Grafana `auth.proxy`
  and Open WebUI's trusted-header SSO; neither would accept a
  federation-minted `Authorization` token.

If non-browser API clients ever need gateway access (the cookie/redirect
flow is awkward for scripts), the additive extension is token validation
*at the gateway* (e.g. Authelia OIDC provider mode), still emitting plain
`X-Auth-User` upstream — apps unchanged.

**Pass-through rule**: the gateway owns `X-Auth-User` / `Remote-*` and
strips them from clients, but passes `Authorization` through untouched —
it is not part of the identity contract, and upstreams use it internally
(Open WebUI issues its own JWTs after the trusted-header handshake).

## Repo layout and conventions

```
edge-plane/
  caddy/Caddyfile
  authelia/configuration.yml
  authelia/users.template.yml      # synthetic placeholders only
  landing/index.html
  docker/compose.yaml              # production shape: publishes :443 (+:80)
  docker/compose.override.yaml    # dev overlay: adds whoami header-echo upstream + dev Caddy routes, publishes nothing extra
  scripts/                         # bundle, user-hash, CA-export helpers
  Makefile                         # bespoke (obs-plane mold)
  VERSION
  .github/workflows/release-tag.yml
```

- Images pulled and digest-pinned; `make bundle` produces the pulled
  tarball keyed to the latest annotated tag;
  `EDGE_PLANE_VERSION_OVERRIDE` allows a working-tree bundle
  (data-plane/obs-plane precedent).
- External volumes `edge-state` (Authelia SQLite, notifier output) and
  `edge-ca` (Caddy internal CA root) follow the blast-radius pattern:
  `docker compose down -v` can never destroy them; only a gated
  `make nuke` can.
- `make network` creates `edge-net`; `make health` probes Caddy and
  Authelia (`/api/health`).

## Deploy integration

Bring-up order becomes: inference → state → obs → apps → **edge**.
deploy adds an edge tier, health-gated like the others. Ordering is a
nicety, not a correctness requirement — Caddy answers 502 for a down
upstream and recovers without restart. `make up-dev` federation-wide keeps
its current meaning; edge-plane's own `up-dev` publishes nothing extra —
it adds the whoami header-echo upstream and a dev Caddy route
(`caddy/conf.d.dev/`) for local iteration.

## Risks and mitigations

1. **SPAs under a path prefix (the main risk).** The four in-house SPAs
   are built to serve from `/`. Each needs its Vite `base`, router
   basename, and frontend-nginx config to tolerate a prefix like
   `/chorus/`. This is per-app work, verified per-app by a smoke test
   through the gateway. Grafana and Open WebUI have first-class sub-path
   support. Fallback if one SPA resists: serve that app on a dedicated
   extra Caddy port instead of a path — contained, but to be avoided.
2. **Header spoofing.** Mitigated by the unconditional strip in Caddy
   (verified by an explicit test, below).
3. **Sessions lost on gateway restart.** In-memory session provider;
   users re-login after a gateway bounce. Accepted for v1; Redis is the
   escape hatch if it ever matters.
4. **Self-signed TLS friction.** Internal-CA root export + install
   runbook; browser warning is the degraded-but-working fallback.
5. **Grafana access-model change.** Explicit revisit of obs-plane's v1
   decision; obs-plane README updated in the follow-up PR; tunnel path
   retained.

## Verification

- Compose smoke test: both services healthy, `:443` answering.
- Auth flow: unauthenticated request → redirect to `/auth/`;
  authenticated session → 200.
- Header contract: through an authenticated session, an upstream
  header-echo confirms `X-Auth-User` = the logged-in user.
- Spoof test: a request carrying a forged `X-Auth-User` never delivers
  that value to an upstream (stripped and replaced or rejected).
- Airgap check: no runtime egress attempts from either container
  (consistent with the federation's no-fetch rule).

## Delivery decomposition

| # | Repo | Change |
|---|---|---|
| ① | `edge-plane` (new) | The member itself — this spec's core |
| ② | chorus, docint, Nextext, translator | Frontend joins `edge-net` with alias; SPA sub-path support |
| ③ | open-webui-service | `WEBUI_AUTH_TRUSTED_EMAIL_HEADER` + `edge-net` attach |
| ④ | obs-plane | Grafana `serve_from_sub_path` + `auth.proxy` + `edge-net` attach; README access-model update |
| ⑤ | deploy | Edge tier in bring-up order |
| ⑥ | infra `CLAUDE.md` | Document the third seam + new member |

① is implemented first and is independently testable against a stub
upstream; ②–④ land per-repo behind it; ⑤/⑥ close the loop.
