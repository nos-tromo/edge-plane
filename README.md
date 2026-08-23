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
| `caddy` | TLS termination (`:443` + the `:8443` Open WebUI site, `:80` redirect), path routing, `forward_auth`, `X-Auth-User` injection | `edge-net` **and** the project-internal `default` network |
| `authelia` | Identity provider: file-backed users, SQLite state (sessions/TOTP/preferences), filesystem notifier | project-internal (default) network only, reached by Caddy via `forward_auth` |

`caddy` joins `edge-net` and the project-internal `default` network —
never `inference-net` or `data-net` — so the gateway itself can never
reach a backend or a database directly. The `default` membership is
load-bearing, not incidental: it is the only place `forward_auth
authelia:9091` resolves, because Authelia joins that network alone and is
never reachable from `edge-net`.

All application traffic flows through each app's own frontend nginx,
reached by alias on `edge-net` (`chorus-frontend`, `docint-frontend`,
`nextext-frontend`, `translator-frontend`, `open-webui`, `grafana`).
`edge-net` is the federation's third external network seam, alongside
`inference-net` and `data-net`; `make network` creates it.

## Routing

| Path | Upstream (`edge-net` alias) | Auth | Notes |
|---|---|---|---|
| `/chorus/*` | `chorus-frontend:8080` | forward_auth | SPA serves from the sub-path |
| `/docint/*` | `docint-frontend:8080` | forward_auth | same |
| `/nextext/*` | `nextext-frontend:8080` | forward_auth | same |
| `/translator/*` | `translator-frontend:8080` | forward_auth | app ignores `X-Auth-User` (stateless) |
| `/webui/*` | — | forward_auth | redirects to the dedicated `:8443` site — Open WebUI has no sub-path support |
| `/grafana/*` | `grafana:3000` | forward_auth | `serve_from_sub_path` + `auth.proxy`; **admins group only** — see [docs/identity-contract.md](docs/identity-contract.md#access-control-the-admins-group-grafana-gate) |
| `/auth/*` | `authelia:9091` | — | Authelia's own login portal + API (sub-path mode) |
| `/auth-code` | — (static, `authcode/`) | forward_auth | one-time verification code viewer for password self-service; gated to the account whose `X-Auth-Email` matches |
| `/whoami/*` | `whoami:80` | forward_auth | **dev only** — header-echo upstream, added by `docker/compose.override.yaml` and routed via `caddy/conf.d.dev/dev.caddy`; absent in production |
| everything else | static landing page (`landing/`) | forward_auth | portal with service tiles, status indicators, and inline password-change form; light/dark via the shared `infra-ui-theme` tri-state toggle (OS-preference default) |

Open WebUI is the one exception to the path model: it is served from its own
site at `https://<EDGE_HOST>:8443/`, published alongside `:443`/`:80` as the
only other host-port exception, because its image bakes root-absolute asset
paths and cannot serve from a sub-path — see
[docs/decisions/0002-open-webui-dedicated-port.md](docs/decisions/0002-open-webui-dedicated-port.md).

Full design rationale, including the risk analysis for SPA sub-path serving
and the Grafana access-model change from obs-plane's tunnel-only v1
decision: [docs/2026-07-23-edge-plane-design.md](docs/2026-07-23-edge-plane-design.md).

### What is deliberately NOT routed

- **Neo4j Browser, Qdrant dashboard** — operator/admin surfaces, not
  end-user apps. SSH tunnel remains their access model, unchanged by
  edge-plane.
- **`vllm-router`** — backend-only; it stays on `inference-net`, which
  the gateway never joins. Apps reach inference over the network as
  today; the gateway has no business terminating user traffic there.

Routing either would mean the gateway (or a browser) reaching directly
into `inference-net` or `data-net` — exactly the seam violation the
two-network design exists to prevent.

## Identity

Every request follows **strip → authenticate → inject**. Caddy
unconditionally strips any client-supplied `X-Auth-*` and `Remote-*` header
before routing; `forward_auth` hands the request to Authelia, which either
redirects to the login portal or returns `Remote-User` (+ `-Email`,
`-Groups`, `-Name`); Caddy copies those into `X-Auth-User`, `X-Auth-Email`,
`X-Auth-Groups` and `X-Auth-Name` for the upstream. `Authorization` passes
through untouched — it is not part of the contract. `scripts/smoke.sh`
proves the strip: a forged `X-Auth-User` must never reach an upstream.

Members of `edge-net` accept those headers unverified, so adding one is an
access-control decision. Full contract, plus the admins-group `/grafana`
gate: [docs/identity-contract.md](docs/identity-contract.md).

## Container hardening

Both services run with `no-new-privileges` and `cap_drop: ALL` (the
`x-hardened` compose anchor); Caddy adds a read-only root filesystem and
re-adds only `NET_BIND_SERVICE` for its `:443`/`:80`/`:8443` binds.
Federation-wide policy: [../deploy/docs/decisions/0001-container-engine-docker.md](../deploy/docs/decisions/0001-container-engine-docker.md).

The four app-frontend upstreams are **:8080** — the apps' hardened images
serve on 8080 (`nginx-unprivileged`), so an edge-plane release before/after
the app releases must land in the same deployment window or those routes
502.

## Quickstart

```bash
cp .env.example .env
$EDITOR .env                              # set EDGE_HOST; generate real secrets with `make secret`
cp authelia/users.template.yml authelia/users.yml
make user                                 # hash a real password, paste the result into users.yml
make up                                   # production shape — :443, :8443 (+:80 redirect) only
```

For local iteration, `make up-dev` layers `docker/compose.override.yaml`,
which adds a `whoami` header-echo upstream and its `/whoami/*` route —
useful for exercising the auth/header contract without any real app
attached.

Set the real Authelia secrets **before the first `make up`** — the storage
encryption key is baked into the SQLite store at first startup and cannot
simply be changed afterwards. Recovery, and the rest of account
provisioning, is in
[docs/user-accounts.md](docs/user-accounts.md#secrets-and-the-first-start-storage-key).
Every variable, with defaults, is in
[docs/configuration.md](docs/configuration.md#environment-variables).

TLS defaults to Caddy's internal CA — no ACME, no egress. Distributing the
root to LAN browsers, using an org-issued certificate instead, and the
`EDGE_HOST` dotted-name rule are all in
[docs/tls-runbook.md](docs/tls-runbook.md).

## Operating

```bash
make ps                       # service status
make health                   # caddy + authelia readiness
make logs S=caddy             # tail logs for one service (omit S= to tail all)
make stop                     # stop containers without removing them
make down                     # stop + remove containers (volumes preserved)
make restart                  # down + up
make smoke                    # end-to-end auth/header checks (needs make up-dev)
```

`make nuke` destroys `edge-state` (Authelia's auth DB) and `edge-ca`
(Caddy's internal CA and its private key). It is interactive, and the
single destructive command in this repo — recovery is not a restart, see
[docs/tls-runbook.md](docs/tls-runbook.md#recovering-after-make-nuke).

## Airgap delivery

```bash
make bundle                                       # bundles the latest annotated release tag
EDGE_PLANE_VERSION_OVERRIDE=<version> make bundle  # bundles the current working tree instead
```

What ends up in the tarball, and the pinned digests CI and compose must
match: [docs/images.md](docs/images.md).

## Documentation

Start at [docs/README.md](docs/README.md) for the full index.

- [docs/configuration.md](docs/configuration.md) — every environment
  variable, the UI-language switch, corporate-proxy bypass.
- [docs/user-accounts.md](docs/user-accounts.md) — provisioning, the
  first-start storage key, self-service password change, session lifetimes.
- [docs/tls-runbook.md](docs/tls-runbook.md) — internal CA vs org-issued
  certificates, client trust, the `EDGE_HOST` caveat.
- [docs/identity-contract.md](docs/identity-contract.md) — the
  trusted-header contract and the admins-group `/grafana` gate.
- [docs/images.md](docs/images.md) — pinned image digests and airgap
  bundling.
- [docs/portal-tokens.md](docs/portal-tokens.md) — the vendored `@infra/ui`
  design tokens behind the portal pages, and the CI checks that guard them.
- [docs/decisions/](docs/decisions/) — architecture decision records.
