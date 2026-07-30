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
| `/webui/*` | — | forward_auth | redirects to the dedicated `:8443` site (below) — Open WebUI has no sub-path support |
| `/grafana/*` | `grafana:3000` | forward_auth | `serve_from_sub_path` + `auth.proxy` |
| `/auth/*` | `authelia:9091` | — | Authelia's own login portal + API (sub-path mode) |
| `/auth-code` | — (static, `authcode/`) | forward_auth | one-time verification code viewer for password self-service; gated to the account whose `X-Auth-Email` matches |
| `/whoami/*` | `whoami:80` | forward_auth | **dev only** — header-echo upstream, added by `docker/compose.override.yaml` and routed via `caddy/conf.d.dev/dev.caddy`; absent in production |
| everything else | static landing page (`landing/`) | forward_auth | portal with service tiles, status indicators, and inline password-change form; light/dark via the shared `infra-ui-theme` tri-state toggle (OS-preference default) |

**Open WebUI (`https://<EDGE_HOST>:8443/`, separate site block).** The
upstream image has no base-path support: its SvelteKit frontend bakes
root-absolute asset paths (`/_app/...`) at image build time, with no
runtime env to rewrite them (confirmed against the pinned image's config
and the `v0.9.6` source — no `WEBUI_BASE_URL`/`root_path` mechanism
exists). So unlike the four SPAs above, it cannot share the `:443` site
under `/webui` — it gets a dedicated port instead, same `strip_identity` +
`authed` chain, published alongside `:443`/`:80` as the only other
host-port exception. `/webui/*` on the main site just redirects there.

See `docs/2026-07-23-edge-plane-design.md` for the full design rationale,
including the risk analysis for SPA sub-path serving and the Grafana
access-model change from obs-plane's tunnel-only v1 decision (note: that
doc's Open WebUI sub-path assumption did not hold — this README is
authoritative).

## UI language

`RESPONSE_LANGUAGE` (`en` | `de`, default `en`) localizes the static
landing page (`landing/`) via Caddy's `templates` directive — the same
uniform env var used across the federation's other frontends. Set it in
`.env` and re-run `make up` (the container must be recreated, not just
restarted — `docker compose restart` reuses the old interpolated value).

The Authelia login portal is not affected by this variable — it
self-localizes from the browser's `Accept-Language` header (German
included), so no configuration is needed there.

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

## User accounts

- **Provisioning** is operator-side: `make user` hashes a password; add the
  entry to `authelia/users.yml` (see `authelia/users.template.yml`).
  `authentication_backend.file.watch: true` re-reads the file on change, so
  admin edits (new users, manual hash replacement) are picked up without an
  `authelia` restart — configured for this and verified to apply on restart;
  in local `make up-dev` testing on Docker Desktop for Mac, an edit made
  directly on the host filesystem was not observed to trigger a live reload
  within ~15 seconds (the bind-mounted filesystem may not propagate the
  change-notify events Authelia's watcher relies on) — a restart always
  picks it up immediately, so treat `watch: true` as a same-host / Linux
  convenience, not something to depend on across every environment.
- **Password change** is self-service and verified end-to-end: the portal's
  inline *Change password* form (current + new password) drives Authelia's
  session-elevation API directly — no navigation to Authelia's own settings
  UI, which is a dead end behind the gateway. Submitting the form starts
  elevation, which sends a one-time verification code to Authelia's
  filesystem notifier; the code is fetched and redeemed automatically. The
  code also remains available at `/auth-code` if ever needed manually,
  gated to the account whose `X-Auth-Email` matches the notification's
  recipient — no other logged-in account can see it. Codes are single-use
  and valid for 5 minutes. Redeeming the code elevates the session, and the
  subsequent password change writes the new hash back to
  `authelia/users.yml`, confirmed to persist across an `authelia` restart.
  (The `users.yml` bind mount must be writable — it was briefly `:ro`,
  which made every change silently fail: the API returned
  HTTP 500 while still mutating the in-memory user store, so the old
  password stopped working and the new one worked until the next restart,
  with nothing persisted to disk. Fixed by dropping `:ro` from that one
  mount; `configuration.yml` itself stays read-only.)
- Cross-user binding is enforced: a code requested by one account cannot be
  read from `/auth-code` or redeemed via the elevation API by any other
  account's session (verified with a second dev user — both the "no code
  pending" render and a direct redemption attempt were rejected).
- **Password reset** ("forgotten password") is admin-mediated by design: the
  filesystem notifier means Authelia's built-in reset flow cannot reach
  users, so it is disabled (`password_reset.disable: true`). To reset,
  run `make user` and replace the user's hash in `authelia/users.yml`.
- **Back up `authelia/users.yml`**: it is gitignored and lives outside the
  `edge-state`/`edge-ca` volumes, so with self-service password change it is
  now the *only* copy of user-chosen credentials — restoring it from
  `users.template.yml` silently reverts every user's password. Authelia
  rewrites the file to its full schema on the first self-service change, so
  a post-rollout diff looking unfamiliar is expected.

### Session behaviour

Sessions last 12 h (4 h inactivity timeout; "remember me" 2 months).
On expiry, in-flight requests/streams are not severed — forward-auth gates
each new request — so server-side jobs keep running; the next UI request
redirects to the login portal, and the page resumes after re-login.
Verified with a shortened 2 m/1 m session: a request already authorized and
in progress (a slow ~200 s upload, started before expiry) completed
normally with the injected `X-Auth-User` header intact, while a fresh
request issued afterward on the same now-expired session cookie received a
302 to `/auth`.

## The trusted-header contract

Three apps (chorus, docint, Nextext) already implement an identical
seam: a configurable header (default `X-Auth-User`) resolved fail-closed
to a principal, with the upstream reverse proxy named as the intended
issuer. Nothing issued it in production before edge-plane. The flow:

1. Caddy **unconditionally strips** client-supplied `X-Auth-User`,
   `X-Auth-Groups`, `X-Auth-Name`, and `Remote-*` headers on every
   request, before anything else — the `strip_identity` snippet in
   `caddy/Caddyfile`.
2. `forward_auth` sends the request to Authelia. Unauthenticated →
   redirect to `/auth/`. Authenticated → Authelia returns `Remote-User`
   (+ `Remote-Email`, `Remote-Groups`, `Remote-Name`).
3. Caddy copies `Remote-User` into **`X-Auth-User`** on the proxied
   request — the `authed` snippet's `copy_headers`. The gateway also
   forwards `X-Auth-Email` (from Authelia's `Remote-Email`) for
   upstreams keyed on email, e.g. Open WebUI's
   `WEBUI_AUTH_TRUSTED_EMAIL_HEADER=X-Auth-Email`.

   The gateway likewise forwards **`X-Auth-Groups`** (from Authelia's
   `Remote-Groups`, comma-separated) so upstreams can make group-based
   authorization decisions — e.g. docint grants members of the `admins`
   group visibility into all users' collections. Groups are defined per
   user in `authelia/users.yml`.

   The gateway also forwards **`X-Auth-Name`** (from Authelia's
   `Remote-Name`, the `displayname` set per user in
   `authelia/users.yml`) — a decorative display name for UI use only.
   It is not an identity key: apps must keep keying on `X-Auth-User`.
   The portal (`landing/index.html`) uses it to greet the signed-in user
   by name, falling back to `X-Auth-User` when absent.

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

Caddy terminates TLS using its own internal CA by default (`EDGE_TLS`
unset → `tls internal` in the Caddyfile) — there is no ACME, no external
CA, and no egress, consistent with the airgap-first rule. There are two
supported cert sources:

### Option A (default): internal CA

To make LAN browsers trust it:

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

### Option B: org-issued certificate

If your organization runs an internal CA that managed clients already
trust (the usual case when an org-provided domain points at the
federation host), skip the root-distribution step entirely: have the org
issue a certificate for the `EDGE_HOST` name, then

1. place the PEM pair in `certs/` (gitignored; never commit certs or
   keys):
   `certs/cert.pem` (leaf, plus any intermediate chain) and
   `certs/key.pem`
2. set in `.env`:
   `EDGE_TLS=/etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem`
3. `make restart`

The `certs/` directory is bind-mounted read-only into the container at
`/etc/caddy/certs`. Certificate rotation is the same three steps with a
new PEM pair. Reverting to the internal CA = unset `EDGE_TLS` and
restart. The `edge-ca` volume and `make ca-export` remain functional
either way (the internal CA is simply unused while `EDGE_TLS` points at
org PEMs). Renewal is manual — the airgap rule means nothing renews
itself, so track the org cert's expiry in whatever calendar the host's
backups live in.

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

## Portal design tokens

The build-free portal pages (`landing/index.html`, `authcode/index.html`)
link a vendored copy of `@infra/ui`'s plain-CSS design tokens,
`landing/tokens.css` — the same background/foreground/muted/border/primary/
danger custom properties the React frontends get via Tailwind, exported as
plain `:root` rules for consumers with no build step. It's vendored, not
`@import`ed live, following the same pattern as `scripts/bundle-lib.sh`:
`landing/tokens.css`'s header comment records the canonical source
(`nos-tromo/infra-ui`, pinned commit/tag) and the manual re-vendor step; CI
(`scripts/check-tokens-vendor.sh`) only checks that header is present and
well-formed, since infra-ui hadn't cut a release tag for this artifact as of
vendoring — there's no stable ref CI could fetch against.

It's served unauthenticated at the absolute path `/tokens.css` (a dedicated
Caddyfile matcher, `root * /srv/landing`) rather than a same-origin relative
link — `authcode`'s handle rewrites every `/auth-code/*` path to
`index.html`, so a relative link scoped under that prefix would never reach
a real file.

Each page still keeps a small local `<style>` block, but it now only
contains: aliases that reference the vendored tokens 1:1
(`--bg`/`--surface`/`--border`/`--text`/`--muted`/`--neutral` — true
duplicates of infra-ui's values, no longer hand-copied) plus a handful of
portal-owned tokens that are genuinely *not* shared with infra-ui:
`--accent` and `--down` use portal-tuned values distinct from
`--color-primary`/`--color-danger` (this unprocessed static HTML needs its
own AA-checked contrast against a plain white/near-black surface), and
`--ok` (the online-status green) has no infra-ui equivalent at all —
infra-ui ships no status-color tokens.

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
  landing/tokens.css            vendored infra-ui design tokens, served at /tokens.css
  authcode/index.html          one-time-code viewer page
  docker/
    compose.yaml               production shape — publishes :443 (+:80) only
    compose.override.yaml      dev overlay — whoami upstream + its route, relaxed conf.d mount
  scripts/
    bundle_images.sh           airgap bundler, sources vendored bundle-lib.sh
    bundle-lib.sh              vendored verbatim from nos-tromo/.github
    check-tokens-vendor.sh     verifies landing/tokens.css's vendoring header
    smoke.sh                   end-to-end contract test (portal redirect, login, header inject/strip)
  Makefile                     bespoke operator commands (data-plane/obs-plane style)
  VERSION                      one-line semver, read by the release-tag workflow
  docs/
    images.md                  pinned image references (source of truth for CI + compose)
    2026-07-23-edge-plane-design.md   design spec
  .env.example                 copy to .env; EDGE_HOST + Authelia secrets required
```
