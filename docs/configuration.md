# Configuration

All configuration is environment-driven: copy `.env.example` to `.env` and
adjust per host. `.env` is gitignored and must never be committed.

Config that is not an environment variable lives mainly in two files, both
bind-mounted read-only: `caddy/Caddyfile` (routing, TLS, the identity-header
snippets) and `authelia/configuration.yml` (sessions, storage, access
control). The Caddyfile also imports `caddy/conf.d/*.caddy` for extra
routes: production ships a single intentionally empty file there, and
`make up-dev` swaps the whole directory for `caddy/conf.d.dev` (which
carries the `/whoami` route). The user database, `authelia/users.yml`, is
the one bind mount that is deliberately writable — see
[user-accounts.md](user-accounts.md#user-accounts).

## Environment variables

| Variable | Default | What it does |
|---|---|---|
| `EDGE_HOST` | — (required) | LAN hostname or IP users type into the browser. Must be a dotted hostname or an IP — see [tls-runbook.md](tls-runbook.md#edge_host-caveat) |
| `EDGE_NET` | `edge-net` | Name of the external `edge-net` Docker network to join |
| `AUTHELIA_SESSION_SECRET` | — (required) | Session signing secret |
| `AUTHELIA_STORAGE_ENCRYPTION_KEY` | — (required) | Encrypts Authelia's SQLite store. Must be final **before the first `make up`** — see [user-accounts.md](user-accounts.md#secrets-and-the-first-start-storage-key) |
| `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET` | — (required) | Signs the password-change elevation tokens |
| `EDGE_TLS` | unset → internal CA | Cert source. Set to the in-container PEM path pair for an org-issued certificate — see [tls-runbook.md](tls-runbook.md#option-b-org-issued-certificate) |
| `RESPONSE_LANGUAGE` | `en` | Landing-page UI language (`en` \| `de`) — see below |
| `EDGE_SUPPORT_CONTACT` | unset → tile hidden | Support contact rendered on the portal's "report a problem" tile. Never commit a real value |
| `EXTRA_NO_PROXY` | unset | Extra hostnames to exempt from a corporate proxy — see below |

The three `AUTHELIA_*` values in `.env.example` are insecure dev/CI
placeholders. Generate real ones with `make secret`.

## UI language

`RESPONSE_LANGUAGE` (`en` | `de`, default `en`) localizes the static
landing page (`landing/`) via Caddy's `templates` directive — the same
uniform env var used across the federation's other frontends. Set it in
`.env` and re-run `make up` (the container must be recreated, not just
restarted — `docker compose restart` reuses the old interpolated value).

The Authelia login portal is not affected by this variable — it
self-localizes from the browser's `Accept-Language` header (German
included), so no configuration is needed there.

## Proxy bypass

`NO_PROXY`/`no_proxy` are set in `docker/compose.yaml` with the `edge-net`
upstream aliases and the private ranges. On hosts where the Docker client
config injects `HTTP_PROXY`/`HTTPS_PROXY` into every container, Caddy's Go
transport honors them and would otherwise send upstream requests for the
`edge-net` aliases through a corporate proxy that cannot resolve them.

To exempt additional hostnames, set `EXTRA_NO_PROXY` in `.env`; it is
appended to both lists, so it must start with a leading comma
(`EXTRA_NO_PROXY=,some-extra-host`).
