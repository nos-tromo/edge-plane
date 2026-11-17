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
[user-accounts.md](user-accounts.md#user-accounts). `auth-audit` mounts the
`authelia/` directory and Authelia's `edge-state` volume read-only to record
account changes and login attempts ([audit.md](audit.md)).

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
| `EDGE_ANNOUNCEMENT_FILE` | `announcement.md`; empty → section hidden | Markdown file in `announcements/` rendered as the portal's announcement section — see below |
| `EDGE_PRIVACY_POLICY_LINK` | `false` | `true` adds a link to `/info/privacy` on the Authelia login page; set it once `info/privacy.md` exists — see [Portal information pages](#portal-information-pages) |
| `EXTRA_NO_PROXY` | unset | Extra hostnames to exempt from a corporate proxy — see below |
| `EDGE_SESSION_EXPIRATION` | `12h` | Absolute session lifetime — see [user-accounts.md](user-accounts.md#session-behaviour) |
| `EDGE_SESSION_INACTIVITY` | `4h` | Idle timeout before re-login |
| `EDGE_SESSION_REMEMBER_ME` | `2M` | Session lifetime when "remember me" is ticked |
| `EDGE_AUTH_POLICY` | `two_factor` (`make up-dev`: `one_factor`) | Authelia policy for every protected route: `two_factor` (password + TOTP) or `one_factor`. TOTP is admin-provisioned (`make totp`) — see [user-accounts.md](user-accounts.md#second-factor) |
| `DOCINT_EDGE_SECRET`, `NEXTEXT_EDGE_SECRET`, `TRANSLATOR_EDGE_SECRET`, `GHOSTWRITER_EDGE_SECRET`, `OPEN_WEBUI_EDGE_SECRET` | empty | Per-app secret the gateway sends as `X-Edge-Secret`; each must equal the same variable in that app's `.env`. Generate with `openssl rand -hex 32` — see [identity-contract.md](identity-contract.md#edge-secret) |
| `AUDIT_POLL_INTERVAL` | `5` | Seconds between `auth-audit`'s rounds over Authelia's authentication log and `authelia/users.yml` (1–3600) — see [audit.md](audit.md#configuration) |
| `EDGE_AUTH_RETENTION_DAYS` | `30` | Days after which `auth-retention` deletes Authelia's login records (1–3650, or `off` for development) — see [audit.md](audit.md#retention) |
| `EDGE_AUTH_RETENTION_INTERVAL_S` | `3600` | Seconds between two retention sweeps (60–86400) |
| `GRAFANA_EDGE_SECRET` | empty | The same for obs-plane's Grafana (`/grafana`); must equal the same variable in obs-plane's `.env` |
| `AUDIT_EDGE_SECRET` | none, required | The same for obs-plane's audit-trail viewer (`/audit`); must equal the same variable in obs-plane's `.env`, at least 32 characters. `make up` refuses to start while it is empty, and `/audit` answers 403 until it is set on both sides |

The `EDGE_SESSION_*` values use Authelia's duration syntax (`30m`, `12h`,
`1w`, `2M`, `1y`) and are rendered into `authelia/configuration.yml` by
its template filter, so the file itself stays untouched across updates.

`.env.example` leaves the three `AUTHELIA_*` values, `EDGE_HOST` and
`AUDIT_EDGE_SECRET` empty: `make up` refuses to start until they are set.
Generate the secrets with `openssl rand -hex 32`, and the optional `*_EDGE_SECRET`
values the same way.

## UI language

`RESPONSE_LANGUAGE` (`en` | `de`, default `en`) localizes the static
landing page (`landing/`) via Caddy's `templates` directive — the same
uniform env var used across the federation's other frontends. Set it in
`.env` and re-run `make up` (the container must be recreated, not just
restarted — `docker compose restart` reuses the old interpolated value).

The Authelia login portal is not affected by this variable — it
self-localizes from the browser's `Accept-Language` header (German
included), so no configuration is needed there.

## Portal announcement

The portal can show a block of Markdown between the app tiles and the
settings tiles, titled "Announcements" (German: "Neuigkeiten"), e.g. to
explain new features. Caddy renders it server-side with its `markdown`
template function; nothing is fetched at runtime.

The text comes from a file in `announcements/`, which is mounted read-only
into Caddy. `EDGE_ANNOUNCEMENT_FILE` names the file:

- **With a release:** edit `announcements/announcement.md` (the default) in
  the release PR. It ships with the release and replaces the host's copy on
  every airgap transfer.
- **On one host only:** place another `.md` file in `announcements/` (every
  name but `announcement.md` and the smoke-test fixture `smoke.md` is
  gitignored), set `EDGE_ANNOUNCEMENT_FILE` to its name, and
  run `make up` (the container must be recreated to see a changed variable).
- **Hide it:** set `EDGE_ANNOUNCEMENT_FILE=` (empty), or leave the selected
  file with nothing but HTML comments in it — the shipped default looks like
  that.

Edits to the selected file show on the next page load, without a restart.
The section is also hidden — never an error page — when the named file is
missing, unreadable, a directory, or not a `.md` file. The file must be readable by the
container (mode `0644`).

Content rules:

- GitHub-flavoured Markdown: lists, task lists, tables, strikethrough,
  autolinked URLs, fenced code, footnotes. Start headings at `##`; the
  section title is already the page's top-level heading.
- HTML comments (`<!-- ... -->`) are removed before rendering, so they can
  hold notes for other operators.
- Other raw HTML is passed through unchanged — Caddy's renderer does not
  sanitize it. Treat the file like configuration: no `<script>`, no inline
  event handlers. Every signed-in user sees it, on the same origin as all
  apps.
- No images or other resources from external URLs: the browser would try to
  fetch them, and airgapped clients cannot. Links are fine — they load only
  when clicked.
- Template syntax (`{{ ... }}`) is shown as text, never run: the file is read
  with `readFile`, not `include`, so it cannot pull Caddy's environment (the
  edge secrets) into the page.

## Portal information pages

Notices users must be able to read, such as a privacy notice, an AI notice
or an accessibility statement, are Markdown files in `info/`. Caddy serves
`info/<name>.md` at `https://<EDGE_HOST>/info/<name>`, **without login**: a
privacy notice is due before the login collects anything. The portal and
every information page end in a footer that links the five known pages,
each only when its file exists:

| File | Footer link (de / en) | Template |
|---|---|---|
| `info/privacy.md` | Datenschutz / Privacy | `info/privacy.example.md` |
| `info/ai.md` | KI-Hinweise / AI notice | `info/ai.example.md` |
| `info/accessibility.md` | Barrierefreiheit / Accessibility | `info/accessibility.example.md` |
| `info/terms.md` | Nutzungshinweise / Terms of use | `info/terms.example.md` |
| `info/help.md` | Hilfe / Help | `info/help.example.md` |

The texts are per host and never committed: everything in `info/` except
the `*.example.md` templates and the smoke-test fixture `smoke.md` is
gitignored. The templates are German drafts with `[placeholders]`. They
carry the release's defaults (retention periods, session lifetimes) next to
the variables that change them, and an operator note in an HTML comment.
They state no legal basis: the operator decides that (deploy ADR 0003).

To publish one:

1. Copy the template, e.g. `cp info/privacy.example.md info/privacy.md`, and
   fill in every placeholder. Check each value marked "(prüfen)" against this
   host's `.env` files.
2. Have the text approved, then reload the portal: the footer link appears
   on the next page load, without a restart.
3. For the privacy notice, set `EDGE_PRIVACY_POLICY_LINK=true` and run
   `make up`. The Authelia login page then links `/info/privacy`. Its
   acceptance dialog stays off: Authelia records an acceptance only in the
   browser's `localStorage`, so it proves nothing.

Any other `info/<name>.md` is served too, unlinked, e.g. a help page per
app linked from `help.md`. Content rules:

- A name is lowercase letters, digits and hyphens. Anything else, including
  the `*.example.md` templates, answers 404.
- Start with a `#` heading: it becomes the page title. The same Markdown
  rules as for the [announcement](#portal-announcement) apply: HTML comments
  are removed, raw HTML passes through, nothing external is loaded,
  template syntax stays text.
- **The pages are public on the network.** Put nothing in `info/` that only
  signed-in users may read.
- The files must be readable by the container (mode `0644`).

## Proxy bypass

`NO_PROXY`/`no_proxy` are set in `docker/compose.yaml` with the `edge-net`
upstream aliases and the private ranges. On hosts where the Docker client
config injects `HTTP_PROXY`/`HTTPS_PROXY` into every container, Caddy's Go
transport honors them and would otherwise send upstream requests for the
`edge-net` aliases through a corporate proxy that cannot resolve them.

To exempt additional hostnames, set `EXTRA_NO_PROXY` in `.env`; it is
appended to both lists, so it must start with a leading comma
(`EXTRA_NO_PROXY=,some-extra-host`).
