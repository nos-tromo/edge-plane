# The trusted-header identity contract

The load-bearing thing edge-plane does: turn an authenticated Authelia
session into a header the federation's apps already know how to consume,
and make it impossible for a client to forge that header.

Provisioning the accounts behind it is covered in
[user-accounts.md](user-accounts.md).

## The contract

Three apps (chorus, docint, Nextext) already implement an identical
seam: a configurable header (default `X-Auth-User`) resolved fail-closed
to a principal, with the upstream reverse proxy named as the intended
issuer. Nothing issued it in production before edge-plane. The flow:

1. Caddy **unconditionally strips** client-supplied `X-Auth-User`,
   `X-Auth-Email`, `X-Auth-Groups`, `X-Auth-Name`, and `Remote-*` headers
   on every request, before anything else — the `strip_identity` snippet
   in `caddy/Caddyfile`.
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
4. On every proxied request to an app or to one of obs-plane's two
   Grafanas, Caddy also sets **`X-Edge-Secret`** to that upstream's own
   secret and **`X-Request-ID`** to the request's id —
   see [Edge secret](#edge-secret) and
   [Request id and access log](#request-id-and-access-log). Client-supplied
   values of both are replaced.

Production publishes no host ports anywhere else in the federation, and
the gateway strips the identity headers before setting its own values —
verified by `scripts/smoke.sh`'s spoof test. That alone does not make the
headers trustworthy, though: the apps' backends also sit on the shared
`inference-net` and `data-net` networks, and the Grafanas share `edge-net`
with every app frontend, so any container there could call them directly
with forged headers. The edge secret closes that gap.

**`Authorization` pass-through rule**: the gateway owns `X-Auth-User` /
`Remote-*` and strips them from clients, but passes `Authorization`
through untouched. It is not part of the identity contract — upstreams
use it internally (Open WebUI issues its own JWTs after the
trusted-header handshake). Full rationale, including why trusted-header
was chosen over pushing token validation into four apps, is in
[2026-07-23-edge-plane-design.md](2026-07-23-edge-plane-design.md).

## Edge secret

Each app that consumes the identity headers gets its own secret, set in
edge-plane's `.env` (`CHORUS_EDGE_SECRET`, `DOCINT_EDGE_SECRET`,
`NEXTEXT_EDGE_SECRET`, `TRANSLATOR_EDGE_SECRET`, `OPEN_WEBUI_EDGE_SECRET`)
and, with the same value under the same name, in that app's own `.env`.
The gateway sends it as `X-Edge-Secret` on every request it proxies to
the app (the `header_up` lines in `caddy/Caddyfile`). The app's frontend
passes request headers through to its backend, and the backend:

- trusts `X-Auth-*` only when `X-Edge-Secret` matches its secret (a
  constant-time comparison), and otherwise ignores them — the request is
  then treated as carrying no identity at all (401 in production);
- rejects a configured secret shorter than 32 characters at startup;
- without a secret of its own, behaves as before and logs a startup
  warning that identity headers are trusted from any caller.

Per-app values mean a compromised app cannot impersonate users towards
another app.

Grafana cannot check a secret itself either, and obs-plane's two Grafanas
are reachable from every app frontend on `edge-net`. obs-plane therefore
puts a guard in front of each, in the same network namespace, with a
secret of its own:

- `GRAFANA_EDGE_SECRET` (`/grafana`) works like the apps' secrets: unset,
  the headers are trusted as before.
- `AUDIT_EDGE_SECRET` (`/audit`) is required. Without it, or with a
  mismatch, the audit-trail viewer refuses every request, so `/audit`
  answers 403 until both `.env` files carry the same value.

Open WebUI cannot check a secret itself either, and it does sit on
`inference-net`. open-webui-service therefore puts a small nginx in front
of it, in the same network namespace, which passes the identity headers on
only when the secret matches.

Direct service-to-service calls do not use the edge secret. docint's call
to Nextext authenticates with a service token instead (Nextext's
`NEXTEXT_SERVICE_TOKENS`, docint's `NEXTEXT_API_KEY`), which maps to a
fixed service principal and cannot carry a user's identity.

**Setting up or rotating.** Generate each value with `make secret`, put
it into edge-plane's `.env` and the receiving repo's `.env` (the app's, or
obs-plane's for the Grafanas), then recreate both
(`make up` in each; a plain restart keeps the old value). Order matters
only when an app starts enforcing for the first time: the gateway has to
send the secret before the app requires it, otherwise every request to
that app is unauthenticated. `deploy`'s `make up` starts the gateway last,
so a full bring-up has no such window.

## Request id and access log

Caddy writes one JSON access line per request to stdout (the
`access_log` snippet): method, path, status, duration, client address,
the authenticated account (`user`) and the request id (`uuid`). The
query string is cut from the URI and all request and response headers are
dropped, since they carry referers, cookies and the identity headers. The
same id goes to each app as `X-Request-ID`, so the gateway's line can be
matched with the app's own records of the request.

## Access control: the admins-group `/grafana` gate

Authentication says *who* you are; authorization says *where you may go*.
The latter lives in `authelia/configuration.yml`, not in Caddy.

The default policy is `deny`, with a final catch-all rule granting
`two_factor` (password plus TOTP; `EDGE_AUTH_POLICY`, see
[user-accounts.md](user-accounts.md#second-factor)) to every user for the
whole protected domain — so in practice any provisioned account reaches
any routed app. There is no `one_factor` exception, not even for the
`/auth-code` viewer. See [user-accounts.md](user-accounts.md#second-factor)
for why second factors are admin-provisioned. The exception is
Grafana: **`/grafana` is admins-group only**, expressed as a
match-then-explicit-deny rule pair.

```yaml
- domain: '{{ env "EDGE_HOST" }}'
  resources:
    - '(?i)^/grafana(/|$)'
  subject: 'group:admins'
  policy: '{{ env "EDGE_AUTH_POLICY" | default "two_factor" }}'
- domain: '{{ env "EDGE_HOST" }}'
  resources:
    - '(?i)^/grafana(/|$)'
  policy: deny
```

The patterns are case-insensitive (`(?i)`) because Caddy's `path` matcher
is. Without it, `/Grafana/` is routed to Grafana by Caddy but matches
neither Grafana rule here, so it falls through to the catch-all. Dot
segments, percent-encoding and repeated slashes need no such care:
Authelia normalizes the path before matching (verified for
`/chorus/../grafana/`, `//grafana/` and `/%67rafana/`).

Order matters — first match wins — and the pair is deliberate: `subject`
is part of a rule's **match** criteria, not a condition applied after
matching, so a non-admin does not fail the first rule, it simply skips
it. Without the explicit `deny` immediately behind it, a non-admin would
fall through to the catch-all rule and be let in. Collapsing
the pair into one rule, or reordering it, silently opens Grafana to every
account.

**`/audit` is the same construct for the group `audit`**: the audit-trail
viewer (obs-plane's `grafana-audit`) is open to its members only. `admins`
is deliberately not enough: operating the stack and reviewing who accessed
which data are separate duties, so give the `audit` group to the people
doing the latter, and to admins only by explicit decision. Reading the trail
is itself recorded, since every request to `/audit/` is in the gateway's
access log, which obs-plane routes into the audit lane.

Group membership is set per user in `authelia/users.yml`, the same place
that feeds `X-Auth-Groups` above.

The config file is rendered with `X_AUTHELIA_CONFIG_FILTERS=template`,
which is what lets those rules read `EDGE_HOST` from the environment.
