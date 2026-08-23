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
[2026-07-23-edge-plane-design.md](2026-07-23-edge-plane-design.md).

## Access control: the admins-group `/grafana` gate

Authentication says *who* you are; authorization says *where you may go*.
The latter lives in `authelia/configuration.yml`, not in Caddy.

The default policy is `deny`, with a final catch-all rule granting
`one_factor` to every user for the whole protected domain — so in
practice any provisioned account reaches any routed app. The exception is
Grafana: **`/grafana` is admins-group only**, expressed as a
match-then-explicit-deny rule pair.

```yaml
- domain: '{{ env "EDGE_HOST" }}'
  resources:
    - '^/grafana(/|$)'
  subject: 'group:admins'
  policy: one_factor
- domain: '{{ env "EDGE_HOST" }}'
  resources:
    - '^/grafana(/|$)'
  policy: deny
```

Order matters — first match wins — and the pair is deliberate: `subject`
is part of a rule's **match** criteria, not a condition applied after
matching, so a non-admin does not fail the first rule, it simply skips
it. Without the explicit `deny` immediately behind it, a non-admin would
fall through to the catch-all `one_factor` rule and be let in. Collapsing
the pair into one rule, or reordering it, silently opens Grafana to every
account.

Group membership is set per user in `authelia/users.yml`, the same place
that feeds `X-Auth-Groups` above.

The config file is rendered with `X_AUTHELIA_CONFIG_FILTERS=template`,
which is what lets those rules read `EDGE_HOST` from the environment.
