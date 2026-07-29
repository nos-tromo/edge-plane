# Rollout-readiness release — session tuning, password self-service, portal upgrade

Date: 2026-07-28
Status: approved (design); implementation pending

## Context

First small-user-number rollout of the federation. Three gaps block it, all
in this repo:

1. Users are logged out after short periods of inactivity.
2. Users cannot change their own passwords.
3. The landing page is a bare link list — no app status, descriptions,
   user settings, or support path — and carries the working-title branding.

Explicitly out of scope (deferred by decision): self-signup / IdP migration
(admin-provisioned accounts are acceptable at this scale), a dedicated
tickets app (a portal "report a problem" tile replaces it), and the
infra-ui AppHeader / theme-toggle rollout (separate work package).

## 1. Session tuning

`authelia/configuration.yml` sets no session lifetimes today, so Authelia
defaults apply: 1 h absolute expiration, **5 min inactivity** — the root
cause of the frequent logouts. Fix, in the session block:

```yaml
session:
  expiration: 12h
  inactivity: 4h
  remember_me: 2M
```

Rationale: a workday-plus absolute lifetime; inactivity long enough that a
meal break does not end the session; remember-me long enough that a
vacation does not (2 months, per review). Config-only; takes effect on
restart; no storage migration.

**Job-survival test** (manual, once, in dev): start a long-running app job,
force session expiry with temporarily short lifetimes, and record the
outcome. Expected per the forward-auth model: `forward_auth` gates each
request, so the server-side job completes and any established stream stays
open; the UI's next poll redirects to login. Document the observed
behaviour in the README.

## 2. Password self-service

Authelia 4.39 (pinned: 4.39.20) ships self-service password change in its
settings UI, enabled by default. Make the posture explicit in
`authelia/configuration.yml`:

```yaml
authentication_backend:
  file:
    path: /config/users.yml
  password_change:
    disable: false
  password_reset:
    disable: true
```

`password_reset` is disabled deliberately: reset requires the notifier, and
this deployment's filesystem notifier writes the "email" to a file only
operators can read — so the built-in "Forgot password?" affordance is a
dead end. Forgotten passwords stay admin-mediated (`make user`, replace the
hash in `users.yml`), and the portal says so.

**Verification item (RESOLVED 2026-07-28):** live verification showed the
password-change flow DOES demand an elevated-session one-time code, and
Authelia 4.39 offers no way to disable that (the only skip requires 2FA
enrollment, which itself requires elevation). Decision: deliver the code to
the user instead of the operator — a **code-viewer page** on the gateway,
recipient-matching variant:

- The filesystem notifier writes to a small dedicated compose volume
  (`edge-notify`) shared by Authelia (rw) and Caddy (ro) — the encrypted
  SQLite state stays unmounted from Caddy.
- Caddy serves an authenticated `/auth-code` page (`templates` directive,
  no new service) that reads the notification file and shows its content
  **only when the notification's `Recipient:` matches the signed-in user's
  `X-Auth-Email`** (case-insensitive); otherwise it says no code is
  pending for this account. The raw notification file must not be
  reachable through any route.
- The portal's user section links the page ("Get verification code").
- Codes are single-use and expire in 5 minutes; the file holds only the
  latest notification.
- **Writable user store (found in live verification):** `users.yml` was
  bind-mounted `:ro`; a password change then 500s on persist while still
  mutating Authelia's in-memory store (old password stops working until
  restart — silently inconsistent). Self-service change requires the
  mount read-write, plus `authentication_backend.file.watch: true` so
  operator-side edits (admin resets) are picked up without a restart.

**Ship-gate (replaces the old one):** verify with a second dev user that a
code requested by user A cannot be redeemed from user B's session
(cross-user binding). If that binding does not hold, the feature does not
ship — fall back to removing the settings link.

README gets a short "User accounts" section: provisioning, self-service
change via the settings UI, admin-mediated reset.

## 3. Portal upgrade

`landing/index.html` stays a single Caddy-templated static file — no build
step, no new container. Changes:

- **App tiles.** One card per app: name, one-line synthetic description,
  open link. Grafana's tile is shown to everyone; the existing admins-only
  ACL rule enforces access (Caddy templates cannot see group membership —
  accepted trade-off).
- **Live status.** Client-side JS issues same-origin `HEAD` requests to
  each app path (e.g. `/chorus/`) and renders an online/offline indicator
  per tile; refresh on load and every 60 s. No new endpoints or backend.
- **User section.** Signed-in-as (existing), an **inline password-change
  form** (revised 2026-07-29 — see below), a "Get verification code"
  fallback link to `/auth-code` (the code-viewer page, §2), logout
  (existing), and a note that password reset is handled by the
  administrator.

  **Inline password change (supersedes the `/auth/settings` link):** live
  use showed Authelia's settings SPA is a dead end — it has no navigation
  back to the portal, no config knob for one, and the stock Caddy image
  cannot rewrite its HTML. Instead the portal renders the form itself and
  drives Authelia's own (undocumented but live-verified) API: `POST
  /auth/api/user/session/elevation` (starts the flow, mails the OTC to the
  notifier), fetch `/auth-code` and read the machine-readable code marker
  (`<code id="otc">`, added to the viewer for this), `PUT
  /auth/api/user/session/elevation` `{"otc": ...}` (redeem), `POST
  /auth/api/change-password` `{"old_password","new_password"}`. The OTC is
  auto-redeemed: it proves mailbox access, and our "mailbox" is a page
  gated by the same session and recipient match, so auto-redeeming is
  security-equivalent to manual copying — the effective protection is the
  `old_password` requirement, the industry-standard bar. The
  `/auth/settings` link is dropped (no other settings feature is in use —
  no 2FA enrollment). Risk accepted: undocumented API may shift on an
  Authelia bump — guarded by a smoke-test cycle that exercises all three
  endpoints (change to a temp password and back), so upgrades fail in
  CI/staging, not production.
- **Report a problem.** A static tile with contact instructions. The
  contact value comes from a new optional env var `EDGE_SUPPORT_CONTACT`
  (rendered via the template filter; tile hidden when unset) so no real
  contact data is committed.
- **De-branding.** Neutral title/heading (default "Apps"); removes the
  working-title branding currently in the committed file. Keeps the
  existing `RESPONSE_LANGUAGE` en/de switch for all new strings.
- **Styling.** Dark theme matching the infra-ui token palette, copied as
  CSS variables (the portal does not consume the pnpm package). Ships
  dark-only; it pre-seeds the shared theme `localStorage` key to `dark` so
  the later infra-ui theme-toggle work has a consistent origin-wide
  default.

## Testing & release

- `scripts/smoke.sh` stays green — the strip → auth → inject header
  contract is untouched by all three changes.
- Add a portal smoke check: authenticated `GET /` returns 200 and contains
  the status-script marker.
- Code-viewer smoke checks: unauthenticated `/auth-code` redirects to the
  portal; no `/auth-code/...` path returns the raw notification file.
- Password-API smoke cycle (guards the undocumented endpoints the inline
  form uses): elevation start → OTC via `/auth-code` marker → redeem →
  change to a temp password → verify login → change back → verify original.
- Manual: password-change flow end-to-end via the code-viewer page;
  cross-user code-binding check (ship-gate, §2); job-survival test (§1).
- CI as usual (compose + Caddyfile validation, yamllint/shellcheck,
  bundle-lib drift check).
- Ships as one release: bump `VERSION`, merge, `release-tag` mints the tag.
