# User accounts and sessions

Everything an operator needs to provision, recover and reason about
accounts on the edge gateway: the secrets that must be right before the
first start, how users are created and how they change their own
passwords, and how long a session lasts.

Authelia is the identity provider; what the gateway does with an
identity once Authelia has established it is a separate contract — see
[identity-contract.md](identity-contract.md).

## Secrets, and the first-start storage key

Generate production secrets with:

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
  docker.io/authelia/authelia:<pinned tag, see images.md> -c 'rm -f /data/db.sqlite3'
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

## Session behaviour

Sessions last 12 h (4 h inactivity timeout; "remember me" 2 months).
On expiry, in-flight requests/streams are not severed — forward-auth gates
each new request — so server-side jobs keep running; the next UI request
redirects to the login portal, and the page resumes after re-login.
Verified with a shortened 2 m/1 m session: a request already authorized and
in progress (a slow ~200 s upload, started before expiry) completed
normally with the injected `X-Auth-User` header intact, while a fresh
request issued afterward on the same now-expired session cookie received a
302 to `/auth`.
