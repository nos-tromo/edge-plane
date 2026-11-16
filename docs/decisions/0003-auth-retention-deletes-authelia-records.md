# 0003 — A separate service deletes Authelia's login records

Status: accepted (2026-11-14)
Date: 2026-11-14

## Context

Authelia 4.39.20 never deletes from the tables that log who signed in or
tried to, from which address: `authentication_logs`, `one_time_code`,
`identity_verification`, `totp_history` and the ban tables. They grow for as
long as `edge-state` lives. Every login attempt is also in the audit trail
(`auth-audit`, kept for `AUDIT_RETENTION` in obs-plane), so Authelia's copy
duplicates it outside any retention. A privacy notice could therefore state no
storage period for login records, which data-protection law requires.

Authelia has no setting or command for this. Its own reads of these tables
reach back minutes at most (`docs/audit.md#retention`).

## Decision

A fourth compose service, `auth-retention`, deletes the rows
`EDGE_AUTH_RETENTION_DAYS` (default 30) after they were recorded or ended:

- **The authentication log only after its export:** never past the position
  `auth-audit` keeps for this database (read-only mount of
  `edge-audit-state`). In doubt it deletes nothing from that table.
- **Every deletion recorded:** each batch is a `delete` audit event written
  before its transaction commits, in the service's own chain. obs-plane's
  verifier accepts `edge-plane/auth-retention` as an emitter.
- **Safe beside a running Authelia:** short transactions by primary key with
  pauses, because an attempt Authelia cannot insert within its busy timeout is
  never logged. `secure_delete` is on.
- **Fails closed on a new Authelia:** a schema guard (the verified schema
  version and columns) and a test pinning the verified image make an
  Authelia bump stop the sweep until its queries and schema have been
  re-checked.
- **Least privilege:** it runs as uid 0, because that is the owner of the
  database file and directory, with every capability dropped (no
  `DAC_OVERRIDE`), a read-only root filesystem and no network.

`auth-audit` stays as it was: read-only on Authelia's database, uid 65534.

## Alternatives considered

- **Give `auth-audit` the deletion.** Rejected. The recorder would gain write
  access to the source it records and would have to run as the database's
  owner (uid 0) instead of 65534. It would also break the rule that the
  exporter can never alter what it exports.
- **A host cron job running `sqlite3`.** Rejected. Airgap hosts would need
  the tool and the schedule set up by hand; nothing would record the
  deletions in the audit trail, and nothing would guard the schema.
- **Run Authelia with its own PUID, so the sweeper needs no uid 0.**
  Deferred. It changes the ownership of existing volumes on every host (a
  migration step) for little gain, since the sweeper holds no capabilities.
- **A notice period before deleting, as for chats in open-webui-service.**
  Rejected. Users have nothing to save from these tables, and every
  authentication-log row is in the audit trail before it can be deleted.

## Consequences

- An obs-plane release that lists `edge-plane/auth-retention` among its
  emitters must be deployed before or together with this one. Otherwise its
  chains are reported as `unlisted_source`.
- The first sweep on an existing host deletes the backlog older than the
  period at once (exported attempts only).
- Bumping Authelia includes re-verifying the sweeper (`docs/images.md`).
- Rows of accounts removed from `users.yml` that Authelia keeps, such as
  `totp_configurations` and `user_preferences`, are not covered. Those hold
  account state, not a log; deleting them would need the users file and is
  left for later.
