# Audit events

What edge-plane contributes to the federation's data-protection audit log
(§76 BDSG as the reference standard): who logged in, who tried to, and every
change of who may log in and with which groups. The events are hash-chained
JSON lines (`audit/audit_event.py`, vendored from `nos-tromo/.github`) that
obs-plane routes into its separate audit store. The store, its retention,
the chain verifier and who may read the trail are obs-plane's — see
[obs-plane's `docs/audit.md`](../../obs-plane/docs/audit.md). This page covers
what edge-plane writes.

Two sources reach the audit lane from this repo:

| Source | Container | What |
|---|---|---|
| The gateway's access log | `caddy` | one line per request: account, path (query cut), status, client address, request id — see [identity-contract.md](identity-contract.md#request-id-and-access-log) |
| `auth-audit` | `auth-audit` | the events below, as hash chains with `service: edge-plane` |

## The auth-audit service

`auth-audit` runs `audit/edge_audit.py` (stdlib Python, mounted read-only)
on the pinned python image: as uid 65534, read-only root filesystem, all
capabilities dropped, no network at all. It reads two things, both through
read-only mounts, and writes only its stdout and its own state volume:

- Authelia's SQLite database on `edge-state`, opened with a read-only
  connection (`mode=ro`). Each query is short; no lock is held between them,
  so logins are never held up by the export.
- the `authelia/` directory, for `users.yml`. It is the directory, not the
  file: an editor that saves by renaming a new file over `users.yml` would
  leave a file bind pointing at the old one.

Every `AUDIT_POLL_INTERVAL` seconds (default 5) it exports new rows of the
authentication log and compares the users file with the version it saw last.
The account targets (`make totp`) write their events through this container
too, with `docker compose exec`, so every edge-plane chain starts in
`auth-audit` — the compose service obs-plane's verifier binds them to.

A one-shot `auth-audit-init` (only `CAP_CHOWN`, no network) hands the
`edge-audit-state` volume to uid 65534 on every `up`.

## Login attempts (`auth`)

Authelia records every first- and second-factor attempt in its storage table
`authentication_logs`. At its `info` log level it never logs a successful
login, so this table is the only record of one. `auth-audit` writes one event
per row, in row order.

| Authelia `auth_type` | `operation` |
|---|---|
| `1FA` (password) | `login.1fa` |
| `TOTP` | `login.2fa.totp` |
| `WebAuthn` | `login.2fa.webauthn` |
| `Duo` | `login.2fa.duo` |
| `Password` (as second factor) | `login.2fa.password` |
| `Passkey` | `login.passkey` |
| anything else | `login.other` (the raw type stays in `criteria.auth_type`) |

- **`outcome`** is Authelia's own verdict: `ok` when it accepted the attempt,
  `denied` otherwise — wrong credentials, an account that does not exist, or
  a ban. A **banned** attempt is `denied` with `criteria.banned: true`: after
  too many failures Authelia refuses the account (or address) for a while
  without checking the credentials, and records the attempt as unsuccessful.
- **`actor`** is `{user: <account>, via: "edge"}`: the account the attempt was
  for, as entered at the gateway's login page. On a `denied` event this is
  the account tried, not a proven identity. When the name entered matches no
  account, Authelia stores an empty name (so a password typed into the name
  field never reaches its log or this one); the event then has `user: null`
  and `criteria.unknown_account: true`.
- **`criteria`**:

  | Key | What |
  |---|---|
  | `log_id` | the row's id in `authentication_logs` (never reused) |
  | `attempted_at` | when Authelia recorded the attempt (UTC); the event's own `ts` is when it was exported |
  | `auth_type` | the factor, as Authelia names it |
  | `banned` | whether the attempt hit a ban |
  | `client_ip` | the client address the gateway forwarded |
  | `request_path`, `request_port` | the URL the login was for, as the login page reported it: the path only (the query string and fragment are dropped — they can carry search terms), and the port when it is explicit (`8443` is the Open WebUI site) |
  | `request_method` | that request's method |
  | `unknown_account` | `true` when no account matched |

**The client address is recorded.** It is the fact that tells the account
holder's own logins apart from someone else using the account — a
successful login from an unfamiliar address after a run of failures — and
that is what a record of logins is for. It adds nothing new to the audit lane:
the gateway's access log there already carries the client address of every
request, including each login request, just without the account (a login
request has no identity yet). The event links the two for login attempts
only.

There is no `request_id`: Authelia does not store the gateway's. The access
log line of the same login (`POST /auth/api/firstfactor`, same address, same
second) is its counterpart.

### Position, restarts and replaced databases

The id of the last exported row is kept in `edge-audit-state`
(`auth-export.json`), written after every event, so a restart continues right
after it. On the first start it exports what is already there. A crash
between writing an event and saving the position can repeat that one row
once; the repeat carries the same `log_id`.

The position also records which database it belongs to (the time of its
first schema migration). When the database is replaced — `make nuke`, or the
recovery in [user-accounts.md](user-accounts.md#secrets-and-the-first-start-storage-key)
that deletes `db.sqlite3` — or restored from an older backup, the log is
exported again from its first row, after one `admin` / `auth_log.rewind`
event (`criteria.reason`: `database_replaced` or `sequence_behind`;
`previous_last_id`). Re-exported rows reappear with the `log_id` they had;
none is skipped. `make nuke` keeps `edge-audit-state` for exactly this
reason.

A damaged position file stops the service (it does not guess): restore the
file, or remove it to export the whole log again.

### The table is Authelia's

`auth-audit` never writes to Authelia's database. Authelia 4.39.20 never
deletes from `authentication_logs` either: it grows by one row (a few hundred
bytes) per attempt, for as long as `edge-state` lives, holding account names
and client addresses outside the audit lane's retention. Pruning it is not
part of this change.

## Account changes (`admin`)

Who may log in, and to which group-gated routes (`admins` → `/grafana`,
`audit` → `/audit`), is set in two places, and both are recorded.

### Second factors: `make totp`

`make totp U=<user> [FORCE=1]` runs through `scripts/audit-admin.sh`:

1. It checks that `auth-audit` can write its audit stream, and refuses to
   change anything otherwise ("start the stack first").
2. It provisions the TOTP registration as before.
3. It writes one `admin` / `account.totp` event, as a chain of its own, with
   `docker compose exec` into `auth-audit`: `actor` `{user: <operator>, via:
   "cli"}` (the sudo user, else the login user), `target` the account,
   `criteria.force`. `outcome` is `ok` when the change succeeded and `error`
   when it failed — it may have been applied in part, so the attempt is
   recorded rather than dropped. The target then exits with the change's
   status.

When the change succeeded but its event could not be written, the target
fails loudly: record it by other means. Neither the URI nor the secret is
ever recorded.

`make user` only prints a password hash and changes no account; the edit of
`users.yml` that uses it is what is recorded (below). `make secret` is not
an account operation.

### Accounts, passwords and groups: `authelia/users.yml`

Creating an account, resetting a password, changing groups and removing an
account are edits of `authelia/users.yml`, and Authelia rewrites the file
itself when a user changes their own password. `auth-audit` compares every
new version with the previous one and writes one event per change of an
account, with `target` the account:

| `operation` | When | `criteria` |
|---|---|---|
| `account.create` | an account appears | `groups`, `disabled` |
| `account.delete` | an account disappears | — |
| `account.groups` | its groups change | `groups` (now), `added`, `removed` |
| `account.password` | its password hash changes (admin reset or the user's own change) | — |
| `account.disable`, `account.enable` | its `disabled` flag changes | — |
| `account.profile` | another attribute changes | `fields`: the names of the changed attributes |

The first version seen is recorded as a baseline instead: one
`account.baseline` event naming every account (`criteria.accounts`: their
number), one `account.baseline.group` per group naming its members, and
`account.baseline.disabled` naming the disabled accounts. Lists longer than
200 names continue in `<operation>.ids` events that point at their first
(`parent_event_id`).

What is never written: a password hash or any digest of it, e-mail
addresses, display names, or the value of any other attribute. Group names
and the disabled flag are recorded: they are who may access what. To detect
changes, `auth-audit` keeps per-account digests in `edge-audit-state`
(`users-file.json`), so a restart neither repeats nor misses a change.

A version of the file that the parser cannot read — it reads the
block-style YAML that `users.template.yml` and Authelia write, not anchors,
tags or multi-line values — is recorded once, as `account.unparsed` with
`criteria.file_sha256` and no content, if it is still there one round later
(so an editor's half-written file is not). Once the file can be read again,
everything that changed is itemised against the last readable version.

**These events carry no operator identity** (`actor` `{user: null, via:
"system"}`): a changed file does not say who changed it, and a password
change looks the same whether an admin reset it or the user changed it.
Host-level auditing of `authelia/users.yml` is what would supply the person;
that is a deploy runbook item, not part of this repo.

**Do not disable accounts with `disabled: true`.** On the pinned Authelia
(4.39.20), its rewrite of the file after any user's self-service password
change writes `disabled: false` for every account. The account can log in
again after the next Authelia restart. This was verified with a synthetic
account. Remove the account from the file instead. `auth-audit` records the
silent flip as `account.enable`.

## Chain events

Every chain starts with a `lifecycle` / `start` event, ends with
`lifecycle` / `shutdown` (a stop or restart of the container), and the
long-running one beats every 60 s (`lifecycle` / `heartbeat`). After its
start, the service writes `admin` / `config.audit` with its sources, poll
interval and the row it resumes after.

## Failure handling

- **An event cannot be written** (the container stream fails): the service
  stops with exit 1 before saving the position, so the row is exported after
  the restart (`restart: unless-stopped`). Logins themselves are never
  blocked — Authelia keeps recording them in its table.
- **The position cannot be saved**, or its file is damaged: the service
  stops with exit 1.
- **The database cannot be read for a round** (locked, missing during a
  replacement): it logs a warning and tries again the next round. The
  healthcheck fails when no round has read the database for three intervals
  (at least a minute); `make health` reports it.
- **The users file cannot be read** (missing, permissions): it logs a warning
  and records nothing for that round. A missing file is never taken for
  deleted accounts.
- **The account targets** refuse to change anything when `auth-audit` cannot
  record the change, and fail when the change ran but its event could not be
  written.

Operational messages go to the container's stderr and never carry account
names, attribute values or event content.

## Configuration

| Variable | Default | What |
|---|---|---|
| `AUDIT_POLL_INTERVAL` | `5` | seconds between rounds (1–3600) |

Fixed in `docker/compose.yaml`: `AUDIT_OUTPUT=container` (every process in
the container writes to its main stdout under one lock, so the lines of a
`docker compose exec` run land in the same log and never interleave),
`AUDIT_AUTHELIA_DB`, `AUDIT_USERS_FILE` and `AUDIT_STATE_DIR` (the mounts).
The account targets pass `AUDIT_CLI_USER` themselves.

## Checking it

```bash
make health                     # includes "auth-audit: exporting the authentication log"
make logs S=auth-audit          # the events (stdout) and operational messages (stderr)
docker compose --env-file .env -f docker/compose.yaml logs --no-log-prefix auth-audit \
  | docker compose --env-file .env -f docker/compose.yaml exec -T auth-audit python /app/edge_audit.py verify
```

`verify` checks the hash chains in the container's log, and `make smoke`
runs it after asserting that the smoke login was exported. The tests
(`python3 -m unittest discover -s audit/tests -t audit`) run the exporter
against synthetic databases built with the pinned Authelia's schema.
