"""edge-plane's data-protection audit events: login attempts and account changes.

Authelia records every first- and second-factor attempt in its storage table
``authentication_logs``, but at its ``info`` log level it does not log a
successful login at all. This module turns those rows into the federation's
hash-chained audit events (``audit_event.py``) and records the account changes
operators make with edge-plane's account targets. Operator guide:
``docs/audit.md``.

Subcommands:

``serve``
    The long-running ``auth-audit`` service. Every ``AUDIT_POLL_INTERVAL``
    seconds it reads the rows Authelia appended since the last round from its
    SQLite database, opened read-only, and writes one ``auth`` event per row.
    The id of the last exported row is kept in ``AUDIT_STATE_DIR``, so a
    restart neither repeats nor skips rows. In the same rounds it records the
    account changes in Authelia's users file (``users_file.py``).
``check``
    Exit 0 when this container's audit stream can be written. The account
    targets run it before they change anything.
``admin OPERATION ACCOUNT [KEY=VALUE ...]``
    Write one ``admin`` event about an account change an operator made, as a
    chain of its own, into this container's log.
``health``
    Exit 0 when ``serve`` read the database recently (the compose healthcheck).
``verify``
    Check the hash chains in audit lines read from stdin, e.g. this container's
    ``docker compose logs`` (the smoke test). The audit store's own verifier
    lives in obs-plane.

Stdlib only; Python 3.12.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Final, NamedTuple, TextIO

from audit_event import STREAM_MARKER, Actor, AuditEmitter, AuditWriteError, Target, verify_chain
from audit_runtime import open_audit_stream
from users_file import UsersFileWatcher, load_users_state

#: The compose project: every chain this module writes names it as its service.
SERVICE: Final = "edge-plane"
DEFAULT_DATABASE: Final = "/authelia-state/db.sqlite3"
DEFAULT_USERS_FILE: Final = "/authelia-config/users.yml"
DEFAULT_STATE_DIR: Final = "/state"
DEFAULT_VERSION_FILE: Final = "/etc/edge-plane/VERSION"
#: Touched after every round that read the database; ``health`` checks its age.
DEFAULT_ALIVE_FILE: Final = "/tmp/auth-audit.alive"
DEFAULT_POLL_INTERVAL_S: Final = 5
MAX_POLL_INTERVAL_S: Final = 3600
#: Rows read per query. Each query holds a shared lock only while it runs, so
#: Authelia's writes are never held up by an export.
BATCH_ROWS: Final = 500
#: Rows per round at most, so a long first backlog still reports progress to
#: the healthcheck; the next round then starts at once.
ROUND_ROWS: Final = 10_000
#: How long a read waits for Authelia's write lock before the round is retried.
BUSY_TIMEOUT_S: Final = 5.0
STATE_FILE: Final = "auth-export.json"
STATE_VERSION: Final = 1

#: Authelia's authentication types (its ``internal/regulation/const.go``) and
#: the operation each becomes. Anything else is ``login.other``.
OPERATIONS: Final = {
    "1FA": "login.1fa",
    "Passkey": "login.passkey",
    "TOTP": "login.2fa.totp",
    "WebAuthn": "login.2fa.webauthn",
    "Duo": "login.2fa.duo",
    "Password": "login.2fa.password",
}
OTHER_OPERATION: Final = "login.other"
#: The account changes the account targets record (``scripts/audit-admin.sh``).
ADMIN_OPERATIONS: Final = frozenset({"account.totp"})
ADMIN_OUTCOMES: Final = ("ok", "error")

_SELECT_ATTEMPTS: Final = (
    "SELECT id, time, successful, banned, username, auth_type, remote_ip, request_uri, request_method "
    "FROM authentication_logs WHERE id > ? ORDER BY id LIMIT ?"
)
_DB_TIME: Final = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?")
_ACCOUNT: Final = re.compile(r"[^\x00-\x20\x7f-\x9f]{1,100}")
_CRITERION: Final = re.compile(r"([a-z][a-z0-9_]{0,31})=(.*)", re.DOTALL)
_VERSION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}")

LOG = logging.getLogger("auth-audit")


class StateError(RuntimeError):
    """Raised when the export position cannot be read or written."""


@dataclass(frozen=True)
class AuthAttempt:
    """One row of Authelia's ``authentication_logs`` table.

    Attributes:
        id: The row id. The column is ``AUTOINCREMENT``, so an id is never reused.
        time: When Authelia recorded the attempt, as stored.
        successful: Whether Authelia accepted the attempt.
        banned: Whether the account (or address) was banned at the time. Authelia
            then refuses the attempt without checking the credentials, and
            records it as unsuccessful.
        username: The account. Authelia leaves it empty when the name entered
            matches no account, so a mistyped secret never reaches the log.
        auth_type: The factor: ``1FA``, ``TOTP``, ``WebAuthn``, ...
        remote_ip: The client address the gateway forwarded.
        request_uri: The URL the login was for, as the login page reported it.
        request_method: That request's method, as the login page reported it.
    """

    id: int
    time: str
    successful: bool
    banned: bool
    username: str
    auth_type: str
    remote_ip: str | None
    request_uri: str | None
    request_method: str

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> AuthAttempt:
        """Build an attempt from a row of :data:`_SELECT_ATTEMPTS`.

        Args:
            row: The columns, in query order.

        Returns:
            The attempt.
        """
        rid, when, successful, banned, username, auth_type, remote_ip, request_uri, request_method = row
        return cls(
            id=int(rid),
            time="" if when is None else str(when),
            successful=bool(successful),
            banned=bool(banned),
            username="" if username is None else str(username),
            auth_type="" if auth_type is None else str(auth_type),
            remote_ip=None if remote_ip in (None, "") else str(remote_ip),
            request_uri=None if request_uri in (None, "") else str(request_uri),
            request_method="" if request_method is None else str(request_method),
        )


def iso_utc(value: str) -> str | None:
    """Normalize a timestamp as Authelia's SQLite driver stores it.

    Args:
        value: E.g. ``2026-01-31 12:00:00.123456789+00:00``. A value without
            an offset is taken as UTC (SQLite's ``CURRENT_TIMESTAMP``).

    Returns:
        The time as ``2026-01-31T12:00:00.123Z`` (the events' own format), or
        ``None`` when the value is not a timestamp.
    """
    match = _DB_TIME.fullmatch(value.strip())
    if match is None:
        return None
    day, clock, fraction, zone = match.groups()
    micros = (fraction or "")[:6].ljust(6, "0")
    if zone in (None, "Z"):
        zone = "+00:00"
    elif ":" not in zone:
        zone = f"{zone[:3]}:{zone[3:]}"
    try:
        moment = datetime.fromisoformat(f"{day}T{clock}.{micros}{zone}")
    except ValueError:
        return None
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def request_target(uri: str | None) -> tuple[str | None, int | None]:
    """Reduce the URL a login was for to its path and explicit port.

    The query string and fragment can carry search terms and other personal
    data, so they are dropped, as the gateway's access log drops them. The
    port tells the dedicated Open WebUI site (``:8443``) apart from the main one.

    Args:
        uri: The stored ``request_uri``, or ``None``.

    Returns:
        ``(path, port)``, each ``None`` when absent or unparseable.
    """
    if not uri:
        return None, None
    try:
        parts = urllib.parse.urlsplit(uri)
    except ValueError:
        return None, None
    try:
        port = parts.port
    except ValueError:
        port = None
    path = parts.path or ("/" if parts.netloc else "")
    return path or None, port


def attempt_criteria(attempt: AuthAttempt) -> dict[str, object]:
    """Collect the non-secret facts of one attempt for its event's ``criteria``.

    Args:
        attempt: The attempt.

    Returns:
        ``log_id`` (the row id), ``attempted_at``, ``auth_type``, ``banned``,
        and when known ``client_ip``, ``request_path``, ``request_port``,
        ``request_method``; ``unknown_account`` when Authelia recorded no account.
    """
    criteria: dict[str, object] = {
        "log_id": attempt.id,
        "attempted_at": iso_utc(attempt.time) or attempt.time,
        "auth_type": attempt.auth_type,
        "banned": attempt.banned,
    }
    if not attempt.username:
        criteria["unknown_account"] = True
    if attempt.remote_ip:
        criteria["client_ip"] = attempt.remote_ip
    path, port = request_target(attempt.request_uri)
    if path:
        criteria["request_path"] = path
    if port is not None:
        criteria["request_port"] = port
    if attempt.request_method:
        criteria["request_method"] = attempt.request_method
    return criteria


def emit_attempt(emitter: AuditEmitter, attempt: AuthAttempt) -> dict[str, object]:
    """Write the ``auth`` event of one attempt.

    ``outcome`` is Authelia's own verdict: ``ok`` when it accepted the attempt,
    ``denied`` otherwise (wrong credentials, unknown account, banned).

    Args:
        emitter: The started emitter.
        attempt: The attempt.

    Returns:
        The event as written.

    Raises:
        AuditWriteError: If the event could not be written.
    """
    return emitter.emit(
        "auth",
        OPERATIONS.get(attempt.auth_type, OTHER_OPERATION),
        Actor(attempt.username or None, "edge"),
        outcome="ok" if attempt.successful else "denied",
        criteria=attempt_criteria(attempt),
    )


@dataclass(frozen=True)
class ExportState:
    """Where the export stands.

    Attributes:
        database: The identity of the database the position refers to (see
            :func:`database_id`); ``None`` before the first round.
        last_id: The id of the last exported row.
    """

    database: str | None = None
    last_id: int = 0


def load_state(directory: Path) -> ExportState:
    """Read the export position.

    Args:
        directory: The state directory.

    Returns:
        The position; the start when there is none yet.

    Raises:
        StateError: If the state file exists but cannot be read or is not a
            state this version wrote. Exporting from the start would repeat
            every row, so the operator decides (``docs/audit.md``).
    """
    path = directory / STATE_FILE
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ExportState()
    except (OSError, UnicodeDecodeError) as exc:
        raise StateError(f"cannot read the export position {path}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise StateError(f"the export position {path} is not valid") from exc
    database = data.get("database") if isinstance(data, dict) else None
    last_id = data.get("last_id") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("version") != STATE_VERSION
        or not (database is None or isinstance(database, str))
        or not isinstance(last_id, int)
        or isinstance(last_id, bool)
        or last_id < 0
    ):
        raise StateError(f"the export position {path} is not valid")
    return ExportState(database=database, last_id=last_id)


def save_state(directory: Path, state: ExportState) -> None:
    """Persist the export position atomically and durably.

    Args:
        directory: The state directory.
        state: The position.

    Raises:
        StateError: If it could not be written.
    """
    path = directory / STATE_FILE
    temp = directory / f"{STATE_FILE}.tmp"
    text = json.dumps({"database": state.database, "last_id": state.last_id, "version": STATE_VERSION}) + "\n"
    try:
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise StateError(f"cannot write the export position {path}") from exc


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open Authelia's database without any chance of writing to it.

    Args:
        path: The database file.

    Returns:
        A connection in autocommit mode, so every query is its own short read
        transaction and no lock is held between queries.
    """
    uri = f"file:{urllib.parse.quote(str(path))}?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_S, isolation_level=None)


def database_id(conn: sqlite3.Connection) -> str | None:
    """Identify the database instance: when its first schema migration ran.

    A replaced database (``make nuke``, a deleted ``db.sqlite3``) restarts its
    row ids at 1, which a bare position would silently skip.

    Args:
        conn: The read-only connection.

    Returns:
        The identity, or ``None`` while Authelia has not created its schema yet.
    """
    try:
        row = conn.execute("SELECT applied FROM migrations ORDER BY id LIMIT 1").fetchone()
    except sqlite3.OperationalError:
        return None
    return None if row is None else str(row[0])


def last_allocated_id(conn: sqlite3.Connection) -> int:
    """Return the highest row id the log has ever handed out.

    Args:
        conn: The read-only connection.

    Returns:
        ``sqlite_sequence``'s value for the table; 0 before the first row.
    """
    row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'authentication_logs'").fetchone()
    return 0 if row is None else int(row[0])


class AuthLogExporter:
    """Exports new rows of ``authentication_logs`` as ``auth`` events."""

    def __init__(
        self,
        emitter: AuditEmitter,
        database: Path,
        state_dir: Path,
        state: ExportState,
        *,
        batch: int = BATCH_ROWS,
        round_rows: int = ROUND_ROWS,
        stop: threading.Event | None = None,
    ) -> None:
        """Prepare an exporter; nothing is read until :meth:`poll`.

        Args:
            emitter: The started emitter.
            database: Authelia's database file.
            state_dir: Where the position is kept.
            state: The position loaded from ``state_dir``.
            batch: Rows per query.
            round_rows: Rows per :meth:`poll` at most.
            stop: Set to end a running :meth:`poll` after the current row.
        """
        self._emitter = emitter
        self._database = database
        self._state_dir = state_dir
        self._state = state
        self._batch = batch
        self.round_rows = round_rows
        self._stop = stop or threading.Event()
        self._waiting: str | None = None

    @property
    def state(self) -> ExportState:
        """The current position."""
        return self._state

    def poll(self) -> int | None:
        """Export the rows added since the last round, up to ``round_rows``.

        Returns:
            The number of rows exported (``round_rows`` when more may be
            waiting), or ``None`` when the database is not there yet (Authelia
            creates it on its first start).

        Raises:
            AuditWriteError: If an event could not be written; the row stays
                unexported.
            StateError: If the position could not be saved.
            sqlite3.Error: If the database could not be read this round.
        """
        if not self._database.is_file():
            self._wait("no database file yet")
            return None
        conn = open_readonly(self._database)
        try:
            instance = database_id(conn)
            if instance is None:
                self._wait("no schema yet")
                return None
            if self._waiting is not None:
                LOG.info("database available, exporting")
                self._waiting = None
            self._reconcile(conn, instance)
            return self._export(conn)
        finally:
            conn.close()

    def _wait(self, reason: str) -> None:
        """Log once that the database is not ready.

        Args:
            reason: What is missing.
        """
        if self._waiting != reason:
            LOG.info("waiting for Authelia's database: %s", reason)
            self._waiting = reason

    def _save(self, state: ExportState) -> None:
        """Persist and adopt a new position.

        Args:
            state: The new position.
        """
        save_state(self._state_dir, state)
        self._state = state

    def _reconcile(self, conn: sqlite3.Connection, instance: str) -> None:
        """Check the position still refers to this database, and start over if not.

        Args:
            conn: The read-only connection.
            instance: The database's identity.
        """
        if self._state.database is None:
            self._save(ExportState(database=instance, last_id=self._state.last_id))
        elif self._state.database != instance:
            self._rewind("database_replaced", instance)
        elif last_allocated_id(conn) < self._state.last_id:
            # A restored backup hands out ids after its last row again, possibly
            # already to new rows: only a full re-export cannot skip one.
            self._rewind("sequence_behind", instance)

    def _rewind(self, reason: str, instance: str) -> None:
        """Record that the log is exported again from its first row, and do so.

        Rows exported before reappear with the ``log_id`` they had; nothing is
        skipped.

        Args:
            reason: ``database_replaced`` or ``sequence_behind``.
            instance: The database's identity.
        """
        LOG.warning("authentication log %s: exporting it again from its first row", reason.replace("_", " "))
        self._emitter.emit(
            "admin",
            "auth_log.rewind",
            Actor(None, "system"),
            criteria={"reason": reason, "previous_last_id": self._state.last_id},
        )
        self._save(ExportState(database=instance, last_id=0))

    def _export(self, conn: sqlite3.Connection) -> int:
        """Export rows after the position, oldest first, one event each.

        Args:
            conn: The read-only connection.

        Returns:
            The number of rows exported.
        """
        exported = 0
        while exported < self.round_rows and not self._stop.is_set():
            limit = min(self._batch, self.round_rows - exported)
            rows = conn.execute(_SELECT_ATTEMPTS, (self._state.last_id, limit)).fetchall()
            for row in rows:
                attempt = AuthAttempt.from_row(row)
                emit_attempt(self._emitter, attempt)
                self._save(ExportState(database=self._state.database, last_id=attempt.id))
                exported += 1
                if self._stop.is_set():
                    break
            if len(rows) < limit:
                break
        if exported:
            LOG.info("exported %d authentication log rows, up to row %d", exported, self._state.last_id)
        return exported


def read_version(path: Path) -> str:
    """Read the release this checkout is (the repo's ``VERSION`` file).

    Args:
        path: The mounted version file.

    Returns:
        The version, e.g. ``0.11.0``.

    Raises:
        ValueError: If the file is missing or holds no version.
    """
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read the edge-plane version from {path}") from exc
    if _VERSION.fullmatch(text) is None:
        raise ValueError(f"{path} holds no version")
    return text


def parse_interval(value: str | None) -> int:
    """Parse ``AUDIT_POLL_INTERVAL``.

    Args:
        value: Whole seconds, or ``None``/blank for the default.

    Returns:
        The interval in seconds.

    Raises:
        ValueError: If it is not a whole number from 1 to 3600.
    """
    if value is None or not value.strip():
        return DEFAULT_POLL_INTERVAL_S
    text = value.strip()
    if not text.isdigit() or not 1 <= int(text) <= MAX_POLL_INTERVAL_S:
        raise ValueError(f"AUDIT_POLL_INTERVAL must be whole seconds from 1 to {MAX_POLL_INTERVAL_S}")
    return int(text)


def parse_criteria(pairs: Sequence[str]) -> dict[str, object]:
    """Parse ``KEY=VALUE`` arguments of ``admin`` into event criteria.

    Args:
        pairs: E.g. ``["force=true"]``. ``true``/``false`` become booleans,
            whole numbers integers, anything else stays text.

    Returns:
        The criteria.

    Raises:
        ValueError: If a pair is malformed or a key repeats.
    """
    criteria: dict[str, object] = {}
    for pair in pairs:
        match = _CRITERION.fullmatch(pair)
        if match is None:
            raise ValueError(f"not a key=value criterion: {pair!r}")
        key, raw = match.groups()
        if key in criteria:
            raise ValueError(f"criterion {key!r} given twice")
        value: object = raw
        if raw in ("true", "false"):
            value = raw == "true"
        elif re.fullmatch(r"-?\d{1,18}", raw):
            value = int(raw)
        criteria[key] = value
    return criteria


class Settings(NamedTuple):
    """The paths the subcommands use, from the environment.

    Attributes:
        database: Authelia's SQLite database (``AUDIT_AUTHELIA_DB``).
        users_file: Authelia's users file (``AUDIT_USERS_FILE``).
        state_dir: Where positions are kept (``AUDIT_STATE_DIR``).
        version_file: The repo's ``VERSION`` file.
        alive_file: Touched after every round that read the database.
    """

    database: Path
    users_file: Path
    state_dir: Path
    version_file: Path
    alive_file: Path

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        """Read the settings, falling back to the container's paths.

        Args:
            environ: The process environment.

        Returns:
            The settings.
        """
        return cls(
            database=Path(environ.get("AUDIT_AUTHELIA_DB") or DEFAULT_DATABASE),
            users_file=Path(environ.get("AUDIT_USERS_FILE") or DEFAULT_USERS_FILE),
            state_dir=Path(environ.get("AUDIT_STATE_DIR") or DEFAULT_STATE_DIR),
            version_file=Path(environ.get("AUDIT_VERSION_FILE") or DEFAULT_VERSION_FILE),
            alive_file=Path(environ.get("AUDIT_ALIVE_FILE") or DEFAULT_ALIVE_FILE),
        )


def account_change_emitter(
    emitter: AuditEmitter,
) -> Callable[[str, Target | None, Mapping[str, object] | None, str | None], Mapping[str, object]]:
    """Bind the users-file watcher's events to an emitter.

    Args:
        emitter: The started emitter.

    Returns:
        A function writing one ``admin`` event by the system: a file change
        carries no operator identity.
    """

    def emit(
        operation: str,
        target: Target | None,
        criteria: Mapping[str, object] | None,
        parent_event_id: str | None,
    ) -> Mapping[str, object]:
        return emitter.emit(
            "admin",
            operation,
            Actor(None, "system"),
            target=target,
            criteria=criteria,
            parent_event_id=parent_event_id,
        )

    return emit


def serve(environ: Mapping[str, str], stop: threading.Event | None = None) -> int:
    """Run the exporter until SIGTERM/SIGINT (or ``stop``).

    Args:
        environ: The process environment.
        stop: Ends the loop when set; signal handlers set it in the container.

    Returns:
        The exit status: 0 after a clean stop, 1 when an event or the position
        could not be written (the container restarts and resumes), 2 on bad
        configuration.
    """
    settings = Settings.from_env(environ)
    try:
        interval = parse_interval(environ.get("AUDIT_POLL_INTERVAL"))
        version = read_version(settings.version_file)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    try:
        state = load_state(settings.state_dir)
    except StateError as exc:
        LOG.error("%s: restore it, or remove it to export the whole log again (docs/audit.md)", exc)
        return 1
    try:
        users_state = load_users_state(settings.state_dir)
    except (OSError, ValueError) as exc:
        LOG.error("%s: restore it, or remove it to record a new baseline (docs/audit.md)", exc)
        return 1
    try:
        stream = open_audit_stream(environ.get("AUDIT_OUTPUT"))
    except (OSError, ValueError) as exc:
        LOG.error("cannot open the audit stream: %s", exc)
        return 1
    stop = stop or threading.Event()
    emitter = AuditEmitter(SERVICE, version, stream=stream)
    status = 0
    try:
        emitter.start()
        emitter.emit(
            "admin",
            "config.audit",
            Actor(None, "system"),
            criteria={
                "sources": ["authelia.authentication_logs", "authelia.users_file"],
                "poll_interval_s": interval,
                "resume_after_id": state.last_id,
            },
        )
        exporter = AuthLogExporter(emitter, settings.database, settings.state_dir, state, stop=stop)
        users = UsersFileWatcher(account_change_emitter(emitter), settings.users_file, settings.state_dir, users_state)
        while not stop.is_set():
            exported = None
            try:
                exported = exporter.poll()
            except sqlite3.Error as exc:
                LOG.warning("authentication log not readable this round (%s); retrying", exc)
            if exported is not None:
                settings.alive_file.touch()
            users.poll()
            stop.wait(0 if exported == exporter.round_rows else interval)
    except (StateError, OSError) as exc:  # StateError first: it is a RuntimeError
        LOG.error("%s; stopping", exc)
        status = 1
    except (AuditWriteError, RuntimeError) as exc:
        LOG.error("an audit event could not be written (%s); stopping", exc)
        status = 1
    try:
        emitter.close()
    except (AuditWriteError, RuntimeError):
        LOG.error("the shutdown event could not be written")
        status = 1
    return status


def check(environ: Mapping[str, str]) -> int:
    """Check that an account change could be recorded right now.

    Args:
        environ: The process environment.

    Returns:
        0 when the audit stream opens and the version is readable, else 1.
    """
    try:
        read_version(Settings.from_env(environ).version_file)
        stream = open_audit_stream(environ.get("AUDIT_OUTPUT"))
    except (OSError, ValueError) as exc:
        print(f"auth-audit cannot record events: {exc}", file=sys.stderr)
        return 1
    if stream is not None:
        stream.close()
    return 0


def admin(
    environ: Mapping[str, str],
    operation: str,
    account: str,
    outcome: str,
    pairs: Sequence[str],
) -> int:
    """Record one account change an operator made, as a chain of its own.

    Args:
        environ: The process environment; ``AUDIT_CLI_USER`` names the operator.
        operation: One of :data:`ADMIN_OPERATIONS`.
        account: The account changed.
        outcome: ``ok``, or ``error`` when the change failed (it may have been
            applied in part).
        pairs: ``KEY=VALUE`` criteria, never a secret.

    Returns:
        0 when the event was written, 1 when it was not, 2 on bad arguments.
    """
    try:
        if operation not in ADMIN_OPERATIONS:
            raise ValueError(f"unknown admin operation {operation!r}")
        if _ACCOUNT.fullmatch(account) is None:
            raise ValueError("the account name is empty, too long or contains spaces or control characters")
        if outcome not in ADMIN_OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        criteria = parse_criteria(pairs)
        version = read_version(Settings.from_env(environ).version_file)
    except ValueError as exc:
        print(f"auth-audit admin: {exc}", file=sys.stderr)
        return 2
    try:
        stream = open_audit_stream(environ.get("AUDIT_OUTPUT"))
    except (OSError, ValueError) as exc:
        print(f"auth-audit cannot record events: {exc}", file=sys.stderr)
        return 1
    emitter = AuditEmitter(SERVICE, version, stream=stream, heartbeat_interval_s=0)
    try:
        emitter.start()
        emitter.emit(
            "admin",
            operation,
            Actor(environ.get("AUDIT_CLI_USER") or None, "cli"),
            outcome=outcome,
            target=Target(kind="account", ids=[account], count=1),
            criteria=criteria or None,
        )
        emitter.close()
    except (AuditWriteError, RuntimeError) as exc:
        print(f"auth-audit could not write the event: {exc}", file=sys.stderr)
        return 1
    return 0


def health(environ: Mapping[str, str], now: float | None = None) -> int:
    """Report whether ``serve`` read the database recently.

    Args:
        environ: The process environment.
        now: The current time, for tests.

    Returns:
        0 when the last successful round is at most three intervals (and at
        least a minute) old, else 1.
    """
    try:
        interval = parse_interval(environ.get("AUDIT_POLL_INTERVAL"))
        age = (time.time() if now is None else now) - Settings.from_env(environ).alive_file.stat().st_mtime
    except (OSError, ValueError):
        return 1
    return 0 if age <= max(3 * interval, 60) else 1


def verify(lines: Iterable[str], out: TextIO) -> int:
    """Check the hash chains of the audit lines among ``lines``.

    Args:
        lines: Log lines; only those carrying the audit marker are read.
        out: Where the summary goes.

    Returns:
        0 when there were events and every chain verified, else 1.
    """
    marker = f'"stream":"{STREAM_MARKER}"'
    events: list[object] = []
    for line in lines:
        if marker not in line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            events.append(line)  # reported as a schema problem
    report = verify_chain(events)
    print(f"{report.events} audit events in {len(report.heads)} chains, {len(report.problems)} problems", file=out)
    for problem in report.problems:
        print(f"  {problem.kind}: {problem.service} {problem.instance} seq {problem.seq}: {problem.detail}", file=out)
    return 0 if report.events and report.ok else 1


def _install_stop_handlers(stop: threading.Event) -> None:
    """End ``serve`` cleanly on SIGTERM (``docker stop``) and SIGINT.

    As PID 1, the process would otherwise ignore SIGTERM.

    Args:
        stop: The event ``serve`` waits on.
    """

    def handler(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch a subcommand.

    Args:
        argv: The arguments, without the program name.

    Returns:
        The exit status.
    """
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="edge_audit.py", description="edge-plane audit events (docs/audit.md)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="export Authelia's authentication log until stopped")
    commands.add_parser("check", help="exit 0 when this container can record audit events")
    commands.add_parser("health", help="exit 0 when serve read the database recently")
    commands.add_parser("verify", help="check the hash chains of the audit lines on stdin")
    record = commands.add_parser("admin", help="record one account change")
    record.add_argument("operation", help=f"one of {', '.join(sorted(ADMIN_OPERATIONS))}")
    record.add_argument("account", help="the account changed")
    record.add_argument("criteria", nargs="*", metavar="KEY=VALUE", help="non-secret facts of the change")
    record.add_argument("--outcome", choices=ADMIN_OUTCOMES, default="ok")
    args = parser.parse_args(argv)
    if args.command == "serve":
        stop = threading.Event()
        _install_stop_handlers(stop)
        return serve(os.environ, stop)
    if args.command == "check":
        return check(os.environ)
    if args.command == "health":
        return health(os.environ)
    if args.command == "verify":
        return verify(sys.stdin, sys.stdout)
    return admin(os.environ, args.operation, args.account, args.outcome, args.criteria)


if __name__ == "__main__":
    sys.exit(main())
