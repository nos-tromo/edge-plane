"""edge-plane's ``auth-retention`` service: deletes Authelia's records after a period.

Authelia never deletes the rows that log who signed in or tried to, from which
address (``auth_sweep.py`` lists the tables and their rules). This service
deletes them ``EDGE_AUTH_RETENTION_DAYS`` after they were recorded or ended,
the authentication log only once ``auth-audit`` exported it. Every deletion
is a ``delete`` audit event, written before its transaction commits. Operator
guide: ``docs/audit.md#retention``.

Subcommands:

``serve``
    The long-running service: sweeps every ``EDGE_AUTH_RETENTION_INTERVAL_S``
    seconds and writes a status file for ``health``.
``dry-run [--days N|off]``
    Show, per table, what a period would delete now, through a read-only
    connection. Nothing is deleted or recorded; no name or address is shown.
``schema``
    Exit 0 when the database is the schema this service was verified against.
``health``
    Exit 0 when the sweep loop reported recently and no table is refused.
``verify``
    Check the hash chains in audit lines read from stdin.

Stdlib only; Python 3.12.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NamedTuple, TextIO

from audit_event import AuditEmitter, AuditWriteError
from audit_runtime import open_audit_stream
from auth_sweep import (
    AUTH_LOG,
    RULES,
    SYSTEM,
    TABLES,
    VERIFIED_SCHEMA_VERSIONS,
    Plan,
    SchemaRefused,
    Sweeper,
    open_database,
    preview,
    schema_problems,
)
from edge_audit import (
    DEFAULT_DATABASE,
    DEFAULT_VERSION_FILE,
    SERVICE,
    database_id,
    install_stop_handlers,
    read_version,
    verify,
)

LOG = logging.getLogger("auth-retention")

DEFAULT_STATE_DIR: Final = "/state"
DEFAULT_STATUS_FILE: Final = "/tmp/auth-retention-status.json"
DEFAULT_DAYS: Final = 30
MAX_DAYS: Final = 3_650
DEFAULT_INTERVAL_S: Final = 3_600
MIN_INTERVAL_S: Final = 60
MAX_INTERVAL_S: Final = 86_400
#: How often the loop wakes to write its status, at most.
TICK_S: Final = 60
#: The pause before the next round when a sweep stopped at its batch limit.
CONTINUE_S: Final = 5
#: How old the status file may be before ``health`` fails.
STATUS_STALE_S: Final = 180
STATUS_VERSION: Final = 1


def parse_days(value: str | None) -> int | None:
    """Parse ``EDGE_AUTH_RETENTION_DAYS``.

    Args:
        value: Whole days, ``off``, or ``None``/blank for the default.

    Returns:
        The period, or ``None`` when off.

    Raises:
        ValueError: If it is neither ``off`` nor a whole number from 1 to :data:`MAX_DAYS`.
    """
    text = (value or "").strip().lower()
    if not text:
        return DEFAULT_DAYS
    if text == "off":
        return None
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= MAX_DAYS:
        raise ValueError(f"EDGE_AUTH_RETENTION_DAYS must be whole days from 1 to {MAX_DAYS}, or off")
    return int(text)


def parse_interval(value: str | None) -> int:
    """Parse ``EDGE_AUTH_RETENTION_INTERVAL_S``.

    Args:
        value: Whole seconds, or ``None``/blank for the default.

    Returns:
        The interval.

    Raises:
        ValueError: If it is not a whole number from :data:`MIN_INTERVAL_S` to :data:`MAX_INTERVAL_S`.
    """
    text = (value or "").strip()
    if not text:
        return DEFAULT_INTERVAL_S
    if not text.isascii() or not text.isdigit() or not MIN_INTERVAL_S <= int(text) <= MAX_INTERVAL_S:
        raise ValueError(
            f"EDGE_AUTH_RETENTION_INTERVAL_S must be whole seconds from {MIN_INTERVAL_S} to {MAX_INTERVAL_S}"
        )
    return int(text)


class Settings(NamedTuple):
    """The service's settings, from the environment.

    Attributes:
        database: Authelia's database (``AUDIT_AUTHELIA_DB``).
        state_dir: ``auth-audit``'s state directory, read-only (``AUDIT_STATE_DIR``).
        version_file: The repo's ``VERSION`` file (``AUDIT_VERSION_FILE``).
        status_file: Where ``serve`` reports to ``health`` (``AUTH_RETENTION_STATUS_FILE``).
        days: The period, ``None`` when off.
        interval_s: Seconds between sweeps.
    """

    database: Path
    state_dir: Path
    version_file: Path
    status_file: Path
    days: int | None
    interval_s: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        """Read the settings, falling back to the container's paths.

        Args:
            environ: The process environment.

        Returns:
            The settings.

        Raises:
            ValueError: If a value is out of range.
        """
        return cls(
            database=Path(environ.get("AUDIT_AUTHELIA_DB") or DEFAULT_DATABASE),
            state_dir=Path(environ.get("AUDIT_STATE_DIR") or DEFAULT_STATE_DIR),
            version_file=Path(environ.get("AUDIT_VERSION_FILE") or DEFAULT_VERSION_FILE),
            status_file=Path(environ.get("AUTH_RETENTION_STATUS_FILE") or DEFAULT_STATUS_FILE),
            days=parse_days(environ.get("EDGE_AUTH_RETENTION_DAYS")),
            interval_s=parse_interval(environ.get("EDGE_AUTH_RETENTION_INTERVAL_S")),
        )


@dataclass
class TableStatus:
    """How one table's retention stands.

    Attributes:
        state: ``off``; ``pending`` (not swept yet); ``ok``; ``waiting`` (no
            database or schema yet); ``held`` (the authentication log waits for
            ``auth-audit``'s export); ``error`` (the last attempt failed and is
            retried every round); or ``refused`` (it will not run until fixed).
        last_ok: When it last ran to the end, in seconds since the epoch.
        reason: Why it is held or refused.
    """

    state: str
    last_ok: float | None = None
    reason: str | None = None


@dataclass
class Status:
    """What ``serve`` reports to ``health``.

    Attributes:
        written_at: When it was written.
        started_at: When ``serve`` started.
        interval_s: Seconds between sweeps.
        tables: By table name.
    """

    written_at: float
    started_at: float
    interval_s: int
    tables: dict[str, TableStatus] = field(default_factory=dict)


def write_status(path: Path, status: Status) -> None:
    """Replace the status file atomically.

    Args:
        path: The status file.
        status: The status.

    Raises:
        OSError: If it cannot be written.
    """
    data = {
        "version": STATUS_VERSION,
        "written_at": status.written_at,
        "started_at": status.started_at,
        "interval_s": status.interval_s,
        "tables": {
            name: {"state": table.state, "last_ok": table.last_ok, "reason": table.reason}
            for name, table in status.tables.items()
        },
    }
    temp = path.with_name(f"{path.name}.tmp")
    temp.write_text(json.dumps(data) + "\n", encoding="utf-8")
    temp.replace(path)


def stale_after(interval_s: int) -> float:
    """How long a table may go without a completed sweep and still count as healthy.

    Args:
        interval_s: Seconds between sweeps.

    Returns:
        Three intervals, plus a minute for the sweep itself.
    """
    return 3 * interval_s + 60


def health(settings: Settings, now: float | None = None) -> int:
    """Report whether the loop reported recently and every table is swept.

    Args:
        settings: The settings.
        now: The current time, for tests.

    Returns:
        0 when healthy, else 1 (with the reason on stderr).
    """
    moment = time.time() if now is None else now
    try:
        data = json.loads(settings.status_file.read_text(encoding="utf-8"))
        written_at = float(data["written_at"])
        started_at = float(data["started_at"])
        interval_s = int(data["interval_s"])
        tables = data["tables"]
        if not isinstance(tables, dict):
            raise TypeError("tables")
    except (OSError, ValueError, KeyError, TypeError):
        print("auth-retention: no status yet", file=sys.stderr)
        return 1
    if moment - written_at > STATUS_STALE_S:
        print("auth-retention: the sweep loop has not reported recently", file=sys.stderr)
        return 1
    healthy = True
    for name, raw in sorted(tables.items()):
        state = raw.get("state") if isinstance(raw, dict) else None
        if state == "off":
            continue
        if state == "refused":
            print(f"auth-retention: {name} refused ({raw.get('reason')})", file=sys.stderr)
            healthy = False
            continue
        last_ok = raw.get("last_ok") if isinstance(raw, dict) else None
        since = last_ok if isinstance(last_ok, int | float) else started_at
        if moment - since > stale_after(interval_s):
            print(f"auth-retention: {name} has not been swept recently ({state})", file=sys.stderr)
            healthy = False
    return 0 if healthy else 1


class Rounds:
    """The work of ``serve``: one sweep over every table, and its status."""

    def __init__(self, emitter: AuditEmitter, settings: Settings, stop: threading.Event) -> None:
        """Prepare the rounds; nothing is swept until :meth:`run`.

        Args:
            emitter: The started emitter.
            settings: The settings.
            stop: Ends a sweep after its current batch when set.
        """
        self._emitter = emitter
        self._settings = settings
        self._stop = stop
        initial = "off" if settings.days is None else "pending"
        self.tables: dict[str, TableStatus] = {name: TableStatus(initial) for name in TABLES}

    def run(self, now: float) -> bool:
        """Sweep every table once.

        Args:
            now: The round's time, in seconds since the epoch.

        Returns:
            ``False`` when the sweep stopped at its batch limit, so the next
            round should follow soon.

        Raises:
            AuditWriteError: If a record could not be written.
            RuntimeError: If the emitter is closed.
        """
        days = self._settings.days
        if days is None:
            return True
        sweeper = Sweeper(self._emitter, self._settings.database, self._settings.state_dir, days, stop=self._stop)
        try:
            result = sweeper.sweep(datetime.fromtimestamp(now, UTC))
        except SchemaRefused as exc:
            for name in TABLES:
                self._refuse(name, "schema", str(exc))
            return True
        except sqlite3.Error as exc:
            LOG.warning("sweep failed (%s); retrying next round", exc)
            for name in TABLES:
                self._fail(name)
            return True
        if not result.ready:
            for name in TABLES:
                self.tables[name] = TableStatus("waiting", last_ok=self.tables[name].last_ok)
            LOG.info("waiting for Authelia's database")
            return True
        for name in TABLES:
            table = result.tables.get(name)
            if table is None:
                continue  # not reached: the sweep stopped early
            if table.refused:
                self._refuse(name, table.refused, f"{name}: a stored time does not parse")
            elif table.held_reason or table.held:
                self._hold(name, table.held_reason or "not_exported")
            else:
                self._ok(name, now)
        return result.complete

    def _ok(self, name: str, now: float) -> None:
        """Note a completed sweep, and record the end of a refusal or hold.

        Args:
            name: The table.
            now: The round's time.
        """
        status = self.tables[name]
        if status.state in ("refused", "held"):
            LOG.info("%s: sweeping again", name)
            self._emitter.emit("admin", "retention.resumed", SYSTEM, criteria={"store": name})
        self.tables[name] = TableStatus("ok", last_ok=now)

    def _fail(self, name: str) -> None:
        """Note a failed attempt; it is retried next round.

        Args:
            name: The table.
        """
        status = self.tables[name]
        if status.state not in ("refused", "held"):
            self.tables[name] = TableStatus("error", last_ok=status.last_ok)

    def _hold(self, name: str, reason: str) -> None:
        """Note that old rows wait for ``auth-audit``'s export, and record that once.

        Args:
            name: The table.
            reason: Why: ``not_exported`` or an export-position reason.
        """
        status = self.tables[name]
        if status.state != "held" or status.reason != reason:
            LOG.warning("%s: rows past the period are kept until auth-audit has exported them (%s)", name, reason)
            self._emitter.emit("admin", "retention.held", SYSTEM, criteria={"store": name, "reason": reason})
        self.tables[name] = TableStatus("held", last_ok=status.last_ok, reason=reason)

    def _refuse(self, name: str, reason: str, detail: str) -> None:
        """Stop sweeping a table until the cause is fixed, and record that once.

        Args:
            name: The table.
            reason: ``schema`` or ``time_format``.
            detail: What is wrong, by table and column name only.
        """
        status = self.tables[name]
        if status.state != "refused" or status.reason != reason:
            LOG.error("%s: retention refused, nothing is deleted from it: %s", name, detail)
            self._emitter.emit(
                "admin", "retention.refused", SYSTEM, outcome="error", criteria={"store": name, "reason": reason}
            )
        self.tables[name] = TableStatus("refused", last_ok=status.last_ok, reason=reason)


def config_criteria(settings: Settings) -> dict[str, object]:
    """The facts of the configuration, for the ``config.audit`` record.

    Args:
        settings: The settings.

    Returns:
        The criteria.
    """
    return {
        "stores": list(TABLES),
        "retention_days": settings.days,
        "interval_s": settings.interval_s,
        "age_from": {rule.table: rule.age_from for rule in RULES},
        "auth_log_after_export": True,
        "verified_schema_versions": sorted(VERIFIED_SCHEMA_VERSIONS),
    }


def serve(settings: Settings, audit_output: str | None, stop: threading.Event | None = None) -> int:
    """Sweep until SIGTERM/SIGINT (or ``stop``).

    Args:
        settings: The settings.
        audit_output: ``AUDIT_OUTPUT``.
        stop: Ends the loop when set; signal handlers set it in the container.

    Returns:
        The exit status: 0 after a clean stop, 1 when a record could not be
        written (the container restarts; nothing is deleted until it can
        record), 2 on bad configuration.
    """
    try:
        version = read_version(settings.version_file)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    try:
        stream = open_audit_stream(audit_output)
    except (OSError, ValueError) as exc:
        LOG.error("cannot open the audit stream (%s); nothing is deleted", exc)
        return 1
    stop = stop or threading.Event()
    emitter = AuditEmitter(SERVICE, version, stream=stream)
    status = 0
    started_at = time.time()
    try:
        emitter.start()
        emitter.emit("admin", "config.audit", SYSTEM, criteria=config_criteria(settings))
        if settings.days is None:
            LOG.warning("retention is off: Authelia's records are never deleted (EDGE_AUTH_RETENTION_DAYS=off)")
        else:
            LOG.info("Authelia's records are deleted %d days after they were recorded or ended", settings.days)
        rounds = Rounds(emitter, settings, stop)
        next_sweep = 0.0
        while not stop.is_set():
            now = time.time()
            if settings.days is not None and now >= next_sweep:
                complete = rounds.run(now)
                next_sweep = time.time() + (settings.interval_s if complete else CONTINUE_S)
            try:
                write_status(settings.status_file, Status(time.time(), started_at, settings.interval_s, rounds.tables))
            except OSError as exc:
                LOG.warning("cannot write the status file (%s)", exc)
            stop.wait(max(0.0, min(TICK_S, next_sweep - time.time())) if settings.days is not None else TICK_S)
    except (AuditWriteError, RuntimeError) as exc:
        LOG.error("an audit record could not be written (%s); stopping, nothing more is deleted", exc)
        status = 1
    try:
        emitter.close()
    except (AuditWriteError, RuntimeError):
        LOG.error("the shutdown event could not be written")
        status = 1
    return status


def _describe(found: Plan | str, held_reason: str | None) -> str:
    """One table's line in the dry run.

    Args:
        found: The table's plan, or ``time_format``.
        held_reason: Why the whole authentication log is held, if it is.

    Returns:
        The line's counts, never a name or an address.
    """
    if isinstance(found, str):
        return "refused: a stored time does not parse; nothing would be deleted"
    text = f"would delete {len(found.due)}, keep {found.kept}"
    if found.held:
        why = held_reason or "not exported by auth-audit yet"
        text += f", hold {found.held} ({why})"
    return text


def dry_run(settings: Settings, days: int | None, out: TextIO, now: float | None = None) -> int:
    """Show what a period would delete now, without deleting or recording anything.

    Args:
        settings: The settings.
        days: The period to preview; ``None`` (off) deletes nothing.
        out: Where the report goes.
        now: The time to measure from, for tests.

    Returns:
        0 when every table could be planned, else 1.
    """
    if days is None:
        print("retention is off: nothing would be deleted", file=out)
        return 0
    if not settings.database.is_file():
        print(f"no database at {settings.database}", file=out)
        return 1
    conn = open_database(settings.database, readonly=True)
    try:
        if database_id(conn) is None:
            print("the database has no schema yet", file=out)
            return 1
        problems = schema_problems(conn)
        if problems:
            print("refused, not the verified schema: " + "; ".join(problems), file=out)
            return 1
        moment = datetime.fromtimestamp(time.time() if now is None else now, UTC)
        plans = preview(conn, settings.state_dir, days, moment)
    finally:
        conn.close()
    held = plans.get(f"{AUTH_LOG}:held")
    print(f"period: {days} days", file=out)
    code = 0
    for name in TABLES:
        found = plans[name]
        if isinstance(found, str):
            code = 1
        print(f"  {name}: {_describe(found, held if name == AUTH_LOG and isinstance(held, str) else None)}", file=out)
    return code


def schema_check(database: Path, out: TextIO) -> int:
    """Report whether the database is the verified schema.

    Args:
        database: Authelia's database file.
        out: Where the report goes.

    Returns:
        0 when it is, else 1.
    """
    if not database.is_file():
        print(f"no database at {database}", file=out)
        return 1
    conn = open_database(database, readonly=True)
    try:
        if database_id(conn) is None:
            print("the database has no schema yet", file=out)
            return 1
        problems = schema_problems(conn)
    finally:
        conn.close()
    if problems:
        print("not the verified schema: " + "; ".join(problems), file=out)
        return 1
    print("the verified schema", file=out)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch a subcommand.

    Args:
        argv: The arguments, without the program name.

    Returns:
        The exit status.
    """
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(
        prog="auth_retention.py", description="deletes Authelia's records after a period (docs/audit.md#retention)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="sweep until stopped")
    preview_cmd = commands.add_parser("dry-run", help="show what a period would delete now")
    preview_cmd.add_argument("--days", help="the period to preview (default: EDGE_AUTH_RETENTION_DAYS), or off")
    commands.add_parser("schema", help="exit 0 when the database is the verified schema")
    commands.add_parser("health", help="exit 0 when the sweep loop reported recently and no table is refused")
    commands.add_parser("verify", help="check the hash chains of the audit lines on stdin")
    args = parser.parse_args(argv)
    try:
        settings = Settings.from_env(os.environ)
        days = settings.days if getattr(args, "days", None) is None else parse_days(args.days)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    if args.command == "serve":
        stop = threading.Event()
        install_stop_handlers(stop)
        return serve(settings, os.environ.get("AUDIT_OUTPUT"), stop)
    if args.command == "dry-run":
        return dry_run(settings, days, sys.stdout)
    if args.command == "schema":
        return schema_check(settings.database, sys.stdout)
    if args.command == "health":
        return health(settings)
    return verify(sys.stdin, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
