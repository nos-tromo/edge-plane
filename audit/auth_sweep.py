"""Retention for the records Authelia keeps in its SQLite database (``db.sqlite3``).

Authelia 4.39.20 never deletes from the tables that log who signed in or tried
to, from which address: its authentication log, the one-time codes and identity
verifications it issued, the TOTP codes it saw used, and the bans regulation
imposed. This module deletes their rows a set number of days after they were
recorded or ended (operator guide: ``docs/audit.md#retention``):

* ``authentication_logs``: by ``time``, and only rows ``auth-audit`` has
  already exported to the audit trail (``id`` up to the position in its
  ``auth-export.json``, for the same database). When that position is missing,
  damaged, belongs to another database or is ahead of the log, nothing is
  deleted from this table;
* ``one_time_code``: by ``expires``, so a code that is still valid stays;
* ``identity_verification``: by ``exp``;
* ``totp_history``: by ``created_at``;
* ``banned_user`` and ``banned_ip``: by when the ban ended, the earlier of its
  revocation (``expired``) and its expiry (``expires``). A ban in force,
  including a permanent one, is never deleted.

What Authelia reads back from these tables was checked in the pinned image's
source (``internal/storage/sql_provider_queries.go``): the regulation reads the
log back for minutes (``find_time``), the TOTP replay check for one code step,
codes and verifications are looked up by their own identifier (a deleted one is
refused), and a ban counts only while it is in force. A period of at least one
day therefore changes nothing Authelia does.

Times are parsed, never compared as text: the driver stores Go times with a
trimmed fraction and the container's offset, and ``CURRENT_TIMESTAMP`` columns
hold another format. A value that does not parse stops its table alone.

Schema guard: before anything is planned, and again inside every write
transaction, :func:`schema_problems` checks the schema version against
:data:`VERIFIED_SCHEMA_VERSIONS` and the tables and columns every statement
relies on. A newer Authelia therefore stops the sweep until its schema and
queries have been checked (``docs/images.md``).

Locking: Authelia keeps running and writes the same database, in its rollback
journal mode. While a transaction here holds the write lock, Authelia's insert
of a login attempt waits (its driver's default busy timeout is five seconds),
and an attempt it cannot insert is never logged. So the sweeper plans without a
lock and deletes in short ``BEGIN IMMEDIATE`` transactions of at most
:data:`IDS_PER_BATCH` rows by primary key, pausing between them. Each writes its
``delete`` record before it commits and rolls back if the record cannot be
written. ``secure_delete`` is on, so the deleted rows and their index entries
are overwritten with zeros in the database file. Stdlib only.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from audit_event import Actor, AuditEmitter, Target
from audit_runtime import MAX_IDS_PER_EVENT
from edge_audit import StateError, database_id, db_time, last_allocated_id, load_state

LOG = logging.getLogger("auth-retention")

#: Authelia's schema versions (``migrations.version_after``) this module was
#: verified against: 4.39.20 creates version 24.
VERIFIED_SCHEMA_VERSIONS: Final = frozenset({24})
#: The image whose schema and queries were checked; ``docker/compose.yaml``
#: must pin exactly this one (a test compares them).
VERIFIED_AUTHELIA_IMAGE: Final = (
    "docker.io/authelia/authelia:4.39.20@sha256:1b363e9279e742397966333f364e0876ae02bf5c876de73e83af6d48c57ff51b"
)
#: Rows per write transaction, at most: one record's worth of ids.
IDS_PER_BATCH: Final = MAX_IDS_PER_EVENT
#: Batches per sweep, at most; the rest follow in the next round.
MAX_BATCHES: Final = 300
#: Rows per planning read.
SCAN_ROWS: Final = 1000
#: How long a statement waits for Authelia's lock.
BUSY_TIMEOUT_S: Final = 10.0
#: Pause between batches, longer than SQLite's busy-retry step, so a write of
#: Authelia's that waited for the lock gets it before the next batch.
BATCH_PAUSE_S: Final = 0.2
#: The records' container: the service whose database they were deleted from.
CONTAINER: Final = "authelia"
AUTH_LOG: Final = "authentication_logs"
#: The sweeper acts on its own schedule; no caller, no purpose.
SYSTEM: Final = Actor(None, "system")
SWEEP: Final = "retention.sweep"


class SchemaRefused(RuntimeError):
    """Raised when the database is not the verified schema; nothing is deleted."""

    def __init__(self, problems: Sequence[str]) -> None:
        """Keep the problems, by table and column name only.

        Args:
            problems: What does not match.
        """
        super().__init__("; ".join(problems))
        self.problems = list(problems)


class TimeFormatRefused(RuntimeError):
    """Raised when a stored time does not parse; nothing is deleted from that table."""

    def __init__(self, table: str, column: str, row_id: int) -> None:
        """Name the place, never the value.

        Args:
            table: The table.
            column: The column.
            row_id: The row.
        """
        super().__init__(f"{table}.{column} of row {row_id} is not a time this sweeper reads")
        self.table = table
        self.column = column


def _earliest(values: Mapping[str, datetime | None]) -> datetime | None:
    """When a row ended: the earliest of its set times, ``None`` when none is set.

    Args:
        values: The parsed times, by column.

    Returns:
        The end, or ``None`` (never due).
    """
    moments = [moment for moment in values.values() if moment is not None]
    return min(moments) if moments else None


@dataclass(frozen=True)
class TableRule:
    """When the rows of one table are due.

    Attributes:
        table: The table.
        columns: The time columns the rule reads.
        age_from: What the age counts from, as the records name it.
        ended: Turns the row's parsed times into the moment its age counts
            from; ``None`` means the row is never due.
    """

    table: str
    columns: tuple[str, ...]
    age_from: str
    ended: Callable[[Mapping[str, datetime | None]], datetime | None] = _earliest


RULES: Final = (
    TableRule(AUTH_LOG, ("time",), "time"),
    TableRule("one_time_code", ("expires",), "expires"),
    TableRule("identity_verification", ("exp",), "exp"),
    TableRule("totp_history", ("created_at",), "created_at"),
    TableRule("banned_user", ("expired", "expires"), "ended"),
    TableRule("banned_ip", ("expired", "expires"), "ended"),
)
TABLES: Final = tuple(rule.table for rule in RULES)
#: The columns every statement here relies on, by table.
REQUIRED_COLUMNS: Final = {
    "migrations": ("id", "applied", "version_after"),
    **{rule.table: ("id", *rule.columns) for rule in RULES},
}


def open_database(path: Path, *, readonly: bool, busy_timeout_s: float = BUSY_TIMEOUT_S) -> sqlite3.Connection:
    """Open Authelia's database without ever creating it.

    The journal mode is left as Authelia set it.

    Args:
        path: The database file.
        readonly: Open it read-only (the dry run and the schema check).
        busy_timeout_s: How long a statement waits for a lock.

    Returns:
        A connection in autocommit mode: every read is its own short
        transaction, and writes run in explicit ones.

    Raises:
        sqlite3.Error: If it cannot be opened.
    """
    uri = f"file:{urllib.parse.quote(str(path))}?mode={'ro' if readonly else 'rw'}"
    conn = sqlite3.connect(uri, uri=True, timeout=busy_timeout_s, isolation_level=None)
    try:
        # The container's /tmp is a small tmpfs: sort in memory, never in temp files.
        conn.execute("PRAGMA temp_store = MEMORY")
        if readonly:
            conn.execute("PRAGMA query_only = ON")
        else:
            conn.execute("PRAGMA secure_delete = ON")
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def schema_version(conn: sqlite3.Connection) -> int | None:
    """Return the schema version Authelia migrated the database to.

    Args:
        conn: The connection.

    Returns:
        The highest ``migrations.version_after``, or ``None`` when there is none.
    """
    row = conn.execute("SELECT MAX(version_after) FROM migrations").fetchone()
    return None if row is None or row[0] is None else int(row[0])


def schema_problems(conn: sqlite3.Connection) -> list[str]:
    """Check that the database is the schema this module was verified against.

    Args:
        conn: The connection.

    Returns:
        What does not match, by table and column name only; empty when it does.
    """
    problems: list[str] = []
    for table, columns in REQUIRED_COLUMNS.items():
        present = {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')}
        if not present:
            problems.append(f"table {table} is missing")
            continue
        missing = [column for column in columns if column not in present]
        if missing:
            problems.append(f"table {table} lacks {', '.join(missing)}")
    if "table migrations is missing" not in problems:
        version = schema_version(conn)
        if version not in VERIFIED_SCHEMA_VERSIONS:
            verified = ", ".join(str(item) for item in sorted(VERIFIED_SCHEMA_VERSIONS))
            problems.append(f"schema version {version} is not verified (verified: {verified})")
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (AUTH_LOG,)).fetchone()
    if row is not None and "AUTOINCREMENT" not in str(row[0]).upper():
        problems.append(f"table {AUTH_LOG} does not keep its ids (no AUTOINCREMENT)")
    return problems


@dataclass(frozen=True)
class ExportLimit:
    """How far the authentication log may be deleted.

    Attributes:
        last_id: The last row ``auth-audit`` exported from this database;
            ``None`` when nothing may be deleted.
        reason: Why nothing may be deleted: ``export_position_invalid``,
            ``export_position_missing``, ``export_position_other_database`` or
            ``export_position_ahead`` (a restored backup, which ``auth-audit``
            exports again from its first row).
    """

    last_id: int | None
    reason: str | None = None


def export_limit(conn: sqlite3.Connection, state_dir: Path) -> ExportLimit:
    """Read how far ``auth-audit`` exported the authentication log of this database.

    Args:
        conn: The connection.
        state_dir: ``auth-audit``'s state directory, mounted read-only.

    Returns:
        The limit.
    """
    try:
        state = load_state(state_dir)
    except StateError:
        return ExportLimit(None, "export_position_invalid")
    if state.database is None:
        return ExportLimit(None, "export_position_missing")
    if state.database != database_id(conn):
        return ExportLimit(None, "export_position_other_database")
    if last_allocated_id(conn) < state.last_id:
        return ExportLimit(None, "export_position_ahead")
    return ExportLimit(state.last_id)


@dataclass
class Plan:
    """What one table holds against the cutoff.

    Attributes:
        due: Rows to delete, oldest id first.
        held: Rows old enough but not exported yet (authentication log only).
        kept: Rows not due.
    """

    due: list[int] = field(default_factory=list)
    held: int = 0
    kept: int = 0


def _row_end(rule: TableRule, row: Sequence[object]) -> datetime | None:
    """Parse one row's times and return when its age counts from.

    Args:
        rule: The table's rule.
        row: ``id`` followed by the rule's columns.

    Returns:
        The moment, or ``None`` when the row is never due.

    Raises:
        TimeFormatRefused: If a set time does not parse.
    """
    row_id = int(str(row[0]))
    values: dict[str, datetime | None] = {}
    for column, raw in zip(rule.columns, row[1:], strict=True):
        if raw is None:
            values[column] = None
            continue
        moment = db_time(str(raw))
        if moment is None:
            raise TimeFormatRefused(rule.table, column, row_id)
        values[column] = moment
    return rule.ended(values)


def _select(rule: TableRule) -> str:
    """The planning read of one table.

    Args:
        rule: The table's rule.

    Returns:
        The statement: one page of rows after an id.
    """
    columns = ", ".join(rule.columns)
    return f"SELECT id, {columns} FROM {rule.table} WHERE id > ? ORDER BY id LIMIT ?"


def plan(conn: sqlite3.Connection, rule: TableRule, cutoff: datetime, max_id: int | None = None) -> Plan:
    """Find the rows of one table that are due, one short read per page.

    Args:
        conn: The connection, outside any transaction.
        rule: The table's rule.
        cutoff: Rows that ended before this moment are due.
        max_id: The highest id that may be deleted; ``None`` for no limit.
            Rows due by age above it count as held.

    Returns:
        The plan.

    Raises:
        TimeFormatRefused: If a stored time does not parse.
    """
    result = Plan()
    after = 0
    while True:
        rows = conn.execute(_select(rule), (after, SCAN_ROWS)).fetchall()
        for row in rows:
            row_id = int(row[0])
            end = _row_end(rule, row)
            if end is None or end >= cutoff:
                result.kept += 1
            elif max_id is not None and row_id > max_id:
                result.held += 1
            else:
                result.due.append(row_id)
        if len(rows) < SCAN_ROWS:
            return result
        after = int(rows[-1][0])


def record_time(moment: datetime) -> str:
    """Format a moment the way the records do.

    Args:
        moment: An aware moment.

    Returns:
        E.g. ``2026-01-31T12:00:00Z``.
    """
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _placeholders(count: int) -> str:
    """Return ``?, ?, ...`` for ``count`` parameters.

    Args:
        count: How many.

    Returns:
        The placeholders.
    """
    return ", ".join("?" * count)


def _chunks(ids: Sequence[int], size: int = IDS_PER_BATCH) -> Iterator[list[int]]:
    """Split ids into batches.

    Args:
        ids: The ids.
        size: The most per batch.

    Yields:
        The batches, in order.
    """
    for start in range(0, len(ids), size):
        yield list(ids[start : start + size])


@dataclass
class TableSweep:
    """What one table's sweep did.

    Attributes:
        deleted: Rows deleted.
        batches: Transactions committed.
        held: Rows old enough but not exported yet (authentication log only).
        held_reason: Why the authentication log is held entirely, if it is.
        refused: ``time_format`` when a stored time did not parse.
    """

    deleted: int = 0
    batches: int = 0
    held: int = 0
    held_reason: str | None = None
    refused: str | None = None


@dataclass
class SweepResult:
    """What one sweep did.

    Attributes:
        ready: ``False`` when there is no database or schema yet (Authelia
            creates both on its first start); nothing was read.
        tables: By table, for the tables swept.
        complete: ``False`` when the sweep stopped at :data:`MAX_BATCHES` or on
            ``stop``; the rest follows in the next round.
    """

    ready: bool = True
    tables: dict[str, TableSweep] = field(default_factory=dict)
    complete: bool = True


class Sweeper:
    """Deletes the rows that are due, table by table, in recorded batches."""

    def __init__(
        self,
        emitter: AuditEmitter,
        database: Path,
        state_dir: Path,
        days: int,
        *,
        busy_timeout_s: float = BUSY_TIMEOUT_S,
        pause_s: float = BATCH_PAUSE_S,
        max_batches: int = MAX_BATCHES,
        stop: threading.Event | None = None,
    ) -> None:
        """Prepare a sweeper; nothing is read until :meth:`sweep`.

        Args:
            emitter: The started emitter.
            database: Authelia's database file.
            state_dir: ``auth-audit``'s state directory, read-only.
            days: The period.
            busy_timeout_s: How long a statement waits for a lock.
            pause_s: Pause between batches.
            max_batches: Batches per sweep, at most.
            stop: Ends a sweep after its current batch when set.
        """
        self._emitter = emitter
        self._database = database
        self._state_dir = state_dir
        self._days = days
        self._busy_timeout_s = busy_timeout_s
        self._pause_s = pause_s
        self._max_batches = max_batches
        self._stop = stop or threading.Event()
        self._batches = 0

    def sweep(self, now: datetime) -> SweepResult:
        """Delete every row that ended more than the period before ``now``.

        Args:
            now: The sweep's time (aware).

        Returns:
            What was deleted, held or refused, by table.

        Raises:
            SchemaRefused: If the database is not the verified schema; nothing
                has been deleted in that transaction.
            sqlite3.Error: If the database could not be read or written; the
                failed batch was rolled back (and recorded as failed if its
                commit failed).
            AuditWriteError: If a record could not be written; its batch was
                rolled back.
            RuntimeError: If the emitter is closed.
        """
        result = SweepResult()
        self._batches = 0
        if not self._database.is_file():
            result.ready = False
            return result
        cutoff = now - timedelta(days=self._days)
        conn = open_database(self._database, readonly=False, busy_timeout_s=self._busy_timeout_s)
        try:
            if database_id(conn) is None:
                result.ready = False
                return result
            problems = schema_problems(conn)
            if problems:
                raise SchemaRefused(problems)
            for rule in RULES:
                table = result.tables.setdefault(rule.table, TableSweep())
                try:
                    self._sweep_table(conn, rule, cutoff, table, result)
                except TimeFormatRefused as exc:
                    LOG.error("%s: retention refused, nothing more is deleted from it: %s", rule.table, exc)
                    table.refused = "time_format"
                if not result.complete:
                    break
        finally:
            conn.close()
            for name, table in result.tables.items():
                if table.deleted:
                    LOG.info(
                        "%s: deleted %d rows older than %d days, in %d batches",
                        name,
                        table.deleted,
                        self._days,
                        table.batches,
                    )
        return result

    def _sweep_table(
        self, conn: sqlite3.Connection, rule: TableRule, cutoff: datetime, table: TableSweep, result: SweepResult
    ) -> None:
        """Plan one table and delete its due rows, batch by batch.

        Args:
            conn: The connection, outside any transaction.
            rule: The table's rule.
            cutoff: Rows that ended before this moment are due.
            table: Where the table's outcome is noted.
            result: The sweep's result; ``complete`` turns ``False`` when the
                batch limit or ``stop`` ends the sweep.

        Raises:
            TimeFormatRefused: If a stored time does not parse.
        """
        max_id = None
        if rule.table == AUTH_LOG:
            limit = export_limit(conn, self._state_dir)
            table.held_reason = limit.reason
            max_id = 0 if limit.last_id is None else limit.last_id
        found = plan(conn, rule, cutoff, max_id)
        table.held = found.held
        for batch in _chunks(found.due):
            if self._batches >= self._max_batches or self._stop.is_set():
                result.complete = False
                return
            deleted = self._delete_batch(conn, rule, batch, cutoff)
            if deleted:
                self._batches += 1
                table.batches += 1
                table.deleted += deleted
            self._stop.wait(self._pause_s)

    def _delete_batch(self, conn: sqlite3.Connection, rule: TableRule, batch: Sequence[int], cutoff: datetime) -> int:
        """Delete one batch of a table's rows in one recorded transaction.

        Args:
            conn: The connection, outside any transaction.
            rule: The table's rule.
            batch: The planned ids.
            cutoff: Rows that ended before this moment are due.

        Returns:
            How many rows were deleted.
        """
        criteria: dict[str, object] = {
            "store": rule.table,
            "period_days": self._days,
            "cutoff": record_time(cutoff),
            "age_from": rule.age_from,
        }
        conn.execute("BEGIN IMMEDIATE")
        try:
            problems = schema_problems(conn)
            if problems:
                raise SchemaRefused(problems)
            max_id = None
            if rule.table == AUTH_LOG:
                # Planned without a lock: the export position may have changed.
                limit = export_limit(conn, self._state_dir)
                if limit.last_id is None:
                    conn.execute("ROLLBACK")
                    return 0
                max_id = limit.last_id
                criteria["exported_through"] = max_id
            rows = conn.execute(
                f"SELECT id, {', '.join(rule.columns)} FROM {rule.table} WHERE id IN ({_placeholders(len(batch))})",
                tuple(batch),
            ).fetchall()
            ids: list[int] = []
            for row in rows:
                end = _row_end(rule, row)
                if end is not None and end < cutoff and (max_id is None or int(row[0]) <= max_id):
                    ids.append(int(row[0]))
            ids.sort()
            if not ids:
                conn.execute("ROLLBACK")
                return 0
            deleted = conn.execute(
                f"DELETE FROM {rule.table} WHERE id IN ({_placeholders(len(ids))})", tuple(ids)
            ).rowcount
            record = self._record(rule.table, ids, criteria)
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        try:
            conn.execute("COMMIT")
        except sqlite3.Error:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            LOG.error("%s: a batch of %d rows could not be committed and was rolled back", rule.table, len(ids))
            self._record(rule.table, ids, criteria, outcome="error", parent_event_id=str(record["event_id"]))
            raise
        return deleted

    def _record(
        self,
        table: str,
        ids: Sequence[int],
        criteria: Mapping[str, object],
        *,
        outcome: str = "ok",
        parent_event_id: str | None = None,
    ) -> dict[str, object]:
        """Write the ``delete`` record of one batch.

        Args:
            table: The table.
            ids: The rows; at most :data:`IDS_PER_BATCH`, so they fit one event.
            criteria: The rule.
            outcome: ``ok``, or ``error`` for a batch that was rolled back.
            parent_event_id: The ``ok`` record an ``error`` one corrects.

        Returns:
            The event as written.
        """
        return self._emitter.emit(
            "delete",
            SWEEP,
            SYSTEM,
            outcome=outcome,
            parent_event_id=parent_event_id,
            target=Target(kind=table, ids=[str(item) for item in ids], count=len(ids), container=CONTAINER),
            criteria=criteria,
        )


def preview(conn: sqlite3.Connection, state_dir: Path, days: int, now: datetime) -> dict[str, Plan | str]:
    """Plan every table without deleting anything (the dry run).

    Args:
        conn: A read-only connection.
        state_dir: ``auth-audit``'s state directory.
        days: The period.
        now: The time to measure from.

    Returns:
        The plan by table, or ``time_format`` for a table whose times do not
        parse; the authentication log's hold reason, if any, under
        ``authentication_logs:held``.
    """
    cutoff = now - timedelta(days=days)
    out: dict[str, Plan | str] = {}
    for rule in RULES:
        max_id = None
        if rule.table == AUTH_LOG:
            limit = export_limit(conn, state_dir)
            if limit.reason:
                out[f"{AUTH_LOG}:held"] = limit.reason
            max_id = 0 if limit.last_id is None else limit.last_id
        try:
            out[rule.table] = plan(conn, rule, cutoff, max_id)
        except TimeFormatRefused:
            out[rule.table] = "time_format"
    return out
