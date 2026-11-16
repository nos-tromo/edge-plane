"""A synthetic Authelia database with the pinned image's full schema, for the retention tests.

``fixtures/authelia-schema.sql`` is the schema a fresh database of the pinned
image holds (``authelia storage migrate up``, schema version 24). Rows are
written the way Authelia's driver writes them: Go times with a trimmed fraction
and the container's offset, or SQLite's ``CURRENT_TIMESTAMP`` format.
"""

from __future__ import annotations

import contextlib
import io
import itertools
import json
import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import edge_audit

SCHEMA_FILE = Path(__file__).resolve().parent / "fixtures" / "authelia-schema.sql"
FIRST_MIGRATION = "2026-01-31 08:00:00.000000001+00:00"
#: A name and an address that must never reach a record, and must be gone
#: from the database file once their rows are deleted.
SENTINEL_USER = "sentinel.user.example"
SENTINEL_IP = "198.51.100.77"
NOW = datetime(2026, 6, 30, 12, 0, 0, tzinfo=UTC)
#: Unique values for the columns the schema keeps unique (signature, step, jti).
_SERIAL = itertools.count(1)


def make_database(path: Path, *, applied: str = FIRST_MIGRATION, version: int = 24) -> None:
    """Create a database with the pinned schema and its migrations applied.

    Args:
        path: The database file to create.
        applied: The first migration's time, which identifies the database.
        version: The schema version the migrations reach.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
        for step in range(1, version + 1):
            conn.execute(
                "INSERT INTO migrations (applied, version_before, version_after, application_version) "
                "VALUES (?, ?, ?, 'v4.39.20')",
                (applied if step == 1 else "2026-01-31 08:00:01+00:00", step - 1, step),
            )
        conn.commit()


def go_time(moment: datetime, offset_hours: int = 0) -> str:
    """Format a moment as Authelia's driver stores Go times.

    Args:
        moment: An aware moment.
        offset_hours: The container's offset to write it in.

    Returns:
        E.g. ``2026-01-31 12:00:00.12345+02:00`` (the fraction's trailing
        zeros dropped, no fraction at all on a whole second).
    """
    local = moment.astimezone(timezone(timedelta(hours=offset_hours)))
    fraction = f"{local.microsecond * 1000:09d}".rstrip("0")
    zone = local.strftime("%z")
    return f"{local:%Y-%m-%d %H:%M:%S}{'.' + fraction if fraction else ''}{zone[:3]}:{zone[3:]}"


def sqlite_time(moment: datetime) -> str:
    """Format a moment as SQLite's ``CURRENT_TIMESTAMP`` does.

    Args:
        moment: An aware moment.

    Returns:
        E.g. ``2026-01-31 12:00:00`` (UTC).
    """
    return f"{moment.astimezone(UTC):%Y-%m-%d %H:%M:%S}"


def insert(path: Path, table: str, **values: Any) -> int:
    """Insert one row.

    Args:
        path: The database file.
        table: The table.
        **values: The columns.

    Returns:
        The new row's id.
    """
    columns = ", ".join(values)
    marks = ", ".join("?" * len(values))
    with contextlib.closing(sqlite3.connect(path)) as conn:
        cursor = conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({marks})", tuple(values.values()))
        conn.commit()
        return int(cursor.lastrowid or 0)


def add_attempt(path: Path, when: str, *, username: str = "alice.example", ip: str = "192.0.2.10") -> int:
    """Append one login attempt.

    Args:
        path: The database file.
        when: The stored time.
        username: The account.
        ip: The client address.

    Returns:
        The row id.
    """
    return insert(
        path,
        "authentication_logs",
        time=when,
        successful=True,
        banned=False,
        username=username,
        auth_type="1FA",
        remote_ip=ip,
        request_uri="https://edge.example/",
        request_method="GET",
    )


def add_code(path: Path, issued: str, expires: str, *, username: str = "alice.example", ip: str = "192.0.2.10") -> int:
    """Append one one-time code.

    Args:
        path: The database file.
        issued: When it was issued.
        expires: When it expires.
        username: The account.
        ip: The address it was issued to.

    Returns:
        The row id.
    """
    return insert(
        path,
        "one_time_code",
        public_id=f"00000000-0000-4000-8000-{next(_SERIAL):012d}",
        signature=f"sig-{next(_SERIAL)}",
        issued=issued,
        issued_ip=ip,
        expires=expires,
        username=username,
        intent="i",
        code=b"\x00",
    )


def add_verification(path: Path, iat: str, exp: str, *, username: str = "alice.example") -> int:
    """Append one identity verification.

    Args:
        path: The database file.
        iat: When it was issued.
        exp: When it expires.
        username: The account.

    Returns:
        The row id.
    """
    return insert(
        path,
        "identity_verification",
        jti=f"00000000-0000-4000-8000-{next(_SERIAL):012d}",
        iat=iat,
        issued_ip="192.0.2.10",
        exp=exp,
        username=username,
        action="ResetPassword",
    )


def add_totp_step(path: Path, created_at: str, *, username: str = "alice.example") -> int:
    """Append one used TOTP step.

    Args:
        path: The database file.
        created_at: When it was used.
        username: The account.

    Returns:
        The row id.
    """
    return insert(path, "totp_history", created_at=created_at, username=username, step=f"{next(_SERIAL):064d}")


def add_ban(
    path: Path,
    table: str,
    *,
    when: str,
    expires: str | None,
    expired: str | None = None,
    revoked: bool = False,
    subject: str = "alice.example",
) -> int:
    """Append one ban.

    Args:
        path: The database file.
        table: ``banned_user`` or ``banned_ip``.
        when: When it was imposed.
        expires: When it runs out; ``None`` for a permanent ban.
        expired: When it was revoked.
        revoked: Whether it was revoked.
        subject: The account or address.

    Returns:
        The row id.
    """
    key = "username" if table == "banned_user" else "ip"
    return insert(
        path, table, time=when, expires=expires, expired=expired, revoked=revoked, source="regulation", **{key: subject}
    )


def ids(path: Path, table: str) -> list[int]:
    """List a table's row ids.

    Args:
        path: The database file.
        table: The table.

    Returns:
        The ids, ascending.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        return [int(row[0]) for row in conn.execute(f"SELECT id FROM {table} ORDER BY id")]


def export_position(state_dir: Path, path: Path, last_id: int) -> None:
    """Write ``auth-audit``'s export position for a database, as it writes it.

    Args:
        state_dir: The state directory.
        path: The database file, for its identity.
        last_id: The last exported row.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        identity = edge_audit.database_id(conn)
    edge_audit.save_state(state_dir, edge_audit.ExportState(database=identity, last_id=last_id))


def events(stream: io.StringIO) -> list[dict[str, Any]]:
    """Parse everything an emitter wrote.

    Args:
        stream: The emitter's stream.

    Returns:
        The events.
    """
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def deletions(stream: io.StringIO) -> list[dict[str, Any]]:
    """Select the ``delete`` records.

    Args:
        stream: The emitter's stream.

    Returns:
        The records, in order.
    """
    return [event for event in events(stream) if event["action"] == "delete"]
