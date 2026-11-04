"""Tests for edge_audit.py against a synthetic Authelia database.

The tables are created with the exact DDL the pinned Authelia image
(4.39.20) creates, so the queries run against the real column layout. Run
from the repo root: ``python3 -m unittest discover -s audit/tests -t audit``.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

import edge_audit
from audit_event import AuditEmitter, verify_chain

# Verbatim from the pinned image's db.sqlite3 (sqlite_master), schema version 24.
SCHEMA = """
CREATE TABLE migrations (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    applied DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version_before INTEGER NULL DEFAULT NULL,
    version_after INTEGER NOT NULL,
    application_version VARCHAR(128) NOT NULL
);
CREATE TABLE authentication_logs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful BOOLEAN NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    username VARCHAR(100) NOT NULL,
    auth_type VARCHAR(8) NOT NULL DEFAULT '1FA',
    remote_ip VARCHAR(39) NULL DEFAULT NULL,
    request_uri TEXT,
    request_method VARCHAR(8) NOT NULL DEFAULT ''
);
CREATE INDEX authentication_logs_username_idx ON authentication_logs (time, username, auth_type);
CREATE INDEX authentication_logs_remote_ip_idx ON authentication_logs (time, remote_ip, auth_type);
"""
FIRST_MIGRATION = "2026-01-31 08:00:00.000000001+00:00"
REPO = Path(__file__).resolve().parents[2]
WRAPPER = ("bash", str(REPO / "scripts" / "audit-admin.sh"))
ENVELOPE = frozenset(
    {"stream", "v", "event_id", "ts", "service", "service_version", "instance", "seq", "prev_hash", "hash"}
    | {"action", "operation", "outcome", "actor"}
)


def make_database(path: Path, applied: str = FIRST_MIGRATION) -> None:
    """Create an Authelia-shaped database with its first migration applied.

    Args:
        path: The database file to create.
        applied: The first migration's time, which identifies the database.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO migrations (applied, version_before, version_after, application_version) VALUES (?, 0, 1, ?)",
            (applied, "v4.39.20"),
        )
        conn.commit()


def add_attempt(
    path: Path,
    username: str = "alice.example",
    *,
    successful: bool = True,
    banned: bool = False,
    auth_type: str = "1FA",
    remote_ip: str | None = "192.0.2.10",
    request_uri: str = "",
    request_method: str = "",
    when: str = "2026-01-31 09:15:30.123456789+00:00",
) -> int:
    """Append one row the way Authelia's regulator does.

    Args:
        path: The database file.
        username: The account, empty for a name that matches none.
        successful: Whether the attempt was accepted.
        banned: Whether the account was banned at the time.
        auth_type: The factor.
        remote_ip: The client address.
        request_uri: The target URL from the login page.
        request_method: Its method.
        when: The stored time.

    Returns:
        The new row's id.
    """
    with contextlib.closing(sqlite3.connect(path)) as conn:
        cursor = conn.execute(
            "INSERT INTO authentication_logs (time, successful, banned, username, auth_type, remote_ip, "
            "request_uri, request_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (when, successful, banned, username, auth_type, remote_ip, request_uri, request_method),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)


def lines(stream: io.StringIO) -> list[dict[str, Any]]:
    """Parse everything an emitter wrote.

    Args:
        stream: The emitter's stream.

    Returns:
        The events.
    """
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def auth_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Select the ``auth`` events.

    Args:
        events: Parsed events.

    Returns:
        The ``auth`` events, in order.
    """
    return [event for event in events if event["action"] == "auth"]


class Workspace(unittest.TestCase):
    """A temporary database and state directory per test."""

    def setUp(self) -> None:
        """Create the temporary paths."""
        self.tmp = Path(tempfile.mkdtemp(prefix="edge-audit-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db_dir = self.tmp / "authelia"
        self.db_dir.mkdir()
        self.database = self.db_dir / "db.sqlite3"
        self.state_dir = self.tmp / "state"
        self.state_dir.mkdir()
        self.version_file = self.tmp / "VERSION"
        self.version_file.write_text("0.11.0\n", encoding="utf-8")
        self.streams: list[io.StringIO] = []

    def emitter(self) -> tuple[AuditEmitter, io.StringIO]:
        """Start an emitter on a captured stream.

        Returns:
            The emitter and its stream.
        """
        stream = io.StringIO()
        emitter = AuditEmitter(edge_audit.SERVICE, "0.11.0", stream=stream, heartbeat_interval_s=0)
        emitter.start()
        self.addCleanup(emitter.close)
        self.streams.append(stream)
        return emitter, stream

    def exporter(self, emitter: AuditEmitter, *, batch: int = edge_audit.BATCH_ROWS) -> edge_audit.AuthLogExporter:
        """Build an exporter on the workspace, resuming from its saved position.

        Args:
            emitter: The started emitter.
            batch: Rows per query.

        Returns:
            The exporter.
        """
        state = edge_audit.load_state(self.state_dir)
        return edge_audit.AuthLogExporter(emitter, self.database, self.state_dir, state, batch=batch)

    def assert_chains_intact(self, *streams: io.StringIO) -> None:
        """Assert every captured chain verifies.

        Args:
            *streams: The streams to check; all of this test's by default.
        """
        events = [event for stream in streams or self.streams for event in lines(stream)]
        report = verify_chain(events)
        self.assertEqual(report.problems, [])


class MappingTest(Workspace):
    """One event per row, mapped from Authelia's columns."""

    def test_every_auth_type_becomes_its_operation(self) -> None:
        """Each factor maps to a stable operation; unknown ones to login.other."""
        make_database(self.database)
        for auth_type in ("1FA", "TOTP", "WebAuthn", "Duo", "Passkey", "Password", "Smartcard"):
            add_attempt(self.database, auth_type=auth_type)
        emitter, stream = self.emitter()
        self.assertEqual(self.exporter(emitter).poll(), 7)
        events = auth_events(lines(stream))
        self.assertEqual(
            [event["operation"] for event in events],
            [
                "login.1fa",
                "login.2fa.totp",
                "login.2fa.webauthn",
                "login.2fa.duo",
                "login.passkey",
                "login.2fa.password",
                "login.other",
            ],
        )
        self.assertEqual(events[-1]["criteria"]["auth_type"], "Smartcard")
        self.assert_chains_intact()

    def test_successful_attempt(self) -> None:
        """An accepted login is ok, by the account, with its non-secret facts."""
        make_database(self.database)
        row = add_attempt(
            self.database,
            request_uri="https://edge.example/chorus/search?q=Alice+Example#hit-3",
            request_method="GET",
        )
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        self.assertEqual(event["service"], "edge-plane")
        self.assertEqual(event["outcome"], "ok")
        self.assertEqual(event["actor"], {"user": "alice.example", "via": "edge"})
        self.assertEqual(
            event["criteria"],
            {
                "log_id": row,
                "attempted_at": "2026-01-31T09:15:30.123Z",
                "auth_type": "1FA",
                "banned": False,
                "client_ip": "192.0.2.10",
                "request_path": "/chorus/search",
                "request_method": "GET",
            },
        )
        self.assertEqual(set(event), ENVELOPE | {"criteria"})
        self.assertNotIn("Alice", json.dumps(event))
        self.assert_chains_intact()

    def test_failed_attempt_is_denied(self) -> None:
        """Wrong credentials: denied, still attributed to the account tried."""
        make_database(self.database)
        add_attempt(self.database, successful=False, auth_type="TOTP")
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        self.assertEqual((event["operation"], event["outcome"]), ("login.2fa.totp", "denied"))
        self.assertEqual(event["actor"], {"user": "alice.example", "via": "edge"})
        self.assertIs(event["criteria"]["banned"], False)
        self.assert_chains_intact()

    def test_banned_attempt_is_denied_and_flagged(self) -> None:
        """Authelia refuses a banned account without checking: denied, banned."""
        make_database(self.database)
        add_attempt(self.database, successful=False, banned=True)
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        self.assertEqual(event["outcome"], "denied")
        self.assertIs(event["criteria"]["banned"], True)
        self.assert_chains_intact()

    def test_unknown_account_has_no_user(self) -> None:
        """A name matching no account is stored empty and stays unattributed."""
        make_database(self.database)
        add_attempt(self.database, username="", successful=False, remote_ip="198.51.100.7")
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        self.assertEqual(event["actor"], {"user": None, "via": "edge"})
        self.assertIs(event["criteria"]["unknown_account"], True)
        self.assertEqual(event["criteria"]["client_ip"], "198.51.100.7")
        self.assert_chains_intact()

    def test_missing_optional_columns_are_left_out(self) -> None:
        """No address, target or method: the keys are absent, not empty."""
        make_database(self.database)
        add_attempt(self.database, remote_ip=None)
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        criteria = event["criteria"]
        for key in ("client_ip", "request_path", "request_port", "request_method", "unknown_account"):
            self.assertNotIn(key, criteria)
        self.assert_chains_intact()

    def test_dedicated_site_keeps_its_port(self) -> None:
        """The :8443 Open WebUI site is told apart from the main site."""
        make_database(self.database)
        add_attempt(self.database, request_uri="https://edge.example:8443/")
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        (event,) = auth_events(lines(stream))
        self.assertEqual(event["criteria"]["request_path"], "/")
        self.assertEqual(event["criteria"]["request_port"], 8443)
        self.assert_chains_intact()

    def test_from_row_tolerates_nulls(self) -> None:
        """Nullable columns become empty values, never the string 'None'."""
        attempt = edge_audit.AuthAttempt.from_row((4, None, 0, 1, None, None, None, None, None))
        self.assertEqual(attempt, edge_audit.AuthAttempt(4, "", False, True, "", "", None, None, ""))


class HelperTest(unittest.TestCase):
    """The pure helpers."""

    def test_iso_utc(self) -> None:
        """Authelia's stored times become the events' UTC format."""
        cases = {
            "2026-11-03 18:18:11.736297758+00:00": "2026-11-03T18:18:11.736Z",
            "2026-11-03 20:18:11+02:00": "2026-11-03T18:18:11.000Z",
            "2026-11-03 18:18:11": "2026-11-03T18:18:11.000Z",
            "2026-11-03T18:18:11.5Z": "2026-11-03T18:18:11.500Z",
            "2026-11-03 18:18:11.1-0130": "2026-11-03T19:48:11.100Z",
        }
        for stored, expected in cases.items():
            self.assertEqual(edge_audit.iso_utc(stored), expected, stored)
        for junk in ("", "yesterday", "2026-13-40 25:61:61"):
            self.assertIsNone(edge_audit.iso_utc(junk), junk)

    def test_unparseable_time_is_kept_raw(self) -> None:
        """An odd stored time is recorded as stored rather than dropped."""
        attempt = edge_audit.AuthAttempt(1, "yesterday", True, False, "alice.example", "1FA", None, None, "")
        self.assertEqual(edge_audit.attempt_criteria(attempt)["attempted_at"], "yesterday")

    def test_request_target(self) -> None:
        """Only the path (and an explicit port) of the target URL remains."""
        cases = {
            None: (None, None),
            "": (None, None),
            "https://edge.example/docint/collections/x?filter=Bob+Example": ("/docint/collections/x", None),
            "https://edge.example": ("/", None),
            "https://edge.example:8443/c/1": ("/c/1", 8443),
            "/nextext/jobs?id=1": ("/nextext/jobs", None),
            "https://[::1": (None, None),
            "https://edge.example:99999/x": ("/x", None),
            "?only=query": (None, None),
        }
        for uri, expected in cases.items():
            self.assertEqual(edge_audit.request_target(uri), expected, uri)

    def test_parse_interval(self) -> None:
        """Whole seconds from 1 to 3600; blank means the default."""
        self.assertEqual(edge_audit.parse_interval(None), 5)
        self.assertEqual(edge_audit.parse_interval(" "), 5)
        self.assertEqual(edge_audit.parse_interval("30"), 30)
        for bad in ("0", "3601", "1.5", "-1", "soon"):
            with self.assertRaises(ValueError, msg=bad):
                edge_audit.parse_interval(bad)

    def test_parse_criteria(self) -> None:
        """Booleans and integers are typed; everything else stays text."""
        self.assertEqual(
            edge_audit.parse_criteria(["force=true", "kept=false", "count=3", "note=a=b"]),
            {"force": True, "kept": False, "count": 3, "note": "a=b"},
        )
        for bad in (["Force=true"], ["force"], ["force=true", "force=false"], ["=x"]):
            with self.assertRaises(ValueError, msg=str(bad)):
                edge_audit.parse_criteria(bad)

    def test_read_version(self) -> None:
        """The VERSION file's content, trimmed; anything else is refused."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "VERSION"
            path.write_text("0.11.0\n", encoding="utf-8")
            self.assertEqual(edge_audit.read_version(path), "0.11.0")
            path.write_text("\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                edge_audit.read_version(path)
            with self.assertRaises(ValueError):
                edge_audit.read_version(Path(tmp) / "missing")


class PositionTest(Workspace):
    """The position survives restarts and follows the database."""

    def test_empty_table(self) -> None:
        """No rows: nothing written, the database identity recorded."""
        make_database(self.database)
        emitter, stream = self.emitter()
        exporter = self.exporter(emitter)
        self.assertEqual(exporter.poll(), 0)
        self.assertEqual(auth_events(lines(stream)), [])
        self.assertEqual(edge_audit.load_state(self.state_dir), edge_audit.ExportState(FIRST_MIGRATION, 0))
        self.assert_chains_intact()

    def test_no_database_yet(self) -> None:
        """Before Authelia's first start there is nothing to read."""
        emitter, stream = self.emitter()
        self.assertIsNone(self.exporter(emitter).poll())
        self.database.touch()  # an empty file is an empty database: no schema yet
        self.assertIsNone(self.exporter(emitter).poll())
        self.assertEqual(auth_events(lines(stream)), [])
        self.assertFalse((self.state_dir / edge_audit.STATE_FILE).exists())

    def test_restart_neither_repeats_nor_skips(self) -> None:
        """A new process resumes right after the last exported row."""
        make_database(self.database)
        first = [add_attempt(self.database, f"user{n}.example") for n in range(3)]
        emitter, stream_a = self.emitter()
        self.assertEqual(self.exporter(emitter).poll(), 3)
        emitter.close()
        later = [add_attempt(self.database, f"user{n}.example") for n in range(3, 5)]
        emitter, stream_b = self.emitter()
        exporter = self.exporter(emitter)
        self.assertEqual(exporter.poll(), 2)
        self.assertEqual(exporter.poll(), 0)
        ids = [event["criteria"]["log_id"] for event in auth_events(lines(stream_a) + lines(stream_b))]
        self.assertEqual(ids, first + later)
        self.assert_chains_intact()

    def test_backlog_is_read_in_batches(self) -> None:
        """More rows than one query returns are all exported in one round."""
        make_database(self.database)
        for n in range(7):
            add_attempt(self.database, f"user{n}.example")
        emitter, stream = self.emitter()
        self.assertEqual(self.exporter(emitter, batch=3).poll(), 7)
        self.assertEqual(len(auth_events(lines(stream))), 7)
        self.assert_chains_intact()

    def test_a_round_is_capped(self) -> None:
        """A long backlog is exported over several rounds, in order."""
        make_database(self.database)
        for n in range(7):
            add_attempt(self.database, f"user{n}.example")
        emitter, stream = self.emitter()
        state = edge_audit.load_state(self.state_dir)
        exporter = edge_audit.AuthLogExporter(emitter, self.database, self.state_dir, state, batch=3, round_rows=4)
        self.assertEqual([exporter.poll(), exporter.poll(), exporter.poll()], [4, 3, 0])
        self.assertEqual([e["criteria"]["log_id"] for e in auth_events(lines(stream))], list(range(1, 8)))
        self.assert_chains_intact()

    def test_replaced_database_is_recorded_and_read_from_the_start(self) -> None:
        """A new database restarts its ids at 1; the jump is an admin event."""
        make_database(self.database)
        for _ in range(3):
            add_attempt(self.database)
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        self.database.unlink()
        make_database(self.database, applied="2026-02-01 07:00:00.5+00:00")
        add_attempt(self.database, "bob.example")
        self.assertEqual(self.exporter(emitter).poll(), 1)
        events = lines(stream)
        rewind = next(event for event in events if event["operation"] == "auth_log.rewind")
        self.assertEqual(rewind["action"], "admin")
        self.assertEqual(rewind["actor"], {"user": None, "via": "system"})
        self.assertEqual(rewind["criteria"], {"reason": "database_replaced", "previous_last_id": 3})
        self.assertEqual(auth_events(events)[-1]["actor"]["user"], "bob.example")
        self.assertEqual(edge_audit.load_state(self.state_dir).database, "2026-02-01 07:00:00.5+00:00")
        self.assert_chains_intact()

    def test_restored_backup_is_read_again_from_the_start(self) -> None:
        """A restored backup hands out ids already exported: nothing may be skipped."""
        make_database(self.database)
        for _ in range(5):
            add_attempt(self.database)
        edge_audit.save_state(self.state_dir, edge_audit.ExportState(FIRST_MIGRATION, 8))
        add_attempt(self.database, "bob.example")  # id 6, already handed out before the restore
        emitter, stream = self.emitter()
        self.assertEqual(self.exporter(emitter).poll(), 6)
        events = lines(stream)
        rewind = next(event for event in events if event["operation"] == "auth_log.rewind")
        self.assertEqual(rewind["criteria"], {"reason": "sequence_behind", "previous_last_id": 8})
        self.assertEqual([e["criteria"]["log_id"] for e in auth_events(events)], [1, 2, 3, 4, 5, 6])
        self.assertEqual(auth_events(events)[-1]["actor"]["user"], "bob.example")
        self.assert_chains_intact()

    def test_deleted_rows_do_not_rewind(self) -> None:
        """Rows removed from the end keep their ids allocated: no jump."""
        make_database(self.database)
        for _ in range(4):
            add_attempt(self.database)
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.execute("DELETE FROM authentication_logs WHERE id > 2")
            conn.commit()
        self.assertEqual(self.exporter(emitter).poll(), 0)
        self.assertNotIn("auth_log.rewind", [event["operation"] for event in lines(stream)])
        self.assertEqual(add_attempt(self.database), 5)
        self.assertEqual(self.exporter(emitter).poll(), 1)
        self.assert_chains_intact()

    def test_corrupt_state_is_refused(self) -> None:
        """A damaged position is never guessed at."""
        bad = ("{", "[]", '{"version": 1, "database": null}', '{"version": 2, "database": null, "last_id": 0}')
        for content in bad:
            (self.state_dir / edge_audit.STATE_FILE).write_text(content, encoding="utf-8")
            with self.assertRaises(edge_audit.StateError, msg=content):
                edge_audit.load_state(self.state_dir)
        (self.state_dir / edge_audit.STATE_FILE).write_text(
            '{"version": 1, "database": null, "last_id": true}', encoding="utf-8"
        )
        with self.assertRaises(edge_audit.StateError):
            edge_audit.load_state(self.state_dir)

    def test_write_failure_leaves_the_row_unexported(self) -> None:
        """Fail closed: the position only moves past rows that were written."""

        class FailAfter(io.StringIO):
            """Accepts the first writes, then fails like a full disk."""

            def __init__(self, good_writes: int) -> None:
                super().__init__()
                self.good_writes = good_writes

            def write(self, s: str) -> int:
                if self.good_writes <= 0:
                    raise OSError("disk full")
                self.good_writes -= 1
                return super().write(s)

        make_database(self.database)
        add_attempt(self.database)
        stream = FailAfter(good_writes=1)  # the chain's start event
        emitter = AuditEmitter(edge_audit.SERVICE, "0.11.0", stream=stream, heartbeat_interval_s=0)
        emitter.start()
        with self.assertRaises(edge_audit.AuditWriteError):
            self.exporter(emitter).poll()
        self.assertEqual(edge_audit.load_state(self.state_dir).last_id, 0)
        stream.good_writes = 1
        emitter.close()

    def test_database_is_only_read(self) -> None:
        """A read-only database file and directory (the :ro mount) are enough."""
        make_database(self.database)
        add_attempt(self.database)
        before = self.database.read_bytes()
        self.database.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        self.db_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(self.db_dir.chmod, stat.S_IRWXU)
        emitter, _ = self.emitter()
        self.assertEqual(self.exporter(emitter).poll(), 1)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(sorted(path.name for path in self.db_dir.iterdir()), ["db.sqlite3"])
        self.assert_chains_intact()

    def test_stop_ends_a_round(self) -> None:
        """A stop request is honoured between rows."""
        make_database(self.database)
        for _ in range(3):
            add_attempt(self.database)
        emitter, _ = self.emitter()
        stop = threading.Event()
        stop.set()
        state = edge_audit.load_state(self.state_dir)
        exporter = edge_audit.AuthLogExporter(emitter, self.database, self.state_dir, state, stop=stop)
        self.assertEqual(exporter.poll(), 0)


class ServeWorkspace(Workspace):
    """A workspace with the environment and stdout capture the subcommands use."""

    def environ(self, **extra: str) -> dict[str, str]:
        """Point the subcommands at the workspace.

        Args:
            **extra: More variables.

        Returns:
            The environment.
        """
        return {
            "AUDIT_AUTHELIA_DB": str(self.database),
            "AUDIT_USERS_FILE": str(self.tmp / "users.yml"),
            "AUDIT_STATE_DIR": str(self.state_dir),
            "AUDIT_VERSION_FILE": str(self.version_file),
            "AUDIT_ALIVE_FILE": str(self.tmp / "alive"),
            "AUDIT_POLL_INTERVAL": "1",
            **extra,
        }

    @contextlib.contextmanager
    def captured_stdout(self) -> Iterator[io.StringIO]:
        """Capture what the emitter writes to the process's stdout.

        Yields:
            The captured stream.
        """
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            yield stream
        self.streams.append(stream)


class ServeTest(ServeWorkspace):
    """The service loop, as the container runs it."""

    def test_serve_exports_until_stopped(self) -> None:
        """start, config.audit, auth events, the users baseline, shutdown — one intact chain."""
        make_database(self.database)
        add_attempt(self.database)
        add_attempt(self.database, "", successful=False)
        (self.tmp / "users.yml").write_text(
            "users:\n  alice.example:\n    password: x\n    groups: [users]\n", encoding="utf-8"
        )
        stop = threading.Event()
        result: list[int] = []
        with self.captured_stdout() as stream:
            worker = threading.Thread(target=lambda: result.append(edge_audit.serve(self.environ(), stop)))
            worker.start()
            deadline = time.monotonic() + 10
            while len(auth_events(lines(stream))) < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            stop.set()
            worker.join(10)
        self.assertEqual(result, [0])
        events = lines(stream)
        self.assertEqual(
            [event["operation"] for event in events],
            [
                "start",
                "config.audit",
                "login.1fa",
                "login.1fa",
                "account.baseline",
                "account.baseline.group",
                "shutdown",
            ],
        )
        self.assertEqual(
            events[1]["criteria"],
            {
                "sources": ["authelia.authentication_logs", "authelia.users_file"],
                "poll_interval_s": 1,
                "resume_after_id": 0,
            },
        )
        self.assertEqual(events[4]["target"], {"kind": "account", "ids": ["alice.example"], "count": 1})
        self.assertTrue((self.tmp / "alive").exists())
        self.assertEqual(edge_audit.health(self.environ()), 0)
        self.assert_chains_intact()
        self.assertTrue(verify_chain(events).heads[str(events[0]["instance"])].ended)

    def test_serve_stops_when_the_position_cannot_be_saved(self) -> None:
        """An unwritable state directory stops the service (exit 1) after a clean shutdown event."""
        make_database(self.database)
        add_attempt(self.database)
        self.state_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # readable, so startup succeeds; not writable
        self.addCleanup(self.state_dir.chmod, stat.S_IRWXU)
        with self.captured_stdout() as stream, self.assertLogs("auth-audit", level="ERROR") as logged:
            status = edge_audit.serve(self.environ(), threading.Event())
        self.assertEqual(status, 1)
        self.assertIn("cannot write the export position", "\n".join(logged.output))
        self.assertNotIn("could not be written (", "\n".join(logged.output))
        self.assertEqual(lines(stream)[-1]["operation"], "shutdown")
        self.assert_chains_intact()

    def test_serve_refuses_a_corrupt_position(self) -> None:
        """Exit 1 before writing anything; the operator decides."""
        (self.state_dir / edge_audit.STATE_FILE).write_text("{", encoding="utf-8")
        with self.captured_stdout() as stream:
            self.assertEqual(edge_audit.serve(self.environ(), threading.Event()), 1)
        self.assertEqual(stream.getvalue(), "")

    def test_serve_refuses_bad_configuration(self) -> None:
        """A bad interval or a missing version stops startup (exit 2)."""
        with self.captured_stdout() as stream:
            self.assertEqual(edge_audit.serve(self.environ(AUDIT_POLL_INTERVAL="0"), threading.Event()), 2)
            self.version_file.unlink()
            self.assertEqual(edge_audit.serve(self.environ(), threading.Event()), 2)
        self.assertEqual(stream.getvalue(), "")

    def test_health(self) -> None:
        """Healthy while the last good round is recent."""
        alive = self.tmp / "alive"
        self.assertEqual(edge_audit.health(self.environ()), 1)
        alive.touch()
        self.assertEqual(edge_audit.health(self.environ()), 0)
        self.assertEqual(edge_audit.health(self.environ(), now=time.time() + 61), 1)
        self.assertEqual(edge_audit.health(self.environ(AUDIT_POLL_INTERVAL="60"), now=time.time() + 170), 0)


class AdminTest(ServeWorkspace):
    """The admin subcommand the account targets run."""

    def test_admin_event(self) -> None:
        """One admin event in a chain of its own, attributed to the operator."""
        env = self.environ(AUDIT_CLI_USER="ops.example")
        with self.captured_stdout() as stream:
            self.assertEqual(edge_audit.admin(env, "account.totp", "alice.example", "ok", ["force=true"]), 0)
        start, event, shutdown = lines(stream)
        self.assertEqual((start["operation"], shutdown["operation"]), ("start", "shutdown"))
        self.assertEqual(event["action"], "admin")
        self.assertEqual(event["operation"], "account.totp")
        self.assertEqual(event["outcome"], "ok")
        self.assertEqual(event["actor"], {"user": "ops.example", "via": "cli"})
        self.assertEqual(event["target"], {"kind": "account", "ids": ["alice.example"], "count": 1})
        self.assertEqual(event["criteria"], {"force": True})
        self.assert_chains_intact()

    def test_failed_change_is_an_error_event(self) -> None:
        """A change that failed (perhaps in part) is still recorded."""
        with self.captured_stdout() as stream:
            self.assertEqual(edge_audit.admin(self.environ(), "account.totp", "alice.example", "error", []), 0)
        (event,) = [event for event in lines(stream) if event["action"] == "admin"]
        self.assertEqual(event["outcome"], "error")
        self.assertEqual(event["actor"], {"user": None, "via": "cli"})
        self.assertNotIn("criteria", event)
        self.assert_chains_intact()

    def test_bad_arguments_write_nothing(self) -> None:
        """Unknown operation, odd account name, bad criteria: exit 2, no event."""
        bad = [
            ("account.rename", "alice.example", "ok", []),
            ("account.totp", "", "ok", []),
            ("account.totp", "alice example", "ok", []),
            ("account.totp", "a" * 101, "ok", []),
            ("account.totp", "alice.example", "denied", []),
            ("account.totp", "alice.example", "ok", ["Force=1"]),
        ]
        with self.captured_stdout() as stream:
            with contextlib.redirect_stderr(io.StringIO()):
                for args in bad:
                    self.assertEqual(edge_audit.admin(self.environ(), *args), 2, args)
        self.assertEqual(stream.getvalue(), "")

    def test_unwritable_stream_fails(self) -> None:
        """No stream, no change recorded: exit 1."""
        with self.captured_stdout() as stream:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    edge_audit.admin(self.environ(AUDIT_OUTPUT="nowhere"), "account.totp", "a.example", "ok", []), 1
                )
                self.assertEqual(edge_audit.check(self.environ(AUDIT_OUTPUT="nowhere")), 1)
        self.assertEqual(stream.getvalue(), "")

    def test_check(self) -> None:
        """The check passes with a stream and a version, and writes nothing."""
        with self.captured_stdout() as stream:
            self.assertEqual(edge_audit.check(self.environ()), 0)
            self.version_file.unlink()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(edge_audit.check(self.environ()), 1)
        self.assertEqual(stream.getvalue(), "")

    def test_command_line(self) -> None:
        """The argument order the wrapper script uses parses."""
        env = self.environ(AUDIT_CLI_USER="ops.example")
        with self.captured_stdout() as stream:
            with mock.patch.dict(os.environ, env, clear=True):
                argv = ["admin", "--outcome", "error", "account.totp", "alice.example", "force=false"]
                status = edge_audit.main(argv)
        self.assertEqual(status, 0)
        (event,) = [event for event in lines(stream) if event["action"] == "admin"]
        self.assertEqual((event["outcome"], event["criteria"]), ("error", {"force": False}))
        self.assert_chains_intact()


class VerifyTest(Workspace):
    """The verify subcommand the smoke test pipes the container log into."""

    def log(self) -> list[str]:
        """Produce a container log: ops lines on stderr between audit lines.

        Returns:
            The log lines.
        """
        make_database(self.database)
        add_attempt(self.database)
        emitter, stream = self.emitter()
        self.exporter(emitter).poll()
        emitter.close()
        audit = stream.getvalue().splitlines()
        return ["2026-01-31 09:15:31,000 INFO auth-audit: exported 1 authentication log rows", *audit]

    def test_intact_log_verifies(self) -> None:
        """Every chain intact: exit 0 and a one-line summary."""
        out = io.StringIO()
        self.assertEqual(edge_audit.verify(self.log(), out), 0)
        self.assertEqual(out.getvalue(), "3 audit events in 1 chains, 0 problems\n")

    def test_altered_line_fails(self) -> None:
        """A changed event breaks its hash."""
        log = self.log()
        log[2] = log[2].replace('"outcome":"ok"', '"outcome":"denied"')
        out = io.StringIO()
        self.assertEqual(edge_audit.verify(log, out), 1)
        self.assertIn("bad_hash", out.getvalue())

    def test_removed_line_and_junk_fail(self) -> None:
        """A missing event and an unparseable audit line are both reported."""
        log = self.log()
        del log[2]
        log.append('{"stream":"audit", not json')
        out = io.StringIO()
        self.assertEqual(edge_audit.verify(log, out), 1)
        self.assertIn("seq_gap", out.getvalue())
        self.assertIn("schema", out.getvalue())

    def test_no_events_fails(self) -> None:
        """Nothing to check is not a pass."""
        self.assertEqual(edge_audit.verify(["plain ops line"], io.StringIO()), 1)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class WrapperScriptTest(unittest.TestCase):
    """scripts/audit-admin.sh, with a stand-in for docker compose."""

    FAKE_COMPOSE = """#!/usr/bin/env bash
printf 'compose %s\\n' "$*" >> "$FAKE_LOG"
case "$*" in
  *" check") exit "${FAKE_CHECK:-0}" ;;
  *" admin "*) exit "${FAKE_ADMIN:-0}" ;;
esac
"""

    def setUp(self) -> None:
        """Create the stand-in and the call log."""
        self.tmp = Path(tempfile.mkdtemp(prefix="edge-audit-wrapper-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.log = self.tmp / "calls.log"
        compose = self.tmp / "fake-compose"
        compose.write_text(self.FAKE_COMPOSE, encoding="utf-8")
        compose.chmod(0o755)
        self.compose = f"{compose} --env-file .env -f docker/compose.yaml"

    def run_wrapper(self, change_status: int, **env: str) -> tuple[int, list[str]]:
        """Run an account change through the wrapper.

        Args:
            change_status: The change command's exit status.
            **env: FAKE_CHECK / FAKE_ADMIN / SUDO_USER overrides.

        Returns:
            The wrapper's exit status and the calls, in order.
        """
        change = f'echo change >> "$FAKE_LOG"; exit {change_status}'
        result = subprocess.run(
            [*WRAPPER, "account.totp", "alice.example", "force=true", "--", "sh", "-c", change],
            env={"PATH": os.environ["PATH"], "COMPOSE": self.compose, "FAKE_LOG": str(self.log), **env},
            capture_output=True,
            text=True,
            check=False,
        )
        calls = self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []
        return result.returncode, calls

    def test_successful_change_is_recorded_ok(self) -> None:
        """check, change, admin --outcome ok — attributed to the sudo user."""
        status, calls = self.run_wrapper(0, SUDO_USER="ops.example")
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0].endswith("auth-audit python /app/edge_audit.py check"), calls[0])
        self.assertEqual(calls[1], "change")
        self.assertIn("exec -T -e AUDIT_CLI_USER=ops.example auth-audit", calls[2])
        self.assertTrue(
            calls[2].endswith("edge_audit.py admin --outcome ok account.totp alice.example force=true"), calls[2]
        )

    def test_failed_change_is_recorded_as_error(self) -> None:
        """The change's status is passed on; the event says error."""
        status, calls = self.run_wrapper(3)
        self.assertEqual(status, 3)
        self.assertTrue(calls[2].endswith("admin --outcome error account.totp alice.example force=true"), calls[2])

    def test_nothing_changes_without_the_audit_stream(self) -> None:
        """A failing check stops before the change."""
        status, calls = self.run_wrapper(0, FAKE_CHECK="1")
        self.assertEqual(status, 1)
        self.assertEqual(len(calls), 1)

    def test_unrecorded_change_fails_loudly(self) -> None:
        """When the event cannot be written, the target fails even after a good change."""
        status, calls = self.run_wrapper(0, FAKE_ADMIN="1")
        self.assertEqual(status, 1)
        self.assertEqual(calls[1], "change")


if __name__ == "__main__":
    unittest.main()
