"""Tests for auth_retention.py, the auth-retention service.

Run from the repo root: ``python3 -m unittest discover -s audit/tests -t audit``.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import auth_retention
import auth_sweep
from audit_event import AuditEmitter, verify_chain
from tests.authelia_fixture import (
    NOW,
    add_attempt,
    add_totp_step,
    events,
    export_position,
    go_time,
    ids,
    make_database,
    sqlite_time,
)

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "docker" / "compose.yaml"
OLD = NOW - timedelta(days=45)


class FailingStream(io.StringIO):
    """Fails every write, like a closed container stream."""

    def write(self, s: str) -> int:
        """Fail.

        Args:
            s: The text.

        Raises:
            OSError: Always.
        """
        del s
        raise OSError("stream closed")


class ServiceWorkspace(unittest.TestCase):
    """A database, state directory, version and status file per test."""

    def setUp(self) -> None:
        """Create the temporary paths."""
        self.tmp = Path(tempfile.mkdtemp(prefix="auth-retention-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.database = self.tmp / "db.sqlite3"
        self.state_dir = self.tmp / "state"
        self.state_dir.mkdir()
        self.version_file = self.tmp / "VERSION"
        self.version_file.write_text("0.16.0\n", encoding="utf-8")
        self.status_file = self.tmp / "status.json"
        self.streams: list[io.StringIO] = []

    def settings(self, **extra: str) -> auth_retention.Settings:
        """Point the service at the workspace.

        Args:
            **extra: More variables.

        Returns:
            The settings.
        """
        return auth_retention.Settings.from_env(
            {
                "AUDIT_AUTHELIA_DB": str(self.database),
                "AUDIT_STATE_DIR": str(self.state_dir),
                "AUDIT_VERSION_FILE": str(self.version_file),
                "AUTH_RETENTION_STATUS_FILE": str(self.status_file),
                "EDGE_AUTH_RETENTION_DAYS": "30",
                **extra,
            }
        )

    def emitter(self) -> tuple[AuditEmitter, io.StringIO]:
        """Start an emitter on a captured stream.

        Returns:
            The emitter and its stream.
        """
        stream = io.StringIO()
        emitter = AuditEmitter("edge-plane", "0.16.0", stream=stream, heartbeat_interval_s=0)
        emitter.start()
        self.addCleanup(emitter.close)
        self.streams.append(stream)
        return emitter, stream

    @contextlib.contextmanager
    def serving(self, settings: auth_retention.Settings) -> Iterator[tuple[io.StringIO, list[int], threading.Event]]:
        """Run ``serve`` in a thread with its stdout captured, and stop it on exit.

        Args:
            settings: The settings.

        Yields:
            The captured stream, the exit status (once stopped) and the stop event.
        """
        stream = io.StringIO()
        stop = threading.Event()
        result: list[int] = []
        with contextlib.redirect_stdout(stream):
            worker = threading.Thread(target=lambda: result.append(auth_retention.serve(settings, None, stop)))
            worker.start()
            try:
                yield stream, result, stop
            finally:
                stop.set()
                worker.join(10)
        self.streams.append(stream)

    def wait_for(self, condition: Any, timeout: float = 10.0) -> None:
        """Wait until ``condition()`` holds.

        Args:
            condition: A callable returning truthy when done.
            timeout: Seconds to wait at most.
        """
        deadline = time.monotonic() + timeout
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(condition(), "timed out")

    def status(self) -> dict[str, Any]:
        """Read the status file.

        Returns:
            Its content, or an empty mapping before the first write.
        """
        try:
            return dict(json.loads(self.status_file.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return {}

    def assert_chains_intact(self) -> None:
        """Assert every captured chain verifies."""
        report = verify_chain([event for stream in self.streams for event in events(stream)])
        self.assertEqual(report.problems, [])


class ParseTest(unittest.TestCase):
    """The settings."""

    def test_days(self) -> None:
        """30 by default; off; whole ASCII days from 1 to 3650 only."""
        self.assertEqual(auth_retention.parse_days(None), 30)
        self.assertEqual(auth_retention.parse_days(" 7 "), 7)
        self.assertIsNone(auth_retention.parse_days("OFF"))
        for bad in ("0", "3651", "1.5", "-1", "٣", "30d"):
            with self.subTest(bad), self.assertRaises(ValueError):
                auth_retention.parse_days(bad)

    def test_interval(self) -> None:
        """An hour by default; 60 s to a day."""
        self.assertEqual(auth_retention.parse_interval(""), 3600)
        self.assertEqual(auth_retention.parse_interval("60"), 60)
        for bad in ("59", "86401", "1h"):
            with self.subTest(bad), self.assertRaises(ValueError):
                auth_retention.parse_interval(bad)


class ServeTest(ServiceWorkspace):
    """The service loop, as the container runs it."""

    def test_serve_sweeps_and_reports(self) -> None:
        """start, config.audit, a delete record, shutdown: one intact chain; healthy."""
        make_database(self.database)
        add_attempt(self.database, go_time(OLD))
        add_totp_step(self.database, sqlite_time(OLD))
        export_position(self.state_dir, self.database, 1)
        settings = self.settings()
        with self.serving(settings) as (stream, result, _):
            self.wait_for(lambda: self.status().get("tables", {}).get("banned_ip", {}).get("state") == "ok")
            self.assertEqual(auth_retention.health(settings), 0)
        self.assertEqual(result, [0])
        operations = [event["operation"] for event in events(stream)]
        self.assertEqual(operations, ["start", "config.audit", "retention.sweep", "retention.sweep", "shutdown"])
        config = events(stream)[1]["criteria"]
        self.assertEqual(config["retention_days"], 30)
        self.assertEqual(config["stores"], list(auth_sweep.TABLES))
        self.assertTrue(config["auth_log_after_export"])
        self.assertEqual(ids(self.database, "authentication_logs"), [])
        self.assertEqual(ids(self.database, "totp_history"), [])
        self.assert_chains_intact()

    def test_off_never_opens_the_database(self) -> None:
        """off: stated in config.audit, warned about, nothing touched; healthy."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        before = self.database.read_bytes()
        settings = self.settings(EDGE_AUTH_RETENTION_DAYS="off")
        with self.assertLogs("auth-retention", level="WARNING") as logged:
            with self.serving(settings) as (stream, _, _):
                self.wait_for(lambda: bool(self.status()))
                self.assertEqual(auth_retention.health(settings), 0)
        self.assertIn("retention is off", "\n".join(logged.output))
        self.assertIsNone(events(stream)[1]["criteria"]["retention_days"])
        self.assertEqual(self.database.read_bytes(), before)

    def test_an_unwritable_stream_stops_before_deleting(self) -> None:
        """Exit 1, nothing deleted."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        with (
            contextlib.redirect_stdout(FailingStream()),
            self.assertLogs("auth-retention", level="ERROR"),
        ):
            self.assertEqual(auth_retention.serve(self.settings(), None, threading.Event()), 1)
        self.assertEqual(ids(self.database, "totp_history"), [1])

    def test_bad_configuration_exits_2(self) -> None:
        """A missing version stops startup."""
        self.version_file.unlink()
        with self.assertLogs("auth-retention", level="ERROR"):
            self.assertEqual(auth_retention.serve(self.settings(), None, threading.Event()), 2)


class RoundsTest(ServiceWorkspace):
    """Refusals, holds and their records."""

    def test_a_refusal_is_recorded_once_and_resumes(self) -> None:
        """An unverified schema: one refused record per table across rounds; unhealthy; resumed once verified."""
        make_database(self.database, version=25)
        emitter, stream = self.emitter()
        settings = self.settings()
        rounds = auth_retention.Rounds(emitter, settings, threading.Event())
        with self.assertLogs("auth-retention", level="ERROR"):
            rounds.run(time.time())
            rounds.run(time.time())
        refused = [event for event in events(stream) if event["operation"] == "retention.refused"]
        self.assertEqual(len(refused), len(auth_sweep.TABLES))
        self.assertEqual(refused[0]["criteria"], {"store": "authentication_logs", "reason": "schema"})
        now = time.time()
        auth_retention.write_status(self.status_file, auth_retention.Status(now, now, 3600, rounds.tables))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(auth_retention.health(settings, now), 1)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.execute("DELETE FROM migrations WHERE version_after = 25")
            conn.commit()
        export_position(self.state_dir, self.database, 0)
        rounds.run(time.time())
        resumed = [event for event in events(stream) if event["operation"] == "retention.resumed"]
        self.assertEqual(len(resumed), len(auth_sweep.TABLES))
        self.assertTrue(all(status.state == "ok" for status in rounds.tables.values()))

    def test_a_hold_is_recorded_once(self) -> None:
        """No export position: the log is held, once recorded; the other tables are swept."""
        make_database(self.database)
        add_attempt(self.database, go_time(OLD))
        emitter, stream = self.emitter()
        rounds = auth_retention.Rounds(emitter, self.settings(), threading.Event())
        with self.assertLogs("auth-retention", level="WARNING"):
            rounds.run(time.time())
            rounds.run(time.time())
        held = [event for event in events(stream) if event["operation"] == "retention.held"]
        self.assertEqual(
            [event["criteria"] for event in held], [{"store": "authentication_logs", "reason": "export_position_missing"}]
        )
        self.assertEqual(rounds.tables["authentication_logs"].state, "held")
        self.assertEqual(rounds.tables["totp_history"].state, "ok")
        self.assertEqual(ids(self.database, "authentication_logs"), [1])


class HealthTest(ServiceWorkspace):
    """What ``health`` reports."""

    def write(self, *, written_at: float, started_at: float, tables: dict[str, auth_retention.TableStatus]) -> None:
        """Write a status file.

        Args:
            written_at: When it was written.
            started_at: When serve started.
            tables: The tables.
        """
        auth_retention.write_status(self.status_file, auth_retention.Status(written_at, started_at, 3600, tables))

    def test_health(self) -> None:
        """No status; recent ok; a stale loop; refused; off; pending within its grace."""
        settings = self.settings()
        now = time.time()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(auth_retention.health(settings, now), 1)
            self.write(written_at=now, started_at=now, tables={"t": auth_retention.TableStatus("ok", last_ok=now)})
            self.assertEqual(auth_retention.health(settings, now), 0)
            self.assertEqual(auth_retention.health(settings, now + 181), 1)
            self.write(written_at=now, started_at=now, tables={"t": auth_retention.TableStatus("refused", now, "x")})
            self.assertEqual(auth_retention.health(settings, now), 1)
            self.write(written_at=now, started_at=now - 10**6, tables={"t": auth_retention.TableStatus("off")})
            self.assertEqual(auth_retention.health(settings, now), 0)
            self.write(written_at=now, started_at=now - 60, tables={"t": auth_retention.TableStatus("pending")})
            self.assertEqual(auth_retention.health(settings, now), 0)
            self.write(written_at=now, started_at=now - 4 * 3600, tables={"t": auth_retention.TableStatus("held")})
            self.assertEqual(auth_retention.health(settings, now), 1)


class DryRunTest(ServiceWorkspace):
    """The read-only preview."""

    def test_dry_run_counts_without_changing_anything(self) -> None:
        """Counts per table, the hold reason, no names; the database is unchanged and nothing recorded."""
        make_database(self.database)
        add_attempt(self.database, go_time(OLD), username="sentinel.user.example")
        add_totp_step(self.database, sqlite_time(OLD))
        before = self.database.read_bytes()
        out = io.StringIO()
        self.assertEqual(auth_retention.dry_run(self.settings(), 30, out, now=NOW.timestamp()), 0)
        report = out.getvalue()
        self.assertIn("authentication_logs: would delete 0, keep 0, hold 1 (export_position_missing)", report)
        self.assertIn("totp_history: would delete 1, keep 0", report)
        self.assertNotIn("sentinel", report)
        self.assertEqual(self.database.read_bytes(), before)

    def test_schema_check(self) -> None:
        """0 for the pinned schema, 1 for anything else or no database."""
        out = io.StringIO()
        self.assertEqual(auth_retention.schema_check(self.database, out), 1)
        make_database(self.database)
        self.assertEqual(auth_retention.schema_check(self.database, out), 0)


@unittest.skipUnless(COMPOSE.is_file(), "needs the repo checkout (the pinned-image run mounts only audit/)")
class ComposeTest(unittest.TestCase):
    """docker/compose.yaml matches what this service was verified and hardened for."""

    @staticmethod
    def service_block(text: str, name: str) -> str:
        """Cut one service's block out of the compose file.

        Args:
            text: The compose file.
            name: The service.

        Returns:
            Its lines, up to the next service or top-level key.
        """
        match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|^\S)", text, re.MULTILINE | re.DOTALL)
        assert match is not None, name
        return match.group(1)

    def test_compose(self) -> None:
        """The verified Authelia image; auth-audit stays read-only; auth-retention is hardened."""
        text = COMPOSE.read_text(encoding="utf-8")
        authelia = self.service_block(text, "authelia")
        self.assertIn(f"image: {auth_sweep.VERIFIED_AUTHELIA_IMAGE}\n", authelia)
        self.assertIn("- edge-state:/authelia-state:ro\n", self.service_block(text, "auth-audit"))
        retention = self.service_block(text, "auth-retention")
        for line in (
            'user: "0:0"',
            "read_only: true",
            "network_mode: none",
            "- edge-audit-state:/state:ro",
            "- edge-state:/authelia-state\n",
            "EDGE_AUTH_RETENTION_DAYS: ${EDGE_AUTH_RETENTION_DAYS:-30}",
        ):
            self.assertIn(line, retention)
        self.assertNotIn("cap_add", retention)


if __name__ == "__main__":
    unittest.main()
