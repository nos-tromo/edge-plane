"""Tests for auth_sweep.py against a synthetic Authelia database with the pinned schema.

Run from the repo root: ``python3 -m unittest discover -s audit/tests -t audit``.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock
from datetime import timedelta
from pathlib import Path

import auth_sweep
import edge_audit
from audit_event import AuditEmitter, AuditWriteError, verify_chain
from tests.authelia_fixture import (
    NOW,
    SENTINEL_IP,
    SENTINEL_USER,
    add_attempt,
    add_ban,
    add_code,
    add_totp_step,
    add_verification,
    deletions,
    events,
    export_position,
    go_time,
    ids,
    make_database,
    sqlite_time,
)

OLD = NOW - timedelta(days=45)
YOUNG = NOW - timedelta(days=5)
DAYS = 30
#: Authelia's own queries for a ban in force (sql_provider_queries.go, v4.39.20).
ACTIVE_USER_BANS = (
    "SELECT id FROM banned_user WHERE revoked = FALSE AND (expires IS NULL OR expires > ?) AND expired IS NULL"
)
ACTIVE_IP_BANS = "SELECT id FROM banned_ip WHERE revoked = FALSE AND (expires IS NULL OR expires > ?) AND expired IS NULL"


class FailAfter(io.StringIO):
    """Accepts the first writes, then fails like a full disk."""

    def __init__(self, good_writes: int) -> None:
        """Count down the writes that succeed.

        Args:
            good_writes: How many writes succeed.
        """
        super().__init__()
        self.good_writes = good_writes

    def write(self, s: str) -> int:
        """Write, or fail once the good writes are used up.

        Args:
            s: The text.

        Returns:
            Its length.

        Raises:
            OSError: When no good writes are left.
        """
        if self.good_writes <= 0:
            raise OSError("disk full")
        self.good_writes -= 1
        return super().write(s)


class SweepWorkspace(unittest.TestCase):
    """A temporary database and auth-audit state directory per test."""

    def setUp(self) -> None:
        """Create the temporary paths."""
        self.tmp = Path(tempfile.mkdtemp(prefix="auth-sweep-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db_dir = self.tmp / "authelia"
        self.db_dir.mkdir()
        self.database = self.db_dir / "db.sqlite3"
        self.state_dir = self.tmp / "state"
        self.state_dir.mkdir()
        self.streams: list[io.StringIO] = []

    def emitter(self) -> tuple[AuditEmitter, io.StringIO]:
        """Start an emitter on a captured stream.

        Returns:
            The emitter and its stream.
        """
        stream = io.StringIO()
        emitter = AuditEmitter(edge_audit.SERVICE, "0.16.0", stream=stream, heartbeat_interval_s=0)
        emitter.start()
        self.addCleanup(emitter.close)
        self.streams.append(stream)
        return emitter, stream

    def sweeper(self, emitter: AuditEmitter, **options: object) -> auth_sweep.Sweeper:
        """Build a sweeper on the workspace with the test period.

        Args:
            emitter: The started emitter.
            **options: Overrides, e.g. ``max_batches``.

        Returns:
            The sweeper.
        """
        defaults: dict[str, object] = {"pause_s": 0.0, "busy_timeout_s": 0.2}
        defaults.update(options)
        return auth_sweep.Sweeper(emitter, self.database, self.state_dir, DAYS, **defaults)  # type: ignore[arg-type]

    def assert_chains_intact(self) -> None:
        """Assert every captured chain verifies."""
        report = verify_chain([event for stream in self.streams for event in events(stream)])
        self.assertEqual(report.problems, [])


class SchemaTest(SweepWorkspace):
    """The guard against an unverified schema."""

    def test_pinned_schema_passes(self) -> None:
        """The fixture is the schema the pinned image creates."""
        make_database(self.database)
        with contextlib.closing(auth_sweep.open_database(self.database, readonly=True)) as conn:
            self.assertEqual(auth_sweep.schema_problems(conn), [])
            self.assertEqual(auth_sweep.schema_version(conn), 24)

    def test_newer_schema_is_refused_and_nothing_is_deleted(self) -> None:
        """An unverified version stops the sweep before anything is touched or recorded."""
        make_database(self.database, version=25)
        add_attempt(self.database, go_time(OLD))
        export_position(self.state_dir, self.database, 1)
        emitter, stream = self.emitter()
        with self.assertRaises(auth_sweep.SchemaRefused) as caught:
            self.sweeper(emitter).sweep(NOW)
        self.assertIn("schema version 25 is not verified", str(caught.exception))
        self.assertEqual(ids(self.database, "authentication_logs"), [1])
        self.assertEqual(deletions(stream), [])

    def test_missing_column_is_refused(self) -> None:
        """A renamed column is named, never guessed at."""
        make_database(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.execute("ALTER TABLE totp_history RENAME COLUMN created_at TO created")
        with contextlib.closing(auth_sweep.open_database(self.database, readonly=True)) as conn:
            self.assertEqual(auth_sweep.schema_problems(conn), ["table totp_history lacks created_at"])

    def test_no_database_or_schema_means_waiting(self) -> None:
        """Before Authelia's first start nothing is read, and nothing is created."""
        emitter, _ = self.emitter()
        self.assertFalse(self.sweeper(emitter).sweep(NOW).ready)
        self.assertFalse(self.database.exists())
        self.database.touch()
        self.assertFalse(self.sweeper(emitter).sweep(NOW).ready)

    def test_migration_between_planning_and_deleting_is_caught(self) -> None:
        """The guard runs again inside the write transaction."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        emitter, stream = self.emitter()
        real_plan = auth_sweep.plan

        def plan_then_migrate(*args: object, **kwargs: object) -> auth_sweep.Plan:
            found = real_plan(*args, **kwargs)  # type: ignore[arg-type]
            with contextlib.closing(sqlite3.connect(self.database)) as conn:
                conn.execute(
                    "INSERT INTO migrations (version_before, version_after, application_version) VALUES (24, 25, 'x')"
                )
                conn.commit()
            return found

        with (
            mock.patch.object(auth_sweep, "plan", plan_then_migrate),
            self.assertRaises(auth_sweep.SchemaRefused),
        ):
            self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "totp_history"), [1])
        self.assertEqual(deletions(stream), [])


class ExportGateTest(SweepWorkspace):
    """The authentication log is deleted only after auth-audit exported it."""

    def setUp(self) -> None:
        """Three old rows and one young one; something to sweep in another table."""
        super().setUp()
        make_database(self.database)
        for _ in range(3):
            add_attempt(self.database, go_time(OLD))
        add_attempt(self.database, go_time(YOUNG))
        add_totp_step(self.database, sqlite_time(OLD))

    def test_only_exported_old_rows_are_deleted(self) -> None:
        """Rows past the position stay, counted as held; young rows stay."""
        export_position(self.state_dir, self.database, 2)
        emitter, stream = self.emitter()
        result = self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "authentication_logs"), [3, 4])
        table = result.tables["authentication_logs"]
        self.assertEqual((table.deleted, table.held, table.held_reason), (2, 1, None))
        record = [event for event in deletions(stream) if event["target"]["kind"] == "authentication_logs"][0]
        self.assertEqual(record["target"]["ids"], ["1", "2"])
        self.assertEqual(record["criteria"]["exported_through"], 2)
        self.assert_chains_intact()

    def test_every_doubtful_position_holds_the_whole_log(self) -> None:
        """Missing, damaged, foreign or ahead: the log stays, the other tables are swept."""
        cases = {
            "export_position_missing": lambda: None,
            "export_position_invalid": lambda: (self.state_dir / edge_audit.STATE_FILE).write_text(
                "{", encoding="utf-8"
            ),
            "export_position_other_database": lambda: edge_audit.save_state(
                self.state_dir, edge_audit.ExportState(database="2020-01-01 00:00:00+00:00", last_id=4)
            ),
            "export_position_ahead": lambda: export_position(self.state_dir, self.database, 99),
        }
        for reason, arrange in cases.items():
            with self.subTest(reason):
                (self.state_dir / edge_audit.STATE_FILE).unlink(missing_ok=True)
                arrange()
                emitter, _ = self.emitter()
                result = self.sweeper(emitter).sweep(NOW)
                self.assertEqual(result.tables["authentication_logs"].held_reason, reason)
                self.assertEqual(ids(self.database, "authentication_logs"), [1, 2, 3, 4])
        self.assertEqual(ids(self.database, "totp_history"), [])

    def test_deleting_every_row_does_not_rewind_the_export(self) -> None:
        """DELETE never lowers sqlite_sequence: auth-audit neither re-exports nor skips."""
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.execute("DELETE FROM authentication_logs WHERE id = 4")
            conn.commit()
        emitter, stream = self.emitter()
        state = edge_audit.load_state(self.state_dir)
        exporter = edge_audit.AuthLogExporter(emitter, self.database, self.state_dir, state)
        self.assertEqual(exporter.poll(), 3)
        self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "authentication_logs"), [])
        self.assertEqual(exporter.poll(), 0)
        self.assertEqual(add_attempt(self.database, go_time(NOW)), 5)
        self.assertEqual(exporter.poll(), 1)
        self.assertNotIn("auth_log.rewind", [event["operation"] for event in events(stream)])
        self.assert_chains_intact()


class RuleTest(SweepWorkspace):
    """What is due in each table."""

    def test_mixed_formats_and_offsets_are_compared_as_times(self) -> None:
        """Rows whose text order and time order disagree; a row exactly at the cutoff stays."""
        make_database(self.database)
        cutoff = NOW - timedelta(days=DAYS)
        # 1 h before the cutoff, written at +02:00: its text sorts after the cutoff's.
        old_east = add_attempt(self.database, go_time(cutoff - timedelta(hours=1), offset_hours=2))
        # 1 h after the cutoff, written at -05:00: its text sorts before the cutoff's.
        young_west = add_attempt(self.database, go_time(cutoff + timedelta(hours=1), offset_hours=-5))
        at_cutoff = add_attempt(self.database, go_time(cutoff))
        whole_second = add_attempt(self.database, go_time(OLD.replace(microsecond=0)))
        add_totp_step(self.database, sqlite_time(cutoff - timedelta(seconds=1)))
        add_totp_step(self.database, sqlite_time(cutoff + timedelta(seconds=1)))
        export_position(self.state_dir, self.database, 4)
        emitter, _ = self.emitter()
        self.sweeper(emitter).sweep(NOW)
        remaining = ids(self.database, "authentication_logs")
        self.assertNotIn(old_east, remaining)
        self.assertNotIn(whole_second, remaining)
        self.assertEqual(remaining, [young_west, at_cutoff])
        self.assertEqual(ids(self.database, "totp_history"), [2])

    def test_unparseable_time_refuses_only_its_table(self) -> None:
        """Nothing is deleted from it; the other tables are swept."""
        make_database(self.database)
        add_totp_step(self.database, "yesterday")
        add_verification(self.database, go_time(OLD), go_time(OLD + timedelta(minutes=5)))
        emitter, stream = self.emitter()
        with self.assertLogs("auth-retention", level="ERROR") as logged:
            result = self.sweeper(emitter).sweep(NOW)
        self.assertEqual(result.tables["totp_history"].refused, "time_format")
        self.assertNotIn("yesterday", "\n".join(logged.output))
        self.assertEqual(ids(self.database, "totp_history"), [1])
        self.assertEqual(ids(self.database, "identity_verification"), [])
        self.assertEqual([event["target"]["kind"] for event in deletions(stream)], ["identity_verification"])

    def test_codes_count_from_their_expiry(self) -> None:
        """A code issued long ago that is still valid stays."""
        make_database(self.database)
        add_code(self.database, go_time(OLD), go_time(OLD + timedelta(minutes=5)))
        still_valid = add_code(self.database, go_time(OLD), go_time(NOW + timedelta(days=1)))
        add_verification(self.database, go_time(OLD), go_time(OLD + timedelta(minutes=5)))
        valid_token = add_verification(self.database, go_time(OLD), go_time(NOW + timedelta(hours=1)))
        emitter, _ = self.emitter()
        self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "one_time_code"), [still_valid])
        self.assertEqual(ids(self.database, "identity_verification"), [valid_token])

    def test_bans_in_force_are_never_deleted(self) -> None:
        """Only bans that ended more than the period ago go; Authelia's view of bans in force is unchanged."""
        make_database(self.database)
        kept: dict[str, list[int]] = {}
        for table in ("banned_user", "banned_ip"):
            subject = "alice.example" if table == "banned_user" else "192.0.2.10"
            active_temporary = add_ban(
                self.database, table, when=go_time(YOUNG), expires=go_time(NOW + timedelta(hours=1)), subject=subject
            )
            permanent = add_ban(self.database, table, when=go_time(OLD), expires=None, subject=subject)
            ended_recently = add_ban(self.database, table, when=go_time(YOUNG), expires=go_time(YOUNG), subject=subject)
            odd_revoked = add_ban(self.database, table, when=go_time(OLD), expires=None, revoked=True, subject=subject)
            add_ban(self.database, table, when=go_time(OLD), expires=go_time(OLD), subject=subject)
            add_ban(
                self.database,
                table,
                when=go_time(OLD),
                expires=None,
                expired=go_time(OLD),
                revoked=True,
                subject=subject,
            )
            kept[table] = [active_temporary, permanent, ended_recently, odd_revoked]
        moment = go_time(NOW)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            before = (conn.execute(ACTIVE_USER_BANS, (moment,)).fetchall(), conn.execute(ACTIVE_IP_BANS, (moment,)).fetchall())
        emitter, _ = self.emitter()
        self.sweeper(emitter).sweep(NOW)
        for table, expected in kept.items():
            self.assertEqual(ids(self.database, table), expected)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            after = (conn.execute(ACTIVE_USER_BANS, (moment,)).fetchall(), conn.execute(ACTIVE_IP_BANS, (moment,)).fetchall())
        self.assertEqual(before, after)
        self.assertTrue(before[0] and before[1])


class RecordTest(SweepWorkspace):
    """Every deletion is recorded before it is committed."""

    def test_a_failed_record_rolls_the_batch_back(self) -> None:
        """No record, no deletion."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        stream = FailAfter(good_writes=1)  # the chain's start event
        emitter = AuditEmitter(edge_audit.SERVICE, "0.16.0", stream=stream, heartbeat_interval_s=0)
        emitter.start()
        with self.assertRaises(AuditWriteError):
            self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "totp_history"), [1])
        stream.good_writes = 1
        emitter.close()

    def test_a_failed_commit_is_recorded_as_an_error(self) -> None:
        """The batch is rolled back, and an error record points at its ok record."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        emitter, stream = self.emitter()
        real_open = auth_sweep.open_database

        class CommitFails:
            """A connection whose COMMIT fails like a full disk."""

            def __init__(self, conn: sqlite3.Connection) -> None:
                self._conn = conn

            def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
                if sql == "COMMIT":
                    raise sqlite3.OperationalError("disk I/O error")
                return self._conn.execute(sql, *args)

            def __getattr__(self, name: str) -> object:
                return getattr(self._conn, name)

        def failing_open(*args: object, **kwargs: object) -> object:
            return CommitFails(real_open(*args, **kwargs))  # type: ignore[arg-type]

        with (
            mock.patch.object(auth_sweep, "open_database", failing_open),
            self.assertLogs("auth-retention", level="ERROR"),
            self.assertRaises(sqlite3.OperationalError),
        ):
            self.sweeper(emitter).sweep(NOW)
        self.assertEqual(ids(self.database, "totp_history"), [1])
        ok, error = deletions(stream)
        self.assertEqual((ok["outcome"], error["outcome"]), ("ok", "error"))
        self.assertEqual(error["parent_event_id"], ok["event_id"])
        self.assert_chains_intact()

    def test_a_lock_held_too_long_deletes_and_records_nothing(self) -> None:
        """While Authelia (here: another connection) holds the write lock, the batch waits, then gives up."""
        make_database(self.database)
        add_totp_step(self.database, sqlite_time(OLD))
        emitter, stream = self.emitter()
        with contextlib.closing(sqlite3.connect(self.database, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                self.sweeper(emitter, busy_timeout_s=0.1).sweep(NOW)
            holder.execute("ROLLBACK")
        self.assertEqual(ids(self.database, "totp_history"), [1])
        self.assertEqual(deletions(stream), [])

    def test_batches_fit_one_record_each(self) -> None:
        """450 rows: three records of at most 200 ids, matching the deleted rows."""
        make_database(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.executemany(
                "INSERT INTO totp_history (created_at, username, step) VALUES (?, 'alice.example', ?)",
                [(sqlite_time(OLD), f"{n:064d}") for n in range(450)],
            )
            conn.commit()
        emitter, stream = self.emitter()
        self.sweeper(emitter).sweep(NOW)
        records = deletions(stream)
        self.assertEqual([record["target"]["count"] for record in records], [200, 200, 50])
        recorded = [int(item) for record in records for item in record["target"]["ids"]]
        self.assertEqual(recorded, list(range(1, 451)))
        self.assertEqual(ids(self.database, "totp_history"), [])
        self.assertEqual(
            records[0]["criteria"],
            {"store": "totp_history", "period_days": DAYS, "cutoff": "2026-05-31T12:00:00Z", "age_from": "created_at"},
        )
        self.assertEqual(records[0]["target"]["container"], "authelia")
        self.assert_chains_intact()

    def test_the_batch_limit_and_stop_end_a_sweep_early(self) -> None:
        """The rest follows in the next round."""
        make_database(self.database)
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            conn.executemany(
                "INSERT INTO totp_history (created_at, username, step) VALUES (?, 'alice.example', ?)",
                [(sqlite_time(OLD), f"{n:064d}") for n in range(450)],
            )
            conn.commit()
        emitter, _ = self.emitter()
        result = self.sweeper(emitter, max_batches=2).sweep(NOW)
        self.assertFalse(result.complete)
        self.assertEqual(len(ids(self.database, "totp_history")), 50)
        stop = threading.Event()
        stop.set()
        result = self.sweeper(emitter, stop=stop).sweep(NOW)
        self.assertFalse(result.complete)
        self.assertEqual(len(ids(self.database, "totp_history")), 50)
        self.assertTrue(self.sweeper(emitter).sweep(NOW).complete)
        self.assertEqual(ids(self.database, "totp_history"), [])


class PrivacyTest(SweepWorkspace):
    """What the records and the database file keep."""

    def test_no_name_or_address_is_recorded_and_the_bytes_are_gone(self) -> None:
        """secure_delete zeroes the rows and their index entries; the journal is gone; its mode unchanged."""
        make_database(self.database)
        add_attempt(self.database, go_time(OLD), username=SENTINEL_USER, ip=SENTINEL_IP)
        add_code(self.database, go_time(OLD), go_time(OLD), username=SENTINEL_USER, ip=SENTINEL_IP)
        export_position(self.state_dir, self.database, 1)
        self.assertIn(SENTINEL_USER.encode(), self.database.read_bytes())
        emitter, stream = self.emitter()
        self.sweeper(emitter).sweep(NOW)
        self.assertNotIn(SENTINEL_USER, stream.getvalue())
        self.assertNotIn(SENTINEL_IP, stream.getvalue())
        content = self.database.read_bytes()
        self.assertNotIn(SENTINEL_USER.encode(), content)
        self.assertNotIn(SENTINEL_IP.encode(), content)
        self.assertEqual(sorted(path.name for path in self.db_dir.iterdir()), ["db.sqlite3"])
        with contextlib.closing(sqlite3.connect(self.database)) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "delete")

    def test_the_read_only_connection_cannot_write(self) -> None:
        """The dry run's connection refuses a write."""
        make_database(self.database)
        with contextlib.closing(auth_sweep.open_database(self.database, readonly=True)) as conn:
            with self.assertRaises(sqlite3.Error):
                conn.execute("DELETE FROM totp_history")

    def test_preview_counts_without_deleting(self) -> None:
        """The dry run's plan matches what a sweep would do."""
        make_database(self.database)
        add_attempt(self.database, go_time(OLD))
        add_attempt(self.database, go_time(OLD))
        add_attempt(self.database, go_time(YOUNG))
        export_position(self.state_dir, self.database, 1)
        with contextlib.closing(auth_sweep.open_database(self.database, readonly=True)) as conn:
            plans = auth_sweep.preview(conn, self.state_dir, DAYS, NOW)
        found = plans["authentication_logs"]
        assert isinstance(found, auth_sweep.Plan)
        self.assertEqual((found.due, found.held, found.kept), ([1], 1, 1))
        self.assertEqual(ids(self.database, "authentication_logs"), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
