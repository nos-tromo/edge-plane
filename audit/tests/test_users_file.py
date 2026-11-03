"""Tests for users_file.py: the users-file parser, the diff and the watcher.

``REWRITTEN`` mirrors what the pinned Authelia (4.39.20) writes back after a
self-service password change: four-space indentation, every extended
attribute as ``""``, ``address: null``, ``extra: {}`` — and ``disabled: false``
even for an account that was disabled.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import users_file
from audit_event import Actor, AuditEmitter, Target, verify_chain
from users_file import Account, UsersFileError, UsersFileWatcher, accounts_from, diff_accounts, parse_yaml

HASH = "$argon2id$v=19$m=65536,t=3,p=4$6bXVGzGU/7kmUP8b/6MS7w$jh5OoGXP07Kb8Tza4KZvBuCGO9vI2A4TqYC4HTbBxEA"
OTHER_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

TEMPLATE = f"""# Template — copy to authelia/users.yml
---
users:
  alice.example:
    displayname: "Alice Example"
    password: "{HASH}"
    email: alice@example.invalid
    groups:
      - users
      - admins
  bob.example:
    displayname: 'Bob O''Example'
    password: "{HASH}"
    email: bob@example.invalid  # trailing comment
    groups: [users]
    disabled: true
"""

REWRITTEN = f"""users:
    alice.example:
        password: {HASH}
        displayname: Alice Example
        email: alice@example.invalid
        groups:
            - users
            - admins
        given_name: ""
        middle_name: ""
        family_name: ""
        nickname: ""
        gender: ""
        birthdate: ""
        website: ""
        profile: ""
        picture: ""
        zoneinfo: ""
        locale: ""
        phone_number: ""
        phone_extension: ""
        disabled: false
        address: null
        extra: {{}}
    bob.example:
        password: {HASH}
        displayname: 'Bob O''Example'
        email: bob@example.invalid
        groups:
            - users
        given_name: ""
        disabled: false
        address: null
        extra: {{}}
"""


class ParserTest(unittest.TestCase):
    """The block-style YAML subset."""

    def test_template_format(self) -> None:
        """Two-space indentation, quoted values, block and flow sequences, comments."""
        users = parse_yaml(TEMPLATE)["users"]
        self.assertEqual(
            users["alice.example"],
            {
                "displayname": "Alice Example",
                "password": HASH,
                "email": "alice@example.invalid",
                "groups": ["users", "admins"],
            },
        )
        self.assertEqual(users["bob.example"]["displayname"], "Bob O'Example")
        self.assertEqual(users["bob.example"]["email"], "bob@example.invalid")
        self.assertEqual(users["bob.example"]["groups"], ["users"])
        self.assertIs(users["bob.example"]["disabled"], True)

    def test_authelia_rewrite_format(self) -> None:
        """Four-space indentation, empty strings, null and empty mappings."""
        alice = parse_yaml(REWRITTEN)["users"]["alice.example"]
        self.assertEqual(alice["password"], HASH)
        self.assertEqual(alice["given_name"], "")
        self.assertIsNone(alice["address"])
        self.assertEqual(alice["extra"], {})
        self.assertEqual(alice["groups"], ["users", "admins"])

    def test_compact_sequence_crlf_bom_and_markers(self) -> None:
        """A sequence at its key's indentation, CRLF line ends, a BOM, document markers."""
        text = "\ufeff---\r\nusers:\r\n  carol.example:\r\n    groups:\r\n    - users\r\n    - audit\r\n...\r\n"
        self.assertEqual(parse_yaml(text), {"users": {"carol.example": {"groups": ["users", "audit"]}}})

    def test_scalars(self) -> None:
        """Quoting, escapes, booleans, null, flow items, comments."""
        doc = parse_yaml(
            'a: "caf\\u00e9 \\x41 \\\\ \\" \\t"\n'
            "b: 'it''s # not a comment'\n"
            "c: [users, \"ad,mins\", 'x''y']  # comment\n"
            "d: True\n"
            "e: ~\n"
            "f: # only a comment\n"
            "g: https://edge.example/x#frag\n"
            "h: plain text # comment\n"
            "'quoted key': 1\n"
            "i: []\n"
        )
        self.assertEqual(
            doc,
            {
                "a": 'café A \\ " \t',
                "b": "it's # not a comment",
                "c": ["users", "ad,mins", "x'y"],
                "d": True,
                "e": None,
                "f": None,
                "g": "https://edge.example/x#frag",
                "h": "plain text",
                "quoted key": "1",
                "i": [],
            },
        )

    def test_empty_document(self) -> None:
        """Comments only: no document."""
        self.assertIsNone(parse_yaml("# nothing\n\n"))

    def test_outside_the_subset_is_refused(self) -> None:
        """Every unsupported construct fails with a line number and no content."""
        cases = {
            "users:\n\talice: x\n": "line 2",
            "users: &anchor\n  a: b\n": "line 1",
            "a: *alias\n": "line 1",
            "a: !!str x\n": "line 1",
            "a: |\n  text\n": "line 1",
            "a: one\n  continued\n": "line 2",
            'a: "open\n': "line 1",
            "a: 1\na: 2\n": "line 2",
            "a:\n  - b: c\n": "line 2",
            "a: [b, [c]]\n": "line 1",
            "a: {b: c}\n": "line 1",
            "a:\n    b: 1\n  c: 2\n": "line 3",
            'a: "x" y\n': "line 1",
            'a: "\\q"\n': "line 1",
            "just text\n": "line 1",
        }
        for text, where in cases.items():
            with self.assertRaises(UsersFileError, msg=text) as caught:
                parse_yaml(text)
            self.assertTrue(str(caught.exception).startswith(where), (text, str(caught.exception)))

    def test_errors_never_carry_content(self) -> None:
        """A refused line's value does not reach the message (it goes to the ops log)."""
        with self.assertRaises(UsersFileError) as caught:
            parse_yaml(f'users:\n  alice.example:\n    password: "{HASH}\n')
        self.assertNotIn("argon2", str(caught.exception))


class AccountsTest(unittest.TestCase):
    """From a parsed file to the compared facts."""

    def test_accounts_from_template_and_rewrite_agree(self) -> None:
        """Authelia's rewrite of the same accounts changes nothing but the disabled flag."""
        before = accounts_from(parse_yaml(TEMPLATE))
        after = accounts_from(parse_yaml(REWRITTEN))
        self.assertEqual(before["alice.example"], after["alice.example"])
        self.assertEqual(before["alice.example"].groups, ("admins", "users"))
        self.assertTrue(before["bob.example"].disabled)
        self.assertEqual(diff_accounts(before, after), [("account.enable", "bob.example", {})])

    def test_values(self) -> None:
        """Missing groups and flags have defaults; yes/no count as booleans."""
        doc = {"users": {"a": {"password": HASH, "disabled": "yes", "groups": ["x", "x"]}, "b": {}}}
        accounts = accounts_from(doc)
        self.assertEqual(accounts["a"], Account(("x",), True, accounts["a"].password, {}))
        self.assertEqual((accounts["b"].groups, accounts["b"].disabled), ((), False))
        self.assertNotIn(HASH, json.dumps(accounts["a"].to_json()))
        self.assertEqual(accounts_from({"users": None}), {})

    def test_not_a_users_file(self) -> None:
        """The shape is checked, not assumed."""
        for doc in (None, [], {"other": {}}, {"users": []}, {"users": {"a": "b"}}, {"users": {"a": {"groups": "x"}}}):
            with self.assertRaises(UsersFileError, msg=str(doc)):
                accounts_from(doc)
        with self.assertRaises(UsersFileError):
            accounts_from({"users": {"a": {"disabled": "maybe"}}})

    def test_diff(self) -> None:
        """One change per kind and account, by account name."""
        before = {
            "a": Account(("users",), False, "p1", {"email": "e1"}),
            "b": Account(("users",), False, "p1", {}),
            "c": Account((), True, "p1", {}),
        }
        after = {
            "a": Account(("admins", "users"), True, "p2", {"email": "e2", "displayname": "d"}),
            "c": Account((), False, "p1", {}),
            "d": Account(("audit",), False, "p3", {}),
        }
        self.assertEqual(
            diff_accounts(before, after),
            [
                ("account.groups", "a", {"groups": ["admins", "users"], "added": ["admins"], "removed": []}),
                ("account.disable", "a", {}),
                ("account.password", "a", {}),
                ("account.profile", "a", {"fields": ["displayname", "email"]}),
                ("account.delete", "b", {}),
                ("account.enable", "c", {}),
                ("account.create", "d", {"groups": ["audit"], "disabled": False}),
            ],
        )
        self.assertEqual(diff_accounts(after, after), [])


class WatcherTest(unittest.TestCase):
    """The watcher, writing real chained events."""

    def setUp(self) -> None:
        """A users file, a state directory and a captured chain per test."""
        self.tmp = Path(tempfile.mkdtemp(prefix="edge-users-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = self.tmp / "users.yml"
        self.state_dir = self.tmp / "state"
        self.state_dir.mkdir()
        self.stream = io.StringIO()
        self.emitter = AuditEmitter("edge-plane", "0.11.0", stream=self.stream, heartbeat_interval_s=0)
        self.emitter.start()
        self.addCleanup(self.emitter.close)

    def emit(
        self,
        operation: str,
        target: Target | None,
        criteria: Mapping[str, object] | None,
        parent_event_id: str | None,
    ) -> Mapping[str, object]:
        """Write the watcher's events the way auth-audit does.

        Args:
            operation: The operation.
            target: The accounts.
            criteria: The facts.
            parent_event_id: The event this one continues.

        Returns:
            The event as written.
        """
        return self.emitter.emit(
            "admin",
            operation,
            Actor(None, "system"),
            target=target,
            criteria=criteria,
            parent_event_id=parent_event_id,
        )

    def watcher(self) -> UsersFileWatcher:
        """Build a watcher resuming from the saved state.

        Returns:
            The watcher.
        """
        return UsersFileWatcher(self.emit, self.path, self.state_dir, users_file.load_users_state(self.state_dir))

    def write(self, text: str) -> None:
        """Replace the file the way an editor does: a new file renamed over it.

        Args:
            text: The new content.
        """
        temp = self.tmp / "users.yml.new"
        temp.write_text(text, encoding="utf-8")
        os.replace(temp, self.path)

    def events(self) -> list[dict[str, Any]]:
        """Parse the admin events written so far.

        Returns:
            The events, in order.
        """
        lines = [json.loads(line) for line in self.stream.getvalue().splitlines()]
        return [event for event in lines if event["action"] == "admin"]

    def assert_intact_and_clean(self) -> None:
        """The chain verifies, and no secret or contact value was written."""
        lines = [json.loads(line) for line in self.stream.getvalue().splitlines()]
        self.assertEqual(verify_chain(lines).problems, [])
        text = self.stream.getvalue()
        for value in ("argon2", "example.invalid", "Alice Example", "O'Example"):
            self.assertNotIn(value, text)

    def test_baseline(self) -> None:
        """One event naming every account, one per group, one for disabled accounts."""
        self.write(TEMPLATE)
        self.assertEqual(self.watcher().poll(), 4)
        events = self.events()
        self.assertEqual(
            [(e["operation"], e["target"]["ids"], e.get("criteria")) for e in events],
            [
                ("account.baseline", ["alice.example", "bob.example"], {"accounts": 2}),
                ("account.baseline.group", ["alice.example"], {"group": "admins"}),
                ("account.baseline.group", ["alice.example", "bob.example"], {"group": "users"}),
                ("account.baseline.disabled", ["bob.example"], None),
            ],
        )
        self.assertEqual(events[0]["actor"], {"user": None, "via": "system"})
        self.assertEqual(events[0]["target"]["count"], 2)
        self.assert_intact_and_clean()

    def test_baseline_names_past_200_continue(self) -> None:
        """Long name lists are continued, not cut."""
        accounts = "\n".join(f"  user{n:03d}.example:\n    groups: [users]" for n in range(450))
        self.write(f"users:\n{accounts}\n")
        self.watcher().poll()
        events = self.events()
        self.assertEqual(
            [(e["operation"], len(e["target"]["ids"]), e["target"]["count"]) for e in events],
            [
                ("account.baseline", 200, 450),
                ("account.baseline.ids", 200, 200),
                ("account.baseline.ids", 50, 50),
                ("account.baseline.group", 200, 450),
                ("account.baseline.group.ids", 200, 200),
                ("account.baseline.group.ids", 50, 50),
            ],
        )
        self.assertEqual({e["parent_event_id"] for e in events[1:3]}, {events[0]["event_id"]})
        self.assertEqual({e["parent_event_id"] for e in events[4:6]}, {events[3]["event_id"]})
        named = [name for e in events[:3] for name in e["target"]["ids"]]
        self.assertEqual(named, [f"user{n:03d}.example" for n in range(450)])
        self.assert_intact_and_clean()

    def test_changes_are_itemised(self) -> None:
        """Each change of an account is one event, targeting it."""
        self.write(TEMPLATE)
        watcher = self.watcher()
        watcher.poll()
        changed = (
            TEMPLATE.replace("      - admins\n", "")
            .replace(f'password: "{HASH}"\n    email: bob', f'password: "{OTHER_HASH}"\n    email: bob')
            .replace("alice@example.invalid", "alice.new@example.invalid")
        ) + "  carol.example:\n    groups: [audit]\n"
        self.write(changed)
        self.assertEqual(watcher.poll(), 4)
        self.assertEqual(
            [(e["operation"], e["target"], e.get("criteria")) for e in self.events()[4:]],
            [
                (
                    "account.groups",
                    {"kind": "account", "ids": ["alice.example"], "count": 1},
                    {"groups": ["users"], "added": [], "removed": ["admins"]},
                ),
                ("account.profile", {"kind": "account", "ids": ["alice.example"], "count": 1}, {"fields": ["email"]}),
                ("account.password", {"kind": "account", "ids": ["bob.example"], "count": 1}, None),
                (
                    "account.create",
                    {"kind": "account", "ids": ["carol.example"], "count": 1},
                    {"groups": ["audit"], "disabled": False},
                ),
            ],
        )
        self.assertEqual(watcher.poll(), 0)
        self.assert_intact_and_clean()

    def test_restart_neither_repeats_nor_misses(self) -> None:
        """A change made while the watcher was down is recorded once, after the restart."""
        self.write(TEMPLATE)
        self.watcher().poll()
        self.write(TEMPLATE.replace("  bob.example:", "  bobby.example:"))
        watcher = self.watcher()
        self.assertEqual(watcher.poll(), 2)
        self.assertEqual(
            [(e["operation"], e["target"]["ids"]) for e in self.events()[4:]],
            [("account.delete", ["bob.example"]), ("account.create", ["bobby.example"])],
        )
        self.assertEqual(self.watcher().poll(), 0)
        self.assert_intact_and_clean()

    def test_authelia_rewrite_re_enables_disabled_accounts(self) -> None:
        """The rewrite is formatting only, except that it clears disabled: recorded."""
        self.write(TEMPLATE)
        watcher = self.watcher()
        watcher.poll()
        self.path.write_text(REWRITTEN, encoding="utf-8")  # Authelia writes in place
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(
            [(e["operation"], e["target"]["ids"]) for e in self.events()[4:]],
            [("account.enable", ["bob.example"])],
        )
        self.assert_intact_and_clean()

    def test_unchanged_content_writes_nothing(self) -> None:
        """Touching the file, or a comment edit, is not an account change."""
        self.write(TEMPLATE)
        watcher = self.watcher()
        watcher.poll()
        os.utime(self.path)
        self.assertEqual(watcher.poll(), 0)
        self.write("# a new comment\n" + TEMPLATE)
        self.assertEqual(watcher.poll(), 0)
        self.assertEqual(len(self.events()), 4)

    def test_an_edit_that_hides_its_metadata_is_still_recorded(self) -> None:
        """Same size, same inode, mtime set back: the content decides, not the metadata."""
        self.write(TEMPLATE)
        watcher = self.watcher()
        watcher.poll()
        before = os.stat(self.path)
        edited = TEMPLATE.replace("      - admins\n", "      - audits\n")
        self.assertEqual(len(edited), len(TEMPLATE))
        self.path.write_text(edited, encoding="utf-8")  # in place: same inode
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(os.stat(self.path).st_ino, before.st_ino)
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(
            [(e["operation"], e["target"]["ids"], e.get("criteria")) for e in self.events()[4:]],
            [
                (
                    "account.groups",
                    ["alice.example"],
                    {"groups": ["audits", "users"], "added": ["audits"], "removed": ["admins"]},
                )
            ],
        )
        self.assert_intact_and_clean()

    def test_unreadable_version_is_recorded_once(self) -> None:
        """Seen twice in a row: one coarse event; readable again: itemised."""
        self.write(TEMPLATE)
        watcher = self.watcher()
        watcher.poll()
        broken = TEMPLATE.replace("    groups: [users]\n", "    groups: &g [users]\n")
        self.write(broken)
        self.assertEqual(watcher.poll(), 0)  # perhaps an editor mid-write
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(watcher.poll(), 0)
        unparsed = self.events()[-1]
        self.assertEqual(unparsed["operation"], "account.unparsed")
        self.assertNotIn("target", unparsed)
        self.assertEqual(set(unparsed["criteria"]), {"file_sha256"})
        self.assertEqual(len(unparsed["criteria"]["file_sha256"]), 64)
        self.assertEqual(self.watcher().poll(), 0)  # restarted: already recorded
        self.write(TEMPLATE.replace("    disabled: true\n", ""))
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(self.events()[-1]["operation"], "account.enable")
        self.assert_intact_and_clean()

    def test_missing_file(self) -> None:
        """No file, nothing to read: no events, and certainly no deletions."""
        watcher = self.watcher()
        self.assertIsNone(watcher.poll())
        self.write(TEMPLATE)
        watcher.poll()
        self.path.unlink()
        self.assertIsNone(watcher.poll())
        self.assertEqual(len(self.events()), 4)

    def test_corrupt_state_is_refused(self) -> None:
        """A damaged state is never guessed at."""
        for content in ("[]", '{"version": 2}', '{"version": 1, "accounts": {"a": {"groups": "x"}}}'):
            (self.state_dir / users_file.STATE_FILE).write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError, msg=content):
                users_file.load_users_state(self.state_dir)


if __name__ == "__main__":
    unittest.main()
