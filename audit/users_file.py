"""Account changes in Authelia's user database file, as ``admin`` events.

Accounts, passwords and group memberships live in ``authelia/users.yml``:
operators edit it by hand, and Authelia rewrites it when a user changes their
own password. :class:`UsersFileWatcher` notices every change to the file and
writes one event per change of an account — created, deleted, groups,
password, disabled/enabled, profile — compared with the previous version it
saw. Who edited the file is not known here, so the actor is the system.

The file is read with a small parser for the block-style YAML subset this file
is written in (by hand from ``users.template.yml``, or by Authelia itself).
Anything outside it — anchors, tags, multi-line scalars — is refused rather
than guessed at: the change is then recorded as not itemised, and itemised
against the last readable version once the file can be read again.

Recorded are the account names (as the event's target), group names and the
disabled flag: who may access what. Never recorded: a password hash (nor a
digest of it), e-mail addresses, display names or any other attribute value.
Changes are detected by comparing digests the watcher keeps in its state.

Stdlib only; Python 3.12.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, NamedTuple

from audit_event import Target
from audit_runtime import id_chunks

STATE_FILE: Final = "users-file.json"
STATE_VERSION: Final = 1
#: Fields compared on their own; every other attribute is part of the profile.
_OWN_FIELDS: Final = frozenset({"password", "groups", "disabled"})
_TRUE: Final = frozenset({"true", "yes", "on"})
_FALSE: Final = frozenset({"false", "no", "off"})
_NULL: Final = frozenset({"", "~", "null"})
_UNSUPPORTED_START: Final = frozenset("|>&*!%@`?")
_ESCAPES: Final = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}
_HEX_ESCAPES: Final = {"x": 2, "u": 4, "U": 8}
_COMMENT: Final = re.compile(r"[ \t]#")

LOG = logging.getLogger("auth-audit")

#: ``emit(operation, target, criteria, parent_event_id)`` writes one admin
#: event and returns it as written.
Emit = Callable[[str, Target | None, Mapping[str, object] | None, str | None], Mapping[str, object]]


class UsersFileError(ValueError):
    """Raised for a users file this parser cannot read. Messages name lines, never content."""


class _Line(NamedTuple):
    number: int
    indent: int
    item: bool
    key: str | None
    value: str


def _strip_comment(text: str, number: int) -> str:
    """Remove a trailing comment from a value, respecting quotes.

    Args:
        text: The value text after the key or the sequence dash.
        number: The line number, for errors.

    Returns:
        The value without the comment and surrounding blanks.

    Raises:
        UsersFileError: If a quoted value is not closed or is followed by text.
    """
    text = text.strip()
    if text.startswith("#"):
        return ""
    if text[:1] in ('"', "'"):
        end = _quote_end(text, number)
        rest = text[end + 1 :].strip()
        if rest and not rest.startswith("#"):
            raise UsersFileError(f"line {number}: text after a quoted value")
        return text[: end + 1]
    if text.startswith("["):
        depth_end = _flow_end(text, number)
        rest = text[depth_end + 1 :].strip()
        if rest and not rest.startswith("#"):
            raise UsersFileError(f"line {number}: text after a flow value")
        return text[: depth_end + 1]
    match = _COMMENT.search(text)
    return (text[: match.start()] if match else text).strip()


def _quote_end(text: str, number: int) -> int:
    """Find the closing quote of a quoted scalar.

    Args:
        text: Text starting with ``"`` or ``'``.
        number: The line number, for errors.

    Returns:
        The index of the closing quote.

    Raises:
        UsersFileError: If the quote is not closed on this line.
    """
    quote = text[0]
    index = 1
    while index < len(text):
        char = text[index]
        if quote == '"' and char == "\\":
            index += 2
            continue
        if char == quote:
            if quote == "'" and text[index + 1 : index + 2] == "'":
                index += 2
                continue
            return index
        index += 1
    raise UsersFileError(f"line {number}: unclosed quote (multi-line scalars are not supported)")


def _flow_end(text: str, number: int) -> int:
    """Find the closing bracket of a one-line flow sequence.

    Args:
        text: Text starting with ``[``.
        number: The line number, for errors.

    Returns:
        The index of the closing ``]``.

    Raises:
        UsersFileError: If the sequence does not close on this line.
    """
    index = 1
    while index < len(text):
        char = text[index]
        if char in ('"', "'"):
            index += _quote_end(text[index:], number) + 1
            continue
        if char == "]":
            return index
        if char in "[{":
            raise UsersFileError(f"line {number}: nested flow collections are not supported")
        index += 1
    raise UsersFileError(f"line {number}: unclosed flow sequence")


def _unquote_double(body: str, number: int) -> str:
    """Decode the inside of a double-quoted scalar.

    Args:
        body: The text between the quotes.
        number: The line number, for errors.

    Returns:
        The decoded string.

    Raises:
        UsersFileError: On an unknown or malformed escape.
    """
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        code = body[index + 1 : index + 2]
        if code in _ESCAPES:
            out.append(_ESCAPES[code])
            index += 2
        elif code in _HEX_ESCAPES:
            width = _HEX_ESCAPES[code]
            digits = body[index + 2 : index + 2 + width]
            if len(digits) != width or not all(c in "0123456789abcdefABCDEF" for c in digits):
                raise UsersFileError(f"line {number}: malformed escape")
            out.append(chr(int(digits, 16)))
            index += 2 + width
        else:
            raise UsersFileError(f"line {number}: unknown escape")
    return "".join(out)


def _scalar(text: str, number: int) -> object:
    """Resolve one scalar or one-line flow value.

    Args:
        text: The value, comment already removed.
        number: The line number, for errors.

    Returns:
        ``None``, a bool, a string, a list of scalars, or an empty dict.

    Raises:
        UsersFileError: For anything outside the supported subset.
    """
    if text.startswith('"'):
        return _unquote_double(text[1:-1], number)
    if text.startswith("'"):
        return text[1:-1].replace("''", "'")
    if text.startswith("["):
        inner = text[1:-1].strip()
        if not inner:
            empty_list: list[object] = []
            return empty_list
        items: list[object] = []
        start, index = 0, 0
        while index <= len(inner):
            if index < len(inner) and inner[index] in ('"', "'"):
                index += _quote_end(inner[index:], number) + 1
                continue
            if index == len(inner) or inner[index] == ",":
                item = inner[start:index].strip()
                if not item:
                    raise UsersFileError(f"line {number}: empty flow sequence item")
                items.append(_scalar(item, number))
                start = index + 1
            index += 1
        return items
    if text == "{}":
        empty_map: dict[str, object] = {}
        return empty_map
    if text[:1] in _UNSUPPORTED_START or text.startswith("{"):
        raise UsersFileError(f"line {number}: unsupported YAML (anchor, alias, tag, block scalar or flow mapping)")
    lowered = text.lower()
    if lowered in _NULL:
        return None
    if lowered in ("true", "false"):
        return lowered == "true"
    return text


def _split_key(content: str, number: int) -> tuple[str, str]:
    """Split ``key: value`` (the key plain or quoted).

    Args:
        content: The line without its indentation.
        number: The line number, for errors.

    Returns:
        The key and the raw value text.

    Raises:
        UsersFileError: If the line is not a mapping entry.
    """
    if content[:1] in ('"', "'"):
        end = _quote_end(content, number)
        key = _scalar(content[: end + 1], number)
        rest = content[end + 1 :]
        if not rest.startswith(":") or (len(rest) > 1 and rest[1] not in " \t"):
            raise UsersFileError(f"line {number}: expected ':' after a quoted key")
        return str(key), rest[1:]
    match = re.search(r":(?:[ \t]|$)", content)
    if match is None:
        raise UsersFileError(f"line {number}: not a 'key: value' line (multi-line scalars are not supported)")
    key = content[: match.start()].strip()
    if not key or key.startswith("#") or key[:1] in _UNSUPPORTED_START | {"-", "[", "{"}:
        raise UsersFileError(f"line {number}: unsupported key")
    return key, content[match.end() :]


def _lines(text: str) -> list[_Line]:
    """Tokenize the document into mapping entries and sequence items.

    Args:
        text: The whole file.

    Returns:
        One entry per meaningful line.

    Raises:
        UsersFileError: On tabs in indentation or lines outside the subset.
    """
    out: list[_Line] = []
    for number, raw in enumerate(text.removeprefix("﻿").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw.startswith(("---", "...")) and raw.rstrip() in ("---", "..."):
            continue
        content = raw.lstrip(" ")
        if content.startswith("\t"):
            raise UsersFileError(f"line {number}: tab in indentation")
        indent = len(raw) - len(content)
        if content == "-" or content.startswith(("- ", "-\t")):
            value = _strip_comment(content[1:], number)
            if value and _COMMENT.search(" " + value) is None and re.search(r":(?:[ \t]|$)", value):
                if value[:1] not in ('"', "'", "["):
                    raise UsersFileError(f"line {number}: mappings inside sequences are not supported")
            out.append(_Line(number, indent, True, None, value))
            continue
        key, value = _split_key(content, number)
        value = _strip_comment(value, number)
        if value[:1] in ("|", ">"):
            raise UsersFileError(f"line {number}: block scalars are not supported")
        out.append(_Line(number, indent, False, key, value))
    return out


def _block(lines: list[_Line], index: int, indent: int) -> tuple[object, int]:
    """Parse the block (mapping or sequence) starting at ``index``.

    Args:
        lines: The tokens.
        index: Where the block starts.
        indent: Its indentation.

    Returns:
        The value and the index after it.

    Raises:
        UsersFileError: On inconsistent indentation or duplicate keys.
    """
    first = lines[index]
    if first.item:
        items: list[object] = []
        while index < len(lines) and lines[index].indent == indent and lines[index].item:
            line = lines[index]
            if not line.value:
                raise UsersFileError(f"line {line.number}: nested blocks inside sequences are not supported")
            items.append(_scalar(line.value, line.number))
            index += 1
        if index < len(lines) and lines[index].indent > indent:
            raise UsersFileError(f"line {lines[index].number}: unexpected indentation")
        return items, index
    mapping: dict[str, object] = {}
    while index < len(lines) and lines[index].indent == indent and not lines[index].item:
        line = lines[index]
        index += 1
        key = line.key or ""
        if key in mapping:
            raise UsersFileError(f"line {line.number}: duplicate key")
        if line.value:
            mapping[key] = _scalar(line.value, line.number)
            if index < len(lines) and lines[index].indent > indent:
                raise UsersFileError(f"line {lines[index].number}: unexpected indentation")
            continue
        child = lines[index] if index < len(lines) else None
        if child is not None and (child.indent > indent or (child.indent == indent and child.item)):
            mapping[key], index = _block(lines, index, child.indent)
        else:
            mapping[key] = None
    if index < len(lines) and lines[index].indent > indent:
        raise UsersFileError(f"line {lines[index].number}: unexpected indentation")
    return mapping, index


def parse_yaml(text: str) -> object:
    """Parse the block-style YAML subset of a users file.

    Args:
        text: The file's text.

    Returns:
        The document: nested dicts, lists and scalars; ``None`` when empty.

    Raises:
        UsersFileError: If the text is outside the subset.
    """
    lines = _lines(text)
    if not lines:
        return None
    value, index = _block(lines, 0, lines[0].indent)
    if index != len(lines):
        raise UsersFileError(f"line {lines[index].number}: unexpected indentation")
    return value


def _digest(value: object) -> str:
    """Fingerprint a value without keeping it.

    Args:
        value: A parsed value.

    Returns:
        The SHA-256 of its canonical JSON.
    """
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Account:
    """What is compared of one account, by value or by digest.

    Attributes:
        groups: Its groups, sorted.
        disabled: Whether it is disabled.
        password: A digest of its password hash.
        profile: A digest per other attribute that has a value.
    """

    groups: tuple[str, ...]
    disabled: bool
    password: str
    profile: Mapping[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, object]:
        """Return the form kept in the state file.

        Returns:
            The account as JSON-compatible data.
        """
        return {
            "groups": list(self.groups),
            "disabled": self.disabled,
            "password": self.password,
            "profile": dict(self.profile),
        }

    @classmethod
    def from_json(cls, data: object) -> Account:
        """Rebuild an account from the state file.

        Args:
            data: The stored form.

        Returns:
            The account.

        Raises:
            ValueError: If the stored form is not valid.
        """
        if not isinstance(data, dict):
            raise ValueError("not an account")
        groups, disabled = data.get("groups"), data.get("disabled")
        password, profile = data.get("password"), data.get("profile")
        if (
            not isinstance(groups, list)
            or not all(isinstance(group, str) for group in groups)
            or not isinstance(disabled, bool)
            or not isinstance(password, str)
            or not isinstance(profile, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in profile.items())
        ):
            raise ValueError("not an account")
        return cls(tuple(groups), disabled, password, dict(profile))


def accounts_from(document: object) -> dict[str, Account]:
    """Extract the accounts from a parsed users file.

    Args:
        document: The parsed file.

    Returns:
        The accounts by name.

    Raises:
        UsersFileError: If the document is not a users file.
    """
    if not isinstance(document, dict) or "users" not in document:
        raise UsersFileError("no top-level 'users' mapping")
    users = document["users"]
    if users is None:
        return {}
    if not isinstance(users, dict):
        raise UsersFileError("'users' is not a mapping")
    accounts: dict[str, Account] = {}
    for name, details in users.items():
        if not name or not isinstance(details, dict):
            raise UsersFileError("an account is not a mapping")
        groups = details.get("groups")
        if groups is None:
            groups = list[str]()
        if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
            raise UsersFileError("an account's groups are not a list of names")
        disabled = details.get("disabled")
        if isinstance(disabled, str) and disabled.lower() in _TRUE | _FALSE:
            disabled = disabled.lower() in _TRUE
        if disabled is None:
            disabled = False
        if not isinstance(disabled, bool):
            raise UsersFileError("an account's 'disabled' is not a boolean")
        password = details.get("password")
        profile = {
            key: _digest(value)
            for key, value in details.items()
            if key not in _OWN_FIELDS and value not in (None, "", [], {})
        }
        accounts[name] = Account(tuple(sorted(set(groups))), disabled, _digest(password), profile)
    return accounts


def diff_accounts(
    before: Mapping[str, Account], after: Mapping[str, Account]
) -> list[tuple[str, str, dict[str, object]]]:
    """List the changes between two versions of the file, account by account.

    Args:
        before: The accounts as last seen.
        after: The accounts now.

    Returns:
        ``(operation, account, criteria)`` per change, by account name.
    """
    changes: list[tuple[str, str, dict[str, object]]] = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name), after.get(name)
        if old is None and new is not None:
            changes.append(("account.create", name, {"groups": list(new.groups), "disabled": new.disabled}))
            continue
        if new is None:
            changes.append(("account.delete", name, {}))
            continue
        if old is None:
            continue
        if old.groups != new.groups:
            added = sorted(set(new.groups) - set(old.groups))
            removed = sorted(set(old.groups) - set(new.groups))
            changes.append(("account.groups", name, {"groups": list(new.groups), "added": added, "removed": removed}))
        if old.disabled != new.disabled:
            changes.append(("account.disable" if new.disabled else "account.enable", name, {}))
        if old.password != new.password:
            changes.append(("account.password", name, {}))
        fields = sorted(
            key for key in set(old.profile) | set(new.profile) if old.profile.get(key) != new.profile.get(key)
        )
        if fields:
            changes.append(("account.profile", name, {"fields": fields}))
    return changes


@dataclass
class UsersState:
    """What the watcher last saw.

    Attributes:
        file_sha256: The digest of the last itemised version of the file.
        accounts: Its accounts; ``None`` until the first readable version.
        unparsed_sha256: The digest of the unreadable version last recorded.
    """

    file_sha256: str | None = None
    accounts: dict[str, Account] | None = None
    unparsed_sha256: str | None = None


def load_users_state(directory: Path) -> UsersState:
    """Read the watcher's state.

    Args:
        directory: The state directory.

    Returns:
        The state; empty when there is none yet.

    Raises:
        ValueError: If the state file exists but is not valid.
    """
    path = directory / STATE_FILE
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return UsersState()
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise ValueError(f"the users file state {path} is not valid")
    file_sha256, accounts, unparsed = data.get("file_sha256"), data.get("accounts"), data.get("unparsed_sha256")
    if not (file_sha256 is None or isinstance(file_sha256, str)) or not (unparsed is None or isinstance(unparsed, str)):
        raise ValueError(f"the users file state {path} is not valid")
    if accounts is not None and not isinstance(accounts, dict):
        raise ValueError(f"the users file state {path} is not valid")
    parsed = None if accounts is None else {str(name): Account.from_json(item) for name, item in accounts.items()}
    return UsersState(file_sha256, parsed, unparsed)


def save_users_state(directory: Path, state: UsersState) -> None:
    """Persist the watcher's state atomically.

    Args:
        directory: The state directory.
        state: The state.

    Raises:
        OSError: If it could not be written.
    """
    path = directory / STATE_FILE
    temp = directory / f"{STATE_FILE}.tmp"
    accounts = None if state.accounts is None else {name: account.to_json() for name, account in state.accounts.items()}
    text = json.dumps(
        {
            "version": STATE_VERSION,
            "file_sha256": state.file_sha256,
            "accounts": accounts,
            "unparsed_sha256": state.unparsed_sha256,
        },
        sort_keys=True,
    )
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(text + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    temp.replace(path)


class UsersFileWatcher:
    """Turns changes of the users file into ``admin`` events."""

    def __init__(self, emit: Emit, path: Path, state_dir: Path, state: UsersState) -> None:
        """Prepare a watcher; nothing is read until :meth:`poll`.

        Args:
            emit: Writes one event (see :data:`Emit`).
            path: The users file.
            state_dir: Where the state is kept.
            state: The state loaded from ``state_dir``.
        """
        self._emit = emit
        self._path = path
        self._state_dir = state_dir
        self._state = state
        self._pending: str | None = None
        self._problem: str | None = None

    @property
    def state(self) -> UsersState:
        """The current state."""
        return self._state

    def poll(self) -> int | None:
        """Record what changed in the file since the last round.

        The first readable version is recorded as a baseline (see
        :meth:`_baseline`). A version this parser cannot read is recorded once,
        as ``account.unparsed``, when it is still there one round later (so an
        editor's half-written file is not), and itemised against the last
        readable version when the file can be read again.

        Returns:
            The number of events written, or ``None`` when the file could not
            be read this round.

        Raises:
            AuditWriteError: If an event could not be written.
            OSError: If the state could not be saved.
        """
        # The whole file every round, compared by digest: it is small, and no
        # metadata shortcut (size, mtime) can be trusted, since mtime can be
        # set back after an edit that keeps the size.
        try:
            data = self._path.read_bytes()
        except OSError as exc:
            self._report(f"users file not readable ({exc.strerror or type(exc).__name__})")
            return None
        digest = hashlib.sha256(data).hexdigest()
        if digest == self._state.file_sha256:
            self._pending = None
            self._report(None)
            return 0
        try:
            accounts = accounts_from(parse_yaml(data.decode("utf-8")))
        except (UsersFileError, UnicodeDecodeError) as exc:
            return self._unreadable(digest, exc)
        self._pending = None
        self._report(None)
        if self._state.accounts is None:
            written = self._baseline(accounts)
        else:
            changes = diff_accounts(self._state.accounts, accounts)
            for operation, name, criteria in changes:
                self._emit(operation, Target(kind="account", ids=[name], count=1), criteria or None, None)
            written = len(changes)
        self._state = UsersState(file_sha256=digest, accounts=accounts, unparsed_sha256=None)
        save_users_state(self._state_dir, self._state)
        if written:
            LOG.info("users file: %d events recorded", written)
        return written

    def _baseline(self, accounts: Mapping[str, Account]) -> int:
        """Record the accounts as first seen, so later changes have a reference.

        ``account.baseline`` names every account; one ``account.baseline.group``
        per group names its members, and ``account.baseline.disabled`` the
        disabled accounts. Lists over 200 names continue in ``<operation>.ids``
        events pointing at their first.

        Args:
            accounts: The accounts.

        Returns:
            The number of events written.
        """
        names = sorted(accounts)
        written = self._chunked("account.baseline", names, {"accounts": len(names)})
        for group in sorted({group for account in accounts.values() for group in account.groups}):
            members = [name for name in names if group in accounts[name].groups]
            written += self._chunked("account.baseline.group", members, {"group": group})
        disabled = [name for name in names if accounts[name].disabled]
        if disabled:
            written += self._chunked("account.baseline.disabled", disabled, None)
        return written

    def _chunked(self, operation: str, names: Sequence[str], criteria: Mapping[str, object] | None) -> int:
        """Write one event naming ``names``, continued in chunks past 200.

        Args:
            operation: The first event's operation.
            names: The account names.
            criteria: The first event's criteria.

        Returns:
            The number of events written.
        """
        chunks = id_chunks(names) or [[]]
        first = self._emit(operation, Target(kind="account", ids=chunks[0], count=len(names)), criteria, None)
        for chunk in chunks[1:]:
            target = Target(kind="account", ids=chunk, count=len(chunk))
            self._emit(f"{operation}.ids", target, None, str(first["event_id"]))
        return len(chunks)

    def _unreadable(self, digest: str, exc: Exception) -> int:
        """Handle a version of the file the parser refuses.

        Args:
            digest: The version's digest.
            exc: Why it was refused; its message names lines only.

        Returns:
            The number of events written (0 or 1).
        """
        reason = exc if isinstance(exc, UsersFileError) else "not UTF-8"
        self._report(f"users file changed but cannot be itemised: {reason}")
        if digest != self._pending:
            self._pending = digest
            return 0
        if self._state.unparsed_sha256 == digest:
            return 0
        self._emit("account.unparsed", None, {"file_sha256": digest}, None)
        self._state = UsersState(self._state.file_sha256, self._state.accounts, unparsed_sha256=digest)
        save_users_state(self._state_dir, self._state)
        return 1

    def _report(self, problem: str | None) -> None:
        """Log a problem once, and its end.

        Args:
            problem: The current problem, or ``None`` when there is none.
        """
        if problem == self._problem:
            return
        if problem is None:
            LOG.info("users file readable again")
        else:
            LOG.warning("%s", problem)
        self._problem = problem
