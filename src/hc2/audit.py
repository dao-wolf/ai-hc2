"""The audit trail: one hash-chained JSON line per event (FR-11, S-8, O-1).

Files are `audit/YYYY-MM-DD.jsonl` in the state folder, dated in UTC. Each line
is `Event.to_log_record()` plus two attributes:

* `hc2.prev_hash`: the previous record's `hc2.hash`, or 64 zeros for the first
  record ever written.
* `hc2.hash`: the SHA-256 of the record's canonical JSON without `hc2.hash`.

The chain runs across files, in file-name order. Editing a record, or deleting
one from the middle, breaks the chain and `verify_chain()` says where.

What the chain does not catch (S-9, see the threat model, row 19):

* Someone who rewrites every record from some point on with fresh hashes.
* Deleting records or files from the end, which leaves a shorter valid chain.

Closing those gaps needs an anchor kept somewhere else, such as the chain head
signed into each approval challenge (S-8). That arrives in a later slice.

Every body is a plain-English sentence written by HC2. Appends are one whole
line in one write, under a lock, so two writers never interleave.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hc2._fs import PRIVATE_FILE_MODE, ensure_private_dir
from hc2.errors import UserError
from hc2.model import Event, Model

GENESIS_HASH = "0" * 64
ATTR_PREV = "hc2.prev_hash"
ATTR_HASH = "hc2.hash"

_FILE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl")
_TAIL_BYTES = 8192


def canonical_json(record: Mapping[str, Any]) -> str:
    """The one JSON spelling that hashes are taken over: sorted, compact."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: Mapping[str, Any]) -> str:
    """The SHA-256 of a record without its own `hc2.hash`."""
    attributes = {
        key: value
        for key, value in dict(record.get("attributes", {})).items()
        if key != ATTR_HASH
    }
    body = {**record, "attributes": attributes}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainBreak(Model):
    """Where the chain first fails: a file name, a 1-based line and a reason."""

    file: str
    line: int
    reason: str


@dataclass(frozen=True)
class ChainReport(Model):
    """The result of `verify_chain()`. `records` counts those checked so far."""

    ok: bool
    records: int
    first_break: ChainBreak | None = None


def event_date(event: Event) -> str:
    """The UTC date, as `YYYY-MM-DD`, that an event belongs to."""
    seconds = int(event.time_unix_nano) // 1_000_000_000
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%d")


class AuditLog:
    """The audit folder. Creates nothing until the first append."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def files(self) -> list[Path]:
        """Every audit file, oldest first."""
        if not self.directory.is_dir():
            return []
        return sorted(
            path
            for path in self.directory.iterdir()
            if _FILE_RE.fullmatch(path.name) and path.is_file()
        )

    # -- reading ---------------------------------------------------------

    @staticmethod
    def _last_line(path: Path) -> bytes | None:
        """The last non-empty line of a file, read from the end."""
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            window = _TAIL_BYTES
            while True:
                start = max(0, size - window)
                handle.seek(start)
                chunk = handle.read(size - start)
                lines = [line for line in chunk.split(b"\n") if line.strip()]
                if len(lines) > 1 or start == 0:
                    return lines[-1] if lines else None
                window *= 2

    def head(self) -> str:
        """The hash the next record will chain from."""
        for path in reversed(self.files()):
            line = self._last_line(path)
            if line is None:
                continue
            try:
                record = json.loads(line)
                value = record["attributes"][ATTR_HASH]
            except (ValueError, KeyError, TypeError):
                value = None
            # A damaged last line is chained from its own hash, so appending
            # never fails and `verify_chain()` still reports the damage.
            return value if isinstance(value, str) else hashlib.sha256(line).hexdigest()
        return GENESIS_HASH

    # -- writing ---------------------------------------------------------

    @contextmanager
    def _locked(self) -> Iterator[None]:
        fd = os.open(
            self.directory / ".lock", os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def append(self, event: Event) -> str:
        """Chain an event onto the log and return its hash.

        Raises:
            UserError: the audit folder could not be written.
        """
        try:
            ensure_private_dir(self.directory)
            with self._locked():
                return self._append_locked(event)
        except OSError as error:
            raise UserError(
                "HC2 could not write to its audit log. Check that the state "
                "folder exists and that you can write to it."
            ) from error

    def _append_locked(self, event: Event) -> str:
        existing = self.files()
        name = f"{event_date(event)}.jsonl"
        if existing and existing[-1].name > name:
            name = existing[-1].name  # never write into the past
        record = event.to_log_record()
        record["attributes"][ATTR_PREV] = self.head()
        digest = record_hash(record)
        record["attributes"][ATTR_HASH] = digest
        line = (canonical_json(record) + "\n").encode("utf-8")
        path = self.directory / name
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, PRIVATE_FILE_MODE)
        try:
            if os.fstat(fd).st_size and not _ends_with_newline(path):
                line = b"\n" + line  # a crash left half a line: start a fresh one
            written = os.write(fd, line)
            if written != len(line):  # pragma: no cover - local disks write whole lines
                raise OSError("short write")
            os.fsync(fd)
        finally:
            os.close(fd)
        return digest

    # -- checking --------------------------------------------------------

    def verify_chain(self) -> ChainReport:
        """Walk every record and report the first one that breaks the chain."""
        expected = GENESIS_HASH
        count = 0
        for path in self.files():
            try:
                data = path.read_bytes()
            except OSError:
                return ChainReport(
                    False, count, ChainBreak(path.name, 0, "The file cannot be read.")
                )
            lines = data.split(b"\n")
            if lines and lines[-1] == b"":
                lines.pop()
            for number, raw in enumerate(lines, start=1):
                problem, expected = _check_line(raw, expected)
                if problem:
                    broken = ChainBreak(path.name, number, problem)
                    return ChainReport(False, count, broken)
                count += 1
        return ChainReport(True, count)


def _ends_with_newline(path: Path) -> bool:
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        return handle.read(1) == b"\n"


def _check_line(raw: bytes, expected_prev: str) -> tuple[str | None, str]:
    """Check one line. Returns a problem (or `None`) and the next expected hash."""
    if not raw.strip():
        return "There is an unexpected blank line.", expected_prev
    try:
        record = json.loads(raw.decode("utf-8"))
        attributes = record["attributes"]
        stored = attributes[ATTR_HASH]
        previous = attributes[ATTR_PREV]
    except (ValueError, KeyError, TypeError):
        return "The record is damaged or is not a valid audit record.", expected_prev
    if not isinstance(stored, str) or not isinstance(previous, str):
        return "The record is damaged or is not a valid audit record.", expected_prev
    if record_hash(record) != stored:
        return "The record was changed after it was written.", expected_prev
    if previous != expected_prev:
        return (
            "The record does not follow the one before it, so a record was "
            "removed or the order was changed.",
            expected_prev,
        )
    return None, stored
