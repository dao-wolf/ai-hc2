"""The audit log: hash chain, atomic appends and its known limits (S-8, S-9)."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path

from hc2.audit import (
    ATTR_HASH,
    ATTR_PREV,
    GENESIS_HASH,
    AuditLog,
    canonical_json,
    event_date,
    record_hash,
)
from hc2.errors import UserError
from hc2.model import Actor, ActorType, Event, Pairs

SYSTEM = Actor(ActorType.SYSTEM, "hc2")


def make_event(n: int, day: str = "2026-10-30") -> Event:
    when = datetime.fromisoformat(f"{day}T09:00:{n % 60:02d}+00:00")
    nanos = str(int(when.timestamp()) * 1_000_000_000)
    return Event(
        time_unix_nano=nanos,
        event_name="hc2.test.event",
        body=f"Test event number {n} happened.",
        actor=SYSTEM,
        attributes=Pairs.of({"n": n}),
    )


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "audit"
        self.log = AuditLog(self.dir)

    def lines(self, name: str = "2026-10-30.jsonl") -> list[str]:
        return (self.dir / name).read_text(encoding="utf-8").splitlines()

    def fill(self, count: int, day: str = "2026-10-30") -> None:
        for n in range(count):
            self.log.append(make_event(n, day))

    # -- writing ---------------------------------------------------------

    def test_nothing_is_created_until_the_first_append(self) -> None:
        self.assertFalse(self.dir.exists())
        report = self.log.verify_chain()
        self.assertTrue(report.ok)
        self.assertEqual(report.records, 0)
        self.assertEqual(self.log.head(), GENESIS_HASH)

    def test_records_chain_from_the_genesis_hash(self) -> None:
        self.fill(3)
        records = [json.loads(line) for line in self.lines()]
        self.assertEqual(records[0]["attributes"][ATTR_PREV], GENESIS_HASH)
        for before, after in zip(records, records[1:], strict=False):
            self.assertEqual(
                after["attributes"][ATTR_PREV], before["attributes"][ATTR_HASH]
            )
        self.assertEqual(self.log.head(), records[-1]["attributes"][ATTR_HASH])

    def test_the_hash_covers_the_record_without_its_own_hash(self) -> None:
        self.fill(1)
        record = json.loads(self.lines()[0])
        self.assertEqual(record["attributes"][ATTR_HASH], record_hash(record))
        record["body"] = "Changed."
        self.assertNotEqual(record["attributes"][ATTR_HASH], record_hash(record))

    def test_each_line_is_canonical_json_with_otel_fields(self) -> None:
        self.fill(1)
        line = self.lines()[0]
        record = json.loads(line)
        self.assertEqual(line, canonical_json(record))
        for key in ("timeUnixNano", "eventName", "body", "severityText", "attributes"):
            self.assertIn(key, record)
        self.assertEqual(record["attributes"]["hc2.schema"], "1")

    def test_files_are_dated_in_utc_by_the_event_time(self) -> None:
        late = datetime(2026, 10, 30, 23, 59, 59, tzinfo=UTC)
        nanos = str(int(late.timestamp()) * 1_000_000_000)
        event = Event(nanos, "hc2.test.event", "Late event.", SYSTEM)
        self.assertEqual(event_date(event), "2026-10-30")
        self.log.append(event)
        self.assertEqual([p.name for p in self.log.files()], ["2026-10-30.jsonl"])

    def test_the_chain_spans_files(self) -> None:
        self.fill(2, "2026-10-29")
        self.fill(2, "2026-10-30")
        names = [p.name for p in self.log.files()]
        self.assertEqual(names, ["2026-10-29.jsonl", "2026-10-30.jsonl"])
        first = json.loads(self.lines("2026-10-30.jsonl")[0])
        last_before = json.loads(self.lines("2026-10-29.jsonl")[-1])
        self.assertEqual(
            first["attributes"][ATTR_PREV], last_before["attributes"][ATTR_HASH]
        )
        report = self.log.verify_chain()
        self.assertTrue(report.ok)
        self.assertEqual(report.records, 4)

    def test_an_older_event_never_writes_into_the_past(self) -> None:
        self.fill(1, "2026-10-30")
        self.log.append(make_event(9, "2026-10-01"))
        self.assertEqual([p.name for p in self.log.files()], ["2026-10-30.jsonl"])
        self.assertTrue(self.log.verify_chain().ok)

    def test_files_are_private(self) -> None:
        self.fill(1)
        mode = stat.S_IMODE(os.stat(self.dir / "2026-10-30.jsonl").st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)

    def test_concurrent_appends_keep_the_chain_valid(self) -> None:
        def work(start: int) -> None:
            for n in range(start, start + 10):
                self.log.append(make_event(n))

        threads = [threading.Thread(target=work, args=(i * 10,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        report = self.log.verify_chain()
        self.assertTrue(report.ok)
        self.assertEqual(report.records, 40)

    def test_a_long_last_line_is_still_chained_from(self) -> None:
        event = Event(
            make_event(0).time_unix_nano, "hc2.test.event", "x" * 30_000, SYSTEM
        )
        self.log.append(event)
        self.log.append(make_event(1))
        self.assertTrue(self.log.verify_chain().ok)

    def test_an_unwritable_folder_is_a_plain_error(self) -> None:
        blocker = Path(self._tmp.name) / "blocker"
        blocker.write_text("a file, not a folder")
        with self.assertRaises(UserError) as caught:
            AuditLog(blocker / "audit").append(make_event(0))
        self.assertNotIn(str(blocker), str(caught.exception))

    # -- tampering -------------------------------------------------------

    def rewrite(self, lines: list[str], name: str = "2026-10-30.jsonl") -> None:
        (self.dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_editing_a_line_breaks_the_chain_at_that_line(self) -> None:
        self.fill(5)
        lines = self.lines()
        lines[2] = lines[2].replace("number 2", "number 99")
        self.rewrite(lines)
        report = self.log.verify_chain()
        self.assertFalse(report.ok)
        assert report.first_break is not None
        self.assertEqual(report.first_break.line, 3)
        self.assertEqual(report.first_break.file, "2026-10-30.jsonl")
        self.assertIn("changed", report.first_break.reason)
        self.assertEqual(report.records, 2)

    def test_deleting_a_middle_line_breaks_the_chain_at_the_next_line(self) -> None:
        self.fill(5)
        lines = self.lines()
        del lines[2]
        self.rewrite(lines)
        report = self.log.verify_chain()
        self.assertFalse(report.ok)
        assert report.first_break is not None
        self.assertEqual(report.first_break.line, 3)
        self.assertIn("removed", report.first_break.reason)

    def test_deleting_the_first_line_is_caught(self) -> None:
        self.fill(3)
        self.rewrite(self.lines()[1:])
        report = self.log.verify_chain()
        assert report.first_break is not None
        self.assertEqual(report.first_break.line, 1)

    def test_swapping_two_lines_is_caught(self) -> None:
        self.fill(4)
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.rewrite(lines)
        self.assertFalse(self.log.verify_chain().ok)

    def test_a_break_in_an_earlier_file_is_found_first(self) -> None:
        self.fill(3, "2026-10-29")
        self.fill(3, "2026-10-30")
        lines = self.lines("2026-10-29.jsonl")
        lines[1] = lines[1].replace("number 1", "number 7")
        self.rewrite(lines, "2026-10-29.jsonl")
        report = self.log.verify_chain()
        assert report.first_break is not None
        self.assertEqual(report.first_break.file, "2026-10-29.jsonl")

    def test_deleting_a_whole_file_in_the_middle_is_caught(self) -> None:
        for day in ("2026-10-28", "2026-10-29", "2026-10-30"):
            self.fill(2, day)
        (self.dir / "2026-10-29.jsonl").unlink()
        report = self.log.verify_chain()
        assert report.first_break is not None
        self.assertEqual(report.first_break.file, "2026-10-30.jsonl")

    def test_damaged_and_blank_lines_are_reported(self) -> None:
        for bad in ("{not json", "", "[1, 2]", '{"attributes": {}}'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                log = AuditLog(Path(tmp) / "audit")
                log.append(make_event(0))
                path = log.files()[0]
                path.write_text(path.read_text() + bad + "\n")
                report = log.verify_chain()
                assert report.first_break is not None
                self.assertEqual(report.first_break.line, 2)

    def test_appending_after_a_half_written_line_still_works(self) -> None:
        self.fill(2)
        path = self.dir / "2026-10-30.jsonl"
        with path.open("ab") as handle:
            handle.write(b'{"half": "a line')  # a crash before the newline
        self.log.append(make_event(5))
        report = self.log.verify_chain()
        assert report.first_break is not None
        self.assertEqual(report.first_break.line, 3)

    # -- documented limits (S-9) ----------------------------------------

    def test_limitation_a_full_rewrite_with_fresh_hashes_is_not_caught(self) -> None:
        """KNOWN LIMITATION, not a feature (S-8, S-9, threat model row 19).

        Someone who can write the file can rebuild every record and every hash
        from the first line. The chain then verifies. Catching this needs an
        anchor kept elsewhere, such as the chain head signed into approvals.
        """
        self.fill(4)
        original_head = self.log.head()
        forged: list[str] = []
        previous = GENESIS_HASH
        for n in range(4):
            record = make_event(n).to_log_record()
            record["body"] = "Nothing happened here." if n == 1 else record["body"]
            record["attributes"][ATTR_PREV] = previous
            previous = record_hash(record)
            record["attributes"][ATTR_HASH] = previous
            forged.append(canonical_json(record))
        self.rewrite(forged)
        report = self.log.verify_chain()
        self.assertTrue(report.ok)  # the forgery is not detected
        self.assertNotEqual(self.log.head(), original_head)  # only an anchor shows it

    def test_limitation_removing_records_from_the_end_is_not_caught(self) -> None:
        """KNOWN LIMITATION: a shorter chain is still a valid chain."""
        self.fill(5)
        self.rewrite(self.lines()[:3])
        self.assertTrue(self.log.verify_chain().ok)


if __name__ == "__main__":
    unittest.main()
