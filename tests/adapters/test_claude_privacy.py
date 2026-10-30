"""Privacy, bounded-read and determinism tests for the Claude adapters (T-4, P-1)."""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from typing import BinaryIO
from unittest import mock

from hc2.adapters import claude_common as common
from hc2.adapters.claude_common import HEAD_BYTES, MAX_LINE_BYTES, TAIL_BYTES

from .support import (
    CONFIDENTIAL,
    FIXTURE_HOME,
    by_id,
    fake_home,
    fixture_sentinels,
    scan_all,
)

PROJECT = ".claude/projects/-home-alice-projects-example-project"
SUPPORT = "Library/Application Support/Claude"
DESKTOP_INDEX = f"{SUPPORT}/claude-code-sessions/acct-a/org-a"
COWORK_INDEX = f"{SUPPORT}/local-agent-mode-sessions/acct-a/org-a"


def all_json(home: Path, confidential: tuple[str, ...] = (CONFIDENTIAL,)) -> str:
    reports = scan_all(home, confidential)
    return "\n".join(report.to_json() for report in reports.values())


class SentinelTests(unittest.TestCase):
    def test_the_fixtures_really_contain_sentinels(self) -> None:
        sentinels = fixture_sentinels()
        kinds = {s.split("_")[1] for s in sentinels}
        self.assertEqual(kinds, {"MSG", "CONFTITLE"})
        self.assertGreater(len(sentinels), 20)

    def test_no_sentinel_reaches_any_report(self) -> None:
        with fake_home() as home:
            text = all_json(home)
            for sentinel in fixture_sentinels():
                self.assertNotIn(sentinel, text, sentinel)

    def test_message_sentinels_stay_out_even_without_confidential_folders(self) -> None:
        with fake_home() as home:
            text = all_json(home, ())
        for sentinel in fixture_sentinels():
            if sentinel.startswith("SENTINEL_MSG"):
                self.assertNotIn(sentinel, text, sentinel)

    def test_account_details_in_index_files_never_appear(self) -> None:
        with fake_home() as home:
            text = all_json(home)
        for private in ("alice@example.com", "Alice Example", "example-vm"):
            self.assertNotIn(private, text)

    def test_no_report_mentions_the_fake_home_folder(self) -> None:
        with fake_home() as home:
            self.assertNotIn(str(home), all_json(home))

    def test_problems_never_carry_paths_or_file_names(self) -> None:
        with fake_home() as home:
            reports = scan_all(home)
        for report in reports.values():
            for line in report.problems:
                for leak in ("/", "alice", "local_", ".json", ".jsonl"):
                    self.assertNotIn(leak, line)


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_bytes(self) -> None:
        with fake_home() as home:
            self.assertEqual(all_json(home), all_json(home))

    def test_the_result_does_not_depend_on_where_the_home_is(self) -> None:
        with fake_home() as first, fake_home() as second:
            self.assertNotEqual(first, second)
            self.assertEqual(all_json(first), all_json(second))

    def test_file_times_on_disk_do_not_change_the_order(self) -> None:
        with fake_home() as first, fake_home() as second:
            for path in sorted(second.rglob("*.json"), reverse=True):
                path.touch()
            self.assertEqual(all_json(first), all_json(second))


class CountingFile(io.BufferedReader):
    """A real file wrapper that counts the bytes handed out."""

    total = 0

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        CountingFile.total += len(data)
        return data


def record(kind: str, **fields: object) -> str:
    return json.dumps({"type": kind, **fields})


class BoundedReadTests(unittest.TestCase):
    def write_big(self, home: Path) -> Path:
        """About 6 MB: a header, a decoy title in the middle, then a tail."""
        path = home / PROJECT / "big-0001.jsonl"
        header = record(
            "user",
            cwd="/home/alice/projects/example-project",
            entrypoint="cli",
            timestamp="2026-10-10T08:00:00.000Z",
            message={"role": "user", "content": "SENTINEL_MSG_BIG_HEAD"},
        )
        filler = record(
            "user",
            timestamp="2026-10-10T09:00:00.000Z",
            message={"content": "SENTINEL_MSG_BIG_MIDDLE " + "x" * 2000},
        )
        decoy = record("custom-title", customTitle="SENTINEL_MSG_MIDDLE_TITLE")
        title = record("custom-title", customTitle="Big session title")
        last = record(
            "assistant",
            timestamp="2026-10-10T11:00:00.000Z",
            message={"model": "claude-example-model-1", "content": "SENTINEL_MSG_TAIL"},
        )
        lines = [header, decoy, *([filler] * 3000), title, last]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_only_the_head_and_tail_windows_are_read(self) -> None:
        with fake_home() as home:
            big = self.write_big(home)
            self.assertGreater(big.stat().st_size, 10 * (HEAD_BYTES + TAIL_BYTES))
            CountingFile.total = 0
            real_open = common._open_binary

            def counting_open(path: str) -> BinaryIO:
                if path != str(big):
                    return real_open(path)
                return CountingFile(io.FileIO(path, "rb"))

            with mock.patch.object(common, "_open_binary", counting_open):
                sessions = by_id(scan_all(home)["cli"])
            read = CountingFile.total
        self.assertGreater(read, 0)
        self.assertLessEqual(read, HEAD_BYTES + TAIL_BYTES)
        session = sessions["big-0001"]
        self.assertEqual(session.title, "Big session title")  # tail, not middle
        self.assertEqual(session.created, "2026-10-10T08:00:00Z")
        self.assertEqual(session.last_activity, "2026-10-10T11:00:00Z")
        self.assertEqual(session.model, "claude-example-model-1")

    def test_nothing_from_a_big_file_leaks_into_the_output(self) -> None:
        with fake_home() as home:
            self.write_big(home)
            text = all_json(home)
        for part in ("BIG_MIDDLE", "MIDDLE_TITLE", "BIG_HEAD", "SENTINEL_MSG_TAIL"):
            self.assertNotIn(part, text)

    def test_windows_never_exceed_their_limits(self) -> None:
        with fake_home() as home:
            head, tail = common.read_windows(str(self.write_big(home)))
        self.assertLessEqual(sum(len(x) + 1 for x in head), HEAD_BYTES)
        self.assertLessEqual(sum(len(x) + 1 for x in tail), TAIL_BYTES)

    def test_a_huge_line_is_skipped_not_parsed(self) -> None:
        with fake_home() as home:
            stamp = "2026-10-11T08:00:00Z"
            first = record("user", cwd="/home/alice/p", timestamp=stamp)
            huge = record(
                "assistant",
                timestamp="2026-10-11T09:00:00Z",
                message={"model": "m", "content": "y" * (MAX_LINE_BYTES + 10)},
            )
            path = home / PROJECT / "huge-0001.jsonl"
            path.write_text(first + "\n" + huge + "\n", encoding="utf-8")
            session = by_id(scan_all(home)["cli"])["huge-0001"]
        self.assertIsNone(session.model)
        self.assertEqual(session.created, "2026-10-11T08:00:00Z")

    def test_an_oversized_index_file_is_not_parsed(self) -> None:
        with fake_home() as home:
            pad = "z" * common.MAX_JSON_BYTES
            body = json.dumps({"sessionId": "local_big", "pad": pad})
            (home / DESKTOP_INDEX / "local_big.json").write_text(body)
            report = scan_all(home)["desktop"]
        self.assertNotIn("local_big", by_id(report))
        self.assertTrue(any("not in a format" in p for p in report.problems))


class DamagedInputTests(unittest.TestCase):
    def test_deeply_nested_json_is_a_problem_not_a_crash(self) -> None:
        nested = "[" * 200_000
        with fake_home() as home:
            (home / DESKTOP_INDEX / "local_deep.json").write_text(nested)
            (home / ".claude/sessions/5000.json").write_text(nested)
            (home / PROJECT / "deep-0001.jsonl").write_text(nested + "\n")
            reports = scan_all(home)
        self.assertIn("deep-0001", by_id(reports["cli"]))
        self.assertTrue(reports["cli"].problems)
        self.assertTrue(reports["desktop"].problems)

    def test_binary_junk_is_a_problem_not_a_crash(self) -> None:
        junk = bytes(range(256)) * 40
        with fake_home() as home:
            (home / PROJECT / "junk-0001.jsonl").write_bytes(junk)
            (home / COWORK_INDEX / "local_junk.json").write_bytes(junk)
            reports = scan_all(home)
        self.assertIn("junk-0001", by_id(reports["cli"]))
        self.assertTrue(any("valid data" in p for p in reports["cowork"].problems))

    def test_empty_and_wrong_shape_files(self) -> None:
        with fake_home() as home:
            (home / PROJECT / "empty-0001.jsonl").write_text("")
            (home / DESKTOP_INDEX / "local_empty.json").write_text("")
            (home / DESKTOP_INDEX / "local_str.json").write_text('"text"')
            reports = scan_all(home)
        self.assertIn("empty-0001", by_id(reports["cli"]))
        self.assertTrue(reports["desktop"].problems)

    def test_a_wrong_typed_field_becomes_none(self) -> None:
        body = {
            "sessionId": "local_types",
            "title": 5,
            "cwd": ["x"],
            "model": {},
            "createdAt": "soon",
            "lastActivityAt": None,
            "isArchived": "yes",
            "cliSessionId": 7,
        }
        with fake_home() as home:
            (home / DESKTOP_INDEX / "local_types.json").write_text(json.dumps(body))
            session = by_id(scan_all(home)["desktop"])["local_types"]
        for value in (session.title, session.folder, session.model, session.created):
            self.assertIsNone(value)


def snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


class ReadOnlyTests(unittest.TestCase):
    def test_scanning_changes_no_file(self) -> None:
        with fake_home() as home:
            before = snapshot(home)
            scan_all(home)
            self.assertEqual(before, snapshot(home))

    def test_the_fixture_tree_itself_is_never_written(self) -> None:
        before = snapshot(FIXTURE_HOME)
        with fake_home() as home:
            scan_all(home)
        self.assertEqual(before, snapshot(FIXTURE_HOME))


if __name__ == "__main__":
    unittest.main()
