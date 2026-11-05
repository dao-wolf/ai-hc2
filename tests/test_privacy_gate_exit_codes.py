"""Tests for scripts/privacy_gate.py: the gate fails closed.

Exit 0 and exit 1 are only possible when the scan finished, and a finished scan
ends with a summary line. Every other outcome exits 2 without one.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import AT, gate, run_gate, setup_repo

SUMMARY_RE = re.compile(r"^privacy gate: scanned .*, \d+ hits\.$")


def last_line(err: str) -> str:
    return err.strip().splitlines()[-1]


def stage_notes(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "notes.md"], check=True)


class SummaryLineTests(unittest.TestCase):
    def test_a_clean_run_ends_with_the_summary_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            code, _, err = run_gate("--root", str(root), "--denylist", str(deny))
        self.assertEqual(code, 0)
        self.assertRegex(last_line(err), SUMMARY_RE)

    def test_a_run_with_hits_ends_with_the_summary_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, f"jane{AT}corp.org\n")
            code, _, err = run_gate("--root", str(root), "--denylist", str(deny))
        self.assertEqual(code, 1)
        self.assertRegex(last_line(err), SUMMARY_RE)

    def test_a_commit_message_run_ends_with_the_summary_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, deny = setup_repo(tmp, "")
            message = Path(tmp) / "msg.txt"
            message.write_text("fix: nothing to see\n")
            code, _, err = run_gate("--denylist", str(deny), "--message", str(message))
        self.assertEqual(code, 0)
        self.assertRegex(last_line(err), SUMMARY_RE)


class UnexpectedFailureTests(unittest.TestCase):
    def assert_failed_closed(self, result: tuple[int, str, str], kind: str) -> None:
        code, out, err = result
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn(f"FAILED ({kind})", err)
        self.assertNotRegex(err, re.compile(r"^privacy gate: scanned ", re.MULTILINE))

    def test_any_exception_during_the_scan_exits_2_and_hides_its_text(self) -> None:
        boom = RuntimeError("Zorblax is in this message")
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            with mock.patch.object(gate, "scan_source", side_effect=boom):
                result = run_gate("--root", str(root), "--denylist", str(deny))
        self.assert_failed_closed(result, "RuntimeError")
        self.assertNotIn("zorblax", (result[1] + result[2]).lower())

    def test_an_exception_in_the_identity_check_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            with mock.patch.object(gate, "scan_identity", side_effect=ValueError()):
                result = run_gate(
                    "--root", str(root), "--denylist", str(deny), "--check-identity"
                )
        self.assert_failed_closed(result, "ValueError")

    def test_a_deny_list_that_is_not_utf8_exits_2_without_quoting_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            deny.write_bytes(b"\xff\xfe\n")
            result = run_gate("--root", str(root), "--denylist", str(deny))
        self.assert_failed_closed(result, "UnicodeDecodeError")
        self.assertNotIn("0xff", result[2])

    def test_a_missing_staged_object_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            stage_notes(root)
            staged = subprocess.run(
                ["git", "-C", str(root), "ls-files", "--stage"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            object_id = staged.split()[1]
            (root / ".git" / "objects" / object_id[:2] / object_id[2:]).unlink()
            result = run_gate("--root", str(root), "--denylist", str(deny), "--staged")
        code, out, err = result
        self.assertEqual((code, out), (2, ""))
        self.assertIn("staged object", err)
        self.assertNotIn("IndexError", err)
        self.assertNotRegex(err, re.compile(r"^privacy gate: scanned ", re.MULTILINE))


class EmptyDenylistTests(unittest.TestCase):
    def run_with_comments_only(self, *extra: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            deny.write_text("# only a comment\n\n")
            return run_gate("--root", str(root), "--denylist", str(deny), *extra)

    def test_a_required_deny_list_with_no_terms_exits_2(self) -> None:
        code, out, err = self.run_with_comments_only("--require-denylist")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no terms", err)

    def test_an_empty_deny_list_is_allowed_when_it_is_not_required(self) -> None:
        code, _, err = self.run_with_comments_only()
        self.assertEqual(code, 0)
        self.assertRegex(last_line(err), SUMMARY_RE)


class ConflictingOptionsTests(unittest.TestCase):
    def test_generic_only_with_require_denylist_exits_2_not_a_quiet_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            with self.assertRaises(SystemExit) as raised:
                run_gate("--root", str(root), "--generic-only", "--require-denylist")
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
