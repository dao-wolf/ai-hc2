"""Tests for scripts/privacy_gate.py: scanning the commits a push would send.

A leak that one commit adds and the next removes passes a scan of the files at
the tip, yet it is public once pushed. --range scans each commit's message,
author, committer, file names and added lines. --pre-push works out which
commits are outgoing from the lines git gives the hook. Made-up data only.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import AT, DENYLIST, gate, run_gate

SUMMARY_RE = re.compile(r"^privacy gate: scanned .*, \d+ hits\.$", re.MULTILINE)
ZEROS = "0" * 40
LIMIT = 20


class RangeRepoTestCase(unittest.TestCase):
    """A throwaway repo whose commits the tests make by hand."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "repo"
        self.root.mkdir()
        self.denylist = Path(tmp.name) / "denylist.txt"
        self.denylist.write_text(DENYLIST)
        email = "alice" + AT + "example.com"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env |= {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": tmp.name,
            "GIT_AUTHOR_NAME": "alice",
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": "alice",
            "GIT_COMMITTER_EMAIL": email,
        }
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")

    def git(self, *argv: str, extra_env: dict[str, str] | None = None) -> str:
        env = self.env | (extra_env or {})
        command = ["git", "-C", str(self.root), *argv]
        done = subprocess.run(command, env=env, capture_output=True, check=True)
        return done.stdout.decode().strip()

    def commit(
        self,
        files: dict[str, str | bytes | None],
        message: str = "docs: change",
        extra_env: dict[str, str] | None = None,
    ) -> str:
        """Make a commit: a value of None deletes the file. Returns its id."""
        for name, body in files.items():
            path = self.root / name
            if body is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(body, bytes):
                path.write_bytes(body)
            else:
                path.write_text(body)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message, extra_env=extra_env)
        return self.git("rev-parse", "HEAD")

    def arguments(self, *extra: str) -> list[str]:
        return ["--root", str(self.root), "--denylist", str(self.denylist), *extra]

    def scan_range(self, spec: str, *extra: str) -> tuple[int, str, str]:
        return run_gate(*self.arguments(f"--range={spec}", *extra))

    def scan_tip(self) -> tuple[int, str, str]:
        return run_gate(*self.arguments())


def short(commit: str) -> str:
    return commit[:10]


class RangeScanTests(RangeRepoTestCase):
    def test_a_clean_range_exits_0_and_counts_its_commits(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.commit({"a.md": "one\n"})
        self.commit({"b.md": "two\n"})
        code, out, err = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))
        self.assertRegex(err, SUMMARY_RE)
        self.assertIn("scanned 2 commits, 2 files, skipped 0, 0 hits", err)

    def test_a_term_added_and_removed_again_is_still_found(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        leak = self.commit({"notes.md": "the zorblax plan\n"})
        self.commit({"notes.md": "fine\n"})
        self.assertEqual(self.scan_tip()[0], 0)
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:1 term#2"])

    def test_a_term_in_a_commit_message_is_found(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        leak = self.commit({"a.md": "one\n"}, message="docs: the zorblax plan")
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:<message>:1 term#2"])

    def test_a_term_in_the_author_or_committer_is_found(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        by_author = self.commit(
            {"a.md": "1\n"}, extra_env={"GIT_AUTHOR_NAME": "Zorblax"}
        )
        by_committer = self.commit(
            {"b.md": "2\n"}, extra_env={"GIT_COMMITTER_NAME": "Zorblax"}
        )
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        expected = [
            f"{short(by_author)}:<author>:1 term#2",
            f"{short(by_committer)}:<committer>:1 term#2",
        ]
        self.assertEqual(sorted(out.splitlines()), sorted(expected))

    def test_a_hit_from_before_the_range_is_not_reported(self) -> None:
        base = self.commit({"notes.md": "zorblax long ago\nsecond\n"})
        self.commit({"notes.md": "zorblax long ago\nsecond, edited\n"})
        self.assertEqual(self.scan_tip()[0], 1)
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))

    def test_a_new_hit_in_an_edited_file_names_its_line(self) -> None:
        base = self.commit({"notes.md": "a\nb\n"})
        leak = self.commit({"notes.md": "a\nb\nzorblax\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:3 term#2"])

    def test_a_deleted_file_is_not_scanned(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.commit({"old.md": "fine\n"})
        self.commit({"old.md": None})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))

    def test_a_file_name_with_a_term_is_found(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        leak = self.commit({"zorblax.txt": "fine\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:zorblax.txt:0 term#2"])

    def test_a_root_commit_in_the_range_is_scanned(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.git("checkout", "-q", "--orphan", "other")
        leak = self.commit({"leak.txt": "zorblax\n"})
        code, out, _ = self.scan_range(f"{base}..other")
        self.assertEqual(code, 1)
        self.assertIn(f"{short(leak)}:leak.txt:1 term#2", out)

    def test_commits_brought_in_by_a_merge_are_scanned(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.git("checkout", "-q", "-b", "side")
        leak = self.commit({"leak.txt": "zorblax\n"})
        self.git("checkout", "-q", "main")
        self.commit({"other.md": "fine\n"})
        self.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
        code, out, err = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:leak.txt:1 term#2"])
        self.assertIn("scanned 3 commits", err)

    def test_generic_checks_run_on_added_lines_and_the_generic_only_option_works(
        self,
    ) -> None:
        base = self.commit({"notes.md": "fine\n"})
        leak = self.commit({"notes.md": "mail jane" + AT + "corp.org, zorblax\n"})
        code, out, err = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:1 email"])
        self.assertIn("generic checks only", err)

    def test_utf16_text_with_a_byte_order_mark_is_scanned(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        wide = b"\xff\xfe" + "zorblax\n".encode("utf-16-le")
        leak = self.commit({"wide.txt": wide})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:wide.txt:1 term#2"])

    def test_a_binary_file_is_a_quiet_count(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.commit({"image.bin": b"\0\1\2 zorblax"})
        code, out, err = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("skipped 1", err)
        self.assertNotIn("image.bin", err)

    def test_an_empty_range_is_clean_and_says_it_scanned_no_commits(self) -> None:
        self.commit({"notes.md": "fine\n"})
        code, out, err = self.scan_range("HEAD..HEAD")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)


class RangeFailureTests(RangeRepoTestCase):
    def test_a_range_git_cannot_resolve_exits_2_with_no_summary(self) -> None:
        self.commit({"notes.md": "fine\n"})
        code, out, err = self.scan_range("nope..HEAD")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("could not read", err)
        self.assertNotRegex(err, SUMMARY_RE)

    def test_a_range_that_is_not_two_refs_joined_by_dots_exits_2(self) -> None:
        self.commit({"notes.md": "fine\n"})
        for spec in ("HEAD", "--all..HEAD", ""):
            with self.subTest(spec=spec):
                code, out, err = self.scan_range(spec)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("BASE..HEAD", err)
                self.assertNotRegex(err, SUMMARY_RE)

    def test_the_range_cannot_be_combined_with_another_source(self) -> None:
        for other in ("--staged", "--pre-push"):
            shown = io.StringIO()
            with (
                self.subTest(other=other),
                contextlib.redirect_stderr(shown),
                self.assertRaises(SystemExit) as raised,
            ):
                gate.main(self.arguments("--range", "HEAD..HEAD", other))
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("not allowed with", shown.getvalue())

    def test_a_file_that_is_too_large_exits_2_unless_allowed(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        big = self.commit({"big.txt": "x" * (LIMIT + 1)})
        with mock.patch.object(gate, "MAX_BYTES", LIMIT):
            code, out, err = self.scan_range(f"{base}..HEAD")
            allowed = self.scan_range(f"{base}..HEAD", "--allow-skipped")
        self.assertEqual((code, out), (2, ""))
        self.assertIn(f"{short(big)}:big.txt", err)
        self.assertIn("--allow-skipped", err)
        self.assertNotRegex(err, SUMMARY_RE)
        self.assertEqual(allowed[:2], (0, ""))
        self.assertRegex(allowed[2], SUMMARY_RE)


class PrePushTests(RangeRepoTestCase):
    def pre_push(
        self, *lines: str, extra: tuple[str, ...] = ()
    ) -> tuple[int, str, str]:
        stdin = io.StringIO("".join(line + "\n" for line in lines))
        with mock.patch.object(gate.sys, "stdin", stdin):
            return run_gate(*self.arguments("--pre-push", *extra))

    @staticmethod
    def update(local: str, remote: str) -> str:
        return f"refs/heads/topic {local} refs/heads/topic {remote}"

    def test_an_update_scans_what_the_remote_does_not_have(self) -> None:
        base = self.commit({"notes.md": "zorblax long ago\n"})
        leak = self.commit({"a.md": "zorblax\n"})
        code, out, _ = self.pre_push(self.update(leak, base))
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:a.md:1 term#2"])

    def test_a_clean_update_passes_though_the_remote_holds_an_old_hit(self) -> None:
        base = self.commit({"notes.md": "zorblax long ago\n"})
        head = self.commit({"a.md": "fine\n"})
        code, out, err = self.pre_push(self.update(head, base))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 1 commits", err)

    def test_a_new_branch_scans_only_what_no_remote_branch_has(self) -> None:
        base = self.commit({"notes.md": "zorblax long ago\n"})
        self.git("update-ref", "refs/remotes/origin/main", base)
        leak = self.commit({"a.md": "zorblax\n"})
        code, out, _ = self.pre_push(self.update(leak, ZEROS))
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:a.md:1 term#2"])

    def test_a_clean_new_branch_passes(self) -> None:
        base = self.commit({"notes.md": "zorblax long ago\n"})
        self.git("update-ref", "refs/remotes/origin/main", base)
        head = self.commit({"a.md": "fine\n"})
        code, out, err = self.pre_push(self.update(head, ZEROS))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 1 commits", err)

    def test_a_remote_commit_this_clone_lacks_is_treated_as_a_new_branch(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.git("update-ref", "refs/remotes/origin/main", base)
        leak = self.commit({"a.md": "zorblax\n"})
        code, out, _ = self.pre_push(self.update(leak, "1" * 40))
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:a.md:1 term#2"])

    def test_deleting_a_branch_scans_nothing(self) -> None:
        base = self.commit({"notes.md": "zorblax\n"})
        code, out, err = self.pre_push(self.update(ZEROS, base))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)

    def test_nothing_to_push_is_clean(self) -> None:
        self.commit({"notes.md": "fine\n"})
        code, out, err = self.pre_push()
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)

    def test_two_branches_at_the_same_commit_scan_it_once(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        head = self.commit({"a.md": "fine\n"})
        other = f"refs/heads/other {head} refs/heads/other {base}"
        code, _, err = self.pre_push(self.update(head, base), other)
        self.assertEqual(code, 0)
        self.assertIn("scanned 1 commits", err)

    def test_a_line_git_would_not_send_exits_2(self) -> None:
        self.commit({"notes.md": "fine\n"})
        for line in ("nonsense", "a b c", "refs/heads/x --all refs/heads/x " + ZEROS):
            with self.subTest(line=line):
                code, out, err = self.pre_push(line)
                self.assertEqual((code, out), (2, ""))
                self.assertNotRegex(err, SUMMARY_RE)


if __name__ == "__main__":
    unittest.main()
