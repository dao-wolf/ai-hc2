"""Tests for scripts/privacy_gate.py: the author and committer of a commit.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import AT, DENYLIST, gate, run_gate, setup_repo


class CommitIdentityTests(unittest.TestCase):
    def test_check_identity_scans_the_author_and_the_committer(self) -> None:
        email = "1+example-handle" + AT + "users.noreply.github.com"
        env = {
            "GIT_AUTHOR_NAME": "Quentin Example",
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": "Zorblax",
            "GIT_COMMITTER_EMAIL": email,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            args = ("--root", str(root), "--denylist", str(deny))
            without = run_gate(*args, env=env)[:2]
            checked = run_gate(*args, "--check-identity", env=env)[:2]
        self.assertEqual(without, (0, ""))
        expected = "<git author>:1 term#6\n<git committer>:1 term#2\n"
        self.assertEqual(checked, (1, expected))

    def test_a_failed_author_lookup_does_not_skip_the_committer(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        ident = b"Quentin Example <1+q" + AT.encode() + b"users.noreply.github.com>"
        committer = subprocess.CompletedProcess(
            [], 0, stdout=ident + b" 1700000000 +0000"
        )
        for failure in [subprocess.CalledProcessError(128, "git"), OSError()]:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    gate.subprocess, "run", side_effect=[failure, committer]
                ):
                    hits = gate.scan_identity(Path("."), terms)
                found = [(h.path, h.line, h.label) for h in hits]
                self.assertEqual(found, [("<git committer>", 1, "term#6")])

    def idents(
        self, stdout: bytes, terms: str = DENYLIST
    ) -> list[tuple[str, int, str]]:
        done = subprocess.CompletedProcess([], 0, stdout=stdout)
        with mock.patch.object(gate.subprocess, "run", return_value=done):
            hits = gate.scan_identity(Path("."), gate.parse_terms(terms))
        return [(h.path, h.line, h.label) for h in hits]

    def test_only_the_name_and_email_are_read_not_the_time_stamp(self) -> None:
        ident = b"alice <alice" + AT.encode() + b"example.com> 1700000000 +0000"
        self.assertEqual(self.idents(ident, "1700000000\n"), [])

    def test_a_term_in_the_email_is_found_though_the_name_holds_a_bracket(
        self,
    ) -> None:
        ident = b"x>y <zorblax" + AT.encode() + b"example.com> 1700000000 +0000"
        expected = [("<git author>", 1, "term#2"), ("<git committer>", 1, "term#2")]
        self.assertEqual(self.idents(ident), expected)

    def test_a_name_that_is_not_utf8_does_not_stop_the_check(self) -> None:
        ident = b"\xff Zorblax <alice" + AT.encode() + b"example.com> 1 +0000"
        expected = [("<git author>", 1, "term#2"), ("<git committer>", 1, "term#2")]
        self.assertEqual(self.idents(ident), expected)

    def test_a_lookup_that_fails_is_skipped_not_read_as_an_empty_identity(self) -> None:
        def fail_as_git_does(
            command: list[str], **options: object
        ) -> subprocess.CompletedProcess[bytes]:
            if options.get("check") is True:
                raise subprocess.CalledProcessError(128, command)
            return subprocess.CompletedProcess(command, 128, stdout=b"")

        terms = gate.parse_terms(">\n")
        with mock.patch.object(gate.subprocess, "run", side_effect=fail_as_git_does):
            self.assertEqual(gate.scan_identity(Path("."), terms), [])


if __name__ == "__main__":
    unittest.main()
