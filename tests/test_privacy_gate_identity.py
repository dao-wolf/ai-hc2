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


if __name__ == "__main__":
    unittest.main()
