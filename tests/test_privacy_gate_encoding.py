"""Tests for scripts/privacy_gate.py: reading files that are not UTF-8.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import SCRIPT, gate, run_gate, setup_repo


class EncodingTests(unittest.TestCase):
    def test_a_non_ascii_term_is_caught_under_a_non_utf8_locale(self) -> None:
        term = "Exämple Person"
        locale = {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
        with tempfile.TemporaryDirectory() as tmp:
            deny = Path(tmp) / "denylist.txt"
            deny.write_text(f"{term}\n", encoding="utf-8")
            message = Path(tmp) / "COMMIT_EDITMSG"
            message.write_text(f"docs: thank {term}\n", encoding="utf-8")
            command = [sys.executable, str(SCRIPT), "--denylist", str(deny)]
            command += ["--message", str(message)]
            done = subprocess.run(
                command, capture_output=True, text=True, env=os.environ | locale
            )
        self.assertEqual(
            (done.returncode, done.stdout), (1, "<commit message>:1 term#1\n")
        )

    def test_files_are_read_as_utf8_whatever_the_default_encoding(self) -> None:
        # mutmut cannot see a mutant in a subprocess, so this models the test above
        # in-process: a default encoding that is not UTF-8, as under LC_ALL=C.
        term = "Exämple Person"
        read_bytes = Path.read_bytes

        def read_text(
            path: Path, encoding: str | None = None, errors: str | None = None
        ):
            return read_bytes(path).decode(encoding or "ascii", errors or "strict")

        with tempfile.TemporaryDirectory() as tmp:
            deny, message = Path(tmp) / "denylist.txt", Path(tmp) / "COMMIT_EDITMSG"
            deny.write_bytes(f"{term}\n".encode())
            message.write_bytes(f"docs: thank {term}\n".encode())
            with mock.patch.object(Path, "read_text", read_text):
                hits = gate.scan_message(message, gate.load_denylist(deny))
        self.assertEqual([(h.path, h.line) for h in hits], [("<commit message>", 1)])

    def test_a_message_with_an_invalid_byte_is_still_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "x\n")
            message = Path(tmp) / "COMMIT_EDITMSG"
            message.write_bytes(b"fix: caf\xe9 for Quentin Example\n")
            args = ("--root", str(root), "--denylist", str(deny))
            code, out, _ = run_gate(*args, "--message", str(message))
        self.assertEqual((code, out), (1, "<commit message>:1 term#6\n"))


if __name__ == "__main__":
    unittest.main()
