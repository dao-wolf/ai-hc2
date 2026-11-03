"""Tests for scripts/privacy_gate.py: what it does when given nothing.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import AT, SCRIPT, gate, setup_repo


class DefaultsTests(unittest.TestCase):
    def test_default_denylist_path_when_the_variable_is_unset(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "HC2_PRIVACY_DENYLIST"}
        with mock.patch.dict(os.environ, env, clear=True):
            path = gate.resolve_denylist(None)
        expected = Path("~/.config/ai-hc2/privacy-denylist.txt").expanduser()
        self.assertEqual(path, expected)

    def test_main_reads_the_command_line_when_given_no_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = setup_repo(tmp, f"jane{AT}corp.org\n")
            argv = ["privacy_gate.py", "--root", str(root), "--generic-only"]
            out = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = gate.main()
        self.assertEqual((code, out.getvalue()), (1, "notes.md:1 email\n"))

    def test_the_default_root_is_the_repo_the_script_lives_in(self) -> None:
        self.assertEqual(gate.build_parser().parse_args([]).root, SCRIPT.parent.parent)


if __name__ == "__main__":
    unittest.main()
