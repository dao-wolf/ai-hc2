"""Shared pieces of the privacy gate's tests: the gate, a made-up deny-list, helpers.

Strings that the gate would flag are built from pieces, so these files do not
trip the gate itself.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "privacy_gate.py"
AT = "@"
USERS = "/Users/"
HOME = "/home/"


def load_gate() -> ModuleType:
    # The dotted name is the one mutmut gives the module, so it can match its mutants.
    spec = importlib.util.spec_from_file_location("scripts.privacy_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = load_gate()

DENYLIST = """\
# a made-up deny-list
Zorblax

acme-secret/
foo.bar
Quentin Example
"""
# Line numbers: Zorblax 2, acme-secret/ 4, foo.bar 5, Quentin Example 6.


def labels(text: str, generic: bool = True) -> list[str]:
    terms = gate.parse_terms(DENYLIST)
    return [hit.label for hit in gate.scan_text("f.txt", text, terms, generic)]


def run_gate(*argv: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env or {}),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = gate.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def setup_repo(tmp: str, body: str) -> tuple[Path, Path]:
    root = Path(tmp) / "repo"
    root.mkdir()
    (root / "notes.md").write_text(body)
    denylist = Path(tmp) / "denylist.txt"
    denylist.write_text(DENYLIST)
    return root, denylist


class HookRepoTestCase(unittest.TestCase):
    """A throwaway repo with the gate copied in, to run real git hooks in."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "repo"
        (self.root / "scripts").mkdir(parents=True)
        for name in ["privacy_gate.py", "install-hooks.sh"]:
            shutil.copy(SCRIPT.parent / name, self.root / "scripts")
        self.denylist = Path(tmp.name) / "denylist.txt"
        self.denylist.write_text(DENYLIST)
        email = "alice" + AT + "example.com"
        # Drop GIT_DIR and the like, so a run from inside a hook can't commit here.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env |= {
            "HC2_PRIVACY_DENYLIST": str(self.denylist),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": tmp.name,
            "GIT_EDITOR": "true",
            "GIT_AUTHOR_NAME": "alice",
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": "alice",
            "GIT_COMMITTER_EMAIL": email,
        }
        self.run_in_repo("git", "init", "-q")
        self.notes = self.root / "notes.md"

    def run_in_repo(self, *argv: str) -> tuple[int, str]:
        done = subprocess.run(
            argv, cwd=self.root, env=self.env, capture_output=True, text=True
        )
        return done.returncode, done.stdout + done.stderr

    def install(self, *options: str) -> tuple[int, str]:
        return self.run_in_repo("sh", "scripts/install-hooks.sh", *options)
