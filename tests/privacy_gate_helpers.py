"""Shared pieces of the privacy gate's tests: the gate, a made-up deny-list, helpers.

Strings that the gate would flag are built from pieces, so these files do not
trip the gate itself.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
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
