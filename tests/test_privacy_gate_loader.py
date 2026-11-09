"""Tests for scripts/privacy_gate.py: loading the modules beside it.

The gate keeps its generic checks and its git reading in sibling files. If one
is missing, the gate must exit 2 with a plain message, as it does for its other
failures, and not exit 1 with a traceback.

Made-up data only.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from unittest import mock

from privacy_gate_helpers import SCRIPT, gate

GENERIC = "privacy_gate_generic"
MISSING = "privacy_gate_zorblax"


def refusal(stem: str) -> str:
    return f"privacy gate: cannot load {stem}.py. Keep it beside privacy_gate.py.\n"


def fresh_load(stem: str) -> tuple[ModuleType, str]:
    """Load a sibling as if for the first time, and return it with what was printed."""
    err = io.StringIO()
    with (
        mock.patch.dict(sys.modules),
        contextlib.redirect_stderr(err),
    ):
        sys.modules.pop(f"scripts.{stem}", None)
        module = gate.load_sibling(stem)
    return module, err.getvalue()


def exit_of(
    stem: str, *patches: contextlib.AbstractContextManager[object]
) -> tuple[object, str, bool]:
    """Call load_sibling on a stem, with any patches applied, and return the exit
    code, what it printed and whether the stem was left in sys.modules."""
    err = io.StringIO()
    code: object = None
    with mock.patch.dict(sys.modules), contextlib.redirect_stderr(err):
        sys.modules.pop(f"scripts.{stem}", None)
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            try:
                gate.load_sibling(stem)
            except SystemExit as stop:
                code = stop.code
        left = f"scripts.{stem}" in sys.modules
    return code, err.getvalue(), left


class LoadSiblingTests(unittest.TestCase):
    def test_a_sibling_loads_by_its_dotted_name_from_beside_the_script(self) -> None:
        module, err = fresh_load(GENERIC)
        self.assertEqual(err, "")
        self.assertEqual(module.__name__, f"scripts.{GENERIC}")
        self.assertEqual(Path(module.__file__), SCRIPT.parent / f"{GENERIC}.py")
        self.assertTrue(callable(module.generic_labels))

    def test_a_loaded_sibling_is_registered_under_its_dotted_name(self) -> None:
        with mock.patch.dict(sys.modules):
            sys.modules.pop(f"scripts.{GENERIC}", None)
            module = gate.load_sibling(GENERIC)
            self.assertIs(sys.modules[f"scripts.{GENERIC}"], module)

    def test_a_second_call_returns_the_same_module_without_loading_again(self) -> None:
        with mock.patch.dict(sys.modules):
            sys.modules.pop(f"scripts.{GENERIC}", None)
            first = gate.load_sibling(GENERIC)
            with mock.patch.object(
                gate.importlib.util, "spec_from_file_location"
            ) as loader:
                second = gate.load_sibling(GENERIC)
            loader.assert_not_called()
        self.assertIs(second, first)

    def test_a_missing_sibling_exits_2_with_a_plain_message(self) -> None:
        code, err, _ = exit_of(MISSING)
        self.assertEqual(code, 2)
        self.assertEqual(
            err,
            refusal(MISSING),
        )

    def test_a_failed_load_leaves_no_half_loaded_module_behind(self) -> None:
        _, _, left = exit_of(MISSING)
        self.assertFalse(left)

    def test_a_spec_with_no_loader_exits_2_with_the_same_message(self) -> None:
        for spec in [None, mock.Mock(loader=None)]:
            with self.subTest(spec=spec):
                patch = mock.patch.object(
                    gate.importlib.util, "spec_from_file_location", return_value=spec
                )
                code, err, left = exit_of(GENERIC, patch)
                self.assertEqual((code, err, left), (2, refusal(GENERIC), False))

    def test_an_unreadable_sibling_exits_2_and_is_not_left_loaded(self) -> None:
        for failure in [FileNotFoundError(), PermissionError(), IsADirectoryError()]:
            with self.subTest(failure=type(failure).__name__):
                patch = mock.patch.object(
                    SourceFileLoader, "exec_module", side_effect=failure
                )
                code, err, left = exit_of(GENERIC, patch)
                self.assertEqual((code, err, left), (2, refusal(GENERIC), False))


class CopiedAloneTests(unittest.TestCase):
    """The real script, run the way a hook runs it, with a sibling gone."""

    def run_copy(self, keep: list[str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "scripts"
            folder.mkdir()
            for name in keep:
                shutil.copy(SCRIPT.parent / name, folder / name)
            (Path(tmp) / "notes.md").write_text("all good\n")
            deny = Path(tmp) / "deny.txt"
            deny.write_text("Zorblax\n")
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(folder / "privacy_gate.py"),
                    "--root",
                    tmp,
                    "--denylist",
                    str(deny),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_the_script_alone_exits_2_with_no_traceback(self) -> None:
        result = self.run_copy(["privacy_gate.py"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(
            "privacy gate: cannot load privacy_gate_generic.py", result.stderr
        )

    def test_a_missing_git_module_exits_2_with_no_traceback(self) -> None:
        result = self.run_copy(["privacy_gate.py", "privacy_gate_generic.py"])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("privacy gate: cannot load privacy_gate_git.py", result.stderr)


if __name__ == "__main__":
    unittest.main()
