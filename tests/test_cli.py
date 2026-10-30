"""Tests for the `hc2` command line."""

from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from hc2 import __version__, cli


def run(*argv: str) -> tuple[int, str, str]:
    """Run main() and return the exit code, stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def folders(*, config: bool, state: bool) -> Iterator[Path]:
    """Point HC2 at a temporary root, creating the chosen folders."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if config:
            (root / "config").mkdir()
        if state:
            (root / "state").mkdir()
        env = {
            "HC2_CONFIG_DIR": str(root / "config"),
            "HC2_STATE_DIR": str(root / "state"),
        }
        with mock.patch.dict(os.environ, env):
            yield root


class VersionTests(unittest.TestCase):
    def test_version_in_plain_english(self) -> None:
        code, out, _ = run("--version")
        self.assertEqual((code, out), (0, f"hc2 {__version__}\n"))

    def test_version_is_0_0_1(self) -> None:
        self.assertEqual(__version__, "0.0.1")

    def test_version_json(self) -> None:
        code, out, _ = run("--version", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(out),
            {"name": "ai-hc2", "schema": 2, "version": __version__},
        )


class DoctorTests(unittest.TestCase):
    def test_all_clear(self) -> None:
        with folders(config=True, state=True):
            code, out, _ = run("doctor")
        self.assertEqual(code, 0)
        self.assertIn("Everything looks fine.", out)
        self.assertIn("Python", out)
        self.assertNotIn("Fix:", out)

    def test_missing_folders_are_notes_not_failures(self) -> None:
        with folders(config=False, state=False):
            code, out, _ = run("doctor")
        self.assertEqual(code, 0)
        self.assertIn("does not exist yet", out)
        self.assertIn("mkdir -p", out)
        self.assertIn("No problems. 2 things to note.", out)

    def test_one_missing_folder_uses_the_singular(self) -> None:
        with folders(config=True, state=False):
            _, out, _ = run("doctor")
        self.assertIn("No problems. 1 thing to note.", out)

    def test_a_file_where_a_folder_should_be_fails(self) -> None:
        with folders(config=False, state=True) as root:
            (root / "config").write_text("oops")
            code, out, _ = run("doctor")
        self.assertEqual(code, 1)
        self.assertIn("is a file, not a folder", out)
        self.assertIn("Found 1 problem to fix.", out)

    def test_old_python_fails_with_a_fix(self) -> None:
        check = cli.check_python((3, 10, 4))
        self.assertEqual(check.status, cli.FAIL)
        self.assertIn("too old", check.summary)
        self.assertIsNotNone(check.fix)
        old = (3, 9, 1, "final", 0)
        with (
            folders(config=True, state=True),
            mock.patch.object(sys, "version_info", old),
        ):
            code, out, _ = run("doctor")
        self.assertEqual(code, 1)
        self.assertIn("Python 3.9.1 is too old", out)

    def test_new_enough_python_passes(self) -> None:
        for version in [(3, 11, 0), (3, 12, 7), (4, 0, 0)]:
            with self.subTest(version=version):
                self.assertEqual(cli.check_python(version).status, cli.OK)

    def test_json_output(self) -> None:
        with folders(config=True, state=False):
            code, out, _ = run("doctor", "--json")
        self.assertEqual(code, 0)
        data: dict[str, Any] = json.loads(out)
        self.assertEqual(data["schema"], 2)
        self.assertTrue(data["ok"])
        ids = [check["id"] for check in data["checks"]]
        self.assertEqual(ids, ["python", "config_dir", "state_dir"])
        statuses = {check["id"]: check["status"] for check in data["checks"]}
        self.assertEqual(statuses["config_dir"], "ok")
        self.assertEqual(statuses["state_dir"], "warn")

    def test_json_flag_works_before_the_command_too(self) -> None:
        with folders(config=True, state=True):
            _, after, _ = run("doctor", "--json")
            _, before, _ = run("--json", "doctor")
        self.assertEqual(after, before)

    def test_json_failure_sets_ok_false_and_exit_code(self) -> None:
        with folders(config=False, state=True) as root:
            (root / "config").write_text("oops")
            code, out, _ = run("doctor", "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])

    def test_json_output_is_deterministic_and_sorted(self) -> None:
        with folders(config=True, state=True):
            _, first, _ = run("doctor", "--json")
            _, second, _ = run("doctor", "--json")
        self.assertEqual(first, second)
        data = json.loads(first)
        self.assertEqual(first, json.dumps(data, sort_keys=True, indent=2) + "\n")

    def test_doctor_creates_nothing(self) -> None:
        with folders(config=False, state=False) as root:
            run("doctor")
            self.assertFalse((root / "config").exists())
            self.assertFalse((root / "state").exists())

    def test_output_hides_the_home_folder(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            env = {"HOME": home, "HC2_CONFIG_DIR": "", "HC2_STATE_DIR": ""}
            with mock.patch.dict(os.environ, env):
                _, out, _ = run("doctor")
        self.assertNotIn(home, out)
        self.assertIn("~/.config/ai-hc2", out)


class MisuseTests(unittest.TestCase):
    def test_no_command_prints_help_and_exits_2(self) -> None:
        code, out, err = run()
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("doctor", err)

    def test_no_command_with_json_prints_an_error_object(self) -> None:
        code, out, _ = run("--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"], "No command given.")

    def test_unknown_command_exits_2(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.main(["frobnicate"])
        self.assertEqual(caught.exception.code, 2)


class ModuleEntryTests(unittest.TestCase):
    def test_python_dash_m_hc2_runs_main(self) -> None:
        out = io.StringIO()
        argv = mock.patch.object(sys, "argv", ["hc2", "--version"])
        with (
            argv,
            contextlib.redirect_stdout(out),
            self.assertRaises(SystemExit) as caught,
        ):
            runpy.run_module("hc2", run_name="__main__")
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(out.getvalue(), f"hc2 {__version__}\n")


if __name__ == "__main__":
    unittest.main()
