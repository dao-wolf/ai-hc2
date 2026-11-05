"""Tests for scripts/privacy_gate.py: files it cannot read as text, and odd names.

A file the gate skips is a file nobody checked. A file that is too large exits 2
unless --allow-skipped says the skip is fine. Made-up data only.
"""

from __future__ import annotations

import codecs
import contextlib
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import DENYLIST, gate, run_gate, setup_repo

SUMMARY_RE = re.compile(r"^privacy gate: scanned .*, \d+ hits\.$", re.MULTILINE)
LIMIT = 20
BIG = "x" * (LIMIT + 1)
ODD_NAME = os.fsdecode(b"a\xff.txt")


def run_small_limit(*argv: str) -> tuple[int, str, str]:
    with mock.patch.object(gate, "MAX_BYTES", LIMIT):
        return run_gate(*argv)


def stage(root: Path, *names: str) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", *names], check=True)


class OversizeFileTests(unittest.TestCase):
    def run_with(self, files: dict[str, str], *extra: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "fine\n")
            for name, body in files.items():
                (root / name).write_text(body)
            return run_small_limit("--root", str(root), "--denylist", str(deny), *extra)

    def test_a_file_that_is_too_large_to_scan_exits_2_and_is_named(self) -> None:
        code, out, err = self.run_with({"big.txt": BIG})
        self.assertEqual((code, out), (2, ""))
        self.assertIn("big.txt", err)
        self.assertIn("--allow-skipped", err)
        self.assertNotRegex(err, SUMMARY_RE)

    def test_every_file_that_is_too_large_is_named(self) -> None:
        code, _, err = self.run_with({"big1.txt": BIG, "big2.txt": BIG})
        self.assertEqual(code, 2)
        self.assertIn("big1.txt", err)
        self.assertIn("big2.txt", err)

    def test_allow_skipped_turns_the_failure_into_a_notice(self) -> None:
        code, out, err = self.run_with({"big.txt": BIG}, "--allow-skipped")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("big.txt", err)
        self.assertRegex(err, SUMMARY_RE)
        self.assertIn("skipped 1", err)

    def test_hits_in_the_other_files_still_exit_1(self) -> None:
        code, out, err = self.run_with({"big.txt": BIG, "leak.txt": "zorblax\n"})
        self.assertEqual(code, 1)
        self.assertIn("leak.txt:1", out)
        self.assertIn("big.txt", err)

    def test_a_staged_file_that_is_too_large_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, BIG)
            stage(root, "notes.md")
            code, out, err = run_small_limit(
                "--root", str(root), "--denylist", str(deny), "--staged"
            )
        self.assertEqual((code, out), (2, ""))
        self.assertIn("notes.md", err)

    def test_a_file_of_exactly_the_limit_is_scanned(self) -> None:
        code, _, err = self.run_with({"edge.txt": "x" * LIMIT})
        self.assertEqual(code, 0)
        self.assertIn("skipped 0", err)


class BinaryFileTests(unittest.TestCase):
    def test_a_file_with_a_nul_byte_is_a_quiet_count_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "fine\n")
            (root / "image.bin").write_bytes(b"\0\1\2 zorblax")
            code, out, err = run_gate("--root", str(root), "--denylist", str(deny))
        self.assertEqual((code, out), (0, ""))
        self.assertIn("skipped 1", err)
        self.assertNotIn("image.bin", err)


class Utf16FileTests(unittest.TestCase):
    def scan(self, data: bytes) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "fine\n")
            (root / "wide.txt").write_bytes(data)
            return run_gate("--root", str(root), "--denylist", str(deny))

    def test_utf16_with_a_byte_order_mark_is_scanned(self) -> None:
        little = codecs.BOM_UTF16_LE + "ok\nzorblax\n".encode("utf-16-le")
        big = codecs.BOM_UTF16_BE + "ok\nzorblax\n".encode("utf-16-be")
        for data in (little, big):
            with self.subTest(bom=data[:2]):
                code, out, err = self.scan(data)
                self.assertEqual(code, 1)
                self.assertIn("wide.txt:2", out)
                self.assertIn("skipped 0", err)

    def test_clean_utf16_is_scanned_and_passes(self) -> None:
        code, _, err = self.scan(codecs.BOM_UTF16_LE + "all good\n".encode("utf-16-le"))
        self.assertEqual(code, 0)
        self.assertIn("scanned 2 files, skipped 0", err)

    def test_utf16_without_a_mark_stays_a_binary_file(self) -> None:
        code, _, err = self.scan("zorblax\n".encode("utf-16-le"))
        self.assertEqual(code, 0)
        self.assertIn("skipped 1", err)


class OddFileNameTests(unittest.TestCase):
    def test_a_name_that_is_not_utf8_keeps_its_bytes(self) -> None:
        listing = subprocess.CompletedProcess([], 0, stdout=b"ok.txt\0a\xff.txt\0")
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(gate.subprocess, "run", return_value=listing),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(Path, "is_symlink", return_value=False),
        ):
            names = gate.list_files(Path(tmp))
        self.assertEqual([os.fsencode(n) for n in names], [b"a\xff.txt", b"ok.txt"])

    def test_two_staged_names_that_differ_only_in_a_bad_byte_are_both_scanned(
        self,
    ) -> None:
        terms = gate.parse_terms(DENYLIST)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            blob = subprocess.run(
                ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
                input=b"zorblax\n",
                capture_output=True,
                check=True,
            ).stdout.strip()
            for name in (b"a\xff.txt", b"a\xfe.txt"):
                cache = b"100644," + blob + b"," + name
                command = [b"git", b"-C", os.fsencode(root)]
                command += [b"update-index", b"--add", b"--cacheinfo", cache]
                subprocess.run(command, check=True)
            result = gate.scan_index(root, terms)
        self.assertEqual(
            sorted(os.fsencode(h.path) for h in result.hits),
            [b"a\xfe.txt", b"a\xff.txt"],
        )

    def test_a_hit_in_such_a_file_is_printed_with_the_bad_byte_escaped(self) -> None:
        self.assertEqual(str(gate.Hit(ODD_NAME, 3, "term#1")), "a\\xff.txt:3 term#1")

    def test_a_terminal_that_cannot_show_the_byte_does_not_stop_the_report(
        self,
    ) -> None:
        strict = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
        found = ([gate.Hit(ODD_NAME, 1, "term#1")], "scanned 1 files, skipped 0", [])
        with tempfile.TemporaryDirectory() as tmp:
            _, deny = setup_repo(tmp, "fine\n")
            with (
                mock.patch.object(gate, "scan_source", return_value=found),
                contextlib.redirect_stdout(strict),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = gate.main(["--denylist", str(deny)])
            strict.flush()
            shown = strict.buffer.getvalue()  # type: ignore[attr-defined]
        self.assertEqual(code, 1)
        self.assertIn(b"a\\xff.txt:1", shown)


if __name__ == "__main__":
    unittest.main()
