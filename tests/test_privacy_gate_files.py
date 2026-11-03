"""Tests for scripts/privacy_gate.py: which files it reads, and the staged copy.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

from privacy_gate_helpers import AT, DENYLIST, gate, run_gate, setup_repo


class ScanFilesTests(unittest.TestCase):
    """Which files the gate reads, and how it decodes them."""

    def scan(
        self, files: dict[str, bytes], sizes: dict[str, int] | None = None
    ) -> tuple[list[tuple[str, int]], int, int, str]:
        terms = gate.parse_terms(DENYLIST)
        sizes = sizes or {name: len(data) for name, data in files.items()}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            hits, scanned, skipped = gate.scan_files(sizes, files.__getitem__, terms)
        return [(h.path, h.line) for h in hits], scanned, skipped, err.getvalue()

    def test_a_file_over_5_million_bytes_is_skipped_and_the_rest_are_scanned(
        self,
    ) -> None:
        files = {"a.txt": b"zorblax\n", "b.txt": b"ok\nzorblax\n", "c.txt": b"zorblax"}
        sizes = {"a.txt": 5_000_001, "b.txt": 11, "c.txt": 5_000_001}
        hits, scanned, skipped, err = self.scan(files, sizes)
        self.assertEqual(hits, [("b.txt", 2)])
        self.assertEqual((scanned, skipped), (1, 2))
        self.assertIn("a.txt", err)

    def test_a_file_of_exactly_5_million_bytes_is_scanned(self) -> None:
        hits, scanned, skipped, _ = self.scan(
            {"a.txt": b"zorblax\n"}, {"a.txt": 5_000_000}
        )
        self.assertEqual((hits, scanned, skipped), ([("a.txt", 1)], 1, 0))

    def test_only_a_nul_in_the_first_8192_bytes_makes_a_file_binary(self) -> None:
        files = {
            "in.txt": b"x" * 8191 + b"\0 zorblax",
            "in2.txt": b"\0 zorblax",
            "out.txt": b"x" * 8192 + b"\0 zorblax",
        }
        hits, scanned, skipped, _ = self.scan(files)
        self.assertEqual((hits, scanned, skipped), ([("out.txt", 1)], 1, 2))

    def test_bytes_that_are_not_utf8_do_not_stop_the_scan(self) -> None:
        hits, scanned, _, _ = self.scan({"a.txt": b"caf\xe9 zorblax\n"})
        self.assertEqual((hits, scanned), ([("a.txt", 1)], 1))


class StagedFilesTests(unittest.TestCase):
    def git(self, root: Path, *argv: str) -> None:
        subprocess.run(["git", "-C", str(root), *argv], check=True, capture_output=True)

    def test_every_staged_file_is_read_in_full(self) -> None:
        sub = f"160000,{'1' * 40},sub"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.git(root, "init", "-q")
            (root / "a.md").write_text("zorblax first\n")
            (root / "empty.md").write_text("")
            (root / "with\ttab.md").write_text("Quentin Example\nand more\n")
            (root / "link.md").symlink_to("a.md")
            self.git(root, "add", ".")
            self.git(root, "update-index", "--add", "--cacheinfo", sub)
            staged = gate.staged_files(root)
        self.assertEqual(
            staged,
            {
                "a.md": b"zorblax first\n",
                "empty.md": b"",
                "link.md": b"a.md",
                "with\ttab.md": b"Quentin Example\nand more\n",
            },
        )


class StagedCommandTests(unittest.TestCase):
    def test_staged_runs_the_generic_checks_too(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, f"jane{AT}corp.org\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "notes.md"], check=True)
            args = ("--root", str(root), "--denylist", str(deny), "--staged")
            code, out, _ = run_gate(*args)
        self.assertEqual((code, out), (1, "notes.md:1 email\n"))

    def test_staged_with_a_broken_index_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, f"jane{AT}corp.org\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "notes.md"], check=True)
            (root / ".git" / "index").write_bytes(b"garbage")
            args = ("--root", str(root), "--denylist", str(deny), "--staged")
            code, out, _ = run_gate(*args)
        self.assertEqual((code, out), (2, ""))


if __name__ == "__main__":
    unittest.main()
