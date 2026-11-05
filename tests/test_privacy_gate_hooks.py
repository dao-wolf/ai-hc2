"""Tests for the git hooks that scripts/install-hooks.sh writes.

A hook that finds no deny-list must stop the commit, not wave it through. A
contributor with no deny-list can choose the generic-only hooks on purpose.
Made-up data only.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from privacy_gate_helpers import HookRepoTestCase

PLAN = "the zorblax plan\n"


class HookWithoutDenylistTests(HookRepoTestCase):
    def commit_plan(self, *extra: str) -> tuple[int, str]:
        self.notes.write_text(PLAN)
        self.run_in_repo("git", "add", "notes.md")
        return self.run_in_repo("git", "commit", "-m", "docs: add notes", *extra)

    def lose_the_denylist(self, how: str) -> None:
        if how == "missing":
            self.env["HC2_PRIVACY_DENYLIST"] = str(self.denylist.parent / "nope.txt")
        elif how == "folder":
            self.env["HC2_PRIVACY_DENYLIST"] = str(self.denylist.parent)
        else:
            self.denylist.write_text("# no terms yet\n")

    def test_the_pre_commit_hook_stops_a_commit_when_the_denylist_is_unusable(
        self,
    ) -> None:
        for how in ("missing", "folder", "empty"):
            with self.subTest(how=how):
                self.setUp()
                self.assertEqual(self.install()[0], 0)
                self.lose_the_denylist(how)
                code, output = self.commit_plan()
                self.assertNotEqual(code, 0, output)
                self.assertNotIn("zorblax", output.lower())

    def test_the_commit_msg_hook_stops_a_message_when_the_denylist_is_missing(
        self,
    ) -> None:
        self.assertEqual(self.install()[0], 0)
        self.lose_the_denylist("missing")
        message = self.root / "msg.txt"
        message.write_text("docs: add notes\n")
        code, output = self.run_in_repo(".git/hooks/commit-msg", str(message))
        self.assertEqual(code, 2, output)
        self.assertIn("deny-list file not found", output)

    def test_a_commit_made_with_the_all_flag_is_checked_too(self) -> None:
        self.notes.write_text("fine\n")
        self.run_in_repo("git", "add", "notes.md")
        self.run_in_repo("git", "commit", "-q", "-m", "docs: add notes")
        self.assertEqual(self.install()[0], 0)
        self.notes.write_text(PLAN)
        code, output = self.run_in_repo("git", "commit", "-a", "-m", "docs: edit")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 term#2", output)

    def test_the_install_says_what_to_do_without_a_denylist(self) -> None:
        code, output = self.install()
        self.assertEqual(code, 0)
        self.assertIn("make hooks GENERIC_ONLY=1", output)


class GenericOnlyHookTests(HookRepoTestCase):
    def test_the_opt_out_says_plainly_what_it_turns_off(self) -> None:
        code, output = self.install("--generic-only")
        self.assertEqual(code, 0)
        self.assertIn("deny-list is not checked", output)

    def test_the_opt_out_lets_a_commit_through_without_a_denylist_and_says_so(
        self,
    ) -> None:
        self.assertEqual(self.install("--generic-only")[0], 0)
        self.env["HC2_PRIVACY_DENYLIST"] = str(Path(self.root) / "nope.txt")
        self.notes.write_text("all good\n")
        self.run_in_repo("git", "add", "notes.md")
        code, output = self.run_in_repo("git", "commit", "-m", "docs: add notes")
        self.assertEqual(code, 0, output)
        self.assertIn("generic checks only", output)

    def test_the_opt_out_still_blocks_a_generic_hit(self) -> None:
        self.assertEqual(self.install("--generic-only")[0], 0)
        self.notes.write_text("mail jane" + "@" + "corp.org\n")
        self.run_in_repo("git", "add", "notes.md")
        code, output = self.run_in_repo("git", "commit", "-m", "docs: add notes")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 email", output)

    def test_an_unknown_installer_option_is_refused(self) -> None:
        code, output = self.install("--nope")
        self.assertEqual(code, 2)
        self.assertIn("usage", output)
        self.assertFalse((self.root / ".git" / "hooks" / "pre-commit").exists())

    def test_running_the_installer_again_switches_the_mode(self) -> None:
        self.assertEqual(self.install("--generic-only")[0], 0)
        self.assertEqual(self.install()[0], 0)
        hook = (self.root / ".git" / "hooks" / "pre-commit").read_text()
        self.assertIn("--require-denylist", hook)
        self.assertNotIn("--generic-only", hook)


if __name__ == "__main__":
    unittest.main()
