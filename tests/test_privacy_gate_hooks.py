"""Tests for the git hooks that scripts/install-hooks.sh writes.

A hook that finds no deny-list must stop the commit, not wave it through. A
contributor with no deny-list can choose the generic-only hooks on purpose.
Made-up data only.
"""

from __future__ import annotations

import os
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


class PrePushHookTests(HookRepoTestCase):
    """Commits can reach a remote without the pre-commit hook: a cherry-pick, a
    merge, a commit made with --no-verify. The pre-push hook checks them last.
    """

    def commit(self, body: str, message: str = "docs: change") -> None:
        self.notes.write_text(body)
        self.run_in_repo("git", "add", "-A")
        code, output = self.run_in_repo(
            "git", "commit", "-q", "--no-verify", "--allow-empty", "-m", message
        )
        self.assertEqual(code, 0, output)

    def push(self, destination: str) -> tuple[int, str]:
        return self.run_in_repo("git", "push", "origin", f"HEAD:{destination}")

    def remote_has(self, branch: str) -> bool:
        _, listing = self.run_in_repo("git", "ls-remote", "--heads", "origin", branch)
        return branch in listing

    def start(self, first_body: str = "fine\n", *options: str) -> None:
        """Push a first commit to main, then install the hooks."""
        self.commit(first_body, "docs: first")
        bare = self.root.parent / "remote.git"
        self.run_in_repo("git", "init", "-q", "--bare", str(bare))
        self.run_in_repo("git", "remote", "add", "origin", str(bare))
        self.assertEqual(self.push("refs/heads/main")[0], 0)
        self.assertEqual(self.install(*options)[0], 0)

    def test_the_installer_writes_a_pre_push_hook_in_each_mode(self) -> None:
        hook = self.root / ".git" / "hooks" / "pre-push"
        code, output = self.install()
        self.assertEqual(code, 0)
        self.assertIn("Installed the privacy-gate pre-push hook.", output)
        self.assertIn("--pre-push --require-denylist", hook.read_text())
        self.assertEqual(self.install("--generic-only")[0], 0)
        self.assertIn("--pre-push --generic-only", hook.read_text())
        self.assertTrue(os.access(hook, os.X_OK))

    def test_a_term_added_then_removed_is_stopped_before_it_leaves(self) -> None:
        self.start()
        self.commit(PLAN)
        self.commit("fine\n")
        code, output = self.push("refs/heads/topic")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 term#2", output)
        self.assertFalse(self.remote_has("topic"))

    def test_a_term_in_a_commit_message_is_stopped(self) -> None:
        self.start()
        self.commit("fine\n", "docs: the zorblax plan")
        code, output = self.push("refs/heads/topic")
        self.assertNotEqual(code, 0, output)
        self.assertIn("<message>:1 term#2", output)

    def test_a_cherry_picked_leak_is_stopped(self) -> None:
        self.start()
        self.run_in_repo("git", "checkout", "-q", "-b", "side")
        self.commit(PLAN)
        self.run_in_repo("git", "checkout", "-q", "-")
        code, output = self.run_in_repo("git", "cherry-pick", "side")
        self.assertEqual(code, 0, output)
        code, output = self.push("refs/heads/main")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 term#2", output)

    def test_a_clean_push_goes_through_though_the_remote_holds_an_old_hit(
        self,
    ) -> None:
        self.start(PLAN)
        (self.root / "other.md").write_text("fine\n")
        self.run_in_repo("git", "add", "other.md")
        self.run_in_repo("git", "commit", "-q", "--no-verify", "-m", "docs: other")
        code, output = self.push("refs/heads/main")
        self.assertEqual(code, 0, output)

    def test_deleting_a_remote_branch_is_not_scanned(self) -> None:
        self.start()
        self.assertEqual(self.push("refs/heads/topic")[0], 0)
        code, output = self.run_in_repo("git", "push", "origin", ":topic")
        self.assertEqual(code, 0, output)

    def test_the_opt_out_hook_skips_the_denylist_but_not_the_generic_checks(
        self,
    ) -> None:
        self.start("fine\n", "--generic-only")
        self.commit(PLAN)
        code, output = self.push("refs/heads/topic")
        self.assertEqual(code, 0, output)
        self.assertIn("generic checks only", output)
        self.commit("mail jane" + "@" + "corp.org\n")
        code, output = self.push("refs/heads/topic")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 email", output)

    def test_without_a_denylist_the_hook_stops_the_push_and_says_what_to_do(
        self,
    ) -> None:
        self.start()
        self.commit("fine too\n")
        self.env["HC2_PRIVACY_DENYLIST"] = str(self.denylist.parent / "nope.txt")
        code, output = self.push("refs/heads/topic")
        self.assertNotEqual(code, 0, output)
        self.assertIn("deny-list file not found", output)
        self.assertIn("make hooks GENERIC_ONLY=1", output)
        self.assertFalse(self.remote_has("topic"))


if __name__ == "__main__":
    unittest.main()
