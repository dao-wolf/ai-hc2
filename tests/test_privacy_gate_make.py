"""Tests for the make targets that run the privacy gate: `hooks` and `privacy`.

They run the real Makefile in a throwaway repo. Made-up data only.
"""

from __future__ import annotations

from pathlib import Path

from privacy_gate_helpers import HookRepoTestCase


class MakeHooksTests(HookRepoTestCase):
    def hook(self, name: str = "pre-commit") -> str:
        return (self.root / ".git" / "hooks" / name).read_text()

    def test_make_hooks_installs_the_strict_hooks(self) -> None:
        code, output = self.make("hooks")
        self.assertEqual(code, 0, output)
        for name in ("pre-commit", "commit-msg", "pre-push"):
            with self.subTest(hook=name):
                self.assertIn("--require-denylist", self.hook(name))
                self.assertNotIn("--generic-only", self.hook(name))

    def test_generic_only_1_installs_the_opt_out_hooks(self) -> None:
        code, output = self.make("hooks", "GENERIC_ONLY=1")
        self.assertEqual(code, 0, output)
        self.assertIn("deny-list is not checked", output)
        for name in ("pre-commit", "commit-msg", "pre-push"):
            with self.subTest(hook=name):
                self.assertIn("--generic-only", self.hook(name))
                self.assertNotIn("--require-denylist", self.hook(name))

    def test_any_other_value_leaves_the_strict_hooks_in_place(self) -> None:
        for value in ("0", "no", "false", "", "yes"):
            with self.subTest(value=value):
                code, output = self.make("hooks", f"GENERIC_ONLY={value}")
                self.assertEqual(code, 0, output)
                self.assertIn("--require-denylist", self.hook())
                self.assertNotIn("--generic-only", self.hook())


class MakePrivacyTests(HookRepoTestCase):
    def commits(self, *bodies: str) -> None:
        for number, body in enumerate(bodies):
            self.notes.write_text(body)
            self.run_in_repo("git", "add", "-A")
            self.run_in_repo("git", "commit", "-q", "-m", f"docs: change {number}")

    def lose_the_denylist(self) -> None:
        self.env["HC2_PRIVACY_DENYLIST"] = str(Path(self.root) / "nope.txt")

    def test_it_scans_the_whole_branch_not_only_the_tip(self) -> None:
        self.commits("fine\n", "the zorblax plan\n", "fine again\n")
        code, output = self.make("privacy", "RANGE=HEAD~2..HEAD")
        self.assertNotEqual(code, 0, output)
        self.assertIn("notes.md:1 term#2", output)

    def test_a_clean_branch_passes(self) -> None:
        self.commits("fine\n", "fine too\n")
        code, output = self.make("privacy", "RANGE=HEAD~1..HEAD")
        self.assertEqual(code, 0, output)

    def test_it_stops_when_the_denylist_is_missing_and_says_what_to_do(self) -> None:
        self.commits("fine\n", "fine too\n")
        self.lose_the_denylist()
        code, output = self.make("privacy", "RANGE=HEAD~1..HEAD")
        self.assertNotEqual(code, 0, output)
        self.assertIn("deny-list file not found", output)
        self.assertIn("make hooks GENERIC_ONLY=1", output)

    def test_generic_only_1_runs_it_without_a_denylist(self) -> None:
        self.commits("fine\n", "fine too\n")
        self.lose_the_denylist()
        code, output = self.make("privacy", "RANGE=HEAD~1..HEAD", "GENERIC_ONLY=1")
        self.assertEqual(code, 0, output)
        self.assertIn("generic checks only", output)

    def test_an_unknown_base_stops_it_instead_of_passing(self) -> None:
        self.commits("fine\n")
        code, output = self.make("privacy")
        self.assertNotEqual(code, 0, output)
