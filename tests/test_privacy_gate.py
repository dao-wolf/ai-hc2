"""Tests for scripts/privacy_gate.py, using a made-up deny-list.

Strings that the gate would flag are built from pieces, so this file does not
trip the gate itself.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy_gate_helpers import (
    AT,
    DENYLIST,
    HOME,
    USERS,
    HookRepoTestCase,
    gate,
    labels,
    run_gate,
    setup_repo,
)


class TermMatchingTests(unittest.TestCase):
    def test_comments_and_blank_lines_are_skipped(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        self.assertEqual([t.number for t in terms], [2, 4, 5, 6])

    def test_a_first_term_that_starts_with_x_still_matches(self) -> None:
        terms = gate.parse_terms("Xample Person\nZorblax\n")
        self.assertEqual([t.number for t in terms], [1, 2])
        self.assertTrue(terms[0].pattern.search("thank Xample Person for the review"))

    def test_words_match_whole_words_only(self) -> None:
        self.assertEqual(labels("a Zorblax here", generic=False), ["term#2"])
        self.assertEqual(labels("ZORBLAX", generic=False), ["term#2"])
        self.assertEqual(labels("(zorblax)", generic=False), ["term#2"])
        self.assertEqual(labels("zorblax_tool", generic=False), ["term#2"])
        self.assertEqual(labels("Zorblaxes and xzorblax", generic=False), [])

    def test_a_short_word_does_not_match_inside_a_longer_one(self) -> None:
        terms = gate.parse_terms("Sam\n")
        for text in ["sample", "Sample list", "wisam"]:
            with self.subTest(text=text):
                self.assertEqual(gate.scan_text("f", text, terms), [])
        self.assertEqual(len(gate.scan_text("f", "the Sam band", terms)), 1)

    def test_digits_count_as_word_characters(self) -> None:
        terms = gate.parse_terms("abc\n")
        self.assertEqual(gate.scan_text("f", "abc1", terms), [])
        self.assertEqual(len(gate.scan_text("f", "abc 1", terms)), 1)

    def test_terms_with_punctuation_match_as_substrings(self) -> None:
        self.assertEqual(labels("see ACME-SECRET/readme", generic=False), ["term#4"])
        self.assertEqual(labels("xxfoo.barxx", generic=False), ["term#5"])
        self.assertEqual(labels("foo-bar", generic=False), [])

    def test_phrases_match_whole_words_across_spacing(self) -> None:
        self.assertEqual(labels("quentin   example", generic=False), ["term#6"])
        self.assertEqual(labels("Quentin Examples", generic=False), [])

    def test_space_hyphen_and_underscore_are_one_separator(self) -> None:
        terms = gate.parse_terms("example-project\nExample Person\n")
        for text, label in [
            ("Example Project", "term#1"),
            ("example_project", "term#1"),
            ("xexample-projectx", "term#1"),
            ("example-person", "term#2"),
            ("Example_Person", "term#2"),
            ("example - person", "term#2"),
        ]:
            with self.subTest(text=text):
                found = gate.scan_text("f", text, terms)
                self.assertEqual([h.label for h in found], [label])

    def test_a_term_wrapped_onto_the_next_line_is_reported_where_it_starts(
        self,
    ) -> None:
        terms = gate.parse_terms(DENYLIST)
        text = "ok\nsigned, Quentin\n  Example\nsee acme-\nsecret/x\n"
        hits = gate.scan_text("a.md", text, terms)
        found = [(h.line, h.label) for h in hits]
        self.assertEqual(found, [(2, "term#6"), (4, "term#4")])

    def test_a_wrapped_match_does_not_hide_one_on_the_next_line(self) -> None:
        terms = gate.parse_terms("Ab Ab\n")
        hits = gate.scan_text("f", "Ab\nAb Ab\n", terms)
        self.assertEqual([h.line for h in hits], [1, 2])

    def test_a_separator_at_either_end_of_a_term_stays_literal(self) -> None:
        terms = gate.parse_terms("-zz\nyy_\n")
        self.assertEqual(len(gate.scan_text("f", "x-zz yy_x", terms)), 2)
        self.assertEqual(gate.scan_text("f", "x zz yy-x", terms), [])

    def test_line_numbers_are_reported(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        hits = gate.scan_text("a.md", "ok\nok\nzorblax\n", terms)
        self.assertEqual([(h.line, h.label) for h in hits], [(3, "term#2")])

    def test_file_names_are_checked_at_line_zero(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        hits = gate.scan_name("docs/zorblax-notes.md", terms)
        self.assertEqual([(h.line, h.label) for h in hits], [(0, "term#2")])

    def test_a_slash_or_dot_between_a_terms_words_is_a_separator_in_a_name(
        self,
    ) -> None:
        terms = gate.parse_terms(DENYLIST)
        for name in (
            "docs/quentin/example.md",
            "docs/quentin.example.md",
            "quentin/-example/x",
            "docs/quentin_example/x",
            "docs/Quentin Example.md",
        ):
            with self.subTest(name):
                self.assertEqual(
                    [(h.line, h.label) for h in gate.scan_name(name, terms)],
                    [(0, "term#6")],
                )

    def test_a_name_that_only_looks_close_is_not_a_hit(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        for name in (
            "docs/quentinexample.md",
            "docs/quentin/x/example.md",
            "docs/xquentin/example.md",
            "docs/quentin/examples.md",
        ):
            with self.subTest(name):
                self.assertEqual(gate.scan_name(name, terms), [])

    def test_a_slash_or_dot_is_not_a_separator_in_text(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        self.assertEqual(gate.scan_text("a.md", "quentin/example\n", terms), [])
        self.assertEqual(gate.scan_text("a.md", "quentin.example\n", terms), [])

    def test_a_byte_order_mark_is_ignored(self) -> None:
        terms = gate.parse_terms("﻿Zorblax\n")
        self.assertEqual(len(gate.scan_text("f", "zorblax", terms)), 1)


class GenericCheckTests(unittest.TestCase):
    def test_emails_are_flagged(self) -> None:
        self.assertEqual(labels(f"mail jane{AT}corp.org now"), ["email"])
        self.assertEqual(labels(f"jane.doe+x{AT}mail.co.uk"), ["email"])

    def test_allowed_emails_pass(self) -> None:
        allowed = [
            f"noreply{AT}anthropic.com",
            f"NoReply{AT}corp.org",
            f"no-reply{AT}corp.org",
            f"alice{AT}example.com",
            f"alice{AT}mail.example.com",
            f"12345+alice{AT}users.noreply.github.com",
            f"git{AT}github.com",
            f"support{AT}github.com",
        ]
        for text in allowed:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])

    def test_lookalike_domains_are_flagged(self) -> None:
        self.assertEqual(labels(f"a{AT}example.com.evil.org"), ["email"])
        self.assertEqual(labels(f"a{AT}notexample.com"), ["email"])

    def test_only_git_at_github_is_the_github_exception(self) -> None:
        for text in [
            f"alice{AT}github.com",
            f"zed{AT}github.com",
            f"git{AT}gitlab.com",
            f"git{AT}example.org",
            f"support{AT}gitlab.com",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), ["email"])

    def test_version_pins_are_not_emails(self) -> None:
        self.assertEqual(labels("uses: actions/checkout" + AT + "v7.0.1"), [])
        self.assertEqual(labels("pkg" + AT + "1.2.3"), [])

    def test_home_paths_are_flagged(self) -> None:
        for text in [
            f"{USERS}zed/Documents",
            f"cd {HOME}zed/project",
            f'"{USERS}zed"',
            f"file://{USERS}zed/x",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), ["home-path"])

    def test_made_up_home_paths_pass(self) -> None:
        for text in [
            f"{HOME}alice/example-project",
            f"{USERS}Bob/x",
            f"{HOME}runner/work",
            f"{USERS}<name>/x",
            f"{HOME}$USER/x",
            "https://example.com" + HOME + "zed",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])

    def test_secrets_are_flagged_by_kind(self) -> None:
        aws = "AKIA" + "ABCDEFGHIJKLMNOP"
        gh = "ghp_" + "a" * 36
        pat = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1"
        key = "-----BEGIN " + "RSA PRIVATE KEY-----"
        key2 = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertEqual(labels(f"id={aws}"), ["secret:aws-access-key-id"])
        self.assertEqual(labels(f"t={gh}"), ["secret:github-token"])
        self.assertEqual(labels(f"t={pat}"), ["secret:github-token"])
        self.assertEqual(labels(key), ["secret:private-key"])
        self.assertEqual(labels(key2), ["secret:private-key"])

    def test_near_misses_are_not_secrets(self) -> None:
        self.assertEqual(labels("AKIA" + "SHORT"), [])
        self.assertEqual(labels("ghp_" + "a" * 10), [])
        self.assertEqual(labels("-----BEGIN " + "CERTIFICATE-----"), [])

    def test_generic_checks_can_be_turned_off(self) -> None:
        self.assertEqual(labels(f"jane{AT}corp.org", generic=False), [])

    def test_hits_are_reported_once_per_line_and_label(self) -> None:
        text = f"a{AT}b.org c{AT}d.org"
        self.assertEqual(labels(text), ["email"])


class TreeScanTests(unittest.TestCase):
    def make_tree(self, root: Path) -> None:
        (root / "docs").mkdir()
        (root / "docs" / "clean.md").write_text("Nothing to see.\n")
        (root / "docs" / "leak.md").write_text("fine\nthe zorblax project\n")
        (root / "image.bin").write_bytes(b"\0\1\2 zorblax")
        (root / "zorblax-name.txt").write_text("harmless text")
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("zorblax")

    def test_walk_scans_text_skips_binary_and_dot_git(self) -> None:
        terms = gate.parse_terms(DENYLIST)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_tree(root)
            with mock.patch.object(gate.subprocess, "run", side_effect=OSError):
                result = gate.scan_tree(root, terms)
        self.assertEqual(
            [(h.path, h.line, h.label) for h in result.hits],
            [("docs/leak.md", 2, "term#2"), ("zorblax-name.txt", 0, "term#2")],
        )
        self.assertEqual((result.scanned, result.binary), (3, 1))

    def test_git_listing_includes_untracked_and_honours_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("ignored.txt\n")
            (root / "tracked.txt").write_text("a")
            (root / "untracked.txt").write_text("b")
            (root / "ignored.txt").write_text("zorblax")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            files = gate.list_files(root)
        self.assertEqual(files, [".gitignore", "tracked.txt", "untracked.txt"])

    def test_tracked_but_deleted_files_and_links_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real.txt").write_text("x")
            (root / "link.txt").symlink_to(root / "real.txt")
            with mock.patch.object(gate.subprocess, "run", side_effect=OSError):
                self.assertEqual(gate.list_files(root), ["real.txt"])


class IdentityTests(unittest.TestCase):
    """The name and email git will put on a commit are checked too."""

    def scan(self, author: str, email: str) -> list[tuple[str, int, str]]:
        terms = gate.parse_terms(DENYLIST)
        env = {
            "GIT_AUTHOR_NAME": author,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": "example-handle",
            "GIT_COMMITTER_EMAIL": "1+example-handle" + AT + "users.noreply.github.com",
        }
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            with mock.patch.dict(os.environ, env):
                hits = gate.scan_identity(Path(tmp), terms)
        return [(h.path, h.line, h.label) for h in hits]

    def test_a_real_name_in_the_author_is_a_hit(self) -> None:
        noreply = "1+q" + AT + "users.noreply.github.com"
        self.assertEqual(
            self.scan("Quentin Example", noreply), [("<git author>", 1, "term#6")]
        )

    def test_a_personal_email_in_the_author_is_a_hit(self) -> None:
        found = self.scan("example-handle", "quentin" + AT + "mail.example.org")
        self.assertEqual(found, [("<git author>", 1, "email")])

    def test_a_handle_and_noreply_email_are_clean(self) -> None:
        noreply = "1+example-handle" + AT + "users.noreply.github.com"
        self.assertEqual(self.scan("example-handle", noreply), [])


class CommandLineTests(unittest.TestCase):
    def test_clean_repo_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "all good\n")
            args = ("--root", str(root), "--denylist", str(deny))
            code, out, err = run_gate(*args)
        self.assertEqual((code, out), (0, ""))
        self.assertIn("4 deny-list terms loaded", err)
        self.assertIn("0 hits", err)

    def test_hit_exits_1_and_never_prints_the_term(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "ok\nQuentin Example was here\n")
            args = ("--root", str(root), "--denylist", str(deny))
            code, out, err = run_gate(*args)
        self.assertEqual(code, 1)
        self.assertEqual(out, "notes.md:2 term#6\n")
        for secret in ["quentin", "zorblax", "acme", "foo.bar"]:
            self.assertNotIn(secret, (out + err).lower())

    def test_generic_hits_never_print_the_matched_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, f"jane{AT}corp.org\n{USERS}zed/x\n")
            args = ("--root", str(root), "--denylist", str(deny))
            code, out, err = run_gate(*args)
        self.assertEqual(code, 1)
        self.assertEqual(out, "notes.md:1 email\nnotes.md:2 home-path\n")
        self.assertNotIn("corp", out + err)
        self.assertNotIn("zed", out + err)

    def test_environment_variable_selects_the_denylist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "zorblax\n")
            code, out, _ = run_gate(
                "--root", str(root), env={"HC2_PRIVACY_DENYLIST": str(deny)}
            )
        self.assertEqual((code, out), (1, "notes.md:1 term#2\n"))

    def test_missing_denylist_runs_generic_checks_with_a_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = setup_repo(tmp, "zorblax\n")
            missing = str(Path(tmp) / "nope.txt")
            code, out, err = run_gate("--root", str(root), "--denylist", missing)
        self.assertEqual((code, out), (0, ""))
        self.assertIn("NOTICE", err)

    def test_missing_denylist_can_be_made_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = setup_repo(tmp, "x\n")
            missing = str(Path(tmp) / "nope.txt")
            code, out, err = run_gate(
                "--root", str(root), "--denylist", missing, "--require-denylist"
            )
        self.assertEqual((code, out), (2, ""))
        self.assertIn("not found", err)

    def test_generic_only_ignores_the_denylist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "zorblax\n")
            code, _, err = run_gate(
                "--root", str(root), "--denylist", str(deny), "--generic-only"
            )
        self.assertEqual(code, 0)
        self.assertIn("generic checks only", err)

    def test_staged_scans_what_the_commit_will_hold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "the zorblax plan\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "notes.md"], check=True)
            (root / "notes.md").write_text("clean now\n")
            (root / "draft.md").write_text("zorblax\n")
            args = ("--root", str(root), "--denylist", str(deny))
            on_disk = run_gate(*args)[:2]
            staged = run_gate(*args, "--staged")[:2]
        self.assertEqual(on_disk, (1, "draft.md:1 term#2\n"))
        self.assertEqual(staged, (1, "notes.md:1 term#2\n"))

    def test_staged_outside_a_repository_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "x\n")
            args = ("--root", str(root), "--denylist", str(deny), "--staged")
            code, out, err = run_gate(*args, env={"GIT_CEILING_DIRECTORIES": tmp})
        self.assertEqual((code, out), (2, ""))
        self.assertIn("could not read", err)

    def test_message_scans_only_the_commit_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, deny = setup_repo(tmp, "zorblax\n")
            message = Path(tmp) / "COMMIT_EDITMSG"
            message.write_text(f"fix: thank Quentin Example\n\nby jane{AT}corp.org\n")
            args = ("--root", str(root), "--denylist", str(deny))
            code, out, err = run_gate(*args, "--message", str(message))
        self.assertEqual(code, 1)
        self.assertEqual(out, "<commit message>:1 term#6\n<commit message>:3 email\n")
        for secret in ["quentin", "zorblax", "corp"]:
            self.assertNotIn(secret, (out + err).lower())

    def test_default_denylist_path(self) -> None:
        with mock.patch.dict(os.environ, {"HC2_PRIVACY_DENYLIST": ""}):
            path = gate.resolve_denylist(None)
        expected = Path("~/.config/ai-hc2/privacy-denylist.txt").expanduser()
        self.assertEqual(path, expected)

    def test_option_beats_environment(self) -> None:
        with mock.patch.dict(os.environ, {"HC2_PRIVACY_DENYLIST": "/from/env.txt"}):
            chosen = gate.resolve_denylist("/from/option.txt")
            self.assertEqual(chosen, Path("/from/option.txt"))
            self.assertEqual(gate.resolve_denylist(None), Path("/from/env.txt"))


class HookTests(HookRepoTestCase):
    """The hooks that scripts/install-hooks.sh writes, run by a real commit."""

    def test_install_keeps_a_foreign_hook_and_still_writes_the_other(self) -> None:
        foreign = self.root / ".git" / "hooks" / "commit-msg"
        foreign.parent.mkdir(exist_ok=True)
        foreign.write_text("#!/bin/sh\nexit 0\n")
        code, output = self.install()
        self.assertEqual(code, 1)
        self.assertIn("A different commit-msg hook already exists", output)
        self.assertEqual(foreign.read_text(), "#!/bin/sh\nexit 0\n")
        self.assertTrue((self.root / ".git" / "hooks" / "pre-commit").is_file())

    def test_pre_commit_blocks_a_term_in_the_staged_copy(self) -> None:
        self.assertEqual(self.install()[0], 0)
        self.notes.write_text("the zorblax plan\n")
        self.run_in_repo("git", "add", "notes.md")
        self.notes.write_text("clean now\n")
        code, output = self.run_in_repo("git", "commit", "-m", "docs: add notes")
        self.assertNotEqual(code, 0)
        self.assertIn("notes.md:1 term#2", output)

    def test_commit_msg_blocks_a_term_but_not_the_diff_below_the_scissors(
        self,
    ) -> None:
        self.notes.write_text("the zorblax plan\n")
        self.run_in_repo("git", "add", "notes.md")
        self.run_in_repo("git", "commit", "-q", "-m", "docs: add notes")
        self.assertEqual(self.install()[0], 0)
        self.notes.write_text("the plan\n")
        self.run_in_repo("git", "add", "notes.md")
        code, output = self.run_in_repo("git", "commit", "-m", "docs: drop Zorblax")
        self.assertNotEqual(code, 0)
        self.assertIn("<commit message>:1 term#2", output)
        # With -v the message file also holds the diff, which removes the term.
        verbose = ["git", "commit", "-v", "-e", "-m", "docs: drop the old name"]
        code, output = self.run_in_repo(*verbose)
        self.assertEqual(code, 0, output)


if __name__ == "__main__":
    unittest.main()
