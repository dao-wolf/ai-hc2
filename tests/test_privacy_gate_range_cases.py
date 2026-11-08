"""Tests for scripts/privacy_gate.py: cases a range or push scan must get right.

Bot trailers and outside contributors must not fail a scan that is right to
pass, and a leak must not slip through a merge, a ref name, a tag or a match
that runs across an old line and a new one. Made-up data only.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
from unittest import mock

from privacy_gate_helpers import AT, DENYLIST, gate, run_gate
from test_privacy_gate_range import LIMIT, ZEROS, RangeRepoTestCase, short

OUTSIDE = "jane" + AT + "corp.org"
BOT_TRAILER = "Signed-off-by: dependabot[bot] <support" + AT + "github.com>"


class BotAndOutsideAuthorTests(RangeRepoTestCase):
    def test_a_bot_trailer_in_a_message_passes_the_generic_checks(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.commit({"a.md": "1\n"}, message=f"build: bump\n\n{BOT_TRAILER}")
        code, out, _ = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual((code, out), (0, ""))

    def test_only_that_one_support_address_is_allowed(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        trailer = "Signed-off-by: x <support" + AT + "gitlab.com>"
        leak = self.commit({"a.md": "1\n"}, message=f"build: bump\n\n{trailer}")
        code, out, _ = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:<message>:3 email"])

    def outside_author(self) -> tuple[str, str]:
        base = self.commit({"notes.md": "fine\n"})
        env = {"GIT_AUTHOR_EMAIL": OUTSIDE, "GIT_COMMITTER_EMAIL": OUTSIDE}
        return base, self.commit({"a.md": "1\n"}, extra_env=env)

    def test_an_outside_authors_email_is_a_hit_unless_trusted(self) -> None:
        base, commit = self.outside_author()
        code, out, _ = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(out.splitlines()),
            [
                f"{short(commit)}:<author>:1 email",
                f"{short(commit)}:<committer>:1 email",
            ],
        )

    def test_trusting_author_emails_skips_only_the_generic_email_check(self) -> None:
        base, _ = self.outside_author()
        code, out, err = self.scan_range(
            f"{base}..HEAD", "--generic-only", "--trust-author-emails"
        )
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 1 commits", err)

    def test_trusting_author_emails_still_checks_the_deny_list(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        env = {"GIT_AUTHOR_EMAIL": OUTSIDE, "GIT_AUTHOR_NAME": "Zorblax"}
        commit = self.commit({"a.md": "1\n"}, extra_env=env)
        code, out, _ = self.scan_range(f"{base}..HEAD", "--trust-author-emails")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(commit)}:<author>:1 term#2"])

    def test_trusting_author_emails_still_checks_a_key_or_home_path_in_a_name(
        self,
    ) -> None:
        base = self.commit({"notes.md": "fine\n"})
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        names = {
            "secret:aws-access-key-id": key,
            "home-path": "see /Users" + "/jane/work",
        }
        for label, name in names.items():
            with self.subTest(label=label):
                env = {"GIT_AUTHOR_NAME": name, "GIT_COMMITTER_NAME": "alice"}
                commit = self.commit({"a.md": f"{label}\n"}, extra_env=env)
                code, out, _ = self.scan_range(
                    f"{base}..HEAD", "--generic-only", "--trust-author-emails"
                )
                self.assertEqual(code, 1)
                self.assertEqual(
                    out.splitlines(), [f"{short(commit)}:<author>:1 {label}"]
                )
                self.git("reset", "-q", "--hard", base)

    def test_trusting_author_emails_leaves_the_message_checks_alone(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        message = f"docs: mail {OUTSIDE}"
        commit = self.commit({"a.md": "1\n"}, message=message)
        code, out, _ = self.scan_range(
            f"{base}..HEAD", "--generic-only", "--trust-author-emails"
        )
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(commit)}:<message>:1 email"])

    def test_the_option_needs_a_range_or_a_push(self) -> None:
        for other in ([], ["--staged"]):
            shown = io.StringIO()
            with (
                self.subTest(other=other),
                contextlib.redirect_stderr(shown),
                self.assertRaises(SystemExit) as raised,
            ):
                gate.main(self.arguments("--trust-author-emails", *other))
            self.assertEqual(raised.exception.code, 2)
            expected = "error: --trust-author-emails needs --range or --pre-push"
            lines = shown.getvalue().splitlines()
            self.assertTrue(any(line.endswith(expected) for line in lines))

    def test_the_option_is_accepted_with_a_push(self) -> None:
        self.commit({"notes.md": "fine\n"})
        stdin = io.StringIO("")
        with mock.patch.object(gate.sys, "stdin", stdin):
            code, out, _ = run_gate(
                *self.arguments("--pre-push", "--trust-author-emails")
            )
        self.assertEqual((code, out), (0, ""))


class MergeTests(RangeRepoTestCase):
    def two_branches(self) -> str:
        base = self.commit({"notes.md": "fine\n"})
        self.git("checkout", "-q", "-b", "side")
        self.commit({"side.md": "fine\n"})
        self.git("checkout", "-q", "main")
        self.commit({"main.md": "fine\n"})
        return base

    def test_a_term_added_only_by_the_merge_itself_is_found(self) -> None:
        base = self.two_branches()
        self.git("merge", "-q", "--no-commit", "--no-ff", "side")
        (self.root / "joined.md").write_text("fine\nthe zorblax plan\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "merge side")
        merge = self.git("rev-parse", "HEAD")
        self.assertEqual(self.scan_tip()[0], 1)
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(merge)}:joined.md:2 term#2"])

    def test_a_term_a_merge_adds_to_a_file_both_sides_changed_is_found(self) -> None:
        base = self.commit({"shared.md": "a\nb\n"})
        self.git("checkout", "-q", "-b", "side")
        self.commit({"shared.md": "a\nb\nside\n"})
        self.git("checkout", "-q", "main")
        self.commit({"shared.md": "main\na\nb\n"})
        self.git("merge", "-q", "--no-commit", "--no-ff", "side")
        (self.root / "shared.md").write_text("main\na\nb\nside\nzorblax\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "merge side")
        merge = self.git("rev-parse", "HEAD")
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(merge)}:shared.md:5 term#2"])

    def test_a_file_the_merge_takes_whole_from_one_side_is_not_new(self) -> None:
        self.commit({"notes.md": "fine\n"})
        legacy = self.commit({"shared.md": "zorblax long ago\n"})
        self.git("checkout", "-q", "-b", "side")
        self.commit({"side.md": "fine\n"})
        self.git("checkout", "-q", "main")
        self.commit({"shared.md": "fine\n"})
        self.git("merge", "-q", "--no-commit", "--no-ff", "side")
        self.git("checkout", "side", "--", "shared.md")
        self.git("commit", "-q", "-m", "merge side")
        code, out, _ = self.scan_range(f"{legacy}..HEAD")
        self.assertEqual((code, out), (0, ""))

    def test_a_line_either_parent_had_is_not_new_in_the_merge(self) -> None:
        legacy = self.commit({"shared.md": "zorblax long ago\nb\n"})
        self.git("checkout", "-q", "-b", "side")
        self.commit({"shared.md": "zorblax long ago\nb\nside\n"})
        self.git("checkout", "-q", "main")
        self.commit({"shared.md": "main\nzorblax long ago\nb\n"})
        self.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
        self.assertEqual(self.scan_tip()[0], 1)
        code, out, _ = self.scan_range(f"{legacy}..HEAD")
        self.assertEqual((code, out), (0, ""))

    def test_an_octopus_merge_is_compared_with_every_parent(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        for name in ("one", "two"):
            self.git("checkout", "-q", "-b", name, "main")
            self.commit({f"{name}.md": "fine\n"})
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-commit", "one", "two")
        (self.root / "joined.md").write_text("zorblax\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "merge both")
        merge = self.git("rev-parse", "HEAD")
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(merge)}:joined.md:1 term#2"])


class PushedRefTests(RangeRepoTestCase):
    def pre_push(self, *lines: str) -> tuple[int, str, str]:
        stdin = io.StringIO("".join(line + "\n" for line in lines))
        with mock.patch.object(gate.sys, "stdin", stdin):
            return run_gate(*self.arguments("--pre-push"))

    def clean_commit(self) -> str:
        base = self.commit({"notes.md": "fine\n"})
        self.git("update-ref", "refs/remotes/origin/main", base)
        return base

    def test_a_term_in_a_new_branch_name_is_found(self) -> None:
        head = self.clean_commit()
        ref = "refs/heads/zorblax-plan"
        code, out, _ = self.pre_push(f"{ref} {head} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<ref>:0 term#2"])

    def test_a_term_in_the_name_the_branch_gets_on_the_remote_is_found(self) -> None:
        head = self.clean_commit()
        line = f"refs/heads/topic {head} refs/heads/zorblax-plan {ZEROS}"
        code, out, _ = self.pre_push(line)
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<ref>:0 term#2"])

    def test_a_term_in_a_tag_name_is_found(self) -> None:
        head = self.clean_commit()
        ref = "refs/tags/zorblax-v1"
        code, out, _ = self.pre_push(f"{ref} {head} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<ref>:0 term#2"])

    def test_deleting_a_ref_with_a_term_in_its_name_scans_nothing(self) -> None:
        head = self.clean_commit()
        ref = "refs/heads/zorblax-plan"
        code, out, err = self.pre_push(f"(delete) {ZEROS} {ref} {head}")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)

    def test_a_clean_branch_name_passes(self) -> None:
        head = self.clean_commit()
        ref = "refs/heads/topic"
        code, out, _ = self.pre_push(f"{ref} {head} {ref} {ZEROS}")
        self.assertEqual((code, out), (0, ""))

    def tag(self, name: str, message: str, target: str = "HEAD", **env: str) -> str:
        self.git("tag", "-a", name, "-m", message, target, extra_env=env)
        return self.git("rev-parse", f"refs/tags/{name}")

    def test_a_term_in_an_annotated_tag_message_is_found(self) -> None:
        self.clean_commit()
        tag = self.tag("v1", "the zorblax plan")
        ref = "refs/tags/v1"
        code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<tag message>:1 term#2"])

    def test_a_term_in_the_tagger_is_found(self) -> None:
        self.clean_commit()
        tag = self.tag("v1", "release", GIT_COMMITTER_NAME="Zorblax")
        ref = "refs/tags/v1"
        code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<tagger>:1 term#2"])

    def test_a_tag_inside_a_tag_is_read_too(self) -> None:
        self.clean_commit()
        self.tag("inner", "the zorblax plan")
        outer = self.tag("outer", "release", "refs/tags/inner")
        ref = "refs/tags/outer"
        code, out, _ = self.pre_push(f"{ref} {outer} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<tag message>:1 term#2"])

    def test_a_clean_annotated_tag_passes_and_its_commits_are_scanned(self) -> None:
        self.clean_commit()
        leak = self.commit({"a.md": "zorblax\n"})
        tag = self.tag("v1", "release")
        ref = "refs/tags/v1"
        code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:a.md:1 term#2"])

    def test_a_clean_annotated_tag_exits_0(self) -> None:
        self.clean_commit()
        tag = self.tag("v1", "release")
        ref = "refs/tags/v1"
        code, out, err = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)

    def test_a_tag_that_git_cannot_read_exits_2(self) -> None:
        self.clean_commit()
        ref = "refs/tags/v1"
        code, out, _ = self.pre_push(f"{ref} {'1' * 40} {ref} {ZEROS}")
        self.assertEqual((code, out), (2, ""))

    def not_a_commit_push(self, target: str, ref: str = "refs/tags/v1") -> str:
        return f"{ref} {target} {ref} {ZEROS}"

    def test_a_ref_that_points_at_a_file_or_a_tree_is_refused(self) -> None:
        self.clean_commit()
        blob = self.git("rev-parse", "HEAD:notes.md")
        tree = self.git("rev-parse", "HEAD^{tree}")
        self.git("tag", "-a", "annotated-blob", "-m", "x", blob)
        self.git("tag", "-a", "annotated-tree", "-m", "x", tree)
        self.git("tag", "-a", "outer", "-m", "x", "refs/tags/annotated-blob")
        cases = {
            "light tag on a file": blob,
            "light tag on a tree": tree,
            "annotated tag on a file": self.git("rev-parse", "annotated-blob"),
            "annotated tag on a tree": self.git("rev-parse", "annotated-tree"),
            "tag on a tag on a file": self.git("rev-parse", "outer"),
        }
        for name, target in cases.items():
            with self.subTest(name):
                code, out, err = self.pre_push(self.not_a_commit_push(target))
                self.assertEqual((code, out), (2, ""))
                refusal = (
                    "privacy gate: a ref points at something that is not a commit."
                )
                self.assertEqual(err.splitlines()[-1], refusal)
                self.assertNotIn("scanned", err)

    def test_the_refusal_is_not_hidden_by_a_hit_or_a_clean_commit_in_the_push(
        self,
    ) -> None:
        head = self.clean_commit()
        blob = self.git("rev-parse", "HEAD:notes.md")
        code, out, _ = self.pre_push(
            f"refs/heads/main {head} refs/heads/main {ZEROS}",
            self.not_a_commit_push(blob, "refs/tags/zorblax"),
        )
        self.assertEqual((code, out), (2, ""))

    def test_deleting_a_ref_that_points_at_a_file_still_passes(self) -> None:
        self.clean_commit()
        blob = self.git("rev-parse", "HEAD:notes.md")
        code, out, err = self.pre_push(f"(delete) {ZEROS} refs/tags/v1 {blob}")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("scanned 0 commits", err)

    def test_a_branch_name_with_a_slash_between_a_terms_words_is_found(self) -> None:
        head = self.clean_commit()
        for name in ("quentin/example", "quentin.example", "quentin/-_example"):
            with self.subTest(name):
                ref = f"refs/heads/{name}"
                code, out, _ = self.pre_push(f"{ref} {head} {ref} {ZEROS}")
                self.assertEqual((code, out.splitlines()), (1, ["<ref>:0 term#6"]))

    def test_the_name_stored_in_an_annotated_tag_is_checked_apart_from_its_ref(
        self,
    ) -> None:
        self.clean_commit()
        ref = "refs/tags/ok"
        for name, label in (("zorblax-v1", "term#2"), ("quentin/example", "term#6")):
            with self.subTest(name):
                tag = self.tag(name, "release")
                code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
                self.assertEqual((code, out.splitlines()), (1, [f"<ref>:0 {label}"]))

    def raw_tag(self, name: bytes, tagger: bytes, message: bytes) -> str:
        """A tag object made from raw bytes, as git's own commands never would."""
        body = b"object " + self.git("rev-parse", "HEAD").encode() + b"\ntype commit\n"
        body += b"tag " + name + b"\ntagger " + tagger + b" 1700000000 +0000\n\n"
        command = ["git", "-C", str(self.root), "hash-object", "-w", "--literally"]
        command += ["-t", "tag", "--stdin"]
        done = subprocess.run(
            command, input=body + message, env=self.env, capture_output=True, check=True
        )
        return done.stdout.decode().strip()

    def test_text_in_a_tag_that_is_not_utf8_does_not_stop_the_scan(self) -> None:
        self.clean_commit()
        email = b" <alice" + AT.encode() + b"example.com>"
        tag = self.raw_tag(
            b"\xff-zorblax", b"\xff alice" + email, b"\xff-quentin example\n"
        )
        ref = "refs/tags/ok"
        code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), ["<ref>:0 term#2", "<tag message>:1 term#6"])

    def test_a_tag_message_is_read_past_its_first_paragraph_break(self) -> None:
        self.clean_commit()
        tag = self.tag("v1", "intro\n\nmore\n\nthe zorblax plan")
        ref = "refs/tags/v1"
        code, out, _ = self.pre_push(f"{ref} {tag} {ref} {ZEROS}")
        self.assertEqual((code, out.splitlines()), (1, ["<tag message>:5 term#2"]))

    def test_a_delete_does_not_hide_the_refs_after_it(self) -> None:
        head = self.clean_commit()
        leak = "refs/heads/zorblax-plan"
        code, out, _ = self.pre_push(
            f"(delete) {ZEROS} refs/heads/gone {head}", f"{leak} {head} {leak} {ZEROS}"
        )
        self.assertEqual((code, out.splitlines()), (1, ["<ref>:0 term#2"]))

    def test_a_line_git_gives_with_an_unreadable_old_tip_exits_2(self) -> None:
        head = self.clean_commit()
        ref = "refs/heads/topic"
        code, out, err = self.pre_push(f"{ref} {head} {ref} not-an-id")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("privacy gate: could not read the refs git is pushing.", err)


class SplitMatchTests(RangeRepoTestCase):
    def test_a_term_split_across_an_old_line_and_a_new_one_is_found(self) -> None:
        base = self.commit({"notes.md": "quentin\n"})
        leak = self.commit({"notes.md": "quentin\nexample\n"})
        self.assertEqual(self.scan_tip()[0], 1)
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:1 term#6"])

    def test_a_term_split_across_two_old_lines_is_not_new(self) -> None:
        base = self.commit({"notes.md": "quentin\nexample\n"})
        self.commit({"notes.md": "quentin\nexample\nfine\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))

    def test_a_term_on_an_old_line_is_not_new_though_a_later_one_is(self) -> None:
        base = self.commit({"notes.md": "zorblax\n"})
        leak = self.commit({"notes.md": "zorblax\nzorblax again\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:2 term#2"])

    def test_an_old_email_line_is_not_reported_again(self) -> None:
        base = self.commit({"notes.md": f"mail {OUTSIDE}\n"})
        self.commit({"notes.md": f"mail {OUTSIDE}\nmore\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual((code, out), (0, ""))

    def test_a_new_email_line_is_reported_at_its_line(self) -> None:
        base = self.commit({"notes.md": f"mail {OUTSIDE}\n"})
        leak = self.commit({"notes.md": f"mail {OUTSIDE}\nmail {OUTSIDE}\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD", "--generic-only")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(leak)}:notes.md:2 email"])

    def test_a_match_on_an_old_line_stays_old_when_new_lines_follow_it(self) -> None:
        base = self.commit({"a.md": "x\ny\nzorblax\n"})
        self.commit({"a.md": "x\ny\nzorblax\nw\nv\n"})
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual((code, out), (0, ""))


class GitArgumentTests(RangeRepoTestCase):
    def test_a_file_named_like_the_range_does_not_confuse_git(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        self.commit({"a.md": "zorblax\n"})
        (self.root / f"{base}..HEAD").write_text("x")
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(len(out.splitlines()), 1)

    def test_a_file_named_like_a_commit_does_not_confuse_git(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        head = self.commit({"a.md": "zorblax\n"})
        (self.root / head).write_text("x")
        code, out, _ = self.scan_range(f"{base}..HEAD")
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"{short(head)}:a.md:1 term#2"])

    def test_commits_are_read_oldest_first(self) -> None:
        base = self.commit({"notes.md": "fine\n"})
        first = self.commit({"first.txt": "x" * (LIMIT + 1)})
        second = self.commit({"second.txt": "x" * (LIMIT + 1)})
        with mock.patch.object(gate, "MAX_BYTES", LIMIT):
            code, _, err = self.scan_range(f"{base}..HEAD", "--allow-skipped")
        self.assertEqual(code, 0)
        self.assertLess(err.index(short(first)), err.index(short(second)))


class AddedLinesTests(RangeRepoTestCase):
    def test_the_lines_a_change_adds(self) -> None:
        self.assertEqual(gate.added_lines(["a\nb"], "a\nc\nb"), {2})
        self.assertEqual(gate.added_lines(["a\na"], "a\na\na"), {3})
        self.assertEqual(gate.added_lines(["a"], "a\na"), {2})
        self.assertEqual(gate.added_lines([""], "x\ny"), {1, 2})

    def test_a_line_any_old_version_had_is_not_added(self) -> None:
        self.assertEqual(gate.added_lines(["a", "b"], "a\nb\nc"), {3})
        self.assertEqual(gate.added_lines(["a\nb", "c"], "c\nb\na\nd"), {4})

    def test_a_match_counts_only_when_it_touches_an_added_line(self) -> None:
        terms = gate.parse_terms(DENYLIST)

        def lines(text: str, added: set[int]) -> list[int]:
            return [h.line for h in gate.scan_added("f", text, terms, added)]

        self.assertEqual(lines("quentin\nexample\n", {2}), [1])
        self.assertEqual(lines("quentin\nexample\n", {1}), [1])
        self.assertEqual(lines("quentin\nexample\nx\n", {3}), [])
        self.assertEqual(lines("zorblax\nzorblax\n", {2}), [2])
        self.assertEqual(lines("zorblax\nzorblax\n", {1, 2}), [1, 2])
        self.assertEqual(lines("zorblax\n", set()), [])
