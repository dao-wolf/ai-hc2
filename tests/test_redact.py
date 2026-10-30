"""Redaction: labels, paths, secrets and command lines (P-2, P-3, S-3)."""

from __future__ import annotations

import unittest

from hc2.adapters.base import AdapterReport
from hc2.model import Harness, ProcessNode, Session
from hc2.redact import (
    HIDDEN_TITLE,
    TERM_LABEL,
    UNLABELLED,
    Redactor,
    confidential_label,
    fingerprint_command,
    normalise_folder,
    redact_secrets,
    strip_controls,
    summarise_command,
)

HOME = "/home/alice"
CLIENT = "/home/alice/clients/example-client"
MATTER = "/home/alice/legal/example-matter"


def redactor(*folders: str, hide: bool = False) -> Redactor:
    return Redactor(HOME, folders or (CLIENT, MATTER), hide_titles=hide)


class LabelTests(unittest.TestCase):
    def test_labels_run_a_to_z_then_aa(self) -> None:
        self.assertEqual(confidential_label(0), "Confidential A")
        self.assertEqual(confidential_label(25), "Confidential Z")
        self.assertEqual(confidential_label(26), "Confidential AA")
        self.assertEqual(confidential_label(27), "Confidential AB")
        self.assertEqual(confidential_label(701), "Confidential ZZ")
        self.assertEqual(confidential_label(702), "Confidential AAA")

    def test_negative_index_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            confidential_label(-1)

    def test_labels_follow_config_order(self) -> None:
        self.assertEqual(
            redactor(CLIENT, MATTER).labels, ("Confidential A", "Confidential B")
        )
        reversed_order = redactor(MATTER, CLIENT)
        self.assertEqual(reversed_order.label_for(MATTER), "Confidential A")
        self.assertEqual(reversed_order.label_for(CLIENT), "Confidential B")

    def test_labels_are_stable_between_runs(self) -> None:
        first = redactor().label_for(CLIENT + "/src")
        second = redactor().label_for(CLIENT + "/src")
        self.assertEqual(first, second)

    def test_duplicates_share_a_label_and_do_not_skip_letters(self) -> None:
        r = redactor(CLIENT, CLIENT + "/", "~/clients/example-client", MATTER)
        self.assertEqual(r.labels, ("Confidential A", "Confidential B"))
        self.assertEqual(r.label_for(MATTER), "Confidential B")

    def test_tilde_and_absolute_forms_match(self) -> None:
        r = redactor("~/clients/example-client")
        self.assertEqual(r.label_for(CLIENT), "Confidential A")
        self.assertEqual(r.label_for("~/clients/example-client/x"), "Confidential A")

    def test_inside_matches_but_siblings_do_not(self) -> None:
        r = redactor(CLIENT)
        self.assertEqual(r.label_for(CLIENT + "/deep/er"), "Confidential A")
        self.assertIsNone(r.label_for(CLIENT + "-2"))
        self.assertIsNone(r.label_for("/home/alice/clients"))
        self.assertIsNone(r.label_for(None))

    def test_matching_ignores_case(self) -> None:
        self.assertEqual(redactor(CLIENT).label_for(CLIENT.upper()), "Confidential A")

    def test_the_most_specific_folder_wins(self) -> None:
        r = redactor("/home/alice/clients", "/home/alice/clients/example-client")
        self.assertEqual(r.label_for(CLIENT + "/x"), "Confidential B")
        self.assertEqual(r.label_for("/home/alice/clients/other"), "Confidential A")

    def test_normalise_folder(self) -> None:
        self.assertEqual(normalise_folder("~/a/../b/", HOME), "/home/alice/b")
        self.assertEqual(normalise_folder("/", HOME), "/")
        self.assertEqual(normalise_folder("~", HOME), HOME)


class SessionTests(unittest.TestCase):
    def test_confidential_session_shows_only_the_label(self) -> None:
        session = Session(
            "s1", "h", title="Merger plans", folder=CLIENT + "/docs", model="m"
        )
        clean = redactor().session(session)
        self.assertEqual(clean.title, "Confidential A")
        self.assertEqual(clean.folder, "Confidential A")
        self.assertTrue(clean.confidential)
        self.assertEqual(clean.model, "m")
        self.assertNotIn("Merger", clean.to_json())
        self.assertNotIn("example-client", clean.to_json())

    def test_second_folder_gets_the_second_label(self) -> None:
        session = Session("s1", "h", title="x", folder=MATTER)
        self.assertEqual(redactor().session(session).title, "Confidential B")

    def test_adapter_flag_without_a_listed_folder_is_still_hidden(self) -> None:
        session = Session(
            "s1", "h", title="Secret", folder="/elsewhere/x", confidential=True
        )
        clean = redactor().session(session)
        self.assertEqual((clean.title, clean.folder), (UNLABELLED, UNLABELLED))

    def test_ordinary_session_keeps_its_title_and_shortens_the_folder(self) -> None:
        session = Session("s1", "h", title="Example Project", folder=HOME + "/proj")
        clean = redactor().session(session)
        self.assertEqual(clean.title, "Example Project")
        self.assertEqual(clean.folder, "~/proj")
        self.assertFalse(clean.confidential)

    def test_hide_titles_masks_every_title(self) -> None:
        session = Session("s1", "h", title="Example Project", folder=HOME + "/proj")
        clean = redactor(hide=True).session(session)
        self.assertEqual(clean.title, HIDDEN_TITLE)
        self.assertEqual(clean.folder, "~/proj")

    def test_missing_fields_stay_missing(self) -> None:
        clean = redactor().session(Session("s1", "h"))
        self.assertIsNone(clean.title)
        self.assertIsNone(clean.folder)

    def test_session_ids_are_kept_opaque(self) -> None:
        token_like = "Xy9Zw3Kq" * 5
        clean = redactor().session(Session(token_like, "h"))
        self.assertEqual(clean.id, token_like)

    def test_report_redacts_everything_an_adapter_returned(self) -> None:
        report = AdapterReport(
            Harness("h", "Harness", True, config_location=HOME + "/.h"),
            (Session("s1", "h", title="t", folder=CLIENT),),
            (f"Could not read {CLIENT}/index.",),
            ("index: id",),
        )
        clean = redactor().report(report)
        self.assertEqual(clean.harness.config_location, "~/.h")
        self.assertEqual(clean.problems, ("Could not read Confidential A.",))
        self.assertEqual(clean.fields_read, ("index: id",))


TERMS = ("sentinel codename", "Tarn")


def with_terms(*folders: str) -> Redactor:
    return Redactor(HOME, folders, terms=TERMS)


class TermTests(unittest.TestCase):
    def test_a_title_term_masks_a_session_in_a_normal_folder(self) -> None:
        session = Session(
            "s1",
            "h",
            title="Plan for Sentinel   Codename launch",
            folder=HOME + "/proj",
        )
        clean = with_terms().session(session)
        self.assertEqual(clean.title, TERM_LABEL)
        self.assertEqual(clean.folder, TERM_LABEL)
        self.assertTrue(clean.confidential)
        self.assertNotIn("odename", clean.to_json())
        self.assertNotIn("proj", clean.to_json())

    def test_a_folder_term_masks_too(self) -> None:
        session = Session("s1", "h", title="Notes", folder=HOME + "/work/tarn-app")
        clean = with_terms().session(session)
        self.assertEqual((clean.title, clean.folder), (TERM_LABEL, TERM_LABEL))

    def test_matching_ignores_case(self) -> None:
        for title in ("TARN", "tarn", "TaRn"):
            with self.subTest(title=title):
                clean = with_terms().session(Session("s", "h", title=title))
                self.assertEqual(clean.title, TERM_LABEL)

    def test_only_whole_words_match(self) -> None:
        for title in ("Starnet check", "Tarnish", "Stern", "tarn2"):
            with self.subTest(title=title):
                clean = with_terms().session(Session("s", "h", title=title))
                self.assertEqual(clean.title, title)
                self.assertFalse(clean.confidential)

    def test_punctuation_and_underscores_separate_words(self) -> None:
        for title in ("(tarn)", "tarn, again", "the_tarn_plan", "tarn-app"):
            with self.subTest(title=title):
                clean = with_terms().session(Session("s", "h", title=title))
                self.assertEqual(clean.title, TERM_LABEL)

    def test_one_shared_label_never_one_per_term(self) -> None:
        a = with_terms().session(Session("a", "h", title="Tarn notes"))
        b = with_terms().session(Session("b", "h", title="sentinel codename notes"))
        self.assertEqual(a.title, b.title)
        self.assertNotIn("Tarn", a.title or "")

    def test_a_folder_label_wins_over_the_term_label(self) -> None:
        session = Session("s", "h", title="Tarn", folder=CLIENT + "/x")
        clean = with_terms(CLIENT).session(session)
        self.assertEqual(clean.title, "Confidential A")

    def test_terms_do_not_take_a_folder_letter(self) -> None:
        r = with_terms(CLIENT)
        self.assertEqual(r.labels, ("Confidential A",))

    def test_terms_are_scrubbed_from_other_text_too(self) -> None:
        text = with_terms().text("Could not read the Tarn index") or ""
        self.assertNotIn("Tarn", text)
        self.assertIn("[redacted]", text)

    def test_blank_and_repeated_terms_are_harmless(self) -> None:
        r = Redactor(HOME, (), terms=("", "  ", "Tarn", "tarn"))
        masked = r.session(Session("s", "h", title="Tarn"))
        self.assertEqual(masked.title, TERM_LABEL)
        self.assertEqual(r.session(Session("s", "h", title="Other")).title, "Other")

    def test_no_terms_means_no_term_masking(self) -> None:
        clean = redactor().session(Session("s", "h", title="Tarn"))
        self.assertEqual(clean.title, "Tarn")


class TextTests(unittest.TestCase):
    def test_home_becomes_tilde(self) -> None:
        self.assertEqual(redactor().text(HOME + "/a/b"), "~/a/b")
        self.assertEqual(redactor().text("at " + HOME), "at ~")
        self.assertEqual(redactor().text(HOME + "2/a"), "~/a")  # generic rule

    def test_other_users_homes_are_shortened_too(self) -> None:
        text = redactor().text("/Users/bob/x and /home/carol/y")
        self.assertEqual(text, "~/x and ~/y")

    def test_confidential_paths_become_labels_even_inside_text(self) -> None:
        text = f"Failed to open {CLIENT}/notes/plan.md, then {MATTER}."
        self.assertEqual(
            redactor().text(text), "Failed to open Confidential A, then Confidential B."
        )

    def test_secrets_are_hidden(self) -> None:
        cases = [
            "sk-" + "a1" * 15,
            "ghp_" + "A" * 30,
            "xoxb-" + "1234567890-abcdef",
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "eyJhbGciOiJIUzI1" + "NiJ9.eyJzdWIiOiIxMjM0.abc_def-ghi",
            "Bearer abc12345678xyz",
            "api_key=hunter2",
            'password: "correct horse"',
            '"token": "abc123"',
            "https://user:pw@host.example.com/x",
            "carol" + "@" + "mail.example.org",
        ]
        for text in cases:
            with self.subTest(text=text):
                clean = redactor().text("see " + text + " now") or ""
                self.assertIn("[redacted]", clean)
                for part in ("hunter2", "correct horse", "abc123", "pw@", "carol"):
                    self.assertNotIn(part, clean)

    def test_private_key_blocks_are_hidden(self) -> None:
        kind = "RSA " + "PRIVATE KEY"
        block = f"-----BEGIN {kind}-----\nMIIabc\n-----END {kind}-----"
        self.assertEqual(redactor().text("key " + block + " end"), "key [redacted] end")

    def test_long_mixed_strings_are_hidden_but_ids_survive(self) -> None:
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        digest = "ab12" * 16
        self.assertEqual(redactor().text(uuid), uuid)
        self.assertEqual(redactor().text(digest), digest)
        self.assertEqual(redactor().text("Xy9Zw3Kq" * 5), "[redacted]")

    def test_ordinary_words_and_versions_are_untouched(self) -> None:
        text = "Refactor authentication module for claude-code@2.1.0 (token limit)"
        self.assertEqual(redactor().text(text), text)

    def test_control_characters_are_removed(self) -> None:
        self.assertEqual(strip_controls("a\x1b[2Jb\tc\nd\x00"), "a[2Jb c d")
        self.assertEqual(redactor().text("x\x07y"), "xy")

    def test_none_stays_none(self) -> None:
        self.assertIsNone(redactor().text(None))

    def test_redact_secrets_is_pure(self) -> None:
        self.assertEqual(redact_secrets("nothing here"), "nothing here")


class ProcessTests(unittest.TestCase):
    def test_summary_keeps_executable_flag_names_and_a_fingerprint(self) -> None:
        line = (
            "/usr/local/bin/node --port=8080 --api-key=hunter2 -pSECRET "
            "/home/alice/x.js"
        )
        summary = summarise_command(line)
        self.assertEqual(summary.executable, "node")
        self.assertEqual(summary.flags, ("--port", "--api-key", "-p"))
        self.assertEqual(summary.fingerprint, fingerprint_command(line))
        self.assertEqual(len(summary.fingerprint), 64)
        self.assertEqual(summary.display(), "node --port --api-key -p")
        text = summary.to_json()
        for hidden in ("hunter2", "8080", "SECRET", "alice", "/usr/local"):
            self.assertNotIn(hidden, text)

    def test_fingerprint_changes_with_any_argument(self) -> None:
        a = summarise_command("node --port=1").fingerprint
        b = summarise_command("node --port=2").fingerprint
        self.assertNotEqual(a, b)

    def test_odd_input_does_not_crash(self) -> None:
        self.assertEqual(summarise_command("").executable, "")
        self.assertEqual(summarise_command('tool "unterminated --x').executable, "tool")
        many = " ".join(f"--flag{i}" for i in range(100))
        self.assertEqual(len(summarise_command("t " + many).flags), 24)

    def test_non_flag_arguments_are_dropped(self) -> None:
        summary = summarise_command("git commit -m message --amend")
        self.assertEqual(summary.flags, ("-m", "--amend"))

    def test_process_names_lose_any_folder(self) -> None:
        node = ProcessNode(pid=4, name=HOME + "/bin/tool")
        self.assertEqual(redactor().process(node).name, "tool")


if __name__ == "__main__":
    unittest.main()
