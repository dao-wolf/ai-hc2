"""Tests for the helpers shared by the Claude adapters."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest import mock

from hc2.adapters import claude_common as common
from hc2.adapters.claude_common import ConfidentialMatcher, ProcessInfo


class ValueTests(unittest.TestCase):
    def test_times(self) -> None:
        self.assertEqual(common.iso_from_ms(0), "1970-01-01T00:00:00Z")
        self.assertIsNone(common.iso_from_ms(True))
        self.assertIsNone(common.iso_from_ms("123"))
        self.assertIsNone(common.iso_from_ms(10**30))
        self.assertEqual(
            common.iso_from_text("2026-10-30T09:00:00.250Z"), "2026-10-30T09:00:00Z"
        )
        self.assertEqual(
            common.iso_from_text("2026-10-30T10:00:00+01:00"), "2026-10-30T09:00:00Z"
        )
        self.assertIsNone(common.iso_from_text("yesterday"))
        self.assertIsNone(common.iso_from_text(5))

    def test_titles_lose_control_characters_and_are_cut(self) -> None:
        self.assertEqual(common.clean_title("a\nb\x00c"), "a b c")
        self.assertEqual(len(common.clean_title("x" * 1000) or ""), 300)
        self.assertIsNone(common.clean_title("   "))
        self.assertIsNone(common.clean_title(None))

    def test_display_path(self) -> None:
        self.assertEqual(common.display_path("/home/alice/x", "/home/alice"), "~/x")
        self.assertEqual(common.display_path("/home/alice", "/home/alice"), "~")
        self.assertEqual(common.display_path("/opt/x", "/home/alice"), "/opt/x")
        self.assertEqual(common.display_path("/opt/hx/y", "/opt/h"), "/opt/hx/y")

    def test_origin_from_entrypoint(self) -> None:
        origin = common.origin_from_entrypoint
        self.assertEqual(origin("cli").value, "cli")
        self.assertEqual(origin("claude-desktop").value, "desktop")
        self.assertEqual(origin("claude-vscode").value, "ide")
        self.assertEqual(origin("sdk-ts").value, "unknown")
        self.assertEqual(origin(None).value, "unknown")


class ConfidentialMatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matcher = ConfidentialMatcher(
            ["~/legal/example-matter/", ""], "/home/alice"
        )

    def test_folder_and_everything_below_it(self) -> None:
        check = self.matcher.folder_is_confidential
        self.assertTrue(check("/home/alice/legal/example-matter"))
        self.assertTrue(check("/home/alice/legal/example-matter/deep/er"))
        self.assertTrue(check("/home/alice/legal/example-matter/"))
        self.assertTrue(check("/HOME/alice/legal/Example-Matter"))
        self.assertTrue(check(None, "/home/alice/legal/example-matter"))

    def test_siblings_and_parents_are_not_inside(self) -> None:
        check = self.matcher.folder_is_confidential
        self.assertFalse(check("/home/alice/legal"))
        self.assertFalse(check("/home/alice/legal/example-matter-two"))
        self.assertFalse(check("/home/alice/legal/other/../elsewhere"))
        self.assertFalse(check(None, ""))

    def test_dotdot_is_resolved_before_comparing(self) -> None:
        inside = "/home/alice/x/../legal/example-matter/a"
        self.assertTrue(self.matcher.folder_is_confidential(inside))

    def test_project_folder_names_match_by_prefix_safely(self) -> None:
        check = self.matcher.project_dir_is_confidential
        self.assertTrue(check("-home-alice-legal-example-matter"))
        self.assertTrue(check("-home-alice-legal-example-matter-sub"))
        self.assertTrue(check("-home-alice-legal-example-matter-two"))
        self.assertFalse(check("-home-alice-legal"))

    def test_the_root_folder_covers_everything(self) -> None:
        self.assertTrue(ConfidentialMatcher(["/"], "/h").folder_is_confidential("/a/b"))

    def test_no_folders_means_nothing_matches(self) -> None:
        empty = ConfidentialMatcher([], "/home/alice")
        self.assertFalse(empty.folder_is_confidential("/anything"))
        self.assertFalse(empty.project_dir_is_confidential("-anything"))


class ProcessTests(unittest.TestCase):
    def test_parse_ps_reads_padded_days_and_paths_with_spaces(self) -> None:
        output = (
            " 4001 Thu Oct  9 10:05:05 2026 /opt/x/.local/share/claude/versions/9\n"
            "  4002 Thu Oct 29 14:01:43 2026 /opt/x/Library/Application Support/"
            "Claude/claude-code/9/abc/claude.app/Contents/MacOS/claude\n"
            "garbage line\n"
        )
        table = common.parse_ps(output)
        self.assertEqual(table[4001], ProcessInfo("9", "Thu Oct 9 10:05:05 2026"))
        self.assertEqual(table[4002].name, "claude")
        self.assertEqual(len(table), 2)

    def test_start_times_compare_with_spaces_collapsed(self) -> None:
        self.assertEqual(
            common.normalise_start("Thu Oct  9 10:05:05 2026"),
            common.normalise_start("Thu Oct 9 10:05:05 2026"),
        )

    def test_this_process_is_found_and_a_finished_one_is_not(self) -> None:
        found = common.probe_processes([os.getpid()])
        self.assertIsNotNone(found)
        assert found is not None
        self.assertIn(os.getpid(), found)
        self.assertTrue(found[os.getpid()].started)
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        self.assertEqual(common.probe_processes([child.pid]), {})

    def test_invalid_pids_are_never_signalled(self) -> None:
        with mock.patch("hc2.adapters.claude_common.os.kill") as kill:
            self.assertEqual(common.probe_processes([0, 1, -5]), {})
        kill.assert_not_called()

    def test_ps_is_light_bounded_and_failure_is_reported(self) -> None:
        with mock.patch(
            "hc2.adapters.claude_common.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ps", 2),
        ) as run:
            self.assertIsNone(common.probe_processes([os.getpid()]))
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], common.PS_TIMEOUT_SECONDS)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(run.call_args.args[0][:2], ["ps", "-p"])


class ProblemTests(unittest.TestCase):
    def test_sentences_are_counted_sorted_and_singular_or_plural(self) -> None:
        problems = common.Problems("Label")
        problems.add("files_damaged")
        problems.add("files_damaged", 2)
        problems.add("format_unknown")
        lines = problems.render()
        self.assertEqual(
            lines,
            (
                "Label: 3 files could not be read as valid data, so those sessions "
                "have missing details.",
                "Label: 1 file not in a format this version understands. The adapter "
                "may need an update.",
            ),
        )

    def test_unknown_kinds_still_give_a_sentence(self) -> None:
        problems = common.Problems("Label")
        problems.add("surprise")
        self.assertEqual(problems.render(), ("Label: an unexpected problem occurred.",))


if __name__ == "__main__":
    unittest.main()
