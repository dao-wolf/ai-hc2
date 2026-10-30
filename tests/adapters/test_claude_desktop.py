"""Tests for the Claude desktop Code tab and Cowork adapters."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from hc2.adapters.base import Adapter, AdapterContext
from hc2.adapters.claude_cowork import ClaudeCoworkAdapter
from hc2.adapters.claude_desktop import ClaudeDesktopAdapter
from hc2.model import InstallKind, Origin, SessionState

from .support import by_id, failing_probe, fake_home, fake_probe, scan_all

SUPPORT = ("Library", "Application Support", "Claude")


def utc(milliseconds: int) -> str:
    moment = datetime.fromtimestamp(milliseconds / 1000, UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class DesktopInstallTests(unittest.TestCase):
    def test_app_and_embedded_versions(self) -> None:
        with fake_home() as home:
            report = scan_all(home)["desktop"]
        installs = [(i.kind, i.version) for i in report.harness.installs]
        self.assertEqual(
            installs,
            [
                (InstallKind.APP, "9.9.0"),
                (InstallKind.EMBEDDED, "9.8.0"),
                (InstallKind.EMBEDDED, "9.9.0"),
            ],
        )
        self.assertEqual(len({i.id for i in report.harness.installs}), 3)
        self.assertTrue(report.harness.installed)
        self.assertEqual(
            report.harness.installs[0].location, "~/Applications/Claude.app"
        )

    def test_a_broken_info_file_is_a_problem_not_an_error(self) -> None:
        with fake_home() as home:
            plist = home / "Applications" / "Claude.app" / "Contents" / "Info.plist"
            plist.write_text("not a plist", encoding="utf-8")
            report = scan_all(home)["desktop"]
        self.assertIsNone(report.harness.installs[0].version)
        self.assertTrue(any("version could not be read" in p for p in report.problems))

    def test_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = ClaudeDesktopAdapter(fake_probe(), [str(Path(tmp) / "none")])
            report = adapter.scan(AdapterContext(home=tmp))
        self.assertFalse(report.harness.installed)
        self.assertEqual((report.sessions, report.problems), ((), ()))

    def test_installed_without_an_index_folder_is_a_problem(self) -> None:
        with fake_home() as home:
            shutil.rmtree(home.joinpath(*SUPPORT, "claude-code-sessions"))
            report = scan_all(home)["desktop"]
        self.assertEqual(report.sessions, ())
        self.assertTrue(any("folder was not found" in p for p in report.problems))


class DesktopSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with fake_home() as home:
            cls.report = scan_all(home)["desktop"]
        cls.sessions = by_id(cls.report)

    def test_which_sessions_are_listed(self) -> None:
        self.assertEqual(
            set(self.sessions), {f"local_000{n}" for n in range(1, 7)}
        )

    def test_fields_come_from_the_index(self) -> None:
        first = self.sessions["local_0001"]
        self.assertEqual(first.title, "Desktop example session")
        self.assertEqual(first.folder, "/home/alice/projects/example-project")
        self.assertEqual(first.model, "claude-example-model-1")
        self.assertEqual(first.created, utc(1790000000000))
        self.assertEqual(first.last_activity, utc(1790003600000))
        self.assertEqual(first.origin, Origin.DESKTOP)

    def test_running_state_links_through_cli_session_id(self) -> None:
        states = {sid: s.state for sid, s in self.sessions.items()}
        self.assertEqual(states["local_0001"], SessionState.RUNNING_IDLE)
        self.assertEqual(states["local_0002"], SessionState.RUNNING_BUSY)

    def test_sessions_with_no_live_process_have_ended(self) -> None:
        self.assertEqual(self.sessions["local_0003"].state, SessionState.ENDED)
        self.assertEqual(self.sessions["local_0006"].state, SessionState.ENDED)

    def test_missing_keys_become_none(self) -> None:
        bare = self.sessions["local_0006"]
        for value in (bare.title, bare.folder, bare.model, bare.created):
            self.assertIsNone(value)
        self.assertIsNone(bare.last_activity)

    def test_confidential_by_cwd_or_origin_cwd(self) -> None:
        flagged = {s.id for s in self.report.sessions if s.confidential}
        self.assertEqual(flagged, {"local_0004", "local_0005"})
        self.assertIsNone(self.sessions["local_0004"].title)
        self.assertIsNone(self.sessions["local_0005"].title)
        self.assertEqual(
            self.sessions["local_0004"].folder, "/home/alice/legal/example-matter/sub"
        )

    def test_bad_index_files_are_counted_without_paths(self) -> None:
        self.assertEqual(len(self.report.problems), 2)
        joined = " ".join(self.report.problems)
        self.assertIn("1 file could not be read as valid data", joined)
        self.assertIn("2 files not in a format this version understands", joined)
        for leak in ("/", "alice", "local_"):
            self.assertNotIn(leak, joined)

    def test_field_sources_cover_every_value_that_is_set(self) -> None:
        sources = {s.field for s in self.sessions["local_0001"].field_sources}
        self.assertEqual(
            sources,
            {"id", "title", "folder", "model", "created", "last_activity"}
            | {"origin", "state"},
        )

    def test_the_other_state_is_unknown_when_processes_cannot_be_checked(self) -> None:
        with fake_home() as home:
            report = scan_all(home, probe=failing_probe)["desktop"]
        self.assertEqual({s.state for s in report.sessions}, {SessionState.UNKNOWN})

    def test_protocol_and_signature(self) -> None:
        adapter = ClaudeDesktopAdapter()
        self.assertIsInstance(adapter, Adapter)
        signature = adapter.process_signature()
        self.assertEqual(signature.harness_id, "claude-desktop-code")
        self.assertIn("Claude", signature.executable_names)
        self.assertIn("/Claude.app/", signature.path_markers)


class CoworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with fake_home() as home:
            cls.report = scan_all(home)["cowork"]
        cls.sessions = by_id(cls.report)

    def test_which_sessions_are_listed(self) -> None:
        self.assertEqual(
            set(self.sessions), {"local_c001", "local_c002", "local_c003", "local_c004"}
        )

    def test_folder_is_the_first_selected_folder_not_the_vm_path(self) -> None:
        self.assertEqual(
            self.sessions["local_c001"].folder, "/home/alice/projects/example-project"
        )
        self.assertIsNone(self.sessions["local_c004"].folder)

    def test_state_is_unknown_or_ended_when_archived(self) -> None:
        self.assertEqual(self.sessions["local_c001"].state, SessionState.UNKNOWN)
        self.assertEqual(self.sessions["local_c002"].state, SessionState.ENDED)

    def test_any_selected_folder_can_make_a_session_confidential(self) -> None:
        flagged = {s.id for s in self.report.sessions if s.confidential}
        self.assertEqual(flagged, {"local_c003"})
        self.assertIsNone(self.sessions["local_c003"].title)

    def test_fields(self) -> None:
        first = self.sessions["local_c001"]
        self.assertEqual(first.title, "Cowork example task")
        self.assertEqual(first.model, "claude-example-model-1")
        self.assertEqual(first.created, utc(1790200000000))
        self.assertEqual(first.origin, Origin.DESKTOP)

    def test_app_version_and_one_bad_file(self) -> None:
        self.assertEqual(self.report.harness.installs[0].version, "9.9.0")
        self.assertEqual(self.report.harness.installs[0].kind, InstallKind.APP)
        self.assertEqual(len(self.report.problems), 1)
        self.assertIn("1 file could not be read as valid data", self.report.problems[0])

    def test_fields_read_does_not_list_message_or_prompt_keys(self) -> None:
        joined = " ".join(self.report.fields_read)
        for name in ("initialMessage", "systemPrompt", "emailAddress", "error"):
            self.assertNotIn(name, joined)

    def test_protocol_and_signature(self) -> None:
        adapter = ClaudeCoworkAdapter()
        self.assertIsInstance(adapter, Adapter)
        signature = adapter.process_signature()
        self.assertEqual(signature.harness_id, "claude-desktop-cowork")
        self.assertEqual(signature.executable_names, ())

    def test_installed_without_an_index_folder_is_a_problem(self) -> None:
        with fake_home() as home:
            shutil.rmtree(home.joinpath(*SUPPORT, "local-agent-mode-sessions"))
            report = scan_all(home)["cowork"]
        self.assertTrue(any("folder was not found" in p for p in report.problems))


if __name__ == "__main__":
    unittest.main()
