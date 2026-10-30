"""Tests for the Claude Code CLI adapter."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hc2.adapters.base import Adapter, AdapterContext
from hc2.adapters.claude_code import ClaudeCodeAdapter
from hc2.model import InstallKind, Origin, Reliability, SessionState

from .support import (
    CONFIDENTIAL,
    by_id,
    context,
    failing_probe,
    fake_home,
    fake_probe,
    scan_all,
)

LIVE_STATES = {
    SessionState.RUNNING_BUSY,
    SessionState.RUNNING_IDLE,
    SessionState.WAITING,
}


class InstallTests(unittest.TestCase):
    def test_version_comes_from_the_symlink_target_folder(self) -> None:
        with fake_home() as home:
            report = scan_all(home)["cli"]
        install = report.harness.installs[0]
        self.assertTrue(report.harness.installed)
        self.assertEqual(install.kind, InstallKind.CLI)
        self.assertEqual(install.version, "9.9.1")
        self.assertEqual(install.location, "~/.local/bin/claude")
        self.assertTrue(install.id.startswith("install_"))
        self.assertEqual(report.harness.config_location, "~/.claude")

    def test_nothing_installed_is_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = ClaudeCodeAdapter(fake_probe(), [str(Path(tmp) / "bin")])
            report = adapter.scan(AdapterContext(home=tmp))
        self.assertFalse(report.harness.installed)
        self.assertEqual((report.sessions, report.problems), ((), ()))

    def test_installed_without_a_session_folder_is_a_problem(self) -> None:
        with fake_home() as home:
            shutil.rmtree(home / ".claude" / "projects")
            report = scan_all(home)["cli"]
        self.assertTrue(report.harness.installed)
        self.assertTrue(any("folder was not found" in p for p in report.problems))

    def test_link_with_no_version_in_its_target(self) -> None:
        with fake_home() as home:
            link = home / ".local" / "bin" / "claude"
            link.unlink()
            link.symlink_to("../share/claude/latest")
            report = scan_all(home)["cli"]
        self.assertIsNone(report.harness.installs[0].version)
        self.assertTrue(any("version could not be" in p for p in report.problems))


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with fake_home() as home:
            cls.report = scan_all(home)["cli"]
        cls.sessions = by_id(cls.report)

    def test_which_sessions_are_listed(self) -> None:
        expected = {
            "cli-0001",
            "cli-0002",
            "cli-0003",
            "cli-0004",
            "cli-0005",
            "cli-0006",
            "cli-0007",
            "conf-0001",
            "conf-0002",
            "bad-0001",
            "live-only-0001",
        }
        self.assertEqual(set(self.sessions), expected)

    def test_desktop_sessions_are_left_to_the_desktop_adapter(self) -> None:
        for gone in ("s-desk-0001", "s-desk-orphan", "cli-0099"):
            self.assertNotIn(gone, self.sessions)

    def test_title_order_is_custom_then_agent_then_ai(self) -> None:
        titles = {sid: s.title for sid, s in self.sessions.items()}
        self.assertEqual(titles["cli-0001"], "Fix the example parser")
        self.assertEqual(titles["cli-0003"], "Example agent session")
        self.assertEqual(titles["cli-0002"], "Review the example docs")
        self.assertEqual(titles["live-only-0001"], "Live only session")
        self.assertIsNone(titles["cli-0004"])

    def test_metadata_in_message_text_is_not_trusted(self) -> None:
        first = self.sessions["cli-0001"]
        self.assertEqual(first.folder, "/home/alice/projects/example-project")
        self.assertEqual(first.title, "Fix the example parser")

    def test_model_comes_from_the_last_real_assistant_record(self) -> None:
        self.assertEqual(self.sessions["cli-0001"].model, "claude-example-model-1")
        self.assertIsNone(self.sessions["cli-0004"].model)

    def test_times_are_utc_text(self) -> None:
        first = self.sessions["cli-0001"]
        self.assertEqual(first.created, "2026-10-01T09:00:00Z")
        self.assertEqual(first.last_activity, "2026-10-01T10:30:05Z")

    def test_a_missing_timestamp_falls_back_to_the_file_time(self) -> None:
        damaged = self.sessions["bad-0001"]
        self.assertIsNone(damaged.created)
        self.assertIsNotNone(damaged.last_activity)
        sources = {s.field: s for s in damaged.field_sources}
        self.assertEqual(sources["last_activity"].reliability, Reliability.LOW)

    def test_running_states_come_from_the_registry(self) -> None:
        states = {sid: s.state for sid, s in self.sessions.items()}
        self.assertEqual(states["cli-0002"], SessionState.RUNNING_BUSY)
        self.assertEqual(states["cli-0006"], SessionState.WAITING)
        self.assertEqual(states["cli-0007"], SessionState.RUNNING_IDLE)
        self.assertEqual(states["live-only-0001"], SessionState.RUNNING_IDLE)

    def test_dead_recycled_and_foreign_pids_are_not_running(self) -> None:
        for sid in ("cli-0003", "cli-0004", "cli-0005", "cli-0001"):
            self.assertEqual(self.sessions[sid].state, SessionState.ENDED, sid)

    def test_origin_follows_the_entrypoint(self) -> None:
        self.assertEqual(self.sessions["cli-0001"].origin, Origin.CLI)
        self.assertEqual(self.sessions["cli-0007"].origin, Origin.IDE)
        self.assertEqual(self.sessions["bad-0001"].origin, Origin.UNKNOWN)

    def test_field_sources_name_where_each_value_came_from(self) -> None:
        sources = {s.field: s for s in self.sessions["cli-0001"].field_sources}
        self.assertEqual(
            set(sources),
            {"id", "title", "folder", "model", "created", "last_activity"}
            | {"origin", "state"},
        )
        self.assertEqual(
            sources["title"].source, "projects/*.jsonl custom-title record"
        )
        self.assertEqual(sources["model"].reliability, Reliability.MEDIUM)
        for source in sources.values():
            self.assertTrue(source.source)

    def test_fields_read_lists_the_allowed_fields(self) -> None:
        joined = " ".join(self.report.fields_read)
        for name in ("message.model", "customTitle", "cwd", "procStart", "status"):
            self.assertIn(name, joined)

    def test_problems_name_no_paths(self) -> None:
        self.assertEqual(len(self.report.problems), 2)
        for line in self.report.problems:
            for leak in ("/", "alice", ".claude", "bad-0001"):
                self.assertNotIn(leak, line)

    def test_sessions_are_newest_first(self) -> None:
        keys = [(s.last_activity or "", s.id) for s in self.report.sessions]
        self.assertEqual(keys, sorted(keys, reverse=True))


class LivenessTests(unittest.TestCase):
    def test_with_no_live_processes_nothing_is_running(self) -> None:
        with fake_home() as home:
            report = scan_all(home, probe=fake_probe({}))["cli"]
        self.assertFalse(LIVE_STATES & {s.state for s in report.sessions})
        self.assertNotIn("live-only-0001", by_id(report))

    def test_a_failed_process_lookup_gives_unknown_not_ended(self) -> None:
        with fake_home() as home:
            report = scan_all(home, probe=failing_probe)["cli"]
        self.assertEqual({s.state for s in report.sessions}, {SessionState.UNKNOWN})
        self.assertTrue(any("running" in p for p in report.problems))


class ProcessLinkTests(unittest.TestCase):
    def test_a_live_session_carries_its_pid(self) -> None:
        with fake_home() as home:
            sessions = by_id(scan_all(home)["cli"])
        self.assertEqual(sessions["cli-0002"].pid, 4001)
        self.assertEqual(sessions["live-only-0001"].pid, 4008)
        sources = {s.field: s for s in sessions["cli-0002"].field_sources}
        self.assertEqual(sources["pid"].reliability, Reliability.HIGH)
        self.assertNotIn("state_since", sources)  # the fixture has no status time
        self.assertIsNone(sessions["cli-0002"].state_since)

    def test_the_status_time_becomes_state_since_with_a_source(self) -> None:
        with fake_home() as home:
            registry = home / ".claude" / "sessions" / "4001.json"
            text = registry.read_text(encoding="utf-8")
            registry.write_text(
                text.replace("}", ',"statusUpdatedAt":1790000050000}'),
                encoding="utf-8",
            )
            report = scan_all(home)["cli"]
        session = by_id(report)["cli-0002"]
        self.assertEqual(session.state_since, "2026-09-21T14:14:10Z")
        sources = {s.field: s for s in session.field_sources}
        self.assertEqual(
            sources["state_since"].source, "sessions/*.json statusUpdatedAt"
        )
        self.assertIn("statusUpdatedAt", " ".join(report.fields_read))

    def test_a_bad_status_time_is_dropped(self) -> None:
        with fake_home() as home:
            registry = home / ".claude" / "sessions" / "4001.json"
            text = registry.read_text(encoding="utf-8")
            registry.write_text(
                text.replace("}", ',"statusUpdatedAt":"soon"}'), encoding="utf-8"
            )
            session = by_id(scan_all(home)["cli"])["cli-0002"]
        self.assertIsNone(session.state_since)
        self.assertEqual(session.pid, 4001)

    def test_sessions_that_are_not_running_have_no_pid(self) -> None:
        with fake_home() as home:
            sessions = by_id(scan_all(home, probe=fake_probe({}))["cli"])
        for session in sessions.values():
            self.assertIsNone(session.pid)
            self.assertIsNone(session.state_since)

    def test_a_dead_pid_is_not_reported(self) -> None:
        with fake_home() as home:
            sessions = by_id(scan_all(home)["cli"])
        # Registry file 4003 names a dead process, so the session is ended.
        self.assertIsNone(sessions["cli-0003"].pid)


class ConfidentialTests(unittest.TestCase):
    def test_sessions_in_a_confidential_folder_are_flagged(self) -> None:
        with fake_home() as home:
            report = scan_all(home)["cli"]
        flagged = {s.id for s in report.sessions if s.confidential}
        self.assertEqual(flagged, {"conf-0001", "conf-0002"})

    def test_the_folder_stays_raw_and_the_title_is_dropped(self) -> None:
        with fake_home() as home:
            sessions = by_id(scan_all(home)["cli"])
        self.assertEqual(sessions["conf-0001"].folder, CONFIDENTIAL + "/sub")
        self.assertIsNone(sessions["conf-0001"].title)
        self.assertIsNone(sessions["conf-0002"].title)

    def test_nothing_is_flagged_when_no_folders_are_configured(self) -> None:
        with fake_home() as home:
            report = scan_all(home, confidential=())["cli"]
        self.assertFalse(any(s.confidential for s in report.sessions))

    def test_a_live_session_without_a_transcript_can_be_flagged(self) -> None:
        with fake_home() as home:
            ctx = context(home, ("/home/alice/projects",))
            adapter = ClaudeCodeAdapter(
                fake_probe(), [str(home / ".local" / "bin")]
            )
            sessions = by_id(adapter.scan(ctx))
        self.assertTrue(sessions["live-only-0001"].confidential)
        self.assertIsNone(sessions["live-only-0001"].title)


class ToleranceTests(unittest.TestCase):
    def test_a_permission_error_on_a_transcript_is_a_problem(self) -> None:
        denied = mock.patch(
            "hc2.adapters.claude_common._open_binary",
            side_effect=PermissionError("denied"),
        )
        with fake_home() as home, denied:
            report = scan_all(home)["cli"]
        self.assertTrue(any("permission denied" in p for p in report.problems))

    def test_an_unreadable_projects_folder_is_a_problem(self) -> None:
        real = os.listdir

        def listdir(path: str) -> list[str]:
            if str(path).endswith("projects"):
                raise PermissionError("denied")
            return real(path)

        patched = mock.patch("hc2.adapters.claude_common.os.listdir", listdir)
        with fake_home() as home, patched:
            report = scan_all(home)["cli"]
        listed = {s.id for s in report.sessions}
        self.assertNotIn("cli-0001", listed)  # transcripts could not be listed
        self.assertIn("live-only-0001", listed)  # the registry still works
        self.assertTrue(any("folder could not be read" in p for p in report.problems))

    def test_an_unexpected_error_becomes_a_plain_problem(self) -> None:
        adapter = ClaudeCodeAdapter(fake_probe(), [])
        boom = RuntimeError("SENTINEL_MSG_BOOM /home/alice/secret")
        with mock.patch.object(ClaudeCodeAdapter, "_scan", side_effect=boom):
            report = adapter.scan(AdapterContext(home="/home/alice"))
        self.assertEqual(len(report.problems), 1)
        self.assertNotIn("SENTINEL", report.problems[0])
        self.assertNotIn("alice", report.problems[0])
        self.assertFalse(report.harness.installed)


class SignatureTests(unittest.TestCase):
    def test_adapter_satisfies_the_protocol(self) -> None:
        adapter = ClaudeCodeAdapter()
        self.assertIsInstance(adapter, Adapter)
        self.assertEqual(adapter.id, "claude-code-cli")

    def test_process_signature(self) -> None:
        signature = ClaudeCodeAdapter().process_signature()
        self.assertEqual(signature.harness_id, "claude-code-cli")
        self.assertEqual(signature.executable_names, ("claude",))
        self.assertIn("/.local/share/claude/versions/", signature.path_markers)


if __name__ == "__main__":
    unittest.main()
