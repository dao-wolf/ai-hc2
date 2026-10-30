"""`hc2 scan`, `status` and `sessions` end to end, with privacy checks (T-4)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from typing import Any
from unittest import mock

from core_helpers import (
    CONFIDENTIAL_NAME,
    CONFIDENTIAL_TITLE,
    EXCEPTION_SENTINEL,
    FakeHome,
    FileAdapter,
    HangingAdapter,
    RaisingAdapter,
    everything_written,
    fake_home,
    registered,
    sample_rows,
)
from hc2 import cli
from hc2.commands import command_modules

SECRET_TERM = "sentinel codename"
TITLE_WITH_TERM = "Plan for the Sentinel Codename launch"


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def rows_with_term(fake: FakeHome) -> list[dict[str, object]]:
    rows = sample_rows(fake)
    rows.append(
        {
            "id": "sess-4",
            "title": TITLE_WITH_TERM,
            "folder": str(fake.home / "projects" / "plain"),
            "last": "2026-10-30T08:45:00Z",
            "state": "running-idle",
        }
    )
    return rows


def configured(fake: FakeHome) -> mock._patch_dict:  # type: ignore[type-arg]
    return mock.patch.dict(
        os.environ,
        {
            "HC2_CONFIDENTIAL_FOLDERS": fake.confidential,
            "HC2_CONFIDENTIAL_TERMS": SECRET_TERM,
        },
    )


class CommandRegistrationTests(unittest.TestCase):
    def test_every_command_module_registers_with_a_handler(self) -> None:
        names = [m.__name__.rsplit(".", 1)[-1] for m in command_modules()]
        self.assertEqual(names, ["doctor", "scan", "sessions", "status"])
        for name in names:
            with self.subTest(command=name):
                args = cli.build_parser().parse_args([name])
                self.assertTrue(callable(args.handler))

    def test_no_command_json_lists_the_commands(self) -> None:
        code, out, _ = run("--json")
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(out)["commands"], ["doctor", "scan", "sessions", "status"]
        )


class ScanCommandTests(unittest.TestCase):
    def test_scan_prints_a_plain_english_summary(self) -> None:
        with fake_home() as fake, registered(FileAdapter(), RaisingAdapter()):
            fake.write_sessions(sample_rows(fake))
            code, out, err = run("scan")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Scan finished.", out)
        self.assertIn("Overall: AMBER", out)
        self.assertIn("Fake Raises could not be checked", out)
        self.assertIn("Fake Files (fake-files): installed", out)
        self.assertIn("Fake Raises (fake-raises): unknown", out)

    def test_scan_json_has_the_status_fields_and_the_findings(self) -> None:
        with fake_home() as fake, registered(FileAdapter(), RaisingAdapter()):
            fake.write_sessions(sample_rows(fake))
            code, out, _ = run("scan", "--json")
        data: dict[str, Any] = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["schema"], 2)
        self.assertEqual(data["level"], "amber")
        self.assertEqual(len(data["findings"]), 1)
        self.assertFalse(data["config_changed"])

    def test_a_clean_scan_is_green(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("scan")
        self.assertIn("Overall: GREEN", out)

    def test_flags_beat_the_environment(self) -> None:
        hang = HangingAdapter()
        self.addCleanup(hang.release)
        with fake_home() as fake, registered(hang):
            with mock.patch.dict(os.environ, {"HC2_ADAPTER_TIMEOUT_SECONDS": "30"}):
                code, out, _ = run("scan", "--json", "--adapter-timeout", "0.2")
        self.assertEqual(code, 0)
        first = json.loads(out)["findings"][0]
        self.assertEqual(first["rule_id"], "adapter.unavailable")

    def test_disable_flag_skips_an_adapter(self) -> None:
        with fake_home() as fake, registered(FileAdapter(), RaisingAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("scan", "--json", "--disable-adapter", "fake-raises")
        data = json.loads(out)
        self.assertEqual([h["id"] for h in data["harnesses"]], ["fake-files"])
        self.assertEqual(data["level"], "green")

    def test_scan_in_an_unwritable_state_folder_is_a_plain_error(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.state_dir.parent.joinpath("state").write_text("a file")
            code, out, err = run("scan")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("could not open its history database", err)
        self.assertNotIn(str(fake.root), err)

    def test_json_error_for_the_same_failure(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.state_dir.parent.joinpath("state").write_text("a file")
            code, out, _ = run("scan", "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])


class StatusCommandTests(unittest.TestCase):
    def test_status_scans_once_when_there_is_no_scan(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            code, out, err = run("status")
            self.assertTrue((fake.state_dir / "hc2.db").exists())
        self.assertEqual(code, 0)
        self.assertIn("No earlier scan was found", err)
        self.assertIn("AI HC2 status", out)

    def test_status_json_stays_quiet_about_the_first_scan(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            _, _, err = run("status", "--json")
        self.assertEqual(err, "")

    def test_status_uses_the_stored_scan_without_running_adapters(self) -> None:
        adapter = FileAdapter()
        with fake_home() as fake, registered(adapter):
            fake.write_sessions(sample_rows(fake))
            run("scan")
            calls = len(adapter.seen_contexts)
            run("status")
            run("status", "--json")
            self.assertEqual(len(adapter.seen_contexts), calls)
            run("status", "--rescan")
            self.assertEqual(len(adapter.seen_contexts), calls + 1)

    def test_status_json_follows_the_api_fields(self) -> None:
        with fake_home() as fake, registered(FileAdapter(), RaisingAdapter()):
            fake.write_sessions(sample_rows(fake))
            run("scan")
            _, out, _ = run("status", "--json")
        data: dict[str, Any] = json.loads(out)
        expected = (
            "approvals changes content_hash counts generated harnesses level "
            "next_scan_at pressure scan_error scan_id scan_seconds scan_state "
            "schema top"
        ).split()
        self.assertEqual(sorted(data), expected)
        self.assertEqual(data["level"], "amber")
        self.assertEqual(
            data["counts"], {"acknowledged": 0, "amber": 1, "info": 0, "red": 0}
        )
        self.assertEqual(len(data["top"]), 1)
        top = data["top"][0]
        self.assertEqual(
            sorted(top), ["fix", "harness", "id", "sev", "title", "web_path"]
        )
        self.assertEqual(top["web_path"], "/findings/" + top["id"])
        self.assertEqual(data["changes"]["new_count"], 1)
        self.assertEqual(data["changes"]["fixed_count"], 0)
        self.assertIsNone(data["changes"]["since"])
        self.assertEqual(
            data["approvals"], {"oldest_at": None, "pending_count": 0, "top": []}
        )
        self.assertIsNone(data["pressure"])
        self.assertIsNone(data["scan_error"])
        self.assertEqual(data["scan_state"], "ok")
        by_id = {h["id"]: h for h in data["harnesses"]}
        self.assertEqual(by_id["fake-files"]["state"], "installed")
        self.assertEqual(by_id["fake-files"]["sessions_running"], 1)
        self.assertEqual(by_id["fake-files"]["sessions_stale"], 1)
        self.assertEqual(by_id["fake-raises"]["state"], "unknown")
        self.assertLess(len(out), 8 * 1024)

    def test_content_hash_ignores_times(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, first, _ = run("scan", "--json")
            _, second, _ = run("status", "--rescan", "--json")
        a, b = json.loads(first), json.loads(second)
        self.assertEqual(a["content_hash"], b["content_hash"])

    def test_content_hash_changes_when_findings_change(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            with registered(FileAdapter()):
                _, first, _ = run("scan", "--json")
            with registered(FileAdapter(), RaisingAdapter()):
                _, second, _ = run("scan", "--json")
        self.assertNotEqual(
            json.loads(first)["content_hash"], json.loads(second)["content_hash"]
        )

    def test_status_shows_what_changed_since_the_last_scan(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            with registered(FileAdapter(), RaisingAdapter()):
                run("scan")
            with registered(FileAdapter()):
                _, out, _ = run("scan", "--json")
                changes = json.loads(out)["changes"]
                _, plain, _ = run("status")
        self.assertEqual((changes["new_count"], changes["fixed_count"]), (0, 1))
        self.assertEqual(
            changes["fixed"][0]["title"], "Fake Raises could not be checked"
        )
        self.assertIsNotNone(changes["since"])
        self.assertIn("Fixed: [AMBER] Fake Raises could not be checked", plain)

    def test_acknowledged_findings_do_not_count_towards_the_level(self) -> None:
        import sqlite3

        with fake_home() as fake, registered(RaisingAdapter()):
            _, out, _ = run("scan", "--json")
            finding_id = json.loads(out)["findings"][0]["id"]
            conn = sqlite3.connect(fake.state_dir / "hc2.db")
            conn.execute(
                "INSERT INTO acknowledgements (finding_id, note, expires_at, "
                "acknowledged_at, actor) VALUES (?, 'seen', NULL, "
                "'2026-10-30T09:00:00Z', 'human:alice')",
                (finding_id,),
            )
            conn.commit()
            conn.close()
            _, out, _ = run("status", "--json")
        data = json.loads(out)
        self.assertEqual(data["level"], "green")
        self.assertEqual(data["counts"]["acknowledged"], 1)
        self.assertEqual(data["top"], [])


class SessionsCommandTests(unittest.TestCase):
    def test_sessions_table_lists_every_session(self) -> None:
        with fake_home() as fake, configured(fake), registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            code, out, _ = run("sessions")
        self.assertEqual(code, 0)
        self.assertIn("3 sessions from the scan at", out)
        self.assertIn("HARNESS", out)
        self.assertIn("Example Project", out)
        self.assertIn("~/projects/example-project", out)
        self.assertIn("Confidential A", out)
        self.assertIn("stale", out)

    def test_sessions_json_is_sorted_and_complete(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("sessions", "--json")
        data = json.loads(out)
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["filters"], {"harness": None, "state": None})
        ids = [s["id"] for s in data["sessions"]]
        self.assertEqual(ids, ["sess-1", "sess-3", "sess-2"])
        first = data["sessions"][0]
        keys = (
            "id harness_id title folder model created last_activity state origin "
            "confidential field_sources"
        ).split()
        for key in keys:
            self.assertIn(key, first)
        self.assertEqual(out, json.dumps(data, sort_keys=True, indent=2) + "\n")

    def test_state_filter(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("sessions", "--json", "--state", "stale")
            _, plain, _ = run("sessions", "--state", "ended")
        self.assertEqual([s["id"] for s in json.loads(out)["sessions"]], ["sess-2"])
        self.assertIn("0 sessions from the scan at", plain)
        self.assertIn("None match.", plain)

    def test_harness_filter(self) -> None:
        adapters = (FileAdapter("one-a", "One"), FileAdapter("two-b", "Two"))
        with fake_home() as fake, registered(*adapters):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("sessions", "--json", "--harness", "two-b")
        data = json.loads(out)
        self.assertEqual({s["harness_id"] for s in data["sessions"]}, {"two-b"})
        self.assertEqual(data["count"], 3)

    def test_an_unknown_harness_is_a_misuse_with_a_hint(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            code, out, _ = run("sessions", "--harness", "nope")
            jcode, jout, _ = run("sessions", "--json", "--harness", "nope")
        self.assertEqual(code, 2)
        self.assertIn("Harnesses in the last scan: fake-files.", out)
        self.assertEqual(jcode, 2)
        self.assertEqual(json.loads(jout)["harnesses"], ["fake-files"])

    def test_a_bad_state_value_is_rejected_by_the_parser(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.main(["sessions", "--state", "sleeping"])
        self.assertEqual(caught.exception.code, 2)

    def test_terminal_escape_codes_in_titles_do_not_reach_the_table(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            rows = sample_rows(fake)
            rows[0]["title"] = "Fine\x1b[2J\x1b[Hscreen wiped"
            fake.write_sessions(rows)
            _, out, _ = run("sessions")
            _, js, _ = run("sessions", "--json")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\\u001b", js)


class PrivacyTests(unittest.TestCase):
    """Sentinels planted in fixtures must never appear in any output (T-4)."""

    def everything(self, fake: FakeHome) -> tuple[str, list[str]]:
        outputs: list[str] = []
        with registered(FileAdapter(), RaisingAdapter(str(fake.home))):
            fake.write_sessions(rows_with_term(fake))
            commands = (
                "scan|scan --json|status|status --json|sessions|sessions --json|"
                "sessions --json --state unknown|sessions --harness fake-files|"
                "status --rescan|doctor"
            )
            for argv in (text.split() for text in commands.split("|")):
                code, out, err = run(*argv)
                self.assertIn(code, (0, 1), argv)
                outputs += [out, err]
        return "\n".join(outputs), outputs

    def test_no_sentinel_in_any_cli_output_snapshot_audit_or_database(self) -> None:
        with fake_home() as fake, configured(fake):
            rows = rows_with_term(fake)
            rows[1]["title"] = "Key " + "sk-" + "Q7" * 16
            fake.write_sessions(rows)
            shown, _ = self.everything(fake)
            stored = everything_written(fake)
            home = str(fake.home)
        sentinels = [
            CONFIDENTIAL_TITLE,
            CONFIDENTIAL_NAME,
            EXCEPTION_SENTINEL,
            SECRET_TERM,
            "Codename",
            "codename",
            "Q7Q7",
            home,
        ]
        for text, where in ((shown, "cli output"), (stored, "stored data")):
            for sentinel in sentinels:
                with self.subTest(where=where, sentinel=sentinel):
                    self.assertNotIn(sentinel, text)

    def test_masked_sessions_still_show_a_label(self) -> None:
        with fake_home() as fake, configured(fake):
            with registered(FileAdapter()):
                fake.write_sessions(rows_with_term(fake))
                _, out, _ = run("sessions", "--json")
        sessions = {s["id"]: s for s in json.loads(out)["sessions"]}
        self.assertEqual(sessions["sess-3"]["title"], "Confidential A")
        self.assertEqual(sessions["sess-4"]["title"], "Confidential (by title)")
        self.assertEqual(sessions["sess-4"]["folder"], "Confidential (by title)")
        self.assertTrue(sessions["sess-4"]["confidential"])
        self.assertEqual(sessions["sess-1"]["title"], "Example Project")

    def test_the_term_flag_masks_too(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(rows_with_term(fake))
            term = "Example Project"
            _, out, _ = run("sessions", "--json", "--confidential-term", term)
        titles = {s["id"]: s["title"] for s in json.loads(out)["sessions"]}
        self.assertEqual(titles["sess-1"], "Confidential (by title)")

    def test_terms_match_whole_words_only(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            rows = sample_rows(fake)
            rows[0]["title"] = "Starnet check"
            fake.write_sessions(rows)
            _, out, _ = run("sessions", "--json", "--confidential-term", "Tarn")
        titles = {s["id"]: s["title"] for s in json.loads(out)["sessions"]}
        self.assertEqual(titles["sess-1"], "Starnet check")

    def test_the_home_folder_is_shown_as_a_tilde(self) -> None:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            _, out, _ = run("sessions", "--json")
            home = str(fake.home)
        self.assertNotIn(home, out)
        self.assertIn("~/projects/example-project", out)


class DeterminismTests(unittest.TestCase):
    def sessions_json(self) -> str:
        with fake_home() as fake, registered(FileAdapter()):
            fake.write_sessions(sample_rows(fake))
            run("scan")
            _, out, _ = run("sessions", "--json")
        data = json.loads(out)
        del data["generated"]
        return json.dumps(data, sort_keys=True)

    def test_two_runs_over_the_same_fake_home_match_apart_from_times(self) -> None:
        self.assertEqual(self.sessions_json(), self.sessions_json())


if __name__ == "__main__":
    unittest.main()
