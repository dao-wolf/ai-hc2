"""The scan: isolation, timeouts, findings, diffs, audit events and privacy."""

from __future__ import annotations

import json
import sqlite3
import time
import unittest
from collections.abc import Sequence
from datetime import datetime, timedelta

from core_helpers import (
    CONFIDENTIAL_NAME,
    CONFIDENTIAL_TITLE,
    EXCEPTION_SENTINEL,
    NOW,
    FakeHome,
    FileAdapter,
    HangingAdapter,
    RaisingAdapter,
    WrongTypeAdapter,
    config_for,
    everything_written,
    fake_home,
    registered,
    sample_rows,
)
from hc2.adapters.base import Adapter, ProcessSignature
from hc2.audit import AuditLog
from hc2.model import (
    Finding,
    ProcessNode,
    SessionState,
    Severity,
    SystemSample,
)
from hc2.scan import Resources, ScanResult, build_snapshot, run_scan
from hc2.store import Store


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


class IsolationTests(unittest.TestCase):
    def test_a_raising_adapter_becomes_unknown_with_a_plain_problem(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            adapters = [FileAdapter(), RaisingAdapter(str(fake.home))]
            built = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=adapters, now=NOW
            )
        reports = {r.harness.id: r for r in built.snapshot.harnesses}
        bad = reports["fake-raises"]
        self.assertIsNone(bad.harness.installed)
        self.assertEqual(
            bad.problems,
            ("Fake Raises could not be checked because of an unexpected error.",),
        )
        self.assertTrue(reports["fake-files"].harness.installed)
        self.assertEqual(len(reports["fake-files"].sessions), 3)
        text = built.snapshot.to_json()
        self.assertNotIn(EXCEPTION_SENTINEL, text)
        self.assertNotIn(CONFIDENTIAL_NAME, text)
        self.assertNotIn("/home/", text)

    def test_a_hanging_adapter_times_out_and_the_scan_goes_on(self) -> None:
        hang = HangingAdapter()
        self.addCleanup(hang.release)
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            config = config_for(fake, timeout=0.3)
            started = time.monotonic()
            built = build_snapshot(
                config, home=str(fake.home), adapters=[hang, FileAdapter()], now=NOW
            )
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0)
        reports = {r.harness.id: r for r in built.snapshot.harnesses}
        self.assertIsNone(reports["fake-hangs"].harness.installed)
        self.assertEqual(
            reports["fake-hangs"].problems,
            (
                "Fake Hangs could not be checked because it took longer "
                "than 0.3 seconds.",
            ),
        )
        self.assertEqual(len(reports["fake-files"].sessions), 3)

    def test_several_hanging_adapters_share_one_timeout(self) -> None:
        hangs = [HangingAdapter() for _ in range(3)]
        for index, adapter in enumerate(hangs):
            adapter.id = f"hang-{index}"
            self.addCleanup(adapter.release)
        with fake_home() as fake:
            started = time.monotonic()
            build_snapshot(
                config_for(fake, timeout=0.4),
                home=str(fake.home),
                adapters=hangs,
                now=NOW,
            )
            self.assertLess(time.monotonic() - started, 1.2)

    def test_wrong_return_type_is_a_failure_not_a_crash(self) -> None:
        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[WrongTypeAdapter()],
                now=NOW,
            )
        (report,) = built.snapshot.harnesses
        self.assertIn("returned data HC2 cannot use", report.problems[0])
        self.assertEqual(rules(built.snapshot.findings), ["adapter.unavailable"])

    def test_failures_become_amber_findings_with_a_fix(self) -> None:
        hang = HangingAdapter()
        self.addCleanup(hang.release)
        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake, timeout=0.2),
                home=str(fake.home),
                adapters=[RaisingAdapter(), hang],
                now=NOW,
            )
        findings = built.snapshot.findings
        self.assertEqual(rules(findings), ["adapter.unavailable"] * 2)
        for item in findings:
            self.assertEqual(item.severity, Severity.AMBER)
            self.assertTrue(item.fix)
            self.assertNotIn("/", item.id)
        titles = sorted(f.title for f in findings)
        self.assertEqual(
            titles,
            ["Fake Hangs could not be checked", "Fake Raises could not be checked"],
        )
        timeout_fix = next(f for f in findings if "Hangs" in f.title).fix
        self.assertIn("adapter_timeout_seconds", timeout_fix)

    def test_adapter_problems_become_findings(self) -> None:
        adapter = FileAdapter()
        adapter.problems = ("Session index format not recognised (version 3).",)
        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[adapter], now=NOW
            )
        (item,) = built.snapshot.findings
        self.assertEqual(item.rule_id, "adapter.problem")
        self.assertEqual(item.harness_id, "fake-files")
        self.assertIn("Session index format not recognised", item.title)

    def test_problem_text_is_redacted(self) -> None:
        adapter = FileAdapter()
        with fake_home() as fake:
            adapter.problems = (f"Could not read {fake.confidential}/index.",)
            built = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[adapter], now=NOW
            )
        text = built.snapshot.to_json()
        self.assertNotIn(CONFIDENTIAL_NAME, text)
        self.assertIn("Confidential A", text)

    def test_disabled_adapters_do_not_run(self) -> None:
        on, off = FileAdapter("on-one", "On"), FileAdapter("off-one", "Off")
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            config = config_for(
                fake,
                extra=lambda o: type(o)(
                    **{**o.__dict__, "disable_adapters": ("off-one",)}
                ),
            )
            built = build_snapshot(
                config, home=str(fake.home), adapters=[on, off], now=NOW
            )
        self.assertEqual([r.harness.id for r in built.snapshot.harnesses], ["on-one"])
        self.assertEqual(off.seen_contexts, [])

    def test_the_default_adapters_come_from_the_registry_at_call_time(self) -> None:
        adapter = FileAdapter()
        with fake_home() as fake, registered(adapter):
            built = build_snapshot(config_for(fake), home=str(fake.home), now=NOW)
        ids = [r.harness.id for r in built.snapshot.harnesses]
        self.assertEqual(ids, ["fake-files"])

    def test_adapters_get_the_home_and_absolute_confidential_folders(self) -> None:
        adapter = FileAdapter()
        with fake_home() as fake:
            build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[adapter], now=NOW
            )
            (ctx,) = adapter.seen_contexts
            self.assertEqual(ctx.home, str(fake.home))
            self.assertEqual(ctx.confidential_folders, (fake.confidential,))
            self.assertFalse(ctx.network)


class SessionTests(unittest.TestCase):
    def build(self, stale_hours: float = 2.0) -> Snapshot:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            return build_snapshot(
                config_for(fake, stale_hours=stale_hours),
                home=str(fake.home),
                adapters=[FileAdapter()],
                now=NOW,
            ).snapshot

    def test_idle_sessions_past_the_limit_become_stale(self) -> None:
        snapshot = self.build()
        states = {s.id: s for s in snapshot.harnesses[0].sessions}
        self.assertEqual(states["sess-1"].state, SessionState.RUNNING_IDLE)
        self.assertEqual(states["sess-2"].state, SessionState.STALE)
        self.assertEqual(states["sess-3"].state, SessionState.UNKNOWN)
        marks = [f for f in states["sess-2"].field_sources if f.field == "state"]
        self.assertEqual(len(marks), 1)

    def test_the_limit_is_configurable(self) -> None:
        snapshot = self.build(stale_hours=0.25)
        states = {s.id: s.state for s in snapshot.harnesses[0].sessions}
        self.assertEqual(states["sess-1"], SessionState.STALE)
        # A session whose liveness is unknown is never called stale.
        self.assertEqual(states["sess-3"], SessionState.UNKNOWN)

    def test_busy_and_ended_sessions_are_never_made_stale(self) -> None:
        with fake_home() as fake:
            rows = sample_rows(fake)
            rows[0]["state"] = "running-busy"
            rows[0]["last"] = "2026-01-01T00:00:00Z"
            rows[1]["state"] = "ended"
            fake.write_sessions(rows)
            snapshot = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[FileAdapter()], now=NOW
            ).snapshot
        states = {s.id: s.state for s in snapshot.harnesses[0].sessions}
        self.assertEqual(states["sess-1"], SessionState.RUNNING_BUSY)
        self.assertEqual(states["sess-2"], SessionState.ENDED)

    def test_sessions_without_a_usable_time_are_left_alone(self) -> None:
        with fake_home() as fake:
            rows = sample_rows(fake)
            rows[0]["last"] = "not a time"
            fake.write_sessions(rows)
            snapshot = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[FileAdapter()], now=NOW
            ).snapshot
        states = {s.id: s.state for s in snapshot.harnesses[0].sessions}
        self.assertEqual(states["sess-1"], SessionState.RUNNING_IDLE)

    def test_sessions_are_newest_first_then_by_id(self) -> None:
        snapshot = self.build()
        ids = [s.id for s in snapshot.harnesses[0].sessions]
        self.assertEqual(ids, ["sess-1", "sess-3", "sess-2"])

    def test_confidential_sessions_are_masked_in_the_snapshot(self) -> None:
        snapshot = self.build()
        sessions = {s.id: s for s in snapshot.harnesses[0].sessions}
        self.assertEqual(sessions["sess-3"].title, "Confidential A")
        self.assertEqual(sessions["sess-3"].folder, "Confidential A")
        self.assertEqual(sessions["sess-1"].folder, "~/projects/example-project")
        text = snapshot.to_json()
        self.assertNotIn(CONFIDENTIAL_TITLE, text)
        self.assertNotIn(CONFIDENTIAL_NAME, text)


class DeterminismTests(unittest.TestCase):
    def snapshot_json(self) -> str:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            result = run_scan(
                config_for(fake),
                home=str(fake.home),
                state=fake.state_dir,
                adapters=[FileAdapter(), RaisingAdapter()],
                clock=lambda: NOW,
            )
            return result.snapshot.to_json()

    def test_two_scans_of_the_same_fake_home_give_identical_json(self) -> None:
        first = self.snapshot_json()
        second = self.snapshot_json()
        self.assertEqual(first, second)

    def test_adapter_order_does_not_matter(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            a = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[FileAdapter("b-one", "B"), FileAdapter("a-one", "A")],
                now=NOW,
            )
            b = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[FileAdapter("a-one", "A"), FileAdapter("b-one", "B")],
                now=NOW,
            )
        self.assertEqual(a.snapshot.to_json(), b.snapshot.to_json())

    def test_only_the_generated_time_differs_between_clock_times(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            config = config_for(fake)
            home = str(fake.home)
            a = build_snapshot(config, home=home, adapters=[FileAdapter()], now=NOW)
            later = NOW + timedelta(seconds=30)
            b = build_snapshot(config, home=home, adapters=[FileAdapter()], now=later)
        da, db = a.snapshot.to_dict(), b.snapshot.to_dict()
        self.assertNotEqual(da["generated"], db["generated"])
        da.pop("generated")
        db.pop("generated")
        self.assertEqual(da, db)
        self.assertEqual(a.snapshot.scan_id, b.snapshot.scan_id)
        self.assertEqual(a.content_hash, b.content_hash)

    def test_ids_hold_no_clock_time_and_no_path(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            result = run_scan(
                config_for(fake),
                home=str(fake.home),
                state=fake.state_dir,
                adapters=[RaisingAdapter()],
                clock=lambda: NOW,
            )
        for item in result.snapshot.findings:
            self.assertRegex(item.id, r"^finding_[0-9a-f]{16}$")
        self.assertRegex(result.snapshot.scan_id, r"^scan_[0-9a-f]{16}$")

    def test_a_different_scan_gets_a_different_id(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            cfg = config_for(fake)
            home = str(fake.home)
            first = build_snapshot(cfg, home=home, adapters=[FileAdapter()], now=NOW)
            rows = sample_rows(fake)
            rows[0]["title"] = "Another"
            fake.write_sessions(rows)
            second = build_snapshot(cfg, home=home, adapters=[FileAdapter()], now=NOW)
        self.assertNotEqual(first.snapshot.scan_id, second.snapshot.scan_id)


class RunScanTests(unittest.TestCase):
    def scan(
        self, fake: FakeHome, adapters: list[Adapter], moment: datetime = NOW
    ) -> ScanResult:
        return run_scan(
            config_for(fake),
            home=str(fake.home),
            state=fake.state_dir,
            adapters=adapters,
            clock=lambda: moment,
        )

    def audit_events(self, fake: FakeHome) -> list[dict[str, object]]:
        log = AuditLog(fake.state_dir / "audit")
        rows: list[dict[str, object]] = []
        for path in log.files():
            rows += [json.loads(x) for x in path.read_text().splitlines()]
        return rows

    def events_named(self, fake: FakeHome, name: str) -> list[dict[str, object]]:
        return [e for e in self.audit_events(fake) if e["eventName"] == name]

    def test_a_scan_stores_a_snapshot_history_and_audit_events(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            result = self.scan(fake, [FileAdapter(), RaisingAdapter()])
            with Store.create(fake.state_dir) as store:
                self.assertEqual(store.last_scan(), result.record)
                self.assertEqual(store.latest_snapshot(), result.snapshot)
            names = [e["eventName"] for e in self.audit_events(fake)]
            self.assertEqual(names, ["hc2.scan.completed", "hc2.finding.new"])
            self.assertTrue(AuditLog(fake.state_dir / "audit").verify_chain().ok)

    def test_every_audit_body_is_a_plain_sentence_and_shares_one_trace(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            self.scan(fake, [FileAdapter(), RaisingAdapter()])
            events = self.audit_events(fake)
        traces = {e["traceId"] for e in events}
        self.assertEqual(len(traces), 1)
        self.assertRegex(str(next(iter(traces))), r"^[0-9a-f]{32}$")
        for event in events:
            body = str(event["body"])
            self.assertTrue(body.endswith("."), body)
            self.assertNotIn("/", body)
        self.assertIn(
            "Scan finished: checked 2 harnesses, found 3 sessions",
            str(events[0]["body"]),
        )

    def test_new_and_fixed_findings_are_diffed_and_audited(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            first = self.scan(fake, [FileAdapter(), RaisingAdapter()])
            self.assertEqual(len(first.new_findings), 1)
            hour = NOW + timedelta(hours=1)
            same = self.scan(fake, [FileAdapter(), RaisingAdapter()], hour)
            self.assertEqual((same.new_findings, same.fixed_findings), ((), ()))
            fixed = self.scan(fake, [FileAdapter()], NOW + timedelta(hours=2))
            self.assertEqual(len(fixed.fixed_findings), 1)
            self.assertEqual(
                fixed.fixed_findings[0].title, "Fake Raises could not be checked"
            )
            names = [e["eventName"] for e in self.audit_events(fake)]
            self.assertEqual(names.count("hc2.finding.new"), 1)
            self.assertEqual(names.count("hc2.finding.resolved"), 1)
            self.assertEqual(names.count("hc2.scan.completed"), 3)
            resolved = self.events_named(fake, "hc2.finding.resolved")
            self.assertIn("no longer present", str(resolved[0]["body"]))

    def test_a_changed_config_raises_a_finding_and_an_event(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            fake.write_config("[audit]\nretention_days = 30\n")
            first = self.scan(fake, [FileAdapter()])
            self.assertFalse(first.config_changed)
            self.assertEqual(first.snapshot.findings, ())
            fake.write_config("[audit]\nretention_days = 29\n")
            second = self.scan(fake, [FileAdapter()], NOW + timedelta(hours=1))
            self.assertTrue(second.config_changed)
            self.assertEqual(rules(second.snapshot.findings), ["config.changed"])
            third = self.scan(fake, [FileAdapter()], NOW + timedelta(hours=2))
            self.assertFalse(third.config_changed)
            events = self.events_named(fake, "hc2.config.changed")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["severityText"], "WARN")

    def test_the_first_scan_never_reports_a_config_change(self) -> None:
        with fake_home() as fake:
            fake.write_config("[audit]\nretention_days = 12\n")
            result = self.scan(fake, [FileAdapter()])
        self.assertFalse(result.config_changed)

    def test_config_problems_become_findings(self) -> None:
        with fake_home() as fake:
            fake.write_config("[scan]\nadapter_timeout_seconds = -3\n")
            from hc2.config import load_config

            config = load_config(path=fake.config_dir / "config.toml", env={})
            built = build_snapshot(config, home=str(fake.home), adapters=[], now=NOW)
        self.assertEqual(rules(built.snapshot.findings), ["config.invalid"])

    def test_a_broken_audit_chain_raises_a_red_finding(self) -> None:
        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            self.scan(fake, [FileAdapter(), RaisingAdapter()])
            path = AuditLog(fake.state_dir / "audit").files()[0]
            path.write_text(path.read_text().replace("Scan finished", "Scan edited"))
            hour = NOW + timedelta(hours=1)
            result = self.scan(fake, [FileAdapter(), RaisingAdapter()], hour)
        findings = result.snapshot.findings
        red = [f for f in findings if f.severity is Severity.RED]
        self.assertEqual([f.rule_id for f in red], ["audit.chain_broken"])
        self.assertIn("line 1", red[0].reason)

    def test_collector_data_lands_in_the_snapshot_redacted_and_sorted(self) -> None:
        seen: list[ProcessSignature] = []

        def collector(signatures: Sequence[ProcessSignature]) -> Resources:
            seen.extend(signatures)
            return Resources(
                SystemSample(sampled_at="2026-10-30T09:00:00Z", load_1m=1.5),
                (
                    ProcessNode(pid=20, name="/home/alice/bin/tool"),
                    ProcessNode(pid=3, name="node"),
                ),
            )

        with fake_home() as fake:
            fake.write_sessions(sample_rows(fake))
            result = run_scan(
                config_for(fake),
                home=str(fake.home),
                state=fake.state_dir,
                adapters=[FileAdapter()],
                collector=collector,
                clock=lambda: NOW,
            )
        snap = result.snapshot
        self.assertEqual(seen, [ProcessSignature("fake-files", ("fake",))])
        self.assertEqual(snap.system, SystemSample("2026-10-30T09:00:00Z", load_1m=1.5))
        nodes = [(p.pid, p.name) for p in snap.processes]
        self.assertEqual(nodes, [(3, "node"), (20, "tool")])

    def test_a_failing_collector_is_a_finding_not_a_crash(self) -> None:
        def collector(signatures: Sequence[ProcessSignature]) -> Resources:
            raise OSError(f"/home/alice/{CONFIDENTIAL_NAME}")

        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[FileAdapter()],
                collector=collector,
                now=NOW,
            )
        self.assertEqual(rules(built.snapshot.findings), ["collector.unavailable"])
        self.assertIsNone(built.snapshot.system)
        self.assertNotIn(CONFIDENTIAL_NAME, built.snapshot.to_json())

    def test_no_collector_leaves_resources_empty(self) -> None:
        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake), home=str(fake.home), adapters=[], now=NOW
            )
        self.assertIsNone(built.snapshot.system)
        self.assertEqual(built.snapshot.processes, ())

    def test_nothing_sensitive_reaches_any_stored_file_or_row(self) -> None:
        with fake_home() as fake:
            rows = sample_rows(fake)
            secret = "sk-" + "Q7" * 16 + " for carol" + "@" + "sentinel-mail.org"
            rows[0]["title"] = "Key " + secret
            fake.write_sessions(rows)
            self.scan(fake, [FileAdapter(), RaisingAdapter(str(fake.home))])
            self.scan(fake, [FileAdapter()], NOW + timedelta(hours=1))
            stored = everything_written(fake)
            home = str(fake.home)
        for sentinel in (
            CONFIDENTIAL_TITLE,
            CONFIDENTIAL_NAME,
            EXCEPTION_SENTINEL,
            "Q7Q7Q7",
            "sentinel-mail",
            home,
        ):
            with self.subTest(sentinel=sentinel):
                self.assertNotIn(sentinel, stored)
        self.assertIn("Confidential A", stored)

    def test_the_database_is_the_only_place_findings_history_lives(self) -> None:
        with fake_home() as fake:
            self.scan(fake, [RaisingAdapter()])
            conn = sqlite3.connect(fake.state_dir / "hc2.db")
            rows = conn.execute("SELECT rule_id, title FROM findings").fetchall()
            conn.close()
        self.assertEqual(
            rows, [("adapter.unavailable", "Fake Raises could not be checked")]
        )


if __name__ == "__main__":
    unittest.main()
