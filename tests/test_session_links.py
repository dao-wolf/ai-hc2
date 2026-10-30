"""Linking sessions to their processes, and the session rules that follow.

Everything here is made up. The process tables are hand-built or come from the
recorded fixtures, so no test samples this machine.
"""

from __future__ import annotations

import json
import unittest
from collections.abc import Sequence
from dataclasses import replace
from datetime import timedelta

from collect import fixture
from core_helpers import NOW, FakeHome, config_for, fake_home
from hc2.adapters.base import AdapterContext, AdapterReport, ProcessSignature
from hc2.commands.resources import scan_collector
from hc2.model import (
    Finding,
    Harness,
    ProcessNode,
    ProcessRole,
    Session,
    SessionState,
    Severity,
    SystemSample,
)
from hc2.rules import resources as rules
from hc2.scan import (
    Built,
    Collector,
    Resources,
    build_snapshot,
    iso,
    link_processes,
    run_scan,
    session_activities,
)
from hc2.store import Store
from hc2.summary import status_from_store

MB = 1024 * 1024
HOUR = 3600
SENTINEL_TITLE = "SENTINELTITLE-board-paper"
SENTINEL_FOLDER = "/home/alice/sentinel-link-folder"


def ago(seconds: float) -> str:
    return iso(NOW - timedelta(seconds=seconds))


def make_session(
    session_id: str,
    pid: int | None,
    *,
    state: SessionState = SessionState.RUNNING_IDLE,
    since: float | None = None,
    last: float | None = None,
    harness: str = "fake-linked",
) -> Session:
    return Session(
        id=session_id,
        harness_id=harness,
        title=SENTINEL_TITLE,
        folder=SENTINEL_FOLDER,
        last_activity=None if last is None else ago(last),
        state=state,
        pid=pid,
        state_since=None if since is None else ago(since),
    )


class LinkedAdapter:
    """Returns the sessions it was given."""

    def __init__(
        self, sessions: Sequence[Session], adapter_id: str = "fake-linked"
    ) -> None:
        self.id = adapter_id
        self.name = "Fake Linked"
        self._sessions = tuple(sessions)

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        harness = Harness(id=self.id, name=self.name, installed=True)
        return AdapterReport(harness, self._sessions, (), ("fake: id, pid",))

    def process_signature(self) -> ProcessSignature:
        return ProcessSignature(self.id, ("agent",))


def node(
    pid: int,
    parent: int | None = 1,
    *,
    mb: float = 0.0,
    cpu: float = 0.0,
    role: ProcessRole = ProcessRole.OTHER,
) -> ProcessNode:
    return ProcessNode(
        pid=pid,
        name="agent",
        parent_pid=parent,
        role=role,
        harness_id="fake-linked",
        memory_bytes=int(mb * MB),
        cpu_percent=cpu,
        fingerprint=f"fp{pid}",
    )


# Session one: 10 -> 11 -> 12. Session two: 30 -> 31. Nobody's: 20.
TABLE = (
    node(10, mb=100, cpu=0.5),
    node(11, 10, mb=200, cpu=0.5),
    node(12, 11, mb=300),
    node(20, mb=50),
    node(30, mb=10),
    node(31, 30, mb=20, cpu=1.0),
)


def collector_for(
    nodes: Sequence[ProcessNode],
    *,
    pressured: bool = False,
    calls: list[int] | None = None,
) -> Collector:
    def judge(
        raw: Sequence[ProcessNode], sessions: Sequence[rules.SessionActivity]
    ) -> tuple[Finding, ...]:
        if calls is not None:
            calls.append(len(sessions))
        return rules.evaluate_sessions(raw, sessions, pressured=pressured)

    def collect(_signatures: Sequence[ProcessSignature]) -> Resources:
        return Resources(
            SystemSample(sampled_at=iso(NOW)), tuple(nodes), (), session_rules=judge
        )

    return collect


def build(
    fake: FakeHome,
    sessions: Sequence[Session],
    nodes: Sequence[ProcessNode] = TABLE,
    *,
    pressured: bool = False,
    calls: list[int] | None = None,
) -> Built:
    return build_snapshot(
        config_for(fake),
        home=str(fake.home),
        adapters=[LinkedAdapter(sessions)],
        collector=collector_for(nodes, pressured=pressured, calls=calls),
        now=NOW,
    )


def by_rule(built: Built, rule_id: str) -> list[Finding]:
    return [f for f in built.snapshot.findings if f.rule_id == rule_id]


class LinkingTests(unittest.TestCase):
    def test_the_root_and_its_descendants_get_the_session_id(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10), make_session("b", 30)])
        linked = {p.pid: p.session_id for p in built.snapshot.processes}
        self.assertEqual(
            linked,
            {10: "a", 11: "a", 12: "a", 20: None, 30: "b", 31: "b"},
        )

    def test_a_pid_that_matches_two_sessions_goes_to_the_lowest_id(self) -> None:
        sessions = [make_session("zeta", 10), make_session("alpha", 10)]
        with fake_home() as fake:
            built = build(fake, sessions)
            reversed_ = build(fake, sessions[::-1])
        for result in (built, reversed_):
            linked = {p.pid: p.session_id for p in result.snapshot.processes}
            self.assertEqual({linked[10], linked[11], linked[12]}, {"alpha"})

    def test_a_nested_session_tree_is_claimed_once_by_the_lowest_id(self) -> None:
        activities = session_activities(
            [make_session("b", 10), make_session("a", 11)], NOW
        )
        self.assertEqual(
            link_processes(TABLE, activities), {10: "b", 11: "a", 12: "a"}
        )

    def test_a_pid_that_is_not_in_the_table_links_nothing(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 999)])
        self.assertEqual({p.session_id for p in built.snapshot.processes}, {None})

    def test_sessions_without_a_pid_link_nothing(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", None)])
        self.assertEqual({p.session_id for p in built.snapshot.processes}, {None})

    def test_the_session_keeps_its_pid_in_the_snapshot(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, since=60)])
        (report,) = built.snapshot.harnesses
        self.assertEqual(report.sessions[0].pid, 10)
        self.assertEqual(report.sessions[0].state_since, ago(60))


class ActivityTests(unittest.TestCase):
    def test_age_comes_from_state_since(self) -> None:
        (item,) = session_activities([make_session("a", 10, since=7 * HOUR)], NOW)
        self.assertEqual(item.state_age_seconds, 7 * HOUR)
        self.assertEqual(item.root_pid, 10)

    def test_age_falls_back_to_last_activity(self) -> None:
        (item,) = session_activities(
            [make_session("a", 10, last=8 * HOUR)], NOW
        )
        self.assertEqual(item.state_age_seconds, 8 * HOUR)

    def test_state_since_beats_last_activity(self) -> None:
        (item,) = session_activities(
            [make_session("a", 10, since=7 * HOUR, last=HOUR)], NOW
        )
        self.assertEqual(item.state_age_seconds, 7 * HOUR)

    def test_age_is_none_when_both_times_are_missing(self) -> None:
        (item,) = session_activities([make_session("a", 10)], NOW)
        self.assertIsNone(item.state_age_seconds)

    def test_a_bad_time_counts_as_missing_and_a_future_time_as_zero(self) -> None:
        bad = replace(make_session("a", 10), state_since="soon", last_activity=None)
        future = make_session("b", 11, since=-HOUR)
        first, second = session_activities([bad, future], NOW)
        self.assertIsNone(first.state_age_seconds)
        self.assertEqual(second.state_age_seconds, 0)

    def test_only_sessions_with_a_pid_are_listed(self) -> None:
        found = session_activities(
            [make_session("a", None), make_session("b", 5)], NOW
        )
        self.assertEqual([i.session_id for i in found], ["b"])


class SessionRuleTests(unittest.TestCase):
    def test_an_idle_session_holding_memory_raises_the_idle_finding(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, since=7 * HOUR)])
        (finding,) = by_rule(built, rules.RULE_IDLE_SESSION)
        self.assertIs(finding.severity, Severity.INFO)
        self.assertEqual(finding.session_id, "a")
        self.assertEqual(finding.harness_id, "fake-linked")
        self.assertIn("3 processes", finding.reason)
        self.assertIn("600 MB", finding.reason)

    def test_a_long_idle_session_is_amber(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, since=25 * HOUR)])
        (finding,) = by_rule(built, rules.RULE_IDLE_SESSION)
        self.assertIs(finding.severity, Severity.AMBER)

    def test_pressure_from_the_collector_lifts_the_severity(self) -> None:
        with fake_home() as fake:
            built = build(
                fake, [make_session("a", 10, since=7 * HOUR)], pressured=True
            )
        (finding,) = by_rule(built, rules.RULE_IDLE_SESSION)
        self.assertIs(finding.severity, Severity.AMBER)

    def test_a_session_marked_stale_still_counts_as_idle(self) -> None:
        # The default stale limit is 2 hours, so this session is shown as stale.
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, since=7 * HOUR, last=7 * HOUR)])
        (report,) = built.snapshot.harnesses
        self.assertIs(report.sessions[0].state, SessionState.STALE)
        self.assertEqual(len(by_rule(built, rules.RULE_IDLE_SESSION)), 1)

    def test_last_activity_is_used_when_there_is_no_status_time(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, last=7 * HOUR)])
        self.assertEqual(len(by_rule(built, rules.RULE_IDLE_SESSION)), 1)

    def test_a_session_with_no_times_never_raises_the_idle_finding(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10)])
        self.assertEqual(by_rule(built, rules.RULE_IDLE_SESSION), [])

    def test_a_session_with_no_pid_never_raises_a_session_finding(self) -> None:
        sessions = [
            make_session("a", None, since=30 * HOUR),
            make_session("b", None, state=SessionState.RUNNING_BUSY, since=3 * HOUR),
        ]
        with fake_home() as fake:
            built = build(fake, sessions)
        self.assertEqual(by_rule(built, rules.RULE_IDLE_SESSION), [])
        self.assertEqual(by_rule(built, rules.RULE_BUSY_QUIET), [])

    def test_a_recently_idle_session_raises_nothing(self) -> None:
        with fake_home() as fake:
            built = build(fake, [make_session("a", 10, since=HOUR)])
        self.assertEqual(by_rule(built, rules.RULE_IDLE_SESSION), [])

    def test_a_busy_session_with_a_quiet_tree_raises_the_busy_finding(self) -> None:
        busy = make_session("a", 10, state=SessionState.RUNNING_BUSY, since=HOUR)
        with fake_home() as fake:
            built = build(fake, [busy])
        (finding,) = by_rule(built, rules.RULE_BUSY_QUIET)
        self.assertIs(finding.severity, Severity.INFO)
        self.assertEqual(finding.session_id, "a")

    def test_the_session_rules_run_once_with_every_pid_session(self) -> None:
        calls: list[int] = []
        sessions = [
            make_session("a", 10),
            make_session("b", 30),
            make_session("c", None),
        ]
        with fake_home() as fake:
            build(fake, sessions, calls=calls)
        self.assertEqual(calls, [2])

    def test_no_session_with_a_pid_means_the_rules_are_not_called(self) -> None:
        calls: list[int] = []
        with fake_home() as fake:
            build(fake, [make_session("c", None)], calls=calls)
        self.assertEqual(calls, [])

    def test_a_failing_session_rule_is_a_finding_not_a_crash(self) -> None:
        def broken(
            _nodes: Sequence[ProcessNode],
            _sessions: Sequence[rules.SessionActivity],
        ) -> tuple[Finding, ...]:
            raise RuntimeError(f"{SENTINEL_FOLDER} {SENTINEL_TITLE}")

        def collect(_signatures: Sequence[ProcessSignature]) -> Resources:
            return Resources(None, TABLE, (), session_rules=broken)

        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[LinkedAdapter([make_session("a", 10, since=9 * HOUR)])],
                collector=collect,
                now=NOW,
            )
        (finding,) = by_rule(built, "collector.unavailable")
        self.assertIs(finding.severity, Severity.AMBER)
        # The exception text is never copied into the finding.
        text = json.dumps(finding.to_dict())
        self.assertNotIn("sentinel", text.lower())
        self.assertNotIn("/home/", text)
        # The processes are still linked even though the rules failed.
        linked = {p.pid: p.session_id for p in built.snapshot.processes}
        self.assertEqual(linked[11], "a")


class PrivacyAndDeterminismTests(unittest.TestCase):
    def test_no_title_or_path_reaches_the_new_findings_or_nodes(self) -> None:
        sessions = [
            make_session("a", 10, since=30 * HOUR),
            make_session("b", 30, state=SessionState.RUNNING_BUSY, since=2 * HOUR),
        ]
        with fake_home() as fake:
            built = build(fake, sessions)
        findings = [
            f
            for f in built.snapshot.findings
            if f.rule_id in (rules.RULE_IDLE_SESSION, rules.RULE_BUSY_QUIET)
        ]
        self.assertEqual(len(findings), 2)
        text = json.dumps([f.to_dict() for f in findings])
        text += json.dumps([p.to_dict() for p in built.snapshot.processes])
        for leak in ("SENTINEL", "sentinel", "/home/", "alice"):
            self.assertNotIn(leak, text)

    def test_the_same_inputs_give_the_same_bytes_in_any_order(self) -> None:
        sessions = [
            make_session("a", 10, since=30 * HOUR),
            make_session("b", 30, state=SessionState.RUNNING_BUSY, since=2 * HOUR),
            make_session("c", None, since=9 * HOUR),
        ]
        with fake_home() as fake:
            first = build(fake, sessions)
            second = build(fake, sessions[::-1], TABLE[::-1])
        self.assertEqual(first.snapshot.to_json(), second.snapshot.to_json())
        self.assertEqual(first.content_hash, second.content_hash)
        self.assertEqual(first.snapshot.scan_id, second.snapshot.scan_id)

    def test_finding_ids_hold_no_pid(self) -> None:
        with fake_home() as fake:
            a = build(fake, [make_session("a", 10, since=9 * HOUR)])
            b = build(
                fake,
                [make_session("a", 30, since=9 * HOUR)],
                (node(30, mb=100), node(31, 30)),
            )
        (first,) = by_rule(a, rules.RULE_IDLE_SESSION)
        (second,) = by_rule(b, rules.RULE_IDLE_SESSION)
        self.assertEqual(first.id, second.id)


class RealCollectorTests(unittest.TestCase):
    """`scan_collector` with the recorded command outputs, never the real Mac."""

    OUTPUTS = {
        "ps": "ps.txt",
        "lsof": "lsof_listen.txt",
        "ioreg": "ioreg_agx.txt",
        "sysctl": "sysctl.txt",
        "vm_stat": "vm_stat.txt",
        "memory_pressure": "memory_pressure_q.txt",
        "pmset": "pmset_therm_nominal.txt",
    }

    @staticmethod
    def runner(argv: Sequence[str], timeout: float) -> str | None:
        return fixture(RealCollectorTests.OUTPUTS[argv[0]])

    signatures = (
        ProcessSignature("example-agent", path_markers=("/Example Agent.app/",)),
        ProcessSignature("agent-cli", executable_names=("agent-cli",)),
    )

    def resources(self, fake: FakeHome) -> Resources:
        collect = scan_collector(config_for(fake), runner=self.runner)
        return collect(self.signatures)

    def test_the_collector_alone_finds_no_session_problems(self) -> None:
        with fake_home() as fake:
            resources = self.resources(fake)
        self.assertIsNotNone(resources.session_rules)
        ids = {f.rule_id for f in resources.findings}
        self.assertFalse(ids & {rules.RULE_IDLE_SESSION, rules.RULE_BUSY_QUIET})

    def test_the_scan_adds_the_session_finding_once_under_pressure(self) -> None:
        session = make_session("a", 100, since=8 * HOUR, harness="example-agent")
        with fake_home() as fake:
            built = build_snapshot(
                config_for(fake),
                home=str(fake.home),
                adapters=[LinkedAdapter([session], "example-agent")],
                collector=scan_collector(config_for(fake), runner=self.runner),
                now=NOW,
            )
        (finding,) = by_rule(built, rules.RULE_IDLE_SESSION)
        # The recorded memory reading is under pressure, so 8 hours is amber.
        self.assertIs(finding.severity, Severity.AMBER)
        self.assertEqual(finding.session_id, "a")
        linked = {p.pid for p in built.snapshot.processes if p.session_id == "a"}
        self.assertEqual(linked, {100, 101})


if __name__ == "__main__":
    unittest.main()
