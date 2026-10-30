"""The rules over a whole recorded (made-up) machine."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from hc2.adapters.base import ProcessSignature
from hc2.collect import processes as P
from hc2.collect import system as S
from hc2.model import SessionState, Severity
from hc2.rules import resources as R

from . import fixture

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
SIGNATURES = (
    ProcessSignature("example-agent", path_markers=("/Example Agent.app/",)),
    ProcessSignature("agent-cli", executable_names=("agent-cli",)),
)


def scan(sessions: list[R.SessionActivity] | None = None) -> tuple[R.Finding, ...]:
    table = P.build_table(
        P.parse_ps(fixture("ps.txt")),
        now=NOW,
        signatures=SIGNATURES,
        ports=P.parse_listeners(fixture("lsof_listen.txt")),
    )
    reading = S.build_reading(
        sysctl=fixture("sysctl.txt"),
        vm_stat=fixture("vm_stat.txt"),
        memory_pressure=fixture("memory_pressure_q.txt"),
        pmset=fixture("pmset_therm_nominal.txt"),
    )
    return R.evaluate(
        reading,
        table.nodes,
        sessions or [],
        cpu_seconds=table.cpu_seconds,
        heavy_lock_present=True,
    )


class FixtureScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = scan()
        self.by_rule: dict[str, list[R.Finding]] = {}
        for finding in self.findings:
            self.by_rule.setdefault(finding.rule_id, []).append(finding)

    def test_which_rules_fire(self) -> None:
        self.assertEqual(
            sorted(self.by_rule),
            [
                R.RULE_CONCURRENT_TESTS,
                R.RULE_DUPLICATE_MCP,
                R.RULE_HEAVY_LOCK,
                R.RULE_HOT_CHILD,
                R.RULE_MEMORY_PRESSURE,
                R.RULE_ORPHAN,
                R.RULE_RENDERER_BLOAT,
            ],
        )

    def test_memory_pressure_reasons(self) -> None:
        finding = self.by_rule[R.RULE_MEMORY_PRESSURE][0]
        self.assertIs(finding.severity, Severity.AMBER)
        for part in ("swap is 50% used", "compressor holds 25%", "12%", "warning"):
            self.assertIn(part, finding.reason)

    def test_orphans_are_the_dev_server_and_the_automated_browser(self) -> None:
        titles = sorted(f.title for f in self.by_rule[R.RULE_ORPHAN])
        self.assertEqual(len(titles), 2)
        self.assertTrue(any("node process is still running on port 5173" in t
                            for t in titles))
        self.assertTrue(any("Chromium" in t for t in titles))
        for finding in self.by_rule[R.RULE_ORPHAN]:
            self.assertNotIn("Everyday Browser", finding.title)
            self.assertNotIn("young-script", finding.reason)

    def test_the_rest(self) -> None:
        self.assertEqual(len(self.by_rule[R.RULE_CONCURRENT_TESTS]), 1)
        self.assertIs(self.by_rule[R.RULE_DUPLICATE_MCP][0].severity, Severity.AMBER)
        # The watcher on port 9229 and the two vitest workers (63% over their life).
        self.assertEqual(len(self.by_rule[R.RULE_HOT_CHILD]), 2)
        # Under pressure, the 1.6 GB renderer is red.
        self.assertIs(self.by_rule[R.RULE_RENDERER_BLOAT][0].severity, Severity.RED)

    def test_session_rules_use_the_tree(self) -> None:
        # Pid 100 is the app; its tree is quiet.
        idle = R.SessionActivity(
            "s1", "agent-cli", SessionState.RUNNING_IDLE, 8 * 3600, 100
        )
        found = [f for f in scan([idle]) if f.rule_id == R.RULE_IDLE_SESSION]
        self.assertEqual(len(found), 1)
        # Pressure lifts an 8-hour idle session from info to amber.
        self.assertIs(found[0].severity, Severity.AMBER)

    def test_same_scan_twice_gives_the_same_ids(self) -> None:
        self.assertEqual([f.id for f in self.findings], [f.id for f in scan()])


if __name__ == "__main__":
    unittest.main()
