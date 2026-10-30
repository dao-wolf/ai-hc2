"""Threshold-edge tests for the resource rules, using hand-made inputs."""

from __future__ import annotations

import unittest
from typing import Any

from hc2.collect.system import SystemReading
from hc2.model import ProcessNode, ProcessRole, SessionState, Severity, SystemSample
from hc2.rules import resources as R

MB = R.MB
R_ = ProcessRole


def reading(
    *,
    swap_used: int | None = None,
    swap_total: int | None = 10_000,
    compressor: int | None = None,
    ram: int | None = 1_000,
    free: int | None = None,
    level: str | None = None,
) -> SystemReading:
    return SystemReading(
        sample=SystemSample(memory_total_bytes=ram, swap_used_bytes=swap_used),
        swap_total_bytes=swap_total,
        compressor_bytes=compressor,
        free_percent=free,
        kernel_level=level,
    )


def node(
    pid: int,
    name: str = "node",
    *,
    ppid: int | None = 1,
    role: ProcessRole = R_.OTHER,
    cpu: float = 0.0,
    mb: float = 0.0,
    minutes: float = 0.0,
    harness: str | None = None,
    ports: tuple[int, ...] = (),
    fp: str | None = None,
) -> ProcessNode:
    return ProcessNode(
        pid=pid,
        name=name,
        parent_pid=ppid,
        role=role,
        cpu_percent=cpu,
        memory_bytes=int(mb * MB),
        age_seconds=int(minutes * 60),
        harness_id=harness,
        listening_ports=ports,
        fingerprint=fp or f"fp{pid}",
    )


def run(
    nodes: list[ProcessNode] | None = None,
    sys_reading: SystemReading | None = None,
    sessions: list[R.SessionActivity] | None = None,
    **kwargs: Any,
) -> tuple[R.Finding, ...]:
    return R.evaluate(
        sys_reading or reading(), nodes or [], sessions or [], **kwargs
    )


def only(findings: tuple[R.Finding, ...], rule: str) -> list[R.Finding]:
    return [f for f in findings if f.rule_id == rule]


class MemoryPressureTests(unittest.TestCase):
    def severity(self, **kwargs: Any) -> Severity | None:
        found = only(run(sys_reading=reading(**kwargs)), R.RULE_MEMORY_PRESSURE)
        self.assertLessEqual(len(found), 1)
        return found[0].severity if found else None

    def test_swap_edges(self) -> None:
        self.assertIsNone(self.severity(swap_used=4999))
        self.assertIs(self.severity(swap_used=5000), Severity.AMBER)
        self.assertIs(self.severity(swap_used=7999), Severity.AMBER)
        self.assertIs(self.severity(swap_used=8000), Severity.RED)
        self.assertIs(self.severity(swap_used=10_000), Severity.RED)

    def test_compressor_edges(self) -> None:
        self.assertIsNone(self.severity(compressor=249))
        self.assertIs(self.severity(compressor=250), Severity.AMBER)

    def test_free_memory_edges(self) -> None:
        self.assertIsNone(self.severity(free=15))
        self.assertIs(self.severity(free=14), Severity.AMBER)

    def test_kernel_levels(self) -> None:
        self.assertIsNone(self.severity(level="normal"))
        self.assertIs(self.severity(level="warn"), Severity.AMBER)
        self.assertIs(self.severity(level="critical"), Severity.RED)

    def test_worst_reason_wins_and_all_are_listed(self) -> None:
        found = only(
            run(sys_reading=reading(swap_used=8000, free=10, level="warn")),
            R.RULE_MEMORY_PRESSURE,
        )[0]
        self.assertIs(found.severity, Severity.RED)
        self.assertIn("swap is 80% used", found.reason)
        self.assertIn("10% of memory is free", found.reason)

    def test_missing_values_raise_nothing(self) -> None:
        empty = reading(swap_total=None, ram=None)
        self.assertEqual(run(sys_reading=empty), ())
        zero = reading(swap_used=0, swap_total=0)
        self.assertEqual(run(sys_reading=zero), ())

    def test_custom_thresholds(self) -> None:
        th = R.Thresholds(swap_amber_percent=10.0, swap_red_percent=20.0)
        found = run(sys_reading=reading(swap_used=2000), thresholds=th)
        self.assertIs(only(found, R.RULE_MEMORY_PRESSURE)[0].severity, Severity.RED)


def session(
    state: SessionState, seconds: float | None, root: int | None = 10
) -> R.SessionActivity:
    return R.SessionActivity(
        "s1", "h1", state, None if seconds is None else int(seconds), root
    )


HOUR = 3600


def idle(seconds: float | None, root: int | None = 10) -> R.SessionActivity:
    return session(SessionState.RUNNING_IDLE, seconds, root)


class IdleSessionTests(unittest.TestCase):
    def nodes(
        self, cpu: float = 0.5, extra: list[ProcessNode] | None = None
    ) -> list[ProcessNode]:
        root = node(10, "agent", ppid=1, role=R_.HARNESS, cpu=cpu, mb=200, harness="h1")
        return [root, *(extra or [])]

    def find(self, sess: R.SessionActivity, nodes: list[ProcessNode] | None = None,
             **kwargs: Any) -> list[R.Finding]:
        return only(run(nodes or self.nodes(), sessions=[sess], **kwargs),
                    R.RULE_IDLE_SESSION)

    def test_age_edges(self) -> None:
        self.assertEqual(self.find(idle(6 * HOUR - 1)), [])
        info = self.find(session(SessionState.RUNNING_IDLE, 6 * HOUR))
        self.assertIs(info[0].severity, Severity.INFO)
        info = self.find(session(SessionState.RUNNING_IDLE, 24 * HOUR - 1))
        self.assertIs(info[0].severity, Severity.INFO)
        amber = self.find(session(SessionState.RUNNING_IDLE, 24 * HOUR))
        self.assertIs(amber[0].severity, Severity.AMBER)

    def test_waiting_counts_and_other_states_do_not(self) -> None:
        self.assertEqual(len(self.find(session(SessionState.WAITING, 7 * HOUR))), 1)
        for state in (SessionState.RUNNING_BUSY, SessionState.STALE,
                      SessionState.ENDED, SessionState.UNKNOWN):
            self.assertEqual(self.find(session(state, 30 * HOUR)), [], state)

    def test_cpu_edge_is_strict(self) -> None:
        old = session(SessionState.RUNNING_IDLE, 7 * HOUR)
        self.assertEqual(len(self.find(old, self.nodes(cpu=2.9))), 1)
        self.assertEqual(self.find(old, self.nodes(cpu=3.0)), [])

    def test_test_or_browser_children_block_it(self) -> None:
        old = session(SessionState.RUNNING_IDLE, 7 * HOUR)
        for role in (R_.TEST_WORKER, R_.BROWSER):
            kid = node(11, "x", ppid=10, role=role, harness="h1")
            self.assertEqual(self.find(old, self.nodes(extra=[kid])), [], role)
        calm = node(12, "x", ppid=10, role=R_.SHELL, harness="h1")
        self.assertEqual(len(self.find(old, self.nodes(extra=[calm]))), 1)

    def test_pressure_lifts_info_to_amber_but_never_higher(self) -> None:
        old = session(SessionState.RUNNING_IDLE, 7 * HOUR)
        calm = self.find(old)
        self.assertIs(calm[0].severity, Severity.INFO)
        tense = self.find(old, sys_reading=reading(swap_used=9000))
        self.assertIs(tense[0].severity, Severity.AMBER)
        very_old = session(SessionState.RUNNING_IDLE, 50 * HOUR)
        self.assertIs(
            self.find(very_old, sys_reading=reading(swap_used=9000))[0].severity,
            Severity.AMBER,
        )

    def test_unknown_age_or_process_is_skipped(self) -> None:
        self.assertEqual(self.find(session(SessionState.RUNNING_IDLE, None)), [])
        self.assertEqual(self.find(idle(9 * HOUR, root=None)), [])
        self.assertEqual(self.find(idle(9 * HOUR, root=99)), [])

    def test_links_and_text(self) -> None:
        found = self.find(session(SessionState.RUNNING_IDLE, 7 * HOUR))[0]
        self.assertEqual((found.harness_id, found.session_id), ("h1", "s1"))
        self.assertIn("idle for 7.0 hours", found.reason)
        self.assertIn("200 MB", found.reason)

    def test_custom_hours(self) -> None:
        th = R.Thresholds(idle_info_hours=1.0, idle_amber_hours=2.0)
        found = self.find(session(SessionState.RUNNING_IDLE, 2 * HOUR), thresholds=th)
        self.assertIs(found[0].severity, Severity.AMBER)


class BusyQuietTests(unittest.TestCase):
    def find(self, minutes: float, cpu: float) -> list[R.Finding]:
        root = node(10, "agent", role=R_.HARNESS, cpu=cpu, harness="h1")
        sess = session(SessionState.RUNNING_BUSY, minutes * 60)
        return only(run([root], sessions=[sess]), R.RULE_BUSY_QUIET)

    def test_edges(self) -> None:
        self.assertEqual(self.find(44.9, 0.0), [])
        self.assertIs(self.find(45, 1.9)[0].severity, Severity.INFO)
        self.assertEqual(self.find(45, 2.0), [])
        self.assertEqual(self.find(300, 50.0), [])

    def test_only_busy_sessions(self) -> None:
        root = node(10, "agent", role=R_.HARNESS, cpu=0.0, harness="h1")
        sess = session(SessionState.RUNNING_IDLE, 99 * 60)
        self.assertEqual(only(run([root], sessions=[sess]), R.RULE_BUSY_QUIET), [])


class OrphanTests(unittest.TestCase):
    def find(self, *nodes: ProcessNode, **kwargs: Any) -> list[R.Finding]:
        return only(run(list(nodes), **kwargs), R.RULE_ORPHAN)

    def test_age_edge(self) -> None:
        self.assertEqual(self.find(node(5, role=R_.DEV_SERVER, minutes=9.9)), [])
        self.assertEqual(len(self.find(node(5, role=R_.DEV_SERVER, minutes=10))), 1)

    def test_memory_and_cpu_edges(self) -> None:
        def sev(mb: float = 1, cpu: float = 0.0) -> Severity:
            mcp = node(5, role=R_.MCP_SERVER, minutes=60, mb=mb, cpu=cpu)
            return self.find(mcp)[0].severity

        self.assertIs(sev(mb=499.9), Severity.AMBER)
        self.assertIs(sev(mb=500), Severity.RED)
        self.assertIs(sev(cpu=24.9), Severity.AMBER)
        self.assertIs(sev(cpu=25.0), Severity.RED)

    def test_which_processes_count(self) -> None:
        for role in (R_.BROWSER, R_.DEV_SERVER, R_.TEST_WORKER, R_.MCP_SERVER):
            self.assertEqual(len(self.find(node(5, role=role, minutes=60))), 1, role)
        python = node(5, "python3", role=R_.OTHER, minutes=60)
        self.assertEqual(len(self.find(python)), 1)
        browser = node(5, "Everyday Browser", role=R_.OTHER, minutes=60)
        self.assertEqual(self.find(browser), [])
        self.assertEqual(self.find(node(5, role=R_.SHELL, minutes=60)), [])
        self.assertEqual(self.find(node(5, role=R_.HARNESS, minutes=60)), [])
        self.assertEqual(self.find(node(5, ppid=2, role=R_.DEV_SERVER, minutes=60)), [])
        no_parent = node(5, ppid=None, role=R_.DEV_SERVER, minutes=60)
        self.assertEqual(self.find(no_parent), [])

    def test_grouping_and_stable_ids(self) -> None:
        one = self.find(node(5, minutes=60), node(6, minutes=60))
        self.assertEqual(len(one), 1)
        self.assertIn("2 node processes", one[0].reason)
        again = self.find(node(70, minutes=99), node(71, minutes=99))
        self.assertEqual(one[0].id, again[0].id)
        ported = self.find(
            node(5, minutes=60, ports=(3000,)), node(6, minutes=60, ports=(3001,))
        )
        self.assertEqual(len({f.id for f in ported}), 2)
        self.assertIn("port 3000", ported[0].title + ported[1].title)
        self.assertNotEqual(one[0].id, ported[0].id)

    def test_fix_is_advice_only(self) -> None:
        found = self.find(node(5, minutes=60, ports=(3000,)))[0]
        self.assertIn("Suggested action", found.fix)
        self.assertIn("never stops anything itself", found.fix)
        self.assertIn("port 3000", found.fix)


class ConcurrentTestTests(unittest.TestCase):
    def job(self, base: int, cpu: float, mb: float) -> list[ProcessNode]:
        return [
            node(base, "node", ppid=1, role=R_.TEST_WORKER, cpu=cpu / 2, mb=mb / 2),
            node(
                base + 1, "node", ppid=base, role=R_.TEST_WORKER,
                cpu=cpu / 2, mb=mb / 2,
            ),
        ]

    def find(self, *jobs: list[ProcessNode], **kwargs: Any) -> list[R.Finding]:
        nodes = [n for job in jobs for n in job]
        return only(run(nodes, **kwargs), R.RULE_CONCURRENT_TESTS)

    def test_one_heavy_job_is_fine(self) -> None:
        self.assertEqual(self.find(self.job(10, 90, 900)), [])
        self.assertEqual(self.find(self.job(10, 90, 900), self.job(20, 39.9, 499)), [])

    def test_two_heavy_jobs_fire_at_the_edges(self) -> None:
        by_cpu = self.find(self.job(10, 40, 1), self.job(20, 40, 1))
        self.assertIs(by_cpu[0].severity, Severity.RED)
        by_mem = self.find(self.job(10, 1, 500), self.job(20, 1, 500))
        self.assertEqual(len(by_mem), 1)
        mixed = self.find(self.job(10, 40, 1), self.job(20, 1, 500))
        self.assertEqual(len(mixed), 1)

    def test_workers_of_one_job_are_one_job(self) -> None:
        one_job_many_workers = [
            node(10, role=R_.TEST_WORKER, cpu=30),
            node(11, ppid=10, role=R_.TEST_WORKER, cpu=30),
            node(12, ppid=10, role=R_.TEST_WORKER, cpu=30),
        ]
        self.assertEqual(self.find(one_job_many_workers), [])

    def test_allowed_jobs_is_configurable(self) -> None:
        th = R.Thresholds(heavy_jobs_allowed=2)
        self.assertEqual(
            self.find(self.job(10, 90, 1), self.job(20, 90, 1), thresholds=th), []
        )
        found = self.find(
            self.job(10, 90, 1), self.job(20, 90, 1), self.job(30, 90, 1), thresholds=th
        )
        self.assertEqual(len(found), 1)


class DuplicateMcpTests(unittest.TestCase):
    def pair(self, mb_each: float, name: str = "mcp-example") -> list[ProcessNode]:
        return [
            node(10, name, ppid=100, role=R_.MCP_SERVER, mb=mb_each, fp="same"),
            node(11, name, ppid=101, role=R_.MCP_SERVER, mb=mb_each, fp="same"),
        ]

    def find(self, nodes: list[ProcessNode], **kwargs: Any) -> list[R.Finding]:
        return only(run(nodes, **kwargs), R.RULE_DUPLICATE_MCP)

    def test_severity_edges(self) -> None:
        self.assertIs(self.find(self.pair(49.9))[0].severity, Severity.INFO)
        self.assertIs(self.find(self.pair(50))[0].severity, Severity.AMBER)
        self.assertIs(self.find(self.pair(249.9))[0].severity, Severity.AMBER)
        self.assertIs(self.find(self.pair(250))[0].severity, Severity.RED)

    def test_a_single_instance_is_fine(self) -> None:
        self.assertEqual(self.find(self.pair(900)[:1]), [])

    def test_same_name_counts_even_with_different_arguments(self) -> None:
        nodes = [
            node(10, "mcp-example", ppid=100, role=R_.MCP_SERVER, fp="a"),
            node(11, "mcp-example", ppid=101, role=R_.MCP_SERVER, fp="b"),
        ]
        self.assertEqual(len(self.find(nodes)), 1)

    def test_generic_runtimes_need_the_same_fingerprint(self) -> None:
        different = [
            node(10, "node", ppid=100, role=R_.MCP_SERVER, fp="aaaaaaaa1"),
            node(11, "node", ppid=101, role=R_.MCP_SERVER, fp="bbbbbbbb2"),
        ]
        self.assertEqual(self.find(different), [])
        same = [
            node(10, "node", ppid=100, role=R_.MCP_SERVER, fp="aaaaaaaa1"),
            node(11, "node", ppid=101, role=R_.MCP_SERVER, fp="aaaaaaaa1"),
        ]
        self.assertEqual(len(self.find(same)), 1)

    def test_wrapper_chain_counts_once_and_adds_memory(self) -> None:
        nodes = [
            node(10, "npm", ppid=100, role=R_.MCP_SERVER, mb=60, fp="x"),
            node(12, "node", ppid=10, role=R_.MCP_SERVER, mb=60, fp="y"),
            node(11, "npm", ppid=101, role=R_.MCP_SERVER, mb=60, fp="x"),
            node(13, "node", ppid=11, role=R_.MCP_SERVER, mb=60, fp="y"),
        ]
        found = self.find(nodes)
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].severity, Severity.AMBER)  # 240 MB, not 120
        self.assertIn("2 copies", found[0].reason)
        self.assertEqual(self.find(nodes[:2]), [])

    def test_min_instances_is_configurable(self) -> None:
        th = R.Thresholds(duplicate_mcp_min_instances=3)
        self.assertEqual(self.find(self.pair(10), thresholds=th), [])


class HotChildTests(unittest.TestCase):
    def find(self, nodes: list[ProcessNode], **kwargs: Any) -> list[R.Finding]:
        return only(run(nodes, **kwargs), R.RULE_HOT_CHILD)

    def hot(self, cpu: float, minutes: float, **kwargs: Any) -> ProcessNode:
        return node(5, "watcher", ppid=2, role=R_.OTHER, cpu=cpu, minutes=minutes,
                    harness="h1", **kwargs)

    def test_edges(self) -> None:
        self.assertEqual(self.find([self.hot(59.9, 60)]), [])
        self.assertEqual(self.find([self.hot(90, 14.9)]), [])
        found = self.find([self.hot(60, 15)])
        self.assertIs(found[0].severity, Severity.AMBER)
        self.assertIs(self.find([self.hot(150, 60)])[0].severity, Severity.RED)

    def test_cumulative_cpu_time_beats_a_single_reading(self) -> None:
        quiet_now = self.hot(1.0, 20)  # 20 minutes old
        self.assertEqual(self.find([quiet_now]), [])
        busy_life = self.find([quiet_now], cpu_seconds={5: 20 * 60 * 0.6})
        self.assertEqual(len(busy_life), 1)
        busy_now = self.hot(99.0, 20)
        self.assertEqual(self.find([busy_now], cpu_seconds={5: 20 * 60 * 0.59}), [])

    def test_only_children_inside_a_harness(self) -> None:
        stray = node(5, ppid=2, cpu=99, minutes=60)
        self.assertEqual(self.find([stray]), [])
        root = node(5, ppid=2, role=R_.HARNESS, cpu=99, minutes=60, harness="h1")
        self.assertEqual(self.find([root]), [])

    def test_unknown_numbers_are_skipped(self) -> None:
        unknown = ProcessNode(pid=5, name="x", harness_id="h1", age_seconds=None)
        self.assertEqual(self.find([unknown]), [])


class RendererTests(unittest.TestCase):
    NAME = "Example Helper (Renderer)"

    def find(
        self, mb: float, harness: str | None = "h1", **kwargs: Any
    ) -> list[R.Finding]:
        found = run([node(5, self.NAME, ppid=2, mb=mb, harness=harness)], **kwargs)
        return only(found, R.RULE_RENDERER_BLOAT)

    def test_edges(self) -> None:
        self.assertEqual(self.find(1499.9), [])
        self.assertIs(self.find(1500)[0].severity, Severity.AMBER)

    def test_pressure_makes_it_red(self) -> None:
        found = self.find(2000, sys_reading=reading(swap_used=9000))
        self.assertIs(found[0].severity, Severity.RED)

    def test_other_processes_and_apps_are_ignored(self) -> None:
        self.assertEqual(self.find(3000, harness=None), [])
        other = node(5, "Example Helper (GPU)", ppid=2, mb=3000, harness="h1")
        self.assertEqual(only(run([other]), R.RULE_RENDERER_BLOAT), [])


class HeavyLockTests(unittest.TestCase):
    def test_info_only_when_present(self) -> None:
        self.assertEqual(only(run(), R.RULE_HEAVY_LOCK), [])
        found = only(run(heavy_lock_present=True), R.RULE_HEAVY_LOCK)
        self.assertEqual([f.severity for f in found], [Severity.INFO])

    def test_the_path_never_appears(self) -> None:
        text = repr(only(run(heavy_lock_present=True), R.RULE_HEAVY_LOCK))
        self.assertNotIn("/", text)


class ThresholdsTests(unittest.TestCase):
    def test_defaults_match_the_spike(self) -> None:
        th = R.Thresholds()
        self.assertEqual((th.swap_red_percent, th.swap_amber_percent), (80, 50))
        self.assertEqual((th.idle_info_hours, th.idle_amber_hours), (6, 24))
        self.assertEqual((th.orphan_min_age_minutes, th.orphan_red_mb), (10, 500))
        self.assertEqual((th.hot_child_cpu, th.hot_child_minutes), (60, 15))
        self.assertEqual(th.renderer_mb, 1500)

    def test_from_mapping(self) -> None:
        th = R.Thresholds.from_mapping(
            {"swap_red_percent": 90, "heavy_jobs_allowed": 3.0, "orphan_red_mb": True,
             "bogus": 1, "idle_cpu_max": "high"}
        )
        self.assertEqual(th.swap_red_percent, 90.0)
        self.assertIsInstance(th.swap_red_percent, float)
        self.assertEqual(th.heavy_jobs_allowed, 3)
        self.assertIsInstance(th.heavy_jobs_allowed, int)
        self.assertEqual(th.orphan_red_mb, 500.0)
        self.assertEqual(th.idle_cpu_max, 3.0)


class OutputShapeTests(unittest.TestCase):
    def everything(self) -> tuple[R.Finding, ...]:
        nodes = [
            node(5, role=R_.DEV_SERVER, minutes=60, mb=600, ports=(3000,)),
            node(6, "mcp-x", ppid=100, role=R_.MCP_SERVER, mb=300, fp="s"),
            node(7, "mcp-x", ppid=101, role=R_.MCP_SERVER, mb=300, fp="s"),
        ]
        return run(nodes, reading(swap_used=9000), heavy_lock_present=True)

    def test_sorted_most_urgent_first_and_deterministic(self) -> None:
        found = self.everything()
        ranks = [f.severity.rank for f in found]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertEqual(found, self.everything())
        self.assertGreaterEqual(len(found), 4)
        self.assertEqual(len({f.id for f in found}), len(found))

    def test_plain_english_without_dashes(self) -> None:
        for finding in self.everything():
            for text in (finding.title, finding.reason, finding.fix):
                self.assertTrue(text and text[0].isupper() or text[0].isdigit(), text)
                self.assertNotIn("—", text)
                self.assertNotIn("–", text)
            if finding.rule_id != R.RULE_HEAVY_LOCK:
                self.assertIn("Suggested action", finding.fix)

    def test_no_process_ids_or_paths_in_ids(self) -> None:
        a = run([node(5, role=R_.DEV_SERVER, minutes=60, ports=(3000,))])
        b = run([node(9999, role=R_.DEV_SERVER, minutes=99, ports=(3000,))])
        self.assertEqual([f.id for f in a], [f.id for f in b])
        self.assertTrue(a[0].id.startswith("finding_"))

    def test_odd_names_never_crash(self) -> None:
        weird = node(5, "/odd\\name", role=R_.DEV_SERVER, minutes=60)
        self.assertEqual(len(only(run([weird]), R.RULE_ORPHAN)), 1)

    def test_nothing_to_report(self) -> None:
        self.assertEqual(run(), ())


if __name__ == "__main__":
    unittest.main()
