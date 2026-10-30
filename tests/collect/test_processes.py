"""Tests for the process collector, using recorded made-up command output."""

from __future__ import annotations

import json
import unittest
from collections.abc import Sequence
from datetime import UTC, datetime

from hc2.adapters.base import ProcessSignature
from hc2.collect import PS_ARGV, UnsafeCommandError, assert_read_only, run_command
from hc2.collect import processes as P
from hc2.model import ProcessRole

from . import fixture

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
SIGNATURES = (
    ProcessSignature("example-agent", path_markers=("/Example Agent.app/",)),
    ProcessSignature("agent-cli", executable_names=("agent-cli",)),
)


def table(**kwargs: object) -> P.ProcessTable:
    return P.build_table(
        P.parse_ps(fixture("ps.txt")),
        now=NOW,
        signatures=SIGNATURES,
        ports=P.parse_listeners(fixture("lsof_listen.txt")),
        gpu_ms=P.parse_gpu(fixture("ioreg_agx.txt")),
        **kwargs,  # type: ignore[arg-type]
    )


class ParserTests(unittest.TestCase):
    def test_etime(self) -> None:
        self.assertEqual(P.parse_etime("12-04:00:00"), 12 * 86400 + 4 * 3600)
        self.assertEqual(P.parse_etime("02:10:00"), 7800)
        self.assertEqual(P.parse_etime("05:30"), 330)
        self.assertEqual(P.parse_etime("45"), 45)
        self.assertIsNone(P.parse_etime("soon"))
        self.assertIsNone(P.parse_etime("1:2:3:4"))

    def test_cpu_time(self) -> None:
        self.assertEqual(P.parse_cpu_time("0:30.00"), 30.0)
        self.assertEqual(P.parse_cpu_time("1:01:01.5"), 3661.5)
        self.assertIsNone(P.parse_cpu_time("n/a"))

    def test_split_executable(self) -> None:
        bundle = "/Apps/My App.app/Contents/MacOS/My App"
        helper = "/Apps/My App.app/Contents/Frameworks/H.app/Contents/MacOS/H (R)"
        cases = {
            "/bin/ls -l": "/bin/ls",
            "/usr/local/bin/node /srv/a b.js": "/usr/local/bin/node",
            bundle: bundle,
            bundle + " --type=x --y=/a/b": bundle,
            bundle + " /Users/alice/file.txt": bundle,
            helper + " --type=renderer": helper,
            "/usr/bin/tool /Apps/X.app/Contents/MacOS/y": "/usr/bin/tool",
            "node server.js": "node",
            "-zsh": "-zsh",
            "(sh)": "(sh)",
            "": "",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(P.split_executable(text), expected)

    def test_parse_ps(self) -> None:
        rows = P.parse_ps(fixture("ps.txt"))
        self.assertEqual(len(rows), 17)
        by_pid = {row.pid: row for row in rows}
        self.assertEqual(by_pid[1].age_seconds, 12 * 86400 + 4 * 3600)
        self.assertEqual(by_pid[101].rss_kb, 1700000)
        self.assertTrue(by_pid[101].comm.endswith("Example Agent Helper (Renderer)"))
        self.assertIn("--type=renderer", by_pid[101].args)
        self.assertEqual(by_pid[300].comm, "node")
        self.assertEqual(by_pid[200].comm, "/opt/tools/bin/agent-cli")
        self.assertEqual(by_pid[401].cpu_seconds, 720.0)

    def test_parse_ps_skips_bad_lines(self) -> None:
        text = "garbage\n 12 1 12 00:01 0.0 100 0:00.01 /bin/x /bin/x\n\n  PID PPID\n"
        self.assertEqual([row.pid for row in P.parse_ps(text)], [12])

    def test_repr_hides_the_command_line(self) -> None:
        rows = P.parse_ps(fixture("ps.txt"))
        self.assertNotIn("FAKE", " ".join(repr(row) for row in rows))

    def test_listeners(self) -> None:
        ports = P.parse_listeners(fixture("lsof_listen.txt"))
        self.assertEqual(ports[300], (5173,))
        self.assertEqual(ports[100], (8765,))
        self.assertEqual(ports[800], (9229,))
        self.assertNotIn(999, ports)

    def test_cwds(self) -> None:
        cwds = P.parse_cwds(fixture("lsof_cwd.txt"))
        self.assertEqual(cwds[300], "/home/alice/sentinel-project")
        self.assertEqual(len(cwds), 2)

    def test_gpu(self) -> None:
        gpu = P.parse_gpu(fixture("ioreg_agx.txt"))
        self.assertEqual(gpu, {101: 4500, 700: 42})
        self.assertEqual(P.parse_gpu(""), {})


class ClassifyTests(unittest.TestCase):
    def role(self, comm: str, args: str = "", ports: Sequence[int] = ()) -> ProcessRole:
        return P.classify_role(comm, args or comm, ports)

    def test_roles(self) -> None:
        node = "/usr/local/bin/node"
        self.assertIs(self.role("-zsh"), ProcessRole.SHELL)
        self.assertIs(self.role("/bin/bash"), ProcessRole.SHELL)
        self.assertIs(self.role("/x/mcp-server-foo"), ProcessRole.MCP_SERVER)
        self.assertIs(
            self.role(node, node + " /srv/pkg/mcp/index.js"), ProcessRole.MCP_SERVER
        )
        self.assertIs(
            self.role(node, node + " node_modules/vitest/vitest.mjs run"),
            ProcessRole.TEST_WORKER,
        )
        self.assertIs(self.role(node, "node (vitest 3)"), ProcessRole.TEST_WORKER)
        self.assertIs(self.role("/usr/bin/xcodebuild"), ProcessRole.TEST_WORKER)
        self.assertIs(self.role(node, "node a/vite --port 1"), ProcessRole.DEV_SERVER)
        self.assertIs(self.role(node, "node server.js", [3000]), ProcessRole.DEV_SERVER)
        self.assertIs(self.role(node, "node script.js"), ProcessRole.OTHER)
        self.assertIs(self.role("/bin/ls"), ProcessRole.OTHER)

    def test_only_automated_browsers_are_browsers(self) -> None:
        chromium = "/opt/ms-playwright/x/Chromium.app/Contents/MacOS/Chromium"
        self.assertIs(self.role(chromium), ProcessRole.BROWSER)
        chrome = "/Applications/Example Chrome.app/Contents/MacOS/Example Chrome"
        self.assertIs(self.role(chrome), ProcessRole.OTHER)
        self.assertIs(
            self.role(chrome, chrome + " --headless=new"), ProcessRole.BROWSER
        )
        self.assertIs(
            self.role(chrome, chrome + " --remote-debugging-port=9222"),
            ProcessRole.BROWSER,
        )

    def test_flag_names_hold_no_values(self) -> None:
        flags = P.flag_names("/x/y --token=SECRET -v --a-b=c plain", "/x/y")
        self.assertEqual(flags, ("--token", "-v", "--a-b"))
        self.assertEqual(P.flag_names("x --0bad --=x", "x"), ())

    def test_fingerprint_is_a_hash(self) -> None:
        one = P.fingerprint("a --token=SECRET", "a")
        self.assertRegex(one, r"^[0-9a-f]{64}$")
        self.assertNotEqual(one, P.fingerprint("a --token=OTHER", "a"))
        self.assertEqual(one, P.fingerprint("a --token=SECRET", "a"))

    def test_signature_matching_is_exact(self) -> None:
        sigs = [
            ProcessSignature(
                "h", executable_names=("agent",), path_markers=("/A.app/",)
            )
        ]
        self.assertEqual(P.match_signature("/bin/agent", sigs), "h")
        self.assertEqual(P.match_signature("/x/A.app/Contents/y", sigs), "h")
        self.assertIsNone(P.match_signature("/bin/agent-cli", sigs))
        self.assertIsNone(P.match_signature("/bin/agen", sigs))
        self.assertIsNone(P.match_signature("/x/a.app/y", sigs))
        empty = [ProcessSignature("h", path_markers=("",))]
        self.assertIsNone(P.match_signature("/bin/x", empty))


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.table = table()
        self.nodes = {node.pid: node for node in self.table.nodes}

    def test_roles_and_harnesses(self) -> None:
        n = self.nodes

        def pair(pid: int) -> tuple[str | None, ProcessRole]:
            return n[pid].harness_id, n[pid].role

        self.assertEqual(pair(100), ("example-agent", ProcessRole.HARNESS))
        self.assertEqual(pair(101), ("example-agent", ProcessRole.OTHER))
        self.assertEqual(pair(200), ("agent-cli", ProcessRole.HARNESS))
        self.assertEqual(pair(400), ("agent-cli", ProcessRole.TEST_WORKER))
        self.assertEqual(pair(300), (None, ProcessRole.DEV_SERVER))
        self.assertIs(n[150].role, ProcessRole.SHELL)
        self.assertIs(n[500].role, ProcessRole.MCP_SERVER)
        self.assertIs(n[600].role, ProcessRole.BROWSER)
        self.assertIs(n[601].role, ProcessRole.BROWSER)
        self.assertIs(n[700].role, ProcessRole.OTHER)
        self.assertIs(n[800].role, ProcessRole.DEV_SERVER)

    def test_numbers(self) -> None:
        node = self.nodes[101]
        self.assertEqual(node.name, "Example Agent Helper (Renderer)")
        self.assertEqual(node.memory_bytes, 1700000 * 1024)
        self.assertEqual(node.age_seconds, 7740)
        self.assertEqual(node.start_time, "2026-10-30T09:51:00Z")
        self.assertEqual(node.parent_pid, 100)
        self.assertEqual(node.gpu_time_ms, 4500)
        self.assertEqual(self.nodes[300].listening_ports, (5173,))
        self.assertEqual(self.nodes[200].gpu_time_ms, 0)
        self.assertIsNone(node.threads)
        self.assertIsNone(node.session_id)
        self.assertEqual(self.table.sampled_at, "2026-10-30T12:00:00Z")

    def test_gpu_unavailable_is_none(self) -> None:
        bare = P.build_table(P.parse_ps(fixture("ps.txt")), now=NOW, gpu_ms=None)
        self.assertTrue(all(node.gpu_time_ms is None for node in bare.nodes))

    def test_fingerprints(self) -> None:
        self.assertEqual(self.nodes[500].fingerprint, self.nodes[510].fingerprint)
        self.assertNotEqual(self.nodes[400].fingerprint, self.nodes[401].fingerprint)

    def test_flag_names_kept_but_not_values(self) -> None:
        self.assertEqual(self.table.flags[100], ("--secret-token",))
        self.assertEqual(self.table.flags[101], ("--type", "--user-data-dir"))

    def test_nothing_private_is_kept(self) -> None:
        text = json.dumps(
            [node.to_dict() for node in self.table.nodes]
            + [{str(k): v for k, v in self.table.flags.items()}]
        )
        for forbidden in ("FAKE-", "sentinel", "/home/alice", "node_modules"):
            self.assertNotIn(forbidden, text)

    def test_excluded_pids_are_dropped(self) -> None:
        smaller = table(exclude_pids={400, 401})
        self.assertEqual(len(smaller.nodes), len(self.table.nodes) - 2)

    def test_cpu_seconds_kept(self) -> None:
        self.assertEqual(self.table.cpu_seconds[800], 1680.0)


class CollectTests(unittest.TestCase):
    def runner(self, calls: list[tuple[str, ...]]) -> P.Runner:
        outputs = {
            "ps": fixture("ps.txt"),
            "lsof": fixture("lsof_listen.txt"),
            "ioreg": fixture("ioreg_agx.txt"),
        }

        def run(argv: Sequence[str], timeout: float) -> str | None:
            calls.append(tuple(argv))
            return outputs[argv[0]]

        return run

    def test_collect_excludes_own_tree(self) -> None:
        calls: list[tuple[str, ...]] = []
        result = P.collect_processes(
            SIGNATURES, runner=self.runner(calls), now=NOW, pid=400
        )
        pids = {node.pid for node in result.nodes}
        self.assertFalse({400, 401, 402} & pids)
        self.assertIn(300, pids)
        self.assertEqual({call[0] for call in calls}, {"ps", "lsof", "ioreg"})
        self.assertIn(PS_ARGV, calls)

    def test_collect_survives_failed_commands(self) -> None:
        result = P.collect_processes(runner=lambda argv, timeout: None, now=NOW)
        self.assertEqual(result.nodes, ())

    def test_read_cwds_command_and_limits(self) -> None:
        calls: list[tuple[str, ...]] = []

        def run(argv: Sequence[str], timeout: float) -> str | None:
            calls.append(tuple(argv))
            return fixture("lsof_cwd.txt")

        cwds = P.read_cwds([401, 300, 300, -5], runner=run)
        self.assertEqual(
            calls, [("lsof", "-a", "-p", "300,401", "-d", "cwd", "-Fn")]
        )
        self.assertEqual(cwds[401], "/home/alice/sentinel-project/packages/app")
        self.assertEqual(P.read_cwds([], runner=run), {})
        self.assertEqual(len(calls), 1)
        P.read_cwds(range(1, 200), runner=run)
        self.assertEqual(len(calls[1][3].split(",")), P.MAX_CWD_PIDS)


class IndexTests(unittest.TestCase):
    def test_subtree_and_top_level(self) -> None:
        index = P.ProcessIndex(table().nodes)
        pids = {node.pid for node in index.subtree(200)}
        self.assertEqual(pids, {200, 400, 401, 402, 500, 800})
        self.assertEqual(index.subtree(99999), [])
        top = {node.pid for node in index.top_level()}
        self.assertIn(100, top)
        self.assertNotIn(1, top)
        self.assertNotIn(200, top)

    def test_cycles_do_not_hang(self) -> None:
        a = P.ProcessNode(pid=5, name="a", parent_pid=6)
        b = P.ProcessNode(pid=6, name="b", parent_pid=5)
        self.assertEqual(len(P.ProcessIndex([a, b]).subtree(5)), 2)


class NeverReadEnvironmentsTests(unittest.TestCase):
    """S-3: no collector may ask for a process environment."""

    def test_guard_refuses_environment_flags(self) -> None:
        bad = (
            ["ps", "eww"],
            ["ps", "-E"],
            ["ps", "-axeo", "pid"],
            ["ps", "auxeww"],
            ["ps", "-axo", "pid,command", "-e"],
            ["ps", "-eww", "-p", "1"],
            ["lsof", "eww"],
            ["kill", "-9", "1"],
            ["sh", "-c", "ps eww"],
            [],
        )
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(UnsafeCommandError):
                assert_read_only(argv)
            with self.subTest(run=argv):
                self.assertIsNone(self.safe_run(argv))

    def safe_run(self, argv: list[str]) -> str | None:
        try:
            return run_command(argv, 1.0)
        except UnsafeCommandError:
            return None

    def test_every_collector_command_is_read_only(self) -> None:
        from hc2.collect.system import collect_system

        calls: list[tuple[str, ...]] = []

        def record(argv: Sequence[str], timeout: float) -> str | None:
            calls.append(tuple(argv))
            return ""

        P.collect_processes(runner=record)
        P.read_cwds([1, 2], runner=record)
        collect_system(runner=record)
        self.assertGreaterEqual(len(calls), 8)
        for argv in calls:
            assert_read_only(argv)
            for token in argv:
                self.assertNotEqual(token, "eww")
                if argv[0] == "ps" and token.startswith("-"):
                    self.assertFalse(set(token[1:]) & set("eE"), token)
            if argv[0] == "ps":
                self.assertEqual(argv, PS_ARGV)

    def test_source_never_builds_an_environment_command(self) -> None:
        from pathlib import Path

        root = Path(P.__file__).resolve().parent
        for source in root.glob("*.py"):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn('"eww"', text.replace('arg == "eww"', ""))
            self.assertNotIn('"-E"', text)
            self.assertNotIn("environ", text.replace("environment", ""))


if __name__ == "__main__":
    unittest.main()
