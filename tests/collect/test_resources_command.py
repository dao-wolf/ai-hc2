"""Tests for `hc2 resources`: output, privacy gate and (opt-in) live timing."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import unittest
from collections.abc import Sequence
from unittest import mock

from hc2.adapters.base import ProcessSignature
from hc2.commands import command_modules
from hc2.commands import resources as C
from hc2.model import SCHEMA_VERSION

from . import fixture

SIGNATURES = (
    ProcessSignature("example-agent", path_markers=("/Example Agent.app/",)),
    ProcessSignature("agent-cli", executable_names=("agent-cli",)),
)
OUTPUTS = {
    "ps": "ps.txt",
    "lsof": "lsof_listen.txt",
    "ioreg": "ioreg_agx.txt",
    "sysctl": "sysctl.txt",
    "vm_stat": "vm_stat.txt",
    "memory_pressure": "memory_pressure_q.txt",
    "pmset": "pmset_therm_nominal.txt",
}
# Command-line values that must never be stored or shown: made-up secrets and
# sentinel paths. Flag names alone (such as "--resume") may be held internally,
# but never shown.
VALUES = (
    "FAKE-SECRET-VALUE",
    "FAKE-SESSION-TOKEN",
    "sentinel",
    "/home/alice",
    "node_modules",
    "young-script",
)
FORBIDDEN = (*VALUES, "--resume", "--user-data-dir")


def fake_runner(argv: Sequence[str], timeout: float) -> str | None:
    return fixture(OUTPUTS[argv[0]])


def report() -> C.ResourceReport:
    return C.sample(SIGNATURES, runner=fake_runner)


class SampleTests(unittest.TestCase):
    def test_top_trees(self) -> None:
        trees = report().trees
        self.assertEqual(len(trees), C.TOP_TREES)
        self.assertEqual(trees[0].name, "Example Agent")  # app plus renderer, 2.1 GB
        sizes = [tree.memory_bytes for tree in trees]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        names = {tree.name for tree in trees}
        self.assertNotIn("launchd", names)

    def test_findings_appear(self) -> None:
        rules = {finding.rule_id for finding in report().findings}
        self.assertIn("resources.memory_pressure", rules)
        self.assertIn("resources.orphan", rules)

    def test_lock_file(self) -> None:
        self.assertFalse(C.lock_present(None))
        self.assertFalse(C.lock_present(""))
        self.assertFalse(C.lock_present("/definitely/not/here/lock"))
        self.assertTrue(C.lock_present(__file__))
        found = C.sample(SIGNATURES, runner=fake_runner, lock_file=__file__).findings
        self.assertIn("resources.heavy_lock", {f.rule_id for f in found})

    def test_a_broken_machine_still_reports(self) -> None:
        empty = C.sample(runner=lambda argv, timeout: None)
        self.assertEqual(empty.findings, ())
        text = C.render(empty)
        self.assertIn("Memory: unknown in total", text)
        self.assertIn("None found.", text)
        self.assertIn("Findings: none", text)


class RenderTests(unittest.TestCase):
    def test_plain_english_summary(self) -> None:
        text = C.render(report())
        for part in (
            "AI HC2 resources",
            "Memory: 16.0 GB in total, about 12% free.",
            "Swap: 2.0 GB of 4.0 GB used (50%).",
            "Compressor: 4.0 GB.",
            "Pressure reported by macOS: warn.",
            "Load: 2.10 (1 min), 2.35 (5 min), 2.40 (15 min) on 8 cores.",
            "Heat: nominal.",
            "Biggest process trees by memory:",
            "Findings (",
            "[RED]",
            "[AMBER]",
            "Why:",
            "Fix:",
            "Sampled 17 processes",
        ):
            self.assertIn(part, text)
        self.assertNotIn("—", text)
        self.assertNotIn("–", text)

    def test_json(self) -> None:
        args = argparse.Namespace(json=True)
        out = io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            mock.patch.object(C, "sample", return_value=report()),
            mock.patch.object(C, "known_signatures", return_value=[]),
        ):
            self.assertEqual(C.run(args), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["schema"], SCHEMA_VERSION)
        self.assertEqual(data["process_count"], 17)
        self.assertEqual(data["system"]["free_percent"], 12)
        self.assertEqual(data["system"]["sample"]["thermal_state"], "nominal")
        self.assertTrue(data["findings"])
        self.assertEqual(data["findings"][0]["severity"], "red")
        self.assertTrue(all(p["harness_id"] for p in data["harness_processes"]))
        self.assertEqual(list(data), sorted(data))


class PrivacyTests(unittest.TestCase):
    def outputs(self) -> list[str]:
        result = report()
        data = json.dumps(result.to_dict(), sort_keys=True)
        every_finding = " ".join(
            f"{f.title} {f.reason} {f.fix} {f.id}" for f in result.findings
        )
        return [C.render(result), data, every_finding]

    def test_command_lines_never_reach_the_output(self) -> None:
        for text in self.outputs():
            for forbidden in FORBIDDEN:
                self.assertNotIn(forbidden, text)

    def test_no_paths_in_output(self) -> None:
        for text in self.outputs():
            for marker in ("/Applications", "/usr/local", "/opt/", "/Users/", "/home/"):
                self.assertNotIn(marker, text)

    def test_process_table_holds_only_hashes_and_flag_names(self) -> None:
        table = report().table
        blob = repr(table)
        for forbidden in VALUES:
            self.assertNotIn(forbidden, blob)
        for node in table.nodes:
            self.assertRegex(node.fingerprint or "", r"^[0-9a-f]{64}$")


class WiringTests(unittest.TestCase):
    def test_register_adds_the_subcommand(self) -> None:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        C.register(subparsers)
        args = parser.parse_args(["resources", "--json", "--lock-file", "x"])
        self.assertEqual(args.command, "resources")
        self.assertTrue(args.json)
        self.assertEqual(args.lock_file, "x")
        self.assertIs(args.handler, C.run)
        plain = parser.parse_args(["resources"])
        self.assertFalse(getattr(plain, "json", False))

    def test_the_command_package_finds_it(self) -> None:
        self.assertIn(C, command_modules())

    def test_known_signatures_survive_a_broken_adapter(self) -> None:
        class Broken:
            id = "broken"
            name = "Broken"

            def process_signature(self) -> ProcessSignature:
                raise RuntimeError("boom")

        class Fine:
            id = "fine"
            name = "Fine"

            def process_signature(self) -> ProcessSignature:
                return ProcessSignature("fine", executable_names=("fine",))

        with mock.patch("hc2.adapters.ALL_ADAPTERS", (Broken(), Fine())):
            found = C.known_signatures()
        self.assertEqual([sig.harness_id for sig in found], ["fine"])


LIVE = sys.platform == "darwin" and os.environ.get("HC2_LIVE_TESTS") == "1"


@unittest.skipUnless(
    LIVE, "live timing runs on macOS only, and only when HC2_LIVE_TESTS=1"
)
class LiveTests(unittest.TestCase):
    """One real sample: F-1 says 2 seconds or less. Prints counts only."""

    def test_sample_is_fast_and_clean(self) -> None:
        result = C.sample(C.known_signatures())
        self.assertLessEqual(result.elapsed_seconds, 2.0)
        self.assertGreater(len(result.table.nodes), 10)
        blob = C.render(result) + json.dumps(result.to_dict())
        for marker in ("/Users/", "/home/", "/Applications/", "/private/"):
            self.assertNotIn(marker, blob)
        rules = sorted({finding.rule_id for finding in result.findings})
        print(
            f"\nlive: {result.elapsed_seconds:.2f}s, "
            f"{len(result.table.nodes)} processes, "
            f"{len(result.findings)} findings {rules}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    unittest.main()
