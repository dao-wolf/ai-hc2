"""`hc2 resources`: one sample of system pressure, process trees and waste.

Takes one reading, then prints a plain-English summary: pressure, the biggest
process trees by memory, and any findings. With `--json` it prints one JSON
object instead. It only reads: it never stops or signals a process (FR-5).
Target: 2 seconds or less (F-1).
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hc2.adapters.base import ProcessSignature
from hc2.collect import Runner, run_command
from hc2.collect.processes import (
    ProcessIndex,
    ProcessTable,
    collect_processes,
    total_cpu,
    total_memory,
)
from hc2.collect.system import SystemReading, collect_system
from hc2.model import SCHEMA_VERSION, Finding, ProcessNode
from hc2.rules.resources import GB, MB, evaluate

TOP_TREES = 5
SEVERITY_LABELS = {"red": "RED", "amber": "AMBER", "info": "INFO", "green": "OK"}


@dataclass(frozen=True)
class TreeSummary:
    """The total cost of one top-level process and everything below it."""

    name: str
    harness_id: str | None
    process_count: int
    memory_bytes: int
    cpu_percent: float

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON types."""
        return {
            "cpu_percent": round(self.cpu_percent, 1),
            "harness_id": self.harness_id,
            "memory_bytes": self.memory_bytes,
            "name": self.name,
            "process_count": self.process_count,
        }


@dataclass(frozen=True)
class ResourceReport:
    """One sample, ready to print."""

    system: SystemReading
    table: ProcessTable
    trees: tuple[TreeSummary, ...]
    findings: tuple[Finding, ...]
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON types. Only processes that belong to a harness are listed."""
        belonging = [node for node in self.table.nodes if node.harness_id]
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "findings": [finding.to_dict() for finding in self.findings],
            "harness_processes": [node.to_dict() for node in belonging],
            "process_count": len(self.table.nodes),
            "sampled_at": self.table.sampled_at,
            "system": self.system.to_dict(),
            "top_trees": [tree.to_dict() for tree in self.trees],
        }


def top_trees(
    nodes: Sequence[ProcessNode], limit: int = TOP_TREES
) -> list[TreeSummary]:
    """The biggest process trees by memory, named by their top process only."""
    index = ProcessIndex(nodes)
    summaries: list[TreeSummary] = []
    for root in index.top_level():
        members = index.subtree(root.pid)
        summaries.append(
            TreeSummary(
                name=root.name,
                harness_id=root.harness_id,
                process_count=len(members),
                memory_bytes=total_memory(members),
                cpu_percent=total_cpu(members),
            )
        )
    summaries.sort(key=lambda tree: (-tree.memory_bytes, tree.name))
    return summaries[:limit]


def known_signatures() -> list[ProcessSignature]:
    """Ask each registered adapter how to recognise its processes."""
    from hc2.adapters import ALL_ADAPTERS

    signatures: list[ProcessSignature] = []
    for adapter in ALL_ADAPTERS:
        try:
            signatures.append(adapter.process_signature())
        except Exception:
            continue  # a broken adapter must not stop the sample
    return signatures


def lock_present(path: str | None) -> bool:
    """True when a configured heavy-work lock file exists."""
    if not path:
        return False
    try:
        return Path(path).expanduser().exists()
    except OSError:
        return False


def sample(
    signatures: Sequence[ProcessSignature] = (),
    *,
    lock_file: str | None = None,
    runner: Runner = run_command,
) -> ResourceReport:
    """Take one reading and run the rules over it."""
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:
        system_job = pool.submit(collect_system, runner=runner)
        table_job = pool.submit(collect_processes, signatures, runner=runner)
        system, table = system_job.result(), table_job.result()
    findings = evaluate(
        system,
        table.nodes,
        cpu_seconds=table.cpu_seconds,
        heavy_lock_present=lock_present(lock_file),
    )
    return ResourceReport(
        system=system,
        table=table,
        trees=tuple(top_trees(table.nodes)),
        findings=findings,
        elapsed_seconds=time.monotonic() - started,
    )


# --------------------------------------------------------------------------
# Printing
# --------------------------------------------------------------------------


def _gb(value: int | None) -> str:
    return "unknown" if value is None else f"{value / GB:.1f} GB"


def _size(value: int) -> str:
    return f"{value / GB:.1f} GB" if value >= GB else f"{value / MB:.0f} MB"


def render(report: ResourceReport) -> str:
    """The plain-English summary."""
    reading, sample_ = report.system, report.system.sample
    lines = ["AI HC2 resources", ""]
    memory = f"Memory: {_gb(sample_.memory_total_bytes)} in total"
    if reading.free_percent is not None:
        memory += f", about {reading.free_percent}% free"
    lines.append(memory + ".")
    if sample_.swap_used_bytes is not None and reading.swap_total_bytes:
        percent = 100 * sample_.swap_used_bytes / reading.swap_total_bytes
        lines.append(
            f"Swap: {_gb(sample_.swap_used_bytes)} of "
            f"{_gb(reading.swap_total_bytes)} used ({percent:.0f}%)."
        )
    if reading.compressor_bytes is not None:
        lines.append(f"Compressor: {_gb(reading.compressor_bytes)}.")
    lines.append(f"Pressure reported by macOS: {reading.kernel_level or 'unknown'}.")
    if sample_.load_1m is not None:
        cores = f" on {reading.cpu_count} cores" if reading.cpu_count else ""
        lines.append(
            f"Load: {sample_.load_1m:.2f} (1 min), {sample_.load_5m:.2f} (5 min), "
            f"{sample_.load_15m:.2f} (15 min){cores}."
        )
    lines.append(f"Heat: {sample_.thermal_state or 'unknown'}.")
    lines += ["", "Biggest process trees by memory:"]
    if not report.trees:
        lines.append("  None found.")
    for number, tree in enumerate(report.trees, start=1):
        owner = f" [{tree.harness_id}]" if tree.harness_id else ""
        lines.append(
            f"  {number}. {tree.name}{owner}: "
            f"{_plural(tree.process_count, 'process', 'processes')}, "
            f"{_size(tree.memory_bytes)}, CPU {tree.cpu_percent:.0f}%"
        )
    lines += ["", _findings_heading(report.findings)]
    for finding in report.findings:
        label = SEVERITY_LABELS[finding.severity.value]
        lines += [
            f"  [{label}] {finding.title}",
            f"    Why: {finding.reason}",
            f"    Fix: {finding.fix}",
        ]
    count = len(report.table.nodes)
    lines += ["", f"Sampled {count} processes in {report.elapsed_seconds:.2f} seconds."]
    return "\n".join(lines)


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _findings_heading(findings: Sequence[Finding]) -> str:
    if not findings:
        return "Findings: none. Nothing here needs attention."
    return f"Findings ({len(findings)}):"


# --------------------------------------------------------------------------
# Command wiring
# --------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    """Run the command. Returns the exit code."""
    report = sample(known_signatures(), lock_file=getattr(args, "lock_file", None))
    if getattr(args, "json", False):
        data = {"schema": SCHEMA_VERSION, **report.to_dict()}
        print(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        print(render(report))
    return 0


def register(subparsers: Any) -> None:
    """Add `hc2 resources` to the parser."""
    parser = subparsers.add_parser(
        "resources",
        help="show memory pressure, process trees and wasted resources",
        description="Take one reading and explain it. Read-only: nothing is stopped.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print JSON instead of plain English",
    )
    parser.add_argument(
        "--lock-file",
        default=None,
        metavar="PATH",
        help="a heavy-work lock file to look for (F-3); off by default",
    )
    parser.set_defaults(handler=run)
