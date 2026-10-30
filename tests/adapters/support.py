"""Shared helpers for the Claude adapter tests.

Every test works on a copy of the made-up home under `tests/fixtures/claude`.
The process table is faked, so no test depends on what runs on this machine.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from hc2.adapters.base import AdapterContext, AdapterReport
from hc2.adapters.claude_code import ClaudeCodeAdapter
from hc2.adapters.claude_common import ProcessInfo, ProcessProbe
from hc2.adapters.claude_cowork import ClaudeCoworkAdapter
from hc2.adapters.claude_desktop import ClaudeDesktopAdapter
from hc2.model import Session

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "claude"
FIXTURE_HOME = FIXTURES / "home"
CONFIDENTIAL = "/home/alice/legal/example-matter"
SENTINEL_RE = re.compile(r"SENTINEL_[A-Z]+_[A-Z0-9_]+")

# pid -> (executable, start time as `ps` prints it). Pid 4003 is absent (dead).
PROCESSES: Mapping[int, ProcessInfo] = {
    4001: ProcessInfo("claude", "Thu Oct 29 10:05:05 2026"),
    4002: ProcessInfo("claude", "Thu Oct 29 14:01:43 2026"),
    4004: ProcessInfo("claude", "Fri Oct 30 09:15:00 2026"),  # registry says 08:00
    4005: ProcessInfo("zsh", "Thu Oct 29 10:05:05 2026"),  # not claude
    4006: ProcessInfo("claude", "Thu Oct 29 11:00:00 2026"),
    4007: ProcessInfo("claude", "Thu Oct 29 12:00:00 2026"),
    4008: ProcessInfo("claude", "Thu Oct 29 13:00:00 2026"),
    4009: ProcessInfo("claude", "Thu Oct 29 15:00:00 2026"),
}


def fake_probe(table: Mapping[int, ProcessInfo] | None = None) -> ProcessProbe:
    """A probe that answers from a fixed table instead of the real system."""
    known = PROCESSES if table is None else table

    def probe(pids: Sequence[int]) -> dict[int, ProcessInfo]:
        return {pid: known[pid] for pid in pids if pid in known}

    return probe


def failing_probe(pids: Sequence[int]) -> None:
    """A probe whose lookup failed."""
    return None


@contextlib.contextmanager
def fake_home() -> Iterator[Path]:
    """A writable copy of the made-up home, with the `claude` symlink in place."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "home"
        shutil.copytree(FIXTURE_HOME, home, symlinks=True)
        bin_dir = home / ".local" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "claude").symlink_to("../share/claude/versions/9.9.1")
        yield home


def adapters(
    home: Path, probe: ProcessProbe | None = None
) -> tuple[ClaudeCodeAdapter, ClaudeDesktopAdapter, ClaudeCoworkAdapter]:
    """The three adapters, pointed at the made-up home only."""
    apps = [str(home / "Applications")]
    return (
        ClaudeCodeAdapter(probe or fake_probe(), [str(home / ".local" / "bin")]),
        ClaudeDesktopAdapter(probe or fake_probe(), apps),
        ClaudeCoworkAdapter(apps),
    )


def context(
    home: Path, confidential: Sequence[str] = (CONFIDENTIAL,)
) -> AdapterContext:
    """A scan context for the made-up home."""
    return AdapterContext(home=str(home), confidential_folders=tuple(confidential))


def scan_all(
    home: Path,
    confidential: Sequence[str] = (CONFIDENTIAL,),
    probe: ProcessProbe | None = None,
) -> dict[str, AdapterReport]:
    """Run all three adapters. Keys are `cli`, `desktop` and `cowork`."""
    code, desktop, cowork = adapters(home, probe)
    ctx = context(home, confidential)
    return {
        "cli": code.scan(ctx),
        "desktop": desktop.scan(ctx),
        "cowork": cowork.scan(ctx),
    }


def by_id(report: AdapterReport) -> dict[str, Session]:
    """A report's sessions keyed by id."""
    return {session.id: session for session in report.sessions}


def fixture_sentinels() -> set[str]:
    """Every sentinel string planted anywhere in the fixtures."""
    found: set[str] = set()
    for path in FIXTURE_HOME.rglob("*"):
        if path.is_file() and not path.is_symlink():
            found.update(SENTINEL_RE.findall(path.read_text(encoding="utf-8")))
    return found
