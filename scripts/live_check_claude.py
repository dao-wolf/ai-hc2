#!/usr/bin/env python3
"""Run the three Claude adapters on the real home folder and print counts only.

Not part of CI. It prints no titles, paths, ids or problem text: only numbers.
Confidential folders come from `[privacy] confidential_folders` in the HC2
config file, if that file exists. Standard library only.
"""

from __future__ import annotations

import sys
import time
import tomllib
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hc2 import paths  # noqa: E402
from hc2.adapters.base import AdapterContext  # noqa: E402
from hc2.adapters.claude_code import ClaudeCodeAdapter  # noqa: E402
from hc2.adapters.claude_cowork import ClaudeCoworkAdapter  # noqa: E402
from hc2.adapters.claude_desktop import ClaudeDesktopAdapter  # noqa: E402
from hc2.model import SessionState  # noqa: E402


def masked_folder_setup() -> tuple[tuple[str, ...], str]:
    """The configured folders and a count-only description of them."""
    config = paths.config_file()
    if not config.is_file():
        return (), "not configured (no config file)"
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (), "not configured (config file unreadable)"
    privacy = data.get("privacy")
    raw = privacy.get("confidential_folders") if isinstance(privacy, dict) else None
    folders = tuple(f for f in raw or () if isinstance(f, str) and f.strip())
    if not folders:
        return (), "not configured (no folders listed)"
    return folders, f"{len(folders)} folder(s) configured"


def main() -> int:
    folders, setup = masked_folder_setup()
    ctx = AdapterContext(home=str(Path.home()), confidential_folders=folders)
    print(f"confidential folders: {setup}")
    started = time.monotonic()
    total_installs = total_sessions = total_masked = total_problems = 0
    exposed = 0
    for adapter in (ClaudeCodeAdapter(), ClaudeDesktopAdapter(), ClaudeCoworkAdapter()):
        report = adapter.scan(ctx)
        states = Counter(session.state for session in report.sessions)
        masked = sum(1 for s in report.sessions if s.confidential)
        exposed += sum(1 for s in report.sessions if s.confidential and s.title)
        total_installs += len(report.harness.installs)
        total_sessions += len(report.sessions)
        total_masked += masked
        total_problems += len(report.problems)
        counts = " ".join(f"{s.value}={states.get(s, 0)}" for s in SessionState)
        print(
            f"{adapter.id}: installed={report.harness.installed} "
            f"installs={len(report.harness.installs)} "
            f"sessions={len(report.sessions)} {counts} "
            f"masked={masked} problems={len(report.problems)}"
        )
    print(
        f"total: installs={total_installs} sessions={total_sessions} "
        f"masked={total_masked} problems={total_problems}"
    )
    print(f"confidential sessions with a title still set: {exposed}")
    print(f"scan time: {time.monotonic() - started:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
