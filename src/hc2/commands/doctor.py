"""`hc2 doctor`: check the setup and explain any problem."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from hc2 import __version__
from hc2.commands._common import add_json_flag, print_json
from hc2.paths import config_dir, display_path, state_dir

MIN_PYTHON = (3, 11)

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class Check:
    """The result of one `doctor` check."""

    id: str
    status: str
    summary: str
    fix: str | None = None


def check_python(version: Sequence[int]) -> Check:
    """Check that the running Python is new enough."""
    text = ".".join(str(part) for part in version[:3])
    needed = ".".join(str(part) for part in MIN_PYTHON)
    if tuple(version[:2]) >= MIN_PYTHON:
        return Check("python", OK, f"Python {text} is new enough ({needed} or later).")
    return Check(
        "python",
        FAIL,
        f"Python {text} is too old. HC2 needs {needed} or later.",
        f"Install Python {needed} or later and run HC2 with it.",
    )


def check_folder(check_id: str, label: str, path: Path) -> Check:
    """Check that a config or state folder exists. Never creates it."""
    shown = display_path(path)
    if path.is_dir():
        return Check(check_id, OK, f"The {label} folder exists: {shown}")
    if path.exists():
        return Check(
            check_id,
            FAIL,
            f"The {label} folder path is a file, not a folder: {shown}",
            f"Move or delete that file so HC2 can use the folder: {shown}",
        )
    return Check(
        check_id,
        WARN,
        f"The {label} folder does not exist yet: {shown}",
        f"HC2 creates it when it first needs it. To create it now: mkdir -p {shown}",
    )


def run_doctor() -> list[Check]:
    """Run every `doctor` check, in a fixed order."""
    return [
        check_python(sys.version_info[:3]),
        check_folder("config_dir", "config", config_dir()),
        check_folder("state_dir", "state", state_dir()),
    ]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _doctor_summary(checks: Sequence[Check]) -> str:
    fails = sum(1 for check in checks if check.status == FAIL)
    warns = sum(1 for check in checks if check.status == WARN)
    if fails:
        return f"Found {_plural(fails, 'problem')} to fix."
    if warns:
        return f"No problems. {_plural(warns, 'thing')} to note."
    return "Everything looks fine."


def run(args: argparse.Namespace) -> int:
    """Run the checks and print the result."""
    checks = run_doctor()
    failed = any(check.status == FAIL for check in checks)
    if args.json:
        data: dict[str, Any] = {
            "checks": [asdict(check) for check in checks],
            "ok": not failed,
            "version": __version__,
        }
        print_json(data)
        return 1 if failed else 0
    labels = {OK: "OK  ", WARN: "NOTE", FAIL: "FAIL"}
    print(f"AI HC2 doctor (version {__version__})")
    for check in checks:
        print(f"  {labels[check.status]}  {check.summary}")
        if check.fix:
            print(f"        Fix: {check.fix}")
    print(_doctor_summary(checks))
    return 1 if failed else 0


def register(subparsers: Any) -> None:
    """Add the `doctor` command."""
    parser = subparsers.add_parser(
        "doctor",
        help="check the setup and explain any problem",
        description="Check the Python version and the config and state folders.",
    )
    add_json_flag(parser)
    parser.set_defaults(handler=run)
