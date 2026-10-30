"""The `hc2` command line.

Every command takes `--json`, either before or after the command name, and then
prints one JSON object with sorted keys instead of plain English.

Exit codes: 0 for success, 1 when a check fails, 2 for misuse.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from hc2 import __version__
from hc2.model import SCHEMA_VERSION
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


def _print_json(data: dict[str, Any]) -> None:
    data = {"schema": SCHEMA_VERSION, **data}
    print(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False))


def _cmd_version(as_json: bool) -> int:
    if as_json:
        _print_json({"name": "ai-hc2", "version": __version__})
    else:
        print(f"hc2 {__version__}")
    return 0


def _cmd_doctor(as_json: bool) -> int:
    checks = run_doctor()
    failed = any(check.status == FAIL for check in checks)
    if as_json:
        _print_json(
            {
                "checks": [asdict(check) for check in checks],
                "ok": not failed,
                "version": __version__,
            }
        )
        return 1 if failed else 0
    labels = {OK: "OK  ", WARN: "NOTE", FAIL: "FAIL"}
    print(f"AI HC2 doctor (version {__version__})")
    for check in checks:
        print(f"  {labels[check.status]}  {check.summary}")
        if check.fix:
            print(f"        Fix: {check.fix}")
    print(_doctor_summary(checks))
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="hc2",
        description="See and steer every AI harness on this machine. Local only.",
    )
    parser.add_argument(
        "--version", action="store_true", help="print the version and exit"
    )
    parser.add_argument(
        "--json", action="store_true", help="print JSON instead of plain English"
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    doctor = commands.add_parser(
        "doctor",
        help="check the setup and explain any problem",
        description="Check the Python version and the config and state folders.",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print JSON instead of plain English",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    as_json: bool = args.json
    if args.version:
        return _cmd_version(as_json)
    if args.command == "doctor":
        return _cmd_doctor(as_json)
    if as_json:
        _print_json({"error": "No command given.", "commands": ["doctor"]})
    else:
        parser.print_help(sys.stderr)
    return 2
