"""The `hc2` command line.

Every command takes `--json`, either before or after the command name, and then
prints one JSON object with sorted keys instead of plain English. Commands live
in `hc2.commands`, one module each, and are found by `command_modules()`.

Exit codes: 0 for success, 1 when a check fails or HC2 cannot do the job,
2 for misuse.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from hc2 import __version__
from hc2.commands import command_modules
from hc2.commands._common import print_json
from hc2.commands.doctor import (  # noqa: F401 - kept importable from here
    FAIL,
    MIN_PYTHON,
    OK,
    WARN,
    Check,
    check_folder,
    check_python,
    run_doctor,
)
from hc2.errors import UserError


def _cmd_version(as_json: bool) -> int:
    if as_json:
        print_json({"name": "ai-hc2", "version": __version__})
    else:
        print(f"hc2 {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser, with every command module registered."""
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
    for module in command_modules():
        module.register(commands)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    as_json: bool = args.json
    if args.version:
        return _cmd_version(as_json)
    handler = getattr(args, "handler", None)
    if handler is None:
        if as_json:
            names = [module.__name__.rsplit(".", 1)[-1] for module in command_modules()]
            print_json({"commands": names, "error": "No command given."})
        else:
            parser.print_help(sys.stderr)
        return 2
    try:
        code: int = handler(args)
    except UserError as error:
        if as_json:
            print_json({"error": str(error), "ok": False})
        else:
            print(f"hc2: {error}", file=sys.stderr)
        return 1
    return code
