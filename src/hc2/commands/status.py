"""`hc2 status`: the state of every harness and the findings that need a look."""

from __future__ import annotations

import argparse
from typing import Any

from hc2.commands._common import (
    add_config_flags,
    add_json_flag,
    latest_scan,
    print_json,
)
from hc2.text import plural

_HEADLINE = {
    "red": "RED. Something needs fixing now.",
    "amber": "AMBER. Something needs a look.",
    "green": "GREEN. Nothing needs fixing.",
    "unknown": "UNKNOWN. HC2 could not tell.",
}


def render_status(status: dict[str, Any]) -> str:
    """The plain-English form of a status payload."""
    counts = status["counts"]
    changes = status["changes"]
    lines = [f"AI HC2 status, from the scan at {status['generated']}"]
    seconds = status["scan_seconds"]
    if seconds is not None:
        lines[0] += f" (took {seconds:g} seconds)"
    lines.append(f"Overall: {_HEADLINE[status['level']]}")
    lines.append(
        f"Findings: {counts['red']} red, {counts['amber']} amber, "
        f"{counts['info']} info, {counts['acknowledged']} acknowledged."
    )
    lines.append(
        f"Since the scan before: {plural(changes['new_count'], 'new finding')}, "
        f"{plural(changes['fixed_count'], 'finding')} fixed."
    )
    for item in changes["new"]:
        lines.append(f"  New: [{item['sev'].upper()}] {item['title']}")
    for item in changes["fixed"]:
        lines.append(f"  Fixed: [{item['sev'].upper()}] {item['title']}")
    if status["top"]:
        lines.append("Findings to look at:")
        for number, item in enumerate(status["top"], start=1):
            lines.append(f"  {number}. [{item['sev'].upper()}] {item['title']}")
            lines.append(f"     Fix: {item['fix']}")
    lines.append("Harnesses:")
    if not status["harnesses"]:
        lines.append("  None were checked.")
    for item in status["harnesses"]:
        state = item["state"].replace("_", " ")
        lines.append(
            f"  {item['name']} ({item['id']}): {state}, "
            f"{item['sessions_running']} running, {item['sessions_stale']} stale"
        )
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    """Show the latest scan, scanning first if there is none or `--rescan`."""
    _, status = latest_scan(args, rescan=args.rescan)
    if args.json:
        print_json(status)
    else:
        print(render_status(status))
    return 0


def register(subparsers: Any) -> None:
    """Add the `status` command."""
    parser = subparsers.add_parser(
        "status",
        help="show the overall state and the findings that need a look",
        description="Show the latest scan. If there is none yet, HC2 scans first.",
    )
    add_json_flag(parser)
    parser.add_argument(
        "--rescan", action="store_true", help="scan again before showing the state"
    )
    add_config_flags(parser)
    parser.set_defaults(handler=run)
