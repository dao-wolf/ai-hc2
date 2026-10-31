"""`hc2 sessions`: list the sessions found in the latest scan."""

from __future__ import annotations

import argparse
from typing import Any

from hc2.commands._common import (
    add_config_flags,
    add_json_flag,
    latest_scan,
    print_json,
    render_table,
)
from hc2.model import Session, SessionState, Snapshot
from hc2.text import plural

_HEADERS = ("HARNESS", "STATE", "LAST ACTIVITY", "MODEL", "TITLE", "FOLDER", "ID")
_WIDTHS = (24, 13, 20, 24, 40, 30, 36)


def select_sessions(
    snapshot: Snapshot, harness: str | None, state: str | None
) -> list[Session]:
    """The snapshot's sessions, filtered by harness id and state."""
    chosen: list[Session] = []
    for report in snapshot.harnesses:
        if harness is not None and report.harness.id != harness:
            continue
        chosen.extend(
            item for item in report.sessions if state is None or item.state == state
        )
    return chosen


def render_sessions(snapshot: Snapshot, sessions: list[Session]) -> str:
    """The plain-English table."""
    head = f"{plural(len(sessions), 'session')} from the scan at {snapshot.generated}."
    if not sessions:
        return head + " None match."
    rows = [
        (
            item.harness_id,
            item.state.value,
            item.last_activity,
            item.model,
            item.title,
            item.folder,
            item.id,
        )
        for item in sessions
    ]
    return head + "\n" + render_table(_HEADERS, rows, _WIDTHS)


def run(args: argparse.Namespace) -> int:
    """List sessions from the latest scan, scanning first if there is none."""
    snapshot, _ = latest_scan(args, rescan=args.rescan)
    known = sorted(report.harness.id for report in snapshot.harnesses)
    if args.harness is not None and args.harness not in known:
        listed = ", ".join(known) if known else "none"
        message = f"No harness has that id. Harnesses in the last scan: {listed}."
        if args.json:
            print_json({"error": message, "harnesses": known, "ok": False})
        else:
            print(f"hc2: {message}")
        return 2
    sessions = select_sessions(snapshot, args.harness, args.state)
    if args.json:
        print_json(
            {
                "count": len(sessions),
                "filters": {"harness": args.harness, "state": args.state},
                "generated": snapshot.generated,
                "scan_id": snapshot.scan_id,
                "sessions": [item.to_dict() for item in sessions],
            }
        )
    else:
        print(render_sessions(snapshot, sessions))
    return 0


def register(subparsers: Any) -> None:
    """Add the `sessions` command."""
    parser = subparsers.add_parser(
        "sessions",
        help="list sessions from the latest scan",
        description="List sessions. If there is no scan yet, HC2 scans first.",
    )
    add_json_flag(parser)
    parser.add_argument("--harness", metavar="ID", help="only this harness")
    parser.add_argument(
        "--state",
        choices=[item.value for item in SessionState],
        help="only sessions in this state",
    )
    parser.add_argument(
        "--rescan", action="store_true", help="scan again before listing"
    )
    add_config_flags(parser)
    parser.set_defaults(handler=run)
