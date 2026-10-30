"""`hc2 scan`: look at every harness now and store what was found."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from typing import Any

from hc2.commands._common import (
    add_config_flags,
    add_json_flag,
    print_json,
    runtime_from_args,
)
from hc2.commands.resources import scan_collector
from hc2.commands.status import render_status
from hc2.scan import run_scan
from hc2.store import Store
from hc2.summary import status_from_store


def run(args: argparse.Namespace) -> int:
    """Run a scan, store it and print the result."""
    runtime = runtime_from_args(args)
    result = run_scan(
        runtime.config,
        home=runtime.home,
        state=runtime.state,
        collector=(
            scan_collector(runtime.config)
            if runtime.config.adapter_enabled("resources")
            else None
        ),
    )
    with Store.create(runtime.state) as store:
        found = status_from_store(store, datetime.now(UTC))
    if found is None:  # pragma: no cover - the scan was just stored
        raise RuntimeError("the scan just stored could not be read back")
    _, status = found
    if args.json:
        print_json(
            {
                **status,
                "config_changed": result.config_changed,
                "findings": [item.to_dict() for item in result.snapshot.findings],
            }
        )
    else:
        print("Scan finished.")
        print(render_status(status))
    return 0


def register(subparsers: Any) -> None:
    """Add the `scan` command."""
    parser = subparsers.add_parser(
        "scan",
        help="scan every harness now and store the result",
        description="Read every enabled harness, list problems and store the result.",
    )
    add_json_flag(parser)
    add_config_flags(parser)
    parser.set_defaults(handler=run)
