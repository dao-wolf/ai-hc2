"""Shared pieces for the command modules. The leading underscore keeps this out
of `command_modules()`, so it is not a command."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hc2.config import Config, Overrides, load_config
from hc2.model import SCHEMA_VERSION, Snapshot
from hc2.paths import state_dir
from hc2.commands.resources import scan_collector
from hc2.scan import run_scan
from hc2.store import Store
from hc2.summary import status_from_store
from hc2.text import truncate

NO_SCAN_NOTICE = "No earlier scan was found, so HC2 is scanning now."


def print_json(data: dict[str, Any]) -> None:
    """Print one JSON object with sorted keys, led by the schema version."""
    payload = {"schema": SCHEMA_VERSION, **data}
    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


def add_json_flag(parser: argparse.ArgumentParser) -> None:
    """Add `--json` so it works after the command name as well as before it."""
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print JSON instead of plain English",
    )


def add_config_flags(parser: argparse.ArgumentParser) -> None:
    """Add the settings that can be given on the command line (C-1)."""
    group = parser.add_argument_group(
        "settings (these beat the environment and the config file)"
    )
    group.add_argument(
        "--confidential-folder",
        action="append",
        metavar="PATH",
        help="treat this folder as confidential (repeat for more); "
        "replaces the configured list",
    )
    group.add_argument(
        "--confidential-term",
        action="append",
        metavar="WORD",
        help="mask sessions with this word or phrase in the title or folder "
        "(repeat for more); replaces the configured list",
    )
    group.add_argument(
        "--adapter-timeout",
        type=float,
        metavar="SECONDS",
        help="time allowed per adapter",
    )
    group.add_argument(
        "--stale-hours",
        type=float,
        metavar="HOURS",
        help="idle time before a session is stale",
    )
    group.add_argument(
        "--retention-days", type=int, metavar="DAYS", help="days to keep snapshots"
    )
    group.add_argument(
        "--enable-adapter", action="append", metavar="ID", help="turn an adapter on"
    )
    group.add_argument(
        "--disable-adapter", action="append", metavar="ID", help="turn an adapter off"
    )


def overrides_from_args(args: argparse.Namespace) -> Overrides:
    """Collect the settings given as flags."""
    folders = getattr(args, "confidential_folder", None)
    terms = getattr(args, "confidential_term", None)
    return Overrides(
        confidential_folders=tuple(folders) if folders is not None else None,
        confidential_terms=tuple(terms) if terms is not None else None,
        adapter_timeout_seconds=getattr(args, "adapter_timeout", None),
        stale_hours=getattr(args, "stale_hours", None),
        retention_days=getattr(args, "retention_days", None),
        enable_adapters=tuple(getattr(args, "enable_adapter", None) or ()),
        disable_adapters=tuple(getattr(args, "disable_adapter", None) or ()),
    )


@dataclass(frozen=True)
class Runtime:
    """Where this run reads and writes."""

    config: Config
    home: str
    state: Path


def runtime_from_args(args: argparse.Namespace) -> Runtime:
    """Load the config and find the home and state folders."""
    config = load_config(overrides=overrides_from_args(args))
    home = str(Path("~").expanduser().absolute())
    return Runtime(config, home, state_dir())


def latest_scan(
    args: argparse.Namespace, *, rescan: bool
) -> tuple[Snapshot, dict[str, Any]]:
    """The newest stored scan and its status payload, scanning first if needed.

    HC2 scans when asked to (`rescan`) or when no scan has been stored yet.
    """
    runtime = runtime_from_args(args)
    if not rescan:
        store = Store.existing(runtime.state)
        if store is not None:
            with store:
                found = status_from_store(store, datetime.now(UTC))
            if found is not None:
                return found
        if not getattr(args, "json", False):
            print(NO_SCAN_NOTICE, file=sys.stderr)
    run_scan(
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
    if found is None:  # pragma: no cover - a scan was just stored
        raise RuntimeError("the scan just stored could not be read back")
    return found


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str | None]],
    widths: Sequence[int],
) -> str:
    """A plain-text table. Cells are cut to `widths`; `None` shows as `-`."""
    cells = [
        [truncate(cell or "-", width) for cell, width in zip(row, widths, strict=True)]
        for row in rows
    ]
    sizes = [
        max([len(head)] + [len(row[index]) for row in cells])
        for index, head in enumerate(headers)
    ]

    def line(values: Sequence[str]) -> str:
        return "  ".join(v.ljust(sizes[i]) for i, v in enumerate(values)).rstrip()

    rule = "  ".join("-" * size for size in sizes)
    return "\n".join([line(headers), rule, *(line(row) for row in cells)])
