"""CLI subcommands, one module each.

Every module in this package exposes `register(subparsers)`, which adds its
subcommand to the `hc2` parser. `hc2.cli` finds them with `command_modules()`,
so adding a command never means editing a shared list.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType


def command_modules() -> list[ModuleType]:
    """Every command module in this package, sorted by name for a stable `--help`."""
    names = sorted(
        info.name
        for info in pkgutil.iter_modules(__path__)
        if not info.name.startswith("_")
    )
    return [importlib.import_module(f"{__name__}.{name}") for name in names]
