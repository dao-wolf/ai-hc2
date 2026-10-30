"""Collectors: read-only facts about this machine, as plain data.

Each collector splits "run a command" from "parse its text". The parsers take
strings, so tests feed them recorded text. Every command goes through
`run_command`, which refuses anything outside a short read-only allow-list and
never lets a process environment be read (S-3).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Sequence

Runner = Callable[[Sequence[str], float], str | None]
"""Runs a command with a timeout and returns its text, or `None` if it failed."""

ALLOWED_PROGRAMS = frozenset(
    {"ps", "lsof", "ioreg", "sysctl", "vm_stat", "memory_pressure", "pmset"}
)
PS_ARGV: tuple[str, ...] = (
    "ps",
    "-axo",
    "pid=,ppid=,pgid=,etime=,%cpu=,rss=,time=,args=",
)
"""The only `ps` call HC2 makes. `args` is last because it holds spaces.

`comm` is left out on purpose: macOS cuts it to 16 characters, so the
executable is read from the start of `args` instead.
"""


class UnsafeCommandError(ValueError):
    """A collector tried to run something outside the read-only allow-list."""


def assert_read_only(argv: Sequence[str]) -> None:
    """Raise `UnsafeCommandError` unless `argv` is an allowed read-only command.

    Process environments can hold tokens (`ps e`, `ps eww` and `ps -E` print
    them), so `ps` may only run as `PS_ARGV`, and no command may be given `eww`.
    """
    if not argv:
        raise UnsafeCommandError("empty command")
    program = os.path.basename(argv[0])
    if program not in ALLOWED_PROGRAMS:
        raise UnsafeCommandError(f"{program} is not an allowed command")
    if program == "ps":
        if tuple(argv) != PS_ARGV:
            raise UnsafeCommandError("ps may only run with the fixed argument list")
        return
    for arg in argv[1:]:
        if arg == "eww":
            raise UnsafeCommandError("environment flags are never allowed")


def run_command(argv: Sequence[str], timeout: float) -> str | None:
    """Run an allowed command without a shell and return its standard output.

    Returns `None` when the program is missing, fails to start or times out.
    A non-zero exit still returns its output, because `lsof` exits 1 when it
    finds nothing.
    """
    assert_read_only(argv)
    try:
        result = subprocess.run(
            list(argv),
            capture_output=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.decode("utf-8", errors="replace")
