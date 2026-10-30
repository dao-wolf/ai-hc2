"""System pressure: memory, swap, compressor, load and heat (FR-4).

Four quick commands feed one reading: `sysctl`, `vm_stat`, `memory_pressure -Q`
and `pmset -g therm`. Each has a timeout and a parser that takes text, so a
missing tool or an odd format gives `None` for that value and nothing else.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime

from hc2.collect import Runner, run_command
from hc2.model import Model, SystemSample

SYSCTL_ARGV: tuple[str, ...] = (
    "sysctl",
    "hw.memsize",
    "hw.ncpu",
    "vm.swapusage",
    "vm.loadavg",
    "kern.memorystatus_vm_pressure_level",
)
VM_STAT_ARGV: tuple[str, ...] = ("vm_stat",)
MEMORY_PRESSURE_ARGV: tuple[str, ...] = ("memory_pressure", "-Q")
PMSET_ARGV: tuple[str, ...] = ("pmset", "-g", "therm")
TIMEOUT = 1.5

_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_SWAP_RE = re.compile(
    r"total\s*=\s*([\d.]+)([KMGT])\s+used\s*=\s*([\d.]+)([KMGT])", re.IGNORECASE
)
_LEVELS = {1: "normal", 2: "warn", 4: "critical"}


@dataclass(frozen=True)
class SystemReading(Model):
    """A `SystemSample` plus the extra readings the resource rules need.

    `kernel_level` is `normal`, `warn` or `critical`. Missing values are `None`.
    """

    sample: SystemSample
    swap_total_bytes: int | None = None
    compressor_bytes: int | None = None
    free_percent: int | None = None
    kernel_level: str | None = None
    cpu_count: int | None = None


def _int(text: str | None) -> int | None:
    if text is None:
        return None
    match = re.search(r"\d+", text)
    return int(match.group()) if match else None


def parse_sysctl(text: str) -> dict[str, str]:
    """Turn `name: value` lines into a dict. Other lines are ignored."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() and " " not in name.strip():
            values[name.strip()] = value.strip()
    return values


def parse_swap(value: str | None) -> tuple[int | None, int | None]:
    """Parse `vm.swapusage` into `(total_bytes, used_bytes)`."""
    match = _SWAP_RE.search(value or "")
    if match is None:
        return None, None
    total = float(match.group(1)) * _UNITS[match.group(2).upper()]
    used = float(match.group(3)) * _UNITS[match.group(4).upper()]
    return int(total), int(used)


def parse_loadavg(value: str | None) -> tuple[float | None, float | None, float | None]:
    """Parse `vm.loadavg`, such as `{ 1.20 1.50 1.70 }`, into three loads."""
    numbers = re.findall(r"\d+(?:\.\d+)?", value or "")
    if len(numbers) < 3:
        return None, None, None
    return float(numbers[0]), float(numbers[1]), float(numbers[2])


def parse_memory_pressure_q(text: str) -> int | None:
    """Parse the free percentage from `memory_pressure -Q`."""
    match = re.search(r"free percentage:\s*(\d{1,3})\s*%", text)
    if match is None:
        return None
    percent = int(match.group(1))
    return percent if percent <= 100 else None


def parse_vm_stat_compressor(text: str) -> int | None:
    """Parse bytes held by the memory compressor from `vm_stat`."""
    size = re.search(r"page size of (\d+) bytes", text)
    pages = re.search(r"Pages occupied by compressor:\s*(\d+)", text)
    if size is None or pages is None:
        return None
    return int(size.group(1)) * int(pages.group(1))


def parse_thermal(text: str) -> str | None:
    """Parse `pmset -g therm` into `nominal`, `elevated` or `throttled`.

    Returns `None` when the text is not recognised.
    """
    limit = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", text)
    if limit is not None and int(limit.group(1)) < 100:
        return "throttled"
    if "No thermal warning level has been recorded" in text:
        return "nominal"
    level = re.search(r"thermal warning level\D*=\s*(\d+)", text, re.IGNORECASE)
    if level is not None:
        return "elevated" if int(level.group(1)) > 0 else "nominal"
    if limit is not None:
        return "nominal"
    return None


def build_reading(
    *,
    sysctl: str,
    vm_stat: str,
    memory_pressure: str,
    pmset: str,
    sampled_at: str | None = None,
) -> SystemReading:
    """Build a reading from the text of the four commands. Pure."""
    values = parse_sysctl(sysctl)
    total = _int(values.get("hw.memsize"))
    swap_total, swap_used = parse_swap(values.get("vm.swapusage"))
    load = parse_loadavg(values.get("vm.loadavg"))
    free = parse_memory_pressure_q(memory_pressure)
    used = None
    if total is not None and free is not None:
        used = total * (100 - free) // 100
    level_number = _int(values.get("kern.memorystatus_vm_pressure_level"))
    sample = SystemSample(
        sampled_at=sampled_at,
        memory_total_bytes=total,
        memory_used_bytes=used,
        swap_used_bytes=swap_used,
        load_1m=load[0],
        load_5m=load[1],
        load_15m=load[2],
        thermal_state=parse_thermal(pmset),
    )
    return SystemReading(
        sample=sample,
        swap_total_bytes=swap_total,
        compressor_bytes=parse_vm_stat_compressor(vm_stat),
        free_percent=free,
        kernel_level=_LEVELS.get(level_number) if level_number is not None else None,
        cpu_count=_int(values.get("hw.ncpu")),
    )


def collect_system(
    *, runner: Runner = run_command, now: datetime | None = None
) -> SystemReading:
    """Run the four commands together and build a reading."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    commands = (SYSCTL_ARGV, VM_STAT_ARGV, MEMORY_PRESSURE_ARGV, PMSET_ARGV)
    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        jobs = [pool.submit(runner, argv, TIMEOUT) for argv in commands]
        texts = [job.result() or "" for job in jobs]
    return build_reading(
        sysctl=texts[0],
        vm_stat=texts[1],
        memory_pressure=texts[2],
        pmset=texts[3],
        sampled_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
