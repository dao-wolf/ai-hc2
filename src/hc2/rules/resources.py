"""Waste rules for resources (FR-5): pure functions that return findings.

Inputs are a `SystemReading`, the `ProcessNode`s and the state of each session.
No rule runs a command, reads a file or changes anything. A finding's `fix`
text may suggest an action, but only as advice: proposals come later (S6).

Ids never hold a pid or a path (FR-9): they come from the rule id, the process
name and the listening port, so the same problem keeps the same id from one
scan to the next. Similar processes are grouped into one finding for that
reason, and their process ids appear in the reason text only.

Memory sizes use 1 MB = 1,048,576 bytes, the same as `ps`. Thresholds are
inclusive (`>=`) unless this file says "more than" or "below".
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from typing import Any

from hc2.collect.processes import (
    ProcessIndex,
    is_interpreter,
    total_cpu,
    total_memory,
)
from hc2.collect.system import SystemReading
from hc2.model import (
    Finding,
    ProcessNode,
    ProcessRole,
    SessionState,
    Severity,
    stable_id,
)

MB = 1024 * 1024
GB = 1024 * MB

RULE_MEMORY_PRESSURE = "resources.memory_pressure"
RULE_IDLE_SESSION = "resources.idle_session"
RULE_BUSY_QUIET = "resources.busy_quiet"
RULE_ORPHAN = "resources.orphan"
RULE_CONCURRENT_TESTS = "resources.concurrent_tests"
RULE_DUPLICATE_MCP = "resources.duplicate_mcp"
RULE_HOT_CHILD = "resources.hot_child"
RULE_RENDERER_BLOAT = "resources.renderer_bloat"
RULE_HEAVY_LOCK = "resources.heavy_lock"

NOTHING_RUNS = "HC2 only suggests this. It never stops anything itself."


@dataclass(frozen=True)
class Thresholds:
    """Every limit a rule uses. The defaults come from the resource spike."""

    swap_red_percent: float = 80.0
    swap_amber_percent: float = 50.0
    compressor_percent_of_ram: float = 25.0
    free_percent_min: float = 15.0
    idle_info_hours: float = 6.0
    idle_amber_hours: float = 24.0
    idle_cpu_max: float = 3.0
    busy_quiet_minutes: float = 45.0
    busy_quiet_cpu_max: float = 2.0
    orphan_min_age_minutes: float = 10.0
    orphan_red_mb: float = 500.0
    orphan_red_cpu: float = 25.0
    heavy_job_cpu: float = 40.0
    heavy_job_mb: float = 500.0
    heavy_jobs_allowed: int = 1
    duplicate_mcp_min_instances: int = 2
    duplicate_mcp_amber_mb: float = 100.0
    duplicate_mcp_red_mb: float = 500.0
    hot_child_cpu: float = 60.0
    hot_child_minutes: float = 15.0
    hot_child_red_cpu: float = 150.0
    renderer_mb: float = 1500.0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Thresholds:
        """Override defaults from config values. Unknown or bad keys are ignored."""
        defaults = cls()
        changes: dict[str, float | int] = {}
        for item in fields(cls):
            value = data.get(item.name)
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            default = getattr(defaults, item.name)
            is_count = isinstance(default, int)
            changes[item.name] = int(value) if is_count else float(value)
        return replace(defaults, **changes)


DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True)
class SessionActivity:
    """What the scan knows about one live session, for the session rules.

    `state_age_seconds` is how long the session has been in `state`. `root_pid`
    is the harness process the session runs in, or `None` when unknown; a
    session whose process is not found is skipped, since it holds nothing.
    """

    session_id: str
    harness_id: str
    state: SessionState
    state_age_seconds: int | None = None
    root_pid: int | None = None


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _subject(*parts: str | int) -> str:
    text = ":".join(str(part) for part in parts)
    try:
        stable_id("finding", "check", text)
    except ValueError:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return text


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    reason: str,
    fix: str,
    subject: str,
    *,
    harness_id: str | None = None,
    session_id: str | None = None,
) -> Finding:
    return Finding(
        id=stable_id("finding", rule_id, harness_id or "", _subject(subject)),
        rule_id=rule_id,
        severity=severity,
        title=title,
        reason=reason,
        fix=fix,
        harness_id=harness_id,
        session_id=session_id,
    )


def _size(num_bytes: float) -> str:
    if num_bytes >= GB:
        return f"{num_bytes / GB:.1f} GB"
    return f"{num_bytes / MB:.0f} MB"


def _duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} minutes"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.0f} hours" if hours >= 10 else f"{hours:.1f} hours"
    return f"{hours / 24:.0f} days"


def _plural(count: int, noun: str) -> str:
    if count == 1:
        return f"{count} {noun}"
    suffix = "es" if noun.endswith(("s", "ss")) else "s"
    return f"{count} {noun}{suffix}"


def _pids(nodes: Sequence[ProcessNode], limit: int = 5) -> str:
    ordered = sorted(node.pid for node in nodes)
    shown = ", ".join(str(pid) for pid in ordered[:limit])
    extra = len(nodes) - limit
    return f"{shown} and {extra} more" if extra > 0 else shown


def _common_harness(nodes: Iterable[ProcessNode]) -> str | None:
    harnesses = {node.harness_id for node in nodes}
    return next(iter(harnesses)) if len(harnesses) == 1 else None


def _port_text(ports: Sequence[int]) -> str:
    return "" if not ports else " on port " + ", ".join(str(p) for p in ports)


def _group_by_name_and_ports(
    nodes: Iterable[ProcessNode],
) -> dict[tuple[str, tuple[int, ...]], list[ProcessNode]]:
    groups: dict[tuple[str, tuple[int, ...]], list[ProcessNode]] = {}
    for node in nodes:
        groups.setdefault((node.name, node.listening_ports), []).append(node)
    return groups


def _memory_of(node: ProcessNode) -> int:
    return node.memory_bytes or 0


# --------------------------------------------------------------------------
# Memory pressure
# --------------------------------------------------------------------------


def _pressure(
    reading: SystemReading, th: Thresholds
) -> tuple[Severity | None, list[str]]:
    """Return the worst pressure severity (or `None`) and the plain reasons."""
    worst: Severity | None = None
    reasons: list[str] = []

    def raise_to(level: Severity) -> None:
        nonlocal worst
        if worst is None or level.rank > worst.rank:
            worst = level

    used = reading.sample.swap_used_bytes
    total = reading.swap_total_bytes
    if used is not None and total:
        percent = 100.0 * used / total
        if percent >= th.swap_red_percent:
            raise_to(Severity.RED)
        elif percent >= th.swap_amber_percent:
            raise_to(Severity.AMBER)
        if percent >= th.swap_amber_percent:
            reasons.append(
                f"swap is {percent:.0f}% used ({_size(used)} of {_size(total)})"
            )
    ram = reading.sample.memory_total_bytes
    if reading.compressor_bytes is not None and ram:
        percent = 100.0 * reading.compressor_bytes / ram
        if percent >= th.compressor_percent_of_ram:
            raise_to(Severity.AMBER)
            reasons.append(f"the memory compressor holds {percent:.0f}% of RAM")
    if reading.free_percent is not None and reading.free_percent < th.free_percent_min:
        raise_to(Severity.AMBER)
        reasons.append(f"only {reading.free_percent}% of memory is free")
    if reading.kernel_level == "critical":
        raise_to(Severity.RED)
        reasons.append("macOS reports critical memory pressure")
    elif reading.kernel_level == "warn":
        raise_to(Severity.AMBER)
        reasons.append("macOS reports a memory pressure warning")
    return worst, reasons


def is_under_pressure(reading: SystemReading, th: Thresholds) -> bool:
    """True when swap, the compressor, free memory or macOS report pressure."""
    return _pressure(reading, th)[0] is not None


def memory_pressure(reading: SystemReading, th: Thresholds) -> list[Finding]:
    """One finding when swap, the compressor, free memory or macOS say so."""
    severity, reasons = _pressure(reading, th)
    if severity is None:
        return []
    return [
        _finding(
            RULE_MEMORY_PRESSURE,
            severity,
            "This Mac is short of memory",
            "Memory is under pressure: " + "; ".join(reasons) + ". "
            "Everything slows down when this happens.",
            "Suggested action: close or archive sessions you have finished and quit "
            "apps you are not using. The other findings show what holds the most. "
            + NOTHING_RUNS,
            "memory",
        )
    ]


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def _session_tree(
    index: ProcessIndex, session: SessionActivity
) -> list[ProcessNode]:
    return [] if session.root_pid is None else index.subtree(session.root_pid)


def idle_sessions(
    index: ProcessIndex,
    sessions: Sequence[SessionActivity],
    th: Thresholds,
    *,
    under_pressure: bool,
) -> list[Finding]:
    """Idle or waiting sessions that still hold processes and memory."""
    findings: list[Finding] = []
    for session in sessions:
        if session.state not in (SessionState.RUNNING_IDLE, SessionState.WAITING):
            continue
        age = session.state_age_seconds
        if age is None or age < th.idle_info_hours * 3600:
            continue
        tree = _session_tree(index, session)
        if not tree:
            continue
        children = [node for node in tree if node.pid != session.root_pid]
        busy_kind = any(
            node.role in (ProcessRole.TEST_WORKER, ProcessRole.BROWSER)
            for node in children
        )
        cpu = total_cpu(tree)
        if cpu >= th.idle_cpu_max or busy_kind:
            continue
        long_idle = age >= th.idle_amber_hours * 3600
        severity = Severity.AMBER if long_idle else Severity.INFO
        if under_pressure and severity is Severity.INFO:
            severity = Severity.AMBER
        findings.append(
            _finding(
                RULE_IDLE_SESSION,
                severity,
                "An idle session is still holding memory",
                f"This session has been {session.state.value.replace('running-', '')} "
                f"for {_duration(age)}, yet it keeps {_plural(len(tree), 'process')} "
                f"open that use {_size(total_memory(tree))} and about {cpu:.1f}% CPU.",
                "Suggested action: archive or close the session if you have "
                "finished with it, so its processes can exit. " + NOTHING_RUNS,
                session.session_id,
                harness_id=session.harness_id,
                session_id=session.session_id,
            )
        )
    return findings


def busy_but_quiet(
    index: ProcessIndex, sessions: Sequence[SessionActivity], th: Thresholds
) -> list[Finding]:
    """Sessions that say they are busy while nothing uses any CPU."""
    findings: list[Finding] = []
    for session in sessions:
        age = session.state_age_seconds
        if session.state is not SessionState.RUNNING_BUSY or age is None:
            continue
        if age < th.busy_quiet_minutes * 60:
            continue
        tree = _session_tree(index, session)
        if not tree:
            continue
        cpu = total_cpu(tree)
        if cpu >= th.busy_quiet_cpu_max:
            continue
        findings.append(
            _finding(
                RULE_BUSY_QUIET,
                Severity.INFO,
                "A session says it is busy but is doing nothing",
                f"This session has reported busy for {_duration(age)}, but its "
                f"processes use only {cpu:.1f}% CPU. It may be waiting on a stuck "
                "tool or a network call.",
                "Suggested action: look at the session and stop the current turn "
                "if it has hung. " + NOTHING_RUNS,
                session.session_id,
                harness_id=session.harness_id,
                session_id=session.session_id,
            )
        )
    return findings


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------

_ORPHAN_ROLES = frozenset(
    {
        ProcessRole.BROWSER,
        ProcessRole.DEV_SERVER,
        ProcessRole.TEST_WORKER,
        ProcessRole.MCP_SERVER,
    }
)


def _is_orphan_candidate(node: ProcessNode) -> bool:
    if node.parent_pid != 1 or node.role is ProcessRole.HARNESS:
        return False
    if node.role in _ORPHAN_ROLES:
        return True
    return node.role is ProcessRole.OTHER and is_interpreter(node.name)


def orphans(nodes: Sequence[ProcessNode], th: Thresholds) -> list[Finding]:
    """Long-lived helper processes whose parent has gone (their parent is launchd)."""
    candidates = [
        node
        for node in nodes
        if _is_orphan_candidate(node)
        and node.age_seconds is not None
        and node.age_seconds >= th.orphan_min_age_minutes * 60
    ]
    findings: list[Finding] = []
    for (name, ports), group in sorted(_group_by_name_and_ports(candidates).items()):
        heavy = any(
            _memory_of(node) >= th.orphan_red_mb * MB
            or (node.cpu_percent or 0.0) >= th.orphan_red_cpu
            for node in group
        )
        oldest = max(node.age_seconds or 0 for node in group)
        what = _plural(len(group), name + " process")
        extra = f", especially if nothing should use port {ports[0]}" if ports else ""
        findings.append(
            _finding(
                RULE_ORPHAN,
                Severity.RED if heavy else Severity.AMBER,
                f"A leftover {name} process is still running{_port_text(ports)}",
                f"{what} (ids {_pids(group)}) lost the program that "
                f"started {'it' if len(group) == 1 else 'them'}, and "
                f"{'has' if len(group) == 1 else 'have'} run for "
                f"{_duration(oldest)}. Memory used: {_size(total_memory(group))}; "
                f"CPU: {total_cpu(group):.0f}%.",
                "Suggested action: check what it is for and stop it from a "
                "terminal if you no longer need it"
                + extra
                + ". "
                + NOTHING_RUNS,
                _subject(name, *(f"p{port}" for port in ports)),
                harness_id=_common_harness(group),
            )
        )
    return findings


def _test_jobs(index: ProcessIndex) -> list[list[ProcessNode]]:
    """Group test-worker processes into jobs by their top test-worker ancestor."""
    jobs: dict[int, list[ProcessNode]] = {}
    for node in index.nodes:
        if node.role is not ProcessRole.TEST_WORKER:
            continue
        top = node
        seen = {top.pid}
        while top.parent_pid in index.by_pid:
            parent = index.by_pid[top.parent_pid]
            if parent.role is not ProcessRole.TEST_WORKER or parent.pid in seen:
                break
            seen.add(parent.pid)
            top = parent
        jobs.setdefault(top.pid, []).append(node)
    return list(jobs.values())


def concurrent_tests(index: ProcessIndex, th: Thresholds) -> list[Finding]:
    """More heavy test jobs at once than the Mac should run."""
    heavy = [
        job
        for job in _test_jobs(index)
        if total_cpu(job) >= th.heavy_job_cpu
        or total_memory(job) >= th.heavy_job_mb * MB
    ]
    if len(heavy) <= th.heavy_jobs_allowed:
        return []
    everything = [node for job in heavy for node in job]
    return [
        _finding(
            RULE_CONCURRENT_TESTS,
            Severity.RED,
            "Several heavy test jobs are running at once",
            f"{len(heavy)} test jobs each use at least {th.heavy_job_cpu:.0f}% CPU "
            f"or {th.heavy_job_mb:.0f} MB. Together they use "
            f"{total_cpu(everything):.0f}% CPU and {_size(total_memory(everything))}, "
            f"and only {th.heavy_jobs_allowed} should run at a time.",
            "Suggested action: let one job finish before starting the next, or "
            "run them one after another. " + NOTHING_RUNS,
            "test-jobs",
        )
    ]


def _mcp_group_key(node: ProcessNode) -> str:
    """Group by name, but only by command fingerprint for generic runtimes."""
    if is_interpreter(node.name):
        return f"{node.name}-{(node.fingerprint or 'unknown')[:8]}"
    return node.name


def duplicate_mcp(index: ProcessIndex, th: Thresholds) -> list[Finding]:
    """The same MCP server running more than once."""
    groups: dict[str, list[ProcessNode]] = {}
    for node in index.nodes:
        if node.role is not ProcessRole.MCP_SERVER:
            continue
        parent = index.by_pid.get(node.parent_pid) if node.parent_pid else None
        if parent is not None and parent.role is ProcessRole.MCP_SERVER:
            continue  # inner process of a wrapper such as npm: count the wrapper
        groups.setdefault(_mcp_group_key(node), []).append(node)
    findings: list[Finding] = []
    for key, group in sorted(groups.items()):
        if len(group) < th.duplicate_mcp_min_instances:
            continue
        members = {
            member.pid: member
            for node in group
            for member in index.subtree(node.pid)
            if member.role is ProcessRole.MCP_SERVER
        }
        memory = total_memory(members.values())
        if memory >= th.duplicate_mcp_red_mb * MB:
            severity = Severity.RED
        elif memory >= th.duplicate_mcp_amber_mb * MB:
            severity = Severity.AMBER
        else:
            severity = Severity.INFO
        name = group[0].name
        title = (
            f"An MCP server started by {name} is running {len(group)} times"
            if is_interpreter(name)
            else f"The {name} MCP server is running {len(group)} times"
        )
        findings.append(
            _finding(
                RULE_DUPLICATE_MCP,
                severity,
                title,
                f"{len(group)} copies of the same MCP server (ids {_pids(group)}) "
                f"are running and use {_size(memory)} between them. Most setups "
                "need only one.",
                "Suggested action: restart the harness that started the extra "
                "copies, or remove the duplicate server from its configuration. "
                + NOTHING_RUNS,
                key,
                harness_id=_common_harness(group),
            )
        )
    return findings


def _average_cpu(node: ProcessNode, cpu_seconds: Mapping[int, float]) -> float | None:
    """CPU over the process's whole life if known, else the current reading."""
    used = cpu_seconds.get(node.pid)
    if used is not None and node.age_seconds:
        return 100.0 * used / node.age_seconds
    return node.cpu_percent


def hot_children(
    nodes: Sequence[ProcessNode],
    th: Thresholds,
    cpu_seconds: Mapping[int, float],
) -> list[Finding]:
    """Helper processes inside a harness that have run hot for a long time."""
    hot: dict[int, float] = {}
    for node in nodes:
        if node.harness_id is None or node.role is ProcessRole.HARNESS:
            continue
        if node.age_seconds is None or node.age_seconds < th.hot_child_minutes * 60:
            continue
        average = _average_cpu(node, cpu_seconds)
        if average is not None and average >= th.hot_child_cpu:
            hot[node.pid] = average
    findings: list[Finding] = []
    chosen = [node for node in nodes if node.pid in hot]
    for (name, ports), group in sorted(_group_by_name_and_ports(chosen).items()):
        peak = max(hot[node.pid] for node in group)
        oldest = max(node.age_seconds or 0 for node in group)
        findings.append(
            _finding(
                RULE_HOT_CHILD,
                Severity.RED if peak >= th.hot_child_red_cpu else Severity.AMBER,
                f"A {name} process has been working hard for a long time"
                f"{_port_text(ports)}",
                f"{_plural(len(group), name + ' process')} (ids {_pids(group)}) "
                f"{'has' if len(group) == 1 else 'have'} averaged "
                f"{peak:.0f}% CPU over {_duration(oldest)}.",
                "Suggested action: check that it is doing useful work. A runaway "
                "file watcher or a test loop is the usual cause. " + NOTHING_RUNS,
                _subject(name, *(f"p{port}" for port in ports)),
                harness_id=_common_harness(group),
            )
        )
    return findings


def renderer_bloat(
    nodes: Sequence[ProcessNode], th: Thresholds, *, under_pressure: bool
) -> list[Finding]:
    """An app's renderer process that has grown very large."""
    big = [
        node
        for node in nodes
        if node.harness_id is not None
        and node.name.endswith("Helper (Renderer)")
        and _memory_of(node) >= th.renderer_mb * MB
    ]
    findings: list[Finding] = []
    for (name, _), group in sorted(_group_by_name_and_ports(big).items()):
        biggest = max(_memory_of(node) for node in group)
        findings.append(
            _finding(
                RULE_RENDERER_BLOAT,
                Severity.RED if under_pressure else Severity.AMBER,
                f"The {name} process has grown very large",
                f"A renderer (id {_pids(group)}) uses {_size(biggest)}. These "
                "grow the longer an app stays open.",
                "Suggested action: quit and reopen the app when no session is "
                "mid-task. That normally resets it. " + NOTHING_RUNS,
                name,
                harness_id=_common_harness(group),
            )
        )
    return findings


def heavy_lock(present: bool) -> list[Finding]:
    """Information only: the heavy-work lock file exists (F-3)."""
    if not present:
        return []
    return [
        _finding(
            RULE_HEAVY_LOCK,
            Severity.INFO,
            "A heavy job holds the shared lock",
            "The heavy-work lock file exists, so one of your own heavy jobs is "
            "probably running. HC2 will not start heavy work while it does.",
            "Nothing to do unless the lock is left over from a job that has "
            "finished. In that case remove the file yourself. " + NOTHING_RUNS,
            "lock",
        )
    ]


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def evaluate(
    reading: SystemReading,
    nodes: Sequence[ProcessNode],
    sessions: Sequence[SessionActivity] = (),
    *,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    cpu_seconds: Mapping[int, float] | None = None,
    heavy_lock_present: bool = False,
) -> tuple[Finding, ...]:
    """Run every resource rule. Most urgent first, then by id, so output is stable.

    `cpu_seconds` is cumulative CPU time per pid (from `ProcessTable`); with it
    the hot-child rule judges a process over its whole life. `sessions` may be
    empty, in which case the session rules simply find nothing. The scan passes
    none here and runs them later with `evaluate_sessions`, once the adapters'
    sessions are known, so no finding is made twice.
    """
    th = thresholds
    index = ProcessIndex(nodes)
    pressured = is_under_pressure(reading, th)
    found: list[Finding] = []
    found += memory_pressure(reading, th)
    found += idle_sessions(index, sessions, th, under_pressure=pressured)
    found += busy_but_quiet(index, sessions, th)
    found += orphans(nodes, th)
    found += concurrent_tests(index, th)
    found += duplicate_mcp(index, th)
    found += hot_children(nodes, th, cpu_seconds or {})
    found += renderer_bloat(nodes, th, under_pressure=pressured)
    found += heavy_lock(heavy_lock_present)
    return tuple(sorted(found, key=lambda f: (-f.severity.rank, f.rule_id, f.id)))


def evaluate_sessions(
    nodes: Sequence[ProcessNode],
    sessions: Sequence[SessionActivity],
    *,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    pressured: bool = False,
) -> tuple[Finding, ...]:
    """Run only the two session rules (idle and busy-but-quiet).

    `pressured` is the same "under pressure" flag `evaluate` derives from the
    system reading. The result is sorted the same way as `evaluate`'s.
    """
    index = ProcessIndex(nodes)
    found: list[Finding] = []
    found += idle_sessions(index, sessions, thresholds, under_pressure=pressured)
    found += busy_but_quiet(index, sessions, thresholds)
    return tuple(sorted(found, key=lambda f: (-f.severity.rank, f.rule_id, f.id)))
