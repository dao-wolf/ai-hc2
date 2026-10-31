"""Process trees: who is running, what they cost and what they listen on (FR-4).

One `ps` call gives the table. One `lsof` call gives listening ports, and one
`ioreg` call gives GPU time. Current folders are read only on demand, for a
short list of process ids.

Privacy (S-3): the full command line is hashed into `fingerprint` and then
dropped. The only other things kept from it are flag names such as `--port`,
never their values. A role is decided from the name, the flag names and a short
closed list of tool words (such as `vitest`) found in the arguments. Process
environments are never read: no `ps -E`, no `eww`. `run_command` enforces it.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from hc2.adapters.base import ProcessSignature
from hc2.collect import PS_ARGV, Runner, run_command
from hc2.model import ProcessNode, ProcessRole

PS_TIMEOUT = 2.0
LSOF_TIMEOUT = 2.0
IOREG_TIMEOUT = 1.5
LSOF_LISTEN_ARGV: tuple[str, ...] = (
    "lsof",
    "-nP",
    "-iTCP",
    "-sTCP:LISTEN",
    "-F",
    "pcn",
)
IOREG_GPU_ARGV: tuple[str, ...] = ("ioreg", "-r", "-c", "AGXDeviceUserClient", "-w0")
MAX_CWD_PIDS = 50
MAX_FLAGS = 20

SHELLS = frozenset({"sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "login"})
_INTERPRETER_RE = re.compile(
    r"^(node|python[\d.]*|ruby|bun|deno|npm|npx|pnpm|yarn|uv|uvx|tsx|ts-node|java)$"
)
_MCP_RE = re.compile(r"(^|[-_.])mcp($|[-_.])")
_BROWSER_NAME_RE = re.compile(r"chrom|firefox|webkit|headless_shell")
_ALWAYS_AUTOMATION_BROWSERS = frozenset(
    {"chromium", "chrome-headless-shell", "headless_shell"}
)
_AUTOMATION_FLAGS = frozenset(
    {
        "--headless",
        "--enable-automation",
        "--remote-debugging-port",
        "--remote-debugging-pipe",
    }
)
_AUTOMATION_PATH_MARKERS = ("ms-playwright", "puppeteer", "chrome for testing")
_TEST_NAMES = frozenset({"xcodebuild", "xctest", "pytest", "jest", "vitest"})
_TEST_WORDS = frozenset(
    {"vitest", "jest", "mocha", "pytest", "cypress", "karma", "stryker", "jest-worker"}
)
_DEV_WORDS = frozenset(
    {
        "vite",
        "next",
        "webpack",
        "astro",
        "nuxt",
        "uvicorn",
        "gunicorn",
        "flask",
        "live-server",
        "storybook",
        "parcel",
        "http.server",
        "serve",
    }
)
_FLAG_NAME_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9_.-]{0,39}$")
_STRIP = "()[]\"',"


# --------------------------------------------------------------------------
# Raw rows
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RawProcess:
    """One parsed `ps` row. Held in memory only; `args` is never shown."""

    pid: int
    ppid: int
    age_seconds: int | None
    cpu_percent: float | None
    rss_kb: int | None
    cpu_seconds: float | None
    comm: str  # the executable, read from the start of `args`
    args: str = field(repr=False)


def parse_etime(text: str) -> int | None:
    """Turn ps elapsed time `[[dd-]hh:]mm:ss` into seconds, or `None`."""
    try:
        days = 0
        rest = text.strip()
        if "-" in rest:
            day_text, rest = rest.split("-", 1)
            days = int(day_text)
        parts = [int(part) for part in rest.split(":")]
        if not 1 <= len(parts) <= 3:
            return None
        while len(parts) < 3:
            parts.insert(0, 0)
        hours, minutes, seconds = parts
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    except ValueError:
        return None


def parse_cpu_time(text: str) -> float | None:
    """Turn ps cumulative CPU time `[[hh:]mm:]ss.cc` into seconds, or `None`."""
    try:
        total = 0.0
        for part in text.strip().split(":"):
            total = total * 60 + float(part)
        return total
    except ValueError:
        return None


def split_executable(args: str) -> str:
    """Return the executable part at the start of a ps `args` text.

    A path may hold spaces when it is inside an app bundle, as in
    `/Apps/My App.app/Contents/MacOS/My App --flag`. For a bundle, the name runs
    to the first flag or to the next absolute path. Anything else ends at the
    first space.
    """
    text = args.strip()
    first = text.split(" ", 1)[0]
    if not text.startswith("/"):
        return first
    flag = text.find(" -")
    head = text if flag < 0 else text[:flag]
    marker = head.find("/MacOS/")
    if marker < 0 or " /" in head[:marker]:
        return first
    start = marker + len("/MacOS/")
    cut = head.find(" /", start)
    return head if cut < 0 else head[:cut]


def parse_ps(text: str) -> list[RawProcess]:
    """Parse the output of `PS_ARGV` into rows. Bad lines are skipped."""
    rows: list[RawProcess] = []
    for line in text.splitlines():
        fields = line.strip().split(None, 7)
        if len(fields) < 8 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        args = fields[7].strip()
        comm = split_executable(args)
        try:
            cpu = float(fields[4])
        except ValueError:
            cpu = None
        rss = int(fields[5]) if fields[5].isdigit() else None
        rows.append(
            RawProcess(
                pid=int(fields[0]),
                ppid=int(fields[1]),
                age_seconds=parse_etime(fields[3]),
                cpu_percent=cpu,
                rss_kb=rss,
                cpu_seconds=parse_cpu_time(fields[6]),
                comm=comm,
                args=args,
            )
        )
    return rows


def parse_listeners(text: str) -> dict[int, tuple[int, ...]]:
    """Parse `lsof -F pcn` into listening ports per process id."""
    ports: dict[int, set[int]] = {}
    current: int | None = None
    for line in text.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current = int(line[1:])
        elif line.startswith("n") and current is not None:
            address = line[1:].split(" ")[0]
            _, _, port = address.rpartition(":")
            if port.isdigit() and 0 < int(port) < 65536:
                ports.setdefault(current, set()).add(int(port))
    return {pid: tuple(sorted(found)) for pid, found in ports.items()}


def parse_cwds(text: str) -> dict[int, str]:
    """Parse `lsof -a -p PID -d cwd -Fn`. The paths are raw: the core redacts."""
    result: dict[int, str] = {}
    current: int | None = None
    for line in text.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current = int(line[1:])
        elif line.startswith("n") and current is not None and line[1:]:
            result[current] = line[1:]
    return result


_GPU_CREATOR_RE = re.compile(r'"IOUserClientCreator"\s*=\s*"pid (\d+),')
_GPU_TIME_RE = re.compile(r'"accumulatedGPUTime"\s*=\s*(\d+)')


def parse_gpu(text: str) -> dict[int, int]:
    """Parse `ioreg` GPU clients into cumulative GPU milliseconds per process."""
    totals: dict[int, int] = {}
    for block in text.split("+-o ")[1:]:
        creator = _GPU_CREATOR_RE.search(block)
        if creator is None:
            continue
        nanos = sum(int(match) for match in _GPU_TIME_RE.findall(block))
        pid = int(creator.group(1))
        totals[pid] = totals.get(pid, 0) + nanos // 1_000_000
    return totals


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def is_interpreter(name: str) -> bool:
    """True for a generic language runtime such as `node` or `python3`."""
    return bool(_INTERPRETER_RE.match(name.lower()))


def executable_name(comm: str) -> str:
    """The executable basename, without a login-shell dash."""
    base = comm.rstrip("/").rsplit("/", 1)[-1]
    return base.lstrip("-") or base


def flag_names(args: str, comm: str) -> tuple[str, ...]:
    """Flag names only (`--port`, never `--port=3000`), first appearance first."""
    tail = args[len(comm) :] if args.startswith(comm) else args
    found: list[str] = []
    for token in tail.split():
        if not token.startswith("-"):
            continue
        name = token.split("=", 1)[0]
        if _FLAG_NAME_RE.match(name) and name not in found:
            found.append(name)
        if len(found) >= MAX_FLAGS:
            break
    return tuple(found)


def _tool_words(args: str, comm: str) -> frozenset[str]:
    """Closed-list tool words seen in the arguments. Used and then dropped."""
    tail = args[len(comm) :] if args.startswith(comm) else args
    words: set[str] = set()
    for token in tail.split():
        if token.startswith("-"):
            continue
        cleaned = token.strip(_STRIP).lower()
        if "modelcontextprotocol" in cleaned:
            words.add("mcp")
        parts = cleaned.rsplit("/", 2)
        base = parts[-1]
        has_ext = base.endswith((".js", ".mjs", ".py", ".ts"))
        stem = base.rsplit(".", 1)[0] if has_ext else base
        if any(_MCP_RE.search(part) for part in (stem, *parts[:-1][-1:])):
            words.add("mcp")
        for candidate in (base, stem):
            if candidate in _TEST_WORDS or candidate in _DEV_WORDS:
                words.add(candidate)
    return frozenset(words)


def _is_automation_browser(lname: str, flags: Iterable[str], comm: str) -> bool:
    if not _BROWSER_NAME_RE.search(lname):
        return False
    if lname in _ALWAYS_AUTOMATION_BROWSERS:
        return True
    if any(flag in _AUTOMATION_FLAGS for flag in flags):
        return True
    lowered = comm.lower()
    return any(marker in lowered for marker in _AUTOMATION_PATH_MARKERS)


def classify_role(comm: str, args: str, ports: Sequence[int] = ()) -> ProcessRole:
    """Decide a role from the name, flag names and a closed list of tool words.

    Ordinary browsers that a person opened are `OTHER`: only browsers that look
    automated (headless, remote debugging, test-runner builds) are `BROWSER`.
    """
    name = executable_name(comm)
    lname = name.lower()
    flags = flag_names(args, comm)
    words = _tool_words(args, comm)
    interpreter = is_interpreter(name)
    if lname in SHELLS:
        return ProcessRole.SHELL
    if _MCP_RE.search(lname) or (interpreter and "mcp" in words):
        return ProcessRole.MCP_SERVER
    if lname in _TEST_NAMES or (interpreter and words & _TEST_WORDS):
        return ProcessRole.TEST_WORKER
    if _is_automation_browser(lname, flags, comm):
        return ProcessRole.BROWSER
    if (interpreter and (ports or words & _DEV_WORDS)) or lname in _DEV_WORDS:
        return ProcessRole.DEV_SERVER
    return ProcessRole.OTHER


def fingerprint(args: str, comm: str) -> str:
    """SHA-256 of the full command line (S-2, S-3). The line itself is not kept."""
    return hashlib.sha256((args or comm).encode("utf-8", errors="replace")).hexdigest()


def match_signature(comm: str, signatures: Sequence[ProcessSignature]) -> str | None:
    """Return the first harness whose signature matches exactly, else `None`.

    An executable name must equal the basename. A path marker must appear in
    the executable's path as written, with no pattern matching.
    """
    name = executable_name(comm)
    for signature in signatures:
        if name in signature.executable_names:
            return signature.harness_id
        if any(marker and marker in comm for marker in signature.path_markers):
            return signature.harness_id
    return None


# --------------------------------------------------------------------------
# Building nodes
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessTable:
    """Everything one process scan found.

    `nodes` is flat; follow `parent_pid` or use `ProcessIndex`. `cpu_seconds` is
    cumulative CPU time per pid, which lets a rule judge a process over its whole
    life instead of one noisy reading. `flags` holds flag names only.
    """

    sampled_at: str
    nodes: tuple[ProcessNode, ...] = ()
    cpu_seconds: Mapping[int, float] = field(default_factory=dict)
    flags: Mapping[int, tuple[str, ...]] = field(default_factory=dict)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _descendants(rows: Sequence[RawProcess], root: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for row in rows:
        children.setdefault(row.ppid, []).append(row.pid)
    seen: set[int] = set()
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
    return seen


def build_table(
    rows: Sequence[RawProcess],
    *,
    now: datetime,
    signatures: Sequence[ProcessSignature] = (),
    ports: Mapping[int, tuple[int, ...]] | None = None,
    gpu_ms: Mapping[int, int] | None = None,
    exclude_pids: Iterable[int] = (),
) -> ProcessTable:
    """Turn parsed rows into `ProcessNode`s with roles, harnesses and ports.

    `gpu_ms` is `None` when GPU time is unavailable; then every node gets `None`.
    A process matching a signature gets that `harness_id` and, unless its parent
    matches the same harness, the `HARNESS` role. Other processes inherit the
    nearest ancestor's `harness_id`.
    """
    skip = set(exclude_pids)
    kept = [row for row in rows if row.pid not in skip]
    by_pid = {row.pid: row for row in kept}
    listening = ports or {}
    matches = {row.pid: match_signature(row.comm, signatures) for row in kept}

    def inherited(pid: int) -> str | None:
        seen: set[int] = set()
        while pid in by_pid and pid not in seen:
            seen.add(pid)
            if matches[pid] is not None:
                return matches[pid]
            pid = by_pid[pid].ppid
        return None

    roles: dict[int, ProcessRole] = {}
    for row in kept:
        roles[row.pid] = classify_role(row.comm, row.args, listening.get(row.pid, ()))
    for _ in range(4):  # browser helpers inherit the automated browser's role
        changed = False
        for row in kept:
            if (
                roles[row.pid] is ProcessRole.OTHER
                and _BROWSER_NAME_RE.search(executable_name(row.comm).lower())
                and roles.get(row.ppid) is ProcessRole.BROWSER
            ):
                roles[row.pid] = ProcessRole.BROWSER
                changed = True
        if not changed:
            break

    nodes: list[ProcessNode] = []
    flags: dict[int, tuple[str, ...]] = {}
    cpu_seconds: dict[int, float] = {}
    for row in kept:
        harness = inherited(row.pid)
        own = matches[row.pid]
        parent_harness = inherited(row.ppid) if row.ppid in by_pid else None
        role = roles[row.pid]
        if own is not None and parent_harness != own:
            role = ProcessRole.HARNESS
        start = (
            _iso(now - timedelta(seconds=row.age_seconds))
            if row.age_seconds is not None
            else None
        )
        gpu = None if gpu_ms is None else gpu_ms.get(row.pid, 0)
        nodes.append(
            ProcessNode(
                pid=row.pid,
                name=executable_name(row.comm),
                start_time=start,
                fingerprint=fingerprint(row.args, row.comm),
                parent_pid=row.ppid,
                role=role,
                harness_id=harness,
                cpu_percent=row.cpu_percent,
                memory_bytes=None if row.rss_kb is None else row.rss_kb * 1024,
                gpu_time_ms=gpu,
                age_seconds=row.age_seconds,
                listening_ports=listening.get(row.pid, ()),
            )
        )
        flags[row.pid] = flag_names(row.args, row.comm)
        if row.cpu_seconds is not None:
            cpu_seconds[row.pid] = row.cpu_seconds
    return ProcessTable(
        sampled_at=_iso(now),
        nodes=tuple(nodes),
        cpu_seconds=cpu_seconds,
        flags=flags,
    )


def collect_processes(
    signatures: Sequence[ProcessSignature] = (),
    *,
    runner: Runner = run_command,
    now: datetime | None = None,
    pid: int | None = None,
) -> ProcessTable:
    """Run `ps`, `lsof` and `ioreg` together and build the process table.

    HC2's own process and its children (the `ps` call itself) are left out.
    Any command that fails gives an empty part, not an error.
    """
    moment = now or datetime.now(UTC)
    own_pid = os.getpid() if pid is None else pid
    with ThreadPoolExecutor(max_workers=3) as pool:
        ps_job = pool.submit(runner, PS_ARGV, PS_TIMEOUT)
        lsof_job = pool.submit(runner, LSOF_LISTEN_ARGV, LSOF_TIMEOUT)
        gpu_job = pool.submit(runner, IOREG_GPU_ARGV, IOREG_TIMEOUT)
        ps_text, lsof_text, gpu_text = (
            ps_job.result(),
            lsof_job.result(),
            gpu_job.result(),
        )
    rows = parse_ps(ps_text or "")
    gpu = parse_gpu(gpu_text or "") if gpu_text else {}
    return build_table(
        rows,
        now=moment,
        signatures=signatures,
        ports=parse_listeners(lsof_text or ""),
        gpu_ms=gpu or None,
        exclude_pids=_descendants(rows, own_pid),
    )


def read_cwds(pids: Iterable[int], *, runner: Runner = run_command) -> dict[int, str]:
    """Read the current folder of a few processes, on demand.

    Returned raw, so a caller must redact before showing anything (P-3). At most
    `MAX_CWD_PIDS` are read in one call.
    """
    chosen = sorted({pid for pid in pids if isinstance(pid, int) and pid > 0})
    chosen = chosen[:MAX_CWD_PIDS]
    if not chosen:
        return {}
    pid_list = ",".join(str(pid) for pid in chosen)
    argv = ("lsof", "-a", "-p", pid_list, "-d", "cwd", "-Fn")
    return parse_cwds(runner(argv, LSOF_TIMEOUT) or "")


# --------------------------------------------------------------------------
# Trees
# --------------------------------------------------------------------------


class ProcessIndex:
    """Look up processes and their descendants by pid."""

    def __init__(self, nodes: Iterable[ProcessNode]) -> None:
        self.nodes: tuple[ProcessNode, ...] = tuple(nodes)
        self.by_pid: dict[int, ProcessNode] = {node.pid: node for node in self.nodes}
        self.children: dict[int, list[ProcessNode]] = {}
        for node in self.nodes:
            if node.parent_pid is not None:
                self.children.setdefault(node.parent_pid, []).append(node)

    def subtree(self, pid: int) -> list[ProcessNode]:
        """The process and everything below it. Empty if `pid` is unknown."""
        root = self.by_pid.get(pid)
        if root is None:
            return []
        found: list[ProcessNode] = []
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node.pid in seen:
                continue
            seen.add(node.pid)
            found.append(node)
            stack.extend(self.children.get(node.pid, []))
        return found

    def top_level(self) -> list[ProcessNode]:
        """Processes whose parent is launchd or not in the table (launchd excluded)."""
        return [
            node
            for node in self.nodes
            if node.pid > 1
            and (
                node.parent_pid is None
                or node.parent_pid <= 1
                or node.parent_pid not in self.by_pid
            )
        ]


def total_memory(nodes: Iterable[ProcessNode]) -> int:
    """Sum of known memory in bytes."""
    return sum(node.memory_bytes or 0 for node in nodes)


def total_cpu(nodes: Iterable[ProcessNode]) -> float:
    """Sum of known CPU percent."""
    return sum(node.cpu_percent or 0.0 for node in nodes)
