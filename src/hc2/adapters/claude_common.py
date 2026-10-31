"""Helpers shared by the three Claude adapters.

Everything here reads named metadata fields only (P-1). Nothing here keeps,
logs or returns message text, and nothing raises for bad input: unreadable or
unrecognised files are counted and turned into plain-English problems that
carry no paths (R-2).
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import threading
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import BinaryIO, Literal

from hc2.model import (
    FieldSource,
    Install,
    InstallKind,
    Origin,
    Reliability,
    SessionState,
    stable_id,
)

# --------------------------------------------------------------------------
# Limits. Every read is bounded by one of these.
# --------------------------------------------------------------------------

HEAD_BYTES = 64 * 1024
"""How much of the start of a transcript is read."""

TAIL_BYTES = 256 * 1024
"""How much of the end of a transcript is read."""

MAX_LINE_BYTES = 256 * 1024
"""A transcript line longer than this is skipped without parsing."""

MAX_HEAD_LINES = 400
"""At most this many lines of the head window are looked at."""

MAX_JSON_BYTES = 4 * 1024 * 1024
"""Largest session index file that is parsed. Real ones are about 1 MB."""

MAX_REGISTRY_BYTES = 64 * 1024
"""Largest live-session registry file that is parsed."""

MAX_PLIST_BYTES = 1024 * 1024
"""Largest app information file that is parsed."""

MAX_REGISTRY_FILES = 1000
"""Most registry files looked at in one scan."""

MAX_TITLE_CHARS = 300
"""Titles are cut to this length."""

PS_TIMEOUT_SECONDS = 2.0
"""How long the single `ps` call may take."""

# --------------------------------------------------------------------------
# Folder names and the version pattern
# --------------------------------------------------------------------------

RELEASE_NOTES_URL = "https://support.claude.com/en/articles/12138966-release-notes"
CLAUDE_DIR = ".claude"
APP_SUPPORT_PARTS = ("Library", "Application Support", "Claude")
APP_BUNDLE = "Claude.app"
CLI_NAME = "claude"
VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.+-]+)?")
_PS_ROW_RE = re.compile(
    r"\s*(\d+)\s+([A-Za-z]{3} [A-Za-z]{3}\s+\d+ \d\d:\d\d:\d\d \d{4})\s+(.+?)\s*"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

DirStatus = Literal["ok", "missing", "denied"]

# --------------------------------------------------------------------------
# Small value helpers
# --------------------------------------------------------------------------


def as_str(value: object) -> str | None:
    """The value if it is a non-blank string, else `None`."""
    if isinstance(value, str) and value.strip():
        return value
    return None


def as_int(value: object) -> int | None:
    """The value if it is a real integer (not a bool), else `None`."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def as_bool(value: object) -> bool | None:
    """The value if it is a bool, else `None`."""
    return value if isinstance(value, bool) else None


def clean_title(value: object) -> str | None:
    """A title with control characters removed and a length limit."""
    text = as_str(value)
    if text is None:
        return None
    text = _CONTROL_RE.sub(" ", text).strip()
    return text[:MAX_TITLE_CHARS] or None


def iso_from_ms(value: object) -> str | None:
    """Milliseconds since the epoch as `2026-10-30T09:00:00Z`, or `None`."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        moment = datetime.fromtimestamp(value / 1000, UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_text(value: object) -> str | None:
    """An ISO 8601 string as UTC `2026-10-30T09:00:00Z`, or `None`."""
    text = as_str(value)
    if text is None:
        return None
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def display_path(path: str, home: str) -> str:
    """Show a path under the home folder as `~/...`."""
    base = home.rstrip("/")
    if base and path == base:
        return "~"
    if base and path.startswith(base + "/"):
        return "~" + path[len(base) :]
    return path


def plural(count: int, one: str, many: str) -> str:
    """`one` when `count` is 1, else `many`."""
    return one if count == 1 else many


# --------------------------------------------------------------------------
# Problems: counted, then written as plain sentences with no paths
# --------------------------------------------------------------------------


class Problems:
    """Counts what went wrong, then renders one sentence per kind."""

    def __init__(self, label: str) -> None:
        self._label = label
        self._counts: Counter[str] = Counter()

    def add(self, kind: str, count: int = 1) -> None:
        """Record `count` more cases of `kind`."""
        self._counts[kind] += count

    def render(self) -> tuple[str, ...]:
        """The sentences, in a fixed order."""
        lines: list[str] = []
        for kind in sorted(self._counts):
            lines.append(_sentence(kind, self._label, self._counts[kind]))
        return tuple(lines)


def _files(count: int) -> str:
    return f"{count} {plural(count, 'file', 'files')}"


def _sentence(kind: str, label: str, count: int) -> str:
    texts = {
        "store_missing": "the session folder was not found, so no sessions "
        "were listed.",
        "store_denied": "the session folder could not be read (permission "
        "denied), so no sessions were listed.",
        "files_denied": f"{_files(count)} could not be read (permission "
        "denied or another read error).",
        "files_damaged": f"{_files(count)} could not be read as valid data, so "
        "those sessions have missing details.",
        "format_unknown": f"{_files(count)} not in a format this version "
        "understands. The adapter may need an update.",
        "registry_denied": "the list of running sessions could not be read "
        "(permission denied).",
        "registry_unknown": f"{_files(count)} in the list of running sessions "
        "not in a format this version understands.",
        "processes_unknown": "could not check which Claude processes are "
        "running, so session states are unknown.",
        "app_plist": "the app's version could not be read from its information file.",
        "cli_version": "Claude Code was found but its version could not be "
        "worked out from the install.",
        "scan_failed": "the scan failed unexpectedly, so nothing was listed.",
    }
    return f"{label}: {texts.get(kind, 'an unexpected problem occurred.')}"


# --------------------------------------------------------------------------
# Reading folders and files safely
# --------------------------------------------------------------------------


def list_dir(path: str) -> tuple[list[str], DirStatus]:
    """Sorted entry names of a folder, and whether it could be read."""
    try:
        return sorted(os.listdir(path)), "ok"
    except (FileNotFoundError, NotADirectoryError):
        return [], "missing"
    except OSError:
        return [], "denied"


def _open_binary(path: str) -> BinaryIO:
    """Open a file for reading. Tests wrap this to count bytes read."""
    return open(path, "rb")


def read_small_file(path: str, limit: int) -> bytes | None:
    """Whole file if it is at most `limit` bytes, else `None`.

    Raises:
        OSError: the file cannot be read.
    """
    if os.path.getsize(path) > limit:
        return None
    with _open_binary(path) as handle:
        return handle.read(limit + 1)


# --------------------------------------------------------------------------
# Confidential folders (P-2). Paths stay raw; the core redacts them.
# --------------------------------------------------------------------------


def _norm(path: str) -> str:
    return os.path.normpath(path).casefold()


def _encode_dir(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", path)


class ConfidentialMatcher:
    """Decides whether a folder is, or is inside, a confidential folder."""

    def __init__(self, folders: Sequence[str], home: str) -> None:
        self._folders: list[str] = []
        self._encoded: list[str] = []
        for raw in folders:
            if not raw.strip():
                continue
            full = home + raw[1:] if raw.startswith("~") else raw
            self._folders.append(_norm(full))
            self._encoded.append(_encode_dir(os.path.normpath(full)).casefold())

    def folder_is_confidential(self, *paths: str | None) -> bool:
        """True if any path is, or is inside, a confidential folder."""
        for path in paths:
            if not path:
                continue
            here = _norm(path)
            for folder in self._folders:
                prefix = folder if folder.endswith("/") else folder + "/"
                if here == folder or here.startswith(prefix):
                    return True
        return False

    def project_dir_is_confidential(self, dirname: str) -> bool:
        """True if a Claude project folder name starts like a confidential folder.

        Claude names a project folder after the working folder with every
        symbol turned into a dash. This errs on the side of hiding too much.
        """
        name = dirname.casefold()
        return any(name.startswith(prefix) for prefix in self._encoded)


# --------------------------------------------------------------------------
# Transcript windows (FR-2, P-1)
# --------------------------------------------------------------------------

_TITLE_TYPES = {
    "custom-title": "customTitle",
    "agent-name": "agentName",
    "ai-title": "aiTitle",
}
_TITLE_ORDER = ("custom-title", "agent-name", "ai-title")
_TITLE_HINT = re.compile(rb"custom-title|agent-name|ai-title")


@dataclass(frozen=True)
class TranscriptMeta:
    """The only things taken from a transcript."""

    created: str | None
    last_activity: str | None
    cwd: str | None
    entrypoint: str | None
    model: str | None
    title: str | None
    title_kind: str | None
    recognised: bool


def read_windows(path: str) -> tuple[list[bytes], list[bytes]]:
    """The lines of the head and tail windows of a file, never more.

    Partial lines at a cut are dropped. A file that fits in both windows is
    read once and returned as both.

    Raises:
        OSError: the file cannot be read.
    """
    size = os.path.getsize(path)
    with _open_binary(path) as handle:
        if size <= HEAD_BYTES + TAIL_BYTES:
            lines = handle.read(HEAD_BYTES + TAIL_BYTES).split(b"\n")
            return lines, lines
        head = handle.read(HEAD_BYTES).split(b"\n")[:-1]
        handle.seek(size - TAIL_BYTES)
        tail = handle.read(TAIL_BYTES).split(b"\n")[1:]
    return head, tail


def _parse_record(raw: bytes) -> dict[str, object] | None:
    if len(raw) > MAX_LINE_BYTES or not raw.startswith(b"{"):
        return None
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _title_of(record: Mapping[str, object]) -> tuple[str, str] | None:
    kind = record.get("type")
    if not isinstance(kind, str) or kind not in _TITLE_TYPES:
        return None
    title = clean_title(record.get(_TITLE_TYPES[kind]))
    return (kind, title) if title else None


def _model_of(record: Mapping[str, object]) -> str | None:
    if record.get("type") != "assistant":
        return None
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    model = as_str(message.get("model"))
    if model is None or model.startswith("<"):
        return None
    return model


def scan_transcript(path: str) -> TranscriptMeta:
    """Take the allowed metadata from the head and tail of one transcript.

    Fields taken: `timestamp`, `cwd`, `entrypoint`, `type`, the title keys of
    the three title records, and `message.model` of assistant records. Every
    other value is parsed at most for the line and then dropped.

    Raises:
        OSError: the file cannot be read.
    """
    head, tail = read_windows(path)
    recognised = False
    created: str | None = None
    cwd: str | None = None
    entrypoint: str | None = None
    titles: dict[str, str] = {}
    for raw in head[:MAX_HEAD_LINES]:
        record = _parse_record(raw)
        if record is None:
            continue
        recognised = True
        found = _title_of(record)
        if found:
            titles[found[0]] = found[1]
        if created is None:
            created = iso_from_text(record.get("timestamp"))
        if cwd is None:
            cwd = as_str(record.get("cwd"))
        if entrypoint is None:
            entrypoint = as_str(record.get("entrypoint"))
    last: str | None = None
    model: str | None = None
    tail_titles: dict[str, str] = {}
    for raw in reversed(tail):
        wants_meta = last is None or model is None
        wants_title = _TITLE_HINT.search(raw) is not None
        if not (wants_meta or wants_title):
            continue
        record = _parse_record(raw)
        if record is None:
            continue
        recognised = True
        found = _title_of(record)
        if found:
            tail_titles.setdefault(found[0], found[1])
            continue
        if last is None:
            last = iso_from_text(record.get("timestamp"))
        if model is None:
            model = _model_of(record)
    titles.update(tail_titles)
    title: str | None = None
    title_kind: str | None = None
    for kind in _TITLE_ORDER:
        if kind in titles:
            title, title_kind = titles[kind], kind
            break
    return TranscriptMeta(
        created=created,
        last_activity=last,
        cwd=cwd,
        entrypoint=entrypoint,
        model=model,
        title=title,
        title_kind=title_kind,
        recognised=recognised,
    )


# --------------------------------------------------------------------------
# Desktop and Cowork index files
# --------------------------------------------------------------------------

INDEX_KEYS = (
    "sessionId",
    "cliSessionId",
    "priorCliSessionIds",
    "title",
    "cwd",
    "originCwd",
    "userSelectedFolders",
    "model",
    "createdAt",
    "lastActivityAt",
    "isArchived",
)
"""Every key taken from either kind of index file. All other keys are dropped."""

_INDEX_CACHE: dict[tuple[str, int, int], dict[str, object] | None] = {}
_INDEX_CACHE_MAX = 4096
_INDEX_LOCK = threading.Lock()


def load_index(path: str) -> dict[str, object] | None:
    """The `INDEX_KEYS` of one index file, or `None` if it is not an object.

    Results are cached by path, size and modification time, so the three
    adapters share one parse. A file over `MAX_JSON_BYTES` is not parsed.

    Raises:
        OSError: the file cannot be read.
        ValueError: the file is not valid JSON.
    """
    info = os.stat(path)
    key = (path, info.st_size, info.st_mtime_ns)
    with _INDEX_LOCK:
        if key in _INDEX_CACHE:
            cached = _INDEX_CACHE[key]
            return None if cached is None else dict(cached)
        picked: dict[str, object] | None = None
        data = read_small_file(path, MAX_JSON_BYTES)
        if data is not None:
            try:
                value = json.loads(data)
            except RecursionError as error:
                raise ValueError("too deeply nested") from error
            if isinstance(value, dict):
                picked = {k: value[k] for k in INDEX_KEYS if k in value}
        if len(_INDEX_CACHE) >= _INDEX_CACHE_MAX:
            _INDEX_CACHE.clear()
        _INDEX_CACHE[key] = picked
        return None if picked is None else dict(picked)


def index_paths(root: str) -> tuple[list[str], DirStatus]:
    """Paths of `<root>/<account>/<organisation>/local_*.json`, sorted."""
    accounts, status = list_dir(root)
    found: list[str] = []
    for account in accounts:
        orgs, _ = list_dir(os.path.join(root, account))
        for org in orgs:
            names, _ = list_dir(os.path.join(root, account, org))
            found.extend(
                os.path.join(root, account, org, name)
                for name in names
                if name.startswith("local_") and name.endswith(".json")
            )
    return found, status


def read_index_records(
    root: str, problems: Problems
) -> tuple[list[dict[str, object]], DirStatus]:
    """Every readable index record under `root`; failures are counted."""
    paths, status = index_paths(root)
    records: list[dict[str, object]] = []
    for path in paths:
        try:
            record = load_index(path)
        except ValueError:
            problems.add("files_damaged")
            continue
        except OSError:
            problems.add("files_denied")
            continue
        if record is None or as_str(record.get("sessionId")) is None:
            problems.add("format_unknown")
            continue
        records.append(record)
    return records, status


def string_list(value: object) -> list[str]:
    """The string items of a list, or an empty list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


# --------------------------------------------------------------------------
# Live sessions: ~/.claude/sessions/<pid>.json plus the process table
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessInfo:
    """What the process table says about one process."""

    name: str
    started: str


ProcessProbe = Callable[[Sequence[int]], Mapping[int, ProcessInfo] | None]
"""Looks up processes by id. `None` means the lookup itself failed."""


def _pid_exists(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except (ProcessLookupError, OverflowError, OSError):
        return False
    return True


def normalise_start(text: str) -> str:
    """Collapse spaces so two spellings of a start time compare equal."""
    return " ".join(text.split())


def parse_ps(output: str) -> dict[int, ProcessInfo]:
    """Read `ps -o pid=,lstart=,comm=` output."""
    found: dict[int, ProcessInfo] = {}
    for line in output.splitlines():
        match = _PS_ROW_RE.fullmatch(line)
        if match is None:
            continue
        executable = match.group(3)
        found[int(match.group(1))] = ProcessInfo(
            name=executable.rsplit("/", 1)[-1],
            started=normalise_start(match.group(2)),
        )
    return found


def probe_processes(pids: Sequence[int]) -> dict[int, ProcessInfo] | None:
    """Look up live processes with one light `ps` call (never a shell)."""
    alive = [pid for pid in dict.fromkeys(pids) if _pid_exists(pid)]
    if not alive:
        return {}
    try:
        result = subprocess.run(
            ["ps", "-p", ",".join(map(str, alive)), "-o", "pid=,lstart=,comm="],
            capture_output=True,
            text=True,
            timeout=PS_TIMEOUT_SECONDS,
            check=False,
            env={"LC_ALL": "C", "PATH": "/bin:/usr/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_ps(result.stdout)


@dataclass(frozen=True)
class LiveSession:
    """One running `claude` that is listed in the registry.

    `pid` is the process id from the registry file, and `status_ms` is when
    `status` last changed (the registry's `statusUpdatedAt`).
    """

    session_id: str
    status: str | None
    name: str | None
    cwd: str | None
    entrypoint: str | None
    started_ms: int | None
    updated_ms: int | None
    pid: int | None = None
    status_ms: int | None = None


@dataclass(frozen=True)
class LiveSessions:
    """Live sessions by id, and whether liveness could be checked at all."""

    by_id: Mapping[str, LiveSession]
    known: bool


def state_from_status(status: str | None) -> SessionState:
    """Map the registry's `status` to a state for a process known to be alive."""
    return {
        "busy": SessionState.RUNNING_BUSY,
        "idle": SessionState.RUNNING_IDLE,
        "waiting": SessionState.WAITING,
    }.get(status or "", SessionState.UNKNOWN)


def live_link(entry: LiveSession | None) -> tuple[int | None, str | None]:
    """The process id and the time the status last changed, for a live session."""
    if entry is None:
        return None, None
    return entry.pid, iso_from_ms(entry.status_ms)


def live_sources(entry: LiveSession | None) -> list[FieldSource | None]:
    """Where `pid` and `state_since` came from, for fields that are present."""
    pid, since = live_link(entry)
    return [
        source("pid", "sessions/*.json pid, process confirmed alive", Reliability.HIGH)
        if pid is not None
        else None,
        source("state_since", "sessions/*.json statusUpdatedAt", Reliability.MEDIUM)
        if since is not None
        else None,
    ]


def read_live_sessions(
    home: str,
    probe: ProcessProbe,
    problems: Problems,
    report_format: bool = True,
) -> LiveSessions:
    """Sessions whose registry file names a live `claude` process.

    A file counts only if its pid is alive, the process is called `claude`, and
    (when the file records one) the process start time matches `procStart`.
    That last check rejects recycled process ids. Files in an unknown format
    are reported only when `report_format` is true, so that when several
    adapters read the same registry, only one of them says so.
    """
    folder = os.path.join(home, CLAUDE_DIR, "sessions")
    names, status = list_dir(folder)
    if status == "denied":
        problems.add("registry_denied")
        return LiveSessions({}, True)
    candidates: list[tuple[int, str | None, LiveSession]] = []
    registry_bad = 0
    for name in [n for n in names if n.endswith(".json")][:MAX_REGISTRY_FILES]:
        try:
            data = read_small_file(os.path.join(folder, name), MAX_REGISTRY_BYTES)
            value = None if data is None else json.loads(data)
        except (OSError, ValueError, RecursionError):
            value = None
        if not isinstance(value, dict):
            registry_bad += 1
            continue
        pid = as_int(value.get("pid"))
        session_id = as_str(value.get("sessionId"))
        if pid is None or session_id is None:
            registry_bad += 1
            continue
        candidates.append(
            (
                pid,
                as_str(value.get("procStart")),
                LiveSession(
                    session_id=session_id,
                    status=as_str(value.get("status")),
                    name=clean_title(value.get("name")),
                    cwd=as_str(value.get("cwd")),
                    entrypoint=as_str(value.get("entrypoint")),
                    started_ms=as_int(value.get("startedAt")),
                    updated_ms=as_int(value.get("updatedAt")),
                    pid=pid,
                    status_ms=as_int(value.get("statusUpdatedAt")),
                ),
            )
        )
    if report_format and registry_bad:
        problems.add("registry_unknown", registry_bad)
    if not candidates:
        return LiveSessions({}, True)
    table = probe([pid for pid, _, _ in candidates])
    if table is None:
        problems.add("processes_unknown")
        return LiveSessions({}, False)
    live: dict[str, LiveSession] = {}
    for pid, proc_start, session in candidates:
        info = table.get(pid)
        if info is None or info.name != CLI_NAME:
            continue
        if proc_start is not None and normalise_start(proc_start) != info.started:
            continue
        best = live.get(session.session_id)
        if best is None or (session.updated_ms or 0) >= (best.updated_ms or 0):
            live[session.session_id] = session
    return LiveSessions(live, True)


def origin_from_entrypoint(entrypoint: str | None) -> Origin:
    """Map a transcript's `entrypoint` to where the session was started."""
    if entrypoint is None:
        return Origin.UNKNOWN
    text = entrypoint.casefold()
    if text == "cli":
        return Origin.CLI
    if text == "claude-desktop":
        return Origin.DESKTOP
    if any(word in text for word in ("vscode", "jetbrains", "ide")):
        return Origin.IDE
    return Origin.UNKNOWN


# --------------------------------------------------------------------------
# Installs
# --------------------------------------------------------------------------


def make_install(
    harness_id: str,
    kind: InstallKind,
    version: str | None,
    version_source: str | None,
    location: str | None,
) -> Install:
    """Build an `Install` with its meaning-based id."""
    return Install(
        id=stable_id("install", harness_id, kind.value, version or ""),
        harness_id=harness_id,
        kind=kind,
        version=version,
        version_source=version_source,
        location=location,
    )


def app_version(app_path: str) -> str | None:
    """`CFBundleShortVersionString` of an app bundle, or `None`.

    Raises:
        OSError: the file cannot be read.
        ValueError: the file is not a property list.
    """
    data = read_small_file(
        os.path.join(app_path, "Contents", "Info.plist"), MAX_PLIST_BYTES
    )
    if data is None:
        raise ValueError("information file too large")
    try:
        info = plistlib.loads(data)
    except Exception as error:  # plistlib raises several types for bad input
        raise ValueError("not a property list") from error
    if not isinstance(info, dict):
        return None
    version = as_str(info.get("CFBundleShortVersionString"))
    return version if version and VERSION_RE.fullmatch(version) else None


def find_app(app_dirs: Sequence[str]) -> str | None:
    """The first `Claude.app` found in the given folders."""
    for folder in app_dirs:
        candidate = os.path.join(folder, APP_BUNDLE)
        if os.path.isdir(candidate):
            return candidate
    return None


def default_app_dirs(home: str) -> tuple[str, ...]:
    """Where Claude.app is normally installed."""
    return ("/Applications", os.path.join(home, "Applications"))


def app_support(home: str) -> str:
    """The Claude folder under Application Support."""
    return os.path.join(home, *APP_SUPPORT_PARTS)


def app_install(
    harness_id: str, home: str, app_dirs: Sequence[str], problems: Problems
) -> Install | None:
    """The desktop app as an install, or `None` if it is not found."""
    app = find_app(app_dirs)
    if app is None:
        return None
    try:
        version = app_version(app)
    except (OSError, ValueError):
        version = None
    if version is None:
        problems.add("app_plist")
    return make_install(
        harness_id,
        InstallKind.APP,
        version,
        "Info.plist CFBundleShortVersionString",
        display_path(app, home),
    )


# --------------------------------------------------------------------------
# Field sources (FR-2)
# --------------------------------------------------------------------------


def source(field: str, where: str, reliability: Reliability) -> FieldSource:
    """Shorthand for a `FieldSource`."""
    return FieldSource(field=field, source=where, reliability=reliability)


def sorted_sources(items: Sequence[FieldSource | None]) -> tuple[FieldSource, ...]:
    """The non-empty sources, sorted by field name."""
    return tuple(sorted((i for i in items if i), key=lambda s: s.field))
