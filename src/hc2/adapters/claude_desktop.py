"""Adapter for the Claude desktop app's Code tab.

Installs come from the app's `Info.plist` and from the Claude Code copies the
app carries under Application Support. Sessions come from the Code tab's index
files; running state comes through `cliSessionId`, which links a session to
the live-session registry that the Claude Code CLI also writes.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from hc2.adapters.base import AdapterContext, AdapterReport, ProcessSignature
from hc2.adapters.claude_common import (
    APP_BUNDLE,
    RELEASE_NOTES_URL,
    VERSION_RE,
    ConfidentialMatcher,
    LiveSession,
    LiveSessions,
    Problems,
    ProcessProbe,
    app_install,
    app_support,
    as_bool,
    as_str,
    clean_title,
    default_app_dirs,
    display_path,
    iso_from_ms,
    list_dir,
    live_link,
    live_sources,
    make_install,
    probe_processes,
    read_index_records,
    read_live_sessions,
    sorted_sources,
    source,
    state_from_status,
)
from hc2.model import (
    FieldSource,
    Harness,
    Install,
    InstallKind,
    Origin,
    Reliability,
    Session,
    SessionState,
)

HARNESS_ID = "claude-desktop-code"
LABEL = "Claude desktop (Code tab)"
INDEX_FOLDER = "claude-code-sessions"
EMBEDDED_FOLDER = "claude-code"

FIELDS_READ = (
    "Claude.app/Contents/Info.plist: CFBundleShortVersionString",
    "claude-code/<version>/<hash>/claude.app: folder names only",
    "claude-code-sessions/*/*/local_*.json: sessionId, cliSessionId, title, cwd, "
    "originCwd, model, createdAt, lastActivityAt, isArchived",
    "sessions/*.json (shared registry): sessionId, pid, procStart, status, "
    "statusUpdatedAt, startedAt, updatedAt",
    "process table: pid, start time, executable name",
)


class ClaudeDesktopAdapter:
    """The desktop app's Code tab."""

    id = HARNESS_ID
    name = LABEL

    def __init__(
        self,
        probe: ProcessProbe | None = None,
        app_dirs: Sequence[str] | None = None,
    ) -> None:
        self._probe: ProcessProbe = probe or probe_processes
        self._app_dirs = None if app_dirs is None else tuple(app_dirs)

    def process_signature(self) -> ProcessSignature:
        """The app, its helpers, and the Claude Code copies it carries."""
        return ProcessSignature(
            harness_id=HARNESS_ID,
            executable_names=(
                "Claude",
                "Claude Helper",
                "Claude Helper (GPU)",
                "Claude Helper (Plugin)",
                "Claude Helper (Renderer)",
            ),
            path_markers=(
                f"/{APP_BUNDLE}/",
                "/Application Support/Claude/claude-code/",
            ),
        )

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        """Find the app and list Code tab sessions. Never raises."""
        problems = Problems(LABEL)
        try:
            return self._scan(ctx, problems)
        except Exception:  # R-1: one broken adapter must not stop the scan
            failed = Problems(LABEL)
            failed.add("scan_failed")
            harness = Harness(id=HARNESS_ID, name=LABEL, installed=False)
            return AdapterReport(
                harness=harness, problems=failed.render(), fields_read=FIELDS_READ
            )

    def _scan(self, ctx: AdapterContext, problems: Problems) -> AdapterReport:
        home = ctx.home
        support = app_support(home)
        installs = _installs(
            home, self._app_dirs or default_app_dirs(home), support, problems
        )
        live = read_live_sessions(home, self._probe, problems, report_format=False)
        matcher = ConfidentialMatcher(ctx.confidential_folders, home)
        records, status = read_index_records(
            os.path.join(support, INDEX_FOLDER), problems
        )
        if status == "denied":
            problems.add("store_denied")
        elif status == "missing" and installs:
            problems.add("store_missing")
        sessions: dict[str, Session] = {}
        for record in records:
            session = _session(record, live, matcher)
            sessions.setdefault(session.id, session)
        ordered = sorted(
            sessions.values(), key=lambda s: (s.last_activity or "", s.id), reverse=True
        )
        harness = Harness(
            id=HARNESS_ID,
            name=LABEL,
            installed=bool(installs),
            installs=tuple(installs),
            config_location=display_path(support, home),
            docs_url="https://support.claude.com/en/collections/16163169-claude-code",
            changelog_url=RELEASE_NOTES_URL,
            llms_txt_url="https://support.claude.com/llms.txt",
        )
        return AdapterReport(
            harness=harness,
            sessions=tuple(ordered),
            problems=problems.render(),
            fields_read=FIELDS_READ,
        )


def _version_key(version: str) -> tuple[int, ...]:
    parts = version.split("-", 1)[0].split("+", 1)[0].split(".")
    return tuple(int(part) if part.isdigit() else 0 for part in parts)


def _installs(
    home: str, app_dirs: Sequence[str], support: str, problems: Problems
) -> list[Install]:
    installs: list[Install] = []
    app = app_install(HARNESS_ID, home, app_dirs, problems)
    if app is not None:
        installs.append(app)
    root = os.path.join(support, EMBEDDED_FOLDER)
    versions, _ = list_dir(root)
    seen: set[str] = set()
    for version in sorted(
        (v for v in versions if VERSION_RE.fullmatch(v)), key=_version_key
    ):
        hashes, _ = list_dir(os.path.join(root, version))
        for digest in hashes:
            bundle = os.path.join(root, version, digest, "claude.app")
            if version in seen or not os.path.isdir(bundle):
                continue
            seen.add(version)
            installs.append(
                make_install(
                    HARNESS_ID,
                    InstallKind.EMBEDDED,
                    version,
                    "folder name under claude-code",
                    display_path(bundle, home),
                )
            )
    return installs


def _session(
    record: dict[str, object], live: LiveSessions, matcher: ConfidentialMatcher
) -> Session:
    session_id = as_str(record.get("sessionId")) or ""
    cli_id = as_str(record.get("cliSessionId"))
    entry: LiveSession | None = live.by_id.get(cli_id) if cli_id else None
    folder = as_str(record.get("cwd"))
    origin_cwd = as_str(record.get("originCwd"))
    confidential = matcher.folder_is_confidential(folder, origin_cwd)
    title = clean_title(record.get("title"))
    model = as_str(record.get("model"))
    created = iso_from_ms(record.get("createdAt"))
    last = iso_from_ms(record.get("lastActivityAt"))
    archived = as_bool(record.get("isArchived"))
    state, state_source = _state(entry, live, archived)
    refs: list[FieldSource | None] = [
        source("id", "index sessionId", Reliability.HIGH),
        source("origin", "desktop Code tab index", Reliability.HIGH),
        source("state", state_source, Reliability.MEDIUM),
        source("title", "index title", Reliability.HIGH)
        if title and not confidential
        else None,
        source("folder", "index cwd", Reliability.HIGH) if folder else None,
        source("model", "index model", Reliability.HIGH) if model else None,
        source("created", "index createdAt", Reliability.HIGH) if created else None,
        source("last_activity", "index lastActivityAt", Reliability.HIGH)
        if last
        else None,
        *live_sources(entry),
    ]
    pid, state_since = live_link(entry)
    return Session(
        id=session_id,
        harness_id=HARNESS_ID,
        title=None if confidential else title,
        folder=folder,
        model=model,
        created=created,
        last_activity=last,
        state=state,
        origin=Origin.DESKTOP,
        confidential=confidential,
        field_sources=sorted_sources(refs),
        pid=pid,
        state_since=state_since,
    )


def _state(
    entry: LiveSession | None, live: LiveSessions, archived: bool | None
) -> tuple[SessionState, str]:
    if entry is not None:
        return (
            state_from_status(entry.status),
            "registry status via cliSessionId, process confirmed alive",
        )
    if not live.known:
        return SessionState.UNKNOWN, "process table could not be read"
    if archived:
        return SessionState.ENDED, "index isArchived"
    return SessionState.ENDED, "no live claude process lists this session"
