"""Adapter for the Claude Code command line, from the `~/.claude` folder.

Installs come from the `claude` symlink. Sessions come from the head and tail
of each transcript, and running state from the live-session registry checked
against the process table. Sessions started by the desktop Code tab share this
store and are left to the desktop adapter (see `docs/harnesses/claude.md`).
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from hc2.adapters.base import AdapterContext, AdapterReport, ProcessSignature
from hc2.adapters.claude_common import (
    CLAUDE_DIR,
    CLI_NAME,
    VERSION_RE,
    ConfidentialMatcher,
    LiveSession,
    LiveSessions,
    Problems,
    ProcessProbe,
    app_support,
    display_path,
    iso_from_ms,
    list_dir,
    live_link,
    live_sources,
    make_install,
    origin_from_entrypoint,
    probe_processes,
    read_index_records,
    read_live_sessions,
    scan_transcript,
    sorted_sources,
    source,
    state_from_status,
    string_list,
)
from hc2.model import (
    FieldSource,
    Harness,
    Install,
    InstallKind,
    Reliability,
    Session,
    SessionState,
)

HARNESS_ID = "claude-code-cli"
LABEL = "Claude Code (CLI)"

FIELDS_READ = (
    "bin/claude symlink: target folder name only",
    "projects/*/*.jsonl, head and tail only: type, timestamp, cwd, entrypoint, "
    "message.model (assistant records), customTitle, agentName, aiTitle",
    "sessions/*.json: sessionId, pid, procStart, status, statusUpdatedAt, name, "
    "cwd, entrypoint, startedAt, updatedAt",
    "claude-code-sessions/*/*/local_*.json: sessionId, cliSessionId, "
    "priorCliSessionIds (to avoid listing desktop sessions twice)",
    "local-agent-mode-sessions/*/*/local_*.json: sessionId, cliSessionId, "
    "priorCliSessionIds (to avoid listing Cowork sessions twice)",
    "process table: pid, start time, executable name",
)

_TITLE_SOURCES = {
    "custom-title": "projects/*.jsonl custom-title record",
    "agent-name": "projects/*.jsonl agent-name record",
    "ai-title": "projects/*.jsonl ai-title record",
}


def _default_bin_dirs(home: str) -> tuple[str, ...]:
    return (
        os.path.join(home, ".local", "bin"),
        "/usr/local/bin",
        "/opt/homebrew/bin",
    )


class ClaudeCodeAdapter:
    """The Claude Code CLI and its `~/.claude` session store."""

    id = HARNESS_ID
    name = LABEL

    def __init__(
        self,
        probe: ProcessProbe | None = None,
        bin_dirs: Sequence[str] | None = None,
    ) -> None:
        self._probe: ProcessProbe = probe or probe_processes
        self._bin_dirs = None if bin_dirs is None else tuple(bin_dirs)

    def process_signature(self) -> ProcessSignature:
        """The `claude` executable, wherever it lives."""
        return ProcessSignature(
            harness_id=HARNESS_ID,
            executable_names=(CLI_NAME,),
            path_markers=("/.local/share/claude/versions/",),
        )

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        """Find the CLI and list its sessions. Never raises."""
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

    # ------------------------------------------------------------------

    def _scan(self, ctx: AdapterContext, problems: Problems) -> AdapterReport:
        home = ctx.home
        installs = self._installs(home, problems)
        live = read_live_sessions(home, self._probe, problems)
        foreign = _desktop_cli_ids(home)
        matcher = ConfidentialMatcher(ctx.confidential_folders, home)
        sessions = self._sessions(
            home, live, foreign, matcher, bool(installs), problems
        )
        sessions.sort(key=lambda s: (s.last_activity or "", s.id), reverse=True)
        harness = Harness(
            id=HARNESS_ID,
            name=LABEL,
            installed=bool(installs),
            installs=tuple(installs),
            config_location=display_path(os.path.join(home, CLAUDE_DIR), home),
            docs_url="https://code.claude.com/docs",
            changelog_url="https://code.claude.com/docs/en/changelog",
            llms_txt_url="https://code.claude.com/docs/llms.txt",
        )
        return AdapterReport(
            harness=harness,
            sessions=tuple(sessions),
            problems=problems.render(),
            fields_read=FIELDS_READ,
        )

    def _installs(self, home: str, problems: Problems) -> list[Install]:
        for folder in self._bin_dirs or _default_bin_dirs(home):
            link = os.path.join(folder, CLI_NAME)
            if not os.path.lexists(link):
                continue
            version = _version_from_link(link)
            if version is None:
                problems.add("cli_version")
            return [
                make_install(
                    HARNESS_ID,
                    InstallKind.CLI,
                    version,
                    "symlink target folder name",
                    display_path(link, home),
                )
            ]
        return []

    def _sessions(
        self,
        home: str,
        live: LiveSessions,
        foreign: set[str],
        matcher: ConfidentialMatcher,
        installed: bool,
        problems: Problems,
    ) -> list[Session]:
        sessions: list[Session] = []
        seen: set[str] = set()
        root = os.path.join(home, CLAUDE_DIR, "projects")
        project_dirs, status = list_dir(root)
        if status == "denied":
            problems.add("store_denied")
        elif status == "missing" and installed:
            problems.add("store_missing")
        for project in project_dirs:
            names, _ = list_dir(os.path.join(root, project))
            for name in names:
                if not name.endswith(".jsonl"):
                    continue
                session_id = name[: -len(".jsonl")]
                if session_id in foreign or session_id in seen:
                    continue
                built = self._transcript_session(
                    os.path.join(root, project, name),
                    session_id,
                    project,
                    live,
                    matcher,
                    problems,
                )
                if built is not None:
                    seen.add(session_id)
                    sessions.append(built)
        for session_id, entry in sorted(live.by_id.items()):
            if session_id in seen or session_id in foreign:
                continue
            if entry.entrypoint == "claude-desktop":
                continue
            sessions.append(_registry_session(entry, live, matcher))
        return sessions

    def _transcript_session(
        self,
        path: str,
        session_id: str,
        project: str,
        live: LiveSessions,
        matcher: ConfidentialMatcher,
        problems: Problems,
    ) -> Session | None:
        try:
            meta = scan_transcript(path)
            modified = os.path.getmtime(path)
        except OSError:
            problems.add("files_denied")
            return None
        if meta.entrypoint == "claude-desktop":
            return None
        if not meta.recognised:
            problems.add("files_damaged")
        entry = live.by_id.get(session_id)
        folder = meta.cwd or (entry.cwd if entry else None)
        confidential = matcher.folder_is_confidential(
            meta.cwd, entry.cwd if entry else None
        ) or matcher.project_dir_is_confidential(project)
        title = meta.title or (entry.name if entry else None)
        last = meta.last_activity
        last_source = "projects/*.jsonl last timestamp"
        last_reliability = Reliability.HIGH
        if last is None:
            last = _mtime_text(modified)
            last_source = "transcript file modification time"
            last_reliability = Reliability.LOW
        state, state_source = _state(entry, live)
        origin_value = meta.entrypoint or (entry.entrypoint if entry else None)
        refs: list[FieldSource | None] = [
            source("id", "transcript file name", Reliability.HIGH),
            source("last_activity", last_source, last_reliability) if last else None,
            source("state", state_source, Reliability.MEDIUM),
            source("origin", "entrypoint field", Reliability.HIGH)
            if origin_value
            else None,
            source("created", "projects/*.jsonl first timestamp", Reliability.HIGH)
            if meta.created
            else None,
            source("folder", "projects/*.jsonl cwd", Reliability.HIGH)
            if meta.cwd
            else (
                source("folder", "sessions/*.json cwd", Reliability.MEDIUM)
                if folder
                else None
            ),
            source(
                "model", "message.model of last assistant record", Reliability.MEDIUM
            )
            if meta.model
            else None,
        ]
        refs += live_sources(entry)
        if title and not confidential:
            if meta.title and meta.title_kind:
                refs.append(
                    source("title", _TITLE_SOURCES[meta.title_kind], Reliability.HIGH)
                )
            else:
                refs.append(source("title", "sessions/*.json name", Reliability.MEDIUM))
        pid, state_since = live_link(entry)
        return Session(
            id=session_id,
            harness_id=HARNESS_ID,
            title=None if confidential else title,
            folder=folder,
            model=meta.model,
            created=meta.created,
            last_activity=last,
            state=state,
            origin=origin_from_entrypoint(origin_value),
            confidential=confidential,
            field_sources=sorted_sources(refs),
            pid=pid,
            state_since=state_since,
        )


# --------------------------------------------------------------------------


def _version_from_link(link: str) -> str | None:
    """The version from the folder name the symlink points at."""
    try:
        target = os.readlink(link)
    except OSError:
        return None
    leaf = os.path.basename(target.rstrip("/"))
    return leaf if VERSION_RE.fullmatch(leaf) else None


def _mtime_text(seconds: float) -> str | None:
    return iso_from_ms(seconds * 1000)


def _state(entry: LiveSession | None, live: LiveSessions) -> tuple[SessionState, str]:
    if entry is not None:
        return (
            state_from_status(entry.status),
            "sessions/*.json status, process confirmed alive",
        )
    if live.known:
        return SessionState.ENDED, "no live claude process lists this session"
    return SessionState.UNKNOWN, "process table could not be read"


def _registry_session(
    entry: LiveSession, live: LiveSessions, matcher: ConfidentialMatcher
) -> Session:
    confidential = matcher.folder_is_confidential(entry.cwd)
    state, state_source = _state(entry, live)
    refs: list[FieldSource | None] = [
        source("id", "sessions/*.json sessionId", Reliability.HIGH),
        source("state", state_source, Reliability.MEDIUM),
        source("created", "sessions/*.json startedAt", Reliability.MEDIUM)
        if entry.started_ms
        else None,
        source("last_activity", "sessions/*.json updatedAt", Reliability.MEDIUM)
        if entry.updated_ms
        else None,
        source("folder", "sessions/*.json cwd", Reliability.MEDIUM)
        if entry.cwd
        else None,
        source("origin", "sessions/*.json entrypoint", Reliability.HIGH)
        if entry.entrypoint
        else None,
        source("title", "sessions/*.json name", Reliability.MEDIUM)
        if entry.name and not confidential
        else None,
        *live_sources(entry),
    ]
    pid, state_since = live_link(entry)
    return Session(
        id=entry.session_id,
        harness_id=HARNESS_ID,
        title=None if confidential else entry.name,
        folder=entry.cwd,
        created=iso_from_ms(entry.started_ms),
        last_activity=iso_from_ms(entry.updated_ms),
        state=state,
        origin=origin_from_entrypoint(entry.entrypoint),
        confidential=confidential,
        field_sources=sorted_sources(refs),
        pid=pid,
        state_since=state_since,
    )


def _desktop_cli_ids(home: str) -> set[str]:
    """CLI session ids that belong to the desktop app or Cowork."""
    ids: set[str] = set()
    support = app_support(home)
    quiet = Problems(LABEL)  # the desktop adapters report their own index problems
    for folder in ("claude-code-sessions", "local-agent-mode-sessions"):
        records, _ = read_index_records(os.path.join(support, folder), quiet)
        for record in records:
            link = record.get("cliSessionId")
            if isinstance(link, str) and link:
                ids.add(link)
            ids.update(string_list(record.get("priorCliSessionIds")))
    return ids
