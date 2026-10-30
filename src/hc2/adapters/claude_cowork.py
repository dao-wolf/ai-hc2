"""Adapter for Claude desktop's Cowork sessions.

Cowork runs inside a virtual machine, so there is no per-session process to
check. Sessions come from the index files only: archived ones are `ENDED`
and the rest are `UNKNOWN` (FR-2).
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from hc2.adapters.base import AdapterContext, AdapterReport, ProcessSignature
from hc2.adapters.claude_common import (
    RELEASE_NOTES_URL,
    ConfidentialMatcher,
    Problems,
    app_install,
    app_support,
    as_bool,
    as_str,
    clean_title,
    default_app_dirs,
    display_path,
    iso_from_ms,
    read_index_records,
    sorted_sources,
    source,
    string_list,
)
from hc2.model import (
    FieldSource,
    Harness,
    Origin,
    Reliability,
    Session,
    SessionState,
)

HARNESS_ID = "claude-desktop-cowork"
LABEL = "Claude desktop (Cowork)"
INDEX_FOLDER = "local-agent-mode-sessions"

FIELDS_READ = (
    "Claude.app/Contents/Info.plist: CFBundleShortVersionString",
    "local-agent-mode-sessions/*/*/local_*.json: sessionId, title, "
    "userSelectedFolders, model, createdAt, lastActivityAt, isArchived",
)


class ClaudeCoworkAdapter:
    """The desktop app's Cowork sessions."""

    id = HARNESS_ID
    name = LABEL

    def __init__(self, app_dirs: Sequence[str] | None = None) -> None:
        self._app_dirs = None if app_dirs is None else tuple(app_dirs)

    def process_signature(self) -> ProcessSignature:
        """Cowork's virtual machine bundle. The app itself belongs to the Code tab."""
        return ProcessSignature(
            harness_id=HARNESS_ID,
            path_markers=("/Application Support/Claude/vm_bundles/",),
        )

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        """Find the app and list Cowork sessions. Never raises."""
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
        app = app_install(
            HARNESS_ID, home, self._app_dirs or default_app_dirs(home), problems
        )
        matcher = ConfidentialMatcher(ctx.confidential_folders, home)
        records, status = read_index_records(
            os.path.join(support, INDEX_FOLDER), problems
        )
        if status == "denied":
            problems.add("store_denied")
        elif status == "missing" and app is not None:
            problems.add("store_missing")
        sessions: dict[str, Session] = {}
        for record in records:
            session = _session(record, matcher)
            sessions.setdefault(session.id, session)
        ordered = sorted(
            sessions.values(), key=lambda s: (s.last_activity or "", s.id), reverse=True
        )
        harness = Harness(
            id=HARNESS_ID,
            name=LABEL,
            installed=app is not None,
            installs=(app,) if app else (),
            config_location=display_path(support, home),
            docs_url="https://support.claude.com",
            changelog_url=RELEASE_NOTES_URL,
            llms_txt_url="https://claude.com/docs/llms.txt",
        )
        return AdapterReport(
            harness=harness,
            sessions=tuple(ordered),
            problems=problems.render(),
            fields_read=FIELDS_READ,
        )


def _session(record: dict[str, object], matcher: ConfidentialMatcher) -> Session:
    folders = string_list(record.get("userSelectedFolders"))
    folder = folders[0] if folders else None
    confidential = matcher.folder_is_confidential(*folders)
    title = clean_title(record.get("title"))
    model = as_str(record.get("model"))
    created = iso_from_ms(record.get("createdAt"))
    last = iso_from_ms(record.get("lastActivityAt"))
    archived = as_bool(record.get("isArchived"))
    if archived:
        state, state_source = SessionState.ENDED, "index isArchived"
    else:
        state, state_source = SessionState.UNKNOWN, "Cowork has no per-session process"
    refs: list[FieldSource | None] = [
        source("id", "index sessionId", Reliability.HIGH),
        source("origin", "Cowork index", Reliability.HIGH),
        source("state", state_source, Reliability.MEDIUM),
        source("title", "index title", Reliability.HIGH)
        if title and not confidential
        else None,
        source("folder", "index userSelectedFolders", Reliability.HIGH)
        if folder
        else None,
        source("model", "index model", Reliability.HIGH) if model else None,
        source("created", "index createdAt", Reliability.HIGH) if created else None,
        source("last_activity", "index lastActivityAt", Reliability.HIGH)
        if last
        else None,
    ]
    return Session(
        id=as_str(record.get("sessionId")) or "",
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
    )
