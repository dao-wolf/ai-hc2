"""Shared fakes for the core tests. Everything here is made up."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import hc2.adapters as adapter_registry
from hc2.adapters.base import AdapterContext, AdapterReport, ProcessSignature
from hc2.config import Config, Overrides, load_config
from hc2.model import (
    Harness,
    Install,
    InstallKind,
    Origin,
    Session,
    SessionState,
)

NOW = datetime(2026, 10, 30, 9, 0, 0, tzinfo=UTC)

# Strings that must never reach any output (T-4).
CONFIDENTIAL_TITLE = "SENTINELTITLE-quarterly-merger"
CONFIDENTIAL_NAME = "sentinel-client-folder"
SECRET_KEY = "sk-" + "Q7" * 16
SECRET_EMAIL = "carol" + "@" + "sentinel-mail.org"
SECRET_PASSWORD = "hunter2-sentinel"
EXCEPTION_SENTINEL = "SENTINELEXCEPTIONTEXT"


@dataclass(frozen=True)
class FakeHome:
    """A made-up home folder inside a temp directory."""

    root: Path
    home: Path
    config_dir: Path
    state_dir: Path

    @property
    def confidential(self) -> str:
        return str(self.home / "clients" / CONFIDENTIAL_NAME)

    def write_sessions(self, rows: list[dict[str, object]]) -> None:
        (self.home / "fake-sessions.json").write_text(json.dumps(rows))

    def write_config(self, text: str) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        (self.config_dir / "config.toml").write_text(text)


@contextlib.contextmanager
def fake_home() -> Iterator[FakeHome]:
    """A temp home, config and state folder, with HC2's environment pointed there.

    The scan clock is fixed at `NOW`, so stale sessions do not depend on the day
    the tests run.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        home = root / "home" / "alice"
        home.mkdir(parents=True)
        fake = FakeHome(root, home, root / "config", root / "state")
        env = {
            "HOME": str(home),
            "HC2_CONFIG_DIR": str(fake.config_dir),
            "HC2_STATE_DIR": str(fake.state_dir),
        }
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("hc2.scan.utc_now", lambda: NOW),  # a steady clock
        ):
            for name in list(os.environ):
                if name.startswith("HC2_") and name not in env:
                    del os.environ[name]
            yield fake


def sample_rows(fake: FakeHome) -> list[dict[str, object]]:
    """Three sessions: one ordinary, one old, one in a confidential folder."""
    return [
        {
            "id": "sess-1",
            "title": "Example Project",
            "folder": str(fake.home / "projects" / "example-project"),
            "model": "example-model-1",
            "last": "2026-10-30T08:30:00Z",
            "state": "running-idle",
        },
        {
            "id": "sess-2",
            "title": "Old work",
            "folder": str(fake.home / "projects" / "old-work"),
            "last": "2026-10-28T08:30:00Z",
            "state": "running-idle",
        },
        {
            "id": "sess-3",
            "title": CONFIDENTIAL_TITLE,
            "folder": fake.confidential + "/notes",
            "last": "2026-10-30T08:00:00Z",
            "state": "unknown",
            "confidential": True,
        },
    ]


class FileAdapter:
    """Reads `fake-sessions.json` from the context's home, like a real adapter."""

    def __init__(
        self, adapter_id: str = "fake-files", name: str = "Fake Files"
    ) -> None:
        self.id = adapter_id
        self.name = name
        self.seen_contexts: list[AdapterContext] = []
        self.problems: tuple[str, ...] = ()

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        self.seen_contexts.append(ctx)
        path = Path(ctx.home) / "fake-sessions.json"
        rows = json.loads(path.read_text()) if path.exists() else []
        sessions = tuple(
            Session(
                id=str(row["id"]),
                harness_id=self.id,
                title=str(row["title"]),
                folder=str(row["folder"]),
                model=str(row["model"]) if "model" in row else None,
                last_activity=str(row["last"]),
                state=SessionState(str(row["state"])),
                origin=Origin.CLI,
                confidential=bool(row.get("confidential", False)),
            )
            for row in rows
        )
        harness = Harness(
            id=self.id,
            name=self.name,
            installed=True,
            installs=(
                Install(
                    id="install_fake",
                    harness_id=self.id,
                    kind=InstallKind.CLI,
                    version="1.2.3",
                    location=str(Path(ctx.home) / "bin" / "fake"),
                ),
            ),
            config_location=str(Path(ctx.home) / ".fake"),
        )
        return AdapterReport(
            harness,
            sessions,
            self.problems,
            ("fake-sessions.json: id, title, folder, last, state",),
        )

    def process_signature(self) -> ProcessSignature:
        return ProcessSignature(self.id, ("fake",))


class RaisingAdapter:
    """Raises an error whose text holds a path and a sentinel."""

    id = "fake-raises"
    name = "Fake Raises"

    def __init__(self, home: str = "/home/alice") -> None:
        self.home = home

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        raise RuntimeError(f"{self.home}/{CONFIDENTIAL_NAME}/x {EXCEPTION_SENTINEL}")

    def process_signature(self) -> ProcessSignature:
        return ProcessSignature(self.id)


class HangingAdapter:
    """Blocks until released. Call `release()` in cleanup."""

    id = "fake-hangs"
    name = "Fake Hangs"

    def __init__(self) -> None:
        self._gate = threading.Event()

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        self._gate.wait(30)
        raise RuntimeError("released")

    def release(self) -> None:
        self._gate.set()

    def process_signature(self) -> ProcessSignature:
        return ProcessSignature(self.id)


class WrongTypeAdapter:
    """Returns something that is not an AdapterReport."""

    id = "fake-wrong"
    name = "Fake Wrong"

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        return "not a report"  # type: ignore[return-value]

    def process_signature(self) -> ProcessSignature:
        return ProcessSignature(self.id)


def config_for(
    fake: FakeHome,
    *,
    confidential: bool = True,
    timeout: float = 2.0,
    stale_hours: float = 2.0,
    extra: Callable[[Overrides], Overrides] | None = None,
) -> Config:
    """A config with the fake confidential folder listed."""
    overrides = Overrides(
        confidential_folders=(fake.confidential,) if confidential else (),
        adapter_timeout_seconds=timeout,
        stale_hours=stale_hours,
    )
    if extra is not None:
        overrides = extra(overrides)
    path = fake.config_dir / "config.toml"
    return load_config(path=path, env={}, overrides=overrides)


@contextlib.contextmanager
def registered(*adapters: object) -> Iterator[None]:
    """Make `hc2.adapters.ALL_ADAPTERS` hold exactly these adapters."""
    with mock.patch.object(adapter_registry, "ALL_ADAPTERS", tuple(adapters)):
        yield


def everything_written(fake: FakeHome) -> str:
    """All text HC2 stored: snapshots, audit lines, and every database row."""
    import sqlite3

    chunks: list[str] = []
    for path in sorted(fake.state_dir.rglob("*")):
        if path.is_file() and path.suffix in (".json", ".jsonl"):
            chunks.append(path.read_text(encoding="utf-8"))
    db = fake.state_dir / "hc2.db"
    if db.exists():
        conn = sqlite3.connect(db)
        try:
            for (table,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall():
                chunks.append(repr(conn.execute(f"SELECT * FROM {table}").fetchall()))
        finally:
            conn.close()
    return "\n".join(chunks)
