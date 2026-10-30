"""History in SQLite, plus the latest snapshots as JSON (FR-9, Op-2).

Everything lives in the state folder:

* `hc2.db`: scans, finding history (first seen, last seen, resolved) and
  acknowledgements. Schema v1, tracked in `schema_version`.
* `snapshots/<time>-<row>.json`: the redacted snapshot of each recent scan, so
  `status` can show the latest one without rescanning. Snapshots older than the
  retention setting are deleted, but the newest one always stays.

Only redacted data is stored (P-3). Acknowledging a finding is an approver
action (A-2), so this module only reads acknowledgements. The table exists so
that the S6 approval flow can write to it.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hc2._fs import PRIVATE_FILE_MODE, atomic_write, ensure_private_dir
from hc2.errors import UserError
from hc2.model import Model, Severity, Snapshot

SCHEMA_VERSION = 1
"""The newest database layout this code writes."""

DB_NAME = "hc2.db"
SNAPSHOT_DIR = "snapshots"

_SNAPSHOT_RE = re.compile(r"(\d{8}T\d{6}Z)-(\d{6})\.json")

Migration = Callable[[sqlite3.Connection], None]


_V1_STATEMENTS = (
    """
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        generated TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        config_fingerprint TEXT NOT NULL,
        scan_seconds REAL,
        red_count INTEGER NOT NULL,
        amber_count INTEGER NOT NULL,
        info_count INTEGER NOT NULL,
        new_ids TEXT NOT NULL,
        fixed_ids TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        harness_id TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        resolved_at TEXT,
        times_seen INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE acknowledgements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        note TEXT,
        expires_at TEXT,
        acknowledged_at TEXT NOT NULL,
        actor TEXT NOT NULL
    )
    """,
    "CREATE INDEX acknowledgements_by_finding ON acknowledgements (finding_id)",
)


def _migrate_to_v1(conn: sqlite3.Connection) -> None:
    for statement in _V1_STATEMENTS:
        conn.execute(statement)


MIGRATIONS: dict[int, Migration] = {1: _migrate_to_v1}
"""Version number to the step that upgrades the database to it.

To change the layout, add the next number here and raise `SCHEMA_VERSION`.
"""


def _version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def migrate(
    conn: sqlite3.Connection,
    migrations: dict[int, Migration] | None = None,
    target: int | None = None,
) -> int:
    """Bring the database up to `target` and return its version.

    Each step runs in one transaction together with its version bump, so a
    failure leaves the previous version in place. Steps must use `execute`, not
    `executescript`, which would end the transaction early.

    Raises:
        UserError: the database comes from a newer HC2.
    """
    steps = MIGRATIONS if migrations is None else migrations
    goal = SCHEMA_VERSION if target is None else target
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    conn.commit()
    if _version(conn) > goal:
        raise UserError(
            "HC2's history was written by a newer version of HC2. "
            "Upgrade HC2 to read it."
        )
    for version in range(1, goal + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            if _version(conn) < version:  # another HC2 may have got here first
                steps[version](conn)
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)", (version,)
                )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    return _version(conn)


@dataclass(frozen=True)
class ScanRecord(Model):
    """One row of the scan history."""

    row_id: int
    scan_id: str
    generated: str
    content_hash: str
    config_fingerprint: str
    scan_seconds: float | None
    new_ids: tuple[str, ...]
    fixed_ids: tuple[str, ...]


@dataclass(frozen=True)
class FindingRecord(Model):
    """A finding's history: when it first appeared, last appeared and resolved."""

    finding_id: str
    rule_id: str
    severity: Severity
    title: str
    harness_id: str | None
    first_seen: str
    last_seen: str
    resolved_at: str | None
    times_seen: int


@dataclass(frozen=True)
class Acknowledgement(Model):
    """A person's note that they have seen a finding (FR-9)."""

    finding_id: str
    note: str | None
    expires_at: str | None
    acknowledged_at: str
    actor: str


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


class Store:
    """The state folder's database and snapshot files."""

    def __init__(self, state: Path, conn: sqlite3.Connection) -> None:
        self._state = state
        self._conn = conn

    # -- opening ---------------------------------------------------------

    @classmethod
    def create(cls, state: Path) -> Store:
        """Open the store, creating the state folder and database if needed.

        Raises:
            UserError: the database cannot be opened or is from a newer HC2.
        """
        store = cls._open(state, create=True)
        assert store is not None
        return store

    @classmethod
    def existing(cls, state: Path) -> Store | None:
        """Open the store if it exists. Creates nothing, and returns `None` if
        there is no database yet.

        Raises:
            UserError: the database cannot be opened or is from a newer HC2.
        """
        return cls._open(state, create=False)

    @classmethod
    def _open(cls, state: Path, *, create: bool) -> Store | None:
        path = state / DB_NAME
        if not create and not path.is_file():
            return None
        try:
            if create:
                ensure_private_dir(state)
            fresh = not path.exists()
            conn = sqlite3.connect(path, timeout=10)
            if fresh:
                path.chmod(PRIVATE_FILE_MODE)
            try:
                migrate(conn)
            except BaseException:
                conn.close()
                raise
        except (OSError, sqlite3.Error) as error:
            raise UserError(
                "HC2 could not open its history database. Check that the state "
                "folder exists and that you can write to it."
            ) from error
        return cls(state, conn)

    def close(self) -> None:
        """Close the database."""
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def schema_version(self) -> int:
        """The database layout version."""
        return _version(self._conn)

    # -- scans -----------------------------------------------------------

    @staticmethod
    def _scan(row: Sequence[object]) -> ScanRecord:
        return ScanRecord(
            row_id=int(str(row[0])),
            scan_id=str(row[1]),
            generated=str(row[2]),
            content_hash=str(row[3]),
            config_fingerprint=str(row[4]),
            scan_seconds=None if row[5] is None else float(str(row[5])),
            new_ids=tuple(json.loads(str(row[6]))),
            fixed_ids=tuple(json.loads(str(row[7]))),
        )

    _SCAN_COLUMNS = (
        "id, scan_id, generated, content_hash, config_fingerprint, scan_seconds, "
        "new_ids, fixed_ids"
    )

    def last_scan(self) -> ScanRecord | None:
        """The newest scan, or `None` before the first one."""
        row = self._conn.execute(
            f"SELECT {self._SCAN_COLUMNS} FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return self._scan(row) if row else None

    def previous_scan(self) -> ScanRecord | None:
        """The scan before the newest one."""
        row = self._conn.execute(
            f"SELECT {self._SCAN_COLUMNS} FROM scans ORDER BY id DESC LIMIT 1 OFFSET 1"
        ).fetchone()
        return self._scan(row) if row else None

    def open_finding_ids(self) -> frozenset[str]:
        """Ids of findings that were present in the newest scan."""
        rows = self._conn.execute(
            "SELECT finding_id FROM findings WHERE resolved_at IS NULL"
        )
        return frozenset(str(row[0]) for row in rows)

    def record_scan(
        self,
        snapshot: Snapshot,
        *,
        content_hash: str,
        config_fingerprint: str,
        scan_seconds: float,
        retention_days: int,
    ) -> ScanRecord:
        """Save a scan: its row, the finding history and the snapshot file.

        New and fixed findings are worked out here, against the findings that
        were open after the previous scan, so the history and the diff cannot
        disagree.

        Raises:
            UserError: the database or snapshot folder could not be written.
        """
        try:
            return self._record(
                snapshot, content_hash, config_fingerprint, scan_seconds, retention_days
            )
        except (OSError, sqlite3.Error) as error:
            raise UserError(
                "HC2 could not save the scan. Check that the state folder "
                "exists and that you can write to it."
            ) from error

    def _record(
        self,
        snapshot: Snapshot,
        content_hash: str,
        config_fingerprint: str,
        scan_seconds: float,
        retention_days: int,
    ) -> ScanRecord:
        current = {item.id: item for item in snapshot.findings}
        before = self.open_finding_ids()
        new_ids = tuple(sorted(set(current) - before))
        fixed_ids = tuple(sorted(before - set(current)))
        counts = {sev: 0 for sev in Severity}
        for item in snapshot.findings:
            counts[item.severity] += 1
        with self._conn:
            for item in snapshot.findings:
                self._conn.execute(
                    """
                    INSERT INTO findings (finding_id, rule_id, severity, title,
                        harness_id, first_seen, last_seen, resolved_at, times_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        severity = excluded.severity, title = excluded.title,
                        last_seen = excluded.last_seen, resolved_at = NULL,
                        times_seen = times_seen + 1
                    """,
                    (
                        item.id,
                        item.rule_id,
                        item.severity.value,
                        item.title,
                        item.harness_id,
                        snapshot.generated,
                        snapshot.generated,
                    ),
                )
            self._conn.executemany(
                "UPDATE findings SET resolved_at = ? WHERE finding_id = ?",
                [(snapshot.generated, finding_id) for finding_id in fixed_ids],
            )
            cursor = self._conn.execute(
                """
                INSERT INTO scans (scan_id, generated, content_hash,
                    config_fingerprint, scan_seconds, red_count, amber_count,
                    info_count, new_ids, fixed_ids)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.scan_id,
                    snapshot.generated,
                    content_hash,
                    config_fingerprint,
                    round(scan_seconds, 3),
                    counts[Severity.RED],
                    counts[Severity.AMBER],
                    counts[Severity.INFO],
                    json.dumps(new_ids),
                    json.dumps(fixed_ids),
                ),
            )
            row_id = int(cursor.lastrowid or 0)
        self._write_snapshot(snapshot, row_id)
        self._prune_snapshots(_parse(snapshot.generated), retention_days)
        return ScanRecord(
            row_id=row_id,
            scan_id=snapshot.scan_id,
            generated=snapshot.generated,
            content_hash=content_hash,
            config_fingerprint=config_fingerprint,
            scan_seconds=round(scan_seconds, 3),
            new_ids=new_ids,
            fixed_ids=fixed_ids,
        )

    # -- findings --------------------------------------------------------

    _FINDING_COLUMNS = (
        "finding_id, rule_id, severity, title, harness_id, first_seen, last_seen, "
        "resolved_at, times_seen"
    )

    @staticmethod
    def _finding(row: Sequence[object]) -> FindingRecord:
        return FindingRecord(
            finding_id=str(row[0]),
            rule_id=str(row[1]),
            severity=Severity(str(row[2])),
            title=str(row[3]),
            harness_id=None if row[4] is None else str(row[4]),
            first_seen=str(row[5]),
            last_seen=str(row[6]),
            resolved_at=None if row[7] is None else str(row[7]),
            times_seen=int(str(row[8])),
        )

    def finding_history(self, *, open_only: bool = False) -> tuple[FindingRecord, ...]:
        """Every finding HC2 has seen, newest first appearance last."""
        where = " WHERE resolved_at IS NULL" if open_only else ""
        rows = self._conn.execute(
            f"SELECT {self._FINDING_COLUMNS} FROM findings{where} "
            "ORDER BY first_seen, finding_id"
        )
        return tuple(self._finding(row) for row in rows)

    def finding_records(self, ids: Iterable[str]) -> dict[str, FindingRecord]:
        """History rows for the given finding ids."""
        found: dict[str, FindingRecord] = {}
        for finding_id in ids:
            row = self._conn.execute(
                f"SELECT {self._FINDING_COLUMNS} FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row:
                found[finding_id] = self._finding(row)
        return found

    # -- acknowledgements (read only until S6) ---------------------------

    def acknowledgements(self, now: datetime) -> dict[str, Acknowledgement]:
        """The live acknowledgement for each finding, keyed by finding id.

        The newest row per finding wins. Rows whose expiry has passed are left out.
        """
        rows = self._conn.execute(
            "SELECT finding_id, note, expires_at, acknowledged_at, actor "
            "FROM acknowledgements ORDER BY id"
        )
        live: dict[str, Acknowledgement] = {}
        for row in rows:
            ack = Acknowledgement(
                finding_id=str(row[0]),
                note=None if row[1] is None else str(row[1]),
                expires_at=None if row[2] is None else str(row[2]),
                acknowledged_at=str(row[3]),
                actor=str(row[4]),
            )
            live[ack.finding_id] = ack
        return {
            key: ack
            for key, ack in live.items()
            if ack.expires_at is None or _safe_parse(ack.expires_at) > now
        }

    # -- snapshots -------------------------------------------------------

    @property
    def snapshot_dir(self) -> Path:
        """The folder holding the snapshot files."""
        return self._state / SNAPSHOT_DIR

    def _snapshot_files(self) -> list[Path]:
        if not self.snapshot_dir.is_dir():
            return []
        return sorted(
            path
            for path in self.snapshot_dir.iterdir()
            if _SNAPSHOT_RE.fullmatch(path.name)
        )

    def _write_snapshot(self, snapshot: Snapshot, row_id: int) -> None:
        ensure_private_dir(self.snapshot_dir)
        stamp = _parse(snapshot.generated).strftime("%Y%m%dT%H%M%SZ")
        path = self.snapshot_dir / f"{stamp}-{row_id:06d}.json"
        atomic_write(path, (snapshot.to_json() + "\n").encode("utf-8"))

    def _prune_snapshots(self, now: datetime, retention_days: int) -> None:
        cutoff = now - timedelta(days=retention_days)
        files = self._snapshot_files()
        for path in files[:-1]:  # the newest always stays
            match = _SNAPSHOT_RE.fullmatch(path.name)
            if match is None:
                continue
            taken = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ")
            if taken.replace(tzinfo=UTC) < cutoff:
                with suppress(OSError):
                    path.unlink()

    def latest_snapshot(self) -> Snapshot | None:
        """The newest saved snapshot, or `None` if there is none or it is damaged."""
        files = self._snapshot_files()
        if not files:
            return None
        try:
            data = json.loads(files[-1].read_text(encoding="utf-8"))
            return Snapshot.from_dict(data)
        except (OSError, ValueError, TypeError, KeyError):
            return None


def _safe_parse(value: str) -> datetime:
    """Parse a stored time. A value that cannot be read counts as already expired."""
    try:
        return _parse(value)
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
