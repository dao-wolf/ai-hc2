"""The store: schema, migrations, finding history and snapshots (FR-9, Op-2)."""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hc2 import store as store_module
from hc2.errors import UserError
from hc2.model import (
    SCHEMA_VERSION,
    Finding,
    Harness,
    HarnessReport,
    Session,
    Severity,
    Snapshot,
    stable_id,
)
from hc2.store import Store, migrate

BASE = datetime(2026, 10, 30, 9, 0, 0, tzinfo=UTC)


def finding(name: str, severity: Severity = Severity.AMBER) -> Finding:
    return Finding(
        id=stable_id("finding", "test.rule", "", name),
        rule_id="test.rule",
        severity=severity,
        title=f"Title for {name}",
        reason="Because.",
        fix="Fix it.",
        harness_id="h",
    )


def snapshot(
    findings: tuple[Finding, ...], when: datetime = BASE, scan_id: str = "scan_a"
) -> Snapshot:
    report = HarnessReport(
        Harness("h", "Harness", True), (Session("s1", "h", title="Example Project"),)
    )
    return Snapshot(
        SCHEMA_VERSION,
        when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        scan_id,
        (report,),
        findings,
    )


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"

    def save(
        self, store: Store, snap: Snapshot, retention: int = 30
    ) -> tuple[str, ...]:
        record = store.record_scan(
            snap,
            content_hash="c" * 64,
            config_fingerprint="f" * 64,
            scan_seconds=0.25,
            retention_days=retention,
        )
        return record.new_ids + ("|",) + record.fixed_ids

    # -- opening and schema ---------------------------------------------

    def test_existing_creates_nothing_when_there_is_no_database(self) -> None:
        self.assertIsNone(Store.existing(self.state))
        self.assertFalse(self.state.exists())

    def test_create_makes_a_private_database_at_schema_v1(self) -> None:
        with Store.create(self.state) as store:
            self.assertEqual(store.schema_version(), 1)
            self.assertEqual(store_module.SCHEMA_VERSION, 1)
            self.assertIsNone(store.last_scan())
            self.assertIsNone(store.latest_snapshot())
        mode = stat.S_IMODE(os.stat(self.state / "hc2.db").st_mode)
        self.assertEqual(mode, 0o600)

    def test_all_three_tables_exist(self) -> None:
        with Store.create(self.state):
            pass
        conn = sqlite3.connect(self.state / "hc2.db")
        names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        conn.close()
        wanted = {"scans", "findings", "acknowledgements", "schema_version"}
        self.assertTrue(wanted <= names)

    def test_reopening_does_not_migrate_twice(self) -> None:
        with Store.create(self.state):
            pass
        with Store.create(self.state) as store:
            self.assertEqual(store.schema_version(), 1)
        conn = sqlite3.connect(self.state / "hc2.db")
        count = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        self.assertEqual(count, 1)
        conn.close()

    def test_the_migration_hook_runs_each_missing_step_in_order(self) -> None:
        conn = sqlite3.connect(":memory:")
        ran: list[int] = []

        def one(c: sqlite3.Connection) -> None:
            ran.append(1)
            c.execute("CREATE TABLE a (x)")

        def two(c: sqlite3.Connection) -> None:
            ran.append(2)
            c.execute("ALTER TABLE a ADD COLUMN y")

        steps = {1: one, 2: two}
        self.assertEqual(migrate(conn, steps, 1), 1)
        self.assertEqual(migrate(conn, steps, 2), 2)
        self.assertEqual(migrate(conn, steps, 2), 2)
        self.assertEqual(ran, [1, 2])

    def test_a_failed_step_leaves_the_old_version(self) -> None:
        conn = sqlite3.connect(":memory:")

        def one(c: sqlite3.Connection) -> None:
            c.execute("CREATE TABLE a (x)")

        def broken(c: sqlite3.Connection) -> None:
            c.execute("CREATE TABLE b (x)")
            raise RuntimeError("boom")

        steps = {1: one, 2: broken}
        migrate(conn, steps, 1)
        with self.assertRaises(RuntimeError):
            migrate(conn, steps, 2)
        self.assertEqual(migrate(conn, {1: one}, 1), 1)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        self.assertNotIn("b", tables)

    def test_a_database_from_a_newer_hc2_is_refused_plainly(self) -> None:
        with Store.create(self.state):
            pass
        conn = sqlite3.connect(self.state / "hc2.db")
        conn.execute("INSERT INTO schema_version VALUES (99)")
        conn.commit()
        conn.close()
        with self.assertRaises(UserError) as caught:
            Store.create(self.state)
        self.assertIn("newer version", str(caught.exception))

    def test_an_unopenable_state_folder_is_a_plain_error(self) -> None:
        blocker = Path(self._tmp.name) / "file"
        blocker.write_text("x")
        with self.assertRaises(UserError) as caught:
            Store.create(blocker / "state")
        self.assertNotIn(str(blocker), str(caught.exception))

    # -- scans and the diff ---------------------------------------------

    def test_first_scan_reports_everything_as_new(self) -> None:
        a, b = finding("a"), finding("b")
        with Store.create(self.state) as store:
            record = store.record_scan(
                snapshot((a, b)),
                content_hash="c" * 64,
                config_fingerprint="f" * 64,
                scan_seconds=0.1234567,
                retention_days=30,
            )
            self.assertEqual(record.new_ids, tuple(sorted((a.id, b.id))))
            self.assertEqual(record.fixed_ids, ())
            self.assertEqual(record.scan_seconds, 0.123)
            self.assertEqual(store.last_scan(), record)
            self.assertIsNone(store.previous_scan())

    def test_new_and_fixed_findings_come_from_the_open_set(self) -> None:
        a, b, c = finding("a"), finding("b"), finding("c")
        with Store.create(self.state) as store:
            self.save(store, snapshot((a, b), BASE))
            second = store.record_scan(
                snapshot((b, c), BASE + timedelta(hours=1), "scan_b"),
                content_hash="d" * 64,
                config_fingerprint="f" * 64,
                scan_seconds=0.1,
                retention_days=30,
            )
            self.assertEqual(second.new_ids, (c.id,))
            self.assertEqual(second.fixed_ids, (a.id,))
            self.assertEqual(store.open_finding_ids(), frozenset({b.id, c.id}))
            previous = store.previous_scan()
            assert previous is not None
            self.assertEqual(previous.scan_id, "scan_a")

    def test_history_keeps_first_seen_last_seen_and_resolved(self) -> None:
        a = finding("a")
        with Store.create(self.state) as store:
            self.save(store, snapshot((a,), BASE))
            self.save(store, snapshot((a,), BASE + timedelta(hours=1)))
            self.save(store, snapshot((), BASE + timedelta(hours=2)))
            (row,) = store.finding_history()
            self.assertEqual(row.first_seen, "2026-10-30T09:00:00Z")
            self.assertEqual(row.last_seen, "2026-10-30T10:00:00Z")
            self.assertEqual(row.resolved_at, "2026-10-30T11:00:00Z")
            self.assertEqual(row.times_seen, 2)
            self.assertEqual(store.finding_history(open_only=True), ())

    def test_a_finding_that_returns_is_new_again_with_its_old_first_seen(self) -> None:
        a = finding("a")
        with Store.create(self.state) as store:
            self.save(store, snapshot((a,), BASE))
            self.save(store, snapshot((), BASE + timedelta(hours=1)))
            record = store.record_scan(
                snapshot((a,), BASE + timedelta(hours=2)),
                content_hash="e" * 64,
                config_fingerprint="f" * 64,
                scan_seconds=0,
                retention_days=30,
            )
            self.assertEqual(record.new_ids, (a.id,))
            (row,) = store.finding_history()
            self.assertEqual(row.first_seen, "2026-10-30T09:00:00Z")
            self.assertIsNone(row.resolved_at)
            self.assertEqual(row.times_seen, 2)

    def test_finding_records_looks_up_titles(self) -> None:
        a = finding("a")
        with Store.create(self.state) as store:
            self.save(store, snapshot((a,)))
            found = store.finding_records([a.id, "finding_missing"])
            self.assertEqual(list(found), [a.id])
            self.assertEqual(found[a.id].title, "Title for a")

    # -- acknowledgements (read only) ------------------------------------

    def test_acknowledgements_can_be_read_and_expire(self) -> None:
        a, b, c = finding("a"), finding("b"), finding("c")
        with Store.create(self.state) as store:
            self.assertEqual(store.acknowledgements(BASE), {})
            conn = sqlite3.connect(self.state / "hc2.db")
            rows = [
                (a.id, "seen", None, "2026-10-29T09:00:00Z", "me"),
                (b.id, None, "2026-10-31T09:00:00Z", "2026-10-29T09:00:00Z", "me"),
                (c.id, "old", "2026-10-01T09:00:00Z", "2026-09-29T09:00:00Z", "me"),
            ]
            conn.executemany(
                "INSERT INTO acknowledgements (finding_id, note, expires_at, "
                "acknowledged_at, actor) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            conn.commit()
            conn.close()
            live = store.acknowledgements(BASE)
            self.assertEqual(set(live), {a.id, b.id})
            self.assertEqual(live[a.id].note, "seen")
            later = store.acknowledgements(BASE + timedelta(days=3))
            self.assertEqual(set(later), {a.id})

    def test_there_is_no_write_api_for_acknowledgements(self) -> None:
        names = {n for n in dir(Store) if "ack" in n.lower()}
        self.assertEqual(names, {"acknowledgements"})

    # -- snapshots -------------------------------------------------------

    def test_the_latest_snapshot_round_trips(self) -> None:
        snap = snapshot((finding("a"),))
        with Store.create(self.state) as store:
            self.save(store, snap)
            self.assertEqual(store.latest_snapshot(), snap)
        files = sorted((self.state / "snapshots").iterdir())
        self.assertEqual([f.name for f in files], ["20261030T090000Z-000001.json"])
        self.assertEqual(stat.S_IMODE(os.stat(files[0]).st_mode), 0o600)

    def test_old_snapshots_are_pruned_but_the_newest_always_stays(self) -> None:
        with Store.create(self.state) as store:
            self.save(store, snapshot((), BASE - timedelta(days=40)), retention=30)
            self.save(store, snapshot((), BASE - timedelta(days=36)), retention=30)
            self.save(store, snapshot((), BASE - timedelta(days=5)), retention=30)
            names = sorted(p.name for p in (self.state / "snapshots").iterdir())
            self.assertEqual(names, ["20261025T090000Z-000003.json"])
            self.save(store, snapshot((), BASE + timedelta(days=60)), retention=30)
            names = sorted(p.name for p in (self.state / "snapshots").iterdir())
            self.assertEqual(names, ["20261229T090000Z-000004.json"])

    def test_a_damaged_snapshot_reads_as_none(self) -> None:
        with Store.create(self.state) as store:
            self.save(store, snapshot(()))
            (path,) = (self.state / "snapshots").iterdir()
            path.write_text("{not json")
            self.assertIsNone(store.latest_snapshot())

    def test_unrelated_files_in_the_snapshot_folder_are_left_alone(self) -> None:
        with Store.create(self.state) as store:
            self.save(store, snapshot(()))
            note = self.state / "snapshots" / "notes.txt"
            note.write_text("mine")
            self.save(store, snapshot((), BASE + timedelta(days=90)))
            self.assertTrue(note.exists())


if __name__ == "__main__":
    unittest.main()
