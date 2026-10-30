"""The `/status` summary of a stored scan (api.md, schema 2).

`build_status()` reads only redacted data: the latest snapshot and the history
in the store. Fields that later slices fill (`scan_error`, `next_scan_at`,
`approvals`) are `null` or empty today, and `pressure` stays `null` until a
resource collector supplies a `SystemSample`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from hc2.audit import canonical_json
from hc2.model import SCHEMA_VERSION, Finding, Severity, SessionState, Snapshot
from hc2.rules.resources import RULE_MEMORY_PRESSURE
from hc2.store import Acknowledgement, FindingRecord, ScanRecord, Store
from hc2.text import truncate

TOP_LIMIT = 10
CHANGE_LIMIT = 4
TEXT_LIMIT = 200

_RUNNING = frozenset(
    {SessionState.RUNNING_BUSY, SessionState.RUNNING_IDLE, SessionState.WAITING}
)
_TIME_KEYS = ("generated", "scan_id", "scan_seconds", "next_scan_at", "content_hash")


def status_content_hash(payload: Mapping[str, Any]) -> str:
    """Hash a status payload with every time left out, so equal means unchanged."""
    cleaned = {key: value for key, value in payload.items() if key not in _TIME_KEYS}
    changes = dict(cleaned.get("changes") or {})
    changes.pop("since", None)
    cleaned["changes"] = changes
    return hashlib.sha256(canonical_json(cleaned).encode("utf-8")).hexdigest()


def _short(item: Finding | FindingRecord) -> dict[str, Any]:
    ident = item.id if isinstance(item, Finding) else item.finding_id
    return {
        "id": ident,
        "sev": item.severity.value,
        "title": truncate(item.title, TEXT_LIMIT),
    }


def _ranked(items: Iterable[Finding]) -> list[Finding]:
    return sorted(items, key=lambda item: (-item.severity.rank, item.id))


def _level(live: list[Finding]) -> str:
    severities = {item.severity for item in live}
    if Severity.RED in severities:
        return "red"
    if Severity.AMBER in severities:
        return "amber"
    return "green"


def _pressure(snapshot: Snapshot) -> dict[str, Any] | None:
    sample = snapshot.system
    if sample is None:
        return None
    used = None
    if sample.memory_used_bytes is not None and sample.memory_total_bytes:
        used = round(100 * sample.memory_used_bytes / sample.memory_total_bytes, 1)
    swap = None
    if sample.swap_used_bytes is not None:
        swap = round(sample.swap_used_bytes / 1024**3, 2)
    pressure = [f for f in snapshot.findings if f.rule_id == RULE_MEMORY_PRESSURE]
    level = max((f.severity for f in pressure), key=lambda s: s.rank, default=None)
    return {
        "level": level.value if level is not None else "green",
        "load1": sample.load_1m,
        "mem_used_pct": used,
        "swap_gb": swap,
    }


def build_status(
    snapshot: Snapshot,
    record: ScanRecord,
    *,
    previous: ScanRecord | None,
    fixed: Iterable[FindingRecord],
    acknowledgements: Mapping[str, Acknowledgement],
) -> dict[str, Any]:
    """Build the `/status` payload for a stored scan."""
    acknowledged = [i for i in snapshot.findings if i.id in acknowledgements]
    live = [i for i in snapshot.findings if i.id not in acknowledgements]
    counts = {
        "acknowledged": len(acknowledged),
        "amber": sum(1 for i in live if i.severity is Severity.AMBER),
        "info": sum(1 for i in live if i.severity is Severity.INFO),
        "red": sum(1 for i in live if i.severity is Severity.RED),
    }
    top: list[dict[str, Any]] = []
    for item in _ranked(live):
        if item.severity is Severity.GREEN or len(top) == TOP_LIMIT:
            continue
        top.append(
            {
                "fix": truncate(item.fix, TEXT_LIMIT),
                "harness": item.harness_id,
                "id": item.id,
                "sev": item.severity.value,
                "title": truncate(item.title, TEXT_LIMIT),
                "web_path": f"/findings/{item.id}",
            }
        )
    new_ids = set(record.new_ids)
    new = _ranked(i for i in snapshot.findings if i.id in new_ids)
    gone = sorted(fixed, key=lambda i: (-i.severity.rank, i.finding_id))
    harnesses = [
        {
            "id": report.harness.id,
            "name": report.harness.name,
            "sessions_running": sum(1 for s in report.sessions if s.state in _RUNNING),
            "sessions_stale": sum(
                1 for s in report.sessions if s.state is SessionState.STALE
            ),
            "state": _harness_state(report.harness.installed),
        }
        for report in snapshot.harnesses
    ]
    payload: dict[str, Any] = {
        "approvals": {"oldest_at": None, "pending_count": 0, "top": []},
        "changes": {
            "fixed": [_short(i) for i in gone[:CHANGE_LIMIT]],
            "fixed_count": len(gone),
            "new": [_short(i) for i in new[:CHANGE_LIMIT]],
            "new_count": len(new),
            "since": previous.generated if previous else None,
        },
        "content_hash": "",
        "counts": counts,
        "generated": snapshot.generated,
        "harnesses": harnesses,
        "level": _level(live),
        "next_scan_at": None,
        "pressure": _pressure(snapshot),
        "scan_error": None,
        "scan_id": snapshot.scan_id,
        "scan_seconds": record.scan_seconds,
        "scan_state": "ok",
        "schema": SCHEMA_VERSION,
        "top": top,
    }
    payload["content_hash"] = status_content_hash(payload)
    return payload


def _harness_state(installed: bool | None) -> str:
    if installed is None:
        return "unknown"
    return "installed" if installed else "not_installed"


def status_from_store(
    store: Store, now: datetime
) -> tuple[Snapshot, dict[str, Any]] | None:
    """The latest snapshot and its status payload, or `None` if there is no scan."""
    record = store.last_scan()
    snapshot = store.latest_snapshot()
    if record is None or snapshot is None or snapshot.scan_id != record.scan_id:
        return None
    payload = build_status(
        snapshot,
        record,
        previous=store.previous_scan(),
        fixed=store.finding_records(record.fixed_ids).values(),
        acknowledgements=store.acknowledgements(now),
    )
    return snapshot, payload
