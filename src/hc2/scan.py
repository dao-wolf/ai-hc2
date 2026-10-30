"""The scan: adapters in, one redacted snapshot out (design flow 1).

`build_snapshot()` does the work and writes nothing. `run_scan()` wraps it: it
diffs against the previous scan, stores the result and writes audit events.

Steps:

1. Run every enabled adapter in its own thread, all at once, each with the
   same timeout (R-1). An adapter that raises, hangs or returns rubbish becomes
   a report with `installed` unknown and one plain-English problem. No path and
   no exception text is ever copied in, because either could hold a path.
2. Redact everything once (P-3), mark idle sessions stale, and turn adapter
   problems, config problems and a changed config into findings.
3. Sort everything, hash the content and derive the scan id from the hash, so
   the same inputs give the same bytes (D-1).

Resource data comes in through a `Collector`, a function that gets the
adapters' process signatures and returns `Resources`. Without one, `system` is
`None` and `processes` is empty.

Once both the adapters and the collector have finished, the scan links each
session that has a `pid` to its process tree: it sets `session_id` on the
session's root process and everything below it, then runs the session rules
(`Resources.session_rules`) over those sessions. The collector runs before the
sessions are known, so it cannot do this itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Generic, TypeVar

import hc2.adapters as adapter_registry
from hc2.adapters.base import Adapter, AdapterContext, AdapterReport, ProcessSignature
from hc2.audit import AuditLog, ChainBreak, canonical_json
from hc2.config import Config
from hc2.model import (
    SCHEMA_VERSION,
    Actor,
    ActorType,
    Event,
    FieldSource,
    Finding,
    Harness,
    HarnessReport,
    Pairs,
    ParamValue,
    ProcessNode,
    Reliability,
    Session,
    SessionState,
    Severity,
    Snapshot,
    SystemSample,
    stable_id,
)
from hc2.collect.processes import ProcessIndex
from hc2.redact import Redactor, normalise_folder
from hc2.rules.resources import SessionActivity
from hc2.store import FindingRecord, ScanRecord, Store
from hc2.text import plural

T = TypeVar("T")

SYSTEM_ACTOR = Actor(ActorType.SYSTEM, "hc2")

# States in which a session is known to be open, so idle time can make it stale.
# UNKNOWN is left out: a harness that cannot tell whether a session is running
# (Cowork, for one) would otherwise have every old session called stale.
_STALE_CANDIDATES = frozenset({SessionState.RUNNING_IDLE, SessionState.WAITING})


SessionRules = Callable[
    [Sequence[ProcessNode], Sequence[SessionActivity]], tuple[Finding, ...]
]
"""Runs the session rules over raw process nodes and the live sessions.

The collector builds one with its thresholds and its "under pressure" reading,
and the scan calls it once the sessions are known.
"""


@dataclass(frozen=True)
class Resources:
    """What a resource collector returns (FR-4).

    `session_rules` is optional. When set, the scan calls it with the raw
    process nodes and a `SessionActivity` for each session that has a `pid`,
    and adds the findings it returns. The collector's own `findings` must not
    include what these rules would find, or they would be counted twice.
    """

    system: SystemSample | None = None
    processes: tuple[ProcessNode, ...] = ()
    findings: tuple[Finding, ...] = ()
    session_rules: SessionRules | None = None


Collector = Callable[[Sequence[ProcessSignature]], Resources]
"""A function from the adapters' process signatures to raw resource data.

Pass one to `run_scan(collector=...)`. It runs in a thread with the same
timeout as the adapters, and its output is redacted like everything else.
"""

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    """The current time, in UTC."""
    return datetime.now(UTC)


def iso(moment: datetime) -> str:
    """A time as `2026-10-30T09:00:00Z`."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Running work with a timeout
# --------------------------------------------------------------------------

OK = "ok"
TIMEOUT = "timeout"
ERROR = "error"
BAD_DATA = "bad-data"


class _Job(Generic[T]):
    """A call running in a daemon thread, so a hang never blocks exit."""

    def __init__(self, call: Callable[[], T]) -> None:
        self._result: list[T] = []
        self._thread = threading.Thread(target=self._run, args=(call,), daemon=True)
        self._thread.start()

    def _run(self, call: Callable[[], T]) -> None:
        # Whatever goes wrong, the caller reports it without the error's text.
        with contextlib.suppress(BaseException):
            self._result.append(call())

    def wait(self, deadline: float) -> tuple[str, T | None]:
        """Wait until `deadline` (a `time.monotonic()` value) for the result."""
        self._thread.join(max(0.0, deadline - time.monotonic()))
        if self._thread.is_alive():
            return TIMEOUT, None
        if not self._result:
            return ERROR, None
        return OK, self._result[0]


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def make_finding(
    rule_id: str,
    severity: Severity,
    subject: str,
    title: str,
    reason: str,
    fix: str,
    harness_id: str | None = None,
) -> Finding:
    """Build a finding with a meaning-based id (FR-9)."""
    return Finding(
        id=stable_id("finding", rule_id, harness_id or "", subject),
        rule_id=rule_id,
        severity=severity,
        title=title,
        reason=reason,
        fix=fix,
        harness_id=harness_id,
    )


_FIX_TIMEOUT = (
    "Run the scan again. If it keeps happening, check that the tool is not stuck "
    "or very slow, or raise adapter_timeout_seconds in the config file."
)
_FIX_ERROR = (
    "Run the scan again. If it keeps happening, update HC2 or report the problem "
    "so the adapter can be fixed."
)
_FIX_PROBLEM = (
    "Update HC2 to the latest version. If the problem stays, report it so the "
    "adapter can be updated."
)


def _adapter_findings(
    report: HarnessReport, failure: str | None
) -> list[Finding]:
    harness = report.harness
    findings: list[Finding] = []
    for problem in report.problems:
        if failure is not None:
            findings.append(
                make_finding(
                    "adapter.unavailable",
                    Severity.AMBER,
                    failure,
                    f"{harness.name} could not be checked",
                    problem,
                    _FIX_TIMEOUT if failure == TIMEOUT else _FIX_ERROR,
                    harness.id,
                )
            )
        else:
            findings.append(
                make_finding(
                    "adapter.problem",
                    Severity.AMBER,
                    _digest(problem),
                    f"{harness.name}: {problem}".rstrip("."),
                    problem,
                    _FIX_PROBLEM,
                    harness.id,
                )
            )
    return findings


def _config_findings(config: Config, changed: bool) -> list[Finding]:
    findings = [
        make_finding(
            "config.invalid",
            Severity.AMBER,
            _digest(warning),
            "A setting in the HC2 config is not valid",
            warning,
            "Open the config file and correct the setting. "
            "examples/config.toml shows the expected layout.",
        )
        for warning in config.warnings
    ]
    if changed:
        findings.append(
            make_finding(
                "config.changed",
                Severity.AMBER,
                "fingerprint",
                "The HC2 config has changed since the last scan",
                "Settings such as confidential folders, rule switches or "
                "thresholds were edited, in HC2 or outside it.",
                "If you made this change, no action is needed. If you did not, "
                "check the config file and who or what edited it.",
            )
        )
    return findings


def _audit_findings(broken: ChainBreak | None) -> list[Finding]:
    if broken is None:
        return []
    return [
        make_finding(
            "audit.chain_broken",
            Severity.RED,
            "chain",
            "HC2's audit history has been changed or damaged",
            f"Audit file {broken.file}, line {broken.line}: {broken.reason}",
            "Look at that file for edits or deletions. Keep a copy of the audit "
            "folder before you change anything.",
        )
    ]


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def _with_state(session: Session, now: datetime, stale_hours: float) -> Session:
    """Mark a session stale when it has been idle longer than the limit (FR-3)."""
    if session.state not in _STALE_CANDIDATES:
        return session
    last = _parse_time(session.last_activity)
    if last is None or (now - last).total_seconds() <= stale_hours * 3600:
        return session
    sources = tuple(item for item in session.field_sources if item.field != "state")
    sources += (FieldSource("state", "hc2 idle-time rule", Reliability.MEDIUM),)
    return replace(session, state=SessionState.STALE, field_sources=sources)


def session_activities(
    sessions: Sequence[Session], now: datetime
) -> list[SessionActivity]:
    """The session rules' view of each session that has a process id (FR-3).

    `state_age_seconds` is `now` minus `state_since`, or minus `last_activity`
    when the harness gives no status time, or `None` when there is neither.
    Sessions without a `pid` are left out: nothing links them to a process.
    """
    found: list[SessionActivity] = []
    for session in sessions:
        if session.pid is None:
            continue
        since = _parse_time(session.state_since) or _parse_time(session.last_activity)
        age = None if since is None else max(0, int((now - since).total_seconds()))
        found.append(
            SessionActivity(
                session_id=session.id,
                harness_id=session.harness_id,
                state=session.state,
                state_age_seconds=age,
                root_pid=session.pid,
            )
        )
    return found


def link_processes(
    nodes: Sequence[ProcessNode], activities: Sequence[SessionActivity]
) -> dict[int, str]:
    """Map each process id to the session whose tree it is in.

    A session's tree is its root process and every descendant. If a process is
    in the trees of two sessions, the lowest session id wins, so the answer does
    not depend on the order the adapters ran in (D-1).
    """
    index = ProcessIndex(nodes)
    linked: dict[int, str] = {}
    for activity in sorted(activities, key=lambda a: (a.session_id, a.harness_id)):
        if activity.root_pid is None:
            continue
        for node in index.subtree(activity.root_pid):
            linked.setdefault(node.pid, activity.session_id)
    return linked


def _sorted_sessions(sessions: Sequence[Session]) -> tuple[Session, ...]:
    """Newest activity first, then by id. Sessions without a time go last."""
    by_id = sorted(sessions, key=lambda item: item.id)
    return tuple(sorted(by_id, key=lambda item: item.last_activity or "", reverse=True))


# --------------------------------------------------------------------------
# Building the snapshot
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Built:
    """A finished snapshot, and the hash of its content with times left out."""

    snapshot: Snapshot
    content_hash: str


def content_hash(snapshot: Snapshot) -> str:
    """Hash everything in a snapshot except `generated` and `scan_id`."""
    payload = {
        key: value
        for key, value in snapshot.to_dict().items()
        if key not in ("generated", "scan_id")
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _failed_report(
    adapter: Adapter, redactor: Redactor, kind: str, seconds: float
) -> HarnessReport:
    """The report for an adapter that failed. Its text is written here, not copied."""
    name = redactor.words(str(getattr(adapter, "name", "") or adapter.id))
    if kind == TIMEOUT:
        why = f"it took longer than {seconds:g} seconds"
    elif kind == BAD_DATA:
        why = "it returned data HC2 cannot use"
    else:
        why = "of an unexpected error"
    harness = Harness(id=redactor.ident(str(adapter.id)), name=name, installed=None)
    problem = f"{name} could not be checked because {why}."
    return HarnessReport(harness=harness, problems=(problem,))


def _adapter_job(adapter: Adapter, context: AdapterContext) -> _Job[AdapterReport]:
    return _Job(lambda: adapter.scan(context))


def _collector_job(
    collector: Collector, signatures: Sequence[ProcessSignature]
) -> _Job[Resources]:
    return _Job(lambda: collector(signatures))


def _signatures(adapters: Sequence[Adapter]) -> tuple[ProcessSignature, ...]:
    found: list[ProcessSignature] = []
    for adapter in adapters:
        try:
            found.append(adapter.process_signature())
        except Exception:  # an adapter that cannot say is just left out
            continue
    return tuple(found)


def _linked(node: ProcessNode, linked: dict[int, str]) -> ProcessNode:
    session_id = linked.get(node.pid, node.session_id)
    if session_id == node.session_id:
        return node
    return replace(node, session_id=session_id)


def _session_findings(
    outcome: Resources, activities: Sequence[SessionActivity], redactor: Redactor
) -> list[Finding]:
    """Findings from the session rules, redacted. A failing rule is a finding."""
    if outcome.session_rules is None or not activities:
        return []
    try:
        found = outcome.session_rules(outcome.processes, activities)
    except Exception:  # a rule bug must not stop the scan; no text is copied
        return [
            make_finding(
                "collector.unavailable",
                Severity.AMBER,
                "session-rules",
                "Session resource checks could not run",
                "The check that matches sessions to their processes failed "
                "unexpectedly.",
                _FIX_ERROR,
            )
        ]
    return [redactor.finding(item) for item in found]


def _clean_report(
    redactor: Redactor, raw: AdapterReport, now: datetime, stale_hours: float
) -> tuple[HarnessReport, tuple[Session, ...]]:
    """The redacted report, and its sessions as the harness reported them.

    The second item keeps each state from before `_with_state`, because a
    session marked stale for its idle time still holds its processes, and the
    session rules need to see that it is idle.
    """
    report = redactor.report(raw)
    sessions = tuple(_with_state(item, now, stale_hours) for item in report.sessions)
    return replace(report, sessions=_sorted_sessions(sessions)), report.sessions


def build_snapshot(
    config: Config,
    *,
    home: str,
    adapters: Sequence[Adapter] | None = None,
    collector: Collector | None = None,
    now: datetime | None = None,
    previous_fingerprint: str | None = None,
    audit_break: ChainBreak | None = None,
) -> Built:
    """Run the adapters and build the redacted snapshot. Writes nothing.

    `adapters` defaults to `hc2.adapters.ALL_ADAPTERS`, read at call time.
    `previous_fingerprint` is the config fingerprint of the last scan, if any;
    when it differs from `config.fingerprint` a "config changed" finding is added.
    """
    moment = now or utc_now()
    pool = adapter_registry.ALL_ADAPTERS if adapters is None else tuple(adapters)
    redactor = Redactor(
        home,
        config.confidential_folders,
        hide_titles=config.redact_all_titles,
        terms=config.confidential_terms,
    )
    folders = dict.fromkeys(
        normalise_folder(item, home) for item in config.confidential_folders
    )
    context = AdapterContext(
        home=home, confidential_folders=tuple(folders), network=False
    )
    chosen = sorted(
        (item for item in pool if config.adapter_enabled(item.id)),
        key=lambda item: item.id,
    )
    deadline = time.monotonic() + config.adapter_timeout_seconds
    jobs = [(item, _adapter_job(item, context)) for item in chosen]
    resource_job = (
        _collector_job(collector, _signatures(chosen)) if collector else None
    )

    reports: list[HarnessReport] = []
    reported: list[Session] = []
    failures: dict[str, str] = {}
    for adapter, job in jobs:
        status, result = job.wait(deadline)
        if status == OK and not isinstance(result, AdapterReport):
            status = BAD_DATA
        if isinstance(result, AdapterReport) and status == OK:
            clean, original = _clean_report(
                redactor, result, moment, config.stale_hours
            )
            reports.append(clean)
            reported.extend(original)
            continue
        failed = _failed_report(
            adapter, redactor, status, config.adapter_timeout_seconds
        )
        failures[failed.harness.id] = TIMEOUT if status == TIMEOUT else ERROR
        reports.append(failed)
    reports.sort(key=lambda item: item.harness.id)

    system: SystemSample | None = None
    processes: tuple[ProcessNode, ...] = ()
    findings: list[Finding] = []
    if resource_job is not None:
        status, outcome = resource_job.wait(deadline)
        if status == OK and isinstance(outcome, Resources):
            system = outcome.system
            activities = session_activities(reported, moment)
            linked = link_processes(outcome.processes, activities)
            nodes = (
                redactor.process(_linked(node, linked)) for node in outcome.processes
            )
            processes = tuple(sorted(nodes, key=lambda node: node.pid))
            findings.extend(redactor.finding(item) for item in outcome.findings)
            findings.extend(_session_findings(outcome, activities, redactor))
        else:
            timed_out = status == TIMEOUT
            findings.append(
                make_finding(
                    "collector.unavailable",
                    Severity.AMBER,
                    TIMEOUT if timed_out else ERROR,
                    "Resource data could not be collected",
                    "The resource check "
                    + ("took too long." if timed_out else "failed unexpectedly."),
                    _FIX_TIMEOUT if timed_out else _FIX_ERROR,
                )
            )

    for report in reports:
        findings.extend(_adapter_findings(report, failures.get(report.harness.id)))
    changed = (
        previous_fingerprint is not None and previous_fingerprint != config.fingerprint
    )
    findings.extend(_config_findings(config, changed))
    findings.extend(_audit_findings(audit_break))

    unique = {item.id: redactor.finding(item) for item in findings}
    ordered = tuple(sorted(unique.values(), key=lambda f: (-f.severity.rank, f.id)))
    draft = Snapshot(
        schema=SCHEMA_VERSION,
        generated=iso(moment),
        scan_id="",
        harnesses=tuple(reports),
        findings=ordered,
        system=system,
        processes=processes,
    )
    digest = content_hash(draft)
    return Built(replace(draft, scan_id=stable_id("scan", digest)), digest)


# --------------------------------------------------------------------------
# Running and recording a scan
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """The outcome of `run_scan()`."""

    snapshot: Snapshot
    record: ScanRecord
    new_findings: tuple[Finding, ...]
    fixed_findings: tuple[FindingRecord, ...]
    config_changed: bool


def _nanos(moment: datetime) -> str:
    utc = moment.astimezone(UTC)
    return str(int(utc.timestamp()) * 1_000_000_000 + utc.microsecond * 1000)


def _event(
    name: str,
    body: str,
    moment: datetime,
    trace: str,
    attributes: dict[str, ParamValue],
    severity: str = "INFO",
) -> Event:
    span = _digest(f"{trace}:{name}:{sorted(attributes.items())}")
    return Event(
        time_unix_nano=_nanos(moment),
        event_name=name,
        body=body,
        actor=SYSTEM_ACTOR,
        severity_text=severity,
        trace_id=trace,
        span_id=span,
        attributes=Pairs.of(attributes),
    )


def _sentence(text: str) -> str:
    return text if text.endswith((".", "!", "?")) else text + "."


def _write_audit(
    log: AuditLog,
    result: ScanResult,
    config: Config,
    previous: str | None,
    when: datetime,
) -> None:
    """Append this scan's events. All of them share one trace id."""
    snapshot, record = result.snapshot, result.record
    trace = hashlib.sha256(f"{record.scan_id}:{record.row_id}".encode()).hexdigest()
    trace = trace[:32]
    harnesses = len(snapshot.harnesses)
    sessions = sum(len(item.sessions) for item in snapshot.harnesses)
    total = len(snapshot.findings)
    new, fixed = result.new_findings, result.fixed_findings
    log.append(
        _event(
            "hc2.scan.completed",
            f"Scan finished: checked {plural(harnesses, 'harness', 'harnesses')}, "
            f"found {plural(sessions, 'session')} and {plural(total, 'finding')} "
            f"({len(new)} new, {len(fixed)} fixed).",
            when,
            trace,
            {
                "hc2.scan.id": record.scan_id,
                "hc2.scan.harnesses": harnesses,
                "hc2.scan.sessions": sessions,
                "hc2.scan.findings": total,
                "hc2.scan.new": len(new),
                "hc2.scan.fixed": len(fixed),
            },
        )
    )
    for item in new:
        log.append(
            _event(
                "hc2.finding.new",
                _sentence(f"New {item.severity.value} finding: {item.title}"),
                when,
                trace,
                {
                    "hc2.finding.id": item.id,
                    "hc2.finding.severity": item.severity.value,
                    "hc2.rule.id": item.rule_id,
                    "hc2.harness.id": item.harness_id or "",
                },
                "WARN" if item.severity.rank >= Severity.AMBER.rank else "INFO",
            )
        )
    for old in fixed:
        log.append(
            _event(
                "hc2.finding.resolved",
                _sentence(
                    f"A {old.severity.value} finding is no longer present: {old.title}"
                ),
                when,
                trace,
                {
                    "hc2.finding.id": old.finding_id,
                    "hc2.finding.severity": old.severity.value,
                    "hc2.rule.id": old.rule_id,
                    "hc2.harness.id": old.harness_id or "",
                },
            )
        )
    if result.config_changed:
        log.append(
            _event(
                "hc2.config.changed",
                "The HC2 config file has changed since the last scan.",
                when,
                trace,
                {
                    "hc2.config.fingerprint": config.fingerprint[:16],
                    "hc2.config.previous_fingerprint": (previous or "")[:16],
                },
                "WARN",
            )
        )


def run_scan(
    config: Config,
    *,
    home: str,
    state: Path,
    adapters: Sequence[Adapter] | None = None,
    collector: Collector | None = None,
    clock: Clock | None = None,
) -> ScanResult:
    """Scan, diff against the last scan, store the result and write audit events.

    Raises:
        UserError: the state folder could not be written.
    """
    moment = (clock or utc_now)()
    started = time.monotonic()
    log = AuditLog(state / "audit")
    chain = log.verify_chain()
    with Store.create(state) as store:
        last = store.last_scan()
        previous = last.config_fingerprint if last else None
        built = build_snapshot(
            config,
            home=home,
            adapters=adapters,
            collector=collector,
            now=moment,
            previous_fingerprint=previous,
            audit_break=chain.first_break,
        )
        record = store.record_scan(
            built.snapshot,
            content_hash=built.content_hash,
            config_fingerprint=config.fingerprint,
            scan_seconds=time.monotonic() - started,
            retention_days=config.retention_days,
        )
        wanted = set(record.new_ids)
        new = tuple(item for item in built.snapshot.findings if item.id in wanted)
        known = store.finding_records(record.fixed_ids)
        fixed = tuple(known[key] for key in record.fixed_ids if key in known)
    changed = previous is not None and previous != config.fingerprint
    result = ScanResult(built.snapshot, record, new, fixed, changed)
    _write_audit(log, result, config, previous, moment)
    return result
