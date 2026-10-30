"""The data contract for AI HC2.

Every adapter, collector, rule, store and surface speaks in these types. They
are plain, frozen dataclasses with no behaviour beyond serialising.

Conventions
-----------
* Times are ISO 8601 strings in UTC with a trailing `Z`, such as
  `2026-10-30T09:00:00Z`. The audit record uses nanosecond strings instead.
* Ids are never built from file paths or clock time (see `stable_id`).
* Missing data is `None`, never a made-up value (R-2).
* `to_dict()` gives plain JSON types with every key sorted, so the same input
  always gives the same bytes (D-1). `from_dict()` reverses it and ignores
  unknown keys, so older readers survive newer writers.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import types
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, StrEnum
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

SCHEMA_VERSION = 2
"""Version of the status and snapshot JSON contract."""

AUDIT_SCHEMA_VERSION = "1"
"""Version of the `audit.jsonl` record, carried as `hc2.schema`."""

ParamValue = str | int | float | bool
"""The only value types allowed in action parameters and event attributes."""

# --------------------------------------------------------------------------
# Stable ids
# --------------------------------------------------------------------------

_ID_HEX_LENGTH = 16
_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")


def _looks_like_path(part: str) -> bool:
    return (
        part.startswith(("/", "~", "./", "../"))
        or "\\" in part
        or "/Users/" in part
        or "/home/" in part
        or bool(_DRIVE_RE.match(part))
    )


def stable_id(kind: str, *parts: str | int) -> str:
    """Return an id built from the meaning of something, such as `finding_9f2c...`.

    The id is `<kind>_` plus the first 16 hex digits of a SHA-256 over the kind
    and the parts. The same meaning always gives the same id, so ids survive
    file moves, restarts and rescans (FR-9, D-1).

    Pass only facts about what the thing *is*: a rule id, a harness id, a
    harness's own session id. Never pass a file path or a time. The function
    refuses parts that look like either, so a slip fails in tests rather than
    leaking a path into an id.

    Raises:
        ValueError: `kind` is not lower snake case, or a part looks like a
            file path or an ISO timestamp.
        TypeError: a part is not a `str` or an `int`.
    """
    if not _KIND_RE.fullmatch(kind):
        raise ValueError(f"kind must be lower snake case, got {kind!r}")
    cleaned: list[str] = []
    for part in parts:
        if isinstance(part, bool) or not isinstance(part, str | int):
            raise TypeError(f"id parts must be str or int, got {type(part).__name__}")
        text = str(part)
        if _looks_like_path(text):
            raise ValueError("id parts must not be file paths")
        if _TIMESTAMP_RE.match(text):
            raise ValueError("id parts must not be timestamps")
        cleaned.append(text)
    # JSON encoding keeps ("ab", "c") and ("a", "bc") apart.
    canonical = json.dumps([kind, *cleaned], ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{kind}_{digest[:_ID_HEX_LENGTH]}"


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class Severity(StrEnum):
    """How much a finding matters (FR-9). Never shown by colour alone (X-2)."""

    RED = "red"
    AMBER = "amber"
    INFO = "info"
    GREEN = "green"

    @property
    def rank(self) -> int:
        """Sort weight: higher is more urgent. Red 3, amber 2, info 1, green 0."""
        return {"red": 3, "amber": 2, "info": 1, "green": 0}[self.value]


class SessionState(StrEnum):
    """What a session is doing now (FR-2). `UNKNOWN` is the honest default."""

    RUNNING_BUSY = "running-busy"
    RUNNING_IDLE = "running-idle"
    WAITING = "waiting"
    STALE = "stale"
    ENDED = "ended"
    UNKNOWN = "unknown"


class Origin(StrEnum):
    """Where a session was started from (FR-2)."""

    CLI = "cli"
    DESKTOP = "desktop"
    IDE = "ide"
    UNKNOWN = "unknown"


class Reliability(StrEnum):
    """How far to trust a field: read directly, worked out, or guessed (FR-2)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class InstallKind(StrEnum):
    """The kind of installed copy of a harness (FR-1, FR-7)."""

    CLI = "cli"
    APP = "app"
    EMBEDDED = "embedded"
    EXTENSION = "extension"


class ProcessRole(StrEnum):
    """What a process in a harness's tree is for (FR-4)."""

    HARNESS = "harness"
    BROWSER = "browser"
    DEV_SERVER = "dev-server"
    TEST_WORKER = "test-worker"
    MCP_SERVER = "mcp-server"
    SHELL = "shell"
    OTHER = "other"
    UNKNOWN = "unknown"


class ActionKind(StrEnum):
    """The v1 action catalogue (FR-10). Nothing outside this list can run."""

    STOP_PROCESS_TREE = "stop_process_tree"
    STOP_PORT_SERVER = "stop_port_server"
    OPEN_PATH = "open_path"
    RESCAN = "rescan"


class Risk(StrEnum):
    """How much harm a proposed action could do if it went wrong (FR-10)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ProposalStatus(StrEnum):
    """Where a proposal is in its life (FR-10)."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class ActionResult(StrEnum):
    """How an action run ended (FR-10)."""

    OK = "ok"
    FAILED = "failed"
    REFUSED = "refused"
    UNVERIFIED = "unverified"


class ActorType(StrEnum):
    """Who did something (FR-11)."""

    SYSTEM = "system"
    HUMAN = "human"
    LLM = "llm"


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------


class Pairs(tuple[tuple[str, ParamValue], ...]):
    """An immutable, key-sorted mapping stored as a tuple of `(key, value)` pairs.

    Frozen dataclasses cannot safely hold a `dict`, so action parameters and
    event attributes use this. It serialises as a JSON object.
    """

    __slots__ = ()

    @classmethod
    def of(cls, mapping: Mapping[str, ParamValue]) -> Pairs:
        """Build from a mapping, sorting by key."""
        return cls(sorted(mapping.items(), key=lambda pair: pair[0]))

    def as_dict(self) -> dict[str, ParamValue]:
        """A plain dict copy."""
        return dict(self)


def _encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Pairs):
        return dict(sorted(value, key=lambda pair: pair[0]))
    if is_dataclass(value) and not isinstance(value, type):
        names = sorted(field.name for field in fields(value))
        return {name: _encode(getattr(value, name)) for name in names}
    if isinstance(value, tuple | list):
        return [_encode(item) for item in value]
    return value


def _decode(tp: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = get_origin(tp)
    if origin is Union or origin is types.UnionType:
        wrapped = [arg for arg in get_args(tp) if arg is not type(None)]
        return _decode(wrapped[0], value)
    if origin is tuple:
        return tuple(_decode(get_args(tp)[0], item) for item in value)
    if isinstance(tp, type):
        if issubclass(tp, Pairs):
            return tp.of(value)
        if issubclass(tp, Enum):
            return tp(value)
        if is_dataclass(tp):
            return _build(tp, value)
        if tp is float:
            return float(value)
    return value


@functools.cache
def _hints(cls: type) -> dict[str, Any]:
    return get_type_hints(cls)


def _build(cls: Any, data: Mapping[str, Any]) -> Any:
    hints = _hints(cls)
    kwargs = {
        field.name: _decode(hints[field.name], data[field.name])
        for field in fields(cls)
        if field.name in data
    }
    return cls(**kwargs)


M = TypeVar("M", bound="Model")


class Model:
    """Base for every contract type: deterministic JSON in and out."""

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON types, every key sorted, enums as their values."""
        result: dict[str, Any] = _encode(self)
        return result

    def to_json(self) -> str:
        """Compact JSON with sorted keys. The same object always gives the same text."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    @classmethod
    def from_dict(cls: type[M], data: Mapping[str, Any]) -> M:
        """Rebuild from `to_dict()` output. Unknown keys are ignored.

        Raises:
            TypeError: a required field is missing.
            ValueError: an enum value is not recognised.
        """
        built: M = _build(cls, data)
        return built


# --------------------------------------------------------------------------
# Who
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Actor(Model):
    """The system, a person, or a named LLM client and its model (FR-11, FR-13).

    Every note, proposal and event carries one, so no opinion goes unattributed.
    """

    type: ActorType
    name: str
    model: str | None = None


# --------------------------------------------------------------------------
# What is installed (FR-1)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Install(Model):
    """One installed copy of a harness, such as a CLI or an embedded runtime.

    `id` is `stable_id("install", harness_id, kind, version or "")`. Locations
    are for display and may use `~`; they are redacted before any surface sees
    them (P-3).
    """

    id: str
    harness_id: str
    kind: InstallKind
    version: str | None = None
    version_source: str | None = None
    location: str | None = None


@dataclass(frozen=True)
class Harness(Model):
    """A tool that runs an AI agent or chat, and what HC2 knows about its setup.

    `id` is a short slug the adapter owns, such as `claude-code-cli`. It is
    never a path. `installs` is empty when the harness is not installed.
    `installed` is `None` when HC2 could not tell, for example after an adapter
    failed or timed out (R-1).
    """

    id: str
    name: str
    installed: bool | None
    installs: tuple[Install, ...] = ()
    config_location: str | None = None
    docs_url: str | None = None
    changelog_url: str | None = None
    llms_txt_url: str | None = None


# --------------------------------------------------------------------------
# Sessions (FR-2)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSource(Model):
    """Where one session field came from, and how far to trust it (FR-2)."""

    field: str
    source: str
    reliability: Reliability


@dataclass(frozen=True)
class Session(Model):
    """One conversation or task in a harness. Metadata only, never content (P-1).

    `id` is the harness's own session id, never a file path. `title` and
    `folder` arrive already masked when `confidential` is true: the redactor
    replaces them with labels such as "Confidential A" (P-2).
    """

    id: str
    harness_id: str
    title: str | None = None
    folder: str | None = None
    model: str | None = None
    created: str | None = None
    last_activity: str | None = None
    state: SessionState = SessionState.UNKNOWN
    origin: Origin = Origin.UNKNOWN
    confidential: bool = False
    field_sources: tuple[FieldSource, ...] = ()


# --------------------------------------------------------------------------
# Resources (FR-4)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessNode(Model):
    """One process in a harness's process tree.

    The tree is flat: follow `parent_pid` to rebuild it. Before an executor
    stops a process it must re-check that `pid`, `start_time` and `fingerprint`
    all still match (S-2). The fingerprint is a hash of the executable and the
    shape of its arguments, never the arguments themselves, which can hold
    secrets (S-3). `harness_id` and `session_id` are links, set only when known.
    """

    pid: int
    name: str
    start_time: str | None = None
    fingerprint: str | None = None
    parent_pid: int | None = None
    role: ProcessRole = ProcessRole.UNKNOWN
    harness_id: str | None = None
    session_id: str | None = None
    cpu_percent: float | None = None
    memory_bytes: int | None = None
    gpu_time_ms: int | None = None
    threads: int | None = None
    age_seconds: int | None = None
    listening_ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class SystemSample(Model):
    """One reading of system pressure: memory, swap, load and heat (FR-4)."""

    sampled_at: str | None = None
    memory_total_bytes: int | None = None
    memory_used_bytes: int | None = None
    swap_used_bytes: int | None = None
    load_1m: float | None = None
    load_5m: float | None = None
    load_15m: float | None = None
    thermal_state: str | None = None


# --------------------------------------------------------------------------
# Findings (FR-9)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding(Model):
    """Something worth knowing or fixing: a severity, a reason and a fix.

    `id` is `stable_id("finding", rule_id, harness_id or "", subject)` where
    `subject` names what the finding is about by meaning, such as a rule key,
    not by path. That keeps it stable across file moves. A finding can be
    acknowledged with a note and an optional expiry; rules never set those.
    """

    id: str
    rule_id: str
    severity: Severity
    title: str
    reason: str
    fix: str
    location: str | None = None
    harness_id: str | None = None
    session_id: str | None = None
    acknowledged: bool = False
    ack_note: str | None = None
    ack_until: str | None = None


# --------------------------------------------------------------------------
# Proposals and actions (FR-10)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Proposal(Model):
    """A suggested action from a rule, an LLM or a person. Nothing runs unseen.

    `id` is `stable_id("proposal", kind, params_json, proposer_name)`, so the
    same proposer suggesting the same thing twice gives the same id. `preview`
    says exactly what will happen, in plain English. Only a person can move
    `status` to approved or rejected (A-2); `decided_by` records who.

    `preview_hash` is the SHA-256 of the canonical action, parameters and
    preview, which a passkey assertion signs (A-4). `expires_at` is when the
    proposal lapses. `risk` and `reversible` help the person decide. All four
    are `None` until the proposer or the action catalogue sets them.
    """

    id: str
    kind: ActionKind
    params: Pairs
    reason: str
    preview: str
    proposed_by: Actor
    status: ProposalStatus = ProposalStatus.PENDING
    finding_id: str | None = None
    created: str | None = None
    decided_by: Actor | None = None
    decided_at: str | None = None
    trace_id: str | None = None
    preview_hash: str | None = None
    expires_at: str | None = None
    risk: Risk | None = None
    reversible: bool | None = None


@dataclass(frozen=True)
class Action(Model):
    """The record of one catalogued operation being run for an approved proposal.

    `result` stays `None` until the executor has run and verified the action.
    `UNVERIFIED` means it ran but the check that it worked did not pass.
    `detail` is a plain-English summary of the outcome.
    """

    id: str
    proposal_id: str
    kind: ActionKind
    params: Pairs
    result: ActionResult | None = None
    detail: str | None = None
    executed_at: str | None = None
    verified: bool | None = None
    trace_id: str | None = None


# --------------------------------------------------------------------------
# Snapshot (FR-1, FR-2, FR-9)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HarnessReport(Model):
    """What one adapter found in one scan, after redaction (P-3).

    It has the same shape as `AdapterReport`, which lives in `hc2.adapters`.
    A `Snapshot` holds these, never the raw adapter reports.
    """

    harness: Harness
    sessions: tuple[Session, ...] = ()
    problems: tuple[str, ...] = ()
    fields_read: tuple[str, ...] = ()


@dataclass(frozen=True)
class Snapshot(Model):
    """Everything one scan found, redacted once and ready for every surface.

    `scan_id` is `stable_id("scan", content_hash)`: it comes from the content,
    never the clock, so identical scans share an id (D-1). Harness reports are
    sorted by harness id and findings by severity then id. `system` and
    `processes` stay empty until a resource collector fills them (FR-4).
    """

    schema: int
    generated: str
    scan_id: str
    harnesses: tuple[HarnessReport, ...] = ()
    findings: tuple[Finding, ...] = ()
    system: SystemSample | None = None
    processes: tuple[ProcessNode, ...] = ()


# --------------------------------------------------------------------------
# Notes and events (FR-11, FR-13)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Note(Model):
    """One attributed comment in the thread on a finding or proposal (FR-13).

    `target_kind` is `"finding"` or `"proposal"`. Notes are opinions. HC2 never
    turns one into a fact (D-3).
    """

    id: str
    target_kind: str
    target_id: str
    author: Actor
    body: str
    created: str | None = None


@dataclass(frozen=True)
class Event(Model):
    """One line in the audit trail, shaped like an OpenTelemetry LogRecord (O-1).

    `time_unix_nano` is a string of digits, as OTLP JSON requires for 64-bit
    integers. `trace_id` is 32 hex digits and `span_id` is 16, or both empty.
    `body` is a plain-English sentence written by HC2, never by a model.
    `event_name` is namespaced, such as `hc2.action.executed`.
    """

    time_unix_nano: str
    event_name: str
    body: str
    actor: Actor
    severity_text: str = "INFO"
    trace_id: str = ""
    span_id: str = ""
    attributes: Pairs = Pairs()

    def __post_init__(self) -> None:
        if not self.time_unix_nano.isdigit():
            raise ValueError("time_unix_nano must be a string of digits")
        if self.trace_id and not re.fullmatch(r"[0-9a-f]{32}", self.trace_id):
            raise ValueError("trace_id must be 32 lower-case hex digits")
        if self.span_id and not re.fullmatch(r"[0-9a-f]{16}", self.span_id):
            raise ValueError("span_id must be 16 lower-case hex digits")

    def to_log_record(self) -> dict[str, Any]:
        """The `audit.jsonl` line for this event, with sorted keys.

        The actor and schema version join the attributes under `hc2.*`.
        """
        attributes: dict[str, ParamValue] = self.attributes.as_dict()
        attributes["hc2.schema"] = AUDIT_SCHEMA_VERSION
        attributes["hc2.actor.type"] = self.actor.type.value
        attributes["hc2.actor.name"] = self.actor.name
        if self.actor.model is not None:
            attributes["hc2.actor.model"] = self.actor.model
        return {
            "attributes": dict(sorted(attributes.items())),
            "body": self.body,
            "eventName": self.event_name,
            "severityText": self.severity_text,
            "spanId": self.span_id,
            "timeUnixNano": self.time_unix_nano,
            "traceId": self.trace_id,
        }
