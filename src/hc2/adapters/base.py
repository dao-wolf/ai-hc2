"""How HC2 talks to one harness.

Each harness gets one module in this package with one class that satisfies
`Adapter`, listed in `hc2.adapters.ALL_ADAPTERS`. The scan runs every adapter
in its own thread with a timeout and catches everything it raises, so a broken
adapter only turns its own harness "unknown" (R-1).

Adapters return raw facts, including real paths. Redaction happens once, in
the core, when the snapshot is built (P-3). Adapters never read conversation
text: they read only the metadata fields they list in `fields_read` (P-1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from hc2.model import Harness, Model, Session


@dataclass(frozen=True)
class AdapterContext:
    """What every adapter gets for one scan.

    `home` is the user's home folder; tests point it at a made-up home.
    `confidential_folders` are absolute paths; a session whose folder is one of
    them, or inside one, must come back with `confidential=True`.
    `network` is true only for opt-in latest-version and docs checks (S-1).
    """

    home: str
    confidential_folders: tuple[str, ...] = ()
    network: bool = False


@dataclass(frozen=True)
class ProcessSignature(Model):
    """How the resource collector recognises this harness's processes (FR-4).

    `executable_names` are process basenames, such as `claude`.
    `path_markers` are fragments of an executable's path that identify the
    harness, such as `/Claude.app/`. Both are matched exactly, never as patterns.
    """

    harness_id: str
    executable_names: tuple[str, ...] = ()
    path_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterReport(Model):
    """Everything one adapter found in one scan.

    `problems` are plain-English sentences with no paths, such as
    "Session index format not recognised (version 3)". They become findings.
    `fields_read` names every metadata field the adapter read, such as
    `projects/*.jsonl: sessionId, cwd, timestamp, message.model` (P-1).
    """

    harness: Harness
    sessions: tuple[Session, ...] = ()
    problems: tuple[str, ...] = ()
    fields_read: tuple[str, ...] = ()


@runtime_checkable
class Adapter(Protocol):
    """One harness, read-only.

    An adapter never writes, never runs a harness, and calls the network only
    when `ctx.network` is true.
    """

    id: str
    name: str

    def scan(self, ctx: AdapterContext) -> AdapterReport:
        """Detect the harness, its installs and its sessions."""
        ...

    def process_signature(self) -> ProcessSignature:
        """How to recognise this harness's processes."""
        ...
