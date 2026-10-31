"""Redaction, done once in the core before anything reaches a surface (P-3).

What it does:

* Confidential folders become "Confidential A", "Confidential B" and so on,
  labelled in config order. The labels never change while the config list keeps
  its order, and there is no setting that reveals the real names (P-2).
* A session in a confidential folder, or one the adapter marked confidential,
  loses its title and folder; both become the label.
* A session whose title or folder holds a confidential term as a whole word
  (case-insensitive) is masked the same way. If its folder is not a listed
  confidential folder it gets the one shared label "Confidential (by title)",
  never a label per term, which would reveal which term matched.
* The home folder becomes `~`, and so does any `/Users/<name>` or
  `/home/<name>`.
* Tokens, keys, passwords in `name=value` pairs, emails and URL passwords
  become `[redacted]`.
* Control characters (including terminal escape codes) are removed, so a hostile
  title cannot redraw a terminal (S-4).

Process command lines get their own helper, `summarise_command` (S-3).

Matching of folders is case-insensitive on purpose: macOS paths are, and an
over-match only hides more.
"""

from __future__ import annotations

import functools
import hashlib
import os
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, replace

from hc2.adapters.base import AdapterReport
from hc2.model import (
    FieldSource,
    Finding,
    Harness,
    HarnessReport,
    Install,
    Model,
    ProcessNode,
    Session,
)

REDACTED = "[redacted]"
HIDDEN_TITLE = "Title hidden"
TERM_LABEL = "Confidential (by title)"
"""Label for a session masked only because of a confidential term."""
UNLABELLED = "Confidential"
"""Label for a session an adapter marked confidential in an unlisted folder."""

MAX_FLAGS = 24

# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------


@functools.cache
def _realpath(path: str) -> str:
    """`os.path.realpath`, remembered: it touches the disk, which can be slow."""
    return os.path.realpath(path)


def confidential_label(index: int) -> str:
    """The label for the folder at `index`: A to Z, then AA, AB and so on."""
    if index < 0:
        raise ValueError("index must not be negative")
    letters = ""
    number = index + 1
    while number:
        number, remainder = divmod(number - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return f"Confidential {letters}"


def normalise_folder(raw: str, home: str) -> str:
    """Make a configured folder absolute: expand `~`, tidy `..` and slashes."""
    text = raw.strip()
    if text == "~" or text.startswith(("~/", "~\\")):
        text = home.rstrip("/") + text[1:]
    text = os.path.normpath(text) if text else text
    return text if text == "/" else text.rstrip("/")


# --------------------------------------------------------------------------
# Secret-like strings
# --------------------------------------------------------------------------

_KEY_WORDS = (
    r"api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|"
    r"private[_-]?key|secret|token|passwd|password|pwd|authorization|credentials?"
)

_SECRET_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*"
            r"PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*",
            re.DOTALL,
        ),
        REDACTED,
    ),
    (re.compile(r"(?<=://)[^/\s:@]*:[^/\s@]+@"), f"{REDACTED}@"),
    (
        re.compile(
            r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"
            r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
            r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
            r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
            r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
            r"|\bAIza[0-9A-Za-z_-]{30,}"
            r"|\b(?:npm|hf|glpat|dop_v1)[_-][A-Za-z0-9_-]{20,}"
            r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
        ),
        REDACTED,
    ),
    (
        re.compile(
            r"\b(Bearer)\s+(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{8,}",
            re.IGNORECASE,
        ),
        rf"\1 {REDACTED}",
    ),
    (
        re.compile(
            rf"\b({_KEY_WORDS})([\"']?\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)",
            re.IGNORECASE,
        ),
        rf"\1\2{REDACTED}",
    ),
    (
        re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
        ),
        REDACTED,
    ),
)

_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=-]{32,}")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_GENERIC_HOME_RE = re.compile(r"(?<![\w~.-])/(?:Users|home)/[A-Za-z0-9._-]+")


def _long_token(match: re.Match[str]) -> str:
    """Hide a long mixed-case string with digits. Ids and hashes are left alone."""
    text = match.group(0)
    if _UUID_RE.fullmatch(text) or _HEX_RE.fullmatch(text):
        return text
    mixed = (
        any(ch.isupper() for ch in text)
        and any(ch.islower() for ch in text)
        and any(ch.isdigit() for ch in text)
    )
    return REDACTED if mixed else text


def redact_secrets(text: str) -> str:
    """Replace tokens, keys, passwords and emails with `[redacted]`."""
    for pattern, replacement in _SECRET_RULES:
        text = pattern.sub(replacement, text)
    return _LONG_TOKEN_RE.sub(_long_token, text)


def strip_controls(text: str) -> str:
    """Turn tabs and line breaks into spaces and drop other control characters."""
    text = re.sub(r"[\t\r\n  ]+", " ", text)
    return _CONTROL_RE.sub("", text)


# --------------------------------------------------------------------------
# The redactor
# --------------------------------------------------------------------------


def _folder_regex(variant: str) -> re.Pattern[str]:
    """Match a folder, and any path below it, but not a sibling like `name-2`."""
    return re.compile(
        re.escape(variant)
        + r"(?:[/\\](?:[^\s\"'`<>()\[\]{},;]*[^\s\"'`<>()\[\]{},;.:!?])?)?(?![\w-])",
        re.IGNORECASE,
    )


def _term_patterns(terms: Sequence[str]) -> tuple[re.Pattern[str], ...]:
    """Whole-word, case-insensitive patterns. An underscore counts as a separator."""
    seen: dict[str, re.Pattern[str]] = {}
    for term in terms:
        words = term.split()
        if not words:
            continue
        body = r"\s+".join(re.escape(word) for word in words)
        seen.setdefault(
            " ".join(words).lower(),
            re.compile(rf"(?<![^\W_]){body}(?![^\W_])", re.IGNORECASE),
        )
    return tuple(seen.values())


@dataclass(frozen=True)
class _Folder:
    label: str
    path: str
    bases: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]


class Redactor:
    """Applies every redaction rule. Build one per scan.

    `home` is the home folder the adapters were pointed at. `confidential` is
    the configured folder list in config order; the first folder is
    "Confidential A". Duplicates (after tidying) share a label.
    """

    def __init__(
        self,
        home: str,
        confidential: Sequence[str] = (),
        *,
        hide_titles: bool = False,
        terms: Sequence[str] = (),
    ) -> None:
        self._terms = _term_patterns(terms)
        self._home = home.rstrip("/") if home not in ("", "/") else ""
        self._hide_titles = hide_titles
        self._folders = self._build_folders(confidential)

    def _build_folders(self, confidential: Sequence[str]) -> tuple[_Folder, ...]:
        seen: dict[str, str] = {}
        for raw in confidential:
            path = normalise_folder(raw, self._home)
            if path and path not in seen and path != "/":
                seen[path] = confidential_label(len(seen))
        folders: list[_Folder] = []
        for path, label in seen.items():
            variants = {path, _realpath(path)}
            if self._home and path.startswith(self._home + "/"):
                variants.add("~" + path[len(self._home) :])
            ordered = sorted(variants, key=lambda item: (-len(item), item))
            bases = tuple(sorted({path.lower(), _realpath(path).lower()}))
            patterns = tuple(_folder_regex(item) for item in ordered)
            folders.append(_Folder(label, path, bases, patterns))
        return tuple(folders)

    @property
    def labels(self) -> tuple[str, ...]:
        """The labels in use, in config order."""
        return tuple(folder.label for folder in self._folders)

    def label_for(self, folder: str | None) -> str | None:
        """The label if `folder` is, or is inside, a confidential folder."""
        if not folder:
            return None
        candidate = normalise_folder(folder, self._home).lower()
        best: _Folder | None = None
        for item in self._folders:
            inside = any(
                candidate == base or candidate.startswith(base + "/")
                for base in item.bases
            )
            if inside and (best is None or len(item.path) > len(best.path)):
                best = item
        return best.label if best else None

    def has_term(self, *values: str | None) -> bool:
        """Whether any value holds a confidential term as a whole word."""
        return any(
            pattern.search(value)
            for value in values
            if value
            for pattern in self._terms
        )

    # -- text ------------------------------------------------------------

    def _hide_terms(self, text: str) -> str:
        for pattern in self._terms:
            text = pattern.sub(REDACTED, text)
        return text

    def _hide_paths(self, text: str) -> str:
        for item in sorted(self._folders, key=lambda f: -len(f.path)):
            for pattern in item.patterns:
                text = pattern.sub(item.label, text)
        if self._home:
            for variant in {self._home, _realpath(self._home)}:
                text = re.sub(re.escape(variant) + r"(?![\w-])", "~", text)
        return _GENERIC_HOME_RE.sub("~", text)

    def ident(self, value: str) -> str:
        """Clean an id: hide paths and control characters, but keep it opaque."""
        return self._hide_paths(strip_controls(value))

    def text(self, value: str | None) -> str | None:
        """Fully redact free text. `None` stays `None`."""
        if value is None:
            return None
        hidden = self._hide_terms(self._hide_paths(strip_controls(value)))
        return redact_secrets(hidden)

    def words(self, value: str) -> str:
        """Fully redact text that is never `None`."""
        return self.text(value) or ""

    # -- types -----------------------------------------------------------

    def session(self, session: Session) -> Session:
        """Redact one session. Confidential ones show only the label (P-2)."""
        label = self.label_for(session.folder)
        clean = replace(
            session,
            id=self.ident(session.id),
            harness_id=self.ident(session.harness_id),
            model=self.text(session.model),
            field_sources=tuple(
                FieldSource(
                    self.words(item.field), self.words(item.source), item.reliability
                )
                for item in session.field_sources
            ),
        )
        by_term = self.has_term(session.title, session.folder)
        if session.confidential or label is not None or by_term:
            shown = label or (TERM_LABEL if by_term else UNLABELLED)
            return replace(clean, title=shown, folder=shown, confidential=True)
        title = session.title
        if self._hide_titles and title is not None:
            title = HIDDEN_TITLE
        return replace(clean, title=self.text(title), folder=self.text(session.folder))

    def install(self, install: Install) -> Install:
        """Redact an install's version and location."""
        return replace(
            install,
            version=self.text(install.version),
            version_source=self.text(install.version_source),
            location=self.text(install.location),
        )

    def harness(self, harness: Harness) -> Harness:
        """Redact a harness's locations and URLs."""
        return replace(
            harness,
            name=self.words(harness.name),
            installs=tuple(self.install(item) for item in harness.installs),
            config_location=self.text(harness.config_location),
            docs_url=self.text(harness.docs_url),
            changelog_url=self.text(harness.changelog_url),
            llms_txt_url=self.text(harness.llms_txt_url),
        )

    def finding(self, finding: Finding) -> Finding:
        """Redact a finding's words. Ids are built from meaning and stay as they are."""
        return replace(
            finding,
            title=self.words(finding.title),
            reason=self.words(finding.reason),
            fix=self.words(finding.fix),
            location=self.text(finding.location),
            ack_note=self.text(finding.ack_note),
        )

    def report(self, report: AdapterReport) -> HarnessReport:
        """Redact everything an adapter returned."""
        sessions = tuple(self.session(item) for item in report.sessions)
        return HarnessReport(
            harness=self.harness(report.harness),
            sessions=sessions,
            problems=tuple(self.words(item) for item in report.problems),
            fields_read=tuple(self.words(item) for item in report.fields_read),
        )

    def process(self, node: ProcessNode) -> ProcessNode:
        """Keep a process's name as a bare executable name, never a path."""
        name = self.words(node.name).replace("\\", "/").rsplit("/", 1)[-1]
        return replace(node, name=name)


# --------------------------------------------------------------------------
# Process command lines (S-3)
# --------------------------------------------------------------------------

_LONG_FLAG_RE = re.compile(r"--[A-Za-z][A-Za-z0-9_-]{0,39}")


@dataclass(frozen=True)
class CommandSummary(Model):
    """What HC2 may keep of a process command line.

    `executable` is the program's file name, with no folder. `flags` are flag
    names only, in the order they appear, with no values and no more than
    `MAX_FLAGS`. `fingerprint` is the SHA-256 of the full line, which lets an
    executor check it is stopping the same process (S-2) without HC2 keeping the
    arguments, which can hold secrets and private paths.
    """

    executable: str
    flags: tuple[str, ...]
    fingerprint: str

    def display(self) -> str:
        """The safe one-line form: the executable and its flag names."""
        return " ".join((self.executable, *self.flags))


def fingerprint_command(line: str) -> str:
    """The SHA-256 of a full command line, as 64 hex digits."""
    return hashlib.sha256(line.encode("utf-8", "surrogateescape")).hexdigest()


def summarise_command(line: str) -> CommandSummary:
    """Reduce a process command line to its executable, flag names and fingerprint.

    A long flag keeps its name and loses any `=value`. A short flag keeps only
    its first two characters, so `-pSECRET` becomes `-p`. Anything else, such
    as a positional argument, is dropped.
    """
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    executable = ""
    if parts:
        executable = strip_controls(parts[0]).replace("\\", "/").rsplit("/", 1)[-1]
        executable = redact_secrets(executable)
    flags: list[str] = []
    for part in parts[1:]:
        if len(flags) >= MAX_FLAGS:
            break
        if part.startswith("--"):
            name = part.split("=", 1)[0]
            if _LONG_FLAG_RE.fullmatch(name):
                flags.append(redact_secrets(name))
        elif part.startswith("-") and len(part) >= 2 and part[1].isalpha():
            flags.append(part[:2])
    return CommandSummary(executable, tuple(flags), fingerprint_command(line))
