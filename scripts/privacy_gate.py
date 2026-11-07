#!/usr/bin/env python3
"""Privacy gate: stop personal data reaching the public repo.

By default it scans every tracked file, plus untracked files that git does not
ignore, as they are on disk. With --staged it scans the staged copy of each
file instead, which is what the next commit will hold. With --message it scans
only a commit message file. With --range BASE..HEAD it scans each commit in the
range: its message, author and committer, the names of the files it touches and
the lines it adds, so a leak that one commit adds and a later one removes is
still found. A merge commit is compared with each of its parents, and a line
counts as added only if none of them had it. With --pre-push it reads the ref
lines git gives a pre-push hook and scans the same way, covering only the
commits the push would send, plus the names of the refs and the message and
tagger of an annotated tag. A hit is shown as
`<first 10 characters of the commit id>:<file>:line`, and a hit in a message,
author or committer is shown as `<message>`, `<author>` or `<committer>` in
place of the file; a ref name, tag message or tagger shows as `<ref>`,
`<tag message>` or `<tagger>`. --trust-author-emails (CI) skips the generic
email check on the author and committer of each commit, because an outside
contributor's own address is not a leak; the deny-list still checks them. Two
sets of checks run:

1. A personal deny-list that lives outside the repo. Its path comes from the
   environment variable HC2_PRIVACY_DENYLIST, and defaults to
   ~/.config/ai-hc2/privacy-denylist.txt. One term per line. Blank lines and
   lines starting with # are ignored.
2. Generic checks: email addresses, absolute home paths and common secrets.

Matching is case-insensitive. A term made only of letters, digits and spaces
matches whole words, so "Sam" does not match "sample". A term with any
other character (/ . - and so on) matches as a substring. In both, a space,
hyphen or underscore between words matches any run of them, line breaks
included, so "Example Person" also matches "example-person". A hit is reported
on the line where the match starts.

Output is one line per hit: `file:line term#N`. N is the term's line number in
the deny-list file. The term itself is never printed, and neither is the text
matched by a generic check. Line 0 means the file's name matched.

A file over 5 MB is not searched, so the gate names it and exits 2, unless
--allow-skipped turns that into a notice. A binary file (a NUL byte near the
start) is not searched either, and is only counted, not named. UTF-16 and
UTF-32 text with a byte order mark is read as text.

Exit codes: 0 clean, 1 hits found, 2 the gate could not run. Any failure, of
any kind, exits 2, as does a file left unchecked for being too large. Exit 0
and 1 happen only after the scan finished, and a finished scan ends with a
summary line on stderr: `privacy gate: scanned ..., N hits.` A run that exits
2 never prints that line.
Standard library only.
"""

from __future__ import annotations

import argparse
import codecs
import os
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence, Set
from dataclasses import dataclass
from pathlib import Path

ENV_DENYLIST = "HC2_PRIVACY_DENYLIST"
DEFAULT_DENYLIST = "~/.config/ai-hc2/privacy-denylist.txt"
MAX_BYTES = 5_000_000
# A file that starts with one of these marks is text in that encoding, though it
# holds NUL bytes. Without a mark, a NUL in the first bytes means binary.
TEXT_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
BINARY_CHECK_BYTES = 8192
SEPARATORS = r"[\s_-]+"
# Only a separator between two other characters is loosened. A loose one at the
# start of a term would make the search slow on a long run of hyphens.
BETWEEN_WORDS_RE = re.compile(rf"(?<=[^\s_-]){SEPARATORS}(?=[^\s_-])")

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
ALLOWED_EMAIL_LOCALS = {"noreply", "no-reply"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com"}
ALLOWED_EMAIL_SUFFIX = ".example.com"
# GitHub's own addresses: the one in ssh clone URLs, and the one that bots such
# as Dependabot put in a Signed-off-by trailer.
ALLOWED_GITHUB_LOCALS = {"git", "support"}

HOME_PATH_RE = re.compile(r"(?<![\w.~-])/(?:Users|home)/([A-Za-z0-9._-]+)")
# A Windows home folder: drive letter, Users, then the name. With forward
# slashes HOME_PATH_RE already matches.
WINDOWS_HOME_RE = re.compile(r"(?<![\w.~-])[A-Za-z]:\\Users\\([A-Za-z0-9._-]+)")
# A folder under the home shorthand (a tilde, $HOME or ${HOME} and a slash).
# Hidden folders are where tools keep their settings, so they pass.
TILDE_PATH_RE = re.compile(
    r"(?<![\w.~/$-])(?:~|\$HOME|\$\{HOME\})/([A-Za-z0-9_][A-Za-z0-9._/-]*)"
)
# Folders that name no one: where an operating system keeps application data,
# and placeholders. A single character such as x is one too. Only the first
# folder counts: a personal folder with "example" further down is still personal.
ALLOWED_HOME_FOLDERS = {
    "applications",
    "library",
    "path",
    "project",
    "projects",
    "repo",
}
MADE_UP_FOLDER_PREFIX = "example"
ALLOWED_HOME_NAMES = {
    "alice",
    "bob",
    "carol",
    "dave",
    "default",
    "eve",
    "example",
    "me",
    "name",
    "public",
    "runner",
    "shared",
    "user",
    "username",
    "you",
    "yourname",
}

SECRET_PATTERNS = (
    ("secret:aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "secret:github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    (
        "secret:private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    ),
)

# `git commit -v` adds the diff below this line of the message file, and git
# drops it from the message. The gate drops it too, or the diff of a commit
# that removes a leak would block that commit.
SCISSORS_RE = re.compile(r"^\S+ -{24} >8 -{24}$", re.MULTILINE)

# The first line git prints for an object read with `cat-file --batch`.
OBJECT_HEADER_RE = re.compile(rb"[0-9a-f]+ [a-z]+ ([0-9]+)\n")

# A commit id as git writes it (SHA-1 or SHA-256), and the all-zero id that git
# uses for "no such object" in a pre-push hook and in a diff.
COMMIT_ID_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
COMMIT_ID_SHORT = 10

DENYLIST_NEXT_STEP = (
    "privacy gate: create your deny-list (see CONTRIBUTING.md). With none, "
    "run: make hooks GENERIC_ONLY=1"
)


class ScanError(Exception):
    """The gate can't tell what it was asked to scan. The text is safe to print."""


@dataclass(frozen=True, order=True)
class Hit:
    """One finding. `line` 0 means the file name, not its contents."""

    path: str
    line: int
    label: str

    def __str__(self) -> str:
        return f"{printable(self.path)}:{self.line} {self.label}"


def printable(name: str) -> str:
    """A file name safe to print: a byte that is not UTF-8 shows as \\xNN."""
    return os.fsencode(name).decode("utf-8", "backslashreplace")


@dataclass(frozen=True)
class ScanResult:
    """What a scan of files found. `binary` files hold NUL bytes and are only
    counted; each `oversize` file is named, because nobody checked it.
    """

    hits: list[Hit]
    scanned: int
    binary: int
    oversize: list[str]


@dataclass(frozen=True)
class Term:
    """A compiled deny-list entry and its line number in the deny-list file."""

    number: int
    pattern: re.Pattern[str]


def compile_term(term: str) -> re.Pattern[str]:
    """Whole-word match for letters, digits and spaces; substring otherwise.

    Each run of spaces, hyphens or underscores between the term's words matches
    any such run in the text, line breaks included.
    """
    parts = BETWEEN_WORDS_RE.split(term)
    body = SEPARATORS.join(re.escape(part) for part in parts)
    if all(ch.isalnum() or ch == " " for ch in term):
        # [^\W_] is "a letter or digit", so an underscore counts as a separator.
        return re.compile(rf"(?<![^\W_]){body}(?![^\W_])", re.IGNORECASE)
    return re.compile(body, re.IGNORECASE)


def parse_terms(text: str) -> list[Term]:
    """Read deny-list text. Blank lines and # comments are skipped."""
    terms: list[Term] = []
    for number, raw in enumerate(text.lstrip("﻿").split("\n"), start=1):
        term = raw.strip()
        if term and not term.startswith("#"):
            terms.append(Term(number, compile_term(term)))
    return terms


def load_denylist(path: Path) -> list[Term]:
    """Load a deny-list file."""
    return parse_terms(path.read_text(encoding="utf-8"))


def _email_allowed(match: re.Match[str]) -> bool:
    local = match.group(0).rsplit("@", 1)[0].lower()
    domain = match.group(1).lower()
    return (
        local in ALLOWED_EMAIL_LOCALS
        or domain in ALLOWED_EMAIL_DOMAINS
        or domain.endswith(ALLOWED_EMAIL_SUFFIX)
        or (local in ALLOWED_GITHUB_LOCALS and domain == "github.com")
    )


def _folders_allowed(path: str) -> bool:
    """Whether a path under the home shorthand names nothing personal."""
    folders = path.lower().split("/")
    first = folders[0]
    return (
        len(first) == 1
        or first in ALLOWED_HOME_FOLDERS
        or first.startswith(MADE_UP_FOLDER_PREFIX)
    )


def _has_personal_home_path(line: str) -> bool:
    """A user name or a folder under the home shorthand that isn't made up."""
    users = (
        m.group(1).lower()
        for rx in (HOME_PATH_RE, WINDOWS_HOME_RE)
        for m in rx.finditer(line)
    )
    folders = (m.group(1) for m in TILDE_PATH_RE.finditer(line))
    return any(u not in ALLOWED_HOME_NAMES for u in users) or any(
        not _folders_allowed(f) for f in folders
    )


def generic_labels(line: str) -> list[str]:
    """Labels of every generic check that the line trips."""
    labels: list[str] = []
    if any(not _email_allowed(m) for m in EMAIL_RE.finditer(line)):
        labels.append("email")
    if _has_personal_home_path(line):
        labels.append("home-path")
    labels.extend(label for label, rx in SECRET_PATTERNS if rx.search(line))
    return labels


def touches(added: Set[int] | None, first: int, last: int) -> bool:
    """Whether any line from `first` to `last` is one that counts. None means
    every line does.
    """
    return added is None or any(n in added for n in range(first, last + 1))


def match_lines(
    pattern: re.Pattern[str], text: str, added: Set[int] | None = None
) -> Iterator[int]:
    """Yield each line where a match starts. A match may run onto later lines.

    With `added`, only a match that touches one of those lines counts, so an old
    line followed by a new one can still form a term. After a match the search
    goes on from the next line, so a match that wraps never hides one that
    starts on the line below.
    """
    start, line = 0, 1
    while match := pattern.search(text, start):
        line += text.count("\n", start, match.start())
        if touches(added, line, line + text.count("\n", match.start(), match.end())):
            yield line
        start = text.find("\n", match.start()) + 1
        if not start:
            return
        line += 1


def scan_text(
    path: str,
    text: str,
    terms: Sequence[Term],
    generic: bool = True,
    added: Set[int] | None = None,
) -> list[Hit]:
    """Scan one file's text. Each (line, label) pair is reported once. With
    `added`, a hit counts only if it touches one of those lines.
    """
    hits = {
        Hit(path, line, f"term#{term.number}")
        for term in terms
        for line in match_lines(term.pattern, text, added)
    }
    if generic:
        for number, line in enumerate(text.split("\n"), start=1):
            if added is None or number in added:
                hits.update(Hit(path, number, label) for label in generic_labels(line))
    return sorted(hits)


def scan_name(path: str, terms: Sequence[Term]) -> list[Hit]:
    """Check a file's own path against the deny-list."""
    return [Hit(path, 0, f"term#{t.number}") for t in terms if t.pattern.search(path)]


def list_files(root: Path) -> list[str]:
    """Tracked files plus untracked files that git does not ignore.

    Falls back to walking the folder (skipping .git) when git is unavailable or
    `root` is not a repository. Deleted-but-tracked files and links are skipped.
    """
    command = ["git", "-C", str(root), "ls-files", "-z"]
    command += ["--cached", "--others", "--exclude-standard"]
    try:
        done = subprocess.run(command, capture_output=True, check=True)
        names = [os.fsdecode(n) for n in done.stdout.split(b"\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.relative_to(root).parts
        ]
    found = {n for n in names if (root / n).is_file() and not (root / n).is_symlink()}
    return sorted(found)


def decode_text(data: bytes) -> str | None:
    """The text in a file's bytes, or None when it is binary."""
    for mark, codec in TEXT_BOMS:
        if data.startswith(mark):
            return data.decode(codec, "replace")
    if b"\0" in data[:BINARY_CHECK_BYTES]:
        return None
    return data.decode("utf-8", "replace")


def scan_files(
    sizes: dict[str, int],
    read: Callable[[str], bytes],
    terms: Sequence[Term],
) -> ScanResult:
    """Scan files by name. Their names are always checked; a file over
    MAX_BYTES is not read, and a binary one is not searched.
    """
    hits: list[Hit] = []
    scanned = binary = 0
    oversize: list[str] = []
    for name, size in sizes.items():
        hits.extend(scan_name(name, terms))
        if size > MAX_BYTES:
            oversize.append(name)
            continue
        text = decode_text(read(name))
        if text is None:
            binary += 1
            continue
        scanned += 1
        hits.extend(scan_text(name, text, terms))
    return ScanResult(sorted(set(hits)), scanned, binary, oversize)


def scan_tree(root: Path, terms: Sequence[Term]) -> ScanResult:
    """Scan a folder's files as they are on disk."""
    sizes = {name: (root / name).stat().st_size for name in list_files(root)}
    return scan_files(sizes, lambda name: (root / name).read_bytes(), terms)


def staged_entries(root: Path) -> list[tuple[str, bytes]]:
    """The path and object id of every staged file. Submodules are skipped."""
    command = ["git", "-C", str(root), "ls-files", "--stage", "-z"]
    listing = subprocess.run(command, capture_output=True, check=True).stdout
    entries: list[tuple[str, bytes]] = []
    for record in filter(None, listing.split(b"\0")):
        info, name = record.split(b"\t", 1)
        mode, object_id, _stage = info.split()
        if mode != b"160000":
            entries.append((os.fsdecode(name), object_id))
    return entries


def read_object(out: bytes, at: int) -> tuple[bytes, int]:
    """Cut one object from `git cat-file --batch` output. Returns it and where
    the next one starts. Each comes back as "<id> <type> <size>\n<content>\n";
    a missing one is "<id> missing\n", which doesn't match.
    """
    header = OBJECT_HEADER_RE.match(out, at)
    if header is None:
        raise ScanError("privacy gate: a staged object is missing or unreadable.")
    start = header.end()
    end = start + int(header.group(1))
    if end > len(out):
        raise ScanError("privacy gate: git's answer for a staged object was cut short.")
    return out[start:end], end + 1


def read_objects(root: Path, ids: Sequence[bytes]) -> dict[bytes, bytes]:
    """The content of each git object, by id. Raises OSError or
    CalledProcessError when git can't be read, and ScanError when an object is
    missing or git's answer is cut short.
    """
    unique = list(dict.fromkeys(ids))
    command = ["git", "-C", str(root), "cat-file", "--batch"]
    request = b"".join(object_id + b"\n" for object_id in unique)
    out = subprocess.run(command, input=request, capture_output=True, check=True).stdout
    found: dict[bytes, bytes] = {}
    at = 0
    for object_id in unique:
        found[object_id], at = read_object(out, at)
    return found


def staged_files(root: Path) -> dict[str, bytes]:
    """The staged copy of every file in git's index, by path.

    A link's copy is the target path it stores. Raises OSError or
    CalledProcessError when git or the index can't be read, and ScanError when
    an object is missing or git's answer is cut short.
    """
    entries = staged_entries(root)
    objects = read_objects(root, [object_id for _, object_id in entries])
    return {name: objects[object_id] for name, object_id in entries}


def scan_index(root: Path, terms: Sequence[Term]) -> ScanResult:
    """Scan what the next commit will hold, leaving out unstaged edits."""
    files = staged_files(root)
    sizes = {name: len(data) for name, data in files.items()}
    return scan_files(sizes, files.__getitem__, terms)


def scan_message(path: Path, terms: Sequence[Term]) -> list[Hit]:
    """Scan a commit message file, as git passes it to the commit-msg hook."""
    text = path.read_text(encoding="utf-8", errors="replace")
    message = SCISSORS_RE.split(text, maxsplit=1)[0]
    return scan_text("<commit message>", message, terms)


def scan_identity(root: Path, terms: Sequence[Term]) -> list[Hit]:
    """Check the author and committer name and email git will put on a commit.

    Commit metadata becomes public with the history and can't be taken back
    after a push, so a real name in `user.name` counts as a leak too.
    """
    hits: list[Hit] = []
    roles = (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT"))
    for role, variable in roles:
        command = ["git", "-C", str(root), "var", variable]
        try:
            done = subprocess.run(command, capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            continue
        # The ident ends with a timestamp and offset; keep only "Name <email>".
        ident = done.stdout.decode("utf-8", "replace").strip().rsplit(">", 1)[0] + ">"
        hits.extend(scan_text(f"<git {role}>", ident, terms))
    return sorted(set(hits))


@dataclass(frozen=True)
class Change:
    """A file a commit adds or edits. `old_ids` holds its object id in each
    parent of the commit, all zeros where that parent lacks it.
    """

    path: str
    old_ids: tuple[bytes, ...]
    new_id: bytes


@dataclass(frozen=True)
class Push:
    """One line a pre-push hook is given."""

    local_ref: str
    local: str
    remote_ref: str
    remote: str


def is_zero_id(object_id: bytes | str) -> bool:
    return not object_id.strip(b"0" if isinstance(object_id, bytes) else "0")


def prefixed(hits: Iterable[Hit], prefix: str) -> list[Hit]:
    """The hits with a commit id in front of each path."""
    return [Hit(f"{prefix}:{hit.path}", hit.line, hit.label) for hit in hits]


def git_output(root: Path, *arguments: str) -> bytes:
    """What a git command prints. Raises when it fails."""
    command = ["git", "-C", str(root), *arguments]
    return subprocess.run(command, capture_output=True, check=True).stdout


def rev_list(root: Path, selection: Sequence[str]) -> list[str]:
    """The ids of the commits a selection names, oldest first."""
    return git_output(root, "rev-list", "--reverse", *selection, "--").decode().split()


def commit_parents(root: Path, commit: str) -> list[str]:
    """The ids of a commit's parents."""
    line = git_output(root, "rev-list", "--parents", "-n", "1", commit, "--")
    return line.decode().split()[1:]


def diff_tree(root: Path, *trees: str) -> list[Change]:
    """The files that differ between two trees, or that a commit adds or edits.
    Deleted files and submodules are left out.
    """
    flags = ["-r", "-z", "--root", "--no-renames", "--no-commit-id"]
    fields = git_output(root, "diff-tree", *flags, *trees).split(b"\0")
    changes: list[Change] = []
    for info, name in zip(fields[0::2], fields[1::2], strict=False):
        _old_mode, new_mode, old_id, new_id, status = info.split()
        if status != b"D" and new_mode != b"160000":
            changes.append(Change(os.fsdecode(name), (old_id,), new_id))
    return changes


def common_changes(per_parent: Sequence[Sequence[Change]]) -> list[Change]:
    """The files of a merge that differ from every parent. A file equal to one
    parent's came from that parent, so it is not new. Each keeps the id it had
    in every parent.
    """
    by_path = [{change.path: change for change in changes} for changes in per_parent]
    return [
        Change(
            change.path,
            tuple(m[change.path].old_ids[0] for m in by_path),
            change.new_id,
        )
        for change in per_parent[0]
        if all(change.path in m for m in by_path)
    ]


def commit_changes(root: Path, commit: str) -> list[Change]:
    """The files a commit adds or edits. A merge is compared with each parent,
    so only what the merge itself brings is left. Deleted files and submodules
    are left out.
    """
    parents = commit_parents(root, commit)
    if len(parents) < 2:
        return diff_tree(root, commit)
    return common_changes([diff_tree(root, parent, commit) for parent in parents])


def ident_of(line: bytes) -> str:
    """ "Name <email>" from the rest of an author, committer or tagger line,
    which ends with a time stamp and offset.
    """
    return line.decode("utf-8", "replace").rsplit(">", 1)[0] + ">"


def commit_idents_and_message(
    root: Path, commit: str
) -> tuple[list[tuple[str, str]], str]:
    """The author and committer of a commit as ("author", "Name <email>"), and
    its message.
    """
    raw = git_output(root, "cat-file", "commit", commit)
    header, _, body = raw.partition(b"\n\n")
    idents: list[tuple[str, str]] = []
    for line in header.split(b"\n"):
        role, _, rest = line.partition(b" ")
        if role in (b"author", b"committer"):
            idents.append((role.decode(), ident_of(rest)))
    return idents, body.decode("utf-8", "replace")


def added_lines(olds: Sequence[str], new: str) -> frozenset[int]:
    """The numbers of the lines of `new` that none of the old versions had. A
    line that is repeated counts once for each time an old version had it.
    """
    known: Counter[str] = Counter()
    for old in olds:
        known |= Counter(old.split("\n"))
    added: set[int] = set()
    for number, line in enumerate(new.split("\n"), start=1):
        if known[line] > 0:
            known[line] -= 1
        else:
            added.add(number)
    return frozenset(added)


def old_text(objects: dict[bytes, bytes], object_id: bytes) -> str:
    """An earlier version of a file as text. A missing or binary one is empty."""
    if is_zero_id(object_id):
        return ""
    return decode_text(objects[object_id]) or ""


def scan_change(
    change: Change, objects: dict[bytes, bytes], terms: Sequence[Term]
) -> tuple[list[Hit], str]:
    """Scan the lines one change adds. Returns the hits and what became of the
    file: "scanned", "binary" or "oversize".
    """
    hits = scan_name(change.path, terms)
    new = objects[change.new_id]
    if len(new) > MAX_BYTES:
        return hits, "oversize"
    text = decode_text(new)
    if text is None:
        return hits, "binary"
    olds = [old_text(objects, object_id) for object_id in change.old_ids]
    added = added_lines(olds, text)
    return hits + scan_text(change.path, text, terms, added=added), "scanned"


def scan_commit(
    root: Path, commit: str, terms: Sequence[Term], trust_idents: bool = False
) -> ScanResult:
    """Scan one commit: its message, author, committer and added lines. With
    `trust_idents` the generic checks skip the author and committer.
    """
    prefix = commit[:COMMIT_ID_SHORT]
    idents, message = commit_idents_and_message(root, commit)
    hits = scan_text("<message>", message, terms)
    for role, ident in idents:
        hits.extend(scan_text(f"<{role}>", ident, terms, generic=not trust_idents))
    changes = commit_changes(root, commit)
    wanted = [c.new_id for c in changes]
    wanted += [i for c in changes for i in c.old_ids if not is_zero_id(i)]
    objects = read_objects(root, wanted)
    tally = {"scanned": 0, "binary": 0}
    oversize: list[str] = []
    for change in changes:
        found, outcome = scan_change(change, objects, terms)
        hits.extend(found)
        if outcome == "oversize":
            oversize.append(f"{prefix}:{change.path}")
        else:
            tally[outcome] += 1
    shown = prefixed(hits, prefix)
    return ScanResult(shown, tally["scanned"], tally["binary"], oversize)


def scan_range(
    root: Path,
    selections: Sequence[Sequence[str]],
    terms: Sequence[Term],
    trust_idents: bool = False,
) -> tuple[ScanResult, int]:
    """Scan every commit the selections name, each once. Returns the result and
    the number of commits.
    """
    commits = list(dict.fromkeys(c for s in selections for c in rev_list(root, s)))
    results = [scan_commit(root, commit, terms, trust_idents) for commit in commits]
    merged = ScanResult(
        sorted({hit for r in results for hit in r.hits}),
        sum(r.scanned for r in results),
        sum(r.binary for r in results),
        [name for r in results for name in r.oversize],
    )
    return merged, len(commits)


def range_selection(spec: str) -> list[str]:
    """What `git rev-list` is asked for by --range: two refs joined by dots."""
    if ".." not in spec or spec.startswith("-"):
        raise ScanError(
            "privacy gate: --range needs BASE..HEAD (two refs joined by '..')."
        )
    return [spec]


def has_commit(root: Path, commit: str) -> bool:
    command = ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"]
    return subprocess.run(command, capture_output=True).returncode == 0


def parse_push(line: str) -> Push:
    """Read one line a pre-push hook is given:
    `<local ref> <local id> <remote ref> <remote id>`.
    """
    fields = line.split()
    if len(fields) != 4 or not all(COMMIT_ID_RE.fullmatch(i) for i in fields[1::2]):
        raise ScanError("privacy gate: could not read the refs git is pushing.")
    return Push(*fields)


def pre_push_selections(root: Path, pushes: Iterable[Push]) -> list[list[str]]:
    """Which commits a push sends. A deleted ref sends none. A new ref, or one
    whose old tip this clone lacks, sends every commit that no remote-tracking
    branch has. Any other sends everything from the old tip to the new one.
    """
    selections: list[list[str]] = []
    for push in pushes:
        if is_zero_id(push.local):
            continue
        if is_zero_id(push.remote) or not has_commit(root, push.remote):
            selections.append([push.local, "--not", "--remotes"])
        else:
            selections.append([f"{push.remote}..{push.local}"])
    return selections


def tag_hits(root: Path, object_id: str, terms: Sequence[Term]) -> list[Hit]:
    """The deny-list hits in an annotated tag: its name, tagger and message. A
    tag that points at another tag is followed down to the commit.
    """
    hits: list[Hit] = []
    while git_output(root, "cat-file", "-t", object_id).strip() == b"tag":
        header, _, message = git_output(root, "cat-file", "tag", object_id).partition(
            b"\n\n"
        )
        for line in header.split(b"\n"):
            key, _, rest = line.partition(b" ")
            if key == b"object":
                object_id = rest.decode()
            elif key == b"tag":
                hits.extend(ref_hits(rest.decode("utf-8", "replace"), terms))
            elif key == b"tagger":
                hits.extend(scan_text("<tagger>", ident_of(rest), terms))
        text = message.decode("utf-8", "replace")
        hits.extend(scan_text("<tag message>", text, terms))
    return hits


def ref_hits(name: str, terms: Sequence[Term]) -> list[Hit]:
    """The deny-list hits in the name of a ref."""
    return [Hit("<ref>", hit.line, hit.label) for hit in scan_name(name, terms)]


def pushed_ref_hits(
    root: Path, pushes: Iterable[Push], terms: Sequence[Term]
) -> list[Hit]:
    """The deny-list hits in what a push names rather than holds: ref names and
    annotated tags. A deleted ref sends nothing.
    """
    hits: list[Hit] = []
    for push in pushes:
        if is_zero_id(push.local):
            continue
        hits.extend(ref_hits(push.local_ref, terms))
        hits.extend(ref_hits(push.remote_ref, terms))
        hits.extend(tag_hits(root, push.local, terms))
    return hits


def resolve_denylist(option: str | None) -> Path:
    """Pick the deny-list path: the option, then the environment, then the default."""
    chosen = option or os.environ.get(ENV_DENYLIST, "").strip() or DEFAULT_DENYLIST
    return Path(chosen).expanduser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan the repo for personal data.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="folder to scan (default: the repo this script lives in)",
    )
    parser.add_argument(
        "--denylist",
        help=f"deny-list file (default: ${ENV_DENYLIST}, then {DEFAULT_DENYLIST})",
    )
    denylist_mode = parser.add_mutually_exclusive_group()
    denylist_mode.add_argument(
        "--generic-only",
        action="store_true",
        help="skip the personal deny-list and run only the generic checks",
    )
    denylist_mode.add_argument(
        "--require-denylist",
        action="store_true",
        help="exit 2 if the deny-list file is missing, instead of a notice "
        "(the git hooks pass this; it cannot be combined with --generic-only)",
    )
    parser.add_argument(
        "--allow-skipped",
        action="store_true",
        help="accept files that are too large to scan: name them in a notice "
        "instead of exiting 2",
    )
    parser.add_argument(
        "--trust-author-emails",
        action="store_true",
        help="with --range or --pre-push, skip the generic email check on the "
        "author and committer of each commit; the deny-list still checks them "
        "(CI passes this, because an outside contributor's address is no leak)",
    )
    parser.add_argument(
        "--check-identity",
        action="store_true",
        help="also check the author and committer git will use (the pre-commit "
        "hook passes this; CI runners have no real identity to check)",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--staged",
        action="store_true",
        help="scan the staged copy of each file, which the next commit will "
        "hold, instead of the files on disk (the pre-commit hook passes this)",
    )
    source.add_argument(
        "--message",
        type=Path,
        metavar="FILE",
        help="scan only this commit message file (the commit-msg hook passes this)",
    )
    source.add_argument(
        "--range",
        metavar="BASE..HEAD",
        help="scan each commit in the range: its message, author, committer, "
        "file names and added lines (make privacy and CI pass this)",
    )
    source.add_argument(
        "--pre-push",
        action="store_true",
        help="scan the commits a push would send, from the ref lines on standard "
        "input (the pre-push hook passes this)",
    )
    return parser


def load_terms(args: argparse.Namespace) -> list[Term] | None:
    """Load the deny-list the options ask for. None means a required one is missing."""
    if args.generic_only:
        note = "privacy gate: generic checks only (deny-list skipped)."
        print(note, file=sys.stderr)
        return []
    path = resolve_denylist(args.denylist)
    if path.is_file():
        terms = load_denylist(path)
        note = f"privacy gate: {len(terms)} deny-list terms loaded."
        print(note, file=sys.stderr)
        if args.require_denylist and not terms:
            print("privacy gate: the deny-list has no terms.", file=sys.stderr)
            print(DENYLIST_NEXT_STEP, file=sys.stderr)
            return None
        return terms
    if args.require_denylist:
        print("privacy gate: deny-list file not found.", file=sys.stderr)
        print(DENYLIST_NEXT_STEP, file=sys.stderr)
        return None
    print(
        "privacy gate: NOTICE deny-list file not found, running generic checks only.",
        file=sys.stderr,
    )
    return []


def scan_commits(
    args: argparse.Namespace, terms: Sequence[Term]
) -> tuple[list[Hit], str, list[str]]:
    """Scan the commits that --range or --pre-push names. A push also has its
    ref names and annotated tags checked.
    """
    if args.pre_push:
        pushes = [parse_push(line) for line in sys.stdin if line.strip()]
        selections = pre_push_selections(args.root, pushes)
        named = pushed_ref_hits(args.root, pushes, terms)
    else:
        selections = [range_selection(args.range)]
        named = []
    result, commits = scan_range(args.root, selections, terms, args.trust_author_emails)
    skipped = result.binary + len(result.oversize)
    summary = f"scanned {commits} commits, {result.scanned} files, skipped {skipped}"
    return sorted(set(result.hits) | set(named)), summary, result.oversize


def scan_source(
    args: argparse.Namespace, terms: Sequence[Term]
) -> tuple[list[Hit], str, list[str]]:
    """Scan what the options name. Returns the hits, a summary for the log and
    the files that were too large to scan.
    """
    if args.message:
        return scan_message(args.message, terms), "scanned the commit message", []
    if args.range is not None or args.pre_push:
        return scan_commits(args, terms)
    scan = scan_index if args.staged else scan_tree
    result = scan(args.root, terms)
    skipped = result.binary + len(result.oversize)
    summary = f"scanned {result.scanned} files, skipped {skipped}"
    return result.hits, summary, result.oversize


def report_oversize(oversize: Sequence[str], allowed: bool) -> None:
    """Name every file that was too large to scan, and say what that means."""
    word = "NOTICE skipped" if allowed else "NOT SCANNED"
    for name in oversize:
        note = f"privacy gate: {word} {printable(name)} (over {MAX_BYTES} bytes)"
        print(note, file=sys.stderr)
    if oversize and not allowed:
        print(
            "privacy gate: files above were not checked. Shrink or remove them, "
            "or pass --allow-skipped to accept the skip.",
            file=sys.stderr,
        )


def left_unchecked(oversize: Sequence[str], hits: Sequence[Hit], allowed: bool) -> bool:
    """True when a file was too large to scan and nothing else explains a failing
    run: hits already fail it, and --allow-skipped accepts the skip.
    """
    if allowed or hits:
        return False
    return bool(oversize)


def run(args: argparse.Namespace) -> int:
    """Scan what the options name. Anything that goes wrong raises."""
    terms = load_terms(args)
    if terms is None:
        return 2
    hits, summary, oversize = scan_source(args, terms)
    if args.check_identity:
        hits = sorted(set(hits) | set(scan_identity(args.root, terms)))
    for hit in hits:
        print(hit)
    report_oversize(oversize, args.allow_skipped)
    if left_unchecked(oversize, hits, args.allow_skipped):
        return 2
    print(f"privacy gate: {summary}, {len(hits)} hits.", file=sys.stderr)
    return 1 if hits else 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(None if argv is None else list(argv))
    if args.trust_author_emails and args.range is None and not args.pre_push:
        parser.error("--trust-author-emails needs --range or --pre-push")
    try:
        return run(args)
    except ScanError as error:
        print(error, file=sys.stderr)
    except (OSError, subprocess.CalledProcessError):
        print("privacy gate: could not read what it had to scan.", file=sys.stderr)
    except Exception as error:
        # Only the class name is printed: the text of an error may quote a
        # deny-list term or a line of a scanned file.
        print(f"privacy gate: FAILED ({type(error).__name__}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
