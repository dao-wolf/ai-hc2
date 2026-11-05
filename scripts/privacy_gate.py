#!/usr/bin/env python3
"""Privacy gate: stop personal data reaching the public repo.

By default it scans every tracked file, plus untracked files that git does not
ignore, as they are on disk. With --staged it scans the staged copy of each
file instead, which is what the next commit will hold. With --message it scans
only a commit message file. Two sets of checks run:

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
from collections.abc import Callable, Iterable, Iterator, Sequence
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
        or (local == "git" and domain == "github.com")
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


def match_lines(pattern: re.Pattern[str], text: str) -> Iterator[int]:
    """Yield each line where a match starts. A match may run onto later lines.

    After a match the search goes on from the next line, so a match that wraps
    never hides one that starts on the line below.
    """
    start, line = 0, 1
    while match := pattern.search(text, start):
        line += text.count("\n", start, match.start())
        yield line
        start = text.find("\n", match.start()) + 1
        if not start:
            return
        line += 1


def scan_text(
    path: str, text: str, terms: Sequence[Term], generic: bool = True
) -> list[Hit]:
    """Scan one file's text. Each (line, label) pair is reported once."""
    hits = {
        Hit(path, line, f"term#{term.number}")
        for term in terms
        for line in match_lines(term.pattern, text)
    }
    if generic:
        for number, line in enumerate(text.split("\n"), start=1):
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


def staged_files(root: Path) -> dict[str, bytes]:
    """The staged copy of every file in git's index, by path.

    A link's copy is the target path it stores. Raises OSError or
    CalledProcessError when git or the index can't be read, and ScanError when
    an object is missing or git's answer is cut short.
    """
    entries = staged_entries(root)
    command = ["git", "-C", str(root), "cat-file", "--batch"]
    ids = b"".join(object_id + b"\n" for _, object_id in entries)
    out = subprocess.run(command, input=ids, capture_output=True, check=True).stdout
    files: dict[str, bytes] = {}
    at = 0
    for name, _ in entries:
        files[name], at = read_object(out, at)
    return files


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
            return None
        return terms
    if args.require_denylist:
        print("privacy gate: deny-list file not found.", file=sys.stderr)
        return None
    print(
        "privacy gate: NOTICE deny-list file not found, running generic checks only.",
        file=sys.stderr,
    )
    return []


def scan_source(
    args: argparse.Namespace, terms: Sequence[Term]
) -> tuple[list[Hit], str, list[str]]:
    """Scan what the options name. Returns the hits, a summary for the log and
    the files that were too large to scan.
    """
    if args.message:
        return scan_message(args.message, terms), "scanned the commit message", []
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
    args = build_parser().parse_args(None if argv is None else list(argv))
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
