#!/usr/bin/env python3
"""Privacy gate: stop personal data reaching the public repo.

It scans every tracked file, plus untracked files that git does not ignore,
against two sets of checks:

1. A personal deny-list that lives outside the repo. Its path comes from the
   environment variable HC2_PRIVACY_DENYLIST, and defaults to
   ~/.config/ai-hc2/privacy-denylist.txt. One term per line. Blank lines and
   lines starting with # are ignored.
2. Generic checks: email addresses, absolute home paths and common secrets.

Matching is case-insensitive. A term made only of letters, digits and spaces
matches whole words, so "Sam" does not match "sample". A term with any
other character (/ . - and so on) matches as a substring.

Output is one line per hit: `file:line term#N`. N is the term's line number in
the deny-list file. The term itself is never printed, and neither is the text
matched by a generic check. Line 0 means the file's name matched.

Exit codes: 0 clean, 1 hits found, 2 the gate could not run.
Standard library only.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

ENV_DENYLIST = "HC2_PRIVACY_DENYLIST"
DEFAULT_DENYLIST = "~/.config/ai-hc2/privacy-denylist.txt"
MAX_BYTES = 5_000_000

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
ALLOWED_EMAIL_LOCALS = {"noreply", "no-reply"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com"}
ALLOWED_EMAIL_SUFFIX = ".example.com"

HOME_PATH_RE = re.compile(r"(?<![\w.~-])/(?:Users|home)/([A-Za-z0-9._-]+)")
ALLOWED_HOME_NAMES = {
    "alice",
    "bob",
    "carol",
    "dave",
    "eve",
    "example",
    "me",
    "name",
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


@dataclass(frozen=True, order=True)
class Hit:
    """One finding. `line` 0 means the file name, not its contents."""

    path: str
    line: int
    label: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line} {self.label}"


@dataclass(frozen=True)
class Term:
    """A compiled deny-list entry and its line number in the deny-list file."""

    number: int
    pattern: re.Pattern[str]


def compile_term(term: str) -> re.Pattern[str]:
    """Whole-word match for letters, digits and spaces; substring otherwise."""
    if all(ch.isalnum() or ch == " " for ch in term):
        body = r"\s+".join(re.escape(word) for word in term.split())
        # [^\W_] is "a letter or digit", so an underscore counts as a separator.
        return re.compile(rf"(?<![^\W_]){body}(?![^\W_])", re.IGNORECASE)
    return re.compile(re.escape(term), re.IGNORECASE)


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


def generic_labels(line: str) -> list[str]:
    """Labels of every generic check that the line trips."""
    labels: list[str] = []
    if any(not _email_allowed(m) for m in EMAIL_RE.finditer(line)):
        labels.append("email")
    names = (m.group(1).lower() for m in HOME_PATH_RE.finditer(line))
    if any(name not in ALLOWED_HOME_NAMES for name in names):
        labels.append("home-path")
    labels.extend(label for label, rx in SECRET_PATTERNS if rx.search(line))
    return labels


def scan_text(
    path: str, text: str, terms: Sequence[Term], generic: bool = True
) -> list[Hit]:
    """Scan one file's text. Each (line, label) pair is reported once."""
    hits: set[Hit] = set()
    for number, line in enumerate(text.split("\n"), start=1):
        for term in terms:
            if term.pattern.search(line):
                hits.add(Hit(path, number, f"term#{term.number}"))
        if generic:
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
        names = [n for n in done.stdout.decode("utf-8", "replace").split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [
            str(p.relative_to(root))
            for p in root.rglob("*")
            if ".git" not in p.relative_to(root).parts
        ]
    found = {n for n in names if (root / n).is_file() and not (root / n).is_symlink()}
    return sorted(found)


def scan_tree(
    root: Path, terms: Sequence[Term], generic: bool = True
) -> tuple[list[Hit], int, int]:
    """Scan a folder. Returns the hits, files scanned and files skipped."""
    hits: list[Hit] = []
    scanned = skipped = 0
    for name in list_files(root):
        hits.extend(scan_name(name, terms))
        file = root / name
        if file.stat().st_size > MAX_BYTES:
            skipped += 1
            note = f"privacy gate: skipped {name} (over {MAX_BYTES} bytes)"
            print(note, file=sys.stderr)
            continue
        data = file.read_bytes()
        if b"\0" in data[:8192]:
            skipped += 1
            continue
        scanned += 1
        hits.extend(scan_text(name, data.decode("utf-8", "replace"), terms, generic))
    return sorted(set(hits)), scanned, skipped


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
    parser.add_argument(
        "--generic-only",
        action="store_true",
        help="skip the personal deny-list and run only the generic checks",
    )
    parser.add_argument(
        "--require-denylist",
        action="store_true",
        help="exit 2 if the deny-list file is missing, instead of a notice",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(None if argv is None else list(argv))
    terms: list[Term] = []
    if args.generic_only:
        note = "privacy gate: generic checks only (deny-list skipped)."
        print(note, file=sys.stderr)
    else:
        path = resolve_denylist(args.denylist)
        if path.is_file():
            terms = load_denylist(path)
            note = f"privacy gate: {len(terms)} deny-list terms loaded."
            print(note, file=sys.stderr)
        elif args.require_denylist:
            print("privacy gate: deny-list file not found.", file=sys.stderr)
            return 2
        else:
            print(
                "privacy gate: NOTICE deny-list file not found, "
                "running generic checks only.",
                file=sys.stderr,
            )
    hits, scanned, skipped = scan_tree(args.root, terms)
    hits = sorted(set(hits) | set(scan_identity(args.root, terms)))
    for hit in hits:
        print(hit)
    print(
        f"privacy gate: scanned {scanned} files, skipped {skipped}, {len(hits)} hits.",
        file=sys.stderr,
    )
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
