"""The git side of the privacy gate: reading commits, trees and the lines a push
sends. It scans nothing itself, and knows no deny-list.

Loaded by scripts/privacy_gate.py, which re-exports every name here.
Standard library only.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

# A commit id as git writes it (SHA-1 or SHA-256).
COMMIT_ID_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class ScanError(Exception):
    """The gate can't tell what it was asked to scan. The text is safe to print."""


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
    fields = git_output(root, "diff-tree", *flags, *trees, "--").split(b"\0")
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
