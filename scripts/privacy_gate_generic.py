"""The generic checks of the privacy gate: email addresses, absolute home paths
and common secrets. Pure functions on one line of text, no deny-list, no git.

Loaded by scripts/privacy_gate.py, which re-exports every name here.
Standard library only.
"""

from __future__ import annotations

import re

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
ALLOWED_EMAIL_LOCALS = {"noreply", "no-reply"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "users.noreply.github.com"}
ALLOWED_EMAIL_SUFFIX = ".example.com"
EMAIL_LABEL = "email"
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
        labels.append(EMAIL_LABEL)
    if _has_personal_home_path(line):
        labels.append("home-path")
    labels.extend(label for label, rx in SECRET_PATTERNS if rx.search(line))
    return labels
