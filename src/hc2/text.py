"""Small helpers for plain-English output."""

from __future__ import annotations


def plural(count: int, noun: str, many: str | None = None) -> str:
    """`1 session`, `2 sessions`. Pass `many` for irregular plurals."""
    if count == 1:
        return f"{count} {noun}"
    return f"{count} {many if many is not None else noun + 's'}"


def truncate(text: str, limit: int) -> str:
    """Cut text to `limit` characters, ending with `...` when it was longer."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."
