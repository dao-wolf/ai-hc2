"""Tests for the resource rules."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "resources"


def fixture(name: str) -> str:
    """Read one recorded (made-up) command output."""
    return (FIXTURES / name).read_text(encoding="utf-8")
