"""Harness adapters. Add each new adapter to `ALL_ADAPTERS`."""

from __future__ import annotations

from hc2.adapters.base import Adapter, AdapterContext, AdapterReport, ProcessSignature
from hc2.adapters.claude_code import ClaudeCodeAdapter
from hc2.adapters.claude_cowork import ClaudeCoworkAdapter
from hc2.adapters.claude_desktop import ClaudeDesktopAdapter

ALL_ADAPTERS: tuple[Adapter, ...] = (
    ClaudeCodeAdapter(),
    ClaudeDesktopAdapter(),
    ClaudeCoworkAdapter(),
)

__all__ = [
    "ALL_ADAPTERS",
    "Adapter",
    "AdapterContext",
    "AdapterReport",
    "ProcessSignature",
]
