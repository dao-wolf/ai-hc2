"""Harness adapters. Add each new adapter to `ALL_ADAPTERS`."""

from __future__ import annotations

from hc2.adapters.base import Adapter, AdapterContext, AdapterReport, ProcessSignature

ALL_ADAPTERS: tuple[Adapter, ...] = ()

__all__ = ["ALL_ADAPTERS", "Adapter", "AdapterContext", "AdapterReport", "ProcessSignature"]
