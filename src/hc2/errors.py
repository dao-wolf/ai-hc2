"""Errors that are safe to show a person as they are."""

from __future__ import annotations


class UserError(Exception):
    """A problem explained in plain English, with no paths and no secrets.

    The command line prints `str(error)` and exits with code 1. Raise this only
    with text HC2 wrote itself, never with text from a harness or an OS error.
    """
