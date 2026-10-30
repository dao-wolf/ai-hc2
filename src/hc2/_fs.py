"""Small file helpers shared by the store and the audit log."""

from __future__ import annotations

import os
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> None:
    """Create a folder (and parents) that only the user can open.

    Folders that already exist keep their mode.
    """
    if path.is_dir():
        return
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    os.chmod(path, PRIVATE_DIR_MODE)


def atomic_write(path: Path, data: bytes) -> None:
    """Write a file so a reader sees the old content or the new, never half.

    The file is written beside the target, flushed to disk, then renamed over it.
    Only the user can read the result.
    """
    temp = path.with_name(f".{path.name}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
