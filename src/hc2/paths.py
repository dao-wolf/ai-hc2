"""Where HC2 keeps its files.

The layout follows XDG on every OS, macOS included, so the paths are the same
everywhere. Both folders can be moved with an environment variable.

| What   | Default                | Override         |
|--------|------------------------|------------------|
| Config | `~/.config/ai-hc2`     | `HC2_CONFIG_DIR` |
| State  | `~/.local/state/ai-hc2`| `HC2_STATE_DIR`  |

Nothing here creates a folder. Callers that write must create it themselves.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_CONFIG_DIR = "HC2_CONFIG_DIR"
ENV_STATE_DIR = "HC2_STATE_DIR"


def _resolve(env_name: str, *default: str) -> Path:
    raw = os.environ.get(env_name, "").strip()
    base = Path(raw) if raw else Path("~").joinpath(*default)
    return base.expanduser().absolute()


def config_dir() -> Path:
    """The folder for the config file and personal extras."""
    return _resolve(ENV_CONFIG_DIR, ".config", "ai-hc2")


def state_dir() -> Path:
    """The folder for the database, audit log, snapshots and token."""
    return _resolve(ENV_STATE_DIR, ".local", "state", "ai-hc2")


def config_file() -> Path:
    """The path of `config.toml` (it may not exist)."""
    return config_dir() / "config.toml"


def display_path(path: Path) -> str:
    """Show a path with the home folder as `~`, so output never names the user."""
    home = Path("~").expanduser().absolute()
    try:
        relative = path.absolute().relative_to(home)
    except ValueError:
        return str(path)
    return "~" if str(relative) == "." else f"~/{relative}"
