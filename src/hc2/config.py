"""Settings: defaults, the config file, environment variables and flags (C-1).

Precedence, highest first: a command-line flag, an environment variable, the
config file, then the built-in default.

* Confidential folders: `[privacy] confidential_folders`, or
  `HC2_CONFIDENTIAL_FOLDERS`.
* Confidential terms: `[privacy] confidential_terms`, or
  `HC2_CONFIDENTIAL_TERMS` (separated by commas). A session whose title or
  folder holds a term as a whole word is masked like one in a confidential
  folder (P-2).
* Hide every title: `[privacy] redact_all_titles` (file only).
* Adapter timeout in seconds: `[scan] adapter_timeout_seconds`, or
  `HC2_ADAPTER_TIMEOUT_SECONDS`.
* Stale after, in hours: `[rules.stale_session] idle_hours`, or
  `HC2_STALE_HOURS`.
* Retention in days: `[audit] retention_days`, or `HC2_RETENTION_DAYS`.
* Adapter switches: `[adapters] <adapter_id> = true`, then
  `HC2_ENABLE_ADAPTERS` and `HC2_DISABLE_ADAPTERS`. The id `resources` switches
  the process and system collector, which `hc2 scan` runs by default.
* Resource rule thresholds: the `[rules.resources]` table, passed through
  unchanged as `Config.resources_table()`. The resources lane owns the key
  names and checks them (`Thresholds.from_mapping`); this module does not.

Folder lists in the environment are separated like `PATH`. Adapter lists are
separated by commas. A bad value never stops HC2: it is ignored, the next layer
applies, and a plain-English warning is kept in `Config.warnings`. Warnings
never repeat the bad value, which could be a path.

`Config.fingerprint` is a hash of the parsed config file alone, so editing the
file changes it but a flag or environment variable does not. A changed
fingerprint between scans raises a finding (S-7).
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hc2.model import Model, Pairs, ParamValue
from hc2.paths import config_file

DEFAULT_ADAPTER_TIMEOUT_SECONDS = 10.0
DEFAULT_STALE_HOURS = 2.0
DEFAULT_RETENTION_DAYS = 30

MAX_TIMEOUT_SECONDS = 600.0
MAX_CONFIG_BYTES = 1_000_000

ENV_CONFIDENTIAL_FOLDERS = "HC2_CONFIDENTIAL_FOLDERS"
ENV_CONFIDENTIAL_TERMS = "HC2_CONFIDENTIAL_TERMS"
ENV_ADAPTER_TIMEOUT = "HC2_ADAPTER_TIMEOUT_SECONDS"
ENV_STALE_HOURS = "HC2_STALE_HOURS"
ENV_RETENTION_DAYS = "HC2_RETENTION_DAYS"
ENV_ENABLE_ADAPTERS = "HC2_ENABLE_ADAPTERS"
ENV_DISABLE_ADAPTERS = "HC2_DISABLE_ADAPTERS"

_FILE = "the config file"
_ENV = "the environment"


def adapter_key(adapter_id: str) -> str:
    """The config key for an adapter id: `claude-code-cli` is `claude_code_cli`."""
    return adapter_id.strip().lower().replace("-", "_")


@dataclass(frozen=True)
class Overrides:
    """Settings given on the command line. `None` or empty means "not given"."""

    confidential_folders: tuple[str, ...] | None = None
    confidential_terms: tuple[str, ...] | None = None
    adapter_timeout_seconds: float | None = None
    stale_hours: float | None = None
    retention_days: int | None = None
    enable_adapters: tuple[str, ...] = ()
    disable_adapters: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config(Model):
    """The effective settings for one run.

    `confidential_folders` and `confidential_terms` are exactly as written (folders
    may use `~`); they are left out of `repr` so logs never show them. Never print this
    object. Adapters not named in `adapters` are enabled.
    """

    confidential_folders: tuple[str, ...] = field(default=(), repr=False)
    confidential_terms: tuple[str, ...] = field(default=(), repr=False)
    redact_all_titles: bool = False
    adapter_timeout_seconds: float = DEFAULT_ADAPTER_TIMEOUT_SECONDS
    stale_hours: float = DEFAULT_STALE_HOURS
    retention_days: int = DEFAULT_RETENTION_DAYS
    adapters: Pairs = Pairs()
    resources: Pairs = Pairs()
    fingerprint: str = ""
    warnings: tuple[str, ...] = ()

    def resources_table(self) -> dict[str, ParamValue]:
        """The `[rules.resources]` table exactly as written in the file.

        Pass it to `Thresholds.from_mapping`. Nested tables are left out.
        """
        return self.resources.as_dict()

    def adapter_enabled(self, adapter_id: str) -> bool:
        """Whether the adapter may run. Adapters are on unless switched off."""
        value = self.adapters.as_dict().get(adapter_key(adapter_id), True)
        return value is not False


# --------------------------------------------------------------------------
# Value checks. Each returns a clean value, or None when the input is unusable.
# --------------------------------------------------------------------------


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _timeout(value: object) -> float | None:
    number = _number(value)
    if number is None or not 0 < number <= MAX_TIMEOUT_SECONDS:
        return None
    return number


def _hours(value: object) -> float | None:
    number = _number(value)
    if number is None or not 0 < number <= 24 * 365:
        return None
    return number


def _days(value: object) -> int | None:
    number = _number(value)
    if number is None or number != int(number) or not 1 <= number <= 3650:
        return None
    return int(number)


def _folders(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list | tuple):
        return None
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        items.append(item.strip())
    return tuple(items)


def _flag(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _parse_text(kind: str, text: str) -> object:
    """Turn environment text into the type the setting expects, or `None`."""
    try:
        if kind == "int":
            return int(text)
        return float(text)
    except ValueError:
        return None


@dataclass
class _Builder:
    """Collects layers, lowest first, and the warnings they raise."""

    folders: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    redact_all_titles: bool = False
    timeout: float = DEFAULT_ADAPTER_TIMEOUT_SECONDS
    stale_hours: float = DEFAULT_STALE_HOURS
    retention_days: int = DEFAULT_RETENTION_DAYS
    adapters: dict[str, bool] = field(default_factory=dict)
    resources: dict[str, ParamValue] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def warn(self, name: str, where: str) -> None:
        self.warnings.append(
            f"The setting '{name}' in {where} is not valid, so it was ignored."
        )


def _table(data: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    node: Any = data
    for key in path:
        node = node.get(key) if isinstance(node, Mapping) else None
    return node if isinstance(node, Mapping) else {}


def _apply_file(builder: _Builder, data: Mapping[str, Any]) -> None:
    schema = data.get("schema")
    if schema is not None and schema != 1:
        builder.warnings.append(
            "The config file uses a layout this version of HC2 does not know, "
            "so some settings may be ignored."
        )
    privacy = _table(data, "privacy")
    if "confidential_folders" in privacy:
        folders = _folders(privacy["confidential_folders"])
        if folders is None:
            builder.warn("confidential_folders", _FILE)
        else:
            builder.folders = folders
    if "confidential_terms" in privacy:
        terms = _folders(privacy["confidential_terms"])
        if terms is None:
            builder.warn("confidential_terms", _FILE)
        else:
            builder.terms = terms
    if "redact_all_titles" in privacy:
        flag = _flag(privacy["redact_all_titles"])
        if flag is None:
            builder.warn("redact_all_titles", _FILE)
        else:
            builder.redact_all_titles = flag
    scan = _table(data, "scan")
    if "adapter_timeout_seconds" in scan:
        timeout = _timeout(scan["adapter_timeout_seconds"])
        if timeout is None:
            builder.warn("adapter_timeout_seconds", _FILE)
        else:
            builder.timeout = timeout
    stale = _table(data, "rules", "stale_session")
    if "idle_hours" in stale:
        hours = _hours(stale["idle_hours"])
        if hours is None:
            builder.warn("idle_hours", _FILE)
        else:
            builder.stale_hours = hours
    audit = _table(data, "audit")
    if "retention_days" in audit:
        days = _days(audit["retention_days"])
        if days is None:
            builder.warn("retention_days", _FILE)
        else:
            builder.retention_days = days
    for key, value in _table(data, "rules", "resources").items():
        if isinstance(value, str | int | float | bool):
            builder.resources[key] = value
    for key, value in _table(data, "adapters").items():
        flag = _flag(value)
        if flag is None:
            builder.warn(f"adapters.{key}", _FILE)
        else:
            builder.adapters[adapter_key(key)] = flag


def _split(text: str, separator: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in text.split(separator) if part.strip())


def _apply_env(builder: _Builder, env: Mapping[str, str]) -> None:
    def raw(name: str) -> str | None:
        value = env.get(name, "").strip()
        return value or None

    if (text := raw(ENV_CONFIDENTIAL_FOLDERS)) is not None:
        builder.folders = _split(text, os.pathsep)
    if (text := raw(ENV_CONFIDENTIAL_TERMS)) is not None:
        builder.terms = _split(text, ",")
    if (text := raw(ENV_ADAPTER_TIMEOUT)) is not None:
        timeout = _timeout(_parse_text("float", text))
        if timeout is None:
            builder.warn(ENV_ADAPTER_TIMEOUT, _ENV)
        else:
            builder.timeout = timeout
    if (text := raw(ENV_STALE_HOURS)) is not None:
        hours = _hours(_parse_text("float", text))
        if hours is None:
            builder.warn(ENV_STALE_HOURS, _ENV)
        else:
            builder.stale_hours = hours
    if (text := raw(ENV_RETENTION_DAYS)) is not None:
        days = _days(_parse_text("int", text))
        if days is None:
            builder.warn(ENV_RETENTION_DAYS, _ENV)
        else:
            builder.retention_days = days
    _switch(builder, _split(raw(ENV_ENABLE_ADAPTERS) or "", ","), True)
    _switch(builder, _split(raw(ENV_DISABLE_ADAPTERS) or "", ","), False)


def _switch(builder: _Builder, ids: Sequence[str], value: bool) -> None:
    for adapter_id in ids:
        builder.adapters[adapter_key(adapter_id)] = value


def _apply_overrides(builder: _Builder, overrides: Overrides) -> None:
    if overrides.confidential_folders is not None:
        builder.folders = tuple(
            item.strip() for item in overrides.confidential_folders if item.strip()
        )
    if overrides.confidential_terms is not None:
        builder.terms = tuple(
            item.strip() for item in overrides.confidential_terms if item.strip()
        )
    if overrides.adapter_timeout_seconds is not None:
        timeout = _timeout(overrides.adapter_timeout_seconds)
        if timeout is None:
            builder.warn("adapter timeout", "the command line")
        else:
            builder.timeout = timeout
    if overrides.stale_hours is not None:
        hours = _hours(overrides.stale_hours)
        if hours is None:
            builder.warn("stale hours", "the command line")
        else:
            builder.stale_hours = hours
    if overrides.retention_days is not None:
        days = _days(overrides.retention_days)
        if days is None:
            builder.warn("retention days", "the command line")
        else:
            builder.retention_days = days
    _switch(builder, overrides.enable_adapters, True)
    _switch(builder, overrides.disable_adapters, False)


# --------------------------------------------------------------------------
# The file
# --------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_file(path: Path) -> tuple[Mapping[str, Any], str, str | None]:
    """Parse the file. Returns its data, its fingerprint and any warning."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return {}, _sha256(b"{}"), None
    except OSError:
        return (
            {},
            _sha256(b"unreadable"),
            "The config file could not be read, so the defaults were used.",
        )
    if len(raw) > MAX_CONFIG_BYTES:
        return (
            {},
            _sha256(b"too-large:" + raw[:1024]),
            "The config file is far too large, so it was ignored.",
        )
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return (
            {},
            _sha256(b"invalid:" + raw),
            "The config file is not valid TOML, so the defaults were used.",
        )
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return data, _sha256(canonical.encode("utf-8")), None


def load_config(
    *,
    path: Path | None = None,
    env: Mapping[str, str] | None = None,
    overrides: Overrides | None = None,
) -> Config:
    """Build the effective config. Never raises for a bad file or value (C-1).

    `path` defaults to `config.toml` in the config folder, `env` to the real
    environment and `overrides` to no flags. A missing file is not an error.
    """
    file_path = path if path is not None else config_file()
    environment = os.environ if env is None else env
    data, fingerprint, problem = _read_file(file_path)
    builder = _Builder()
    if problem:
        builder.warnings.append(problem)
    _apply_file(builder, data)
    _apply_env(builder, environment)
    if overrides is not None:
        _apply_overrides(builder, overrides)
    return Config(
        confidential_folders=builder.folders,
        confidential_terms=builder.terms,
        redact_all_titles=builder.redact_all_titles,
        adapter_timeout_seconds=builder.timeout,
        stale_hours=builder.stale_hours,
        retention_days=builder.retention_days,
        adapters=Pairs.of(builder.adapters),
        resources=Pairs.of(builder.resources),
        fingerprint=fingerprint,
        warnings=tuple(builder.warnings),
    )
