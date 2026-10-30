"""Config: defaults, file, environment and flags, in that order of strength (C-1)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hc2.config import (
    DEFAULT_ADAPTER_TIMEOUT_SECONDS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_STALE_HOURS,
    Overrides,
    adapter_key,
    load_config,
)

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "config.toml"

FILE = """
schema = 1
[privacy]
confidential_folders = ["/home/alice/from-file"]
redact_all_titles = true
confidential_terms = ["from file", "other"]
[scan]
adapter_timeout_seconds = 7
[rules.stale_session]
idle_hours = 5
[audit]
retention_days = 9
[adapters]
claude_code_cli = false
codex = true
"""


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "config.toml"

    def write(self, text: str) -> None:
        self.path.write_text(text, encoding="utf-8")

    def load(self, env: dict[str, str] | None = None, **flags: object) -> object:
        overrides = Overrides(**flags) if flags else None  # type: ignore[arg-type]
        return load_config(path=self.path, env=env or {}, overrides=overrides)

    # -- defaults and the file ------------------------------------------

    def test_defaults_when_there_is_no_file(self) -> None:
        config = load_config(path=self.path, env={})
        self.assertEqual(config.confidential_folders, ())
        self.assertFalse(config.redact_all_titles)
        self.assertEqual(
            config.adapter_timeout_seconds, DEFAULT_ADAPTER_TIMEOUT_SECONDS
        )
        self.assertEqual(config.adapter_timeout_seconds, 10.0)
        self.assertEqual(config.stale_hours, DEFAULT_STALE_HOURS)
        self.assertEqual(config.retention_days, DEFAULT_RETENTION_DAYS)
        self.assertEqual(config.warnings, ())
        self.assertTrue(config.adapter_enabled("anything"))

    def test_terms_follow_the_same_precedence(self) -> None:
        self.write(FILE)
        self.assertEqual(
            load_config(path=self.path, env={}).confidential_terms,
            ("from file", "other"),
        )
        env = {"HC2_CONFIDENTIAL_TERMS": "from env, second"}
        from_env = load_config(path=self.path, env=env)
        self.assertEqual(from_env.confidential_terms, ("from env", "second"))
        flags = Overrides(confidential_terms=("from flag",))
        from_flag = load_config(path=self.path, env=env, overrides=flags)
        self.assertEqual(from_flag.confidential_terms, ("from flag",))
        self.assertNotIn("from", repr(from_flag))

    def test_bad_terms_warn_without_repeating_them(self) -> None:
        self.write('[privacy]\nconfidential_terms = ["ok", 5]\n')
        config = load_config(path=self.path, env={})
        self.assertEqual(config.confidential_terms, ())
        self.assertEqual(len(config.warnings), 1)
        self.assertNotIn("ok", config.warnings[0])

    def test_changing_a_term_changes_the_fingerprint(self) -> None:
        self.write(FILE)
        first = load_config(path=self.path, env={}).fingerprint
        self.write(FILE.replace("other", "another"))
        self.assertNotEqual(first, load_config(path=self.path, env={}).fingerprint)

    def test_the_file_beats_the_defaults(self) -> None:
        self.write(FILE)
        config = load_config(path=self.path, env={})
        self.assertEqual(config.confidential_folders, ("/home/alice/from-file",))
        self.assertTrue(config.redact_all_titles)
        self.assertEqual(config.adapter_timeout_seconds, 7.0)
        self.assertEqual(config.stale_hours, 5.0)
        self.assertEqual(config.retention_days, 9)
        self.assertFalse(config.adapter_enabled("claude-code-cli"))
        self.assertTrue(config.adapter_enabled("codex"))
        self.assertEqual(config.warnings, ())

    # -- precedence ------------------------------------------------------

    def test_environment_beats_the_file(self) -> None:
        self.write(FILE)
        env = {
            "HC2_CONFIDENTIAL_FOLDERS": "/home/alice/a:/home/alice/b",
            "HC2_ADAPTER_TIMEOUT_SECONDS": "3.5",
            "HC2_STALE_HOURS": "1",
            "HC2_RETENTION_DAYS": "4",
            "HC2_ENABLE_ADAPTERS": "claude-code-cli",
            "HC2_DISABLE_ADAPTERS": "codex, pi",
        }
        config = load_config(path=self.path, env=env)
        self.assertEqual(
            config.confidential_folders, ("/home/alice/a", "/home/alice/b")
        )
        self.assertEqual(config.adapter_timeout_seconds, 3.5)
        self.assertEqual(config.stale_hours, 1.0)
        self.assertEqual(config.retention_days, 4)
        self.assertTrue(config.adapter_enabled("claude-code-cli"))
        self.assertFalse(config.adapter_enabled("codex"))
        self.assertFalse(config.adapter_enabled("pi"))

    def test_flags_beat_the_environment_and_the_file(self) -> None:
        self.write(FILE)
        env = {"HC2_STALE_HOURS": "1", "HC2_ADAPTER_TIMEOUT_SECONDS": "3"}
        overrides = Overrides(
            confidential_folders=("/home/alice/flag",),
            adapter_timeout_seconds=1.5,
            stale_hours=0.5,
            retention_days=2,
            enable_adapters=("codex",),
            disable_adapters=("pi",),
        )
        config = load_config(path=self.path, env=env, overrides=overrides)
        self.assertEqual(config.confidential_folders, ("/home/alice/flag",))
        self.assertEqual(config.adapter_timeout_seconds, 1.5)
        self.assertEqual(config.stale_hours, 0.5)
        self.assertEqual(config.retention_days, 2)
        self.assertFalse(config.adapter_enabled("pi"))

    def test_a_flag_can_switch_an_adapter_back_on(self) -> None:
        self.write(FILE)
        env = {"HC2_DISABLE_ADAPTERS": "claude-code-cli"}
        flags = Overrides(enable_adapters=("claude-code-cli",))
        config = load_config(path=self.path, env=env, overrides=flags)
        self.assertTrue(config.adapter_enabled("claude-code-cli"))

    def test_off_wins_when_a_layer_names_an_adapter_twice(self) -> None:
        config = load_config(
            path=self.path,
            env={},
            overrides=Overrides(enable_adapters=("pi",), disable_adapters=("pi",)),
        )
        self.assertFalse(config.adapter_enabled("pi"))

    def test_an_empty_environment_variable_means_not_set(self) -> None:
        self.write(FILE)
        config = load_config(path=self.path, env={"HC2_STALE_HOURS": "  "})
        self.assertEqual(config.stale_hours, 5.0)

    # -- bad values ------------------------------------------------------

    def test_bad_environment_values_fall_back_to_the_file(self) -> None:
        self.write(FILE)
        env = {
            "HC2_STALE_HOURS": "soon",
            "HC2_RETENTION_DAYS": "0",
            "HC2_ADAPTER_TIMEOUT_SECONDS": "-1",
        }
        config = load_config(path=self.path, env=env)
        self.assertEqual(config.stale_hours, 5.0)
        self.assertEqual(config.retention_days, 9)
        self.assertEqual(config.adapter_timeout_seconds, 7.0)
        self.assertEqual(len(config.warnings), 3)

    def test_bad_file_values_fall_back_to_defaults(self) -> None:
        self.write(
            '[privacy]\nconfidential_folders = "not a list"\nredact_all_titles = 3\n'
            "[scan]\nadapter_timeout_seconds = true\n"
            '[rules.stale_session]\nidle_hours = "x"\n'
            "[audit]\nretention_days = 1.5\n[adapters]\ncodex = 'yes'\n"
        )
        config = load_config(path=self.path, env={})
        self.assertEqual(config.confidential_folders, ())
        self.assertFalse(config.redact_all_titles)
        self.assertEqual(config.adapter_timeout_seconds, 10.0)
        self.assertEqual(config.stale_hours, DEFAULT_STALE_HOURS)
        self.assertEqual(config.retention_days, DEFAULT_RETENTION_DAYS)
        self.assertTrue(config.adapter_enabled("codex"))
        self.assertEqual(len(config.warnings), 6)

    def test_warnings_never_repeat_the_bad_value(self) -> None:
        self.write('[privacy]\nconfidential_folders = ["/home/alice/x", 5]\n')
        config = load_config(path=self.path, env={"HC2_STALE_HOURS": "/home/alice/y"})
        text = " ".join(config.warnings)
        self.assertNotIn("/home/alice", text)
        self.assertEqual(len(config.warnings), 2)

    def test_invalid_toml_uses_defaults_and_warns(self) -> None:
        self.write("this is = = not toml")
        config = load_config(path=self.path, env={})
        self.assertEqual(config.stale_hours, DEFAULT_STALE_HOURS)
        self.assertEqual(len(config.warnings), 1)
        self.assertIn("not valid TOML", config.warnings[0])

    def test_a_newer_layout_is_noted(self) -> None:
        self.write("schema = 2\n")
        self.assertEqual(len(load_config(path=self.path, env={}).warnings), 1)

    def test_a_folder_in_place_of_the_file_is_unreadable_not_fatal(self) -> None:
        self.path.mkdir()
        config = load_config(path=self.path, env={})
        self.assertEqual(len(config.warnings), 1)

    # -- fingerprint (S-7) ----------------------------------------------

    def test_fingerprint_changes_when_the_file_changes(self) -> None:
        self.write(FILE)
        first = load_config(path=self.path, env={}).fingerprint
        self.write(FILE.replace("idle_hours = 5", "idle_hours = 6"))
        second = load_config(path=self.path, env={}).fingerprint
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_fingerprint_ignores_comments_and_spacing(self) -> None:
        self.write(FILE)
        first = load_config(path=self.path, env={}).fingerprint
        self.write("# a note\n" + FILE.replace(" = ", "  =  "))
        self.assertEqual(first, load_config(path=self.path, env={}).fingerprint)

    def test_fingerprint_ignores_environment_and_flags(self) -> None:
        self.write(FILE)
        plain = load_config(path=self.path, env={}).fingerprint
        env = {"HC2_STALE_HOURS": "9"}
        flags = Overrides(stale_hours=3)
        self.assertEqual(plain, load_config(path=self.path, env=env).fingerprint)
        self.assertEqual(
            plain, load_config(path=self.path, env=env, overrides=flags).fingerprint
        )

    def test_fingerprint_covers_settings_the_code_does_not_read_yet(self) -> None:
        self.write(FILE + "[rules.memory_pressure]\namber_percent = 80\n")
        first = load_config(path=self.path, env={}).fingerprint
        self.write(FILE + "[rules.memory_pressure]\namber_percent = 95\n")
        self.assertNotEqual(first, load_config(path=self.path, env={}).fingerprint)

    def test_missing_and_empty_files_share_a_fingerprint(self) -> None:
        missing = load_config(path=self.path, env={}).fingerprint
        self.write("")
        self.assertEqual(missing, load_config(path=self.path, env={}).fingerprint)

    def test_invalid_toml_still_changes_the_fingerprint(self) -> None:
        self.write("= = 1")
        first = load_config(path=self.path, env={}).fingerprint
        self.write("= = 2")
        self.assertNotEqual(first, load_config(path=self.path, env={}).fingerprint)

    def test_the_fingerprint_does_not_reveal_folder_names(self) -> None:
        self.write(FILE)
        self.assertNotIn("from-file", load_config(path=self.path, env={}).fingerprint)

    def test_repr_hides_the_confidential_folders(self) -> None:
        self.write(FILE)
        self.assertNotIn("from-file", repr(load_config(path=self.path, env={})))

    # -- the committed example ------------------------------------------

    def test_the_example_config_loads_cleanly(self) -> None:
        config = load_config(path=EXAMPLE, env={})
        self.assertEqual(config.warnings, ())
        self.assertEqual(config.adapter_timeout_seconds, 10.0)
        self.assertEqual(config.stale_hours, 2.0)
        self.assertEqual(config.retention_days, 30)
        self.assertEqual(len(config.confidential_folders), 2)
        self.assertTrue(config.adapter_enabled("claude-code-cli"))
        self.assertTrue(config.adapter_enabled("claude-desktop-code"))
        self.assertTrue(config.adapter_enabled("claude-desktop-cowork"))

    def test_the_resources_table_passes_through_unchanged(self) -> None:
        self.write(
            "[rules.resources]\nenabled = true\nswap_red_percent = 70.5\n"
            'heavy_jobs_allowed = 2\nmade_up_key = "kept"\n'
            "[rules.resources.nested]\nx = 1\n"
        )
        table = load_config(path=self.path, env={}).resources_table()
        self.assertEqual(
            table,
            {
                "enabled": True,
                "heavy_jobs_allowed": 2,
                "made_up_key": "kept",
                "swap_red_percent": 70.5,
            },
        )

    def test_no_resources_table_gives_an_empty_one(self) -> None:
        self.assertEqual(load_config(path=self.path, env={}).resources_table(), {})

    def test_the_example_resources_table_is_all_numbers(self) -> None:
        table = load_config(path=EXAMPLE, env={}).resources_table()
        self.assertEqual(len(table), 23)
        numbers = {k: v for k, v in table.items() if k != "enabled"}
        self.assertTrue(all(isinstance(v, int | float) for v in numbers.values()))

    def test_adapter_key_swaps_hyphens_for_underscores(self) -> None:
        self.assertEqual(adapter_key(" Claude-Code-CLI "), "claude_code_cli")


if __name__ == "__main__":
    unittest.main()
