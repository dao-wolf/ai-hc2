"""Tests for the config and state folder helpers."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hc2 import paths


class PathsTests(unittest.TestCase):
    def test_defaults_follow_the_xdg_layout_under_home(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            env = {"HOME": home, "HC2_CONFIG_DIR": "", "HC2_STATE_DIR": ""}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(paths.config_dir(), Path(home) / ".config/ai-hc2")
                self.assertEqual(paths.state_dir(), Path(home) / ".local/state/ai-hc2")
                self.assertEqual(
                    paths.config_file(), Path(home) / ".config/ai-hc2/config.toml"
                )

    def test_environment_overrides_win(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "HC2_CONFIG_DIR": f"{tmp}/c",
                "HC2_STATE_DIR": f"{tmp}/s",
            }
            with mock.patch.dict(os.environ, env):
                self.assertEqual(paths.config_dir(), Path(tmp) / "c")
                self.assertEqual(paths.state_dir(), Path(tmp) / "s")

    def test_override_may_use_a_tilde(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            env = {"HOME": home, "HC2_CONFIG_DIR": "~/elsewhere"}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(paths.config_dir(), Path(home) / "elsewhere")

    def test_relative_override_becomes_absolute(self) -> None:
        with mock.patch.dict(os.environ, {"HC2_STATE_DIR": "relative/state"}):
            self.assertTrue(paths.state_dir().is_absolute())

    def test_nothing_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "never"
            with mock.patch.dict(os.environ, {"HC2_CONFIG_DIR": str(target)}):
                paths.config_dir()
                paths.config_file()
            self.assertFalse(target.exists())

    def test_display_path_hides_the_home_folder(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            home_path = Path(home)
            outside = Path(tempfile.gettempdir()) / "elsewhere"
            with mock.patch.dict(os.environ, {"HOME": home}):
                shown = paths.display_path(home_path / ".config/ai-hc2")
                self.assertEqual(shown, "~/.config/ai-hc2")
                self.assertEqual(paths.display_path(home_path), "~")
                self.assertEqual(paths.display_path(outside), str(outside))


if __name__ == "__main__":
    unittest.main()
