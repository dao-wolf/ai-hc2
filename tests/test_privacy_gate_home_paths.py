"""Tests for scripts/privacy_gate.py: home paths written without /Users or /home.

Made-up data only. Strings that the gate would flag are built from pieces.
"""

from __future__ import annotations

import unittest

from privacy_gate_helpers import labels

TILDE = "~/"
HOME_VAR = "$" + "HOME/"
HOME_BRACES = "$" + "{HOME}/"
DRIVE = "C:" + "\\" + "Users" + "\\"
DRIVE_SLASH = "D:/Users/"


class TildePathTests(unittest.TestCase):
    def test_a_folder_under_the_home_shorthand_is_flagged(self) -> None:
        for text in [
            f"see {TILDE}Documents/example/gate.py",
            f"cd {TILDE}Downloads",
            f'"{TILDE}Dropbox/notes.txt"',
            f"{TILDE}work_stuff/x",
            f"{TILDE}Documents/example-project",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), ["home-path"])

    def test_the_home_variable_is_flagged_like_the_shorthand(self) -> None:
        for text in [
            f"cd {HOME_VAR}Documents/x",
            f'cp a "{HOME_VAR}Desktop/b"',
            f"cd {HOME_BRACES}Documents/x",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), ["home-path"])

    def test_hidden_folders_pass_because_tools_keep_their_config_there(self) -> None:
        for text in [
            f"{TILDE}.config/ai-hc2/privacy-denylist.txt",
            f"{TILDE}.local/state/ai-hc2/token",
            f"{HOME_VAR}.ssh/config",
            f"{HOME_BRACES}.cache/x",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])

    def test_made_up_folders_pass(self) -> None:
        for text in [
            f"{TILDE}example-project/x",
            f"{TILDE}Example/x",
            f"{TILDE}project/x",
            f"{TILDE}Library/Application Support/Example",
            f"{TILDE}Applications/Example.app",
            f"{TILDE}x/y",
            f"{TILDE}projects/x",
            f"{HOME_VAR}example/x",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])

    def test_text_that_only_looks_like_a_home_path_passes(self) -> None:
        for text in [
            "~/",
            f"{TILDE}<folder>/x",
            f"{TILDE}$FOLDER/x",
            f"https://example.com/{TILDE}Documents",
            f"a/b{TILDE}Documents",
            "$HOMEWORK/Documents",
            "price ~ 5/Documents",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])


class WindowsHomePathTests(unittest.TestCase):
    def test_a_user_folder_on_a_drive_is_flagged(self) -> None:
        for text in [
            f"{DRIVE}zed" + "\\Documents",
            f"open {DRIVE_SLASH}zed/x",
            f'"{DRIVE}zed"',
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), ["home-path"])

    def test_made_up_and_shared_user_folders_pass(self) -> None:
        for text in [
            f"{DRIVE}alice" + "\\x",
            f"{DRIVE}Public" + "\\Documents",
            f"{DRIVE}Default" + "\\x",
            f"{DRIVE}<name>" + "\\x",
        ]:
            with self.subTest(text=text):
                self.assertEqual(labels(text), [])


if __name__ == "__main__":
    unittest.main()
