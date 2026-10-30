"""The committed example config must stay valid and free of real data."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "config.toml"


class ExampleConfigTests(unittest.TestCase):
    def test_parses_as_toml(self) -> None:
        data = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], 1)
        for table in ["privacy", "scan", "adapters", "rules", "network", "audit"]:
            self.assertIn(table, data)

    def test_every_rule_has_an_enabled_switch(self) -> None:
        data = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        for name, rule in data["rules"].items():
            with self.subTest(rule=name):
                self.assertIn("enabled", rule)

    def test_network_and_export_are_off_by_default(self) -> None:
        data = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.assertFalse(data["network"]["check_versions"])
        self.assertFalse(data["network"]["check_docs"])
        self.assertFalse(data["telemetry"]["otlp_export"])

    def test_only_made_up_paths_are_used(self) -> None:
        text = EXAMPLE.read_text(encoding="utf-8")
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/home/", text.replace("/home/alice", ""))


if __name__ == "__main__":
    unittest.main()
