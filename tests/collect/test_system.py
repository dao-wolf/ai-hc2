"""Tests for the system collector, using recorded made-up command output."""

from __future__ import annotations

import unittest
from collections.abc import Sequence
from datetime import UTC, datetime

from hc2.collect import system as S

from . import fixture

GB = 1024**3


class ParserTests(unittest.TestCase):
    def test_sysctl(self) -> None:
        values = S.parse_sysctl(fixture("sysctl.txt"))
        self.assertEqual(values["hw.memsize"], "17179869184")
        self.assertEqual(values["hw.ncpu"], "8")
        self.assertEqual(S.parse_sysctl("nonsense\n: x\nsome words: y"), {})

    def test_swap(self) -> None:
        value = S.parse_sysctl(fixture("sysctl.txt"))["vm.swapusage"]
        self.assertEqual(S.parse_swap(value), (4096 * 1024**2, 2048 * 1024**2))
        self.assertEqual(
            S.parse_swap("total = 1.5G  used = 0.50G  free = 1G"),
            (int(1.5 * GB), int(0.5 * GB)),
        )
        self.assertEqual(S.parse_swap(None), (None, None))
        self.assertEqual(S.parse_swap("garbage"), (None, None))

    def test_loadavg(self) -> None:
        self.assertEqual(S.parse_loadavg("{ 2.10 2.35 2.40 }"), (2.1, 2.35, 2.4))
        self.assertEqual(S.parse_loadavg("{ 1 2 }"), (None, None, None))
        self.assertEqual(S.parse_loadavg(None), (None, None, None))

    def test_memory_pressure(self) -> None:
        text = fixture("memory_pressure_q.txt")
        self.assertEqual(S.parse_memory_pressure_q(text), 12)
        self.assertIsNone(S.parse_memory_pressure_q("nothing here"))
        self.assertIsNone(S.parse_memory_pressure_q("free percentage: 400%"))

    def test_compressor(self) -> None:
        self.assertEqual(S.parse_vm_stat_compressor(fixture("vm_stat.txt")), 4 * GB)
        self.assertIsNone(S.parse_vm_stat_compressor("Pages free: 1."))
        self.assertIsNone(S.parse_vm_stat_compressor(""))

    def test_thermal(self) -> None:
        self.assertEqual(S.parse_thermal(fixture("pmset_therm_nominal.txt")), "nominal")
        throttled = fixture("pmset_therm_throttled.txt")
        self.assertEqual(S.parse_thermal(throttled), "throttled")
        self.assertEqual(S.parse_thermal("CPU_Speed_Limit = 100"), "nominal")
        self.assertEqual(S.parse_thermal("Thermal warning level = 2"), "elevated")
        self.assertEqual(S.parse_thermal("Thermal warning level = 0"), "nominal")
        self.assertIsNone(S.parse_thermal("who knows"))


class ReadingTests(unittest.TestCase):
    def reading(self) -> S.SystemReading:
        return S.build_reading(
            sysctl=fixture("sysctl.txt"),
            vm_stat=fixture("vm_stat.txt"),
            memory_pressure=fixture("memory_pressure_q.txt"),
            pmset=fixture("pmset_therm_nominal.txt"),
            sampled_at="2026-10-30T12:00:00Z",
        )

    def test_full_reading(self) -> None:
        reading = self.reading()
        sample = reading.sample
        self.assertEqual(sample.memory_total_bytes, 16 * GB)
        self.assertEqual(sample.memory_used_bytes, 16 * GB * 88 // 100)
        self.assertEqual(sample.swap_used_bytes, 2048 * 1024**2)
        loads = (sample.load_1m, sample.load_5m, sample.load_15m)
        self.assertEqual(loads, (2.1, 2.35, 2.4))
        self.assertEqual(sample.thermal_state, "nominal")
        self.assertEqual(sample.sampled_at, "2026-10-30T12:00:00Z")
        self.assertEqual(reading.swap_total_bytes, 4096 * 1024**2)
        self.assertEqual(reading.compressor_bytes, 4 * GB)
        self.assertEqual(reading.free_percent, 12)
        self.assertEqual(reading.kernel_level, "warn")
        self.assertEqual(reading.cpu_count, 8)

    def test_levels(self) -> None:
        for number, name in (("1", "normal"), ("2", "warn"), ("4", "critical")):
            text = f"kern.memorystatus_vm_pressure_level: {number}\n"
            reading = S.build_reading(
                sysctl=text, vm_stat="", memory_pressure="", pmset=""
            )
            self.assertEqual(reading.kernel_level, name)
        odd = S.build_reading(
            sysctl="kern.memorystatus_vm_pressure_level: 3\n",
            vm_stat="",
            memory_pressure="",
            pmset="",
        )
        self.assertIsNone(odd.kernel_level)

    def test_missing_everything_is_none(self) -> None:
        reading = S.build_reading(sysctl="", vm_stat="", memory_pressure="", pmset="")
        self.assertIsNone(reading.sample.memory_total_bytes)
        self.assertIsNone(reading.sample.memory_used_bytes)
        self.assertIsNone(reading.sample.swap_used_bytes)
        self.assertIsNone(reading.sample.load_1m)
        self.assertIsNone(reading.sample.thermal_state)
        self.assertIsNone(reading.compressor_bytes)
        self.assertIsNone(reading.free_percent)
        self.assertIsNone(reading.kernel_level)

    def test_serialises(self) -> None:
        data = self.reading().to_dict()
        self.assertEqual(data["sample"]["thermal_state"], "nominal")
        self.assertEqual(data["free_percent"], 12)

    def test_collect_with_a_fake_runner(self) -> None:
        calls: list[tuple[str, ...]] = []
        outputs = {
            "sysctl": fixture("sysctl.txt"),
            "vm_stat": fixture("vm_stat.txt"),
            "memory_pressure": fixture("memory_pressure_q.txt"),
            "pmset": fixture("pmset_therm_throttled.txt"),
        }

        def run(argv: Sequence[str], timeout: float) -> str | None:
            calls.append(tuple(argv))
            self.assertLessEqual(timeout, 2.0)
            return outputs[argv[0]]

        now = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
        reading = S.collect_system(runner=run, now=now)
        self.assertEqual(len(calls), 4)
        self.assertIn(("memory_pressure", "-Q"), calls)
        self.assertEqual(reading.sample.thermal_state, "throttled")
        self.assertEqual(reading.sample.sampled_at, "2026-10-30T12:00:00Z")

    def test_collect_survives_failures(self) -> None:
        reading = S.collect_system(runner=lambda argv, timeout: None)
        self.assertIsNone(reading.sample.memory_total_bytes)


if __name__ == "__main__":
    unittest.main()
