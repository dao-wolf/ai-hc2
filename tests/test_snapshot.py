"""The Snapshot type and the S1 additions to the model."""

from __future__ import annotations

import json
import unittest

from hc2.model import (
    SCHEMA_VERSION,
    ActionKind,
    Actor,
    ActorType,
    Finding,
    Harness,
    HarnessReport,
    Pairs,
    ProcessNode,
    Proposal,
    Risk,
    Session,
    Severity,
    Snapshot,
    SystemSample,
    stable_id,
)


def sample() -> Snapshot:
    finding = Finding(
        id=stable_id("finding", "r", "h", "x"),
        rule_id="r",
        severity=Severity.AMBER,
        title="t",
        reason="why",
        fix="how",
        harness_id="h",
    )
    return Snapshot(
        schema=SCHEMA_VERSION,
        generated="2026-10-30T09:00:00Z",
        scan_id="scan_0123456789abcdef",
        harnesses=(
            HarnessReport(
                Harness("h", "Harness", True),
                (Session("s1", "h", title="Example Project"),),
                ("A problem.",),
                ("index: id",),
            ),
        ),
        findings=(finding,),
        system=SystemSample(load_1m=0.5),
        processes=(ProcessNode(pid=1, name="node", listening_ports=(8080,)),),
    )


class SnapshotTests(unittest.TestCase):
    def test_round_trips_through_json(self) -> None:
        snap = sample()
        again = Snapshot.from_dict(json.loads(snap.to_json()))
        self.assertEqual(again, snap)

    def test_system_and_processes_are_empty_by_default(self) -> None:
        snap = Snapshot(SCHEMA_VERSION, "2026-10-30T09:00:00Z", "scan_x")
        self.assertIsNone(snap.system)
        self.assertEqual(snap.processes, ())
        self.assertEqual(snap.harnesses, ())
        data = snap.to_dict()
        self.assertIsNone(data["system"])
        self.assertEqual(data["processes"], [])

    def test_keys_are_sorted_and_output_is_stable(self) -> None:
        text = sample().to_json()
        self.assertEqual(text, sample().to_json())
        data = json.loads(text)
        self.assertEqual(list(data), sorted(data))
        self.assertEqual(
            sorted(data),
            [
                "findings",
                "generated",
                "harnesses",
                "processes",
                "scan_id",
                "schema",
                "system",
            ],
        )

    def test_a_harness_can_be_installed_unknown(self) -> None:
        harness = Harness("h", "Harness", None)
        again = Harness.from_dict(harness.to_dict())
        self.assertIsNone(again.installed)


class ProposalAdditionTests(unittest.TestCase):
    def proposal(self, **extra: object) -> Proposal:
        return Proposal(
            id="proposal_x",
            kind=ActionKind.RESCAN,
            params=Pairs(),
            reason="r",
            preview="p",
            proposed_by=Actor(ActorType.SYSTEM, "hc2"),
            **extra,  # type: ignore[arg-type]
        )

    def test_new_fields_default_to_none(self) -> None:
        p = self.proposal()
        self.assertEqual(
            (p.preview_hash, p.expires_at, p.risk, p.reversible),
            (None, None, None, None),
        )

    def test_new_fields_round_trip(self) -> None:
        p = self.proposal(
            preview_hash="a" * 64,
            expires_at="2026-10-30T09:05:00Z",
            risk=Risk.MEDIUM,
            reversible=True,
        )
        again = Proposal.from_dict(json.loads(p.to_json()))
        self.assertEqual(again, p)
        self.assertEqual(p.to_dict()["risk"], "medium")

    def test_risk_values(self) -> None:
        self.assertEqual([r.value for r in Risk], ["low", "medium", "high"])


if __name__ == "__main__":
    unittest.main()
