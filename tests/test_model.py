"""Tests for the data contract: stable ids and deterministic serialisation."""

from __future__ import annotations

import dataclasses
import json
import re
import unittest
from typing import Any

from hc2 import model
from hc2.model import (
    Action,
    ActionKind,
    ActionResult,
    Actor,
    ActorType,
    Event,
    FieldSource,
    Finding,
    Harness,
    Install,
    InstallKind,
    Note,
    Origin,
    Pairs,
    ProcessNode,
    ProcessRole,
    Proposal,
    ProposalStatus,
    Reliability,
    Session,
    SessionState,
    Severity,
    SystemSample,
    stable_id,
)

ALICE = Actor(ActorType.HUMAN, "alice")
ROBOT = Actor(ActorType.LLM, "example-client", "example-model-1")


def make_install() -> Install:
    return Install(
        id=stable_id("install", "example-cli", "cli", "1.2.3"),
        harness_id="example-cli",
        kind=InstallKind.CLI,
        version="1.2.3",
        version_source="the binary's own --version output",
        location="~/.local/bin/example",
    )


def make_harness() -> Harness:
    return Harness(
        id="example-cli",
        name="Example CLI",
        installed=True,
        installs=(make_install(),),
        config_location="~/.example",
        docs_url="https://example.com/docs",
        changelog_url="https://example.com/changelog",
        llms_txt_url="https://example.com/llms.txt",
    )


def make_session() -> Session:
    return Session(
        id="session-0001",
        harness_id="example-cli",
        title="Fix the Example Project build",
        folder="/home/alice/example-project",
        model="example-model-1",
        created="2026-10-30T09:00:00Z",
        last_activity="2026-10-30T09:30:00Z",
        state=SessionState.RUNNING_IDLE,
        origin=Origin.CLI,
        confidential=False,
        field_sources=(
            FieldSource("model", "last assistant entry", Reliability.MEDIUM),
            FieldSource("title", "session index", Reliability.HIGH),
        ),
    )


def make_process() -> ProcessNode:
    return ProcessNode(
        pid=4242,
        name="node",
        start_time="2026-10-30T09:01:00Z",
        fingerprint="0123456789abcdef",
        parent_pid=4000,
        role=ProcessRole.DEV_SERVER,
        harness_id="example-cli",
        session_id="session-0001",
        cpu_percent=12.5,
        memory_bytes=104857600,
        gpu_time_ms=0,
        threads=9,
        age_seconds=1800,
        listening_ports=(3000, 8777),
    )


def make_sample() -> SystemSample:
    return SystemSample(
        sampled_at="2026-10-30T09:31:00Z",
        memory_total_bytes=17179869184,
        memory_used_bytes=12884901888,
        swap_used_bytes=0,
        load_1m=1.5,
        load_5m=2.0,
        load_15m=3,
        thermal_state="nominal",
    )


def make_finding() -> Finding:
    return Finding(
        id=stable_id("finding", "idle-memory", "example-cli", "session-0001"),
        rule_id="idle-memory",
        severity=Severity.AMBER,
        title="An idle session holds memory",
        reason="Session session-0001 has been idle for 3 hours and holds 400 MB.",
        fix="Close the session if you have finished with it.",
        location="~/.example",
        harness_id="example-cli",
        session_id="session-0001",
        acknowledged=True,
        ack_note="Needed for the demo",
        ack_until="2026-11-30T00:00:00Z",
    )


def make_proposal() -> Proposal:
    params = Pairs.of({"port": 8777, "pid": 4242, "dry_run": False})
    return Proposal(
        id=stable_id("proposal", "stop_process_tree", "port=8777", "example-client"),
        kind=ActionKind.STOP_PROCESS_TREE,
        params=params,
        reason="The dev server is orphaned.",
        preview="Stop process 4242 and its 2 children.",
        proposed_by=ROBOT,
        status=ProposalStatus.APPROVED,
        finding_id=make_finding().id,
        created="2026-10-30T09:40:00Z",
        decided_by=ALICE,
        decided_at="2026-10-30T09:41:00Z",
        trace_id="5b8efff798038103d269b633813fc60c",
    )


def make_action() -> Action:
    return Action(
        id=stable_id("action", make_proposal().id),
        proposal_id=make_proposal().id,
        kind=ActionKind.STOP_PROCESS_TREE,
        params=Pairs.of({"pid": 4242}),
        result=ActionResult.OK,
        detail="Stopped 3 processes.",
        executed_at="2026-10-30T09:42:00Z",
        verified=True,
        trace_id="5b8efff798038103d269b633813fc60c",
    )


def make_note() -> Note:
    return Note(
        id=stable_id("note", make_finding().id, "example-client", 1),
        target_kind="finding",
        target_id=make_finding().id,
        author=ROBOT,
        body="This looks like a leftover from a test run.",
        created="2026-10-30T09:50:00Z",
    )


def make_event() -> Event:
    return Event(
        time_unix_nano="1793350800000000000",
        event_name="hc2.action.executed",
        body="Stopped orphaned dev server on port 8777 (approved by alice).",
        actor=ALICE,
        severity_text="INFO",
        trace_id="5b8efff798038103d269b633813fc60c",
        span_id="eee19b7ec3c1b174",
        attributes=Pairs.of(
            {
                "hc2.action.kind": "stop_process_tree",
                "hc2.proposal.id": "p_3f2a",
                "hc2.result": "ok",
            }
        ),
    )


FACTORIES = {
    "Actor": lambda: ROBOT,
    "Install": make_install,
    "Harness": make_harness,
    "FieldSource": lambda: FieldSource("model", "x", Reliability.LOW),
    "Session": make_session,
    "ProcessNode": make_process,
    "SystemSample": make_sample,
    "Finding": make_finding,
    "Proposal": make_proposal,
    "Action": make_action,
    "Note": make_note,
    "Event": make_event,
}


def keys_sorted(value: Any) -> bool:
    """True when every dict, at any depth, has its keys in sorted order."""
    if isinstance(value, dict):
        keys = list(value)
        return keys == sorted(keys) and all(keys_sorted(v) for v in value.values())
    if isinstance(value, list):
        return all(keys_sorted(v) for v in value)
    return True


class StableIdTests(unittest.TestCase):
    def test_same_meaning_gives_same_id(self) -> None:
        first = stable_id("finding", "idle-memory", "example-cli", "s1")
        second = stable_id("finding", "idle-memory", "example-cli", "s1")
        self.assertEqual(first, second)

    def test_golden_value_never_changes(self) -> None:
        # Changing the hash scheme breaks every stored id. Do not edit lightly.
        self.assertEqual(
            stable_id("finding", "idle-memory", "example-cli", "s1"),
            "finding_0d2c00639043ab43",
        )

    def test_shape(self) -> None:
        self.assertRegex(stable_id("session", "abc"), r"^session_[0-9a-f]{16}$")

    def test_kind_and_order_and_values_matter(self) -> None:
        base = stable_id("finding", "a", "b")
        self.assertNotEqual(base, stable_id("proposal", "a", "b"))
        self.assertNotEqual(base, stable_id("finding", "b", "a"))
        self.assertNotEqual(base, stable_id("finding", "a", "c"))

    def test_part_boundaries_are_unambiguous(self) -> None:
        self.assertNotEqual(stable_id("k", "ab", "c"), stable_id("k", "a", "bc"))
        self.assertNotEqual(stable_id("k", "a"), stable_id("k", "a", ""))

    def test_ints_are_allowed_and_match_their_text(self) -> None:
        self.assertEqual(stable_id("note", "x", 1), stable_id("note", "x", "1"))

    def test_path_free_output(self) -> None:
        value = stable_id("session", "id-with/slash-ok")
        self.assertNotIn("/", value)
        self.assertNotIn("Users", value)

    def test_refuses_paths(self) -> None:
        bad = [
            "/home/alice/project",
            "~/project",
            "./project",
            "../project",
            "C:\\Users\\alice",
            "C:/Users/alice",
            "projects\\one",
            "see /Users/alice/x",
        ]
        for part in bad:
            with self.subTest(part=part), self.assertRaises(ValueError):
                stable_id("finding", part)

    def test_refuses_timestamps(self) -> None:
        for part in ["2026-10-30T09:00:00Z", "2026-10-30 09:00"]:
            with self.subTest(part=part), self.assertRaises(ValueError):
                stable_id("finding", part)

    def test_refuses_wrong_types(self) -> None:
        for part in [1.5, None, True, b"x", ("a",)]:
            with self.subTest(part=part), self.assertRaises(TypeError):
                stable_id("finding", part)  # type: ignore[arg-type]

    def test_refuses_bad_kind(self) -> None:
        for kind in ["", "Finding", "a-b", "1abc", "a b"]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                stable_id(kind, "x")


class EnumTests(unittest.TestCase):
    def test_session_states_match_the_requirements(self) -> None:
        self.assertEqual(
            [state.value for state in SessionState],
            [
                "running-busy",
                "running-idle",
                "waiting",
                "stale",
                "ended",
                "unknown",
            ],
        )

    def test_severities_match_the_requirements(self) -> None:
        self.assertEqual(
            {sev.value for sev in Severity}, {"red", "amber", "info", "green"}
        )

    def test_severity_rank_orders_by_urgency(self) -> None:
        ordered = sorted(Severity, key=lambda sev: sev.rank, reverse=True)
        self.assertEqual(
            ordered, [Severity.RED, Severity.AMBER, Severity.INFO, Severity.GREEN]
        )

    def test_action_catalogue_is_the_v1_list(self) -> None:
        self.assertEqual(
            {kind.value for kind in ActionKind},
            {"stop_process_tree", "stop_port_server", "open_path", "rescan"},
        )

    def test_enums_print_as_their_values(self) -> None:
        self.assertEqual(str(Severity.RED), "red")
        self.assertEqual(f"{SessionState.RUNNING_BUSY}", "running-busy")


class SerialisationTests(unittest.TestCase):
    def test_every_class_round_trips_through_dicts(self) -> None:
        for name, factory in FACTORIES.items():
            with self.subTest(cls=name):
                original = factory()
                rebuilt = type(original).from_dict(original.to_dict())
                self.assertEqual(rebuilt, original)

    def test_every_class_round_trips_through_json_text(self) -> None:
        for name, factory in FACTORIES.items():
            with self.subTest(cls=name):
                original = factory()
                rebuilt = type(original).from_dict(json.loads(original.to_json()))
                self.assertEqual(rebuilt, original)

    def test_to_dict_keys_are_sorted_at_every_depth(self) -> None:
        for name, factory in FACTORIES.items():
            with self.subTest(cls=name):
                self.assertTrue(keys_sorted(factory().to_dict()))

    def test_to_json_is_deterministic_and_compact(self) -> None:
        text = make_harness().to_json()
        self.assertEqual(text, make_harness().to_json())
        again = json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
        self.assertEqual(text, again)

    def test_pairs_input_order_does_not_change_output(self) -> None:
        one = Pairs.of({"b": 1, "a": 2})
        two = Pairs.of({"a": 2, "b": 1})
        self.assertEqual(one, two)
        self.assertEqual(list(one.as_dict()), ["a", "b"])

    def test_enums_and_pairs_become_plain_json(self) -> None:
        data = make_proposal().to_dict()
        self.assertEqual(data["kind"], "stop_process_tree")
        self.assertEqual(data["status"], "approved")
        self.assertEqual(data["params"], {"dry_run": False, "pid": 4242, "port": 8777})
        self.assertEqual(data["proposed_by"]["type"], "llm")
        self.assertIsInstance(make_process().to_dict()["listening_ports"], list)

    def test_defaults_serialise_as_null_or_empty(self) -> None:
        data = Session(id="s", harness_id="h").to_dict()
        self.assertEqual(data["state"], "unknown")
        self.assertEqual(data["origin"], "unknown")
        self.assertIsNone(data["title"])
        self.assertEqual(data["field_sources"], [])
        self.assertIsNone(data["pid"])
        self.assertIsNone(data["state_since"])

    def test_pid_and_state_since_round_trip(self) -> None:
        session = dataclasses.replace(
            make_session(), pid=4242, state_since="2026-10-30T09:10:00Z"
        )
        data = session.to_dict()
        self.assertEqual(data["pid"], 4242)
        self.assertEqual(Session.from_dict(json.loads(session.to_json())), session)

    def test_an_older_session_record_without_the_new_keys_still_loads(self) -> None:
        data = make_session().to_dict()
        del data["pid"], data["state_since"]
        rebuilt = Session.from_dict(data)
        self.assertIsNone(rebuilt.pid)
        self.assertIsNone(rebuilt.state_since)

    def test_whole_numbers_come_back_as_floats_where_declared(self) -> None:
        rebuilt = SystemSample.from_dict(json.loads(make_sample().to_json()))
        self.assertIsInstance(rebuilt.load_15m, float)

    def test_unknown_keys_are_ignored(self) -> None:
        data = make_session().to_dict()
        data["added_in_a_later_version"] = {"anything": 1}
        self.assertEqual(Session.from_dict(data), make_session())

    def test_missing_required_field_fails(self) -> None:
        with self.assertRaises(TypeError):
            Session.from_dict({"id": "only-an-id"})

    def test_unknown_enum_value_fails(self) -> None:
        data = make_session().to_dict()
        data["state"] = "sleeping"
        with self.assertRaises(ValueError):
            Session.from_dict(data)

    def test_objects_are_frozen(self) -> None:
        session = make_session()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            session.title = "changed"  # type: ignore[misc]

    def test_objects_are_hashable(self) -> None:
        self.assertEqual(len({make_proposal(), make_proposal()}), 1)

    def test_nothing_path_like_is_added_by_serialisation(self) -> None:
        text = make_finding().to_json() + make_harness().to_json()
        self.assertIsNone(re.search(r"/(Users|home)/", text))

    def test_every_public_class_has_a_docstring(self) -> None:
        for name, factory in FACTORIES.items():
            with self.subTest(cls=name):
                self.assertTrue(type(factory()).__doc__)
        self.assertTrue(model.Model.__doc__)
        self.assertTrue(Pairs.__doc__)


class EventTests(unittest.TestCase):
    def test_log_record_matches_the_design_example(self) -> None:
        record = make_event().to_log_record()
        self.assertEqual(record["timeUnixNano"], "1793350800000000000")
        self.assertEqual(record["severityText"], "INFO")
        self.assertEqual(record["eventName"], "hc2.action.executed")
        self.assertEqual(record["traceId"], "5b8efff798038103d269b633813fc60c")
        self.assertEqual(record["spanId"], "eee19b7ec3c1b174")
        attrs = record["attributes"]
        self.assertEqual(attrs["hc2.schema"], "1")
        self.assertEqual(attrs["hc2.actor.type"], "human")
        self.assertEqual(attrs["hc2.actor.name"], "alice")
        self.assertEqual(attrs["hc2.action.kind"], "stop_process_tree")
        self.assertEqual(attrs["hc2.result"], "ok")

    def test_log_record_is_sorted_and_stable(self) -> None:
        record = make_event().to_log_record()
        self.assertTrue(keys_sorted(record))
        self.assertEqual(record, make_event().to_log_record())

    def test_llm_actor_adds_the_model(self) -> None:
        event = dataclasses.replace(make_event(), actor=ROBOT)
        attrs = event.to_log_record()["attributes"]
        self.assertEqual(attrs["hc2.actor.type"], "llm")
        self.assertEqual(attrs["hc2.actor.model"], "example-model-1")

    def test_bad_values_are_refused(self) -> None:
        base = make_event()
        with self.assertRaises(ValueError):
            dataclasses.replace(base, time_unix_nano="2026-10-30")
        with self.assertRaises(ValueError):
            dataclasses.replace(base, trace_id="not-hex")
        with self.assertRaises(ValueError):
            dataclasses.replace(base, span_id="abc")

    def test_empty_ids_are_allowed(self) -> None:
        system = Actor(ActorType.SYSTEM, "hc2")
        event = Event("1", "hc2.scan.finished", "Scan finished.", system)
        self.assertEqual(event.to_log_record()["traceId"], "")


if __name__ == "__main__":
    unittest.main()
