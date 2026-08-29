"""D. Telemetry completeness and ordering."""

import pytest

from sandbox import EventType, FileImpactScenario, SandboxNotReadyError
from sandbox.dataset import BASELINE_FILENAMES


def test_lifecycle_events_are_emitted_in_order(manager, collector):
    manager.create()
    manager.reset()
    manager.destroy()
    assert collector.types() == [
        EventType.SANDBOX_CREATED,
        EventType.SANDBOX_RESET,
        EventType.SANDBOX_DESTROYED,
    ]


def test_scenario_emits_the_full_expected_sequence(manager, collector):
    manager.create()
    collector.events.clear()
    FileImpactScenario(manager).run(session_id="sess-1")

    types = collector.types()
    assert types[0] == EventType.SCENARIO_STARTED
    assert types[1] == EventType.FILE_IMPACT_STARTED
    assert types[-2] == EventType.FILE_IMPACT_COMPLETED
    assert types[-1] == EventType.SCENARIO_COMPLETED

    impacts = [t for t in types if t == EventType.FILE_IMPACT]
    assert len(impacts) == len(BASELINE_FILENAMES)


def test_file_impact_events_carry_workspace_target_and_detail(manager, collector):
    manager.create()
    collector.events.clear()
    FileImpactScenario(manager).run(targets=["finance_report.txt"])

    impact = [e for e in collector.events if e["event_type"] == EventType.FILE_IMPACT][0]
    assert impact["target"] == "/workspace/finance_report.txt"
    assert "finance_report.txt.demo_locked" in impact["details"]
    assert impact["source"] == "scenario:file_impact"


def test_events_share_one_scenario_id_and_session_id(manager, collector):
    manager.create()
    collector.events.clear()
    result = FileImpactScenario(manager).run(session_id="sess-42")

    scenario_events = [e for e in collector.events if e["scenario_id"]]
    assert scenario_events, "scenario events must carry a scenario_id"
    assert {e["scenario_id"] for e in scenario_events} == {result["scenario_id"]}
    assert {e["session_id"] for e in scenario_events} == {"sess-42"}


def test_timestamps_are_monotonic(manager, collector):
    manager.create()
    FileImpactScenario(manager).run()
    stamps = [e["timestamp"] for e in collector.events]
    assert stamps == sorted(stamps)


def test_rejected_target_emits_dedicated_event(manager, collector):
    manager.create()
    collector.events.clear()
    FileImpactScenario(manager).run(targets=["../secrets.txt"])

    types = collector.types()
    assert EventType.FILE_IMPACT_REJECTED in types
    assert EventType.FILE_IMPACT not in types


def test_missing_sandbox_emits_scenario_failed(manager, collector):
    with pytest.raises(SandboxNotReadyError):
        FileImpactScenario(manager).run()
    assert collector.types() == [
        EventType.SCENARIO_STARTED,
        EventType.SCENARIO_FAILED,
    ]


def test_telemetry_carries_no_credentials_or_host_paths(manager, collector):
    manager.create()
    FileImpactScenario(manager).run()
    for event in collector.events:
        blob = "%s %s" % (event.get("target") or "", event.get("details") or "")
        assert "password" not in blob.lower()
        assert ":\\" not in blob
