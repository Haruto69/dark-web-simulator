"""Adversarial tests for :mod:`rewindsec.domain.incidents`."""

import pytest

from rewindsec.domain.errors import IdentityMismatchError, InvalidDomainStateError, \
    UnknownReferenceError
from rewindsec.domain.incidents import CycleError, IncidentGraph


def test_open_incident_and_record_single_consequence():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    consequence = graph.record_consequence(
        incident.incident_id, sim_time_ms=100, cause_event_id="e" * 32,
        affected_namespace="mailbox", affected_key="unread",
        mutation_ref="m" * 32, description={"note": "credentials submitted"})
    assert consequence.incident_id == incident.incident_id
    assert consequence.cause_event_id == "e" * 32


def test_consequence_requires_a_cause():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    with pytest.raises(InvalidDomainStateError):
        graph.record_consequence(incident.incident_id, sim_time_ms=100)


def test_multi_step_chain_via_parent_consequence_ids():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    step1 = graph.record_consequence(
        incident.incident_id, sim_time_ms=100, cause_event_id="e" * 32)
    step2 = graph.record_consequence(
        incident.incident_id, sim_time_ms=200,
        parent_consequence_ids=[step1.consequence_id])
    assert step2.parent_consequence_ids == (step1.consequence_id,)


def test_record_consequence_unknown_incident_raises():
    graph = IncidentGraph("s1")
    with pytest.raises(UnknownReferenceError):
        graph.record_consequence("0" * 32, sim_time_ms=0, cause_event_id="e" * 32)


def test_record_consequence_unknown_parent_raises():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    with pytest.raises(UnknownReferenceError):
        graph.record_consequence(incident.incident_id, sim_time_ms=0,
                                 parent_consequence_ids=["0" * 32])


def test_duplicate_parent_in_single_call_rejected():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    step1 = graph.record_consequence(
        incident.incident_id, sim_time_ms=100, cause_event_id="e" * 32)
    with pytest.raises(InvalidDomainStateError):
        graph.record_consequence(
            incident.incident_id, sim_time_ms=200,
            parent_consequence_ids=[step1.consequence_id, step1.consequence_id])


def test_affected_namespace_and_key_must_be_both_or_neither():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    with pytest.raises(InvalidDomainStateError):
        graph.record_consequence(incident.incident_id, sim_time_ms=0,
                                 cause_event_id="e" * 32,
                                 affected_namespace="mailbox", affected_key=None)


def test_consequences_for_incident_filters_correctly():
    graph = IncidentGraph("s1")
    incident_a = graph.open_incident("A", opened_at_ms=0)
    incident_b = graph.open_incident("B", opened_at_ms=0)
    graph.record_consequence(incident_a.incident_id, sim_time_ms=0, cause_event_id="e" * 32)
    graph.record_consequence(incident_b.incident_id, sim_time_ms=0, cause_event_id="e" * 32)
    assert len(graph.consequences_for_incident(incident_a.incident_id)) == 1
    assert len(graph.consequences_for_incident(incident_b.incident_id)) == 1


def test_capture_restore_roundtrip():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0, opening_event_id="e" * 32)
    step1 = graph.record_consequence(
        incident.incident_id, sim_time_ms=100, cause_event_id="e" * 32,
        description=["a", "b"])
    graph.record_consequence(
        incident.incident_id, sim_time_ms=200,
        parent_consequence_ids=[step1.consequence_id],
        triggering_action_id="a" * 32)
    state = graph.capture_state()
    restored = IncidentGraph.from_state(state)
    assert restored.capture_state() == state
    assert len(restored.incidents()) == 1
    assert len(restored.consequences()) == 2


def test_restore_rejects_foreign_session_identity():
    graph = IncidentGraph("s1")
    graph.open_incident("Phish chain", opened_at_ms=0)
    state = graph.capture_state()
    other = IncidentGraph("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_restore_rejects_consequence_with_forward_parent_reference():
    """A consequence cannot reference a parent that has not yet been defined
    in the restored payload -- restoring must process causes before effects."""
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    step1 = graph.record_consequence(incident.incident_id, sim_time_ms=100,
                                     cause_event_id="e" * 32)
    step2 = graph.record_consequence(incident.incident_id, sim_time_ms=200,
                                     parent_consequence_ids=[step1.consequence_id])
    state = graph.capture_state()
    state["consequences"] = list(reversed(state["consequences"]))
    with pytest.raises(InvalidDomainStateError):
        IncidentGraph.from_state(state)


def test_restore_rejects_consequence_under_unknown_incident():
    graph = IncidentGraph("s1")
    incident = graph.open_incident("Phish chain", opened_at_ms=0)
    graph.record_consequence(incident.incident_id, sim_time_ms=0, cause_event_id="e" * 32)
    state = graph.capture_state()
    state["consequences"][0]["incident_id"] = "0" * 32
    with pytest.raises(InvalidDomainStateError):
        IncidentGraph.from_state(state)


def test_restore_rejects_tampered_incident_id():
    graph = IncidentGraph("s1")
    graph.open_incident("Phish chain", opened_at_ms=0)
    state = graph.capture_state()
    state["incidents"][0]["incident_id"] = "0" * 32
    with pytest.raises(InvalidDomainStateError):
        IncidentGraph.from_state(state)


def test_consequence_cannot_be_its_own_parent():
    from rewindsec.domain.incidents import Consequence
    cid = "a" * 32
    with pytest.raises(InvalidDomainStateError):
        Consequence(consequence_id=cid, seq=0, incident_id="b" * 32,
                   parent_consequence_ids=[cid], cause_event_id=None,
                   triggering_action_id=None, scheduled_delay_ms=None,
                   affected_namespace=None, affected_key=None, mutation_ref=None,
                   sim_time_ms=0, description=None)
