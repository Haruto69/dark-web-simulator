"""Adversarial tests for :mod:`rewindsec.domain.session.SimulationSession`."""

import pytest

from rewindsec.domain.enums import ActionClass, Focus, Mode, SessionStatus
from rewindsec.domain.errors import (IdentityMismatchError, InvalidDomainStateError,
                                     SessionNotActiveError, UnknownReferenceError)
from rewindsec.domain.session import SimulationSession


def _fresh(seed=1):
    return SimulationSession.create("s1", "learner-1", Focus.PHISHING,
                                    Mode.PRACTICE, root_seed=seed)


def test_create_starts_active_at_time_zero_revision_zero():
    session = _fresh()
    assert session.is_active
    assert session.now_ms == 0
    assert session.revision == 0
    assert session.root_seed == 1


def test_record_immediate_event_bumps_revision_and_uses_current_time():
    session = _fresh()
    session.advance_time(500)
    event = session.record_immediate_event("mail.delivered")
    assert event.sim_time_ms == 500
    assert session.revision == 1  # advance_time with nothing due does not bump


def test_schedule_then_advance_fires_and_records_in_both_logs():
    session = _fresh()
    entry = session.schedule_event("mail.delivered", delay_ms=1000, payload={"x": 1})
    assert session.schedule_audit.get(entry.schedule_id).is_pending
    fired = session.advance_time(1000)
    assert len(fired) == 1
    assert session.event_log.has(fired[0].event_id)
    audit = session.schedule_audit.get(entry.schedule_id)
    assert audit.status == "fired"
    assert audit.fired_event_id == fired[0].event_id


def test_cancel_scheduled_prevents_firing_and_records_reason():
    session = _fresh()
    entry = session.schedule_event("mail.delivered", delay_ms=1000)
    session.cancel_scheduled(entry.schedule_id, reason="isolated host")
    fired = session.advance_time(2000)
    assert fired == ()
    audit = session.schedule_audit.get(entry.schedule_id)
    assert audit.status == "cancelled"
    assert audit.cancellation_reason == "isolated host"


def test_record_immediate_event_with_unknown_cause_rejected():
    session = _fresh()
    with pytest.raises(UnknownReferenceError):
        session.record_immediate_event("mail.opened", causes=("0" * 32,))


def test_observe_fact_requires_known_action():
    session = _fresh()
    session.introduce_fact("company_domain", "org", "acme.example", "directory")
    with pytest.raises(UnknownReferenceError):
        session.observe_fact("company_domain", "0" * 32)


def test_mutate_world_with_unknown_cause_event_rejected():
    session = _fresh()
    with pytest.raises(UnknownReferenceError):
        session.mutate_world("mailbox", "unread", 1, cause_event_id="0" * 32)


def test_record_consequence_requires_known_mutation_ref():
    session = _fresh()
    event = session.record_immediate_event("mail.delivered")
    incident = session.open_incident("chain", opening_event_id=event.event_id)
    with pytest.raises(UnknownReferenceError):
        session.record_consequence(incident.incident_id, cause_event_id=event.event_id,
                                   mutation_ref="0" * 32)


def test_no_mutating_operation_allowed_once_completed():
    session = _fresh()
    session.complete()
    assert session.status is SessionStatus.COMPLETED
    with pytest.raises(SessionNotActiveError):
        session.record_immediate_event("mail.delivered")
    with pytest.raises(SessionNotActiveError):
        session.advance_time(100)


def test_no_mutating_operation_allowed_once_abandoned():
    session = _fresh()
    session.abandon()
    with pytest.raises(SessionNotActiveError):
        session.record_action("inspect.open_mail", ActionClass.OBSERVATIONAL)


def test_full_scenario_capture_restore_equivalence():
    session = _fresh(seed=99)
    ev = session.record_immediate_event("mail.delivered", payload={"n": 1})
    session.schedule_event("mail.delivered", delay_ms=1000)
    session.advance_time(1000)
    act = session.record_action("inspect.open_mail", ActionClass.OBSERVATIONAL,
                                target=ev.event_id)
    session.introduce_fact("company_domain", "org", "acme.example", "directory",
                           introduced_by_event_id=ev.event_id)
    session.observe_fact("company_domain", act.action_id)
    mutation = session.mutate_world("mailbox", "unread", 1, cause_event_id=ev.event_id)
    incident = session.open_incident("chain", opening_event_id=ev.event_id)
    session.record_consequence(incident.incident_id, cause_event_id=ev.event_id,
                               triggering_action_id=act.action_id,
                               mutation_ref=mutation.mutation_id)

    state = session.capture_state()
    restored = SimulationSession.from_state(state)
    assert restored.capture_state() == state
    assert restored.revision == session.revision
    assert restored.now_ms == session.now_ms


def test_restore_rejects_wrong_session_identity_into_existing_instance():
    session = _fresh()
    state = session.capture_state()
    other = _fresh()
    other._session_id  # sanity: exists
    bad_state = dict(state)
    bad_state["session_id"] = "different"
    other_session = SimulationSession.create("s-other", "learner-1", Focus.MFA,
                                             Mode.SIMULATION, root_seed=1)
    with pytest.raises(IdentityMismatchError):
        other_session.restore_state(state)


def test_restore_rejects_snapshot_referencing_unknown_event():
    session = _fresh()
    session.record_immediate_event("mail.delivered")
    state = session.capture_state()
    state["world"]["mutations"] = []  # unrelated, keep simple
    state["ledger"]["facts"] = [{
        "fact_id": "f1", "category": "org", "value": 1, "source": "src",
        "introduced_by_event_id": "0" * 32, "introduced_at_ms": 0,
        "last_updated_at_ms": 0, "available": True, "available_at_ms": 0,
        "observed": False, "observed_by_action_id": None, "observed_at_ms": None,
        "version": 1,
    }]
    with pytest.raises(InvalidDomainStateError):
        SimulationSession.from_state(state)


def test_restore_rejects_snapshot_with_bad_scheduler_identity():
    session = _fresh()
    state = session.capture_state()
    state["scheduler"]["identity"] = "someone-else"
    with pytest.raises(Exception):
        SimulationSession.from_state(state)


def test_unknown_top_level_field_rejected():
    session = _fresh()
    state = session.capture_state()
    state["bogus"] = 1
    with pytest.raises(InvalidDomainStateError):
        SimulationSession.from_state(state)


def test_unsupported_version_rejected():
    session = _fresh()
    state = session.capture_state()
    state["version"] = 999
    with pytest.raises(InvalidDomainStateError):
        SimulationSession.from_state(state)
